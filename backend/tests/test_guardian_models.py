"""Guardian persistence: a small root per audit, one bounded run per attempt, disjoint from legacy and dormant."""

import ast
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder
from pydantic import ValidationError

import mist_config_guardian_backend
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.guardian import repository as repo
from mist_config_guardian_backend.guardian.contracts import (
    RUN_DOCUMENT_MAX_BYTES,
    CompactImpactedDevice,
    Evidence,
    Verdict,
)
from mist_config_guardian_backend.models import document_models
from mist_config_guardian_backend.models.adjudication import ImpactAdjudication
from mist_config_guardian_backend.models.guardian import (
    AttemptCounts,
    GuardianClaim,
    GuardianInvestigation,
    GuardianResult,
    GuardianRun,
    RunDocumentTooLargeError,
    bson_size,
    check_run_document_size,
)
from mist_config_guardian_backend.models.investigation import (
    ImpactInvestigation,
    InvestigationRevision,
    ModelRequestArtifact,
)
from mist_config_guardian_backend.models.neighbor_binding import NeighborBinding
from mist_config_guardian_backend.schemas.guardian import GuardianAttemptSummary, GuardianSummary

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
ORG = PydanticObjectId()
ROOT = PydanticObjectId()
TOKEN = PydanticObjectId()
MAC = "5c5b35000001"
SITE = "978c48e6-6ef6-11e6-8bbf-02e208b2d34f"
BACKEND = Path(mist_config_guardian_backend.__file__).resolve().parent
REPO_ROOT = BACKEND.parents[2]
LEGACY_COLLECTIONS = {
    "impact_investigations",
    "investigation_revisions",
    "impact_model_request_artifacts",
    "impact_adjudications",
    "neighbor_bindings",
    "impact_neighbor_bindings",
}


@pytest.fixture(autouse=True)
def _validate_without_mongo(monkeypatch):
    # Beanie refuses to build a document before init_beanie; these tests only exercise validation.
    for model in (GuardianInvestigation, GuardianRun):
        monkeypatch.setattr(model, "get_pymongo_collection", lambda *_: None)


def verdict(**overrides) -> Verdict:
    values = {
        "peak": "warning",
        "current": "info",
        "recovery": "recovered",
        "confidence": "low",
        "coverage": "partial",
        "sources": ("monitoring",),
        "summary": "Monitoring saw a warning that later recovered.",
    }
    return Verdict.model_validate(values | overrides)


def published(run_id=TOKEN, kind="early", **overrides) -> GuardianResult:
    return GuardianResult.from_verdict(run_id=run_id, run_kind=kind, evaluated_at=NOW, verdict=verdict(**overrides))


def root(**overrides) -> GuardianInvestigation:
    values = {
        "id": ROOT,
        "organization_id": ORG,
        "audit_id": "audit-1",
        "changed_at": NOW,
        "anchor_known": True,
        "next_check_at": NOW + timedelta(minutes=1),
    }
    return GuardianInvestigation.model_validate(values | overrides)


def claim(**overrides) -> GuardianClaim:
    values = {"token": TOKEN, "kind": "final", "lease_until": NOW + timedelta(minutes=5)}
    return GuardianClaim.model_validate(values | overrides)


def run(**overrides) -> GuardianRun:
    values = {
        "id": TOKEN,
        "organization_id": ORG,
        "investigation_id": ROOT,
        "audit_id": "audit-1",
        "kind": "early",
        "attempt": 1,
        "state": "running",
        "started_at": NOW,
    }
    return GuardianRun.model_validate(values | overrides)


def index_keys(model) -> dict[str, dict]:
    return {index.document["name"]: index.document for index in model.Settings.indexes}


def test_guardian_collections_are_registered_and_disjoint_from_legacy_collections():
    assert GuardianInvestigation.Settings.name == "guardian_investigations"
    assert GuardianRun.Settings.name == "guardian_runs"
    legacy = {m.Settings.name for m in (ImpactInvestigation, InvestigationRevision, ModelRequestArtifact)}
    legacy |= {ImpactAdjudication.Settings.name, NeighborBinding.Settings.name}
    assert legacy <= LEGACY_COLLECTIONS
    assert {"guardian_investigations", "guardian_runs"}.isdisjoint(LEGACY_COLLECTIONS)
    assert {GuardianInvestigation, GuardianRun} <= set(document_models())


def test_indexes_match_the_design():
    roots = index_keys(GuardianInvestigation)
    assert dict(roots["guardian_investigation_identity"]["key"]) == {"organization_id": 1, "audit_id": 1}
    assert roots["guardian_investigation_identity"]["unique"] is True
    assert dict(roots["guardian_investigation_due"]["key"]) == {"status": 1, "next_check_at": 1}
    runs = index_keys(GuardianRun)
    assert dict(runs["guardian_run_lookup"]["key"]) == {
        "organization_id": 1,
        "investigation_id": 1,
        "kind": 1,
        "attempt": 1,
    }
    for ttl in (roots["guardian_investigation_retention"], runs["guardian_run_retention"]):
        assert dict(ttl["key"]) == {"retained_until": 1}
        assert ttl["expireAfterSeconds"] == 0
        assert ttl["partialFilterExpression"] == {"retained_until": {"$exists": True}}
    assert len(roots) == 3
    assert len(runs) == 2


def test_claims_stay_uncommitted_until_attempt_and_start_are_recorded_together():
    assert not claim().committed
    assert claim(attempt=1, started_at=NOW).committed
    assert claim(final_forced=True).final_forced
    with pytest.raises(ValidationError, match="together"):
        claim(attempt=1)
    with pytest.raises(ValidationError, match="together"):
        claim(started_at=NOW)
    with pytest.raises(ValidationError, match="final"):
        claim(kind="early", final_forced=True)
    with pytest.raises(ValidationError):
        claim(attempt=3, started_at=NOW)


def test_root_status_invariants():
    done = root(status="done", status_reason="Final run published", next_check_at=None)
    assert done.status == "done"
    with pytest.raises(ValidationError, match="reason"):
        root(status="done", next_check_at=None)
    with pytest.raises(ValidationError, match="next check"):
        root(status="done", status_reason="Done")
    with pytest.raises(ValidationError, match="claim"):
        root(status="done", status_reason="Done", next_check_at=None, claim=claim())
    with pytest.raises(ValidationError, match="next check"):
        root(next_check_at=None)
    with pytest.raises(ValidationError):
        root(status="done", status_reason="line\nbreak", next_check_at=None)


def test_a_committed_claim_carries_the_attempt_it_consumed():
    committed = claim(attempt=2, started_at=NOW)
    assert root(claim=committed, attempts=AttemptCounts(final=2)).claim == committed
    with pytest.raises(ValidationError, match="attempt"):
        root(claim=committed, attempts=AttemptCounts(final=1))
    with pytest.raises(ValidationError):
        AttemptCounts(early=3)


def test_the_published_result_matches_the_run_pointers():
    early = PydanticObjectId()
    assert root(early_run_id=early, result=published(early)).result.run_id == early
    final = root(
        status="done",
        status_reason="Final run published",
        next_check_at=None,
        early_run_id=early,
        final_run_id=TOKEN,
        result=published(TOKEN, "final"),
    )
    assert final.published_run_id("final") == TOKEN
    exhausted = root(
        status="done",
        status_reason="Final run failed after 2 attempts: Lease expired",
        next_check_at=None,
        attempts=AttemptCounts(final=2),
        early_run_id=early,
        result=published(early),
    )
    assert exhausted.result.run_kind == "early"
    with pytest.raises(ValidationError, match="result"):
        root(result=published())
    with pytest.raises(ValidationError, match="result"):
        root(early_run_id=early)
    with pytest.raises(ValidationError, match="result"):
        root(early_run_id=early, result=published(PydanticObjectId()))
    with pytest.raises(ValidationError, match="result"):
        root(early_run_id=early, result=published(early, "final"))
    with pytest.raises(ValidationError, match="done"):
        root(final_run_id=TOKEN, result=published(TOKEN, "final"))


def test_root_results_cap_devices_and_count_every_impacted_device():
    devices = tuple(
        CompactImpactedDevice(mac=f"5c5b350000{n:02x}", site_id=SITE, name="x" * 128, peak="warning", current="info")
        for n in range(30)
    )
    result = published(impacted_devices=devices, impacted_devices_omitted=7, summary="s" * 2000)
    assert len(result.impacted_devices) == 20
    assert result.impacted_device_count == 37
    with pytest.raises(ValidationError):
        GuardianResult.model_validate(result.model_dump() | {"impacted_devices": devices})
    with pytest.raises(ValidationError, match="count"):
        GuardianResult.model_validate(result.model_dump() | {"impacted_device_count": 19})
    with pytest.raises(ValidationError, match="complete"):
        GuardianResult.model_validate(result.model_dump() | {"current": "none", "recovery": "recovered"})
    # The root holds only the capped summary; evidence and conclusions live on runs.
    largest = root(early_run_id=TOKEN, result=result, claim=claim(kind="early"))
    assert bson_size(largest) < 16_000
    run_only = {"evidence", "ledger", "obligations", "monitoring", "deployment", "rules", "agent", "steps", "change"}
    assert run_only.isdisjoint(GuardianInvestigation.model_fields)
    assert run_only <= set(GuardianRun.model_fields)


def test_run_state_invariants():
    assert run().state == "running"
    assert run(state="succeeded", finished_at=NOW, verdict=verdict()).verdict is not None
    assert run(state="failed", finished_at=NOW, failure_reason="Ledger construction failed").failure_reason
    assert run(state="abandoned", finished_at=NOW, failure_reason=repo.ABANDONED_REASON).finished_at == NOW
    with pytest.raises(ValidationError, match="claim token"):
        run(id=None)
    with pytest.raises(ValidationError, match="finished"):
        run(state="succeeded", verdict=verdict())
    with pytest.raises(ValidationError, match="finished"):
        run(finished_at=NOW)
    with pytest.raises(ValidationError, match="verdict"):
        run(state="succeeded", finished_at=NOW)
    for state in ("failed", "abandoned"):
        with pytest.raises(ValidationError, match="reason"):
            run(state=state, finished_at=NOW)
    with pytest.raises(ValidationError, match="reason"):
        run(state="succeeded", finished_at=NOW, verdict=verdict(), failure_reason="late")
    with pytest.raises(ValidationError):
        run(state="failed", finished_at=NOW, failure_reason="x" * 301)
    with pytest.raises(ValidationError):
        run(state="failed", finished_at=NOW, failure_reason="Traceback:\n  secret")
    with pytest.raises(ValidationError):
        run(attempt=3)


def evidence(identifier: str) -> Evidence:
    return Evidence(
        id=identifier,
        source="monitoring",
        kind="service_health",
        title="Monitoring",
        captured_at=NOW,
        collection="complete",
        representation="full",
    )


def test_run_evidence_is_stored_in_e_id_order():
    assert [item.id for item in run(evidence=(evidence("E2"), evidence("E10"))).evidence] == ["E2", "E10"]
    with pytest.raises(ValidationError, match="E-id order"):
        run(evidence=(evidence("E10"), evidence("E2")))
    with pytest.raises(ValidationError, match="E-id order"):
        run(evidence=(evidence("E1"), evidence("E1")))


def test_publication_is_derived_from_root_pointers():
    succeeded = run(state="succeeded", finished_at=NOW, verdict=verdict())
    pointed = root(early_run_id=TOKEN, result=published())
    assert pointed.publishes(succeeded)
    assert not root().publishes(succeeded)
    assert not pointed.publishes(run(id=PydanticObjectId(), state="succeeded", finished_at=NOW, verdict=verdict()))
    assert not pointed.publishes(succeeded.model_copy(update={"kind": "final"}))
    assert not pointed.publishes(succeeded.model_copy(update={"organization_id": PydanticObjectId()}))
    assert not pointed.publishes(succeeded.model_copy(update={"investigation_id": PydanticObjectId()}))
    assert not any("publish" in field for field in GuardianRun.model_fields)


def test_repository_documents_are_valid_models():
    ensure = repo.ensure_investigation(
        organization_id=ORG,
        audit_id="audit-1",
        changed_at=NOW,
        anchor_known=False,
        now=NOW,
        retained_until=NOW + timedelta(days=90),
    )
    ensured = GuardianInvestigation.model_validate({"_id": ROOT, **ensure.filter, **ensure.update["$setOnInsert"]})
    assert ensured.status == "waiting"
    assert ensured.next_check_at == NOW + timedelta(minutes=1)
    attempt = repo.CommittedAttempt(
        token=TOKEN,
        organization_id=ORG,
        investigation_id=ROOT,
        audit_id="audit-1",
        kind="final",
        attempt=2,
        started_at=NOW,
        retained_until=None,
    )
    assert GuardianRun.model_validate(repo.running_run_document(attempt, now=NOW)).state == "running"
    abandoned = GuardianRun.model_validate(repo.abandoned_run_document(attempt, now=NOW))
    assert abandoned.failure_reason == repo.ABANDONED_REASON
    encoded = Encoder(to_db=True).encode(published(TOKEN, "final"))
    assert (
        repo.publish_succeeded_run(
            repo.ClaimFence(root_id=ROOT, token=TOKEN, attempt=2),
            kind="final",
            result=encoded,
            status_reason="Final run published",
        ).filter["claim.token"]
        == TOKEN
    )


def test_serialized_size_helpers_bound_run_documents():
    small = run()
    stored = bson_size(small)
    assert 0 < stored == bson_size(small.model_dump(by_alias=True, exclude={"revision_id"}))
    assert check_run_document_size(small) == stored
    big = run(steps=tuple({"output": "x" * 3_000} for _ in range(90)))
    assert bson_size(big) > RUN_DOCUMENT_MAX_BYTES
    with pytest.raises(RunDocumentTooLargeError, match="256000"):
        check_run_document_size(big)


def test_api_summaries_expose_status_results_and_attempts_but_never_evidence():
    summary = GuardianSummary.from_root(root(early_run_id=TOKEN, result=published()))
    assert summary.model_dump(mode="json")["result"]["run_id"] == str(TOKEN)
    attempt = GuardianAttemptSummary.from_run(
        run(state="failed", finished_at=NOW, failure_reason="Provider timed out", evidence=(evidence("E1"),))
    )
    assert attempt.model_dump(mode="json") == {
        "id": str(TOKEN),
        "kind": "early",
        "attempt": 1,
        "state": "failed",
        "failure_reason": "Provider timed out",
        "budget": {"model_turns": 0, "mcp_calls": 0, "rule_reads": 0},
    }


def test_guardian_is_disabled_by_default_everywhere(monkeypatch):
    monkeypatch.delenv("GUARDIAN_ENABLED", raising=False)
    monkeypatch.delenv("IMPACT_ENGINE_MODE", raising=False)
    defaults = Settings(_env_file=None)
    assert defaults.guardian_enabled is False
    assert defaults.impact_engine_mode == "legacy"
    monkeypatch.setenv("GUARDIAN_ENABLED", "true")
    assert Settings(_env_file=None).guardian_enabled is True

    chart = REPO_ROOT / "helm" / "mist-config-guardian"
    assert yaml.safe_load((chart / "values.yaml").read_text())["config"]["guardianEnabled"] is False
    questions = yaml.safe_load((chart / "questions.yaml").read_text())["questions"]
    [question] = [q for q in questions if q["variable"] == "config.guardianEnabled"]
    assert question["type"] == "boolean"
    assert question["default"] is False
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())["services"]
    for service in ("api", "worker"):
        assert compose[service]["environment"]["GUARDIAN_ENABLED"] == "${GUARDIAN_ENABLED:-false}"


def imported_modules(path: Path) -> set[str]:
    modules = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            modules.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    return modules


GUARDIAN_MODULES = (
    "mist_config_guardian_backend.guardian",
    "mist_config_guardian_backend.models.guardian",
    "mist_config_guardian_backend.schemas.guardian",
)


def guardian_sources() -> list[Path]:
    return [
        *sorted((BACKEND / "guardian").rglob("*.py")),
        BACKEND / "models" / "guardian.py",
        BACKEND / "schemas" / "guardian.py",
    ]


def test_guardian_code_never_touches_the_legacy_engine():
    legacy_modules = (
        "mist_config_guardian_backend.impact",
        "mist_config_guardian_backend.models.investigation",
        "mist_config_guardian_backend.models.adjudication",
        "mist_config_guardian_backend.models.neighbor_binding",
        "mist_config_guardian_backend.services",
        "mist_config_guardian_backend.integrations",
    )
    for path in guardian_sources():
        imports = imported_modules(path)
        assert not {m for m in imports if m.startswith(legacy_modules)}, path
        text = path.read_text()
        assert not {name for name in LEGACY_COLLECTIONS if f'"{name}"' in text}, path


# The deterministic core: it may use the pure snapshot helpers (registry, canonical form, diff walker), never the
# service, settings, security, persistence or transport layers. Later pure modules join this list.
PURE_GUARDIAN_MODULES = ("change", "contracts", "deployment", "evidence", "ledger", "monitoring", "repository")
IMPURE_LAYERS = (
    "beanie",
    "motor",
    "pymongo",
    "mist_config_guardian_backend.api",
    "mist_config_guardian_backend.config",
    "mist_config_guardian_backend.integrations",
    "mist_config_guardian_backend.models",
    "mist_config_guardian_backend.schemas",
    "mist_config_guardian_backend.security",
    "mist_config_guardian_backend.services",
    "mist_config_guardian_backend.snapshots.canonical",
)


def in_layer(module: str, layers: tuple[str, ...]) -> bool:
    return any(module == layer or module.startswith(f"{layer}.") for layer in layers)


def test_the_pure_guardian_core_imports_no_service_settings_or_database_layer():
    for name in PURE_GUARDIAN_MODULES:
        path = BACKEND / "guardian" / f"{name}.py"
        assert not {m for m in imported_modules(path) if in_layer(m, IMPURE_LAYERS)}, path


def test_the_pure_guardian_core_loads_no_database_driver_settings_or_service_transitively():
    modules = ", ".join(f"mist_config_guardian_backend.guardian.{name}" for name in PURE_GUARDIAN_MODULES)
    probe = (
        f"import sys; import {modules}; "
        f"layers = {IMPURE_LAYERS!r}; "
        "loaded = sorted(m for m in sys.modules if any(m == l or m.startswith(l + '.') for l in layers)); "
        "print(loaded)"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True)  # noqa: S603

    assert result.stdout.strip() == "[]"


def test_guardian_stays_dormant_until_a_gated_path_is_wired():
    # Only persistence registration and retention reach Guardian code. Later tasks extend this set as they add
    # guardian_enabled-gated paths.
    allowed = {
        *(path.relative_to(BACKEND).as_posix() for path in guardian_sources()),
        "models/__init__.py",
        "services/investigation_retention.py",
    }
    importers = {
        path.relative_to(BACKEND).as_posix()
        for path in BACKEND.rglob("*.py")
        if any(module.startswith(GUARDIAN_MODULES) for module in imported_modules(path))
    }
    assert importers <= allowed
    readers = {
        path.relative_to(BACKEND).as_posix() for path in BACKEND.rglob("*.py") if "guardian_enabled" in path.read_text()
    }
    assert readers == {"config.py"}
