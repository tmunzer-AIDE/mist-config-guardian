"""Guardian's read path: bounded root projections, and detailed reads that prove tenancy before they answer.

Every detailed read walks organization, change group, root, run pointer and run tenant. The doubles here answer the
filters the service actually builds, so a foreign organization or a run from another investigation is excluded by
the query rather than by the test's arrangement. Nothing in this path re-derives a verdict: the report is rendered
from the stored run, and the root's published result is passed through as stored.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pymongo.errors import ConnectionFailure

from mist_config_guardian_backend.api.dependencies import require_organization, require_viewer
from mist_config_guardian_backend.api.routes import change_groups as routes
from mist_config_guardian_backend.guardian import repository as repo
from mist_config_guardian_backend.guardian.contracts import (
    MAX_ROOT_IMPACTED_DEVICES,
    ChangeAtom,
    CompactImpactedDevice,
    Conclusion,
    Evidence,
    Obligation,
    ObligationOutcome,
    ObligationStatus,
    RunBudget,
    Target,
    Verdict,
)
from mist_config_guardian_backend.models.guardian import GuardianInvestigation, GuardianResult, GuardianRun
from mist_config_guardian_backend.models.investigation import ImpactInvestigation, InvestigationRevision
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.guardian import CARRIED_RUN_FIELDS, GuardianRunResponse
from mist_config_guardian_backend.services import guardian_reads
from mist_config_guardian_backend.services.guardian_reads import (
    MAX_PROJECTED_AUDITS,
    PublishedGuardianReader,
    guardian_investigation,
    guardian_run,
)

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
ORG = PydanticObjectId()
OTHER_ORG = PydanticObjectId()
ROOT = PydanticObjectId()
OTHER_ROOT = PydanticObjectId()
GROUP = PydanticObjectId()
EARLY = PydanticObjectId()
FINAL = PydanticObjectId()
AUDIT = "audit-1"
SITE = "978c48e6-6ef6-11e6-8bbf-02e208b2d34f"
OTHER_SITE = "1c7f5d2a-6ef6-11e6-8bbf-02e208b2d34f"
MAC = "5c5b35000001"


@pytest.fixture(autouse=True)
def _validate_without_mongo(monkeypatch):
    # Beanie refuses to build a document before init_beanie; these tests only read and validate them.
    for model in (GuardianInvestigation, GuardianRun, AuditChangeGroup):
        monkeypatch.setattr(model, "get_pymongo_collection", lambda *_: None)


# --- documents --------------------------------------------------------------------------------------------------


def device(mac: str = MAC, site: str = SITE, peak: str = "warning", current: str = "none") -> CompactImpactedDevice:
    return CompactImpactedDevice(mac=mac, site_id=site, name="ap-1", peak=peak, current=current)


def verdict(**overrides: Any) -> Verdict:
    values: dict[str, Any] = {
        "peak": "warning",
        "current": "none",
        "recovery": "recovered",
        "confidence": "low",
        "coverage": "complete",
        "sources": ("monitoring",),
        "summary": "Peak impact warning (coverage complete); current none; 1 impacted device.",
        "impacted_devices": (device(),),
    }
    return Verdict.model_validate(values | overrides)


def run(**overrides: Any) -> GuardianRun:
    values: dict[str, Any] = {
        "id": FINAL,
        "organization_id": ORG,
        "investigation_id": ROOT,
        "audit_id": AUDIT,
        "kind": "final",
        "attempt": 1,
        "state": "succeeded",
        "started_at": NOW,
        "finished_at": NOW + timedelta(seconds=90),
        "change": (
            ChangeAtom(
                id="A1",
                logical_object_id="networktemplate:1",
                version=3,
                attribute="dns_servers",
                paths=(("dns_servers", "0"),),
                paths_complete=True,
            ),
        ),
        "evidence": (
            Evidence(
                id="E1",
                source="monitoring",
                kind="service_health",
                title="Monitoring ap-1",
                captured_at=NOW,
                collection="complete",
                representation="digest",
                payload={"devices": {"satisfied:none": 4}},
                detail="Devices beyond the monitoring evidence budget",
            ),
        ),
        "monitoring": Conclusion(peak="warning", current="none"),
        "verdict": verdict(),
        "steps": ({"turn": 1, "kind": "call", "evidence_id": "E1"},),
        "budget": RunBudget(model_turns=3, mcp_calls=2, rule_reads=1),
    }
    return GuardianRun.model_validate(values | overrides)


def unseen_input() -> ObligationOutcome:
    """The core ``input`` obligation: an observation that names no change atom, so ``change_ref`` is null."""
    return ObligationOutcome(
        obligation=Obligation(
            id="O9",
            owner="core",
            role="observation",
            kind="input",
            target=Target(site_id=SITE),
        ),
        status=ObligationStatus(status="unsatisfied", reason="The attempt never saw the wlans it changed"),
    )


def published(run_id: PydanticObjectId = FINAL, kind: str = "final", **overrides: Any) -> GuardianResult:
    return GuardianResult.from_verdict(run_id=run_id, run_kind=kind, evaluated_at=NOW, verdict=verdict(**overrides))


def root(**overrides: Any) -> GuardianInvestigation:
    values: dict[str, Any] = {
        "id": ROOT,
        "organization_id": ORG,
        "audit_id": AUDIT,
        "changed_at": NOW,
        "anchor_known": True,
        "next_check_at": NOW + timedelta(minutes=1),
    }
    return GuardianInvestigation.model_validate(values | overrides)


def done_root(**overrides: Any) -> GuardianInvestigation:
    """A root that published its final run, which is the state every detailed read is exercised against."""
    values: dict[str, Any] = {
        "status": "done",
        "status_reason": "Final run published",
        "next_check_at": None,
        "attempts": {"early": 1, "final": 1},
        "early_run_id": EARLY,
        "final_run_id": FINAL,
        "result": published(),
    }
    return root(**(values | overrides))


def group(**overrides: Any) -> AuditChangeGroup:
    values: dict[str, Any] = {"id": GROUP, "organization_id": ORG, "audit_id": AUDIT}
    return AuditChangeGroup.model_construct(**(values | overrides))


# --- doubles ----------------------------------------------------------------------------------------------------


def matches(document: dict[str, Any], criteria: dict[str, Any]) -> bool:
    """Evaluate the operators these reads actually use, so a filter that omits a tenant returns foreign rows."""
    for key, expected in criteria.items():
        if key == "$or":
            if not any(matches(document, branch) for branch in expected):
                return False
            continue
        value = document.get(key)
        if isinstance(expected, dict) and "$in" in expected:
            if value not in expected["$in"]:
                return False
        elif value != expected:
            return False
    return True


def fields(model: Any) -> dict[str, Any]:
    """A stored document's fields. A raw mapping is already one: it stands for a document no model can build."""
    if isinstance(model, dict):
        return model
    data = {name: getattr(model, name, None) for name in type(model).model_fields}
    data["_id"] = model.id
    return data


def stored(model: Any) -> dict[str, Any]:
    """The document as Mongo holds it, so a projected read gets values rather than model objects."""
    return model if isinstance(model, dict) else dict(Encoder(to_db=True).encode(fields(model)))


def drifted_root(audit_id: str, **overrides: Any) -> dict[str, Any]:
    """A root a newer deploy wrote: the fields are there, but this build cannot make a model of them."""
    return {
        "_id": PydanticObjectId(),
        "organization_id": ORG,
        "audit_id": audit_id,
        "status": "archived",
        "status_reason": None,
        "result": None,
        **overrides,
    }


def project(document: dict[str, Any], projection: dict[str, int] | None) -> dict[str, Any]:
    """Apply an inclusion projection, dotted paths included, so a read only sees what it asked for."""
    if not projection:
        return document
    kept: dict[str, Any] = {"_id": document.get("_id")}
    for path in projection:
        parts = path.split(".")
        value: Any = document
        for part in parts:
            value = value.get(part) if isinstance(value, dict) else None
        if value is None:
            continue
        target = kept
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
    return kept


class _Query:
    def __init__(self, documents: list[Any]) -> None:
        self._documents = documents
        self.sorted: Any = None
        self.limited: int | None = None

    def sort(self, *args: Any) -> "_Query":
        self.sorted = args
        return self

    def limit(self, value: int) -> "_Query":
        self.limited = value
        return self

    async def to_list(self, length: int | None = None) -> list[Any]:
        del length
        return list(self._documents)


class _Documents:
    """One collection of validated documents that answers the filters the service builds."""

    def __init__(self, model: Any, documents: list[Any]) -> None:
        self.model = model
        self.documents = documents
        self.filters: list[dict[str, Any]] = []
        self.projections: list[dict[str, int] | None] = []
        self.queries: list[_Query] = []
        self.failure: Exception | None = None

    def install(self, monkeypatch: pytest.MonkeyPatch) -> "_Documents":
        monkeypatch.setattr(self.model, "find_one", self._find_one)
        monkeypatch.setattr(self.model, "find", self._find)
        monkeypatch.setattr(self.model, "get_pymongo_collection", lambda *_: self._collection())
        return self

    def _matching(self, criteria: dict[str, Any]) -> list[Any]:
        self.filters.append(criteria)
        if self.failure is not None:
            raise self.failure
        return [item for item in self.documents if matches(fields(item), criteria)]

    def _as_model(self, item: Any) -> Any:
        """What a document read through Beanie gives back: a model, or the validation error it raises."""
        return self.model.model_validate(item) if isinstance(item, dict) else item

    async def _find_one(self, criteria: dict[str, Any], *_args: Any, **_kwargs: Any) -> Any:
        found = self._matching(criteria)
        return self._as_model(found[0]) if found else None

    def _find(self, criteria: dict[str, Any], *_args: Any, **_kwargs: Any) -> _Query:
        query = _Query([self._as_model(item) for item in self._matching(criteria)])
        self.queries.append(query)
        return query

    def _collection(self) -> SimpleNamespace:
        def find(criteria: dict[str, Any], projection: dict[str, int] | None = None) -> _Query:
            self.projections.append(projection)
            query = _Query([project(stored(item), projection) for item in self._matching(criteria)])
            self.queries.append(query)
            return query

        async def find_one(criteria: dict[str, Any], projection: dict[str, int] | None = None) -> Any:
            found = await find(criteria, projection).to_list()
            return found[0] if found else None

        return SimpleNamespace(find=find, find_one=find_one)


class _Legacy:
    """Any read of a legacy collection is a failure, not a value."""

    @staticmethod
    def install(monkeypatch: pytest.MonkeyPatch) -> None:
        def refuse(*_args: Any, **_kwargs: Any) -> None:
            msg = "Guardian projections never read legacy collections"
            raise AssertionError(msg)

        for model in (ImpactInvestigation, InvestigationRevision):
            monkeypatch.setattr(model, "get_pymongo_collection", refuse)


# --- batch root projection --------------------------------------------------------------------------------------


async def test_roots_are_projected_in_one_bounded_batch_without_evidence_or_legacy_collections(monkeypatch):
    _Legacy.install(monkeypatch)
    roots = _Documents(GuardianInvestigation, [done_root()]).install(monkeypatch)
    runs = _Documents(GuardianRun, [run()]).install(monkeypatch)

    result = await PublishedGuardianReader().summaries(ORG, [AUDIT, "audit-2", AUDIT])

    assert result[AUDIT].status == "done"
    assert result[AUDIT].result is not None
    assert result[AUDIT].result.run_id == FINAL
    assert "audit-2" not in result  # No root is no summary, not a clean one.
    assert roots.filters == [{"organization_id": ORG, "audit_id": {"$in": [AUDIT, "audit-2"]}}]
    projection = roots.projections[0]
    assert projection is not None
    assert set(projection.values()) == {1}
    assert not {name for name in projection if name.startswith(("evidence", "steps", "ledger"))}
    assert not runs.filters  # Device rows are read only when a caller asks for them.


async def test_a_waiting_root_is_pending_rather_than_clean(monkeypatch):
    _Documents(GuardianInvestigation, [root()]).install(monkeypatch)

    summary = (await PublishedGuardianReader().summaries(ORG, [AUDIT]))[AUDIT]

    assert (summary.availability, summary.status, summary.result) == ("projected", "waiting", None)


async def test_a_failed_projection_is_unavailable_and_never_a_clean_result(monkeypatch):
    roots = _Documents(GuardianInvestigation, [done_root()]).install(monkeypatch)
    roots.failure = ConnectionFailure("internal connection detail")

    result = await PublishedGuardianReader().summaries(ORG, [AUDIT])

    assert result[AUDIT].availability == "unavailable"
    assert (result[AUDIT].status, result[AUDIT].result, result[AUDIT].impacted) == (None, None, None)
    assert "internal connection" not in result[AUDIT].model_dump_json()


async def test_a_root_this_build_cannot_read_is_unavailable_for_its_own_audit_alone(monkeypatch):
    """A newer deploy's status value, or a half-written root, degrades one column and not the page."""
    unknown_status = drifted_root("audit-2")
    missing_status = drifted_root("audit-3")
    del missing_status["status"]
    _Documents(GuardianInvestigation, [done_root(), unknown_status, missing_status]).install(monkeypatch)

    result = await PublishedGuardianReader().summaries(ORG, [AUDIT, "audit-2", "audit-3"])

    assert result[AUDIT].status == "done"
    assert result[AUDIT].result is not None
    assert result["audit-2"].availability == result["audit-3"].availability == "unavailable"
    assert result["audit-2"].result is result["audit-3"].result is None


async def test_a_result_this_build_cannot_read_is_unavailable_rather_than_a_partial_verdict(monkeypatch):
    _Documents(GuardianInvestigation, [drifted_root(AUDIT, status="done", result={"peak": "catastrophic"})]).install(
        monkeypatch
    )

    summary = (await PublishedGuardianReader().summaries(ORG, [AUDIT]))[AUDIT]

    assert summary.availability == "unavailable"
    assert summary.status is None


async def test_device_rows_this_build_cannot_read_leave_the_audit_unavailable(monkeypatch):
    _Documents(GuardianInvestigation, [done_root()]).install(monkeypatch)
    _Documents(
        GuardianRun,
        [
            {
                "_id": FINAL,
                "organization_id": ORG,
                "investigation_id": ROOT,
                "verdict": {"impacted_devices": [{"mac": "not-a-mac"}], "impacted_devices_omitted": 1},
            }
        ],
    ).install(monkeypatch)

    summary = (await PublishedGuardianReader().summaries(ORG, [AUDIT], include_devices=True))[AUDIT]

    # The caller asked for the rows the overlay renders; a result without them would look site-clean.
    assert summary.availability == "unavailable"
    assert summary.impacted is None


async def test_empty_and_oversized_batches_do_not_query(monkeypatch):
    roots = _Documents(GuardianInvestigation, [done_root()]).install(monkeypatch)

    assert await PublishedGuardianReader().summaries(ORG, []) == {}
    with pytest.raises(ValueError, match="page limit"):
        await PublishedGuardianReader().summaries(ORG, [str(index) for index in range(MAX_PROJECTED_AUDITS + 1)])
    assert not roots.filters


async def test_device_rows_come_from_the_published_run_inside_the_tenant_not_the_capped_root_list(monkeypatch):
    rows = tuple(device(mac=f"5c5b3500{index:04d}") for index in range(MAX_ROOT_IMPACTED_DEVICES + 2))
    full = verdict(impacted_devices=rows, impacted_devices_omitted=3)
    _Documents(
        GuardianInvestigation, [done_root(result=published(**full.model_dump(include={"impacted_devices"})))]
    ).install(monkeypatch)
    runs = _Documents(
        GuardianRun, [run(verdict=full), run(id=PydanticObjectId(), organization_id=OTHER_ORG, verdict=full)]
    ).install(monkeypatch)

    summary = (await PublishedGuardianReader().summaries(ORG, [AUDIT], include_devices=True))[AUDIT]

    assert summary.result is not None
    assert len(summary.result.impacted_devices) == MAX_ROOT_IMPACTED_DEVICES  # The root list stays capped.
    assert summary.impacted is not None
    assert summary.impacted.devices == rows
    assert summary.impacted.omitted == 3
    assert runs.filters == [
        {"organization_id": ORG, "$or": [{"_id": FINAL, "investigation_id": ROOT}]},
    ]


async def test_an_unpublished_root_has_no_device_rows_to_overlay(monkeypatch):
    _Documents(GuardianInvestigation, [root()]).install(monkeypatch)
    runs = _Documents(GuardianRun, [run()]).install(monkeypatch)

    summary = (await PublishedGuardianReader().summaries(ORG, [AUDIT], include_devices=True))[AUDIT]

    assert summary.impacted is None
    assert not runs.filters


# --- the investigation read -------------------------------------------------------------------------------------


def investigation_documents(monkeypatch, *, runs: list[GuardianRun] | None = None, groups=None, roots=None):
    _Legacy.install(monkeypatch)
    return (
        _Documents(AuditChangeGroup, [group()] if groups is None else groups).install(monkeypatch),
        _Documents(GuardianInvestigation, [done_root()] if roots is None else roots).install(monkeypatch),
        _Documents(GuardianRun, runs if runs is not None else [run()]).install(monkeypatch),
    )


async def test_the_investigation_returns_the_root_its_published_runs_and_every_attempt(monkeypatch):
    early = run(
        id=EARLY,
        kind="early",
        attempt=2,
        verdict=verdict(peak="info", current="info", recovery="none", impacted_devices=()),
    )
    abandoned = run(
        id=PydanticObjectId(),
        kind="early",
        attempt=1,
        state="abandoned",
        failure_reason="Lease expired before the attempt finished",
        verdict=None,
    )
    investigation_documents(monkeypatch, runs=[abandoned, early, run()])

    detail = await guardian_investigation(ORG, GROUP)

    assert detail is not None
    assert (detail.root.id, detail.root.audit_id, detail.root.status) == (str(ROOT), AUDIT, "done")
    assert detail.root.result is not None
    assert detail.root.result.run_id == FINAL
    assert [(item.kind, item.attempt) for item in detail.runs] == [("early", 2), ("final", 1)]
    assert detail.runs[0].report.header is not None
    assert detail.runs[0].report.header.peak == "info"
    assert detail.runs[1].report.header is not None
    assert detail.runs[1].report.header.peak == "warning"
    assert [(item.kind, item.attempt, item.state, item.published) for item in detail.attempts] == [
        ("early", 1, "abandoned", False),
        ("early", 2, "succeeded", True),
        ("final", 1, "succeeded", True),
    ]
    assert detail.attempts[0].failure_reason == "Lease expired before the attempt finished"


async def test_runs_are_read_only_inside_the_organization_and_the_change_groups_investigation(monkeypatch):
    groups, roots, runs = investigation_documents(
        monkeypatch,
        runs=[
            run(),
            run(id=PydanticObjectId(), organization_id=OTHER_ORG),
            run(id=PydanticObjectId(), investigation_id=OTHER_ROOT),
        ],
    )

    detail = await guardian_investigation(ORG, GROUP)

    assert detail is not None
    assert [item.id for item in detail.attempts] == [str(FINAL)]
    assert groups.filters == [{"_id": GROUP, "organization_id": ORG}]
    assert roots.filters == [{"organization_id": ORG, "audit_id": AUDIT}]
    assert runs.filters == [{"organization_id": ORG, "investigation_id": ROOT}]
    assert runs.queries[0].limited == guardian_reads.MAX_RUNS


async def test_a_change_group_or_root_outside_the_organization_is_not_found(monkeypatch):
    investigation_documents(monkeypatch, groups=[group(organization_id=OTHER_ORG)])
    assert await guardian_investigation(ORG, GROUP) is None

    investigation_documents(monkeypatch, roots=[done_root(organization_id=OTHER_ORG)])
    assert await guardian_investigation(ORG, GROUP) is None

    investigation_documents(monkeypatch, groups=[group(audit_id="audit-other")])
    assert await guardian_investigation(ORG, GROUP) is None


async def test_a_published_pointer_to_a_missing_run_publishes_nothing(monkeypatch):
    investigation_documents(monkeypatch, runs=[])

    detail = await guardian_investigation(ORG, GROUP)

    assert detail is not None
    assert detail.runs == []
    assert detail.attempts == []
    assert detail.root.final_run_id == str(FINAL)  # The root still says what it points at.


async def test_a_root_this_build_cannot_read_is_not_served_as_an_investigation(monkeypatch):
    investigation_documents(monkeypatch, roots=[drifted_root(AUDIT)])

    assert await guardian_investigation(ORG, GROUP) is None
    assert await guardian_run(ORG, GROUP, FINAL) is None


async def test_an_attempt_this_build_cannot_read_is_counted_and_never_breaks_the_investigation(monkeypatch):
    drifted = {
        "_id": PydanticObjectId(),
        "organization_id": ORG,
        "investigation_id": ROOT,
        "audit_id": AUDIT,
        "kind": "final",
        "attempt": 2,
        "state": "quarantined",
    }
    investigation_documents(monkeypatch, runs=[run(), drifted])

    detail = await guardian_investigation(ORG, GROUP)

    assert detail is not None
    assert [(item.kind, item.attempt) for item in detail.attempts] == [("final", 1)]
    assert detail.unreadable_attempts == 1
    assert detail.runs[0].report.header is not None


# --- one run ----------------------------------------------------------------------------------------------------


async def test_one_full_run_is_returned_with_its_rendered_report_and_derived_publication(monkeypatch):
    investigation_documents(monkeypatch, runs=[run(obligations=(unseen_input(),))])

    detail = await guardian_run(ORG, GROUP, FINAL)

    assert detail is not None
    assert (detail.id, detail.kind, detail.attempt, detail.state) == (str(FINAL), "final", 1, "succeeded")
    assert detail.published is True
    assert detail.evidence[0].id == "E1"
    assert detail.evidence[0].payload == {"devices": {"satisfied:none": 4}}
    assert detail.steps == ({"turn": 1, "kind": "call", "evidence_id": "E1"},)
    assert detail.obligations[0].obligation.change_ref is None  # A core input obligation claims no atom.
    assert detail.report.header is not None
    assert detail.report.header.peak == "warning"
    assert detail.report.coverage.obligations.items[0].obligation.kind == "input"
    assert detail.verdict == run().verdict  # Rendered from what is stored; nothing is re-derived.


async def test_an_unpublished_run_is_returned_and_says_it_is_unpublished(monkeypatch):
    token = PydanticObjectId()
    investigation_documents(
        monkeypatch, runs=[run(id=token, kind="early", attempt=1, state="failed", failure_reason="x", verdict=None)]
    )

    detail = await guardian_run(ORG, GROUP, token)

    assert detail is not None
    assert detail.published is False
    assert detail.report.header is None
    assert detail.report.header_note is not None


async def test_a_run_this_build_cannot_read_is_not_found_rather_than_an_error(monkeypatch):
    token = PydanticObjectId()
    investigation_documents(
        monkeypatch,
        runs=[
            {
                "_id": token,
                "organization_id": ORG,
                "investigation_id": ROOT,
                "audit_id": AUDIT,
                "kind": "final",
                "attempt": 2,
                "state": "quarantined",
            }
        ],
    )

    assert await guardian_run(ORG, GROUP, token) is None


async def test_a_run_from_another_investigation_or_organization_is_not_found(monkeypatch):
    other_investigation = PydanticObjectId()
    _groups, _roots, runs = investigation_documents(
        monkeypatch,
        runs=[
            run(id=other_investigation, investigation_id=OTHER_ROOT),
            run(id=PydanticObjectId(), organization_id=OTHER_ORG),
        ],
    )

    assert await guardian_run(ORG, GROUP, other_investigation) is None
    assert await guardian_run(ORG, GROUP, PydanticObjectId()) is None
    assert runs.filters[0] == {"_id": other_investigation, "organization_id": ORG, "investigation_id": ROOT}


async def test_a_run_is_unreachable_through_another_organizations_change_group(monkeypatch):
    # The same audit, wholly owned by another organization: reachable by its owner, and by nobody else.
    investigation_documents(
        monkeypatch,
        groups=[group(organization_id=OTHER_ORG)],
        roots=[done_root(id=OTHER_ROOT, organization_id=OTHER_ORG)],
        runs=[run(organization_id=OTHER_ORG, investigation_id=OTHER_ROOT)],
    )

    assert await guardian_run(OTHER_ORG, GROUP, FINAL) is not None
    assert await guardian_run(ORG, GROUP, FINAL) is None
    assert await guardian_investigation(ORG, GROUP) is None


# --- the endpoints ----------------------------------------------------------------------------------------------


@pytest.fixture
def api():
    app = FastAPI()
    app.include_router(routes.router, prefix="/api/v1")
    app.dependency_overrides[require_organization] = lambda: SimpleNamespace(id=ORG)
    app.dependency_overrides[require_viewer] = lambda: SimpleNamespace(email="viewer@example.test")
    return TestClient(app)


def test_the_endpoints_answer_the_investigation_and_one_run(api, monkeypatch):
    investigation_documents(monkeypatch)

    investigation = api.get(f"/api/v1/organizations/{ORG}/change-groups/{GROUP}/guardian")
    detail = api.get(f"/api/v1/organizations/{ORG}/change-groups/{GROUP}/guardian/runs/{FINAL}")

    assert investigation.status_code == 200
    assert investigation.json()["root"]["audit_id"] == AUDIT
    assert [item["kind"] for item in investigation.json()["runs"]] == ["final"]
    assert detail.status_code == 200
    assert detail.json()["published"] is True
    assert detail.json()["report"]["header"]["peak"] == "warning"


def test_unknown_change_groups_roots_and_runs_answer_not_found(api, monkeypatch):
    investigation_documents(monkeypatch, groups=[], roots=[])
    missing = PydanticObjectId()

    assert api.get(f"/api/v1/organizations/{ORG}/change-groups/{missing}/guardian").status_code == 404
    assert api.get(f"/api/v1/organizations/{ORG}/change-groups/{missing}/guardian/runs/{FINAL}").status_code == 404

    investigation_documents(monkeypatch, runs=[])
    assert api.get(f"/api/v1/organizations/{ORG}/change-groups/{GROUP}/guardian/runs/{missing}").status_code == 404


def test_the_legacy_investigation_routes_are_still_served(api):
    paths = set(api.app.openapi()["paths"])  # type: ignore[attr-defined]
    prefix = "/api/v1/organizations/{organization_id}/change-groups/{change_group_id}"
    assert {
        f"{prefix}/investigation",
        f"{prefix}/investigation/history",
        f"{prefix}/investigation/model-requests/{{request_id}}",
        f"{prefix}/investigation/mcp-requests/{{request_id}}",
        f"{prefix}/investigation/adjudication",
        f"{prefix}/investigation/acceptance",
        f"{prefix}/guardian",
        f"{prefix}/guardian/runs/{{run_id}}",
    } <= paths


def test_the_run_response_carries_a_pinned_set_of_the_run_document():
    """A new field on the run document is a decision here, not a silent addition or omission."""
    # Identity and tenancy the caller already has, retention and timestamps no reader acts on, and Beanie's own
    # revision marker.
    internal = {
        "id",
        "organization_id",
        "investigation_id",
        "retained_until",
        "created_at",
        "updated_at",
        "revision_id",
    }
    assert set(GuardianRun.model_fields) - internal == CARRIED_RUN_FIELDS
    assert set(GuardianRunResponse.model_fields) == CARRIED_RUN_FIELDS | {
        "id",
        "investigation_id",
        "published",
        "report",
    }


def test_a_drifted_run_answers_not_found_through_the_endpoint(api, monkeypatch):
    token = PydanticObjectId()
    investigation_documents(
        monkeypatch,
        runs=[{"_id": token, "organization_id": ORG, "investigation_id": ROOT, "state": "quarantined"}],
    )

    response = api.get(f"/api/v1/organizations/{ORG}/change-groups/{GROUP}/guardian/runs/{token}")

    assert response.status_code == 404


def test_the_run_read_filter_comes_from_the_repository():
    read = repo.run_in_investigation(FINAL, root_id=ROOT, organization_id=ORG)
    assert read.filter == {"_id": FINAL, "organization_id": ORG, "investigation_id": ROOT}
    assert repo.investigation_runs(ROOT, organization_id=ORG).filter == {
        "organization_id": ORG,
        "investigation_id": ROOT,
    }
