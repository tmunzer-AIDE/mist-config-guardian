"""Private source provenance and spend-neutral AP inventory discovery."""

import re
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import httpx
import pytest
from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder
from bson import BSON
from bson.codec_options import CodecOptions
from pymongo.errors import ConnectionFailure

from mist_config_guardian_backend.impact.agent import capabilities
from mist_config_guardian_backend.impact.contracts import NeighborEvidence
from mist_config_guardian_backend.integrations import mist_neighbor_evidence, mist_port_evidence
from mist_config_guardian_backend.models import document_models
from mist_config_guardian_backend.models.investigation import InvestigationRevision
from mist_config_guardian_backend.models.neighbor_binding import NeighborBinding
from mist_config_guardian_backend.services import impact_investigations as runtime
from mist_config_guardian_backend.services import investigation_reads, neighbor_bindings
from test_impact_agent import AI_URL, agent_runtime, ai_response, read_context
from test_impact_change_context import gap_report, use_data
from test_impact_dispatch_journal import empty_response
from test_impact_mixed_publication import mixed_inputs
from test_impact_port_scope import payload, port_inputs
from test_wlan_investigation import LATER, SITE

MIST_ORG = UUID("22222222-2222-4222-8222-222222222222")
CANDIDATE = "001122334455"
PORT_URL = re.compile(r".*/stats/ports/search\?.*")
INVENTORY_URL = re.compile(r".*/inventory/search\?.*")


def neighbor_runtime(monkeypatch, mode="shadow", *, mixed=False):
    service, root, collection, artifacts, stored = agent_runtime(monkeypatch)
    organization = runtime.Organization.get.return_value
    organization.mist_org_id = MIST_ORG
    organization.monitoring_retention_days = 90
    monkeypatch.setattr(runtime, "get_settings", lambda: SimpleNamespace(impact_engine_mode=mode))
    # Non-millisecond timestamps exercise the real BSON precision boundary.
    precise = LATER.replace(microsecond=123456)
    for module in (runtime, neighbor_bindings, mist_port_evidence, mist_neighbor_evidence):
        monkeypatch.setattr(module, "utc_now", lambda: precise)
    use_data(service, mixed_inputs() if mixed else port_inputs())
    stored["bindings"] = []
    monkeypatch.setattr(NeighborBinding, "get_pymongo_collection", lambda *_: collection)

    async def insert(artifact, **_kwargs):
        encoded = BSON(BSON.encode(Encoder().encode(artifact.model_dump(by_alias=True)))).decode(
            codec_options=CodecOptions(tz_aware=True)
        )
        persisted = NeighborBinding.model_validate(encoded)
        assert persisted.identity == artifact.identity
        stored["bindings"].append(persisted)
        return artifact

    async def find(query):
        # Beanie encodes the exact nested identity before dispatch to Mongo.
        BSON.encode(Encoder().encode(query))
        return next((a for a in stored["bindings"] if a.id == query["_id"]), None)

    monkeypatch.setattr(NeighborBinding, "insert", insert)
    monkeypatch.setattr(NeighborBinding, "find_one", AsyncMock(side_effect=find))
    normal_read = collection.find_one.side_effect

    async def read(query, projection):
        if "$elemMatch" not in projection.get("dispatches", {}):
            return await normal_read(query, projection)
        assert query == {
            "_id": root.id,
            "organization_id": root.organization_id,
            "generation": root.generation,
            "revision": root.revision,
        }
        predicate = projection["dispatches"]["$elemMatch"]
        records = [d for d in stored["dispatches"] if all(d[k] == v for k, v in predicate.items())]
        return {**query, "generation": stored["generation"], "dispatches": records}

    collection.find_one.side_effect = read
    return service, root, collection, artifacts, stored


def inventory_payload():
    return {
        "total": 1,
        "results": [
            {
                "mac": CANDIDATE,
                "org_id": str(MIST_ORG),
                "site_id": str(SITE),
                "type": "ap",
                "status": "disconnected",
                "name": "secret-injected-name",
                "magic": "secret-claim-code",
            }
        ],
    }


def register_port(httpx_mock):
    httpx_mock.add_callback(
        lambda request: httpx.Response(200, json=payload(port_id=request.url.params["port_id"])),
        method="GET",
        url=PORT_URL,
        is_reusable=True,
    )


@pytest.mark.parametrize("mode", ["shadow", "agent_shadow"])
async def test_maximal_discovery_publishes_twelve_checks_without_extra_agent_reads(monkeypatch, httpx_mock, mode):
    service, root, collection, artifacts, stored = neighbor_runtime(monkeypatch, mode, mixed=True)
    register_port(httpx_mock)
    httpx_mock.add_callback(
        empty_response,
        method="GET",
        url=re.compile(r".*/clients/sessions/search\?.*"),
        is_reusable=True,
    )

    def inventory(request):
        assert dict(request.url.params) == {"type": "ap", "site_id": str(SITE), "mac": CANDIDATE, "limit": "2"}
        assert request.url.path == f"/api/v1/orgs/{MIST_ORG}/inventory/search"
        assert len(stored["bindings"]) == 2
        assert all(d["state"] == "complete" for d in stored["dispatches"] if d["port_id"])
        assert stored["dispatches"][-1]["state"] == "reserved"
        return httpx.Response(200, json=inventory_payload())

    httpx_mock.add_callback(inventory, method="GET", url=INVENTORY_URL, is_reusable=True)
    if mode == "agent_shadow":

        def model(request):
            context = read_context(request)
            assert CANDIDATE not in str(context)
            assert "secret-" not in str(context)
            observed = {e["ref"] for e in context["observations"]}
            missing = [c["ref"] for c in context["capabilities"] if c["ref"] not in observed]
            assert len(context["capabilities"]) == 12
            return ai_response({"action": "collect", "checks": missing[:8]} if missing else gap_report())

        httpx_mock.add_callback(model, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert len(capabilities(artifact.plan, artifact.evidence[0].window.end)) == 12
    assert len(artifact.evidence) == stored["calls_used"] == len(stored["dispatches"]) == 12
    assert all(d["state"] == "complete" for d in stored["dispatches"])
    neighbors = [e for e in artifact.evidence if isinstance(e, NeighborEvidence)]
    assert len(neighbors) == 2
    assert all(e.state == "complete" and e.rows[0].relationship == "unverified" for e in neighbors)
    assert artifact.assessment.impact == "info"
    assert all(f.impact == "none" for f in artifact.assessment.findings)
    assert InvestigationRevision.model_validate_json(artifact.model_dump_json()).evidence == artifact.evidence
    assert CANDIDATE not in artifact.model_dump_json()
    assert CANDIDATE not in str(stored["dispatches"])
    assert CANDIDATE not in str(stored["model_artifacts"])
    assert all(CANDIDATE not in b.model_dump_json() for b in stored["bindings"])
    publications = [c for c in collection.update_one.await_args_list if "report_id" in c.args[1].get("$set", {})]
    assert len(publications) == 1
    if mode == "agent_shadow":
        assert artifact.agent.state == "complete"
        assert stored["model_calls_used"] == 3


@pytest.mark.parametrize("mutation", ["org", "site", "mac", "type", "alias", "multiple", "missing", "cursor", "http"])
async def test_inventory_rejects_ambiguity_and_scope_without_recursive_queries(monkeypatch, httpx_mock, mutation):
    service, root, _, artifacts, stored = neighbor_runtime(monkeypatch)
    register_port(httpx_mock)
    response = inventory_payload()
    if mutation in {"org", "site", "mac", "type"}:
        response["results"][0][{"org": "org_id", "site": "site_id"}.get(mutation, mutation)] = "secret-wrong"
    elif mutation == "alias":
        response["results"][0]["vc_mac"] = "secret-alias"
    elif mutation == "multiple":
        response["total"] = 2
    elif mutation == "missing":
        response = {"total": 0, "results": []}
    elif mutation == "cursor":
        response["next"] = "https://attacker.invalid/secret"
    httpx_mock.add_response(
        method="GET", url=INVENTORY_URL, json=response, status_code=429 if mutation == "http" else 200
    )
    await service._poll(root)  # noqa: SLF001
    reading = artifacts[0].evidence[-1]
    assert isinstance(reading, NeighborEvidence)
    assert reading.state == ("partial" if mutation in {"multiple", "missing", "cursor"} else "error")
    assert not reading.rows
    assert "secret" not in reading.model_dump_json()
    assert len(httpx_mock.get_requests()) == stored["calls_used"] == 2


@pytest.mark.parametrize("committed", [False, True])
async def test_uncertain_private_insert_leaves_source_reserved_and_never_queries_inventory(
    monkeypatch, httpx_mock, committed
):
    service, root, _, artifacts, stored = neighbor_runtime(monkeypatch)
    normal = NeighborBinding.insert

    async def fail(artifact, **kwargs):
        if committed:
            await normal(artifact, **kwargs)
        message = "uncertain private insert"
        raise ConnectionFailure(message)

    monkeypatch.setattr(NeighborBinding, "insert", fail)
    register_port(httpx_mock)
    with pytest.raises(ConnectionFailure):
        await service._poll(root)  # noqa: SLF001
    assert len(stored["bindings"]) == int(committed)
    assert len(httpx_mock.get_requests()) == 1
    assert stored["dispatches"][0]["state"] == "reserved"
    assert not artifacts


@pytest.mark.parametrize(
    "fault", ["artifact", "digest", "ciphertext", "audit", "site", "revision", "generation", "journal", "source"]
)
async def test_binding_tampering_never_authorizes_inventory(monkeypatch, httpx_mock, fault):
    service, root, collection, artifacts, stored = neighbor_runtime(monkeypatch)
    normal_find = NeighborBinding.find_one.side_effect

    async def find(query):
        artifact = await normal_find(query)
        if fault == "artifact":
            return None
        if fault == "digest":
            return artifact.model_copy(update={"content_hash": "0" * 64})
        if fault == "ciphertext":
            return artifact.model_copy(update={"encrypted_mac": "invalid"})
        if fault in {"audit", "site", "revision", "generation"}:
            identity = artifact.identity
            change = {
                "audit": {"audit_id": "foreign-audit"},
                "site": {"mist_org_id": UUID(int=0)},
                "revision": {"candidate_revision": identity.candidate_revision + 1},
                "generation": {"generation": identity.generation + 1},
            }[fault]
            return artifact.model_copy(update={"identity": identity.model_copy(update=change)})
        return artifact

    monkeypatch.setattr(NeighborBinding, "find_one", AsyncMock(side_effect=find))
    if fault == "journal":
        normal = collection.find_one.side_effect

        async def read(query, projection):
            doc = await normal(query, projection)
            doc["dispatches"] = []
            return doc

        collection.find_one.side_effect = read
    if fault == "source":
        normal = neighbor_bindings.NeighborBindingStore.persist

        async def persist(self, identity, _mac):
            return await normal(self, identity, "001122334466")

        monkeypatch.setattr(neighbor_bindings.NeighborBindingStore, "persist", persist)
    register_port(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].evidence[-1].state == "binding_unavailable"
    assert artifacts[0].assessment.impact == "info"
    assert len(httpx_mock.get_requests()) == stored["calls_used"] == 1


def test_private_collection_has_expiring_orphan_retention():
    assert NeighborBinding in document_models()
    ttl = NeighborBinding.Settings.indexes[-1].document
    assert ttl["expireAfterSeconds"] == 0
    assert dict(ttl["key"]) == {"identity.expires_at": 1}


@pytest.mark.parametrize("fault", ["expired", "credentials", "completion", "lease"])
async def test_private_source_never_bypasses_live_dispatch_authority(monkeypatch, httpx_mock, fault):
    service, root, collection, artifacts, stored = neighbor_runtime(monkeypatch)
    register_port(httpx_mock)
    normal = collection.update_one.side_effect

    async def update(query, mutation):
        if "dispatches" in query and fault == "completion":
            message = "source completion acknowledgement lost"
            raise ConnectionFailure(message)
        result = await normal(query, mutation)
        if "dispatches" in query:
            if fault == "credentials":
                runtime.Organization.get.return_value.encrypted_service_token = "revoked"
            if fault == "lease":
                stored["generation"] += 1
            if fault == "expired":
                monkeypatch.setattr(neighbor_bindings, "utc_now", lambda: LATER + timedelta(days=91))
        return result

    collection.update_one.side_effect = update
    if fault == "completion":
        with pytest.raises(ConnectionFailure):
            await service._poll(root)  # noqa: SLF001
        assert not artifacts
        assert stored["dispatches"][0]["state"] == "reserved"
    else:
        await service._poll(root)  # noqa: SLF001
        reading = artifacts[0].evidence[-1]
        assert reading.state == ("dispatch_denied" if fault == "credentials" else "binding_unavailable")
        if fault == "credentials":
            assert reading.dispatch_denial == "credentials_changed"
            assert collection.update_one.await_args.args[1]["$set"]["next_poll_at"] is None
    assert len(stored["bindings"]) == 1
    assert stored["calls_used"] == len(httpx_mock.get_requests()) == 1


async def test_public_preview_exposes_inventory_result_without_private_binding(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = neighbor_runtime(monkeypatch)
    register_port(httpx_mock)
    httpx_mock.add_response(url=INVENTORY_URL, json=inventory_payload())
    await service._poll(root)  # noqa: SLF001
    root.report_id = artifacts[0].id
    root.revision = artifacts[0].revision
    monkeypatch.setattr(investigation_reads, "read_investigation_root", AsyncMock(return_value=root))
    monkeypatch.setattr(InvestigationRevision, "find_one", AsyncMock(return_value=artifacts[0]))
    preview = await investigation_reads.shadow_investigation(root.organization_id, PydanticObjectId())
    row = preview.checks[-1]
    assert row.managed_neighbor.identity == "verified_inventory"
    assert row.managed_neighbor.relationship == "unverified"
    assert row.device_mac is None
    encoded = preview.model_dump_json()
    for value in [CANDIDATE, "secret-", "candidate_binding", "encrypted_mac", str(stored["bindings"][0].id)]:
        assert value not in encoded


@pytest.mark.parametrize("fault", ["candidate_mac", "candidate_site", "target", "window"])
async def test_inventory_executor_rejects_unplanned_arguments_before_reserving(monkeypatch, httpx_mock, fault):
    service, root, _, artifacts, _ = neighbor_runtime(monkeypatch)
    register_port(httpx_mock)
    httpx_mock.add_response(url=INVENTORY_URL, json=inventory_payload())
    await service._poll(root)  # noqa: SLF001
    plan = artifacts[0].plan
    target = plan.neighbor_targets[0]
    candidate = mist_neighbor_evidence.PrivateCandidate(CANDIDATE, MIST_ORG, SITE)
    window = artifacts[0].evidence[-1].window
    if fault == "candidate_mac":
        candidate = mist_neighbor_evidence.PrivateCandidate("*", MIST_ORG, SITE)
    elif fault == "candidate_site":
        candidate = mist_neighbor_evidence.PrivateCandidate(CANDIDATE, MIST_ORG, UUID(int=0))
    elif fault == "target":
        target = target.model_copy(update={"handle": "0" * 64})
    else:
        window = window.model_copy(update={"end": window.end + timedelta(hours=2)})
    reserve = AsyncMock(return_value=None)
    async with mist_neighbor_evidence.MistNeighborEvidenceClient(
        token="test", region=runtime.Organization.get.return_value.cloud_region
    ) as client:
        with pytest.raises(ValueError, match="not authorized"):
            await client.capture_neighbor(
                plan=plan, target=target, candidate=candidate, window=window, reserve_dispatch=reserve
            )
    reserve.assert_not_awaited()
    assert len(httpx_mock.get_requests()) == 2


async def test_dynamic_maximal_plan_stops_at_fifty_six_reads(monkeypatch, httpx_mock):
    service, root, collection, artifacts, stored = neighbor_runtime(monkeypatch, mixed=True)
    root.revision = 0
    register_port(httpx_mock)
    httpx_mock.add_callback(
        empty_response, method="GET", url=re.compile(r".*/clients/sessions/search\?.*"), is_reusable=True
    )
    httpx_mock.add_response(url=INVENTORY_URL, json=inventory_payload(), is_reusable=True)
    for checkpoint in range(5):
        now = root.changed_at + timedelta(minutes=1 if checkpoint == 0 else checkpoint * 10)
        for module in (runtime, neighbor_bindings, mist_port_evidence, mist_neighbor_evidence):
            monkeypatch.setattr(module, "utc_now", lambda now=now: now)
        root.generation += 1
        stored["generation"] = root.generation
        root.lease_until = now + timedelta(minutes=3)
        await service._poll(root)  # noqa: SLF001
        for key, value in collection.update_one.await_args.args[1]["$set"].items():
            setattr(root, key, value)
    assert stored["calls_used"] == len(httpx_mock.get_requests()) == 56
    assert [len(a.evidence) for a in artifacts] == [12, 12, 12, 12, 9]
    assert artifacts[-1].evidence[-1].dispatch_denial == "budget_exhausted"
    assert root.next_poll_at is None
    assert root.status == "incomplete"
