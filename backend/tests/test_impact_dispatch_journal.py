"""Dispatch records survive failure independently of evidence publication."""

import asyncio
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from beanie import PydanticObjectId
from bson import BSON
from bson.codec_options import CodecOptions
from pydantic import ValidationError
from pymongo.errors import ConnectionFailure

from mist_config_guardian_backend.impact.contracts import DispatchDenial, SessionEvidence, Window
from mist_config_guardian_backend.impact.dispatch import DispatchRecord
from mist_config_guardian_backend.models.organization import OrganizationStatus
from mist_config_guardian_backend.services import impact_investigations as runtime
from mist_config_guardian_backend.services import investigation_reads
from test_impact_investigation_runtime import setup_runtime
from test_wlan_investigation import LATER, NOW, ORG


def journal_runtime(monkeypatch):
    service, root, collection, artifacts, _ = setup_runtime(monkeypatch)
    stored = {"generation": root.generation, "calls_used": 0, "dispatches": []}

    async def update(query, update):
        # Exercise actual BSON encoding with the application's default UUID codec.
        BSON.encode(query)
        encoded = BSON(BSON.encode(update)).decode(codec_options=CodecOptions(tz_aware=True))
        assert query["_id"] == root.id
        assert query["organization_id"] == ORG
        if "$inc" in update:
            if (
                query["generation"] != stored["generation"]
                or stored["calls_used"] >= root.calls_limit
                or len(stored["dispatches"]) >= 56
            ):
                return SimpleNamespace(matched_count=0)
            stored["calls_used"] += 1
            stored["dispatches"].append(encoded["$push"]["dispatches"])
        elif "dispatches" in query:
            predicate = query["dispatches"]["$elemMatch"]
            matching = [
                record
                for record in stored["dispatches"]
                if all(record[key] == value for key, value in predicate.items())
            ]
            if not matching:
                return SimpleNamespace(matched_count=0)
            for key, value in encoded["$set"].items():
                matching[0][key.removeprefix("dispatches.$.")] = value
        elif query["generation"] != stored["generation"]:
            return SimpleNamespace(matched_count=0)
        return SimpleNamespace(matched_count=1)

    async def read(query, projection):
        assert query == {"_id": root.id, "organization_id": ORG}
        assert projection["dispatches"] == {"$slice": [55, 1]}
        return {**stored, "lease_until": root.lease_until, "dispatches": stored["dispatches"][55:56]}

    collection.find_one.side_effect = read
    collection.update_one.side_effect = update
    return service, root, collection, artifacts, stored


def empty_response(request):
    return httpx.Response(
        200,
        json={
            "start": int(request.url.params["start"]),
            "end": int(request.url.params["end"]),
            "results": [],
            "total": 0,
        },
    )


async def test_reservation_and_budget_are_durable_before_http_with_typed_result_metadata(monkeypatch, httpx_mock):
    service, root, collection, artifacts, stored = journal_runtime(monkeypatch)

    def respond(request):
        record = stored["dispatches"][-1]
        assert record["state"] == "reserved"
        assert stored["calls_used"] == len(stored["dispatches"])
        assert record["finished_at"] is None
        return empty_response(request)

    httpx_mock.add_callback(respond, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert len(artifacts) == 1
    assert len(stored["dispatches"]) == 2
    for raw in stored["dispatches"]:
        record = DispatchRecord.model_validate(raw)
        assert record.state == "complete"
        assert record.http_status == 200
        assert record.response_bytes > 0
        assert record.row_count == 0
        assert record.generation == root.generation
        assert record.candidate_revision == root.revision + 1
    assert len({record["id"] for record in stored["dispatches"]}) == 2
    for call in collection.update_one.await_args_list:
        if "$inc" in call.args[1]:
            assert call.args[0]["dispatches.55"] == {"$exists": False}


@pytest.mark.parametrize("failure", ["http", "invalid", "timeout", "partial"])
async def test_failures_preserve_diagnostics_without_provider_text(monkeypatch, httpx_mock, failure):
    service, root, _, artifacts, stored = journal_runtime(monkeypatch)

    def respond(request):
        if failure == "http":
            return httpx.Response(503, text="secret-provider-message")
        if failure == "invalid":
            return httpx.Response(200, text="secret-invalid-json")
        if failure == "timeout":
            message = "secret-transport-error"
            raise httpx.ReadTimeout(message)
        payload = empty_response(request).json()
        payload["next"] = "https://attacker.invalid/secret-cursor"
        return httpx.Response(200, json=payload)

    httpx_mock.add_callback(respond, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    for raw in stored["dispatches"]:
        record = DispatchRecord.model_validate(raw)
        assert record.state == ("partial" if failure == "partial" else "error")
        assert record.http_status == (503 if failure == "http" else None if failure == "timeout" else 200)
        assert record.finished_at is not None
        assert "secret" not in record.model_dump_json()
        assert "attacker" not in record.model_dump_json()
    assert artifacts[0].assessment.impact == "info"
    assert len(httpx_mock.get_requests()) == 2


@pytest.mark.parametrize("committed", [False, True])
async def test_uncertain_reservation_never_dispatches(monkeypatch, httpx_mock, committed):
    service, root, collection, artifacts, stored = journal_runtime(monkeypatch)
    normal = collection.update_one.side_effect

    async def fail(query, update):
        if committed:
            await normal(query, update)
        message = "write acknowledgement lost"
        raise ConnectionFailure(message)

    collection.update_one.side_effect = fail
    with pytest.raises(ConnectionFailure):
        await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    assert not artifacts
    assert stored["calls_used"] == int(committed)
    if committed:
        assert stored["dispatches"][0]["state"] == "reserved"


async def test_completion_failure_retains_unknown_outcome_and_stops_publication(monkeypatch, httpx_mock):
    service, root, collection, artifacts, stored = journal_runtime(monkeypatch)
    normal = collection.update_one.side_effect

    async def fail(query, update):
        if "dispatches" in query:
            message = "completion failed"
            raise ConnectionFailure(message)
        return await normal(query, update)

    collection.update_one.side_effect = fail
    httpx_mock.add_callback(empty_response)
    with pytest.raises(ConnectionFailure):
        await service._poll(root)  # noqa: SLF001
    assert len(httpx_mock.get_requests()) == 1
    assert stored["calls_used"] == 1
    assert stored["dispatches"][0]["state"] == "reserved"
    assert not artifacts


async def test_cancellation_leaves_reservation_without_fabricating_a_result(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = journal_runtime(monkeypatch)

    def cancel(_request):
        raise asyncio.CancelledError

    httpx_mock.add_callback(cancel)
    with pytest.raises(asyncio.CancelledError):
        await service._poll(root)  # noqa: SLF001
    assert stored["dispatches"][0]["state"] == "reserved"
    assert stored["dispatches"][0]["finished_at"] is None
    assert not artifacts


async def test_lost_lease_can_complete_own_log_but_cannot_dispatch_again_or_publish(monkeypatch, httpx_mock):
    service, root, collection, artifacts, stored = journal_runtime(monkeypatch)

    def steal_lease(request):
        stored["generation"] += 1
        return empty_response(request)

    httpx_mock.add_callback(steal_lease)
    await service._poll(root)  # noqa: SLF001
    assert len(httpx_mock.get_requests()) == 1
    assert stored["dispatches"][0]["state"] == "complete"
    assert stored["generation"] == root.generation + 1
    # Artifact creation is permitted; the final root publication fence still fails.
    assert len(artifacts) == 1
    assert collection.update_one.await_args.args[0]["generation"] == root.generation
    completion = next(call for call in collection.update_one.await_args_list if "dispatches" in call.args[0])
    assert "generation" not in completion.args[0]
    assert completion.args[0]["dispatches"]["$elemMatch"]["generation"] == root.generation


async def test_live_journal_and_legacy_gaps_do_not_require_a_published_report(monkeypatch):
    _, root, _, _, _ = journal_runtime(monkeypatch)
    root.calls_used = 4
    monkeypatch.setattr(
        investigation_reads.AuditChangeGroup,
        "find_one",
        AsyncMock(return_value=SimpleNamespace(audit_id=root.audit_id)),
    )
    monkeypatch.setattr(investigation_reads.ImpactInvestigation, "find_one", AsyncMock(return_value=root))
    response = await investigation_reads.shadow_investigation(ORG, PydanticObjectId())
    assert response.assessment is None
    assert response.dispatch_log.source == "live_investigation_root"
    assert response.dispatch_log.unlogged_reservations == 4
    assert response.dispatch_log.records == ()


@pytest.mark.parametrize("field", ["headers", "response_body", "configuration"])
def test_journal_contract_cannot_accept_raw_payload_or_headers(field):
    record = DispatchRecord(
        id=uuid4(),
        generation=1,
        candidate_revision=1,
        target_handle="a" * 64,
        site_id=uuid4(),
        wlan_id=uuid4(),
        reserved_at=LATER,
        window=Window(start=NOW, end=LATER),
    )
    with pytest.raises(ValidationError):
        DispatchRecord.model_validate({**record.model_dump(), field: {"Authorization": "secret"}})


async def test_journal_cap_is_independent_of_a_larger_call_limit(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = journal_runtime(monkeypatch)
    root.calls_limit = 100
    stored["dispatches"] = [{}] * 56
    await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    assert stored["calls_used"] == 0
    assert len(stored["dispatches"]) == 56
    assert artifacts[0].assessment.impact == "info"


async def test_completed_record_cannot_be_overwritten(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = journal_runtime(monkeypatch)
    httpx_mock.add_callback(empty_response, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    record = DispatchRecord.model_validate(stored["dispatches"][0])
    with pytest.raises(RuntimeError, match="could not be recorded"):
        await service._finish_dispatch(root, record, artifacts[0].evidence[0])  # noqa: SLF001
    assert DispatchRecord.model_validate(stored["dispatches"][0]) == record


async def test_result_for_another_handle_cannot_complete_a_reservation(monkeypatch, httpx_mock):
    service, root, collection, artifacts, stored = journal_runtime(monkeypatch)
    httpx_mock.add_callback(empty_response, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    record = DispatchRecord.model_validate(stored["dispatches"][0])
    reading = artifacts[0].evidence[0].model_copy(update={"target_handle": "b" * 64})
    collection.update_one.reset_mock()
    with pytest.raises(ValueError, match="identity does not match"):
        await service._finish_dispatch(root, record, reading)  # noqa: SLF001
    collection.update_one.assert_not_awaited()


@pytest.mark.parametrize(
    "cause", ["revoked", "changed", "expired", "budget", "journal", "lease", "missing", "read_error", "unknown"]
)
async def test_denials_explain_the_blocker_without_dispatch_or_budget_use(monkeypatch, httpx_mock, cause):
    service, root, collection, artifacts, stored = journal_runtime(monkeypatch)
    original_get = runtime.Organization.get
    organization = await original_get(ORG)
    expected = DispatchDenial.RESERVATION_REJECTED
    if cause in {"revoked", "changed", "expired"}:
        replacement = SimpleNamespace(
            status=OrganizationStatus.DISABLED if cause == "revoked" else OrganizationStatus.VERIFIED,
            encrypted_service_token="replacement" if cause == "changed" else organization.encrypted_service_token,
        )

        async def fresh(_org_id):
            if cause == "expired":
                monkeypatch.setattr(runtime, "utc_now", lambda: root.expires_at + timedelta(minutes=3))
            return replacement

        async def get(org_id):
            runtime.Organization.get.side_effect = fresh
            return await original_get(org_id)

        monkeypatch.setattr(runtime.Organization, "get", AsyncMock(side_effect=get))
        expected = {
            "revoked": DispatchDenial.CREDENTIALS_UNAVAILABLE,
            "changed": DispatchDenial.CREDENTIALS_CHANGED,
            "expired": DispatchDenial.WINDOW_EXPIRED,
        }[cause]
    elif cause == "budget":
        stored["calls_used"] = root.calls_limit
        expected = DispatchDenial.BUDGET_EXHAUSTED
    elif cause == "journal":
        stored["dispatches"] = [{}] * 56
        expected = DispatchDenial.JOURNAL_FULL
    elif cause == "lease":
        stored["generation"] += 1
        expected = DispatchDenial.LEASE_LOST
    else:
        collection.update_one.side_effect = None
        collection.update_one.return_value = SimpleNamespace(matched_count=0)
        if cause == "read_error":
            collection.find_one.side_effect = ConnectionFailure("secret connection detail")
        elif cause == "missing":
            collection.find_one.side_effect = None
            collection.find_one.return_value = None
    used_before, records_before = stored["calls_used"], len(stored["dispatches"])
    await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    assert stored["calls_used"] == used_before
    assert len(stored["dispatches"]) == records_before
    assert len(artifacts[0].evidence) == 1  # Stop at the first denial, including remaining targets/windows.
    evidence = artifacts[0].evidence[0]
    assert evidence.state == "dispatch_denied"
    assert evidence.dispatch_denial is expected
    assert evidence.reason == expected.explanation
    assert evidence.http_status is evidence.response_bytes is None
    assert artifacts[0].assessment.impact == "info"
    assert collection.find_one.await_count == int(cause not in {"revoked", "changed", "expired"})
    # The API preserves the discriminant independently of the human-readable message.
    artifact = artifacts[0]
    root.report_id, root.revision = artifact.id, artifact.revision
    monkeypatch.setattr(runtime.ImpactInvestigation, "find_one", AsyncMock(return_value=root))
    monkeypatch.setattr(runtime.InvestigationRevision, "find_one", AsyncMock(return_value=artifact))
    response = await investigation_reads.shadow_investigation(ORG, PydanticObjectId())
    assert response.checks[0].dispatch_denial is expected
    assert "secret connection detail" not in response.model_dump_json()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("state", "complete"),
        ("dispatch_denial", None),
        ("http_status", 200),
        ("response_bytes", 0),
    ],
)
def test_dispatch_denial_cannot_claim_a_collected_response(field, value):
    denied = SessionEvidence(
        target_handle="a" * 64,
        window=Window(start=NOW, end=LATER),
        captured_at=LATER,
        state="dispatch_denied",
        dispatch_denial=DispatchDenial.CREDENTIALS_CHANGED,
    )
    with pytest.raises(ValidationError):
        SessionEvidence.model_validate({**denied.model_dump(), field: value})
