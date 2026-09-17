"""Guardian lifecycle builders execute on MongoDB 8 with the fencing, phases and $$NOW timing they encode.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB. Time passing is simulated by moving stored instants
(``changed_at``, ``next_check_at``, ``claim.lease_until``) into the past; every predicate still runs on the server.
"""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from beanie.odm.utils.encoder import Encoder
from pymongo import AsyncMongoClient
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.guardian import repository as repo
from mist_config_guardian_backend.guardian.contracts import CompactImpactedDevice, RunKind, Verdict
from mist_config_guardian_backend.models.guardian import GuardianInvestigation, GuardianResult, GuardianRun, bson_size

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "guardian_repository"
ORG = PydanticObjectId()
PAST = timedelta(seconds=1)

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[GuardianInvestigation, GuardianRun])
    yield
    await client.drop_database(DATABASE)
    await client.close()


def roots():
    return GuardianInvestigation.get_pymongo_collection()


def runs():
    return GuardianRun.get_pymongo_collection()


async def apply(collection, write: repo.Write) -> int:
    result = await collection.update_one(write.filter, write.update, upsert=write.upsert)
    return result.modified_count


async def shift(root_id, **instants: timedelta) -> None:
    """Move stored instants relative to now, standing in for elapsed server time."""
    now = datetime.now(UTC)
    await roots().update_one({"_id": root_id}, {"$set": {k: now + delta for k, delta in instants.items()}})


async def new_root(changed: timedelta) -> PydanticObjectId:
    now = datetime.now(UTC)
    write = repo.ensure_investigation(
        organization_id=ORG,
        audit_id=str(uuid4()),
        changed_at=now - changed,
        anchor_known=True,
        now=now,
        retained_until=now + timedelta(days=1),
    )
    result = await roots().update_one(write.filter, write.update, upsert=True)
    await shift(result.upserted_id, next_check_at=-PAST)
    return PydanticObjectId(result.upserted_id)


async def load(root_id) -> GuardianInvestigation:
    root = await GuardianInvestigation.get(root_id)
    assert root is not None
    return root


def verdict(**overrides) -> Verdict:
    values = {
        "peak": "info",
        "current": "info",
        "recovery": "none",
        "confidence": "low",
        "coverage": "partial",
        "sources": ("monitoring",),
        "summary": "$summary is stored as text",
    }
    return Verdict.model_validate(values | overrides)


async def run_attempt(root_id, kind: RunKind, *, succeed: bool = True, verdict_value: Verdict | None = None):
    """Lease, commit, insert, finalize and publish one attempt through the builders."""
    token = PydanticObjectId()
    assert await apply(roots(), repo.lease(root_id, kind=kind, token=token)) == 1
    fence = repo.ClaimFence(root_id=root_id, token=token)
    assert await apply(roots(), repo.commit_attempt(fence, kind=kind)) == 1
    root = await load(root_id)
    assert root.claim is not None
    assert root.claim.started_at is not None
    attempt = repo.CommittedAttempt(
        token=token,
        organization_id=root.organization_id,
        investigation_id=root_id,
        audit_id=root.audit_id,
        kind=kind,
        attempt=root.claim.attempt or 0,
        started_at=root.claim.started_at,
        retained_until=root.retained_until,
    )
    await runs().insert_one(repo.running_run_document(attempt, now=datetime.now(UTC)))
    committed = repo.ClaimFence(root_id=root_id, token=token, attempt=attempt.attempt)
    if not succeed:
        failed = repo.finalize_run(token, state="failed", fields={}, failure_reason="Ledger construction failed")
        assert await apply(runs(), failed) == 1
        assert await apply(roots(), repo.publish_failed_run(committed)) == 1
        return token, None
    value = verdict_value or verdict()
    fields = {
        "verdict": Encoder(to_db=True).encode(value),
        "budget": {"model_turns": 2, "mcp_calls": 1, "rule_reads": 0},
    }
    assert await apply(runs(), repo.finalize_run(token, state="succeeded", fields=fields)) == 1
    evaluated_at = datetime.now(UTC)
    # MongoDB stores milliseconds, so compare against what it can round-trip.
    evaluated_at = evaluated_at.replace(microsecond=evaluated_at.microsecond // 1000 * 1000)
    result = GuardianResult.from_verdict(run_id=token, run_kind=kind, evaluated_at=evaluated_at, verdict=value)
    encoded = Encoder(to_db=True).encode(result)
    reason = "Final run published" if kind == "final" else None
    publish = repo.publish_succeeded_run(committed, kind=kind, result=encoded, status_reason=reason)
    assert await apply(roots(), publish) == 1
    assert await apply(roots(), publish) == 0
    return token, result


async def test_indexes_are_created_as_specified() -> None:
    root_indexes = await roots().index_information()
    assert root_indexes["guardian_investigation_identity"]["key"] == [("organization_id", 1), ("audit_id", 1)]
    assert root_indexes["guardian_investigation_identity"]["unique"] is True
    assert root_indexes["guardian_investigation_due"]["key"] == [("status", 1), ("next_check_at", 1)]
    run_indexes = await runs().index_information()
    assert run_indexes["guardian_run_lookup"]["key"] == [
        ("organization_id", 1),
        ("investigation_id", 1),
        ("kind", 1),
        ("attempt", 1),
    ]
    for ttl in (root_indexes["guardian_investigation_retention"], run_indexes["guardian_run_retention"]):
        assert ttl["key"] == [("retained_until", 1)]
        assert ttl["expireAfterSeconds"] == 0
        assert ttl["partialFilterExpression"] == {"retained_until": {"$exists": True}}


async def test_ensure_is_idempotent_and_the_due_query_only_selects_candidates() -> None:
    now = datetime.now(UTC)
    write = repo.ensure_investigation(
        organization_id=ORG, audit_id="ensure", changed_at=now, anchor_known=False, now=now, retained_until=None
    )
    first = await roots().update_one(write.filter, write.update, upsert=True)
    second = await roots().update_one(write.filter, write.update, upsert=True)
    assert (second.matched_count, second.modified_count) == (1, 0)
    root = await load(first.upserted_id)
    assert (root.status, root.anchor_known, root.claim) == ("waiting", False, None)

    def due(at: datetime):
        return roots().find(repo.due_candidates_filter(at)).sort(list(repo.DUE_SORT)).limit(repo.DUE_LIMIT)

    assert first.upserted_id not in [row["_id"] for row in await due(now).to_list()]
    assert first.upserted_id in [row["_id"] for row in await due(now + timedelta(minutes=2)).to_list()]


async def test_nothing_due_waits_for_server_time() -> None:
    root_id = await new_root(timedelta(minutes=5))
    await shift(root_id, next_check_at=timedelta(minutes=5))
    assert await apply(roots(), repo.nothing_due(root_id)) == 0
    await shift(root_id, next_check_at=-PAST)
    before = datetime.now(UTC)
    assert await apply(roots(), repo.nothing_due(root_id)) == 1
    root = await load(root_id)
    assert root.next_check_at is not None
    assert before + timedelta(seconds=50) < root.next_check_at < before + timedelta(seconds=70)


async def test_the_final_trigger_and_forced_branch_are_judged_on_server_time() -> None:
    for changed, leased, forced in ((59, 0, None), (61, 1, False), (119, 1, False), (121, 1, True)):
        root_id = await new_root(timedelta(minutes=changed))
        before = datetime.now(UTC)
        assert await apply(roots(), repo.lease(root_id, kind="final", token=PydanticObjectId())) == leased
        root = await load(root_id)
        if forced is None:
            assert root.claim is None
            continue
        assert root.claim is not None
        assert (root.claim.final_forced, root.claim.attempt, root.claim.started_at) == (forced, None, None)
        assert before + timedelta(seconds=290) < root.claim.lease_until < before + timedelta(seconds=310)


async def test_a_lease_cannot_be_taken_twice_or_before_the_root_is_due() -> None:
    root_id = await new_root(timedelta(minutes=61))
    await shift(root_id, next_check_at=timedelta(minutes=1))
    assert await apply(roots(), repo.lease(root_id, kind="final", token=PydanticObjectId())) == 0
    await shift(root_id, next_check_at=-PAST)
    assert await apply(roots(), repo.lease(root_id, kind="final", token=PydanticObjectId())) == 1
    assert await apply(roots(), repo.lease(root_id, kind="final", token=PydanticObjectId())) == 0


async def test_an_early_commit_after_the_cutoff_matches_nothing_and_release_consumes_no_attempt() -> None:
    root_id = await new_root(timedelta(minutes=40))
    token = PydanticObjectId()
    fence = repo.ClaimFence(root_id=root_id, token=token)
    assert await apply(roots(), repo.lease(root_id, kind="early", token=token)) == 1
    await shift(root_id, changed_at=-timedelta(minutes=46))
    assert await apply(roots(), repo.commit_attempt(fence, kind="early")) == 0
    assert await roots().find_one(repo.commit_applied_filter(fence)) is None
    assert await apply(roots(), repo.release(fence)) == 1
    assert await apply(roots(), repo.release(fence)) == 0
    root = await load(root_id)
    assert (root.claim, root.attempts.early) == (None, 0)
    assert root.next_check_at is not None
    assert root.next_check_at > datetime.now(UTC)


async def test_uncommitted_recovery_needs_server_expiry_and_a_stale_commit_then_matches_nothing() -> None:
    root_id = await new_root(timedelta(minutes=61))
    token = PydanticObjectId()
    fence = repo.ClaimFence(root_id=root_id, token=token)
    assert await apply(roots(), repo.lease(root_id, kind="final", token=token)) == 1
    assert await apply(roots(), repo.recover_uncommitted_claim(fence)) == 0
    await shift(root_id, **{"claim.lease_until": -PAST})
    assert await apply(roots(), repo.recover_uncommitted_claim(fence)) == 1
    assert await apply(roots(), repo.commit_attempt(fence, kind="final")) == 0
    root = await load(root_id)
    assert (root.claim, root.attempts.final) == (None, 0)


async def test_a_commit_that_wins_first_keeps_its_claim_metadata() -> None:
    root_id = await new_root(timedelta(minutes=61))
    token = PydanticObjectId()
    fence = repo.ClaimFence(root_id=root_id, token=token)
    assert await apply(roots(), repo.lease(root_id, kind="final", token=token)) == 1
    assert await apply(roots(), repo.commit_attempt(fence, kind="final")) == 1
    assert await apply(roots(), repo.commit_attempt(fence, kind="final")) == 0
    assert await roots().find_one(repo.commit_applied_filter(fence)) is not None
    await shift(root_id, **{"claim.lease_until": -PAST})
    assert await apply(roots(), repo.recover_uncommitted_claim(fence)) == 0
    assert await apply(roots(), repo.release(fence)) == 0
    committed = repo.ClaimFence(root_id=root_id, token=token, attempt=1)
    assert await roots().find_one(repo.expired_committed_claim_filter(committed)) is not None
    root = await load(root_id)
    assert root.claim is not None
    assert (root.claim.attempt, root.attempts.final) == (1, 1)


async def test_committed_recovery_records_an_abandoned_run_and_publishes_it_as_failed() -> None:
    root_id = await new_root(timedelta(minutes=61))
    token = PydanticObjectId()
    fence = repo.ClaimFence(root_id=root_id, token=token)
    assert await apply(roots(), repo.lease(root_id, kind="final", token=token)) == 1
    assert await apply(roots(), repo.commit_attempt(fence, kind="final")) == 1
    committed = repo.ClaimFence(root_id=root_id, token=token, attempt=1)
    assert await roots().find_one(repo.expired_committed_claim_filter(committed)) is None
    await shift(root_id, **{"claim.lease_until": -PAST})
    root = await load(root_id)
    assert root.claim is not None
    assert root.claim.started_at is not None
    attempt = repo.CommittedAttempt(
        token=token,
        organization_id=ORG,
        investigation_id=root_id,
        audit_id=root.audit_id,
        kind="final",
        attempt=1,
        started_at=root.claim.started_at,
        retained_until=root.retained_until,
    )
    await runs().insert_one(repo.abandoned_run_document(attempt, now=datetime.now(UTC)))
    with pytest.raises(DuplicateKeyError):
        await runs().insert_one(repo.running_run_document(attempt, now=datetime.now(UTC)))
    assert await apply(runs(), repo.finalize_run(token, state="succeeded", fields={"verdict": {}})) == 0
    stale = repo.ClaimFence(root_id=root_id, token=token, attempt=2)
    assert await apply(roots(), repo.publish_failed_run(stale)) == 0
    assert await apply(roots(), repo.publish_failed_run(committed)) == 1
    assert await apply(roots(), repo.publish_failed_run(committed)) == 0
    abandoned = await GuardianRun.get(token)
    assert abandoned is not None
    assert (abandoned.state, abandoned.failure_reason) == ("abandoned", repo.ABANDONED_REASON)
    root = await load(root_id)
    assert (root.claim, root.final_run_id, root.result, root.attempts.final) == (None, None, None, 1)
    assert not root.publishes(abandoned)


async def test_a_running_run_is_abandoned_once_and_never_finalized_afterwards() -> None:
    root_id = await new_root(timedelta(minutes=61))
    token = PydanticObjectId()
    attempt = repo.CommittedAttempt(
        token=token,
        organization_id=ORG,
        investigation_id=root_id,
        audit_id="abandon",
        kind="final",
        attempt=1,
        started_at=datetime.now(UTC),
        retained_until=None,
    )
    await runs().insert_one(repo.running_run_document(attempt, now=datetime.now(UTC)))
    assert await apply(runs(), repo.abandon_running_run(token)) == 1
    assert await apply(runs(), repo.abandon_running_run(token)) == 0
    failed = repo.finalize_run(token, state="failed", fields={}, failure_reason="Composition failed")
    assert await apply(runs(), failed) == 0
    run = await GuardianRun.get(token)
    assert run is not None
    assert run.state == "abandoned"
    assert run.finished_at is not None


async def test_early_then_final_publication_replaces_the_result_and_completes_the_root() -> None:
    root_id = await new_root(timedelta(minutes=10))
    device = CompactImpactedDevice(mac="5c5b35000001", site_id="site-1", peak="warning", current="warning")
    early_verdict = verdict(
        peak="warning", current="warning", recovery="unrecovered", impacted_devices=(device,), sources=("agent",)
    )
    early_token, _ = await run_attempt(root_id, "early", verdict_value=early_verdict)
    root = await load(root_id)
    assert (root.status, root.early_run_id, root.attempts.early) == ("waiting", early_token, 1)
    assert root.result is not None
    assert root.result.impacted_device_count == 1
    assert root.next_check_at is not None
    assert root.next_check_at > datetime.now(UTC)
    assert await apply(roots(), repo.lease(root_id, kind="early", token=PydanticObjectId())) == 0

    await shift(root_id, changed_at=-timedelta(minutes=61), next_check_at=-PAST)
    final_token, final_result = await run_attempt(root_id, "final")
    root = await load(root_id)
    assert (root.status, root.status_reason, root.next_check_at, root.claim) == (
        "done",
        "Final run published",
        None,
        None,
    )
    assert root.result == final_result
    stored = await roots().find_one({"_id": root_id})
    assert stored["result"] == Encoder(to_db=True).encode(final_result)
    final_run = await GuardianRun.get(final_token)
    early_run = await GuardianRun.get(early_token)
    assert final_run is not None
    assert early_run is not None
    assert final_run.verdict is not None
    assert final_run.verdict.summary == "$summary is stored as text"
    assert root.publishes(final_run)
    assert root.publishes(early_run)

    # bson_size measures what Beanie writes for a full model, without needing an initialized collection.
    full = await final_run.model_copy(update={"id": PydanticObjectId()}).insert()
    sizes = await runs().aggregate([{"$match": {"_id": full.id}}, {"$project": {"size": {"$bsonSize": "$$ROOT"}}}])
    [measured] = await sizes.to_list()
    assert bson_size(full) == measured["size"]


async def test_exhaustion_completes_the_root_after_two_failed_finals_and_keeps_the_early_result() -> None:
    root_id = await new_root(timedelta(minutes=10))
    early_token, early_result = await run_attempt(root_id, "early")
    await shift(root_id, changed_at=-timedelta(minutes=61), next_check_at=-PAST)
    await run_attempt(root_id, "final", succeed=False)
    exhaust = repo.exhaust_final_attempts(root_id, last_failure_reason="Ledger construction failed")
    assert await apply(roots(), exhaust) == 0, "one final attempt remains"
    await shift(root_id, next_check_at=-PAST)
    await run_attempt(root_id, "final", succeed=False)
    assert await apply(roots(), repo.lease(root_id, kind="final", token=PydanticObjectId())) == 0
    assert await apply(roots(), exhaust) == 0, "not due yet on server time"
    await shift(root_id, next_check_at=-PAST)
    assert await apply(roots(), exhaust) == 1
    root = await load(root_id)
    assert (root.status, root.status_reason, root.next_check_at) == (
        "done",
        "Final run failed after 2 attempts: Ledger construction failed",
        None,
    )
    assert (root.early_run_id, root.final_run_id, root.result) == (early_token, None, early_result)
