"""The fenced tick on MongoDB 8: every crash boundary, both orders of every race, and the scheduling transitions.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB. A crash is simulated by running the tick's steps up to
one boundary and then letting a later tick continue from what the database holds, which is exactly what a killed
worker leaves behind. Elapsed server time is simulated by moving stored instants into the past; every predicate
still runs on the server's own clock.
"""

# The tick's steps are exercised one at a time, so its private members are reached directly.
# ruff: noqa: SLF001

import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from bson import ObjectId
from pymongo import AsyncMongoClient
from pymongo.errors import NetworkTimeout

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.guardian import repository as repo
from mist_config_guardian_backend.guardian.agent import NO_RUNTIME
from mist_config_guardian_backend.guardian.contracts import (
    EARLY_CUTOFF,
    FINAL_FORCED,
    FINAL_MINIMUM,
    RECHECK_DELAY,
)
from mist_config_guardian_backend.models.adjudication import ImpactAdjudication
from mist_config_guardian_backend.models.guardian import (
    GuardianInvestigation,
    GuardianRun,
    RunDocumentTooLargeError,
)
from mist_config_guardian_backend.models.investigation import (
    ImpactInvestigation,
    InvestigationRevision,
    ModelRequestArtifact,
)
from mist_config_guardian_backend.models.monitoring import DeviceType, MonitoringSession, MonitoringStatus
from mist_config_guardian_backend.models.neighbor_binding import NeighborBinding
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectIncarnation, ObjectVersion
from mist_config_guardian_backend.models.webhook import WebhookReceipt
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import guardian
from mist_config_guardian_backend.services.guardian import AttemptOutcome, AttemptTools, GuardianService
from mist_config_guardian_backend.services.investigation_retention import maintain_investigation_retention

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "guardian_runtime"
PAST = timedelta(seconds=1)
SITE = "20000000-0000-4000-8000-000000000001"
MAC = "5c5b350a0b01"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]

DOCUMENTS = [
    GuardianInvestigation,
    GuardianRun,
    Organization,
    MonitoringSession,
    WebhookReceipt,
    ObjectVersion,
    LogicalObject,
    ObjectIncarnation,
    # The retention job spans every investigation family, so they are registered too.
    ImpactInvestigation,
    InvestigationRevision,
    ModelRequestArtifact,
    ImpactAdjudication,
    NeighborBinding,
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> Any:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=DOCUMENTS)
    yield
    await client.drop_database(DATABASE)
    await client.close()


@pytest_asyncio.fixture(loop_scope="module")
async def organization() -> Organization:
    existing = await Organization.find_one({"mist_org_id": "guardian-runtime"})
    if existing is not None:
        return existing
    return await Organization(
        name="Guardian Runtime",
        mist_org_id="guardian-runtime",
        monitoring_retention_days=30,
        encrypted_service_token=vault().encrypt_for_context("token", context="service-token"),
        service_token_last_four="oken",
    ).insert()


def roots() -> Any:
    return GuardianInvestigation.get_pymongo_collection()


def runs() -> Any:
    return GuardianRun.get_pymongo_collection()


def vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", database_enabled=False))


class FakeTools:
    """One attempt's collaborators: nothing external, and an agent that is always skipped with a reason."""

    def __init__(self, tools: AttemptTools | None = None) -> None:
        self.tools = tools or AttemptTools(skip_reason=NO_RUNTIME)
        self.entered = 0

    def __call__(self, _organization: Organization | None) -> "FakeTools":
        return self

    async def __aenter__(self) -> AttemptTools:
        self.entered += 1
        return self.tools

    async def __aexit__(self, *_args: object) -> None:
        return None


def service(**overrides: Any) -> GuardianService:
    return GuardianService(vault(), tools=overrides.pop("tools", FakeTools()), **overrides)


async def shift(root_id: Any, **instants: timedelta) -> None:
    """Move stored instants relative to now, standing in for elapsed server time."""
    now = datetime.now(UTC)
    await roots().update_one({"_id": root_id}, {"$set": {key: now + delta for key, delta in instants.items()}})


MARGIN = timedelta(minutes=5)


async def new_root(organization: Organization, *, changed: timedelta = FINAL_MINIMUM + MARGIN, due: bool = True) -> Any:
    """A due root whose change is far enough past a limit that worker and server clocks cannot disagree on it."""
    audit_id = str(uuid4())
    await service().ensure(organization, audit_id, changed_at=datetime.now(UTC) - changed, anchor_known=True)
    root = await GuardianInvestigation.find_one({"organization_id": organization.id, "audit_id": audit_id})
    assert root is not None
    if due:
        await shift(root.id, next_check_at=-PAST)
    return await load(root.id)


async def load(root_id: Any) -> GuardianInvestigation:
    root = await GuardianInvestigation.find_one({"_id": root_id})
    assert root is not None
    return root


async def apply(collection: Any, write: repo.Write) -> int:
    result = await collection.update_one(write.filter, write.update, upsert=write.upsert)
    return result.modified_count


async def take_lease(root: GuardianInvestigation, kind: str = "final") -> ObjectId:
    """Step 4 alone: the lease, exactly as the tick takes it."""
    token = ObjectId()
    assert await apply(roots(), repo.lease(root.id, kind=kind, token=token)) == 1
    return token


async def commit(root: GuardianInvestigation, token: ObjectId, kind: str = "final") -> repo.CommittedAttempt:
    """Steps 4 and 6 alone: a committed attempt with no run document yet."""
    fence = repo.ClaimFence(root_id=root.id, token=token)
    assert await apply(roots(), repo.commit_attempt(fence, kind=kind)) == 1
    claimed = await load(root.id)
    assert claimed.claim is not None
    assert claimed.claim.attempt is not None
    assert claimed.claim.started_at is not None
    return repo.CommittedAttempt(
        token=token,
        organization_id=claimed.organization_id,
        investigation_id=claimed.id,
        audit_id=claimed.audit_id,
        kind=kind,
        attempt=claimed.claim.attempt,
        started_at=claimed.claim.started_at,
        retained_until=datetime.now(UTC) + timedelta(days=30),
    )


async def insert_run(attempt: repo.CommittedAttempt) -> None:
    await runs().insert_one(repo.running_run_document(attempt, now=datetime.now(UTC)))


async def finalize(attempt: repo.CommittedAttempt, *, state: str = "succeeded") -> GuardianRun:
    """Steps 8 and 9 alone: the attempt's own execution, then its finalization."""
    fields = await succeeded_fields(attempt) if state == "succeeded" else {}
    write = repo.finalize_run(
        attempt.token,
        state="succeeded" if state == "succeeded" else "failed",
        fields=fields,
        failure_reason=None if state == "succeeded" else "The attempt failed on purpose",
    )
    assert await apply(runs(), write) == 1
    run = await GuardianRun.find_one({"_id": attempt.token})
    assert run is not None
    return run


async def succeeded_fields(attempt: repo.CommittedAttempt) -> dict[str, Any]:
    """A minimal succeeded attempt, produced by the orchestrator's own execution over an empty audit."""
    root = await load(attempt.investigation_id)
    outcome = await service()._execute(root, None, attempt, started=time.monotonic())
    assert outcome.state == "succeeded"
    return {name: guardian._stored(value) for name, value in outcome.fields.items()}


# -- the happy path -------------------------------------------------------------------------------------------------


async def test_one_tick_leases_commits_executes_and_publishes_a_final_run(organization: Organization) -> None:
    root = await new_root(organization)

    await service().tick(root)

    published = await load(root.id)
    assert published.status == "done"
    assert published.claim is None
    assert published.next_check_at is None
    assert published.attempts.final == 1
    assert published.result is not None
    assert published.result.run_kind == "final"
    run = await GuardianRun.find_one({"_id": published.final_run_id})
    assert run is not None
    assert run.state == "succeeded"
    assert run.retained_until is not None
    assert published.retained_until is not None


async def test_a_second_tick_after_publication_changes_nothing(organization: Organization) -> None:
    root = await new_root(organization)
    await service().tick(root)
    before = await load(root.id)

    await service().tick(before)

    after = await load(root.id)
    assert (after.status, after.final_run_id, after.attempts.final) == ("done", before.final_run_id, 1)
    assert await runs().count_documents({"investigation_id": root.id}) == 1


async def test_the_due_query_selects_only_candidates_and_caps_them(organization: Organization) -> None:
    root = await new_root(organization)
    candidates = (
        await GuardianInvestigation.find(repo.due_candidates_filter(datetime.now(UTC)))
        .sort("+next_check_at")
        .limit(repo.DUE_LIMIT)
        .to_list()
    )

    assert len(candidates) <= repo.DUE_LIMIT
    assert root.id in {candidate.id for candidate in candidates}


# -- crash boundaries -----------------------------------------------------------------------------------------------


async def test_a_crash_between_lease_and_commit_consumes_no_attempt(organization: Organization) -> None:
    root = await new_root(organization)
    token = await take_lease(root)
    await shift(root.id, **{"claim.lease_until": -PAST})

    await service().tick(await load(root.id))

    recovered = await load(root.id)
    assert recovered.claim is None
    assert recovered.attempts.final == 0
    assert await runs().count_documents({"investigation_id": root.id, "_id": token}) == 0


async def test_a_crash_between_commit_and_run_insert_leaves_an_abandoned_run(organization: Organization) -> None:
    root = await new_root(organization)
    attempt = await commit(root, await take_lease(root))
    await shift(root.id, **{"claim.lease_until": -PAST})

    await service().tick(await load(root.id))

    run = await GuardianRun.find_one({"_id": attempt.token})
    assert run is not None
    assert (run.state, run.attempt, run.kind) == ("abandoned", 1, "final")
    assert run.failure_reason == repo.ABANDONED_REASON
    cleared = await load(root.id)
    assert cleared.claim is None
    assert cleared.final_run_id is None
    assert cleared.next_check_at is not None


async def test_a_crash_between_run_insert_and_finalize_abandons_the_running_run(organization: Organization) -> None:
    root = await new_root(organization)
    attempt = await commit(root, await take_lease(root))
    await insert_run(attempt)
    await shift(root.id, **{"claim.lease_until": -PAST})

    await service().tick(await load(root.id))

    run = await GuardianRun.find_one({"_id": attempt.token})
    assert run is not None
    assert run.state == "abandoned"
    assert (await load(root.id)).claim is None


async def test_a_crash_between_finalize_and_publish_adopts_a_succeeded_run(organization: Organization) -> None:
    root = await new_root(organization)
    attempt = await commit(root, await take_lease(root))
    await insert_run(attempt)
    await finalize(attempt, state="succeeded")
    await shift(root.id, **{"claim.lease_until": -PAST})

    await service().tick(await load(root.id))

    published = await load(root.id)
    assert published.final_run_id == attempt.token
    assert published.status == "done"
    assert published.result is not None
    assert published.result.run_id == attempt.token


async def test_a_crash_between_finalize_and_publish_publishes_a_failed_run(organization: Organization) -> None:
    root = await new_root(organization)
    attempt = await commit(root, await take_lease(root))
    await insert_run(attempt)
    await finalize(attempt, state="failed")
    await shift(root.id, **{"claim.lease_until": -PAST})

    await service().tick(await load(root.id))

    published = await load(root.id)
    assert published.final_run_id is None
    assert published.status == "waiting"
    assert published.result is None
    assert published.claim is None
    assert published.next_check_at is not None


async def test_recovery_that_crashes_before_clearing_the_claim_is_finished_by_the_next_tick(
    organization: Organization,
) -> None:
    root = await new_root(organization)
    attempt = await commit(root, await take_lease(root))
    await insert_run(attempt)
    await shift(root.id, **{"claim.lease_until": -PAST})
    # The recovering worker marked the run abandoned and then died before its publication.
    assert await apply(runs(), repo.abandon_running_run(attempt.token)) == 1
    assert (await load(root.id)).claim is not None

    await service().tick(await load(root.id))

    assert (await load(root.id)).claim is None


# -- races ----------------------------------------------------------------------------------------------------------


async def test_a_stale_commit_that_wins_keeps_its_claim_metadata(organization: Organization) -> None:
    root = await new_root(organization)
    token = await take_lease(root)
    fence = repo.ClaimFence(root_id=root.id, token=token)
    # The stale worker's commit lands first, then the recovering tick tries to clear the uncommitted claim.
    assert await apply(roots(), repo.commit_attempt(fence, kind="final")) == 1
    await shift(root.id, **{"claim.lease_until": -PAST})

    assert await apply(roots(), repo.recover_uncommitted_claim(fence)) == 0

    committed = await load(root.id)
    assert committed.claim is not None
    assert committed.claim.attempt == 1
    assert committed.attempts.final == 1


async def test_a_clear_that_wins_leaves_the_stale_commit_matching_nothing(organization: Organization) -> None:
    root = await new_root(organization)
    token = await take_lease(root)
    fence = repo.ClaimFence(root_id=root.id, token=token)
    await shift(root.id, **{"claim.lease_until": -PAST})

    assert await apply(roots(), repo.recover_uncommitted_claim(fence)) == 1
    assert await apply(roots(), repo.commit_attempt(fence, kind="final")) == 0

    cleared = await load(root.id)
    assert cleared.claim is None
    assert cleared.attempts.final == 0


async def test_recovery_abandoning_a_run_stops_a_stale_workers_finalization(organization: Organization) -> None:
    root = await new_root(organization)
    attempt = await commit(root, await take_lease(root))
    await insert_run(attempt)
    assert await apply(runs(), repo.abandon_running_run(attempt.token)) == 1

    stale = repo.finalize_run(attempt.token, state="failed", fields={}, failure_reason="too late")
    assert await apply(runs(), stale) == 0

    run = await GuardianRun.find_one({"_id": attempt.token})
    assert run is not None
    assert run.failure_reason == repo.ABANDONED_REASON


async def test_a_succeeded_run_finalized_first_is_adopted_and_published_exactly_once(
    organization: Organization,
) -> None:
    root = await new_root(organization)
    attempt = await commit(root, await take_lease(root))
    await insert_run(attempt)
    run = await finalize(attempt, state="succeeded")
    await shift(root.id, **{"claim.lease_until": -PAST})

    # Both the run's own worker and the recovering tick try the same publication; at most one matches.
    await service()._publish(run)
    await service()._publish(run)

    published = await load(root.id)
    assert published.final_run_id == attempt.token
    assert published.attempts.final == 1


async def test_a_publication_whose_attempt_does_not_match_the_run_matches_nothing(
    organization: Organization,
) -> None:
    root = await new_root(organization)
    attempt = await commit(root, await take_lease(root))
    await insert_run(attempt)
    run = await finalize(attempt, state="succeeded")

    mismatched = run.model_copy(update={"attempt": 2})
    await service()._publish(mismatched)

    assert (await load(root.id)).final_run_id is None


# -- ambiguous commit responses -------------------------------------------------------------------------------------


class AmbiguousRoots:
    """Wraps the roots collection so the first ``find_one_and_update`` raises, after the server applied it or before."""

    def __init__(self, *, applied: bool) -> None:
        self._applied = applied
        self._raised = False

    def __getattr__(self, name: str) -> Any:
        return getattr(roots(), name)

    async def find_one_and_update(self, *args: Any, **kwargs: Any) -> Any:
        if not self._raised:
            self._raised = True
            if self._applied:
                await roots().update_one(args[0], args[1])
            msg = "the response never arrived"
            raise NetworkTimeout(msg)
        return await roots().find_one_and_update(*args, **kwargs)


async def _commit_ambiguously(root: GuardianInvestigation, token: ObjectId, *, applied: bool) -> Any:
    worker = service()
    collection = AmbiguousRoots(applied=applied)
    worker._roots = lambda: collection  # type: ignore[method-assign]
    return await worker._commit(
        repo.ClaimFence(root_id=root.id, token=token), root=root, organization=None, kind="final"
    )


async def test_an_ambiguous_commit_that_applied_continues_with_exactly_one_increment(
    organization: Organization,
) -> None:
    root = await new_root(organization)
    token = await take_lease(root)

    attempt = await _commit_ambiguously(await load(root.id), token, applied=True)

    assert attempt is not None
    assert attempt.attempt == 1
    assert (await load(root.id)).attempts.final == 1


async def test_an_ambiguous_commit_that_never_applied_stops_the_worker(organization: Organization) -> None:
    root = await new_root(organization)
    token = await take_lease(root)

    attempt = await _commit_ambiguously(await load(root.id), token, applied=False)

    assert attempt is None
    stopped = await load(root.id)
    assert stopped.attempts.final == 0
    # Nothing frees a claim it cannot prove is still uncommitted; the lease's own expiry resolves it.
    assert stopped.claim is not None
    assert stopped.claim.token == token
    await shift(root.id, **{"claim.lease_until": -PAST})
    await service().tick(await load(root.id))
    assert (await load(root.id)).claim is None


# -- trigger and revalidation fences --------------------------------------------------------------------------------


async def test_a_candidate_a_fast_worker_clock_picked_too_early_changes_nothing(organization: Organization) -> None:
    root = await new_root(organization, due=False)

    # The worker believes the root is due and evaluates a final; the server disagrees on both counts.
    assert await apply(roots(), repo.lease(root.id, kind="final", token=ObjectId())) == 0

    untouched = await load(root.id)
    assert untouched.claim is None
    assert untouched.attempts.final == 0


async def test_a_lease_is_refused_while_another_workers_lease_is_live(organization: Organization) -> None:
    root = await new_root(organization)
    await take_lease(root)

    assert await apply(roots(), repo.lease(root.id, kind="final", token=ObjectId())) == 0


async def test_one_clock_decides_both_the_commit_and_its_recovery(organization: Organization) -> None:
    # A worker clock ahead of or behind the server cannot make one lease both unexpired at commit and expired at
    # recovery: both predicates are ``$$NOW`` against the same stored instant.
    live = await new_root(organization)
    expired = await new_root(organization)
    live_fence = repo.ClaimFence(root_id=live.id, token=await take_lease(live))
    expired_fence = repo.ClaimFence(root_id=expired.id, token=await take_lease(expired))
    await shift(expired.id, **{"claim.lease_until": -PAST})

    assert await apply(roots(), repo.commit_attempt(live_fence, kind="final")) == 1
    assert await apply(roots(), repo.recover_uncommitted_claim(live_fence)) == 0
    assert await apply(roots(), repo.commit_attempt(expired_fence, kind="final")) == 0
    assert await apply(roots(), repo.recover_uncommitted_claim(expired_fence)) == 1


async def test_a_stale_decision_cannot_skip_the_retry_delay(organization: Organization) -> None:
    root = await new_root(organization, due=False)
    await shift(root.id, next_check_at=RECHECK_DELAY)

    assert await apply(roots(), repo.lease(root.id, kind="final", token=ObjectId())) == 0


async def test_a_stale_decision_cannot_start_a_second_early_run(organization: Organization) -> None:
    root = await new_root(organization, changed=timedelta(minutes=10))
    attempt = await commit(await load(root.id), await take_lease(root, "early"), kind="early")
    await insert_run(attempt)
    await service()._publish(await finalize(attempt, state="succeeded"))
    await shift(root.id, next_check_at=-PAST)

    assert (await load(root.id)).early_run_id is not None
    assert await apply(roots(), repo.lease(root.id, kind="early", token=ObjectId())) == 0


async def test_final_forced_is_false_at_119_minutes_and_true_at_120(organization: Organization) -> None:
    before = await new_root(organization, changed=FINAL_FORCED - timedelta(minutes=1))
    after = await new_root(organization, changed=FINAL_FORCED + timedelta(seconds=30))

    await take_lease(before)
    await take_lease(after)

    assert (await load(before.id)).claim.final_forced is False
    assert (await load(after.id)).claim.final_forced is True


async def test_a_forced_final_runs_even_while_a_linked_session_is_active(organization: Organization) -> None:
    root = await new_root(organization, changed=FINAL_FORCED + timedelta(seconds=30))
    await MonitoringSession(
        organization_id=organization.id,
        audit_ids=[root.audit_id],
        site_id=SITE,
        device_mac=f"{MAC[:-1]}a",
        device_type=DeviceType.SWITCH,
        status=MonitoringStatus.MONITORING,
        active=True,
    ).insert()
    token = await take_lease(root)
    claim = (await load(root.id)).claim
    assert claim is not None
    assert claim.final_forced is True

    assert await service()._revalidated(root, kind="final", forced=claim.final_forced) is True
    assert await service()._revalidated(root, kind="final", forced=False) is False
    await service()._release(repo.ClaimFence(root_id=root.id, token=token))


async def test_an_active_linked_session_fails_final_revalidation_without_consuming_an_attempt(
    organization: Organization,
) -> None:
    root = await new_root(organization)
    await MonitoringSession(
        organization_id=organization.id,
        audit_ids=[root.audit_id],
        site_id=SITE,
        device_mac=MAC,
        device_type=DeviceType.SWITCH,
        status=MonitoringStatus.MONITORING,
        active=True,
    ).insert()

    await service().tick(root)

    # The trigger evaluation never chooses a final while a session is active, so nothing is leased at all.
    untouched = await load(root.id)
    assert untouched.attempts.final == 0
    assert untouched.claim is None
    assert untouched.next_check_at is not None


async def test_a_session_that_reopens_under_the_lease_releases_it_without_consuming_an_attempt(
    organization: Organization,
) -> None:
    root = await new_root(organization)
    token = await take_lease(root)
    await MonitoringSession(
        organization_id=organization.id,
        audit_ids=[root.audit_id],
        site_id=SITE,
        device_mac=f"{MAC[:-1]}9",
        device_type=DeviceType.SWITCH,
        status=MonitoringStatus.MONITORING,
        active=True,
    ).insert()

    assert await service()._revalidated(root, kind="final", forced=False) is False
    await service()._release(repo.ClaimFence(root_id=root.id, token=token))

    released = await load(root.id)
    assert released.claim is None
    assert released.attempts.final == 0
    assert released.next_check_at is not None


async def test_an_early_lease_taken_before_the_cutoff_cannot_commit_after_it(organization: Organization) -> None:
    root = await new_root(organization, changed=EARLY_CUTOFF - timedelta(minutes=1))
    token = await take_lease(root, "early")
    fence = repo.ClaimFence(root_id=root.id, token=token)
    # The cutoff passes while the worker is between its lease and its commit.
    await shift(root.id, changed_at=-EARLY_CUTOFF - timedelta(minutes=1))

    assert await apply(roots(), repo.commit_attempt(fence, kind="early")) == 0
    assert await apply(roots(), repo.release(fence)) == 1

    released = await load(root.id)
    assert released.attempts.early == 0
    assert released.claim is None
    # The final trigger then proceeds normally over the same root.
    await shift(released.id, changed_at=-FINAL_MINIMUM - MARGIN, next_check_at=-PAST)
    await service().tick(await load(root.id))
    assert (await load(root.id)).attempts.final == 1


# -- scheduling, caps and exhaustion ---------------------------------------------------------------------------------


async def test_nothing_due_pushes_the_next_check_one_minute_out(organization: Organization) -> None:
    root = await new_root(organization, changed=timedelta(minutes=1))

    await service().tick(root)

    rescheduled = await load(root.id)
    assert rescheduled.next_check_at is not None
    assert rescheduled.next_check_at > datetime.now(UTC) + RECHECK_DELAY - timedelta(seconds=5)
    assert rescheduled.attempts.final == 0


async def test_a_failed_final_attempt_is_retried_and_then_exhausts(organization: Organization) -> None:
    root = await new_root(organization)
    reasons = []
    for _attempt in range(repo.MAX_ATTEMPTS_PER_KIND):
        current = await load(root.id)
        attempt = await commit(current, await take_lease(current))
        await insert_run(attempt)
        run = await finalize(attempt, state="failed")
        reasons.append(run.failure_reason)
        await service()._publish(run)
        await shift(root.id, next_check_at=-PAST)

    retried = await load(root.id)
    assert retried.attempts.final == repo.MAX_ATTEMPTS_PER_KIND
    assert retried.status == "waiting"

    await service().tick(retried)

    exhausted = await load(root.id)
    assert exhausted.status == "done"
    assert exhausted.next_check_at is None
    assert exhausted.status_reason is not None
    assert reasons[-1] in exhausted.status_reason


async def test_two_committed_attempts_that_never_created_a_run_still_exhaust(organization: Organization) -> None:
    root = await new_root(organization)
    for _attempt in range(repo.MAX_ATTEMPTS_PER_KIND):
        current = await load(root.id)
        await commit(current, await take_lease(current))
        await shift(root.id, **{"claim.lease_until": -PAST})
        await service().tick(await load(root.id))
        await shift(root.id, next_check_at=-PAST)

    abandoned = await runs().count_documents({"investigation_id": root.id, "state": "abandoned"})
    assert abandoned == repo.MAX_ATTEMPTS_PER_KIND

    await service().tick(await load(root.id))

    exhausted = await load(root.id)
    assert exhausted.status == "done"
    assert repo.ABANDONED_REASON in (exhausted.status_reason or "")


async def test_an_exhausted_final_keeps_a_published_early_result(organization: Organization) -> None:
    root = await new_root(organization, changed=timedelta(minutes=10))
    early_token = await take_lease(root, "early")
    early = await commit(await load(root.id), early_token, kind="early")
    await insert_run(early)
    await service()._publish(await finalize(early, state="succeeded"))
    published = await load(root.id)
    assert published.early_run_id == early_token
    assert published.result is not None

    await shift(root.id, changed_at=-FINAL_MINIMUM - MARGIN, next_check_at=-PAST)
    for _attempt in range(repo.MAX_ATTEMPTS_PER_KIND):
        current = await load(root.id)
        attempt = await commit(current, await take_lease(current, "final"))
        await insert_run(attempt)
        await service()._publish(await finalize(attempt, state="failed"))
        await shift(root.id, next_check_at=-PAST)

    await service().tick(await load(root.id))

    exhausted = await load(root.id)
    assert exhausted.status == "done"
    assert exhausted.result is not None
    assert exhausted.result.run_kind == "early"
    assert exhausted.final_run_id is None


async def test_exhausted_early_attempts_never_block_the_final(organization: Organization) -> None:
    root = await new_root(organization, changed=timedelta(minutes=10))
    for _attempt in range(repo.MAX_ATTEMPTS_PER_KIND):
        current = await load(root.id)
        attempt = await commit(current, await take_lease(current, "early"), kind="early")
        await insert_run(attempt)
        await service()._publish(await finalize(attempt, state="failed"))
        await shift(root.id, next_check_at=-PAST)

    assert (await load(root.id)).attempts.early == repo.MAX_ATTEMPTS_PER_KIND
    assert await apply(roots(), repo.lease(root.id, kind="early", token=ObjectId())) == 0

    await shift(root.id, changed_at=-FINAL_MINIMUM - MARGIN, next_check_at=-PAST)
    await service().tick(await load(root.id))

    assert (await load(root.id)).attempts.final == 1


async def test_an_early_publication_reschedules_rather_than_completing_the_root(organization: Organization) -> None:
    root = await new_root(organization, changed=timedelta(minutes=10))
    attempt = await commit(await load(root.id), await take_lease(root, "early"), kind="early")
    await insert_run(attempt)

    await service()._publish(await finalize(attempt, state="succeeded"))

    published = await load(root.id)
    assert published.status == "waiting"
    assert published.next_check_at is not None
    assert published.early_run_id == attempt.token
    assert published.result is not None
    assert published.result.run_kind == "early"


async def test_poll_due_isolates_one_failing_root_from_the_others(organization: Organization) -> None:
    healthy = await new_root(organization)
    broken = await new_root(organization)

    class Exploding(FakeTools):
        def __call__(self, _organization: Organization | None) -> "Exploding":
            return self

        async def __aenter__(self) -> AttemptTools:
            msg = "the collaborators could not be built"
            raise RuntimeError(msg)

    worker = service(tools=Exploding())
    await worker.tick(broken)
    await service().tick(healthy)

    # The broken root's attempt is consumed and recorded as failed; the healthy one still publishes.
    failed = await load(broken.id)
    assert failed.attempts.final == 1
    assert failed.final_run_id is None
    run = await GuardianRun.find_one({"investigation_id": broken.id})
    assert run is not None
    assert run.state == "failed"
    assert run.failure_reason
    assert (await load(healthy.id)).status == "done"


async def test_poll_due_runs_a_tick_for_every_candidate(organization: Organization) -> None:
    root = await new_root(organization)

    handled = await service().poll_due()

    assert handled >= 1
    assert (await load(root.id)).status == "done"


# -- loading one attempt's inputs -------------------------------------------------------------------------------------


async def seed_change(root: GuardianInvestigation, *, secret: str) -> PydanticObjectId:
    """One site device the audit changed, stored exactly as the snapshot writer stores it."""
    logical = await LogicalObject(
        organization_id=root.organization_id,
        scope="site",
        object_type="devices",
        source_key=f"devices:{root.audit_id}",
        current_mist_id="40000000-0000-4000-8000-000000000001",
        site_mist_id=SITE,
        name="SEA-SW-1",
        current_version=2,
    ).insert()
    incarnation = await ObjectIncarnation(
        organization_id=root.organization_id,
        logical_object_id=logical.id,
        mist_object_id="40000000-0000-4000-8000-000000000001",
        site_mist_id=SITE,
        ordinal=1,
    ).insert()
    identity = {"mac": MAC, "type": "switch", "site_id": SITE}
    for version, dns, audit in ((1, "10.0.0.1", None), (2, "10.0.0.2", root.audit_id)):
        await ObjectVersion(
            organization_id=root.organization_id,
            logical_object_id=logical.id,
            incarnation_id=incarnation.id,
            version=version,
            event="updated",
            configuration={**identity, "dns_servers": [dns], "root_password": secret},
            configuration_hash=f"hash-{version}",
            changed_fields=["dns_servers"],
            audit_id=audit,
        ).insert()
    await WebhookReceipt(
        organization_id=root.organization_id,
        topic="device-events",
        event_id=f"{root.audit_id}-trigger",
        audit_id=root.audit_id,
        payload_hash="hash",
        encrypted_payload="",
        signature_version="v2",
        deployment_normalized=True,
        deployment={
            "event_type": "SW_CONFIG_CHANGED_BY_USER",
            "outcome": "pending",
            "device_type": "switch",
            "device_mac": MAC,
            "site_id": SITE,
            "occurred_at": root.changed_at,
            "gaps": [],
        },
    ).insert()
    return logical.id


async def test_an_attempt_loads_its_change_devices_and_sessions_from_the_database(
    organization: Organization,
) -> None:
    root = await new_root(organization)
    await seed_change(root, secret="hunter2")
    await MonitoringSession(
        organization_id=organization.id,
        audit_ids=[root.audit_id],
        site_id=SITE,
        device_mac=MAC,
        device_name="SEA-SW-1",
        device_type=DeviceType.SWITCH,
        status=MonitoringStatus.COMPLETED,
        active=False,
    ).insert()

    await service().tick(root)

    published = await load(root.id)
    run = await GuardianRun.find_one({"_id": published.final_run_id})
    assert run is not None
    assert run.state == "succeeded"
    assert [atom.attribute for atom in run.change] == ["dns_servers"]
    # A plaintext value under a registry-declared sensitive name never reaches the stored run.
    assert "hunter2" not in repr(run.model_dump())
    assert run.anchor is not None
    assert run.anchor.source == "audit"
    assert any(item.source == "deployment" for item in run.evidence)
    assert guardian.check_run_document_size(run) > 0


async def test_a_run_above_its_asserted_bound_fails_rather_than_being_stored(
    organization: Organization, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = await new_root(organization)
    attempt = await commit(await load(root.id), await take_lease(root))
    await insert_run(attempt)
    fields = await succeeded_fields(attempt)

    def too_large(run: GuardianRun, **_kwargs: object) -> int:
        # Only the run carrying an outcome is over the bound; the failed record that replaces it is not.
        if run.verdict is None:
            return 1
        msg = f"Guardian run {run.id} serializes above its bound"
        raise RunDocumentTooLargeError(msg)

    monkeypatch.setattr(guardian, "check_run_document_size", too_large)
    finalized = await service()._finalize(attempt, AttemptOutcome(state="succeeded", fields=fields))

    assert finalized is not None
    assert finalized.state == "failed"
    stored = await GuardianRun.find_one({"_id": attempt.token})
    assert stored is not None
    assert stored.state == "failed"
    assert stored.verdict is None
    assert "bound" in (stored.failure_reason or "")


# -- indexes and retention -------------------------------------------------------------------------------------------


async def test_both_collections_carry_the_indexes_the_design_names() -> None:
    root_indexes = await roots().index_information()
    run_indexes = await runs().index_information()

    assert "guardian_investigation_identity" in root_indexes
    assert root_indexes["guardian_investigation_identity"]["unique"] is True
    assert "guardian_investigation_due" in root_indexes
    assert root_indexes["guardian_investigation_retention"]["expireAfterSeconds"] == 0
    assert "guardian_run_lookup" in run_indexes
    assert run_indexes["guardian_run_retention"]["expireAfterSeconds"] == 0


async def test_retention_never_backfills_a_guardian_document(organization: Organization) -> None:
    root = await new_root(organization)
    await service().tick(root)

    await maintain_investigation_retention()

    assert await roots().count_documents({"retained_until": None}) == 0
    assert await runs().count_documents({"retained_until": None}) == 0
    assert (await load(root.id)).retained_until is not None
