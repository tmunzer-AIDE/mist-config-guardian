"""Every Guardian claim and run lifecycle write is a pure builder, fenced by token and phase, timed by $$NOW."""

import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from bson import ObjectId

from mist_config_guardian_backend.guardian import repository as repo

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
ROOT = ObjectId()
TOKEN = ObjectId()
ORG = ObjectId()
LEASE_END = {"$dateAdd": {"startDate": "$$NOW", "unit": "millisecond", "amount": 300_000}}
RECHECK = {"$dateAdd": {"startDate": "$$NOW", "unit": "millisecond", "amount": 60_000}}
EARLY_CUTOFF = {"$dateAdd": {"startDate": "$changed_at", "unit": "millisecond", "amount": 2_700_000}}
FINAL_MINIMUM = {"$dateAdd": {"startDate": "$changed_at", "unit": "millisecond", "amount": 3_600_000}}
FINAL_FORCED = {"$dateAdd": {"startDate": "$changed_at", "unit": "millisecond", "amount": 7_200_000}}
UNCOMMITTED = repo.ClaimFence(root_id=ROOT, token=TOKEN)
COMMITTED = repo.ClaimFence(root_id=ROOT, token=TOKEN, attempt=2)


def walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from walk(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from walk(item)


def result(kind: str = "early", **overrides) -> dict[str, Any]:
    return {"run_id": TOKEN, "run_kind": kind, "summary": "$claim is literal text"} | overrides


def root_writes() -> dict[str, repo.Write]:
    return {
        "nothing_due": repo.nothing_due(ROOT),
        "lease_early": repo.lease(ROOT, kind="early", token=TOKEN),
        "lease_final": repo.lease(ROOT, kind="final", token=TOKEN),
        "release": repo.release(UNCOMMITTED),
        "commit_early": repo.commit_attempt(UNCOMMITTED, kind="early"),
        "commit_final": repo.commit_attempt(UNCOMMITTED, kind="final"),
        "recover_uncommitted": repo.recover_uncommitted_claim(UNCOMMITTED),
        "publish_early": repo.publish_succeeded_run(COMMITTED, kind="early", result=result()),
        "publish_final": repo.publish_succeeded_run(
            COMMITTED, kind="final", result=result("final"), status_reason="Final run published"
        ),
        "publish_failed": repo.publish_failed_run(COMMITTED),
        "exhaust": repo.exhaust_final_attempts(ROOT, last_failure_reason="Provider timed out"),
    }


def test_the_due_query_is_a_plain_indexed_candidate_filter_on_worker_time():
    assert repo.due_candidates_filter(NOW) == {
        "status": "waiting",
        "next_check_at": {"$lte": NOW},
        "$or": [{"claim": None}, {"claim.lease_until": {"$lte": NOW}}],
    }
    assert repo.DUE_SORT == (("next_check_at", 1),)
    assert repo.DUE_LIMIT == 20
    assert "$$NOW" not in walk(repo.due_candidates_filter(NOW))


@pytest.mark.parametrize(
    ("changed_at", "first_check"),
    [(NOW - timedelta(hours=1), NOW), (NOW + timedelta(seconds=5), NOW + timedelta(seconds=5))],
)
def test_ensure_inserts_a_waiting_root_once_with_a_worker_time_hint(changed_at, first_check):
    retained = NOW + timedelta(days=30)
    write = repo.ensure_investigation(
        organization_id=ORG,
        audit_id="audit-1",
        changed_at=changed_at,
        anchor_known=True,
        now=NOW,
        retained_until=retained,
    )
    assert write.upsert
    assert write.filter == {"organization_id": ORG, "audit_id": "audit-1"}
    assert write.update == {
        "$setOnInsert": {
            "changed_at": changed_at,
            "anchor_known": True,
            "status": "waiting",
            "status_reason": None,
            "next_check_at": first_check + timedelta(minutes=1),
            "claim": None,
            "attempts": {"early": 0, "final": 0},
            "early_run_id": None,
            "final_run_id": None,
            "result": None,
            "retained_until": retained,
            "created_at": NOW,
            "updated_at": NOW,
        }
    }


@pytest.mark.parametrize("name", list(root_writes()))
def test_every_root_cas_is_a_server_time_pipeline(name):
    write = root_writes()[name]
    assert not write.upsert
    assert write.filter["_id"] == ROOT
    assert not any(isinstance(item, datetime) for item in walk(write.filter)), "no worker time in a root CAS"
    assert not any(isinstance(item, datetime) for item in walk(write.update)), "no worker time in a root CAS"
    assert isinstance(write.update, list)
    assert "$$NOW" in walk(write.filter) or "$expr" not in write.filter
    [stage] = write.update
    assert stage["$set"]["updated_at"] == "$$NOW"
    # Every assigned value is an expression, $$NOW or $literal, so stored text can never be read as a field path.
    assert all(isinstance(value, dict) or value == "$$NOW" for value in stage["$set"].values())


@pytest.mark.parametrize(
    "name", [n for n in root_writes() if n not in {"nothing_due", "lease_early", "lease_final", "exhaust"}]
)
def test_every_claim_transition_is_fenced_by_token_and_phase(name):
    query = root_writes()[name].filter
    assert query["claim.token"] == TOKEN
    assert query["claim.attempt"] in (None, 2)


def test_nothing_due_only_moves_a_due_unclaimed_root():
    assert repo.nothing_due(ROOT) == repo.Write(
        filter={"_id": ROOT, "status": "waiting", "claim": None, "$expr": {"$lte": ["$next_check_at", "$$NOW"]}},
        update=[{"$set": {"next_check_at": RECHECK, "updated_at": "$$NOW"}}],
    )


def test_early_lease_repeats_root_local_trigger_conditions_on_server_time():
    assert repo.lease(ROOT, kind="early", token=TOKEN) == repo.Write(
        filter={
            "_id": ROOT,
            "status": "waiting",
            "claim": None,
            "attempts.early": {"$lt": 2},
            "early_run_id": None,
            "$expr": {"$and": [{"$lte": ["$next_check_at", "$$NOW"]}, {"$lt": ["$$NOW", EARLY_CUTOFF]}]},
        },
        update=[
            {
                "$set": {
                    "claim": {
                        "token": {"$literal": TOKEN},
                        "kind": {"$literal": "early"},
                        "lease_until": LEASE_END,
                        "attempt": {"$literal": None},
                        "started_at": {"$literal": None},
                        "final_forced": {"$literal": False},
                    },
                    "updated_at": "$$NOW",
                }
            }
        ],
    )


def test_final_lease_records_the_forced_branch_evaluated_on_server_time():
    write = repo.lease(ROOT, kind="final", token=TOKEN)
    assert write.filter == {
        "_id": ROOT,
        "status": "waiting",
        "claim": None,
        "attempts.final": {"$lt": 2},
        "$expr": {"$and": [{"$lte": ["$next_check_at", "$$NOW"]}, {"$gte": ["$$NOW", FINAL_MINIMUM]}]},
    }
    assert write.update[0]["$set"]["claim"]["final_forced"] == {"$gte": ["$$NOW", FINAL_FORCED]}
    assert write.update[0]["$set"]["claim"]["kind"] == {"$literal": "final"}


def test_release_frees_only_an_uncommitted_claim_and_delays_the_next_check():
    assert repo.release(UNCOMMITTED) == repo.Write(
        filter={"_id": ROOT, "claim.token": TOKEN, "claim.attempt": None},
        update=[{"$set": {"claim": {"$literal": None}, "next_check_at": RECHECK, "updated_at": "$$NOW"}}],
    )


def test_early_commit_rechecks_the_live_lease_attempts_and_cutoff_then_consumes_one_attempt():
    assert repo.commit_attempt(UNCOMMITTED, kind="early") == repo.Write(
        filter={
            "_id": ROOT,
            "claim.token": TOKEN,
            "claim.attempt": None,
            "claim.kind": "early",
            "status": "waiting",
            "attempts.early": {"$lt": 2},
            "early_run_id": None,
            "$expr": {"$and": [{"$gt": ["$claim.lease_until", "$$NOW"]}, {"$lt": ["$$NOW", EARLY_CUTOFF]}]},
        },
        update=[
            {
                "$set": {
                    "attempts.early": {"$add": ["$attempts.early", 1]},
                    "claim.attempt": {"$add": ["$attempts.early", 1]},
                    "claim.started_at": "$$NOW",
                    "claim.lease_until": LEASE_END,
                    "updated_at": "$$NOW",
                }
            }
        ],
    )


def test_final_commit_has_no_early_cutoff():
    write = repo.commit_attempt(UNCOMMITTED, kind="final")
    assert "early_run_id" not in write.filter
    assert write.filter["attempts.final"] == {"$lt": 2}
    assert write.filter["$expr"] == {"$and": [{"$gt": ["$claim.lease_until", "$$NOW"]}]}
    assert write.update[0]["$set"]["claim.attempt"] == {"$add": ["$attempts.final", 1]}


def test_an_ambiguous_commit_is_resolved_by_reading_the_token_phase():
    assert repo.commit_applied_filter(UNCOMMITTED) == {
        "_id": ROOT,
        "claim.token": TOKEN,
        "claim.attempt": {"$ne": None},
    }


def test_claim_recovery_judges_expiry_on_server_time_in_each_phase():
    assert repo.recover_uncommitted_claim(UNCOMMITTED) == repo.Write(
        filter={
            "_id": ROOT,
            "claim.token": TOKEN,
            "claim.attempt": None,
            "$expr": {"$lte": ["$claim.lease_until", "$$NOW"]},
        },
        update=[{"$set": {"claim": {"$literal": None}, "updated_at": "$$NOW"}}],
    )
    assert repo.expired_committed_claim_filter(COMMITTED) == {
        "_id": ROOT,
        "claim.token": TOKEN,
        "claim.attempt": 2,
        "$expr": {"$lte": ["$claim.lease_until", "$$NOW"]},
    }


def test_publishing_a_succeeded_early_run_sets_its_pointer_and_result_and_keeps_waiting():
    assert repo.publish_succeeded_run(COMMITTED, kind="early", result=result()) == repo.Write(
        filter={"_id": ROOT, "claim.token": TOKEN, "claim.attempt": 2, "claim.kind": "early", "status": "waiting"},
        update=[
            {
                "$set": {
                    "claim": {"$literal": None},
                    "early_run_id": {"$literal": TOKEN},
                    "result": {"$literal": result()},
                    "next_check_at": RECHECK,
                    "updated_at": "$$NOW",
                }
            }
        ],
    )


def test_publishing_a_succeeded_final_run_completes_the_root():
    write = repo.publish_succeeded_run(COMMITTED, kind="final", result=result("final"), status_reason="Published")
    assert write.filter == {
        "_id": ROOT,
        "claim.token": TOKEN,
        "claim.attempt": 2,
        "claim.kind": "final",
        "status": "waiting",
    }
    assert write.update == [
        {
            "$set": {
                "claim": {"$literal": None},
                "final_run_id": {"$literal": TOKEN},
                "result": {"$literal": result("final")},
                "status": {"$literal": "done"},
                "status_reason": {"$literal": "Published"},
                "next_check_at": {"$literal": None},
                "updated_at": "$$NOW",
            }
        }
    ]


def test_publishing_a_failed_run_sets_no_pointer_and_keeps_the_result():
    assert repo.publish_failed_run(COMMITTED) == repo.Write(
        filter={"_id": ROOT, "claim.token": TOKEN, "claim.attempt": 2, "status": "waiting"},
        update=[{"$set": {"claim": {"$literal": None}, "next_check_at": RECHECK, "updated_at": "$$NOW"}}],
    )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"kind": "early", "result": result(run_id=ObjectId())}, "describes"),
        ({"kind": "final", "result": result("early"), "status_reason": "x"}, "describes"),
        ({"kind": "early", "result": result(), "status_reason": "Done"}, "status reason"),
        ({"kind": "final", "result": result("final")}, "status reason"),
        ({"kind": "final", "result": result("final"), "status_reason": "line\nbreak"}, "status reason"),
    ],
)
def test_publication_refuses_results_that_do_not_match_the_fenced_run(kwargs, message):
    with pytest.raises(ValueError, match=message):
        repo.publish_succeeded_run(COMMITTED, **kwargs)


def test_builders_refuse_the_wrong_claim_phase():
    for build in (repo.release, repo.recover_uncommitted_claim, repo.commit_applied_filter):
        with pytest.raises(ValueError, match="uncommitted"):
            build(COMMITTED)
    with pytest.raises(ValueError, match="uncommitted"):
        repo.commit_attempt(COMMITTED, kind="final")
    for build in (repo.publish_failed_run, repo.expired_committed_claim_filter):
        with pytest.raises(ValueError, match="committed"):
            build(UNCOMMITTED)
    with pytest.raises(ValueError, match="committed"):
        repo.publish_succeeded_run(UNCOMMITTED, kind="early", result=result())
    for attempt in (0, 3):
        with pytest.raises(ValueError, match="attempt"):
            repo.ClaimFence(root_id=ROOT, token=TOKEN, attempt=attempt)


def test_exhaustion_completes_an_unclaimed_root_with_the_last_final_failure():
    assert repo.exhaust_final_attempts(ROOT, last_failure_reason="Lease expired") == repo.Write(
        filter={
            "_id": ROOT,
            "status": "waiting",
            "claim": None,
            "attempts.final": 2,
            "final_run_id": None,
            "$expr": {"$lte": ["$next_check_at", "$$NOW"]},
        },
        update=[
            {
                "$set": {
                    "status": {"$literal": "done"},
                    "status_reason": {"$literal": "Final run failed after 2 attempts: Lease expired"},
                    "next_check_at": {"$literal": None},
                    "updated_at": "$$NOW",
                }
            }
        ],
    )
    with pytest.raises(ValueError, match="reason"):
        repo.exhaust_final_attempts(ROOT, last_failure_reason="")


def attempt(**overrides) -> repo.CommittedAttempt:
    values = {
        "token": TOKEN,
        "organization_id": ORG,
        "investigation_id": ROOT,
        "audit_id": "audit-1",
        "kind": "final",
        "attempt": 1,
        "started_at": NOW,
        "retained_until": NOW + timedelta(days=30),
    }
    return repo.CommittedAttempt(**(values | overrides))


def test_run_inserts_are_rebuilt_from_the_committed_claim():
    identity = {
        "_id": TOKEN,
        "organization_id": ORG,
        "investigation_id": ROOT,
        "audit_id": "audit-1",
        "kind": "final",
        "attempt": 1,
        "started_at": NOW,
        "deadline_at": NOW + timedelta(seconds=240),
        "retained_until": NOW + timedelta(days=30),
        "created_at": NOW + timedelta(seconds=1),
        "updated_at": NOW + timedelta(seconds=1),
    }
    later = NOW + timedelta(seconds=1)
    assert repo.running_run_document(attempt(), now=later) == identity | {
        "state": "running",
        "finished_at": None,
        "failure_reason": None,
    }
    assert repo.abandoned_run_document(attempt(), now=later) == identity | {
        "state": "abandoned",
        "finished_at": later,
        "failure_reason": "Lease expired before the attempt finished",
    }
    with pytest.raises(ValueError, match="attempt"):
        attempt(attempt=3)


def test_finalization_only_moves_a_running_run_and_stores_outcome_fields_literally():
    verdict = {"peak": "info", "summary": "$evidence stays text"}
    assert repo.finalize_run(TOKEN, state="succeeded", fields={"verdict": verdict, "evidence": []}) == repo.Write(
        filter={"_id": TOKEN, "state": "running"},
        update=[
            {
                "$set": {
                    "verdict": {"$literal": verdict},
                    "evidence": {"$literal": []},
                    "state": {"$literal": "succeeded"},
                    "failure_reason": {"$literal": None},
                    "finished_at": "$$NOW",
                    "updated_at": "$$NOW",
                }
            }
        ],
    )
    failed = repo.finalize_run(TOKEN, state="failed", fields={}, failure_reason="Ledger construction failed")
    assert failed.filter == {"_id": TOKEN, "state": "running"}
    assert failed.update[0]["$set"]["failure_reason"] == {"$literal": "Ledger construction failed"}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"state": "succeeded", "fields": {}}, "verdict"),
        ({"state": "succeeded", "fields": {"verdict": {}}, "failure_reason": "x"}, "reason"),
        ({"state": "failed", "fields": {}}, "reason"),
        ({"state": "failed", "fields": {}, "failure_reason": "x" * 301}, "reason"),
        ({"state": "running", "fields": {}}, "terminal"),
        ({"state": "abandoned", "fields": {}, "failure_reason": "x"}, "terminal"),
        ({"state": "failed", "fields": {"state": "succeeded"}, "failure_reason": "x"}, "outcome field"),
        ({"state": "failed", "fields": {"_id": ObjectId()}, "failure_reason": "x"}, "outcome field"),
    ],
)
def test_finalization_refuses_inconsistent_outcomes(kwargs, message):
    with pytest.raises(ValueError, match=message):
        repo.finalize_run(TOKEN, **kwargs)


def test_recovery_abandons_only_a_running_run():
    assert repo.abandon_running_run(TOKEN) == repo.Write(
        filter={"_id": TOKEN, "state": "running"},
        update=[
            {
                "$set": {
                    "state": {"$literal": "abandoned"},
                    "failure_reason": {"$literal": "Lease expired before the attempt finished"},
                    "finished_at": "$$NOW",
                    "updated_at": "$$NOW",
                }
            }
        ],
    )


def test_no_run_write_can_match_a_terminal_run():
    writes = [
        repo.abandon_running_run(TOKEN),
        repo.finalize_run(TOKEN, state="succeeded", fields={"verdict": {}}),
        repo.finalize_run(TOKEN, state="failed", fields={}, failure_reason="x"),
    ]
    assert all(write.filter == {"_id": TOKEN, "state": "running"} for write in writes)


def test_builders_stay_pure_and_import_no_odm_or_driver():
    probe = (
        "import sys; import mist_config_guardian_backend.guardian.repository; "
        "loaded = {'beanie', 'pymongo', 'motor'} & set(sys.modules); "
        "sys.exit(f'loaded: {sorted(loaded)}' if loaded else 0)"
    )
    subprocess.run([sys.executable, "-c", probe], check=True)  # noqa: S603 - fixed interpreter and probe
