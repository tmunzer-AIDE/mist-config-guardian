"""Raw PyMongo filters and updates for every Guardian claim and run lifecycle transition, and for the API's reads.

This is the only place lifecycle predicates are written. Each builder is pure and returns the filter and update for
one conditional write; the orchestrator executes them and never inlines its own. Nothing uses transactions.

- **Tenancy.** The read builders the API is served from name the organization, and a run read names the
  investigation as well, so no read can resolve a run that belongs to another tenant or another audit.

- **One clock for root time.** Every authoritative temporal predicate and assignment on ``guardian_investigations``
  uses MongoDB's ``$$NOW`` through ``$expr`` filters and pipeline updates. Worker time appears only in the due query
  and the webhook's initial scheduling hint, both of which a later server-time CAS re-checks.
- **Fencing.** Every root write that touches a claim filters on the exact token and the claim's phase: uncommitted
  (``claim.attempt`` null) or committed (``claim.attempt`` equal to the run's attempt).
- **Literals.** Every assigned literal in a pipeline is wrapped in ``$literal``, so stored text such as a summary
  that starts with ``$`` is never evaluated as a field path.
- **Immutable terminal runs.** Every run update filters on ``state == running``, so none can match a terminal run.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from bson import ObjectId
from pydantic import TypeAdapter, ValidationError

from mist_config_guardian_backend.guardian.contracts import (
    ATTEMPT_DEADLINE,
    EARLY_CUTOFF,
    FINAL_FORCED,
    FINAL_MINIMUM,
    LEASE,
    MAX_ATTEMPTS_PER_KIND,
    RECHECK_DELAY,
    RunKind,
    SafeReason,
    StatusReason,
)

NOW = "$$NOW"
DUE_SORT = (("next_check_at", 1),)
DUE_LIMIT = 20
ABANDONED_REASON = "Lease expired before the attempt finished"
# Fields a finalization may store. Identity, timing and state are set by the builders themselves.
RUN_OUTCOME_FIELDS = frozenset(
    {
        "anchor",
        "as_of",
        "change",
        "change_omitted",
        "evidence",
        "ledger",
        "ledger_omitted",
        "obligations",
        "obligations_omitted",
        "monitoring",
        "deployment",
        "rules",
        "agent",
        "verdict",
        "steps",
        "steps_omitted",
        "budget",
    }
)

_SAFE_REASON: TypeAdapter[str] = TypeAdapter(SafeReason)
_STATUS_REASON: TypeAdapter[str] = TypeAdapter(StatusReason)


@dataclass(frozen=True, slots=True)
class Write:
    """One conditional ``update_one`` (or ``find_one_and_update``)."""

    filter: dict[str, Any]
    update: list[dict[str, Any]] | dict[str, Any]
    upsert: bool = False


@dataclass(frozen=True, slots=True)
class Read:
    """One tenant-scoped run query: the filter, and the projection and sort it is read with."""

    filter: dict[str, Any]
    projection: dict[str, int] | None = None
    sort: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class ClaimFence:
    """A claim token and its phase: ``attempt`` is null until the attempt is committed."""

    root_id: ObjectId
    token: ObjectId
    attempt: int | None = None

    def __post_init__(self) -> None:
        if self.attempt is not None and not 1 <= self.attempt <= MAX_ATTEMPTS_PER_KIND:
            msg = f"A committed attempt is numbered 1 to {MAX_ATTEMPTS_PER_KIND}"
            raise ValueError(msg)

    def as_filter(self) -> dict[str, Any]:
        return {"_id": self.root_id, "claim.token": self.token, "claim.attempt": self.attempt}


@dataclass(frozen=True, slots=True)
class CommittedAttempt:
    """A committed claim with its root identity: enough to rebuild the attempt record."""

    token: ObjectId
    organization_id: ObjectId
    investigation_id: ObjectId
    audit_id: str
    kind: RunKind
    attempt: int
    started_at: datetime
    retained_until: datetime | None

    def __post_init__(self) -> None:
        if not 1 <= self.attempt <= MAX_ATTEMPTS_PER_KIND:
            msg = f"A committed attempt is numbered 1 to {MAX_ATTEMPTS_PER_KIND}"
            raise ValueError(msg)


def _literal(value: object) -> dict[str, object]:
    return {"$literal": value}


def _after(start: str, delay: timedelta) -> dict[str, Any]:
    return {"$dateAdd": {"startDate": start, "unit": "millisecond", "amount": delay // timedelta(milliseconds=1)}}


def _uncommitted(fence: ClaimFence) -> dict[str, Any]:
    if fence.attempt is not None:
        msg = "This transition needs an uncommitted claim"
        raise ValueError(msg)
    return fence.as_filter()


def _committed(fence: ClaimFence) -> dict[str, Any]:
    if fence.attempt is None:
        msg = "This transition needs a committed claim"
        raise ValueError(msg)
    return fence.as_filter()


def _is_valid(adapter: TypeAdapter[str], text: str | None) -> bool:
    try:
        adapter.validate_python(text)
    except ValidationError:
        return False
    return True


def ensure_investigation(  # noqa: PLR0913 - one argument per identity, anchor and retention field
    *,
    organization_id: ObjectId,
    audit_id: str,
    changed_at: datetime,
    anchor_known: bool,
    now: datetime,
    retained_until: datetime | None,
) -> Write:
    """Idempotent root creation. ``$$NOW`` is unavailable in a classic upsert, so the first check is a worker hint."""
    return Write(
        filter={"organization_id": organization_id, "audit_id": audit_id},
        update={
            "$setOnInsert": {
                "changed_at": changed_at,
                "anchor_known": anchor_known,
                "status": "waiting",
                "status_reason": None,
                "next_check_at": max(now, changed_at) + RECHECK_DELAY,
                "claim": None,
                "attempts": {"early": 0, "final": 0},
                "early_run_id": None,
                "final_run_id": None,
                "result": None,
                "retained_until": retained_until,
                "created_at": now,
                "updated_at": now,
            }
        },
        upsert=True,
    )


def due_candidates_filter(now: datetime) -> dict[str, Any]:
    """Candidate selection on worker time over the ``(status, next_check_at)`` index; every step re-checks it."""
    return {
        "status": "waiting",
        "next_check_at": {"$lte": now},
        "$or": [{"claim": None}, {"claim.lease_until": {"$lte": now}}],
    }


def nothing_due(root_id: ObjectId) -> Write:
    return Write(
        filter={"_id": root_id, "status": "waiting", "claim": None, "$expr": {"$lte": ["$next_check_at", NOW]}},
        update=[{"$set": {"next_check_at": _after(NOW, RECHECK_DELAY), "updated_at": NOW}}],
    )


def lease(root_id: ObjectId, *, kind: RunKind, token: ObjectId) -> Write:
    """Take an uncommitted lease, repeating the root-local trigger conditions. No attempt is consumed."""
    query: dict[str, Any] = {
        "_id": root_id,
        "status": "waiting",
        "claim": None,
        f"attempts.{kind}": {"$lt": MAX_ATTEMPTS_PER_KIND},
    }
    conditions: list[dict[str, Any]] = [{"$lte": ["$next_check_at", NOW]}]
    if kind == "early":
        query["early_run_id"] = None
        conditions.append({"$lt": [NOW, _after("$changed_at", EARLY_CUTOFF)]})
        final_forced: dict[str, Any] = _literal(value=False)
    else:
        conditions.append({"$gte": [NOW, _after("$changed_at", FINAL_MINIMUM)]})
        final_forced = {"$gte": [NOW, _after("$changed_at", FINAL_FORCED)]}
    query["$expr"] = {"$and": conditions}
    claim = {
        "token": _literal(token),
        "kind": _literal(kind),
        "lease_until": _after(NOW, LEASE),
        "attempt": _literal(None),
        "started_at": _literal(None),
        "final_forced": final_forced,
    }
    return Write(filter=query, update=[{"$set": {"claim": claim, "updated_at": NOW}}])


def release(fence: ClaimFence) -> Write:
    """Free an uncommitted lease after failed revalidation or an unmatched commit. Idempotent with recovery."""
    return Write(
        filter=_uncommitted(fence),
        update=[{"$set": {"claim": _literal(None), "next_check_at": _after(NOW, RECHECK_DELAY), "updated_at": NOW}}],
    )


def commit_attempt(fence: ClaimFence, *, kind: RunKind) -> Write:
    """Consume one attempt under a live lease. Never retry it: resolve an ambiguous response by reading."""
    counter = f"attempts.{kind}"
    query: dict[str, Any] = {
        **_uncommitted(fence),
        "claim.kind": kind,
        "status": "waiting",
        counter: {"$lt": MAX_ATTEMPTS_PER_KIND},
    }
    conditions: list[dict[str, Any]] = [{"$gt": ["$claim.lease_until", NOW]}]
    if kind == "early":
        query["early_run_id"] = None
        conditions.append({"$lt": [NOW, _after("$changed_at", EARLY_CUTOFF)]})
    query["$expr"] = {"$and": conditions}
    attempt = {"$add": [f"${counter}", 1]}
    return Write(
        filter=query,
        update=[
            {
                "$set": {
                    counter: attempt,
                    "claim.attempt": attempt,
                    "claim.started_at": NOW,
                    "claim.lease_until": _after(NOW, LEASE),
                    "updated_at": NOW,
                }
            }
        ],
    )


def commit_applied_filter(fence: ClaimFence) -> dict[str, Any]:
    """Matches the root only if this uncommitted fence's commit was applied."""
    return {**_uncommitted(fence), "claim.attempt": {"$ne": None}}


def recover_uncommitted_claim(fence: ClaimFence) -> Write:
    """Clear an expired uncommitted claim. A stale commit that wins first makes this match nothing."""
    return Write(
        filter={**_uncommitted(fence), "$expr": {"$lte": ["$claim.lease_until", NOW]}},
        update=[{"$set": {"claim": _literal(None), "updated_at": NOW}}],
    )


def expired_committed_claim_filter(fence: ClaimFence) -> dict[str, Any]:
    """Gate committed recovery on server time before touching the run.

    Nothing renews a committed lease, so once this matches the claim's worker is past its deadline for good. Recovery
    then inserts or abandons the run, or adopts a terminal one, and closes with ``publish_succeeded_run`` or
    ``publish_failed_run`` on the same fence.
    """
    return {**_committed(fence), "$expr": {"$lte": ["$claim.lease_until", NOW]}}


def claimed_run(fence: ClaimFence, *, organization_id: ObjectId) -> dict[str, Any]:
    """The one run a committed claim owns, inside its own tenant and investigation.

    Recovery reads a run by the claim's token alone only in the sense that the token is an ``ObjectId`` nobody else
    holds; the tenant and investigation are still part of the filter, so a claim can never resolve, abandon or
    adopt another organization's run.
    """
    _committed(fence)
    return {"_id": fence.token, "organization_id": organization_id, "investigation_id": fence.root_id}


def investigations_for_audits(organization_id: ObjectId, audit_ids: Sequence[str]) -> Read:
    """The roots of one page of audits, projected to what a summary shows: status, reason, result and pointers."""
    return Read(
        filter={"organization_id": organization_id, "audit_id": {"$in": list(audit_ids)}},
        projection={"audit_id": 1, "status": 1, "status_reason": 1, "result": 1, "early_run_id": 1, "final_run_id": 1},
    )


def investigation_identity(organization_id: ObjectId, audit_id: str) -> Read:
    """One audit's root inside its tenant; the identity index makes it unique."""
    return Read(filter={"organization_id": organization_id, "audit_id": audit_id})


def investigation_runs(root_id: ObjectId, *, organization_id: ObjectId) -> Read:
    """Every attempt one root consumed, in kind and attempt order, inside its tenant."""
    return Read(
        filter={"organization_id": organization_id, "investigation_id": root_id},
        sort=(("kind", 1), ("attempt", 1)),
    )


def run_in_investigation(run_id: ObjectId, *, root_id: ObjectId, organization_id: ObjectId) -> Read:
    """One run, and only when it belongs to this organization and to this root's investigation."""
    return Read(filter={"_id": run_id, "organization_id": organization_id, "investigation_id": root_id})


def published_runs(pointers: Sequence[tuple[ObjectId, ObjectId]], *, organization_id: ObjectId) -> Read:
    """The exact runs a page of roots points at, projected to the impacted-device rows a site overlay shows.

    Each pointer is ``(run_id, investigation_id)``, so a root can only ever reach the run it published itself.
    """
    return Read(
        filter={
            "organization_id": organization_id,
            "$or": [{"_id": run_id, "investigation_id": root_id} for run_id, root_id in pointers],
        },
        projection={"investigation_id": 1, "verdict.impacted_devices": 1, "verdict.impacted_devices_omitted": 1},
    )


def last_failed_final_run(root_id: ObjectId, *, organization_id: ObjectId) -> Read:
    """The final run whose recorded reason closes an exhausted root: the highest attempt that recorded one.

    Recovery runs before exhaustion, so every consumed final attempt already has a terminal run; this picks the
    last one that recorded a reason, which is the reason the root's completion quotes.
    """
    return Read(
        filter={
            "organization_id": organization_id,
            "investigation_id": root_id,
            "kind": "final",
            "failure_reason": {"$ne": None},
        },
        projection={"attempt": 1, "failure_reason": 1},
        sort=(("attempt", -1),),
    )


def publish_succeeded_run(
    fence: ClaimFence, *, kind: RunKind, result: Mapping[str, Any], status_reason: str | None = None
) -> Write:
    """Point the root at a succeeded run. Used by the run's worker and by recovery; at most one matches.

    ``result`` is the BSON-encoded ``GuardianResult`` for this run, stored whole in place of any earlier result.
    """
    query = {**_committed(fence), "claim.kind": kind, "status": "waiting"}
    if result.get("run_id") != fence.token or result.get("run_kind") != kind:
        msg = "A published result describes the run it points at"
        raise ValueError(msg)
    fields: dict[str, Any] = {
        "claim": _literal(None),
        f"{kind}_run_id": _literal(fence.token),
        "result": _literal(dict(result)),
    }
    if kind == "final":
        if not _is_valid(_STATUS_REASON, status_reason):
            msg = "A final publication needs a bounded single-line status reason"
            raise ValueError(msg)
        fields |= {
            "status": _literal("done"),
            "status_reason": _literal(status_reason),
            "next_check_at": _literal(None),
        }
    else:
        if status_reason is not None:
            msg = "An early publication sets no status reason"
            raise ValueError(msg)
        fields["next_check_at"] = _after(NOW, RECHECK_DELAY)
    return Write(filter=query, update=[{"$set": fields | {"updated_at": NOW}}])


def publish_failed_run(fence: ClaimFence) -> Write:
    """Publish a failed or abandoned run: no pointer, the result stays, and the root is re-checked later."""
    return Write(
        filter={**_committed(fence), "status": "waiting"},
        update=[{"$set": {"claim": _literal(None), "next_check_at": _after(NOW, RECHECK_DELAY), "updated_at": NOW}}],
    )


def exhaust_final_attempts(root_id: ObjectId, *, last_failure_reason: str) -> Write:
    """Complete a root whose final attempts all failed, keeping any early result. Runs only after recovery."""
    if not _is_valid(_SAFE_REASON, last_failure_reason):
        msg = "Exhaustion reports the last final run's bounded failure reason"
        raise ValueError(msg)
    reason = f"Final run failed after {MAX_ATTEMPTS_PER_KIND} attempts: {last_failure_reason}"
    return Write(
        filter={
            "_id": root_id,
            "status": "waiting",
            "claim": None,
            "attempts.final": MAX_ATTEMPTS_PER_KIND,
            "final_run_id": None,
            "$expr": {"$lte": ["$next_check_at", NOW]},
        },
        update=[
            {
                "$set": {
                    "status": _literal("done"),
                    "status_reason": _literal(reason),
                    "next_check_at": _literal(None),
                    "updated_at": NOW,
                }
            }
        ],
    )


def _run_identity(attempt: CommittedAttempt, now: datetime) -> dict[str, Any]:
    return {
        "_id": attempt.token,
        "organization_id": attempt.organization_id,
        "investigation_id": attempt.investigation_id,
        "audit_id": attempt.audit_id,
        "kind": attempt.kind,
        "attempt": attempt.attempt,
        "started_at": attempt.started_at,
        "deadline_at": attempt.started_at + ATTEMPT_DEADLINE,
        "retained_until": attempt.retained_until,
        "created_at": now,
        "updated_at": now,
    }


def running_run_document(attempt: CommittedAttempt, *, now: datetime) -> dict[str, Any]:
    """The run a worker inserts after its commit. A duplicate key means recovery already resolved the token."""
    return _run_identity(attempt, now) | {"state": "running", "finished_at": None, "failure_reason": None}


def abandoned_run_document(attempt: CommittedAttempt, *, now: datetime) -> dict[str, Any]:
    """The record recovery inserts for a committed attempt with no run. On a duplicate key, read the run again."""
    return _run_identity(attempt, now) | {"state": "abandoned", "finished_at": now, "failure_reason": ABANDONED_REASON}


def finalize_run(
    token: ObjectId,
    *,
    state: Literal["succeeded", "failed"],
    fields: Mapping[str, Any],
    failure_reason: str | None = None,
) -> Write:
    """Move a running run to its terminal state before publication. No match means recovery abandoned it."""
    if state not in {"succeeded", "failed"}:
        msg = "Finalization moves a running run to the terminal state succeeded or failed"
        raise ValueError(msg)
    if unknown := sorted(set(fields) - RUN_OUTCOME_FIELDS):
        msg = f"Not a run outcome field: {', '.join(unknown)}"
        raise ValueError(msg)
    if state == "succeeded":
        if fields.get("verdict") is None:
            msg = "A succeeded run needs a verdict"
            raise ValueError(msg)
        if failure_reason is not None:
            msg = "A succeeded run has no failure reason"
            raise ValueError(msg)
    elif not _is_valid(_SAFE_REASON, failure_reason):
        msg = "A failed run needs a bounded single-line failure reason"
        raise ValueError(msg)
    assigned = {name: _literal(value) for name, value in fields.items()}
    return Write(
        filter={"_id": token, "state": "running"},
        update=[
            {
                "$set": assigned
                | {
                    "state": _literal(state),
                    "failure_reason": _literal(failure_reason),
                    "finished_at": NOW,
                    "updated_at": NOW,
                }
            }
        ],
    )


def abandon_running_run(token: ObjectId) -> Write:
    """Recovery's mark for a run whose lease expired while running. No match means it already ended."""
    return Write(
        filter={"_id": token, "state": "running"},
        update=[
            {
                "$set": {
                    "state": _literal("abandoned"),
                    "failure_reason": _literal(ABANDONED_REASON),
                    "finished_at": NOW,
                    "updated_at": NOW,
                }
            }
        ],
    )
