# Restore Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make configuration restore crash-safe, recreation-correct, concurrency-safe, drift-safe, consistently hashed, and bound to a reviewed intent, so that no restore can be left running forever, silently split history, overwrite unrelated changes, or execute without a fresh backup.

**Architecture:** The Mist mutation client classifies every failure (and whether a write may have been applied) and retries within bounds. The executor guarantees a terminal, notified, credential-free state on every exit, guards every write with a live re-read and a read-back, holds an organization lease, and records restored identities under the keys the backup collector uses. Compensation compares against what the restore actually wrote and can be re-planned. One fingerprint module owns normalization and hashing for backup, baseline, compensation, executor and verification. Execution requires a prepared plan, and approvals bind to the plan's intent so they survive preparation.

**Tech Stack:** Python 3.13, FastAPI, Beanie/MongoDB (pymongo async), Celery (beat), httpx + pytest-httpx 0.36, pydantic v2, uv, ruff, ty; Angular 20 standalone components with signals, Vitest.

**Spec:** The "Review findings" section of this plan (verified code review, 2026-09-14) and docs/product-specification.md §9.

This plan lives at `docs/superpowers/plans/2026-09-14-restore-hardening.md`.

## Global Constraints

- Stored historical operations, approvals, logical objects and versions remain readable. Every new model field is optional with a default. No bulk migration unless a task says so (none does).
- Never log, return, or put in an exception message a secret, delegated credential, token, or configuration value. Log records carry operation ids, action orders, object names and exception *type names* only.
- Delegated credentials (`encrypted_delegated_credential`, `delegated_credential_expires_at`) are cleared whenever an operation reaches a terminal status (`completed`, `failed`, `compensation_available`, `compensated`, `superseded`).
- No real Mist calls in tests. Use `pytest_httpx` for the HTTP client and the fakes named in each task everywhere else.
- DB-backed tests are skipped unless `MONGO_TEST_URL` is set; run them with `MONGO_TEST_URL=mongodb://localhost:27018`. Follow the module-scoped-loop pattern in `backend/tests/test_restore_targets_mongo.py:35-56`.
- Backend gate, from the repository root: `cd backend && uv run ruff format --check . && uv run ruff check . && uv run ty check src && uv run pytest`.
- Any response-schema or route change requires `make openapi` (writes `docs/openapi.json`); `cd backend && uv run python ../scripts/export-openapi.py --check` must pass before commit.
- When `frontend/` is touched: `cd frontend && npm test -- --watch=false && npm run build` must pass.
- Docstrings on public functions and classes (ruff enforces). Explain why, not what.
- Every task ends green. Never commit with a failing test. Commit only the paths the task names.
- Every commit message ends with the trailer `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

## Review findings

File references are relative to `backend/src/mist_config_guardian_backend`. H1, H2, H4 and H5 were verified by the controller; the implementer re-verifies each finding at the start of its task (the "Re-verify" step).

| ID | Finding | Evidence | Task |
|----|---------|----------|------|
| H1 | A crash mid-execution leaves the operation `RUNNING` forever. `RestoreExecutor.execute` has no catch-all; `_run_actions` only catches `MistMutationError`; the mutation client raises that only for status/JSON errors, not httpx transport/timeout errors; `_record_result` can hit `DuplicateKeyError` inserting `latest.version + 1` while a webhook tombstones; decrypt errors escape. Result: `RUNNING` status, `EXECUTING` action, no notification, compensation refused (needs `COMPENSATION_AVAILABLE`), credential never cleared (expiry job only scans `PLANNED`/`QUEUED`), no stale-`RUNNING` janitor. | `services/restore_executor.py:76-132, 175-204, 389`; `integrations/mist_mutation.py:116-136`; `services/audit_versioning.py:139-158`; `services/restore_compensation.py:341`; `services/restore_authorization.py:247-272` | 1, 2, 3, 4 |
| M6 | No 429/5xx retry for Mist writes or reads during restore. | `integrations/mist_mutation.py:122` | 1 |
| H2 | Reverse dependents of a restored deleted object are added at their current version and then dropped (`target.id == latest.id` → no action; fresh-baseline equal-hash skip), so references are never rewritten to the recreated UUID and verification's stale-reference check fails. Spec §9.4 steps 4-5 promise reference updates. | `services/restore_planner.py:497-507, 589-597, 711`; `services/restore_verification.py:53-76` | 7 |
| H3 | Restoring a deleted site with its settings: the webhook tombstones site children; site settings are non-list → `UPDATE` with `expected_current_hash=None`; `capture_safety_snapshot` pre-reads every action against the old site id before the site is recreated → preflight fails. Spec §9.1. | `services/audit_versioning.py:114-128`; `services/restore_planner.py:632, 706-709`; `services/restore_compensation.py:83-98, 305-312` | 5 |
| H4 | `_record_result` updates `current_mist_id` but never `source_key`; the collector matches `LogicalObject` by `f"{site_id or 'org'}:{definition.key}:{mist_object_id}"`, so a recreated object splits into two logical identities. | `services/restore_executor.py:415-420`; `services/snapshots.py:219-237` | 6 |
| M7 | CREATE preflight only checks the old UUID; an object recreated manually (new UUID, same name) is duplicated. | `services/restore_compensation.py:300-304`; `services/restore_baseline.py:114-122` | 8 |
| H5 | No organization-scoped restore lock (spec §9.5.1); all live reads happen once before the first write, whereas spec §9.4.6 re-reads immediately before each update. | `services/restore_compensation.py:83` | 5 (re-read), 9 (lock) |
| M1 | Compensation drift protection: relaxed mode returns before the hash compare; inverse actions carry `expected_current_hash=None`, so compensation overwrites manual fixes made after the failed restore. | `services/restore_compensation.py:308-309, 540` | 10 |
| M2 | A failed compensation is not retryable: a second plan is created when the existing one is not `PLANNED`, but `find_compensation_of` is an unsorted `find_one`, so the execute route can load the old failed plan. | `services/restore_compensation.py:350-357`; `services/restore_planner.py:174-184` | 10 |
| M3 | `RESTORED` versions are hashed from `result or payload` without the definition's `ignored_fields` (Mist response includes `modified_time`; payload lacks `id`/`org_id`/`site_id`) → false drift and spurious updates until the next backup. Same family as #28 (8144ff0). | `services/restore_executor.py:382-404` | 11 |
| S1 | Normalization/hashing is duplicated about six ways; verification compares nested values strictly with no ignored fields or mask tolerance. | `services/snapshots.py:259-292`; `services/restore_baseline.py:138`; `services/restore_compensation.py:122, 186, 315, 498`; `services/restore_executor.py:403`; `services/restore_verification.py:279-282` | 11 |
| M4 | The unprepared execute path is still accepted (pasted token, no fresh baseline); the UI only uses prepared execution and compensation. The original plan stays `PLANNED` after prepare. | `api/routes/restores.py:198-223`; `services/restore_authorization.py:132-153`; `frontend/src/app/features/restore/restore-page.ts:787-827, 1034-1060` | 12 |
| M5 | Approval is bound to the prepared plan hash; the prepared session lasts 15 minutes (`delegated_credential_ttl_minutes`, expiry job every 60 s) so a second approver must act inside 15 minutes. The plan hash omits payload and target ids; `assert_plan_current` passes when no state record exists. | `config.py:53`; `services/approvals.py:51-70`; `services/restore_planner.py:279-292` | 13 |
| S2 | Dead resume path: completed actions are skipped but nothing re-queues partial plans. | `services/restore_executor.py:183-186`; `tests/test_restore_verification.py:535-548` | 2 |

## Task order and dependencies

Tasks keep the binding group order 1 → 5. **One explicit reordering:** the per-write live re-read from decision 3 (H5 second half) is implemented in Task 5, at the start of group 2, because the H3 fix (deferred reads under a recreated site) *is* that re-read. Task 9 (lease) and Task 10 (strict compensation drift) build on it.

| Group | Task | Title |
|-------|------|-------|
| 1 Crash safety | 1 | Typed Mist mutation errors with bounded retry |
| | 2 | The executor always reaches a terminal, notified, credential-free state |
| | 3 | Compensation of unconfirmed writes |
| | 4 | Worker heartbeat and interrupted-restore janitor |
| 2 Recreation | 5 | Per-write live guard, read-back, and deferred reads under a recreated site (moved ahead from decision 3) |
| | 6 | Restored identities keep the collector's source key |
| | 7 | Forced reference-rewrite actions for reverse dependents |
| | 8 | CREATE preflight refuses a live name collision |
| 3 Concurrency/drift | 9 | Organization restore lease |
| | 10 | Strict compensation drift and retryable compensation |
| 4 Normalization | 11 | One configuration fingerprint module |
| 5 API/approval | 12 | Prepared-only execution and superseded drafts |
| | 13 | Approvals bound to plan intent and carried across prepare |

## File map

| File | Responsibility | Tasks |
|------|----------------|-------|
| `integrations/mist_mutation.py` | Typed errors, retry policy, `list_objects` | 1, 8 |
| `models/restore.py` | New action fields (`outcome_unknown`, `compensates_action_order`, `applied_hash`, `resulting_site_mist_id`, `reason`), `RestoreActionReason`, `RestoreStatus.SUPERSEDED`, `superseded_by`, `RestoreLease` | 2, 3, 5, 6, 7, 9, 12 |
| `services/restore_outcome.py` (new) | Terminal failure status and unconfirmed-action marking shared by executor and janitor | 2, 4, 10 |
| `services/restore_executor.py` | Execution flow, heartbeat, lease, guard, read-back, identity recording | 2, 3, 4, 5, 6, 9, 10, 11 |
| `services/restore_recovery.py` (new) | Stale `RUNNING` janitor | 4, 9 |
| `services/restore_write_guard.py` (new) | Pre-write live check and deferred snapshot entries | 5, 10 |
| `services/restore_identity.py` (new) | Source-key re-keying and adoption of a racing capture | 6 |
| `services/restore_lease.py` (new) | Lease store protocol, Mongo and memory stores, active-restore query | 9 |
| `services/restore_compensation.py` | Snapshot capture, name-collision preflight, inversion, strict drift | 3, 5, 8, 10, 11 |
| `services/restore_planner.py` | Reference-rewrite actions, compensation lookup, fail-closed plan currency | 7, 10, 13 |
| `services/restore_baseline.py` | Skip reads under deleted sites; fingerprint | 5, 11 |
| `services/restore_verification.py` | Masked-tolerant read-after-write | 11 |
| `services/snapshots.py` | `source_key` helper; fingerprint | 6, 11 |
| `snapshots/fingerprint.py` (new) | Single normalization/hash/equivalence module | 11 |
| `services/restore_authorization.py` | Concurrency 409, prepared-only authorize, supersede draft | 4, 9, 12 |
| `services/approvals.py`, `models/approval.py` | Plan hash, intent hash, action signature, carry-over | 13 |
| `api/routes/restores.py`, `schemas/restore.py` | Execute/prepare contracts, 409 mapping, response fields | 2, 7, 9, 12, 13 |
| `tasks/restores.py`, `worker.py`, `config.py` | Janitor task and schedule, heartbeat timeout | 4 |
| `frontend/src/app/features/restore/*` | Status/flag rendering, prepared-only client, approval before prepare | 2, 7, 12, 13 |

---

### Task 1: Typed Mist mutation errors with bounded retry

**Findings:** H1 (transport errors escape), M6.

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/integrations/mist_mutation.py` (whole module; current 136 lines)
- Test: `backend/tests/test_mist_mutation.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `class MistMutationError(RuntimeError)` with `__init__(self, message: str, *, outcome_unknown: bool = False, status_code: int | None = None)` and attributes `outcome_unknown: bool`, `status_code: int | None`. Existing `MistMutationError(msg)` call sites stay valid.
  - `class MistMutationStatusError(MistMutationError)` — Mist answered with a non-success status.
  - `class MistMutationTransportError(MistMutationError)` — no usable answer (connect/read/timeout/protocol).
  - `MistMutationClient.__init__(self, *, token: str, region: MistCloudRegion, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep)`.
  - Constants `MAX_ATTEMPTS = 3`, `BACKOFF_BASE_SECONDS = 0.5`, `RETRY_AFTER_CAP_SECONDS = 30.0`.
  - Private `MistMutationClient._send(method, path, *, action, object_type, json=None, params=None) -> httpx.Response` (Task 8 reuses it).
- Outcome rule every later task relies on: `outcome_unknown` is `True` only for a write (`POST`/`PUT`/`DELETE`) that Mist may have applied — a transport failure, a 5xx answer, or a 2xx answer whose JSON could not be read. A `GET`, a 4xx, and an exhausted 429 are always `False`.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && grep -n "except\|raise MistMutationError\|self._client\.\(get\|post\|put\|delete\)" src/mist_config_guardian_backend/integrations/mist_mutation.py`
Expected: four bare `self._client.<verb>` calls with no `try`, and `raise MistMutationError` only inside `_response_payload`. If transport errors are already converted, stop and report.

- [ ] **Step 2: Write the failing tests**

Append to `backend/tests/test_mist_mutation.py` (add `import httpx` to the imports and extend the existing `mist_mutation` import with `MistMutationStatusError, MistMutationTransportError`):

```python
NETWORKS_URL = "https://api.mist.com/api/v1/orgs/org-1/networks"
NETWORK_URL = f"{NETWORKS_URL}/network-1"


def _networks():
    return next(item for item in ORG_OBJECTS if item.key == "networks")


class _Sleeps:
    """Records every back-off instead of waiting."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def _client(sleeps: _Sleeps) -> MistMutationClient:
    return MistMutationClient(token="temporary-admin-token", region=MistCloudRegion.GLOBAL_01, sleep=sleeps)


async def test_a_throttled_update_is_retried_after_the_advertised_delay(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="PUT", url=NETWORK_URL, status_code=429, headers={"Retry-After": "7"})
    httpx_mock.add_response(method="PUT", url=NETWORK_URL, json={"id": "network-1"})
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        result = await client.update(_networks(), "network-1", {"name": "Corp"}, org_id="org-1", site_id=None)

    assert result == {"id": "network-1"}
    assert sleeps.delays == [7.0]


async def test_retry_after_is_capped(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="GET", url=NETWORK_URL, status_code=503, headers={"Retry-After": "600"})
    httpx_mock.add_response(method="GET", url=NETWORK_URL, json={"id": "network-1"})
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        await client.get_current(_networks(), "network-1", org_id="org-1", site_id=None)

    assert sleeps.delays == [30.0]


@pytest.mark.parametrize("status", [502, 503, 504])
async def test_a_delete_gives_up_after_three_attempts_with_an_unknown_outcome(
    httpx_mock: HTTPXMock, status: int
) -> None:
    for _ in range(3):
        httpx_mock.add_response(method="DELETE", url=NETWORK_URL, status_code=status)
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        with pytest.raises(MistMutationStatusError) as error:
            await client.delete(_networks(), "network-1", org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is True
    assert error.value.status_code == status
    assert len(httpx_mock.get_requests()) == 3
    assert sleeps.delays == [0.5, 1.0]


async def test_a_create_that_times_out_is_not_retried_and_may_have_happened(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_exception(httpx.ReadTimeout("slow"), method="POST", url=NETWORKS_URL)
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        with pytest.raises(MistMutationTransportError) as error:
            await client.create(_networks(), {"name": "Corp"}, org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is True
    assert len(httpx_mock.get_requests()) == 1
    assert sleeps.delays == []


async def test_a_create_answered_with_a_server_error_is_not_retried(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=NETWORKS_URL, status_code=503)

    async with _client(_Sleeps()) as client:
        with pytest.raises(MistMutationStatusError) as error:
            await client.create(_networks(), {"name": "Corp"}, org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is True
    assert len(httpx_mock.get_requests()) == 1


async def test_a_throttled_create_is_retried_because_mist_did_not_process_it(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=NETWORKS_URL, status_code=429)
    httpx_mock.add_response(method="POST", url=NETWORKS_URL, status_code=201, json={"id": "network-1", "name": "Corp"})
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        created = await client.create(_networks(), {"name": "Corp"}, org_id="org-1", site_id=None)

    assert created["id"] == "network-1"
    assert sleeps.delays == [0.5]


async def test_a_read_that_cannot_reach_mist_is_retried_and_changed_nothing(httpx_mock: HTTPXMock) -> None:
    for _ in range(3):
        httpx_mock.add_exception(httpx.ConnectError("refused"), method="GET", url=NETWORK_URL)

    async with _client(_Sleeps()) as client:
        with pytest.raises(MistMutationTransportError) as error:
            await client.get_current(_networks(), "network-1", org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is False
    assert len(httpx_mock.get_requests()) == 3


async def test_a_rejected_update_is_not_retried_and_was_not_applied(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="PUT", url=NETWORK_URL, status_code=400, text="sensitive upstream response")

    async with _client(_Sleeps()) as client:
        with pytest.raises(MistMutationStatusError) as error:
            await client.update(_networks(), "network-1", {"name": "Corp"}, org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is False
    assert "sensitive upstream response" not in str(error.value)
    assert len(httpx_mock.get_requests()) == 1
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_mist_mutation.py -v`
Expected: FAIL — `ImportError: cannot import name 'MistMutationStatusError'`.

- [ ] **Step 4: Implement the client**

Replace the body of `integrations/mist_mutation.py` from the imports through `_response_payload` with:

```python
"""Short-lived Mist configuration mutation client."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from http import HTTPStatus
from types import TracebackType
from typing import Literal, Self, cast

import httpx

from mist_config_guardian_backend.integrations.mist import REGION_HOSTS
from mist_config_guardian_backend.integrations.mist_session import SESSION_PREFIX, credential_headers, logout_session
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition

MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 0.5
RETRY_AFTER_CAP_SECONDS = 30.0

_RETRYABLE_STATUSES = frozenset(
    {
        HTTPStatus.TOO_MANY_REQUESTS,
        HTTPStatus.BAD_GATEWAY,
        HTTPStatus.SERVICE_UNAVAILABLE,
        HTTPStatus.GATEWAY_TIMEOUT,
    }
)
_SUCCESS_STATUSES = frozenset({HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED, HTTPStatus.NO_CONTENT})

Method = Literal["GET", "POST", "PUT", "DELETE"]


class MistMutationError(RuntimeError):
    """Raised when an authenticated Mist read or write fails.

    ``outcome_unknown`` is the one fact the executor cannot recover on its own:
    whether a write Mist never confirmed may nevertheless have been applied. It
    is true only for writes that failed in transport, were answered with a
    server error, or succeeded with an unreadable body.
    """

    def __init__(self, message: str, *, outcome_unknown: bool = False, status_code: int | None = None) -> None:
        super().__init__(message)
        self.outcome_unknown = outcome_unknown
        self.status_code = status_code


class MistMutationStatusError(MistMutationError):
    """Mist answered with a status the request did not succeed with."""


class MistMutationTransportError(MistMutationError):
    """The request never produced an answer this client could use."""


def _backoff(attempt: int) -> float:
    return BACKOFF_BASE_SECONDS * 2 ** (attempt - 1)


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    advertised = response.headers.get("Retry-After", "")
    if advertised.isdigit():
        return min(float(advertised), RETRY_AFTER_CAP_SECONDS)
    return _backoff(attempt)


class MistMutationClient(AbstractAsyncContextManager["MistMutationClient"]):
    """Use a freshly verified administrator token for bounded writes."""

    def __init__(
        self,
        *,
        token: str,
        region: MistCloudRegion,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._session = token.startswith(SESSION_PREFIX)
        self._sleep = sleep
        self._client = httpx.AsyncClient(
            base_url=REGION_HOSTS[region],
            headers=credential_headers(token),
            timeout=30,
        )

    # __aenter__, __aexit__, close_transport: unchanged.

    async def create(
        self,
        definition: ObjectDefinition,
        configuration: dict[str, object],
        *,
        org_id: str,
        site_id: str | None,
    ) -> dict[str, object]:
        """Create one configuration object."""
        response = await self._send(
            "POST",
            definition.path(org_id=org_id, site_id=site_id),
            action="create",
            object_type=definition.key,
            json=configuration,
        )
        payload = self._response_payload(response, "create", definition.key, write=True)
        if not isinstance(payload, dict):
            msg = f"Mist did not return the created {definition.key}"
            raise MistMutationError(msg, outcome_unknown=True)
        return cast("dict[str, object]", payload)

    async def get_current(
        self,
        definition: ObjectDefinition,
        object_id: str,
        *,
        org_id: str,
        site_id: str | None,
    ) -> dict[str, object] | None:
        """Read one live object; ``None`` when Mist says it does not exist."""
        response = await self._send(
            "GET",
            definition.item_path(object_id, org_id=org_id, site_id=site_id),
            action="read",
            object_type=definition.key,
        )
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None
        payload = self._response_payload(response, "read", definition.key, write=False)
        if not isinstance(payload, dict):
            msg = f"Mist did not return the current {definition.key}"
            raise MistMutationError(msg)
        return cast("dict[str, object]", payload)

    async def update(
        self,
        definition: ObjectDefinition,
        object_id: str,
        configuration: dict[str, object],
        *,
        org_id: str,
        site_id: str | None,
    ) -> dict[str, object] | None:
        """Replace one configuration object."""
        response = await self._send(
            "PUT",
            definition.item_path(object_id, org_id=org_id, site_id=site_id),
            action="update",
            object_type=definition.key,
            json=configuration,
        )
        payload = self._response_payload(response, "update", definition.key, write=True)
        return cast("dict[str, object]", payload) if isinstance(payload, dict) else None

    async def delete(
        self,
        definition: ObjectDefinition,
        object_id: str,
        *,
        org_id: str,
        site_id: str | None,
    ) -> None:
        """Delete one configuration object."""
        response = await self._send(
            "DELETE",
            definition.item_path(object_id, org_id=org_id, site_id=site_id),
            action="delete",
            object_type=definition.key,
        )
        self._response_payload(response, "delete", definition.key, write=True)

    async def _send(
        self,
        method: Method,
        path: str,
        *,
        action: str,
        object_type: str,
        json: dict[str, object] | None = None,
        params: Mapping[str, str | int] | None = None,
    ) -> httpx.Response:
        """Send one request, retrying only where a retry cannot apply a write twice.

        GET, PUT and DELETE are idempotent and are retried on throttling,
        gateway errors and transport failures. POST is retried only on 429,
        the one answer that proves Mist did not process it.
        """
        write = method != "GET"
        for attempt in range(1, MAX_ATTEMPTS + 1):
            last = attempt == MAX_ATTEMPTS
            try:
                response = await self._client.request(method, path, json=json, params=params)
            except httpx.TransportError as exc:
                if method == "POST" or last:
                    msg = f"Unable to reach Mist to {action} {object_type}"
                    raise MistMutationTransportError(msg, outcome_unknown=write) from exc
                await self._sleep(_backoff(attempt))
                continue
            except httpx.HTTPError as exc:
                msg = f"Mist returned an unusable answer to {action} {object_type}"
                raise MistMutationTransportError(msg, outcome_unknown=write) from exc
            retryable = response.status_code in _RETRYABLE_STATUSES and (
                method != "POST" or response.status_code == HTTPStatus.TOO_MANY_REQUESTS
            )
            if not retryable or last:
                return response
            await self._sleep(_retry_delay(response, attempt))
        msg = f"Unable to {action} {object_type} in Mist"
        raise MistMutationTransportError(msg, outcome_unknown=write)

    @staticmethod
    def _response_payload(
        response: httpx.Response,
        action: str,
        object_type: str,
        *,
        write: bool,
    ) -> object:
        if response.status_code not in _SUCCESS_STATUSES:
            msg = f"Mist failed to {action} {object_type} ({response.status_code})"
            raise MistMutationStatusError(
                msg,
                outcome_unknown=write and response.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR,
                status_code=response.status_code,
            )
        if response.status_code == HTTPStatus.NO_CONTENT or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            msg = f"Mist returned invalid JSON after {action} of {object_type}"
            raise MistMutationError(msg, outcome_unknown=write) from exc
```

Keep `__aenter__`, `__aexit__` and `close_transport` exactly as they are today.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_mist_mutation.py -v`
Expected: PASS (11 tests).

- [ ] **Step 6: Lint, type-check, run related tests**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src && uv run pytest tests/test_restore_compensation.py tests/test_restore_verification.py tests/test_restore_baseline.py -q`
Expected: clean; PASS. `MistMutationClient(token=..., region=...)` call sites in `services/restore_baseline.py:63` and `services/restore_executor.py:86` need no change.

- [ ] **Step 7: Commit**

```bash
git add backend/src/mist_config_guardian_backend/integrations/mist_mutation.py backend/tests/test_mist_mutation.py
git commit -m "fix(restore): classify Mist write failures and retry within bounds" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: The executor always reaches a terminal, notified, credential-free state

**Findings:** H1 (no catch-all, decrypt errors, version-number race, credential left behind), S2 (dead resume path).

**Files:**
- Create: `backend/src/mist_config_guardian_backend/services/restore_outcome.py`
- Modify: `backend/src/mist_config_guardian_backend/models/restore.py:51-69` (`RestoreAction`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_executor.py:1-204, 213-232, 342-445`
- Modify: `backend/src/mist_config_guardian_backend/schemas/restore.py:63-101` (`RestoreActionResponse`)
- Modify: `frontend/src/app/features/restore/restore.model.ts:20-36, 241-270`
- Modify: `frontend/src/app/features/restore/restore-step-plan.ts:46`
- Create: `frontend/src/app/features/restore/restore.model.spec.ts`
- Create: `backend/tests/test_restore_outcome.py`
- Create: `backend/tests/test_restore_executor_mongo.py`
- Test: `backend/tests/test_restore_verification.py:408-548` (execution section)
- Regenerate: `docs/openapi.json`

**Interfaces:**
- Consumes: `MistMutationError.outcome_unknown` (Task 1).
- Produces:
  - `RestoreAction.outcome_unknown: bool = False` — the action was being written when Mist stopped answering; it may have been applied. Such an action has `status == RestoreActionStatus.FAILED`. (Chosen over a new enum value: the frontend switches on `RestoreActionStatus` in `restore.model.ts:241-270`, and `failed` already renders the halted row.)
  - `restore_outcome.terminal_failure_status(actions: Sequence[RestoreAction]) -> RestoreStatus` — `COMPENSATION_AVAILABLE` if any action is `COMPLETED` or `outcome_unknown`, else `FAILED`.
  - `restore_outcome.mark_unconfirmed(actions: list[RestoreAction], reason: str) -> int | None` — every `EXECUTING` action becomes `FAILED` + `outcome_unknown=True` + `error=reason`; returns the first marked order.
  - `RestoreExecutor._insert_next_version(logical_id: PydanticObjectId, build: Callable[[ObjectVersion], ObjectVersion]) -> ObjectVersion` (static) — retries `DuplicateKeyError` up to `_RECORD_ATTEMPTS = 3`.
  - `RestoreExecutor._clear_delegated_credential(operation: RestoreOperation) -> None` (static).
  - `RestoreActionResponse.outcome_unknown: bool = False`; frontend `RestoreAction.outcome_unknown?: boolean`, `actionStatusTone(status, outcomeUnknown = false)`.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && sed -n 76,132p src/mist_config_guardian_backend/services/restore_executor.py && sed -n 183,186p src/mist_config_guardian_backend/services/restore_executor.py`
Expected: no `except Exception`/`finally` in `execute`, and the `if action.status is RestoreActionStatus.COMPLETED: ... continue` resume skip.

- [ ] **Step 2: Write the failing pure tests**

Create `backend/tests/test_restore_outcome.py`:

```python
"""Which terminal status a stopped restore gets, and what happens to writes in flight."""

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreStatus,
)
from mist_config_guardian_backend.services.restore_outcome import mark_unconfirmed, terminal_failure_status


def _action(order: int, status: RestoreActionStatus, *, outcome_unknown: bool = False) -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=order,
        action=RestoreActionType.UPDATE,
        scope="site",
        object_type="wlans",
        object_name=f"wlan-{order}",
        current_mist_id=f"mist-{order}",
        site_mist_id="site-a",
        protected_configuration={},
        status=status,
        outcome_unknown=outcome_unknown,
    )


def test_nothing_applied_is_a_plain_failure() -> None:
    actions = [_action(0, RestoreActionStatus.FAILED), _action(1, RestoreActionStatus.PENDING)]

    assert terminal_failure_status(actions) is RestoreStatus.FAILED


def test_an_applied_write_makes_the_restore_compensable() -> None:
    actions = [_action(0, RestoreActionStatus.COMPLETED), _action(1, RestoreActionStatus.FAILED)]

    assert terminal_failure_status(actions) is RestoreStatus.COMPENSATION_AVAILABLE


def test_an_unconfirmed_write_makes_the_restore_compensable() -> None:
    actions = [_action(0, RestoreActionStatus.FAILED, outcome_unknown=True)]

    assert terminal_failure_status(actions) is RestoreStatus.COMPENSATION_AVAILABLE


def test_writes_in_flight_are_marked_unconfirmed() -> None:
    actions = [
        _action(0, RestoreActionStatus.COMPLETED),
        _action(1, RestoreActionStatus.EXECUTING),
        _action(2, RestoreActionStatus.PENDING),
    ]

    first = mark_unconfirmed(actions, "Restore worker interrupted")

    assert first == 1
    assert actions[1].status is RestoreActionStatus.FAILED
    assert actions[1].outcome_unknown is True
    assert actions[1].error == "Restore worker interrupted"
    assert actions[0].outcome_unknown is False
    assert actions[2].status is RestoreActionStatus.PENDING


def test_nothing_in_flight_marks_nothing() -> None:
    assert mark_unconfirmed([_action(0, RestoreActionStatus.PENDING)], "reason") is None
```

- [ ] **Step 3: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_outcome.py -v`
Expected: FAIL — `ModuleNotFoundError: ... restore_outcome` (and `outcome_unknown` is not a field).

- [ ] **Step 4: Add the field and the outcome module**

In `models/restore.py`, add to `RestoreAction` after `error: str | None = None`:

```python
    # The write was in flight when Mist stopped answering, so it may have been
    # applied. Such an action is FAILED, and compensation treats it as possibly
    # applied rather than as never attempted.
    outcome_unknown: bool = False
```

Create `services/restore_outcome.py`:

```python
"""Terminal outcomes shared by the executor and the interrupted-restore janitor."""

from collections.abc import Sequence

from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionStatus, RestoreStatus


def terminal_failure_status(actions: Sequence[RestoreAction]) -> RestoreStatus:
    """Decide the status of a restore that stopped before finishing.

    Anything that reached Mist, or may have, has to stay reversible, so an
    applied or unconfirmed write keeps compensation available.
    """
    if any(action.status is RestoreActionStatus.COMPLETED or action.outcome_unknown for action in actions):
        return RestoreStatus.COMPENSATION_AVAILABLE
    return RestoreStatus.FAILED


def mark_unconfirmed(actions: list[RestoreAction], reason: str) -> int | None:
    """Close every write still in flight as possibly applied; return the first order marked."""
    first: int | None = None
    for action in actions:
        if action.status is not RestoreActionStatus.EXECUTING:
            continue
        action.status = RestoreActionStatus.FAILED
        action.outcome_unknown = True
        action.error = reason
        if first is None:
            first = action.order
    return first
```

Run: `cd backend && uv run pytest tests/test_restore_outcome.py -v` → PASS.

- [ ] **Step 5: Write the failing executor tests**

In `backend/tests/test_restore_verification.py`:

1. Add imports: `from beanie.odm.fields import ExpressionField` (already imported), `from mist_config_guardian_backend.integrations.mist_mutation import MistMutationStatusError, MistMutationTransportError`.
2. Delete `test_a_completed_action_is_not_applied_again_on_resume` (lines 535-548).
3. Extend the `executed` fixture (after the `_record_result` patch) so credential clearing is observable without a database:

```python
    monkeypatch.setattr(RestoreOperation, "id", ExpressionField("id"), raising=False)

    class _Cleared:
        async def update(self, change, *_args, **_kwargs) -> None:
            assert change == {"$set": {"encrypted_delegated_credential": None, "delegated_credential_expires_at": None}}

    monkeypatch.setattr(RestoreOperation, "find_one", lambda *_args, **_kwargs: _Cleared())
```

4. Add a raising client and let `_run` accept a client:

```python
class _FailingClient(_FakeClient):
    """Fails every update with a chosen Mist error."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    async def update(self, definition, object_id, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(("update", object_id))
        raise self.error
```

Change `_run`'s signature to `def _run(monkeypatch, operation, *, verified, store=None, client=None)` and its first line to `client = client or _FakeClient()`.

5. Add the tests:

```python
@pytest.mark.usefixtures("executed")
async def test_an_unconfirmed_write_leaves_the_restore_compensable(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    client = _FailingClient(MistMutationTransportError("Unable to reach Mist to update wlans", outcome_unknown=True))
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, client=client)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert result.actions[0].status is RestoreActionStatus.FAILED
    assert result.actions[0].outcome_unknown is True
    assert result.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1


@pytest.mark.usefixtures("executed")
async def test_a_rejected_first_write_fails_the_restore(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    client = _FailingClient(MistMutationStatusError("Mist failed to update wlans (400)", status_code=400))
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, client=client)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.FAILED
    assert result.actions[0].outcome_unknown is False
    assert result.encrypted_delegated_credential is None
    assert notifications.failed == ["wlan-0: Mist failed to update wlans (400)"]


@pytest.mark.usefixtures("executed")
async def test_an_unexpected_error_after_a_write_still_ends_the_restore(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _database_gone(*_args, **_kwargs) -> None:
        msg = "connection reset"
        raise RuntimeError(msg)

    monkeypatch.setattr(RestoreExecutor, "_record_result", _database_gone)
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-0")]
    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert result.actions[0].status is RestoreActionStatus.COMPLETED
    assert result.completed_at is not None
    assert result.encrypted_delegated_credential is None
    assert notifications.failed == ["Restore worker error (RuntimeError)"]
    assert "connection reset" not in " ".join(result.preflight_errors)


@pytest.mark.usefixtures("executed")
async def test_an_error_before_any_write_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _broken_snapshot(*_args, **_kwargs):
        msg = "store unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot",
        _broken_snapshot,
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert result.status is RestoreStatus.FAILED
    assert result.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1


@pytest.mark.usefixtures("executed")
async def test_a_credential_that_will_not_decrypt_fails_the_restore(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    operation.encrypted_delegated_credential = "broken"
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    with pytest.raises(RestoreExecutionError, match="could not be decrypted"):
        await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert operation.status is RestoreStatus.FAILED
    assert operation.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1
```

- [ ] **Step 6: Write the failing version-race test (DB-backed)**

Create `backend/tests/test_restore_executor_mongo.py`. Tasks 6 and 11 add tests to this module and reuse its helpers.

```python
"""Database-backed checks of what the executor records after a Mist write.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectIncarnation, ObjectVersion, VersionEvent
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import restore_executor
from mist_config_guardian_backend.services.restore_executor import RestoreExecutor
from mist_config_guardian_backend.snapshots.registry import get_definition

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_executor_records"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[LogicalObject, ObjectIncarnation, ObjectVersion])
    yield
    await client.drop_database(DATABASE)
    await client.close()


def _vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


async def _deleted_object(
    *,
    object_type: str = "networks",
    scope: str = "org",
    mist_id: str = "old-network",
    site_mist_id: str | None = None,
    configuration: dict[str, object] | None = None,
) -> LogicalObject:
    """Seed an object that was captured once and then deleted."""
    organization_id = PydanticObjectId()
    logical = LogicalObject(
        organization_id=organization_id,
        scope=scope,
        object_type=object_type,
        source_key=f"{site_mist_id or 'org'}:{object_type}:{mist_id}",
        current_mist_id=mist_id,
        site_mist_id=site_mist_id,
        name="Corp",
        is_deleted=True,
        current_version=2,
    )
    await logical.insert()
    incarnation = ObjectIncarnation(
        organization_id=organization_id,
        logical_object_id=logical.id,
        mist_object_id=mist_id,
        site_mist_id=site_mist_id,
        ordinal=1,
        ended_at=datetime.now(UTC),
    )
    await incarnation.insert()
    stored = configuration or {"id": mist_id, "name": "Corp"}
    for number, deleted in ((1, False), (2, True)):
        await ObjectVersion(
            organization_id=organization_id,
            logical_object_id=logical.id,
            incarnation_id=incarnation.id,
            version=number,
            event=VersionEvent.DELETED if deleted else VersionEvent.INITIAL,
            configuration=stored,
            configuration_hash=f"hash-{number}",
            is_deleted=deleted,
        ).insert()
    return logical


def _operation_for(
    logical: LogicalObject,
    *,
    action_type: RestoreActionType = RestoreActionType.CREATE,
    resulting_mist_id: str | None = "new-network",
) -> tuple[RestoreOperation, RestoreAction]:
    action = RestoreAction(
        logical_object_id=logical.id,
        source_version_id=PydanticObjectId(),
        order=0,
        action=action_type,
        scope=logical.scope,
        object_type=logical.object_type,
        object_name=logical.name,
        current_mist_id=logical.current_mist_id,
        site_mist_id=logical.site_mist_id,
        protected_configuration={"name": "Corp"},
        status=RestoreActionStatus.COMPLETED,
        resulting_mist_id=resulting_mist_id,
    )
    operation = RestoreOperation.model_construct(
        id=PydanticObjectId(),
        organization_id=logical.organization_id,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        include_dependencies=True,
        requested_version_ids=[],
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.RUNNING,
        actions=[action],
        warnings=[],
        preflight_errors=[],
        credential_actor="admin@example.com",
        started_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    return operation, action


async def test_a_version_number_taken_by_a_concurrent_tombstone_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    real_latest = restore_executor.latest_version
    raced = False

    async def _racing_latest(logical_id):
        nonlocal raced
        latest = await real_latest(logical_id)
        if not raced and latest is not None:
            raced = True
            await ObjectVersion(
                organization_id=latest.organization_id,
                logical_object_id=latest.logical_object_id,
                incarnation_id=latest.incarnation_id,
                version=latest.version + 1,
                event=VersionEvent.DELETED,
                configuration=latest.configuration,
                configuration_hash=latest.configuration_hash,
                is_deleted=True,
            ).insert()
        return latest

    monkeypatch.setattr(restore_executor, "latest_version", _racing_latest)
    definition = get_definition("org", "networks")
    assert definition is not None

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition.sensitive_fields, {"name": "Corp"}, site_id=None
    )

    versions = await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("version").to_list()
    assert [(version.version, version.event) for version in versions] == [
        (1, VersionEvent.INITIAL),
        (2, VersionEvent.DELETED),
        (3, VersionEvent.DELETED),
        (4, VersionEvent.RESTORED),
    ]
```

- [ ] **Step 7: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_verification.py -v -k "unconfirmed or rejected_first or unexpected or before_any_write or will_not_decrypt" && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_executor_mongo.py -v`
Expected: the unit tests FAIL (operation stays `RUNNING` / exception escapes); the DB test FAILS with `DuplicateKeyError` or `AttributeError: ... has no attribute 'latest_version'`.

- [ ] **Step 8: Implement the executor changes**

In `services/restore_executor.py`:

Imports — add `import logging`, `from collections.abc import Callable`, `from pymongo.errors import DuplicateKeyError`, `from mist_config_guardian_backend.security.credentials import CredentialDecryptionError, CredentialVault`, `from mist_config_guardian_backend.services.restore_outcome import mark_unconfirmed, terminal_failure_status`, and add `latest_version` to the `restore_planner` import. Add module constants:

```python
logger = logging.getLogger(__name__)
_RECORD_ATTEMPTS = 3
```

Replace `execute` (lines 76-132) with a guarded shell plus the old body renamed `_run`:

```python
    async def execute(self, operation_id: PydanticObjectId) -> RestoreOperation:
        """Execute pending actions once using the delegated Mist identity.

        Every exit leaves a terminal status, a failure notification when it did
        not complete, and no delegated credential: a worker that stops halfway
        must never leave an operation running with a live session attached.
        """
        operation, organization, token = await self._prepare(operation_id)
        try:
            return await self._run(operation, organization, token)
        except Exception as exc:  # noqa: BLE001 - every exit must end in a terminal, notified state
            await self._fail_unexpectedly(operation, exc)
            return operation
        finally:
            await self._clear_delegated_credential(operation)

    async def _run(self, operation: RestoreOperation, organization: Organization, token: str) -> RestoreOperation:
        """The execution itself; ``execute`` owns the guarantees around it."""
        state = await load_or_build_state(self._store, operation)
        compensating = state.compensates_operation_id is not None
        operation.status = RestoreStatus.RUNNING
        operation.started_at = utc_now()
        operation.touch()
        await operation.save()

        async with MistMutationClient(
            token=token,
            region=organization.cloud_region,
        ) as client:
            try:
                state.safety_snapshot = await capture_safety_snapshot(
                    client,
                    organization,
                    operation,
                    self._vault,
                    relaxed=compensating,
                )
            except MistMutationError as exc:
                await self._fail_preflight(operation, str(exc))
                await self._notify_failure(operation, str(exc))
                return operation
            await self._store.save(state)

            outcome = await self._run_actions(client, organization, operation)
            if not outcome.succeeded:
                await self._notify_failure(operation, _failure_reason(operation))
                return operation
            verification = await self._verifier.verify(
                client,
                organization,
                operation,
                id_map=outcome.id_map,
                applied=outcome.applied,
            )

        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.completed_at = utc_now()
        if not verification.verified:
            await self._fail_verification(operation, verification)
            return operation
        operation.status = RestoreStatus.COMPENSATED if compensating else RestoreStatus.COMPLETED
        operation.touch()
        await operation.save()
        if compensating and state.compensates_operation_id is not None:
            await self._mark_compensated(operation.organization_id, state.compensates_operation_id)
        await self._notifications.notify_restore_completed(
            organization_id=operation.organization_id,
            restore_id=str(operation.id),
            applied_count=sum(1 for action in operation.actions if action.status is RestoreActionStatus.COMPLETED),
        )
        return operation
```

(This is the former `execute` body, lines 79-132, unchanged.)

In `_prepare`, notify on the expired-credential path (before its `raise`) and guard decryption (replace lines 169-173):

```python
        try:
            token = self._vault.decrypt_for_context(
                operation.encrypted_delegated_credential,
                context=f"restore:{operation.id}",
            )
        except CredentialDecryptionError:
            reason = "The delegated Mist administrator credential could not be decrypted"
            await self._fail_preflight(operation, reason)
            await self._notify_failure(operation, reason)
            msg = "Delegated Mist administrator credential could not be decrypted"
            raise RestoreExecutionError(msg) from None
        return operation, organization, token
```

and in the expired branch (lines 147-159), after `await operation.save()` add `await self._notify_failure(operation, "Delegated Mist administrator credential expired before execution")`.

Replace `_run_actions` (lines 175-204) — the resume skip is removed:

```python
    async def _run_actions(
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
    ) -> _RunOutcome:
        outcome = _RunOutcome()
        for index, action in enumerate(operation.actions):
            try:
                outcome.applied[action.order] = await self._execute_action(
                    client,
                    organization,
                    operation,
                    index,
                    outcome.id_map,
                )
            except MistMutationError as exc:
                current = operation.actions[index]
                await self._fail_operation(
                    operation,
                    index,
                    str(exc),
                    action_failed=current.status is not RestoreActionStatus.COMPLETED,
                    outcome_unknown=exc.outcome_unknown and current.status is RestoreActionStatus.EXECUTING,
                )
                outcome.succeeded = False
                return outcome
        return outcome
```

Replace `_fail_operation` (lines 422-445):

```python
    @staticmethod
    async def _fail_operation(
        operation: RestoreOperation,
        action_index: int,
        message: str,
        *,
        action_failed: bool = True,
        outcome_unknown: bool = False,
    ) -> None:
        action = operation.actions[action_index]
        if action_failed:
            action.status = RestoreActionStatus.FAILED
            action.outcome_unknown = outcome_unknown
        action.error = message
        operation.actions[action_index] = action
        operation.failure_action_order = action.order
        operation.status = terminal_failure_status(operation.actions)
        operation.completed_at = utc_now()
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.touch()
        await operation.save()
```

In `_fail_verification` (lines 224-228) replace the conditional expression with `operation.status = terminal_failure_status(operation.actions)`.

Add:

```python
    async def _fail_unexpectedly(self, operation: RestoreOperation, exc: Exception) -> None:
        """Close a run that stopped on an error nothing else handled.

        Only the exception type is recorded: an arbitrary exception message can
        carry request or configuration content, which must never be stored or
        logged.
        """
        reason = str(exc) if isinstance(exc, MistMutationError) else f"Restore worker error ({type(exc).__name__})"
        logger.error("restore_execution_aborted operation=%s error_type=%s", operation.id, type(exc).__name__)
        first = mark_unconfirmed(operation.actions, reason)
        if first is not None:
            operation.failure_action_order = first
        operation.status = terminal_failure_status(operation.actions)
        operation.preflight_errors.append(reason)
        operation.completed_at = utc_now()
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.touch()
        try:
            await operation.save()
        except Exception as save_error:  # noqa: BLE001 - the janitor recovers an unsaved terminal state
            logger.error(
                "restore_terminal_state_unsaved operation=%s error_type=%s",
                operation.id,
                type(save_error).__name__,
            )
        try:
            await self._notify_failure(operation, reason)
        except Exception as notify_error:  # noqa: BLE001 - a lost notification must not mask the failure
            logger.error(
                "restore_failure_notification_lost operation=%s error_type=%s",
                operation.id,
                type(notify_error).__name__,
            )

    @staticmethod
    async def _clear_delegated_credential(operation: RestoreOperation) -> None:
        """Remove the delegated credential with a field-scoped write, whatever else failed."""
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        if operation.id is None:
            return
        try:
            await RestoreOperation.find_one(RestoreOperation.id == operation.id).update(
                {"$set": {"encrypted_delegated_credential": None, "delegated_credential_expires_at": None}}
            )
        except Exception as exc:  # noqa: BLE001 - the janitor and expiry job retry the clear
            logger.error("restore_credential_clear_failed operation=%s error_type=%s", operation.id, type(exc).__name__)

    @staticmethod
    async def _insert_next_version(
        logical_id: PydanticObjectId,
        build: Callable[[ObjectVersion], ObjectVersion],
    ) -> ObjectVersion:
        """Append a version after the newest one, re-reading if another writer took the number."""
        for attempt in range(1, _RECORD_ATTEMPTS + 1):
            latest = await latest_version(logical_id)
            if latest is None:
                msg = "Restore target has no source history"
                raise MistMutationError(msg)
            version = build(latest)
            try:
                await version.insert()
            except DuplicateKeyError:
                if attempt == _RECORD_ATTEMPTS:
                    raise
                continue
            return version
        msg = "Restore target history could not be extended"
        raise MistMutationError(msg)
```

Rewrite `_record_result` (lines 342-420) to use it:

```python
    async def _record_result(
        self,
        operation: RestoreOperation,
        action: RestoreAction,
        sensitive_fields: frozenset[str],
        configuration: dict[str, object],
        *,
        site_id: str | None,
    ) -> None:
        logical = await LogicalObject.get(action.logical_object_id)
        if logical is None or logical.id is None:
            msg = "Restore target logical object no longer exists"
            raise MistMutationError(msg)
        logical_id = logical.id
        deleted = action.action is RestoreActionType.DELETE
        resulting_id = action.resulting_mist_id or action.current_mist_id

        if action.action is RestoreActionType.CREATE:
            previous = (
                await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == logical_id)
                .sort("-ordinal")
                .first_or_none()
            )
            incarnation = ObjectIncarnation(
                organization_id=operation.organization_id,
                logical_object_id=logical_id,
                mist_object_id=resulting_id,
                site_mist_id=site_id,
                ordinal=1 if previous is None else previous.ordinal + 1,
            )
            await incarnation.insert()
        else:
            current = await latest_version(logical_id)
            incarnation = None if current is None else await ObjectIncarnation.get(current.incarnation_id)
        if incarnation is None or incarnation.id is None:
            msg = "Restore target incarnation is unavailable"
            raise MistMutationError(msg)
        incarnation_id = incarnation.id

        restored_configuration = dict(configuration)
        if not deleted:
            restored_configuration["id"] = resulting_id

        def build(latest: ObjectVersion) -> ObjectVersion:
            return ObjectVersion(
                organization_id=operation.organization_id,
                logical_object_id=logical_id,
                incarnation_id=incarnation_id,
                version=latest.version + 1,
                event=VersionEvent.RESTORED,
                configuration=(
                    latest.configuration
                    if deleted
                    else protect_configuration(restored_configuration, self._vault, sensitive_fields=sensitive_fields)
                ),
                configuration_hash=(
                    latest.configuration_hash if deleted else configuration_hash(restored_configuration)
                ),
                changed_fields=[],
                references=latest.references if deleted else extract_uuid_references(restored_configuration),
                is_deleted=deleted,
                actor=operation.credential_actor,
            )

        version = await self._insert_next_version(logical_id, build)
        logical.current_mist_id = resulting_id
        logical.site_mist_id = site_id
        logical.current_version = max(logical.current_version, version.version)
        logical.is_deleted = deleted
        logical.touch()
        await logical.save()
```

(The hash formula is deliberately unchanged here; Task 11 fixes it.)

- [ ] **Step 9: Expose the flag in the API and the frontend**

In `schemas/restore.py` `RestoreActionResponse`, add `outcome_unknown: bool = False` after `error: str | None`, and `outcome_unknown=action.outcome_unknown,` in `from_model`.

In `frontend/src/app/features/restore/restore.model.ts`: add `outcome_unknown?: boolean;` to `RestoreAction`; in `actionStatusLabel` change the `failed` case to `return action.outcome_unknown ? 'UNCONFIRMED' : 'FAILED';`; replace `actionStatusTone` with:

```ts
export function actionStatusTone(status: RestoreActionStatus, outcomeUnknown = false): Tone {
  switch (status) {
    case 'completed':
      return 'ok';
    case 'failed':
      return outcomeUnknown ? 'warn' : 'crit';
    case 'executing':
      return 'info';
    default:
      return 'none';
  }
}
```

In `restore-step-plan.ts:46` use `statusTone: actionStatusTone(action.status, action.outcome_unknown === true),`.

Create `frontend/src/app/features/restore/restore.model.spec.ts`:

```ts
import { actionStatusLabel, actionStatusTone, RestoreAction } from './restore.model';

function action(overrides: Partial<RestoreAction> = {}): RestoreAction {
  return {
    logical_object_id: 'lo-1',
    source_version_id: 'v-1',
    order: 0,
    action: 'update',
    scope: 'org',
    object_type: 'wlan',
    object_name: 'NW-Corp',
    current_mist_id: 'mist-1',
    site_mist_id: null,
    configuration: {},
    depends_on: [],
    status: 'pending',
    resulting_mist_id: null,
    error: null,
    ...overrides,
  };
}

describe('restore action status', () => {
  it('names a write Mist never confirmed as unconfirmed rather than failed', () => {
    const unconfirmed = action({ status: 'failed', outcome_unknown: true, error: 'Unable to reach Mist' });

    expect(actionStatusLabel(unconfirmed, 'compensation_available')).toBe('UNCONFIRMED');
    expect(actionStatusTone('failed', true)).toBe('warn');
  });

  it('still reports a rejected write as failed', () => {
    expect(actionStatusLabel(action({ status: 'failed' }), 'failed')).toBe('FAILED');
    expect(actionStatusTone('failed')).toBe('crit');
  });
});
```

- [ ] **Step 10: Run the tests**

Run: `cd backend && uv run pytest tests/test_restore_outcome.py tests/test_restore_verification.py tests/test_restore_compensation.py -v && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_executor_mongo.py -v`
Expected: PASS.

Run: `make openapi && cd backend && uv run python ../scripts/export-openapi.py --check`
Expected: `docs/openapi.json` gains `outcome_unknown`; check passes.

Run: `cd frontend && npm test -- --watch=false && npm run build`
Expected: PASS.

- [ ] **Step 11: Lint and type-check**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src`
Expected: clean.

- [ ] **Step 12: Commit**

```bash
git add backend/src/mist_config_guardian_backend/services/restore_outcome.py \
  backend/src/mist_config_guardian_backend/models/restore.py \
  backend/src/mist_config_guardian_backend/services/restore_executor.py \
  backend/src/mist_config_guardian_backend/schemas/restore.py \
  backend/tests/test_restore_outcome.py backend/tests/test_restore_executor_mongo.py \
  backend/tests/test_restore_verification.py docs/openapi.json \
  frontend/src/app/features/restore/restore.model.ts frontend/src/app/features/restore/restore-step-plan.ts \
  frontend/src/app/features/restore/restore.model.spec.ts
git commit -m "fix(restore): end every execution in a terminal, notified, credential-free state" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Compensation of unconfirmed writes

**Findings:** H1 (compensation must treat an unconfirmed write as possibly applied).

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/models/restore.py` (`RestoreAction`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_compensation.py:293-317` (`_validate_live_state`), `:331-410` (`create_compensation_plan`), `:502-542` (`_invert`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_executor.py` (`_run`, `_run_actions`, `_execute_action`)
- Test: `backend/tests/test_restore_compensation.py`, `backend/tests/test_restore_verification.py`

**Interfaces:**
- Consumes: `RestoreAction.outcome_unknown`, `terminal_failure_status` (Task 2).
- Produces:
  - `RestoreAction.compensates_action_order: int | None = None` — on a compensation action, the `order` of the original action it reverses (Task 10 uses it to avoid reversing twice).
  - Inverse actions copy `outcome_unknown` from the action they reverse.
  - Rules: an unconfirmed UPDATE → inverse UPDATE from the safety snapshot; an unconfirmed DELETE → inverse CREATE that is **skipped** at execution when the old UUID still exists; an unconfirmed CREATE → no action, a manual follow-up warning (Mist returned no id, so nothing can be targeted safely).
  - `RestoreExecutor._execute_action(...) -> dict[str, object] | None` — `None` when the action was skipped.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && sed -n 359,367p src/mist_config_guardian_backend/services/restore_compensation.py`
Expected: `applied` selects only `RestoreActionStatus.COMPLETED`, so an unconfirmed write is never reversed.

- [ ] **Step 2: Write the failing compensation tests**

Append to `backend/tests/test_restore_compensation.py` (compensation section):

```python
@pytest.mark.usefixtures("offline_documents")
async def test_an_unconfirmed_update_is_reversed_from_its_safety_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)
    operation.actions[3].status = RestoreActionStatus.FAILED
    operation.actions[3].outcome_unknown = True

    plan = await RestoreCompensationService(store).create_compensation_plan(
        operation=operation,
        requested_by=ADMINISTRATOR_ID,
    )

    assert [action.object_name for action in plan.actions] == ["wlan-3", "wlan-2", "wlan-1", "wlan-0"]
    assert plan.actions[0].action is RestoreActionType.UPDATE
    assert plan.actions[0].outcome_unknown is True
    assert plan.actions[0].compensates_action_order == 3
    assert plan.actions[0].protected_configuration["name"] == "Guest"
    assert [action.compensates_action_order for action in plan.actions] == [3, 2, 1, 0]


@pytest.mark.usefixtures("offline_documents")
async def test_an_unconfirmed_create_is_left_for_manual_follow_up(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)
    create = operation.actions[0]
    create.status = RestoreActionStatus.FAILED
    create.outcome_unknown = True
    create.resulting_mist_id = None

    plan = await RestoreCompensationService(store).create_compensation_plan(
        operation=operation,
        requested_by=ADMINISTRATOR_ID,
    )

    assert "wlan-0" not in [action.object_name for action in plan.actions]
    assert any(warning.startswith("wlan-0 may have been created in Mist") for warning in plan.warnings)


async def test_a_restore_whose_only_change_is_an_unconfirmed_create_cannot_be_reversed_automatically() -> None:
    create = _action(0, RestoreActionType.CREATE, status=RestoreActionStatus.FAILED)
    create.outcome_unknown = True
    operation = _operation([create])
    store = _MemoryStateStore()
    await store.save(
        _snapshot_state(
            [
                SafetySnapshotEntry(
                    logical_object_id=create.logical_object_id,
                    order=0,
                    action=RestoreActionType.CREATE,
                    scope="site",
                    object_type="wlans",
                    object_name="wlan-0",
                    mist_object_id="mist-0",
                    site_mist_id="site-a",
                    existed=False,
                )
            ]
        )
    )

    with pytest.raises(RestoreCompensationError, match="wlan-0 may have been created in Mist"):
        await RestoreCompensationService(store).create_compensation_plan(
            operation=operation,
            requested_by=ADMINISTRATOR_ID,
        )


def test_an_inverse_create_may_find_the_object_its_unconfirmed_delete_never_removed() -> None:
    recreate = _action(0, RestoreActionType.CREATE)
    recreate.outcome_unknown = True

    _validate_live_state(recreate, dict(GUEST_WLAN), relaxed=True)

    recreate.outcome_unknown = False
    with pytest.raises(MistMutationError, match="was recreated"):
        _validate_live_state(recreate, dict(GUEST_WLAN), relaxed=True)
```

- [ ] **Step 3: Write the failing executor test**

In `backend/tests/test_restore_verification.py`, add `SafetySnapshotEntry` to the `restore_planner` import and add:

```python
@pytest.mark.usefixtures("executed")
async def test_an_unconfirmed_delete_that_never_happened_is_not_recreated(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _mark(_organization_id, _operation_id) -> None:
        return

    monkeypatch.setattr(RestoreExecutor, "_mark_compensated", staticmethod(_mark))
    recreate = _action(0, RestoreActionType.CREATE)
    recreate.outcome_unknown = True
    entry = SafetySnapshotEntry(
        logical_object_id=recreate.logical_object_id,
        order=0,
        action=RestoreActionType.CREATE,
        scope="site",
        object_type="wlans",
        object_name="wlan-0",
        mist_object_id="mist-0",
        site_mist_id="site-a",
        existed=True,
    )

    async def _snapshot(*_args, **_kwargs):
        return [entry]

    monkeypatch.setattr("mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _snapshot)
    store = _MemoryStateStore()
    await store.save(
        RestoreOperationState(
            organization_id=ORGANIZATION_ID,
            operation_id=OPERATION_ID,
            plan_hash="plan-hash",
            compensates_operation_id=SOURCE_OPERATION_ID,
        )
    )
    operation = _operation([recreate])
    executor, _, _, client = _run(monkeypatch, operation, verified=True, store=store)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert result.actions[0].status is RestoreActionStatus.SKIPPED
```

- [ ] **Step 4: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_compensation.py tests/test_restore_verification.py -v -k "unconfirmed"`
Expected: FAIL — `compensates_action_order` missing / the unconfirmed actions are ignored / the CREATE is written.

- [ ] **Step 5: Implement**

`models/restore.py`, add to `RestoreAction` after `outcome_unknown`:

```python
    # On a compensation action: the order of the original action it reverses.
    compensates_action_order: int | None = None
```

`services/restore_compensation.py`, in `_validate_live_state` replace the CREATE branch:

```python
    if action.action is RestoreActionType.CREATE:
        # An inverse CREATE of a delete that may never have happened is allowed
        # to find the object; the executor then skips it.
        if current is not None and not action.outcome_unknown:
            msg = f"{action.object_name} was recreated after this plan was reviewed"
            raise MistMutationError(msg)
        return
```

In `create_compensation_plan`, replace lines 359-375 (from `snapshot = ...` through the inversion loop) with:

```python
        snapshot = {entry.order: entry for entry in state.safety_snapshot}
        reversible = sorted(
            (
                action
                for action in operation.actions
                if action.status is RestoreActionStatus.COMPLETED or action.outcome_unknown
            ),
            key=lambda action: action.order,
            reverse=True,
        )
        if not reversible:
            msg = "This restore applied no changes, so there is nothing to reverse"
            raise RestoreCompensationError(msg)

        follow_ups: list[str] = []
        actions: list[RestoreAction] = []
        for action in reversible:
            if action.outcome_unknown and action.action is RestoreActionType.CREATE:
                # Mist never returned an id, so there is nothing to target
                # without guessing; a person has to look.
                follow_ups.append(
                    f"{action.object_name} may have been created in Mist before the worker lost contact; "
                    "check for it and delete it manually if it exists"
                )
                continue
            entry = snapshot.get(action.order)
            if entry is None:
                msg = f"{action.object_name} has no safety snapshot entry, so it cannot be reversed"
                raise RestoreCompensationError(msg)
            actions.append(await self._invert(action, entry, len(actions)))
        if not actions:
            raise RestoreCompensationError("; ".join(follow_ups))
```

and change the `warnings=[...]` of the new `RestoreOperation` to:

```python
            warnings=[
                (
                    f"Compensating plan for restore {operation.id}: reverses "
                    f"{len(actions)} applied actions in reverse dependency order"
                ),
                *follow_ups,
            ],
```

In `_invert`, add to the returned `RestoreAction(...)`:

```python
            outcome_unknown=action.outcome_unknown,
            compensates_action_order=action.order,
```

`services/restore_executor.py`:
- In `_run`, call `self._run_actions(client, organization, operation, snapshot={entry.order: entry for entry in state.safety_snapshot})`.
- `_run_actions` gains `*, snapshot: dict[int, SafetySnapshotEntry]`, passes it to `_execute_action`, and records `applied` only for a non-`None` result:

```python
                payload = await self._execute_action(client, organization, operation, index, outcome.id_map, snapshot)
                if payload is not None:
                    outcome.applied[action.order] = payload
```

- `_execute_action` gains a `snapshot: dict[int, SafetySnapshotEntry]` parameter, returns `dict[str, object] | None`, and right after the two definition checks (before `action.status = RestoreActionStatus.EXECUTING`) adds:

```python
        entry = snapshot.get(action.order)
        if action.outcome_unknown and action.action is RestoreActionType.CREATE and entry is not None and entry.existed:
            # The delete this CREATE reverses never happened: the object is
            # still there, and writing it again would duplicate it.
            action.status = RestoreActionStatus.SKIPPED
            operation.actions[index] = action
            operation.touch()
            await operation.save()
            return None
```

Add `SafetySnapshotEntry` to the `restore_planner` import.

- [ ] **Step 6: Run the tests**

Run: `cd backend && uv run pytest tests/test_restore_compensation.py tests/test_restore_verification.py -v`
Expected: PASS.

- [ ] **Step 7: Lint, type-check, OpenAPI**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src && uv run python ../scripts/export-openapi.py --check`
Expected: clean (the response schema does not expose the new field, so the contract is unchanged).

- [ ] **Step 8: Commit**

```bash
git add backend/src/mist_config_guardian_backend/models/restore.py \
  backend/src/mist_config_guardian_backend/services/restore_compensation.py \
  backend/src/mist_config_guardian_backend/services/restore_executor.py \
  backend/tests/test_restore_compensation.py backend/tests/test_restore_verification.py
git commit -m "fix(restore): reverse writes Mist never confirmed" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Worker heartbeat and interrupted-restore janitor

**Findings:** H1 (no stale-`RUNNING` janitor; expiry job never clears a running operation's credential).

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/config.py:53` (after `delegated_credential_ttl_minutes`)
- Create: `backend/src/mist_config_guardian_backend/services/restore_recovery.py`
- Modify: `backend/src/mist_config_guardian_backend/services/restore_authorization.py:245, 271, 274` (rename `_logout_unused_credential` → `logout_unused_credential`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_executor.py` (`_run`, `_run_actions`, new `_heartbeat`)
- Modify: `backend/src/mist_config_guardian_backend/tasks/restores.py`
- Modify: `backend/src/mist_config_guardian_backend/worker.py:34-37` (beat schedule)
- Create: `backend/tests/test_restore_recovery.py`, `backend/tests/test_restore_recovery_mongo.py`
- Test: `backend/tests/test_restore_verification.py`

**Interfaces:**
- Consumes: `terminal_failure_status`, `mark_unconfirmed` (Task 2).
- Produces:
  - `Settings.restore_worker_heartbeat_timeout_minutes: int = 15`.
  - `RestoreExecutor._heartbeat(self, operation: RestoreOperation) -> None` — touches and saves; called after the safety snapshot, before every action, and before verification. Task 9 extends it to renew the lease.
  - `restore_recovery.INTERRUPTED_REASON: str`.
  - `class RestoreRecoveryService` with `__init__(self, settings: Settings, vault: CredentialVault, *, notifications: NotificationService | None = None, authorization: RestoreAuthorizationService | None = None)` and `async def recover_interrupted(self, *, now: datetime | None = None) -> int`; private `_interrupt(operation, now) -> bool` (Task 9 adds lease release there).
  - `RestoreAuthorizationService.logout_unused_credential(self, operation: dict[str, Any]) -> None` (renamed, now public).
  - Celery task `restores.recover_interrupted` scheduled every 60 s as `recover-interrupted-restores`.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && grep -n "RUNNING" src/mist_config_guardian_backend/services/restore_authorization.py src/mist_config_guardian_backend/tasks/restores.py`
Expected: no match — nothing ever moves a `RUNNING` operation on.

- [ ] **Step 2: Write the failing schedule and heartbeat tests**

Create `backend/tests/test_restore_recovery.py`:

```python
"""The janitor is scheduled, and its timeout outlasts any single Mist call."""

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist_mutation import MAX_ATTEMPTS, RETRY_AFTER_CAP_SECONDS
from mist_config_guardian_backend.tasks import restores as restore_tasks
from mist_config_guardian_backend.worker import celery_app

_REQUEST_TIMEOUT_SECONDS = 30


def test_interrupted_restores_are_recovered_every_minute() -> None:
    assert celery_app.conf.beat_schedule["recover-interrupted-restores"] == {
        "task": "restores.recover_interrupted",
        "schedule": 60.0,
    }
    assert restore_tasks.recover_interrupted_restores.name == "restores.recover_interrupted"


def test_the_heartbeat_timeout_outlasts_the_slowest_mist_call() -> None:
    slowest = MAX_ATTEMPTS * _REQUEST_TIMEOUT_SECONDS + (MAX_ATTEMPTS - 1) * RETRY_AFTER_CAP_SECONDS

    assert Settings(environment="test").restore_worker_heartbeat_timeout_minutes * 60 > slowest
```

Append to `backend/tests/test_restore_verification.py`:

```python
@pytest.mark.usefixtures("executed")
async def test_the_worker_heartbeats_around_every_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    async def _beat(self, operation) -> None:  # noqa: ARG001
        events.append("beat")

    async def _snapshot(*_args, **_kwargs):
        events.append("capture")
        return []

    monkeypatch.setattr(RestoreExecutor, "_heartbeat", _beat)
    monkeypatch.setattr("mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _snapshot)
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, verifier, client = _run(monkeypatch, operation, verified=True)
    original_update = client.update
    original_verify = verifier.verify

    async def _update(*args, **kwargs):
        events.append("write")
        return await original_update(*args, **kwargs)

    async def _verify(*args, **kwargs):
        events.append("verify")
        return await original_verify(*args, **kwargs)

    client.update = _update
    verifier.verify = _verify

    await executor.execute(OPERATION_ID)

    assert events == ["capture", "beat", "beat", "write", "beat", "verify"]
```

- [ ] **Step 3: Write the failing DB-backed janitor tests**

Create `backend/tests/test_restore_recovery_mongo.py`:

```python
"""The janitor closes restores whose worker stopped, and only those.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_recovery import INTERRUPTED_REASON, RestoreRecoveryService

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_recovery"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[RestoreOperation])
    yield
    await client.drop_database(DATABASE)
    await client.close()


class _Notifications:
    def __init__(self) -> None:
        self.failed: list[str] = []

    async def notify_restore_failed(self, *, organization_id, restore_id, reason, user_id=None):  # noqa: ARG002
        self.failed.append(reason)


def _settings() -> Settings:
    return Settings(environment="test", credential_encryption_key="test-key")


def _action(order: int, status: RestoreActionStatus) -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=order,
        action=RestoreActionType.UPDATE,
        scope="site",
        object_type="wlans",
        object_name=f"wlan-{order}",
        current_mist_id=f"mist-{order}",
        site_mist_id="site-a",
        protected_configuration={},
        status=status,
    )


async def _running(*, minutes_ago: int, actions: list[RestoreAction]) -> RestoreOperation:
    identifier = PydanticObjectId()
    stamp = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    operation = RestoreOperation(
        id=identifier,
        organization_id=PydanticObjectId(),
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.RUNNING,
        actions=actions,
        encrypted_delegated_credential=CredentialVault(_settings()).encrypt_for_context(
            "api-token", context=f"restore:{identifier}"
        ),
        delegated_credential_expires_at=stamp + timedelta(minutes=15),
        started_at=stamp,
        created_at=stamp,
        updated_at=stamp,
    )
    await operation.insert()
    return operation


def _service(notifications: _Notifications) -> RestoreRecoveryService:
    settings = _settings()
    return RestoreRecoveryService(settings, CredentialVault(settings), notifications=notifications)


async def test_a_stale_run_with_a_write_in_flight_becomes_compensable() -> None:
    await RestoreOperation.get_pymongo_collection().delete_many({})
    stale = await _running(
        minutes_ago=20,
        actions=[
            _action(0, RestoreActionStatus.COMPLETED),
            _action(1, RestoreActionStatus.EXECUTING),
            _action(2, RestoreActionStatus.PENDING),
        ],
    )
    fresh = await _running(minutes_ago=1, actions=[_action(0, RestoreActionStatus.EXECUTING)])
    notifications = _Notifications()

    assert await _service(notifications).recover_interrupted() == 1

    closed = await RestoreOperation.get(stale.id)
    assert closed is not None
    assert closed.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert closed.actions[1].status is RestoreActionStatus.FAILED
    assert closed.actions[1].outcome_unknown is True
    assert closed.failure_action_order == 1
    assert closed.encrypted_delegated_credential is None
    assert closed.delegated_credential_expires_at is None
    assert closed.completed_at is not None
    assert INTERRUPTED_REASON in closed.preflight_errors
    untouched = await RestoreOperation.get(fresh.id)
    assert untouched is not None
    assert untouched.status is RestoreStatus.RUNNING
    assert untouched.encrypted_delegated_credential is not None
    assert notifications.failed == [INTERRUPTED_REASON]


async def test_a_stale_run_that_never_wrote_fails() -> None:
    await RestoreOperation.get_pymongo_collection().delete_many({})
    stale = await _running(minutes_ago=30, actions=[_action(0, RestoreActionStatus.PENDING)])

    assert await _service(_Notifications()).recover_interrupted() == 1

    closed = await RestoreOperation.get(stale.id)
    assert closed is not None
    assert closed.status is RestoreStatus.FAILED


async def test_a_run_that_heartbeats_before_the_janitor_writes_is_left_alone() -> None:
    await RestoreOperation.get_pymongo_collection().delete_many({})
    stale = await _running(minutes_ago=30, actions=[_action(0, RestoreActionStatus.EXECUTING)])
    observed = await RestoreOperation.get(stale.id)
    assert observed is not None
    await RestoreOperation.get_pymongo_collection().update_one(
        {"_id": stale.id}, {"$set": {"updated_at": datetime.now(UTC)}}
    )
    notifications = _Notifications()

    assert await _service(notifications)._interrupt(observed, datetime.now(UTC)) is False  # noqa: SLF001

    alive = await RestoreOperation.get(stale.id)
    assert alive is not None
    assert alive.status is RestoreStatus.RUNNING
    assert notifications.failed == []
```

- [ ] **Step 4: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_recovery.py tests/test_restore_verification.py -v -k "recovered or heartbeat" && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_recovery_mongo.py -v`
Expected: FAIL — `KeyError: 'recover-interrupted-restores'`, missing `restore_worker_heartbeat_timeout_minutes`, missing `_heartbeat`, `ModuleNotFoundError: ... restore_recovery`.

- [ ] **Step 5: Implement**

`config.py`, after `delegated_credential_ttl_minutes: int = 15`:

```python
    # A running restore that has not written progress for this long is treated
    # as interrupted. It must outlast the slowest single Mist call the mutation
    # client can make (three 30 s attempts plus capped back-offs).
    restore_worker_heartbeat_timeout_minutes: int = 15
```

`services/restore_authorization.py`: rename `_logout_unused_credential` to `logout_unused_credential` at its definition (line 274) and both call sites (lines 245, 271). Keep its docstring.

`services/restore_executor.py`:

```python
    async def _heartbeat(self, operation: RestoreOperation) -> None:
        """Record that this worker is still alive, so the janitor leaves it alone."""
        operation.touch()
        await operation.save()
```

In `_run`: after `await self._store.save(state)` (post safety snapshot) add `await self._heartbeat(operation)`; immediately before `verification = await self._verifier.verify(` add `await self._heartbeat(operation)`. In `_run_actions`, make the first statement inside the `for` loop (before the `try`) `await self._heartbeat(operation)`.

Create `services/restore_recovery.py`:

```python
"""Close restores whose worker stopped before reaching a terminal state.

Celery runs ``restores.execute`` without redelivery, so a worker lost mid-run
leaves its operation ``RUNNING`` with a live delegated credential attached. The
executor writes progress at least once per action; an operation silent for
longer than the heartbeat timeout has no worker left.
"""

import logging
from datetime import datetime, timedelta

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist import MistVerificationService
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreStatus
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.notifications import NotificationService
from mist_config_guardian_backend.services.restore_authorization import RestoreAuthorizationService
from mist_config_guardian_backend.services.restore_outcome import mark_unconfirmed, terminal_failure_status

logger = logging.getLogger(__name__)

INTERRUPTED_REASON = "Restore worker interrupted before the run finished; writes in progress are unconfirmed"


class RestoreRecoveryService:
    """Move silent running restores to the same terminal state a crash inside the executor gets."""

    def __init__(
        self,
        settings: Settings,
        vault: CredentialVault,
        *,
        notifications: NotificationService | None = None,
        authorization: RestoreAuthorizationService | None = None,
    ) -> None:
        self._settings = settings
        self._notifications = notifications or NotificationService()
        self._authorization = authorization or RestoreAuthorizationService(settings, vault, MistVerificationService())

    async def recover_interrupted(self, *, now: datetime | None = None) -> int:
        """Close every running restore whose last progress write is older than the timeout."""
        instant = now or utc_now()
        cutoff = instant - timedelta(minutes=self._settings.restore_worker_heartbeat_timeout_minutes)
        stale = await RestoreOperation.find(
            RestoreOperation.status == RestoreStatus.RUNNING,
            {"updated_at": {"$lte": cutoff}},
        ).to_list()
        recovered = 0
        for operation in stale:
            if await self._interrupt(operation, instant):
                recovered += 1
        return recovered

    async def _interrupt(self, operation: RestoreOperation, now: datetime) -> bool:
        """Close one operation unless its worker wrote progress after it was read."""
        if operation.id is None:
            return False
        encrypted = operation.encrypted_delegated_credential
        observed = operation.updated_at
        first = mark_unconfirmed(operation.actions, INTERRUPTED_REASON)
        status = terminal_failure_status(operation.actions)
        changes: dict[str, object] = {
            "status": status,
            "actions": [action.model_dump() for action in operation.actions],
            "encrypted_delegated_credential": None,
            "delegated_credential_expires_at": None,
            "completed_at": now,
            "updated_at": now,
        }
        if first is not None:
            changes["failure_action_order"] = first
        result = await RestoreOperation.find_one(
            RestoreOperation.id == operation.id,
            RestoreOperation.status == RestoreStatus.RUNNING,
            RestoreOperation.updated_at == observed,
        ).update({"$set": changes, "$push": {"preflight_errors": INTERRUPTED_REASON}})
        if result is None or result.modified_count != 1:
            return False
        logger.warning("restore_interrupted operation=%s status=%s", operation.id, status)
        await self._authorization.logout_unused_credential(
            {
                "_id": operation.id,
                "organization_id": operation.organization_id,
                "encrypted_delegated_credential": encrypted,
            }
        )
        await self._notifications.notify_restore_failed(
            organization_id=operation.organization_id,
            restore_id=str(operation.id),
            reason=INTERRUPTED_REASON,
        )
        return True
```

Verify while implementing: the DB test reloads `actions[1].outcome_unknown is True`; if Beanie's update encoder rejects the dumped dicts, keep `model_dump()` (it yields `ObjectId`-compatible `PydanticObjectId` values and `StrEnum` members, both BSON-encodable).

`tasks/restores.py`, add the import `from mist_config_guardian_backend.services.restore_recovery import RestoreRecoveryService` and:

```python
@celery_app.task(name="restores.recover_interrupted")
def recover_interrupted_restores() -> int:
    """Close running restores whose worker stopped heartbeating."""
    return asyncio.run(_recover_interrupted_restores())


async def _recover_interrupted_restores() -> int:
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        return await RestoreRecoveryService(settings, CredentialVault(settings)).recover_interrupted()
    finally:
        await database.close()
```

`worker.py`, add to `beat_schedule` after `expire-restore-credentials`:

```python
        # A worker lost mid-restore leaves its operation running with a live
        # delegated credential; this closes it like an executor crash would.
        "recover-interrupted-restores": {
            "task": "restores.recover_interrupted",
            "schedule": 60.0,
        },
```

- [ ] **Step 6: Run the tests**

Run: `cd backend && uv run pytest tests/test_restore_recovery.py tests/test_restore_verification.py tests/test_restore_credential_cleanup.py -v && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_recovery_mongo.py -v`
Expected: PASS.

- [ ] **Step 7: Lint and type-check**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add backend/src/mist_config_guardian_backend/config.py \
  backend/src/mist_config_guardian_backend/services/restore_recovery.py \
  backend/src/mist_config_guardian_backend/services/restore_authorization.py \
  backend/src/mist_config_guardian_backend/services/restore_executor.py \
  backend/src/mist_config_guardian_backend/tasks/restores.py backend/src/mist_config_guardian_backend/worker.py \
  backend/tests/test_restore_recovery.py backend/tests/test_restore_recovery_mongo.py \
  backend/tests/test_restore_verification.py
git commit -m "fix(restore): recover restores whose worker stopped heartbeating" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Per-write live guard, read-back, and deferred reads under a recreated site

**Findings:** H5 second half (re-read immediately before each write, spec §9.4.6, §9.5.5), H3.

**Ordering note:** this is decision 3's per-write re-read, deliberately moved ahead of the rest of group 3. The H3 fix is a deferred read taken right before the write, after id remapping, so both are one mechanism. Task 9 (lease) and Task 10 (strict compensation drift) build on `check_before_write` and `RestoreAction.applied_hash` from this task.

**Files:**
- Create: `backend/src/mist_config_guardian_backend/services/restore_write_guard.py`
- Modify: `backend/src/mist_config_guardian_backend/services/restore_compensation.py:63-127` (new `RestoreDriftError`, `recreated_site_ids`, `build_snapshot_entry`; `capture_safety_snapshot` skips)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_executor.py` (`_RunContext`, `_run`, `_run_actions`, `_execute_action`, new `_read_back`)
- Modify: `backend/src/mist_config_guardian_backend/models/restore.py` (`RestoreAction.applied_hash`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_baseline.py:99-126` (`_capture`)
- Create: `backend/tests/test_restore_write_guard.py`
- Test: `backend/tests/test_restore_verification.py`, `backend/tests/test_restore_compensation.py`, `backend/tests/test_restore_baseline.py`

**Interfaces:**
- Consumes: `SafetySnapshotEntry` (`services/restore_planner.py:54-68`), `RestoreAction.outcome_unknown` (Task 2).
- Produces:
  - `restore_compensation.RestoreDriftError(MistMutationError)`.
  - `restore_compensation.recreated_site_ids(actions: Sequence[RestoreAction]) -> frozenset[str]` — `current_mist_id` of every `sites` CREATE in the plan.
  - `restore_compensation.build_snapshot_entry(action: RestoreAction, definition: ObjectDefinition, vault: CredentialVault, current: dict[str, object] | None, *, mist_object_id: str, site_mist_id: str | None) -> SafetySnapshotEntry` (async).
  - `restore_write_guard.WriteCheck` (frozen dataclass: `entry: SafetySnapshotEntry`, `recorded: bool`; Task 10 adds `skip: bool = False`).
  - `restore_write_guard.check_before_write(client, organization, vault, action, definition, *, object_id: str, site_id: str | None, entry: SafetySnapshotEntry | None, deferred: bool, compensating: bool) -> WriteCheck` (async).
  - `RestoreAction.applied_hash: str | None = None` — `configuration_hash(read-back, ignored_fields=definition.ignored_fields)` of the object right after the write; `None` for deletes and for actions not yet executed.
  - `RestoreExecutor._read_back(client, organization, action, definition, *, object_id: str, site_id: str | None) -> dict[str, object] | None` (static, async) — raises `MistMutationError` when a written object is missing or a deleted one still exists.
  - `RestoreExecutor._execute_action(client, organization, operation, index, id_map, context: _RunContext) -> dict[str, object] | None`, with `_RunContext(state, snapshot, recreated_sites, compensating)`.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && sed -n 83,98p src/mist_config_guardian_backend/services/restore_compensation.py && grep -n "get_current" src/mist_config_guardian_backend/services/restore_executor.py`
Expected: every action is read against `action.site_mist_id` (the old site) before any write, and the executor never reads before or after a write.

- [ ] **Step 2: Write the failing guard tests**

Create `backend/tests/test_restore_write_guard.py`:

```python
"""The live check taken immediately before each Mist write."""

from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization, OrganizationStatus
from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionType
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_compensation import RestoreDriftError
from mist_config_guardian_backend.services.restore_planner import SafetySnapshotEntry
from mist_config_guardian_backend.services.restore_write_guard import check_before_write
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.registry import get_definition

WLANS = get_definition("site", "wlans")
SETTINGS = get_definition("site", "settings")
assert WLANS is not None
assert SETTINGS is not None


class _Client:
    def __init__(self, live: dict[str, dict[str, object]]) -> None:
        self.live = live
        self.reads: list[tuple[str, str | None]] = []

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        self.reads.append((object_id, site_id))
        value = self.live.get(object_id)
        return None if value is None else dict(value)


def _vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


def _organization() -> Organization:
    return Organization.model_construct(
        id=PydanticObjectId(),
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="alue",
    )


def _action(
    action_type: RestoreActionType,
    *,
    object_type: str = "wlans",
    current_mist_id: str = "mist-0",
    site_mist_id: str = "site-a",
) -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=0,
        action=action_type,
        scope="site",
        object_type=object_type,
        object_name="Corp",
        current_mist_id=current_mist_id,
        site_mist_id=site_mist_id,
        protected_configuration={"name": "Corp"},
    )


def _entry(action: RestoreAction, live: dict[str, object]) -> SafetySnapshotEntry:
    return SafetySnapshotEntry(
        logical_object_id=action.logical_object_id,
        order=action.order,
        action=action.action,
        scope=action.scope,
        object_type=action.object_type,
        object_name=action.object_name,
        mist_object_id=action.current_mist_id,
        site_mist_id=action.site_mist_id,
        existed=True,
        configuration=dict(live),
        configuration_hash=configuration_hash(live, ignored_fields=WLANS.ignored_fields),
    )


async def _check(client: _Client, action: RestoreAction, **overrides):
    arguments = {
        "object_id": action.current_mist_id,
        "site_id": action.site_mist_id,
        "entry": None,
        "deferred": False,
        "compensating": False,
    } | overrides
    definition = SETTINGS if action.object_type == "settings" else WLANS
    return await check_before_write(client, _organization(), _vault(), action, definition, **arguments)


async def test_an_update_proceeds_while_live_state_still_matches_the_snapshot() -> None:
    snapshot = {"name": "Corp", "enabled": True, "modified_time": 1}
    action = _action(RestoreActionType.UPDATE)
    client = _Client({"mist-0": {**snapshot, "modified_time": 2}})

    check = await _check(client, action, entry=_entry(action, snapshot))

    assert check.recorded is False


async def test_an_update_is_refused_when_the_object_changed_after_the_snapshot() -> None:
    snapshot = {"name": "Corp", "enabled": True}
    action = _action(RestoreActionType.UPDATE)
    client = _Client({"mist-0": {"name": "Corp", "enabled": False}})

    with pytest.raises(RestoreDriftError, match="changed in Mist after the pre-restore safety snapshot"):
        await _check(client, action, entry=_entry(action, snapshot))


async def test_a_delete_of_an_object_that_is_already_gone_is_refused() -> None:
    action = _action(RestoreActionType.DELETE)

    with pytest.raises(RestoreDriftError, match="no longer exists"):
        await _check(_Client({}), action, entry=_entry(action, {"name": "Corp"}))


async def test_an_action_without_a_snapshot_entry_is_refused() -> None:
    with pytest.raises(RestoreDriftError, match="no pre-restore safety snapshot"):
        await _check(_Client({"mist-0": {"name": "Corp"}}), _action(RestoreActionType.UPDATE))


async def test_settings_under_a_recreated_site_are_read_at_the_new_site_and_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        AsyncMock(return_value=None),
    )
    action = _action(
        RestoreActionType.UPDATE,
        object_type="settings",
        current_mist_id="site-old:settings",
        site_mist_id="site-old",
    )
    client = _Client({"site-old:settings": {"vlan": 1}})

    check = await _check(client, action, site_id="site-new", deferred=True)

    assert client.reads == [("site-old:settings", "site-new")]
    assert check.recorded is True
    assert check.entry.existed is True
    assert check.entry.site_mist_id == "site-new"


async def test_a_create_under_a_recreated_site_records_absence_without_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        AsyncMock(return_value=None),
    )
    client = _Client({})

    check = await _check(client, _action(RestoreActionType.CREATE, site_mist_id="site-old"), site_id="site-new", deferred=True)

    assert client.reads == []
    assert check.recorded is True
    assert check.entry.existed is False
```

- [ ] **Step 3: Write the failing capture, baseline and executor tests**

Append to `backend/tests/test_restore_compensation.py` (safety snapshot section):

```python
async def test_capture_leaves_objects_under_a_site_this_plan_recreates_for_later(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    site = RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=0,
        action=RestoreActionType.CREATE,
        scope="org",
        object_type="sites",
        object_name="Lab",
        current_mist_id="site-old",
        protected_configuration={"name": "Lab"},
    )
    settings = RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=1,
        action=RestoreActionType.UPDATE,
        scope="site",
        object_type="settings",
        object_name="Lab settings",
        current_mist_id="site-old:settings",
        site_mist_id="site-old",
        protected_configuration={"vlan": 5},
    )
    client = _FakeMistClient({})

    entries = await capture_safety_snapshot(client, _organization(), _operation([site, settings]), _vault())

    assert client.reads == ["site-old"]
    assert [entry.order for entry in entries] == [0]
```

Append to `backend/tests/test_restore_baseline.py`:

```python
async def test_objects_under_a_deleted_site_are_not_read(capture):
    service, client, org, objects, manifest, versions, _vault = capture
    organization_id = next(iter(objects.values())).organization_id
    site_id, settings_id = PydanticObjectId(), PydanticObjectId()
    site = SimpleNamespace(
        scope="org", object_type="sites", current_mist_id="site-old", site_mist_id=None,
        is_deleted=True, organization_id=organization_id,
    )
    settings = SimpleNamespace(
        scope="site", object_type="settings", current_mist_id="site-old:settings", site_mist_id="site-old",
        is_deleted=True, organization_id=organization_id,
    )
    client.get_current.return_value = None

    baselines = await service._capture(client, org, {site_id: site, settings_id: settings}, manifest, "admin")

    assert [call.args[1] for call in client.get_current.await_args_list] == ["site-old"]
    assert set(baselines) == {site_id, settings_id}
    assert versions == []
```

In `backend/tests/test_restore_verification.py`:

1. Add imports: `from mist_config_guardian_backend.snapshots.canonical import configuration_hash`, `from mist_config_guardian_backend.snapshots.registry import get_definition`, and `SafetySnapshotEntry` (already imported in Task 3). Add `WLAN_DEFINITION = get_definition("site", "wlans")` below the id constants.
2. Replace `_FakeClient` with a stateful fake (existing callers pass the same `readback` mapping):

```python
class _FakeClient:
    """A Mist mutation client whose reads reflect its own writes."""

    def __init__(self, readback: dict[str, dict[str, object] | None] | None = None) -> None:
        self.state: dict[str, dict[str, object]] = {
            key: dict(value) for key, value in (readback or {}).items() if value is not None
        }
        self.writes: list[tuple[str, str]] = []
        self.reads: list[tuple[str, str | None]] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return

    async def create(self, definition, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(("create", str(configuration.get("name"))))
        created = {"id": "new-uuid", **configuration}
        self.state["new-uuid"] = created
        return dict(created)

    async def update(self, definition, object_id, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(("update", object_id))
        self.state[object_id] = {"id": object_id, **configuration}
        return dict(configuration)

    async def delete(self, definition, object_id, *, org_id, site_id) -> None:  # noqa: ARG002
        self.writes.append(("delete", object_id))
        self.state.pop(object_id, None)

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        self.reads.append((object_id, site_id))
        value = self.state.get(object_id)
        return None if value is None else dict(value)


def _snapshot_entries(client: _FakeClient, operation: RestoreOperation) -> list[SafetySnapshotEntry]:
    """What capture_safety_snapshot records against the fake's current state."""
    assert WLAN_DEFINITION is not None
    entries = []
    for action in operation.actions:
        live = client.state.get(action.current_mist_id)
        entries.append(
            SafetySnapshotEntry(
                logical_object_id=action.logical_object_id,
                order=action.order,
                action=action.action,
                scope=action.scope,
                object_type=action.object_type,
                object_name=action.object_name,
                mist_object_id=action.current_mist_id,
                site_mist_id=action.site_mist_id,
                existed=live is not None,
                configuration=dict(live or {}),
                configuration_hash=(
                    None if live is None else configuration_hash(live, ignored_fields=WLAN_DEFINITION.ignored_fields)
                ),
            )
        )
    return entries
```

3. In the `executed` fixture, replace the `_snapshot` stub with:

```python
    async def _snapshot(client, _organization, operation, *_args, **_kwargs):
        return _snapshot_entries(client, operation)
```

4. In `_run`, right after `client = client or _FakeClient()`, seed live state for every object the plan updates or deletes:

```python
    for action in operation.actions:
        if action.action is not RestoreActionType.CREATE:
            client.state.setdefault(action.current_mist_id, dict(action.protected_configuration))
```

5. In `test_the_worker_heartbeats_around_every_phase` (Task 4), change the `_snapshot` stub to `async def _snapshot(client, _organization, operation, *_args, **_kwargs):` returning `events.append("capture") or _snapshot_entries(client, operation)`.

6. Add:

```python
@pytest.mark.usefixtures("executed")
async def test_an_object_changed_after_the_safety_snapshot_is_not_overwritten(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.UPDATE)])
    executor, _, _, client = _run(monkeypatch, operation, verified=True)
    original_update = client.update

    async def _update_while_someone_edits(definition, object_id, configuration, *, org_id, site_id):
        result = await original_update(definition, object_id, configuration, org_id=org_id, site_id=site_id)
        client.state["mist-1"] = {"name": "wlan-1", "enabled": False}
        return result

    client.update = _update_while_someone_edits

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-0")]
    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert result.actions[1].status is RestoreActionStatus.FAILED
    assert "changed in Mist after the pre-restore safety snapshot" in (result.actions[1].error or "")


@pytest.mark.usefixtures("executed")
async def test_each_write_is_read_back_and_its_fingerprint_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    assert WLAN_DEFINITION is not None
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, _, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert result.actions[0].applied_hash == configuration_hash(
        client.state["mist-0"], ignored_fields=WLAN_DEFINITION.ignored_fields
    )


@pytest.mark.usefixtures("executed")
async def test_a_write_mist_does_not_show_afterwards_stops_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)
    original_update = client.update

    async def _update_then_vanish(definition, object_id, configuration, *, org_id, site_id):
        result = await original_update(definition, object_id, configuration, org_id=org_id, site_id=site_id)
        client.state.pop(object_id)
        return result

    client.update = _update_then_vanish

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-0")]
    assert result.actions[0].status is RestoreActionStatus.COMPLETED
    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert "was not found in Mist after the write" in notifications.failed[0]
```

- [ ] **Step 4: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_write_guard.py tests/test_restore_compensation.py tests/test_restore_baseline.py tests/test_restore_verification.py -v`
Expected: FAIL — `ModuleNotFoundError: ... restore_write_guard`, `ImportError: RestoreDriftError`, the capture reads `site-old:settings`, the baseline reads the settings, and the executor writes over the edited object.

- [ ] **Step 5: Implement the snapshot helpers**

In `services/restore_compensation.py`, below `RestoreCompensationError`:

```python
class RestoreDriftError(MistMutationError):
    """Live state no longer matches what the plan was validated against."""


def recreated_site_ids(actions: Sequence[RestoreAction]) -> frozenset[str]:
    """Site ids that do not exist in Mist until this plan creates them."""
    return frozenset(
        action.current_mist_id
        for action in actions
        if action.object_type == "sites" and action.action is RestoreActionType.CREATE
    )


async def build_snapshot_entry(
    action: RestoreAction,
    definition: ObjectDefinition,
    vault: CredentialVault,
    current: dict[str, object] | None,
    *,
    mist_object_id: str,
    site_mist_id: str | None,
) -> SafetySnapshotEntry:
    """Record what one object looked like immediately before this plan touched it."""
    stored = await latest_version(action.logical_object_id)
    return SafetySnapshotEntry(
        logical_object_id=action.logical_object_id,
        order=action.order,
        action=action.action,
        scope=action.scope,
        object_type=action.object_type,
        object_name=action.object_name,
        mist_object_id=mist_object_id,
        site_mist_id=site_mist_id,
        existed=current is not None,
        configuration=(
            {} if current is None else protect_configuration(current, vault, sensitive_fields=definition.sensitive_fields)
        ),
        configuration_hash=(
            None if current is None else configuration_hash(current, ignored_fields=definition.ignored_fields)
        ),
        pre_version_id=None if stored is None or stored.is_deleted else stored.id,
    )
```

(add `from mist_config_guardian_backend.snapshots.registry import ObjectDefinition, get_definition`), and rewrite the loop of `capture_safety_snapshot`:

```python
    entries: list[SafetySnapshotEntry] = []
    recreated = recreated_site_ids(operation.actions)
    for action in operation.actions:
        if action.site_mist_id is not None and action.site_mist_id in recreated:
            # Nothing exists under a site this plan has not created yet. The
            # executor reads these right before their writes, at the new site.
            continue
        definition = get_definition(action.scope, action.object_type)
        if definition is None:
            msg = f"Unsupported restore type: {action.scope}:{action.object_type}"
            raise MistMutationError(msg)
        current = await client.get_current(
            definition,
            action.current_mist_id,
            org_id=organization.mist_org_id,
            site_id=action.site_mist_id,
        )
        try:
            _validate_live_state(action, current, relaxed=relaxed)
        except MistMutationError:
            await _log_preflight_diagnostics(operation, action, current, vault)
            raise
        entries.append(
            await build_snapshot_entry(
                action,
                definition,
                vault,
                current,
                mist_object_id=action.current_mist_id,
                site_mist_id=action.site_mist_id,
            )
        )
    return entries
```

- [ ] **Step 6: Implement the guard**

Create `services/restore_write_guard.py`:

```python
"""Live-state checks immediately before each Mist write (spec §9.4.6).

The safety snapshot is taken before the first write; a plan with many actions
can run for minutes, and an object edited in between must not be overwritten.
Objects under a site the plan recreates cannot be read up front at all, so
their snapshot entry is recorded here, at the new site, right before the write.
"""

from dataclasses import dataclass

from mist_config_guardian_backend.integrations.mist_mutation import MistMutationClient
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionType
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_compensation import RestoreDriftError, build_snapshot_entry
from mist_config_guardian_backend.services.restore_planner import SafetySnapshotEntry
from mist_config_guardian_backend.snapshots.canonical import configuration_hash_matches
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition


@dataclass(frozen=True)
class WriteCheck:
    """The pre-write state one action is about to replace."""

    entry: SafetySnapshotEntry
    recorded: bool


async def check_before_write(  # noqa: PLR0913 - every argument is a distinct fact about the write
    client: MistMutationClient,
    organization: Organization,
    vault: CredentialVault,
    action: RestoreAction,
    definition: ObjectDefinition,
    *,
    object_id: str,
    site_id: str | None,
    entry: SafetySnapshotEntry | None,
    deferred: bool,
    compensating: bool,
) -> WriteCheck:
    """Refuse a write whose target drifted since the safety snapshot, or record a deferred entry."""
    if entry is None and not deferred:
        msg = f"{action.object_name} has no pre-restore safety snapshot entry"
        raise RestoreDriftError(msg)
    if action.action is RestoreActionType.CREATE:
        if entry is not None:
            return WriteCheck(entry=entry, recorded=False)
        # Under a site created moments ago nothing can exist yet.
        absent = await build_snapshot_entry(action, definition, vault, None, mist_object_id=object_id, site_mist_id=site_id)
        return WriteCheck(entry=absent, recorded=True)
    live = await client.get_current(definition, object_id, org_id=organization.mist_org_id, site_id=site_id)
    if live is None:
        msg = f"{action.object_name} no longer exists in Mist"
        raise RestoreDriftError(msg)
    if entry is None:
        observed = await build_snapshot_entry(action, definition, vault, live, mist_object_id=object_id, site_mist_id=site_id)
        return WriteCheck(entry=observed, recorded=True)
    if not compensating and not configuration_hash_matches(
        entry.configuration_hash, live, ignored_fields=definition.ignored_fields
    ):
        msg = f"{action.object_name} changed in Mist after the pre-restore safety snapshot"
        raise RestoreDriftError(msg)
    return WriteCheck(entry=entry, recorded=False)
```

(`compensating` keeps today's relaxed compensation semantics — existence only; Task 10 replaces it.)

- [ ] **Step 7: Wire the guard and read-back into the executor**

`models/restore.py`, add to `RestoreAction`:

```python
    # Fingerprint of the object as Mist returned it right after this action's
    # write: what compensation must find before it undoes the write.
    applied_hash: str | None = None
```

`services/restore_executor.py` — imports: `from mist_config_guardian_backend.services.restore_compensation import capture_safety_snapshot, recreated_site_ids`, `from mist_config_guardian_backend.services.restore_write_guard import check_before_write`, add `RestoreOperationState` to the planner import. Add:

```python
@dataclass
class _RunContext:
    """Plan state one pass over the actions reads and extends."""

    state: RestoreOperationState
    snapshot: dict[int, SafetySnapshotEntry]
    recreated_sites: frozenset[str]
    compensating: bool
```

In `_run`, replace the `_run_actions` call with:

```python
            context = _RunContext(
                state=state,
                snapshot={entry.order: entry for entry in state.safety_snapshot},
                recreated_sites=recreated_site_ids(operation.actions),
                compensating=compensating,
            )
            outcome = await self._run_actions(client, organization, operation, context)
```

`_run_actions(self, client, organization, operation, context: _RunContext)` passes `context` to `_execute_action` (replacing Task 3's `snapshot`). Replace `_execute_action` entirely:

```python
    async def _execute_action(  # noqa: PLR0913 - the pass state travels with the action
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
        index: int,
        id_map: dict[str, str],
        context: _RunContext,
    ) -> dict[str, object] | None:
        action = operation.actions[index]
        definition = get_definition(action.scope, action.object_type)
        if definition is None:
            msg = f"Unsupported restore type: {action.scope}:{action.object_type}"
            raise MistMutationError(msg)
        if not definition.supports_restore_action(action.action):
            msg = f"Unsupported {action.action} for {action.scope}:{action.object_type}"
            raise MistMutationError(msg)

        site_id = rewrite_identifier(action.site_mist_id, id_map)
        object_id = rewrite_identifier(action.current_mist_id, id_map) or action.current_mist_id
        check = await check_before_write(
            client,
            organization,
            self._vault,
            action,
            definition,
            object_id=object_id,
            site_id=site_id,
            entry=context.snapshot.get(action.order),
            deferred=action.site_mist_id is not None and action.site_mist_id in context.recreated_sites,
            compensating=context.compensating,
        )
        if check.recorded:
            context.snapshot[action.order] = check.entry
            context.state.safety_snapshot.append(check.entry)
            await self._store.save(context.state)
        if action.outcome_unknown and action.action is RestoreActionType.CREATE and check.entry.existed:
            # The delete this CREATE reverses never happened: the object is
            # still there, and writing it again would duplicate it.
            action.status = RestoreActionStatus.SKIPPED
            operation.actions[index] = action
            operation.touch()
            await operation.save()
            return None

        action.status = RestoreActionStatus.EXECUTING
        operation.actions[index] = action
        operation.touch()
        await operation.save()

        configuration = reveal_configuration(action.protected_configuration, self._vault)
        payload = prepare_restore_payload(
            configuration,
            excluded_fields=definition.restore_excluded_fields,
            id_map=id_map,
        )

        result: dict[str, object] | None = None
        if action.action is RestoreActionType.CREATE:
            result = await client.create(definition, payload, org_id=organization.mist_org_id, site_id=site_id)
            resulting_id = result.get("id")
            if not isinstance(resulting_id, str) or not resulting_id:
                msg = f"Mist did not return an id for created {action.object_type}"
                raise MistMutationError(msg, outcome_unknown=True)
            action.resulting_mist_id = resulting_id
            id_map[action.current_mist_id] = resulting_id
        elif action.action is RestoreActionType.UPDATE:
            result = await client.update(definition, object_id, payload, org_id=organization.mist_org_id, site_id=site_id)
            action.resulting_mist_id = object_id
        else:
            await client.delete(definition, object_id, org_id=organization.mist_org_id, site_id=site_id)

        # The write has happened in Mist: persist that fact before any local
        # bookkeeping can fail, so compensation knows what was applied.
        action.status = RestoreActionStatus.COMPLETED
        operation.actions[index] = action
        operation.touch()
        await operation.save()

        readback = await self._read_back(client, organization, action, definition, object_id=object_id, site_id=site_id)
        action.applied_hash = (
            None if readback is None else configuration_hash(readback, ignored_fields=definition.ignored_fields)
        )
        operation.actions[index] = action
        operation.touch()
        await operation.save()

        await self._record_result(operation, action, definition.sensitive_fields, result or payload, site_id=site_id)
        return payload

    @staticmethod
    async def _read_back(
        client: MistMutationClient,
        organization: Organization,
        action: RestoreAction,
        definition: ObjectDefinition,
        *,
        object_id: str,
        site_id: str | None,
    ) -> dict[str, object] | None:
        """Read the written object back from Mist before trusting the write (spec §9.5.5)."""
        target = action.resulting_mist_id if action.action is RestoreActionType.CREATE and action.resulting_mist_id else object_id
        current = await client.get_current(definition, target, org_id=organization.mist_org_id, site_id=site_id)
        if action.action is RestoreActionType.DELETE:
            if current is not None:
                msg = f"{action.object_name} still exists in Mist after the delete"
                raise MistMutationError(msg)
            return None
        if current is None:
            msg = f"{action.object_name} was not found in Mist after the write"
            raise MistMutationError(msg)
        return current
```

Add `from mist_config_guardian_backend.snapshots.registry import ObjectDefinition, get_definition`.

- [ ] **Step 8: Skip unreadable objects in the fresh baseline**

In `services/restore_baseline.py` `_capture`, compute before the loop:

```python
        deleted_sites = {
            logical.current_mist_id
            for logical in objects.values()
            if logical.object_type == "sites" and logical.is_deleted
        }
```

and, inside the loop right after the `definition is None or previous is None` check:

```python
            if logical.site_mist_id is not None and logical.site_mist_id in deleted_sites:
                # Nothing under a deleted site can be read back; its recorded
                # history is the only baseline there is.
                baselines[logical_id] = previous
                manifest.unchanged_objects += 1
                continue
```

- [ ] **Step 9: Run the tests**

Run: `cd backend && uv run pytest tests/test_restore_write_guard.py tests/test_restore_compensation.py tests/test_restore_baseline.py tests/test_restore_verification.py tests/test_restore_recovery.py -v`
Expected: PASS.

- [ ] **Step 10: Lint, type-check, OpenAPI unchanged**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src && uv run python ../scripts/export-openapi.py --check`
Expected: clean.

- [ ] **Step 11: Commit**

```bash
git add backend/src/mist_config_guardian_backend/services/restore_write_guard.py \
  backend/src/mist_config_guardian_backend/services/restore_compensation.py \
  backend/src/mist_config_guardian_backend/services/restore_executor.py \
  backend/src/mist_config_guardian_backend/services/restore_baseline.py \
  backend/src/mist_config_guardian_backend/models/restore.py \
  backend/tests/test_restore_write_guard.py backend/tests/test_restore_compensation.py \
  backend/tests/test_restore_baseline.py backend/tests/test_restore_verification.py
git commit -m "fix(restore): re-read before and after each write, deferring reads under recreated sites" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: Restored identities keep the collector's source key

**Findings:** H4.

**Files:**
- Create: `backend/src/mist_config_guardian_backend/services/restore_identity.py`
- Modify: `backend/src/mist_config_guardian_backend/services/snapshots.py:219-237` (new static `SnapshotService.source_key`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_executor.py` (`_execute_action`, `_record_result`, new `_incarnation_for`)
- Modify: `backend/src/mist_config_guardian_backend/models/restore.py` (`RestoreAction.resulting_site_mist_id`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_compensation.py:502-542` (`_invert`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_verification.py:241-246, 308-314`
- Test: `backend/tests/test_restore_executor_mongo.py`, `backend/tests/test_restore_compensation.py`, `backend/tests/test_restore_verification.py`

**Interfaces:**
- Consumes: `RestoreExecutor._read_back`, `_insert_next_version` (Tasks 2, 5).
- Produces:
  - `SnapshotService.source_key(definition: ObjectDefinition, site_id: str | None, mist_object_id: str) -> str` (static) — the only place the key format lives.
  - `restore_identity.RestoreIdentityConflictError(MistMutationError)`.
  - `restore_identity.rekey_logical_object(logical: LogicalObject, *, source_key: str, restore_started_at: datetime | None, incarnation_id: PydanticObjectId) -> None` (async) — persists the new `source_key`; when a `LogicalObject` already holds that key and was created at or after `restore_started_at` (a webhook or backup captured the object this restore just created), folds its versions into the restored identity and deletes it; an older holder raises `RestoreIdentityConflictError`.
  - `RestoreExecutor._record_result(operation: RestoreOperation, action: RestoreAction, definition: ObjectDefinition, written: dict[str, object], *, readback: dict[str, object] | None, site_id: str | None) -> None` (new signature; Task 11 changes only its hashing).
  - `RestoreAction.resulting_site_mist_id: str | None = None` — set when the site id was remapped at execution; compensation and verification use it in preference to `site_mist_id`.
- Unique index check (done while planning): `logical_object_source_unique` on `(organization_id, scope, object_type, source_key)` in `models/snapshot.py:76-85` — the conflict the adoption path handles.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && sed -n 415,420p src/mist_config_guardian_backend/services/restore_executor.py && sed -n 219,226p src/mist_config_guardian_backend/services/snapshots.py`
Expected: `_record_result` never assigns `source_key`; the collector matches on `f"{context.site_id or 'org'}:{definition.key}:{mist_object_id}"`. (If Task 2 already rewrote the lines, look for `source_key` in `_record_result` — there must be none.)

- [ ] **Step 2: Write the failing DB-backed tests**

In `backend/tests/test_restore_executor_mongo.py`, add imports `from mist_config_guardian_backend.services.restore_identity import RestoreIdentityConflictError` and `from mist_config_guardian_backend.services.snapshots import CaptureContext, SnapshotService`. Update the call in `test_a_version_number_taken_by_a_concurrent_tombstone_is_retried` to the new signature:

```python
    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"name": "Corp"}, readback={"id": "new-network", "name": "Corp"}, site_id=None
    )
```

and add:

```python
async def test_a_recreated_object_keeps_the_identity_the_collector_looks_for() -> None:
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    definition = get_definition("org", "networks")
    assert definition is not None
    live = {"id": "new-network", "name": "Corp", "org_id": "org-1"}

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"name": "Corp"}, readback=live, site_id=None
    )
    await SnapshotService(_vault()).capture_configuration(
        logical.organization_id, definition, dict(live), CaptureContext(snapshot_id=None, site_id=None)
    )

    stored = await LogicalObject.get(logical.id)
    assert stored is not None
    assert stored.source_key == "org:networks:new-network"
    assert stored.current_mist_id == "new-network"
    assert stored.is_deleted is False
    assert await LogicalObject.find(LogicalObject.organization_id == logical.organization_id).count() == 1
    incarnations = await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == logical.id).sort("ordinal").to_list()
    assert [incarnation.mist_object_id for incarnation in incarnations] == ["old-network", "new-network"]


async def test_an_object_restored_under_a_recreated_site_moves_to_the_new_site() -> None:
    wlan = await _deleted_object(object_type="wlans", scope="site", mist_id="wlan-old", site_mist_id="site-old")
    operation, action = _operation_for(wlan, resulting_mist_id="wlan-new")
    definition = get_definition("site", "wlans")
    assert definition is not None

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation,
        action,
        definition,
        {"ssid": "Corp"},
        readback={"id": "wlan-new", "ssid": "Corp", "site_id": "site-new"},
        site_id="site-new",
    )

    stored = await LogicalObject.get(wlan.id)
    assert stored is not None
    assert stored.source_key == "site-new:wlans:wlan-new"
    assert stored.site_mist_id == "site-new"


async def test_site_settings_restored_under_a_recreated_site_are_rekeyed() -> None:
    settings = await _deleted_object(
        object_type="settings",
        scope="site",
        mist_id="site-old:settings",
        site_mist_id="site-old",
        configuration={"vlan": 5},
    )
    operation, action = _operation_for(
        settings, action_type=RestoreActionType.UPDATE, resulting_mist_id="site-old:settings"
    )
    definition = get_definition("site", "settings")
    assert definition is not None

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"vlan": 5}, readback={"vlan": 5, "site_id": "site-new"}, site_id="site-new"
    )

    stored = await LogicalObject.get(settings.id)
    assert stored is not None
    assert stored.source_key == "site-new:settings:site-new:settings"
    assert stored.current_mist_id == "site-new:settings"
    incarnations = await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == settings.id).sort("ordinal").to_list()
    assert [(item.ordinal, item.site_mist_id) for item in incarnations] == [(1, "site-old"), (2, "site-new")]


async def _captured_duplicate(logical: LogicalObject, *, created_at: datetime) -> LogicalObject:
    """What the webhook or a backup records for the new UUID before the executor re-keys."""
    duplicate = LogicalObject(
        organization_id=logical.organization_id,
        scope="org",
        object_type="networks",
        source_key="org:networks:new-network",
        current_mist_id="new-network",
        name="Corp",
        current_version=1,
        created_at=created_at,
    )
    await duplicate.insert()
    incarnation = ObjectIncarnation(
        organization_id=logical.organization_id,
        logical_object_id=duplicate.id,
        mist_object_id="new-network",
        ordinal=1,
    )
    await incarnation.insert()
    await ObjectVersion(
        organization_id=logical.organization_id,
        logical_object_id=duplicate.id,
        incarnation_id=incarnation.id,
        version=1,
        event=VersionEvent.CREATED,
        configuration={"id": "new-network", "name": "Corp"},
        configuration_hash="captured",
    ).insert()
    return duplicate


async def test_a_capture_that_raced_the_restore_is_folded_into_the_restored_identity() -> None:
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    duplicate = await _captured_duplicate(logical, created_at=datetime.now(UTC))
    definition = get_definition("org", "networks")
    assert definition is not None

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"name": "Corp"}, readback={"id": "new-network", "name": "Corp"}, site_id=None
    )

    assert await LogicalObject.get(duplicate.id) is None
    assert await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == duplicate.id).count() == 0
    versions = await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("version").to_list()
    assert [(version.version, version.event) for version in versions] == [
        (1, VersionEvent.INITIAL),
        (2, VersionEvent.DELETED),
        (3, VersionEvent.RESTORED),
        (4, VersionEvent.CREATED),
    ]
    assert versions[3].incarnation_id == versions[2].incarnation_id
    stored = await LogicalObject.get(logical.id)
    assert stored is not None
    assert stored.source_key == "org:networks:new-network"
    assert stored.current_version == 4


async def test_an_identity_older_than_the_restore_is_never_merged() -> None:
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    duplicate = await _captured_duplicate(logical, created_at=datetime.now(UTC) - timedelta(days=1))
    definition = get_definition("org", "networks")
    assert definition is not None

    with pytest.raises(RestoreIdentityConflictError, match="already owns"):
        await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
            operation, action, definition, {"name": "Corp"}, readback={"id": "new-network", "name": "Corp"}, site_id=None
        )

    assert await LogicalObject.get(duplicate.id) is not None
```

- [ ] **Step 3: Write the failing site-remap tests (no database)**

Append to `backend/tests/test_restore_compensation.py`:

```python
@pytest.mark.usefixtures("offline_documents")
async def test_a_child_created_under_a_recreated_site_is_reversed_at_the_new_site(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)
    operation.actions[0].resulting_site_mist_id = "site-new"

    plan = await RestoreCompensationService(store).create_compensation_plan(
        operation=operation,
        requested_by=ADMINISTRATOR_ID,
    )

    reverse_create = next(action for action in plan.actions if action.compensates_action_order == 0)
    assert reverse_create.site_mist_id == "site-new"
    assert next(action for action in plan.actions if action.compensates_action_order == 1).site_mist_id == "site-a"
```

Append to `backend/tests/test_restore_verification.py`:

```python
async def test_read_after_write_reads_where_the_object_now_lives() -> None:
    action = _action(0, RestoreActionType.CREATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="new-uuid")
    action.resulting_site_mist_id = "site-b"
    client = _FakeClient({"new-uuid": {"name": "wlan-0", "enabled": True}})

    await _build_verifier().verify(
        client, _organization(), _operation([action]), id_map={}, applied={0: {"name": "wlan-0", "enabled": True}}
    )

    assert client.reads == [("new-uuid", "site-b")]
```

- [ ] **Step 4: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_compensation.py tests/test_restore_verification.py -v -k "new_site or now_lives" && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_executor_mongo.py -v`
Expected: FAIL — `resulting_site_mist_id` is not a field, `_record_result` rejects the new arguments, `restore_identity` does not exist.

- [ ] **Step 5: Implement the key helper and identity module**

`services/snapshots.py`, add to `SnapshotService`:

```python
    @staticmethod
    def source_key(definition: ObjectDefinition, site_id: str | None, mist_object_id: str) -> str:
        """The identity key the collector matches objects by; a restore must record the same one."""
        return f"{site_id or 'org'}:{definition.key}:{mist_object_id}"
```

and in `capture_configuration` replace the f-string at line 220 with `source_key = self.source_key(definition, context.site_id, mist_object_id)`.

Create `services/restore_identity.py`:

```python
"""Keep a recreated object on the logical identity its history belongs to.

The collector finds a logical object by its source key, which embeds the Mist
id and the site id. Recreating an object gives it a new id (and a recreated
site gives its children a new site id), so the restore must move the key with
it, or the next capture starts a second identity for the same object.
"""

from datetime import datetime

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.integrations.mist_mutation import MistMutationError
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectIncarnation, ObjectVersion
from mist_config_guardian_backend.services.restore_planner import latest_version

_REKEY_ATTEMPTS = 2


class RestoreIdentityConflictError(MistMutationError):
    """Another recorded identity owns the key a restored object needs."""


async def rekey_logical_object(
    logical: LogicalObject,
    *,
    source_key: str,
    restore_started_at: datetime | None,
    incarnation_id: PydanticObjectId,
) -> None:
    """Move ``logical`` to ``source_key``, adopting a capture of the same object that raced the restore."""
    for attempt in range(1, _REKEY_ATTEMPTS + 1):
        holder = await LogicalObject.find_one(
            LogicalObject.organization_id == logical.organization_id,
            LogicalObject.scope == logical.scope,
            LogicalObject.object_type == logical.object_type,
            LogicalObject.source_key == source_key,
        )
        if holder is not None and holder.id != logical.id:
            if restore_started_at is None or holder.created_at < restore_started_at:
                msg = f"{logical.name}: another recorded identity already owns {source_key}; history needs manual review"
                raise RestoreIdentityConflictError(msg)
            await _adopt(logical, holder, incarnation_id)
        try:
            await LogicalObject.find_one(LogicalObject.id == logical.id).update({"$set": {"source_key": source_key}})
        except DuplicateKeyError as exc:
            if attempt == _REKEY_ATTEMPTS:
                msg = f"{logical.name}: another capture keeps claiming {source_key}; history needs manual review"
                raise RestoreIdentityConflictError(msg) from exc
            continue
        logical.source_key = source_key
        return


async def _adopt(restored: LogicalObject, duplicate: LogicalObject, incarnation_id: PydanticObjectId) -> None:
    """Fold a same-object capture into the restored identity, after its restored version."""
    if restored.id is None or duplicate.id is None:
        return
    latest = await latest_version(restored.id)
    number = 0 if latest is None else latest.version
    moved = await ObjectVersion.find(ObjectVersion.logical_object_id == duplicate.id).sort("version").to_list()
    for version in moved:
        number += 1
        await ObjectVersion.find_one(ObjectVersion.id == version.id).update(
            {"$set": {"logical_object_id": restored.id, "version": number, "incarnation_id": incarnation_id}}
        )
    await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == duplicate.id).delete()
    await duplicate.delete()
    restored.current_version = max(restored.current_version, number)
```

- [ ] **Step 6: Record results under the collector's identity**

`models/restore.py`, add to `RestoreAction`:

```python
    # The site id the action was executed under when it differs from
    # ``site_mist_id`` (the site was recreated by this restore).
    resulting_site_mist_id: str | None = None
```

`services/restore_executor.py` — import `ObjectDefinition`, `SnapshotService` (`from mist_config_guardian_backend.services.snapshots import SnapshotService`) and `rekey_logical_object`. In `_execute_action`, directly after computing `site_id`/`object_id`, add:

```python
        if site_id != action.site_mist_id:
            action.resulting_site_mist_id = site_id
```

and change the final bookkeeping call to:

```python
        await self._record_result(operation, action, definition, result or payload, readback=readback, site_id=site_id)
```

Replace `_record_result` (the Task 2 version) with:

```python
    async def _record_result(  # noqa: PLR0913 - the write, its read-back, and where it landed
        self,
        operation: RestoreOperation,
        action: RestoreAction,
        definition: ObjectDefinition,
        written: dict[str, object],
        *,
        readback: dict[str, object] | None,
        site_id: str | None,
    ) -> None:
        logical = await LogicalObject.get(action.logical_object_id)
        if logical is None or logical.id is None:
            msg = "Restore target logical object no longer exists"
            raise MistMutationError(msg)
        logical_id = logical.id
        deleted = action.action is RestoreActionType.DELETE
        object_id = action.resulting_mist_id or action.current_mist_id
        if readback is not None:
            # Exactly the id the collector will derive from the same response.
            object_id = SnapshotService.object_id(readback, definition, site_id)
        incarnation_id = await self._incarnation_for(operation, logical_id, action, object_id=object_id, site_id=site_id)

        restored_configuration = dict(written)
        if not deleted and definition.is_list:
            restored_configuration["id"] = object_id

        def build(latest: ObjectVersion) -> ObjectVersion:
            return ObjectVersion(
                organization_id=operation.organization_id,
                logical_object_id=logical_id,
                incarnation_id=incarnation_id,
                version=latest.version + 1,
                event=VersionEvent.RESTORED,
                configuration=(
                    latest.configuration
                    if deleted
                    else protect_configuration(
                        restored_configuration, self._vault, sensitive_fields=definition.sensitive_fields
                    )
                ),
                configuration_hash=(
                    latest.configuration_hash if deleted else configuration_hash(restored_configuration)
                ),
                changed_fields=[],
                references=latest.references if deleted else extract_uuid_references(restored_configuration),
                is_deleted=deleted,
                actor=operation.credential_actor,
            )

        version = await self._insert_next_version(logical_id, build)
        if not deleted:
            source_key = SnapshotService.source_key(definition, site_id, object_id)
            if source_key != logical.source_key:
                await rekey_logical_object(
                    logical,
                    source_key=source_key,
                    restore_started_at=operation.started_at,
                    incarnation_id=incarnation_id,
                )
        logical.current_mist_id = object_id
        logical.site_mist_id = site_id
        logical.current_version = max(logical.current_version, version.version)
        logical.is_deleted = deleted
        logical.touch()
        await logical.save()

    @staticmethod
    async def _incarnation_for(
        operation: RestoreOperation,
        logical_id: PydanticObjectId,
        action: RestoreAction,
        *,
        object_id: str,
        site_id: str | None,
    ) -> PydanticObjectId:
        """Reuse the current incarnation unless the object came back under a new id or site."""
        current = (
            await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == logical_id)
            .sort("-ordinal")
            .first_or_none()
        )
        unchanged = current is not None and current.mist_object_id == object_id and current.site_mist_id == site_id
        if current is not None and current.id is not None and (
            action.action is RestoreActionType.DELETE or (action.action is RestoreActionType.UPDATE and unchanged)
        ):
            return current.id
        incarnation = ObjectIncarnation(
            organization_id=operation.organization_id,
            logical_object_id=logical_id,
            mist_object_id=object_id,
            site_mist_id=site_id,
            ordinal=1 if current is None else current.ordinal + 1,
        )
        await incarnation.insert()
        if incarnation.id is None:
            msg = "Restore target incarnation is unavailable"
            raise MistMutationError(msg)
        return incarnation.id
```

Verify while implementing: `RestoreIdentityConflictError` subclasses `MistMutationError`, so `_run_actions` stops the run with the action already `COMPLETED` → `COMPENSATION_AVAILABLE`.

- [ ] **Step 7: Use the remapped site in compensation and verification**

`services/restore_compensation.py` `_invert`: in the returned `RestoreAction(...)`, replace `site_mist_id=action.site_mist_id,` with `site_mist_id=action.resulting_site_mist_id or action.site_mist_id,`.

`services/restore_verification.py`: in `_read_after_write` pass `site_id=action.resulting_site_mist_id or action.site_mist_id`; in `_affected_sites` yield `action.resulting_site_mist_id or action.site_mist_id` (keep the `if ... and <that value>` filter).

- [ ] **Step 8: Run the tests**

Run: `cd backend && uv run pytest tests/test_restore_compensation.py tests/test_restore_verification.py tests/test_snapshot_registry.py tests/test_webhook_ingestion.py -v && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_executor_mongo.py -v`
Expected: PASS.

- [ ] **Step 9: Lint and type-check**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src && uv run python ../scripts/export-openapi.py --check`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add backend/src/mist_config_guardian_backend/services/restore_identity.py \
  backend/src/mist_config_guardian_backend/services/snapshots.py \
  backend/src/mist_config_guardian_backend/services/restore_executor.py \
  backend/src/mist_config_guardian_backend/services/restore_compensation.py \
  backend/src/mist_config_guardian_backend/services/restore_verification.py \
  backend/src/mist_config_guardian_backend/models/restore.py \
  backend/tests/test_restore_executor_mongo.py backend/tests/test_restore_compensation.py \
  backend/tests/test_restore_verification.py
git commit -m "fix(restore): keep recreated objects on the identity the collector matches" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: Forced reference-rewrite actions for reverse dependents

**Findings:** H2.

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/models/restore.py` (`RestoreActionReason`, `RestoreAction.reason`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_planner.py:349-359` (`PlanningContext`), `:384-467` (`create_plan`), `:469-507` (`_expand_dependencies`), `:575-636` (`_build_actions`)
- Modify: `backend/src/mist_config_guardian_backend/schemas/restore.py` (`RestoreActionResponse.reason`)
- Modify: `frontend/src/app/features/restore/restore.model.ts` (`RestoreAction.reason`)
- Modify: `frontend/src/app/features/restore/restore-step-plan.ts:56-70` (`detailOf`)
- Test: `backend/tests/test_restore_dependencies.py`, `backend/tests/test_restore_baseline.py:208`, `frontend/src/app/features/restore/restore-page.spec.ts`
- Regenerate: `docs/openapi.json`

**Interfaces:**
- Consumes: Task 5's guard (a rewrite UPDATE is guarded like any update) and executor id remapping (`prepare_restore_payload(..., id_map=...)`, `services/restore_executor.py:456-474`).
- Produces:
  - `class RestoreActionReason(StrEnum)`: `RESTORE = "restore"`, `REFERENCE_REWRITE = "reference_rewrite"`; `RestoreAction.reason: RestoreActionReason = RestoreActionReason.RESTORE`.
  - `PlanningContext.reference_rewrites: set[PydanticObjectId]` (dataclass field, default empty).
  - `RestorePlanner._build_actions(organization_id, selected, logical_objects, force_delete, reference_rewrites: frozenset[PydanticObjectId] = frozenset()) -> list[RestoreAction]`.
  - A rewrite action: `action=UPDATE`, `reason=REFERENCE_REWRITE`, `source_version_id` = the dependent's current (baseline when prepared) version, `protected_configuration` = that version's configuration (the executor rewrites old UUIDs through `id_map`), `expected_current_hash` = that version's hash, `depends_on` includes the recreated object's logical id. It bypasses both no-op skips.
  - Behavior change: a reverse dependent is no longer queued for further dependency expansion — it is not being restored, only re-pointed.
  - `RestoreActionResponse.reason: RestoreActionReason`; frontend `reason?: 'restore' | 'reference_rewrite'`.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && sed -n 497,507p src/mist_config_guardian_backend/services/restore_planner.py && sed -n 711,712p src/mist_config_guardian_backend/services/restore_planner.py`
Expected: the dependent is selected at `current_version`, and `_action_type` returns `None` when `target.id == latest.id`.

- [ ] **Step 2: Write the failing planner test**

Append to `backend/tests/test_restore_dependencies.py` (add `RestoreActionReason` to the `models.restore` import and `order_restore_actions` to the planner import):

```python
async def test_a_reverse_dependent_of_a_recreated_object_gets_a_reference_rewrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = PydanticObjectId()
    wlan_uuid = "8aa21779-1178-4357-b3e0-42c02b93b870"
    wlan = _logical(organization_id, object_type="wlans", mist_id=wlan_uuid, is_deleted=True)
    device = _logical(organization_id, object_type="devices", mist_id="device-1")
    assert wlan.id is not None
    assert device.id is not None
    wlan_target = _version(organization_id, wlan)
    wlan_tombstone = ObjectVersion.model_construct(**{**wlan_target.model_dump(), "id": PydanticObjectId(), "is_deleted": True})
    device_current = _version(
        organization_id,
        device,
        references=[ObjectReference(target_mist_id=wlan_uuid, field_path="port_config.eth0.wlan_id")],
    )
    planner = _planner()
    related = AsyncMock(return_value=[])
    monkeypatch.setattr(planner, "_related_logical_objects", related)
    monkeypatch.setattr(planner, "_reverse_dependents", AsyncMock(return_value=[(device, device_current)]))
    context = PlanningContext(
        organization_id=organization_id,
        selected={wlan.id: wlan_target},
        requested_logical_ids=frozenset({wlan.id}),
        logical_objects={wlan.id: wlan},
        force_delete=set(),
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        mode=RestoreMode.NON_DESTRUCTIVE,
    )

    await planner._expand_dependencies(context)  # noqa: SLF001

    assert context.reference_rewrites == {device.id}
    related.assert_awaited_once()

    latest = {wlan.id: wlan_tombstone, device.id: device_current}
    monkeypatch.setattr(planner, "_latest_version", AsyncMock(side_effect=lambda logical_id: latest[logical_id]))
    monkeypatch.setattr(
        planner,
        "_action_dependencies",
        AsyncMock(side_effect=lambda _org, target, *_args: [wlan.id] if target.logical_object_id == device.id else []),
    )

    actions = order_restore_actions(
        await planner._build_actions(  # noqa: SLF001
            organization_id,
            context.selected,
            context.logical_objects,
            context.force_delete,
            frozenset(context.reference_rewrites),
        )
    )

    assert [(action.object_type, action.action, action.reason) for action in actions] == [
        ("wlans", RestoreActionType.CREATE, RestoreActionReason.RESTORE),
        ("devices", RestoreActionType.UPDATE, RestoreActionReason.REFERENCE_REWRITE),
    ]
    rewrite = actions[1]
    assert rewrite.source_version_id == device_current.id
    assert rewrite.expected_current_hash == device_current.configuration_hash
    assert rewrite.depends_on == [wlan.id]
```

- [ ] **Step 3: Write the failing frontend test**

Append inside the `describe` in `frontend/src/app/features/restore/restore-page.spec.ts`:

```ts
  it('explains an update that only re-points references at a recreated object', async () => {
    await plan({
      actions: [
        action({ action: 'create', object_name: 'Corp WLAN' }),
        action({
          logical_object_id: 'lo-2',
          order: 1,
          object_name: 'Lobby-AP',
          reason: 'reference_rewrite',
          depends_on: ['lo-1'],
        }),
      ],
    });

    expect(text()).toContain('Updates references to a recreated object');
  });
```

- [ ] **Step 4: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_dependencies.py -v -k reference_rewrite`
Expected: FAIL — `ImportError: cannot import name 'RestoreActionReason'`.

Run: `cd frontend && npm test -- --watch=false`
Expected: FAIL — the text is missing (and a type error on `reason`).

- [ ] **Step 5: Implement the model and planner**

`models/restore.py`, after `RestoreActionStatus`:

```python
class RestoreActionReason(StrEnum):
    """Why a plan contains an action."""

    RESTORE = "restore"
    # The object is not being restored; its references to an object this plan
    # recreates must be pointed at the new UUID (spec §9.4 steps 4-5).
    REFERENCE_REWRITE = "reference_rewrite"
```

and in `RestoreAction` after `depends_on`: `reason: RestoreActionReason = RestoreActionReason.RESTORE`.

`services/restore_planner.py`: import `field` from `dataclasses` and `RestoreActionReason`. Add to `PlanningContext`:

```python
    reference_rewrites: set[PydanticObjectId] = field(default_factory=set)
```

In `create_plan`, build the context in a local variable before `_expand_dependencies` so its `reference_rewrites` survive:

```python
        context = PlanningContext(
            organization_id=organization_id,
            selected=selected,
            requested_logical_ids=frozenset(selected),
            logical_objects=logical_objects,
            force_delete=force_delete,
            target_at=target_at,
            mode=mode,
        )
        if include_dependencies:
            await self._expand_dependencies(context)
```

and call `self._build_actions(organization_id, selected, logical_objects, force_delete, frozenset(context.reference_rewrites))`.

In `_expand_dependencies`, replace the reverse-dependent loop (lines 502-507) with:

```python
                for dependent, current_version in reverse_dependents:
                    if dependent.id is None or dependent.id in context.selected:
                        continue
                    # Re-pointed at the recreated UUID, not restored: its own
                    # references are current and are not expanded further.
                    context.selected[dependent.id] = current_version
                    context.logical_objects[dependent.id] = dependent
                    context.reference_rewrites.add(dependent.id)
```

Replace `_build_actions` with:

```python
    async def _build_actions(
        self,
        organization_id: PydanticObjectId,
        selected: dict[PydanticObjectId, ObjectVersion],
        logical_objects: dict[PydanticObjectId, LogicalObject],
        force_delete: set[PydanticObjectId],
        reference_rewrites: frozenset[PydanticObjectId] = frozenset(),
    ) -> list[RestoreAction]:
        actions: list[RestoreAction] = []
        for logical_id, target in selected.items():
            logical = logical_objects[logical_id]
            latest = self._baselines.get(logical_id) or await self._latest_version(logical_id)
            if latest is None or target.id is None:
                continue
            definition = get_definition(logical.scope, logical.object_type)
            rewrite = logical_id in reference_rewrites
            if rewrite:
                # The live configuration is written back unchanged except for
                # the UUIDs the executor remaps, so the source is the current
                # (freshly backed-up) version, never an older one.
                target = latest
                action_type: RestoreActionType | None = RestoreActionType.UPDATE
            else:
                if (
                    logical_id in self._baselines
                    and not logical.is_deleted
                    and not target.is_deleted
                    and logical_id not in force_delete
                    and definition is not None
                    and target.configuration_hash == latest.configuration_hash
                ):
                    continue
                action_type = self._action_type(logical, target, latest, force_delete=logical_id in force_delete)
            if action_type is None or target.id is None:
                continue
            dependencies = await self._action_dependencies(
                organization_id,
                target,
                selected,
                logical_objects,
                action_type,
            )
            actions.append(
                RestoreAction(
                    logical_object_id=logical_id,
                    source_version_id=target.id,
                    baseline_version_id=latest.id if logical_id in self._baselines else None,
                    order=0,
                    action=action_type,
                    scope=logical.scope,
                    object_type=logical.object_type,
                    object_name=logical.name,
                    current_mist_id=logical.current_mist_id,
                    site_mist_id=logical.site_mist_id,
                    protected_configuration=protect_configuration(
                        target.configuration,
                        self._vault,
                        sensitive_fields=definition.sensitive_fields,
                    )
                    if definition is not None
                    else target.configuration,
                    expected_current_hash=(None if logical.is_deleted else latest.configuration_hash),
                    depends_on=dependencies,
                    reason=RestoreActionReason.REFERENCE_REWRITE if rewrite else RestoreActionReason.RESTORE,
                )
            )
        return actions
```

Verify while implementing: `_action_dependencies` already adds a dependency on a referenced object that is selected and deleted (`restore_planner.py:669-681`), which is what orders the rewrite after the CREATE; the test asserts it through the patched method, so also run `tests/test_restore_ordering.py`.

- [ ] **Step 6: Expose the reason**

`schemas/restore.py`: import `RestoreActionReason`; add `reason: RestoreActionReason = RestoreActionReason.RESTORE` to `RestoreActionResponse` and `reason=action.reason,` in `from_model`.

`frontend/src/app/features/restore/restore.model.ts`: add `export type RestoreActionReason = 'restore' | 'reference_rewrite';` and `reason?: RestoreActionReason;` to `RestoreAction`.

`frontend/src/app/features/restore/restore-step-plan.ts` `detailOf`, replace the `else` branch:

```ts
  } else if (action.reason === 'reference_rewrite') {
    parts.push('Updates references to a recreated object');
  } else {
    parts.push(`Updated to version ${shortOperationId(action.source_version_id)}`);
  }
```

- [ ] **Step 7: Run the tests**

Run: `cd backend && uv run pytest tests/test_restore_dependencies.py tests/test_restore_ordering.py tests/test_restore_baseline.py tests/test_restore_verification.py -v`
Expected: PASS (`test_plan_uses_pinned_backup_even_if_background_history_changes` still calls `_build_actions` with four arguments).

Run: `make openapi && cd backend && uv run python ../scripts/export-openapi.py --check`, then `cd frontend && npm test -- --watch=false && npm run build`
Expected: PASS.

- [ ] **Step 8: Lint and type-check**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src`
Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add backend/src/mist_config_guardian_backend/models/restore.py \
  backend/src/mist_config_guardian_backend/services/restore_planner.py \
  backend/src/mist_config_guardian_backend/schemas/restore.py \
  backend/tests/test_restore_dependencies.py docs/openapi.json \
  frontend/src/app/features/restore/restore.model.ts frontend/src/app/features/restore/restore-step-plan.ts \
  frontend/src/app/features/restore/restore-page.spec.ts
git commit -m "fix(restore): rewrite references to recreated objects instead of dropping them" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8: CREATE preflight refuses a live name collision

**Findings:** M7.

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/integrations/mist_mutation.py` (new `list_objects`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_compensation.py` (`restore_name`, `_refuse_name_collision`, `capture_safety_snapshot`)
- Test: `backend/tests/test_mist_mutation.py`, `backend/tests/test_restore_compensation.py`

**Interfaces:**
- Consumes: `MistMutationClient._send` (Task 1); `recreated_site_ids` skip (Task 5); `outcome_unknown` (Task 2).
- Produces:
  - `MistMutationClient.list_objects(definition: ObjectDefinition, *, org_id: str, site_id: str | None) -> list[dict[str, object]]` — paginated like `MistConfigurationClient._paginate` (`integrations/mist_config.py:70-99`): `limit=1000`, `page`, `X-Page-Total`/`X-Page-Limit`, honouring `definition.request_params` and `definition.response_items_key`.
  - `restore_compensation.restore_name(definition: ObjectDefinition, configuration: Mapping[str, object]) -> str | None` — first non-blank string among `definition.name_fields`; `None` when the configuration carries no explicit name (then no check is possible or made).
  - Rule: during `capture_safety_snapshot`, every CREATE that is read up front (not deferred under a recreated site, and not an unconfirmed-delete reversal whose old UUID still exists) lists live objects of its type at its scope once per `(type, site)` and fails preflight when another object has the same name. Message: `"{object_name}: a {definition.key} named '{name}' already exists in Mist; it may have been recreated manually. Rename or remove it, then rebuild the plan"`.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && sed -n 300,304p src/mist_config_guardian_backend/services/restore_compensation.py`
Expected: the CREATE check only asks whether `current` (the old UUID) is `None`.

- [ ] **Step 2: Write the failing tests**

Append to `backend/tests/test_mist_mutation.py`:

```python
async def test_list_objects_reads_every_page(httpx_mock: HTTPXMock) -> None:
    headers = {"X-Page-Total": "2", "X-Page-Limit": "1"}
    httpx_mock.add_response(
        method="GET", url=f"{NETWORKS_URL}?limit=1000&page=1", json=[{"id": "network-1", "name": "Corp"}], headers=headers
    )
    httpx_mock.add_response(
        method="GET", url=f"{NETWORKS_URL}?limit=1000&page=2", json=[{"id": "network-2", "name": "Guest"}], headers=headers
    )

    async with _client(_Sleeps()) as client:
        listed = await client.list_objects(_networks(), org_id="org-1", site_id=None)

    assert [item["id"] for item in listed] == ["network-1", "network-2"]
```

In `backend/tests/test_restore_compensation.py`, extend `_FakeMistClient`:

```python
class _FakeMistClient:
    """Returns canned live state for every plan target."""

    def __init__(
        self,
        live: dict[str, dict[str, object] | None],
        listing: dict[tuple[str, str | None], list[dict[str, object]]] | None = None,
    ) -> None:
        self.live = live
        self.reads: list[str] = []
        self.listing = listing or {}
        self.listed: list[tuple[str, str | None]] = []

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        self.reads.append(object_id)
        return self.live.get(object_id)

    async def list_objects(self, definition, *, org_id, site_id):  # noqa: ARG002
        self.listed.append((definition.key, site_id))
        return [dict(item) for item in self.listing.get((definition.key, site_id), [])]
```

and add:

```python
async def test_a_create_is_refused_when_mist_already_has_an_object_with_that_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version", _no_stored_version
    )
    client = _FakeMistClient({}, listing={("wlans", "site-a"): [{"id": "manual-uuid", "name": "wlan-0"}]})

    with pytest.raises(MistMutationError, match="named 'wlan-0' already exists in Mist"):
        await capture_safety_snapshot(
            client, _organization(), _operation([_action(0, RestoreActionType.CREATE)]), _vault()
        )


async def test_a_create_with_a_free_name_lists_its_scope_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version", _no_stored_version
    )
    client = _FakeMistClient({}, listing={("wlans", "site-a"): [{"id": "other", "name": "Guest"}]})
    operation = _operation([_action(0, RestoreActionType.CREATE), _action(1, RestoreActionType.CREATE)])

    entries = await capture_safety_snapshot(client, _organization(), operation, _vault())

    assert len(entries) == 2
    assert client.listed == [("wlans", "site-a")]


async def test_a_reversal_that_finds_its_object_still_present_is_not_a_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version", _no_stored_version
    )
    recreate = _action(0, RestoreActionType.CREATE)
    recreate.outcome_unknown = True
    client = _FakeMistClient(
        {"mist-0": {"id": "mist-0", "name": "wlan-0"}},
        listing={("wlans", "site-a"): [{"id": "mist-0", "name": "wlan-0"}]},
    )

    await capture_safety_snapshot(client, _organization(), _operation([recreate]), _vault(), relaxed=True)

    assert client.listed == []
```

- [ ] **Step 3: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_mist_mutation.py tests/test_restore_compensation.py -v -k "list_objects or named or free_name or still_present"`
Expected: FAIL — `AttributeError: 'MistMutationClient' object has no attribute 'list_objects'`; the collision is not detected; `client.listed` stays empty.

- [ ] **Step 4: Implement the listing**

Add to `MistMutationClient`:

```python
    async def list_objects(
        self,
        definition: ObjectDefinition,
        *,
        org_id: str,
        site_id: str | None,
    ) -> list[dict[str, object]]:
        """List every live object of one type at one scope."""
        path = definition.path(org_id=org_id, site_id=site_id)
        items: list[dict[str, object]] = []
        page = 1
        while True:
            params: dict[str, str | int] = {**dict(definition.request_params), "limit": 1000, "page": page}
            response = await self._send("GET", path, action="list", object_type=definition.key, params=params)
            payload = self._response_payload(response, "list", definition.key, write=False)
            if definition.response_items_key is not None and isinstance(payload, dict):
                payload = payload.get(definition.response_items_key)
            if not isinstance(payload, list):
                msg = f"Mist returned an invalid list for {definition.key}"
                raise MistMutationError(msg)
            items.extend(cast("dict[str, object]", item) for item in payload if isinstance(item, dict))
            total = response.headers.get("X-Page-Total", "")
            limit = response.headers.get("X-Page-Limit", "")
            page_size = int(limit) if limit.isdigit() else len(payload)
            if not payload or not total.isdigit() or page * page_size >= int(total):
                return items
            page += 1
```

- [ ] **Step 5: Implement the preflight**

In `services/restore_compensation.py` (import `Mapping` is already present):

```python
def restore_name(definition: ObjectDefinition, configuration: Mapping[str, object]) -> str | None:
    """The explicit display name a configuration carries, if any."""
    for field_name in definition.name_fields:
        value = configuration.get(field_name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


async def _refuse_name_collision(  # noqa: PLR0913 - one argument per fact the check needs
    client: MistMutationClient,
    organization: Organization,
    action: RestoreAction,
    definition: ObjectDefinition,
    vault: CredentialVault,
    listings: dict[tuple[str, str | None], list[dict[str, object]]],
) -> None:
    """Refuse to create an object Mist already holds under a new UUID with the same name."""
    name = restore_name(definition, reveal_configuration(action.protected_configuration, vault))
    if name is None:
        return
    scope = (definition.key, action.site_mist_id)
    if scope not in listings:
        listings[scope] = await client.list_objects(
            definition, org_id=organization.mist_org_id, site_id=action.site_mist_id
        )
    for item in listings[scope]:
        if item.get("id") != action.current_mist_id and restore_name(definition, item) == name:
            msg = (
                f"{action.object_name}: a {definition.key} named {name!r} already exists in Mist; "
                "it may have been recreated manually. Rename or remove it, then rebuild the plan"
            )
            raise MistMutationError(msg)
```

In `capture_safety_snapshot`, create `listings: dict[tuple[str, str | None], list[dict[str, object]]] = {}` before the loop and, inside the `try` right after `_validate_live_state(...)`:

```python
            if action.action is RestoreActionType.CREATE and not (action.outcome_unknown and current is not None):
                await _refuse_name_collision(client, organization, action, definition, vault, listings)
```

(inside the `try`, so a collision also emits the value-free preflight diagnostics log.)

- [ ] **Step 6: Run the tests**

Run: `cd backend && uv run pytest tests/test_mist_mutation.py tests/test_restore_compensation.py tests/test_restore_write_guard.py tests/test_restore_verification.py -v`
Expected: PASS. `_applied_plan` lists `("wlans", "site-a")` and gets `[]`.

- [ ] **Step 7: Lint and type-check**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add backend/src/mist_config_guardian_backend/integrations/mist_mutation.py \
  backend/src/mist_config_guardian_backend/services/restore_compensation.py \
  backend/tests/test_mist_mutation.py backend/tests/test_restore_compensation.py
git commit -m "fix(restore): refuse to recreate an object Mist already holds under the same name" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 9: Organization restore lease

**Findings:** H5 first half (spec §9.5.1).

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/models/restore.py` (new `RestoreLease` document)
- Modify: `backend/src/mist_config_guardian_backend/models/__init__.py` (register `RestoreLease` in `document_models()` and `__all__`)
- Create: `backend/src/mist_config_guardian_backend/services/restore_lease.py`
- Modify: `backend/src/mist_config_guardian_backend/services/restore_executor.py` (`__init__`, `execute`, `_heartbeat`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_recovery.py` (`__init__`, `_interrupt`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_authorization.py` (`__init__`, `authorize`, `prepare`, new `RestoreConcurrencyError`)
- Modify: `backend/src/mist_config_guardian_backend/api/routes/restores.py:247-258, 405-408`
- Modify: `backend/src/mist_config_guardian_backend/tasks/restores.py:25-32`
- Create: `backend/tests/test_restore_lease.py`, `backend/tests/test_restore_lease_mongo.py`
- Test: `backend/tests/test_restore_verification.py`, `backend/tests/test_restore_baseline.py`, `backend/tests/test_restore_compensation.py`, `backend/tests/test_restore_recovery_mongo.py`

**Interfaces:**
- Consumes: `_heartbeat` (Task 4), `RestoreRecoveryService._interrupt` (Task 4).
- Produces:
  - `class RestoreLease(Document)` — collection `restore_leases`; fields `organization_id: PydanticObjectId`, `holder_operation_id: PydanticObjectId`, `acquired_at: datetime`, `expires_at: datetime`; indexes `restore_lease_organization_unique` (unique on `organization_id`) and `restore_lease_expiry` (TTL, `expireAfterSeconds=0` on `expires_at`).
  - `restore_lease.ANOTHER_RESTORE_RUNNING = "Another restore is running for this organization"`.
  - `class RestoreLeaseStore(Protocol)`: `acquire(organization_id, operation_id, *, ttl: timedelta) -> bool`, `renew(organization_id, operation_id, *, ttl: timedelta) -> bool`, `release(organization_id, operation_id) -> None` (all async). Implementations `MongoRestoreLeaseStore`, `MemoryRestoreLeaseStore(clock: Callable[[], datetime] = utc_now)`.
  - `class RestoreLeaseLostError(MistMutationError)`.
  - `restore_lease.has_active_restore(organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> bool` (async) — another operation of the organization is `QUEUED` or `RUNNING`.
  - `RestoreExecutor.__init__(..., leases: RestoreLeaseStore | None = None, lease_ttl: timedelta = timedelta(minutes=15))`.
  - `RestoreRecoveryService.__init__(..., leases: RestoreLeaseStore | None = None)`.
  - `class RestoreConcurrencyError(RestoreAuthorizationError)`; `RestoreAuthorizationService.__init__(settings, vault, mist, *, active_restores: Callable[[PydanticObjectId, PydanticObjectId], Awaitable[bool]] | None = None)`.
  - API: `POST .../execute`, `.../compensation/execute` and `.../prepare` answer **409** with `ANOTHER_RESTORE_RUNNING` while another operation of the organization is queued or running. Compensation runs through the same executor and therefore the same lease.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && grep -rn "lock\|lease" src/mist_config_guardian_backend/services/restore_*.py`
Expected: no match.

- [ ] **Step 2: Write the failing memory-store and executor tests**

Create `backend/tests/test_restore_lease.py`:

```python
"""The in-memory lease behaves like the MongoDB one the executor relies on."""

from datetime import UTC, datetime, timedelta

from beanie import PydanticObjectId

from mist_config_guardian_backend.services.restore_lease import MemoryRestoreLeaseStore

TTL = timedelta(minutes=15)


async def test_one_holder_per_organization_until_release() -> None:
    store = MemoryRestoreLeaseStore()
    organization, first, second = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()

    assert await store.acquire(organization, first, ttl=TTL) is True
    assert await store.acquire(organization, second, ttl=TTL) is False
    assert await store.acquire(PydanticObjectId(), second, ttl=TTL) is True
    assert await store.renew(organization, second, ttl=TTL) is False
    await store.release(organization, second)
    assert await store.acquire(organization, second, ttl=TTL) is False
    await store.release(organization, first)
    assert await store.acquire(organization, second, ttl=TTL) is True


async def test_an_expired_lease_can_be_taken_over() -> None:
    now = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
    clock = [now]
    store = MemoryRestoreLeaseStore(clock=lambda: clock[0])
    organization, first, second = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()
    await store.acquire(organization, first, ttl=TTL)

    clock[0] = now + TTL + timedelta(seconds=1)

    assert await store.acquire(organization, second, ttl=TTL) is True
    assert await store.renew(organization, first, ttl=TTL) is False
```

In `backend/tests/test_restore_verification.py`: add imports `from mist_config_guardian_backend.services.restore_lease import ANOTHER_RESTORE_RUNNING, MemoryRestoreLeaseStore`; give `_run` a `leases: MemoryRestoreLeaseStore | None = None` keyword and pass `leases=leases or MemoryRestoreLeaseStore()` to `RestoreExecutor(...)`; add:

```python
@pytest.mark.usefixtures("executed")
async def test_a_second_restore_for_the_organization_fails_without_writing(monkeypatch: pytest.MonkeyPatch) -> None:
    leases = MemoryRestoreLeaseStore()
    await leases.acquire(ORGANIZATION_ID, PydanticObjectId(), ttl=timedelta(minutes=15))
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True, leases=leases)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert result.status is RestoreStatus.FAILED
    assert ANOTHER_RESTORE_RUNNING in result.preflight_errors
    assert result.encrypted_delegated_credential is None
    assert notifications.failed == [ANOTHER_RESTORE_RUNNING]


@pytest.mark.usefixtures("executed")
async def test_the_lease_is_released_when_the_run_ends(monkeypatch: pytest.MonkeyPatch) -> None:
    leases = MemoryRestoreLeaseStore()
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, _, _ = _run(monkeypatch, operation, verified=True, leases=leases)

    await executor.execute(OPERATION_ID)

    assert await leases.acquire(ORGANIZATION_ID, PydanticObjectId(), ttl=timedelta(minutes=15)) is True


class _LostLeases(MemoryRestoreLeaseStore):
    async def renew(self, organization_id, operation_id, *, ttl):  # noqa: ARG002
        return False


@pytest.mark.usefixtures("executed")
async def test_a_lost_lease_stops_before_the_next_write(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True, leases=_LostLeases())

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert result.status is RestoreStatus.FAILED
    assert "lease was lost" in notifications.failed[0]
```

- [ ] **Step 3: Write the failing authorization and route tests**

In `backend/tests/test_restore_baseline.py`: import `RestoreConcurrencyError` from `restore_authorization`; in the `authorization` fixture construct the service as `RestoreAuthorizationService(settings, vault, mist, active_restores=AsyncMock(return_value=False))`; add:

```python
async def test_authorization_refuses_while_another_restore_is_queued_or_running(authorization):
    service, operation, query, mist = authorization
    service._active_restores = AsyncMock(return_value=True)

    with pytest.raises(RestoreConcurrencyError, match="Another restore is running"):
        await service.authorize(operation.organization_id, operation.id, None, "task")

    query.update.assert_not_awaited()
    mist.verify_write_token.assert_not_awaited()
```

In `backend/tests/test_restore_compensation.py`: import `RestoreConcurrencyError` and `ANOTHER_RESTORE_RUNNING`; add:

```python
class _BusyAuthorization(_RecordingAuthorization):
    """Another restore of the organization holds the queue."""

    async def authorize(self, organization_id, operation_id, credential, task_id, **_kwargs):  # noqa: ARG002
        raise RestoreConcurrencyError(ANOTHER_RESTORE_RUNNING)


async def test_compensation_is_refused_with_a_conflict_while_another_restore_runs(routed: list[str]) -> None:
    plan = _operation([], status=RestoreStatus.PLANNED, identifier=COMPENSATION_ID)
    transport = httpx.ASGITransport(app=_app(_StubCompensation(plan), _BusyAuthorization()))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/compensation/execute",
            json={"administrator_token": "fresh-admin-token"},
        )

    assert response.status_code == 409
    assert response.json()["detail"] == ANOTHER_RESTORE_RUNNING
    assert routed == []
```

- [ ] **Step 4: Write the failing DB-backed lease test**

Create `backend/tests/test_restore_lease_mongo.py`:

```python
"""The MongoDB lease admits one restore per organization.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.restore import RestoreLease, RestoreMode, RestoreOperation, RestoreStatus
from mist_config_guardian_backend.services.restore_lease import MongoRestoreLeaseStore, has_active_restore

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_leases"
TTL = timedelta(minutes=15)

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[RestoreLease, RestoreOperation])
    yield
    await client.drop_database(DATABASE)
    await client.close()


async def test_one_holder_per_organization() -> None:
    store = MongoRestoreLeaseStore()
    organization, first, second = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()

    assert await store.acquire(organization, first, ttl=TTL) is True
    assert await store.acquire(organization, second, ttl=TTL) is False
    assert await store.acquire(organization, first, ttl=TTL) is True
    assert await store.renew(organization, second, ttl=TTL) is False
    assert await store.renew(organization, first, ttl=TTL) is True
    await store.release(organization, second)
    assert await store.acquire(organization, second, ttl=TTL) is False
    await store.release(organization, first)
    assert await store.acquire(organization, second, ttl=TTL) is True


async def test_an_expired_lease_can_be_taken_over() -> None:
    store = MongoRestoreLeaseStore()
    organization, first, second = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()
    await store.acquire(organization, first, ttl=-timedelta(seconds=1))

    assert await store.acquire(organization, second, ttl=TTL) is True
    assert await store.renew(organization, first, ttl=TTL) is False


async def test_abandoned_leases_expire_and_organizations_are_unique() -> None:
    indexes = await RestoreLease.get_pymongo_collection().index_information()

    assert indexes["restore_lease_expiry"]["expireAfterSeconds"] == 0
    assert indexes["restore_lease_organization_unique"]["unique"] is True


async def test_active_restores_are_other_queued_or_running_operations() -> None:
    organization = PydanticObjectId()
    queued = RestoreOperation(
        organization_id=organization,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.QUEUED,
    )
    await queued.insert()
    assert queued.id is not None

    assert await has_active_restore(organization, queued.id) is False
    assert await has_active_restore(organization, PydanticObjectId()) is True
    assert await has_active_restore(PydanticObjectId(), PydanticObjectId()) is False
```

In `backend/tests/test_restore_recovery_mongo.py`: import `MemoryRestoreLeaseStore`; `_service` passes `leases=leases` from a new `leases: MemoryRestoreLeaseStore` parameter; in `test_a_stale_run_with_a_write_in_flight_becomes_compensable` create `leases = MemoryRestoreLeaseStore()`, `await leases.acquire(stale.organization_id, stale.id, ttl=timedelta(minutes=15))` before recovering, and assert afterwards `await leases.acquire(stale.organization_id, PydanticObjectId(), ttl=timedelta(minutes=15)) is True`. The other two tests pass `MemoryRestoreLeaseStore()`.

- [ ] **Step 5: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_lease.py tests/test_restore_verification.py tests/test_restore_baseline.py tests/test_restore_compensation.py -v -k "lease or holder or expired or another_restore or conflict_while" && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_lease_mongo.py tests/test_restore_recovery_mongo.py -v`
Expected: FAIL — `ModuleNotFoundError: ... restore_lease`, `ImportError: RestoreLease`.

- [ ] **Step 6: Implement the model and lease module**

`models/restore.py` (add `from datetime import datetime` is already imported):

```python
class RestoreLease(Document):
    """The one restore allowed to write to an organization at a time (spec §9.5.1).

    A holder renews it with every action. A worker that dies stops renewing, so
    the lease lapses on its own and MongoDB removes the document.
    """

    organization_id: PydanticObjectId
    holder_operation_id: PydanticObjectId
    acquired_at: datetime
    expires_at: datetime

    class Settings:
        name = "restore_leases"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1)], unique=True, name="restore_lease_organization_unique"),
            IndexModel([("expires_at", 1)], expireAfterSeconds=0, name="restore_lease_expiry"),
        ]
```

Register it: in `models/__init__.py` import `RestoreLease` alongside `RestoreOperation`, add `RestoreLease` after `RestoreOperationStateRecord` in `document_models()` and to `__all__`.

Create `services/restore_lease.py`:

```python
"""Organization-scoped restore lease and the queue check that accompanies it."""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Protocol

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.integrations.mist_mutation import MistMutationError
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.restore import RestoreLease, RestoreOperation, RestoreStatus

ANOTHER_RESTORE_RUNNING = "Another restore is running for this organization"


class RestoreLeaseLostError(MistMutationError):
    """The executor no longer holds its organization's lease."""


class RestoreLeaseStore(Protocol):
    """Exclusive, expiring ownership of an organization for one restore."""

    async def acquire(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta) -> bool:
        """Take or re-enter the lease; ``False`` while another live holder has it."""

    async def renew(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta) -> bool:
        """Extend the lease; ``False`` when this operation no longer holds it."""

    async def release(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> None:
        """Give the lease up if this operation holds it."""


class MongoRestoreLeaseStore:
    """Lease backed by a unique organization document with a TTL index."""

    async def acquire(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta) -> bool:
        """Take the lease atomically: the unique index refuses a second live holder."""
        now = utc_now()
        try:
            await RestoreLease.get_pymongo_collection().find_one_and_update(
                {
                    "organization_id": organization_id,
                    "$or": [{"holder_operation_id": operation_id}, {"expires_at": {"$lte": now}}],
                },
                {"$set": {"holder_operation_id": operation_id, "acquired_at": now, "expires_at": now + ttl}},
                upsert=True,
            )
        except DuplicateKeyError:
            return False
        return True

    async def renew(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta) -> bool:
        """Extend the lease only while this operation still holds it."""
        result = await RestoreLease.get_pymongo_collection().update_one(
            {"organization_id": organization_id, "holder_operation_id": operation_id},
            {"$set": {"expires_at": utc_now() + ttl}},
        )
        return result.matched_count == 1

    async def release(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> None:
        """Remove the lease if this operation holds it."""
        await RestoreLease.get_pymongo_collection().delete_one(
            {"organization_id": organization_id, "holder_operation_id": operation_id}
        )


class MemoryRestoreLeaseStore:
    """Process-local lease with the same semantics, for tests."""

    def __init__(self, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock
        self._leases: dict[PydanticObjectId, tuple[PydanticObjectId, datetime]] = {}

    async def acquire(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta) -> bool:
        """Take or re-enter the lease; ``False`` while another live holder has it."""
        now = self._clock()
        held = self._leases.get(organization_id)
        if held is not None and held[0] != operation_id and held[1] > now:
            return False
        self._leases[organization_id] = (operation_id, now + ttl)
        return True

    async def renew(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta) -> bool:
        """Extend the lease only while this operation still holds it."""
        held = self._leases.get(organization_id)
        if held is None or held[0] != operation_id:
            return False
        self._leases[organization_id] = (operation_id, self._clock() + ttl)
        return True

    async def release(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> None:
        """Remove the lease if this operation holds it."""
        held = self._leases.get(organization_id)
        if held is not None and held[0] == operation_id:
            del self._leases[organization_id]


async def has_active_restore(organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> bool:
    """Whether another restore of this organization is queued or running."""
    count = await RestoreOperation.find(
        RestoreOperation.organization_id == organization_id,
        {"_id": {"$ne": operation_id}, "status": {"$in": [RestoreStatus.QUEUED, RestoreStatus.RUNNING]}},
    ).count()
    return count > 0
```

Note the Mongo `acquire` test (step 4) takes over an "expired" lease: `renew` of the old holder then matches nothing because the holder id changed.

- [ ] **Step 7: Hold the lease in the executor and release it in recovery**

`services/restore_executor.py` — imports `from datetime import timedelta`, `from mist_config_guardian_backend.services.restore_lease import ANOTHER_RESTORE_RUNNING, MongoRestoreLeaseStore, RestoreLeaseLostError, RestoreLeaseStore`. Constructor gains `leases: RestoreLeaseStore | None = None, lease_ttl: timedelta = timedelta(minutes=15)` stored as `self._leases = leases or MongoRestoreLeaseStore()` and `self._lease_ttl = lease_ttl`. Replace `execute`:

```python
    async def execute(self, operation_id: PydanticObjectId) -> RestoreOperation:
        """Execute pending actions once using the delegated Mist identity.

        Every exit leaves a terminal status, a failure notification when it did
        not complete, no delegated credential, and no organization lease.
        """
        operation, organization, token = await self._prepare(operation_id)
        acquired = False
        try:
            acquired = await self._leases.acquire(operation.organization_id, operation_id, ttl=self._lease_ttl)
            if not acquired:
                # Opening and closing the client revokes a session credential.
                async with MistMutationClient(token=token, region=organization.cloud_region):
                    pass
                await self._fail_preflight(operation, ANOTHER_RESTORE_RUNNING)
                await self._notify_failure(operation, ANOTHER_RESTORE_RUNNING)
                return operation
            return await self._run(operation, organization, token)
        except Exception as exc:  # noqa: BLE001 - every exit must end in a terminal, notified state
            await self._fail_unexpectedly(operation, exc)
            return operation
        finally:
            if acquired:
                try:
                    await self._leases.release(operation.organization_id, operation_id)
                except Exception as exc:  # noqa: BLE001 - the TTL index lets an unreleased lease lapse
                    logger.error("restore_lease_release_failed operation=%s error_type=%s", operation_id, type(exc).__name__)
            await self._clear_delegated_credential(operation)
```

Replace `_heartbeat`:

```python
    async def _heartbeat(self, operation: RestoreOperation) -> None:
        """Renew the organization lease and record that this worker is alive."""
        if operation.id is None or not await self._leases.renew(
            operation.organization_id, operation.id, ttl=self._lease_ttl
        ):
            msg = "The organization restore lease was lost; no further writes were attempted"
            raise RestoreLeaseLostError(msg)
        operation.touch()
        await operation.save()
```

`services/restore_recovery.py`: constructor gains `leases: RestoreLeaseStore | None = None` stored as `self._leases = leases or MongoRestoreLeaseStore()`; in `_interrupt`, right after the `modified_count` check, add `await self._leases.release(operation.organization_id, operation.id)`.

`tasks/restores.py` `_execute_restore`: `RestoreExecutor(CredentialVault(settings), lease_ttl=timedelta(minutes=settings.restore_worker_heartbeat_timeout_minutes)).execute(...)` (import `timedelta`).

- [ ] **Step 8: Refuse concurrent authorization and preparation**

`services/restore_authorization.py`: import `from collections.abc import Awaitable, Callable` and `from mist_config_guardian_backend.services.restore_lease import ANOTHER_RESTORE_RUNNING, has_active_restore`; add

```python
class RestoreConcurrencyError(RestoreAuthorizationError):
    """Another restore of the organization is queued or running."""
```

Constructor:

```python
    def __init__(
        self,
        settings: Settings,
        vault: CredentialVault,
        mist: MistVerificationService,
        *,
        active_restores: Callable[[PydanticObjectId, PydanticObjectId], Awaitable[bool]] | None = None,
    ) -> None:
        self._settings = settings
        self._vault = vault
        self._mist = mist
        self._active_restores = active_restores or has_active_restore

    async def _refuse_concurrent(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> None:
        if await self._active_restores(organization_id, operation_id):
            raise RestoreConcurrencyError(ANOTHER_RESTORE_RUNNING)
```

In `authorize`, after the `operation.id is None` check (line 65-67) add `await self._refuse_concurrent(organization_id, operation.id)`. In `prepare`, after the status check (line 176-178) add `if operation.id is not None: await self._refuse_concurrent(operation.organization_id, operation.id)`.

`api/routes/restores.py`: import `RestoreConcurrencyError`. In `_authorize_and_queue`, before `except (RestoreAuthorizationError, MistVerificationError)`:

```python
    except RestoreConcurrencyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
```

and the same clause in `prepare_restore` before `except (RestoreAuthorizationError, ...)`.

- [ ] **Step 9: Run the tests**

Run: `cd backend && uv run pytest tests/test_restore_lease.py tests/test_restore_verification.py tests/test_restore_baseline.py tests/test_restore_compensation.py tests/test_restore_credential_cleanup.py -v && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_lease_mongo.py tests/test_restore_recovery_mongo.py tests/test_restore_executor_mongo.py -v`
Expected: PASS.

- [ ] **Step 10: Lint, type-check, OpenAPI**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src && uv run pytest -q && uv run python ../scripts/export-openapi.py --check`
Expected: clean (409 is raised via `HTTPException`; the contract is unchanged — if the exporter now lists a 409 response, run `make openapi` and add `docs/openapi.json` to the commit).

- [ ] **Step 11: Commit**

```bash
git add backend/src/mist_config_guardian_backend/models/restore.py backend/src/mist_config_guardian_backend/models/__init__.py \
  backend/src/mist_config_guardian_backend/services/restore_lease.py \
  backend/src/mist_config_guardian_backend/services/restore_executor.py \
  backend/src/mist_config_guardian_backend/services/restore_recovery.py \
  backend/src/mist_config_guardian_backend/services/restore_authorization.py \
  backend/src/mist_config_guardian_backend/api/routes/restores.py backend/src/mist_config_guardian_backend/tasks/restores.py \
  backend/tests/test_restore_lease.py backend/tests/test_restore_lease_mongo.py \
  backend/tests/test_restore_verification.py backend/tests/test_restore_baseline.py \
  backend/tests/test_restore_compensation.py backend/tests/test_restore_recovery_mongo.py
git commit -m "fix(restore): allow one restore per organization at a time" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 10: Strict compensation drift and retryable compensation

**Findings:** M1, M2.

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/services/restore_compensation.py` (`capture_safety_snapshot`, `_validate_live_state` → `assess_live_state`, `RestoreCompensationService.__init__`, `create_compensation_plan`, `compensation_for`, `compensated_operation`, `_invert`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_write_guard.py` (`WriteCheck.skip`, compensating branch)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_planner.py:101-184` (`RestoreStateStore.compensations_of`, `MongoRestoreStateStore.find_compensation_of`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_outcome.py` (`terminal_failure_status(..., compensating=)`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_executor.py` (`execute`, `_run`, `_execute_action`, `_fail_operation`, `_fail_verification`, `_fail_unexpectedly`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_recovery.py` (`__init__`, `_interrupt`)
- Create: `backend/tests/test_restore_state_store_mongo.py`
- Test: `backend/tests/test_restore_compensation.py`, `backend/tests/test_restore_write_guard.py`, `backend/tests/test_restore_outcome.py`, `backend/tests/test_restore_verification.py`

**Interfaces:**
- Consumes: `RestoreAction.applied_hash` (Task 5), `compensates_action_order` and `outcome_unknown` (Tasks 2-3), `check_before_write` (Task 5).
- Produces:
  - Inverse actions carry `expected_current_hash = original.applied_hash` for UPDATE and DELETE inverses (what the restore wrote); `None` for CREATE inverses and for reversals of unconfirmed writes.
  - `restore_compensation.LiveAssessment = Literal["proceed", "already_reversed"]` and `assess_live_state(action: RestoreAction, current: dict[str, object] | None, vault: CredentialVault) -> LiveAssessment` — raises `RestoreDriftError` when live state forbids the action. `_validate_live_state(action, current, vault) -> None` wraps it (the `relaxed` parameter is removed from both it and `capture_safety_snapshot`).
  - Reversal rules: live matches `expected_current_hash` → proceed; a reversal UPDATE whose live state already equals its payload → `already_reversed`; a reversal DELETE whose object is gone → `already_reversed`; a reversal CREATE whose object exists and whose original was unconfirmed → `already_reversed`; a reversal of an unconfirmed UPDATE (no expected hash) → proceed, with a plan warning; anything else → drift.
  - `WriteCheck.skip: bool = False`; the executor marks a skipped action `SKIPPED`.
  - Planning refuses (preflight error) an applied non-DELETE action with `applied_hash is None` — restores recorded before Task 5 cannot prove the object is unchanged.
  - `RestoreStateStore.compensations_of(organization_id, operation_id) -> list[RestoreOperationState]` (oldest first); `find_compensation_of` returns the state named by the source's `compensation_operation_id`, else the newest by `created_at`.
  - `RestoreCompensationService.__init__(store=None, vault=None, *, plans: RestorePlanRepository | None = None)`.
  - `create_compensation_plan` returns an existing `PLANNED` compensation, refuses while one is `QUEUED`/`RUNNING`, and otherwise plans only the originals no earlier compensation `COMPLETED`.
  - `terminal_failure_status(actions, *, compensating: bool = False)` — a failed compensation ends `FAILED`; the original stays `COMPENSATION_AVAILABLE` and is compensated again from there.

- [ ] **Step 1: Re-verify the findings**

Run: `cd backend && sed -n 305,312p src/mist_config_guardian_backend/services/restore_compensation.py && grep -n "expected_current_hash=None" src/mist_config_guardian_backend/services/restore_compensation.py && sed -n 180,183p src/mist_config_guardian_backend/services/restore_planner.py`
Expected: `if relaxed: return` before the hash compare; inverse actions built with `expected_current_hash=None`; `find_compensation_of` is an unsorted `find_one`.

- [ ] **Step 2: Update the existing tests to the strict contract**

In `backend/tests/test_restore_compensation.py`:

1. Extend `_MemoryStateStore`:

```python
    async def find_compensation_of(self, organization_id, operation_id):
        source = self.items.get((organization_id, operation_id))
        if source is not None and source.compensation_operation_id is not None:
            linked = self.items.get((organization_id, source.compensation_operation_id))
            if linked is not None:
                return linked
        matches = [
            state
            for state in self.items.values()
            if state.organization_id == organization_id and state.compensates_operation_id == operation_id
        ]
        return matches[-1] if matches else None

    async def compensations_of(self, organization_id, operation_id):
        return [
            state
            for state in self.items.values()
            if state.organization_id == organization_id and state.compensates_operation_id == operation_id
        ]
```

2. In `_applied_plan`, replace the loop that sets `expected_current_hash = None` and the relaxed capture with:

```python
    live_state = live or {"mist-1": dict(CORP_WLAN), "mist-2": dict(GUEST_WLAN), "mist-3": dict(GUEST_WLAN)}
    client = _FakeMistClient(live_state)
    for action in actions:
        if action.action is not RestoreActionType.CREATE:
            action.expected_current_hash = configuration_hash(live_state[action.current_mist_id], ignored_fields=IGNORED)
        if action.status is RestoreActionStatus.COMPLETED and action.action is not RestoreActionType.DELETE:
            action.applied_hash = f"applied-{action.order}"
    entries = await capture_safety_snapshot(client, _organization(), operation, _vault())
```

(and delete the old `client = _FakeMistClient(...)` line above it).

3. `test_a_rotated_mist_read_only_url_does_not_invalidate_the_plan`: replace both `relaxed=False` arguments with `_vault()`.
4. Task 3's `test_an_inverse_create_may_find_the_object_its_unconfirmed_delete_never_removed` and Task 8's `test_a_reversal_that_finds_its_object_still_present_is_not_a_collision`: replace `relaxed=True` with `_vault()` / drop the keyword from `capture_safety_snapshot`.
5. Replace `test_relaxed_capture_accepts_the_state_a_restore_already_replaced` with:

```python
async def test_compensation_capture_accepts_what_the_restore_wrote_and_nothing_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version", _no_stored_version
    )
    revert = _action(
        0, RestoreActionType.UPDATE, expected_current_hash=configuration_hash(GUEST_WLAN, ignored_fields=IGNORED)
    )
    revert.compensates_action_order = 4
    revert.protected_configuration = dict(CORP_WLAN)

    entries = await capture_safety_snapshot(
        _FakeMistClient({"mist-0": dict(GUEST_WLAN)}), _organization(), _operation([revert]), _vault()
    )
    assert entries[0].existed is True

    with pytest.raises(MistMutationError, match="changed after this plan was reviewed"):
        await capture_safety_snapshot(
            _FakeMistClient({"mist-0": {**GUEST_WLAN, "vlan": 30}}), _organization(), _operation([revert]), _vault()
        )
```

- [ ] **Step 3: Write the failing new tests**

Append to `backend/tests/test_restore_compensation.py`:

```python
@pytest.mark.usefixtures("offline_documents")
async def test_reversals_expect_exactly_what_the_restore_wrote(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)

    plan = await RestoreCompensationService(store).create_compensation_plan(
        operation=operation, requested_by=ADMINISTRATOR_ID
    )

    by_original = {action.compensates_action_order: action for action in plan.actions}
    assert by_original[0].expected_current_hash == "applied-0"
    assert by_original[1].expected_current_hash == "applied-1"
    assert by_original[2].expected_current_hash is None


@pytest.mark.usefixtures("offline_documents")
async def test_a_restore_recorded_without_read_back_is_not_reversed_blindly(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)
    operation.actions[1].applied_hash = None

    plan = await RestoreCompensationService(store).create_compensation_plan(
        operation=operation, requested_by=ADMINISTRATOR_ID
    )

    assert plan.preflight_errors == [
        "wlan-1 was restored before writes were read back, so compensation cannot prove it is unchanged; "
        "restore it from its history instead"
    ]


def _reversal_of(order: int, *, status: RestoreActionStatus) -> RestoreAction:
    action = _action(order, RestoreActionType.UPDATE, status=status)
    action.compensates_action_order = order
    return action


@pytest.mark.usefixtures("offline_documents")
async def test_a_failed_compensation_can_be_planned_again_without_repeating_reversed_actions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation, store = await _applied_plan(monkeypatch)
    earlier_id = PydanticObjectId()
    earlier = _operation(
        [
            _reversal_of(2, status=RestoreActionStatus.COMPLETED),
            _reversal_of(1, status=RestoreActionStatus.FAILED),
        ],
        status=RestoreStatus.FAILED,
        identifier=earlier_id,
    )
    await store.save(
        RestoreOperationState(
            organization_id=ORGANIZATION_ID,
            operation_id=earlier_id,
            plan_hash="earlier",
            compensates_operation_id=OPERATION_ID,
        )
    )
    source = await store.load(ORGANIZATION_ID, OPERATION_ID)
    assert source is not None
    source.compensation_operation_id = earlier_id
    await store.save(source)
    plans = _MemoryPlans([operation, earlier])
    service = RestoreCompensationService(store, plans=plans)

    plan = await service.create_compensation_plan(operation=operation, requested_by=ADMINISTRATOR_ID)
    plans.plans.append(plan)

    assert [action.compensates_action_order for action in plan.actions] == [1, 0]
    linked = await service.compensation_for(operation)
    assert linked is not None
    assert linked.id == COMPENSATION_ID


@pytest.mark.usefixtures("offline_documents")
async def test_a_compensation_already_running_is_not_planned_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)
    running = _operation([], status=RestoreStatus.RUNNING, identifier=PydanticObjectId())
    await store.save(
        RestoreOperationState(
            organization_id=ORGANIZATION_ID,
            operation_id=running.id,
            plan_hash="running",
            compensates_operation_id=OPERATION_ID,
        )
    )

    with pytest.raises(RestoreCompensationError, match="already queued or running"):
        await RestoreCompensationService(store, plans=_MemoryPlans([operation, running])).create_compensation_plan(
            operation=operation, requested_by=ADMINISTRATOR_ID
        )
```

Append to `backend/tests/test_restore_write_guard.py`:

```python
def _reversal(action_type: RestoreActionType, *, expected: str | None, payload: dict[str, object]) -> RestoreAction:
    action = _action(action_type)
    action.compensates_action_order = 3
    action.expected_current_hash = expected
    action.protected_configuration = dict(payload)
    return action


async def test_a_reversal_refuses_to_overwrite_a_fix_made_after_the_restore() -> None:
    written = {"name": "Corp", "enabled": True}
    action = _reversal(
        RestoreActionType.UPDATE,
        expected=configuration_hash(written, ignored_fields=WLANS.ignored_fields),
        payload={"name": "Corp", "enabled": False},
    )
    client = _Client({"mist-0": {**written, "vlan": 9}})

    with pytest.raises(RestoreDriftError, match="changed after this plan was reviewed"):
        await _check(client, action, entry=_entry(action, written), compensating=True)


async def test_a_reversal_skips_an_object_already_back_in_its_earlier_state() -> None:
    earlier = {"name": "Corp", "enabled": False}
    action = _reversal(RestoreActionType.UPDATE, expected="applied-hash", payload=earlier)

    check = await _check(_Client({"mist-0": dict(earlier)}), action, entry=_entry(action, earlier), compensating=True)

    assert check.skip is True


async def test_a_reversal_skips_deleting_an_object_that_is_already_gone() -> None:
    action = _reversal(RestoreActionType.DELETE, expected="applied-hash", payload={})

    check = await _check(_Client({}), action, entry=_entry(action, {"name": "Corp"}), compensating=True)

    assert check.skip is True


async def test_the_reversal_of_an_unconfirmed_update_proceeds_without_an_expected_state() -> None:
    action = _reversal(RestoreActionType.UPDATE, expected=None, payload={"name": "Corp", "enabled": False})
    action.outcome_unknown = True

    check = await _check(
        _Client({"mist-0": {"name": "Corp", "enabled": True}}),
        action,
        entry=_entry(action, {"name": "Corp", "enabled": True}),
        compensating=True,
    )

    assert check.skip is False
```

Append to `backend/tests/test_restore_outcome.py`:

```python
def test_a_failed_compensation_is_a_plain_failure_even_after_applying_something() -> None:
    actions = [_action(0, RestoreActionStatus.COMPLETED), _action(1, RestoreActionStatus.FAILED)]

    assert terminal_failure_status(actions, compensating=True) is RestoreStatus.FAILED
```

Create `backend/tests/test_restore_state_store_mongo.py`:

```python
"""The compensation lookup returns the newest attempt.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.restore import RestoreOperationStateRecord
from mist_config_guardian_backend.services.restore_planner import MongoRestoreStateStore

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_state_store"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[RestoreOperationStateRecord])
    yield
    await client.drop_database(DATABASE)
    await client.close()


async def _compensation(organization: PydanticObjectId, source: PydanticObjectId, *, age: timedelta) -> PydanticObjectId:
    identifier = PydanticObjectId()
    await RestoreOperationStateRecord(
        organization_id=organization,
        operation_id=identifier,
        plan_hash="hash",
        compensates_operation_id=source,
        created_at=datetime.now(UTC) - age,
    ).insert()
    return identifier


async def test_without_a_pointer_the_newest_compensation_is_returned() -> None:
    organization, source = PydanticObjectId(), PydanticObjectId()
    await _compensation(organization, source, age=timedelta(hours=2))
    newest = await _compensation(organization, source, age=timedelta(minutes=1))
    await _compensation(organization, source, age=timedelta(hours=1))
    store = MongoRestoreStateStore()

    found = await store.find_compensation_of(organization, source)

    assert found is not None
    assert found.operation_id == newest
    assert len(await store.compensations_of(organization, source)) == 3


async def test_the_source_pointer_wins() -> None:
    organization, source = PydanticObjectId(), PydanticObjectId()
    pointed = await _compensation(organization, source, age=timedelta(hours=2))
    await _compensation(organization, source, age=timedelta(minutes=1))
    await RestoreOperationStateRecord(
        organization_id=organization, operation_id=source, plan_hash="source", compensation_operation_id=pointed
    ).insert()

    found = await MongoRestoreStateStore().find_compensation_of(organization, source)

    assert found is not None
    assert found.operation_id == pointed
```

- [ ] **Step 4: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_compensation.py tests/test_restore_write_guard.py tests/test_restore_outcome.py -v && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_state_store_mongo.py -v`
Expected: FAIL — `capture_safety_snapshot() got an unexpected keyword argument` is gone but the strict checks and `plans=` keyword do not exist; `compensations_of` is missing; `terminal_failure_status` rejects `compensating`.

- [ ] **Step 5: Implement live-state assessment**

In `services/restore_compensation.py` (add `from typing import Literal`), replace `_validate_live_state` with:

```python
LiveAssessment = Literal["proceed", "already_reversed"]


def assess_live_state(
    action: RestoreAction,
    current: dict[str, object] | None,
    vault: CredentialVault,
) -> LiveAssessment:
    """Decide whether live state still allows this action, raising when it does not.

    A reversal is held to the same standard as a restore: it may only replace
    what the restore wrote. Finding the object already back in the state the
    reversal would write is not drift; it is a reversal with nothing left to do.
    """
    definition = get_definition(action.scope, action.object_type)
    ignored = frozenset() if definition is None else definition.ignored_fields
    reversal = action.compensates_action_order is not None
    if action.action is RestoreActionType.CREATE:
        if current is None:
            return "proceed"
        if action.outcome_unknown:
            return "already_reversed"
        msg = f"{action.object_name} was recreated after this plan was reviewed"
        raise RestoreDriftError(msg)
    if current is None:
        if reversal and action.action is RestoreActionType.DELETE:
            return "already_reversed"
        msg = f"{action.object_name} no longer exists"
        raise RestoreDriftError(msg)
    if reversal and action.outcome_unknown and action.expected_current_hash is None:
        return "proceed"
    if action.expected_current_hash is None:
        msg = f"{action.object_name} was recreated after this plan was reviewed"
        raise RestoreDriftError(msg)
    if configuration_hash_matches(action.expected_current_hash, current, ignored_fields=ignored):
        return "proceed"
    if (
        reversal
        and action.action is RestoreActionType.UPDATE
        and canonicalize(reveal_configuration(action.protected_configuration, vault), ignored_fields=ignored)
        == canonicalize(current, ignored_fields=ignored)
    ):
        return "already_reversed"
    msg = f"{action.object_name} changed after this plan was reviewed"
    raise RestoreDriftError(msg)


def _validate_live_state(action: RestoreAction, current: dict[str, object] | None, vault: CredentialVault) -> None:
    """Abort before writes when live state differs from the reviewed plan."""
    assess_live_state(action, current, vault)
```

Move `RestoreDriftError` above this function if needed. In `capture_safety_snapshot` drop the `relaxed` parameter (and its docstring paragraph) and call `_validate_live_state(action, current, vault)`.

- [ ] **Step 6: Implement strict reversal planning and retry**

`services/restore_compensation.py`: import `RestorePlanRepository, get_restore_plan_repository` from the planner.

```python
    def __init__(
        self,
        store: RestoreStateStore | None = None,
        vault: CredentialVault | None = None,
        *,
        plans: RestorePlanRepository | None = None,
    ) -> None:
        self._store = store or get_restore_state_store()
        self._vault = vault or CredentialVault(get_settings())
        self._plans = plans or get_restore_plan_repository()
```

In `create_compensation_plan`, replace the `existing = ...` block (lines 350-357) with:

```python
        already_reversed: set[int] = set()
        for earlier in reversed(await self._store.compensations_of(operation.organization_id, operation.id)):
            plan = await self._plans.load(operation.organization_id, earlier.operation_id)
            if plan is None:
                continue
            if plan.status is RestoreStatus.PLANNED:
                return plan
            if plan.status in {RestoreStatus.QUEUED, RestoreStatus.RUNNING}:
                msg = "A compensation of this restore is already queued or running"
                raise RestoreCompensationError(msg)
            already_reversed.update(
                action.compensates_action_order
                for action in plan.actions
                if action.status is RestoreActionStatus.COMPLETED and action.compensates_action_order is not None
            )
```

In the `reversible` selection add `and action.order not in already_reversed`; if the result is empty and `already_reversed` is non-empty raise `RestoreCompensationError("Every change this restore applied has already been reversed")`. Inside the loop, before `actions.append(...)`, collect:

```python
            if action.outcome_unknown and action.action is RestoreActionType.UPDATE:
                follow_ups.append(
                    f"{action.object_name} was not confirmed, so its reversal cannot check for changes made since"
                )
```

After the loop compute and prepend the legacy preflight errors:

```python
        unverifiable = [
            f"{action.object_name} was restored before writes were read back, so compensation cannot prove it is "
            "unchanged; restore it from its history instead"
            for action in reversible
            if action.status is RestoreActionStatus.COMPLETED
            and action.action is not RestoreActionType.DELETE
            and action.applied_hash is None
        ]
```

and set `preflight_errors=unverifiable + validate_action_capabilities(actions) + unavailable_secret_errors(actions, self._vault)`.

Replace both `RestoreOperation.find_one(...)` reads in `compensation_for` and `compensated_operation` with `await self._plans.load(operation.organization_id, state.operation_id)` / `await self._plans.load(compensation.organization_id, state.compensates_operation_id)`.

In `_invert`, compute and pass the expected state:

```python
        expected = (
            None
            if inverse is RestoreActionType.CREATE or action.outcome_unknown
            else action.applied_hash
        )
```

and use `expected_current_hash=expected,` in the returned action.

`services/restore_planner.py`: add to the `RestoreStateStore` protocol

```python
    async def compensations_of(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> list[RestoreOperationState]:
        """Return every compensation planned for this operation, oldest first."""
```

and replace `MongoRestoreStateStore.find_compensation_of` / add `compensations_of`:

```python
    async def find_compensation_of(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> RestoreOperationState | None:
        """Return the newest compensation of this operation."""
        source = await RestoreOperationStateRecord.find_one(
            RestoreOperationStateRecord.organization_id == organization_id,
            RestoreOperationStateRecord.operation_id == operation_id,
        )
        if source is not None and source.compensation_operation_id is not None:
            linked = await RestoreOperationStateRecord.find_one(
                RestoreOperationStateRecord.organization_id == organization_id,
                RestoreOperationStateRecord.operation_id == source.compensation_operation_id,
            )
            if linked is not None:
                return _state_from_record(linked)
        record = (
            await RestoreOperationStateRecord.find(
                RestoreOperationStateRecord.organization_id == organization_id,
                RestoreOperationStateRecord.compensates_operation_id == operation_id,
            )
            .sort("-created_at")
            .first_or_none()
        )
        return None if record is None else _state_from_record(record)

    async def compensations_of(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> list[RestoreOperationState]:
        """Return every compensation planned for this operation, oldest first."""
        records = (
            await RestoreOperationStateRecord.find(
                RestoreOperationStateRecord.organization_id == organization_id,
                RestoreOperationStateRecord.compensates_operation_id == operation_id,
            )
            .sort("created_at")
            .to_list()
        )
        return [_state_from_record(record) for record in records]
```

- [ ] **Step 7: Enforce in the guard, executor, outcome and recovery**

`services/restore_write_guard.py`: add `skip: bool = False` to `WriteCheck`; import `assess_live_state`; replace the function body after the missing-entry check with:

```python
    if action.action is RestoreActionType.CREATE:
        if entry is None:
            absent = await build_snapshot_entry(action, definition, vault, None, mist_object_id=object_id, site_mist_id=site_id)
            return WriteCheck(entry=absent, recorded=True)
        return WriteCheck(entry=entry, recorded=False, skip=compensating and action.outcome_unknown and entry.existed)
    live = await client.get_current(definition, object_id, org_id=organization.mist_org_id, site_id=site_id)
    if compensating:
        verdict = assess_live_state(action, live, vault)
        observed = entry or await build_snapshot_entry(
            action, definition, vault, live, mist_object_id=object_id, site_mist_id=site_id
        )
        return WriteCheck(entry=observed, recorded=entry is None, skip=verdict == "already_reversed")
    if live is None:
        msg = f"{action.object_name} no longer exists in Mist"
        raise RestoreDriftError(msg)
    if entry is None:
        observed = await build_snapshot_entry(action, definition, vault, live, mist_object_id=object_id, site_mist_id=site_id)
        return WriteCheck(entry=observed, recorded=True)
    if not configuration_hash_matches(entry.configuration_hash, live, ignored_fields=definition.ignored_fields):
        msg = f"{action.object_name} changed in Mist after the pre-restore safety snapshot"
        raise RestoreDriftError(msg)
    return WriteCheck(entry=entry, recorded=False)
```

`services/restore_outcome.py`:

```python
def terminal_failure_status(actions: Sequence[RestoreAction], *, compensating: bool = False) -> RestoreStatus:
    """Decide the status of a restore that stopped before finishing.

    Anything that reached Mist, or may have, has to stay reversible, so an
    applied or unconfirmed write keeps compensation available. A compensation
    that stops is simply failed: the restore it reverses stays compensable and
    is compensated again from there.
    """
    if compensating:
        return RestoreStatus.FAILED
    if any(action.status is RestoreActionStatus.COMPLETED or action.outcome_unknown for action in actions):
        return RestoreStatus.COMPENSATION_AVAILABLE
    return RestoreStatus.FAILED
```

`services/restore_executor.py`:
- In `execute`, before acquiring the lease inside the `try`, load the state and pass it on:

```python
    async def execute(self, operation_id: PydanticObjectId) -> RestoreOperation:
        """Execute pending actions once using the delegated Mist identity.

        Every exit leaves a terminal status, a failure notification when it did
        not complete, no delegated credential, and no organization lease.
        """
        operation, organization, token = await self._prepare(operation_id)
        compensating = False
        acquired = False
        try:
            state = await load_or_build_state(self._store, operation)
            compensating = state.compensates_operation_id is not None
            acquired = await self._leases.acquire(operation.organization_id, operation_id, ttl=self._lease_ttl)
            if not acquired:
                # Opening and closing the client revokes a session credential.
                async with MistMutationClient(token=token, region=organization.cloud_region):
                    pass
                await self._fail_preflight(operation, ANOTHER_RESTORE_RUNNING)
                await self._notify_failure(operation, ANOTHER_RESTORE_RUNNING)
                return operation
            return await self._run(operation, organization, token, state)
        except Exception as exc:  # noqa: BLE001 - every exit must end in a terminal, notified state
            await self._fail_unexpectedly(operation, exc, compensating=compensating)
            return operation
        finally:
            if acquired:
                try:
                    await self._leases.release(operation.organization_id, operation_id)
                except Exception as exc:  # noqa: BLE001 - the TTL index lets an unreleased lease lapse
                    logger.error("restore_lease_release_failed operation=%s error_type=%s", operation_id, type(exc).__name__)
            await self._clear_delegated_credential(operation)
```

- `_run(self, operation, organization, token, state)` no longer loads the state; `capture_safety_snapshot(client, organization, operation, self._vault)` without `relaxed`.
- In `_execute_action` replace the Task 5 unconfirmed-CREATE skip condition with `if check.skip:` (same body).
- `_fail_operation(..., compensating: bool = False)`, `_fail_verification(operation, verification, *, compensating: bool = False)` and `_fail_unexpectedly(operation, exc, *, compensating: bool = False)` pass `compensating=compensating` to `terminal_failure_status`; `_run_actions` receives it through `context.compensating`, and `_run` passes `compensating=compensating` to `_fail_verification`.

`services/restore_recovery.py`: constructor gains `store: RestoreStateStore | None = None` (`self._store = store or get_restore_state_store()`); in `_interrupt`, before computing the status:

```python
        state = await self._store.load(operation.organization_id, operation.id)
        compensating = state is not None and state.compensates_operation_id is not None
        status = terminal_failure_status(operation.actions, compensating=compensating)
```

In `backend/tests/test_restore_recovery_mongo.py` `_service`, pass `store=_EmptyStates()` where

```python
class _EmptyStates:
    async def load(self, organization_id, operation_id):  # noqa: ARG002
        return None
```

- [ ] **Step 8: Run the tests**

Run: `cd backend && uv run pytest tests/test_restore_compensation.py tests/test_restore_write_guard.py tests/test_restore_outcome.py tests/test_restore_verification.py -v && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_state_store_mongo.py tests/test_restore_recovery_mongo.py -v`
Expected: PASS. `test_a_verified_compensation_marks_both_operations_compensated` still passes: its state is now loaded in `execute`.

- [ ] **Step 9: Lint and type-check**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src && uv run python ../scripts/export-openapi.py --check`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add backend/src/mist_config_guardian_backend/services/restore_compensation.py \
  backend/src/mist_config_guardian_backend/services/restore_write_guard.py \
  backend/src/mist_config_guardian_backend/services/restore_planner.py \
  backend/src/mist_config_guardian_backend/services/restore_outcome.py \
  backend/src/mist_config_guardian_backend/services/restore_executor.py \
  backend/src/mist_config_guardian_backend/services/restore_recovery.py \
  backend/tests/test_restore_compensation.py backend/tests/test_restore_write_guard.py \
  backend/tests/test_restore_outcome.py backend/tests/test_restore_state_store_mongo.py \
  backend/tests/test_restore_recovery_mongo.py backend/tests/test_restore_verification.py
git commit -m "fix(restore): hold compensation to what the restore wrote and let it be retried" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 11: One configuration fingerprint module

**Findings:** S1, M3.

**Existing-module check (done while planning):** `snapshots/canonical.py` holds the generic `canonicalize`/`configuration_hash` primitives but knows nothing of registry definitions, masks or read-back; `services/diff.py:661` uses its own display-only `COMPARISON_IGNORED_FIELDS`; `tasks/hashes.py` deliberately hashes under historical field sets. The new module sits beside `canonical.py` in `snapshots/` and is the only definition-aware entry point; `canonical.py`, `diff.py` and `tasks/hashes.py` keep their roles.

**Files:**
- Create: `backend/src/mist_config_guardian_backend/snapshots/fingerprint.py`
- Modify: `backend/src/mist_config_guardian_backend/services/snapshots.py:259-292`
- Modify: `backend/src/mist_config_guardian_backend/services/restore_baseline.py:138`
- Modify: `backend/src/mist_config_guardian_backend/services/restore_compensation.py` (`build_snapshot_entry`, `_log_preflight_diagnostics`, `assess_live_state`, `_describes`, remove `_MISSING`, `_at_path`, `_without_paths` in favour of the module's)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_write_guard.py`
- Modify: `backend/src/mist_config_guardian_backend/services/restore_executor.py` (`_execute_action` applied hash, `_record_result`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_verification.py:219-286` (`_read_after_write`, `_compare`)
- Create: `backend/tests/test_configuration_fingerprint.py`
- Test: `backend/tests/test_restore_executor_mongo.py`, `backend/tests/test_restore_verification.py`, `backend/tests/test_restore_compensation.py`

**Interfaces:**
- Consumes: `canonicalize`, `configuration_hash`, `configuration_hash_matches` (`snapshots/canonical.py`); `find_unavailable_secrets`, `SecretPath` (`snapshots/secrets.py`); `ObjectDefinition`.
- Produces (`snapshots/fingerprint.py`):
  - `MISSING: object` sentinel.
  - `normalize(definition: ObjectDefinition, configuration: Mapping[str, object]) -> object`
  - `fingerprint(definition: ObjectDefinition, configuration: Mapping[str, object]) -> str`
  - `fingerprint_matches(definition: ObjectDefinition, stored: str | None, configuration: Mapping[str, object]) -> bool`
  - `at_path(value: object, path: SecretPath) -> object` and `without_paths(value: object, paths: frozenset[SecretPath]) -> object` (moved verbatim from `restore_compensation._at_path` / `_without_paths`).
  - `differing_fields(definition, expected: Mapping[str, object], actual: Mapping[str, object], *, fields: Collection[str] | None = None) -> list[str]` — top-level keys (restricted to `fields` when given) whose normalized values differ after dropping ignored fields and every location masked on either side.
  - `equivalent(definition, expected, actual, *, fields=None) -> bool` — `not differing_fields(...)`.
  - `restored_configuration(definition, readback: Mapping[str, object], written: Mapping[str, object]) -> dict[str, object]` — the read-back with each masked secret filled from the value just written.
- Rule for `RESTORED` versions: `configuration_hash = fingerprint(definition, readback)` (exactly what the collector computes for the same response), `configuration = protect_configuration(restored_configuration(definition, readback, written))`, `references = extract_uuid_references(readback)`; `RestoreAction.applied_hash = fingerprint(definition, readback)` — so compensation (Task 10) and history agree.

- [ ] **Step 1: Re-verify the findings**

Run: `cd backend && grep -rn "configuration_hash(\|configuration_hash_matches(\|canonicalize(" src --include='*.py' | grep -v "snapshots/canonical.py"`
Expected: call sites in `services/snapshots.py`, `services/restore_baseline.py`, `services/restore_compensation.py`, `services/restore_write_guard.py`, `services/restore_executor.py` (including one with no `ignored_fields` in `_record_result`), `services/restore_verification.py`, plus `tasks/hashes.py` and `services/diff.py`.

- [ ] **Step 2: Write the failing unit tests**

Create `backend/tests/test_configuration_fingerprint.py`:

```python
"""One normalization for backup, baseline, compensation, executor and verification."""

from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.fingerprint import (
    differing_fields,
    equivalent,
    fingerprint,
    fingerprint_matches,
    normalize,
    restored_configuration,
)
from mist_config_guardian_backend.snapshots.registry import get_definition

WLANS = get_definition("site", "wlans")
MAPS = get_definition("site", "maps")
assert WLANS is not None
assert MAPS is not None


def test_normalize_drops_server_managed_and_read_only_fields() -> None:
    first = {"name": "Floor 1", "url": "https://generated.example/a", "modified_time": 1}
    second = {"name": "Floor 1", "url": "https://generated.example/b", "modified_time": 2}

    assert normalize(MAPS, first) == normalize(MAPS, second)
    assert fingerprint(MAPS, first) == fingerprint(MAPS, second)
    assert fingerprint(MAPS, first) == configuration_hash(first, ignored_fields=MAPS.ignored_fields)


def test_fingerprint_matches_a_digest_the_collector_stored() -> None:
    live = {"id": "wlan-1", "ssid": "Corp", "modified_time": 5}

    assert fingerprint_matches(WLANS, configuration_hash(live, ignored_fields=WLANS.ignored_fields), live)


def test_equivalence_tolerates_a_mask_where_a_secret_was_written() -> None:
    written = {"ssid": "Corp", "psk": "correct-horse"}
    live = {"id": "wlan-1", "ssid": "Corp", "psk": "********", "modified_time": 5}

    assert equivalent(WLANS, written, live, fields=written.keys())


def test_equivalence_still_sees_a_changed_secret_and_names_the_field() -> None:
    written = {"ssid": "Corp", "psk": "correct-horse", "vlan_id": 10}
    live = {"ssid": "Corp", "psk": "battery-staple", "vlan_id": 11}

    assert differing_fields(WLANS, written, live, fields=written.keys()) == ["psk", "vlan_id"]


def test_a_restored_configuration_keeps_the_secret_mist_masked() -> None:
    readback = {"id": "wlan-1", "ssid": "Corp", "auth": {"psk": "********"}}

    restored = restored_configuration(WLANS, readback, {"ssid": "Corp", "auth": {"psk": "correct-horse"}})

    assert restored == {"id": "wlan-1", "ssid": "Corp", "auth": {"psk": "correct-horse"}}
    assert readback["auth"] == {"psk": "********"}
```

In `backend/tests/test_restore_verification.py` add:

```python
async def test_read_after_write_accepts_a_secret_mist_returns_masked() -> None:
    operation = _operation(
        [_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="mist-0")]
    )
    client = _FakeClient({"mist-0": {"name": "wlan-0", "psk": "********", "modified_time": 9}})

    result = await _build_verifier().verify(
        client, _organization(), operation, id_map={}, applied={0: {"name": "wlan-0", "psk": "correct-horse"}}
    )

    assert result.checks[0].status == "ok"
```

- [ ] **Step 3: Write the failing regression test (DB-backed)**

Append to `backend/tests/test_restore_executor_mongo.py`:

```python
async def test_a_restored_version_is_what_the_next_backup_would_record() -> None:
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    definition = get_definition("org", "networks")
    assert definition is not None
    readback = {"id": "new-network", "org_id": "org-1", "name": "Corp", "created_time": 1, "modified_time": 1}

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"name": "Corp"}, readback=readback, site_id=None
    )
    restored = await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("-version").first_or_none()
    created = await SnapshotService(_vault()).capture_configuration(
        logical.organization_id,
        definition,
        {**readback, "modified_time": 99},
        CaptureContext(snapshot_id=None, site_id=None),
    )

    assert restored is not None
    assert restored.event is VersionEvent.RESTORED
    assert created is False
    assert await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).count() == restored.version


async def test_a_site_object_restored_version_matches_its_site_scoped_capture() -> None:
    wlan = await _deleted_object(object_type="wlans", scope="site", mist_id="wlan-old", site_mist_id="site-a")
    operation, action = _operation_for(wlan, resulting_mist_id="wlan-new")
    definition = get_definition("site", "wlans")
    assert definition is not None
    readback = {"id": "wlan-new", "org_id": "org-1", "site_id": "site-a", "ssid": "Corp", "modified_time": 1}

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"ssid": "Corp"}, readback=readback, site_id="site-a"
    )

    assert (
        await SnapshotService(_vault()).capture_configuration(
            wlan.organization_id,
            definition,
            {**readback, "modified_time": 2},
            CaptureContext(snapshot_id=None, site_id="site-a"),
        )
        is False
    )
```

- [ ] **Step 4: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_configuration_fingerprint.py tests/test_restore_verification.py -v -k "fingerprint or normalize or equivalence or restored_configuration or masked" && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_executor_mongo.py -v -k "next_backup or site_scoped"`
Expected: FAIL — `ModuleNotFoundError: ... snapshots.fingerprint`; the masked read-after-write fails; `capture_configuration` returns `True` (the restored hash ignores nothing and was taken over the payload).

- [ ] **Step 5: Implement the module**

Create `snapshots/fingerprint.py`:

```python
"""The one definition-aware normalization every configuration comparison uses.

Backup captures, fresh baselines, safety snapshots, write guards, restored
versions and read-after-write verification all compare the same objects. Each
used to strip fields and treat masks its own way, and every disagreement showed
up as drift that was not there (#28, M3). They now all come through here.
"""

import copy
from collections.abc import Collection, Mapping, Sequence

from mist_config_guardian_backend.snapshots.canonical import (
    canonicalize,
    configuration_hash,
    configuration_hash_matches,
)
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition
from mist_config_guardian_backend.snapshots.secrets import SecretPath, find_unavailable_secrets

MISSING = object()


def normalize(definition: ObjectDefinition, configuration: Mapping[str, object]) -> object:
    """The canonical structure of a configuration under its registry field policy."""
    return canonicalize(configuration, ignored_fields=definition.ignored_fields)


def fingerprint(definition: ObjectDefinition, configuration: Mapping[str, object]) -> str:
    """The keyed digest the collector stores for this configuration."""
    return configuration_hash(configuration, ignored_fields=definition.ignored_fields)


def fingerprint_matches(definition: ObjectDefinition, stored: str | None, configuration: Mapping[str, object]) -> bool:
    """Whether a stored digest of either generation describes this configuration."""
    return configuration_hash_matches(stored, configuration, ignored_fields=definition.ignored_fields)


def at_path(value: object, path: SecretPath) -> object:
    """Read one location reported by ``find_unavailable_secrets``; ``MISSING`` when absent."""
    for step in path:
        if isinstance(step, str) and isinstance(value, Mapping):
            if step not in value:
                return MISSING
            value = value[step]
        elif isinstance(step, int) and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            if not -len(value) <= step < len(value):
                return MISSING
            value = value[step]
        else:
            return MISSING
    return value


def without_paths(value: object, paths: frozenset[SecretPath], *, path: SecretPath = ()) -> object:
    """Drop exactly those locations, leaving same-named fields elsewhere."""
    if isinstance(value, Mapping):
        kept: dict[str, object] = {}
        for key, child in value.items():
            child_path = (*path, str(key))
            if child_path in paths:
                continue
            kept[str(key)] = without_paths(child, paths, path=child_path)
        return kept
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [without_paths(child, paths, path=(*path, index)) for index, child in enumerate(value)]
    return value


def differing_fields(
    definition: ObjectDefinition,
    expected: Mapping[str, object],
    actual: Mapping[str, object],
    *,
    fields: Collection[str] | None = None,
) -> list[str]:
    """Top-level fields whose values differ, ignoring server fields and masked secrets."""
    masked = frozenset(
        find_unavailable_secrets(dict(expected), definition.sensitive_fields)
        | find_unavailable_secrets(dict(actual), definition.sensitive_fields)
    )
    left = without_paths(expected, masked)
    right = without_paths(actual, masked)
    assert isinstance(left, dict)
    assert isinstance(right, dict)
    keys = sorted(set(expected) | set(actual)) if fields is None else sorted(fields)
    ignored = definition.ignored_fields
    return [
        key
        for key in keys
        if key not in ignored
        and canonicalize(left.get(key, MISSING), ignored_fields=ignored)
        != canonicalize(right.get(key, MISSING), ignored_fields=ignored)
    ]


def equivalent(
    definition: ObjectDefinition,
    expected: Mapping[str, object],
    actual: Mapping[str, object],
    *,
    fields: Collection[str] | None = None,
) -> bool:
    """Whether two configurations agree under the registry policy and mask tolerance."""
    return not differing_fields(definition, expected, actual, fields=fields)


def restored_configuration(
    definition: ObjectDefinition,
    readback: Mapping[str, object],
    written: Mapping[str, object],
) -> dict[str, object]:
    """What Mist now holds, with each secret it masked filled from the value just written.

    The digest is taken over the read-back as returned, masks included, because
    that is what the next capture of the same object will hash. The stored
    configuration keeps the real secret, so the restored version stays replayable.
    """
    restored = copy.deepcopy(dict(readback))
    for path in find_unavailable_secrets(restored, definition.sensitive_fields):
        value = at_path(written, path)
        if isinstance(value, str) and value and set(value) != {"*"}:
            _assign(restored, path, value)
    return restored


def _assign(container: object, path: SecretPath, value: object) -> None:
    for step in path[:-1]:
        container = container[step]  # type: ignore[index]
    container[path[-1]] = value  # type: ignore[index]
```

Verify while implementing: `canonicalize(MISSING)` returns the sentinel itself, so a key present on one side only differs. If `ty` rejects the `type: ignore` comments, replace `_assign` with explicit `isinstance(container, dict)` / `list` narrowing.

- [ ] **Step 6: Replace every call site**

- `services/snapshots.py`: `canonical_hash = fingerprint(definition, configuration)`; `if latest is not None and fingerprint_matches(definition, latest.configuration_hash, configuration):`; the policy-upgrade comparison becomes `if normalize(definition, previous_configuration) == normalize(definition, configuration):`. Drop the now-unused `canonical` imports.
- `services/restore_baseline.py:138`: `configuration_hash=fingerprint(definition, current),`.
- `services/restore_compensation.py`:
  - `build_snapshot_entry`: `configuration_hash=None if current is None else fingerprint(definition, current)`.
  - `_log_preflight_diagnostics`: when `definition is not None`, `before = normalize(definition, stored)`, `after = normalize(definition, current)` and both `configuration_hash_matches(...)` calls become `fingerprint_matches(definition, action.expected_current_hash, ...)`; keep the `definition is None` fallback (`canonicalize` with `frozenset()`) inside this diagnostic only.
  - `assess_live_state`: resolve `definition` once (raise `RestoreDriftError(f"Unsupported restore type: {action.scope}:{action.object_type}")` when `None`); use `fingerprint_matches(definition, action.expected_current_hash, current)` and `equivalent(definition, reveal_configuration(action.protected_configuration, vault), current)` for the already-reversed test.
  - `_describes`: `return normalize(definition, without_paths(live, masked)) == normalize(definition, without_paths(plaintext, masked))` (the arguments are dicts; add `cast("dict[str, object]", ...)` if `ty` requires); replace `_at_path` with `at_path` and `_MISSING` with `MISSING` in `_usable_secret`; delete the local `_MISSING`, `_at_path`, `_without_paths` (keep `_switch_management_differences`, which uses its own local sentinel — rename its uses to `MISSING`).
- `services/restore_write_guard.py`: `fingerprint_matches(definition, entry.configuration_hash, live)`.
- `services/restore_executor.py` `_execute_action`: `action.applied_hash = None if readback is None else fingerprint(definition, readback)`. In `_record_result`, replace the configuration block and `build`:

```python
        if not deleted and readback is None:
            msg = f"{action.object_name} has no read-back to record"
            raise MistMutationError(msg)
        recorded = {} if readback is None else restored_configuration(definition, readback, written)

        def build(latest: ObjectVersion) -> ObjectVersion:
            return ObjectVersion(
                organization_id=operation.organization_id,
                logical_object_id=logical_id,
                incarnation_id=incarnation_id,
                version=latest.version + 1,
                event=VersionEvent.RESTORED,
                configuration=(
                    latest.configuration
                    if deleted
                    else protect_configuration(recorded, self._vault, sensitive_fields=definition.sensitive_fields)
                ),
                configuration_hash=latest.configuration_hash if deleted or readback is None else fingerprint(definition, readback),
                changed_fields=[],
                references=latest.references if deleted or readback is None else extract_uuid_references(readback),
                is_deleted=deleted,
                actor=operation.credential_actor,
            )
```

  (the `restored_configuration["id"] = object_id` special case is gone — the read-back carries whatever id Mist returns, exactly as a capture would.)
- `services/restore_verification.py`: in `_read_after_write` call `self._compare(definition, action.object_name, action.action, current, applied.get(action.order))`; rewrite `_compare`:

```python
    @staticmethod
    def _compare(
        definition: ObjectDefinition,
        object_name: str,
        action_type: RestoreActionType,
        current: dict[str, object] | None,
        expected: dict[str, object] | None,
    ) -> VerificationCheck:
        label = f"Read-after-write: {object_name}"
        if action_type is RestoreActionType.DELETE:
            return VerificationCheck(
                label=label,
                status="ok" if current is None else "failed",
                detail=("Deleted object is gone" if current is None else "The object still exists in Mist"),
            )
        if current is None:
            return VerificationCheck(label=label, status="failed", detail="The object was not found after the write")
        if expected is None:
            return VerificationCheck(label=label, status="skipped", detail="No submitted payload was recorded")
        # Mist echoes server-managed fields the plan never sent and masks some
        # secrets it stores, so only the written fields are compared, under the
        # same policy the collector hashes with.
        differing = differing_fields(definition, expected, current, fields=expected.keys())
        if not differing:
            return VerificationCheck(label=label, status="ok", detail=f"{len(expected)} written fields match")
        listed = ", ".join(differing[:_MAX_REPORTED_FIELDS])
        if len(differing) > _MAX_REPORTED_FIELDS:
            listed = f"{listed}, +{len(differing) - _MAX_REPORTED_FIELDS} more"
        return VerificationCheck(label=label, status="failed", detail=f"Mist stored different values for {listed}")
```

- [ ] **Step 7: Confirm no stray normalization remains**

Run: `cd backend && grep -rn "configuration_hash(\|configuration_hash_matches(\|canonicalize(" src --include='*.py' | grep -v "snapshots/canonical.py\|snapshots/fingerprint.py\|tasks/hashes.py\|services/diff.py\|_log_preflight_diagnostics"`
Expected: no output (the diagnostic's `definition is None` fallback is the only allowed direct use; if grep shows it on a separate line, confirm by reading it).

- [ ] **Step 8: Run the tests**

Run: `cd backend && uv run pytest tests/test_configuration_fingerprint.py tests/test_restore_verification.py tests/test_restore_compensation.py tests/test_restore_write_guard.py tests/test_restore_baseline.py tests/test_snapshot_canonical.py tests/test_snapshot_secrets.py tests/test_configuration_hash_backfill.py -v && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_executor_mongo.py -v`
Expected: PASS. In `test_a_recreated_object_keeps_the_identity_the_collector_looks_for` (Task 6) the capture now records no new version; its assertions still hold.

- [ ] **Step 9: Lint, type-check, full suite**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src && uv run pytest -q && uv run python ../scripts/export-openapi.py --check`
Expected: clean; PASS.

- [ ] **Step 10: Commit**

```bash
git add backend/src/mist_config_guardian_backend/snapshots/fingerprint.py \
  backend/src/mist_config_guardian_backend/services/snapshots.py \
  backend/src/mist_config_guardian_backend/services/restore_baseline.py \
  backend/src/mist_config_guardian_backend/services/restore_compensation.py \
  backend/src/mist_config_guardian_backend/services/restore_write_guard.py \
  backend/src/mist_config_guardian_backend/services/restore_executor.py \
  backend/src/mist_config_guardian_backend/services/restore_verification.py \
  backend/tests/test_configuration_fingerprint.py backend/tests/test_restore_executor_mongo.py \
  backend/tests/test_restore_verification.py backend/tests/test_restore_compensation.py
git commit -m "fix(restore): hash and compare configurations through one fingerprint module" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 12: Prepared-only execution and superseded drafts

**Findings:** M4.

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/models/restore.py` (`RestoreStatus.SUPERSEDED`, `RestoreOperation.superseded_by`)
- Modify: `backend/src/mist_config_guardian_backend/schemas/restore.py:35-60` (`RestoreExecuteRequest`), `:104-165` (`RestoreOperationResponse.superseded_by`)
- Modify: `backend/src/mist_config_guardian_backend/services/restore_authorization.py:43-153` (`authorize`, `_execution_credential`), `:167-221` (`prepare`), new `supersede`
- Modify: `backend/src/mist_config_guardian_backend/api/routes/restores.py:198-223` (`execute_restore`), `:289-327` (`execute_compensation_plan`), `:384-422` (`_authorize_and_queue`)
- Modify: `frontend/src/app/features/restore/restore.service.ts:56-72`
- Modify: `frontend/src/app/features/restore/restore.model.ts:8-15, 75-99`
- Modify: `frontend/src/app/features/restore/restore-page.ts:1133-1174` (`openOperation`)
- Test: `backend/tests/test_restore_compensation.py`, `backend/tests/test_restore_baseline.py`, `backend/tests/test_restore_credential_cleanup.py`, `backend/tests/test_mist_login.py:119-129`, `frontend/src/app/features/restore/restore-page.spec.ts:614-660`
- Regenerate: `docs/openapi.json`

**Interfaces:**
- Consumes: `RestoreAuthorizationService.logout_unused_credential` (Task 4); `RestoreConcurrencyError` mapping (Task 9).
- Produces:
  - `POST /organizations/{id}/restores/{op}/execute` takes **no body**, requires `baseline_snapshot_id`, answers 409 `"Prepare a fresh backup of this plan before executing it"` otherwise, and uses the retained session of the administrator who prepared it.
  - `RestoreExecuteRequest` accepts exactly one of `administrator_token`, `mist_login` (the `use_prepared_credential` option is removed); `credential() -> str | MistLoginCredentials`.
  - `RestoreAuthorizationService.authorize(organization_id, operation_id, credential: str | MistLoginCredentials | None, task_id: str, *, compensation: bool = False)` — ordinary plans require `credential is None` and a live prepared session; compensation requires a fresh credential.
  - `RestoreStatus.SUPERSEDED = "superseded"`; `RestoreOperation.superseded_by: PydanticObjectId | None = None`; `RestoreOperationResponse.superseded_by: str | None = None`.
  - `RestoreAuthorizationService.supersede(operation_id: PydanticObjectId, replacement_id: PydanticObjectId) -> bool` — atomically moves a never-started `PLANNED`/`FAILED` plan to `SUPERSEDED`, clears and revokes any session it retained.
  - `_authorize_and_queue(organization_id, operation, authorization, approvals, credential, *, compensation: bool = False)`.
  - Frontend: `RestoreService.execute` deleted (dead: only `executePrepared` and `executeCompensation` are called, `restore-page.ts:802, 1044`); `executePrepared` posts `{}`; `RestoreStatus` gains `'superseded'`; `RestoreOperation.superseded_by?: string | null`; opening a superseded plan opens its replacement.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && sed -n 132,141p src/mist_config_guardian_backend/services/restore_authorization.py && grep -n "execute(" ../frontend/src/app/features/restore/restore.service.ts ../frontend/src/app/features/restore/restore-page.ts`
Expected: a pasted credential is accepted whenever `baseline_snapshot_id` is `None`; the frontend's `execute(` client method has no caller.

- [ ] **Step 2: Write the failing backend tests**

In `backend/tests/test_restore_compensation.py`:

1. `_RecordingAuthorization` records the flag:

```python
class _RecordingAuthorization:
    """Captures the delegated credential the route hands to authorization."""

    def __init__(self) -> None:
        self.credentials: list[str | None] = []
        self.operations: list[PydanticObjectId] = []
        self.compensation: list[bool] = []

    async def authorize(self, organization_id, operation_id, credential, task_id, *, compensation=False):  # noqa: ARG002
        self.credentials.append(credential)
        self.operations.append(operation_id)
        self.compensation.append(compensation)
        return _operation([], status=RestoreStatus.QUEUED, identifier=operation_id)

    async def release(self, operation_id, task_id) -> None:  # noqa: ARG002
        return
```

2. `_app` takes the plans and a shared state store:

```python
def _app(
    compensation: _StubCompensation,
    authorization: _RecordingAuthorization,
    *,
    plans: list[RestoreOperation] | None = None,
    states: _MemoryStateStore | None = None,
):
    from mist_config_guardian_backend.api.dependencies import (  # noqa: PLC0415
        get_restore_authorization_service,
    )

    shared_states = states or _MemoryStateStore()
    listed = plans if plans is not None else [
        _operation([_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED)])
    ]
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _administrator
    app.dependency_overrides[require_organization] = _organization
    app.dependency_overrides[get_restore_compensation_service] = lambda: compensation
    app.dependency_overrides[get_restore_authorization_service] = lambda: authorization
    app.dependency_overrides[get_plan_state_store] = lambda: shared_states
    app.dependency_overrides[get_restore_plans] = lambda: _MemoryPlans(listed)
    app.dependency_overrides[get_approval_service] = lambda: ApprovalService(_NoApprovals())
    return app


async def _reviewed(states: _MemoryStateStore, plan: RestoreOperation) -> _MemoryStateStore:
    """Record the plan hash a reviewer saw, as planning does."""
    assert plan.id is not None
    await states.save(
        RestoreOperationState(
            organization_id=ORGANIZATION_ID, operation_id=plan.id, plan_hash=compute_plan_hash(plan.actions)
        )
    )
    return states
```

3. Add:

```python
async def test_a_plan_without_a_fresh_backup_cannot_be_executed(routed: list[str]) -> None:
    draft = _operation([_action(0, RestoreActionType.UPDATE)], status=RestoreStatus.PLANNED)
    authorization = _RecordingAuthorization()
    app = _app(_StubCompensation(None), authorization, plans=[draft], states=await _reviewed(_MemoryStateStore(), draft))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/execute", json={})

    assert response.status_code == 409
    assert "Prepare a fresh backup" in response.json()["detail"]
    assert authorization.operations == []
    assert routed == []


async def test_a_prepared_plan_is_queued_with_its_retained_session(routed: list[str]) -> None:
    prepared = _operation([_action(0, RestoreActionType.UPDATE)], status=RestoreStatus.PLANNED)
    prepared.baseline_snapshot_id = PydanticObjectId()
    authorization = _RecordingAuthorization()
    app = _app(
        _StubCompensation(None), authorization, plans=[prepared], states=await _reviewed(_MemoryStateStore(), prepared)
    )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/execute", json={})

    assert response.status_code == 202
    assert authorization.credentials == [None]
    assert authorization.compensation == [False]
    assert len(routed) == 1


@pytest.mark.usefixtures("routed")
async def test_compensation_still_requires_a_fresh_credential() -> None:
    plan = _operation([], status=RestoreStatus.PLANNED, identifier=COMPENSATION_ID)
    authorization = _RecordingAuthorization()
    app = _app(_StubCompensation(plan), authorization)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/compensation/execute",
            json={"use_prepared_credential": True},
        )

    assert response.status_code == 422
    assert authorization.credentials == []
```

and in `test_compensation_execution_uses_the_delegated_administrator_credential` add `assert authorization.compensation == [True]`.

In `backend/tests/test_restore_baseline.py` (fixture operation already has a `baseline_snapshot_id`):

```python
async def test_a_pasted_credential_cannot_execute_an_ordinary_plan(authorization):
    service, operation, query, mist = authorization

    with pytest.raises(RestoreAuthorizationError, match="Prepare a fresh backup"):
        await service.authorize(operation.organization_id, operation.id, "pasted-token", "task")

    query.update.assert_not_awaited()
    mist.verify_write_token.assert_not_awaited()


async def test_a_compensation_plan_is_authorized_with_a_fresh_credential(authorization):
    service, operation, _query, mist = authorization
    operation.baseline_snapshot_id = None

    await service.authorize(operation.organization_id, operation.id, "fresh-token", "task", compensation=True)

    assert mist.verify_write_token.call_args.kwargs["token"] == "fresh-token"


async def test_a_superseded_draft_cannot_be_prepared_again():
    service = RestoreAuthorizationService(
        Settings(environment="test"), CredentialVault(Settings(environment="test")), AsyncMock(),
        active_restores=AsyncMock(return_value=False),
    )
    draft = RestoreOperation.model_construct(id=PydanticObjectId(), status=RestoreStatus.SUPERSEDED)

    with pytest.raises(RestoreAuthorizationError, match="replaced by a newer prepared plan"):
        await service.prepare(SimpleNamespace(), draft, PydanticObjectId(), "token", AsyncMock())
```

In `backend/tests/test_restore_credential_cleanup.py`:

```python
async def test_a_prepared_plan_retires_the_draft_it_replaced(cleanup, httpx_mock):
    service, vault, collection = cleanup
    draft = queued(vault, status=RestoreStatus.PLANNED, expired=False)
    collection.documents.append(draft)
    httpx_mock.add_response(url=BASE + "/api/v1/logout", status_code=200)
    replacement = PydanticObjectId()

    assert await service.supersede(draft["_id"], replacement) is True
    assert draft["status"] == RestoreStatus.SUPERSEDED
    assert draft["superseded_by"] == replacement
    assert draft["encrypted_delegated_credential"] is None
    assert len(httpx_mock.get_requests()) == 1
    assert await service.supersede(draft["_id"], PydanticObjectId()) is False
```

In `backend/tests/test_mist_login.py`, add `{"use_prepared_credential": True}` to the `test_restore_rejects_ambiguous_or_internal_credentials` parameter list.

- [ ] **Step 3: Write the failing frontend tests**

In `frontend/src/app/features/restore/restore-page.spec.ts`, change the prepared-execution assertion at line 651 to `expect(execution.request.body).toEqual({});` and append:

```ts
  it('opens the prepared plan in place of the draft it superseded', async () => {
    await boot(targetList([NW_CORP]), [operation({ id: 'op-1', status: 'superseded', superseded_by: 'op-2' })]);

    all('.entry')[0].click();
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(operation({ id: 'op-1', status: 'superseded', superseded_by: 'op-2' }));
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-2`).flush(
      operation({ id: 'op-2', baseline_snapshot_id: 'backup-1', prepared_until: new Date(Date.now() + 60_000).toISOString() }),
    );
    await settle();

    expect(button('Execute reviewed plan')).toBeTruthy();
    expect(JSON.stringify(navigations.at(-1))).toContain('"operation":"op-2"');
  });
```

- [ ] **Step 4: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_restore_compensation.py tests/test_restore_baseline.py tests/test_restore_credential_cleanup.py tests/test_mist_login.py -v`
Expected: FAIL — the draft is queued (202), `compensation` is not accepted, `supersede` and `SUPERSEDED` do not exist, `use_prepared_credential` is still valid.

Run: `cd frontend && npm test -- --watch=false`
Expected: FAIL — body `{ use_prepared_credential: true }` and the superseded plan is shown instead of its replacement.

- [ ] **Step 5: Implement the backend**

`models/restore.py`: add `SUPERSEDED = "superseded"` to `RestoreStatus` (comment: a plan replaced by the prepared plan built from its fresh backup; never executed); add `superseded_by: PydanticObjectId | None = None` to `RestoreOperation` after `baseline_snapshot_id`.

`schemas/restore.py`:

```python
class RestoreExecuteRequest(BaseModel):
    """Fresh delegated Mist administrator credential."""

    administrator_token: SecretStr | None = Field(default=None, min_length=1, max_length=2048)
    mist_login: MistLoginCredentials | None = None

    @model_validator(mode="after")
    def exactly_one_credential(self) -> Self:
        if (self.administrator_token is None) == (self.mist_login is None):
            msg = "Supply exactly one of administrator_token or mist_login"
            raise ValueError(msg)
        if self.administrator_token and self.administrator_token.get_secret_value().startswith("mist-session:"):
            msg = "Supply an API token, not an encoded session"
            raise ValueError(msg)
        return self

    def credential(self) -> str | MistLoginCredentials:
        if self.administrator_token is not None:
            return self.administrator_token.get_secret_value()
        if self.mist_login is None:
            msg = "Mist login is missing"
            raise ValueError(msg)
        return self.mist_login
```

and add `superseded_by: str | None = None` to `RestoreOperationResponse` with `superseded_by=None if operation.superseded_by is None else str(operation.superseded_by),` in `from_document`.

`services/restore_authorization.py`:
- `authorize(..., task_id: str, *, compensation: bool = False)`: replace `using_prepared = credential is None` / `credential = self._execution_credential(operation, credential)` with `using_prepared = not compensation` / `credential = self._execution_credential(operation, credential, compensation=compensation)`.
- Replace `_execution_credential`:

```python
    def _execution_credential(
        self,
        operation: RestoreOperation,
        credential: str | MistLoginCredentials | None,
        *,
        compensation: bool,
    ) -> str | MistLoginCredentials:
        if compensation:
            if credential is None:
                msg = "Compensation needs a fresh administrator credential"
                raise RestoreAuthorizationError(msg)
            return credential
        if credential is not None:
            msg = "Prepare a fresh backup of this plan and execute it with the session that backup retained"
            raise RestoreAuthorizationError(msg)
        if (
            operation.baseline_snapshot_id is None
            or operation.encrypted_delegated_credential is None
            or operation.delegated_credential_expires_at is None
            or operation.delegated_credential_expires_at <= utc_now()
        ):
            msg = "The prepared session expired; capture a fresh backup and review a new plan"
            raise RestoreAuthorizationError(msg)
        return self._vault.decrypt_for_context(
            operation.encrypted_delegated_credential,
            context=f"restore:{operation.id}",
        )
```

- In `prepare`, before the existing status check:

```python
        if operation.status is RestoreStatus.SUPERSEDED:
            msg = "This plan was replaced by a newer prepared plan; open that plan instead"
            raise RestoreAuthorizationError(msg)
```

  and right after `if plan.id is None: ...`: `if operation.id is not None: await self.supersede(operation.id, plan.id)`.
- Add:

```python
    async def supersede(self, operation_id: PydanticObjectId, replacement_id: PydanticObjectId) -> bool:
        """Retire a never-executed plan once the prepared plan built from it exists.

        The draft could otherwise still be authorized, and a prepared plan it
        replaces could still hold a live session; both end here, atomically.
        """
        before = await RestoreOperation.get_pymongo_collection().find_one_and_update(
            {
                "_id": operation_id,
                "status": {"$in": [RestoreStatus.PLANNED, RestoreStatus.FAILED]},
                "started_at": None,
            },
            {
                "$set": {
                    "status": RestoreStatus.SUPERSEDED,
                    "superseded_by": replacement_id,
                    "encrypted_delegated_credential": None,
                    "delegated_credential_expires_at": None,
                    "updated_at": utc_now(),
                }
            },
            return_document=ReturnDocument.BEFORE,
            projection={"encrypted_delegated_credential": 1, "organization_id": 1},
        )
        if before is None:
            return False
        await self.logout_unused_credential(before)
        return True
```

`api/routes/restores.py`:

```python
@router.post("/{operation_id}/execute", status_code=status.HTTP_202_ACCEPTED)
async def execute_restore(  # noqa: PLR0913, PLR0917 - one dependency per collaborating service
    organization_id: PydanticObjectId,
    operation_id: PydanticObjectId,
    organization: Annotated[Organization, Depends(require_organization)],
    plans: Annotated[RestorePlanRepository, Depends(get_restore_plans)],
    authorization: Annotated[RestoreAuthorizationService, Depends(get_restore_authorization_service)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    store: Annotated[RestoreStateStore, Depends(get_plan_state_store)],
    administrator: Annotated[User, Depends(require_administrator)],
    _stepped_up: Annotated[User, Depends(require_fresh_mfa)],
) -> RestoreOperationResponse:
    """Queue a prepared plan with the administrator session its fresh backup retained."""
    operation = await _load(plans, organization_id, operation_id)
    if operation.baseline_snapshot_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Prepare a fresh backup of this plan before executing it",
        )
    if operation.requested_by != administrator.id:
        raise HTTPException(status_code=403, detail="Only the administrator who prepared this plan can use its session")
    await _assert_plan_current(store, operation)
    await _assert_approved(organization, operation, approvals)
    return await _authorize_and_queue(organization_id, operation, authorization, approvals, None)
```

`_authorize_and_queue` gains `*, compensation: bool = False` and calls `authorization.authorize(organization_id, operation.id, credential, task_id, compensation=compensation)`; `execute_compensation_plan` passes `request.credential(), compensation=True`.

- [ ] **Step 6: Implement the frontend**

`restore.model.ts`: add `| 'superseded'` to `RestoreStatus`; add `superseded_by?: string | null;` to `RestoreOperation`.

`restore.service.ts`: delete `execute(...)`; replace `executePrepared` with:

```ts
  /** Queue a prepared plan with the administrator session its fresh backup retained. */
  executePrepared(organizationId: string, operationId: string): Promise<RestoreOperation> {
    return firstValueFrom(
      this.http.post<RestoreOperation>(orgPath(organizationId, `/restores/${operationId}/execute`), {}),
    );
  }
```

`restore-page.ts` `openOperation`, directly after `if (!operation || this.stale(token)) { return false; }`:

```ts
    if (operation.status === 'superseded' && operation.superseded_by) {
      // A draft that was prepared has nothing left to review; its replacement does.
      this.canonicalize(organizationId, operation.superseded_by, true);
      return this.openOperation(operation.superseded_by, compensate);
    }
```

- [ ] **Step 7: Run the tests**

Run: `cd backend && uv run pytest tests/test_restore_compensation.py tests/test_restore_baseline.py tests/test_restore_credential_cleanup.py tests/test_mist_login.py tests/test_approvals.py tests/test_historical_writes.py -v`
Expected: PASS.

Run: `make openapi && cd backend && uv run python ../scripts/export-openapi.py --check`, then `cd frontend && npm test -- --watch=false && npm run build`
Expected: PASS; `docs/openapi.json` loses the execute request body and `use_prepared_credential`, gains `superseded` and `superseded_by`.

- [ ] **Step 8: Lint and type-check**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src`
Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add backend/src/mist_config_guardian_backend/models/restore.py backend/src/mist_config_guardian_backend/schemas/restore.py \
  backend/src/mist_config_guardian_backend/services/restore_authorization.py \
  backend/src/mist_config_guardian_backend/api/routes/restores.py \
  backend/tests/test_restore_compensation.py backend/tests/test_restore_baseline.py \
  backend/tests/test_restore_credential_cleanup.py backend/tests/test_mist_login.py docs/openapi.json \
  frontend/src/app/features/restore/restore.service.ts frontend/src/app/features/restore/restore.model.ts \
  frontend/src/app/features/restore/restore-page.ts frontend/src/app/features/restore/restore-page.spec.ts
git commit -m "fix(restore): execute only prepared plans and retire the drafts they replace" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 13: Approvals bound to plan intent and carried across prepare

**Findings:** M5.

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/models/approval.py:51-68` (`RestoreApproval.intent_hash`, `action_signature`)
- Modify: `backend/src/mist_config_guardian_backend/services/approvals.py:51-70` (`compute_plan_hash`), new `payload_digest`, `compute_intent_hash`, `compute_action_signature`, `ApprovalDraft`, `BeanieApprovalStore.insert`, `ApprovalService.request`, `_reopen`, new `carry_to_prepared`
- Modify: `backend/src/mist_config_guardian_backend/services/restore_planner.py:279-292` (`assert_plan_current`)
- Modify: `backend/src/mist_config_guardian_backend/api/routes/restores.py` (`prepare_restore`, `_operation_response` and every caller)
- Modify: `backend/src/mist_config_guardian_backend/schemas/restore.py` (`RestoreOperationResponse.approval_required`)
- Modify: `frontend/src/app/features/restore/restore.model.ts` (`approval_required`, `blocksExecution`)
- Modify: `frontend/src/app/features/restore/restore-page.ts:294-295`, `restore-page.html:109-123`
- Modify: `frontend/src/app/features/restore/restore-step-authorize.ts`, `restore-step-authorize.html`
- Test: `backend/tests/test_approvals.py`, `backend/tests/test_restore_compensation.py`, `frontend/src/app/features/restore/restore-page.spec.ts`
- Regenerate: `docs/openapi.json`

**Interfaces:**
- Consumes: `RestoreActionReason` (Task 7); prepare route and superseding (Task 12); `_reviewed` test helper (Task 12).
- Produces:
  - `payload_digest(configuration: Mapping[str, object]) -> str` — SHA-256 of the canonical JSON with each protected value replaced by its `$fingerprint` (ciphertext is re-encrypted with a fresh nonce on every planning; the fingerprint is `CredentialVault.fingerprint`, a keyed deterministic HMAC, `security/credentials.py:31-39`).
  - `compute_plan_hash(actions)` now covers `order, logical_object_id, action, source_version_id, expected_current_hash, current_mist_id, site_mist_id, reason, payload_digest(protected_configuration)`. **Consequence:** plans and approvals created before this task no longer hash as reviewed and must be re-planned (fail closed; nothing is migrated).
  - `compute_intent_hash(operation: RestoreOperation) -> str` over `organization_id`, sorted `requested_version_ids`, `mode`, `target_at` (UTC ISO), `requested_by`.
  - `compute_action_signature(actions: Sequence[RestoreAction]) -> str` over sorted `(logical_object_id, action, target, reason)` where `target` is `source_version_id`, or `""` for a `REFERENCE_REWRITE` action (its source is whatever the fresh backup just captured, so it always moves).
  - `RestoreApproval.intent_hash: str | None = None`, `RestoreApproval.action_signature: str | None = None`; `ApprovalDraft.intent_hash: str`, `ApprovalDraft.action_signature: str`.
  - `CarryOutcome = Literal["carried", "not_carried", "no_approval"]`; `ApprovalService.carry_to_prepared(source: RestoreOperation, prepared: RestoreOperation) -> CarryOutcome` — a `PENDING` or `APPROVED` approval moves to the prepared plan (its `restore_operation_id`, `plan_hash`, summary and counts are updated; its decision and expiry are kept) iff intent hash and action signature match.
  - `APPROVAL_NOT_CARRIED: str` warning appended to a prepared plan whose draft approval did not carry.
  - `assert_plan_current` raises `RestorePlanningError("This restore plan has no reviewed plan record; create a new plan")` when no state record exists.
  - `RestoreOperationResponse.approval_required: bool = False` (policy evaluated per response); `_operation_response(operation, approvals, organization, *, compensation_available=None)`.
  - Frontend: `RestoreOperation.approval_required?: boolean`; `blocksExecution(approval, required = false)`; authorize step input `approvalRequired`.

- [ ] **Step 1: Re-verify the finding**

Run: `cd backend && sed -n 59,67p src/mist_config_guardian_backend/services/approvals.py && sed -n 288,291p src/mist_config_guardian_backend/services/restore_planner.py && grep -n "delegated_credential_ttl_minutes" src/mist_config_guardian_backend/config.py`
Expected: the hash omits target ids and payload; `state is not None and ...` lets a missing record pass; a 15-minute prepared session.

- [ ] **Step 2: Write the failing backend tests**

In `backend/tests/test_approvals.py`:

1. Imports: add `RestoreActionReason`, `RestorePlanningError`, `assert_plan_current`, `payload_digest`, `CredentialVault`, `protect_configuration` (`snapshots.secrets`), `get_restore_authorization_service` (`api.dependencies`), `get_plan_state_store`, `get_restore_plans` (`api.routes.restores`).
2. `_action` gains `reason: RestoreActionReason = RestoreActionReason.RESTORE` and passes `reason=reason`.
3. `_operation` gains `identifier: PydanticObjectId = OPERATION_ID` and `requested_version_ids: list[PydanticObjectId] | None = None`, passing `id=identifier` and `requested_version_ids=requested_version_ids or []`.
4. `_MemoryApprovalStore.insert` passes `intent_hash=draft.intent_hash, action_signature=draft.action_signature` into `model_construct`.
5. Extend the `test_any_plan_change_changes_the_hash` parameter list:

```python
        lambda action: setattr(action, "current_mist_id", "mist-other"),
        lambda action: setattr(action, "site_mist_id", "site-other"),
        lambda action: setattr(action, "protected_configuration", {"ssid": "Guest"}),
        lambda action: setattr(action, "reason", RestoreActionReason.REFERENCE_REWRITE),
```

6. Add:

```python
PREPARED_ID = PydanticObjectId()


def _prepared_from(draft: RestoreOperation, actions: list[RestoreAction] | None = None, **changes) -> RestoreOperation:
    """The plan a fresh backup produces: new id, new baseline hashes, same intent."""
    prepared = draft.model_copy(update={"id": PREPARED_ID, "baseline_snapshot_id": PydanticObjectId(), **changes})
    prepared.actions = (
        actions
        if actions is not None
        else [action.model_copy(update={"expected_current_hash": "fresh-backup-hash"}) for action in draft.actions]
    )
    return prepared


async def _approved_draft(policy: ApprovalPolicy, actions: list[RestoreAction]):
    version = PydanticObjectId()
    draft = _operation(actions, requested_version_ids=[version])
    service, store, _ = _service(draft)
    approval = await service.request(_organization(policy), draft, _requester())
    assert approval.id is not None
    await service.decide(ORGANIZATION_ID, approval.id, _approver(), approved=True)
    return draft, service, store, approval


def test_payload_digest_is_blind_to_encryption_nonces_but_not_to_secrets() -> None:
    vault = CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))
    sensitive = frozenset({"psk"})
    first = protect_configuration({"ssid": "Corp", "psk": "correct-horse"}, vault, sensitive_fields=sensitive)
    second = protect_configuration({"ssid": "Corp", "psk": "correct-horse"}, vault, sensitive_fields=sensitive)
    other = protect_configuration({"ssid": "Corp", "psk": "battery-staple"}, vault, sensitive_fields=sensitive)

    assert first != second
    assert payload_digest(first) == payload_digest(second)
    assert payload_digest(first) != payload_digest(other)


async def test_an_approval_carries_to_the_prepared_plan_of_the_same_intent() -> None:
    policy = ApprovalPolicy(enabled=True)
    draft, service, store, approval = await _approved_draft(policy, [_action(scope="org")])
    prepared = _prepared_from(draft)
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "carried"
    assert approval.restore_operation_id == PREPARED_ID
    assert await service.assert_execution_allowed(_organization(policy), prepared) is approval


async def test_an_approval_does_not_carry_when_the_backup_changes_the_actions() -> None:
    policy = ApprovalPolicy(enabled=True)
    draft, service, store, approval = await _approved_draft(policy, [_action(scope="org")])
    prepared = _prepared_from(draft, actions=[*draft.actions, _action(order=1, action=RestoreActionType.DELETE)])
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "not_carried"
    assert approval.restore_operation_id == OPERATION_ID
    with pytest.raises(ApprovalRequiredError):
        await service.assert_execution_allowed(_organization(policy), prepared)


async def test_an_approval_does_not_carry_to_a_plan_in_another_mode() -> None:
    draft, service, store, _approval = await _approved_draft(ApprovalPolicy(enabled=True), [_action(scope="org")])
    prepared = _prepared_from(draft, mode=RestoreMode.EXACT)
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "not_carried"


async def test_a_reference_rewrite_whose_source_moved_still_carries() -> None:
    rewrite = _action(scope="org", reason=RestoreActionReason.REFERENCE_REWRITE)
    draft, service, store, _approval = await _approved_draft(ApprovalPolicy(enabled=True), [rewrite])
    prepared = _prepared_from(
        draft, actions=[rewrite.model_copy(update={"source_version_id": PydanticObjectId(), "expected_current_hash": "x"})]
    )
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "carried"


class _NoStates:
    async def load(self, organization_id, operation_id):  # noqa: ARG002
        return None


async def test_a_plan_without_a_reviewed_record_is_not_current() -> None:
    with pytest.raises(RestorePlanningError, match="no reviewed plan record"):
        await assert_plan_current(_NoStates(), _operation([_action()]))


class _PreparingAuthorization:
    def __init__(self, prepared: RestoreOperation) -> None:
        self.prepared = prepared

    async def prepare(self, organization, operation, requested_by, credential, store):  # noqa: ARG002
        return self.prepared


class _Plans:
    def __init__(self, *plans: RestoreOperation) -> None:
        self.plans = {plan.id: plan for plan in plans}

    async def load(self, organization_id, operation_id):  # noqa: ARG002
        return self.plans.get(operation_id)

    async def page(self, organization_id, *, skip, limit):  # noqa: ARG002
        return list(self.plans.values()), len(self.plans)


async def test_preparing_an_approved_draft_carries_its_approval_over_the_api() -> None:
    draft, service, store, _approval = await _approved_draft(ApprovalPolicy(), [_action()])
    prepared = _prepared_from(draft)
    store.operations[PREPARED_ID] = prepared
    administrator = _user(UserRole.ADMINISTRATOR, identifier=REQUESTER_ID, email="operator@example.com")
    app = _app(service, administrator)
    app.dependency_overrides[get_restore_authorization_service] = lambda: _PreparingAuthorization(prepared)
    app.dependency_overrides[get_restore_plans] = lambda: _Plans(draft)
    app.dependency_overrides[get_plan_state_store] = _NoStates

    async with _client(app) as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/prepare",
            json={"administrator_token": "fresh-admin-token"},
        )

    assert response.status_code == 201
    body = response.json()
    assert body["id"] == str(PREPARED_ID)
    assert body["approval"]["status"] == "approved"
    assert body["approval_required"] is False
```

In `backend/tests/test_restore_compensation.py`, seed reviewed state wherever a compensation plan reaches `_assert_plan_current` (it now fails closed): in `test_compensation_execution_uses_the_delegated_administrator_credential` and Task 9's `test_compensation_is_refused_with_a_conflict_while_another_restore_runs`, build the app with `states=await _reviewed(_MemoryStateStore(), plan)`.

- [ ] **Step 3: Write the failing frontend tests**

In `frontend/src/app/features/restore/restore-page.spec.ts`, import `ApprovalRequest` from `./restore.model`, add below `operation(...)`:

```ts
function approvalRequest(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    id: 'ap-1',
    restore_operation_id: 'op-1',
    status: 'pending',
    triggered_rules: [{ rule: 'organization_scope', detail: 'NW-Corp is organization-scoped.' }],
    requested_by_email: 's.kaur@northwind.example',
    decided_by_email: null,
    decided_at: null,
    decision_reason: null,
    expires_at: '2026-09-08T14:22:00Z',
    plan_hash: 'abc',
    summary: '2 objects restored to their 02 SEP state.',
    object_count: 2,
    delete_count: 0,
    created_at: '2026-09-07T14:22:00Z',
    ...overrides,
  };
}
```

and append inside the `describe`:

```ts
  it('lets a second administrator review the draft before the fresh backup and keeps that approval', async () => {
    await plan({ approval_required: true });
    expect(text()).toContain('carries over to the prepared plan');

    button('Ask a second administrator to review')!.click();
    await tick();
    const request = httpMock.expectOne(`${BASE}/approvals`);
    expect(request.request.body).toEqual({ restore_operation_id: 'op-1' });
    request.flush(approvalRequest());
    await settle();

    const token = element().querySelector<HTMLInputElement>('.token-input')!;
    token.value = 'a-fresh-administrator-token';
    token.dispatchEvent(new Event('input'));
    await settle();
    expect(button('Capture backup and review new plan')!.disabled).toBe(false);
    button('Capture backup and review new plan')!.click();
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1/prepare`).flush(
      operation({
        id: 'op-2',
        approval_required: true,
        baseline_snapshot_id: 'backup-1',
        prepared_until: new Date(Date.now() + 60_000).toISOString(),
        approval: approvalRequest({
          restore_operation_id: 'op-2',
          status: 'approved',
          decided_by_email: 'a.osei@northwind.example',
          decided_at: '2026-09-07T15:00:00Z',
        }),
      }),
    );
    await settle();

    expect(text()).toContain('APPROVED');
    expect(button('Execute reviewed plan')!.disabled).toBe(false);
  });

  it('withholds a prepared plan that needs an approval it does not have', async () => {
    await plan({
      approval_required: true,
      baseline_snapshot_id: 'backup-1',
      prepared_until: new Date(Date.now() + 60_000).toISOString(),
    });

    expect(button('Execute reviewed plan')!.disabled).toBe(true);
    expect(button('Ask a second administrator to review')).toBeTruthy();
  });
```

- [ ] **Step 4: Run to verify failure**

Run: `cd backend && uv run pytest tests/test_approvals.py tests/test_restore_compensation.py -v`
Expected: FAIL — `ImportError: payload_digest`, `carry_to_prepared` missing, the plan without a record passes, `approval_required` absent.

Run: `cd frontend && npm test -- --watch=false`
Expected: FAIL — no carry-over text; the prepared plan without approval is executable.

- [ ] **Step 5: Implement hashing, intent and carry-over**

`models/approval.py`, add to `RestoreApproval` after `plan_hash`:

```python
    # What was asked for and which actions it produced, independent of the
    # fresh backup that refines the plan; lets an approval survive preparation.
    intent_hash: str | None = None
    action_signature: str | None = None
```

`services/approvals.py` — imports: `from datetime import UTC, datetime, timedelta`, `from typing import Literal, Protocol`, `RestoreActionReason`, `from mist_config_guardian_backend.snapshots.secrets import is_protected, protected_fingerprint`.

```python
CarryOutcome = Literal["carried", "not_carried", "no_approval"]

APPROVAL_NOT_CARRIED = (
    "The fresh backup changed what this restore would do, so the approval of the earlier plan does not apply; "
    "request approval for this plan"
)


def _digest(value: object) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


def payload_digest(configuration: Mapping[str, object]) -> str:
    """Digest a protected configuration without its ciphertext, which changes on every planning."""

    def stable(value: object) -> object:
        if is_protected(value):
            return {"$fingerprint": protected_fingerprint(value)}
        if isinstance(value, Mapping):
            return {str(key): stable(child) for key, child in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [stable(child) for child in value]
        return value

    return _digest(stable(configuration))


def compute_plan_hash(actions: Sequence[RestoreAction]) -> str:
    """Hash the reviewed plan so any change to it invalidates an approval.

    The reviewed intent is hashed - object identity, target ids, action type,
    why the action exists, source version, expected live hash, and what would
    be written. Execution progress is excluded so a running restore never
    invalidates its own approval.
    """
    return _digest(
        [
            [
                action.order,
                str(action.logical_object_id),
                str(action.action),
                str(action.source_version_id),
                action.expected_current_hash,
                action.current_mist_id,
                action.site_mist_id,
                str(action.reason),
                payload_digest(action.protected_configuration),
            ]
            for action in sorted(actions, key=lambda item: item.order)
        ]
    )


def compute_intent_hash(operation: RestoreOperation) -> str:
    """Hash what the requester asked for, which a fresh backup does not change."""
    return _digest(
        {
            "organization_id": str(operation.organization_id),
            "requested_version_ids": sorted(str(version_id) for version_id in operation.requested_version_ids),
            "mode": str(operation.mode),
            "target_at": operation.target_at.astimezone(UTC).isoformat(),
            "requested_by": str(operation.requested_by),
        }
    )


def compute_action_signature(actions: Sequence[RestoreAction]) -> str:
    """Hash which objects the plan changes and how, ignoring the backup-specific details."""
    return _digest(
        sorted(
            [
                str(action.logical_object_id),
                str(action.action),
                "" if action.reason is RestoreActionReason.REFERENCE_REWRITE else str(action.source_version_id),
                str(action.reason),
            ]
            for action in actions
        )
    )
```

Remove the old body of `compute_plan_hash` (and the now-unused `datetime` import only if unused). Add `intent_hash: str` and `action_signature: str` to `ApprovalDraft`; pass them in `BeanieApprovalStore.insert`; in `request`, add `intent_hash=compute_intent_hash(operation), action_signature=compute_action_signature(operation.actions)` to the draft; in `_reopen` set `approval.intent_hash = compute_intent_hash(operation)` and `approval.action_signature = compute_action_signature(operation.actions)`. Add to `ApprovalService`:

```python
    async def carry_to_prepared(self, source: RestoreOperation, prepared: RestoreOperation) -> CarryOutcome:
        """Move a draft's approval onto the plan its fresh backup produced, when nothing that was reviewed changed.

        A prepared session lasts minutes and an approver may take hours, so the
        decision is made on the draft. It stays valid for the prepared plan only
        when the request and the set of changes are the same; the plan hash is
        rebound because the baseline hashes necessarily differ.
        """
        if prepared.id is None:
            return "no_approval"
        approval = await self.for_operation(source)
        if approval is None or approval.status not in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
            return "no_approval"
        if approval.intent_hash != compute_intent_hash(prepared) or approval.action_signature != compute_action_signature(
            prepared.actions
        ):
            return "not_carried"
        approval.restore_operation_id = prepared.id
        approval.plan_hash = compute_plan_hash(prepared.actions)
        approval.summary = plan_summary(prepared)
        approval.object_count = len(prepared.actions)
        approval.delete_count = delete_count(prepared)
        await self._store.save(approval)
        return "carried"
```

`services/restore_planner.py` `assert_plan_current`:

```python
    state = await store.load(operation.organization_id, operation.id)
    if state is None:
        msg = "This restore plan has no reviewed plan record; create a new plan"
        raise RestorePlanningError(msg)
    if state.plan_hash != current:
        msg = "This restore plan changed after it was reviewed; create a new plan"
        raise RestorePlanningError(msg)
    return current
```

- [ ] **Step 6: Carry in the prepare route and report the policy**

`schemas/restore.py`: `RestoreOperationResponse.approval_required: bool = False`; `from_document(..., approval_required: bool = False)` sets it.

`api/routes/restores.py`: import `APPROVAL_NOT_CARRIED`, `evaluate_approval_policy`.

```python
async def _operation_response(
    operation: RestoreOperation,
    approvals: ApprovalService,
    organization: Organization,
    *,
    compensation_available: bool | None = None,
) -> RestoreOperationResponse:
    """Render one operation with its approval, whether policy needs one, and compensation availability."""
    approval = await approvals.for_operation(operation)
    return RestoreOperationResponse.from_document(
        operation,
        approval=None if approval is None else ApprovalResponse.from_document(approval),
        approval_required=bool(
            evaluate_approval_policy(organization_policy(organization), operation.actions, operation.mode)
        ),
        compensation_available=(
            operation.status is RestoreStatus.COMPENSATION_AVAILABLE
            if compensation_available is None
            else compensation_available
        ),
    )
```

Pass the organization at every call: `list_restore_operations` and `get_restore_operation` rename `_organization` to `organization`; `create_compensation_plan` likewise; `_authorize_and_queue` gains an `organization: Organization` parameter (second position) supplied by both execute routes. In `prepare_restore`, after the `try/except` block:

```python
    if await approvals.carry_to_prepared(operation, plan) == "not_carried":
        plan.warnings.append(APPROVAL_NOT_CARRIED)
        await plan.save()
    return await _operation_response(plan, approvals, organization)
```

Verify while implementing: `create_restore_plan` uses `RestoreOperationResponse.from_document(operation)` directly; switch it to `from_document(operation, approval_required=bool(evaluate_approval_policy(organization_policy(organization), operation.actions, operation.mode)))` so a new draft tells the page an approval will be needed.

- [ ] **Step 7: Implement the frontend**

`restore.model.ts`: add `approval_required?: boolean;` to `RestoreOperation`, and replace `blocksExecution`:

```ts
/** Execution waits on an approval that exists and is not granted, or on one policy needs and nobody asked for. */
export function blocksExecution(approval: ApprovalRequest | null | undefined, required = false): boolean {
  if (approval != null) {
    return approval.status !== 'approved';
  }
  return required;
}
```

`restore-page.ts:295`: `protected readonly blockedByApproval = computed(() => blocksExecution(this.approval(), this.activeOperation()?.approval_required === true));`

`restore-page.html`, on the plan-step `<app-restore-step-authorize>` add `[approvalRequired]="operation.approval_required === true"`.

`restore-step-authorize.ts`: add `readonly approvalRequired = input(false);`.

`restore-step-authorize.html`: after the first lead paragraph block add

```html
  @if (needsPreparation() && approvalRequired() && !approval()) {
    <p class="lead">A second administrator must approve this restore. Ask now: the approval carries over to the prepared plan when the fresh backup leaves the actions unchanged.</p>
  }
```

and replace the `approval-wait` paragraph text with: `Execution stays closed until a second administrator approves this restore. The approval carries over to the prepared plan when the fresh backup leaves the actions unchanged; rebuilding the plan invalidates it.`

- [ ] **Step 8: Run the tests**

Run: `cd backend && uv run pytest tests/test_approvals.py tests/test_restore_compensation.py tests/test_restore_baseline.py -v && uv run pytest -q`
Expected: PASS.

Run: `make openapi && cd backend && uv run python ../scripts/export-openapi.py --check`, then `cd frontend && npm test -- --watch=false && npm run build`
Expected: PASS; `docs/openapi.json` gains `approval_required`.

- [ ] **Step 9: Lint and type-check**

Run: `cd backend && uv run ruff format . && uv run ruff check . && uv run ty check src`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add backend/src/mist_config_guardian_backend/models/approval.py backend/src/mist_config_guardian_backend/services/approvals.py \
  backend/src/mist_config_guardian_backend/services/restore_planner.py \
  backend/src/mist_config_guardian_backend/api/routes/restores.py backend/src/mist_config_guardian_backend/schemas/restore.py \
  backend/tests/test_approvals.py backend/tests/test_restore_compensation.py docs/openapi.json \
  frontend/src/app/features/restore/restore.model.ts frontend/src/app/features/restore/restore-page.ts \
  frontend/src/app/features/restore/restore-page.html frontend/src/app/features/restore/restore-step-authorize.ts \
  frontend/src/app/features/restore/restore-step-authorize.html frontend/src/app/features/restore/restore-page.spec.ts
git commit -m "fix(restore): bind approvals to plan intent so they survive preparation" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Final verification

- [ ] From the repository root: `make check`
- [ ] `cd backend && MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest tests/test_restore_executor_mongo.py tests/test_restore_recovery_mongo.py tests/test_restore_lease_mongo.py tests/test_restore_state_store_mongo.py tests/test_restore_targets_mongo.py -v`
- [ ] `cd backend && grep -rn "relaxed\|use_prepared_credential" src ../frontend/src` returns nothing.

## Self-review

**Spec coverage**

| Finding / decision | Where |
|---|---|
| H1 transport errors, retry, outcome flag | Task 1 |
| H1 catch-all, terminal status, notification, credential `finally`, version race, decrypt | Task 2 |
| H1 unconfirmed action treated as possibly applied by compensation | Task 3 (+ Task 10 skip rules) |
| H1 heartbeat + janitor clearing credentials | Task 4 (+ Task 9 lease release, Task 10 compensation status) |
| S2 dead resume path removed, idempotency guard kept | Task 2 |
| M6 bounded 429/5xx retry, POST only on 429 | Task 1 |
| H3 deferred reads under a recreated site, baseline skip | Task 5 |
| H5 per-write re-read (moved ahead) | Task 5; compensation variant Task 10 |
| H4 source-key re-keying incl. site children, unique-index conflict | Task 6 |
| H2 forced reference-rewrite actions ordered after the CREATE | Task 7 |
| M7 name-collision preflight | Task 8 |
| H5 organization lease, 409 on authorize/prepare, compensation shares it | Task 9 |
| M1 strict compensation drift against what the restore wrote | Task 10 |
| M2 newest compensation lookup, re-plan and re-execute | Task 10 |
| S1/M3 single fingerprint module, RESTORED parity regression | Task 11 |
| M4 prepared-only execute, superseded source plan, dead client method removed | Task 12 |
| M5 intent-bound approval carried across prepare, plan hash covers targets/payload, fail-closed currency, approval before prepare in UI | Task 13 |

**Name and type consistency checked across tasks:** `MistMutationError(message, *, outcome_unknown, status_code)`; `terminal_failure_status(actions, *, compensating=False)` (kwarg added in Task 10, all call sites updated there); `mark_unconfirmed(actions, reason) -> int | None`; `RestoreAction` fields `outcome_unknown`, `compensates_action_order`, `applied_hash`, `resulting_site_mist_id`, `reason`; `check_before_write(..., object_id, site_id, entry, deferred, compensating) -> WriteCheck(entry, recorded, skip)`; `build_snapshot_entry(action, definition, vault, current, *, mist_object_id, site_mist_id)`; `_record_result(operation, action, definition, written, *, readback, site_id)` from Task 6 onward (Task 2's DB test is updated in Task 6); `RestoreLeaseStore.acquire/renew/release(organization_id, operation_id, ...)`; `authorize(organization_id, operation_id, credential, task_id, *, compensation=False)`; `_operation_response(operation, approvals, organization, *, compensation_available=None)`; `carry_to_prepared(source, prepared) -> CarryOutcome`.

**Decisions made while planning (review before execution):**
1. Unconfirmed writes are `FAILED` + `outcome_unknown=True`, not a new `RestoreActionStatus` (frontend switches on the enum).
2. An unconfirmed CREATE produces a manual follow-up warning, not a name-based delete: Mist returned no id and deleting by name could remove a legitimate object.
3. Task 5 adds a read-back after every write and stores `applied_hash`; compensation compares against it (the "hash of what the restore wrote"). Task 11 makes the `RESTORED` version hash equal to it. Restores recorded before Task 5 cannot be compensated automatically for non-delete actions (explicit preflight error).
4. The reversal of an unconfirmed UPDATE is the one compensation action written without a drift check (nothing trustworthy to compare against); the plan says so in a warning.
5. A capture that raced the restore (a logical object created at/after `started_at` holding the new source key) is folded into the restored identity; an older holder stops the run.
6. Reverse dependents are no longer expanded further (they are re-pointed, not restored).
7. The new plan-hash formula invalidates plans and approvals created before Task 13; they must be rebuilt.
8. Intent `requester` is the plan's `requested_by`; a draft built by an operator and prepared by an administrator therefore does not carry its approval.
9. A failed compensation ends `FAILED`; retry starts from the original operation, which stays `COMPENSATION_AVAILABLE`.
