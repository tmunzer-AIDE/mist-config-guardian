"""Guardian's orchestrator: the fenced tick, one attempt's execution, and the loading each attempt needs.

The module is read in three parts, in this order:

1. **Loading and mapping.** Everything an attempt reads from the database is loaded once, before execution, and
   mapped onto the pure inputs of :mod:`~mist_config_guardian_backend.guardian.change`,
   :mod:`~mist_config_guardian_backend.guardian.deployment` and
   :mod:`~mist_config_guardian_backend.guardian.monitoring`. Configurations are mapped in their protected form
   only; no plaintext secret ever reaches a change set.
2. **Attempt execution.** :func:`execute_attempt` is the phase machine: one fixed evidence instant, one anchor,
   local monotonic phase deadlines, and the failure isolation the design states. It touches no collection, so it
   is exercised without MongoDB.
3. **The tick procedure.** :class:`GuardianService` runs the design's numbered steps. Every root and run mutation
   is a builder from :mod:`~mist_config_guardian_backend.guardian.repository`; this module never writes its own
   filter or update pipeline, and every publication fence is built from the finalized run document rather than
   from the root's claim, so the attempt match is structural.

Guardian stays dormant unless ``guardian_enabled`` is set: the webhook gates root creation and the worker gates
polling. Nothing here runs otherwise.
"""

import contextlib
import json
import logging
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, AsyncExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import TracebackType
from typing import Any

import httpx
from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder
from bson import ObjectId
from pydantic import BaseModel, ValidationError
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.guardian import repository as repo
from mist_config_guardian_backend.guardian.agent import (
    AgentInputs,
    AgentRun,
    ModelClient,
    ModelError,
    availability,
    run_agent,
    skipped,
)
from mist_config_guardian_backend.guardian.agent_schema import (
    ACTION_SCHEMA,
    ACTION_SCHEMA_NAME,
    ACTION_SCHEMA_STRICT,
)
from mist_config_guardian_backend.guardian.change import ChangeSet, ObjectChange, build_change_set, change_view
from mist_config_guardian_backend.guardian.composition import DeviceSeverity, compose
from mist_config_guardian_backend.guardian.contracts import (
    EARLY_CUTOFF,
    FINAL_FORCED,
    FINAL_MINIMUM,
    MAX_ATTEMPTS_PER_KIND,
    MAX_STATUS_REASON_CHARS,
    AgentConclusion,
    Band,
    Conclusion,
    ExpectedDevice,
    LedgerRow,
    ObligationOutcome,
    ObligationStatus,
    RunBudget,
    RunKind,
    Verdict,
    bound_reason,
)
from mist_config_guardian_backend.guardian.deployment import (
    DeviceEventReceipt,
    ReplayFrame,
    expected_devices,
    pair_deployments,
    record_deployment,
    resolve_anchor,
)
from mist_config_guardian_backend.guardian.evidence import (
    CHANGE_VIEW_BUDGET,
    CONCLUSIONS_BUDGET,
    LEDGER_VIEW_BUDGET,
    STEPS_BUDGET,
    EvidenceRegistry,
    json_size,
    pack,
)
from mist_config_guardian_backend.guardian.ledger import build_ledger, coverage, deterministic_view, resolve_statuses
from mist_config_guardian_backend.guardian.monitoring import (
    ComparisonRecord,
    DeviceMonitoring,
    FindingRecord,
    IncidentRecord,
    MonitoringRecord,
    SleSample,
    record_monitoring,
    replay_monitoring,
)
from mist_config_guardian_backend.guardian.plugins import PLUGINS
from mist_config_guardian_backend.guardian.plugins.base import rule_allowances, run_rules
from mist_config_guardian_backend.guardian.reader import (
    MAX_TRANSPORT_BYTES,
    McpTransport,
    Reader,
    RuleTransport,
    SiteAuthority,
    TransportError,
    evidence_windows,
)
from mist_config_guardian_backend.integrations.ai_provider import (
    AiMessage,
    AiProviderError,
    JsonObjectFormat,
    JsonSchemaFormat,
    OpenAiCompatibleProvider,
    ResponseFormat,
)
from mist_config_guardian_backend.integrations.mist import REGION_HOSTS
from mist_config_guardian_backend.integrations.mist_mcp import MistMcpClient, MistMcpError
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.guardian import (
    GuardianInvestigation,
    GuardianResult,
    GuardianRun,
    RunDocumentTooLargeError,
    check_run_document_size,
)
from mist_config_guardian_backend.models.monitoring import MonitoringSession, SleObservation
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectIncarnation, ObjectVersion
from mist_config_guardian_backend.models.webhook import WebhookReceipt
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.application_configuration import ApplicationConfigurationService
from mist_config_guardian_backend.services.service_credentials import service_token
from mist_config_guardian_backend.snapshots.diffing import ENCRYPTED_MARKER, FINGERPRINT_MARKER, is_secret, stable_json
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition, ObjectFamily, get_definition

logger = logging.getLogger(__name__)

# The phases of the design's attempt-deadline table, on the local monotonic clock started just before the commit.
RULE_PHASE = timedelta(seconds=90)
AGENT_PHASE = timedelta(seconds=210)
PUBLISH_PHASE = timedelta(seconds=240)

# The early trigger's signal: an append-only assessment transition recorded on a linked monitoring session.
DEGRADATION_EVENTS = frozenset({"ASSESSMENT_WARNING", "ASSESSMENT_CRITICAL"})
# Bands the old free-form monitoring finding severity may name. Anything else keeps the old model's own default.
_BANDS: Mapping[str, Band] = {"none": "none", "info": "info", "warning": "warning", "critical": "critical"}
_DEFAULT_FINDING_BAND: Band = "warning"
_DEFAULT_SENSITIVE: frozenset[str] = ObjectDefinition.sensitive_fields

# The legacy device-event normalizer recognizes no ``AP_CONFIG_REVERTED``, so a stored receipt can never carry one
# and an access point revert is read as "no outcome observed" rather than as a revert. Guardian's pairing accepts
# the event type; only the stored normalization is narrower. The mapping keeps this explicit rather than implying
# that the absence of the event means a deployment succeeded.
UNOBSERVABLE_EVENT_TYPES = frozenset({"AP_CONFIG_REVERTED"})

MAX_AUDIT_VERSIONS = 200
MAX_DEVICE_RECEIPTS = 2_000
MAX_LINKED_SESSIONS = 500
MAX_RETENTION_DAYS = 36_500
NO_FAILURE_REASON = "The final run recorded no failure reason"
ATTEMPT_FAILED = "The attempt could not be completed: {detail}"
RUN_TOO_LARGE = "The run document exceeded its asserted bound: {detail}"

# An input the attempt could not see in full. Each of these becomes both a core gap on the verdict and an
# unsatisfied core obligation on the ledger, so a run can never publish complete coverage over what it never read.
VERSION_CAP_GAP = (
    "This audit changed more than {cap} object versions; the changed objects beyond that limit were not examined"
)
SESSION_CAP_GAP = (
    "This audit is linked to more than {cap} monitoring sessions; the sessions beyond that limit were not examined"
)
RECEIPT_CAP_GAP = (
    "More than {cap} device-event receipts match this audit; the receipts beyond that limit were not examined"
)
ELIDED_GAP = (
    "Object {name} changed {count} time(s) within this audit and ended where it started; the configurations it "
    "held in between were not examined"
)


def _encoded(model: BaseModel) -> dict[str, Any]:
    """One model as Beanie writes it, so a builder stores exactly what the document model validates."""
    fields = type(model).model_fields
    return dict(
        Encoder(to_db=True).encode(
            {(fields[name].alias or name): value for name, value in model if not fields[name].exclude}
        )
    )


def _retained_until(organization: Organization | None, now: datetime) -> datetime:
    """The organization's retention policy, pinned at creation so retention never scans for unpinned documents."""
    days = organization.monitoring_retention_days if organization is not None else 1
    if type(days) is not int or not 1 <= days <= MAX_RETENTION_DAYS:
        days = 1
    return now + timedelta(days=days)


# -- loading and mapping ------------------------------------------------------------------------------------------


def mask_secrets(value: object, fields: frozenset[str], *, name: str | None = None) -> object:
    """Replace any unprotected value under a registry-declared sensitive name with a fingerprint-only marker.

    Stored configurations are already protected, so this only defends against one that is not: a legacy document, or
    a value the writer could not encrypt. The replacement keeps the diff's own secret shape, so two different
    secrets still compare as changed while neither is ever rendered.
    """
    if name is not None and name.lower() in fields and not is_secret(value):
        return {ENCRYPTED_MARKER: "", FINGERPRINT_MARKER: sha256(stable_json(value).encode()).hexdigest()}
    if isinstance(value, Mapping):
        return {str(key): mask_secrets(child, fields, name=str(key)) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask_secrets(child, fields) for child in value]
    return value


def protected_configuration(configuration: Mapping[str, object] | None, definition: ObjectDefinition | None) -> dict:
    """A stored configuration as a change set may see it: protected values only, never revealed plaintext."""
    fields = definition.sensitive_fields if definition is not None else _DEFAULT_SENSITIVE
    masked = mask_secrets(dict(configuration or {}), fields)
    return masked if isinstance(masked, dict) else {}


def device_identity(configuration: Mapping[str, object]) -> tuple[str, str] | None:
    """A device object's immutable ``(mac, site_id)``, read from the configuration rather than today's fields."""
    mac = configuration.get("mac")
    site = configuration.get("site_id")
    if not isinstance(mac, str) or not isinstance(site, str) or not site:
        return None
    normalized = mac.replace(":", "").replace("-", "").lower()
    if len(normalized) != 12 or any(character not in "0123456789abcdef" for character in normalized):  # noqa: PLR2004
        return None
    return normalized, site


@dataclass(frozen=True, slots=True)
class SupersededObject:
    """A logical object this audit changed more than once, and how many versions it held in between.

    Only the net change is compiled, so an object that ends where it started yields no atom at all. Nothing else
    would record that the audit touched it, which is why the elision is reported rather than elided.
    """

    logical_object_id: str
    name: str
    intermediate: int


@dataclass(frozen=True, slots=True)
class LoadedChanges:
    """The audit's changes, what a read cap dropped, and the objects whose net change may have elided something."""

    changes: tuple[ObjectChange, ...] = ()
    gaps: tuple[str, ...] = ()
    superseded: tuple[SupersededObject, ...] = ()


@dataclass(frozen=True, slots=True)
class AttemptInputs:
    """Everything one attempt reads from the database, loaded once before execution begins.

    ``gaps`` and ``superseded`` are what loading itself could not see in full. Both end as core gaps and as
    unsatisfied core obligations, never as silence.
    """

    organization_id: PydanticObjectId
    audit_id: str
    received_at: datetime
    audit_time: datetime | None
    changes: tuple[ObjectChange, ...] = ()
    receipts: tuple[DeviceEventReceipt, ...] = ()
    sessions: tuple[MonitoringRecord, ...] = ()
    gaps: tuple[str, ...] = ()
    superseded: tuple[SupersededObject, ...] = ()


def _sle_sample(observation: SleObservation | None) -> SleSample | None:
    if observation is None:
        return None
    return SleSample.model_validate(
        {
            name: getattr(observation, name)
            for name in ("captured_at", "scope", "scope_id", "values", "no_data", "errors", "requested_metrics")
        }
        | {
            "metric_errors": dict(observation.metric_errors),
            "metric_states": dict(observation.metric_states),
        }
    )


def _band(value: object) -> Band:
    """The old free-form finding severity as a band. An unrecognized value keeps the old model's own default."""
    return _BANDS.get(str(value).lower(), _DEFAULT_FINDING_BAND)


def monitoring_record(session: MonitoringSession) -> MonitoringRecord | None:
    """One stored session as monitoring replay reads it, or ``None`` when it identifies no device."""
    if session.id is None or not session.device_mac or not session.site_id:
        return None
    return MonitoringRecord(
        session_id=str(session.id),
        device_mac=session.device_mac,
        site_id=session.site_id,
        device_name=session.device_name[:128],
        audit_ids=tuple(session.audit_ids),
        created_at=session.created_at,
        active=session.active,
        completed_at=session.completed_at,
        baseline=_sle_sample(session.baseline),
        observations=tuple(sample for sample in map(_sle_sample, session.observations) if sample is not None),
        incidents=tuple(
            IncidentRecord(
                event_type=incident.event_type,
                occurred_at=incident.occurred_at,
                severity=_band(incident.severity),
                resolved_at=incident.resolved_at,
            )
            for incident in session.incidents
        ),
        comparisons=tuple(
            ComparisonRecord(
                followup_at=None if comparison.followup is None else comparison.followup.captured_at,
                findings=tuple(
                    FindingRecord(kind=item.kind, severity=_band(item.severity)) for item in comparison.findings
                ),
                latest_at=None if comparison.latest is None else comparison.latest.captured_at,
                current_findings=None
                if comparison.current_findings is None
                else tuple(
                    FindingRecord(kind=finding.kind, severity=_band(finding.severity))
                    for finding in comparison.current_findings
                ),
            )
            for comparison in session.device_comparisons
        ),
    )


def device_receipt(row: Mapping[str, Any]) -> DeviceEventReceipt | None:
    """One normalized device-event receipt, or ``None`` when it identifies no device, site or event."""
    signal = row.get("deployment")
    if not isinstance(signal, Mapping):
        return None
    mac, site = signal.get("device_mac"), signal.get("site_id")
    event_type = signal.get("event_type")
    if not isinstance(mac, str) or not site or not isinstance(event_type, str):
        return None
    return DeviceEventReceipt(
        receipt_id=str(row["_id"]),
        received_at=row["created_at"],
        event_type=event_type,
        device_mac=mac,
        site_id=str(site),
        occurred_at=signal.get("occurred_at"),
        audit_id=row.get("audit_id"),
    )


async def _audit_versions(
    organization_id: PydanticObjectId, audit_id: str
) -> tuple[list[ObjectVersion], tuple[str, ...]]:
    """This audit's object versions, ordered so the retained window is deterministic, and the cap's own gap.

    The order is ``(logical object, version)``, so every object's versions are contiguous. When the cap truncates
    an object's own versions, that object is dropped whole rather than half-read: its net change would otherwise
    be taken from an arbitrary surviving version, which is wrong rather than merely incomplete. An object the
    window contains entirely is kept, and the gap says the rest were not examined.
    """
    rows = await (
        ObjectVersion.find({"organization_id": organization_id, "audit_id": audit_id})
        .sort("+logical_object_id", "+version")
        .to_list(MAX_AUDIT_VERSIONS + 1)
    )
    if len(rows) <= MAX_AUDIT_VERSIONS:
        return rows, ()
    kept, overflow = rows[:MAX_AUDIT_VERSIONS], rows[MAX_AUDIT_VERSIONS]
    if overflow.logical_object_id == kept[-1].logical_object_id:
        kept = [row for row in kept if row.logical_object_id != overflow.logical_object_id]
    return kept, (VERSION_CAP_GAP.format(cap=MAX_AUDIT_VERSIONS),)


async def _object_changes(organization_id: PydanticObjectId, audit_id: str) -> LoadedChanges:
    """Every logical object this audit changed, as its net change, from protected configurations alone."""
    versions, gaps = await _audit_versions(organization_id, audit_id)
    if not versions:
        return LoadedChanges(gaps=gaps)
    spans: dict[PydanticObjectId, list[ObjectVersion]] = {}
    for version in versions:
        spans.setdefault(version.logical_object_id, []).append(version)
    latest = {key: max(items, key=lambda item: item.version) for key, items in spans.items()}
    earliest = {key: min(items, key=lambda item: item.version) for key, items in spans.items()}
    logicals = {
        item.id: item
        for item in await LogicalObject.find(
            {"organization_id": organization_id, "_id": {"$in": list(spans)}},
        ).to_list()
    }
    wanted = [(key, item.version - 1) for key, item in earliest.items() if item.version > 1]
    priors = {
        (item.logical_object_id, item.version): item
        for item in (
            await ObjectVersion.find(
                {
                    "organization_id": organization_id,
                    "$or": [{"logical_object_id": key, "version": version} for key, version in wanted],
                },
            ).to_list()
            if wanted
            else []
        )
    }
    incarnations = {
        item.id: item
        for item in await ObjectIncarnation.find(
            {
                "organization_id": organization_id,
                "_id": {"$in": sorted({version.incarnation_id for version in versions})},
            },
        ).to_list()
    }
    changes = []
    superseded = []
    for key, after in sorted(latest.items(), key=lambda entry: str(entry[0])):
        logical = logicals.get(key)
        if logical is None:
            continue
        if len(spans[key]) > 1:
            superseded.append(
                SupersededObject(logical_object_id=str(key), name=logical.name, intermediate=len(spans[key]) - 1)
            )
        prior = priors.get((key, earliest[key].version - 1))
        if prior is not None and prior.is_deleted:
            prior = None
        definition = get_definition(logical.scope, logical.object_type)
        incarnation = incarnations.get(after.incarnation_id)
        # One provider identity holds only while every version of the change shares an incarnation with its baseline.
        single = len({version.incarnation_id for version in spans[key]}) == 1 and (
            prior is None or prior.incarnation_id == after.incarnation_id
        )
        identity = (
            device_identity(after.configuration)
            if definition is not None and definition.family is ObjectFamily.DEVICE
            else None
        )
        changes.append(
            ObjectChange(
                logical_object_id=str(key),
                scope=logical.scope,
                object_type=logical.object_type,
                name=logical.name,
                version=after.version,
                before={} if prior is None else protected_configuration(prior.configuration, definition),
                after={} if after.is_deleted else protected_configuration(after.configuration, definition),
                site_id=(incarnation.site_mist_id if incarnation is not None else None) or logical.site_mist_id,
                device_mac=None if identity is None else identity[0],
                mist_id=incarnation.mist_object_id if single and incarnation is not None else None,
            )
        )
    return LoadedChanges(changes=tuple(changes), gaps=gaps, superseded=tuple(superseded))


async def _device_receipts(
    organization_id: PydanticObjectId,
    audit_id: str,
    candidates: Sequence[PydanticObjectId],
    *,
    as_of: datetime,
) -> tuple[tuple[DeviceEventReceipt, ...], tuple[str, ...]]:
    """Audit-linked and session-candidate device events, normalized for pairing and never carrying a payload.

    Oldest first, because pairing needs each outcome's earlier trigger. A receipt the legacy normalizer could not
    classify carries no ``deployment`` and is invisible here, which is why :data:`UNOBSERVABLE_EVENT_TYPES` is
    stated rather than assumed away.
    """
    rows = (
        await WebhookReceipt.get_pymongo_collection()
        .find(
            {
                "organization_id": organization_id,
                "topic": "device-events",
                "signature_valid": True,
                "created_at": {"$lte": as_of},
                "deployment": {"$ne": None},
                "$or": [{"audit_id": audit_id}, {"audit_id": None, "_id": {"$in": list(candidates)}}],
            },
            {"audit_id": 1, "created_at": 1, "deployment": 1},
        )
        .sort([("created_at", 1), ("_id", 1)])
        .to_list(length=MAX_DEVICE_RECEIPTS + 1)
    )
    gaps = (RECEIPT_CAP_GAP.format(cap=MAX_DEVICE_RECEIPTS),) if len(rows) > MAX_DEVICE_RECEIPTS else ()
    kept = rows[:MAX_DEVICE_RECEIPTS]
    return tuple(receipt for row in kept if (receipt := device_receipt(row)) is not None), gaps


async def linked_sessions(
    organization_id: PydanticObjectId, audit_id: str
) -> tuple[list[MonitoringSession], tuple[str, ...]]:
    """Every monitoring session that names this audit, and the cap's own gap when one was dropped.

    Active sessions come first and the newest next, so the cap can never hide the one fact the final's
    revalidation asks for — whether any linked session is still active — nor the latest session of a device. The
    transitions read from these are a trigger signal, never evidence.
    """
    rows = await (
        MonitoringSession.find({"organization_id": organization_id, "audit_ids": audit_id})
        .sort("-active", "-created_at", "-_id")
        .to_list(MAX_LINKED_SESSIONS + 1)
    )
    gaps = (SESSION_CAP_GAP.format(cap=MAX_LINKED_SESSIONS),) if len(rows) > MAX_LINKED_SESSIONS else ()
    return rows[:MAX_LINKED_SESSIONS], gaps


async def load_attempt_inputs(root: GuardianInvestigation, *, as_of: datetime) -> AttemptInputs:
    """Load every database input of one attempt once, at the attempt's fixed evidence instant.

    Every read cap that fires is carried out as a gap rather than swallowed, so the attempt can report what it
    never saw instead of judging as if it had seen everything.
    """
    sessions, session_gaps = await linked_sessions(root.organization_id, root.audit_id)
    receipt_ids = sorted({receipt_id for session in sessions for receipt_id in session.receipt_ids})
    loaded = await _object_changes(root.organization_id, root.audit_id)
    receipts, receipt_gaps = await _device_receipts(root.organization_id, root.audit_id, receipt_ids, as_of=as_of)
    return AttemptInputs(
        organization_id=root.organization_id,
        audit_id=root.audit_id,
        received_at=root.changed_at,
        audit_time=root.changed_at if root.anchor_known else None,
        changes=loaded.changes,
        receipts=receipts,
        sessions=tuple(record for session in sessions if (record := monitoring_record(session)) is not None),
        gaps=(*loaded.gaps, *session_gaps, *receipt_gaps),
        superseded=loaded.superseded,
    )


# -- transports ---------------------------------------------------------------------------------------------------


class MistRuleTransport:
    """One organization's bounded Mist reads for the rule plug-ins, through the Reader alone."""

    def __init__(self, *, token: str, base_url: str) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url, headers={"Authorization": f"Token {token}"}, timeout=20, follow_redirects=False
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch(self, path: str, params: Mapping[str, str], *, timeout: float, max_bytes: int) -> Any:  # noqa: ANN401, ASYNC109 - the transport's own bound, and dynamic JSON validated by the Reader
        """One bounded Mist read. The wire is bounded as it arrives, not after the whole body is buffered."""
        try:
            async with self._client.stream("GET", path, params=dict(params), timeout=timeout) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        msg = f"The response is above the {max_bytes}-byte transport bound."
                        raise TransportError(msg)  # noqa: TRY301 - one place builds the transport failure
                return json.loads(body)
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(str(exc)) from exc


class GuardianMcpTransport:
    """The Mist MCP endpoint as the Reader's transport: bounded wire, and one error type."""

    def __init__(self, client: MistMcpClient) -> None:
        self._client = client

    async def list_tools(self, *, timeout: float, max_bytes: int) -> Mapping[str, Any]:  # noqa: ASYNC109 - the transport's own request bound
        return await self._call(self._client.list_tools(timeout=timeout), max_bytes)

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        timeout: float,  # noqa: ASYNC109 - the transport's own request bound
        max_bytes: int,
    ) -> Mapping[str, Any]:
        return await self._call(self._client.call_tool(name, dict(arguments), timeout=timeout), max_bytes)

    @staticmethod
    async def _call(awaitable: Awaitable[Mapping[str, Any]], max_bytes: int) -> Mapping[str, Any]:
        try:
            result = await awaitable
        except MistMcpError as exc:
            detail = f"{exc.code}: {exc.detail}"
            raise TransportError(detail) from exc
        except Exception as exc:
            raise TransportError(str(exc)) from exc
        if json_size(result) > max_bytes:
            msg = f"The result is above the {max_bytes}-byte transport bound."
            raise TransportError(msg)
        return result


class GuardianModelClient:
    """One turn of the agent conversation, in the structured-output mode the setup-time probe proved."""

    def __init__(self, provider: OpenAiCompatibleProvider, *, structured_output: str) -> None:
        self._provider = provider
        self._format: ResponseFormat = (
            JsonSchemaFormat(name=ACTION_SCHEMA_NAME, schema=ACTION_SCHEMA, strict=ACTION_SCHEMA_STRICT)
            if structured_output == "json_schema"
            else JsonObjectFormat()
        )

    async def complete(self, system: str, user: str) -> str:
        try:
            completion = await self._provider.complete(
                [AiMessage(role="system", content=system), AiMessage(role="user", content=user)],
                response_format=self._format,
            )
        except AiProviderError as exc:
            raise ModelError(str(exc)) from exc
        return completion.content


@dataclass(frozen=True, slots=True)
class AttemptTools:
    """The external collaborators of one attempt, and the reason the agent is skipped when it has none."""

    rule_transport: RuleTransport | None = None
    mcp_transport: McpTransport | None = None
    model_client: ModelClient | None = None
    skip_reason: str | None = None
    secrets: tuple[str, ...] = ()


class _NoTools(AbstractAsyncContextManager["AttemptTools"]):
    """An attempt with no organization, no token or no provider: every read fails and the agent is skipped."""

    def __init__(self, reason: str) -> None:
        self._reason = reason

    async def __aenter__(self) -> AttemptTools:
        return AttemptTools(skip_reason=self._reason)

    async def __aexit__(self, *_args: object) -> None:
        return None


class GuardianTools(AbstractAsyncContextManager["AttemptTools"]):
    """Builds and closes one attempt's transports. A provider or endpoint that is missing skips the agent."""

    def __init__(self, organization: Organization, *, vault: CredentialVault) -> None:
        self._organization = organization
        self._vault = vault
        self._stack = AsyncExitStack()

    async def __aenter__(self) -> AttemptTools:
        # ``__aexit__`` never runs when ``__aenter__`` raises, so whatever is already open is closed here instead;
        # otherwise a failing provider or endpoint would leak one HTTP client per failed attempt.
        try:
            return await self._build()
        except BaseException:
            await self._stack.aclose()
            raise

    async def _build(self) -> AttemptTools:
        settings = get_settings()
        token = await service_token(self._organization, self._vault)
        rule = MistRuleTransport(token=token, base_url=REGION_HOSTS[self._organization.cloud_region])
        self._stack.push_async_callback(rule.aclose)
        runtime = await ApplicationConfigurationService(self._vault).ai_runtime()
        reason = availability(
            runtime=runtime is not None,
            mcp_endpoint=bool(settings.mist_mcp_url),
            capability=runtime is not None and runtime.structured_output is not None,
        )
        if reason is not None or runtime is None:
            return AttemptTools(rule_transport=rule, skip_reason=reason)
        cloud = httpx.URL(REGION_HOSTS[self._organization.cloud_region]).host
        client = await self._stack.enter_async_context(
            MistMcpClient(url=settings.mist_mcp_url, token=token, cloud=cloud, max_wire_bytes=MAX_TRANSPORT_BYTES)
        )
        provider = await self._stack.enter_async_context(
            OpenAiCompatibleProvider(base_url=runtime.base_url, model=runtime.model, api_key=runtime.api_key)
        )
        return AttemptTools(
            rule_transport=rule,
            mcp_transport=GuardianMcpTransport(client),
            model_client=GuardianModelClient(provider, structured_output=runtime.structured_output or ""),
            secrets=(token, runtime.api_key),
        )

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        await self._stack.aclose()


ToolsFactory = Callable[[Organization | None], AbstractAsyncContextManager[AttemptTools]]


# -- attempt execution --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AttemptOutcome:
    """One attempt's terminal state and the run fields it produced, ready for the finalization builder."""

    state: str
    fields: dict[str, Any] = field(default_factory=dict)
    failure_reason: str | None = None


def _fit[T](items: Iterable[T], *, budget: int, priority: Callable[[T], Any]) -> tuple[T, ...]:
    """The rows that fit one stored budget, in priority order. Full lists stay in memory for evaluation only."""
    return pack(
        items,
        budget=budget,
        priority=priority,
        category=lambda _item: "row",
        overhead=lambda omitted, kept: 2 + max(kept - 1, 0) + (8 * bool(omitted)),
    ).kept


def _fit_conclusion[T: Conclusion | AgentConclusion](conclusion: T | None, budget: int) -> T | None:
    """A conclusion within its share of the conclusions budget, dropping its listed devices then its findings."""
    if conclusion is None or json_size(conclusion) <= budget:
        return conclusion
    devices = list(conclusion.impacted_devices)
    findings = list(conclusion.findings)
    trimmed = conclusion
    while json_size(trimmed) > budget and (devices or findings):
        if devices:
            devices.pop()
        else:
            findings.pop()
        trimmed = conclusion.model_copy(update={"impacted_devices": tuple(devices), "findings": tuple(findings)})
    return trimmed


def _unseen_inputs(inputs: AttemptInputs, change: ChangeSet) -> tuple[str, ...]:
    """What this attempt was asked to judge but never saw in full, as bounded reasons.

    A read cap that fired says so directly. A net change is subtler: an object the audit changed more than once
    can end exactly where it started, which compiles to no atom at all, so no ledger row, no obligation and no
    gap would otherwise record that the audit touched it — and another object's clean change could then publish
    complete coverage over it.
    """
    changed = {atom.logical_object_id for atom in change.atoms}
    elided = [
        ELIDED_GAP.format(name=item.name or item.logical_object_id, count=item.intermediate)
        for item in inputs.superseded
        if item.logical_object_id not in changed
    ]
    return (*inputs.gaps, *elided)


def _site_authority(change: ChangeSet, devices: Sequence[ExpectedDevice]) -> SiteAuthority:
    """The sites this attempt may read, fixed before the first read from what the change itself names."""
    sites = {device.site_id for device in devices}
    sites |= {item.site_id for item in change.objects if item.site_id}
    return SiteAuthority(site_ids=frozenset(sites), org_wide=any(item.scope == "org" for item in change.objects))


async def execute_attempt(
    inputs: AttemptInputs,
    *,
    tools: AttemptTools,
    started: float,
    as_of: datetime | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> AttemptOutcome:
    """Run one attempt within its local monotonic phase deadlines and return what the run should record.

    ``started`` is the monotonic instant taken just before the attempt commit was sent, so a slow commit response
    shortens the usable time rather than extending it past the lease. Only change-set construction, the ledger,
    composition and the persistence invariants fail the attempt; every other failure becomes a gap.
    """
    instant = as_of or utc_now()
    registry = EvidenceRegistry()
    try:
        change = build_change_set(inputs.changes)
    except Exception as exc:  # noqa: BLE001 - a change set that cannot be built is the one thing an attempt needs
        return AttemptOutcome(state="failed", failure_reason=bound_reason(ATTEMPT_FAILED.format(detail=exc)))
    anchor = resolve_anchor(
        inputs.receipts,
        audit_id=inputs.audit_id,
        audit_time=inputs.audit_time,
        received_at=inputs.received_at,
        as_of=instant,
    )
    unseen = _unseen_inputs(inputs, change)
    frame = ReplayFrame(audit_id=inputs.audit_id, anchor=anchor, as_of=instant)
    expected = expected_devices(inputs.receipts, audit_id=inputs.audit_id, as_of=instant)
    reader = Reader(
        org_id=str(inputs.organization_id),
        authority=_site_authority(change, expected),
        windows=evidence_windows(anchor.changed_at, instant),
        registry=registry,
        deadlines={"rule": started + RULE_PHASE.total_seconds(), "agent": started + AGENT_PHASE.total_seconds()},
        rule_allowances=rule_allowances(PLUGINS),
        mcp_transport=tools.mcp_transport,
        rule_transport=tools.rule_transport,
        clock=clock,
        secrets=tools.secrets,
    )
    rules = await run_rules(PLUGINS, change, expected, reader)
    try:
        ledger = build_ledger(change, expected, rules.plans, anchor.source, unseen)
    except Exception as exc:  # noqa: BLE001 - the ledger is the attempt's coverage; without it nothing can publish
        return AttemptOutcome(state="failed", failure_reason=bound_reason(ATTEMPT_FAILED.format(detail=exc)))
    deployment_replay = pair_deployments(inputs.receipts, frame=frame, ledger=ledger)
    deployment = record_deployment(deployment_replay, frame=frame, registry=registry)
    monitoring_replay = replay_monitoring(
        inputs.sessions,
        frame=frame,
        ledger=ledger,
        plans=rules.plans,
        expected=expected,
        deployment=deployment_replay,
    )
    monitoring = record_monitoring(monitoring_replay, frame=frame, registry=registry)
    reported: dict[str, ObligationStatus] = {**deployment.statuses, **monitoring.statuses}
    for plugin_id, conclusion in sorted(rules.conclusions.items()):
        if plugin_id in ledger.plan_ids and conclusion.statuses:
            reported |= ledger.rule_statuses(plugin_id, conclusion.statuses)
    covered = coverage(ledger, reported)
    agent = await _agent_run(
        tools=tools,
        reader=reader,
        registry=registry,
        inputs=AgentInputs(
            change=change_view(change),
            deterministic=deterministic_view(ledger, reported),
            hints={plugin.id: plugin.agent_hint for plugin in PLUGINS},
        ),
        deadline=started + AGENT_PHASE.total_seconds(),
        clock=clock,
    )
    try:
        verdict = compose(
            coverage=covered,
            monitoring=monitoring,
            deployment=deployment,
            rules=rules.conclusions,
            agent=agent.conclusion,
            evidence=registry.evidence,
            devices=_device_severities(monitoring_replay.devices),
            core_gaps=unseen,
        )
    except Exception as exc:  # noqa: BLE001 - composition is the attempt's product; a broken verdict is a failure
        return AttemptOutcome(state="failed", failure_reason=bound_reason(ATTEMPT_FAILED.format(detail=exc)))
    statuses = resolve_statuses(ledger, reported)
    share = CONCLUSIONS_BUDGET // (3 + max(len(rules.conclusions), 1))
    return AttemptOutcome(
        state="succeeded",
        fields={
            "anchor": anchor,
            "as_of": instant,
            "change": _fit(change.atoms, budget=CHANGE_VIEW_BUDGET, priority=lambda atom: int(atom.id[1:])),
            "evidence": registry.evidence,
            "ledger": _fit(ledger.rows, budget=LEDGER_VIEW_BUDGET // 2, priority=_row_priority),
            "obligations": _fit(
                [ObligationOutcome(obligation=o, status=statuses[o.id]) for o in ledger.obligations],
                budget=LEDGER_VIEW_BUDGET // 2,
                priority=lambda outcome: int(outcome.obligation.id[1:]),
            ),
            "monitoring": _fit_conclusion(monitoring, share),
            "deployment": _fit_conclusion(deployment, share),
            "rules": {
                name: fitted
                for name, item in sorted(rules.conclusions.items())
                if (fitted := _fit_conclusion(item, share)) is not None
            },
            "agent": _fit_conclusion(agent.conclusion, share),
            "verdict": verdict,
            "steps": _fit(
                [step.model_dump(mode="json") for step in agent.steps],
                budget=STEPS_BUDGET,
                priority=lambda step: step["turn"],
            ),
            "budget": RunBudget(
                model_turns=agent.turns, mcp_calls=reader.budget.mcp_calls, rule_reads=reader.budget.rule_reads
            ),
        },
    )


def _row_priority(row: LedgerRow) -> tuple[int, str]:
    return (int(row.atom_id[1:]), row.target.device_mac or row.target.site_id or "")


def _device_severities(devices: Iterable[DeviceMonitoring]) -> tuple[DeviceSeverity, ...]:
    """The per-device bands only an exclusive monitoring replay measured, for composition's device rows."""
    return tuple(
        DeviceSeverity(
            mac=device.mac, site_id=device.site_id, name=device.name, peak=device.peak, current=device.current
        )
        for device in devices
        if device.site_id and device.peak is not None and device.current is not None
    )


async def _agent_run(  # noqa: PLR0913 - one collaborator or attempt bound per argument
    *,
    tools: AttemptTools,
    reader: Reader,
    registry: EvidenceRegistry,
    inputs: AgentInputs,
    deadline: float,
    clock: Callable[[], float],
) -> AgentRun:
    """The agent, or the explicit reason it was skipped. Nothing it does can fail the attempt."""
    if tools.skip_reason is not None or tools.model_client is None:
        return AgentRun(conclusion=skipped(tools.skip_reason or "No AI runtime is configured"))
    return await run_agent(
        client=tools.model_client,
        reader=reader,
        registry=registry,
        inputs=inputs,
        deadline=deadline,
        clock=clock,
        secrets=tools.secrets,
    )


# -- the tick procedure -------------------------------------------------------------------------------------------


def _status_reason(verdict: Verdict) -> str:
    """The root's completion reason for a published final run, within the stored status-reason bound."""
    summary = bound_reason(verdict.summary) if verdict.summary.strip() else "no summary was recorded"
    return f"Final run: {verdict.peak} impact, {verdict.coverage} coverage. {summary}"[:MAX_STATUS_REASON_CHARS]


def degraded(sessions: Iterable[MonitoringSession], changed_at: datetime) -> bool:
    """Whether a linked session recorded a degradation transition at or after the change.

    The timeline is append-only, so a transition once seen can never become false; the early trigger is only a
    signal, and attribution still comes from the exclusive evidence the attempt replays.
    """
    return any(
        event.event_type in DEGRADATION_EVENTS and event.occurred_at >= changed_at
        for session in sessions
        for event in session.timeline
    )


def due_kind(root: GuardianInvestigation, now: datetime, sessions: Sequence[MonitoringSession]) -> RunKind | None:
    """The read-only trigger evaluation on worker time. ``final`` wins when both are due, so a late early merges.

    Every root-local condition here is repeated in the lease CAS on server time, and the early cutoff again in the
    commit CAS, so a worker clock that is ahead or behind only changes which candidate is looked at.
    """
    final_due = root.attempts.final < MAX_ATTEMPTS_PER_KIND and now >= root.changed_at + FINAL_MINIMUM
    if final_due and (now >= root.changed_at + FINAL_FORCED or not any(session.active for session in sessions)):
        return "final"
    if (
        root.early_run_id is None
        and root.attempts.early < MAX_ATTEMPTS_PER_KIND
        and now < root.changed_at + EARLY_CUTOFF
        and degraded(sessions, root.changed_at)
    ):
        return "early"
    return None


class GuardianService:
    """The one-minute tick: recover, exhaust, evaluate, lease, revalidate, commit, execute, finalize, publish."""

    def __init__(
        self,
        vault: CredentialVault,
        *,
        clock: Callable[[], float] = time.monotonic,
        tools: ToolsFactory | None = None,
    ) -> None:
        self._vault = vault
        self._clock = clock
        self._tools = tools or self._default_tools

    def _default_tools(self, organization: Organization | None) -> AbstractAsyncContextManager[AttemptTools]:
        if organization is None:
            return _NoTools("No AI runtime is configured")
        return GuardianTools(organization, vault=self._vault)

    # -- roots ---------------------------------------------------------
    async def ensure(
        self,
        organization: Organization,
        audit_id: str,
        *,
        changed_at: datetime,
        anchor_known: bool,
    ) -> None:
        """Create this audit's root once. The first check is a worker hint that every server-time CAS re-checks."""
        if organization.id is None:
            return
        now = utc_now()
        write = repo.ensure_investigation(
            organization_id=ObjectId(organization.id),
            audit_id=audit_id,
            changed_at=changed_at,
            anchor_known=anchor_known,
            now=now,
            retained_until=_retained_until(organization, now),
        )
        await self._roots().update_one(write.filter, write.update, upsert=write.upsert)

    async def poll_due(self) -> int:
        """Run one tick over the candidates the due query selects. Each root is isolated from the others."""
        candidates = (
            await GuardianInvestigation.find(repo.due_candidates_filter(utc_now()))
            .sort(*(f"+{name}" for name, _ in repo.DUE_SORT))
            .limit(repo.DUE_LIMIT)
            .to_list()
        )
        handled = 0
        for root in candidates:
            try:
                await self.tick(root)
            except Exception:
                logger.exception("Guardian tick failed for investigation %s", root.id)
            else:
                handled += 1
        return handled

    async def tick(self, root: GuardianInvestigation) -> None:
        """One root's tick, in the design's numbered order. Every step re-checks its own server-time conditions."""
        if root.id is None:
            return
        organization = await Organization.get(root.organization_id)
        if root.claim is not None:
            await self._recover(root, organization)
            return
        if root.attempts.final >= MAX_ATTEMPTS_PER_KIND and root.final_run_id is None:
            await self._exhaust(root)
            return
        sessions, _gaps = await linked_sessions(root.organization_id, root.audit_id)
        kind = due_kind(root, utc_now(), sessions)
        if kind is None:
            write = repo.nothing_due(root.id)
            await self._roots().update_one(write.filter, write.update)
            return
        await self._attempt(root, organization, kind=kind)

    async def _revalidated(self, root: GuardianInvestigation, *, kind: RunKind, forced: bool) -> bool:
        """The kind's cross-collection conditions, re-read under the lease with the claim's own server branch."""
        sessions, _gaps = await linked_sessions(root.organization_id, root.audit_id)
        if kind == "final":
            return forced or not any(session.active for session in sessions)
        return degraded(sessions, root.changed_at)

    # -- one attempt ---------------------------------------------------
    async def _attempt(self, root: GuardianInvestigation, organization: Organization | None, *, kind: RunKind) -> None:
        """Steps 4 to 10: lease, revalidate, commit, create the run, execute, finalize and publish."""
        root_id = root.id
        if root_id is None:
            return
        token = ObjectId()
        fence = repo.ClaimFence(root_id=root_id, token=token)
        lease = repo.lease(root_id, kind=kind, token=token)
        leased = await self._roots().find_one_and_update(
            lease.filter, lease.update, return_document=ReturnDocument.AFTER
        )
        if leased is None:
            return
        # The forced branch is the server's, taken when the lease was written, never the worker's own evaluation.
        forced = bool((leased.get("claim") or {}).get("final_forced"))
        if not await self._revalidated(root, kind=kind, forced=forced):
            await self._release(fence)
            return
        # The attempt deadline starts here, just before the commit is sent, so a slow or ambiguous response
        # shortens the usable time instead of extending it past the server-side lease.
        started = self._clock()
        committed = await self._commit(fence, root=root, organization=organization, kind=kind)
        if committed is None:
            return
        run = repo.running_run_document(committed, now=utc_now())
        try:
            await self._runs().insert_one(run)
        except DuplicateKeyError:
            return
        outcome = await self._execute(root, organization, committed, started=started)
        finalized = await self._finalize(committed, outcome)
        if finalized is not None:
            await self._publish(finalized)

    async def _commit(
        self,
        fence: repo.ClaimFence,
        *,
        root: GuardianInvestigation,
        organization: Organization | None,
        kind: RunKind,
    ) -> repo.CommittedAttempt | None:
        """Consume one attempt. An ambiguous response is resolved by reading the root, never by retrying.

        A definite no-match frees the uncommitted lease, so a later tick proceeds without waiting it out. An
        ambiguous response only stops: the update may have applied after all, and the lease's own expiry is what
        resolves it, so nothing here may free a claim it cannot prove is still uncommitted.
        """
        write = repo.commit_attempt(fence, kind=kind)
        ambiguous = False
        try:
            claimed = await self._roots().find_one_and_update(
                write.filter, write.update, return_document=ReturnDocument.AFTER
            )
        except PyMongoError:
            ambiguous = True
            claimed = await self._roots().find_one(repo.commit_applied_filter(fence))
        if claimed is None:
            if not ambiguous:
                await self._release(fence)
            return None
        claim = claimed.get("claim") or {}
        attempt, started_at = claim.get("attempt"), claim.get("started_at")
        if attempt is None or started_at is None:
            return None
        return repo.CommittedAttempt(
            token=fence.token,
            organization_id=root.organization_id,
            investigation_id=fence.root_id,
            audit_id=root.audit_id,
            kind=kind,
            attempt=attempt,
            started_at=started_at.replace(tzinfo=UTC) if started_at.tzinfo is None else started_at,
            retained_until=_retained_until(organization, utc_now()),
        )

    async def _execute(
        self,
        root: GuardianInvestigation,
        organization: Organization | None,
        committed: repo.CommittedAttempt,
        *,
        started: float,
    ) -> AttemptOutcome:
        as_of = utc_now()
        try:
            inputs = await load_attempt_inputs(root, as_of=as_of)
            async with self._tools(organization) as tools:
                return await execute_attempt(inputs, tools=tools, started=started, as_of=as_of, clock=self._clock)
        except Exception as exc:
            # An attempt that cannot load its inputs or reach its collaborators fails alone; the root retries.
            logger.exception("Guardian attempt %s failed", committed.token)
            return AttemptOutcome(state="failed", failure_reason=bound_reason(ATTEMPT_FAILED.format(detail=exc)))

    async def _finalize(self, committed: repo.CommittedAttempt, outcome: AttemptOutcome) -> GuardianRun | None:
        """Validate the whole run and its size, then move it out of ``running``. No match means it was abandoned."""
        now = utc_now()
        try:
            run = self._validated(committed, outcome, now=now)
        except (ValidationError, RunDocumentTooLargeError) as exc:
            outcome = AttemptOutcome(state="failed", failure_reason=bound_reason(RUN_TOO_LARGE.format(detail=exc)))
            run = self._validated(committed, outcome, now=now)
        write = repo.finalize_run(
            committed.token,
            state="succeeded" if outcome.state == "succeeded" else "failed",
            fields={name: _stored(value) for name, value in outcome.fields.items()},
            failure_reason=outcome.failure_reason,
        )
        result = await self._runs().update_one(write.filter, write.update)
        return run if result.modified_count else None

    @staticmethod
    def _validated(committed: repo.CommittedAttempt, outcome: AttemptOutcome, *, now: datetime) -> GuardianRun:
        """The whole run as it will be stored, validated before anything is written or published."""
        run = GuardianRun(
            id=committed.token,
            organization_id=committed.organization_id,
            investigation_id=committed.investigation_id,
            audit_id=committed.audit_id,
            kind=committed.kind,
            attempt=committed.attempt,
            state="succeeded" if outcome.state == "succeeded" else "failed",
            started_at=committed.started_at,
            finished_at=now,
            deadline_at=committed.started_at + PUBLISH_PHASE,
            failure_reason=outcome.failure_reason,
            retained_until=committed.retained_until,
            **outcome.fields,
        )
        check_run_document_size(run)
        return run

    async def _publish(self, run: GuardianRun) -> None:
        """Publish one terminal run behind a fence built from the run itself, never from the root's claim."""
        if run.id is None:
            return
        fence = repo.ClaimFence(root_id=run.investigation_id, token=run.id, attempt=run.attempt)
        if run.state == "succeeded" and run.verdict is not None:
            result = GuardianResult.from_verdict(
                run_id=run.id, run_kind=run.kind, evaluated_at=run.finished_at or utc_now(), verdict=run.verdict
            )
            write = repo.publish_succeeded_run(
                fence,
                kind=run.kind,
                result=_encoded(result),
                status_reason=_status_reason(run.verdict) if run.kind == "final" else None,
            )
        else:
            write = repo.publish_failed_run(fence)
        await self._roots().update_one(write.filter, write.update)

    async def _release(self, fence: repo.ClaimFence) -> None:
        write = repo.release(fence)
        await self._roots().update_one(write.filter, write.update)

    # -- recovery and exhaustion ---------------------------------------
    async def _recover(self, root: GuardianInvestigation, organization: Organization | None) -> None:
        """Resolve an expired claim while the root still holds its exact token, then stop for this tick."""
        claim = root.claim
        if claim is None or root.id is None:
            return
        fence = repo.ClaimFence(root_id=root.id, token=claim.token, attempt=claim.attempt)
        if claim.attempt is None:
            write = repo.recover_uncommitted_claim(fence)
            await self._roots().update_one(write.filter, write.update)
            return
        if await self._roots().find_one(repo.expired_committed_claim_filter(fence)) is None:
            return
        run = await self._resolved_run(root, fence, organization)
        if run is not None:
            await self._publish(run)

    async def _resolved_run(
        self, root: GuardianInvestigation, fence: repo.ClaimFence, organization: Organization | None
    ) -> GuardianRun | None:
        """The committed attempt's terminal run: inserted, marked abandoned, or read back. Two passes suffice.

        The read is scoped to the organization and investigation as well as the token, so a claim can only ever
        resolve its own tenant's run.
        """
        claim = root.claim
        if claim is None or claim.attempt is None or claim.started_at is None:
            return None
        scope = repo.claimed_run(fence, organization_id=root.organization_id)
        attempt = repo.CommittedAttempt(
            token=fence.token,
            organization_id=root.organization_id,
            investigation_id=fence.root_id,
            audit_id=root.audit_id,
            kind=claim.kind,
            attempt=claim.attempt,
            started_at=claim.started_at,
            retained_until=_retained_until(organization, utc_now()),
        )
        for _pass in range(2):
            run = await GuardianRun.find_one(scope)
            if run is None:
                # A duplicate key means another worker inserted it first, which the next pass reads back.
                with contextlib.suppress(DuplicateKeyError):
                    await self._runs().insert_one(repo.abandoned_run_document(attempt, now=utc_now()))
                continue
            if run.state != "running":
                return run
            write = repo.abandon_running_run(fence.token)
            await self._runs().update_one(write.filter, write.update)
        return await GuardianRun.find_one(scope)

    async def _exhaust(self, root: GuardianInvestigation) -> None:
        """Complete a root whose final attempts all failed, with the last final run's own recorded reason."""
        if root.id is None:
            return
        read = repo.last_failed_final_run(root.id, organization_id=root.organization_id)
        rows = (
            await self._runs()
            .find(read.filter, read.projection)
            .sort(list(read.sort))
            .to_list(length=MAX_ATTEMPTS_PER_KIND)
        )
        reason = str(rows[0]["failure_reason"]) if rows else NO_FAILURE_REASON
        write = repo.exhaust_final_attempts(root.id, last_failure_reason=bound_reason(reason))
        await self._roots().update_one(write.filter, write.update)

    # -- collections ---------------------------------------------------
    @staticmethod
    def _roots() -> Any:  # noqa: ANN401 - the driver's own collection type
        return GuardianInvestigation.get_pymongo_collection()

    @staticmethod
    def _runs() -> Any:  # noqa: ANN401 - the driver's own collection type
        return GuardianRun.get_pymongo_collection()


def _stored(value: object) -> Any:  # noqa: ANN401 - one run outcome field as the driver stores it
    if isinstance(value, BaseModel):
        return _encoded(value)
    if isinstance(value, Mapping):
        return {str(key): _stored(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_stored(item) for item in value]
    return value
