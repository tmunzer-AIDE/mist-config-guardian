"""Device-event driven post-change monitoring."""

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.integrations.impact_ai import (
    AiImpactError,
    OpenAiCompatibleImpactProvider,
)
from mist_config_guardian_backend.integrations.mist_sle import MistSleClient
from mist_config_guardian_backend.integrations.mist_telemetry import MistTelemetryClient
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    ImpactSeverity,
    MonitoringIncident,
    MonitoringSession,
    MonitoringStatus,
    MonitoringTimelineEvent,
    SleObservation,
)
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.telemetry import DeviceStateComparison, DeviceStateObservation
from mist_config_guardian_backend.models.webhook import WebhookReceipt
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.application_configuration import (
    ApplicationConfigurationError,
    ApplicationConfigurationService,
    ImpactAiRuntimeConfiguration,
)
from mist_config_guardian_backend.services.change_groups import ChangeGroupProjector
from mist_config_guardian_backend.services.device_impact import compare_device_states, refresh_device_findings
from mist_config_guardian_backend.services.impact_analysis import (
    ImpactAssessment,
    assess_impact,
    store_assessment,
)
from mist_config_guardian_backend.services.service_credentials import service_token

_PRE_CONFIG_EVENTS = {
    "AP_CONFIG_CHANGED_BY_RRM",
    "AP_CONFIG_CHANGED_BY_USER",
    "GW_CONFIG_CHANGED_BY_USER",
    "SW_CONFIG_CHANGED_BY_USER",
}
_CONFIGURED_EVENTS = {"AP_CONFIGURED", "GW_CONFIGURED", "SW_CONFIGURED"}
_FAILED_EVENTS = {"AP_CONFIG_FAILED", "GW_CONFIG_FAILED", "SW_CONFIG_FAILED"}
_INCIDENT_EVENTS = {
    "AP_DISCONNECTED",
    "GW_BGP_NEIGHBOR_DOWN",
    "GW_DISCONNECTED",
    "GW_OSPF_NEIGHBOR_DOWN",
    "GW_TUNNEL_DOWN",
    "GW_VPN_PATH_DOWN",
    "SW_BGP_NEIGHBOR_DOWN",
    "SW_DISCONNECTED",
    "SW_OSPF_NEIGHBOR_DOWN",
    "SW_VC_PORT_DOWN",
}
_REVERT_EVENTS = {"GW_CONFIG_REVERTED", "SW_CONFIG_REVERTED"}
_RESOLUTIONS = {
    "AP_CONNECTED": "AP_DISCONNECTED",
    "GW_CONNECTED": "GW_DISCONNECTED",
    "GW_TUNNEL_UP": "GW_TUNNEL_DOWN",
    "GW_VPN_PATH_UP": "GW_VPN_PATH_DOWN",
    "SW_CONNECTED": "SW_DISCONNECTED",
    "SW_BGP_NEIGHBOR_UP": "SW_BGP_NEIGHBOR_DOWN",
    "SW_OSPF_NEIGHBOR_UP": "SW_OSPF_NEIGHBOR_DOWN",
    "GW_BGP_NEIGHBOR_UP": "GW_BGP_NEIGHBOR_DOWN",
    "GW_OSPF_NEIGHBOR_UP": "GW_OSPF_NEIGHBOR_DOWN",
    "SW_VC_PORT_UP": "SW_VC_PORT_DOWN",
}
_MONITORING_DURATION = timedelta(hours=1)
_POLL_INTERVAL = timedelta(minutes=5)
_DEVICE_COMPARISON_DELAY = timedelta(minutes=5)
_BASELINE_ANCHOR = timedelta(hours=1)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeviceEvent:
    """Normalized fields from a Mist device event."""

    event_type: str
    device_mac: str
    site_id: str
    payload: dict[str, object]


class MonitoringEventService:
    """Pair pre/post config events and record incidents."""

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault

    async def handle(  # noqa: PLR0911 - one return per class of device event
        self,
        receipt: WebhookReceipt,
        payload: dict[str, object],
        organization: Organization,
    ) -> MonitoringSession | None:
        """Apply one relevant device event and return the session it changed.

        The caller rebuilds the change groups that session belongs to. It has to
        come from here rather than a later lookup: a failure event closes its
        session, and a device carries a history of sessions, so nothing about
        the device alone identifies the one this event actually touched.
        """
        if receipt.topic != "device-events":
            return None
        event_type = self._first_string(payload, "type", "event_type")
        device_mac = self._first_string(payload, "mac", "device_mac", "ap_mac")
        site_id = self._first_string(payload, "site_id")
        if not event_type or not device_mac or not site_id:
            return None
        event = DeviceEvent(
            event_type=event_type,
            device_mac=device_mac.replace(":", "").replace("-", "").lower(),
            site_id=site_id,
            payload=payload,
        )
        already_handled = (
            await MonitoringSession.find_one({"organization_id": receipt.organization_id, "receipt_ids": receipt.id})
            if receipt.id
            else None
        )
        if already_handled is not None:
            return already_handled
        session = await MonitoringSession.find_one(
            MonitoringSession.organization_id == receipt.organization_id,
            MonitoringSession.device_mac == event.device_mac,
            MonitoringSession.active == True,  # noqa: E712
        )

        if event_type in _PRE_CONFIG_EVENTS:
            return await self._start_or_merge(
                receipt,
                organization,
                event,
                session,
            )
        if event_type in _CONFIGURED_EVENTS:
            return await self._mark_configured(
                receipt,
                organization,
                event,
                session,
            )
        if session is not None and event_type in _FAILED_EVENTS | _INCIDENT_EVENTS | _REVERT_EVENTS:
            self._link_receipt(session, receipt)
            self._record_event(session, event, receipt)
            await self._record_incident(session, event_type)
            return session
        if session is not None and event_type in _RESOLUTIONS:
            self._link_receipt(session, receipt)
            self._record_event(session, event, receipt)
            self._resolve_incidents(session, event_type)
            session.touch()
            await session.save()
            return session
        if session is not None and "_CONFIG" in event_type:
            self._link_receipt(session, receipt)
            self._record_event(session, event, receipt)
            session.touch()
            await session.save()
            return session
        return None

    @staticmethod
    def _resolve_incidents(session: MonitoringSession, event_type: str) -> None:
        now = utc_now()
        for incident in session.incidents:
            if incident.event_type == _RESOLUTIONS[event_type] and not incident.resolved:
                incident.resolved = True
                incident.resolved_at = now
        store_assessment(
            session,
            assess_impact(
                session.baseline,
                session.observations[-1] if session.observations else None,
                session.incidents,
                relevance_plan=session.relevance_plan,
                device_findings=session.device_findings,
            ),
        )

    @staticmethod
    def _record_event(session: MonitoringSession, event: DeviceEvent, receipt: WebhookReceipt) -> None:
        key = str(receipt.id) if receipt.id else f"{event.event_type}:{receipt.created_at.isoformat()}"
        if not any(item.key == key for item in session.timeline):
            session.timeline.append(
                MonitoringTimelineEvent(
                    key=key,
                    event_type=event.event_type,
                    occurred_at=event_time(event, receipt),
                    received_at=receipt.created_at,
                    audit_id=receipt.audit_id,
                )
            )

    @staticmethod
    async def _record_incident(
        session: MonitoringSession,
        event_type: str,
    ) -> None:
        severity = ImpactSeverity.CRITICAL if event_type in _FAILED_EVENTS | _REVERT_EVENTS else ImpactSeverity.WARNING
        session.incidents.append(MonitoringIncident(event_type=event_type, severity=severity))
        assessment = assess_impact(
            session.baseline,
            session.observations[-1] if session.observations else None,
            session.incidents,
            relevance_plan=session.relevance_plan,
            device_findings=session.device_findings,
        )
        session.peak_impact_severity = max_severity(session.peak_impact_severity, assessment.severity)
        if event_type in _FAILED_EVENTS and session.status is MonitoringStatus.AWAITING_CONFIG:
            session.status = MonitoringStatus.FAILED
            session.active = False
            session.completed_at = utc_now()
            assessment.summary = "The configuration failed before monitoring could begin."
        elif event_type in _REVERT_EVENTS:
            # The reverted configuration is no longer under test. Release the
            # unique active-device slot so a later change gets a fresh baseline.
            session.status = MonitoringStatus.FAILED
            session.active = False
            session.completed_at = utc_now()
            session.next_poll_at = None
            assessment.summary = "The configuration was reverted; monitoring for this change has ended."
        store_assessment(session, assessment)
        session.touch()
        await session.save()

    async def _start_or_merge(
        self,
        receipt: WebhookReceipt,
        organization: Organization,
        event: DeviceEvent,
        session: MonitoringSession | None,
    ) -> MonitoringSession:
        if session is not None:
            await self._add_comparison(session, organization, event, receipt)
        if session is None:
            device_type = device_type_from_event(event.event_type)
            triggered_at = event_time(event, receipt)
            baseline, device_baseline = await asyncio.gather(
                self._capture(organization, event.site_id, device_type, event.device_mac, triggered_at),
                self._capture_state(organization, event.site_id, device_type, event.device_mac),
            )
            now = utc_now()
            session = MonitoringSession(
                organization_id=receipt.organization_id,
                audit_ids=[receipt.audit_id] if receipt.audit_id else [],
                receipt_ids=[receipt.id] if receipt.id else [],
                site_id=event.site_id,
                device_mac=event.device_mac,
                device_name=self._first_string(
                    event.payload,
                    "device_name",
                    "ap",
                    "switch_name",
                )
                or "",
                device_type=device_type,
                baseline=baseline,
                device_comparisons=[
                    DeviceStateComparison(
                        triggered_at=triggered_at,
                        baseline=device_baseline,
                        due_at=device_baseline.captured_at + _DEVICE_COMPARISON_DELAY,
                    )
                ],
                change_triggered_at=triggered_at,
                status=MonitoringStatus.MONITORING,
                monitoring_started_at=now,
                monitoring_ends_at=now + _MONITORING_DURATION,
                next_poll_at=device_baseline.captured_at + _DEVICE_COMPARISON_DELAY,
            )
            store_assessment(session, assess_impact(baseline, None, [], relevance_plan=session.relevance_plan))
            try:
                await session.insert()
            except DuplicateKeyError:
                session = await MonitoringSession.find_one(
                    MonitoringSession.organization_id == receipt.organization_id,
                    MonitoringSession.device_mac == event.device_mac,
                    MonitoringSession.active == True,  # noqa: E712
                )
                if session is None:
                    raise
                await self._add_comparison(session, organization, event, receipt)
        self._link_receipt(session, receipt)
        self._record_event(session, event, receipt)
        session.touch()
        await session.save()
        return session

    async def _add_comparison(
        self, session: MonitoringSession, organization: Organization, event: DeviceEvent, receipt: WebhookReceipt
    ) -> None:
        initial = await self._capture_state(organization, event.site_id, session.device_type, event.device_mac)
        due = initial.captured_at + _DEVICE_COMPARISON_DELAY
        session.device_comparisons.append(
            DeviceStateComparison(
                triggered_at=event_time(event, receipt),
                baseline=initial,
                due_at=due,
            )
        )
        session.status = MonitoringStatus.MONITORING
        session.monitoring_started_at = session.monitoring_started_at or utc_now()
        session.monitoring_ends_at = utc_now() + _MONITORING_DURATION
        session.next_poll_at = min(session.next_poll_at, due) if session.next_poll_at else due
        warning = (
            "Multiple configuration triggers overlap; device comparisons are separate, "
            "but SLE and incidents span the combined monitoring window."
        )
        if warning not in session.warnings:
            session.warnings.append(warning)

    async def _mark_configured(
        self,
        receipt: WebhookReceipt,
        organization: Organization,
        event: DeviceEvent,
        session: MonitoringSession | None,
    ) -> MonitoringSession:
        if session is None:
            session = await self._start_or_merge(receipt, organization, event, None)
            session.warnings.append(
                "Pre-change device event was missed. SLE baseline uses the preceding 24 hours; "
                "initial device state was captured after configuration and may already include its effects."
            )

        now = utc_now()
        session.status = MonitoringStatus.MONITORING
        session.config_applied_at = session.config_applied_at or event_time(event, receipt)
        session.monitoring_started_at = now
        session.monitoring_ends_at = now + _MONITORING_DURATION
        session.next_poll_at = now + _POLL_INTERVAL
        for comparison in session.device_comparisons:
            if comparison.followup is None:
                session.next_poll_at = min(session.next_poll_at, comparison.due_at)
        self._link_receipt(session, receipt)
        self._record_event(session, event, receipt)
        session.touch()
        await session.save()
        return session

    async def _capture(
        self,
        organization: Organization,
        site_id: str,
        device_type: DeviceType,
        device_mac: str,
        triggered_at: datetime,
    ) -> SleObservation:
        token = await service_token(organization, self._vault)
        async with MistSleClient(token=token, region=organization.cloud_region) as client:
            return await client.capture(
                site_id=site_id,
                device_type=device_type,
                device_mac=device_mac,
                start=triggered_at - timedelta(hours=24),
                end=triggered_at,
                # The whole day is kept as trend, but the comparison anchors on
                # the final hour: post-change polls measure minutes to an hour,
                # and a 24-hour mean smooths across a day/night cycle the change
                # had nothing to do with.
                anchor=_BASELINE_ANCHOR,
            )

    async def _capture_state(
        self, organization: Organization, site_id: str, device_type: DeviceType, device_mac: str
    ) -> DeviceStateObservation:
        token = await service_token(organization, self._vault)
        async with MistTelemetryClient(token=token, region=organization.cloud_region) as client:
            return await client.capture(site_id=site_id, device_mac=device_mac, device_type=device_type)

    @staticmethod
    def _link_receipt(session: MonitoringSession, receipt: WebhookReceipt) -> None:
        if receipt.id and receipt.id not in session.receipt_ids:
            session.receipt_ids.append(receipt.id)
        if receipt.audit_id and receipt.audit_id not in session.audit_ids:
            session.audit_ids.append(receipt.audit_id)

    @staticmethod
    def _first_string(payload: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
        return None


class MonitoringPollService:
    """Capture due SLE snapshots and finalize bounded windows."""

    def __init__(
        self,
        vault: CredentialVault,
        application_configuration: ApplicationConfigurationService,
        projector: ChangeGroupProjector | None = None,
    ) -> None:
        self._vault = vault
        self._application_configuration = application_configuration
        self._projector = projector or ChangeGroupProjector()

    async def poll_active(self) -> int:
        """Poll every due active session once."""
        now = utc_now()
        # Capture identities before transitioning each due session so its change
        # groups learn that monitoring was abandoned, with its own evidence intact.
        timed_out = await MonitoringSession.find(
            MonitoringSession.status == MonitoringStatus.AWAITING_CONFIG,
            {"created_at": {"$lte": now - timedelta(minutes=10)}},
        ).to_list()
        for session in timed_out:
            assessment = assess_impact(
                session.baseline,
                session.observations[-1] if session.observations else None,
                session.incidents,
                relevance_plan=session.relevance_plan,
                device_findings=session.device_findings,
            )
            assessment.evaluated_at = now
            assessment.summary = "No configured event was received within 10 minutes."
            # Retain each session's metric evidence; a common empty bulk result
            # would erase the very gaps the timeout needs to explain. The status
            # predicate avoids overwriting a concurrently configured session.
            await MonitoringSession.find(
                {"_id": session.id, "status": MonitoringStatus.AWAITING_CONFIG},
            ).update_many(
                {
                    "$set": {
                        "status": MonitoringStatus.FAILED,
                        "active": False,
                        "next_poll_at": None,
                        "completed_at": now,
                        "updated_at": now,
                        "assessment": assessment.model_dump(mode="python"),
                        "impact_severity": assessment.severity,
                        "deterministic_summary": assessment.summary,
                        "degraded_metrics": list(assessment.degraded_metrics),
                    },
                    "$push": {
                        "warnings": "Monitoring was cancelled because the paired configured event was not received."
                    },
                }
            )
            await self._refresh_change_groups(session)
        sessions = await MonitoringSession.find(
            MonitoringSession.status == MonitoringStatus.MONITORING,
            {"next_poll_at": {"$lte": now}},
        ).to_list()
        for session in sessions:
            try:
                await self._poll_session(session, now)
            except Exception:
                logger.exception("Unable to poll monitoring session %s", session.id)
                warning = "A monitoring poll failed; collection will be retried."
                if warning not in session.warnings:
                    session.warnings.append(warning)
                session.next_poll_at = now + _POLL_INTERVAL
                session.touch()
                await session.save()
        return len(sessions)

    @staticmethod
    def _warn_unidentified_baseline(session: MonitoringSession, observation: SleObservation) -> None:
        if session.baseline and session.baseline.scope_id is None and observation.scope_id is not None:
            warning = "Baseline scope identity is unknown; SLE values are retained without comparable deltas."
            if warning not in session.warnings:
                session.warnings.append(warning)

    async def _poll_session(
        self,
        session: MonitoringSession,
        now: datetime,
    ) -> None:
        organization = await Organization.get(session.organization_id)
        if organization is None:
            session.status = MonitoringStatus.FAILED
            session.active = False
            session.warnings.append("Managed organization no longer exists.")
            session.touch()
            await session.save()
            return
        token = await service_token(organization, self._vault)
        async with MistSleClient(token=token, region=organization.cloud_region) as client:
            observation = await client.capture(
                site_id=session.site_id,
                device_type=session.device_type,
                # Older persisted baselines were site-wide. Keep polling their
                # original scope rather than comparing a site to one device.
                device_mac=session.device_mac if session.baseline and session.baseline.scope == "device" else None,
                start=session.config_applied_at or session.change_triggered_at or session.monitoring_started_at,
                end=now,
            )
        await self._compare_due_states(session, organization, token, now)
        self._warn_unidentified_baseline(session, observation)
        session.observations.append(observation)
        assessment = assess_impact(
            session.baseline,
            observation,
            session.incidents,
            device_findings=session.device_findings,
            relevance_plan=session.relevance_plan,
        )
        assessment.evaluated_at = now
        if session.impact_severity != assessment.severity:
            session.timeline.append(
                MonitoringTimelineEvent(
                    key=f"assessment:{now.isoformat()}",
                    event_type=f"ASSESSMENT_{assessment.severity.value.upper()}",
                    occurred_at=now,
                    received_at=now,
                )
            )
        session.peak_impact_severity = max_severity(
            session.peak_impact_severity, max_severity(session.impact_severity, assessment.severity)
        )
        store_assessment(session, assessment)
        if session.monitoring_ends_at is not None and now >= session.monitoring_ends_at:
            try:
                ai_configuration = await self._application_configuration.impact_ai_runtime()
            except ApplicationConfigurationError as exc:
                session.ai_assessment_error = str(exc)
            else:
                if ai_configuration is not None:
                    await self._assess_with_ai(
                        session,
                        assessment,
                        ai_configuration,
                    )
        if session.monitoring_ends_at is not None and now >= session.monitoring_ends_at:
            session.status = MonitoringStatus.COMPLETED
            session.active = False
            session.completed_at = now
            session.next_poll_at = None
        else:
            session.next_poll_at = now + _POLL_INTERVAL
            for comparison in session.device_comparisons:
                if comparison.followup is None:
                    session.next_poll_at = min(session.next_poll_at, comparison.due_at)
        session.touch()
        await session.save()
        await self._refresh_change_groups(session)

    @staticmethod
    async def _compare_due_states(
        session: MonitoringSession, organization: Organization, token: str, now: datetime
    ) -> None:
        due = [item for item in session.device_comparisons if now >= item.due_at]
        if due:
            async with MistTelemetryClient(token=token, region=organization.cloud_region) as telemetry:
                followup = await telemetry.capture(
                    site_id=session.site_id,
                    device_type=session.device_type,
                    device_mac=session.device_mac,
                )
            for comparison in due:
                previous = (
                    comparison.current_findings if comparison.current_findings is not None else comparison.findings
                )
                previous_observation = comparison.latest or comparison.followup
                if comparison.followup is None:
                    comparison.followup = followup
                    comparison.findings = compare_device_states(comparison.baseline, followup)
                comparison.current_findings = refresh_device_findings(
                    comparison.baseline, followup, previous, previous_observation
                )
                comparison.latest = followup
                if previous and not comparison.current_findings:
                    comparison.recovered_at = followup.captured_at
                elif comparison.current_findings:
                    comparison.recovered_at = None
            session.device_findings = [
                finding
                for item in session.device_comparisons
                for finding in (item.current_findings if item.current_findings is not None else item.findings)
            ]

    async def _refresh_change_groups(self, session: MonitoringSession) -> None:
        """Recompute the projections of every change group this session feeds.

        Severity and recovery state live on the change group, so without this a
        group's projection would only refresh on the next webhook for that audit
        and the Changes page would keep reporting a stale recovery state. The
        rebuild is idempotent, so running it on every poll is safe.
        """
        for audit_id in session.audit_ids:
            try:
                await self._projector.rebuild(session.organization_id, audit_id)
            except Exception:
                logger.exception(
                    "Unable to refresh the change-group projection for audit %s",
                    audit_id,
                )

    async def _assess_with_ai(
        self,
        session: MonitoringSession,
        assessment: ImpactAssessment,
        configuration: ImpactAiRuntimeConfiguration,
    ) -> None:
        if get_settings().impact_engine_mode != "legacy":
            return
        async with OpenAiCompatibleImpactProvider(
            base_url=configuration.base_url,
            model=configuration.model,
            api_key=configuration.api_key,
        ) as provider:
            try:
                session.ai_assessment = await provider.assess(assessment)
                session.ai_assessment_error = None
            except AiImpactError as exc:
                session.ai_assessment_error = str(exc)


def device_type_from_event(event_type: str) -> DeviceType:
    """Infer device type from Mist's event prefix."""
    if event_type.startswith("AP_"):
        return DeviceType.AP
    if event_type.startswith("GW_"):
        return DeviceType.GATEWAY
    return DeviceType.SWITCH


def max_severity(left: ImpactSeverity, right: ImpactSeverity) -> ImpactSeverity:
    """Return the more severe impact value."""
    order = {
        ImpactSeverity.NONE: 0,
        ImpactSeverity.INFO: 1,
        ImpactSeverity.WARNING: 2,
        ImpactSeverity.CRITICAL: 3,
    }
    return left if order[left] >= order[right] else right


def event_time(event: DeviceEvent, receipt: WebhookReceipt) -> datetime:
    """Accept source times within 24 hours before receipt, allowing one minute of clock skew."""
    value = event.payload.get("timestamp", event.payload.get("time"))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            reported = datetime.fromtimestamp(value, tz=UTC)
            # Receipt-relative bounds stay stable when processing is retried.
            if receipt.created_at - timedelta(hours=24) <= reported <= receipt.created_at + timedelta(minutes=1):
                return reported
        except (ValueError, OverflowError, OSError):
            pass
    return receipt.created_at
