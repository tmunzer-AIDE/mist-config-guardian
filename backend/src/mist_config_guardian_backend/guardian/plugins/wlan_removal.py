"""The WLAN lifecycle rule: a site WLAN that was deleted or disabled, and the client sessions it was serving.

Ported from ``impact/wlan_removal.py`` and ``integrations/mist_wlan_evidence.py``. What it proves is unchanged: a
client that was connected before the change and disconnected after it is a *possible* disruption of that WLAN's
service, never an access-point failure, a cause, or a failed join. Missing or truncated session evidence is never
zero usage, and no aggregate infrastructure health can reach this rule's severity.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from mist_config_guardian_backend.guardian.change import ChangedObject, ChangeSet
from mist_config_guardian_backend.guardian.contracts import (
    ChangeAtom,
    Conclusion,
    DeviceImpact,
    Evidence,
    ExpectedDevice,
    Finding,
    Identifier,
    Obligation,
    ObligationStatus,
    RuleConclusion,
    RulePlan,
    Target,
)
from mist_config_guardian_backend.guardian.plugins import base
from mist_config_guardian_backend.guardian.reader import Reader, RuleRead, WindowName

ID = "wlan-removal"
VERSION = "1"
MAX_READS = 2
SESSION_LIMIT = "1000"
SHOWN_DEVICES = 10

AGENT_HINT = (
    "Investigate removal/disable only in the resolved WLAN cohort. Compare prior usage and subsequent disconnects. "
    "Successful roaming and ordinary departures are counterevidence. Missing sessions are not zero clients. Serving "
    "APs describe client service, not AP failure. Failed new joins are a separate gap. Never use aggregate AP health "
    "for the WLAN lifecycle verdict. Cite only observed current checks; describe unresolved consumers explicitly."
)

ORG_WLAN_GAP = "Organization WLAN consumer resolution is not implemented; assume the change is effective."
NO_COHORT_GAP = "No access point at this site had an audit-linked configuration change, so no device row is claimed."
DISRUPTION_TEXT = "Ordinary disconnects or roaming remain possible; AP failure and causation are not established."
QUIET_TEXT = "Failed joins and unrecorded sessions are not covered."
SCOPE_REASON = "The session evidence named another WLAN"


class WlanRemovalPlan(base.PluginPlan):
    """The one WLAN this attempt can read, and what its obligations claim."""

    site_id: Identifier | None = None
    wlan_id: Identifier | None = None
    label: Identifier = ""


@dataclass(frozen=True, slots=True)
class Sessions:
    """What the paired session reads say, or the one reason they cannot be relied on."""

    reason: str = ""
    baseline: int = 0
    clients: frozenset[str] = frozenset()
    access_points: tuple[str, ...] = ()


class WlanRemovalPlugin:
    """Site WLAN deleted or disabled: client sessions for that WLAN, before against after."""

    id = ID
    version = VERSION
    max_reads = MAX_READS
    agent_hint = AGENT_HINT

    def plan(self, change: ChangeSet, devices: Sequence[ExpectedDevice]) -> RulePlan | None:
        gaps: list[str] = []
        candidates = [
            (changed, atoms)
            for changed in base.objects_of(change, "wlans")
            if (atoms := _lifecycle_atoms(change, changed, gaps))
        ]
        if not candidates:
            return WlanRemovalPlan(gaps=base.gaps_within(gaps)) if gaps else None
        candidates.sort(key=lambda item: (item[0].site_id or "", item[0].mist_id or ""))
        changed, atoms = candidates[0]
        if len(candidates) > 1:
            gaps.append(
                f"{len(candidates) - 1} further changed WLAN(s) were not checked; "
                f"this attempt reads one WLAN's client sessions."
            )
        site_id, wlan_id = str(changed.site_id), str(changed.mist_id)
        cohort = base.cohort(devices, device_type="ap", site_id=site_id)
        if not cohort:
            gaps.append(NO_COHORT_GAP)
        return WlanRemovalPlan(
            obligations=base.numbered(
                [
                    Obligation(
                        id="O1",
                        owner=ID,
                        change_ref=atom.id,
                        paths=atom.paths,
                        role="observation",
                        kind="rule",
                        target=Target(device_mac=mac, site_id=site_id, wlan_id=wlan_id),
                    )
                    for atom in atoms
                    for mac in cohort
                ]
            ),
            finding_kinds=("ssid_removed", "radio_wlans_reduced"),
            gaps=base.gaps_within(gaps),
            site_id=site_id,
            wlan_id=wlan_id,
            label=base.identifier(changed.name),
        )

    async def collect(self, plan: RulePlan, reader: Reader) -> list[Evidence]:
        target = _plan(plan)
        if target.wlan_id is None or not target.obligations:
            return []
        return [await reader.read(_read(target, window)) for window in ("before", "after")]

    def evaluate(self, plan: RulePlan, evidence: Sequence[Evidence]) -> RuleConclusion:
        target = _plan(plan)
        ids = base.obligation_ids(target)
        reading = _sessions(target, evidence)
        if not ids or reading.reason:
            unsatisfied = ObligationStatus(status="unsatisfied", reason=base.text(reading.reason))
            return Conclusion(statuses=dict.fromkeys(ids, unsatisfied), gaps=target.gaps)
        cited = tuple(item.id for item in evidence)
        severity = "warning" if reading.clients else "none"
        return Conclusion(
            statuses=dict.fromkeys(ids, ObligationStatus(status="satisfied", evidence_ids=cited)),
            peak=severity,
            current=severity,
            findings=(Finding(text=_finding_text(target, reading), severity=severity, evidence_ids=cited),),
            impacted_devices=tuple(
                DeviceImpact(mac=mac, severity="warning", evidence_ids=cited)
                for mac in reading.access_points[:SHOWN_DEVICES]
            ),
            gaps=target.gaps,
        )


def _finding_text(plan: WlanRemovalPlan, reading: Sessions) -> str:
    wlan = plan.label or plan.wlan_id
    if reading.clients:
        return base.text(
            f"{len(reading.clients)} of {reading.baseline} client(s) connected to WLAN {wlan} before the change "
            f"disconnected after it. {DISRUPTION_TEXT}"
        )
    return base.text(
        f"None of the {reading.baseline} client(s) connected to WLAN {wlan} before the change disconnected after "
        f"it. {QUIET_TEXT}"
    )


def _sessions(plan: WlanRemovalPlan, evidence: Sequence[Evidence]) -> Sessions:
    """Pair the before and after reads, and count the clients that were connected and then left."""
    ordered = [item for item in evidence if item.window is not None]
    ordered.sort(key=base.window_start)
    if len(ordered) != base.PAIRED_READS:
        return Sessions(reason=base.NOT_READ_REASON)
    before, after = (base.read_rows(item) for item in ordered)
    if not before.complete or not after.complete:
        return Sessions(reason=before.reason or after.reason)
    if any(base.string(row.get("wlan_id")) not in (None, plan.wlan_id) for row in (*before.rows, *after.rows)):
        return Sessions(reason=SCOPE_REASON)
    window = ordered[1].window
    if window is None:  # pragma: no cover - ordered holds only evidence with a window
        return Sessions(reason=base.NOT_READ_REASON)
    connected = {mac for row in before.rows if (mac := base.string(row.get("mac")))}
    departures = [row for row in after.rows if _departed(row, window.start, window.end)]
    clients = frozenset(mac for row in departures if (mac := base.string(row.get("mac"))) in connected)
    return Sessions(
        baseline=len(connected),
        clients=clients,
        access_points=tuple(
            sorted(
                {
                    access_point
                    for row in departures
                    if base.string(row.get("mac")) in clients
                    and (access_point := base.mac(base.string(row.get("ap")))) is not None
                }
            )
        ),
    )


def _departed(row: Mapping[str, object], changed_at: datetime, end: datetime) -> bool:
    """A session that started before the change and ended between the change and the end of the after window."""
    connect, disconnect = base.number(row.get("connect")), base.number(row.get("disconnect"))
    if connect is None or disconnect is None:
        return False
    return connect < changed_at.timestamp() and changed_at.timestamp() <= disconnect <= end.timestamp()


def _lifecycle_atoms(change: ChangeSet, changed: ChangedObject, gaps: list[str]) -> tuple[ChangeAtom, ...]:
    """The atoms a removal or disablement of this WLAN explains: every atom of a deleted object, else ``enabled``.

    A WLAN that did not exist before the change cannot have lost a client, and every other changed attribute of a
    WLAN that merely stopped serving stays unclaimed, so a mixed edit leaves those paths uncovered.
    """
    if changed.change_kind == "created":
        return ()
    atoms = tuple(
        atom
        for atom in base.atoms_of(change, changed)
        if changed.change_kind == "deleted" or (atom.attribute == "enabled" and not _turned_on(change, atom))
    )
    if not atoms:
        return ()
    if changed.scope == "org":
        gaps.append(ORG_WLAN_GAP)
        return ()
    if not changed.site_id or not changed.mist_id:
        gaps.append(
            f"WLAN {changed.name or changed.logical_object_id}: the site or provider identity of the change is "
            f"unknown, so its client sessions cannot be read."
        )
        return ()
    return atoms


def _turned_on(change: ChangeSet, atom: ChangeAtom) -> bool:
    """Whether the change switched the WLAN on. Atoms carry paths, so the direction comes from the masked view."""
    return any(item.after == "true" for item in change.masked.get(atom.id, ()))


def _read(plan: WlanRemovalPlan, window: WindowName) -> RuleRead:
    return RuleRead(
        plugin=ID,
        title=base.text(f"Client sessions of WLAN {plan.label or plan.wlan_id} {window} the change"),
        kind="service_health",
        path=f"/api/v1/sites/{plan.site_id}/clients/sessions/search",
        params={"wlan_id": str(plan.wlan_id), "limit": SESSION_LIMIT},
        site_id=plan.site_id,
        window=window,
    )


def _plan(plan: RulePlan) -> WlanRemovalPlan:
    if not isinstance(plan, WlanRemovalPlan):
        msg = f"{ID} was given another plug-in's plan"
        raise base.PluginError(msg)
    return plan
