"""The WLAN authentication rule: the same clients before and after a change to how a WLAN authenticates them.

Ported from ``integrations/mist_auth_evidence.py`` and the authentication half of ``impact/domain_evaluation.py``.
Only a client that authenticated successfully before the change and failed after it counts, a later success for that
client is recovery, and contradictory outcomes in one second stay unresolved. No attempt at all is ``not_exercised``:
missing attempts were never successful joins. Client identities are counted, never reported.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from mist_config_guardian_backend.guardian.change import ChangedObject, ChangeSet
from mist_config_guardian_backend.guardian.contracts import (
    Band,
    ChangeAtom,
    Conclusion,
    DeviceImpact,
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
from mist_config_guardian_backend.guardian.reader import Reader, RuleRead, RuleReading, WindowName

ID = "wlan-auth"
VERSION = "1"
MAX_READS = 2
EVENT_LIMIT = "1000"
SHOWN_DEVICES = 10

# The attributes that decide how a WLAN authenticates a client, as the ported rule resolved them.
AUTH_ATTRIBUTES = frozenset(
    {
        "auth",
        "auth_servers",
        "auth_server_selection",
        "auth_servers_nas_id",
        "auth_servers_nas_ip",
        "auth_servers_retries",
        "auth_servers_timeout",
        "dynamic_psk",
    }
)
SUCCESSES = frozenset({"CLIENT_AUTHENTICATED", "CLIENT_AUTH_ASSOCIATION", "CLIENT_AUTH_REASSOCIATION"})
FAILURES = frozenset(
    {
        "MARVIS_EVENT_CLIENT_AUTH_FAILURE",
        "MARVIS_EVENT_CLIENT_AUTH_DENIED",
        "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE",
    }
)

AGENT_HINT = (
    "Investigate authentication outcomes on the exact changed WLAN. Compare the same clients before and after the "
    "change, keeping successful authentication and recovery as counterevidence. Cached sessions do not test new "
    "credentials. Missing attempts are not successful joins. Failure counts are not a failure rate without attempt "
    "denominators. Unrelated RADIUS, RF or AP-health observations cannot establish attribution. Never request or "
    "repeat secret configuration values."
)

ORG_WLAN_GAP = "Organization WLAN consumer resolution is not implemented; assume the change is effective."
NO_COHORT_GAP = "No access point at this site had an audit-linked configuration change, so no device row is claimed."
SCOPE_REASON = "The authentication evidence named another WLAN"
IDENTITY_REASON = "An authentication event carried no usable client identity, so the clients cannot be paired"
CONTRADICTION_REASON = "Same-time contradictory authentication outcomes remain unresolved"
ATTRIBUTION_TEXT = "Causation is provisional; RADIUS, RF and client-side causes remain unresolved."
QUIET_TEXT = "No attempt is not successful authentication."


class WlanAuthPlan(base.PluginPlan):
    """The one WLAN whose authentication events this attempt can read."""

    site_id: Identifier | None = None
    wlan_id: Identifier | None = None
    label: Identifier = ""


@dataclass(frozen=True, slots=True)
class Attempts:
    """What the paired event reads say, or the one reason they cannot be relied on."""

    reason: str = ""
    attempted: bool = False
    affected: int = 0
    recovered: int = 0
    access_points: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _Attempt:
    at: float
    outcome: str
    access_point: str | None


@dataclass
class _Client:
    before: list[_Attempt] = field(default_factory=list)
    after: list[_Attempt] = field(default_factory=list)


class WlanAuthPlugin:
    """WLAN authentication attributes: authentication outcomes for that WLAN, before against after."""

    id = ID
    version = VERSION
    max_reads = MAX_READS
    agent_hint = AGENT_HINT

    def plan(self, change: ChangeSet, devices: Sequence[ExpectedDevice]) -> RulePlan | None:
        gaps: list[str] = []
        candidates = [
            (changed, atoms)
            for changed in base.objects_of(change, "wlans")
            if (atoms := _auth_atoms(change, changed, gaps))
        ]
        if not candidates:
            return WlanAuthPlan(gaps=base.gaps_within(gaps)) if gaps else None
        candidates.sort(key=lambda item: (item[0].site_id or "", item[0].mist_id or ""))
        changed, atoms = candidates[0]
        if len(candidates) > 1:
            gaps.append(
                f"{len(candidates) - 1} further WLAN(s) with changed authentication were not checked; "
                f"this attempt reads one WLAN's authentication events."
            )
        site_id, wlan_id = str(changed.site_id), str(changed.mist_id)
        cohort = base.cohort(devices, device_type="ap", site_id=site_id)
        if not cohort:
            gaps.append(NO_COHORT_GAP)
        return WlanAuthPlan(
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
            gaps=base.gaps_within(gaps),
            site_id=site_id,
            wlan_id=wlan_id,
            label=base.identifier(changed.name),
        )

    async def collect(self, plan: RulePlan, reader: Reader) -> list[RuleReading]:
        target = _plan(plan)
        if target.wlan_id is None or not target.obligations:
            return []
        return [await base.read(reader, _read(target, window)) for window in ("before", "after")]

    def evaluate(self, plan: RulePlan, readings: Sequence[RuleReading]) -> RuleConclusion:
        target = _plan(plan)
        ids = base.obligation_ids(target)
        reading = _attempts(target, readings)
        if not ids or reading.reason:
            unsatisfied = ObligationStatus(status="unsatisfied", reason=base.text(reading.reason))
            return Conclusion(statuses=dict.fromkeys(ids, unsatisfied), gaps=target.gaps)
        cited = tuple(item.id for item in readings if item.evidence.citable)
        if not reading.attempted:
            return Conclusion(
                statuses=dict.fromkeys(ids, ObligationStatus(status="not_exercised", evidence_ids=cited)),
                findings=(
                    Finding(
                        text=base.text(
                            f"No authentication attempt was observed on WLAN {target.label or target.wlan_id} in "
                            f"either window. {QUIET_TEXT}"
                        ),
                        severity="none",
                        evidence_ids=cited,
                    ),
                ),
                gaps=target.gaps,
            )
        peak: Band = "warning" if reading.affected else "none"
        current: Band = "none" if reading.recovered == reading.affected else "warning"
        return Conclusion(
            statuses=dict.fromkeys(ids, ObligationStatus(status="satisfied", evidence_ids=cited)),
            peak=peak,
            current=current,
            findings=(Finding(text=_finding_text(target, reading), severity=peak, evidence_ids=cited),),
            impacted_devices=tuple(
                DeviceImpact(mac=mac, severity="warning", evidence_ids=cited)
                for mac in reading.access_points[:SHOWN_DEVICES]
            ),
            gaps=target.gaps,
        )


def _finding_text(plan: WlanAuthPlan, reading: Attempts) -> str:
    wlan = plan.label or plan.wlan_id
    if not reading.affected:
        return base.text(
            f"Every client that authenticated on WLAN {wlan} before the change kept authenticating after it. "
            f"{QUIET_TEXT}"
        )
    recovered = f", of which {reading.recovered} authenticated again" if reading.recovered else ""
    return base.text(
        f"{reading.affected} client(s) that authenticated on WLAN {wlan} before the change failed after it"
        f"{recovered}. {ATTRIBUTION_TEXT}"
    )


def _attempts(plan: WlanAuthPlan, readings: Sequence[RuleReading]) -> Attempts:
    """Pair the before and after reads and compare each client with itself."""
    ordered = [item for item in readings if item.evidence.window is not None]
    ordered.sort(key=base.window_start)
    if len(ordered) != base.PAIRED_READS:
        return Attempts(reason=base.NOT_READ_REASON)
    results = [base.read_rows(item) for item in ordered]
    if not all(result.complete for result in results):
        return Attempts(reason=next(result.reason for result in results if result.reason))
    clients: dict[str, _Client] = {}
    for result, window in zip(results, ("before", "after"), strict=True):
        for row in result.rows:
            failure = _record(plan, row, window, clients)
            if failure:
                return Attempts(reason=failure)
    affected, recovered, access_points = _compare(clients)
    if affected is None:
        return Attempts(reason=CONTRADICTION_REASON)
    return Attempts(
        attempted=any(client.before or client.after for client in clients.values()),
        affected=affected,
        recovered=recovered,
        access_points=access_points,
    )


def _record(plan: WlanAuthPlan, row: Mapping[str, object], window: str, clients: dict[str, _Client]) -> str:
    """Accept one authentication event, or return why the whole read cannot be used."""
    if base.string(row.get("wlan_id")) not in (None, plan.wlan_id):
        return SCOPE_REASON
    kind = base.string(row.get("type"))
    if kind not in SUCCESSES | FAILURES:
        return ""
    client = base.mac(row.get("mac"))
    at = base.number(row.get("timestamp"))
    if client is None or at is None:
        return IDENTITY_REASON
    attempt = _Attempt(
        at=at, outcome="success" if kind in SUCCESSES else "failure", access_point=base.mac(row.get("ap"))
    )
    attempts = clients.setdefault(client, _Client())
    (attempts.before if window == "before" else attempts.after).append(attempt)
    return ""


def _compare(clients: Mapping[str, _Client]) -> tuple[int | None, int, tuple[str, ...]]:
    """Clients that authenticated before and failed after, how many authenticated again, and the serving APs."""
    affected = 0
    recovered = 0
    access_points: set[str] = set()
    for attempts in clients.values():
        ordered = sorted((*attempts.before, *attempts.after), key=lambda item: item.at)
        if any(len({item.outcome for item in ordered if item.at == other.at}) > 1 for other in ordered):
            return None, 0, ()
        before = sorted(attempts.before, key=lambda item: item.at)
        after = sorted(attempts.after, key=lambda item: item.at)
        failures = [item for item in after if item.outcome == "failure"]
        if not (before and before[-1].outcome == "success" and failures):
            continue
        affected += 1
        if after[-1].outcome == "success":
            recovered += 1
        access_points.update(item.access_point for item in failures if item.access_point)
    return affected, recovered, tuple(sorted(access_points))


def _auth_atoms(change: ChangeSet, changed: ChangedObject, gaps: list[str]) -> tuple[ChangeAtom, ...]:
    """The changed authentication attributes of a WLAN that still exists.

    A deleted WLAN is a lifecycle change, not an authentication change, and every other changed attribute of the
    WLAN stays unclaimed, so a mixed edit leaves those paths uncovered.
    """
    if changed.change_kind == "deleted":
        return ()
    atoms = tuple(atom for atom in base.atoms_of(change, changed) if atom.attribute in AUTH_ATTRIBUTES)
    if not atoms:
        return ()
    if changed.scope == "org":
        gaps.append(ORG_WLAN_GAP)
        return ()
    if not changed.site_id or not changed.mist_id:
        gaps.append(
            f"WLAN {changed.name or changed.logical_object_id}: the site or provider identity of the change is "
            f"unknown, so its authentication events cannot be read."
        )
        return ()
    return atoms


def _read(plan: WlanAuthPlan, window: WindowName) -> RuleRead:
    return RuleRead(
        plugin=ID,
        title=base.text(f"Authentication events of WLAN {plan.label or plan.wlan_id} {window} the change"),
        kind="service_health",
        path=f"/api/v1/sites/{plan.site_id}/clients/events/search",
        params={"wlan_id": str(plan.wlan_id), "limit": EVENT_LIMIT},
        site_id=plan.site_id,
        window=window,
    )


def _plan(plan: RulePlan) -> WlanAuthPlan:
    if not isinstance(plan, WlanAuthPlan):
        msg = f"{ID} was given another plug-in's plan"
        raise base.PluginError(msg)
    return plan
