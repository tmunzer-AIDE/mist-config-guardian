"""Conservative held-out acceptance counts; no synthetic or model supplied ground truth."""

from hashlib import sha256
from importlib.resources import files
from typing import Literal

from pydantic import Field

from mist_config_guardian_backend.impact.contracts import Contract

MIN_CASES, MAX_CASES, MIN_HELD_OUT_CLASS = 20, 50, 3

VerdictLabel = Literal["critical_outage", "benign", "noncritical_outage", "uncertain"]


def policy_hash() -> str:
    """Invalidate acceptance when a load-bearing rule, resolver or contract changes."""
    digest = sha256(b"impact-acceptance.v1")
    for filename in ("contracts.py", "domain_evaluation.py", "wlan_removal.py", "port_scope.py", "limits.py"):
        digest.update(filename.encode())
        digest.update(files("mist_config_guardian_backend.impact").joinpath(filename).read_bytes())
    package = files("mist_config_guardian_backend")
    for path in (
        "snapshots/registry.py",
        "services/impact_investigations.py",
        "services/neighbor_bindings.py",
        "integrations/mist_wlan_evidence.py",
        "integrations/mist_port_evidence.py",
        "integrations/mist_neighbor_evidence.py",
        "integrations/mist_port_history.py",
        "integrations/mist_auth_evidence.py",
    ):
        digest.update(path.encode())
        digest.update(package.joinpath(path).read_bytes())
    return digest.hexdigest()


def held_out(audit_id: str) -> bool:
    return int(sha256(f"impact-holdout.v1:{audit_id}".encode()).hexdigest()[:8], 16) % 4 == 0


class AcceptanceCase(Contract):
    audit_id: str
    label: VerdictLabel
    predicted: Literal["none", "info", "warning", "critical"]
    valid: bool


class AcceptanceResult(Contract):
    policy_hash: str
    eligible: bool = False
    total: int = 0
    held_out: int = 0
    true_positive: int = 0
    false_negative: int = 0
    false_positive: int = 0
    true_negative: int = 0
    critical_misses: int = 0
    abstentions: int = 0
    recall: float | None = None
    precision: float | None = None
    specificity: float | None = None
    reasons: tuple[str, ...] = ()
    scope: Literal["adjudicated_held_out_cases"] = "adjudicated_held_out_cases"
    activation: Literal["manual_release_required"] = "manual_release_required"


class AdjudicationRequest(Contract):
    report_id: str = Field(pattern=r"^[0-9a-f]{24}$")
    revision: int = Field(ge=1)
    label: VerdictLabel
    rationale: str = Field(min_length=10, max_length=1500)
    human_reviewed: Literal[True]


def acceptance(cases: list[AcceptanceCase], *, fingerprint: str) -> AcceptanceResult:
    """Unknowns and duplicate/conflicting labels cannot make a release pass."""
    reasons = []
    if not MIN_CASES <= len(cases) <= MAX_CASES:
        reasons.append("Adjudicate 20 to 50 distinct historical changes before promotion.")
    if len({c.audit_id for c in cases}) != len(cases):
        reasons.append("Duplicate or conflicting audit labels require resolution.")
    if any(not c.valid or c.label == "uncertain" for c in cases):
        reasons.append("Missing, altered or unresolved evidence fails acceptance.")
    held = [c for c in cases if held_out(c.audit_id)]
    positives = [c for c in held if c.label in {"critical_outage", "noncritical_outage"}]
    negatives = [c for c in held if c.label == "benign"]
    if sum(c.label == "critical_outage" for c in positives) < MIN_HELD_OUT_CLASS or len(negatives) < MIN_HELD_OUT_CLASS:
        reasons.append("The fixed held-out subset requires at least three critical outages and three benign changes.")
    tp = sum(c.valid and c.predicted in {"warning", "critical"} for c in positives)
    critical_misses = sum(
        c.label == "critical_outage" and (not c.valid or c.predicted != "critical") for c in positives
    )
    fn = len(positives) - tp
    fp = sum(c.valid and c.predicted in {"warning", "critical"} for c in negatives)
    tn = sum(c.valid and c.predicted == "none" for c in negatives)
    abstentions = sum(not c.valid or c.predicted == "info" or c.label == "uncertain" for c in held)
    if fn or fp or abstentions or critical_misses:
        reasons.append("Held-out misses, false alarms or abstentions fail closed; ties do not pass.")
    if any(c.label == "benign" and c.predicted == "critical" for c in cases):
        reasons.append("A false critical attribution exists in the adjudicated set.")
    return AcceptanceResult(
        policy_hash=fingerprint,
        eligible=not reasons,
        total=len(cases),
        held_out=len(held),
        true_positive=tp,
        false_negative=fn,
        critical_misses=critical_misses,
        false_positive=fp,
        true_negative=tn,
        abstentions=abstentions,
        recall=tp / len(positives) if positives else None,
        precision=tp / (tp + fp) if tp + fp else None,
        specificity=tn / len(negatives) if negatives else None,
        reasons=tuple(reasons),
    )
