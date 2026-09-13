"""Held-out precision and recall gate; unknowns never satisfy production readiness."""

from datetime import timedelta
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.impact.acceptance import AcceptanceCase, acceptance, held_out, policy_hash
from mist_config_guardian_backend.impact.contracts import SessionRow
from mist_config_guardian_backend.impact.wlan_removal import evaluate_wlan_removal
from mist_config_guardian_backend.models.investigation import InvestigationRevision
from mist_config_guardian_backend.services.impact_acceptance import replay_chain
from test_impact_report import report_inputs
from test_wlan_investigation import LATER, NOW, ORG


def acceptance_cases():
    held = [f"audit-{n}" for n in range(200) if held_out(f"audit-{n}")][:6]
    train = [f"audit-{n}" for n in range(200) if not held_out(f"audit-{n}")][:14]
    return [
        AcceptanceCase(
            audit_id=a,
            label="critical_outage" if i < 3 else "benign",
            predicted="critical" if i < 3 else "none",
            valid=True,
        )
        for i, a in enumerate(held + train)
    ]


def test_empty_set_has_no_rates_and_cannot_activate():
    result = acceptance([], fingerprint=policy_hash())
    assert not result.eligible
    assert result.recall is None
    assert result.precision is None
    assert result.specificity is None
    assert result.activation == "manual_release_required"


def test_balanced_heldout_reports_counts_and_requires_manual_release():
    result = acceptance(acceptance_cases(), fingerprint=policy_hash())
    assert result.eligible
    assert (result.true_positive, result.false_negative, result.false_positive, result.true_negative) == (3, 0, 0, 3)
    assert result.recall == result.precision == result.specificity == 1


@pytest.mark.parametrize(
    ("index", "update"),
    [
        (0, {"predicted": "none"}),
        (0, {"predicted": "warning"}),
        (3, {"predicted": "warning"}),
        (3, {"predicted": "info"}),
        (0, {"valid": False}),
        (6, {"label": "uncertain"}),
    ],
)
def test_misses_false_alarms_abstentions_or_unresolved_cases_fail(index, update):
    cases = acceptance_cases()
    cases[index] = cases[index].model_copy(update=update)
    assert not acceptance(cases, fingerprint="test").eligible


def test_duplicate_labels_do_not_increase_sample_size():
    cases = acceptance_cases()
    cases[-1] = cases[0]
    assert not acceptance(cases, fingerprint="test").eligible


async def test_replay_preserves_earlier_loss_and_rejects_a_foreign_parent(monkeypatch):
    data = report_inputs()
    row = SessionRow(
        client_mac="001122334455",
        ap_mac="aabbccddeeff",
        connected_at=NOW - timedelta(minutes=2),
        disconnected_at=NOW + timedelta(minutes=1),
    )
    readings = [e.model_copy(update={"rows": (row,)}) for e in data["evidence"]]
    parent = InvestigationRevision.model_construct(
        id=PydanticObjectId(),
        organization_id=ORG,
        investigation_id=PydanticObjectId(),
        revision=1,
        generated_at=LATER,
        plan=data["plan"],
        evidence=readings,
        assessment=evaluate_wlan_removal(data["plan"], readings, evidence_as_of=LATER),
    )
    head = parent.model_copy(
        update={
            "id": PydanticObjectId(),
            "revision": 2,
            "previous_report_id": parent.id,
            "evidence": [],
            "assessment": evaluate_wlan_removal(data["plan"], [], evidence_as_of=LATER),
        }
    )
    monkeypatch.setattr(InvestigationRevision, "find_one", AsyncMock(return_value=parent))
    replay = await replay_chain(head)
    assert replay[1] == "warning"
    parent.evidence = []
    changed = await replay_chain(head)
    assert changed[0] != replay[0]
    parent.organization_id = PydanticObjectId()
    assert await replay_chain(head) is None
