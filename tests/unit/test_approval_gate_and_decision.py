"""Approval gate (REQ-014, REQ-015) and decision model and findings (REQ-017, REQ-018)."""

from __future__ import annotations

import dataclasses

import pytest
from helpers import POLICY, plan_path

from iac_change_control import policy_engine
from iac_change_control.models import BLOCKED, ERROR, PASS, RULE_CATALOG, WARN, Approval, Finding
from iac_change_control.plan_loader import load_plan, load_policy
from iac_change_control.rules import approval_gate

POLICY_OBJ = load_policy(POLICY)
COMPLIANT = load_plan(plan_path("compliant"))
DESTROY = load_plan(plan_path("destroy-change"))


def approval_for(plan, **override) -> Approval:
    fields = {
        "approval_id": "APR-LAB-9001",
        "status": "approved",
        "scope": dict(plan.change_context),
        "approval_level": "standard",
        "approver_role": "synthetic-change-reviewer",
        "change_set_digest": plan.change_set_digest,
        "policy_version": POLICY_OBJ.policy_version,
        "approved_destructive_addresses": plan.destructive_addresses,
    }
    fields.update(override)
    return Approval(**fields)


def results(assessment):
    return {c["check_id"]: c["result"] for c in assessment.checks}


def failed(plan, approval):
    return approval_gate.assess(plan, approval, POLICY_OBJ).failed_checks


# -- REQ-014 --------------------------------------------------------------------------------
def test_gate_valid_approval():
    assessment = approval_gate.assess(COMPLIANT, approval_for(COMPLIANT), POLICY_OBJ)
    assert assessment.valid and assessment.gate_result == "valid"
    assert set(results(assessment).values()) == {"pass"}
    assert [c["check_id"] for c in assessment.checks] == [f"IAC-APR-00{i}" for i in range(1, 8)]


def test_gate_no_approval_file():
    assessment = approval_gate.assess(COMPLIANT, None, POLICY_OBJ)
    assert assessment.failed_checks == ["IAC-APR-001"]
    assert not assessment.approval_provided
    assert list(results(assessment).values())[1:] == ["not_evaluated"] * 6


def test_gate_not_submitted():
    approval = Approval("APR-LAB-9002", "not_submitted", dict(COMPLIANT.change_context))
    assessment = approval_gate.assess(COMPLIANT, approval, POLICY_OBJ)
    assert assessment.failed_checks == ["IAC-APR-001"] and assessment.approval_provided


def test_gate_rejected():
    assessment = approval_gate.assess(
        COMPLIANT, approval_for(COMPLIANT, status="rejected"), POLICY_OBJ
    )
    assert assessment.failed_checks == ["IAC-APR-002"]
    assert list(results(assessment).values())[2:] == ["not_evaluated"] * 5


def test_gate_stale():
    assert failed(COMPLIANT, approval_for(COMPLIANT, policy_version="0.9.0")) == ["IAC-APR-003"]


def test_gate_out_of_scope():
    other_env = {"change_ref": COMPLIANT.change_context["change_ref"], "environment": "lab-staging"}
    assert failed(COMPLIANT, approval_for(COMPLIANT, scope=other_env)) == ["IAC-APR-004"]
    other_ref = {"change_ref": "LAB-CHG-0999", "environment": "lab-dev"}
    assert failed(COMPLIANT, approval_for(COMPLIANT, scope=other_ref)) == ["IAC-APR-004"]


def test_gate_digest_mismatch():
    wrong = "sha256:" + "0" * 64
    assert failed(COMPLIANT, approval_for(COMPLIANT, change_set_digest=wrong)) == ["IAC-APR-005"]
    # Every failing check is reported, not just the first.
    combined = approval_for(COMPLIANT, change_set_digest=wrong, policy_version="0.1.0")
    assert failed(COMPLIANT, combined) == ["IAC-APR-003", "IAC-APR-005"]


# -- REQ-015 --------------------------------------------------------------------------------
def test_gate_destructive_requires_elevated():
    assert failed(DESTROY, approval_for(DESTROY)) == ["IAC-APR-006"]
    assert failed(DESTROY, approval_for(DESTROY, approval_level="elevated")) == []


def test_gate_destructive_address_mismatch():
    partial = (DESTROY.destructive_addresses[0],)
    assessment = approval_gate.assess(
        DESTROY,
        approval_for(DESTROY, approval_level="elevated", approved_destructive_addresses=partial),
        POLICY_OBJ,
    )
    assert assessment.failed_checks == ["IAC-APR-007"]
    detail = assessment.checks[6]["detail"]
    assert "not listed: labcloud_firewall_rule.web_https" in detail


def test_gate_lists_addresses_without_destructive_changes():
    approval = approval_for(
        COMPLIANT, approved_destructive_addresses=("labcloud_block_disk.app_data",)
    )
    assessment = approval_gate.assess(COMPLIANT, approval, POLICY_OBJ)
    assert assessment.failed_checks == ["IAC-APR-007"]
    assert "listed but not destructive" in assessment.checks[6]["detail"]


# -- REQ-017 --------------------------------------------------------------------------------
def test_finding_fields_complete():
    finding = Finding("IAC-NET-001", "labcloud_firewall_rule.x", "ingress", "why", "fix")
    record = finding.to_dict()
    assert set(record) == {
        "rule_id",
        "title",
        "severity",
        "blocking",
        "requires_elevated_approval",
        "address",
        "detail_key",
        "reason",
        "remediation",
    }
    assert record["title"] == RULE_CATALOG["IAC-NET-001"].title
    with pytest.raises(ValueError):
        Finding("IAC-XXX-999", "a", "b", "c", "d")
    for info in RULE_CATALOG.values():
        assert info.severity in {"critical", "high", "medium", "low"}


def test_findings_sorted_by_stable_key():
    findings = [
        Finding("IAC-TAG-001", "labcloud_block_disk.b", "tags", "r", "m"),
        Finding("IAC-IAM-001", "labcloud_iam_policy.p", "statements[010]", "r", "m"),
        Finding("IAC-IAM-001", "labcloud_iam_policy.p", "statements[002]", "r", "m"),
        Finding("IAC-TAG-001", "labcloud_block_disk.a", "tags", "r", "m"),
        Finding("IAC-APR-005", "change-set", "digest_matches", "r", "m"),
    ]
    ordered = policy_engine.sort_findings(findings)
    assert [f.sort_key for f in ordered] == sorted(f.sort_key for f in findings)
    assert ordered == policy_engine.sort_findings(list(reversed(findings)))
    assert [f.rule_id for f in ordered] == [
        "IAC-APR-005",
        "IAC-IAM-001",
        "IAC-IAM-001",
        "IAC-TAG-001",
        "IAC-TAG-001",
    ]


# -- REQ-018 --------------------------------------------------------------------------------
def test_decision_table():
    blocking = Finding("IAC-ENC-001", "a.b", "encryption", "r", "m")
    nonblocking = Finding("IAC-NET-002", "a.b", "ingress", "r", "m")
    assert policy_engine.decide((), True) == PASS
    assert policy_engine.decide((nonblocking,), True) == WARN
    assert policy_engine.decide((blocking,), True) == BLOCKED
    assert policy_engine.decide((nonblocking, blocking), True) == BLOCKED
    assert policy_engine.decide((), False) == BLOCKED
    assert policy_engine.decide((nonblocking,), False) == BLOCKED


def test_internal_error_is_error_not_pass(monkeypatch):
    class Exploding:
        @staticmethod
        def evaluate(plan, policy):
            raise RuntimeError("simulated rule defect")

    monkeypatch.setattr(policy_engine, "POLICY_RULES", (Exploding,))
    result = policy_engine.evaluate(plan_path("compliant"), None, POLICY, "internal-error")
    assert result.decision == ERROR and result.exit_code == 2
    assert [(e.source, e.code) for e in result.errors] == [
        ("evaluator", "evaluator_internal_error")
    ]
    assert "simulated rule defect" not in result.errors[0].message
    assert result.findings == ()
    assert dataclasses.replace(result, errors=()).exit_code == 2  # decision alone fixes the code
