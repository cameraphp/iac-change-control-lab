"""Fixture-level outcomes for each control: REQ-008 to REQ-017."""

from __future__ import annotations

import pytest
from helpers import POLICY, approval_path, matching_approval, plan_path, write_json

from iac_change_control.plan_loader import load_plan
from iac_change_control.policy_engine import evaluate


def run(plan: str, approval: str | None):
    return evaluate(
        plan_path(plan), approval_path(approval) if approval else None, POLICY, "matrix"
    )


def rule_ids(result) -> list[str]:
    return [f.rule_id for f in result.findings]


def test_fixture_public_ingress_blocked():
    result = run("public-ingress", "approved-public-ingress")
    assert result.decision == "BLOCKED" and result.exit_code == 1
    assert [(f.rule_id, f.address) for f in result.findings] == [
        ("IAC-NET-001", "labcloud_firewall_rule.admin_ssh"),
        ("IAC-NET-001", "labcloud_firewall_rule.debug_all"),
    ]
    assert result.assessment.valid


def test_fixture_wildcard_iam_blocked():
    result = run("wildcard-iam", "approved-wildcard-iam")
    assert result.decision == "BLOCKED"
    assert [(f.rule_id, f.detail_key) for f in result.findings] == [
        ("IAC-IAM-001", "statements[000]")
    ]


def test_fixture_unencrypted_storage_blocked():
    result = run("unencrypted-storage", "approved-unencrypted-storage")
    assert result.decision == "BLOCKED"
    assert [(f.rule_id, f.address) for f in result.findings] == [
        ("IAC-ENC-001", "labcloud_block_disk.scratch"),
        ("IAC-ENC-001", "labcloud_database_instance.reports"),
        ("IAC-ENC-001", "labcloud_storage_bucket.app_logs"),
    ]


def test_fixture_destroy_with_standard_approval_blocked():
    result = run("destroy-change", "approved-destroy-standard")
    assert result.decision == "BLOCKED"
    assert rule_ids(result) == ["IAC-APR-006", "IAC-CHG-001", "IAC-CHG-001"]


def test_fixture_destroy_with_elevated_approval_warns():
    result = run("destroy-change", "approved-destroy-elevated")
    assert result.decision == "WARN" and result.exit_code == 0
    assert rule_ids(result) == ["IAC-CHG-001", "IAC-CHG-001"]
    assert result.assessment.valid


def test_fixture_missing_tags_blocked():
    result = run("missing-tags", "approved-missing-tags")
    assert result.decision == "BLOCKED"
    assert [(f.address, f.reason) for f in result.findings] == [
        (
            "labcloud_block_disk.cache",
            "required tag(s) missing or blank: owner, environment, cost_center",
        ),
        (
            "labcloud_storage_bucket.app_logs",
            "required tag(s) missing or blank: owner, cost_center",
        ),
    ]


def test_fixture_provider_version_violation_blocked():
    result = run("provider-version-violation", "approved-provider-version-violation")
    assert result.decision == "BLOCKED"
    assert [(f.rule_id, f.address) for f in result.findings] == [
        ("IAC-VER-001", "terraform"),
        ("IAC-VER-002", "provider.labdns"),
        ("IAC-VER-003", "provider.labcloud"),
        ("IAC-VER-004", "provider.labcloud"),
    ]


@pytest.mark.parametrize(
    ("approval", "expected"),
    [
        ("missing-approval", ["IAC-APR-001"]),
        (None, ["IAC-APR-001"]),
        ("rejected-approval", ["IAC-APR-002"]),
        ("stale-or-out-of-scope-approval", ["IAC-APR-003", "IAC-APR-004"]),
        ("digest-mismatch-approval", ["IAC-APR-005"]),
    ],
)
def test_fixture_approval_matrix(approval, expected):
    result = run("compliant", approval)
    assert result.decision == "BLOCKED" and result.exit_code == 1
    assert rule_ids(result) == expected
    assert result.assessment.failed_checks == expected


def test_mixed_violations_sorted():
    result = run("mixed-violations", "approved-mixed-violations")
    assert result.decision == "BLOCKED"
    assert [(f.rule_id, f.address) for f in result.findings] == [
        ("IAC-CHG-001", "labcloud_block_disk.old_cache"),
        ("IAC-ENC-001", "labcloud_storage_bucket.ops_exports"),
        ("IAC-IAM-001", "labcloud_iam_policy.ops_admin"),
        ("IAC-NET-001", "labcloud_firewall_rule.admin_db"),
        ("IAC-TAG-001", "labcloud_block_disk.scratch"),
    ]
    assert [f.sort_key for f in result.findings] == sorted(f.sort_key for f in result.findings)


VIOLATIONS = {
    "public-ingress": {"IAC-NET-001"},
    "wildcard-iam": {"IAC-IAM-001"},
    "unencrypted-storage": {"IAC-ENC-001"},
    "missing-tags": {"IAC-TAG-001"},
    "provider-version-violation": {"IAC-VER-001", "IAC-VER-002", "IAC-VER-003", "IAC-VER-004"},
    "mixed-violations": {"IAC-ENC-001", "IAC-IAM-001", "IAC-NET-001", "IAC-TAG-001"},
}


@pytest.mark.parametrize("plan_name", sorted(VIOLATIONS))
@pytest.mark.parametrize("level", ["standard", "elevated"])
def test_valid_approval_never_suppresses_hard_violation(tmp_path, plan_name, level):
    plan = load_plan(plan_path(plan_name))
    # Destructive plans need elevation for the gate to be valid, so only the policy rules remain.
    level_used = "elevated" if plan.destructive_addresses else level
    approval_file = write_json(
        tmp_path / "approval.json", matching_approval(plan, level=level_used)
    )
    result = evaluate(plan_path(plan_name), approval_file, POLICY, "no-suppression")
    assert result.assessment.valid, result.assessment.failed_checks
    assert result.decision == "BLOCKED" and result.exit_code == 1
    blocking = {f.rule_id for f in result.findings if f.blocking}
    assert blocking == VIOLATIONS[plan_name]
