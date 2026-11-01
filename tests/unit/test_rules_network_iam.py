"""Public-ingress (REQ-008) and wildcard-IAM (REQ-009) rules, unit level."""

from __future__ import annotations

import pytest
from helpers import POLICY, plan_doc, resource, tags, to_bytes

from iac_change_control.plan_loader import load_policy, parse_plan
from iac_change_control.rules import public_ingress, wildcard_iam

POLICY_OBJ = load_policy(POLICY)


def plan_with(*rcs):
    doc = plan_doc()
    doc["resource_changes"] = list(rcs)
    return parse_plan(to_bytes(doc))


def fw(name, protocol="tcp", low=443, high=443, cidrs=("0.0.0.0/0",), direction="ingress"):
    return resource(
        "labcloud_firewall_rule",
        name,
        {
            "direction": direction,
            "protocol": protocol,
            "from_port": low,
            "to_port": high,
            "cidr_blocks": list(cidrs),
            "tags": tags(),
        },
    )


def ingress(*rcs):
    return [(f.rule_id, f.address) for f in public_ingress.evaluate(plan_with(*rcs), POLICY_OBJ)]


# -- REQ-008 --------------------------------------------------------------------------------
@pytest.mark.parametrize(("low", "high"), [(22, 22), (3389, 3389), (5000, 6000), (20, 25)])
def test_public_ingress_sensitive_port_blocks(low, high):
    findings = public_ingress.evaluate(plan_with(fw("r", low=low, high=high)), POLICY_OBJ)
    assert [(f.rule_id, f.severity, f.blocking) for f in findings] == [
        ("IAC-NET-001", "critical", True)
    ]
    assert "sensitive port" in findings[0].reason


def test_public_ingress_all_ports_blocks():
    findings = public_ingress.evaluate(plan_with(fw("r", low=0, high=65535)), POLICY_OBJ)
    assert [f.rule_id for f in findings] == ["IAC-NET-001"]
    assert "all ports" in findings[0].reason


def test_public_ingress_protocol_all_blocks():
    assert ingress(fw("r", protocol="all", low=443, high=443)) == [
        ("IAC-NET-001", "labcloud_firewall_rule.r")
    ]


def test_public_ingress_ipv6_world_blocks():
    assert ingress(fw("r", low=22, high=22, cidrs=("2001:db8::/32", "::/0"))) == [
        ("IAC-NET-001", "labcloud_firewall_rule.r")
    ]


def test_public_ingress_allowed_port_passes():
    assert (
        ingress(
            fw("https", low=443, high=443, cidrs=("0.0.0.0/0", "::/0")), fw("http", low=80, high=80)
        )
        == []
    )


def test_public_ingress_nonstandard_port_warns():
    findings = public_ingress.evaluate(plan_with(fw("alt", low=8443, high=8443)), POLICY_OBJ)
    assert [(f.rule_id, f.severity, f.blocking) for f in findings] == [
        ("IAC-NET-002", "medium", False)
    ]
    # 80-443 is not fully inside the allowlist {80, 443}
    assert ingress(fw("range", low=80, high=443)) == [
        ("IAC-NET-002", "labcloud_firewall_rule.range")
    ]


def test_private_cidr_and_egress_not_flagged():
    assert (
        ingress(
            fw("db", low=5432, high=5432, cidrs=("10.20.0.0/16", "192.0.2.0/24", "2001:db8::/32")),
            fw("out", protocol="all", low=0, high=65535, direction="egress"),
        )
        == []
    )
    # A deleted rule has no planned after-state, so there is nothing to expose.
    deleted = fw("gone", low=22, high=22)
    deleted["change"] = {"actions": ["delete"], "before": deleted["change"]["after"], "after": None}
    assert ingress(deleted) == []


# -- REQ-009 --------------------------------------------------------------------------------
def iam(name, *statements):
    return resource(
        "labcloud_iam_policy",
        name,
        {
            "policy_name": "lab-test",
            "statements": list(statements),
            "tags": tags(),
        },
    )


def stmt(actions, resources, effect="Allow"):
    return {"effect": effect, "actions": list(actions), "resources": list(resources)}


def iam_findings(*statements):
    return wildcard_iam.evaluate(plan_with(iam("p", *statements)), POLICY_OBJ)


def test_wildcard_action_blocks():
    findings = iam_findings(stmt(["*"], ["lab:storage:bucket/lab-a"]))
    assert [(f.rule_id, f.severity, f.blocking, f.detail_key) for f in findings] == [
        ("IAC-IAM-001", "critical", True, "statements[000]")
    ]
    assert 'Action "*"' in findings[0].reason and "Resource" not in findings[0].reason


def test_wildcard_resource_blocks():
    findings = iam_findings(
        stmt(["storage:GetObject"], ["lab:storage:bucket/lab-a"]),
        stmt(["storage:GetObject"], ["*"]),
    )
    assert [(f.rule_id, f.detail_key) for f in findings] == [("IAC-IAM-001", "statements[001]")]
    both = iam_findings(stmt(["*"], ["*"]))
    assert 'Action "*" and Resource "*"' in both[0].reason


def test_deny_wildcard_not_flagged():
    assert iam_findings(stmt(["*"], ["*"], effect="Deny")) == []


def test_service_wildcard_warns():
    findings = iam_findings(stmt(["storage:*", "storage:GetObject"], ["lab:storage:bucket/lab-a"]))
    assert [(f.rule_id, f.severity, f.blocking) for f in findings] == [
        ("IAC-IAM-002", "medium", False)
    ]
    # A full wildcard takes precedence; there is no duplicate service-wildcard warning.
    assert [f.rule_id for f in iam_findings(stmt(["*", "storage:*"], ["*"]))] == ["IAC-IAM-001"]


def test_scoped_policy_passes():
    assert (
        iam_findings(
            stmt(
                ["storage:GetObject", "storage:ListBucket"],
                ["lab:storage:bucket/lab-a", "lab:storage:bucket/lab-a/*"],
            )
        )
        == []
    )
