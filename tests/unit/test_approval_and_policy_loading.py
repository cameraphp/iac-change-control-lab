"""Approval contract (REQ-005) and policy configuration (REQ-006) validation."""

from __future__ import annotations

import pytest
from helpers import APPROVALS, INVALID_POLICY, POLICY, plan_path, read_json, run_cli, to_bytes

from iac_change_control.models import InputValidationError
from iac_change_control.plan_loader import load_approval, load_policy, parse_approval, parse_policy


def codes(data: bytes, parser) -> set[str]:
    with pytest.raises(InputValidationError) as exc:
        parser(data)
    return {e.code for e in exc.value.errors}


def approval_doc(name: str = "approved-change") -> dict:
    return read_json(APPROVALS / f"{name}.json")


# -- REQ-005 --------------------------------------------------------------------------------
def test_all_approval_fixtures_load():
    paths = sorted(APPROVALS.glob("*.json"))
    assert len(paths) == 14
    statuses = {load_approval(p).status for p in paths}
    assert statuses == {"approved", "not_submitted", "rejected"}
    missing = load_approval(APPROVALS / "missing-approval.json")
    assert missing.change_set_digest is None and missing.approval_level is None


def test_malformed_approval_is_error():
    assert codes(b"{not json", parse_approval) == {"json_parse_error"}
    doc = approval_doc()
    doc["status"] = "maybe"
    assert codes(to_bytes(doc), parse_approval) == {"schema_violation"}
    doc = approval_doc()
    doc["synthetic"] = False
    assert codes(to_bytes(doc), parse_approval) == {"not_synthetic"}
    doc = approval_doc()
    doc["approver_name"] = "someone"
    assert codes(to_bytes(doc), parse_approval) == {"schema_violation"}


@pytest.mark.parametrize(
    "field",
    [
        "change_set_digest",
        "policy_version",
        "approval_level",
        "approver_role",
        "approved_destructive_addresses",
    ],
)
@pytest.mark.parametrize("status", ["approved", "rejected"])
def test_approval_requires_fields_for_decided_status(field, status):
    doc = approval_doc()
    doc["status"] = status
    del doc[field]
    assert codes(to_bytes(doc), parse_approval) == {"schema_violation"}


def test_approval_digest_format_enforced():
    for bad in ("sha256:ABC", "5bbb2a3b", "sha256:" + "g" * 64, "md5:" + "0" * 64):
        doc = approval_doc()
        doc["change_set_digest"] = bad
        assert codes(to_bytes(doc), parse_approval) == {"schema_violation"}, bad
    doc = approval_doc()
    doc["approved_destructive_addresses"] = ["labcloud_block_disk.a", "labcloud_block_disk.a"]
    assert codes(to_bytes(doc), parse_approval) == {"schema_violation"}


# -- REQ-006 --------------------------------------------------------------------------------
def test_default_policy_loads():
    policy = load_policy(POLICY)
    assert policy.policy_id == "lab-baseline" and policy.policy_version == "1.0.0"
    assert policy.required_tag_keys == ("owner", "environment", "cost_center")
    assert 22 in policy.sensitive_ports and policy.allowed_public_ports == (80, 443)
    assert policy.terraform_min == (1, 6, 0) and policy.terraform_max == (2, 0, 0)


def test_invalid_policy_fixture_is_error():
    assert codes(INVALID_POLICY.read_bytes(), parse_policy) == {
        "invalid_version_range",
        "port_overlap",
    }


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda d: d["provider_allowlist"]["labcloud"].update(max_exclusive="2.4.0"),
            "invalid_version_range",
        ),
        (lambda d: d["public_ingress"].update(sensitive_ports=[]), "schema_violation"),
        (lambda d: d["public_ingress"].update(sensitive_ports=[22, 22]), "schema_violation"),
        (lambda d: d["public_ingress"].update(allowed_public_ports=[0]), "schema_violation"),
        (
            lambda d: d["public_ingress"].update(allowed_public_ports=[443, 70000]),
            "schema_violation",
        ),
        (lambda d: d["required_tags"].update(keys=[]), "schema_violation"),
        (lambda d: d["storage_encryption"].update(allowed_algorithms=[]), "schema_violation"),
        (lambda d: d.update(rules_disabled=["IAC-NET-001"]), "schema_violation"),
        (lambda d: d.update(exceptions=[{"rule": "IAC-IAM-001"}]), "schema_violation"),
        (lambda d: d.pop("required_tags"), "schema_violation"),
        (lambda d: d.update(provider_allowlist={}), "schema_violation"),
    ],
)
def test_policy_semantic_checks(mutate, expected):
    doc = read_json(POLICY)
    mutate(doc)
    assert expected in codes(to_bytes(doc), parse_policy)


def test_cli_invalid_policy_exits_2(tmp_path):
    code, out, err = run_cli(
        "evaluate",
        "--plan",
        str(plan_path("compliant")),
        "--approval",
        str(APPROVALS / "approved-change.json"),
        "--policy",
        str(INVALID_POLICY),
        "--output",
        str(tmp_path / "b"),
        "--run-id",
        "bad-policy",
    )
    assert code == 2
    assert "decision=ERROR" in out
    evaluation = read_json(tmp_path / "b" / "evaluation.json")
    assert evaluation["decision"] == "ERROR"
    assert {e["code"] for e in evaluation["errors"]} == {"invalid_version_range", "port_overlap"}
    assert evaluation["findings"] == []
