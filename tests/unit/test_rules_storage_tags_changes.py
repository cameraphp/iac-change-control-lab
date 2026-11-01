"""Encryption (REQ-010), destructive changes (REQ-011), tags (REQ-012), versions (REQ-013)."""

from __future__ import annotations

import pytest
from helpers import POLICY, plan_doc, resource, tags, to_bytes

from iac_change_control.plan_loader import load_policy, parse_plan
from iac_change_control.rules import (
    destroy_changes,
    provider_version,
    required_tags,
    storage_encryption,
)

POLICY_OBJ = load_policy(POLICY)


def plan_with(*rcs, **top):
    doc = plan_doc()
    doc["resource_changes"] = list(rcs)
    doc.update(top)
    return parse_plan(to_bytes(doc))


def disk(name, encryption="ok", tag_map="ok", actions=("create",)):
    state = {"size_gb": 10}
    if encryption == "ok":
        state["encryption"] = {"enabled": True, "algorithm": "aes-256-gcm"}
    elif encryption != "absent":
        state["encryption"] = encryption
    if tag_map == "ok":
        state["tags"] = tags()
    elif tag_map != "absent":
        state["tags"] = tag_map
    if actions == ("delete",):
        return resource("labcloud_block_disk", name, None, actions, state)
    before = state if actions != ("create",) else None
    return resource("labcloud_block_disk", name, state, actions, before)


# -- REQ-010 --------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("encryption", "fragment"),
    [
        ("absent", "missing or null"),
        (None, "missing or null"),
        ({"enabled": False, "algorithm": "aes-256-gcm"}, "enabled is false"),
        ({"enabled": None, "algorithm": "aes-256-gcm"}, "enabled is null"),
    ],
)
def test_encryption_missing_null_or_disabled_blocks(encryption, fragment):
    findings = storage_encryption.evaluate(plan_with(disk("d", encryption)), POLICY_OBJ)
    assert [(f.rule_id, f.severity, f.blocking) for f in findings] == [
        ("IAC-ENC-001", "high", True)
    ]
    assert fragment in findings[0].reason


def test_disallowed_algorithm_blocks():
    for algorithm in ("lab-legacy-cipher", None):
        findings = storage_encryption.evaluate(
            plan_with(disk("d", {"enabled": True, "algorithm": algorithm})), POLICY_OBJ
        )
        assert [f.rule_id for f in findings] == ["IAC-ENC-001"]
        assert "not allowed by policy" in findings[0].reason


def test_encrypted_storage_passes():
    bucket = resource(
        "labcloud_storage_bucket",
        "b",
        {
            "bucket_name": "lab-b",
            "encryption": {"enabled": True, "algorithm": "kms-managed"},
            "tags": tags(),
        },
    )
    db = resource(
        "labcloud_database_instance",
        "db",
        {
            "engine": "labsql",
            "instance_class": "lab.small",
            "encryption": {"enabled": True, "algorithm": "aes-256-gcm"},
            "tags": tags(),
        },
    )
    assert storage_encryption.evaluate(plan_with(bucket, db, disk("d")), POLICY_OBJ) == []


def test_non_storage_types_not_checked():
    fw = resource(
        "labcloud_firewall_rule",
        "f",
        {
            "direction": "ingress",
            "protocol": "tcp",
            "from_port": 443,
            "to_port": 443,
            "cidr_blocks": ["10.0.0.0/8"],
            "tags": tags(),
        },
    )
    deleted_unencrypted = disk("old", "absent", actions=("delete",))
    assert storage_encryption.evaluate(plan_with(fw, deleted_unencrypted), POLICY_OBJ) == []


# -- REQ-011 --------------------------------------------------------------------------------
def test_delete_action_flagged_high():
    findings = destroy_changes.evaluate(plan_with(disk("old", actions=("delete",))), POLICY_OBJ)
    assert [
        (f.rule_id, f.severity, f.blocking, f.info.requires_elevated_approval) for f in findings
    ] == [("IAC-CHG-001", "high", False, True)]
    assert "nothing was deleted" in findings[0].reason and "(deletion)" in findings[0].reason


@pytest.mark.parametrize("actions", [("delete", "create"), ("create", "delete")])
def test_replace_action_flagged(actions):
    findings = destroy_changes.evaluate(plan_with(disk("r", actions=actions)), POLICY_OBJ)
    assert [f.rule_id for f in findings] == ["IAC-CHG-001"]
    assert "(replacement)" in findings[0].reason


def test_non_destructive_actions_not_flagged():
    plan = plan_with(disk("a"), disk("b", actions=("update",)), disk("c", actions=("no-op",)))
    assert destroy_changes.evaluate(plan, POLICY_OBJ) == []


# -- REQ-012 --------------------------------------------------------------------------------
def test_missing_tag_keys_block():
    findings = required_tags.evaluate(
        plan_with(disk("d", tag_map={"owner": "platform-lab"})), POLICY_OBJ
    )
    assert [(f.rule_id, f.severity, f.blocking) for f in findings] == [
        ("IAC-TAG-001", "high", True)
    ]
    assert findings[0].reason.endswith("environment, cost_center")


def test_blank_tag_values_block():
    findings = required_tags.evaluate(
        plan_with(disk("d", tag_map=tags(owner="   ", cost_center=""))), POLICY_OBJ
    )
    assert findings[0].reason.endswith("owner, cost_center")


def test_absent_tags_block():
    findings = required_tags.evaluate(plan_with(disk("d", tag_map="absent")), POLICY_OBJ)
    assert findings[0].reason.endswith("owner, environment, cost_center")


def test_complete_tags_pass():
    plan = plan_with(disk("d"), disk("gone", tag_map="absent", actions=("delete",)))
    assert required_tags.evaluate(plan, POLICY_OBJ) == []


# -- REQ-013 --------------------------------------------------------------------------------
def provider(**override):
    meta = {
        "name": "labcloud",
        "source": "registry.example/synthetic/labcloud",
        "version_constraint": "~> 2.4",
        "selected_version": "2.4.1",
    }
    meta.update(override)
    return meta


def version_findings(terraform="1.9.8", **providers):
    plan = plan_with(
        disk("d"),
        terraform_version=terraform,
        configuration={"provider_config": providers or {"labcloud": provider()}},
    )
    return [(f.rule_id, f.address) for f in provider_version.evaluate(plan, POLICY_OBJ)]


@pytest.mark.parametrize("version", ["1.5.7", "2.0.0", "0.15.5"])
def test_terraform_version_out_of_range_blocks(version):
    assert version_findings(version) == [("IAC-VER-001", "terraform")]
    assert version_findings("1.6.0") == [] and version_findings("1.99.0") == []


def test_provider_not_allowlisted_blocks():
    found = version_findings(
        labcloud=provider(),
        labdns=provider(name="labdns", source="registry.example/synthetic/labdns"),
    )
    assert found == [("IAC-VER-002", "provider.labdns")]


def test_provider_source_mismatch_blocks():
    found = version_findings(labcloud=provider(source="mirror.example/forked/labcloud"))
    assert found == [("IAC-VER-002", "provider.labcloud")]


@pytest.mark.parametrize("selected", ["2.3.9", "3.0.0", "3.1.0"])
def test_provider_version_out_of_range_blocks(selected):
    assert version_findings(labcloud=provider(selected_version=selected)) == [
        ("IAC-VER-003", "provider.labcloud")
    ]
    assert version_findings(labcloud=provider(selected_version="2.4.0")) == []


def test_provider_missing_constraint_blocks():
    meta = provider()
    del meta["version_constraint"]
    assert version_findings(labcloud=meta) == [("IAC-VER-004", "provider.labcloud")]
    assert version_findings(labcloud=provider(version_constraint="  ")) == [
        ("IAC-VER-004", "provider.labcloud")
    ]
