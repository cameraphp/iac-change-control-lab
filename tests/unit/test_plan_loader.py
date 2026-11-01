"""Strict reading and plan validation: REQ-002, REQ-003, REQ-004, SAFE-003, SAFE-004, NFR-007."""

from __future__ import annotations

import json

import pytest
from helpers import (
    APPROVALS,
    FIXTURES,
    PLANS,
    POLICY,
    VALID_PLAN_NAMES,
    plan_doc,
    plan_path,
    read_json,
    resource,
    single_resource_plan,
    tags,
    to_bytes,
)

from iac_change_control.models import (
    ACTION_VALUES,
    APPROVAL_LEVELS,
    APPROVAL_STATUSES,
    MAX_INPUT_BYTES,
    SUPPORTED_RESOURCE_TYPES,
    InputValidationError,
)
from iac_change_control.plan_loader import (
    load_plan,
    load_schema,
    parse_approval,
    parse_plan,
    parse_policy,
    read_input,
    validator_for,
)


def errors_of(data: bytes, parser=parse_plan):
    with pytest.raises(InputValidationError) as exc:
        parser(data)
    return exc.value.errors


def codes_of(data: bytes, parser=parse_plan) -> set[str]:
    return {e.code for e in errors_of(data, parser)}


def fw_after(**override):
    state = {
        "direction": "ingress",
        "protocol": "tcp",
        "from_port": 443,
        "to_port": 443,
        "cidr_blocks": ["10.0.0.0/8"],
        "tags": tags(),
    }
    state.update(override)
    return state


# -- REQ-002: strict reading ----------------------------------------------------------------
def test_missing_file_is_error(tmp_path):
    raw, errors = read_input(tmp_path / "absent.json", "plan")
    assert raw.data is None and raw.sha256 is None
    assert [e.code for e in errors] == ["file_not_found"]
    with pytest.raises(InputValidationError):
        load_plan(tmp_path / "absent.json")


def test_oversized_file_is_error(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (MAX_INPUT_BYTES + 1))
    raw, errors = read_input(big, "plan")
    assert raw.data is None
    assert [e.code for e in errors] == ["file_too_large"]


def test_non_utf8_file_is_error():
    assert codes_of(b'{"description": "\xff\xfe"}') == {"not_utf8"}


def test_malformed_json_is_error():
    assert codes_of((PLANS / "malformed.json").read_bytes()) == {"json_parse_error"}
    assert codes_of(b"") == {"json_parse_error"}


def test_duplicate_keys_are_error():
    assert codes_of(b'{"synthetic": true, "synthetic": true}') == {"duplicate_key"}
    nested = b'{"configuration": {"provider_config": {"a": 1, "a": 2}}}'
    assert codes_of(nested) == {"duplicate_key"}


@pytest.mark.parametrize("literal", [b"NaN", b"Infinity", b"-Infinity"])
def test_non_finite_numbers_are_error(literal):
    assert codes_of(b'{"x": ' + literal + b"}") == {"non_finite_number"}


@pytest.mark.parametrize("payload", [b"[1, 2]", b'"text"', b"42", b"null"])
def test_top_level_must_be_object(payload):
    assert codes_of(payload) == {"top_level_not_object"}


# -- REQ-003: plan contract -----------------------------------------------------------------
@pytest.mark.parametrize("name", VALID_PLAN_NAMES)
def test_all_valid_plan_fixtures_load(name):
    plan = load_plan(plan_path(name))
    addresses = [rc.address for rc in plan.resources]
    assert addresses == sorted(addresses)
    assert plan.change_set_digest.startswith("sha256:")
    assert plan.fixture_id == f"plan-{name}"


def test_missing_required_field_is_error():
    doc = plan_doc()
    del doc["terraform_version"]
    errors = errors_of(to_bytes(doc))
    assert any(e.path == "$" and "terraform_version" in e.message for e in errors)
    doc = plan_doc()
    del doc["resource_changes"][0]["change"]["after"]["cidr_blocks"]
    assert {e.code for e in errors_of(to_bytes(doc))} == {"schema_violation"}


def test_wrong_type_is_error():
    doc = single_resource_plan(resource("labcloud_firewall_rule", "web", fw_after(from_port="443")))
    errors = errors_of(to_bytes(doc))
    assert [(e.code, e.path) for e in errors] == [
        ("schema_violation", "$.resource_changes[0].change.after.from_port")
    ]
    doc = single_resource_plan(
        resource("labcloud_block_disk", "d", {"size_gb": True, "tags": tags()})
    )
    assert {e.path for e in errors_of(to_bytes(doc))} == {
        "$.resource_changes[0].change.after.size_gb"
    }


def test_unknown_property_is_error():
    doc = plan_doc()
    doc["unexpected"] = 1
    doc["resource_changes"][0]["change"]["after"]["surprise"] = "x"
    paths = {e.path for e in errors_of(to_bytes(doc))}
    assert paths == {"$.unexpected", "$.resource_changes[0].change.after.surprise"}


def test_unsupported_resource_type_is_error():
    data = plan_path("unsupported-resource").read_bytes()
    errors = errors_of(data)
    assert [(e.code, e.path) for e in errors] == [
        ("unsupported_resource_type", "$.resource_changes[0].type")
    ]


def test_synthetic_flag_required():
    doc = plan_doc()
    doc["synthetic"] = False
    assert codes_of(to_bytes(doc)) == {"not_synthetic"}
    del doc["synthetic"]
    assert any("synthetic" in e.message for e in errors_of(to_bytes(doc)))
    doc = plan_doc()
    doc["contract_version"] = "iac-lab-plan/v2"
    assert codes_of(to_bytes(doc)) == {"unsupported_contract_version"}


def test_empty_resource_changes_is_error():
    doc = plan_doc()
    doc["resource_changes"] = []
    errors = errors_of(to_bytes(doc))
    assert [(e.path, e.code) for e in errors] == [("$.resource_changes", "schema_violation")]


def test_address_must_match_type_and_name():
    rc = resource("labcloud_block_disk", "data", {"size_gb": 5, "tags": tags()})
    rc["address"] = "labcloud_block_disk.other"
    assert codes_of(to_bytes(single_resource_plan(rc))) == {"address_mismatch"}


def test_duplicate_address_is_error():
    doc = plan_doc()
    doc["resource_changes"].append(doc["resource_changes"][0])
    assert codes_of(to_bytes(doc)) == {"duplicate_address"}


def test_unknown_provider_reference_is_error():
    doc = plan_doc()
    doc["resource_changes"][0]["provider_name"] = "labother"
    assert codes_of(to_bytes(doc)) == {"unknown_provider_reference"}


def test_provider_key_must_match_name():
    doc = plan_doc()
    doc["configuration"]["provider_config"]["labcloud"]["name"] = "labcloudx"
    assert codes_of(to_bytes(doc)) == {"provider_name_mismatch"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("terraform_version", "1.9"),
        ("terraform_version", "v1.9.8"),
        ("terraform_version", "1.09.8"),
        ("selected_version", "2.4.1-beta"),
        ("selected_version", "2.4"),
    ],
)
def test_malformed_version_is_error(field, value):
    doc = plan_doc()
    if field == "terraform_version":
        doc[field] = value
    else:
        doc["configuration"]["provider_config"]["labcloud"][field] = value
    assert codes_of(to_bytes(doc)) == {"schema_violation"}


def test_schema_enums_match_code_constants():
    plan_schema = load_schema("plan")
    rc_props = plan_schema["$defs"]["resource_change"]["properties"]
    assert rc_props["type"]["enum"] == sorted(SUPPORTED_RESOURCE_TYPES)
    assert rc_props["change"]["properties"]["actions"]["items"]["enum"] == sorted(ACTION_VALUES)
    approval_schema = load_schema("approval")
    assert approval_schema["properties"]["status"]["enum"] == sorted(APPROVAL_STATUSES)
    assert approval_schema["properties"]["approval_level"]["enum"] == sorted(APPROVAL_LEVELS)
    branches = {
        branch["if"]["properties"]["type"]["const"]
        for name, branch in plan_schema["$defs"].items()
        if name.startswith("branch_")
    }
    assert branches == set(SUPPORTED_RESOURCE_TYPES)


def test_fixtures_conform_to_published_schemas():
    for name in VALID_PLAN_NAMES:
        assert validator_for("plan").validate(read_json(plan_path(name))) == [], name
    assert validator_for("plan").validate(read_json(plan_path("unsupported-resource")))
    for path in sorted(APPROVALS.glob("*.json")):
        assert validator_for("approval").validate(read_json(path)) == [], path.name
    assert validator_for("policy").validate(read_json(POLICY)) == []
    assert (
        validator_for("policy").validate(read_json(FIXTURES / "policies" / "invalid-policy.json"))
        == []
    )


# -- REQ-004: actions and change consistency ------------------------------------------------
def test_unknown_action_is_error():
    doc = plan_doc()
    doc["resource_changes"][0]["change"]["actions"] = ["replace"]
    errors = errors_of(to_bytes(doc))
    assert [(e.code, e.path) for e in errors] == [
        ("unknown_action", "$.resource_changes[0].change.actions[0]")
    ]


@pytest.mark.parametrize(
    "actions", [["read"], ["update", "create"], ["create", "create"], ["no-op", "delete"]]
)
def test_unsupported_action_combination_is_error(actions):
    doc = plan_doc()
    doc["resource_changes"][0]["change"]["actions"] = actions
    assert codes_of(to_bytes(doc)) == {"unsupported_action_combination"}


@pytest.mark.parametrize(
    ("actions", "before", "after"),
    [
        (["create"], "obj", "obj"),
        (["delete"], "obj", "obj"),
        (["delete"], None, None),
        (["update"], None, "obj"),
        (["no-op"], "obj", None),
        (["delete", "create"], "obj", None),
    ],
)
def test_before_after_must_match_actions(actions, before, after):
    state = {"size_gb": 5, "tags": tags()}
    rc = resource(
        "labcloud_block_disk",
        "data",
        state if after == "obj" else None,
        actions,
        state if before == "obj" else None,
    )
    assert codes_of(to_bytes(single_resource_plan(rc))) == {"inconsistent_change"}


# -- SAFE-003: secrets ----------------------------------------------------------------------
def test_credential_like_keys_rejected():
    doc = plan_doc()
    doc["resource_changes"][0]["change"]["after"]["tags"]["api_token"] = "placeholder"
    errors = errors_of(to_bytes(doc))
    assert ("credential_like_key", "$.resource_changes[0].change.after.tags.api_token") in {
        (e.code, e.path) for e in errors
    }
    approval = read_json(APPROVALS / "approved-change.json")
    approval["client_secret"] = "placeholder"
    assert "credential_like_key" in codes_of(to_bytes(approval), parse_approval)
    policy = read_json(POLICY)
    policy["password"] = "placeholder"
    assert "credential_like_key" in codes_of(to_bytes(policy), parse_policy)


def test_secret_like_values_rejected():
    fake_key_id = "AKIA" + "Z" * 16
    fake_pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
    for value in (fake_key_id, fake_pem, "ghp_" + "a" * 36):
        doc = plan_doc()
        doc["description"] = f"contains {value}"
        errors = errors_of(to_bytes(doc))
        assert [(e.code, e.path) for e in errors] == [("secret_like_value", "$.description")]
        assert all(value not in e.message and value not in e.path for e in errors)


# -- SAFE-004: synthetic identifiers --------------------------------------------------------
@pytest.mark.parametrize("cidr", ["100.64.0.0/10", "0.0.0.0/1", "fe80::/10", "172.32.0.0/16"])
def test_cidr_outside_reserved_ranges_rejected(cidr):
    rc = resource("labcloud_firewall_rule", "web", fw_after(cidr_blocks=[cidr]))
    errors = errors_of(to_bytes(single_resource_plan(rc)))
    assert [(e.code, e.path) for e in errors] == [
        ("cidr_outside_reserved_ranges", "$.resource_changes[0].change.after.cidr_blocks[0]")
    ]


@pytest.mark.parametrize(
    ("cidr", "code"),
    [
        ("2001:DB8::/32", "non_canonical_cidr"),
        ("10.0.0.0/08", "non_canonical_cidr"),
        ("10.0.0.1/8", "invalid_cidr"),
        ("not-a-cidr", "invalid_cidr"),
        ("10.0.0.0/33", "invalid_cidr"),
    ],
)
def test_non_canonical_cidr_rejected(cidr, code):
    rc = resource("labcloud_firewall_rule", "web", fw_after(cidr_blocks=[cidr]))
    assert codes_of(to_bytes(single_resource_plan(rc))) == {code}


def test_provider_source_must_use_example_domain():
    doc = plan_doc()
    doc["configuration"]["provider_config"]["labcloud"]["source"] = (
        "registry.lab.internal/syn/labcloud"
    )
    assert codes_of(to_bytes(doc)) == {"non_example_provider_source"}
    policy = read_json(POLICY)
    policy["provider_allowlist"]["labcloud"]["source"] = "registry.lab.internal/syn/labcloud"
    assert codes_of(to_bytes(policy), parse_policy) == {"non_example_provider_source"}


def test_all_fixtures_labelled_synthetic():
    paths = sorted(FIXTURES.rglob("*.json")) + [POLICY]
    assert len(paths) >= 26
    for path in paths:
        if path.name == "malformed.json":
            assert '"synthetic": true' in path.read_text(encoding="utf-8")
            continue
        assert read_json(path)["synthetic"] is True, path.name


# -- NFR-007: safe error messages -----------------------------------------------------------
def test_error_messages_do_not_echo_values():
    marker = "MARKERVALUE7731"
    doc = plan_doc()
    doc["fixture_id"] = marker
    doc["description"] = marker * 30
    doc["resource_changes"][0]["change"]["after"]["from_port"] = marker
    doc["resource_changes"][0]["change"]["after"]["direction"] = marker
    doc["resource_changes"][1]["type"] = marker
    errors = errors_of(to_bytes(doc))
    assert len(errors) >= 4
    assert all(marker not in e.message and marker not in e.path for e in errors)


def test_error_list_is_sorted_and_capped():
    doc = plan_doc()
    template = doc["resource_changes"][0]
    doc["resource_changes"] = [json.loads(json.dumps(template)) for _ in range(150)]
    for rc in doc["resource_changes"]:
        rc["change"]["after"]["from_port"] = "bad"
    errors = errors_of(to_bytes(doc))
    assert len(errors) == 101
    assert errors[-1].code == "errors_truncated" and "50 more" in errors[-1].message
    assert errors[:100] == sorted(errors[:100])
