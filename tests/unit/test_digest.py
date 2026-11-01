"""Normalized change-set digest (REQ-007)."""

from __future__ import annotations

import json
import re

import pytest
from helpers import plan_doc, plan_path

from iac_change_control.plan_loader import load_plan, parse_plan


def digest_of(doc: dict, **dump_kwargs) -> str:
    return parse_plan(json.dumps(doc, **dump_kwargs).encode("utf-8")).change_set_digest


def reorder_keys(value):
    if isinstance(value, dict):
        return {k: reorder_keys(value[k]) for k in reversed(list(value))}
    if isinstance(value, list):
        return [reorder_keys(v) for v in value]
    return value


def test_digest_format():
    digest = load_plan(plan_path("compliant")).change_set_digest
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)


def test_digest_ignores_key_order_whitespace_and_descriptive_fields():
    doc = plan_doc()
    baseline = digest_of(doc)
    assert digest_of(reorder_keys(doc)) == baseline
    assert digest_of(doc, indent=7, separators=(" ,", " :  ")) == baseline
    changed = plan_doc()
    changed["description"] = "Rewritten description only."
    changed["fixture_id"] = "plan-renamed"
    assert digest_of(changed) == baseline


def test_digest_ignores_resource_order():
    doc = plan_doc()
    baseline = digest_of(doc)
    doc["resource_changes"].reverse()
    assert digest_of(doc) == baseline


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(terraform_version="1.9.9"),
        lambda d: d["change_context"].update(change_ref="LAB-CHG-0099"),
        lambda d: d["change_context"].update(environment="lab-test"),
        lambda d: d["configuration"]["provider_config"]["labcloud"].update(
            selected_version="2.4.2"
        ),
        lambda d: d["configuration"]["provider_config"]["labcloud"].update(
            version_constraint="~> 2.5"
        ),
        lambda d: d["resource_changes"][0]["change"]["after"].update(to_port=444, from_port=444),
        lambda d: d["resource_changes"][0]["change"]["after"]["cidr_blocks"].reverse(),
        lambda d: d["resource_changes"][3]["change"]["after"]["tags"].update(owner="other-team"),
        lambda d: d["resource_changes"].pop(),
    ],
)
def test_digest_changes_with_substantive_change(mutate):
    baseline = digest_of(plan_doc())
    doc = plan_doc()
    mutate(doc)
    assert digest_of(doc) != baseline
