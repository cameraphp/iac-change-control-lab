"""Required-tags control: IAC-TAG-001 (blocking). REQ-012.

It checks every supported resource with a planned ``after`` state. A missing ``tags`` map, a
missing key and a blank value all count as missing. One finding per resource lists every
missing key in policy order.
"""

from __future__ import annotations

from iac_change_control.models import TAGGABLE_TYPES, Finding, Plan, Policy


def evaluate(plan: Plan, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for rc in plan.resources:
        if rc.type not in TAGGABLE_TYPES or rc.after is None:
            continue
        tags = rc.after.get("tags") or {}
        missing = [key for key in policy.required_tag_keys if not tags.get(key, "").strip()]
        if missing:
            findings.append(
                Finding(
                    "IAC-TAG-001",
                    rc.address,
                    "tags",
                    f"required tag(s) missing or blank: {', '.join(missing)}",
                    "Add non-blank values for every required tag key.",
                )
            )
    return findings
