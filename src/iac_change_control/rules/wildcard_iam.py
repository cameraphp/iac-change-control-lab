"""Wildcard-IAM control: IAC-IAM-001 (blocking) and IAC-IAM-002 (non-blocking). REQ-009.

Policy-language parsing is deliberately simplified. Only ``effect: "Allow"`` statements are
evaluated, there are no conditions or ``NotAction``, and partial resource wildcards (for
example ``lab:storage:bucket/*``) are not evaluated.
"""

from __future__ import annotations

from iac_change_control.models import IAM_POLICY_TYPE, Finding, Plan, Policy


def evaluate(plan: Plan, policy: Policy) -> list[Finding]:
    del policy  # this control has no tunable parameters
    findings: list[Finding] = []
    for rc in plan.resources:
        if rc.type != IAM_POLICY_TYPE or rc.after is None:
            continue
        for index, statement in enumerate(rc.after["statements"]):
            if statement["effect"] != "Allow":
                continue
            detail_key = f"statements[{index:03d}]"
            wildcard_action = "*" in statement["actions"]
            wildcard_resource = "*" in statement["resources"]
            if wildcard_action or wildcard_resource:
                parts = []
                if wildcard_action:
                    parts.append('Action "*"')
                if wildcard_resource:
                    parts.append('Resource "*"')
                findings.append(
                    Finding(
                        "IAC-IAM-001",
                        rc.address,
                        detail_key,
                        f"Allow statement {index} grants {' and '.join(parts)}",
                        "Replace wildcards with the specific actions and resource names the "
                        "workload needs (least privilege).",
                    )
                )
                continue
            service_wildcards = sorted(a for a in statement["actions"] if a.endswith(":*"))
            if service_wildcards:
                findings.append(
                    Finding(
                        "IAC-IAM-002",
                        rc.address,
                        detail_key,
                        f"Allow statement {index} uses service-scoped wildcard(s) "
                        f"{', '.join(service_wildcards)}",
                        "Prefer explicit actions; a human reviewer must accept this warning.",
                    )
                )
    return findings
