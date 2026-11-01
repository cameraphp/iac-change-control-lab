"""Destructive-change detection: IAC-CHG-001 (high, needs an elevated approval). REQ-011.

Any action list containing ``delete`` is flagged: a plain deletion, or a replacement
(delete-then-create or create-then-delete). The finding describes a *proposed* change in a
synthetic fixture. Nothing is ever deleted. The approval gate (IAC-APR-006 and 007) decides
whether the change is blocked.
"""

from __future__ import annotations

from iac_change_control.models import Finding, Plan, Policy


def evaluate(plan: Plan, policy: Policy) -> list[Finding]:
    del policy  # this control has no tunable parameters
    findings: list[Finding] = []
    for rc in plan.resources:
        if not rc.is_destructive:
            continue
        kind = "deletion" if rc.actions == ("delete",) else "replacement"
        findings.append(
            Finding(
                "IAC-CHG-001",
                rc.address,
                "actions",
                f"proposed action list [{', '.join(rc.actions)}] includes delete ({kind}); "
                "fixture only, nothing was deleted",
                "Confirm intent and data retention, then obtain an elevated approval that lists "
                "this address.",
            )
        )
    return findings
