"""Scoped approval gate: IAC-APR-001 to 007 (all blocking). REQ-014, REQ-015, REQ-016.

An approval record is bound to the active policy version, the plan's change context, the
normalized change-set digest and, for destructive changes, an explicit elevated list of
destructive addresses. The gate only ever adds blocking findings. It never removes or downgrades
a policy finding, and there is no exception mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from iac_change_control.models import Approval, Finding, Plan, Policy

GATE_ADDRESS = "change-set"

CHECKS = (
    ("IAC-APR-001", "approval_present"),
    ("IAC-APR-002", "approval_status_approved"),
    ("IAC-APR-003", "policy_version_current"),
    ("IAC-APR-004", "scope_matches"),
    ("IAC-APR-005", "digest_matches"),
    ("IAC-APR-006", "elevation_for_destructive"),
    ("IAC-APR-007", "destructive_addresses_match"),
)

REMEDIATION = {
    "IAC-APR-001": "Submit an approval record for this exact change set.",
    "IAC-APR-002": "Address the reviewer's rejection and submit a new change for approval.",
    "IAC-APR-003": "Re-approve the change against the active policy version.",
    "IAC-APR-004": "Obtain an approval scoped to this change reference and environment.",
    "IAC-APR-005": "Re-approve the change: the plan differs from the approved change set.",
    "IAC-APR-006": "Obtain an elevated approval for the destructive change(s).",
    "IAC-APR-007": "List exactly the destructive addresses in the elevated approval.",
}

PASS, FAIL, NOT_EVALUATED = "pass", "fail", "not_evaluated"


@dataclass(frozen=True)
class ApprovalAssessment:
    approval_provided: bool
    approval: Approval | None
    expected: dict[str, Any]
    checks: tuple[dict[str, str], ...]
    findings: tuple[Finding, ...]

    @property
    def valid(self) -> bool:
        return not self.findings

    @property
    def gate_result(self) -> str:
        return "valid" if self.valid else "blocked"

    @property
    def failed_checks(self) -> list[str]:
        return [c["check_id"] for c in self.checks if c["result"] == FAIL]


def assess(plan: Plan, approval: Approval | None, policy: Policy) -> ApprovalAssessment:
    destructive = sorted(plan.destructive_addresses)
    expected = {
        "change_set_digest": plan.change_set_digest,
        "policy_version": policy.policy_version,
        "scope": dict(plan.change_context),
        "destructive_addresses": destructive,
        "elevated_required": bool(destructive),
    }
    results: dict[str, tuple[str, str]] = {}

    if approval is None or approval.status == "not_submitted":
        why = (
            "no approval file was provided"
            if approval is None
            else "approval status is not_submitted"
        )
        results["IAC-APR-001"] = (FAIL, why)
    else:
        results["IAC-APR-001"] = (PASS, f"approval record {approval.approval_id} present")
        if approval.status == "rejected":
            results["IAC-APR-002"] = (FAIL, "approval status is rejected")
        else:
            results["IAC-APR-002"] = (PASS, "approval status is approved")
            results["IAC-APR-003"] = (
                (PASS, f"approval granted against policy version {policy.policy_version}")
                if approval.policy_version == policy.policy_version
                else (
                    FAIL,
                    f"approval policy_version {approval.policy_version} differs from active "
                    f"policy version {policy.policy_version}",
                )
            )
            results["IAC-APR-004"] = (
                (PASS, "approval scope matches the plan change context")
                if approval.scope == plan.change_context
                else (
                    FAIL,
                    f"approval scope {approval.scope['change_ref']}/"
                    f"{approval.scope['environment']} differs from plan "
                    f"{plan.change_context['change_ref']}/"
                    f"{plan.change_context['environment']}",
                )
            )
            results["IAC-APR-005"] = (
                (PASS, "approval digest matches the computed change-set digest")
                if approval.change_set_digest == plan.change_set_digest
                else (FAIL, "approval digest differs from the computed change-set digest")
            )
            if not destructive:
                results["IAC-APR-006"] = (PASS, "no destructive changes in the plan")
            elif approval.approval_level == "elevated":
                results["IAC-APR-006"] = (PASS, "elevated approval present for destructive changes")
            else:
                results["IAC-APR-006"] = (
                    FAIL,
                    f"{len(destructive)} destructive change(s) require an elevated approval; "
                    f"approval level is {approval.approval_level}",
                )
            listed = sorted(approval.approved_destructive_addresses)
            if listed == destructive:
                detail = (
                    "approved destructive addresses match the plan"
                    if destructive
                    else "no destructive addresses expected or listed"
                )
                results["IAC-APR-007"] = (PASS, detail)
            else:
                missing = sorted(set(destructive) - set(listed))
                extra = sorted(set(listed) - set(destructive))
                parts = []
                if missing:
                    parts.append(f"not listed: {', '.join(missing)}")
                if extra:
                    parts.append(f"listed but not destructive in plan: {', '.join(extra)}")
                results["IAC-APR-007"] = (FAIL, "; ".join(parts))

    checks = []
    findings = []
    for check_id, name in CHECKS:
        result, detail = results.get(
            check_id, (NOT_EVALUATED, "not evaluated after an earlier failure")
        )
        checks.append({"check_id": check_id, "name": name, "result": result, "detail": detail})
        if result == FAIL:
            findings.append(Finding(check_id, GATE_ADDRESS, name, detail, REMEDIATION[check_id]))
    return ApprovalAssessment(
        approval_provided=approval is not None,
        approval=approval,
        expected=expected,
        checks=tuple(checks),
        findings=tuple(findings),
    )
