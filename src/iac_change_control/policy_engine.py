"""Evaluation orchestration and the decision table. REQ-016, REQ-017, REQ-018.

ERROR      any input, schema, semantic, policy-config or evaluator error (exit 2)
BLOCKED    a blocking policy finding, or the approval gate failed (exit 1)
WARN       only non-blocking findings and a valid approval gate (exit 0)
PASS       no findings and a valid approval gate (exit 0)

A valid approval never suppresses a blocking policy finding: gate findings are only ever added.
Any unexpected exception becomes ERROR, never PASS.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from iac_change_control.models import (
    BLOCKED,
    ERROR,
    EXIT_CODES,
    PASS,
    WARN,
    Approval,
    Finding,
    InputError,
    InputValidationError,
    Plan,
    Policy,
)
from iac_change_control.plan_loader import (
    RawInput,
    finalize_errors,
    parse_approval,
    parse_plan,
    parse_policy,
    read_input,
)
from iac_change_control.rules import POLICY_RULES, approval_gate
from iac_change_control.rules.approval_gate import ApprovalAssessment


@dataclass(frozen=True)
class EvaluationResult:
    run_id: str
    decision: str
    plan_input: RawInput
    approval_input: RawInput | None
    policy_input: RawInput
    plan: Plan | None
    approval: Approval | None
    policy: Policy | None
    findings: tuple[Finding, ...]
    assessment: ApprovalAssessment | None
    errors: tuple[InputError, ...]

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.decision]

    @property
    def change_set_digest(self) -> str | None:
        return self.plan.change_set_digest if self.plan else None

    @property
    def decision_basis(self) -> str:
        if self.decision == ERROR:
            return (
                f"ERROR: {len(self.errors)} input, configuration or evaluator error(s); no policy "
                "decision was made and the change cannot be approved."
            )
        blocking = [f for f in self.findings if f.blocking and not f.rule_id.startswith("IAC-APR")]
        if self.decision == BLOCKED:
            parts = []
            if blocking:
                parts.append(f"{len(blocking)} blocking policy finding(s)")
            if self.assessment and not self.assessment.valid:
                parts.append(f"approval gate blocked ({', '.join(self.assessment.failed_checks)})")
            return "BLOCKED: " + " and ".join(parts) + "."
        if self.decision == WARN:
            return (
                f"WARN: no blocking findings; {len(self.findings)} non-blocking finding(s) need "
                "human attention; approval gate valid."
            )
        return "PASS: no findings; approval gate valid. Human review is still required."


def sort_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    return tuple(sorted(findings, key=lambda f: f.sort_key))


def decide(findings: tuple[Finding, ...], gate_valid: bool) -> str:
    if any(f.blocking for f in findings) or not gate_valid:
        return BLOCKED
    if findings:
        return WARN
    return PASS


def _parse(raw: RawInput | None, parser, errors: list[InputError]):
    if raw is None or raw.data is None:
        return None
    try:
        return parser(raw.data)
    except InputValidationError as exc:
        errors.extend(exc.errors)
        return None


def evaluate(
    plan_path: str | Path,
    approval_path: str | Path | None,
    policy_path: str | Path,
    run_id: str,
) -> EvaluationResult:
    errors: list[InputError] = []
    plan_raw, read_errors = read_input(plan_path, "plan")
    errors.extend(read_errors)
    policy_raw, read_errors = read_input(policy_path, "policy")
    errors.extend(read_errors)
    approval_raw = None
    if approval_path is not None:
        approval_raw, read_errors = read_input(approval_path, "approval")
        errors.extend(read_errors)

    def error_result(all_errors: list[InputError], plan=None, approval=None, policy=None):
        return EvaluationResult(
            run_id=run_id,
            decision=ERROR,
            plan_input=plan_raw,
            approval_input=approval_raw,
            policy_input=policy_raw,
            plan=plan,
            approval=approval,
            policy=policy,
            findings=(),
            assessment=None,
            errors=tuple(finalize_errors(all_errors)),
        )

    plan = approval = policy = None
    try:
        plan = _parse(plan_raw, parse_plan, errors)
        policy = _parse(policy_raw, parse_policy, errors)
        approval = _parse(approval_raw, parse_approval, errors)
        if errors:
            return error_result(errors, plan, approval, policy)

        findings: list[Finding] = []
        for rule in POLICY_RULES:
            findings.extend(rule.evaluate(plan, policy))
        assessment = approval_gate.assess(plan, approval, policy)
        findings.extend(assessment.findings)
        ordered = sort_findings(findings)
        decision = decide(ordered, assessment.valid)
    except Exception as exc:  # noqa: BLE001 - any evaluator failure must become ERROR (REQ-018)
        internal = InputError(
            "evaluator",
            "evaluator_internal_error",
            "$",
            f"unexpected {type(exc).__name__} during evaluation; treated as ERROR",
        )
        return error_result([internal], plan, approval, policy)

    return EvaluationResult(
        run_id=run_id,
        decision=decision,
        plan_input=plan_raw,
        approval_input=approval_raw,
        policy_input=policy_raw,
        plan=plan,
        approval=approval,
        policy=policy,
        findings=ordered,
        assessment=assessment,
        errors=(),
    )
