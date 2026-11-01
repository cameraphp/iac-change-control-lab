"""Deterministic evidence bundles: write and verify. REQ-019 to REQ-021, REQ-024, NFR-001,
NFR-002, SAFE-007, SAFE-008.

The bundle has five files:

    evaluation.json            decision, findings, gate result, errors, notice, non-claims
    summary.md                 human-readable rendering of the same evaluation
    provenance.json            input basenames, SHA-256 and sizes, policy and evaluator identity
    approval-assessment.json   every approval-gate check, with expected and presented values
    manifest.sha256            "<sha256>  <name>" for the four files above, sorted by name

No file contains a timestamp, a random value, an absolute path or host data.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from iac_change_control.canonical import evidence_json_bytes, sha256_hex, text_bytes
from iac_change_control.models import (
    ASSESSMENT_SCHEMA,
    DIGEST_SCHEME,
    EVALUATOR_NAME,
    EVALUATOR_VERSION,
    EVIDENCE_SCHEMA,
    NON_CLAIMS,
    NOTICE,
    PROVENANCE_SCHEMA,
    SEVERITIES,
)
from iac_change_control.plan_loader import RawInput
from iac_change_control.policy_engine import EvaluationResult

EVALUATION_FILE = "evaluation.json"
SUMMARY_FILE = "summary.md"
PROVENANCE_FILE = "provenance.json"
ASSESSMENT_FILE = "approval-assessment.json"
MANIFEST_FILE = "manifest.sha256"
HASHED_FILES = tuple(sorted((ASSESSMENT_FILE, EVALUATION_FILE, PROVENANCE_FILE, SUMMARY_FILE)))
BUNDLE_FILES = tuple(sorted((*HASHED_FILES, MANIFEST_FILE)))
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")

HUMAN_REVIEW_FOOTER = (
    "This tool applies no infrastructure change. A PASS or WARN is not authorization to change "
    "infrastructure; human review remains required, outside the tool."
)


class OutputDirectoryError(Exception):
    """The output directory cannot safely receive a bundle (REQ-024)."""


class BundleReadError(Exception):
    """The bundle directory or manifest cannot be read."""


def _evaluator() -> dict[str, str]:
    return {"name": EVALUATOR_NAME, "version": EVALUATOR_VERSION}


# -- documents ----------------------------------------------------------------------------------
def build_evaluation(result: EvaluationResult) -> dict[str, Any]:
    plan = result.plan
    findings = [f.to_dict() for f in result.findings]
    by_severity = {s: sum(1 for f in result.findings if f.severity == s) for s in SEVERITIES}
    blocking = sum(1 for f in result.findings if f.blocking)
    assessment = result.assessment
    return {
        "evidence_schema": EVIDENCE_SCHEMA,
        "synthetic_inputs": True,
        "notice": NOTICE,
        "run_id": result.run_id,
        "decision": result.decision,
        "exit_code": result.exit_code,
        "decision_basis": result.decision_basis,
        "change_set_digest": result.change_set_digest,
        "plan_fixture_id": plan.fixture_id if plan else None,
        "change_context": dict(plan.change_context) if plan else None,
        "resource_changes": [
            {"address": rc.address, "type": rc.type, "actions": list(rc.actions)}
            for rc in (plan.resources if plan else ())
        ],
        "findings": findings,
        "finding_counts": {
            "total": len(findings),
            "blocking": blocking,
            "non_blocking": len(findings) - blocking,
            "by_severity": by_severity,
        },
        "approval_gate": {
            "result": assessment.gate_result if assessment else "not_evaluated",
            "failed_checks": assessment.failed_checks if assessment else [],
        },
        "errors": [e.to_dict() for e in result.errors],
        "evaluator": _evaluator(),
        "non_claims": list(NON_CLAIMS),
    }


def _input_record(raw: RawInput | None, extra: dict[str, Any]) -> dict[str, Any] | None:
    if raw is None:
        return None
    return {"filename": raw.filename, "sha256": raw.sha256, "size_bytes": raw.size_bytes, **extra}


def build_provenance(result: EvaluationResult) -> dict[str, Any]:
    plan, approval, policy = result.plan, result.approval, result.policy
    return {
        "provenance_schema": PROVENANCE_SCHEMA,
        "synthetic_inputs": True,
        "notice": NOTICE,
        "run_id": result.run_id,
        "decision": result.decision,
        "exit_code": result.exit_code,
        "evaluator": _evaluator(),
        "inputs": {
            "plan": _input_record(
                result.plan_input, {"fixture_id": plan.fixture_id if plan else None}
            ),
            "approval": _input_record(
                result.approval_input, {"approval_id": approval.approval_id if approval else None}
            ),
            "policy": _input_record(
                result.policy_input,
                {
                    "policy_id": policy.policy_id if policy else None,
                    "policy_version": policy.policy_version if policy else None,
                },
            ),
        },
        "change_set_digest": result.change_set_digest,
        "digest_scheme": DIGEST_SCHEME,
    }


def build_assessment(result: EvaluationResult) -> dict[str, Any]:
    assessment = result.assessment
    approval = result.approval
    presented = None
    if approval is not None:
        presented = {
            "approval_id": approval.approval_id,
            "status": approval.status,
            "approval_level": approval.approval_level,
            "approver_role": approval.approver_role,
            "scope": dict(approval.scope),
            "change_set_digest": approval.change_set_digest,
            "policy_version": approval.policy_version,
            "approved_destructive_addresses": sorted(approval.approved_destructive_addresses),
        }
    if assessment is None:
        note = "The approval gate was not evaluated because the run ended in ERROR."
    else:
        note = "The approval record is synthetic data; this tool does not authenticate approvers."
    return {
        "assessment_schema": ASSESSMENT_SCHEMA,
        "synthetic_inputs": True,
        "notice": NOTICE,
        "run_id": result.run_id,
        "gate_result": assessment.gate_result if assessment else "not_evaluated",
        "approval_provided": result.approval_input is not None,
        "presented": presented,
        "expected": assessment.expected if assessment else None,
        "checks": [dict(c) for c in assessment.checks] if assessment else [],
        "note": note,
    }


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def render_summary(result: EvaluationResult, provenance: dict[str, Any]) -> str:
    inputs = provenance["inputs"]
    lines = [
        f"# Synthetic change-control evaluation: `{result.run_id}`",
        "",
        f"> **{NOTICE}**",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Decision | **{result.decision}** (exit code {result.exit_code}) |",
        f"| Run ID | `{_cell(result.run_id)}` |",
        f"| Change-set digest | `{_cell(result.change_set_digest or 'not computed')}` |",
    ]
    for role in ("plan", "approval", "policy"):
        record = inputs[role]
        if record is None:
            lines.append(f"| {role.capitalize()} input | none provided |")
        else:
            digest = record["sha256"] or "unreadable"
            lines.append(
                f"| {role.capitalize()} input | `{_cell(record['filename'])}` (sha256 `{digest}`) |"
            )
    if result.policy:
        lines.append(
            f"| Policy | `{result.policy.policy_id}` version `{result.policy.policy_version}` |"
        )
    lines += [
        f"| Evaluator | {EVALUATOR_NAME} {EVALUATOR_VERSION} |",
        "",
        "## Decision basis",
        "",
        result.decision_basis,
        "",
        f"## Findings ({len(result.findings)})",
        "",
    ]
    if result.findings:
        lines += [
            "| # | Rule | Severity | Blocking | Address | Reason | Remediation |",
            "|---|---|---|---|---|---|---|",
        ]
        for index, finding in enumerate(result.findings, start=1):
            lines.append(
                f"| {index} | `{finding.rule_id}` | {finding.severity} | "
                f"{'yes' if finding.blocking else 'no'} | `{_cell(finding.address)}` | "
                f"{_cell(finding.reason)} | {_cell(finding.remediation)} |"
            )
    else:
        lines.append("No findings.")
    lines += ["", "## Approval gate", ""]
    if result.assessment is None:
        lines.append("Not evaluated (the run ended in ERROR).")
    else:
        lines += [
            f"Result: **{result.assessment.gate_result}**",
            "",
            "| Check | Name | Result | Detail |",
            "|---|---|---|---|",
        ]
        for check in result.assessment.checks:
            lines.append(
                f"| `{check['check_id']}` | {check['name']} | {check['result']} | "
                f"{_cell(check['detail'])} |"
            )
    if result.errors:
        lines += [
            "",
            f"## Input errors ({len(result.errors)})",
            "",
            "| Source | Code | Path | Message |",
            "|---|---|---|---|",
        ]
        for error in result.errors:
            lines.append(
                f"| {error.source} | `{error.code}` | `{_cell(error.path)}` | "
                f"{_cell(error.message)} |"
            )
    lines += ["", "## Limitations", ""]
    lines += [f"- {claim}" for claim in NON_CLAIMS]
    lines += ["", HUMAN_REVIEW_FOOTER]
    return "\n".join(lines)


# -- writing ------------------------------------------------------------------------------------
def check_output_dir(output_dir: Path) -> None:
    if output_dir.exists() and not output_dir.is_dir():
        raise OutputDirectoryError("output path exists and is not a directory")
    if output_dir.is_dir():
        foreign = sorted(p.name for p in output_dir.iterdir() if p.name not in BUNDLE_FILES)
        if foreign:
            raise OutputDirectoryError(
                f"output directory contains {len(foreign)} entry(ies) that are not bundle files; "
                "refusing to write"
            )
        for name in BUNDLE_FILES:
            if (output_dir / name).exists() and not (output_dir / name).is_file():
                raise OutputDirectoryError(f"bundle entry {name} is not a regular file")


def bundle_bytes(result: EvaluationResult) -> dict[str, bytes]:
    provenance = build_provenance(result)
    files = {
        EVALUATION_FILE: evidence_json_bytes(build_evaluation(result)),
        PROVENANCE_FILE: evidence_json_bytes(provenance),
        ASSESSMENT_FILE: evidence_json_bytes(build_assessment(result)),
        SUMMARY_FILE: text_bytes(render_summary(result, provenance)),
    }
    manifest = "".join(f"{sha256_hex(files[name])}  {name}\n" for name in HASHED_FILES)
    files[MANIFEST_FILE] = manifest.encode("utf-8")
    return files


def write_bundle(result: EvaluationResult, output_dir: str | Path) -> dict[str, str]:
    """Write the bundle and return ``{name: sha256}`` for every file written."""
    out = Path(output_dir)
    check_output_dir(out)
    files = bundle_bytes(result)
    out.mkdir(parents=True, exist_ok=True)
    for name in (*HASHED_FILES, MANIFEST_FILE):  # manifest last
        (out / name).write_bytes(files[name])
    return {name: sha256_hex(data) for name, data in sorted(files.items())}


# -- verification -------------------------------------------------------------------------------
def verify_bundle(bundle_dir: str | Path) -> list[str]:
    """Return a sorted list of problems. An empty list means the bundle matches its manifest."""
    directory = Path(bundle_dir)
    manifest_path = directory / MANIFEST_FILE
    if not directory.is_dir() or not manifest_path.is_file():
        raise BundleReadError("bundle directory or manifest.sha256 not found")
    try:
        manifest_text = manifest_path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BundleReadError("manifest.sha256 cannot be read") from exc

    problems: list[str] = []
    if not manifest_text.endswith("\n") or "\r" in manifest_text:
        problems.append("manifest is not LF-terminated")
    listed: list[tuple[str, str]] = []
    for number, line in enumerate(manifest_text.splitlines(), start=1):
        match = MANIFEST_LINE.match(line)
        if match is None:
            problems.append(f"manifest line {number} is malformed")
            continue
        listed.append((match.group(2), match.group(1)))
    names = [name for name, _ in listed]
    if names != list(HASHED_FILES):
        problems.append("manifest does not list exactly the four bundle files in sorted order")
    for name, expected in listed:
        path = directory / name
        if not path.is_file():
            problems.append(f"{name} is missing")
        elif sha256_hex(path.read_bytes()) != expected:
            problems.append(f"{name} hash does not match the manifest")
    extra = sorted(p.name for p in directory.iterdir() if p.name not in BUNDLE_FILES)
    problems.extend(f"unexpected entry {name}" for name in extra)
    return sorted(set(problems))
