"""Spec traceability (NFR-006) and lint gate (NFR-005)."""

from __future__ import annotations

import ast
import re
import subprocess
import sys

from helpers import PROJECT_ROOT, SPEC_DIR

ID_DEFINITION = re.compile(r"^- \*\*((?:REQ|NFR|SAFE)-\d{3})\b", re.MULTILINE)
MATRIX_HEADING = "## 3. Traceability matrix"


def defined_ids(requirements_text: str) -> list[str]:
    return ID_DEFINITION.findall(requirements_text)


def matrix_rows(validation_text: str) -> dict[str, tuple[list[str], list[str], str]]:
    section = validation_text.split(MATRIX_HEADING, 1)[1]
    rows = {}
    for line in section.splitlines():
        match = re.match(r"^\| ((?:REQ|NFR|SAFE)-\d{3}) \| (.*?) \| (.*?) \| (.*?) \|$", line)
        if match:
            ident, tests, impl, evidence = match.groups()
            rows[ident] = (
                re.findall(r"`([^`]+)`", tests),
                re.findall(r"`([^`]+)`", impl),
                evidence.strip(),
            )
    return rows


def collect_test_names() -> set[str]:
    names = set()
    for path in (PROJECT_ROOT / "tests").rglob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names.update(
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
        )
    return names


def trace_problems(requirements_text, validation_text, tests, root) -> list[str]:
    ids = defined_ids(requirements_text)
    rows = matrix_rows(validation_text)
    problems = []
    if len(ids) != len(set(ids)):
        problems.append("duplicate requirement IDs")
    for ident in ids:
        if ident not in rows:
            problems.append(f"{ident}: no traceability row")
            continue
        row_tests, impls, evidence = rows[ident]
        if not row_tests:
            problems.append(f"{ident}: no tests mapped")
        problems += [f"{ident}: test {t} not found" for t in row_tests if t not in tests]
        if not impls:
            problems.append(f"{ident}: no implementation mapped")
        problems += [f"{ident}: path {p} missing" for p in impls if not (root / p).exists()]
        if not evidence:
            problems.append(f"{ident}: no evidence artifact")
    problems += [f"{ident}: row for undefined ID" for ident in rows if ident not in ids]
    return problems


def test_every_requirement_is_traced():
    requirements = (SPEC_DIR / "requirements.md").read_text(encoding="utf-8")
    validation = (SPEC_DIR / "validation.md").read_text(encoding="utf-8")
    ids = defined_ids(requirements)
    assert len(ids) == 39
    assert {i.split("-")[0] for i in ids} == {"REQ", "NFR", "SAFE"}
    assert trace_problems(requirements, validation, collect_test_names(), PROJECT_ROOT) == []


def test_traceability_checker_rejects_unmapped_requirement():
    requirements = (SPEC_DIR / "requirements.md").read_text(encoding="utf-8")
    validation = (SPEC_DIR / "validation.md").read_text(encoding="utf-8")
    tests = collect_test_names()
    extended = requirements + "\n- **REQ-999 (Unmapped).** A requirement nobody traced.\n"
    assert "REQ-999: no traceability row" in trace_problems(
        extended, validation, tests, PROJECT_ROOT
    )
    broken = validation.replace("`test_gate_rejected`", "`test_gate_rejected_missing`")
    problems = trace_problems(requirements, broken, tests, PROJECT_ROOT)
    assert "REQ-014: test test_gate_rejected_missing not found" in problems
    no_evidence = re.sub(r"(\| REQ-022 \|.*\|) [^|]+ \|$", r"\1  |", validation, flags=re.MULTILINE)
    assert "REQ-022: no evidence artifact" in trace_problems(
        requirements, no_evidence, tests, PROJECT_ROOT
    )


def test_ruff_check_passes():
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "."],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
