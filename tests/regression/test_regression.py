"""Regression goldens and byte-stability checks: REQ-007, NFR-001.

To update a golden file after an intentional change, regenerate it with the CLI command shown in
``tests/regression/golden/README.md``. Review the diff, and update the specs if behaviour changed.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from helpers import (
    APPROVALS,
    POLICY,
    PROJECT_ROOT,
    REGRESSION,
    approval_path,
    bundle_files,
    evaluate_cli,
    plan_path,
    read_json,
)

from iac_change_control.plan_loader import load_plan
from iac_change_control.policy_engine import evaluate

EXPECTED = read_json(REGRESSION / "expected_outcomes.json")
GOLDEN = REGRESSION / "golden"


@pytest.mark.parametrize("case", EXPECTED["cases"], ids=lambda c: f"row{c['row']:02d}")
def test_fixture_outcomes_match_golden(case):
    policy = PROJECT_ROOT / case["policy"] if case["policy"] else POLICY
    approval = approval_path(case["approval"]) if case["approval"] else None
    result = evaluate(plan_path(case["plan"]), approval, policy, f"row-{case['row']}")
    assert result.decision == case["decision"]
    assert result.exit_code == case["exit_code"]
    assert [f.rule_id for f in result.findings] == case["rule_ids"]
    assert sorted({e.code for e in result.errors}) == case["error_codes"]


def test_golden_digests():
    for name, digest in EXPECTED["digests"].items():
        assert load_plan(plan_path(name)).change_set_digest == digest, name
    # Every "approved-<plan>" fixture pins exactly its plan's digest.
    pairs = {
        "approved-change": "compliant",
        "approved-warn-change": "warn-nonstandard-port",
        "approved-destroy-standard": "destroy-change",
        "approved-destroy-elevated": "destroy-change",
    }
    for path in APPROVALS.glob("approved-*.json"):
        plan_name = pairs.get(path.stem, path.stem.removeprefix("approved-"))
        assert read_json(path)["change_set_digest"] == EXPECTED["digests"][plan_name], path.name


@pytest.mark.parametrize(
    ("golden", "plan", "approval"),
    [
        ("compliant", "compliant", "approved-change"),
        ("mixed-violations", "mixed-violations", "approved-mixed-violations"),
    ],
)
def test_golden_evaluation_files(tmp_path, golden, plan, approval):
    out = tmp_path / golden
    evaluate_cli(out, plan_path(plan), approval_path(approval), run_id=f"golden-{golden}")
    expected = (GOLDEN / f"{golden}.evaluation.json").read_bytes()
    assert (out / "evaluation.json").read_bytes() == expected


def test_repeated_runs_byte_identical(tmp_path):
    for name in ("a", "b"):
        code, _, _ = evaluate_cli(
            tmp_path / name,
            plan_path("compliant"),
            approval_path("approved-change"),
            run_id="fixture-compliant-v1",
        )
        assert code == 0
    first, second = bundle_files(tmp_path / "a"), bundle_files(tmp_path / "b")
    assert len(first) == 5 and first == second


def _subprocess_bundle(out, cwd, seed, plan, approval, policy):
    env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(PROJECT_ROOT / "src"))
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "iac_change_control.cli",
            "evaluate",
            "--plan",
            plan,
            "--approval",
            approval,
            "--policy",
            policy,
            "--output",
            str(out),
            "--run-id",
            "fixture-mixed-v1",
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 1, proc.stderr
    return bundle_files(out)


def test_byte_identical_across_hash_seeds_and_working_directories(tmp_path):
    relative = _subprocess_bundle(
        tmp_path / "rel",
        PROJECT_ROOT,
        "0",
        "fixtures/plans/mixed-violations.json",
        "fixtures/approvals/approved-mixed-violations.json",
        "policy/policy-config.json",
    )
    absolute = _subprocess_bundle(
        tmp_path / "abs",
        tmp_path,
        "12345",
        str(plan_path("mixed-violations")),
        str(approval_path("approved-mixed-violations")),
        str(POLICY),
    )
    assert relative == absolute
    evaluate_cli(
        tmp_path / "inproc",
        plan_path("mixed-violations"),
        approval_path("approved-mixed-violations"),
        run_id="fixture-mixed-v1",
    )
    assert bundle_files(tmp_path / "inproc") == relative
