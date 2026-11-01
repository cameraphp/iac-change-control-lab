"""CLI behaviour: REQ-001, REQ-018, REQ-022, REQ-024, NFR-004."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from helpers import (
    APPROVALS,
    INVALID_POLICY,
    PROJECT_ROOT,
    approval_path,
    bundle_files,
    evaluate_cli,
    plan_doc,
    plan_path,
    read_json,
    run_cli,
    write_json,
)

from iac_change_control.evidence import BUNDLE_FILES


# -- REQ-001 --------------------------------------------------------------------------------
def test_cli_evaluate_compliant_writes_bundle_and_exits_0(tmp_path):
    out = tmp_path / "run-compliant"
    code, stdout, stderr = evaluate_cli(
        out, plan_path("compliant"), approval_path("approved-change"), run_id="fixture-compliant-v1"
    )
    assert code == 0, stderr
    assert "decision=PASS exit=0" in stdout and "synthetic/local fixtures" in stdout
    assert sorted(p.name for p in out.iterdir()) == list(BUNDLE_FILES)
    assert read_json(out / "evaluation.json")["run_id"] == "fixture-compliant-v1"


@pytest.mark.parametrize(
    "run_id", ["Bad ID!", "", "UPPER", "_leading-underscore", "a" * 65, "x/y", "..\\up"]
)
def test_cli_rejects_invalid_run_id(tmp_path, run_id):
    out = tmp_path / "never"
    code, _, stderr = evaluate_cli(
        out, plan_path("compliant"), approval_path("approved-change"), run_id=run_id
    )
    assert code == 2
    assert "no bundle written" in stderr
    assert not out.exists()


def test_cli_requires_mandatory_arguments(tmp_path):
    base = {
        "--plan": str(plan_path("compliant")),
        "--policy": str(PROJECT_ROOT / "policy" / "policy-config.json"),
        "--output": str(tmp_path / "o"),
        "--run-id": "r1",
    }
    for missing in base:
        argv = ["evaluate"]
        for flag, value in base.items():
            if flag != missing:
                argv += [flag, value]
        code, _, _ = run_cli(*argv)
        assert code == 2, missing
    assert run_cli()[0] == 2
    assert not (tmp_path / "o").exists()


# -- REQ-018 --------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("plan", "approval", "decision", "code"),
    [
        ("compliant", "approved-change", "PASS", 0),
        ("warn-nonstandard-port", "approved-warn-change", "WARN", 0),
        ("destroy-change", "approved-destroy-elevated", "WARN", 0),
        ("wildcard-iam", "approved-wildcard-iam", "BLOCKED", 1),
        ("compliant", None, "BLOCKED", 1),
        ("malformed", "approved-change", "ERROR", 2),
        ("unsupported-resource", "approved-change", "ERROR", 2),
    ],
)
def test_cli_exit_codes_match_decisions(tmp_path, plan, approval, decision, code):
    out = tmp_path / "b"
    got, stdout, _ = evaluate_cli(
        out, plan_path(plan), approval_path(approval) if approval else None
    )
    evaluation = read_json(out / "evaluation.json")
    assert (got, evaluation["decision"], evaluation["exit_code"]) == (code, decision, code)
    assert f"decision={decision} exit={code}" in stdout


def test_invalid_inputs_never_pass(tmp_path):
    bad_plans = {}
    doc = plan_doc()
    doc["resource_changes"][0]["change"]["actions"] = ["apply"]
    bad_plans["unknown-action"] = write_json(tmp_path / "in" / "unknown-action.json", doc)
    doc = plan_doc()
    doc["resource_changes"][0]["change"]["after"]["cidr_blocks"] = ["100.64.0.0/10"]
    bad_plans["cidr"] = write_json(tmp_path / "in" / "cidr.json", doc)
    doc = plan_doc()
    doc["synthetic"] = "yes"
    bad_plans["not-synthetic"] = write_json(tmp_path / "in" / "not-synthetic.json", doc)
    (tmp_path / "in" / "bom.json").write_bytes(
        b"\xef\xbb\xbf" + plan_path("compliant").read_bytes()
    )
    bad_plans["bom"] = tmp_path / "in" / "bom.json"
    bad_plans["missing-file"] = tmp_path / "in" / "does-not-exist.json"
    bad_plans["malformed"] = plan_path("malformed")
    bad_plans["unsupported"] = plan_path("unsupported-resource")

    cases = [(path, approval_path("approved-change"), None) for path in bad_plans.values()]
    cases.append((plan_path("compliant"), approval_path("approved-change"), INVALID_POLICY))
    cases.append((plan_path("compliant"), tmp_path / "in" / "no-approval-here.json", None))
    broken_approval = tmp_path / "in" / "broken-approval.json"
    broken_approval.write_text('{"synthetic": true, "status": "approved"', encoding="utf-8")
    cases.append((plan_path("compliant"), broken_approval, None))

    for index, (plan, approval, policy) in enumerate(cases):
        out = tmp_path / f"out-{index}"
        kwargs = {"policy": policy} if policy else {}
        code, stdout, _ = evaluate_cli(out, plan, approval, **kwargs)
        evaluation = read_json(out / "evaluation.json")
        assert code == 2 and evaluation["decision"] == "ERROR", (plan.name, stdout)
        assert evaluation["findings"] == [] and evaluation["errors"]


# -- REQ-022 --------------------------------------------------------------------------------
def test_cli_digest_command():
    code, stdout, _ = run_cli("digest", "--plan", str(plan_path("compliant")))
    assert code == 0
    approval = read_json(APPROVALS / "approved-change.json")
    assert stdout.strip() == approval["change_set_digest"]


def test_cli_digest_invalid_plan_exits_2():
    code, stdout, stderr = run_cli("digest", "--plan", str(plan_path("malformed")))
    assert code == 2 and stdout == ""
    assert "json_parse_error" in stderr


# -- REQ-024 --------------------------------------------------------------------------------
def test_output_dir_with_foreign_files_refused(tmp_path):
    out = tmp_path / "occupied"
    out.mkdir()
    (out / "notes.txt").write_text("keep me", encoding="utf-8")
    code, _, stderr = evaluate_cli(out, plan_path("compliant"), approval_path("approved-change"))
    assert code == 2 and "refusing to write" in stderr
    assert [p.name for p in out.iterdir()] == ["notes.txt"]
    target_file = tmp_path / "a-file"
    target_file.write_text("x", encoding="utf-8")
    assert evaluate_cli(target_file, plan_path("compliant"))[0] == 2


def test_rerun_overwrites_bundle_in_place(tmp_path):
    out = tmp_path / "bundle"
    assert evaluate_cli(out, plan_path("compliant"), approval_path("approved-change"))[0] == 0
    first = bundle_files(out)
    assert evaluate_cli(out, plan_path("compliant"), None)[0] == 1
    second = bundle_files(out)
    assert sorted(second) == sorted(first) == list(BUNDLE_FILES)
    assert second["evaluation.json"] != first["evaluation.json"]
    assert read_json(out / "evaluation.json")["decision"] == "BLOCKED"


# -- NFR-004 --------------------------------------------------------------------------------
def test_evaluator_runs_with_empty_path(tmp_path):
    env = {"PATH": "", "PYTHONPATH": str(PROJECT_ROOT / "src")}
    for key in ("SYSTEMROOT", "SystemRoot"):
        if key in os.environ:
            env[key] = os.environ[key]
    out = tmp_path / "no-path"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "iac_change_control.cli",
            "evaluate",
            "--plan",
            str(plan_path("compliant")),
            "--approval",
            str(approval_path("approved-change")),
            "--policy",
            str(PROJECT_ROOT / "policy" / "policy-config.json"),
            "--output",
            str(out),
            "--run-id",
            "empty-path",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert read_json(out / "evaluation.json")["decision"] == "PASS"
