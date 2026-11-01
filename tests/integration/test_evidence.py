"""Evidence bundles: REQ-019 to REQ-021, NFR-002, SAFE-007, SAFE-008."""

from __future__ import annotations

import getpass
import hashlib
import platform
import re

import pytest
from helpers import (
    APPROVALS,
    PLANS,
    POLICY,
    PROJECT_ROOT,
    approval_path,
    evaluate_cli,
    plan_path,
    read_json,
    run_cli,
)

from iac_change_control.evidence import BUNDLE_FILES, HASHED_FILES
from iac_change_control.models import NOTICE
from iac_change_control.plan_loader import validator_for

CASES = {
    "pass": ("compliant", "approved-change"),
    "warn": ("warn-nonstandard-port", "approved-warn-change"),
    "blocked": ("mixed-violations", "approved-mixed-violations"),
    "no-approval": ("compliant", None),
    "error": ("malformed", "approved-change"),
}


@pytest.fixture(scope="module")
def bundles(tmp_path_factory):
    root = tmp_path_factory.mktemp("bundles")
    for name, (plan, approval) in CASES.items():
        evaluate_cli(
            root / name,
            plan_path(plan),
            approval_path(approval) if approval else None,
            run_id=f"evidence-{name}",
        )
    return root


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# -- REQ-019 --------------------------------------------------------------------------------
def test_bundle_contains_exactly_five_files(bundles):
    for name in CASES:
        assert sorted(p.name for p in (bundles / name).iterdir()) == list(BUNDLE_FILES), name


def test_evaluation_json_content(bundles):
    evaluation = read_json(bundles / "blocked" / "evaluation.json")
    assert evaluation["decision"] == "BLOCKED" and evaluation["exit_code"] == 1
    assert evaluation["run_id"] == "evidence-blocked"
    assert evaluation["plan_fixture_id"] == "plan-mixed-violations"
    assert evaluation["change_context"] == {"change_ref": "LAB-CHG-0009", "environment": "lab-dev"}
    assert (
        evaluation["change_set_digest"]
        == read_json(APPROVALS / "approved-mixed-violations.json")["change_set_digest"]
    )
    assert evaluation["finding_counts"] == {
        "total": 5,
        "blocking": 4,
        "non_blocking": 1,
        "by_severity": {"critical": 2, "high": 3, "medium": 0, "low": 0},
    }
    assert evaluation["approval_gate"] == {"result": "valid", "failed_checks": []}
    assert evaluation["decision_basis"] == "BLOCKED: 4 blocking policy finding(s)."
    assert [r["address"] for r in evaluation["resource_changes"]] == sorted(
        r["address"] for r in evaluation["resource_changes"]
    )


def test_error_run_still_writes_bundle(bundles):
    evaluation = read_json(bundles / "error" / "evaluation.json")
    assert evaluation["decision"] == "ERROR" and evaluation["exit_code"] == 2
    assert evaluation["findings"] == [] and evaluation["change_set_digest"] is None
    assert evaluation["approval_gate"]["result"] == "not_evaluated"
    assert [e["code"] for e in evaluation["errors"]] == ["json_parse_error"]
    assessment = read_json(bundles / "error" / "approval-assessment.json")
    assert assessment["gate_result"] == "not_evaluated" and assessment["checks"] == []
    assert "Input errors (1)" in (bundles / "error" / "summary.md").read_text(encoding="utf-8")


def test_evidence_conforms_to_schema(bundles):
    validator = validator_for("evidence")
    for name in CASES:
        assert validator.validate(read_json(bundles / name / "evaluation.json")) == [], name
        assert (
            validator.validate(
                read_json(bundles / name / "provenance.json"),
                validator.subschema("#/$defs/provenance"),
            )
            == []
        ), name
        assert (
            validator.validate(
                read_json(bundles / name / "approval-assessment.json"),
                validator.subschema("#/$defs/approval_assessment"),
            )
            == []
        ), name


# -- REQ-020 --------------------------------------------------------------------------------
def test_provenance_hashes_match_inputs(bundles):
    provenance = read_json(bundles / "blocked" / "provenance.json")
    inputs = provenance["inputs"]
    plan_file = PLANS / "mixed-violations.json"
    approval_file = APPROVALS / "approved-mixed-violations.json"
    assert inputs["plan"] == {
        "filename": "mixed-violations.json",
        "sha256": sha(plan_file),
        "size_bytes": plan_file.stat().st_size,
        "fixture_id": "plan-mixed-violations",
    }
    assert inputs["approval"] == {
        "filename": approval_file.name,
        "sha256": sha(approval_file),
        "size_bytes": approval_file.stat().st_size,
        "approval_id": "APR-LAB-0010",
    }
    assert inputs["policy"] == {
        "filename": "policy-config.json",
        "sha256": sha(POLICY),
        "size_bytes": POLICY.stat().st_size,
        "policy_id": "lab-baseline",
        "policy_version": "1.0.0",
    }
    assert provenance["evaluator"] == {"name": "iac-change-control-lab", "version": "0.1.0"}
    assert provenance["decision"] == "BLOCKED" and provenance["run_id"] == "evidence-blocked"
    assert provenance["digest_scheme"] == "iac-lab-changeset/v1"
    error_provenance = read_json(bundles / "error" / "provenance.json")
    assert error_provenance["inputs"]["plan"]["sha256"] == sha(PLANS / "malformed.json")
    assert error_provenance["inputs"]["plan"]["fixture_id"] is None


def test_provenance_without_approval(bundles):
    provenance = read_json(bundles / "no-approval" / "provenance.json")
    assert provenance["inputs"]["approval"] is None
    assessment = read_json(bundles / "no-approval" / "approval-assessment.json")
    assert assessment["approval_provided"] is False and assessment["presented"] is None
    assert "Approval input | none provided" in (bundles / "no-approval" / "summary.md").read_text(
        encoding="utf-8"
    )


# -- REQ-021 --------------------------------------------------------------------------------
def test_manifest_lists_hashes_in_stable_order(bundles):
    for name in CASES:
        directory = bundles / name
        raw = (directory / "manifest.sha256").read_bytes()
        assert raw.endswith(b"\n") and b"\r" not in raw
        lines = raw.decode("utf-8").splitlines()
        assert [line.split("  ")[1] for line in lines] == list(HASHED_FILES)
        for line in lines:
            digest, filename = line.split("  ")
            assert re.fullmatch(r"[0-9a-f]{64}", digest)
            assert sha(directory / filename) == digest


def test_verify_bundle_accepts_intact_bundle(bundles):
    for name in CASES:
        code, stdout, _ = run_cli("verify-bundle", "--bundle", str(bundles / name))
        assert code == 0 and stdout.startswith("OK"), name


def test_verify_bundle_detects_tampering(tmp_path):
    out = tmp_path / "b"
    evaluate_cli(out, plan_path("compliant"), approval_path("approved-change"))
    evaluation = out / "evaluation.json"
    evaluation.write_bytes(evaluation.read_bytes().replace(b'"PASS"', b'"FAIL"'))
    code, _, stderr = run_cli("verify-bundle", "--bundle", str(out))
    assert code == 1 and "evaluation.json hash does not match" in stderr
    (out / "extra.txt").write_text("x", encoding="utf-8")
    (out / "summary.md").unlink()
    code, _, stderr = run_cli("verify-bundle", "--bundle", str(out))
    assert (
        code == 1 and "summary.md is missing" in stderr and "unexpected entry extra.txt" in stderr
    )
    assert run_cli("verify-bundle", "--bundle", str(tmp_path / "nope"))[0] == 2


# -- NFR-002 --------------------------------------------------------------------------------
def test_evidence_has_no_timestamps_absolute_paths_or_host_data(bundles):
    forbidden_literals = {
        str(PROJECT_ROOT),
        str(PROJECT_ROOT).replace("\\", "/"),
        str(bundles),
        platform.node(),
        getpass.getuser(),
        platform.python_version(),
    }
    timestamp = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
    drive_or_root = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]|\"/(home|Users|tmp|var)/")
    uuid_like = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
    for name in CASES:
        for path in (bundles / name).iterdir():
            text = path.read_text(encoding="utf-8")
            for literal in forbidden_literals:
                if literal and len(literal) > 2:
                    assert literal not in text, (path, literal)
            assert not timestamp.search(text), path
            assert not drive_or_root.search(text), path
            assert not uuid_like.search(text), path


# -- SAFE-007 / SAFE-008 --------------------------------------------------------------------
def test_every_evidence_file_labelled_synthetic(bundles):
    for name in CASES:
        directory = bundles / name
        for filename in ("evaluation.json", "provenance.json", "approval-assessment.json"):
            document = read_json(directory / filename)
            assert document["synthetic_inputs"] is True and document["notice"] == NOTICE
        summary = (directory / "summary.md").read_text(encoding="utf-8")
        assert "SYNTHETIC / LOCAL FIXTURES ONLY" in summary.splitlines()[2]
    code, stdout, _ = evaluate_cli(bundles.parent / "label-check", plan_path("compliant"))
    assert "synthetic/local fixtures; no infrastructure was changed" in stdout


def test_evidence_states_no_authorization_and_human_review(bundles):
    for name in CASES:
        directory = bundles / name
        evaluation = read_json(directory / "evaluation.json")
        assert "not authorization" in evaluation["notice"]
        assert "human review remains required" in evaluation["notice"]
        assert "applies no infrastructure change" in evaluation["notice"]
        assert any("not authorization" in claim for claim in evaluation["non_claims"])
        summary = (directory / "summary.md").read_text(encoding="utf-8").rstrip("\n")
        assert summary.endswith("human review remains required, outside the tool.")
