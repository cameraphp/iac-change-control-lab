"""Shared test helpers (paths, fixture builders, CLI runner). Synthetic data only."""

from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT_ROOT / "fixtures"
PLANS = FIXTURES / "plans"
APPROVALS = FIXTURES / "approvals"
POLICY = PROJECT_ROOT / "policy" / "policy-config.json"
INVALID_POLICY = FIXTURES / "policies" / "invalid-policy.json"
SCHEMAS = PROJECT_ROOT / "schemas"
SPEC_DIR = PROJECT_ROOT / "specs" / "2026-11-01-iac-change-control"
REGRESSION = PROJECT_ROOT / "tests" / "regression"

VALID_PLAN_NAMES = (
    "compliant",
    "destroy-change",
    "missing-tags",
    "mixed-violations",
    "provider-version-violation",
    "public-ingress",
    "unencrypted-storage",
    "warn-nonstandard-port",
    "wildcard-iam",
)


def plan_path(name: str) -> Path:
    return PLANS / f"{name}.json"


def approval_path(name: str) -> Path:
    return APPROVALS / f"{name}.json"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def plan_doc(name: str = "compliant") -> dict[str, Any]:
    return copy.deepcopy(read_json(plan_path(name)))


def write_json(path: Path, doc: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def to_bytes(doc: Any) -> bytes:
    return json.dumps(doc).encode("utf-8")


def tags(**override: str) -> dict[str, str]:
    base = {"owner": "platform-lab", "environment": "lab-dev", "cost_center": "cc-lab-0001"}
    base.update(override)
    return base


def resource(rtype: str, name: str, after: Any, actions=("create",), before: Any = None) -> dict:
    return {
        "address": f"{rtype}.{name}",
        "type": rtype,
        "name": name,
        "provider_name": "labcloud",
        "change": {"actions": list(actions), "before": before, "after": after},
    }


def single_resource_plan(rc: dict, **top: Any) -> dict[str, Any]:
    doc = plan_doc("compliant")
    doc["resource_changes"] = [rc]
    doc.update(top)
    return doc


def matching_approval(
    plan, policy_version: str = "1.0.0", *, level: str = "standard", destructive=None
) -> dict[str, Any]:
    """Build a fully valid approval for a parsed ``Plan``."""
    return {
        "synthetic": True,
        "contract_version": "iac-lab-approval/v1",
        "approval_id": "APR-LAB-9001",
        "status": "approved",
        "scope": dict(plan.change_context),
        "change_set_digest": plan.change_set_digest,
        "policy_version": policy_version,
        "approval_level": level,
        "approver_role": "synthetic-change-reviewer",
        "approved_destructive_addresses": sorted(
            plan.destructive_addresses if destructive is None else destructive
        ),
    }


def run_cli(*argv: str) -> tuple[int, str, str]:
    """Run the CLI in-process and capture its exit code, stdout and stderr."""
    from iac_change_control.cli import main

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:  # argparse errors
            code = exc.code if isinstance(exc.code, int) else 2
    return code, out.getvalue(), err.getvalue()


def evaluate_cli(
    output: Path,
    plan: Path,
    approval: Path | None = None,
    policy: Path = POLICY,
    run_id: str = "test-run",
) -> tuple[int, str, str]:
    argv = [
        "evaluate",
        "--plan",
        str(plan),
        "--policy",
        str(policy),
        "--output",
        str(output),
        "--run-id",
        run_id,
    ]
    if approval is not None:
        argv += ["--approval", str(approval)]
    return run_cli(*argv)


def bundle_files(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir())}
