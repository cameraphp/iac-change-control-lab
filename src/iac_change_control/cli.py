"""Command-line interface. REQ-001, REQ-018, REQ-021, REQ-022, REQ-024.

    evaluate       0 = PASS or WARN, 1 = BLOCKED, 2 = ERROR
    digest         0 = digest printed, 2 = invalid plan
    verify-bundle  0 = intact, 1 = mismatch, 2 = unreadable bundle

Argument errors exit 2, the same code as ERROR. Everything runs offline against local files.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from iac_change_control import __version__
from iac_change_control.evidence import (
    BundleReadError,
    OutputDirectoryError,
    check_output_dir,
    verify_bundle,
    write_bundle,
)
from iac_change_control.models import ERROR, EXIT_CODES, RUN_ID_PATTERN, InputValidationError
from iac_change_control.plan_loader import load_plan
from iac_change_control.policy_engine import evaluate

SYNTHETIC_TAG = "[synthetic/local fixtures; no infrastructure was changed]"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m iac_change_control.cli",
        description=(
            "Evaluate a synthetic Terraform-plan-like fixture against local policy rules and an "
            "approval gate, and write a deterministic evidence bundle. Lab only: no cloud, no "
            "credentials, no Terraform execution."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser("evaluate", help="evaluate a plan fixture and write an evidence bundle")
    ev.add_argument("--plan", required=True, help="synthetic plan fixture (JSON)")
    ev.add_argument("--approval", help="synthetic approval record (JSON); omitted = missing")
    ev.add_argument("--policy", required=True, help="policy configuration (JSON)")
    ev.add_argument("--output", required=True, help="evidence bundle directory")
    ev.add_argument("--run-id", required=True, help="caller-supplied stable run identifier")

    dg = sub.add_parser("digest", help="print the normalized change-set digest of a plan fixture")
    dg.add_argument("--plan", required=True)

    vb = sub.add_parser("verify-bundle", help="verify an evidence bundle against its manifest")
    vb.add_argument("--bundle", required=True)
    return parser


def _print_errors(errors) -> None:
    for error in errors:
        print(f"  {error.source}: {error.code} at {error.path}: {error.message}", file=sys.stderr)


def _cmd_evaluate(args: argparse.Namespace) -> int:
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        print(
            "ERROR: --run-id must match ^[a-z0-9][a-z0-9._-]{0,63}$; no bundle written",
            file=sys.stderr,
        )
        return EXIT_CODES[ERROR]
    try:
        check_output_dir(Path(args.output))
    except OutputDirectoryError as exc:
        print(f"ERROR: {exc}; no bundle written", file=sys.stderr)
        return EXIT_CODES[ERROR]

    result = evaluate(args.plan, args.approval, args.policy, args.run_id)
    try:
        write_bundle(result, args.output)
    except (OutputDirectoryError, OSError) as exc:
        print(f"ERROR: could not write evidence bundle ({type(exc).__name__})", file=sys.stderr)
        return EXIT_CODES[ERROR]

    rules = ",".join(f.rule_id for f in result.findings) or "-"
    print(
        f"decision={result.decision} exit={result.exit_code} run_id={result.run_id} "
        f"findings={len(result.findings)} rules={rules} {SYNTHETIC_TAG}"
    )
    if result.errors:
        _print_errors(result.errors)
    return result.exit_code


def _cmd_digest(args: argparse.Namespace) -> int:
    try:
        plan = load_plan(args.plan)
    except InputValidationError as exc:
        print("ERROR: plan is invalid; no digest computed", file=sys.stderr)
        _print_errors(exc.errors)
        return EXIT_CODES[ERROR]
    print(plan.change_set_digest)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        problems = verify_bundle(args.bundle)
    except BundleReadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if problems:
        print("MISMATCH:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("OK: bundle matches manifest.sha256")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "evaluate":
        return _cmd_evaluate(args)
    if args.command == "digest":
        return _cmd_digest(args)
    return _cmd_verify(args)


if __name__ == "__main__":
    raise SystemExit(main())
