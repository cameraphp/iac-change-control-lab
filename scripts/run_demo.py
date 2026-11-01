"""End-to-end terminal walkthrough of the change-control lab (REQ-023).

Evaluates a fixed list of synthetic fixture cases, writes one evidence bundle per case under
``evidence/demo/<case>/`` (ignored by version control), verifies every bundle against its
manifest, and exits 0 only if every case produced its expected decision.

Everything is local and offline. Nothing is applied, planned or deployed.

Usage (project root, virtual environment active):

    python scripts/run_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    import iac_change_control  # noqa: F401
except ImportError:  # running from a checkout without the editable install
    sys.path.insert(0, str(ROOT / "src"))

from iac_change_control.evidence import verify_bundle, write_bundle  # noqa: E402
from iac_change_control.policy_engine import evaluate  # noqa: E402

OUTPUT_ROOT = ROOT / "evidence" / "demo"
POLICY = ROOT / "policy" / "policy-config.json"
BANNER = (
    "SYNTHETIC / LOCAL FIXTURES ONLY: no cloud account, no credentials, no Terraform "
    "execution, no infrastructure change"
)

# (case id, plan fixture, approval fixture or None, expected decision)
CASES = (
    ("01-pass-compliant", "compliant", "approved-change", "PASS"),
    ("02-warn-nonstandard-port", "warn-nonstandard-port", "approved-warn-change", "WARN"),
    ("03-blocked-public-ingress", "public-ingress", "approved-public-ingress", "BLOCKED"),
    ("04-blocked-destroy-standard", "destroy-change", "approved-destroy-standard", "BLOCKED"),
    ("05-warn-destroy-elevated", "destroy-change", "approved-destroy-elevated", "WARN"),
    ("06-blocked-mixed-violations", "mixed-violations", "approved-mixed-violations", "BLOCKED"),
    ("07-blocked-missing-approval", "compliant", "missing-approval", "BLOCKED"),
    ("08-error-malformed", "malformed", "approved-change", "ERROR"),
    ("09-error-unsupported-resource", "unsupported-resource", "approved-change", "ERROR"),
)


def main() -> int:
    print(f"iac-change-control-lab demo [{BANNER}]")
    print()
    header = f"{'case':<31} {'expected':<8} {'actual':<8} {'exit':<4} {'bundle':<8} rules / errors"
    print(header)
    print("-" * len(header))
    mismatches = 0
    for case_id, plan, approval, expected in CASES:
        approval_file = ROOT / "fixtures" / "approvals" / f"{approval}.json" if approval else None
        result = evaluate(
            ROOT / "fixtures" / "plans" / f"{plan}.json", approval_file, POLICY, f"demo-{case_id}"
        )
        out = OUTPUT_ROOT / case_id
        write_bundle(result, out)
        bundle_ok = not verify_bundle(out)
        detail = (
            ",".join(f.rule_id for f in result.findings)
            or ",".join(e.code for e in result.errors)
            or "-"
        )
        ok = result.decision == expected and bundle_ok
        mismatches += 0 if ok else 1
        print(
            f"{case_id:<31} {expected:<8} {result.decision:<8} {result.exit_code:<4} "
            f"{'verified' if bundle_ok else 'FAILED':<8} {detail}  [synthetic/local]"
        )
    print()
    relative = OUTPUT_ROOT.relative_to(ROOT).as_posix()
    if mismatches:
        print(f"DEMO FAILED: {mismatches} case(s) did not match their expected decision.")
        return 1
    print(f"All {len(CASES)} cases matched their expected decisions. Bundles: {relative}/<case>/")
    print(
        "Nothing was applied. A PASS or WARN is not authorization; human review remains required."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
