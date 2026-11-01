"""Terraform and provider version metadata control: IAC-VER-001 to 004 (blocking). REQ-013.

This is metadata validation only. It compares fixture metadata with policy ranges and the
allowlist. It never initializes, resolves or downloads a provider.
"""

from __future__ import annotations

from iac_change_control.models import Finding, Plan, Policy, format_semver, parse_semver


def _range_text(low: tuple[int, int, int], high: tuple[int, int, int]) -> str:
    return f">= {format_semver(low)}, < {format_semver(high)}"


def evaluate(plan: Plan, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    terraform = parse_semver(plan.terraform_version)
    if not policy.terraform_min <= terraform < policy.terraform_max:
        findings.append(
            Finding(
                "IAC-VER-001",
                "terraform",
                "terraform_version",
                f"terraform_version {plan.terraform_version} is outside the supported range "
                f"({_range_text(policy.terraform_min, policy.terraform_max)})",
                "Use a Terraform version inside the policy's supported range.",
            )
        )
    for name, meta in sorted(plan.providers.items()):
        address = f"provider.{name}"
        allowance = policy.provider_allowlist.get(name)
        if allowance is None or allowance.source != meta.source:
            if allowance is None:
                why = "is not in the provider allowlist"
            else:
                why = "source does not match the allowlisted source"
            findings.append(
                Finding(
                    "IAC-VER-002",
                    address,
                    "source",
                    f"provider '{name}' ({meta.source}) {why}",
                    "Use an allowlisted provider and source, or request a policy change through "
                    "review.",
                )
            )
        else:
            selected = parse_semver(meta.selected_version)
            if not allowance.min_inclusive <= selected < allowance.max_exclusive:
                allowed = _range_text(allowance.min_inclusive, allowance.max_exclusive)
                findings.append(
                    Finding(
                        "IAC-VER-003",
                        address,
                        "selected_version",
                        f"provider '{name}' selected_version {meta.selected_version} is outside "
                        f"the allowed range ({allowed})",
                        "Pin the provider to a version inside the allowed range.",
                    )
                )
        if not (meta.version_constraint or "").strip():
            findings.append(
                Finding(
                    "IAC-VER-004",
                    address,
                    "version_constraint",
                    f"provider '{name}' has no version constraint",
                    "Declare an explicit provider version constraint.",
                )
            )
    return findings
