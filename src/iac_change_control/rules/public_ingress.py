"""Public-ingress control: IAC-NET-001 (blocking) and IAC-NET-002 (non-blocking). REQ-008.

A "world" CIDR has prefix length 0 (``0.0.0.0/0`` or ``::/0``). The loader has already proved
that every CIDR is canonical and inside the reserved ranges, so this rule only has to recognise
world exposure. Egress rules and non-world sources are out of scope for this control.
"""

from __future__ import annotations

import ipaddress

from iac_change_control.models import FIREWALL_TYPE, Finding, Plan, Policy

ALL_PORTS = (0, 65535)


def _world_cidrs(cidrs: list[str]) -> list[str]:
    return sorted(c for c in cidrs if ipaddress.ip_network(c).prefixlen == 0)


def _port_text(protocol: str, low: int, high: int) -> str:
    return f"{protocol} {low}-{high}"


def evaluate(plan: Plan, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for rc in plan.resources:
        if rc.type != FIREWALL_TYPE or rc.after is None:
            continue
        state = rc.after
        if state["direction"] != "ingress":
            continue
        world = _world_cidrs(state["cidr_blocks"])
        if not world:
            continue
        protocol, low, high = state["protocol"], state["from_port"], state["to_port"]
        sources = ", ".join(world)
        if protocol == "all" or (low, high) == ALL_PORTS:
            findings.append(
                Finding(
                    "IAC-NET-001",
                    rc.address,
                    "ingress",
                    f"ingress from {sources} exposes all ports ({_port_text(protocol, low, high)})",
                    "Restrict the source to a private or documented range, or limit the rule to "
                    "the specific allowed public ports.",
                )
            )
            continue
        exposed = [p for p in policy.sensitive_ports if low <= p <= high]
        if exposed:
            ports = ", ".join(str(p) for p in exposed)
            findings.append(
                Finding(
                    "IAC-NET-001",
                    rc.address,
                    "ingress",
                    f"ingress from {sources} exposes sensitive port(s) {ports} "
                    f"({_port_text(protocol, low, high)})",
                    "Remove world access to sensitive ports; use a private source range or an "
                    "access path outside this rule.",
                )
            )
            continue
        allowed = set(policy.allowed_public_ports)
        within_allowed = (high - low + 1) <= len(allowed) and all(
            p in allowed for p in range(low, high + 1)
        )
        if not within_allowed:
            findings.append(
                Finding(
                    "IAC-NET-002",
                    rc.address,
                    "ingress",
                    f"ingress from {sources} exposes non-allowlisted port range "
                    f"({_port_text(protocol, low, high)})",
                    "Confirm the exposure is intended, or move the service behind an allowed "
                    "public port; a human reviewer must accept this warning.",
                )
            )
    return findings
