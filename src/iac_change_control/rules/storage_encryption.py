"""Storage-encryption control: IAC-ENC-001 (blocking). REQ-010.

It applies to the fictional bucket, database and disk types. Encryption fails when the block is
missing or null, when ``enabled`` is not ``true``, or when the algorithm is not on the policy
allowlist.
"""

from __future__ import annotations

from iac_change_control.models import STORAGE_TYPES, Finding, Plan, Policy


def evaluate(plan: Plan, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    allowed = ", ".join(policy.allowed_encryption_algorithms)
    remediation = (
        f"Enable encryption with an allowlisted algorithm ({allowed}) for this storage resource."
    )
    for rc in plan.resources:
        if rc.type not in STORAGE_TYPES or rc.after is None:
            continue
        encryption = rc.after.get("encryption")
        if encryption is None:
            reason = "encryption block is missing or null"
        elif encryption["enabled"] is not True:
            state = "null" if encryption["enabled"] is None else "false"
            reason = f"encryption.enabled is {state}"
        elif encryption["algorithm"] not in policy.allowed_encryption_algorithms:
            algorithm = encryption["algorithm"]
            shown = "null" if algorithm is None else f"'{algorithm}'"
            reason = f"encryption.algorithm {shown} is not allowed by policy"
        else:
            continue
        findings.append(Finding("IAC-ENC-001", rc.address, "encryption", reason, remediation))
    return findings
