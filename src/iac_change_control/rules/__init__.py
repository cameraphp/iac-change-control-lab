"""Policy rules. Each module exposes ``evaluate(plan, policy) -> list[Finding]``.

The approval gate (``approval_gate.assess``) runs separately in ``policy_engine``. Rules cannot
be disabled through configuration.
"""

from iac_change_control.rules import (
    destroy_changes,
    provider_version,
    public_ingress,
    required_tags,
    storage_encryption,
    wildcard_iam,
)

POLICY_RULES = (
    public_ingress,
    wildcard_iam,
    storage_encryption,
    destroy_changes,
    required_tags,
    provider_version,
)

__all__ = ["POLICY_RULES"]
