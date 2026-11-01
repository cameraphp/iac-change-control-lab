"""Data model, constants, rule catalog and fixed wording (REQ-017, REQ-018, SAFE-007, SAFE-008)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from iac_change_control import __version__

EVALUATOR_NAME = "iac-change-control-lab"
EVALUATOR_VERSION = __version__

PLAN_CONTRACT = "iac-lab-plan/v1"
APPROVAL_CONTRACT = "iac-lab-approval/v1"
POLICY_CONTRACT = "iac-lab-policy/v1"
DIGEST_SCHEME = "iac-lab-changeset/v1"
EVIDENCE_SCHEMA = "iac-lab-evidence/v1"
PROVENANCE_SCHEMA = "iac-lab-provenance/v1"
ASSESSMENT_SCHEMA = "iac-lab-approval-assessment/v1"

# -- Plan contract constants (must equal the schema enumerations; see test_schema_enums...) -----
FIREWALL_TYPE = "labcloud_firewall_rule"
IAM_POLICY_TYPE = "labcloud_iam_policy"
BUCKET_TYPE = "labcloud_storage_bucket"
DATABASE_TYPE = "labcloud_database_instance"
DISK_TYPE = "labcloud_block_disk"
SUPPORTED_RESOURCE_TYPES = (BUCKET_TYPE, DATABASE_TYPE, DISK_TYPE, FIREWALL_TYPE, IAM_POLICY_TYPE)
STORAGE_TYPES = (BUCKET_TYPE, DATABASE_TYPE, DISK_TYPE)
TAGGABLE_TYPES = SUPPORTED_RESOURCE_TYPES

ACTION_VALUES = ("create", "delete", "no-op", "read", "update")
SUPPORTED_ACTION_LISTS = (
    ("no-op",),
    ("create",),
    ("update",),
    ("delete",),
    ("delete", "create"),
    ("create", "delete"),
)

APPROVAL_STATUSES = ("approved", "not_submitted", "rejected")
APPROVAL_LEVELS = ("elevated", "standard")

RUN_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_INPUT_BYTES = 1024 * 1024
MAX_REPORTED_ERRORS = 100

# -- Decisions ----------------------------------------------------------------------------------
PASS = "PASS"
WARN = "WARN"
BLOCKED = "BLOCKED"
ERROR = "ERROR"
EXIT_CODES = {PASS: 0, WARN: 0, BLOCKED: 1, ERROR: 2}

SEVERITIES = ("critical", "high", "medium", "low")

NOTICE = (
    "SYNTHETIC / LOCAL FIXTURES ONLY. Every input to this evaluation is a synthetic, "
    "checked-in fixture; it is not output from a real Terraform plan or cloud account. "
    "This tool applies no infrastructure change: nothing was created, modified, or destroyed. "
    "A PASS or WARN decision is not authorization to change infrastructure; human review "
    "remains required."
)

NON_CLAIMS = (
    "Inputs are synthetic fixtures, not real Terraform plans, state, or cloud resources.",
    "No cloud account, credential, remote state, or provider was accessed.",
    "Terraform was not executed: no init, plan, apply, destroy, import, or refresh occurred.",
    "The rule set is illustrative and incomplete; it is not a policy engine replacement.",
    "This is not a compliance control, audit result, or certification.",
    "A PASS or WARN is not authorization to change infrastructure; human review is required.",
)


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    title: str
    severity: str
    blocking: bool
    requires_elevated_approval: bool = False


RULE_CATALOG: dict[str, RuleInfo] = {
    info.rule_id: info
    for info in (
        RuleInfo("IAC-APR-001", "Approval missing", "high", True),
        RuleInfo("IAC-APR-002", "Approval rejected", "high", True),
        RuleInfo("IAC-APR-003", "Approval stale (policy version changed)", "high", True),
        RuleInfo("IAC-APR-004", "Approval out of scope", "high", True),
        RuleInfo("IAC-APR-005", "Approval digest mismatch", "high", True),
        RuleInfo("IAC-APR-006", "Elevated approval required for destructive change", "high", True),
        RuleInfo("IAC-APR-007", "Approved destructive addresses do not match", "high", True),
        RuleInfo("IAC-CHG-001", "Destructive change proposed", "high", False, True),
        RuleInfo("IAC-ENC-001", "Storage encryption missing or disallowed", "high", True),
        RuleInfo("IAC-IAM-001", "Wildcard IAM action or resource", "critical", True),
        RuleInfo("IAC-IAM-002", "Service-scoped IAM action wildcard", "medium", False),
        RuleInfo("IAC-NET-001", "Sensitive or all ports open to the world", "critical", True),
        RuleInfo("IAC-NET-002", "Non-allowlisted port open to the world", "medium", False),
        RuleInfo("IAC-TAG-001", "Required tags missing or blank", "high", True),
        RuleInfo("IAC-VER-001", "Terraform version outside supported range", "high", True),
        RuleInfo("IAC-VER-002", "Provider not allowlisted", "high", True),
        RuleInfo("IAC-VER-003", "Provider version outside allowed range", "high", True),
        RuleInfo("IAC-VER-004", "Provider version constraint missing", "high", True),
    )
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    address: str
    detail_key: str
    reason: str
    remediation: str

    def __post_init__(self) -> None:
        if self.rule_id not in RULE_CATALOG:
            raise ValueError(f"unknown rule id {self.rule_id!r}")

    @property
    def info(self) -> RuleInfo:
        return RULE_CATALOG[self.rule_id]

    @property
    def severity(self) -> str:
        return self.info.severity

    @property
    def blocking(self) -> bool:
        return self.info.blocking

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (self.rule_id, self.address, self.detail_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.info.title,
            "severity": self.info.severity,
            "blocking": self.info.blocking,
            "requires_elevated_approval": self.info.requires_elevated_approval,
            "address": self.address,
            "detail_key": self.detail_key,
            "reason": self.reason,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, order=True)
class InputError:
    source: str  # plan | approval | policy | evaluator
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


class InputValidationError(Exception):
    def __init__(self, errors: list[InputError]):
        super().__init__(f"{len(errors)} input error(s)")
        self.errors = errors


@dataclass(frozen=True)
class ResourceChange:
    address: str
    type: str
    name: str
    provider_name: str
    actions: tuple[str, ...]
    before: dict[str, Any] | None
    after: dict[str, Any] | None

    @property
    def is_destructive(self) -> bool:
        return "delete" in self.actions


@dataclass(frozen=True)
class ProviderMeta:
    name: str
    source: str
    version_constraint: str | None
    selected_version: str


@dataclass(frozen=True)
class Plan:
    fixture_id: str
    terraform_version: str
    change_context: dict[str, str]
    providers: dict[str, ProviderMeta]
    resources: tuple[ResourceChange, ...]  # sorted by address
    change_set_digest: str

    @property
    def destructive_addresses(self) -> tuple[str, ...]:
        return tuple(rc.address for rc in self.resources if rc.is_destructive)


@dataclass(frozen=True)
class ProviderAllowance:
    source: str
    min_inclusive: tuple[int, int, int]
    max_exclusive: tuple[int, int, int]


@dataclass(frozen=True)
class Policy:
    policy_id: str
    policy_version: str
    terraform_min: tuple[int, int, int]
    terraform_max: tuple[int, int, int]
    provider_allowlist: dict[str, ProviderAllowance]
    sensitive_ports: tuple[int, ...]
    allowed_public_ports: tuple[int, ...]
    allowed_encryption_algorithms: tuple[str, ...]
    required_tag_keys: tuple[str, ...]


@dataclass(frozen=True)
class Approval:
    approval_id: str
    status: str
    scope: dict[str, str]
    approval_level: str | None = None
    approver_role: str | None = None
    change_set_digest: str | None = None
    policy_version: str | None = None
    approved_destructive_addresses: tuple[str, ...] = field(default_factory=tuple)


def parse_semver(text: str) -> tuple[int, int, int]:
    """Parse a strict ``MAJOR.MINOR.PATCH`` string (validated earlier by schema pattern)."""
    match = re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", text)
    if match is None:
        raise ValueError("not a MAJOR.MINOR.PATCH version")
    major, minor, patch = (int(part) for part in match.groups())
    return (major, minor, patch)


def format_semver(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)
