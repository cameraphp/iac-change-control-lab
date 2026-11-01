"""Strict input loading, validation, normalization and the change-set digest.

Covers REQ-002 to REQ-007, NFR-007, SAFE-003 and SAFE-004.

Each document goes through the same pipeline:

1. ``read_input`` reads the raw bytes, enforcing the size limit, and hashes them for provenance.
2. Strict JSON parsing: UTF-8, no duplicate keys, no NaN or Infinity, top-level object.
3. A scan for credential-like keys and secret-like values. It runs on every document, so the
   check holds even inside free-form maps such as ``tags``.
4. Validation against the published schema in ``schemas/``.
5. Semantic checks the schema cannot express.

Any failure raises ``InputValidationError`` with sorted, value-free errors. The engine turns
that into ``ERROR``. An unparseable or unknown input is never treated as compliant.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from iac_change_control.canonical import digest_json_bytes, sha256_hex
from iac_change_control.models import (
    DIGEST_SCHEME,
    FIREWALL_TYPE,
    MAX_INPUT_BYTES,
    MAX_REPORTED_ERRORS,
    SUPPORTED_ACTION_LISTS,
    Approval,
    InputError,
    InputValidationError,
    Plan,
    Policy,
    ProviderAllowance,
    ProviderMeta,
    ResourceChange,
    parse_semver,
)
from iac_change_control.schema_validator import SchemaViolation, Validator

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"
SCHEMA_FILES = {
    "plan": "synthetic-plan.schema.json",
    "approval": "approval.schema.json",
    "policy": "policy-config.schema.json",
    "evidence": "evidence.schema.json",
}

# Reserved, non-routable or documentation ranges (RFC 1918, RFC 4193, RFC 5737, RFC 3849).
# World CIDRs (prefix length 0) are also accepted, because the rules must be able to see them.
RESERVED_NETWORKS = tuple(
    ipaddress.ip_network(text)
    for text in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "fd00::/8",
        "2001:db8::/32",
    )
)

CREDENTIAL_KEY_PATTERN = re.compile(
    r"(passw(or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential"
    r"|auth[_-]?key|session[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)
# Shapes of real-looking secrets. Each is written so the pattern text cannot match itself.
SECRET_VALUE_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
)


@dataclass(frozen=True)
class RawInput:
    """Raw bytes of one input file, plus the provenance data recorded in evidence."""

    role: str
    filename: str  # basename only (NFR-002)
    data: bytes | None
    sha256: str | None
    size_bytes: int | None


class _DuplicateKey(Exception):
    def __init__(self, key: str):
        super().__init__("duplicate key")
        self.key = key


class _NonFinite(Exception):
    pass


# -- schemas ------------------------------------------------------------------------------------
@cache
def load_schema(kind: str) -> dict[str, Any]:
    path = SCHEMA_DIR / SCHEMA_FILES[kind]
    return json.loads(path.read_text(encoding="utf-8"))


@cache
def validator_for(kind: str) -> Validator:
    return Validator(load_schema(kind))


# -- reading ------------------------------------------------------------------------------------
def read_input(path: str | Path, role: str) -> tuple[RawInput, list[InputError]]:
    """Read an input file without raising. Unreadable inputs return ``data=None`` and an error."""
    p = Path(path)
    name = p.name
    if not p.is_file():
        error = InputError(
            role, "file_not_found", "$", "input file does not exist or is not a file"
        )
        return RawInput(role, name, None, None, None), [error]
    with p.open("rb") as handle:
        data = handle.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        error = InputError(role, "file_too_large", "$", f"input exceeds {MAX_INPUT_BYTES} bytes")
        return RawInput(role, name, None, None, None), [error]
    return RawInput(role, name, data, sha256_hex(data), len(data)), []


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(_name: str) -> Any:
    raise _NonFinite()


def parse_json_strict(data: bytes, role: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputValidationError(
            [InputError(role, "not_utf8", "$", "input is not valid UTF-8")]
        ) from None
    try:
        value = json.loads(
            text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
    except _DuplicateKey:
        raise InputValidationError(
            [InputError(role, "duplicate_key", "$", "an object contains a duplicate key")]
        ) from None
    except _NonFinite:
        raise InputValidationError(
            [InputError(role, "non_finite_number", "$", "NaN and Infinity are not permitted")]
        ) from None
    except json.JSONDecodeError as exc:
        message = f"malformed JSON at line {exc.lineno}, column {exc.colno}"
        raise InputValidationError([InputError(role, "json_parse_error", "$", message)]) from None
    if not isinstance(value, dict):
        raise InputValidationError(
            [
                InputError(
                    role, "top_level_not_object", "$", "top-level JSON value must be an object"
                )
            ]
        )
    return value


# -- generic checks -----------------------------------------------------------------------------
def _child(path: str, key: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return f"{path}.{key}"
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'{path}["{escaped}"]'


def scan_secrets(value: Any, role: str, path: str = "$") -> list[InputError]:
    """Flag credential-like keys and secret-like string values at any depth (SAFE-003).

    Messages carry the path only. The offending value is never repeated.
    """
    errors: list[InputError] = []
    if isinstance(value, dict):
        for key in sorted(value):
            child = _child(path, key)
            if CREDENTIAL_KEY_PATTERN.search(key):
                errors.append(
                    InputError(
                        role, "credential_like_key", child, "credential-like key is not permitted"
                    )
                )
            errors.extend(scan_secrets(value[key], role, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(scan_secrets(item, role, f"{path}[{index}]"))
    elif isinstance(value, str) and any(p.search(value) for p in SECRET_VALUE_PATTERNS):
        errors.append(
            InputError(role, "secret_like_value", path, "value resembles a secret and is rejected")
        )
    return errors


def _schema_code(violation: SchemaViolation) -> str:
    path, keyword = violation.path, violation.keyword
    if path == "$.synthetic":
        return "not_synthetic"
    if path == "$.contract_version":
        return "unsupported_contract_version"
    if keyword == "enum" and re.fullmatch(r"\$\.resource_changes\[\d+\]\.type", path):
        return "unsupported_resource_type"
    if keyword == "enum" and re.fullmatch(
        r"\$\.resource_changes\[\d+\]\.change\.actions\[\d+\]", path
    ):
        return "unknown_action"
    if keyword == "pattern" and re.search(
        r"\.(provider_config|provider_allowlist)\.[a-z0-9]+\.source$", path
    ):
        return "non_example_provider_source"
    return "schema_violation"


def schema_errors(document: dict[str, Any], kind: str, role: str) -> list[InputError]:
    return [
        InputError(role, _schema_code(v), v.path, v.message)
        for v in validator_for(kind).validate(document)
    ]


def finalize_errors(errors: list[InputError]) -> list[InputError]:
    """Sort, de-duplicate and cap an error list (NFR-007)."""
    unique = sorted(set(errors))
    if len(unique) <= MAX_REPORTED_ERRORS:
        return unique
    hidden = len(unique) - MAX_REPORTED_ERRORS
    kept = unique[:MAX_REPORTED_ERRORS]
    marker = InputError(
        kept[-1].source, "errors_truncated", "$", f"{hidden} more error(s) not shown"
    )
    return [*kept, marker]


def _raise_if(errors: list[InputError]) -> None:
    if errors:
        raise InputValidationError(finalize_errors(errors))


# -- plan ---------------------------------------------------------------------------------------
def _check_cidr(text: str, path: str) -> InputError | None:
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        return InputError("plan", "invalid_cidr", path, "value is not a valid CIDR block")
    if str(network) != text:
        return InputError("plan", "non_canonical_cidr", path, "CIDR block is not in canonical form")
    if network.prefixlen == 0:
        return None
    if any(
        network.version == reserved.version and network.subnet_of(reserved)
        for reserved in RESERVED_NETWORKS
    ):
        return None
    return InputError(
        "plan",
        "cidr_outside_reserved_ranges",
        path,
        "CIDR block is outside the reserved private/documentation ranges allowed in fixtures",
    )


def _check_firewall_state(state: dict[str, Any], path: str) -> list[InputError]:
    errors = []
    if state["from_port"] > state["to_port"]:
        errors.append(InputError("plan", "invalid_port_range", path, "from_port exceeds to_port"))
    for index, cidr in enumerate(state["cidr_blocks"]):
        error = _check_cidr(cidr, f"{path}.cidr_blocks[{index}]")
        if error:
            errors.append(error)
    return errors


def _plan_semantics(doc: dict[str, Any]) -> list[InputError]:
    errors: list[InputError] = []
    providers = doc["configuration"]["provider_config"]
    for key in sorted(providers):
        if providers[key]["name"] != key:
            errors.append(
                InputError(
                    "plan",
                    "provider_name_mismatch",
                    f"$.configuration.provider_config.{key}.name",
                    "provider name must equal its provider_config key",
                )
            )
    seen: set[str] = set()
    for index, rc in enumerate(doc["resource_changes"]):
        base = f"$.resource_changes[{index}]"
        if rc["address"] != f"{rc['type']}.{rc['name']}":
            errors.append(
                InputError(
                    "plan",
                    "address_mismatch",
                    f"{base}.address",
                    "address must equal <type>.<name>",
                )
            )
        if rc["address"] in seen:
            errors.append(
                InputError(
                    "plan", "duplicate_address", f"{base}.address", "resource address is not unique"
                )
            )
        seen.add(rc["address"])
        if rc["provider_name"] not in providers:
            errors.append(
                InputError(
                    "plan",
                    "unknown_provider_reference",
                    f"{base}.provider_name",
                    "provider_name does not reference configuration.provider_config",
                )
            )
        change = rc["change"]
        actions = tuple(change["actions"])
        if actions not in SUPPORTED_ACTION_LISTS:
            errors.append(
                InputError(
                    "plan",
                    "unsupported_action_combination",
                    f"{base}.change.actions",
                    "action list is not supported by this contract",
                )
            )
            continue
        before, after = change["before"], change["after"]
        if actions == ("create",):
            consistent = before is None and after is not None
        elif actions == ("delete",):
            consistent = before is not None and after is None
        else:
            consistent = before is not None and after is not None
        if not consistent:
            errors.append(
                InputError(
                    "plan",
                    "inconsistent_change",
                    f"{base}.change",
                    "before/after presence does not match the action list",
                )
            )
        if rc["type"] == FIREWALL_TYPE:
            for state_name, state in (("before", before), ("after", after)):
                if state is not None:
                    errors.extend(_check_firewall_state(state, f"{base}.change.{state_name}"))
    return errors


def normalized_change_set(doc: dict[str, Any]) -> dict[str, Any]:
    """Return the digest input (REQ-007). Descriptive fields and ordering are excluded."""
    providers = doc["configuration"]["provider_config"]
    return {
        "digest_scheme": DIGEST_SCHEME,
        "terraform_version": doc["terraform_version"],
        "change_context": doc["change_context"],
        "providers": {
            key: {
                "source": meta["source"],
                "version_constraint": meta.get("version_constraint"),
                "selected_version": meta["selected_version"],
            }
            for key, meta in providers.items()
        },
        "resource_changes": sorted(
            (
                {
                    "address": rc["address"],
                    "type": rc["type"],
                    "name": rc["name"],
                    "provider_name": rc["provider_name"],
                    "actions": list(rc["change"]["actions"]),
                    "before": rc["change"]["before"],
                    "after": rc["change"]["after"],
                }
                for rc in doc["resource_changes"]
            ),
            key=lambda item: item["address"],
        ),
    }


def compute_change_set_digest(doc: dict[str, Any]) -> str:
    return "sha256:" + sha256_hex(digest_json_bytes(normalized_change_set(doc)))


def parse_plan(data: bytes) -> Plan:
    doc = parse_json_strict(data, "plan")
    errors = scan_secrets(doc, "plan") + schema_errors(doc, "plan", "plan")
    _raise_if(errors)
    _raise_if(_plan_semantics(doc))
    doc = copy.deepcopy(doc)
    providers = {
        key: ProviderMeta(
            name=meta["name"],
            source=meta["source"],
            version_constraint=meta.get("version_constraint"),
            selected_version=meta["selected_version"],
        )
        for key, meta in sorted(doc["configuration"]["provider_config"].items())
    }
    resources = tuple(
        sorted(
            (
                ResourceChange(
                    address=rc["address"],
                    type=rc["type"],
                    name=rc["name"],
                    provider_name=rc["provider_name"],
                    actions=tuple(rc["change"]["actions"]),
                    before=rc["change"]["before"],
                    after=rc["change"]["after"],
                )
                for rc in doc["resource_changes"]
            ),
            key=lambda rc: rc.address,
        )
    )
    return Plan(
        fixture_id=doc["fixture_id"],
        terraform_version=doc["terraform_version"],
        change_context=dict(doc["change_context"]),
        providers=providers,
        resources=resources,
        change_set_digest=compute_change_set_digest(doc),
    )


def load_plan(path: str | Path) -> Plan:
    raw, errors = read_input(path, "plan")
    _raise_if(errors)
    return parse_plan(raw.data)


# -- approval -----------------------------------------------------------------------------------
def parse_approval(data: bytes) -> Approval:
    doc = parse_json_strict(data, "approval")
    _raise_if(scan_secrets(doc, "approval") + schema_errors(doc, "approval", "approval"))
    return Approval(
        approval_id=doc["approval_id"],
        status=doc["status"],
        scope=dict(doc["scope"]),
        approval_level=doc.get("approval_level"),
        approver_role=doc.get("approver_role"),
        change_set_digest=doc.get("change_set_digest"),
        policy_version=doc.get("policy_version"),
        approved_destructive_addresses=tuple(doc.get("approved_destructive_addresses", [])),
    )


def load_approval(path: str | Path) -> Approval:
    raw, errors = read_input(path, "approval")
    _raise_if(errors)
    return parse_approval(raw.data)


# -- policy -------------------------------------------------------------------------------------
def _range_error(range_doc: dict[str, str], path: str) -> InputError | None:
    if parse_semver(range_doc["min_inclusive"]) >= parse_semver(range_doc["max_exclusive"]):
        return InputError(
            "policy",
            "invalid_version_range",
            path,
            "min_inclusive must be lower than max_exclusive",
        )
    return None


def parse_policy(data: bytes) -> Policy:
    doc = parse_json_strict(data, "policy")
    _raise_if(scan_secrets(doc, "policy") + schema_errors(doc, "policy", "policy"))
    errors: list[InputError] = []
    tf_error = _range_error(doc["terraform_version"], "$.terraform_version")
    if tf_error:
        errors.append(tf_error)
    for name in sorted(doc["provider_allowlist"]):
        error = _range_error(doc["provider_allowlist"][name], f"$.provider_allowlist.{name}")
        if error:
            errors.append(error)
    ingress = doc["public_ingress"]
    if set(ingress["sensitive_ports"]) & set(ingress["allowed_public_ports"]):
        errors.append(
            InputError(
                "policy",
                "port_overlap",
                "$.public_ingress",
                "a port cannot be both sensitive and allowed-public",
            )
        )
    _raise_if(errors)
    return Policy(
        policy_id=doc["policy_id"],
        policy_version=doc["policy_version"],
        terraform_min=parse_semver(doc["terraform_version"]["min_inclusive"]),
        terraform_max=parse_semver(doc["terraform_version"]["max_exclusive"]),
        provider_allowlist={
            name: ProviderAllowance(
                source=entry["source"],
                min_inclusive=parse_semver(entry["min_inclusive"]),
                max_exclusive=parse_semver(entry["max_exclusive"]),
            )
            for name, entry in sorted(doc["provider_allowlist"].items())
        },
        sensitive_ports=tuple(sorted(ingress["sensitive_ports"])),
        allowed_public_ports=tuple(sorted(ingress["allowed_public_ports"])),
        allowed_encryption_algorithms=tuple(
            sorted(doc["storage_encryption"]["allowed_algorithms"])
        ),
        required_tag_keys=tuple(doc["required_tags"]["keys"]),
    )


def load_policy(path: str | Path) -> Policy:
    raw, errors = read_input(path, "policy")
    _raise_if(errors)
    return parse_policy(raw.data)
