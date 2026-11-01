# Fixture contract

This lab reads three kinds of synthetic JSON document. Each has a JSON Schema in `schemas/`. The
loader (`src/iac_change_control/plan_loader.py`) enforces the schema at runtime, together with
the semantic rules listed below. **Every violation is `ERROR` (exit 2).** No input is ever
silently ignored or treated as compliant.

These contracts *borrow Terraform plan field names*, but they are **not** real Terraform plan
JSON, and none of the fixtures came from a real plan, provider schema or cloud account.

## Reading rules (all documents)

Each input file must meet all of the following:
- at most 1 MiB;
- UTF-8, with no BOM;
- valid JSON;
- no duplicate object keys;
- no `NaN` or `Infinity`;
- a top-level object.

**Error codes:**
- `file_not_found`;
- `file_too_large`;
- `not_utf8`;
- `json_parse_error`;
- `duplicate_key`;
- `non_finite_number`;
- `top_level_not_object`.

## Plan contract: `iac-lab-plan/v1`

| Field | Rule |
|---|---|
| `synthetic` | Must be `true` (`not_synthetic`). |
| `contract_version` | `iac-lab-plan/v1` (`unsupported_contract_version`). |
| `fixture_id` | `^[a-z0-9][a-z0-9-]{0,63}$`. Descriptive; excluded from the digest. |
| `description` | At most 300 characters. Descriptive; excluded from the digest. |
| `terraform_version` | `MAJOR.MINOR.PATCH`. Metadata only. |
| `change_context` | `change_ref` (`LAB-CHG-NNNN`) and `environment` (`lab-*`). |
| `configuration.provider_config.<key>` | `name` equals the key. `source` matches `<host>.example/<ns>/<name>` (`non_example_provider_source`). Optional `version_constraint` (a blank value means `IAC-VER-004`). `selected_version` is `MAJOR.MINOR.PATCH`. |
| `resource_changes[]` | 1 to 200 entries. Each has `address`, `type`, `name`, `provider_name` and `change{actions, before, after}`. |

### Semantic rules

- **Resource type:** `type` must be one of the five supported types
  (`unsupported_resource_type`).
- **Addresses:**
  - `address` must equal `<type>.<name>` (`address_mismatch`);
  - addresses must be unique (`duplicate_address`).
- **Provider references:** `provider_name` must be a `provider_config` key
  (`unknown_provider_reference`), and each provider's `name` must equal its key
  (`provider_name_mismatch`).
- **Actions:**
  - every action must be one of `create`, `delete`, `no-op`, `read` or `update`
    (`unknown_action`);
  - the list must be one of the accepted lists below (`unsupported_action_combination`):
    - `[no-op]`;
    - `[create]`;
    - `[update]`;
    - `[delete]`;
    - `[delete, create]`;
    - `[create, delete]`.

    `[read]` is a known action but is not supported.
- **`before`/`after` consistency** (`inconsistent_change`):
  - `create`: `before` is null and `after` is an object;
  - `delete`: `before` is an object and `after` is null;
  - every other accepted list: both are objects.
- **Firewall ports:** `from_port <= to_port` (`invalid_port_range`).
- **CIDRs:**
  - Each must be valid (`invalid_cidr`) and canonical (`non_canonical_cidr`).
  - Each must be either a world CIDR (`0.0.0.0/0`, `::/0`) or inside the reserved ranges below
    (`cidr_outside_reserved_ranges`):
    - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`;
    - `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`;
    - `fd00::/8`, `2001:db8::/32`.
- **Credentials and secrets** (at any depth):
  - a key that looks like a credential is rejected (`credential_like_key`);
  - a string value that looks like a real secret is rejected (`secret_like_value`).

  The error message names the path only, never the value.

### Resource types (fictional provider `labcloud`)

| Type | Required attributes | Optional |
|---|---|---|
| `labcloud_firewall_rule` | `direction` (`ingress`/`egress`), `protocol` (`all`/`tcp`/`udp`), `from_port`, `to_port` (0..65535), `cidr_blocks` (1 to 16, unique) | `description`, `tags` |
| `labcloud_iam_policy` | `policy_name`, `statements[]` of `{effect: Allow/Deny, actions[], resources[]}` | `tags` |
| `labcloud_storage_bucket` | `bucket_name` | `versioning`, `encryption`, `tags` |
| `labcloud_database_instance` | `engine` (`labsql`), `instance_class` (`lab.*`) | `encryption`, `tags` |
| `labcloud_block_disk` | `size_gb` (1..16384) | `encryption`, `tags` |

Field formats:
- `encryption` is `null` or `{enabled: bool|null, algorithm: string|null}`.
- `tags` maps keys matching `^[a-z][a-z0-9_]{0,62}$` to strings of at most 128 characters.
- IAM actions are `"*"` or `service:Action` or `service:*`.
- IAM resources are `"*"` or `lab:<service>:<path>`.

## Approval contract: `iac-lab-approval/v1`

| Field | Rule |
|---|---|
| `synthetic`, `contract_version` | `true` and `iac-lab-approval/v1`. |
| `approval_id` | `APR-LAB-NNNN`. |
| `status` | `approved`, `rejected` or `not_submitted`. |
| `scope` | `{change_ref, environment}`. Must equal the plan's `change_context`. |
| `change_set_digest` | `sha256:` plus 64 lowercase hex characters. Must equal the computed digest. |
| `policy_version` | Must equal the active policy version. A different value means stale. |
| `approval_level` | `standard` or `elevated`. Any delete requires `elevated`. |
| `approver_role` | A role label only, such as `synthetic-change-reviewer`. Never a name. |
| `approved_destructive_addresses` | Must equal the set of plan addresses whose actions include `delete`. |
| `notes` | Optional, at most 300 characters. |

For `approved` and `rejected`, `change_set_digest`, `policy_version`, `approval_level`,
`approver_role` and `approved_destructive_addresses` are required. A `not_submitted` record
needs only the identity, `status` and `scope` fields. The record is data: the tool authenticates
no one.

To prepare an approval for a changed plan, print the digest with
`python -m iac_change_control.cli digest --plan <file>`.

## Policy contract: `iac-lab-policy/v1`

| Field | Rule |
|---|---|
| `policy_id`, `policy_version` | Identity recorded in provenance. The version is also what approvals bind to. |
| `terraform_version` | `{min_inclusive, max_exclusive}`. The minimum must be lower (`invalid_version_range`). |
| `provider_allowlist.<name>` | `{source (.example), min_inclusive, max_exclusive}`. |
| `public_ingress` | `sensitive_ports` (at least one, unique) and `allowed_public_ports` (unique, no overlap with sensitive: `port_overlap`). |
| `storage_encryption.allowed_algorithms` | At least one, unique. |
| `required_tags.keys` | At least one, unique. |

The policy cannot disable rules or declare exceptions. Those properties are rejected as unknown.

## Fixture inventory

| Plan fixture | Purpose | Paired approval in the matrix |
|---|---|---|
| `compliant` | Every control satisfied. | `approved-change` (PASS) |
| `warn-nonstandard-port` | Only non-blocking findings. | `approved-warn-change` (WARN) |
| `public-ingress` | SSH from `0.0.0.0/0`, and all ports from `::/0`. | `approved-public-ingress` (BLOCKED) |
| `wildcard-iam` | `Allow *` on `*`. A `Deny *` statement is not flagged. | `approved-wildcard-iam` (BLOCKED) |
| `unencrypted-storage` | Encryption disabled, null, and a disallowed algorithm. | `approved-unencrypted-storage` (BLOCKED) |
| `destroy-change` | One deletion and one replacement. | `approved-destroy-standard` (BLOCKED) and `approved-destroy-elevated` (WARN) |
| `missing-tags` | A blank tag, a missing tag, and an untagged disk. | `approved-missing-tags` (BLOCKED) |
| `provider-version-violation` | Terraform below range; provider out of range and unconstrained; a non-allowlisted provider. | `approved-provider-version-violation` (BLOCKED) |
| `mixed-violations` | Five different findings, used to check sort order. | `approved-mixed-violations` (BLOCKED) |
| `malformed` | Truncated JSON. | ERROR |
| `unsupported-resource` | Unknown resource type. | ERROR |

The approval fixtures `missing-approval`, `rejected-approval`, `stale-or-out-of-scope-approval`
and `digest-mismatch-approval` all target `compliant`, and each one blocks.
`fixtures/policies/invalid-policy.json` is schema-valid but semantically invalid, so it yields
ERROR.
