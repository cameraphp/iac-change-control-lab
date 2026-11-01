# Requirements: `iac-change-control-lab`

- **Spec date:** 2026-11-01
- **Plan:** [`plan.md`](plan.md)
- **Validation:** [`validation.md`](validation.md). Its §3 maps every ID below to tests, an
  implementation location and an evidence artifact.

**ID scheme:**
- `REQ-NNN`: functional;
- `NFR-NNN`: non-functional;
- `SAFE-NNN`: safety.

IDs are stable: a retired ID is never reused. "Synthetic" means that a value was invented for this
lab and does not describe any real environment.

## 1. Glossary

- **Plan fixture:** a checked-in JSON file following the `iac-lab-plan/v1` contract
  (`schemas/synthetic-plan.schema.json`). It is *Terraform-plan-like*: it borrows field names
  (`terraform_version`, `configuration.provider_config`, `resource_changes`, `change.actions`,
  `before`, `after`), but it is not real Terraform output.
- **Approval fixture:** a JSON file following `iac-lab-approval/v1`
  (`schemas/approval.schema.json`).
- **Policy configuration:** a JSON file following `iac-lab-policy/v1`
  (`schemas/policy-config.schema.json`). The default is `policy/policy-config.json`.
- **Change-set digest:** `sha256:<64 hex>` over the normalized plan (REQ-007).
- **Finding:** one rule result with the fields defined in REQ-017.
- **Blocking finding:** a finding whose rule is marked blocking in the catalog (§3).

## 2. Functional requirements

### Inputs and validation

- **REQ-001 (CLI evaluate).** `python -m iac_change_control.cli evaluate` takes `--plan`,
  `--policy`, `--output` and `--run-id` (all required) and `--approval` (optional). It evaluates
  offline, writes an evidence bundle and returns the decision's exit code (REQ-018).
  - `--run-id` is a caller-supplied stable identifier that must match
    `^[a-z0-9][a-z0-9._-]{0,63}$`.
  - The tool never generates a run ID.
  - An invalid run ID exits 2 without writing a bundle.
- **REQ-002 (Strict JSON reading).** Every input file is read strictly. Each of the following is
  an input `ERROR`:
  - the file is missing;
  - it is larger than 1 MiB;
  - it is not UTF-8;
  - its JSON is malformed;
  - it contains a duplicate object key;
  - it contains `NaN`, `Infinity` or `-Infinity`;
  - its top level is not an object.
- **REQ-003 (Plan contract).** A plan must validate against
  `schemas/synthetic-plan.schema.json` and pass these semantic checks:
  - `synthetic` is `true`, and `contract_version` is `iac-lab-plan/v1`;
  - required fields are present, types are correct, and unknown properties are absent;
  - `resource_changes` is non-empty;
  - `type` is one of the five supported fictional types;
  - `address` equals `<type>.<name>`, and addresses are unique;
  - every `provider_name` references a `configuration.provider_config` key, and each key equals
    its entry's `name`;
  - version strings are `MAJOR.MINOR.PATCH`.

  An unsupported resource type is `ERROR` (`unsupported_resource_type`), never ignored. The
  schema's enumerations must equal the code constants.
- **REQ-004 (Actions and change consistency).**
  - **Accepted action lists:** `["no-op"]`, `["create"]`, `["update"]`, `["delete"]`,
    `["delete","create"]` and `["create","delete"]`.
  - **Unknown action value:** `ERROR` (`unknown_action`).
  - **Known value in an unsupported list** (for example `["read"]`): `ERROR`
    (`unsupported_action_combination`).
  - **`before`/`after` must match the actions:**
    - `create`: `before` is null and `after` is an object;
    - `delete`: `before` is an object and `after` is null;
    - every other accepted list: both are objects.

    A mismatch is `ERROR` (`inconsistent_change`).
- **REQ-005 (Approval contract).** An approval must validate against
  `schemas/approval.schema.json`:
  - `synthetic` is `true`, and `contract_version` is `iac-lab-approval/v1`;
  - `status` is one of `approved`, `rejected` or `not_submitted`;
  - `scope` contains `change_ref` and `environment`;
  - for `approved` and `rejected`, these fields are also required:
    - `change_set_digest` (`sha256:` plus 64 lowercase hex);
    - `policy_version`;
    - `approval_level` (`standard` or `elevated`);
    - `approver_role`;
    - `approved_destructive_addresses` (unique addresses).

  A malformed approval is `ERROR`.
- **REQ-006 (Policy configuration).** The policy must validate against
  `schemas/policy-config.schema.json` and pass these semantic checks:
  - every version range has `min_inclusive < max_exclusive`;
  - ports are unique and in `1..65535`;
  - sensitive ports and allowed public ports do not overlap;
  - required tag keys are non-empty and unique;
  - provider allowlist sources use the `.example` domain.

  An invalid policy is `ERROR`. The policy cannot disable a rule or add an exception. The covered
  resource types are fixed by the contract.
- **REQ-007 (Change-set digest).** The digest is
  `"sha256:" + SHA-256(compact canonical JSON)`. The JSON input is the normalized plan:
  - the `digest_scheme` tag `iac-lab-changeset/v1`;
  - `terraform_version`;
  - `change_context`;
  - provider metadata;
  - resource changes sorted by address, each with address, type, name, provider, actions, `before`
    and `after`.

  The digest is unaffected by key order, resource order, whitespace, `fixture_id` and
  `description`. It changes when any normalized field changes. `python -m iac_change_control.cli
  digest --plan <file>` prints it.

### Policy rules

- **REQ-008 (Public ingress).** For `labcloud_firewall_rule` resources with
  `direction: "ingress"` and a world CIDR (prefix length 0: `0.0.0.0/0` or `::/0`):
  - **`IAC-NET-001`** (critical, blocking): `protocol: "all"`, a port range of `0-65535`, or a
    port range that overlaps a configured sensitive port.
  - **`IAC-NET-002`** (medium, non-blocking): any other range that is not fully inside the
    configured allowed public ports.

  These are never flagged:
  - egress rules;
  - non-world CIDRs;
  - world exposure limited to allowed public ports.
- **REQ-009 (Wildcard IAM).** For `labcloud_iam_policy` statements with `effect: "Allow"`:
  - **`IAC-IAM-001`** (critical, blocking): `actions` contains `"*"`, `resources` contains
    `"*"`, or both.
  - **`IAC-IAM-002`** (medium, non-blocking): a service-scoped action wildcard (`<service>:*`)
    without an `IAC-IAM-001` hit.

  `Deny` statements are not flagged. Policy-language parsing is deliberately simplified: no
  conditions, no `NotAction`, and partial resource wildcards are not evaluated.
- **REQ-010 (Storage encryption).** For `labcloud_storage_bucket`,
  `labcloud_database_instance` and `labcloud_block_disk` resources with a non-null `after`,
  **`IAC-ENC-001`** (high, blocking) fires when any of the following holds:
  - `encryption` is missing or null;
  - `encryption.enabled` is not `true` (false or null);
  - `encryption.algorithm` is not in the policy's `allowed_algorithms`.
- **REQ-011 (Destructive changes).** Any action list containing `delete` (a deletion or a
  replacement) yields **`IAC-CHG-001`** (high, non-blocking, requires elevated approval). The
  finding describes a *proposed* change in a synthetic fixture, never an executed deletion.
- **REQ-012 (Required tags).** Every supported resource with a non-null `after` must carry each
  configured tag key (default `owner`, `environment`, `cost_center`) with a non-blank value. If
  `tags` is absent or a key is missing or blank, the rule yields **`IAC-TAG-001`** (high,
  blocking), with one finding per resource listing every missing key.
- **REQ-013 (Terraform and provider version metadata).**
  - **`IAC-VER-001`:** `terraform_version` is outside the policy range
    `[min_inclusive, max_exclusive)`.
  - **`IAC-VER-002`:** a provider is not in the allowlist, or its `source` differs from the
    allowlisted source.
  - **`IAC-VER-003`:** the allowlisted provider's `selected_version` is outside its range.
  - **`IAC-VER-004`:** `version_constraint` is missing or blank.

  All four are high and blocking. A malformed version string is `ERROR` (REQ-003). This is
  metadata validation only: nothing is initialized or downloaded.

### Approval gate

- **REQ-014 (Scoped approval gate).** `rules/approval_gate.py` records seven checks in fixed
  order. Each failed check is a blocking finding with address `change-set`.

  | Check | ID | Fails when |
  |---|---|---|
  | `approval_present` | `IAC-APR-001` | No `--approval` given, or `status: "not_submitted"`. |
  | `approval_status_approved` | `IAC-APR-002` | `status: "rejected"`. |
  | `policy_version_current` | `IAC-APR-003` | The approval's `policy_version` differs from the active policy (stale). |
  | `scope_matches` | `IAC-APR-004` | `scope` differs from the plan's `change_context` (out of scope). |
  | `digest_matches` | `IAC-APR-005` | `change_set_digest` differs from the computed digest. |
  | `elevation_for_destructive` | `IAC-APR-006` | See REQ-015. |
  | `destructive_addresses_match` | `IAC-APR-007` | See REQ-015. |

  If 001 fails, the remaining checks are `not_evaluated`. If 002 fails, 003..007 are
  `not_evaluated`. Otherwise every check is evaluated and every failure is reported.
- **REQ-015 (Elevated approval for destructive changes).**
  - **`IAC-APR-006`** fails when the plan contains a destructive change and `approval_level` is
    not `elevated`.
  - **`IAC-APR-007`** fails when the set `approved_destructive_addresses` is not exactly the set
    of destructive addresses. This includes listing addresses when the plan has none.
- **REQ-016 (No suppression of hard violations).** A valid approval, with every gate check
  passing, never removes or downgrades a blocking policy finding. The decision stays `BLOCKED`.
  There is no exception mechanism in this version.

### Decisions and evidence

- **REQ-017 (Findings and stable order).** Each finding has these fields:
  - `rule_id`, `title`, `severity` (`critical`, `high`, `medium` or `low`);
  - `blocking`, `requires_elevated_approval`;
  - `address` (a synthetic address, `terraform`, `provider.<name>` or `change-set`);
  - `detail_key`, `reason`, `remediation`.

  Findings are sorted by `(rule_id, address, detail_key)`.
- **REQ-018 (Decision and exit codes).** Decisions follow the decision table (`plan.md` §3.2):
  - `ERROR`: exit 2;
  - `BLOCKED`: exit 1;
  - `WARN` and `PASS`: exit 0.

  An unexpected exception during evaluation produces `ERROR` (`evaluator_internal_error`). Any
  input or configuration error produces `ERROR`. `ERROR` never yields exit 0.
- **REQ-019 (Evidence bundle).** Every evaluation that passes argument validation writes exactly
  five files into `--output`:
  - `evaluation.json`;
  - `summary.md`;
  - `provenance.json`;
  - `approval-assessment.json`;
  - `manifest.sha256`.

  `ERROR` runs also get a bundle. `evaluation.json` contains:
  - the decision, exit code, run ID and digest;
  - the plan fixture ID, change context and resource summary;
  - sorted findings and finding counts;
  - the approval-gate result;
  - sorted errors;
  - the decision basis, notice and non-claims.

  It conforms to `schemas/evidence.schema.json`.
- **REQ-020 (Provenance).** `provenance.json` records:
  - the run ID, decision and exit code;
  - the evaluator name and version;
  - for each input (plan, approval or `null`, policy): basename, SHA-256 and byte size;
  - the plan `fixture_id`, the `approval_id`, and the policy ID and version;
  - the change-set digest and digest scheme.
- **REQ-021 (Manifest and verification).** `manifest.sha256` lists the other four files as
  `<sha256>  <name>` lines (two spaces), sorted by name and LF-terminated. The format is
  compatible with `sha256sum -c`. `verify-bundle --bundle <dir>` returns:
  - exit 0 if the manifest matches exactly;
  - exit 1 on any mismatch, missing file or extra file;
  - exit 2 if the bundle cannot be read.
- **REQ-022 (Digest helper).** `digest --plan <file>` prints the change-set digest and exits 0.
  An invalid plan prints sorted errors to stderr and exits 2.
- **REQ-023 (Demo walkthrough).** `python scripts/run_demo.py` evaluates a fixed case list with
  at least one `PASS`, `WARN`, `BLOCKED` and `ERROR`:
  - it labels every result as synthetic/local;
  - it verifies every bundle;
  - it writes only under the ignored `evidence/demo/` path;
  - it exits 0 only if every case matches its expected decision.
- **REQ-024 (Output directory safety).** If `--output` contains any entry other than the five
  bundle files, the evaluator refuses with exit 2 and writes nothing. Re-running into an existing
  bundle directory overwrites the bundle in place.

## 3. Rule catalog

| Rule | Title | Severity | Blocking |
|---|---|---|---|
| `IAC-APR-001` | Approval missing | high | blocking |
| `IAC-APR-002` | Approval rejected | high | blocking |
| `IAC-APR-003` | Approval stale (policy version changed) | high | blocking |
| `IAC-APR-004` | Approval out of scope | high | blocking |
| `IAC-APR-005` | Approval digest mismatch | high | blocking |
| `IAC-APR-006` | Elevated approval required for destructive change | high | blocking |
| `IAC-APR-007` | Approved destructive addresses do not match | high | blocking |
| `IAC-CHG-001` | Destructive change proposed | high | non-blocking (requires elevated approval) |
| `IAC-ENC-001` | Storage encryption missing or disallowed | high | blocking |
| `IAC-IAM-001` | Wildcard IAM action or resource | critical | blocking |
| `IAC-IAM-002` | Service-scoped IAM action wildcard | medium | non-blocking |
| `IAC-NET-001` | Sensitive or all ports open to the world | critical | blocking |
| `IAC-NET-002` | Non-allowlisted port open to the world | medium | non-blocking |
| `IAC-TAG-001` | Required tags missing or blank | high | blocking |
| `IAC-VER-001` | Terraform version outside supported range | high | blocking |
| `IAC-VER-002` | Provider not allowlisted | high | blocking |
| `IAC-VER-003` | Provider version outside allowed range | high | blocking |
| `IAC-VER-004` | Provider version constraint missing | high | blocking |

## 4. Non-functional requirements

- **NFR-001 (Determinism).** Evidence files use canonical JSON (sorted keys, indent 2, UTF-8,
  LF, trailing newline) or deterministic Markdown. The same inputs, policy and run ID produce
  byte-identical bundles across:
  - repeated runs;
  - different `PYTHONHASHSEED` values;
  - different working directories;
  - relative and absolute input paths.
- **NFR-002 (No variable data in evidence).** Evidence contains none of the following:
  - wall-clock timestamps;
  - random or generated IDs;
  - absolute paths;
  - drive letters;
  - usernames;
  - hostnames;
  - interpreter versions.
- **NFR-003 (Minimal dependencies).** The runtime uses only the Python standard library
  (`dependencies = []`) and requires Python `>=3.11`. Development tooling is pinned exactly
  (`pytest`, `ruff`) in `pyproject.toml` and `requirements-dev.lock`.
- **NFR-004 (No Terraform or Docker prerequisite).** The evaluator, tests and demo run with
  neither Terraform nor Docker installed. The evaluator also runs with an empty `PATH`.
- **NFR-005 (Quality gates).** `python -m pytest -q` passes and `python -m ruff check .` reports
  no findings.
- **NFR-006 (Traceability).** Every requirement ID maps to at least one existing test function,
  an existing implementation path and an evidence artifact (`validation.md` §3). A test enforces
  this.
- **NFR-007 (Safe error messages).** Input-error messages identify a code and a JSON path and
  never echo input values. The error list is sorted and capped at 100 entries, with a truncation
  marker.

## 5. Safety requirements

- **SAFE-001 (No network or cloud access).** The source, scripts and tests import no network,
  HTTP, cloud-SDK, provider-SDK or Terraform-wrapper module. Every test runs under a socket guard
  that fails any connection attempt.
- **SAFE-002 (No process execution or credential environment).** The evaluator source does not
  import `subprocess`, does not call `os.system` or `os.popen`, and does not read environment
  variables. No code path can invoke Terraform or depend on credential variables.
- **SAFE-003 (No secrets).** Credential-like keys at any depth and secret-like string values in
  plan or approval inputs are `ERROR` (`credential_like_key`, `secret_like_value`). The message
  shows the path only. A repository scan finds no secret-like patterns.
- **SAFE-004 (Synthetic identifiers only).**
  - **Required labels:** inputs require `synthetic: true`.
  - **Provider sources:** must be under a `.example` domain.
  - **CIDRs:** must be canonical and inside the reserved ranges in `plan.md` §5; otherwise
    `ERROR` (`cidr_outside_reserved_ranges` or `non_canonical_cidr`).
  - **Approvers:** recorded by role only.
- **SAFE-005 (No state-changing Terraform).** No executable file (`src/`, `scripts/`,
  `terraform-sample/`, `policy/`, `fixtures/`, `pyproject.toml`) contains a Terraform `init`,
  plan, apply, destroy, import, refresh, login or state command. The optional check script is
  limited to:
  - the `version` and `fmt` subcommands;
  - a network-disabled container and read-only mount;
  - a sample module with no provider, resource, data, module, backend or cloud block.
- **SAFE-006 (No publication operations).** Project code and scripts perform no Git, GitHub,
  CI, deployment or publication operation.
- **SAFE-007 (Labelling and hygiene).** Every evidence file states that its inputs are
  synthetic/local. `README.md` states the non-claims. `.gitignore` excludes:
  - `.venv/` and caches;
  - generated evidence (except `evidence/README.md`);
  - `.env` files;
  - Terraform working directories, state, plans and variable files;
  - logs.
- **SAFE-008 (No authorization semantics).** Every evidence bundle and the README state that the
  tool applies no infrastructure change, that a `PASS` is not authorization, and that human review
  remains required.

## 6. Limitations and non-claims

- The fixtures are synthetic. They are not output from any real Terraform plan or cloud account.
- The rules are a small, illustrative set. They are not a complete policy, not a replacement for
  a policy engine, and not a compliance control or certification.
- IAM parsing is simplified (REQ-009). Network evaluation covers one fictional firewall type.
- The approval gate models approval *records*. It does not authenticate approvers or integrate
  with any ticketing or identity system.
- A `PASS` or `WARN` result does not authorize any change, and nothing in this lab creates,
  modifies or destroys real infrastructure.
