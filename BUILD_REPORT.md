# Build report: `iac-change-control-lab`

- **Build date:** 2026-11-01
- **Phase:** Priority D (optional): local build and validation only.
- **Project path:** `C:\Users\camer\github\improvement-plan\iac-change-control-lab`
- **Status at the end of this phase:** built and validated locally. There is no Git repository,
  commit, push, remote, GitHub repository, CI workflow, license, release or deployment.

## 1. Environment

| Item | Version or state |
|---|---|
| OS | Windows 11 Pro 10.0.26200 |
| Python | 3.13.7 (`C:\Users\camer\AppData\Local\Programs\Python\Python313\python.exe`). Satisfies `>=3.11`. |
| Virtual environment | Project-local `.venv`, ignored. |
| Dev tooling (pinned) | pytest 9.1.1, ruff 0.16.9, setuptools 80.9.0 (build backend for the editable install), pip 25.2. |
| Docker | Client and engine 29.9.1, Docker Desktop 4.96.0, Compose v5.6.0. |
| Terraform (host) | **Not installed** (`terraform` is not recognized). Not required, and not installed by this build. |
| Terraform (optional container) | `hashicorp/terraform:1.14.0`, digest `sha256:3abcdb56739bf9c61a0290cfd1a2e41ef9c3799c0e6fa7f3c467f883367d3ecb`. Used only by the optional safe check (§7). |

Mandatory preflight output:
- `Get-Location`: `C:\Users\camer\github\improvement-plan`.
- `python --version`: 3.13.7.
- `py -0p`: one interpreter, 3.13.
- `docker version` and `docker compose version`: as above.
- `terraform version`: CommandNotFoundException.
- `Get-ChildItem -Force`: the target directory `iac-change-control-lab` did not exist before this
  build.

## 2. Specification-driven development and traceability

- **Specs** (written and completed before any source, fixture or test):
  `specs/2026-11-01-iac-change-control/` (`plan.md`, `requirements.md`, `validation.md`).
- **Requirements:** 39 IDs: 24 `REQ`, 7 `NFR` and 8 `SAFE`.
- **Traceability:** `tests/test_traceability.py` parses the `validation.md` §3 matrix. It
  confirms that every ID has existing test functions, existing implementation paths and an
  evidence entry, and that no row references an undefined ID. A negative self-test proves that the
  checker rejects an unmapped requirement, a missing test name and an empty evidence cell.
  **Result: pass (0 problems).**
- **Spec updates made during implementation:**
  - `plan.md` §10 now names the pinned image tag.
  - The SAFE-005 static scan is case-sensitive, documented in a test comment. Prose such as "a
    real Terraform plan" is not a command. The Terraform-safe-check script still has its own
    subcommand allowlist test.

## 3. Architecture

| Layer | Location |
|---|---|
| Strict loading (UTF-8, 1 MiB cap, duplicate keys, NaN or Infinity, top-level object) and secret scan, then schema, then semantics, then digest | `src/iac_change_control/plan_loader.py` |
| JSON Schema 2020-12 subset validator (unknown keywords rejected; value-free messages) | `src/iac_change_control/schema_validator.py` |
| Contracts | `schemas/synthetic-plan.schema.json`, `approval.schema.json`, `policy-config.schema.json`, `evidence.schema.json` |
| Six policy rules, one module each | `src/iac_change_control/rules/{public_ingress,wildcard_iam,storage_encryption,destroy_changes,required_tags,provider_version}.py` |
| Approval gate (`IAC-APR-001`..`007`) | `src/iac_change_control/rules/approval_gate.py` |
| Decision engine (any exception becomes ERROR) | `src/iac_change_control/policy_engine.py` |
| Evidence writer and verifier | `src/iac_change_control/evidence.py` |
| CLI (`evaluate`, `digest`, `verify-bundle`) | `src/iac_change_control/cli.py` |
| Policy | `policy/policy-config.json` (`lab-baseline` 1.0.0) |
| Fixtures | 11 plans, 14 approvals, 1 invalid policy (`fixtures/`). All `synthetic: true`. |
| Evidence | `evidence/<run>/`: five files per run. Ignored except `evidence/README.md`. |

**Decisions:**
- `PASS` and `WARN`: exit 0;
- `BLOCKED`: exit 1;
- `ERROR`: exit 2.

There is no hard-violation exception: a fully valid approval never suppresses a blocking finding.

## 4. File inventory (85 files including this report, excluding `.venv`, caches, egg-info and generated evidence)

| Area | Files |
|---|---|
| Root | `README.md`, `BUILD_REPORT.md`, `pyproject.toml`, `requirements-dev.lock`, `.gitignore`, `.gitattributes` |
| Specs | `specs/2026-11-01-iac-change-control/{plan,requirements,validation}.md` |
| Source (16) | `src/iac_change_control/`: `__init__`, `__main__`, `canonical`, `cli`, `evidence`, `models`, `plan_loader`, `policy_engine`, `schema_validator`. `rules/`: `__init__`, `approval_gate`, `destroy_changes`, `provider_version`, `public_ingress`, `required_tags`, `storage_encryption`, `wildcard_iam`. |
| Schemas (4), policy (1) | as in §3 |
| Fixtures (26) | `fixtures/plans/` (11), `fixtures/approvals/` (14), `fixtures/policies/invalid-policy.json` |
| Tests (20) | `tests/conftest.py`, `helpers.py`, `test_safety.py`, `test_traceability.py`, `unit/` (7 modules), `integration/` (4 modules), `regression/test_regression.py`, `expected_outcomes.json`, `golden/` (2 golden files and a README) |
| Scripts (3) | `scripts/run_demo.py`, `run-evaluation.ps1`, `terraform-safe-check.ps1` |
| Docs (3) | `docs/fixture-contract.md`, `safe-usage.md`, `ci-design.md` |
| Other | `terraform-sample/main.tf` (provider-free, resource-free), `evidence/README.md` |

Python size:
- `src`: about 1,900 lines;
- `tests`: about 2,150 lines;
- `scripts`: 74 lines.

## 5. Dependency rationale

- **Runtime: none** (`dependencies = []`). JSON, hashing, CIDR parsing (`ipaddress`), schema
  validation (a small in-repo subset) and the CLI (`argparse`) all use the standard library. This
  keeps the evaluator offline-capable and auditable, with no supply-chain surface. A test enforces
  it (`test_runtime_has_no_third_party_dependencies`).
- **Development:**
  - `pytest==9.1.1` and `ruff==0.16.9` are pinned in `pyproject.toml`, with the fully resolved set
    in `requirements-dev.lock`;
  - `setuptools==80.9.0` is pinned as the build backend, used only for `pip install -e .`.
- **Not used:**
  - no cloud or provider SDKs;
  - no Terraform wrappers;
  - no HTTP clients;
  - no telemetry;
  - no model libraries;
  - no third-party JSON Schema library.

## 6. Validation results (all commands run locally from the project root)

| Step | Result |
|---|---|
| V-TEST-01 `python -m pytest -q` | **260 passed** (144 test functions; 159 unit, 60 integration, 24 regression, 14 safety, 3 traceability). |
| V-LINT-01 `python -m ruff check .` | **All checks passed!** (`ruff format --check`: 42 files already formatted.) |
| V-DEMO-01 `python scripts/run_demo.py` | **Exit 0.** 9 of 9 cases matched, every bundle verified, every row labelled `[synthetic/local]`. |
| V-DET-01 (byte stability) | Two compliant runs with run ID `fixture-compliant-v1`: all five files **IDENTICAL**. `verify-bundle`: OK, exit 0. |
| V-NEG-01..12 | **16 of 16 OK.** Exact exit codes and rule or error codes, listed below. |
| V-TRACE-01, V-SAFE-01 | Pass (3 and 14 tests). |
| V-TF-01 (optional) | **PASS.** Terraform v1.14.0 (linux_amd64) in a network-disabled container; `fmt -check` clean. See §7. |
| V-PHASE-01 | `Test-Path .git`: False. `Test-Path .github`: False. `LICENSE*`: none. |

**Demo results** (`evidence/demo/`, ignored):

| Case | Decision | Exit | Rules or errors |
|---|---|---|---|
| 01 compliant + approved-change | PASS | 0 | none |
| 02 warn-nonstandard-port + approved-warn-change | WARN | 0 | `IAC-IAM-002`, `IAC-NET-002` |
| 03 public-ingress + approved-public-ingress | BLOCKED | 1 | `IAC-NET-001` ×2 |
| 04 destroy-change + approved-destroy-standard | BLOCKED | 1 | `IAC-APR-006`, `IAC-CHG-001` ×2 |
| 05 destroy-change + approved-destroy-elevated | WARN | 0 | `IAC-CHG-001` ×2 |
| 06 mixed-violations + approved-mixed-violations | BLOCKED | 1 | `IAC-CHG-001`, `IAC-ENC-001`, `IAC-IAM-001`, `IAC-NET-001`, `IAC-TAG-001` |
| 07 compliant + missing-approval | BLOCKED | 1 | `IAC-APR-001` |
| 08 malformed | ERROR | 2 | `json_parse_error` |
| 09 unsupported-resource | ERROR | 2 | `unsupported_resource_type` |

**Negative sequence:**

| Step | Exit | Result |
|---|---|---|
| V-NEG-01 | 1 | `IAC-NET-001` ×2 |
| V-NEG-02 | 1 | `IAC-IAM-001` |
| V-NEG-03 | 1 | `IAC-ENC-001` ×3 |
| V-NEG-04 | 1 | `IAC-APR-006` + `IAC-CHG-001` ×2 |
| V-NEG-05 | 1 | `IAC-TAG-001` ×2 |
| V-NEG-06 | 1 | `IAC-VER-001`..`004` |
| V-NEG-07a..e | 1 each | `APR-001`, `APR-002`, `APR-003`+`004`, `APR-005`, `APR-001` |
| V-NEG-08 | 2 | `json_parse_error` |
| V-NEG-09 | 2 | `unsupported_resource_type` |
| V-NEG-10 | 2 | `invalid_version_range`, `port_overlap` |
| V-NEG-11 | 2 | Invalid run ID. No bundle written. |
| V-NEG-12 | 2 | Foreign file in the output directory. Refused; the directory is unchanged. |

**Deterministic evidence:** besides V-DET-01, the regression tests check:
- byte-identical bundles across `PYTHONHASHSEED=0` and `12345`;
- two working directories, with relative and absolute paths;
- in-process runs against subprocess runs;
- golden `evaluation.json` files (compliant and mixed-violations);
- golden change-set digests for all 9 valid plans.

**Mutation check** (scratch script outside the project; source restored afterwards, then 260
passed). Each deliberately broken control was caught by the suite:

| Mutation | Failing tests |
|---|---|
| Digest check disabled | 4 |
| Elevation check disabled | 4 |
| Approvals suppress violations | 31 |
| Internal error yields PASS | 2 |
| IPv6 world CIDR ignored | 5 |
| Credential scan disabled | 1 |
| Reserved-CIDR check disabled | 5 |
| Findings unsorted | 10 |
| Blank tags accepted | 2 |
| Timestamp added to evidence | 6 |

**Issues found and fixed during the build:**
- Two schema files initially contained invalid JSON escapes. Every evaluation failed closed to
  `ERROR` (`evaluator_internal_error`) rather than passing, and the schemas were corrected.
- `pip freeze` wrote CRLF into `requirements-dev.lock`. It was normalized to LF.
- One run-ID test case (`-leading-dash`) exercised argparse rather than the validator. It was
  replaced with `_leading-underscore`.

## 7. Terraform-safe check (optional, non-blocking)

`scripts/terraform-safe-check.ps1` ran:

```text
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -e CHECKPOINT_DISABLE=1 -v <terraform-sample>:/work:ro -w /work hashicorp/terraform:1.14.0 version
```

followed by the same container settings with `fmt -check -recursive -diff`.

**Results:**
- **PASS:** Terraform v1.14.0 printed, and `fmt -check` was clean.
- **Negative check:** the sample was temporarily misformatted. The script reported `FAIL` with
  exit 1. The file was restored byte for byte and the re-run passed.
- **Scope:** no `init`, no planning, apply, destroy, import, refresh or state command, and no
  provider download. The sample declares no providers or resources.

**Network:** Docker pulled the official image once from Docker Hub. The container itself ran with
no network. The core evaluator, tests and demo never use Docker or Terraform.

## 8. Limitations and non-claims

- All fixtures are synthetic: fictional `labcloud_*` types, `.example` provider sources, and
  reserved CIDR ranges. None is output from a real Terraform plan or cloud account.
- The rule set is small and illustrative. It is not complete, not a policy-engine replacement,
  not a production control plane, and not a compliance control or certification.
- IAM parsing is simplified:
  - only `Allow` statements;
  - only exact `"*"` and `service:*` actions;
  - no conditions or `NotAction`;
  - partial resource wildcards are not evaluated.
- Network evaluation covers one fictional firewall type.
- Approval records are data. The tool authenticates no approver and integrates with no ticketing
  or identity system.
- A `PASS` or `WARN` is not authorization to change infrastructure. Human review remains
  required.
- The schemas are resolved from the source checkout (`schemas/`). The lab is meant to run from a
  checkout with the editable install, not as a published package.

## 9. Actions taken and not taken in this phase

**Network activity:**
- `pip` downloaded the pinned dev tooling (pytest, ruff, setuptools and their dependencies) from
  PyPI into `.venv`.
- Docker pulled `hashicorp/terraform:1.14.0` for the optional check.
- The evaluator and test suite made no network calls. Tests run under a socket guard.

**Not done:**
- No cloud account, cloud API, remote backend, remote state, credential, `.env`, vault or real
  plan or state was accessed.
- No Terraform `init`, plan, apply, destroy, import, refresh, login or state command was run, and
  no provider was downloaded.
- No Git repository, commit, tag, push, remote, GitHub repository, pull request, release, package
  publication, deployment or CI workflow was created.
- No license was added.
- No file outside `iac-change-control-lab/` was created or modified, except temporary authoring
  and mutation scripts in the session scratchpad, outside the repository. No other portfolio
  project's code or data was used.

**Next steps** are owner decisions: repository initialization, publication, CI, a license, or
any follow-up.
