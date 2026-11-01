# Validation: `iac-change-control-lab`

- **Spec date:** 2026-11-01
- **Plan:** [`plan.md`](plan.md)
- **Requirements:** [`requirements.md`](requirements.md)

All commands run from the project root in Windows PowerShell with the project virtual environment
activated (`.\.venv\Scripts\Activate.ps1`). Every command is local and offline. No command
contacts a cloud provider, runs Terraform against infrastructure, or changes anything outside the
project directory. Generated output goes only to ignored paths under `evidence/`.

## 1. Environment setup (V-ENV-01)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
```

**Expected:** pytest and ruff are installed at the pinned versions, and `iac_change_control`
imports. Runtime dependencies: none. Terraform and Docker are **not** required.

## 2. Validation steps

| Step | Command | Expected exit | Expected result |
|---|---|---|---|
| V-TEST-01 | `python -m pytest -q` | 0 | All tests pass, including the safety and traceability tests. Runs under the socket guard. |
| V-LINT-01 | `python -m ruff check .` | 0 | `All checks passed!` |
| V-DEMO-01 | `python scripts/run_demo.py` | 0 | Every demo case matches its expected decision (§2.2). Each line is labelled synthetic/local. Bundles are verified. Output is only under `evidence/demo/`. |
| V-DET-01 | §2.3 | 0 | Two compliant runs with the same run ID are byte-identical, file by file. |
| V-NEG-01..12 | §2.4 | as listed | Exact exit codes and stable rule IDs or error codes. |
| V-TRACE-01 | `python -m pytest -q tests/test_traceability.py` | 0 | Every requirement ID is mapped (§3). |
| V-SAFE-01 | `python -m pytest -q tests/test_safety.py` | 0 | Static safety checks (SAFE-001..008, NFR-003, NFR-004). |
| V-TF-01 | `powershell -File scripts/terraform-safe-check.ps1` | 0 | Optional. `PASS` (version printed, `fmt -check` clean) or `SKIP` with a reason. Never blocks other steps. |
| V-PHASE-01 | §2.5 | n/a | Build-phase state: no `.git`, no `.github`, no `LICENSE*` in the project. |

### 2.1 Decision and exit-code reference

| Decision | Exit code |
|---|---|
| `PASS` | 0 |
| `WARN` | 0 |
| `BLOCKED` | 1 |
| `ERROR` | 2 |

### 2.2 Fixture outcome matrix (golden: `tests/regression/expected_outcomes.json`)

| # | Plan | Approval | Decision | Exit | Rule IDs (sorted) / error codes |
|---|---|---|---|---|---|
| 1 | `compliant` | `approved-change` | PASS | 0 | none |
| 2 | `warn-nonstandard-port` | `approved-warn-change` | WARN | 0 | `IAC-IAM-002`, `IAC-NET-002` |
| 3 | `public-ingress` | `approved-public-ingress` | BLOCKED | 1 | `IAC-NET-001` ×2 |
| 4 | `wildcard-iam` | `approved-wildcard-iam` | BLOCKED | 1 | `IAC-IAM-001` |
| 5 | `unencrypted-storage` | `approved-unencrypted-storage` | BLOCKED | 1 | `IAC-ENC-001` ×3 |
| 6 | `destroy-change` | `approved-destroy-standard` | BLOCKED | 1 | `IAC-APR-006`, `IAC-CHG-001` ×2 |
| 7 | `destroy-change` | `approved-destroy-elevated` | WARN | 0 | `IAC-CHG-001` ×2 |
| 8 | `missing-tags` | `approved-missing-tags` | BLOCKED | 1 | `IAC-TAG-001` ×2 |
| 9 | `provider-version-violation` | `approved-provider-version-violation` | BLOCKED | 1 | `IAC-VER-001`, `IAC-VER-002`, `IAC-VER-003`, `IAC-VER-004` |
| 10 | `mixed-violations` | `approved-mixed-violations` | BLOCKED | 1 | `IAC-CHG-001`, `IAC-ENC-001`, `IAC-IAM-001`, `IAC-NET-001`, `IAC-TAG-001` |
| 11 | `compliant` | `missing-approval` | BLOCKED | 1 | `IAC-APR-001` |
| 12 | `compliant` | *(none)* | BLOCKED | 1 | `IAC-APR-001` |
| 13 | `compliant` | `rejected-approval` | BLOCKED | 1 | `IAC-APR-002` |
| 14 | `compliant` | `stale-or-out-of-scope-approval` | BLOCKED | 1 | `IAC-APR-003`, `IAC-APR-004` |
| 15 | `compliant` | `digest-mismatch-approval` | BLOCKED | 1 | `IAC-APR-005` |
| 16 | `public-ingress` | `approved-change` | BLOCKED | 1 | `IAC-APR-004`, `IAC-APR-005`, `IAC-NET-001` ×2 |
| 17 | `malformed` | `approved-change` | ERROR | 2 | `json_parse_error` |
| 18 | `unsupported-resource` | `approved-change` | ERROR | 2 | `unsupported_resource_type` |
| 19 | `compliant` + policy `fixtures/policies/invalid-policy.json` | `approved-change` | ERROR | 2 | `invalid_version_range`, `port_overlap` |

In rows 3 to 10, each violating plan is paired with an approval that is fully valid for that plan:
matching digest, scope and policy version, and elevated with matching destructive addresses
where the plan has deletes (rows 7 and 10). That is how the matrix demonstrates REQ-016: a valid
approval never suppresses a blocking policy finding.

**Demo cases** (`scripts/run_demo.py`): rows 1, 2, 3, 6, 7, 10, 11, 17 and 18. That covers PASS,
WARN, BLOCKED and ERROR.

### 2.3 Byte-stability verification (V-DET-01)

```powershell
python -m iac_change_control.cli evaluate --plan fixtures/plans/compliant.json `
  --approval fixtures/approvals/approved-change.json --policy policy/policy-config.json `
  --output evidence/det-a --run-id fixture-compliant-v1
python -m iac_change_control.cli evaluate --plan fixtures/plans/compliant.json `
  --approval fixtures/approvals/approved-change.json --policy policy/policy-config.json `
  --output evidence/det-b --run-id fixture-compliant-v1
Get-ChildItem evidence/det-a -File | ForEach-Object {
  $a = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
  $b = (Get-FileHash (Join-Path 'evidence/det-b' $_.Name) -Algorithm SHA256).Hash
  '{0} {1}' -f $_.Name, ($(if ($a -eq $b) { 'IDENTICAL' } else { 'DIFFERENT' }))
}
python -m iac_change_control.cli verify-bundle --bundle evidence/det-a
```

**Expected:**
- both runs exit 0;
- all five files report `IDENTICAL`;
- `verify-bundle` exits 0.

`tests/regression/test_regression.py` repeats this automatically:
- across two `PYTHONHASHSEED` values;
- from two working directories;
- with relative and absolute input paths.

It also compares `evaluation.json` against the golden files in `tests/regression/golden/`.

### 2.4 Negative-test sequence (V-NEG)

Run each command and check the exit code with `$LASTEXITCODE`. Each one writes a bundle under
`evidence/neg-NN` (ignored), except V-NEG-11 and V-NEG-12, which are refused before writing.

| Step | Inputs | Expected exit | Expected `evaluation.json` content |
|---|---|---|---|
| V-NEG-01 | `public-ingress` + `approved-public-ingress` | 1 | `BLOCKED`, findings `IAC-NET-001` on `labcloud_firewall_rule.admin_ssh` and `labcloud_firewall_rule.debug_all` |
| V-NEG-02 | `wildcard-iam` + `approved-wildcard-iam` | 1 | `BLOCKED`, `IAC-IAM-001` |
| V-NEG-03 | `unencrypted-storage` + `approved-unencrypted-storage` | 1 | `BLOCKED`, `IAC-ENC-001` ×3 |
| V-NEG-04 | `destroy-change` + `approved-destroy-standard` | 1 | `BLOCKED`, `IAC-APR-006` |
| V-NEG-05 | `missing-tags` + `approved-missing-tags` | 1 | `BLOCKED`, `IAC-TAG-001` ×2 |
| V-NEG-06 | `provider-version-violation` + its approval | 1 | `BLOCKED`, `IAC-VER-001`..`004` |
| V-NEG-07 | `compliant` + `missing-approval`, `rejected-approval`, `stale-or-out-of-scope-approval`, `digest-mismatch-approval`, and no approval | 1 each | `BLOCKED`, with `IAC-APR-001`, `002`, `003`+`004`, `005` and `001` respectively |
| V-NEG-08 | `malformed` | 2 | `ERROR`, error `json_parse_error`, no findings |
| V-NEG-09 | `unsupported-resource` | 2 | `ERROR`, error `unsupported_resource_type` |
| V-NEG-10 | `compliant` + `fixtures/policies/invalid-policy.json` | 2 | `ERROR`, policy errors `invalid_version_range` and `port_overlap` |
| V-NEG-11 | `--run-id "Bad ID!"` | 2 | Refused before writing. No bundle. |
| V-NEG-12 | `--output` pointing to a directory that contains a foreign file | 2 | Refused before writing. The directory is unchanged. |

**Failure interpretation:**
- **Exit 0 for any row above:** a control failed open. Treat it as a defect and never accept it.
- **Exit 2 where 1 is expected:** the fixture failed validation. Inspect `errors` in
  `evaluation.json`.
- **Exit 1 where 2 is expected:** invalid input was evaluated. That is a defect in the loader.
- **Rule IDs differ from the matrix:** a rule regression. Compare against
  `tests/regression/expected_outcomes.json`.

### 2.5 Build-phase state (V-PHASE-01)

```powershell
Test-Path .git; Test-Path .github; Get-ChildItem -Force -Filter 'LICENSE*'
```

**Expected:** `False`, `False`, no output. This records the state of this local build phase only.
It is deliberately not a permanent test, because the owner may later add Git, CI or a license.

## 3. Traceability matrix

Columns:
- **Tests:** test function names under `tests/`.
- **Implementation:** paths relative to the project root.
- **Evidence:** what the test run, a bundle or the repository shows.

`tests/test_traceability.py` parses this table.

| ID | Tests | Implementation | Evidence |
|---|---|---|---|
| REQ-001 | `test_cli_evaluate_compliant_writes_bundle_and_exits_0`, `test_cli_rejects_invalid_run_id`, `test_cli_requires_mandatory_arguments` | `src/iac_change_control/cli.py` | pytest pass; `evidence/demo/*` bundles; V-NEG-11 |
| REQ-002 | `test_missing_file_is_error`, `test_oversized_file_is_error`, `test_non_utf8_file_is_error`, `test_malformed_json_is_error`, `test_duplicate_keys_are_error`, `test_non_finite_numbers_are_error`, `test_top_level_must_be_object` | `src/iac_change_control/plan_loader.py` | pytest pass; V-NEG-08 `errors[].code` |
| REQ-003 | `test_all_valid_plan_fixtures_load`, `test_missing_required_field_is_error`, `test_wrong_type_is_error`, `test_unknown_property_is_error`, `test_unsupported_resource_type_is_error`, `test_synthetic_flag_required`, `test_empty_resource_changes_is_error`, `test_address_must_match_type_and_name`, `test_duplicate_address_is_error`, `test_unknown_provider_reference_is_error`, `test_provider_key_must_match_name`, `test_malformed_version_is_error`, `test_schema_enums_match_code_constants`, `test_fixtures_conform_to_published_schemas`, `test_schema_validator_supported_keywords`, `test_schema_validator_rejects_unknown_keyword` | `src/iac_change_control/plan_loader.py`, `src/iac_change_control/schema_validator.py`, `schemas/synthetic-plan.schema.json` | pytest pass; V-NEG-09 |
| REQ-004 | `test_unknown_action_is_error`, `test_unsupported_action_combination_is_error`, `test_before_after_must_match_actions` | `src/iac_change_control/plan_loader.py` | pytest pass; `errors[].code` in ERROR bundles |
| REQ-005 | `test_all_approval_fixtures_load`, `test_malformed_approval_is_error`, `test_approval_requires_fields_for_decided_status`, `test_approval_digest_format_enforced` | `src/iac_change_control/plan_loader.py`, `schemas/approval.schema.json` | pytest pass |
| REQ-006 | `test_default_policy_loads`, `test_invalid_policy_fixture_is_error`, `test_policy_semantic_checks`, `test_cli_invalid_policy_exits_2` | `src/iac_change_control/plan_loader.py`, `schemas/policy-config.schema.json`, `policy/policy-config.json` | pytest pass; V-NEG-10 |
| REQ-007 | `test_digest_format`, `test_digest_ignores_key_order_whitespace_and_descriptive_fields`, `test_digest_ignores_resource_order`, `test_digest_changes_with_substantive_change`, `test_golden_digests`, `test_cli_digest_command` | `src/iac_change_control/plan_loader.py`, `src/iac_change_control/canonical.py` | `change_set_digest` in `evaluation.json`/`provenance.json`; golden digests |
| REQ-008 | `test_public_ingress_sensitive_port_blocks`, `test_public_ingress_all_ports_blocks`, `test_public_ingress_protocol_all_blocks`, `test_public_ingress_ipv6_world_blocks`, `test_public_ingress_allowed_port_passes`, `test_public_ingress_nonstandard_port_warns`, `test_private_cidr_and_egress_not_flagged`, `test_fixture_public_ingress_blocked` | `src/iac_change_control/rules/public_ingress.py` | `IAC-NET-001`/`IAC-NET-002` findings; V-NEG-01 |
| REQ-009 | `test_wildcard_action_blocks`, `test_wildcard_resource_blocks`, `test_deny_wildcard_not_flagged`, `test_service_wildcard_warns`, `test_scoped_policy_passes`, `test_fixture_wildcard_iam_blocked` | `src/iac_change_control/rules/wildcard_iam.py` | `IAC-IAM-001`/`IAC-IAM-002` findings; V-NEG-02 |
| REQ-010 | `test_encryption_missing_null_or_disabled_blocks`, `test_disallowed_algorithm_blocks`, `test_encrypted_storage_passes`, `test_non_storage_types_not_checked`, `test_fixture_unencrypted_storage_blocked` | `src/iac_change_control/rules/storage_encryption.py` | `IAC-ENC-001` findings; V-NEG-03 |
| REQ-011 | `test_delete_action_flagged_high`, `test_replace_action_flagged`, `test_non_destructive_actions_not_flagged`, `test_fixture_destroy_with_standard_approval_blocked` | `src/iac_change_control/rules/destroy_changes.py` | `IAC-CHG-001` findings; V-NEG-04 |
| REQ-012 | `test_missing_tag_keys_block`, `test_blank_tag_values_block`, `test_absent_tags_block`, `test_complete_tags_pass`, `test_fixture_missing_tags_blocked` | `src/iac_change_control/rules/required_tags.py` | `IAC-TAG-001` findings; V-NEG-05 |
| REQ-013 | `test_terraform_version_out_of_range_blocks`, `test_provider_not_allowlisted_blocks`, `test_provider_source_mismatch_blocks`, `test_provider_version_out_of_range_blocks`, `test_provider_missing_constraint_blocks`, `test_fixture_provider_version_violation_blocked` | `src/iac_change_control/rules/provider_version.py` | `IAC-VER-*` findings; V-NEG-06 |
| REQ-014 | `test_gate_valid_approval`, `test_gate_no_approval_file`, `test_gate_not_submitted`, `test_gate_rejected`, `test_gate_stale`, `test_gate_out_of_scope`, `test_gate_digest_mismatch`, `test_fixture_approval_matrix` | `src/iac_change_control/rules/approval_gate.py` | `approval-assessment.json` checks; V-NEG-07 |
| REQ-015 | `test_gate_destructive_requires_elevated`, `test_gate_destructive_address_mismatch`, `test_gate_lists_addresses_without_destructive_changes`, `test_fixture_destroy_with_elevated_approval_warns` | `src/iac_change_control/rules/approval_gate.py` | `IAC-APR-006`/`007` checks; demo rows 6 and 7 |
| REQ-016 | `test_valid_approval_never_suppresses_hard_violation` | `src/iac_change_control/policy_engine.py` | matrix rows 3 to 10 stay BLOCKED with valid approvals |
| REQ-017 | `test_finding_fields_complete`, `test_findings_sorted_by_stable_key`, `test_mixed_violations_sorted`, `test_readme_rule_catalog_matches_code` | `src/iac_change_control/models.py`, `src/iac_change_control/policy_engine.py` | `findings[]` in `evaluation.json`; golden `mixed-violations.evaluation.json` |
| REQ-018 | `test_decision_table`, `test_internal_error_is_error_not_pass`, `test_cli_exit_codes_match_decisions`, `test_invalid_inputs_never_pass` | `src/iac_change_control/policy_engine.py`, `src/iac_change_control/cli.py` | `decision`/`exit_code` in `evaluation.json`; demo exit codes |
| REQ-019 | `test_bundle_contains_exactly_five_files`, `test_evaluation_json_content`, `test_error_run_still_writes_bundle`, `test_evidence_conforms_to_schema` | `src/iac_change_control/evidence.py`, `schemas/evidence.schema.json` | `evidence/demo/*/` five-file bundles |
| REQ-020 | `test_provenance_hashes_match_inputs`, `test_provenance_without_approval` | `src/iac_change_control/evidence.py` | `provenance.json` |
| REQ-021 | `test_manifest_lists_hashes_in_stable_order`, `test_verify_bundle_accepts_intact_bundle`, `test_verify_bundle_detects_tampering` | `src/iac_change_control/evidence.py`, `src/iac_change_control/cli.py` | `manifest.sha256`; `verify-bundle` exit codes |
| REQ-022 | `test_cli_digest_command`, `test_cli_digest_invalid_plan_exits_2` | `src/iac_change_control/cli.py` | stdout `sha256:<hex>` |
| REQ-023 | `test_demo_runs_and_writes_only_to_ignored_path` | `scripts/run_demo.py` | V-DEMO-01 output; `evidence/demo/` |
| REQ-024 | `test_output_dir_with_foreign_files_refused`, `test_rerun_overwrites_bundle_in_place` | `src/iac_change_control/evidence.py` | V-NEG-12 |
| NFR-001 | `test_repeated_runs_byte_identical`, `test_byte_identical_across_hash_seeds_and_working_directories`, `test_golden_evaluation_files`, `test_canonical_json_format` | `src/iac_change_control/canonical.py`, `src/iac_change_control/evidence.py` | V-DET-01 `IDENTICAL`; golden files |
| NFR-002 | `test_evidence_has_no_timestamps_absolute_paths_or_host_data` | `src/iac_change_control/evidence.py` | bundle contents |
| NFR-003 | `test_runtime_has_no_third_party_dependencies`, `test_dev_tooling_pinned` | `pyproject.toml`, `requirements-dev.lock` | `dependencies = []`; lock file |
| NFR-004 | `test_evaluator_runs_with_empty_path`, `test_core_never_references_terraform_or_docker_binaries` | `src/iac_change_control/cli.py` | pytest pass with Terraform absent |
| NFR-005 | `test_ruff_check_passes` | `pyproject.toml` | V-TEST-01 and V-LINT-01 output |
| NFR-006 | `test_every_requirement_is_traced`, `test_traceability_checker_rejects_unmapped_requirement` | `tests/test_traceability.py`, `specs/2026-11-01-iac-change-control/validation.md` | V-TRACE-01 |
| NFR-007 | `test_error_messages_do_not_echo_values`, `test_error_list_is_sorted_and_capped` | `src/iac_change_control/plan_loader.py`, `src/iac_change_control/schema_validator.py` | `errors[]` in ERROR bundles |
| SAFE-001 | `test_no_network_or_cloud_imports`, `test_socket_guard_blocks_network` | `tests/conftest.py`, `src/iac_change_control` | V-SAFE-01 |
| SAFE-002 | `test_no_process_execution_or_env_reads_in_src` | `src/iac_change_control` | V-SAFE-01 |
| SAFE-003 | `test_credential_like_keys_rejected`, `test_secret_like_values_rejected`, `test_repository_contains_no_secret_patterns` | `src/iac_change_control/plan_loader.py` | `credential_like_key`/`secret_like_value` errors; V-SAFE-01 |
| SAFE-004 | `test_cidr_outside_reserved_ranges_rejected`, `test_non_canonical_cidr_rejected`, `test_provider_source_must_use_example_domain`, `test_all_fixtures_labelled_synthetic` | `src/iac_change_control/plan_loader.py`, `schemas/synthetic-plan.schema.json` | fixture review; V-SAFE-01 |
| SAFE-005 | `test_no_state_changing_terraform_commands`, `test_terraform_safe_check_limited_to_version_and_fmt`, `test_terraform_sample_is_provider_and_resource_free` | `scripts/terraform-safe-check.ps1`, `terraform-sample/main.tf` | V-SAFE-01; V-TF-01 output |
| SAFE-006 | `test_scripts_and_source_perform_no_publication_operations` | `scripts/run_demo.py`, `scripts/run-evaluation.ps1`, `scripts/terraform-safe-check.ps1` | V-SAFE-01; V-PHASE-01 |
| SAFE-007 | `test_every_evidence_file_labelled_synthetic`, `test_readme_states_non_claims`, `test_gitignore_covers_generated_and_secret_paths` | `src/iac_change_control/evidence.py`, `README.md`, `.gitignore` | synthetic banner in every bundle file |
| SAFE-008 | `test_evidence_states_no_authorization_and_human_review` | `src/iac_change_control/models.py`, `src/iac_change_control/evidence.py`, `README.md` | `notice` in `evaluation.json`; `summary.md` footer |
