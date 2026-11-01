# Future CI design (not implemented)

This is a design note only. **This build phase creates no CI workflow and no `.github/`
directory.** The owner decides later whether to add one.

## Goals

- Run the same local checks on every push and pull request.
- Use no cloud credentials, remote state, provider downloads or Terraform execution against
  infrastructure.
- Fail if a control fails open: an exit code of 0 where 1 or 2 is expected.

## Proposed job (one runner, read-only permissions)

1. **Check out the repository** with `persist-credentials: false`. Grant `permissions:
   contents: read` only. No secrets are referenced.
2. **Set up Python** 3.13 and install `requirements-dev.lock`, then run
   `pip install --no-deps --no-build-isolation -e .`.
3. **Run `python -m pytest -q`.** This covers unit, integration, regression goldens, byte
   stability, safety and traceability.
4. **Run `python -m ruff check .`.**
5. **Run the demo:** `python scripts/run_demo.py`. It must exit 0.
6. **Run selected fixtures and assert exact exit codes:**
   - `compliant` with `approved-change` must exit 0;
   - `public-ingress` with `approved-public-ingress` must exit 1, never 0;
   - `malformed` must exit 2, never 0.

   The step fails if any command returns an unexpected code. That is an explicit
   expected-failure check, not `|| true`.
7. **Check byte stability:** run the compliant evaluation twice into the runner's temp directory
   and compare every file with `cmp`.
8. **Verify bundles:** run `python -m iac_change_control.cli verify-bundle` on each generated
   bundle.

## Explicitly out of scope for CI

- `terraform init`, plan, apply, destroy, import or refresh, and any provider download.
- Cloud credentials, OIDC federation to a cloud account, remote backends.
- Publishing packages, releases or deployments.
- The optional Docker-based Terraform-safe check. If it is ever added, it must stay a separate,
  non-blocking job, limited to `version` and `fmt -check` on `terraform-sample/`.
