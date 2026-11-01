# Safe usage

This lab is a **local reference** for change-review controls. Use it to study, test and
demonstrate policy-and-evidence workflows over **synthetic** inputs.

## Intended use

- Run the evaluator, tests and demo on your own machine, offline.
- Read and extend the rules, fixtures and specs. Add a fixture for every new rule outcome, and
  map every new requirement in `validation.md`.
- Inspect evidence bundles and re-verify them with `verify-bundle`.

## Do not

- **Do not feed it real plans, state, account identifiers, hostnames, IP addresses or
  credentials.** The loader rejects many of these shapes by design:
  - non-reserved CIDRs;
  - non-`.example` provider sources;
  - credential-like keys and secret-like values.

  That is a guard rail, not a sanitizer.
- **Do not treat `PASS` or `WARN` as authorization.** The decision covers a small, illustrative
  rule set over a synthetic contract. A human reviewer must still decide, outside the tool.
- **Do not wire it into a pipeline that applies infrastructure** and treat it as a control. It is
  not a policy engine, a production control plane or a compliance mechanism.
- **Do not add `terraform init`, plan, apply, destroy, import or refresh to any script.** The
  safety tests fail if a state-changing command appears in an executable file.

## Generated files

Bundles go to the `--output` directory you choose. Use a path under `evidence/`, which is ignored
by version control. The evaluator refuses to write into a directory that contains anything other
than the five bundle files, so it cannot overwrite unrelated files.

## Optional Terraform-safe check

`scripts/terraform-safe-check.ps1` is optional and is never needed by the evaluator. When Docker
is available, it runs a pinned `hashicorp/terraform` image with:
- no container network;
- dropped capabilities;
- a read-only mount of `terraform-sample/` only.

It runs exactly `version` and `fmt -check`. The sample declares no providers, resources, data
sources, modules or backends. Pulling the image is the only network activity, and it is a
one-time Docker image download, not a provider download. Skip the script entirely if you prefer
a fully offline workflow.
