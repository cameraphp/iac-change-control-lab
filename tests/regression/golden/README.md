# Golden evidence files

These are byte-exact `evaluation.json` outputs for two fixed runs. Every input is a synthetic
fixture. `tests/regression/test_regression.py` compares fresh runs against them.

| File | Inputs | Run ID |
|---|---|---|
| `compliant.evaluation.json` | `fixtures/plans/compliant.json` and `fixtures/approvals/approved-change.json` | `golden-compliant` |
| `mixed-violations.evaluation.json` | `fixtures/plans/mixed-violations.json` and `fixtures/approvals/approved-mixed-violations.json` | `golden-mixed-violations` |

Regenerate a golden file only after an intentional, reviewed behaviour change, then update the
specs. Run from the project root:

```powershell
python -m iac_change_control.cli evaluate --plan fixtures/plans/compliant.json `
  --approval fixtures/approvals/approved-change.json --policy policy/policy-config.json `
  --output evidence/golden-compliant --run-id golden-compliant
Copy-Item evidence/golden-compliant/evaluation.json tests/regression/golden/compliant.evaluation.json
```

To regenerate `mixed-violations.evaluation.json`, run the same commands with the
mixed-violations inputs and the run ID `golden-mixed-violations`.
