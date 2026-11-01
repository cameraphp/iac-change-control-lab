# evidence/

Generated evidence bundles go here. Everything in this directory **except this README** is
ignored by version control (`.gitignore`: `evidence/*` and `!evidence/README.md`). Regenerate
bundles at any time with the CLI or `python scripts/run_demo.py`.

Each bundle directory contains:
- `evaluation.json`;
- `summary.md`;
- `provenance.json`;
- `approval-assessment.json`;
- `manifest.sha256`.

Every bundle is derived from **synthetic, local fixtures**. A bundle records a lab evaluation
only. It is not evidence that any real infrastructure was created, modified, destroyed or
approved, and a `PASS` is not authorization to change anything.

Verify a bundle with:

```powershell
python -m iac_change_control.cli verify-bundle --bundle evidence/<bundle-dir>
```
