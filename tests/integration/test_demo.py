"""Demo walkthrough (REQ-023): it runs, matches expectations and writes only to the ignored path."""

from __future__ import annotations

import subprocess
import sys

from helpers import PROJECT_ROOT, read_json

IGNORED_PARTS = {".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}


def snapshot() -> dict[str, tuple[int, int]]:
    state = {}
    for path in PROJECT_ROOT.rglob("*"):
        rel = path.relative_to(PROJECT_ROOT)
        if (
            IGNORED_PARTS & set(rel.parts)
            or rel.parts[0] == "evidence"
            or any(part.endswith(".egg-info") for part in rel.parts)
        ):
            continue
        if path.is_file():
            stat = path.stat()
            state[rel.as_posix()] = (stat.st_size, stat.st_mtime_ns)
    return state


def test_demo_runs_and_writes_only_to_ignored_path():
    before = snapshot()
    evidence_before = {
        p.relative_to(PROJECT_ROOT).as_posix()
        for p in (PROJECT_ROOT / "evidence").rglob("*")
        if p.is_file()
    }
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "run_demo.py")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "SYNTHETIC / LOCAL FIXTURES ONLY" in out.splitlines()[0]
    assert "All 9 cases matched" in out
    rows = [line for line in out.splitlines() if line.startswith("0")]
    assert len(rows) == 9 and all(line.endswith("[synthetic/local]") for line in rows)
    assert {line.split()[2] for line in rows} == {"PASS", "WARN", "BLOCKED", "ERROR"}
    assert all(" verified " in line for line in rows)

    assert snapshot() == before  # nothing outside evidence/ changed
    evidence_after = {
        p.relative_to(PROJECT_ROOT).as_posix()
        for p in (PROJECT_ROOT / "evidence").rglob("*")
        if p.is_file()
    }
    new_files = evidence_after - evidence_before
    assert all(path.startswith("evidence/demo/") for path in new_files)
    first = read_json(PROJECT_ROOT / "evidence" / "demo" / "01-pass-compliant" / "evaluation.json")
    assert first["decision"] == "PASS" and first["synthetic_inputs"] is True
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "evidence/*" in gitignore and "!evidence/README.md" in gitignore
