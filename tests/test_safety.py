"""Static safety policies: SAFE-001 to SAFE-008, NFR-003, NFR-004, REQ-017 (README catalog)."""

from __future__ import annotations

import ast
import re
import socket
import sys
import tomllib

import pytest
from conftest import NetworkAccessBlocked
from helpers import PROJECT_ROOT

from iac_change_control.models import NON_CLAIMS, RULE_CATALOG
from iac_change_control.plan_loader import SECRET_VALUE_PATTERNS

SRC = PROJECT_ROOT / "src" / "iac_change_control"
SCRIPTS = PROJECT_ROOT / "scripts"
SKIP_PARTS = {".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "evidence"}

NETWORK_AND_CLOUD_MODULES = {
    # network and HTTP clients
    "aiohttp", "ftplib", "http", "httpx", "requests", "smtplib", "socketserver", "ssl", "telnetlib",
    "urllib", "urllib3", "websocket", "websockets", "xmlrpc", "paramiko", "fabric",
    # cloud, provider, IaC and orchestration SDKs or wrappers
    "boto3", "botocore", "azure", "google", "googleapiclient", "oci", "ibm_cloud_sdk_core",
    "kubernetes", "hcl2", "python_terraform", "terrascript", "pulumi", "cdktf", "openstack",
}  # fmt: skip
PROCESS_MODULES = {"subprocess", "multiprocessing", "pty", "shutil", "ctypes"}
OS_FORBIDDEN_ATTRS = {
    "system",
    "popen",
    "environ",
    "getenv",
    "putenv",
    "environb",
    "startfile",
    "execv",
    "execve",
    "execl",
    "execlp",
    "execvp",
    "spawnl",
    "spawnv",
    "fork",
}


def project_files(*suffixes):
    for path in sorted(PROJECT_ROOT.rglob("*")):
        rel = path.relative_to(PROJECT_ROOT)
        if SKIP_PARTS & set(rel.parts) or any(p.endswith(".egg-info") for p in rel.parts):
            continue
        if path.is_file() and (not suffixes or path.suffix in suffixes):
            yield path


def imports_of(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def executable_files():
    files = list(SRC.rglob("*.py")) + list(SCRIPTS.iterdir())
    files += list((PROJECT_ROOT / "terraform-sample").iterdir())
    files += list((PROJECT_ROOT / "policy").iterdir()) + list(
        (PROJECT_ROOT / "fixtures").rglob("*")
    )
    files.append(PROJECT_ROOT / "pyproject.toml")
    return [f for f in files if f.is_file() and "__pycache__" not in f.parts]


# -- SAFE-001 -------------------------------------------------------------------------------
def test_no_network_or_cloud_imports():
    python_files = list(project_files(".py"))
    assert len(python_files) >= 20
    for path in python_files:
        found = imports_of(path) & NETWORK_AND_CLOUD_MODULES
        assert not found, (path, found)
    for path in SRC.rglob("*.py"):
        assert "socket" not in imports_of(path), path


def test_socket_guard_blocks_network():
    with pytest.raises(NetworkAccessBlocked):
        socket.create_connection(("192.0.2.10", 443), timeout=1)
    with pytest.raises(NetworkAccessBlocked):
        socket.getaddrinfo("registry.example", 443)
    sock = socket.socket()
    try:
        with pytest.raises(NetworkAccessBlocked):
            sock.connect(("192.0.2.10", 443))
    finally:
        sock.close()


# -- SAFE-002 -------------------------------------------------------------------------------
def test_no_process_execution_or_env_reads_in_src():
    for path in list(SRC.rglob("*.py")) + [SCRIPTS / "run_demo.py"]:
        assert not (imports_of(path) & PROCESS_MODULES), path
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                assert not (node.value.id == "os" and node.attr in OS_FORBIDDEN_ATTRS), (
                    path,
                    node.attr,
                )
            if isinstance(node, ast.ImportFrom) and node.module == "os":
                assert not ({a.name for a in node.names} & OS_FORBIDDEN_ATTRS), path
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "__import__"}, path


# -- SAFE-003 -------------------------------------------------------------------------------
def test_repository_contains_no_secret_patterns():
    scanned = 0
    for path in project_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        for pattern in SECRET_VALUE_PATTERNS:
            assert not pattern.search(text), (path, pattern.pattern)
    assert scanned >= 60
    env_files = [p for p in project_files() if p.name == ".env" or p.name.startswith(".env.")]
    assert env_files == []


# -- SAFE-005 -------------------------------------------------------------------------------
STATE_CHANGING = re.compile(
    r"\bterraform(\.exe)?\s+(init|plan|apply|destroy|import|refresh|login|logout|state|taint|"
    r"untaint|force-unlock|workspace|console|providers|get|test)\b|-auto-approve",
)  # Case-sensitive: CLI invocations are lowercase. Prose such as "a real Terraform plan" is not
# a command. terraform-safe-check.ps1 gets a separate subcommand allowlist test below.


def test_no_state_changing_terraform_commands():
    files = executable_files()
    assert len(files) >= 35
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert not STATE_CHANGING.search(text), path


def test_terraform_safe_check_limited_to_version_and_fmt():
    script = (SCRIPTS / "terraform-safe-check.ps1").read_text(encoding="utf-8")
    invoked = re.findall(r"&\s*docker\s+@containerArgs\s+'([a-z-]+)'", script)
    assert invoked == ["version", "fmt"]
    assert re.search(r"'fmt'\s+'-check'", script)
    quoted = set(re.findall(r"'([^'\s]+)'", script)) | set(re.findall(r'"([^"\s]+)"', script))
    forbidden = {
        "init",
        "plan",
        "apply",
        "destroy",
        "import",
        "refresh",
        "login",
        "state",
        "taint",
        "untaint",
        "workspace",
        "providers",
        "get",
        "console",
        "test",
        "push",
        "-auto-approve",
    }
    assert not (quoted & forbidden)
    assert "'--network', 'none'" in script and ":/work:ro" in script
    assert "CHECKPOINT_DISABLE=1" in script and "terraform-sample" in script
    assert re.search(r"hashicorp/terraform:\d+\.\d+\.\d+'", script)
    assert "latest" not in script


def test_terraform_sample_is_provider_and_resource_free():
    tf_files = list((PROJECT_ROOT / "terraform-sample").glob("*.tf"))
    assert tf_files
    for path in tf_files:
        text = path.read_text(encoding="utf-8")
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        blocks = re.findall(r"^([a-z_]+)\b[^\n]*\{\s*$", code, flags=re.MULTILINE)
        assert set(blocks) <= {"terraform", "locals", "output", "variable"}, blocks
        for forbidden in (
            "provider",
            "resource",
            "data",
            "module",
            "backend",
            "cloud",
            "required_providers",
        ):
            assert not re.search(rf"^\s*{forbidden}\b", code, flags=re.MULTILINE), forbidden


# -- SAFE-006 -------------------------------------------------------------------------------
def test_scripts_and_source_perform_no_publication_operations():
    publication = re.compile(
        r"\bgit(\.exe)?\s+(init|add|commit|push|pull|remote|tag|clone|fetch)\b|\bgh\s+\w+|"
        r"docker\s+(push|login|tag)\b|\btwine\b|\bterraform\s+login\b|\.github/workflows",
        re.IGNORECASE,
    )
    for path in list(SRC.rglob("*.py")) + list(SCRIPTS.iterdir()):
        if path.is_file():
            assert not publication.search(path.read_text(encoding="utf-8")), path


# -- SAFE-007 -------------------------------------------------------------------------------
def test_gitignore_covers_generated_and_secret_paths():
    lines = set((PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    required = {
        ".venv/",
        "__pycache__/",
        ".pytest_cache/",
        ".ruff_cache/",
        "evidence/*",
        "!evidence/README.md",
        ".env",
        ".env.*",
        ".terraform/",
        "*.tfstate",
        "*.tfstate.*",
        "*.tfplan",
        "*.tfvars",
        "*.log",
    }
    assert required <= lines, required - lines
    assert (PROJECT_ROOT / "evidence" / "README.md").is_file()


def test_readme_states_non_claims():
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert "## What this lab does not do" in readme
    lowered = readme.lower()
    for phrase in (
        "synthetic",
        "no cloud",
        "credential",
        "real terraform",
        "apply",
        "destroy",
        "not authorization",
        "compliance",
        "production control plane",
        "human review",
    ):
        assert phrase in lowered, phrase
    assert "no license has been selected" in lowered
    assert not (PROJECT_ROOT / "LICENSE").exists() or "no license" not in lowered
    for claim in NON_CLAIMS:  # the README repeats the evidence non-claims verbatim
        assert claim in readme, claim


# -- SAFE-008 (README side) and REQ-017 (catalog drift) -------------------------------------
def test_readme_rule_catalog_matches_code():
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    rows = re.findall(
        r"^\| `(IAC-[A-Z]{3}-\d{3})` \| ([^|]+) \| (critical|high|medium|low) \| "
        r"(blocking|non-blocking)[^|]*\|",
        readme,
        flags=re.MULTILINE,
    )
    catalog = {
        rule_id: (title.strip(), severity, kind == "blocking")
        for rule_id, title, severity, kind in rows
    }
    expected = {i.rule_id: (i.title, i.severity, i.blocking) for i in RULE_CATALOG.values()}
    assert catalog == expected
    assert "not authorization" in readme and "human review" in readme.lower()


# -- NFR-003 --------------------------------------------------------------------------------
def test_runtime_has_no_third_party_dependencies():
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    assert project["dependencies"] == []
    assert project["requires-python"] == ">=3.11"
    assert "license" not in project
    stdlib = set(sys.stdlib_module_names)
    for path in SRC.rglob("*.py"):
        third_party = {name for name in imports_of(path) if name not in stdlib} - {
            "iac_change_control",
            "__future__",
        }
        assert not third_party, (path, third_party)


def test_dev_tooling_pinned():
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    dev = project["optional-dependencies"]["dev"]
    assert dev and all(re.fullmatch(r"[A-Za-z0-9_.-]+==[0-9][0-9A-Za-z.]*", spec) for spec in dev)
    lock = [
        line
        for line in (PROJECT_ROOT / "requirements-dev.lock")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    ]
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]+==[0-9][0-9A-Za-z.]*", line) for line in lock)
    pins = dict(line.lower().split("==") for line in lock)
    for spec in dev:
        name, version = spec.lower().split("==")
        assert pins[name] == version


# -- NFR-004 --------------------------------------------------------------------------------
def test_core_never_references_terraform_or_docker_binaries():
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.lower()
                assert "docker" not in value, path
                assert not re.search(r"terraform(\.exe)?\s+-|terraform\.exe|/bin/terraform", value)
        assert not (imports_of(path) & {"subprocess", "shutil"}), path
