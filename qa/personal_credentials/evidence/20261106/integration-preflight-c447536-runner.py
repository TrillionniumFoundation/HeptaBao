#!/usr/bin/env python3
"""Isolated, synthetic Python preflight; never server/product qualification."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

SOURCE = "c447536ae0343731d84c18291d2dcd712b3bea08"
TREE = "50835fd4df6e7bdd2b551941a3fa012281c931c2"
BASE = "8f3dd8353aaf9642ad58f7716b0c14813d09983d"
WORK = Path("/home/qq/heptabao-integration-preflight-c447536-20261106-r1")
ORIGINAL = Path("/home/qq/heptabao-broker-ed25519-c447536")
PUBLIC_REPOSITORY = "https://github.com/TrillionniumFoundation/HeptaBao.git"
os.umask(0o077)
WORK.mkdir(mode=0o700)
REPO = WORK / "source"
REPORT = {
    "schema": "heptabao.personal-credentials.integration-preflight.v1",
    "started_unix_ns": time.time_ns(), "source_expected": SOURCE,
    "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "tree_expected": TREE, "synthetic_only": True,
    "production_qualified": False, "full_replacement_qualified": False,
    "server_executed": False, "android_exercised": False,
    "scope": "isolated_python_repository_and_acceptance_preflight",
    "commands": [],
}
ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", PYTHONDONTWRITEBYTECODE="1")

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def save():
    REPORT["updated_unix_ns"] = time.time_ns()
    out = WORK / "result.public.json"
    data = (json.dumps(REPORT, indent=2, sort_keys=True) + "\n").encode()
    with out.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def run(label, argv, *, cwd=None, timeout=180):
    record = {"label": label, "argv": list(map(str, argv)),
              "started_unix_ns": time.time_ns()}
    stdout = WORK / (label + ".stdout")
    stderr = WORK / (label + ".stderr")
    with stdout.open("wb") as o, stderr.open("wb") as e:
        try:
            p = subprocess.run(record["argv"], cwd=cwd, env=ENV,
                               stdout=o, stderr=e, timeout=timeout)
            record["exit_code"] = p.returncode
        except subprocess.TimeoutExpired:
            record["exit_code"] = None
            record["timed_out"] = True
    record.update(finished_unix_ns=time.time_ns(),
                  stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
    combined = stdout.read_text(errors="replace") + stderr.read_text(errors="replace")
    match = re.search(r"Ran (\d+) tests? in ([0-9.]+)s", combined)
    if match:
        record["unittest_count"] = int(match[1])
        record["unittest_elapsed_seconds"] = float(match[2])
        record["unittest_summary"] = [x for x in combined.splitlines()
                                       if x.startswith(("OK", "FAILED (", "ERROR:", "FAIL:"))]
    REPORT["commands"].append(record)
    save()
    print(json.dumps({k: record[k] for k in ("label", "exit_code", "unittest_count", "unittest_summary") if k in record}), flush=True)
    return record["exit_code"]

def source_state():
    head, tree = subprocess.check_output(["git", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=REPO, text=True).splitlines()
    return {"head": head, "tree": tree,
            "status_clean": not subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=REPO),
            "cargo_lock_sha256": sha(REPO / "Cargo.lock")}

try:
    assert run("clone-isolated", ["git", "clone", "--no-hardlinks", str(ORIGINAL), str(REPO)]) == 0
    assert run("checkout-frozen", ["git", "checkout", "--detach", SOURCE], cwd=REPO) == 0
    REPORT["source_before"] = source_state()
    assert REPORT["source_before"]["head"] == SOURCE and REPORT["source_before"]["tree"] == TREE and REPORT["source_before"]["status_clean"]
    shallow = subprocess.check_output(["git", "rev-parse", "--is-shallow-repository"], cwd=REPO, text=True).strip() == "true"
    fetch = ["git", "fetch", "--no-tags"]
    if shallow:
        fetch.append("--unshallow")
    fetch += [PUBLIC_REPOSITORY, BASE]
    run("fetch-real-published-history", fetch, cwd=REPO, timeout=150)
    pins = json.loads((REPO / "qa/openbao-acceptance/fixtures/postgres-schema-migration-sources-v1.json").read_text())
    REPORT["historical_ancestry"] = {}
    for name in ("schema55_generation", "schema56_root_rotation_statements"):
        pin = pins[name]
        p = subprocess.run(["git", "rev-parse", pin["commit"] + "^{tree}"], cwd=REPO, capture_output=True, text=True)
        ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", pin["commit"], SOURCE], cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        REPORT["historical_ancestry"][name] = {"commit": pin["commit"], "expected_tree": pin["tree"], "observed_tree": p.stdout.strip() if p.returncode == 0 else None, "exact_ancestor": ancestor}
    assert all(v["observed_tree"] == v["expected_tree"] and v["exact_ancestor"] for v in REPORT["historical_ancestry"].values()), "published_history_unavailable"
    venv = WORK / "venv"
    assert run("create-private-venv", [sys.executable, "-m", "venv", str(venv)]) == 0
    python = venv / "bin/python"
    assert run("install-declared-python-dependencies", [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--requirement", str(REPO / "requirements-plan.txt")], timeout=240) == 0
    gates = [
        ("verify-python", [str(python), "scripts/verify_python_environment.py"]),
        ("repository-validation", [str(python), "scripts/validate_repository_v2.py"]),
        ("module-closure", [str(python), "scripts/validate_module_closure.py"]),
        ("release-denominator", [str(python), "scripts/validate_openbao_271_release_denominator.py"]),
        ("surface-work", [str(python), "scripts/surface_work.py"]),
        ("repository-tests", [str(python), "-B", "-m", "unittest", "discover", "-s", "tests/repository", "-p", "test_*.py", "-v"]),
        ("acceptance-tests", [str(python), "-B", "-m", "unittest", "discover", "-s", "qa/openbao-acceptance/tests", "-p", "test_*.py", "-v"]),
        ("python-client-tests", [str(python), "-B", "-m", "unittest", "discover", "-s", "clients/python/tests", "-p", "test_*.py", "-v"]),
    ]
    results = [run(label, argv, cwd=REPO, timeout=240) for label, argv in gates]
    REPORT["source_after"] = source_state()
    assert REPORT["source_before"] == REPORT["source_after"], "source_changed"
    REPORT["result"] = "passed" if all(x == 0 for x in results) else "failed"
except Exception as error:
    REPORT["result"] = "failed"
    REPORT["error_class"] = type(error).__name__
    if isinstance(error, AssertionError):
        REPORT["error_code"] = str(error)[:100]
finally:
    REPORT["finished_unix_ns"] = time.time_ns()
    save()
    print(json.dumps({"result": REPORT["result"], "receipt": str(WORK / "result.public.json"), "sha256": sha(WORK / "result.public.json")}), flush=True)
sys.exit(0 if REPORT["result"] == "passed" else 1)
