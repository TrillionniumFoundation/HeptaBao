#!/usr/bin/env python3
"""Record fresh local-only v3 validation; no Runtime, SSH, or host scan."""
from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "local-r8-evidence"
FREEZE_NAME = "authbus-migration-gap-v3-r1-freeze.json"
ARTIFACTS = (
    "authbus_migration_gap_inventory_v3.py", "authbus_migration_gap_allowlist_v3.json",
    "authbus_migration_gap_source_receipts_v3.json", "authbus_migration_gap_schema_v3.json",
    "authbus_migration_gap_inventory_v3_tests.py", "run_authbus_migration_gap_v3_r1.py",
    "run_authbus_migration_gap_v3_r1_tests.py", "authbus_migration_gap_v3_provenance_tests.py",
    "rebuild_authbus_migration_gap_v3.py", "freeze_authbus_migration_gap_v3.py",
    "authbus_migration_gap_v3.README.md",
)
SUITES = (
    ("authbus_migration_gap_inventory_v3_tests.py", 14, "authbus-migration-gap-v3-r1-scanner-tests.log"),
    ("run_authbus_migration_gap_v3_r1_tests.py", 12, "authbus-migration-gap-v3-r1-controller-tests.log"),
    ("authbus_migration_gap_v3_provenance_tests.py", 2, "authbus-migration-gap-v3-r1-provenance-tests.log"),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def info(path):
    raw = path.read_bytes()
    return {"name": path.name, "bytes": len(raw), "sha256": sha(raw)}


def write_new(name, raw):
    fd = os.open(str(EVIDENCE / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return info(EVIDENCE / name)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def main():
    EVIDENCE.mkdir(exist_ok=True)
    if (EVIDENCE / FREEZE_NAME).exists():
        raise RuntimeError("Existing freeze is not overwritten or replayed")
    created_at = datetime.now(timezone.utc).isoformat()
    before = [info(HERE / name) for name in ARTIFACTS]
    for name in ARTIFACTS:
        if name.endswith(".py"):
            ast.parse((HERE / name).read_text(), feature_version=(3, 9))
    controller = module("freeze_authbus_gap_v3_controller", HERE / "run_authbus_migration_gap_v3_r1.py")
    source = (HERE / controller.SCANNER_NAME).read_bytes()
    plan = controller.extract_plan(source)
    assert plan == json.loads((HERE / "authbus_migration_gap_allowlist_v3.json").read_bytes())
    assert plan["source_receipt_set"] == json.loads((HERE / "authbus_migration_gap_source_receipts_v3.json").read_bytes())
    source_receipts = []
    for item in plan["source_receipt_set"]["receipts"]:
        observed = info(EVIDENCE / item["name"])
        assert observed["bytes"] == item["bytes"] and observed["sha256"] == item["sha256"]
        source_receipts.append(observed)
    validation = []
    for name, expected_count, log_name in SUITES:
        argv = [sys.executable, "-I", "-B", str(HERE / name)]
        started = datetime.now(timezone.utc).isoformat()
        result = subprocess.run(argv, cwd=str(HERE), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        observed = re.search(rb"\nRan (\d+) tests? in ", result.stdout)
        passed = result.returncode == 0 and observed and int(observed.group(1)) == expected_count and result.stdout.rstrip().endswith(b"OK")
        log = write_new(log_name, result.stdout)
        validation.append({"test_file": name, "argv": argv, "started_at": started,
                           "finished_at": datetime.now(timezone.utc).isoformat(), "exit_code": result.returncode,
                           "tests": int(observed.group(1)) if observed else None, "passed": bool(passed), "log": log})
        if not passed:
            raise RuntimeError("local_test_suite_failed:" + name)
    planned_result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "run_authbus_migration_gap_v3_r1.py")],
                                    cwd=str(HERE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    assert planned_result.returncode == 0 and not planned_result.stderr
    planned = json.loads(planned_result.stdout)
    assert planned == controller.execution_plan(source, plan)
    plan_log = write_new("authbus-migration-gap-v3-r1-plan-only.json", planned_result.stdout)
    schema = json.loads((HERE / "authbus_migration_gap_schema_v3.json").read_bytes())
    assert schema["properties"]["schema"]["const"] == controller.RECEIPT_SCHEMA
    schema_engine = {"status": "not_run_package_unavailable", "package": "jsonschema", "schema_json_parse_passed": True}
    if importlib.util.find_spec("jsonschema") is not None:
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(schema)
        tests = module("freeze_authbus_gap_v3_controller_tests", HERE / "run_authbus_migration_gap_v3_r1_tests.py")
        validator = jsonschema.Draft202012Validator(schema)
        for host, unused in controller.HOSTS:
            validator.validate(tests.synthetic_receipt(host))
        schema_engine = {"status": "passed", "package": "jsonschema", "schema_json_parse_passed": True,
                         "metaschema_checked": True, "synthetic_receipts_validated": 4, "real_hosts_scanned": 0}
    after = [info(HERE / name) for name in ARTIFACTS]
    assert before == after, "source_changed_during_freeze"
    freeze = {
        "schema": "authbus-migration-gap-local-freeze-v3-r1", "created_at": created_at,
        "completed_at": datetime.now(timezone.utc).isoformat(), "new_version": True,
        "original_v2_plan_recovered": False, "original_migration_manifest_recovered": False,
        "local_only": True, "real_hosts_scanned": 0, "runtime_called": False, "ssh_called": False,
        "credential_payloads_read": False, "production_mutation": False,
        "artifacts": after, "source_receipts": source_receipts,
        "allowlist_canonical_sha256": controller.PLAN_SHA256,
        "source_receipt_set_sha256": controller.SOURCE_RECEIPT_SET_SHA256,
        "tests_passed": sum(item["tests"] for item in validation), "test_suites": validation,
        "plan_only": {"exit_code": planned_result.returncode, "remote_called": False, "receipt": plan_log},
        "python39_ast_parse_passed": True, "schema_engine_validation": schema_engine,
        "known_v2_changes": ["New path/source authority reconstructed from four verified public receipts", "All environment values omitted; field names only", "Actual returned read bytes charged before checking original deadline"],
        "scope_counts": {key: sum(len(h[key]) for h in plan["hosts"].values()) for key in ("secretrefs", "backup_runtime", "binding_files", "missing_agents", "relay_startups", "relay_dependencies")},
        "qualification": controller.QUALIFICATION,
    }
    receipt = write_new(FREEZE_NAME, json.dumps(freeze, sort_keys=True, ensure_ascii=False, indent=2).encode() + b"\n")
    print(json.dumps({"freeze": receipt, "tests_passed": freeze["tests_passed"], "real_hosts_scanned": 0,
                      "scanner": info(HERE / controller.SCANNER_NAME), "controller": info(HERE / "run_authbus_migration_gap_v3_r1.py"),
                      "qualification": controller.QUALIFICATION}, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
