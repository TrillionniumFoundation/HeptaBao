"""Retain one local guard-suite observation; never launches a product service."""
from pathlib import Path
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[4]
OUT = Path(__file__).resolve().parent
MODULES = ["test_ci_lifecycle_regressions", "test_ha_destructive", "test_radius_renewal_live",
           "test_kubernetes_renewal_live", "test_official_oracle_versions", "test_raft_snapshot_observation"]
SOURCES = ["ha_destructive.py", "official_openbao_launcher.py", "renewal_cleanup.py",
           "radius_renewal_live.py", "kubernetes_renewal_live.py", "raft_membership_live.py",
           "raft_snapshot_upgrade.py"]
QA = ROOT / "qa/openbao-acceptance"
FILES = [QA / name for name in SOURCES] + [QA / "tests" / (name + ".py") for name in MODULES]


def pins():
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in FILES}


if __name__ == "__main__":
    label = sys.argv[1] if len(sys.argv) == 2 else "r1"
    if re.fullmatch(r"r[1-9][0-9]*", label) is None:
        raise SystemExit("closed run label required")
    os.umask(0o077)
    os.chdir(ROOT)
    sys.path[:0] = [str(QA), str(QA / "tests")]
    before = pins()
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    expected = suite.countTestCases()
    started = time.monotonic()
    log_path = OUT / ("selected-guards-" + label + ".log")
    with log_path.open("x") as log, contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
        outcome = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    unchanged = before == pins()
    passed = (outcome.wasSuccessful() and outcome.testsRun == expected and not outcome.skipped
              and not outcome.expectedFailures and unchanged)
    log_bytes = log_path.read_bytes()
    report = {"schema": "heptabao.ci-harness-local-regressions.v1",
              "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "selected_modules": MODULES, "expected_methods": expected,
              "executed_methods": outcome.testsRun, "failures": len(outcome.failures),
              "errors": len(outcome.errors), "skipped": len(outcome.skipped),
              "expected_failures": len(outcome.expectedFailures),
              "seconds": time.monotonic() - started, "source_file_pins": before,
              "source_files_unchanged": unchanged,
              "log": str(log_path.relative_to(ROOT)), "log_bytes": len(log_bytes),
              "log_sha256": hashlib.sha256(log_bytes).hexdigest(),
              "status": "passed" if passed else "failed",
              "product_services_started": False, "ci_rerun": False,
              "live_protocol_qualification": False, "production_authority": False,
              "business_denominators_changed": False,
              "run_label": label,
              "reason_for_selected_suite": "Concrete QA exit-contract and binary-response fixes plus existing directly affected guards; r2 adds failed-wait handle retention and exact legacy/current transport distinction. No product or remote run."}
    with (OUT / ("selected-guards-" + label + ".json")).open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True); stream.write("\n")
    print(json.dumps({key: report[key] for key in ("status", "executed_methods", "failures", "errors", "skipped", "log_sha256")}))
    raise SystemExit(0 if passed else 1)
