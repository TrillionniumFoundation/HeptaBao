#!/usr/bin/env python3
"""Validate scoped snapshot timeout comparison; never grants release authority."""
import argparse
import hashlib
import json
from pathlib import Path


class AdmissionError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise AdmissionError(reason)


def is_sha256(s):
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def is_git_oid(s):
    return isinstance(s, str) and len(s) == 40 and all(c in "0123456789abcdef" for c in s)


def check_processes(report):
    processes = report.get("processes")
    require(isinstance(processes, list) and len(processes) >= 3, "missing real owned process lifecycle")
    require(all(isinstance(p, dict) and p.get("actual_process_closed") is True
                and isinstance(p.get("exit_code"), int) for p in processes), "unclosed owned process")
    require(report.get("cleanup_errors") == [], "cleanup not clean")


def check_case(report, expected_source, expected_binary):
    require(report.get("source_commit") == expected_source, "source HEAD differs")
    require(is_git_oid(report.get("source_tree")), "missing source tree")
    require(report.get("server_sha256") == expected_binary, "executable differs")
    require(report.get("versions") == 66 and report.get("payload_bytes_per_version") == 2097152,
            "large unique-history fixture not executed")
    require(report.get("fixture_payload_generation") ==
            "unique per-version SHAKE256 bytes encoded base64; no repeated-block capacity shortcut",
            "payload provenance changed")
    require(report.get("production_changed") is False and report.get("ha_qualified") is False,
            "unexpected production or HA claim")
    require(report.get("default_server_timeout_seconds") == 15, "default-budget source changed")
    require(is_sha256(report.get("archive_sha256")) and
            isinstance(report.get("archive_bytes"), int) and
            report["archive_bytes"] > 128 * 1024 * 1024, "physical archive missing or too small")
    require(isinstance(report.get("checks"), list) and report["checks"], "actual request checks missing")
    require(isinstance(report.get("expected_history_sha256"), dict) and
            len(report["expected_history_sha256"]) == 66 and
            all(is_sha256(report["expected_history_sha256"].get(str(v))) for v in range(1, 67)),
            "66 distinct historical digest expectations missing")
    check_processes(report)
    require(is_sha256(report.get("source_restored_manifest")) and
            is_sha256(report.get("target_seed_manifest")), "historical source/target custody missing")


def find_check(report, name):
    rows = [r for r in report["checks"] if r.get("name") == name]
    require(len(rows) == 1, "missing or duplicate request evidence: " + name)
    return rows[0]


def assess(red, green, failed_log, expected_source, expected_binary):
    require(is_sha256(expected_binary) and
            is_git_oid(expected_source),
            "invalid pinned candidate arguments")
    check_case(red, expected_source, expected_binary)
    check_case(green, expected_source, expected_binary)
    require(red.get("source_tree") == green.get("source_tree"), "source tree differs")
    require(red.get("server_timeout_overridden") is False, "red is not original default")
    require(red.get("passed") is False and red.get("failure") == "RemoteDisconnected",
            "original failed run missing or rewritten")
    require("HBHTTP-RESPONSE-WRITE-FAILURE io_kind=timed_out" in failed_log and
            "original_deadline_expired=true" in failed_log,
            "original deadline failure not captured")
    require(find_check(red, "target-ordinary-unseal").get("passed") is True,
            "red did not reach target import boundary")
    require(not any(r.get("name") == "actual-https-import-into-empty-external-target" and
                    r.get("passed") is True for r in red["checks"]),
            "default import was already acknowledged")
    require(green.get("server_timeout_overridden") is True and
            green.get("configured_server_timeout_seconds") == 30, "green lacks explicit 30 second config")
    require(green.get("passed") is True and green.get("functional_passed") is True,
            "configured green did not complete")
    require(len(green["checks"]) >= 550 and
            all(r.get("passed") is True for r in green["checks"]), "configured checks missing or failed")
    require(sum(1 for r in green["checks"] if r.get("name") ==
                "actual-https-import-into-empty-external-target") == 1, "duplicate import")
    imported = find_check(green, "actual-https-import-into-empty-external-target")
    elapsed = imported.get("elapsed_ms")
    require(imported.get("status") == 200 and isinstance(elapsed, int) and
            15000 < elapsed < 30000, "configured import result or timing not established")
    for name in ("target-cold-history-exact-66", "target-new-write-next-version",
                 "source-unchanged-during-target-recovery", "actual-source-sigkill-reaped",
                 "target-installed-real-v6"):
        require(find_check(green, name).get("passed") is True, "recovery proof missing: " + name)
    require(all(find_check(green, "target-cold-history-exact-"+str(v)).get("passed") is True
                for v in range(1, 67)), "cold history incomplete")
    require(green.get("failure") is None, "green reports a failure")
    return {
        "schema": "heptabao.snapshot.verified-explicit-budget.v1",
        "status": "SCOPED_CONFIGURED_PASS_DEFAULT_15S_HOLD",
        "source_commit": expected_source,
        "source_tree": red["source_tree"],
        "binary_sha256": expected_binary,
        "default_15s": {"passed": False, "failure": red["failure"], "deadline_log_verified": True},
        "configured_30s": {
            "passed": True, "import_status": 200, "import_elapsed_ms": elapsed,
            "archive_bytes": green["archive_bytes"], "archive_sha256": green["archive_sha256"],
            "checks_passed": len(green["checks"]), "history_versions": 66,
            "cold_reopen_and_new_version": True, "owned_processes_reaped": True
        },
        "production_cutover": False,
        "full_openbao271_replacement": False,
        "qualifications_not_proven": [
            "default 15 second large import", "release packaging and final integrated commit",
            "production authority migration", "HA, provider parity, and long duration fault recovery"
        ]
    }


def read_bounded(path, cap=1000000):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= cap,
            "unreadable or oversized evidence file")
    return path.read_bytes()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--default-receipt", type=Path, required=True)
    p.add_argument("--configured-receipt", type=Path, required=True)
    p.add_argument("--failed-server-log", type=Path, required=True)
    p.add_argument("--source-commit", required=True)
    p.add_argument("--server-sha256", required=True)
    a = p.parse_args()
    raw = [read_bounded(a.default_receipt), read_bounded(a.configured_receipt),
           read_bounded(a.failed_server_log, 100000)]
    try:
        report = assess(json.loads(raw[0]), json.loads(raw[1]), raw[2].decode(),
                        a.source_commit, a.server_sha256)
    except (AdmissionError, UnicodeDecodeError, json.JSONDecodeError) as e:
        p.exit(2, "NOT_ADMITTED: "+str(e)+"\n")
    report["inputs_sha256"] = {
        "default_receipt": hashlib.sha256(raw[0]).hexdigest(),
        "configured_receipt": hashlib.sha256(raw[1]).hexdigest(),
        "failed_server_log": hashlib.sha256(raw[2]).hexdigest()
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
