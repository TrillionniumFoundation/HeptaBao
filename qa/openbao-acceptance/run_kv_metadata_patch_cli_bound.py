#!/usr/bin/env python3
"""Exact-identity Linux operator for the fixed four-interface metadata CLI lane.

It executes one runner with a 120-second outer deadline and independently
audits its owned session and exact server executables/configuration roots.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from bao_http import SafeArgumentParser, private_read, private_write
from core_isolation import file_hash
import kv_metadata_patch_cli_live as profile

SCHEMA = "heptabao.kv-metadata-patch-cli-exact-binding.v1"
PINNED_LINUX_BINARY = "9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e"
PINNED_LINUX_ARCHIVE = "c3ab5de9e778223445487ccbfb16c291bf491642b688f3a3df5aeba23d9b3667"
QA_FILES = ("qa/openbao-acceptance/kv_metadata_patch_cli_live.py",
            "qa/openbao-acceptance/run_kv_metadata_patch_cli_bound.py",
            "qa/openbao-acceptance/kv_metadata_patch_cli_cases.json",
            "qa/openbao-acceptance/official_openbao_launcher.py", "qa/openbao-acceptance/bao_http.py",
            "qa/openbao-acceptance/online_evidence.py", "qa/openbao-acceptance/core_isolation.py", "qa/single-node/smoke.py",
            "clients/python/heptabao/transport.py")


def identity(qa_root, cli_root, candidate_root, binary, receipt, oracle, archive):
    return {"qa_source": profile.git_identity(qa_root), "cli_source": profile.cli_identity(cli_root),
            "candidate_source": profile.git_identity(candidate_root),
            "qa_files_sha256": {name: file_hash(qa_root / name) for name in QA_FILES},
            "candidate_binary_sha256": file_hash(binary), "candidate_build_receipt_sha256": file_hash(receipt),
            "oracle_binary_sha256": file_hash(oracle), "oracle_archive_sha256": file_hash(archive)}


def validate_binding(binding, actual, custody):
    if not isinstance(binding, dict) or binding.get("schema") != SCHEMA:
        raise ValueError("binding_schema_invalid")
    if (binding.get("identity") != actual or any(actual[name]["source_dirty"] for name in ("qa_source", "cli_source", "candidate_source"))
            or binding.get("expected_interfaces") != list(profile.INTERFACES)
            or binding.get("expected_cases_per_interface") != list(profile.REQUIRED_INTERFACE_CASES)
            or binding.get("expected_checks") != 64
            or binding.get("budgets_seconds") != {"all_http": 2, "command": 10, "outer": 120}
            or any(type(value) is not int for value in binding["budgets_seconds"].values())
            or actual["oracle_binary_sha256"] != PINNED_LINUX_BINARY or actual["oracle_archive_sha256"] != PINNED_LINUX_ARCHIVE
            or custody["source_identity"] != actual["candidate_source"]
            or custody["binary_sha256"] != actual["candidate_binary_sha256"]
            or custody["receipt_sha256"] != actual["candidate_build_receipt_sha256"]):
        raise ValueError("exact_binding_mismatch")


def run_owned(command, cwd, environment, log_path):
    forced = []
    with log_path.open("xb") as log:
        child = subprocess.Popen(command, cwd=cwd, env=environment, stdout=log, stderr=log, start_new_session=True)
        try:
            code = child.wait(timeout=profile.OUTER_SECONDS)
        except subprocess.TimeoutExpired:
            forced.append("outer_deadline_sigterm")
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                forced.append("outer_deadline_sigkill")
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            code = 124
    return code, child.pid, forced


def owned_session(session_id, proc=Path("/proc")):
    found = []
    for entry in proc.iterdir():
        if entry.name.isdigit():
            try:
                if int((entry / "stat").read_text().rsplit(")", 1)[1].split()[3]) == session_id:
                    found.append(int(entry.name))
            except (OSError, ValueError, IndexError):
                pass
    return sorted(found)


def owned_fixtures(output, binaries, proc=Path("/proc")):
    found = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "exe").resolve(strict=True) not in binaries:
                continue
            arguments = (entry / "cmdline").read_bytes().split(b"\0")
            configurations = []
            for index, argument in enumerate(arguments):
                if argument == b"--config" and index + 1 < len(arguments):
                    configurations.append(os.fsdecode(arguments[index + 1]))
                if argument.startswith(b"-config="):
                    configurations.append(os.fsdecode(argument[len(b"-config="):]))
            if any(Path(value).is_relative_to(output) for value in configurations):
                found.append(int(entry.name))
        except (OSError, ValueError):
            pass
    return sorted(found)


def report_complete(report, actual, custody):
    return (isinstance(report, dict) and report.get("schema") == "heptabao.kv-metadata-patch-cli-live.v1"
            and report.get("status") == "passed" and report.get("expected_checks") == 64
            and report.get("all_fixed_interfaces_complete") is True
            and profile.all_interfaces_complete(report.get("interfaces"))
            and report.get("all_owned_stopped") is True and report.get("forced_cleanup_exit_signals") == []
            and report.get("source_and_binary_unchanged") is True
            and report.get("qa_source_before") == actual["qa_source"] == report.get("qa_source_after")
            and report.get("cli_source_before") == actual["cli_source"] == report.get("cli_source_after")
            and report.get("candidate_build_custody") == custody == report.get("candidate_build_custody_after")
            and report.get("runner_sha256") == actual["qa_files_sha256"][QA_FILES[0]]
            and report.get("checkset_sha256") == actual["qa_files_sha256"][QA_FILES[2]]
            and report.get("oracle_cli_sha256") == actual["oracle_binary_sha256"] and report.get("oracle_version") == "2.7.0"
            and report.get("http_seconds") == 2 and report.get("command_seconds") == 10 and report.get("outer_seconds") == 120
            and report.get("all_http_clients_exact_budget") is True
            and isinstance(report.get("client_budget_seconds_observed"), list)
            and len(report["client_budget_seconds_observed"]) >= 4
            and all(type(value) is int and value == 2 for value in report["client_budget_seconds_observed"])
            and report.get("requested_stdout_saved") is False and report.get("credentials_saved_in_report") is False)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    for name in ("qa-source", "cli-source", "candidate-source", "binary", "build-receipt", "oracle-binary", "oracle-archive",
                 "python", "operator-root", "label", "binding-manifest"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux") or not re.fullmatch("[a-z0-9-]{1,64}", args.label):
        parser.error("Linux owner audit and a fixed safe label are required")
    os.umask(0o077)
    qa_root, cli_root, candidate_root, binary, oracle, archive = (Path(value).resolve(strict=True) for value in
        (args.qa_source, args.cli_source, args.candidate_source, args.binary, args.oracle_binary, args.oracle_archive))
    receipt_path = Path(args.build_receipt).absolute()
    if qa_root != Path(__file__).resolve().parents[2]:
        raise ValueError("operator_qa_source_mismatch")
    operator_root = Path(args.operator_root).resolve(strict=True)
    output = operator_root / "artifacts" / args.label
    output.parent.mkdir(mode=0o700, exist_ok=True); output.mkdir(mode=0o700)
    fixture_parent = output / "privatefixtures"; fixture_parent.mkdir(mode=0o700)
    binding_raw = private_read(args.binding_manifest, 128 * 1024)
    binding = json.loads(binding_raw)
    before = identity(qa_root, cli_root, candidate_root, binary, receipt_path, oracle, archive)
    custody = profile.build_custody(binary, receipt_path, candidate_root)
    validate_binding(binding, before, custody)
    environment = {name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL", "TZ") if name in os.environ}
    environment.update({"HB_ORACLE_BINARY": str(oracle), "HB_ORACLE_ARCHIVE": str(archive),
                        "HB_ORACLE_WORK_ROOT": str(fixture_parent), "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONPATH": str(qa_root / "qa/openbao-acceptance")})
    command = [args.python, "-B", "-W", "error", str(qa_root / QA_FILES[0]), "--binary", str(binary),
               "--build-receipt", str(receipt_path), "--candidate-source", str(candidate_root),
               "--cli-source", str(cli_root), "--output", str(output / "report.json")]
    started = time.monotonic()
    code, session, forced = run_owned(command, qa_root, environment, output / "run.log")
    session_remaining = owned_session(session)
    fixture_remaining = owned_fixtures(output, (binary, oracle))
    report_path = output / "report.json"
    try:
        report = json.loads(private_read(report_path, 2 * 1024 * 1024))
    except Exception:
        report = {}
    try:
        after = identity(qa_root, cli_root, candidate_root, binary, receipt_path, oracle, archive)
    except Exception as error:
        after = {"identity_error": type(error).__name__}
    complete = (code == 0 and not forced and not session_remaining and not fixture_remaining
                and before == after and report_complete(report, before, custody))
    receipt = {"schema": "heptabao.kv-metadata-patch-cli-bound-operator.v1", "identity_before": before,
               "identity_after": after, "binding_manifest_sha256": file_hash(Path(args.binding_manifest)),
               "expected_checks": 64, "http_seconds": 2, "command_seconds": 10, "outer_seconds": 120,
               "runner_exit": code, "elapsed_seconds": time.monotonic() - started, "all_checks_complete": complete,
               "owned_session_id": session, "owned_session_remaining": session_remaining,
               "owned_fixture_remaining": fixture_remaining, "forced_cleanup": forced,
               "run_log_sha256": file_hash(output / "run.log"),
               "report_sha256": file_hash(report_path) if report_path.exists() else None,
               "runtime_qualification_claim": False, "production_authority": False,
               "requested_stdout_saved": False, "requested_stdout_digest_saved": False, "credentials_saved_in_report": False}
    private_write(output / "receipt.json", receipt, replace=False)
    print(json.dumps({"label": args.label, "runner_exit": code, "all_checks_complete": complete,
                      "status": report.get("status"), "failure": report.get("failure"),
                      "interfaces": {name: len(rows) for name, rows in report.get("interfaces", {}).items()},
                      "owned_session_remaining": session_remaining, "owned_fixture_remaining": fixture_remaining,
                      "forced_cleanup": forced}))
    return 0 if complete else (code if code else 1)


if __name__ == "__main__":
    raise SystemExit(main())
