#!/usr/bin/env python3
"""Run the existing scoped acceptance against two real isolated TLS services."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import hashlib
import argparse
import socket

_preparser = argparse.ArgumentParser(add_help=False)
_preparser.add_argument("--candidate-source", type=Path, required=True)
_preargs, _ = _preparser.parse_known_args()
sys.path.insert(0, str(_preargs.candidate_source.resolve() / "qa/openbao-acceptance"))

import acceptance
from bao_http import BaoError, Client, SafeArgumentParser, private_json, private_read, private_write
from official_openbao_launcher import (SUPPORTED_VERSIONS, VERSION, file_digest, private_text,
                                      start_oracle, stop_oracle, verify_selected_oracle)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--candidate-source", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--build-log", type=Path, help="Operator-supplied build log to bind by digest")
    parser.add_argument(
        "--modules",
        default="core,kv,token,transit,pki,totp,userpass,approle,identity,wrapping,edge_tls,system,operations",
        help="Comma-separated acceptance modules; default preserves the bounded baseline",
    )
    parser.add_argument("--oracle-port", type=int, default=0)
    parser.add_argument("--oracle-version", choices=SUPPORTED_VERSIONS, default="2.7.1")
    args = parser.parse_args(argv)
    root = args.work_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = args.candidate_source.resolve()
    source_sha = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True).strip())
    if source_sha != args.expected_source_commit or dirty:
        raise BaoError("candidate_source_binding_mismatch")
    if file_digest(args.binary) != args.expected_binary_sha256 or args.oracle_version != "2.7.1":
        raise BaoError("candidate_artifact_or_oracle_version_mismatch")
    spec = importlib.util.spec_from_file_location("candidate_smoke", source / "qa/single-node/smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    oracle = instance = None
    old_mask = os.umask(0o077)
    old_oracle_root = os.environ.get("HB_ORACLE_WORK_ROOT")
    os.environ["HB_ORACLE_WORK_ROOT"] = str(root)
    native_capacity = None
    report = None
    helpers = source / "qa/openbao-acceptance"
    if Path(acceptance.__file__).resolve() != helpers / "acceptance.py":
        raise BaoError("acceptance_module_source_mismatch")
    helper_files = sorted(helpers.rglob("*.py"))
    helper_hashes = {str(p.relative_to(source)): file_digest(p) for p in helper_files}
    try:
        oracle_port = args.oracle_port
        if oracle_port == 0:
            with socket.socket() as selected_socket:
                selected_socket.bind(("127.0.0.1", 0))
                oracle_port = selected_socket.getsockname()[1]
        oracle = start_oracle(oracle_port, version=args.oracle_version)
        reference = Client(oracle["address"], oracle["ca_file"],
                           private_read(oracle["token_file"]).decode("ascii").strip())
        oracle_identity = verify_selected_oracle(oracle, reference.health(), version=args.oracle_version)
        instance = smoke.Instance(args.binary.resolve(), root / "candidate")
        config_path = instance.root / "server.json"
        config = private_json(config_path)
        if "storage" in config:
            raise BaoError("candidate_storage_already_selected")
        config["storage"] = {"native_v6_file": {"path": config["data_dir"]}}
        replacement = instance.root / "native-server.json"
        with replacement.open("x") as stream:
            json.dump(config, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(replacement, config_path)
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise BaoError("candidate_initialization_failed")
        instance.token = initialized["root_token"]
        private_text(root / "candidate.token", instance.token)
        private_text(root / "candidate-unseal.key", initialized["keys_base64"][0])
        if instance.call("POST", "sys/unseal", {"key": initialized["keys_base64"][0]})[0] != 200:
            raise BaoError("candidate_unseal_failed")
        if instance.call("POST", "sys/storage/native-v6/activate", {})[0] != 204:
            raise BaoError("candidate_native_activation_failed")
        capacity_status, native_capacity = instance.call("GET", "sys/internal/capacity")
        if capacity_status != 200:
            raise BaoError("candidate_native_capacity_unavailable")
        os.environ.update(HB_CANDIDATE_ADDR=instance.address, HB_CANDIDATE_CACERT=str(instance.root / "ca.crt"),
                          HB_CANDIDATE_TOKEN_FILE=str(root / "candidate.token"), HB_ORACLE_ADDR=oracle["address"],
                          HB_ORACLE_CACERT=oracle["ca_file"], HB_ORACLE_TOKEN_FILE=oracle["token_file"])
        for key in ("HB_CANDIDATE_TOKEN", "HB_CANDIDATE_NAMESPACE", "HB_ORACLE_TOKEN", "HB_ORACLE_NAMESPACE"):
            os.environ.pop(key, None)
        code = acceptance.main(
            [
                "--compare",
                "--allow-test-writes",
                "--modules",
                args.modules,
                "--oracle-identity-file",
                oracle["identity_file"],
                "--oracle-version",
                args.oracle_version,
                "--output",
                str(root / "comparison.json"),
            ]
        )
        report = private_json(root / "comparison.json")
        after_sha = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        after_dirty = bool(subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True).strip())
        if after_sha != source_sha or after_dirty or file_digest(args.binary) != args.expected_binary_sha256 or helper_hashes != {str(p.relative_to(source)): file_digest(p) for p in helper_files}:
            raise BaoError("candidate_source_or_artifact_changed")
        report["source_and_binary_unchanged"] = True
        report["scenario_files_sha256"] = helper_hashes
        report["native_storage"] = {"profile": "native_v6_file", "activation_status": 204,
                                    "fixture_options": False, "initial_capacity": native_capacity}
        report["execution_binding"] = {
            "candidate_binary_sha256": file_digest(args.binary), "candidate_source_sha": source_sha,
            "candidate_source_has_uncommitted_changes": dirty,
            "candidate_source_binding_basis": "operator_supplied_build_source_checkout",
            "runner_source_sha256": file_digest(__file__),
            "build_log_sha256": file_digest(args.build_log) if args.build_log else None,
            "official_oracle": oracle_identity,
        }
        private_write(root / "comparison-bound.json", report)
        print(json.dumps({"status": report["status"], "cases_match": report["cases_match"],
                          "mismatched_cases": report.get("mismatched_cases", []),
                          "output": str(root / "comparison-bound.json"),
                          "oracle_version": args.oracle_version,
                          "oracle_storage_backend": oracle_identity["storage"],
                          "candidate_source_sha": source_sha, "candidate_source_dirty": dirty}))
        return code
    finally:
        cleanup_errors = []
        for name, value, stop in (("oracle", oracle, stop_oracle), ("candidate", instance, lambda item: item.stop())):
            if value is not None:
                try:
                    stop(value)
                except Exception as error:
                    cleanup_errors.append({"owner": name, "error_type": type(error).__name__})
        if report is not None:
            report["owned_cleanup_completed"] = not cleanup_errors
            report["cleanup_errors"] = cleanup_errors
            if cleanup_errors:
                report["status"] = "failed_cleanup"
            private_write(root / "comparison-bound.json", report)
        if old_oracle_root is None:
            os.environ.pop("HB_ORACLE_WORK_ROOT", None)
        else:
            os.environ["HB_ORACLE_WORK_ROOT"] = old_oracle_root
        os.umask(old_mask)
        if cleanup_errors:
            raise BaoError("owned_cleanup_failed")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"status": "failed", "reason": "comparison_launcher_" + type(error).__name__}))
        raise SystemExit(2) from None

