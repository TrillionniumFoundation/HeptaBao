#!/usr/bin/env python3
"""Run the existing scoped acceptance against two real isolated TLS services."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess

import acceptance
from bao_http import BaoError, SafeArgumentParser, private_json, private_write
from official_openbao_launcher import file_digest, private_text, start_oracle, stop_oracle


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--candidate-source", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--build-log", type=Path, help="Operator-supplied build log to bind by digest")
    parser.add_argument("--oracle-port", type=int, default=28262)
    args = parser.parse_args(argv)
    root = args.work_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = args.candidate_source.resolve()
    source_sha = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True).strip())
    spec = importlib.util.spec_from_file_location("candidate_smoke", Path(__file__).resolve().parents[1] / "single-node/smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    oracle = instance = None
    old_mask = os.umask(0o077)
    try:
        oracle = start_oracle(args.oracle_port)
        instance = smoke.Instance(args.binary.resolve(), root / "candidate")
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise BaoError("candidate_initialization_failed")
        instance.token = initialized["root_token"]
        private_text(root / "candidate.token", instance.token)
        private_text(root / "candidate-unseal.key", initialized["keys_base64"][0])
        if instance.call("POST", "sys/unseal", {"key": initialized["keys_base64"][0]})[0] != 200:
            raise BaoError("candidate_unseal_failed")
        os.environ.update(HB_CANDIDATE_ADDR=instance.address, HB_CANDIDATE_CACERT=str(instance.root / "ca.crt"),
                          HB_CANDIDATE_TOKEN_FILE=str(root / "candidate.token"), HB_ORACLE_ADDR=oracle["address"],
                          HB_ORACLE_CACERT=oracle["ca_file"], HB_ORACLE_TOKEN_FILE=oracle["token_file"])
        for key in ("HB_CANDIDATE_TOKEN", "HB_CANDIDATE_NAMESPACE", "HB_ORACLE_TOKEN", "HB_ORACLE_NAMESPACE"):
            os.environ.pop(key, None)
        code = acceptance.main(["--compare", "--allow-test-writes", "--oracle-identity-file", oracle["identity_file"],
                                "--output", str(root / "comparison.json")])
        report = private_json(root / "comparison.json")
        report["execution_binding"] = {
            "candidate_binary_sha256": file_digest(args.binary), "candidate_source_sha": source_sha,
            "candidate_source_has_uncommitted_changes": dirty,
            "candidate_source_binding_basis": "operator_supplied_build_source_checkout",
            "runner_source_sha256": file_digest(__file__),
            "build_log_sha256": file_digest(args.build_log) if args.build_log else None,
            "official_oracle": private_json(oracle["identity_file"]),
        }
        private_write(root / "comparison-bound.json", report)
        print(json.dumps({"status": report["status"], "cases_match": report["cases_match"],
                          "mismatched_cases": report.get("mismatched_cases", []),
                          "output": str(root / "comparison-bound.json"),
                          "candidate_source_sha": source_sha, "candidate_source_dirty": dirty}))
        return code
    finally:
        if oracle is not None:
            stop_oracle(oracle)
        if instance is not None:
            instance.stop()
        os.umask(old_mask)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"status": "failed", "reason": "comparison_launcher_" + type(error).__name__}))
        raise SystemExit(2) from None
