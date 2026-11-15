#!/usr/bin/env python3
"""Prepare one R8j physical-89 invocation; --execute runs the unchanged fixture.

Preparation only reads local files and calls the fixture's argument validator.
Both modes require the exact completed 30-test matrix and native build receipts.
The actual fixture retains its own 89-case denominator, deadlines and cleanup.
"""
import argparse
import importlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
import r8j_native_build_freeze as freeze

MATRIX_CASES = {
    "native-ha-capacity": 1,
    "native-ha-service-pipeline": 1,
    "native-ha-forward-precise": 1,
    "native-ha-service-install": 4,
    "native-auth": 18,
    "native-ha-objects-and-tls": 3,
    "native-migration-recovery": 2,
}


def bound_json(path, expected):
    freeze.require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None
                   and path.is_absolute() and path.resolve(strict=True) == path
                   and not path.is_symlink() and path.is_file()
                   and path.stat().st_uid == os.getuid() and not path.stat().st_mode & 0o077
                   and path.stat().st_size <= 64 * 1024
                   and freeze.digest(path) == expected, "receipt_file_binding_mismatch")
    return json.loads(path.read_bytes())


def verify_matrix(matrix):
    freeze.require(matrix.get("schema") == "heptabao.r8j-native-service-matrix.v1"
                   and matrix.get("source_commit") == freeze.COMMIT
                   and matrix.get("source_tree") == freeze.TREE
                   and matrix.get("source_files") == 2582
                   and matrix.get("source_unchanged_after_tests") is True
                   and matrix.get("host_abi") == "aarch64-apple-darwin"
                   and matrix.get("ok") is True, "r8j_matrix_not_complete_and_unchanged")
    cases = matrix.get("cases", [])
    freeze.require(len(cases) == len(MATRIX_CASES)
                   and {case.get("case") for case in cases} == set(MATRIX_CASES),
                   "r8j_matrix_case_set_mismatch")
    for case in cases:
        lines = case.get("summaries", [])
        pattern = (r"test result: ok\. " + str(MATRIX_CASES[case["case"]])
                   + r" passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;.*")
        freeze.require(type(case.get("exit_code")) is int and case["exit_code"] == 0
                       and len(lines) == 1 and re.fullmatch(pattern, lines[0]) is not None,
                       "r8j_matrix_count_or_outcome_mismatch")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "manifest", "matrix", "linux-build", "mac-build", "work-root", "plan-out"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("matrix-sha256", "linux-build-sha256", "mac-build-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--node", action="append", required=True,
                        help="alias,private-IP,NEW-absolute-root; Mac, ROG, Pocket4")
    parser.add_argument("--api-port", type=int, default=46230)
    parser.add_argument("--raft-port", type=int, default=46231)
    parser.add_argument("--mesh-local-port-base", type=int, default=55200)
    parser.add_argument("--mesh-reverse-port-base", type=int, default=55300)
    parser.add_argument("--mesh-api-port-base", type=int, default=55400)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--allow-private-lan", action="store_true")
    scope.add_argument("--allow-private-tailnet", action="store_true")
    parser.add_argument("--execute", action="store_true",
                        help="Execute this single prepared run after every local gate passes")
    args = parser.parse_args(argv)
    os.umask(0o077)
    source = freeze.canonical_directory(args.source_root)
    manifest = freeze.load_manifest(args.manifest)
    freeze.verify_source(source, manifest)
    matrix = bound_json(args.matrix, args.matrix_sha256)
    verify_matrix(matrix)
    linux = bound_json(args.linux_build, args.linux_build_sha256)
    mac = bound_json(args.mac_build, args.mac_build_sha256)
    sys.path.insert(0, str(source / "qa/openbao-acceptance"))
    fixture = importlib.import_module("native_v6_ha_multihost_live")
    freeze.require(len(fixture.REQUIRED_CHECKS) == 89
                   and fixture.REQUEST_SECONDS == 15
                   and fixture.NATIVE_ADMISSION_SECONDS == 8,
                   "native_fixture_contract_drift")
    for receipt, abi in ((linux, "x86_64-unknown-linux-gnu"),
                         (mac, "aarch64-apple-darwin")):
        actual = fixture.base.validate_build_receipt(
            receipt, freeze.COMMIT, freeze.TREE, receipt.get("binary_sha256"))
        freeze.require(actual == abi and receipt.get("source_manifest_sha256") == freeze.MANIFEST_SHA
                       and receipt.get("source_verified_before_and_after") is True
                       and receipt.get("binary_has_independent_inode") is True
                       and receipt.get("copied_binary_readback_verified") is True
                       and receipt.get("features") == [freeze.FEATURE]
                       and re.fullmatch(r"[0-9a-f]{64}", receipt["binary_sha256"]) is not None,
                       "native_r8j_freezer_receipt_incomplete")
    local_binary = Path(linux["binary_path"])
    freeze.require(local_binary.is_file() and not local_binary.is_symlink()
                   and local_binary.stat().st_uid == os.getuid()
                   and not local_binary.stat().st_mode & 0o022
                   and freeze.digest(local_binary) == linux["binary_sha256"],
                   "main_frozen_binary_changed")
    freeze.verify_binary_abi(local_binary, "x86_64-unknown-linux-gnu")
    aliases = [item.split(",", 1)[0] for item in args.node]
    freeze.require(len(aliases) == 3 and set(aliases) == {"macbook-pro", "rog", "pocket4"},
                   "exact_three_known_aliases_required")
    command = ["--source-commit", freeze.COMMIT, "--source-tree", freeze.TREE,
               "--binary-source", "local:" + linux["binary_path"],
               "--expected-binary-sha256", linux["binary_sha256"],
               "--work-root", str(args.work_root),
               "--allow-private-lan" if args.allow_private_lan else "--allow-private-tailnet"]
    for name in ("api-port", "raft-port", "mesh-local-port-base", "mesh-reverse-port-base", "mesh-api-port-base"):
        command += ["--" + name, str(getattr(args, name.replace("-", "_")))]
    for node in args.node:
        alias = node.split(",", 1)[0]
        receipt = mac if alias == "macbook-pro" else linux
        source_alias = "macbook-pro" if alias == "macbook-pro" else "local"
        # Receipt copies stay on the main controller. Their bound binary paths
        # continue to name the actual immutable file on its native build host.
        receipt_path = args.mac_build if alias == "macbook-pro" else args.linux_build
        receipt_sha = args.mac_build_sha256 if alias == "macbook-pro" else args.linux_build_sha256
        command += ["--node", node,
                    "--node-binary", ",".join((alias, source_alias + ":" + receipt["binary_path"],
                                               receipt["binary_sha256"], freeze.COMMIT, freeze.TREE)),
                    "--native-build-receipt", ",".join((alias, "local:" + str(receipt_path), receipt_sha))]
    # Pure checks: full argv grammar, distinct ports/private hosts, fresh local
    # work root, unchanged owned-PID/cipher scripts. No remote call or root mkdir.
    fixture.parsed_arguments(command)
    plan = {
        "schema": "heptabao.r8j-native-physical89-plan.v1", "status": "prepared",
        "source_commit": freeze.COMMIT, "source_tree": freeze.TREE,
        "matrix_sha256": args.matrix_sha256, "matrix_passed_tests": 30,
        "linux_build_receipt_sha256": args.linux_build_sha256,
        "mac_build_receipt_sha256": args.mac_build_sha256,
        "source_manifest_sha256": freeze.MANIFEST_SHA,
        "controller_template_sha256": freeze.digest(Path(__file__).resolve()),
        "fixture_path": str(source / "qa/openbao-acceptance/native_v6_ha_multihost_live.py"),
        "fixture_sha256": freeze.digest(source / "qa/openbao-acceptance/native_v6_ha_multihost_live.py"),
        "arguments": command, "physical_required_checks": 89,
        "physical_checks_executed_during_preparation": False,
        "backup_qualified": False, "production_cutover": False,
    }
    plan_bytes = freeze.json_bytes(plan)
    freeze.canonical_directory(args.plan_out.parent)
    freeze.require(args.plan_out.is_absolute()
                   and args.plan_out.parent.stat().st_uid == os.getuid()
                   and not args.plan_out.parent.stat().st_mode & 0o022,
                   "plan_parent_not_owned")
    if args.plan_out.exists() or args.plan_out.is_symlink():
        freeze.require(not args.plan_out.is_symlink() and args.plan_out.is_file()
                       and args.plan_out.stat().st_uid == os.getuid()
                       and not args.plan_out.stat().st_mode & 0o077
                       and args.plan_out.read_bytes() == plan_bytes, "existing_plan_differs")
    else:
        freeze.write_new(args.plan_out, plan_bytes)
    print(json.dumps({"status": "prepared", "plan": str(args.plan_out),
                      "plan_sha256": freeze.digest(args.plan_out),
                      "physical_execution_requested": args.execute,
                      "physical_pass_claimed": False}, sort_keys=True), flush=True)
    return fixture.main(command) if args.execute else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        code = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(json.dumps({"status": "blocked", "error": code,
                          "physical_pass_claimed": False}), file=sys.stderr)
        raise SystemExit(1)
