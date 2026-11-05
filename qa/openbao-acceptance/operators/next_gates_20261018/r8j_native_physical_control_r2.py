#!/usr/bin/env python3
"""Plan by default; --execute runs physical89 with a separately pinned QA overlay.

The original 2,582-file R8j source, 30-test matrix, native ABI receipts and
binary digests remain mandatory. The QA directory is NOT that source tree.
No build, source edit, retry or production cutover is performed here.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True

FREEZER_SHA256 = "1f90af9625d8efedf8e15ff42fed599f38b1b068ad968679012dd229b5453e84"
PARENT_CONTROLLER_SHA256 = "3cd7c522faf091d7fdbd449641b1c45de4f10b9a07661862a3c6a34eeca9f997"
ORIGINAL_HARNESS_SHA256 = "2f0e3ecf3641262d6fac97166e3b41bdaacd3eebc61fe006c560faa7440cb254"
CHECK_SET_SHA256 = "b8d323c25c8f9f17eb86be2527778b5ac774eb4495d5b6f98ce61c5c8017d670"
MATRIX_SHA256 = "114e38e56a108f24f58b6d6737f8be3077e98ef75bc692fc4dfe1d8bca0367dc"
QA_FILES = {
    "qa/openbao-acceptance/native_v6_ha_multihost_live.py":
        "ca909ec0d8c70954a369ff2d6875094d1e4b8bf0d06d1bb589114b5c56203727",
    "qa/openbao-acceptance/ha_multihost_live.py":
        "7857f62b1e9e46b7d718eb401e6ed75bb48dc9db385327a5cb86bda30c587858",
    "qa/openbao-acceptance/ha_three_host_loopback_live.py":
        "77ceaf2a851ae17bc7cd83b6c2b60e66ed37cd33177e615acdfa56c6b3ed12cf",
    "qa/openbao-acceptance/fixture_mounts.py":
        "55075ee436c22816a176dfb06cec387df37fdadd581c16acc07dabc837ba85b5",
    "tools/physical_ha_loopback_mesh.py":
        "dfff07d56e0e6cd646b3ae003e9123d6506e651dd55bed19b972fafed9a26493",
    "tools/physical_ha_peer_preflight.py":
        "701f432144677e30400937e9407832fa63c3ef05e425bb50216c1cd48a206227",
}
QA_MODULES = (
    ("physical_ha_peer_preflight", "tools/physical_ha_peer_preflight.py"),
    ("physical_ha_loopback_mesh", "tools/physical_ha_loopback_mesh.py"),
    ("fixture_mounts", "qa/openbao-acceptance/fixture_mounts.py"),
    ("ha_multihost_live", "qa/openbao-acceptance/ha_multihost_live.py"),
    ("ha_three_host_loopback_live", "qa/openbao-acceptance/ha_three_host_loopback_live.py"),
    ("native_v6_ha_multihost_live", "qa/openbao-acceptance/native_v6_ha_multihost_live.py"),
)
BUILD_BINDINGS = {
    "x86_64-unknown-linux-gnu": {
        "receipt_sha256": "fbe3ef1de04e732e3a36188a464d0814701300c49ded087abba4e45a2ed05509",
        "binary_sha256": "c0821bae2a8435eddea8506311a09cd3e1f0533948b8489f1e606e210a073560",
        "binary_path": "/home/qian-qi/heptabao-next-gates-20261017/native-r8j-linux-freeze-01/heptabao-server",
    },
    "aarch64-apple-darwin": {
        "receipt_sha256": "76f186ac9aee20646ecb6bea47cb5c3685f4b746329351e8e707934d6cc58a88",
        "binary_sha256": "64b88fd098cfe80c92a2462ab8609b84b98145f3ac5955e14fc3911a8c7a18c0",
        "binary_path": "/Volumes/T5/hepta-vnext-recovery-20261013/v6-next-gates-20261017/native-r8j-mac-freeze-01/heptabao-server",
    },
}
NODE_ROOTS = {
    "macbook-pro": "/Volumes/T5/hepta-vnext-recovery-20261013/native-r8j-physical89-02-node1",
    "rog": "/home/qian-qi/heptabao-native-r8j-physical89-02-node2",
    "pocket4": "/home/alex/heptabao-native-r8j-physical89-02-node3",
}
MATRIX_CASES = {
    "native-ha-capacity": 1, "native-ha-service-pipeline": 1,
    "native-ha-forward-precise": 1, "native-ha-service-install": 4,
    "native-auth": 18, "native-ha-objects-and-tls": 3,
    "native-migration-recovery": 2,
}


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def pinned_bytes(path, expected, maximum=1024 * 1024):
    require(path.is_absolute() and path.resolve(strict=True) == path
            and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
            "pinned_file_path_or_digest_invalid")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and before.st_nlink == 1
                and before.st_size <= maximum, "pinned_file_owner_or_shape")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        require(identity(before) == identity(after) == identity(path.lstat())
                and len(raw) == before.st_size
                and hashlib.sha256(raw).hexdigest() == expected,
                "pinned_file_bytes_changed")
        return raw
    finally:
        os.close(descriptor)


def module_from_bytes(name, path, raw):
    require(name not in sys.modules, "pinned_module_already_loaded")
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_freezer():
    path = Path(__file__).resolve(strict=True).parent / "r8j_native_build_freeze.py"
    return module_from_bytes("_r8j_physical_r2_freezer", path,
                             pinned_bytes(path, FREEZER_SHA256))


def bound_json(path, expected, freeze):
    raw = pinned_bytes(path, expected, 64 * 1024)
    require(not path.stat().st_mode & 0o077, "receipt_file_not_private")
    return json.loads(raw)


def verify_matrix(matrix, freeze):
    require(matrix.get("schema") == "heptabao.r8j-native-service-matrix.v1"
            and matrix.get("source_commit") == freeze.COMMIT
            and matrix.get("source_tree") == freeze.TREE
            and matrix.get("source_files") == 2582
            and matrix.get("source_unchanged_after_tests") is True
            and matrix.get("host_abi") == "aarch64-apple-darwin"
            and matrix.get("ok") is True, "r8j_matrix_not_complete_and_unchanged")
    cases = matrix.get("cases", [])
    require(len(cases) == len(MATRIX_CASES)
            and {case.get("case") for case in cases} == set(MATRIX_CASES),
            "r8j_matrix_case_set_mismatch")
    for case in cases:
        lines = case.get("summaries", [])
        pattern = (r"test result: ok\. " + str(MATRIX_CASES[case["case"]])
                   + r" passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;.*")
        require(type(case.get("exit_code")) is int and case["exit_code"] == 0
                and len(lines) == 1 and re.fullmatch(pattern, lines[0]) is not None,
                "r8j_matrix_count_or_outcome_mismatch")


def verify_qa(root, source, manifest, freeze):
    freeze.canonical_directory(root)
    require(root != source and root not in source.parents and source not in root.parents,
            "qa_overlay_must_be_separate_from_binary_source")
    require(root.name == "native-r8j-physical89-02-qa",
            "qa_overlay_must_name_attempt_02")
    allowed_dirs = {"qa", "qa/openbao-acceptance", "tools"}
    require(root.stat().st_uid == os.getuid() and not root.stat().st_mode & 0o022,
            "qa_overlay_parent_not_owned")
    seen = set()
    for parent, directories, names in os.walk(str(root), followlinks=False):
        for name in directories:
            path = Path(parent) / name
            require(path.relative_to(root).as_posix() in allowed_dirs
                    and not path.is_symlink() and path.stat().st_uid == os.getuid()
                    and not path.stat().st_mode & 0o022, "qa_overlay_directory_mismatch")
        for name in names:
            relative = (Path(parent) / name).relative_to(root).as_posix()
            require(relative in QA_FILES, "qa_overlay_unexpected_file")
            seen.add(relative)
    require(seen == set(QA_FILES), "qa_overlay_file_set_mismatch")
    frozen = {}
    for relative, expected in QA_FILES.items():
        old = ORIGINAL_HARNESS_SHA256 if relative.endswith("/native_v6_ha_multihost_live.py") else expected
        require(manifest["files"].get(relative) == old,
                "qa_original_helper_source_binding_mismatch")
        frozen[relative] = pinned_bytes(root / relative, expected)
    return frozen


def load_qa(root, frozen):
    require(not any(name in sys.modules for name, _ in QA_MODULES),
            "qa_module_cache_must_be_empty")
    original_path = list(sys.path)
    try:
        modules = {name: module_from_bytes(name, root / relative, frozen[relative])
                   for name, relative in QA_MODULES}
    finally:
        # The original loopback helper inserts its tools directory. Every local
        # dependency was already loaded from verified bytes; keep caller search
        # paths unchanged and reject any additional non-standard dependency.
        sys.path[:] = original_path
    fixture = modules["native_v6_ha_multihost_live"]
    required = json.dumps(sorted(fixture.REQUIRED_CHECKS), separators=(",", ":")).encode()
    require(len(fixture.REQUIRED_CHECKS) == 89
            and hashlib.sha256(required).hexdigest() == CHECK_SET_SHA256
            and fixture.REQUEST_SECONDS == 15
            and fixture.NATIVE_ADMISSION_SECONDS == 8
            and fixture.TARGET_BYTES == 35651584, "native_fixture_contract_drift")
    return fixture


def verify_build(receipt, abi, fixture, freeze):
    binding = BUILD_BINDINGS[abi]
    actual = fixture.base.validate_build_receipt(
        receipt, freeze.COMMIT, freeze.TREE, binding["binary_sha256"])
    require(actual == abi and receipt.get("binary_path") == binding["binary_path"]
            and receipt.get("source_manifest_sha256") == freeze.MANIFEST_SHA
            and receipt.get("source_files") == 2582
            and receipt.get("source_verified_before_and_after") is True
            and receipt.get("binary_has_independent_inode") is True
            and receipt.get("copied_binary_readback_verified") is True
            and receipt.get("freezer_sha256") == FREEZER_SHA256
            and receipt.get("features") == [freeze.FEATURE],
            "native_r8j_freezer_receipt_incomplete")


def verify_attempt_roots(args):
    parts = [item.split(",") for item in args.node]
    require(all(len(item) == 3 for item in parts)
            and [item[0] for item in parts] == list(NODE_ROOTS)
            and all(item[2] == NODE_ROOTS[item[0]] for item in parts),
            "exact_three_attempt_02_node_roots_required")
    require(args.work_root.name == "native-r8j-physical89-02-controller"
            and args.plan_out.name == "r8j-native-physical89-02-plan.json"
            and args.report_out.name == "r8j-native-physical89-02-controller-report.json",
            "attempt_02_controller_paths_required")
    require(len({args.work_root, args.plan_out, args.report_out}) == 3,
            "controller_output_paths_overlap")


def output_ready(path, freeze, *, new):
    freeze.canonical_directory(path.parent)
    require(path.is_absolute() and path.resolve(strict=False) == path
            and path.parent.stat().st_uid == os.getuid()
            and not path.parent.stat().st_mode & 0o022,
            "output_parent_not_owned")
    if new:
        require(not path.exists() and not path.is_symlink(), "report_output_must_be_new")


def prepare_command(args, linux, mac, freeze):
    command = ["--source-commit", freeze.COMMIT, "--source-tree", freeze.TREE,
               "--binary-source", "local:" + linux["binary_path"],
               "--expected-binary-sha256", linux["binary_sha256"],
               "--work-root", str(args.work_root),
               "--allow-private-lan" if args.allow_private_lan else "--allow-private-tailnet"]
    for name in ("api-port", "raft-port", "mesh-local-port-base",
                 "mesh-reverse-port-base", "mesh-api-port-base"):
        command += ["--" + name, str(getattr(args, name.replace("-", "_")))]
    for node in args.node:
        alias = node.split(",", 1)[0]
        receipt = mac if alias == "macbook-pro" else linux
        source_alias = "macbook-pro" if alias == "macbook-pro" else "local"
        receipt_path = args.mac_build if alias == "macbook-pro" else args.linux_build
        receipt_sha = args.mac_build_sha256 if alias == "macbook-pro" else args.linux_build_sha256
        command += ["--node", node,
                    "--node-binary", ",".join((alias, source_alias + ":" + receipt["binary_path"],
                                               receipt["binary_sha256"], freeze.COMMIT, freeze.TREE)),
                    "--native-build-receipt", ",".join((alias, "local:" + str(receipt_path), receipt_sha))]
    return command


def binding_fields(args, freeze):
    return {
        "binary_source_commit": freeze.COMMIT,
        "binary_source_tree": freeze.TREE,
        "binary_source_files": 2582,
        "binary_source_manifest_sha256": freeze.MANIFEST_SHA,
        "source_commit_and_tree_arguments_describe": "original_r8j_binary_source",
        "binary_bindings": BUILD_BINDINGS,
        "qa_root": str(args.qa_root),
        "qa_version": "physical89-query-r1-controller-r2",
        "qa_files_sha256": QA_FILES,
        "qa_directory_is_binary_source_tree": False,
        "qa_changes_do_not_change_binary_source_identity": True,
        "controller_sha256": freeze.digest(Path(__file__).resolve(strict=True)),
        "parent_controller_sha256": PARENT_CONTROLLER_SHA256,
        "freezer_sha256": FREEZER_SHA256,
        "required_check_count": 89,
        "required_checks_sha256": CHECK_SET_SHA256,
        "http_request_budget_seconds": 15,
        "native_admission_budget_seconds": 8,
        "payload_target_bytes": 35651584,
        "matrix_sha256": MATRIX_SHA256,
        "matrix_passed_tests": 30,
        "backup_qualified": False,
        "production_cutover": False,
        "direct_lan_qualified": False,
    }


def summary_projection(path, fixture, freeze):
    require(path.is_file() and not path.is_symlink() and path.stat().st_uid == os.getuid()
            and not path.stat().st_mode & 0o077 and path.stat().st_size <= 1024 * 1024,
            "fixture_summary_owner_or_shape")
    raw = path.read_bytes()
    value = json.loads(raw)
    checks = value.get("checks", [])
    exact = (value.get("status") == "passed"
             and value.get("source_commit") == freeze.COMMIT
             and value.get("source_tree") == freeze.TREE
             and value.get("runner_sha256") == QA_FILES["qa/openbao-acceptance/native_v6_ha_multihost_live.py"]
             and value.get("required_check_count") == 89
             and value.get("observed_check_count") == 89
             and value.get("passed_check_count") == 89
             and len(checks) == 89
             and {row.get("case") for row in checks} == fixture.REQUIRED_CHECKS
             and all(row.get("passed") is True for row in checks))
    # Do not copy arbitrary fixture strings, request/response bodies or secrets.
    return {"fixture_summary_path": str(path),
            "fixture_summary_sha256": hashlib.sha256(raw).hexdigest(),
            "fixture_exact_89_passed": exact}


def parsed_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "manifest", "matrix", "linux-build", "mac-build",
                 "qa-root", "work-root", "plan-out", "report-out"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("matrix-sha256", "linux-build-sha256", "mac-build-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--node", action="append", required=True)
    for name, default in (("api-port", 46230), ("raft-port", 46231),
                          ("mesh-local-port-base", 55200), ("mesh-reverse-port-base", 55300),
                          ("mesh-api-port-base", 55400)):
        parser.add_argument("--" + name, type=int, default=default)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--allow-private-lan", action="store_true")
    scope.add_argument("--allow-private-tailnet", action="store_true")
    parser.add_argument("--execute", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    args = parsed_arguments(argv)
    os.umask(0o077)
    freeze = load_freezer()
    verify_attempt_roots(args)
    require(args.matrix_sha256 == MATRIX_SHA256
            and args.linux_build_sha256 == BUILD_BINDINGS["x86_64-unknown-linux-gnu"]["receipt_sha256"]
            and args.mac_build_sha256 == BUILD_BINDINGS["aarch64-apple-darwin"]["receipt_sha256"],
            "original_r8j_receipt_hashes_required")
    source = freeze.canonical_directory(args.source_root)
    manifest = freeze.load_manifest(args.manifest)
    freeze.verify_source(source, manifest)
    matrix = bound_json(args.matrix, MATRIX_SHA256, freeze)
    verify_matrix(matrix, freeze)
    linux = bound_json(args.linux_build, args.linux_build_sha256, freeze)
    mac = bound_json(args.mac_build, args.mac_build_sha256, freeze)
    frozen = verify_qa(args.qa_root, source, manifest, freeze)
    fixture = load_qa(args.qa_root, frozen)
    verify_build(linux, "x86_64-unknown-linux-gnu", fixture, freeze)
    verify_build(mac, "aarch64-apple-darwin", fixture, freeze)
    local_binary = Path(linux["binary_path"])
    require(local_binary.resolve(strict=True) == local_binary
            and local_binary.is_file() and not local_binary.is_symlink()
            and local_binary.stat().st_uid == os.getuid()
            and not local_binary.stat().st_mode & 0o022
            and freeze.digest(local_binary) == linux["binary_sha256"],
            "main_frozen_binary_changed")
    freeze.verify_binary_abi(local_binary, "x86_64-unknown-linux-gnu")
    command = prepare_command(args, linux, mac, freeze)
    fixture.parsed_arguments(command)
    for path in (args.work_root, args.plan_out, args.report_out):
        require(path != source and source not in path.parents
                and path != args.qa_root and args.qa_root not in path.parents,
                "outputs_cannot_change_source_or_qa")
    output_ready(args.plan_out, freeze, new=False)
    output_ready(args.report_out, freeze, new=True)
    plan = {**binding_fields(args, freeze),
            "schema": "heptabao.r8j-native-physical89-plan.v2",
            "status": "prepared", "arguments": command,
            "physical_checks_executed_during_preparation": False,
            "plan_only_is_default": True}
    plan_bytes = freeze.json_bytes(plan)
    if args.plan_out.exists() or args.plan_out.is_symlink():
        require(not args.plan_out.is_symlink() and args.plan_out.is_file()
                and args.plan_out.stat().st_uid == os.getuid()
                and not args.plan_out.stat().st_mode & 0o077
                and args.plan_out.read_bytes() == plan_bytes, "existing_plan_differs")
    else:
        freeze.write_new(args.plan_out, plan_bytes)
    print(json.dumps({"status": "prepared", "plan": str(args.plan_out),
                      "plan_sha256": freeze.digest(args.plan_out),
                      "physical_execution_requested": args.execute,
                      "physical_pass_claimed": False}, sort_keys=True), flush=True)
    if not args.execute:
        return 0
    result = fixture.main(command)
    after_ok, after_failure = True, None
    try:
        freeze.verify_source(source, manifest)
        verify_qa(args.qa_root, source, manifest, freeze)
        require(freeze.digest(local_binary) == linux["binary_sha256"],
                "main_frozen_binary_changed_after_run")
    except Exception:
        after_ok, after_failure = False, "post_run_source_qa_or_binary_binding_failed"
    projection = summary_projection(args.work_root / "summary.json", fixture, freeze)
    passed = result == 0 and after_ok and projection["fixture_exact_89_passed"]
    report = {**binding_fields(args, freeze), **projection,
              "schema": "heptabao.r8j-native-physical89-controller-report.v2",
              "status": "passed" if passed else "failed",
              "fixture_exit_code": result, "post_run_bindings_unchanged": after_ok,
              "binding_failure_code": after_failure,
              "plan_path": str(args.plan_out), "plan_sha256": freeze.digest(args.plan_out),
              "physical_fixture_passed": passed}
    freeze.write_new(args.report_out, freeze.json_bytes(report))
    print(json.dumps({"status": report["status"], "report": str(args.report_out),
                      "report_sha256": freeze.digest(args.report_out),
                      "physical_fixture_passed": passed}, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Only fixed identifier-shaped gate codes may reach public output.
        code = str(error) if isinstance(error, RuntimeError) else "r2_controller_gate_failed"
        if re.fullmatch(r"[a-z][a-z0-9_]{0,159}", code) is None:
            code = "r2_controller_gate_failed"
        print(json.dumps({"status": "blocked", "error": code,
                          "physical_pass_claimed": False}), file=sys.stderr)
        raise SystemExit(1)

