#!/usr/bin/env python3
"""Admit the frozen 09c14 ROG build, then run original full34 and comparison69 once.

Run with Python -I -S -B. The candidate checkout stays clean at the build commit;
this successor controller may live in a later QA checkout. The comparison driver
is the retained, unchanged X230 original, supplied by absolute path. No existing
service endpoint, production credential, retry, deletion or cutover is accepted.
DR25 supplies the existing receipt parser, file custody and process ownership.
"""
from __future__ import annotations

import argparse
import contextlib
from decimal import Decimal
import hashlib
import importlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import runpy
import subprocess
import sys
from types import SimpleNamespace
from urllib.parse import urlsplit

BUILD_COMMIT = "09c14eae7a3b52dee8ce3af3175dad5900ac59ec"
BUILD_TREE = "dfb0df97a2c74b1c0154f45342f3debb0ce438ab"
SELECTION_SHA256 = "d7f6d0971e7a6b3e0096e50a1e3d607bff851ce2295563ad068b80adf2294bfd"
BUILD_CONTROLLER_SHA256 = "56b4696cc252d50d3ddeb9edad90465654e011045d2e3d9feba5919d42247c7f"
COMPARISON_SHA256 = "fd88ed0b8f1c1010e79f9393dfbf6464cabcac48ece8c6e448a64b7ccc45272e"
WORKLOAD_PINS = {
    "qa/openbao-acceptance/kv2_271_lossless_native_live.py":
        "383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581",
    "qa/openbao-acceptance/acceptance.py":
        "8312c400ec5f0946f8a87fb3241bf8db832ddd04763010af7245d6557f55f94d",
}
ORACLE_PINS = {
    "oracle_binary": "535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea",
    "oracle_archive": "0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243",
}
TOOLCHAIN_PINS = {
    "cargo": "ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24",
    "rustc": "3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2",
    "rustfmt": "5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877",
}
ROG_ROOT = Path("/home/qian-qi/heptabao-kv2-ha-convergence-20261106-r1")
ROG_BUILD = ROG_ROOT / "build-test-r8"
ROG_SOURCE = ROG_ROOT / "source-09c14-r8"
TOOLCHAIN = Path("/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin")
MODULES = tuple(sorted("core,kv,token,transit,pki,totp,userpass,approle,identity,wrapping,edge_tls,system,operations".split(",")))
DEPENDENCY_ROOTS = ("qa/openbao-acceptance", "qa/single-node", "clients/python", "tools/migration")
MAX_JSON_BYTES = 8 * 1024 * 1024


class AdmissionFailure(RuntimeError):
    """Closed diagnostic labels only; never credentials or command output."""


def need(value, label):
    if not value:
        raise AdmissionFailure(label)


def git(root, *args):
    return subprocess.check_output(["/usr/bin/git", "-C", str(root), *args],
        stderr=subprocess.DEVNULL, timeout=15,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"})


def source_snapshot(root):
    need(root.is_absolute() and root.resolve(strict=True) == root, "canonical_source_required")
    need(git(root, "rev-parse", "HEAD").decode().strip() == BUILD_COMMIT
         and git(root, "rev-parse", "HEAD^{tree}").decode().strip() == BUILD_TREE,
         "frozen_09c14_source_required")
    need(not git(root, "status", "--porcelain", "--untracked-files=all"), "clean_candidate_source_required")
    rows = git(root, "ls-tree", "-rz", "HEAD", "--", *DEPENDENCY_ROOTS).split(b"\0")
    pins = {}
    for row in filter(None, rows):
        metadata, raw_path = row.split(b"\t", 1)
        relative = os.fsdecode(raw_path)
        if not relative.endswith(".py") or "/evidence/" in relative or "/tests/" in relative:
            continue
        mode, kind, object_id = metadata.split()
        path = root / relative
        need(mode in (b"100644", b"100755") and kind == b"blob"
             and path.resolve(strict=True) == path and path.is_file(), "source_dependency_regular_required")
        raw = path.read_bytes()
        need(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
             == object_id.decode(), "source_dependency_differs_from_frozen_tree")
        pins[relative] = hashlib.sha256(raw).hexdigest()
    need(all(pins.get(name) == value for name, value in WORKLOAD_PINS.items()), "original_workloads_required")
    # -B prevents writes, but would still read preexisting bytecode. No ignored
    # bytecode or untracked Python module may replace a bound source dependency.
    for relative in DEPENDENCY_ROOTS:
        for path in (root / relative).rglob("*"):
            name = path.relative_to(root).as_posix()
            if "/evidence/" in name or "/tests/" in name:
                continue
            need(path.suffix not in (".pyc", ".pyo", ".so"), "cached_source_dependency_refused")
            if path.suffix == ".py":
                need(name in pins, "untracked_source_dependency_refused")
    return {"commit": BUILD_COMMIT, "tree": BUILD_TREE, "dependencies": pins}


def load_dependencies(source):
    sys.path[:0] = [str(source / p) for p in
                   ("qa/openbao-acceptance", "qa/single-node", "clients/python")]
    modules = {}
    for name in ("kv2_native_fresh_directory_dr_live", "kv2_dr_process_custody", "acceptance",
                 "official_openbao_launcher"):
        module = importlib.import_module(name)
        need(Path(module.__file__).resolve() == source / "qa/openbao-acceptance" / (name + ".py"),
             "dependency_import_identity_mismatch")
        modules[name] = module
    dr = modules["kv2_native_fresh_directory_dr_live"]
    need(dr.ROOT == source and dr.full.ROOT == source, "workload_import_root_mismatch")
    return SimpleNamespace(dr=dr, full=dr.full, custody=modules["kv2_dr_process_custody"],
        acceptance=modules["acceptance"], launcher=modules["official_openbao_launcher"])


def selected_groups(selection):
    return [g for key in ("legacy_groups", "legacy_additional_groups", "added_groups")
            for g in selection[key]]


def expected_build_steps(selection):
    """The already executed ROG controller's closed command inventory."""
    entries = [
        ("00-source-head", ["/usr/bin/git", "rev-parse", "HEAD"], 30),
        ("01-preserved-format-diff", ["/usr/bin/git", "diff", "--binary", "HEAD"], 30),
        ("02-untracked", ["/usr/bin/git", "ls-files", "--others", "--exclude-standard"], 30),
        ("03-bundle-verify", ["/usr/bin/git", "bundle", "verify", str(ROG_BUILD / "candidate.bundle")], 30),
        ("04-fetch", ["/usr/bin/git", "fetch", str(ROG_BUILD / "candidate.bundle"), "HEAD"], 30),
        ("05-canonical-tree", ["/usr/bin/git", "rev-parse", BUILD_COMMIT + "^{tree}"], 30),
        ("06-canonical-parent", ["/usr/bin/git", "rev-parse", BUILD_COMMIT + "^"], 30),
        ("07-stage-exact-format", ["/usr/bin/git", "add", "--update"], 30),
        ("08-format-working-tree", ["/usr/bin/git", "write-tree"], 30),
        ("09-checkout-canonical", ["/usr/bin/git", "checkout", "--detach", BUILD_COMMIT], 30),
        ("10-clean-source", ["/usr/bin/git", "status", "--porcelain"], 30),
        ("11-fsck", ["/usr/bin/git", "fsck", "--full", "--strict"], 60),
        ("12-format-check", [str(TOOLCHAIN / "cargo"), "fmt", "--all", "--", "--check"], 60),
    ]
    for label, key, cap in (("13-normal-release-build", "server_release", 1800),
                            ("14-server-libtest-build", "server_libtest", 3600),
                            ("15-peer-libtest-build", "peer_libtest", 3600)):
        entries.append((label, selection["build_examples"][key], cap))
    for crate in ("heptabao-server", "heptabao-ha-service"):
        entries.append((crate + "-list", [str(ROG_BUILD / "artifacts" / (crate + "-libtest")), "--list"], 30))
    for index, group in enumerate(selected_groups(selection)):
        for number, suffix in enumerate(group.get("argv_suffixes", [group.get("argv_suffix")])):
            entries.append((f'test-{index:02d}-{group["label"]}-{number:02d}',
                [str(ROG_BUILD / "artifacts" / (group["crate"] + "-libtest")), *suffix], group["runtime_seconds"]))
    entries.extend((("99-final-source-head", ["/usr/bin/git", "rev-parse", "HEAD"], 30),
                    ("99-final-source-clean", ["/usr/bin/git", "status", "--porcelain"], 30)))
    return entries


def finite_number(value):
    return type(value) in (int, float, Decimal) and math.isfinite(value)


def validate_receipt(receipt, selection, selection_sha, server, seed, dr):
    need(receipt.get("status") == "passed" and receipt.get("failure") is None,
         "terminal_successful_build_required")
    need(selection_sha == SELECTION_SHA256 and receipt.get("source_commit") == BUILD_COMMIT
         and receipt.get("source_tree") == BUILD_TREE
         and receipt.get("controller_sha256") == BUILD_CONTROLLER_SHA256, "current_build_identity_required")
    # Reuse DR25's unique 107 names, 90/17 split, actual enumeration and per-result
    # failed/ignored/measured checks. A previous normal61 receipt cannot pass.
    binding = dr.validate_build_receipt(receipt, BUILD_COMMIT, server, seed, selection, selection_sha)
    need(receipt.get("toolchain_pins") == TOOLCHAIN_PINS
         and receipt.get("build_environment_overrides") == selection["original_build"]["env"]
         and receipt.get("compiler_wrappers_disabled") is True
         and receipt.get("ambient_build_overrides_inherited") is False
         and receipt.get("explicit_compiler") == str(TOOLCHAIN / "rustc"), "normal_rog_build_profile_required")
    need(receipt.get("automatic_retry") is False and receipt.get("deadline_renewed") is False
         and type(receipt.get("outer_budget_seconds")) is int and receipt["outer_budget_seconds"] == 12000
         and finite_number(receipt.get("elapsed_seconds")) and 0 < receipt["elapsed_seconds"] < 12000
         and finite_number(receipt.get("created_at_unix")) and finite_number(receipt.get("finished_at_unix"))
         and 0 < receipt["created_at_unix"] <= receipt["finished_at_unix"], "terminal_original_build_budget_required")
    need(all(receipt.get(key) is False for key in ("production_changed", "production_server_started",
         "formal_kv2_qualified", "physical_ha_qualified", "authbus_migration_qualified",
         "full_replacement_qualified")), "build_receipt_scope_mismatch")
    names = {"heptabao-server", "heptabao-seed", "heptabao-server-libtest", "heptabao-ha-service-libtest"}
    need(set(receipt["artifacts"]) == names, "exact_build_artifact_set_required")
    for name, artifact in receipt["artifacts"].items():
        peer, test = name == "heptabao-ha-service-libtest", name.endswith("-libtest")
        package = "heptabao-ha-service" if peer else "heptabao-server"
        entry = "src/lib.rs" if test else "src/bin/heptabao-seed.rs" if name == "heptabao-seed" else "src/main.rs"
        profile = {"opt_level": "3", "debuginfo": 0, "debug_assertions": True, "overflow_checks": True, "test": test}
        features = ["default", "native-v6-peer-ingress"] if peer else ["default", "native-v6-ha", "native-v6-storage"]
        need(artifact.get("source_commit") == BUILD_COMMIT and artifact.get("source_tree") == BUILD_TREE
             and artifact.get("normal_features_profile_and_source_verified") is True
             and artifact.get("path") == str(ROG_BUILD / "artifacts" / name)
             and artifact.get("cargo_source_entry") == str(ROG_SOURCE / "crates" / package / entry)
             and artifact.get("cargo_package_id", "").startswith("path+file://" + str(ROG_SOURCE / "crates" / package) + "#")
             and artifact.get("cargo_features") == features and artifact.get("cargo_profile") == profile
             and all(type(artifact["cargo_profile"].get(key)) is type(value) for key, value in profile.items())
             and type(artifact.get("bytes")) is int and artifact["bytes"] > 0
             and re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256", "")), "normal_artifact_source_or_features_mismatch")
    expected, steps = expected_build_steps(selection), receipt.get("steps", [])
    need([step.get("step") for step in steps] == [row[0] for row in expected], "exact_completed_build_steps_required")
    for step, (label, argv, cap) in zip(steps, expected):
        cleanup = step.get("owned_group_cleanup", {})
        need(step.get("argv") == argv and type(step.get("attempts")) is int and step["attempts"] == 1
             and type(step.get("exit_code")) is int and step["exit_code"] == 0
             and step.get("timed_out") is False and "exception_type" not in step
             and step.get("unexpected_live_descendants_on_success") is False
             and cleanup.get("all_owned_processes_gone") is True and cleanup.get("abnormal_exit") is False
             and cleanup.get("remaining_before_cleanup") == [] and cleanup.get("remaining_after_cleanup") == []
             and cleanup.get("signals") == [] and "cleanup_error_type" not in cleanup,
             "build_step_not_terminal_success")
        need(step.get("requested_cap_seconds") == cap and finite_number(step.get("effective_budget_seconds"))
             and 0 < step["effective_budget_seconds"] <= cap, "build_step_budget_changed")
        need(type(step.get("pid")) is int and step["pid"] > 0
             and finite_number(step.get("seconds")) and step["seconds"] >= 0
             and finite_number(step.get("started_at_unix")) and step["started_at_unix"] > 0,
             "build_step_execution_observation_missing")
        for stream in ("stdout", "stderr"):
            need(type(step.get(stream + "_bytes")) is int and step[stream + "_bytes"] >= 0
                 and re.fullmatch(r"[0-9a-f]{64}", step.get(stream + "_sha256", "")), "build_step_output_binding_missing")
    for group, expected_group in zip(receipt["groups"], selected_groups(selection)):
        need(group.get("budget_renewed_per_case") is False
             and group.get("original_group_budget_seconds") == expected_group["runtime_seconds"],
             "original_group_budget_required")
    return binding


def pinned_json(path, dr, expected_sha=None):
    pin = dr.file_pin(path, private=True)
    raw = dr.full.private_read(path, MAX_JSON_BYTES)
    need(hashlib.sha256(raw).hexdigest() == pin["sha256"]
         and (expected_sha is None or pin["sha256"] == expected_sha), "receipt_bytes_or_expected_pin_mismatch")
    return dr.full.decode(raw), pin


def comparison_cases(acceptance):
    # The unchanged source declares 68 CASES entries and records one additional
    # actual result in Suite.totp_cases -> mount("totp"). Keep that original
    # 69th observation mandatory instead of editing the retained workload.
    declared = {module + "." + name for module in MODULES for name in acceptance.CASES[module]}
    need(set(acceptance.CASES) == set(MODULES) and len(declared) == 68
         and "totp.mount" not in declared, "original_comparison69_contract_required")
    return declared | {"totp.mount"}


def admit(args, deps, source):
    dr = deps.dr
    pins = {name: dr.file_pin(getattr(args, name)) for name in
            ("binary", "seed_binary", "comparison_driver", "oracle_binary", "oracle_archive")}
    for name in ("binary", "seed_binary"):
        pin = pins[name]
        need(pin["uid"] == os.geteuid() and pin["mode"] & 0o100 and not pin["mode"] & 0o077,
             "owned_private_executable_required")
    need(pins["comparison_driver"]["sha256"] == COMPARISON_SHA256, "unchanged_comparison_driver_required")
    need(all(pins[name]["sha256"] == digest for name, digest in ORACLE_PINS.items()), "official_271_pair_required")
    receipt, pins["build_receipt"] = pinned_json(args.build_receipt, dr, args.build_receipt_sha256)
    selection_path = args.build_receipt.parent / "test-selection.public.json"
    selection, pins["selection"] = pinned_json(selection_path, dr, SELECTION_SHA256)
    binding = validate_receipt(receipt, selection, pins["selection"]["sha256"],
                               pins["binary"], pins["seed_binary"], dr)
    need(deps.full.HTTP_SECONDS == 15 and deps.full.MIGRATION_SECONDS == 360
         and len(deps.full.CHECKS) == 31, "original_full34_contract_required")
    comparison_cases(deps.acceptance)
    return {"source": source, "pins": pins, "build_binding": binding,
            "input_paths": {name: str(value) for name, value in vars(args).items()
                            if isinstance(value, Path) and name != "private_work_root"},
            "selection_path": str(selection_path), "normal_build_qualified": True}


def validate_comparison(report, admission, acceptance):
    expected = comparison_cases(acceptance)
    need(report.get("schema") == "heptabao.live-acceptance.v1"
         and report.get("target") == "OpenBao 2.7.1" and report.get("mode") == "differential"
         and report.get("status") == "passed_scoped_cases" and report.get("cases_match") is True
         and report.get("mismatched_cases") == [] and report.get("scope") == list(MODULES)
         and report.get("full_openbao_compatibility") is False and report.get("production_qualified") is False
         and report.get("owned_cleanup_completed") is True and report.get("cleanup_errors") == []
         and report.get("source_and_binary_unchanged") is True, "comparison69_not_complete")
    for side in ("candidate_results", "oracle_results"):
        value = report.get(side, {})
        need(set(value.get("cases", {})) == expected and len(expected) == 69
             and all(case.get("result") == "passed" for case in value["cases"].values())
             and value.get("cleanup", {}).get("result") == "passed", "comparison69_case_set_or_cleanup")
    need(report["candidate_results"]["cases"] == report["oracle_results"]["cases"], "comparison69_actual_case_mismatch")
    binding = report.get("execution_binding", {})
    need(binding.get("candidate_source_sha") == BUILD_COMMIT
         and binding.get("candidate_binary_sha256") == admission["pins"]["binary"]["sha256"]
         and binding.get("candidate_source_has_uncommitted_changes") is False
         and binding.get("runner_source_sha256") == COMPARISON_SHA256
         and binding.get("build_log_sha256") == admission["pins"]["build_receipt"]["sha256"],
         "comparison69_execution_binding_mismatch")
    need(report.get("native_storage", {}).get("profile") == "native_v6_file"
         and report["native_storage"].get("fixture_options") is False
         and report["native_storage"].get("activation_status") == 204, "comparison69_normal_profile_required")
    need(report["candidate"]["endpoint"] != report["oracle"]["endpoint"], "distinct_loopback_fixtures_required")
    for side in ("candidate", "oracle"):
        endpoint = urlsplit(report.get(side, {}).get("endpoint", ""))
        need(endpoint.scheme == "https" and endpoint.hostname is not None
             and ipaddress.ip_address(endpoint.hostname).is_loopback and endpoint.port is not None
             and endpoint.username is None and endpoint.password is None
             and not endpoint.query and not endpoint.fragment, "owned_loopback_endpoint_required")


@contextlib.contextmanager
def isolated_environment(args):
    previous = dict(os.environ)
    os.environ.clear()
    os.environ.update(PATH="/usr/bin:/bin:/usr/sbin:/sbin", LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC",
        TMPDIR=str(args.private_work_root / "tmp"), HB_ORACLE_BINARY=str(args.oracle_binary),
        HB_ORACLE_ARCHIVE=str(args.oracle_archive))
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def run_workloads(args, deps, admission, report):
    root = args.private_work_root
    with deps.custody.activated() as owner:
        try:
            with (root / "full34.stdout").open("x") as out, (root / "full34.stderr").open("x") as err:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = deps.full.main(["--binary", str(args.binary), "--private-work-root", str(root / "full34"),
                                          "--migration-lane", "native-large", "--profile", "full34"])
            baseline, _ = pinned_json(root / "full34/summary.json", deps.dr)
            need(code == 0 and deps.dr.full34_complete(baseline)
                 and baseline.get("source_commit") == BUILD_COMMIT and baseline.get("source_tree") == BUILD_TREE
                 and baseline.get("source_dirty") is False
                 and baseline.get("binary_sha256") == admission["pins"]["binary"]["sha256"], "original_full34_not_qualified")
            owner.assert_retired()
            report["full34"] = {"status": "passed", "checks_passed": 31, "checks_total": 31,
                                "original_report": "full34/summary.json"}
            # Preserve the original driver's bytes, workload and default module
            # selection. Its newly allocated fixtures remain in this owned root.
            driver = root / "original-comparison69.py"
            raw = args.comparison_driver.read_bytes()
            need(hashlib.sha256(raw).hexdigest() == COMPARISON_SHA256, "comparison_driver_changed")
            deps.full.private_write(driver, raw)
            argv = [str(driver), "--binary", str(args.binary), "--expected-binary-sha256",
                admission["pins"]["binary"]["sha256"], "--expected-source-commit", BUILD_COMMIT,
                "--candidate-source", str(args.candidate_source), "--work-dir", str(root / "comparison69"),
                "--build-log", str(args.build_receipt), "--oracle-version", "2.7.1"]
            previous_argv = sys.argv
            try:
                sys.argv = argv
                with (root / "comparison69.stdout").open("x") as out, (root / "comparison69.stderr").open("x") as err:
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        try:
                            runpy.run_path(str(driver), run_name="__main__")
                        except SystemExit as stopped:
                            need(type(stopped.code) is int and stopped.code == 0, "comparison69_child_failed")
                        else:
                            raise AdmissionFailure("comparison69_missing_terminal_exit")
            finally:
                sys.argv = previous_argv
            original, _ = pinned_json(root / "comparison69/comparison-bound.json", deps.dr)
            validate_comparison(original, admission, deps.acceptance)
            owner.assert_retired()
            report["comparison69"] = {"status": "passed", "candidate_passed": 69, "oracle_passed": 69,
                                      "original_report": "comparison69/comparison-bound.json"}
        finally:
            report["process_custody"] = owner.finish()
    need(report["process_custody"]["passed_process_custody"] is True, "original_processes_not_retired")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("candidate-source", "binary", "seed-binary", "build-receipt", "comparison-driver",
                 "oracle-binary", "oracle-archive", "private-work-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--build-receipt-sha256", required=True)
    args = parser.parse_args(argv)
    need(re.fullmatch(r"[0-9a-f]{64}", args.build_receipt_sha256), "explicit_original_receipt_pin_required")
    for name, value in vars(args).items():
        if isinstance(value, Path):
            need(value.is_absolute() and value == value.absolute(), "absolute_paths_required")
            if name != "private_work_root":
                need(value.resolve(strict=True) == value, "input_symlink_refused")
    return args


def main(argv=None):
    args = parse_args(argv)
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, "isolated_no_site_no_bytecode_python_required")
    need(sys.platform.startswith("linux") and platform.machine() == "x86_64"
         and platform.node() == "qian-ThinkPad-X230", "observed_x230_host_required")
    source = source_snapshot(args.candidate_source)
    deps = load_dependencies(args.candidate_source)
    controller_path = Path(__file__).resolve(strict=True)
    controller_pin = deps.dr.file_pin(controller_path)
    root = args.private_work_root
    deps.dr.private_parent(root.parent)
    need(not os.path.lexists(root) and not root.is_relative_to(args.candidate_source)
         and all(not value.is_relative_to(root) for value in vars(args).values()
                 if isinstance(value, Path) and value != root), "new_disjoint_private_output_required")
    os.umask(0o077)
    root.mkdir(mode=0o700)
    (root / "tmp").mkdir(mode=0o700)
    root_identity = deps.dr.private_parent(root)
    report = {"schema": "heptabao.x230-current-candidate-qualification.v1", "status": "failed",
        "admitted": False, "automatic_retry": False, "production_changed": False,
        "full_replacement_qualified": False, "production_cutover": False, "legacy_cleanup_qualified": False,
        "source_commit": BUILD_COMMIT, "source_tree": BUILD_TREE, "hostname": platform.node(),
        "controller_sha256": controller_pin["sha256"],
        "full34": {"status": "not_run"}, "comparison69": {"status": "not_run"},
        "http_budget_seconds": 15, "migration_budget_seconds": 360, "source_and_inputs_unchanged": False}
    admission = None
    try:
        with isolated_environment(args):
            admission = admit(args, deps, source)
            report["admitted"] = True
            report["input_binding"] = admission
            deps.full.private_write(root / "admission.public.json", deps.full.canonical(admission))
            # validate archive membership too; this never starts the Oracle.
            need(deps.launcher.verify_inputs(version="2.7.1") == args.oracle_binary, "official_oracle_path_mismatch")
            run_workloads(args, deps, admission, report)
        report["status"] = "passed"
    except BaseException as error:
        label = str(error)
        report["failure"] = label if re.fullmatch(r"[a-z0-9_]{1,160}", label) else type(error).__name__
    finally:
        if admission is not None:
            try:
                after = admit(args, deps, source_snapshot(args.candidate_source))
                need(after == admission and deps.dr.private_parent(root) == root_identity,
                     "source_inputs_or_output_custody_changed")
                need(deps.dr.file_pin(controller_path) == controller_pin, "controller_changed")
                report["source_and_inputs_unchanged"] = True
            except BaseException:
                report["status"] = "failed"
                report.setdefault("failure", "source_inputs_or_output_custody_changed")
        deps.full.private_write(root / "result.public.json", deps.full.canonical(report))
    print(json.dumps({"status": report["status"], "admitted": report["admitted"],
                      "result": str(root / "result.public.json"), "full_replacement_qualified": False}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AdmissionFailure, OSError, ValueError, subprocess.SubprocessError):
        print("X230 candidate admission refused before workload execution", file=sys.stderr)
        raise SystemExit(1) from None
