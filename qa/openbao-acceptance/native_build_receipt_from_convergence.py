#!/usr/bin/env python3
"""Project a completed normal107 build for the existing native HA input contract.

This reads the original bound receipt and terminal, rehashes both normal
executables, inspects their actual ABI, and rechecks the frozen source. It never
compiles, executes a product binary, starts a service, or grants HA qualification.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import time

PRODUCT = "4bde9aee03fcd27c59e13607e529b1cee594b249"
TREE = "f08493a23f8ea0637073651231865ea9607b790e"
VALIDATOR_SHA = "01993e6c367bf8b896b4832c7723b1f36900fefbc20fcc05394ce401ec6b4f67"


class Refused(RuntimeError):
    pass


def need(value, message):
    if not value:
        raise Refused(message)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def inspect_file(path, maximum, deadline, *, contents=False):
    need(path.is_absolute() and time.monotonic() < deadline, "absolute path and original deadline")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and 0 <= before.st_size <= maximum, "owned bounded regular input")
        digest = hashlib.sha256()
        data, header, size = [], bytearray(), 0
        while True:
            need(time.monotonic() < deadline, "original projection deadline")
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            need(size <= maximum, "input did not grow beyond bound")
            digest.update(block)
            if len(header) < 64:
                header.extend(block[:64 - len(header)])
            if contents:
                data.append(block)
        need(size == before.st_size and identity(before) == identity(os.fstat(descriptor))
             == identity(path.lstat()), "whole input identity unchanged")
        return {"path": str(path), "sha256": digest.hexdigest(), "bytes": size,
                "identity": list(identity(before)), "mode": stat.S_IMODE(before.st_mode)}, (
                b"".join(data) if contents else bytes(header))
    finally:
        os.close(descriptor)


def actual_abi(header, system, machine):
    if (system, machine) == ("Darwin", "arm64"):
        need(len(header) >= 32 and header[:4] == bytes.fromhex("cffaedfe")
             and struct.unpack_from("<I", header, 4)[0] == 0x0100000C
             and struct.unpack_from("<I", header, 12)[0] == 2, "actual arm64 Mach-O executable")
        return "aarch64-apple-darwin"
    need((system, machine) == ("Linux", "x86_64") and len(header) >= 64
         and header[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", header, 18)[0] == 62
         and struct.unpack_from("<H", header, 16)[0] in (2, 3),
         "actual x86_64 Linux ELF executable")
    return "x86_64-unknown-linux-gnu"


def original_source_path(selection, receipt):
    need(selection.get("schema") == "heptabao.normal-rust-execution-selection.v1",
         "bound producer selection schema")
    paths = []
    if "execution_source" in selection:
        paths.append(selection["execution_source"])
    if "fresh_clean_source" in selection:
        value = selection["fresh_clean_source"]
        need(isinstance(value, dict) and "path" in value, "bound Linux source path shape")
        paths.append(value["path"])
    need(paths and all(isinstance(path, str) and Path(path).is_absolute() for path in paths)
         and len(set(paths)) == 1, "unambiguous original producer source path")
    path = paths[0]
    need("source" not in receipt or receipt["source"] == path,
         "receipt and selection source path agree")
    for name, entry in (("heptabao-server", "src/main.rs"),
                        ("heptabao-seed", "src/bin/heptabao-seed.rs")):
        artifact = receipt.get("artifacts", {}).get(name, {})
        package = str(Path(path) / "crates/heptabao-server")
        need(artifact.get("cargo_source_entry") == str(Path(package) / entry)
             and artifact.get("cargo_package_id", "").startswith("path+file://" + package + "#"),
             "original Cargo source record matches declared producer directory")
    return path


def original_validation(receipt, selection, selection_sha, terminal, job, validator):
    need(terminal.get("job_id") == job and terminal.get("state") == "succeeded"
         and type(terminal.get("exit_code")) is int and terminal["exit_code"] == 0,
         "original successful authoritative terminal")
    need(all(terminal.get(k) is True for k in
             ("output_complete", "output_durable", "terminal_publication_confirmed"))
         and all(terminal.get(k) is False for k in ("timed_out", "cancelled", "automatic_retry")),
         "original durable complete terminal without timeout or retry")
    need(set(terminal.get("log_bytes", {})) == {"stdout", "stderr"}
         and all(type(row.get("seen")) is int and row["seen"] >= 0
                 and row.get("stored") == row["seen"] for row in terminal["log_bytes"].values())
         and all(terminal.get("log_synced", {}).get(k) is True
                 and terminal.get("log_truncated", {}).get(k) is False
                 and terminal.get("log_errors", {}).get(k) is None for k in ("stdout", "stderr")),
         "complete original log publication")
    need(receipt.get("source_commit") == PRODUCT and receipt.get("source_tree") == TREE,
         "exact canonical product source")
    namespace = {"need": need, "re": re}
    names = {"validate_build_tests", "validate_build_receipt"}
    nodes = [node for node in ast.parse(validator).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    need(len(nodes) == 2 and {node.name for node in nodes} == names, "exact pure bound validator definitions")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<bound-normal107-validator>", "exec"), namespace)
    artifacts = receipt.get("artifacts", {})
    for name in ("heptabao-server", "heptabao-seed"):
        artifact = artifacts.get(name, {})
        need(sorted(artifact.get("cargo_features", [])) == ["default", "native-v6-ha", "native-v6-storage"]
             and artifact.get("cargo_profile") == {"opt_level": "3", "debuginfo": 0,
                 "debug_assertions": True, "overflow_checks": True, "test": False},
             "actual original normal feature and compiler profile")
    binding = namespace["validate_build_receipt"](receipt, PRODUCT,
        artifacts.get("heptabao-server", {}), artifacts.get("heptabao-seed", {}), selection, selection_sha)
    steps = [step for step in receipt.get("steps", []) if step.get("step") == "13-normal-release-build"]
    need(len(steps) == 1 and type(steps[0].get("exit_code")) is int and steps[0]["exit_code"] == 0
         and steps[0].get("timed_out") is False and steps[0].get("attempts") == 1
         and steps[0].get("requested_cap_seconds") == 1800
         and steps[0].get("argv") == selection.get("build_examples", {}).get("server_release"),
         "original normal release invocation completed once within original cap")
    need(receipt.get("deadline_renewed") is False and receipt.get("automatic_retry") is False,
         "original build deadline and retry policy")
    return binding


def main():
    started = time.monotonic()
    deadline = started + 60
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("receipt", "selection", "terminal"):
        parser.add_argument("--" + name, required=True, type=Path)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    pins, values = {}, {}
    for name in ("receipt", "selection", "terminal"):
        pin, raw = inspect_file(getattr(args, name), 2 * 1024 * 1024, deadline, contents=True)
        expected = getattr(args, name + "_sha256")
        need(re.fullmatch(r"[0-9a-f]{64}", expected) and pin["sha256"] == expected, "exact original " + name)
        pins[name], values[name] = pin, json.loads(raw)
    validator_path = Path(__file__).resolve().with_name("kv2_native_fresh_directory_dr_live.py")
    validator_pin, validator = inspect_file(validator_path, 128 * 1024, deadline, contents=True)
    need(validator_pin["sha256"] == VALIDATOR_SHA, "reviewed original normal107 validators")
    binding = original_validation(values["receipt"], values["selection"], pins["selection"]["sha256"],
                                  values["terminal"], args.job_id, validator)
    actual, abis = {}, set()
    for name in ("heptabao-server", "heptabao-seed"):
        original = values["receipt"]["artifacts"][name]
        pin, header = inspect_file(Path(original["path"]), 256 * 1024 * 1024, deadline)
        need(pin["sha256"] == original["sha256"] and pin["bytes"] == original["bytes"]
             and pin["mode"] & 0o111, "actual normal executable matches original build")
        abis.add(actual_abi(header, platform.system(), platform.machine()))
        actual[name] = pin
    need(len(abis) == 1, "same actual native ABI")
    source = args.source
    need(source.is_absolute() and source.resolve(strict=True) == source
         and source.stat().st_uid == os.geteuid()
         and str(source) == original_source_path(values["selection"], values["receipt"]),
         "actual owned original producer source directory")
    git_env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"}
    def git(arguments):
        remaining = deadline - time.monotonic()
        need(remaining > 0, "original projection deadline before git")
        result = subprocess.run(["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
            "-C", str(source), *arguments], env=git_env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(15, remaining), check=True)
        need(not result.stderr and len(result.stdout) <= 65536, "bounded completed read-only source observation")
        return result.stdout.decode().strip()
    need(git(["rev-parse", "HEAD", "HEAD^{tree}"]).splitlines() == [PRODUCT, TREE]
         and git(["status", "--porcelain", "--untracked-files=all"]) == "", "current clean source freeze")
    for name, original_pin in pins.items():
        observed, _ = inspect_file(Path(original_pin["path"]), 2 * 1024 * 1024, deadline)
        need(observed == original_pin, "original provenance inputs remain unchanged")
    for pin in actual.values():
        need(identity(Path(pin["path"]).lstat()) == tuple(pin["identity"]), "actual binaries remain unchanged")
    output = args.output
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent,
         "canonical existing output parent")
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
             "private owned projection directory")
        need(identity(info)[:5] == identity(output.parent.lstat())[:5], "held named output parent")
        value = {"schema": "heptabao.native-build.v1", "source_commit": PRODUCT, "source_tree": TREE,
            "binary_sha256": actual["heptabao-server"]["sha256"], "build_exit_code": 0,
            "source_freeze_verified": True, "native_abi": next(iter(abis)),
            "provenance": {"original_job_id": args.job_id, "original_inputs": pins,
                "validator": validator_pin, "actual_artifacts": actual,
                "passed_cases": binding["passed_cases"], "source_directory": str(source),
                "original_receipt_status": values["receipt"]["status"],
                "projection_compiler_invocations": 0, "projection_binary_executions": 0,
                "candidate_until_projection_runtime_terminal": True,
                "observations_are_cross_file_atomic": False},
            "physical_ha_qualified": False, "production_authority": False,
            "full_replacement_qualified": False, "elapsed_seconds": time.monotonic() - started}
        raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
        need(len(raw) <= 65536 and time.monotonic() < deadline, "bounded new HA input receipt")
        descriptor = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
        need(identity(os.fstat(parent))[:5] == identity(output.parent.lstat())[:5]
             == identity(info)[:5], "output parent remains named and held")
    finally:
        os.close(parent)
    observed, _ = inspect_file(output, 65536, deadline)
    need(observed["sha256"] == hashlib.sha256(raw).hexdigest() and observed["bytes"] == len(raw)
         and observed["mode"] == 0o600 and time.monotonic() < deadline, "complete private output readback")
    print(json.dumps({"status": "actual_completed_normal107_projected", "output": str(output),
        "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
        "native_abi": value["native_abi"], "physical_ha_qualified": False}, sort_keys=True))


if __name__ == "__main__":
    main()
