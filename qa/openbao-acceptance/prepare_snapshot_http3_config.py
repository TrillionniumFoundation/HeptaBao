#!/usr/bin/env python3
"""Prepare explicit HTTP3 config from a completed, SHA-pinned host cohort.

This command hashes existing files under the original target's shared lock. It
does not compile, execute a libtest, start a server, or modify the target lock.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types


INPUT_SCHEMA = "heptabao.native-snapshot-http3-preparation.v1"
KEYS = ("source", "source_commit", "source_tree", "manifest", "manifest_sha256", "target_dir", "output",
        "source_runner_sha256", "owned_runner", "owned_runner_sha256", "producer_summary", "producer_summary_sha256")


def prepare(adapter, supplied, destination):
    adapter.need(supplied.get("schema") == INPUT_SCHEMA and set(supplied) == {"schema", *KEYS}, "exact preparation input fields required")
    config = {key: supplied[key] for key in KEYS}
    config["schema"] = adapter.SCHEMA
    destination = Path(destination)
    adapter.need(destination != Path(config["output"]), "config file and future test output directory must differ")
    receipt_path = destination.with_name(destination.name + ".receipt.json")
    for path in (destination, receipt_path):
        adapter.need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent and not path.exists() and not path.is_symlink(), "new canonical config and receipt paths required")
    source, target = Path(config["source"]), Path(config["target_dir"])
    for path in (source, target):
        adapter.need(path.is_absolute() and path.resolve(strict=True) == path and path.is_dir(), "canonical existing source and target required")
        adapter.need(destination != path and path not in destination.parents, "generated config must stay outside source and target")
    summary_path, summary_raw = adapter.pinned_file(config["producer_summary"], config["producer_summary_sha256"])
    producer = adapter.json_bytes(summary_raw)
    compile_row = adapter.command_row(producer, "compile-server-tests")
    retained = {}
    compile_text = adapter.producer_log(summary_path.parent, compile_row, retained)
    matches = re.findall(r"^\s*Executable unittests src/lib\.rs \(([^\r\n()]+)\)\s*$", compile_text, re.MULTILINE)
    adapter.need(len(matches) == 1, "exactly one compiled server libtest required")
    libtest = Path(matches[0])
    adapter.need(libtest.is_absolute() and libtest.resolve(strict=True) == libtest and libtest.parent == target / "debug/deps"
                 and re.fullmatch(r"heptabao_server-[0-9a-f]{16,64}", libtest.name), "compiled artifact must be inside the explicit owned target")
    info = libtest.lstat()
    adapter.need(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111, "regular native executable artifact required")
    helper_path, helper_raw = adapter.pinned_file(config["owned_runner"], config["owned_runner_sha256"])
    helper = adapter.load_module(helper_path, helper_raw, "http3_config_owned_helper")
    config["libtest"] = str(libtest)
    config["build_profile"] = {
        "cargo": adapter.command_row(producer, "cargo-version")["argv"][0],
        "rustc": adapter.command_row(producer, "rustc-version")["argv"][0],
        "rust_release": "1.98.0", "server_features": adapter.FEATURES,
        "compiler_resource_profile": producer["compiler_resource_profile"],
    }
    lock_path = target / helper.LOCK_NAME
    descriptor = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as lock:
        adapter.need(stat.S_ISREG(os.fstat(lock.fileno()).st_mode), "original regular target lock required")
        fcntl.flock(lock.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        original_lock = lock.read()
        config["libtest_sha256"] = helper.sha256_file(libtest)
        context = adapter.load_context(config)
        source_evidence = context[4].verify_tree(context[0], context[3])
        adapter.need(helper.sha256_file(libtest) == config["libtest_sha256"], "artifact changed during preparation")
        for path, digest in context[8].items():
            adapter.pinned_file(path, digest)
        lock.seek(0)
        adapter.need(lock.read() == original_lock, "original lock receipt changed during shared custody")
        raw = (json.dumps(config, indent=2) + "\n").encode()
        receipt = {"schema": "heptabao.native-snapshot-http3-preparation-receipt.v1", "prepared_utc": helper.utc(),
                   "config": str(destination), "config_sha256": adapter.sha(raw), "config_bytes": len(raw),
                   "libtest": str(libtest), "libtest_sha256": config["libtest_sha256"],
                   "producer_summary_sha256": config["producer_summary_sha256"], "source_verification": source_evidence,
                   "target_shared_lock_held": True, "original_lock_receipt_unchanged": True,
                   "processes_started": 0, "Rust_tests_executed": 0, "compiler_invocations": 0,
                   "HTTP_tests_still_pending": True}
        for path, content in ((destination, raw), (receipt_path, (json.dumps(receipt, indent=2) + "\n").encode())):
            with path.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("adapter", "input", "config-out"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("adapter-sha256", "input-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    adapter_path = args.adapter
    if (not adapter_path.is_absolute() or adapter_path.resolve(strict=True) != adapter_path
            or not stat.S_ISREG(adapter_path.lstat().st_mode)):
        parser.error("canonical regular adapter path required")
    raw = adapter_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.adapter_sha256:
        parser.error("adapter SHA256 differs from explicit pin")
    adapter = types.ModuleType("verified_http3_adapter")
    adapter.__file__ = str(adapter_path)
    exec(compile(raw, str(adapter_path), "exec"), adapter.__dict__)
    _, input_raw = adapter.pinned_file(args.input, args.input_sha256)
    receipt = prepare(adapter, adapter.json_bytes(input_raw), args.config_out)
    print(json.dumps(receipt), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
