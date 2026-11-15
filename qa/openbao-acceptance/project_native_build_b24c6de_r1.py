#!/usr/bin/env python3
"""Project one actual b24 physical native55 build using the frozen projector."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys

sys.dont_write_bytecode = True
COMMIT = "b24c6de7831a7389e39ac069277a9e85e858ef98"
TREE = "3356f0a94616e9e1804f497239f33546e16db577"
MANIFEST_SHA = "739ffe3589e8b8c6ddca5efe56b4ef3d33a2633fce4451853413b14a6be6c3e1"
RUNNER_SHA = "587eb864f424b236fbc98e41fbc26c5e6c8713ded2e3dee0f2230df7447f66dd"
PROJECTOR_SHA = "39ea2c6c4414b57cf0b9aa662905db1d3e829108e883fe62435401ed184bc0f0"
PROFILES = {
    "main": ("/home/qian-qi/heptabao-next-gates-20261017", "qian-qi", "Linux", "x86_64", "x86_64-unknown-linux-gnu"),
    "mac": ("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261018", "MacBook-Pro.local", "Darwin", "arm64", "aarch64-apple-darwin"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(PROFILES), required=True)
    parser.add_argument("--summary-sha256", required=True)
    parser.add_argument("--binary-sha256", required=True)
    args = parser.parse_args()
    for value in (args.summary_sha256, args.binary_sha256):
        assert re.fullmatch("[0-9a-f]{64}", value), "actual_sha256_input_required"
    base, hostname, system, machine, abi = PROFILES[args.profile]
    assert (platform.node(), platform.system(), platform.machine()) == (hostname, system, machine)
    root = Path(base)
    assert root.resolve() == root and root.is_dir() and root.stat().st_uid == os.geteuid()
    os.umask(0o077)
    source = root / "source-b24c6de"
    manifest = root / "source-b24c6de-manifest.json"
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == MANIFEST_SHA
    projector = source / "qa/openbao-acceptance/native_build_receipt_from_host_run.py"
    assert not projector.is_symlink() and hashlib.sha256(projector.read_bytes()).hexdigest() == PROJECTOR_SHA
    spec = importlib.util.spec_from_file_location("frozen_native_build_projector", projector)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = root / f"native-full55-b24c6de-{args.profile}-r1/summary.json"
    actual = json.loads(module.owned_bytes(summary, 8 * 1024 * 1024))
    module.need(actual.get("source") == str(source) and actual.get("hostname") == hostname,
                "same_actual_producer_source_and_host_required")
    # This is the original streaming projector: all actual build/compiler/file
    # logs, full source-freeze receipt and binary bytes still have to agree.
    value = module.project(summary, args.summary_sha256, manifest, COMMIT, TREE, RUNNER_SHA)
    module.need(value["binary_sha256"] == args.binary_sha256 and value["native_abi"] == abi,
                "explicit_actual_binary_or_native_abi_differs")
    stage = root / "native-lan98-preflight-b24c6de-20261019-r1"
    module.need(not os.path.lexists(stage), "fresh_projection_directory_required")
    stage.mkdir(mode=0o700)
    receipt = stage / "native-build-receipt.json"
    receipt_sha = module.write_new(receipt, value)
    result = {
        "schema": "heptabao.r5-native-build-projection-controller.v1",
        "status": "actual_build_receipt_projected", "profile": args.profile,
        "source_commit": COMMIT, "source_tree": TREE, "source": str(source),
        "actual_summary_sha256": args.summary_sha256, "actual_binary_sha256": args.binary_sha256,
        "projector_sha256": PROJECTOR_SHA, "runner_sha256": RUNNER_SHA,
        "controller_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "receipt": str(receipt), "receipt_sha256": receipt_sha,
        "original_scoped_host_status": value["provenance"]["original_scoped_host_status"],
        "compiler_invocations": 0, "binary_executions": 0, "lan98_executed": False,
    }
    module.write_new(stage / "projection-controller.json", result)
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
