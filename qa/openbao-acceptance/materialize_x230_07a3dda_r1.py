#!/usr/bin/env python3
"""Reuse the frozen R6 materializer on X230; do not compile or start a service."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import sys
import time

sys.dont_write_bytecode = True
STAGER_SHA = "18428fa9c0bbab511559002ce88895263a8b45415b2a10ff1fedcf4e51122f4e"
PACKET_SHA = "eed541a75491bfeeb4024bcaa32e271c02303ee02797e4d37e3fb97e8712bdca"
ROOT = Path("/home/qian/heptabao-continuation-20261019")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stager", type=Path, required=True)
    parser.add_argument("--packet", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    assert (platform.system(), platform.machine(), platform.node()) == (
        "Linux", "x86_64", "qian-ThinkPad-X230")
    assert os.geteuid() == 1000 and pwd.getpwuid(os.geteuid()).pw_dir == "/home/qian"
    assert ROOT.is_dir() and ROOT.resolve() == ROOT and ROOT.stat().st_uid == os.geteuid()
    for path in (args.stager, args.packet):
        assert path.is_absolute() and path.resolve() == path and path.is_relative_to(ROOT)
        assert path.is_file() and not path.is_symlink() and path.stat().st_uid == os.geteuid()
    assert hashlib.sha256(args.stager.read_bytes()).hexdigest() == STAGER_SHA
    spec = importlib.util.spec_from_file_location("frozen_r6_plain_materializer", args.stager)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    started = time.monotonic()
    until = started + module.STAGING_SECONDS
    documents, packet_receipt = module.load_packet(args.packet, PACKET_SHA)
    old_source = ROOT / "source-b24c6de"
    new_source = ROOT / "source-07a3dda"
    new_manifest = ROOT / "source-07a3dda-manifest.json"
    controller = ROOT / "source-07a3dda-materialization-r1-controller"
    module.owned_directory(old_source)
    module.exact_regular(ROOT / "source-b24c6de-manifest.json", module.BASE_MANIFEST_SHA)
    for path in (new_source, new_manifest, controller):
        module.require(not os.path.lexists(path), "fresh_path_already_exists:" + str(path))
    runner = old_source / module.RUNNER_PATH
    module.exact_regular(runner, module.RUNNER_SHA)
    spec = importlib.util.spec_from_file_location("exact_original_native55_checker", runner)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    module.require(len(checker.GROUPS) == 17 and sum(row[3] for row in checker.GROUPS) == 55,
                   "original_55_group_contract_differs")
    controller.mkdir(mode=0o700)
    module.new_json(controller / "intent.json", {
        "schema": "heptabao.x230-r6-source-only-intent.v1",
        "created_utc": module.utc(), "source_commit": module.COMMIT,
        "source_tree": module.TREE, "stager_sha256": STAGER_SHA,
        "packet": packet_receipt, "source": str(new_source),
        "automatic_retry": False, "staging_seconds": module.STAGING_SECONDS,
        "compiler_invocations": 0, "processes_started": 0})
    try:
        observed = module.materialize(
            old_source, new_source, documents["base_manifest"][1],
            documents["target_manifest"][1], documents["candidate"][1], checker, until)
        module.new_file(new_manifest, documents["target_manifest"][0])
        module.require(time.monotonic() < until, "original_staging_deadline_expired")
        result = {
            "schema": "heptabao.x230-r6-source-only-result.v1",
            "status": "exact_source_materialized", "finished_utc": module.utc(),
            "hostname": platform.node(), "source": str(new_source),
            "source_commit": module.COMMIT, "source_tree": module.TREE,
            "manifest_sha256": module.MANIFEST_SHA,
            "stager_sha256": STAGER_SHA, "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "observed": observed, "elapsed_to_materialization_seconds": time.monotonic() - started,
            "compiler_invocations": 0, "processes_started": 0,
            "actual_55_execution_performed": False, "compiled_on_executor": False}
        module.new_json(controller / "materialization.json", result)
        print(json.dumps(result, sort_keys=True), flush=True)
    except BaseException as error:
        module.new_json(controller / "failure.json", {
            "status": "failed_or_unknown", "error_type": type(error).__name__,
            "elapsed_seconds": time.monotonic() - started,
            "automatic_retry": False, "partial_source_preserved": True,
            "compiler_invocations": 0, "processes_started": 0})
        raise


if __name__ == "__main__":
    main()
