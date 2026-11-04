#!/usr/bin/env python3
"""Review-only stdin runner: compile verified sources; optional memory components.

This wrapper is independently reviewed and pinned by the external caller. It
does not execute any target main, reference helper, product, CLI or network.
"""
from __future__ import annotations

# Preload all standard-library dependencies before the no-I/O audit boundary.
import argparse
import ast
import base64
from contextlib import redirect_stdout
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
from types import ModuleType, SimpleNamespace, FunctionType
import types
import zlib

sys.dont_write_bytecode = True
MAX_STDIN = 2 * 1024 * 1024
COMMIT = "49503322c7f446e5eb41e7744f1fdbd7f1192ecc"
TREE = "1d4211f91e1b34a2ed087a3bbef2e2884bac88e9"
NAMES = (
    "phaseb_controller_r3.py", "phaseb_binding_r3.py", "phaseb_evidence_r3.py",
    "native_fixture_reference_r8.py", "official_cli_reference_r4.py",
    "phaseb_evidence_components_r3.py", "phaseb_controller_components_r3.py",
)
SCHEMA = "heptabao.official271-native-cli-phaseb-r3.offline-review.v1"


class DeniedSideEffect(BaseException):
    pass


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--external-wrapper-sha256", required=True)
    parser.add_argument("--components", action="store_true")
    args = parser.parse_args()
    need(sys.flags.isolated == 1 and sys.flags.no_site == 1 and sys.flags.dont_write_bytecode == 1,
         "python_I_S_B_required")
    need(re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256) is not None
         and re.fullmatch(r"[0-9a-f]{64}", args.external_wrapper_sha256) is not None,
         "explicit_external_source_pins")
    raw = sys.stdin.buffer.read(MAX_STDIN + 1)
    need(len(raw) <= MAX_STDIN, "stdin_bound")
    payload = json.loads(raw, object_pairs_hook=unique)
    need(type(payload) is dict and set(payload) == {"schema", "manifest_text", "sources"},
         "exact_stdin_shape")
    need(payload["schema"] == "heptabao.official271-native-cli-phaseb-r3.offline-input.v1",
         "stdin_schema")
    manifest_bytes = payload["manifest_text"].encode("utf-8")
    need(sha(manifest_bytes) == args.manifest_sha256, "manifest_whole_sha")
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique)
    need(manifest["schema"] == "heptabao.official271-native-cli-phaseb-r3.source-draft-manifest.v1"
         and manifest["candidate_commit"] == COMMIT and manifest["candidate_tree"] == TREE,
         "canonical_source_manifest")
    file_list = manifest["files"]
    need(type(file_list) is list and len({item["name"] for item in file_list}) == len(file_list),
         "unique_manifest_files")
    pins = {item["name"]: item for item in file_list}
    need(type(payload["sources"]) is dict and set(payload["sources"]) == set(NAMES),
         "exact_seven_source_inputs")
    compiled = {}
    observations = []
    started = time.monotonic_ns()
    for name in NAMES:
        need(type(payload["sources"][name]) is str, "source_text_type")
        source = payload["sources"][name].encode("utf-8")
        pin = pins[name]
        need(len(source) == pin["bytes"] and sha(source) == pin["sha256"], "source_whole_sha")
        blob = hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest()
        need(blob == pin["blob"], "source_git_blob")
        filename = "<verified-phaseb-r3/" + name + ">"
        tree = ast.parse(source, filename=filename)
        compiled[name] = compile(tree, filename, "exec", dont_inherit=True)
        observations.append({"name": name, "bytes": len(source), "sha256": sha(source),
                             "git_blob": blob, "ast_parsed": True, "compiled_not_executed": True})
    need(time.monotonic_ns() - started < 30_000_000_000, "offline_original_30_second_envelope")

    denied = []
    def audit(event, arguments):
        # No file opening, metadata traversal or writes are needed after all
        # stdlib dependencies and source bytes have been preloaded.
        forbidden = (
            event == "open" or event.startswith("socket.") or event.startswith("subprocess.")
            or event.startswith("os.") or event.startswith("shutil.")
            or event.startswith("ctypes.") or event.startswith("pty.")
            or event in ("sys.settrace", "sys.setprofile", "sys.addaudithook")
        )
        if forbidden:
            denied.append({"event": event})
            raise DeniedSideEffect(event)
    sys.addaudithook(audit)

    executed = []
    results = []
    def memory_module(name):
        module = ModuleType("offline_verified_" + name[:-3])
        module.__file__ = "/pure-memory-verified/" + name
        sys.modules[module.__name__] = module
        exec(compiled[name], module.__dict__)
        executed.append(name)
        return module

    if args.components:
        evidence = memory_module("phaseb_evidence_r3.py")
        controller = memory_module("phaseb_controller_r3.py")
        evidence_cases = memory_module("phaseb_evidence_components_r3.py")
        controller_cases = memory_module("phaseb_controller_components_r3.py")
        for name, cases, target in (
            ("evidence", evidence_cases, evidence),
            ("controller", controller_cases, controller),
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cases.run(target)
            text = buffer.getvalue()
            need(len(text.encode()) <= 256 * 1024, "component_stdout_bound")
            report = json.loads(text, object_pairs_hook=unique)
            need(code == 0 and report["runtime_qualification"] is False
                 and report["network_calls"] == 0 and report["children_spawned"] == 0
                 and report["passed"] == report["total"]
                 and all(item["passed"] is True for item in report["checks"]),
                 "offline_component_failure")
            results.append({"component": name, "report": report, "stdout_sha256": sha(text.encode())})
    need(not denied, "offline_side_effect_attempted")
    need(time.monotonic_ns() - started < 30_000_000_000, "offline_original_30_second_envelope")
    print(json.dumps({
        "schema": SCHEMA, "status": "passed",
        "manifest_sha256": args.manifest_sha256,
        "wrapper_sha256_from_external_invocation_binding": args.external_wrapper_sha256,
        "wrapper_source_self_attestation_claimed": False,
        "input_sha256": sha(raw), "sources": observations,
        "module_definition_execution": executed, "components": results,
        "target_main_called": False, "reference_helpers_executed": False,
        "binding_constructor_called": False,
        "side_effect_audit_denials": denied, "after_guard_file_operations": 0,
        "network_calls": 0, "children_spawned": 0, "product_or_cli_started": False,
        "production_changed": False, "runtime_qualification": False,
        "elapsed_ms": (time.monotonic_ns() - started) / 1e6,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        record = {"schema": SCHEMA, "status": "failed", "error_type": type(error).__name__,
                  "runtime_qualification": False, "target_main_called": False}
        if isinstance(error, SyntaxError):
            record.update(filename=error.filename, line=error.lineno, column=error.offset)
        elif isinstance(error, (RuntimeError, DeniedSideEffect)):
            value = str(error)
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", value):
                record["failure_code"] = value
        print(json.dumps(record, sort_keys=True))
        raise SystemExit(1) from None
