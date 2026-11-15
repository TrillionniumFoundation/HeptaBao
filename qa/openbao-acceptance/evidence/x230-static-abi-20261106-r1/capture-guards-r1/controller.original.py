#!/usr/bin/env python3
"""Capture current normal artifacts and the actual X230 ELF provider closure.

This invokes only pinned readelf and, on the receiver, pinned ldconfig -p.
It never executes a candidate, changes the loader cache, or grants runtime
qualification. A completed normal107 projection and authoritative terminals
must already exist. Every output is new and every input is rechecked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import stat
import subprocess
import sys
import time

PRODUCT = "4bde9aee03fcd27c59e13607e529b1cee594b249"
TREE = "f08493a23f8ea0637073651231865ea9607b790e"
HELPER_SHA = "1b6594238cfaf26a2411ec422a858f9958626c98e2d5dece8464f24ee8ed73b4"
NAMES = {"heptabao-server", "heptabao-seed"}
HOSTS = {"producer": "alex-G1628-04", "receiver": "qian-ThinkPad-X230"}
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
MAXIMUM = 256 * 1024 * 1024


class Refused(RuntimeError):
    pass


def need(value, label):
    if not value:
        raise Refused(label)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def identity(info):
    return [getattr(info, key) for key in
            ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
             "st_size", "st_mtime_ns", "st_ctime_ns")]


def file_pin(path, deadline, *, system=False, maximum=MAXIMUM, contents=False):
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(path), "absolute_literal_input_path")
    resolved = path.resolve(strict=True)
    if system:
        for parent in (path.parent, *path.parents, resolved.parent, *resolved.parents):
            info = parent.stat()
            need(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022,
                 "root_controlled_system_path")
        alias = path.lstat()
        need(alias.st_uid == 0 and (stat.S_ISREG(alias.st_mode) or stat.S_ISLNK(alias.st_mode)),
             "root_controlled_system_alias")
    else:
        need(resolved == path, "private_input_symlink_refused")
    before = resolved.lstat()
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum
         and before.st_uid == (0 if system else os.geteuid())
         and not stat.S_IMODE(before.st_mode) & (0o022 if system else 0o077)
         and (system or before.st_nlink == 1), "regular_owned_input_custody")
    original = identity(before)
    digest, header, collected = hashlib.sha256(), b"", []
    with open(resolved, "rb", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW)) as stream:
        need(identity(os.fstat(stream.fileno())) == original, "input_changed_at_open")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            need(time.monotonic() < deadline, "capture_absolute_deadline")
            digest.update(block)
            header = (header + block)[:64]
            if contents:
                collected.append(block)
        need(identity(os.fstat(stream.fileno())) == original, "input_changed_while_reading")
    need(identity(resolved.lstat()) == original and path.resolve(strict=True) == resolved,
         "input_named_identity_changed")
    return {"path": str(resolved), "bytes": before.st_size, "sha256": digest.hexdigest(),
            "identity": original, "mode": stat.S_IMODE(before.st_mode)}, (b"".join(collected) if contents else header)


def require_pin(actual, expected):
    need(isinstance(expected, dict) and set(expected) >= {"path", "bytes", "sha256"}
         and actual["path"] == expected["path"] and actual["bytes"] == expected["bytes"]
         and actual["sha256"] == expected["sha256"]
         and re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]), "exact_observed_input_pin")


def require_terminal(value, job):
    need(value.get("job_id") == job and value.get("state") == "succeeded"
         and type(value.get("exit_code")) is int and value["exit_code"] == 0,
         "successful_authoritative_terminal_required")
    need(all(value.get(key) is True for key in
             ("output_complete", "output_durable", "terminal_publication_confirmed"))
         and all(value.get(key) is False for key in ("timed_out", "cancelled", "automatic_retry")),
         "complete_durable_terminal_without_retry_required")
    need(set(value.get("log_bytes", {})) == {"stdout", "stderr"}
         and all(type(row.get("seen")) is int and row["seen"] >= 0
                 and type(row.get("stored")) is int and row["stored"] == row["seen"]
                 for row in value["log_bytes"].values())
         and all(value.get("log_synced", {}).get(key) is True
                 and value.get("log_truncated", {}).get(key) is False
                 and value.get("log_errors", {}).get(key) is None for key in ("stdout", "stderr")),
         "complete_original_log_publication")


def projection_artifacts(value, normal_job):
    provenance = value.get("provenance", {})
    need(value.get("schema") == "heptabao.native-build.v1"
         and value.get("source_commit") == PRODUCT and value.get("source_tree") == TREE
         and type(value.get("build_exit_code")) is int and value["build_exit_code"] == 0
         and value.get("source_freeze_verified") is True
         and value.get("native_abi") == "x86_64-unknown-linux-gnu"
         and provenance.get("original_job_id") == normal_job
         and provenance.get("passed_cases") == 107
         and provenance.get("original_receipt_status") == "passed"
         and provenance.get("projection_compiler_invocations") == 0
         and provenance.get("projection_binary_executions") == 0,
         "actual_normal107_native_projection_required")
    artifacts = provenance.get("actual_artifacts", {})
    need(set(artifacts) == NAMES and value.get("binary_sha256") == artifacts["heptabao-server"].get("sha256"),
         "both_exact_projected_normal_artifacts_required")
    for name, pin in artifacts.items():
        need(isinstance(pin, dict) and type(pin.get("bytes")) is int and 0 < pin["bytes"] <= MAXIMUM
             and re.fullmatch(r"[0-9a-f]{64}", pin.get("sha256", ""))
             and pin.get("mode") == 0o700 and Path(pin.get("path", "")).is_absolute(),
             "projected_normal_artifact_custody")
    return artifacts


def parse_cache(raw):
    lines = raw.splitlines()
    need(lines and re.fullmatch(r"\d+ libs found in cache `[^`]+[`']", lines[0]),
         "complete_loader_cache_header")
    count = int(lines[0].split()[0])
    entries, tail = [], []
    for line in lines[1:]:
        match = re.fullmatch(r"\s*([A-Za-z0-9_.+-]+)\s+\(([^)]+)\)\s+=>\s+(/[A-Za-z0-9_./+-]+)\s*", line)
        if match:
            need(not tail and "/../" not in match[3] and "//" not in match[3],
                 "literal_loader_cache_entry")
            entries.append(match.groups())
        elif line:
            tail.append(line)
    need(len(entries) == count and len(tail) <= 1
         and (not tail or re.fullmatch(r"Cache generated by: ldconfig .+", tail[0])),
         "complete_loader_cache_entry_count")
    need(len(entries) == len(set(entries)), "duplicate_loader_cache_entry")
    result = {}
    for name, flags, path in entries:
        if "x86-64" in [flag.strip() for flag in flags.split(",")]:
            result.setdefault(name, []).append(path)
    return result


def choose_provider(name, cache, interpreter):
    paths = list(cache.get(name, []))
    if name == Path(interpreter).name:
        paths.append(interpreter)
    need(paths, "unresolved_receiver_provider")
    resolved = {str(Path(path).resolve(strict=True)) for path in paths}
    need(len(resolved) == 1, "ambiguous_receiver_provider")
    return next(iter(resolved)), sorted(set(paths))


class Capture:
    def __init__(self, manifest, root, deadline, helper):
        self.manifest, self.root, self.deadline, self.helper = manifest, root, deadline, helper
        self.inputs, self.tools, self.commands = {}, {}, []

    def input_json(self, label, maximum=8 * 1024 * 1024):
        expected = self.manifest[label]
        pin, raw = file_pin(expected["path"], self.deadline, maximum=maximum, contents=True)
        require_pin(pin, expected)
        self.inputs[label] = pin
        return json.loads(raw)

    def tool(self, label):
        expected = self.manifest["tools"][label]
        actual, header = file_pin(expected["path"], self.deadline, system=True)
        require_pin(actual, expected)
        need(header[:4] == b"\x7fELF" and actual["mode"] & 0o111, "existing_native_system_tool")
        self.tools[label] = actual
        return actual["path"]

    def command(self, label, argv):
        need(re.fullmatch(r"[A-Za-z0-9_.+-]+", label), "literal_output_label")
        remaining = self.deadline - time.monotonic()
        need(remaining > 0, "capture_absolute_deadline")
        cap = min(15, remaining)
        out, err = self.root / (label + ".stdout"), self.root / (label + ".stderr")
        def bounded_file_output():
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        begin, timed_out, code = time.monotonic(), False, None
        with out.open("xb") as stdout, err.open("xb") as stderr:
            try:
                done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                    env=ENV, timeout=cap, check=False, preexec_fn=bounded_file_output)
                code = done.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
            stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
        stdout, stderr = out.read_bytes(), err.read_bytes()
        row = {"label": label, "argv": argv, "exit_code": code, "timed_out": timed_out,
               "requested_cap_seconds": 15, "effective_cap_seconds": cap,
               "elapsed_seconds": time.monotonic() - begin,
               "stdout_bytes": len(stdout), "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
               "stderr_bytes": len(stderr), "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
        self.commands.append(row)
        need(not timed_out and code == 0 and not stderr and len(stdout) <= 1024 * 1024,
             "completed_bounded_read_only_tool_required")
        return stdout.decode("utf-8"), row

    def elf(self, label, path, *, system, expected=None):
        before, header = file_pin(path, self.deadline, system=system)
        if expected is not None:
            require_pin(before, expected)
        raw, command = self.command(label, [self.tools["readelf"]["path"], "-W", "-h", "-l", "-d",
                                            "--version-info", before["path"]])
        after, again = file_pin(path, self.deadline, system=system)
        need(before == after and header == again, "elf_input_changed_during_observation")
        parsed = self.helper["parse_elf_observation"](header.hex(), raw)
        return {"pin": before, "pin_before": before, "pin_after": after, "header_hex": header.hex(),
                "raw_readelf": raw, "elf": parsed, "command": command}

    def producer(self):
        projection = self.input_json("native_projection")
        require_terminal(self.input_json("projection_terminal"), self.manifest["projection_job_id"])
        pins = projection_artifacts(projection, self.manifest["normal107_job_id"])
        need(set(self.manifest["expected_artifacts"]) == NAMES, "two_manifest_artifacts_required")
        for name, pin in pins.items():
            require_pin(pin, self.manifest["expected_artifacts"][name])
        artifacts = {name: self.elf(name, pin["path"], system=False, expected=pin)
                     for name, pin in sorted(pins.items())}
        return {"artifacts": artifacts, "normal107_job_id": self.manifest["normal107_job_id"],
                "native_projection_binding": {"source_commit": PRODUCT, "source_tree": TREE,
                    "normal107_passed_cases": 107, "artifact_pins": pins,
                    "projection_job_id": self.manifest["projection_job_id"]},
                "static_receiver_compatibility_qualified": False}

    def receiver(self):
        producer = self.input_json("producer_receipt")
        require_terminal(self.input_json("producer_terminal"), self.manifest["producer_job_id"])
        need(producer.get("schema") == "heptabao.current-native-static-abi-capture.v1"
             and producer.get("status") == "passed" and producer.get("role") == "producer"
             and producer.get("hostname") == HOSTS["producer"]
             and producer.get("source_commit") == PRODUCT and producer.get("source_tree") == TREE
             and producer.get("target_binary_executions") == 0
             and producer.get("inputs_unchanged") is True
             and producer.get("normal107_job_id") == self.manifest["normal107_job_id"],
             "completed_exact_producer_static_capture_required")
        artifacts = producer["artifacts"]
        need(set(artifacts) == set(self.manifest["expected_artifacts"]) == NAMES,
             "two_bound_producer_artifacts_required")
        for name, row in artifacts.items():
            require_pin(row["pin"], self.manifest["expected_artifacts"][name])
        interpreter = self.manifest["interpreter_path"]
        need(interpreter == "/lib64/ld-linux-x86-64.so.2", "literal_current_x230_interpreter")
        loader, _ = file_pin(interpreter, self.deadline, system=True)
        require_pin(loader, self.manifest["interpreter_pin"])
        cache_before, _ = file_pin("/etc/ld.so.cache", self.deadline, system=True)
        raw, _ = self.command("ldconfig-cache", [self.tool("ldconfig"), "-p"])
        cache = parse_cache(raw)
        providers, lookup, pending = {}, {}, {Path(interpreter).name}
        for row in artifacts.values():
            parsed = self.helper["parse_elf_observation"](row["header_hex"], row["raw_readelf"])
            pending.update(parsed["needed"])
        while pending - set(providers):
            need(len(pending) <= 32, "bounded_recursive_provider_closure")
            name = sorted(pending - set(providers))[0]
            path, candidates = choose_provider(name, cache, interpreter)
            row = self.elf("provider-" + name, path, system=True)
            need(row["elf"]["soname"] == name, "actual_receiver_provider_soname")
            providers[name], lookup[name] = row, candidates
            pending.update(row["elf"]["needed"])
        result = self.helper["verify_compatibility"](artifacts, providers,
            expected_artifact_pins=self.manifest["expected_artifacts"], interpreter_path=interpreter,
            interpreter_resolved_path=loader["path"])
        need(file_pin(interpreter, self.deadline, system=True)[0] == loader
             and file_pin("/etc/ld.so.cache", self.deadline, system=True)[0] == cache_before,
             "receiver_loader_or_cache_changed")
        return {"artifacts": artifacts, "providers": providers, "provider_lookup_candidates": lookup,
                "interpreter_pin": loader, "loader_cache_pin": cache_before, "compatibility": result,
                "normal107_job_id": self.manifest["normal107_job_id"],
                "static_receiver_compatibility_qualified": True}

    def recheck(self, result):
        for original in self.inputs.values():
            need(file_pin(original["path"], self.deadline, maximum=8 * 1024 * 1024)[0] == original,
                 "provenance_input_changed")
        for original in self.tools.values():
            need(file_pin(original["path"], self.deadline, system=True)[0] == original, "system_tool_changed")
        rows = result["artifacts"] if self.manifest["role"] == "producer" else result["providers"]
        for row in rows.values():
            need(file_pin(row["pin"]["path"], self.deadline,
                          system=self.manifest["role"] == "receiver")[0] == row["pin"],
                 "captured_elf_changed_before_completion")


def main():
    start = time.monotonic()
    deadline = start + 60
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    need(sys.flags.isolated == 1 and sys.flags.no_site == 1 and sys.dont_write_bytecode,
         "isolated_no_site_no_bytecode_interpreter_required")
    manifest_pin, raw = file_pin(args.manifest, deadline, maximum=128 * 1024, contents=True)
    need(manifest_pin["sha256"] == args.manifest_sha256, "fixed_reviewed_capture_manifest")
    manifest = json.loads(raw)
    role = manifest["role"]
    need(manifest.get("schema") == "heptabao.current-native-static-abi-capture-inputs.v1"
         and role in HOSTS and manifest.get("source_commit") == PRODUCT and manifest.get("source_tree") == TREE
         and platform.node() == HOSTS[role] and platform.system() == "Linux"
         and platform.machine() == "x86_64" and os.geteuid() == 1000, "exact_linux_producer_or_receiver")
    need(set(manifest.get("tools", {})) == ({"readelf"} if role == "producer" else {"readelf", "ldconfig"}),
         "closed_read_only_system_tool_set")
    helper_path = Path(__file__).resolve().with_name("x230_native_abi_admission.py")
    helper_pin, helper_raw = file_pin(helper_path, deadline, maximum=65536, contents=True)
    need(helper_pin["sha256"] == HELPER_SHA, "reviewed_strict_elf_parser")
    helper = {"__name__": "bound_x230_abi_admission"}
    exec(compile(helper_raw, str(helper_path), "exec"), helper)
    own_pin, _ = file_pin(Path(__file__).resolve(), deadline, maximum=65536)
    root = Path(manifest["output_directory"])
    need(root.is_absolute() and root.parent.resolve(strict=True) == root.parent,
         "canonical_existing_capture_parent")
    parent = root.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
         and stat.S_IMODE(parent.st_mode) == 0o700, "private_owned_capture_parent")
    root.mkdir(mode=0o700)
    root_identity = identity(root.lstat())[:6]
    report = {"schema": "heptabao.current-native-static-abi-capture.v1", "status": "failed", "role": role,
              "hostname": platform.node(), "source_commit": PRODUCT, "source_tree": TREE,
              "manifest": manifest_pin, "controller": own_pin, "parser": helper_pin,
              "target_binary_executions": 0, "compiler_invocations": 0, "production_changed": False,
              "actual_x230_runtime_qualified": False, "full_replacement_qualified": False,
              "capture_budget_seconds": 60, "deadline_renewed": False, "automatic_retry": False}
    capture = Capture(manifest, root, deadline, helper)
    try:
        capture.tool("readelf")
        result = capture.producer() if role == "producer" else capture.receiver()
        capture.recheck(result)
        need(file_pin(args.manifest, deadline, maximum=128 * 1024)[0] == manifest_pin
             and file_pin(helper_path, deadline, maximum=65536)[0] == helper_pin
             and file_pin(Path(__file__).resolve(), deadline, maximum=65536)[0] == own_pin,
             "capture_source_or_manifest_changed")
        need(time.monotonic() < deadline, "capture_absolute_deadline")
        report.update(result, status="passed", inputs_unchanged=True)
    except BaseException as error:
        reason = str(error)
        report["failure"] = reason if isinstance(error, (Refused, helper["AbiRefused"])) and re.fullmatch(
            r"[A-Za-z0-9_]{1,160}", reason) else type(error).__name__
    finally:
        report.update(inputs=capture.inputs, tools=capture.tools, commands=capture.commands,
                      elapsed_seconds=time.monotonic() - start)
        need(identity(root.lstat())[:6] == root_identity, "owned_capture_directory_changed")
        data = encode(report)
        need(len(data) <= 8 * 1024 * 1024, "bounded_public_capture_result")
        with (root / "result.public.json").open("xb") as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        print(json.dumps({"status": report["status"], "role": role, "result": str(root / "result.public.json"),
                          "target_binary_executions": 0, "actual_x230_runtime_qualified": False}), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
