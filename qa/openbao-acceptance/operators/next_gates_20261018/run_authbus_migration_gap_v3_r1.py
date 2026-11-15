#!/usr/bin/env python3
"""Root-operated, fixed-scope controller for the frozen metadata gap v3 scanner.

Default: validate the local scanner and print the execution plan, without any
host call or directory creation. --execute runs once on Runtime main and the
three existing authenticated SSH aliases. All outputs remain metadata only.
An existing operation directory is never reused, deleted, or overwritten.
Python 3.9+ standard library. This controller was prepared locally; preparation
and local tests do not constitute a real-host scan.
"""
from __future__ import annotations

import argparse
import ast
import base64
from datetime import datetime, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import platform
import resource
import shlex
import signal
import stat
import subprocess
import sys
import time


SCANNER_NAME = "authbus_migration_gap_inventory_v3.py"
SCANNER_BYTES = 114576
SCANNER_SHA256 = "6e36468e50e6f458cd970779c2a1d7dda7aa761547381edacdb5e1d37e34d2ce"
PLAN_SHA256 = "a37331721a7560b60029c08db9423dd5eda57dc3855c889c492a4a6b79729644"
SOURCE_RECEIPT_SET_SHA256 = "bf03a5819e325fac277a2de74768c2639dcb9650cf47285d87e77d26a2f1068c"
RECEIPT_SCHEMA = "authbus-migration-gap-metadata-v3"
CONTROLLER_SCHEMA = "authbus-migration-gap-controller-v3-r1"
MAIN_ANCHOR = "/home/qian-qi/heptabao-next-gates-20261017"
CONTROLLER_ROOT = MAIN_ANCHOR + "/authbus-migration-gap-v3-r1-controller"
HOSTS = (
    ("main", MAIN_ANCHOR + "/authbus-migration-gap-v3-r1-main"),
    ("macbook-pro", "/Volumes/T5/hepta-vnext-recovery-20261013/authbus-migration-gap-v3-r1"),
    ("rog", "/home/qian-qi/heptabao-authbus-migration-gap-v3-r1"),
    ("pocket4", "/home/alex/heptabao-authbus-migration-gap-v3-r1"),
)
HOST_TIMEOUT_SECONDS = 45
SCANNER_TIMEOUT_SECONDS = 30
CONTROLLER_ADMISSION_BUDGET_SECONDS = 210
MAX_SCANNER_STDOUT_BYTES = 8 * 1024 * 1024
MAX_TRANSPORT_STDOUT_BYTES = 12 * 1024 * 1024
MAX_TRANSPORT_STDERR_BYTES = 64 * 1024
RECEIPT_PART_BYTES = 36000
QUALIFICATION = {
    "allClientsAndBackupsMigrated": False,
    "backupRestoreQualified": False,
    "providerLivenessQualified": False,
    "productionCutoverQualified": False,
    "legacyCleanupQualified": False,
    "metadataOnly": True,
}
SSH_OPTIONS = (
    "ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
    "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
    "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "PermitLocalCommand=no",
    "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no",
    "-o", "ControlPath=none", "-o", "LogLevel=ERROR",
)


class Refused(Exception):
    pass


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def unique_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise Refused("duplicate_json_key")
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs)


def extract_plan(source):
    if len(source) != SCANNER_BYTES or sha(source) != SCANNER_SHA256:
        raise Refused("scanner_source_binding_mismatch")
    tree = ast.parse(source.decode("utf-8"), feature_version=(3, 9))
    matches = [node for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == "PLAN" for target in node.targets)]
    if len(matches) != 1:
        raise Refused("embedded_plan_assignment")
    call = matches[0].value
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name) and call.func.value.id == "json"
            and call.func.attr == "loads" and len(call.args) == 1
            and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)):
        raise Refused("embedded_plan_format")
    plan = unique_json(call.args[0].value)
    if (sha(canonical(plan)) != PLAN_SHA256
            or plan["source_receipt_set_sha256"] != SOURCE_RECEIPT_SET_SHA256
            or sha(canonical(plan["source_receipt_set"])) != SOURCE_RECEIPT_SET_SHA256):
        raise Refused("embedded_plan_binding_mismatch")
    return plan


def require(flag, reason):
    if not flag:
        raise Refused(reason)


def validate_public_receipt(raw, host, plan):
    """Validate the frozen producer's envelope, exact scope, and read receipts.

    This is a strict execution-binding validator, not a replacement JSON Schema
    implementation and not a credential or migration qualification function.
    """
    require(0 < len(raw) <= MAX_SCANNER_STDOUT_BYTES, "public_receipt_size")
    value = unique_json(raw)
    require(isinstance(value, dict), "public_receipt_object")
    allowed_top = {
        "schema", "created_at", "host_label", "host_label_is_caller_asserted", "source_binding",
        "read_only", "network_called", "subprocess_called", "sql_called", "sdk_imported",
        "credential_file_payloads_read", "credential_values_emitted", "production_mutation",
        "configuration_references", "missing_agents", "secretref_metadata", "authbus_binding_metadata",
        "backup_runtime_entries", "relay_startups", "relay_dependencies", "reused_evidence",
        "pending_boundaries", "gaps", "execution_bounds", "qualification",
    }
    require(set(value) == allowed_top, "public_receipt_field_set")
    require(value["schema"] == RECEIPT_SCHEMA and value["host_label"] == host, "public_receipt_host_schema")
    require(value["host_label_is_caller_asserted"] is True, "caller_host_binding_required")
    require(value["read_only"] is True, "readonly_assertion")
    for key in ("network_called", "subprocess_called", "sql_called", "sdk_imported",
                "credential_file_payloads_read", "credential_values_emitted", "production_mutation"):
        require(value[key] is False, "forbidden_side_effect_assertion")
    require(value["qualification"] == QUALIFICATION, "qualification_promotion_prohibited")
    selected = plan["hosts"][host]
    require(value["source_binding"] == {
        "receipt_set_sha256": SOURCE_RECEIPT_SET_SHA256, "allowlist_canonical_sha256": PLAN_SHA256,
        "original_metadata_receipt": selected["receipt"],
    }, "source_receipt_binding")
    require(value["configuration_references"]["path"] == selected["config"]["path"], "configuration_path")
    comparisons = (
        ("secretref_metadata", "secretrefs", "path", "path"),
        ("authbus_binding_metadata", "binding_files", "path", "path"),
        ("backup_runtime_entries", "backup_runtime", "path", "path"),
        ("relay_startups", "relay_startups", "path", "path"),
        ("relay_dependencies", "relay_dependencies", "path", "path"),
        ("missing_agents", "missing_agents", "planned_agent_dir", "agent_dir"),
    )
    for actual_key, expected_key, actual_path_key, expected_path_key in comparisons:
        actual, expected = value[actual_key], selected[expected_key]
        require(isinstance(actual, list), "scope_list")
        require([item[actual_path_key] for item in actual] == [item[expected_path_key] for item in expected],
                "exact_scope_path_order")
    require(value["pending_boundaries"] == plan["pending_boundaries"], "pending_boundary_promotion")
    require(value["reused_evidence"] == {
        "freshly_scanned": False, "observed_at": selected["receipt"]["created_at"],
        "client_store_metadata": selected["reused_existing_store_metadata"],
        "entrypoint_metadata": selected["reused_entrypoint_metadata"],
    }, "reused_evidence_changed_or_freshness_promoted")
    never = {item["path"] for key in ("secretrefs", "binding_files") for item in selected[key]}
    never.update(item["path"] for item in selected["relay_dependencies"] if item["inspection"] == "metadata_only")
    for item in value["secretref_metadata"]:
        require(item["payload_opened"] is False and item["contents_read"] is False,
                "secretref_payload_opened")
        require(item["credential_source_qualified"] is False and item["migration_complete"] is False,
                "secretref_qualification_promotion")
    for item in value["authbus_binding_metadata"] + value["relay_dependencies"]:
        if item["path"] in never:
            require(item["contents_read"] is False, "binding_or_key_payload_opened")
    for item in value["backup_runtime_entries"]:
        require(item["restore_qualified"] is False and item["backup_consistency_verified"] is False,
                "backup_qualification_promotion")
        require(item.get("full_tree_enumerated", False) is False, "full_backup_inventory_promotion")
    bounds = value["execution_bounds"]
    for key, expected in plan["bounds"].items():
        require(bounds[key] == expected, "original_scan_bound_changed")
    for key, ceiling in (("bytes_read", plan["bounds"]["total_read_bytes"]),
                         ("directory_entries_seen", plan["bounds"]["total_entries"]),
                         ("directories_enumerated", plan["bounds"]["total_directories"])):
        require(type(bounds[key]) is int and 0 <= bounds[key] <= ceiling, "scan_counter_bound")
    require(isinstance(bounds["elapsed_seconds"], (int, float)) and 0 <= bounds["elapsed_seconds"] <= 31,
            "scan_elapsed_bound")
    permitted_hits = {"original_time_budget", "total_read_bytes", "total_directories",
                      "per_directory_entries", "total_entries", "maximum_depth"}
    require(isinstance(bounds["bounds_hit"], list) and set(bounds["bounds_hit"]) <= permitted_hits,
            "unknown_bound_hit")
    exact = {selected["config"]["path"]}
    for key in ("secretrefs", "backup_runtime", "binding_files", "relay_startups", "relay_dependencies"):
        exact.update(item["path"] for item in selected[key])
    for item in selected["missing_agents"]:
        exact.add(item["agent_dir"])
        exact.update(item["existing_file_references"])
    roots = [PurePosixPath(item["path"]) for item in selected["backup_runtime"]]
    successful_bytes = 0
    for operation in bounds["content_read_operations"]:
        require(set(operation) == {"path", "profile", "bytes", "header_only"}, "read_operation_fields")
        path = operation["path"]
        parsed = PurePosixPath(path)
        require(str(parsed) == path and path.startswith("/") and ".." not in parsed.parts,
                "read_operation_path_format")
        permitted = path in exact or any(parsed.is_relative_to(root)
                    and len(parsed.relative_to(root).parts) <= plan["bounds"]["maximum_depth"] for root in roots)
        require(permitted and path not in never and "/auth/" not in path and "/credentials/" not in path,
                "read_operation_scope")
        require(not any(component.lower() in {"keys", "secrets", "tokens", ".ssh", ".aws"}
                        for component in parsed.parts), "sensitive_subtree_read")
        require(type(operation["bytes"]) is int and operation["bytes"] >= 0, "read_operation_byte_count")
        profile = operation["profile"]
        if profile in ("database_magic", "executable_magic"):
            require(operation["header_only"] is True and operation["bytes"] <= 16, "header_read_bound")
        elif profile in ("approved_config", "approved_metadata_projection"):
            ceiling = plan["bounds"]["maximum_config_bytes"] if profile == "approved_config" else plan["bounds"]["maximum_code_bytes"]
            require(operation["header_only"] is False and operation["bytes"] <= ceiling, "projection_read_bound")
        else:
            raise Refused("unknown_read_profile")
        require(not path.endswith(("-wal", "-shm", ".secret", ".key", ".pem", ".p12", ".pfx")), "prohibited_read_suffix")
        successful_bytes += operation["bytes"]
    require(successful_bytes <= bounds["bytes_read"], "successful_read_byte_accounting")
    return value


def receipt_summary(value):
    errors = {}
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key in ("scan_error", "projection_error", "error_class"):
                if key in item:
                    label = str(item[key])
                    errors[label] = errors.get(label, 0) + 1
            stack.extend(v for v in item.values() if isinstance(v, (dict, list)))
        elif isinstance(item, list):
            stack.extend(item)
    bounds = value["execution_bounds"]
    return {
        "host": value["host_label"], "schema": value["schema"], "created_at": value["created_at"],
        "counts": {key: len(value[key]) for key in ("secretref_metadata", "authbus_binding_metadata",
                    "backup_runtime_entries", "missing_agents", "relay_startups", "relay_dependencies", "gaps")},
        "configuration_matches_baseline": value["configuration_references"].get("matches_baseline") is True,
        "configuration_same_file_metadata_at_scan_end": value["configuration_references"].get("same_file_metadata_at_scan_end") is True,
        "item_error_class_counts": errors,
        "bounds_hit": bounds["bounds_hit"], "bytes_read": bounds["bytes_read"],
        "directory_entries_seen": bounds["directory_entries_seen"],
        "directories_enumerated": bounds["directories_enumerated"],
        "scan_elapsed_seconds": bounds["elapsed_seconds"],
        "content_read_operations": len(bounds["content_read_operations"]),
        "qualification": value["qualification"],
        "interpretation": "A bounded metadata receipt was emitted; unresolved items, backup restore, cutover and cleanup remain unqualified.",
    }


def make_new_private_directory(path):
    parsed = PurePosixPath(path)
    require(path.startswith("/") and str(parsed) == path and ".." not in parsed.parts, "operation_directory_format")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in parsed.parts[1:-1]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        os.mkdir(parsed.name, 0o700, dir_fd=fd)
        child = os.open(parsed.name, flags, dir_fd=fd)
        os.fsync(fd)
        return child
    finally:
        os.close(fd)


def write_new(dir_fd, name, payload, mode=0o600):
    require("/" not in name and name not in ("", ".", ".."), "output_name")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as out:
            out.write(payload)
            out.flush()
            os.fsync(fd)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
    os.fsync(dir_fd)
    return {"name": name, "bytes": len(payload), "sha256": sha(payload), "mode": oct(mode)}


def remote_main():
    """Runs on the selected owner; only emits a validated public receipt."""
    input_raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    require(len(input_raw) <= 1024 * 1024, "controller_input_bound")
    request = unique_json(input_raw)
    host = request["host"]
    require(host in dict(HOSTS), "host_label")
    source = base64.b64decode(request["scanner_base64"], validate=True)
    plan = extract_plan(source)
    selected = plan["hosts"][host]
    require(str(Path.home()) == selected["expected_home"] and os.geteuid() == selected["expected_uid"]
            and platform.system() == selected["expected_platform"], "host_owner_context_mismatch")
    require(request["operation_root"] == dict(HOSTS)[host], "exact_operation_root")
    root = request["operation_root"]
    root_fd = make_new_private_directory(root)
    try:
        source_info = write_new(root_fd, SCANNER_NAME, source, 0o500)
        argv = [sys.executable, "-I", "-B", root + "/" + SCANNER_NAME, "--host", host]
        stdout_fd = os.open("scanner.stdout.private.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root_fd)
        stderr_fd = os.open("scanner.stderr.private.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root_fd)
        started = time.monotonic()
        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_SCANNER_STDOUT_BYTES, MAX_SCANNER_STDOUT_BYTES))
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout_fd, stderr=stderr_fd,
                                       close_fds=True, start_new_session=True, preexec_fn=limits)
            timed_out = False
            try:
                returncode = process.wait(timeout=SCANNER_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                returncode = process.wait(timeout=5)
            os.fsync(stdout_fd)
            os.fsync(stderr_fd)
        finally:
            os.close(stdout_fd)
            os.close(stderr_fd)
        stdout_path = Path(root) / "scanner.stdout.private.json"
        stderr_path = Path(root) / "scanner.stderr.private.log"
        stdout = stdout_path.read_bytes()
        stderr = stderr_path.read_bytes()
        source_after = (Path(root) / SCANNER_NAME).read_bytes()
        require(source_after == source, "scanner_source_changed")
        envelope = {
            "schema": "authbus-migration-gap-host-execution-v3-r1", "host": host,
            "operation_root": root, "source": source_info, "source_unchanged": True,
            "host_context": {"home": str(Path.home()), "uid": os.geteuid(), "platform": platform.system()},
            "scanner_argv": argv, "scanner_exit_code": returncode, "scanner_timed_out": timed_out,
            "scanner_process_closed": True, "elapsed_seconds": round(time.monotonic() - started, 6),
            "stdout_bytes": len(stdout), "stdout_sha256": sha(stdout),
            "stderr_bytes": len(stderr), "stderr_sha256": sha(stderr),
            "stderr_contents_emitted": False, "qualification": QUALIFICATION,
        }
        if timed_out:
            envelope.update(status="scanner_timeout", public_receipt=None)
        elif returncode != 0:
            envelope.update(status="scanner_nonzero", public_receipt=None)
            try:
                error = unique_json(stdout)
                if (isinstance(error, dict) and error.get("schema") == RECEIPT_SCHEMA and error.get("ok") is False
                        and isinstance(error.get("error_class"), str)
                        and error["error_class"].isascii() and error["error_class"].isalnum()):
                    envelope["scanner_error_class"] = error["error_class"]
            except (ValueError, Refused):
                pass
        else:
            receipt = validate_public_receipt(stdout, host, plan)
            public_info = write_new(root_fd, "public-receipt.json", stdout)
            envelope.update(status="metadata_received", public_receipt=public_info,
                            summary=receipt_summary(receipt))
        write_new(root_fd, "operation.public.json", canonical(envelope) + b"\n")
        if envelope["status"] == "metadata_received":
            envelope["public_receipt_base64"] = base64.b64encode(stdout).decode("ascii")
        print(json.dumps(envelope, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        os.close(root_fd)


def helper_program():
    names = (Refused, sha, canonical, unique_json, extract_plan, require, validate_public_receipt,
             receipt_summary, make_new_private_directory, write_new, remote_main)
    imports = "import ast,base64,hashlib,json,os,platform,resource,signal,stat,subprocess,sys,time\nfrom pathlib import Path,PurePosixPath\n"
    constants = {name: globals()[name] for name in ("SCANNER_NAME", "SCANNER_BYTES", "SCANNER_SHA256",
        "PLAN_SHA256", "SOURCE_RECEIPT_SET_SHA256", "RECEIPT_SCHEMA", "HOSTS", "QUALIFICATION",
        "SCANNER_TIMEOUT_SECONDS", "MAX_SCANNER_STDOUT_BYTES")}
    definitions = "\n".join(name + " = " + repr(value) for name, value in constants.items()) + "\n"
    body = "\n\n".join(inspect.getsource(value) for value in names)
    tail = "\ntry:\n    raise SystemExit(remote_main())\nexcept Exception as exc:\n    reason = exc.args[0] if isinstance(exc, Refused) and exc.args else None\n    print(json.dumps({'schema':'authbus-migration-gap-host-wrapper-error-v3-r1','error_class':type(exc).__name__,'reason':reason,'details_emitted':False,'qualification':QUALIFICATION}))\n    raise SystemExit(2)\n"
    return imports + definitions + body + tail


def run_transport(argv, payload, root_fd, label, timeout):
    """Bound transport output and lifetime; retain unknown outcomes for review."""
    import selectors
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               close_fds=True, start_new_session=True)
    selector = selectors.DefaultSelector()
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    require(len(payload) < 1024 * 1024, "transport_input_bound")
    os.set_blocking(process.stdin.fileno(), False)
    selector.register(process.stdin, selectors.EVENT_WRITE)
    incoming = {process.stdout: bytearray(), process.stderr: bytearray()}
    limits = {process.stdout: MAX_TRANSPORT_STDOUT_BYTES, process.stderr: MAX_TRANSPORT_STDERR_BYTES}
    sent = 0
    deadline = time.monotonic() + timeout
    boundary = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                boundary = "transport_timeout_outcome_unknown"
                break
            for key, _event in selector.select(min(0.25, remaining)):
                stream = key.fileobj
                if stream is process.stdin:
                    try:
                        sent += os.write(stream.fileno(), payload[sent:sent + 65536])
                    except (BlockingIOError, InterruptedError):
                        continue
                    except BrokenPipeError:
                        sent = len(payload)
                    if sent == len(payload):
                        selector.unregister(stream)
                        stream.close()
                    continue
                room = limits[stream] + 1 - len(incoming[stream])
                try:
                    block = os.read(stream.fileno(), min(65536, room))
                except (BlockingIOError, InterruptedError):
                    continue
                if not block:
                    selector.unregister(stream)
                    stream.close()
                else:
                    incoming[stream].extend(block)
                    if len(incoming[stream]) > limits[stream]:
                        boundary = "transport_output_bound_outcome_unknown"
                        break
            if boundary:
                break
        if boundary:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=5)
        else:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        boundary = "transport_timeout_outcome_unknown"
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=5)
    except Exception:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=5)
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    stdout, stderr = bytes(incoming[process.stdout]), bytes(incoming[process.stderr])
    out_info = write_new(root_fd, label + ".transport.stdout.private.json", stdout)
    err_info = write_new(root_fd, label + ".transport.stderr.private.log", stderr)
    return {"exit_code": process.returncode, "boundary": boundary, "stdout": stdout,
            "stdout_file": out_info, "stderr_file": err_info}


def write_receipt_parts(root_fd, host, raw):
    parts = []
    for ordinal, start in enumerate(range(0, len(raw), RECEIPT_PART_BYTES)):
        payload = raw[start:start + RECEIPT_PART_BYTES]
        part = {"schema": "authbus-migration-gap-public-part-v1", "host": host,
                "offset": start, "decoded_bytes": len(payload), "decoded_sha256": sha(payload),
                "receipt_bytes": len(raw), "receipt_sha256": sha(raw),
                "data_base64": base64.b64encode(payload).decode("ascii")}
        encoded = canonical(part) + b"\n"
        require(len(encoded) <= 65536, "receipt_part_transport_bound")
        parts.append(write_new(root_fd, host + ".public.part-%03d.json" % ordinal, encoded))
    return parts


def execution_plan(source, plan):
    return {"schema": CONTROLLER_SCHEMA, "mode": "plan_only", "remote_called": False,
            "production_mutation": False, "source": {"name": SCANNER_NAME, "bytes": len(source), "sha256": sha(source)},
            "allowlist_canonical_sha256": PLAN_SHA256, "receipt_set_sha256": SOURCE_RECEIPT_SET_SHA256,
            "controller_root": CONTROLLER_ROOT,
            "hosts": [{"host": host, "transport": "runtime_main_local" if host == "main" else "strict_ssh_alias",
                       "operation_root": root, "scanner_argv_tail": ["-I", "-B", root + "/" + SCANNER_NAME, "--host", host],
                       "expected_home": plan["hosts"][host]["expected_home"],
                       "expected_uid": plan["hosts"][host]["expected_uid"],
                       "expected_platform": plan["hosts"][host]["expected_platform"],
                       "reference_counts": {key: len(plan["hosts"][host][key]) for key in
                         ("secretrefs", "binding_files", "backup_runtime", "missing_agents", "relay_startups", "relay_dependencies")}}
                      for host, root in HOSTS],
            "ssh_options": list(SSH_OPTIONS), "scanner_timeout_seconds": SCANNER_TIMEOUT_SECONDS,
            "per_host_transport_timeout_seconds": HOST_TIMEOUT_SECONDS,
            "controller_admission_budget_seconds": CONTROLLER_ADMISSION_BUDGET_SECONDS,
            "owned_transport_cleanup_grace_seconds": 5,
            "required_outer_runtime_timeout_seconds": 300,
            "maximum_scanner_stdout_bytes": MAX_SCANNER_STDOUT_BYTES,
            "maximum_transport_stdout_bytes": MAX_TRANSPORT_STDOUT_BYTES,
            "receipt_part_decoded_bytes": RECEIPT_PART_BYTES,
            "qualification": QUALIFICATION}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, default=Path(__file__).with_name(SCANNER_NAME))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    source = args.scanner.read_bytes()
    plan = extract_plan(source)
    planned = execution_plan(source, plan)
    if not args.execute:
        print(json.dumps(planned, sort_keys=True, indent=2))
        return 0
    main_owner = plan["hosts"]["main"]
    require(str(Path.home()) == main_owner["expected_home"] and os.geteuid() == main_owner["expected_uid"]
            and platform.system() == "Linux", "controller_must_run_on_runtime_main_owner")
    root_fd = make_new_private_directory(CONTROLLER_ROOT)
    records = []
    created_at = datetime.now(timezone.utc).isoformat()
    deadline = time.monotonic() + CONTROLLER_ADMISSION_BUDGET_SECONDS
    try:
        write_new(root_fd, "plan.public.json", canonical(planned) + b"\n")
        helper = helper_program()
        for host, root in HOSTS:
            remaining = deadline - time.monotonic()
            if remaining < HOST_TIMEOUT_SECONDS:
                records.append({"host": host, "status": "not_started_controller_deadline"})
                break
            argv = [sys.executable, "-I", "-B", "-c", helper] if host == "main" else [
                *SSH_OPTIONS, host, shlex.join(["python3", "-I", "-B", "-c", helper])]
            request = canonical({"host": host, "operation_root": root,
                                 "scanner_base64": base64.b64encode(source).decode("ascii")})
            transport = run_transport(argv, request, root_fd, host, HOST_TIMEOUT_SECONDS)
            record = {"host": host, "operation_root": root,
                      "transport": "runtime_main_local" if host == "main" else "strict_ssh_alias",
                      "transport_exit_code": transport["exit_code"],
                      "transport_stdout": transport["stdout_file"], "transport_stderr": transport["stderr_file"],
                      "public_receipt_transferred": False}
            if transport["boundary"]:
                record["status"] = transport["boundary"]
            elif transport["exit_code"] != 0:
                record["status"] = "host_wrapper_or_transport_nonzero_outcome_unresolved"
                try:
                    error = unique_json(transport["stdout"])
                    if (isinstance(error, dict) and error.get("schema") == "authbus-migration-gap-host-wrapper-error-v3-r1"
                            and error.get("qualification") == QUALIFICATION
                            and isinstance(error.get("error_class"), str) and error["error_class"].isalnum()
                            and (error.get("reason") is None or isinstance(error["reason"], str)
                                 and len(error["reason"]) <= 96 and all(c.islower() or c == "_" for c in error["reason"]))):
                        record["host_error"] = {"error_class": error["error_class"], "reason": error.get("reason")}
                except (ValueError, Refused):
                    pass
            else:
                envelope = unique_json(transport["stdout"])
                require(envelope["schema"] == "authbus-migration-gap-host-execution-v3-r1"
                        and envelope["host"] == host and envelope["operation_root"] == root,
                        "host_execution_binding")
                require(envelope["source"]["sha256"] == SCANNER_SHA256 and envelope["source"]["bytes"] == SCANNER_BYTES
                        and envelope["source_unchanged"] is True, "host_executed_source_binding")
                require(envelope["scanner_process_closed"] is True and envelope["qualification"] == QUALIFICATION,
                        "host_execution_closed_and_unqualified")
                require(envelope["host_context"] == {"home": plan["hosts"][host]["expected_home"],
                        "uid": plan["hosts"][host]["expected_uid"], "platform": plan["hosts"][host]["expected_platform"]},
                        "host_execution_owner")
                record["status"] = envelope["status"]
                if envelope["status"] == "metadata_received":
                    require(envelope["scanner_exit_code"] == 0 and envelope["scanner_timed_out"] is False,
                            "successful_scanner_exit")
                    raw = base64.b64decode(envelope.pop("public_receipt_base64"), validate=True)
                    require(sha(raw) == envelope["public_receipt"]["sha256"] == envelope["stdout_sha256"]
                            and len(raw) == envelope["public_receipt"]["bytes"] == envelope["stdout_bytes"],
                            "public_receipt_transfer_binding")
                    receipt = validate_public_receipt(raw, host, plan)
                    record.update(public_receipt_transferred=True,
                                  public_receipt=write_new(root_fd, host + ".public.json", raw),
                                  receipt_parts=write_receipt_parts(root_fd, host, raw),
                                  summary=receipt_summary(receipt))
                record["execution"] = envelope
            record_bytes = canonical(record) + b"\n"
            require(len(record_bytes) <= 65536, "host_operation_receipt_fetch_bound")
            record["operation_receipt"] = write_new(root_fd, host + ".operation.public.json", record_bytes)
            records.append(record)
            if record["status"] not in ("metadata_received", "scanner_nonzero", "scanner_timeout"):
                break
        completed = [v for v in records if v["status"] == "metadata_received"]
        result = {"schema": CONTROLLER_SCHEMA, "mode": "executed", "created_at": created_at,
                  "source": {"name": SCANNER_NAME, "bytes": len(source), "sha256": sha(source)},
                  "receipt_set_sha256": SOURCE_RECEIPT_SET_SHA256, "allowlist_canonical_sha256": PLAN_SHA256,
                  "controller_root": CONTROLLER_ROOT, "attempted_host_count": len(records),
                  "valid_metadata_receipt_count": len(completed), "ok": len(completed) == len(HOSTS),
                  "hosts": [{key: value for key, value in record.items() if key in {
                      "host", "operation_root", "transport", "transport_exit_code", "status",
                      "public_receipt_transferred", "public_receipt", "summary", "operation_receipt", "host_error"}}
                      for record in records],
                  "pending_hosts": [h for h, _ in HOSTS if h not in {v["host"] for v in records}],
                  "qualification": QUALIFICATION, "production_mutation": False,
                  "credential_payloads_transferred": False, "scanner_source_copied_to_new_task_directories": True,
                  "existing_operation_directories_reused": False,
                  "unknown_outcomes_must_be_reconciled_before_any_rerun": True}
        result_bytes = canonical(result) + b"\n"
        require(len(result_bytes) <= 32768, "controller_receipt_fetch_bound")
        receipt_info = write_new(root_fd, "public-receipt.json", result_bytes)
        print(json.dumps({"schema": CONTROLLER_SCHEMA, "ok": result["ok"],
                          "valid_metadata_receipt_count": len(completed),
                          "host_statuses": [{"host": v["host"], "status": v["status"]} for v in records],
                          "receipt_path": CONTROLLER_ROOT + "/public-receipt.json",
                          "receipt": receipt_info, "qualification": QUALIFICATION}, sort_keys=True))
        return 0 if result["ok"] else 3
    finally:
        os.close(root_fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"schema": CONTROLLER_SCHEMA, "ok": False, "error_class": type(exc).__name__,
                          "reason": exc.args[0] if isinstance(exc, Refused) and exc.args else None,
                          "details_emitted": False, "qualification": QUALIFICATION}, sort_keys=True))
        raise SystemExit(2)
