#!/usr/bin/env python3
"""Own two fresh TLS servers and exercise the original lossless KV2 migration.

This controller never accepts an existing endpoint or credential. The official
OpenBao 2.7.1 archive/executable must already exist and match the checked-in pins.
The native-small profile diagnoses the dedicated V6 importer independently of
the original raw-record and bundle size limits. Only full34 can qualify full34.
"""
from __future__ import annotations

import argparse
import base64
from decimal import Decimal
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
HTTP_SECONDS = 15
MIGRATION_SECONDS = 360
JSON_BYTES = 4 * MIB
ARCHIVE_BYTES = 128 * MIB
PROFILES = {
    "full34": (17, 2 * MIB, True),
    "raw2": (1, 2 * MIB, True),
    "bundle34": (68, 512 * 1024, True),
    "legacy8": (17, 512 * 1024, False),
    "legacy-small": (2, 4096, False),
    "native-small": (2, 4096, True),
}
STORAGE_CHECKS = (
    "target_storage_full_history_exact",
    "target_storage_cold_history_exact",
    "restored_storage_history_exact",
)
CHECKS = (
    "official_271_pins_and_live_identity",
    "two_distinct_owned_processes",
    "source_api_oracle_captured",
    "source_retained_deleted_destroyed_seeded",
    "source_metadata_cas_seeded",
    "source_cold_restart_exact",
    "target_pristine_before_import",
    "source_export_once",
    "source_raw_history_exact",
    "exported_soft_deleted_payload_preserved",
    "source_unchanged_after_export",
    "target_import_once",
    "target_active_native_v6",
    "target_full_history_exact",
    "target_storage_full_history_exact",
    "target_cold_restart_exact",
    "target_storage_cold_history_exact",
    "snapshot_download",
    "post_snapshot_mutation_once",
    "snapshot_restore_once",
    "restored_cold_history_exact",
    "restored_storage_history_exact",
    "soft_deleted_payload_undelete_exact",
    "destroyed_payload_remains_absent",
    "data_cas_denied_without_effect",
    "metadata_cas_denied_without_effect",
    "metadata_cas_success_counter_exact",
    "source_unchanged_after_target_mutations",
    "source_and_binary_unchanged",
    "owned_processes_stopped",
    "report_excludes_runtime_credentials",
)


class Failure(RuntimeError):
    """Only fixed, locally authored labels enter public diagnostics."""


def need(condition, label):
    if not condition:
        raise Failure(label)


def unique(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(raw):
    need(isinstance(raw, bytes) and len(raw) <= ARCHIVE_BYTES, "json_byte_bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_float=Decimal,
                           parse_constant=lambda _: need(False, "nonfinite_json"))
        pending = [(value, 0)]
        nodes = 0
        while pending:
            current, depth = pending.pop()
            nodes += 1
            need(nodes <= 1000000 and depth <= 128, "json_structural_bound")
            if isinstance(current, dict):
                for key, child in current.items():
                    key.encode("utf-8")
                    pending.append((child, depth + 1))
            elif isinstance(current, list):
                pending.extend((child, depth + 1) for child in current)
            elif isinstance(current, str):
                current.encode("utf-8")
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Failure("invalid_lossless_json") from error


def canonical(value):
    def emit(item):
        if isinstance(item, Decimal):
            need(item.is_finite(), "nonfinite_json")
            return str(item)
        if item is None or isinstance(item, (str, bool, int)):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(emit(child) for child in item) + "]"
        if isinstance(item, dict):
            need(all(isinstance(key, str) for key in item), "json_string_keys")
            return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" + emit(item[key])
                                  for key in sorted(item)) + "}"
        raise Failure("unsupported_json_type")
    return emit(value).encode("utf-8")


def same_json_tokens(left, right):
    """Ignore object order, while retaining integer/decimal token precision."""
    return canonical(left) == canonical(right)


def private_write(path, raw, *, replace=False):
    path = Path(path)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    need(isinstance(raw, bytes), "private_output_bytes")
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_TRUNC if replace else os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
             and info.st_nlink == 1 and info.st_mode & 0o077 == 0, "private_output_identity")
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def private_read(path, maximum=ARCHIVE_BYTES):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
             and info.st_nlink == 1 and info.st_mode & 0o077 == 0
             and info.st_size <= maximum, "private_input_identity")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        need(all(getattr(info, key) == getattr(after, key) for key in fields)
             and len(raw) == info.st_size, "private_input_changed")
        return raw
    finally:
        os.close(fd)


def payload(version, live_count, size):
    need(1 <= version <= live_count + 2, "payload_version")
    return {"ordinal": version,
            "payload": chr(65 + version % 26) * (1024 if version < 3 else size),
            "wide_integer": 9007199254740993,
            "exact_decimal": Decimal("0.123456789012345678901234567890"),
            "unicode": "凭证迁移试验🧪",
            "nested": [None, True, {"zero": "\\u0000"}]}


def http_leaf():
    """One bounded request; bearer and response bytes stay on anonymous pipes."""
    packet = json.loads(sys.stdin.buffer.read(12 * MIB + 1))
    origin = urlsplit(packet["address"])
    need(origin.scheme == "https" and origin.hostname == "127.0.0.1"
         and not origin.username and not origin.password and not origin.path
         and not origin.query and not origin.fragment
         and origin.port is not None, "literal_loopback_tls_required")
    path = packet["path"]
    need(isinstance(path, str) and path and not path.startswith("/")
         and "#" not in path and not any(ord(c) < 32 for c in path), "fixed_api_path")
    method = packet["method"]
    need(method in ("GET", "POST", "DELETE", "LIST"), "fixed_http_method")
    token = packet["token"]
    need(isinstance(token, str) and len(token) <= 65536
         and all(32 < ord(c) < 127 for c in token), "private_http_token")
    archive_in, archive_out = packet["archive_in"], packet["archive_out"]
    need(not (archive_in and archive_out), "archive_direction")
    raw = None if packet["body"] is None else base64.b64decode(packet["body"], validate=True)
    need(raw is None or len(raw) <= JSON_BYTES, "http_json_body_bound")
    if archive_in:
        need(method == "POST" and raw is None, "archive_upload_method")
        raw = private_read(archive_in)
    if archive_out:
        need(method == "GET" and raw is None, "archive_download_method")
    context = ssl.create_default_context(cafile=packet["ca_file"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # http.client has neither environment proxies nor automatic redirects.
    connection = http.client.HTTPSConnection("127.0.0.1", origin.port,
                                             context=context, timeout=HTTP_SECONDS)
    try:
        connection.request(method, "/v1/" + path, body=raw, headers={
            "X-Vault-Token": token, "Accept": "application/json",
            "Content-Type": "application/octet-stream" if archive_in else "application/json",
            "Connection": "close",
        })
        response = connection.getresponse()
        need(not 300 <= response.status < 400, "http_redirect_refused")
        limit = ARCHIVE_BYTES if archive_out and response.status == 200 else JSON_BYTES
        body = response.read(limit + 1)
        need(len(body) <= limit, "http_response_bound")
        if archive_out and response.status == 200:
            private_write(archive_out, body)
            result = {"status": response.status, "archive_bytes": len(body),
                      "archive_sha256": hashlib.sha256(body).hexdigest()}
        else:
            result = {"status": response.status, "body": base64.b64encode(body).decode("ascii")}
        sys.stdout.write(json.dumps(result))
    finally:
        connection.close()


class Endpoint:
    def __init__(self, address, ca_file, token, run, label):
        self.address, self.ca_file, self.token = address, Path(ca_file), token
        self.run, self.label = run, label

    def call(self, method, path, body=None, *, archive_in=None, archive_out=None,
             budget=HTTP_SECONDS, response_evidence=None):
        need(0 < budget <= HTTP_SECONDS, "original_http_budget")
        need(response_evidence is None or (method == "GET" and not archive_in and not archive_out),
             "api_oracle_capture_read_only")
        deadline = time.monotonic() + budget
        packet = {"address": self.address, "ca_file": str(self.ca_file), "token": self.token,
                  "method": method, "path": path,
                  "body": None if body is None else base64.b64encode(canonical(body)).decode("ascii"),
                  "archive_in": None if archive_in is None else str(archive_in),
                  "archive_out": None if archive_out is None else str(archive_out)}
        encoded = json.dumps(packet).encode()
        need(len(encoded) <= 12 * MIB, "http_input_bound")
        mutation = None
        if method not in ("GET", "LIST"):
            mutation = {"endpoint": self.label, "method": method, "path": path,
                        "status": None, "outcome": "unknown", "retried": False}
            self.run.report["mutations"].append(mutation)
            self.run.phase("mutation_begin", mutation)
        process = None
        try:
            need(time.monotonic() < deadline, "http_deadline_before_dispatch")
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--_http_leaf"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, errors = process.communicate(encoded, timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.communicate(timeout=5)
                raise Failure("http_unknown_outcome_no_retry" if mutation else "http_read_deadline") from error
            need(time.monotonic() < deadline, "http_original_absolute_deadline")
            need(process.returncode == 0 and not errors,
                 "http_unknown_outcome_no_retry" if mutation else "http_leaf_failed")
            need(len(stdout) <= 6 * MIB, "http_private_output_bound")
            result = json.loads(stdout)
            status = result["status"]
            need(type(status) is int and 100 <= status <= 599, "http_status_framing")
            if mutation is not None:
                mutation.update(status=status, outcome="response_received")
            if "archive_sha256" in result:
                need(time.monotonic() < deadline, "http_original_absolute_deadline")
                return status, result
            raw = base64.b64decode(result["body"], validate=True)
            need(len(raw) <= JSON_BYTES, "http_json_response_bound")
            decoded = decode(raw) if raw else {}
            if response_evidence is not None:
                private_write(response_evidence, raw)
                self.run.report.setdefault("source_api_wire_observations", []).append({
                    "endpoint": self.label, "method": method, "path": path, "status": status,
                    "body_bytes": len(raw), "body_sha256": hashlib.sha256(raw).hexdigest(),
                    "private_body_path": str(response_evidence), "same_response_decoded": True,
                })
            need(time.monotonic() < deadline, "http_original_absolute_deadline")
            return status, decoded
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            if mutation is not None:
                mutation["owned_leaf_wait_completed"] = process is None or process.poll() is not None
                self.run.phase("mutation_outcome", mutation)


def observations(endpoint, live_count):
    status, config = endpoint.call("GET", "secret/config")
    need(status == 200 and isinstance(config.get("data"), dict), "read_mount_config")
    status, metadata = endpoint.call("GET", "secret/metadata/history")
    need(status == 200 and isinstance(metadata.get("data"), dict), "read_history_metadata")
    versions = {}
    for version in range(1, live_count + 3):
        status, body = endpoint.call("GET", "secret/data/history?version=" + str(version))
        need(status in (200, 404) and isinstance(body.get("data"), dict), "read_history_version")
        versions[str(version)] = {"status": status, "data": body["data"]}
    return {"config": config["data"], "metadata": metadata["data"], "versions": versions}


def verify_storage_witness(response, version, source_metadata, expected_payload):
    """Verify a precise native read independently of the public KV2 projection."""
    need(isinstance(response, dict) and isinstance(response.get("data"), dict), "storage_witness_envelope")
    value = response["data"]
    need("data" not in value and "payload" not in value, "storage_witness_no_plaintext")
    need(value.get("schema") == "heptabao-native-kv2-storage-witness-v1"
         and value.get("canonical_profile") == "heptabao-lossless-json-v1"
         and value.get("mount") == "secret" and value.get("path") == "history"
         and type(value.get("version")) is int and value["version"] == version,
         "storage_witness_exact_identity")
    need(value.get("created_time") == source_metadata["created_time"]
         and value.get("deletion_time") == source_metadata["deletion_time"]
         and value.get("destroyed") is source_metadata["destroyed"],
         "storage_witness_exact_metadata")
    need(type(value.get("mount_incarnation")) is int
         and 0 < value["mount_incarnation"] < (1 << 64)
         and isinstance(value.get("source_root_sha256"), str)
         and re.fullmatch(r"[0-9a-f]{64}", value["source_root_sha256"]) is not None
         and type(value.get("source_publication_generation")) is int
         and 0 <= value["source_publication_generation"] < (1 << 64),
         "storage_witness_actual_source")
    present = expected_payload is not None
    raw = canonical(expected_payload) if present else b""
    expected_hash = hashlib.sha256(raw).hexdigest() if present else None
    need(value.get("payload_present") is present
         and type(value.get("payload_canonical_bytes")) is int
         and value["payload_canonical_bytes"] == len(raw)
         and value.get("payload_canonical_sha256") == expected_hash,
         "storage_witness_lossless_payload")
    keys = ("schema", "canonical_profile", "mount", "path", "version", "created_time", "deletion_time",
            "destroyed", "payload_present", "payload_canonical_bytes", "payload_canonical_sha256",
            "mount_incarnation", "source_root_sha256", "source_publication_generation")
    return {key: value[key] for key in keys}


class Run:
    def __init__(self, args):
        self.args, self.root = args, args.private_work_root
        self.candidate = self.oracle = self.source = self.target = None
        self.original = self.before = None
        self.source_api_payloads = {}
        self.secrets = []
        self.phase_number = 0
        self.report = {
            "schema": "heptabao.openbao271-kv2-lossless-native-live.v1",
            "profile": args.profile, "official_version": "2.7.1",
            "migration_lane": getattr(args, "migration_lane", "legacy"),
            "oracle_layers": {
                "api": "actual official OpenBao 2.7.1 GET response from each seeded version",
                "storage": "lossless source raw/protobuf decoded bundle with original numeric tokens",
                "target_storage_witness": "required; an API read or capacity count is insufficient",
            },
            "checks": [], "mutations": [], "migration_invocations": [],
            "synthetic_only": True, "tls_verified": True,
            "full34_qualified": False, "full_compatibility_claim": False,
            "v6_ha_qualified": False, "replacement_authority": False,
            "production_authority": False,
        }
        self.stop_oracle = None
        self.source_identity = None

    def phase(self, name, details=None):
        self.phase_number += 1
        private_write(self.root / "phases" / f"{self.phase_number:04d}-{name}.json",
                      json.dumps({"phase": name, "details": details}, sort_keys=True).encode())

    def check(self, name, passed):
        need(name in CHECKS and not any(row["case"] == name for row in self.report["checks"]),
             "unique_required_check")
        self.report["checks"].append({"case": name, "passed": passed is True})
        self.phase("check", self.report["checks"][-1])
        need(passed is True, name)

    def migration(self, operation, endpoint, token_file, bundle):
        need(operation not in [row["operation"] for row in self.report["migration_invocations"]],
             "migration_must_not_retry")
        lane = getattr(self.args, "migration_lane", "legacy")
        script = {"legacy": "openbao270_kv2_migrate.py",
                  "native-large": "openbao271_kv2_native_large_migrate.py"}.get(lane)
        need(script is not None, "explicit_migration_lane")
        end = time.monotonic() + MIGRATION_SECONDS
        row = {"operation": operation, "lane": lane, "status": "unknown", "retried": False,
               "original_budget_seconds": MIGRATION_SECONDS}
        self.report["migration_invocations"].append(row)
        self.phase("migration_begin", row)
        argv = [operation, "--address", endpoint.address, "--ca-file", str(endpoint.ca_file),
                "--token-file", str(token_file), "--mount", "secret",
                "--output" if operation == "export" else "--input", str(bundle)]
        # Own the existing CLI's private worker group directly; nesting a CLI
        # supervisor would allow its separate session to outlive our deadline.
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B",
             str(ROOT / "tools/migration" / script), "--_owned-worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        row.update(pid=process.pid, pgid=process.pid, original_popen=True)
        try:
            try:
                stdout, errors = process.communicate(
                    json.dumps({"argv": argv, "end": end}).encode(),
                    timeout=max(0, end - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
                raise Failure("migration_original_deadline_unknown_outcome") from error
            need(len(stdout) <= 4096 and len(errors) <= 4096, "migration_worker_output_bound")
            row["returncode"] = process.returncode
            # The trusted worker emits bounded fixed decoder/transport labels.
            diagnostic = errors.decode("utf-8", "replace")
            for secret in self.secrets:
                diagnostic = diagnostic.replace(secret, "[redacted]")
            row["diagnostic"] = diagnostic
            need(time.monotonic() < end, "migration_original_absolute_deadline")
            need(process.returncode == 0 and not errors, operation + "_worker_failed")
            receipt = json.loads(stdout)
            need(receipt.get("operation") == operation, "migration_receipt_operation")
            need(lane != "native-large" or receipt.get("lane") == lane, "migration_receipt_lane")
            if operation == "import":
                need(receipt.get("status") == 204, "migration_import_receipt_status")
            row.update(status="completed", receipt=receipt)
            return receipt
        finally:
            # Kill the original owned group on every abnormal exit, including
            # KeyboardInterrupt after the worker created its HTTP leaf.
            if row["status"] != "completed":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.communicate(timeout=5)
            row["original_wait_completed"] = process.poll() is not None
            row["returncode"] = process.returncode
            self.phase("migration_outcome", row)

    def seed_source(self, live_count, size):
        source = self.source
        oracle_dir = self.root / "source-api-oracle"
        oracle_dir.mkdir(mode=0o700)
        need(source.call("POST", "sys/mounts/secret",
                         {"type": "kv", "options": {"version": "2"}})[0] == 204, "source_mount")
        need(source.call("POST", "secret/config", {
            "max_versions": live_count + 8, "cas_required": True,
            "metadata_cas_required": True})[0] == 204, "source_config")
        need(source.call("POST", "secret/metadata/history", {
            "max_versions": live_count + 8, "cas_required": True,
            "metadata_cas_required": True, "metadata_cas": 0,
            "custom_metadata": {"purpose": "synthetic-native-migration", "revision": "first"},
        })[0] == 204, "source_initial_metadata")
        for version in range(1, live_count + 3):
            generated = payload(version, live_count, size)
            need(source.call("POST", "secret/data/history", {
                "data": generated, "options": {"cas": version - 1},
            })[0] == 200, "source_write_" + str(version))
            # Preserve this same API response before any soft delete/destroy.
            # OpenBao's public GET numeric projection is independently observed;
            # its precise raw record is checked later against `generated`.
            status, observed = source.call("GET", "secret/data/history?version=" + str(version),
                response_evidence=oracle_dir / ("version-" + str(version).zfill(4) + ".json"))
            need(status == 200 and isinstance(observed.get("data"), dict), "source_seeded_api_read")
            metadata, actual = observed["data"].get("metadata"), observed["data"].get("data")
            need(isinstance(metadata, dict) and metadata.get("version") == version
                 and isinstance(actual, dict) and set(actual) == set(generated), "source_seeded_api_shape")
            numeric = ("wide_integer", "exact_decimal")
            need(all(same_json_tokens(actual[name], expected) for name, expected in generated.items() if name not in numeric)
                 and all(type(actual[name]) is int or isinstance(actual[name], Decimal) for name in numeric),
                 "source_seeded_non_numeric_payload_exact")
            self.source_api_payloads[str(version)] = actual
            self.report.setdefault("source_api_numeric_observations", []).append({
                "version": version,
                **{name: {"actual_token": str(actual[name]), "generated_token": str(generated[name]),
                          "numerically_equal": actual[name] == generated[name]}
                   for name in numeric},
                "private_body_path": str(oracle_dir / ("version-" + str(version).zfill(4) + ".json")),
            })
        self.check("source_api_oracle_captured", len(self.source_api_payloads) == live_count + 2
                   and len(self.report.get("source_api_wire_observations", [])) == live_count + 2)
        status, meta = source.call("GET", "secret/metadata/history")
        need(status == 200, "source_metadata_before_cas")
        current = meta["data"]["current_metadata_version"]
        need(source.call("POST", "secret/metadata/history", {
            "metadata_cas": current,
            "custom_metadata": {"purpose": "synthetic-native-migration", "revision": "second"},
        })[0] == 204, "source_metadata_cas_update")
        need(source.call("POST", "secret/delete/history", {"versions": [1]})[0] == 204,
             "source_soft_delete")
        need(source.call("POST", "secret/destroy/history", {"versions": [2]})[0] == 204,
             "source_destroy")
        original = observations(source, live_count)
        # Retain the actual read baseline even if a later seed predicate fails;
        # cleanup can then reconcile this fixture's history independently of
        # the repository/binary identity check.
        self.original = original
        versions, metadata = original["versions"], original["metadata"]
        valid = (
            metadata["current_version"] == live_count + 2
            and versions["1"]["status"] == 404
            and versions["1"]["data"]["data"] is None
            and versions["1"]["data"]["metadata"]["destroyed"] is False
            and bool(versions["1"]["data"]["metadata"]["deletion_time"])
            and versions["2"]["status"] == 404
            and versions["2"]["data"]["data"] is None
            and versions["2"]["data"]["metadata"]["destroyed"] is True
            and all(versions[str(v)]["status"] == 200
                    and same_json_tokens(versions[str(v)]["data"]["data"], self.source_api_payloads[str(v)])
                    for v in range(3, live_count + 3)))
        self.check("source_retained_deleted_destroyed_seeded", valid)
        self.check("source_metadata_cas_seeded",
                   metadata["metadata_cas_required"] is True
                   and metadata["current_metadata_version"] == current + 1
                   and metadata["custom_metadata"]["revision"] == "second")
        return original

    def verify_bundle(self, bundle, live_count, size):
        value = decode(private_read(bundle))
        need(value.get("schema") == "openbao270-kv2-lossless-v1"
             and set(value["entries"]) == {"history"}, "lossless_bundle_history")
        entry = value["entries"]["history"]
        for key, expected in self.original["metadata"].items():
            if key != "versions":
                need(entry.get(key) == expected, "bundle_metadata_" + key)
        need(value["config"] == self.original["config"], "bundle_config_exact")
        for version in range(1, live_count + 3):
            item = entry["versions"][str(version)]
            source = self.original["metadata"]["versions"][str(version)]
            need(all(item.get(key) == val for key, val in source.items()), "bundle_version_metadata")
            need(canonical(item["data"]) == canonical(None if version == 2 else payload(version, live_count, size)),
                 "bundle_retained_payload")
        self.check("source_raw_history_exact", True)
        self.check("exported_soft_deleted_payload_preserved", canonical(entry["versions"]["1"]["data"])
                   == canonical(payload(1, live_count, size)) and entry["versions"]["2"]["data"] is None)

    def verify_target_storage(self, name, live_count, size):
        need(name in STORAGE_CHECKS and any(row["case"] == "source_raw_history_exact" and row["passed"] is True
                                           for row in self.report["checks"]), "storage_oracle_source_raw_required")
        stage = {"stage": name, "source_raw_bound": True, "versions": []}
        self.report.setdefault("target_storage_witnesses", []).append(stage)
        self.phase("storage_witness_begin", {"stage": name})
        for version in range(1, live_count + 3):
            status, response = self.target.call("POST", "sys/internal/storage/kv2-version-witness", {
                "mount": "secret", "path": "history", "version": version,
            })
            need(status == 200, "storage_witness_http_" + str(status))
            expected = None if version == 2 else payload(version, live_count, size)
            stage["versions"].append(verify_storage_witness(response, version,
                self.original["metadata"]["versions"][str(version)], expected))
        self.check(name, len(stage["versions"]) == live_count + 2)

    def cold_candidate(self):
        self.candidate.stop()
        self.candidate.start()
        need(self.target.call("POST", "sys/unseal", {"key": self.candidate_key})[0] == 200,
             "candidate_cold_unseal")

    def execute(self):
        # Imports stay lazy: --help and the controller unit tests need no server
        # SDK or artifact. A real run uses the complete checked-in repository.
        for directory in ("qa/openbao-acceptance", "qa/single-node", "clients/python/src"):
            sys.path.insert(0, str(ROOT / directory))
        import owned_process
        import smoke
        import official_openbao_launcher as launcher
        from online_evidence import source_identity
        self.source_identity = source_identity
        self.stop_oracle = launcher.stop_oracle
        launcher.verify_inputs(version="2.7.1")
        self.before = source_identity(ROOT, self.args.binary)
        self.report.update(self.before)
        live_count, size, native_first = PROFILES[self.args.profile]
        self.report.update(retained_live_versions=live_count, live_payload_bytes=live_count * size,
                           native_before_import=native_first)
        old_oracle_root = os.environ.get("HB_ORACLE_WORK_ROOT")
        os.environ["HB_ORACLE_WORK_ROOT"] = str(self.root)
        try:
            self.oracle = launcher.start_oracle(smoke.free_loopback_port(), version="2.7.1")
        finally:
            if old_oracle_root is None:
                os.environ.pop("HB_ORACLE_WORK_ROOT", None)
            else:
                os.environ["HB_ORACLE_WORK_ROOT"] = old_oracle_root
        source_root = Path(self.oracle["root"])
        token = private_read(self.oracle["token_file"], 65536).decode().strip()
        key = private_read(source_root / "unseal.key", 65536).decode().strip()
        self.secrets.extend((token, key))
        self.source = Endpoint(self.oracle["address"], self.oracle["ca_file"], token, self, "source")
        # Only the newly allocated official fixture enables its raw endpoint.
        launcher.stop_oracle(self.oracle)
        config = json.loads(private_read(source_root / "server.json"))
        config["raw_storage_endpoint"] = True
        private_write(source_root / "server.json", json.dumps(config).encode(), replace=True)
        launcher.restart_oracle(self.oracle)
        status, health = self.source.call("GET", "sys/health")
        self.report["official_identity"] = launcher.verify_selected_oracle(
            self.oracle, health, version="2.7.1")
        self.check("official_271_pins_and_live_identity", status == 200)
        run = self

        class NativeInstance(smoke.Instance):
            def start(self):
                self.log = open(self.root / "server.log", "ab")
                self.process = owned_process.popen(
                    [str(self.binary), "--config", str(self.root / "server.json"),
                     "--fixture-native-v6-service"], stdout=self.log, stderr=self.log,
                    label="kv2_271_lossless_native_live", action="KILL", stop_timeout=5)
                endpoint = Endpoint(self.address, self.root / "ca.crt", self.token, run, "target")
                deadline = time.monotonic() + HTTP_SECONDS
                try:
                    while time.monotonic() < deadline:
                        need(self.process.poll() is None, "candidate_exited_before_ready")
                        try:
                            status, _ = endpoint.call("GET", "sys/health",
                                                      budget=min(2, deadline - time.monotonic()))
                            if status in (200, 501, 503):
                                return
                        except Failure:
                            pass
                        time.sleep(0.05)
                    raise Failure("candidate_tls_startup_deadline")
                except BaseException as error:
                    owned_process.abort(error, [self.stop])

        self.candidate = NativeInstance(self.args.binary, self.root / "candidate")
        self.candidate.start()
        self.target = Endpoint(self.candidate.address, self.candidate.root / "ca.crt", "", self, "target")
        status, initialized = self.target.call("POST", "sys/init",
                                               {"secret_shares": 1, "secret_threshold": 1})
        need(status == 200, "target_initialize")
        self.target.token = initialized["root_token"]
        self.candidate_key = initialized["keys_base64"][0]
        self.secrets.extend((self.target.token, self.candidate_key))
        private_write(self.candidate.root / "root.token", self.target.token)
        private_write(self.candidate.root / "unseal.key", self.candidate_key)
        self.candidate.token = self.target.token
        need(self.target.call("POST", "sys/unseal", {"key": self.candidate_key})[0] == 200,
             "target_initial_unseal")
        self.check("two_distinct_owned_processes",
                   self.oracle["process"].pid != self.candidate.process.pid
                   and self.oracle["process"].poll() is None and self.candidate.process.poll() is None
                   and self.source.address != self.target.address)
        self.report["owned_roots"] = {"source": str(source_root), "target": str(self.candidate.root)}
        self.original = self.seed_source(live_count, size)
        self.report["source_history_sha256"] = hashlib.sha256(canonical(self.original)).hexdigest()
        launcher.stop_oracle(self.oracle)
        launcher.restart_oracle(self.oracle)
        self.check("source_cold_restart_exact", same_json_tokens(observations(self.source, live_count), self.original))
        need(self.target.call("POST", "sys/mounts/secret",
                              {"type": "kv", "options": {"version": "2"}})[0] == 204, "target_mount")
        if native_first:
            need(self.target.call("POST", "sys/internal/native-v6/activate", {})[0] == 204,
                 "target_activate_before_import")
        self.check("target_pristine_before_import",
                   self.target.call("GET", "secret/metadata/history")[0] == 404
                   and self.target.call("LIST", "secret/metadata")[0] == 404)
        bundle = self.root / "source-bundle.json"
        self.migration("export", self.source, self.oracle["token_file"], bundle)
        self.check("source_export_once", True)
        self.verify_bundle(bundle, live_count, size)
        self.check("source_unchanged_after_export", same_json_tokens(observations(self.source, live_count), self.original))
        self.migration("import", self.target, self.candidate.root / "root.token", bundle)
        self.check("target_import_once", True)
        if not native_first:
            need(self.target.call("POST", "sys/internal/native-v6/activate", {})[0] == 204,
                 "target_activate_after_import")
        status, capacity = self.target.call("GET", "sys/internal/capacity")
        capacity = capacity.get("data", capacity)
        self.report["capacity_after_import"] = capacity
        self.check("target_active_native_v6", status == 200
                   and capacity.get("state_storage_format") == "heptabao-state-records-v6"
                   and capacity.get("native_kv2_reader_format") == 2
                   and capacity.get("native_kv2_logical_payload_bytes", 0) >= live_count * size)
        self.check("target_full_history_exact", same_json_tokens(observations(self.target, live_count), self.original))
        self.verify_target_storage("target_storage_full_history_exact", live_count, size)
        self.cold_candidate()
        self.check("target_cold_restart_exact", same_json_tokens(observations(self.target, live_count), self.original))
        self.verify_target_storage("target_storage_cold_history_exact", live_count, size)
        snapshot = self.root / "native-snapshot.tar.gz"
        status, receipt = self.target.call("GET", "sys/storage/raft/snapshot", archive_out=snapshot)
        self.report["snapshot"] = receipt
        self.check("snapshot_download", status == 200 and receipt.get("archive_bytes", 0) > 0)
        self.check("post_snapshot_mutation_once", self.target.call("POST", "secret/data/history",
                   {"data": {"after_snapshot": True}, "options": {"cas": live_count + 2}})[0] == 200)
        self.check("snapshot_restore_once", self.target.call(
            "POST", "sys/storage/raft/snapshot", archive_in=snapshot)[0] == 200)
        self.cold_candidate()
        self.check("restored_cold_history_exact", same_json_tokens(observations(self.target, live_count), self.original))
        self.verify_target_storage("restored_storage_history_exact", live_count, size)
        need(self.target.call("POST", "secret/undelete/history", {"versions": [1]})[0] == 204,
             "target_soft_undelete")
        status, restored = self.target.call("GET", "secret/data/history?version=1")
        self.check("soft_deleted_payload_undelete_exact",
                   status == 200 and same_json_tokens(restored["data"]["data"], self.source_api_payloads["1"])
                   and restored["data"]["metadata"]["deletion_time"] == "")
        need(self.target.call("POST", "secret/undelete/history", {"versions": [2]})[0] == 204,
             "target_destroyed_undelete")
        status, destroyed = self.target.call("GET", "secret/data/history?version=2")
        self.check("destroyed_payload_remains_absent", status == 404
                   and destroyed["data"]["data"] is None
                   and destroyed["data"]["metadata"]["destroyed"] is True)
        before = observations(self.target, live_count)
        status, _ = self.target.call("POST", "secret/data/history",
                                    {"data": {"must_not_commit": True}, "options": {"cas": 0}})
        self.check("data_cas_denied_without_effect", status == 400
                   and same_json_tokens(observations(self.target, live_count), before))
        status, _ = self.target.call("POST", "secret/metadata/history",
                                    {"custom_metadata": {"must_not_commit": "true"}, "metadata_cas": 0})
        self.check("metadata_cas_denied_without_effect", status == 400
                   and same_json_tokens(observations(self.target, live_count), before))
        counter = before["metadata"]["current_metadata_version"]
        status, _ = self.target.call("POST", "secret/metadata/history",
                                    {"custom_metadata": {"revision": "target"},
                                     "metadata_cas": counter})
        after = observations(self.target, live_count)
        self.check("metadata_cas_success_counter_exact", status == 204
                   and after["metadata"]["current_metadata_version"] == counter + 1
                   and after["metadata"]["custom_metadata"] == {"revision": "target"})
        self.check("source_unchanged_after_target_mutations",
                   same_json_tokens(observations(self.source, live_count), self.original))

    def finish(self):
        if self.source is not None and self.original is not None:
            try:
                count = PROFILES[self.args.profile][0]
                unchanged = same_json_tokens(observations(self.source, count), self.original)
                self.report["source_unchanged_at_cleanup"] = unchanged
                if unchanged is not True:
                    self.report.setdefault("failure", "source_changed_at_cleanup")
            except Exception:
                self.report["source_unchanged_at_cleanup"] = None
                self.report.setdefault("failure", "source_cleanup_reconciliation_failed")
        if self.target is not None and any(
                row["case"] == "target_import_once" and row["passed"] for row in self.report["checks"]):
            try:
                status, _ = self.target.call("GET", "secret/metadata/history")
                self.report["target_history_status_at_cleanup"] = status
                if status != 200:
                    self.report.setdefault("failure", "target_history_unavailable_at_cleanup")
            except Exception:
                self.report["target_history_status_at_cleanup"] = None
                self.report.setdefault("failure", "target_cleanup_reconciliation_failed")
        stopped = True
        for label, owner, stop in (
                ("target", self.candidate, lambda: self.candidate.stop()),
                ("source", self.oracle, lambda: self.stop_oracle(self.oracle))):
            if owner is None:
                continue
            try:
                process = owner.get("process") if isinstance(owner, dict) else owner.process
                stop()
                need(process is None or process.poll() is not None, "owned_process_still_running")
            except BaseException as error:
                stopped = False
                self.report.setdefault("cleanup_failures", []).append(
                    {"owner": label, "error_type": type(error).__name__})
        if self.before is not None and self.source_identity is not None:
            try:
                self.check("source_and_binary_unchanged",
                           self.source_identity(ROOT, self.args.binary) == self.before)
            except BaseException:
                self.report.setdefault("failure", "source_and_binary_unchanged")
        try:
            self.check("owned_processes_stopped", stopped)
        except BaseException:
            self.report.setdefault("failure", "owned_processes_stopped")
        public = json.dumps(self.report, sort_keys=True)
        secret_leak = any(secret and secret in public for secret in self.secrets)
        if secret_leak:
            for secret in self.secrets:
                if secret:
                    public = public.replace(secret, "[redacted]")
            self.report = json.loads(public)
        try:
            self.check("report_excludes_runtime_credentials", not secret_leak)
        except BaseException:
            self.report.setdefault("failure", "report_excludes_runtime_credentials")
        passed = {row["case"] for row in self.report["checks"] if row["passed"] is True}
        self.report["missing_checks"] = sorted(set(CHECKS) - passed)
        if self.report["missing_checks"]:
            self.report.setdefault("failure", "incomplete_required_checks")
        self.report["status"] = "failed" if self.report.get("failure") else "passed"
        self.report["target_storage_precision_qualified"] = set(STORAGE_CHECKS) <= passed
        self.report["api_history_qualified"] = {
            "source_api_oracle_captured", "source_retained_deleted_destroyed_seeded",
            "source_cold_restart_exact", "target_full_history_exact", "target_cold_restart_exact",
            "restored_cold_history_exact", "soft_deleted_payload_undelete_exact",
        } <= passed
        self.report["full34_qualified"] = (self.report["status"] == "passed"
                                            and self.args.profile == "full34"
                                            and self.report["target_storage_precision_qualified"])
        private_write(self.root / "summary.json", json.dumps(
            self.report, ensure_ascii=False, indent=2, sort_keys=True).encode())
        return 0 if self.report["status"] == "passed" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--private-work-root", required=True, type=Path)
    parser.add_argument("--profile", choices=tuple(PROFILES), default="full34")
    parser.add_argument("--migration-lane", choices=("legacy", "native-large"), default="legacy")
    args = parser.parse_args(argv)
    need(os.name == "posix", "owned_posix_process_groups_required")
    need(args.migration_lane != "native-large" or PROFILES[args.profile][2],
         "native_large_requires_native_before_import")
    need(args.binary.is_absolute() and args.private_work_root.is_absolute(), "absolute_paths_required")
    args.binary = args.binary.resolve(strict=True)
    parent = args.private_work_root.parent
    need(parent.resolve(strict=True) == parent and not args.private_work_root.exists(),
         "new_direct_private_root_required")
    info = parent.stat()
    need(info.st_uid == os.geteuid() and stat.S_ISDIR(info.st_mode)
         and info.st_mode & 0o022 == 0, "owned_parent_required")
    need(not args.private_work_root.is_relative_to(ROOT), "private_root_outside_source")
    os.umask(0o077)
    args.private_work_root.mkdir(mode=0o700)
    (args.private_work_root / "phases").mkdir(mode=0o700)
    run = Run(args)
    try:
        run.execute()
    except BaseException as error:
        label = str(error) if isinstance(error, Failure) else type(error).__name__
        for secret in run.secrets:
            label = label.replace(secret, "[redacted]")
        run.report["failure"] = label
    code = run.finish()
    print(json.dumps({"status": run.report["status"], "profile": args.profile,
                      "summary": str(run.root / "summary.json"),
                      "full34_qualified": run.report["full34_qualified"]}))
    return code


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--_http_leaf"]:
            try:
                http_leaf()
            except BaseException:
                print("private HTTP leaf failed", file=sys.stderr)
                raise SystemExit(1) from None
        else:
            raise SystemExit(main())
    except (Failure, OSError, ValueError):
        print("KV2 native migration controller failed before publication", file=sys.stderr)
        raise SystemExit(1) from None
