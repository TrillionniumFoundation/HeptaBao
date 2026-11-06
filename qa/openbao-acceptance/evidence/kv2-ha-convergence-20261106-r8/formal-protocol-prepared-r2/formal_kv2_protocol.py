"""Draft normal native_v6_file protocol and independent-restore acceptance.

No command-line entry point, service launcher, live-SQLite reader or automatic
retry lives here. A reviewed outer controller must supply the fixed lifecycle,
validated-generation and bounded-wire adapters. Importing this module does no
I/O. Passing its narrow guards is not an actual service acceptance result.
"""
from __future__ import annotations

import ast
import base64
import copy
from dataclasses import dataclass, asdict, is_dataclass
from decimal import Decimal
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any, Mapping, Protocol
import zlib

from lifecycle_contract import (
    Deadline, EndpointHandle, Lifecycle, PreActivationSeedBinding,
    RestoreTarget, RestartObservation, ManagerRetirement, PersistentHandoff,
)

MIB = 1024 * 1024
HTTP_SECONDS = 15
JSON_REQUEST_MAX = 3 * MIB
JSON_RESPONSE_MAX = 4 * MIB
EXPORT_MAX = 64 * MIB
SNAPSHOT_MAX = 128 * MIB
TABLES = {
    "auth_profile_store": ("store_key", "store_json", "updated_at"),
    "auth_profile_state": ("state_key", "state_json", "updated_at"),
}
HELPER_PINS = {
    "kv2_271_lossless_native_live.py":
        (49393, "383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581"),
    "kv2_native_fresh_directory_dr_live.py":
        (75012, "2271a4ca539e1190b03e95e95d4d1c79414bd852c80ac85e205def2adac74263"),
    "native_snapshot_cli_live.py":
        (39096, "bad9b52056f5b6bcf1a9a98f87a3c4af50d0a68190c22bf5b7b91b9d2ca3bf08"),
}
CHECKS = (
    "complete_current_generation_projection_bound",
    "source_pristine_mounts_and_native_activation",
    "all_business_rows_written_once_as_new_v1",
    "canary_history_delete_destroy_and_cas_observed",
    "source_complete_api_metadata_raw_and_current_exports",
    "source_manager_cold_restart_and_complete_history",
    "current_snapshot_structure_and_encrypted_staging",
    "bootstrap_seed_missing_all_current_versions",
    "bad_sealed_snapshot_rejected_without_commit",
    "fresh_restore_current_history_and_cold_reads",
    "recovered_canary_undelete_and_destroyed_absence",
    "recovered_canary_new_write_persistent",
    "restore_target_snapshot_rollback_and_complete_history",
    "source_business_and_canary_unchanged",
    "restore_target_manager_retired",
    "persistent_source_manager_handoff_observed",
)
SNAPSHOT_CHECKS = CHECKS[:7] + ("snapshot_ready_source_manager_handoff_observed",)
RECOVERY_CHECKS = ("independent_remote_archive_custody_and_full_readback",) + CHECKS[7:]
ALL_CHECKS = SNAPSHOT_CHECKS + RECOVERY_CHECKS
READBACK_CHECKS = (
    "fixed_readonly_code_and_environment_bound",
    "original_complete_workflow_and_fresh_stage_bound",
    "original_private_generation_roots_files_and_plan_bound",
    "complete_ordered_authenticated_archive_generation",
    "both_existing_copies_full_declared_bytes_and_absences",
    "every_nonempty_database_cold_and_all_agent_rows_exact",
    "all_seven_safety_and_absent_file_boundaries_covered",
    "complete_current_snapshot_denominators_without_truncation",
    "all_bound_inputs_consumed_files_and_roots_unchanged",
    "all_consumed_plaintext_key_and_input_handles_retired",
    "no_live_source_network_process_or_mutation_effect",
)


class Refused(RuntimeError):
    """Only fixed local codes, never arbitrary server or exception text."""


def need(value, code):
    if not value:
        raise Refused(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed_json(value):
    # This matches the capture producer's JSON for its SQLite cell projection.
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def load_pure_helpers(qa_dir: Path):
    """Extract only pinned pure functions; never import a mixed full34 Run."""
    nodes = {}
    for name, (size, sha) in HELPER_PINS.items():
        raw = (qa_dir / name).read_bytes()
        need(len(raw) == size and digest(raw) == sha, "a257_pure_helper_pin")
        nodes[name] = ast.parse(raw, filename=name).body
    env = {"__builtins__": __builtins__, "Decimal": Decimal, "json": json,
           "os": os, "stat": stat, "Path": Path, "re": re,
           "hashlib": hashlib, "gzip": gzip, "zlib": zlib,
           "ARCHIVE_BYTES": SNAPSHOT_MAX}

    def extract(name, wanted):
        selected = [row for row in nodes[name]
                    if isinstance(row, (ast.FunctionDef, ast.ClassDef))
                    and row.name in wanted]
        need({row.name for row in selected} == set(wanted)
             and len(selected) == len(wanted), "pure_helper_definition_set")
        exec(compile(ast.Module(body=selected, type_ignores=[]), name, "exec"), env)

    extract("kv2_271_lossless_native_live.py", (
        "Failure", "need", "unique", "decode", "canonical", "private_read", "private_write"))
    full = SimpleNamespace(**{key: env[key] for key in (
        "Failure", "need", "decode", "canonical", "private_read", "private_write")},
        ARCHIVE_BYTES=SNAPSHOT_MAX)
    env.update(full=full, ARCHIVE_NAMES=(
        "meta.json", "state.bin", "SHA256SUMS", "SHA256SUMS.sealed"))
    extract("kv2_native_fresh_directory_dr_live.py", (
        "file_pin", "tar_header", "single_gzip_member", "inspect_v6_archive"))
    env.update(NAMES=list(env["ARCHIVE_NAMES"]), BLOCK=65536)
    extract("native_snapshot_cli_live.py", ("new_file", "tamper_sealed"))
    return SimpleNamespace(**{key: env[key] for key in (
        "decode", "canonical", "private_read", "private_write", "file_pin",
        "inspect_v6_archive", "tamper_sealed")})


@dataclass(frozen=True, repr=False)
class PrivatePin:
    path: Path
    bytes: int
    sha256: str


@dataclass(frozen=True, repr=False)
class ProjectionSource:
    # A concrete adapter must reconcile the actual successful whole-readback
    # terminal, final stdout, public result and private closure before returning
    # this capture pin. Merely constructing this dataclass is not admission.
    capture: PrivatePin
    projection: PrivatePin
    readback_result: PrivatePin
    readback_terminal: PrivatePin
    readback_stdout: PrivatePin
    private_closure: PrivatePin


@dataclass(frozen=True, repr=False)
class Plan:
    source: EndpointHandle
    generation: ProjectionSource
    seed: PreActivationSeedBinding
    business_mount: str
    canary_mount: str
    canary_key: str
    evidence_dir: Path
    archive_staging_dir: Path
    key_parent: Path
    deadline: Deadline


@dataclass(frozen=True, repr=False)
class RemoteBackupBinding:
    """Root-reviewed native host authority plus locally verified original bytes.

    The native file_info JSON does not authenticate its own host. The parent
    independently reviews request host/path/version and the complete original
    native upload/readback transcript; these archive-only original refs preserve
    that authority evidence. Share-delivery originals must be separate.
    """
    host: str
    destination: Path
    expected_uid: int
    native_info_before: PrivatePin
    native_info_after: PrivatePin
    full_readback: PrivatePin
    archive_transport_original_refs: tuple[PrivatePin, ...]


@dataclass(frozen=True, repr=False)
class ResumeInputs:
    continuation: PrivatePin
    snapshot_public_result: PrivatePin
    snapshot_runtime_terminal: PrivatePin
    snapshot_process_custody: PrivatePin
    remote: RemoteBackupBinding


@dataclass(frozen=True, repr=False)
class WireReply:
    status: int
    body: bytes
    # These observations are from the same connection and original child.
    origin: str
    peer_leaf_sha256: str
    ca_sha256: str
    elapsed_seconds: float
    child_receipt: Mapping[str, Any]
    headers: Mapping[str, str]
    downloaded_file: Path | None = None


class ValidatedGeneration(Protocol):
    def reconcile(self, source: ProjectionSource, *, deadline: Deadline) -> Mapping[str, Any]:
        """Reconsume exact original receipts and private closure; no live DB."""
        ...


def stat_identity(path):
    row = Path(path).lstat()
    return {"dev": row.st_dev, "inode": row.st_ino, "uid": row.st_uid,
            "gid": row.st_gid, "mode": stat.S_IMODE(row.st_mode),
            "file_type": stat.S_IFMT(row.st_mode), "nlink": row.st_nlink,
            "bytes": row.st_size, "mtime_ns": row.st_mtime_ns, "ctime_ns": row.st_ctime_ns}


class ReadbackGenerationAdapter:
    """Consume the existing independent readback, without repeating its work."""
    def __init__(self, helpers):
        self.h = helpers

    def reconcile(self, source, *, deadline):
        need(time.monotonic() < deadline.work_end, "generation_original_deadline")
        result = self.h.decode(read_pin(source.readback_result, self.h, 2 * MIB))
        terminal = self.h.decode(read_pin(source.readback_terminal, self.h, MIB))
        stdout_raw = read_pin(source.readback_stdout, self.h, 2 * MIB)
        final = self.h.decode(stdout_raw)
        need(terminal.get("state") == "succeeded" and terminal.get("exit_code") == 0
             and all(terminal.get(k) is True for k in (
                 "output_complete", "output_durable", "terminal_publication_confirmed"))
             and all(terminal.get(k) is False for k in ("timed_out", "cancelled", "automatic_retry"))
             and terminal["log_bytes"]["stdout"] == {"seen": len(stdout_raw), "stored": len(stdout_raw)}
             and terminal["log_bytes"]["stderr"] == {"seen": 0, "stored": 0}
             and terminal["log_errors"] == {"stdout": None, "stderr": None}
             and terminal["log_synced"] == {"stdout": True, "stderr": True}
             and terminal["log_truncated"] == {"stdout": False, "stderr": False},
             "independent_readback_authoritative_terminal")
        final_only = {"owned_directory_handles_closed", "all_owned_directory_handles_retired"}
        need(set(final) == set(result) | final_only
             and all(final[k] == value for k, value in result.items())
             and final["all_owned_directory_handles_retired"] is True
             and final["owned_directory_handles_closed"] == result["owned_directory_handle_count"] > 0,
             "independent_readback_final_fd_closeout")
        checks = result.get("verification_checks", [])
        need(result.get("schema") == "heptabao.independent-current-sqlite-readback.public.v1"
             and result.get("status") == "passed" and result.get("verification_complete") is True
             and [row.get("check") for row in checks] == list(READBACK_CHECKS)
             and all(row == {"check": name, "passed": True} for row, name in zip(checks, READBACK_CHECKS))
             and result.get("required_verification_check_count") == len(READBACK_CHECKS)
             and result.get("observed_verification_check_count") == len(READBACK_CHECKS)
             and result.get("passed_verification_check_count") == len(READBACK_CHECKS)
             and result.get("missing_required_checks") == []
             and result.get("primary_failure_code") is None and result.get("cleanup_failure_codes") == []
             and result.get("deadline_fired") is False and result.get("interrupted") is False,
             "complete_independent_readback_denominator")
        need(result["whole_file_readback"]["capture"] == result["whole_file_readback"]["restore"]
             and result["cold_sqlite"]["capture"] == result["cold_sqlite"]["restore"]
             and result["cold_connections_opened"] == result["cold_connections_closed"]
             and result["cold_sqlite"]["restore"]["database_families"] == result["declared_database_family_count"],
             "complete_both_copy_readback_counts")
        private = self.h.decode(read_pin(source.private_closure, self.h, 16 * MIB))
        need(stat_identity(source.private_closure.path) == result["verification_private_file_identity"]
             and private.get("schema") == "heptabao.independent-current-sqlite-readback.private.v1",
             "readback_private_closure_original_identity")
        prior = private["public_result_before_publication"]
        need(prior.get("status") == "passed" and prior.get("verification_complete") is True
             and prior.get("original_successful_workflow_job_id") == result["original_successful_workflow_job_id"],
             "readback_original_workflow_identity")
        capture_pin = private["original_completed_file_pins"]["restore_capture_manifest"]
        need(capture_pin["path"] == str(source.capture.path)
             and capture_pin["sha256"] == source.capture.sha256
             and capture_pin["identity"]["bytes"] == source.capture.bytes
             and stat_identity(source.capture.path) == capture_pin["identity"],
             "actual_restored_capture_manifest_not_live_source")
        roots = private["actual_attempt_root_identities"]
        restore = roots["restore"]
        need(source.capture.path == Path(restore["path"]) / "capture.private.json"
             and all(stat_identity(Path(restore["path"]))[k] == restore[k]
                     for k in ("dev", "inode", "uid", "gid", "mode")),
             "actual_restored_generation_root")
        need(time.monotonic() < deadline.work_end, "generation_original_deadline")
        return {"result": result, "terminal": terminal, "final": final,
                "private_closure_identity": stat_identity(source.private_closure.path),
                "capture_binding": capture_pin, "original_generation_roots": roots}


class Wire(Protocol):
    def exchange(self, endpoint: EndpointHandle, method: str, path: str,
                 body: bytes | None, *, download: Path | None,
                 upload: Path | None, maximum: int, absolute_deadline: float) -> WireReply:
        """One owned request, TLS/SAN+CA+leaf checked, no redirect or retry.

        The adapter must hold the original subprocess anchor, wait exactly once
        and retain private outputs. absolute_deadline is no more than 15 seconds
        after entry and is never reset by connection, reads, or cleanup.
        """
        ...


class OwnedWire:
    """Concrete single-request leaf using the already active 669e owner."""
    def __init__(self, *, wire_file: PrivatePin, custody_module, custody_owner,
                 helpers, evidence_dir: Path, total_end: float):
        self.wire_file, self.module, self.owner = wire_file, custody_module, custody_owner
        self.h, self.evidence_dir, self.total_end = helpers, evidence_dir, total_end
        self.serial = 0
        self.handle_receipts = []
        self.check_owner()

    def check_owner(self):
        raw = Path(self.module.__file__).read_bytes()
        need(len(raw) == 26131 and digest(raw) == "669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008"
             and self.module._ACTIVE is self.owner and subprocess.Popen is self.module._TrackedPopen
             and not self.owner.failed and not self.owner.finished and not self.owner.interrupted,
             "fixed_active_original_process_owner_required")
        pin = self.h.file_pin(self.wire_file.path)
        need(pin["bytes"] == self.wire_file.bytes and pin["sha256"] == self.wire_file.sha256,
             "fixed_wire_source_required")

    def exchange(self, endpoint, method, path, body, *, download, upload, maximum, absolute_deadline):
        started = time.monotonic()
        need(started < absolute_deadline <= started + HTTP_SECONDS, "wire_original_absolute_deadline")
        self.check_owner()
        ca, root = self.h.file_pin(endpoint.ca_file, private=True), self.h.file_pin(endpoint.root_token_file, private=True)
        upload_pin = self.h.file_pin(upload, private=True) if upload is not None else None
        packet = {"origin": endpoint.origin, "ca_file": str(endpoint.ca_file), "ca_pin": ca,
                  "root_file": str(endpoint.root_token_file), "root_pin": root,
                  "leaf_sha256": endpoint.leaf_sha256, "method": method, "path": path,
                  "body": None if body is None else base64.b64encode(body).decode("ascii"),
                  "download": None if download is None else str(download),
                  "upload": None if upload is None else str(upload), "upload_pin": upload_pin,
                  "maximum": maximum, "timeout": min(HTTP_SECONDS, absolute_deadline - time.monotonic())}
        self.serial += 1
        paths = [self.evidence_dir / f"wire-{self.serial:06d}.{suffix}.private" for suffix in ("stdout", "stderr")]
        process, descriptors = None, []
        cleanup_error = None
        # The frozen owner makes interrupts sticky while protected. Keep this
        # scope through the original bounded request and cleanup so a signal
        # cannot land between an FD birth and registration, or between entry
        # into finally and retirement. The existing absolute deadline is not
        # changed; any pending interruption prevents a reply from being used.
        self.owner.protected += 1
        try:
            try:
                for path in paths:
                    row = {"fd": None, "birth_registered": False, "identity": None,
                           "sync_attempted": False, "sync_succeeded": False,
                           "close_attempted": False, "close_succeeded": False}
                    descriptors.append(row)
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    row["fd"] = fd
                    row["birth_registered"] = True
                    observed = os.fstat(fd)
                    row["identity"] = {"dev": observed.st_dev, "inode": observed.st_ino,
                                       "uid": observed.st_uid, "mode": stat.S_IMODE(observed.st_mode)}
                    need(stat.S_ISREG(observed.st_mode) and observed.st_uid == os.geteuid()
                         and observed.st_nlink == 1 and stat.S_IMODE(observed.st_mode) == 0o600,
                         "wire_private_output_original_identity")
                need(not self.owner.failed and not self.owner.interrupted
                     and time.monotonic() < absolute_deadline, "wire_cancelled_before_single_dispatch")
                process = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(self.wire_file.path), "--_wire"],
                    stdin=subprocess.PIPE, stdout=descriptors[0]["fd"], stderr=descriptors[1]["fd"],
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                    cwd=self.evidence_dir, start_new_session=True)
                process.communicate(fixed_json(packet), timeout=max(0.001, absolute_deadline - time.monotonic()))
            finally:
                active_error = sys.exc_info()[1]
                try:
                    if process is not None and process.poll() is None:
                        # Only the frozen custody owner signals this original.
                        process.kill()
                        process.wait(timeout=max(0.001, min(5, self.total_end - time.monotonic())))
                except BaseException as error:
                    cleanup_error = error
                for row in descriptors:
                    if not row["birth_registered"]:
                        continue
                    row["sync_attempted"] = True
                    try:
                        os.fsync(row["fd"])
                        row["sync_succeeded"] = True
                    except BaseException as error:
                        cleanup_error = cleanup_error or error
                    finally:
                        # Mark before close. Its numeric descriptor must never
                        # be retried after an ambiguous original close result.
                        row["close_attempted"] = True
                        try:
                            os.close(row["fd"])
                            row["close_succeeded"] = True
                        except BaseException as error:
                            cleanup_error = cleanup_error or error
                handles = {"schema": "heptabao.formal-kv2-wire-original-log-handles.private.v1",
                    "original_rows": copy.deepcopy(descriptors),
                    "birth_count": sum(row["birth_registered"] for row in descriptors),
                    "close_attempt_count": sum(row["close_attempted"] for row in descriptors),
                    "close_success_count": sum(row["close_succeeded"] for row in descriptors),
                    "all_born_original_log_handles_retired": all(not row["birth_registered"]
                        or row["close_attempted"] and row["close_succeeded"] for row in descriptors),
                    "owned_signal_pending": self.owner.interrupted,
                    "scope": "parent_stdout_and_stderr_original_files_only"}
                self.handle_receipts.append(handles)
                if cleanup_error is not None:
                    self.owner.failed = True
                try:
                    self.h.private_write(self.evidence_dir / f"wire-{self.serial:06d}.handles.private.json",
                                         self.h.canonical(private_value(handles)))
                    if process is not None:
                        self.h.private_write(self.evidence_dir / f"wire-{self.serial:06d}.custody.private.json",
                                             self.h.canonical(private_value(copy.deepcopy(process.custody))))
                except BaseException as error:
                    self.owner.failed = True
                    cleanup_error = cleanup_error or error
                if cleanup_error is not None and active_error is None:
                    raise Refused("wire_original_cleanup_failed") from None
        finally:
            self.owner.protected -= 1
        need(not self.owner.failed and not self.owner.interrupted
             and time.monotonic() < absolute_deadline and process.returncode == 0,
             "wire_failed_or_unknown_no_retry")
        stdout = self.h.private_read(paths[0], 6 * MIB)
        stderr = self.h.private_read(paths[1], 65536)
        need(not stderr, "wire_private_error_retained")
        value = json.loads(stdout)
        need(self.h.file_pin(endpoint.ca_file, private=True) == ca
             and self.h.file_pin(endpoint.root_token_file, private=True) == root
             and (upload is None or self.h.file_pin(upload, private=True) == upload_pin),
             "wire_credential_and_archive_custody_unchanged")
        self.check_owner()
        return WireReply(status=value["status"], body=base64.b64decode(value["body"], validate=True),
            origin=value["origin"], peer_leaf_sha256=value["peer_leaf_sha256"], ca_sha256=value["ca_sha256"],
            elapsed_seconds=time.monotonic() - started, child_receipt=copy.deepcopy(process.custody),
            headers=value["headers"], downloaded_file=Path(value["downloaded_file"]) if value["downloaded_file"] else None)


class LifecycleObservations:
    """Thin validation of the frozen manager contract and retained originals.

    The concrete lifecycle adapter registers each actual private original as a
    PrivatePin in raw_original_pins before returning an observation. This map is
    an evidence registry, not self-authenticating manager or host authority.
    The parent reviews the adapter and its original tool bindings separately.
    """
    def __init__(self, helpers, *, expected_binary_sha256, raw_original_pins):
        import lifecycle_contract as contract
        import lifecycle_observations as observations
        for module, size, sha in (
            (contract, 5427, "a51fe465b6acbbbde6732fb35ee06e3c34ca1ccbadcb83b13c7717d4c80c527e"),
            (observations, 11696, "80b5937ba07304d78f7055a35ec9d8a159e051f6923a3e66accd247fa63bb532"),
        ):
            raw = Path(module.__file__).read_bytes()
            need(len(raw) == size and digest(raw) == sha, "frozen_lifecycle_observation_source")
        observations.digest(expected_binary_sha256)
        self.h, self.v = helpers, observations
        self.binary, self.originals = expected_binary_sha256, raw_original_pins

    def original(self, path, *, maximum=16 * MIB):
        self.v.private_ref(path)
        pin = self.originals.get(str(path))
        need(isinstance(pin, PrivatePin) and pin.path == Path(path),
             "actual_lifecycle_original_pin_required")
        raw = read_pin(pin, self.h, maximum)
        self.h.file_pin(pin.path, private=True)
        return raw

    def refs(self, value):
        value = private_value(value)
        if isinstance(value, dict):
            for name, child in value.items():
                if name.endswith("_private_ref") or name == "raw_private_ref":
                    self.original(child)
                else:
                    self.refs(child)
        elif isinstance(value, list):
            for child in value:
                self.refs(child)

    def child(self, value):
        need(type(value.pid) is int and value.pid > 0
             and value.pid == value.pgid == value.session
             and type(value.returncode) is int and value.returncode == 0
             and type(value.original_wait_count) is int and value.original_wait_count == 1
             and list(value.remaining_live_members) == [] and list(value.custody_gaps) == [],
             "actual_lifecycle_short_child_retired_once")
        self.original(value.original_receipt_private_ref)

    def manager(self, value, endpoint):
        self.v.validate_manager_identity(value, endpoint, expected_binary_sha256=self.binary)
        current = private_directory(endpoint.data_dir)
        need(all(value.data_directory_identity.get(key) == current[key] for key in current),
             "actual_manager_directory_still_same")
        self.refs(value)

    def seed(self, value: PreActivationSeedBinding, source: EndpointHandle):
        need(type(value.actual_shares) is int and value.actual_shares == 3
             and type(value.actual_threshold) is int and value.actual_threshold == 2
             and value.ack_durably_completed is True and value.v6_not_yet_activated is True
             and value.no_business_versions_written is True and value.current_history_backup is False,
             "actual_acknowledged_three_share_two_threshold_bootstrap_only")
        self.retirement(value.export_retirement, source)
        fence = value.export_retirement.exclusive_writer_fence_observation
        need(fence is not None, "actual_seed_exclusive_writer_fence_required")
        children = [child for child in value.export_retirement.command_children
                    if child.operation == "seed_export"]
        need(len(children) == 1, "one_actual_seed_export_child")
        self.child(children[0])
        raw = self.original(value.export_receipt_file, maximum=MIB)
        need(digest(raw) == value.export_receipt_sha256, "same_original_seed_export_receipt")
        receipt = self.h.decode(raw)
        need(receipt.get("schema") == 1 and receipt.get("operation") == "export"
             and all(receipt.get(key) is True for key in (
                 "original_writer_fence_held", "every_file_synced_and_read_back", "directory_publication_synced"))
             and receipt.get("cryptographic_state_admission_performed") is False
             and receipt.get("ha_qualified") is False, "actual_seed_export_receipt_scope")
        directory = private_directory(value.directory)
        need(receipt.get("destination_directory") == {
            "device": directory["dev"], "inode": directory["inode"],
            "owner": directory["uid"], "mode": directory["mode"]}, "same_actual_seed_destination")
        current_source = private_directory(source.data_dir)
        need(all(value.source_directory_identity.get(key) == current_source[key] for key in current_source),
             "same_preseed_source_directory")
        names = ("state.hbs", "journal.hbj", "ledger.hbl", "seal.json")
        seed = receipt.get("seed", {})
        rows = seed.get("artifacts", [])
        need(seed.get("profile") == "four-file-shamir-cipher-seed"
             and [row.get("leaf") for row in rows] == list(names)
             and {path.name for path in value.directory.iterdir()} == set(names)
             and [row.get("leaf") for row in value.artifacts_private] == list(names),
             "exact_four_file_bootstrap_seed")
        self.v.digest(receipt.get("seed_manifest_sha256"))
        for expected, artifact in zip(rows, value.artifacts_private):
            actual = self.h.file_pin(value.directory / expected["leaf"], private=True)
            need((actual["bytes"], actual["sha256"]) == (expected.get("bytes"), expected.get("sha256"))
                 and dict(artifact) == {"leaf": expected["leaf"], **actual},
                 "all_actual_seed_artifacts_match_export")
        self.original(fence["receipt_private_ref"])

    def restart(self, value: RestartObservation, endpoint: EndpointHandle):
        self.v.validate_restart_observation(value, endpoint, expected_binary_sha256=self.binary)
        self.manager(value.after, endpoint)
        self.refs(value)

    def retirement(self, value: ManagerRetirement, endpoint: EndpointHandle):
        self.v.validate_manager_identity(value.original, endpoint, expected_binary_sha256=self.binary)
        self.v.validate_manager_retirement(value, value.original)
        self.refs(value)

    def restore_target(self, value: RestoreTarget, seed: PreActivationSeedBinding):
        self.manager(value.manager, value.endpoint)
        need(value.current_history_restored is False
             and dict(value.fresh_directory_identity) == private_directory(value.endpoint.data_dir),
             "actual_fresh_bootstrap_target_before_history_restore")
        self.original(value.seed_binding_private_ref)
        self.original(value.original_receipt_private_ref)
        # The actual seed-stage receipt is the existing native seed schema.
        receipt = self.h.decode(self.original(value.seed_binding_private_ref, maximum=MIB))
        exported = self.h.decode(self.original(seed.export_receipt_file, maximum=MIB))
        need(receipt.get("schema") == 1 and receipt.get("operation") == "stage"
             and receipt.get("seed") == exported.get("seed")
             and receipt.get("seed_manifest_sha256") == exported.get("seed_manifest_sha256")
             and receipt.get("every_file_synced_and_read_back") is True
             and receipt.get("directory_publication_synced") is True,
             "actual_stage_of_same_pre_activation_seed")
        directory = private_directory(value.endpoint.data_dir)
        need(receipt.get("destination_directory") == {
            "device": directory["dev"], "inode": directory["inode"],
            "owner": directory["uid"], "mode": directory["mode"]}, "actual_stage_target_identity")

    def handoff(self, value: PersistentHandoff, endpoint: EndpointHandle):
        need(value.endpoint == endpoint and value.service_left_running is True,
             "actual_long_lived_source_handoff")
        self.manager(value.manager, endpoint)
        state = self.v.exact(value.state_observation,
            {"schema", "tls", "seal", "health", "raw_private_ref"}, "handoff_actual_state_shape")
        need(state["schema"] == "heptabao.actual-managed-kv2-state.v1", "handoff_actual_state_schema")
        tls = self.v.exact(state["tls"], {
            "schema", "origin", "verify_mode", "check_hostname", "peer_leaf_sha256", "protocol", "raw_private_ref"},
            "handoff_tls_shape")
        need(tls["schema"] == "heptabao.actual-managed-tls-observation.v1"
             and tls["origin"] == endpoint.origin and tls["verify_mode"] == "CERT_REQUIRED"
             and tls["check_hostname"] is True and tls["peer_leaf_sha256"] == endpoint.leaf_sha256
             and tls["protocol"] in ("TLSv1.2", "TLSv1.3"), "handoff_actual_strict_tls")
        self.v.validate_seal_response(state["seal"], method="GET", path="sys/seal-status", sealed=False, progress=0)
        health = self.v.exact(state["health"],
            {"schema", "method", "path", "http_status", "body", "raw_private_ref"}, "handoff_health_shape")
        need(health["schema"] == "heptabao.actual-private-health-response.v1"
             and health["method"] == "GET" and health["path"] == "sys/health"
             and type(health["http_status"]) is int and health["http_status"] == 200
             and health["body"].get("initialized") is True
             and all(health["body"].get(key) is False for key in (
                 "sealed", "standby", "ha_enabled", "recovery_required")), "handoff_actual_normal_health")
        owner = self.v.exact(value.long_lived_manager_ownership_observation, {
            "schema", "domain", "label", "manager_pid", "server_parent_pid", "controller_waitpid_parent",
            "query_argv", "query_returncode", "raw_private_ref"}, "persistent_manager_ownership_shape")
        need(owner["schema"] == "heptabao.launchd-persistent-ownership.v1"
             and owner["domain"] == endpoint.manager_domain and owner["label"] == endpoint.label
             and type(owner["manager_pid"]) is int and owner["manager_pid"] == value.manager.pid
             and type(owner["server_parent_pid"]) is int and owner["server_parent_pid"] == 1
             and owner["controller_waitpid_parent"] is False
             and owner["query_argv"] == ["/bin/launchctl", "print", endpoint.manager_domain + "/" + endpoint.label]
             and type(owner["query_returncode"]) is int and owner["query_returncode"] == 0,
             "actual_launchd_ownership_not_controller_child")
        operations = [child.operation for child in value.command_children]
        need(operations.count("launchctl_print_exact_label") == 1
             and operations.count("ps_numeric_census") == 1
             and set(operations) <= {"launchctl_print_exact_label", "ps_numeric_census", "wire_seal_status", "wire_health"},
             "handoff_complete_original_command_denominator")
        for child in value.command_children:
            self.child(child)
        self.refs(value)


def private_directory(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path,
         "private_directory_absolute_without_symlink")
    for component in (path, *path.parents):
        need(not component.is_symlink(), "private_directory_parent_symlink")
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
         and stat.S_IMODE(st.st_mode) == 0o700, "private_directory_owned_0700")
    return {"dev": st.st_dev, "inode": st.st_ino, "uid": st.st_uid, "mode": 0o700}


def disjoint(*paths):
    values = [Path(p) for p in paths]
    return all(a != b and not a.is_relative_to(b) and not b.is_relative_to(a)
               for i, a in enumerate(values) for b in values[i + 1:])


def read_pin(pin, helpers, maximum):
    need(type(pin.bytes) is int and 0 <= pin.bytes <= maximum
         and re.fullmatch(r"[0-9a-f]{64}", pin.sha256) is not None, "private_input_pin_shape")
    raw = helpers.private_read(pin.path, maximum)
    need(len(raw) == pin.bytes and digest(raw) == pin.sha256, "private_input_pin_mismatch")
    return raw


def safe_path(value, *, mount=False):
    limit = 64 if mount else 512
    need(isinstance(value, str) and 0 < len(value) <= limit
         and re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value) is not None
         and (not mount or "/" not in value), "canonical_kv_scope")
    need(not mount or value not in ("sys", "auth", "cubbyhole", "identity"), "reserved_mount")
    return value


def projection_rows(capture, projection, business_mount, capture_sha256):
    """Recompute every agent's original complete two-table row commitment."""
    need(capture.get("schema") == "heptabao.closed-current-sqlite-capture.v1"
         and capture.get("ok") is True, "complete_closed_capture_required")
    need(set(projection) == {"schema", "capture_sha256", "rows"}
         and projection["schema"] == "heptabao.current-sqlite-allrows-to-kv2.private.v1"
         and projection["capture_sha256"] == capture_sha256, "projection_generation_binding")
    dbs = capture.get("database_rows")
    need(isinstance(dbs, list), "capture_database_denominator")
    agents = [row for row in dbs if row.get("kind") == "agent"]
    need(len(agents) == capture.get("configured_agent_count") and len(agents) > 0
         and len({row.get("agent") for row in agents}) == len(agents), "capture_agent_denominator")
    rows = projection["rows"]
    need(isinstance(rows, list) and len(rows) <= len(agents) * 8192, "projection_rows_bound")
    records, identities, keys, per_agent = [], set(), set(), {}
    for row in rows:
        need(isinstance(row, dict) and set(row) == {
            "record_id", "agent_slot", "table", "row_fields", "kv_mount", "kv_key"},
            "projection_row_shape")
        slot, table = row["agent_slot"], row["table"]
        need(type(slot) is int and 0 <= slot < len(agents) and table in TABLES,
             "projection_row_source_scope")
        columns = TABLES[table]
        fields = row["row_fields"]
        need(isinstance(fields, dict) and set(fields) == set(columns), "complete_sqlite_columns")
        primary = fields[columns[0]]
        need(isinstance(primary, str) and primary and len(primary) <= 16384,
             "sqlite_primary_key_exact_text")
        # Strings (including credential JSON text) remain strings. SQL NULL,
        # numbers and the producer's explicit BLOB tag remain exact JSON cells.
        fixed_json(fields)
        identity = (slot, table, primary)
        key = safe_path(row["kv_key"])
        need(row["kv_mount"] == business_mount and key not in keys
             and identity not in identities, "projection_unique_scope_and_row")
        need(isinstance(row["record_id"], str)
             and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", row["record_id"]), "opaque_record_id")
        identities.add(identity)
        keys.add(key)
        grouped = per_agent.setdefault(slot, {name: [] for name in TABLES})
        grouped[table].append([fields[column] for column in columns])
        payload = {
            "schema": "heptabao.current-sqlite-row-baseline.v1",
            "provenance": {
                "kind": "current_sqlite_restored_generation",
                "capture_sha256": capture_sha256,
                "source_agent": agents[slot]["agent"],
                "source_table": table,
                "source_primary_key": primary,
                "source_updated_at": fields["updated_at"],
                "historical_openbao_versions_supplied": False,
            },
            "row": fields,
        }
        need(len(fixed_json({"data": payload, "options": {"cas": 0}})) <= JSON_REQUEST_MAX,
             "business_row_http_bound")
        records.append((key, json.loads(fixed_json(payload), parse_float=Decimal)))
    for slot, source in enumerate(agents):
        grouped = per_agent.get(slot, {name: [] for name in TABLES})
        for values in grouped.values():
            values.sort(key=lambda item: item[0])
            need(len(values) <= 4096, "original_per_table_row_bound")
        if source.get("present") and not source.get("empty_database_marker"):
            need(len(grouped["auth_profile_store"]) == source.get("auth_store_rows")
                 and len(grouped["auth_profile_state"]) == source.get("auth_state_rows")
                 and digest(fixed_json(grouped)) == source.get("auth_rows_sha256"),
                 "complete_agent_allrows_commitment")
        else:
            need(not any(grouped.values()), "absent_or_empty_agent_has_no_rows")
    need(len({row["record_id"] for row in rows}) == len(rows) and records,
         "unique_nonempty_business_baseline")
    return records, {"agents": len(agents), "database_families": len(dbs),
        "business_rows": len(records),
        "auth_profile_store_rows": sum(row["table"] == "auth_profile_store" for row in rows),
        "auth_profile_state_rows": sum(row["table"] == "auth_profile_state" for row in rows)}


def storage_witness(response, mount, key, version, metadata, payload, helpers):
    """a257 precise witness check, with the actual dynamic mount/key preserved."""
    value = response.get("data")
    need(isinstance(value, dict) and "data" not in value and "payload" not in value,
         "raw_witness_envelope")
    need(value.get("schema") == "heptabao-native-kv2-storage-witness-v1"
         and value.get("canonical_profile") == "heptabao-lossless-json-v1"
         and type(value.get("version")) is int
         and (value.get("mount"), value.get("path"), value.get("version")) == (mount, key, version),
         "raw_witness_actual_identity")
    need(type(value.get("destroyed")) is bool and all(value.get(field) == metadata[field] for field in (
        "created_time", "deletion_time", "destroyed")), "raw_witness_exact_version_metadata")
    need(type(value.get("mount_incarnation")) is int and 0 < value["mount_incarnation"] < 2**64
         and type(value.get("source_publication_generation")) is int
         and 0 <= value["source_publication_generation"] < 2**64
         and re.fullmatch(r"[0-9a-f]{64}", value.get("source_root_sha256", "")),
         "raw_witness_actual_root")
    raw = helpers.canonical(payload) if payload is not None else b""
    need(value.get("payload_present") is (payload is not None)
         and type(value.get("payload_canonical_bytes")) is int
         and value["payload_canonical_bytes"] == len(raw)
         and value.get("payload_canonical_sha256") == (digest(raw) if payload is not None else None),
         "raw_witness_complete_payload")
    return value


def export_matches(bundle, config, observed, expected_payloads, helpers):
    need(set(bundle) == {"schema", "config", "entries"}
         and bundle["schema"] == "openbao270-kv2-lossless-v1"
         and helpers.canonical(bundle["config"]) == helpers.canonical(config)
         and set(bundle["entries"]) == set(observed) == set(expected_payloads),
         "export_complete_key_denominator")
    entry_fields = ("created_time", "updated_time", "current_version", "oldest_version",
                    "current_metadata_version", "max_versions", "cas_required",
                    "metadata_cas_required", "delete_version_after", "custom_metadata")
    for key, item in observed.items():
        entry, metadata = bundle["entries"][key], item["metadata"]
        need(set(entry) == {*entry_fields, "versions"}
             and all(helpers.canonical(entry[f]) == helpers.canonical(metadata[f]) for f in entry_fields),
             "export_exact_key_metadata")
        expected = expected_payloads[key]
        need(set(entry["versions"]) == set(metadata["versions"]) == {str(v) for v in expected},
             "export_complete_version_denominator")
        for version, payload in expected.items():
            actual, meta = entry["versions"][str(version)], metadata["versions"][str(version)]
            need(set(actual) == {"created_time", "deletion_time", "destroyed", "source_deletion_time", "data"}
                 and all(actual[f] == meta[f] for f in ("created_time", "deletion_time", "destroyed"))
                 and actual["source_deletion_time"] == ""
                 and helpers.canonical(actual["data"]) == helpers.canonical(payload),
                 "export_exact_retained_payload_and_deletion_state")
    return bundle


class Session:
    """Private operation ledger: one dispatch per label; any unknown poisons it."""
    def __init__(self, plan, wire, helpers):
        self.plan, self.wire, self.h = plan, wire, helpers
        self.allowed = {"source": plan.source}
        self.used, self.unknown, self.stopped = set(), False, False
        self.events, self.counter = [], 0
        self.business = None
        self.snapshot = None
        self.negative_snapshot = None
        self.recovery_only = False

    def bind_business(self, records):
        need(self.business is None, "business_scope_already_bound")
        self.business = dict(records)
        need(len(self.business) == len(records), "business_scope_unique")

    def bind_snapshot(self, path, *, verified_readback=None):
        allowed = path.parent == self.plan.archive_staging_dir
        if verified_readback is not None:
            allowed = (path == verified_readback.path
                       and self.h.file_pin(path, private=True)["bytes"] == verified_readback.bytes
                       and self.h.file_pin(path, private=True)["sha256"] == verified_readback.sha256)
        need(self.snapshot is None and allowed,
             "one_current_backup_binding")
        self.snapshot = (path, self.h.file_pin(path, private=True))

    def bind_negative_snapshot(self, path):
        need(self.snapshot is not None and self.negative_snapshot is None
             and path.parent == self.plan.evidence_dir, "one_negative_snapshot_binding")
        original = self.h.inspect_v6_archive(self.snapshot[0])
        bad = self.h.inspect_v6_archive(path)
        need(original["metadata"] == bad["metadata"]
             and original["members"][:3] == bad["members"][:3]
             and original["members"][3]["bytes"] == bad["members"][3]["bytes"]
             and original["members"][3]["sha256"] != bad["members"][3]["sha256"],
             "only_sealed_checksum_negative_changed")
        self.negative_snapshot = (path, self.h.file_pin(path, private=True))

    def record(self, value):
        self.counter += 1
        self.h.private_write(self.plan.evidence_dir / f"event-{self.counter:06d}.private.json",
                             self.h.canonical(private_value(value)))
        # Persist the new directory entry before a mutation can be dispatched.
        fsync_directory(self.plan.evidence_dir)
        self.events.append(value)

    def add_restore(self, target):
        need("restore" not in self.allowed and not target.current_history_restored,
             "one_fresh_restore_target_only")
        source, endpoint = self.plan.source, target.endpoint
        need(endpoint.origin != source.origin and endpoint.label != source.label
             and disjoint(endpoint.data_dir, source.data_dir, self.plan.archive_staging_dir, self.plan.key_parent),
             "restore_target_distinct_from_source_and_backup")
        observed = private_directory(endpoint.data_dir)
        need(observed == dict(target.fresh_directory_identity), "fresh_restore_directory_identity")
        self.allowed["restore"] = endpoint

    def call(self, label, endpoint, method, path, body=None, *, download=None, upload=None, expected=200):
        need(not self.stopped, "prior_unknown_or_failure_no_more_operations")
        need(label not in self.used and endpoint in self.allowed, "single_dispatch_bound_endpoint")
        need(method in ("GET", "LIST", "POST") and not (download and upload), "protocol_method_direction")
        self.authorize_route(endpoint, method, path, body, upload)
        if upload is not None:
            need(endpoint == "restore" and method == "POST" and path == "sys/storage/raft/snapshot",
                 "snapshot_restore_only_independent_target")
            matches = [row for row in (self.snapshot, self.negative_snapshot)
                       if row is not None and row[0] == upload]
            need(len(matches) == 1 and self.h.file_pin(upload, private=True) == matches[0][1],
                 "exact_current_snapshot_or_fixed_negative_input")
        raw = None if body is None else self.h.canonical(body)
        need(raw is None or len(raw) <= JSON_REQUEST_MAX, "json_request_bound")
        mutating = method == "POST" and path != "sys/internal/storage/kv2-version-witness"
        end = min(self.plan.deadline.work_end, time.monotonic() + HTTP_SECONDS)
        need(time.monotonic() < end, "original_phase_deadline")
        self.used.add(label)
        event = {"operation": label, "endpoint": endpoint, "method": method, "path": path,
                 "request_body": body, "mutating": mutating, "outcome": "unknown", "attempts": 1}
        self.record(dict(event))
        maximum = (EXPORT_MAX if path.startswith("sys/migration/") else SNAPSHOT_MAX) if download else JSON_RESPONSE_MAX
        try:
            reply = self.wire.exchange(self.allowed[endpoint], method, path, raw,
                download=download, upload=upload, maximum=maximum, absolute_deadline=end)
            need(time.monotonic() < end and reply.elapsed_seconds <= HTTP_SECONDS,
                 "original_http_absolute_deadline")
            bound = self.allowed[endpoint]
            need(reply.origin == bound.origin and reply.peer_leaf_sha256 == bound.leaf_sha256
                 and reply.ca_sha256 == digest(self.h.private_read(bound.ca_file, MIB)),
                 "same_connection_tls_endpoint_binding")
            child = reply.child_receipt
            need(type(child.get("pid")) is int and child["pid"] > 0
                 and child.get("exec_admitted") is True and child.get("returncode") == 0
                 and child.get("original_wait_completed") is True and child.get("original_wait_count") == 1
                 and child.get("no_live_members_before_reap") is True
                 and child.get("gaps") == [], "wire_original_child_custody")
            need(type(reply.status) is int and 100 <= reply.status <= 599
                 and len(reply.body) <= JSON_RESPONSE_MAX, "http_status_and_body_bound")
            if download is not None:
                need(reply.downloaded_file == download and reply.body == b"",
                     "binary_download_exact_private_target")
                pin = self.h.file_pin(download, private=True)
                media = "application/vnd.heptabao.kv2-lossless+json" if path.startswith("sys/migration/") else "application/gzip"
                need(reply.headers.get("Content-Type") == media
                     and reply.headers.get("Content-Length") == str(pin["bytes"])
                     and 0 < pin["bytes"] <= maximum, "binary_typed_content_length")
                decoded = {"private_download": str(download), "pin": pin}
            else:
                decoded = self.h.decode(reply.body) if reply.body else {}
            event.update(outcome="response_received", status=reply.status, response=decoded,
                         tls_peer_sha256=reply.peer_leaf_sha256, child=dict(child))
            self.record(event)
            need(reply.status == expected, "exact_http_status")
            return decoded
        except BaseException:
            # A denied known response or broken framing also stops the plan.
            # Nothing dispatches a retry or guesses a mutation's outcome.
            self.stopped = True
            self.unknown = event["outcome"] == "unknown"
            event["failure_code"] = "operation_stopped_no_retry"
            self.record(event)
            raise

    def authorize_route(self, endpoint, method, path, body, upload):
        need(self.business is not None, "business_scope_not_bound")
        need(not (self.recovery_only and endpoint == "source" and method == "POST"
                  and path != "sys/internal/storage/kv2-version-witness"),
             "recovery_phase_source_is_readonly_no_activation_or_import")
        mounts = (self.plan.business_mount, self.plan.canary_mount)
        keysets = {mounts[0]: set(self.business), mounts[1]: {self.plan.canary_key}}
        if method == "GET" and path in ("sys/health", "sys/internal/capacity", "sys/storage/raft/snapshot"):
            return
        if method == "GET" and path in {"sys/migration/openbao/kv2/export?mount=" + m for m in mounts}:
            return
        if method == "POST" and path == "sys/storage/native-v6/activate":
            need(endpoint == "source" and body == {} and upload is None, "source_activation_only")
            return
        if method == "POST" and path == "sys/storage/raft/snapshot":
            need(endpoint == "restore" and upload is not None and body is None,
                 "snapshot_restore_only_independent_target")
            return
        if method == "POST" and path == "sys/internal/storage/kv2-version-witness":
            need(isinstance(body, dict) and set(body) == {"mount", "path", "version"}
                 and body["mount"] in keysets and body["path"] in keysets[body["mount"]]
                 and type(body["version"]) is int and 1 <= body["version"] <= 4,
                 "raw_witness_fixed_inventory")
            return
        need(isinstance(path, str) and "/" in path, "route_scope")
        mount, rest = path.split("/", 1)
        need(mount in mounts, "route_mount_scope")
        if rest == "config":
            need(method == "GET" or (method == "POST" and endpoint == "source"
                 and mount == self.plan.canary_mount and body == {
                     "max_versions": 0, "cas_required": True, "metadata_cas_required": True,
                     "delete_version_after": "0s"}), "config_scope")
            return
        if method == "LIST" and rest == "metadata/":
            return
        need("/" in rest, "route_key_required")
        operation, resource = rest.split("/", 1)
        key, marker, query = resource.partition("?")
        need(key in keysets[mount] and (not marker or re.fullmatch(r"version=[1-4]", query)),
             "route_key_and_version_scope")
        if method == "GET":
            need(operation in ("metadata", "data"), "read_operation_scope")
            return
        need(method == "POST" and not marker, "write_operation_scope")
        if mount == self.plan.business_mount:
            need(endpoint == "source" and operation == "data" and body == {
                "data": self.business[key], "options": {"cas": 0}}, "business_cas0_only")
        else:
            need(operation in ("data", "metadata", "delete", "destroy", "undelete")
                 and key == self.plan.canary_key, "canary_write_scope")


def private_value(value):
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            need(isinstance(key, str) or type(key) is int, "private_json_key_type")
            text = str(key)
            need(text not in result, "private_json_key_collision")
            result[text] = private_value(item)
        return result
    if isinstance(value, (list, tuple)):
        return [private_value(item) for item in value]
    if isinstance(value, float):
        return Decimal(json.dumps(value, allow_nan=False))
    return value


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def terminal_succeeded(value):
    need(value.get("state") == "succeeded" and value.get("exit_code") == 0
         and all(value.get(k) is True for k in (
             "output_complete", "output_durable", "terminal_publication_confirmed"))
         and all(value.get(k) is False for k in ("timed_out", "cancelled", "automatic_retry"))
         and value.get("log_errors") == {"stdout": None, "stderr": None}
         and value.get("log_synced") == {"stdout": True, "stderr": True}
         and value.get("log_truncated") == {"stdout": False, "stderr": False},
         "snapshot_phase_original_terminal_required")


def prior_ledger_complete(state, business_mount, business, helpers):
    groups = {}
    for row in state["complete_original_operation_ledger"]:
        if "operation" in row:
            groups.setdefault(row["operation"], []).append(row)
    labels = state["original_operation_labels"]
    need(len(labels) == len(set(labels)) == len(groups) and set(labels) == set(groups),
         "original_mutation_ledger_complete_denominator")
    accepted_business, activations, snapshots = {}, 0, 0
    for rows in groups.values():
        need(len(rows) == 2 and rows[0]["outcome"] == "unknown"
             and rows[1]["outcome"] == "response_received" and "failure_code" not in rows[1]
             and all(row["attempts"] == 1 for row in rows), "original_operation_completed_once")
        first, last = rows
        need(all(helpers.canonical(private_value(first[key])) == helpers.canonical(private_value(last[key]))
                 for key in ("operation", "endpoint", "method", "path", "request_body", "mutating")),
             "same_original_operation_intent_and_result")
        if first["method"] == "POST" and first["path"] == "sys/storage/native-v6/activate":
            need(last["status"] == 204 and first["endpoint"] == "source", "original_single_activation")
            activations += 1
        prefix = business_mount + "/data/"
        if first["method"] == "POST" and first["path"].startswith(prefix):
            key = first["path"][len(prefix):]
            need(key in business and key not in accepted_business and first["endpoint"] == "source"
                 and helpers.canonical(first["request_body"]) == helpers.canonical({
                     "data": business[key], "options": {"cas": 0}})
                 and last["status"] == 200 and last["response"].get("data", {}).get("version") == 1,
                 "original_business_cas0_exactly_once")
            accepted_business[key] = True
        if first["method"] == "GET" and first["path"] == "sys/storage/raft/snapshot":
            need(first["endpoint"] == "source" and last["status"] == 200, "original_current_snapshot_download")
            snapshots += 1
    need(set(accepted_business) == set(business) and activations == snapshots == 1,
         "original_accepted_business_activation_snapshot_denominator")


def replica_observations(binding, original, helpers, deadline):
    need(binding.host in ("rog", "pocket4") and binding.expected_uid > 0
         and binding.destination.is_absolute() and len(binding.archive_transport_original_refs) > 0,
         "independent_reviewed_remote_host_and_originals_required")
    before = helpers.decode(read_pin(binding.native_info_before, helpers, 2 * MIB))
    after = helpers.decode(read_pin(binding.native_info_after, helpers, 2 * MIB))
    need(before == after and before.get("path") == str(binding.destination)
         and type(before.get("size")) is int and before["size"] == original.bytes
         and before.get("sha256") == original.sha256
         and type(before.get("mode")) is int and before["mode"] == 0o600,
         "remote_native_file_info_before_after_exact")
    metadata = before.get("metadata", {})
    need(type(metadata.get("uid")) is int and metadata["uid"] == binding.expected_uid
         and type(metadata.get("mode")) is int and metadata["mode"] == 0o600
         and type(metadata.get("link_count")) is int and metadata["link_count"] == 1,
         "remote_native_archive_owner_mode_link_count")
    version = before.get("version")
    need(isinstance(version, str) and re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+", version)
         and int(version.split(":")[2]) == original.bytes,
         "actual_remote_immutable_read_version")
    for ref in binding.archive_transport_original_refs:
        need(time.monotonic() < deadline.work_end, "remote_evidence_original_deadline")
        read_pin(ref, helpers, 2 * MIB)
    need(binding.full_readback.path != original.path
         and binding.full_readback.bytes == original.bytes <= SNAPSHOT_MAX
         and binding.full_readback.sha256 == original.sha256,
         "complete_independent_remote_readback_pin")
    pins = [helpers.file_pin(p.path, private=True) for p in (original, binding.full_readback)]
    need(all(value["bytes"] == original.bytes and value["sha256"] == original.sha256 for value in pins)
         and (pins[0]["device"], pins[0]["inode"]) != (pins[1]["device"], pins[1]["inode"]),
         "independent_readback_regular_file_not_alias")
    count = 0
    with os.fdopen(os.open(original.path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as a, \
         os.fdopen(os.open(binding.full_readback.path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as b:
        while True:
            need(time.monotonic() < deadline.work_end, "remote_readback_comparison_deadline")
            left, right = a.read(65536), b.read(65536)
            need(left == right, "remote_archive_full_byte_comparison")
            count += len(left)
            if not left:
                break
    need(count == original.bytes
         and all(helpers.file_pin(p.path, private=True) == pin
                 for p, pin in zip((original, binding.full_readback), pins)),
         "remote_readback_full_length_and_original_identity_unchanged")
    return {"remote_host_authority_basis": "parent_independent_review_of_original_native_requests_and_responses",
            "single_json_self_authenticates_host": False, "host": binding.host,
            "native_before": before, "native_after": after, "local_pins": pins,
            "full_bytes_compared": count, "archive_transport_original_count": len(binding.archive_transport_original_refs),
            "physical_failure_domain_claim_from_st_dev": False}


def sqlite_projection_decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate_projection_key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, "nonfinite_projection_number"))


class ProtocolRun:
    def __init__(self, plan: Plan, lifecycle: Lifecycle, observations: LifecycleObservations,
                 generation: ValidatedGeneration, wire: Wire, helpers):
        self.plan, self.life, self.obs, self.generation = plan, lifecycle, observations, generation
        self.h, self.session = helpers, Session(plan, wire, helpers)
        self.checks, self.counts, self.target = [], {}, None
        self.expected, self.baseline = {}, None
        self.deleted, self.destroyed = set(), set()
        self.sequence = 0
        self.output_ready = False
        self.phase_checks = SNAPSHOT_CHECKS
        self.public = {
            "schema": "heptabao.normal-kv2-protocol-acceptance.public.v1",
            "status": "failed", "normal_kv2_protocol_completed": False,
            "formal_service_qualified": False, "business_client_cutover": False,
            "source_service_rollback_qualified": False, "traffic_rollback_qualified": False,
            "physical_ha_qualified": False, "authbus_qualified": False,
            "old_asset_cleanup_authorized": False, "full_replacement_qualified": False,
            "historical_openbao_history_supplied": False,
            "source_live_freshness_or_cross_db_atomicity_claimed": False,
            "credential_values_or_content_fingerprints_published": False,
            "actual_protocol_execution": False, "required_check_count": len(SNAPSHOT_CHECKS),
            "http_deadline_seconds": HTTP_SECONDS, "automatic_retry": False,
            "independent_remote_archive_custody_verified": False,
            "mac_archive_directory_is_encrypted_staging_only": True,
            "physical_failure_domain_claim_from_st_dev": False,
        }

    def mark(self, name, evidence):
        need(name in self.phase_checks and name not in self.checks, "unique_acceptance_obligation")
        self.session.record({"check": name, "observations": private_value(evidence)})
        self.checks.append(name)

    def call(self, endpoint, method, path, body=None, **kwargs):
        self.sequence += 1
        phase = "recovery" if self.session.recovery_only else "snapshot"
        return self.session.call(f"{phase}-op-{self.sequence:06d}", endpoint, method, path, body, **kwargs)

    def capacity(self, endpoint):
        value = self.call(endpoint, "GET", "sys/internal/capacity")
        need(isinstance(value.get("data"), dict), "actual_capacity_response")
        return value["data"]

    def observe(self, endpoint, label, *, deleted=None):
        deleted = self.deleted if deleted is None else deleted
        result = {}
        for mount, keys in self.expected.items():
            config = self.call(endpoint, "GET", mount + "/config")["data"]
            observed = {}
            for key, versions in keys.items():
                metadata = self.call(endpoint, "GET", mount + "/metadata/" + key)["data"]
                need(type(metadata.get("current_version")) is int
                     and set(metadata["versions"]) == {str(v) for v in versions}
                     and metadata["current_version"] == max(versions), "api_complete_version_denominator")
                rows = {}
                for version, payload in versions.items():
                    meta = metadata["versions"][str(version)]
                    destroyed = (mount, key, version) in self.destroyed
                    is_deleted = (mount, key, version) in deleted
                    need(meta.get("destroyed") is destroyed and bool(meta.get("deletion_time")) is is_deleted,
                         "api_exact_delete_destroy_state")
                    status = 404 if destroyed or is_deleted else 200
                    response = self.call(endpoint, "GET", f"{mount}/data/{key}?version={version}", expected=status)
                    data = response.get("data", {})
                    need(isinstance(data, dict) and isinstance(data.get("metadata"), dict)
                         and data["metadata"].get("version") == version
                         and all(data["metadata"].get(field) == meta[field]
                                 for field in ("created_time", "deletion_time", "destroyed"))
                         and self.h.canonical(data.get("data")) == self.h.canonical(None if status == 404 else payload),
                         "api_complete_payload_and_metadata")
                    raw = self.call(endpoint, "POST", "sys/internal/storage/kv2-version-witness", {
                        "mount": mount, "path": key, "version": version})
                    witness = storage_witness(raw, mount, key, version, meta, payload, self.h)
                    rows[str(version)] = {"api": response, "raw": witness}
                observed[key] = {"metadata": metadata, "versions": rows}
            path = self.plan.evidence_dir / f"{label}-{mount}.lossless.private.json"
            self.call(endpoint, "GET", "sys/migration/openbao/kv2/export?mount=" + mount, download=path)
            bundle = self.h.decode(self.h.private_read(path, EXPORT_MAX))
            export_matches(bundle, config, observed, keys, self.h)
            result[mount] = {"config": config, "observed": observed, "bundle": bundle}
        self.session.record({"complete_inventory_observation": label, "endpoint": endpoint, "result": result})
        return result

    def same_history(self, left, right):
        need(set(left) == set(right), "history_mount_denominator")
        need(all(self.h.canonical(left[m]["bundle"]) == self.h.canonical(right[m]["bundle"])
                 for m in left), "complete_current_history_equal")

    def restart(self, endpoint):
        observation = (self.life.cold_restart(deadline=self.plan.deadline) if endpoint == "source"
                       else self.life.cold_restart_restore(self.target, deadline=self.plan.deadline))
        bound = self.session.allowed[endpoint]
        self.obs.restart(observation, bound)
        need(observation.retirement.server_waitpid_performed_by_this_controller is False
             and observation.before.pid != observation.after.pid
             and observation.before.label == observation.after.label == bound.label
             and observation.before.domain == observation.after.domain == bound.manager_domain,
             "manager_restart_distinct_actual_owner")
        self.session.record({"restart": endpoint, "original_observation": private_value(observation)})
        return observation

    def no_current_history(self, label):
        capacity = self.capacity("restore")
        need(capacity.get("state_storage_format") != "heptabao-state-records-v6",
             "bootstrap_is_not_current_native_store")
        observations = []
        for mount, keys in self.expected.items():
            for key, versions in keys.items():
                for version in versions:
                    missing = self.call("restore", "GET", f"{mount}/data/{key}?version={version}", expected=404)
                    raw = self.call("restore", "POST", "sys/internal/storage/kv2-version-witness", {
                        "mount": mount, "path": key, "version": version}, expected=501)
                    need(not isinstance(missing.get("data"), dict) or missing["data"].get("data") is None,
                         "bootstrap_must_not_supply_business_payload")
                    need(raw.get("data") is None, "bootstrap_raw_witness_unavailable")
                    observations.append({"mount": mount, "key": key, "version": version,
                                         "api_status": 404, "raw_status": 501})
        self.session.record({"bootstrap_missing_history": label, "capacity": capacity,
                             "observations": observations})
        return capacity

    def admit(self):
        p = self.plan
        safe_path(p.business_mount, mount=True)
        safe_path(p.canary_mount, mount=True)
        safe_path(p.canary_key)
        need(p.business_mount != p.canary_mount, "business_canary_mounts_distinct")
        need(time.monotonic() < p.deadline.work_end < p.deadline.total_end
             and p.deadline.original_entry < p.deadline.work_end, "outer_original_deadline_required")
        self.directory_pins = {name: private_directory(path) for name, path in (
            ("evidence", p.evidence_dir), ("backup", p.archive_staging_dir), ("keys", p.key_parent),
            ("source", p.source.data_dir))}
        need(disjoint(p.evidence_dir, p.archive_staging_dir, p.key_parent, p.source.data_dir)
             and self.directory_pins["backup"]["dev"] != self.directory_pins["source"]["dev"],
             "separate_local_archive_staging_filesystem_not_independent_remote_custody")
        need(not list(p.evidence_dir.iterdir()) and not list(p.archive_staging_dir.iterdir()),
             "fresh_protocol_evidence_and_backup_roots")
        self.output_ready = True
        need(self.life.source_handle() == p.source, "exact_lifecycle_source_endpoint")
        proof = self.generation.reconcile(p.generation, deadline=p.deadline)
        capture = self.h.decode(read_pin(p.generation.capture, self.h, 16 * MIB))
        projection = sqlite_projection_decode(read_pin(p.generation.projection, self.h, EXPORT_MAX))
        records, self.counts = projection_rows(capture, projection, p.business_mount, p.generation.capture.sha256)
        need(self.counts["agents"] == proof["result"]["captured_agent_count"]
             and self.counts["database_families"] == proof["result"]["declared_database_family_count"]
             and self.counts["auth_profile_store_rows"] == proof["result"]["cold_sqlite"]["restore"]["all_agent_auth_store_rows"]
             and self.counts["auth_profile_state_rows"] == proof["result"]["cold_sqlite"]["restore"]["all_agent_auth_state_rows"],
             "projection_and_independent_readback_same_denominators")
        self.obs.seed(p.seed, p.source)
        need(p.seed.actual_shares >= 3 and p.seed.actual_threshold == 2
             and p.seed.ack_durably_completed and p.seed.v6_not_yet_activated
             and p.seed.no_business_versions_written and not p.seed.current_history_backup,
             "preactivation_seed_is_bootstrap_only_with_split_threshold")
        self.session.bind_business(records)
        self.expected = {p.business_mount: {key: {1: value} for key, value in records},
                         p.canary_mount: {p.canary_key: {
                             1: {"canary_generation": 1}, 2: None, 3: {"canary_generation": 3}}}}
        self.deleted = {(p.canary_mount, p.canary_key, 1)}
        self.destroyed = {(p.canary_mount, p.canary_key, 2)}
        self.mark("complete_current_generation_projection_bound", proof)

    def seed_baseline(self):
        p = self.plan
        need(self.capacity("source").get("state_storage_format") != "heptabao-state-records-v6",
             "actual_source_not_yet_activated")
        for mount in (p.business_mount, p.canary_mount):
            config = self.call("source", "GET", mount + "/config")["data"]
            need(config == {"max_versions": 0, "cas_required": False,
                            "metadata_cas_required": False, "delete_version_after": "0s"},
                 "seed_mount_default_configuration")
            self.call("source", "LIST", mount + "/metadata/", expected=404)
        self.call("source", "POST", "sys/storage/native-v6/activate", {}, expected=204)
        active = self.capacity("source")
        need(active.get("state_storage_format") == "heptabao-state-records-v6", "ordinary_native_activation")
        self.mark("source_pristine_mounts_and_native_activation", active)
        for key, payload in self.session.business.items():
            written = self.call("source", "POST", p.business_mount + "/data/" + key,
                                {"data": payload, "options": {"cas": 0}})
            need(type(written.get("data", {}).get("version")) is int
                 and written["data"]["version"] == 1, "business_new_baseline_version_one")
        self.mark("all_business_rows_written_once_as_new_v1", {"rows": len(self.session.business)})
        mount, key = p.canary_mount, p.canary_key
        self.call("source", "POST", mount + "/config", {
            "max_versions": 0, "cas_required": True, "metadata_cas_required": True,
            "delete_version_after": "0s"}, expected=204)
        self.call("source", "POST", mount + "/metadata/" + key,
                  {"custom_metadata": {"purpose": "formal-kv2-canary"}, "metadata_cas": 0}, expected=204)
        for version in (1, 2, 3):
            result = self.call("source", "POST", mount + "/data/" + key,
                {"data": {"canary_generation": version}, "options": {"cas": version - 1}})
            need(type(result["data"].get("version")) is int
                 and result["data"]["version"] == version, "canary_exact_version_sequence")
        self.call("source", "POST", mount + "/delete/" + key, {"versions": [1]}, expected=204)
        self.call("source", "POST", mount + "/destroy/" + key, {"versions": [2]}, expected=204)
        before = self.observe("source", "canary-before-cas")
        self.call("source", "POST", mount + "/data/" + key,
            {"data": {"must_not_commit": True}, "options": {"cas": 0}}, expected=400)
        self.same_history(before, self.observe("source", "canary-after-data-denial"))
        self.call("source", "POST", mount + "/metadata/" + key,
            {"custom_metadata": {"must_not_commit": "true"}, "metadata_cas": 0}, expected=400)
        self.same_history(before, self.observe("source", "canary-after-metadata-denial"))
        counter = before[mount]["observed"][key]["metadata"]["current_metadata_version"]
        self.call("source", "POST", mount + "/metadata/" + key,
            {"custom_metadata": {"purpose": "formal-kv2-canary", "revision": "accepted"},
             "metadata_cas": counter}, expected=204)
        self.baseline = self.observe("source", "complete-source-baseline")
        metadata = self.baseline[mount]["observed"][key]["metadata"]
        need(metadata["current_metadata_version"] == counter + 1
             and metadata["custom_metadata"] == {"purpose": "formal-kv2-canary", "revision": "accepted"},
             "metadata_cas_success_exact")
        self.mark("canary_history_delete_destroy_and_cas_observed", {"versions": 3, "data_cas_denied": 400,
            "metadata_cas_denied": 400, "metadata_cas_counter_before": counter, "metadata_after": metadata})
        active = self.capacity("source")
        need(active.get("native_kv2_reader_format") == 2, "actual_paged_native_kv2_after_writes")
        self.mark("source_complete_api_metadata_raw_and_current_exports", self.baseline)

    def snapshot_current(self):
        p = self.plan
        restart = self.restart("source")
        self.same_history(self.baseline, self.observe("source", "source-cold"))
        self.mark("source_manager_cold_restart_and_complete_history", restart)
        self.archive = p.archive_staging_dir / "current-native-v6.snapshot"
        self.call("source", "GET", "sys/storage/raft/snapshot", download=self.archive)
        inspected = self.h.inspect_v6_archive(self.archive)
        self.session.bind_snapshot(self.archive)
        self.same_history(self.baseline, self.observe("source", "source-after-snapshot"))
        self.mark("current_snapshot_structure_and_encrypted_staging", inspected)

    def recover_current(self):
        p = self.plan
        self.target = self.life.fresh_restore_target(seed=p.seed, deadline=p.deadline)
        self.obs.restore_target(self.target, p.seed)
        self.session.add_restore(self.target)
        prior = self.no_current_history("seed-only")
        self.mark("bootstrap_seed_missing_all_current_versions", {"target": self.target, "capacity": prior})
        negative = p.evidence_dir / "bad-sealed-checksum.snapshot.private"
        self.h.tamper_sealed(self.archive, negative)
        self.session.bind_negative_snapshot(negative)
        self.call("restore", "POST", "sys/storage/raft/snapshot", upload=negative, expected=400)
        after = self.no_current_history("bad-restore-online")
        self.restart("restore")
        cold = self.no_current_history("bad-restore-cold")
        need(all(row.get("generation") == prior.get("generation")
                 and row.get("state_storage_format") == prior.get("state_storage_format") for row in (after, cold)),
             "bad_snapshot_no_persistent_commit")
        self.mark("bad_sealed_snapshot_rejected_without_commit", {"before": prior, "online": after, "cold": cold})
        self.call("restore", "POST", "sys/storage/raft/snapshot", upload=self.archive)
        self.same_history(self.baseline, self.observe("restore", "fresh-restored"))
        self.restart("restore")
        self.same_history(self.baseline, self.observe("restore", "fresh-restored-cold"))
        self.mark("fresh_restore_current_history_and_cold_reads", {"all_mounts_and_versions_equal": True})
        mount, key = p.canary_mount, p.canary_key
        self.call("restore", "POST", mount + "/undelete/" + key, {"versions": [1]}, expected=204)
        self.call("restore", "POST", mount + "/undelete/" + key, {"versions": [2]}, expected=204)
        recovered = self.observe("restore", "recovered-undelete", deleted=set())
        self.mark("recovered_canary_undelete_and_destroyed_absence", recovered[mount])
        self.call("restore", "POST", mount + "/data/" + key,
            {"data": {"canary_generation": 4}, "options": {"cas": 3}})
        self.expected[mount][key][4] = {"canary_generation": 4}
        warm = self.observe("restore", "recovered-version4-warm", deleted=set())
        self.restart("restore")
        self.same_history(warm, self.observe("restore", "recovered-version4-cold", deleted=set()))
        self.mark("recovered_canary_new_write_persistent", {"version": 4, "cold_history_equal": True})
        self.call("restore", "POST", "sys/storage/raft/snapshot", upload=self.archive)
        del self.expected[mount][key][4]
        self.restart("restore")
        self.same_history(self.baseline, self.observe("restore", "target-snapshot-rollback-cold"))
        self.mark("restore_target_snapshot_rollback_and_complete_history", {
            "scope": "independent_restore_target_only", "source_rollback": False, "traffic_rollback": False})
        self.same_history(self.baseline, self.observe("source", "source-after-restore-target-tests"))
        self.mark("source_business_and_canary_unchanged", {"complete_both_mount_histories_equal": True})

    def source_handoff(self):
        handoff = self.life.preserve_source_handoff(deadline=self.plan.deadline)
        self.obs.handoff(handoff, self.plan.source)
        need(handoff.endpoint == self.plan.source and handoff.service_left_running,
             "explicit_persistent_manager_handoff")
        return handoff

    def plan_binding(self):
        value = private_value(self.plan)
        del value["deadline"], value["evidence_dir"]
        return value

    def retained_inputs(self):
        read_pin(self.plan.generation.projection, self.h, EXPORT_MAX)
        read_pin(self.plan.generation.capture, self.h, 16 * MIB)
        need(self.h.file_pin(self.archive, private=True) == self.session.snapshot[1],
             "original_current_archive_unchanged")
        for name, path in (("evidence", self.plan.evidence_dir), ("backup", self.plan.archive_staging_dir),
                           ("keys", self.plan.key_parent), ("source", self.plan.source.data_dir)):
            need(private_directory(path) == self.directory_pins[name], "private_root_identity_unchanged")

    def publish_phase_result(self, status, *, failure=False):
        self.public.update(status=status, observed_check_count=len(self.checks),
            required_check_count=len(self.phase_checks), phase_obligation_names=list(self.phase_checks),
            checks=[{"check": name, "passed": True} for name in self.checks], counts=self.counts,
            unknown_http_outcome=self.session.unknown, source_current_version_baseline=1,
            restore_rollback_scope="independent_restore_target_only",
            failure_code="protocol_or_cleanup_failed" if failure else None)
        if self.output_ready:
            need(private_directory(self.plan.evidence_dir) == self.directory_pins["evidence"],
                 "private_output_root_still_owned")
            self.h.private_write(self.plan.evidence_dir / "protocol-result.public.json", fixed_json(self.public))
            fsync_directory(self.plan.evidence_dir)

    def snapshot_ready(self):
        """Single import phase. Never waits for MCP or enters recovery."""
        self.phase_checks = SNAPSHOT_CHECKS
        self.public.update(phase="snapshot_ready", actual_protocol_execution=True)
        try:
            need(type(self.session.wire) is OwnedWire and type(self.generation) is ReadbackGenerationAdapter
                 and type(self.obs) is LifecycleObservations,
                 "actual_fixed_wire_and_generation_adapters_required")
            self.admit()
            self.seed_baseline()
            self.snapshot_current()
            handoff = self.source_handoff()
            self.mark("snapshot_ready_source_manager_handoff_observed", handoff)
            self.retained_inputs()
            need(self.checks == list(SNAPSHOT_CHECKS) and time.monotonic() < self.plan.deadline.work_end,
                 "complete_snapshot_phase_original_budget")
            self.public.update(status="awaiting_remote_backup_custody", local_current_snapshot_ready=True,
                normal_kv2_protocol_completed=False, private_continuation_written=True,
                observed_check_count=len(self.checks), required_check_count=len(SNAPSHOT_CHECKS),
                phase_obligation_names=list(SNAPSHOT_CHECKS),
                checks=[{"check": name, "passed": True} for name in self.checks], counts=self.counts,
                unknown_http_outcome=False, source_current_version_baseline=1,
                restore_rollback_scope="independent_restore_target_only", failure_code=None)
            archive_pin = self.h.file_pin(self.archive, private=True)
            continuation = {
                "schema": "heptabao.normal-kv2-snapshot-ready.private.v1",
                "protocol_source_sha256": digest(Path(__file__).read_bytes()),
                "plan_binding": self.plan_binding(), "directory_pins": self.directory_pins,
                "snapshot_private_pin": private_value(PrivatePin(self.archive, archive_pin["bytes"], archive_pin["sha256"])),
                "snapshot_file_identity": archive_pin, "full_current_history": self.baseline,
                "expected_payloads": self.expected, "deleted_versions": sorted(self.deleted),
                "destroyed_versions": sorted(self.destroyed), "snapshot_checks": list(self.checks),
                "source_manager_handoff": private_value(handoff), "counts": self.counts,
                "complete_original_operation_ledger": self.session.events,
                "original_operation_labels": sorted(self.session.used),
                "original_snapshot_phase_deadline": private_value(self.plan.deadline),
                "public_snapshot_result": dict(self.public),
                "resume_repeats_activation_import_or_cas0": False,
            }
            self.h.private_write(self.plan.evidence_dir / "snapshot-continuation.private.json",
                                 self.h.canonical(private_value(continuation)))
            fsync_directory(self.plan.evidence_dir)
            self.publish_phase_result("awaiting_remote_backup_custody")
        except BaseException:
            self.public.update(local_current_snapshot_ready=False, normal_kv2_protocol_completed=False)
            self.publish_phase_result("failed", failure=True)
            raise Refused("snapshot_phase_failed_no_automatic_retry") from None
        return dict(self.public)

    def admit_resume(self, inputs):
        p = self.plan
        need(type(self.session.wire) is OwnedWire and type(self.generation) is ReadbackGenerationAdapter
             and type(self.obs) is LifecycleObservations,
             "actual_fixed_wire_and_generation_adapters_required")
        need(time.monotonic() < p.deadline.work_end < p.deadline.total_end,
             "new_predeclared_recovery_phase_deadline")
        evidence = private_directory(p.evidence_dir)
        need(not list(p.evidence_dir.iterdir()), "fresh_recovery_phase_evidence_only")
        self.directory_pins = {"evidence": evidence}
        self.output_ready = True
        state = self.h.decode(read_pin(inputs.continuation, self.h, SNAPSHOT_MAX))
        need(state.get("schema") == "heptabao.normal-kv2-snapshot-ready.private.v1"
             and state.get("protocol_source_sha256") == digest(Path(__file__).read_bytes())
             and state.get("resume_repeats_activation_import_or_cas0") is False
             and self.h.canonical(state["plan_binding"]) == self.h.canonical(self.plan_binding()),
             "exact_frozen_snapshot_continuation_and_same_plan")
        need(p.evidence_dir != inputs.continuation.path.parent
             and p.deadline.original_entry > state["original_snapshot_phase_deadline"]["original_entry"],
             "recovery_is_new_phase_not_original_clock_extension")
        terminal = self.h.decode(read_pin(inputs.snapshot_runtime_terminal, self.h, MIB))
        terminal_succeeded(terminal)
        prior_public = self.h.decode(read_pin(inputs.snapshot_public_result, self.h, MIB))
        need(prior_public == state["public_snapshot_result"]
             and prior_public["status"] == "awaiting_remote_backup_custody"
             and prior_public["checks"] == [{"check": name, "passed": True} for name in SNAPSHOT_CHECKS]
             and prior_public["required_check_count"] == prior_public["observed_check_count"] == len(SNAPSHOT_CHECKS)
             and prior_public["formal_service_qualified"] is False
             and prior_public["independent_remote_archive_custody_verified"] is False,
             "successful_snapshot_stage_not_import_replay")
        custody = self.h.decode(read_pin(inputs.snapshot_process_custody, self.h, 16 * MIB))
        need(custody.get("schema") == "heptabao.dr-original-process-custody.v1"
             and custody.get("finished") is True and custody.get("failed") is False
             and custody.get("interrupted") is False and custody.get("passed_process_custody") is True
             and custody.get("original_count") == len(custody.get("children", [])) > 0
             and all(row.get("exec_admitted") is True and row.get("original_wait_completed") is True
                     and row.get("original_wait_count") == 1 and row.get("no_live_members_before_reap") is True
                     and row.get("gaps") == [] for row in custody["children"]),
             "snapshot_phase_all_owned_originals_retired")
        for name, path in (("backup", p.archive_staging_dir), ("keys", p.key_parent), ("source", p.source.data_dir)):
            actual = private_directory(path)
            need(actual == state["directory_pins"][name], "snapshot_phase_original_roots_preserved")
            self.directory_pins[name] = actual
        need(disjoint(p.evidence_dir, p.archive_staging_dir, p.key_parent, p.source.data_dir),
             "recovery_evidence_not_within_original_service_or_keys")
        self.generation.reconcile(p.generation, deadline=p.deadline)
        capture = self.h.decode(read_pin(p.generation.capture, self.h, 16 * MIB))
        projection = sqlite_projection_decode(read_pin(p.generation.projection, self.h, EXPORT_MAX))
        records, self.counts = projection_rows(capture, projection, p.business_mount, p.generation.capture.sha256)
        self.session.bind_business(records)
        prior_ledger_complete(state, p.business_mount, self.session.business, self.h)
        self.expected = {mount: {key: {int(v): payload for v, payload in versions.items()}
                                 for key, versions in keys.items()}
                         for mount, keys in state["expected_payloads"].items()}
        need(self.counts == state["counts"] and set(self.expected) == {p.business_mount, p.canary_mount}
             and self.h.canonical(private_value(self.expected[p.business_mount]))
                 == self.h.canonical(private_value({key: {1: payload} for key, payload in records}))
             and self.expected[p.canary_mount] == {p.canary_key: {
                 1: {"canary_generation": 1}, 2: None, 3: {"canary_generation": 3}}},
             "resume_exact_original_business_and_canary_inventory")
        self.deleted = {tuple(value) for value in state["deleted_versions"]}
        self.destroyed = {tuple(value) for value in state["destroyed_versions"]}
        need(self.deleted == {(p.canary_mount, p.canary_key, 1)}
             and self.destroyed == {(p.canary_mount, p.canary_key, 2)}, "resume_original_deletion_inventory")
        self.baseline = state["full_current_history"]
        need(self.life.source_handle() == p.source, "same_existing_source_handle_on_resume")
        current_handoff = self.source_handoff()
        original_manager = state["source_manager_handoff"]["manager"]
        actual_manager = private_value(current_handoff.manager)
        identity_fields = ("domain", "label", "pid", "uid", "pgid", "session", "plist_file_identity",
                           "executable_identity", "data_directory_identity", "process_birth_observation")
        need(all(actual_manager[key] == original_manager[key] for key in identity_fields),
             "same_retained_source_manager_between_phases")
        self.same_history(self.baseline, self.observe("source", "resume-readonly-complete-source"))
        original = state["snapshot_private_pin"]
        self.original_snapshot = PrivatePin(Path(original["path"]), original["bytes"], original["sha256"])
        need(self.h.file_pin(self.original_snapshot.path, private=True) == state["snapshot_file_identity"],
             "original_staged_snapshot_unchanged")
        proof = replica_observations(inputs.remote, self.original_snapshot, self.h, p.deadline)
        self.archive = inputs.remote.full_readback.path
        need(disjoint(self.archive, p.source.data_dir, p.key_parent), "remote_readback_outside_service_and_key_roots")
        self.h.inspect_v6_archive(self.archive)
        self.session.bind_snapshot(self.archive, verified_readback=inputs.remote.full_readback)
        self.mark("independent_remote_archive_custody_and_full_readback", proof)
        self.public.update(independent_remote_archive_custody_verified=True,
            remote_host_authority_basis="parent_reviewed_original_native_tool_requests_and_responses",
            remote_archive_full_byte_comparison_verified=True,
            snapshot_phase_obligations_previously_verified=len(SNAPSHOT_CHECKS),
            activation_or_business_import_repeated_in_recovery=False)

    def resume_recovery(self, inputs: ResumeInputs):
        """Fresh recovery-only phase; never calls admit/activation/seed_baseline."""
        self.phase_checks = RECOVERY_CHECKS
        self.session.recovery_only = True
        self.public.update(phase="recovery_only", actual_protocol_execution=True)
        failure = None
        try:
            self.admit_resume(inputs)
            self.recover_current()
        except BaseException as error:
            failure = error
        finally:
            if self.target is not None:
                try:
                    retired = self.life.retire_restore_target(self.target, deadline=self.plan.deadline)
                    self.obs.retirement(retired, self.target.endpoint)
                    self.mark("restore_target_manager_retired", retired)
                except BaseException as error:
                    failure = failure or error
            if failure is None:
                try:
                    handoff = self.source_handoff()
                    self.mark("persistent_source_manager_handoff_observed", handoff)
                    self.retained_inputs()
                    read_pin(self.original_snapshot, self.h, SNAPSHOT_MAX)
                    need(self.checks == list(RECOVERY_CHECKS) and time.monotonic() < self.plan.deadline.work_end,
                         "complete_recovery_phase_original_budget")
                except BaseException as error:
                    failure = error
            self.public.update(normal_kv2_protocol_completed=failure is None,
                fresh_recovery_from_remote_readback_completed=failure is None)
            self.publish_phase_result("passed_protocol_only" if failure is None else "failed", failure=failure is not None)
        if failure is not None:
            raise Refused("recovery_phase_failed_no_automatic_retry") from None
        return dict(self.public)
