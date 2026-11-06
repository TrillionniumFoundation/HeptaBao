#!/usr/bin/env python3
"""Own a full34 oracle, then recover V6 from a separate filesystem into a new store.

This is a new DR25 specification, not a recovery of an earlier named receipt.
The unchanged full34 controller must first pass all of its 31 checks. Only an
explicit preactivation four-file seed and an actual pinned OpenBao 2.7.1 CLI
snapshot enter recovery. Original services are stopped and their entire private
root is quarantined. No original bundle is imported into the recovered server.

Different st_dev values prove different filesystems, not independent physical
disks. All data are synthetic. This controller grants no production authority.
"""
from __future__ import annotations

import argparse
import base64
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import zlib

import kv2_271_lossless_native_live as full

ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
VERSIONS = tuple(range(1, 20))
SEED_FILES = ("state.hbs", "journal.hbj", "ledger.hbl", "seal.json")
ARCHIVE_NAMES = ("meta.json", "state.bin", "SHA256SUMS", "SHA256SUMS.sealed")
CHILD_BYTES = 65536
CHECKS = (
    "input_source_and_binaries_pinned",
    "official_271_live_identity_verified",
    "official_full34_api_and_raw_history_bound",
    "normal_native_v6_file_profile",
    "preactivation_seed_export_pinned",
    "independent_backup_filesystem_verified",
    "official_cli_v6_save_complete",
    "complete_v6_archive_seal_binding",
    "backup_manifest_and_separate_key_custody",
    "original_processes_stopped",
    "original_directories_quarantined",
    "fresh_recovery_directory_and_tls_identity",
    "exact_seed_stage_verified",
    "old_closure_negative_cannot_read_history",
    "wrong_unseal_key_denied",
    "tampered_archive_denied_without_commit",
    "official_cli_v6_restore_once",
    "restored_api_19_versions_exact",
    "restored_raw_19_versions_exact",
    "restored_cold_reopen_history_exact",
    "soft_deleted_payload_undelete_exact",
    "destroyed_payload_not_resurrected",
    "data_and_metadata_cas_guards_exact",
    "new_write_survives_cold_reopen",
    "final_custody_cleanup_and_redaction",
)
need = full.need
Failure = full.Failure


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def json_hash(value):
    return digest(full.canonical(value))


def file_pin(path, *, private=False):
    """Hash one unchanged, unlinked regular file without following a leaf link."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular_unlinked_file_required")
        if private:
            need(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,
                 "private_file_custody_required")
        h = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while chunk := stream.read(65536):
                h.update(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
                  "st_mtime_ns", "st_ctime_ns")
        need(all(getattr(before, f) == getattr(after, f) for f in fields), "hashed_file_changed")
        return {"sha256": h.hexdigest(), "bytes": before.st_size, "device": before.st_dev,
                "inode": before.st_ino, "uid": before.st_uid,
                "mode": stat.S_IMODE(before.st_mode), "links": before.st_nlink}
    finally:
        os.close(fd)


def directory_identity(path):
    info = Path(path).lstat()
    need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "directory_required")
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
            "mode": stat.S_IMODE(info.st_mode)}


def private_parent(path):
    need(path.is_absolute() and path.resolve(strict=True) == path, "absolute_unlinked_parent_required")
    for part in (path, *path.parents):
        need(stat.S_ISDIR(part.lstat().st_mode) and not part.is_symlink(), "parent_symlink_refused")
    identity = directory_identity(path)
    need(identity["uid"] == os.geteuid() and identity["mode"] == 0o700,
         "owned_private_parent_required")
    return identity


def disjoint(paths):
    return all(a != b and not a.is_relative_to(b) and not b.is_relative_to(a)
               for i, a in enumerate(paths) for b in paths[i + 1:])


def tree_manifest(root):
    """Retain every original file hash and inode; never follow a closure link."""
    rows = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        current = Path(current)
        for name in directories:
            path = current / name
            rows.append({"path": str(path.relative_to(root)), "kind": "directory",
                         **directory_identity(path)})
        for name in files:
            path = current / name
            rows.append({"path": str(path.relative_to(root)), "kind": "file", **file_pin(path)})
    return {"root": directory_identity(root), "entries": rows}


def tree_summary(manifest):
    # The complete private tree includes plaintext synthetic credential files.
    # Even an aggregate of their hashes stays private; public custody evidence
    # records the directory boundary and counts without a guessing fingerprint.
    return {"root": manifest["root"], "complete_manifest_retained_privately": True,
            "credential_dependent_fingerprints_published": False,
            "file_count": sum(r["kind"] == "file" for r in manifest["entries"]),
            "directory_count": sum(r["kind"] == "directory" for r in manifest["entries"])}


def write_private_tree(path, manifest):
    full.private_write(path, encoded({"schema": "heptabao-dr25-private-closure-v1",
        "manifest_sha256": digest(encoded(manifest)), "manifest": manifest,
        "contains_private_credential_file_fingerprints": True, "publishable": False}))


def credential_markers(secrets):
    """Defense in depth; no credential-bearing input is a public hash source."""
    markers = set()
    for secret in secrets:
        if secret:
            raw = secret.encode()
            markers.update((secret, digest(raw), digest(raw + b"\n")))
    return sorted(markers, key=len, reverse=True)


def parent_handle_retirement(owner, manifest):
    """Observe current-parent handles; retired children have separate receipts.

    This covers the exact files/directories in the retained manifest. It does
    not assert system-wide isolation or discover every historically unlinked
    inode. The controller opens parent files in contexts or owned log handles.
    """
    receipt = {"scope": "current_parent_and_manifest_covered_closure_only", "stdio": [],
               "scans": [], "failure": None, "passed": False,
               "python_thread_count_before": threading.active_count(),
               "hostile_same_uid_isolation_claim": False}
    try:
        need(receipt["python_thread_count_before"] == 1, "parent_fd_synchronous_controller_required")
        for index, child in enumerate(owner.children):
            streams = {}
            for name in ("stdin", "stdout", "stderr"):
                stream = getattr(child, name, None)
                streams[name] = {"present": stream is not None,
                                 "closed": stream is None or getattr(stream, "closed", None) is True}
            receipt["stdio"].append({"owner_index": index, "pid": child.pid, "streams": streams})
        closure = {(row["device"], row["inode"]) for row in (manifest["root"], *manifest["entries"])}
        probe = Path("/proc/self/fd") if sys.platform.startswith("linux") else Path("/dev/fd")
        need(sys.platform.startswith("linux") or sys.platform == "darwin", "parent_fd_platform_unsupported")
        for number in (1, 2):
            scan = {"number": number, "source": str(probe), "observed": [],
                    "closed_during_scan": [], "matches_original_manifest": [], "complete": False}
            receipt["scans"].append(scan)
            entries = list(probe.iterdir())
            need(len(entries) <= 65536 and all(path.name.isdecimal() for path in entries), "parent_fd_enumeration_shape")
            for path in sorted(entries, key=lambda value: int(value.name)):
                descriptor = int(path.name)
                try:
                    info = os.fstat(descriptor)
                except OSError as error:
                    if error.errno == errno.EBADF:
                        scan["closed_during_scan"].append(descriptor)
                        continue
                    scan["observation_error"] = {"fd": descriptor, "errno": error.errno}
                    raise
                row = {"fd": descriptor, "device": info.st_dev, "inode": info.st_ino,
                       "type": stat.S_IFMT(info.st_mode)}
                scan["observed"].append(row)
                if (info.st_dev, info.st_ino) in closure:
                    scan["matches_original_manifest"].append(row)
            scan["complete"] = True
        receipt["python_thread_count_after"] = threading.active_count()
        receipt["all_tracked_stdio_closed"] = all(stream["closed"] is True
            for row in receipt["stdio"] for stream in row["streams"].values())
        receipt["no_parent_fd_matches_manifest"] = all(not scan["matches_original_manifest"]
            and scan["complete"] for scan in receipt["scans"])
        receipt["passed"] = (receipt["python_thread_count_after"] == 1
            and receipt["all_tracked_stdio_closed"] and receipt["no_parent_fd_matches_manifest"])
    except Exception as error:
        receipt["failure"] = failure_label(error)
    return receipt


def complete(checks):
    return (len(checks) == len(CHECKS) == 25
            and {r.get("case") for r in checks if isinstance(r, dict)} == set(CHECKS)
            and all(isinstance(r, dict) and set(r) == {"case", "passed", "evidence"}
                    and r["passed"] is True and isinstance(r["evidence"], dict) and r["evidence"]
                    for r in checks))


def full34_complete(report):
    checks = report.get("checks", [])
    stages = report.get("target_storage_witnesses", [])
    return (report.get("status") == "passed" and report.get("profile") == "full34"
            and report.get("migration_lane") == "native-large"
            and report.get("full34_qualified") is True
            and report.get("production_authority") is False
            and len(checks) == len(full.CHECKS) == 31
            and {r.get("case") for r in checks} == set(full.CHECKS)
            and all(r.get("passed") is True for r in checks)
            and len(stages) == 3 and {r.get("stage") for r in stages} == set(full.STORAGE_CHECKS)
            and all(len(r.get("versions", [])) == 19 for r in stages)
            and len(report.get("source_api_wire_observations", [])) == 19)


def full34_snapshot_history(report):
    """Bind logical full34 history at the unchanged pre-mutation capture point.

    V6 stores repeated payload blocks once while retaining every descriptor
    reference. Its encrypted pack size is not a lower bound on logical history.
    These observations do not authenticate the pack or replace later recovery.
    """
    expected_checks = full.CHECKS[:full.CHECKS.index("snapshot_download") + 1]
    checks = report.get("checks", [])
    capacity = report.get("capacity_after_import", {})
    wires = report.get("source_api_wire_observations", [])
    stages = report.get("target_storage_witnesses", [])
    valid_rows = (isinstance(checks, list) and all(isinstance(row, dict) for row in checks)
                  and isinstance(capacity, dict)
                  and isinstance(wires, list) and all(isinstance(row, dict) for row in wires)
                  and isinstance(stages, list) and all(isinstance(row, dict)
                      and isinstance(row.get("versions"), list)
                      and all(isinstance(value, dict) for value in row["versions"]) for row in stages))
    if not valid_rows:
        return False, {"schema": "heptabao.dr25-full34-snapshot-history.v1",
                       "observation_shape_valid": False}
    wire_fields = ("endpoint", "method", "path", "status", "body_bytes", "same_response_decoded")
    raw_fields = ("version", "payload_present", "payload_canonical_bytes", "destroyed")
    observed = {
        "schema": "heptabao.dr25-full34-snapshot-history.v1", "observation_shape_valid": True,
        "profile": report.get("profile"), "migration_lane": report.get("migration_lane"),
        "retained_live_versions": report.get("retained_live_versions"),
        "live_payload_bytes": report.get("live_payload_bytes"),
        "native_before_import": report.get("native_before_import"),
        "required_logical_payload_bytes": 34 * MIB,
        "capacity_after_import": {key: capacity.get(key) for key in (
            "state_storage_format", "native_kv2_reader_format", "native_kv2_logical_payload_bytes")},
        "required_capture_checks": list(expected_checks),
        "capture_checks": [{"case": row.get("case"), "passed": row.get("passed")} for row in checks],
        "source_api_observations": [{key: row.get(key) for key in wire_fields} for row in wires],
        "storage_witnesses": [{"stage": row.get("stage"), "source_raw_bound": row.get("source_raw_bound"),
            "versions": [{key: value.get(key) for key in raw_fields} for value in row["versions"]]}
            for row in stages],
        "archive_aead_and_restored_history_still_required": True,
    }
    logical_bytes = capacity.get("native_kv2_logical_payload_bytes")
    passed = (full.PROFILES.get("full34") == (17, 2 * MIB, True)
        and report.get("profile") == "full34" and report.get("migration_lane") == "native-large"
        and report.get("retained_live_versions") == 17 and report.get("live_payload_bytes") == 34 * MIB
        and report.get("native_before_import") is True and report.get("production_authority") is False
        and capacity.get("state_storage_format") == "heptabao-state-records-v6"
        and capacity.get("native_kv2_reader_format") == 2
        and type(logical_bytes) is int and logical_bytes >= 34 * MIB
        and len(checks) == len(expected_checks)
        and {row.get("case") for row in checks} == set(expected_checks)
        and all(row.get("passed") is True for row in checks)
        and len(wires) == len(VERSIONS)
        and {row.get("path") for row in wires} == {"secret/data/history?version=" + str(v) for v in VERSIONS}
        and all(row.get("endpoint") == "source" and row.get("method") == "GET"
            and row.get("status") == 200 and row.get("same_response_decoded") is True
            and type(row.get("body_bytes")) is int and row["body_bytes"] > 0 for row in wires)
        and len(stages) == 2 and {row.get("stage") for row in stages} == set(full.STORAGE_CHECKS[:2])
        and all(row.get("source_raw_bound") is True and len(row["versions"]) == len(VERSIONS)
            and all(type(value.get("version")) is int for value in row["versions"])
            and {value.get("version") for value in row["versions"]} == set(VERSIONS)
            and all(value.get("payload_present") is (value["version"] != 2)
                and value.get("destroyed") is (value["version"] == 2)
                and type(value.get("payload_canonical_bytes")) is int
                and (value["payload_canonical_bytes"] == 0 if value["version"] == 2 else
                     value["payload_canonical_bytes"] >= (2 * MIB if value["version"] >= 3 else 1))
                for value in row["versions"]) for row in stages))
    return passed, observed


def validate_build_tests(receipt, selection, selection_sha256):
    need(selection.get("schema") == "heptabao.normal-rust-execution-selection.v1"
         and selection.get("execution_source_commit") == receipt.get("source_commit")
         and selection.get("execution_source_tree") == receipt.get("source_tree")
         and receipt.get("selection_sha256") == selection_sha256,
         "build_test_selection_binding_required")
    denominators = receipt.get("expected_denominators", {})
    need(denominators == selection.get("denominators")
         and all(type(value) is int and value > 0 for value in denominators.values())
         and denominators.get("total_unique_cases") == 107
         and denominators.get("server_total") == 90 and denominators.get("ha_service_total") == 17
         and type(receipt.get("passed_cases")) is int and receipt["passed_cases"] == 107
         and type(receipt.get("executed_passed_cases")) is int and receipt["executed_passed_cases"] == 107
         and type(receipt.get("not_qualified_cases")) is int and receipt["not_qualified_cases"] == 0,
         "completed_107_build_test_counts_required")
    selected = [group for name in ("legacy_groups", "legacy_additional_groups", "added_groups")
                for group in selection.get(name, [])]
    groups, enumeration = receipt.get("groups", []), receipt.get("enumeration", {})
    labels = [group.get("label") for group in selected]
    need(selected and len(labels) == len(set(labels)) and all(isinstance(label, str) and label for label in labels)
         and len(groups) == len(selected) and set(enumeration) == set(labels), "build_test_group_set_required")
    names, observations = [], []
    by_crate = {"heptabao-server": 0, "heptabao-ha-service": 0}
    for expected, actual in zip(selected, groups):
        label, count, tests = expected["label"], expected.get("expected_count"), expected.get("tests", [])
        need(type(count) is int and count > 0 and len(tests) == count
             and all(isinstance(name, str) and name for name in tests)
             and actual.get("label") == label and actual.get("crate") == expected.get("crate")
             and actual.get("crate") in by_crate and actual.get("tests") == tests
             and type(actual.get("expected_count")) is int and actual["expected_count"] == count
             and type(actual.get("passed")) is int and actual["passed"] == count
             and actual.get("status") == "passed", "build_test_group_not_complete")
        enumerated = enumeration[label]
        need(enumerated.get("matched_names") == sorted(tests)
             and type(enumerated.get("matched_count")) is int and enumerated["matched_count"] == count,
             "build_test_enumeration_mismatch")
        suffixes = expected.get("argv_suffixes", [expected.get("argv_suffix")])
        per_result = 1 if len(suffixes) > 1 or expected.get("selection_mode") == "per-test-exact" else count
        results = actual.get("results", [])
        need(suffixes and all(isinstance(suffix, list) and suffix for suffix in suffixes)
             and len(results) == len(suffixes) and len(results) * per_result == count,
             "build_test_result_denominator_mismatch")
        for result in results:
            need(result.get("reported_state") == "ok" and result.get("exact_denominator_passed") is True
                 and type(result.get("passed")) is int and result["passed"] == per_result
                 and all(type(result.get(field)) is int and result[field] == 0
                         for field in ("failed", "ignored", "measured")), "build_test_result_not_passed")
        names.extend(tests)
        by_crate[actual["crate"]] += count
        observations.append({"label": label, "crate": actual["crate"], "expected_count": count,
            "passed": actual["passed"], "results": [{key: result[key] for key in (
                "passed", "failed", "ignored", "measured", "reported_state", "exact_denominator_passed")}
                for result in results],
            "enumeration": {"matched_names": enumerated["matched_names"], "matched_count": count}})
    need(len(names) == len(set(names)) == 107 and sum(group["passed"] for group in groups) == 107
         and by_crate == {"heptabao-server": 90, "heptabao-ha-service": 17}, "build_test_unique_107_required")
    return {"passed_cases": 107, "selection_sha256": selection_sha256,
            "denominators": denominators, "groups": observations}


def validate_build_receipt(receipt, commit, server, seed, selection, selection_sha256):
    need(receipt.get("schema") == "heptabao.convergence-normal-build-tests.v1"
         and receipt.get("status") == "passed" and receipt.get("failure") is None
         and receipt.get("source_commit") == commit
         and re.fullmatch(r"[0-9a-f]{40}", receipt.get("source_tree", "")) is not None
         and receipt.get("source_and_artifacts_unchanged") is True,
         "completed_bound_build_receipt_required")
    pins = receipt.get("toolchain_pins", {})
    need(set(pins) == {"cargo", "rustc", "rustfmt"}
         and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in pins.values()),
         "build_toolchain_pins_required")
    result = {}
    for name, actual in (("heptabao-server", server), ("heptabao-seed", seed)):
        artifact = receipt.get("artifacts", {}).get(name, {})
        need(artifact.get("source_commit") == commit and artifact.get("source_tree") == receipt["source_tree"]
             and artifact.get("normal_features_profile_and_source_verified") is True
             and artifact.get("sha256") == actual["sha256"] and artifact.get("bytes") == actual["bytes"],
             "build_artifact_identity_mismatch")
        result[name] = {key: artifact[key] for key in ("sha256", "bytes", "source_commit", "source_tree",
                       "normal_features_profile_and_source_verified")}
    tests = validate_build_tests(receipt, selection, selection_sha256)
    return {"source_commit": commit, "source_tree": receipt["source_tree"],
            "toolchain_pins": pins, "artifacts": result, "source_and_artifacts_unchanged": True,
            "build_test_observations": tests, "passed_cases": 107, "status": "passed"}


def tar_header(name, length):
    """The native archive's existing canonical ustar header, not a loose tar extractor."""
    block = bytearray(512)
    raw = name.encode()
    block[:len(raw)] = raw
    block[100:108] = b"0000600\0"
    block[108:116] = block[116:124] = b"0000000\0"
    block[124:136] = f"{length:011o}\0".encode()
    block[136:148] = b"00000000000\0"
    block[148:156] = b"        "
    block[156] = ord("0")
    block[257:263], block[263:265] = b"ustar\0", b"00"
    block[148:156] = f"{sum(block):06o}\0 ".encode()
    return bytes(block)


def single_gzip_member(path):
    decoder = zlib.decompressobj(31)
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            pending = chunk
            while pending:
                output = decoder.decompress(pending, 65536)
                count += len(output)
                need(count <= full.ARCHIVE_BYTES + 16384, "archive_decompressed_bound")
                pending = decoder.unconsumed_tail
                if decoder.eof:
                    need(not decoder.unused_data and not pending and stream.read(1) == b"",
                         "archive_trailing_compressed_bytes")
                    break
        need(decoder.eof, "archive_gzip_truncated")
    return count


def inspect_v6_archive(path):
    pin = file_pin(path, private=True)
    need(0 < pin["bytes"] <= full.ARCHIVE_BYTES, "archive_compressed_bound")
    total = single_gzip_member(path)
    hashes, small, lengths, magic = {}, {}, {}, b""
    with gzip.open(path, "rb") as stream:
        for name in ARCHIVE_NAMES:
            header = stream.read(512)
            need(len(header) == 512 and header[135] == 0
                 and all(c in b"01234567" for c in header[124:135]), "archive_header_length")
            length = int(header[124:135], 8)
            need(length <= full.ARCHIVE_BYTES and header == tar_header(name, length),
                 "archive_canonical_header")
            need(name == "state.bin" or length < 8192, "archive_small_member_bound")
            h, kept, left = hashlib.sha256(), bytearray(), length
            while left:
                chunk = stream.read(min(left, 65536))
                need(bool(chunk), "archive_member_truncated")
                if name == "state.bin" and left == length:
                    magic = chunk[:8]
                h.update(chunk)
                if name != "state.bin":
                    kept.extend(chunk)
                left -= len(chunk)
            padding = (-length) % 512
            need(stream.read(padding) == b"\0" * padding, "archive_padding")
            hashes[name], lengths[name] = h.hexdigest(), length
            if name != "state.bin":
                small[name] = bytes(kept)
        need(stream.read(1024) == b"\0" * 1024 and stream.read(1) == b"", "archive_exact_end")
    meta = full.decode(small["meta.json"])
    binding = meta.get("seal_identity", {})
    expected_sums = (hashes["meta.json"] + "  meta.json\n" + hashes["state.bin"] + "  state.bin\n").encode()
    need(set(meta) == {"format", "state_format", "generation", "state_bytes", "seal_identity"}
         and meta["format"] == "heptabao-native-object-snapshot-v1"
         and meta["state_format"] == "heptabao-encrypted-object-backup/HBV6PK01"
         and type(meta["generation"]) is int and meta["generation"] >= 0
         and meta["state_bytes"] == lengths["state.bin"] and magic == b"HBV6PK01"
         and set(binding) == {"format", "sha256"}
         and binding["format"] == "heptabao-seal-metadata-digest-v1"
         and re.fullmatch(r"[0-9a-f]{64}", binding["sha256"]) is not None
         and small["SHA256SUMS"] == expected_sums and bool(small["SHA256SUMS.sealed"]),
         "archive_v6_contract")
    need(file_pin(path, private=True) == pin, "archive_changed_during_inspection")
    return {"archive": pin, "metadata": meta, "members": [
        {"name": name, "bytes": lengths[name], "sha256": hashes[name]} for name in ARCHIVE_NAMES],
        "gzip_uncompressed_bytes": total, "outer_checksums_verified": True,
        "standalone_aead_verified": False}


def validate_seed_receipt(receipt, operation, seed_dir, exported=None):
    need(receipt.get("schema") == 1 and receipt.get("operation") == operation
         and receipt.get("original_writer_fence_held") is True
         and receipt.get("every_file_synced_and_read_back") is True
         and receipt.get("directory_publication_synced") is True
         and receipt.get("cryptographic_state_admission_performed") is False
         and receipt.get("ha_qualified") is False, "seed_receipt_scope")
    seed = receipt.get("seed", {})
    rows = seed.get("artifacts", [])
    actual_directory = directory_identity(seed_dir)
    claimed_directory = receipt.get("destination_directory", {})
    need(claimed_directory == {"device": actual_directory["device"], "inode": actual_directory["inode"],
                              "owner": actual_directory["uid"], "mode": actual_directory["mode"]},
         "seed_receipt_destination_identity")
    need(seed.get("profile") == "four-file-shamir-cipher-seed"
         and [r.get("leaf") for r in rows] == list(SEED_FILES)
         and re.fullmatch(r"[0-9a-f]{64}", receipt.get("seed_manifest_sha256", "")) is not None
         and {p.name for p in seed_dir.iterdir()} == set(SEED_FILES), "seed_exact_four_files")
    observed = []
    for row in rows:
        pin = file_pin(seed_dir / row["leaf"], private=True)
        need((pin["bytes"], pin["sha256"]) == (row.get("bytes"), row.get("sha256")), "seed_artifact_pin")
        observed.append({"leaf": row["leaf"], **pin})
    if exported is not None:
        need(receipt.get("seed") == exported.get("seed")
             and receipt.get("seed_manifest_sha256") == exported.get("seed_manifest_sha256"),
             "stage_must_match_exported_seed")
    return observed


def history_witness(value):
    return {"history_sha256": json_hash(value), "config": value["config"], "metadata": value["metadata"],
            "versions": [{"version": int(v), "status": r["status"],
                          "response_data_sha256": json_hash(r["data"])}
                         for v, r in sorted(value["versions"].items(), key=lambda x: int(x[0]))]}


class CapturedFull34(full.Run):
    """Observe the original controller without changing its cases or qualifications."""
    def __init__(self, args, dr):
        super().__init__(args)
        self.dr = dr

    def seed_source(self, live_count, size):
        self.dr.capture_seed(self)
        return super().seed_source(live_count, size)

    def check(self, name, passed):
        super().check(name, passed)
        if name == "snapshot_download":
            self.dr.capture_backup(self)


class DisasterRecovery:
    def __init__(self, args):
        self.args, self.root = args, args.private_work_root
        self.baseline = self.recovery = self.endpoint = None
        self.process_owner = None
        self.baseline_finished = False
        self.phase_number = 0
        self.secrets = []
        self.before = self.seed_pin = self.cli_pin = self.build_log_pin = None
        self.build_receipt_pin = None
        self.build_selection_pin = self.build_selection_path = None
        self.directory_custody = None
        self.quarantine_manifest = None
        self.backup_manifest = None
        self.report = {
            "schema": "heptabao.native-v6-fresh-directory-dr25.v1", "status": "failed",
            "required_checks": list(CHECKS), "required_count": 25,
            "checks": [], "mutations": [], "commands": [], "cleanup_failures": [],
            "synthetic_only": True, "official_version": "2.7.1", "source_profile": "full34",
            "version_count": 19, "live_payload_bytes": 34 * MIB,
            "original_budgets": {"http_seconds": full.HTTP_SECONDS,
                                 "migration_seconds": full.MIGRATION_SECONDS,
                                 "cli_and_seed_seconds": full.HTTP_SECONDS},
            "physical_disk_independence_verified": False, "physical_power_loss_tested": False,
            "ha_qualified": False, "cross_seal_restore": False, "production_authority": False,
            "replacement_authority": False, "independent_qualification": False,
        }

    def phase(self, name, details=None):
        self.phase_number += 1
        full.private_write(self.root / "dr-phases" / f"{self.phase_number:04d}-{name}.json",
                           encoded({"phase": name, "details": details}))

    def check(self, name, passed, evidence):
        need(name in CHECKS and name not in {r["case"] for r in self.report["checks"]}, "unique_dr25_check")
        need(isinstance(evidence, dict) and evidence, "dr25_requires_observation_evidence")
        row = {"case": name, "passed": passed is True, "evidence": evidence}
        self.report["checks"].append(row)
        self.phase("check", row)
        need(passed is True, name)

    def child(self, label, argv, *, env=None, expected_status=None):
        """One original process group, bounded private outputs, no mutation retries."""
        need(label not in {r["label"] for r in self.report["commands"]}, "child_must_not_retry")
        row = {"label": label, "budget_seconds": full.HTTP_SECONDS, "retried": False,
               "outcome": "unknown", "argv_sha256": digest(encoded([str(x) for x in argv]))}
        self.report["commands"].append(row)
        self.phase("command_begin", row)
        stdout_path, stderr_path = [self.root / "commands" / (label + suffix) for suffix in (".stdout", ".stderr")]
        row.update(private_stdout=str(stdout_path), private_stderr=str(stderr_path))
        process = None
        started, deadline = time.monotonic(), time.monotonic() + full.HTTP_SECONDS
        try:
            with open(stdout_path, "xb") as out, open(stderr_path, "xb") as err:
                os.chmod(stdout_path, 0o600)
                os.chmod(stderr_path, 0o600)
                process = subprocess.Popen([str(x) for x in argv], stdin=subprocess.DEVNULL,
                                           stdout=out, stderr=err, env=env, cwd=self.root,
                                           start_new_session=True)
                row.update(pid=process.pid, pgid=process.pid)
                while process.poll() is None:
                    need(time.monotonic() < deadline, "child_deadline_unknown_outcome_no_retry")
                    need(os.fstat(out.fileno()).st_size <= CHILD_BYTES
                         and os.fstat(err.fileno()).st_size <= CHILD_BYTES, "child_output_bound")
                    time.sleep(min(0.02, max(0, deadline - time.monotonic())))
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
                need(time.monotonic() < deadline, "child_deadline_unknown_outcome_no_retry")
            stdout, stderr = full.private_read(stdout_path, CHILD_BYTES), full.private_read(stderr_path, CHILD_BYTES)
            row["returncode"] = process.returncode
            if expected_status is None:
                need(process.returncode == 0, "owned_child_nonzero")
            else:
                statuses = re.findall(rb"Code: ([0-9]{3})(?:[.\s]|$)", stderr)
                row["http_status_codes"] = [int(x) for x in statuses]
                need(process.returncode != 0 and statuses == [str(expected_status).encode()],
                     "negative_cli_requires_exact_http_rejection")
            row["outcome"] = "response_received"
            return stdout, row
        except BaseException as error:
            row["failure"] = failure_label(error)
            raise
        finally:
            active_error, cleanup_error = sys.exc_info()[1], None
            try:
                running = process is not None and process.poll() is None
                if running:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
            except BaseException as error:
                cleanup_error = error
                row["cleanup_failure"] = failure_label(error)
            private_pins = {}
            for path, field in ((stdout_path, "stdout"), (stderr_path, "stderr")):
                if path.exists():
                    private_pins[field] = file_pin(path, private=True)
                    # Unexpected utility diagnostics could contain credentials;
                    # their content and fingerprints remain in the private kit.
                    row[field] = {key: value for key, value in private_pins[field].items() if key != "sha256"}
                    row[field]["content_fingerprint_published"] = False
            pins_path = self.root / "commands" / (label + ".output-pins.private.json")
            full.private_write(pins_path, encoded({"publishable": False, "files": private_pins}))
            row["private_output_pins"] = str(pins_path)
            row["original_wait_completed"] = (process is None or
                getattr(process, "custody", {}).get("original_wait_completed", process.returncode is not None))
            row["elapsed_seconds"] = round(time.monotonic() - started, 6)
            if process is not None:
                row["returncode"] = process.returncode
            self.phase("command_outcome", row)
            if cleanup_error is not None and active_error is None:
                raise cleanup_error

    def cli(self, label, instance, operation, archive, *, expected_status=None):
        from native_snapshot_cli_live import cli_environment
        env = cli_environment(instance, self.root)
        for prefix in ("BAO", "VAULT"):
            env[prefix + "_CLIENT_TIMEOUT"] = str(full.HTTP_SECONDS) + "s"
            env[prefix + "_MAX_RETRIES"] = "0"
        need(file_pin(self.bao) == self.cli_pin, "official_cli_changed_before_dispatch")
        _, row = self.child(label, [self.bao, "operator", "raft", "snapshot", operation, archive],
                            env=env, expected_status=expected_status)
        need(file_pin(self.bao) == self.cli_pin, "official_cli_changed_after_dispatch")
        return row

    def directory_observations(self):
        need(disjoint([self.args.backup_parent, self.args.key_parent])
             and disjoint([self.root, self.backup, self.keys]), "backup_key_directory_overlap")
        return {"work": private_parent(self.root), "backup_parent": private_parent(self.args.backup_parent),
                "key_parent": private_parent(self.args.key_parent), "backup": private_parent(self.backup),
                "keys": private_parent(self.keys)}

    def prepare(self):
        for relative in ("qa/openbao-acceptance", "qa/single-node", "clients/python/src"):
            sys.path.insert(0, str(ROOT / relative))
        work = directory_identity(self.root)
        backup = private_parent(self.args.backup_parent)
        keys = private_parent(self.args.key_parent)
        self.backup = self.args.backup_parent / self.root.name
        self.keys = self.args.key_parent / self.root.name
        need(disjoint([self.root, self.backup, self.keys]), "recovery_backup_and_keys_must_be_disjoint")
        need(disjoint([self.args.backup_parent, self.args.key_parent]), "backup_key_directory_overlap")
        self.check("independent_backup_filesystem_verified", work["device"] != backup["device"], {
            "work": work, "backup_parent": backup, "key_parent": keys,
            "scope": "distinct_st_dev_filesystems_only", "physical_device_claim": False})
        self.backup.mkdir(mode=0o700)
        self.keys.mkdir(mode=0o700)
        self.directory_custody = self.directory_observations()
        from online_evidence import source_identity
        import official_openbao_launcher as launcher
        self.source_identity = source_identity
        self.before = source_identity(ROOT, self.args.binary)
        need(not self.before["source_dirty"], "clean_controller_checkout_required")
        self.seed_pin = file_pin(self.args.seed_binary)
        self.build_log_pin = file_pin(self.args.build_log)
        self.build_receipt_pin = file_pin(self.args.build_receipt, private=True)
        need(self.build_receipt_pin["sha256"] == self.args.build_receipt_sha256,
             "independently_pinned_build_receipt_required")
        build_receipt = full.decode(full.private_read(self.args.build_receipt, 8 * MIB))
        self.build_selection_path = self.args.build_receipt.parent / "test-selection.public.json"
        self.build_selection_pin = file_pin(self.build_selection_path, private=True)
        selection = full.decode(full.private_read(self.build_selection_path, 8 * MIB))
        binding = validate_build_receipt(build_receipt, self.args.build_source_commit,
                                         file_pin(self.args.binary), self.seed_pin, selection,
                                         self.build_selection_pin["sha256"])
        tree = subprocess.check_output(["git", "rev-parse", self.args.build_source_commit + "^{tree}"],
                                       cwd=ROOT, timeout=full.HTTP_SECONDS).decode().strip()
        need(tree == binding["source_tree"], "build_receipt_source_tree_mismatch")
        changed = subprocess.check_output(["git", "diff", "--name-only", self.args.build_source_commit,
                                           "HEAD", "--", ".", ":!qa", ":!docs"],
                                          cwd=ROOT, timeout=full.HTTP_SECONDS)
        need(not changed, "product_source_differs_from_bound_build")
        self.bao = launcher.verify_inputs(version="2.7.1")
        self.cli_pin = file_pin(self.bao)
        self.release_pin = launcher.pinned_artifact(version="2.7.1")
        need(self.cli_pin["sha256"] == self.release_pin["binary_sha256"], "official_cli_pin")
        self.check("input_source_and_binaries_pinned", True, {
            "controller_and_server": self.before, "seed_binary": self.seed_pin,
            "build_source_commit": self.args.build_source_commit, "build_log": self.build_log_pin,
            "build_receipt": self.build_receipt_pin, "build_binding": binding,
            "build_selection_manifest": self.build_selection_pin,
            "build_binding_basis": "independently_pinned_completed_build_receipt_and_exact_executable_bytes",
            "official_cli": self.cli_pin, "official_release": self.release_pin})

    def capture_seed(self, base):
        original = base.candidate.process
        self.source_tls_sha256 = file_pin(base.candidate.root / "tls.crt")["sha256"]
        base.candidate.stop()
        need(original.poll() is not None, "seed_original_writer_not_stopped")
        seed_dir = self.backup / "seed"
        stdout, command = self.child("seed_export", [self.args.seed_binary, "export",
                                                     base.candidate.root / "data", seed_dir])
        receipt = full.decode(stdout)
        artifacts = validate_seed_receipt(receipt, "export", seed_dir)
        self.seed_receipt = receipt
        self.seed_receipt_path = self.backup / "seed-export.json"
        full.private_write(self.seed_receipt_path, stdout)
        self.seed_receipt_sha256 = digest(stdout)
        self.key, self.token = base.candidate_key, base.target.token
        self.secrets.extend([self.key, self.token])
        full.private_write(self.keys / "unseal.key", self.key)
        full.private_write(self.keys / "root.token", self.token)
        self.check("preactivation_seed_export_pinned", True, {
            "stopped_pid": original.pid, "returncode": original.returncode,
            "command": command, "export_receipt_sha256": self.seed_receipt_sha256,
            "artifacts": artifacts, "retained_native_objects": 0,
            "cryptographic_admission_claim": False})
        base.candidate.start()
        need(base.target.call("POST", "sys/unseal", {"key": base.candidate_key})[0] == 200,
             "baseline_restart_after_seed_export")

    def capture_backup(self, base):
        self.archive = self.backup / "native-v6.snap"
        command = self.cli("official_v6_save", base.candidate, "save", self.archive)
        self.check("official_cli_v6_save_complete", True, {"command": command,
                   "official_version": "2.7.1", "archive": file_pin(self.archive, private=True)})
        archive = inspect_v6_archive(self.archive)
        reference = inspect_v6_archive(base.root / "native-snapshot.tar.gz")
        history_complete, history = full34_snapshot_history(base.report)
        self.check("complete_v6_archive_seal_binding",
                   history_complete
                   and archive["metadata"]["seal_identity"] == reference["metadata"]["seal_identity"], {
                       "cli_archive": archive, "normal_http_archive": reference,
                       "full34_logical_history": history,
                       "physical_pack_bytes_are_observations_not_logical_history_size": True,
                       "aead_authentication_required_at_restore": True})
        self.oracle = history_witness(base.original)
        self.oracle["source_api_live_payload_sha256"] = {
            v: json_hash(value) for v, value in base.source_api_payloads.items()}
        raw_bundle = full.decode(full.private_read(base.root / "source-bundle.json"))
        raw_versions = raw_bundle["entries"]["history"]["versions"]
        self.oracle["raw_versions"] = [{"version": v,
            "payload_present": raw_versions[str(v)]["data"] is not None,
            "payload_canonical_bytes": len(full.canonical(raw_versions[str(v)]["data"])) if v != 2 else 0,
            "payload_canonical_sha256": json_hash(raw_versions[str(v)]["data"]) if v != 2 else None}
            for v in VERSIONS]
        self.oracle["source_bundle_sha256"] = file_pin(base.root / "source-bundle.json", private=True)["sha256"]
        full.private_write(self.backup / "oracle-witness.json", full.canonical(self.oracle))
        manifest = {"schema": "heptabao-dr25-backup-kit-v1", "archive": "native-v6.snap",
                    "seed": "seed", "key_material_included": False,
                    "source_binary_sha256": self.before["binary_sha256"],
                    "build_source_commit": self.args.build_source_commit, "files": []}
        for path in [self.archive, self.seed_receipt_path, self.backup / "oracle-witness.json",
                     *(self.backup / "seed" / name for name in SEED_FILES)]:
            manifest["files"].append({"path": str(path.relative_to(self.backup)), **file_pin(path, private=True)})
            with path.open("rb") as stream:
                tail = b""
                while chunk := stream.read(65536):
                    joined = tail + chunk
                    need(not any(secret.encode() in joined for secret in self.secrets), "backup_key_material_leak")
                    tail = joined[-max(map(len, self.secrets)):]
        self.backup_manifest = manifest
        full.private_write(self.backup / "manifest.json", encoded(manifest))
        self.manifest_pin = file_pin(self.backup / "manifest.json", private=True)
        self.check("backup_manifest_and_separate_key_custody", True, {
            "manifest": self.manifest_pin, "files": manifest["files"],
            "backup_directory": directory_identity(self.backup), "key_directory": directory_identity(self.keys),
            "key_files": [{"name": name, "mode": file_pin(self.keys / name, private=True)["mode"]}
                          for name in ("unseal.key", "root.token")],
            "key_material_absent_from_backup": True, "plaintext_business_values_in_witness": False})

    def run_baseline(self):
        work = self.root / "baseline"
        work.mkdir(mode=0o700)
        (work / "phases").mkdir(mode=0o700)
        args = SimpleNamespace(binary=self.args.binary, private_work_root=work,
                               profile="full34", migration_lane="native-large")
        base = self.baseline = CapturedFull34(args, self)
        try:
            base.execute()
        except BaseException as error:
            base.report["failure"] = failure_label(error)
        finally:
            processes = [x for x in (getattr(base.candidate, "process", None),
                                      base.oracle.get("process") if base.oracle else None) if x is not None]
            base.finish()
            self.baseline_finished = True
        self.report["baseline"] = {"summary": str(work / "summary.json"),
                                   "sha256": file_pin(work / "summary.json", private=True)["sha256"],
                                   "required_count": 31, "qualified": full34_complete(base.report)}
        need(full34_complete(base.report), "original_full34_31_checks_required_before_dr")
        self.check("official_271_live_identity_verified", True, {
            "live_identity": base.report["official_identity"], "release_pin": self.release_pin,
            "original_case": next(x for x in base.report["checks"] if x["case"] == "official_271_pins_and_live_identity")})
        self.check("official_full34_api_and_raw_history_bound", True, {
            "baseline": self.report["baseline"], "oracle": self.oracle,
            "wire_observations": base.report["source_api_wire_observations"],
            "storage_stages": base.report["target_storage_witnesses"]})
        startup = base.report["candidate_startup"]
        config = full.decode(full.private_read(base.candidate.root / "server.json"))
        self.check("normal_native_v6_file_profile", startup["fixture_options"] is False
                   and startup["storage_profile"] == "native_v6_file"
                   and config.get("storage") == {"native_v6_file": {"path": config["data_dir"]}}, {
                       "startup": startup, "capacity": base.report["capacity_after_import"]})
        need(self.process_owner is not None, "owned_process_custody_required")
        self.process_owner.assert_retired()
        log_handles = {"candidate": base.candidate.log.closed, "oracle": base.oracle["log"].closed}
        self.check("original_processes_stopped", len(processes) == 2 and all(p.poll() is not None for p in processes)
                   and all(log_handles.values()), {
            "original_processes": [{"pid": p.pid, "returncode": p.poll()} for p in processes],
            "parent_service_log_handles_closed": log_handles,
            "all_owned_sessions": self.process_owner.receipt(),
            "original_controller_cleanup": next(x for x in base.report["checks"] if x["case"] == "owned_processes_stopped")})

    def quarantine_original(self):
        source = self.baseline.root
        before = tree_manifest(source)
        write_private_tree(self.root / "original-tree-before.json", before)
        handles = parent_handle_retirement(self.process_owner, before)
        self.report["parent_handle_retirement"] = handles
        self.phase("parent_handle_retirement", handles)
        need(handles["passed"] is True, "parent_handles_not_retired_before_quarantine")
        (self.root / "quarantine").mkdir(mode=0o700)
        self.quarantined = self.root / "quarantine" / "original-closure"
        os.rename(source, self.quarantined)
        after = tree_manifest(self.quarantined)
        self.quarantine_manifest = after
        write_private_tree(self.root / "original-tree-after-rename.json", after)
        held_payloads = len(self.baseline.source_api_payloads)
        self.baseline.original = None
        self.baseline.source_api_payloads.clear()
        self.baseline.source = self.baseline.target = None
        self.check("original_directories_quarantined", before == after and not source.exists(), {
            "original_path": str(source), "quarantined_path": str(self.quarantined),
            "before": tree_summary(before), "after": tree_summary(after),
            "complete_manifests": ["original-tree-before.json", "original-tree-after-rename.json"],
            "parent_handle_retirement": handles,
            "original_api_payload_objects_before_release": held_payloads,
            "original_api_payload_objects_after_release": len(self.baseline.source_api_payloads),
            "original_endpoint_objects_released": self.baseline.source is None and self.baseline.target is None,
            "same_uid_adversary_isolation_claim": False})
        self.report["baseline"]["original_summary"] = self.report["baseline"]["summary"]
        self.report["baseline"]["summary"] = str(self.quarantined / "summary.json")

    def make_recovery(self):
        import owned_process
        import smoke
        owner = self

        class RecoveryInstance(smoke.Instance):
            def start(self):
                self.log = open(self.root / "server.log", "ab")
                self.process = owned_process.popen([str(self.binary), "--config", str(self.root / "server.json")],
                    stdout=self.log, stderr=self.log, label="kv2_dr25_recovery", action="KILL", stop_timeout=5)
                deadline = time.monotonic() + full.HTTP_SECONDS
                endpoint = full.Endpoint(self.address, self.root / "ca.crt", self.token, owner, "recovered")
                try:
                    while time.monotonic() < deadline:
                        need(self.process.poll() is None, "recovery_exited_before_ready")
                        try:
                            status, _ = endpoint.call("GET", "sys/health", budget=min(2, deadline - time.monotonic()))
                            if status in (200, 501, 503):
                                return
                        except Failure:
                            pass
                        time.sleep(0.05)
                    raise Failure("recovery_tls_startup_deadline")
                except BaseException as error:
                    owned_process.abort(error, [self.stop])

        instance = self.recovery = RecoveryInstance(self.args.binary, self.root / "recovery")
        config_path = instance.root / "server.json"
        config = full.decode(full.private_read(config_path))
        config["storage"] = {"native_v6_file": {"path": config["data_dir"]}}
        full.private_write(config_path, full.canonical(config), replace=True)
        data = instance.root / "data"
        self.check("fresh_recovery_directory_and_tls_identity", not data.exists()
                   and file_pin(instance.root / "tls.crt")["sha256"] != self.source_tls_sha256, {
                       "recovery_root": directory_identity(instance.root), "data_directory_absent_before_stage": not data.exists(),
                       "new_tls_certificate_sha256": file_pin(instance.root / "tls.crt")["sha256"],
                       "original_tls_certificate_sha256": self.source_tls_sha256,
                       "config_sha256": file_pin(config_path, private=True)["sha256"],
                       "argv": [str(self.args.binary), "--config", str(config_path)], "fixture_options": False})
        stdout, command = self.child("seed_stage", [self.args.seed_binary, "stage", self.backup / "seed",
                                                   data, self.seed_receipt_path, self.seed_receipt_sha256])
        receipt = full.decode(stdout)
        artifacts = validate_seed_receipt(receipt, "stage", data, self.seed_receipt)
        self.check("exact_seed_stage_verified", True, {"command": command, "receipt": receipt, "artifacts": artifacts})
        instance.token = full.private_read(self.keys / "root.token", 65536).decode()
        self.key = full.private_read(self.keys / "unseal.key", 65536).decode()
        self.endpoint = full.Endpoint(instance.address, instance.root / "ca.crt", instance.token, self, "recovered")
        instance.start()

    def capacity(self):
        status, result = self.endpoint.call("GET", "sys/internal/capacity")
        need(status == 200 and isinstance(result.get("data"), dict), "recovered_capacity_required")
        return result["data"]

    def reopen(self):
        original = self.recovery.process
        self.recovery.stop()
        need(original.poll() is not None, "recovered_original_process_not_stopped")
        self.recovery.start()
        status, _ = self.endpoint.call("POST", "sys/unseal", {"key": self.key})
        need(status == 200, "recovered_cold_unseal_failed")
        return {"old_pid": original.pid, "old_returncode": original.returncode,
                "new_pid": self.recovery.process.pid, "unseal_status": status}

    def observe_api(self, *, expected=True, count=17):
        result = history_witness(full.observations(self.endpoint, count))
        self.phase("recovered_api_observation", result)
        if expected:
            need(result["history_sha256"] == self.oracle["history_sha256"]
                 and result["versions"] == self.oracle["versions"], "recovered_api_history_mismatch")
        return result

    def observe_raw(self):
        rows = []
        for version in VERSIONS:
            status, response = self.endpoint.call("POST", "sys/internal/storage/kv2-version-witness", {
                "mount": "secret", "path": "history", "version": version})
            self.phase("recovered_raw_observation", {"version": version, "status": status, "response": response})
            need(status == 200, "recovered_raw_witness_status")
            expected = None if version == 2 else full.payload(version, 17, 2 * MIB)
            witness = full.verify_storage_witness(response, version,
                self.oracle["metadata"]["versions"][str(version)], expected)
            source = self.oracle["raw_versions"][version - 1]
            need(all(witness[k] == source[k] for k in (
                "payload_present", "payload_canonical_bytes", "payload_canonical_sha256")), "recovered_raw_source_binding")
            rows.append({"http_status": status, **witness})
        return {"versions": rows, "source_bundle_sha256": self.oracle["source_bundle_sha256"]}

    def recover(self):
        before_seal = file_pin(self.recovery.root / "data" / "seal.json", private=True)
        wrong = bytearray(base64.b64decode(self.key, validate=True))
        wrong[-1] ^= 1
        wrong_key = base64.b64encode(wrong).decode()
        self.secrets.append(wrong_key)
        status, response = self.endpoint.call("POST", "sys/unseal", {"key": wrong_key})
        health_status, health = self.endpoint.call("GET", "sys/health")
        after_seal = file_pin(self.recovery.root / "data" / "seal.json", private=True)
        self.check("wrong_unseal_key_denied", status == 400 and bool(response.get("errors"))
                   and health_status == 503 and health.get("sealed") is True and before_seal == after_seal, {
                       "wrong_unseal_status": status, "health_status": health_status, "sealed": health.get("sealed"),
                       "seal_before": before_seal, "seal_after": after_seal})
        need(self.endpoint.call("POST", "sys/unseal", {"key": self.key})[0] == 200, "recovery_seed_unseal")
        old = self.capacity()
        missing = []
        for version in VERSIONS:
            api_status, api = self.endpoint.call("GET", "secret/data/history?version=" + str(version))
            raw_status, raw = self.endpoint.call("POST", "sys/internal/storage/kv2-version-witness", {
                "mount": "secret", "path": "history", "version": version})
            api_data = api.get("data")
            missing.append({"version": version, "api_status": api_status, "api_response_sha256": json_hash(api),
                            "api_payload_present": isinstance(api_data, dict) and api_data.get("data") is not None,
                            "raw_status": raw_status, "raw_response_sha256": json_hash(raw),
                            "raw_witness_present": raw.get("data") is not None})
        objects = sorted(p.name for p in (self.recovery.root / "data").iterdir() if p.suffix == ".hbo")
        self.check("old_closure_negative_cannot_read_history", old.get("state_storage_format") != "heptabao-state-records-v6"
                   and not objects and all(r["api_status"] == 404 and r["raw_status"] == 501
                                           and not r["api_payload_present"] and not r["raw_witness_present"]
                                           for r in missing), {
                       "capacity": old, "historical_reads": missing, "external_objects_before_restore": objects,
                       "original_root_exists": self.baseline.root.exists()})
        from native_snapshot_cli_live import tamper_sealed
        tampered = self.root / "tampered.snap"
        tamper_sealed(self.archive, tampered)
        tamper_contract = inspect_v6_archive(tampered)
        command = self.cli("tampered_v6_restore", self.recovery, "restore", tampered, expected_status=400)
        after = self.capacity()
        no_history, _ = self.endpoint.call("GET", "secret/metadata/history")
        rejected_restart = self.reopen()
        cold_after_rejection = self.capacity()
        cold_no_history, _ = self.endpoint.call("GET", "secret/metadata/history")
        self.check("tampered_archive_denied_without_commit", after.get("generation") == old.get("generation")
                   and after.get("state_storage_format") == old.get("state_storage_format")
                   and cold_after_rejection.get("generation") == old.get("generation")
                   and cold_after_rejection.get("state_storage_format") == old.get("state_storage_format")
                   and no_history == cold_no_history == 404
                   and file_pin(self.recovery.root / "data" / "seal.json", private=True) == before_seal, {
                       "command": command, "tampered_archive": tamper_contract, "capacity_before": old,
                       "capacity_after": after, "history_status_after": no_history,
                       "restart_after_rejection": rejected_restart, "cold_capacity_after": cold_after_rejection,
                       "cold_history_status_after": cold_no_history,
                       "same_seal_bytes_and_identity": True})
        command = self.cli("official_v6_restore", self.recovery, "restore", self.archive)
        active = self.capacity()
        self.check("official_cli_v6_restore_once", active.get("state_storage_format") == "heptabao-state-records-v6"
                   and active.get("native_kv2_reader_format") == 2
                   and active.get("native_kv2_logical_payload_bytes", 0) >= 34 * MIB, {
                       "command": command, "capacity_before": after, "capacity_after": active,
                       "archive": file_pin(self.archive, private=True), "valid_restore_attempt_count": 1,
                       "source_bundle_imports_after_quarantine": 0})
        self.check("restored_api_19_versions_exact", True, self.observe_api())
        self.check("restored_raw_19_versions_exact", True, self.observe_raw())
        cold = self.reopen()
        self.check("restored_cold_reopen_history_exact", True, {"restart": cold,
                   "api": self.observe_api(), "raw": self.observe_raw()})
        self.behavior_after_recovery()

    def behavior_after_recovery(self):
        status, _ = self.endpoint.call("POST", "secret/undelete/history", {"versions": [1]})
        read_status, body = self.endpoint.call("GET", "secret/data/history?version=1")
        actual_hash = json_hash(body.get("data", {}).get("data"))
        self.check("soft_deleted_payload_undelete_exact", status == 204 and read_status == 200
                   and actual_hash == self.oracle["source_api_live_payload_sha256"]["1"]
                   and body["data"]["metadata"]["deletion_time"] == "", {
                       "undelete_status": status, "read_status": read_status, "payload_sha256": actual_hash,
                       "source_api_payload_sha256": self.oracle["source_api_live_payload_sha256"]["1"],
                       "metadata": body.get("data", {}).get("metadata")})
        status, _ = self.endpoint.call("POST", "secret/undelete/history", {"versions": [2]})
        read_status, body = self.endpoint.call("GET", "secret/data/history?version=2")
        raw_status, raw = self.endpoint.call("POST", "sys/internal/storage/kv2-version-witness", {
            "mount": "secret", "path": "history", "version": 2})
        self.check("destroyed_payload_not_resurrected", status == 204 and read_status == 404
                   and body.get("data", {}).get("data") is None
                   and body["data"]["metadata"]["destroyed"] is True and raw_status == 200
                   and raw.get("data", {}).get("payload_present") is False
                   and raw["data"].get("payload_canonical_bytes") == 0
                   and raw["data"].get("payload_canonical_sha256") is None, {
                       "undelete_status": status, "read_status": read_status,
                       "metadata": body.get("data", {}).get("metadata"), "raw_status": raw_status, "raw": raw})
        before = self.observe_api(expected=False)
        data_status, _ = self.endpoint.call("POST", "secret/data/history", {
            "data": {"must_not_commit": True}, "options": {"cas": 0}})
        after_data = self.observe_api(expected=False)
        metadata_status, _ = self.endpoint.call("POST", "secret/metadata/history", {
            "custom_metadata": {"must_not_commit": "true"}, "metadata_cas": 0})
        after_metadata = self.observe_api(expected=False)
        counter = before["metadata"]["current_metadata_version"]
        valid_status, _ = self.endpoint.call("POST", "secret/metadata/history", {
            "custom_metadata": {"revision": "dr25"}, "metadata_cas": counter})
        valid = self.observe_api(expected=False)
        self.check("data_and_metadata_cas_guards_exact", data_status == 400 and metadata_status == 400
                   and before == after_data == after_metadata and valid_status == 204
                   and valid["metadata"]["current_metadata_version"] == counter + 1
                   and valid["metadata"]["custom_metadata"] == {"revision": "dr25"}, {
                       "data_cas": {"status": data_status, "before": before, "after": after_data},
                       "metadata_cas": {"denied_status": metadata_status, "before": before,
                                        "after_denial": after_metadata, "valid_status": valid_status,
                                        "after_valid": valid}})
        payload = {"after_fresh_directory_restore": True}
        write_status, write = self.endpoint.call("POST", "secret/data/history", {
            "data": payload, "options": {"cas": 19}})
        need(write_status == 200 and write.get("data", {}).get("version") == 20, "fresh_dr_valid_write")
        expected = self.observe_api(expected=False, count=18)
        restart = self.reopen()
        observed = self.observe_api(expected=False, count=18)
        read_status, result = self.endpoint.call("GET", "secret/data/history?version=20")
        raw_status, raw = self.endpoint.call("POST", "sys/internal/storage/kv2-version-witness", {
            "mount": "secret", "path": "history", "version": 20})
        self.phase("new_write_raw_observation", {"status": raw_status, "response": raw})
        need(raw_status == 200, "new_write_raw_witness_status")
        precise = full.verify_storage_witness(raw, 20, observed["metadata"]["versions"]["20"], payload)
        self.check("new_write_survives_cold_reopen", expected == observed and read_status == 200
                   and full.same_json_tokens(result.get("data", {}).get("data"), payload)
                   and precise["payload_canonical_sha256"] == json_hash(payload), {
                       "write_status": write_status, "version": 20, "restart": restart,
                       "before_restart": expected, "after_restart": observed,
                       "read_status": read_status, "raw_status": raw_status, "raw": precise})

    def execute(self):
        self.prepare()
        self.run_baseline()
        self.quarantine_original()
        self.make_recovery()
        self.recover()

    def finish(self):
        stopped = []
        for label, callback in (
                ("recovery", self.recovery.stop if self.recovery else None),
                ("baseline", self.baseline.finish if self.baseline and not self.baseline_finished else None)):
            if callback is None:
                continue
            original = getattr(self.recovery, "process", None) if label == "recovery" else None
            try:
                callback()
                if original is not None:
                    need(original.poll() is not None, "cleanup_owned_process_running")
                    stopped.append({"owner": label, "pid": original.pid, "returncode": original.returncode})
            except BaseException as error:
                self.report["cleanup_failures"].append({"owner": label, "error": failure_label(error)})
        try:
            need(self.before is not None and self.backup_manifest is not None
                 and self.quarantine_manifest is not None, "final_custody_not_reached")
            after = self.source_identity(ROOT, self.args.binary)
            need(after == self.before and file_pin(self.args.seed_binary) == self.seed_pin
                 and file_pin(self.bao) == self.cli_pin and file_pin(self.args.build_log) == self.build_log_pin
                 and file_pin(self.args.build_receipt, private=True) == self.build_receipt_pin
                 and file_pin(self.build_selection_path, private=True) == self.build_selection_pin,
                 "input_source_binary_or_build_log_changed")
            need(file_pin(self.backup / "manifest.json", private=True) == self.manifest_pin, "backup_manifest_changed")
            for row in self.backup_manifest["files"]:
                need(file_pin(self.backup / row["path"], private=True) == {k: v for k, v in row.items() if k != "path"},
                     "backup_artifact_changed")
            final_tree = tree_manifest(self.quarantined)
            write_private_tree(self.root / "original-tree-after-recovery.json", final_tree)
            need(final_tree == self.quarantine_manifest and not self.baseline.root.exists(), "quarantined_original_changed")
            for name, value in (("unseal.key", self.key), ("root.token", self.token)):
                need(full.private_read(self.keys / name, 65536).decode() == value, "key_custody_changed")
            final_directories = self.directory_observations()
            need(final_directories == self.directory_custody, "private_directory_custody_changed")
            all_secrets = self.secrets + (self.baseline.secrets if self.baseline else [])
            public = json.dumps(self.report, sort_keys=True)
            clean = not any(marker in public for marker in credential_markers(all_secrets))
            need(self.process_owner is not None, "owned_process_custody_required")
            process_receipt = self.process_owner.finish()
            self.report["process_custody"] = process_receipt
            self.check("final_custody_cleanup_and_redaction", not self.report["cleanup_failures"]
                       and clean and not self.process_owner.failed
                       and process_receipt.get("passed_process_custody") is True, {
                "source_identity_after": after, "backup_manifest": self.manifest_pin,
                "quarantine_after": tree_summary(final_tree), "stopped_processes": stopped,
                "private_directory_custody": final_directories,
                "all_owned_sessions": process_receipt,
                "key_files_unchanged_and_private": True, "runtime_credentials_and_fingerprints_absent": clean})
        except BaseException as error:
            self.report.setdefault("failure", failure_label(error))
        finally:
            if self.process_owner is not None:
                try:
                    self.report["process_custody"] = self.process_owner.finish()
                    if (self.process_owner.failed
                            or self.report["process_custody"].get("passed_process_custody") is not True):
                        self.report.setdefault("failure", "owned_process_custody_failed")
                except BaseException as error:
                    self.report.setdefault("failure", failure_label(error))
        all_secrets = self.secrets + (self.baseline.secrets if self.baseline else [])
        public = json.dumps(self.report, sort_keys=True)
        for marker in credential_markers(all_secrets):
            if marker in public:
                public = public.replace(marker, "[redacted]")
                self.report.setdefault("failure", "runtime_credential_or_fingerprint_in_report")
        redacted = json.loads(public)
        if self.report.get("failure"):
            redacted["failure"] = self.report["failure"]
        self.report = redacted
        self.report["missing_checks"] = sorted(set(CHECKS) - {r["case"] for r in self.report["checks"] if r["passed"] is True})
        good = (not self.report.get("failure") and complete(self.report["checks"])
                and self.report.get("baseline", {}).get("qualified") is True)
        self.report["status"] = "passed" if good else "failed"
        self.report["fresh_directory_same_seal_v6_recovery_verified"] = good
        full.private_write(self.root / "dr25-summary.json", encoded(self.report))
        return 0 if good else 1


def failure_label(error):
    value = str(error)
    return value if isinstance(error, Failure) and re.fullmatch(r"[a-z0-9_]{1,160}", value) else type(error).__name__


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--seed-binary", required=True, type=Path)
    parser.add_argument("--build-source-commit", required=True)
    parser.add_argument("--build-log", required=True, type=Path)
    parser.add_argument("--build-receipt", required=True, type=Path)
    parser.add_argument("--build-receipt-sha256", required=True)
    parser.add_argument("--private-work-root", required=True, type=Path)
    parser.add_argument("--backup-parent", required=True, type=Path)
    parser.add_argument("--key-parent", required=True, type=Path)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit):
        parser.error("full build source commit required")
    if not re.fullmatch(r"[0-9a-f]{64}", args.build_receipt_sha256):
        parser.error("independently retained build receipt SHA-256 required")
    if os.name != "posix":
        parser.error("owned POSIX process groups required")
    for name in ("binary", "seed_binary", "build_log", "build_receipt", "private_work_root", "backup_parent", "key_parent"):
        if not getattr(args, name).is_absolute():
            parser.error("absolute paths required")
    for name in ("binary", "seed_binary", "build_log", "build_receipt"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    private_parent(args.private_work_root.parent)
    need(not os.path.lexists(args.private_work_root) and not args.private_work_root.is_relative_to(ROOT),
         "new_private_root_outside_checkout_required")
    return args


def main(argv=None):
    args = parse_args(argv)
    os.umask(0o077)
    args.private_work_root.mkdir(mode=0o700)
    for name in ("dr-phases", "commands"):
        (args.private_work_root / name).mkdir(mode=0o700)
    run = DisasterRecovery(args)
    try:
        import kv2_dr_process_custody as custody
        with custody.activated() as owner:
            run.process_owner = owner
            try:
                run.execute()
            except BaseException as error:
                run.report["failure"] = failure_label(error)
            code = run.finish()
    except BaseException as error:
        run.report["failure"] = failure_label(error)
        if (run.root / "dr25-summary.json").exists():
            run.report["status"] = "failed"
            run.report["fresh_directory_same_seal_v6_recovery_verified"] = False
            full.private_write(run.root / "dr25-summary.json", encoded(run.report), replace=True)
            code = 1
        else:
            code = run.finish()
    print(json.dumps({"status": run.report["status"], "summary": str(run.root / "dr25-summary.json"),
                      "required_count": 25, "fresh_directory_same_seal_v6_recovery_verified":
                          run.report["fresh_directory_same_seal_v6_recovery_verified"]}))
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Failure, OSError, ValueError):
        print("DR25 input admission failed before service execution", file=sys.stderr)
        raise SystemExit(1) from None
