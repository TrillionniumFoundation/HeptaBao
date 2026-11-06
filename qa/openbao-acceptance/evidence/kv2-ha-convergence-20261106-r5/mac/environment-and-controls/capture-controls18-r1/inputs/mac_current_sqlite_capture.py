#!/usr/bin/env python3
"""Create-only current SQLite capture and whole-database rollback verification.

This preparation does not run HeptaBao, an SDK, a provider, or a service manager.
The caller must first bind successful normal-107 and full34/DR25 evidence. This
module never grants production, writer-fence, or cross-database qualification.
All capture manifests, keys, source names, data hashes, and raw diagnostics stay
inside owned private directories. Only public_result() is suitable for export.
"""
import time
ENTRY = time.monotonic()

import argparse
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import sqlite3
import stat
import sys
import urllib.parse
sys.dont_write_bytecode = True

SCHEMA = "heptabao.mac-current-sqlite-capture-plan.v1"
WORKFLOW_SCHEMA = "heptabao.mac-current-sqlite-recovery-workflow.v1"
CAPTURE_SCHEMA = "heptabao.closed-current-sqlite-capture.v1"
ARCHIVE_SCHEMA = "heptabao.current-sqlite-rollback-fernet.v1"
CHUNK = 4 * 1024**2
MAX_DB = 4 * 1024**3
MAX_TOTAL = 64 * 1024**3
MAX_FILES = 80
MAX_META = 16 * 1024**2
MAX_SECONDS = 300
MAX_WORKFLOW_SECONDS = 900
FAMILY = ("", "-wal", "-shm", "-journal")
SAFETY = (
    "authbus-credential-denials-required.v1.json",
    "authbus/credential-denials.v1.jsonl",
    "authbus/bad-refresh-quarantine.json",
    "authbus/lease-epochs.json",
    "authbus/applied-profiles.json",
    "authbus/publish-baseline.json",
    "authbus/refresh-backoff.json",
)
FIXED = {
    "state/openclaw.sqlite": "shared",
    "state/openclaw-quarantine.sqlite": "quarantine",
    "authbus/production-transport/state.sqlite": "transport",
    "authbus/production-transport/operation.sqlite": "transport",
}
MAC_SOURCE = Path("/Users/qianqi/.openclaw")
NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def check(end):
    need(time.monotonic() < end, "original_phase_deadline")


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False,
                      default=lambda x: {"blobHex": x.hex()} if isinstance(x, bytes) else None).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def directory(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_directory")
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == 0o700, "owned_private_directory")
    return path


def directory_pin(path, expected):
    path = directory(path)
    info = path.lstat()
    actual = {"dev": info.st_dev, "inode": info.st_ino,
              "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)}
    need(actual == expected, "directory_identity_pin")
    return path


def directory_binding(path):
    path = directory(path)
    info = path.lstat()
    return {"path": str(path), "identity": {
        "dev": info.st_dev, "inode": info.st_ino,
        "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)}}


def validate_directory_binding(value):
    need(isinstance(value, dict) and set(value) == {"path", "identity"}
         and isinstance(value["path"], str) and Path(value["path"]).is_absolute()
         and str(Path(value["path"])) == value["path"]
         and ".." not in Path(value["path"]).parts,
         "private_directory_binding_shape")
    pin = value["identity"]
    need(isinstance(pin, dict) and set(pin) == {"dev", "inode", "uid", "mode"}
         and all(type(pin[key]) is int for key in pin)
         and pin["dev"] >= 0 and pin["inode"] > 0 and pin["uid"] >= 0
         and pin["mode"] == 0o700, "private_directory_identity_shape")
    return value


def verify_directory_binding(value):
    validate_directory_binding(value)
    need(directory_binding(value["path"]) == value, "bound_directory_identity_changed")


def validate_origin_directories(value):
    need(isinstance(value, dict) and set(value) == {"source_root", "capture_root"},
         "captured_origin_directories_required")
    for item in value.values():
        validate_directory_binding(item)
    disjoint(*(Path(item["path"]) for item in value.values()))
    return value


def backup_filesystem_admission(origin, archive_parent, key_parent):
    validate_origin_directories(origin)
    for item in origin.values():
        verify_directory_binding(item)
    archive = directory_binding(archive_parent)
    key = directory_binding(key_parent)
    need(all(archive["identity"]["dev"] != item["identity"]["dev"]
             for item in origin.values()),
         "backup_requires_filesystem_distinct_from_source_and_capture")
    need(archive["identity"]["dev"] != key["identity"]["dev"],
         "recovery_key_requires_independent_filesystem")
    return {"origin": origin, "archive_parent": archive, "key_parent": key}


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def new_directory(parent, name):
    parent = directory(parent)
    need(isinstance(name, str) and NAME.fullmatch(name) and name not in (".", ".."),
         "single_new_directory_name")
    path = parent / name
    need(not os.path.lexists(path), "create_only_directory")
    path.mkdir(mode=0o700)
    sync_dir(parent)
    return directory(path)


def mkdir_below(root, relative):
    root = directory(root)
    parts = PurePosixPath(relative).parts
    for part in parts:
        need(NAME.fullmatch(part) and part not in (".", ".."), "owned_relative_directory")
        root = directory(root / part) if os.path.lexists(root / part) else new_directory(root, part)
    return root


def disjoint(*paths):
    paths = [Path(p) for p in paths]
    for index, left in enumerate(paths):
        need(left.is_absolute(), "absolute_root")
        for right in paths[index + 1:]:
            need(not left.is_relative_to(right) and not right.is_relative_to(left),
                 "disjoint_source_capture_archive_key_restore_roots")


def observe(path):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"present": False}
    return {"present": True, "identity": identity(info),
            "regular": stat.S_ISREG(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode)}


def family(path):
    return {suffix: observe(Path(str(path) + suffix)) for suffix in FAMILY}


@contextlib.contextmanager
def held(path, limit, exact=None):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_private_file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
             and 0 <= before.st_size <= limit
             and (exact is None or before.st_size == exact), "owned_bounded_private_file")
        yield fd, before
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             "closed_input_changed")
    finally:
        os.close(fd)


def read_private(path, limit, end):
    with held(path, limit) as (fd, before):
        blocks, size = [], 0
        while True:
            check(end)
            block = os.read(fd, min(CHUNK, limit + 1))
            if not block:
                break
            blocks.append(block)
            size += len(block)
            need(size <= limit, "bounded_private_read")
        need(size == before.st_size, "private_read_size")
    return b"".join(blocks)


def private_new(path, raw):
    path = Path(path)
    directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(path.parent)


def file_hash(path, size, end):
    value = hashlib.sha256()
    count = 0
    with held(path, size, exact=size) as (fd, _):
        while True:
            check(end)
            block = os.read(fd, CHUNK)
            if not block:
                break
            count += len(block)
            value.update(block)
    need(count == size, "full_file_hash_size")
    return value.hexdigest()


def copy_closed(source, target, end):
    count, value = 0, hashlib.sha256()
    with held(source, MAX_DB) as (fd, before):
        directory(Path(target).parent)
        output = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(output, "wb") as stream:
            while True:
                check(end)
                block = os.read(fd, CHUNK)
                if not block:
                    break
                stream.write(block)
                value.update(block)
                count += len(block)
            stream.flush()
            os.fsync(stream.fileno())
        need(count == before.st_size, "closed_copy_size")
    sync_dir(Path(target).parent)
    need(file_hash(target, count, end) == value.hexdigest(), "independent_closed_copy_readback")
    return {"bytes": count, "sha256": value.hexdigest()}


def auth_rows(conn):
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
    result = {}
    for name, columns, key in (
        ("auth_profile_store", "store_key,store_json,updated_at", "store_key"),
        ("auth_profile_state", "state_key,state_json,updated_at", "state_key"),
    ):
        rows = conn.execute("SELECT " + columns + " FROM " + name + " ORDER BY " + key
                            + " LIMIT 4097").fetchall() if name in tables else []
        need(len(rows) <= 4096, "complete_bounded_auth_rows")
        result[name] = rows
    return result


def db_schema(conn):
    return conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()


def no_owned_source_handles(identities):
    targets = {(row[0], row[1]) for row in identities}
    surface = Path("/dev/fd" if sys.platform == "darwin" else "/proc/self/fd")
    need(surface.is_dir(), "parent_fd_inventory_available")
    matches = 0
    for entry in surface.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            first = os.fstat(int(entry.name))
            second = os.fstat(int(entry.name))
        except OSError as error:
            need(error.errno == errno.EBADF, "parent_fd_inventory_gap")
            continue
        need((first.st_dev, first.st_ino, first.st_mode)
             == (second.st_dev, second.st_ino, second.st_mode), "parent_fd_identity_changed")
        matches += (first.st_dev, first.st_ino) in targets
    need(matches == 0, "owned_source_handle_not_retired")
    return True


def read_safety(root, end):
    result = {}
    for name in SAFETY:
        path = root / name
        before = observe(path)
        if not before["present"]:
            result[name] = {"present": False}
            continue
        first = read_private(path, MAX_META, end)
        second = read_private(path, MAX_META, end)
        need(first == second and observe(path) == before, "two_held_safety_reads_changed")
        result[name] = {"present": True, "raw": first, "identity": before["identity"]}
    return result


def safe_relative(name):
    need(isinstance(name, str) and 0 < len(name) <= 256, "relative_file_name")
    path = PurePosixPath(name)
    need(not path.is_absolute() and str(path) == name
         and all(part not in ("", ".", "..") for part in path.parts), "canonical_relative_file")
    fixed = {"capture.private.json", "source-config.private.json", "baseline-state/openclaw.json",
             *("baseline-state/" + name for name in SAFETY),
             *("baseline-state/" + name for name in FIXED)}
    need(name in fixed or re.fullmatch(
        r"baseline-state/agents/[A-Za-z0-9_.-]{1,128}/agent/openclaw-agent\.sqlite", name),
        "declared_backup_path_only")
    return name


def validate_plan(plan, *, fixture=False):
    need(isinstance(plan, dict) and plan.get("schema") == SCHEMA, "plan_schema")
    phase = plan.get("phase")
    common = {"schema", "phase", "budget_seconds"}
    required = {
        "capture": {"source_root", "source_root_identity", "source_config_sha256", "agents",
                    "capture_parent", "capture_parent_identity", "capture_name",
                    "maximum_total_bytes", "maximum_database_bytes"},
        "backup": {"capture_root", "capture_sha256", "archive_parent", "archive_name",
                   "key_parent", "key_name"},
        "restore-verify": {"archive_root", "key_file", "capture_sha256",
                           "restore_parent", "restore_name"},
    }
    need(phase in required and set(plan) == common | required[phase], "exact_phase_plan_fields")
    need(type(plan["budget_seconds"]) is int and 0 < plan["budget_seconds"] <= MAX_SECONDS,
         "original_bounded_phase_budget")
    for name in ("source_config_sha256", "capture_sha256"):
        if name in plan:
            need(isinstance(plan[name], str) and re.fullmatch(r"[a-f0-9]{64}", plan[name]),
                 "private_input_digest_pin")
    if phase == "capture":
        need(fixture or (sys.platform == "darwin" and os.geteuid() == 501
                        and Path(plan["source_root"]) == MAC_SOURCE), "explicit_mac_source_scope")
        need(type(plan["maximum_total_bytes"]) is int
             and 0 < plan["maximum_total_bytes"] <= MAX_TOTAL, "aggregate_database_bound")
        need(type(plan["maximum_database_bytes"]) is int
             and 0 < plan["maximum_database_bytes"] <= MAX_DB, "single_database_bound")
        agents = plan["agents"]
        need(isinstance(agents, list) and 0 < len(agents) <= 64
             and len(set(agents)) == len(agents)
             and all(isinstance(name, str) and NAME.fullmatch(name)
                     and name not in (".", "..") for name in agents), "exact_configured_agent_plan")
    return plan


def public_result(phase, detail, error=None):
    return {
        "schema": "heptabao.current-sqlite-reversible-work.public.v1",
        "phase": phase, "status": "passed" if error is None else "failed",
        "error": error, "counts": detail,
        "only_declared_captured_generation": True,
        "source_data_write_invoked": False, "provider_or_sdk_called": False,
        "service_or_client_configuration_changed": False,
        "traffic_cutover_performed": False, "old_assets_removed": False,
        "source_native_sqlite_sidecar_writes_excluded": False,
        "cross_database_atomic_snapshot_qualified": False,
        "all_known_writers_fenced": False, "source_freshness_after_capture_qualified": False,
        "current_credential_validity_qualified": False, "full_host_inventory_qualified": False,
        "formal_kv2_qualified": False, "all_clients_and_backups_migrated": False,
        "credential_values_or_content_fingerprints_published": False,
    }


def register_output(owner, path, phase):
    if owner is not None:
        info = directory(path).lstat()
        owner.append({"path": path, "phase": phase,
                      "identity": identity(info)[:5]})


def capture(plan, end, owner=None):
    """Per-database transaction snapshots; no claim of a global writer fence."""
    source = directory_pin(plan["source_root"], plan["source_root_identity"])
    parent = directory_pin(plan["capture_parent"], plan["capture_parent_identity"])
    disjoint(source, parent / plan["capture_name"])
    config_raw = read_private(source / "openclaw.json", 1024**2, end)
    need(digest(config_raw) == plan["source_config_sha256"], "current_config_bytes_pin")
    config = json.loads(config_raw, object_pairs_hook=unique)
    configured = config.get("agents", {}).get("list")
    need(isinstance(configured, list) and all(isinstance(row, dict) for row in configured),
         "explicit_configured_agent_list")
    ids = [row.get("id") for row in configured]
    need(len(ids) == len(set(ids)) == len(plan["agents"]) and set(ids) == set(plan["agents"]),
         "complete_current_configured_agent_set")
    for row in configured:
        expected = source / "agents" / row["id"] / "agent"
        need(Path(row.get("agentDir", str(expected))) == expected,
             "configured_agent_directory_requires_exact_supported_scope")
    paths = [(f"agents/{agent}/agent/openclaw-agent.sqlite", "agent", agent)
             for agent in plan["agents"]] + [(name, kind, None) for name, kind in FIXED.items()]
    preflight = []
    for name, kind, agent in paths:
        observed = family(source / name)
        need(observed[""]["present"] or not any(row["present"] for row in observed.values()),
             "absent_main_with_present_sqlite_sidecar")
        if observed[""]["present"] and observed[""]["identity"][6] == 0:
            need(not any(observed[suffix]["present"] for suffix in FAMILY[1:]),
                 "empty_main_with_present_sqlite_sidecar")
        need(kind != "transport" or not any(row["present"] for row in observed.values()),
             "present_transport_requires_independent_current_writer_operation_fence")
        preflight.append((name, kind, agent, observed))
    need(not os.path.lexists(source / "authbus-credential-denials-writer.v1.lock"),
         "existing_security_writer_lock_preserved")
    need(shutil.disk_usage(parent).free >= 2 * plan["maximum_total_bytes"]
         + plan["maximum_database_bytes"] + 512 * 1024**2, "capture_disk_headroom")
    safety_before = read_safety(source, end)
    root = new_directory(parent, plan["capture_name"])
    register_output(owner, root, "capture")
    baseline = new_directory(root, "baseline-state")
    candidate = new_directory(root, "candidate-state")
    private_new(root / "source-config.private.json", config_raw)
    result = {"schema": CAPTURE_SCHEMA, "ok": False, "host": "mac",
              "origin_directories": {"source_root": directory_binding(source),
                                     "capture_root": directory_binding(root)},
              "configured_agent_count": len(ids), "database_rows": [], "files": [],
              "sqlite_family_suffixes": list(FAMILY), "safety_paths": list(SAFETY),
              "source_config_sha256": digest(config_raw),
              "source_physical_byte_equality_claimed": False,
              "source_native_sidecar_writes_excluded": False,
              "external_writer_fence_claimed": False,
              "cross_database_atomic_snapshot_claimed": False}
    identities, total = [], 0
    for name, row in safety_before.items():
        entry = {"path": "baseline-state/" + name, "present": row["present"]}
        if row["present"]:
            identities.append(row["identity"])
            for base in (baseline, candidate):
                mkdir_below(base, str(PurePosixPath(name).parent))
                private_new(base / name, row["raw"])
            entry.update(bytes=len(row["raw"]), sha256=digest(row["raw"]))
        result["files"].append(entry)
    for name, kind, agent, original_family in preflight:
        check(end)
        path = source / name
        current = family(path)
        need(current[""]["present"] == original_family[""]["present"], "source_presence_changed")
        row = {"relative_path": name, "kind": kind, "agent": agent,
               "source_family_before": current, "present": current[""]["present"]}
        result["database_rows"].append(row)
        file_row = {"path": "baseline-state/" + name, "present": row["present"]}
        result["files"].append(file_row)
        if not row["present"]:
            need(not any(value["present"] for value in current.values()), "absent_family_changed")
            continue
        info = path.lstat()
        need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
             and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_nlink == 1, "source_database_custody")
        for member in current.values():
            if member["present"]:
                meta = member["identity"]
                need(member["regular"] and not member["symlink"] and meta[2] == os.geteuid()
                     and stat.S_IMODE(meta[4]) == 0o600 and meta[5] == 1,
                     "source_sqlite_family_custody")
                identities.append(meta)
        mkdir_below(baseline, str(PurePosixPath(name).parent))
        mkdir_below(candidate, str(PurePosixPath(name).parent))
        target, clone = baseline / name, candidate / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        source_db = target_db = None
        try:
            need(identity(os.fstat(fd)) == identity(info), "source_database_held_identity")
            if info.st_size == 0:
                empty_family = family(path)
                need(not any(empty_family[suffix]["present"] for suffix in FAMILY[1:]),
                     "empty_main_with_present_sqlite_sidecar")
                private_new(target, b"")
                row["empty_database_marker"] = True
            else:
                source_db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
                source_db.execute("PRAGMA query_only=ON")
                source_db.set_progress_handler(lambda: int(time.monotonic() >= end), 1000)
                source_db.execute("BEGIN")
                schema = db_schema(source_db)
                pages = source_db.execute("PRAGMA page_count").fetchone()[0]
                size = source_db.execute("PRAGMA page_size").fetchone()[0]
                total += pages * size
                need(pages * size <= plan["maximum_database_bytes"]
                     and total <= plan["maximum_total_bytes"], "logical_snapshot_byte_bound")
                rows = auth_rows(source_db) if kind == "agent" else None
                target_db = sqlite3.connect(target, timeout=1)
                target_db.set_progress_handler(lambda: int(time.monotonic() >= end), 1000)
                source_db.backup(target_db, pages=256,
                                 progress=lambda *_: check(end), sleep=0.05)
                need(target_db.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete",
                     "closed_destination_journal_normalization")
                need(target_db.execute("PRAGMA quick_check").fetchall() == [("ok",)]
                     and db_schema(target_db) == schema
                     and target_db.execute("PRAGMA page_count").fetchone()[0] == pages,
                     "complete_database_backup_integrity")
                if rows is not None:
                    need(auth_rows(target_db) == rows == auth_rows(source_db),
                         "all_auth_rows_same_source_transaction")
                    row["auth_rows_sha256"] = digest(encoded(rows))
                    row["auth_store_rows"] = len(rows["auth_profile_store"])
                    row["auth_state_rows"] = len(rows["auth_profile_state"])
                row["schema_sha256"] = digest(encoded(schema))
                row["page_count"] = pages
                target_db.close()
                target_db = None
                source_db.rollback()
                source_db.close()
                source_db = None
                target.chmod(0o600)
                with held(target, MAX_DB) as (owned_fd, _):
                    os.fsync(owned_fd)
            need(identity(os.fstat(fd))[:6] == identity(path.lstat())[:6] == identity(info)[:6],
                 "source_database_custody_changed")
            if row.get("empty_database_marker"):
                empty_family = family(path)
                need(identity(os.fstat(fd)) == identity(path.lstat()) == identity(info)
                     and not any(empty_family[suffix]["present"] for suffix in FAMILY[1:]),
                     "empty_database_family_changed")
        finally:
            if target_db is not None:
                target_db.close()
            if source_db is not None:
                source_db.close()
            os.close(fd)
        need(not any(observe(Path(str(target) + suffix))["present"] for suffix in FAMILY[1:]),
             "closed_snapshot_has_no_sidecars")
        pin = copy_closed(target, clone, end)
        file_row.update(pin)
        row.update(snapshot_bytes=pin["bytes"], snapshot_sha256=pin["sha256"],
                   source_family_after=family(path))
        row["source_family_metadata_changed"] = row["source_family_before"] != row["source_family_after"]
    for name, _kind, _agent, before in preflight:
        if not before[""]["present"]:
            need(not any(value["present"] for value in family(source / name).values()),
                 "declared_absent_family_became_present")
    for row in result["database_rows"]:
        if row.get("empty_database_marker"):
            final = family(source / row["relative_path"])
            need(final[""] == row["source_family_before"][""]
                 and not any(final[suffix]["present"] for suffix in FAMILY[1:]),
                 "declared_empty_database_family_changed")
    need(read_safety(source, end) == safety_before, "complete_safety_cohort_changed")
    need(not os.path.lexists(source / "authbus-credential-denials-writer.v1.lock"),
         "security_writer_lock_appeared")
    need(read_private(source / "openclaw.json", 1024**2, end) == config_raw,
         "source_configuration_changed")
    for base in (baseline, candidate):
        projected = json.loads(config_raw, object_pairs_hook=unique)
        for row in projected["agents"]["list"]:
            row["agentDir"] = str(base / "agents" / row["id"] / "agent")
        raw = encoded(projected)
        private_new(base / "openclaw.json", raw)
        if base == baseline:
            result["files"].append({"path": "baseline-state/openclaw.json", "present": True,
                                    "bytes": len(raw), "sha256": digest(raw)})
    result["files"].append({"path": "source-config.private.json", "present": True,
                            "bytes": len(config_raw), "sha256": digest(config_raw)})
    need(len(result["files"]) + 1 <= MAX_FILES, "complete_capture_file_bound")
    no_owned_source_handles(identities)
    directory_pin(source, plan["source_root_identity"])
    directory_pin(parent, plan["capture_parent_identity"])
    for item in result["origin_directories"].values():
        verify_directory_binding(item)
    check(end)
    result.update(ok=True, logical_snapshot_bytes=total, all_owned_source_handles_retired=True,
                  strict_safety_cohort_equal=True, source_config_exact=True,
                  capture_completed_unix_ns=time.time_ns())
    raw = encoded(result)
    private_new(root / "capture.private.json", raw)
    private_new(root / "capture-binding.private.json",
                encoded({"capture_sha256": digest(raw), "bytes": len(raw)}))
    private_new(root / "result.public.json",
                encoded(public_result("capture", {"configured_agents": len(ids),
                                                  "database_entries": len(paths),
                                                  "present_databases": sum(row["present"] for row in result["database_rows"]),
                                                  "logical_snapshot_bytes": total,
                                                  "complete_declared_files": len(result["files"]) })))
    sync_dir(root)
    return root, result


def validate_capture_manifest(value):
    need(value.get("schema") == CAPTURE_SCHEMA and value.get("ok") is True
         and value.get("all_owned_source_handles_retired") is True
         and value.get("strict_safety_cohort_equal") is True
         and value.get("sqlite_family_suffixes") == list(FAMILY)
         and value.get("safety_paths") == list(SAFETY), "complete_closed_capture_required")
    validate_origin_directories(value.get("origin_directories"))
    rows = value["files"]
    need(isinstance(rows, list) and 0 < len(rows) < MAX_FILES
         and len({row["path"] for row in rows}) == len(rows), "unique_capture_paths")
    names = {safe_relative(row["path"]) for row in rows}
    databases = value["database_rows"]
    agent_names = [row["agent"] for row in databases if row["kind"] == "agent"]
    need(len(agent_names) == len(set(agent_names)) == value["configured_agent_count"],
         "complete_capture_agent_denominator")
    expected_names = {"source-config.private.json", "baseline-state/openclaw.json",
                      *("baseline-state/" + name for name in SAFETY),
                      *("baseline-state/" + name for name in FIXED),
                      *(f"baseline-state/agents/{agent}/agent/openclaw-agent.sqlite" for agent in agent_names)}
    need(names == expected_names, "complete_capture_path_set")
    fixed = {row["relative_path"]: row for row in databases if row["kind"] != "agent"}
    need(set(fixed) == set(FIXED)
         and all(fixed[name]["kind"] == kind for name, kind in FIXED.items()),
         "complete_shared_quarantine_transport_set")
    by_name = {row["path"]: row for row in rows}
    for database in databases:
        item = by_name["baseline-state/" + database["relative_path"]]
        need(item["present"] is database["present"], "capture_database_presence_binding")
        if database["present"]:
            need(item["bytes"] == database["snapshot_bytes"]
                 and item["sha256"] == database["snapshot_sha256"], "capture_database_bytes_binding")
        if database["kind"] == "transport":
            need(database["present"] is False, "unsupported_present_transport")
    for row in rows:
        need(type(row.get("present")) is bool, "capture_presence_type")
        if row["present"]:
            need(type(row.get("bytes")) is int and 0 <= row["bytes"] <= MAX_DB
                 and re.fullmatch(r"[a-f0-9]{64}", row.get("sha256", "")), "capture_file_pin")
        else:
            need(set(row) == {"path", "present"}, "absent_capture_file_fields")
    return rows


def validate_original_configuration(value, raw):
    need(digest(raw) == value["source_config_sha256"], "original_configuration_bytes_binding")
    config = json.loads(raw, object_pairs_hook=unique)
    configured = config.get("agents", {}).get("list")
    need(isinstance(configured, list) and all(isinstance(row, dict) for row in configured),
         "original_configuration_agent_shape")
    ids = [row.get("id") for row in configured]
    observed = [row["agent"] for row in value["database_rows"] if row["kind"] == "agent"]
    need(len(ids) == len(set(ids)) == value["configured_agent_count"]
         and set(ids) == set(observed), "original_configuration_all_agents_required")


def capture_inputs(root, expected, end, *, require_completion=True):
    root = directory(root)
    raw = read_private(root / "capture.private.json", MAX_META, end)
    need(digest(raw) == expected, "independent_capture_manifest_pin")
    value = json.loads(raw, object_pairs_hook=unique)
    rows = validate_capture_manifest(value)
    validate_original_configuration(value, read_private(root / "source-config.private.json", 1024**2, end))
    for row in rows:
        if not row["present"]:
            need(not os.path.lexists(root / row["path"]), "closed_capture_absence_changed")
    if require_completion:
        completion = json.loads(read_private(root / "result.public.json", 65536, end), object_pairs_hook=unique)
        need(completion.get("schema") == "heptabao.current-sqlite-reversible-work.public.v1"
             and completion.get("phase") == "capture" and completion.get("status") == "passed",
             "completed_capture_phase_receipt_required")
    return value, [{"path": "capture.private.json", "present": True,
                    "bytes": len(raw), "sha256": expected}, *rows]


def backup(plan, end, owner=None):
    from cryptography.fernet import Fernet
    source = directory(plan["capture_root"])
    capture_value, rows = capture_inputs(source, plan["capture_sha256"], end)
    archive_parent, key_parent = directory(plan["archive_parent"]), directory(plan["key_parent"])
    origin = capture_value["origin_directories"]
    need(origin["capture_root"] == directory_binding(source), "original_capture_directory_binding")
    locations = backup_filesystem_admission(origin, archive_parent, key_parent)
    archive = archive_parent / plan["archive_name"]
    keys = key_parent / plan["key_name"]
    disjoint(source, archive, keys)
    total = sum(row.get("bytes", 0) for row in rows if row["present"])
    need(total <= MAX_TOTAL and shutil.disk_usage(archive_parent).free
         >= (total * 4 + 2) // 3 + len(rows) * CHUNK + 128 * 1024**2,
         "encrypted_backup_disk_admission")
    need(not os.path.lexists(archive) and not os.path.lexists(keys), "fresh_archive_and_key_roots")
    keys = new_directory(key_parent, plan["key_name"])
    key = Fernet.generate_key()
    private_new(keys / "recovery.key", key)
    need(read_private(keys / "recovery.key", 44, end) == key, "recovery_key_written_exact")
    cipher = Fernet(key)
    archive = new_directory(archive_parent, plan["archive_name"])
    register_output(owner, archive, "backup")
    chunks = new_directory(archive, "chunks")
    locations.update(archive_root=directory_binding(archive), key_root=directory_binding(keys))
    manifest = {"schema": ARCHIVE_SCHEMA, "capture_sha256": plan["capture_sha256"],
                "chunk_bytes": CHUNK, "files": [], "private_location_binding": locations}
    serial = 0
    for item in rows:
        row = dict(item, chunks=[])
        if row["present"]:
            count, value = 0, hashlib.sha256()
            with held(source / row["path"], row["bytes"], exact=row["bytes"]) as (fd, _):
                while True:
                    check(end)
                    plain = os.read(fd, CHUNK)
                    if not plain:
                        break
                    count += len(plain)
                    value.update(plain)
                    token = cipher.encrypt(plain)
                    name = f"{serial:08d}.fernet"
                    serial += 1
                    private_new(chunks / name, token)
                    row["chunks"].append({"name": name, "bytes": len(token),
                                          "plaintext_bytes": len(plain), "sha256": digest(token)})
            need(count == row["bytes"] and value.hexdigest() == row["sha256"],
                 "closed_backup_input_bytes_changed")
        manifest["files"].append(row)
    capture_inputs(source, plan["capture_sha256"], end)
    need(backup_filesystem_admission(origin, archive_parent, key_parent)
         == {name: locations[name] for name in ("origin", "archive_parent", "key_parent")},
         "backup_location_identity_changed")
    for name in ("archive_root", "key_root"):
        verify_directory_binding(locations[name])
    body = encoded(manifest)
    need(len(body) <= MAX_META, "encrypted_manifest_bound")
    private_new(archive / "manifest.fernet", cipher.encrypt(body))
    check(end)
    result = public_result("backup", {"declared_files": len(rows), "encrypted_chunks": serial,
                                      "plaintext_bytes": total})
    result.update(archive_filesystem_distinct_from_source_and_capture=True,
                  key_filesystem_distinct_from_archive=True,
                  distinct_physical_device_or_power_failure_qualification=False)
    private_new(archive / "result.public.json", encoded(result))
    return archive, result


def authenticate_archive(plan, end):
    from cryptography.fernet import Fernet
    archive = directory(plan["archive_root"])
    directory(archive / "chunks")
    completion = json.loads(read_private(archive / "result.public.json", 65536, end), object_pairs_hook=unique)
    need(completion.get("schema") == "heptabao.current-sqlite-reversible-work.public.v1"
         and completion.get("phase") == "backup" and completion.get("status") == "passed",
         "completed_backup_phase_receipt_required")
    key_path = Path(plan["key_file"])
    directory(key_path.parent)
    key_identity = identity(key_path.lstat())
    disjoint(archive, key_path.parent, Path(plan["restore_parent"]) / plan["restore_name"])
    need(archive.stat().st_dev != key_path.parent.stat().st_dev, "independent_recovery_key_filesystem")
    key = read_private(key_path, 44, end)
    need(len(key) == 44, "bounded_recovery_key")
    cipher = Fernet(key)
    manifest_raw = cipher.decrypt(read_private(archive / "manifest.fernet", MAX_META * 2, end))
    need(len(manifest_raw) <= MAX_META, "authenticated_manifest_bound")
    manifest = json.loads(manifest_raw, object_pairs_hook=unique)
    need(manifest.get("schema") == ARCHIVE_SCHEMA and manifest.get("chunk_bytes") == CHUNK
         and manifest.get("capture_sha256") == plan["capture_sha256"], "authenticated_capture_binding")
    rows = manifest["files"]
    need(isinstance(rows, list) and 0 < len(rows) <= MAX_FILES, "archive_file_bound")
    names, chunk_names, total, capture_raw, config_raw = set(), set(), 0, None, None
    for row in rows:
        name = safe_relative(row["path"])
        need(name not in names and type(row["present"]) is bool and isinstance(row["chunks"], list),
             "unique_authenticated_file_presence")
        names.add(name)
        if not row["present"]:
            need(row["chunks"] == [], "absent_file_chunks")
            continue
        need(type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_DB
             and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]), "archive_plaintext_file_bound")
        total += row["bytes"]
        need(total <= MAX_TOTAL, "archive_plaintext_total_bound")
        count, value, parts = 0, hashlib.sha256(), []
        if name in ("capture.private.json", "source-config.private.json"):
            need(row["bytes"] <= (MAX_META if name == "capture.private.json" else 1024**2),
                 "capture_or_original_config_bound")
        for chunk in row["chunks"]:
            check(end)
            need(chunk["name"] == f"{len(chunk_names):08d}.fernet"
                 and type(chunk["plaintext_bytes"]) is int and 0 < chunk["plaintext_bytes"] <= CHUNK,
                 "exact_ordered_chunk_inventory")
            chunk_names.add(chunk["name"])
            token = read_private(archive / "chunks" / chunk["name"], CHUNK * 2, end)
            need(len(token) == chunk["bytes"] and digest(token) == chunk["sha256"],
                 "ciphertext_bytes_binding")
            plain = cipher.decrypt(token)
            need(len(plain) == chunk["plaintext_bytes"], "authenticated_chunk_length")
            count += len(plain)
            value.update(plain)
            if name in ("capture.private.json", "source-config.private.json"):
                parts.append(plain)
        need(count == row["bytes"] and value.hexdigest() == row["sha256"],
             "complete_authenticated_plaintext_file")
        if name == "capture.private.json":
            capture_raw = b"".join(parts)
        if name == "source-config.private.json":
            config_raw = b"".join(parts)
    need(capture_raw is not None and digest(capture_raw) == plan["capture_sha256"],
         "original_capture_manifest_authenticated")
    need({entry.name for entry in (archive / "chunks").iterdir()} == chunk_names
         and {entry.name for entry in archive.iterdir()} == {"manifest.fernet", "chunks", "result.public.json"},
         "no_missing_extra_archive_files")
    capture_value = json.loads(capture_raw, object_pairs_hook=unique)
    validate_capture_manifest(capture_value)
    locations = manifest.get("private_location_binding")
    need(isinstance(locations, dict) and set(locations) == {
        "origin", "archive_parent", "key_parent", "archive_root", "key_root"
    } and locations["origin"] == capture_value["origin_directories"],
         "authenticated_original_backup_location_binding")
    # Original source/capture may be lost. Only their authenticated captured
    # identities are needed here; restoration does not reopen those paths.
    for name in ("archive_parent", "key_parent", "archive_root", "key_root"):
        validate_directory_binding(locations[name])
    need(locations["archive_root"] == directory_binding(archive)
         and locations["key_root"] == directory_binding(key_path.parent),
         "actual_archive_and_key_directory_binding")
    need(all(locations["archive_root"]["identity"]["dev"] != item["identity"]["dev"]
             for item in locations["origin"].values()),
         "authenticated_archive_filesystem_independence")
    need(config_raw is not None, "authenticated_original_configuration_required")
    validate_original_configuration(capture_value, config_raw)
    declared = [{"path": "capture.private.json", "present": True,
                 "bytes": len(capture_raw), "sha256": digest(capture_raw)}, *capture_value["files"]]
    need(len(declared) == len(rows)
         and {row["path"]: {k: row[k] for k in ("path", "present", "bytes", "sha256") if k in row}
              for row in rows} == {row["path"]: row for row in declared},
         "all_original_capture_files_and_absences_bound")
    need(identity(key_path.lstat()) == key_identity, "key_custody_changed_during_authentication")
    return archive, cipher, manifest, capture_value, key_identity


def restore_verify(plan, end, owner=None):
    parent = directory(plan["restore_parent"])
    destination = parent / plan["restore_name"]
    need(not os.path.lexists(destination), "fresh_restore_root")
    archive, cipher, manifest, capture_value, key_identity = authenticate_archive(plan, end)
    total = sum(row.get("bytes", 0) for row in manifest["files"] if row["present"])
    need(shutil.disk_usage(parent).free >= total + 128 * 1024**2, "restore_disk_admission")
    # Every MAC and original plaintext hash is checked before this creation.
    destination = new_directory(parent, plan["restore_name"])
    register_output(owner, destination, "restore-verify")
    for row in manifest["files"]:
        check(end)
        target = destination / row["path"]
        if not row["present"]:
            need(not os.path.lexists(target), "restored_absence")
            continue
        relative_parent = str(PurePosixPath(row["path"]).parent)
        if relative_parent != ".":
            mkdir_below(destination, relative_parent)
        value, count = hashlib.sha256(), 0
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            for chunk in row["chunks"]:
                check(end)
                token = read_private(archive / "chunks" / chunk["name"], CHUNK * 2, end)
                need(len(token) == chunk["bytes"] and digest(token) == chunk["sha256"],
                     "late_ciphertext_drift")
                plain = cipher.decrypt(token)
                need(len(plain) == chunk["plaintext_bytes"], "late_authenticated_chunk_length")
                stream.write(plain)
                count += len(plain)
                value.update(plain)
            need(count == row["bytes"] and value.hexdigest() == row["sha256"], "restored_file_exact")
            stream.flush()
            os.fsync(stream.fileno())
        sync_dir(target.parent)
        need(file_hash(target, row["bytes"], end) == row["sha256"], "independent_restore_readback")
    restored_capture, _ = capture_inputs(destination, plan["capture_sha256"], end,
                                        require_completion=False)
    need(restored_capture == capture_value, "complete_restored_capture")
    nonempty, auth, absent, identities = 0, 0, 0, []
    for row in capture_value["database_rows"]:
        path = destination / "baseline-state" / row["relative_path"]
        members = family(path)
        if not row["present"]:
            need(not any(value["present"] for value in members.values()), "restored_absent_database_family")
            absent += 1
            continue
        need(not any(members[suffix]["present"] for suffix in FAMILY[1:]),
             "closed_restore_sidecars_absent")
        if row.get("empty_database_marker"):
            need(path.stat().st_size == 0, "restored_empty_marker")
            continue
        with held(path, row["snapshot_bytes"], exact=row["snapshot_bytes"]) as (_, before):
            identities.append(identity(before))
            conn = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=1)
            try:
                conn.execute("PRAGMA query_only=ON")
                conn.set_progress_handler(lambda: int(time.monotonic() >= end), 1000)
                need(conn.execute("PRAGMA quick_check").fetchall() == [("ok",)]
                     and digest(encoded(db_schema(conn))) == row["schema_sha256"],
                     "whole_database_cold_integrity_and_schema")
                if row["kind"] == "agent":
                    observed_auth = auth_rows(conn)
                    need(digest(encoded(observed_auth)) == row["auth_rows_sha256"]
                         and len(observed_auth["auth_profile_store"]) == row["auth_store_rows"]
                         and len(observed_auth["auth_profile_state"]) == row["auth_state_rows"],
                         "all_captured_auth_rows_cold_exact")
                    auth += row["auth_store_rows"] > 0
            finally:
                conn.close()
        need(not any(observe(Path(str(path) + suffix))["present"] for suffix in FAMILY[1:]),
             "cold_check_created_no_sidecars")
        nonempty += 1
    no_owned_source_handles(identities)
    for name in ("archive_root", "key_root"):
        verify_directory_binding(manifest["private_location_binding"][name])
    need(identity(Path(plan["key_file"]).lstat()) == key_identity, "original_key_custody_unchanged")
    check(end)
    result = public_result("restore-verify", {"nonempty_databases": nonempty,
                                              "auth_stores": auth, "absent_families": absent,
                                              "all_declared_files": len(manifest["files"]),
                                              "plaintext_bytes": total})
    result["all_chunks_authenticated_before_destination_creation"] = True
    result["full_restored_file_bytes_and_declared_absences_exact"] = True
    result["all_owned_restore_handles_retired"] = True
    private_new(destination / "result.public.json", encoded(result))
    sync_dir(destination)
    return destination, result


def validate_workflow(plan, *, fixture=False):
    need(isinstance(plan, dict) and set(plan) == {
        "schema", "overall_budget_seconds", "capture", "backup", "restore"
    } and plan["schema"] == WORKFLOW_SCHEMA, "exact_new_workflow_plan")
    need(type(plan["overall_budget_seconds"]) is int
         and 60 < plan["overall_budget_seconds"] <= MAX_WORKFLOW_SECONDS,
         "new_workflow_total_budget_with_cleanup_reserve")
    validate_plan(plan["capture"], fixture=fixture)
    need(plan["capture"]["phase"] == "capture", "workflow_starts_with_current_capture")
    need(isinstance(plan["backup"], dict) and set(plan["backup"]) == {
        "budget_seconds", "archive_parent", "archive_name", "key_parent", "key_name"
    }, "exact_backup_proposal")
    need(isinstance(plan["restore"], dict) and set(plan["restore"]) == {
        "budget_seconds", "restore_parent", "restore_name"
    }, "exact_restore_proposal")
    for section in ("backup", "restore"):
        value = plan[section]["budget_seconds"]
        need(type(value) is int and 0 < value <= MAX_SECONDS, "bounded_new_phase_budget")
    capture_plan = plan["capture"]
    targets = [Path(capture_plan["source_root"]),
               Path(capture_plan["capture_parent"]) / capture_plan["capture_name"],
               Path(plan["backup"]["archive_parent"]) / plan["backup"]["archive_name"],
               Path(plan["backup"]["key_parent"]) / plan["backup"]["key_name"],
               Path(plan["restore"]["restore_parent"]) / plan["restore"]["restore_name"]]
    disjoint(*targets)
    return plan


def safe_error(error):
    value = str(error) if isinstance(error, Refused) else type(error).__name__
    return value if re.fullmatch(r"[A-Za-z0-9_]{1,100}", value) else "private_workflow_failed"


def workflow_location_admission(plan):
    capture_plan = plan["capture"]
    source = directory_pin(capture_plan["source_root"], capture_plan["source_root_identity"])
    capture_parent = directory_pin(capture_plan["capture_parent"], capture_plan["capture_parent_identity"])
    values = {"source_root": directory_binding(source),
              "capture_parent": directory_binding(capture_parent),
              "archive_parent": directory_binding(plan["backup"]["archive_parent"]),
              "key_parent": directory_binding(plan["backup"]["key_parent"]),
              "restore_parent": directory_binding(plan["restore"]["restore_parent"])}
    archive_dev = values["archive_parent"]["identity"]["dev"]
    need(all(archive_dev != values[name]["identity"]["dev"]
             for name in ("source_root", "capture_parent")),
         "backup_requires_filesystem_distinct_from_source_and_capture")
    need(archive_dev != values["key_parent"]["identity"]["dev"],
         "recovery_key_requires_independent_filesystem")
    return values


def write_owned_workflow_receipt(owners, name, value):
    candidates = [row for row in owners if row["phase"] == "capture"]
    if not candidates:
        return False
    row = candidates[0]
    path = directory(row["path"])
    need(identity(path.lstat())[:5] == row["identity"], "owned_output_directory_replaced")
    private_new(path / name, encoded(value))
    return True


def run_workflow(plan, *, start=None, fixture=False, arm=None):
    """One attempt, one original total deadline; no resume/retry entry point."""
    validate_workflow(plan, fixture=fixture)
    start = time.monotonic() if start is None else start
    overall_end = start + plan["overall_budget_seconds"]
    work_end = overall_end - 60
    phases, owners, locations = [], [], {}
    active = "admission"
    report = public_result("current-source-recovery-workflow", {})
    report.update(schema="heptabao.mac-current-sqlite-recovery-workflow.public.v1",
                  budget_origin="new_workflow_definition_not_previous_whole_capture_budget",
                  total_runtime_cap_seconds=plan["overall_budget_seconds"],
                  controller_work_cap_seconds=plan["overall_budget_seconds"] - 60,
                  cleanup_and_receipt_reserve_seconds=60,
                  automatic_retry=False, resume_after_failed_phase_supported=False,
                  phases=phases,
                  durable_completion_authority="separate_original_runtime_terminal",
                  source_capture_or_service_cutover_qualified=False)
    def phase(name, phase_plan, function):
        nonlocal active
        active = name
        begin = time.monotonic()
        end = min(work_end, begin + phase_plan["budget_seconds"])
        check(end)
        if arm is not None:
            arm(end)
        for item in locations.values():
            verify_directory_binding(item)
        output, result = function(phase_plan, end, owners)
        for item in locations.values():
            verify_directory_binding(item)
        check(end)
        check(work_end)
        phases.append({"phase": name, "status": "passed",
                       "phase_cap_seconds": phase_plan["budget_seconds"],
                       "elapsed_seconds": time.monotonic() - begin,
                       "completion_observed_within_original_phase_and_total_deadlines": True})
        return output, result
    try:
        check(work_end)
        # A missing encryption dependency must reject admission before reading
        # any source configuration or creating plaintext database copies.
        from cryptography.fernet import Fernet
        need(callable(Fernet.generate_key), "encryption_dependency_unavailable")
        locations = workflow_location_admission(plan)
        capture_root, captured = phase("capture", plan["capture"], capture)
        private_new(capture_root / "workflow.plan.private.json", encoded(plan))
        private_new(capture_root / "workflow-locations.private.json", encoded(locations))
        capture_raw = read_private(capture_root / "capture.private.json", MAX_META, work_end)
        capture_sha = digest(capture_raw)
        archive_plan = {"schema": SCHEMA, "phase": "backup",
                        "capture_root": str(capture_root), "capture_sha256": capture_sha,
                        **plan["backup"]}
        validate_plan(archive_plan, fixture=fixture)
        archive, _ = phase("backup", archive_plan, backup)
        restore_plan = {"schema": SCHEMA, "phase": "restore-verify",
                        "archive_root": str(archive),
                        "key_file": str(Path(archive_plan["key_parent"])
                                        / archive_plan["key_name"] / "recovery.key"),
                        "capture_sha256": capture_sha, **plan["restore"]}
        validate_plan(restore_plan, fixture=fixture)
        _restored, recovery = phase("restore-verify", restore_plan, restore_verify)
        check(work_end)
        report["counts"] = {
            "configured_agents": captured["configured_agent_count"],
            "captured_database_entries": len(captured["database_rows"]),
            "logical_snapshot_bytes": captured["logical_snapshot_bytes"],
            "recovery": recovery["counts"],
        }
        report["elapsed_observation_before_receipt_publication_seconds"] = time.monotonic() - start
        write_owned_workflow_receipt(owners, "workflow-result.public.json", report)
        check(overall_end)
        return report
    except BaseException as error:
        report.update(status="failed", error=safe_error(error), failed_phase=active,
                      partial_owned_directories_retained=True,
                      elapsed_observation_before_receipt_publication_seconds=time.monotonic() - start)
        try:
            if arm is not None:
                # Failure never starts another phase. The original total
                # deadline remains the cleanup ceiling, without a fresh budget.
                arm(overall_end)
            write_owned_workflow_receipt(owners, "workflow-failure.public.json", report)
        except BaseException as receipt_error:
            report["failure_receipt_publication_error"] = safe_error(receipt_error)
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        plan = json.loads(read_private(args.plan, 65536, ENTRY + MAX_WORKFLOW_SECONDS),
                          object_pairs_hook=unique)
        validate_workflow(plan)
        work_end = ENTRY + plan["overall_budget_seconds"] - 60
        check(work_end)
        if args.validate_only:
            print(json.dumps({"schema": WORKFLOW_SCHEMA, "status": "plan_shape_validated",
                              "source_payloads_opened": False,
                              "product_or_sdk_executed": False,
                              "production_qualification": False}, sort_keys=True))
            return 0
        need(signal.getsignal(signal.SIGALRM) == signal.SIG_DFL
             and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
             "caller_timer_must_be_unowned")
    except BaseException as error:
        print(json.dumps(public_result("admission", {}, error=safe_error(error)), sort_keys=True))
        return 1
    previous = {number: signal.getsignal(number) for number in
                (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)}
    def interrupted(_number, _frame):
        raise Refused("interrupted_original_workflow")
    def arm(end):
        remaining = end - time.monotonic()
        need(remaining > 0, "original_total_deadline_not_extended")
        signal.setitimer(signal.ITIMER_REAL, remaining)
    for number in previous:
        signal.signal(number, interrupted)
    try:
        arm(work_end)
        result = run_workflow(plan, start=ENTRY, arm=arm)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "passed" else 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
