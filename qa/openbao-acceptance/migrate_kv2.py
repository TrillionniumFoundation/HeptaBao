#!/usr/bin/env python3
"""Controlled KV-v2 copy with CAS, readback and resumable private checkpoints.

Default is read-only dry-run. This tool never writes to, unseals, fences, switches,
deletes or cuts over the source. It is not an OpenBao storage-format migration.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
from pathlib import Path

from bao_http import (BaoError, Client, MAX_BODY, SafeArgumentParser, canonical, digest, distinct_endpoints, endpoint,
                      key_path, private_json, private_write)

MAX_KEYS = 1000
MAX_VERSIONS = 128
SCHEMA = "heptabao.kv2-readable-history.v1"


class CheckpointLock:
    def __init__(self, filename):
        self.filename, self.fd = str(filename) + ".lock", None

    def __enter__(self):
        try:
            self.fd = os.open(self.filename, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise BaoError("checkpoint_lock_not_private_regular_file")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BaoError):
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise BaoError("checkpoint_locked_or_inaccessible") from None
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)


def expect(response, statuses=(200,)):
    if response.status not in statuses:
        raise BaoError("unexpected_api_status_" + str(response.status))
    return response


def read_keys(filename):
    keys = private_json(filename)
    if (not isinstance(keys, list) or not 0 < len(keys) <= MAX_KEYS
            or any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys)):
        raise BaoError("bounded_unique_key_allowlist_required")
    for key in keys:
        key_path(key)
    return keys


def verify_mount(client, mount):
    key_path(mount)
    value = expect(client.request("GET", "/v1/sys/mounts")).data().get(mount + "/")
    if not isinstance(value, dict) or value.get("type") not in ("kv", "kv-v2"):
        raise BaoError("existing_kv_v2_mount_required")
    if value.get("type") != "kv-v2" and str((value.get("options") or {}).get("version")) != "2":
        raise BaoError("existing_kv_v2_mount_required")


def api(mount, operation, key):
    return "/v1/" + key_path(mount) + "/" + operation + "/" + key_path(key)


def read_metadata(client, mount, key, *, absent_ok=False):
    response = client.request("GET", api(mount, "metadata", key))
    if absent_ok and response.status == 404:
        return None
    return expect(response).data()


def metadata_version(meta):
    value = meta.get("current_version")
    if type(value) is not int or not 0 <= value <= MAX_VERSIONS:
        raise BaoError("unsupported_or_unbounded_version_history")
    return value


def active_history(meta, *, allow_empty=False):
    current = metadata_version(meta)
    versions = meta.get("versions")
    if not isinstance(versions, dict) or (current == 0 and not allow_empty):
        raise BaoError("empty_or_invalid_source_history")
    if set(versions) != {str(n) for n in range(1, current + 1)}:
        raise BaoError("pruned_or_noncontiguous_history_not_supported")
    for state in versions.values():
        if (not isinstance(state, dict) or state.get("destroyed") is not False
                or state.get("deletion_time") not in ("", None)):
            raise BaoError("deleted_destroyed_or_scheduled_versions_not_supported")
    return current


def snapshot(client, mount, key):
    before = read_metadata(client, mount, key)
    current = active_history(before)
    if before.get("delete_version_after", "0s") not in ("0s", "0", ""):
        raise BaoError("automatic_deletion_policy_not_supported")
    custom = before.get("custom_metadata") or {}
    if not isinstance(custom, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in custom.items()):
        raise BaoError("unsupported_custom_metadata_schema")
    maximum = before.get("max_versions", 0)
    if type(maximum) is not int or maximum < 0 or type(before.get("cas_required", False)) is not bool:
        raise BaoError("unsupported_metadata_schema")
    versions = []
    total = 0
    for version in range(1, current + 1):
        response = expect(client.request("GET", api(mount, "data", key) + "?version=" + str(version)))
        data = response.data()
        if not isinstance(data.get("data"), dict) or data.get("metadata", {}).get("version") != version:
            raise BaoError("source_version_readback_mismatch")
        total += len(canonical(data["data"]))
        if total > MAX_BODY:
            raise BaoError("object_history_size_limit")
        versions.append({"version": version, "data": data["data"]})
    after = read_metadata(client, mount, key)
    if before != after:
        raise BaoError("source_changed_during_snapshot")
    return {"key": key, "source_metadata": before, "versions": versions,
            "target_metadata": {"custom_metadata": custom, "cas_required": before.get("cas_required", False),
                                "max_versions": max(current, maximum), "delete_version_after": "0s"}}


def validate_export_record(record):
    if not isinstance(record, dict) or not isinstance(record.get("key"), str):
        raise BaoError("invalid_export_object")
    key_path(record["key"])
    source_meta = record.get("source_metadata")
    if not isinstance(source_meta, dict):
        raise BaoError("invalid_export_metadata")
    current = active_history(source_meta)
    versions = record.get("versions")
    if (not isinstance(versions, list) or len(versions) != current
            or any(not isinstance(v, dict) or v.get("version") != index or not isinstance(v.get("data"), dict)
                   for index, v in enumerate(versions, 1))):
        raise BaoError("invalid_export_versions")
    custom = source_meta.get("custom_metadata") or {}
    maximum = source_meta.get("max_versions", 0)
    if (source_meta.get("delete_version_after", "0s") not in ("0s", "0", "")
            or type(maximum) is not int or maximum < 0
            or type(source_meta.get("cas_required", False)) is not bool
            or not isinstance(custom, dict)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in custom.items())):
        raise BaoError("unsupported_export_metadata")
    expected = {"custom_metadata": custom, "cas_required": source_meta.get("cas_required", False),
                "max_versions": max(current, maximum), "delete_version_after": "0s"}
    if record.get("target_metadata") != expected or len(canonical(record)) > MAX_BODY:
        raise BaoError("export_target_metadata_or_size_mismatch")


def settings_match(meta, settings):
    return all((meta.get(name) or {}) == value if name == "custom_metadata"
               else meta.get(name) == value for name, value in settings.items())


class Checkpoint:
    def __init__(self, filename, binding):
        self.filename = filename
        self.binding = digest(binding)
        if Path(filename).exists() or Path(filename).is_symlink():
            self.state = private_json(filename)
            if (not isinstance(self.state, dict) or self.state.get("schema") != "heptabao.kv2-checkpoint.v1"
                    or self.state.get("binding") != self.binding or not isinstance(self.state.get("objects"), dict)):
                raise BaoError("checkpoint_context_mismatch")
        else:
            self.state = {"schema": "heptabao.kv2-checkpoint.v1", "binding": self.binding, "objects": {}}
            private_write(filename, self.state, replace=False)

    def save(self):
        private_write(self.filename, self.state)


def verify_target(client, mount, record, expected_count):
    meta = read_metadata(client, mount, record["key"])
    if active_history(meta, allow_empty=True) != expected_count:
        raise BaoError("target_history_changed_or_conflicts")
    for index in range(expected_count):
        item = record["versions"][index]
        data = expect(client.request("GET", api(mount, "data", record["key"]) + "?version=" + str(index + 1))).data()
        if data.get("metadata", {}).get("version") != index + 1 or data.get("data") != item["data"]:
            raise BaoError("target_version_readback_mismatch")
    return meta


def transfer_record(target, mount, record, checkpoint):
    """Resume a committed-but-unacknowledged CAS using exact durable readback.

    An in-flight write still absent at readback is NOT retried: absence is not
    proof a timed-out request cannot subsequently commit.
    """
    validate_export_record(record)
    object_id = digest(record["key"])
    source_digest = digest(record)
    entry = checkpoint.state["objects"].get(object_id)
    data_path = api(mount, "data", record["key"])
    metadata_path = api(mount, "metadata", record["key"])
    settings = record["target_metadata"]
    if entry is None:
        if read_metadata(target, mount, record["key"], absent_ok=True) is not None:
            raise BaoError("target_object_exists_without_owned_checkpoint")
        entry = {"source_digest": source_digest, "completed_version": 0, "phase": "initializing_metadata"}
        checkpoint.state["objects"][object_id] = entry
        checkpoint.save()
        expect(target.request("POST", metadata_path, settings), (204,))
        observed = read_metadata(target, mount, record["key"])
        if metadata_version(observed) != 0 or not settings_match(observed, settings):
            raise BaoError("target_metadata_initialization_readback_mismatch")
        entry["phase"] = "copying"
        checkpoint.save()
    else:
        if (not isinstance(entry, dict) or entry.get("source_digest") != source_digest
                or type(entry.get("completed_version")) is not int
                or not 0 <= entry["completed_version"] <= len(record["versions"])
                or entry.get("phase") not in ("initializing_metadata", "copying", "version_inflight", "complete")):
            raise BaoError("checkpoint_object_or_source_changed")
        if ((entry["phase"] == "complete" and entry["completed_version"] != len(record["versions"]))
                or (entry["phase"] == "initializing_metadata" and entry["completed_version"] != 0)
                or (entry["phase"] == "version_inflight" and entry["completed_version"] >= len(record["versions"]))):
            raise BaoError("checkpoint_phase_inconsistent")
        observed = read_metadata(target, mount, record["key"], absent_ok=True)
        if observed is None:
            raise BaoError("ambiguous_pending_write_requires_authoritative_reconciliation")
        if entry["phase"] == "initializing_metadata":
            if metadata_version(observed) != 0 or not settings_match(observed, settings):
                raise BaoError("ambiguous_metadata_initialization")
            entry["phase"] = "copying"
            checkpoint.save()
        elif entry["phase"] == "version_inflight":
            expected = entry["completed_version"] + 1
            if entry.get("inflight_version") != expected:
                raise BaoError("checkpoint_inflight_version_invalid")
            if metadata_version(observed) == entry["completed_version"]:
                raise BaoError("ambiguous_pending_write_requires_authoritative_reconciliation")
            verify_target(target, mount, record, expected)
            entry["completed_version"], entry["phase"] = expected, "copying"
            entry.pop("inflight_version", None)
            checkpoint.save()
        verify_target(target, mount, record, entry["completed_version"])
        if not settings_match(observed, settings):
            raise BaoError("target_metadata_changed")
        if entry["phase"] == "complete":
            return "already_verified"
    for item in record["versions"][entry["completed_version"]:]:
        version = item["version"]
        entry["phase"], entry["inflight_version"] = "version_inflight", version
        checkpoint.save()  # durable intent BEFORE the remote effect
        response = expect(target.request("POST", data_path,
                                         {"data": item["data"], "options": {"cas": version - 1}}))
        if response.data().get("version") != version:
            raise BaoError("target_write_version_mismatch")
        verify_target(target, mount, record, version)
        entry["completed_version"], entry["phase"] = version, "copying"
        entry.pop("inflight_version", None)
        checkpoint.save()
    meta = verify_target(target, mount, record, len(record["versions"]))
    if not settings_match(meta, settings):
        raise BaoError("target_final_metadata_mismatch")
    entry["phase"] = "complete"
    checkpoint.save()
    return "copied_and_verified"


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("transfer", "export", "import"))
    parser.add_argument("--source-prefix", default="HB_SOURCE")
    parser.add_argument("--target-prefix", default="HB_TARGET")
    parser.add_argument("--source-mount", default="secret")
    parser.add_argument("--target-mount", default="secret")
    parser.add_argument("--keys-file", help="0600 JSON array of explicitly selected relative key paths")
    parser.add_argument("--export-file", help="0600 plaintext export, never written without explicit opt-in")
    parser.add_argument("--checkpoint", help="0600 resumable checkpoint in a 0700 directory")
    parser.add_argument("--apply", action="store_true", help="perform destination writes (default dry-run)")
    parser.add_argument("--source-writes-frozen", action="store_true", help="operator attests source writers remain frozen")
    parser.add_argument("--target-exclusive", action="store_true", help="operator attests exclusive control of selected target keys")
    parser.add_argument("--allow-plaintext-export", action="store_true")
    args = parser.parse_args(argv)
    result = {"schema": "heptabao.kv2-transfer-result.v1", "status": "failed", "mode": "apply" if args.apply else "dry_run",
              "action": args.action, "objects_checked": 0, "objects_copied": 0, "objects_already_verified": 0,
              "source_modified": False, "source_cutover": False, "full_format_migration": False,
              "preserves_original_timestamps": False, "preserves_deleted_destroyed_pruned_history": False,
              "scope": "contiguous_readable_active_versions_1_to_n_and_selected_metadata"}
    code = 2
    try:
        source = target = None
        records = None
        if args.action in ("transfer", "export"):
            if not args.keys_file:
                raise BaoError("explicit_private_key_allowlist_required")
            keys = read_keys(args.keys_file)
            source = Client.from_env(args.source_prefix)
            source_health = source.health()
            verify_mount(source, args.source_mount)
            source_identity = {"endpoint": source.address, "namespace": source.namespace, "mount": args.source_mount,
                               "cluster_id": source_health["cluster_id"], "version": source_health["version"]}
        else:
            if not args.export_file:
                raise BaoError("private_export_file_required")
            bundle = private_json(args.export_file)
            if (not isinstance(bundle, dict) or bundle.get("schema") != SCHEMA
                    or bundle.get("source_writes_frozen_attestation") is not True
                    or not isinstance(bundle.get("source_identity"), dict)
                    or not isinstance(bundle.get("objects"), list) or not 0 < len(bundle["objects"]) <= MAX_KEYS):
                raise BaoError("invalid_or_unfrozen_export")
            records, source_identity = bundle["objects"], bundle["source_identity"]
            if (not isinstance(source_identity.get("endpoint"), str)
                    or endpoint(source_identity["endpoint"]) != source_identity["endpoint"]
                    or not isinstance(source_identity.get("cluster_id"), str) or not source_identity["cluster_id"]
                    or not isinstance(source_identity.get("version"), str) or not source_identity["version"]
                    or not isinstance(source_identity.get("namespace"), str)
                    or not isinstance(source_identity.get("mount"), str)):
                raise BaoError("invalid_export_source_identity")
            key_path(source_identity["namespace"], allow_empty=True)
            key_path(source_identity["mount"])
            for record in records:
                validate_export_record(record)
            keys = [r["key"] for r in records]
            if len(set(keys)) != len(keys):
                raise BaoError("duplicate_export_objects")
            result["source_live_revalidated"] = False
        if args.action in ("transfer", "import"):
            target = Client.from_env(args.target_prefix)
            target_health = target.health()
            verify_mount(target, args.target_mount)
            if source:
                distinct_endpoints(source, source_health, target, target_health)
            elif (source_identity.get("endpoint") == target.address
                  or source_identity.get("cluster_id") == target_health["cluster_id"]):
                raise BaoError("source_and_target_must_be_distinct")
            if args.apply and (not args.checkpoint or not args.target_exclusive
                               or (source and not args.source_writes_frozen)):
                raise BaoError("apply_requires_checkpoint_exclusive_target_and_frozen_source")
        elif args.apply and (not args.export_file or not args.allow_plaintext_export or not args.source_writes_frozen):
            raise BaoError("export_requires_private_path_plaintext_opt_in_and_frozen_source")
        binding = {"source_identity": source_identity, "keys_digest": digest(keys), "profile": SCHEMA}
        if target:
            binding["target_identity"] = {"endpoint": target.address, "namespace": target.namespace,
                                          "mount": args.target_mount, "cluster_id": target_health["cluster_id"]}
        checkpoint = lock = None
        exported = []
        try:
            if args.apply and target:
                lock = CheckpointLock(args.checkpoint)
                lock.__enter__()
                checkpoint = Checkpoint(args.checkpoint, binding)
            for index, key in enumerate(keys):
                record = snapshot(source, args.source_mount, key) if source else records[index]
                result["objects_checked"] += 1
                if args.action == "export":
                    if args.apply:
                        exported.append(record)
                        if len(canonical(exported)) > MAX_BODY - 65536:
                            raise BaoError("export_size_limit_use_direct_transfer")
                elif args.apply:
                    outcome = transfer_record(target, args.target_mount, record, checkpoint)
                    result["objects_already_verified" if outcome == "already_verified" else "objects_copied"] += 1
                    if source and read_metadata(source, args.source_mount, key) != record["source_metadata"]:
                        raise BaoError("source_changed_after_copy_target_not_cut_over")
                else:
                    existing = read_metadata(target, args.target_mount, key, absent_ok=True)
                    if existing is not None:
                        # Dry-run cannot certify a resumable target without checking the bound checkpoint.
                        result["target_existing_objects"] = result.get("target_existing_objects", 0) + 1
            if args.action == "export" and args.apply:
                private_write(args.export_file, {"schema": SCHEMA, "source_identity": source_identity,
                              "source_writes_frozen_attestation": True, "objects": exported}, replace=False)
        finally:
            if lock:
                lock.__exit__(None, None, None)
        result["status"] = "copied_and_verified" if args.apply and target else ("exported_private_plaintext" if args.apply else "dry_run_complete")
        result["readback_verified"] = bool(args.apply and target)
        if source and target and args.apply:
            result["source_live_revalidated"] = True
        result["retention_rule"] = "target_max_versions_at_least_copied_history_length_auto_delete_disabled"
        result["next_step"] = "independent_rehearsal_and_explicit_operator_cutover_decision"
        code = 0
    except BaoError as error:
        result["reason"] = error.code
    except (OSError, UnicodeError, TypeError, AttributeError, KeyError, ValueError):
        result["reason"] = "invalid_configuration_export_or_response"
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
