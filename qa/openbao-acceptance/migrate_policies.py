#!/usr/bin/env python3
"""Bounded OpenBao 2.6.2 -> HeptaBao ACL policy transfer with durable resume.

The adapter transfers only explicitly inventoried, user-defined ACL policies in
one namespace. Built-in ``root`` and ``default`` policies are observed but never
copied, no token authority is transferred, and no source mutation or cutover is
performed. Apply mode requires an owner-only checkpoint, an operator source
freeze attestation, and exclusive ownership of the selected target policy names.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
from pathlib import Path

from bao_http import (
    BaoError,
    Client,
    SafeArgumentParser,
    digest,
    distinct_endpoints,
    key_path,
    private_json,
    private_write,
)

SCHEMA = "heptabao.acl-policy-transfer.v1"
CHECKPOINT_SCHEMA = "heptabao.acl-policy-checkpoint.v1"
MAX_POLICIES = 2048
MAX_POLICY_BYTES = 512 * 1024
MAX_TOTAL_POLICY_BYTES = 8 * 1024 * 1024
RESERVED_POLICIES = frozenset(("default", "root"))


def expect(response, statuses=(200,)):
    if response.status not in statuses:
        raise BaoError("unexpected_api_status_" + str(response.status))
    return response


def policy_name(value: str) -> str:
    if not isinstance(value, str) or "/" in value:
        raise BaoError("noncanonical_policy_name")
    encoded = key_path(value)
    if encoded != value:
        raise BaoError("noncanonical_policy_name")
    return value


def list_user_policies(client):
    response = expect(client.request("LIST", "/v1/sys/policies/acl"))
    data = response.data()
    keys, policies = data.get("keys"), data.get("policies")
    if keys is None:
        keys = policies
    if policies is not None and keys != policies:
        raise BaoError("policy_inventory_alias_mismatch")
    if not isinstance(keys, list) or len(keys) > MAX_POLICIES + len(RESERVED_POLICIES):
        raise BaoError("invalid_or_unbounded_policy_inventory")
    if any(not isinstance(name, str) for name in keys) or len(keys) != len(set(keys)):
        raise BaoError("invalid_or_duplicate_policy_inventory")
    names, reserved = [], []
    for name in keys:
        policy_name(name)
        (reserved if name in RESERVED_POLICIES else names).append(name)
    names.sort()
    reserved.sort()
    if len(names) > MAX_POLICIES:
        raise BaoError("policy_inventory_limit")
    return names, reserved


def read_policy(client, name: str, *, absent_ok=False):
    policy_name(name)
    response = client.request("GET", "/v1/sys/policies/acl/" + name)
    if absent_ok and response.status == 404:
        return None
    data = expect(response).data()
    if data.get("name") not in (None, name):
        raise BaoError("policy_readback_name_mismatch")
    rules = data.get("rules")
    source = data.get("policy")
    if source is None:
        source = rules
    if rules is not None and source != rules:
        raise BaoError("policy_readback_alias_mismatch")
    if not isinstance(source, str) or not source or len(source.encode("utf-8")) > MAX_POLICY_BYTES:
        raise BaoError("invalid_or_unbounded_policy_source")
    return source


def snapshot_inventory(client):
    before_names, before_reserved = list_user_policies(client)
    records = []
    total = 0
    for name in before_names:
        source = read_policy(client, name)
        total += len(source.encode("utf-8"))
        if total > MAX_TOTAL_POLICY_BYTES:
            raise BaoError("policy_inventory_size_limit")
        records.append({"name": name, "source": source, "source_digest": digest(source)})
    after_names, after_reserved = list_user_policies(client)
    if before_names != after_names or before_reserved != after_reserved:
        raise BaoError("source_policy_inventory_changed_during_snapshot")
    for record in records:
        if read_policy(client, record["name"]) != record["source"]:
            raise BaoError("source_policy_changed_during_snapshot")
    manifest = {
        "namespace": client.namespace,
        "objects": [{"name": row["name"], "source_digest": row["source_digest"]} for row in records],
    }
    return records, digest(manifest), before_reserved


def validate_record(record):
    if not isinstance(record, dict) or set(record) != {"name", "source", "source_digest"}:
        raise BaoError("invalid_policy_record")
    name = policy_name(record["name"])
    if name in RESERVED_POLICIES:
        raise BaoError("reserved_policy_transfer_forbidden")
    source = record["source"]
    if not isinstance(source, str) or not source or len(source.encode("utf-8")) > MAX_POLICY_BYTES:
        raise BaoError("invalid_or_unbounded_policy_source")
    if record["source_digest"] != digest(source):
        raise BaoError("policy_record_digest_mismatch")


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
            self.fd = None


class Checkpoint:
    def __init__(self, filename, binding):
        self.filename = Path(filename)
        self.binding = digest(binding)
        if self.filename.exists() or self.filename.is_symlink():
            self.state = private_json(self.filename)
            if (
                not isinstance(self.state, dict)
                or self.state.get("schema") != CHECKPOINT_SCHEMA
                or self.state.get("binding") != self.binding
                or not isinstance(self.state.get("objects"), dict)
            ):
                raise BaoError("checkpoint_context_mismatch")
        else:
            self.state = {"schema": CHECKPOINT_SCHEMA, "binding": self.binding, "objects": {}}
            private_write(self.filename, self.state, replace=False)

    def save(self):
        private_write(self.filename, self.state)


def transfer_policy(target, record, checkpoint):
    validate_record(record)
    name, source = record["name"], record["source"]
    object_id = digest(name)
    entry = checkpoint.state["objects"].get(object_id)
    if entry is None:
        if read_policy(target, name, absent_ok=True) is not None:
            raise BaoError("target_policy_exists_without_owned_checkpoint")
        entry = {"source_digest": record["source_digest"], "phase": "write_inflight"}
        checkpoint.state["objects"][object_id] = entry
        checkpoint.save()  # durable intent BEFORE the remote effect
        response = target.request("POST", "/v1/sys/policies/acl/" + name, {"policy": source})
        expect(response, (204,))
        observed = read_policy(target, name)
        if observed != source:
            raise BaoError("target_policy_readback_mismatch")
        entry["phase"] = "complete"
        checkpoint.save()
        return "copied_and_verified"

    if (
        not isinstance(entry, dict)
        or entry.get("source_digest") != record["source_digest"]
        or entry.get("phase") not in ("write_inflight", "complete")
        or set(entry) != {"source_digest", "phase"}
    ):
        raise BaoError("checkpoint_object_or_source_changed")
    observed = read_policy(target, name, absent_ok=True)
    if entry["phase"] == "write_inflight":
        if observed is None:
            raise BaoError("ambiguous_pending_write_requires_authoritative_reconciliation")
        if observed != source:
            raise BaoError("target_policy_conflicts_with_pending_write")
        entry["phase"] = "complete"
        checkpoint.save()
        return "copied_and_verified"
    if observed != source:
        raise BaoError("target_policy_changed_after_checkpoint")
    return "already_verified"


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--source-prefix", default="HB_SOURCE")
    parser.add_argument("--target-prefix", default="HB_TARGET")
    parser.add_argument("--checkpoint", help="0600 resumable checkpoint in an owner-only directory")
    parser.add_argument("--apply", action="store_true", help="perform target writes (default dry-run)")
    parser.add_argument(
        "--source-writes-frozen",
        action="store_true",
        help="operator attests ACL policy writers remain frozen during the transfer",
    )
    parser.add_argument(
        "--target-exclusive",
        action="store_true",
        help="operator attests exclusive control of selected target policy names",
    )
    args = parser.parse_args(argv)
    result = {
        "schema": SCHEMA,
        "status": "failed",
        "mode": "apply" if args.apply else "dry_run",
        "objects_checked": 0,
        "objects_copied": 0,
        "objects_already_verified": 0,
        "target_existing_objects": 0,
        "source_modified": False,
        "source_cutover": False,
        "root_authority_transferred": False,
        "default_policy_transferred": False,
        "full_asset_migration": False,
        "cutover_authority": False,
        "rollback_authority": False,
        "scope": "single_namespace_user_defined_acl_policy_source_and_exact_readback",
    }
    lock = None
    code = 2
    try:
        source = Client.from_env(args.source_prefix)
        target = Client.from_env(args.target_prefix)
        source_health, target_health = source.health(), target.health()
        if source_health["version"] != "2.6.2":
            raise BaoError("openbao_2_6_2_source_required")
        distinct_endpoints(source, source_health, target, target_health)
        if source.namespace != target.namespace:
            raise BaoError("namespace_remapping_not_supported")
        if args.apply and (not args.checkpoint or not args.source_writes_frozen or not args.target_exclusive):
            raise BaoError("apply_requires_checkpoint_exclusive_target_and_frozen_source")

        records, inventory_digest, reserved = snapshot_inventory(source)
        result["reserved_policies_observed"] = reserved
        result["inventory_digest"] = inventory_digest
        result["objects_checked"] = len(records)
        binding = {
            "profile": SCHEMA,
            "source_identity": {
                "cluster_id": source_health["cluster_id"],
                "version": source_health["version"],
                "namespace": source.namespace,
            },
            "target_identity": {
                "cluster_id": target_health["cluster_id"],
                "version": target_health["version"],
                "namespace": target.namespace,
            },
            "inventory_digest": inventory_digest,
        }

        checkpoint = None
        if args.apply:
            lock = CheckpointLock(args.checkpoint)
            lock.__enter__()
            checkpoint = Checkpoint(args.checkpoint, binding)

        for record in records:
            if args.apply:
                outcome = transfer_policy(target, record, checkpoint)
                if outcome == "already_verified":
                    result["objects_already_verified"] += 1
                else:
                    result["objects_copied"] += 1
                if read_policy(source, record["name"]) != record["source"]:
                    raise BaoError("source_policy_changed_after_copy_target_not_cut_over")
            elif read_policy(target, record["name"], absent_ok=True) is not None:
                result["target_existing_objects"] += 1

        final_names, final_reserved = list_user_policies(source)
        if final_names != [row["name"] for row in records] or final_reserved != reserved:
            raise BaoError("source_policy_inventory_changed_after_transfer")
        result["status"] = "copied_and_verified" if args.apply else "dry_run_complete"
        result["readback_verified"] = bool(args.apply)
        code = 0
    except BaoError as error:
        result["reason"] = error.code
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
