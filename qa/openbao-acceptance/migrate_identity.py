#!/usr/bin/env python3
"""Bounded OpenBao 2.6.2 -> HeptaBao Identity entity/group recreation.

This adapter recreates one namespace's entities and INTERNAL groups while
rewriting source IDs to newly allocated target IDs. It intentionally refuses
entity aliases, external groups, group aliases and merged-entity lineage because
those objects bind source authentication accessors or historical authority.
Tokens, cubbyhole state and authentication credentials are never transferred.

Apply mode requires a durable owner-only checkpoint, an operator source-freeze
attestation and exclusive ownership of the selected target names. Every create
persists an inflight intent before the HTTPS effect. A lost acknowledgement is
resolved only by authoritative target readback; absence is never auto-retried.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from pathlib import Path

from bao_http import (
    BaoError,
    Client,
    SafeArgumentParser,
    digest,
    distinct_endpoints,
    private_json,
    private_write,
)

SCHEMA = "heptabao.identity-recreation.v1"
CHECKPOINT_SCHEMA = "heptabao.identity-recreation-checkpoint.v1"
MAX_ENTITIES = 1024
MAX_GROUPS = 1024
MAX_MEMBERS = 256
MAX_POLICIES = 64
MAX_METADATA = 64
MAX_NAME_BYTES = 128
MAX_METADATA_KEY_BYTES = 128
MAX_METADATA_VALUE_BYTES = 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]*\Z")


def expect(response, statuses=(200,)):
    if response.status not in statuses:
        raise BaoError("unexpected_api_status_" + str(response.status))
    return response


def _name(value, label):
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_NAME_BYTES
        or value.endswith(".")
        or NAME.fullmatch(value) is None
    ):
        raise BaoError("unsupported_" + label + "_name")
    return value


def _source_id(value, label):
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 256
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
    ):
        raise BaoError("invalid_" + label + "_id")
    return value


def _metadata(value):
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_METADATA:
        raise BaoError("unsupported_identity_metadata")
    result = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key.encode("utf-8")) > MAX_METADATA_KEY_BYTES
            or not isinstance(item, str)
            or len(item.encode("utf-8")) > MAX_METADATA_VALUE_BYTES
            or any(not char.isprintable() for char in item)
        ):
            raise BaoError("unsupported_identity_metadata")
        result[key] = item
    return dict(sorted(result.items()))


def _names(value, label, maximum):
    if value is None:
        return []
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or any(not isinstance(item, str) for item in value)
        or len(value) != len(set(value))
    ):
        raise BaoError("invalid_identity_" + label)
    return sorted(_name(item, label.rstrip("s")) for item in value)


def _ids(value, label):
    if value is None:
        return []
    if (
        not isinstance(value, list)
        or len(value) > MAX_MEMBERS
        or any(not isinstance(item, str) for item in value)
        or len(value) != len(set(value))
    ):
        raise BaoError("invalid_identity_" + label)
    return sorted(_source_id(item, label.rstrip("s")) for item in value)


def list_ids(client, kind, *, allow_empty=False):
    if kind not in ("entity", "group"):
        raise BaoError("invalid_identity_kind")
    limit = MAX_ENTITIES if kind == "entity" else MAX_GROUPS
    response = client.request("LIST", f"/v1/identity/{kind}/id")
    if allow_empty and response.status == 404:
        return []
    data = expect(response).data()
    keys = data.get("keys")
    if (
        not isinstance(keys, list)
        or len(keys) > limit
        or any(not isinstance(item, str) for item in keys)
        or len(keys) != len(set(keys))
    ):
        raise BaoError("invalid_or_unbounded_identity_" + kind + "_inventory")
    values = sorted(_source_id(item, kind) for item in keys)
    return values


def read_raw(client, kind, object_id, *, absent_ok=False):
    _source_id(object_id, kind)
    response = client.request("GET", f"/v1/identity/{kind}/id/{object_id}")
    if absent_ok and response.status == 404:
        return None
    return expect(response).data()


def normalize_entity(data):
    if not isinstance(data, dict):
        raise BaoError("invalid_identity_entity")
    aliases = data.get("aliases")
    if aliases not in (None, []):
        raise BaoError("identity_alias_transfer_requires_reauthentication")
    merged = data.get("merged_entity_ids")
    if merged not in (None, []):
        raise BaoError("merged_identity_lineage_requires_explicit_reconciliation")
    disabled = data.get("disabled", False)
    if type(disabled) is not bool:
        raise BaoError("invalid_identity_disabled_state")
    return {
        "source_id": _source_id(data.get("id"), "entity"),
        "name": _name(data.get("name"), "entity"),
        "metadata": _metadata(data.get("metadata")),
        "policies": _names(data.get("policies"), "policies", MAX_POLICIES),
        "disabled": disabled,
    }


def normalize_group(data):
    if not isinstance(data, dict):
        raise BaoError("invalid_identity_group")
    kind = data.get("type")
    if kind != "internal":
        raise BaoError("external_identity_group_requires_reauthentication")
    alias = data.get("alias")
    if alias not in (None, {}):
        raise BaoError("group_alias_transfer_requires_reauthentication")
    return {
        "source_id": _source_id(data.get("id"), "group"),
        "name": _name(data.get("name"), "group"),
        "type": "internal",
        "metadata": _metadata(data.get("metadata")),
        "policies": _names(data.get("policies"), "policies", MAX_POLICIES),
        "member_entity_ids": _ids(data.get("member_entity_ids"), "member_entity_ids"),
        "member_group_ids": _ids(data.get("member_group_ids"), "member_group_ids"),
    }


def snapshot_inventory(client):
    before_entities = list_ids(client, "entity", allow_empty=True)
    before_groups = list_ids(client, "group", allow_empty=True)
    entities = [normalize_entity(read_raw(client, "entity", object_id)) for object_id in before_entities]
    groups = [normalize_group(read_raw(client, "group", object_id)) for object_id in before_groups]
    entity_ids = {row["source_id"] for row in entities}
    group_ids = {row["source_id"] for row in groups}
    if len(entity_ids) != len(entities) or len(group_ids) != len(groups):
        raise BaoError("duplicate_identity_object_id")
    for group in groups:
        if not set(group["member_entity_ids"]).issubset(entity_ids):
            raise BaoError("identity_group_references_unselected_entity")
        if not set(group["member_group_ids"]).issubset(group_ids):
            raise BaoError("identity_group_references_unselected_group")
        if group["source_id"] in group["member_group_ids"]:
            raise BaoError("identity_group_cycle")
    after_entities = list_ids(client, "entity", allow_empty=True)
    after_groups = list_ids(client, "group", allow_empty=True)
    if before_entities != after_entities or before_groups != after_groups:
        raise BaoError("source_identity_inventory_changed_during_snapshot")
    for row in entities:
        if normalize_entity(read_raw(client, "entity", row["source_id"])) != row:
            raise BaoError("source_identity_entity_changed_during_snapshot")
    for row in groups:
        if normalize_group(read_raw(client, "group", row["source_id"])) != row:
            raise BaoError("source_identity_group_changed_during_snapshot")
    manifest = {
        "namespace": client.namespace,
        "entities": [{"id": row["source_id"], "digest": digest(row)} for row in entities],
        "groups": [{"id": row["source_id"], "digest": digest(row)} for row in groups],
    }
    return entities, groups, digest(manifest)


def policy_names(client):
    response = expect(client.request("LIST", "/v1/sys/policies/acl"))
    data = response.data()
    values = data.get("keys")
    if values is None:
        values = data.get("policies")
    if (
        not isinstance(values, list)
        or len(values) > 4096
        or any(not isinstance(value, str) for value in values)
    ):
        raise BaoError("target_policy_inventory_invalid")
    return set(values)


def require_target_policy_dependencies(target, entities, groups):
    required = {
        policy
        for row in [*entities, *groups]
        for policy in row["policies"]
        if policy not in ("default",)
    }
    missing = sorted(required - policy_names(target))
    if missing:
        raise BaoError("target_identity_policy_dependency_missing")


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
                or not isinstance(self.state.get("entities"), dict)
                or not isinstance(self.state.get("groups"), dict)
            ):
                raise BaoError("checkpoint_context_mismatch")
        else:
            self.state = {
                "schema": CHECKPOINT_SCHEMA,
                "binding": self.binding,
                "entities": {},
                "groups": {},
            }
            private_write(self.filename, self.state, replace=False)

    def save(self):
        private_write(self.filename, self.state)


def transfer_binding(source_health, target_health, namespace, inventory_digest):
    return {
        "profile": SCHEMA,
        "source_identity": {
            "cluster_id": source_health["cluster_id"],
            "version": source_health["version"],
            "namespace": namespace,
        },
        "target_identity": {
            "cluster_id": target_health["cluster_id"],
            "version": target_health["version"],
            "namespace": namespace,
        },
        "inventory_digest": inventory_digest,
    }


def _find_by_name(client, kind, name):
    found = []
    for object_id in list_ids(client, kind, allow_empty=True):
        data = read_raw(client, kind, object_id)
        if data.get("name") == name:
            found.append(data)
    if len(found) > 1:
        raise BaoError("duplicate_target_identity_name")
    return found[0] if found else None


def _entity_payload(record):
    return {
        "name": record["name"],
        "metadata": record["metadata"],
        "policies": record["policies"],
        "disabled": record["disabled"],
    }


def _verify_target_entity(data, record):
    if data is None:
        raise BaoError("target_identity_entity_missing")
    observed = normalize_entity(data)
    for field in ("name", "metadata", "policies", "disabled"):
        if observed[field] != record[field]:
            raise BaoError("target_identity_entity_readback_mismatch")
    return observed["source_id"]


def transfer_entity(target, record, checkpoint):
    source_id = record["source_id"]
    object_id = digest(source_id)
    source_digest = digest(record)
    entry = checkpoint.state["entities"].get(object_id)
    if entry is None:
        if _find_by_name(target, "entity", record["name"]) is not None:
            raise BaoError("target_identity_entity_exists_without_owned_checkpoint")
        entry = {
            "source_digest": source_digest,
            "name": record["name"],
            "phase": "create_inflight",
        }
        checkpoint.state["entities"][object_id] = entry
        checkpoint.save()
        response = expect(target.request("POST", "/v1/identity/entity", _entity_payload(record)))
        target_id = response.data().get("id")
        _source_id(target_id, "target_entity")
        observed = read_raw(target, "entity", target_id)
        _verify_target_entity(observed, record)
        entry["target_id"] = target_id
        entry["phase"] = "complete"
        checkpoint.save()
        return "copied_and_verified"

    if (
        not isinstance(entry, dict)
        or entry.get("source_digest") != source_digest
        or entry.get("name") != record["name"]
        or entry.get("phase") not in ("create_inflight", "complete")
    ):
        raise BaoError("checkpoint_identity_entity_or_source_changed")
    if entry["phase"] == "create_inflight":
        observed = _find_by_name(target, "entity", record["name"])
        if observed is None:
            raise BaoError("ambiguous_pending_identity_create_requires_authoritative_reconciliation")
        target_id = _verify_target_entity(observed, record)
        entry["target_id"] = target_id
        entry["phase"] = "complete"
        checkpoint.save()
        return "copied_and_verified"

    target_id = entry.get("target_id")
    _source_id(target_id, "target_entity")
    _verify_target_entity(read_raw(target, "entity", target_id, absent_ok=True), record)
    return "already_verified"


def _group_payload(record, entity_map, group_map):
    try:
        members = [entity_map[source_id] for source_id in record["member_entity_ids"]]
        children = [group_map[source_id] for source_id in record["member_group_ids"]]
    except KeyError:
        raise BaoError("identity_group_dependency_not_transferred") from None
    return {
        "name": record["name"],
        "type": "internal",
        "metadata": record["metadata"],
        "policies": record["policies"],
        "member_entity_ids": members,
        "member_group_ids": children,
    }


def _verify_target_group(data, record, entity_map, group_map):
    if data is None:
        raise BaoError("target_identity_group_missing")
    if data.get("type") != "internal":
        raise BaoError("target_identity_group_readback_mismatch")
    expected = _group_payload(record, entity_map, group_map)
    observed = {
        "name": data.get("name"),
        "type": data.get("type"),
        "metadata": _metadata(data.get("metadata")),
        "policies": _names(data.get("policies"), "policies", MAX_POLICIES),
        "member_entity_ids": sorted(_ids(data.get("member_entity_ids"), "member_entity_ids")),
        "member_group_ids": sorted(_ids(data.get("member_group_ids"), "member_group_ids")),
    }
    expected["member_entity_ids"] = sorted(expected["member_entity_ids"])
    expected["member_group_ids"] = sorted(expected["member_group_ids"])
    if observed != expected:
        raise BaoError("target_identity_group_readback_mismatch")
    return _source_id(data.get("id"), "target_group")


def transfer_group(target, record, checkpoint, entity_map, group_map):
    source_id = record["source_id"]
    object_id = digest(source_id)
    source_digest = digest(record)
    entry = checkpoint.state["groups"].get(object_id)
    if entry is None:
        if _find_by_name(target, "group", record["name"]) is not None:
            raise BaoError("target_identity_group_exists_without_owned_checkpoint")
        entry = {
            "source_digest": source_digest,
            "name": record["name"],
            "phase": "create_inflight",
        }
        checkpoint.state["groups"][object_id] = entry
        checkpoint.save()
        response = expect(
            target.request(
                "POST",
                "/v1/identity/group",
                _group_payload(record, entity_map, group_map),
            )
        )
        target_id = response.data().get("id")
        _source_id(target_id, "target_group")
        _verify_target_group(read_raw(target, "group", target_id), record, entity_map, group_map)
        entry["target_id"] = target_id
        entry["phase"] = "complete"
        checkpoint.save()
        return "copied_and_verified"

    if (
        not isinstance(entry, dict)
        or entry.get("source_digest") != source_digest
        or entry.get("name") != record["name"]
        or entry.get("phase") not in ("create_inflight", "complete")
    ):
        raise BaoError("checkpoint_identity_group_or_source_changed")
    if entry["phase"] == "create_inflight":
        observed = _find_by_name(target, "group", record["name"])
        if observed is None:
            raise BaoError("ambiguous_pending_identity_group_create_requires_authoritative_reconciliation")
        target_id = _verify_target_group(observed, record, entity_map, group_map)
        entry["target_id"] = target_id
        entry["phase"] = "complete"
        checkpoint.save()
        return "copied_and_verified"

    target_id = entry.get("target_id")
    _source_id(target_id, "target_group")
    _verify_target_group(
        read_raw(target, "group", target_id, absent_ok=True),
        record,
        entity_map,
        group_map,
    )
    return "already_verified"


def checkpoint_map(entries, records, label):
    by_digest = {digest(row["source_id"]): row for row in records}
    result = {}
    for object_id, entry in entries.items():
        record = by_digest.get(object_id)
        if record is None:
            raise BaoError("checkpoint_contains_unknown_" + label)
        if not isinstance(entry, dict) or entry.get("phase") not in ("create_inflight", "complete"):
            raise BaoError("invalid_checkpoint_" + label)
        if entry["phase"] == "complete":
            target_id = entry.get("target_id")
            _source_id(target_id, "target_" + label)
            result[record["source_id"]] = target_id
    return result


def order_groups(groups):
    by_id = {row["source_id"]: row for row in groups}
    pending = dict(by_id)
    ordered = []
    resolved = set()
    while pending:
        progressed = False
        for source_id in sorted(list(pending)):
            row = pending[source_id]
            if set(row["member_group_ids"]).issubset(resolved):
                ordered.append(row)
                resolved.add(source_id)
                del pending[source_id]
                progressed = True
        if not progressed:
            raise BaoError("identity_group_cycle_or_unresolved_dependency")
    return ordered


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--source-prefix", default="HB_SOURCE")
    parser.add_argument("--target-prefix", default="HB_TARGET")
    parser.add_argument("--checkpoint", help="0600 resumable checkpoint in an owner-only directory")
    parser.add_argument("--apply", action="store_true", help="perform target writes (default dry-run)")
    parser.add_argument("--source-writes-frozen", action="store_true")
    parser.add_argument("--target-exclusive", action="store_true")
    args = parser.parse_args(argv)
    result = {
        "schema": SCHEMA,
        "status": "failed",
        "mode": "apply" if args.apply else "dry_run",
        "entities_checked": 0,
        "groups_checked": 0,
        "objects_copied": 0,
        "objects_already_verified": 0,
        "source_modified": False,
        "aliases_transferred": False,
        "group_aliases_transferred": False,
        "tokens_transferred": False,
        "auth_credentials_transferred": False,
        "full_asset_migration": False,
        "source_cutover": False,
        "cutover_authority": False,
        "rollback_authority": False,
        "independent_qualification": False,
        "scope": "single_namespace_entities_and_internal_groups_recreated_with_new_target_ids",
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
        if args.apply and (
            not args.checkpoint or not args.source_writes_frozen or not args.target_exclusive
        ):
            raise BaoError("apply_requires_checkpoint_exclusive_target_and_frozen_source")

        entities, groups, inventory_digest = snapshot_inventory(source)
        require_target_policy_dependencies(target, entities, groups)
        result["entities_checked"] = len(entities)
        result["groups_checked"] = len(groups)
        result["inventory_digest"] = inventory_digest
        binding = transfer_binding(
            source_health,
            target_health,
            source.namespace,
            inventory_digest,
        )

        if not args.apply:
            result["target_entity_name_conflicts"] = sum(
                _find_by_name(target, "entity", row["name"]) is not None for row in entities
            )
            result["target_group_name_conflicts"] = sum(
                _find_by_name(target, "group", row["name"]) is not None for row in groups
            )
            result["status"] = "dry_run_complete"
            return_code = 0
        else:
            lock = CheckpointLock(args.checkpoint)
            lock.__enter__()
            checkpoint = Checkpoint(args.checkpoint, binding)
            entity_map = checkpoint_map(checkpoint.state["entities"], entities, "entity")
            group_map = checkpoint_map(checkpoint.state["groups"], groups, "group")

            for record in entities:
                outcome = transfer_entity(target, record, checkpoint)
                target_id = checkpoint.state["entities"][digest(record["source_id"])]["target_id"]
                entity_map[record["source_id"]] = target_id
                result["objects_" + ("already_verified" if outcome == "already_verified" else "copied")] += 1

            for record in order_groups(groups):
                outcome = transfer_group(target, record, checkpoint, entity_map, group_map)
                target_id = checkpoint.state["groups"][digest(record["source_id"])]["target_id"]
                group_map[record["source_id"]] = target_id
                result["objects_" + ("already_verified" if outcome == "already_verified" else "copied")] += 1

            after_entities, after_groups, after_digest = snapshot_inventory(source)
            if (
                after_digest != inventory_digest
                or after_entities != entities
                or after_groups != groups
            ):
                raise BaoError("source_identity_changed_after_copy_target_not_cut_over")
            result["source_to_target_entity_ids"] = {
                digest(source_id): digest(target_id)
                for source_id, target_id in sorted(entity_map.items())
            }
            result["source_to_target_group_ids"] = {
                digest(source_id): digest(target_id)
                for source_id, target_id in sorted(group_map.items())
            }
            result["readback_verified"] = True
            result["status"] = "copied_and_verified"
            return_code = 0
        code = return_code
    except BaoError as error:
        result["reason"] = error.code
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
