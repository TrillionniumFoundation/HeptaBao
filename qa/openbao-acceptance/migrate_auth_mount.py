#!/usr/bin/env python3
"""Bounded auth-mount recreation without transferring authentication authority.

One explicitly selected OpenBao auth mount is recreated on HeptaBao with only
its method type, description and default/max lease TTL. Accessors, principals,
password verifiers, AppRole secret IDs, OIDC/Kubernetes/LDAP provider secrets,
identity aliases and live tokens are intentionally not transferred.

Apply mode requires a durable checkpoint plus operator attestations that source
writes are frozen and the selected target path is exclusively owned. Remote
create/tune intents are checkpointed before HTTPS effects. A lost response is
resolved only by authoritative target readback and is never blindly retried.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import stat

from bao_http import (
    BaoError,
    Client,
    SafeArgumentParser,
    digest,
    distinct_endpoints,
    private_json,
    private_write,
)

SCHEMA = "heptabao.auth-mount-recreation.v1"
CHECKPOINT_SCHEMA = "heptabao.auth-mount-recreation-checkpoint.v1"
MAX_TTL = 32 * 24 * 3600
MOUNT_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
SUPPORTED_TYPES = {"userpass", "approle", "jwt", "kubernetes", "oidc", "ldap"}
SAFE_TUNE_FIELDS = {
    "default_lease_ttl",
    "description",
    "force_no_cache",
    "max_lease_ttl",
    "token_type",
}


def expect(response, statuses=(200,)):
    if response.status not in statuses:
        raise BaoError("unexpected_api_status_" + str(response.status))
    return response


def mount_path(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 256
        or value == "token"
        or any(MOUNT_SEGMENT.fullmatch(segment) is None for segment in value.split("/"))
    ):
        raise BaoError("invalid_auth_mount_path")
    return value


def _bounded_description(value):
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 512
        or any(not char.isprintable() for char in value)
    ):
        raise BaoError("invalid_auth_mount_description")
    return value


def _ttl(value, label):
    if type(value) is not int or value < 0 or value > MAX_TTL:
        raise BaoError("unsupported_auth_mount_" + label)
    return value


def _default_value(value):
    return value is None or value is False or value == 0 or value == "" or value == [] or value == {}


def read_source_record(client, mount):
    mount = mount_path(mount)
    descriptor_response = client.request("GET", f"/v1/sys/auth/{mount}")
    tune_response = client.request("GET", f"/v1/sys/auth/{mount}/tune")
    descriptor = expect(descriptor_response).data()
    tune = expect(tune_response).data()
    if not isinstance(descriptor, dict) or not isinstance(tune, dict):
        raise BaoError("invalid_auth_mount_source_response")

    kind = descriptor.get("type")
    if kind not in SUPPORTED_TYPES:
        raise BaoError("unsupported_auth_mount_type")
    if descriptor.get("local") not in (None, False) or descriptor.get("seal_wrap") not in (None, False):
        raise BaoError("auth_mount_storage_flags_require_manual_reconciliation")
    options = descriptor.get("options")
    if options not in (None, {}):
        raise BaoError("auth_mount_options_require_manual_reconciliation")

    for key, value in tune.items():
        if key not in SAFE_TUNE_FIELDS and not _default_value(value):
            raise BaoError("auth_mount_tune_requires_manual_reconciliation")

    description = _bounded_description(
        tune.get("description", descriptor.get("description", ""))
    )
    default_ttl = _ttl(tune.get("default_lease_ttl", 0), "default_lease_ttl")
    max_ttl = _ttl(tune.get("max_lease_ttl", 0), "max_lease_ttl")
    if default_ttl > 0 and max_ttl > 0 and default_ttl > max_ttl:
        raise BaoError("invalid_auth_mount_ttl_order")
    if tune.get("force_no_cache") not in (None, False):
        raise BaoError("auth_mount_force_no_cache_not_supported")
    if tune.get("token_type") not in (None, "", "default-service"):
        raise BaoError("auth_mount_token_type_requires_manual_reconciliation")

    return {
        "mount": mount,
        "type": kind,
        "description": description,
        "default_lease_ttl": default_ttl,
        "max_lease_ttl": max_ttl,
    }


def read_target_descriptor(client, mount, *, absent_ok=False):
    response = client.request("GET", f"/v1/sys/auth/{mount}")
    if absent_ok and response.status == 404:
        return None
    return expect(response).data()


def read_target_tune(client, mount, *, absent_ok=False):
    response = client.request("GET", f"/v1/sys/auth/{mount}/tune")
    if absent_ok and response.status == 404:
        return None
    return expect(response).data()


def verify_target_descriptor(data, record):
    if not isinstance(data, dict):
        raise BaoError("target_auth_mount_missing")
    if data.get("type") != record["type"] or data.get("description") != record["description"]:
        raise BaoError("target_auth_mount_descriptor_mismatch")
    accessor = data.get("accessor")
    if not isinstance(accessor, str) or not accessor:
        raise BaoError("target_auth_mount_accessor_missing")
    revision = data.get("revision")
    if type(revision) is not int or revision < 1:
        raise BaoError("target_auth_mount_revision_invalid")
    return accessor, revision


def verify_target_tune(data, record):
    if not isinstance(data, dict):
        raise BaoError("target_auth_mount_tune_missing")
    observed = {
        "description": data.get("description"),
        "default_lease_ttl": data.get("default_lease_ttl"),
        "max_lease_ttl": data.get("max_lease_ttl"),
    }
    expected = {
        "description": record["description"],
        "default_lease_ttl": record["default_lease_ttl"],
        "max_lease_ttl": record["max_lease_ttl"],
    }
    if observed != expected:
        raise BaoError("target_auth_mount_tune_mismatch")
    revision = data.get("revision")
    if type(revision) is not int or revision < 1:
        raise BaoError("target_auth_mount_tune_revision_invalid")
    return revision


class CheckpointLock:
    def __init__(self, filename):
        self.filename = str(filename) + ".lock"
        self.fd = None

    def __enter__(self):
        try:
            self.fd = os.open(
                self.filename,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
            info = os.fstat(self.fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
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
                or not isinstance(self.state.get("transfer"), dict)
            ):
                raise BaoError("checkpoint_context_mismatch")
        else:
            self.state = {
                "schema": CHECKPOINT_SCHEMA,
                "binding": self.binding,
                "transfer": {},
            }
            private_write(self.filename, self.state, replace=False)

    def save(self):
        private_write(self.filename, self.state)


def transfer_binding(source_health, target_health, namespace, record):
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
        "record_digest": digest(record),
    }


def transfer(target, record, checkpoint):
    state = checkpoint.state["transfer"]
    record_digest = digest(record)
    if state and state.get("record_digest") != record_digest:
        raise BaoError("checkpoint_auth_mount_or_source_changed")

    if not state:
        if read_target_descriptor(target, record["mount"], absent_ok=True) is not None:
            raise BaoError("target_auth_mount_exists_without_owned_checkpoint")
        state.update(
            {
                "record_digest": record_digest,
                "phase": "create_inflight",
            }
        )
        checkpoint.save()
        response = target.request(
            "POST",
            f"/v1/sys/auth/{record['mount']}",
            {
                "type": record["type"],
                "description": record["description"],
                "cas_revision": 0,
            },
        )
        expect(response, (200, 204))
        descriptor = read_target_descriptor(target, record["mount"])
        accessor, revision = verify_target_descriptor(descriptor, record)
        state.update(
            {
                "phase": "created",
                "target_accessor_digest": digest(accessor),
                "revision": revision,
            }
        )
        checkpoint.save()

    if state.get("phase") == "create_inflight":
        descriptor = read_target_descriptor(target, record["mount"], absent_ok=True)
        if descriptor is None:
            raise BaoError(
                "ambiguous_pending_auth_mount_create_requires_authoritative_reconciliation"
            )
        accessor, revision = verify_target_descriptor(descriptor, record)
        state.update(
            {
                "phase": "created",
                "target_accessor_digest": digest(accessor),
                "revision": revision,
            }
        )
        checkpoint.save()

    if state.get("phase") == "created":
        descriptor = read_target_descriptor(target, record["mount"])
        accessor, revision = verify_target_descriptor(descriptor, record)
        if digest(accessor) != state.get("target_accessor_digest"):
            raise BaoError("target_auth_mount_incarnation_changed")
        state.update({"phase": "tune_inflight", "revision": revision})
        checkpoint.save()
        response = target.request(
            "POST",
            f"/v1/sys/auth/{record['mount']}/tune",
            {
                "description": record["description"],
                "default_lease_ttl": record["default_lease_ttl"],
                "max_lease_ttl": record["max_lease_ttl"],
                "cas_revision": revision,
            },
        )
        expect(response, (200, 204))
        tune_revision = verify_target_tune(
            read_target_tune(target, record["mount"]),
            record,
        )
        state.update({"phase": "complete", "revision": tune_revision})
        checkpoint.save()
        return "copied_and_verified"

    if state.get("phase") == "tune_inflight":
        tune = read_target_tune(target, record["mount"], absent_ok=True)
        if tune is None:
            raise BaoError("target_auth_mount_disappeared_during_tune")
        tune_revision = verify_target_tune(tune, record)
        descriptor = read_target_descriptor(target, record["mount"])
        accessor, _ = verify_target_descriptor(descriptor, record)
        if digest(accessor) != state.get("target_accessor_digest"):
            raise BaoError("target_auth_mount_incarnation_changed")
        state.update({"phase": "complete", "revision": tune_revision})
        checkpoint.save()
        return "copied_and_verified"

    if state.get("phase") == "complete":
        descriptor = read_target_descriptor(target, record["mount"])
        accessor, _ = verify_target_descriptor(descriptor, record)
        if digest(accessor) != state.get("target_accessor_digest"):
            raise BaoError("target_auth_mount_incarnation_changed")
        verify_target_tune(read_target_tune(target, record["mount"]), record)
        return "already_verified"

    raise BaoError("invalid_auth_mount_checkpoint_phase")


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--source-prefix", default="HB_SOURCE")
    parser.add_argument("--target-prefix", default="HB_TARGET")
    parser.add_argument("--mount", required=True)
    parser.add_argument("--checkpoint")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--source-writes-frozen", action="store_true")
    parser.add_argument("--target-exclusive", action="store_true")
    args = parser.parse_args(argv)
    result = {
        "schema": SCHEMA,
        "status": "failed",
        "mode": "apply" if args.apply else "dry_run",
        "mount": args.mount,
        "source_modified": False,
        "accessor_transferred": False,
        "principals_transferred": False,
        "password_verifiers_transferred": False,
        "approle_secret_ids_transferred": False,
        "provider_secrets_transferred": False,
        "tokens_transferred": False,
        "identity_alias_bindings_transferred": False,
        "consumer_reauthentication_required": True,
        "full_asset_migration": False,
        "source_cutover": False,
        "cutover_authority": False,
        "rollback_authority": False,
        "independent_qualification": False,
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
            not args.checkpoint
            or not args.source_writes_frozen
            or not args.target_exclusive
        ):
            raise BaoError(
                "apply_requires_checkpoint_exclusive_target_and_frozen_source"
            )

        record = read_source_record(source, args.mount)
        result["record_digest"] = digest(record)
        result["auth_type"] = record["type"]
        result["default_lease_ttl"] = record["default_lease_ttl"]
        result["max_lease_ttl"] = record["max_lease_ttl"]
        if not args.apply:
            result["target_conflict"] = (
                read_target_descriptor(target, record["mount"], absent_ok=True)
                is not None
            )
            result["status"] = "dry_run_complete"
            code = 0
        else:
            lock = CheckpointLock(args.checkpoint)
            lock.__enter__()
            checkpoint = Checkpoint(
                args.checkpoint,
                transfer_binding(
                    source_health,
                    target_health,
                    source.namespace,
                    record,
                ),
            )
            outcome = transfer(target, record, checkpoint)
            after = read_source_record(source, args.mount)
            if after != record:
                raise BaoError("source_auth_mount_changed_after_recreation")
            result["outcome"] = outcome
            result["target_readback_verified"] = True
            result["status"] = "recreated_configuration_reauthentication_required"
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
