#!/usr/bin/env python3
"""Scoped real OpenBao 2.6.2 -> HeptaBao Identity recreation rehearsal.

The fixture recreates only entities and internal groups. Source authentication
aliases are deliberately introduced only after the positive rehearsal and must
make the adapter fail closed; they are never copied to the target.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile

from bao_http import BaoError, Client, SafeArgumentParser, private_write
import migrate_identity as migration
from official_openbao_launcher import BINARY_SHA256, file_digest, start_oracle, stop_oracle

ROOT = Path(__file__).resolve().parents[2]


def tool(arguments, expected_code=0):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = migration.main(arguments)
    result = json.loads(output.getvalue())
    if code != expected_code:
        raise BaoError("identity_live_cli_" + result.get("reason", "failed"))
    return result


class LoseOneEntityAcknowledgement:
    """Discard one successful real HTTPS entity-create response after commit."""

    def __init__(self, client):
        self.client = client
        self.namespace = client.namespace
        self.discarded = False

    def request(self, method, path, payload=None):
        response = self.client.request(method, path, payload)
        if (
            not self.discarded
            and method == "POST"
            and path == "/v1/identity/entity"
            and response.status == 200
        ):
            self.discarded = True
            raise BaoError("transport_outcome_unknown")
        return response


def private_text(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(value)


def run(binary, output):
    checks = []

    def check(name, condition):
        if not condition:
            raise BaoError("identity_live_" + name)
        checks.append(name)

    if not all(
        Path(os.environ.get(name, "/missing")).is_file()
        for name in ("HB_ORACLE_BINARY", "HB_ORACLE_ARCHIVE")
    ):
        raise FileNotFoundError("pinned oracle prerequisite missing")

    with tempfile.TemporaryDirectory(prefix="heptabao-identity-migration-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        spec = importlib.util.spec_from_file_location(
            "identity_migration_smoke",
            ROOT / "qa/single-node/smoke.py",
        )
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        oracle = instance = None
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                oracle_port = listener.getsockname()[1]
            oracle = start_oracle(oracle_port)
            source = Client(
                oracle["address"],
                oracle["ca_file"],
                Path(oracle["token_file"]).read_text().strip(),
            )

            instance = smoke.Instance(binary.resolve(), root / "candidate")
            instance.start()
            status, initialized = instance.call(
                "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
            )
            check("candidate_init", status == 200)
            instance.token = initialized["root_token"]
            unseal = initialized["keys_base64"][0]
            check(
                "candidate_unseal",
                instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200,
            )
            target = Client(instance.address, str(instance.root / "ca.crt"), instance.token)

            policy = 'path "secret/data/identity-migration" { capabilities = ["read"] }'
            check(
                "source_policy",
                source.request(
                    "PUT",
                    "/v1/sys/policies/acl/identity-migrate-reader",
                    {"policy": policy},
                ).status
                == 204,
            )
            check(
                "target_policy",
                target.request(
                    "PUT",
                    "/v1/sys/policies/acl/identity-migrate-reader",
                    {"policy": policy},
                ).status
                == 204,
            )

            alice = source.request(
                "POST",
                "/v1/identity/entity",
                {
                    "name": "identity-migrate-alice",
                    "metadata": {"team": "runtime", "generation": "one"},
                    "policies": ["identity-migrate-reader"],
                    "disabled": False,
                },
            )
            bob = source.request(
                "POST",
                "/v1/identity/entity",
                {
                    "name": "identity-migrate-bob",
                    "metadata": {"team": "runtime", "generation": "one"},
                    "policies": [],
                    "disabled": True,
                },
            )
            check("source_entities", alice.status == 200 and bob.status == 200)
            alice_id = alice.data()["id"]
            bob_id = bob.data()["id"]

            child = source.request(
                "POST",
                "/v1/identity/group",
                {
                    "name": "identity-migrate-child",
                    "type": "internal",
                    "metadata": {"tier": "child"},
                    "policies": [],
                    "member_entity_ids": [alice_id, bob_id],
                },
            )
            check("source_child_group", child.status == 200)
            child_id = child.data()["id"]
            parent = source.request(
                "POST",
                "/v1/identity/group",
                {
                    "name": "identity-migrate-parent",
                    "type": "internal",
                    "metadata": {"tier": "parent"},
                    "policies": ["identity-migrate-reader"],
                    "member_group_ids": [child_id],
                },
            )
            check("source_parent_group", parent.status == 200)

            target_token = root / "target.token"
            private_text(target_token, instance.token)
            os.environ.update(
                HB_SOURCE_ADDR=oracle["address"],
                HB_SOURCE_CACERT=oracle["ca_file"],
                HB_SOURCE_TOKEN_FILE=oracle["token_file"],
                HB_TARGET_ADDR=instance.address,
                HB_TARGET_CACERT=str(instance.root / "ca.crt"),
                HB_TARGET_TOKEN_FILE=str(target_token),
            )
            for name in (
                "HB_SOURCE_TOKEN",
                "HB_TARGET_TOKEN",
                "HB_SOURCE_NAMESPACE",
                "HB_TARGET_NAMESPACE",
            ):
                os.environ.pop(name, None)

            dry = tool([])
            check(
                "dry_run_no_target_identity_effect",
                dry["status"] == "dry_run_complete"
                and dry["entities_checked"] == 2
                and dry["groups_checked"] == 2
                and migration.list_ids(target, "entity", allow_empty=True) == []
                and migration.list_ids(target, "group", allow_empty=True) == [],
            )

            # Persist an inflight intent, let the real target commit the create,
            # then discard the successful HTTPS response before checkpoint ack.
            entities, groups, inventory_digest = migration.snapshot_inventory(source)
            source_health, target_health = source.health(), target.health()
            checkpoint_path = root / "identity-checkpoint.json"
            checkpoint = migration.Checkpoint(
                checkpoint_path,
                migration.transfer_binding(
                    source_health,
                    target_health,
                    source.namespace,
                    inventory_digest,
                ),
            )
            lost = LoseOneEntityAcknowledgement(target)
            try:
                migration.transfer_entity(lost, entities[0], checkpoint)
                check("lost_ack_injection_required", False)
            except BaoError as error:
                check(
                    "real_committed_entity_ack_loss_observed",
                    error.code == "transport_outcome_unknown" and lost.discarded,
                )
            check(
                "real_entity_commit_exists_before_checkpoint_ack",
                migration._find_by_name(target, "entity", entities[0]["name"]) is not None,
            )

            apply_args = [
                "--checkpoint",
                str(checkpoint_path),
                "--apply",
                "--source-writes-frozen",
                "--target-exclusive",
            ]
            applied = tool(apply_args)
            check(
                "resume_after_real_ack_loss",
                applied["status"] == "copied_and_verified"
                and applied["objects_copied"] == 4
                and applied["objects_already_verified"] == 0,
            )
            repeated = tool(apply_args)
            check(
                "identity_recreation_idempotent",
                repeated["objects_already_verified"] == 4
                and repeated["objects_copied"] == 0,
            )

            target_alice = migration._find_by_name(
                target, "entity", "identity-migrate-alice"
            )
            target_bob = migration._find_by_name(
                target, "entity", "identity-migrate-bob"
            )
            target_child = migration._find_by_name(
                target, "group", "identity-migrate-child"
            )
            target_parent = migration._find_by_name(
                target, "group", "identity-migrate-parent"
            )
            check(
                "entity_fields_recreated",
                target_alice is not None
                and target_alice.get("metadata")
                == {"team": "runtime", "generation": "one"}
                and target_alice.get("policies") == ["identity-migrate-reader"]
                and target_alice.get("disabled") is False
                and target_bob is not None
                and target_bob.get("disabled") is True,
            )
            target_alice_id = target_alice["id"]
            target_bob_id = target_bob["id"]
            target_child_id = target_child["id"]
            check(
                "group_memberships_rewritten_to_new_target_ids",
                set(target_child.get("member_entity_ids", []))
                == {target_alice_id, target_bob_id}
                and alice_id not in target_child.get("member_entity_ids", [])
                and bob_id not in target_child.get("member_entity_ids", [])
                and target_parent.get("member_group_ids") == [target_child_id]
                and child_id not in target_parent.get("member_group_ids", []),
            )
            check(
                "no_auth_aliases_were_recreated",
                not target_alice.get("aliases")
                and not target_bob.get("aliases"),
            )

            instance.stop()
            instance.start()
            check(
                "restart_unseal",
                instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200,
            )
            after_restart = tool(apply_args)
            check(
                "restart_resume_preserves_identity_mapping",
                after_restart["objects_already_verified"] == 4
                and after_restart["objects_copied"] == 0,
            )
            target = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
            check(
                "restart_readback",
                migration._find_by_name(
                    target, "entity", "identity-migrate-alice"
                ).get("metadata")
                == {"team": "runtime", "generation": "one"},
            )

            # Source aliases bind an auth-mount accessor and must force reauth
            # instead of being copied under a target accessor that merely looks
            # equivalent.
            check(
                "source_userpass_mount",
                source.request(
                    "POST",
                    "/v1/sys/auth/identity-migrate-userpass",
                    {"type": "userpass"},
                ).status
                == 204,
            )
            registry = source.request("GET", "/v1/sys/auth").data()
            accessor = registry["identity-migrate-userpass/"]["accessor"]
            alias = source.request(
                "POST",
                "/v1/identity/entity-alias",
                {
                    "canonical_id": alice_id,
                    "name": "identity-migrate-alice-login",
                    "mount_accessor": accessor,
                },
            )
            check("source_alias_created", alias.status == 200)
            before_entities = migration.list_ids(target, "entity", allow_empty=True)
            try:
                migration.snapshot_inventory(source)
                check("source_alias_must_block_transfer", False)
            except BaoError as error:
                check(
                    "source_alias_requires_reauthentication",
                    error.code == "identity_alias_transfer_requires_reauthentication",
                )
            check(
                "alias_rejection_has_no_target_effect",
                migration.list_ids(target, "entity", allow_empty=True) == before_entities,
            )

            result = {
                "schema": "heptabao.identity-migration-live.v1",
                "status": "passed_scoped_identity_recreation",
                "checks": checks,
                "count": len(checks),
                "candidate_binary_sha256": file_digest(binary),
                "oracle_binary_sha256": BINARY_SHA256,
                "official_openbao_version": source.health()["version"],
                "entities_recreated": 2,
                "internal_groups_recreated": 2,
                "source_ids_reused_on_target": False,
                "aliases_transferred": False,
                "group_aliases_transferred": False,
                "tokens_transferred": False,
                "auth_credentials_transferred": False,
                "full_asset_migration": False,
                "source_cutover": False,
                "cutover_authority": False,
                "rollback_authority": False,
                "independent_qualification": False,
            }
            private_write(output, result, replace=False)
            return result
        finally:
            if instance is not None:
                instance.stop()
            if oracle is not None:
                stop_oracle(oracle)
                shutil.rmtree(oracle["root"], ignore_errors=True)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        raise BaoError("output_already_exists")
    result = run(args.binary.resolve(), args.output.absolute())
    print(
        json.dumps(
            {
                "status": result["status"],
                "count": result["count"],
                "full_asset_migration": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError:
        print(json.dumps({"status": "blocked_prerequisite", "full_asset_migration": False}))
        raise SystemExit(77) from None
    except Exception as error:
        reason = (
            str(error)
            if isinstance(error, BaoError) and str(error).startswith("identity_live_")
            else "identity_migration_live_failed"
        )
        print(json.dumps({"status": "failed", "reason": reason, "full_asset_migration": False}))
        raise SystemExit(2) from None
