#!/usr/bin/env python3
"""Real OpenBao 2.6.2 -> HeptaBao auth-mount recreation rehearsal.

The rehearsal proves that only bounded mount lifecycle configuration crosses
the boundary. Source AppRole role IDs, secret IDs, live tokens and the source
mount accessor are never admitted by the target. The target must allocate a
new mount incarnation and new consumer credentials before service resumes.
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
import migrate_auth_mount as migration
from official_openbao_launcher import (
    BINARY_SHA256,
    file_digest,
    start_oracle,
    stop_oracle,
)

ROOT = Path(__file__).resolve().parents[2]
MOUNT = "migration-approle"
ROLE = "consumer"


def invoke(arguments, expected_code=0):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = migration.main(arguments)
    result = json.loads(output.getvalue())
    if code != expected_code:
        raise BaoError(
            "auth_mount_migration_cli_" + result.get("reason", "failed")
        )
    return result


class LoseCreateAcknowledgement:
    """Send one real mount create, then discard its successful HTTPS response."""

    def __init__(self, client):
        self.client = client
        self.namespace = client.namespace
        self.discarded = False

    def request(self, method, path, payload=None):
        response = self.client.request(method, path, payload)
        if (
            not self.discarded
            and method == "POST"
            and path == f"/v1/sys/auth/{MOUNT}"
            and response.status in (200, 204)
        ):
            self.discarded = True
            raise BaoError("transport_outcome_unknown")
        return response


def private_text(path, value):
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(fd, "w") as handle:
        handle.write(value)


def role_credentials(client):
    role_id_response = client.request(
        "GET", f"/v1/auth/{MOUNT}/role/{ROLE}/role-id"
    )
    secret_id_response = client.request(
        "POST", f"/v1/auth/{MOUNT}/role/{ROLE}/secret-id", {}
    )
    if role_id_response.status != 200 or secret_id_response.status != 200:
        raise BaoError("auth_mount_migration_role_credentials_unavailable")
    role_id = role_id_response.data().get("role_id")
    secret_id = secret_id_response.data().get("secret_id")
    if (
        not isinstance(role_id, str)
        or not role_id
        or not isinstance(secret_id, str)
        or not secret_id
    ):
        raise BaoError("auth_mount_migration_invalid_role_credentials")
    return role_id, secret_id


def approle_login(client, role_id, secret_id):
    return client.request(
        "POST",
        f"/v1/auth/{MOUNT}/login",
        {"role_id": role_id, "secret_id": secret_id},
    )


def run(binary, output):
    checks = []

    def check(name, condition):
        if not condition:
            raise BaoError("auth_mount_live_" + name)
        checks.append(name)

    if not all(
        Path(os.environ.get(name, "/missing")).is_file()
        for name in ("HB_ORACLE_BINARY", "HB_ORACLE_ARCHIVE")
    ):
        raise FileNotFoundError("pinned oracle prerequisite missing")

    spec = importlib.util.spec_from_file_location(
        "auth_mount_migration_smoke",
        ROOT / "qa/single-node/smoke.py",
    )
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)

    with tempfile.TemporaryDirectory(
        prefix="heptabao-auth-mount-migration-"
    ) as temporary:
        root = Path(temporary)
        root.chmod(0o700)
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
                "POST",
                "sys/init",
                {"secret_shares": 1, "secret_threshold": 1},
            )
            check("candidate_init", status == 200)
            instance.token = initialized["root_token"]
            unseal_key = initialized["keys_base64"][0]
            check(
                "candidate_unseal",
                instance.call(
                    "POST", "sys/unseal", {"key": unseal_key}
                )[0]
                == 200,
            )
            target = Client(
                instance.address,
                str(instance.root / "ca.crt"),
                instance.token,
            )

            check(
                "source_mount_created",
                source.request(
                    "POST",
                    f"/v1/sys/auth/{MOUNT}",
                    {
                        "type": "approle",
                        "description": "migration AppRole boundary",
                    },
                ).status
                == 204,
            )
            check(
                "source_mount_tuned",
                source.request(
                    "POST",
                    f"/v1/sys/auth/{MOUNT}/tune",
                    {
                        "description": "migration AppRole boundary",
                        "default_lease_ttl": 120,
                        "max_lease_ttl": 300,
                        "user_lockout_config": {
                            "lockout_disable": True,
                        },
                    },
                ).status
                == 204,
            )
            source_descriptor = source.request(
                "GET", f"/v1/sys/auth/{MOUNT}"
            ).data()
            source_accessor = source_descriptor.get("accessor")
            check(
                "source_accessor_present",
                isinstance(source_accessor, str) and bool(source_accessor),
            )
            source_tune = source.request(
                "GET", f"/v1/sys/auth/{MOUNT}/tune"
            ).data()
            check(
                "source_ttl_semantics",
                source_tune.get("default_lease_ttl") == 120
                and source_tune.get("max_lease_ttl") == 300,
            )
            source_lockout = source_tune.get("user_lockout_config")
            check(
                "source_user_lockout_explicitly_disabled",
                isinstance(source_lockout, dict)
                and source_lockout.get("lockout_disable") is True,
            )

            check(
                "source_consumer_role_created",
                source.request(
                    "POST",
                    f"/v1/auth/{MOUNT}/role/{ROLE}",
                    {
                        "bind_secret_id": True,
                        "token_policies": ["default"],
                        "secret_id_num_uses": 0,
                    },
                ).status
                == 204,
            )
            source_role_id, source_secret_id = role_credentials(source)
            source_login = approle_login(
                source, source_role_id, source_secret_id
            )
            source_token = source_login.body.get("auth", {}).get(
                "client_token"
            )
            check(
                "source_credentials_work_before_recreation",
                source_login.status == 200
                and source_login.body.get("auth", {}).get(
                    "lease_duration"
                )
                == 120
                and isinstance(source_token, str)
                and bool(source_token),
            )

            target_token_file = root / "target.token"
            private_text(target_token_file, instance.token)
            os.environ.update(
                HB_SOURCE_ADDR=oracle["address"],
                HB_SOURCE_CACERT=oracle["ca_file"],
                HB_SOURCE_TOKEN_FILE=oracle["token_file"],
                HB_TARGET_ADDR=instance.address,
                HB_TARGET_CACERT=str(instance.root / "ca.crt"),
                HB_TARGET_TOKEN_FILE=str(target_token_file),
            )
            for name in (
                "HB_SOURCE_TOKEN",
                "HB_TARGET_TOKEN",
                "HB_SOURCE_NAMESPACE",
                "HB_TARGET_NAMESPACE",
            ):
                os.environ.pop(name, None)

            dry = invoke(["--mount", MOUNT])
            check(
                "dry_run_has_no_target_effect",
                dry["status"] == "dry_run_complete"
                and dry["target_conflict"] is False
                and target.request(
                    "GET", f"/v1/sys/auth/{MOUNT}"
                ).status
                == 404,
            )

            record = migration.read_source_record(source, MOUNT)
            checkpoint_path = root / "auth-mount-checkpoint.json"
            checkpoint = migration.Checkpoint(
                checkpoint_path,
                migration.transfer_binding(
                    source.health(),
                    target.health(),
                    source.namespace,
                    record,
                ),
            )
            lost = LoseCreateAcknowledgement(target)
            try:
                migration.transfer(lost, record, checkpoint)
                check("lost_create_ack_injection_required", False)
            except BaoError as error:
                check(
                    "real_committed_mount_create_ack_loss_observed",
                    error.code == "transport_outcome_unknown"
                    and lost.discarded,
                )
            committed = target.request(
                "GET", f"/v1/sys/auth/{MOUNT}"
            )
            check(
                "mount_exists_before_checkpoint_ack",
                committed.status == 200
                and committed.data().get("type") == "approle",
            )

            apply_args = [
                "--mount",
                MOUNT,
                "--checkpoint",
                str(checkpoint_path),
                "--apply",
                "--source-writes-frozen",
                "--target-exclusive",
            ]
            applied = invoke(apply_args)
            check(
                "resume_reconciles_real_lost_ack",
                applied["status"]
                == "recreated_configuration_reauthentication_required"
                and applied["outcome"] == "copied_and_verified"
                and applied["consumer_reauthentication_required"] is True
                and applied["source_user_lockout_disabled_required_when_applicable"] is True,
            )
            repeated = invoke(apply_args)
            check(
                "mount_recreation_is_idempotent",
                repeated["outcome"] == "already_verified",
            )

            target_descriptor = target.request(
                "GET", f"/v1/sys/auth/{MOUNT}"
            ).data()
            target_tune = target.request(
                "GET", f"/v1/sys/auth/{MOUNT}/tune"
            ).data()
            target_accessor = target_descriptor.get("accessor")
            check(
                "target_mount_configuration_matches",
                target_descriptor.get("type") == "approle"
                and target_descriptor.get("description")
                == "migration AppRole boundary"
                and target_tune.get("default_lease_ttl") == 120
                and target_tune.get("max_lease_ttl") == 300,
            )
            check(
                "target_mount_incarnation_is_new",
                isinstance(target_accessor, str)
                and bool(target_accessor)
                and target_accessor != source_accessor,
            )

            anonymous_target = Client(
                instance.address,
                str(instance.root / "ca.crt"),
                "synthetic-anonymous-token",
            )
            check(
                "source_approle_credentials_not_transferred",
                approle_login(
                    anonymous_target,
                    source_role_id,
                    source_secret_id,
                ).status
                >= 400,
            )
            check(
                "source_live_token_not_transferred",
                target.request(
                    "GET",
                    "/v1/auth/token/lookup-self",
                    token=source_token,
                ).status
                == 403,
            )

            check(
                "target_consumer_role_recreated",
                target.request(
                    "POST",
                    f"/v1/auth/{MOUNT}/role/{ROLE}",
                    {
                        "bind_secret_id": True,
                        "token_policies": ["default"],
                        "secret_id_num_uses": 0,
                    },
                ).status
                == 204,
            )
            target_role_id, target_secret_id = role_credentials(target)
            check(
                "target_consumer_credentials_are_new",
                target_role_id != source_role_id
                and target_secret_id != source_secret_id,
            )
            target_login = approle_login(
                anonymous_target,
                target_role_id,
                target_secret_id,
            )
            target_token = target_login.body.get("auth", {}).get(
                "client_token"
            )
            check(
                "consumer_reauth_with_target_credentials_succeeds",
                target_login.status == 200
                and target_login.body.get("auth", {}).get(
                    "lease_duration"
                )
                == 120
                and isinstance(target_token, str)
                and bool(target_token),
            )
            check(
                "source_credentials_still_fail_after_target_role_recreation",
                approle_login(
                    anonymous_target,
                    source_role_id,
                    source_secret_id,
                ).status
                >= 400,
            )

            instance.stop()
            instance.start()
            check(
                "restart_unseal",
                instance.call(
                    "POST", "sys/unseal", {"key": unseal_key}
                )[0]
                == 200,
            )
            target = Client(
                instance.address,
                str(instance.root / "ca.crt"),
                instance.token,
            )
            anonymous_target = Client(
                instance.address,
                str(instance.root / "ca.crt"),
                "synthetic-anonymous-token",
            )
            restarted_tune = target.request(
                "GET", f"/v1/sys/auth/{MOUNT}/tune"
            ).data()
            check(
                "mount_tune_survives_restart",
                restarted_tune.get("default_lease_ttl") == 120
                and restarted_tune.get("max_lease_ttl") == 300,
            )
            check(
                "target_consumer_credentials_survive_restart",
                approle_login(
                    anonymous_target,
                    target_role_id,
                    target_secret_id,
                ).status
                == 200,
            )
            check(
                "source_credentials_remain_invalid_after_restart",
                approle_login(
                    anonymous_target,
                    source_role_id,
                    source_secret_id,
                ).status
                >= 400,
            )
            check(
                "source_token_remains_invalid_after_restart",
                target.request(
                    "GET",
                    "/v1/auth/token/lookup-self",
                    token=source_token,
                ).status
                == 403,
            )

            report = {
                "schema": "heptabao.auth-mount-migration-live.v1",
                "status": "passed_scoped_auth_mount_recreation",
                "checks": checks,
                "count": len(checks),
                "candidate_binary_sha256": file_digest(binary),
                "oracle_binary_sha256": BINARY_SHA256,
                "official_openbao_version": source.health()["version"],
                "auth_type": "approle",
                "mount_configuration_recreated": True,
                "mount_ttl_semantics_recreated": True,
                "lost_create_ack_reconciled": True,
                "target_mount_incarnation_reallocated": True,
                "consumer_reauthentication_required": True,
                "consumer_reauthentication_rehearsed": True,
                "source_user_lockout_explicitly_disabled": True,
                "accessor_transferred": False,
                "principals_transferred": False,
                "approle_secret_ids_transferred": False,
                "tokens_transferred": False,
                "identity_alias_bindings_transferred": False,
                "full_asset_migration": False,
                "source_cutover": False,
                "cutover_authority": False,
                "rollback_authority": False,
                "independent_qualification": False,
            }
            private_write(output, report, replace=False)
            return report
        finally:
            if instance is not None:
                instance.stop()
            if oracle is not None:
                stop_oracle(oracle)
                shutil.rmtree(oracle["root"], ignore_errors=True)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        raise BaoError("output_already_exists")
    report = run(args.binary.resolve(), args.output.absolute())
    print(
        json.dumps(
            {
                "status": report["status"],
                "count": report["count"],
                "consumer_reauthentication_required": True,
                "full_asset_migration": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError:
        print(
            json.dumps(
                {
                    "status": "blocked_prerequisite",
                    "full_asset_migration": False,
                }
            )
        )
        raise SystemExit(77) from None
    except Exception as error:
        reason = (
            error.code
            if isinstance(error, BaoError)
            else "auth_mount_migration_live_failed"
        )
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason": reason,
                    "full_asset_migration": False,
                }
            )
        )
        raise SystemExit(2) from None
