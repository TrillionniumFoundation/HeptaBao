#!/usr/bin/env python3
"""Live synthetic OpenBao->HeptaBao rehearsal in one process/network context.

Requires the independently verified Oracle launcher supplied by the operator.
The launcher and binary are executable inputs, not downloaded or generated here.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import secrets
import sys
import time
from unittest.mock import patch
from pathlib import Path

from bao_http import BaoError, Client, SafeArgumentParser, digest, private_read, private_write
import migrate_kv2 as migration


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_text(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)


def run_tool(arguments, expected_code=0):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = migration.main(arguments)
    result = json.loads(output.getvalue())
    if code != expected_code:
        raise BaoError("migration_cli_failed_" + result.get("reason", "unexpected_result"))
    return result


class LoseOneAcknowledgement:
    """Every request reaches real HTTPS; discard one successful data-write result."""
    def __init__(self, client):
        self.client, self.discarded = client, False

    def __getattr__(self, name):
        return getattr(self.client, name)

    def request(self, method, path, payload=None):
        response = self.client.request(method, path, payload)
        if not self.discarded and method == "POST" and "/data/" in path and response.status == 200:
            self.discarded = True
            raise BaoError("transport_outcome_unknown")
        return response


def run(binary, launcher_path, work_dir, oracle_port):
    os.umask(0o077)
    work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    launcher = load_module("external_verified_oracle_launcher", launcher_path)
    smoke = load_module("heptabao_real_instance", Path(__file__).resolve().parents[1] / "single-node/smoke.py")
    oracle = instance = None
    source_mount_created = False
    source_mount = "hbmigrate-" + secrets.token_hex(8)
    cases, results = [], {}
    stage = "initialization"
    report = {"schema": "heptabao.live-migration-rehearsal.v1", "synthetic_only": True,
              "started_at_unix": time.time(),
              "full_format_migration": False, "production_authority": False, "source_cutover": False,
              "candidate_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "tool_source_sha256": hashlib.sha256(Path(migration.__file__).read_bytes()).hexdigest()}
    def check(name, condition):
        if not condition:
            raise BaoError("rehearsal_failed_" + name)
        cases.append(name)
    def mount(client, name):
        migration.expect(client.request("POST", "/v1/sys/mounts/" + name,
                                        {"type": "kv", "options": {"version": "2"}, "description": "synthetic migration rehearsal"}), (204,))
    def restart():
        instance.stop()
        instance.start()
        check("restart_unseal", instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200)
    try:
        oracle = launcher.start_oracle(port=oracle_port)
        instance = smoke.Instance(binary, work_dir / "candidate")
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("candidate_initialized", status == 200)
        instance.token, unseal = initialized["root_token"], initialized["keys_base64"][0]
        private_text(work_dir / "candidate.token", instance.token)
        private_text(work_dir / "candidate-unseal.key", unseal)
        check("candidate_unsealed", instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200)
        os.environ.update(HB_SOURCE_ADDR=oracle["address"], HB_SOURCE_CACERT=oracle["ca_file"],
                          HB_SOURCE_TOKEN_FILE=oracle["token_file"], HB_TARGET_ADDR=instance.address,
                          HB_TARGET_CACERT=str(instance.root / "ca.crt"), HB_TARGET_TOKEN_FILE=str(work_dir / "candidate.token"))
        os.environ.pop("HB_SOURCE_TOKEN", None)
        os.environ.pop("HB_TARGET_TOKEN", None)
        os.environ.pop("HB_SOURCE_NAMESPACE", None)
        os.environ.pop("HB_TARGET_NAMESPACE", None)
        source, target = Client.from_env("HB_SOURCE"), Client.from_env("HB_TARGET")
        source_health, target_health = source.health(), target.health()
        check("real_distinct_source_and_target", source_health["version"] == "2.6.2"
              and source_health["cluster_id"] != target_health["cluster_id"])
        report["source"] = {"version": source_health["version"], "artifact_sha256": oracle["artifact_sha256"],
                            "binary_sha256": oracle["binary_sha256"], "cluster_digest": digest(source_health["cluster_id"]),
                            "tls_verified": True, "mode": "server_not_dev"}
        report["target"] = {"version": target_health["version"], "cluster_digest": digest(target_health["cluster_id"]), "tls_verified": True}
        stage = "source_mount"
        mount(source, source_mount)
        source_mount_created = True
        keys = ["synthetic/history", "synthetic/other"]
        for offset, key in enumerate(keys):
            stage = "source_metadata_fixture"
            migration.expect(source.request("POST", migration.api(source_mount, "metadata", key),
                {"custom_metadata": {"purpose": "synthetic-migration-only"}, "max_versions": 10, "cas_required": True}), (204,))
            for version in range(1, 4 - offset):
                stage = "source_version_fixture"
                value = {"synthetic": secrets.token_hex(16), "generation": version,
                         "typed": {"enabled": version % 2 == 0, "list": [1, "two", {"n": 3}]}}
                migration.expect(source.request("POST", migration.api(source_mount, "data", key),
                                                {"data": value, "options": {"cas": version - 1}}))
        stage = "source_snapshot"
        original = [migration.snapshot(source, source_mount, key) for key in keys]

        # Exercise authority classes that must never be copied. An active source
        # token owns cubbyhole state; a second token is explicitly revoked; and a
        # response-wrapping token is minted from the selected source data. None of
        # these identities may authenticate to the target, before or after cutover.
        stage = "source_nontransferable_authority"
        active_created = source.request("POST", "/v1/auth/token/create",
                                        {"policies": ["default"], "ttl": "1h"})
        check("source_active_token_created", active_created.status == 200)
        source_active_token = active_created.body.get("auth", {}).get("client_token")
        check("source_active_token_is_present", isinstance(source_active_token, str) and bool(source_active_token))
        authority_marker = "source-cubbyhole-" + secrets.token_hex(16)
        check(
            "source_active_token_owns_cubbyhole_state",
            source.request("POST", "/v1/cubbyhole/migration-authority",
                           {"value": authority_marker}, token=source_active_token).status in (200, 204),
        )
        source_cubbyhole = source.request("GET", "/v1/cubbyhole/migration-authority",
                                          token=source_active_token)
        check(
            "source_cubbyhole_readback",
            source_cubbyhole.status == 200
            and source_cubbyhole.body.get("data", {}).get("value") == authority_marker,
        )

        revoked_created = source.request("POST", "/v1/auth/token/create",
                                         {"policies": ["default"], "ttl": "1h"})
        check("source_revoked_token_created", revoked_created.status == 200)
        source_revoked_token = revoked_created.body.get("auth", {}).get("client_token")
        check("source_revoked_token_is_present", isinstance(source_revoked_token, str) and bool(source_revoked_token))
        check(
            "source_token_revoked_before_cutover",
            source.request("POST", "/v1/auth/token/revoke",
                           {"token": source_revoked_token}).status in (200, 204),
        )
        check(
            "source_revoked_token_immediately_denied",
            source.request("GET", "/v1/auth/token/lookup-self",
                           token=source_revoked_token).status >= 400,
        )

        wrapped = source.request(
            "GET",
            migration.api(source_mount, "data", keys[0]) + "?version=1",
            wrap_ttl="600s",
        )
        source_wrap_token = wrapped.body.get("wrap_info", {}).get("token")
        check(
            "source_wrapping_token_created",
            wrapped.status == 200 and isinstance(source_wrap_token, str) and bool(source_wrap_token),
        )
        check(
            "source_active_token_never_admitted_by_target",
            target.request("GET", "/v1/auth/token/lookup-self",
                           token=source_active_token).status >= 400,
        )
        check(
            "source_revoked_token_never_admitted_by_target",
            target.request("GET", "/v1/auth/token/lookup-self",
                           token=source_revoked_token).status >= 400,
        )
        check(
            "source_wrapping_authority_never_admitted_by_target",
            target.request("POST", "/v1/sys/wrapping/unwrap", {},
                           token=source_wrap_token).status >= 400,
        )

        keys_file, checkpoint_file = work_dir / "keys.json", work_dir / "transfer-checkpoint.json"
        private_write(keys_file, keys)
        base = ["transfer", "--source-mount", source_mount, "--keys-file", str(keys_file), "--target-mount", "secret"]
        stage = "transfer_dry_run"
        results["dry_run"] = run_tool(base)
        check("dry_run_no_target_side_effects", not checkpoint_file.exists()
              and all(migration.read_metadata(target, "secret", key, absent_ok=True) is None for key in keys))
        applied = base + ["--checkpoint", str(checkpoint_file), "--apply", "--source-writes-frozen", "--target-exclusive"]
        stage = "transfer_apply"
        results["apply"] = run_tool(applied)
        for record in original:
            metadata = migration.verify_target(target, "secret", record, len(record["versions"]))
            check("history_and_metadata_readback", migration.settings_match(metadata, record["target_metadata"]))
        stage = "transfer_repeat"
        results["repeat"] = run_tool(applied)
        check("repeat_no_new_versions", results["repeat"]["objects_already_verified"] == len(keys))
        restart()
        stage = "transfer_after_sigkill"
        results["after_sigkill"] = run_tool(applied)
        check("target_sigkill_preserves_all_versions", results["after_sigkill"]["objects_already_verified"] == len(keys))
        stage = "checkpoint_ack_loss"
        mount(target, "resumed")
        single_file = work_dir / "single-key.json"
        private_write(single_file, [keys[0]])
        resume_file = work_dir / "resume-checkpoint.json"
        binding = migration.checkpoint_binding(
            migration.source_binding_identity(source, source_health, source_mount),
            [keys[0]],
            migration.selected_inventory_digest(source_mount, [original[0]]),
            migration.target_binding_identity(target, target_health, "resumed"),
        )
        loss = LoseOneAcknowledgement(target)
        cp = migration.Checkpoint(resume_file, binding)
        try:
            migration.transfer_record(loss, "resumed", original[0], cp)
            raise BaoError("acknowledgement_loss_not_injected")
        except BaoError as error:
            if error.code != "transport_outcome_unknown":
                raise
        check("real_commit_before_client_ack_loss", loss.discarded
              and migration.read_metadata(target, "resumed", keys[0])["current_version"] == 1)
        restart()
        resume_args = ["transfer", "--source-mount", source_mount, "--target-mount", "resumed",
                       "--keys-file", str(single_file), "--checkpoint", str(resume_file),
                       "--apply", "--source-writes-frozen", "--target-exclusive"]
        stage = "checkpoint_resume"
        results["resume_after_ack_loss_and_sigkill"] = run_tool(resume_args)
        migration.verify_target(target, "resumed", original[0], 3)
        check("checkpoint_resume_without_duplicate_version", results["resume_after_ack_loss_and_sigkill"]["objects_copied"] == 1)
        results["resumed_repeat"] = run_tool(resume_args)
        check("resumed_copy_idempotent", results["resumed_repeat"]["objects_already_verified"] == 1)
        export_file = work_dir / "synthetic-export.json"
        stage = "plaintext_export"
        results["export"] = run_tool(["export", "--source-mount", source_mount, "--keys-file", str(keys_file),
            "--export-file", str(export_file), "--apply", "--source-writes-frozen", "--allow-plaintext-export"])
        check("explicit_plaintext_export_owner_only", export_file.stat().st_mode & 0o777 == 0o600)
        mount(target, "imported")
        import_args = ["import", "--target-mount", "imported", "--export-file", str(export_file)]
        stage = "offline_import"
        results["import_dry_run"] = run_tool(import_args)
        check("import_dry_run_no_effect", all(migration.read_metadata(target, "imported", key, absent_ok=True) is None for key in keys))
        import_args += ["--apply", "--target-exclusive", "--checkpoint", str(work_dir / "import-checkpoint.json")]
        results["import_apply"] = run_tool(import_args)
        for record in original:
            migration.verify_target(target, "imported", record, len(record["versions"]))
        check("offline_import_exact_history", results["import_apply"]["objects_copied"] == len(keys))
        results["import_repeat"] = run_tool(import_args)
        check("offline_import_idempotent", results["import_repeat"]["objects_already_verified"] == len(keys))
        check("source_selected_objects_unchanged", all(migration.snapshot(source, source_mount, key) == record for key, record in zip(keys, original)))

        # Rehearse deployment-level writer fencing with the real processes. The
        # source is stopped before target service is accepted as the cutover
        # endpoint. Rollback then fences the target process before restarting the
        # exact same OpenBao data root; there is never a live source/target writer
        # overlap in this bounded fixture.
        stage = "cutover_source_fence"
        launcher.stop_oracle(oracle)
        check(
            "cutover_source_process_fenced_before_target_acceptance",
            oracle["process"].poll() is not None,
        )
        try:
            source.request("GET", migration.api(source_mount, "metadata", keys[0]))
            raise BaoError("cutover_source_still_reachable")
        except BaoError as error:
            if error.code == "cutover_source_still_reachable":
                raise
        for record in original:
            migration.verify_target(target, "secret", record, len(record["versions"]))
        check("cutover_target_serves_verified_migrated_history", True)
        check(
            "cutover_target_still_rejects_source_active_token",
            target.request("GET", "/v1/auth/token/lookup-self",
                           token=source_active_token).status >= 400,
        )
        check(
            "cutover_target_still_rejects_source_revoked_token",
            target.request("GET", "/v1/auth/token/lookup-self",
                           token=source_revoked_token).status >= 400,
        )
        check(
            "cutover_target_still_rejects_source_wrapping_token",
            target.request("POST", "/v1/sys/wrapping/unwrap", {},
                           token=source_wrap_token).status >= 400,
        )

        # Now the source process is demonstrably stopped. Admit synthetic new
        # target versions, capture a frozen offline image, and only then stop the
        # target before restarting the original source for append-only readback.
        stage = "post_cutover_target_writes"
        for record in original:
            old_count = len(record["versions"])
            for version in range(old_count + 1, old_count + 3):
                migration.expect(target.request("POST", migration.api("secret", "data", record["key"]),
                    {"data": {"synthetic_post_cutover": secrets.token_hex(16), "generation": version},
                     "options": {"cas": version - 1}}))
        post_cutover = [migration.snapshot(target, "secret", key) for key in keys]
        check("post_cutover_appends_observed_only_with_source_stopped", oracle["process"].poll() is not None)
        reverse_export = work_dir / "synthetic-post-cutover-export.json"
        results["post_cutover_export"] = run_tool([
            "export", "--source-prefix", "HB_TARGET", "--source-mount", "secret",
            "--keys-file", str(keys_file), "--export-file", str(reverse_export),
            "--apply", "--source-writes-frozen", "--allow-plaintext-export"])
        check("post_cutover_export_is_private", reverse_export.stat().st_mode & 0o777 == 0o600)

        stage = "rollback_target_fence"
        instance.stop()
        check("rollback_target_process_fenced_before_source_reactivation", instance.process is None)
        launcher.restart_oracle(oracle)
        source = Client.from_env("HB_SOURCE")
        for key, record in zip(keys, original):
            check(
                "rollback_source_same_root_preserves_original_history",
                migration.snapshot(source, source_mount, key) == record,
            )
        stage = "rollback_append_new_versions"
        rollback_checkpoint = work_dir / "rollback-append-checkpoint.json"
        rollback_args = ["import", "--target-prefix", "HB_SOURCE", "--target-mount", source_mount,
                         "--export-file", str(reverse_export), "--append-verified-prefix"]
        results["rollback_dry_run"] = run_tool(rollback_args)
        check("rollback_prefix_preflight_is_read_only", not rollback_checkpoint.exists()
              and all(migration.snapshot(source, source_mount, key) == record for key, record in zip(keys, original)))
        rollback_apply = rollback_args + ["--apply", "--target-exclusive", "--checkpoint", str(rollback_checkpoint)]
        # Inject response loss only after the actual OpenBao HTTPS append
        # acknowledges success. The production copier/checkpoint code is unchanged.
        reverse_loss = LoseOneAcknowledgement(source)
        with patch.object(migration.Client, "from_env", return_value=reverse_loss):
            results["rollback_lost_ack"] = run_tool(rollback_apply, expected_code=2)
        check("rollback_actual_append_committed_before_lost_ack", reverse_loss.discarded
              and results["rollback_lost_ack"].get("reason") == "transport_outcome_unknown"
              and migration.read_metadata(source, source_mount, keys[0])["current_version"] == len(original[0]["versions"]) + 1)
        launcher.stop_oracle(oracle)
        launcher.restart_oracle(oracle)
        results["rollback_resume_after_source_restart"] = run_tool(rollback_apply)
        for record in post_cutover:
            meta = migration.verify_target(source, source_mount, record, len(record["versions"]))
            check("rollback_preserves_original_prefix_and_post_cutover_versions",
                  migration.settings_match(meta, record["target_metadata"]))
        results["rollback_repeat"] = run_tool(rollback_apply)
        check("rollback_repeat_does_not_duplicate_versions", results["rollback_repeat"]["objects_already_verified"] == len(keys))
        check("rollback_target_remains_stopped_during_source_append", instance.process is None)
        report["post_cutover_kv_appends_repatriated"] = True
        report["post_cutover_new_keys_deletes_or_metadata_changes_covered"] = False
        report["writer_overlap_scope"] = "cutover_and_rollback_activation"

        restored_cubbyhole = source.request(
            "GET", "/v1/cubbyhole/migration-authority", token=source_active_token
        )
        check(
            "rollback_reactivates_source_authority_only_after_target_fence",
            restored_cubbyhole.status == 200
            and restored_cubbyhole.body.get("data", {}).get("value") == authority_marker,
        )
        check(
            "rollback_does_not_resurrect_source_revoked_token",
            source.request("GET", "/v1/auth/token/lookup-self",
                           token=source_revoked_token).status >= 400,
        )
        unwrapped = source.request(
            "POST", "/v1/sys/wrapping/unwrap", {}, token=source_wrap_token
        )
        check(
            "rollback_source_wrapping_authority_restored_only_after_target_fence",
            unwrapped.status == 200 and isinstance(unwrapped.body.get("data"), dict),
        )
        report["source_authority_reactivated_only_after_target_fence"] = True
        report["revoked_source_authority_remained_revoked_after_rollback"] = True
        report["source_ephemeral_authority_never_admitted_by_target"] = True
        report["bounded_process_cutover_rehearsed"] = True
        report["bounded_process_rollback_rehearsed"] = True
        report["writer_overlap_observed"] = False
        report["status"] = "passed_live_scoped_migration"
        report["ack_loss_injection"] = "real_https_write_committed_then_client_discards_response_before_checkpoint_ack"
    except BaoError as error:
        report["status"], report["reason"] = "failed", error.code
        report["failed_stage"] = stage
    except Exception as error:
        report["status"], report["reason"] = "failed", "rehearsal_exception_" + type(error).__name__
    finally:
        if oracle is not None and source_mount_created:
            try:
                cleanup_source = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"]).decode().strip())
                cleanup = cleanup_source.request("DELETE", "/v1/sys/mounts/" + source_mount)
                report["source_synthetic_fixture_cleanup"] = cleanup.status == 204
                if cleanup.status != 204:
                    report["status"] = "failed"
            except Exception:
                report["source_synthetic_fixture_cleanup"] = False
                report["status"] = "failed"
        if oracle is not None:
            launcher.stop_oracle(oracle)
        if instance is not None:
            instance.stop()
    report["passed_cases"], report["count"], report["tool_results"] = cases, len(cases), results
    report["finished_at_unix"] = time.time()
    private_write(work_dir / "live-migration-result.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "passed_live_scoped_migration" else 2


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--oracle-launcher", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--oracle-port", type=int, default=28500)
    args = parser.parse_args(argv)
    return run(args.binary.resolve(), args.oracle_launcher.resolve(), args.work_dir.resolve(), args.oracle_port)


if __name__ == "__main__":
    raise SystemExit(main())
