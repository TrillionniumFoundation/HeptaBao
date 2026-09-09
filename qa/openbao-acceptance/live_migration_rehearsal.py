#!/usr/bin/env python3
"""Live synthetic OpenBao->HeptaBao rehearsal in one process/network context.

Requires the independently verified Oracle launcher supplied by the operator.
The launcher and binary are executable inputs, not downloaded or generated here.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import secrets
import sys
import time
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
        recovery_nonce = base64.b64encode(secrets.token_bytes(32)).decode()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1, "recovery_nonce": recovery_nonce})
        check("candidate_initialized", status == 200)
        instance.token, unseal = initialized["root_token"], initialized["keys_base64"][0]
        check("candidate_init_ack", instance.call("POST", "sys/init/ack", {"recovery_nonce": recovery_nonce, "ack_token": initialized["init_ack_token"]})[0] == 204)
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
        binding = {"source_identity": {"endpoint": source.address, "namespace": source.namespace, "mount": source_mount,
                    "cluster_id": source_health["cluster_id"], "version": source_health["version"]},
                   "keys_digest": digest([keys[0]]), "profile": migration.SCHEMA,
                   "target_identity": {"endpoint": target.address, "namespace": target.namespace, "mount": "resumed",
                                       "cluster_id": target_health["cluster_id"]}}
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
