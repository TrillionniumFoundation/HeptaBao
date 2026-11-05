#!/usr/bin/env python3
"""Real owned credential → new native V6 → unchanged AuthBus plugin → SQLite.

Run on the credential's existing owner host with the locally staged private
candidate from authbus_google_source_prepare.py. All server, SDK and plugin
writes remain in a new private work directory. The production gateway and its
configuration, services, stores, roles, credentials and J3160 remain untouched.
Artifacts survive failures and include private recovery material. Do not
download private artifacts into a transcript.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import owned_process
from native_v6_authbus_client_live import CanaryFailure, NativeInstance, private, sha, value_sha
from cert_auth_live import cert_sha256


HERE = Path(__file__).resolve().parent
FILES = (
    "index.js", "order-policy.js", "runtime-refresh-policy.js", "codex-client-recycler.js",
    "lease-assignments.js", "provider-error-classifier.js", "bad-refresh-quarantine.js",
)
HOST_ID = "authbus-isolated-main"
ROLE = "auth/approle/role/authbus-isolated-main"
POLICY_NAME = "authbus-isolated-main"
POLICY = '\n'.join((
    'path "openclaw-auth/data/manifest" { capabilities = ["read"] }',
    'path "openclaw-auth/data/profiles/*" { capabilities = ["read"] }',
    'path "openclaw-auth/data/order-policy" { capabilities = ["read"] }',
    'path "openclaw-auth/data/scheduler-assignments" { capabilities = ["read"] }',
    f'path "openclaw-auth/data/inbox/{HOST_ID}/*" {{ capabilities = ["create", "update"] }}',
    'path "auth/token/lookup-self" { capabilities = ["read"] }',
    'path "auth/token/renew-self" { capabilities = ["update"] }',
    'path "auth/token/revoke-self" { capabilities = ["update"] }',
)) + '\n'


def owned_private_json(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077 or meta.st_size > 1024 * 1024:
            raise CanaryFailure("private_source_custody_invalid")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = None
            value = json.load(stream)
    finally:
        if fd is not None:
            os.close(fd)
    return value


def mkdir(path: Path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.geteuid() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise CanaryFailure("private_directory_custody_invalid")


def run(args, report):
    root = args.work_dir
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    if root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise CanaryFailure("new_work_root_custody_invalid")
    candidate = owned_private_json(args.candidate)
    report["source_candidate_sha256"] = sha(args.candidate)
    report["checks"], report["client_cycles"], report["server_cycles"] = [], [], []
    instance = None
    confidential = []
    issued_tokens = []
    receipt_paths = []

    def check(name, condition, **metadata):
        report["checks"].append({"case": name, "passed": bool(condition), **metadata})
        if not condition:
            raise CanaryFailure(name)

    def call(name, method, path, body=None, *, token=None, expected=200):
        status, result = instance.call(method, path, body, token=token)
        check(name, status == expected, status=status, expected=expected)
        return result

    def restart_server(name, unseal):
        previous = instance.process
        instance.stop()
        report["server_cycles"].append({"case": name, "pid": previous.pid, "stop": "SIGKILL", "exit_code": previous.returncode})
        check(name + ".binary_unchanged", sha(args.binary) == report["binary_sha256"])
        instance.start()
        call(name + ".sealed", "GET", "sys/health", expected=503)
        call(name + ".unseal", "POST", "sys/unseal", {"key": unseal}, token="")
        capacity = call(name + ".native_capacity", "GET", "sys/internal/capacity")["data"]
        check(name + ".native_reader_format2", capacity.get("native_kv2_reader_format") == 2)

    def prepare_state(name):
        state = root / name
        agent = state / "agents/main/agent"
        for directory in (state, state / "agents", state / "agents/main", agent, state / "credentials"):
            mkdir(directory)
        private(state / "openclaw.json", json.dumps({"agents": {"list": [{"id": "main", "default": True, "agentDir": str(agent)}]}}))
        return state, agent

    def client(name, *, state, agent, ca=None, expected=0, provider=False):
        run_dir = root / "runs" / name
        mkdir(run_dir)
        plugin_config = json.loads(binding_path.read_text())
        if ca is not None:
            plugin_config["caFile"] = str(ca)
        cfg = {
            "schema": "actual-openclaw-authbus-driver-v1", "workRoot": str(root),
            "stateDir": str(state), "agentDir": str(agent), "runDir": str(run_dir),
            "openclawHome": str(root / "openclaw-home"), "oauthDir": str(state / "credentials"),
            "configPath": str(state / "openclaw.json"), "openclawRoot": str(args.openclaw_root),
            "pluginEntry": str(root / "plugin/index.js"), "pluginConfig": plugin_config,
            "capturePath": str(run_dir / "auth.private.json"), "receiptPath": str(run_dir / "receipt.json"),
            "expectedProfileId": profile_id, "expectedProvider": "google", "expectedDigest": profile_digest,
            "verifyProvider": provider,
        }
        cfg_path = run_dir / "driver.private.json"
        private(cfg_path, json.dumps(cfg))
        # Credentials are never arguments or inherited provider environment
        # values; the unchanged plugin must receive them from the new server.
        environment = dict(os.environ)
        for key in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN"):
            environment.pop(key, None)
        completed = owned_process.run(
            [str(args.node), str(HERE / "native_v6_openclaw_authbus_consumer.mjs"), str(cfg_path)],
            cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=55, label="actual-authbus." + name,
        )
        private(run_dir / "stdout.log", completed.stdout)
        private(run_dir / "stderr.log", completed.stderr)
        # Include this cycle's newly issued bearer before checking diagnostics
        # or accepting its public receipt. It did not exist before the child
        # executed, so scanning only the previous custody set is insufficient.
        auth_path = run_dir / "auth.private.json"
        if auth_path.exists():
            tokens = owned_private_json(auth_path).get("tokens", [])
            for auth in tokens:
                bearer = auth.get("token")
                check(name + ".captured_actual_plugin_token_shape", isinstance(bearer, str) and len(bearer) >= 8)
                issued_tokens.append(bearer)
                confidential.append(bearer)
        check(name + ".diagnostics_redacted", all(secret.encode() not in completed.stdout + completed.stderr for secret in confidential))
        receipt_path = run_dir / "receipt.json"
        receipt_paths.append(receipt_path)
        if receipt_path.exists():
            observation = owned_private_json(receipt_path)
            public_observation = json.dumps(observation, sort_keys=True).encode()
            check(name + ".public_receipt_redacted", all(secret.encode() not in public_observation for secret in confidential))
            report["client_cycles"].append({"case": name, "exit_code": completed.returncode, **observation})
        else:
            observation = {}
            report["client_cycles"].append({"case": name, "exit_code": completed.returncode, "receipt_missing": True})
        check(name + ".exit", completed.returncode == expected, exit_code=completed.returncode, expected=expected)
        if expected == 0:
            check(name + ".actual_plugin_ok", observation.get("ok") is True)
            check(name + ".actual_sdk_store_exact", observation.get("actualSdkReadbackMatches") is True and observation.get("profileCountAfter") == 1)
            check(name + ".default_main_scoped", observation.get("scope", {}).get("defaultAgentDirScoped") is True)
            check(name + ".real_login", observation.get("authentications") == 1)
            bao_observations = [x for x in observation.get("observations", []) if x.get("service") == "isolated_heptabao"]
            check(name + ".real_verified_tls", bool(bao_observations) and all(x.get("tlsAuthorized") is True and x.get("peerCertificateSha256") == report["server_cert_der_sha256"] for x in bao_observations))
            check(name + ".fresh_full_tls_per_request", all(x.get("isSessionReused") is False and x.get("socketId") == x.get("requestSocketId") and isinstance(x.get("socketId"), int) for x in bao_observations) and len({x["socketId"] for x in bao_observations}) == len(bao_observations))
        return observation

    try:
        check("source.schema", candidate.get("schema") == "authbus-private-bootstrap-candidate-v1" and candidate.get("mount") == "openclaw-auth")
        credential = candidate["profile"]["data"]["credential"]
        confidential.append(credential.get("key", ""))
        check("source.real_google_api_key_shape", credential.get("type") == "api_key" and credential.get("provider") == "google" and len(credential.get("key", "")) >= 8)
        profile_id = candidate["profile"]["data"]["profileId"]
        profile_digest = value_sha(credential)
        check("source.profile_digest", candidate["profile"]["data"]["digest"] == profile_digest)
        identity = {field: credential.get(field) for field in ("provider", "type", "email", "accountId", "projectId")}
        check("source.identity_digest", candidate["profile"]["data"]["identity"] == value_sha(identity))
        manifest = candidate["manifest"]["data"]
        check("source.manifest_single_verified_profile", len(manifest.get("profiles", [])) == 1 and manifest["profiles"][0]["profileId"] == profile_id and manifest["profiles"][0]["digest"] == profile_digest)
        check("source.immutable_profile_key", candidate["profile"]["path"] == "profiles/" + manifest["profiles"][0]["key"] and manifest["profiles"][0]["key"] == "sha256-" + profile_digest)
        proof = candidate.get("verification", {})
        check("source.official_negative_and_positive_evidence", proof.get("unauthenticated_control", {}).get("http_status") in (400, 401, 403) and proof.get("authenticated_probe", {}).get("http_status") == 200 and proof.get("authenticated_probe", {}).get("models_array") is True)
        source_path = Path(candidate["source"]["path"])
        check("source.fingerprint_current", sha(source_path) == candidate["source"]["sha256"])
        report.update(profile_id=profile_id, credential_digest=profile_digest, real_owned_credential_used=True,
                      verified_source_profiles=1, source_oauth_refreshed=False, legacy_oauth_migrated=False,
                      binary_sha256=sha(args.binary), harness_sha256=sha(__file__),
                      node_harness_sha256=sha(HERE / "native_v6_openclaw_authbus_consumer.mjs"))
        for directory in (root / "plugin", root / "node_modules", root / "credentials", root / "runs", root / "openclaw-home"):
            mkdir(directory)
        report["plugin_source_sha256"] = {}
        for filename in FILES:
            source = args.plugin_root / filename
            check("plugin_copy." + filename + ".bounded", source.is_file() and not source.is_symlink() and source.stat().st_size <= 262144)
            payload = source.read_bytes()
            report["plugin_source_sha256"][filename] = hashlib.sha256(payload).hexdigest()
            private(root / "plugin" / filename, payload)
        private(root / "plugin/package.json", json.dumps({"name": "isolated-unchanged-openclaw-authbus", "private": True, "type": "module"}))
        (root / "node_modules/openclaw").symlink_to(args.openclaw_root, target_is_directory=True)
        state, agent = prepare_state("openclaw-state")
        instance = NativeInstance(args.binary, root / "server")
        report["server_cert_der_sha256"] = cert_sha256(instance.root / "tls.crt")
        report["new_ca_sha256"] = sha(instance.root / "ca.crt")
        instance.start()
        init = call("server.init", "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}, token="")
        instance.token, unseal = init["root_token"], init["keys_base64"][0]
        confidential.extend((instance.token, unseal))
        private(root / "recovery.private.json", json.dumps({"root_token": instance.token, "unseal_key": unseal}))
        call("server.unseal", "POST", "sys/unseal", {"key": unseal}, token="")
        call("server.bootstrap_mount", "POST", "sys/mounts/openclaw-auth", {"type": "kv", "options": {"version": "2"}}, expected=204)
        call("server.activate_native_v6", "POST", "sys/internal/native-v6/activate", {}, expected=204)
        capacity = call("server.native_capacity", "GET", "sys/internal/capacity")["data"]
        check("server.reader_format2", capacity.get("native_kv2_reader_format") == 2)
        # Publish profile material first; the manifest is the final CAS commit.
        for part in ("profile", "order_policy", "scheduler_assignments", "manifest"):
            entry = candidate[part]
            check("bootstrap." + part + ".cas0", entry.get("cas") == 0)
            result = call("bootstrap." + part, "POST", "openclaw-auth/data/" + entry["path"], {"data": entry["data"], "options": {"cas": 0}})
            check("bootstrap." + part + ".version1", result.get("data", {}).get("version") == 1)
        readback = call("bootstrap.private_profile_readback", "GET", "openclaw-auth/data/" + candidate["profile"]["path"])
        check("bootstrap.exact_real_credential", value_sha(readback["data"]["data"]["credential"]) == profile_digest)
        call("auth.policy", "PUT", "sys/policies/acl/" + POLICY_NAME, {"policy": POLICY}, expected=204)
        call("auth.fixed_approle_mount", "POST", "sys/auth/approle", {"type": "approle"}, expected=204)
        call("auth.reusable_sid_role", "POST", ROLE, {"token_policies": [POLICY_NAME], "token_ttl": "300s", "token_max_ttl": "600s", "secret_id_num_uses": 0, "secret_id_ttl": "3600s"}, expected=204)
        role_id = call("auth.role_id", "GET", ROLE + "/role-id")["data"]["role_id"]
        sid = call("auth.secret_id", "POST", ROLE + "/secret-id", {})["data"]
        confidential.extend((role_id, sid["secret_id"], sid["secret_id_accessor"]))
        private(root / "credentials/role_id", role_id)
        private(root / "credentials/secret_id", sid["secret_id"])
        private(root / "credentials/ca.crt", (instance.root / "ca.crt").read_bytes())
        binding = {"address": instance.address, "caFile": str(root / "credentials/ca.crt"), "roleIdFile": str(root / "credentials/role_id"), "secretIdFile": str(root / "credentials/secret_id"), "hostId": HOST_ID, "leader": False, "publishNew": False, "manageOrder": False, "schedulerMode": "shadow", "pollIntervalMs": 60000, "releaseGeneration": 1}
        binding_path = root / "plugin-binding.private.json"
        private(binding_path, json.dumps(binding))
        binding_bytes = binding_path.read_bytes()
        first = client("initial", state=state, agent=agent, provider=True)
        check("initial.empty_isolated_store", first.get("profileCountBefore") == 0)
        plugin_token = issued_tokens[-1]
        call("acl.profile_write_denied", "POST", "openclaw-auth/data/" + candidate["profile"]["path"], {"data": {"blocked": True}, "options": {"cas": 1}}, token=plugin_token, expected=403)
        call("acl.other_host_inbox_denied", "POST", "openclaw-auth/data/inbox/another-host/blocked", {"data": {"blocked": True}, "options": {"cas": 0}}, token=plugin_token, expected=403)
        renewed = call("token.actual_plugin_renew_self", "POST", "auth/token/renew-self", {"increment": "300s"}, token=plugin_token)
        check("token.actual_plugin_bearer_retained", renewed.get("auth", {}).get("client_token") == plugin_token)
        check("token.actual_plugin_renewable", renewed.get("auth", {}).get("renewable") is True)

        # Closed-process SQLite checkpoint, copied only from the new shadow
        # agent. No production database pages are copied or altered.
        backup = root / "sqlite-backup"
        mkdir(backup)
        report["sqlite_backup"] = []
        for suffix in ("", "-wal"):
            source = agent / ("openclaw-agent.sqlite" + suffix)
            if source.exists():
                check("backup.sqlite_bound" + (suffix or ".db"), source.stat().st_size <= 32 * 1024 * 1024)
                destination = backup / source.name
                private(destination, source.read_bytes())
                report["sqlite_backup"].append({"name": source.name, "bytes": destination.stat().st_size, "sha256": sha(destination)})
        check("backup.database_present", any(item["name"] == "openclaw-agent.sqlite" for item in report["sqlite_backup"]))
        restart_server("cold_restart", unseal)
        persisted = call("cold_restart.real_profile_read", "GET", "openclaw-auth/data/" + candidate["profile"]["path"])
        check("cold_restart.real_profile_exact", value_sha(persisted["data"]["data"]["credential"]) == profile_digest)
        restarted = client("cold_restart", state=state, agent=agent)
        check("cold_restart.actual_client_sqlite_survived", restarted.get("profileCountBefore") == 1)

        owned_process.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=AuthBus Rollback Untrusted CA", "-keyout", str(root / "wrong-ca.key"), "-out", str(root / "wrong-ca.crt")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, label="actual-authbus.wrong-ca")
        (root / "wrong-ca.key").chmod(0o600)
        wrong_binding = dict(binding)
        wrong_binding["caFile"] = str(root / "wrong-ca.crt")
        private(binding_path, json.dumps(wrong_binding), replace=True)
        refused = client("bad_ca", state=state, agent=agent, expected=3)
        check("rollback.bad_ca_did_not_authenticate", refused.get("authentications") == 0 and refused.get("plugin", {}).get("ok") is False)
        check("rollback.failed_binding_kept_exact_profile", refused.get("actualSdkReadbackMatches") is True)
        private(binding_path, binding_bytes, replace=True)
        check("rollback.binding_exact_bytes", binding_path.read_bytes() == binding_bytes)
        client("binding_restored", state=state, agent=agent)

        restore_state, restore_agent = prepare_state("restored-state")
        for item in report["sqlite_backup"]:
            private(restore_agent / item["name"], (backup / item["name"]).read_bytes())
        restored = client("backup_restored", state=restore_state, agent=restore_agent, provider=True)
        check("backup.actual_sdk_restore", restored.get("profileCountBefore") == 1 and restored.get("actualSdkReadbackMatches") is True)
        inbox = call("plugin.actual_inbox_list", "LIST", "openclaw-auth/metadata/inbox/" + HOST_ID)
        keys = inbox.get("data", {}).get("keys", [])
        check("plugin.actual_host_reports_persisted", 4 <= len(keys) <= 16, reports=len(keys))
        for index, key in enumerate(keys):
            event = call("plugin.report_read." + str(index), "GET", "openclaw-auth/data/inbox/" + HOST_ID + "/" + key)["data"]["data"]
            check("plugin.report_contract." + str(index), event.get("kind") == "agent-report" and event.get("sourceHost") == HOST_ID and any(profile.get("digest") == profile_digest and profile.get("profileId") == profile_id for profile in event.get("profiles", [])))

        for index, token in enumerate(issued_tokens):
            call("revoke.actual_plugin_token." + str(index), "POST", "auth/token/revoke-self", {}, token=token, expected=204)
            call("revoke.actual_plugin_token_denied." + str(index), "GET", "openclaw-auth/data/manifest", token=token, expected=403)
        call("revoke.secret_id_accessor", "POST", ROLE + "/secret-id-accessor/destroy", {"secret_id_accessor": sid["secret_id_accessor"]}, expected=204)
        rejected = client("sid_revoked", state=state, agent=agent, expected=3)
        check("revoke.actual_plugin_relogin_denied", rejected.get("authentications") == 0 and rejected.get("plugin", {}).get("ok") is False)
        restart_server("revocations_cold_restart", unseal)
        for index, token in enumerate(issued_tokens):
            call("revoke.persisted_token_denial." + str(index), "GET", "openclaw-auth/data/manifest", token=token, expected=403)
        sid_denial = call("revoke.persisted_sid_denial", "POST", "auth/approle/login", {"role_id": role_id, "secret_id": sid["secret_id"]}, token="", expected=400)
        check("revoke.persisted_sid_exact_error", sid_denial.get("errors") == ["invalid role or secret ID"] and "auth" not in sid_denial)
        check("source.environment_unchanged", sha(source_path) == candidate["source"]["sha256"])
        check("source.candidate_unchanged", sha(args.candidate) == report["source_candidate_sha256"])
        check("plugin.production_code_unchanged", all(sha(args.plugin_root / name) == expected for name, expected in report["plugin_source_sha256"].items()))
        public_bytes = json.dumps(report, sort_keys=True).encode()
        diagnostics = (instance.root / "server.log").read_bytes()
        check("evidence.no_secret_values", all(secret.encode() not in public_bytes + diagnostics for secret in confidential))
        report["ok"] = True
    finally:
        if instance is not None:
            instance.stop()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--candidate", required=True, type=Path)
    p.add_argument("--work-dir", required=True, type=Path)
    p.add_argument("--plugin-root", required=True, type=Path)
    p.add_argument("--openclaw-root", required=True, type=Path)
    p.add_argument("--node", default=Path("/usr/bin/node"), type=Path)
    args = p.parse_args()
    report = {"schema": "native-v6-actual-openclaw-authbus-live-v1", "ok": False, "created_at": datetime.now(timezone.utc).isoformat(), "native_v6_fixture": True, "production_cutover": False, "ha_qualification": False, "j3160_contacted": False}
    try:
        for name in ("binary", "candidate", "work_dir", "plugin_root", "openclaw_root", "node"):
            if not getattr(args, name).is_absolute():
                raise CanaryFailure("all_paths_must_be_absolute")
        args.binary = args.binary.resolve(strict=True)
        args.plugin_root = args.plugin_root.resolve(strict=True)
        args.openclaw_root = args.openclaw_root.resolve(strict=True)
        run(args, report)
    except CanaryFailure as exc:
        report["error"] = str(exc)
    except BaseException as exc:
        report["error"] = "unexpected_" + type(exc).__name__
    if args.work_dir.is_dir():
        try:
            private(args.work_dir / "public-receipt.json", json.dumps(report, sort_keys=True))
        except OSError as exc:
            report["receipt_persistence_error"] = type(exc).__name__
            report["ok"] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
