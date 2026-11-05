#!/usr/bin/env python3
"""Real main-mode plugin/SDK and bounded central-writer contract in isolation.

Creates a new loopback V6 server and private SDK stores. Every provider secret
is synthetic. No provider request, production gateway change or coordinator
replacement is performed. The existing actual-provider canary is separate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

import owned_process
from cert_auth_live import cert_sha256
from native_v6_authbus_client_live import CanaryFailure, NativeInstance, private, sha, value_sha
from native_v6_openclaw_authbus_live import FILES, mkdir, owned_private_json


HERE = Path(__file__).resolve().parent
MOUNT = "openclaw-auth"
SOURCE = "authbus-modes-main"
PEER = "authbus-modes-peer"
WRITER = "authbus-modes-writer"
A, B, LOCAL = ("google:authbus-modes-" + letter for letter in ("a", "b", "local"))
C = "openai:authbus-modes-new"
ORIGINAL_SHA = "b19b6a9e7c1d57ccef8d67994ed3421891788ac30a82ff6bad2eef2ef7e30f9b"


def identity(credential):
    return value_sha({key: credential.get(key) for key in ("provider", "type", "email", "accountId", "projectId")})


def profile_payload(profile_id, credential):
    return {"schemaVersion": 1, "profileId": profile_id, "credential": credential,
            "digest": value_sha(credential), "identity": identity(credential)}


def manifest_entry(profile_id, credential):
    entry = {"profileId": profile_id, "key": "sha256-" + value_sha(credential), "digest": value_sha(credential),
             "identity": identity(credential), "provider": credential["provider"], "type": credential["type"]}
    if "expires" in credential:
        entry["expires"] = credential["expires"]
    return entry


def run(args, report):
    root = args.work_dir
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    if root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise CanaryFailure("new_fixture_root_custody")
    report.update(checks=[], clients=[], server_cycles=[], central_commits=[],
                  binary_sha256=sha(args.binary), driver_sha256=sha(__file__),
                  consumer_sha256=sha(HERE / "native_v6_authbus_modes_consumer.mjs"))
    confidential, plugin_tokens, client_logs = [], [], []
    instance = None
    credentials = {profile: {"type": "api_key", "provider": "google", "key": "synthetic-authbus-modes-" + secrets.token_hex(20)}
                   for profile in (A, B, LOCAL)}
    first_oauth = {"type": "oauth", "provider": "openai", "access": "synthetic-authbus-modes-" + secrets.token_hex(20),
                   "refresh": "synthetic-authbus-modes-" + secrets.token_hex(20), "expires": round(time.time() * 1000) + 86400000,
                   "email": "synthetic-authbus-modes@example.invalid", "accountId": "synthetic-authbus-modes-account"}
    second_oauth = {**first_oauth, "access": "synthetic-authbus-modes-" + secrets.token_hex(20),
                    "refresh": "synthetic-authbus-modes-" + secrets.token_hex(20), "expires": first_oauth["expires"] + 3600000}
    for value in [*credentials.values(), first_oauth, second_oauth]:
        confidential.extend(value[key] for key in ("key", "access", "refresh") if key in value)

    def check(name, condition, **metadata):
        report["checks"].append({"case": name, "passed": bool(condition), **metadata})
        if not condition:
            raise CanaryFailure(name)

    def call(name, method, path, body=None, *, token=None, expected=200):
        status, result = instance.call(method, path, body, token=token)
        check(name, status == expected, status=status, expected=expected)
        return result

    def read(name, path, *, token=None):
        return call(name, "GET", MOUNT + "/data/" + path, token=token)

    def write(name, path, data, cas, *, token, expected=200):
        return call(name, "POST", MOUNT + "/data/" + path, {"data": data, "options": {"cas": cas}}, token=token, expected=expected)

    def restart(name):
        old = instance.process
        instance.stop()
        report["server_cycles"].append({"case": name, "pid": old.pid, "stop": "SIGKILL", "exit_code": old.returncode})
        check(name + ".binary_unchanged", sha(args.binary) == report["binary_sha256"])
        instance.start()
        call(name + ".sealed", "GET", "sys/health", expected=503)
        call(name + ".unseal", "POST", "sys/unseal", {"key": unseal}, token="")
        capacity = call(name + ".capacity", "GET", "sys/internal/capacity")["data"]
        check(name + ".native_reader", capacity.get("native_kv2_reader_format") == 2)

    roles, states, bindings = {}, {}, {}

    def create_role(host, policy):
        role = "auth/approle/role/" + host
        call(host + ".policy", "PUT", "sys/policies/acl/" + host, {"policy": policy}, expected=204)
        call(host + ".role", "POST", role, {"token_policies": [host], "token_ttl": "600s", "token_max_ttl": "1200s", "secret_id_num_uses": 0, "secret_id_ttl": "3600s"}, expected=204)
        role_id = call(host + ".role_id", "GET", role + "/role-id")["data"]["role_id"]
        sid = call(host + ".sid", "POST", role + "/secret-id", {})["data"]
        confidential.extend((role_id, sid["secret_id"], sid["secret_id_accessor"]))
        directory = root / "credentials" / host
        mkdir(directory)
        private(directory / "role_id", role_id)
        private(directory / "secret_id", sid["secret_id"])
        private(directory / "ca.crt", (instance.root / "ca.crt").read_bytes())
        roles[host] = {"role": role, "role_id": role_id, **sid}
        return directory

    def prepare_state(host, credential_dir):
        state = root / host
        agent = state / "agents/main/agent"
        for directory in (state, state / "agents", state / "agents/main", agent, state / "home", state / "credentials"):
            mkdir(directory)
        private(state / "openclaw.json", json.dumps({"agents": {"list": [{"id": "main", "default": True, "agentDir": str(agent)}]}}))
        raw = {"address": instance.address, "caFile": str(credential_dir / "ca.crt"), "roleIdFile": str(credential_dir / "role_id"),
               "secretIdFile": str(credential_dir / "secret_id"), "hostId": host, "leader": False, "publishNew": True,
               "manageOrder": True, "releaseGeneration": 201, "pollIntervalMs": 15000, "refreshMarginMs": 900000, "maxRefreshesPerCycle": 1}
        binding = root / (host + "-binding.private.json")
        private(binding, json.dumps(raw))
        states[host], bindings[host] = (state, agent), binding

    def client(name, host=SOURCE, steps=None, expected=0):
        state, agent = states[host]
        run_dir = root / "runs" / name
        mkdir(run_dir)
        cfg = {"schema": "authbus-main-modes-driver-v1", "workRoot": str(root), "stateDir": str(state), "agentDir": str(agent),
               "runDir": str(run_dir), "homeDir": str(state / "home"), "oauthDir": str(state / "credentials"),
               "configPath": str(state / "openclaw.json"), "openclawRoot": str(args.openclaw_root), "pluginEntry": str(root / "plugin/index.js"),
               "pluginConfig": owned_private_json(bindings[host]), "capturePath": str(run_dir / "tokens.private.json"),
               "receiptPath": str(run_dir / "receipt.json"), "serverCertificateSha256": report["server_cert_der_sha256"], "steps": steps or [{}]}
        cfg_path = run_dir / "driver.private.json"
        private(cfg_path, json.dumps(cfg))
        environment = dict(os.environ)
        for key in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_GATEWAY_TOKEN"):
            environment.pop(key, None)
        result = owned_process.run([str(args.node), str(HERE / "native_v6_authbus_modes_consumer.mjs"), str(cfg_path)],
                                   cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=55, label="authbus-modes." + name)
        for filename, data in (("stdout.log", result.stdout), ("stderr.log", result.stderr)):
            private(run_dir / filename, data)
            client_logs.append(run_dir / filename)
        capture_path = run_dir / "tokens.private.json"
        if capture_path.exists():
            for auth in owned_private_json(capture_path).get("tokens", []):
                token = auth.get("token")
                check(name + ".actual_token_shape", isinstance(token, str) and len(token) >= 8)
                confidential.append(token)
                plugin_tokens.append(token)
        check(name + ".diagnostics_redacted", all(secret.encode() not in result.stdout + result.stderr for secret in confidential))
        receipt = owned_private_json(run_dir / "receipt.json")
        check(name + ".receipt_redacted", all(secret not in json.dumps(receipt) for secret in confidential))
        report["clients"].append({"case": name, "exit_code": result.returncode, **receipt})
        check(name + ".exit", result.returncode == expected, actual=result.returncode, expected=expected)
        check(name + ".scoped", receipt.get("defaultAgentScoped") is True)
        if expected == 0:
            check(name + ".plugin_ok", receipt.get("ok") is True)
            check(name + ".actual_login", receipt.get("authentications") == 1)
            observations = receipt["observations"]
            check(name + ".verified_tls", bool(observations) and all(item.get("tlsAuthorized") is True and item.get("peerCertificateSha256") == report["server_cert_der_sha256"] for item in observations))
            check(name + ".fresh_full_tls_per_request", all(item.get("isSessionReused") is False and item.get("socketId") == item.get("requestSocketId") and isinstance(item.get("socketId"), int) for item in observations)
                  and len({item["socketId"] for item in observations}) == len(observations))
            for index, cycle in enumerate(receipt["cycles"]):
                status = cycle["plugin"]
                check(name + f".cycle{index}.main_defaults", status.get("schedulerMode") == "shadow" and status.get("releaseGeneration") == 201 and status.get("leader") is False)
                check(name + f".cycle{index}.managed_order", status.get("verifiedOrderBindings", 0) == 2 and status.get("managedOrderBindings", 0) == 2)
                check(name + f".cycle{index}.shadow_does_not_enforce", status.get("strictLeaseAssignments") == 0 and status.get("strictLeaseShadow") == 1)
                check(name + f".cycle{index}.effective", status.get("effectiveMissing") == 0 and status.get("effectiveMismatched") == 0)
        return receipt

    def inbox_events(reason):
        keys = call("writer.inbox_list", "LIST", MOUNT + "/metadata/inbox/" + SOURCE, token=writer_token)["data"]["keys"]
        check("writer.inbox_bound", 0 < len(keys) <= 32)
        events = []
        for index, key in enumerate(keys):
            item = read("writer.inbox_read." + str(index), "inbox/" + SOURCE + "/" + key, token=writer_token)["data"]["data"]
            check("writer.inbox_path_binding." + str(index), item.get("sourceHost") == SOURCE and item.get("eventId") == key)
            if item.get("schemaVersion") == 1 and item.get("reason") == reason:
                events.append(item)
        return events

    def ingest(event, credential, expected_prior):
        # Test-only trusted acceptance for one known synthetic source. A
        # production coordinator needs its own enrollment/epoch/rotation owner.
        wanted = profile_payload(C, credential)
        check("writer.event_contract", set(event) == {"schemaVersion", "eventId", "sourceHost", "reason", "createdAt", "profileId", "digest", "identity", "credential"}
              and event["schemaVersion"] == 1 and event["reason"] == ("new-profile" if expected_prior is None else "manual-login")
              and isinstance(event["createdAt"], int) and 0 < event["createdAt"] <= round(time.time() * 1000)
              and isinstance(event["eventId"], str) and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", event["eventId"]) is not None
              and event["sourceHost"] == SOURCE and event["profileId"] == C and event["digest"] == wanted["digest"]
              and event["identity"] == wanted["identity"] and value_sha(event["credential"]) == wanted["digest"])
        previous = read("writer.manifest_before", "manifest", token=writer_token)["data"]
        manifest, version = previous["data"], previous["metadata"]["version"]
        found = next((entry for entry in manifest["profiles"] if entry["profileId"] == C), None)
        if found and found["digest"] == wanted["digest"]:
            report["central_commits"].append({"case": "duplicate_digest_no_change", "generation": manifest["generation"], "manifest_version": version})
            return manifest
        check("writer.exact_previous_digest", (found or {}).get("digest") == expected_prior)
        key = "profiles/sha256-" + wanted["digest"]
        write("writer.immutable_profile_first", key, wanted, 0, token=writer_token)
        updated = {"schemaVersion": 1, "generation": manifest["generation"] + 1,
                   "profiles": sorted([entry for entry in manifest["profiles"] if entry["profileId"] != C] + [manifest_entry(C, credential)], key=lambda entry: entry["profileId"])}
        write("writer.manifest_final_cas", "manifest", updated, version, token=writer_token)
        write("writer.stale_manifest_cas_denied", "manifest", manifest, version, token=writer_token, expected=400)
        write("writer.immutable_profile_cas0_denied", key, wanted, 0, token=writer_token, expected=400)
        final = read("writer.manifest_after", "manifest", token=writer_token)["data"]["data"]
        check("writer.manifest_exact_after_conflicts", final == updated)
        report["central_commits"].append({"case": event["reason"], "generation": final["generation"], "profile_digest": wanted["digest"], "profile_published_before_manifest": True})
        return final

    try:
        for directory in (root / "plugin", root / "node_modules", root / "credentials", root / "runs"):
            mkdir(directory)
        report["plugin_source_sha256"] = {}
        for filename in FILES:
            source = args.plugin_root / filename
            check("plugin." + filename + ".bounded_source", source.is_file() and not source.is_symlink() and source.stat().st_size <= 262144)
            report["plugin_source_sha256"][filename] = sha(source)
            private(root / "plugin" / filename, source.read_bytes())
        check("plugin.exact_original", report["plugin_source_sha256"]["index.js"] == ORIGINAL_SHA)
        private(root / "plugin/package.json", json.dumps({"private": True, "type": "module"}))
        (root / "node_modules/openclaw").symlink_to(args.openclaw_root, target_is_directory=True)
        instance = NativeInstance(args.binary, root / "server")
        report["server_cert_der_sha256"] = cert_sha256(instance.root / "tls.crt")
        instance.start()
        init = call("server.init", "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}, token="")
        instance.token, unseal = init["root_token"], init["keys_base64"][0]
        confidential.extend((instance.token, unseal))
        private(root / "recovery.private.json", json.dumps({"root_token": instance.token, "unseal_key": unseal}))
        call("server.unseal", "POST", "sys/unseal", {"key": unseal}, token="")
        call("server.kv2", "POST", "sys/mounts/" + MOUNT, {"type": "kv", "options": {"version": "2"}}, expected=204)
        call("server.activate", "POST", "sys/internal/native-v6/activate", {}, expected=204)
        check("server.native_reader_format2", call("server.capacity", "GET", "sys/internal/capacity")["data"].get("native_kv2_reader_format") == 2)
        call("server.approle", "POST", "sys/auth/approle", {"type": "approle"}, expected=204)
        reader_paths = ["manifest", "profiles/*", "order-policy", "scheduler-assignments"]
        for host in (SOURCE, PEER):
            policy = "\n".join(f'path "{MOUNT}/data/{entry}" {{ capabilities = ["read"] }}' for entry in reader_paths)
            policy += f'\npath "{MOUNT}/data/inbox/{host}/*" {{ capabilities = ["create", "update"] }}\n'
            policy += 'path "auth/token/revoke-self" { capabilities = ["update"] }\n'
            prepare_state(host, create_role(host, policy))
        policy = "\n".join(f'path "{MOUNT}/data/{entry}" {{ capabilities = ["create", "read", "update"] }}' for entry in reader_paths)
        for host in (SOURCE, PEER):
            policy += f'\npath "{MOUNT}/data/inbox/{host}/*" {{ capabilities = ["read"] }}'
            policy += f'\npath "{MOUNT}/metadata/inbox/{host}" {{ capabilities = ["list"] }}'
        create_role(WRITER, policy)
        writer = roles[WRITER]
        auth = call("writer.actual_approle", "POST", "auth/approle/login", {"role_id": writer["role_id"], "secret_id": writer["secret_id"]}, token="")["auth"]
        writer_token = auth["client_token"]
        confidential.append(writer_token)
        private(root / "writer-token.private.json", json.dumps({"client_token": writer_token, "accessor": auth.get("accessor")}))
        for profile in (A, B):
            payload = profile_payload(profile, credentials[profile])
            write("bootstrap.immutable." + profile[-1], "profiles/sha256-" + payload["digest"], payload, 0, token=writer_token)
        manifest = {"schemaVersion": 1, "generation": 1, "profiles": [manifest_entry(profile, credentials[profile]) for profile in (A, B)]}
        write("bootstrap.manifest", "manifest", manifest, 0, token=writer_token)
        order = {"schemaVersion": 1, "generation": 1, "providers": {"google": {"activeProfile": A, "enforceManagedOrder": True,
                 "candidates": [{"profileId": profile, "digest": value_sha(credentials[profile])} for profile in (A, B)]}}}
        write("bootstrap.order_policy", "order-policy", order, 0, token=writer_token)
        assignments = {"schemaVersion": 1, "generation": 201, "refreshLeases": [], "scopes": [], "assignments": []}
        for host in (SOURCE, PEER):
            assignments["scopes"].append({"hostId": host, "provider": "google", "model": "google/synthetic-model", "agentIds": ["main"], "strict": True})
            assignments["assignments"].append({"hostId": host, "provider": "google", "model": "google/synthetic-model", "agentId": "main", "status": "ASSIGNED", "mode": "enforce", "epoch": 201,
                                               "profileId": B, "digest": value_sha(credentials[B]), "leaseId": "synthetic-authbus-modes-lease", "expiresAt": round(time.time() * 1000) + 3600000})
        write("bootstrap.shadow_assignments", "scheduler-assignments", assignments, 0, token=writer_token)
        first = client("baseline", steps=[{"upserts": [{"profileId": LOCAL, "credential": credentials[LOCAL]}], "setOrder": [LOCAL]}])
        first_cycle = first["cycles"][0]
        check("baseline.initial_empty_sdk", first["initial"]["profiles"] == {})
        check("baseline.existing_local_not_published", first_cycle["plugin"]["publishedEvents"] == 0)
        check("baseline.managed_order_applied", first_cycle["after"]["order"] == [A, B] and first_cycle["after"]["resolvedOrder"] == [A, B])
        baseline = owned_private_json(states[SOURCE][0] / "authbus/publish-baseline.json")
        check("baseline.persisted_exact_local_digest", baseline["profiles"] == {LOCAL: value_sha(credentials[LOCAL])})
        actual_token = plugin_tokens[-1]
        for entry in reader_paths:
            target = "profiles/blocked" if entry == "profiles/*" else entry
            write("acl.consumer_canonical_write_denied." + target.replace("/", "_"), target, {"blocked": True}, 0, token=actual_token, expected=403)
        write("acl.consumer_other_inbox_denied", "inbox/another-host/blocked", {"blocked": True}, 0, token=actual_token, expected=403)
        call("acl.consumer_inbox_read_denied", "GET", MOUNT + "/data/inbox/" + SOURCE + "/blocked", token=actual_token, expected=403)
        write("acl.writer_cannot_impersonate_source", "inbox/" + SOURCE + "/blocked", {"blocked": True}, 0, token=writer_token, expected=403)

        published = client("new_profile", steps=[{"upserts": [{"profileId": C, "credential": first_oauth}]}, {}])
        check("publish_new.actual_event_then_process_dedupe", [cycle["plugin"]["publishedEvents"] for cycle in published["cycles"]] == [1, 0])
        events = inbox_events("new-profile")
        check("publish_new.exactly_one_new_profile_event", len(events) == 1 and events[0]["profileId"] == C)
        manifest = ingest(events[0], first_oauth, None)
        duplicate = ingest(events[0], first_oauth, None)
        check("writer.duplicate_does_not_advance_manifest", duplicate == manifest)
        acknowledged = client("central_acknowledged")
        check("central.acknowledged_generation", acknowledged["cycles"][0]["plugin"]["manifestGeneration"] == 2 and acknowledged["cycles"][0]["plugin"]["publishedEvents"] == 0)
        manual = client("manual_login", steps=[{"upserts": [{"profileId": C, "credential": second_oauth}]}])
        check("manual_login.real_pending_contract", manual["cycles"][0]["plugin"]["pendingRuntimeRefreshes"] == 1 and manual["cycles"][0]["plugin"]["publishedEvents"] == 1)
        events = inbox_events("manual-login")
        check("manual_login.one_exact_event", len(events) == 1)
        manifest = ingest(events[0], second_oauth, value_sha(first_oauth))
        next_order = json.loads(json.dumps(order))
        next_order["generation"] = 2
        next_order["providers"]["google"]["activeProfile"] = B
        write("writer.order_policy_cas", "order-policy", next_order, 1, token=writer_token)
        write("writer.order_policy_stale_cas_denied", "order-policy", order, 1, token=writer_token, expected=400)
        switched = client("order_changed")
        check("manage_order.central_change_actual_resolver", switched["cycles"][0]["after"]["order"] == [B, A] and switched["cycles"][0]["after"]["resolvedOrder"] == [B, A])
        check("manual_login.central_acknowledged", switched["cycles"][0]["after"]["profiles"][C] == value_sha(second_oauth) and switched["cycles"][0]["plugin"]["pendingRuntimeRefreshes"] == 0)

        restart("cold_committed_control")
        check("cold.manifest_exact", read("cold.manifest", "manifest", token=writer_token)["data"]["data"] == manifest)
        receiver = client("fresh_receiver_after_restart", host=PEER)
        expected_profiles = {**{profile: value_sha(credentials[profile]) for profile in (A, B)}, C: value_sha(second_oauth)}
        check("cold.new_sdk_receives_full_manifest", receiver["initial"]["profiles"] == {} and receiver["cycles"][0]["after"]["profiles"] == expected_profiles)
        check("cold.new_sdk_receives_order", receiver["cycles"][0]["after"]["resolvedOrder"] == [B, A])
        original_binding = bindings[SOURCE].read_bytes()
        unrelated = NativeInstance(args.binary, root / "unrelated-tls-fixture")
        wrong = json.loads(original_binding)
        wrong["caFile"] = str(unrelated.root / "ca.crt")
        private(bindings[SOURCE], json.dumps(wrong), replace=True)
        failed = client("bad_ca_binding", expected=3)
        check("rollback.bad_ca_has_no_authentication", failed.get("authentications") == 0 and failed["cycles"][0]["plugin"].get("ok") is False)
        check("rollback.failed_config_keeps_sdk_state", failed["cycles"][0]["before"] == failed["cycles"][0]["after"])
        private(bindings[SOURCE], original_binding, replace=True)
        check("rollback.same_binding_bytes", bindings[SOURCE].read_bytes() == original_binding)
        recovered = client("binding_restored")
        check("rollback.actual_reader_restored", recovered["cycles"][0]["after"] == switched["cycles"][0]["after"])
        for index, token in enumerate(dict.fromkeys(plugin_tokens)):
            call("revoke.actual_plugin_token." + str(index), "POST", "auth/token/revoke-self", {}, token=token, expected=204)
            call("revoke.token_denied." + str(index), "GET", MOUNT + "/data/manifest", token=token, expected=403)
        source = roles[SOURCE]
        call("revoke.source_sid", "POST", source["role"] + "/secret-id-accessor/destroy", {"secret_id_accessor": source["secret_id_accessor"]}, expected=204)
        rejected = client("revoked_source_login", expected=3)
        check("revoke.actual_plugin_denied", rejected.get("authentications") == 0 and rejected["cycles"][0]["plugin"].get("ok") is False
              and len(rejected["observations"]) == 1 and rejected["observations"][0].get("route") == "login" and rejected["observations"][0].get("status") == 400)
        restart("cold_revocation")
        for index, token in enumerate(dict.fromkeys(plugin_tokens)):
            call("revoke.cold_token_denied." + str(index), "GET", MOUNT + "/data/manifest", token=token, expected=403)
        denied = call("revoke.cold_sid_denied", "POST", "auth/approle/login", {"role_id": source["role_id"], "secret_id": source["secret_id"]}, token="", expected=400)
        check("revoke.fixed_sid_error", denied.get("errors") == ["invalid role or secret ID"] and "auth" not in denied)
        check("production.plugin_source_unchanged", all(sha(args.plugin_root / filename) == expected for filename, expected in report["plugin_source_sha256"].items()))
        evidence = json.dumps(report, sort_keys=True).encode() + (instance.root / "server.log").read_bytes()
        for filename in client_logs:
            evidence += filename.read_bytes()
        check("evidence.no_secret_values", all(secret.encode() not in evidence for secret in confidential))
        report["ok"] = True
    finally:
        if instance is not None:
            instance.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "work-dir", "plugin-root", "openclaw-root"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--node", type=Path, default=Path("/usr/bin/node"))
    args = parser.parse_args()
    report = {"schema": "native-v6-authbus-main-modes-v1", "ok": False, "created_at": datetime.now(timezone.utc).isoformat(),
              "production_coordinator_replacement": False, "production_mutation": False, "production_cutover": False,
              "provider_network_allowed": False, "real_provider_credentials": False, "oauth_refreshed": False, "j3160_contacted": False,
              "main_config_source_sha256": "791d2d5e7166d02b871a8aa21b0194ca65456c0019757451bfe46d0fe8127d55"}
    try:
        for name in ("binary", "work_dir", "plugin_root", "openclaw_root", "node"):
            if not getattr(args, name).is_absolute():
                raise CanaryFailure("absolute_paths_required")
        args.binary = args.binary.resolve(strict=True)
        args.plugin_root = args.plugin_root.resolve(strict=True)
        args.openclaw_root = args.openclaw_root.resolve(strict=True)
        run(args, report)
    except CanaryFailure as error:
        report["error"] = str(error)
    except BaseException as error:
        report["error"] = "unexpected_" + type(error).__name__
    if args.work_dir.is_dir():
        try:
            private(args.work_dir / "public-receipt.json", json.dumps(report, sort_keys=True))
        except OSError:
            report["receipt_persistence_failed"] = True
            report["ok"] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
