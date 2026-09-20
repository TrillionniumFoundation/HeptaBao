#!/usr/bin/env python3
"""Exercise the pinned schema-21 RADIUS store through native parameters (schema 22+).

Only fresh encrypted stores, enrolled UDP endpoints, and actual signed PAP
requests are used. Old renewable finite tokens use current provider limits.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from radius_renewal_live import RadiusResponder, configuration, SECRET, USERNAME, PASSWORD
from radius_renewal_live import renewal_token_shape
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import Instance

LEGACY_SOURCE = "0e47d47e37d783dd6f3dc7c35f7938a25a9a36f5"
LEGACY_SHA256 = "db3769839e5fbe6bc45bab5812175420bc6fae427924ea234fa880d313fe0cd1"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/oidc-renewal-0e47d47.json"


def admit_legacy(candidate, legacy, expected, receipt):
    required = {"build_source_commit": LEGACY_SOURCE,
                "harness_source_commit": LEGACY_SOURCE, "harness_source_dirty": False,
                "harness_source_unchanged": True, "candidate_binary_unchanged": True,
                "candidate_binary_sha256": LEGACY_SHA256, "status": "passed"}
    if expected != LEGACY_SHA256 or any(receipt.get(key) != value for key, value in required.items()):
        raise ValueError("legacy_schema21_build_receipt_mismatch")
    return validate_binary_pins(candidate, legacy, expected)


class Trace:
    def __init__(self, client, cases, responder=None):
        self.client, self.cases, self.responder = client, cases, responder

    def check(self, name, condition, **observed):
        name = "radius_native_upgrade." + name
        self.cases.append({"case": name, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(name)

    def call(self, name, path, body=None, *, method="POST", token=None, expected=200, provider=None):
        before = self.responder.count() if self.responder is not None else 0
        response = self.client.request(method, "/v1/" + path, body, token=token)
        passed, observed = response.status == expected, {"status": response.status}
        if provider is not None:
            observed["provider_checked"] = (self.responder is not None and self.responder.count() == before + 1
                                             and self.responder.observed(before, accepted=provider))
            passed &= observed["provider_checked"]
        self.check(name, passed, **observed)
        return response.body


def prepare_legacy(instance, responder, cases):
    instance.start()
    status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
    if status != 200:
        raise ScenarioFailure("radius_native_upgrade.initialize")
    instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
    t = Trace(Client(instance.address, str(instance.root / "ca.crt"), instance.token), cases, responder)
    t.call("legacy.unseal", "sys/unseal", {"key": key})
    t.call("legacy.mount", "sys/auth/radius-upgrade", {"type": "radius"}, expected=204)
    rules = ('path "auth/token/create" { capabilities = ["update", "sudo"] }\n'
             'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
    t.call("legacy.policy", "sys/policies/acl/radius-upgrade", {"policy": rules}, method="PUT", expected=204)
    config_path, login_path = "auth/radius-upgrade/config", "auth/radius-upgrade/login"
    config = configuration("candidate", responder, ["default", "radius-upgrade"])
    config["token_ttl"] = 120
    t.call("legacy.config", config_path, config, expected=204)
    t.call("legacy.write", "secret/data/radius-upgrade", {"data": {"synthetic": True}})
    original = t.call("legacy.login", login_path,
                     {"username": USERNAME.decode(), "password": PASSWORD.decode()}, token="", provider=True).get("auth", {})
    t.check("legacy.token_shape", all(isinstance(original.get(k), str) and original[k]
                                     for k in ("client_token", "accessor", "entity_id")))
    t.check("legacy.renewable_finite", original.get("renewable") is True and original.get("lease_duration") == 120)
    lookup = t.call("legacy.lookup", "auth/token/lookup-self", method="GET", token=original["client_token"]).get("data", {})
    t.check("legacy.no_issued_period_or_explicit_cap", "period" not in lookup and lookup.get("explicit_max_ttl") == 0)
    children = {}
    for label, path in [("child", "auth/token/create"), ("orphan", "auth/token/create-orphan")]:
        child = t.call("legacy." + label + ".create", path, {"policies": ["default"], "ttl": "120s"},
                       token=original["client_token"]).get("auth", {})
        t.check("legacy." + label + ".shape", isinstance(child.get("client_token"), str)
                and bool(child["client_token"]) and child.get("renewable") is True)
        children[label] = child["client_token"]
    return {"trace": t, "key": key, "original": original, "children": children,
            "config_path": config_path, "login_path": login_path, "config": config}


def cap_preserved(data, *, period, cap):
    return (isinstance(data, dict) and data.get("period") == period and data.get("explicit_max_ttl") == cap
            and type(data.get("creation_time")) is int and type(data.get("expire_time_unix")) is int
            and data["expire_time_unix"] == data["creation_time"] + cap)


def run_upgrade(instance, responder, candidate, legacy, cases):
    prepared = prepare_legacy(instance, responder, cases)
    t, key, original = prepared["trace"], prepared["key"], prepared["original"]
    children = prepared["children"]
    instance.stop()
    store = instance.root / "data"
    old_application = durable_manifest(store, application_only=True)
    instance.binary = candidate
    instance.start()
    t.call("current.unseal", "sys/unseal", {"key": key})
    t.check("current.reopen_preserves_application", durable_manifest(store, application_only=True) == old_application)
    before = durable_manifest(store)
    value = t.call("current.read", "secret/data/radius-upgrade", method="GET")
    t.check("current.value_preserved", value.get("data", {}).get("data") == {"synthetic": True})
    old = t.call("current.old_token_active", "auth/token/lookup-self", method="GET", token=original["client_token"]).get("data", {})
    t.check("current.old_issue_parameters_preserved", old.get("renewable") is True
            and "period" not in old and old.get("explicit_max_ttl") == 0)
    config = t.call("current.old_config", prepared["config_path"], method="GET").get("data", {})
    t.check("current.old_config_compatible_defaults", config.get("token_ttl") == 120
            and config.get("token_max_ttl") == 600 and config.get("token_period") == 0
            and config.get("token_explicit_max_ttl") == 0)
    for label, child in children.items():
        t.call("current." + label + ".active", "auth/token/lookup-self", method="GET", token=child)
    t.check("current.reads_preserve_entire_store", durable_manifest(store) == before)
    t.call("current.partial_period_config", prepared["config_path"],
           {"token_period": 60, "token_explicit_max_ttl": 120}, expected=204)
    config = t.call("current.partial_readback", prepared["config_path"], method="GET").get("data", {})
    t.check("current.partial_preserves_old_fields", config.get("url") == prepared["config"]["url"]
            and config.get("token_policies") == ["default", "radius-upgrade"]
            and config.get("token_ttl") == 120 and config.get("token_max_ttl") == 600)
    for label, path, body, caller in [("self", "auth/token/renew-self", {}, original["client_token"]),
                                     ("token", "auth/token/renew", {"token": original["client_token"]}, None),
                                     ("accessor", "auth/token/renew-accessor", {"accessor": original["accessor"]}, None)]:
        renewed = t.call("current.old_" + label + ".uses_current_period", path, dict(body, increment=300),
                         token=caller, provider=True).get("auth", {})
        t.check("current.old_" + label + ".lease_and_echo", renewed.get("lease_duration") == 60
                and renewal_token_shape(renewed, original["client_token"], via_accessor=label == "accessor"))
    old = t.call("current.old_lookup_after_period_renewal", "auth/token/lookup-self", method="GET", token=original["client_token"]).get("data", {})
    t.check("current.renewal_does_not_rewrite_old_issue_parameters", "period" not in old and old.get("explicit_max_ttl") == 0)
    native = t.call("current.new_periodic_login", prepared["login_path"],
                    {"username": USERNAME.decode(), "password": PASSWORD.decode()}, token="", provider=True).get("auth", {})
    t.check("current.new_periodic_shape", native.get("renewable") is True and native.get("lease_duration") == 60
            and native.get("entity_id") == original["entity_id"]
            and isinstance(native.get("client_token"), str) and bool(native["client_token"])
            and native["client_token"] != original["client_token"])
    new = t.call("current.new_lookup", "auth/token/lookup-self", method="GET", token=native["client_token"]).get("data", {})
    t.check("current.new_issue_parameters_captured", new.get("period") == 60 and new.get("explicit_max_ttl") == 120)
    t.call("current.raise_config_after_issue", prepared["config_path"],
           {"token_period": 300, "token_explicit_max_ttl": 600}, expected=204)
    body = t.call("current.old_has_no_new_explicit_cap", "auth/token/renew-self", {"increment": 600},
                  token=original["client_token"], provider=True)
    t.check("current.old_uses_new_period", body.get("auth", {}).get("lease_duration") == 300)
    body = t.call("current.new_cap_not_extended", "auth/token/renew-self", {"increment": 600},
                  token=native["client_token"], provider=True)
    lease = body.get("auth", {}).get("lease_duration")
    t.check("current.new_lease_clamped", type(lease) is int and 0 < lease <= 120)
    new = t.call("current.new_cap_lookup", "auth/token/lookup-self", method="GET", token=native["client_token"]).get("data", {})
    t.check("current.absolute_issued_cap_and_original_period", cap_preserved(new, period=60, cap=120))
    responder.allow = False
    before = durable_manifest(store)
    denied = t.call("current.provider_reject", "auth/token/renew-self", {"increment": 600},
                    token=native["client_token"], provider=False, expected=400)
    t.check("current.rejection_has_no_auth", not denied.get("auth") and not denied.get("wrap_info"))
    t.check("current.provider_reject_preserves_entire_store", durable_manifest(store) == before)
    calls = responder.count()
    for label, child in children.items():
        body = t.call("current." + label + ".generic_renew", "auth/token/renew-self", {"increment": 300}, token=child)
        t.check("current." + label + ".renewable", body.get("auth", {}).get("renewable") is True)
    t.check("current.children_never_contact_provider", responder.count() == calls)
    instance.stop()
    upgraded_application = durable_manifest(store, application_only=True)
    t.check("current.native_mutation_persisted", upgraded_application != old_application)
    instance.binary = legacy
    instance.start()
    t.call("downgrade.unseal_rejected", "sys/unseal", {"key": key}, expected=503)
    t.call("downgrade.remains_sealed", "sys/health", method="GET", expected=503)
    t.call("downgrade.read_denied", "secret/data/radius-upgrade", method="GET", expected=503)
    instance.stop()
    t.check("downgrade.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    instance.binary = candidate
    instance.start()
    t.call("recovery.unseal", "sys/unseal", {"key": key})
    t.check("recovery.application_unchanged", durable_manifest(store, application_only=True) == upgraded_application)
    for label, bearer in [("old", original["client_token"]), ("native", native["client_token"]), *children.items()]:
        t.call("recovery." + label + ".active", "auth/token/lookup-self", method="GET", token=bearer)
    responder.allow = True
    for label, bearer in [("old", original["client_token"]), ("native", native["client_token"])]:
        t.call("recovery." + label + ".renews_through_provider", "auth/token/renew-self", {"increment": 600},
               token=bearer, provider=True)
    old = t.call("recovery.old_lookup", "auth/token/lookup-self", method="GET", token=original["client_token"]).get("data", {})
    t.check("recovery.old_issue_parameters", "period" not in old and old.get("explicit_max_ttl") == 0)
    new = t.call("recovery.native_lookup", "auth/token/lookup-self", method="GET", token=native["client_token"]).get("data", {})
    t.check("recovery.native_cap_and_period", cap_preserved(new, period=60, cap=120))
    calls = responder.count()
    for label, child in children.items():
        t.call("recovery." + label + ".generic_renew", "auth/token/renew-self", {"increment": 300}, token=child)
    t.check("recovery.children_never_contact_provider", responder.count() == calls)
    instance.stop()
    sensitive = [PASSWORD, SECRET, key.encode(), instance.token.encode(), original["client_token"].encode(),
                 native["client_token"].encode(), *[value.encode() for value in children.values()]]
    files = [p for p in store.rglob("*") if p.is_file()] + [instance.root / "server.log", instance.root / "audit.jsonl"]
    t.check("plaintext_credentials_absent", all(secret not in path.read_bytes()
                                               for path in files if path.exists() for secret in sensitive))


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--legacy-binary", required=True)
    parser.add_argument("--expected-legacy-sha256", required=True)
    parser.add_argument("--build-source-commit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit):
        parser.error("full build source commit required")
    candidate, legacy = Path(args.binary).resolve(strict=True), Path(args.legacy_binary).resolve(strict=True)
    candidate_hash, legacy_hash = admit_legacy(candidate, legacy, args.expected_legacy_sha256,
                                              json.loads(LEGACY_RECEIPT.read_text()))
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before = source_identity(ROOT, candidate)
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-radius-native-upgrade-"))
    root.chmod(0o700)
    instance = responder = None
    result = {"schema": "heptabao.radius-native-upgrade.v1", "from_schema": 21, "minimum_to_schema": 22,
              "synthetic_only": True, "legacy_source_commit": LEGACY_SOURCE,
              "legacy_binary_sha256": legacy_hash, "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT),
              "candidate_binary_sha256": candidate_hash, "build_source_commit": args.build_source_commit,
              "build_source_binding_basis": "caller-supplied build commit and observed binary hash; not independent binary attestation",
              "runner_sha256": runner_hash, "cases": [], "started_at_unix": time.time(),
              "radius_profile": "enrolled UDP PAP with mandatory candidate request and response authenticators",
              "independent_qualification": False, "full_migration_qualification": False,
              "rolling_upgrade_qualification": False, "production_authority": False,
              "reopen_replay_ledger_may_change": True,
              "unchanged_application_artifacts_scope": "all store entries except root ledger.hbl, rebuilt before schema validation on reopen"}
    try:
        instance = Instance(legacy, root / "instance")
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["lifecycle_interval_seconds"] = 0
        responder = RadiusResponder(require_ma=True)
        config["outbound_endpoints"] = [{"origin": "radius://127.0.0.1:" + str(responder.port),
            "address": "127.0.0.1:" + str(responder.port), "server_name": "127.0.0.1", "ca_pem": "",
            "path_prefix": "/", "shared_secret": SECRET.decode()}]
        private_write(config_path, config)
        run_upgrade(instance, responder, candidate, legacy, result["cases"])
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed"
        result["safe_failure_code"] = str(error) if isinstance(error, ScenarioFailure) else type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if responder is not None:
            responder.close()
        shutil.rmtree(root)
        after = source_identity(ROOT, candidate)
        result["binaries_unchanged"] = (after["binary_sha256"] == candidate_hash and file_hash(legacy) == legacy_hash)
        for field in ("source_commit", "source_tree", "source_dirty", "source_content_sha256"):
            result["harness_" + field] = before[field]
        result["harness_source_unchanged"] = before == after
        if not result["binaries_unchanged"] or file_hash(Path(__file__)) != runner_hash:
            result["status"], result["safe_failure_code"] = "failed", "binary_or_runner_changed_during_execution"
        result["finished_at_unix"] = time.time()
        if admit_output(output) != parent:
            raise ValueError("report_parent_changed")
        private_write(output, result, replace=False)
    print(json.dumps({"status": result["status"], "checks": len(result["cases"]),
                      "safe_failure_code": result.get("safe_failure_code")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
