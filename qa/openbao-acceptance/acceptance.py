#!/usr/bin/env python3
"""Synthetic, live HTTPS differential acceptance; never a full OpenBao certification."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from pathlib import Path

from bao_http import (BaoError, Client, SafeArgumentParser, digest, distinct_endpoints, private_json,
                      private_write, verify_oracle_identity)

CASES = {
    "core": ["unknown_route_denied"],
    "kv": ["mount", "write_v1", "read_v1", "write_v2", "read_old_version", "cas_rejected",
           "cas_no_effect", "list", "soft_delete", "deleted_read", "deleted_metadata",
           "undelete", "restored_read", "destroy_v1", "destroyed_read", "destroyed_metadata",
           "metadata_write", "metadata_read"],
    "token": ["policy", "create", "read_allowed", "write_denied", "denial_no_effect",
              "revoke", "revoked_denied", "invalid_denied", "create_expiring", "expired_denied"],
    "transit": ["mount", "create_key", "read_key", "encrypt_v1", "decrypt_v1", "rotate",
                "read_rotated_key", "encrypt_v2", "decrypt_v2", "decrypt_old_after_rotation"],
    "totp": ["roundtrip"],
    "userpass": ["login"],
    "approle": ["login"],
    "edge_tls": ["health"],
    "system": ["init_status"],
    "operations": ["seal_status"],
}


class Suite:
    def __init__(self, client: Client, run_id: str, modules: set[str], allow_writes: bool):
        self.client, self.run_id, self.modules = client, run_id, modules
        self.allow_writes = allow_writes
        self.kv, self.transit, self.totp, self.policy = (
            f"hbqa-{run_id}-{suffix}" for suffix in ("kv", "transit", "totp", "reader")
        )
        self.marker = "heptabao-synthetic-" + run_id
        self.results = {}
        self.requests = {}
        self.owned_mounts = []
        self.owned_auth_mounts = []
        self.owned_users = []
        self.owned_roles = []
        self.policy_owned = False
        self.child_tokens = []

    def call(self, case, method, path, payload=None, *, token=None):
        if method not in ("GET", "LIST", "HEAD") and not self.allow_writes:
            raise BaoError("test_write_opt_in_required")
        self.requests[case] = {"method": method, "path_template": path.replace(self.run_id, "{run_id}")}
        try:
            return self.client.request(method, path, payload, token=token)
        except BaoError as error:
            self.results[case] = {"result": "failed", "reason": error.code,
                                  "http_status": None, "semantics": {}}
            raise

    def check(self, case, response, status, **semantics):
        expected = (status,) if isinstance(status, int) else status
        passed = response.status in expected and all(v is True for v in semantics.values())
        self.results[case] = {"result": "passed" if passed else "failed", "http_status": response.status,
                              "expected_http_status": list(expected), "semantics": semantics,
                              **self.requests.get(case, {})}
        if not passed:
            raise BaoError("case_status_or_semantics_mismatch")
        return response

    def perform(self, case, method, path, payload=None, status=204, *, token=None):
        return self.check(case, self.call(case, method, path, payload, token=token), status)

    def mount(self, kind, mount):
        inventory = self.client.request("GET", "/v1/sys/mounts")
        if inventory.status != 200 or mount + "/" in inventory.data():
            raise BaoError("cannot_prove_synthetic_mount_absent")
        if kind not in {"kv", "transit", "totp"}:
            raise BaoError("unsupported_fixture_mount_kind")
        payload = {"type": kind, "description": self.marker}
        if kind == "kv":
            payload["options"] = {"version": "2"}
        self.perform(kind + ".mount", "POST", "/v1/sys/mounts/" + mount, payload)
        self.owned_mounts.append(mount)

    def ensure_auth_mount(self, kind):
        inventory = self.client.request("GET", "/v1/sys/auth")
        if inventory.status != 200:
            raise BaoError("cannot_read_auth_mount_inventory")
        existing = inventory.data().get(kind + "/")
        if existing is not None:
            if not isinstance(existing, dict) or existing.get("type") != kind:
                raise BaoError("auth_mount_type_mismatch")
            return
        response = self.client.request(
            "POST", "/v1/sys/auth/" + kind, {"type": kind, "description": self.marker}
        )
        if response.status != 204:
            raise BaoError("auth_mount_enable_failed")
        self.owned_auth_mounts.append(kind)

    def core_cases(self):
        path = "/v1/hbqa-" + self.run_id + "-unsupported"
        r = self.call("core.unknown_route_denied", "GET", path)
        self.check(
            "core.unknown_route_denied",
            r,
            404,
            error_envelope=isinstance(r.body.get("errors"), list) and bool(r.body["errors"]),
        )

    def kv_cases(self):
        self.mount("kv", self.kv)
        path = "/v1/" + self.kv
        one = {"synthetic": "fixture-one", "typed": [True, 7, {"nested": "alpha"}]}
        two = {"synthetic": "fixture-two", "typed": [False, 8, {"nested": "beta"}]}
        r = self.call("kv.write_v1", "POST", path + "/data/item", {"data": one, "options": {"cas": 0}})
        self.check("kv.write_v1", r, 200, version_is_one=r.data().get("version") == 1)
        r = self.call("kv.read_v1", "GET", path + "/data/item")
        self.check("kv.read_v1", r, 200, exact_data=r.data().get("data") == one,
                   version_is_one=r.data().get("metadata", {}).get("version") == 1)
        r = self.call("kv.write_v2", "POST", path + "/data/item", {"data": two, "options": {"cas": 1}})
        self.check("kv.write_v2", r, 200, version_is_two=r.data().get("version") == 2)
        r = self.call("kv.read_old_version", "GET", path + "/data/item?version=1")
        self.check("kv.read_old_version", r, 200, exact_old_data=r.data().get("data") == one)
        r = self.call("kv.cas_rejected", "POST", path + "/data/item", {"data": one, "options": {"cas": 1}})
        self.check("kv.cas_rejected", r, 400, errors_present=isinstance(r.body.get("errors"), list) and bool(r.body["errors"]))
        r = self.call("kv.cas_no_effect", "GET", path + "/data/item")
        self.check("kv.cas_no_effect", r, 200, current_data_unchanged=r.data().get("data") == two,
                   version_unchanged=r.data().get("metadata", {}).get("version") == 2)
        r = self.call("kv.list", "LIST", path + "/metadata/")
        self.check("kv.list", r, 200, exact_key_listing=r.data().get("keys") == ["item"])
        self.perform("kv.soft_delete", "DELETE", path + "/data/item")
        self.perform("kv.deleted_read", "GET", path + "/data/item", status=404)
        r = self.call("kv.deleted_metadata", "GET", path + "/metadata/item")
        v = r.data().get("versions", {}).get("2", {})
        self.check("kv.deleted_metadata", r, 200, tombstone_present=bool(v.get("deletion_time")),
                   not_destroyed=v.get("destroyed") is False, generation_preserved=r.data().get("current_version") == 2)
        self.perform("kv.undelete", "POST", path + "/undelete/item", {"versions": [2]})
        r = self.call("kv.restored_read", "GET", path + "/data/item")
        self.check("kv.restored_read", r, 200, exact_restored_data=r.data().get("data") == two)
        self.perform("kv.destroy_v1", "POST", path + "/destroy/item", {"versions": [1]})
        self.perform("kv.destroyed_read", "GET", path + "/data/item?version=1", status=404)
        r = self.call("kv.destroyed_metadata", "GET", path + "/metadata/item")
        self.check("kv.destroyed_metadata", r, 200,
                   destroyed=r.data().get("versions", {}).get("1", {}).get("destroyed") is True)
        self.perform("kv.metadata_write", "POST", path + "/metadata/item",
                     {"custom_metadata": {"qa": "synthetic"}, "cas_required": True, "max_versions": 5})
        r = self.call("kv.metadata_read", "GET", path + "/metadata/item")
        self.check("kv.metadata_read", r, 200, custom_metadata=r.data().get("custom_metadata") == {"qa": "synthetic"},
                   cas_required=r.data().get("cas_required") is True, max_versions=r.data().get("max_versions") == 5)

    def token_cases(self):
        if self.results.get("kv.metadata_read", {}).get("result") != "passed":
            raise BaoError("token_cases_require_successful_kv_fixture")
        policy_path = "/v1/sys/policies/acl/" + self.policy
        exists = self.client.request("GET", policy_path)
        if exists.status != 404:
            raise BaoError("cannot_prove_synthetic_policy_absent")
        self.perform("token.policy", "POST", policy_path,
                     {"policy": 'path "' + self.kv + '/data/*" { capabilities = ["read"] }'})
        self.policy_owned = True
        path = "/v1/" + self.kv + "/data/item"
        r = self.call("token.create", "POST", "/v1/auth/token/create",
                      {"policies": [self.policy], "no_default_policy": True, "ttl": "30s", "renewable": False})
        auth = r.body.get("auth") or {}
        child = auth.get("client_token")
        if isinstance(child, str) and child:
            self.child_tokens.append(child)
        self.check("token.create", r, 200, token_issued=isinstance(child, str) and bool(child),
                   no_root_policy="root" not in auth.get("policies", []),
                   requested_policy=self.policy in auth.get("policies", []))
        self.perform("token.read_allowed", "GET", path, status=200, token=child)
        self.perform("token.write_denied", "POST", path, {"data": {"synthetic": "must-never-appear"}, "options": {"cas": 2}},
                     status=403, token=child)
        r = self.call("token.denial_no_effect", "GET", path)
        self.check("token.denial_no_effect", r, 200, version_unchanged=r.data().get("metadata", {}).get("version") == 2,
                   data_unchanged=r.data().get("data", {}).get("synthetic") == "fixture-two")
        self.perform("token.revoke", "POST", "/v1/auth/token/revoke", {"token": child})
        self.child_tokens.remove(child)
        self.perform("token.revoked_denied", "GET", path, status=403, token=child)
        self.perform("token.invalid_denied", "GET", path, status=403, token="hbqa-invalid-" + self.run_id)
        r = self.call("token.create_expiring", "POST", "/v1/auth/token/create",
                      {"policies": [self.policy], "no_default_policy": True, "ttl": "2s",
                       "explicit_max_ttl": "2s", "renewable": False})
        auth = r.body.get("auth") or {}
        expiring, ttl = auth.get("client_token"), auth.get("lease_duration")
        if isinstance(expiring, str) and expiring:
            self.child_tokens.append(expiring)
        self.check("token.create_expiring", r, 200, token_issued=isinstance(expiring, str) and bool(expiring),
                   bounded_ttl=isinstance(ttl, (int, float)) and 0 < ttl <= 2)
        time.sleep(float(ttl) + 0.3)
        self.perform("token.expired_denied", "GET", path, status=403, token=expiring)

    def transit_cases(self):
        self.mount("transit", self.transit)
        path = "/v1/" + self.transit
        plain = base64.b64encode(b"HeptaBao synthetic transit acceptance only").decode("ascii")
        r = self.call("transit.create_key", "POST", path + "/keys/item", {"type": "aes256-gcm96"})
        self.check("transit.create_key", r, 200, latest_version=r.data().get("latest_version") == 1,
                   key_type=r.data().get("type") == "aes256-gcm96")
        r = self.call("transit.read_key", "GET", path + "/keys/item")
        self.check("transit.read_key", r, 200, latest_version=r.data().get("latest_version") == 1,
                   key_type=r.data().get("type") == "aes256-gcm96")
        ciphertexts = []
        for version in (1, 2):
            if version == 2:
                r = self.call("transit.rotate", "POST", path + "/keys/item/rotate", {})
                self.check("transit.rotate", r, 200, latest_version=r.data().get("latest_version") == 2)
                r = self.call("transit.read_rotated_key", "GET", path + "/keys/item")
                self.check("transit.read_rotated_key", r, 200, latest_version=r.data().get("latest_version") == 2)
            case = f"transit.encrypt_v{version}"
            r = self.call(case, "POST", path + "/encrypt/item", {"plaintext": plain})
            ciphertext = r.data().get("ciphertext")
            self.check(case, r, 200, versioned_ciphertext=isinstance(ciphertext, str) and ciphertext.startswith(f"vault:v{version}:"))
            ciphertexts.append(ciphertext)
            case = f"transit.decrypt_v{version}"
            r = self.call(case, "POST", path + "/decrypt/item", {"ciphertext": ciphertext})
            self.check(case, r, 200, exact_roundtrip=r.data().get("plaintext") == plain)
        r = self.call("transit.decrypt_old_after_rotation", "POST", path + "/decrypt/item", {"ciphertext": ciphertexts[0]})
        self.check("transit.decrypt_old_after_rotation", r, 200, old_key_retained=r.data().get("plaintext") == plain)

    def totp_cases(self):
        self.mount("totp", self.totp)
        path = "/v1/" + self.totp
        key_name = "fixture"
        imported = {
            "key": "JBSWY3DPEHPK3PXP",
            "issuer": "HeptaBao-QA",
            "account_name": "synthetic@example.invalid",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
            "skew": 1,
        }
        created = self.call("totp.roundtrip", "POST", path + "/keys/" + key_name, imported)
        if created.status not in (200, 204):
            self.check("totp.roundtrip", created, (200, 204), key_created=False)
            return
        code_response = self.client.request("GET", path + "/code/" + key_name)
        code = code_response.data().get("code") if code_response.status == 200 else None
        validation = self.client.request(
            "POST", path + "/code/" + key_name, {"code": code} if isinstance(code, str) else {"code": ""}
        )
        self.requests["totp.roundtrip"] = {
            "method": "MULTI",
            "path_template": path.replace(self.run_id, "{run_id}") + "/{keys,code}/fixture",
        }
        self.check(
            "totp.roundtrip", validation, 200,
            key_created=created.status in (200, 204),
            code_generated=isinstance(code, str) and len(code) == 6 and code.isdigit(),
            validation_true=validation.data().get("valid") is True,
        )

    def userpass_cases(self):
        self.ensure_auth_mount("userpass")
        username = "hbqa-" + self.run_id
        password = "HeptaBao-QA-" + self.run_id + "-Password"
        user_path = "/v1/auth/userpass/users/" + username
        created = self.client.request(
            "POST", user_path, {"password": password, "token_policies": ["default"]}
        )
        if created.status != 204:
            raise BaoError("userpass_fixture_user_create_failed")
        self.owned_users.append(username)
        r = self.call("userpass.login", "POST", "/v1/auth/userpass/login/" + username, {"password": password})
        auth = r.body.get("auth") or {}
        child = auth.get("client_token")
        if isinstance(child, str) and child:
            self.child_tokens.append(child)
        self.check(
            "userpass.login", r, 200,
            token_issued=isinstance(child, str) and bool(child),
            default_policy="default" in auth.get("policies", []),
        )

    def approle_cases(self):
        self.ensure_auth_mount("approle")
        role = "hbqa-" + self.run_id
        role_path = "/v1/auth/approle/role/" + role
        created = self.client.request(
            "POST", role_path, {"token_policies": ["default"], "secret_id_num_uses": 1}
        )
        if created.status != 204:
            raise BaoError("approle_fixture_role_create_failed")
        self.owned_roles.append(role)
        role_id_response = self.client.request("GET", role_path + "/role-id")
        role_id = role_id_response.data().get("role_id") if role_id_response.status == 200 else None
        secret_response = self.client.request("POST", role_path + "/secret-id", {})
        secret_id = secret_response.data().get("secret_id") if secret_response.status == 200 else None
        payload = {
            "role_id": role_id if isinstance(role_id, str) else "",
            "secret_id": secret_id if isinstance(secret_id, str) else "",
        }
        r = self.call("approle.login", "POST", "/v1/auth/approle/login", payload)
        auth = r.body.get("auth") or {}
        child = auth.get("client_token")
        if isinstance(child, str) and child:
            self.child_tokens.append(child)
        self.check(
            "approle.login", r, 200,
            role_id_observed=isinstance(role_id, str) and bool(role_id),
            secret_id_observed=isinstance(secret_id, str) and bool(secret_id),
            token_issued=isinstance(child, str) and bool(child),
            default_policy="default" in auth.get("policies", []),
        )

    def edge_tls_cases(self):
        r = self.call("edge_tls.health", "GET", "/v1/sys/health")
        self.check("edge_tls.health", r, 200, initialized=r.body.get("initialized") is True, unsealed=r.body.get("sealed") is False)

    def system_cases(self):
        r = self.call("system.init_status", "GET", "/v1/sys/init")
        self.check("system.init_status", r, 200, initialized=r.body.get("initialized") is True)

    def operations_cases(self):
        r = self.call("operations.seal_status", "GET", "/v1/sys/seal-status")
        self.check("operations.seal_status", r, 200, initialized=r.body.get("initialized") is True, unsealed=r.body.get("sealed") is False)

    def cleanup(self):
        failures = 0
        for token in self.child_tokens:
            try:
                if self.client.request("POST", "/v1/auth/token/revoke", {"token": token}).status != 204:
                    failures += 1
            except BaoError:
                failures += 1
        for username in self.owned_users:
            try:
                if self.client.request("DELETE", "/v1/auth/userpass/users/" + username).status != 204:
                    failures += 1
            except BaoError:
                failures += 1
        for role in self.owned_roles:
            try:
                if self.client.request("DELETE", "/v1/auth/approle/role/" + role).status != 204:
                    failures += 1
            except BaoError:
                failures += 1
        for kind in reversed(self.owned_auth_mounts):
            try:
                inventory = self.client.request("GET", "/v1/sys/auth")
                entry = inventory.data().get(kind + "/") if inventory.status == 200 else None
                if not isinstance(entry, dict) or entry.get("type") != kind:
                    failures += 1
                    continue
                if self.client.request("DELETE", "/v1/sys/auth/" + kind).status != 204:
                    failures += 1
            except BaoError:
                failures += 1
        if self.policy_owned:
            try:
                if self.client.request("DELETE", "/v1/sys/policies/acl/" + self.policy).status != 204:
                    failures += 1
            except BaoError:
                failures += 1
        for mount in reversed(self.owned_mounts):
            try:
                inventory = self.client.request("GET", "/v1/sys/mounts")
                if inventory.status != 200 or inventory.data().get(mount + "/", {}).get("description") != self.marker:
                    failures += 1
                    continue
                if self.client.request("DELETE", "/v1/sys/mounts/" + mount).status != 204:
                    failures += 1
            except BaoError:
                failures += 1
        return {"result": "passed" if failures == 0 else "failed", "failure_count": failures,
                "scope": "only_newly_created_synthetic_resources", "run_id": self.run_id}

    def run(self):
        cleanup = {"result": "not_run", "reason": "writes_not_authorized"}
        try:
            for module in ("core", "kv", "token", "transit", "totp", "userpass", "approle", "edge_tls", "system", "operations"):
                if module not in self.modules or not self.allow_writes:
                    continue
                try:
                    getattr(self, module + "_cases")()
                except BaoError as error:
                    for case in CASES[module]:
                        name = module + "." + case
                        if name not in self.results:
                            self.results[name] = {"result": "not_run", "reason": error.code}
                except (TypeError, AttributeError, KeyError, ValueError):
                    self.results[module + ".response_schema"] = {"result": "failed", "reason": "unexpected_response_schema"}
        finally:
            if self.allow_writes:
                cleanup = self.cleanup()
        for module, names in CASES.items():
            for name in names:
                self.results.setdefault(module + "." + name, {"result": "not_run", "reason": "module_not_selected_or_writes_not_authorized"})
        return {"cases": self.results, "cleanup": cleanup}


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--compare", action="store_true")
    mode.add_argument("--candidate-only", action="store_true")
    parser.add_argument("--candidate-prefix", default="HB_CANDIDATE")
    parser.add_argument("--oracle-prefix", default="HB_ORACLE")
    parser.add_argument("--oracle-identity-file")
    parser.add_argument("--allow-test-writes", action="store_true")
    parser.add_argument("--modules", default="core,kv,token,transit,totp,userpass,approle,edge_tls,system,operations")
    parser.add_argument("--output", help="0600 JSON in an existing 0700 directory")
    args = parser.parse_args(argv)
    report = {"schema": "heptabao.live-acceptance.v1", "target": "OpenBao 2.6.2",
              "observed_at_unix": time.time(),
              "tool_source_sha256": hashlib.sha256(Path(__file__).read_bytes() + Path(__file__).with_name("bao_http.py").read_bytes()).hexdigest(),
              "full_openbao_compatibility": False, "production_qualified": False,
              "mode": "differential" if args.compare else "candidate_smoke",
              "status": "not_run", "cases_match": False}
    code = 2
    try:
        modules = set(args.modules.split(","))
        if not modules or not modules <= set(CASES) or ("token" in modules and "kv" not in modules):
            raise BaoError("invalid_modules_or_token_missing_kv_dependency")
        candidate = Client.from_env(args.candidate_prefix)
        candidate_health = candidate.health()
        report["candidate"] = {"endpoint": candidate.address, "namespace_digest": digest(candidate.namespace),
                               "version": candidate_health["version"], "cluster_id_digest": digest(candidate_health["cluster_id"])}
        oracle = None
        if args.compare:
            if not args.oracle_identity_file:
                raise BaoError("independent_oracle_identity_file_required")
            oracle = Client.from_env(args.oracle_prefix)
            health = oracle.health()
            distinct_endpoints(candidate, candidate_health, oracle, health)
            report["oracle"] = verify_oracle_identity(private_json(args.oracle_identity_file), oracle, health)
            report["oracle"]["endpoint"] = oracle.address
            report["oracle"]["cluster_id_digest"] = digest(health["cluster_id"])
        run_id = secrets.token_hex(8)
        # The actual Oracle always runs first, on an isolated fresh synthetic mount.
        if oracle:
            report["oracle_results"] = Suite(oracle, run_id, modules, args.allow_test_writes).run()
        report["candidate_results"] = Suite(candidate, run_id, modules, args.allow_test_writes).run()
        selected = [module + "." + name for module in modules for name in CASES[module]]
        sides = [report["candidate_results"]] + ([report["oracle_results"]] if oracle else [])
        passed = all(side["cleanup"]["result"] == "passed" and
                     all(side["cases"][name]["result"] == "passed" for name in selected) for side in sides)
        if oracle:
            report["mismatched_cases"] = [name for name in selected if
                report["oracle_results"]["cases"][name] != report["candidate_results"]["cases"][name]]
            report["cases_match"] = passed and not report["mismatched_cases"]
            passed = report["cases_match"]
        report["status"] = "passed_scoped_cases" if passed else ("not_run" if not args.allow_test_writes else "failed")
        report["scope"] = sorted(modules)
        report["uncovered"] = ["full_endpoint_error_precedence", "other_auth_methods", "other_secret_engines",
                               "persistent_restart", "ha", "migration", "upgrade", "agent_proxy_cli", "production_security"]
        code = 0 if passed else 2
    except BaoError as error:
        report["status"], report["reason"] = "failed", error.code
    except (UnicodeError, TypeError, AttributeError, ValueError):
        report["status"], report["reason"] = "failed", "invalid_configuration_or_response"
    if args.output:
        try:
            private_write(args.output, report)
        except BaoError as error:
            print(json.dumps({"status": "failed", "reason": error.code}))
            return 2
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
