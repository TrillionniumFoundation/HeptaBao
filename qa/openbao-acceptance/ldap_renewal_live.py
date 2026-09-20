#!/usr/bin/env python3
"""Compare selected LDAP renewals with official 2.6.2 and actual OpenLDAP.

Fresh private LDAP stores and synthetic credentials only. Configuration adapters
are explicit; this does not establish LDAP configuration API or AD parity.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash, successful_comparison
from online_evidence import source_identity
from ldap_openldap_live import Directory, private, ssha, Instance
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle
from radius_renewal_live import renewal_token_shape, wrapped_renewal_shape

USER_DN = "uid=alice,ou=people,dc=example,dc=test"
ADAPTATION = {
    "candidate": "host-enrolled LDAPS CA/address; user DN template and local user policy/TTL authority",
    "oracle": "LDAP config CA, service bind credentials, user/group search and mount token TTL",
    "disabled_credential": "delete LDAP userPassword; no claim about Active Directory account flags",
    "directory_observation": "fresh slapd do_bind/do_search log suffix; no LDAP log content in receipt",
    "configuration_api_parity": False,
}


class RenewalDirectory(Directory):
    def cursor(self):
        return (self.root / "slapd.log").stat().st_size

    def observed(self, cursor, *, search):
        # Debug output is fixture-private. Only booleans cross into the report.
        with (self.root / "slapd.log").open("rb") as stream:
            stream.seek(cursor)
            suffix = stream.read()
        return b"do_bind" in suffix and (not search or b"do_search" in suffix)

    def unchanged(self, cursor):
        return self.cursor() == cursor

    def password(self, value):
        change = self.root / "password-change.ldif"
        operation = ("delete: userPassword\n" if value is None else
                     "replace: userPassword\nuserPassword: " + ssha(value) + "\n")
        private(change, "dn: " + USER_DN + "\nchangetype: modify\n" + operation)
        subprocess.run(["ldapmodify", "-x", "-H", self.origin, "-D", self.admin_dn,
                        "-y", str(self.password_file), "-f", str(change)],
                       env=self.ldap_env, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15)


def configuration(side, directory, ca):
    if side == "candidate":
        return {"url": directory.origin, "bind_dn": directory.admin_dn,
                "user_dn_template": "uid={{username}},ou=people,dc=example,dc=test",
                "starttls": False, "group_dn": "ou=groups,dc=example,dc=test",
                "group_attr": "member", "group_name_attr": "cn"}
    return {"url": directory.origin, "binddn": directory.admin_dn,
            "bindpass": directory.admin_password, "userdn": "ou=people,dc=example,dc=test",
            "userattr": "uid", "groupdn": "ou=groups,dc=example,dc=test",
            "groupattr": "cn", "groupfilter": "(member={{.UserDN}})",
            "certificate": ca, "token_ttl": 60, "token_max_ttl": 600,
            "connection_timeout": 2, "request_timeout": 2}


def user_configuration(side, policies):
    if side == "candidate":
        return {"password": "synthetic-local-mapping-only", "policies": policies,
                "token_ttl": 60, "token_max_ttl": 600}
    return {"policies": policies}


class Trace:
    def __init__(self, client, directory, results):
        self.client, self.directory, self.results = client, directory, results

    def check(self, name, condition, **observed):
        case = "ldap_renewal." + name
        self.results.append({"case": case, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(case)

    def call(self, name, path, body=None, *, method="POST", token=None,
             expected=200, provider=None, wrap_ttl=None):
        cursor = self.directory.cursor()
        response = self.client.request(method, "/v1/" + path, body, token=token, wrap_ttl=wrap_ttl)
        observed = {"status": response.status}
        passed = response.status == expected
        if provider is not None:
            observed["provider_checked"] = self.directory.observed(cursor, search=provider == "search")
            passed &= observed["provider_checked"]
        self.check(name, passed, **observed)
        return response.body

    def ttl(self, name, token):
        body = self.call(name, "auth/token/lookup-self", method="GET", token=token)
        ttl = body.get("data", {}).get("ttl")
        self.check(name + ".shape", type(ttl) is int and ttl > 0)
        return ttl

    def login(self, name, mount):
        body = self.call(name, "auth/" + mount + "/login/alice",
                         {"password": self.directory.user_password}, provider="search")
        auth = body.get("auth", {})
        self.check(name + ".shape", all(isinstance(auth.get(key), str) and auth[key]
                                        for key in ("client_token", "accessor", "entity_id")))
        return auth

    def mount(self, name, config, user_config):
        self.call(name + ".mount", "sys/auth/" + name, {"type": "ldap"}, expected=204)
        self.call(name + ".config", "auth/" + name + "/config", config, expected=204)
        self.call(name + ".user", "auth/" + name + "/users/alice", user_config(["default"]),
                  method="PUT", expected=204)


def run_provider_scenarios(client, directory, config, user_config, restart, results):
    t = Trace(client, directory, results)
    mount = "ldap-renew"
    t.mount(mount, config, user_config)
    t.call("provider.policy", "sys/policies/acl/ldap-token-policy",
           {"policy": 'path "sys/health" { capabilities = ["read"] }'}, method="PUT", expected=204)
    mapping = "auth/" + mount + "/groups/engineering"
    t.call("provider.mapping", mapping, {"policies": ["ldap-token-policy"]}, method="PUT", expected=204)
    auth = t.login("provider.login", mount)
    token, accessor = auth["client_token"], auth["accessor"]
    t.check("provider.mapped_token_policy", "ldap-token-policy" in auth.get("token_policies", []))
    routes = [("self", "auth/token/renew-self", {}, token),
              ("token", "auth/token/renew", {"token": token}, None),
              ("accessor", "auth/token/renew-accessor", {"accessor": accessor}, None)]
    for name, path, payload, caller in routes:
        body = t.call(name + ".accepted", path, dict(payload, increment=120), token=caller, provider="search")
        renewed = body.get("auth", {})
        t.check(name + ".lease", renewed.get("renewable") is True
                and type(renewed.get("lease_duration")) is int and renewed["lease_duration"] > 0)
        t.check(name + ".bearer_shape", renewal_token_shape(renewed, token, via_accessor=name == "accessor"))
        before = t.ttl(name + ".before_reject", token)
        directory.password("synthetic-replaced-directory-password")
        t.call(name + ".password_changed", path, dict(payload, increment=300), token=caller,
               expected=400, provider="bind")
        after = t.ttl(name + ".after_reject", token)
        t.check(name + ".no_extension", after <= before)
        directory.password(directory.user_password)

    before = t.ttl("disabled.before", token)
    directory.password(None)
    t.call("disabled.password_absent", "auth/token/renew-self", {"increment": 300}, token=token,
           expected=400, provider="bind")
    t.check("disabled.no_extension", t.ttl("disabled.after", token) <= before)
    directory.password(directory.user_password)
    directory.stop()
    before = t.ttl("outage.before", token)
    t.call("outage.rejected", "auth/token/renew-self", {"increment": 300}, token=token, expected=400)
    t.check("outage.no_extension", t.ttl("outage.after", token) <= before)
    directory.start()
    t.call("outage.recovered", "auth/token/renew-self", {"increment": 120}, token=token, provider="search")

    before = t.ttl("group.before", token)
    directory.replace_engineering_member(directory.admin_dn)
    t.call("group.token_policy_changed", "auth/token/renew-self", {"increment": 300}, token=token,
           expected=500, provider="search")
    t.check("group.no_extension", t.ttl("group.after", token) <= before)
    directory.replace_engineering_member(USER_DN)
    t.call("group.restored", "auth/token/renew-self", {"increment": 120}, token=token, provider="search")
    t.call("mapping.changed", mapping, {"policies": []}, method="PUT", expected=204)
    t.call("mapping.renew_rejected", "auth/token/renew-self", {"increment": 300}, token=token,
           expected=500, provider="search")
    t.call("mapping.restored", mapping, {"policies": ["ldap-token-policy"]}, method="PUT", expected=204)

    wrapped = t.call("wrap.accepted", "auth/token/renew-self", {"increment": 120}, token=token,
                     provider="search", wrap_ttl="60s")
    t.check("wrap.opaque", wrapped_renewal_shape(wrapped, token))
    wrapper = wrapped["wrap_info"]["token"]
    body = t.call("wrap.unwrap", "sys/wrapping/unwrap", {"token": wrapper})
    t.check("wrap.target_restored", renewal_token_shape(body.get("auth"), token, via_accessor=False))
    t.call("wrap.single_use", "sys/wrapping/unwrap", {"token": wrapper}, expected=400)
    before = t.ttl("wrap.before_reject", token)
    directory.password("synthetic-replaced-directory-password")
    body = t.call("wrap.provider_rejected", "auth/token/renew-self", {"increment": 300}, token=token,
                  expected=400, provider="bind", wrap_ttl="60s")
    t.check("wrap.no_auth_or_wrapper", body.get("auth") is None and not body.get("wrap_info"))
    t.check("wrap.no_extension", t.ttl("wrap.after_reject", token) <= before)
    directory.password(directory.user_password)

    revoked = t.login("revocation.login", mount)["client_token"]
    t.call("revocation.revoke", "auth/token/revoke", {"token": revoked}, expected=204)
    cursor = directory.cursor()
    t.call("revocation.denied", "auth/token/renew-self", {"increment": 120}, token=revoked, expected=403)
    t.check("revocation.no_directory_operation", directory.unchanged(cursor))
    restart()
    t.check("restart.same_store", True)
    directory.password("synthetic-replaced-directory-password")
    t.call("restart.provider_rejects", "auth/token/renew-self", {"increment": 300}, token=token,
           expected=400, provider="bind")
    directory.password(directory.user_password)
    t.call("restart.provider_accepts", "auth/token/renew-self", {"increment": 120}, token=token, provider="search")


def identity_projection_matches(body, present, *, envelope):
    value = body.get(envelope, {})
    if not isinstance(value, dict):
        return False
    identity_values = value.get("identity_policies") or []
    token_values = value.get("token_policies", value.get("policies")) or []
    if not all(isinstance(items, list) and all(isinstance(item, str) for item in items)
               for items in (identity_values, token_values)):
        return False
    identity = set(identity_values)
    token = set(token_values)
    return (all((policy in identity) == enabled for policy, enabled in present.items())
            and not any(policy in token for policy in present))


def run_identity_scenarios(client, directory, config, user_config, restart, results):
    t = Trace(client, directory, results)
    mounts = ["ldap-alias", "ldap-other"]
    policies = ["ldap-identity-reader", "ldap-other-reader"]
    t.call("identity.mount_kv", "sys/mounts/ldap-identity-data",
           {"type": "kv", "options": {"version": "2"}}, expected=204)
    for index in range(2):
        t.mount(mounts[index], config, user_config)
        t.call("identity.seed." + str(index), "ldap-identity-data/data/item" + str(index),
               {"data": {"synthetic": True}})
        t.call("identity.policy." + str(index), "sys/policies/acl/" + policies[index],
               {"policy": 'path "ldap-identity-data/data/item' + str(index) + '" { capabilities = ["read"] }'},
               method="PUT", expected=204)
    registry = t.call("identity.mount_registry", "sys/auth", method="GET")["data"]
    accessors = [registry[mount + "/"]["accessor"] for mount in mounts]
    groups = []
    for index in range(2):
        group = t.call("identity.group." + str(index), "identity/group",
                       {"name": "ldap-external-" + str(index), "type": "external", "policies": [policies[index]]})["data"]["id"]
        groups.append(group)
        t.call("identity.group_alias." + str(index), "identity/group-alias",
               {"name": "engineering", "mount_accessor": accessors[index], "canonical_id": group})
    first = t.login("identity.first_login", mounts[0])
    token, entity = first["client_token"], first["entity_id"]
    t.call("identity.same_entity_other_alias", "identity/entity-alias",
           {"name": "alice", "mount_accessor": accessors[1], "canonical_id": entity})
    second = t.login("identity.other_login", mounts[1])
    t.check("identity.same_entity", second["entity_id"] == entity)
    other_token = second["client_token"]

    def verify(label, present, response=None):
        expected = dict(zip(policies, present))
        if response is not None:
            t.check(label + ".renew_projection", identity_projection_matches(response, expected, envelope="auth"))
        lookup = t.call(label + ".lookup", "auth/token/lookup-self", method="GET", token=token)
        t.check(label + ".lookup_projection", identity_projection_matches(lookup, expected, envelope="data"))
        for index, enabled in enumerate(present):
            group = t.call(label + ".group." + str(index), "identity/group/id/" + groups[index], method="GET")["data"]
            t.check(label + ".member." + str(index), (entity in (group.get("member_entity_ids") or [])) == enabled)
            t.call(label + ".permission." + str(index), "ldap-identity-data/data/item" + str(index),
                   method="GET", token=token, expected=200 if enabled else 403)

    verify("identity.initial", [True, True])
    directory.replace_engineering_member(directory.admin_dn)
    body = t.call("identity.remove_first.renew", "auth/token/renew-self", {"increment": 120}, token=token, provider="search")
    verify("identity.remove_first", [False, True], body)
    body = t.call("identity.remove_other.renew", "auth/token/renew-self", {"increment": 120}, token=other_token, provider="search")
    verify("identity.remove_other", [False, False], body)
    directory.replace_engineering_member(USER_DN)
    body = t.call("identity.restore_first.renew", "auth/token/renew-self", {"increment": 120}, token=token, provider="search")
    verify("identity.restore_first", [True, False], body)
    body = t.call("identity.restore_other.renew", "auth/token/renew-self", {"increment": 120}, token=other_token, provider="search")
    verify("identity.restore_other", [True, True], body)
    restart()
    t.check("identity.restart.same_store", True)
    verify("identity.restart.persisted", [True, True])
    directory.replace_engineering_member(directory.admin_dn)
    body = t.call("identity.restart.renew", "auth/token/renew-self", {"increment": 120}, token=token, provider="search")
    verify("identity.restart.refreshed", [False, True], body)
    directory.replace_engineering_member(USER_DN)



def run_finite_lifetime_scenarios(client, provider, configure, update_limits, restart, results):
    """Finite service lifetime only; no period/explicit configuration adaptation."""
    mount = 'ldap' + "-finite-lifetime"
    def check(name, passed, **observed):
        case = 'ldap' + "_renewal.finite." + name
        results.append({"case": case, **observed, "passed": bool(passed)})
        if not passed:
            raise ScenarioFailure(case)
    def call(name, method, path, payload=None, *, token=None, expected=200, contact=False):
        cursor = provider.cursor()
        response = client.request(method, "/v1/" + path, payload, token=token)
        safe = {"status": response.status}
        passed = response.status == expected
        if contact:
            safe["provider_checked"] = provider.observed(cursor, search=True)
            passed &= safe["provider_checked"]
        check(name, passed, **safe)
        return response.body
    call("mount", "POST", "sys/auth/" + mount, {"type": 'ldap'}, expected=204)
    configure(mount, 60, 120)
    check("initial_config", True)
    issued = call("login", "POST", "auth/" + mount + '/login/alice',
                  {"password": provider.user_password}, token="", contact=True)["auth"]
    raw, accessor = issued["client_token"], issued["accessor"]
    check("initial_ttl60", issued.get("lease_duration") == 60)
    data = call("lookup_initial", "GET", "auth/token/lookup-self", token=raw)["data"]
    check("ordinary_max_is_not_explicit", data.get("explicit_max_ttl") == 0)
    update_limits(mount, 120, 600)
    check("raised_current_max", True)
    routes = [("self", "auth/token/renew-self", {}, raw),
              ("token", "auth/token/renew", {"token": raw}, None),
              ("accessor", "auth/token/renew-accessor", {"accessor": accessor}, None)]
    for name, path, payload, actor in routes:
        renewed = call(name + ".raised_renew", "POST", path, dict(payload, increment=300),
                       token=actor, contact=True)["auth"]
        check(name + ".full300_beyond_issue_max", renewed.get("lease_duration") == 300)
    restart()
    check("same_store_restart", True)
    data = call("lookup_reopened", "GET", "auth/token/lookup-self", token=raw)["data"]
    check("no_explicit_cap_after_reopen", data.get("explicit_max_ttl") == 0)
    for name, payload in [("omitted", {}), ("zero", {"increment": 0})]:
        renewed = call(name + ".renew", "POST", "auth/token/renew-self", payload,
                       token=raw, contact=True)["auth"]
        check(name + ".current_ttl120", renewed.get("lease_duration") == 120)
    time.sleep(2)
    update_limits(mount, 1, 1)
    check("shrink_max_past_issue_age", True)
    for name, path, payload, actor in routes:
        before = call(name + ".before_past_max", "GET", "auth/token/lookup-self", token=raw)["data"]["ttl"]
        call(name + ".past_max500", "POST", path, payload, token=actor, expected=500, contact=True)
        after = call(name + ".lease_still_active", "GET", "auth/token/lookup-self", token=raw)["data"]["ttl"]
        check(name + ".failed_renewal_did_not_extend", type(after) is int and 0 < after <= before)
    check("complete", True)


def run_finite_scenarios(client, directory, config, user_config, restart, results):
    candidate = "user_dn_template" in config
    def checked(path, payload):
        response = client.request("POST", "/v1/" + path, payload)
        if response.status != 204:
            raise ScenarioFailure("ldap_renewal.finite.config_failed")
    def settings(mount, ttl, maximum):
        if candidate:
            checked("auth/" + mount + "/users/alice",
                    dict(user_config(["default"]), token_ttl=ttl, token_max_ttl=maximum))
        else:
            checked("auth/" + mount + "/config", dict(config, token_ttl=ttl, token_max_ttl=maximum))
    def configure(mount, ttl, maximum):
        checked("auth/" + mount + "/config", config if candidate else dict(config, token_ttl=ttl, token_max_ttl=maximum))
        checked("auth/" + mount + "/users/alice", user_config(["default"]))
        settings(mount, ttl, maximum)
    run_finite_lifetime_scenarios(client, directory, configure, settings, restart, results)


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).resolve()
    parent = output.parent.stat()
    if output.exists() or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        parser.error("private unused output required")
    root = Path(tempfile.mkdtemp(prefix="heptabao-ldap-renewal-"))
    root.chmod(0o700)
    source_before = source_identity(ROOT, binary)
    instance = None
    oracle = None
    directories = []
    result = {"schema": "heptabao.ldap-renewal-comparison.v1", "synthetic_only": True,
              "target_version": "2.6.2", "full_openbao_compatibility": False,
              "independent_qualification": False, "production_authority": False,
              "configuration_adaptation": ADAPTATION, "actual_openldap": True,
              "candidate_binary_sha256": file_hash(binary), "oracle_binary_sha256": BINARY_SHA256,
              "runner_sha256": file_hash(Path(__file__)), "cargo_lock_sha256": file_hash(ROOT / "Cargo.lock"),
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "started_at_unix": time.time(), "cases": {}, "side_failures": {}}
    try:
        instance = Instance(binary, root / "candidate")
        for name in ("candidate", "oracle"):
            directories.append(RenewalDirectory(root / (name + "-ldap"), instance.root / "tls.crt",
                                               instance.root / "tls.key", instance.root / "ca.crt"))
        candidate_directory, oracle_directory = directories
        ca = (instance.root / "ca.crt").read_text()
        cfg = json.loads((instance.root / "server.json").read_text())
        cfg["lifecycle_interval_seconds"] = 0
        cfg["outbound_endpoints"] = [{"origin": candidate_directory.origin,
            "address": "127.0.0.1:" + str(candidate_directory.port), "server_name": "127.0.0.1",
            "ca_pem": ca, "path_prefix": "/"}]
        private(instance.root / "server.json", json.dumps(cfg))
        instance.start()
        status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise ScenarioFailure("ldap_renewal.candidate_init")
        instance.token = init["root_token"]
        key = init["keys_base64"][0]
        if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
            raise ScenarioFailure("ldap_renewal.candidate_unseal")
        candidate = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        oracle = start_oracle(port)
        reference = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"], 8192).decode().strip())

        def restart_candidate():
            instance.stop()
            instance.start()
            if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                raise ScenarioFailure("ldap_renewal.candidate_restart_unseal")

        def restart_reference():
            oracle["process"].kill()
            oracle["process"].wait(timeout=5)
            stop_oracle(oracle)
            restart_oracle(oracle)

        for side, client, directory, restart in [("candidate", candidate, candidate_directory, restart_candidate),
                                                 ("oracle", reference, oracle_directory, restart_reference)]:
            result["cases"][side] = []
            for profile, runner in [("provider", run_provider_scenarios), ("identity", run_identity_scenarios), ("finite", run_finite_scenarios)]:
                try:
                    directory.start()
                    directory.password(directory.user_password)
                    directory.replace_engineering_member(USER_DN)
                    runner(client, directory, configuration(side, directory, ca),
                           lambda policies: user_configuration(side, policies), restart, result["cases"][side])
                except ScenarioFailure as error:
                    result["side_failures"][side + "." + profile] = str(error)
                except Exception as error:
                    result["side_failures"][side + "." + profile] = "unexpected_" + type(error).__name__
        result["cases_match"] = result["cases"].get("candidate") == result["cases"].get("oracle")
        complete = all(len(rows) == 201 and len({row["case"] for row in rows}) == 201
                       and rows[-1].get("case") == "ldap_renewal.finite.complete"
                       for rows in result["cases"].values()) and len(result["cases"]) == 2
        result["status"] = "passed" if complete and successful_comparison(result["cases"], result["side_failures"]) else "mismatch"
    except ScenarioFailure as error:
        result["status"] = "failed"
        result["safe_failure_code"] = str(error)
    except Exception as error:
        result["status"] = "failed"
        result["safe_failure_code"] = "unexpected_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if oracle is not None:
            stop_oracle(oracle)
            shutil.rmtree(oracle["root"])
        for directory in directories:
            directory.stop()
        shutil.rmtree(root)
        result["candidate_binary_unchanged"] = file_hash(binary) == result["candidate_binary_sha256"]
        result["source_identity"] = source_before
        result["source_and_binary_unchanged"] = source_before == source_identity(ROOT, binary)
        if not result["source_and_binary_unchanged"]:
            result["status"] = "failed"
            result["safe_failure_code"] = "source_or_binary_changed_during_execution"
        result["finished_at_unix"] = time.time()
        private_write(output, result)
    print(json.dumps({"status": result["status"], "checks_per_side": {side: len(rows) for side, rows in result["cases"].items()},
                      "side_failures": result["side_failures"], "safe_failure_code": result.get("safe_failure_code")}))
    return 0 if result["status"] == "passed" and result["candidate_binary_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
