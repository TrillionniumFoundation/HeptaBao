#!/usr/bin/env python3
"""Selected native LDAP APIs with actual OpenLDAP and pinned OpenBao 2.6.2.

Both sides configure LDAPS authority through the standard URL and CA fields.
The candidate runs with no process-enrolled outbound endpoints. This profile does not establish general LDAP/AD API parity.
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
from urllib.parse import quote

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from ldap_renewal_live import RenewalDirectory, USER_DN, renewal_token_shape, wrapped_renewal_shape
from ldap_openldap_live import Instance, private, ssha
from official_openbao_launcher import start_oracle, stop_oracle, restart_oracle, BINARY_SHA256, certificates
from online_evidence import admit_output, source_identity
from ldap_transport_tls_probe import wrong_san_probe, san_rejection_observed

ADAPTATION = {
    "candidate": "native URL, certificate and timeout fields; no process-enrolled LDAPS endpoints",
    "oracle": "native LDAP API fields with certificate CA supplied in auth configuration",
    "directory": "real local OpenLDAP; synthetic users, manager account and groups",
    "filters": "bounded AND/OR/NOT/equality/presence and Username/UserDN/UserAttr templates",
    "excluded": "StartTLS/SASL/referrals/paging, substring/matching rules and arbitrary Go templates",
    "configuration_api_parity": False,
}
USER_FILTER = "({{.UserAttr}}={{.Username}})"
GROUP_FILTER = "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))"


class NativeDirectory(RenewalDirectory):
    def add_user(self, cn, uid):
        dn = "cn=" + cn + ",ou=people,dc=example,dc=test"
        path = self.root / "native-add.ldif"
        private(path, "dn: " + dn + "\nobjectClass: inetOrgPerson\ncn: " + cn +
                "\nsn: Example\nuid: " + uid + "\nuserPassword: " + ssha(self.user_password) + "\n")
        subprocess.run(["ldapadd", "-x", "-H", self.origin, "-D", self.admin_dn,
                        "-y", str(self.password_file), "-f", str(path)], env=self.ldap_env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
        return dn

    def alias_attribute(self, values):
        path = self.root / "native-alias-attribute.ldif"
        change = ("replace: description\n" + "".join("description: " + value + "\n" for value in values)
                  if values else "delete: description\n")
        private(path, "dn: " + USER_DN + "\nchangetype: modify\n" + change)
        subprocess.run(["ldapmodify", "-x", "-H", self.origin, "-D", self.admin_dn,
                        "-y", str(self.password_file), "-f", str(path)], env=self.ldap_env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)

    def delete_user(self, dn):
        subprocess.run(["ldapdelete", "-x", "-H", self.origin, "-D", self.admin_dn,
                        "-y", str(self.password_file), dn], env=self.ldap_env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)


def configuration(side, directory, ca, **options):
    data = {"url": directory.origin, "binddn": directory.admin_dn,
            "bindpass": directory.admin_password, "userdn": "ou=people,dc=example,dc=test",
            "userattr": "uid", "groupdn": "ou=groups,dc=example,dc=test", "groupattr": "cn",
            "token_ttl": 0, "token_max_ttl": 600, "token_policies": [], **options}
    data.setdefault("certificate", ca)
    data.setdefault("connection_timeout", 2)
    data.setdefault("request_timeout", 2)
    return data


def mapping_matches(data, groups, policies):
    return data.get("groups") == groups and data.get("policies") == policies


def config_matches(data, **fields):
    return "bindpass" not in data and all(type(data.get(key)) is type(value) and data[key] == value
                                          for key, value in fields.items())


class Trace:
    def __init__(self, client, directory, config, results):
        self.client, self.directory, self.config, self.results = client, directory, config, results

    def check(self, name, passed, **safe):
        case = "ldap_native." + name
        self.results.append({"case": case, **safe, "passed": bool(passed)})
        if not passed:
            raise ScenarioFailure(case)

    def call(self, name, path, body=None, *, method="POST", token=None,
             expected=200, provider=False, wrap_ttl=None):
        cursor = self.directory.cursor()
        r = self.client.request(method, "/v1/" + path, body, token=token, wrap_ttl=wrap_ttl)
        safe = {"status": r.status}
        passed = r.status == expected
        if provider:
            safe["provider_checked"] = self.directory.observed(cursor, search=True)
            passed &= safe["provider_checked"]
        self.check(name, passed, **safe)
        return r.body

    def mount(self, name, **options):
        mount = "native-" + name
        self.call(name + ".mount", "sys/auth/" + mount, {"type": "ldap"}, expected=204)
        self.call(name + ".config", "auth/" + mount + "/config",
                  dict(self.config, **options), expected=204)
        self.call(name + ".tune", "sys/auth/" + mount + "/tune",
                  {"default_lease_ttl": 75, "max_lease_ttl": 600}, expected=204)
        return mount

    def update(self, name, mount, **options):
        self.call(name, "auth/" + mount + "/config", options, expected=204)

    def login(self, name, mount, username="alice", *, ttl=75, policies=("default",),
              expected=200, password=None):
        body = self.call(name, "auth/" + mount + "/login/" + quote(username, safe=""),
                         {"password": self.directory.user_password if password is None else password},
                         token="", expected=expected, provider=True)
        if expected != 200:
            return body
        auth = body.get("auth", {})
        self.check(name + ".auth", isinstance(auth.get("client_token"), str)
                   and bool(auth["client_token"]) and isinstance(auth.get("entity_id"), str)
                   and bool(auth["entity_id"]) and auth.get("lease_duration") == ttl
                   and set(auth.get("token_policies", [])) == set(policies))
        return auth

    def alias(self, name, auth, alias, username):
        body = self.call(name, "identity/entity/id/" + auth["entity_id"], method="GET")
        self.check(name + ".name", any(a.get("name") == alias for a in body["data"]["aliases"])
                   and auth.get("metadata", {}).get("username") == username)

    def lookup(self, name, auth):
        return self.call(name, "auth/token/lookup-self", method="GET", token=auth["client_token"])["data"]

    def renew(self, name, auth, *, via="self", increment=None, ttl=75, expected=200):
        path, body, actor = {
            "self": ("auth/token/renew-self", {}, auth["client_token"]),
            "token": ("auth/token/renew", {"token": auth["client_token"]}, None),
            "accessor": ("auth/token/renew-accessor", {"accessor": auth["accessor"]}, None),
        }[via]
        if increment is not None:
            body["increment"] = increment
        result = self.call(name, path, body, token=actor, expected=expected, provider=True)
        if expected == 200:
            renewed = result.get("auth", {})
            actual = renewed.get("lease_duration")
            valid_ttl = (type(actual) is int and ttl[0] <= actual <= ttl[1]
                         if isinstance(ttl, tuple) else actual == ttl)
            self.check(name + ".lease", valid_ttl and renewal_token_shape(
                renewed, auth["client_token"], via_accessor=via == "accessor"))
        return result

    def policy(self, name, rule='path "cubbyhole/*" { capabilities = ["read"] }'):
        self.call("policy." + name, "sys/policies/acl/" + name, {"policy": rule}, expected=204)



def run_transport_scenarios(t, alternate_ca, probe_root, oracle_root):
    m = t.mount("transport", url=t.directory.origin.replace("127.0.0.1", "localhost"))
    auth = t.login("transport.dns_login", m)
    for via in ("self", "token", "accessor"):
        t.renew("transport.dns_renew_" + via, auth, via=via)
    data = t.call("transport.read", "auth/" + m + "/config", method="GET")["data"]
    t.check("transport.fields", config_matches(data, certificate=t.config["certificate"],
            connection_timeout=2, request_timeout=2))
    t.update("transport.wrong_ca", m, certificate=alternate_ca)
    before = t.lookup("transport.before_wrong_ca", auth)["expire_time"]
    for via in ("self", "token", "accessor"):
        path, payload, actor = {
            "self": ("auth/token/renew-self", {}, auth["client_token"]),
            "token": ("auth/token/renew", {"token": auth["client_token"]}, None),
            "accessor": ("auth/token/renew-accessor", {"accessor": auth["accessor"]}, None),
        }[via]
        t.call("transport.wrong_ca_reject_" + via, path, payload, token=actor, expected=400)
    t.check("transport.failed_lease_unchanged",
            t.lookup("transport.after_wrong_ca", auth)["expire_time"] == before)
    t.update("transport.restore_ca", m, certificate=t.config["certificate"])
    t.renew("transport.restored_without_restart", auth)
    t.call("transport.invalid_pem", "auth/" + m + "/config", {"certificate": "not-a-certificate"}, expected=400)
    t.renew("transport.invalid_write_preserved_authority", auth)
    t.update("transport.clear_ca", m, certificate=None)
    data = t.call("transport.empty_ca_read", "auth/" + m + "/config", method="GET")["data"]
    t.check("transport.empty_ca_is_system_roots", data.get("certificate") == "")
    t.call("transport.private_ca_not_system_trusted", "auth/" + m + "/login/alice",
           {"password": t.directory.user_password}, token="", expected=400)
    t.update("transport.restore_again", m, certificate=t.config["certificate"],
             connection_timeout=None, request_timeout=None)
    data = t.call("transport.default_timeouts_read", "auth/" + m + "/config", method="GET")["data"]
    t.check("transport.default_timeouts", config_matches(data, connection_timeout=30, request_timeout=90))
    t.renew("transport.default_timeouts_work", auth)
    with wrong_san_probe(probe_root, oracle_root / "ca.crt", oracle_root / "ca.key") as probe:
        t.update("transport.wrong_san_target", m, url=probe.origin)
        t.call("transport.wrong_san_rejected", "auth/" + m + "/login/alice",
               {"password": t.directory.user_password}, token="", expected=400)
        evidence = probe.wait()
        t.check("transport.wrong_san_before_ldap", san_rejection_observed(evidence), **evidence)
    t.update("transport.restore_target", m, url=t.directory.origin)
    t.renew("transport.restored_after_san_rejection", auth)
    # The CA rotation applies to existing direct tokens on the next exchange.
    t.check("transport.complete", True)


def run_directory_scenarios(t):
    # Actual Oracle 2.6.2 accepts uppercase URL scheme and user attribute,
    # stores both lowercase, and uses the normalized endpoint on login.
    case_mount = t.mount("config-case", userattr="UID", url=t.directory.origin.upper())
    for phase in ("create", "partial"):
        if phase == "partial":
            t.update("config_case.partial", case_mount, userattr="UID", url=t.directory.origin.upper())
        data = t.call("config_case." + phase + ".read", "auth/" + case_mount + "/config", method="GET")["data"]
        t.check("config_case." + phase + ".normalized",
                config_matches(data, userattr="uid", url=t.directory.origin))
        t.login("config_case." + phase + ".login", case_mount)
    mount = t.mount("directory")
    data = t.call("config.read", "auth/" + mount + "/config", method="GET")["data"]
    t.check("config.defaults", config_matches(data, userattr="uid", userfilter=USER_FILTER,
             groupattr="cn", groupfilter=GROUP_FILTER, case_sensitive_names=False,
             username_as_alias=False, token_ttl=0, token_max_ttl=600, token_period=0,
             token_explicit_max_ttl=0, token_policies=[], token_num_uses=0))
    t.call("no_mapping.list_empty", "auth/" + mount + "/users", method="LIST", expected=404)
    auth = t.login("no_mapping.uppercase_login", mount, "ALICE")
    t.alias("no_mapping.alias", auth, "alice", "alice")
    for via in ("self", "token", "accessor"):
        t.renew("no_mapping.renew_" + via, auth, via=via)
    t.login("no_user_dn", mount, "missing", expected=400)
    t.login("bad_password", mount, expected=400, password="synthetic-wrong-password")
    dn = t.directory.add_user("Duplicate", "alice")
    try:
        t.login("multiple_user_dn", mount, expected=400)
    finally:
        t.directory.delete_user(dn)
    t.update("filter.bounded", mount,
             userfilter="(&({{.UserAttr}}={{.Username}})(|(objectClass=inetOrgPerson)(objectClass=person))(!(sn=Blocked))(cn=*))",
             groupfilter="(&(objectClass=groupOfNames)(|(member={{.UserDN}})(memberUid={{.Username}})))")
    t.login("filter.allowed_boolean_profile", mount)
    t.directory.stop()
    t.call("provider_down", "auth/" + mount + "/login/alice",
           {"password": t.directory.user_password}, token="", expected=400)
    t.directory.start()
    t.login("provider_recovered", mount)
    t.directory.add_user("Case Person", "MixedUID")
    for label, opts, alias, username in [
        ("attribute", {}, "MixedUID", "mixeduid"),
        ("username", {"username_as_alias": True}, "mixeduid", "mixeduid"),
        ("exact", {"username_as_alias": True, "case_sensitive_names": True}, "MIXEDUID", "MIXEDUID"),
        ("other_attribute", {"userattr": "cn", "userfilter": "(&(uid={{.Username}})({{.UserAttr}}=*))"}, "Case Person", "mixeduid"),
    ]:
        m = t.mount("alias-" + label, **opts)
        a = t.login("alias." + label + ".login", m, "MIXEDUID")
        t.alias("alias." + label, a, alias, username)
    t.update("partial.boolean_set", mount, case_sensitive_names=True, username_as_alias=True)
    t.update("partial.nulls", mount, case_sensitive_names=None, username_as_alias=None,
             token_ttl=None, token_max_ttl=None, token_policies=None, token_num_uses=None)
    data = t.call("partial.read", "auth/" + mount + "/config", method="GET")["data"]
    t.check("partial.fields", config_matches(data, case_sensitive_names=False,
             username_as_alias=False, token_ttl=0, token_max_ttl=600, token_policies=[], token_num_uses=0))
    t.update("partial.empty_filter", mount, userfilter=None)
    data = t.call("partial.empty_filter_read", "auth/" + mount + "/config", method="GET")["data"]
    t.check("partial.empty_filter_stored", data.get("userfilter") == "")
    t.login("partial.empty_filter_default_search", mount)
    t.check("directory.complete", True)


def run_alias_attribute_scenarios(t):
    m = t.mount("alias-optional", userattr="description", username_as_alias=True,
                userfilter="(&(uid={{.Username}})(|({{.UserAttr}}=*)(!({{.UserAttr}}=*))))")
    auth = t.login("alias_missing.username_login", m)
    t.alias("alias_missing.username", auth, "alice", "alice")
    t.update("alias_missing.require_attribute", m, username_as_alias=False)
    t.login("alias_missing.attribute_rejected", m, expected=400)
    t.directory.alias_attribute(["first-alias", "second-alias"])
    try:
        t.login("alias_multiple.attribute_rejected", m, expected=400)
        t.update("alias_multiple.use_username", m, username_as_alias=True)
        auth = t.login("alias_multiple.username_login", m)
        t.alias("alias_multiple.username", auth, "alice", "alice")
    finally:
        t.directory.alias_attribute([])
    t.check("alias_attribute.complete", True)


def run_mapping_scenarios(t):
    m = t.mount("mapping", token_policies=["native-global"])
    for name in ("native-global", "native-direct", "native-aux", "native-engineering"):
        t.policy(name)
    for group, policy in (("Engineering", "native-engineering"), ("AUX", "native-aux")):
        t.call("mapping.group." + group, "auth/" + m + "/groups/" + group,
               {"policies": [policy]}, expected=204)
    data = t.call("mapping.group_list", "auth/" + m + "/groups", method="LIST")["data"]
    t.check("mapping.group_keys", data.get("keys") == ["aux", "engineering"])
    t.call("mapping.user_create", "auth/" + m + "/users/ALICE",
           {"groups": ["AUX"], "policies": ["native-direct"]}, expected=204)
    data = t.call("mapping.user_read", "auth/" + m + "/users/ALICE", method="GET")["data"]
    t.check("mapping.user_shape", mapping_matches(data, "aux", ["native-direct"]))
    data = t.call("mapping.user_list", "auth/" + m + "/users", method="LIST")["data"]
    t.check("mapping.user_keys", data.get("keys") == ["alice"])
    mapped = t.login("mapping.union_login", m, policies=("default", "native-global", "native-direct", "native-aux", "native-engineering"))
    t.renew("mapping.union_renew", mapped)
    t.call("mapping.user_replace", "auth/" + m + "/users/alice", {"policies": ["native-direct"]}, expected=204)
    data = t.call("mapping.user_replace_read", "auth/" + m + "/users/alice", method="GET")["data"]
    t.check("mapping.omitted_groups_clear", mapping_matches(data, "", ["native-direct"]))
    t.renew("mapping.policy_change_denied", mapped, expected=500)
    t.call("mapping.upper_delete", "auth/" + m + "/users/ALICE", method="DELETE", expected=204)
    t.call("mapping.upper_delete_preserves_canonical", "auth/" + m + "/users/alice", method="GET")
    t.call("mapping.lower_delete", "auth/" + m + "/users/alice", method="DELETE", expected=204)
    t.call("mapping.deleted_read", "auth/" + m + "/users/alice", method="GET", expected=404)
    t.login("mapping.deleted_still_directory_login", m, policies=("default", "native-global", "native-engineering"))
    t.call("mapping.null_user", "auth/" + m + "/users/alice", {"groups": None, "policies": None}, expected=204)
    data = t.call("mapping.null_user_read", "auth/" + m + "/users/alice", method="GET")["data"]
    t.check("mapping.null_user_empty", mapping_matches(data, "", []))
    t.call("mapping.upper_group_delete", "auth/" + m + "/groups/Engineering", method="DELETE", expected=204)
    t.call("mapping.upper_group_preserved", "auth/" + m + "/groups/engineering", method="GET")
    t.call("mapping.lower_group_delete", "auth/" + m + "/groups/engineering", method="DELETE", expected=204)
    t.call("mapping.group_deleted", "auth/" + m + "/groups/engineering", method="GET", expected=404)
    t.login("mapping.deleted_group_login", m, policies=("default", "native-global"))
    case_mount = t.mount("case-mapping", case_sensitive_names=True)
    for group, policy in (("Engineering", "native-engineering"), ("AUX", "native-aux")):
        t.call("mapping.case.group." + group, "auth/" + case_mount + "/groups/" + group,
               {"policies": [policy]}, expected=204)
    t.call("mapping.case.user", "auth/" + case_mount + "/users/ALICE",
           {"groups": ["AUX"], "policies": ["native-direct"]}, expected=204)
    data = t.call("mapping.case.read", "auth/" + case_mount + "/users/ALICE", method="GET")["data"]
    t.check("mapping.case.exact_shape", mapping_matches(data, "AUX", ["native-direct"]))
    t.login("mapping.case.exact_login", case_mount, "ALICE", policies=("default", "native-direct", "native-aux"))
    t.login("mapping.case.lower_login", case_mount, "alice", policies=("default",))
    t.check("mapping.complete", True)


def run_identity_and_lifetime_scenarios(t, restart):
    m = t.mount("identity")
    t.call("identity.kv_mount", "sys/mounts/native-secret", {"type": "kv", "options": {"version": "1"}}, expected=204)
    t.call("identity.kv_write", "native-secret/value", {"value": "synthetic"}, expected=204)
    t.policy("native-identity", 'path "native-secret/value" { capabilities = ["read"] }')
    mounts = t.call("identity.mounts", "sys/auth", method="GET")["data"]
    accessor = mounts[m + "/"]["accessor"]
    group = t.call("identity.group", "identity/group", {"name": "native-engineering", "type": "external", "policies": ["native-identity"]})["data"]["id"]
    t.call("identity.group_alias", "identity/group-alias", {"name": "engineering", "mount_accessor": accessor, "canonical_id": group})
    auth = t.login("identity.login", m)
    def verify(label, present):
        data = t.lookup(label + ".lookup", auth)
        t.check(label + ".policies", ("native-identity" in data.get("identity_policies", [])) == present)
        body = t.call(label + ".group", "identity/group/id/" + group, method="GET")["data"]
        t.check(label + ".membership", (auth["entity_id"] in (body.get("member_entity_ids") or [])) == present)
        t.call(label + ".kv", "native-secret/value", method="GET", token=auth["client_token"], expected=200 if present else 403)
    verify("identity.initial", True)
    t.directory.replace_engineering_member(t.directory.admin_dn)
    t.renew("identity.remove", auth)
    verify("identity.removed", False)
    t.directory.replace_engineering_member(USER_DN)
    t.renew("identity.restore", auth)
    verify("identity.restored", True)
    wrapped = t.call("identity.wrap", "auth/token/renew-self", {}, token=auth["client_token"], provider=True, wrap_ttl="60s")
    t.check("identity.wrap_opaque", wrapped_renewal_shape(wrapped, auth["client_token"]))
    wrapper = wrapped["wrap_info"]["token"]
    body = t.call("identity.unwrap", "sys/wrapping/unwrap", {"token": wrapper})
    t.check("identity.unwrap_bearer", renewal_token_shape(body.get("auth"), auth["client_token"], via_accessor=False))
    t.call("identity.unwrap_once", "sys/wrapping/unwrap", {"token": wrapper}, expected=400)
    restart()
    t.check("identity.same_store_restart", True)
    verify("identity.reopened", True)
    t.renew("identity.reopened_provider_checked", auth)
    m = t.mount("lifetime", token_ttl=60, token_explicit_max_ttl=90)
    limited = t.login("lifetime.login", m, ttl=60)
    t.update("lifetime.raise_explicit", m, token_explicit_max_ttl=600)
    for via in ("self", "token", "accessor"):
        t.renew("lifetime.fixed_cap_" + via, limited, via=via, increment=300, ttl=(70, 90))
    data = t.lookup("lifetime.fixed_cap_lookup", limited)
    t.check("lifetime.explicit_snapshot", data.get("explicit_max_ttl") == 90 and "period" not in data)
    t.update("lifetime.current_period", m, token_period=30, token_explicit_max_ttl=0)
    t.renew("lifetime.old_finite_current_period", limited, increment=300, ttl=30)
    periodic = t.login("lifetime.periodic_login", m, ttl=30)
    t.update("lifetime.period45", m, token_period=45)
    t.renew("lifetime.current45", periodic, increment=300, ttl=45)
    data = t.lookup("lifetime.period_lookup", periodic)
    t.check("lifetime.issued_period_snapshot", data.get("period") == 30 and data.get("explicit_max_ttl") == 0)
    t.check("identity_lifetime.complete", True)


def complete_scenarios(rows):
    if not rows or any(row.get("passed") is not True for row in rows):
        return False
    names = [row.get("case") for row in rows]
    if any(not isinstance(n, str) for n in names) or len(set(names)) != len(names):
        return False
    required = {"ldap_native.transport.dns_login.auth", "ldap_native.transport.failed_lease_unchanged",
                "ldap_native.transport.restored_without_restart.lease", "ldap_native.transport.private_ca_not_system_trusted",
                "ldap_native.transport.default_timeouts", "ldap_native.transport.wrong_san_before_ldap",
                "ldap_native.transport.complete",
                "ldap_native.directory.complete", "ldap_native.mapping.complete",
                "ldap_native.config_case.create.normalized", "ldap_native.config_case.partial.normalized",
                "ldap_native.config_case.create.login.auth", "ldap_native.config_case.partial.login.auth",
                "ldap_native.alias_missing.username_login.auth", "ldap_native.alias_missing.attribute_rejected",
                "ldap_native.alias_multiple.attribute_rejected", "ldap_native.alias_multiple.username_login.auth",
                "ldap_native.no_mapping.uppercase_login.auth", "ldap_native.multiple_user_dn",
                "ldap_native.alias.attribute.name", "ldap_native.alias.exact.name",
                "ldap_native.mapping.deleted_still_directory_login.auth",
                "ldap_native.identity.removed.kv", "ldap_native.identity.reopened_provider_checked.lease",
                "ldap_native.lifetime.explicit_snapshot", "ldap_native.lifetime.issued_period_snapshot",
                "ldap_native.identity_lifetime.complete"}
    return required.issubset(names) and names[-1] == "ldap_native.identity_lifetime.complete"


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary")
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not args.oracle_only and not args.binary:
        parser.error("--binary is required for the candidate")
    binary = Path(args.binary).resolve(strict=True) if args.binary else Path(os.environ["HB_ORACLE_BINARY"]).resolve(strict=True)
    output = Path(args.output).absolute()
    admitted = admit_output(output)
    before = source_identity(ROOT, binary)
    root = Path(tempfile.mkdtemp(prefix="heptabao-native-ldap-"))
    root.chmod(0o700)
    oracle = instance = None
    directories = []
    report = {"schema": "heptabao.ldap-native-comparison.v1", "target_version": "2.6.2",
              "synthetic_only": True, "full_openbao_compatibility": False, "production_authority": False,
              "independent_qualification": False, "configuration_adaptation": ADAPTATION,
              "oracle_binary_sha256": BINARY_SHA256, "runner_sha256": file_hash(Path(__file__)),
              "source_identity": before, "cases": {}, "side_failures": {}}
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        oracle = start_oracle(port)
        oracle_root = Path(oracle["root"])
        ca = Path(oracle["ca_file"]).read_text()
        reference = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"]).decode().strip())
        alternate = root / "alternate-ca"
        alternate.mkdir(mode=0o700)
        certificates(alternate)
        alternate_ca = (alternate / "ca.crt").read_text()
        sides = []
        def restart_reference():
            oracle["process"].kill()
            oracle["process"].wait(timeout=5)
            stop_oracle(oracle)
            restart_oracle(oracle)
        if not args.oracle_only:
            instance = Instance(binary, root / "candidate")
            directory = NativeDirectory(root / "candidate-ldap", oracle_root / "tls.crt",
                                        oracle_root / "tls.key", oracle_root / "ca.crt")
            directories.append(directory)
            cfg = json.loads((instance.root / "server.json").read_text())
            cfg["lifecycle_interval_seconds"] = 0
            cfg["outbound_endpoints"] = []
            private(instance.root / "server.json", json.dumps(cfg))
            instance.start()
            status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
            if status != 200:
                raise ScenarioFailure("ldap_native.candidate_init")
            instance.token, key = init["root_token"], init["keys_base64"][0]
            if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                raise ScenarioFailure("ldap_native.candidate_unseal")
            candidate = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
            def restart_candidate():
                instance.stop()
                instance.start()
                if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                    raise ScenarioFailure("ldap_native.candidate_reopen")
            sides.append(("candidate", candidate, directory, restart_candidate))
        directory = NativeDirectory(root / "oracle-ldap", oracle_root / "tls.crt",
                                    oracle_root / "tls.key", oracle_root / "ca.crt")
        directories.append(directory)
        sides.append(("oracle", reference, directory, restart_reference))
        for side, client, directory, restart in sides:
            rows = report["cases"][side] = []
            try:
                trace = Trace(client, directory, configuration(side, directory, ca), rows)
                run_transport_scenarios(trace, alternate_ca, root / (side + "-wrong-san"), oracle_root)
                run_directory_scenarios(trace)
                run_alias_attribute_scenarios(trace)
                run_mapping_scenarios(trace)
                run_identity_and_lifetime_scenarios(trace, restart)
            except ScenarioFailure as error:
                report["side_failures"][side] = str(error)
            except Exception as error:
                report["side_failures"][side] = "unexpected_" + type(error).__name__
        complete = all(complete_scenarios(rows) for rows in report["cases"].values())
        report["cases_match"] = args.oracle_only or report["cases"].get("candidate") == report["cases"].get("oracle")
        report["status"] = ("oracle_passed" if args.oracle_only else "passed") if complete and report["cases_match"] and not report["side_failures"] else "failed"
    except Exception as error:
        report["status"] = "failed"
        report["safe_failure_code"] = type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        for directory in directories:
            directory.stop()
        if oracle is not None:
            stop_oracle(oracle)
            shutil.rmtree(oracle["root"])
        shutil.rmtree(root)
        report["source_and_binary_unchanged"] = before == source_identity(ROOT, binary)
        if not report["source_and_binary_unchanged"]:
            report["status"] = "failed"
            report["safe_failure_code"] = "source_or_binary_changed"
        if admit_output(output) != admitted:
            raise ValueError("report_directory_changed")
        private_write(output, report)
    print(json.dumps({"status": report["status"], "counts": {k: len(v) for k, v in report["cases"].items()},
                      "side_failures": report["side_failures"], "safe_failure_code": report.get("safe_failure_code")}))
    return 0 if report["status"] in ("passed", "oracle_passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
