#!/usr/bin/env python3
"""Compare Kubernetes role CIDRs with real TLS socket sources and TokenReview.

The upstream is a synthetic HTTPS TokenReview server, not kube-apiserver/RBAC.
Only numeric address constraints and service tokens are covered here.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile

from bao_http import SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from kubernetes_renewal_live import Reviewer, assertion, configuration, role
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle
from oidc_renewal_live import free_port
from online_evidence import admit_output, source_identity
from radius_cidrs_live import SourceClient
from radius_renewal_live import renewal_token_shape, wrapped_renewal_shape
from remote_jwks_live import Instance, signing_key

MOUNT = "cidr-kubernetes"
BASE = "auth/" + MOUNT
ROLE = BASE + "/role/app"
RULES = ('path "cidr-kv/*" { capabilities = ["create", "read", "update"] } '
         'path "auth/token/create" { capabilities = ["update", "sudo"] } '
         'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
ADAPTATION = {
    "source": "real TLS sockets bound to 127.0.0.1 or 127.0.0.2; forwarded headers are untrusted",
    "provider": "synthetic HTTPS TokenReview server; no kube-apiserver, RBAC or real cluster claim",
    "configuration": "API explicit private CA on both; official additionally gets ES256 PEM and issuer validation",
    "request": "candidate sends TypeMeta while official omits it; exact spec and reviewer bearer required on both",
    "scope": "native token_bound_cidrs numeric service-token constraints; no deprecated bound_cidrs, DNS/Unix SockAddr or strictly_bind_ip",
    "num_uses": "existing role token_num_uses integer path, reset explicitly to zero; null semantics excluded",
}


class Trace:
    def __init__(self, client, reviewer, config, rows):
        self.client, self.reviewer, self.config, self.rows = client, reviewer, config, rows
        self.tokens = []

    def check(self, name, condition, **observed):
        if (not isinstance(name, str) or re.fullmatch(r"[a-z0-9_.]{1,150}", name) is None
                or any(type(value) not in (int, bool) for value in observed.values())):
            raise ValueError("unsafe_observation")
        label = "kubernetes_cidrs." + name
        self.rows.append({"case":label, **observed, "passed":condition is True})
        if condition is not True:
            raise ScenarioFailure(label)

    def call(self, name, method, path, body=None, *, status=200, reviews=0, token=None,
             source="127.0.0.1", wrap=None, spoof=False):
        before = len(self.reviewer.calls)
        response = self.client.request(method, path, body, token=token, source=source, wrap_ttl=wrap, spoof=spoof)
        count = len(self.reviewer.calls) - before
        self.check(name, response.status == status and count == reviews
                   and (reviews == 0 or self.reviewer.request_valid), status=response.status,
                   tokenreview_count=count, source_family=self.client.last_family)
        return response.body

    def update(self, name, body):
        return self.call(name, "POST", ROLE, body, status=204)

    def read_bounds(self, name, expected):
        data = self.call(name, "GET", ROLE).get("data", {})
        self.check(name + ".exact", data.get("token_bound_cidrs") == expected)
        return data

    def login(self, name, *, source="127.0.0.1", status=200, reviews=1, spoof=False):
        body = self.call(name, "POST", BASE + "/login", {"role":"app", "jwt":self.reviewer.presented},
                         source=source, status=status, reviews=reviews, token="", spoof=spoof)
        auth = body.get("auth", {})
        if status == 200:
            self.check(name + ".issued", isinstance(auth.get("client_token"), str) and bool(auth["client_token"])
                       and isinstance(auth.get("accessor"), str) and bool(auth["accessor"]) and auth.get("renewable") is True)
            self.tokens.append(auth["client_token"])
        else:
            self.check(name + ".no_authority", not auth and not body.get("wrap_info"))
        return auth

    def token_bounds(self, name, auth, expected):
        data = self.call(name, "POST", "auth/token/lookup", {"token":auth["client_token"]}, source="127.0.0.2").get("data", {})
        self.check(name + ".exact", data.get("bound_cidrs", []) == expected)

    def renew_all(self, name, auth):
        for label, path, body, actor, source in (
            ("self", "renew-self", {}, auth["client_token"], "127.0.0.1"),
            ("token", "renew", {"token":auth["client_token"]}, None, "127.0.0.2"),
            ("accessor", "renew-accessor", {"accessor":auth["accessor"]}, None, "127.0.0.2"),
        ):
            response = self.call(name + "." + label, "POST", "auth/token/" + path,
                                 dict(body, increment=120), token=actor, source=source)
            self.check(name + "." + label + ".shape",
                       renewal_token_shape(response.get("auth"), auth["client_token"], via_accessor=label == "accessor"))


DEVIATIONS = {
    "invalid_prefix_as_unix": {"input":"127.0.0.1/33", "oracle_status":204, "candidate_status":400},
    "slash_text_as_unix": {"input":"not-an-address/", "oracle_status":204, "candidate_status":400},
}
DEVIATION_SOURCE = {
    "openbao":"sdk/helper/tokenutil/tokenutil.go:175-182 delegates token_bound_cidrs to parseutil.ParseAddrs",
    "dependency":"github.com/hashicorp/go-sockaddr v1.0.7, pinned in sdk/go.sum",
    "source":"https://github.com/hashicorp/go-sockaddr/blob/v1.0.7/sockaddr.go#L64-L83",
    "behavior":"failed IP parsing falls back to UnixSock for strings containing slash; candidate numeric-only profile rejects",
    "readback":"UnixSock.String quotes paths; write plus storage reload produces two quoting layers, observed against pinned binary",
}


def profile_deviations(t, side):
    # Keep actual unequal public statuses outside the equal-profile trace. Never
    # erase the upstream acceptance or describe these inputs as a shared error.
    for label, expected in DEVIATIONS.items():
        before = t.call(label + ".before", "GET", ROLE).get("data", {})
        t.call(label + ".write", "POST", ROLE, {"token_bound_cidrs":[expected["input"]]},
               status=expected[side + "_status"])
        after = t.call(label + ".read", "GET", ROLE).get("data", {})
        t.check(label + ".readback", after.get("token_bound_cidrs") == [json.dumps(json.dumps(expected["input"]))]
                if side == "oracle" else after == before)
        t.login(label + ".login", status=403, reviews=0)
        t.update(label + ".restore", {"token_bound_cidrs":before["token_bound_cidrs"]})


def deviations_complete(rows):
    required = {"kubernetes_cidrs." + label + suffix for label in DEVIATIONS for suffix in
                (".before", ".write", ".read", ".readback", ".login", ".login.no_authority", ".restore")}
    return (isinstance(rows, list) and len(rows) == len(required)
            and {row.get("case") for row in rows if isinstance(row, dict)} == required
            and all(row.get("passed") is True and all(type(v) in (bool, int)
                    for k,v in row.items() if k not in ("case", "passed")) for row in rows))


def scenario(t, restart, side, deviations):
    c = t.call
    c("mount", "POST", "sys/auth/" + MOUNT, {"type":"kubernetes"}, status=204)
    c("kv_mount", "POST", "sys/mounts/cidr-kv", {"type":"kv", "options":{"version":"1"}}, status=204)
    c("policy", "PUT", "sys/policies/acl/cidr-user", {"policy":RULES}, status=204)
    c("seed", "POST", "cidr-kv/item", {"value":"synthetic"}, status=204)
    c("config", "POST", BASE + "/config", t.config, status=204)
    base_role = role(token_policies=["cidr-user"], token_ttl=120, token_max_ttl=600)
    t.update("role", base_role)
    t.read_bounds("role.default_bounds", [])
    t.update("role.list", {"token_bound_cidrs":["127.0.0.1/32"]})
    t.read_bounds("role.list_read", ["127.0.0.1"])
    t.update("role.partial_ttl", {"token_ttl":121})
    data = t.read_bounds("role.partial_read", ["127.0.0.1"])
    t.check("role.partial_other_fields", data.get("bound_service_account_names") == ["worker"]
            and data.get("bound_service_account_namespaces") == ["workload"]
            and data.get("token_ttl") == 121)
    original = t.login("allowed.login")
    t.token_bounds("allowed.snapshot", original, ["127.0.0.1"])
    t.login("denied.login", source="127.0.0.2", status=403, reviews=0, spoof=True)
    t.reviewer.mode = "unavailable"
    t.login("denied.before_unavailable_provider", source="127.0.0.2", status=403, reviews=0)
    t.renew_all("provider_offline.renew", original)
    t.reviewer.mode = "normal"
    for label, method, path, body in (
        ("lookup", "GET", "auth/token/lookup-self", None),
        ("read", "GET", "cidr-kv/item", None),
        ("write", "POST", "cidr-kv/item", {"value":"denied"}),
        ("renew", "POST", "auth/token/renew-self", {"increment":300}),
    ):
        denied = c("denied." + label, method, path, body, token=original["client_token"],
                   source="127.0.0.2", status=403, spoof=True)
        t.check("denied." + label + ".no_authority", not denied.get("auth") and not denied.get("wrap_info"))
    c("allowed.read", "GET", "cidr-kv/item", token=original["client_token"])
    c("allowed.write", "POST", "cidr-kv/item", {"value":"allowed"}, token=original["client_token"], status=204)
    t.renew_all("actor_scope", original)
    descendants = {}
    for name, route, inherits in (("child", "create", True), ("orphan", "create-orphan", False)):
        auth = c(name + ".create", "POST", "auth/token/" + route, {"policies":["default"], "ttl":120},
                 token=original["client_token"]).get("auth", {})
        t.check(name + ".issued", isinstance(auth.get("client_token"), str) and bool(auth["client_token"]))
        t.tokens.append(auth["client_token"])
        descendants[name] = auth
        t.token_bounds(name + ".snapshot", auth, ["127.0.0.1"] if inherits else [])
        c(name + ".other_source", "GET", "auth/token/lookup-self", token=auth["client_token"],
          source="127.0.0.2", status=403 if inherits else 200)
        c(name + ".renew", "POST", "auth/token/renew-self", {"increment":120}, token=auth["client_token"],
          source="127.0.0.1" if inherits else "127.0.0.2")
    t.update("changed.role", {"token_bound_cidrs":["192.0.2.0/24"]})
    t.login("changed.new_login", status=403, reviews=0)
    t.renew_all("changed.old_renew", original)
    t.token_bounds("changed.old_snapshot", original, ["127.0.0.1"])
    wrapped = c("wrapped_renew.accepted", "POST", "auth/token/renew-self", {"increment":120},
                token=original["client_token"], wrap="60s")
    t.check("wrapped_renew.outer", wrapped_renewal_shape(wrapped, original["client_token"]))
    wrapper = wrapped["wrap_info"]["token"]
    t.tokens.append(wrapper)
    inner = c("wrapped_renew.unwrap_other_source", "POST", "sys/wrapping/unwrap", {}, token=wrapper, source="127.0.0.2")
    t.check("wrapped_renew.inner", renewal_token_shape(inner.get("auth"), original["client_token"], via_accessor=False))
    c("wrapped_renew.single_use", "POST", "sys/wrapping/unwrap", {}, token=wrapper, status=400)
    denied = c("wrapped_renew.denied", "POST", "auth/token/renew-self", {"increment":300},
               token=original["client_token"], source="127.0.0.2", wrap="60s", status=403)
    t.check("wrapped_renew.no_publication", not denied.get("auth") and not denied.get("wrap_info"))
    t.update("finite.role", {"token_bound_cidrs":["127.0.0.1"], "token_num_uses":2})
    finite = t.login("finite.login")
    c("finite.denied_no_use", "GET", "cidr-kv/item", token=finite["client_token"], source="127.0.0.2", status=403)
    c("finite.first", "GET", "cidr-kv/item", token=finite["client_token"])
    c("finite.second", "GET", "cidr-kv/item", token=finite["client_token"])
    c("finite.exhausted", "GET", "cidr-kv/item", token=finite["client_token"], status=403)
    t.update("finite.restore", {"token_num_uses":0})
    t.update("parse.csv", {"token_bound_cidrs":"127.0.0.1/32, 127.0.0.2/32"})
    t.read_bounds("parse.csv_read", ["127.0.0.1", "127.0.0.2"])
    t.login("parse.csv_other_source", source="127.0.0.2")
    for label, value, normalized, status in (
        ("host_bits", "127.0.0.2/24", "127.0.0.2/24", 200),
        ("mapped", "::ffff:127.0.0.1/128", "127.0.0.1", 200),
        ("port", "127.0.0.1:999", "127.0.0.1:999", 200),
        ("v6_excludes_v4", "::/0", "::/0", 403),
    ):
        t.update("parse." + label, {"token_bound_cidrs":[value]})
        t.read_bounds("parse." + label + ".read", [normalized])
        t.login("parse." + label + ".login", status=status, reviews=int(status == 200))
    profile_deviations(Trace(t.client, t.reviewer, t.config, deviations), side)
    for label, invalid in (("bad_type", {"value":"127.0.0.1"}),):
        previous = c("invalid." + label + ".before", "GET", ROLE).get("data", {})
        c("invalid." + label, "POST", ROLE, {"token_bound_cidrs":invalid}, status=400)
        current = c("invalid." + label + ".after", "GET", ROLE).get("data", {})
        t.check("invalid." + label + ".unchanged", current == previous)
    for label, value in (("empty_list", []), ("empty_string", ""), ("null", None)):
        t.update("clear." + label + ".seed", {"token_bound_cidrs":["127.0.0.1"]})
        t.update("clear." + label, {"token_bound_cidrs":value})
        t.read_bounds("clear." + label + ".read", [])
        unbound = t.login("clear." + label + ".login", source="127.0.0.2")
        t.token_bounds("clear." + label + ".snapshot", unbound, [])
    t.token_bounds("clear.old_snapshot", original, ["127.0.0.1"])
    c("clear.old_still_denied", "GET", "auth/token/lookup-self", token=original["client_token"], source="127.0.0.2", status=403)
    t.renew_all("clear.old_renew", original)
    t.update("persist.bound_role", {"token_bound_cidrs":["127.0.0.1"]})
    wrapped = c("persist.wrapped_login", "POST", BASE + "/login", {"role":"app", "jwt":t.reviewer.presented},
                token="", reviews=1, wrap="60s")
    t.check("persist.wrapper", not wrapped.get("auth") and bool(wrapped.get("wrap_info", {}).get("token")))
    persistent_wrapper = wrapped["wrap_info"]["token"]
    t.tokens.append(persistent_wrapper)
    t.update("persist.clear_role", {"token_bound_cidrs":[]})
    restart()
    t.check("restart.same_store", True)
    t.read_bounds("restart.empty_role", [])
    t.token_bounds("restart.old_snapshot", original, ["127.0.0.1"])
    c("restart.old_denied", "GET", "auth/token/lookup-self", token=original["client_token"], source="127.0.0.2", status=403)
    t.renew_all("restart.old_renew", original)
    c("restart.unbound", "GET", "auth/token/lookup-self", token=unbound["client_token"], source="127.0.0.2")
    inner = c("restart.unwrap_other_source", "POST", "sys/wrapping/unwrap", {}, token=persistent_wrapper, source="127.0.0.2").get("auth", {})
    t.check("restart.wrapped_token", bool(inner.get("client_token")) and inner.get("accessor") == wrapped["wrap_info"].get("wrapped_accessor"))
    t.tokens.append(inner["client_token"])
    t.token_bounds("restart.wrapped_snapshot", inner, ["127.0.0.1"])
    c("restart.wrapped_denied", "GET", "auth/token/lookup-self", token=inner["client_token"], source="127.0.0.2", status=403)
    c("restart.wrapped_allowed", "GET", "auth/token/lookup-self", token=inner["client_token"])
    c("restart.wrapper_single_use", "POST", "sys/wrapping/unwrap", {}, token=persistent_wrapper, status=400)
    c("role_deleted.delete", "DELETE", ROLE, status=204)
    c("role_deleted.direct_renew", "POST", "auth/token/renew", {"token":original["client_token"]}, source="127.0.0.2", status=500)
    for name, source in (("child", "127.0.0.1"), ("orphan", "127.0.0.2")):
        c("role_deleted." + name + "_renew", "POST", "auth/token/renew-self", {}, token=descendants[name]["client_token"], source=source)
    c("revoke.parent", "POST", "auth/token/revoke", {"token":original["client_token"]}, source="127.0.0.2", status=204)
    c("revoke.child", "GET", "auth/token/lookup-self", token=descendants["child"]["client_token"], status=403)
    c("revoke.orphan_survives", "GET", "auth/token/lookup-self", token=descendants["orphan"]["client_token"], source="127.0.0.2")
    t.check("receipt.no_sensitive_values", all(secret not in json.dumps(t.rows) for secret in
            [t.reviewer.reviewer, t.reviewer.presented, t.client.root_token, *t.tokens]))


MILESTONES = {
    "role.default_bounds.exact", "role.list_read.exact", "role.partial_other_fields",
    "denied.login", "denied.before_unavailable_provider", "denied.read", "denied.write", "denied.renew",
    "provider_offline.renew.self.shape", "provider_offline.renew.token.shape", "provider_offline.renew.accessor.shape",
    "actor_scope.token.shape", "actor_scope.accessor.shape", "child.other_source", "orphan.other_source",
    "child.renew", "orphan.renew", "changed.old_renew.self.shape", "changed.old_snapshot.exact",
    "wrapped_renew.inner", "wrapped_renew.single_use", "wrapped_renew.no_publication",
    "finite.denied_no_use", "finite.first", "finite.second", "finite.exhausted",
    "parse.csv_read.exact", "parse.csv_other_source.issued", "parse.host_bits.read.exact",
    "parse.mapped.read.exact", "parse.v6_excludes_v4.login.no_authority", "invalid.bad_type.unchanged",
    "clear.empty_list.read.exact", "clear.empty_string.read.exact", "clear.null.read.exact",
    "clear.old_still_denied", "clear.old_renew.self.shape", "clear.old_renew.accessor.shape",
    "restart.old_snapshot.exact", "restart.old_denied", "restart.old_renew.self.shape",
    "restart.unbound", "restart.wrapped_snapshot.exact", "restart.wrapped_denied", "restart.wrapper_single_use",
    "role_deleted.direct_renew", "role_deleted.child_renew", "role_deleted.orphan_renew",
    "revoke.child", "revoke.orphan_survives", "receipt.no_sensitive_values",
    "storage.no_plaintext_credentials", "complete",
}


def complete(rows):
    if not isinstance(rows, list) or not rows:
        return False
    names = []
    for row in rows:
        if (not isinstance(row, dict) or row.get("passed") is not True
                or not isinstance(row.get("case"), str)
                or re.fullmatch(r"kubernetes_cidrs\.[a-z0-9_.]{1,150}", row["case"]) is None
                or any(type(v) not in (bool, int) for k,v in row.items() if k not in ("case", "passed"))):
            return False
        names.append(row["case"])
    return (len(names) == len(set(names)) and {"kubernetes_cidrs." + n for n in MILESTONES}.issubset(names)
            and names[-1] == "kubernetes_cidrs.complete")


def scan_storage(root, sensitive):
    # Control artifacts intentionally contain synthetic initialization secrets;
    # examine only actual store data and process/audit output, never root.token,
    # unseal.key, PEM private keys or the API setup configuration.
    store = root / "data"
    files = [p for p in store.rglob('*') if p.is_file()]
    if not store.is_dir() or not files or not (root / "server.log").is_file():
        return False
    files += [p for p in (root / "server.log", root / "audit.jsonl") if p.is_file()]
    if not sensitive or any(not isinstance(value, str) or not value for value in sensitive):
        return False
    return all(value.encode() not in p.read_bytes() for p in files for value in sensitive)


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--build-source-commit")
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.oracle_only and (args.binary is None or re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit or "") is None):
        parser.error("candidate binary and full build source commit required")
    binary = args.binary.resolve(strict=True) if args.binary else None
    output = args.output.absolute()
    admitted = admit_output(output)
    before = source_identity(ROOT, binary) if not args.oracle_only else None
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-kubernetes-cidrs-"))
    root.chmod(0o700)
    oracle = instance = None
    providers = []
    cases, failures, deviations = {}, {}, {}
    no_enrollment = False
    try:
        oracle = start_oracle(free_port())
        cert_root = Path(oracle["root"])
        ca = Path(oracle["ca_file"]).read_text()
        for side in (["oracle"] if args.oracle_only else ["candidate", "oracle"]):
            reviewer = Reviewer(cert_root / "tls.crt", cert_root / "tls.key", side)
            providers.append(reviewer)
            private, jwk = signing_key("ES256", "synthetic-kubernetes-cidrs")
            reviewer.presented = assertion(private, jwk)
            if side == "candidate":
                instance = Instance(binary, root / "candidate")
                settings = json.loads((instance.root / "server.json").read_text())
                settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
                private_write(instance.root / "server.json", settings)
                no_enrollment = json.loads((instance.root / "server.json").read_text())["outbound_endpoints"] == []
                instance.start()
                status, initialized = instance.call("POST", "sys/init", {"secret_shares":1, "secret_threshold":1})
                if status != 200:
                    raise ScenarioFailure("kubernetes_cidrs.candidate_init")
                instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
                if instance.call("POST", "sys/unseal", {"key":key})[0] != 200:
                    raise ScenarioFailure("kubernetes_cidrs.candidate_unseal")
                client = SourceClient(instance.address, instance.root / "ca.crt", instance.token)
                store_root = instance.root
                def restart():
                    instance.stop()
                    if json.loads((instance.root / "server.json").read_text())["outbound_endpoints"] != []:
                        raise ScenarioFailure("kubernetes_cidrs.enrollment_changed")
                    instance.start()
                    if instance.call("POST", "sys/unseal", {"key":key})[0] != 200:
                        raise ScenarioFailure("kubernetes_cidrs.candidate_reopen")
            else:
                client = SourceClient(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"]).decode().strip())
                key = private_read(cert_root / "unseal.key").decode().strip()
                store_root = cert_root
                def restart():
                    stop_oracle(oracle)
                    restart_oracle(oracle)
            rows = cases[side] = []
            trace = Trace(client, reviewer, configuration(side, reviewer, private, ca), rows)
            try:
                profile_rows = deviations[side] = []
                scenario(trace, restart, side, profile_rows)
                if side == "candidate": instance.stop()
                else: stop_oracle(oracle)
                trace.check("storage.no_plaintext_credentials", scan_storage(store_root,
                    [key, client.root_token, reviewer.reviewer, reviewer.presented, *trace.tokens]))
                trace.check("complete", True)
            except Exception as error:
                failures[side] = str(error) if isinstance(error, ScenarioFailure) else "fixture_" + type(error).__name__
    except Exception as error:
        failures["setup"] = str(error) if isinstance(error, ScenarioFailure) else "fixture_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        for provider in providers:
            provider.close()
        if oracle is not None:
            stop_oracle(oracle)
            shutil.rmtree(oracle["root"])
        shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary) if before else None
    runner_unchanged = file_hash(Path(__file__)) == runner_hash
    expected = {"oracle"} if args.oracle_only else {"candidate", "oracle"}
    compared = args.oracle_only or cases.get("candidate") == cases.get("oracle")
    passed = (not failures and set(cases) == expected and compared and all(complete(rows) for rows in cases.values())
              and set(deviations) == expected and all(deviations_complete(rows) for rows in deviations.values())
              and runner_unchanged and (args.oracle_only or (unchanged and no_enrollment)))
    report = {"schema":"heptabao.kubernetes-cidrs-comparison.v1", "status":"passed" if passed else "failed",
        "target_version":"2.6.2", "cases":cases, "failures":failures, "cases_match":compared,
        "oracle_only":args.oracle_only, "oracle_binary_sha256":BINARY_SHA256,
        "candidate_source":before, "build_source_commit":args.build_source_commit,
        "source_and_binary_unchanged":unchanged, "runner_sha256":runner_hash, "runner_unchanged":runner_unchanged,
        "candidate_startup_enrollment_empty":no_enrollment, "configuration_adaptation":ADAPTATION,
        "synthetic_tokenreview":True, "actual_kube_apiserver":False,
        "numeric_only":True, "full_api_parity":False, "explicit_deviations":deviations,
        "deviation_contract":DEVIATIONS, "deviation_source":DEVIATION_SOURCE,
        "full_openbao_compatibility":False, "independent_qualification":False, "production_authority":False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status":report["status"], "cases":{side:len(rows) for side,rows in cases.items()}, "failures":failures}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
