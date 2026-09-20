#!/usr/bin/env python3
"""Compare native OIDC service-token renewal after real official code exchange.

Both targets authenticate through independent, pinned official OpenBao OIDC
issuers. Issuers are stopped after short-lived ID tokens expire. No browser UI,
third-party IdP, refresh-token exchange, or full OIDC API parity is claimed.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import secrets
import shutil
import socket
import tempfile
import time
import urllib.parse

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash, successful_comparison
from online_evidence import admit_output, source_identity
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle
from radius_renewal_live import renewal_token_shape, wrapped_renewal_shape
from remote_jwks_live import Instance

ADAPTATION = {
    "candidate": "process-enrolled issuer CA/address and explicit pkce_s256_enrolled; POST callback with client_nonce proof",
    "oracle": "mount oidc_discovery_ca_pem; GET callback query with client_nonce proof",
    "issuer": "independent pinned official OpenBao 2.6.2 confidential RS256 clients, code exchange and S256 PKCE",
    "role_updates": "complete role payloads",
    "configuration_api_parity": False,
    "callback_api_parity": False,
}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def role(redirect, **changes):
    value = {"role_type": "oidc", "user_claim": "sub", "allowed_redirect_uris": [redirect],
             "token_policies": ["oidc-old"], "token_ttl": 60, "token_max_ttl": 90}
    value.update(changes)
    return value


def configuration(side, issuer):
    result = {"oidc_discovery_url": issuer.discovery, "oidc_client_id": issuer.client_id,
              "oidc_client_secret": issuer.client_secret, "jwt_supported_algs": ["RS256"]}
    if side == "candidate":
        result["pkce_s256_enrolled"] = True
    else:
        result["oidc_discovery_ca_pem"] = Path(issuer.server["ca_file"]).read_text()
    return result


def policy_snapshot(auth):
    values = auth.get("token_policies")
    return isinstance(values, list) and "oidc-old" in values and "oidc-new" not in values


class Trace:
    def __init__(self, client, issuer, rows):
        self.client, self.issuer, self.rows = client, issuer, rows

    def check(self, name, passed, **observed):
        case = "oidc_renewal." + name
        self.rows.append({"case": case, **observed, "passed": bool(passed)})
        if not passed:
            raise ScenarioFailure(case)

    def call(self, name, path, body=None, *, method="POST", bearer=None, expected=200,
             offline=False, wrap_ttl=None):
        before = self.issuer.stopped()
        result = self.client.request(method, "/v1/" + path, body, token=bearer, wrap_ttl=wrap_ttl)
        observed = {"status": result.status}
        passed = result.status == expected
        if offline:
            observed["issuer_stopped"] = before and self.issuer.stopped()
            passed &= observed["issuer_stopped"]
        self.check(name, passed, **observed)
        return result.body

    def ttl(self, name, bearer):
        body = self.call(name, "auth/token/lookup-self", method="GET", bearer=bearer, offline=True)
        ttl = body.get("data", {}).get("ttl")
        self.check(name + ".shape", type(ttl) is int and ttl > 0)
        return ttl


class OfficialIssuer:
    def __init__(self, server):
        self.server = server
        self.admin = Client(server["address"], server["ca_file"], private_read(server["token_file"], 8192).decode().strip())
        self.redirect = "http://127.0.0.1:" + str(free_port()) + "/oidc/callback"
        self.discovery = server["address"] + "/v1/identity/oidc/provider/renewal"
        self.client_id = self.client_secret = self.enduser = ""

    def stopped(self):
        return self.server["process"].poll() is not None

    def setup(self, trace, *, id_token_ttl=2):
        def call(name, path, body=None, *, method="POST", bearer=None, expected=204):
            response = self.admin.request(method, "/v1/" + path, body, token=bearer)
            trace.check("issuer." + name, response.status == expected, status=response.status)
            return response.body
        call("mount", "sys/auth/people", {"type": "userpass"})
        password = secrets.token_urlsafe(32)
        call("user", "auth/people/users/alice", {"password": password, "token_policies": ["default"]})
        self.enduser = call("login", "auth/people/login/alice", {"password": password}, bearer="", expected=200)["auth"]["client_token"]
        call("key", "identity/oidc/key/renewal", {"algorithm": "RS256", "allowed_client_ids": ["*"]})
        call("client", "identity/oidc/client/renewal", {"client_type": "confidential", "key": "renewal",
             "redirect_uris": [self.redirect], "assignments": ["allow_all"], "id_token_ttl": id_token_ttl, "access_token_ttl": 300})
        data = call("credentials", "identity/oidc/client/renewal", method="GET", expected=200).get("data", {})
        trace.check("issuer.credential_shape", all(isinstance(data.get(k), str) and data[k] for k in ("client_id", "client_secret")))
        self.client_id, self.client_secret = data["client_id"], data["client_secret"]
        call("provider", "identity/oidc/provider/renewal", {"allowed_client_ids": [self.client_id]})

    def begin(self, trace, name, mount, role_name):
        proof = secrets.token_urlsafe(32)
        body = trace.call(name + ".auth_url", "auth/" + mount + "/oidc/auth_url",
                          {"role": role_name, "redirect_uri": self.redirect, "client_nonce": proof}, bearer="")
        url = body.get("data", {}).get("auth_url")
        trace.check(name + ".url_shape", isinstance(url, str) and bool(url))
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, strict_parsing=True)
        trace.check(name + ".bound_code_request", query.get("client_id") == [self.client_id]
                    and query.get("redirect_uri") == [self.redirect] and query.get("response_type") == ["code"]
                    and query.get("code_challenge_method") == ["S256"]
                    and all(len(query.get(k, [])) == 1 and query[k][0] for k in ("state", "nonce", "code_challenge")))
        trace.check(name + ".url_hides_credentials", proof not in url and self.client_secret not in url)
        response = self.admin.request("POST", "/v1/identity/oidc/provider/renewal/authorize",
                                      {k: v[0] for k, v in query.items()}, token=self.enduser)
        trace.check(name + ".actual_issuer_authorize", response.status == 200 and isinstance(response.body.get("code"), str))
        return {"state": query["state"][0], "client_nonce": proof, "code": response.body["code"]}

    def finish(self, trace, side, name, mount, callback):
        if side == "candidate":
            result = trace.call(name + ".callback", "auth/" + mount + "/oidc/callback", callback, bearer="")
        else:
            result = trace.call(name + ".callback", "auth/" + mount + "/oidc/callback?" + urllib.parse.urlencode(callback),
                                method="GET", bearer="")
        auth = result.get("auth", {})
        trace.check(name + ".service_token_shape", all(isinstance(auth.get(k), str) and auth[k]
                    for k in ("client_token", "accessor", "entity_id")))
        return auth

    def login(self, trace, side, name, mount, role_name):
        return self.finish(trace, side, name, mount, self.begin(trace, name, mount, role_name))


def run_scenarios(client, issuer, restart, side, rows):
    t = Trace(client, issuer, rows)
    issuer.setup(t)
    mount = "browser/renewal"
    role_path = "auth/" + mount + "/role/finite"
    periodic_path = "auth/" + mount + "/role/periodic"
    t.call("mount", "sys/auth/" + mount, {"type": "oidc"}, expected=204)
    t.call("config", "auth/" + mount + "/config", configuration(side, issuer), expected=204)
    rules = ('path "auth/token/create" { capabilities = ["update", "sudo"] }\n'
             'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
    t.call("old_policy", "sys/policies/acl/oidc-old", {"policy": rules}, method="PUT", expected=204)
    t.call("new_policy", "sys/policies/acl/oidc-new", {"policy": 'path "sys/health" { capabilities = ["read"] }'}, method="PUT", expected=204)
    t.call("role", role_path, role(issuer.redirect), expected=204)
    data = t.call("role.explicit_policy_readback", role_path, method="GET").get("data", {})
    t.check("role.no_implicit_default_in_readback", data.get("token_policies") == ["oidc-old"])
    t.call("role.partial_update", role_path, {"token_ttl": 60}, expected=204)
    data = t.call("role.partial_readback", role_path, method="GET").get("data", {})
    t.check("role.partial_preserves_policy", data.get("token_policies") == ["oidc-old"]
            and data.get("allowed_redirect_uris") == [issuer.redirect] and data.get("token_max_ttl") == 90)
    finite = issuer.login(t, side, "finite", mount, "finite")
    t.check("finite.own_lifetime", finite.get("lease_duration") == 60 and finite.get("renewable") is True)
    t.check("finite.policy_snapshot", policy_snapshot(finite))
    bearer, accessor = finite["client_token"], finite["accessor"]
    children = {}
    for name, path in [("child", "auth/token/create"), ("orphan", "auth/token/create-orphan")]:
        auth = t.call(name + ".create", path, {"policies": ["default", "oidc-old"], "ttl": "120s"}, bearer=bearer).get("auth", {})
        children[name] = auth.get("client_token")
        t.check(name + ".shape", isinstance(children[name], str) and bool(children[name]) and auth.get("renewable") is True)
    defaults_path = "auth/" + mount + "/role/defaults"
    omitted_policy = role(issuer.redirect)
    omitted_policy.pop("token_policies")
    t.call("defaults.omitted_role", defaults_path, omitted_policy, expected=204)
    data = t.call("defaults.omitted_readback", defaults_path, method="GET").get("data", {})
    t.check("defaults.omitted_stores_empty_policies", data.get("token_policies") == [])
    omitted = issuer.login(t, side, "defaults.omitted", mount, "defaults")
    t.check("defaults.omitted_issues_default", omitted.get("token_policies") == ["default"])
    t.call("defaults.explicit_empty", defaults_path, role(issuer.redirect, token_policies=[]), expected=204)
    data = t.call("defaults.empty_readback", defaults_path, method="GET").get("data", {})
    t.check("defaults.empty_stores_empty_policies", data.get("token_policies") == [])
    empty = issuer.login(t, side, "defaults.empty", mount, "defaults")
    t.check("defaults.empty_issues_default", empty.get("token_policies") == ["default"])
    # Start the short periodic lease last, after all other code exchanges.
    t.call("periodic.role", periodic_path, role(issuer.redirect, token_period=20, token_explicit_max_ttl=120), expected=204)
    periodic_auth = issuer.login(t, side, "periodic", mount, "periodic")
    periodic = periodic_auth["client_token"]
    t.check("periodic.own_lifetime", periodic_auth.get("lease_duration") == 20 and periodic_auth.get("renewable") is True)
    completed_login = time.monotonic()
    time.sleep(3)
    t.check("id_token_lifetimes_elapsed", time.monotonic() - completed_login > 2)
    stop_oracle(issuer.server)
    t.check("issuer.stopped", issuer.stopped())
    # Check this short lease before the longer finite-token matrix.
    body = t.call("periodic.increment_ignored", "auth/token/renew-self", {"increment": 300}, bearer=periodic, offline=True)
    t.check("periodic.current_period", body.get("auth", {}).get("lease_duration") == 20)
    t.call("periodic.lower_caps", periodic_path, role(issuer.redirect, token_ttl=3, token_max_ttl=3,
           token_period=20, token_explicit_max_ttl=1), expected=204, offline=True)
    body = t.call("periodic.age_exceeds_role_max", "auth/token/renew-self", {"increment": 300}, bearer=periodic, offline=True)
    t.check("periodic.role_max_caps_period", body.get("auth", {}).get("lease_duration") == 3)
    # Keep adjacent: the preceding lease lasts three seconds.
    t.call("periodic.change_period", periodic_path, role(issuer.redirect, token_period=10, token_explicit_max_ttl=1), expected=204, offline=True)
    body = t.call("periodic.issued_explicit_cap_retained", "auth/token/renew-self", {"increment": 300}, bearer=periodic, offline=True)
    t.check("periodic.new_period_old_cap", body.get("auth", {}).get("lease_duration") == 10)
    for name, path, payload, caller in [("self", "auth/token/renew-self", {}, bearer),
                                      ("token", "auth/token/renew", {"token": bearer}, None),
                                      ("accessor", "auth/token/renew-accessor", {"accessor": accessor}, None)]:
        body = t.call(name + ".renew_after_id_token_expiry", path, payload, bearer=caller, offline=True)
        auth = body.get("auth", {})
        t.check(name + ".lease", auth.get("lease_duration") == 60 and auth.get("renewable") is True)
        t.check(name + ".bearer_shape", renewal_token_shape(auth, bearer, via_accessor=name == "accessor"))
    t.call("role.max_raised", role_path, role(issuer.redirect, token_max_ttl=600), expected=204, offline=True)
    body = t.call("role.raised_renew", "auth/token/renew-self", {"increment": 300}, bearer=bearer, offline=True)
    t.check("role.raised_cap_used", body.get("auth", {}).get("lease_duration") == 300)
    t.call("role.policy_and_claim_changed", role_path, role(issuer.redirect, token_max_ttl=600,
           token_policies=["oidc-new"], bound_subject="different"), expected=204, offline=True)
    body = t.call("changed_role.renew", "auth/token/renew-self", {"increment": 120}, bearer=bearer, offline=True)
    t.check("changed_role.issued_policy_preserved", policy_snapshot(body.get("auth", {})))
    wrapped = t.call("wrap.renew", "auth/token/renew-self", {"increment": 120}, bearer=bearer, offline=True, wrap_ttl="60s")
    t.check("wrap.opaque", wrapped_renewal_shape(wrapped, bearer))
    wrapper = wrapped["wrap_info"]["token"]
    body = t.call("wrap.unwrap", "sys/wrapping/unwrap", {"token": wrapper}, offline=True)
    t.check("wrap.target", renewal_token_shape(body.get("auth"), bearer, via_accessor=False))
    t.call("wrap.single_use", "sys/wrapping/unwrap", {"token": wrapper}, expected=400, offline=True)
    t.call("role.shrunk", role_path, role(issuer.redirect, token_ttl=1, token_max_ttl=1), expected=204, offline=True)
    before = t.ttl("role.shrunk_before", bearer)
    body = t.call("role.shrunk_denied", "auth/token/renew-self", {"increment": 300}, bearer=bearer,
                  expected=500, offline=True, wrap_ttl="60s")
    t.check("role.shrunk_no_wrapper", not body.get("wrap_info") and not body.get("auth"))
    t.check("role.shrunk_no_extension", t.ttl("role.shrunk_after", bearer) <= before)
    t.call("role.deleted", role_path, method="DELETE", expected=204, offline=True)
    before = t.ttl("role.deleted_before", bearer)
    t.call("role.deleted_denied", "auth/token/renew-self", {}, bearer=bearer, expected=500, offline=True)
    t.check("role.deleted_no_extension", t.ttl("role.deleted_after", bearer) <= before)
    for name, child in children.items():
        body = t.call(name + ".renew_after_role_delete", "auth/token/renew-self", {"increment": 120}, bearer=child, offline=True)
        t.check(name + ".bearer_shape", renewal_token_shape(body.get("auth"), child, via_accessor=False))
    for label, auth in [("omitted", omitted), ("empty", empty)]:
        body = t.call("defaults." + label + ".renews", "auth/token/renew-self", {},
                      bearer=auth["client_token"], offline=True)
        t.check("defaults." + label + ".renewed_default", body.get("auth", {}).get("token_policies") == ["default"])
    restart()
    t.check("restart.same_store_issuer_stopped", issuer.stopped())
    t.call("restart.deleted_role_denied", "auth/token/renew-self", {}, bearer=bearer, expected=500, offline=True)
    for name, child in children.items():
        t.call("restart." + name + ".renew", "auth/token/renew-self", {"increment": 120}, bearer=child, offline=True)
    t.call("restart.role_restored", role_path, role(issuer.redirect, token_max_ttl=600), expected=204, offline=True)
    body = t.call("restart.direct_renews", "auth/token/renew-self", {"increment": 120}, bearer=bearer, offline=True)
    t.check("restart.issued_policy_preserved", policy_snapshot(body.get("auth", {})))


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--build-source-commit", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("full lowercase build source commit required")
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before = source_identity(ROOT, binary)
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-oidc-renewal-")); root.chmod(0o700)
    instance = target_oracle = None
    issuers = []
    report = {"schema": "heptabao.oidc-renewal-comparison.v1", "target_version": "2.6.2", "synthetic_only": True,
              "candidate_binary_sha256": before["binary_sha256"], "oracle_binary_sha256": BINARY_SHA256,
              "build_source_commit": args.build_source_commit,
              "build_source_binding_basis": "caller-supplied build commit and observed binary hash; not inferred from current checkout or independently attested",
              "runner_sha256": runner_hash, "configuration_adaptation": ADAPTATION,
              "actual_official_oidc_issuer": True, "browser_ui_automation": False,
              "no_provider_requirement": "issuer process is stopped during renewals; outbound attempt counting is not claimed",
              "third_party_idp_qualification": False, "full_openbao_compatibility": False,
              "independent_qualification": False, "production_authority": False,
              "cases": {}, "side_failures": {}, "started_at_unix": time.time()}
    try:
        for _ in range(2):
            issuers.append(OfficialIssuer(start_oracle(free_port())))
        instance = Instance(binary, root / "candidate")
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["lifecycle_interval_seconds"] = 0
        config["outbound_endpoints"] = [{"origin": issuers[0].server["address"],
            "address": "127.0.0.1:" + str(urllib.parse.urlsplit(issuers[0].server["address"]).port),
            "server_name": "127.0.0.1", "ca_pem": Path(issuers[0].server["ca_file"]).read_text()}]
        private_write(config_path, config)
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200: raise ScenarioFailure("oidc_renewal.candidate_init")
        instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
        if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
            raise ScenarioFailure("oidc_renewal.candidate_unseal")
        candidate = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
        target_oracle = start_oracle(free_port())
        reference = Client(target_oracle["address"], target_oracle["ca_file"], private_read(target_oracle["token_file"], 8192).decode().strip())
        def restart_candidate():
            instance.stop(); instance.start()
            if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                raise ScenarioFailure("oidc_renewal.candidate_restart")
        def restart_reference():
            target_oracle["process"].kill(); target_oracle["process"].wait(timeout=5)
            stop_oracle(target_oracle); restart_oracle(target_oracle)
        for side, client, issuer, restart in [("candidate", candidate, issuers[0], restart_candidate),
                                             ("oracle", reference, issuers[1], restart_reference)]:
            report["cases"][side] = []
            try:
                run_scenarios(client, issuer, restart, side, report["cases"][side])
            except ScenarioFailure as error:
                report["side_failures"][side] = str(error)
            except Exception as error:
                report["side_failures"][side] = "unexpected_" + type(error).__name__
        report["cases_match"] = report["cases"].get("candidate") == report["cases"].get("oracle")
        report["status"] = "passed" if successful_comparison(report["cases"], report["side_failures"]) else "mismatch"
    except Exception as error:
        report["status"] = "failed"
        report["safe_failure_code"] = str(error) if isinstance(error, ScenarioFailure) else type(error).__name__
    finally:
        if instance is not None: instance.stop()
        if target_oracle is not None:
            stop_oracle(target_oracle); shutil.rmtree(target_oracle["root"])
        for issuer in issuers:
            stop_oracle(issuer.server); shutil.rmtree(issuer.server["root"])
        shutil.rmtree(root)
        after = source_identity(ROOT, binary)
        for field in ("source_commit", "source_tree", "source_dirty", "source_content_sha256"):
            report["harness_" + field] = before[field]
        report["harness_source_unchanged"] = before == after
        report["candidate_binary_unchanged"] = before["binary_sha256"] == after["binary_sha256"]
        if not report["candidate_binary_unchanged"] or file_hash(Path(__file__)) != runner_hash:
            report["status"], report["safe_failure_code"] = "failed", "binary_or_runner_changed_during_execution"
        report["finished_at_unix"] = time.time()
        if admit_output(output) != parent: raise ValueError("report_parent_changed")
        private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "checks_per_side": {side: len(rows) for side, rows in report["cases"].items()},
                      "side_failures": report["side_failures"], "safe_failure_code": report.get("safe_failure_code")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
