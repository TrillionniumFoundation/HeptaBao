#!/usr/bin/env python3
"""Compare local JWT token renewal with pinned official 2.6.2 over HTTPS.

Static ES256 and remote JWKS logins use fresh synthetic assertions. Renewal
re-reads local role settings and does not revalidate the original assertion.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import socket
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash, successful_comparison
from online_evidence import admit_output, source_identity
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle
from radius_renewal_live import renewal_token_shape, wrapped_renewal_shape
from remote_jwks_live import Instance, JsonIssuer, signing_key, token, serialization

ADAPTATION = {
    "static_candidate": "issuer/audiences and inline JWKS",
    "static_oracle": "bound_issuer and PEM jwt_validation_pubkeys with ES256",
    "remote_candidate": "JWKS URL with process-enrolled address and CA",
    "remote_oracle": "JWKS URL and mount-level jwks_ca_pem",
    "role_updates": "complete role payloads; partial-update parity is not asserted",
    "configuration_api_parity": False,
}


def configuration(side, mode, issuer, private, jwk, ca):
    if mode == "static":
        if side == "candidate":
            return {"issuer": issuer.origin, "audiences": ["heptabao-test"], "jwks": {"keys": [jwk]}}
        pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return {"bound_issuer": issuer.origin, "jwt_validation_pubkeys": [pem], "jwt_supported_algs": ["ES256"]}
    params = {"bound_issuer": issuer.origin, "jwks_url": issuer.origin + "/keys", "jwt_supported_algs": ["ES256"]}
    if side == "oracle":
        params["jwks_ca_pem"] = ca
    return params


def role(**changes):
    values = {"role_type": "jwt", "user_claim": "sub", "bound_audiences": ["heptabao-test"],
              "token_policies": ["jwt-old"], "token_ttl": 60, "token_max_ttl": 90}
    values.update(changes)
    return values


def issued_policy_snapshot(auth):
    policies = auth.get("token_policies")
    return isinstance(policies, list) and "jwt-old" in policies and "jwt-new" not in policies


class Trace:
    def __init__(self, client, issuer, mode, results):
        self.client, self.issuer, self.mode, self.results = client, issuer, mode, results

    def check(self, name, condition, **observed):
        case = "jwt_renewal." + self.mode + "." + name
        self.results.append({"case": case, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(case)

    def call(self, name, path, payload=None, *, method="POST", bearer=None, expected=200,
             no_provider=False, wrap_ttl=None):
        before = len(self.issuer.calls)
        response = self.client.request(method, "/v1/" + path, payload, token=bearer, wrap_ttl=wrap_ttl)
        observed = {"status": response.status}
        passed = response.status == expected
        if no_provider:
            observed["no_provider_request"] = len(self.issuer.calls) == before
            passed &= observed["no_provider_request"]
        self.check(name, passed, **observed)
        return response.body

    def ttl(self, name, bearer):
        body = self.call(name, "auth/token/lookup-self", method="GET", bearer=bearer)
        ttl = body.get("data", {}).get("ttl")
        self.check(name + ".shape", type(ttl) is int and ttl > 0)
        return ttl


def run_scenarios(client, issuer, private, jwk, config, restart, mode, results):
    t = Trace(client, issuer, mode, results)
    mount = "jwt-renew-" + mode
    role_path = "auth/" + mount + "/role/test"
    issuer.mode = "normal"
    t.call("mount", "sys/auth/" + mount, {"type": "jwt"}, expected=204)
    t.call("config", "auth/" + mount + "/config", config, expected=204)
    rules = ('path "auth/token/create" { capabilities = ["update", "sudo"] }\n'
             'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
    t.call("old_policy", "sys/policies/acl/jwt-old", {"policy": rules}, method="PUT", expected=204)
    t.call("new_policy", "sys/policies/acl/jwt-new", {"policy": 'path "sys/health" { capabilities = ["read"] }'}, method="PUT", expected=204)
    t.call("role", role_path, role(), expected=204)
    assertion_expiry = int(time.time()) + 2
    signed = token(private, jwk, issuer.origin, exp=assertion_expiry)
    logged = t.call("login", "auth/" + mount + "/login", {"role": "test", "jwt": signed})
    auth = logged.get("auth", {})
    t.check("login.shape", all(isinstance(auth.get(field), str) and auth[field] for field in ("client_token", "accessor")))
    bearer, accessor = auth["client_token"], auth["accessor"]
    t.check("login.ttl_not_capped_by_assertion", auth.get("lease_duration") == 60)
    t.check("login.policy_snapshot", issued_policy_snapshot(auth))
    t.check("login.key_profile", bool(issuer.calls) if mode == "remote" else not issuer.calls)
    children = {}
    for name, path in [("child", "auth/token/create"), ("orphan", "auth/token/create-orphan")]:
        body = t.call(name + ".create", path, {"policies": ["default", "jwt-old"], "ttl": "60s"}, bearer=bearer)
        children[name] = body.get("auth", {}).get("client_token")
        t.check(name + ".shape", isinstance(children[name], str) and bool(children[name]))
    time.sleep(3)
    t.check("assertion_expired", int(time.time()) > assertion_expiry)
    issuer.mode = "unavailable"
    for name, path, payload, caller in [("self", "auth/token/renew-self", {}, bearer),
                                      ("token", "auth/token/renew", {"token": bearer}, None),
                                      ("accessor", "auth/token/renew-accessor", {"accessor": accessor}, None)]:
        body = t.call(name + ".renew_after_assertion_expiry", path, payload, bearer=caller, no_provider=True)
        renewed = body.get("auth", {})
        t.check(name + ".renewed_ttl", renewed.get("lease_duration") == 60 and renewed.get("renewable") is True)
        t.check(name + ".bearer_shape", renewal_token_shape(renewed, bearer, via_accessor=name == "accessor"))

    t.call("max_raised", role_path, role(token_max_ttl=600), expected=204, no_provider=True)
    body = t.call("max_raised.renew", "auth/token/renew-self", {"increment": 300}, bearer=bearer, no_provider=True)
    t.check("max_raised.new_role_cap_used", body.get("auth", {}).get("lease_duration") == 300)
    t.call("role_policy_and_claim_changed", role_path,
           role(token_max_ttl=600, token_policies=["jwt-new"], bound_audiences=["new-audience"]), expected=204, no_provider=True)
    body = t.call("changed_role.renew", "auth/token/renew-self", {"increment": 120}, bearer=bearer, no_provider=True)
    t.check("changed_role.issued_policy_preserved", issued_policy_snapshot(body.get("auth", {})))
    wrapped = t.call("wrap.renew", "auth/token/renew-self", {"increment": 120}, bearer=bearer,
                     no_provider=True, wrap_ttl="60s")
    t.check("wrap.opaque", wrapped_renewal_shape(wrapped, bearer))
    wrapper = wrapped["wrap_info"]["token"]
    unwrapped = t.call("wrap.unwrap", "sys/wrapping/unwrap", {"token": wrapper})
    t.check("wrap.original_target", renewal_token_shape(unwrapped.get("auth"), bearer, via_accessor=False))
    t.call("wrap.single_use", "sys/wrapping/unwrap", {"token": wrapper}, expected=400)

    t.call("maximum_shrunk", role_path, role(token_ttl=1, token_max_ttl=1), expected=204, no_provider=True)
    before = t.ttl("maximum_shrunk.before", bearer)
    denied = t.call("maximum_shrunk.denied", "auth/token/renew-self", {"increment": 300}, bearer=bearer,
                    expected=500, no_provider=True, wrap_ttl="60s")
    t.check("maximum_shrunk.no_wrapper", not denied.get("wrap_info") and denied.get("auth") is None)
    t.check("maximum_shrunk.no_extension", t.ttl("maximum_shrunk.after", bearer) <= before)
    t.call("role_restored", role_path, role(token_max_ttl=600), expected=204, no_provider=True)
    t.call("role_restored.renew", "auth/token/renew-self", {"increment": 120}, bearer=bearer, no_provider=True)
    t.call("role_deleted", role_path, method="DELETE", expected=204, no_provider=True)
    before = t.ttl("role_deleted.before", bearer)
    t.call("role_deleted.denied", "auth/token/renew-self", {"increment": 300}, bearer=bearer, expected=500, no_provider=True)
    t.check("role_deleted.no_extension", t.ttl("role_deleted.after", bearer) <= before)
    for name, child in children.items():
        body = t.call(name + ".renew_after_role_delete", "auth/token/renew-self", {"increment": 120}, bearer=child, no_provider=True)
        t.check(name + ".bearer_shape", renewal_token_shape(body.get("auth"), child, via_accessor=False))
    restart()
    t.check("restart.same_store", True)
    t.call("restart.deleted_role_denied", "auth/token/renew-self", {"increment": 300}, bearer=bearer, expected=500, no_provider=True)
    for name, child in children.items():
        t.call("restart." + name + ".renews", "auth/token/renew-self", {"increment": 120}, bearer=child, no_provider=True)
    t.call("restart.restore_role", role_path, role(token_max_ttl=600), expected=204, no_provider=True)
    body = t.call("restart.direct_renews", "auth/token/renew-self", {"increment": 120}, bearer=bearer, no_provider=True)
    t.check("restart.policy_snapshot", issued_policy_snapshot(body.get("auth", {})))

    periodic_path = "auth/" + mount + "/role/periodic"
    t.call("periodic.role", periodic_path,
           role(token_period=20, token_explicit_max_ttl=120), expected=204, no_provider=True)
    issuer.mode = "normal"
    signed = token(private, jwk, issuer.origin)
    body = t.call("periodic.login", "auth/" + mount + "/login", {"role": "periodic", "jwt": signed})
    periodic = body.get("auth", {}).get("client_token")
    t.check("periodic.login_shape", isinstance(periodic, str) and bool(periodic)
            and body.get("auth", {}).get("lease_duration") == 20)
    issuer.mode = "unavailable"
    body = t.call("periodic.increment_ignored", "auth/token/renew-self", {"increment": 300},
                  bearer=periodic, no_provider=True)
    t.check("periodic.period_controls_lease", body.get("auth", {}).get("lease_duration") == 20)
    time.sleep(4)
    t.call("periodic.lower_caps", periodic_path,
           role(token_ttl=3, token_max_ttl=3, token_period=20, token_explicit_max_ttl=1), expected=204, no_provider=True)
    body = t.call("periodic.age_can_exceed_role_max", "auth/token/renew-self", {"increment": 300},
                  bearer=periodic, no_provider=True)
    t.check("periodic.role_max_caps_each_period", body.get("auth", {}).get("lease_duration") == 3)
    # The preceding token has only three seconds. Keep these two local calls
    # adjacent: the point is issue-time explicit max, not timeout scheduling.
    t.call("periodic.change_period", periodic_path,
           role(token_ttl=60, token_max_ttl=90, token_period=10, token_explicit_max_ttl=1), expected=204, no_provider=True)
    body = t.call("periodic.issued_explicit_cap_retained", "auth/token/renew-self", {"increment": 300},
                  bearer=periodic, no_provider=True)
    t.check("periodic.new_period_old_explicit_cap", body.get("auth", {}).get("lease_duration") == 10)


def main(*, scenario_runner=run_scenarios, profile="jwt-renewal", runner_path=None, scope=None):
    runner_path = Path(__file__) if runner_path is None else runner_path
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--build-source-commit")
    args = parser.parse_args()
    if args.build_source_commit is not None and re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("build source commit must be a full lowercase commit id")
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before = source_identity(ROOT, binary)
    root = Path(tempfile.mkdtemp(prefix="heptabao-" + profile + "-"))
    root.chmod(0o700)
    instance = oracle = None
    issuers = []
    result = {"schema": "heptabao." + profile + "-comparison.v1", "synthetic_only": True,
              "target_version": "2.6.2", "full_openbao_compatibility": False,
              "independent_qualification": False, "production_authority": False,
              "configuration_adaptation": ADAPTATION, "candidate_binary_sha256": before["binary_sha256"],
              "oracle_binary_sha256": BINARY_SHA256, "build_source_commit": args.build_source_commit,
              "build_source_binding_basis": "caller-supplied if present; exact binary hash recorded; not inferred from active checkout or independently attested",
              "runner_sha256": file_hash(runner_path), "launcher_sha256": file_hash(Path(__file__)),
              "scope": scope, "cases": {}, "side_failures": {},
              "started_at_unix": time.time()}
    try:
        instance = Instance(binary, root / "candidate")
        for _ in range(2):
            issuers.append(JsonIssuer(instance.root / "tls.crt", instance.root / "tls.key"))
        ca = (instance.root / "ca.crt").read_text()
        cfg_path = instance.root / "server.json"
        cfg = json.loads(cfg_path.read_text())
        cfg["lifecycle_interval_seconds"] = 0
        cfg["outbound_endpoints"] = [{"origin": issuers[0].origin, "address": "127.0.0.1:" + str(issuers[0].port),
                                     "server_name": "localhost", "ca_pem": ca}]
        cfg_path.write_text(json.dumps(cfg))
        cfg_path.chmod(0o600)
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise ScenarioFailure("jwt_renewal.candidate_init")
        instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
        if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
            raise ScenarioFailure("jwt_renewal.candidate_unseal")
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
                raise ScenarioFailure("jwt_renewal.candidate_restart_unseal")

        def restart_reference():
            oracle["process"].kill()
            oracle["process"].wait(timeout=5)
            stop_oracle(oracle)
            restart_oracle(oracle)

        for side, client, issuer, restart in [("candidate", candidate, issuers[0], restart_candidate),
                                             ("oracle", reference, issuers[1], restart_reference)]:
            result["cases"][side] = []
            for mode in ("static", "remote"):
                private, jwk = signing_key("ES256", "synthetic-" + mode)
                issuer.documents["/keys"] = {"keys": [jwk]}
                try:
                    scenario_runner(client, issuer, private, jwk, configuration(side, mode, issuer, private, jwk, ca),
                                    restart, mode, result["cases"][side])
                except ScenarioFailure as error:
                    result["side_failures"][side + "." + mode] = str(error)
                except Exception as error:
                    result["side_failures"][side + "." + mode] = "unexpected_" + type(error).__name__
        result["cases_match"] = result["cases"].get("candidate") == result["cases"].get("oracle")
        result["status"] = "passed" if successful_comparison(result["cases"], result["side_failures"]) else "mismatch"
    except ScenarioFailure as error:
        result["status"], result["safe_failure_code"] = "failed", str(error)
    except Exception as error:
        result["status"], result["safe_failure_code"] = "failed", "unexpected_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if oracle is not None:
            stop_oracle(oracle)
            shutil.rmtree(oracle["root"])
        for issuer in issuers:
            issuer.close()
        shutil.rmtree(root)
        after = source_identity(ROOT, binary)
        for name in ("source_commit", "source_tree", "source_dirty", "source_content_sha256"):
            result["harness_" + name] = before[name]
        result["harness_source_unchanged"] = before == after
        result["candidate_binary_unchanged"] = before["binary_sha256"] == after["binary_sha256"]
        if (not result["candidate_binary_unchanged"] or result["runner_sha256"] != file_hash(runner_path)
                or result["launcher_sha256"] != file_hash(Path(__file__))):
            result["status"], result["safe_failure_code"] = "failed", "binary_or_runner_changed_during_execution"
        result["finished_at_unix"] = time.time()
        if admit_output(output) != parent:
            raise ValueError("report_parent_changed")
        private_write(output, result)
    print(json.dumps({"status": result["status"], "checks_per_side": {side: len(rows) for side, rows in result["cases"].items()},
                      "side_failures": result["side_failures"], "safe_failure_code": result.get("safe_failure_code")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
