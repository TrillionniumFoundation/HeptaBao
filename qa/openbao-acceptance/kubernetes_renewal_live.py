#!/usr/bin/env python3
"""Compare Kubernetes token renewal against pinned OpenBao 2.6.2 over HTTPS.

The upstream is a synthetic TLS TokenReview protocol fixture, not kube-apiserver,
etcd, a Kubernetes distribution, or a Kubernetes RBAC acceptance test.
"""
from __future__ import annotations

import http.server
import json
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import tempfile
import threading
import time

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash, successful_comparison
from online_evidence import admit_output, source_identity
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle
from radius_renewal_live import renewal_token_shape, wrapped_renewal_shape
from remote_jwks_live import Instance, signing_key, serialization
from jwt_login_claims_live import signed_assertion
from jwt_renewal_live import Trace as JwtTrace

AUDIENCE = "heptabao-online"
REVIEW_PATH = "/apis/authentication.k8s.io/v1/tokenreviews"
ADAPTATION = {
    "candidate": "TokenReview host and reviewer JWT; CA/address enrolled at process startup",
    "oracle": "same TokenReview host and reviewer JWT; mount CA, ES256 PEM key, issuer validation",
    "assertion": "same synthetic ES256 signed ServiceAccount JWT claims; aud is an array",
    "request": "candidate sends apiVersion/kind; official 2.6.2 omits TypeMeta; both must bind exact spec and reviewer bearer",
    "role_updates": "complete payloads except the explicit partial-update case",
    "configuration_api_parity": False,
}


def request_matches(path, body, authorization, reviewer, presented, side):
    if not isinstance(body, dict):
        return False
    type_meta = ((body.get("apiVersion") == "authentication.k8s.io/v1" and body.get("kind") == "TokenReview")
                 if side == "candidate" else "apiVersion" not in body and "kind" not in body)
    return (path == REVIEW_PATH and type_meta and authorization == ["Bearer " + reviewer]
            and body.get("spec") == {"token": presented, "audiences": [AUDIENCE]})


class Reviewer:
    def __init__(self, cert, key, side):
        self.reviewer, self.presented = secrets.token_urlsafe(32), ""
        self.mode, self.calls, self.request_valid = "normal", [], True
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                owner.calls.append(REVIEW_PATH)
                try:
                    lengths = self.headers.get_all("Content-Length", [])
                    length = int(lengths[0]) if len(lengths) == 1 else -1
                    if not 0 < length <= 65536:
                        raise ValueError("request_bounds")
                    body = json.loads(self.rfile.read(length))
                    valid = request_matches(self.path, body, self.headers.get_all("Authorization"),
                                            owner.reviewer, owner.presented, side)
                    owner.request_valid &= valid
                    if not valid or owner.mode == "unavailable":
                        self.send_response(503)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    response = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                                "status": {"authenticated": True, "audiences": [AUDIENCE],
                                           "user": {"username": "system:serviceaccount:workload:worker",
                                                    "uid": "synthetic-kube-uid", "groups": ["system:serviceaccounts"]}}}
                    raw = json.dumps(response).encode()
                    self.send_response(201)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except (ValueError, OSError, ssl.SSLError):
                    owner.request_valid = False
                    self.close_connection = True
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_port
        self.origin = "https://localhost:" + str(self.port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("reviewer_join_failed")


def configuration(side, reviewer, private, ca):
    config = {"kubernetes_host": reviewer.origin, "token_reviewer_jwt": reviewer.reviewer,
              "disable_local_ca_jwt": True}
    if side == "oracle":
        config.update(kubernetes_ca_cert=ca, issuer="kubernetes/serviceaccount", disable_iss_validation=False,
                      pem_keys=[private.public_key().public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()])
    return config


def assertion(private, jwk, **changes):
    claims = {"aud": [AUDIENCE], "sub": "system:serviceaccount:workload:worker",
              "kubernetes.io/serviceaccount/service-account.name": "worker",
              "kubernetes.io/serviceaccount/service-account.uid": "synthetic-kube-uid",
              "kubernetes.io/serviceaccount/namespace": "workload"}
    claims.update(changes)
    return signed_assertion(private, jwk, "kubernetes/serviceaccount", case="kubernetes-renewal", **claims)


def role(**changes):
    config = {"bound_service_account_names": ["worker"], "bound_service_account_namespaces": ["workload"],
              "audience": AUDIENCE, "token_policies": ["kube-old"], "token_ttl": 60, "token_max_ttl": 90}
    config.update(changes)
    return config


def issued_policy_snapshot(auth):
    policies = auth.get("token_policies")
    return isinstance(policies, list) and "kube-old" in policies and "kube-new" not in policies


class Trace(JwtTrace):
    def __init__(self, client, reviewer, results):
        super().__init__(client, reviewer, "tokenreview", results)

    def check(self, name, condition, **observed):
        case = "kubernetes_renewal." + name
        self.results.append({"case": case, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(case)


def run_scenarios(client, issuer, private, jwk, config, restart, mode, results):
    t = Trace(client, issuer, results)
    mount = "platform/kubernetes-renew"
    role_path = "auth/" + mount + "/role/test"
    issuer.mode = "normal"
    t.call("mount", "sys/auth/" + mount, {"type": "kubernetes"}, expected=204)
    t.call("config", "auth/" + mount + "/config", config, expected=204)
    rules = ('path "auth/token/create" { capabilities = ["update", "sudo"] }\n'
             'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
    t.call("old_policy", "sys/policies/acl/kube-old", {"policy": rules}, method="PUT", expected=204)
    t.call("new_policy", "sys/policies/acl/kube-new", {"policy": 'path "sys/health" { capabilities = ["read"] }'}, method="PUT", expected=204)
    t.call("role", role_path, role(), expected=204)
    assertion_expiry = int(time.time()) + 2
    signed = assertion(private, jwk, exp=assertion_expiry)
    issuer.presented = signed
    before_login = len(issuer.calls)
    logged = t.call("login", "auth/" + mount + "/login", {"role": "test", "jwt": signed})
    auth = logged.get("auth", {})
    t.check("login.shape", all(isinstance(auth.get(field), str) and auth[field] for field in ("client_token", "accessor")))
    bearer, accessor = auth["client_token"], auth["accessor"]
    t.check("login.ttl_not_capped_by_assertion", auth.get("lease_duration") == 60)
    t.check("login.policy_snapshot", issued_policy_snapshot(auth))
    t.check("login.tokenreview_binding", len(issuer.calls) == before_login + 1 and issuer.request_valid)
    t.check("login.renewable", auth.get("renewable") is True)
    children = {}
    for name, path in [("child", "auth/token/create"), ("orphan", "auth/token/create-orphan")]:
        body = t.call(name + ".create", path, {"policies": ["default", "kube-old"], "ttl": "60s"}, bearer=bearer)
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
           role(token_max_ttl=600, token_policies=["kube-new"], audience="new-audience", bound_service_account_names=["other"], bound_service_account_namespaces=["foreign"]), expected=204, no_provider=True)
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
    signed = assertion(private, jwk)
    issuer.presented = signed
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

    t.call("config.reviewer_changed", "auth/" + mount + "/config",
           dict(config, token_reviewer_jwt=secrets.token_urlsafe(32)), expected=204, no_provider=True)
    body = t.call("config_change.does_not_revalidate", "auth/token/renew-self", {"increment": 120}, bearer=bearer, no_provider=True)
    t.check("config_change.policy_snapshot", issued_policy_snapshot(body.get("auth", {})))
    t.call("config.restore", "auth/" + mount + "/config", config, expected=204, no_provider=True)
    default_path = "auth/" + mount + "/role/defaults"
    t.call("defaults.tune", "sys/auth/" + mount + "/tune",
           {"default_lease_ttl": "45s", "max_lease_ttl": "600s"}, expected=204, no_provider=True)
    t.call("defaults.role", default_path, role(token_ttl=0, token_max_ttl=0), expected=204, no_provider=True)
    readback = t.call("defaults.readback", default_path, method="GET", no_provider=True).get("data", {})
    t.check("defaults.zero_preserved", readback.get("token_ttl") == 0 and readback.get("token_max_ttl") == 0)
    t.call("defaults.partial_update", default_path, {"token_policies": ["kube-new"]}, expected=204, no_provider=True)
    readback = t.call("defaults.partial_readback", default_path, method="GET", no_provider=True).get("data", {})
    t.check("defaults.partial_preserves_bindings", readback.get("bound_service_account_names") == ["worker"]
            and readback.get("bound_service_account_namespaces") == ["workload"]
            and readback.get("audience") == AUDIENCE and readback.get("token_ttl") == 0
            and readback.get("token_policies") == ["kube-new"])
    issuer.mode = "normal"
    issuer.presented = assertion(private, jwk)
    body = t.call("defaults.login", "auth/" + mount + "/login", {"role": "defaults", "jwt": issuer.presented})
    default_token = body.get("auth", {}).get("client_token")
    t.check("defaults.mount_default_applies", isinstance(default_token, str) and bool(default_token)
            and body.get("auth", {}).get("lease_duration") == 45 and body.get("auth", {}).get("renewable") is True)
    issuer.mode = "unavailable"
    body = t.call("defaults.renew", "auth/token/renew-self", {}, bearer=default_token, no_provider=True)
    t.check("defaults.renew_uses_mount_default", body.get("auth", {}).get("lease_duration") == 45)
    for label, path, payload in [
            ("empty", default_path, {"token_policies": []}),
            ("omitted", "auth/" + mount + "/role/no-policies",
             {key: value for key, value in role(token_ttl=0, token_max_ttl=0).items() if key != "token_policies"})]:
        t.call("policies." + label + ".configure", path, payload, expected=204, no_provider=True)
        readback = t.call("policies." + label + ".read", path, method="GET", no_provider=True).get("data", {})
        t.check("policies." + label + ".role_has_no_implicit_default", readback.get("token_policies") == [])
        issuer.mode = "normal"
        issuer.presented = assertion(private, jwk)
        body = t.call("policies." + label + ".login", "auth/" + mount + "/login",
                      {"role": path.rsplit("/", 1)[1], "jwt": issuer.presented})
        t.check("policies." + label + ".token_has_default", body.get("auth", {}).get("token_policies") == ["default"])
        issuer.mode = "unavailable"
    t.check("all_tokenreview_requests_bound", issuer.request_valid)

def main():
    runner_path = Path(__file__)
    launcher_path = runner_path.with_name("official_openbao_launcher.py")
    profile = "kubernetes-renewal"
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
              "runner_sha256": file_hash(runner_path), "launcher_sha256": file_hash(launcher_path),
              "actual_kube_apiserver": False, "kubernetes_rbac_acceptance": False,
              "scope": "Synthetic TLS TokenReview login followed by native service-token renewal", "cases": {}, "side_failures": {},
              "started_at_unix": time.time()}
    try:
        instance = Instance(binary, root / "candidate")
        for side in ("candidate", "oracle"):
            issuers.append(Reviewer(instance.root / "tls.crt", instance.root / "tls.key", side))
        ca = (instance.root / "ca.crt").read_text()
        cfg_path = instance.root / "server.json"
        cfg = json.loads(cfg_path.read_text())
        cfg["lifecycle_interval_seconds"] = 0
        cfg["outbound_endpoints"] = [{"origin": issuers[0].origin, "address": "127.0.0.1:" + str(issuers[0].port),
                                     "server_name": "localhost", "ca_pem": ca, "path_prefix": "/apis/authentication.k8s.io/v1/"}]
        cfg_path.write_text(json.dumps(cfg))
        cfg_path.chmod(0o600)
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise ScenarioFailure("kubernetes_renewal.candidate_init")
        instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
        if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
            raise ScenarioFailure("kubernetes_renewal.candidate_unseal")
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
                raise ScenarioFailure("kubernetes_renewal.candidate_restart_unseal")

        def restart_reference():
            oracle["process"].kill()
            oracle["process"].wait(timeout=5)
            stop_oracle(oracle)
            restart_oracle(oracle)

        for side, client, issuer, restart in [("candidate", candidate, issuers[0], restart_candidate),
                                             ("oracle", reference, issuers[1], restart_reference)]:
            result["cases"][side] = []
            private, jwk = signing_key("ES256", "synthetic-kubernetes")
            try:
                run_scenarios(client, issuer, private, jwk, configuration(side, issuer, private, ca),
                              restart, "tokenreview", result["cases"][side])
            except ScenarioFailure as error:
                result["side_failures"][side] = str(error)
            except Exception as error:
                result["side_failures"][side] = "unexpected_" + type(error).__name__
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
                or result["launcher_sha256"] != file_hash(launcher_path)):
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
