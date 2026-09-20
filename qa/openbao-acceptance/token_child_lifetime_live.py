#!/usr/bin/env python3
"""Compare scoped child-token lifetimes and period lookup with OpenBao 2.6.2.

Fresh HTTPS stores exercise multi-level ancestry, expiry/revocation, explicit
caps, orphans, restart, and AppRole/JWT issue-period lookup snapshots. Static
JWT configuration is adapted; this is not full token API qualification.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import socket
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, successful_comparison
from official_openbao_launcher import ARTIFACT_SHA256, BINARY_SHA256, restart_oracle, start_oracle, stop_oracle, verify_inputs
from online_evidence import admit_output, source_identity
from radius_renewal_live import renewal_token_shape
from remote_jwks_live import signing_key, token as sign_token, serialization

ISSUER = "https://synthetic-token-period.example.test"
EXPECTED_COUNT = 202


def period_matches(data, expected):
    return "period" not in data if expected == 0 else type(data.get("period")) is int and data["period"] == expected


def complete_side(rows):
    return (len(rows) == EXPECTED_COUNT and len({row.get("case") for row in rows}) == EXPECTED_COUNT
            and all(row.get("passed") is True for row in rows)
            and bool(rows) and rows[-1].get("case") == "token_child_lifetime.complete")


def run_scenarios(client, restart, jwt_config, assertion, results=None, *, wait=time.sleep):
    rows = [] if results is None else results

    def check(name, condition, **observation):
        rows.append({"case": "token_child_lifetime." + name, **observation, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure("token_child_lifetime." + name)

    def call(name, method, path, payload=None, *, bearer=None, expected=204):
        response = client.request(method, "/v1/" + path, payload, token=bearer)
        check(name, response.status == expected, status=response.status)
        return response.body

    def identity(name, body):
        auth = body.get("auth", {})
        check(name, all(isinstance(auth.get(key), str) and auth[key] for key in ("client_token", "accessor")))
        return {"token": auth["client_token"], "accessor": auth["accessor"]}

    def create(name, parent, ttl, *, orphan=False, explicit=0, can_issue=True):
        body = call(name + ".create", "POST", "auth/token/create", {
            "ttl": ttl, "policies": ["lifetime-issuer"] if can_issue else ["default"],
            "no_parent": orphan, "explicit_max_ttl": explicit},
            bearer=None if parent is None else parent["token"], expected=200)
        issued = identity(name + ".identity", body)
        check(name + ".reported_ttl", body["auth"].get("lease_duration") == (min(ttl, explicit) if explicit else ttl))
        return issued

    def lookup(name, issued, *, period=0, expected=200):
        body = call(name + ".lookup", "GET", "auth/token/lookup-self", bearer=issued["token"], expected=expected)
        if expected != 200:
            return None
        data = body.get("data", {})
        check(name + ".lookup_shape", type(data.get("ttl")) is int and data["ttl"] > 0 and period_matches(data, period))
        return data["ttl"]

    def renew(name, issued, increment, *, operation="renew-self", maximum=None, expected=200):
        payload = {} if increment is None else {"increment": increment}
        if operation == "renew":
            payload["token"] = issued["token"]
        if operation == "renew-accessor":
            payload["accessor"] = issued["accessor"]
        body = call(name + ".renew", "POST", "auth/token/" + operation, payload,
                    bearer=issued["token"] if operation == "renew-self" else None, expected=expected)
        if expected != 200:
            return
        auth = body.get("auth", {})
        check(name + ".renew_shape", renewal_token_shape(auth, issued["token"], via_accessor=operation == "renew-accessor")
              and auth.get("renewable") is True)
        value = auth.get("lease_duration")
        check(name + ".renew_ttl", type(value) is int and value > 0
              and (value <= maximum if maximum is not None else value == increment))

    call("issuer_policy", "POST", "sys/policies/acl/lifetime-issuer", {
        "policy": 'path "auth/token/*" { capabilities = ["read", "update", "sudo"] }'})
    call("approle_mount", "POST", "sys/auth/lifetime-approle", {"type": "approle"})
    role_defaults = {"token_ttl": 60, "token_max_ttl": 600, "token_period": 0,
                     "token_policies": ["lifetime-issuer"], "secret_id_num_uses": 0}

    def approle(name, period=0):
        path = "auth/lifetime-approle/role/" + name
        role = {**role_defaults, "token_period": period}
        call(name + ".role", "POST", path, role)
        role_id = call(name + ".role_id", "GET", path + "/role-id", expected=200)["data"]["role_id"]
        secret = call(name + ".secret_id", "POST", path + "/secret-id", {}, expected=200)["data"]["secret_id"]
        body = call(name + ".login", "POST", "auth/lifetime-approle/login", {"role_id": role_id, "secret_id": secret}, bearer="", expected=200)
        return identity(name + ".identity", body), path, role

    parent, _, _ = approle("parent60")
    child = create("child120", parent, 120)
    grandchild = create("grandchild240", child, 240, can_issue=False)
    orphan = create("orphan180", child, 180, orphan=True, can_issue=False)
    capped = create("explicit90", parent, 300, explicit=90, can_issue=False)
    parent_ttl = lookup("parent_before", parent)
    child_ttl = lookup("child_before", child)
    check("child_ttl_exceeds_parent", child_ttl > parent_ttl)
    for label, target, requested in (("child", child, 300), ("grandchild", grandchild, 600)):
        for operation in ("renew-self", "renew", "renew-accessor"):
            renew(label + "." + operation, target, requested, operation=operation)
    renew("child_explicit_cap", capped, 300, maximum=90)
    restart()
    call("reopened_health", "GET", "sys/health", expected=200)
    for label, target in (("parent", parent), ("child", child), ("grandchild", grandchild), ("capped", capped), ("orphan", orphan)):
        lookup("reopened." + label, target)
    call("revoke_grandparent", "POST", "auth/token/revoke", {"token": parent["token"]})
    for label, target in (("child", child), ("grandchild", grandchild), ("capped", capped)):
        lookup("revoked." + label, target, expected=403)
        renew("revoked." + label, target, 300, expected=403)
    lookup("orphan_after_revoke", orphan)
    renew("orphan_after_revoke", orphan, 300)

    # Revoke an intermediate node without revoking its parent or its orphan.
    upper = create("intermediate_revoke.parent", None, 60)
    middle = create("intermediate_revoke.child", upper, 120)
    leaf = create("intermediate_revoke.grandchild", middle, 240, can_issue=False)
    detached = create("intermediate_revoke.orphan", middle, 180, orphan=True, can_issue=False)
    call("revoke_intermediate", "POST", "auth/token/revoke", {"token": middle["token"]})
    lookup("intermediate_revoke.parent_survives", upper)
    lookup("intermediate_revoke.child_denied", middle, expected=403)
    lookup("intermediate_revoke.grandchild_denied", leaf, expected=403)
    lookup("intermediate_revoke.orphan_survives", detached)

    # Three independent trees share one short wait. Their reported child TTLs
    # exceed the short ancestor lifetime; only the third ancestor is renewed.
    short = create("expiry.grandparent", None, 4)
    long_child = create("expiry.child", short, 120)
    long_grandchild = create("expiry.grandchild", long_child, 240, can_issue=False)
    detached_short = create("expiry.orphan", long_child, 180, orphan=True, can_issue=False)
    upper = create("middle_expiry.parent", None, 60)
    middle = create("middle_expiry.child", upper, 4)
    leaf = create("middle_expiry.grandchild", middle, 120, can_issue=False)
    extended_parent = create("extended.parent", None, 4)
    extended_child = create("extended.child", extended_parent, 120, can_issue=False)
    renew("extended.parent", extended_parent, 60)
    wait(5)
    for label, target in (("grandparent", short), ("child", long_child), ("grandchild", long_grandchild)):
        lookup("expired." + label, target, expected=403)
        renew("expired." + label, target, 300, expected=403)
    lookup("expired.orphan_independent", detached_short)
    lookup("middle_expired.parent_survives", upper)
    lookup("middle_expired.child_denied", middle, expected=403)
    lookup("middle_expired.grandchild_denied", leaf, expected=403)
    lookup("extended.parent_survives", extended_parent)
    lookup("extended.child_survives", extended_child)

    call("jwt_mount", "POST", "sys/auth/lifetime-jwt", {"type": "jwt"})
    call("jwt_config", "POST", "auth/lifetime-jwt/config", jwt_config)

    def jwt(name, period):
        path = "auth/lifetime-jwt/role/" + name
        role = {"role_type": "jwt", "user_claim": "sub", "bound_audiences": ["heptabao-test"],
                "token_ttl": 60, "token_max_ttl": 600, "token_period": period}
        call(name + ".role", "POST", path, role)
        body = call(name + ".login", "POST", "auth/lifetime-jwt/login", {"role": name, "jwt": assertion()}, bearer="", expected=200)
        return identity(name + ".identity", body), path, role

    for provider, issue in (("approle", approle), ("jwt", jwt)):
        for initial, current, label in ((0, 30, "finite_to_periodic"), (30, 45, "period_changed"), (30, 0, "periodic_to_finite")):
            name = provider + "_" + label
            issued, path, role = issue(name, initial)
            lookup(name + ".before", issued, period=initial)
            call(name + ".change_role", "POST", path, {**role, "token_period": current})
            # Omitted increment follows the new live period/default TTL, but
            # lookup must keep the original token entry's period snapshot.
            body = call(name + ".renew", "POST", "auth/token/renew-self", {}, bearer=issued["token"], expected=200)
            check(name + ".current_lease", body.get("auth", {}).get("lease_duration") == (current or 60))
            lookup(name + ".after", issued, period=initial)
    check("complete", True)
    return rows


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary")
    parser.add_argument("--build-source-commit")
    parser.add_argument("--output", required=True)
    parser.add_argument("--oracle-only", action="store_true")
    args = parser.parse_args()
    if not args.oracle_only and not args.binary:
        parser.error("candidate binary required")
    if args.build_source_commit is not None and (len(args.build_source_commit) != 40
            or any(c not in "0123456789abcdef" for c in args.build_source_commit)):
        parser.error("build source commit must be a full lowercase commit id")
    output = Path(args.output).absolute()
    admitted = admit_output(output)
    binary = verify_inputs() if args.oracle_only else Path(args.binary).resolve(strict=True)
    before = source_identity(ROOT, binary)
    private_root = Path(tempfile.mkdtemp(prefix="heptabao-token-child-lifetime-"))
    private_root.chmod(0o700)
    instance = oracle = None
    report = {"schema": "heptabao.token-child-lifetime-comparison.v1", "synthetic_only": True,
              "target_version": "2.6.2", "candidate_observed": not args.oracle_only,
              "oracle_binary_sha256": BINARY_SHA256, "oracle_artifact_sha256": ARTIFACT_SHA256,
              "candidate_binary_sha256": None if args.oracle_only else before["binary_sha256"],
              "build_source_commit": args.build_source_commit,
              "build_source_binding_basis": "caller-supplied if present; exact binary hash recorded; not independent binary attestation",
              "configuration_adaptation": {"static_jwt": "candidate inline JWKS/issuer/audiences; oracle PEM public key/bound_issuer", "configuration_api_parity": False},
              "scope": "token-API child lifetime and ancestor validity; AppRole/JWT lookup period snapshots",
              "independent_qualification": False, "compatibility_claim": False, "production_authority": False,
              "expected_cases_per_side": EXPECTED_COUNT, "cases": {}, "side_failures": {}}
    try:
        for side in (["oracle"] if args.oracle_only else ["oracle", "candidate"]):
            rows = report["cases"][side] = []
            private, jwk = signing_key("ES256", "synthetic-period-key")
            if side == "oracle":
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = sock.getsockname()[1]
                oracle = start_oracle(port)
                client = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"], 8192).decode().strip())
                pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                config = {"bound_issuer": ISSUER, "jwt_validation_pubkeys": [pem], "jwt_supported_algs": ["ES256"]}

                def restart():
                    oracle["process"].kill()
                    oracle["process"].wait(timeout=5)
                    stop_oracle(oracle)
                    restart_oracle(oracle)
            else:
                spec = importlib.util.spec_from_file_location("token_lifetime_smoke", ROOT / "qa/single-node/smoke.py")
                smoke = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(smoke)
                instance = smoke.Instance(binary, private_root / "candidate")
                path = instance.root / "server.json"
                settings = json.loads(path.read_text())
                settings["lifecycle_interval_seconds"] = 0
                private_write(path, settings)
                instance.start()
                status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
                if status != 200:
                    raise ScenarioFailure("token_child_lifetime.candidate_init")
                instance.token = initialized["root_token"]
                key = initialized["keys_base64"][0]
                if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                    raise ScenarioFailure("token_child_lifetime.candidate_unseal")
                client = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
                config = {"issuer": ISSUER, "audiences": ["heptabao-test"], "jwks": {"keys": [jwk]}}

                def restart():
                    instance.stop()
                    instance.start()
                    if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                        raise ScenarioFailure("token_child_lifetime.candidate_restart_unseal")
            try:
                run_scenarios(client, restart, config, lambda: sign_token(private, jwk, ISSUER), rows)
            except ScenarioFailure as error:
                report["side_failures"][side] = str(error)
            except Exception as error:
                report["side_failures"][side] = "unexpected_" + type(error).__name__
        complete = all(complete_side(rows) for rows in report["cases"].values()) and not report["side_failures"]
        report["cases_match"] = not args.oracle_only and successful_comparison(report["cases"], report["side_failures"])
        report["status"] = ("oracle_passed" if args.oracle_only else "passed") if complete and (args.oracle_only or report["cases_match"]) else "failed"
    except Exception as error:
        report["status"] = "failed"
        report["safe_failure_code"] = str(error) if isinstance(error, ScenarioFailure) else "unexpected_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if oracle is not None:
            stop_oracle(oracle)
            shutil.rmtree(oracle["root"])
        shutil.rmtree(private_root)
        after = source_identity(ROOT, binary)
        report["source_identity"] = before
        report["source_and_binary_unchanged"] = before == after
        if before != after:
            report["status"] = "failed"
            report["safe_failure_code"] = "source_or_binary_changed_during_execution"
        if admit_output(output) != admitted:
            raise ValueError("report_parent_changed")
        private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "counts": {side: len(rows) for side, rows in report["cases"].items()}, "side_failures": report["side_failures"]}))
    return 0 if report["status"] in ("passed", "oracle_passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
