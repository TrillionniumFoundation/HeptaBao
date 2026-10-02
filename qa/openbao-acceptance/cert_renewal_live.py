#!/usr/bin/env python3
"""Compare scoped certificate renewal with pinned OpenBao 2.6.2 over real TLS.

HeptaBao currently requires a client certificate whenever a client CA is
configured. To test token renewal without mTLS, it restarts the same store
without that listener setting. OpenBao's default optional-client-certificate
listener is unchanged across its corresponding restart. This explicit listener
adaptation does not claim configuration API parity or overall cert parity.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import time
import urllib.request

from bao_http import Client, NoRedirect, SafeArgumentParser, private_read, private_write
from cert_auth_live import Fixture
from core_isolation import ROOT, ScenarioFailure, successful_comparison
from official_openbao_launcher import ARTIFACT_SHA256, BINARY_SHA256, restart_oracle, start_oracle, stop_oracle, verify_inputs
from online_evidence import admit_output, source_identity

ADAPTATION = {
    "candidate": "initial mandatory client-CA listener; same store restarted without tls_client_ca_file before no-client-certificate requests",
    "oracle": "default optional client-certificate listener; same store restarted with unchanged listener configuration",
    "role": "identical leaf PEM and token fields on both sides",
    "configuration_api_parity": False,
}


def tls_client(address, ca_file, token, certificates=None):
    client = Client(address, str(ca_file), token)
    if certificates is not None:
        context = ssl.create_default_context(cafile=str(ca_file))
        context.load_cert_chain(str(certificates[0]), str(certificates[1]))
        client._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    return client


def renewal_shape(body, maximum):
    auth = body.get("auth", {})
    return (isinstance(auth, dict) and auth.get("renewable") is True
            and type(auth.get("lease_duration")) is int
            and 0 < auth["lease_duration"] <= maximum
            and auth.get("token_policies") == ["default"])


def run_scenarios(cert_client, plain_client, certificate, restart, results=None, *, wait=time.sleep):
    results = [] if results is None else results

    def check(case, condition, **observation):
        results.append({"case": "cert_renewal." + case, **observation, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure("cert_renewal." + case)

    def call(case, client, method, path, body=None, *, token=None, expected=204):
        response = client.request(method, "/v1/" + path, body, token=token)
        check(case, response.status == expected, status=response.status)
        return response.body

    call("mount", cert_client, "POST", "sys/auth/cert-renewal", {"type": "cert"})
    call("issuer_policy", cert_client, "POST", "sys/policies/acl/cert-issuer", {
        "policy": 'path "auth/token/create" { capabilities = ["update", "sudo"] }'})
    role = {"certificate": certificate, "token_policies": ["cert-issuer"],
            "token_ttl": 120, "token_max_ttl": 300}
    role_path = "auth/cert-renewal/certs/operator"
    call("role", cert_client, "POST", role_path, role)
    login = call("login", cert_client, "POST", "auth/cert-renewal/login", {"name": "operator"}, token="", expected=200)
    direct = login.get("auth", {}).get("client_token")
    check("login_shape", isinstance(direct, str) and bool(direct))
    renewed = call("same_leaf_renewal", cert_client, "POST", "auth/token/renew-self", {"increment": 120}, token=direct, expected=200)
    check("same_leaf_shape", renewed.get("auth", {}).get("renewable") is True
          and 0 < renewed.get("auth", {}).get("lease_duration", 0) <= 120)
    call("raise_current_role_maximum", cert_client, "POST", role_path, {**role, "token_max_ttl": 600})
    raised = call("raised_maximum_renewal", cert_client, "POST", "auth/token/renew-self",
                  {"increment": 500}, token=direct, expected=200)
    check("raised_maximum_extends_beyond_issue_snapshot", raised.get("auth", {}).get("lease_duration") == 500)
    defaulted = call("omitted_increment_renewal", cert_client, "POST", "auth/token/renew-self", {}, token=direct, expected=200)
    check("omitted_increment_uses_current_role_ttl", defaulted.get("auth", {}).get("lease_duration") == 120)
    children = {}
    for label, orphan in (("child", False), ("orphan", True)):
        created = call(label + "_create", cert_client, "POST", "auth/token/create",
                       {"policies": ["default"], "ttl": 120, "no_parent": orphan}, token=direct, expected=200)
        auth = created.get("auth", {})
        check(label + "_identity", isinstance(auth.get("client_token"), str) and bool(auth["client_token"])
              and isinstance(auth.get("accessor"), str) and bool(auth["accessor"]))
        children[label] = (auth["client_token"], auth["accessor"])

    # This wait is longer than the newly configured maximum, but far shorter
    # than the issued lease. No assumption about wall-clock second alignment.
    wait(3)
    call("shrink_current_role_maximum", cert_client, "POST", role_path,
         {**role, "token_ttl": 1, "token_max_ttl": 1})
    before = call("before_past_maximum", cert_client, "GET", "auth/token/lookup-self", token=direct, expected=200)
    # Confirmed against official 2.6.2: CalculateTTL's past-max error propagates
    # as 500. Denial is not normalized into another status in this comparison.
    call("past_issue_time_maximum", cert_client, "POST", "auth/token/renew-self", {"increment": 60}, token=direct, expected=500)
    after = call("after_past_maximum", cert_client, "GET", "auth/token/lookup-self", token=direct, expected=200)
    before_ttl, after_ttl = before.get("data", {}).get("ttl"), after.get("data", {}).get("ttl")
    check("failed_renewal_did_not_extend", type(before_ttl) is int and type(after_ttl) is int
          and 0 < after_ttl <= before_ttl)

    call("restore_valid_certificate_role", cert_client, "POST", role_path, {**role, "token_max_ttl": 600})
    restart()
    call("restart_no_client_certificate_transport", plain_client, "GET", "sys/health", expected=200)
    call("direct_binding_requires_client_certificate", plain_client, "POST", "auth/token/renew-self",
         {"increment": 60}, token=direct, expected=400)
    for label, (token, _) in children.items():
        renewed = call(label + "_without_client_certificate", plain_client, "POST", "auth/token/renew-self",
                       {"increment": 60}, token=token, expected=200)
        check(label + "_without_client_certificate_shape", renewal_shape(renewed, 60))
    call("delete_certificate_role", plain_client, "DELETE", role_path)
    for label, (token, accessor) in children.items():
        for operation, payload, actor in (
            ("renew-self", {"increment": 60}, token),
            ("renew", {"token": token, "increment": 60}, None),
            ("renew-accessor", {"accessor": accessor, "increment": 60}, None),
        ):
            name = label + "_deleted_role_" + operation.replace("-", "_")
            renewed = call(name, plain_client, "POST", "auth/token/" + operation,
                           payload, token=actor, expected=200)
            check(name + "_shape", renewal_shape(renewed, 60))
    call("disable_certificate_mount", plain_client, "DELETE", "sys/auth/cert-renewal")
    call("child_revoked_with_parent", plain_client, "GET", "auth/token/lookup-self", token=children["child"][0], expected=403)
    call("orphan_survives_parent_mount", plain_client, "GET", "auth/token/lookup-self", token=children["orphan"][0], expected=200)
    renewed = call("orphan_renews_after_mount_disable", plain_client, "POST", "auth/token/renew-self",
                   {"increment": 60}, token=children["orphan"][0], expected=200)
    check("orphan_renews_after_mount_disable_shape", renewal_shape(renewed, 60))
    return results


EXPECTED_CASES = tuple("cert_renewal." + name for name in [
    "mount", "issuer_policy", "role", "login", "login_shape", "same_leaf_renewal", "same_leaf_shape",
    "raise_current_role_maximum", "raised_maximum_renewal", "raised_maximum_extends_beyond_issue_snapshot",
    "omitted_increment_renewal", "omitted_increment_uses_current_role_ttl",
    "child_create", "child_identity", "orphan_create", "orphan_identity",
    "shrink_current_role_maximum", "before_past_maximum", "past_issue_time_maximum",
    "after_past_maximum", "failed_renewal_did_not_extend", "restore_valid_certificate_role",
    "restart_no_client_certificate_transport", "direct_binding_requires_client_certificate",
    "child_without_client_certificate", "child_without_client_certificate_shape",
    "orphan_without_client_certificate", "orphan_without_client_certificate_shape", "delete_certificate_role",
    *[label + "_deleted_role_" + operation + suffix
      for label in ("child", "orphan") for operation in ("renew_self", "renew", "renew_accessor")
      for suffix in ("", "_shape")],
    "disable_certificate_mount", "child_revoked_with_parent", "orphan_survives_parent_mount",
    "orphan_renews_after_mount_disable", "orphan_renews_after_mount_disable_shape",
])
EXPECTED_COUNT = len(EXPECTED_CASES)


def complete_side(rows):
    return (tuple(row.get("case") for row in rows) == EXPECTED_CASES
            and all(row.get("passed") is True for row in rows))


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary")
    parser.add_argument("--output", required=True)
    parser.add_argument("--oracle-only", action="store_true")
    args = parser.parse_args()
    if not args.oracle_only and not args.binary:
        parser.error("candidate binary required for comparison")
    output = Path(args.output).absolute()
    admitted = admit_output(output)
    binary = verify_inputs() if args.oracle_only else Path(args.binary).resolve(strict=True)
    before = source_identity(ROOT, binary)
    private_root = Path(tempfile.mkdtemp(prefix="heptabao-cert-renewal-"))
    private_root.chmod(0o700)
    fixtures, oracle = [], None
    report = {"schema": "heptabao.cert-renewal-comparison.v1", "synthetic_only": True,
              "target_version": "2.6.2", "configuration_adaptation": ADAPTATION,
              "candidate_observed": not args.oracle_only, "oracle_binary_sha256": BINARY_SHA256,
              "oracle_artifact_sha256": ARTIFACT_SHA256,
              "candidate_binary_sha256": None if args.oracle_only else before["binary_sha256"],
              "expected_cases_per_side": EXPECTED_COUNT,
              "independent_qualification": False, "compatibility_claim": False, "production_authority": False,
              "cases": {}, "side_failures": {}, "started_at_unix": time.time()}
    try:
        # Oracle first makes status/lease expectations inspectable before a
        # candidate failure; both sides always use independent fresh stores.
        for side in (["oracle"] if args.oracle_only else ["oracle", "candidate"]):
            rows = report["cases"][side] = []
            fixture = Fixture(binary, private_root / side)
            fixtures.append(fixture)
            if side == "oracle":
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = sock.getsockname()[1]
                oracle = start_oracle(port)
                address, ca = oracle["address"], oracle["ca_file"]
                root_token = private_read(oracle["token_file"], 8192).decode().strip()

                def restart():
                    oracle["process"].kill()
                    oracle["process"].wait(timeout=5)
                    stop_oracle(oracle)
                    restart_oracle(oracle)
            else:
                config_path = fixture.root / "server.json"
                config = json.loads(config_path.read_text())
                config["lifecycle_interval_seconds"] = 0
                private_write(config_path, config)
                fixture.start()
                status, initialized = fixture.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
                if status != 200:
                    raise ScenarioFailure("cert_renewal.candidate_init")
                fixture.token = initialized["root_token"]
                fixture.unseal_key = initialized["keys_base64"][0]
                if fixture.call("POST", "sys/unseal", {"key": fixture.unseal_key})[0] != 200:
                    raise ScenarioFailure("cert_renewal.candidate_unseal")
                address, ca, root_token = fixture.address, fixture.root / "root.crt", fixture.token

                def restart():
                    fixture.stop()
                    config.pop("tls_client_ca_file")
                    private_write(config_path, config)
                    fixture.start()
                    if fixture.call("POST", "sys/unseal", {"key": fixture.unseal_key}, client=fixture.no_cert_client)[0] != 200:
                        raise ScenarioFailure("cert_renewal.candidate_restart_unseal")

            cert = tls_client(address, ca, root_token, (fixture.root / "client-chain.pem", fixture.root / "client.key"))
            plain = tls_client(address, ca, root_token)
            try:
                run_scenarios(cert, plain, (fixture.root / "client.crt").read_text(), restart, rows)
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
        for fixture in fixtures:
            fixture.stop()
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
        report["finished_at_unix"] = time.time()
        if admit_output(output) != admitted:
            raise ValueError("report_parent_changed")
        private_write(output, report, replace=False)
    print(json.dumps({key: report[key] for key in ("status", "candidate_observed", "side_failures")}))
    return 0 if report["status"] in ("passed", "oracle_passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
