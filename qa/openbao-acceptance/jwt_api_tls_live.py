#!/usr/bin/env python3
"""Compare API-owned JWT/OIDC TLS trust using private local CAs and real code exchange.

Candidate endpoints have no startup outbound enrollment. The OIDC issuer is a
separate checksum-pinned OpenBao 2.6.2 process; JWTs use real ES256 signatures.
The profile still adapts OIDC PKCE enrollment and callback transport explicitly.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT
from external_tls_fixtures import JsonIssuer
from official_openbao_launcher import BINARY_SHA256, certificates, start_oracle, stop_oracle, restart_oracle
from oidc_renewal_live import OfficialIssuer, free_port
from online_evidence import admit_output, source_identity
from remote_jwks_live import Instance, signing_key, token

MODES = ("jwks", "jwt_discovery", "oidc")
CA_CASES = (("empty_ca", ""), ("null_ca", None), ("omitted_ca", "omitted"),
            ("wrong_ca", "wrong"), ("malformed_ca", "not-a-certificate"))


class Failure(Exception):
    pass


class Trace:
    def __init__(self, client, rows, prefix="setup"):
        self.client, self.rows, self.prefix = client, rows, prefix

    def check(self, name, passed, **observed):
        # Only fixed labels/status/booleans are accepted as evidence, never
        # request URLs, authorization codes, credentials or raw responses.
        if (not isinstance(name, str) or re.fullmatch(r"[a-z0-9_.]{1,150}", name) is None
                or any(type(value) not in (int, bool) for value in observed.values())):
            raise Failure("invalid_observation_shape")
        case = "api_tls." + self.prefix + "." + name
        self.rows.append({"case": case, **observed, "passed": passed is True})
        if passed is not True:
            raise Failure(case)

    def call(self, name, path, body=None, *, method="POST", bearer=None, expected=200, **unused):
        response = self.client.request(method, "/v1/" + path, body, token=bearer)
        self.check(name, response.status == expected, status=response.status)
        return response.body


def bounded_issuer(cert, key):
    issuer = JsonIssuer(cert, key)
    # Go keeps idle HTTP/1.1 sockets after config probes. The shared fixture's
    # error paths omit Connection: close; close every test connection here so a
    # previous failure cannot block this single-thread fixture's next request.
    original = issuer.server.RequestHandlerClass.do_GET
    def get(handler):
        try:
            original(handler)
        finally:
            handler.close_connection = True
    issuer.server.RequestHandlerClass.do_GET = get
    return issuer


def wrong_name_leaf(root, ca_root):
    root.mkdir(mode=0o700)
    (root / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:unrelated.invalid\n")
    commands = [
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "tls.key"),
         "-out", str(root / "tls.csr"), "-subj", "/CN=unrelated.invalid"],
        ["openssl", "x509", "-req", "-in", str(root / "tls.csr"), "-CA", str(ca_root / "ca.crt"),
         "-CAkey", str(ca_root / "ca.key"), "-set_serial", "4321", "-out", str(root / "tls.crt"),
         "-days", "2", "-sha256", "-extfile", str(root / "leaf.ext")],
    ]
    for command in commands:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / "tls.key").chmod(0o600)
    return root / "tls.crt", root / "tls.key"


def discovery(origin):
    return {"issuer": origin, "jwks_uri": origin + "/keys", "authorization_endpoint": origin + "/authorize",
            "token_endpoint": origin + "/token", "response_types_supported": ["code"],
            "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["ES256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"], "code_challenge_methods_supported": ["S256"]}


def configuration(mode, side, json_issuer, oidc, ca):
    if mode == "oidc":
        body = {"oidc_discovery_url": oidc.discovery, "oidc_client_id": oidc.client_id,
                "oidc_client_secret": oidc.client_secret, "jwt_supported_algs": ["RS256"],
                "oidc_discovery_ca_pem": ca}
        if side == "candidate":
            body["pkce_s256_enrolled"] = True
        return body
    body = {"bound_issuer": json_issuer.origin, "jwt_supported_algs": ["ES256"]}
    if mode == "jwks":
        body.update(jwks_url=json_issuer.origin + "/keys", jwks_ca_pem=ca)
    else:
        body.update(oidc_discovery_url=json_issuer.origin, oidc_discovery_ca_pem=ca)
    return body


def ca_variant(config, field, value, wrong):
    body = dict(config)
    if value == "omitted":
        body.pop(field)
    else:
        body[field] = wrong if value == "wrong" else value
    return body


def run_side(client, side, issuer, oidc, mismatch, private, jwk, ca, wrong, restart, rows):
    for mode in MODES:
        t = Trace(client, rows, mode)
        mount = "api-tls-" + mode
        field = "jwks_ca_pem" if mode == "jwks" else "oidc_discovery_ca_pem"
        params = configuration(mode, side, issuer, oidc, ca)
        kind = "oidc" if mode == "oidc" else "jwt"
        t.call("mount", "sys/auth/" + mount, {"type": kind}, expected=204)
        path = "auth/" + mount + "/config"
        # A fresh missing CA cannot silently borrow a process or issuer CA.
        t.call("fresh_private_ca_not_system_trusted", path, ca_variant(params, field, "omitted", wrong), expected=400)
        t.call("correct_ca", path, params, expected=204)
        current = t.call("correct_ca_read", path, method="GET").get("data", {})
        t.check("ca_exact_readback", current.get(field) == ca)
        t.check("client_secret_redacted", "oidc_client_secret" not in current)
        for label, value in CA_CASES:
            body = t.call(label, path, ca_variant(params, field, value, wrong), expected=400)
            t.check(label + ".no_authority_response", not body.get("auth") and not body.get("wrap_info"))
            preserved = t.call(label + ".read", path, method="GET").get("data", {})
            t.check(label + ".prior_config_preserved", preserved == current)

        # Name mismatch is isolated on a new mount: an existing immutable OIDC
        # issuer binding must not reject the URL before TLS verifies its SAN.
        bad_mount = mount + "-san"
        t.call("san.mount", "sys/auth/" + bad_mount, {"type": kind}, expected=204)
        bad = dict(params)
        if mode == "jwks":
            bad.update(bound_issuer=mismatch.origin, jwks_url=mismatch.origin + "/keys")
        else:
            bad["oidc_discovery_url"] = mismatch.origin
            if mode != "oidc":
                bad["bound_issuer"] = mismatch.origin
            else:
                bad["jwt_supported_algs"] = ["ES256"]
        before = len(mismatch.calls)
        t.call("san.rejected_with_correct_ca", "auth/" + bad_mount + "/config", bad, expected=400)
        t.check("san.no_http_request_after_failed_tls", len(mismatch.calls) == before)

        role = {"role_type": "oidc" if mode == "oidc" else "jwt", "user_claim": "sub",
                "token_policies": ["default"], "token_ttl": 300, "token_max_ttl": 600}
        if mode == "oidc":
            role["allowed_redirect_uris"] = [oidc.redirect]
        else:
            role["bound_audiences"] = ["heptabao-test"]
        t.call("role", "auth/" + mount + "/role/app", role, expected=204)
        if mode == "oidc":
            auth = oidc.login(t, side, "real_code", mount, "app")
        else:
            auth = t.call("signed_jwt", "auth/" + mount + "/login",
                          {"role": "app", "jwt": token(private, jwk, issuer.origin)}, bearer="").get("auth", {})
        t.check("issued_service_token", isinstance(auth.get("client_token"), str) and bool(auth["client_token"]))
        bearer = auth["client_token"]
        t.call("issued_token_usable", "auth/token/lookup-self", method="GET", bearer=bearer)
        restart()
        t.check("restart", True)
        reopened = t.call("restart.config", path, method="GET").get("data", {})
        t.check("restart.ca_preserved", reopened == current)
        t.call("restart.existing_token", "auth/token/lookup-self", method="GET", bearer=bearer)
        if mode == "oidc":
            again = oidc.login(t, side, "restart.real_code", mount, "app")
        else:
            again = t.call("restart.signed_jwt", "auth/" + mount + "/login",
                          {"role": "app", "jwt": token(private, jwk, issuer.origin)}, bearer="").get("auth", {})
        t.check("restart.fresh_token", isinstance(again.get("client_token"), str)
                and bool(again["client_token"]) and again["client_token"] != bearer)
        t.check("complete", True)


def successful(rows):
    if not isinstance(rows, list) or not rows:
        return False
    names = []
    for row in rows:
        if (not isinstance(row, dict) or row.get("passed") is not True
                or not isinstance(row.get("case"), str) or re.fullmatch(r"api_tls\.[a-z0-9_.]{1,160}", row["case"]) is None
                or any(type(value) not in (int, bool) for key, value in row.items() if key not in ("case", "passed"))):
            return False
        names.append(row["case"])
    return len(names) == len(set(names)) and all("api_tls." + mode + ".complete" in names for mode in MODES)


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--build-source-commit")
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.oracle_only and (args.binary is None or re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit or "") is None):
        parser.error("candidate binary and full build source commit required")
    output = args.output.absolute()
    admitted = admit_output(output)
    binary = args.binary.resolve(strict=True) if args.binary else None
    before = source_identity(ROOT, binary) if not args.oracle_only else None
    runner_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    root = Path(tempfile.mkdtemp(prefix="heptabao-jwt-api-tls-"))
    root.chmod(0o700)
    servers, providers, instance = [], [], None
    cases, setup, failures = {}, [], {}
    candidate_unenrolled = False
    try:
        issuer_server = start_oracle(free_port())
        servers.append(issuer_server)
        oidc = OfficialIssuer(issuer_server)
        oidc.setup(Trace(oidc.admin, setup), id_token_ttl=300)
        ca_root = Path(issuer_server["root"])
        ca = (ca_root / "ca.crt").read_text()
        issuer = bounded_issuer(ca_root / "tls.crt", ca_root / "tls.key")
        providers.append(issuer)
        private, jwk = signing_key("ES256", "synthetic-api-tls")
        issuer.documents["/keys"] = {"keys": [jwk]}
        issuer.documents["/.well-known/openid-configuration"] = discovery(issuer.origin)
        mismatch = bounded_issuer(*wrong_name_leaf(root / "mismatch", ca_root))
        providers.append(mismatch)
        mismatch.documents["/keys"] = {"keys": [jwk]}
        mismatch.documents["/.well-known/openid-configuration"] = discovery(mismatch.origin)
        wrong_root = root / "wrong-ca"
        wrong_root.mkdir(mode=0o700)
        certificates(wrong_root)
        wrong = (wrong_root / "ca.crt").read_text()

        oracle = start_oracle(free_port())
        servers.append(oracle)
        reference = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"], 8192).decode().strip())
        def restart_reference():
            stop_oracle(oracle)
            restart_oracle(oracle)

        targets = [("oracle", reference, restart_reference)]
        if not args.oracle_only:
            instance = Instance(binary, root / "candidate")
            cfg_path = instance.root / "server.json"
            cfg = json.loads(cfg_path.read_text())
            cfg.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
            cfg_path.write_text(json.dumps(cfg))
            cfg_path.chmod(0o600)
            candidate_unenrolled = json.loads(cfg_path.read_text()).get("outbound_endpoints") == []
            instance.start()
            status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
            if status != 200:
                raise Failure("candidate_init_failed")
            instance.token, key = init["root_token"], init["keys_base64"][0]
            if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                raise Failure("candidate_unseal_failed")
            candidate = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
            def restart_candidate():
                instance.stop()
                if json.loads(cfg_path.read_text()).get("outbound_endpoints") != []:
                    raise Failure("candidate_enrollment_changed")
                instance.start()
                if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                    raise Failure("candidate_restart_failed")
            targets.append(("candidate", candidate, restart_candidate))
        for side, client, restart in targets:
            cases[side] = []
            try:
                run_side(client, side, issuer, oidc, mismatch, private, jwk, ca, wrong, restart, cases[side])
            except Exception as error:
                failures[side] = str(error) if isinstance(error, Failure) else "fixture_" + type(error).__name__
    except Exception as error:
        failures["setup"] = str(error) if isinstance(error, Failure) else "fixture_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        for provider in providers:
            provider.close()
        for server in servers:
            stop_oracle(server)
            shutil.rmtree(server["root"])
        shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary) if before is not None else None
    runner_unchanged = runner_hash == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    equal = cases.get("candidate") == cases.get("oracle") if not args.oracle_only else None
    passed = (not failures and all(successful(rows) for rows in cases.values()) and bool(cases)
              and runner_unchanged and (args.oracle_only or (unchanged and candidate_unenrolled and equal)))
    report = {"schema": "heptabao.jwt-api-tls-comparison.v1", "status": "passed" if passed else "failed",
        "candidate_source": before, "build_source_commit": args.build_source_commit,
        "source_and_binary_unchanged": unchanged, "runner_sha256": runner_hash, "runner_unchanged": runner_unchanged,
        "oracle_binary_sha256": BINARY_SHA256, "target_version": "2.6.2", "oracle_only": args.oracle_only,
        "candidate_startup_enrollment_empty": candidate_unenrolled, "cases": cases, "setup": setup,
        "cases_match": equal, "failures": failures,
        "configuration_adaptation": {"candidate_oidc": "explicit pkce_s256_enrolled and POST callback with client_nonce",
            "oracle_oidc": "native GET callback query with client_nonce", "ca_fields": "identical API CA fields",
            "endpoint_authority": "candidate startup outbound_endpoints empty"},
        "real_official_oidc_issuer": any(row.get("case") == "api_tls.setup.issuer.login" and row.get("passed") is True for row in setup),
        "synthetic_only": True, "full_openbao_compatibility": False,
        "independent_qualification": False, "production_authority": False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "cases": {side: len(rows) for side, rows in cases.items()}, "failures": failures}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
