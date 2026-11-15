#!/usr/bin/env python3
"""Compare native JWT bound_claims against official 2.6.2; OIDC is excluded.

Static ES256 configuration is explicitly adapted. Remote JWKS uses the same API
CA. All assertions are signed synthetic data. Candidate concurrency checks are
reported separately from differential observations.
"""
from __future__ import annotations
import hashlib
import http.client
import json
from pathlib import Path
import re
import shutil
import ssl
import tempfile
import urllib.parse

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT
from jwt_api_tls_live import Failure, bounded_issuer
from jwt_login_claims_live import signed_assertion
from jwt_renewal_live import configuration, role
from jwt_split_phase_live import gate, EVENTS, COUNTERS
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle
from oidc_renewal_live import free_port
from online_evidence import admit_output, source_identity
from remote_jwks_live import Instance, signing_key

MODES = ("static", "remote")
ACCEPTED = frozenset({
    "string_exact", "boolean_exact", "number_integer_scalar", "number_fraction_scalar_truncates",
    "number_negative_fraction_truncates", "number_expected_zero", "number_array_scalar",
    "number_rounded_above_exact_float", "null_list_element", "mixed_list_alternative",
    "string_scalar_list", "string_list_scalar", "glob_star_empty", "glob_empty_exact",
    "glob_crosses_slash", "glob_question_exact", "glob_multiple_parts", "glob_skips_nonstring_actual",
    "pointer_escaped", "pointer_plus", "pointer_octal", "pointer_hex", "pointer_empty_index",
    "pointer_invalid_escape_literal", "pointer_empty_key", "literal_empty_selector",
})
ROLE_REJECTED = frozenset({"glob_rejects_nonstring_expected"})
ADAPTATION = {
    "static_candidate": "issuer/audiences and inline ES256 JWKS",
    "static_oracle": "bound_issuer and PEM jwt_validation_pubkeys with ES256",
    "remote": "same JWKS URL and API jwks_ca_pem; candidate startup endpoints empty",
    "partial": "role_type=jwt explicit in partial writes to avoid official default OIDC role behavior",
    "scope": "signed JWT login only; not OIDC code/UserInfo, proof API, out-of-i64 claims or arrays of composite values",
    "gate": "candidate-only full-role snapshot fence while HTTPS JWKS response is held",
}


class Trace:
    def __init__(self, client, rows, prefix):
        self.client, self.rows, self.prefix = client, rows, prefix

    def check(self, name, passed, **observed):
        if (re.fullmatch(r"[a-z0-9_.]{1,150}", name) is None
                or any(type(value) not in (int, bool) for value in observed.values())):
            raise Failure("invalid_observation")
        label = "bound_claims." + self.prefix + "." + name
        self.rows.append({"case": label, **observed, "passed": passed is True})
        if passed is not True:
            raise Failure(label)

    def call(self, name, path, payload=None, *, method="POST", bearer=None, expected=200, wrap_ttl=None):
        response = self.client.request(method, "/v1/" + path, payload, token=bearer, wrap_ttl=wrap_ttl)
        self.check(name, response.status == expected, status=response.status)
        return response.body


def matrix():
    # The optional final item supplies a raw bound numeric literal. Python's
    # JSON float formatting must not erase the official Number's lexical form.
    rows = []
    def add(name, expected, actual, *, mode="string", selector="value", raw=None, claims=None):
        rows.append((name, mode, {selector: expected},
                     {"value": actual} if claims is None else claims, raw))
    add("string_exact", "alpha", "alpha")
    add("string_case_sensitive", "alpha", "Alpha")
    add("boolean_exact", True, True)
    add("boolean_string_distinct", True, "true")
    add("number_integer_scalar", 42, 42)
    add("number_fraction_scalar_truncates", 42, 42.9)
    add("number_negative_fraction_truncates", -42, -42.9)
    add("number_expected_fraction", 42.9, 42.9)
    add("number_expected_decimal_integer", 42.0, 42)
    add("number_expected_exponent_integer", "_bound_number_", 42, raw="42e0")
    add("number_expected_negative_zero", "_bound_number_", 0, raw="-0")
    add("number_expected_zero", 0, -0.0)
    add("number_string_distinct", 42, "42")
    add("number_scalar_array", 42, [42])
    add("number_array_scalar", [42], 42)
    add("number_array_array", [42], [42])
    add("number_rounded_above_exact_float", 9007199254740992, 9007199254740993)
    add("number_unrounded_above_exact_float", 9007199254740993, 9007199254740993)
    add("null_scalar", None, None)
    add("null_list_element", [None], [None])
    add("mixed_list_alternative", [None, "alpha"], [False, "alpha"])
    add("string_scalar_list", "alpha", ["other", "alpha"])
    add("string_list_scalar", ["other", "alpha"], "alpha")
    add("empty_list", [], [])
    add("missing", "alpha", None, claims={})
    add("object_scalar", {"key": "alpha"}, {"key": "alpha"})
    add("glob_star_empty", "*", "", mode="glob")
    add("glob_empty_exact", "", "", mode="glob")
    add("glob_crosses_slash", "repo/*/main", "repo/team/sub/main", mode="glob")
    add("glob_question_literal", "a?c", "abc", mode="glob")
    add("glob_brackets_literal", "a[bc]", "ab", mode="glob")
    add("glob_question_exact", "a?c", "a?c", mode="glob")
    add("glob_multiple_parts", "a*b*c", "a---b---c", mode="glob")
    add("glob_rejects_nonstring_expected", 42, "42", mode="glob")
    add("glob_skips_nonstring_actual", "a*", [42, "alpha"], mode="glob")
    pointer_claims = {"a/b": {"~name": ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight"]},
                      "invalid~2": "literal", "": "empty-key"}
    for name, pointer, expected in (
        ("pointer_escaped", "/a~1b/~0name/1", "one"),
        ("pointer_plus", "/a~1b/~0name/+1", "one"),
        ("pointer_octal", "/a~1b/~0name/010", "eight"),
        ("pointer_octal_invalid", "/a~1b/~0name/08", "eight"),
        ("pointer_hex", "/a~1b/~0name/0x1", "one"),
        ("pointer_empty_index", "/a~1b/~0name/", "zero"),
        ("pointer_invalid_escape_literal", "/invalid~2", "literal"),
        ("pointer_empty_key", "/", "empty-key"),
        ("literal_empty_selector", "", "empty-key"),
        ("pointer_missing", "/absent", "alpha"),
    ):
        add(name, expected, None, selector=pointer, claims=pointer_claims)
    return rows


def numeric_payload(payload, raw):
    if raw not in ("42e0", "-0"):
        raise ValueError("unrecognized_numeric_literal")
    encoded = json.dumps(payload)
    if encoded.count('"_bound_number_"') != 1:
        raise ValueError("numeric_marker_shape")
    return encoded.replace('"_bound_number_"', raw).encode()


def raw_role(client, ca, path, payload, raw):
    address = urllib.parse.urlsplit(client.address)
    connection = http.client.HTTPSConnection(address.hostname, address.port,
        context=ssl.create_default_context(cafile=ca), timeout=10)
    try:
        connection.request("POST", "/v1/" + path, numeric_payload(payload, raw),
                           {"Content-Type": "application/json", "X-Vault-Token": client._token})
        response = connection.getresponse()
        if len(response.read(128 * 1024 + 1)) > 128 * 1024:
            raise Failure("numeric_role_response_oversized")
        return response.status
    finally:
        connection.close()


def claims_role(**changes):
    return role(token_policies=["default"], token_ttl=300, token_max_ttl=600, **changes)


def partial_steps():
    initial = claims_role(bound_claims_type="glob", bound_claims={"value": "a*"})
    return [
        ("setup", initial, 204, "glob", {"value": "a*"}),
        ("ttl_only", {"role_type": "jwt", "token_ttl": 301}, 204, "string", {"value": "a*"}),
        ("restore_glob", {"role_type": "jwt", "bound_claims_type": "glob"}, 204, "glob", {"value": "a*"}),
        ("empty_map", {"role_type": "jwt", "bound_claims_type": "glob", "bound_claims": {}}, 204, "glob", {}),
        ("restore", initial, 204, "glob", {"value": "a*"}),
        ("null_map", {"role_type": "jwt", "bound_claims": None}, 204, "string", {}),
        ("restore_again", initial, 204, "glob", {"value": "a*"}),
        ("null_type", {"role_type": "jwt", "bound_claims_type": None}, 400, "glob", {"value": "a*"}),
    ]


def run_mode(client, ca_file, issuer_ca, issuer, private, jwk, side, mode, restart, rows):
    t = Trace(client, rows, mode)
    base = "auth/jwt-claims-" + mode
    t.call("mount", "sys/" + base, {"type": "jwt"}, expected=204)
    t.call("config", base + "/config", configuration(side, mode, issuer, private, jwk, issuer_ca), expected=204)
    role_path = base + "/role/test"
    for name, kind, bound, claims, raw in matrix():
        payload = claims_role(bound_claims_type=kind, bound_claims=bound)
        written = raw_role(client, ca_file, role_path, payload, raw) if raw is not None else client.request("POST", "/v1/" + role_path, payload).status
        expected_role = 400 if name in ROLE_REJECTED else 204
        t.check("matrix." + name + ".role", written == expected_role, status=written)
        if expected_role == 400:
            continue
        signed = signed_assertion(private, jwk, issuer.origin, case=name, **claims)
        expected_login = 200 if name in ACCEPTED else 400
        response = t.call("matrix." + name + ".login", base + "/login", {"role": "test", "jwt": signed},
                          bearer="", expected=expected_login)
        auth = response.get("auth")
        t.check("matrix." + name + ".publication", bool(auth and auth.get("client_token")) == (expected_login == 200)
                and not response.get("wrap_info"))
    t.check("matrix.complete", True)
    for label, payload, status, kind, bounds in partial_steps():
        t.call("partial." + label, role_path, payload, expected=status)
        data = t.call("partial." + label + ".read", role_path, method="GET").get("data", {})
        t.check("partial." + label + ".shape", data.get("bound_claims_type") == kind
                and (data.get("bound_claims") or {}) == bounds and data.get("role_type") == "jwt")
    t.check("partial.complete", True)
    t.call("signature.role", role_path, claims_role(bound_claims_type="string", bound_claims={"value": "alpha"}), expected=204)
    other, _ = signing_key("ES256", "untrusted-signature")
    signed = signed_assertion(other, jwk, issuer.origin, case="forged", value="alpha")
    rejected = t.call("signature.invalid", base + "/login", {"role": "test", "jwt": signed}, bearer="", expected=400)
    t.check("signature.no_authority", not rejected.get("auth") and not rejected.get("wrap_info"))
    signed = signed_assertion(private, jwk, issuer.origin, case="issued", value="alpha")
    auth = t.call("issued.login", base + "/login", {"role": "test", "jwt": signed}, bearer="").get("auth", {})
    bearer = auth.get("client_token")
    t.check("issued.token", isinstance(bearer, str) and bool(bearer))
    t.call("issued.change_bound", role_path, {"role_type": "jwt", "bound_claims": {"value": "beta"}}, expected=204)
    rejected = t.call("wrap.rejected", base + "/login", {"role": "test", "jwt": signed},
                      bearer="", expected=400, wrap_ttl="60s")
    t.check("wrap.no_authority", not rejected.get("auth") and not rejected.get("wrap_info"))
    issuer.mode = "unavailable"
    before = len(issuer.calls)
    renewed = t.call("issued.renew_ignores_changed_claims", "auth/token/renew-self", {}, bearer=bearer).get("auth", {})
    t.check("issued.renew_preserves_token", renewed.get("client_token") == bearer and renewed.get("renewable") is True)
    t.check("issued.renew_no_provider", len(issuer.calls) == before)
    issuer.mode = "normal"
    restart()
    t.check("restart", True)
    data = t.call("restart.role", role_path, method="GET").get("data", {})
    t.check("restart.bound_preserved", data.get("bound_claims_type") == "string" and data.get("bound_claims") == {"value": "beta"})
    t.call("restart.old_token", "auth/token/lookup-self", method="GET", bearer=bearer)
    rejected = t.call("restart.old_claims_denied", base + "/login", {"role": "test", "jwt": signed}, bearer="", expected=400)
    t.check("restart.no_authority", not rejected.get("auth") and not rejected.get("wrap_info"))
    new_signed = signed_assertion(private, jwk, issuer.origin, case="new-bound", value="beta")
    new_auth = t.call("restart.new_claims_login", base + "/login", {"role": "test", "jwt": new_signed}, bearer="").get("auth", {})
    t.check("restart.new_token", bool(new_auth.get("client_token")) and new_auth["client_token"] != bearer)
    t.check("complete", True)


def candidate_gate(client, issuer, safety, observations):
    t = Trace(client, safety, "candidate_gate")
    private, jwk = signing_key("ES256", "gated-bound-claims")
    issuer.documents["/keys"] = {"keys": [jwk]}
    base = "auth/jwt-claims-remote"
    t.call("role", base + "/role/test", claims_role(bound_claims_type="string", bound_claims={"value": "alpha"}), expected=204)
    signed = signed_assertion(private, jwk, issuer.origin, case="gated", value="alpha")
    def counters():
        data = t.client.request("GET", "/v1/sys/internal/capacity").body.get("data", {})
        if any(type(data.get(k)) is not int for k in COUNTERS):
            raise Failure("capacity_unavailable")
        return {k: data[k] for k in COUNTERS}
    def concurrent():
        response = client.request("POST", "/v1/" + base + "/role/test", {"role_type": "jwt", "bound_claims": {"value": "beta"}})
        if response.status != 204:
            raise Failure("bound_role_update_failed")
        return counters()
    response, after_change = gate(issuer, "bound_role_changed",
        lambda: client.request("POST", "/v1/" + base + "/login", {"role": "test", "jwt": signed}, token="", wrap_ttl="60s"),
        concurrent, observations)
    t.check("late_result_denied", response.status == 409, status=response.status)
    t.check("no_token_or_wrapper", not response.body.get("auth") and not response.body.get("wrap_info"))
    t.check("no_key_token_wrapper_publication", counters() == after_change)
    current = t.call("latest_role", base + "/role/test", method="GET").get("data", {})
    t.check("new_bound_preserved", current.get("bound_claims") == {"value": "beta"})
    signed = signed_assertion(private, jwk, issuer.origin, case="gated-new", value="beta")
    auth = t.call("new_bound_login", base + "/login", {"role": "test", "jwt": signed}, bearer="").get("auth", {})
    t.check("new_token", bool(auth.get("client_token")))
    before = counters()
    bad = signed_assertion(private, jwk, issuer.origin, case="wrapped-rejected", value="alpha")
    rejected = t.call("wrapped_bad_claim", base + "/login", {"role": "test", "jwt": bad}, bearer="", wrap_ttl="60s", expected=400)
    t.check("wrapped_no_authority", not rejected.get("auth") and not rejected.get("wrap_info"))
    t.check("wrapped_rejection_no_publication", counters() == before)
    t.check("complete", True)


def valid_rows(rows, required):
    if not isinstance(rows, list) or not rows:
        return False
    names = []
    for row in rows:
        if (not isinstance(row, dict) or row.get("passed") is not True
                or not isinstance(row.get("case"), str) or re.fullmatch(r"bound_claims\.[a-z0-9_.]{1,180}", row["case"]) is None
                or any(type(value) not in (bool, int) for key, value in row.items() if key not in ("case", "passed"))):
            return False
        names.append(row["case"])
    return len(names) == len(set(names)) and required.issubset(names)


def required_comparison():
    names = set()
    for mode in MODES:
        prefix = "bound_claims." + mode + "."
        for name, *_ in matrix():
            names.add(prefix + "matrix." + name + ".role")
            if name not in ROLE_REJECTED:
                names |= {prefix + "matrix." + name + suffix for suffix in (".login", ".publication")}
        names |= {prefix + "partial." + step[0] + ".shape" for step in partial_steps()}
        names |= {prefix + name for name in ("partial.complete", "signature.invalid", "wrap.no_authority",
                  "issued.renew_no_provider", "restart.bound_preserved", "restart.new_token", "complete")}
    return names


def valid_gate(rows):
    fields = {"phase", "events", "held_before_release", "concurrent_completed_before_release",
              "request_pending_before_release", "within_gate_budget"}
    return (isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
            and set(rows[0]) == fields and rows[0].get("phase") == "bound_role_changed"
            and rows[0].get("events") == EVENTS
            and all(rows[0].get(k) is True for k in fields - {"phase", "events"}))


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--build-source-commit")
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.oracle_only and (args.binary is None or re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit or "") is None):
        parser.error("candidate binary and full build source commit required")
    output = args.output.absolute()
    admitted = admit_output(output)
    binary = args.binary.resolve(strict=True) if args.binary else None
    before = source_identity(ROOT, binary) if not args.oracle_only else None
    runner_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    root = Path(tempfile.mkdtemp(prefix="heptabao-jwt-bound-claims-")); root.chmod(0o700)
    oracle = instance = issuer = None
    cases, failures, safety, observations = {}, {}, [], []
    unenrolled = False
    try:
        oracle = start_oracle(free_port())
        ca_root = Path(oracle["root"])
        issuer = bounded_issuer(ca_root / "tls.crt", ca_root / "tls.key")
        reference = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"]).decode().strip())
        def restart_reference():
            stop_oracle(oracle); restart_oracle(oracle)
        targets = [("oracle", reference, oracle["ca_file"], restart_reference)]
        if not args.oracle_only:
            instance = Instance(binary, root / "candidate")
            cfg_path = instance.root / "server.json"
            cfg = json.loads(cfg_path.read_text()); cfg.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
            cfg_path.write_text(json.dumps(cfg)); cfg_path.chmod(0o600)
            unenrolled = json.loads(cfg_path.read_text())["outbound_endpoints"] == []
            instance.start()
            status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
            if status != 200:
                raise Failure("candidate_init_failed")
            instance.token, key = init["root_token"], init["keys_base64"][0]
            if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                raise Failure("candidate_unseal_failed")
            def restart_candidate():
                instance.stop()
                if json.loads(cfg_path.read_text())["outbound_endpoints"] != []:
                    raise Failure("candidate_enrollment_changed")
                instance.start()
                if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                    raise Failure("candidate_restart_failed")
            targets.append(("candidate", Client(instance.address, str(instance.root / "ca.crt"), instance.token), str(instance.root / "ca.crt"), restart_candidate))
        for side, client, ca_file, restart in targets:
            cases[side] = []
            try:
                for mode in MODES:
                    private, jwk = signing_key("ES256", "synthetic-bound-claims-" + mode)
                    issuer.documents["/keys"] = {"keys": [jwk]}; issuer.mode = "normal"
                    run_mode(client, ca_file, Path(oracle["ca_file"]).read_text(), issuer, private, jwk, side, mode, restart, cases[side])
                if side == "candidate":
                    candidate_gate(client, issuer, safety, observations)
            except Exception as error:
                failures[side] = str(error) if isinstance(error, Failure) else "fixture_" + type(error).__name__
    except Exception as error:
        failures["setup"] = str(error) if isinstance(error, Failure) else "fixture_" + type(error).__name__
    finally:
        if issuer is not None:
            issuer.release_block()
        if instance is not None:
            instance.stop()
        if issuer is not None:
            issuer.close()
        if oracle is not None:
            stop_oracle(oracle); shutil.rmtree(oracle["root"])
        shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary) if before else None
    runner_unchanged = runner_hash == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    equal = cases.get("candidate") == cases.get("oracle") if not args.oracle_only else None
    gate_complete = valid_rows(safety, {"bound_claims.candidate_gate." + name for name in
        ("late_result_denied", "no_key_token_wrapper_publication", "new_bound_preserved", "wrapped_rejection_no_publication", "complete")}) and valid_gate(observations)
    passed = (not failures and set(cases) == ({"oracle"} if args.oracle_only else {"oracle", "candidate"})
              and all(valid_rows(rows, required_comparison()) for rows in cases.values()) and runner_unchanged
              and (args.oracle_only or (unchanged and unenrolled and equal and gate_complete)))
    report = {"schema": "heptabao.jwt-bound-claims-comparison.v1", "status": "passed" if passed else "failed",
              "candidate_source": before, "build_source_commit": args.build_source_commit,
              "source_and_binary_unchanged": unchanged, "runner_sha256": runner_hash, "runner_unchanged": runner_unchanged,
              "oracle_binary_sha256": BINARY_SHA256, "oracle_only": args.oracle_only, "target_version": "2.6.2",
              "candidate_startup_enrollment_empty": unenrolled, "cases": cases, "cases_match": equal, "failures": failures,
              "candidate_publication_checks": safety, "candidate_gate_observations": observations,
              "configuration_adaptation": ADAPTATION, "synthetic_only": True, "oidc_covered": False,
              "full_openbao_compatibility": False, "independent_qualification": False, "production_authority": False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "cases": {side: len(rows) for side, rows in cases.items()}, "failures": failures}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
