#!/usr/bin/env python3
"""Compare ordinary JWT optional claims and repeated login, never OIDC codes."""
from __future__ import annotations

import json
from pathlib import Path
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from external_tls_fixtures import b64
from core_isolation import ScenarioFailure
import jwt_renewal_live


def signed_assertion(private, jwk, issuer, *, omit=(), case="synthetic", **overrides):
    now = int(time.time())
    claims = {"iss": issuer, "aud": "heptabao-test", "sub": "synthetic-subject",
              "iat": now, "exp": now + 120, "jti": "synthetic-" + case}
    claims.update(overrides)
    for name in omit:
        claims.pop(name, None)
    payload = (b64(json.dumps({"alg": "ES256", "kid": jwk["kid"]}).encode())
               + "." + b64(json.dumps(claims).encode())).encode()
    r, s = decode_dss_signature(private.sign(payload, ec.ECDSA(hashes.SHA256())))
    return payload.decode() + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def service_token_shape(auth):
    return (isinstance(auth, dict) and all(isinstance(auth.get(field), str) and auth[field]
            for field in ("client_token", "accessor", "entity_id"))
            and auth.get("lease_duration") == 60 and auth.get("renewable") is True)


def distinct_service_tokens(first, second):
    return (service_token_shape(first) and service_token_shape(second)
            and first["client_token"] != second["client_token"]
            and first["accessor"] != second["accessor"]
            and first["entity_id"] == second["entity_id"])


class Trace(jwt_renewal_live.Trace):
    def check(self, name, condition, **observed):
        case = "jwt_login_claims." + self.mode + "." + name
        self.results.append({"case": case, **observed, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(case)


def native_time_matrix(now):
    """Integer offsets avoid the live clock-skew boundary; no credentials here."""
    zero = {"clock_skew_leeway": 0, "expiration_leeway": 0, "not_before_leeway": 0}
    no_clock = dict(zero, clock_skew_leeway=-1)
    rows = []

    def add(name, *, claims=None, omit=(), leeway=None, status=200):
        rows.append((name, dict(zero if leeway is None else leeway), omit, claims or {}, status))

    add("exp_only", omit=("iat", "nbf", "jti"))
    add("exp_only_far_future_synthesized_nbf", omit=("iat", "nbf"), claims={"exp": now + 300}, status=400)
    add("iat_only", omit=("exp", "nbf"))
    add("iat_only_past_with_synthesized_expiry", omit=("exp", "nbf"), claims={"iat": now - 200})
    add("iat_only_expired", omit=("exp", "nbf"), claims={"iat": now - 240}, status=400)
    add("nbf_only", omit=("exp", "iat"), claims={"nbf": now})
    add("iat_and_nbf_without_exp", omit=("exp",), claims={"iat": now - 30, "nbf": now})
    add("all_times_zero", claims={"iat": 0, "nbf": 0, "exp": 0}, status=400)
    add("all_times_null", claims={"iat": None, "nbf": None, "exp": None}, status=400)
    add("zero_exp_is_synthesized", claims={"exp": 0})
    add("zero_iat_is_missing", claims={"iat": 0})
    add("zero_nbf_is_synthesized", claims={"nbf": 0})
    add("no_implicit_hour_lifetime_cap", claims={"exp": now + 7200})
    add("fractional_numeric_dates", claims={"iat": now - 1.5, "nbf": now - 1.25, "exp": now + 120.75})
    add("negative_iat", claims={"iat": -1})
    add("negative_nbf", claims={"nbf": -1})
    add("negative_exp", claims={"exp": -1}, status=400)
    add("negative_fraction_iat", claims={"iat": -0.5})
    add("fraction_truncated_to_missing", omit=("exp", "nbf"), claims={"iat": 0.75}, status=400)
    add("nonnumeric_date", claims={"iat": "not-a-date"}, status=400)
    add("boolean_date", claims={"iat": True}, status=400)
    add("zero_clock_defaults_accept_future_iat", claims={"iat": now + 30, "exp": now + 180})
    add("zero_clock_defaults_deny_far_future_iat", claims={"iat": now + 120, "exp": now + 300}, status=400)
    add("zero_clock_defaults_accept_future_nbf", claims={"nbf": now + 30, "exp": now + 180})
    add("zero_clock_defaults_deny_far_future_nbf", claims={"nbf": now + 120, "exp": now + 300}, status=400)
    add("zero_clock_defaults_accept_recent_expiry", claims={"iat": now - 90, "exp": now - 30})
    add("zero_clock_defaults_deny_old_expiry", claims={"iat": now - 180, "exp": now - 120}, status=400)
    add("negative_clock_disables_iat_grace", claims={"iat": now + 10}, leeway=no_clock, status=400)
    add("negative_clock_disables_nbf_grace", claims={"nbf": now + 10}, leeway=no_clock, status=400)
    add("negative_clock_disables_exp_grace", claims={"iat": now - 90, "exp": now - 10}, leeway=no_clock, status=400)
    positive_clock = dict(zero, clock_skew_leeway=120)
    add("positive_clock_accepts_future_iat", claims={"iat": now + 90, "exp": now + 300}, leeway=positive_clock)
    add("positive_clock_accepts_future_nbf", claims={"nbf": now + 90, "exp": now + 300}, leeway=positive_clock)
    add("positive_clock_accepts_recent_expiry", claims={"iat": now - 240, "exp": now - 90}, leeway=positive_clock)
    add("default_expiry_synthesis", omit=("exp", "nbf"), claims={"iat": now - 90}, leeway=no_clock)
    add("disabled_expiry_synthesis", omit=("exp", "nbf"), claims={"iat": now - 10},
        leeway=dict(no_clock, expiration_leeway=-1), status=400)
    add("positive_expiry_synthesis", omit=("exp", "nbf"), claims={"iat": now - 200},
        leeway=dict(no_clock, expiration_leeway=300))
    add("expiry_leeway_does_not_relax_present_exp", claims={"iat": now - 90, "exp": now - 10},
        leeway=dict(no_clock, expiration_leeway=300), status=400)
    add("default_nbf_synthesis", omit=("iat", "nbf"), leeway=no_clock)
    add("disabled_nbf_synthesis", omit=("iat", "nbf"), leeway=dict(no_clock, not_before_leeway=-1), status=400)
    add("positive_nbf_synthesis", omit=("iat", "nbf"), claims={"exp": now + 300},
        leeway=dict(no_clock, not_before_leeway=400))
    add("nbf_leeway_does_not_relax_present_nbf", claims={"nbf": now + 10},
        leeway=dict(no_clock, not_before_leeway=400), status=400)
    return rows


def run_scenarios(client, issuer, private, jwk, config, restart, mode, results):
    t = Trace(client, issuer, mode, results)
    mount = "jwt-claims-" + mode
    login = "auth/" + mount + "/login"
    issuer.mode = "normal"
    t.call("mount", "sys/auth/" + mount, {"type": "jwt"}, expected=204)
    t.call("config", "auth/" + mount + "/config", config, expected=204)
    t.call("role", "auth/" + mount + "/role/test",
           jwt_renewal_live.role(token_policies=["default"]), expected=204)
    remembered = []
    for name, omit, overrides in [("complete", (), {}), ("no_jti", ("jti",), {}), ("no_iat", ("iat",), {}),
                                  ("no_jti_or_iat", ("jti", "iat"), {}), ("empty_jti", (), {"jti": ""})]:
        assertion = signed_assertion(private, jwk, issuer.origin, omit=omit, case=mode + "-" + name, **overrides)
        auth = []
        for attempt in (1, 2):
            body = t.call(name + ".login_" + str(attempt), login, {"role": "test", "jwt": assertion})
            current = body.get("auth")
            t.check(name + ".shape_" + str(attempt), service_token_shape(current))
            auth.append(current)
        t.check(name + ".distinct_tokens_same_entity", distinct_service_tokens(*auth))
        remembered.append((name, assertion, auth[-1]))
    t.check("key_profile", bool(issuer.calls) if mode == "remote" else not issuer.calls)
    restart()
    t.check("restart.same_store", True)
    for name, assertion, previous in remembered:
        body = t.call("restart." + name, login, {"role": "test", "jwt": assertion})
        t.check("restart." + name + ".distinct_token_same_entity", distinct_service_tokens(previous, body.get("auth")))

    # Default validator clock skew can accept recently expired assertions. This
    # timestamp is deliberately far outside the official default grace window.
    now = int(time.time())
    for name, assertion in [
        ("expired", signed_assertion(private, jwk, issuer.origin, case=mode + "-expired", iat=now - 600, exp=now - 300)),
        ("no_time_claims", signed_assertion(private, jwk, issuer.origin, omit=("iat", "nbf", "exp"), case=mode + "-no-time")),
    ]:
        body = t.call(name + ".denied", login, {"role": "test", "jwt": assertion}, expected=400)
        t.check(name + ".no_service_token", body.get("auth") is None and not body.get("wrap_info"))

    for index, (name, leeway, _, _, _) in enumerate(native_time_matrix(0)):
        t.call("time." + name + ".role", "auth/" + mount + "/role/test",
               jwt_renewal_live.role(token_policies=["default"], **leeway), expected=204)
        # Rebase time offsets after the role write, so earlier matrix cases
        # cannot consume this case's clock-skew margin on a slower machine.
        _, _, omit, claims, expected = native_time_matrix(int(time.time()))[index]
        assertion = signed_assertion(private, jwk, issuer.origin, omit=omit, case=mode + "-" + name, **claims)
        body = t.call("time." + name + ".login", login, {"role": "test", "jwt": assertion}, expected=expected)
        if expected == 200:
            t.check("time." + name + ".service_token_shape", service_token_shape(body.get("auth")))
        else:
            t.check("time." + name + ".no_service_token", body.get("auth") is None and not body.get("wrap_info"))


def main():
    return jwt_renewal_live.main(scenario_runner=run_scenarios, profile="jwt-login-claims", runner_path=Path(__file__),
        scope="ordinary native JWT login only: optional/synthesized time claims, NumericDate values, role leeway, optional/empty jti and repeated assertions; OIDC authorization code, state and nonce are excluded")


if __name__ == "__main__":
    raise SystemExit(main())
