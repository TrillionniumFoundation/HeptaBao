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
    for name, omit in [("complete", ()), ("no_jti", ("jti",)), ("no_iat", ("iat",)),
                       ("no_jti_or_iat", ("jti", "iat"))]:
        assertion = signed_assertion(private, jwk, issuer.origin, omit=omit, case=mode + "-" + name)
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


def main():
    return jwt_renewal_live.main(scenario_runner=run_scenarios, profile="jwt-login-claims", runner_path=Path(__file__),
        scope="ordinary JWT login only: optional iat/jti, repeated assertions, time validation; OIDC authorization code, state and nonce are excluded")


if __name__ == "__main__":
    raise SystemExit(main())
