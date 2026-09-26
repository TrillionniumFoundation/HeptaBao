#!/usr/bin/env python3
"""Pinned-official differential, selected opaque response-wrapping behavior.

Fresh synthetic TLS instances only. No remote endpoint or real credential input.
These observations do not certify JWT wrapping, all policy constraints, HA,
independent qualification, or complete OpenBao replacement.
"""
from __future__ import annotations
import json
from pathlib import Path
from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results
    def call(path, body=None, *, token=None, ttl=None, method="POST"):
        return client.request(method, "/v1/" + path, body, token=token, wrap_ttl=ttl)
    def check(name, response, expected=200):
        results.append({"case": name, "status": response.status, "passed": response.status == expected})
        if response.status != expected:
            raise ScenarioFailure(name)
        return response.body
    def truth(name, condition):
        results.append({"case": name, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(name)
    def wrap(name, payload, *, token=None, ttl="60s"):
        result = check(name, call("sys/wrapping/wrap", payload, token=token, ttl=ttl))
        truth(name + ".redacted", result.get("data") is None and result.get("auth") is None)
        return result["wrap_info"]

    payload = {"value": "synthetic-wrapped-secret", "entity_id": "arbitrary-user-data", "nested": {"count": 3}}
    info = wrap("wrap.create", payload)
    token = info["token"]
    truth("wrap.metadata", info.get("ttl") == 60 and info.get("creation_path") == "sys/wrapping/wrap"
          and isinstance(info.get("creation_time"), str) and bool(info["creation_time"])
          and isinstance(info.get("accessor"), str) and bool(info["accessor"]))
    meta = check("wrap.lookup_body_no_auth", call("sys/wrapping/lookup", {"token": token}, token=""))
    truth("wrap.lookup_metadata_only", set(meta["data"]) == {"creation_path", "creation_ttl", "creation_time"}
          and meta["data"]["creation_ttl"] == 60 and "synthetic-wrapped-secret" not in json.dumps(meta))
    check("wrap.lookup_header_get", call("sys/wrapping/lookup", token=token, method="GET"))
    check("wrap.lookup_header_post_repeat", call("sys/wrapping/lookup", token=token))
    unwrapped = check("wrap.unwrap_self", call("sys/wrapping/unwrap", token=token))
    truth("wrap.exact_payload", unwrapped.get("data") == payload)
    check("wrap.self_replay_denied", call("sys/wrapping/unwrap", token=token), 400)
    check("wrap.lookup_consumed", call("sys/wrapping/lookup", {"token": token}), 400)
    check("wrap.missing_header", call("sys/wrapping/wrap", payload), 400)
    check("wrap.invalid_target", call("sys/wrapping/unwrap", {"token": "synthetic-not-a-token"}), 400)
    check("wrap.normal_token_not_wrapper", call("sys/wrapping/unwrap", {"token": client._token}), 400)
    check("wrap.normal_token_still_valid", call("auth/token/lookup-self", method="GET"))

    user = check("wrap.create_default_user", call("auth/token/create", {"policies": ["default"], "ttl": "1h"}))["auth"]["client_token"]
    info = wrap("wrap.default_policy", {"value": "only-synthetic"}, token=user, ttl="120")
    old = info["token"]
    check("wrap.default_policy_cannot_rewrap", call("sys/wrapping/rewrap", {"token": old}, token=user), 403)
    check("wrap.denied_rewrap_does_not_consume", call("sys/wrapping/lookup", {"token": old}))
    new = check("wrap.rewrap", call("sys/wrapping/rewrap", {"token": old}))["wrap_info"]
    truth("wrap.rewrap_preserves_ttl_and_origin", new["ttl"] == 120 and new["creation_path"] == info["creation_path"] and new["token"] != old)
    check("wrap.old_invalid_after_rotation", call("sys/wrapping/lookup", {"token": old}), 400)
    unwrapped = check("wrap.unwrap_body", call("sys/wrapping/unwrap", {"token": new["token"]}, token=user))
    truth("wrap.rewrapped_payload", unwrapped.get("data") == {"value": "only-synthetic"})
    check("wrap.body_replay_denied", call("sys/wrapping/unwrap", {"token": new["token"]}, token=user), 400)
    info = wrap("wrap.revoke_create", {"value": "revoked"})
    check("wrap.revoke_accessor", call("auth/token/revoke-accessor", {"accessor": info["accessor"]}), 204)
    check("wrap.revoked_lookup", call("sys/wrapping/lookup", {"token": info["token"]}), 400)

    # Wrapping a credential never exposes it before unwrap; accessor reports the
    # issued token, not the enclosing one-time delivery capability.
    issued = check("wrap.auth_response", call("auth/token/create", {"policies": ["default"], "ttl": "10m"}, ttl="60s"))
    truth("wrap.auth_hidden", issued.get("auth") is None and issued.get("data") is None)
    info = issued["wrap_info"]
    truth("wrap.distinct_accessors", bool(info.get("wrapped_accessor")) and info["wrapped_accessor"] != info["accessor"])
    auth = check("wrap.unwrap_auth", call("sys/wrapping/unwrap", token=info["token"]))["auth"]
    truth("wrap.auth_accessor_matches", auth["accessor"] == info["wrapped_accessor"])
    check("wrap.issued_token_works", call("auth/token/lookup-self", token=auth["client_token"], method="GET"))
    mount = "wrapping-differential"
    check("wrap.mount", call("sys/mounts/" + mount, {"type": "kv", "options": {"version": "2"}}), 204)
    path = mount + "/data/item"
    check("wrap.seed", call(path, {"data": {"value": "synthetic-kv"}}))
    captured = check("wrap.kv_read", call(path, method="GET", ttl="1m"))
    truth("wrap.kv_not_released", captured.get("data") is None and "synthetic-kv" not in json.dumps(captured))
    info = captured["wrap_info"]
    truth("wrap.kv_creation_path", info["creation_path"] == path)
    value = check("wrap.unwrap_kv", call("sys/wrapping/unwrap", token=info["token"]))
    truth("wrap.kv_payload", value["data"]["data"] == {"value": "synthetic-kv"} and value["data"]["metadata"]["version"] == 1)
    denied = check("wrap.errors_are_not_wrapped", call(path, method="GET", token=user, ttl="60s"), 403)
    truth("wrap.error_has_no_wrapper", not denied.get("wrap_info"))
    # A wrapping token has no authority to rewrap itself or read general secrets.
    info = wrap("wrap.scope_create", {"value": "unavailable"})
    check("wrap.scope_no_rewrap_self", call("sys/wrapping/rewrap", token=info["token"]), 403)
    check("wrap.scope_consumed_on_attempt", call("sys/wrapping/lookup", {"token": info["token"]}), 400)
    return results


def main() -> int:
    return core_isolation.main(scenario_runner=run_scenarios, profile="response-wrapping",
        scope="selected_opaque_wrapping_lookup_unwrap_rewrap_and_response_capture", runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
