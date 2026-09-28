#!/usr/bin/env python3
"""Pinned OpenBao 2.6.2 ACL wrapping TTL differential on private synthetic services."""
from __future__ import annotations
import json
from pathlib import Path
from core_isolation import ScenarioFailure, main


def expected_boundary_status(name, ttl):
    minimum, maximum = {"min": (10, 0), "max": (0, 30), "range": (10, 30), "zero": (0, 0)}[name]
    if minimum == 0 and maximum == 0:
        return 200
    if ttl is None:
        return 403
    seconds = int(ttl)
    return 200 if seconds >= minimum and (maximum == 0 or seconds <= maximum) else 403


def run_scenarios(client, results=None):
    results = [] if results is None else results
    def call(method, path, body=None, token=None, ttl=None):
        return client.request(method, "/v1/" + path, body, token=token, wrap_ttl=ttl)
    def check(name, response, expected=200):
        results.append({"case": "acl_wrap." + name, "status": response.status,
                        "passed": response.status == expected})
        if response.status != expected:
            raise ScenarioFailure("acl_wrap." + name)
        return response.body
    def truth(name, condition):
        results.append({"case": "acl_wrap." + name, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure("acl_wrap." + name)
    def policy(name, bounds, path="wrap-policy/data/item", caps=None):
        caps = ["read", "create", "update"] if caps is None else caps
        text = "path " + json.dumps(path) + " { capabilities = " + json.dumps(caps)
        text += " ".join(" " + key + " = " + json.dumps(value) for key, value in bounds.items()) + " }"
        check("policy_" + name, call("PUT", "sys/policies/acl/" + name, {"policy": text}), 204)
    def issue(name, policies):
        value = check("issuer_" + name, call("POST", "auth/token/create", {
            "policies": policies, "no_default_policy": True, "ttl": "10m"}))
        return value["auth"]["client_token"]
    def read(name, token, ttl, expected, body=None, path="wrap-policy/data/item"):
        response = check(name, call("GET", path, body, token, ttl), expected)
        if expected != 200:
            truth(name + "_no_delivery", response.get("wrap_info") is None and response.get("data") is None)
        elif ttl not in (None, "0"):
            info = response.get("wrap_info", {})
            truth(name + "_wrapped", response.get("data") is None and info.get("ttl") == int(ttl))
            unwrapped = check(name + "_unwrap", call("POST", "sys/wrapping/unwrap", token=info["token"]))
            truth(name + "_payload", unwrapped.get("data", {}).get("data") == {"value": "unchanged"})
        else:
            truth(name + "_plain", response.get("data", {}).get("data") == {"value": "unchanged"})

    check("mount", call("POST", "sys/mounts/wrap-policy", {"type": "kv", "options": {"version": "2"}}), 204)
    check("seed", call("POST", "wrap-policy/data/item", {"data": {"value": "unchanged"}}))
    for name, bounds in [
        ("min", {"min_wrapping_ttl": "10s"}),
        ("max", {"max_wrapping_ttl": "30s"}),
        ("range", {"min_wrapping_ttl": 10, "max_wrapping_ttl": "30s"}),
        ("zero", {"min_wrapping_ttl": 0, "max_wrapping_ttl": "0s"}),
    ]:
        policy(name, bounds)
        token = issue(name, [name])
        for label, ttl in [("absent", None), ("zero", "0"), ("below", "9"),
                           ("lower", "10"), ("inside", "20"), ("upper", "30"), ("above", "31")]:
            read(name + "_" + label, token, ttl, expected_boundary_status(name, ttl))

    policy("merge-wide", {"min_wrapping_ttl": 40, "max_wrapping_ttl": 50})
    merged = issue("merged", ["range", "merge-wide"])
    for label, ttl, status in [("below", "9", 403), ("inside", "20", 200), ("above", "31", 403)]:
        read("merged_" + label, merged, ttl, status)
    policy("merge-min", {"min_wrapping_ttl": 40})
    conflict = issue("conflict", ["merge-min", "max"])
    read("merged_conflict", conflict, "40", 403)
    policy("wildcard", {"min_wrapping_ttl": 60}, "wrap-policy/*")
    specific = issue("specific", ["range", "wildcard"])
    read("winning_specific_path", specific, "20", 200)
    policy("enumeration", {"min_wrapping_ttl": 10}, "wrap-policy/metadata/*", ["list", "scan"])
    listing = issue("enumeration", ["enumeration"])
    for method in ("LIST", "SCAN"):
        check(method.lower() + "_requires_wrapper", call(method, "wrap-policy/metadata/", token=listing), 403)
        wrapped = check(method.lower() + "_wrapped", call(method, "wrap-policy/metadata/", token=listing, ttl="10"))
        payload = check(method.lower() + "_unwrap", call("POST", "sys/wrapping/unwrap", token=wrapped["wrap_info"]["token"]))
        truth(method.lower() + "_keys", payload.get("data", {}).get("keys") == ["item"])
    policy("delete", {"min_wrapping_ttl": 10}, caps=["delete"])
    deletion = issue("delete", ["delete"])
    check("delete_without_wrapping_denied", call("DELETE", "wrap-policy/data/item", token=deletion), 403)
    read("denied_delete_preserved_value", None, None, 200)
    policy("parameters", {"min_wrapping_ttl": 10, "required_parameters": ["version"]})
    constrained = issue("parameters", ["parameters"])
    read("parameters_and_ttl_missing_query", constrained, "10", 403)
    # GET body bytes are bounded and consumed, but are not logical request data
    # in OpenBao. The positive case must use a real query field, not JSON bytes.
    read("parameters_get_body_ignored", constrained, "10", 403, {"version": 1})
    read("parameters_and_ttl_present", constrained, "10", 200,
         path="wrap-policy/data/item?version=1")
    bad = 'path "wrap-policy/data/item" { capabilities = ["read"] min_wrapping_ttl = 40 max_wrapping_ttl = 30 }'
    check("contradictory_policy_denied", call("PUT", "sys/policies/acl/invalid-bounds", {"policy": bad}), 400)
    check("contradictory_policy_absent", call("GET", "sys/policies/acl/invalid-bounds"), 404)
    # A denied write must not change either the data or the KV version.
    writer = issue("writer", ["range"])
    check("unwrapped_write_denied", call("POST", "wrap-policy/data/item", {"data": {"value": "forbidden"}}, writer), 403)
    value = check("denied_write_readback", call("GET", "wrap-policy/data/item"))
    truth("denied_write_no_effect", value["data"]["data"] == {"value": "unchanged"} and value["data"]["metadata"]["version"] == 1)
    # A positive wrapped DELETE can have a native 204 empty acknowledgement;
    # its bounds are still checked before the transaction and effect readback.
    check("delete_zero_denied", call("DELETE", "wrap-policy/data/item", token=deletion, ttl="0"), 403)
    read("delete_zero_no_effect", None, None, 200)
    deleted = check("delete_positive_empty_ack", call("DELETE", "wrap-policy/data/item", token=deletion, ttl="10"), 204)
    truth("delete_positive_no_wrapper", deleted.get("wrap_info") is None and deleted.get("data") is None)
    check("delete_positive_effect", call("GET", "wrap-policy/data/item"), 404)
    policy("default-broad", {"min_wrapping_ttl": 60, "required_parameters": ["never"]}, "*")
    default = check("default_issuer", call("POST", "auth/token/create", {
        "policies": ["default", "default-broad"], "no_default_policy": False, "ttl": "10m"}))
    truth("default_actually_issued", "default" in default["auth"]["policies"])
    check("default_exact_path_wins", call("GET", "auth/token/lookup-self", token=default["auth"]["client_token"]))
    truth("complete", True)
    return results


if __name__ == "__main__":
    raise SystemExit(main(scenario_runner=run_scenarios, profile="policy-wrapping-ttl-live",
        scope="bounded whole-second ACL min/max wrapping TTL, selected path union and effect refusal",
        runner_path=Path(__file__)))
