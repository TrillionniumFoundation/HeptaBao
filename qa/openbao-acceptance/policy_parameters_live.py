#!/usr/bin/env python3
"""Compare bounded OpenBao 2.6.2 ACL request-parameter constraints.

This profile uses new isolated TLS services and synthetic KV v1 data only. It
covers public HTTP decoding, not internal Go value types, and grants no whole-
policy, namespace, compatibility, production or independent authority.
"""
from __future__ import annotations
from pathlib import Path

from bao_http import Client
from core_isolation import ScenarioFailure, main


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results

    def call(method: str, path: str, body=None, token=None):
        return client.request(method, "/v1/" + path, body, token=token)

    def check(name: str, response, status: int, expected_data=None):
        row = {"case": name, "status": response.status, "passed": response.status == status}
        if expected_data is not None:
            row["data_matches"] = response.body.get("data") == expected_data
            row["passed"] &= row["data_matches"]
        results.append(row)
        if not row["passed"]:
            raise ScenarioFailure(name)
        return response.body

    check(
        "acl_parameters.mount",
        call("POST", "sys/mounts/acl-param", {"type": "kv", "options": {"version": "1"}}),
        204,
    )
    policy = r'''path "acl-param/item" {
  capabilities = ["create", "read", "update", "delete"]
  required_parameters = ["foo"]
  allowed_parameters = {
    "foo" = ["good*"]
    "bar" = [1, 2]
    "flag" = [false]
    "map" = [{"good" = "one"}]
  }
  denied_parameters = {
    "blocked" = []
  }
}
path "acl-param/*" {
  capabilities = ["list", "scan"]
  required_parameters = ["never"]
  denied_parameters = { "*" = [] }
}'''
    check(
        "acl_parameters.policy_accepted",
        call("PUT", "sys/policies/acl/parameter-guard", {"policy": policy}),
        204,
    )
    issued = check(
        "acl_parameters.issuer",
        call(
            "POST",
            "auth/token/create",
            {"policies": ["parameter-guard"], "no_default_policy": True, "ttl": "1h"},
        ),
        200,
    )
    token = issued["auth"]["client_token"]
    check(
        "acl_parameters.allowed_string_glob",
        call("POST", "acl-param/item", {"foo": "good-value"}, token),
        204,
    )
    check(
        "acl_parameters.read_required_missing",
        call("GET", "acl-param/item", token=token),
        403,
    )
    check(
        "acl_parameters.list_skips_generic_constraints",
        call("LIST", "acl-param/", token=token),
        200,
        {"keys": ["item"]},
    )
    check(
        "acl_parameters.scan_skips_generic_constraints",
        call("SCAN", "acl-param/", token=token),
        200,
        {"keys": ["item"]},
    )
    for name, body in [
        ("required_missing", {"bar": 1}),
        ("allowed_value_mismatch", {"foo": "wrong"}),
        ("unknown_parameter", {"foo": "good-value", "unknown": 1}),
        ("denied_empty_list", {"foo": "good-value", "blocked": "anything"}),
        # OpenBao's public HTTP decoder and HCL decoder use different numeric
        # dynamic types, so even a listed number is not DeepEqual here.
        ("numeric_http_type_mismatch", {"foo": "good-value", "bar": 1}),
        ("boolean_mismatch", {"foo": "good-value", "flag": True}),
        ("map_mismatch", {"foo": "good-value", "map": {"bad": "one"}}),
    ]:
        check("acl_parameters." + name, call("POST", "acl-param/item", body, token), 403)
    check(
        "acl_parameters.denials_no_effect",
        call("GET", "acl-param/item"),
        200,
        {"foo": "good-value"},
    )
    check(
        "acl_parameters.delete_skips_generic_constraints",
        call("DELETE", "acl-param/item", token=token),
        204,
    )
    check("acl_parameters.delete_effect_observed", call("GET", "acl-param/item"), 404)
    check(
        "acl_parameters.recreated_after_delete",
        call("POST", "acl-param/item", {"foo": "good-recreated"}, token),
        204,
    )
    list_only_policy = 'path "acl-param/*" { capabilities = ["list"] }'
    check(
        "acl_parameters.list_only_policy_accepted",
        call("POST", "sys/policies/acl/acl-list-only", {"policy": list_only_policy}),
        204,
    )
    issued = check(
        "acl_parameters.list_only_issuer",
        call(
            "POST", "auth/token/create",
            {"policies": ["acl-list-only"], "no_default_policy": True, "ttl": "10m"},
        ),
        200,
    )
    list_only = issued["auth"]["client_token"]
    check(
        "acl_parameters.list_only_lists",
        call("LIST", "acl-param/", token=list_only),
        200,
        {"keys": ["item"]},
    )
    check(
        "acl_parameters.list_only_scan_denied",
        call("SCAN", "acl-param/", token=list_only),
        403,
    )
    final = {"foo": "good-map", "flag": False, "map": {"good": "one"}}
    check("acl_parameters.allowed_bool_and_map", call("POST", "acl-param/item", final, token), 204)
    check("acl_parameters.final_readback", call("GET", "acl-param/item"), 200, final)
    results.append({"case": "acl_parameters.complete", "passed": True})
    return results


if __name__ == "__main__":
    raise SystemExit(
        main(
            scenario_runner=run_scenarios,
            profile="policy-parameters-live",
            scope="bounded OpenBao 2.6.2 ACL request-parameter constraints over KV v1",
            runner_path=Path(__file__),
        )
    )
