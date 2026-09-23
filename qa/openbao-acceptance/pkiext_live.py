#!/usr/bin/env python3
"""Compare the bounded OpenBao PKI extension configuration slice.

OpenBao 2.6.2's builtin/logical/pkiext package is test-only. Its executable
extension coverage configures the real PKI engine for ACME, so this profile
only qualifies the persisted cluster/ACME configuration boundary. ACME
account, order, challenge, certificate and revocation protocol routes remain
outside this profile and are intentionally unsupported by HeptaBao.
"""
from pathlib import Path

from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results

    def call(name, method, path, body=None, token=None):
        response = client.request(method, "/v1/" + path, body, token=token)
        results.append({"case": name, "status": response.status})
        return response

    def expect(name, response, status):
        row = results[-1]
        row["passed"] = response.status == status
        if not row["passed"]:
            raise ScenarioFailure(name)
        return response.body

    mount = "pkiext-compare"
    expect("pkiext.mount", call("pkiext.mount", "POST", "sys/mounts/" + mount,
                                 {"type": "pki"}), 204)

    unauthorized = expect(
        "pkiext.unauthorized_denied",
        call("pkiext.unauthorized_denied", "GET", mount + "/config/cluster",
             token="invalid-pkiext-token"),
        403,
    )
    if "private_key" in str(unauthorized) or unauthorized.get("data") is not None:
        raise ScenarioFailure("pkiext.unauthorized_no_secret")

    cluster_path = "https://acme.example.test/v1/" + mount
    cluster = expect(
        "pkiext.cluster_config",
        call("pkiext.cluster_config", "POST", mount + "/config/cluster", {
            "path": cluster_path,
            "aia_path": "http://cdn.example.test/pki",
        }),
        200,
    )
    cluster_data = cluster.get("data", {})
    row = results[-1]
    row["data_matches"] = cluster_data == {
        "path": cluster_path,
        "aia_path": "http://cdn.example.test/pki",
    }
    row["passed"] = row["passed"] and row["data_matches"]
    if not row["passed"]:
        raise ScenarioFailure("pkiext.cluster_config")

    config = expect(
        "pkiext.acme_config",
        call("pkiext.acme_config", "POST", mount + "/config/acme", {
            "enabled": True,
            "eab_policy": "new-account-required",
        }),
        200,
    )
    expected = {
        "allowed_roles": ["*"],
        "allow_role_ext_key_usage": False,
        "allowed_issuers": ["*"],
        "default_directory_policy": "sign-verbatim",
        "enabled": False,
        "dns_resolver": "",
        "eab_policy": "new-account-required",
    }
    row = results[-1]
    row["data_matches"] = config.get("data") == expected
    row["passed"] = row["passed"] and row["data_matches"]
    if not row["passed"]:
        raise ScenarioFailure("pkiext.acme_config")

    readback = expect(
        "pkiext.acme_config_read",
        call("pkiext.acme_config_read", "GET", mount + "/config/acme"),
        200,
    )
    row = results[-1]
    row["data_matches"] = readback.get("data") == expected
    row["passed"] = row["passed"] and row["data_matches"]
    if not row["passed"]:
        raise ScenarioFailure("pkiext.acme_config_read")

    invalid_cluster = expect(
        "pkiext.invalid_cluster_rejected",
        call("pkiext.invalid_cluster_rejected", "POST", mount + "/config/cluster",
             {"path": "not-a-url"}),
        500,
    )
    if invalid_cluster.get("data") is not None:
        raise ScenarioFailure("pkiext.invalid_cluster_no_data")

    expected_after_unknown = dict(expected)
    expected_after_unknown["enabled"] = False
    unknown = expect(
        "pkiext.unknown_field_ignored_with_warning",
        call("pkiext.unknown_field_ignored_with_warning", "POST", mount + "/config/acme",
             {"enabled": False, "private_key": "must-not-be-accepted"}),
        200,
    )
    row = results[-1]
    row["data_matches"] = unknown.get("data") == expected_after_unknown
    row["warning_matches"] = unknown.get("warnings") == [
        "Endpoint ignored these unrecognized parameters: [private_key]"
    ]
    row["passed"] = (
        row["passed"] and row["data_matches"] and row["warning_matches"]
        and "must-not-be-accepted" not in str(unknown)
    )
    if not row["passed"]:
        raise ScenarioFailure("pkiext.unknown_field_ignored_with_warning")

    final = expect(
        "pkiext.known_field_persists_after_unknown",
        call("pkiext.known_field_persists_after_unknown", "GET", mount + "/config/acme"),
        200,
    )
    row = results[-1]
    row["data_matches"] = final.get("data") == expected_after_unknown
    row["passed"] = row["passed"] and row["data_matches"]
    if not row["passed"]:
        raise ScenarioFailure("pkiext.known_field_persists_after_unknown")
    return results


def run_restart_scenarios(client: Client, results: list[dict]) -> None:
    expected_cluster = {
        "path": "https://acme.example.test/v1/pkiext-compare",
        "aia_path": "http://cdn.example.test/pki",
    }
    expected_acme = {
        "allowed_roles": ["*"],
        "allow_role_ext_key_usage": False,
        "allowed_issuers": ["*"],
        "default_directory_policy": "sign-verbatim",
        "enabled": True,
        "dns_resolver": "",
        "eab_policy": "new-account-required",
    }
    for case, path, expected in (
        ("pkiext.cluster_persists_after_restart", "config/cluster", expected_cluster),
        ("pkiext.acme_persists_after_restart", "config/acme", expected_acme),
    ):
        response = client.request("GET", "/v1/pkiext-compare/" + path)
        passed = response.status == 200 and response.body.get("data") == expected
        results.append({"case": case, "status": response.status, "data_matches": passed, "passed": passed})
        if not passed:
            raise ScenarioFailure(case)


if __name__ == "__main__":
    raise SystemExit(core_isolation.main(
        scenario_runner=run_scenarios,
        restart_runner=run_restart_scenarios,
        profile="pkiext-live",
        scope="selected persisted PKI ACME configuration boundary only",
        runner_path=Path(__file__),
    ))
