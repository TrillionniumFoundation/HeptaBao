#!/usr/bin/env python3
"""OpenBao 2.7 External Keys registry comparison on two isolated TLS services.

Explicit verify=false only: no remote provider, HSM or external cryptographic
operation is claimed. Credentials remain in memory, never in report rows.
"""
from pathlib import Path
import copy

from bao_http import Client
from core_isolation import ScenarioFailure, main as compare

CONFIGS = "sys/external-keys/configs"
CONFIG = CONFIGS + "/demo"
KEY = CONFIG + "/keys/key1"
GRANTS = KEY + "/grants"
_RESTART_STATE: dict[int, dict] = {}
_UNSET = object()
PRE_CASES = tuple("externalkeys270." + name for name in (
    "empty", "missing", "missing_patch", "missing_plugin", "config_create",
    "config_read", "config_list", "config_patch", "config_after_patch",
    "config_remove_field", "config_after_remove", "keys_empty", "key_missing",
    "key_no_config", "key_create", "key_read", "key_patch", "key_after_patch",
    "key_list", "grants_empty", "grant_add", "grant_repeat_canonical", "grant_repeat", "grant_list",
    "grant_absent_delete", "grant_list_unchanged", "alias_write", "alias_read",
    "canonical_unchanged", "policy", "reader_create", "reader_read",
    "denied_write", "denied_absent", "spent_reader", "namespace_create",
    "team_create", "root_list", "team_list", "root_key_missing_team",
    "team_config_not_root", "root_key_unchanged"))
RESTART_CASES = tuple("externalkeys270." + name for name in (
    "restart_config", "restart_key", "restart_grant", "restart_spent",
    "restart_denied_absent", "restart_team_config", "grant_delete",
    "grants_after_delete", "key_delete", "key_delete_repeat",
    "key_missing_after_delete", "key_recreate", "config_delete",
    "config_missing_after_delete", "cascade_key_absent", "configs_empty_after_delete",
    "peer_namespace_survives", "team_delete", "team_empty", "complete"))


def require_sequence(rows, expected):
    if tuple(row["case"] for row in rows) != expected or not all(row.get("passed") is True for row in rows):
        raise ScenarioFailure("externalkeys270.incomplete_or_reordered_trace")


class Trace:
    def __init__(self, client, rows):
        self.client, self.rows = client, rows

    def call(self, name, method, path, expected, body=None, *, data=_UNSET,
             token=None, namespace="", errors=_UNSET):
        client = copy.copy(self.client)
        client.namespace = namespace
        response = client.request(method, "/v1/" + path, body, token=token,
            content_type="application/merge-patch+json" if method == "PATCH" else "application/json")
        row = {"case": "externalkeys270." + name, "status": response.status,
               "passed": response.status == expected}
        if data is not _UNSET:
            row["passed"] &= response.body.get("data") == data
        if errors is not _UNSET:
            row["passed"] &= response.body.get("errors") == errors
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])
        return response.body


def config_data():
    return {"plugin": "transit", "address": "https://127.0.0.1:1",
            "token": "(redacted)", "mount_path": "remote-transit",
            "tls_client_key_bytes": "(redacted)",
            "tls_client_cert_bytes": "synthetic-public-client-certificate",
            "tls_ca_cert_bytes": "synthetic-public-ca"}


def run_scenarios(client: Client, results: list[dict] | None = None):
    rows = [] if results is None else results
    t = Trace(client, rows)
    t.call("empty", "LIST", CONFIGS, 404, errors=[])
    t.call("missing", "GET", CONFIG, 400, errors=['config "demo" not found'])
    t.call("missing_patch", "PATCH", CONFIG, 400, {"verify": False, "namespace": "x"})
    t.call("missing_plugin", "POST", CONFIG, 400, {"verify": False})
    t.call("config_create", "POST", CONFIG, 204,
        {"plugin": "transit", "verify": False, "address": "https://127.0.0.1:1",
         "token": "synthetic-registry-only", "mount_path": "transit", "namespace": "",
         "tls_client_key_bytes": "synthetic-private-client-key-never-used",
         "tls_client_cert_bytes": "synthetic-public-client-certificate",
         "tls_ca_cert_bytes": "synthetic-public-ca"})
    t.call("config_read", "GET", CONFIG, 200,
        data={**config_data(), "mount_path": "transit", "namespace": ""})
    t.call("config_list", "LIST", CONFIGS, 200, data={"keys": ["demo"]})
    t.call("config_patch", "PATCH", CONFIG, 204,
        {"verify": False, "mount_path": "remote-transit", "namespace": "team/"})
    t.call("config_after_patch", "GET", CONFIG, 200, data={**config_data(), "namespace": "team/"})
    t.call("config_remove_field", "PATCH", CONFIG, 204, {"verify": False, "namespace": None})
    t.call("config_after_remove", "GET", CONFIG, 200, data=config_data())
    t.call("keys_empty", "LIST", CONFIG + "/keys", 404, errors=[])
    t.call("key_missing", "GET", KEY, 400, errors=['key "key1" not found'])
    t.call("key_no_config", "POST", CONFIGS + "/missing/keys/k", 400, {"verify": False})
    t.call("key_create", "POST", KEY, 204, {"verify": False, "name": "remote", "version": 3})
    t.call("key_read", "GET", KEY, 200, data={"name": "remote", "version": 3})
    t.call("key_patch", "PATCH", KEY, 204, {"verify": False, "version": 4})
    t.call("key_after_patch", "GET", KEY, 200, data={"name": "remote", "version": 4})
    t.call("key_list", "LIST", CONFIG + "/keys", 200, data={"keys": ["key1"]})
    t.call("grants_empty", "LIST", GRANTS, 404, errors=[])
    t.call("grant_add", "POST", GRANTS + "/pki", 204)
    t.call("grant_repeat_canonical", "POST", GRANTS + "/pki", 204)
    t.call("grant_repeat", "POST", GRANTS + "/pki/", 400)
    t.call("grant_list", "LIST", GRANTS, 200, data={"keys": ["pki/"]})
    t.call("grant_absent_delete", "DELETE", GRANTS + "/transit", 204)
    t.call("grant_list_unchanged", "LIST", GRANTS, 200, data={"keys": ["pki/"]})
    t.call("alias_write", "POST", CONFIGS + "demo", 404, {"plugin": "transit", "verify": False})
    t.call("alias_read", "GET", CONFIGS + "demo", 404)
    t.call("canonical_unchanged", "GET", CONFIG, 200, data=config_data())
    policy = 'path "sys/external-keys/*" { capabilities = ["read", "list"] }'
    t.call("policy", "PUT", "sys/policies/acl/externalkeys-reader", 204, {"policy": policy})
    reader = t.call("reader_create", "POST", "auth/token/create", 200,
        {"policies": ["externalkeys-reader"], "no_default_policy": True, "num_uses": 2})["auth"]["client_token"]
    t.call("reader_read", "GET", CONFIG, 200, token=reader, data=config_data())
    t.call("denied_write", "POST", CONFIGS + "/denied", 403,
        {"plugin": "transit", "verify": False, "token": "must-not-persist"}, token=reader)
    t.call("denied_absent", "GET", CONFIGS + "/denied", 400)
    t.call("spent_reader", "LIST", CONFIGS, 403, token=reader)
    t.call("namespace_create", "POST", "sys/namespaces/team", 200,
        {"custom_metadata": {"owner": "synthetic-external-keys"}})
    t.call("team_create", "POST", CONFIGS + "/team-key", 204,
        {"plugin": "transit", "verify": False, "token": "synthetic-team"}, namespace="team")
    t.call("root_list", "LIST", CONFIGS, 200, data={"keys": ["demo"]})
    t.call("team_list", "LIST", CONFIGS, 200, namespace="team", data={"keys": ["team-key"]})
    t.call("root_key_missing_team", "GET", CONFIG, 400, namespace="team")
    t.call("team_config_not_root", "GET", CONFIGS + "/team-key", 400)
    t.call("root_key_unchanged", "GET", KEY, 200, data={"name": "remote", "version": 4})
    require_sequence(rows, PRE_CASES)
    _RESTART_STATE[id(rows)] = {"reader": reader}
    return rows


def run_after_restart(client: Client, rows: list[dict]):
    state = _RESTART_STATE.pop(id(rows), None)
    if state is None:
        raise ScenarioFailure("externalkeys270.restart_context_missing")
    require_sequence(rows, PRE_CASES)
    t = Trace(client, rows)
    t.call("restart_config", "GET", CONFIG, 200, data=config_data())
    t.call("restart_key", "GET", KEY, 200, data={"name": "remote", "version": 4})
    t.call("restart_grant", "LIST", GRANTS, 200, data={"keys": ["pki/"]})
    t.call("restart_spent", "LIST", CONFIGS, 403, token=state["reader"])
    t.call("restart_denied_absent", "GET", CONFIGS + "/denied", 400)
    team_data = {"plugin": "transit", "token": "(redacted)"}
    t.call("restart_team_config", "GET", CONFIGS + "/team-key", 200, namespace="team", data=team_data)
    t.call("grant_delete", "DELETE", GRANTS + "/pki", 204)
    t.call("grants_after_delete", "LIST", GRANTS, 404, errors=[])
    t.call("key_delete", "DELETE", KEY, 204)
    t.call("key_delete_repeat", "DELETE", KEY, 204)
    t.call("key_missing_after_delete", "GET", KEY, 400)
    t.call("key_recreate", "POST", KEY, 204, {"verify": False, "name": "remote", "version": 5})
    t.call("config_delete", "DELETE", CONFIG, 204)
    t.call("config_missing_after_delete", "GET", CONFIG, 400)
    t.call("cascade_key_absent", "GET", KEY, 400)
    t.call("configs_empty_after_delete", "LIST", CONFIGS, 404, errors=[])
    t.call("peer_namespace_survives", "GET", CONFIGS + "/team-key", 200, namespace="team", data=team_data)
    t.call("team_delete", "DELETE", CONFIGS + "/team-key", 204, namespace="team")
    t.call("team_empty", "LIST", CONFIGS, 404, namespace="team", errors=[])
    rows.append({"case": "externalkeys270.complete", "passed": True})
    require_sequence(rows, PRE_CASES + RESTART_CASES)


def main():
    return compare(scenario_runner=run_scenarios, restart_runner=run_after_restart,
        profile="external-keys270", required_oracle_version="2.7.0",
        scope="verify_false_registry_crud_patch_grants_acl_namespace_and_restart_not_provider_key_use",
        runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
