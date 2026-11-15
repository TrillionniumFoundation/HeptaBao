#!/usr/bin/env python3
"""Compare scoped live Identity ACL templates against an exact pinned OpenBao release.

Fresh local TLS services and synthetic data only. The retained restart context
is process memory, never a report or token store. This is not whole-ACL,
whole-Identity, migration, independent or production qualification.
"""
from __future__ import annotations
from pathlib import Path

from bao_http import Client
from core_isolation import ScenarioFailure, main

_RESTART_STATE: dict[int, dict] = {}


class Trace:
    def __init__(self, client: Client, rows: list[dict]):
        self.client, self.rows = client, rows

    def check(self, name: str, response, status: int, data=None):
        row = {"case": "acl_templates." + name, "status": response.status,
               "passed": response.status == status}
        if data is not None:
            row["data_matches"] = response.body.get("data") == data
            row["passed"] &= row["data_matches"]
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])
        return response.body

    def call(self, name: str, method: str, path: str, status: int, body=None, token=None, data=None):
        return self.check(name, self.client.request(method, "/v1/" + path, body, token=token), status, data)

    def truth(self, name: str, condition: bool):
        row = {"case": "acl_templates." + name, "passed": bool(condition)}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])


def invalid_substitution_status(version: str) -> int:
    # Measured on independent pinned official artifacts, not an accepted union.
    return {"2.6.2": 403, "2.7.0": 400}[version]


def run_scenarios(client: Client, results: list[dict] | None = None, *,
                  oracle_version: str = "2.6.2") -> list[dict]:
    invalid_status = invalid_substitution_status(oracle_version)
    rows = [] if results is None else results
    t = Trace(client, rows)
    t.call("mount_kv", "POST", "sys/mounts/acl-template", 204,
           {"type": "kv", "options": {"version": "1"}})
    t.call("mount_auth", "POST", "sys/auth/acl-template-login", 204, {"type": "approle"})
    mounts = t.call("mount_accessor", "GET", "sys/auth", 200)
    accessor = mounts["data"]["acl-template-login/"]["accessor"]
    role = "auth/acl-template-login/role/synthetic"
    t.call("create_role", "POST", role, 204, {"token_policies": ["default"], "secret_id_num_uses": 0})
    role_id = t.call("role_id", "GET", role + "/role-id", 200)["data"]["role_id"]
    secret_id = t.call("secret_id", "POST", role + "/secret-id", 200, {})["data"]["secret_id"]
    credentials = {"role_id": role_id, "secret_id": secret_id}
    issued = t.call("login_service", "POST", "auth/acl-template-login/login", 200, credentials)["auth"]
    token, entity = issued["client_token"], issued["entity_id"]
    t.call("batch_role", "POST", role, 204, {"token_type": "batch"})
    batch = t.call("login_batch", "POST", "auth/acl-template-login/login", 200, credentials)["auth"]
    t.truth("batch_same_identity", batch["entity_id"] == entity and batch["client_token"] != token)
    entity_path = "identity/entity/id/" + entity
    record = t.call("entity_alias", "GET", entity_path, 200)["data"]
    aliases = [alias for alias in record["aliases"] if alias["mount_accessor"] == accessor]
    t.truth("unique_mount_alias", len(aliases) == 1)
    alias = aliases[0]
    alias_path = "identity/entity-alias/id/" + alias["id"]
    alias_body = {"canonical_id": entity, "mount_accessor": accessor, "name": role_id,
                  "custom_metadata": {"tenant": "blue"}}
    t.call("custom_alias_metadata", "POST", alias_path, 200, alias_body)
    child = t.call("direct_group", "POST", "identity/group", 200,
                   {"name": "acl-template-team", "type": "internal", "member_entity_ids": [entity],
                    "metadata": {"zone": "blue"}})["data"]["id"]
    t.call("parent_group", "POST", "identity/group", 200,
           {"name": "acl-template-division", "type": "internal", "member_group_ids": [child]})
    t.call("nonmember_group", "POST", "identity/group", 200,
           {"name": "acl-template-peer", "type": "internal", "metadata": {"zone": "peer"}})
    bindings = [
        ("entity", "identity.entity.id", entity),
        ("name", "identity.entity.name", "acl-template-alice"),
        ("team", "identity.entity.metadata.team", "blue"),
        ("alias-id", f"identity.entity.aliases.{accessor}.id", alias["id"]),
        ("alias-name", f"identity.entity.aliases.{accessor}.name", role_id),
        ("login-meta", f"identity.entity.aliases.{accessor}.metadata.role_name", "synthetic"),
        ("custom-meta", f"identity.entity.aliases.{accessor}.custom_metadata.tenant", "blue"),
        ("group-id", f"identity.groups.ids.{child}.id", child),
        ("group-name", "identity.groups.names.acl-template-team.name", "acl-template-team"),
        ("group-zone", "identity.groups.names.acl-template-team.metadata.zone", "blue"),
        ("parent", "identity.groups.names.acl-template-division.name", "acl-template-division"),
    ]
    policy = "\n".join(
        f'path "acl-template/{prefix}/{{{{ {selector} }}}}/*" {{ capabilities = ["read"] }}'
        for prefix, selector, _ in bindings
    ) + '''
path "acl-template/nonmember/{{identity.groups.names.acl-template-peer.metadata.zone}}/*" { capabilities = ["read"] }
path "acl-template/parameter/{{identity.entity.id}}/item" {
  capabilities = ["create", "read", "update"]
  required_parameters = ["foo"]
  allowed_parameters = { "foo" = ["good"] }
}
'''
    t.call("policy_accepted", "PUT", "sys/policies/acl/identity-template", 204, {"policy": policy})
    t.call("identity_projection", "POST", entity_path, 204,
           {"name": "acl-template-alice", "metadata": {"team": "blue"}, "policies": ["identity-template"]})
    payload = {"synthetic": "original"}
    for prefix, _, value in bindings:
        path = f"acl-template/{prefix}/{value}/item"
        t.call("seed_" + prefix, "POST", path, 204, payload)
        for kind, bearer in [("service", token), ("batch", batch["client_token"])]:
            t.call(kind + "_" + prefix, "GET", path, 200, token=bearer, data=payload)
    peer = "acl-template/entity/peer/item"
    t.call("seed_peer", "POST", peer, 204, payload)
    t.call("peer_denied", "GET", peer, 403, token=token)
    t.call("seed_nonmember", "POST", "acl-template/nonmember/peer/item", 204, payload)
    t.call("nonmember_denied", "GET", "acl-template/nonmember/peer/item", 403, token=token)
    own = f"acl-template/entity/{entity}/item"
    caps = t.call("inspect_target", "POST", "sys/capabilities", 200,
                  {"token": token, "paths": [own, peer]})["data"]
    t.truth("inspected_target_not_root_identity", caps[own] == ["read"] and caps[peer] == ["deny"])
    caps = t.call("inspect_self", "POST", "sys/capabilities-self", 200,
                  {"paths": [own, peer]}, token=token)["data"]
    t.truth("self_and_dispatch_agree", caps[own] == ["read"] and caps[peer] == ["deny"])
    parameter_path = f"acl-template/parameter/{entity}/item"
    t.call("allowed_parameter", "POST", parameter_path, 204, {"foo": "good"}, token)
    t.call("denied_parameter", "POST", parameter_path, 403, {"foo": "bad"}, token)
    t.call("required_parameter", "POST", parameter_path, 403, {}, token)
    t.call("denied_parameter_no_effect", "GET", parameter_path, 200, data={"foo": "good"})
    orphan = t.call("unbound_token", "POST", "auth/token/create", 200,
                    {"policies": ["identity-template"], "no_default_policy": True, "ttl": "10m"})["auth"]["client_token"]
    t.call("unbound_identity_denied", "GET", own, 403, token=orphan)
    t.call("rename_and_change_metadata", "POST", entity_path, 204,
           {"name": "acl-template-renamed", "metadata": {"team": "red"}})
    t.call("old_name_denied", "GET", "acl-template/name/acl-template-alice/item", 403, token=token)
    t.call("old_team_denied", "GET", "acl-template/team/blue/item", 403, token=token)
    t.call("seed_new_name", "POST", "acl-template/name/acl-template-renamed/item", 204, payload)
    t.call("seed_new_team", "POST", "acl-template/team/red/item", 204, payload)
    t.call("new_name_current_token", "GET", "acl-template/name/acl-template-renamed/item", 200, token=token, data=payload)
    t.call("new_team_current_batch", "GET", "acl-template/team/red/item", 200, token=batch["client_token"], data=payload)
    for label, value in [("star", "*"), ("segment", "+"), ("suffix", "red*")]:
        t.call("inject_" + label, "POST", entity_path, 204, {"metadata": {"team": value}})
        t.call("injected_" + label + "_denied", "GET", "acl-template/team/red/item", invalid_status, token=token)
        if oracle_version == "2.7.0":
            t.call("injected_" + label + "_batch_denied", "GET", "acl-template/team/red/item", 400,
                   token=batch["client_token"])
            t.call("injected_" + label + "_write_denied", "POST", "acl-template/team/red/item", 400,
                   {"synthetic": "must-not-publish"}, token=token)
            t.call("injected_" + label + "_write_no_effect", "GET", "acl-template/team/red/item", 200, data=payload)
            t.call("injected_" + label + "_inspection_rejected", "POST", "sys/capabilities", 403,
                   {"token": token, "path": "acl-template/team/red/item"})
    t.call("restore_team", "POST", entity_path, 204, {"metadata": {"team": "red"}})
    t.call("remove_direct_membership", "POST", "identity/group/id/" + child, 204, {"member_entity_ids": []})
    t.call("direct_group_revoked", "GET", f"acl-template/group-id/{child}/item", 403, token=token)
    t.call("parent_group_revoked", "GET", "acl-template/parent/acl-template-division/item", 403, token=token)
    alias_body["custom_metadata"] = {"tenant": "red"}
    t.call("change_alias_metadata", "POST", alias_path, 200, alias_body)
    t.call("old_alias_metadata_denied", "GET", "acl-template/custom-meta/blue/item", 403, token=token)
    t.call("seed_new_alias_metadata", "POST", "acl-template/custom-meta/red/item", 204, payload)
    t.call("new_alias_metadata_allowed", "GET", "acl-template/custom-meta/red/item", 200, token=token, data=payload)
    _RESTART_STATE[id(rows)] = {"token": token, "batch": batch["client_token"], "entity_path": entity_path,
                               "own": own, "group_path": f"acl-template/group-id/{child}/item"}
    t.truth("pre_restart_complete", True)
    return rows


def run_scenarios_270(client: Client, results: list[dict] | None = None) -> list[dict]:
    return run_scenarios(client, results, oracle_version="2.7.0")


def run_after_restart(client: Client, rows: list[dict]) -> None:
    context = _RESTART_STATE.pop(id(rows), None)
    if context is None:
        raise ScenarioFailure("acl_templates.restart_context_missing")
    t = Trace(client, rows)
    t.call("restart_original_token", "GET", context["own"], 200, token=context["token"], data={"synthetic": "original"})
    t.call("restart_original_batch", "GET", context["own"], 200, token=context["batch"], data={"synthetic": "original"})
    t.call("restart_old_metadata_denied", "GET", "acl-template/team/blue/item", 403, token=context["token"])
    t.call("restart_new_metadata_allowed", "GET", "acl-template/team/red/item", 200, token=context["token"], data={"synthetic": "original"})
    t.call("restart_membership_revoked", "GET", context["group_path"], 403, token=context["token"])
    t.call("restart_old_alias_denied", "GET", "acl-template/custom-meta/blue/item", 403, token=context["token"])
    t.call("disable_entity", "POST", context["entity_path"], 204, {"disabled": True})
    t.call("disabled_original_token", "GET", context["own"], 403, token=context["token"])
    t.call("disabled_original_batch", "GET", context["own"], 403, token=context["batch"])
    t.truth("complete", True)


if __name__ == "__main__":
    raise SystemExit(main(scenario_runner=run_scenarios, restart_runner=run_after_restart,
                         versioned_scenario_runners={"2.7.0": run_scenarios_270},
                         profile="policy-templates-live", runner_path=Path(__file__),
                         scope="bounded live Identity ACL substitutions, membership, parameter constraints and restart"))
