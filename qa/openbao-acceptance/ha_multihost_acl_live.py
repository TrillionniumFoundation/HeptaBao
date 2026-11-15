#!/usr/bin/env python3
"""Compose the existing three-host fault lifecycle with live ACL authority checks.

Fresh synthetic identities and private fixture storage only. This is not an
independent audit, a mixed-version admission, or a full OpenBao verdict.
"""
from __future__ import annotations
from pathlib import Path
import secrets

import ha_multihost_live as ha

SETUP_CHECKS = (
    "acl_mount_created", "acl_auth_enabled", "acl_role_created", "acl_role_id_observed",
    "acl_secret_id_created", "acl_service_login", "acl_batch_role_selected", "acl_batch_login",
    "acl_same_entity", "acl_group_created", "acl_policy_stored", "acl_entity_bound",
    "acl_seed_own", "acl_seed_blue", "acl_seed_red", "acl_seed_peer", "acl_seed_max", "acl_seed_group",
    "acl_standby_min_absent_denied", "acl_standby_min_zero_denied",
    "acl_standby_max_absent_denied", "acl_standby_max_zero_plain",
    "acl_standby_batch_max_zero_plain", "acl_foreign_entity_denied",
    "acl_standby_original_wrapped", "acl_standby_original_unwrapped", "acl_unwrap_replay_denied",
    "acl_group_member_wrapped", "acl_group_member_unwrapped",
    "acl_write_zero_denied", "acl_write_zero_no_effect", "acl_write_wrapped", "acl_write_unwrapped",
    "acl_write_effect_version_one", "acl_metadata_changed", "acl_old_metadata_revoked",
    "acl_new_metadata_wrapped", "acl_new_metadata_unwrapped", "acl_group_membership_removed",
    "acl_removed_group_denied",
)
SNAPSHOT_CHECKS = (
    "acl_snapshot_original_wrapped", "acl_snapshot_original_unwrapped",
    "acl_snapshot_batch_wrapped", "acl_snapshot_batch_unwrapped",
    "acl_snapshot_old_metadata_denied", "acl_snapshot_removed_group_denied",
    "acl_snapshot_max_zero_plain",
)
FAILOVER_CHECKS = (
    "acl_failover_original_wrapped", "acl_failover_original_unwrapped",
    "acl_failover_batch_wrapped", "acl_failover_batch_unwrapped",
    "acl_failover_entity_disabled", "acl_failover_service_revoked_on_survivors",
    "acl_failover_batch_revoked_on_survivors",
)
REJOIN_CHECKS = ("acl_rejoined_old_leader_service_revoked", "acl_rejoined_old_leader_batch_revoked")
RECOVERY_CHECKS = ("acl_quorum_recovery_service_revoked_on_all", "acl_quorum_recovery_batch_revoked_on_all")
CLEANUP_CHECKS = (
    "acl_cleanup_group", "acl_cleanup_entity", "acl_cleanup_auth_mount",
    "acl_cleanup_policy", "acl_cleanup_secret_mount", "acl_cleanup_data_absent",
)
REQUIRED_CHECKS = frozenset(SETUP_CHECKS + SNAPSHOT_CHECKS + FAILOVER_CHECKS + REJOIN_CHECKS + RECOVERY_CHECKS + CLEANUP_CHECKS)


class AclLifecycle:
    required_checks = REQUIRED_CHECKS
    runner_path = Path(__file__)
    schema = "heptabao.multihost-acl-ha.v1"
    scope = "live-identity-acl-and-wrapping-context-across-three-host-faults"

    def __init__(self):
        self.context = None
        self.check = None
        self.root = ""
        self.service = ""
        self.batch = ""
        self.role_id = ""
        self.secret_id = ""
        self.entity = ""
        self.group = ""
        self.wrappers: list[str] = []
        self.paths: dict[str, str] = {}
        self.prefix = ""
        self.auth_mount = ""
        self.policy_name = ""
        self.group_name = ""
        self.started = False

    def runtime_secrets(self) -> tuple[str, ...]:
        return tuple(value for value in (self.root, self.service, self.batch, self.role_id, self.secret_id, *self.wrappers) if value)

    def clear(self) -> None:
        self.root = self.service = self.batch = self.role_id = self.secret_id = ""
        self.wrappers.clear()
        self.started = False

    @staticmethod
    def _text(body: dict, *parts: str) -> str:
        value = body
        for part in parts:
            if not isinstance(value, dict):
                raise ha.FixtureError("acl_fixture_response_shape")
            value = value.get(part)
        if not isinstance(value, str) or not value or len(value) > 32768:
            raise ha.FixtureError("acl_fixture_response_shape")
        return value

    @staticmethod
    def _no_payload(body: dict) -> bool:
        return all(body.get(key) is None for key in ("data", "auth", "wrap_info"))

    def _request(self, node, method, path, body=None, *, token=None, ttl=None):
        return ha.api(self.context, node, method, path, body,
                      self.root if token is None else token, timeout=12, wrap_ttl=ttl)

    def _call(self, name, node, method, path, expected, body=None, *, token=None, ttl=None):
        status, response = self._request(node, method, path, body, token=token, ttl=ttl)
        self.check(name, status == expected and (expected != 403 or self._no_payload(response)))
        return response

    def _plain(self, name, node, key, token, expected):
        status, body = self._request(node, "GET", self.paths[key], token=token, ttl="0")
        self.check(name, status == 200 and body.get("data", {}).get("data") == {"synthetic": expected}
                   and body.get("wrap_info") is None and body.get("auth") is None)

    def _wrapped(self, prefix, node, key, token, *, write=False, expected=None):
        body = {"data": {"synthetic": "written-once"}} if write else None
        status, response = self._request(node, "POST" if write else "GET", self.paths[key], body, token=token, ttl="20")
        info = response.get("wrap_info")
        valid = (status == 200 and isinstance(info, dict)
                 and info.get("ttl") == 20 and info.get("creation_path") == self.paths[key]
                 and response.get("data") is None and response.get("auth") is None
                 and isinstance(info.get("token"), str) and bool(info["token"]))
        self.check(prefix + "_wrapped", valid)
        wrapper = info["token"]
        self.wrappers.append(wrapper)
        status, payload = self._request(node, "POST", "sys/wrapping/unwrap", {}, token=wrapper)
        data = payload.get("data", {})
        observed = data.get("version") == 1 if write else data.get("data") == {"synthetic": expected}
        self.check(prefix + "_unwrapped", status == 200 and observed and payload.get("wrap_info") is None)
        return wrapper

    def setup(self, context, nodes, leader, standby, root_token, check):
        if self.started:
            raise ha.FixtureError("acl_fixture_setup_repeated")
        self.started = True
        self.context, self.check, self.root = context, check, root_token
        nonce = secrets.token_hex(8)
        self.prefix, self.auth_mount = "acl-mh-" + nonce, "acl-login-" + nonce
        self.policy_name, self.group_name = "acl-policy-" + nonce, "acl-group-" + nonce
        self._call("acl_mount_created", leader, "POST", "sys/mounts/" + self.prefix, 204,
                   {"type": "kv", "options": {"version": "2"}})
        self._call("acl_auth_enabled", leader, "POST", "sys/auth/" + self.auth_mount, 204, {"type": "approle"})
        role = "auth/" + self.auth_mount + "/role/synthetic"
        self._call("acl_role_created", leader, "POST", role, 204,
                   {"token_policies": ["default"], "secret_id_num_uses": 0, "token_ttl": "30m"})
        self.role_id = self._text(self._call("acl_role_id_observed", leader, "GET", role + "/role-id", 200), "data", "role_id")
        self.secret_id = self._text(self._call("acl_secret_id_created", leader, "POST", role + "/secret-id", 200, {}), "data", "secret_id")
        credentials = {"role_id": self.role_id, "secret_id": self.secret_id}
        login_path = "auth/" + self.auth_mount + "/login"
        service = self._call("acl_service_login", leader, "POST", login_path, 200, credentials, token="")
        self.service, self.entity = self._text(service, "auth", "client_token"), self._text(service, "auth", "entity_id")
        self._call("acl_batch_role_selected", leader, "POST", role, 204, {"token_type": "batch"})
        batch = self._call("acl_batch_login", leader, "POST", login_path, 200, credentials, token="")
        self.batch = self._text(batch, "auth", "client_token")
        self.check("acl_same_entity", self._text(batch, "auth", "entity_id") == self.entity and self.service != self.batch)
        group = self._call("acl_group_created", leader, "POST", "identity/group", 200,
                           {"name": self.group_name, "type": "internal", "member_entity_ids": [self.entity]})
        self.group = self._text(group, "data", "id")
        policy = f'''
path "{self.prefix}/data/{{{{identity.entity.id}}}}/*" {{ capabilities = ["read", "create", "update"] min_wrapping_ttl = 10 max_wrapping_ttl = 30 }}
path "{self.prefix}/data/team/{{{{identity.entity.metadata.team}}}}/*" {{ capabilities = ["read"] min_wrapping_ttl = 10 max_wrapping_ttl = 30 }}
path "{self.prefix}/data/group/{{{{identity.groups.names.{self.group_name}.id}}}}/*" {{ capabilities = ["read"] min_wrapping_ttl = 10 max_wrapping_ttl = 30 }}
path "{self.prefix}/data/max/item" {{ capabilities = ["read"] max_wrapping_ttl = 30 }}
'''
        self._call("acl_policy_stored", leader, "PUT", "sys/policies/acl/" + self.policy_name, 204, {"policy": policy})
        self._call("acl_entity_bound", leader, "POST", "identity/entity/id/" + self.entity, 204,
                   {"metadata": {"team": "blue"}, "policies": [self.policy_name]})
        self.paths = {
            "own": f"{self.prefix}/data/{self.entity}/item", "write": f"{self.prefix}/data/{self.entity}/write",
            "blue": f"{self.prefix}/data/team/blue/item", "red": f"{self.prefix}/data/team/red/item",
            "peer": f"{self.prefix}/data/unrelated-entity/item", "max": f"{self.prefix}/data/max/item",
            "group": f"{self.prefix}/data/group/{self.group}/item",
        }
        for key in ("own", "blue", "red", "peer", "max", "group"):
            self._call("acl_seed_" + key, leader, "POST", self.paths[key], 200, {"data": {"synthetic": key}})
        self._call("acl_standby_min_absent_denied", standby, "GET", self.paths["own"], 403, token=self.service)
        self._call("acl_standby_min_zero_denied", standby, "GET", self.paths["own"], 403, token=self.service, ttl="0")
        self._call("acl_standby_max_absent_denied", standby, "GET", self.paths["max"], 403, token=self.service)
        self._plain("acl_standby_max_zero_plain", standby, "max", self.service, "max")
        self._plain("acl_standby_batch_max_zero_plain", standby, "max", self.batch, "max")
        self._call("acl_foreign_entity_denied", standby, "GET", self.paths["peer"], 403, token=self.service, ttl="20")
        wrapper = self._wrapped("acl_standby_original", standby, "own", self.service, expected="own")
        self._call("acl_unwrap_replay_denied", standby, "POST", "sys/wrapping/unwrap", 400, {}, token=wrapper)
        self._wrapped("acl_group_member", standby, "group", self.service, expected="group")
        self._call("acl_write_zero_denied", standby, "POST", self.paths["write"], 403,
                   {"data": {"synthetic": "not-allowed"}}, token=self.service, ttl="0")
        self._call("acl_write_zero_no_effect", leader, "GET", self.paths["write"], 404)
        self._wrapped("acl_write", standby, "write", self.service, write=True)
        status, written = self._request(leader, "GET", self.paths["write"])
        self.check("acl_write_effect_version_one", status == 200
                   and written.get("data", {}).get("metadata", {}).get("version") == 1
                   and written.get("data", {}).get("data") == {"synthetic": "written-once"})
        self._call("acl_metadata_changed", standby, "POST", "identity/entity/id/" + self.entity, 204, {"metadata": {"team": "red"}})
        self._call("acl_old_metadata_revoked", leader, "GET", self.paths["blue"], 403, token=self.service, ttl="20")
        self._wrapped("acl_new_metadata", standby, "red", self.batch, expected="red")
        self._call("acl_group_membership_removed", standby, "POST", "identity/group/id/" + self.group, 204, {"member_entity_ids": []})
        self._call("acl_removed_group_denied", leader, "GET", self.paths["group"], 403, token=self.service, ttl="20")

    def after_snapshot(self, node):
        self._wrapped("acl_snapshot_original", node, "own", self.service, expected="own")
        self._wrapped("acl_snapshot_batch", node, "red", self.batch, expected="red")
        self._call("acl_snapshot_old_metadata_denied", node, "GET", self.paths["blue"], 403, token=self.service, ttl="20")
        self._call("acl_snapshot_removed_group_denied", node, "GET", self.paths["group"], 403, token=self.service, ttl="20")
        self._plain("acl_snapshot_max_zero_plain", node, "max", self.service, "max")

    def _revoked_on_all(self, name, nodes, token):
        # Read-only observations may enumerate all peers; no mutation is retried.
        responses = [self._request(node, "GET", self.paths["max"], token=token, ttl="0") for node in nodes]
        self.check(name, bool(responses) and all(status == 403 and self._no_payload(body) for status, body in responses))

    def after_failover(self, survivors, leader):
        standby = next(node for node in survivors if node != leader)
        self._wrapped("acl_failover_original", standby, "own", self.service, expected="own")
        self._wrapped("acl_failover_batch", standby, "red", self.batch, expected="red")
        self._call("acl_failover_entity_disabled", standby, "POST", "identity/entity/id/" + self.entity, 204, {"disabled": True})
        self._revoked_on_all("acl_failover_service_revoked_on_survivors", survivors, self.service)
        self._revoked_on_all("acl_failover_batch_revoked_on_survivors", survivors, self.batch)

    def after_rejoin(self, node):
        self._revoked_on_all("acl_rejoined_old_leader_service_revoked", [node], self.service)
        self._revoked_on_all("acl_rejoined_old_leader_batch_revoked", [node], self.batch)

    def after_quorum_recovery(self, nodes):
        self._revoked_on_all("acl_quorum_recovery_service_revoked_on_all", nodes, self.service)
        self._revoked_on_all("acl_quorum_recovery_batch_revoked_on_all", nodes, self.batch)

    def cleanup(self, leader):
        for name, path in (
            ("group", "identity/group/id/" + self.group), ("entity", "identity/entity/id/" + self.entity),
            ("auth_mount", "sys/auth/" + self.auth_mount), ("policy", "sys/policies/acl/" + self.policy_name),
            ("secret_mount", "sys/mounts/" + self.prefix),
        ):
            self._call("acl_cleanup_" + name, leader, "DELETE", path, 204)
        self._call("acl_cleanup_data_absent", leader, "GET", self.paths["own"], 404)


if __name__ == "__main__":
    raise SystemExit(ha.main(extension=AclLifecycle()))
