#!/usr/bin/env python3
"""External Keys registry on the existing three-host fault lifecycle.

Only disposable synthetic state and explicit verify=false mappings are used.
A registry or grant observation is not evidence of external KMS key use.
"""
from pathlib import Path
import secrets

import ha_multihost_live as ha

CHECK_NAMES = (
    "ek_config_created", "ek_key_created", "ek_grant_created", "ek_setup_local_frontiers",
    "ek_standby_config", "ek_standby_key", "ek_standby_grant",
    "ek_reader_policy", "ek_reader_created", "ek_acl_write_denied",
    "ek_denied_config_absent", "ek_spent_token_denied",
    "ek_snapshot_config", "ek_snapshot_key", "ek_snapshot_spent",
    "ek_failover_key_updated", "ek_failover_grant_removed", "ek_failover_local_frontiers",
    "ek_failover_key_on_survivors", "ek_failover_spent_on_survivors",
    "ek_rejoined_key", "ek_rejoined_grant_absent", "ek_rejoined_spent",
    "ek_recovered_local_frontiers", "ek_recovered_key_on_all",
    "ek_recovered_grant_absent_on_all", "ek_recovered_spent_on_all",
    "ek_config_deleted", "ek_cascade_key_absent", "ek_policy_deleted",
)
REQUIRED_CHECKS = frozenset(CHECK_NAMES)
_UNSET = object()


class ExternalKeysLifecycle:
    required_checks = REQUIRED_CHECKS
    runner_path = Path(__file__)
    schema = "heptabao.multihost-external-keys-ha.v1"
    scope = "verify-false-registry-and-finite-use-acl-across-three-host-faults-not-kms-key-use"

    def __init__(self):
        self.context = self.check = None
        self.root = self.reader = self.provider_token = ""
        self.config = self.key = self.grants = self.policy = self.denied = ""
        self.started = False

    def runtime_secrets(self):
        return tuple(value for value in (self.root, self.reader, self.provider_token) if value)

    def clear(self):
        self.root = self.reader = self.provider_token = ""
        self.context = self.check = None
        self.started = False

    def _request(self, node, method, path, body=None, *, token=None):
        return ha.api(self.context, node, method, path, body,
                      self.root if token is None else token, timeout=12)

    def _call(self, name, node, method, path, expected, body=None, *, token=None, data=_UNSET):
        status, response = self._request(node, method, path, body, token=token)
        valid = status == expected
        if data is not _UNSET:
            valid &= response.get("data") == data
        if expected == 403:
            valid &= all(response.get(key) is None for key in ("data", "auth", "wrap_info"))
        self.check(name, bool(valid))
        return response

    def _frontiers(self, name, nodes, leader):
        required = ha.capture_committed_frontier(self.context, leader)
        observed = [ha.wait_local_frontier(self.context, node, required) for node in nodes]
        self.check(name, bool(observed) and all(
            committed >= required and applied >= required for committed, applied in observed),
            required_index=required)

    def _all(self, name, nodes, path, expected, *, data=_UNSET, token=None):
        observed = [self._request(node, "GET", path, token=token) for node in nodes]
        valid = bool(observed) and all(status == expected for status, _ in observed)
        if data is not _UNSET:
            valid &= all(body.get("data") == data for _, body in observed)
        if expected == 403:
            valid &= all(all(body.get(key) is None for key in ("data", "auth", "wrap_info"))
                         for _, body in observed)
        self.check(name, bool(valid))

    def _config_data(self):
        return {"plugin": "transit", "address": "https://127.0.0.1:1",
                "token": "(redacted)", "mount_path": "synthetic-transit"}

    def setup(self, context, nodes, leader, standby, root_token, check):
        if self.started or len(CHECK_NAMES) != len(REQUIRED_CHECKS):
            raise ha.FixtureError("external_keys_fixture_setup_invalid")
        self.started = True
        self.context, self.check, self.root = context, check, root_token
        suffix = secrets.token_hex(8)
        self.provider_token = secrets.token_urlsafe(24)
        self.config = "sys/external-keys/configs/ek-" + suffix
        self.denied = "sys/external-keys/configs/denied-" + suffix
        self.key, self.policy = self.config + "/keys/synthetic", "ek-reader-" + suffix
        self.grants = self.key + "/grants"
        self._call("ek_config_created", leader, "POST", self.config, 204,
                   {"plugin": "transit", "verify": False, "address": "https://127.0.0.1:1",
                    "token": self.provider_token, "mount_path": "synthetic-transit"})
        self._call("ek_key_created", standby, "POST", self.key, 204,
                   {"verify": False, "name": "synthetic-key", "version": 1})
        self._call("ek_grant_created", standby, "POST", self.grants + "/pki", 204, {})
        self._frontiers("ek_setup_local_frontiers", nodes, leader)
        self._call("ek_standby_config", standby, "GET", self.config, 200, data=self._config_data())
        self._call("ek_standby_key", standby, "GET", self.key, 200,
                   data={"name": "synthetic-key", "version": 1})
        self._call("ek_standby_grant", standby, "LIST", self.grants, 200, data={"keys": ["pki/"]})
        self._call("ek_reader_policy", leader, "PUT", "sys/policies/acl/" + self.policy, 204,
                   {"policy": 'path "sys/external-keys/*" { capabilities = ["read", "list"] }'})
        body = self._call("ek_reader_created", leader, "POST", "auth/token/create", 200,
                         {"policies": [self.policy], "no_default_policy": True, "num_uses": 1})
        auth = body.get("auth")
        if not isinstance(auth, dict) or not isinstance(auth.get("client_token"), str) or not auth["client_token"]:
            raise ha.FixtureError("external_keys_fixture_credential_shape")
        self.reader = auth["client_token"]
        self._call("ek_acl_write_denied", standby, "POST", self.denied, 403,
                   {"plugin": "transit", "verify": False, "token": self.provider_token}, token=self.reader)
        self._call("ek_denied_config_absent", leader, "GET", self.denied, 400)
        self._call("ek_spent_token_denied", leader, "GET", self.config, 403, token=self.reader)

    def after_snapshot(self, node):
        self._call("ek_snapshot_config", node, "GET", self.config, 200, data=self._config_data())
        self._call("ek_snapshot_key", node, "GET", self.key, 200,
                   data={"name": "synthetic-key", "version": 1})
        self._call("ek_snapshot_spent", node, "GET", self.config, 403, token=self.reader)

    def after_failover(self, survivors, leader):
        standby = next(node for node in survivors if node != leader)
        self._call("ek_failover_key_updated", standby, "POST", self.key, 204,
                   {"verify": False, "name": "synthetic-key", "version": 2})
        self._call("ek_failover_grant_removed", standby, "DELETE", self.grants + "/pki", 204)
        self._frontiers("ek_failover_local_frontiers", survivors, leader)
        self._all("ek_failover_key_on_survivors", survivors, self.key, 200,
                  data={"name": "synthetic-key", "version": 2})
        self._all("ek_failover_spent_on_survivors", survivors, self.config, 403, token=self.reader)

    def after_rejoin(self, node):
        self._call("ek_rejoined_key", node, "GET", self.key, 200,
                   data={"name": "synthetic-key", "version": 2})
        self._call("ek_rejoined_grant_absent", node, "LIST", self.grants, 404)
        self._call("ek_rejoined_spent", node, "GET", self.config, 403, token=self.reader)

    def after_quorum_recovery(self, nodes):
        leader = ha.wait_leader(self.context, nodes, self.root)
        self._frontiers("ek_recovered_local_frontiers", nodes, leader)
        self._all("ek_recovered_key_on_all", nodes, self.key, 200,
                  data={"name": "synthetic-key", "version": 2})
        # List observes the grant set; GET on this collection is not substituted.
        statuses = [self._request(node, "LIST", self.grants)[0] for node in nodes]
        self.check("ek_recovered_grant_absent_on_all", bool(statuses) and all(status == 404 for status in statuses))
        self._all("ek_recovered_spent_on_all", nodes, self.config, 403, token=self.reader)

    def cleanup(self, leader):
        self._call("ek_config_deleted", leader, "DELETE", self.config, 204)
        self._call("ek_cascade_key_absent", leader, "GET", self.key, 400)
        self._call("ek_policy_deleted", leader, "DELETE", "sys/policies/acl/" + self.policy, 204)


if __name__ == "__main__":
    raise SystemExit(ha.main(extension=ExternalKeysLifecycle()))
