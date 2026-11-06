#!/usr/bin/env python3
"""SOURCE ONLY: the immutable 23-cell JWT ACL matrix on one owned TLS fixture.

No process launch, binary selection, credential file, or live entry point is
provided here. A separately reviewed fixture supplies its private admin Client,
the frozen public RSA key, and the original remaining-clock callback.
"""
from __future__ import annotations

import hashlib
import json
import re

from bao_http import BaoError
from raw_status_observer import RawStatusCalls

MOUNT = "jwt-acl"
PREFIX = "/v1/auth/" + MOUNT
COMMON_ROLE_FIELDS = ("role_type", "user_claim", "bound_audiences")
COMMON_CONFIG_FIELDS = ("bound_issuer", "jwt_validation_pubkeys", "jwt_supported_algs")


class FixedAcl23:
    def __init__(self, admin, remaining, matrix_raw, public_pem, run_id):
        if (not isinstance(matrix_raw, bytes) or len(matrix_raw) != 14285
                or hashlib.sha256(matrix_raw).hexdigest() !=
                "59e3c9519e59e7ae26cde512a8171d39e2175e8bb24f12039222218570ebe6f8"):
            raise BaoError("frozen_original_matrix_whole_required")
        matrix = json.loads(matrix_raw.decode("utf-8"))
        if (matrix.get("case_count") != 23 or len(matrix.get("matrix", [])) != 23
                or matrix.get("actual_cases_executed") != 0
                or matrix.get("raw_status_equality_required_for_parity") is not True):
            raise BaoError("original_unexecuted_23_matrix_required")
        if not re.fullmatch("[a-z0-9-]{1,32}", run_id):
            raise BaoError("fixed_fixture_run_id")
        if (not isinstance(public_pem, str) or len(public_pem) > 8192
                or not public_pem.startswith("-----BEGIN PUBLIC KEY-----\n")
                or not public_pem.endswith("-----END PUBLIC KEY-----\n")):
            raise BaoError("frozen_public_spki_required")
        self.calls = RawStatusCalls(admin, remaining)
        self.admin = admin
        self.remaining = remaining
        self.rows = tuple(matrix["matrix"])
        self.run_id = run_id
        self.marker = "heptabao-acl23-" + run_id
        self.baseline_config = {
            "bound_issuer": self.marker,
            "jwt_validation_pubkeys": [public_pem[:-1]],  # Only the validated source PEM final LF.
            "jwt_supported_algs": ["RS256"],
        }
        self.existing = tuple(
            row["path"].split("/")[-1] for row in self.rows
            if row["id"].startswith(("delete-", "existing-post-"))
        ) + ("collection-seed",)
        self.fresh = tuple(
            row["path"].split("/")[-1] for row in self.rows
            if row["id"].startswith("fresh-post-")
        )
        self.names = tuple(sorted(set(self.existing + self.fresh)))
        self.results = []
        self.setup_completed = False
        self.setup_config_projection = None
        self.owned_policy_names = []
        self.mount_created_known = False
        self._private_tokens = []
        self.stopped_reason = None
        self.current_case = None

    def admin_call(self, label, method, path, payload=None):
        return self.calls.call("setup-" + label, method, path, payload,
                               public_body=False, path_template=path)

    def require_status(self, response, expected, reason):
        if response.status != expected:
            raise BaoError(reason)
        return response

    def role_body(self, marker):
        return {"role_type": "jwt", "user_claim": "sub", "bound_audiences": [marker]}

    def common_role(self, value):
        if not isinstance(value, dict):
            raise BaoError("role_object_required")
        out = {name: value.get(name) for name in COMMON_ROLE_FIELDS}
        if (out["role_type"] != "jwt" or out["user_claim"] != "sub"
                or not isinstance(out["bound_audiences"], list)
                or not all(isinstance(x, str) for x in out["bound_audiences"])):
            raise BaoError("common_role_projection_invalid")
        policies_present = "token_policies" in value
        policies = value.get("token_policies")
        if policies is not None and (not isinstance(policies, list)
                                     or not all(isinstance(x, str) for x in policies)):
            raise BaoError("explicit_role_policy_projection_required")
        # Preserve missing/null/[]/["default"] separately; no default injection
        # or normalization of the independent role-policy compatibility gap.
        return {"common": out, "token_policies_present": policies_present,
                "token_policies": policies}

    def snapshot(self):
        config = self.require_status(
            self.admin_call("config-read", "GET", PREFIX + "/config"), 200,
            "admin_config_read_failed").data()
        config = {name: config.get(name) for name in COMMON_CONFIG_FIELDS}
        listing = self.require_status(
            self.admin_call("role-list", "LIST", PREFIX + "/role"), 200,
            "admin_role_list_failed").data().get("keys")
        if (not isinstance(listing, list) or len(listing) != len(set(listing))
                or not set(listing).issubset(set(self.names))):
            raise BaoError("fresh_owned_role_inventory_invalid")
        roles = {}
        for name in self.names:
            response = self.admin_call("role-read", "GET", PREFIX + "/role/" + name)
            if name in listing:
                self.require_status(response, 200, "listed_role_not_readable")
                roles[name] = self.common_role(response.data())
            else:
                self.require_status(response, 404, "unlisted_role_not_absent")
                roles[name] = None
        return {"config": config, "roles": roles, "listed": sorted(listing)}

    def setup(self):
        inventory = self.require_status(
            self.admin_call("auth-inventory", "GET", "/v1/sys/auth"), 200,
            "admin_auth_inventory_failed").data()
        if MOUNT + "/" in inventory:
            raise BaoError("fresh_fixed_jwt_mount_required")
        self.require_status(
            self.admin_call("mount-create", "POST", "/v1/sys/auth/" + MOUNT,
                            {"type": "jwt", "description": self.marker}),
            204, "root_jwt_mount_create_failed")
        self.mount_created_known = True
        self.require_status(
            self.admin_call("config-create", "POST", PREFIX + "/config", self.baseline_config),
            204, "common_jwt_config_precondition_failed")
        for name in self.existing:
            self.require_status(
                self.admin_call("role-seed", "POST", PREFIX + "/role/" + name,
                                self.role_body(self.marker + "-seed-" + name)),
                204, "common_role_seed_precondition_failed")
        state = self.snapshot()
        self.setup_config_projection = state["config"]
        if state["config"] != self.baseline_config:
            raise BaoError("common_config_projection_mismatch")
        if any(state["roles"][name] is None for name in self.existing):
            raise BaoError("existing_role_precondition_failed")
        if any(state["roles"][name] is not None for name in self.fresh):
            raise BaoError("fresh_role_precondition_failed")
        self.setup_completed = True
        return state

    def issue_actor(self, row, ordinal):
        policy_name = "hbqa-acl23-" + self.run_id + "-" + str(ordinal)
        route = row["path"].split("?", 1)[0]
        policy = "path " + json.dumps(route) + " { capabilities = " + json.dumps(row["capabilities"]) + " }"
        self.require_status(
            self.admin_call("actor-policy-absence", "GET", "/v1/sys/policies/acl/" + policy_name),
            404, "fresh_owned_actor_policy_required")
        self.require_status(
            self.admin_call("actor-policy", "POST", "/v1/sys/policies/acl/" + policy_name,
                            {"policy": policy}), 204, "actor_policy_setup_failed")
        self.owned_policy_names.append(policy_name)
        issued = self.require_status(
            self.admin_call("actor-create", "POST", "/v1/auth/token/create", {
                "policies": [policy_name], "no_default_policy": True,
                "ttl": "5m", "type": "service", "renewable": False,
            }), 200, "real_actor_issuance_failed").body.get("auth")
        if not isinstance(issued, dict):
            raise BaoError("real_actor_auth_shape")
        token = issued.get("client_token")
        if not isinstance(token, str) or not 1 <= len(token) <= 8192:
            raise BaoError("real_actor_token_missing")
        self._private_tokens.append(token)
        data = self.require_status(
            self.admin_call("actor-lookup", "POST", "/v1/auth/token/lookup", {"token": token}),
            200, "real_actor_independent_lookup_failed").data()
        if (data.get("policies") != [policy_name] or data.get("type") != "service"
                or data.get("entity_id") != ""
                or type(data.get("ttl")) is not int or data["ttl"] < 30):
            raise BaoError("actor_no_default_nonroot_precondition_failed")
        if issued.get("policies") != [policy_name]:
            raise BaoError("issued_actor_policy_binding_failed")
        # Tokens, accessors, lookup IDs and full token responses remain private.
        return token, {"real_issued_service": True, "independent_lookup": True,
                       "only_exact_case_policy": True, "no_default_policy": True,
                       "no_root_policy": True, "no_entity_binding": True,
                       "minimum_observed_ttl_seconds": 30}

    def case_payload(self, row):
        if row["method"] != "POST":
            return None
        marker = self.marker + "-" + row["id"]
        if row["path"] == "auth/" + MOUNT + "/config":
            return {**self.baseline_config, "bound_issuer": marker}
        return self.role_body(marker)

    def verify_transition(self, row, status, payload, before, after):
        success = status == 204
        if row["path"] == "auth/" + MOUNT + "/config":
            if after["roles"] != before["roles"] or after["listed"] != before["listed"]:
                raise BaoError("config_cell_changed_roles")
            if after["config"] != (payload if success else before["config"]):
                raise BaoError("config_cell_transition_mismatch")
            return
        if after["config"] != before["config"]:
            raise BaoError("role_cell_changed_config")
        if row["method"] in ("GET", "LIST"):
            if after != before:
                raise BaoError("read_cell_changed_common_state")
            return
        name = row["path"].split("/")[-1]
        for other in self.names:
            if other != name and after["roles"][other] != before["roles"][other]:
                raise BaoError("role_cell_changed_other_role")
        if not success:
            if after != before:
                raise BaoError("rejected_cell_changed_common_state")
        elif row["method"] == "DELETE":
            if after["roles"][name] is not None or name in after["listed"]:
                raise BaoError("delete_cell_did_not_remove_exact_role")
        else:
            if after["roles"][name] is None or after["roles"][name]["common"] != payload:
                raise BaoError("post_cell_did_not_install_common_role")
            if name not in after["listed"]:
                raise BaoError("post_cell_inventory_missing")
        expected_list = sorted(name for name, value in after["roles"].items() if value is not None)
        if after["listed"] != expected_list:
            raise BaoError("complete_common_inventory_mismatch")

    def run(self):
        try:
            self.setup()
            for ordinal, row in enumerate(self.rows):
                self.remaining()
                before = self.snapshot()
                if row["id"].startswith(("delete-", "existing-post-")):
                    if before["roles"][row["path"].split("/")[-1]] is None:
                        raise BaoError("this_cell_existing_role_not_observed")
                if row["id"].startswith("fresh-post-"):
                    if before["roles"][row["path"].split("/")[-1]] is not None:
                        raise BaoError("this_cell_role_absence_not_observed")
                self.current_case = {"case_id": row["id"], "method": row["method"],
                                     "path": row["path"], "original_request_attempted": False}
                token, actor_proof = self.issue_actor(row, ordinal)
                payload = self.case_payload(row)
                self.current_case["original_request_attempted"] = True
                response = self.calls.call(
                    row["id"], row["method"], "/v1/" + row["path"], payload,
                    token=token, public_body=True, path_template="/v1/" + row["path"],
                )
                actual_wire = dict(self.calls.records[-1])
                after = self.snapshot()
                result = {
                    "case_id": row["id"], "method": row["method"], "path": row["path"],
                    "capabilities": row["capabilities"], "actor": actor_proof,
                    "wire": actual_wire, "actual_raw_status": response.status,
                    "official_source_prediction": row["official_source_prediction"],
                    "R2_source_prediction": row["R2_source_prediction"],
                    "normalize_status": False, "before": before, "after": after,
                    "transition_checked": False, "parity": None,
                }
                self.results.append(result)
                self.verify_transition(row, response.status, payload, before, after)
                result["transition_checked"] = True
                if row["path"] == "auth/" + MOUNT + "/config" and after["config"] != self.baseline_config:
                    # Explicit independent administrative baseline reset only
                    # after known original response and verified complete state.
                    self.require_status(
                        self.admin_call("config-baseline-reset", "POST", PREFIX + "/config",
                                        self.baseline_config), 204, "known_baseline_reset_failed")
                    if self.snapshot()["config"] != self.baseline_config:
                        raise BaoError("known_baseline_reset_not_observed")
                self.require_status(
                    self.admin_call("actor-revoke", "POST", "/v1/auth/token/revoke", {"token": token}),
                    204, "issued_actor_revoke_failed")
                self._private_tokens.remove(token)
                self.current_case = None
        except BaoError as error:
            self.stopped_reason = error.code
            raise
        return {"matrix_cases": 23, "actual_case_records": len(self.results),
                "cases": self.results, "setup_completed": self.setup_completed,
                "setup_config_projection": self.setup_config_projection,
                "raw_status_normalization": False, "parity_qualified": False,
                "requires_pair_comparison": True}

    def public_partial(self):
        return {"matrix_cases": 23, "actual_case_records": len(self.results),
                "cases": self.results, "setup_completed": self.setup_completed,
                "stopped_reason": self.stopped_reason, "parity_qualified": False,
                "setup_config_projection": self.setup_config_projection,
                "current_case": self.current_case,
                "original_case_wire_records": [
                    row for row in self.calls.records
                    if row["case_id"] in {cell["id"] for cell in self.rows}
                ],
                "private_unretired_actor_count": len(self._private_tokens),
                "owned_mount_created_known": self.mount_created_known,
                "unknown_mutation_must_not_be_replayed": True}
