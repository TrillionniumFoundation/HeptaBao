"""Fault and authority-boundary tests for bounded Identity recreation."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bao_http import BaoError, Response
from migrate_identity import (
    Checkpoint,
    normalize_entity,
    normalize_group,
    order_groups,
    transfer_entity,
    transfer_group,
)


def entity_record(source_id="source-e-1", name="alice"):
    return {
        "source_id": source_id,
        "name": name,
        "metadata": {"team": "synthetic"},
        "policies": ["reader"],
        "disabled": False,
    }


def group_record(source_id="source-g-1", name="operators", members=None, children=None):
    return {
        "source_id": source_id,
        "name": name,
        "type": "internal",
        "metadata": {"scope": "synthetic"},
        "policies": ["reader"],
        "member_entity_ids": list(members or []),
        "member_group_ids": list(children or []),
    }


class FaultTarget:
    namespace = ""

    def __init__(self, fault=None):
        self.fault = fault
        self.entities = {}
        self.groups = {}
        self.entity_writes = 0
        self.group_writes = 0
        self._entity_serial = 0
        self._group_serial = 0

    @staticmethod
    def _entity_data(object_id, payload):
        return {
            "id": object_id,
            "name": payload["name"],
            "metadata": dict(payload.get("metadata", {})),
            "policies": list(payload.get("policies", [])),
            "disabled": payload.get("disabled", False),
            "aliases": [],
            "merged_entity_ids": None,
        }

    @staticmethod
    def _group_data(object_id, payload):
        return {
            "id": object_id,
            "name": payload["name"],
            "type": payload.get("type", "internal"),
            "metadata": dict(payload.get("metadata", {})),
            "policies": list(payload.get("policies", [])),
            "member_entity_ids": list(payload.get("member_entity_ids", [])),
            "member_group_ids": list(payload.get("member_group_ids", [])),
        }

    def request(self, method, path, payload=None):
        if path == "/v1/identity/entity/id" and method == "LIST":
            return Response(200, {"data": {"keys": sorted(self.entities)}}) if self.entities else Response(404, {})
        if path == "/v1/identity/group/id" and method == "LIST":
            return Response(200, {"data": {"keys": sorted(self.groups)}}) if self.groups else Response(404, {})
        if path.startswith("/v1/identity/entity/id/") and method == "GET":
            object_id = path.rsplit("/", 1)[1]
            data = self.entities.get(object_id)
            return Response(200, {"data": data}) if data is not None else Response(404, {})
        if path.startswith("/v1/identity/group/id/") and method == "GET":
            object_id = path.rsplit("/", 1)[1]
            data = self.groups.get(object_id)
            return Response(200, {"data": data}) if data is not None else Response(404, {})
        if path == "/v1/identity/entity" and method == "POST":
            self.entity_writes += 1
            if self.fault == "entity_before_effect":
                self.fault = None
                raise BaoError("transport_outcome_unknown")
            self._entity_serial += 1
            object_id = f"target-e-{self._entity_serial}"
            self.entities[object_id] = self._entity_data(object_id, payload)
            if self.fault == "entity_after_effect":
                self.fault = None
                raise BaoError("transport_outcome_unknown")
            return Response(200, {"data": {"id": object_id}})
        if path == "/v1/identity/group" and method == "POST":
            self.group_writes += 1
            if self.fault == "group_before_effect":
                self.fault = None
                raise BaoError("transport_outcome_unknown")
            self._group_serial += 1
            object_id = f"target-g-{self._group_serial}"
            self.groups[object_id] = self._group_data(object_id, payload)
            if self.fault == "group_after_effect":
                self.fault = None
                raise BaoError("transport_outcome_unknown")
            return Response(200, {"data": {"id": object_id}})
        return Response(404, {})


class IdentityMigrationTests(unittest.TestCase):
    def test_committed_but_unacknowledged_entity_create_reconciles_without_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint_path = Path(directory) / "identity-checkpoint.json"
            target = FaultTarget("entity_after_effect")
            record = entity_record()
            checkpoint = Checkpoint(checkpoint_path, {"binding": "one"})
            with self.assertRaisesRegex(BaoError, "transport_outcome_unknown"):
                transfer_entity(target, record, checkpoint)
            self.assertEqual(target.entity_writes, 1)

            resumed = Checkpoint(checkpoint_path, {"binding": "one"})
            self.assertEqual(
                transfer_entity(target, record, resumed),
                "copied_and_verified",
            )
            self.assertEqual(target.entity_writes, 1)
            self.assertEqual(
                transfer_entity(target, record, resumed),
                "already_verified",
            )
            self.assertEqual(target.entity_writes, 1)

    def test_absent_after_unknown_entity_create_is_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint_path = Path(directory) / "identity-checkpoint.json"
            target = FaultTarget("entity_before_effect")
            record = entity_record()
            with self.assertRaisesRegex(BaoError, "transport_outcome_unknown"):
                transfer_entity(target, record, Checkpoint(checkpoint_path, {}))
            with self.assertRaisesRegex(BaoError, "authoritative_reconciliation"):
                transfer_entity(target, record, Checkpoint(checkpoint_path, {}))
            self.assertEqual(target.entity_writes, 1)

    def test_group_memberships_are_rewritten_to_target_ids_and_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Checkpoint(Path(directory) / "identity-checkpoint.json", {})
            target = FaultTarget()
            entity = entity_record()
            self.assertEqual(transfer_entity(target, entity, checkpoint), "copied_and_verified")
            target_entity_id = next(iter(target.entities))
            group = group_record(members=[entity["source_id"]])
            entity_map = {entity["source_id"]: target_entity_id}
            group_map = {}
            self.assertEqual(
                transfer_group(target, group, checkpoint, entity_map, group_map),
                "copied_and_verified",
            )
            target_group = next(iter(target.groups.values()))
            self.assertEqual(target_group["member_entity_ids"], [target_entity_id])
            self.assertNotIn(entity["source_id"], target_group["member_entity_ids"])
            group_map[group["source_id"]] = target_group["id"]
            self.assertEqual(
                transfer_group(target, group, checkpoint, entity_map, group_map),
                "already_verified",
            )
            self.assertEqual(target.group_writes, 1)

    def test_alias_external_group_and_merged_lineage_fail_closed(self):
        with self.assertRaisesRegex(BaoError, "requires_reauthentication"):
            normalize_entity({
                "id": "source-e-1",
                "name": "alice",
                "aliases": [{"id": "alias-1"}],
                "merged_entity_ids": None,
            })
        with self.assertRaisesRegex(BaoError, "explicit_reconciliation"):
            normalize_entity({
                "id": "source-e-1",
                "name": "alice",
                "aliases": [],
                "merged_entity_ids": ["source-e-old"],
            })
        with self.assertRaisesRegex(BaoError, "requires_reauthentication"):
            normalize_group({
                "id": "source-g-1",
                "name": "external",
                "type": "external",
                "member_entity_ids": [],
                "member_group_ids": [],
            })

    def test_nested_group_order_is_child_before_parent_and_cycle_is_rejected(self):
        child = group_record("source-g-child", "child")
        parent = group_record(
            "source-g-parent",
            "parent",
            children=["source-g-child"],
        )
        self.assertEqual(
            [row["source_id"] for row in order_groups([parent, child])],
            ["source-g-child", "source-g-parent"],
        )
        child["member_group_ids"] = ["source-g-parent"]
        with self.assertRaisesRegex(BaoError, "cycle_or_unresolved"):
            order_groups([parent, child])

    def test_checkpoint_binding_cannot_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity-checkpoint.json"
            Checkpoint(path, {"target": "one"})
            with self.assertRaisesRegex(BaoError, "context_mismatch"):
                Checkpoint(path, {"target": "two"})


if __name__ == "__main__":
    unittest.main()
