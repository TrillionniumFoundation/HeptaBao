"""Fault-injection tests for bounded ACL policy migration."""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bao_http import BaoError, Response, digest
from migrate_policies import (
    Checkpoint,
    RESERVED_POLICIES,
    list_user_policies,
    snapshot_inventory,
    transfer_policy,
)


def policy_record(name="synthetic-reader", source='path "secret/data/app" { capabilities = ["read"] }'):
    return {"name": name, "source": source, "source_digest": digest(source)}


class FaultTarget:
    namespace = ""

    def __init__(self, fault=None, existing=None):
        self.fault = fault
        self.policies = dict(existing or {})
        self.writes = 0

    def request(self, method, path, payload=None):
        prefix = "/v1/sys/policies/acl/"
        if path == "/v1/sys/policies/acl" and method == "LIST":
            names = sorted({"default", "root", *self.policies})
            return Response(200, {"data": {"keys": names, "policies": names}})
        if not path.startswith(prefix):
            return Response(404, {"errors": ["synthetic"]})
        name = path[len(prefix):]
        if method == "GET":
            if name not in self.policies:
                return Response(404, {"errors": ["synthetic missing"]})
            source = self.policies[name]
            return Response(200, {"data": {"name": name, "policy": source, "rules": source}})
        self.writes += 1
        if self.fault == "before_effect":
            self.fault = None
            raise BaoError("transport_outcome_unknown")
        self.policies[name] = payload["policy"]
        if self.fault == "after_effect":
            self.fault = None
            raise BaoError("transport_outcome_unknown")
        return Response(204, {})


class SnapshotSource(FaultTarget):
    def __init__(self, policies, mutate_after_first_read=False):
        super().__init__(existing=policies)
        self.mutate_after_first_read = mutate_after_first_read
        self.reads = 0

    def request(self, method, path, payload=None):
        response = super().request(method, path, payload)
        if method == "GET" and response.status == 200:
            self.reads += 1
            if self.mutate_after_first_read and self.reads == 1:
                name = path.rsplit("/", 1)[1]
                self.policies[name] += "\n# changed"
        return response


class PolicyMigrationTests(unittest.TestCase):
    def test_committed_but_unacknowledged_write_resumes_without_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            record = policy_record()
            target = FaultTarget("after_effect")
            checkpoint = Checkpoint(path, {"target_cluster": "one"})
            with self.assertRaisesRegex(BaoError, "transport_outcome_unknown"):
                transfer_policy(target, record, checkpoint)
            self.assertEqual(target.writes, 1)
            checkpoint = Checkpoint(path, {"target_cluster": "one"})
            self.assertEqual(transfer_policy(target, record, checkpoint), "copied_and_verified")
            self.assertEqual(target.writes, 1)
            self.assertEqual(transfer_policy(target, record, checkpoint), "already_verified")
            self.assertEqual(target.writes, 1)

    def test_absent_after_unknown_write_is_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            record = policy_record()
            target = FaultTarget("before_effect")
            checkpoint = Checkpoint(path, {"target_cluster": "one"})
            with self.assertRaisesRegex(BaoError, "transport_outcome_unknown"):
                transfer_policy(target, record, checkpoint)
            with self.assertRaisesRegex(BaoError, "authoritative_reconciliation"):
                transfer_policy(target, record, Checkpoint(path, {"target_cluster": "one"}))
            self.assertEqual(target.writes, 1)

    def test_existing_unowned_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            record = policy_record()
            target = FaultTarget(existing={record["name"]: record["source"]})
            checkpoint = Checkpoint(Path(directory) / "checkpoint.json", {})
            with self.assertRaisesRegex(BaoError, "without_owned_checkpoint"):
                transfer_policy(target, record, checkpoint)
            self.assertEqual(target.writes, 0)

    def test_checkpoint_cannot_be_rebound_or_reused_for_changed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            Checkpoint(path, {"target_cluster": "one"})
            with self.assertRaisesRegex(BaoError, "context_mismatch"):
                Checkpoint(path, {"target_cluster": "two"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            record = policy_record()
            target = FaultTarget("after_effect")
            with self.assertRaises(BaoError):
                transfer_policy(target, record, Checkpoint(path, {}))
            changed = copy.deepcopy(record)
            changed["source"] += "\n# mutation"
            changed["source_digest"] = digest(changed["source"])
            with self.assertRaisesRegex(BaoError, "source_changed"):
                transfer_policy(target, changed, Checkpoint(path, {}))
            self.assertEqual(target.writes, 1)

    def test_reserved_policies_are_observed_but_never_inventory_objects(self):
        source = SnapshotSource(
            {
                "synthetic-reader": 'path "secret/data/app" { capabilities = ["read"] }',
                "synthetic-deny": 'path "secret/data/app" { capabilities = ["deny"] }',
            }
        )
        names, reserved = list_user_policies(source)
        self.assertEqual(names, ["synthetic-deny", "synthetic-reader"])
        self.assertEqual(set(reserved), RESERVED_POLICIES)
        records, inventory_digest, observed = snapshot_inventory(source)
        self.assertEqual([row["name"] for row in records], names)
        self.assertEqual(set(observed), RESERVED_POLICIES)
        self.assertRegex(inventory_digest, r"^[0-9a-f]{64}$")

    def test_source_change_during_snapshot_fails_closed(self):
        source = SnapshotSource(
            {"synthetic-reader": 'path "secret/data/app" { capabilities = ["read"] }'},
            mutate_after_first_read=True,
        )
        with self.assertRaisesRegex(BaoError, "changed_during_snapshot"):
            snapshot_inventory(source)


if __name__ == "__main__":
    unittest.main()
