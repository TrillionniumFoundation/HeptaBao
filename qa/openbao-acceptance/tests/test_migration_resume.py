"""Fault-injection unit tests for the copier; not a fake OpenBao Oracle."""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import BaoError, Response, digest
from migrate_kv2 import Checkpoint, active_history, transfer_record


def fixture_record():
    return {"key": "synthetic/item", "source_metadata": {
                "current_version": 2, "versions": {
                    "1": {"destroyed": False, "deletion_time": ""},
                    "2": {"destroyed": False, "deletion_time": ""}},
                "cas_required": True, "custom_metadata": {"classification": "synthetic"},
                "max_versions": 5, "delete_version_after": "0s"},
            "versions": [{"version": 1, "data": {"value": "one"}}, {"version": 2, "data": {"value": "two"}}],
            "target_metadata": {"cas_required": True, "custom_metadata": {"classification": "synthetic"},
                                "max_versions": 5, "delete_version_after": "0s"}}


class FaultTarget:
    def __init__(self, fault=None):
        self.meta, self.values, self.writes, self.fault = None, [], 0, fault

    def request(self, method, path, payload=None):
        if "/metadata/" in path:
            if method == "GET":
                return Response(404, {"errors": ["synthetic missing"]}) if self.meta is None else Response(200, {"data": copy.deepcopy(self.meta)})
            self.meta = {**copy.deepcopy(payload), "current_version": 0, "versions": {}}
            return Response(204, {})
        if method == "GET":
            version = int(path.split("?version=")[1])
            return Response(200, {"data": {"data": copy.deepcopy(self.values[version - 1]), "metadata": {"version": version}}})
        self.writes += 1
        if self.fault == "before_effect":
            self.fault = None
            raise BaoError("transport_outcome_unknown")
        if payload["options"]["cas"] != len(self.values):
            return Response(400, {"errors": ["synthetic CAS"]})
        self.values.append(copy.deepcopy(payload["data"]))
        version = len(self.values)
        self.meta["current_version"] = version
        self.meta["versions"][str(version)] = {"destroyed": False, "deletion_time": ""}
        if self.fault == "after_effect":
            self.fault = None
            raise BaoError("transport_outcome_unknown")
        return Response(200, {"data": {"version": version}})


class ResumeTests(unittest.TestCase):
    def test_committed_but_unacknowledged_version_is_read_back_not_duplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            record = fixture_record()
            target = FaultTarget("after_effect")
            checkpoint = Checkpoint(path, {"source": "a", "target": "b"})
            with self.assertRaisesRegex(BaoError, "transport_outcome_unknown"):
                transfer_record(target, "secret", record, checkpoint)
            self.assertEqual(len(target.values), 1)
            # A fresh process reloads the durable intent and observes version one.
            checkpoint = Checkpoint(path, {"source": "a", "target": "b"})
            self.assertEqual(transfer_record(target, "secret", record, checkpoint), "copied_and_verified")
            self.assertEqual(target.writes, 2)
            self.assertEqual(target.values, [{"value": "one"}, {"value": "two"}])
            self.assertEqual(transfer_record(target, "secret", record, Checkpoint(path, {"source": "a", "target": "b"})), "already_verified")
            self.assertEqual(target.writes, 2)

    def test_absent_after_timeout_is_not_treated_as_proof_of_noncommit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            target = FaultTarget("before_effect")
            with self.assertRaises(BaoError):
                transfer_record(target, "secret", fixture_record(), Checkpoint(path, {"target": "b"}))
            with self.assertRaisesRegex(BaoError, "authoritative_reconciliation"):
                transfer_record(target, "secret", fixture_record(), Checkpoint(path, {"target": "b"}))
            self.assertEqual(target.writes, 1)
            self.assertEqual(target.values, [])

    def test_checkpoint_cannot_be_rebound_to_a_new_target(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            Checkpoint(path, {"target_cluster": "one"})
            with self.assertRaisesRegex(BaoError, "context_mismatch"):
                Checkpoint(path, {"target_cluster": "two"})

    def test_partial_checkpoint_cannot_claim_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            target = FaultTarget("after_effect")
            checkpoint = Checkpoint(Path(directory) / "cp", {})
            record = fixture_record()
            with self.assertRaises(BaoError):
                transfer_record(target, "secret", record, checkpoint)
            entry = checkpoint.state["objects"][digest(record["key"])]
            entry["completed_version"], entry["phase"] = 1, "complete"
            checkpoint.save()
            with self.assertRaisesRegex(BaoError, "phase_inconsistent"):
                transfer_record(target, "secret", record, checkpoint)
            self.assertEqual(target.writes, 1)

    def test_changed_source_is_rejected_on_resume_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            target = FaultTarget("after_effect")
            record = fixture_record()
            with self.assertRaises(BaoError):
                transfer_record(target, "secret", record, Checkpoint(path, {"target": "b"}))
            changed = copy.deepcopy(record)
            changed["versions"][1]["data"]["value"] = "different"
            with self.assertRaisesRegex(BaoError, "source_changed"):
                transfer_record(target, "secret", changed, Checkpoint(path, {"target": "b"}))
            self.assertEqual(target.writes, 1)

    def test_existing_unowned_target_is_never_silently_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            target = FaultTarget()
            target.meta = {"current_version": 1}
            with self.assertRaisesRegex(BaoError, "without_owned_checkpoint"):
                transfer_record(target, "secret", fixture_record(), Checkpoint(Path(directory) / "cp", {}))
            self.assertEqual(target.writes, 0)

    def test_destroyed_or_pruned_history_is_rejected_instead_of_fabricated(self):
        meta = fixture_record()["source_metadata"]
        meta["versions"]["1"]["destroyed"] = True
        with self.assertRaisesRegex(BaoError, "destroyed"):
            active_history(meta)
        del meta["versions"]["1"]
        with self.assertRaisesRegex(BaoError, "noncontiguous"):
            active_history(meta)


if __name__ == "__main__":
    unittest.main()
