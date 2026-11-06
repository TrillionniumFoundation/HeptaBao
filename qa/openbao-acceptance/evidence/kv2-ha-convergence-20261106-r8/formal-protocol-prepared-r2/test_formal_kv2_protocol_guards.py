"""Narrow draft guards. No service, TLS connection, provider or real data.

These exercise refusal boundaries, not a simulated full acceptance workflow.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest

from lifecycle_contract import Deadline, EndpointHandle, RestoreTarget
from formal_kv2_protocol import (
    Plan, Refused, Session, WireReply, load_pure_helpers, fixed_json, projection_rows,
    export_matches, storage_witness,
)


class NoNetwork:
    def __init__(self, response=None):
        self.calls = []
        self.response = response

    def exchange(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.response is None:
            raise TimeoutError("synthetic_only_private_exception_marker")
        return self.response


class ProtocolBoundaryGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = load_pure_helpers(Path(os.environ["HB_PURE_QA_REFERENCE_DIR"]))

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.events = self.root / "events"
        self.events.mkdir(mode=0o700)
        self.ca = self.root / "ca.pem"
        self.h.private_write(self.ca, b"synthetic-test-ca")
        self.endpoint = EndpointHandle("https://127.0.0.1:8401", self.ca,
            self.root / "root.token", "a" * 64, self.root / "data", "test-source", "gui/501")
        now = time.monotonic()
        self.plan = Plan(self.endpoint, None, None, "business", "canary", "history",
                         self.events, self.root / "staging", self.root / "keys",
                         Deadline(now, now + 10, now + 15, "synthetic_guard"))

    def session(self, wire):
        session = Session(self.plan, wire, self.h)
        session.bind_business([("row-a", {"synthetic": "row"})])
        return session

    def test_unknown_mutation_stops_later_operation_without_retry(self):
        wire = NoNetwork()
        session = self.session(wire)
        with self.assertRaises(TimeoutError):
            session.call("once", "source", "POST", "business/data/row-a",
                         {"data": {"synthetic": "row"}, "options": {"cas": 0}})
        self.assertTrue(session.unknown)
        self.assertTrue(session.stopped)
        with self.assertRaises(Refused):
            session.call("different-label", "source", "GET", "sys/health")
        self.assertEqual(len(wire.calls), 1)
        self.assertTrue(all("synthetic_only_private_exception_marker" not in p.read_text()
                            for p in self.events.iterdir()))

    def test_known_denial_stops_without_becoming_unknown_or_retry(self):
        response = WireReply(403, b'{"errors":["synthetic denial"]}', self.endpoint.origin,
            self.endpoint.leaf_sha256, hashlib.sha256(self.ca.read_bytes()).hexdigest(), 0.001,
            {"pid": 1, "exec_admitted": True, "returncode": 0, "original_wait_completed": True,
             "original_wait_count": 1, "no_live_members_before_reap": True, "gaps": []}, {})
        wire = NoNetwork(response)
        session = self.session(wire)
        with self.assertRaises(Refused):
            session.call("once", "source", "GET", "sys/health")
        self.assertTrue(session.stopped)
        self.assertFalse(session.unknown)
        with self.assertRaises(Refused):
            session.call("later", "source", "POST", "business/data/row-a",
                         {"data": {"synthetic": "row"}, "options": {"cas": 0}})
        self.assertEqual(len(wire.calls), 1)

    def test_wrong_endpoint_restore_or_business_write_never_dispatches(self):
        wire = NoNetwork()
        session = self.session(wire)
        with self.assertRaises(Refused):
            session.call("bad-restore", "source", "POST", "sys/storage/raft/snapshot",
                         upload=self.root / "never-opened.snapshot")
        with self.assertRaises(Refused):
            session.call("wrong-label", "other", "POST", "business/data/row-a",
                         {"data": {"synthetic": "row"}, "options": {"cas": 0}})
        target = RestoreTarget(self.endpoint, None, {}, self.root / "seed-proof", False,
                               self.root / "target-proof")
        with self.assertRaises(Refused):
            session.add_restore(target)
        session.allowed["restore"] = EndpointHandle("https://127.0.0.1:8402", self.ca,
            self.root / "root.token", "b" * 64, self.root / "fresh-data", "test-restore", "gui/501")
        with self.assertRaises(Refused):
            session.call("wrong-business-write", "restore", "POST", "business/data/row-a",
                         {"data": {"synthetic": "row"}, "options": {"cas": 0}})
        with self.assertRaises(Refused):
            session.call("business-destroy", "source", "POST", "business/destroy/row-a", {"versions": [1]})
        self.assertEqual(wire.calls, [])

    def test_recovery_scope_refuses_reactivation_and_all_source_writes(self):
        wire = NoNetwork()
        session = self.session(wire)
        session.recovery_only = True
        requests = [
            ("sys/storage/native-v6/activate", {}),
            ("business/data/row-a", {"data": {"synthetic": "row"}, "options": {"cas": 0}}),
            ("canary/data/history", {"data": {"canary_generation": 4}, "options": {"cas": 3}}),
        ]
        for index, (path, body) in enumerate(requests):
            with self.subTest(path=path), self.assertRaises(Refused):
                session.call("forbidden-" + str(index), "source", "POST", path, body)
        self.assertEqual(wire.calls, [])

    def projection(self):
        groups = [
            {"auth_profile_store": [["primary", "{\"synthetic\":1}", 1], ["secondary", "{}", 2]],
             "auth_profile_state": [["state", "{\"synthetic\":true}", 3]]},
            {"auth_profile_store": [["different", "null", 4]], "auth_profile_state": []},
        ]
        capture = {"schema": "heptabao.closed-current-sqlite-capture.v1", "ok": True,
                   "configured_agent_count": 2, "database_rows": []}
        rows = []
        for slot, group in enumerate(groups):
            capture["database_rows"].append({"kind": "agent", "agent": "agent-" + str(slot),
                "present": True, "auth_rows_sha256": hashlib.sha256(fixed_json(group)).hexdigest(),
                "auth_store_rows": len(group["auth_profile_store"]),
                "auth_state_rows": len(group["auth_profile_state"])})
            for table, values in group.items():
                prefix = "store" if table == "auth_profile_store" else "state"
                for value in values:
                    index = len(rows)
                    rows.append({"record_id": "row-" + str(index), "agent_slot": slot, "table": table,
                        "row_fields": dict(zip((prefix + "_key", prefix + "_json", "updated_at"), value)),
                        "kv_mount": "business", "kv_key": "row-" + str(index)})
        return capture, {"schema": "heptabao.current-sqlite-allrows-to-kv2.private.v1",
                         "capture_sha256": "c" * 64, "rows": rows}

    def test_allrows_refuses_missing_nonprimary_state_agent_or_duplicate_key(self):
        capture, projection = self.projection()
        actual, counts = projection_rows(capture, projection, "business", "c" * 64)
        self.assertEqual(len(actual), 4)
        self.assertEqual(counts["auth_profile_store_rows"], 3)
        self.assertEqual(counts["auth_profile_state_rows"], 1)
        for missing_index in (1, 2, 3):
            changed = deepcopy(projection)
            del changed["rows"][missing_index]
            with self.subTest(missing=missing_index), self.assertRaises(Refused):
                projection_rows(capture, changed, "business", "c" * 64)
        changed = deepcopy(projection)
        changed["rows"][1]["kv_key"] = changed["rows"][0]["kv_key"]
        with self.assertRaises(Refused):
            projection_rows(capture, changed, "business", "c" * 64)

    def history(self):
        config = {"max_versions": 0, "cas_required": True,
                  "metadata_cas_required": True, "delete_version_after": "0s"}
        metadata = dict(config, created_time="2026-11-06T00:00:00Z", updated_time="2026-11-06T00:00:02Z",
                        current_version=3, oldest_version=0, current_metadata_version=1,
                        custom_metadata={"synthetic": "yes"}, versions={})
        payloads = {1: {"synthetic": 1}, 2: None, 3: {"synthetic": 3}}
        versions = {}
        for version in (1, 2, 3):
            meta = {"created_time": "2026-11-06T00:00:00Z", "deletion_time": "gone" if version == 1 else "",
                    "destroyed": version == 2}
            metadata["versions"][str(version)] = meta
            versions[str(version)] = dict(meta, source_deletion_time="", data=payloads[version])
        entry = deepcopy(metadata)
        entry["versions"] = versions
        return ({"schema": "openbao270-kv2-lossless-v1", "config": config, "entries": {"history": entry}},
                config, {"history": {"metadata": metadata}}, {"history": payloads})

    def test_export_rejects_missing_destroyed_version_or_soft_deleted_payload(self):
        bundle, config, observed, payloads = self.history()
        export_matches(bundle, config, observed, payloads, self.h)
        missing = deepcopy(bundle)
        del missing["entries"]["history"]["versions"]["2"]
        with self.assertRaises(Refused):
            export_matches(missing, config, observed, payloads, self.h)
        changed = deepcopy(bundle)
        changed["entries"]["history"]["versions"]["1"]["data"] = None
        with self.assertRaises(Refused):
            export_matches(changed, config, observed, payloads, self.h)
        extra = deepcopy(bundle)
        extra["entries"]["unobserved"] = extra["entries"]["history"]
        with self.assertRaises(Refused):
            export_matches(extra, config, observed, payloads, self.h)

    def test_dynamic_raw_witness_keeps_actual_mount_and_key_binding(self):
        metadata = {"created_time": "synthetic", "deletion_time": "", "destroyed": False}
        payload = {"synthetic": "only"}
        raw = self.h.canonical(payload)
        value = dict(metadata, schema="heptabao-native-kv2-storage-witness-v1",
            canonical_profile="heptabao-lossless-json-v1", mount="business", path="row-a", version=1,
            mount_incarnation=2, source_root_sha256="d" * 64, source_publication_generation=7,
            payload_present=True, payload_canonical_bytes=len(raw), payload_canonical_sha256=hashlib.sha256(raw).hexdigest())
        storage_witness({"data": value}, "business", "row-a", 1, metadata, payload, self.h)
        for field, wrong in (("mount", "other"), ("path", "other"), ("version", True)):
            changed = dict(value, **{field: wrong})
            with self.subTest(field=field), self.assertRaises(Refused):
                storage_witness({"data": changed}, "business", "row-a", 1, metadata, payload, self.h)


if __name__ == "__main__":
    unittest.main(verbosity=2)
