"""Meaningful local controls only: synthetic owned SQLite, no product or provider."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("current_capture", HERE / "mac_current_sqlite_capture.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CurrentCaptureControls(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o077)
        self.tmp = tempfile.TemporaryDirectory(prefix="heptabao-owned-synthetic-capture-")
        self.base = Path(self.tmp.name).resolve()
        self.source = self.base / "source"
        self.work = self.base / "work"
        self.restores = self.base / "restores"
        self.keys = self.base / "keys"
        for path in (self.source, self.work, self.keys, self.restores):
            path.mkdir(mode=0o700)
        archive_parent = os.environ.get("HEPTABAO_CAPTURE_TEST_ARCHIVE_PARENT")
        if archive_parent is not None:
            archive_parent = str(m.directory(archive_parent))
        else:
            self.assertEqual(sys.platform, "linux", "Darwin requires a fixed private archive fixture parent")
            archive_parent = "/dev/shm"
        self.archives_tmp = tempfile.TemporaryDirectory(prefix="heptabao-owned-synthetic-archive-", dir=archive_parent)
        self.archives = Path(self.archives_tmp.name).resolve()
        self.assertNotEqual(self.keys.stat().st_dev, self.archives.stat().st_dev)
        self.assertNotEqual(self.source.stat().st_dev, self.archives.stat().st_dev)
        self.agents = ["main", "secondary"]
        for agent in self.agents:
            directory = self.source / "agents" / agent / "agent"
            directory.mkdir(mode=0o700, parents=True)
            self.make_db(directory / "openclaw-agent.sqlite", auth=True)
        (self.source / "state").mkdir(mode=0o700)
        self.make_db(self.source / "state/openclaw.sqlite", auth=False)
        (self.source / "authbus").mkdir(mode=0o700)
        m.private_new(self.source / "authbus/bad-refresh-quarantine.json", b'{"generation":1}')
        self.config = {"agents": {"list": [{"id": agent} for agent in self.agents]}}
        m.private_new(self.source / "openclaw.json", m.encoded(self.config))
        self.capture_plan = {
            "schema": m.SCHEMA, "phase": "capture", "budget_seconds": 10,
            "source_root": str(self.source), "source_root_identity": self.dirpin(self.source),
            "source_config_sha256": m.digest(m.encoded(self.config)), "agents": self.agents,
            "capture_parent": str(self.work), "capture_parent_identity": self.dirpin(self.work),
            "capture_name": "capture-r1", "maximum_total_bytes": 4 * 1024**2,
            "maximum_database_bytes": 2 * 1024**2,
        }
        self.workflow = {
            "schema": m.WORKFLOW_SCHEMA, "overall_budget_seconds": 120,
            "capture": self.capture_plan,
            "backup": {"budget_seconds": 10, "archive_parent": str(self.archives),
                       "archive_name": "encrypted-r1", "key_parent": str(self.keys),
                       "key_name": "key-r1"},
            "restore": {"budget_seconds": 10, "restore_parent": str(self.restores),
                        "restore_name": "restore-r1"},
        }

    def tearDown(self):
        self.tmp.cleanup()
        self.archives_tmp.cleanup()
        os.umask(self.mask)

    @staticmethod
    def dirpin(path):
        info = path.stat()
        return {"dev": info.st_dev, "inode": info.st_ino,
                "uid": info.st_uid, "mode": info.st_mode & 0o777}

    @staticmethod
    def make_db(path, auth):
        conn = sqlite3.connect(path)
        try:
            conn.execute("CREATE TABLE business_records(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
            conn.execute("INSERT INTO business_records VALUES(1,?)", (b"whole-database-not-only-auth\x00\xff",))
            if auth:
                conn.execute("CREATE TABLE auth_profile_store(store_key TEXT PRIMARY KEY, store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)")
                conn.execute("CREATE TABLE auth_profile_state(state_key TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at INTEGER NOT NULL)")
                conn.execute("INSERT INTO auth_profile_store VALUES(?,?,?)",
                             ("primary", '{"profiles":{"synthetic-profile":{"token":"synthetic-private-value"}}}', 3))
                conn.execute("INSERT INTO auth_profile_state VALUES(?,?,?)", ("primary", '{"generation":7}', 5))
            conn.commit()
        finally:
            conn.close()
        path.chmod(0o600)

    def captured(self):
        m.validate_plan(self.capture_plan, fixture=True)
        return m.capture(self.capture_plan, time.monotonic() + 10)

    def archive(self):
        root, value = self.captured()
        pin = m.digest((root / "capture.private.json").read_bytes())
        plan = {"schema": m.SCHEMA, "phase": "backup", "capture_root": str(root),
                "capture_sha256": pin, **self.workflow["backup"]}
        archive, _ = m.backup(plan, time.monotonic() + 10)
        restore = {"schema": m.SCHEMA, "phase": "restore-verify",
                   "archive_root": str(archive), "capture_sha256": pin,
                   "key_file": str(self.keys / "key-r1/recovery.key"), **self.workflow["restore"]}
        return root, value, archive, restore

    def test_full_workflow_restores_non_auth_tables_all_auth_rows_and_absences(self):
        original = self.source / "agents/main/agent/openclaw-agent.sqlite"
        before = m.digest(original.read_bytes())
        result = m.run_workflow(self.workflow, fixture=True)
        self.assertEqual(result["status"], "passed")
        self.assertEqual([row["phase"] for row in result["phases"]], ["capture", "backup", "restore-verify"])
        self.assertEqual(result["counts"]["recovery"]["nonempty_databases"], 3)
        self.assertEqual(result["counts"]["recovery"]["auth_stores"], 2)
        self.assertEqual(result["counts"]["recovery"]["absent_families"], 3)
        self.assertEqual(m.digest(original.read_bytes()), before)
        restored = self.restores / "restore-r1/baseline-state/agents/main/agent/openclaw-agent.sqlite"
        baseline = self.work / "capture-r1/baseline-state/agents/main/agent/openclaw-agent.sqlite"
        self.assertEqual(m.digest(restored.read_bytes()), m.digest(baseline.read_bytes()))
        conn = sqlite3.connect(restored.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            self.assertEqual(conn.execute("SELECT payload FROM business_records").fetchall(),
                             [(b"whole-database-not-only-auth\x00\xff",)])
        finally:
            conn.close()
        self.assertTrue(all(not Path(str(restored) + suffix).exists() for suffix in m.FAMILY[1:]))
        self.assertFalse(result["formal_kv2_qualified"])
        self.assertFalse(result["all_known_writers_fenced"])
        self.assertFalse(result["cross_database_atomic_snapshot_qualified"])

    def test_live_wal_transaction_is_captured_from_real_separate_owned_writer(self):
        database = self.source / "agents/main/agent/openclaw-agent.sqlite"
        script = (
            "import sqlite3,sys\n"
            "c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA journal_mode=WAL'); "
            "c.execute('PRAGMA wal_autocheckpoint=0'); "
            "c.execute('INSERT INTO business_records VALUES(2,?)',(b\"uncheckpointed-wal-fixture\",)); "
            "c.commit(); print('ready',flush=True); sys.stdin.buffer.read(1); c.close()\n"
        )
        child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", script, str(database)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
        try:
            self.assertEqual(child.stdout.readline(), b"ready\n")
            self.assertTrue(Path(str(database) + "-wal").stat().st_size > 0)
            root, report = self.captured()
            row = next(row for row in report["database_rows"] if row["agent"] == "main")
            self.assertTrue(row["source_family_before"]["-wal"]["present"])
            copy_path = root / "baseline-state/agents/main/agent/openclaw-agent.sqlite"
            conn = sqlite3.connect(copy_path.as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                self.assertEqual(conn.execute("SELECT payload FROM business_records WHERE id=2").fetchall(),
                                 [(b"uncheckpointed-wal-fixture",)])
            finally:
                conn.close()
            self.assertFalse(report["external_writer_fence_claimed"])
        finally:
            try:
                child.communicate(input=b"x", timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0)

    def test_absent_main_with_stray_wal_is_refused_before_output_creation(self):
        stray = self.source / "state/openclaw-quarantine.sqlite-wal"
        m.private_new(stray, b"owned-orphan-wal")
        with self.assertRaisesRegex(m.Refused, "absent_main_with_present_sqlite_sidecar"):
            self.captured()
        self.assertFalse((self.work / "capture-r1").exists())

    def test_present_transport_requires_a_separate_current_operation_fence(self):
        parent = self.source / "authbus/production-transport"
        parent.mkdir(mode=0o700)
        self.make_db(parent / "state.sqlite", auth=False)
        with self.assertRaisesRegex(m.Refused, "present_transport_requires"):
            self.captured()
        self.assertFalse((self.work / "capture-r1").exists())

    def test_zero_length_main_requires_absent_sidecars_at_both_capture_boundaries(self):
        database = self.source / "state/openclaw-quarantine.sqlite"
        m.private_new(database, b"")
        for suffix in m.FAMILY[1:]:
            with self.subTest(existing_sidecar=suffix):
                sidecar = Path(str(database) + suffix)
                m.private_new(sidecar, b"owned-uninterpreted-sidecar")
                try:
                    with self.assertRaisesRegex(m.Refused, "empty_main_with_present_sqlite_sidecar"):
                        self.captured()
                    self.assertFalse((self.work / "capture-r1").exists())
                finally:
                    sidecar.unlink()
        root, report = self.captured()
        row = next(item for item in report["database_rows"]
                   if item["relative_path"] == "state/openclaw-quarantine.sqlite")
        self.assertTrue(row["empty_database_marker"])
        self.assertEqual((root / "baseline-state/state/openclaw-quarantine.sqlite").read_bytes(), b"")
        self.capture_plan["capture_name"] = "capture-late-sidecar-r1"
        original_copy = m.copy_closed
        def late_sidecar(source, target, end):
            value = original_copy(source, target, end)
            if source.name == database.name:
                m.private_new(Path(str(database) + "-wal"), b"owned-late-sidecar")
            return value
        with mock.patch.object(m, "copy_closed", side_effect=late_sidecar):
            with self.assertRaisesRegex(m.Refused, "declared_empty_database_family_changed"):
                self.captured()
        self.assertFalse((self.work / "capture-late-sidecar-r1/capture.private.json").exists())

    def test_missing_configured_agent_is_rejected_before_any_copy(self):
        self.capture_plan["agents"] = ["main"]
        with self.assertRaisesRegex(m.Refused, "complete_current_configured_agent_set"):
            self.captured()
        self.assertFalse((self.work / "capture-r1").exists())

    def test_changed_safety_cohort_keeps_partial_copies_unqualified(self):
        original_copy = m.copy_closed
        state = self.source / "authbus/bad-refresh-quarantine.json"
        changed = False
        def observed_copy(*args, **kwargs):
            nonlocal changed
            value = original_copy(*args, **kwargs)
            if not changed:
                state.write_bytes(b'{"generation":2}')
                changed = True
            return value
        with mock.patch.object(m, "copy_closed", side_effect=observed_copy):
            with self.assertRaisesRegex(m.Refused, "complete_safety_cohort_changed"):
                self.captured()
        self.assertTrue((self.work / "capture-r1/baseline-state").is_dir())
        self.assertFalse((self.work / "capture-r1/capture.private.json").exists())

    def test_hardlinked_source_database_is_refused(self):
        source = self.source / "agents/main/agent/openclaw-agent.sqlite"
        os.link(source, self.base / "owned-alias.sqlite")
        with self.assertRaisesRegex(m.Refused, "source_database_custody"):
            self.captured()

    def test_changed_non_auth_table_blocks_whole_database_backup(self):
        root, _ = self.captured()
        baseline = root / "baseline-state/agents/main/agent/openclaw-agent.sqlite"
        conn = sqlite3.connect(baseline)
        try:
            conn.execute("UPDATE business_records SET payload=?", (b"changed-only-business-table",))
            conn.commit()
        finally:
            conn.close()
        plan = {"schema": m.SCHEMA, "phase": "backup", "capture_root": str(root),
                "capture_sha256": m.digest((root / "capture.private.json").read_bytes()),
                **self.workflow["backup"]}
        with self.assertRaisesRegex(m.Refused, "closed_backup_input_bytes_changed"):
            m.backup(plan, time.monotonic() + 10)
        self.assertTrue((self.archives / "encrypted-r1").is_dir())
        self.assertFalse((self.archives / "encrypted-r1/manifest.fernet").exists())

    def test_missing_agent_cannot_be_hidden_by_rewriting_capture_denominator(self):
        root, original = self.captured()
        value = copy.deepcopy(original)
        value["configured_agent_count"] = 1
        value["database_rows"] = [row for row in value["database_rows"] if row["agent"] != "secondary"]
        value["files"] = [row for row in value["files"] if "/agents/secondary/" not in row["path"]]
        raw = m.encoded(value)
        (root / "capture.private.json").write_bytes(raw)
        with self.assertRaisesRegex(m.Refused, "original_configuration_all_agents_required"):
            m.capture_inputs(root, m.digest(raw), time.monotonic() + 10)

    def test_wrong_key_and_corrupt_archive_never_create_restore_destination(self):
        from cryptography.fernet import Fernet, InvalidToken
        _root, _value, archive, plan = self.archive()
        wrong = self.keys / "wrong"
        wrong.mkdir(mode=0o700)
        m.private_new(wrong / "recovery.key", Fernet.generate_key())
        invalid = dict(plan, key_file=str(wrong / "recovery.key"), restore_name="wrong-key")
        with self.assertRaises(InvalidToken):
            m.restore_verify(invalid, time.monotonic() + 10)
        self.assertFalse((self.restores / "wrong-key").exists())
        chunk = next((archive / "chunks").iterdir())
        original = chunk.read_bytes()
        chunk.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(m.Refused, "ciphertext_bytes_binding"):
            m.restore_verify(dict(plan, restore_name="corrupt"), time.monotonic() + 10)
        self.assertFalse((self.restores / "corrupt").exists())

    def test_same_filesystem_key_rejects_then_whole_workflow_cannot_resume(self):
        key_parent = self.archives / "same-device-key-parent"
        key_parent.mkdir(mode=0o700)
        plan = copy.deepcopy(self.workflow)
        plan["backup"]["key_parent"] = str(key_parent)
        result = m.run_workflow(plan, fixture=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_phase"], "admission")
        self.assertEqual(result["error"], "recovery_key_requires_independent_filesystem")
        self.assertEqual(result["phases"], [])
        self.assertFalse((self.work / "capture-r1").exists())
        self.assertFalse((key_parent / "key-r1").exists())
        self.assertFalse((self.restores / "restore-r1").exists())
        original_backup = m.backup
        def changed_before_backup(value, end, owner):
            database = Path(value["capture_root"]) / "baseline-state/agents/main/agent/openclaw-agent.sqlite"
            conn = sqlite3.connect(database)
            try:
                conn.execute("UPDATE business_records SET payload=?", (b"failure-boundary-fixture",))
                conn.commit()
            finally:
                conn.close()
            return original_backup(value, end, owner)
        with mock.patch.object(m, "backup", side_effect=changed_before_backup):
            result = m.run_workflow(self.workflow, fixture=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_phase"], "backup")
        self.assertEqual(result["error"], "closed_backup_input_bytes_changed")
        self.assertEqual([row["phase"] for row in result["phases"]], ["capture"])
        first_failure = (self.work / "capture-r1/workflow-failure.public.json").read_bytes()
        again = m.run_workflow(self.workflow, fixture=True)
        self.assertEqual(again["status"], "failed")
        self.assertEqual(again["error"], "create_only_directory")
        self.assertEqual((self.work / "capture-r1/workflow-failure.public.json").read_bytes(), first_failure)

    def test_same_source_or_capture_filesystem_archive_refuses_even_with_other_filesystem_key(self):
        source_disk_archive = self.base / "source-disk-archive"
        external_key = self.archives / "external-key-parent"
        for path in (source_disk_archive, external_key):
            path.mkdir(mode=0o700)
        plan = copy.deepcopy(self.workflow)
        plan["backup"].update(archive_parent=str(source_disk_archive), key_parent=str(external_key))
        self.assertNotEqual(source_disk_archive.stat().st_dev, external_key.stat().st_dev)
        self.assertEqual(source_disk_archive.stat().st_dev, self.source.stat().st_dev)
        result = m.run_workflow(plan, fixture=True)
        self.assertEqual(result["error"], "backup_requires_filesystem_distinct_from_source_and_capture")
        self.assertEqual(result["failed_phase"], "admission")
        self.assertFalse((self.work / "capture-r1").exists())
        captured, _value = self.captured()
        backup_plan = {"schema": m.SCHEMA, "phase": "backup", "capture_root": str(captured),
                       "capture_sha256": m.digest((captured / "capture.private.json").read_bytes()),
                       **plan["backup"]}
        with self.assertRaisesRegex(m.Refused, "backup_requires_filesystem_distinct_from_source_and_capture"):
            m.backup(backup_plan, time.monotonic() + 10)
        self.assertFalse((source_disk_archive / "encrypted-r1").exists())
        self.assertFalse((external_key / "key-r1").exists())
        external_capture_parent = self.archives / "capture-parent"
        external_capture_parent.mkdir(mode=0o700)
        external_plan = copy.deepcopy(self.workflow)
        external_plan["capture"].update(capture_parent=str(external_capture_parent),
                                        capture_parent_identity=self.dirpin(external_capture_parent))
        self.assertNotEqual(self.archives.stat().st_dev, self.source.stat().st_dev)
        result = m.run_workflow(external_plan, fixture=True)
        self.assertEqual(result["error"], "backup_requires_filesystem_distinct_from_source_and_capture")
        external_capture, _ = m.capture(external_plan["capture"], time.monotonic() + 10)
        backup_plan.update(capture_root=str(external_capture),
                           capture_sha256=m.digest((external_capture / "capture.private.json").read_bytes()),
                           **self.workflow["backup"])
        with self.assertRaisesRegex(m.Refused, "backup_requires_filesystem_distinct_from_source_and_capture"):
            m.backup(backup_plan, time.monotonic() + 10)
        self.assertFalse((self.archives / "encrypted-r1").exists())

    def test_backup_refuses_replaced_original_source_directory_identity(self):
        captured, _ = self.captured()
        plan = {"schema": m.SCHEMA, "phase": "backup", "capture_root": str(captured),
                "capture_sha256": m.digest((captured / "capture.private.json").read_bytes()),
                **self.workflow["backup"]}
        original = self.source.rename(self.base / "source-retained-original")
        self.source.mkdir(mode=0o700)
        self.assertNotEqual(self.source.stat().st_ino, original.stat().st_ino)
        with self.assertRaisesRegex(m.Refused, "bound_directory_identity_changed"):
            m.backup(plan, time.monotonic() + 10)
        self.assertFalse((self.archives / "encrypted-r1").exists())
        self.assertFalse((self.keys / "key-r1").exists())

    def test_fresh_restore_uses_authenticated_origin_without_original_source_or_capture_paths(self):
        captured, _value, _archive, plan = self.archive()
        self.source.rename(self.base / "source-retained-original")
        captured.rename(self.work / "capture-retained-original")
        self.assertFalse(self.source.exists())
        self.assertFalse(captured.exists())
        restored, result = m.restore_verify(plan, time.monotonic() + 10)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["full_restored_file_bytes_and_declared_absences_exact"])
        self.assertTrue((restored / "baseline-state/agents/main/agent/openclaw-agent.sqlite").is_file())

    def test_original_total_deadline_does_not_start_capture_or_reset_on_failure(self):
        arm = mock.Mock()
        start = time.monotonic() - 61
        with mock.patch.object(m, "capture", side_effect=AssertionError("must_not_start")):
            result = m.run_workflow(self.workflow, fixture=True, start=start, arm=arm)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_phase"], "admission")
        self.assertEqual(result["phases"], [])
        self.assertFalse((self.work / "capture-r1").exists())
        self.assertTrue(all(call.args[0] == start + 120 for call in arm.call_args_list))

    def test_unavailable_encryption_refuses_before_source_configuration_or_copy(self):
        with mock.patch.dict(sys.modules, {"cryptography.fernet": None}), \
             mock.patch.object(m, "capture", side_effect=AssertionError("capture_must_not_start")), \
             mock.patch.object(m, "read_private", side_effect=AssertionError("source_must_not_open")):
            result = m.run_workflow(self.workflow, fixture=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_phase"], "admission")
        self.assertEqual(result["error"], "ModuleNotFoundError")
        self.assertFalse((self.work / "capture-r1").exists())
        self.assertFalse((self.archives / "encrypted-r1").exists())

    def test_public_result_never_exports_source_names_hashes_or_credential_values(self):
        result = m.run_workflow(self.workflow, fixture=True)
        self.assertEqual(result["status"], "passed")
        raw = json.dumps(result)
        for forbidden in (str(self.source), "synthetic-private-value", "synthetic-profile", "sha256", "secondary"):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(m.safe_error(m.Refused("private token = do-not-print")), "private_workflow_failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)

