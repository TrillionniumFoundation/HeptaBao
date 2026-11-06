"""Guard-only tests: no current source, product, network or remote execution."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("outer_under_test", HERE / "mac_current_sqlite_data_protection_outer.py")
outer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(outer)


def read(name):
    return json.loads((HERE / "qualification-inputs" / name).read_bytes())


def successful_report():
    flags = ("source_data_write_invoked", "provider_or_sdk_called", "service_or_client_configuration_changed",
             "traffic_cutover_performed", "old_assets_removed", "source_native_sqlite_sidecar_writes_excluded",
             "cross_database_atomic_snapshot_qualified", "all_known_writers_fenced", "source_freshness_after_capture_qualified",
             "current_credential_validity_qualified", "full_host_inventory_qualified", "formal_kv2_qualified",
             "all_clients_and_backups_migrated", "credential_values_or_content_fingerprints_published",
             "source_capture_or_service_cutover_qualified", "automatic_retry", "resume_after_failed_phase_supported")
    value = {k: False for k in flags}
    value.update(schema="heptabao.mac-current-sqlite-recovery-workflow.public.v1", status="passed",
                 phases=[{"phase": phase, "status": "passed", "phase_cap_seconds": 300, "elapsed_seconds": 0.1,
                          "completion_observed_within_original_phase_and_total_deadlines": True}
                         for phase in ("capture", "backup", "restore-verify")],
                 counts={"configured_agents": 5, "captured_database_entries": 9, "logical_snapshot_bytes": 8192,
                         "recovery": {"nonempty_databases": 6, "auth_stores": 5, "absent_families": 3,
                                      "all_declared_files": 19, "plaintext_bytes": 16384}})
    return value


class OuterAdmissionGuards(unittest.TestCase):
    def setUp(self):
        self.saved = {key: getattr(outer, key) for key in ("ENTRY", "WORK_END", "TOTAL_END", "ACTIVE_END", "FIRED",
                                                        "INTERRUPTED", "FAILURE_CLEANUP", "CONTROL", "FS_PROTECTED")}
        outer.ENTRY, outer.WORK_END, outer.TOTAL_END, outer.ACTIVE_END = 100.0, 940.0, 1000.0, 160.0
        outer.FIRED = outer.INTERRUPTED = outer.FAILURE_CLEANUP = outer.FS_PROTECTED = False

    def tearDown(self):
        for key, value in self.saved.items():
            setattr(outer, key, value)

    def test_all_fixed_actual_public_qualification_denominators_validate(self):
        outer.validate_build107(read("mac107-result.public.json"), read("mac107-selection.public.json"))
        outer.validate_dr(read("dr2-result.public.json"), read("dr26-runtime.stdout.original"))
        source = (HERE / "test_mac_current_sqlite_capture.original.py").read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), "0b93d597b9fd525470951cb7b49cdb6707c11fc38b5e42f0d06bcedc7e0395f6")
        outer.validate_env_and_controls(read("environment-result.public.json"), read("controls18-result.public.json"),
                                        read("environment-owned-three.public.json"), read("controls18-owned-one.public.json"), source)

    def test_missing_actual_case_or_unreaped_original_is_rejected(self):
        build, selection = read("mac107-result.public.json"), read("mac107-selection.public.json")
        build["groups"][0]["results"][0]["passed"] -= 1
        with self.assertRaises(outer.Refused):
            outer.validate_build107(build, selection)
        projection = read("dr26-runtime.stdout.original")
        projection["owned_process_custody"]["children"][-1][3] = 0
        with self.assertRaises(outer.Refused):
            outer.validate_dr(read("dr2-result.public.json"), projection)

    def test_private_native_nanosecond_identity_and_payload_both_bind(self):
        raw = b'{"synthetic":true}\n'
        identity = {"dev": 1, "inode": 2, "uid": 501, "gid": 20, "mode": 0o600,
                    "file_type": 0o100000, "nlink": 1, "bytes": len(raw),
                    "mtime_ns": 1793982926986652471, "ctime_ns": 1793982926986652472}
        pin = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
               "version": outer.version(identity), "uid": 501, "mode": 0o600, "nlink": 1}
        outer.validate_private_pin(raw, identity, pin, copy.deepcopy(identity))
        changed = dict(identity, ctime_ns=identity["ctime_ns"] + 1)
        with self.assertRaises(outer.Refused):
            outer.validate_private_pin(raw, changed, pin, changed)
        with self.assertRaises(outer.Refused):
            outer.validate_private_pin(raw.replace(b"true", b"nope"), identity, pin, identity)

    def test_preflight_time_cannot_create_a_fresh_840_second_budget(self):
        core = mock.Mock()
        with mock.patch.object(outer.time, "monotonic", return_value=941.0):
            with self.assertRaises(outer.Refused):
                outer.invoke_workflow({}, core=core)
        core.run_workflow.assert_not_called()

    def test_qualified_core_receives_the_original_outer_entry(self):
        core = mock.Mock()
        core.run_workflow.return_value = successful_report()
        with mock.patch.object(outer.time, "monotonic", return_value=130.0), \
                mock.patch.object(outer.signal, "setitimer") as timer:
            outer.invoke_workflow({}, core=core)
        self.assertEqual(core.run_workflow.call_args.kwargs["start"], 100.0)
        self.assertIs(core.run_workflow.call_args.kwargs["arm"], outer.arm_workflow)
        self.assertEqual(timer.call_args.args[1], 810.0)

    def test_failure_cleanup_or_sticky_interrupt_cannot_become_pass(self):
        class Core:
            def run_workflow(self, plan, *, start, arm):
                arm(start + 900)
                return successful_report()
        with mock.patch.object(outer.time, "monotonic", return_value=130.0), \
                mock.patch.object(outer.signal, "setitimer"):
            with self.assertRaises(outer.Refused):
                outer.invoke_workflow({}, core=Core())
        self.assertTrue(outer.FAILURE_CLEANUP)
        outer.FAILURE_CLEANUP = False
        class InterruptedCore:
            def run_workflow(self, plan, *, start, arm):
                outer.FIRED = True
                return successful_report()
        with mock.patch.object(outer.time, "monotonic", return_value=130.0):
            with self.assertRaises(outer.Refused):
                outer.invoke_workflow({}, core=InterruptedCore())

    def test_private_output_and_alphanumeric_exception_payload_are_not_projected(self):
        report = successful_report()
        report["untrusted_private_payload"] = "secret-source-value"
        safe = outer.safe_workflow_projection(report)
        self.assertNotIn("secret-source-value", json.dumps(safe))
        report.update(status="failed", error="SyntheticSensitiveAlphanumericValue", failed_phase="secret-source-value")
        safe = outer.safe_workflow_projection(report)
        self.assertEqual(safe["error"], "private_failure")
        self.assertEqual(safe["failed_phase"], "private_failure")
        self.assertNotIn("SyntheticSensitive", json.dumps(safe))
        report = successful_report()
        report["formal_kv2_qualified"] = True
        with self.assertRaises(outer.Refused):
            outer.safe_workflow_projection(report)

    def test_native_stdio_partial_setup_failure_restores_both_original_descriptors(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            outer.CONTROL = {"fd": fd}
            before = {n: (os.fstat(n).st_dev, os.fstat(n).st_ino) for n in (1, 2)}
            real_open = os.open
            def controlled_open(path, *args, **kwargs):
                if path == "workflow.stderr.private":
                    raise OSError("fixture-only failure after stdout replacement")
                return real_open(path, *args, **kwargs)
            try:
                with mock.patch.object(outer.os, "open", side_effect=controlled_open):
                    with self.assertRaises(OSError):
                        with outer.private_stdio():
                            self.fail("partial setup must not enter workflow")
                after = {n: (os.fstat(n).st_dev, os.fstat(n).st_ino) for n in (1, 2)}
                self.assertEqual(before, after)
                self.assertFalse(outer.FS_PROTECTED)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
