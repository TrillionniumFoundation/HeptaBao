"""Negative controls for separately scoped 15s-red / 30s-green receipts."""
import importlib.util
import pathlib
import unittest

m = pathlib.Path(__file__).with_name("v6_snapshot_budget_admission.py")
spec = importlib.util.spec_from_file_location("v6_snapshot_budget_admission", m)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

HEAD = "e1c59a5b8284c698b17d16cf43b2f401e35916c2"
TREE = "e4d293bd276d8be6c46b26b046065097254a143b"
BIN = "0bb9be5a6ae44095970552a3e71fc664b3780b45f24c4ad2386c8ee05e629fd5"
FAILLOG = "HBHTTP-RESPONSE-WRITE-FAILURE io_kind=timed_out accepted_plaintext_bytes=9 original_deadline_expired=true"


def record(is_green):
    checks = [{"name": "target-ordinary-unseal", "passed": True}]
    if is_green:
        checks += [{"name": "actual-https-import-into-empty-external-target",
                    "passed": True, "status": 200, "elapsed_ms": 17712}]
        checks += [{"name": name, "passed": True} for name in (
            "target-new-write-next-version", "source-unchanged-during-target-recovery",
            "actual-source-sigkill-reaped", "target-installed-real-v6")]
        checks += [{"name": "target-cold-history-exact-"+str(i), "passed": True}
                   for i in range(1, 67)]
        checks += [{"name": "extra-"+str(i), "passed": True} for i in range(480)]
    return {
        "source_commit": HEAD, "source_tree": TREE, "server_sha256": BIN,
        "versions": 66, "payload_bytes_per_version": 2097152,
        "fixture_payload_generation": "unique per-version SHAKE256 bytes encoded base64; no repeated-block capacity shortcut",
        "production_changed": False, "ha_qualified": False,
        "default_server_timeout_seconds": 15, "server_timeout_overridden": is_green,
        "configured_server_timeout_seconds": 30 if is_green else None,
        "archive_bytes": 139781694, "archive_sha256": "a"*64,
        "expected_history_sha256": {str(i): "b"*64 for i in range(1,67)},
        "source_restored_manifest": "c"*64, "target_seed_manifest": "d"*64,
        "checks": checks,
        "processes": [{"actual_process_closed": True, "exit_code": -15} for _ in range(4)],
        "cleanup_errors": [], "passed": is_green,
        "functional_passed": is_green, "failure": None if is_green else "RemoteDisconnected"
    }


class GateControls(unittest.TestCase):
    def setUp(self):
        self.red = record(False)
        self.green = record(True)

    def validate(self):
        return gate.assess(self.red, self.green, FAILLOG, HEAD, BIN)

    def test_accepted_scoped_configured_only(self):
        self.assertEqual(self.validate()["status"], "SCOPED_CONFIGURED_PASS_DEFAULT_15S_HOLD")

    def reject(self):
        with self.assertRaises(gate.AdmissionError): self.validate()

    def test_red_unexpected_success_cannot_be_relabelled(self):
        self.red["passed"] = True
        self.reject()

    def test_missing_expired_deadline_log_rejected(self):
        with self.assertRaises(gate.AdmissionError):
            gate.assess(self.red, self.green, "no timeout record", HEAD, BIN)

    def test_different_binary_rejected(self):
        self.green["server_sha256"] = "f"*64
        self.reject()

    def test_different_source_rejected(self):
        self.green["source_commit"] = "0"*40
        self.reject()

    def test_green_uses_default_only_is_not_configured(self):
        self.green["server_timeout_overridden"] = False
        self.reject()

    def test_duplicate_mutation_receipts_rejected(self):
        self.green["checks"].append(dict(self.green["checks"][1]))
        self.reject()

    def test_green_failure_rejected(self):
        self.green["passed"] = False
        self.reject()

    def test_unreaped_process_rejected(self):
        self.green["processes"][-1]["actual_process_closed"] = False
        self.reject()

    def test_missing_history_hash_rejected(self):
        del self.green["expected_history_sha256"]["55"]
        self.reject()

    def test_failed_cold_read_rejected(self):
        self.green["checks"][15]["passed"] = False
        self.reject()

    def test_missing_128mib_archive_rejected(self):
        self.green["archive_bytes"] = 10
        self.reject()

    def test_over_budget_write_cannot_be_admitted(self):
        self.green["checks"][1]["elapsed_ms"] = 30001
        self.reject()


if __name__ == "__main__":
    unittest.main()
