"""Controller-only synthetic tests: no Runtime, SSH, host scan, or credentials."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


C = module("metadata_gap_v3_controller", HERE / "run_authbus_migration_gap_v3_r1.py")
S = module("metadata_gap_v3_scanner", HERE / C.SCANNER_NAME)
SOURCE = (HERE / C.SCANNER_NAME).read_bytes()
PLAN = C.extract_plan(SOURCE)


def synthetic_receipt(host):
    """Exercise the producer on fake missing metadata, without host path I/O."""
    inspector = S.Inspector(PLAN["hosts"][host], PLAN["bounds"])
    def fake_metadata(path, parents=False):
        return {"path": path, "exists": False, "contents_read": False, "scan_error": "SyntheticMissing"}
    inspector.fs.metadata = fake_metadata
    inspector.fs.children = mock.Mock(side_effect=AssertionError("host enumeration prohibited"))
    inspector.fs.read = mock.Mock(side_effect=AssertionError("host file read prohibited"))
    return inspector.run(host, C.PLAN_SHA256)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="authbus-gap-controller-review-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def operation_fd(self, name="operation"):
        fd = C.make_new_private_directory(str(self.root / name))
        self.addCleanup(os.close, fd)
        return fd

    def test_exact_frozen_source_and_four_host_plan(self):
        planned = C.execution_plan(SOURCE, PLAN)
        self.assertEqual(planned["source"]["sha256"], C.SCANNER_SHA256)
        self.assertEqual(planned["mode"], "plan_only")
        self.assertFalse(planned["remote_called"])
        self.assertEqual([v["host"] for v in planned["hosts"]], ["main", "macbook-pro", "rog", "pocket4"])
        self.assertEqual(sum(len(v["secretrefs"]) for v in PLAN["hosts"].values()), 19)
        self.assertEqual(sum(len(v["backup_runtime"]) for v in PLAN["hosts"].values()), 38)
        self.assertIn("StrictHostKeyChecking=yes", planned["ssh_options"])
        self.assertIn("ProxyCommand=none", planned["ssh_options"])
        self.assertIn("ForwardAgent=no", planned["ssh_options"])
        with self.assertRaises(C.Refused):
            C.extract_plan(SOURCE + b"\n")

    def test_four_synthetic_receipts_bind_exact_original_paths(self):
        for host, _root in C.HOSTS:
            value = synthetic_receipt(host)
            result = C.validate_public_receipt(C.canonical(value), host, PLAN)
            self.assertEqual(result["host_label"], host)
            self.assertEqual(result["execution_bounds"]["bytes_read"], 0)
            self.assertFalse(result["qualification"]["allClientsAndBackupsMigrated"])

    def test_public_validator_rejects_secret_reads_and_qualification_promotion(self):
        cases = []
        value = synthetic_receipt("rog")
        promoted = copy.deepcopy(value)
        promoted["qualification"]["productionCutoverQualified"] = True
        cases.append(promoted)
        opened = copy.deepcopy(value)
        opened["secretref_metadata"][0]["payload_opened"] = True
        cases.append(opened)
        secret_read = copy.deepcopy(value)
        secret_read["execution_bounds"]["content_read_operations"] = [{
            "path": PLAN["hosts"]["rog"]["secretrefs"][0]["path"],
            "profile": "approved_config", "bytes": 1, "header_only": False}]
        secret_read["execution_bounds"]["bytes_read"] = 1
        cases.append(secret_read)
        for case in cases:
            with self.assertRaises(C.Refused):
                C.validate_public_receipt(C.canonical(case), "rog", PLAN)

    def test_readindex_is_not_invented_from_metadata_and_unknown_fields_fail(self):
        value = synthetic_receipt("main")
        value["read_index_qualified"] = True
        with self.assertRaises(C.Refused):
            C.validate_public_receipt(C.canonical(value), "main", PLAN)

    def test_scope_and_original_deadline_cannot_expand(self):
        cases = []
        value = synthetic_receipt("pocket4")
        new_path = copy.deepcopy(value)
        new_path["secretref_metadata"][0]["path"] = "/unapproved/credential.secret"
        cases.append(new_path)
        deadline = copy.deepcopy(value)
        deadline["execution_bounds"]["seconds"] = 60
        cases.append(deadline)
        db_read = copy.deepcopy(value)
        db_read["execution_bounds"]["content_read_operations"] = [{
            "path": PLAN["hosts"]["pocket4"]["backup_runtime"][0]["path"] + "/state.sqlite",
            "profile": "database_magic", "bytes": 17, "header_only": True}]
        db_read["execution_bounds"]["bytes_read"] = 17
        cases.append(db_read)
        for case in cases:
            with self.assertRaises(C.Refused):
                C.validate_public_receipt(C.canonical(case), "pocket4", PLAN)

    def test_bound_hit_is_a_valid_incomplete_metadata_receipt(self):
        value = synthetic_receipt("main")
        value["execution_bounds"]["bounds_hit"] = ["maximum_depth", "per_directory_entries"]
        result = C.validate_public_receipt(C.canonical(value), "main", PLAN)
        summary = C.receipt_summary(result)
        self.assertEqual(summary["bounds_hit"], ["maximum_depth", "per_directory_entries"])
        self.assertIn("SyntheticMissing", summary["item_error_class_counts"])
        self.assertFalse(summary["qualification"]["backupRestoreQualified"])

    def test_private_directory_and_file_never_overwrite_or_follow_symlink(self):
        fd = self.operation_fd()
        info = C.write_new(fd, "new.txt", b"synthetic", 0o600)
        self.assertEqual(info["bytes"], 9)
        self.assertEqual((self.root / "operation" / "new.txt").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            C.write_new(fd, "new.txt", b"replacement")
        with self.assertRaises(FileExistsError):
            C.make_new_private_directory(str(self.root / "operation"))
        (self.root / "linked").symlink_to(self.root / "operation", target_is_directory=True)
        with self.assertRaises(OSError):
            C.make_new_private_directory(str(self.root / "linked" / "child"))

    def test_public_parts_roundtrip_with_individual_fetch_bounds(self):
        import base64
        fd = self.operation_fd()
        raw = C.canonical(synthetic_receipt("main")) * 3
        parts = C.write_receipt_parts(fd, "main", raw)
        decoded = bytearray()
        for file in parts:
            encoded = (self.root / "operation" / file["name"]).read_bytes()
            self.assertLessEqual(len(encoded), 65536)
            part = C.unique_json(encoded)
            payload = base64.b64decode(part["data_base64"], validate=True)
            self.assertEqual(part["offset"], len(decoded))
            self.assertEqual(C.sha(payload), part["decoded_sha256"])
            self.assertEqual(part["receipt_sha256"], C.sha(raw))
            decoded.extend(payload)
        self.assertEqual(bytes(decoded), raw)

    def test_transport_local_pipe_roundtrip_and_no_stderr_emission(self):
        fd = self.operation_fd()
        payload = b"metadata-source-only" * 9000
        command = "import sys,hashlib,json; b=sys.stdin.buffer.read(); sys.stderr.write('synthetic private diagnostic'); print(json.dumps({'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))"
        result = C.run_transport([sys.executable, "-I", "-B", "-c", command], payload, fd, "synthetic", 3)
        self.assertEqual(result["exit_code"], 0)
        self.assertIsNone(result["boundary"])
        self.assertEqual(C.unique_json(result["stdout"])["sha256"], C.sha(payload))
        self.assertNotIn("synthetic private diagnostic", json.dumps({k: v for k, v in result.items() if k != "stdout"}))

    def test_transport_output_cap_and_timeout_close_only_own_child(self):
        fd = self.operation_fd()
        with mock.patch.object(C, "MAX_TRANSPORT_STDOUT_BYTES", 127):
            result = C.run_transport([sys.executable, "-I", "-B", "-c", "print('x'*4096)"], b"{}", fd, "cap", 3)
        self.assertEqual(result["boundary"], "transport_output_bound_outcome_unknown")
        self.assertLessEqual(len(result["stdout"]), 128)
        result = C.run_transport([sys.executable, "-I", "-B", "-c", "import time; time.sleep(3)"], b"{}", fd, "timeout", 0.05)
        self.assertEqual(result["boundary"], "transport_timeout_outcome_unknown")
        self.assertIsNotNone(result["exit_code"])

    def test_host_helper_has_python39_syntax_and_refuses_wrong_owner_before_path_scan(self):
        import base64
        helper = C.helper_program()
        ast.parse(helper, feature_version=(3, 9))
        request = C.canonical({"host": "macbook-pro", "operation_root": dict(C.HOSTS)["macbook-pro"],
                               "scanner_base64": base64.b64encode(SOURCE).decode("ascii")})
        result = subprocess.run([sys.executable, "-I", "-B", "-c", helper], input=request,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        self.assertEqual(result.returncode, 2)
        envelope = C.unique_json(result.stdout)
        self.assertEqual(envelope["reason"], "host_owner_context_mismatch")
        self.assertFalse(envelope["qualification"]["legacyCleanupQualified"])
        self.assertEqual(result.stderr, b"")

    def test_duplicate_json_and_changed_original_receipt_are_rejected(self):
        with self.assertRaises(C.Refused):
            C.unique_json(b'{"schema":"one","schema":"two"}')
        value = synthetic_receipt("rog")
        value["source_binding"] = copy.deepcopy(value["source_binding"])
        value["source_binding"]["original_metadata_receipt"]["sha256"] = "0" * 64
        with self.assertRaises(C.Refused):
            C.validate_public_receipt(C.canonical(value), "rog", PLAN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
