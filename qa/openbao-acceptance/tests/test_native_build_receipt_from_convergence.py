import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

QA = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("normal107_native_projection",
                                            QA / "native_build_receipt_from_convergence.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
EVIDENCE = QA / "evidence/authbus-fleet-closure-20261106-r2/mac-4bde9-canonical"


class CompletedBuildProjectionTests(unittest.TestCase):
    def setUp(self):
        self.receipt = json.loads((EVIDENCE / "result.public.json").read_bytes())
        selection_raw = (EVIDENCE / "test-selection.public.json").read_bytes()
        self.selection = json.loads(selection_raw)
        self.selection_sha = hashlib.sha256(selection_raw).hexdigest()
        self.terminal = json.loads((EVIDENCE / "runtime-terminal.original.json").read_bytes())
        self.validator = (QA / "kv2_native_fresh_directory_dr_live.py").read_bytes()
        self.assertEqual(hashlib.sha256(self.validator).hexdigest(), MODULE.VALIDATOR_SHA)

    def validate(self, receipt=None, terminal=None):
        return MODULE.original_validation(receipt or self.receipt, self.selection, self.selection_sha,
            terminal or self.terminal, "1a1b116ba98-fc05-75a6", self.validator)

    def test_complete_original_mac107_receipt_is_admitted_as_provenance_only(self):
        value = self.validate()
        self.assertEqual(value["passed_cases"], 107)
        self.assertEqual(value["source_commit"], MODULE.PRODUCT)

    def test_bound_mac_and_linux_source_fields_are_exact_and_unambiguous(self):
        expected = self.selection["execution_source"]
        self.assertEqual(MODULE.original_source_path(self.selection, self.receipt), expected)
        linux_shape = dict(self.selection)
        del linux_shape["execution_source"]
        linux_shape["fresh_clean_source"] = {"path": expected}
        self.assertEqual(MODULE.original_source_path(linux_shape, self.receipt), expected)
        both = dict(self.selection, fresh_clean_source={"path": expected})
        self.assertEqual(MODULE.original_source_path(both, self.receipt), expected)
        for altered in (
                dict(both, fresh_clean_source={"path": "/different/producer"}),
                dict(linux_shape, fresh_clean_source={}),
                dict(linux_shape, fresh_clean_source={"path": "relative/source"}),
                {"schema": self.selection["schema"]}):
            with self.subTest(selection=altered.get("fresh_clean_source")), self.assertRaises(MODULE.Refused):
                MODULE.original_source_path(altered, self.receipt)
        changed = copy.deepcopy(self.receipt)
        changed["artifacts"]["heptabao-seed"]["cargo_source_entry"] = "/other/src/bin/heptabao-seed.rs"
        with self.assertRaises(MODULE.Refused):
            MODULE.original_source_path(self.selection, changed)

    def test_failed_or_lost_original_terminal_cannot_qualify_a_pass_receipt(self):
        for field, value in (("exit_code", 1), ("exit_code", False), ("timed_out", True),
                             ("output_durable", False), ("job_id", "different-job")):
            with self.subTest(field=field), self.assertRaises(MODULE.Refused):
                self.validate(terminal=dict(self.terminal, **{field: value}))
        lost = copy.deepcopy(self.terminal)
        lost["log_bytes"]["stdout"]["stored"] -= 1
        with self.assertRaises(MODULE.Refused):
            self.validate(terminal=lost)

    def test_partial_counts_and_changed_original_build_cannot_be_projected(self):
        for field, value in (("passed_cases", 106), ("source_commit", "0" * 40),
                             ("source_and_artifacts_unchanged", False)):
            with self.subTest(field=field), self.assertRaises(MODULE.Refused):
                self.validate(receipt=dict(self.receipt, **{field: value}))
        failed = copy.deepcopy(self.receipt)
        step = next(row for row in failed["steps"] if row["step"] == "13-normal-release-build")
        step["exit_code"] = 101
        with self.assertRaises(MODULE.Refused):
            self.validate(receipt=failed)
        changed = copy.deepcopy(self.receipt)
        changed["artifacts"]["heptabao-server"]["cargo_features"].append("fixture-only")
        with self.assertRaises(MODULE.Refused):
            self.validate(receipt=changed)

    def test_binary_header_must_match_host_and_executable_kind(self):
        macho = bytearray(64)
        macho[:4] = bytes.fromhex("cffaedfe")
        struct.pack_into("<I", macho, 4, 0x0100000C)
        struct.pack_into("<I", macho, 12, 2)
        elf = bytearray(64)
        elf[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", elf, 16, 3, 62)
        self.assertEqual(MODULE.actual_abi(macho, "Darwin", "arm64"), "aarch64-apple-darwin")
        self.assertEqual(MODULE.actual_abi(elf, "Linux", "x86_64"), "x86_64-unknown-linux-gnu")
        for data, system, machine in ((macho, "Linux", "x86_64"), (elf, "Darwin", "arm64"),
                                      (b"not-an-executable", "Linux", "x86_64")):
            with self.subTest(system=system), self.assertRaises(MODULE.Refused):
                MODULE.actual_abi(data, system, machine)
        struct.pack_into("<I", macho, 12, 6)
        with self.assertRaises(MODULE.Refused):
            MODULE.actual_abi(macho, "Darwin", "arm64")


if __name__ == "__main__":
    unittest.main()
