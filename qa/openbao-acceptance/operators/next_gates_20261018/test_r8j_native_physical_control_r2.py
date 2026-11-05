#!/usr/bin/env python3
"""Local pure binding checks; no physical run, SSH, Cargo, or candidate secrets."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("physical_control_r2_under_test",
                                             ROOT / "r8j_native_physical_control_r2.py")
r2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r2)


class R2PhysicalControllerBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.freeze = r2.load_freezer()
        cls.matrix = json.loads((ROOT / "local-r8-evidence/r8j-mac-native-matrix.json").read_bytes())
        cls.linux = json.loads((ROOT / "local-r8-evidence/r8j-linux-native-build-receipt.json").read_bytes())
        cls.mac = json.loads((ROOT / "local-r8-evidence/r8j-mac-native-build-receipt.json").read_bytes())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="physical-r2-binding-")
        self.parent = Path(self.temp.name).resolve()
        self.qa = self.parent / "native-r8j-physical89-02-qa"
        self.qa.mkdir(mode=0o700)
        self.source = self.parent / "source-r8j"
        self.source.mkdir(mode=0o700)
        self.manifest = {"files": dict(r2.QA_FILES)}
        harness = "qa/openbao-acceptance/native_v6_ha_multihost_live.py"
        self.manifest["files"][harness] = r2.ORIGINAL_HARNESS_SHA256
        for relative, expected in r2.QA_FILES.items():
            source = ROOT / "HeptaBao" / relative
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), expected)
            destination = self.qa / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o600)
        self.args = argparse.Namespace(
            qa_root=self.qa, source_root=self.source,
            node=[alias + ",100.64.0." + str(i) + "," + path
                  for i, (alias, path) in enumerate(r2.NODE_ROOTS.items(), 1)],
            work_root=self.parent / "native-r8j-physical89-02-controller",
            plan_out=self.parent / "r8j-native-physical89-02-plan.json",
            report_out=self.parent / "r8j-native-physical89-02-controller-report.json",
            linux_build=ROOT / "local-r8-evidence/r8j-linux-native-build-receipt.json",
            linux_build_sha256=r2.BUILD_BINDINGS["x86_64-unknown-linux-gnu"]["receipt_sha256"],
            mac_build=ROOT / "local-r8-evidence/r8j-mac-native-build-receipt.json",
            mac_build_sha256=r2.BUILD_BINDINGS["aarch64-apple-darwin"]["receipt_sha256"],
            allow_private_lan=False, api_port=46230, raft_port=46231,
            mesh_local_port_base=55200, mesh_reverse_port_base=55300,
            mesh_api_port_base=55400)
        self.saved_modules = {name: sys.modules.pop(name, None) for name, _ in r2.QA_MODULES}

    def tearDown(self):
        for name, old in self.saved_modules.items():
            sys.modules.pop(name, None)
            if old is not None:
                sys.modules[name] = old
        self.temp.cleanup()

    def frozen(self):
        return r2.verify_qa(self.qa, self.source, self.manifest, self.freeze)

    def fixture(self):
        return r2.load_qa(self.qa, self.frozen())

    def test_exact_dependency_closure_loads_from_verified_bytes(self):
        fixture = self.fixture()
        self.assertEqual(len(fixture.REQUIRED_CHECKS), 89)
        self.assertEqual((fixture.REQUEST_SECONDS, fixture.NATIVE_ADMISSION_SECONDS,
                          fixture.TARGET_BYTES), (15, 8, 35651584))
        for name, relative in r2.QA_MODULES:
            self.assertEqual(Path(sys.modules[name].__file__), self.qa / relative)

    def test_each_helper_and_harness_corruption_rejected_before_import(self):
        for relative in r2.QA_FILES:
            with self.subTest(relative=relative):
                path = self.qa / relative
                original = path.read_bytes()
                path.write_bytes(original + b"# changed bytes")
                with self.assertRaisesRegex(RuntimeError, "pinned_file_bytes_changed"):
                    self.frozen()
                self.assertFalse(any(name in sys.modules for name, _ in r2.QA_MODULES))
                path.write_bytes(original)

    def test_missing_extra_symlink_and_hardlink_are_rejected(self):
        relative = "qa/openbao-acceptance/fixture_mounts.py"
        target = self.qa / relative
        original = target.read_bytes()
        target.unlink()
        with self.assertRaisesRegex(RuntimeError, "file_set_mismatch"):
            self.frozen()
        target.write_bytes(original)
        target.chmod(0o600)
        extra = self.qa / "tools/unpinned.py"
        extra.write_bytes(b"")
        with self.assertRaisesRegex(RuntimeError, "unexpected_file"):
            self.frozen()
        extra.unlink()
        target.unlink()
        target.symlink_to(ROOT / "HeptaBao" / relative)
        with self.assertRaisesRegex(RuntimeError, "pinned_file_path_or_digest_invalid"):
            self.frozen()
        target.unlink()
        copied = self.parent / "extra-link"
        copied.write_bytes(original)
        copied.chmod(0o600)
        os.link(copied, target)
        with self.assertRaisesRegex(RuntimeError, "pinned_file_owner_or_shape"):
            self.frozen()

    def test_original_source_tree_cannot_be_relabelled_as_qa_overlay(self):
        with self.assertRaisesRegex(RuntimeError, "separate_from_binary_source"):
            r2.verify_qa(self.qa, self.qa, self.manifest, self.freeze)
        with self.assertRaisesRegex(RuntimeError, "separate_from_binary_source"):
            r2.verify_qa(self.qa, self.parent, self.manifest, self.freeze)
        for relative in r2.QA_FILES:
            with self.subTest(relative=relative):
                changed = copy.deepcopy(self.manifest)
                changed["files"][relative] = "0" * 64
                with self.assertRaisesRegex(RuntimeError, "original_helper_source_binding"):
                    r2.verify_qa(self.qa, self.source, changed, self.freeze)

    def test_import_cache_cannot_override_a_pinned_helper(self):
        sys.modules["physical_ha_peer_preflight"] = types.ModuleType("substitution")
        with self.assertRaisesRegex(RuntimeError, "module_cache_must_be_empty"):
            r2.load_qa(self.qa, self.frozen())

    def test_original_receipt_bytes_and_full_30_case_matrix_are_bound(self):
        for path, expected in (
            (self.args.linux_build, self.args.linux_build_sha256),
            (self.args.mac_build, self.args.mac_build_sha256),
            (ROOT / "local-r8-evidence/r8j-mac-native-matrix.json", r2.MATRIX_SHA256),
        ):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)
        r2.verify_matrix(self.matrix, self.freeze)
        self.assertEqual(sum(r2.MATRIX_CASES.values()), 30)
        for mutate in (
            lambda v: v.update(source_unchanged_after_tests=False),
            lambda v: v.update(source_files=2581),
            lambda v: v["cases"].pop(),
            lambda v: v["cases"][0].update(exit_code=1),
            lambda v: v["cases"][0].update(exit_code=False),
            lambda v: v["cases"][0].update(summaries=["test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2702 filtered out;"]),
        ):
            changed = copy.deepcopy(self.matrix)
            mutate(changed)
            with self.assertRaises(RuntimeError):
                r2.verify_matrix(changed, self.freeze)

    def test_both_original_native_builds_reject_abi_binary_or_provenance_substitution(self):
        fixture = self.fixture()
        for receipt, abi in ((self.linux, "x86_64-unknown-linux-gnu"),
                             (self.mac, "aarch64-apple-darwin")):
            r2.verify_build(receipt, abi, fixture, self.freeze)
            for key, replacement in (
                ("binary_sha256", "0" * 64), ("native_abi", "wrong"),
                ("source_tree", "0" * 40), ("source_files", 2581),
                ("freezer_sha256", "0" * 64), ("binary_has_independent_inode", False),
                ("binary_path", receipt["binary_path"] + "-replacement"),
            ):
                with self.subTest(abi=abi, key=key):
                    changed = copy.deepcopy(receipt)
                    changed[key] = replacement
                    with self.assertRaises(RuntimeError):
                        r2.verify_build(changed, abi, fixture, self.freeze)

    def test_only_attempt_02_roots_and_original_binary_roots_survive_command(self):
        fixture = self.fixture()
        r2.verify_attempt_roots(self.args)
        wire_args = copy.deepcopy(self.args)
        wire_args.linux_build = Path("/home/qian-qi/heptabao-next-gates-20261017/native-r8j-linux-freeze-01/native-build-r8j.json")
        wire_args.mac_build = Path("/home/qian-qi/heptabao-next-gates-20261017/r8j-mac-native-build-receipt.json")
        command = r2.prepare_command(wire_args, self.linux, self.mac, self.freeze)
        with mock.patch.object(fixture.base, "ssh", side_effect=AssertionError("network forbidden")), \
             mock.patch.object(fixture.subprocess, "Popen", side_effect=AssertionError("spawn forbidden")):
            fixture.parsed_arguments(command)
        self.assertFalse(self.args.work_root.exists())
        self.assertIn("local:" + self.linux["binary_path"], command)
        for alias, root in r2.NODE_ROOTS.items():
            self.assertTrue(any(value.startswith(alias + ",") and value.endswith("," + root)
                                for value in command))
        changed = copy.deepcopy(self.args)
        changed.node[0] = changed.node[0].replace("physical89-02-node1", "physical89-01-node1")
        with self.assertRaisesRegex(RuntimeError, "attempt_02_node_roots"):
            r2.verify_attempt_roots(changed)
        changed = copy.deepcopy(self.args)
        changed.work_root = self.parent / "native-r8j-physical89-01-controller"
        with self.assertRaisesRegex(RuntimeError, "attempt_02_controller_paths"):
            r2.verify_attempt_roots(changed)

    def test_plan_and_report_expose_separate_qa_and_binary_bindings(self):
        fields = r2.binding_fields(self.args, self.freeze)
        self.assertEqual(fields["binary_source_commit"], "4f0bacd59be21d204783d69b500d2a19ef6af55a")
        self.assertEqual(fields["binary_source_tree"], "9514b66b8cda559938e135d6c7c5b9606296fd4a")
        self.assertFalse(fields["qa_directory_is_binary_source_tree"])
        self.assertEqual(fields["qa_files_sha256"], r2.QA_FILES)
        self.assertFalse(fields["production_cutover"])
        self.assertFalse(fields["backup_qualified"])

    def test_summary_requires_exact_89_checks_and_new_runner_hash(self):
        fixture = self.fixture()
        summary = {
            "status": "passed", "source_commit": self.freeze.COMMIT, "source_tree": self.freeze.TREE,
            "runner_sha256": r2.QA_FILES["qa/openbao-acceptance/native_v6_ha_multihost_live.py"],
            "required_check_count": 89, "observed_check_count": 89, "passed_check_count": 89,
            "checks": [{"case": name, "passed": True} for name in sorted(fixture.REQUIRED_CHECKS)],
        }
        path = self.parent / "summary.json"
        def project(value):
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            return r2.summary_projection(path, fixture, self.freeze)
        self.assertTrue(project(summary)["fixture_exact_89_passed"])
        for mutate in (
            lambda v: v["checks"].pop(),
            lambda v: v["checks"][0].update(passed=False),
            lambda v: v["checks"][0].update(case=v["checks"][1]["case"]),
            lambda v: v.update(runner_sha256=r2.ORIGINAL_HARNESS_SHA256),
            lambda v: v.update(observed_check_count=18, passed_check_count=18, status="failed"),
        ):
            changed = copy.deepcopy(summary)
            mutate(changed)
            self.assertFalse(project(changed)["fixture_exact_89_passed"])

    def test_execute_is_opt_in_and_receipt_permissions_are_strict(self):
        command = []
        for name in ("source-root", "manifest", "matrix", "linux-build", "mac-build",
                     "qa-root", "work-root", "plan-out", "report-out"):
            command += ["--" + name, str(self.parent / name)]
        for name in ("matrix-sha256", "linux-build-sha256", "mac-build-sha256"):
            command += ["--" + name, "0" * 64]
        command += ["--node", self.args.node[0], "--allow-private-tailnet"]
        self.assertFalse(r2.parsed_arguments(command).execute)
        self.assertTrue(r2.parsed_arguments(command + ["--execute"]).execute)
        path = self.parent / "receipt.json"
        raw = b'{"private":true}'
        path.write_bytes(raw)
        path.chmod(0o644)
        expected = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "not_private"):
            r2.bound_json(path, expected, self.freeze)
        path.chmod(0o600)
        self.assertEqual(r2.bound_json(path, expected, self.freeze), {"private": True})


if __name__ == "__main__":
    unittest.main()

