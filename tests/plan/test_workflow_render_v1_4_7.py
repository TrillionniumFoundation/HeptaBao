from __future__ import annotations

import hashlib
import importlib.util
import os
import py_compile
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repaired_renderer", ROOT / "scripts/render_plan_v1_4_7.py")
assert SPEC and SPEC.loader
RENDERER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDERER)


class WorkflowRenderTests(unittest.TestCase):
    def test_frozen_generator_bytes_are_pinned(self) -> None:
        self.assertEqual(RENDERER.BASELINE_SHA256,
                         hashlib.sha256(RENDERER.BASELINE_PATH.read_bytes()).hexdigest())

    def test_complete_workflow_is_reproducible(self) -> None:
        path = ROOT / ".github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml"
        self.assertEqual(path.read_bytes(), RENDERER.workflow_source().encode())

    def test_printf_escape_sequences_stay_inside_yaml_run_block(self) -> None:
        text = RENDERER.workflow_source()
        self.assertIn(r"printf 'source_kind=%s\nsource_sha=%s\ntree=%s\n'", text)
        self.assertNotIn("\nsource_sha=%s\n", text)

    def test_all_generated_shell_steps_parse(self) -> None:
        data = yaml.load(RENDERER.workflow_source(), Loader=yaml.BaseLoader)
        for step in data["jobs"]["validate"]["steps"]:
            if "run" in step:
                with self.subTest(name=step["name"]):
                    result = subprocess.run(["bash", "-n"], input=step["run"], text=True,
                                            capture_output=True, check=False)
                    self.assertEqual(0, result.returncode, result.stderr)

    def test_workflow_keeps_both_source_identities_and_read_only_permission(self) -> None:
        data = yaml.load(RENDERER.workflow_source(), Loader=yaml.BaseLoader)
        self.assertEqual({"pull_request"}, set(data["on"]))
        self.assertEqual({"contents": "read"}, data["permissions"])
        job = data["jobs"]["validate"]
        self.assertEqual(["exact-head", "prospective-merge"], job["strategy"]["matrix"]["source_kind"])
        self.assertNotIn("if", job)
        self.assertNotIn("continue-on-error", job)
        for step in job["steps"]:
            self.assertNotIn("continue-on-error", step)
        self.assertIn("cargo +1.98.0 test --locked --workspace --all-targets", RENDERER.workflow_source())
        self.assertIn("cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings",
                      RENDERER.workflow_source())

    def test_new_generator_and_regression_are_normatively_bound(self) -> None:
        paths = RENDERER.normative_paths(RENDERER.build_truth(ROOT))
        self.assertIn(Path("scripts/_render_plan_v1_4_7_baseline.py"), paths)
        self.assertIn(Path("scripts/render_plan_v1_4_7.py"), paths)
        self.assertIn(Path("tests/plan/test_workflow_render_v1_4_7.py"), paths)

    def test_check_mode_rejects_changes_without_repairing_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "workflow.yml"
            path.write_text(RENDERER.workflow_source().replace("contents: read", "contents: write"))
            before = path.read_bytes()
            with self.assertRaises(SystemExit):
                RENDERER.write_or_compare(root, {Path("workflow.yml"): RENDERER.workflow_source()}, write=False)
            self.assertEqual(before, path.read_bytes())

    def test_missing_or_ambiguous_patch_anchor_fails_closed(self) -> None:
        for value in ("invalid", RENDERER._ORIGINAL_WORKFLOW() * 2):
            with self.subTest(value_length=len(value)), patch.object(RENDERER, "_ORIGINAL_WORKFLOW", return_value=value):
                with self.assertRaises(ValueError):
                    RENDERER.workflow_source()


class FrozenExecutionTests(unittest.TestCase):
    def prepare(self, root: Path) -> tuple[Path, Path, bytes]:
        scripts = root / "scripts"
        scripts.mkdir()
        wrapper = scripts / "render_plan_v1_4_7.py"
        baseline = scripts / "_render_plan_v1_4_7_baseline.py"
        wrapper.write_bytes((ROOT / "scripts/render_plan_v1_4_7.py").read_bytes())
        verified_bytes = RENDERER.BASELINE_PATH.read_bytes()
        baseline.write_bytes(verified_bytes)
        return wrapper, baseline, verified_bytes

    def load(self, wrapper: Path):
        spec = importlib.util.spec_from_file_location("isolated_v147_wrapper", wrapper)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_valid_foreign_timestamp_pyc_cannot_replace_verified_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper, baseline, trusted = self.prepare(Path(temporary))
            foreign = b'raise RuntimeError("foreign cached renderer was executed")\n#'
            self.assertLess(len(foreign), len(trusted))
            foreign += b"x" * (len(trusted) - len(foreign) - 1) + b"\n"
            timestamp = 1_700_000_000
            baseline.write_bytes(foreign)
            os.utime(baseline, (timestamp, timestamp))
            pyc = Path(py_compile.compile(
                str(baseline), doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
            ))
            cached = pyc.read_bytes()
            self.assertEqual((0, timestamp, len(trusted)), struct.unpack("<III", cached[4:16]))
            baseline.write_bytes(trusted)
            os.utime(baseline, (timestamp, timestamp))
            self.assertEqual(RENDERER.BASELINE_SHA256, hashlib.sha256(baseline.read_bytes()).hexdigest())
            module = self.load(wrapper)
            self.assertEqual(RENDERER.workflow_source(), module.workflow_source())
            self.assertEqual(str(baseline), module.BASELINE.__file__)
            self.assertEqual("heptabao_v147_frozen_renderer", module.BASELINE.__name__)
            self.assertFalse(module.BASELINE.CLAIMS["production_authority"])
            self.assertEqual(cached, pyc.read_bytes(), "the cache must be ignored, not rewritten")

    def test_verified_bytes_are_executed_after_source_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper, baseline, trusted = self.prepare(Path(temporary))
            original_read = Path.read_bytes
            reads = []

            def replace_after_read(path: Path) -> bytes:
                data = original_read(path)
                if path == baseline:
                    reads.append(path)
                    path.write_bytes(b'raise RuntimeError("reopened source was executed")\n')
                return data

            with patch.object(Path, "read_bytes", replace_after_read):
                module = self.load(wrapper)
            self.assertEqual([baseline], reads, "read the source exactly once")
            self.assertNotEqual(trusted, baseline.read_bytes())
            self.assertEqual(RENDERER.workflow_source(), module.workflow_source())
            self.assertFalse(module.BASELINE.CLAIMS["production_authority"])

    def test_integrity_failure_precedes_any_baseline_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper, baseline, _ = self.prepare(Path(temporary))
            baseline.write_bytes(b'raise RuntimeError("unverified source was executed")\n')
            with self.assertRaisesRegex(ValueError, "frozen V1.4.7 generator integrity mismatch"):
                self.load(wrapper)


if __name__ == "__main__":
    unittest.main()
