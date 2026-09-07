from __future__ import annotations

import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_validator():
    path = ROOT / "scripts/validate_h02_openraft_fault_lab_v1.py"
    spec = importlib.util.spec_from_file_location("h02_fault_source_validator", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class FaultLabSourceBindingTests(unittest.TestCase):
    def test_checked_in_guarded_source_is_semantically_bound(self):
        validator = load_validator()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(validator.main(), 0)

    def test_guard_file_is_required(self):
        validator = load_validator()
        validator.HOSTILE_GUARD = ROOT / "does-not-exist-hostile-snapshot-guard.rs"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(validator.main(), 1)

    def test_guard_semantics_cannot_be_replaced_by_an_unbound_stub(self):
        validator = load_validator()
        original = validator.HOSTILE_GUARD.read_text(encoding="utf-8")
        mutated = original.replace("guarded_state_unchanged", "guarded_state_changed")
        self.assertNotEqual(original, mutated)
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "hostile_snapshot_guard.rs"
            candidate.write_text(mutated, encoding="utf-8")
            validator.HOSTILE_GUARD = candidate
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(validator.main(), 1)

    def test_openraft_probe_uses_inline_format_capture(self):
        source = (ROOT / "probes/h02/openraft-tokio/src/main.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("{CANDIDATE_ID}", source)
        self.assertIn("{case_id}", source)
        self.assertIn("{assertions}", source)
        self.assertNotIn("CANDIDATE_ID, VERSION, PROFILE_ID, seed", source)
        self.assertNotIn("case_id, status, assertions, detail", source)

    def test_obsolete_unguarded_helper_is_absent(self):
        source = (
            ROOT
            / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/cluster.rs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("pub async fn execute_hostile_snapshot_child(", source)


if __name__ == "__main__":
    unittest.main()
