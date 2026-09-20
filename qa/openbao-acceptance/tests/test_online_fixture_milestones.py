"""The real publication entry points must reject incomplete or interrupted evidence."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import kubernetes_online
import online_auth_ha
import radius_renewal_ha

MODULES = (online_auth_ha, kubernetes_online, radius_renewal_ha)
BASE_HA = ["new_leader_after_sigkill", "quorum_loss_write_denied",
           "all_three_rejoined_after_quorum_recovery"]


class MilestonePublicationTests(unittest.TestCase):
    def publish(self, module, rows, *, interrupted=False, inherited=None):
        def observed_run(binary, root, checks, *args, **kwargs):
            checks.extend(rows)
            if module is online_auth_ha:
                args[0].extend(BASE_HA if inherited is None else inherited)
            elif module is radius_renewal_ha:
                args[1].extend(sorted(module.REQUIRED_BOOTSTRAP) if inherited is None else inherited)
            if interrupted:
                raise RuntimeError("sensitive_exception_must_not_be_reported")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.parent.chmod(0o700)
            with patch.object(sys, "argv", [module.__name__, "--binary", __file__, "--output", str(output)]), \
                 patch.object(module, "source_identity", return_value={"test_identity": True}), \
                 patch.object(module, "run", side_effect=observed_run), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = module.main()
            raw = output.read_text()
            self.assertNotIn("sensitive_exception_must_not_be_reported", raw)
            return code, json.loads(raw)

    @staticmethod
    def rows(module):
        return [{"case": name, "passed": True} for name in sorted(module.REQUIRED_CASES)]

    def test_every_named_phase_is_required_even_with_terminal_complete(self):
        for module in MODULES:
            for missing in module.REQUIRED_CASES:
                with self.subTest(fixture=module.__name__, missing=missing):
                    rows = [row for row in self.rows(module) if row["case"] != missing]
                    code, report = self.publish(module, rows)
                    self.assertEqual((code, report["status"]), (1, "failed"))

    def test_additional_successful_observations_do_not_invalidate_complete_run(self):
        for module in MODULES:
            with self.subTest(fixture=module.__name__):
                rows = self.rows(module) + [{"case": "new_independent_safety_check", "passed": True}]
                code, report = self.publish(module, rows)
                self.assertEqual((code, report["status"], report["failure"]), (0, "passed", None))

    def test_duplicate_and_nonboolean_results_reject(self):
        for module in MODULES:
            rows = self.rows(module)
            malformed = [rows + [rows[0]], rows + [{"case": "extra", "passed": 1}],
                         rows + [{"case": "extra", "passed": "true"}],
                         rows + [{"case": "extra", "passed": False}]]
            for values in malformed:
                with self.subTest(fixture=module.__name__, last=values[-1]):
                    code, report = self.publish(module, values)
                    self.assertEqual((code, report["status"]), (1, "failed"))

    def test_exception_after_all_successes_cannot_publish_pass(self):
        for module in MODULES:
            with self.subTest(fixture=module.__name__):
                code, report = self.publish(module, self.rows(module), interrupted=True)
                self.assertEqual((code, report["status"], report["failure"]),
                                 (1, "failed", "fixture_RuntimeError"))

    def test_ha_base_phases_are_required_but_additions_are_allowed(self):
        for module, required in ((online_auth_ha, BASE_HA),
                                 (radius_renewal_ha, sorted(radius_renewal_ha.REQUIRED_BOOTSTRAP))):
            for missing in required:
                with self.subTest(fixture=module.__name__, missing=missing):
                    code, report = self.publish(module, self.rows(module),
                                                inherited=[name for name in required if name != missing])
                    self.assertEqual((code, report["status"]), (1, "failed"))
            code, _ = self.publish(module, self.rows(module), inherited=required + [required[0]])
            self.assertEqual(code, 1)
            code, _ = self.publish(module, self.rows(module), inherited=required + ["new_bootstrap_observation"])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
