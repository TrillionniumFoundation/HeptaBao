"""Real child controls for intentional fixture crashes; no OpenBao or network."""
import ast
import io
from pathlib import Path
import select
import signal
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import official_openbao_launcher as launcher
import renewal_cleanup


class OracleCrashControls(unittest.TestCase):
    def live_child(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; print('ready', flush=True); sys.stdin.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )

        def close():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()

        self.addCleanup(close)
        self.assertTrue(select.select([child.stdout], [], [], 5)[0])
        self.assertEqual(child.stdout.readline(), b"ready\n")
        oracle = {"process": child, "log": io.BytesIO()}
        self.addCleanup(oracle["log"].close)
        return oracle, child

    def test_deliberate_crash_reaps_original_then_normal_cleanup_is_safe(self):
        oracle, child = self.live_child()
        log = oracle["log"]
        receipt = launcher.crash_oracle_for_restart(oracle)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertIsNone(oracle["process"])
        self.assertTrue(log.closed)
        self.assertIsNone(oracle["log"])
        self.assertEqual(receipt["status"], "passed")
        self.assertTrue(receipt["original_wait_completed"])
        launcher.stop_oracle(oracle)
        self.assertEqual(child.wait(timeout=0), -signal.SIGKILL)

    def test_normal_stop_still_rejects_a_killed_original(self):
        oracle, child = self.live_child()
        child.kill()
        child.wait(timeout=5)
        with self.assertRaisesRegex(launcher.owned_process.OwnedFailure,
                                    "owned_standalone_shutdown_code"):
            launcher.stop_oracle(oracle)
        self.assertIs(oracle["process"], child)
        self.assertTrue(oracle["log"].closed)

    def test_already_exited_child_is_not_reclassified_as_intentional_crash(self):
        for expected in (0, -signal.SIGKILL):
            with self.subTest(expected=expected):
                oracle, child = self.live_child()
                if expected == 0:
                    child.stdin.close()
                else:
                    child.kill()
                self.assertEqual(child.wait(timeout=5), expected)
                with self.assertRaisesRegex(launcher.BaoError,
                                            "official_oracle_crash_requires_live_original"):
                    launcher.crash_oracle_for_restart(oracle)
                self.assertIsNone(oracle["process"])
                self.assertEqual(oracle["process_lifecycle"][-1]["status"], "failed")
                self.assertTrue(oracle["process_lifecycle"][-1]["original_wait_completed"])

    def test_missing_handle_never_becomes_a_crash(self):
        with self.assertRaisesRegex(launcher.BaoError,
                                    "official_oracle_crash_requires_live_original"):
            launcher.crash_oracle_for_restart({})

    def test_wrong_owner_result_does_not_clear_handle_or_permit_restart(self):
        oracle, child = self.live_child()
        log = oracle["log"]
        with patch.object(launcher.owned_process, "stop", return_value=0) as stop:
            with self.assertRaisesRegex(launcher.BaoError, "official_oracle_crash_exit_code"):
                launcher.crash_oracle_for_restart(oracle)
        stop.assert_called_once_with(child, action="KILL", timeout=5)
        self.assertIs(oracle["process"], child)
        self.assertTrue(log.closed)
        self.assertFalse(oracle["process_lifecycle"][-1]["original_wait_completed"])

    def test_stop_error_preserved_after_log_close(self):
        oracle, child = self.live_child()
        log = oracle["log"]
        with patch.object(launcher.owned_process, "stop",
                          side_effect=launcher.BaoError("synthetic_wait_failure")):
            with self.assertRaisesRegex(launcher.BaoError, "synthetic_wait_failure"):
                launcher.crash_oracle_for_restart(oracle)
        self.assertIs(oracle["process"], child)
        self.assertTrue(log.closed)


class RenewalCleanupReportControls(unittest.TestCase):
    def actual_cleanup(self, script, original_result, *, fail):
        path = Path(__file__).resolve().parents[1] / script
        tree = ast.parse(path.read_text(), filename=str(path))
        main = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        outer = next(node for node in main.body
                     if isinstance(node, ast.Try) and node.finalbody)
        # Execute the runner's actual cleanup call through the shared helper.
        # Source observation and report publication are separate callbacks;
        # their full runner behavior is covered by the lifecycle regressions.
        block = [node for node in outer.finalbody
                 if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                 and isinstance(node.value.func, ast.Name)
                 and node.value.func.id == "finish_fixture"]
        self.assertEqual(len(block), 1)
        calls = []

        def close(name):
            calls.append(name)
            if fail and name == "candidate":
                raise RuntimeError("private detail must not enter report")

        scope = {
            "instance": SimpleNamespace(stop=lambda: close("candidate")),
            "oracle": {"root": "owned-oracle-root"},
            "responders": [SimpleNamespace(close=lambda: close("responder"))],
            "issuers": [SimpleNamespace(close=lambda: close("issuer"))],
            "root": "owned-profile-root", "private_root": "owned-profile-root",
            "stop_oracle": lambda _: close("oracle"),
            "finish_fixture": renewal_cleanup.finish_fixture,
            "validate_final": lambda: close("validate"),
            "publish_final": lambda value: close("publish"),
            "result": original_result,
        }
        with patch.object(renewal_cleanup.shutil, "rmtree", side_effect=close):
            exec(compile(ast.Module(body=block, type_ignores=[]), str(path), "exec"), scope)
        provider = "responder" if script.startswith("radius") else "issuer"
        expected = ["candidate", "oracle", provider, "owned-oracle-root"]
        if not fail:
            expected.append("owned-profile-root")
        self.assertEqual(calls, expected + ["validate", "publish"])
        self.assertEqual(original_result["retained_private_roots"],
                         ["owned-profile-root"] if fail else [])

    def test_cleanup_error_retains_business_failure_and_attempts_all_resources(self):
        for script in ("radius_renewal_live.py", "kubernetes_renewal_live.py"):
            with self.subTest(script=script):
                result = {"status": "mismatch", "safe_failure_code": "original_business_failure",
                          "side_failures": {"candidate": "original_denial"}}
                self.actual_cleanup(script, result, fail=True)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["status_before_cleanup"], "mismatch")
                self.assertEqual(result["safe_failure_code"], "original_business_failure")
                self.assertEqual(result["side_failures"], {"candidate": "original_denial"})
                self.assertEqual(result["cleanup_failures"], [
                    {"stage": "candidate_stop", "exception_class": "RuntimeError"}])
                self.assertEqual(result["cleanup_failure_class"], "RuntimeError")
                self.assertNotIn("private detail", repr(result))

    def test_cleanup_error_cannot_publish_business_pass_as_run_pass(self):
        for script in ("radius_renewal_live.py", "kubernetes_renewal_live.py"):
            with self.subTest(script=script):
                result = {"status": "passed"}
                self.actual_cleanup(script, result, fail=True)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["status_before_cleanup"], "passed")
                self.assertEqual(result["safe_failure_code"], "fixture_cleanup_or_final_observation_failed")

    def test_successful_cleanup_preserves_business_pass_and_records_retirement(self):
        for script in ("radius_renewal_live.py", "kubernetes_renewal_live.py"):
            with self.subTest(script=script):
                result = {"status": "passed"}
                self.actual_cleanup(script, result, fail=False)
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["cleanup_failures"], [])
                self.assertEqual(result["retained_private_roots"], [])
                self.assertNotIn("safe_failure_code", result)


if __name__ == "__main__":
    unittest.main()
