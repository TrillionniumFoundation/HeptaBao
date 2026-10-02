"""Public diagnostics project only fixed failure IDs and numeric HTTP statuses."""
import ast
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core_isolation import public_http_failure_statuses


class PublicHttpFailureDiagnosticsTests(unittest.TestCase):
    def test_reports_only_fixed_cases_sides_and_numeric_statuses(self):
        cases = {
            "candidate": [{"case": "acl.seed", "status": 200, "passed": True}],
            "oracle": [
                {"case": "acl.seed", "status": 503, "passed": False},
                {"case": "mount-discovery270.fixture.data.v2", "status": 404, "passed": False},
            ],
        }
        self.assertEqual(public_http_failure_statuses(cases, {}), [
            {"side": "oracle", "case": "acl.seed", "expected_status": 200, "observed_status": 503},
            {"side": "oracle", "case": "mount-discovery270.fixture.data.v2",
             "expected_status": 200, "observed_status": 404},
        ])

    def test_missing_malformed_and_ambiguous_statuses_are_explicitly_unknown(self):
        for value in [None, "503", "sentinel-private-status", True, False, 99, 600,
                      503.0, {"token": "sentinel-private-token"}, [503]]:
            with self.subTest(value=value):
                rows = [{"case": "acl.seed", "passed": False, "status": value}]
                self.assertEqual(public_http_failure_statuses({"oracle": rows}, {})[0][
                    "observed_status"], "unknown")
        for rows in [[], [{"case": "acl.seed", "passed": False}],
                     [{"case": "acl.seed", "passed": False, "status": 503}] * 2]:
            with self.subTest(rows=rows):
                self.assertEqual(public_http_failure_statuses(
                    {"oracle": rows}, {"oracle": "acl.seed"})[0]["observed_status"], "unknown")

    def test_private_fields_dynamic_identifiers_and_unknown_sides_never_escape(self):
        secret = "sentinel-private-response-token-header"
        cases = {
            "oracle": [
                {"case": "acl.seed", "status": 500, "passed": False,
                 "body": secret, "token": secret, "headers": {"Authorization": secret},
                 "expected_status": secret, "path": secret},
                {"case": secret, "status": 403, "passed": False},
            ],
            secret: [{"case": "acl.seed", "status": 500, "passed": False}],
        }
        before = copy.deepcopy(cases)
        result = public_http_failure_statuses(cases, {secret: secret})
        self.assertEqual(result, [{"side": "oracle", "case": "acl.seed",
                                  "expected_status": 200, "observed_status": 500}])
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(cases, before)

    def test_success_unknown_case_and_non_boolean_failure_are_not_promoted(self):
        for passed in [True, None, 0, "false"]:
            rows = [{"case": "acl.seed", "status": 503, "passed": passed}]
            self.assertEqual(public_http_failure_statuses({"oracle": rows}, {}), [])
        self.assertEqual(public_http_failure_statuses({}, {"oracle": "unlisted"}), [])

    def test_known_failure_without_a_trace_reports_unknown_without_inventing_status(self):
        for cases in [{}, {"oracle": None}, {"oracle": "private-trace"}, None]:
            self.assertEqual(public_http_failure_statuses(cases, {"oracle": "acl.seed"}), [
                {"side": "oracle", "case": "acl.seed", "expected_status": 200,
                 "observed_status": "unknown"}])

    def test_both_actual_final_stdout_expressions_use_only_the_safe_projection(self):
        root = Path(__file__).resolve().parents[1]
        for filename in ["core_isolation.py", "mount_discovery_live.py"]:
            with self.subTest(filename=filename):
                module = ast.parse((root / filename).read_text())
                main = next(node for node in module.body
                            if isinstance(node, ast.FunctionDef) and node.name == "main")
                prints = [node for node in ast.walk(main) if isinstance(node, ast.Expr)
                          and isinstance(node.value, ast.Call)
                          and isinstance(node.value.func, ast.Name)
                          and node.value.func.id == "print"]
                self.assertEqual(len(prints), 1)
                result = {"status": "mismatch", "side_failures": {"oracle": "acl.seed"},
                          "cases": {"oracle": [{"case": "acl.seed", "passed": False,
                                                "status": 503, "body": "private-body",
                                                "headers": "private-header", "token": "private-token"}]}}
                output = io.StringIO()
                # Execute only the existing final print, never fixture setup or requests.
                expression = ast.Module(body=prints, type_ignores=[])
                with contextlib.redirect_stdout(output):
                    exec(compile(expression, filename, "exec"), {
                        "json": json, "result": result, "admitted": False,
                        "public_http_failure_statuses": public_http_failure_statuses,
                    })
                public = json.loads(output.getvalue())
                self.assertEqual(public["http_failure_statuses"][0]["observed_status"], 503)
                self.assertNotIn("private-", output.getvalue())


if __name__ == "__main__":
    unittest.main()
