"""Synthetic seed diagnostics; no native differential or qualification evidence."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch, sentinel

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import BaoError
import response_wrapping as wrapping


PRIVATE = "SENTINEL-private-body-header-token-url-path"
SEED_PATH = "/v1/wrapping-differential/data/item"


def response(status, body=None):
    return SimpleNamespace(status=status, body={} if body is None else body,
                           headers={"private-header": PRIVATE})


def wrapped(token, ttl=60, **extra):
    return {"wrap_info": {"token": PRIVATE + token, "ttl": ttl,
                          "creation_path": "sys/wrapping/wrap",
                          "creation_time": "synthetic-created-at",
                          "accessor": PRIVATE + token + "-accessor", **extra}}


def prefix_script():
    """The real ordered successful prefix, ending at the existing mount gate."""
    payload = {"value": "synthetic-wrapped-secret", "entity_id": "arbitrary-user-data",
               "nested": {"count": 3}}
    return [
        ("POST", "sys/wrapping/wrap", response(200, wrapped("first"))),
        ("POST", "sys/wrapping/lookup", response(200, {"data": {
            "creation_path": "sys/wrapping/wrap", "creation_ttl": 60,
            "creation_time": "synthetic-created-at"}})),
        ("GET", "sys/wrapping/lookup", response(200)),
        ("POST", "sys/wrapping/lookup", response(200)),
        ("POST", "sys/wrapping/unwrap", response(200, {"data": payload})),
        ("POST", "sys/wrapping/unwrap", response(400)),
        ("POST", "sys/wrapping/lookup", response(400)),
        ("POST", "sys/wrapping/wrap", response(400)),
        ("POST", "sys/wrapping/unwrap", response(400)),
        ("POST", "sys/wrapping/unwrap", response(400)),
        ("GET", "auth/token/lookup-self", response(200)),
        ("POST", "auth/token/create", response(200, {"auth": {"client_token": PRIVATE + "user"}})),
        ("POST", "sys/wrapping/wrap", response(200, wrapped("old", 120))),
        ("POST", "sys/wrapping/rewrap", response(403)),
        ("POST", "sys/wrapping/lookup", response(200)),
        ("POST", "sys/wrapping/rewrap", response(200, wrapped("new", 120))),
        ("POST", "sys/wrapping/lookup", response(400)),
        ("POST", "sys/wrapping/unwrap", response(200, {"data": {"value": "only-synthetic"}})),
        ("POST", "sys/wrapping/unwrap", response(400)),
        ("POST", "sys/wrapping/wrap", response(200, wrapped("revoked"))),
        ("POST", "auth/token/revoke-accessor", response(204)),
        ("POST", "sys/wrapping/lookup", response(400)),
        ("POST", "auth/token/create", response(200, wrapped(
            "auth-wrapper", wrapped_accessor=PRIVATE + "issued-accessor"))),
        ("POST", "sys/wrapping/unwrap", response(200, {"auth": {
            "accessor": PRIVATE + "issued-accessor", "client_token": PRIVATE + "issued-token"}})),
        ("GET", "auth/token/lookup-self", response(200)),
        ("POST", "sys/mounts/wrapping-differential", response(204)),
    ]


class ScriptedClient:
    _token = PRIVATE + "root-token"
    address = "https://" + PRIVATE + ".invalid"

    def __init__(self, seed):
        self.script = prefix_script() + [
            ("POST", "wrapping-differential/data/item", seed),
            ("GET", "wrapping-differential/data/item", response(503)),
        ]
        self.calls = []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, body, kwargs))
        expected_method, route, result = self.script[len(self.calls) - 1]
        if (method, path) != (expected_method, "/v1/" + route):
            raise AssertionError("scripted request order changed")
        if isinstance(result, BaseException):
            raise result
        return result


class ResponseWrappingSeedTests(unittest.TestCase):
    def assert_seed_requested_once(self, client):
        self.assertEqual(len(client.calls), 27)
        self.assertEqual(client.calls[-1], (
            "POST", SEED_PATH, {"data": {"value": "synthetic-kv"}},
            {"token": None, "wrap_ttl": None}))
        self.assertEqual(sum(method == "POST" and path == SEED_PATH
                             for method, path, *_ in client.calls), 1)
        self.assertFalse(any(method == "GET" and path == SEED_PATH
                             for method, path, *_ in client.calls))

    def diagnostic(self, captured):
        text = captured.getvalue()
        self.assertNotIn(PRIVATE, text)
        self.assertEqual(len(text.splitlines()), 1)
        return json.loads(text)

    def test_http_failures_keep_original_gate_row_and_one_seed_request(self):
        for side in ("candidate", "oracle"):
            for status in (400, 503, 700):
                with self.subTest(side=side, status=status):
                    client = ScriptedClient(response(status, {"errors": [PRIVATE], "auth": {"client_token": PRIVATE}}))
                    previous = {"case": "previous", "passed": True}
                    rows = [previous]
                    captured = io.StringIO()
                    with redirect_stdout(captured), self.assertRaisesRegex(wrapping.ScenarioFailure, "^wrap.seed$"):
                        wrapping.run_scenarios(client, rows, side=side)
                    self.assertIs(rows[0], previous)
                    self.assertTrue(all(row["passed"] is True for row in rows[:-1]))
                    self.assertEqual(rows[-1], {"case": "wrap.seed", "status": status, "passed": False})
                    self.assertEqual(self.diagnostic(captured), {
                        "case": "wrap.seed", "side": side, "expected_status": 200, "actual_status": status})
                    self.assertNotIn(PRIVATE, json.dumps(rows))
                    self.assert_seed_requested_once(client)

    def test_transport_error_preserves_exception_identity_and_successful_prefix(self):
        for side in ("candidate", "oracle"):
            with self.subTest(side=side):
                original = BaoError(PRIVATE)
                client = ScriptedClient(original)
                previous = {"case": "previous", "passed": True}
                rows = [previous]
                captured = io.StringIO()
                with redirect_stdout(captured), self.assertRaises(BaoError) as raised:
                    wrapping.run_scenarios(client, rows, side=side)
                self.assertIs(raised.exception, original)
                self.assertIs(rows[0], previous)
                self.assertEqual(rows[-1], {"case": "wrap.mount", "status": 204, "passed": True})
                self.assertTrue(all(row["passed"] is True for row in rows))
                self.assertFalse(any(row["case"] == "wrap.seed" for row in rows))
                self.assertEqual(self.diagnostic(captured), {
                    "case": "wrap.seed", "side": side, "expected_status": 200,
                    "transport_error": "request_failed"})
                self.assertNotIn(PRIVATE, json.dumps(rows))
                self.assert_seed_requested_once(client)

    def test_unknown_side_is_fixed_and_cannot_export_operator_input(self):
        for side in (None, PRIVATE, "oracle\n" + PRIVATE, [], {}):
            with self.subTest(side=side):
                client, rows, captured = ScriptedClient(response(503)), [], io.StringIO()
                with redirect_stdout(captured), self.assertRaises(wrapping.ScenarioFailure):
                    wrapping.run_scenarios(client, rows, side=side)
                self.assertEqual(self.diagnostic(captured), {
                    "case": "wrap.seed", "side": "unknown", "expected_status": 200, "actual_status": 503})
                self.assert_seed_requested_once(client)

    def test_noninteger_status_is_not_copied_to_diagnostic_or_coerced(self):
        for status in (True, 503.0, None, PRIVATE, object()):
            with self.subTest(status=status):
                client, rows, captured = ScriptedClient(response(status)), [], io.StringIO()
                with redirect_stdout(captured), self.assertRaisesRegex(wrapping.ScenarioFailure, "^wrap.seed$"):
                    wrapping.run_scenarios(client, rows, side="oracle")
                self.assertEqual(self.diagnostic(captured), {
                    "case": "wrap.seed", "side": "oracle", "expected_status": 200,
                    "transport_error": "status_unavailable"})
                # Preserve the original observation; only the new diagnostic is sanitized.
                self.assertIs(rows[-1]["status"], status)
                self.assertIs(rows[-1]["passed"], False)
                self.assert_seed_requested_once(client)

    def test_seed_success_emits_no_diagnostic_and_reaches_original_get_gate(self):
        for side in ("candidate", "oracle"):
            with self.subTest(side=side):
                client, rows, captured = ScriptedClient(response(200)), [], io.StringIO()
                with redirect_stdout(captured), self.assertRaisesRegex(wrapping.ScenarioFailure, "^wrap.kv_read$"):
                    wrapping.run_scenarios(client, rows, side=side)
                self.assertEqual(captured.getvalue(), "")
                self.assertEqual(rows[-2:], [
                    {"case": "wrap.seed", "status": 200, "passed": True},
                    {"case": "wrap.kv_read", "status": 503, "passed": False}])
                self.assertEqual(len(client.calls), 28)
                self.assertEqual(client.calls[-1], (
                    "GET", SEED_PATH, None, {"token": None, "wrap_ttl": "1m"}))
                self.assertEqual(sum(method == "POST" and path == SEED_PATH
                                     for method, path, *_ in client.calls), 1)

    def test_output_oserror_never_masks_original_failure_or_reissues_seed(self):
        for seed in (response(503), BaoError(PRIVATE)):
            with self.subTest(transport_error=isinstance(seed, BaoError)):
                client, rows = ScriptedClient(seed), []
                original_error = BaoError if isinstance(seed, BaoError) else wrapping.ScenarioFailure
                with patch("builtins.print", side_effect=OSError(PRIVATE)) as output, \
                        self.assertRaises(original_error) as raised:
                    wrapping.run_scenarios(client, rows, side="oracle")
                if isinstance(seed, BaoError):
                    self.assertIs(raised.exception, seed)
                    self.assertEqual(rows[-1], {"case": "wrap.mount", "status": 204, "passed": True})
                    detail = {"transport_error": "request_failed"}
                else:
                    self.assertEqual(str(raised.exception), "wrap.seed")
                    self.assertEqual(rows[-1], {"case": "wrap.seed", "status": 503, "passed": False})
                    detail = {"actual_status": 503}
                self.assertTrue(all(row["passed"] is True for row in rows[:-1]))
                output.assert_called_once()
                message = output.call_args.args[0]
                self.assertNotIn(PRIVATE, message)
                self.assertEqual(json.loads(message), {
                    "case": "wrap.seed", "side": "oracle", "expected_status": 200, **detail})
                self.assert_seed_requested_once(client)

    def test_closed_stdout_preserves_original_failure_and_one_seed_request(self):
        for seed in (response(503), BaoError(PRIVATE)):
            with self.subTest(transport_error=isinstance(seed, BaoError)):
                client, rows, closed = ScriptedClient(seed), [], io.StringIO()
                closed.close()
                expected = BaoError if isinstance(seed, BaoError) else wrapping.ScenarioFailure
                with redirect_stdout(closed), self.assertRaises(expected) as raised:
                    wrapping.run_scenarios(client, rows, side="oracle")
                if isinstance(seed, BaoError):
                    self.assertIs(raised.exception, seed)
                    self.assertEqual(rows[-1], {"case": "wrap.mount", "status": 204, "passed": True})
                else:
                    self.assertEqual(str(raised.exception), "wrap.seed")
                    self.assertEqual(rows[-1], {"case": "wrap.seed", "status": 503, "passed": False})
                self.assert_seed_requested_once(client)

    def test_main_binds_exact_sides_and_preserves_core_failure_return(self):
        candidate_client, oracle_client = object(), object()
        candidate_rows, oracle_rows = [], []
        with patch.object(wrapping.core_isolation, "main", return_value=1) as core_main, \
                patch.object(wrapping, "run_scenarios", return_value=sentinel.rows) as scenarios:
            self.assertEqual(wrapping.main(), 1)
            core_main.assert_called_once()
            options = core_main.call_args.kwargs
            self.assertEqual(set(options), {"scenario_runner", "oracle_scenario_runner", "profile", "scope", "runner_path"})
            self.assertEqual(options["profile"], "response-wrapping")
            self.assertEqual(options["scope"], "selected_opaque_wrapping_lookup_unwrap_rewrap_and_response_capture")
            self.assertEqual(options["runner_path"], Path(wrapping.__file__))
            self.assertIs(options["scenario_runner"](candidate_client, candidate_rows), sentinel.rows)
            self.assertIs(options["oracle_scenario_runner"](oracle_client, oracle_rows), sentinel.rows)
            self.assertEqual(scenarios.call_args_list, [
                call(candidate_client, candidate_rows, side="candidate"),
                call(oracle_client, oracle_rows, side="oracle")])


if __name__ == "__main__":
    unittest.main()
