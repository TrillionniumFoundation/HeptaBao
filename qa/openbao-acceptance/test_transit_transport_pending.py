import contextlib
import http.client
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bao_http import BaoError, Client
import core_isolation as core
from fixture_transport_case import begin_case, complete_case, pending_case
import transit_derived_live as derived


class PendingTransportCaseTests(unittest.TestCase):
    def test_actual_failed_request_keeps_its_controlled_case_before_any_completed_row(self):
        with contextlib.ExitStack() as stack:
            left, right = socket.socketpair()
            stack.enter_context(left)
            stack.enter_context(right)
            private = b"synthetic-private-status-line"
            right.sendall(private + b"\r\n")
            right.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(left)
            stack.callback(response.close)
            opener = MagicMock()
            opener.open.side_effect = lambda *args, **kwargs: response.begin()
            client = object.__new__(Client)
            client.address, client.namespace = "https://localhost:8200", ""
            client._token, client.timeout, client._opener = "synthetic-private-token", 15, opener
            old = "derived270.xchacha20-poly1305.ordinary.message.2.aad.0.wrong_aad"
            rows = [{"case": old, "passed": True}]
            attempted = "xchacha20-poly1305.ordinary.message.2.aad.1.encrypt"
            with self.assertRaises(BaoError) as caught:
                derived.Trace(client, rows).call(attempted, "POST", "synthetic-route", 200,
                                                 {"private_input": "synthetic-private-body"})
            result = {}
            core.retain_transport_failure(result, "candidate", "scenario",
                                          caught.exception, client=client)
            detail = result["transport_failures"]["candidate"]
            self.assertEqual(detail["pending_request_case"], "derived270." + attempted)
            self.assertNotEqual(detail["pending_request_case"], rows[-1]["case"])
            self.assertEqual(rows, [{"case": old, "passed": True}])
            self.assertNotIn(private.decode(), json.dumps(result))
            self.assertNotIn("synthetic-private-token", json.dumps(result))
            self.assertNotIn("synthetic-private-body", json.dumps(result))
            self.assertEqual(opener.open.call_count, 1)
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)

    def test_completed_http_response_clears_pending_even_when_status_check_fails(self):
        class FixtureClient:
            def request(self, *args):
                return type("Response", (), {"status": 500, "body": {"secret": "synthetic-private-body"}})()
        client = FixtureClient()
        with self.assertRaises(core.ScenarioFailure):
            derived.Trace(client, []).call("xchacha20-poly1305.convergent.hmac_context.1",
                                          "POST", "synthetic-route", 200, {})
        self.assertIsNone(pending_case(client))

    def test_unknown_or_forged_case_never_becomes_pending_request_metadata(self):
        class FixtureClient:
            def request(self, *args):
                raise BaoError("transport_outcome_unknown")
        client = FixtureClient()
        with self.assertRaises(BaoError):
            derived.Trace(client, []).call("synthetic-private-caller-label", "POST",
                                          "synthetic-route", 200, {})
        self.assertIsNone(pending_case(client))
        client._heptabao_derived_pending_case = {"label": "derived270.mount"}
        self.assertIsNone(pending_case(client))
        class HostileLabel:
            def __str__(self):
                raise AssertionError("label str was called")
            def __repr__(self):
                raise AssertionError("label repr was called")
        begin_case(client, HostileLabel())
        self.assertIsNone(pending_case(client))

    def test_selected_profile_and_restart_history_cannot_be_reassigned(self):
        class FixtureClient:
            def request(self, *args):
                raise AssertionError("invalid selected profile dispatched")
        for selected in ("synthetic-private-profile", True, ["xchacha20-poly1305.ordinary"]):
            with self.assertRaises(ValueError):
                derived.run_scenarios(FixtureClient(), [], selected_profile=selected)
        rows = []
        derived._CONTEXT[id(rows)] = [
            ("synthetic-key", "xchacha20-poly1305.ordinary", "", "", "", "", "", False, False)]
        with self.assertRaises(core.ScenarioFailure):
            derived.run_after_restart(FixtureClient(), rows,
                                     selected_profile="xchacha20-poly1305.convergent")
        full_rows = []
        derived._CONTEXT[id(full_rows)] = [
            ("synthetic-key", "xchacha20-poly1305.ordinary", "", "", "", "", "", False, False)]
        with self.assertRaises(core.ScenarioFailure):
            derived.run_after_restart(FixtureClient(), full_rows)

    def test_actual_convergent_case_is_retained_and_success_clears_it(self):
        class FixtureClient:
            def request(self, *args):
                self.observed_pending = pending_case(self)
                return type("Response", (), {"status": 200, "body": {"data": {}}})()
        client = FixtureClient()
        rows = []
        label = "xchacha20-poly1305.convergent.hmac_context.1"
        derived.Trace(client, rows).call(label, "POST", "synthetic-route", 200, {})
        self.assertEqual(client.observed_pending, "derived270." + label)
        self.assertIsNone(pending_case(client))
        self.assertEqual(rows, [{"case": "derived270." + label, "status": 200, "passed": True}])


if __name__ == "__main__":
    unittest.main()
