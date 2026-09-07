from __future__ import annotations

import errno
import importlib.util
import sys
import time
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
MODULE_PATH = SCRIPTS / "p0_transport_exact_v1.py"
SPEC = importlib.util.spec_from_file_location("p0_transport_exact_v1", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeReadableSocket:
    def __init__(self, events: list[bytes | BaseException]) -> None:
        self.events = list(events)
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def recv(self, size: int) -> bytes:
        del size
        if not self.events:
            return b""
        event = self.events.pop(0)
        if isinstance(event, BaseException):
            raise event
        return event


class P0TransportResetToleranceTests(unittest.TestCase):
    def read(self, events: list[bytes | BaseException]):
        started = time.monotonic()
        return MODULE._read_response(
            FakeReadableSocket(events),
            started=started,
            deadline=started + 1.0,
            timeout_message="test timeout",
            reset_message="test reset before bytes",
        )

    def test_complete_response_followed_by_reset_is_accepted(self) -> None:
        response = self.read(
            [
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
                ConnectionResetError(errno.ECONNRESET, "reset after response"),
            ]
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, b"{}")

    def test_reset_before_response_bytes_remains_explicit_socket_failure(self) -> None:
        with self.assertRaisesRegex(ConnectionResetError, "test reset before bytes"):
            self.read([ConnectionResetError(errno.ECONNRESET, "reset")])

    def test_partial_response_followed_by_reset_still_fails_closed(self) -> None:
        with self.assertRaises(MODULE.MatrixFailure):
            self.read(
                [
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}",
                    ConnectionResetError(errno.ECONNRESET, "reset after partial body"),
                ]
            )

    def test_non_reset_socket_error_is_not_relabelled(self) -> None:
        with self.assertRaises(PermissionError):
            self.read([PermissionError(errno.EACCES, "denied")])

    def test_delivery_failure_requires_one_request_bound_audit_graph(self) -> None:
        request_id = "p0-startup-0001"
        lines = [
            (
                f"request_id={request_id} operation=KvWrite "
                "phase=RequestAccepted commit=NotAttempted status=0 "
                "detail=dispatch-authorized"
            ),
            (
                f"request_id={request_id} operation=KvWrite "
                "phase=ResponseCommitted commit=Committed status=204 "
                "detail=response-committed"
            ),
            (
                f"request_id={request_id} operation=NONE "
                "phase=ResponseCommitted commit=Committed status=503 "
                "detail=response-delivery-failed-after-commit"
            ),
        ]
        self.assertTrue(
            MODULE._delivery_attempt_matches(
                lines, "response-delivery-failed-after-commit"
            )
        )

    def test_delivery_failure_rejects_cross_request_line_matching(self) -> None:
        lines = [
            (
                "request_id=p0-a operation=KvRead phase=RequestAccepted "
                "commit=NotAttempted status=0 detail=dispatch-authorized"
            ),
            (
                "request_id=p0-a operation=KvRead phase=ResponsePrepared "
                "commit=NotCommitted status=200 detail=response-prepared"
            ),
            (
                "request_id=p0-b operation=NONE phase=ResponsePrepared "
                "commit=NotCommitted status=503 "
                "detail=response-delivery-failed-before-commit"
            ),
        ]
        self.assertFalse(
            MODULE._delivery_attempt_matches(
                lines, "response-delivery-failed-before-commit"
            )
        )

    def test_delivery_failure_rejects_wrong_commit_disposition(self) -> None:
        request_id = "p0-startup-0002"
        lines = [
            (
                f"request_id={request_id} operation=KvWrite "
                "phase=RequestAccepted commit=NotAttempted status=0 "
                "detail=dispatch-authorized"
            ),
            (
                f"request_id={request_id} operation=KvWrite "
                "phase=ResponseCommitted commit=Committed status=204 "
                "detail=response-committed"
            ),
            (
                f"request_id={request_id} operation=NONE "
                "phase=ResponseCommitted commit=NotCommitted status=503 "
                "detail=response-delivery-failed-after-commit"
            ),
        ]
        self.assertFalse(
            MODULE._delivery_attempt_matches(
                lines, "response-delivery-failed-after-commit"
            )
        )

    def test_delegated_runner_bytes_and_regression_are_manifest_bound(self) -> None:
        manifest = yaml.safe_load(
            (
                ROOT
                / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml"
            ).read_text(encoding="utf-8")
        )
        final_input = yaml.safe_load(
            (ROOT / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml").read_text(
                encoding="utf-8"
            )
        )
        documents = {
            entry["path"]: entry
            for entry in manifest["documents"]
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        }
        required_paths = set(
            final_input["workflow_coverage"]["required_manifest_paths"]
        )
        expected = {
            "scripts/p0_transport_exact_v1.py",
            "scripts/p0_transport_exact_core_v1.py",
            "tests/plan/test_p0_transport_reset_tolerance.py",
        }
        self.assertTrue(expected <= set(documents))
        self.assertTrue(expected <= required_paths)
        for path in expected:
            self.assertEqual(documents[path]["kind"], "NORMATIVE")
            self.assertEqual(documents[path]["authority_effect"], "NONE")

        wrapper = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("import p0_transport_exact_core_v1 as core", wrapper)
        self.assertIn("core.exchange = exchange", wrapper)
        self.assertIn("core.trickle_request = trickle_request", wrapper)
        self.assertIn(
            "core.force_delivery_failure_detail = force_delivery_failure_detail",
            wrapper,
        )
        self.assertIn("_delivery_attempt_matches", wrapper)

    def test_serial_closure_uses_canonical_p0_v2_count_shape(self) -> None:
        workflow = (
            ROOT / ".github/workflows/plan-v1.3.1-final-exact.yml"
        ).read_text(encoding="utf-8")
        start = workflow.index('assert p0["counts"] == {')
        end = workflow.index('}, p0', start)
        p0_count_block = workflow[start:end]
        for marker in (
            '"executed_pass": 11',
            '"source_bound_pass": 2',
            '"best_effort_source_bound_pass": 1',
            '"fail": 0',
            '"blocked": 0',
            '"unexecuted": 0',
            '"total": 14',
        ):
            self.assertIn(marker, p0_count_block)
        for forbidden in (
            '"runtime_socket_observed": 11',
            '"exact_head_compiled_source_bound": 2',
            '"best_effort_controlled_drop_source_bound": 1',
            '"failed": 0',
            '"unknown": 0',
        ):
            self.assertNotIn(forbidden, p0_count_block)


if __name__ == "__main__":
    unittest.main()
