"""Listener allocation must honor the operator's actual network boundary."""
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "single-node"))
import smoke


class FixturePortRangeTests(unittest.TestCase):
    def test_default_allocates_an_available_loopback_port(self):
        with patch.dict(os.environ, {}, clear=True):
            port = smoke.free_loopback_port()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", port))

    def test_occupied_single_port_never_escapes_the_requested_range(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            with patch.dict(os.environ, {"HEPTABAO_FIXTURE_PORT_RANGE": f"{port}-{port}"}):
                with self.assertRaisesRegex(RuntimeError, "fixture_port_range_exhausted"):
                    smoke.free_loopback_port()

    def test_single_available_port_is_selected_exactly(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with patch.dict(os.environ, {"HEPTABAO_FIXTURE_PORT_RANGE": f"{port}-{port}"}):
            self.assertEqual(smoke.free_loopback_port(), port)

    def test_invalid_configuration_is_rejected_before_any_bind(self):
        for value in ("", "31000", "31000,31001", "31000-", "0-65535", "1023-31000",
                      "31001-31000", "31000-65536", "31000-31099\n", " 31000-31099"):
            with self.subTest(value=value), patch.dict(os.environ, {"HEPTABAO_FIXTURE_PORT_RANGE": value}):
                with patch.object(socket.socket, "bind", side_effect=AssertionError("unexpected bind")):
                    with self.assertRaisesRegex(ValueError, "invalid_fixture_port_range"):
                        smoke.free_loopback_port()


if __name__ == "__main__":
    unittest.main()
