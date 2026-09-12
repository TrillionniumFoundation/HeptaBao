"""Test the owned-loopback fault harness without claiming product qualification."""
from __future__ import annotations

import contextlib
import importlib.util
from pathlib import Path
import select
import socket
import threading
import time
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / "ha_network_partition.py"
SPEC = importlib.util.spec_from_file_location("ha_network_partition_fixture", SOURCE)
assert SPEC is not None and SPEC.loader is not None
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class Echo:
    """One bounded worker, synthetic bytes, no external network addresses."""
    def __init__(self):
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(32)
        self.listener.setblocking(False)
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        clients = set()
        try:
            while not self.stop.is_set():
                readable, _, _ = select.select([self.listener, *clients], [], [], 0.02)
                for sock in readable:
                    if sock is self.listener:
                        client, _ = self.listener.accept()
                        client.settimeout(0.2)
                        clients.add(client)
                        continue
                    try:
                        data = sock.recv(16384)
                        if data:
                            sock.sendall(data)
                            continue
                    except OSError:
                        pass
                    clients.remove(sock)
                    fixture.shutdown(sock)
        finally:
            for client in clients:
                fixture.shutdown(client)
            self.listener.close()

    def close(self):
        self.stop.set()
        self.worker.join(timeout=2)
        if self.worker.is_alive():
            raise AssertionError("synthetic echo worker did not stop")


@contextlib.contextmanager
def echo_link():
    echo = Echo()
    link = fixture.LoopbackLink(echo.port, {echo.port})
    try:
        yield link
    finally:
        try:
            link.close()
        finally:
            echo.close()


class LinkTests(unittest.TestCase):
    def test_rejects_destinations_not_owned_by_fixture(self):
        for value in (0, -1, 65536, True, "8200", 8200):
            with self.subTest(value=value), self.assertRaises(fixture.FixtureError):
                fixture.LoopbackLink(value, {8201})

    def test_roundtrip_preserves_opaque_bytes(self):
        payload = bytes(range(256)) * 80
        with echo_link() as link, socket.create_connection(("127.0.0.1", link.port), 1) as client:
            client.settimeout(1)
            client.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = client.recv(16384)
                self.assertTrue(chunk)
                received.extend(chunk)
            self.assertEqual(payload, received)

    def test_partition_closes_existing_stream_and_heal_needs_new_connection(self):
        with echo_link() as link:
            with socket.create_connection(("127.0.0.1", link.port), 1) as client:
                client.settimeout(1)
                client.sendall(b"synthetic-before-partition")
                self.assertEqual(b"synthetic-before-partition", client.recv(128))
                link.set_blocked(True)
                try:
                    self.assertEqual(b"", client.recv(128))
                except ConnectionResetError:
                    pass
            with socket.create_connection(("127.0.0.1", link.port), 1) as denied:
                denied.settimeout(1)
                try:
                    self.assertEqual(b"", denied.recv(128))
                except ConnectionResetError:
                    pass
            link.set_blocked(False)
            with socket.create_connection(("127.0.0.1", link.port), 1) as client:
                client.settimeout(1)
                client.sendall(b"synthetic-after-heal")
                self.assertEqual(b"synthetic-after-heal", client.recv(128))

    def test_fault_state_requires_boolean_and_identical_update_is_idempotent(self):
        with echo_link() as link:
            for value in (0, 1, "false", None):
                with self.assertRaises(fixture.FixtureError):
                    link.set_blocked(value)
            initial = link._generation
            link.set_blocked(False)
            self.assertEqual(initial, link._generation)
            link.set_blocked(True)
            blocked = link._generation
            link.set_blocked(True)
            self.assertEqual(blocked, link._generation)

    def test_unexpected_worker_failure_cannot_be_reported_as_success(self):
        echo = Echo()
        link = fixture.LoopbackLink(echo.port, {echo.port})
        link._failed = True
        try:
            with self.assertRaises(fixture.FixtureError):
                link.close()
            self.assertFalse(link._acceptor.is_alive())
        finally:
            echo.close()

    def test_cleanup_closes_active_clients_and_joins_workers(self):
        echo = Echo()
        link = fixture.LoopbackLink(echo.port, {echo.port})
        try:
            with socket.create_connection(("127.0.0.1", link.port), 1) as client:
                client.settimeout(1)
                client.sendall(b"cleanup")
                self.assertEqual(b"cleanup", client.recv(128))
                link.close()
                self.assertFalse(link._acceptor.is_alive())
                self.assertFalse(any(worker.is_alive() for worker in link._threads))
        finally:
            echo.close()


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.cluster = fixture.PartitionCluster.__new__(fixture.PartitionCluster)
        self.cluster.root_token = "synthetic-token"
        self.node = Mock()

    @staticmethod
    def response(value="correct", version=1):
        return 200, {"data": {"data": {"value": value}, "metadata": {"version": version}}}

    def test_inactive_health_never_means_available_or_active(self):
        for status, health in ((429, {"ha_active": False, "standby": True}),
                               (503, {"ha_active": False, "standby": False}),
                               (503, {"ha_active": False, "standby": True})):
            self.assertTrue(fixture.inactive_health(status, health))
        for status in (200, 404, 501, True, "503", 503.0):
            self.assertFalse(fixture.inactive_health(status, {"ha_active": False, "standby": True}))
        for health in ({}, {"ha_active": 0, "standby": True},
                       {"ha_active": True, "standby": True}, {"ha_active": False},
                       {"ha_active": False, "standby": 1}):
            self.assertFalse(fixture.inactive_health(429, health))

    def test_exact_acknowledged_read(self):
        self.node.call.return_value = self.response()
        self.cluster._read_exact(self.node, "synthetic", "correct")
        self.node.call.assert_called_once()

    def test_successful_stale_read_is_not_retried(self):
        for response in (self.response("stale"), self.response(version=0),
                         self.response(version=2), self.response(version=True), (200, {}), (404, {})):
            with self.subTest(response=response):
                self.node.reset_mock()
                self.node.call.return_value = response
                with self.assertRaises(fixture.FixtureError):
                    self.cluster._read_exact(self.node, "synthetic", "correct")
                self.node.call.assert_called_once()

    def test_read_only_unavailability_may_retry(self):
        self.node.call.side_effect = [(503, {}), self.response()]
        with patch.object(fixture.time, "sleep"):
            self.cluster._read_exact(self.node, "synthetic", "correct")
        self.assertEqual(2, self.node.call.call_count)

    def test_uncertain_write_is_never_replayed(self):
        for result in ((503, {}), (200, {"data": {"version": True}}), (200, {"data": {"version": 2}})):
            with self.subTest(result=result):
                self.node.reset_mock()
                self.node.call.return_value = result
                with self.assertRaises(fixture.FixtureError):
                    self.cluster._new_value(self.node, "synthetic", "correct")
                self.node.call.assert_called_once()
                self.assertEqual({"cas": 0}, self.node.call.call_args.args[2]["options"])

    def test_timed_out_write_is_never_replayed(self):
        self.node.call.side_effect = TimeoutError("synthetic")
        with self.assertRaises(TimeoutError):
            self.cluster._new_value(self.node, "synthetic", "correct")
        self.node.call.assert_called_once()

    def test_partition_scopes_are_directed_connection_faults(self):
        self.cluster.links = {(a, b): Mock() for a in (1, 2, 3) for b in (1, 2, 3) if a != b}
        self.cluster._partition(2, outbound_only=True)
        for (source, target), link in self.cluster.links.items():
            link.set_blocked.assert_called_once_with(source == 2)
            link.reset_mock()
        self.cluster._partition(2, outbound_only=False)
        for (source, target), link in self.cluster.links.items():
            link.set_blocked.assert_called_once_with(source == 2 or target == 2)

    def test_cleanup_attempts_every_link_even_after_failure(self):
        first, second = Mock(), Mock()
        first.close.side_effect = fixture.FixtureError("synthetic")
        self.cluster.links = {(1, 2): first, (2, 1): second}
        with patch.object(fixture.Cluster, "close"), self.assertRaises(fixture.FixtureError):
            self.cluster.close()
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_signal_is_a_failure_not_success(self):
        with self.assertRaises(fixture.FixtureError):
            fixture.terminate(15, None)


if __name__ == "__main__":
    unittest.main()
