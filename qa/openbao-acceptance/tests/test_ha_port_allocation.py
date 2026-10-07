"""The OS may immediately recycle a closed ephemeral port; do not assume otherwise."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_destructive as fixture


class RecyclingSockets:
    def __init__(self, fail_at=None):
        self.owned = set()
        self.created = []
        self.maximum_owned = 0
        self.fail_at = fail_at

    def socket(self, *args, **kwargs):
        owner = self
        class Socket:
            port = None
            closed = False
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
            def bind(self, address):
                if address != ("127.0.0.1", 0):
                    raise AssertionError("only an isolated loopback bind is allowed")
                if owner.fail_at == len(owner.created):
                    raise OSError("synthetic bind failure")
                self.port = next(port for port in range(35000, 35100) if port not in owner.owned)
                owner.owned.add(self.port)
                owner.maximum_owned = max(owner.maximum_owned, len(owner.owned))
            def getsockname(self): return ("127.0.0.1", self.port)
            def close(self):
                if not self.closed:
                    owner.owned.discard(self.port)
                    self.closed = True
        result = Socket()
        self.created.append(result)
        return result


class PortAllocationTests(unittest.TestCase):
    def test_node_pair_cannot_reuse_the_just_closed_http_port(self):
        sockets = RecyclingSockets()
        with patch.object(fixture.socket, "socket", sockets.socket):
            node = fixture.Node(1, Path("/synthetic/binary"), Path("/synthetic/node"), None)
        self.assertNotEqual(node.http_port, node.raft_port)
        self.assertEqual(sockets.maximum_owned, 2)
        self.assertFalse(sockets.owned)
        self.assertTrue(all(item.closed for item in sockets.created))

    def test_entire_cluster_allocates_six_ports_before_releasing_any(self):
        sockets = RecyclingSockets()
        with tempfile.TemporaryDirectory() as root:
            with patch.object(fixture.socket, "socket", sockets.socket):
                cluster = fixture.Cluster(Path(sys.executable).resolve(), Path(root).resolve() / "cluster")
            ports = [port for node in cluster.nodes for port in (node.http_port, node.raft_port)]
            self.assertEqual(len(ports), 6)
            self.assertEqual(len(set(ports)), 6)
            self.assertTrue(all(node.process is None for node in cluster.nodes))
        self.assertEqual(sockets.maximum_owned, 6)
        self.assertFalse(sockets.owned)
        self.assertTrue(all(item.closed for item in sockets.created))

    def test_mid_batch_bind_failure_closes_every_created_socket(self):
        sockets = RecyclingSockets(fail_at=3)
        with patch.object(fixture.socket, "socket", sockets.socket):
            with self.assertRaises(OSError): fixture.free_ports(6)
        self.assertEqual(len(sockets.created), 3)
        self.assertTrue(all(item.closed for item in sockets.created))
        self.assertFalse(sockets.owned)

    def test_count_bound_rejects_before_socket_allocation(self):
        for value in [True, False, 0, -1, 65, "6", None, 1.0]:
            with self.subTest(value=value), patch.object(fixture.socket,"socket") as opened:
                with self.assertRaisesRegex(fixture.FixtureError,"invalid_ephemeral_port_count"):
                    fixture.free_ports(value)
                opened.assert_not_called()

    def test_preselected_ports_do_not_allocate_replacements(self):
        with patch.object(fixture.socket,"socket") as opened:
            node = fixture.Node(1,Path("/synthetic/binary"),Path("/synthetic/node"),None,
                                ports=(35001,35002))
            self.assertEqual((node.http_port,node.raft_port),(35001,35002))
            for pair in [(1,1),(0,2),(True,2),(65536,2),(1,),()]:
                with self.subTest(pair=pair), self.assertRaises(fixture.FixtureError):
                    fixture.Node(1,Path("/synthetic/binary"),Path("/synthetic/node"),None,ports=pair)
            opened.assert_not_called()


if __name__ == "__main__": unittest.main()
