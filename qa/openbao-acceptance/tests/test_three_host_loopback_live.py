#!/usr/bin/env python3
import copy
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_multihost_live as base
import ha_three_host_loopback_live as live


class ThreeHostLoopbackTests(unittest.TestCase):
    def nodes(self):
        return [base.Node(i, alias, f"100.100.1.{i}", f"/home/test/fixture-{i}", 56540, 56541)
                for i, alias in enumerate(("macbook-pro", "rog", "pocket4"), 1)]

    def test_fixture_local_routing_does_not_mutate_shared_identity_or_existing_baseline(self):
        nodes = self.nodes()
        mesh = live.CompleteLoopbackMesh()
        peers = {str(node.node_id): {"address": f"{node.ip}:{node.raft_port}",
                                    "server_name": node.server_name,
                                    "certificate_sha256": str(node.node_id)*64} for node in nodes}
        original = copy.deepcopy(peers)
        configured = mesh.prepare_nodes(nodes)
        for old, node in zip(nodes, configured):
            self.assertEqual(old.api_origin, f"https://{old.ip}:56540")
            self.assertEqual(node.api_origin, f"https://127.0.0.1:{55400+node.node_id}")
            config = mesh.configure(node, {"listen": "unused:56541", "peers": peers})
            for peer in (1, 2, 3):
                port = 56541 if peer == node.node_id else 55300+peer
                self.assertEqual(config["peers"][str(peer)]["address"], f"127.0.0.1:{port}")
                self.assertEqual(config["peers"][str(peer)]["server_name"], original[str(peer)]["server_name"])
                self.assertEqual(config["peers"][str(peer)]["certificate_sha256"], original[str(peer)]["certificate_sha256"])
        self.assertEqual(peers, original)

    @unittest.skipUnless(shutil.which("openssl"), "requires actual certificate verifier")
    def test_fresh_mesh_leaf_verifies_for_both_node_sni_and_loopback_api(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mesh = live.CompleteLoopbackMesh()
            node = mesh.prepare_nodes(self.nodes())[0]
            base.create_fixture_ca(root/"ca.key", root/"ca.crt")
            _, certificate = base.create_fixture_node_certificate(node, root, root/"ca.key", root/"ca.crt")
            for option, value in (("-verify_hostname", node.server_name), ("-verify_ip", "127.0.0.1")):
                result = subprocess.run(["openssl", "verify", "-x509_strict", "-CAfile", str(root/"ca.crt"),
                                         option, value, str(certificate)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
