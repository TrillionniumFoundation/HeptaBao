#!/usr/bin/env python3
"""Check complete directed routing and exact reversible fixture-only changes."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import physical_ha_loopback_mesh as mesh
import physical_ha_peer_preflight as pre


class LoopbackMeshTests(unittest.TestCase):
    def test_every_directed_edge_reaches_its_enrolled_physical_host(self):
        plan = mesh.mesh_plan(["mac", "rog", "pocket4"], 49231, 55200, 55300)
        exports = {}
        for command in plan["commands"]:
            argv = command["args"]
            forwarding = argv[argv.index("-L")+1].split(":")
            exports[int(forwarding[1])] = command["node_id"]
            self.assertEqual(forwarding[0:4:2], ["127.0.0.1", "127.0.0.1"])
            self.assertEqual(int(forwarding[3]), 49231)
        edges = set()
        for command in plan["commands"]:
            node = command["node_id"]
            argv = command["args"]
            reverse = {}
            for i, part in enumerate(argv):
                if part == "-R":
                    forwarding = argv[i+1].split(":")
                    self.assertEqual(forwarding[0:4:2], ["127.0.0.1", "127.0.0.1"])
                    reverse[int(forwarding[1])] = int(forwarding[3])
            for peer, endpoint in plan["node_peer_addresses"][str(node)].items():
                if int(peer) == node:
                    self.assertEqual(endpoint, "127.0.0.1:49231")
                else:
                    target = exports[reverse[int(endpoint.rsplit(":", 1)[1])]]
                    self.assertEqual(target, int(peer))
                    edges.add((node, target))
        self.assertEqual(edges, {(i, j) for i in (1, 2, 3) for j in (1, 2, 3) if i != j})

    def test_transport_only_patch_and_byte_exact_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            manifest = root / "manifest.json"
            config = {"cluster_id": "isolated-fixture", "node_id": 1,
                      "listen": "192.168.1.10:49231", "replication_key_file": "/private/path",
                      "peers": {str(i): {"node_name": f"node-{i}",
                                          "server_name": f"node-{i}.heptabao.synthetic",
                                          "certificate_sha256": hex(i)[2:]*64,
                                          "address": f"192.168.1.{i+9}:49231"} for i in (1, 2, 3)}}
            original = json.dumps(config, indent=3).encode()
            files = {"manifest.json": json.dumps({"cluster_id": "isolated-fixture",
                       "synthetic_only": True, "allow_production": False}).encode(),
                     "ha.json": original, "tls.crt": b"test", "tls.key": b"test", "ca.crt": b"test"}
            for name, raw in files.items():
                (root/name).write_bytes(raw)
                (root/name).chmod(0o600)
            with patch.object(pre, "pinned_hash", return_value="1"*64), patch.object(mesh, "stopped"):
                result = mesh.patch(root, manifest, 49231, 55200, 55300)
                self.assertTrue(result["peer_identity_unchanged"])
                changed = json.loads((root/"ha.json").read_bytes())
                self.assertEqual(changed["peers"]["2"]["address"], "127.0.0.1:55302")
                for i in ("1", "2", "3"):
                    self.assertEqual(changed["peers"][i]["certificate_sha256"], config["peers"][i]["certificate_sha256"])
                    self.assertEqual(changed["peers"][i]["server_name"], config["peers"][i]["server_name"])
                self.assertEqual(changed["replication_key_file"], config["replication_key_file"])
                self.assertEqual(mesh.restore(root, manifest)["status"], "restored")
                self.assertEqual((root/"ha.json").read_bytes(), original)
                self.assertEqual((root/mesh.BACKUP).read_bytes(), original)

    def test_running_exact_fixture_refuses_reconfiguration(self):
        class ProcessList:
            stdout = "/isolated/heptabao-server --config /isolated/server.json --ha-config /isolated/ha.json\n"
        with patch.object(mesh.subprocess, "run", return_value=ProcessList()):
            with self.assertRaises(pre.Refusal) as result:
                mesh.stopped(Path("/isolated/ha.json"))
        self.assertEqual(result.exception.label, "FIXTURE_PROCESS_MUST_BE_STOPPED")


if __name__ == "__main__":
    unittest.main()
