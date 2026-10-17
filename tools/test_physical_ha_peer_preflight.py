#!/usr/bin/env python3
"""Private fixture gate regression tests; no real remote peers contacted."""
from __future__ import annotations
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
import physical_ha_peer_preflight as pre


class PrivatePeerPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "node-1"
        self.root.mkdir(mode=0o700)
        self.manifest = self.base / "manifest.json"
        self.peers = {}
        for i,letter in ((1,"a"),(2,"b"),(3,"c")):
            self.peers[str(i)] = {
                "node_name":f"node-{i}",
                "server_name":f"node-{i}.heptabao.synthetic",
                "address":f"127.0.0.1:{46000+i}",
                "certificate_sha256":letter*64,
            }
        self.conf = {"cluster_id":"synthetic-cluster-1","node_id":1,"peers":self.peers}
        self.marker={"cluster_id":"synthetic-cluster-1","synthetic_only":True,"allow_production":False}
        for name in ("ca.crt","tls.crt","tls.key"):
            self.private(self.root / name,"private test fixture")
        self.sync()

    def private(self,path:Path, content:str):
        path.write_text(content)
        path.chmod(0o600)

    def sync(self):
        self.private(self.root / "ha.json",json.dumps(self.conf))
        self.private(self.manifest,json.dumps(self.marker))

    def load(self):
        with patch.object(pre, "pinned_hash", return_value="a"*64):
            return pre.load_fixture(self.root,self.manifest)

    def denied(self,label):
        with self.assertRaises(pre.Refusal) as cm:
            self.load()
        self.assertEqual(cm.exception.label,label)

    def test_offline_private_manifest_passes_without_network(self):
        with patch.object(pre, "pinned_hash", return_value="a"*64):
            with patch.object(socket,"create_connection",side_effect=AssertionError("network forbidden")):
                config,marker,root=pre.load_fixture(self.root,self.manifest)
        self.assertEqual(config["node_id"],1)
        self.assertEqual(len(config["peers"]),3)
        self.assertEqual(root,self.root)
        self.assertTrue(marker["synthetic_only"])

    def test_no_production_marker_fails_closed(self):
        self.marker["synthetic_only"]=False
        self.sync()
        self.denied("NON_SYNTHETIC_FIXTURE_DENIED")

    def test_stale_cluster_manifest_rejected(self):
        self.marker["cluster_id"]="wrong-cluster"
        self.sync()
        self.denied("CLUSTER_IDENTITY_MISMATCH")

    def test_duplicate_tls_leaf_rejected(self):
        self.peers["3"]["certificate_sha256"]="b"*64
        self.sync()
        self.denied("INVALID_ENROLLMENT")

    def test_ambiguous_peer_endpoint_rejected(self):
        for value in ("localhost:443","0.0.0.0:46342","127.0.0.1:0","192.168.0.13:65536",
                      "224.0.0.1:46342","192.168.0.9:notaport"):
            with self.subTest(value=value):
                with self.assertRaises(pre.Refusal) as c:
                    pre.peer_address(value)
                self.assertEqual(c.exception.label,"INVALID_PEER_ADDRESS")

    def test_local_cert_must_match_declared_pin(self):
        with patch.object(pre,"pinned_hash",return_value="d"*64):
            with self.assertRaises(pre.Refusal) as c:
                pre.load_fixture(self.root,self.manifest)
        self.assertEqual(c.exception.label,"LOCAL_CERT_PIN_MISMATCH")

    def test_symlinked_key_refused(self):
        (self.root/"tls.key").unlink()
        (self.root/"tls.key").symlink_to(self.root/"ca.crt")
        self.denied("SYMLINK_REFUSED")

    def test_public_fixture_refused(self):
        self.root.chmod(0o755)
        self.denied("PRIVATE_FIXTURE_REQUIRED")

    def test_invalid_probes_do_not_dial(self):
        config,_,root=self.load()
        with patch.object(socket,"create_connection",side_effect=AssertionError("network")):
            for peer in (1,5):
                with self.assertRaises(pre.Refusal) as c:
                    pre.probe_peer(config,root,peer,0.5)
                self.assertEqual(c.exception.label,"INVALID_PEER_ID")

    def test_bad_deadline_refused_without_network(self):
        config,_,root=self.load()
        with patch.object(socket,"create_connection",side_effect=AssertionError("network")):
            with self.assertRaises(pre.Refusal) as c:
                pre.probe_peer(config,root,2,90.0)
        self.assertEqual(c.exception.label,"INVALID_DEADLINE")


    def test_noncanonical_numeric_id_cannot_duplicate_a_voter(self):
        self.peers["01"] = self.peers["1"].copy()
        self.peers.pop("3")
        self.sync()
        self.denied("INVALID_MEMBERSHIP")

    def test_duplicate_peer_endpoint_fails_before_network(self):
        self.peers["3"]["address"] = self.peers["2"]["address"]
        self.sync()
        self.denied("DUPLICATE_PEER_ENDPOINT")

    def test_all_peer_probe_checks_both_and_uses_original_budget(self):
        conf, _, root = self.load()
        with patch.object(pre, "probe_peer", side_effect=["TLSv1.2", "TLSv1.3"]) as probe:
            result = pre.probe_all_peers(conf, root, 2.5)
        self.assertEqual(result, {"2": "TLSv1.2", "3": "TLSv1.3"})
        self.assertEqual([c.args[2] for c in probe.call_args_list], [2, 3])
        self.assertTrue(all(0 < c.args[3] <= 2.5 for c in probe.call_args_list))

    def test_second_peer_failure_cannot_be_promoted_to_partial_success(self):
        conf, _, root = self.load()
        with patch.object(pre, "probe_peer", side_effect=[
            "TLSv1.3", pre.Refusal("TCP_REFUSED"),
        ]) as probe:
            with self.assertRaises(pre.Refusal) as caught:
                pre.probe_all_peers(conf, root, 2)
        self.assertEqual(caught.exception.label, "TCP_REFUSED")
        self.assertEqual(probe.call_count, 2)

    def test_all_peer_budget_refuses_without_network(self):
        conf, _, root = self.load()
        with patch.object(pre, "probe_peer", side_effect=AssertionError("network")):
            with self.assertRaises(pre.Refusal) as caught:
                pre.probe_all_peers(conf, root, 0.01)
        self.assertEqual(caught.exception.label, "INVALID_DEADLINE")

    def test_fingerprint_ignores_per_host_tunnel_address_not_identity(self):
        conf, _, _ = self.load()
        original = pre.identity_fingerprint(conf)
        conf["peers"]["3"]["address"] = "127.0.0.1:47454"
        self.assertEqual(pre.identity_fingerprint(conf), original)
        conf["peers"]["3"]["certificate_sha256"] = "e" * 64
        self.assertNotEqual(pre.identity_fingerprint(conf), original)


if __name__ == "__main__":
    unittest.main()
