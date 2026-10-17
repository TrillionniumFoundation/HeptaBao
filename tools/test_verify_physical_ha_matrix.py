#!/usr/bin/env python3
"""No network: exact directed synthetic mTLS matrix contract."""
import copy
import unittest
from verify_physical_ha_matrix import verify_reports
from physical_ha_peer_preflight import Refusal, SCHEMA


def sample():
    return [
        dict(schema=SCHEMA, status="all_peers_mtls_passed", test_only=True,
             production_authority=False, v6_ha_qualified=False,
             node_id=n, members=3, network_attempts=2,
             identity_sha256="a"*64,
             tls_by_peer={str(t): "TLSv1.3" for t in (1, 2, 3) if t != n})
        for n in (1, 2, 3)
    ]


class MeshMatrixTests(unittest.TestCase):
    def test_exact_six_directed_edges(self):
        r=verify_reports(sample())
        self.assertEqual(r["edge_count"],6)
        self.assertEqual(len(set((e["source"],e["target"]) for e in r["edges"])),6)
        self.assertFalse(r["production_authority"])
        self.assertFalse(r["raft_rpc_qualified"])

    def denied(self,reports):
        with self.assertRaises(Refusal):
            verify_reports(reports)

    def test_missing_or_duplicate_host_denied(self):
        r=sample()
        self.denied(r[:2])
        r[2]["node_id"]=2
        self.denied(r)

    def test_invalid_or_missing_direction_denied(self):
        r=sample()
        del r[0]["tls_by_peer"]["3"]
        self.denied(r)
        r=sample()
        r[1]["tls_by_peer"]["1"]="TLS_UNKNOWN"
        self.denied(r)

    def test_mismatched_identity_and_partial_failure_denied(self):
        r=sample()
        r[2]["identity_sha256"]="f"*64
        self.denied(r)
        r=sample()
        r[2]["status"]="refused"
        self.denied(r)

    def test_unqualified_lease_or_fake_receipt_denied(self):
        r=sample()
        r[0]["production_authority"]=True
        self.denied(r)
        r=sample()
        r[1]["network_attempts"]=1
        self.denied(r)


if __name__ == "__main__":
    unittest.main()
