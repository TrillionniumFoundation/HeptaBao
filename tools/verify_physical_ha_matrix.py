#!/usr/bin/env python3
"""Reject any synthetic HA mTLS 'full mesh' claim missing a directed edge.

Read three owner-only, already-observed operator reports; never open a socket,
change configuration, grant a Raft/root ACK, or view credentials.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from physical_ha_peer_preflight import Refusal, SCHEMA, private_regular

MATRIX_SCHEMA = "heptabao.synthetic-three-host-six-edge-mtls-matrix.v1"


def verify_reports(reports: list[dict]) -> dict:
    if len(reports) != 3 or any(type(r) is not dict for r in reports):
        raise Refusal("MATRIX_INCOMPLETE")
    if any(
        r.get("schema") != SCHEMA
        or r.get("status") != "all_peers_mtls_passed"
        or r.get("test_only") is not True
        or r.get("production_authority") is not False
        or r.get("v6_ha_qualified") is not False
        or type(r.get("node_id")) is not int
        or r.get("members") != 3
        or r.get("network_attempts") != 2
        for r in reports
    ):
        raise Refusal("MATRIX_INVALID_REPORT")
    by_id = {r["node_id"]: r for r in reports}
    if set(by_id) != {1, 2, 3}:
        raise Refusal("MATRIX_MISSING_NODE")
    common = {r.get("identity_sha256") for r in reports}
    if (
        len(common) != 1
        or type(next(iter(common))) is not str
        or len(next(iter(common))) != 64
        or any(ch not in "0123456789abcdef" for ch in next(iter(common)))
    ):
        raise Refusal("MATRIX_IDENTITY_MISMATCH")
    edges: list[dict] = []
    for source in sorted(by_id):
        reported = by_id[source].get("tls_by_peer")
        expected = {str(i) for i in by_id if i != source}
        if type(reported) is not dict or set(reported) != expected:
            raise Refusal("MATRIX_EDGE_MISSING")
        for target in sorted(expected):
            version = reported[target]
            if version not in ("TLSv1.2", "TLSv1.3"):
                raise Refusal("MATRIX_TLS_VERSION_INVALID")
            edges.append({"source": source, "target": int(target), "tls": version})
    assert len(edges) == 6
    return {
        "schema": MATRIX_SCHEMA,
        "status": "six_directed_edges_observed",
        "test_only": True,
        "production_authority": False,
        "v6_ha_qualified": False,
        "raft_rpc_qualified": False,
        "identity_sha256": next(iter(common)),
        "edge_count": 6,
        "edges": edges,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path, nargs=3)
    args = parser.parse_args()
    try:
        raw = []
        for path in args.reports:
            # No symlink/hardlink and no publicly readable evidence.
            data = private_regular(path).read_bytes()
            if len(data) > 16384:
                raise Refusal("MATRIX_REPORT_BOUND")
            raw.append(data)
        parsed = [json.loads(v) for v in raw]
        receipt = verify_reports(parsed)
        receipt["input_sha256"] = [hashlib.sha256(v).hexdigest() for v in raw]
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0
    except Refusal as error:
        print(json.dumps({
            "schema": MATRIX_SCHEMA, "status": "refused",
            "reason": error.label, "production_authority": False,
            "v6_ha_qualified": False,
        }, sort_keys=True))
        return 77
    except (OSError, ValueError, TypeError, UnicodeError):
        print(json.dumps({
            "schema": MATRIX_SCHEMA, "status": "refused",
            "reason": "MATRIX_INVALID_INPUT", "production_authority": False,
            "v6_ha_qualified": False,
        }, sort_keys=True))
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
