#!/usr/bin/env python3
"""Exercise response wrapping across real local HA forwarding and failures.

Uses only newly created owner-private synthetic state. The inherited baseline
scenarios are included in this profile, not additional independent coverage.
No production endpoint, live token, or mutation retry option is accepted.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import Cluster, FixtureError, checked_binary


class WrappingCluster(Cluster):
    def run(self) -> None:
        super().run()
        leader = self.leader()
        standby = next(node for node in self.nodes if node is not leader)
        payload = {"value": secrets.token_hex(24), "synthetic_only": True}
        status, body = standby.call("POST", "sys/wrapping/wrap", payload,
                                    token=self.root_token, wrap_ttl="300s")
        self.check("wrapping.standby_header_capture", status == 200 and body.get("data") is None)
        info = body.get("wrap_info", {})
        self.check("wrapping.forwarded_options_preserved", info.get("ttl") == 300
                   and info.get("creation_path") == "sys/wrapping/wrap" and bool(info.get("token")))
        token = info["token"]
        for node in self.nodes:
            status, metadata = node.call("POST", "sys/wrapping/lookup", {"token": token})
            self.check(f"wrapping.lookup_node_{node.node_id}", status == 200
                       and metadata.get("data", {}).get("creation_ttl") == 300
                       and "response" not in metadata.get("data", {}))
        leader.stop()
        successor = self.leader()
        self.check("wrapping.leader_killed_before_unwrap", successor is not leader)
        follower = next(node for node in self.running() if node is not successor)
        status, recovered = follower.call("POST", "sys/wrapping/unwrap", {}, token=token)
        self.check("wrapping.failover_unwrap_exact_response", status == 200 and recovered.get("data") == payload)
        self.restart(leader)
        self.leader()
        for node in self.nodes:
            self.check(f"wrapping.replay_node_{node.node_id}",
                       node.call("POST", "sys/wrapping/unwrap", {}, token=token)[0] == 400)
        # Quorum rejection cannot release data or turn into an automatic retry.
        leader = self.leader()
        status, body = leader.call("POST", "sys/wrapping/wrap", payload,
                                   token=self.root_token, wrap_ttl="300s")
        self.check("wrapping.quorum_probe_issued", status == 200)
        pending = body["wrap_info"]["token"]
        peers = [node for node in self.nodes if node is not leader]
        for peer in peers:
            peer.stop()
        time.sleep(1.5)
        status, rejected = leader.call("POST", "sys/wrapping/unwrap", {}, token=pending)
        self.check("wrapping.quorum_loss_withholds_payload", status == 503 and rejected.get("data") is None)
        for peer in peers:
            self.restart(peer)
        self.leader()
        # Explicit reconciliation: metadata must prove the original token remains
        # before a new, deliberate attempt. Never retry an ambiguous unwrap blindly.
        status, metadata = leader.call("POST", "sys/wrapping/lookup", {"token": pending})
        self.check("wrapping.reconciled_unconsumed_after_quorum_recovery", status == 200
                   and metadata.get("data", {}).get("creation_path") == "sys/wrapping/wrap")
        status, recovered = leader.call("POST", "sys/wrapping/unwrap", {}, token=pending)
        self.check("wrapping.recovered_single_release", status == 200 and recovered.get("data") == payload)
        for node in self.nodes:
            node.stop()
            self.restart(node)
            self.leader()
            self.check(f"wrapping.restart_replay_node_{node.node_id}",
                       node.call("POST", "sys/wrapping/unwrap", {}, token=pending)[0] == 400)


def main(*, cluster_type=WrappingCluster, profile="wrapping-ha", runner_path=None,
         scope="same-version loopback three-voter forwarding, process loss, quorum fencing and restart; includes baseline HA cases") -> int:
    if profile not in ("wrapping-ha", "ssh-otp-ha", "idle-lifecycle-ha"):
        raise ValueError("unknown local HA qualification profile")
    runner_path = Path(__file__) if runner_path is None else Path(runner_path)
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--lifecycle-interval-seconds", type=int, choices=range(61))
    args = parser.parse_args()
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).resolve()
    mode = output.parent.stat()
    if output.exists() or mode.st_uid != os.geteuid() or mode.st_mode & 0o077:
        parser.error("new output in caller-owned mode 0700 directory required")
    digest = checked_binary(binary, args.expected_binary_sha256)
    temporary = Path(tempfile.mkdtemp(prefix="heptabao-wrapping-ha-"))
    temporary.chmod(0o700)
    cluster = None
    report = {"schema": "heptabao." + profile + ".v1", "synthetic_only": True,
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
              "source_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "lifecycle_interval_override": args.lifecycle_interval_seconds,
              "binary_sha256": digest, "runner_sha256": file_hash(runner_path),
              "wrapping_harness_sha256": file_hash(Path(__file__)),
              "baseline_harness_sha256": file_hash(Path(__file__).with_name("ha_destructive.py")),
              "scenarios": [], "independent_qualification": False,
              "full_openbao_compatibility": False, "production_authority": False,
              "scope": scope,
              "started_at_unix": time.time()}
    try:
        cluster = cluster_type(binary, temporary / "cluster")
        if args.lifecycle_interval_seconds is not None:
            for node in cluster.nodes:
                configuration = node.root / "server.json"
                values = json.loads(configuration.read_text())
                values["lifecycle_interval_seconds"] = args.lifecycle_interval_seconds
                configuration.write_text(json.dumps(values))
                configuration.chmod(0o600)
        cluster.run()
        checked_binary(binary, digest)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["failure"] = str(error) if isinstance(error, FixtureError) else type(error).__name__
    finally:
        if cluster is not None:
            report["scenarios"] = cluster.scenarios
            try:
                cluster.close()
            except Exception:
                report["status"], report["failure"] = "failed", "process_cleanup_failed"
        try:
            shutil.rmtree(temporary)
        except OSError:
            report["status"], report["failure"] = "failed", "private_fixture_cleanup_failed"
        report["scenario_count"] = len(report["scenarios"])
        report["finished_at_unix"] = time.time()
        private_write(output, report)
    print(json.dumps({"status": report["status"], "count": report["scenario_count"], "failure": report.get("failure")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
