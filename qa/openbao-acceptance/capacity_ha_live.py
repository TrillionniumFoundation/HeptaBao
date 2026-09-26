#!/usr/bin/env python3
"""Prove lower-only owner capacity fencing during real three-process HA catch-up.

Uses only fresh synthetic loopback state and a fixture-capacity-limit binary.
This is not multi-host, full replacement, release or independent qualification.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error

from ha_certificate_rotation import replace_json
from ha_destructive import Cluster, FixtureError, Node, checked_binary

OWNER_LIMIT = 2 * 1024 * 1024
LOW_LIMIT = 1024 * 1024
PAYLOAD_BYTES = 224 * 1024


def set_limit(node: Node, limit: int) -> None:
    if node.process is not None:
        raise FixtureError("capacity_configuration_requires_stopped_process")
    config = json.loads((node.root / "server.json").read_text())
    config["fixture_opaque_owner_limit_bytes"] = limit
    replace_json(node.root / "server.json", config)


class CapacityCluster(Cluster):
    def wait_capacity_fence(self, node: Node) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                status, health = node.call("GET", "sys/health", timeout=2)
            except (OSError, urllib.error.URLError, TimeoutError):
                time.sleep(0.1)
                continue
            if status == 200:
                raise FixtureError("over_capacity_elected_node_claimed_ready")
            if health.get("ha_active") is True:
                self.check("capacity_elected_node_is_fenced", status == 503)
                self.check("capacity_fence_keeps_committed_outcome", health.get("recovery_required") is True)
                self.check("capacity_fence_cannot_claim_application_ready", health.get("ha_application_ready") is False)
                self.check("capacity_fence_is_not_a_lost_unseal_key", health.get("sealed") is False)
                return
            time.sleep(0.1)
        raise FixtureError("capacity_fenced_leader_not_observed")

    def run(self) -> None:
        for node in self.nodes:
            set_limit(node, OWNER_LIMIT)
        self.bootstrap()
        leader = self.leader()
        low = next(node for node in self.nodes if node is not leader)
        spectator = next(node for node in self.nodes if node not in (leader, low))
        low.stop()
        set_limit(low, LOW_LIMIT)
        self.restart(low)
        self.check("capacity_lower_limit_follower_rejoins", self.leader() is leader)
        spectator.stop()
        self.check("capacity_test_retains_two_voter_quorum", len(self.running()) == 2)
        value = "x" * PAYLOAD_BYTES
        for index in range(5):
            self.write(leader, f"capacity-growth-{index}", value)
        status, capacity = leader.call("GET", "sys/internal/capacity", token=self.root_token)
        data = capacity.get("data", {})
        self.check("capacity_higher_limit_leader_acknowledges_state", status == 200)
        self.check("capacity_committed_owner_exceeds_follower_limit",
                   LOW_LIMIT < data.get("state_bytes", 0) < OWNER_LIMIT)
        self.check("capacity_diagnostic_is_not_admission_budget",
                   data.get("state_remaining_is_admission_budget") is False)
        status, _ = leader.call("POST", "sys/step-down", {}, token=self.root_token, timeout=15)
        self.check("capacity_leadership_transfer_acknowledged", status == 204)
        self.wait_capacity_fence(low)
        status, body = low.call("GET", "secret/data/capacity-growth-0", token=self.root_token)
        self.check("capacity_fenced_leader_releases_no_stale_secret", status == 503 and "data" not in body)
        status, _ = low.call("GET", "sys/internal/capacity", token=self.root_token)
        self.check("capacity_fenced_leader_releases_no_stale_capacity", status == 503)
        status, _ = low.call("POST", "secret/data/capacity-denied", {"data": {"value": "never-admitted"}}, token=self.root_token)
        self.check("capacity_fenced_leader_rejects_new_mutation", status == 503)
        low.stop()
        set_limit(low, OWNER_LIMIT)
        self.restart(low)
        current = self.leader()
        if current is not low:
            status, _ = current.call("POST", "sys/step-down", {}, token=self.root_token, timeout=15)
            self.check("capacity_recovery_leadership_transfer_acknowledged", status == 204)
        self.check("capacity_recovered_node_becomes_current_leader", self.leader() is low)
        for index in range(5):
            self.read(low, f"capacity-growth-{index}", value)
        self.check("capacity_recovery_reads_all_committed_values", True)
        status, _ = low.call("GET", "secret/data/capacity-denied", token=self.root_token)
        self.check("capacity_rejected_mutation_never_replayed", status == 404)
        self.write(low, "capacity-recovered", "accepted-after-recovery")
        self.read(low, "capacity-recovered", "accepted-after-recovery")
        self.check("capacity_recovered_leader_accepts_fresh_mutation", True)
        self.restart(spectator)
        self.leader()
        for node in self.nodes:
            self.read(node, "capacity-recovered", "accepted-after-recovery")
        self.check("capacity_three_voters_rejoined_without_state_loss", True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    report = {"schema": "heptabao.capacity-ha.v1", "status": "not_run",
              "qualification": False, "independent_attestation": False,
              "compatibility_claim": False, "production_authority": False,
              "release_authority": False, "scenarios": []}
    started = time.monotonic()
    cluster = None
    code = 1
    try:
        report["binary_sha256"] = checked_binary(args.binary, args.expected_binary_sha256)
        cluster = CapacityCluster(args.binary, args.work_dir)
        cluster.run()
        checked_binary(args.binary, args.expected_binary_sha256)
        report["status"] = "pass_scoped_repository_fixture"
        report["node_count"] = 3
        code = 0
    except (FixtureError, OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, IndexError) as error:
        report["status"] = "failed"
        report["failure_class"] = str(error) if isinstance(error, FixtureError) else type(error).__name__
    finally:
        if cluster is not None:
            report["scenarios"] = cluster.scenarios
            try:
                cluster.close()
            except (FixtureError, OSError, subprocess.SubprocessError):
                report["status"], report["failure_class"], code = "failed", "cleanup_failed", 1
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["scenario_count"] = len(report["scenarios"])
    print(json.dumps(report, sort_keys=True, indent=2), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
