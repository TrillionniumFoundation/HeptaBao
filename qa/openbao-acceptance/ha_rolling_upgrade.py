#!/usr/bin/env python3
"""Roll a real three-process HA cluster from the PR base binary to the candidate.

The fixture owns all state and loopback endpoints. It proves only one repository
version step (the exact PR base to the exact candidate) and never upgrades an
existing deployment. Availability and acknowledged data are checked after every
node replacement; replay retirement is exercised only after every voter runs the
candidate so an old binary is never asked to interpret a new epoch schema.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error

from ha_destructive import Cluster, FixtureError, Node, checked_binary


def running_digest(node: Node) -> str:
    if node.process is None:
        raise FixtureError("rolling_upgrade_node_not_running")
    executable = Path("/proc") / str(node.process.pid) / "exe"
    try:
        return hashlib.sha256(executable.read_bytes()).hexdigest()
    except OSError as error:
        raise FixtureError("rolling_upgrade_running_binary_unreadable") from error


class RollingUpgradeCluster(Cluster):
    def __init__(self, base_binary: Path, candidate_binary: Path, root: Path):
        self.candidate_binary = candidate_binary
        self.base_digest = hashlib.sha256(base_binary.read_bytes()).hexdigest()
        self.candidate_digest = hashlib.sha256(candidate_binary.read_bytes()).hexdigest()
        super().__init__(base_binary, root)

    def leader(self) -> Node:
        """Resolve one stable leader across the exact base/candidate health schema.

        The exact base predates ``ha_application_ready``. Accept that missing
        field only while /proc proves the process is the pinned base binary.
        Candidate processes must expose and assert the stronger readiness bit.
        """
        deadline = time.monotonic() + 30
        previous, stable_since = None, None
        while time.monotonic() < deadline:
            active = []
            for node in self.running():
                try:
                    status, health = node.call("GET", "sys/health", timeout=2)
                except (OSError, urllib.error.URLError, TimeoutError):
                    continue
                if status != 200:
                    continue
                digest = running_digest(node)
                if health.get("ha_active") is not True or health.get("standby") is not False:
                    raise FixtureError("health_success_without_active_authority")
                if digest == self.candidate_digest:
                    if health.get("ha_application_ready") is not True:
                        raise FixtureError("candidate_health_success_without_application_readiness")
                elif digest == self.base_digest:
                    if "ha_application_ready" in health and health["ha_application_ready"] is not True:
                        raise FixtureError("base_health_explicitly_not_application_ready")
                else:
                    raise FixtureError("rolling_upgrade_unknown_running_binary")
                active.append(node)
            if len(active) > 1:
                raise FixtureError("multiple_active_health_responses")
            if len(active) == 1:
                node = active[0]
                status, body = node.call("GET", "sys/leader", token=self.root_token)
                if status == 200 and body.get("is_self") is True:
                    observed = time.monotonic()
                    if previous is not node:
                        previous, stable_since = node, observed
                    elif observed - stable_since >= 2.2:
                        return node
                else:
                    previous, stable_since = None, None
            else:
                previous, stable_since = None, None
            time.sleep(0.1)
        raise FixtureError("unique_active_leader_not_observed")

    def read(self, node: Node, path: str, value: str) -> None:
        """Read without retrying writes and retain bounded mixed-version diagnostics."""
        deadline = time.monotonic() + 30
        last_status = None
        while time.monotonic() < deadline:
            try:
                status, body = node.call(
                    "GET", f"secret/data/{path}", token=self.root_token
                )
            except (OSError, urllib.error.URLError, TimeoutError):
                time.sleep(0.1)
                continue
            last_status = status
            if status == 200:
                if body.get("data", {}).get("data", {}).get("value") != value:
                    raise FixtureError("successful_read_returned_stale_or_wrong_data")
                return
            if status not in (429, 503):
                raise FixtureError("acknowledged_write_not_visible")
            time.sleep(0.1)
        try:
            health_status, health = node.call("GET", "sys/health", timeout=2)
            detail = (
                f"node_{node.node_id}_last_{last_status}_health_{health_status}"
                f"_active_{health.get('ha_active')}_ready_{health.get('ha_application_ready')}"
                f"_standby_{health.get('standby')}_sealed_{health.get('sealed')}"
                f"_recovery_{health.get('recovery_required')}"
            )
        except (OSError, urllib.error.URLError, TimeoutError):
            detail = f"node_{node.node_id}_last_{last_status}_health_unavailable"
        raise FixtureError("readback_timeout_" + detail)

    def set_legacy_forward_transition(self, node: Node, enabled: bool,
                                      *, emit_legacy: bool | None = None) -> None:
        if node.process is not None:
            raise FixtureError("rolling_wire_configuration_requires_stopped_node")
        if emit_legacy is True and not enabled:
            raise FixtureError("rolling_legacy_sender_requires_legacy_receiver")
        config_path = node.root / "ha.json"
        config = json.loads(config_path.read_text())
        if enabled:
            config["allow_legacy_peer_v1"] = True
        else:
            config.pop("allow_legacy_peer_v1", None)
        if emit_legacy is None:
            config.pop("emit_legacy_peer_v1", None)
        else:
            config["emit_legacy_peer_v1"] = emit_legacy
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)

    def upgrade(self, node: Node, label: str) -> None:
        node.stop()
        node.binary = self.candidate_binary
        self.set_legacy_forward_transition(node, True)
        node.start()
        if node.call("POST", "sys/unseal", {"key": self.unseal_key})[0] != 200:
            raise FixtureError(label + "_candidate_unseal_failed")
        self.leader()
        self.check(label + "_candidate_process_digest",
                   running_digest(node) == self.candidate_digest)

    def retire_epoch(self, leader: Node, previous: int) -> int:
        status, body = leader.call(
            "POST", "sys/storage/raft/replay-retire", {},
            token=self.root_token, timeout=15,
        )
        data = body.get("data") if isinstance(body, dict) else None
        if (
            status != 200
            or not isinstance(data, dict)
            or data.get("previous_epoch") != previous
            or data.get("replay_epoch") != previous + 1
            or data.get("cluster_coordinated") is not True
        ):
            raise FixtureError("rolling_upgrade_post_upgrade_replay_retirement_failed")
        return previous + 1

    def replay_epoch(self, leader: Node) -> int:
        status, body = leader.call(
            "GET", "sys/internal/storage/capacity",
            token=self.root_token, timeout=10,
        )
        data = body.get("data") if isinstance(body, dict) else None
        if status != 200 or not isinstance(data, dict) or type(data.get("replay_epoch")) is not int:
            raise FixtureError("rolling_upgrade_replay_epoch_unavailable")
        return int(data["replay_epoch"])

    def run(self) -> None:
        super().run()
        self.check(
            "rolling_upgrade_all_nodes_started_on_base_binary",
            all(running_digest(node) == self.base_digest for node in self.nodes),
        )
        leader = self.leader()
        baseline = secrets.token_hex(16)
        self.write(leader, "rolling-upgrade-baseline", baseline)

        upgraded: set[int] = set()
        for ordinal in (1, 2):
            leader = self.leader()
            candidates = [
                node for node in self.nodes
                if node.node_id not in upgraded and node is not leader
            ]
            if not candidates:
                raise FixtureError("rolling_upgrade_no_follower_candidate")
            node = candidates[0]
            self.upgrade(node, f"rolling_upgrade_follower_{ordinal}")
            upgraded.add(node.node_id)
            leader = self.leader()
            value = secrets.token_hex(16)
            self.write(leader, f"rolling-upgrade-after-follower-{ordinal}", value)
            for running in self.nodes:
                self.read(running, f"rolling-upgrade-after-follower-{ordinal}", value)
            self.check(f"rolling_upgrade_mixed_version_write_{ordinal}", True)
            if ordinal == 1:
                status, _ = leader.call(
                    "GET", "sys/storage/raft/snapshot",
                    token=self.root_token, timeout=20,
                )
                self.check("rolling_upgrade_snapshot_with_one_candidate_voter", status == 200)

        old = next(node for node in self.nodes if node.node_id not in upgraded)
        old.stop()
        leader = self.leader()
        self.check(
            "rolling_upgrade_candidate_majority_serves_while_old_voter_down",
            running_digest(leader) == self.candidate_digest,
        )
        majority_value = secrets.token_hex(16)
        self.write(leader, "rolling-upgrade-candidate-majority", majority_value)
        self.upgrade(old, "rolling_upgrade_final_voter")
        upgraded.add(old.node_id)
        self.check("rolling_upgrade_all_three_candidate_voters", len(upgraded) == 3)

        # First retire legacy *senders* while every receiver still accepts
        # both formats. Closing receive admission at the same time would
        # partition the remaining legacy senders during a rolling restart.
        for node in self.nodes:
            node.stop()
            self.set_legacy_forward_transition(node, True, emit_legacy=False)
            node.start()
            if node.call("POST", "sys/unseal", {"key": self.unseal_key})[0] != 200:
                raise FixtureError(f"rolling_upgrade_node_{node.node_id}_sender_restart_unseal_failed")
            self.leader()
            config = json.loads((node.root / "ha.json").read_text())
            self.check(f"rolling_upgrade_node_{node.node_id}_strict_sender_dual_receiver",
                       config.get("allow_legacy_peer_v1") is True
                       and config.get("emit_legacy_peer_v1") is False)
            marker = secrets.token_hex(16)
            self.write(node, f"rolling-new-wire-{node.node_id}", marker)
            for observer in self.nodes:
                self.read(observer, f"rolling-new-wire-{node.node_id}", marker)
            self.check(f"rolling_upgrade_node_{node.node_id}_new_wire_write_observed", True)
        self.check("rolling_upgrade_all_senders_current_before_any_receiver_closes", True)

        # The compatibility wire is an upgrade-only bridge. Restart each
        # candidate one at a time with the flag removed, preserving quorum,
        # then prove the strict cluster-bound current wire across all voters.
        for node in self.nodes:
            node.stop()
            self.set_legacy_forward_transition(node, False)
            node.start()
            if node.call("POST", "sys/unseal", {"key": self.unseal_key})[0] != 200:
                raise FixtureError(
                    f"rolling_upgrade_node_{node.node_id}_strict_restart_unseal_failed"
                )
            self.leader()
            self.check(
                f"rolling_upgrade_node_{node.node_id}_legacy_forwarding_disabled",
                not {"allow_legacy_peer_v1", "emit_legacy_peer_v1"}
                & json.loads((node.root / "ha.json").read_text()).keys(),
            )
        self.check("rolling_upgrade_strict_current_wire_restored", True)

        leader = self.leader()
        for node in self.nodes:
            self.check(
                f"rolling_upgrade_node_{node.node_id}_candidate_digest",
                running_digest(node) == self.candidate_digest,
            )
            self.read(node, "rolling-upgrade-baseline", baseline)
            self.read(node, "rolling-upgrade-candidate-majority", majority_value)
        self.check("rolling_upgrade_preexisting_and_mixed_writes_survive", True)

        previous = self.replay_epoch(leader)
        current = self.retire_epoch(leader, previous)
        after = secrets.token_hex(16)
        self.write(leader, "rolling-upgrade-after-epoch-retirement", after)
        old_leader = leader
        old_leader.stop()
        leader = self.leader()
        self.check("rolling_upgrade_post_epoch_failover", leader is not old_leader)
        self.check("rolling_upgrade_epoch_survives_failover", self.replay_epoch(leader) == current)
        self.restart(old_leader)
        self.leader()
        for node in self.nodes:
            self.read(node, "rolling-upgrade-after-epoch-retirement", after)
        self.check("rolling_upgrade_post_epoch_value_converged", True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-binary", required=True, type=Path)
    parser.add_argument("--base-sha256", required=True)
    parser.add_argument("--candidate-binary", required=True, type=Path)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()
    report = {
        "schema": "heptabao.ha-rolling-upgrade.v1",
        "status": "not_run",
        "scenarios": [],
        "scope": "exact-pr-base-to-exact-candidate-private-loopback-three-process",
        "qualification": False,
        "compatibility_claim": False,
        "production_authority": False,
        "release_authority": False,
        "independent_attestation": False,
        "mixed_version_replay_epoch_transition": False,
        "uncovered": [
            "multi_host_upgrade",
            "skipped_version_upgrade",
            "mixed_version_replay_epoch_transition",
            "upgrade_with_network_partition",
            "power_loss_during_upgrade",
            "independent_reproduction",
        ],
    }
    cluster = None
    code = 1
    started = time.monotonic()
    try:
        report["base_binary_sha256"] = checked_binary(args.base_binary, args.base_sha256)
        report["candidate_binary_sha256"] = checked_binary(
            args.candidate_binary, args.candidate_sha256
        )
        if report["base_binary_sha256"] == report["candidate_binary_sha256"]:
            raise FixtureError("rolling_upgrade_requires_distinct_binaries")
        cluster = RollingUpgradeCluster(
            args.base_binary, args.candidate_binary, args.work_dir
        )
        report["status"] = "running"
        cluster.run()
        checked_binary(args.base_binary, args.base_sha256)
        checked_binary(args.candidate_binary, args.candidate_sha256)
        report["status"] = "pass_scoped_repository_fixture"
        report["node_count"] = 3
        code = 0
    except (
        FixtureError,
        OSError,
        subprocess.SubprocessError,
        urllib.error.URLError,
        TimeoutError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        StopIteration,
    ) as error:
        report["status"] = "failed"
        report["failure_class"] = (
            str(error) if isinstance(error, FixtureError) else type(error).__name__
        )
    finally:
        if cluster is not None:
            report["scenarios"] = cluster.scenarios
            try:
                cluster.close()
            except (FixtureError, OSError, subprocess.SubprocessError):
                report["status"] = "failed"
                report["failure_class"] = "cleanup_failed"
                code = 1
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["scenario_count"] = len(report["scenarios"])
    print(json.dumps(report, sort_keys=True, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
