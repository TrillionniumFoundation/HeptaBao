#!/usr/bin/env python3
"""Exercise replay-epoch retirement through a real three-process TLS/Raft lifecycle.

The fixture extends the repository's destructive HA harness with repeated replay-epoch
transitions, including a voter that remains offline across multiple committed epochs.
It proves only the named exact-binary scenarios on private synthetic loopback state.
It is not multi-host, independent, release, migration, or production qualification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error

from ha_destructive import Cluster, FixtureError, Node, checked_binary


class ReplayEpochCluster(Cluster):
    def replay_capacity(self, node: Node) -> dict[str, object]:
        status, body = node.call(
            "GET",
            "sys/internal/storage/capacity",
            token=self.root_token,
            timeout=10,
        )
        if status != 200:
            raise FixtureError("replay_capacity_unavailable_on_active_node")
        data = body.get("data")
        if not isinstance(data, dict):
            raise FixtureError("replay_capacity_missing_data")
        if type(data.get("replay_epoch")) is not int or data["replay_epoch"] < 0:
            raise FixtureError("replay_capacity_invalid_epoch")
        if type(data.get("retained_requests")) is not int or data["retained_requests"] < 0:
            raise FixtureError("replay_capacity_invalid_retained_request_count")
        if data.get("replay_retirement") != "raft-coordinated":
            raise FixtureError("replay_retirement_not_raft_coordinated")
        return data

    def retire_epoch(self, leader: Node, expected_previous: int, scenario: str) -> int:
        status, body = leader.call(
            "POST",
            "sys/storage/raft/replay-retire",
            {},
            token=self.root_token,
            timeout=15,
        )
        data = body.get("data") if isinstance(body, dict) else None
        if (
            status != 200
            or not isinstance(data, dict)
            or data.get("previous_epoch") != expected_previous
            or data.get("replay_epoch") != expected_previous + 1
            or data.get("cluster_coordinated") is not True
            or type(data.get("retired_requests")) is not int
            or data["retired_requests"] <= 0
        ):
            raise FixtureError(scenario)
        self.check(scenario, True)
        return expected_previous + 1

    def run(self) -> None:
        # First establish all of the ordinary three-process HA, snapshot/catch-up,
        # leader SIGKILL, quorum-loss and rejoin invariants from the existing
        # destructive fixture. Replay retirement is then exercised on the same
        # live cluster rather than a weaker in-process simulation.
        super().run()

        leader_before = self.leader()
        before = self.replay_capacity(leader_before)
        initial_epoch = int(before["replay_epoch"])
        self.check("replay_epoch_initial_active_leader_observed", initial_epoch >= 0)
        self.check(
            "replay_ledger_populated_before_retirement",
            int(before["retained_requests"]) > 0,
        )

        pre_value = secrets.token_hex(16)
        self.write(leader_before, "replay-before-retirement", pre_value)
        target_epoch = self.retire_epoch(
            leader_before,
            initial_epoch,
            "first_replay_epoch_retirement_committed_by_raft",
        )
        retired = self.replay_capacity(leader_before)
        self.check(
            "first_retirement_converged_on_active_leader",
            retired["replay_epoch"] == target_epoch,
        )

        post_value = secrets.token_hex(16)
        self.write(leader_before, "replay-after-retirement", post_value)
        self.check("post_retirement_mutation_acknowledged_in_new_epoch", True)

        # Killing the acknowledged leader forces a former follower to become the
        # serving leader. Its first capacity observation and write therefore pass
        # through its own local durable replay-epoch checks; a stale local ledger
        # cannot hide behind standby request forwarding.
        leader_before.stop()
        leader_after = self.leader()
        self.check("leader_sigkill_after_epoch_retirement", leader_after is not leader_before)
        after_failover = self.replay_capacity(leader_after)
        self.check(
            "former_follower_became_leader_with_committed_replay_epoch",
            after_failover["replay_epoch"] == target_epoch,
        )
        follower_value = secrets.token_hex(16)
        self.write(leader_after, "replay-former-follower-write", follower_value)
        self.check("former_follower_commits_in_retired_epoch_after_failover", True)

        # Rejoin the killed leader, then make it authoritative again. If another
        # node still leads, leave exactly the restarted node plus that leader as a
        # two-of-three quorum and use the authenticated leadership-transfer route.
        # Once the restarted process is leader, the observation/write are local.
        self.restart(leader_before)
        current = self.leader()
        spectator: Node | None = None
        if current is not leader_before:
            spectator = next(
                node
                for node in self.running()
                if node is not current and node is not leader_before
            )
            spectator.stop()
            self.check("leadership_transfer_uses_two_of_three_live_voters", len(self.running()) == 2)
            status, _ = current.call(
                "POST",
                "sys/step-down",
                {},
                token=self.root_token,
                timeout=15,
            )
            self.check("leadership_transfer_to_restarted_epoch_node_acknowledged", status == 204)
            restarted_leader = self.leader()
            self.check("restarted_original_leader_became_authoritative", restarted_leader is leader_before)
        else:
            restarted_leader = leader_before
            self.check("restarted_original_leader_became_authoritative", True)

        restarted_capacity = self.replay_capacity(restarted_leader)
        self.check(
            "restarted_original_leader_preserved_replay_epoch",
            restarted_capacity["replay_epoch"] == target_epoch,
        )
        rejoin_value = secrets.token_hex(16)
        self.write(restarted_leader, "replay-restarted-leader-write", rejoin_value)
        self.check("restarted_original_leader_commits_in_retired_epoch", True)

        if spectator is not None:
            self.restart(spectator)
            self.leader()
            self.check("third_voter_rejoined_after_epoch_leadership_transfer", True)

        # Repeat retirement after leadership has changed and force another leader
        # loss. This rejects a one-shot/single-leader implementation of epochs.
        second_leader = self.leader()
        second_epoch = self.retire_epoch(
            second_leader,
            target_epoch,
            "second_replay_epoch_retirement_after_leader_change_committed_by_raft",
        )
        second_capacity = self.replay_capacity(second_leader)
        self.check(
            "second_retirement_converged_on_active_leader",
            second_capacity["replay_epoch"] == second_epoch,
        )
        second_leader.stop()
        final_leader = self.leader()
        self.check("second_epoch_survives_second_leader_sigkill", final_leader is not second_leader)
        final_capacity = self.replay_capacity(final_leader)
        self.check(
            "second_former_follower_became_leader_with_latest_epoch",
            final_capacity["replay_epoch"] == second_epoch,
        )
        final_value = secrets.token_hex(16)
        self.write(final_leader, "replay-second-failover-write", final_value)
        self.check("second_failover_mutation_commits_in_latest_epoch", True)

        self.restart(second_leader)
        final_leader = self.leader()
        for node, path, value in (
            (final_leader, "replay-before-retirement", pre_value),
            (final_leader, "replay-after-retirement", post_value),
            (final_leader, "replay-former-follower-write", follower_value),
            (final_leader, "replay-restarted-leader-write", rejoin_value),
            (final_leader, "replay-second-failover-write", final_value),
        ):
            self.read(node, path, value)
        self.check("all_replay_lifecycle_acknowledgements_read_back_after_rejoin", True)

        # Keep one voter completely offline while the two-voter quorum commits two
        # additional +1 retirements. Restarting that voter then presents it with a
        # committed state two epochs ahead of its local durable replay authority.
        # Make the laggard authoritative before inspecting capacity so standby
        # forwarding cannot conceal a failure to catch up its local ledger.
        current = self.leader()
        laggard = next(node for node in self.running() if node is not current)
        laggard.stop()
        self.check("multi_epoch_laggard_offline_with_two_voter_quorum", len(self.running()) == 2)

        third_epoch = self.retire_epoch(
            current,
            second_epoch,
            "third_replay_epoch_retirement_while_laggard_offline",
        )
        third_value = secrets.token_hex(16)
        self.write(current, "replay-laggard-offline-epoch-one", third_value)
        self.check("two_voter_quorum_commits_after_first_missed_epoch", True)

        fourth_epoch = self.retire_epoch(
            current,
            third_epoch,
            "fourth_replay_epoch_retirement_while_laggard_offline",
        )
        fourth_value = secrets.token_hex(16)
        self.write(current, "replay-laggard-offline-epoch-two", fourth_value)
        self.check("two_voter_quorum_commits_after_second_missed_epoch", True)
        snapshot_status, _ = current.call(
            "GET",
            "sys/storage/raft/snapshot",
            token=self.root_token,
            timeout=15,
        )
        self.check("raft_snapshot_triggered_after_multiple_missed_epochs", snapshot_status == 200)

        self.restart(laggard)
        current = self.leader()
        transfer_spectator = next(
            node
            for node in self.running()
            if node is not current and node is not laggard
        )
        transfer_spectator.stop()
        self.check("multi_epoch_catchup_transfer_uses_two_live_voters", len(self.running()) == 2)
        if current is not laggard:
            status, _ = current.call(
                "POST",
                "sys/step-down",
                {},
                token=self.root_token,
                timeout=15,
            )
            self.check("leadership_transfer_to_multi_epoch_laggard_acknowledged", status == 204)
        laggard_leader = self.leader()
        self.check("multi_epoch_laggard_became_authoritative", laggard_leader is laggard)
        laggard_capacity = self.replay_capacity(laggard_leader)
        self.check(
            "multi_epoch_laggard_local_replay_authority_caught_up",
            laggard_capacity["replay_epoch"] == fourth_epoch,
        )
        laggard_value = secrets.token_hex(16)
        self.write(laggard_leader, "replay-multi-epoch-laggard-write", laggard_value)
        self.check("multi_epoch_laggard_commits_after_catchup", True)

        self.restart(transfer_spectator)
        stable_leader = self.leader()
        for path, value in (
            ("replay-laggard-offline-epoch-one", third_value),
            ("replay-laggard-offline-epoch-two", fourth_value),
            ("replay-multi-epoch-laggard-write", laggard_value),
        ):
            self.read(stable_leader, path, value)
        self.check("multi_epoch_catchup_acknowledgements_read_back_after_full_rejoin", True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()

    report: dict[str, object] = {
        "schema": "heptabao.replay-epoch-ha.v1",
        "status": "not_run",
        "scenarios": [],
        "node_count": 3,
        "scope": "repository-controlled-private-loopback-three-process-raft",
        "qualification": False,
        "compatibility_claim": False,
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "independent_attestation": False,
        "uncovered": [
            "multi_host_replay_epoch_transition",
            "power_loss_during_epoch_transition",
            "disk_full_or_permission_fault_during_epoch_transition",
            "network_partition_during_epoch_transition",
            "forced_snapshot_install_across_epoch",
            "rolling_version_upgrade_across_epoch",
            "more_than_32000_real_operations_between_retirements",
            "independent_reproduction",
        ],
    }
    cluster: ReplayEpochCluster | None = None
    started = time.monotonic()
    return_code = 1
    try:
        report["binary_sha256"] = checked_binary(args.binary, args.expected_binary_sha256)
        cluster = ReplayEpochCluster(args.binary, args.work_dir)
        report["status"] = "running"
        cluster.run()
        checked_binary(args.binary, args.expected_binary_sha256)
        report["status"] = "pass_scoped_repository_fixture"
        return_code = 0
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
        report["failure_class"] = str(error) if isinstance(error, FixtureError) else type(error).__name__
    finally:
        if cluster is not None:
            report["scenarios"] = cluster.scenarios
            try:
                cluster.close()
            except (FixtureError, OSError, subprocess.SubprocessError):
                report["status"] = "failed"
                report["failure_class"] = "cleanup_failed"
                return_code = 1
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["scenario_count"] = len(report["scenarios"])
    print(json.dumps(report, sort_keys=True, indent=2))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
