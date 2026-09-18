#!/usr/bin/env python3
"""Exercise authenticated Raft leadership transfer on a real three-process cluster.

This is a same-version loopback qualification fixture. It proves bounded manual
leadership transfer and post-transfer forwarding; it is not mixed-version,
multi-host, WAN, power-loss, or production qualification.
"""
from pathlib import Path
import secrets

from ha_destructive import Cluster
from wrapping_ha import main as run_ha


class StepDownCluster(Cluster):
    def run(self):
        super().run()
        original = self.leader()
        original_id = original.node_id
        status, body = original.call("POST", "sys/step-down", {}, token=self.root_token, timeout=10)
        self.check("step_down.accepted_by_current_leader", status == 204 and body == {})
        successor = self.leader()
        self.check("step_down.changed_leader", successor.node_id != original_id)
        status, leader = successor.call("GET", "sys/leader", token=self.root_token)
        self.check("step_down.successor_reports_authority", status == 200 and leader.get("is_self") is True)
        forwarded = secrets.token_hex(16)
        self.write(original, "after-explicit-step-down", forwarded)
        self.read(successor, "after-explicit-step-down", forwarded)
        self.check("step_down.old_leader_forwards_after_transfer", True)
        status, denied = successor.call("POST", "sys/step-down", {"unexpected": True}, token=self.root_token)
        self.check("step_down.rejects_nonempty_body", status == 400 and bool(denied.get("errors")))
        status, denied = successor.call("POST", "sys/step-down", {}, token="")
        self.check("step_down.requires_authentication", status == 403 and bool(denied.get("errors")))


if __name__ == "__main__":
    raise SystemExit(run_ha(
        cluster_type=StepDownCluster,
        profile="ha-step-down",
        runner_path=Path(__file__),
        scope="same-version loopback three-voter explicit leadership transfer and forwarding; includes core HA; no mixed-version or multi-host qualification",
    ))
