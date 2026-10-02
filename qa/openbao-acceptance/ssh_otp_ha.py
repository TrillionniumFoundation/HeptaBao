#!/usr/bin/env python3
"""Synthetic online OTP issuance/verification/revocation across actual HA.

The role does not configure an SSH host or invoke a PAM helper. This profile
includes the existing wrapping/HA baseline, so counts must not be summed.
"""
from pathlib import Path
from wrapping_ha import WrappingCluster, main as run_ha


class SshOtpCluster(WrappingCluster):
    def run(self) -> None:
        super().run()
        leader = self.leader()
        follower = next(node for node in self.nodes if node is not leader)
        mount = "ha-ssh"
        status, _ = follower.call("POST", "sys/mounts/" + mount,
                                  {"type":"ssh"}, token=self.root_token)
        self.check("ssh_ha.mount_through_follower", status == 204)
        status, _ = follower.call("POST", mount + "/roles/test", {
            "key_type":"otp", "default_user":"deploy", "cidr_list":"127.0.0.0/8"}, token=self.root_token)
        self.check("ssh_ha.role_through_follower", status == 204)
        status, wrapped = follower.call("POST", mount + "/creds/test", {"ip":"127.0.0.1"},
                                         token=self.root_token, wrap_ttl="300s")
        self.check("ssh_ha.wrapped_issue_hides_otp", status == 200 and wrapped.get("data") is None)
        wrapping_token = wrapped["wrap_info"]["token"]
        leader.stop()
        successor = self.leader()
        self.check("ssh_ha.new_leader", successor is not leader)
        recipient = next(node for node in self.nodes if node is not successor and node is not leader)
        status, issued = recipient.call("POST", "sys/wrapping/unwrap", {}, token=wrapping_token)
        self.check("ssh_ha.unwrap_after_failover", status == 200 and bool(issued.get("lease_id")))
        otp, lease = issued["data"]["key"], issued["lease_id"]
        status, verified = recipient.call("POST", mount + "/verify", {"otp":otp})
        self.check("ssh_ha.verify_forwarded_without_bearer", status == 200 and verified.get("data") == {
            "ip":"127.0.0.1", "username":"deploy", "role_name":"test"})
        self.check("ssh_ha.leader_denies_replay", successor.call("POST", mount + "/verify", {"otp":otp})[0] == 400)
        self.restart(leader)
        self.leader()
        self.check("ssh_ha.restarted_node_denies_replay", leader.call("POST", mount + "/verify", {"otp":otp})[0] == 400)
        status, metadata = leader.call("POST", "sys/leases/lookup", {"lease_id":lease}, token=self.root_token)
        self.check("ssh_ha.metadata_retained", status == 200 and metadata.get("data", {}).get("id") == lease)
        status, pending = leader.call("POST", mount + "/creds/test", {"ip":"127.0.0.1"}, token=self.root_token)
        self.check("ssh_ha.issue_for_revocation", status == 200)
        status, _ = recipient.call("POST", "sys/leases/revoke", {"lease_id":pending["lease_id"],"sync":True}, token=self.root_token)
        self.check("ssh_ha.revoke_forwarded", status == 204)
        for node in self.nodes:
            node.stop()
            self.restart(node)
            self.leader()
            self.check(f"ssh_ha.consumed_after_restart_{node.node_id}", node.call("POST", mount + "/verify", {"otp":otp})[0] == 400)
            self.check(f"ssh_ha.revoked_after_restart_{node.node_id}", node.call("POST", mount + "/verify", {"otp":pending["data"]["key"]})[0] == 400)


if __name__ == "__main__":
    raise SystemExit(run_ha(cluster_type=SshOtpCluster, profile="ssh-otp-ha", runner_path=Path(__file__),
                           scope="same-version loopback SSH OTP and local lease lifecycle, wrapping, leader failure and restart; includes wrapping and baseline HA scenarios; no SSH host login"))
