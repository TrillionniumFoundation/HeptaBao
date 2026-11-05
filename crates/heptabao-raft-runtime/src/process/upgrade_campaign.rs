//! A configured, bounded upgrade campaign; never entered by a client request.
use super::MembershipObservation;
use super::network::RemoteRaftError;
use super::node::ProcessRaftNode;
use openraft::Instant as _;
use openraft::async_runtime::WatchReceiver;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

const UPGRADE_CAMPAIGN_INTERVAL: Duration = Duration::from_millis(2500);

impl ProcessRaftNode {
    /// Called once during an explicitly configured legacy-wire process reopen.
    /// This is a real election, not a transfer authorization or read witness.
    /// Votes still apply the actual lease, log and committed membership rules.
    pub async fn campaign_for_legacy_upgrade_before(
        &self,
        deadline: Instant,
    ) -> Result<MembershipObservation, RemoteRaftError> {
        let deadline = tokio::time::Instant::from_std(deadline);
        let receiver = self.raft.metrics();
        let membership = {
            let metrics = receiver.borrow_watched();
            let membership = &metrics.membership_config;
            let voters = membership.voter_ids().collect::<BTreeSet<_>>();
            let nodes = membership
                .nodes()
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>();
            let enrolled = self.peer_network.enrolled_peer_ids();
            if metrics.running_state.is_err()
                || membership != &metrics.committed_membership_config
                || membership.get_joint_config().len() != 1
                || !voters.contains(&self.id)
                || voters.len() < 3
                || !voters.is_subset(enrolled)
                || !nodes.is_subset(enrolled)
                || membership.log_id().as_ref().is_none()
                || metrics.last_applied < *membership.log_id()
            {
                return Err(RemoteRaftError::InvalidTopology);
            }
            membership.clone()
        };
        let mut next_campaign = tokio::time::Instant::now();
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(RemoteRaftError::Consensus(
                    "legacy upgrade campaign deadline exceeded".into(),
                ));
            }
            let (leader, term) = {
                let metrics = receiver.borrow_watched();
                if metrics.running_state.is_err()
                    || metrics.membership_config != membership
                    || metrics.committed_membership_config != membership
                    || metrics.last_applied < *membership.log_id()
                {
                    return Err(RemoteRaftError::InvalidTopology);
                }
                (metrics.current_leader, metrics.current_term)
            };
            // A capable leader may already have won through normal consensus.
            // Remote peer-v1 cannot satisfy this current ReadIndex protocol.
            if leader.is_some() {
                let probe_end = deadline.min(now + Duration::from_millis(750));
                if super::follower_read::ensure_node_read(self, probe_end)
                    .await
                    .is_ok()
                {
                    let metrics = receiver.borrow_watched();
                    if tokio::time::Instant::now() < deadline
                        && metrics.running_state.is_ok()
                        && metrics.current_leader == leader
                        && metrics.current_term == term
                        && metrics.membership_config == membership
                        && metrics.committed_membership_config == membership
                        && metrics.last_applied >= *membership.log_id()
                    {
                        let observed = MembershipObservation {
                            local_id: self.id,
                            leader,
                            term,
                            membership_index: membership.log_id().as_ref().map(|l| l.index),
                            committed: true,
                            joint: false,
                            voters: membership.voter_ids().collect(),
                            nodes: membership.nodes().map(|(id, _)| *id).collect(),
                            applied_index: metrics.last_applied.map(|l| l.index),
                            snapshot_index: metrics.snapshot.map(|l| l.index),
                            purged_index: metrics.purged.map(|l| l.index),
                            peer_matched: metrics
                                .replication
                                .clone()
                                .unwrap_or_default()
                                .iter()
                                .map(|(id, log)| (*id, log.as_ref().map(|l| l.index)))
                                .collect(),
                            peer_contact_ms: metrics
                                .heartbeat
                                .clone()
                                .unwrap_or_default()
                                .iter()
                                .map(|(id, t)| {
                                    (
                                        *id,
                                        t.as_ref().map(|t| {
                                            t.elapsed().as_millis().min(u64::MAX as u128) as u64
                                        }),
                                    )
                                })
                                .collect(),
                        };
                        return Ok(observed);
                    }
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                continue;
            }
            if now >= next_campaign {
                // false means ordinary real election. It does NOT mark the
                // VoteRequest as leadership_transfer or bypass voter leases.
                tokio::time::timeout_at(deadline, self.raft.trigger().elect(false))
                    .await
                    .map_err(|_| {
                        RemoteRaftError::Consensus(
                            "legacy upgrade campaign deadline exceeded".into(),
                        )
                    })?
                    .map_err(|error| RemoteRaftError::Consensus(error.to_string()))?;
                next_campaign = now + UPGRADE_CAMPAIGN_INTERVAL;
            }
            tokio::time::sleep_until(
                deadline.min(tokio::time::Instant::now() + Duration::from_millis(25)),
            )
            .await;
        }
    }
}
