//! Observations of actual committed consensus state, not configured peer names.
//! Timeouts mean outcome unknown: callers must re-read the membership frontier.
use super::RemoteRaftError;
use super::node::ProcessRaftNode;
use openraft::{Instant, async_runtime::WatchReceiver, storage::RaftStateMachine};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

#[derive(Clone, Debug, Serialize)]
pub struct MembershipObservation {
    pub local_id: u64,
    pub leader: Option<u64>,
    pub term: u64,
    pub membership_index: Option<u64>,
    pub committed: bool,
    pub joint: bool,
    pub voters: BTreeSet<u64>,
    pub nodes: BTreeSet<u64>,
    pub applied_index: Option<u64>,
    pub snapshot_index: Option<u64>,
    pub purged_index: Option<u64>,
    pub peer_matched: BTreeMap<u64, Option<u64>>,
    pub peer_contact_ms: BTreeMap<u64, Option<u64>>,
}
#[derive(Clone, Debug, Serialize)]
pub struct SnapshotObservation {
    pub requested_index: u64,
    pub persisted_index: u64,
    pub byte_count: usize,
    pub sha256: [u8; 32],
}
impl ProcessRaftNode {
    pub async fn membership_observation(&self) -> Result<MembershipObservation, RemoteRaftError> {
        let metrics = self.raft.metrics().borrow_watched().clone();
        if metrics.running_state.is_err() {
            return Err(RemoteRaftError::Io("Raft is not healthy".into()));
        }
        let membership = &metrics.membership_config;
        Ok(MembershipObservation {
            local_id: self.id,
            leader: metrics.current_leader,
            term: metrics.current_term,
            membership_index: membership.log_id().as_ref().map(|l| l.index),
            committed: membership == &metrics.committed_membership_config,
            joint: membership.get_joint_config().len() != 1,
            voters: membership.voter_ids().collect(),
            nodes: membership.nodes().map(|(id, _)| *id).collect(),
            applied_index: metrics.last_applied.map(|l| l.index),
            snapshot_index: metrics.snapshot.map(|l| l.index),
            purged_index: metrics.purged.map(|l| l.index),
            peer_matched: metrics
                .replication
                .unwrap_or_default()
                .iter()
                .map(|(id, log)| (*id, log.as_ref().map(|l| l.index)))
                .collect(),
            peer_contact_ms: metrics
                .heartbeat
                .unwrap_or_default()
                .iter()
                .map(|(id, t)| {
                    (
                        *id,
                        t.as_ref()
                            .map(|t| t.elapsed().as_millis().min(u64::MAX as u128) as u64),
                    )
                })
                .collect(),
        })
    }
    pub async fn change_membership_guarded(
        &self,
        expected_index: u64,
        target: u64,
        operation: &str,
    ) -> Result<MembershipObservation, RemoteRaftError> {
        self.ensure_linearizable().await?;
        let before = self.membership_observation().await?;
        if before.leader != Some(self.id)
            || !before.committed
            || before.joint
            || before.membership_index != Some(expected_index)
            || target == 0
            || target == self.id
        {
            return Err(RemoteRaftError::InvalidTopology);
        }
        let mut voters = before.voters.clone();
        match operation {
            "add_learner" if !before.nodes.contains(&target) => {
                self.add_learner(target).await?;
            }
            "promote" if before.nodes.contains(&target) && !before.voters.contains(&target) => {
                let frontier = before
                    .applied_index
                    .ok_or(RemoteRaftError::InvalidTopology)?;
                // Policy publication immediately before this call can advance
                // the log. Wait for acknowledgement rather than treating a
                // healthy learner's ordinary replication lag as failure.
                self.raft
                    .wait(Some(Duration::from_secs(2)))
                    .metrics(
                        |m| {
                            m.current_leader == Some(self.id)
                                && m.membership_config.log_id().as_ref().map(|l| l.index)
                                    == Some(expected_index)
                                && m.replication
                                    .as_ref()
                                    .and_then(|r| r.get(&target))
                                    .and_then(|l| l.as_ref())
                                    .is_some_and(|l| l.index >= frontier)
                                && m.heartbeat
                                    .as_ref()
                                    .and_then(|h| h.get(&target))
                                    .and_then(|t| t.as_ref())
                                    .is_some_and(|t| t.elapsed() <= Duration::from_secs(1))
                        },
                        "learner caught up to policy frontier",
                    )
                    .await
                    .map_err(|_| {
                        RemoteRaftError::Consensus("learner catch-up not observed".into())
                    })?;
                voters.insert(target);
                tokio::time::timeout(
                    Duration::from_secs(4),
                    self.raft.change_membership(voters.clone(), true),
                )
                .await
                .map_err(|_| RemoteRaftError::Consensus("membership outcome unknown".into()))?
                .map_err(|_| RemoteRaftError::Consensus("promotion failed".into()))?;
            }
            "remove" if before.nodes.contains(&target) && !before.voters.contains(&target) => {
                tokio::time::timeout(
                    Duration::from_secs(4),
                    self.raft.change_membership(
                        openraft::ChangeMembers::RemoveNodes(BTreeSet::from([target])),
                        false,
                    ),
                )
                .await
                .map_err(|_| RemoteRaftError::Consensus("membership outcome unknown".into()))?
                .map_err(|_| RemoteRaftError::Consensus("learner removal failed".into()))?;
            }
            "remove" | "demote" if before.voters.contains(&target) && before.voters.len() > 3 => {
                voters.remove(&target);
                tokio::time::timeout(
                    Duration::from_secs(4),
                    self.raft
                        .change_membership(voters.clone(), operation == "demote"),
                )
                .await
                .map_err(|_| RemoteRaftError::Consensus("membership outcome unknown".into()))?
                .map_err(|_| RemoteRaftError::Consensus("membership transition failed".into()))?;
            }
            _ => return Err(RemoteRaftError::InvalidTopology),
        }
        // An enqueued/mid-joint change is not success. Observe the stable,
        // committed configuration and reestablish authority before returning.
        self.raft
            .wait(Some(Duration::from_secs(3)))
            .metrics(
                |m| {
                    let membership = &m.membership_config;
                    membership == &m.committed_membership_config
                        && membership.get_joint_config().len() == 1
                        && match operation {
                            "add_learner" => {
                                membership.get_node(&target).is_some()
                                    && !membership.voter_ids().any(|id| id == target)
                            }
                            "remove" => membership.get_node(&target).is_none(),
                            "demote" => {
                                membership.get_node(&target).is_some()
                                    && !membership.voter_ids().any(|id| id == target)
                            }
                            "promote" => membership.voter_ids().any(|id| id == target),
                            _ => false,
                        }
                },
                "committed membership readback",
            )
            .await
            .map_err(|_| RemoteRaftError::Consensus("membership completion unobserved".into()))?;
        self.ensure_linearizable().await?;
        self.membership_observation().await
    }
    pub async fn snapshot_observed(&self) -> Result<SnapshotObservation, RemoteRaftError> {
        self.ensure_linearizable().await?;
        let before = self.membership_observation().await?;
        let requested = before
            .applied_index
            .ok_or(RemoteRaftError::InvalidTopology)?;
        self.trigger_snapshot().await?;
        self.raft
            .wait(Some(Duration::from_secs(4)))
            .metrics(
                |m| m.snapshot.as_ref().is_some_and(|s| s.index >= requested),
                "durable snapshot frontier",
            )
            .await
            .map_err(|_| RemoteRaftError::Consensus("snapshot completion unobserved".into()))?;
        let mut state = self.state_machine.clone();
        let snapshot = state
            .get_current_snapshot()
            .await
            .map_err(|_| RemoteRaftError::Io("snapshot readback failed".into()))?
            .ok_or(RemoteRaftError::InvalidTopology)?;
        let persisted = snapshot
            .meta
            .last_log_id
            .as_ref()
            .map(|l| l.index)
            .ok_or(RemoteRaftError::InvalidTopology)?;
        if persisted < requested {
            return Err(RemoteRaftError::InvalidTopology);
        }
        let data = snapshot.snapshot.into_inner();
        use sha2::{Digest, Sha256};
        Ok(SnapshotObservation {
            requested_index: requested,
            persisted_index: persisted,
            byte_count: data.len(),
            sha256: Sha256::digest(&data).into(),
        })
    }
}
