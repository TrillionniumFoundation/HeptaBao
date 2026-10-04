//! A follower must obtain a fresh quorum ReadIndex over authenticated peer RPC
//! and apply its complete log witness locally. Remembered leadership or a warm
//! application image alone never grants read authority. No operation writes a log.
use super::network::{RaftRpcService, RemoteRaftError};
use super::node::{MAX_READ_INDEX_WAIT, ProcessRaftNode, READ_INDEX_TIMEOUT};
use crate::network::DurableRaft;
use crate::state_machine::TypeConfig;
use openraft::async_runtime::WatchReceiver;
use openraft::raft::linearizable_read::{Linearizer, ReadLogId};
use openraft::type_config::alias::LogIdOf;
use openraft::{ReadPolicy, ServerState};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadIndexRequest {
    pub leader: u64,
    pub term: u64,
    pub request_id: u64,
    pub budget_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadIndexWitness {
    pub leader: u64,
    pub term: u64,
    pub request_id: u64,
    pub read_log_id: LogIdOf<TypeConfig>,
    pub leader_applied: LogIdOf<TypeConfig>,
}

#[derive(Serialize, Deserialize)]
pub(super) enum ReadIndexFailure {
    NotLeader,
    Deadline,
    Unavailable,
}

impl ReadIndexFailure {
    pub(super) fn remote(self) -> RemoteRaftError {
        RemoteRaftError::Consensus(
            match self {
                Self::NotLeader => "ReadIndex leadership changed",
                Self::Deadline => READ_INDEX_TIMEOUT,
                Self::Unavailable => "ReadIndex quorum or applied witness unavailable",
            }
            .into(),
        )
    }
}

pub(super) fn bound(raft: &DurableRaft, leader: u64, term: u64, require_leader: bool) -> bool {
    let receiver = raft.metrics();
    let metrics = receiver.borrow_watched();
    metrics.running_state.is_ok()
        && metrics.current_leader == Some(leader)
        && metrics.current_term == term
        && metrics.vote.committed
        && metrics.vote.leader_id.node_id == leader
        && metrics.vote.leader_id.term == term
        && (!require_leader || metrics.state == ServerState::Leader)
}

#[cfg(test)]
tokio::task_local! {
    static LEADER_READ_OBSERVATION_START: std::time::Instant;
}

#[cfg(test)]
pub(crate) async fn observe_leader_read_scope<F: std::future::Future>(
    started: std::time::Instant,
    operation: F,
) -> F::Output {
    LEADER_READ_OBSERVATION_START
        .scope(started, operation)
        .await
}

#[cfg(test)]
fn record_leader_read(stage: &str, raft: &DurableRaft) {
    let _ = LEADER_READ_OBSERVATION_START.try_with(|started| {
        let receiver = raft.metrics();
        eprintln!(
            "actual-leader-read-stage: stage={stage} elapsed_ms={} metrics={:?}",
            started.elapsed().as_millis(),
            receiver.borrow_watched()
        );
    });
}

async fn leader_witness(
    raft: &DurableRaft,
    request: &ReadIndexRequest,
    deadline: Instant,
) -> Result<ReadIndexWitness, ReadIndexFailure> {
    if !bound(raft, request.leader, request.term, true) {
        return Err(ReadIndexFailure::NotLeader);
    }
    loop {
        #[cfg(test)]
        record_leader_read("first-api-before", raft);
        let result =
            tokio::time::timeout_at(deadline, raft.ensure_linearizable(ReadPolicy::ReadIndex))
                .await;
        #[cfg(test)]
        {
            record_leader_read("first-api-after", raft);
            if matches!(result, Err(_) | Ok(Err(_))) {
                let _ = LEADER_READ_OBSERVATION_START.try_with(|_| {
                    eprintln!("actual-leader-read-error: stage=first-api original={result:?}");
                });
            }
        }
        // Tokio may poll a ready operation after its timer. A completed probe
        // cannot renew either the caller's or this peer's absolute budget.
        if Instant::now() >= deadline {
            return Err(ReadIndexFailure::Deadline);
        }
        if !bound(raft, request.leader, request.term, true) {
            return Err(ReadIndexFailure::NotLeader);
        }
        match result {
            Ok(Ok(read)) => {
                let log = *read.log_id();
                // The genuine quorum read above may finish while the public
                // applied metrics still precede that same log. Observe this
                // leader's own applied frontier under the ORIGINAL deadline;
                // no learner catch-up, new probe budget or write is introduced.
                let linearizer = Linearizer::<TypeConfig>::new(request.leader, read, None);
                #[cfg(not(test))]
                let local = tokio::time::timeout_at(deadline, linearizer.await_ready(raft))
                    .await
                    .map_err(|_| ReadIndexFailure::Deadline)?
                    .map_err(|_| ReadIndexFailure::Unavailable)?;
                #[cfg(test)]
                let local = {
                    record_leader_read("own-metrics-before", raft);
                    let result =
                        tokio::time::timeout_at(deadline, linearizer.await_ready(raft)).await;
                    record_leader_read("own-metrics-after", raft);
                    if matches!(result, Err(_) | Ok(Err(_))) {
                        let _ = LEADER_READ_OBSERVATION_START.try_with(|_| {
                            eprintln!(
                                "actual-leader-read-error: stage=own-metrics original={result:?}"
                            );
                        });
                    }
                    result
                        .map_err(|_| ReadIndexFailure::Deadline)?
                        .map_err(|_| ReadIndexFailure::Unavailable)?
                };
                if Instant::now() >= deadline {
                    return Err(ReadIndexFailure::Deadline);
                }
                if !bound(raft, request.leader, request.term, true) {
                    return Err(ReadIndexFailure::NotLeader);
                }
                let receiver = raft.metrics();
                let metrics = receiver.borrow_watched();
                let applied = metrics.last_applied.ok_or(ReadIndexFailure::Unavailable)?;
                if local.node_id() != &request.leader
                    || local.read_log_id().log_id() != &log
                    || local.applied() < Some(&log)
                {
                    return Err(ReadIndexFailure::Unavailable);
                }
                if read.committed_leader_id().node_id != request.leader
                    || read.committed_leader_id().term != request.term
                    || applied < log
                {
                    return Err(ReadIndexFailure::Unavailable);
                }
                if Instant::now() >= deadline {
                    return Err(ReadIndexFailure::Deadline);
                }
                if !bound(raft, request.leader, request.term, true) {
                    return Err(ReadIndexFailure::NotLeader);
                }
                return Ok(ReadIndexWitness {
                    leader: request.leader,
                    term: request.term,
                    request_id: request.request_id,
                    read_log_id: log,
                    leader_applied: applied,
                });
            }
            Ok(Err(openraft::errors::RaftError::APIError(
                openraft::errors::LinearizableReadError::QuorumNotEnough(_),
            ))) => {
                // Retry only a failed read probe within the original deadline.
                // Leadership loss, fatal errors and mutations are never replayed.
                tokio::time::sleep_until(
                    (Instant::now() + Duration::from_millis(20)).min(deadline),
                )
                .await;
            }
            Ok(Err(_)) => return Err(ReadIndexFailure::Unavailable),
            Err(_) => return Err(ReadIndexFailure::Deadline),
        }
    }
}

impl RaftRpcService {
    pub(super) async fn handle_read_index(
        &self,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RemoteRaftError> {
        if payload.len() > 4096 {
            return Err(RemoteRaftError::InvalidRpc);
        }
        let request: ReadIndexRequest =
            serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
        if request.leader != self.local_id
            || request.request_id == 0
            || request.budget_ms == 0
            || request.budget_ms > 8000
        {
            return Err(RemoteRaftError::InvalidRpc);
        }
        let deadline = Instant::now() + Duration::from_millis(request.budget_ms);
        let deadline = super::read_deadline::current()
            .map_or(deadline, |outer| deadline.min(Instant::from_std(outer)));
        let result = leader_witness(&self.raft, &request, deadline).await;
        serde_json::to_vec(&result).map_err(|_| RemoteRaftError::InvalidRpc)
    }
}

pub(super) async fn ensure_node_read(
    node: &ProcessRaftNode,
    deadline: Instant,
) -> Result<(), RemoteRaftError> {
    ensure_node_read_witness(node, deadline).await.map(|_| ())
}

pub(super) async fn ensure_node_read_witness(
    node: &ProcessRaftNode,
    deadline: Instant,
) -> Result<ReadIndexWitness, RemoteRaftError> {
    let receiver = node.raft.metrics();
    let (leader, term) = {
        let metrics = receiver.borrow_watched();
        (metrics.current_leader, metrics.current_term)
    };
    let leader = leader.ok_or_else(|| ReadIndexFailure::NotLeader.remote())?;
    if !bound(&node.raft, leader, term, leader == node.id) {
        return Err(ReadIndexFailure::NotLeader.remote());
    }
    if leader == node.id {
        let request = ReadIndexRequest {
            leader,
            term,
            request_id: 0,
            budget_ms: 8000,
        };
        leader_witness(&node.raft, &request, deadline)
            .await
            .map_err(ReadIndexFailure::remote)
    } else {
        let operation = async {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| ReadIndexFailure::Deadline.remote())?;
            let witness = node
                .peer_network
                .read_index(leader, term, remaining.min(MAX_READ_INDEX_WAIT))
                .await?;
            if !bound(&node.raft, leader, term, false)
                || witness.read_log_id.committed_leader_id().node_id != leader
                || witness.read_log_id.committed_leader_id().term != term
                || witness.leader_applied < witness.read_log_id
            {
                return Err(ReadIndexFailure::NotLeader.remote());
            }
            // Never use the remote applied value for local readiness. OpenRaft
            // observes this node's actual apply frontier, with no cached hint.
            let linearizer = Linearizer::<TypeConfig>::new(
                node.id,
                ReadLogId::from_log_id(witness.read_log_id),
                None,
            );
            let local = linearizer
                .await_ready(&node.raft)
                .await
                .map_err(|_| ReadIndexFailure::Unavailable.remote())?;
            if local.node_id() != &node.id
                || local.read_log_id().log_id() != &witness.read_log_id
                || local.applied() < Some(&witness.read_log_id)
                || !bound(&node.raft, leader, term, false)
                || node.state_machine.last_applied_log_index().await
                    < Some(witness.read_log_id.index())
            {
                return Err(ReadIndexFailure::NotLeader.remote());
            }
            Ok(witness)
        };
        let result = tokio::time::timeout_at(deadline, operation).await;
        if Instant::now() >= deadline {
            return Err(ReadIndexFailure::Deadline.remote());
        }
        result.map_err(|_| ReadIndexFailure::Deadline.remote())?
    }
}
