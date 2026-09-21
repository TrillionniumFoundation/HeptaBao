//! Passive, node-local diagnosis. This is never a linearizable-read capability.
use super::RemoteRaftError;
use super::node::ProcessRaftNode;
use openraft::async_runtime::WatchReceiver;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalLeaderObservation {
    pub local_id: u64,
    pub leader: Option<u64>,
    pub committed_index: Option<u64>,
    pub applied_index: Option<u64>,
}

impl ProcessRaftNode {
    /// Sample one local metrics observation without RPC, ReadIndex, application
    /// materialization, or waiting for a new leader's blank log entry.
    pub fn local_leader_observation(&self) -> Result<LocalLeaderObservation, RemoteRaftError> {
        let receiver = self.raft.metrics();
        let metrics = receiver.borrow_watched();
        if metrics.running_state.is_err() {
            return Err(RemoteRaftError::Io("Raft is not healthy".into()));
        }
        Ok(LocalLeaderObservation {
            local_id: self.id,
            leader: metrics.current_leader,
            committed_index: metrics.local_committed.as_ref().map(|log| log.index),
            applied_index: metrics.last_applied.as_ref().map(|log| log.index),
        })
    }
}
