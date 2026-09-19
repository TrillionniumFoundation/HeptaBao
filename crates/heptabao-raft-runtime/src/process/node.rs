use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openraft::{Config, Instant, ReadPolicy, SnapshotPolicy};
use openraft_memstore::{ClientRequest, MemStoreStateMachine};
use tokio::task::spawn_blocking;

use super::network::{RaftRpcService, RemoteNetworkFactory, RemoteRaftError};
use crate::network::DurableRaft;
use crate::store::{DurableLogStore, DurableStateMachine};
use crate::{CommitReceipt, RaftRuntimeError, ReplicatedEnvelope};

const PRODUCTION_CLIENT_ID: &str = "heptabao-production-ha";
const PRODUCTION_CHUNK_CLIENT_PREFIX: &str = "heptabao-production-ha-chunk";
const MAX_APPLICATION_CHUNK_INDEX: u16 = 127;

pub struct ProcessRaftNode {
    pub(super) id: u64,
    pub(super) raft: DurableRaft,
    pub(super) state_machine: DurableStateMachine,
    rpc_service: RaftRpcService,
}

impl std::fmt::Debug for ProcessRaftNode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessRaftNode")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ProcessRaftNode {
    pub async fn create(
        root: impl AsRef<Path>,
        id: u64,
        network: RemoteNetworkFactory,
    ) -> Result<Self, RemoteRaftError> {
        Self::open(root.as_ref().to_path_buf(), id, network, true).await
    }

    pub async fn reopen(
        root: impl AsRef<Path>,
        id: u64,
        network: RemoteNetworkFactory,
    ) -> Result<Self, RemoteRaftError> {
        Self::open(root.as_ref().to_path_buf(), id, network, false).await
    }

    async fn open(
        root: PathBuf,
        id: u64,
        network: RemoteNetworkFactory,
        create: bool,
    ) -> Result<Self, RemoteRaftError> {
        if id == 0 || network.local_id() != id {
            return Err(RemoteRaftError::InvalidTopology);
        }
        let stores = spawn_blocking(move || {
            std::fs::create_dir_all(&root)?;
            let log_root = root.join("log");
            let state_root = root.join("state-machine");
            if create {
                Ok::<_, io::Error>((
                    DurableLogStore::create(log_root)?,
                    DurableStateMachine::create(state_root)?,
                ))
            } else {
                Ok::<_, io::Error>((
                    DurableLogStore::open_existing(log_root)?,
                    DurableStateMachine::open_existing(state_root)?,
                ))
            }
        })
        .await
        .map_err(|error| RemoteRaftError::Io(error.to_string()))?
        .map_err(|error| RemoteRaftError::Io(error.to_string()))?;
        let (log_store, state_machine) = stores;
        let rpc_factory = network.clone();
        let raft = DurableRaft::new(
            id,
            Arc::new(production_config()?),
            network,
            log_store,
            state_machine.clone(),
        )
        .await
        .map_err(|error| RemoteRaftError::Consensus(error.to_string()))?;
        let rpc_service = rpc_factory.rpc_service(raft.clone());
        Ok(Self {
            id,
            raft,
            state_machine,
            rpc_service,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn rpc_service(&self) -> RaftRpcService {
        self.rpc_service.clone()
    }

    pub async fn initialize_single(&self) -> Result<(), RemoteRaftError> {
        self.raft
            .initialize(BTreeMap::from([(self.id, ())]))
            .await
            .map(|_| ())
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    pub async fn add_learner(&self, id: u64) -> Result<(), RemoteRaftError> {
        if id == 0 || id == self.id {
            return Err(RemoteRaftError::InvalidTopology);
        }
        // Admission itself is deliberately non-blocking.  The OpenRaft
        // blocking variant waits on its own replication heuristic and does
        // not expose a committed, non-joint membership/heartbeat receipt to
        // callers.  Observe those conditions explicitly below instead.
        let response = self
            .raft
            .add_learner(id, (), false)
            .await
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))?;
        let membership_frontier = response.log_id.index;
        let target = id;
        self.raft
            .wait(Some(std::time::Duration::from_secs(8)))
            .metrics(
                move |metrics| {
                    let membership = &metrics.membership_config;
                    if metrics.current_leader != Some(self.id)
                        || membership != &metrics.committed_membership_config
                        || membership.get_joint_config().len() != 1
                        || membership.log_id().as_ref().map(|log| log.index)
                            < Some(membership_frontier)
                    {
                        return false;
                    }
                    let matched = metrics
                        .replication
                        .as_ref()
                        .and_then(|replication| replication.get(&target))
                        .and_then(|log| log.as_ref())
                        .map(|log| log.index);
                    let heartbeat_recent = metrics
                        .heartbeat
                        .as_ref()
                        .and_then(|heartbeats| heartbeats.get(&target))
                        .and_then(|instant| instant.as_ref())
                        .is_some_and(|instant| {
                            instant.elapsed() <= std::time::Duration::from_secs(1)
                        });
                    matched.is_some_and(|index| index >= membership_frontier) && heartbeat_recent
                },
                "learner committed replication frontier",
            )
            .await
            .map(|_| ())
            .map_err(|_| {
                RemoteRaftError::Consensus("learner replication completion unobserved".into())
            })
    }

    pub async fn change_membership(&self, voters: BTreeSet<u64>) -> Result<(), RemoteRaftError> {
        if voters.len() < 3 || !voters.contains(&self.id) || voters.contains(&0) {
            return Err(RemoteRaftError::InvalidTopology);
        }
        self.raft
            .change_membership(voters, false)
            .await
            .map(|_| ())
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    pub async fn current_leader(&self) -> Option<u64> {
        self.raft.current_leader().await
    }
    pub async fn transfer_leadership(&self, target: u64) -> Result<(), RemoteRaftError> {
        if target == 0 || target == self.id {
            return Err(RemoteRaftError::InvalidTopology);
        }
        self.raft
            .trigger()
            .transfer_leader(target)
            .await
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    /// Return a nonzero monotonically increasing serial for the production
    /// application client.
    ///
    /// The pinned memstore state machine does not retain client serials; it
    /// persists the latest client status and the last applied Raft log id. The
    /// latter survives restart and snapshot installation, so using its index + 1
    /// prevents serial reuse after leader restart or failover. Membership and
    /// blank entries may create harmless gaps but cannot make the serial regress.
    pub async fn next_production_client_serial(&self) -> Result<u64, RaftRuntimeError> {
        let state = self.state_machine.get_state_machine().await;
        match state.last_applied_log {
            Some(log_id) => log_id
                .index
                .checked_add(1)
                .filter(|value| *value != 0)
                .ok_or(RaftRuntimeError::InvalidSerial),
            None => Ok(1),
        }
    }

    pub async fn replicate(
        &self,
        client_serial: u64,
        envelope: &ReplicatedEnvelope,
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        self.replicate_for_client(PRODUCTION_CLIENT_ID, client_serial, envelope)
            .await
    }

    /// Stage one bounded application-state chunk under a fixed index/slot key.
    /// The authoritative production manifest is a different client identity, so
    /// an interrupted sequence of chunk writes cannot publish a partial state.
    pub async fn replicate_application_chunk(
        &self,
        index: u16,
        slot: u8,
        client_serial: u64,
        envelope: &ReplicatedEnvelope,
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        let client = application_chunk_client(index, slot)?;
        self.replicate_for_client(&client, client_serial, envelope)
            .await
    }

    async fn replicate_for_client(
        &self,
        client: &str,
        client_serial: u64,
        envelope: &ReplicatedEnvelope,
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        if client_serial == 0 {
            return Err(RaftRuntimeError::InvalidSerial);
        }
        let response = self
            .raft
            .client_write(ClientRequest {
                client: client.to_owned(),
                serial: client_serial,
                status: envelope.encoded_status(),
            })
            .await
            .map_err(|error| RaftRuntimeError::Consensus(error.to_string()))?;
        Ok(CommitReceipt {
            leader_id: self.id,
            log_index: response.log_id.index,
            envelope_digest: envelope.digest(),
        })
    }

    pub async fn ensure_linearizable(&self) -> Result<(), RemoteRaftError> {
        self.raft
            .ensure_linearizable(ReadPolicy::ReadIndex)
            .await
            .map(|_| ())
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    pub async fn trigger_snapshot(&self) -> Result<(), RemoteRaftError> {
        self.raft
            .trigger()
            .snapshot()
            .await
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    pub async fn applied_state(&self) -> MemStoreStateMachine {
        self.state_machine.get_state_machine().await
    }

    /// Return the latest authoritative application envelope committed through
    /// the production HA client identity. A malformed durable value is a hard
    /// recovery error rather than an empty state or best-effort fallback.
    pub async fn latest_envelope(&self) -> Result<Option<ReplicatedEnvelope>, RemoteRaftError> {
        let state = self.state_machine.get_state_machine().await;
        let Some(status) = state.client_status.get(PRODUCTION_CLIENT_ID) else {
            return Ok(None);
        };
        ReplicatedEnvelope::decode_status(status)
            .map(Some)
            .map_err(|error| {
                RemoteRaftError::Io(format!("invalid committed application envelope: {error}"))
            })
    }

    pub async fn application_chunk_envelope(
        &self,
        index: u16,
        slot: u8,
    ) -> Result<Option<ReplicatedEnvelope>, RemoteRaftError> {
        let client = application_chunk_client(index, slot)
            .map_err(|error| RemoteRaftError::Io(error.to_string()))?;
        let state = self.state_machine.get_state_machine().await;
        let Some(status) = state.client_status.get(&client) else {
            return Ok(None);
        };
        ReplicatedEnvelope::decode_status(status)
            .map(Some)
            .map_err(|error| {
                RemoteRaftError::Io(format!(
                    "invalid staged application chunk envelope: {error}"
                ))
            })
    }

    pub async fn shutdown(self) -> Result<(), RemoteRaftError> {
        self.raft
            .shutdown()
            .await
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }
}

fn application_chunk_client(index: u16, slot: u8) -> Result<String, RaftRuntimeError> {
    if index > MAX_APPLICATION_CHUNK_INDEX || slot > 1 {
        return Err(RaftRuntimeError::InvalidEnvelope);
    }
    Ok(format!(
        "{PRODUCTION_CHUNK_CLIENT_PREFIX}:{index:03}:{slot}"
    ))
}

fn production_config() -> Result<Config, RemoteRaftError> {
    Config {
        heartbeat_interval: 200,
        election_timeout_min: 1_000,
        election_timeout_max: 2_000,
        // A single logical state commit can stage dozens of bounded chunks plus
        // one manifest. Snapshotting every three Raft entries would turn the
        // periodic full checkpoint into the dominant write path and erase the
        // delta-journal benefit. 128 keeps worst-case retained encoded chunk
        // history bounded while amortizing full state-machine checkpoints.
        snapshot_policy: SnapshotPolicy::LogsSinceLast(128),
        max_in_snapshot_log_to_keep: 0,
        enable_pre_vote: Some(true),
        ..Config::default()
    }
    .validate()
    .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    #[test]
    fn process_timers_allow_tls_and_durable_io_without_using_lease_reads()
    -> Result<(), RemoteRaftError> {
        let config = production_config()?;
        assert_eq!(config.heartbeat_interval, 200);
        assert!(config.election_timeout_min >= 5 * config.heartbeat_interval);
        assert!(config.election_timeout_max >= config.election_timeout_min * 2);
        Ok(())
    }
}
