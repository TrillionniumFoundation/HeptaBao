use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openraft::{Config, ReadPolicy, SnapshotPolicy};
use openraft_memstore::{ClientRequest, MemStoreStateMachine};
use tokio::task::spawn_blocking;

use super::network::{RaftRpcService, RemoteNetworkFactory, RemoteRaftError};
use crate::network::DurableRaft;
use crate::store::{DurableLogStore, DurableStateMachine};
use crate::{CommitReceipt, RaftRuntimeError, ReplicatedEnvelope};

const PRODUCTION_CLIENT_ID: &str = "heptabao-production-ha";

pub struct ProcessRaftNode {
    id: u64,
    raft: DurableRaft,
    state_machine: DurableStateMachine,
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
        self.raft
            .add_learner(id, (), true)
            .await
            .map(|_| ())
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
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

    /// Return the next serial for the durable production application client.
    ///
    /// The serial is recovered from the replicated state machine rather than a
    /// process-local counter. A restarted node or newly elected leader therefore
    /// cannot accidentally reuse an old serial and receive a cached response for
    /// a different state proposal.
    pub async fn next_production_client_serial(&self) -> Result<u64, RaftRuntimeError> {
        let state = self.state_machine.get_state_machine().await;
        match state.client_serial_responses.get(PRODUCTION_CLIENT_ID) {
            Some((serial, _)) => serial
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
        if client_serial == 0 {
            return Err(RaftRuntimeError::InvalidSerial);
        }
        let response = self
            .raft
            .client_write(ClientRequest {
                client: PRODUCTION_CLIENT_ID.to_owned(),
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

    pub async fn shutdown(self) -> Result<(), RemoteRaftError> {
        self.raft
            .shutdown()
            .await
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }
}

fn production_config() -> Result<Config, RemoteRaftError> {
    Config {
        heartbeat_interval: 40,
        election_timeout_min: 120,
        election_timeout_max: 240,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(3),
        max_in_snapshot_log_to_keep: 0,
        enable_pre_vote: Some(true),
        ..Config::default()
    }
    .validate()
    .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
}
