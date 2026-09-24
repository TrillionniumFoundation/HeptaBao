use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::state_machine::StateMachine as MemStoreStateMachine;
use openraft::{Config, Instant, ReadPolicy, SnapshotPolicy};
use openraft_memstore::ClientRequest;
use tokio::task::spawn_blocking;

use super::network::{RaftRpcService, RemoteNetworkFactory, RemoteRaftError};
use crate::network::DurableRaft;
use crate::store::{DurableLogStore, DurableStateMachine};
use crate::{CommitReceipt, RaftRuntimeError, ReplicatedEnvelope};

const PRODUCTION_CLIENT_ID: &str = "heptabao-production-ha";
const PRODUCTION_CHUNK_CLIENT_PREFIX: &str = "heptabao-production-ha-chunk";
const MAX_APPLICATION_CHUNK_INDEX: u16 = 127;
// Bound both the quorum probe and the subsequent applied-log wait. In
// particular, OpenRaft can otherwise wait indefinitely for a new leader's
// blank entry. This allows the current 5s peer ceiling plus the 2s election
// ceiling and 1s scheduling margin; it is not an HTTP end-to-end deadline.
const MAX_READ_INDEX_WAIT: Duration = Duration::from_secs(8);
const READ_INDEX_TIMEOUT: &str = "linearizable read deadline exceeded";

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
        match self.state_machine.last_applied_log_index().await {
            Some(index) => index
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
        let request = ClientRequest {
            client: client.to_owned(),
            serial: client_serial,
            status: envelope.encoded_status(),
        }
        .into();
        crate::replication_bounds::validate_proposal(&request)
            .map_err(|_| RaftRuntimeError::InvalidEnvelope)?;
        let response = self
            .raft
            .client_write(request)
            .await
            .map_err(|error| RaftRuntimeError::Consensus(error.to_string()))?;
        response
            .data
            .result()
            .map_err(RaftRuntimeError::RecordRejected)?;
        Ok(CommitReceipt {
            leader_id: self.id,
            log_index: response.log_id.index,
            envelope_digest: envelope.digest(),
        })
    }

    async fn replicate_record_command(
        &self,
        serial: u64,
        command: crate::records::RecordCommand,
        digest: [u8; 32],
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        let request = crate::state_machine::ApplicationRequest::records(serial, command)
            .map_err(RaftRuntimeError::RecordRejected)?;
        crate::replication_bounds::validate_proposal(&request)
            .map_err(|_| RaftRuntimeError::InvalidEnvelope)?;
        let response = self
            .raft
            .client_write(request)
            .await
            .map_err(|error| RaftRuntimeError::Consensus(error.to_string()))?;
        response
            .data
            .result()
            .map_err(RaftRuntimeError::RecordRejected)?;
        Ok(CommitReceipt {
            leader_id: self.id,
            log_index: response.log_id.index,
            envelope_digest: digest,
        })
    }
    /// Trusted application maintenance, not a public client operation. Caller
    /// authenticates either a complete inline HBSR1 state or the complete HBSM4
    /// manifest/chunks under its leader writer. An empty active set is accepted
    /// by the state machine only when the exact persisted production envelope is
    /// HBSR1. Success installs a durable legacy-write fence.
    pub async fn retain_legacy_application_chunks(
        &self,
        serial: u64,
        expected_manifest: crate::LegacyStatusIdentity,
        active: &[crate::LegacyChunkRef],
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        if active.len() > 128 {
            return Err(RaftRuntimeError::RecordRejected(
                crate::RecordRejection::Invalid,
            ));
        }
        self.replicate_record_command(
            serial,
            crate::records::RecordCommand::RetainLegacyChunks {
                expected_manifest,
                active: active.to_vec(),
            },
            expected_manifest.digest,
        )
        .await
    }

    /// Exact raw-status identity accompanies the envelope that the caller must
    /// authenticate. No unrelated legacy values are copied.
    pub async fn latest_envelope_identity_at_generation(
        &self,
    ) -> Result<(u64, Option<crate::LegacyEnvelopeObservation>), RemoteRaftError> {
        let (generation, status) = self
            .state_machine
            .client_status_at_generation(PRODUCTION_CLIENT_ID)
            .await;
        let observed = status
            .as_deref()
            .map(crate::LegacyStatusIdentity::inspect)
            .transpose()
            .map_err(|_| RemoteRaftError::Io("invalid committed legacy envelope".into()))?;
        Ok((generation, observed))
    }
    pub async fn application_chunk_identity(
        &self,
        index: u16,
        slot: u8,
    ) -> Result<Option<crate::LegacyEnvelopeObservation>, RemoteRaftError> {
        let client = application_chunk_client(index, slot)
            .map_err(|error| RemoteRaftError::Io(error.to_string()))?;
        self.state_machine
            .client_status(&client)
            .await
            .as_deref()
            .map(crate::LegacyStatusIdentity::inspect)
            .transpose()
            .map_err(|_| RemoteRaftError::Io("invalid committed legacy chunk".into()))
    }

    /// Staging never changes the published application root. No legacy client
    /// identities are allocated for object IDs.
    pub async fn stage_application_object(
        &self,
        serial: u64,
        object: &crate::SealedRecordObject,
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        self.replicate_record_command(
            serial,
            crate::records::RecordCommand::Stage {
                object: object.clone(),
            },
            object.reference().id,
        )
        .await
    }
    pub async fn application_object(
        &self,
        reference: &crate::RecordObjectRef,
    ) -> Result<Option<crate::SealedRecordObject>, RaftRuntimeError> {
        self.state_machine
            .record_object(reference)
            .await
            .map_err(RaftRuntimeError::RecordRejected)
    }
    pub async fn publish_application_root(
        &self,
        serial: u64,
        root: &crate::PublishedRecordRoot,
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        self.replicate_record_command(
            serial,
            crate::records::RecordCommand::Publish { root: root.clone() },
            root.envelope().digest(),
        )
        .await
    }
    pub async fn prune_application_objects(
        &self,
        serial: u64,
        expected_root: [u8; 32],
        ids: &[crate::RecordObjectId],
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        if ids.is_empty() || ids.len() > 256 {
            return Err(RaftRuntimeError::RecordRejected(
                crate::RecordRejection::Invalid,
            ));
        }
        self.replicate_record_command(
            serial,
            crate::records::RecordCommand::Prune {
                expected_root,
                ids: ids.to_vec(),
            },
            expected_root,
        )
        .await
    }
    /// Caller establishes ReadIndex/authority before using these observations;
    /// generation must still match after assembling a multi-object read.
    pub async fn record_root_at_generation(
        &self,
    ) -> Result<(u64, Option<crate::PublishedRecordRoot>), RaftRuntimeError> {
        Ok(self.state_machine.record_root_at_generation().await)
    }
    pub async fn application_object_inventory(
        &self,
        after: Option<crate::RecordObjectId>,
        limit: usize,
    ) -> Result<(u64, Vec<crate::RecordObjectRef>), RaftRuntimeError> {
        self.state_machine
            .record_inventory(after, limit)
            .await
            .map_err(RaftRuntimeError::RecordRejected)
    }
    pub async fn application_record_usage(
        &self,
    ) -> Result<(u64, crate::RecordUsage), RaftRuntimeError> {
        self.state_machine
            .record_usage()
            .await
            .map_err(RaftRuntimeError::RecordRejected)
    }
    /// Read-only whole-publication capacity/closure admission. Caller retains
    /// application writer authority; normal per-command validation still runs.
    pub async fn preflight_application_publication(
        &self,
        objects: &[crate::SealedRecordObject],
        root: &crate::PublishedRecordRoot,
    ) -> Result<(), RaftRuntimeError> {
        self.state_machine
            .preflight_record_publication(objects, root)
            .await
            .map_err(RaftRuntimeError::RecordRejected)
    }

    pub async fn prunable_application_objects(
        &self,
        expected_root: [u8; 32],
        limit: usize,
    ) -> Result<Vec<crate::RecordObjectId>, RaftRuntimeError> {
        self.state_machine
            .prunable_records(expected_root, limit)
            .await
            .map_err(RaftRuntimeError::RecordRejected)
    }

    pub async fn ensure_linearizable(&self) -> Result<(), RemoteRaftError> {
        self.ensure_linearizable_with_timeout(MAX_READ_INDEX_WAIT)
            .await
    }

    /// Confirm ReadIndex leadership and apply its required log within the
    /// smaller of the caller's remaining budget and the runtime's bound.
    /// Timeout authorizes no read and does not retry or submit a write.
    pub async fn ensure_linearizable_with_timeout(
        &self,
        remaining: Duration,
    ) -> Result<(), RemoteRaftError> {
        let budget = remaining.min(MAX_READ_INDEX_WAIT);
        let deadline = tokio::time::Instant::now() + budget;
        let deadline = super::read_deadline::current().map_or(deadline, |outer| {
            deadline.min(tokio::time::Instant::from_std(outer))
        });
        if budget.is_zero() || tokio::time::Instant::now() >= deadline {
            return Err(RemoteRaftError::Consensus(READ_INDEX_TIMEOUT.into()));
        }
        let result = tokio::time::timeout_at(
            deadline,
            self.raft.ensure_linearizable(ReadPolicy::ReadIndex),
        )
        .await;
        // A ready future can win Tokio's timeout poll even after the clock has
        // advanced. Do not turn an already elapsed caller budget into success.
        if tokio::time::Instant::now() >= deadline {
            return Err(RemoteRaftError::Consensus(READ_INDEX_TIMEOUT.into()));
        }
        result
            .map_err(|_| RemoteRaftError::Consensus(READ_INDEX_TIMEOUT.into()))?
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
        let Some(status) = self.state_machine.client_status(PRODUCTION_CLIENT_ID).await else {
            return Ok(None);
        };
        ReplicatedEnvelope::decode_status(&status)
            .map(Some)
            .map_err(|error| {
                RemoteRaftError::Io(format!("invalid committed application envelope: {error}"))
            })
    }

    /// Observe the publication envelope and state-machine generation atomically.
    pub async fn latest_envelope_at_generation(
        &self,
    ) -> Result<(u64, Option<ReplicatedEnvelope>), RemoteRaftError> {
        let (generation, status) = self
            .state_machine
            .client_status_at_generation(PRODUCTION_CLIENT_ID)
            .await;
        let envelope = status
            .as_deref()
            .map(ReplicatedEnvelope::decode_status)
            .transpose()
            .map_err(|error| {
                RemoteRaftError::Io(format!("invalid committed application envelope: {error}"))
            })?;
        Ok((generation, envelope))
    }

    pub async fn application_state_generation(&self) -> u64 {
        self.state_machine.generation().await
    }

    pub async fn application_chunk_envelope(
        &self,
        index: u16,
        slot: u8,
    ) -> Result<Option<ReplicatedEnvelope>, RemoteRaftError> {
        let client = application_chunk_client(index, slot)
            .map_err(|error| RemoteRaftError::Io(error.to_string()))?;
        let Some(status) = self.state_machine.client_status(&client).await else {
            return Ok(None);
        };
        ReplicatedEnvelope::decode_status(&status)
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

#[cfg(test)]
#[path = "read_index_tests.rs"]
mod read_index_tests;
