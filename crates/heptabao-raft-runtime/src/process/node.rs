use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::state_machine::StateMachine as MemStoreStateMachine;
#[cfg(test)]
use openraft::ReadPolicy;
use openraft::{Config, Instant, SnapshotPolicy, storage::RaftStateMachine};
#[cfg(feature = "experimental-v6-raft-objects")]
use openraft::{EntryPayload, storage::RaftLogReader};
use openraft_memstore::ClientRequest;
use tokio::task::spawn_blocking;

use super::network::{RaftRpcService, RemoteNetworkFactory, RemoteRaftError};
use crate::network::DurableRaft;
use crate::store::{DurableLogStore, DurableStateMachine};
use crate::{CommitReceipt, RaftRuntimeError, ReplicatedEnvelope};

#[cfg(feature = "experimental-v6-raft-objects")]
#[path = "v6_closure_admission.rs"]
mod v6_closure_admission;
#[cfg(feature = "experimental-v6-raft-objects")]
pub use v6_closure_admission::NativeV6ClosureAdmission;
#[cfg(feature = "experimental-v6-raft-objects")]
#[path = "v6_committed_root_read.rs"]
mod v6_committed_root_read;
#[cfg(feature = "experimental-v6-raft-objects")]
pub use v6_committed_root_read::NativeV6CommittedRootRead;
#[cfg(feature = "experimental-v6-raft-objects")]
#[path = "v6_epoch_restore.rs"]
mod v6_epoch_restore;
#[cfg(feature = "experimental-v6-raft-objects")]
pub use v6_epoch_restore::NativeV6EpochRestoreRead;

const PRODUCTION_CLIENT_ID: &str = "heptabao-production-ha";
const PRODUCTION_CHUNK_CLIENT_PREFIX: &str = "heptabao-production-ha-chunk";
const MAX_APPLICATION_CHUNK_INDEX: u16 = 127;
// Bound both the quorum probe and the subsequent applied-log wait. In
// particular, OpenRaft can otherwise wait indefinitely for a new leader's
// blank entry. This allows the current 5s peer ceiling plus the 2s election
// ceiling and 1s scheduling margin; it is not an HTTP end-to-end deadline.
pub(super) const MAX_READ_INDEX_WAIT: Duration = Duration::from_secs(8);
pub(super) const READ_INDEX_TIMEOUT: &str = "linearizable read deadline exceeded";

/// Opaque evidence of a fresh quorum ReadIndex and this runtime instance's
/// actual applied application observation. Only application_read_witness can
/// construct it; generation alone and remote applied hints cannot authorize it.
pub struct ApplicationReadWitness {
    store: DurableStateMachine,
    generation: u64,
    deadline: tokio::time::Instant,
    leader: u64,
    term: u64,
    read_log: openraft::type_config::alias::LogIdOf<crate::state_machine::TypeConfig>,
    applied_log: openraft::type_config::alias::LogIdOf<crate::state_machine::TypeConfig>,
}

/// An authenticated application's completed snapshot belongs to this actual
/// committed log prefix. Deserializing the stamp alone grants no read authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedApplicationPrefix {
    term: u64,
    node: u64,
    index: u64,
}
impl CommittedApplicationPrefix {
    pub fn index(&self) -> u64 {
        self.index
    }
    pub fn valid(&self) -> bool {
        self.term > 0 && self.node > 0 && self.index > 0
    }
}

impl ApplicationReadWitness {
    /// Caller first authenticates the selected application and validates this
    /// opaque witness under its original quorum deadline.
    pub fn completed_prefix(&self) -> CommittedApplicationPrefix {
        let leader = self.applied_log.committed_leader_id();
        CommittedApplicationPrefix {
            term: leader.term,
            node: leader.node_id,
            index: self.applied_log.index,
        }
    }
    /// Raft's fresh quorum and this same store's real applied snapshot cover
    /// the authenticated peer completion. Passive numeric metrics never enter.
    pub fn covers_completed_prefix(&self, prefix: &CommittedApplicationPrefix) -> bool {
        let read = self.read_log.committed_leader_id();
        let applied = self.applied_log.committed_leader_id();
        prefix.valid()
            && self.read_log.index >= prefix.index
            && self.applied_log.index >= prefix.index
            && read.term >= prefix.term
            && applied.term >= prefix.term
            && (self.read_log.index != prefix.index
                || (read.term == prefix.term && read.node_id == prefix.node))
            && (self.applied_log.index != prefix.index
                || (applied.term == prefix.term && applied.node_id == prefix.node))
    }

    /// Cover an earlier atomic application observation with this same live
    /// store's current quorum proof. The store identity is an in-process Arc
    /// identity: reopen, another process, or another boot cannot supply it.
    /// Neither witness is Clone/Serde and neither original deadline is renewed.
    /// The caller must validate this current witness before using the relation.
    pub fn covers_application_witness(&self, selected: &Self) -> bool {
        let now = tokio::time::Instant::now();
        let outer_live = super::read_deadline::current()
            .is_none_or(|outer| now < tokio::time::Instant::from_std(outer));
        outer_live
            && now < self.deadline
            && now < selected.deadline
            && self.store.same_instance(&selected.store)
            && self.generation >= selected.generation
            && selected.applied_log >= selected.read_log
            && self.covers_completed_prefix(&selected.completed_prefix())
    }

    /// A later quorum covers a strictly newer applied prefix of the same live
    /// local store. Application identity and monotonic owners are separately
    /// authenticated by the application before interpreting supersession.
    pub fn supersedes(&self, previous: &Self) -> bool {
        self.store.same_instance(&previous.store)
            && self.generation > previous.generation
            && self.read_log.index > previous.applied_log.index
            && self.read_log.committed_leader_id().term
                >= previous.applied_log.committed_leader_id().term
            && self.applied_log >= self.read_log
            && self.applied_log.committed_leader_id().term
                >= previous.applied_log.committed_leader_id().term
    }
}

pub struct ProcessRaftNode {
    pub(super) id: u64,
    pub(super) raft: DurableRaft,
    pub(super) state_machine: DurableStateMachine,
    // Feature-only read-only access to the SAME persisted Raft log store.
    // The clone retains the original Arc; it does not reopen a different store.
    #[cfg(feature = "experimental-v6-raft-objects")]
    v6_intent_log_reader: DurableLogStore,
    rpc_service: RaftRpcService,
    pub(super) peer_network: RemoteNetworkFactory,
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
        let (log_store, mut state_machine) = stores;
        // Starting the core does not synchronously publish recovered metrics.
        // Capture only its validated durable frontier, not application payloads.
        let recovered = if create {
            None
        } else {
            Some(state_machine.applied_state().await.map_err(|_| {
                RemoteRaftError::Io("recovered Raft membership is unavailable".into())
            })?)
        };
        #[cfg(feature = "experimental-v6-raft-objects")]
        let v6_intent_log_reader = log_store.clone();
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
        if let Some((applied, membership)) = recovered {
            let recovered_index = membership.log_id().as_ref().map(|log| log.index);
            let published = raft
                .wait(Some(Duration::from_secs(8)))
                .metrics(
                    move |metrics| {
                        let observed = &metrics.committed_membership_config;
                        let observed_index = observed.log_id().as_ref().map(|log| log.index);
                        metrics.running_state.is_ok()
                            && metrics.last_applied >= applied
                            && observed_index >= recovered_index
                            && (observed_index != recovered_index
                                || observed.as_ref() == &membership)
                    },
                    "recovered durable membership publication",
                )
                .await;
            if published.is_err() {
                let _ = raft.shutdown().await;
                return Err(RemoteRaftError::Consensus(
                    "recovered Raft membership publication deadline exceeded".into(),
                ));
            }
        }
        let rpc_service = rpc_factory.rpc_service(raft.clone());
        Ok(Self {
            id,
            raft,
            state_machine,
            #[cfg(feature = "experimental-v6-raft-objects")]
            v6_intent_log_reader,
            rpc_service,
            peer_network: rpc_factory,
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
        self.enroll_learner(id).await?;
        self.wait_for_learner_replication(id, std::time::Duration::from_secs(8))
            .await
    }

    /// Commit learner membership without requiring the target to be reachable.
    ///
    /// Bootstrap uses this operation before checking replication readiness. A
    /// committed learner remains durable and can catch up when its process
    /// returns; treating an unavailable learner as an admission failure would
    /// strand a partially bootstrapped cluster.
    pub async fn enroll_learner(&self, id: u64) -> Result<(), RemoteRaftError> {
        if id == 0 || id == self.id {
            return Err(RemoteRaftError::InvalidTopology);
        }
        let response = self
            .raft
            .add_learner(id, (), false)
            .await
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))?;
        let membership_frontier = response.log_id.index;
        self.raft
            .wait(Some(std::time::Duration::from_secs(4)))
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
                    membership.get_node(&id).is_some()
                },
                "learner membership committed",
            )
            .await
            .map(|_| ())
            .map_err(|_| RemoteRaftError::Consensus("learner membership commit unobserved".into()))
    }

    /// Observe replication and heartbeat readiness separately from learner
    /// enrollment. A timeout means the learner remains committed but is not
    /// eligible for voter promotion yet.
    pub async fn wait_for_learner_replication(
        &self,
        id: u64,
        timeout: std::time::Duration,
    ) -> Result<(), RemoteRaftError> {
        if id == 0 || id == self.id {
            return Err(RemoteRaftError::InvalidTopology);
        }
        self.raft
            .wait(Some(timeout))
            .metrics(
                move |metrics| {
                    let membership = &metrics.membership_config;
                    if metrics.current_leader != Some(self.id)
                        || membership != &metrics.committed_membership_config
                        || membership.get_joint_config().len() != 1
                    {
                        return false;
                    }
                    let frontier = membership.log_id().as_ref().map(|log| log.index);
                    let matched = metrics
                        .replication
                        .as_ref()
                        .and_then(|replication| replication.get(&id))
                        .and_then(|log| log.as_ref())
                        .map(|log| log.index);
                    let heartbeat_recent = metrics
                        .heartbeat
                        .as_ref()
                        .and_then(|heartbeats| heartbeats.get(&id))
                        .and_then(|instant| instant.as_ref())
                        .is_some_and(|instant| {
                            instant.elapsed() <= std::time::Duration::from_secs(1)
                        });
                    frontier.is_some_and(|frontier| {
                        matched.is_some_and(|index| index >= frontier) && heartbeat_recent
                    })
                },
                "learner committed replication frontier",
            )
            .await
            .map(|_| ())
            .map_err(|_| {
                RemoteRaftError::Consensus("learner replication readiness unobserved".into())
            })
    }

    pub async fn change_membership(&self, voters: BTreeSet<u64>) -> Result<(), RemoteRaftError> {
        if voters.len() < 3 || !voters.contains(&self.id) || voters.contains(&0) {
            return Err(RemoteRaftError::InvalidTopology);
        }
        let expected_voters = voters.clone();
        let response = self
            .raft
            .change_membership(voters, false)
            .await
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))?;
        let expected = response.log_id.index;
        self.raft
            .wait(Some(std::time::Duration::from_secs(4)))
            .metrics(
                move |metrics| {
                    let membership = &metrics.membership_config;
                    membership == &metrics.committed_membership_config
                        && membership.get_joint_config().len() == 1
                        && membership
                            .log_id()
                            .as_ref()
                            .is_some_and(|log| log.index >= expected)
                        && membership.voter_ids().collect::<BTreeSet<_>>() == expected_voters
                },
                "voter membership committed",
            )
            .await
            .map(|_| ())
            .map_err(|_| RemoteRaftError::Consensus("voter membership commit unobserved".into()))
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

    /// Read-only, exact-log-index reconciliation of a previously Raft-staged
    /// V6 intent. An arbitrary applied-index metric or client-supplied digest
    /// CANNOT prove that this specific Raft log slot held this exact intent.
    ///
    /// A fresh local quorum ReadIndex, exact persisted log-entry identity,
    /// current committed three-voter membership, and the same durable applied
    /// object are all checked before returning. If the historical slot was
    /// purged, a *persisted, validated Raft state-machine snapshot* must carry
    /// the original applied log's immutable intent ID and full LogId. Missing,
    /// stale or unbound snapshot provenance remains unavailable.
    ///
    /// This does NOT establish the originating Actor/ACL, real local ciphertext
    /// custody on each voter, V6 root publication, or client write authority.
    /// Feature default OFF; no service or production caller invokes it.
    #[cfg(feature = "experimental-v6-raft-objects")]
    pub async fn reconcile_exact_staged_v6_intent(
        &self,
        expected: &crate::NativeV6CommitIntent,
        receipt: &crate::CommitReceipt,
    ) -> Result<(), crate::RaftRuntimeError> {
        fn deny() -> crate::RaftRuntimeError {
            crate::RaftRuntimeError::Consensus(
                "exact V6 intent Raft-log provenance unavailable".into(),
            )
        }
        // A new leader may reconcile an intent committed under an older
        // leader. Only the exact persisted log slot determines origin identity.
        if receipt.log_index == 0 || receipt.leader_id == 0 {
            return Err(deny());
        }
        let object = crate::SealedRecordObject::new_native_v6_commit_intent(*expected)
            .map_err(|_| deny())?;
        if object.reference().id != receipt.envelope_digest {
            return Err(deny());
        }
        // Real quorum evidence, not a follower's passive last-applied metric.
        // Native intent provenance remains available after native activation;
        // the ordinary application witness deliberately fences retained V5.
        let deadline = super::read_deadline::current()
            .unwrap_or_else(|| std::time::Instant::now() + MAX_READ_INDEX_WAIT);
        let (quorum, _, _) = self
            .native_v6_application_read_witness(deadline)
            .await
            .map_err(|_| deny())?;
        if quorum.leader != self.id
            || quorum.read_log.index < receipt.log_index
            || quorum.applied_log.index < receipt.log_index
        {
            return Err(deny());
        }
        let membership = self.membership_observation().await.map_err(|_| deny())?;
        if !membership.committed
            || membership.joint
            || membership.voters.len() < 3
            || !membership.voters.contains(&self.id)
            || membership.leader != Some(self.id)
            || membership.term != quorum.term
            || membership.membership_index.is_none()
            || membership
                .applied_index
                .is_none_or(|i| i < receipt.log_index)
        {
            return Err(deny());
        }
        let end = receipt.log_index.checked_add(1).ok_or_else(deny)?;
        let mut reader = self.v6_intent_log_reader.clone();
        let entries = tokio::time::timeout_at(
            quorum.deadline,
            reader.try_get_log_entries(receipt.log_index..end),
        )
        .await
        .map_err(|_| deny())?
        .map_err(|_| deny())?;
        match entries.as_slice() {
            [entry] => {
                if entry.log_id.index != receipt.log_index
                    || entry.log_id.committed_leader_id().node_id != receipt.leader_id
                {
                    return Err(deny());
                }
                match &entry.payload {
                    EntryPayload::Normal(crate::state_machine::ApplicationRequest::RecordsV5(
                        data,
                    )) => match &data.records_v5 {
                        crate::records::RecordCommand::Stage { object: staged }
                            if staged == &object => {}
                        _ => return Err(deny()),
                    },
                    _ => return Err(deny()),
                }
            }
            [] => {
                // Empty entry results do not imply compaction. Require an
                // independent actual Raft purged frontier, plus the original
                // applied LogId inside the *persisted snapshot*, not a cached
                // application object or caller-supplied receipt.
                if membership
                    .purged_index
                    .is_none_or(|purged| purged < receipt.log_index)
                {
                    return Err(deny());
                }
                let observed = self
                    .state_machine
                    .durable_snapshot_v6_intent_log_id(&object.reference().id, receipt.log_index)
                    .await
                    .map_err(|_| deny())?;
                if observed.is_none_or(|log| {
                    log.index != receipt.log_index
                        || log.committed_leader_id().node_id != receipt.leader_id
                }) {
                    return Err(deny());
                }
            }
            _ => return Err(deny()),
        }
        if self
            .state_machine
            .record_object(object.reference())
            .await
            .map_err(|_| deny())?
            != Some(object)
        {
            return Err(deny());
        }
        // A checkpoint, leadership change, deadline expiry, or other applied
        // mutation during the observation invalidates the SAME original proof.
        self.verify_application_read_witness(&quorum)
            .await
            .map_err(|_| deny())
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

    /// Commit the trusted configuration owner's static voter-to-leaf pins.
    /// Raft binds the exact membership LogId. The caller must authenticate the
    /// source of this enrollment; arbitrary network clients must not reach it.
    /// This slice deliberately forbids changing enrollment after V6 activation.
    #[cfg(feature = "experimental-v6-raft-objects")]
    pub async fn enroll_native_v6_peers(
        &self,
        serial: u64,
        cluster_digest: [u8; 32],
        epoch: u64,
        pins: BTreeMap<u64, [u8; 32]>,
        deadline: std::time::Instant,
    ) -> Result<crate::NativeV6PeerEnrollment, RaftRuntimeError> {
        super::with_read_index_deadline(deadline, async {
            let deadline = super::read_deadline::current().unwrap_or(deadline);
            let (witness, _, _) = self.application_read_witness().await.map_err(|_| {
                RaftRuntimeError::Consensus("V6 enrollment quorum unavailable".into())
            })?;
            let (membership, _) = self.state_machine.native_v6_enrollment().await;
            let (membership_log, _) = crate::v6_root_publication::membership_binding(&membership)
                .map_err(RaftRuntimeError::RecordRejected)?;
            let enrollment = crate::v6_root_publication::NativeV6EnrollmentCommand {
                cluster_digest,
                epoch,
                membership_log,
                pins,
            };
            enrollment
                .matches_membership(&membership)
                .map_err(RaftRuntimeError::RecordRejected)?;
            self.verify_application_read_witness(&witness)
                .await
                .map_err(|_| RaftRuntimeError::Consensus("V6 enrollment source changed".into()))?;
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.replicate_record_command(
                    serial,
                    crate::records::RecordCommand::EnrollNativeV6 {
                        enrollment: enrollment.clone(),
                    },
                    cluster_digest,
                ),
            )
            .await
            .map_err(|_| RaftRuntimeError::Consensus("V6 enrollment outcome unknown".into()))??;
            let (actual_membership, actual) = self.state_machine.native_v6_enrollment().await;
            let actual =
                actual.ok_or_else(|| RaftRuntimeError::Consensus("V6 enrollment absent".into()))?;
            if actual.0.command != enrollment || std::time::Instant::now() >= deadline {
                return Err(RaftRuntimeError::Consensus(
                    "V6 enrollment outcome unknown".into(),
                ));
            }
            actual
                .0
                .command
                .matches_membership(&actual_membership)
                .map_err(RaftRuntimeError::RecordRejected)?;
            Ok(actual)
        })
        .await
    }

    /// Exact V5 root source for the first native generation (0 -> 1). Old V5
    /// snapshots without original publication provenance require an explicit
    /// successful unchanged-root Publish before starting native migration.
    /// This observation alone grants no writer or linearizable business read.
    #[cfg(feature = "experimental-v6-raft-objects")]
    pub async fn native_v6_migration_source(
        &self,
    ) -> Option<([u8; 32], openraft::alias::LogIdOf<crate::TypeConfig>)> {
        self.state_machine.native_v6_migration_source().await
    }

    /// Root metadata CAS through actual durable Raft. Before invoking this
    /// trusted-writer primitive, the application must authenticate its Actor,
    /// typed sealed root, original deadline and a majority of fsynced external
    /// closures under this EXACT committed enrollment. Local custody observations
    /// do not meet that precondition. This API never returns an HTTP/client ACK.
    /// A timeout can follow a real commit: reconcile the same operation, do not
    /// manufacture a new intent or conclude that the root was unchanged.
    #[cfg(feature = "experimental-v6-raft-objects")]
    pub async fn publish_native_v6_root(
        &self,
        serial: u64,
        intent: &crate::NativeV6CommitIntent,
        intent_receipt: &CommitReceipt,
        enrollment: &crate::NativeV6PeerEnrollment,
        sealed_root: Vec<u8>,
        deadline: std::time::Instant,
    ) -> Result<crate::NativeV6PublishedRoot, RaftRuntimeError> {
        super::with_read_index_deadline(deadline, async {
            let deadline = super::read_deadline::current().unwrap_or(deadline);
            self.reconcile_exact_staged_v6_intent(intent, intent_receipt)
                .await?;
            let origin = self
                .state_machine
                .native_v6_intent_origin(&intent_receipt.envelope_digest)
                .await
                .ok_or(RaftRuntimeError::RecordRejected(
                    crate::RecordRejection::MissingDependency,
                ))?;
            let root = crate::v6_root_publication::NativeV6RootCommand {
                intent: *intent,
                intent_log: origin,
                enrollment_digest: enrollment.digest(),
                envelope: ReplicatedEnvelope::new(
                    crate::v6_root_publication::NativeV6RootCommand::operation_id(intent),
                    intent.proposed_root_digest,
                    sealed_root,
                )?,
            };
            root.validate().map_err(RaftRuntimeError::RecordRejected)?;
            let receipt = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.replicate_record_command(
                    serial,
                    crate::records::RecordCommand::PublishNativeV6 { root },
                    intent.proposed_root_digest,
                ),
            )
            .await
            .map_err(|_| {
                RaftRuntimeError::Consensus("V6 root publication outcome unknown".into())
            })??;
            self.reconcile_native_v6_root(intent, &receipt, deadline)
                .await
        })
        .await
    }

    /// Read-only current committed root. Pair with a fresh ReadIndex before a
    /// business read, and reopen/validate the complete external closure before
    /// activating a server. A Raft snapshot by itself contains no ciphertext.
    #[cfg(feature = "experimental-v6-raft-objects")]
    pub async fn native_v6_root_at_generation(
        &self,
    ) -> (u64, Option<crate::NativeV6PublishedRoot>) {
        self.state_machine.native_v6_root().await
    }

    /// Recover the actually committed enrollment and native root together with
    /// a fresh quorum witness for that exact local state-machine generation.
    /// The handles, membership and applied log come from one bundle lock; a
    /// cold process never recreates enrollment from caller-supplied pins.
    ///
    /// This performs the existing real ReadIndex before the local observation.
    /// Local snapshots alone grant no quorum, and this result still proves no
    /// external-closure fsync, barrier/Actor/ACL or HTTP delivery authority.
    /// The caller must validate the typed graph and recheck the same witness
    /// before using it. No original deadline is extended.
    #[cfg(feature = "experimental-v6-raft-objects")]
    pub async fn native_v6_application_read_witness(
        &self,
        deadline: std::time::Instant,
    ) -> Result<
        (
            ApplicationReadWitness,
            Option<crate::NativeV6PeerEnrollment>,
            Option<crate::NativeV6PublishedRoot>,
        ),
        RemoteRaftError,
    > {
        super::with_read_index_deadline(deadline, async {
            let outer = super::read_deadline::current().unwrap_or(deadline);
            let deadline = tokio::time::Instant::from_std(outer)
                .min(tokio::time::Instant::now() + MAX_READ_INDEX_WAIT);
            let read = super::follower_read::ensure_node_read_witness(self, deadline).await?;
            let (generation, applied, membership, enrollment, root) = tokio::time::timeout_at(
                deadline,
                self.state_machine.native_v6_application_snapshot(),
            )
            .await
            .map_err(|_| RemoteRaftError::Consensus(READ_INDEX_TIMEOUT.into()))?;
            let applied = applied.ok_or_else(|| {
                RemoteRaftError::Consensus("native ReadIndex applied witness unavailable".into())
            })?;
            if tokio::time::Instant::now() >= deadline || applied < read.read_log_id {
                return Err(RemoteRaftError::Consensus(READ_INDEX_TIMEOUT.into()));
            }
            if let Some(enrollment) = enrollment.as_ref() {
                enrollment.0.validate().map_err(|_| {
                    RemoteRaftError::Io("invalid committed native enrollment".into())
                })?;
                enrollment
                    .0
                    .command
                    .matches_membership(&membership)
                    .map_err(|_| {
                        RemoteRaftError::Consensus("native enrollment membership changed".into())
                    })?;
                if enrollment.enrollment_log_id() > applied {
                    return Err(RemoteRaftError::Io(
                        "native enrollment is not applied".into(),
                    ));
                }
            }
            if let Some(root) = root.as_ref() {
                root.0
                    .validate()
                    .map_err(|_| RemoteRaftError::Io("invalid committed native root".into()))?;
                let enrollment = enrollment.as_ref().ok_or_else(|| {
                    RemoteRaftError::Io("committed native root has no enrollment".into())
                })?;
                if root.enrollment_digest() != enrollment.digest()
                    || root.intent().cluster_digest != enrollment.cluster_digest()
                    || root.intent().epoch != enrollment.epoch()
                    || root.publication_log_id() > applied
                {
                    return Err(RemoteRaftError::Io(
                        "native root enrollment binding changed".into(),
                    ));
                }
            }
            let witness = ApplicationReadWitness {
                store: self.state_machine.clone(),
                generation,
                deadline,
                leader: read.leader,
                term: read.term,
                read_log: read.read_log_id,
                applied_log: applied,
            };
            self.verify_application_read_witness(&witness).await?;
            Ok((witness, enrollment, root))
        })
        .await
    }

    /// Reconcile the exact published root and original full publication LogId
    /// from durable state, including after compaction/restart. If superseded,
    /// this bounded current-root API returns unavailable, never a false denial.
    #[cfg(feature = "experimental-v6-raft-objects")]
    pub async fn reconcile_native_v6_root(
        &self,
        intent: &crate::NativeV6CommitIntent,
        receipt: &CommitReceipt,
        deadline: std::time::Instant,
    ) -> Result<crate::NativeV6PublishedRoot, RaftRuntimeError> {
        fn unknown() -> RaftRuntimeError {
            RaftRuntimeError::Consensus("V6 root publication reconciliation unavailable".into())
        }
        super::with_read_index_deadline(deadline, async {
            let deadline = super::read_deadline::current().unwrap_or(deadline);
            let (witness, enrollment, root) = self
                .native_v6_application_read_witness(deadline)
                .await
                .map_err(|_| unknown())?;
            let root = root.ok_or_else(unknown)?;
            let enrollment = enrollment.ok_or_else(unknown)?;
            if root.intent() != *intent
                || root.root_digest() != receipt.envelope_digest
                || root.publication_log_id().index != receipt.log_index
                || root.publication_log_id().committed_leader_id().node_id != receipt.leader_id
                || root.enrollment_digest() != enrollment.digest()
                || std::time::Instant::now() >= deadline
            {
                return Err(unknown());
            }
            self.verify_application_read_witness(&witness)
                .await
                .map_err(|_| unknown())?;
            Ok(root)
        })
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
        super::follower_read::ensure_node_read(self, deadline).await
    }

    /// Return the exact selected root/status alongside a fresh, locally applied
    /// quorum witness. The original outer ReadIndex deadline bounds both work
    /// and final observation; no write or retry budget is introduced.
    pub async fn application_read_witness(
        &self,
    ) -> Result<
        (
            ApplicationReadWitness,
            Option<ReplicatedEnvelope>,
            Option<crate::PublishedRecordRoot>,
        ),
        RemoteRaftError,
    > {
        let deadline = tokio::time::Instant::now() + MAX_READ_INDEX_WAIT;
        let deadline = super::read_deadline::current().map_or(deadline, |outer| {
            deadline.min(tokio::time::Instant::from_std(outer))
        });
        let read = super::follower_read::ensure_node_read_witness(self, deadline).await?;
        let (generation, applied, status, root, native_active) = tokio::time::timeout_at(
            deadline,
            self.state_machine
                .application_read_snapshot(PRODUCTION_CLIENT_ID),
        )
        .await
        .map_err(|_| RemoteRaftError::Consensus(READ_INDEX_TIMEOUT.into()))?;
        // The format and old values belong to ONE locked observation. Checking
        // native state first under another lock would race V6 activation and
        // could turn a preserved migration source into a current V5 read.
        if native_active {
            return Err(RemoteRaftError::Consensus(
                "legacy application read fenced by committed native root".into(),
            ));
        }
        let applied = applied.ok_or_else(|| {
            RemoteRaftError::Consensus("ReadIndex own applied witness unavailable".into())
        })?;
        if tokio::time::Instant::now() >= deadline
            || applied < read.read_log_id
            || !super::follower_read::bound(
                &self.raft,
                read.leader,
                read.term,
                read.leader == self.id,
            )
        {
            return Err(RemoteRaftError::Consensus(
                "ReadIndex application witness is not current".into(),
            ));
        }
        let envelope = status
            .as_deref()
            .map(ReplicatedEnvelope::decode_status)
            .transpose()
            .map_err(|_| {
                RemoteRaftError::Io("invalid committed application witness envelope".into())
            })?;
        // Decoding must not issue a witness after the original bound elapsed
        // or leadership changed during final observation work.
        if tokio::time::Instant::now() >= deadline
            || !super::follower_read::bound(
                &self.raft,
                read.leader,
                read.term,
                read.leader == self.id,
            )
        {
            return Err(RemoteRaftError::Consensus(
                "ReadIndex application witness is not current".into(),
            ));
        }
        let witness = ApplicationReadWitness {
            store: self.state_machine.clone(),
            generation,
            deadline,
            leader: read.leader,
            term: read.term,
            read_log: read.read_log_id,
            applied_log: applied,
        };
        // An activation/apply after the atomic selection invalidates this same
        // generation. Callers retain their existing final witness recheck too.
        self.verify_application_read_witness(&witness).await?;
        Ok((witness, envelope, root))
    }

    /// Final application authentication cannot renew a witness's original
    /// ReadIndex bound. Validate its same live store, generation and term under
    /// that bound, even if the application has entered a later request scope.
    pub async fn verify_application_read_witness(
        &self,
        witness: &ApplicationReadWitness,
    ) -> Result<(), RemoteRaftError> {
        let deadline = super::read_deadline::current().map_or(witness.deadline, |outer| {
            witness.deadline.min(tokio::time::Instant::from_std(outer))
        });
        if !self.state_machine.same_instance(&witness.store)
            || tokio::time::Instant::now() >= deadline
        {
            return Err(RemoteRaftError::Consensus(READ_INDEX_TIMEOUT.into()));
        }
        let generation = tokio::time::timeout_at(deadline, self.state_machine.generation())
            .await
            .map_err(|_| RemoteRaftError::Consensus(READ_INDEX_TIMEOUT.into()))?;
        if tokio::time::Instant::now() >= deadline
            || generation != witness.generation
            || !super::follower_read::bound(
                &self.raft,
                witness.leader,
                witness.term,
                witness.leader == self.id,
            )
        {
            return Err(RemoteRaftError::Consensus(
                "ReadIndex application witness is not current".into(),
            ));
        }
        Ok(())
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
        // Snapshot segments include transfer, validation and durable install,
        // not just an empty heartbeat. OpenRaft's inherited 200ms install
        // default gave this path a 150ms transport budget and could repeat the
        // same failed transfer forever after the source log had been purged.
        // Keep this separately bounded; the transport still caps each exchange
        // at its configured peer timeout and honors cancellation. Ordinary
        // append/heartbeat, ReadIndex and product request budgets are unchanged.
        install_snapshot_timeout: 1_000,
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
        assert_eq!(config.install_snapshot_timeout, 1_000);
        assert!(config.install_snapshot_timeout > config.heartbeat_interval);
        assert!(config.install_snapshot_timeout <= config.election_timeout_min);
        assert!(config.election_timeout_min >= 5 * config.heartbeat_interval);
        assert!(config.election_timeout_max >= config.election_timeout_min * 2);
        Ok(())
    }
}

#[cfg(test)]
#[path = "read_index_tests.rs"]
mod read_index_tests;
