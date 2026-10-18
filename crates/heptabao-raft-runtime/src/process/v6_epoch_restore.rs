//! Opaque actual ReadIndex ownership of a committed pending epoch restore.
//! This proof cannot read business data or attest ciphertext durability. It
//! only permits the actual trusted coordinator to prepare its exact next root.
use super::*;
use crate::v6_epoch_restore::{
    NativeV6EpochRestoreCommand, NativeV6EpochRestorePublication,
    NativeV6EpochRestoreSource, NativeV6PendingEpochRestore,
};
use crate::{NativeV6PeerEnrollment, NativeV6PublishedRoot};

type Log = openraft::alias::LogIdOf<crate::TypeConfig>;

pub struct NativeV6EpochRestoreRead {
    witness: ApplicationReadWitness,
    pub(super) pending: NativeV6PendingEpochRestore,
    source: NativeV6PublishedRoot,
    source_enrollment: NativeV6PeerEnrollment,
    target_enrollment: NativeV6PeerEnrollment,
    operation_deadline: std::time::Instant,
}

impl std::fmt::Debug for NativeV6EpochRestoreRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeV6EpochRestoreRead")
            .field("source_epoch", &self.source_enrollment.epoch())
            .field("target_epoch", &self.target_enrollment.epoch())
            .field("begin_index", &self.pending.begin_log.index)
            .field("intent_staged", &self.pending.intent.is_some())
            .finish_non_exhaustive()
    }
}

impl NativeV6EpochRestoreRead {
    // Only a sibling actual-admission implementation may consume this handle.
    // The caller has already selected the exact sealed pending intent; this
    // transfers its witness unchanged, never turning wire epoch facts into a
    // permission or extending its original ReadIndex deadline.
    pub(super) fn into_closure_selection(self) -> (
        ApplicationReadWitness, NativeV6PeerEnrollment, NativeV6PublishedRoot,
    ) {
        (self.witness, self.target_enrollment, self.source)
    }
    pub fn target_enrollment(&self) -> &NativeV6PeerEnrollment { &self.target_enrollment }
    pub fn source_enrollment(&self) -> &NativeV6PeerEnrollment { &self.source_enrollment }
    pub fn source_root(&self) -> &NativeV6PublishedRoot { &self.source }
    pub fn operation_digest(&self) -> [u8; 32] { self.pending.command.operation_digest }
    pub fn proposed_root_digest(&self) -> [u8; 32] { self.pending.command.proposed_root_digest }
    pub fn begin_log_id(&self) -> Log { self.pending.begin_log }
    pub fn intent(&self) -> Option<crate::NativeV6CommitIntent> {
        self.pending.intent.as_ref().map(|bound| bound.intent)
    }
    pub fn intent_log_id(&self) -> Option<Log> {
        self.pending.intent.as_ref().map(|bound| bound.log)
    }
    pub fn leader_id(&self) -> u64 { self.witness.leader }
    pub fn term(&self) -> u64 { self.witness.term }
    pub fn operation_deadline(&self) -> std::time::Instant { self.operation_deadline }
    pub fn read_index_deadline(&self) -> std::time::Instant { self.witness.deadline.into_std() }

    /// Comparison only: an unsealed Begin may become its EXACT sealed Stage.
    /// Own Stage changes applied generation, so its old witness is never
    /// revived. Verify a separately obtained new read before using it.
    pub fn same_transition(&self, other: &Self) -> bool {
        self.witness.store.same_instance(&other.witness.store)
            && self.witness.leader == other.witness.leader
            && self.witness.term == other.witness.term
            && self.operation_deadline == other.operation_deadline
            && self.pending.command == other.pending.command
            && self.pending.begin_log == other.pending.begin_log
            && self.target_enrollment == other.target_enrollment
            && self.source_enrollment == other.source_enrollment
            && self.source == other.source
            && match (&self.pending.intent, &other.pending.intent) {
                (Some(left), Some(right)) => left == right,
                (None, _) => true,
                (Some(_), None) => false,
            }
    }
}

fn unavailable() -> RemoteRaftError {
    RemoteRaftError::Consensus("exact pending native epoch restore unavailable".into())
}

impl ProcessRaftNode {
    /// Select a pending operation from actual applied state under a fresh
    /// quorum witness, and verify its original durable Begin slot or snapshot.
    /// The caller-supplied digest is only a lookup selector, never provenance.
    pub async fn native_v6_epoch_restore_read(
        &self,
        operation_digest: [u8; 32],
        deadline: std::time::Instant,
    ) -> Result<NativeV6EpochRestoreRead, RemoteRaftError> {
        super::super::with_read_index_deadline(deadline, async {
            let operation_deadline = super::super::read_deadline::current().unwrap_or(deadline);
            let (witness, enrollment, root) = self.native_v6_application_read_witness(operation_deadline)
                .await?;
            let enrollment = enrollment.ok_or_else(unavailable)?;
            let root = root.ok_or_else(unavailable)?;
            let pending = tokio::time::timeout_at(witness.deadline,
                self.state_machine.native_v6_pending_epoch_restore()).await
                .map_err(|_| unavailable())?.ok_or_else(unavailable)?;
            if operation_digest == [0; 32] || pending.command.operation_digest != operation_digest
                || !enrollment.pins().contains_key(&self.id)
                || !enrollment.pins().contains_key(&witness.leader)
                || pending.begin_log > witness.applied_log
                || pending.begin_log > witness.read_log
            {
                return Err(unavailable());
            }
            pending.matches_current(&enrollment.0, &root.0).map_err(|_| unavailable())?;
            self.verify_epoch_restore_begin_provenance(&pending, &witness).await?;
            self.verify_application_read_witness(&witness).await?;
            let target_enrollment = NativeV6PeerEnrollment(pending.target_enrollment.clone());
            Ok(NativeV6EpochRestoreRead {
                witness, pending, source: root, source_enrollment: enrollment,
                target_enrollment, operation_deadline,
            })
        }).await
    }

    async fn verify_epoch_restore_begin_provenance(
        &self, pending: &NativeV6PendingEpochRestore, witness: &ApplicationReadWitness,
    ) -> Result<(), RemoteRaftError> {
        let log = pending.begin_log;
        let end = log.index.checked_add(1).ok_or_else(unavailable)?;
        let mut reader = self.v6_intent_log_reader.clone();
        let entries = tokio::time::timeout_at(witness.deadline,
            reader.try_get_log_entries(log.index..end)).await
            .map_err(|_| unavailable())?.map_err(|_| unavailable())?;
        match entries.as_slice() {
            [entry] if entry.log_id == log => match &entry.payload {
                EntryPayload::Normal(crate::ApplicationRequest::RecordsV5(data)) => {
                    match &data.records_v5 {
                        crate::records::RecordCommand::BeginNativeV6EpochRestore { pending: command }
                            if command == &pending.command => {}
                        _ => return Err(unavailable()),
                    }
                }
                _ => return Err(unavailable()),
            },
            [] => {
                let membership = tokio::time::timeout_at(witness.deadline,
                    self.membership_observation()).await
                    .map_err(|_| unavailable())?.map_err(|_| unavailable())?;
                if membership.purged_index.is_none_or(|index| index < log.index) {
                    return Err(unavailable());
                }
                let persisted = tokio::time::timeout_at(witness.deadline,
                    self.state_machine.durable_snapshot_v6_epoch_restore_begin(&pending.command, log))
                    .await.map_err(|_| unavailable())?.map_err(|_| unavailable())?;
                if !persisted { return Err(unavailable()); }
            }
            _ => return Err(unavailable()),
        }
        Ok(())
    }

    pub async fn verify_native_v6_epoch_restore_read(
        &self, read: &NativeV6EpochRestoreRead,
    ) -> Result<(), RemoteRaftError> {
        super::super::with_read_index_deadline(read.operation_deadline, async {
            self.verify_application_read_witness(&read.witness).await
        }).await
    }

    /// Begin through actual durable Raft, bound to the SAME opaque current
    /// root and its original operation deadline. Only +1 is proposed; neither
    /// a caller epoch integer nor a configured pin map creates this transition.
    pub async fn begin_native_v6_epoch_restore(
        &self,
        serial: u64,
        source: &NativeV6CommittedRootRead,
        operation_digest: [u8; 32],
        proposed_root_digest: [u8; 32],
    ) -> Result<NativeV6EpochRestoreRead, RaftRuntimeError> {
        let deadline = source.operation_deadline();
        super::super::with_read_index_deadline(deadline, async {
            self.verify_native_v6_committed_root_read(source).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore source changed".into()))?;
            let pending = NativeV6EpochRestoreCommand {
                source: NativeV6EpochRestoreSource::from_current(&source.enrollment().0, &source.root().0)
                    .map_err(RaftRuntimeError::RecordRejected)?,
                operation_digest, proposed_root_digest,
                next_epoch: source.enrollment().epoch().checked_add(1)
                    .ok_or(RaftRuntimeError::RecordRejected(crate::RecordRejection::Invalid))?,
            };
            pending.validate().map_err(RaftRuntimeError::RecordRejected)?;
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),
                self.replicate_record_command(serial,
                    crate::records::RecordCommand::BeginNativeV6EpochRestore { pending: pending.clone() },
                    operation_digest)).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore Begin outcome unknown".into()))??;
            let actual = self.native_v6_epoch_restore_read(operation_digest, deadline).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore Begin requires reconciliation".into()))?;
            if actual.pending.command != pending {
                return Err(RaftRuntimeError::RecordRejected(crate::RecordRejection::StaleRoot));
            }
            Ok(actual)
        }).await
    }

    /// Trusted coordinator primitive. Its caller must separately retain the
    /// original Actor/local source and a REAL mTLS fsync majority for exactly
    /// this next-epoch intent/enrollment. This API grants no client success.
    pub async fn publish_native_v6_epoch_restore(
        &self,
        serial: u64,
        selected: &NativeV6EpochRestoreRead,
        intent_receipt: &CommitReceipt,
        sealed_root: Vec<u8>,
    ) -> Result<NativeV6PublishedRoot, RaftRuntimeError> {
        let deadline = selected.operation_deadline;
        super::super::with_read_index_deadline(deadline, async {
            self.verify_native_v6_epoch_restore_read(selected).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore pending source changed".into()))?;
            let admitted = selected.pending.intent.as_ref()
                .ok_or(RaftRuntimeError::RecordRejected(crate::RecordRejection::MissingDependency))?;
            self.reconcile_exact_staged_v6_intent(&admitted.intent, intent_receipt).await?;
            if intent_receipt.log_index != admitted.log.index
                || intent_receipt.leader_id != admitted.log.committed_leader_id().node_id
            {
                return Err(RaftRuntimeError::RecordRejected(crate::RecordRejection::StaleRoot));
            }
            self.verify_native_v6_epoch_restore_read(selected).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore pending source changed".into()))?;
            let root = crate::v6_root_publication::NativeV6RootCommand {
                intent: admitted.intent, intent_log: admitted.log,
                enrollment_digest: selected.target_enrollment.digest(),
                envelope: ReplicatedEnvelope::new(
                    crate::v6_root_publication::NativeV6RootCommand::operation_id(&admitted.intent),
                    admitted.intent.proposed_root_digest, sealed_root,
                )?,
            };
            root.validate().map_err(RaftRuntimeError::RecordRejected)?;
            let publication = NativeV6EpochRestorePublication { pending: selected.pending.clone(), root };
            let receipt = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),
                self.replicate_record_command(serial,
                    crate::records::RecordCommand::PublishNativeV6EpochRestore { publication },
                    admitted.intent.proposed_root_digest)).await
                .map_err(|_| RaftRuntimeError::Consensus("native epoch/root CAS outcome unknown".into()))??;
            self.reconcile_native_v6_root(&admitted.intent, &receipt, deadline).await
        }).await
    }

    /// Explicit cancellation by the trusted coordinator, never an automatic
    /// retry or timeout heuristic. A changed/sealed/superseded selection fails.
    pub async fn cancel_native_v6_epoch_restore(
        &self, serial: u64, selected: &NativeV6EpochRestoreRead,
    ) -> Result<(), RaftRuntimeError> {
        let deadline = selected.operation_deadline;
        super::super::with_read_index_deadline(deadline, async {
            self.verify_native_v6_epoch_restore_read(selected).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore cancellation source changed".into()))?;
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline),
                self.replicate_record_command(serial,
                    crate::records::RecordCommand::CancelNativeV6EpochRestore { pending: selected.pending.clone() },
                    selected.operation_digest())).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore cancellation outcome unknown".into()))??;
            let (witness, enrollment, root) = self.native_v6_application_read_witness(deadline).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore cancellation requires reconciliation".into()))?;
            let remaining = tokio::time::timeout_at(witness.deadline,
                self.state_machine.native_v6_pending_epoch_restore()).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore cancellation outcome unknown".into()))?;
            if remaining.is_some() || enrollment.as_ref() != Some(&selected.source_enrollment)
                || root.as_ref() != Some(&selected.source)
            {
                return Err(RaftRuntimeError::Consensus("native restore cancellation requires reconciliation".into()));
            }
            self.verify_application_read_witness(&witness).await
                .map_err(|_| RaftRuntimeError::Consensus("native restore cancellation witness changed".into()))
        }).await
    }
}
