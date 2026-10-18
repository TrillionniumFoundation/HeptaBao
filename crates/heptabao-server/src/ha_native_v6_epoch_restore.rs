//! A historical restore publishes one new epoch/root through actual Raft.
//! Archive bytes are data. Original Service custody remains in `original_gate`
//! through Begin, authenticated ciphertext fsync quorum, CAS and actual reread.
use super::*;
use crate::ha_state::native_v6::{CodecResult, NativeV6CodecError};
use crate::service::native_v6_ha_objects::PreparedNativeV6HaObjects;
use heptabao_ha_service::replicate_native_v6_closure_to_quorum;
use heptabao_raft_runtime::{NativeV6CommitIntent, NativeV6EpochRestoreRead,
    SealedRecordObject, with_read_index_deadline};
use ring::rand::{SecureRandom, SystemRandom};
use std::cell::RefCell;

/// A failure never invites automatic retry. Even before root invocation a
/// Begin/Stage may have committed. The random identifier only selects that
/// exact operation for explicit reconciliation; it is no retry authority.
#[derive(Debug)]
pub(crate) struct NativeHaEpochRestoreError {
    operation: Option<[u8; 32]>,
    root_attempted: bool,
    reason: String,
}
impl NativeHaEpochRestoreError {
    pub(crate) fn root_attempted(&self) -> bool { self.root_attempted }
    pub(crate) fn operation_digest(&self) -> Option<[u8; 32]> { self.operation }
    pub(crate) fn reference_id(&self) -> Option<String> {
        self.operation.map(|operation| {
            let mut text = String::from("native-v6-restore-");
            for byte in operation { use std::fmt::Write as _; let _ = write!(text, "{byte:02x}"); }
            text
        })
    }
}
impl fmt::Display for NativeHaEpochRestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native historical restore requires reconciliation (root_attempted={}): {}",
            self.root_attempted, self.reason)
    }
}
impl std::error::Error for NativeHaEpochRestoreError {}

pub(crate) enum NativeHaPendingRestoreOutcome {
    Pending([u8; 32]),
    Cancelled,
    NotPending,
    Committed,
    DifferentPending,
}
impl NativeHaPendingRestoreOutcome {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Pending(_) => "pending",
            Self::Cancelled => "cancelled",
            Self::NotPending => "not_pending",
            Self::Committed => "committed",
            Self::DifferentPending => "different_pending",
        }
    }
    pub(crate) fn pending_operation(&self) -> Option<[u8; 32]> {
        match self { Self::Pending(operation) => Some(*operation), _ => None }
    }
}

fn original(deadline: OriginalDeadline, gate: &mut dyn FnMut() -> CodecResult<()>) -> CodecResult<()> {
    if crate::request_deadline::current() != Some(deadline.instant()) {
        return Err(NativeV6CodecError::Gate);
    }
    deadline.check().map_err(|_| NativeV6CodecError::Gate)?;
    gate()?;
    deadline.check().map_err(|_| NativeV6CodecError::Gate)
}

// Own Begin/Stage legitimately invalidate earlier applied-generation witnesses.
// A fresh witness must compare this exact operation, Begin/full source logs,
// leader/term, static and dynamic enrollment, root, and original deadline.
// It never refreshes on arbitrary currentness failure, only capped expiry.
struct PendingOwner<'a> {
    process: &'a HaProcess,
    initial: NativeV6EpochRestoreRead,
    active: Option<NativeV6EpochRestoreRead>,
    deadline: OriginalDeadline,
}
impl PendingOwner<'_> {
    fn fresh_same(&self) -> Result<NativeV6EpochRestoreRead, String> {
        self.deadline.check().map_err(|error| error.to_string())?;
        let node = self.process.node.as_ref().ok_or("HA process is shut down")?;
        let fresh = self.process.runtime.block_on(node.native_v6_epoch_restore_read(
            self.initial.operation_digest(), self.deadline.instant(),
        )).map_err(|error| error.to_string())?;
        if !self.initial.same_transition(&fresh) || fresh.leader_id() != node.id() {
            return Err("native epoch restore original pending operation changed".into());
        }
        self.process.runtime.block_on(node.verify_native_v6_epoch_restore_read(&fresh))
            .map_err(|error| error.to_string())?;
        self.deadline.check().map_err(|error| error.to_string())?;
        Ok(fresh)
    }
    fn check(&mut self) -> CodecResult<()> {
        self.deadline.check().map_err(|_| NativeV6CodecError::Gate)?;
        if Instant::now() >= self.active.as_ref().unwrap_or(&self.initial).read_index_deadline() {
            self.active = Some(self.fresh_same().map_err(|_| NativeV6CodecError::Gate)?);
        }
        let node = self.process.node.as_ref().ok_or(NativeV6CodecError::Gate)?;
        self.process.runtime.block_on(node.verify_native_v6_epoch_restore_read(
            self.active.as_ref().unwrap_or(&self.initial),
        )).map_err(|_| NativeV6CodecError::Gate)
    }
}

impl HaProcess {
    /// A NEW explicitly admitted request may reconcile one exact operation.
    /// This method never invokes Begin, Stage or a historical root CAS. Only a
    /// matching actual pending operation can be cancelled. With no supplied
    /// operation this is an explicit read-only discovery request, and returns
    /// only the actual current pending selector under the same source witness.
    /// A committed lineage entry, verified absence and a different pending
    /// operation are read-only outcomes. Cancellation timeout never becomes
    /// absence or success.
    pub(crate) fn reconcile_native_v6_historical_restore(
        &self,
        anchor: &NativeV6ArchiveRootAnchor,
        operation: Option<[u8; 32]>,
        original_gate: &mut dyn FnMut() -> CodecResult<()>,
    ) -> Result<(CommittedNativeV6Read, NativeHaPendingRestoreOutcome), NativeHaEpochRestoreError> {
        let deadline = anchor.deadline();
        let stopped = |reason: String| NativeHaEpochRestoreError {
            operation, root_attempted: false, reason,
        };
        original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
        if operation == Some([0; 32]) {
            return Err(stopped("invalid pending restore reference".into()));
        }
        let node = self.node.as_ref().ok_or_else(|| stopped("HA process is shut down".into()))?;
        let selected = anchor.fresh_for_epoch_restore(self)
            .map_err(|error| stopped(error.to_string()))?;
        let (selected, outcome) = if operation.is_none() {
            let pending = self.runtime.block_on(node.native_v6_pending_epoch_restore_operation(&selected))
                .map_err(|error| stopped(error.to_string()))?;
            let outcome = match pending {
                Some(operation) => NativeHaPendingRestoreOutcome::Pending(operation),
                None => NativeHaPendingRestoreOutcome::NotPending,
            };
            (selected, outcome)
        } else if selected.root().epoch_transitions()
            .any(|step| Some(step.operation_digest()) == operation)
        {
            (selected, NativeHaPendingRestoreOutcome::Committed)
        } else {
            match self.runtime.block_on(node.native_v6_pending_epoch_restore_operation(&selected))
                .map_err(|error| stopped(error.to_string()))?
            {
                None => (selected, NativeHaPendingRestoreOutcome::NotPending),
                Some(pending_operation) if Some(pending_operation) != operation =>
                    (selected, NativeHaPendingRestoreOutcome::DifferentPending),
                Some(pending_operation) => {
                    let pending = self.runtime.block_on(node.native_v6_epoch_restore_read(
                        pending_operation, deadline.instant(),
                    )).map_err(|error| stopped(error.to_string()))?;
                    if pending.source_root() != selected.root()
                        || pending.source_enrollment() != selected.enrollment()
                        || pending.leader_id() != node.id()
                        || pending.term() != selected.term()
                        || pending.operation_deadline() != deadline.instant()
                    {
                        return Err(stopped("pending cancellation changed original source custody".into()));
                    }
                    let serial = self.runtime.block_on(node.next_production_client_serial())
                        .map_err(|error| stopped(error.to_string()))?;
                    original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
                    self.runtime.block_on(node.cancel_native_v6_epoch_restore(serial, &pending))
                        .map_err(|error| stopped(error.to_string()))?;
                    original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
                    // Own cancellation changes applied generation. Retire both
                    // old witnesses; only a new actual read of the unchanged
                    // complete source under the original leader/term may pass.
                    let fresh = self.runtime.block_on(node.native_v6_committed_root_read(deadline.instant()))
                        .map_err(|error| stopped(error.to_string()))?
                        .ok_or_else(|| stopped("native source absent after pending cancellation".into()))?;
                    if fresh.root() != selected.root() || fresh.enrollment() != selected.enrollment()
                        || fresh.leader_id() != node.id() || fresh.term() != selected.term()
                        || fresh.operation_deadline() != deadline.instant()
                    {
                        return Err(stopped("native source changed after pending cancellation".into()));
                    }
                    if self.runtime.block_on(node.native_v6_pending_epoch_restore_operation(&fresh))
                        .map_err(|error| stopped(error.to_string()))?.is_some()
                    {
                        return Err(stopped("pending cancellation requires reconciliation".into()));
                    }
                    (fresh, NativeHaPendingRestoreOutcome::Cancelled)
                }
            }
        };
        original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
        let read = self.native_v6_committed_read(deadline).map_err(stopped)?
            .ok_or_else(|| stopped("native reconciliation source is absent".into()))?;
        if !read.selected.same_selection(&selected) {
            return Err(stopped("native reconciliation observation changed".into()));
        }
        self.verify_native_v6_committed_read(&read).map_err(stopped)?;
        original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
        Ok((read, outcome))
    }

    #[cfg(test)]
    pub(crate) fn pending_native_v6_restore_for_test(
        &self, read: &CommittedNativeV6Read,
    ) -> Result<Option<[u8; 32]>, String> {
        self.verify_native_v6_committed_read(read)?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        let operation = self.runtime.block_on(node.native_v6_pending_epoch_restore_operation(&read.selected))
            .map_err(|error| error.to_string())?;
        self.verify_native_v6_committed_read(read)?;
        Ok(operation)
    }

    /// The proposed digest is computed from the completely authenticated
    /// historical typed graph with live protected floors before Begin. Only
    /// the actual committed Begin creates the target enrollment used to seal
    /// new ciphertext; an archive epoch never acts as transport admission.
    pub(crate) fn publish_native_v6_historical_restore(
        &self,
        anchor: &NativeV6ArchiveRootAnchor,
        proposed_root_digest: [u8; 32],
        prepare: impl FnOnce(
            &ClusterStateCodec, &NativeV6PeerEnrollment, &LocalV6BlobStage,
            &mut dyn FnMut() -> CodecResult<()>,
        ) -> CodecResult<PreparedNativeV6HaObjects>,
        original_gate: &mut dyn FnMut() -> CodecResult<()>,
    ) -> Result<CommittedNativeV6Read, NativeHaEpochRestoreError> {
        let deadline = anchor.deadline();
        let before = |reason: String| NativeHaEpochRestoreError {
            operation: None, root_attempted: false, reason,
        };
        original(deadline, original_gate).map_err(|error| before(error.to_string()))?;
        let native = self.native_v6.as_ref().filter(|native| native.enabled())
            .ok_or_else(|| before("native HA was not explicitly enabled".into()))?;
        let node = self.node.as_ref().ok_or_else(|| before("HA process is shut down".into()))?;
        let storage = native.storage.get().ok_or_else(|| before("native ciphertext store absent".into()))?;
        let selected = anchor.fresh_for_epoch_restore(self).map_err(|error| before(error.to_string()))?;
        if proposed_root_digest == [0; 32] || proposed_root_digest == selected.root().root_digest() {
            return Err(before("native epoch restore proposed root is invalid".into()));
        }
        let mut operation = [0; 32];
        SystemRandom::new().fill(&mut operation)
            .map_err(|_| before("native restore operation randomness unavailable".into()))?;
        let stopped = |reason: String| NativeHaEpochRestoreError {
            operation: Some(operation), root_attempted: false, reason,
        };
        let begin_serial = self.runtime.block_on(node.next_production_client_serial())
            .map_err(|error| before(error.to_string()))?;
        original(deadline, original_gate).map_err(|error| before(error.to_string()))?;
        let pending = self.runtime.block_on(node.begin_native_v6_epoch_restore(
            begin_serial, &selected, operation, proposed_root_digest,
        )).map_err(|error| stopped(error.to_string()))?;
        original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
        let enrollment = pending.target_enrollment().clone();
        let term = pending.term();
        if pending.source_root() != selected.root()
            || pending.source_enrollment() != selected.enrollment()
            || enrollment.epoch() != selected.enrollment().epoch().checked_add(1)
                .ok_or_else(|| stopped("native epoch exhausted".into()))?
            || pending.leader_id() != node.id()
            || pending.operation_deadline() != deadline.instant()
        {
            return Err(stopped("native restore Begin differs from original source".into()));
        }
        native.validate_enrollment(&self.codec, &enrollment).map_err(stopped)?;
        let owner = RefCell::new(PendingOwner { process: self, initial: pending,
            active: None, deadline });
        let prepared = prepare(&self.codec, &enrollment, storage, &mut || {
            original(deadline, original_gate)?;
            owner.try_borrow_mut().map_err(|_| NativeV6CodecError::Gate)?.check()?;
            original(deadline, original_gate)
        }).map_err(|error| stopped(error.to_string()))?;
        if prepared.root_digest() != proposed_root_digest
            || prepared.original_deadline().instant() != deadline.instant()
        {
            return Err(stopped("native restore preparation changed proposed root or deadline".into()));
        }
        let local = prepared.local_closure();
        let intent = NativeV6CommitIntent {
            cluster_digest: enrollment.cluster_digest(), epoch: enrollment.epoch(),
            operation_digest: operation, closure_manifest_sha256: local.manifest_sha256(),
            object_count: local.object_count() as u64, ciphertext_bytes: local.ciphertext_bytes(),
            prior_root_digest: selected.root().root_digest(), proposed_root_digest,
            prior_generation: selected.root().generation(),
            proposed_generation: selected.root().generation().checked_add(1)
                .ok_or_else(|| stopped("native root generation exhausted".into()))?,
            expected_previous_commit_index: selected.root().publication_log_id().index,
        };
        let object = SealedRecordObject::new_native_v6_commit_intent(intent)
            .map_err(|error| stopped(error.to_string()))?;
        let proposal = prepared.into_proposal(&self.codec, &enrollment, intent, &mut || {
            original(deadline, original_gate)?;
            owner.try_borrow_mut().map_err(|_| NativeV6CodecError::Gate)?.check()
        }).map_err(|error| stopped(error.to_string()))?;
        let serial = self.runtime.block_on(node.next_production_client_serial())
            .map_err(|error| stopped(error.to_string()))?;
        original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
        owner.borrow_mut().check().map_err(|error| stopped(error.to_string()))?;
        let intent_receipt = self.runtime.block_on(with_read_index_deadline(deadline.instant(), async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.instant()),
                node.stage_application_object(serial, &object)).await
        })).map_err(|_| stopped("native restore Stage outcome unknown; root not invoked".into()))?
            .map_err(|error| stopped(error.to_string()))?;
        original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
        let staged = owner.borrow().fresh_same().map_err(stopped)?;
        if staged.intent() != Some(intent) || staged.intent_log_id().is_none_or(|log| {
            log.index != intent_receipt.log_index || log.committed_leader_id().node_id != intent_receipt.leader_id
        }) || staged.term() != term {
            return Err(stopped("native restore Stage original provenance differs".into()));
        }
        self.runtime.block_on(with_read_index_deadline(deadline.instant(),
            node.reconcile_exact_staged_v6_intent(&intent, &intent_receipt)))
            .map_err(|error| stopped(error.to_string()))?;
        // The Stage-bound owner is new actual authority. The pre-Stage witness
        // is retired; no caller can turn its stale generation into permission.
        let owner = RefCell::new(PendingOwner { process: self, initial: staged,
            active: None, deadline });
        original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
        owner.borrow_mut().check().map_err(|error| stopped(error.to_string()))?;
        let quorum = replicate_native_v6_closure_to_quorum(
            node, self.runtime.handle(), &native.transport, &self.peers, storage,
            proposal.references(), &intent, deadline.instant(),
        ).map_err(|error| stopped(error.to_string()))?;
        original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
        if quorum.intent() != &intent || quorum.enrollment() != &enrollment {
            return Err(stopped("native restore fsync quorum differs from exact pending intent".into()));
        }
        let selected_pending = owner.borrow().fresh_same().map_err(stopped)?;
        let root_serial = self.runtime.block_on(node.next_production_client_serial())
            .map_err(|error| stopped(error.to_string()))?;
        self.runtime.block_on(with_read_index_deadline(deadline.instant(),
            quorum.verify_for_publication(node))).map_err(|error| stopped(error.to_string()))?;
        original(deadline, original_gate).map_err(|error| stopped(error.to_string()))?;
        let unknown = |reason: String| NativeHaEpochRestoreError {
            operation: Some(operation), root_attempted: true, reason,
        };
        // Never retry an attempted epoch/root CAS, including engine rejection.
        let published = self.runtime.block_on(node.publish_native_v6_epoch_restore(
            root_serial, &selected_pending, &intent_receipt, proposal.sealed_root().to_vec(),
        )).map_err(|error| unknown(error.to_string()))?;
        original(deadline, original_gate).map_err(|error| unknown(error.to_string()))?;
        let read = self.native_v6_committed_read(deadline).map_err(unknown)?
            .ok_or_else(|| unknown("native restored committed root is absent".into()))?;
        if read.published() != &published || read.published().intent() != intent
            || read.enrollment() != &enrollment
        {
            return Err(unknown("native restored root was changed or superseded".into()));
        }
        self.verify_native_v6_committed_read(&read).map_err(unknown)?;
        original(deadline, original_gate).map_err(|error| unknown(error.to_string()))?;
        Ok(read)
    }
}
