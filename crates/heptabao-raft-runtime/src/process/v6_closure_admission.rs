//! Fresh follower-capable admission for one actually committed native intent.
//! This selects consensus metadata only; ciphertext fsync and Actor authority
//! must come from their real owners. No wire fields can construct this handle.
use super::*;
use crate::{NativeV6CommitIntent, NativeV6PeerEnrollment, SealedRecordObject};

type NativeLogId = openraft::type_config::alias::LogIdOf<crate::state_machine::TypeConfig>;

/// One exact intent, enrollment and original log provenance, observed under
/// this runtime instance's fresh quorum/read deadline. This is neither Clone
/// nor Serialize/Deserialize. It does not certify any ciphertext or HTTP reply.
pub struct NativeV6ClosureAdmission {
    witness: ApplicationReadWitness,
    enrollment: NativeV6PeerEnrollment,
    intent: NativeV6CommitIntent,
    intent_log: NativeLogId,
    intent_object_digest: [u8; 32],
}

impl std::fmt::Debug for NativeV6ClosureAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeV6ClosureAdmission")
            .field("leader", &self.witness.leader)
            .field("term", &self.witness.term)
            .field("intent_index", &self.intent_log.index)
            .field("voters", &self.enrollment.pins().len())
            .finish_non_exhaustive()
    }
}

impl NativeV6ClosureAdmission {
    pub fn enrollment(&self) -> &NativeV6PeerEnrollment {
        &self.enrollment
    }
    pub fn intent(&self) -> &NativeV6CommitIntent {
        &self.intent
    }
    pub fn intent_log_id(&self) -> NativeLogId {
        self.intent_log
    }
    pub fn intent_object_digest(&self) -> [u8; 32] {
        self.intent_object_digest
    }
    pub fn leader_id(&self) -> u64 {
        self.witness.leader
    }
    pub fn term(&self) -> u64 {
        self.witness.term
    }
    pub fn deadline(&self) -> std::time::Instant {
        self.witness.deadline.into_std()
    }
}

impl ProcessRaftNode {
    /// Resolve an untrusted expected intent against this node's ACTUAL applied
    /// state and durable original Raft log/snapshot, including on followers.
    /// A supplied CommitReceipt, numeric applied hint or locally parsed intent
    /// never substitutes for this observation. No leadership is inferred from
    /// accepting a TLS connection: callers compare its real peer identity to
    /// the returned current leader and committed enrollment.
    pub async fn admit_native_v6_closure(
        &self,
        expected: &NativeV6CommitIntent,
        deadline: std::time::Instant,
    ) -> Result<NativeV6ClosureAdmission, RemoteRaftError> {
        fn unavailable() -> RemoteRaftError {
            RemoteRaftError::Consensus("committed native closure admission unavailable".into())
        }
        super::super::with_read_index_deadline(deadline, async {
            let (witness, enrollment, root) = self
                .native_v6_application_read_witness(deadline)
                .await
                .map_err(|_| unavailable())?;
            let enrollment = enrollment.ok_or_else(unavailable)?;
            // A next-epoch transfer has ONE distinct admission path. It must
            // consume an actual fresh pending restore read whose exact Stage
            // is already sealed in Raft. A numeric epoch or configured pins
            // cannot widen ordinary current-epoch admission. This replaces
            // the initial lookup witness with the actual pending witness;
            // neither handle is revived after an intervening apply.
            let (witness, enrollment, root, restore_intent_log) =
                if expected.epoch == enrollment.epoch() {
                    (witness, enrollment, root, None)
                } else {
                    let pending = self
                        .native_v6_epoch_restore_read(expected.operation_digest, deadline)
                        .await
                        .map_err(|_| unavailable())?;
                    if pending.intent() != Some(*expected) {
                        return Err(unavailable());
                    }
                    let log = pending.intent_log_id().ok_or_else(unavailable)?;
                    let (witness, enrollment, source) = pending.into_closure_selection();
                    (witness, enrollment, Some(source), Some(log))
                };
            let bound = witness.deadline;
            if !enrollment.pins().contains_key(&self.id)
                || expected.cluster_digest != enrollment.cluster_digest()
                || expected.epoch != enrollment.epoch()
                || witness.term == 0
                || !enrollment.pins().contains_key(&witness.leader)
            {
                return Err(unavailable());
            }
            let object = SealedRecordObject::new_native_v6_commit_intent(*expected)
                .map_err(|_| unavailable())?;
            let intent_log = tokio::time::timeout_at(
                bound,
                self.state_machine
                    .native_v6_intent_origin(&object.reference().id),
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
            if intent_log.index == 0
                || intent_log.committed_leader_id().node_id == 0
                || intent_log.committed_leader_id().term == 0
                || intent_log.index <= expected.expected_previous_commit_index
                || intent_log > witness.read_log
                || intent_log > witness.applied_log
                || restore_intent_log.is_some_and(|exact| exact != intent_log)
            {
                return Err(unavailable());
            }

            // An exact current root can be rechecked after a lost reply. Any
            // different superseding root makes this old intent unavailable.
            match root.as_ref() {
                Some(root)
                    if root.intent() == *expected
                        && root.intent_log_id() == intent_log
                        && root.enrollment_digest() == enrollment.digest() => {}
                Some(root)
                    if root.root_digest() == expected.prior_root_digest
                        && root.generation() == expected.prior_generation
                        && root.publication_log_id().index
                            == expected.expected_previous_commit_index => {}
                None if expected.prior_generation == 0 => {
                    let source = tokio::time::timeout_at(
                        bound,
                        self.state_machine.native_v6_migration_source(),
                    )
                    .await
                    .map_err(|_| unavailable())?
                    .ok_or_else(unavailable)?;
                    if source.0 != expected.prior_root_digest
                        || source.1.index != expected.expected_previous_commit_index
                        || source.1 >= intent_log
                    {
                        return Err(unavailable());
                    }
                }
                _ => return Err(unavailable()),
            }

            // Fetch the exact persisted slot, not merely the cached object or
            // its last-applied number. A purged slot instead requires the real
            // persisted state-machine snapshot's original FULL LogId.
            let end = intent_log.index.checked_add(1).ok_or_else(unavailable)?;
            let mut reader = self.v6_intent_log_reader.clone();
            let entries =
                tokio::time::timeout_at(bound, reader.try_get_log_entries(intent_log.index..end))
                    .await
                    .map_err(|_| unavailable())?
                    .map_err(|_| unavailable())?;
            match entries.as_slice() {
                [entry] if entry.log_id == intent_log => match &entry.payload {
                    EntryPayload::Normal(crate::state_machine::ApplicationRequest::RecordsV5(
                        data,
                    )) => match &data.records_v5 {
                        crate::records::RecordCommand::Stage { object: staged }
                            if staged == &object => {}
                        _ => return Err(unavailable()),
                    },
                    _ => return Err(unavailable()),
                },
                [] => {
                    let membership = tokio::time::timeout_at(bound, self.membership_observation())
                        .await
                        .map_err(|_| unavailable())?
                        .map_err(|_| unavailable())?;
                    if membership
                        .purged_index
                        .is_none_or(|purged| purged < intent_log.index)
                    {
                        return Err(unavailable());
                    }
                    let persisted = tokio::time::timeout_at(
                        bound,
                        self.state_machine.durable_snapshot_v6_intent_log_id(
                            &object.reference().id,
                            intent_log.index,
                        ),
                    )
                    .await
                    .map_err(|_| unavailable())?
                    .map_err(|_| unavailable())?;
                    if persisted != Some(intent_log) {
                        return Err(unavailable());
                    }
                }
                _ => return Err(unavailable()),
            }
            let applied_object = tokio::time::timeout_at(
                bound,
                self.state_machine.record_object(object.reference()),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
            if applied_object.as_ref() != Some(&object) {
                return Err(unavailable());
            }
            // This also fences every intervening apply, snapshot install,
            // ownership/reopen, term change and original deadline expiry.
            self.verify_application_read_witness(&witness).await?;
            Ok(NativeV6ClosureAdmission {
                witness,
                enrollment,
                intent: *expected,
                intent_log,
                intent_object_digest: object.reference().id,
            })
        })
        .await
    }

    /// Revalidate this same instance/generation/term under the handle's original
    /// bound. This does not renew the witness or observe a new request clock.
    pub async fn verify_native_v6_closure_admission(
        &self,
        admission: &NativeV6ClosureAdmission,
    ) -> Result<(), RemoteRaftError> {
        self.verify_application_read_witness(&admission.witness)
            .await
    }
}
