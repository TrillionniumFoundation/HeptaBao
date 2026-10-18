//! A distinct, Raft-ordered native historical restore protocol.
//! Begin retains the active root and enrollment. Only its exact staged intent
//! admits next-epoch ciphertext. One later CAS activates root AND enrollment.
//! These internal wire facts never construct a public read/quorum capability.
use crate::v6_root_publication::{
    NativeV6EnrollmentState, NativeV6RootCommand, NativeV6RootState, valid_log,
};
use crate::{NativeV6CommitIntent, RecordRejection, TypeConfig};
use openraft::alias::LogIdOf;
use serde::{Deserialize, Serialize};

pub(crate) const MAX_NATIVE_EPOCH_TRANSITIONS: usize = 64;
const MAX_NATIVE_EPOCH_HISTORY_BYTES: usize = 512 * 1024;

fn follows(previous: LogIdOf<TypeConfig>, current: LogIdOf<TypeConfig>) -> bool {
    let before = previous.committed_leader_id();
    let after = current.committed_leader_id();
    previous.index < current.index
        && before.term <= after.term
        && (before.term != after.term || before.node_id == after.node_id)
}

pub(crate) mod lineage_wire {
    use super::{MAX_NATIVE_EPOCH_TRANSITIONS, NativeV6EpochRestoreRecord};
    use serde::de::{Error as _, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        records: &[NativeV6EpochRestoreRecord], serializer: S,
    ) -> Result<S::Ok, S::Error> {
        records.serialize(serializer)
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<NativeV6EpochRestoreRecord>, D::Error> {
        struct History;
        impl<'de> Visitor<'de> for History {
            type Value = Vec<NativeV6EpochRestoreRecord>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("at most 64 native epoch transitions")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                let mut records = Vec::new();
                while let Some(record) = sequence.next_element()? {
                    if records.len() == MAX_NATIVE_EPOCH_TRANSITIONS {
                        return Err(A::Error::custom("native epoch history capacity exceeded"));
                    }
                    records.push(record);
                }
                Ok(records)
            }
        }
        deserializer.deserialize_seq(History)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6EpochRestoreSource {
    pub(crate) root_digest: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) publication_log: LogIdOf<TypeConfig>,
    pub(crate) intent_log: LogIdOf<TypeConfig>,
    pub(crate) enrollment: NativeV6EnrollmentState,
    pub(crate) migration_digest: [u8; 32],
    pub(crate) migration_log: LogIdOf<TypeConfig>,
}

impl NativeV6EpochRestoreSource {
    pub(crate) fn from_current(enrollment: &NativeV6EnrollmentState, root: &NativeV6RootState)
    -> Result<Self, RecordRejection> {
        enrollment.validate()?;
        root.validate()?;
        if enrollment.digest() != root.command.enrollment_digest
            || enrollment.command.epoch != root.command.intent.epoch
            || enrollment.command.cluster_digest != root.command.intent.cluster_digest
        {
            return Err(RecordRejection::StaleRoot);
        }
        Ok(Self {
            root_digest: root.command.intent.proposed_root_digest,
            generation: root.command.intent.proposed_generation,
            publication_log: root.publication_log,
            intent_log: root.command.intent_log,
            enrollment: enrollment.clone(),
            migration_digest: root.migration_source_digest,
            migration_log: root.migration_source_log,
        })
    }

    fn validate(&self) -> Result<(), RecordRejection> {
        self.enrollment.validate()?;
        if self.root_digest == [0; 32] || self.migration_digest == [0; 32]
            || self.generation == 0
            || !valid_log(self.publication_log) || !valid_log(self.intent_log)
            || !valid_log(self.migration_log)
            || !follows(self.migration_log, self.intent_log)
            || !follows(self.enrollment.log, self.intent_log)
            || !follows(self.intent_log, self.publication_log)
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6EpochRestoreCommand {
    pub(crate) source: NativeV6EpochRestoreSource,
    pub(crate) operation_digest: [u8; 32],
    pub(crate) proposed_root_digest: [u8; 32],
    pub(crate) next_epoch: u64,
}

impl NativeV6EpochRestoreCommand {
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        self.source.validate()?;
        if self.operation_digest == [0; 32] || self.proposed_root_digest == [0; 32]
            || self.proposed_root_digest == self.source.root_digest
            || self.next_epoch != self.source.enrollment.command.epoch.checked_add(1)
                .ok_or(RecordRejection::Invalid)?
            || self.source.generation.checked_add(1).is_none()
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }

    pub(crate) fn matches_intent(&self, intent: &NativeV6CommitIntent)
    -> Result<(), RecordRejection> {
        self.validate()?;
        intent.encode()?;
        if intent.cluster_digest != self.source.enrollment.command.cluster_digest
            || intent.epoch != self.next_epoch
            || intent.operation_digest != self.operation_digest
            || intent.prior_root_digest != self.source.root_digest
            || intent.prior_generation != self.source.generation
            || intent.proposed_root_digest != self.proposed_root_digest
            || intent.proposed_generation != self.source.generation + 1
            || intent.expected_previous_commit_index != self.source.publication_log.index
        {
            return Err(RecordRejection::StaleRoot);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6EpochRestoreIntent {
    pub(crate) intent: NativeV6CommitIntent,
    pub(crate) log: LogIdOf<TypeConfig>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6PendingEpochRestore {
    pub(crate) command: NativeV6EpochRestoreCommand,
    pub(crate) begin_log: LogIdOf<TypeConfig>,
    pub(crate) target_enrollment: NativeV6EnrollmentState,
    pub(crate) intent: Option<NativeV6EpochRestoreIntent>,
}

impl NativeV6PendingEpochRestore {
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        self.command.validate()?;
        self.target_enrollment.validate()?;
        let mut expected = self.command.source.enrollment.command.clone();
        expected.epoch = self.command.next_epoch;
        if !valid_log(self.begin_log)
            || !follows(self.command.source.publication_log, self.begin_log)
            || self.target_enrollment.command != expected
            || self.target_enrollment.log != self.begin_log
        {
            return Err(RecordRejection::Invalid);
        }
        if let Some(intent) = &self.intent {
            self.command.matches_intent(&intent.intent)?;
            if !valid_log(intent.log) || !follows(self.begin_log, intent.log) {
                return Err(RecordRejection::Invalid);
            }
        }
        Ok(())
    }

    pub(crate) fn matches_current(
        &self, enrollment: &NativeV6EnrollmentState, root: &NativeV6RootState,
    ) -> Result<(), RecordRejection> {
        self.validate()?;
        if self.command.source != NativeV6EpochRestoreSource::from_current(enrollment, root)? {
            return Err(RecordRejection::StaleRoot);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6EpochRestorePublication {
    pub(crate) pending: NativeV6PendingEpochRestore,
    pub(crate) root: NativeV6RootCommand,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6EpochRestoreRecord {
    pub(crate) pending: NativeV6PendingEpochRestore,
    pub(crate) publication_log: LogIdOf<TypeConfig>,
}

/// Read-only lineage from an actual published root. This borrowed metadata can
/// compare authenticated old local cursor facts during catch-up; it is not a
/// fresh read witness, Actor authority, peer custody or a local install permit.
pub struct NativeV6EpochTransition<'a>(pub(crate) &'a NativeV6EpochRestoreRecord);

impl NativeV6EpochTransition<'_> {
    pub fn source_enrollment(&self) -> crate::NativeV6PeerEnrollment {
        crate::NativeV6PeerEnrollment(self.0.pending.command.source.enrollment.clone())
    }
    pub fn source_root_digest(&self) -> [u8; 32] { self.0.pending.command.source.root_digest }
    pub fn source_generation(&self) -> u64 { self.0.pending.command.source.generation }
    pub fn source_publication_log_id(&self) -> LogIdOf<TypeConfig> {
        self.0.pending.command.source.publication_log
    }
    pub fn source_intent_log_id(&self) -> LogIdOf<TypeConfig> {
        self.0.pending.command.source.intent_log
    }
    pub fn target_enrollment(&self) -> crate::NativeV6PeerEnrollment {
        crate::NativeV6PeerEnrollment(self.0.pending.target_enrollment.clone())
    }
    pub fn operation_digest(&self) -> [u8; 32] { self.0.pending.command.operation_digest }
    pub fn begin_log_id(&self) -> LogIdOf<TypeConfig> { self.0.pending.begin_log }
    pub fn intent(&self) -> Option<NativeV6CommitIntent> {
        self.0.pending.intent.as_ref().map(|sealed| sealed.intent)
    }
    pub fn intent_log_id(&self) -> Option<LogIdOf<TypeConfig>> {
        self.0.pending.intent.as_ref().map(|sealed| sealed.log)
    }
    pub fn publication_log_id(&self) -> LogIdOf<TypeConfig> { self.0.publication_log }
}

impl std::fmt::Debug for NativeV6EpochTransition<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeV6EpochTransition")
            .field("source_epoch", &self.0.pending.command.source.enrollment.command.epoch)
            .field("target_epoch", &self.0.pending.command.next_epoch)
            .field("publication_index", &self.0.publication_log.index)
            .finish_non_exhaustive()
    }
}

impl NativeV6EpochRestoreRecord {
    fn validate(&self) -> Result<(), RecordRejection> {
        self.pending.validate()?;
        let intent = self.pending.intent.as_ref().ok_or(RecordRejection::Invalid)?;
        if !valid_log(self.publication_log) || !follows(intent.log, self.publication_log) {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
}

pub(crate) fn validate_lineage(root: &NativeV6RootState) -> Result<(), RecordRejection> {
    if root.restore_lineage.len() > MAX_NATIVE_EPOCH_TRANSITIONS
        || crate::records::json_size(&root.restore_lineage)?
            > MAX_NATIVE_EPOCH_HISTORY_BYTES
    {
        return Err(RecordRejection::Budget);
    }
    let mut previous: Option<&NativeV6EpochRestoreRecord> = None;
    for record in &root.restore_lineage {
        record.validate()?;
        let source = &record.pending.command.source;
        let intent = record.pending.intent.as_ref().ok_or(RecordRejection::Invalid)?;
        if source.migration_digest != root.migration_source_digest
            || source.migration_log != root.migration_source_log
            || record.publication_log.index > root.publication_log.index
            || intent.intent.proposed_generation > root.command.intent.proposed_generation
        {
            return Err(RecordRejection::Invalid);
        }
        if let Some(previous) = previous {
            let prior_intent = &previous.pending.intent.as_ref()
                .ok_or(RecordRejection::Invalid)?.intent;
            if source.enrollment != previous.pending.target_enrollment
                || source.generation < prior_intent.proposed_generation
                || (source.generation > prior_intent.proposed_generation
                    && !follows(previous.publication_log, source.publication_log))
                || (source.generation == prior_intent.proposed_generation
                    && (source.publication_log != previous.publication_log
                        || source.intent_log != previous.pending.intent.as_ref()
                            .ok_or(RecordRejection::Invalid)?.log
                        || source.root_digest != prior_intent.proposed_root_digest))
            {
                return Err(RecordRejection::Invalid);
            }
        }
        previous = Some(record);
    }
    if let Some(last) = previous {
        let intent = last.pending.intent.as_ref().ok_or(RecordRejection::Invalid)?;
        if root.command.enrollment_digest != last.pending.target_enrollment.digest()
            || root.command.intent.epoch != last.pending.command.next_epoch
            || root.command.intent.cluster_digest
                != last.pending.target_enrollment.command.cluster_digest
            || (root.command.intent.proposed_generation > intent.intent.proposed_generation
                && !follows(last.publication_log, root.publication_log))
            || (root.command.intent.proposed_generation == intent.intent.proposed_generation
                && (root.publication_log != last.publication_log
                    || root.command.intent != intent.intent
                    || root.command.intent_log != intent.log))
        {
            return Err(RecordRejection::Invalid);
        }
    }
    Ok(())
}

impl crate::StateMachine {
    pub(crate) fn apply_begin_native_v6_epoch_restore(
        &mut self, command: &NativeV6EpochRestoreCommand,
    ) -> Result<(), RecordRejection> {
        command.validate()?;
        let current = self.v6_root.as_ref().ok_or(RecordRejection::MissingDependency)?;
        let enrollment = self.v6_enrollment.as_ref().ok_or(RecordRejection::MissingDependency)?;
        enrollment.command.matches_membership(&self.last_membership)?;
        if command.source != NativeV6EpochRestoreSource::from_current(enrollment, current)? {
            return Err(RecordRejection::StaleRoot);
        }
        if current.restore_lineage.len() >= MAX_NATIVE_EPOCH_TRANSITIONS {
            return Err(RecordRejection::Budget);
        }
        if let Some(existing) = &self.v6_pending_epoch_restore {
            return if existing.command == *command {
                Ok(())
            } else {
                Err(RecordRejection::ImmutableConflict)
            };
        }
        let begin_log = self.last_applied_log.ok_or(RecordRejection::Invalid)?;
        let mut target_enrollment = enrollment.clone();
        target_enrollment.command.epoch = command.next_epoch;
        target_enrollment.log = begin_log;
        let pending = NativeV6PendingEpochRestore {
            command: command.clone(), begin_log, target_enrollment, intent: None,
        };
        pending.validate()?;
        self.v6_epoch_protocol = Some(1);
        self.v6_pending_epoch_restore = Some(pending);
        // Neither active field is changed at Begin. Old-epoch business reads
        // remain available while the historical closure is being prepared.
        Ok(())
    }

    pub(crate) fn apply_cancel_native_v6_epoch_restore(
        &mut self, expected: &NativeV6PendingEpochRestore,
    ) -> Result<(), RecordRejection> {
        expected.validate()?;
        if self.v6_pending_epoch_restore.as_ref() != Some(expected) {
            return Err(RecordRejection::StaleRoot);
        }
        self.v6_pending_epoch_restore = None;
        Ok(())
    }

    pub(crate) fn validate_native_v6_epoch_intent_stage(
        &self, intent: &NativeV6CommitIntent,
    ) -> Result<(), RecordRejection> {
        let Some(root) = &self.v6_root else { return Ok(()); };
        let enrollment = self.v6_enrollment.as_ref().ok_or(RecordRejection::MissingDependency)?;
        if intent.epoch == enrollment.command.epoch {
            return Ok(());
        }
        let pending = self.v6_pending_epoch_restore.as_ref()
            .ok_or(RecordRejection::StaleRoot)?;
        pending.matches_current(enrollment, root)?;
        pending.command.matches_intent(intent)?;
        let log = self.last_applied_log.ok_or(RecordRejection::Invalid)?;
        if log.index <= pending.begin_log.index
            || pending.intent.as_ref().is_some_and(|existing| existing.intent != *intent)
        {
            return Err(RecordRejection::ImmutableConflict);
        }
        Ok(())
    }

    pub(crate) fn record_native_v6_epoch_intent_stage(
        &mut self, intent: NativeV6CommitIntent, log: LogIdOf<TypeConfig>,
    ) {
        if let Some(pending) = &mut self.v6_pending_epoch_restore
            && pending.command.matches_intent(&intent).is_ok()
        {
            // Called only after successful Stage and insertion of its actual
            // immutable FIRST applied-log provenance. Duplicate Stage cannot
            // rebind the pending operation to a later log slot.
            pending.intent.get_or_insert(NativeV6EpochRestoreIntent { intent, log });
        }
    }

    pub(crate) fn apply_publish_native_v6_epoch_restore(
        &mut self, publication: &NativeV6EpochRestorePublication,
    ) -> Result<(), RecordRejection> {
        let pending = &publication.pending;
        pending.validate()?;
        publication.root.validate()?;
        if self.v6_pending_epoch_restore.as_ref() != Some(pending) {
            return Err(RecordRejection::StaleRoot);
        }
        let current = self.v6_root.as_ref().ok_or(RecordRejection::MissingDependency)?;
        let enrollment = self.v6_enrollment.as_ref().ok_or(RecordRejection::MissingDependency)?;
        enrollment.command.matches_membership(&self.last_membership)?;
        pending.matches_current(enrollment, current)?;
        let admitted = pending.intent.as_ref().ok_or(RecordRejection::MissingDependency)?;
        if publication.root.intent != admitted.intent
            || publication.root.intent_log != admitted.log
            || publication.root.enrollment_digest != pending.target_enrollment.digest()
        {
            return Err(RecordRejection::StaleRoot);
        }
        let object = crate::SealedRecordObject::new_native_v6_commit_intent(admitted.intent)
            .map_err(|_| RecordRejection::Invalid)?;
        if self.v6_intent_log_id(&object.reference().id) != Some(admitted.log)
            || self.records_v5.as_ref().ok_or(RecordRejection::MissingDependency)?
                .object(object.reference())? != Some(object)
        {
            return Err(RecordRejection::MissingDependency);
        }
        let publication_log = self.last_applied_log.ok_or(RecordRejection::Invalid)?;
        let mut lineage = current.restore_lineage.clone();
        lineage.push(NativeV6EpochRestoreRecord { pending: pending.clone(), publication_log });
        let root = NativeV6RootState {
            command: publication.root.clone(), publication_log,
            migration_source_digest: current.migration_source_digest,
            migration_source_log: current.migration_source_log,
            restore_lineage: lineage,
        };
        root.validate()?;
        // One Raft apply publishes both active facts. A restart/snapshot cannot
        // expose new enrollment with an old root, or consume pending early.
        self.v6_enrollment = Some(pending.target_enrollment.clone());
        self.v6_root = Some(root);
        self.v6_pending_epoch_restore = None;
        Ok(())
    }
}
