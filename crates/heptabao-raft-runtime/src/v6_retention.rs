//! Replicated retirement of strictly superseded native commit intents.
//!
//! This changes only bounded Raft metadata. It is deliberately NOT permission
//! to unlink ciphertext: a durable checkpoint, retained log, snapshot, restore
//! lineage or in-flight operation can still require the old closure.
use crate::records::{RecordCommand, RecordRootBase};
use crate::v6_root_publication::valid_log;
use crate::{
    NativeV6CommitIntent, RecordObjectId, RecordRejection, SealedRecordObject, TypeConfig,
};
use openraft::alias::LogIdOf;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_RETIREMENT_INTENTS: usize = 32;
pub(crate) const RETENTION_PROTOCOL: u8 = 1;
pub(crate) type Log = LogIdOf<TypeConfig>;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6RetentionSource {
    pub(crate) enrollment_digest: [u8; 32],
    pub(crate) root_digest: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) epoch: u64,
    pub(crate) publication_log: Log,
    pub(crate) intent_log: Log,
}

impl NativeV6RetentionSource {
    pub(crate) fn from_state(state: &crate::StateMachine) -> Result<Self, RecordRejection> {
        let root = state
            .v6_root
            .as_ref()
            .ok_or(RecordRejection::MissingDependency)?;
        let enrollment = state
            .v6_enrollment
            .as_ref()
            .ok_or(RecordRejection::MissingDependency)?;
        root.validate()?;
        enrollment.validate()?;
        enrollment
            .command
            .matches_membership(&state.last_membership)?;
        if root.command.enrollment_digest != enrollment.digest()
            || root.command.intent.cluster_digest != enrollment.command.cluster_digest
            || root.command.intent.epoch != enrollment.command.epoch
        {
            return Err(RecordRejection::StaleRoot);
        }
        Ok(Self {
            enrollment_digest: enrollment.digest(),
            root_digest: root.command.intent.proposed_root_digest,
            generation: root.command.intent.proposed_generation,
            epoch: root.command.intent.epoch,
            publication_log: root.publication_log,
            intent_log: root.command.intent_log,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        if self.enrollment_digest == [0; 32]
            || self.root_digest == [0; 32]
            || self.generation == 0
            || !valid_log(self.publication_log)
            || !valid_log(self.intent_log)
            || self.intent_log.index >= self.publication_log.index
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6RetiredIntent {
    pub(crate) id: RecordObjectId,
    pub(crate) original_log: Log,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6IntentRetirementCommand {
    pub(crate) protocol: u8,
    pub(crate) source: NativeV6RetentionSource,
    pub(crate) intents: Vec<NativeV6RetiredIntent>,
}

impl NativeV6IntentRetirementCommand {
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        self.source.validate()?;
        if self.protocol != RETENTION_PROTOCOL || self.intents.len() > MAX_RETIREMENT_INTENTS {
            return Err(RecordRejection::Invalid);
        }
        let mut previous = None;
        for selected in &self.intents {
            if selected.id == [0; 32]
                || !valid_log(selected.original_log)
                || previous.is_some_and(|id| id >= selected.id)
            {
                return Err(RecordRejection::Invalid);
            }
            previous = Some(selected.id);
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], RecordRejection> {
        use sha2::{Digest, Sha256};
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"HeptaBao/native-v6/intent-retirement/v1\0");
        hash.update(serde_json::to_vec(self).map_err(|_| RecordRejection::Invalid)?);
        Ok(hash.finalize().into())
    }
}

/// Authenticated-ledger DATA describing one previously prepared command.
/// Decoding these bytes cannot reconstruct its original committed read, grant
/// an Actor, mint a new serial, submit a command, or permit physical deletion.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeV6IntentRetirementRecovery {
    format: u8,
    pub(crate) cluster_digest: [u8; 32],
    pub(crate) serial: u64,
    pub(crate) command: NativeV6IntentRetirementCommand,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retained_root_activation:
        Option<crate::v6_retained_roots::NativeV6RetainedRootActivation>,
}

impl std::fmt::Debug for NativeV6IntentRetirementRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeV6IntentRetirementRecovery")
            .field("serial", &self.serial)
            .field("selected_intents", &self.command.intents.len())
            .finish_non_exhaustive()
    }
}

impl NativeV6IntentRetirementRecovery {
    pub(crate) fn prepared(
        cluster_digest: [u8; 32],
        serial: u64,
        command: NativeV6IntentRetirementCommand,
    ) -> Result<Self, RecordRejection> {
        let data = Self {
            format: 1,
            cluster_digest,
            serial,
            command,
            retained_root_activation: None,
        };
        data.validate()?;
        Ok(data)
    }
    pub(crate) fn prepared_root_activation(
        cluster_digest: [u8; 32],
        serial: u64,
        activation: crate::v6_retained_roots::NativeV6RetainedRootActivation,
    ) -> Result<Self, RecordRejection> {
        let command = NativeV6IntentRetirementCommand {
            protocol: RETENTION_PROTOCOL,
            source: activation.source.clone(),
            intents: Vec::new(),
        };
        let data = Self {
            format: 2,
            cluster_digest,
            serial,
            command,
            retained_root_activation: Some(activation),
        };
        data.validate()?;
        Ok(data)
    }
    fn validate(&self) -> Result<(), RecordRejection> {
        if self.cluster_digest == [0; 32] || self.serial == 0 {
            return Err(RecordRejection::Invalid);
        }
        self.command.validate()?;
        match (&self.retained_root_activation, self.format) {
            (None, 1) => Ok(()),
            (Some(activation), 2)
                if self.command.intents.is_empty() && activation.source == self.command.source =>
            {
                activation.validate()
            }
            _ => Err(RecordRejection::Invalid),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, RecordRejection> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| RecordRejection::Invalid)?;
        if bytes.len() > 16 * 1024 {
            return Err(RecordRejection::Invalid);
        }
        Ok(bytes)
    }
    pub fn decode_for_reconciliation(bytes: &[u8]) -> Result<Self, RecordRejection> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(RecordRejection::Invalid);
        }
        let data: Self = serde_json::from_slice(bytes).map_err(|_| RecordRejection::Invalid)?;
        if data.encode()?.as_slice() != bytes {
            return Err(RecordRejection::Invalid);
        }
        Ok(data)
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    pub fn selected_intents(&self) -> usize {
        self.command.intents.len()
    }
    pub fn command_digest(&self) -> Result<[u8; 32], RecordRejection> {
        self.validate()?;
        match &self.retained_root_activation {
            Some(activation) => activation.digest(),
            None => self.command.digest(),
        }
    }
    pub fn activates_retained_roots(&self) -> bool {
        self.retained_root_activation.is_some()
    }
    pub(crate) fn into_record_command(self) -> RecordCommand {
        match self.retained_root_activation {
            Some(activation) => RecordCommand::ActivateNativeV6RetainedRoots { activation },
            None => RecordCommand::RetireNativeV6Intents {
                retirement: self.command,
            },
        }
    }
    pub fn capsule_digest(&self) -> Result<[u8; 32], RecordRejection> {
        use sha2::{Digest, Sha256};
        Ok(Sha256::digest(self.encode()?).into())
    }
}

/// A new observation about current metadata. None of these variants asserts
/// that the historical request returned success or authorizes any new deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeV6IntentRetirementResolution {
    Pending,
    EffectsObserved,
    SupersededByNewRoot,
}

impl crate::StateMachine {
    pub(crate) fn observe_native_v6_intent_retirement(
        &self,
        previous: &NativeV6IntentRetirementRecovery,
    ) -> Result<NativeV6IntentRetirementResolution, RecordRejection> {
        use NativeV6IntentRetirementResolution::{EffectsObserved, Pending, SupersededByNewRoot};
        previous.validate()?;
        self.validate()?;
        let current = NativeV6RetentionSource::from_state(self)?;
        let old = &previous.command.source;
        let enrollment = self
            .v6_enrollment
            .as_ref()
            .ok_or(RecordRejection::MissingDependency)?;
        // Foreign clusters, changed enrollment/epoch, rollback or an unrelated
        // identity are holds. "Different" is not by itself proof of closure.
        if enrollment.command.cluster_digest != previous.cluster_digest
            || current.enrollment_digest != old.enrollment_digest
            || current.epoch != old.epoch
        {
            return Ok(Pending);
        }
        if current == *old {
            if previous.activates_retained_roots() {
                return Ok(
                    if self.v6_retained_root_protocol
                        == Some(crate::v6_retained_roots::RETAINED_ROOT_PROTOCOL)
                    {
                        EffectsObserved
                    } else {
                        Pending
                    },
                );
            }
            let actual = self.native_v6_retained_intents()?;
            if self.v6_retention_protocol == Some(RETENTION_PROTOCOL)
                && previous
                    .command
                    .intents
                    .iter()
                    .all(|selected| !actual.contains_key(&selected.id))
            {
                return Ok(EffectsObserved);
            }
            return Ok(Pending);
        }
        // apply_native_v6_intent_retirement rejects any command whose FULL
        // source tuple is not current. Within the same committed enrollment
        // and epoch, this strictly later native generation and publication
        // cannot become the old tuple again. A still delayed old command is
        // therefore fenced by its actual application predicate. This only
        // closes that old request; a new deletion needs new preparation.
        if current.generation > old.generation
            && current.publication_log.index > old.publication_log.index
            && current.intent_log.index > old.intent_log.index
            && current.publication_log.committed_leader_id().term
                >= old.publication_log.committed_leader_id().term
        {
            return Ok(SupersededByNewRoot);
        }
        Ok(Pending)
    }
}

fn key(id: &[u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    crate::append_hex(&mut text, id);
    text
}

impl crate::StateMachine {
    /// All actual intent objects, with their original applied-log identity.
    /// This is read-only metadata, never external-closure or Actor authority.
    pub(crate) fn native_v6_retained_intents(
        &self,
    ) -> Result<BTreeMap<RecordObjectId, (NativeV6CommitIntent, Log)>, RecordRejection> {
        let mut intents = BTreeMap::new();
        let Some(records) = &self.records_v5 else {
            return if self.v6_intent_log_provenance.is_empty() {
                Ok(intents)
            } else {
                Err(RecordRejection::MissingDependency)
            };
        };
        let mut after = None;
        loop {
            let page = records.inventory(after, 256)?;
            for reference in &page {
                if reference.kind == crate::RecordObjectKind::NativeV6CommitIntent {
                    let object = records
                        .object(reference)?
                        .ok_or(RecordRejection::MissingDependency)?;
                    let intent = NativeV6CommitIntent::decode(object.sealed())?;
                    let origin = self
                        .v6_intent_log_id(&reference.id)
                        .ok_or(RecordRejection::MissingDependency)?;
                    if intents.insert(reference.id, (intent, origin)).is_some() {
                        return Err(RecordRejection::ImmutableConflict);
                    }
                }
            }
            if page.len() < 256 {
                break;
            }
            after = page.last().map(|reference| reference.id);
        }
        if intents.len() != self.v6_intent_log_provenance.len() {
            return Err(RecordRejection::MissingDependency);
        }
        Ok(intents)
    }

    pub(crate) fn native_v6_protected_intent_logs(&self) -> Result<BTreeSet<Log>, RecordRejection> {
        let root = self
            .v6_root
            .as_ref()
            .ok_or(RecordRejection::MissingDependency)?;
        let mut by_log = BTreeMap::new();
        for (_, (intent, origin)) in self.native_v6_retained_intents()? {
            if by_log.insert(origin, intent).is_some() {
                return Err(RecordRejection::ImmutableConflict);
            }
        }
        if by_log.get(&root.command.intent_log) != Some(&root.command.intent) {
            return Err(RecordRejection::MissingDependency);
        }
        let mut logs = BTreeSet::from([root.command.intent_log]);
        let mut keep_pending = |pending: &crate::v6_epoch_restore::NativeV6PendingEpochRestore| {
            let source = &pending.command.source;
            let actual = by_log
                .get(&source.intent_log)
                .ok_or(RecordRejection::MissingDependency)?;
            if actual.proposed_root_digest != source.root_digest
                || actual.proposed_generation != source.generation
                || actual.cluster_digest != source.enrollment.command.cluster_digest
                || actual.epoch != source.enrollment.command.epoch
            {
                return Err(RecordRejection::ImmutableConflict);
            }
            logs.insert(source.intent_log);
            if let Some(target) = &pending.intent {
                if by_log.get(&target.log) != Some(&target.intent) {
                    return Err(RecordRejection::MissingDependency);
                }
                logs.insert(target.log);
            }
            Ok(())
        };
        // Each historical transition owns BOTH its actual source and its
        // staged target. Merely collecting a LogId is insufficient: it must
        // resolve to the unique original intent with the exact epoch/root.
        for step in &root.restore_lineage {
            if step.pending.intent.is_none() {
                return Err(RecordRejection::MissingDependency);
            }
            keep_pending(&step.pending)?;
        }
        if let Some(pending) = &self.v6_pending_epoch_restore {
            keep_pending(pending)?;
        }
        Ok(logs)
    }

    pub(crate) fn prepare_native_v6_intent_retirement(
        &self,
        limit: usize,
    ) -> Result<NativeV6IntentRetirementCommand, RecordRejection> {
        if limit == 0 || limit > MAX_RETIREMENT_INTENTS {
            return Err(RecordRejection::Invalid);
        }
        self.validate()?;
        let source = NativeV6RetentionSource::from_state(self)?;
        let protected = self.native_v6_protected_intent_logs()?;
        let intents = self
            .native_v6_retained_intents()?
            .into_iter()
            .filter(|(_, (intent, origin))| {
                // Native generation increases across ordinary writes AND
                // epoch restore. A candidate at an already reached generation
                // can no longer pass root CAS. Future or still-publishable
                // intents remain untouched, including speculative candidates.
                intent.proposed_generation <= source.generation && !protected.contains(origin)
            })
            .take(limit)
            .map(|(id, (_, original_log))| NativeV6RetiredIntent { id, original_log })
            .collect();
        let command = NativeV6IntentRetirementCommand {
            protocol: RETENTION_PROTOCOL,
            source,
            intents,
        };
        command.validate()?;
        Ok(command)
    }

    pub(crate) fn apply_native_v6_intent_retirement(
        &mut self,
        command: &NativeV6IntentRetirementCommand,
    ) -> Result<(), RecordRejection> {
        command.validate()?;
        self.validate()?;
        if command.source != NativeV6RetentionSource::from_state(self)? {
            return Err(RecordRejection::StaleRoot);
        }
        let applied = self.last_applied_log.ok_or(RecordRejection::Invalid)?;
        if applied.index <= command.source.publication_log.index {
            return Err(RecordRejection::Invalid);
        }
        let protected = self.native_v6_protected_intent_logs()?;
        let objects = self.native_v6_retained_intents()?;
        for selected in &command.intents {
            let (intent, origin) = objects
                .get(&selected.id)
                .ok_or(RecordRejection::MissingDependency)?;
            if *origin != selected.original_log
                || origin.index >= applied.index
                || protected.contains(origin)
                || intent.proposed_generation > command.source.generation
            {
                return Err(RecordRejection::ReferencedByStaged);
            }
        }
        // Validate a complete candidate before touching live state. The
        // original V5 prune enforces reachability and remaining child refs;
        // only this typed native command may remove native provenance.
        let mut candidate = self.clone();
        if !command.intents.is_empty() {
            let digest = candidate
                .records_v5
                .as_ref()
                .and_then(crate::records::RecordState::published_digest)
                .ok_or(RecordRejection::MissingDependency)?;
            let legacy_bytes = candidate.legacy_size()?;
            candidate
                .records_v5
                .as_mut()
                .ok_or(RecordRejection::MissingDependency)?
                .apply(
                    &RecordCommand::Prune {
                        expected_root: digest,
                        ids: command.intents.iter().map(|entry| entry.id).collect(),
                    },
                    RecordRootBase::RecordsV5(digest),
                    legacy_bytes,
                )?;
            for selected in &command.intents {
                if candidate
                    .v6_intent_log_provenance
                    .remove(&key(&selected.id))
                    != Some(selected.original_log)
                {
                    return Err(RecordRejection::MissingDependency);
                }
            }
        }
        candidate.v6_retention_protocol = Some(RETENTION_PROTOCOL);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// After the retirement format is committed, an old removed intent must
    /// never obtain new provenance by replaying Stage at a later log slot.
    /// Existing exact objects retain their FIRST log identity as before.
    pub(crate) fn validate_native_v6_retention_stage(
        &self,
        intent: &NativeV6CommitIntent,
    ) -> Result<(), RecordRejection> {
        if self.v6_retention_protocol.is_none() {
            return Ok(());
        }
        if self.v6_retention_protocol != Some(RETENTION_PROTOCOL) {
            return Err(RecordRejection::Invalid);
        }
        let object = SealedRecordObject::new_native_v6_commit_intent(*intent)
            .map_err(|_| RecordRejection::Invalid)?;
        if self.v6_intent_log_id(&object.reference().id).is_some() {
            return Ok(());
        }
        let root = self
            .v6_root
            .as_ref()
            .ok_or(RecordRejection::MissingDependency)?;
        let enrollment = self
            .v6_enrollment
            .as_ref()
            .ok_or(RecordRejection::MissingDependency)?;
        if intent.epoch != enrollment.command.epoch {
            return self
                .v6_pending_epoch_restore
                .as_ref()
                .ok_or(RecordRejection::StaleRoot)?
                .command
                .matches_intent(intent);
        }
        if intent.cluster_digest != enrollment.command.cluster_digest
            || intent.prior_root_digest != root.command.intent.proposed_root_digest
            || intent.prior_generation != root.command.intent.proposed_generation
            || intent.expected_previous_commit_index != root.publication_log.index
        {
            return Err(RecordRejection::StaleRoot);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "v6_retention_tests.rs"]
mod tests;
