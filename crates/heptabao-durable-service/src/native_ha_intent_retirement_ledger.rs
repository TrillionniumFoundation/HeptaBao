//! Durable Pending before one externally owned Raft metadata submission.
//! Cold reconciliation observes the exact old capsule under new read custody;
//! it never reconstructs or submits that old command and never grants deletion.
use super::*;
use std::collections::BTreeSet;

#[path = "native_ha_intent_retirement_execute.rs"]
mod execute;

#[cfg(all(test, unix))]
#[path = "native_ha_intent_retirement_tests.rs"]
mod tests;

pub const NATIVE_HA_INTENT_RETIREMENT_RESOURCE: &str = "state-native-v6/ha-intent-retirement";
const MAGIC: &[u8; 16] = b"HBHAINTENTGC0001";
const MAX_CAPSULE: usize = 16 * 1024;
const MAX_RECORD: usize = MAX_CAPSULE + 256;
const REQUIRED: [&str; 4] = [
    "state",
    "state-native-v6/active-publication-cursor",
    "state-native-v6/active-source-root",
    "state-native-v6/ha-publication-cursor",
];

pub struct NativeHaIntentSelection {
    pub capsule: Secret,
    pub serial: u64,
    pub command_sha256: [u8; 32],
    pub selected_intents: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHaIntentCommit {
    pub leader_id: u64,
    pub log_index: u64,
    pub command_sha256: [u8; 32],
}

/// Trusted in-process integration, never a caller-supplied HTTP capability.
/// submit consumes the original affine prepared Raft command once. Its gate
/// must verify the exact known Pending before invoking the one network effect.
pub trait NativeHaIntentOwner: Sized {
    type Completed: NativeHaIntentCompletedOwner;
    fn selection(&self) -> Result<NativeHaIntentSelection, ServiceError>;
    fn verify(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError>;
    fn submit(
        self,
        known_pending: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<Self::Completed, ServiceError>;
}
pub trait NativeHaIntentCompletedOwner {
    fn committed(&self) -> NativeHaIntentCommit;
    fn verify_completed(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHaIntentResolution {
    Pending,
    EffectsObserved,
    SupersededByNewRoot,
}
/// A fresh opaque Raft read owner, never the old serial's submission owner.
pub trait NativeHaIntentReconciliationOwner {
    fn capsule_sha256(&self) -> [u8; 32];
    fn resolution(&self) -> NativeHaIntentResolution;
    fn verify_observation(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError>;
}

pub struct NativeHaIntentRetirementRequest<O: NativeHaIntentOwner> {
    pub session: ImmutableSourceSession,
    pub principal: String,
    pub operation_id: String,
    pub authorization_digest: [u8; 32],
    pub conditions: Vec<PublicationCondition>,
    pub owner: O,
}
pub struct NativeHaIntentReconciliationRequest<O: NativeHaIntentReconciliationOwner> {
    pub session: ImmutableSourceSession,
    pub principal: String,
    pub operation_id: String,
    pub authorization_digest: [u8; 32],
    pub conditions: Vec<PublicationCondition>,
    pub expected_pending_sha256: [u8; 32],
    pub observer: O,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHaIntentRetirementOutcome {
    pub generation: u64,
    pub committed: NativeHaIntentCommit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHaIntentReconciliationOutcome {
    pub generation: u64,
    pub resolution: NativeHaIntentResolution,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Pending,
    Completed,
    Observed,
    Superseded,
}
impl Phase {
    fn byte(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Completed => 1,
            Self::Observed => 2,
            Self::Superseded => 3,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "original-completed",
            Self::Observed => "reconciled-effects-observed",
            Self::Superseded => "reconciled-source-superseded",
        }
    }
}
struct Record {
    phase: Phase,
    source_generation: u64,
    pending_generation: u64,
    epoch: u64,
    serial: u64,
    selected_intents: usize,
    command_sha256: [u8; 32],
    leader_id: u64,
    log_index: u64,
    capsule: Secret,
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
impl Record {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.source_generation == 0
            || self.source_generation.checked_add(1) != Some(self.pending_generation)
            || self.serial == 0
            || self.selected_intents > 32
            || self.command_sha256 == [0; 32]
            || self.capsule.expose().is_empty()
            || self.capsule.expose().len() > MAX_CAPSULE
            || (self.phase == Phase::Completed
                && (self.leader_id == 0 || self.log_index < self.serial))
            || (self.phase != Phase::Completed && (self.leader_id != 0 || self.log_index != 0))
        {
            return Err(ServiceError::CorruptState);
        }
        Ok(())
    }
    fn encode_as(
        &self,
        phase: Phase,
        leader_id: u64,
        log_index: u64,
    ) -> Result<Secret, ServiceError> {
        let mut bytes = Vec::with_capacity(128 + self.capsule.expose().len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(phase.byte());
        for value in [
            self.source_generation,
            self.pending_generation,
            self.epoch,
            self.serial,
        ] {
            write_u64(&mut bytes, value);
        }
        write_u32(&mut bytes, self.selected_intents as u32);
        bytes.extend_from_slice(&self.command_sha256);
        write_u64(&mut bytes, leader_id);
        write_u64(&mut bytes, log_index);
        write_u32(&mut bytes, self.capsule.expose().len() as u32);
        bytes.extend_from_slice(self.capsule.expose());
        if bytes.len() > MAX_RECORD {
            return Err(ServiceError::CorruptState);
        }
        Secret::new(bytes)
    }
    fn encode(&self) -> Result<Secret, ServiceError> {
        self.validate()?;
        self.encode_as(self.phase, self.leader_id, self.log_index)
    }
    fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        if bytes.len() > MAX_RECORD {
            return Err(ServiceError::CorruptState);
        }
        let mut input = Cursor::new(bytes);
        if input.read_exact(MAGIC.len())? != MAGIC {
            return Err(ServiceError::CorruptState);
        }
        let phase = match input.read_u8()? {
            0 => Phase::Pending,
            1 => Phase::Completed,
            2 => Phase::Observed,
            3 => Phase::Superseded,
            _ => return Err(ServiceError::CorruptState),
        };
        let source_generation = input.read_u64()?;
        let pending_generation = input.read_u64()?;
        let epoch = input.read_u64()?;
        let serial = input.read_u64()?;
        let selected_intents = input.read_u32()? as usize;
        let command_sha256 = input
            .read_exact(32)?
            .try_into()
            .map_err(|_| ServiceError::CorruptState)?;
        let leader_id = input.read_u64()?;
        let log_index = input.read_u64()?;
        let length = input.read_u32()? as usize;
        if length > MAX_CAPSULE {
            return Err(ServiceError::CorruptState);
        }
        let capsule = Secret::new(input.read_exact(length)?.to_vec())?;
        input.finish()?;
        let value = Self {
            phase,
            source_generation,
            pending_generation,
            epoch,
            serial,
            selected_intents,
            command_sha256,
            leader_id,
            log_index,
            capsule,
        };
        value.validate()?;
        if value.encode()?.expose() != bytes {
            return Err(ServiceError::CorruptState);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHaIntentRetirementStatus {
    pub phase: &'static str,
    pub pending: bool,
    pub record_sha256: [u8; 32],
    pub original_pending_sha256: [u8; 32],
    pub capsule_sha256: [u8; 32],
    pub serial: u64,
    pub selected_intents: usize,
    pub pending_generation: u64,
    pub replay_epoch: u64,
    pub historical_request_outcome_reclassified: bool,
}

fn copy_conditions(conditions: &[PublicationCondition]) -> Vec<PublicationCondition> {
    conditions
        .iter()
        .map(|condition| PublicationCondition {
            resource: condition.resource.clone(),
            expected: condition.expected.clone(),
        })
        .collect()
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    fn ha_intent_record(&self) -> Result<Option<(Secret, Record)>, ServiceError> {
        self.get("system", NATIVE_HA_INTENT_RETIREMENT_RESOURCE)?
            .map(|bytes| {
                let record = Record::decode(bytes.expose())?;
                Ok((bytes, record))
            })
            .transpose()
    }
    pub fn native_ha_intent_retirement_status(
        &mut self,
    ) -> Result<Option<NativeHaIntentRetirementStatus>, ServiceError> {
        self.verify_live_ownership()?;
        self.ha_intent_record()?
            .map(|(bytes, record)| {
                if record.pending_generation > self.generation() {
                    return Err(ServiceError::CorruptState);
                }
                Ok(NativeHaIntentRetirementStatus {
                    phase: record.phase.name(),
                    pending: record.phase == Phase::Pending,
                    record_sha256: digest(bytes.expose()),
                    original_pending_sha256: digest(
                        record.encode_as(Phase::Pending, 0, 0)?.expose(),
                    ),
                    capsule_sha256: digest(record.capsule.expose()),
                    serial: record.serial,
                    selected_intents: record.selected_intents,
                    pending_generation: record.pending_generation,
                    replay_epoch: record.epoch,
                    historical_request_outcome_reclassified: false,
                })
            })
            .transpose()
    }
    pub fn native_ha_pending_intent_retirement(
        &mut self,
        expected: [u8; 32],
    ) -> Result<Secret, ServiceError> {
        self.verify_live_ownership()?;
        let (bytes, record) = self
            .ha_intent_record()?
            .ok_or(ServiceError::PublicationConditionConflict)?;
        if record.phase != Phase::Pending
            || digest(bytes.expose()) != expected
            || record.epoch != self.replay_epoch
            || record.pending_generation > self.generation()
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        Ok(record.capsule)
    }
    pub(crate) fn ensure_no_pending_ha_intent_retirement(&self) -> Result<(), ServiceError> {
        if self
            .ha_intent_record()?
            .is_some_and(|(_, record)| record.phase == Phase::Pending)
        {
            return Err(ServiceError::RecoveryRequired);
        }
        Ok(())
    }
    pub(crate) fn ensure_ha_intent_retirement_restore_complete(
        prepared: &PreparedRestore,
    ) -> Result<(), ServiceError> {
        if let Some(bytes) = prepared.get("system", NATIVE_HA_INTENT_RETIREMENT_RESOURCE)?
            && Record::decode(bytes)?.phase == Phase::Pending
        {
            return Err(ServiceError::RecoveryRequired);
        }
        Ok(())
    }
    pub(crate) fn ensure_ha_intent_retirement_snapshot_complete(
        snapshot: &Snapshot,
    ) -> Result<(), ServiceError> {
        if let Some(bytes) = snapshot.entries.get(&(
            "system".to_owned(),
            NATIVE_HA_INTENT_RETIREMENT_RESOURCE.to_owned(),
        )) && Record::decode(bytes.expose())?.phase == Phase::Pending
        {
            return Err(ServiceError::RecoveryRequired);
        }
        Ok(())
    }
    fn ha_intent_check_conditions(
        &self,
        conditions: &[PublicationCondition],
    ) -> Result<(), ServiceError> {
        for condition in conditions {
            if self
                .get("system", &condition.resource)?
                .as_ref()
                .map(Secret::expose)
                != condition.expected.as_ref().map(Secret::expose)
            {
                return Err(ServiceError::PublicationConditionConflict);
            }
        }
        Ok(())
    }
    fn ha_intent_admit(
        &mut self,
        session: &ImmutableSourceSession,
        principal: &str,
        operation: &str,
        authorization_digest: [u8; 32],
        conditions: &[PublicationCondition],
    ) -> Result<(), ServiceError> {
        self.check_immutable_source_session(session)?;
        validate_identifier(principal)?;
        validate_identifier(operation)?;
        if session.namespace != "system"
            || session.resource != "state"
            || authorization_digest == [0; 32]
            || conditions.len() < REQUIRED.len()
            || conditions.len() > 8
        {
            return Err(ServiceError::InvalidResource);
        }
        let mut names = BTreeSet::new();
        for condition in conditions {
            validate_resource(&condition.resource)?;
            if condition.resource == NATIVE_HA_INTENT_RETIREMENT_RESOURCE
                || !names.insert(condition.resource.as_str())
            {
                return Err(ServiceError::InvalidResource);
            }
        }
        for resource in REQUIRED {
            if !conditions
                .iter()
                .any(|condition| condition.resource == resource && condition.expected.is_some())
            {
                return Err(ServiceError::InvalidResource);
            }
        }
        if conditions
            .iter()
            .find(|condition| condition.resource == "state")
            .and_then(|condition| condition.expected.as_ref())
            .map(Secret::expose)
            != Some(session.root.expose())
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        self.ensure_no_pending_immutable_retirement()?;
        self.ensure_no_pending_ha_shared_retirement()?;
        self.ha_intent_check_conditions(conditions)
    }
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    fn reserve_ha_intent_pair(
        &self,
        principal: &str,
        begin_id: &str,
        done_id: &str,
        authorization_digest: [u8; 32],
        pending: &Secret,
    ) -> Result<(), ServiceError> {
        if self
            .ledger
            .len()
            .checked_add(2)
            .is_none_or(|count| count > self.max_retained_requests)
        {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        if self
            .journal_sequence
            .checked_add(6)
            .is_none_or(|count| count > MAX_RECORDS as u64)
        {
            return Err(ServiceError::JournalCapacityExhausted);
        }
        let mut journal = self.journal_bytes;
        let mut ledger = self.ledger_plaintext_bytes;
        let mut previous_snapshot = None;
        let mut previous_marker = None;
        for (index, id) in [begin_id, done_id].into_iter().enumerate() {
            let generation = self
                .generation()
                .checked_add(index as u64 + 1)
                .ok_or(ServiceError::GenerationOverflow)?;
            let sequence = self
                .journal_sequence
                .checked_add(index as u64 * 3 + 1)
                .ok_or(ServiceError::GenerationOverflow)?;
            let key = RequestKey {
                principal: principal.into(),
                namespace: "system".into(),
                request_id: scope_request_id(self.replay_epoch, id)?,
            };
            if self.ledger.contains_key(&key) {
                return Err(ServiceError::RequestBindingConflict);
            }
            let marker = CommitMarker {
                key,
                binding_digest: authorization_digest,
                recovery_reference: recovery_reference(&authorization_digest, generation, sequence),
                generation,
            };
            let marker_bytes = encoded_marker_len(&marker)?;
            ledger = ledger
                .checked_add(marker_bytes)
                .ok_or(ServiceError::RequestCapacityExhausted)?;
            // Only phase/fixed-width Raft receipt fields change on completion. The
            // exact capsule and all variable-length bytes remain identical.
            let mutations = vec![JournalMutation {
                resource: NATIVE_HA_INTENT_RETIREMENT_RESOURCE.into(),
                value: Some(pending.clone()),
            }];
            let snapshot = if index == 0 {
                candidate_snapshot_plaintext_len(
                    &self.snapshot,
                    self.snapshot_plaintext_bytes,
                    &marker,
                    &mutations,
                )?
            } else {
                previous_snapshot
                    .and_then(|n: usize| n.checked_sub(previous_marker?))
                    .and_then(|n| n.checked_add(marker_bytes))
                    .ok_or(ServiceError::RequestCapacityExhausted)?
            };
            if snapshot_frame_len_bound(&self.barrier, snapshot).is_none_or(|n| n > MAX_FILE_BYTES)
                || self
                    .barrier
                    .sealed_len_bound(ledger)
                    .and_then(|n| n.checked_add(48))
                    .is_none_or(|n| n > MAX_FILE_BYTES)
            {
                return Err(ServiceError::RequestCapacityExhausted);
            }
            previous_snapshot = Some(snapshot);
            previous_marker = Some(marker_bytes);
            for event in [
                JournalEvent::Intent(marker.clone()),
                JournalEvent::Apply {
                    marker: marker.clone(),
                    mutations,
                },
                JournalEvent::Commit(marker),
            ] {
                let bytes = encode_journal_event(&event)?;
                let bound = self
                    .barrier
                    .sealed_len_bound(bytes.len())
                    .and_then(|n| n.checked_add(48))
                    .filter(|n| *n <= MAX_FILE_BYTES)
                    .ok_or(ServiceError::RequestCapacityExhausted)?;
                journal = journal
                    .checked_add(bound)
                    .ok_or(ServiceError::JournalCapacityExhausted)?;
                if journal > self.journal_limit {
                    return Err(ServiceError::JournalCapacityExhausted);
                }
            }
        }
        Ok(())
    }
}
