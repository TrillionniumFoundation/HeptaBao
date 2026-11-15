//! A local barrier-authenticated journal around one externally owned physical
//! shared-replica retirement. The physical owner must separately retain the
//! complete actual Raft catalog, shared-operation quiescence, exact FDs and
//! original Actor/deadline. This ledger never supplies those permissions.
use super::*;
use std::collections::BTreeSet;

pub const NATIVE_HA_SHARED_RETIREMENT_RESOURCE: &str = "state-native-v6/ha-shared-retirement";
const MAGIC: &[u8; 16] = b"HBHAGCLEDGER0001";
const MAX_CAPSULE: usize = 64 * 1024;
const MAX_RECORD: usize = MAX_CAPSULE + 512;
const MAX_SELECTED: usize = 32;
const REQUIRED: [&str; 4] = [
    "state",
    "state-native-v6/active-publication-cursor",
    "state-native-v6/active-source-root",
    "state-native-v6/ha-publication-cursor",
];

/// Data returned by the caller's non-serializable actual physical owner. The
/// exact capsule is authenticated by this service's existing barrier/journal.
pub struct NativeHaSharedSelection {
    pub capsule: Secret,
    pub selected_files: usize,
    pub predecessor_selection_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeHaSharedPhysicalOutcome {
    pub removed_blobs: u64,
    pub removed_manifests: u64,
    pub removed_temporary_files: u64,
    pub removed_ciphertext_bytes: u64,
    pub removed_other_bytes: u64,
    pub confirmed_absent_files: u64,
    pub currently_retained_files: u64,
}
impl NativeHaSharedPhysicalOutcome {
    fn columns(self) -> [u64; 7] {
        [
            self.removed_blobs,
            self.removed_manifests,
            self.removed_temporary_files,
            self.removed_ciphertext_bytes,
            self.removed_other_bytes,
            self.confirmed_absent_files,
            self.currently_retained_files,
        ]
    }
    fn from_columns(columns: [u64; 7]) -> Self {
        Self {
            removed_blobs: columns[0],
            removed_manifests: columns[1],
            removed_temporary_files: columns[2],
            removed_ciphertext_bytes: columns[3],
            removed_other_bytes: columns[4],
            confirmed_absent_files: columns[5],
            currently_retained_files: columns[6],
        }
    }
    fn validate(self, selected: usize, reconciliation: bool) -> Result<(), ServiceError> {
        let count = self
            .removed_blobs
            .checked_add(self.removed_manifests)
            .and_then(|n| n.checked_add(self.removed_temporary_files))
            .and_then(|n| n.checked_add(self.confirmed_absent_files))
            .and_then(|n| n.checked_add(self.currently_retained_files));
        if count != Some(selected as u64)
            || self.removed_ciphertext_bytes > MAX_SELECTED as u64 * 256 * 1024
            || self.removed_other_bytes > MAX_SELECTED as u64 * (16 + 131_072 * 40)
            || (!reconciliation
                && (self.confirmed_absent_files != 0 || self.currently_retained_files != 0))
        {
            return Err(ServiceError::CorruptState);
        }
        Ok(())
    }
}

/// Trusted in-process integration, implemented by the Service wrapper around
/// the affine shared-store plan. It is NOT a public HTTP authority or a way
/// to reconstruct a plan from a capsule. Both methods keep original owners;
/// retire consumes them exactly once and must call the gate at every I/O.
pub trait NativeHaSharedPhysicalOwner: Sized {
    type Completed: NativeHaSharedCompletedOwner;
    fn selection(&self) -> Result<NativeHaSharedSelection, ServiceError>;
    fn verify(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError>;
    fn retire(
        self,
        verify_known_pending: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<Self::Completed, ServiceError>;
}
pub trait NativeHaSharedCompletedOwner {
    fn outcome(&self) -> NativeHaSharedPhysicalOutcome;
    fn verify_completed(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError>;
}

pub struct NativeHaSharedRetirementRequest<O: NativeHaSharedPhysicalOwner> {
    pub session: ImmutableSourceSession,
    pub principal: String,
    pub operation_id: String,
    pub authorization_digest: [u8; 32],
    pub conditions: Vec<PublicationCondition>,
    pub expected_pending_sha256: Option<[u8; 32]>,
    pub physical: O,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHaSharedRetirementOutcome {
    pub generation: u64,
    pub physical: NativeHaSharedPhysicalOutcome,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Pending,
    Completed,
    ReconciliationPending,
    ReconciliationCompleted,
}
impl Phase {
    fn byte(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Completed => 1,
            Self::ReconciliationPending => 2,
            Self::ReconciliationCompleted => 3,
        }
    }
    fn pending(self) -> bool {
        matches!(self, Self::Pending | Self::ReconciliationPending)
    }
    fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "original-completed",
            Self::ReconciliationPending => "reconciliation-pending",
            Self::ReconciliationCompleted => "reconciliation-completed",
        }
    }
}
struct Record {
    phase: Phase,
    source_generation: u64,
    pending_generation: u64,
    replay_epoch: u64,
    attempt: u64,
    predecessor_record_sha256: [u8; 32],
    original_pending_sha256: [u8; 32],
    selected_files: usize,
    capsule: Secret,
    physical: NativeHaSharedPhysicalOutcome,
}
fn raw_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
impl Record {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.source_generation == 0
            || self.source_generation.checked_add(1) != Some(self.pending_generation)
            || self.selected_files == 0
            || self.selected_files > MAX_SELECTED
            || self.capsule.expose().len() > MAX_CAPSULE
            || (self.attempt == 0) != matches!(self.phase, Phase::Pending | Phase::Completed)
            || (self.attempt == 0) != (self.original_pending_sha256 == [0; 32])
            || (self.attempt > 0 && self.predecessor_record_sha256 == [0; 32])
        {
            return Err(ServiceError::CorruptState);
        }
        if self.phase.pending() {
            if self.physical != NativeHaSharedPhysicalOutcome::default() {
                return Err(ServiceError::CorruptState);
            }
        } else {
            self.physical
                .validate(self.selected_files, self.attempt > 0)?;
        }
        Ok(())
    }
    fn encode_with(
        &self,
        phase: Phase,
        physical: NativeHaSharedPhysicalOutcome,
    ) -> Result<Secret, ServiceError> {
        let mut bytes = Vec::with_capacity(self.capsule.expose().len() + 192);
        bytes.extend_from_slice(MAGIC);
        bytes.push(phase.byte());
        for value in [
            self.source_generation,
            self.pending_generation,
            self.replay_epoch,
            self.attempt,
        ] {
            write_u64(&mut bytes, value);
        }
        bytes.extend_from_slice(&self.predecessor_record_sha256);
        bytes.extend_from_slice(&self.original_pending_sha256);
        write_u32(&mut bytes, self.selected_files as u32);
        for value in physical.columns() {
            write_u64(&mut bytes, value);
        }
        write_u32(&mut bytes, self.capsule.expose().len() as u32);
        bytes.extend_from_slice(self.capsule.expose());
        if bytes.len() > MAX_RECORD {
            return Err(ServiceError::CorruptState);
        }
        Secret::new(bytes)
    }
    fn encode(&self) -> Result<Secret, ServiceError> {
        self.validate()?;
        self.encode_with(self.phase, self.physical)
    }
    fn original_pending_digest(&self) -> Result<[u8; 32], ServiceError> {
        if self.attempt > 0 {
            return Ok(self.original_pending_sha256);
        }
        Ok(raw_digest(
            self.encode_with(Phase::Pending, NativeHaSharedPhysicalOutcome::default())?
                .expose(),
        ))
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
            2 => Phase::ReconciliationPending,
            3 => Phase::ReconciliationCompleted,
            _ => return Err(ServiceError::CorruptState),
        };
        let source_generation = input.read_u64()?;
        let pending_generation = input.read_u64()?;
        let replay_epoch = input.read_u64()?;
        let attempt = input.read_u64()?;
        let predecessor_record_sha256 = input.read_array_32()?;
        let original_pending_sha256 = input.read_array_32()?;
        let selected_files = input.read_u32()? as usize;
        let mut columns = [0; 7];
        for value in &mut columns {
            *value = input.read_u64()?;
        }
        let length = input.read_u32()? as usize;
        if length == 0 || length > MAX_CAPSULE {
            return Err(ServiceError::CorruptState);
        }
        let capsule = Secret::new(input.read_exact(length)?.to_vec())?;
        input.finish()?;
        let result = Self {
            phase,
            source_generation,
            pending_generation,
            replay_epoch,
            attempt,
            predecessor_record_sha256,
            original_pending_sha256,
            selected_files,
            capsule,
            physical: NativeHaSharedPhysicalOutcome::from_columns(columns),
        };
        if result.encode()?.expose() != bytes {
            return Err(ServiceError::CorruptState);
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHaSharedRetirementStatus {
    pub phase: &'static str,
    pub pending: bool,
    pub record_sha256: [u8; 32],
    pub original_pending_sha256: [u8; 32],
    pub selected_files: usize,
    pub pending_generation: u64,
    pub replay_epoch: u64,
    pub reconciliation_attempt: u64,
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
    fn ha_shared_record(&self) -> Result<Option<(Secret, Record)>, ServiceError> {
        self.get("system", NATIVE_HA_SHARED_RETIREMENT_RESOURCE)?
            .map(|bytes| {
                let record = Record::decode(bytes.expose())?;
                Ok((bytes, record))
            })
            .transpose()
    }

    pub fn native_ha_shared_retirement_status(
        &mut self,
    ) -> Result<Option<NativeHaSharedRetirementStatus>, ServiceError> {
        self.verify_live_ownership()?;
        self.ha_shared_record()?
            .map(|(bytes, record)| {
                if record.pending_generation > self.generation() {
                    return Err(ServiceError::CorruptState);
                }
                Ok(NativeHaSharedRetirementStatus {
                    phase: record.phase.name(),
                    pending: record.phase.pending(),
                    record_sha256: raw_digest(bytes.expose()),
                    original_pending_sha256: record.original_pending_digest()?,
                    selected_files: record.selected_files,
                    pending_generation: record.pending_generation,
                    replay_epoch: record.replay_epoch,
                    reconciliation_attempt: record.attempt,
                    historical_request_outcome_reclassified: false,
                })
            })
            .transpose()
    }

    /// Authenticated DATA for one explicit fresh reconciliation only. A caller
    /// must match the exact status digest before receiving the old capsule.
    /// No old physical owner, descriptor or source permission is reconstituted.
    pub fn native_ha_shared_pending_selection(
        &mut self,
        expected: [u8; 32],
    ) -> Result<Secret, ServiceError> {
        self.verify_live_ownership()?;
        let (bytes, record) = self
            .ha_shared_record()?
            .ok_or(ServiceError::PublicationConditionConflict)?;
        if !record.phase.pending()
            || raw_digest(bytes.expose()) != expected
            || record.pending_generation > self.generation()
            || record.replay_epoch != self.replay_epoch
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        Ok(record.capsule)
    }

    pub(crate) fn ensure_no_pending_ha_shared_retirement(&self) -> Result<(), ServiceError> {
        if self
            .ha_shared_record()?
            .is_some_and(|(_, record)| record.phase.pending())
        {
            return Err(ServiceError::RecoveryRequired);
        }
        Ok(())
    }

    pub(crate) fn ensure_ha_shared_retirement_restore_complete(
        prepared: &PreparedRestore,
    ) -> Result<(), ServiceError> {
        if let Some(bytes) = prepared.get("system", NATIVE_HA_SHARED_RETIREMENT_RESOURCE)?
            && Record::decode(bytes)?.phase.pending()
        {
            return Err(ServiceError::RecoveryRequired);
        }
        Ok(())
    }

    fn ha_shared_check_conditions(
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

    /// Reserve both request identities, six exact-size journal frames, both
    /// ledger markers and two snapshot bounds before the first pending Apply.
    /// No implicit checkpoint/compaction/epoch rotation or deadline renewal.
    fn reserve_ha_shared_pair(
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
            // Only phase/fixed-width effect counts change on completion. The
            // exact capsule and all variable-length bytes remain identical.
            let mutations = vec![JournalMutation {
                resource: NATIVE_HA_SHARED_RETIREMENT_RESOURCE.into(),
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

    /// Execute ONE newly authorized physical owner between two known local
    /// authenticated metadata commits. An old pending record always rejects
    /// ordinary retirement; explicit fresh reconciliation additionally binds
    /// its exact digest and the old selection digest in the NEW capsule.
    pub fn retire_native_ha_shared<O: NativeHaSharedPhysicalOwner>(
        &mut self,
        request: NativeHaSharedRetirementRequest<O>,
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<NativeHaSharedRetirementOutcome, ServiceError> {
        before()?;
        self.check_immutable_source_session(&request.session)?;
        if request.session.namespace != "system"
            || request.session.resource != "state"
            || request.conditions.len() < REQUIRED.len()
            || request.conditions.len() > 8
            || request.authorization_digest == [0; 32]
        {
            return Err(ServiceError::InvalidResource);
        }
        validate_identifier(&request.principal)?;
        validate_identifier(&request.operation_id)?;
        let begin_id = format!("{}-retire", request.operation_id);
        let done_id = format!("{}-complete", request.operation_id);
        validate_identifier(&begin_id)?;
        validate_identifier(&done_id)?;
        let mut names = BTreeSet::new();
        for condition in &request.conditions {
            validate_resource(&condition.resource)?;
            if condition.resource == NATIVE_HA_SHARED_RETIREMENT_RESOURCE
                || !names.insert(condition.resource.as_str())
            {
                return Err(ServiceError::InvalidResource);
            }
        }
        for resource in REQUIRED {
            if !request
                .conditions
                .iter()
                .any(|condition| condition.resource == resource && condition.expected.is_some())
            {
                return Err(ServiceError::InvalidResource);
            }
        }
        if request
            .conditions
            .iter()
            .find(|condition| condition.resource == "state")
            .and_then(|condition| condition.expected.as_ref())
            .map(Secret::expose)
            != Some(request.session.root.expose())
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        self.ha_shared_check_conditions(&request.conditions)?;
        self.ensure_no_pending_immutable_retirement()?;
        self.ensure_no_pending_ha_intent_retirement()?;
        let generation = self.generation();
        let epoch = self.replay_epoch;
        let selected = request.physical.selection()?;
        if selected.capsule.expose().len() > MAX_CAPSULE || selected.selected_files > MAX_SELECTED {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let previous = self.ha_shared_record()?;
        let (attempt, original_pending_sha256) = match request.expected_pending_sha256 {
            None => {
                if selected.predecessor_selection_sha256.is_some()
                    || previous
                        .as_ref()
                        .is_some_and(|(_, record)| record.phase.pending())
                {
                    return Err(ServiceError::PublicationConditionConflict);
                }
                (0, [0; 32])
            }
            Some(expected) => {
                let (bytes, record) = previous
                    .as_ref()
                    .ok_or(ServiceError::PublicationConditionConflict)?;
                if !record.phase.pending()
                    || raw_digest(bytes.expose()) != expected
                    || record.replay_epoch != epoch
                    || record.pending_generation > generation
                    || selected.selected_files != record.selected_files
                    || selected.predecessor_selection_sha256
                        != Some(raw_digest(record.capsule.expose()))
                {
                    return Err(ServiceError::PublicationConditionConflict);
                }
                (
                    record
                        .attempt
                        .checked_add(1)
                        .ok_or(ServiceError::GenerationOverflow)?,
                    record.original_pending_digest()?,
                )
            }
        };
        request.physical.verify(before)?;
        self.check_immutable_source_session(&request.session)?;
        // A prepared restore or unrelated actual source session must remain
        // visible. Consume only THIS session before testing the real owner.
        drop(request.session);
        Arc::get_mut(&mut self.restore_instance)
            .ok_or(ServiceError::PublicationConditionConflict)?;
        before()?;
        self.verify_live_ownership()?;
        if selected.selected_files == 0 {
            if attempt != 0 {
                return Err(ServiceError::CorruptState);
            }
            request.physical.verify(before)?;
            return Ok(NativeHaSharedRetirementOutcome {
                generation,
                physical: NativeHaSharedPhysicalOutcome::default(),
            });
        }
        let mut record = Record {
            phase: if attempt == 0 {
                Phase::Pending
            } else {
                Phase::ReconciliationPending
            },
            source_generation: generation,
            pending_generation: generation
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?,
            replay_epoch: epoch,
            attempt,
            predecessor_record_sha256: previous
                .as_ref()
                .map_or([0; 32], |(bytes, _)| raw_digest(bytes.expose())),
            original_pending_sha256,
            selected_files: selected.selected_files,
            capsule: selected.capsule,
            physical: NativeHaSharedPhysicalOutcome::default(),
        };
        let pending = record.encode()?;
        self.reserve_ha_shared_pair(
            &request.principal,
            &begin_id,
            &done_id,
            request.authorization_digest,
            &pending,
        )?;
        request.physical.verify(before)?;
        let stable = request.physical.selection()?;
        if stable.capsule.expose() != record.capsule.expose()
            || stable.selected_files != record.selected_files
            || stable.predecessor_selection_sha256 != selected.predecessor_selection_sha256
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        self.ha_shared_check_conditions(&request.conditions)?;
        if self.generation() != generation || self.replay_epoch != epoch {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let mut conditions = copy_conditions(&request.conditions);
        conditions.push(PublicationCondition {
            resource: NATIVE_HA_SHARED_RETIREMENT_RESOURCE.into(),
            expected: previous.map(|(bytes, _)| bytes),
        });
        before()?;
        let begin = self.apply_batch_conditionally_with_io_gate(
            BatchPublication {
                replay_epoch: epoch,
                principal: request.principal.clone(),
                namespace: "system".into(),
                request_id: begin_id,
                authorization_digest: request.authorization_digest,
                mutations: vec![(
                    NATIVE_HA_SHARED_RETIREMENT_RESOURCE.into(),
                    Some(pending.clone()),
                )],
            },
            conditions,
            &mut *before,
        )?;
        if !matches!(begin, MutationOutcome::Committed { generation: actual, .. } if actual == record.pending_generation)
        {
            self.unresolved = true;
            return Err(ServiceError::RecoveryRequired);
        }
        let result = (|| -> Result<NativeHaSharedRetirementOutcome, ServiceError> {
            let completed_owner = {
                let mut verify_known = || -> Result<(), ServiceError> {
                    before()?;
                    self.verify_live_ownership()?;
                    self.ha_shared_check_conditions(&request.conditions)?;
                    if self.generation() != record.pending_generation
                        || self.replay_epoch != epoch
                        || self
                            .get("system", NATIVE_HA_SHARED_RETIREMENT_RESOURCE)?
                            .as_ref()
                            .map(Secret::expose)
                            != Some(pending.expose())
                    {
                        return Err(ServiceError::PublicationConditionConflict);
                    }
                    Arc::get_mut(&mut self.restore_instance)
                        .ok_or(ServiceError::PublicationConditionConflict)?;
                    before()
                };
                verify_known()?;
                request.physical.retire(&mut verify_known)?
            };
            completed_owner.verify_completed(before)?;
            let physical = completed_owner.outcome();
            physical.validate(record.selected_files, attempt > 0)?;
            before()?;
            self.verify_live_ownership()?;
            self.ha_shared_check_conditions(&request.conditions)?;
            if self.generation() != record.pending_generation || self.replay_epoch != epoch {
                return Err(ServiceError::PublicationConditionConflict);
            }
            record.phase = if attempt == 0 {
                Phase::Completed
            } else {
                Phase::ReconciliationCompleted
            };
            record.physical = physical;
            let completed = record.encode()?;
            if completed.expose().len() != pending.expose().len() {
                return Err(ServiceError::CorruptState);
            }
            let mut conditions = copy_conditions(&request.conditions);
            conditions.push(PublicationCondition {
                resource: NATIVE_HA_SHARED_RETIREMENT_RESOURCE.into(),
                expected: Some(pending),
            });
            let mut terminal_gate = || completed_owner.verify_completed(before);
            let done = self.apply_batch_conditionally_with_io_gate(
                BatchPublication {
                    replay_epoch: epoch,
                    principal: request.principal,
                    namespace: "system".into(),
                    request_id: done_id,
                    authorization_digest: request.authorization_digest,
                    mutations: vec![(NATIVE_HA_SHARED_RETIREMENT_RESOURCE.into(), Some(completed))],
                },
                conditions,
                &mut terminal_gate,
            )?;
            if !matches!(done, MutationOutcome::Committed { generation: actual, .. } if Some(actual) == record.pending_generation.checked_add(1))
            {
                return Err(ServiceError::RecoveryRequired);
            }
            completed_owner.verify_completed(before)?;
            Ok(NativeHaSharedRetirementOutcome {
                generation: self.generation(),
                physical,
            })
        })();
        if result.is_err() {
            self.unresolved = true;
        }
        result
    }
}

#[cfg(all(test, unix))]
#[path = "native_ha_retirement_ledger_tests.rs"]
mod tests;
