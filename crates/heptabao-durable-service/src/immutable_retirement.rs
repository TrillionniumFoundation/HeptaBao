//! A bounded authenticated retirement transaction followed by physical unlink.
//! The caller owns the complete typed root closure and original Actor/deadline.
//! Neither the session nor the retained-name set grants that application proof.
use super::*;
use crate::v6_object_backup::Slot;
use std::collections::BTreeSet;

pub const IMMUTABLE_RETIREMENT_RESOURCE: &str = "state-native-v6/file-retirement";
const MAGIC_V1: &[u8; 16] = b"HBV6RETIRE0001\0\0";
const MAGIC: &[u8; 16] = b"HBV6RETIRE0002\0\0";
const OBJECT_PREFIX: &str = "state-records/v6/";
const MAX_OBJECTS: usize = 1_000_000;
const MAX_BATCH: usize = heptabao_filesystem_guard::MAX_IMMUTABLE_RETIREMENT_FILES;
const MAX_CONDITIONS: usize = 8;
const MAX_RECORD: usize = 32 * 1024;

#[path = "immutable_ha_local_retirement.rs"]
mod ha_local;
pub use ha_local::{NativeHaLocalRetentionOwner, NativeHaLocalRetirementBoundary};

#[derive(Clone, Copy)]
enum RetirementCatalog {
    Standalone,
    NativeHa,
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Read-only registered-resource DATA from the same live source session.
    /// Every slot is decoded from the authenticated snapshot; duplicate local
    /// addresses, foreign stores, Pending ledgers and unknown side selectors
    /// hold the whole inspection. This returns no retirement plan or locator
    /// deletion permission and does not change the File GC HA refusal.
    pub fn inspect_native_ha_local_resources(
        &mut self,
        session: &ImmutableSourceSession,
        conditions: &[PublicationCondition],
        original: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<BTreeSet<String>, ServiceError> {
        const REQUIRED: [&str; 4] = [
            "state",
            "state-native-v6/active-publication-cursor",
            "state-native-v6/active-source-root",
            "state-native-v6/ha-publication-cursor",
        ];
        original()?;
        self.check_immutable_source_session(session)?;
        self.ensure_no_pending_immutable_retirement()?;
        self.ensure_no_pending_ha_shared_retirement()?;
        self.ensure_no_pending_ha_intent_retirement()?;
        if session.namespace != "system"
            || session.resource != "state"
            || conditions.len() != REQUIRED.len()
            || REQUIRED.iter().any(|name| {
                conditions
                    .iter()
                    .filter(|condition| condition.resource == *name && condition.expected.is_some())
                    .count()
                    != 1
            })
            || conditions
                .iter()
                .find(|condition| condition.resource == "state")
                .and_then(|condition| condition.expected.as_ref())
                .map(Secret::expose)
                != Some(session.root.expose())
        {
            return Err(ServiceError::InvalidResource);
        }
        self.check_retirement_conditions(conditions)?;
        if self.get("system", "state-native-v6")?.is_some()
            || self.get("system", "state-records/v6")?.is_some()
        {
            return Err(ServiceError::UnsupportedProfile);
        }
        for leaf in self.list("system", "state-native-v6")? {
            original()?;
            if !matches!(
                leaf.as_str(),
                "active-publication-cursor"
                    | "active-source-root"
                    | "ha-publication-cursor"
                    | "file-retirement"
                    | "ha-shared-retirement"
                    | "ha-intent-retirement"
            ) {
                return Err(ServiceError::UnsupportedProfile);
            }
        }
        let mut resources = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for ((namespace, resource), value) in &self.snapshot.entries {
            original()?;
            if namespace != "system" || !resource.starts_with(OBJECT_PREFIX) {
                continue;
            }
            let slot = Slot::decode(resource, value.expose())?;
            if slot.locator.store_id() != session.store_id
                || !addresses.insert((slot.locator.store_id(), slot.locator.address()))
            {
                return Err(ServiceError::CorruptState);
            }
            if resources.len() >= MAX_OBJECTS {
                return Err(ServiceError::RequestCapacityExhausted);
            }
            resources.insert(resource.clone());
        }
        if resources.is_empty() {
            return Err(ServiceError::CorruptState);
        }
        original()?;
        self.check_immutable_source_session(session)?;
        self.check_retirement_conditions(conditions)?;
        original()?;
        Ok(resources)
    }
}

#[cfg(test)]
thread_local! {
    // One owned test thread may interrupt a precise boundary. There is no
    // environment/CLI/serialized switch and no production retry branch.
    static TEST_RETIREMENT_STOP: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
fn test_boundary(stage: u8) -> Result<(), ServiceError> {
    TEST_RETIREMENT_STOP.with(|slot| {
        if slot.get() == stage {
            slot.set(0);
            Err(ServiceError::RecoveryRequired)
        } else {
            Ok(())
        }
    })
}

pub struct ImmutableRetirementRequest {
    pub session: ImmutableSourceSession,
    pub principal: String,
    pub operation_id: String,
    pub authorization_digest: [u8; 32],
    pub conditions: Vec<PublicationCondition>,
    pub retained_resources: BTreeSet<String>,
}
impl fmt::Debug for ImmutableRetirementRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmutableRetirementRequest")
            .field("retained_objects", &self.retained_resources.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImmutableRetirementOutcome {
    pub generation: u64,
    pub removed_objects: usize,
    pub removed_ciphertext_bytes: u64,
    pub confirmed_absent_objects: usize,
    pub registered_objects_before: usize,
    pub retained_objects: usize,
}

struct Entry {
    slot: Slot,
    marker: Secret,
    ciphertext_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RetirementPhase {
    Pending = 0,
    OriginalCompleted = 1,
    AbsenceConfirmed = 2,
    ReconciliationPending = 3,
    ReconciliationCompleted = 4,
}
impl RetirementPhase {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::OriginalCompleted | Self::AbsenceConfirmed | Self::ReconciliationCompleted
        )
    }
    fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::OriginalCompleted => "original-completed",
            Self::AbsenceConfirmed => "absence-confirmed",
            Self::ReconciliationPending => "reconciliation-pending",
            Self::ReconciliationCompleted => "reconciliation-completed",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RecordFormat {
    V1 = 1,
    V2 = 2,
}
struct ReconciliationLineage {
    original_format: RecordFormat,
    original_pending_digest: [u8; 32],
    predecessor_digest: [u8; 32],
    attempt: u64,
    source_generation: u64,
    publication_generation: u64,
    replay_epoch: u64,
    selection_digest: [u8; 32],
    descriptor_digest: [u8; 32],
    present_mask: u32,
}
struct Retirement {
    format: RecordFormat,
    phase: RetirementPhase,
    source_generation: u64,
    retirement_generation: u64,
    replay_epoch: u64,
    selection_digest: [u8; 32],
    lineage: Option<ReconciliationLineage>,
    entries: Vec<Entry>,
}
fn raw_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
impl Retirement {
    fn original_format(&self) -> RecordFormat {
        self.lineage
            .as_ref()
            .map_or(self.format, |lineage| lineage.original_format)
    }
    fn original_pending_digest(&self) -> Result<[u8; 32], ServiceError> {
        Ok(raw_digest(
            self.encode_wire(self.original_format(), RetirementPhase::Pending, None)?
                .expose(),
        ))
    }
    fn active_retirement_generation(&self) -> u64 {
        self.lineage
            .as_ref()
            .map_or(self.retirement_generation, |lineage| {
                lineage.publication_generation
            })
    }
    fn validate(&self) -> Result<(), ServiceError> {
        if self.entries.is_empty()
            || self.entries.len() > MAX_BATCH
            || self.source_generation == 0
            || self.source_generation.checked_add(1) != Some(self.retirement_generation)
        {
            return Err(ServiceError::CorruptState);
        }
        match &self.lineage {
            None if matches!(
                self.phase,
                RetirementPhase::Pending
                    | RetirementPhase::OriginalCompleted
                    | RetirementPhase::AbsenceConfirmed
            ) => {}
            Some(lineage)
                if self.format == RecordFormat::V2
                    && matches!(
                        self.phase,
                        RetirementPhase::ReconciliationPending
                            | RetirementPhase::ReconciliationCompleted
                            | RetirementPhase::AbsenceConfirmed
                    )
                    && lineage.attempt > 0
                    && lineage.source_generation >= self.retirement_generation
                    && lineage.source_generation.checked_add(1)
                        == Some(lineage.publication_generation)
                    && lineage.replay_epoch == self.replay_epoch
                    && lineage.present_mask != 0
                    && u64::from(lineage.present_mask) < (1_u64 << self.entries.len())
                    && lineage.original_pending_digest == self.original_pending_digest()? => {}
            _ => return Err(ServiceError::CorruptState),
        }
        Ok(())
    }
    fn encode(&self) -> Result<Secret, ServiceError> {
        self.validate()?;
        self.encode_wire(self.format, self.phase, self.lineage.as_ref())
    }
    fn encode_wire(
        &self,
        format: RecordFormat,
        phase: RetirementPhase,
        lineage: Option<&ReconciliationLineage>,
    ) -> Result<Secret, ServiceError> {
        if self.entries.is_empty()
            || self.entries.len() > MAX_BATCH
            || (format == RecordFormat::V1 && (lineage.is_some() || phase as u8 > 2))
        {
            return Err(ServiceError::CorruptState);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(match format {
            RecordFormat::V1 => MAGIC_V1,
            RecordFormat::V2 => MAGIC,
        });
        bytes.push(phase as u8);
        write_u64(&mut bytes, self.source_generation);
        write_u64(&mut bytes, self.retirement_generation);
        write_u64(&mut bytes, self.replay_epoch);
        bytes.extend_from_slice(&self.selection_digest);
        if format == RecordFormat::V2 {
            bytes.push(u8::from(lineage.is_some()));
            if let Some(lineage) = lineage {
                bytes.push(lineage.original_format as u8);
                bytes.extend_from_slice(&lineage.original_pending_digest);
                bytes.extend_from_slice(&lineage.predecessor_digest);
                write_u64(&mut bytes, lineage.attempt);
                write_u64(&mut bytes, lineage.source_generation);
                write_u64(&mut bytes, lineage.publication_generation);
                write_u64(&mut bytes, lineage.replay_epoch);
                bytes.extend_from_slice(&lineage.selection_digest);
                bytes.extend_from_slice(&lineage.descriptor_digest);
                write_u32(&mut bytes, lineage.present_mask);
            }
        }
        write_u32(&mut bytes, self.entries.len() as u32);
        for entry in &self.entries {
            encode_string(&mut bytes, &entry.slot.resource);
            bytes.extend_from_slice(entry.marker.expose());
            bytes.extend_from_slice(&entry.ciphertext_digest);
        }
        if bytes.len() > MAX_RECORD {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        Secret::new(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        if bytes.len() > MAX_RECORD {
            return Err(ServiceError::CorruptState);
        }
        let mut input = Cursor::new(bytes);
        let magic = input.read_exact(MAGIC.len())?;
        let format = if magic == MAGIC_V1 {
            RecordFormat::V1
        } else if magic == MAGIC {
            RecordFormat::V2
        } else {
            return Err(ServiceError::CorruptState);
        };
        let phase = match input.read_u8()? {
            0 => RetirementPhase::Pending,
            1 => RetirementPhase::OriginalCompleted,
            2 => RetirementPhase::AbsenceConfirmed,
            3 if format == RecordFormat::V2 => RetirementPhase::ReconciliationPending,
            4 if format == RecordFormat::V2 => RetirementPhase::ReconciliationCompleted,
            _ => return Err(ServiceError::CorruptState),
        };
        let source_generation = input.read_u64()?;
        let retirement_generation = input.read_u64()?;
        let replay_epoch = input.read_u64()?;
        let selection_digest = input.read_array_32()?;
        let lineage = if format == RecordFormat::V1 {
            None
        } else {
            match input.read_u8()? {
                0 => None,
                1 => Some(ReconciliationLineage {
                    original_format: match input.read_u8()? {
                        1 => RecordFormat::V1,
                        2 => RecordFormat::V2,
                        _ => return Err(ServiceError::CorruptState),
                    },
                    original_pending_digest: input.read_array_32()?,
                    predecessor_digest: input.read_array_32()?,
                    attempt: input.read_u64()?,
                    source_generation: input.read_u64()?,
                    publication_generation: input.read_u64()?,
                    replay_epoch: input.read_u64()?,
                    selection_digest: input.read_array_32()?,
                    descriptor_digest: input.read_array_32()?,
                    present_mask: input.read_u32()?,
                }),
                _ => return Err(ServiceError::CorruptState),
            }
        };
        let count = input.read_u32()? as usize;
        if count == 0 || count > MAX_BATCH {
            return Err(ServiceError::CorruptState);
        }
        let mut entries = Vec::with_capacity(count);
        let mut addresses = BTreeSet::new();
        let mut names = BTreeSet::new();
        for _ in 0..count {
            let resource = input.read_string(MAX_STRING_BYTES)?;
            validate_resource(&resource)?;
            let marker = Secret::new(input.read_exact(72)?.to_vec())?;
            let slot = Slot::decode(&resource, marker.expose())?;
            if !addresses.insert((slot.locator.store_id(), slot.locator.address()))
                || !names.insert(resource)
            {
                return Err(ServiceError::CorruptState);
            }
            entries.push(Entry {
                slot,
                marker,
                ciphertext_digest: input.read_array_32()?,
            });
        }
        input.finish()?;
        let record = Self {
            format,
            phase,
            source_generation,
            retirement_generation,
            replay_epoch,
            selection_digest,
            lineage,
            entries,
        };
        record.validate()?;
        if record.encode()?.expose() != bytes {
            return Err(ServiceError::CorruptState);
        }
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImmutableRetirementStatus {
    pub phase: &'static str,
    pub pending: bool,
    pub record_sha256: [u8; 32],
    pub original_pending_sha256: [u8; 32],
    pub original_completion_recorded: bool,
    pub historical_request_outcome_reclassified: bool,
    pub selected_objects: usize,
    pub original_retirement_generation: u64,
    pub active_retirement_generation: u64,
    pub replay_epoch: u64,
    pub reconciliation_attempt: u64,
}

#[path = "immutable_retirement_reconcile.rs"]
mod reconciliation;

fn copy_conditions(conditions: &[PublicationCondition]) -> Vec<PublicationCondition> {
    conditions
        .iter()
        .map(|condition| PublicationCondition {
            resource: condition.resource.clone(),
            expected: condition.expected.clone(),
        })
        .collect()
}
fn selection_digest(conditions: &[PublicationCondition]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for condition in conditions {
        encode_string(&mut bytes, &condition.resource);
        match &condition.expected {
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&digest32(
                    b"heptabao.retirement-selected-root.v1",
                    value.expose(),
                ));
            }
            None => bytes.push(0),
        }
    }
    digest32(b"heptabao.retirement-selection.v1", &bytes)
}
fn authenticate<B: Barrier>(barrier: &B, entry: &Entry, bytes: &[u8]) -> Result<(), BackendError> {
    if bytes.len() != entry.slot.ciphertext_bytes {
        return Err(BackendError::Corrupt);
    }
    let plaintext = Zeroizing::new(
        barrier
            .open(&entry.slot.aad(), bytes)
            .map_err(|_| BackendError::Corrupt)?,
    );
    if plaintext.len() != entry.slot.plaintext_bytes {
        return Err(BackendError::Corrupt);
    }
    Ok(())
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    fn retirement_record(&self) -> Result<Option<(Secret, Retirement)>, ServiceError> {
        self.snapshot
            .entries
            .get(&("system".into(), IMMUTABLE_RETIREMENT_RESOURCE.into()))
            .map(|value| Ok((value.clone(), Retirement::decode(value.expose())?)))
            .transpose()
    }

    /// Pending retirement cannot be reused as a newly staged object, even
    /// after a cold reopen has resolved the metadata journal. Unknown physical
    /// outcomes are held for explicit absence reconciliation, never retried.
    pub(super) fn ensure_immutable_locator_not_retiring(
        &self,
        locator: BlobLocator,
    ) -> Result<(), ServiceError> {
        if self.retirement_record()?.is_some_and(|(_, record)| {
            !record.phase.is_terminal()
                && record
                    .entries
                    .iter()
                    .any(|entry| entry.slot.locator == locator)
        }) {
            return Err(ServiceError::PublicationConditionConflict);
        }
        Ok(())
    }

    pub(crate) fn ensure_no_pending_immutable_retirement(&self) -> Result<(), ServiceError> {
        if self
            .retirement_record()?
            .is_some_and(|(_, record)| !record.phase.is_terminal())
        {
            return Err(ServiceError::RecoveryRequired);
        }
        Ok(())
    }

    pub(crate) fn ensure_retirement_restore_complete(
        prepared: &PreparedRestore,
    ) -> Result<(), ServiceError> {
        if let Some(bytes) = prepared.get("system", IMMUTABLE_RETIREMENT_RESOURCE)?
            && !Retirement::decode(bytes)?.phase.is_terminal()
        {
            return Err(ServiceError::RecoveryRequired);
        }
        Ok(())
    }

    fn check_retirement_conditions(
        &self,
        conditions: &[PublicationCondition],
    ) -> Result<(), ServiceError> {
        for condition in conditions {
            let value = self.get("system", &condition.resource)?;
            if value.as_ref().map(Secret::expose) != condition.expected.as_ref().map(Secret::expose)
            {
                return Err(ServiceError::PublicationConditionConflict);
            }
        }
        Ok(())
    }

    // Reserve BOTH original journal transactions before entering either one.
    // The codec supplies exact plaintext lengths; the actual barrier supplies
    // its conservative ciphertext bound. No implicit compaction, speculative
    // seal, replay-epoch rotation, checkpoint or graph mutation occurs here.
    fn reserve_retirement_pair(
        &self,
        principal: &str,
        begin_id: &str,
        done_id: &str,
        authorization_digest: [u8; 32],
        mutations: &[(String, Option<Secret>)],
        pending: &Secret,
    ) -> Result<(), ServiceError> {
        let mut journal = self.journal_bytes;
        let mut ledger = self.ledger_plaintext_bytes;
        let mut next_snapshot = None;
        let mut previous_marker = None;
        if self
            .journal_sequence
            .checked_add(6)
            .is_none_or(|n| n > MAX_RECORDS as u64)
        {
            return Err(ServiceError::JournalCapacityExhausted);
        }
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
            let marker_len = encoded_marker_len(&marker)?;
            ledger = ledger
                .checked_add(marker_len)
                .ok_or(ServiceError::RequestCapacityExhausted)?;
            let entries = if index == 0 {
                mutations
                    .iter()
                    .map(|(resource, value)| JournalMutation {
                        resource: resource.clone(),
                        value: value.clone(),
                    })
                    .collect::<Vec<_>>()
            } else {
                // Terminal confirmation changes one phase byte only. Its length,
                // resource and marker count exactly equal this pending value.
                vec![JournalMutation {
                    resource: IMMUTABLE_RETIREMENT_RESOURCE.into(),
                    value: Some(pending.clone()),
                }]
            };
            let snapshot_len = if index == 0 {
                candidate_snapshot_plaintext_len(
                    &self.snapshot,
                    self.snapshot_plaintext_bytes,
                    &marker,
                    &entries,
                )?
            } else {
                next_snapshot
                    .and_then(|n: usize| n.checked_sub(previous_marker?))
                    .and_then(|n| n.checked_add(marker_len))
                    .ok_or(ServiceError::RequestCapacityExhausted)?
            };
            if snapshot_frame_len_bound(&self.barrier, snapshot_len)
                .is_none_or(|n| n > MAX_FILE_BYTES)
                || self
                    .barrier
                    .sealed_len_bound(ledger)
                    .and_then(|n| n.checked_add(48))
                    .is_none_or(|n| n > MAX_FILE_BYTES)
            {
                return Err(ServiceError::RequestCapacityExhausted);
            }
            next_snapshot = Some(snapshot_len);
            previous_marker = Some(marker_len);
            for event in [
                JournalEvent::Intent(marker.clone()),
                JournalEvent::Apply {
                    marker: marker.clone(),
                    mutations: entries,
                },
                JournalEvent::Commit(marker),
            ] {
                let encoded = encode_journal_event(&event)?;
                let bound = self
                    .barrier
                    .sealed_len_bound(encoded.len())
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

    /// Retire at most 32 registered, authenticated immutable objects that the
    /// caller's actual complete typed closure did not reach. No unregistered
    /// directory orphan, V5 record, side root or HA object is collected.
    ///
    /// The caller must drop its mark reader first. This consumes the final
    /// supplied session, checks BOTH service and physical read-owner uniqueness,
    /// publishes one exact pending record + locator removals, and only then
    /// unlinks the original descriptors. Duplicate/unknown metadata results
    /// never enter physical deletion. This call never recaptures a deadline.
    pub fn retire_immutable_objects(
        &mut self,
        request: ImmutableRetirementRequest,
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<ImmutableRetirementOutcome, ServiceError> {
        self.retire_immutable_objects_owned(
            request,
            before,
            RetirementCatalog::Standalone,
            &mut |_| Ok(()),
        )
    }

    fn retire_immutable_objects_owned(
        &mut self,
        request: ImmutableRetirementRequest,
        before: &mut impl FnMut() -> Result<(), ServiceError>,
        catalog: RetirementCatalog,
        boundary: &mut impl FnMut(NativeHaLocalRetirementBoundary) -> Result<(), ServiceError>,
    ) -> Result<ImmutableRetirementOutcome, ServiceError> {
        before()?;
        self.ensure_no_pending_ha_shared_retirement()?;
        self.ensure_no_pending_ha_intent_retirement()?;
        self.check_immutable_source_session(&request.session)?;
        #[cfg(test)]
        eprintln!("HBGC-RETIRE stage=source-checked");
        if request.session.namespace != "system"
            || request.session.resource != "state"
            || request.retained_resources.is_empty()
            || request.retained_resources.len() > MAX_OBJECTS
            || request.conditions.len() < 3
            || request.conditions.len() > MAX_CONDITIONS
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
        let mut condition_names = BTreeSet::new();
        for condition in &request.conditions {
            validate_resource(&condition.resource)?;
            if condition.resource == IMMUTABLE_RETIREMENT_RESOURCE
                || !condition_names.insert(condition.resource.as_str())
            {
                return Err(ServiceError::InvalidResource);
            }
        }
        for resource in [
            "state",
            "state-native-v6/active-publication-cursor",
            "state-native-v6/active-source-root",
        ] {
            if !request
                .conditions
                .iter()
                .any(|c| c.resource == resource && c.expected.is_some())
            {
                return Err(ServiceError::InvalidResource);
            }
        }
        if request
            .conditions
            .iter()
            .find(|c| c.resource == "state")
            .and_then(|c| c.expected.as_ref())
            .map(Secret::expose)
            != Some(request.session.root.expose())
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        self.check_retirement_conditions(&request.conditions)?;
        // Standalone keeps its original HA refusal. The separate HA entry
        // reaches this private branch only with its held production custody.
        self.check_immutable_retirement_catalog(catalog, &request.conditions, before)?;
        let generation = self.snapshot.generation;
        let epoch = self.replay_epoch;
        let store_id = request.session.store_id;
        let selected_digest = selection_digest(&request.conditions);
        let mut candidates = Vec::new();
        let mut addresses = BTreeSet::new();
        let mut registered = 0usize;
        let mut reached = BTreeSet::new();
        for ((namespace, resource), value) in &self.snapshot.entries {
            before()?;
            if namespace != "system" || !resource.starts_with(OBJECT_PREFIX) {
                continue;
            }
            let slot = Slot::decode(resource, value.expose())?;
            if slot.locator.store_id() != store_id
                || !addresses.insert((slot.locator.store_id(), slot.locator.address()))
            {
                return Err(ServiceError::CorruptState);
            }
            registered = registered
                .checked_add(1)
                .filter(|count| *count <= MAX_OBJECTS)
                .ok_or(ServiceError::RequestCapacityExhausted)?;
            if request.retained_resources.contains(resource) {
                reached.insert(resource.clone());
            } else if candidates.len() < MAX_BATCH {
                candidates.push(Entry {
                    slot,
                    marker: value.clone(),
                    ciphertext_digest: [0; 32],
                });
            }
        }
        if reached != request.retained_resources {
            return Err(ServiceError::CorruptState);
        }
        #[cfg(test)]
        eprintln!(
            "HBGC-RETIRE stage=catalog-checked registered={registered} candidates={} retained={}",
            candidates.len(),
            reached.len()
        );
        before()?;
        self.check_immutable_source_session(&request.session)?;
        let previous = self.retirement_record()?;
        // The sole supplied Weak/profile must be consumed, not counted as an
        // unrelated active reader. All other Weak/strong holders still block.
        drop(request.session);
        Arc::get_mut(&mut self.restore_instance)
            .ok_or(ServiceError::PublicationConditionConflict)?;
        before()?;
        #[cfg(test)]
        eprintln!("HBGC-RETIRE stage=source-quiescent");
        if let Some((record_bytes, record)) = previous
            .as_ref()
            .filter(|(_, record)| !record.phase.is_terminal())
        {
            // No automatic unlink is reachable on this branch. Reconcile only
            // authenticated journal retirement whose EVERY exact leaf is now
            // absent on both sides of an explicit directory barrier and whose
            // locator has not re-entered the current closure.
            if record.replay_epoch != epoch
                || record.active_retirement_generation() > generation
                || record.entries.iter().any(|entry| {
                    entry.slot.locator.store_id() != store_id
                        || request.retained_resources.contains(&entry.slot.resource)
                        || self
                            .snapshot
                            .entries
                            .contains_key(&("system".into(), entry.slot.resource.clone()))
                })
            {
                return Err(ServiceError::PublicationConditionConflict);
            }
            let objects = record
                .entries
                .iter()
                .map(|entry| entry.slot.locator)
                .collect::<Vec<_>>();
            let mut gate = || before().map_err(|_| BackendError::Unavailable);
            self.backend
                .confirm_immutable_retirement_absent(&objects, &mut gate)
                .map_err(map_backend_error)?;
            before()?;
            self.check_retirement_conditions(&request.conditions)?;
            if self.snapshot.generation != generation || self.replay_epoch != epoch {
                return Err(ServiceError::PublicationConditionConflict);
            }
            // Re-decode to own the affine record; no previous descriptor or
            // stale source session is reconstructed from serialized metadata.
            let count = record.entries.len();
            let mut complete = Retirement::decode(record_bytes.expose())?;
            complete.phase = RetirementPhase::AbsenceConfirmed;
            let mut conditions = copy_conditions(&request.conditions);
            conditions.push(PublicationCondition {
                resource: IMMUTABLE_RETIREMENT_RESOURCE.into(),
                expected: Some(record_bytes.clone()),
            });
            for entry in &record.entries {
                conditions.push(PublicationCondition {
                    resource: entry.slot.resource.clone(),
                    expected: None,
                });
            }
            let expected_generation = generation
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?;
            let result = self.apply_batch_conditionally_with_io_gate(
                BatchPublication {
                    replay_epoch: epoch,
                    principal: request.principal,
                    namespace: "system".into(),
                    request_id: done_id,
                    authorization_digest: request.authorization_digest,
                    mutations: vec![(
                        IMMUTABLE_RETIREMENT_RESOURCE.into(),
                        Some(complete.encode()?),
                    )],
                },
                conditions,
                before,
            );
            if !matches!(result, Ok(MutationOutcome::Committed { generation: actual, .. }) if actual == expected_generation)
            {
                self.unresolved = true;
                return Err(ServiceError::RecoveryRequired);
            }
            return Ok(ImmutableRetirementOutcome {
                generation: self.generation(),
                removed_objects: 0,
                removed_ciphertext_bytes: 0,
                confirmed_absent_objects: count,
                registered_objects_before: registered,
                retained_objects: request.retained_resources.len(),
            });
        }
        if candidates.is_empty() {
            // Even a zero-object result must not imply quiescence while a
            // physical read profile or pin is still admitted. The empty list
            // asks for this owner's check only; it never publishes or unlinks.
            let mut gate = || before().map_err(|_| BackendError::Unavailable);
            self.backend
                .confirm_immutable_retirement_absent(&[], &mut gate)
                .map_err(map_backend_error)?;
            before()?;
            return Ok(ImmutableRetirementOutcome {
                generation,
                removed_objects: 0,
                removed_ciphertext_bytes: 0,
                confirmed_absent_objects: 0,
                registered_objects_before: registered,
                retained_objects: request.retained_resources.len(),
            });
        }
        if self
            .ledger
            .len()
            .checked_add(2)
            .is_none_or(|count| count > self.max_retained_requests)
        {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let objects = candidates
            .iter()
            .map(|entry| (entry.slot.locator, entry.slot.ciphertext_bytes))
            .collect::<Vec<_>>();
        let prepared = {
            let barrier = &self.barrier;
            let mut auth = |index: usize, bytes: &[u8]| {
                authenticate(
                    barrier,
                    candidates.get(index).ok_or(BackendError::Corrupt)?,
                    bytes,
                )
            };
            let mut gate = || before().map_err(|_| BackendError::Unavailable);
            let observation = self
                .backend
                .prepare_immutable_retirement(&objects, &mut auth, &mut gate);
            #[cfg(test)]
            eprintln!(
                "HBGC-RETIRE stage=fd-preparation-returned accepted={} error={:?}",
                observation.is_ok(),
                observation.as_ref().err()
            );
            observation.map_err(map_backend_error)?
        };
        for (index, entry) in candidates.iter_mut().enumerate() {
            entry.ciphertext_digest = prepared
                .ciphertext_digest(index)
                .map_err(map_backend_error)?;
        }
        before()?;
        self.check_retirement_conditions(&request.conditions)?;
        if self.snapshot.generation != generation || self.replay_epoch != epoch {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let mut retirement = Retirement {
            format: RecordFormat::V2,
            phase: RetirementPhase::Pending,
            lineage: None,
            source_generation: generation,
            retirement_generation: generation
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?,
            replay_epoch: epoch,
            selection_digest: selected_digest,
            entries: candidates,
        };
        let pending = retirement.encode()?;
        #[cfg(test)]
        eprintln!(
            "HBGC-RETIRE stage=pending-encoded bytes={}",
            pending.expose().len()
        );
        let mut conditions = copy_conditions(&request.conditions);
        conditions.push(PublicationCondition {
            resource: IMMUTABLE_RETIREMENT_RESOURCE.into(),
            expected: previous.map(|(bytes, _)| bytes),
        });
        for entry in &retirement.entries {
            conditions.push(PublicationCondition {
                resource: entry.slot.resource.clone(),
                expected: Some(entry.marker.clone()),
            });
        }
        let mut mutations = retirement
            .entries
            .iter()
            .map(|entry| (entry.slot.resource.clone(), None))
            .collect::<Vec<_>>();
        mutations.push((IMMUTABLE_RETIREMENT_RESOURCE.into(), Some(pending.clone())));
        self.reserve_retirement_pair(
            &request.principal,
            &begin_id,
            &done_id,
            request.authorization_digest,
            &mutations,
            &pending,
        )?;
        before()?;
        #[cfg(test)]
        eprintln!("HBGC-RETIRE stage=both-transactions-reserved");
        #[cfg(test)]
        test_boundary(1)?;
        #[cfg(test)]
        eprintln!("HBGC-RETIRE stage=before-apply");
        let committed = self.apply_batch_conditionally_with_io_gate(
            BatchPublication {
                replay_epoch: epoch,
                principal: request.principal.clone(),
                namespace: "system".into(),
                request_id: begin_id,
                authorization_digest: request.authorization_digest,
                mutations,
            },
            conditions,
            &mut *before,
        )?;
        // A duplicate is never evidence that THIS instance owns a fresh unlink.
        if !matches!(committed, MutationOutcome::Committed { generation: actual, .. } if actual == retirement.retirement_generation)
        {
            self.unresolved = true;
            return Err(ServiceError::RecoveryRequired);
        }
        let result = (|| -> Result<ImmutableRetirementOutcome, ServiceError> {
            #[cfg(test)]
            test_boundary(2)?;
            boundary(NativeHaLocalRetirementBoundary::KnownPending)?;
            before()?;
            self.check_retirement_conditions(&request.conditions)?;
            if self.generation() != retirement.retirement_generation
                || self
                    .get("system", IMMUTABLE_RETIREMENT_RESOURCE)?
                    .as_ref()
                    .map(Secret::expose)
                    != Some(pending.expose())
                || retirement.entries.iter().any(|entry| {
                    self.snapshot
                        .entries
                        .contains_key(&("system".into(), entry.slot.resource.clone()))
                })
            {
                return Err(ServiceError::PublicationConditionConflict);
            }
            Arc::get_mut(&mut self.restore_instance)
                .ok_or(ServiceError::PublicationConditionConflict)?;
            {
                let barrier = &self.barrier;
                let mut auth = |index: usize, bytes: &[u8]| {
                    authenticate(
                        barrier,
                        retirement.entries.get(index).ok_or(BackendError::Corrupt)?,
                        bytes,
                    )
                };
                let mut gate = || before().map_err(|_| BackendError::Unavailable);
                self.backend
                    .retire_prepared_immutable_ciphertexts(prepared, &mut auth, &mut gate)
                    .map_err(map_backend_error)?;
            }
            #[cfg(test)]
            test_boundary(3)?;
            boundary(NativeHaLocalRetirementBoundary::PhysicalCompleted)?;
            before()?;
            self.check_retirement_conditions(&request.conditions)?;
            if self.generation() != retirement.retirement_generation {
                return Err(ServiceError::PublicationConditionConflict);
            }
            retirement.phase = RetirementPhase::OriginalCompleted;
            let mut conditions = copy_conditions(&request.conditions);
            conditions.push(PublicationCondition {
                resource: IMMUTABLE_RETIREMENT_RESOURCE.into(),
                expected: Some(pending),
            });
            for entry in &retirement.entries {
                conditions.push(PublicationCondition {
                    resource: entry.slot.resource.clone(),
                    expected: None,
                });
            }
            let result = self.apply_batch_conditionally_with_io_gate(
                BatchPublication {
                    replay_epoch: epoch,
                    principal: request.principal,
                    namespace: "system".into(),
                    request_id: done_id,
                    authorization_digest: request.authorization_digest,
                    mutations: vec![(
                        IMMUTABLE_RETIREMENT_RESOURCE.into(),
                        Some(retirement.encode()?),
                    )],
                },
                conditions,
                &mut *before,
            )?;
            if !matches!(result, MutationOutcome::Committed { generation: actual, .. } if Some(actual) == retirement.retirement_generation.checked_add(1))
            {
                return Err(ServiceError::RecoveryRequired);
            }
            before()?;
            Ok(ImmutableRetirementOutcome {
                generation: self.generation(),
                removed_objects: retirement.entries.len(),
                removed_ciphertext_bytes: retirement
                    .entries
                    .iter()
                    .map(|entry| entry.slot.ciphertext_bytes as u64)
                    .sum(),
                confirmed_absent_objects: 0,
                registered_objects_before: registered,
                retained_objects: request.retained_resources.len(),
            })
        })();
        if result.is_err() {
            self.unresolved = true;
        }
        result
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "immutable_retirement_tests.rs"]
mod tests;
