//! Durable, fail-closed migration inventory and reconciliation journal.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use heptabao_domain::{CanonicalPath, Id};
use heptabao_filesystem_guard::{DirectoryGuardError, ExclusiveDirectory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[path = "durable_auth.rs"]
mod authentication;
use authentication::JournalAuthentication;
pub use authentication::MigrationJournalAuthenticator;

const JOURNAL_SCHEMA: &str = "heptabao.migration-journal.v1";
const ENVELOPE_SCHEMA: &str = "heptabao.migration-journal-envelope.v1";
const CURRENT_FILE: &str = "migration-state.json";
const PREVIOUS_FILE: &str = "migration-state.previous.json";
const MAX_OBJECTS: usize = 4096;
const MAX_DEPENDENCIES: usize = 128;
const MAX_PROFILE_BYTES: usize = 128;
const MAX_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

/// Closed set of persisted product domains admitted by the migration journal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationObjectClass {
    Policy,
    Mount,
    AuthMethod,
    Identity,
    Token,
    Lease,
    KvHistory,
    Transit,
    Pki,
    Ssh,
    Database,
    Audit,
    PluginCatalog,
    SystemMetadata,
}

/// One immutable source-to-target object binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationObject {
    pub object_id: String,
    pub class: MigrationObjectClass,
    pub source_path: String,
    pub source_sha256: String,
    pub expected_target_sha256: String,
    pub dependencies: Vec<String>,
}

impl MigrationObject {
    pub fn new(
        object_id: impl Into<String>,
        class: MigrationObjectClass,
        source_path: impl Into<String>,
        source_sha256: impl Into<String>,
        expected_target_sha256: impl Into<String>,
        dependencies: Vec<String>,
    ) -> Result<Self, MigrationJournalError> {
        let mut value = Self {
            object_id: object_id.into(),
            class,
            source_path: source_path.into(),
            source_sha256: source_sha256.into(),
            expected_target_sha256: expected_target_sha256.into(),
            dependencies,
        };
        value.dependencies.sort();
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), MigrationJournalError> {
        validate_id(&self.object_id, "object_id")?;
        CanonicalPath::parse(self.source_path.clone())
            .map_err(|_| MigrationJournalError::InvalidSourcePath)?;
        validate_sha256(&self.source_sha256)?;
        validate_sha256(&self.expected_target_sha256)?;
        if self.dependencies.len() > MAX_DEPENDENCIES {
            return Err(MigrationJournalError::TooManyDependencies);
        }
        for dependency in &self.dependencies {
            validate_id(dependency, "dependency")?;
            if dependency == &self.object_id {
                return Err(MigrationJournalError::InvalidDependency);
            }
        }
        if self
            .dependencies
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return Err(MigrationJournalError::InvalidDependency);
        }
        Ok(())
    }
}

/// Canonically sorted, dependency-closed migration inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MigrationInventory {
    objects: Vec<MigrationObject>,
    sha256: String,
}

impl MigrationInventory {
    pub fn new(mut objects: Vec<MigrationObject>) -> Result<Self, MigrationJournalError> {
        if objects.is_empty() || objects.len() > MAX_OBJECTS {
            return Err(MigrationJournalError::InvalidObjectCount);
        }
        for object in &objects {
            object.validate()?;
        }
        objects.sort_by(|left, right| left.object_id.cmp(&right.object_id));
        if objects
            .windows(2)
            .any(|pair| pair[0].object_id == pair[1].object_id)
        {
            return Err(MigrationJournalError::DuplicateObject);
        }
        let identifiers: BTreeSet<&str> = objects
            .iter()
            .map(|object| object.object_id.as_str())
            .collect();
        for object in &objects {
            if object
                .dependencies
                .iter()
                .any(|dependency| !identifiers.contains(dependency.as_str()))
            {
                return Err(MigrationJournalError::UnknownDependency);
            }
        }
        validate_dependency_graph(&objects)?;
        let sha256 = sha256_json(&objects)?;
        Ok(Self { objects, sha256 })
    }

    fn validate(&self) -> Result<(), MigrationJournalError> {
        if self.objects.is_empty() || self.objects.len() > MAX_OBJECTS {
            return Err(MigrationJournalError::InvalidObjectCount);
        }
        if self
            .objects
            .windows(2)
            .any(|pair| pair[0].object_id.as_str() >= pair[1].object_id.as_str())
        {
            return Err(MigrationJournalError::DuplicateObject);
        }
        for object in &self.objects {
            object.validate()?;
        }
        let identifiers: BTreeSet<&str> = self
            .objects
            .iter()
            .map(|object| object.object_id.as_str())
            .collect();
        if self.objects.iter().any(|object| {
            object
                .dependencies
                .iter()
                .any(|dependency| !identifiers.contains(dependency.as_str()))
        }) {
            return Err(MigrationJournalError::UnknownDependency);
        }
        validate_dependency_graph(&self.objects)?;
        if sha256_json(&self.objects)? != self.sha256 {
            return Err(MigrationJournalError::IntegrityMismatch);
        }
        Ok(())
    }

    pub fn objects(&self) -> &[MigrationObject] {
        &self.objects
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn execution_order(&self) -> Result<Vec<&MigrationObject>, MigrationJournalError> {
        let mut indegree: BTreeMap<&str, usize> = self
            .objects
            .iter()
            .map(|object| (object.object_id.as_str(), object.dependencies.len()))
            .collect();
        let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for object in &self.objects {
            for dependency in &object.dependencies {
                dependents
                    .entry(dependency.as_str())
                    .or_default()
                    .push(object.object_id.as_str());
            }
        }
        let mut ready: BTreeSet<&str> = indegree
            .iter()
            .filter_map(|(identifier, count)| (*count == 0).then_some(*identifier))
            .collect();
        let by_id: BTreeMap<&str, &MigrationObject> = self
            .objects
            .iter()
            .map(|object| (object.object_id.as_str(), object))
            .collect();
        let mut ordered = Vec::with_capacity(self.objects.len());
        while let Some(identifier) = ready.pop_first() {
            let object = by_id
                .get(identifier)
                .copied()
                .ok_or(MigrationJournalError::UnknownObject)?;
            ordered.push(object);
            if let Some(children) = dependents.get(identifier) {
                for child in children {
                    let value = indegree
                        .get_mut(child)
                        .ok_or(MigrationJournalError::UnknownDependency)?;
                    *value = value
                        .checked_sub(1)
                        .ok_or(MigrationJournalError::DependencyCycle)?;
                    if *value == 0 {
                        ready.insert(child);
                    }
                }
            }
        }
        if ordered.len() != self.objects.len() {
            return Err(MigrationJournalError::DependencyCycle);
        }
        Ok(ordered)
    }
}

/// Immutable binding supplied when creating or reopening a journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationBinding {
    pub migration_id: String,
    pub source_id: String,
    pub target_id: String,
    pub profile: String,
    pub inventory_sha256: String,
}

impl MigrationBinding {
    pub fn new(
        migration_id: impl Into<String>,
        source_id: impl Into<String>,
        target_id: impl Into<String>,
        profile: impl Into<String>,
        inventory_sha256: impl Into<String>,
    ) -> Result<Self, MigrationJournalError> {
        let binding = Self {
            migration_id: migration_id.into(),
            source_id: source_id.into(),
            target_id: target_id.into(),
            profile: profile.into(),
            inventory_sha256: inventory_sha256.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), MigrationJournalError> {
        validate_id(&self.migration_id, "migration_id")?;
        validate_id(&self.source_id, "source_id")?;
        validate_id(&self.target_id, "target_id")?;
        if self.source_id == self.target_id {
            return Err(MigrationJournalError::SameEndpoint);
        }
        if self.profile.is_empty()
            || self.profile.len() > MAX_PROFILE_BYTES
            || !self.profile.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(MigrationJournalError::InvalidProfile);
        }
        validate_sha256(&self.inventory_sha256)
    }
}

/// Durable per-object state. `OutcomeUnknownAfterEntry` is reconcile-only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum MigrationObjectState {
    Pending {
        last_operation_id: Option<String>,
        attempts: u32,
    },
    IntentPersisted {
        operation_id: String,
        attempt: u32,
    },
    OutcomeUnknownAfterEntry {
        operation_id: String,
        attempt: u32,
    },
    Verified {
        operation_id: String,
        attempt: u32,
        target_sha256: String,
    },
    FailedClosed {
        operation_id: Option<String>,
        reason_code: String,
    },
}

impl MigrationObjectState {
    pub fn requires_reconciliation(&self) -> bool {
        matches!(self, Self::OutcomeUnknownAfterEntry { .. })
    }
}

/// Persisted journal phase.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableMigrationPhase {
    Planned,
    SourceFenced,
    Copying,
    CutoverReady,
    TargetActive,
    TargetFenced,
    RolledBack,
    FailedClosed,
}

/// Receipt for an externally performed writer-fencing operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterFenceReceipt {
    pub endpoint_id: String,
    pub writer_enabled: bool,
    pub generation: u64,
    pub sha256: String,
}

impl WriterFenceReceipt {
    pub fn new(
        endpoint_id: impl Into<String>,
        writer_enabled: bool,
        generation: u64,
        sha256: impl Into<String>,
    ) -> Result<Self, MigrationJournalError> {
        let receipt = Self {
            endpoint_id: endpoint_id.into(),
            writer_enabled,
            generation,
            sha256: sha256.into(),
        };
        validate_id(&receipt.endpoint_id, "endpoint_id")?;
        if receipt.generation == 0 {
            return Err(MigrationJournalError::InvalidReceipt);
        }
        validate_sha256(&receipt.sha256)?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), MigrationJournalError> {
        validate_id(&self.endpoint_id, "endpoint_id")?;
        if self.generation == 0 {
            return Err(MigrationJournalError::InvalidReceipt);
        }
        validate_sha256(&self.sha256)
    }
}

/// Intent returned only after the journal has durably entered the operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyIntent {
    pub object_id: String,
    pub operation_id: String,
    pub attempt: u32,
    pub source_sha256: String,
    pub expected_target_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    schema: String,
    migration_id: String,
    source_id: String,
    target_id: String,
    profile: String,
    inventory_sha256: String,
    generation: u64,
    phase: DurableMigrationPhase,
    source_writer: bool,
    target_writer: bool,
    source_fence_sha256: Option<String>,
    source_fence_generation: Option<u64>,
    target_activation_sha256: Option<String>,
    target_activation_generation: Option<u64>,
    target_fence_sha256: Option<String>,
    target_fence_generation: Option<u64>,
    source_reactivation_sha256: Option<String>,
    source_reactivation_generation: Option<u64>,
    cutover_anchor_sha256: Option<String>,
    rollback_anchor_sha256: Option<String>,
    objects: BTreeMap<String, MigrationObjectState>,
    used_operation_ids: BTreeSet<String>,
}

impl JournalRecord {
    fn binding(&self) -> MigrationBinding {
        MigrationBinding {
            migration_id: self.migration_id.clone(),
            source_id: self.source_id.clone(),
            target_id: self.target_id.clone(),
            profile: self.profile.clone(),
            inventory_sha256: self.inventory_sha256.clone(),
        }
    }

    fn validate(&self) -> Result<(), MigrationJournalError> {
        if self.schema != JOURNAL_SCHEMA {
            return Err(MigrationJournalError::UnsupportedSchema);
        }
        self.binding().validate()?;
        if self.generation == 0 || self.objects.is_empty() || self.objects.len() > MAX_OBJECTS {
            return Err(MigrationJournalError::InvalidJournal);
        }
        if self.source_writer && self.target_writer {
            return Err(MigrationJournalError::WriterOverlap);
        }
        let phase_writers_valid = match self.phase {
            DurableMigrationPhase::Planned | DurableMigrationPhase::RolledBack => {
                self.source_writer && !self.target_writer
            }
            DurableMigrationPhase::TargetActive => !self.source_writer && self.target_writer,
            DurableMigrationPhase::SourceFenced
            | DurableMigrationPhase::Copying
            | DurableMigrationPhase::CutoverReady
            | DurableMigrationPhase::TargetFenced
            | DurableMigrationPhase::FailedClosed => !self.source_writer && !self.target_writer,
        };
        if !phase_writers_valid {
            return Err(MigrationJournalError::InvalidJournal);
        }
        let source_fenced = self.source_fence_sha256.is_some()
            && self.source_fence_generation.is_some_and(|value| value > 0);
        if self.phase != DurableMigrationPhase::Planned && !source_fenced {
            return Err(MigrationJournalError::InvalidJournal);
        }
        if self.phase == DurableMigrationPhase::TargetActive
            && (self.target_activation_sha256.is_none()
                || self
                    .target_activation_generation
                    .is_none_or(|value| value == 0)
                || self.cutover_anchor_sha256.is_none())
        {
            return Err(MigrationJournalError::InvalidJournal);
        }
        if self.phase == DurableMigrationPhase::TargetFenced
            && (self.target_activation_sha256.is_none()
                || self
                    .target_activation_generation
                    .is_none_or(|value| value == 0)
                || self.cutover_anchor_sha256.is_none()
                || self.target_fence_sha256.is_none()
                || self.target_fence_generation.is_none_or(|value| value == 0))
        {
            return Err(MigrationJournalError::InvalidJournal);
        }
        if self.phase == DurableMigrationPhase::RolledBack
            && (self.source_reactivation_sha256.is_none()
                || self
                    .source_reactivation_generation
                    .is_none_or(|value| value == 0)
                || self.rollback_anchor_sha256.is_none())
        {
            return Err(MigrationJournalError::InvalidJournal);
        }
        for digest in [
            self.source_fence_sha256.as_deref(),
            self.target_activation_sha256.as_deref(),
            self.target_fence_sha256.as_deref(),
            self.source_reactivation_sha256.as_deref(),
            self.cutover_anchor_sha256.as_deref(),
            self.rollback_anchor_sha256.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_sha256(digest)?;
        }
        for (object_id, state) in &self.objects {
            validate_id(object_id, "object_id")?;
            match state {
                MigrationObjectState::Pending {
                    last_operation_id,
                    attempts,
                } => {
                    if let Some(operation_id) = last_operation_id {
                        validate_id(operation_id, "operation_id")?;
                        if *attempts == 0 || !self.used_operation_ids.contains(operation_id) {
                            return Err(MigrationJournalError::InvalidJournal);
                        }
                    } else if *attempts != 0 {
                        return Err(MigrationJournalError::InvalidJournal);
                    }
                }
                MigrationObjectState::IntentPersisted {
                    operation_id,
                    attempt,
                }
                | MigrationObjectState::OutcomeUnknownAfterEntry {
                    operation_id,
                    attempt,
                } => {
                    validate_id(operation_id, "operation_id")?;
                    if *attempt == 0 || !self.used_operation_ids.contains(operation_id) {
                        return Err(MigrationJournalError::InvalidJournal);
                    }
                }
                MigrationObjectState::Verified {
                    operation_id,
                    attempt,
                    target_sha256,
                } => {
                    validate_id(operation_id, "operation_id")?;
                    validate_sha256(target_sha256)?;
                    if *attempt == 0 || !self.used_operation_ids.contains(operation_id) {
                        return Err(MigrationJournalError::InvalidJournal);
                    }
                }
                MigrationObjectState::FailedClosed {
                    operation_id,
                    reason_code,
                } => {
                    if let Some(operation_id) = operation_id {
                        validate_id(operation_id, "operation_id")?;
                    }
                    validate_reason_code(reason_code)?;
                }
            }
        }
        let all_pending_initial = self.objects.values().all(|state| {
            matches!(
                state,
                MigrationObjectState::Pending {
                    last_operation_id: None,
                    attempts: 0
                }
            )
        });
        let all_verified = self
            .objects
            .values()
            .all(|state| matches!(state, MigrationObjectState::Verified { .. }));
        let no_unresolved = self.objects.values().all(|state| {
            !matches!(
                state,
                MigrationObjectState::IntentPersisted { .. }
                    | MigrationObjectState::OutcomeUnknownAfterEntry { .. }
            )
        });
        if (self.phase == DurableMigrationPhase::Planned && !all_pending_initial)
            || (matches!(
                self.phase,
                DurableMigrationPhase::CutoverReady
                    | DurableMigrationPhase::TargetActive
                    | DurableMigrationPhase::TargetFenced
            ) && !all_verified)
            || (self.phase == DurableMigrationPhase::RolledBack && !no_unresolved)
            || (self.phase == DurableMigrationPhase::FailedClosed
                && !self
                    .objects
                    .values()
                    .any(|state| matches!(state, MigrationObjectState::FailedClosed { .. })))
        {
            return Err(MigrationJournalError::InvalidJournal);
        }
        for operation_id in &self.used_operation_ids {
            validate_id(operation_id, "operation_id")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    schema: String,
    payload_sha256: String,
    payload: JournalRecord,
}

impl JournalEnvelope {
    fn new(payload: JournalRecord) -> Result<Self, MigrationJournalError> {
        let payload_sha256 = sha256_json(&payload)?;
        Ok(Self {
            schema: ENVELOPE_SCHEMA.to_owned(),
            payload_sha256,
            payload,
        })
    }

    fn validate(self) -> Result<JournalRecord, MigrationJournalError> {
        if self.schema != ENVELOPE_SCHEMA {
            return Err(MigrationJournalError::UnsupportedSchema);
        }
        validate_sha256(&self.payload_sha256)?;
        if sha256_json(&self.payload)? != self.payload_sha256 {
            return Err(MigrationJournalError::IntegrityMismatch);
        }
        self.payload.validate()?;
        Ok(self.payload)
    }
}

/// One process-exclusive, descriptor-anchored migration journal.
pub struct DurableMigrationJournal {
    root: ExclusiveDirectory,
    inventory: MigrationInventory,
    record: JournalRecord,
    recovered_from_previous: bool,
    authentication: JournalAuthentication,
}

impl fmt::Debug for DurableMigrationJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableMigrationJournal")
            .field("root", &self.root)
            .field("migration_id", &self.record.migration_id)
            .field("generation", &self.record.generation)
            .field("phase", &self.record.phase)
            .field("authentication_key_id", &self.authentication.key_id())
            .field("recovered_from_previous", &self.recovered_from_previous)
            .finish_non_exhaustive()
    }
}

impl DurableMigrationJournal {
    /// Compatibility entry point for the original unkeyed v1 checksum profile.
    /// Use `create_authenticated` when malicious checkpoint rewriting is in scope.
    pub fn create_new(
        root: impl AsRef<Path>,
        binding: MigrationBinding,
        inventory: MigrationInventory,
    ) -> Result<Self, MigrationJournalError> {
        Self::create_legacy_checksum(root, binding, inventory)
    }

    /// Explicit legacy v1 creation; SHA-256 is a checksum, not authentication.
    pub fn create_legacy_checksum(
        root: impl AsRef<Path>,
        binding: MigrationBinding,
        inventory: MigrationInventory,
    ) -> Result<Self, MigrationJournalError> {
        Self::create_with_authentication(
            root,
            binding,
            inventory,
            JournalAuthentication::LegacyChecksum,
        )
    }

    /// Create a new v2 journal authenticated with an externally supplied key.
    /// Existing v1/v2 files are never overwritten or implicitly migrated.
    pub fn create_authenticated(
        root: impl AsRef<Path>,
        binding: MigrationBinding,
        inventory: MigrationInventory,
        authenticator: MigrationJournalAuthenticator,
    ) -> Result<Self, MigrationJournalError> {
        Self::create_with_authentication(
            root,
            binding,
            inventory,
            JournalAuthentication::Authenticated(authenticator),
        )
    }

    fn create_with_authentication(
        root: impl AsRef<Path>,
        binding: MigrationBinding,
        inventory: MigrationInventory,
        authentication: JournalAuthentication,
    ) -> Result<Self, MigrationJournalError> {
        binding.validate()?;
        inventory.validate()?;
        if binding.inventory_sha256 != inventory.sha256 {
            return Err(MigrationJournalError::BindingMismatch);
        }
        let root = ExclusiveDirectory::open(root).map_err(map_guard_error)?;
        ensure_absent(&root, CURRENT_FILE)?;
        ensure_absent(&root, PREVIOUS_FILE)?;
        let objects = inventory
            .objects
            .iter()
            .map(|object| {
                (
                    object.object_id.clone(),
                    MigrationObjectState::Pending {
                        last_operation_id: None,
                        attempts: 0,
                    },
                )
            })
            .collect();
        let record = JournalRecord {
            schema: JOURNAL_SCHEMA.to_owned(),
            migration_id: binding.migration_id,
            source_id: binding.source_id,
            target_id: binding.target_id,
            profile: binding.profile,
            inventory_sha256: binding.inventory_sha256,
            generation: 1,
            phase: DurableMigrationPhase::Planned,
            source_writer: true,
            target_writer: false,
            source_fence_sha256: None,
            source_fence_generation: None,
            target_activation_sha256: None,
            target_activation_generation: None,
            target_fence_sha256: None,
            target_fence_generation: None,
            source_reactivation_sha256: None,
            source_reactivation_generation: None,
            cutover_anchor_sha256: None,
            rollback_anchor_sha256: None,
            objects,
            used_operation_ids: BTreeSet::new(),
        };
        record.validate()?;
        Self::validate_record_against_inventory(&record, &inventory)?;
        persist_initial(&root, &record, &authentication)?;
        Ok(Self {
            root,
            inventory,
            record,
            recovered_from_previous: false,
            authentication,
        })
    }

    /// Compatibility entry point for reopening only the legacy v1 checksum profile.
    pub fn open(
        root: impl AsRef<Path>,
        expected: &MigrationBinding,
        inventory: MigrationInventory,
    ) -> Result<Self, MigrationJournalError> {
        Self::open_legacy_checksum(root, expected, inventory)
    }

    /// Reopen a legacy v1 checkpoint. Authenticated v2 files are rejected.
    pub fn open_legacy_checksum(
        root: impl AsRef<Path>,
        expected: &MigrationBinding,
        inventory: MigrationInventory,
    ) -> Result<Self, MigrationJournalError> {
        Self::open_with_authentication(
            root,
            expected,
            inventory,
            JournalAuthentication::LegacyChecksum,
        )
    }

    /// Reopen v2 only. Both current and previous generations must authenticate;
    /// this operation never falls back to an unkeyed checkpoint or a different key.
    pub fn open_authenticated(
        root: impl AsRef<Path>,
        expected: &MigrationBinding,
        inventory: MigrationInventory,
        authenticator: MigrationJournalAuthenticator,
    ) -> Result<Self, MigrationJournalError> {
        Self::open_with_authentication(
            root,
            expected,
            inventory,
            JournalAuthentication::Authenticated(authenticator),
        )
    }

    fn open_with_authentication(
        root: impl AsRef<Path>,
        expected: &MigrationBinding,
        inventory: MigrationInventory,
        authentication: JournalAuthentication,
    ) -> Result<Self, MigrationJournalError> {
        expected.validate()?;
        inventory.validate()?;
        if expected.inventory_sha256 != inventory.sha256 {
            return Err(MigrationJournalError::BindingMismatch);
        }
        let root = ExclusiveDirectory::open(root).map_err(map_guard_error)?;
        let current = load_optional(&root, CURRENT_FILE, &authentication)?;
        let previous = load_optional(&root, PREVIOUS_FILE, &authentication)?;
        let (record, recovered_from_previous) = select_generation(current, previous)?;
        if record.binding() != *expected {
            return Err(MigrationJournalError::BindingMismatch);
        }
        record.validate()?;
        Self::validate_record_against_inventory(&record, &inventory)?;
        Ok(Self {
            root,
            inventory,
            record,
            recovered_from_previous,
            authentication,
        })
    }

    /// `None` identifies the legacy checksum profile; no secret key is returned.
    pub fn authentication_key_id(&self) -> Option<&str> {
        self.authentication.key_id()
    }

    pub fn binding(&self) -> MigrationBinding {
        self.record.binding()
    }

    pub const fn generation(&self) -> u64 {
        self.record.generation
    }

    pub const fn phase(&self) -> DurableMigrationPhase {
        self.record.phase
    }

    pub const fn source_writer_enabled(&self) -> bool {
        self.record.source_writer
    }

    pub const fn target_writer_enabled(&self) -> bool {
        self.record.target_writer
    }

    pub const fn recovered_from_previous(&self) -> bool {
        self.recovered_from_previous
    }

    pub fn object_state(&self, object_id: &str) -> Option<&MigrationObjectState> {
        self.record.objects.get(object_id)
    }

    pub fn pending_reconciliation(&self) -> Vec<&str> {
        self.record
            .objects
            .iter()
            .filter_map(|(identifier, state)| {
                state
                    .requires_reconciliation()
                    .then_some(identifier.as_str())
            })
            .collect()
    }

    pub fn fence_source(
        &mut self,
        receipt: &WriterFenceReceipt,
    ) -> Result<(), MigrationJournalError> {
        receipt.validate()?;
        if self.record.phase != DurableMigrationPhase::Planned
            || receipt.endpoint_id != self.record.source_id
            || receipt.writer_enabled
        {
            return Err(MigrationJournalError::InvalidTransition);
        }
        let mut candidate = self.record.clone();
        candidate.source_writer = false;
        candidate.source_fence_sha256 = Some(receipt.sha256.clone());
        candidate.source_fence_generation = Some(receipt.generation);
        candidate.phase = DurableMigrationPhase::SourceFenced;
        self.commit(candidate)
    }

    pub fn begin_object(
        &mut self,
        object_id: &str,
        operation_id: &str,
    ) -> Result<CopyIntent, MigrationJournalError> {
        if !matches!(
            self.record.phase,
            DurableMigrationPhase::SourceFenced | DurableMigrationPhase::Copying
        ) || self.record.source_writer
            || self.record.target_writer
        {
            return Err(MigrationJournalError::InvalidTransition);
        }
        validate_id(operation_id, "operation_id")?;
        let object = self
            .inventory
            .objects
            .iter()
            .find(|object| object.object_id == object_id)
            .ok_or(MigrationJournalError::UnknownObject)?;
        let intent_object_id = object.object_id.clone();
        let intent_source_sha256 = object.source_sha256.clone();
        let intent_target_sha256 = object.expected_target_sha256.clone();
        if self.record.used_operation_ids.contains(operation_id) {
            return Err(MigrationJournalError::DuplicateOperation);
        }
        for dependency in &object.dependencies {
            if !matches!(
                self.record.objects.get(dependency),
                Some(MigrationObjectState::Verified { .. })
            ) {
                return Err(MigrationJournalError::DependencyNotVerified);
            }
        }
        let previous_attempt = match self.record.objects.get(object_id) {
            Some(MigrationObjectState::Pending { attempts, .. }) => *attempts,
            Some(MigrationObjectState::FailedClosed { .. }) => {
                return Err(MigrationJournalError::FailedClosed);
            }
            Some(_) => return Err(MigrationJournalError::ReconciliationRequired),
            None => return Err(MigrationJournalError::UnknownObject),
        };
        let attempt = previous_attempt
            .checked_add(1)
            .ok_or(MigrationJournalError::GenerationOverflow)?;
        let mut candidate = self.record.clone();
        candidate.phase = DurableMigrationPhase::Copying;
        candidate.used_operation_ids.insert(operation_id.to_owned());
        candidate.objects.insert(
            object_id.to_owned(),
            MigrationObjectState::IntentPersisted {
                operation_id: operation_id.to_owned(),
                attempt,
            },
        );
        self.commit(candidate)?;
        Ok(CopyIntent {
            object_id: intent_object_id,
            operation_id: operation_id.to_owned(),
            attempt,
            source_sha256: intent_source_sha256,
            expected_target_sha256: intent_target_sha256,
        })
    }

    pub fn mark_outcome_unknown(
        &mut self,
        object_id: &str,
        operation_id: &str,
    ) -> Result<(), MigrationJournalError> {
        if self.record.phase != DurableMigrationPhase::Copying {
            return Err(MigrationJournalError::InvalidTransition);
        }
        let attempt = match self.record.objects.get(object_id) {
            Some(MigrationObjectState::IntentPersisted {
                operation_id: observed,
                attempt,
            }) if observed == operation_id => *attempt,
            Some(MigrationObjectState::OutcomeUnknownAfterEntry { .. }) => {
                return Err(MigrationJournalError::ReconciliationRequired);
            }
            _ => return Err(MigrationJournalError::InvalidTransition),
        };
        let mut candidate = self.record.clone();
        candidate.objects.insert(
            object_id.to_owned(),
            MigrationObjectState::OutcomeUnknownAfterEntry {
                operation_id: operation_id.to_owned(),
                attempt,
            },
        );
        self.commit(candidate)
    }

    pub fn confirm_committed(
        &mut self,
        object_id: &str,
        operation_id: &str,
        target_sha256: &str,
    ) -> Result<(), MigrationJournalError> {
        if self.record.phase != DurableMigrationPhase::Copying {
            return Err(MigrationJournalError::InvalidTransition);
        }
        validate_sha256(target_sha256)?;
        let object = self
            .inventory
            .objects
            .iter()
            .find(|object| object.object_id == object_id)
            .ok_or(MigrationJournalError::UnknownObject)?;
        if object.expected_target_sha256 != target_sha256 {
            return Err(MigrationJournalError::TargetDigestMismatch);
        }
        let attempt = active_attempt(self.record.objects.get(object_id), operation_id)?;
        let mut candidate = self.record.clone();
        candidate.objects.insert(
            object_id.to_owned(),
            MigrationObjectState::Verified {
                operation_id: operation_id.to_owned(),
                attempt,
                target_sha256: target_sha256.to_owned(),
            },
        );
        self.commit(candidate)
    }

    pub fn confirm_not_committed(
        &mut self,
        object_id: &str,
        operation_id: &str,
    ) -> Result<(), MigrationJournalError> {
        if self.record.phase != DurableMigrationPhase::Copying {
            return Err(MigrationJournalError::InvalidTransition);
        }
        let active_attempt_value = match self.record.objects.get(object_id) {
            Some(MigrationObjectState::OutcomeUnknownAfterEntry {
                operation_id: observed,
                attempt,
            }) if observed == operation_id => *attempt,
            _ => return Err(MigrationJournalError::InvalidTransition),
        };
        let mut candidate = self.record.clone();
        candidate.objects.insert(
            object_id.to_owned(),
            MigrationObjectState::Pending {
                last_operation_id: Some(operation_id.to_owned()),
                attempts: active_attempt_value,
            },
        );
        self.commit(candidate)
    }

    pub fn fail_object(
        &mut self,
        object_id: &str,
        reason_code: &str,
    ) -> Result<(), MigrationJournalError> {
        validate_reason_code(reason_code)?;
        if matches!(
            self.record.phase,
            DurableMigrationPhase::Planned
                | DurableMigrationPhase::TargetActive
                | DurableMigrationPhase::TargetFenced
                | DurableMigrationPhase::RolledBack
                | DurableMigrationPhase::FailedClosed
        ) {
            return Err(MigrationJournalError::InvalidTransition);
        }
        let operation_id = match self.record.objects.get(object_id) {
            Some(MigrationObjectState::IntentPersisted { operation_id, .. })
            | Some(MigrationObjectState::OutcomeUnknownAfterEntry { operation_id, .. }) => {
                Some(operation_id.clone())
            }
            Some(MigrationObjectState::Pending { .. }) => None,
            Some(MigrationObjectState::Verified { .. }) => {
                return Err(MigrationJournalError::InvalidTransition);
            }
            Some(MigrationObjectState::FailedClosed { .. }) => {
                return Err(MigrationJournalError::FailedClosed);
            }
            None => return Err(MigrationJournalError::UnknownObject),
        };
        let mut candidate = self.record.clone();
        candidate.objects.insert(
            object_id.to_owned(),
            MigrationObjectState::FailedClosed {
                operation_id,
                reason_code: reason_code.to_owned(),
            },
        );
        candidate.phase = DurableMigrationPhase::FailedClosed;
        candidate.source_writer = false;
        candidate.target_writer = false;
        self.commit(candidate)
    }

    pub fn verify_copy(&mut self) -> Result<(), MigrationJournalError> {
        if self.record.phase != DurableMigrationPhase::Copying
            || self.record.source_writer
            || self.record.target_writer
            || self
                .record
                .objects
                .values()
                .any(|state| !matches!(state, MigrationObjectState::Verified { .. }))
        {
            return Err(MigrationJournalError::InvalidTransition);
        }
        let mut candidate = self.record.clone();
        candidate.phase = DurableMigrationPhase::CutoverReady;
        self.commit(candidate)
    }

    pub fn activate_target(
        &mut self,
        receipt: &WriterFenceReceipt,
        anchor_sha256: &str,
    ) -> Result<(), MigrationJournalError> {
        receipt.validate()?;
        validate_sha256(anchor_sha256)?;
        if self.record.phase != DurableMigrationPhase::CutoverReady
            || self.record.source_writer
            || self.record.target_writer
            || receipt.endpoint_id != self.record.target_id
            || !receipt.writer_enabled
        {
            return Err(MigrationJournalError::InvalidTransition);
        }
        let mut candidate = self.record.clone();
        candidate.target_writer = true;
        candidate.target_activation_sha256 = Some(receipt.sha256.clone());
        candidate.target_activation_generation = Some(receipt.generation);
        candidate.cutover_anchor_sha256 = Some(anchor_sha256.to_owned());
        candidate.phase = DurableMigrationPhase::TargetActive;
        self.commit(candidate)
    }

    pub fn fence_target(
        &mut self,
        receipt: &WriterFenceReceipt,
    ) -> Result<(), MigrationJournalError> {
        receipt.validate()?;
        if self.record.phase != DurableMigrationPhase::TargetActive
            || receipt.endpoint_id != self.record.target_id
            || receipt.writer_enabled
            || self
                .record
                .target_activation_generation
                .is_none_or(|generation| receipt.generation <= generation)
        {
            return Err(MigrationJournalError::InvalidTransition);
        }
        let mut candidate = self.record.clone();
        candidate.target_writer = false;
        candidate.target_fence_sha256 = Some(receipt.sha256.clone());
        candidate.target_fence_generation = Some(receipt.generation);
        candidate.phase = DurableMigrationPhase::TargetFenced;
        self.commit(candidate)
    }

    pub fn rollback(
        &mut self,
        receipt: &WriterFenceReceipt,
        anchor_sha256: &str,
    ) -> Result<(), MigrationJournalError> {
        receipt.validate()?;
        validate_sha256(anchor_sha256)?;
        if !matches!(
            self.record.phase,
            DurableMigrationPhase::SourceFenced
                | DurableMigrationPhase::Copying
                | DurableMigrationPhase::CutoverReady
                | DurableMigrationPhase::TargetFenced
        ) || self.record.target_writer
            || receipt.endpoint_id != self.record.source_id
            || !receipt.writer_enabled
            || self
                .record
                .source_fence_generation
                .is_none_or(|generation| receipt.generation <= generation)
        {
            return Err(MigrationJournalError::InvalidTransition);
        }
        if self.record.objects.values().any(|state| {
            matches!(
                state,
                MigrationObjectState::IntentPersisted { .. }
                    | MigrationObjectState::OutcomeUnknownAfterEntry { .. }
            )
        }) {
            return Err(MigrationJournalError::ReconciliationRequired);
        }
        let mut candidate = self.record.clone();
        candidate.source_writer = true;
        candidate.source_reactivation_sha256 = Some(receipt.sha256.clone());
        candidate.source_reactivation_generation = Some(receipt.generation);
        candidate.rollback_anchor_sha256 = Some(anchor_sha256.to_owned());
        candidate.phase = DurableMigrationPhase::RolledBack;
        self.commit(candidate)
    }

    fn validate_record_against_inventory(
        record: &JournalRecord,
        inventory: &MigrationInventory,
    ) -> Result<(), MigrationJournalError> {
        let expected: BTreeMap<&str, &MigrationObject> = inventory
            .objects
            .iter()
            .map(|object| (object.object_id.as_str(), object))
            .collect();
        if expected.len() != record.objects.len() {
            return Err(MigrationJournalError::BindingMismatch);
        }
        for (object_id, state) in &record.objects {
            let object = expected
                .get(object_id.as_str())
                .copied()
                .ok_or(MigrationJournalError::BindingMismatch)?;
            if let MigrationObjectState::Verified { target_sha256, .. } = state
                && target_sha256 != &object.expected_target_sha256
            {
                return Err(MigrationJournalError::TargetDigestMismatch);
            }
        }
        Ok(())
    }

    fn commit(&mut self, mut candidate: JournalRecord) -> Result<(), MigrationJournalError> {
        candidate.generation = self
            .record
            .generation
            .checked_add(1)
            .ok_or(MigrationJournalError::GenerationOverflow)?;
        candidate.validate()?;
        Self::validate_record_against_inventory(&candidate, &self.inventory)?;
        persist_replace(&self.root, &candidate, &self.authentication)?;
        self.record = candidate;
        self.recovered_from_previous = false;
        Ok(())
    }
}

/// Journal validation and transition failures.
#[derive(Debug)]
pub enum MigrationJournalError {
    SameEndpoint,
    InvalidIdentifier,
    InvalidSourcePath,
    InvalidDigest,
    InvalidProfile,
    InvalidReceipt,
    InvalidReasonCode,
    InvalidObjectCount,
    TooManyDependencies,
    DuplicateObject,
    InvalidDependency,
    UnknownDependency,
    DependencyCycle,
    DependencyNotVerified,
    UnknownObject,
    DuplicateOperation,
    ReconciliationRequired,
    TargetDigestMismatch,
    InvalidTransition,
    WriterOverlap,
    FailedClosed,
    BindingMismatch,
    UnsupportedSchema,
    IntegrityMismatch,
    InvalidAuthenticationKey,
    AuthenticationFailed,
    InvalidJournal,
    JournalMissing,
    AmbiguousGeneration,
    GenerationOverflow,
    UnsupportedPlatform,
    UnsafeRoot,
    WriterBusy,
    Io(io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for MigrationJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SameEndpoint => "migration source and target are identical",
            Self::InvalidIdentifier => "migration identifier is invalid",
            Self::InvalidSourcePath => "migration source path is invalid",
            Self::InvalidDigest => "migration SHA-256 value is invalid",
            Self::InvalidProfile => "migration profile is invalid",
            Self::InvalidReceipt => "writer fence receipt is invalid",
            Self::InvalidReasonCode => "migration failure reason code is invalid",
            Self::InvalidObjectCount => "migration inventory object count is invalid",
            Self::TooManyDependencies => "migration object dependency count is too large",
            Self::DuplicateObject => "migration inventory contains a duplicate object",
            Self::InvalidDependency => "migration object dependency is invalid",
            Self::UnknownDependency => "migration object dependency is absent",
            Self::DependencyCycle => "migration inventory dependency graph contains a cycle",
            Self::DependencyNotVerified => "migration dependency is not verified",
            Self::UnknownObject => "migration object is unknown",
            Self::DuplicateOperation => "migration operation identifier has already been used",
            Self::ReconciliationRequired => {
                "migration outcome requires authoritative reconciliation"
            }
            Self::TargetDigestMismatch => "migrated target digest does not match the inventory",
            Self::InvalidTransition => "migration journal transition is invalid",
            Self::WriterOverlap => "source and target writer authority overlap",
            Self::FailedClosed => "migration journal is failed closed",
            Self::BindingMismatch => "migration journal binding does not match the expected source",
            Self::UnsupportedSchema => "migration journal schema is unsupported",
            Self::IntegrityMismatch => "migration journal integrity digest does not match",
            Self::InvalidAuthenticationKey => "migration journal authentication key is invalid",
            Self::AuthenticationFailed => {
                "migration journal authentication failed or profile is incompatible"
            }
            Self::InvalidJournal => "migration journal state is invalid",
            Self::JournalMissing => "migration journal has no valid generation",
            Self::AmbiguousGeneration => "migration journal generations conflict",
            Self::GenerationOverflow => "migration journal generation overflowed",
            Self::UnsupportedPlatform => {
                "durable migration journal is unsupported on this platform"
            }
            Self::UnsafeRoot => "durable migration root is unsafe or changed",
            Self::WriterBusy => "another process owns the migration journal writer fence",
            Self::Io(_) => "migration journal I/O failed",
            Self::Json(_) => "migration journal JSON is invalid",
        })
    }
}

impl Error for MigrationJournalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for MigrationJournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for MigrationJournalError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

fn validate_dependency_graph(objects: &[MigrationObject]) -> Result<(), MigrationJournalError> {
    let provisional = MigrationInventory {
        objects: objects.to_vec(),
        sha256: String::new(),
    };
    provisional.execution_order().map(|_| ())
}

fn active_attempt(
    state: Option<&MigrationObjectState>,
    operation_id: &str,
) -> Result<u32, MigrationJournalError> {
    match state {
        Some(MigrationObjectState::IntentPersisted {
            operation_id: observed,
            attempt,
        })
        | Some(MigrationObjectState::OutcomeUnknownAfterEntry {
            operation_id: observed,
            attempt,
        }) if observed == operation_id => Ok(*attempt),
        Some(MigrationObjectState::OutcomeUnknownAfterEntry { .. }) => {
            Err(MigrationJournalError::ReconciliationRequired)
        }
        _ => Err(MigrationJournalError::InvalidTransition),
    }
}

fn validate_id(value: &str, _field: &str) -> Result<(), MigrationJournalError> {
    Id::parse(value.to_owned())
        .map(|_| ())
        .map_err(|_| MigrationJournalError::InvalidIdentifier)
}

fn validate_sha256(value: &str) -> Result<(), MigrationJournalError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(MigrationJournalError::InvalidDigest)
    }
}

fn validate_reason_code(value: &str) -> Result<(), MigrationJournalError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        Err(MigrationJournalError::InvalidReasonCode)
    } else {
        Ok(())
    }
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String, MigrationJournalError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn map_guard_error(error: DirectoryGuardError) -> MigrationJournalError {
    match error {
        DirectoryGuardError::UnsupportedPlatform => MigrationJournalError::UnsupportedPlatform,
        DirectoryGuardError::WriterBusy => MigrationJournalError::WriterBusy,
        DirectoryGuardError::RootMustBeAbsolute
        | DirectoryGuardError::UnsafeRoot
        | DirectoryGuardError::RootIdentityChanged
        | DirectoryGuardError::DescriptorPathUnavailable
        | DirectoryGuardError::InvalidLeafName => MigrationJournalError::UnsafeRoot,
        DirectoryGuardError::Io(error) => MigrationJournalError::Io(error),
    }
}

fn ensure_absent(root: &ExclusiveDirectory, name: &str) -> Result<(), MigrationJournalError> {
    let path = root.leaf_path(name).map_err(map_guard_error)?;
    match fs::symlink_metadata(path) {
        Ok(_) => Err(MigrationJournalError::InvalidTransition),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(MigrationJournalError::Io(error)),
    }
}

fn secure_create_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

fn secure_open_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

fn persist_initial(
    root: &ExclusiveDirectory,
    record: &JournalRecord,
    authentication: &JournalAuthentication,
) -> Result<(), MigrationJournalError> {
    root.verify().map_err(map_guard_error)?;
    let current = root.leaf_path(CURRENT_FILE).map_err(map_guard_error)?;
    let bytes = authentication.encode(record)?;
    write_new(&current, &bytes)?;
    root.sync_all().map_err(map_guard_error)
}

fn persist_replace(
    root: &ExclusiveDirectory,
    record: &JournalRecord,
    authentication: &JournalAuthentication,
) -> Result<(), MigrationJournalError> {
    root.verify().map_err(map_guard_error)?;
    let current = root.leaf_path(CURRENT_FILE).map_err(map_guard_error)?;
    let previous = root.leaf_path(PREVIOUS_FILE).map_err(map_guard_error)?;
    reject_symlink_or_non_regular_if_present(&current)?;
    reject_symlink_or_non_regular_if_present(&previous)?;
    let temporary_name = format!("migration-state.{}.tmp", record.generation);
    let temporary = root.leaf_path(&temporary_name).map_err(map_guard_error)?;
    let bytes = authentication.encode(record)?;
    write_new(&temporary, &bytes)?;
    if current.exists() {
        if previous.exists() {
            fs::remove_file(&previous)?;
            root.sync_all().map_err(map_guard_error)?;
        }
        fs::rename(&current, &previous)?;
        root.sync_all().map_err(map_guard_error)?;
    }
    if let Err(error) = fs::rename(&temporary, &current) {
        if previous.exists() && !current.exists() {
            let _ = fs::rename(&previous, &current);
            let _ = root.sync_all();
        }
        return Err(MigrationJournalError::Io(error));
    }
    root.sync_all().map_err(map_guard_error)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), MigrationJournalError> {
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_JOURNAL_BYTES {
        return Err(MigrationJournalError::InvalidJournal);
    }
    let mut file = secure_create_new(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn reject_symlink_or_non_regular_if_present(path: &Path) -> Result<(), MigrationJournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(MigrationJournalError::UnsafeRoot)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(MigrationJournalError::Io(error)),
    }
}

fn load_optional(
    root: &ExclusiveDirectory,
    name: &str,
    authentication: &JournalAuthentication,
) -> Result<Option<JournalRecord>, MigrationJournalError> {
    root.verify().map_err(map_guard_error)?;
    let path = root.leaf_path(name).map_err(map_guard_error)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MigrationJournalError::Io(error)),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(MigrationJournalError::UnsafeRoot);
    }
    let file = secure_open_read(&path)?;
    let opened = file.metadata()?;
    if !same_file(&metadata, &opened) {
        return Err(MigrationJournalError::UnsafeRoot);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    let mut limited = file.take(MAX_JOURNAL_BYTES + 1);
    limited.read_to_end(&mut bytes)?;
    let closed = limited.into_inner().metadata()?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != opened.len()
        || !same_file(&opened, &closed)
    {
        return Err(MigrationJournalError::InvalidJournal);
    }
    authentication.decode(&bytes).map(Some)
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    if left.len() != right.len() || !left.is_file() || !right.is_file() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

fn select_generation(
    current: Option<JournalRecord>,
    previous: Option<JournalRecord>,
) -> Result<(JournalRecord, bool), MigrationJournalError> {
    match (current, previous) {
        (Some(current), Some(previous)) if current.generation > previous.generation => {
            Ok((current, false))
        }
        (Some(current), Some(previous)) if previous.generation > current.generation => {
            Err(MigrationJournalError::AmbiguousGeneration)
        }
        (Some(current), Some(previous)) if current == previous => Ok((current, false)),
        (Some(_), Some(_)) => Err(MigrationJournalError::AmbiguousGeneration),
        (Some(current), None) => Ok((current, false)),
        (None, Some(previous)) => Ok((previous, true)),
        (None, None) => Err(MigrationJournalError::JournalMissing),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug)]
    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Result<Self, Box<dyn Error>> {
            let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "heptabao-migration-{}-{ordinal}",
                std::process::id()
            ));
            match fs::remove_dir_all(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(Box::new(error)),
            }
            fs::create_dir(&path)?;
            let path = fs::canonicalize(path)?;
            Ok(Self { path })
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn inventory() -> Result<MigrationInventory, MigrationJournalError> {
        MigrationInventory::new(vec![
            MigrationObject::new(
                "policy-root",
                MigrationObjectClass::Policy,
                "/sys/policies/root",
                digest('a'),
                digest('b'),
                vec![],
            )?,
            MigrationObject::new(
                "mount-kv",
                MigrationObjectClass::Mount,
                "/sys/mounts/kv",
                digest('c'),
                digest('d'),
                vec!["policy-root".to_owned()],
            )?,
        ])
    }

    fn binding(inventory: &MigrationInventory) -> Result<MigrationBinding, MigrationJournalError> {
        MigrationBinding::new(
            "migration-one",
            "openbao-source",
            "heptabao-target",
            "openbao-2.6.2-complete-v1",
            inventory.sha256(),
        )
    }

    fn source_fence() -> Result<WriterFenceReceipt, MigrationJournalError> {
        WriterFenceReceipt::new("openbao-source", false, 7, digest('e'))
    }

    #[test]
    fn inventory_is_closed_sorted_dependency_checked_and_hashed() -> Result<(), Box<dyn Error>> {
        let inventory = inventory()?;
        assert_eq!("mount-kv", inventory.objects()[0].object_id.as_str());
        assert_eq!(
            "policy-root",
            inventory.execution_order()?[0].object_id.as_str()
        );
        assert_eq!(64, inventory.sha256().len());
        let cycle = MigrationInventory::new(vec![
            MigrationObject::new(
                "a-object",
                MigrationObjectClass::Policy,
                "/a",
                digest('a'),
                digest('b'),
                vec!["b-object".to_owned()],
            )?,
            MigrationObject::new(
                "b-object",
                MigrationObjectClass::Mount,
                "/b",
                digest('c'),
                digest('d'),
                vec!["a-object".to_owned()],
            )?,
        ]);
        assert!(matches!(cycle, Err(MigrationJournalError::DependencyCycle)));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn intent_unknown_and_reconciliation_survive_restart() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let inventory = inventory()?;
        let expected = binding(&inventory)?;
        let mut journal = DurableMigrationJournal::create_new(
            &directory.path,
            expected.clone(),
            inventory.clone(),
        )?;
        journal.fence_source(&source_fence()?)?;
        let intent = journal.begin_object("policy-root", "copy-policy-1")?;
        assert_eq!(1, intent.attempt);
        journal.mark_outcome_unknown("policy-root", "copy-policy-1")?;
        drop(journal);

        let mut reopened =
            DurableMigrationJournal::open(&directory.path, &expected, inventory.clone())?;
        assert_eq!(vec!["policy-root"], reopened.pending_reconciliation());
        assert!(matches!(
            reopened.begin_object("policy-root", "copy-policy-2"),
            Err(MigrationJournalError::ReconciliationRequired)
        ));
        reopened.confirm_not_committed("policy-root", "copy-policy-1")?;
        let next = reopened.begin_object("policy-root", "copy-policy-2")?;
        assert_eq!(2, next.attempt);
        assert!(matches!(
            reopened.begin_object("policy-root", "copy-policy-1"),
            Err(MigrationJournalError::DuplicateOperation)
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cutover_requires_every_digest_and_never_overlaps_writers() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let inventory = inventory()?;
        let expected = binding(&inventory)?;
        let mut journal =
            DurableMigrationJournal::create_new(&directory.path, expected, inventory)?;
        journal.fence_source(&source_fence()?)?;
        journal.begin_object("policy-root", "copy-policy-1")?;
        assert!(matches!(
            journal.confirm_committed("policy-root", "copy-policy-1", &digest('f')),
            Err(MigrationJournalError::TargetDigestMismatch)
        ));
        journal.confirm_committed("policy-root", "copy-policy-1", &digest('b'))?;
        assert!(matches!(
            journal.verify_copy(),
            Err(MigrationJournalError::InvalidTransition)
        ));
        journal.begin_object("mount-kv", "copy-mount-1")?;
        journal.confirm_committed("mount-kv", "copy-mount-1", &digest('d'))?;
        journal.verify_copy()?;
        journal.activate_target(
            &WriterFenceReceipt::new("heptabao-target", true, 8, digest('5'))?,
            &digest('1'),
        )?;
        assert!(!journal.source_writer_enabled());
        assert!(journal.target_writer_enabled());
        assert!(matches!(
            journal.rollback(
                &WriterFenceReceipt::new("openbao-source", true, 10, digest('6'))?,
                &digest('2'),
            ),
            Err(MigrationJournalError::InvalidTransition)
        ));
        journal.fence_target(&WriterFenceReceipt::new(
            "heptabao-target",
            false,
            9,
            digest('3'),
        )?)?;
        journal.rollback(
            &WriterFenceReceipt::new("openbao-source", true, 10, digest('6'))?,
            &digest('4'),
        )?;
        assert!(journal.source_writer_enabled());
        assert!(!journal.target_writer_enabled());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn binding_tampering_and_second_writer_fail_closed() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let inventory = inventory()?;
        let expected = binding(&inventory)?;
        let journal = DurableMigrationJournal::create_new(
            &directory.path,
            expected.clone(),
            inventory.clone(),
        )?;
        assert!(matches!(
            DurableMigrationJournal::open(&directory.path, &expected, inventory.clone()),
            Err(MigrationJournalError::WriterBusy)
        ));
        drop(journal);
        let wrong = MigrationBinding::new(
            "migration-one",
            "different-source",
            "heptabao-target",
            "openbao-2.6.2-complete-v1",
            inventory.sha256(),
        )?;
        assert!(matches!(
            DurableMigrationJournal::open(&directory.path, &wrong, inventory),
            Err(MigrationJournalError::BindingMismatch)
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn previous_generation_is_recovered_but_conflicts_are_rejected() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let inventory = inventory()?;
        let expected = binding(&inventory)?;
        let mut journal = DurableMigrationJournal::create_new(
            &directory.path,
            expected.clone(),
            inventory.clone(),
        )?;
        journal.fence_source(&source_fence()?)?;
        drop(journal);
        let current = directory.path.join(CURRENT_FILE);
        let previous = directory.path.join(PREVIOUS_FILE);
        fs::remove_file(&current)?;
        let recovered =
            DurableMigrationJournal::open(&directory.path, &expected, inventory.clone())?;
        assert!(recovered.recovered_from_previous());
        drop(recovered);

        fs::copy(&previous, &current)?;
        let mut envelope: JournalEnvelope = serde_json::from_slice(&fs::read(&current)?)?;
        envelope.payload.profile = "different-profile".to_owned();
        envelope.payload_sha256 = sha256_json(&envelope.payload)?;
        fs::write(&current, serde_json::to_vec(&envelope)?)?;
        assert!(matches!(
            DurableMigrationJournal::open(&directory.path, &expected, inventory),
            Err(MigrationJournalError::AmbiguousGeneration)
                | Err(MigrationJournalError::BindingMismatch)
        ));
        Ok(())
    }
    fn authenticator() -> Result<MigrationJournalAuthenticator, MigrationJournalError> {
        MigrationJournalAuthenticator::new("migration-test-key", &[7; 32])
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_checkpoint_preserves_reconciliation_and_cutover_after_restart()
    -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let inventory = inventory()?;
        let expected = binding(&inventory)?;
        let mut journal = DurableMigrationJournal::create_authenticated(
            &directory.path,
            expected.clone(),
            inventory.clone(),
            authenticator()?,
        )?;
        assert_eq!(journal.authentication_key_id(), Some("migration-test-key"));
        journal.fence_source(&source_fence()?)?;
        journal.begin_object("policy-root", "copy-policy-1")?;
        journal.mark_outcome_unknown("policy-root", "copy-policy-1")?;
        let generation = journal.generation();
        drop(journal);
        let mut reopened = DurableMigrationJournal::open_authenticated(
            &directory.path,
            &expected,
            inventory.clone(),
            authenticator()?,
        )?;
        assert_eq!(reopened.generation(), generation);
        assert!(matches!(
            reopened.begin_object("policy-root", "copy-policy-2"),
            Err(MigrationJournalError::ReconciliationRequired)
        ));
        assert!(matches!(
            reopened.confirm_committed("policy-root", "copy-policy-1", &digest('f')),
            Err(MigrationJournalError::TargetDigestMismatch)
        ));
        reopened.confirm_committed("policy-root", "copy-policy-1", &digest('b'))?;
        reopened.begin_object("mount-kv", "copy-mount-1")?;
        reopened.confirm_committed("mount-kv", "copy-mount-1", &digest('d'))?;
        reopened.verify_copy()?;
        reopened.activate_target(
            &WriterFenceReceipt::new("heptabao-target", true, 8, digest('5'))?,
            &digest('1'),
        )?;
        assert!(!reopened.source_writer_enabled());
        assert!(reopened.target_writer_enabled());
        drop(reopened);
        let final_state = DurableMigrationJournal::open_authenticated(
            &directory.path,
            &expected,
            inventory,
            authenticator()?,
        )?;
        assert_eq!(final_state.phase(), DurableMigrationPhase::TargetActive);
        let files: Vec<_> = fs::read_dir(&directory.path)?.collect::<Result<Vec<_>, _>>()?;
        assert!(files.iter().all(|entry| {
            [CURRENT_FILE, PREVIOUS_FILE]
                .iter()
                .any(|name| entry.file_name() == *name)
        }));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_checkpoint_rejects_recomputed_checksum_and_wrong_key_without_rewriting()
    -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let inventory = inventory()?;
        let expected = binding(&inventory)?;
        let mut journal = DurableMigrationJournal::create_authenticated(
            &directory.path,
            expected.clone(),
            inventory.clone(),
            authenticator()?,
        )?;
        journal.fence_source(&source_fence()?)?;
        drop(journal);
        let current = directory.path.join(CURRENT_FILE);
        let bytes = fs::read(&current)?;
        for auth in [
            MigrationJournalAuthenticator::new("migration-test-key", &[8; 32])?,
            MigrationJournalAuthenticator::new("different-key-id", &[7; 32])?,
        ] {
            assert!(matches!(
                DurableMigrationJournal::open_authenticated(
                    &directory.path,
                    &expected,
                    inventory.clone(),
                    auth
                ),
                Err(MigrationJournalError::AuthenticationFailed)
            ));
            assert_eq!(fs::read(&current)?, bytes);
        }
        let mut envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
        envelope["unsigned"]["payload"]["generation"] = serde_json::json!(99);
        let record: JournalRecord =
            serde_json::from_value(envelope["unsigned"]["payload"].clone())?;
        record.validate()?;
        envelope["unsigned"]["payload_sha256"] = serde_json::json!(sha256_json(&record)?);
        let forged = serde_json::to_vec(&envelope)?;
        fs::write(&current, &forged)?;
        assert!(matches!(
            DurableMigrationJournal::open_authenticated(
                &directory.path,
                &expected,
                inventory,
                authenticator()?
            ),
            Err(MigrationJournalError::AuthenticationFailed)
        ));
        assert_eq!(fs::read(current)?, forged);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_checkpoint_rejects_legacy_downgrade_in_either_generation()
    -> Result<(), Box<dyn Error>> {
        for target in [CURRENT_FILE, PREVIOUS_FILE] {
            let directory = TestDirectory::new()?;
            let inventory = inventory()?;
            let expected = binding(&inventory)?;
            let mut journal = DurableMigrationJournal::create_authenticated(
                &directory.path,
                expected.clone(),
                inventory.clone(),
                authenticator()?,
            )?;
            journal.fence_source(&source_fence()?)?;
            drop(journal);
            let path = directory.path.join(target);
            let envelope: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
            let record: JournalRecord =
                serde_json::from_value(envelope["unsigned"]["payload"].clone())?;
            let legacy = serde_json::to_vec(&JournalEnvelope::new(record)?)?;
            fs::write(&path, &legacy)?;
            assert!(matches!(
                DurableMigrationJournal::open_authenticated(
                    &directory.path,
                    &expected,
                    inventory,
                    authenticator()?
                ),
                Err(MigrationJournalError::AuthenticationFailed)
            ));
            assert_eq!(fs::read(path)?, legacy);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authentication_profiles_require_explicit_creation_without_implicit_upgrade()
    -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let inventory = inventory()?;
        let expected = binding(&inventory)?;
        let legacy = DurableMigrationJournal::create_legacy_checksum(
            &directory.path,
            expected.clone(),
            inventory.clone(),
        )?;
        assert_eq!(legacy.authentication_key_id(), None);
        drop(legacy);
        let original = fs::read(directory.path.join(CURRENT_FILE))?;
        assert!(matches!(
            DurableMigrationJournal::open_authenticated(
                &directory.path,
                &expected,
                inventory.clone(),
                authenticator()?
            ),
            Err(MigrationJournalError::AuthenticationFailed)
        ));
        assert!(matches!(
            DurableMigrationJournal::create_authenticated(
                &directory.path,
                expected.clone(),
                inventory.clone(),
                authenticator()?
            ),
            Err(MigrationJournalError::InvalidTransition)
        ));
        assert_eq!(fs::read(directory.path.join(CURRENT_FILE))?, original);
        let legacy = DurableMigrationJournal::open_legacy_checksum(
            &directory.path,
            &expected,
            inventory.clone(),
        )?;
        assert_eq!(legacy.authentication_key_id(), None);
        drop(legacy);
        let authenticated_directory = TestDirectory::new()?;
        let authenticated = DurableMigrationJournal::create_authenticated(
            &authenticated_directory.path,
            expected.clone(),
            inventory.clone(),
            authenticator()?,
        )?;
        drop(authenticated);
        assert!(
            DurableMigrationJournal::open_legacy_checksum(
                &authenticated_directory.path,
                &expected,
                inventory
            )
            .is_err()
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_previous_generation_recovery_keeps_binding_and_reconcile_only_state()
    -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let inventory = inventory()?;
        let expected = binding(&inventory)?;
        let mut journal = DurableMigrationJournal::create_authenticated(
            &directory.path,
            expected.clone(),
            inventory.clone(),
            authenticator()?,
        )?;
        journal.fence_source(&source_fence()?)?;
        journal.begin_object("policy-root", "copy-policy-1")?;
        journal.mark_outcome_unknown("policy-root", "copy-policy-1")?;
        drop(journal);
        let current = directory.path.join(CURRENT_FILE);
        fs::remove_file(&current)?;
        let mut recovered = DurableMigrationJournal::open_authenticated(
            &directory.path,
            &expected,
            inventory.clone(),
            authenticator()?,
        )?;
        assert!(recovered.recovered_from_previous());
        assert!(matches!(
            recovered.begin_object("policy-root", "new-attempt"),
            Err(MigrationJournalError::ReconciliationRequired)
        ));
        recovered.confirm_committed("policy-root", "copy-policy-1", &digest('b'))?;
        drop(recovered);
        let wrong = MigrationBinding::new(
            "migration-one",
            "different-source",
            "heptabao-target",
            "openbao-2.6.2-complete-v1",
            inventory.sha256(),
        )?;
        assert!(matches!(
            DurableMigrationJournal::open_authenticated(
                &directory.path,
                &wrong,
                inventory,
                authenticator()?
            ),
            Err(MigrationJournalError::BindingMismatch)
        ));
        Ok(())
    }

    #[test]
    fn authentication_key_validation_and_debug_do_not_expose_key_material()
    -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            MigrationJournalAuthenticator::new("key-one", &[0; 32]),
            Err(MigrationJournalError::InvalidAuthenticationKey)
        ));
        assert!(matches!(
            MigrationJournalAuthenticator::new("key-one", &[7; 31]),
            Err(MigrationJournalError::InvalidAuthenticationKey)
        ));
        let auth = authenticator()?;
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("[7, 7"));
        Ok(())
    }
}
