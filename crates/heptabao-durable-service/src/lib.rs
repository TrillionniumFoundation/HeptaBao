#![forbid(unsafe_code)]

//! Restart-safe single-node mutation runtime for the HeptaBao repository candidate.
//!
//! The runtime accepts only already-authorized mutation envelopes. It binds each
//! request identity to the authenticated principal, namespace, operation, resource,
//! authorization digest, and value digest. Intent, sealed state publication, commit
//! acknowledgement, and the replay ledger have explicit durable ordering.
//!
//! This crate deliberately does not provide a production cryptographic primitive.
//! Callers must supply a [`Barrier`] implementation that provides confidentiality and
//! authenticity for every persisted payload.

use heptabao_filesystem_guard::{DirectoryGuardError, ExclusiveDirectory};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use zeroize::{Zeroize, Zeroizing};

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SNAPSHOT_MAGIC: &[u8; 4] = b"HBS2";
const SNAPSHOT_PLAINTEXT_MAGIC: &[u8; 4] = b"HBP2";
const JOURNAL_MAGIC: &[u8; 4] = b"HBJ2";
const LEDGER_MAGIC: &[u8; 4] = b"HBL2";
const LEDGER_PLAINTEXT_MAGIC: &[u8; 4] = b"HBC2";
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
const BACKUP_MAGIC: &[u8; 4] = b"HBB2";
const BACKUP_VERSION: u16 = 1;
const MAX_BACKUP_BYTES: usize = MAX_FILE_BYTES * 2 + 2 * 1024 * 1024;
const MAX_STRING_BYTES: usize = 4 * 1024;
const MAX_SECRET_BYTES: usize = 1024 * 1024;
const MAX_RECORDS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierError;

impl fmt::Display for BarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("barrier operation failed")
    }
}

impl std::error::Error for BarrierError {}

/// Protection boundary for all state, ledger, and journal payloads.
///
/// `context` is public associated data and must be authenticated by the provider.
/// Implementations must reject modified ciphertext and context mismatches.
pub trait Barrier {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError>;
    fn open(&self, context: &[u8], protected: &[u8]) -> Result<Vec<u8>, BarrierError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ServiceError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            return Err(ServiceError::InvalidSecret);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Secret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PutRequest {
    principal: String,
    namespace: String,
    request_id: String,
    resource: String,
    authorization_digest: [u8; 32],
    value: Secret,
}

impl PutRequest {
    pub fn new(
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        resource: impl Into<String>,
        authorization_digest: [u8; 32],
        value: Secret,
    ) -> Result<Self, ServiceError> {
        let request = Self {
            principal: principal.into(),
            namespace: namespace.into(),
            request_id: request_id.into(),
            resource: resource.into(),
            authorization_digest,
            value,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), ServiceError> {
        validate_identifier(&self.principal)?;
        validate_namespace(&self.namespace)?;
        validate_identifier(&self.request_id)?;
        validate_resource(&self.resource)?;
        if self.authorization_digest == [0; 32] {
            return Err(ServiceError::InvalidAuthorizationDigest);
        }
        Ok(())
    }
}

impl fmt::Debug for PutRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PutRequest")
            .field("principal", &"[REDACTED]")
            .field("namespace", &"[REDACTED]")
            .field("request_id", &"[REDACTED]")
            .field("resource", &"[REDACTED]")
            .field("authorization_digest", &"[REDACTED]")
            .field("value", &self.value)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeleteRequest {
    principal: String,
    namespace: String,
    request_id: String,
    resource: String,
    authorization_digest: [u8; 32],
}

impl DeleteRequest {
    pub fn new(
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        resource: impl Into<String>,
        authorization_digest: [u8; 32],
    ) -> Result<Self, ServiceError> {
        let request = Self {
            principal: principal.into(),
            namespace: namespace.into(),
            request_id: request_id.into(),
            resource: resource.into(),
            authorization_digest,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), ServiceError> {
        validate_identifier(&self.principal)?;
        validate_namespace(&self.namespace)?;
        validate_identifier(&self.request_id)?;
        validate_resource(&self.resource)?;
        if self.authorization_digest == [0; 32] {
            return Err(ServiceError::InvalidAuthorizationDigest);
        }
        Ok(())
    }
}

impl fmt::Debug for DeleteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeleteRequest")
            .field("principal", &"[REDACTED]")
            .field("namespace", &"[REDACTED]")
            .field("request_id", &"[REDACTED]")
            .field("resource", &"[REDACTED]")
            .field("authorization_digest", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failpoint {
    None,
    AfterIntent,
    AfterSnapshotPublication,
    AfterCommitJournal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationOutcome {
    Committed {
        generation: u64,
        recovery_reference: String,
    },
    Duplicate {
        generation: u64,
        recovery_reference: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationStatus {
    Committed { generation: u64 },
    Aborted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionOutcome {
    pub generation: u64,
    pub retained_requests: usize,
    pub journal_bytes_before: usize,
    pub journal_bytes_after: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreOutcome {
    pub previous_generation: u64,
    pub restored_generation: u64,
    pub retained_requests: usize,
}

#[derive(Debug)]
pub enum ServiceError {
    InvalidRoot,
    RootNotEmpty,
    WriterLocked,
    UnsupportedProfile,
    LegacySchema,
    RecoveryRequired,
    JournalCapacityExhausted,
    InvalidIdentifier,
    InvalidNamespace,
    InvalidResource,
    InvalidSecret,
    InvalidAuthorizationDigest,
    RequestBindingConflict,
    RequestCapacityExhausted,
    BackupRollbackRejected,
    GenerationOverflow,
    OutcomeUnknown { recovery_reference: String },
    CorruptState,
    BarrierFailure,
    Io(std::io::Error),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot => formatter.write_str("invalid durable-service root"),
            Self::RootNotEmpty => formatter.write_str("durable-service root is not empty"),
            Self::UnsupportedProfile => {
                formatter.write_str("Linux descriptor-bound storage is required")
            }
            Self::LegacySchema => {
                formatter.write_str("legacy HBS1 state requires an explicit offline migration")
            }
            Self::RecoveryRequired => {
                formatter.write_str("reopen and reconcile before further access")
            }
            Self::JournalCapacityExhausted => {
                formatter.write_str("journal retention limit reached before entry")
            }
            Self::WriterLocked => formatter.write_str("durable-service writer is already active"),
            Self::InvalidIdentifier => formatter.write_str("invalid bounded identifier"),
            Self::InvalidNamespace => formatter.write_str("invalid namespace"),
            Self::InvalidResource => formatter.write_str("invalid canonical resource"),
            Self::InvalidSecret => formatter.write_str("invalid secret payload"),
            Self::InvalidAuthorizationDigest => formatter.write_str("invalid authorization digest"),
            Self::RequestBindingConflict => {
                formatter.write_str("request identity is bound to a different operation")
            }
            Self::RequestCapacityExhausted => {
                formatter.write_str("retained request capacity exhausted")
            }
            Self::BackupRollbackRejected => {
                formatter.write_str("backup generation is older than the live state")
            }
            Self::GenerationOverflow => formatter.write_str("generation overflow"),
            Self::OutcomeUnknown { .. } => formatter.write_str("mutation outcome is unknown"),
            Self::CorruptState => formatter.write_str("durable state failed closed"),
            Self::BarrierFailure => formatter.write_str("barrier authentication failed"),
            Self::Io(_) => formatter.write_str("durable I/O failed"),
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ServiceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RequestKey {
    principal: String,
    namespace: String,
    request_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationKind {
    Put,
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Binding {
    key: RequestKey,
    resource: String,
    kind: MutationKind,
    authorization_digest: [u8; 32],
    value_digest: [u8; 32],
}

impl Binding {
    fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        encode_string(&mut bytes, &self.key.principal);
        encode_string(&mut bytes, &self.key.namespace);
        encode_string(&mut bytes, &self.key.request_id);
        encode_string(&mut bytes, &self.resource);
        bytes.push(match self.kind {
            MutationKind::Put => 1,
            MutationKind::Delete => 2,
        });
        bytes.extend_from_slice(&self.authorization_digest);
        bytes.extend_from_slice(&self.value_digest);
        digest32(b"heptabao.durable-service.binding.v1", &bytes)
    }

    fn storage_key(&self) -> (String, String) {
        (self.key.namespace.clone(), self.resource.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommitMarker {
    key: RequestKey,
    binding_digest: [u8; 32],
    recovery_reference: String,
    generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LedgerRecord {
    binding_digest: [u8; 32],
    recovery_reference: String,
    generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckpointMarker {
    generation: u64,
    retained_requests: u64,
    last_commit: Option<CommitMarker>,
    ledger_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    generation: u64,
    entries: BTreeMap<(String, String), Secret>,
    last_commit: Option<CommitMarker>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JournalEvent {
    Intent(CommitMarker),
    Commit(CommitMarker),
    Abort(CommitMarker),
    Checkpoint(CheckpointMarker),
}

pub struct DurableService<B: Barrier> {
    root: PathBuf,
    directory: ExclusiveDirectory,
    barrier: B,
    snapshot: Snapshot,
    ledger: BTreeMap<RequestKey, LedgerRecord>,
    reconciliation: BTreeMap<String, ReconciliationStatus>,
    journal_sequence: u64,
    journal_bytes: usize,
    journal_limit: usize,
    max_retained_requests: usize,
    unresolved: bool,
}

struct BackupComponents {
    snapshot_bytes: Vec<u8>,
    journal_bytes: Vec<u8>,
    ledger_bytes: Vec<u8>,
    snapshot: Snapshot,
    ledger: BTreeMap<RequestKey, LedgerRecord>,
    journal_sequence: u64,
}

impl<B: Barrier> fmt::Debug for DurableService<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableService")
            .field("root", &"[REDACTED]")
            .field("generation", &self.snapshot.generation)
            .field("entry_count", &self.snapshot.entries.len())
            .field("retained_request_count", &self.ledger.len())
            .field("unresolved", &self.unresolved)
            .finish()
    }
}

impl<B: Barrier> DurableService<B> {
    pub fn create_new(
        root: impl AsRef<Path>,
        barrier: B,
        max_retained_requests: usize,
    ) -> Result<Self, ServiceError> {
        validate_capacity(max_retained_requests)?;
        let root = validate_root(root.as_ref(), true)?;
        if root.exists() {
            let mut entries = fs::read_dir(&root)?;
            if entries.next().transpose()?.is_some() {
                return Err(ServiceError::RootNotEmpty);
            }
        } else {
            fs::create_dir_all(&root)?;
        }
        let directory = acquire_writer_lock(&root)?;
        let root = directory.access_path().to_path_buf();
        // Recheck under the acquired process fence: concurrent creators cannot
        // initialize an already-populated directory.
        if fs::read_dir(&root)?.next().transpose()?.is_some() {
            return Err(ServiceError::RootNotEmpty);
        }
        let snapshot = Snapshot {
            generation: 0,
            entries: BTreeMap::new(),
            last_commit: None,
        };
        let ledger = BTreeMap::new();
        persist_snapshot(&root, &barrier, &snapshot)?;
        initialize_journal(&root)?;
        persist_ledger(&root, &barrier, 0, &ledger)?;
        Ok(Self {
            root,
            directory,
            barrier,
            snapshot,
            ledger,
            reconciliation: BTreeMap::new(),
            journal_sequence: 0,
            journal_bytes: JOURNAL_MAGIC.len(),
            journal_limit: MAX_FILE_BYTES,
            max_retained_requests,
            unresolved: false,
        })
    }

    pub fn reopen(
        root: impl AsRef<Path>,
        barrier: B,
        max_retained_requests: usize,
    ) -> Result<Self, ServiceError> {
        validate_capacity(max_retained_requests)?;
        let root = validate_root(root.as_ref(), false)?;
        let directory = acquire_writer_lock(&root)?;
        let root = directory.access_path().to_path_buf();
        let snapshot = load_snapshot(&root, &barrier)?;
        let (journal_sequence, events, journal_bytes, incomplete_tail) =
            load_journal(&root, &barrier)?;
        let (ledger_generation, ledger) = load_ledger(&root, &barrier)?;
        let mut service = Self {
            root,
            directory,
            barrier,
            snapshot,
            ledger,
            reconciliation: BTreeMap::new(),
            journal_sequence,
            journal_bytes,
            journal_limit: MAX_FILE_BYTES,
            max_retained_requests,
            unresolved: false,
        };
        service.recover(events, ledger_generation, incomplete_tail)?;
        Ok(service)
    }

    pub fn put(&mut self, request: PutRequest) -> Result<MutationOutcome, ServiceError> {
        self.put_with_failpoint(request, Failpoint::None)
    }

    pub fn put_with_failpoint(
        &mut self,
        mut request: PutRequest,
        failpoint: Failpoint,
    ) -> Result<MutationOutcome, ServiceError> {
        request.validate()?;
        let value_digest = digest32(b"heptabao.durable-service.value.v1", request.value.expose());
        let binding = Binding {
            key: RequestKey {
                principal: request.principal,
                namespace: request.namespace,
                request_id: request.request_id,
            },
            resource: request.resource,
            kind: MutationKind::Put,
            authorization_digest: request.authorization_digest,
            value_digest,
        };
        self.execute(
            binding,
            Some(std::mem::take(&mut request.value.0)),
            failpoint,
        )
    }

    pub fn delete(&mut self, request: DeleteRequest) -> Result<MutationOutcome, ServiceError> {
        self.delete_with_failpoint(request, Failpoint::None)
    }

    pub fn delete_with_failpoint(
        &mut self,
        request: DeleteRequest,
        failpoint: Failpoint,
    ) -> Result<MutationOutcome, ServiceError> {
        request.validate()?;
        let binding = Binding {
            key: RequestKey {
                principal: request.principal,
                namespace: request.namespace,
                request_id: request.request_id,
            },
            resource: request.resource,
            kind: MutationKind::Delete,
            authorization_digest: request.authorization_digest,
            value_digest: digest32(b"heptabao.durable-service.delete.v1", b"delete"),
        };
        self.execute(binding, None, failpoint)
    }

    pub fn get(&self, namespace: &str, resource: &str) -> Result<Option<Secret>, ServiceError> {
        validate_namespace(namespace)?;
        validate_resource(resource)?;
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        let key = (namespace.to_owned(), resource.to_owned());
        Ok(self.snapshot.entries.get(&key).cloned())
    }

    /// Return immediate child names in exactly one namespace. A trailing slash
    /// on a result denotes a child directory. Empty prefix lists the namespace.
    pub fn list(&self, namespace: &str, prefix: &str) -> Result<Vec<String>, ServiceError> {
        validate_namespace(namespace)?;
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        if !prefix.is_empty() {
            validate_resource(prefix)?;
        }
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        let prefix = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}/")
        };
        let mut children = std::collections::BTreeSet::new();
        for (entry_namespace, resource) in self.snapshot.entries.keys() {
            if entry_namespace == namespace
                && let Some(suffix) = resource.strip_prefix(&prefix)
            {
                if let Some((child, _)) = suffix.split_once('/') {
                    children.insert(format!("{child}/"));
                } else if !suffix.is_empty() {
                    children.insert(suffix.to_owned());
                }
            }
        }
        Ok(children.into_iter().collect())
    }

    #[must_use]
    pub const fn recovery_required(&self) -> bool {
        self.unresolved
    }

    #[must_use]
    pub fn reconcile(&self, recovery_reference: &str) -> ReconciliationStatus {
        self.reconciliation
            .get(recovery_reference)
            .copied()
            .unwrap_or(ReconciliationStatus::Unknown)
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.snapshot.generation
    }

    #[must_use]
    pub fn retained_request_count(&self) -> usize {
        self.ledger.len()
    }

    /// Replace the replay journal with one authenticated checkpoint for the
    /// currently committed snapshot and complete request ledger.
    ///
    /// The snapshot and ledger remain unchanged. A failure after replacement
    /// starts fences this live instance; reopening accepts either the old or
    /// new complete journal and rejects mixed or unauthenticated state.
    pub fn compact(&mut self) -> Result<CompactionOutcome, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.directory.verify().map_err(map_guard_error)?;
        validate_committed_state(&self.snapshot, self.snapshot.generation, &self.ledger)?;
        let checkpoint = checkpoint_marker(&self.snapshot, &self.ledger)?;
        let frame = sealed_journal_record(&self.barrier, 1, &JournalEvent::Checkpoint(checkpoint))?;
        let mut journal = Vec::with_capacity(JOURNAL_MAGIC.len() + frame.len());
        journal.extend_from_slice(JOURNAL_MAGIC);
        journal.extend_from_slice(&frame);
        if journal.len() > self.journal_limit {
            return Err(ServiceError::JournalCapacityExhausted);
        }
        let before = self.journal_bytes;
        self.unresolved = true;
        atomic_write(&self.root, &journal_path(&self.root), &journal)?;
        self.journal_sequence = 1;
        self.journal_bytes = journal.len();
        self.unresolved = false;
        Ok(CompactionOutcome {
            generation: self.snapshot.generation,
            retained_requests: self.ledger.len(),
            journal_bytes_before: before,
            journal_bytes_after: journal.len(),
        })
    }

    /// Export a self-authenticating, still-barrier-encrypted backup of the
    /// exact committed snapshot and request ledger. The bundle contains no
    /// barrier key and can be opened only with the original barrier provider.
    pub fn export_backup(&self) -> Result<Vec<u8>, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.directory.verify().map_err(map_guard_error)?;
        validate_committed_state(&self.snapshot, self.snapshot.generation, &self.ledger)?;
        let snapshot = sealed_snapshot(&self.barrier, &self.snapshot)?;
        let ledger = sealed_ledger(&self.barrier, self.snapshot.generation, &self.ledger)?;
        let checkpoint = sealed_journal_record(
            &self.barrier,
            1,
            &JournalEvent::Checkpoint(checkpoint_marker(&self.snapshot, &self.ledger)?),
        )?;
        let mut journal = Vec::with_capacity(JOURNAL_MAGIC.len() + checkpoint.len());
        journal.extend_from_slice(JOURNAL_MAGIC);
        journal.extend_from_slice(&checkpoint);
        encode_backup(self.snapshot.generation, &snapshot, &journal, &ledger)
    }

    /// Restore one previously exported backup into this exclusively owned
    /// directory. Rollback is rejected unless `allow_rollback` is explicit.
    ///
    /// Replacement uses independently atomic files. A crash or I/O failure can
    /// leave a mixed set, which is deliberately rejected on reopen rather than
    /// being guessed or automatically reset.
    pub fn restore_backup(
        &mut self,
        backup: &[u8],
        allow_rollback: bool,
    ) -> Result<RestoreOutcome, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.directory.verify().map_err(map_guard_error)?;
        let restored = decode_backup(&self.barrier, backup, self.max_retained_requests)?;
        if restored.snapshot.generation < self.snapshot.generation && !allow_rollback {
            return Err(ServiceError::BackupRollbackRejected);
        }
        let previous_generation = self.snapshot.generation;
        self.unresolved = true;
        atomic_write(
            &self.root,
            &snapshot_path(&self.root),
            &restored.snapshot_bytes,
        )?;
        atomic_write(&self.root, &ledger_path(&self.root), &restored.ledger_bytes)?;
        atomic_write(
            &self.root,
            &journal_path(&self.root),
            &restored.journal_bytes,
        )?;
        self.snapshot = restored.snapshot;
        self.ledger = restored.ledger;
        self.journal_sequence = restored.journal_sequence;
        self.journal_bytes = restored.journal_bytes.len();
        self.rebuild_reconciliation()?;
        self.unresolved = false;
        Ok(RestoreOutcome {
            previous_generation,
            restored_generation: self.snapshot.generation,
            retained_requests: self.ledger.len(),
        })
    }

    fn rebuild_reconciliation(&mut self) -> Result<(), ServiceError> {
        self.reconciliation.clear();
        for record in self.ledger.values() {
            validate_ledger_record(record)?;
            self.reconciliation.insert(
                record.recovery_reference.clone(),
                ReconciliationStatus::Committed {
                    generation: record.generation,
                },
            );
        }
        Ok(())
    }

    fn execute(
        &mut self,
        binding: Binding,
        value: Option<Vec<u8>>,
        failpoint: Failpoint,
    ) -> Result<MutationOutcome, ServiceError> {
        let value = value.map(Zeroizing::new);
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.directory.verify().map_err(map_guard_error)?;
        let binding_digest = binding.digest();
        if let Some(existing) = self.ledger.get(&binding.key) {
            if existing.binding_digest != binding_digest {
                return Err(ServiceError::RequestBindingConflict);
            }
            return Ok(MutationOutcome::Duplicate {
                generation: existing.generation,
                recovery_reference: existing.recovery_reference.clone(),
            });
        }
        if self.ledger.len() >= self.max_retained_requests {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let generation = self
            .snapshot
            .generation
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let intent_sequence = self
            .journal_sequence
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let terminal_sequence = intent_sequence
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let recovery_reference = recovery_reference(&binding_digest, generation, intent_sequence);
        let marker = CommitMarker {
            key: binding.key.clone(),
            binding_digest,
            recovery_reference: recovery_reference.clone(),
            generation,
        };
        let mut candidate = self.snapshot.clone();
        candidate.generation = generation;
        candidate.last_commit = Some(marker.clone());
        match binding.kind {
            MutationKind::Put => {
                let mut value = value.ok_or(ServiceError::InvalidSecret)?;
                candidate
                    .entries
                    .insert(binding.storage_key(), Secret(std::mem::take(&mut *value)));
            }
            MutationKind::Delete => {
                candidate.entries.remove(&binding.storage_key());
            }
        }
        let mut candidate_ledger = self.ledger.clone();
        candidate_ledger.insert(
            binding.key,
            LedgerRecord {
                binding_digest,
                recovery_reference: recovery_reference.clone(),
                generation,
            },
        );
        // Seal every payload and reserve BOTH journal records before durable
        // entry. Capacity failure can therefore never strand an admitted intent.
        let snapshot_bytes = sealed_snapshot(&self.barrier, &candidate)?;
        let ledger_bytes = sealed_ledger(&self.barrier, generation, &candidate_ledger)?;
        let intent = sealed_journal_record(
            &self.barrier,
            intent_sequence,
            &JournalEvent::Intent(marker.clone()),
        )?;
        let commit = sealed_journal_record(
            &self.barrier,
            terminal_sequence,
            &JournalEvent::Commit(marker),
        )?;
        if snapshot_bytes.len() > MAX_FILE_BYTES || ledger_bytes.len() > MAX_FILE_BYTES {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        if terminal_sequence > MAX_RECORDS as u64
            || self
                .journal_bytes
                .checked_add(intent.len())
                .and_then(|n| n.checked_add(commit.len()))
                .is_none_or(|n| n > self.journal_limit)
        {
            return Err(ServiceError::JournalCapacityExhausted);
        }
        // Even write_all/sync_all failures can have published bytes. Poison the
        // live instance before the first attempted append and preserve its ref.
        self.unresolved = true;
        let result = (|| {
            self.append_frame(&intent)?;
            if failpoint == Failpoint::AfterIntent {
                return Err(ServiceError::RecoveryRequired);
            }
            atomic_write(&self.root, &snapshot_path(&self.root), &snapshot_bytes)?;
            self.snapshot = candidate;
            if failpoint == Failpoint::AfterSnapshotPublication {
                return Err(ServiceError::RecoveryRequired);
            }
            self.append_frame(&commit)?;
            if failpoint == Failpoint::AfterCommitJournal {
                return Err(ServiceError::RecoveryRequired);
            }
            atomic_write(&self.root, &ledger_path(&self.root), &ledger_bytes)?;
            self.ledger = candidate_ledger;
            Ok(())
        })();
        if result.is_err() {
            return Err(ServiceError::OutcomeUnknown { recovery_reference });
        }
        self.reconciliation.insert(
            recovery_reference.clone(),
            ReconciliationStatus::Committed { generation },
        );
        self.unresolved = false;
        Ok(MutationOutcome::Committed {
            generation,
            recovery_reference,
        })
    }

    fn append_frame(&mut self, frame: &[u8]) -> Result<(), ServiceError> {
        let next = self
            .journal_sequence
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let size = self
            .journal_bytes
            .checked_add(frame.len())
            .ok_or(ServiceError::JournalCapacityExhausted)?;
        if size > self.journal_limit || next > MAX_RECORDS as u64 {
            return Err(ServiceError::JournalCapacityExhausted);
        }
        append_journal_frame(&self.root, frame)?;
        // Never consume a sequence in memory on a failed append.
        self.journal_sequence = next;
        self.journal_bytes = size;
        Ok(())
    }

    fn append_event(&mut self, event: &JournalEvent) -> Result<(), ServiceError> {
        let sequence = self
            .journal_sequence
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let frame = sealed_journal_record(&self.barrier, sequence, event)?;
        self.append_frame(&frame)
    }

    fn recover(
        &mut self,
        events: Vec<JournalEvent>,
        ledger_generation: u64,
        incomplete_tail: bool,
    ) -> Result<(), ServiceError> {
        validate_ledger_generation(&self.ledger, ledger_generation)?;
        let mut pending: Option<CommitMarker> = None;
        let mut committed: BTreeMap<RequestKey, CommitMarker> = BTreeMap::new();
        let mut last_commit: Option<CommitMarker> = None;
        let mut committed_generation = 0_u64;
        let mut references = std::collections::BTreeSet::new();
        let mut saw_checkpoint = false;

        for (offset, event) in events.into_iter().enumerate() {
            match event {
                JournalEvent::Checkpoint(checkpoint) => {
                    if offset != 0 || saw_checkpoint || pending.is_some() || !committed.is_empty() {
                        return Err(ServiceError::CorruptState);
                    }
                    saw_checkpoint = true;
                    let prefix = ledger_prefix(&self.ledger, checkpoint.generation)?;
                    validate_checkpoint(&checkpoint, &prefix)?;
                    committed_generation = checkpoint.generation;
                    last_commit = checkpoint.last_commit.clone();
                    for (key, record) in prefix {
                        let marker = marker_from_ledger(&key, &record)?;
                        if !references.insert(marker.recovery_reference.clone()) {
                            return Err(ServiceError::CorruptState);
                        }
                        committed.insert(key, marker);
                    }
                }
                JournalEvent::Intent(marker) => {
                    validate_marker(&marker)?;
                    let sequence = u64::try_from(offset)
                        .ok()
                        .and_then(|value| value.checked_add(1))
                        .ok_or(ServiceError::GenerationOverflow)?;
                    if pending.is_some()
                        || committed.contains_key(&marker.key)
                        || marker.generation
                            != committed_generation
                                .checked_add(1)
                                .ok_or(ServiceError::GenerationOverflow)?
                        || marker.recovery_reference
                            != recovery_reference(
                                &marker.binding_digest,
                                marker.generation,
                                sequence,
                            )
                        || !references.insert(marker.recovery_reference.clone())
                    {
                        return Err(ServiceError::CorruptState);
                    }
                    pending = Some(marker);
                }
                JournalEvent::Commit(marker) => {
                    if pending.as_ref() != Some(&marker) {
                        return Err(ServiceError::CorruptState);
                    }
                    pending = None;
                    committed_generation = marker.generation;
                    last_commit = Some(marker.clone());
                    committed.insert(marker.key.clone(), marker);
                }
                JournalEvent::Abort(marker) => {
                    if pending.as_ref() != Some(&marker) {
                        return Err(ServiceError::CorruptState);
                    }
                    pending = None;
                    self.reconciliation
                        .insert(marker.recovery_reference, ReconciliationStatus::Aborted);
                }
            }
        }
        if committed.len() as u64 != committed_generation {
            return Err(ServiceError::CorruptState);
        }
        // The snapshot must be precisely the journal's committed frontier, or
        // the sole pending intent's publication. A valid older snapshot is a
        // rollback, not a reason to acknowledge the newer ledger.
        let published_pending = pending.as_ref().is_some_and(|marker| {
            self.snapshot.generation == marker.generation
                && self.snapshot.last_commit.as_ref() == Some(marker)
        });
        if !published_pending
            && (self.snapshot.generation != committed_generation
                || self.snapshot.last_commit != last_commit)
        {
            return Err(ServiceError::CorruptState);
        }
        if self.snapshot.generation == 0
            && (!self.snapshot.entries.is_empty() || self.snapshot.last_commit.is_some())
        {
            return Err(ServiceError::CorruptState);
        }
        // A ledger is an authenticated complete prefix of commits. Header and
        // records cannot independently drift forward, backwards or develop gaps.
        if ledger_generation > committed_generation
            || ledger_generation.saturating_add(1) < committed_generation
        {
            return Err(ServiceError::CorruptState);
        }
        for (key, marker) in &committed {
            if marker.generation <= ledger_generation {
                let record = self.ledger.get(key).ok_or(ServiceError::CorruptState)?;
                if marker.binding_digest != record.binding_digest
                    || marker.generation != record.generation
                    || marker.recovery_reference != record.recovery_reference
                {
                    return Err(ServiceError::CorruptState);
                }
            } else if self.ledger.contains_key(key) {
                return Err(ServiceError::CorruptState);
            }
        }
        for key in self.ledger.keys() {
            if !committed.contains_key(key) {
                return Err(ServiceError::CorruptState);
            }
        }
        if committed.len() + usize::from(published_pending) > self.max_retained_requests {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        // Only a physically incomplete tail is repairable. Fully framed bad
        // checksums, sequence gaps and authentication failures fail closed.
        if incomplete_tail {
            let file = nofollow_options()
                .write(true)
                .open(journal_path(&self.root))?;
            file.set_len(self.journal_bytes as u64)?;
            file.sync_all()?;
        }
        if let Some(marker) = pending {
            if published_pending {
                self.append_event(&JournalEvent::Commit(marker.clone()))?;
                committed.insert(marker.key.clone(), marker);
            } else {
                self.append_event(&JournalEvent::Abort(marker.clone()))?;
                self.reconciliation
                    .insert(marker.recovery_reference, ReconciliationStatus::Aborted);
            }
        }
        self.ledger.clear();
        for (key, marker) in committed {
            self.reconciliation.insert(
                marker.recovery_reference.clone(),
                ReconciliationStatus::Committed {
                    generation: marker.generation,
                },
            );
            self.ledger.insert(
                key,
                LedgerRecord {
                    binding_digest: marker.binding_digest,
                    recovery_reference: marker.recovery_reference,
                    generation: marker.generation,
                },
            );
        }
        persist_ledger(
            &self.root,
            &self.barrier,
            self.snapshot.generation,
            &self.ledger,
        )?;
        self.unresolved = false;
        Ok(())
    }
}

fn validate_ledger_record(record: &LedgerRecord) -> Result<(), ServiceError> {
    if record.binding_digest == [0; 32]
        || record.generation == 0
        || record.recovery_reference.len() != 32
        || !record
            .recovery_reference
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ServiceError::CorruptState);
    }
    Ok(())
}

fn validate_ledger_generation(
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
    generation: u64,
) -> Result<(), ServiceError> {
    if ledger.len() as u64 != generation {
        return Err(ServiceError::CorruptState);
    }
    let mut generations = std::collections::BTreeSet::new();
    let mut references = std::collections::BTreeSet::new();
    for (key, record) in ledger {
        validate_identifier(&key.principal)?;
        validate_namespace(&key.namespace)?;
        validate_identifier(&key.request_id)?;
        validate_ledger_record(record)?;
        if record.generation > generation
            || !generations.insert(record.generation)
            || !references.insert(record.recovery_reference.clone())
        {
            return Err(ServiceError::CorruptState);
        }
    }
    if generations.iter().copied().ne(1..=generation) {
        return Err(ServiceError::CorruptState);
    }
    Ok(())
}

fn validate_committed_state(
    snapshot: &Snapshot,
    ledger_generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<(), ServiceError> {
    if snapshot.generation != ledger_generation {
        return Err(ServiceError::CorruptState);
    }
    validate_ledger_generation(ledger, ledger_generation)?;
    if ledger_generation == 0 {
        if snapshot.last_commit.is_some() || !ledger.is_empty() {
            return Err(ServiceError::CorruptState);
        }
        return Ok(());
    }
    let (key, record) = ledger
        .iter()
        .find(|(_, record)| record.generation == ledger_generation)
        .ok_or(ServiceError::CorruptState)?;
    if snapshot.last_commit.as_ref() != Some(&marker_from_ledger(key, record)?) {
        return Err(ServiceError::CorruptState);
    }
    Ok(())
}

fn marker_from_ledger(
    key: &RequestKey,
    record: &LedgerRecord,
) -> Result<CommitMarker, ServiceError> {
    validate_ledger_record(record)?;
    let marker = CommitMarker {
        key: key.clone(),
        binding_digest: record.binding_digest,
        recovery_reference: record.recovery_reference.clone(),
        generation: record.generation,
    };
    validate_marker(&marker)?;
    Ok(marker)
}

fn ledger_prefix(
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
    generation: u64,
) -> Result<BTreeMap<RequestKey, LedgerRecord>, ServiceError> {
    let prefix = ledger
        .iter()
        .filter(|(_, record)| record.generation <= generation)
        .map(|(key, record)| (key.clone(), record.clone()))
        .collect::<BTreeMap<_, _>>();
    validate_ledger_generation(&prefix, generation)?;
    Ok(prefix)
}

fn checkpoint_marker(
    snapshot: &Snapshot,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<CheckpointMarker, ServiceError> {
    validate_committed_state(snapshot, snapshot.generation, ledger)?;
    let encoded = Zeroizing::new(encode_ledger(ledger)?);
    Ok(CheckpointMarker {
        generation: snapshot.generation,
        retained_requests: ledger.len() as u64,
        last_commit: snapshot.last_commit.clone(),
        ledger_digest: digest32(b"heptabao.durable-service.checkpoint-ledger.v1", &encoded),
    })
}

fn validate_checkpoint(
    checkpoint: &CheckpointMarker,
    prefix: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<(), ServiceError> {
    if checkpoint.retained_requests != checkpoint.generation
        || checkpoint.retained_requests != prefix.len() as u64
    {
        return Err(ServiceError::CorruptState);
    }
    validate_ledger_generation(prefix, checkpoint.generation)?;
    let encoded = Zeroizing::new(encode_ledger(prefix)?);
    let expected = digest32(b"heptabao.durable-service.checkpoint-ledger.v1", &encoded);
    if !constant_time_eq(&checkpoint.ledger_digest, &expected) {
        return Err(ServiceError::CorruptState);
    }
    if checkpoint.generation == 0 {
        if checkpoint.last_commit.is_some() {
            return Err(ServiceError::CorruptState);
        }
    } else {
        let (key, record) = prefix
            .iter()
            .find(|(_, record)| record.generation == checkpoint.generation)
            .ok_or(ServiceError::CorruptState)?;
        if checkpoint.last_commit.as_ref() != Some(&marker_from_ledger(key, record)?) {
            return Err(ServiceError::CorruptState);
        }
    }
    Ok(())
}

fn validate_capacity(capacity: usize) -> Result<(), ServiceError> {
    if capacity == 0 || capacity > MAX_RECORDS {
        return Err(ServiceError::RequestCapacityExhausted);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ServiceError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ServiceError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_namespace(value: &str) -> Result<(), ServiceError> {
    validate_segmented_path(value, 1024).map_err(|()| ServiceError::InvalidNamespace)
}

fn validate_resource(value: &str) -> Result<(), ServiceError> {
    validate_segmented_path(value, MAX_STRING_BYTES).map_err(|()| ServiceError::InvalidResource)
}

fn validate_segmented_path(value: &str, maximum: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > maximum
        || value.starts_with('/')
        || value.ends_with('/')
        || !value.is_ascii()
    {
        return Err(());
    }
    for segment in value.split('/') {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(());
        }
    }
    Ok(())
}

fn validate_root(root: &Path, create: bool) -> Result<PathBuf, ServiceError> {
    if !root.is_absolute() {
        return Err(ServiceError::InvalidRoot);
    }
    if root.exists() {
        let metadata = fs::symlink_metadata(root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ServiceError::InvalidRoot);
        }
    } else if !create {
        return Err(ServiceError::InvalidRoot);
    }
    Ok(root.to_path_buf())
}

fn acquire_writer_lock(root: &Path) -> Result<ExclusiveDirectory, ServiceError> {
    ExclusiveDirectory::open(root).map_err(map_guard_error)
}

fn map_guard_error(error: DirectoryGuardError) -> ServiceError {
    match error {
        DirectoryGuardError::WriterBusy => ServiceError::WriterLocked,
        DirectoryGuardError::UnsupportedPlatform
        | DirectoryGuardError::DescriptorPathUnavailable => ServiceError::UnsupportedProfile,
        DirectoryGuardError::Io(error) => ServiceError::Io(error),
        _ => ServiceError::InvalidRoot,
    }
}

fn nofollow_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(target_os = "linux")]
    options.custom_flags(0o400000 | 0o2000000); // O_NOFOLLOW | O_CLOEXEC
    options
}

fn snapshot_path(root: &Path) -> PathBuf {
    root.join("state.hbs")
}

fn journal_path(root: &Path) -> PathBuf {
    root.join("journal.hbj")
}

fn ledger_path(root: &Path) -> PathBuf {
    root.join("ledger.hbl")
}

fn persist_snapshot<B: Barrier>(
    root: &Path,
    barrier: &B,
    snapshot: &Snapshot,
) -> Result<(), ServiceError> {
    let encoded = sealed_snapshot(barrier, snapshot)?;
    atomic_write(root, &snapshot_path(root), &encoded)
}

fn sealed_snapshot<B: Barrier>(barrier: &B, snapshot: &Snapshot) -> Result<Vec<u8>, ServiceError> {
    let plaintext = Zeroizing::new(encode_snapshot(snapshot)?);
    let context = snapshot_context(snapshot.generation);
    let protected = barrier
        .seal(&context, &plaintext)
        .map_err(|_| ServiceError::BarrierFailure)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(SNAPSHOT_MAGIC);
    write_u64(&mut encoded, snapshot.generation);
    write_bytes(&mut encoded, &protected)?;
    let checksum = digest32(b"heptabao.durable-service.snapshot-frame.v2", &encoded);
    encoded.extend_from_slice(&checksum);
    Ok(encoded)
}

fn load_snapshot<B: Barrier>(root: &Path, barrier: &B) -> Result<Snapshot, ServiceError> {
    let encoded = read_bounded(&snapshot_path(root))?;
    decode_snapshot_frame(&encoded, barrier)
}

fn decode_snapshot_frame<B: Barrier>(
    encoded: &[u8],
    barrier: &B,
) -> Result<Snapshot, ServiceError> {
    if encoded.starts_with(b"HBS1") {
        return Err(ServiceError::LegacySchema);
    }
    if encoded.len() < 4 + 8 + 4 + 32 || &encoded[..4] != SNAPSHOT_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let frame_len = encoded
        .len()
        .checked_sub(32)
        .ok_or(ServiceError::CorruptState)?;
    let expected = digest32(
        b"heptabao.durable-service.snapshot-frame.v2",
        &encoded[..frame_len],
    );
    if !constant_time_eq(&expected, &encoded[frame_len..]) {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&encoded[4..frame_len]);
    let generation = cursor.read_u64()?;
    let protected = cursor.read_bytes(MAX_FILE_BYTES)?;
    cursor.finish()?;
    let plaintext = barrier
        .open(&snapshot_context(generation), protected)
        .map_err(|_| ServiceError::BarrierFailure)?;
    let plaintext = Zeroizing::new(plaintext);
    let snapshot = decode_snapshot(&plaintext)?;
    if snapshot.generation != generation {
        return Err(ServiceError::CorruptState);
    }
    Ok(snapshot)
}

fn initialize_journal(root: &Path) -> Result<(), ServiceError> {
    let path = journal_path(root);
    let mut file = nofollow_options()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(JOURNAL_MAGIC)?;
    file.sync_all()?;
    sync_parent(root)
}

fn sealed_journal_record<B: Barrier>(
    barrier: &B,
    sequence: u64,
    event: &JournalEvent,
) -> Result<Vec<u8>, ServiceError> {
    let plaintext = encode_journal_event(event)?;
    let protected = barrier
        .seal(&journal_context(sequence), &plaintext)
        .map_err(|_| ServiceError::BarrierFailure)?;
    let mut frame = Vec::new();
    write_u64(&mut frame, sequence);
    write_bytes(&mut frame, &protected)?;
    let checksum = digest32(b"heptabao.durable-service.journal-frame.v2", &frame);
    frame.extend_from_slice(&checksum);
    let frame_len = u32::try_from(frame.len()).map_err(|_| ServiceError::CorruptState)?;
    let mut encoded = Vec::with_capacity(frame.len() + 4);
    write_u32(&mut encoded, frame_len);
    encoded.extend_from_slice(&frame);
    Ok(encoded)
}

fn append_journal_frame(root: &Path, frame: &[u8]) -> Result<(), ServiceError> {
    let mut file = nofollow_options().append(true).open(journal_path(root))?;
    if !file.metadata()?.is_file() {
        return Err(ServiceError::CorruptState);
    }
    file.write_all(frame)?;
    file.sync_all()?;
    Ok(())
}

fn load_journal<B: Barrier>(
    root: &Path,
    barrier: &B,
) -> Result<(u64, Vec<JournalEvent>, usize, bool), ServiceError> {
    let encoded = read_bounded(&journal_path(root))?;
    decode_journal_frames(&encoded, barrier)
}

fn decode_journal_frames<B: Barrier>(
    encoded: &[u8],
    barrier: &B,
) -> Result<(u64, Vec<JournalEvent>, usize, bool), ServiceError> {
    if !encoded.starts_with(JOURNAL_MAGIC) {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&encoded[4..]);
    let mut expected_sequence = 1_u64;
    let mut events = Vec::new();
    let mut verified_bytes = 4;
    let mut incomplete_tail = false;
    while !cursor.is_finished() {
        let remaining = cursor.bytes.len() - cursor.position;
        if remaining < 4 {
            incomplete_tail = true;
            break;
        }
        let frame_len = cursor.read_u32()? as usize;
        if !(8 + 4 + 32..=MAX_FILE_BYTES).contains(&frame_len) {
            return Err(ServiceError::CorruptState);
        }
        if cursor.bytes.len() - cursor.position < frame_len {
            incomplete_tail = true;
            break;
        }
        let frame = cursor.read_exact(frame_len)?;
        let payload_len = frame_len - 32;
        let expected = digest32(
            b"heptabao.durable-service.journal-frame.v2",
            &frame[..payload_len],
        );
        if !constant_time_eq(&expected, &frame[payload_len..]) {
            return Err(ServiceError::CorruptState);
        }
        let mut frame_cursor = Cursor::new(&frame[..payload_len]);
        let sequence = frame_cursor.read_u64()?;
        if sequence != expected_sequence {
            return Err(ServiceError::CorruptState);
        }
        let protected = frame_cursor.read_bytes(MAX_FILE_BYTES)?;
        frame_cursor.finish()?;
        let plaintext = barrier
            .open(&journal_context(sequence), protected)
            .map_err(|_| ServiceError::BarrierFailure)?;
        events.push(decode_journal_event(&plaintext)?);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        if events.len() > MAX_RECORDS {
            return Err(ServiceError::CorruptState);
        }
        verified_bytes = cursor.position + 4;
    }
    Ok((
        expected_sequence - 1,
        events,
        verified_bytes,
        incomplete_tail,
    ))
}

fn persist_ledger<B: Barrier>(
    root: &Path,
    barrier: &B,
    generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<(), ServiceError> {
    let encoded = sealed_ledger(barrier, generation, ledger)?;
    atomic_write(root, &ledger_path(root), &encoded)
}

fn sealed_ledger<B: Barrier>(
    barrier: &B,
    generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<Vec<u8>, ServiceError> {
    let plaintext = Zeroizing::new(encode_ledger(ledger)?);
    let protected = barrier
        .seal(&ledger_context(generation), &plaintext)
        .map_err(|_| ServiceError::BarrierFailure)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(LEDGER_MAGIC);
    write_u64(&mut encoded, generation);
    write_bytes(&mut encoded, &protected)?;
    let checksum = digest32(b"heptabao.durable-service.ledger-frame.v2", &encoded);
    encoded.extend_from_slice(&checksum);
    Ok(encoded)
}

fn load_ledger<B: Barrier>(
    root: &Path,
    barrier: &B,
) -> Result<(u64, BTreeMap<RequestKey, LedgerRecord>), ServiceError> {
    let encoded = read_bounded(&ledger_path(root))?;
    decode_ledger_frame(&encoded, barrier)
}

fn decode_ledger_frame<B: Barrier>(
    encoded: &[u8],
    barrier: &B,
) -> Result<(u64, BTreeMap<RequestKey, LedgerRecord>), ServiceError> {
    if encoded.len() < 4 + 8 + 4 + 32 || &encoded[..4] != LEDGER_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let frame_len = encoded
        .len()
        .checked_sub(32)
        .ok_or(ServiceError::CorruptState)?;
    let expected = digest32(
        b"heptabao.durable-service.ledger-frame.v2",
        &encoded[..frame_len],
    );
    if !constant_time_eq(&expected, &encoded[frame_len..]) {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&encoded[4..frame_len]);
    let generation = cursor.read_u64()?;
    let protected = cursor.read_bytes(MAX_FILE_BYTES)?;
    cursor.finish()?;
    let plaintext = barrier
        .open(&ledger_context(generation), protected)
        .map_err(|_| ServiceError::BarrierFailure)?;
    let plaintext = Zeroizing::new(plaintext);
    Ok((generation, decode_ledger(&plaintext)?))
}

fn encode_backup(
    generation: u64,
    snapshot: &[u8],
    journal: &[u8],
    ledger: &[u8],
) -> Result<Vec<u8>, ServiceError> {
    if snapshot.len() > MAX_FILE_BYTES
        || journal.len() > MAX_FILE_BYTES
        || ledger.len() > MAX_FILE_BYTES
    {
        return Err(ServiceError::CorruptState);
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(BACKUP_MAGIC);
    write_u16(&mut encoded, BACKUP_VERSION);
    write_u16(&mut encoded, 0);
    write_u64(&mut encoded, generation);
    write_bytes(&mut encoded, snapshot)?;
    write_bytes(&mut encoded, journal)?;
    write_bytes(&mut encoded, ledger)?;
    if encoded
        .len()
        .checked_add(32)
        .is_none_or(|length| length > MAX_BACKUP_BYTES)
    {
        return Err(ServiceError::CorruptState);
    }
    let checksum = digest32(b"heptabao.durable-service.backup.v1", &encoded);
    encoded.extend_from_slice(&checksum);
    Ok(encoded)
}

fn decode_backup<B: Barrier>(
    barrier: &B,
    encoded: &[u8],
    max_retained_requests: usize,
) -> Result<BackupComponents, ServiceError> {
    if encoded.len() < 4 + 2 + 2 + 8 + 4 * 3 + 32 || encoded.len() > MAX_BACKUP_BYTES {
        return Err(ServiceError::CorruptState);
    }
    let payload_len = encoded
        .len()
        .checked_sub(32)
        .ok_or(ServiceError::CorruptState)?;
    let expected = digest32(
        b"heptabao.durable-service.backup.v1",
        &encoded[..payload_len],
    );
    if !constant_time_eq(&expected, &encoded[payload_len..]) {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&encoded[..payload_len]);
    if cursor.read_exact(4)? != BACKUP_MAGIC
        || cursor.read_u16()? != BACKUP_VERSION
        || cursor.read_u16()? != 0
    {
        return Err(ServiceError::CorruptState);
    }
    let generation = cursor.read_u64()?;
    let snapshot_bytes = cursor.read_bytes(MAX_FILE_BYTES)?.to_vec();
    let journal_bytes = cursor.read_bytes(MAX_FILE_BYTES)?.to_vec();
    let ledger_bytes = cursor.read_bytes(MAX_FILE_BYTES)?.to_vec();
    cursor.finish()?;

    let snapshot = decode_snapshot_frame(&snapshot_bytes, barrier)?;
    let (ledger_generation, ledger) = decode_ledger_frame(&ledger_bytes, barrier)?;
    let (journal_sequence, events, journal_verified_bytes, incomplete_tail) =
        decode_journal_frames(&journal_bytes, barrier)?;
    if incomplete_tail
        || journal_verified_bytes != journal_bytes.len()
        || journal_sequence != 1
        || events.len() != 1
        || generation != snapshot.generation
        || generation != ledger_generation
        || ledger.len() > max_retained_requests
    {
        return Err(ServiceError::CorruptState);
    }
    validate_committed_state(&snapshot, ledger_generation, &ledger)?;
    match &events[0] {
        JournalEvent::Checkpoint(checkpoint) => {
            validate_checkpoint(checkpoint, &ledger)?;
            if checkpoint.generation != generation {
                return Err(ServiceError::CorruptState);
            }
        }
        _ => return Err(ServiceError::CorruptState),
    }
    Ok(BackupComponents {
        snapshot_bytes,
        journal_bytes,
        ledger_bytes,
        snapshot,
        ledger,
        journal_sequence,
    })
}

fn atomic_write(root: &Path, target: &Path, bytes: &[u8]) -> Result<(), ServiceError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ServiceError::CorruptState);
    }
    let temporary = target.with_extension("tmp");
    let mut file = nofollow_options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, target)?;
    sync_parent(root)
}

fn sync_parent(root: &Path) -> Result<(), ServiceError> {
    File::open(root)?.sync_all()?;
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ServiceError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ServiceError::CorruptState);
    }
    let length = usize::try_from(metadata.len()).map_err(|_| ServiceError::CorruptState)?;
    if length > MAX_FILE_BYTES {
        return Err(ServiceError::CorruptState);
    }
    let mut bytes = Vec::with_capacity(length);
    nofollow_options()
        .read(true)
        .open(path)?
        .take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err(ServiceError::CorruptState);
    }
    Ok(bytes)
}

fn encode_snapshot(snapshot: &Snapshot) -> Result<Vec<u8>, ServiceError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SNAPSHOT_PLAINTEXT_MAGIC);
    write_u64(&mut bytes, snapshot.generation);
    match &snapshot.last_commit {
        Some(marker) => {
            bytes.push(1);
            encode_marker(&mut bytes, marker)?;
        }
        None => bytes.push(0),
    }
    write_u32(
        &mut bytes,
        u32::try_from(snapshot.entries.len()).map_err(|_| ServiceError::CorruptState)?,
    );
    for ((namespace, resource), value) in &snapshot.entries {
        encode_string_checked(&mut bytes, namespace)?;
        encode_string_checked(&mut bytes, resource)?;
        write_bytes(&mut bytes, value.expose())?;
    }
    Ok(bytes)
}

fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot, ServiceError> {
    if bytes.len() < 4 || &bytes[..4] != SNAPSHOT_PLAINTEXT_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&bytes[4..]);
    let generation = cursor.read_u64()?;
    let last_commit = match cursor.read_u8()? {
        0 => None,
        1 => Some(decode_marker(&mut cursor)?),
        _ => return Err(ServiceError::CorruptState),
    };
    let count = usize::try_from(cursor.read_u32()?).map_err(|_| ServiceError::CorruptState)?;
    if count > MAX_RECORDS {
        return Err(ServiceError::CorruptState);
    }
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let namespace = cursor.read_string(1024)?;
        let resource = cursor.read_string(MAX_STRING_BYTES)?;
        validate_namespace(&namespace)?;
        validate_resource(&resource)?;
        let key = (namespace, resource);
        let value = cursor.read_bytes(MAX_SECRET_BYTES)?.to_vec();
        if value.is_empty() {
            return Err(ServiceError::CorruptState);
        }
        if entries.insert(key, Secret(value)).is_some() {
            return Err(ServiceError::CorruptState);
        }
    }
    cursor.finish()?;
    Ok(Snapshot {
        generation,
        entries,
        last_commit,
    })
}

fn encode_journal_event(event: &JournalEvent) -> Result<Vec<u8>, ServiceError> {
    let mut bytes = Vec::new();
    match event {
        JournalEvent::Intent(marker) => {
            bytes.push(1);
            encode_marker(&mut bytes, marker)?;
        }
        JournalEvent::Commit(marker) => {
            bytes.push(2);
            encode_marker(&mut bytes, marker)?;
        }
        JournalEvent::Abort(marker) => {
            bytes.push(3);
            encode_marker(&mut bytes, marker)?;
        }
        JournalEvent::Checkpoint(checkpoint) => {
            bytes.push(4);
            write_u64(&mut bytes, checkpoint.generation);
            write_u64(&mut bytes, checkpoint.retained_requests);
            match &checkpoint.last_commit {
                Some(marker) => {
                    bytes.push(1);
                    encode_marker(&mut bytes, marker)?;
                }
                None => bytes.push(0),
            }
            bytes.extend_from_slice(&checkpoint.ledger_digest);
        }
    }
    Ok(bytes)
}

fn decode_journal_event(bytes: &[u8]) -> Result<JournalEvent, ServiceError> {
    let mut cursor = Cursor::new(bytes);
    let kind = cursor.read_u8()?;
    let event = match kind {
        1 => JournalEvent::Intent(decode_marker(&mut cursor)?),
        2 => JournalEvent::Commit(decode_marker(&mut cursor)?),
        3 => JournalEvent::Abort(decode_marker(&mut cursor)?),
        4 => {
            let generation = cursor.read_u64()?;
            let retained_requests = cursor.read_u64()?;
            let last_commit = match cursor.read_u8()? {
                0 => None,
                1 => Some(decode_marker(&mut cursor)?),
                _ => return Err(ServiceError::CorruptState),
            };
            let ledger_digest = cursor.read_array_32()?;
            JournalEvent::Checkpoint(CheckpointMarker {
                generation,
                retained_requests,
                last_commit,
                ledger_digest,
            })
        }
        _ => return Err(ServiceError::CorruptState),
    };
    cursor.finish()?;
    Ok(event)
}

fn encode_ledger(ledger: &BTreeMap<RequestKey, LedgerRecord>) -> Result<Vec<u8>, ServiceError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LEDGER_PLAINTEXT_MAGIC);
    write_u32(
        &mut bytes,
        u32::try_from(ledger.len()).map_err(|_| ServiceError::CorruptState)?,
    );
    for (key, record) in ledger {
        encode_request_key(&mut bytes, key)?;
        bytes.extend_from_slice(&record.binding_digest);
        encode_string_checked(&mut bytes, &record.recovery_reference)?;
        write_u64(&mut bytes, record.generation);
    }
    Ok(bytes)
}

fn decode_ledger(bytes: &[u8]) -> Result<BTreeMap<RequestKey, LedgerRecord>, ServiceError> {
    if bytes.len() < 4 || &bytes[..4] != LEDGER_PLAINTEXT_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&bytes[4..]);
    let count = usize::try_from(cursor.read_u32()?).map_err(|_| ServiceError::CorruptState)?;
    if count > MAX_RECORDS {
        return Err(ServiceError::CorruptState);
    }
    let mut ledger = BTreeMap::new();
    for _ in 0..count {
        let key = decode_request_key(&mut cursor)?;
        let binding_digest = cursor.read_array_32()?;
        let recovery_reference = cursor.read_string(128)?;
        let generation = cursor.read_u64()?;
        let record = LedgerRecord {
            binding_digest,
            recovery_reference,
            generation,
        };
        if ledger.insert(key, record).is_some() {
            return Err(ServiceError::CorruptState);
        }
    }
    cursor.finish()?;
    Ok(ledger)
}

fn encode_marker(bytes: &mut Vec<u8>, marker: &CommitMarker) -> Result<(), ServiceError> {
    encode_request_key(bytes, &marker.key)?;
    bytes.extend_from_slice(&marker.binding_digest);
    encode_string_checked(bytes, &marker.recovery_reference)?;
    write_u64(bytes, marker.generation);
    Ok(())
}

fn decode_marker(cursor: &mut Cursor<'_>) -> Result<CommitMarker, ServiceError> {
    let marker = CommitMarker {
        key: decode_request_key(cursor)?,
        binding_digest: cursor.read_array_32()?,
        recovery_reference: cursor.read_string(128)?,
        generation: cursor.read_u64()?,
    };
    validate_marker(&marker)?;
    Ok(marker)
}

fn validate_marker(marker: &CommitMarker) -> Result<(), ServiceError> {
    validate_identifier(&marker.key.principal)?;
    validate_namespace(&marker.key.namespace)?;
    validate_identifier(&marker.key.request_id)?;
    if marker.binding_digest == [0; 32]
        || marker.recovery_reference.len() != 32
        || !marker
            .recovery_reference
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || marker.generation == 0
    {
        return Err(ServiceError::CorruptState);
    }
    Ok(())
}

fn encode_request_key(bytes: &mut Vec<u8>, key: &RequestKey) -> Result<(), ServiceError> {
    encode_string_checked(bytes, &key.principal)?;
    encode_string_checked(bytes, &key.namespace)?;
    encode_string_checked(bytes, &key.request_id)?;
    Ok(())
}

fn decode_request_key(cursor: &mut Cursor<'_>) -> Result<RequestKey, ServiceError> {
    let key = RequestKey {
        principal: cursor.read_string(256)?,
        namespace: cursor.read_string(1024)?,
        request_id: cursor.read_string(256)?,
    };
    validate_identifier(&key.principal)?;
    validate_namespace(&key.namespace)?;
    validate_identifier(&key.request_id)?;
    Ok(key)
}

fn encode_string_checked(bytes: &mut Vec<u8>, value: &str) -> Result<(), ServiceError> {
    if value.len() > MAX_STRING_BYTES * 2 {
        return Err(ServiceError::CorruptState);
    }
    write_bytes(bytes, value.as_bytes())
}

fn encode_string(bytes: &mut Vec<u8>, value: &str) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn write_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ServiceError> {
    let length = u32::try_from(value.len()).map_err(|_| ServiceError::CorruptState)?;
    write_u32(output, length);
    output.extend_from_slice(value);
    Ok(())
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], ServiceError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ServiceError::CorruptState)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ServiceError::CorruptState)?;
        self.position = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, ServiceError> {
        let bytes = self.read_exact(1)?;
        bytes.first().copied().ok_or(ServiceError::CorruptState)
    }

    fn read_u32(&mut self) -> Result<u32, ServiceError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| ServiceError::CorruptState)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u16(&mut self) -> Result<u16, ServiceError> {
        let bytes: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| ServiceError::CorruptState)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, ServiceError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| ServiceError::CorruptState)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_array_32(&mut self) -> Result<[u8; 32], ServiceError> {
        self.read_exact(32)?
            .try_into()
            .map_err(|_| ServiceError::CorruptState)
    }

    fn read_bytes(&mut self, maximum: usize) -> Result<&'a [u8], ServiceError> {
        let length = usize::try_from(self.read_u32()?).map_err(|_| ServiceError::CorruptState)?;
        if length > maximum {
            return Err(ServiceError::CorruptState);
        }
        self.read_exact(length)
    }

    fn read_string(&mut self, maximum: usize) -> Result<String, ServiceError> {
        let bytes = self.read_bytes(maximum)?;
        let value = std::str::from_utf8(bytes).map_err(|_| ServiceError::CorruptState)?;
        Ok(value.to_owned())
    }

    fn finish(&self) -> Result<(), ServiceError> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(ServiceError::CorruptState)
        }
    }
}

fn snapshot_context(generation: u64) -> Vec<u8> {
    context_with_u64(b"heptabao.durable-service.snapshot.v2", generation)
}

fn journal_context(sequence: u64) -> Vec<u8> {
    context_with_u64(b"heptabao.durable-service.journal.v2", sequence)
}

fn ledger_context(generation: u64) -> Vec<u8> {
    context_with_u64(b"heptabao.durable-service.ledger.v2", generation)
}

fn context_with_u64(domain: &[u8], value: u64) -> Vec<u8> {
    let mut context = Vec::with_capacity(domain.len() + 8);
    context.extend_from_slice(domain);
    context.extend_from_slice(&value.to_le_bytes());
    context
}

fn recovery_reference(binding_digest: &[u8; 32], generation: u64, intent_sequence: u64) -> String {
    let mut bytes = Vec::with_capacity(48);
    bytes.extend_from_slice(binding_digest);
    bytes.extend_from_slice(&generation.to_le_bytes());
    bytes.extend_from_slice(&intent_sequence.to_le_bytes());
    let digest = digest32(b"heptabao.durable-service.recovery.v2", &bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut reference = String::with_capacity(32);
    for byte in &digest[..16] {
        reference.push(char::from(HEX[usize::from(byte >> 4)]));
        reference.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    reference
}

fn digest32(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let domain_len = u64::try_from(domain.len()).unwrap_or(u64::MAX);
    let bytes_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut hasher = Sha256::new();
    hasher.update(domain_len.to_le_bytes());
    hasher.update(domain);
    hasher.update(bytes_len.to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);
    // fork+exec transiently inherits descriptors from every thread, even those
    // marked CLOEXEC. Serialize process-spawning tests with all writer owners.
    static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial_test() -> std::sync::MutexGuard<'static, ()> {
        match TEST_SERIAL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[derive(Clone)]
    struct TestBarrier {
        key: [u8; 32],
    }

    impl TestBarrier {
        const fn new() -> Self {
            Self { key: [0x5a; 32] }
        }

        fn tag(&self, context: &[u8], ciphertext: &[u8]) -> [u8; 32] {
            let mut material = Vec::new();
            material.extend_from_slice(&self.key);
            material.extend_from_slice(context);
            material.extend_from_slice(ciphertext);
            digest32(b"heptabao.test-barrier.v1", &material)
        }
    }

    impl Barrier for TestBarrier {
        fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
            let ciphertext: Vec<u8> = plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
                .collect();
            let mut protected = Vec::with_capacity(32 + ciphertext.len());
            protected.extend_from_slice(&self.tag(context, &ciphertext));
            protected.extend_from_slice(&ciphertext);
            Ok(protected)
        }

        fn open(&self, context: &[u8], protected: &[u8]) -> Result<Vec<u8>, BarrierError> {
            let (tag, ciphertext) = protected.split_at_checked(32).ok_or(BarrierError)?;
            if !constant_time_eq(tag, &self.tag(context, ciphertext)) {
                return Err(BarrierError);
            }
            Ok(ciphertext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
                .collect())
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Result<Self, ServiceError> {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "heptabao-durable-service-{label}-{}-{sequence}",
                std::process::id()
            ));
            if path.exists() {
                fs::remove_dir_all(&path)?;
            }
            Ok(Self(path))
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn digest(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn put_request(id: &str, value: &[u8]) -> Result<PutRequest, ServiceError> {
        PutRequest::new(
            "principal-a",
            "root/team-a",
            id,
            "secret/application",
            digest(7),
            Secret::new(value.to_vec())?,
        )
    }

    fn recovery_from_result(
        result: Result<MutationOutcome, ServiceError>,
    ) -> Result<String, ServiceError> {
        match result {
            Err(ServiceError::OutcomeUnknown { recovery_reference }) => Ok(recovery_reference),
            Err(other) => Err(other),
            Ok(_) => Err(ServiceError::CorruptState),
        }
    }

    #[test]
    fn put_restart_read_and_duplicate_are_durable() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("restart")?;
        let barrier = TestBarrier::new();
        let request = put_request("request-1", b"top-secret-value")?;
        let mut service = DurableService::create_new(&root.0, barrier.clone(), 16)?;
        let outcome = service.put(request.clone())?;
        assert!(matches!(
            outcome,
            MutationOutcome::Committed { generation: 1, .. }
        ));
        drop(service);

        let mut reopened = DurableService::reopen(&root.0, barrier, 16)?;
        let secret = reopened
            .get("root/team-a", "secret/application")?
            .ok_or(ServiceError::CorruptState)?;
        assert_eq!(secret.expose(), b"top-secret-value");
        assert!(matches!(
            reopened.put(request)?,
            MutationOutcome::Duplicate { generation: 1, .. }
        ));
        assert_eq!(reopened.generation(), 1);
        Ok(())
    }

    #[test]
    fn published_snapshot_is_reconciled_after_restart() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("published")?;
        let barrier = TestBarrier::new();
        let request = put_request("request-2", b"committed-before-reply")?;
        let mut service = DurableService::create_new(&root.0, barrier.clone(), 16)?;
        let recovery_reference = recovery_from_result(
            service.put_with_failpoint(request.clone(), Failpoint::AfterSnapshotPublication),
        )?;
        drop(service);

        let mut reopened = DurableService::reopen(&root.0, barrier, 16)?;
        assert_eq!(
            reopened.reconcile(&recovery_reference),
            ReconciliationStatus::Committed { generation: 1 }
        );
        assert!(matches!(
            reopened.put(request)?,
            MutationOutcome::Duplicate { generation: 1, .. }
        ));
        Ok(())
    }

    #[test]
    fn intent_without_publication_is_aborted_and_retryable() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("intent")?;
        let barrier = TestBarrier::new();
        let request = put_request("request-3", b"not-yet-published")?;
        let mut service = DurableService::create_new(&root.0, barrier.clone(), 16)?;
        let recovery_reference = recovery_from_result(
            service.put_with_failpoint(request.clone(), Failpoint::AfterIntent),
        )?;
        drop(service);

        let mut reopened = DurableService::reopen(&root.0, barrier, 16)?;
        assert_eq!(
            reopened.reconcile(&recovery_reference),
            ReconciliationStatus::Aborted
        );
        let retry_recovery_reference = match reopened.put(request)? {
            MutationOutcome::Committed {
                generation: 1,
                recovery_reference,
            } => recovery_reference,
            _ => return Err(ServiceError::CorruptState),
        };
        assert_ne!(recovery_reference, retry_recovery_reference);
        assert_eq!(
            reopened.reconcile(&recovery_reference),
            ReconciliationStatus::Aborted
        );
        Ok(())
    }

    #[test]
    fn commit_journal_rebuilds_missing_ledger() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("ledger")?;
        let barrier = TestBarrier::new();
        let request = put_request("request-4", b"ledger-rebuild")?;
        let mut service = DurableService::create_new(&root.0, barrier.clone(), 16)?;
        let recovery_reference = recovery_from_result(
            service.put_with_failpoint(request.clone(), Failpoint::AfterCommitJournal),
        )?;
        drop(service);

        let mut reopened = DurableService::reopen(&root.0, barrier, 16)?;
        assert_eq!(
            reopened.reconcile(&recovery_reference),
            ReconciliationStatus::Committed { generation: 1 }
        );
        assert!(matches!(
            reopened.put(request)?,
            MutationOutcome::Duplicate { generation: 1, .. }
        ));
        Ok(())
    }

    #[test]
    fn namespace_keys_do_not_collide() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("namespace")?;
        let barrier = TestBarrier::new();
        let mut service = DurableService::create_new(&root.0, barrier, 16)?;
        service.put(PutRequest::new(
            "principal-a",
            "root/team-a",
            "request-a",
            "secret/shared",
            digest(1),
            Secret::new(b"team-a".to_vec())?,
        )?)?;
        service.put(PutRequest::new(
            "principal-b",
            "root/team-b",
            "request-b",
            "secret/shared",
            digest(2),
            Secret::new(b"team-b".to_vec())?,
        )?)?;
        assert_eq!(
            service
                .get("root/team-a", "secret/shared")?
                .ok_or(ServiceError::CorruptState)?
                .expose(),
            b"team-a"
        );
        assert_eq!(
            service
                .get("root/team-b", "secret/shared")?
                .ok_or(ServiceError::CorruptState)?
                .expose(),
            b"team-b"
        );
        Ok(())
    }

    #[test]
    fn capacity_never_evicts_committed_request_identity() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("capacity")?;
        let barrier = TestBarrier::new();
        let first = put_request("request-old", b"first")?;
        let second = put_request("request-new", b"second")?;
        let mut service = DurableService::create_new(&root.0, barrier, 1)?;
        service.put(first.clone())?;
        assert!(matches!(
            service.put(second),
            Err(ServiceError::RequestCapacityExhausted)
        ));
        assert!(matches!(
            service.put(first)?,
            MutationOutcome::Duplicate { generation: 1, .. }
        ));
        assert_eq!(service.generation(), 1);
        Ok(())
    }

    #[test]
    fn request_identity_is_exact_operation_bound() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("binding")?;
        let barrier = TestBarrier::new();
        let mut service = DurableService::create_new(&root.0, barrier, 4)?;
        service.put(put_request("request-bound", b"first")?)?;
        assert!(matches!(
            service.put(put_request("request-bound", b"different")?),
            Err(ServiceError::RequestBindingConflict)
        ));
        Ok(())
    }

    #[test]
    fn writer_fence_and_secret_redaction_hold() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("fence")?;
        let barrier = TestBarrier::new();
        let mut service = DurableService::create_new(&root.0, barrier.clone(), 4)?;
        assert!(matches!(
            DurableService::reopen(&root.0, barrier, 4),
            Err(ServiceError::WriterLocked)
        ));
        let request = put_request("request-redacted", b"never-print-this")?;
        assert!(!format!("{request:?}").contains("never-print-this"));
        service.put(request)?;
        assert!(!format!("{service:?}").contains("secret/application"));
        Ok(())
    }

    #[test]
    fn persisted_files_do_not_contain_plaintext_secret() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("sealed")?;
        let barrier = TestBarrier::new();
        let secret = b"plaintext-must-not-appear";
        let mut service = DurableService::create_new(&root.0, barrier, 4)?;
        service.put(put_request("request-sealed", secret)?)?;
        for name in ["state.hbs", "journal.hbj", "ledger.hbl"] {
            let bytes = read_bounded(&root.0.join(name))?;
            assert!(!bytes.windows(secret.len()).any(|window| window == secret));
        }
        Ok(())
    }

    #[test]
    fn corruption_and_wrong_barrier_fail_closed() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("corruption")?;
        let barrier = TestBarrier::new();
        let mut service = DurableService::create_new(&root.0, barrier.clone(), 4)?;
        service.put(put_request("request-corrupt", b"value")?)?;
        drop(service);

        let mut bytes = read_bounded(&snapshot_path(&root.0))?;
        let index = bytes
            .len()
            .checked_sub(33)
            .ok_or(ServiceError::CorruptState)?;
        bytes[index] ^= 0x80;
        fs::write(snapshot_path(&root.0), bytes)?;
        assert!(matches!(
            DurableService::reopen(&root.0, barrier, 4),
            Err(ServiceError::CorruptState | ServiceError::BarrierFailure)
        ));
        Ok(())
    }
    #[test]
    fn ambiguous_namespace_resource_pairs_are_isolated_across_restart_and_delete()
    -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("tuple-key")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
        for (namespace, resource, id, value) in [
            ("a", "b/c", "one", b"first".as_slice()),
            ("a/b", "c", "two", b"second".as_slice()),
        ] {
            service.put(PutRequest::new(
                "p",
                namespace,
                id,
                resource,
                digest(1),
                Secret::new(value.to_vec())?,
            )?)?;
        }
        drop(service);
        let mut service = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        assert_eq!(
            service.get("a", "b/c")?.map(|s| s.expose().to_vec()),
            Some(b"first".to_vec())
        );
        assert_eq!(
            service.get("a/b", "c")?.map(|s| s.expose().to_vec()),
            Some(b"second".to_vec())
        );
        assert_eq!(service.list("a", "")?, vec!["b/"]);
        assert_eq!(service.list("a/b", "")?, vec!["c"]);
        service.delete(DeleteRequest::new("p", "a", "delete", "b/c", digest(1))?)?;
        drop(service);
        let service = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        assert_eq!(service.get("a", "b/c")?, None);
        assert_eq!(
            service.get("a/b", "c")?.map(|s| s.expose().to_vec()),
            Some(b"second".to_vec())
        );
        Ok(())
    }

    #[test]
    fn legacy_schema_is_rejected_without_rewriting_it() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("legacy-schema")?;
        let service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
        drop(service);
        let mut encoded = fs::read(snapshot_path(&root.0))?;
        encoded[..4].copy_from_slice(b"HBS1");
        fs::write(snapshot_path(&root.0), &encoded)?;
        assert!(matches!(
            DurableService::reopen(&root.0, TestBarrier::new(), 16),
            Err(ServiceError::LegacySchema)
        ));
        assert_eq!(fs::read(snapshot_path(&root.0))?, encoded);
        Ok(())
    }

    #[test]
    fn genuine_snapshot_and_ledger_io_faults_preserve_recovery_reference()
    -> Result<(), ServiceError> {
        let _serial = serial_test();
        for (blocked, expected) in [
            ("state.tmp", ReconciliationStatus::Aborted),
            (
                "ledger.tmp",
                ReconciliationStatus::Committed { generation: 1 },
            ),
        ] {
            let root = TestRoot::new(blocked)?;
            let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
            fs::create_dir(root.0.join(blocked))?; // Actual EISDIR from the persistence open.
            let reference = recovery_from_result(service.put(put_request("io-fault", b"secret")?))?;
            assert!(service.recovery_required());
            assert!(matches!(
                service.get("root/team-a", "secret/application"),
                Err(ServiceError::RecoveryRequired)
            ));
            assert!(matches!(
                service.put(put_request("next", b"next")?),
                Err(ServiceError::RecoveryRequired)
            ));
            drop(service);
            fs::remove_dir(root.0.join(blocked))?;
            let mut reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
            assert_eq!(reopened.reconcile(&reference), expected);
            reopened.put(put_request("next", b"next")?)?;
        }
        Ok(())
    }

    #[test]
    fn failed_append_does_not_consume_sequence_and_reopen_recovers() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("append-io")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
        fs::rename(journal_path(&root.0), root.0.join("journal.saved"))?;
        fs::create_dir(journal_path(&root.0))?;
        let _reference =
            recovery_from_result(service.put(put_request("failed-append", b"secret")?))?;
        assert_eq!(service.journal_sequence, 0);
        assert!(service.recovery_required());
        drop(service);
        fs::remove_dir(journal_path(&root.0))?;
        fs::rename(root.0.join("journal.saved"), journal_path(&root.0))?;
        let mut reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        reopened.put(put_request("successful-append", b"secret")?)?;
        drop(reopened);
        assert_eq!(
            DurableService::reopen(&root.0, TestBarrier::new(), 16)?.generation(),
            1
        );
        Ok(())
    }

    #[test]
    fn authenticated_old_snapshot_and_contradictory_ledger_fail_closed() -> Result<(), ServiceError>
    {
        let _serial = serial_test();
        let root = TestRoot::new("snapshot-rollback")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
        service.put(put_request("one", b"one")?)?;
        let old_snapshot = fs::read(snapshot_path(&root.0))?;
        service.put(put_request("two", b"two")?)?;
        let current_snapshot = fs::read(snapshot_path(&root.0))?;
        let ledger = service.ledger.clone();
        drop(service);
        fs::write(snapshot_path(&root.0), old_snapshot)?;
        assert!(matches!(
            DurableService::reopen(&root.0, TestBarrier::new(), 16),
            Err(ServiceError::CorruptState)
        ));
        fs::write(snapshot_path(&root.0), current_snapshot)?;
        persist_ledger(&root.0, &TestBarrier::new(), 1, &ledger)?;
        assert!(matches!(
            DurableService::reopen(&root.0, TestBarrier::new(), 16),
            Err(ServiceError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn journal_budget_reserves_terminal_record_before_entry() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("journal-budget")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
        service.journal_limit = JOURNAL_MAGIC.len() + 1;
        assert!(matches!(
            service.put(put_request("full", b"value")?),
            Err(ServiceError::JournalCapacityExhausted)
        ));
        assert_eq!(
            fs::metadata(journal_path(&root.0))?.len(),
            JOURNAL_MAGIC.len() as u64
        );
        assert!(!service.recovery_required());
        service.journal_limit = MAX_FILE_BYTES;
        service.put(put_request("accepted", b"value")?)?;
        Ok(())
    }

    #[test]
    fn compaction_checkpoints_complete_ledger_and_allows_future_commits() -> Result<(), ServiceError>
    {
        let _serial = serial_test();
        let root = TestRoot::new("compaction")?;
        let barrier = TestBarrier::new();
        let mut service = DurableService::create_new(&root.0, barrier.clone(), 64)?;
        let first = put_request("compact-0", b"value-0")?;
        service.put(first.clone())?;
        for number in 1..12 {
            service.put(put_request(
                &format!("compact-{number}"),
                format!("value-{number}").as_bytes(),
            )?)?;
        }
        let before = fs::metadata(journal_path(&root.0))?.len() as usize;
        let outcome = service.compact()?;
        assert_eq!(outcome.generation, 12);
        assert_eq!(outcome.retained_requests, 12);
        assert_eq!(outcome.journal_bytes_before, before);
        assert!(outcome.journal_bytes_after < before);
        assert!(matches!(
            service.put(first)?,
            MutationOutcome::Duplicate { generation: 1, .. }
        ));
        service.put(put_request("after-compact", b"future")?)?;
        drop(service);

        let mut reopened = DurableService::reopen(&root.0, barrier, 64)?;
        assert_eq!(reopened.generation(), 13);
        assert_eq!(reopened.retained_request_count(), 13);
        assert_eq!(
            reopened
                .get("root/team-a", "secret/application")?
                .ok_or(ServiceError::CorruptState)?
                .expose(),
            b"future"
        );
        reopened.put(put_request("after-reopen", b"still-live")?)?;
        Ok(())
    }

    #[test]
    fn encrypted_backup_restores_exact_generation_and_requires_explicit_rollback()
    -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("backup")?;
        let barrier = TestBarrier::new();
        let first = put_request("backup-one", b"one")?;
        let second = put_request("backup-two", b"two")?;
        let mut service = DurableService::create_new(&root.0, barrier.clone(), 16)?;
        let first_outcome = service.put(first.clone())?;
        let first_reference = match first_outcome {
            MutationOutcome::Committed {
                recovery_reference, ..
            } => recovery_reference,
            _ => return Err(ServiceError::CorruptState),
        };
        let backup = service.export_backup()?;
        service.put(second)?;
        assert!(matches!(
            service.restore_backup(&backup, false),
            Err(ServiceError::BackupRollbackRejected)
        ));
        let outcome = service.restore_backup(&backup, true)?;
        assert_eq!(outcome.previous_generation, 2);
        assert_eq!(outcome.restored_generation, 1);
        assert_eq!(outcome.retained_requests, 1);
        assert_eq!(
            service
                .get("root/team-a", "secret/application")?
                .ok_or(ServiceError::CorruptState)?
                .expose(),
            b"one"
        );
        assert_eq!(
            service.reconcile(&first_reference),
            ReconciliationStatus::Committed { generation: 1 }
        );
        assert!(matches!(
            service.put(first)?,
            MutationOutcome::Duplicate { generation: 1, .. }
        ));
        drop(service);
        assert_eq!(
            DurableService::reopen(&root.0, barrier, 16)?.generation(),
            1
        );
        Ok(())
    }

    #[test]
    fn backup_tampering_fails_before_live_state_is_fenced() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("backup-tamper")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
        service.put(put_request("backup-source", b"value")?)?;
        let mut backup = service.export_backup()?;
        let index = backup.len() / 2;
        backup[index] ^= 1;
        assert!(matches!(
            service.restore_backup(&backup, true),
            Err(ServiceError::CorruptState)
        ));
        assert!(!service.recovery_required());
        service.put(put_request("backup-after-tamper", b"safe")?)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_sigkill_releases_writer_and_recovers_pending_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let _serial = serial_test();
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        const MODE: &str = "HEPTABAO_DURABLE_SIGKILL_ROOT";
        const TEST: &str = "tests::actual_sigkill_releases_writer_and_recovers_pending_publication";
        if let Some(root) = std::env::var_os(MODE) {
            let mut service =
                DurableService::create_new(PathBuf::from(root), TestBarrier::new(), 16)?;
            let reference = recovery_from_result(service.put_with_failpoint(
                put_request("killed", b"survives-kill")?,
                Failpoint::AfterSnapshotPublication,
            ))?;
            println!("READY:{reference}");
            std::io::stdout().flush()?;
            loop {
                std::thread::park();
            }
        }
        let root = TestRoot::new("actual-sigkill")?;
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", TEST, "--nocapture"])
            .env(MODE, &root.0)
            .stdout(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("missing child stdout"))?;
        let mut reference = None;
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            if let Some(value) = line.strip_prefix("READY:") {
                reference = Some(value.to_owned());
                break;
            }
        }
        assert!(reference.is_some());
        assert!(matches!(
            DurableService::reopen(&root.0, TestBarrier::new(), 16),
            Err(ServiceError::WriterLocked)
        ));
        child.kill()?; // SIGKILL: no Rust destructor or cooperative cleanup.
        let status = child.wait()?;
        assert!(!status.success());
        let mut service = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        assert_eq!(
            service.reconcile(reference.as_deref().ok_or(ServiceError::CorruptState)?),
            ReconciliationStatus::Committed { generation: 1 }
        );
        assert_eq!(
            service
                .get("root/team-a", "secret/application")?
                .map(|s| s.expose().to_vec()),
            Some(b"survives-kill".to_vec())
        );
        service.put(put_request("after-kill", b"live")?)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_partial_write_efbig_tail_is_recovered() -> Result<(), Box<dyn std::error::Error>> {
        let _serial = serial_test();
        use std::process::Command;
        const MODE: &str = "HEPTABAO_DURABLE_EFBIG_ROOT";
        const TEST: &str = "tests::real_partial_write_efbig_tail_is_recovered";
        if let Some(root) = std::env::var_os(MODE) {
            let root = PathBuf::from(root);
            let mut service = DurableService::create_new(&root, TestBarrier::new(), 16)?;
            for number in 0..16 {
                let before = fs::metadata(journal_path(&root))?.len();
                match service.put(put_request(&format!("limited-{number}"), b"value")?) {
                    Ok(_) => {}
                    Err(ServiceError::OutcomeUnknown { recovery_reference }) => {
                        let after = fs::metadata(journal_path(&root))?.len();
                        // Linux RLIMIT_FSIZE makes write_all partially write the
                        // last frame then return EFBIG, without simulated hooks.
                        assert_eq!(after, 1024);
                        assert!(after > before);
                        assert!(service.journal_bytes as u64 >= before);
                        assert!((service.journal_bytes as u64) < after);
                        fs::write(root.join("failure-reference"), recovery_reference)?;
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            return Err(
                std::io::Error::other("file size limit did not cause a write failure").into(),
            );
        }
        let root = TestRoot::new("actual-efbig")?;
        // The size limit applies to EVERY regular file, including stdout when
        // the parent suite redirects it to a log larger than 1024 bytes. Capture
        // child output through pipes so libtest reporting cannot fail with EFBIG
        // before the actual storage experiment starts.
        let output = Command::new("bash")
            .args([
                "-c",
                "ulimit -f 1; trap '' XFSZ; exec \"$@\"",
                "heptabao-efbig",
            ])
            .arg(std::env::current_exe()?)
            .args(["--exact", TEST, "--nocapture"])
            .env(MODE, &root.0)
            .output()?;
        assert!(
            output.status.success(),
            "EFBIG subprocess status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let _reference = fs::read_to_string(root.0.join("failure-reference"))?;
        let mut reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        reopened.put(put_request("after-efbig", b"restored")?)?;
        drop(reopened);
        let reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        assert_eq!(
            reopened
                .get("root/team-a", "secret/application")?
                .map(|s| s.expose().to_vec()),
            Some(b"restored".to_vec())
        );
        Ok(())
    }
}
