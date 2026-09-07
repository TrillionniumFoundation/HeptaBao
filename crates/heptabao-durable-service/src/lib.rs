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

use sha2::{Digest, Sha256};

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SNAPSHOT_MAGIC: &[u8; 4] = b"HBS1";
const SNAPSHOT_PLAINTEXT_MAGIC: &[u8; 4] = b"HBP1";
const JOURNAL_MAGIC: &[u8; 4] = b"HBJ1";
const LEDGER_MAGIC: &[u8; 4] = b"HBL1";
const LEDGER_PLAINTEXT_MAGIC: &[u8; 4] = b"HBC1";
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
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

#[derive(Debug)]
pub enum ServiceError {
    InvalidRoot,
    RootNotEmpty,
    WriterLocked,
    InvalidIdentifier,
    InvalidNamespace,
    InvalidResource,
    InvalidSecret,
    InvalidAuthorizationDigest,
    RequestBindingConflict,
    RequestCapacityExhausted,
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

    fn storage_key(&self) -> String {
        format!("{}/{}", self.key.namespace, self.resource)
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
struct Snapshot {
    generation: u64,
    entries: BTreeMap<String, Vec<u8>>,
    last_commit: Option<CommitMarker>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JournalEvent {
    Intent(CommitMarker),
    Commit(CommitMarker),
    Abort(CommitMarker),
}

pub struct DurableService<B: Barrier> {
    root: PathBuf,
    lock_path: PathBuf,
    barrier: B,
    snapshot: Snapshot,
    ledger: BTreeMap<RequestKey, LedgerRecord>,
    reconciliation: BTreeMap<String, ReconciliationStatus>,
    journal_sequence: u64,
    max_retained_requests: usize,
    unresolved: bool,
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
        let lock_path = acquire_writer_lock(&root)?;
        let snapshot = Snapshot {
            generation: 0,
            entries: BTreeMap::new(),
            last_commit: None,
        };
        let ledger = BTreeMap::new();
        let result = (|| {
            persist_snapshot(&root, &barrier, &snapshot)?;
            initialize_journal(&root)?;
            persist_ledger(&root, &barrier, 0, &ledger)?;
            Ok(Self {
                root,
                lock_path: lock_path.clone(),
                barrier,
                snapshot,
                ledger,
                reconciliation: BTreeMap::new(),
                journal_sequence: 0,
                max_retained_requests,
                unresolved: false,
            })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&lock_path);
        }
        result
    }

    pub fn reopen(
        root: impl AsRef<Path>,
        barrier: B,
        max_retained_requests: usize,
    ) -> Result<Self, ServiceError> {
        validate_capacity(max_retained_requests)?;
        let root = validate_root(root.as_ref(), false)?;
        let lock_path = acquire_writer_lock(&root)?;
        let result = (|| {
            let snapshot = load_snapshot(&root, &barrier)?;
            let (journal_sequence, events) = load_journal(&root, &barrier)?;
            let ledger = load_ledger(&root, &barrier)?;
            let mut service = Self {
                root,
                lock_path: lock_path.clone(),
                barrier,
                snapshot,
                ledger,
                reconciliation: BTreeMap::new(),
                journal_sequence,
                max_retained_requests,
                unresolved: false,
            };
            service.recover(events)?;
            Ok(service)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&lock_path);
        }
        result
    }

    pub fn put(&mut self, request: PutRequest) -> Result<MutationOutcome, ServiceError> {
        self.put_with_failpoint(request, Failpoint::None)
    }

    pub fn put_with_failpoint(
        &mut self,
        request: PutRequest,
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
        self.execute(binding, Some(request.value.0), failpoint)
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
        let key = format!("{namespace}/{resource}");
        Ok(self.snapshot.entries.get(&key).cloned().map(Secret))
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

    fn execute(
        &mut self,
        binding: Binding,
        value: Option<Vec<u8>>,
        failpoint: Failpoint,
    ) -> Result<MutationOutcome, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RequestCapacityExhausted);
        }
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
        let recovery_reference = recovery_reference(&binding_digest, generation, intent_sequence);
        if self.reconciliation.contains_key(&recovery_reference) {
            return Err(ServiceError::RequestBindingConflict);
        }
        let marker = CommitMarker {
            key: binding.key.clone(),
            binding_digest,
            recovery_reference: recovery_reference.clone(),
            generation,
        };
        self.append_event(&JournalEvent::Intent(marker.clone()))?;
        self.unresolved = true;
        if failpoint == Failpoint::AfterIntent {
            return Err(ServiceError::OutcomeUnknown { recovery_reference });
        }

        let mut candidate = self.snapshot.clone();
        candidate.generation = generation;
        candidate.last_commit = Some(marker.clone());
        let storage_key = binding.storage_key();
        match binding.kind {
            MutationKind::Put => {
                let secret = value.ok_or(ServiceError::InvalidSecret)?;
                candidate.entries.insert(storage_key, secret);
            }
            MutationKind::Delete => {
                candidate.entries.remove(&storage_key);
            }
        }
        persist_snapshot(&self.root, &self.barrier, &candidate)?;
        self.snapshot = candidate;
        if failpoint == Failpoint::AfterSnapshotPublication {
            return Err(ServiceError::OutcomeUnknown { recovery_reference });
        }

        self.append_event(&JournalEvent::Commit(marker.clone()))?;
        if failpoint == Failpoint::AfterCommitJournal {
            return Err(ServiceError::OutcomeUnknown { recovery_reference });
        }

        let record = LedgerRecord {
            binding_digest,
            recovery_reference: recovery_reference.clone(),
            generation,
        };
        self.ledger.insert(binding.key, record);
        persist_ledger(
            &self.root,
            &self.barrier,
            self.snapshot.generation,
            &self.ledger,
        )?;
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

    fn append_event(&mut self, event: &JournalEvent) -> Result<(), ServiceError> {
        self.journal_sequence = self
            .journal_sequence
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        append_journal_record(&self.root, &self.barrier, self.journal_sequence, event)
    }

    fn recover(&mut self, events: Vec<JournalEvent>) -> Result<(), ServiceError> {
        let mut pending: BTreeMap<RequestKey, CommitMarker> = BTreeMap::new();
        let mut committed: BTreeMap<RequestKey, CommitMarker> = BTreeMap::new();
        for event in events {
            match event {
                JournalEvent::Intent(marker) => {
                    validate_marker(&marker)?;
                    if let Some(previous) = pending.get(&marker.key)
                        && previous != &marker
                    {
                        return Err(ServiceError::CorruptState);
                    }
                    pending.insert(marker.key.clone(), marker);
                }
                JournalEvent::Commit(marker) => {
                    validate_marker(&marker)?;
                    let Some(intent) = pending.get(&marker.key) else {
                        return Err(ServiceError::CorruptState);
                    };
                    if intent != &marker {
                        return Err(ServiceError::CorruptState);
                    }
                    committed.insert(marker.key.clone(), marker.clone());
                    pending.remove(&marker.key);
                }
                JournalEvent::Abort(marker) => {
                    validate_marker(&marker)?;
                    let Some(intent) = pending.get(&marker.key) else {
                        return Err(ServiceError::CorruptState);
                    };
                    if intent != &marker {
                        return Err(ServiceError::CorruptState);
                    }
                    self.reconciliation.insert(
                        marker.recovery_reference.clone(),
                        ReconciliationStatus::Aborted,
                    );
                    pending.remove(&marker.key);
                }
            }
        }

        for (key, record) in &self.ledger {
            let Some(marker) = committed.get(key) else {
                return Err(ServiceError::CorruptState);
            };
            if marker.binding_digest != record.binding_digest
                || marker.generation != record.generation
                || marker.recovery_reference != record.recovery_reference
            {
                return Err(ServiceError::CorruptState);
            }
            self.reconciliation.insert(
                record.recovery_reference.clone(),
                ReconciliationStatus::Committed {
                    generation: record.generation,
                },
            );
        }

        let missing_ledger: Vec<CommitMarker> = committed
            .into_iter()
            .filter_map(|(key, marker)| (!self.ledger.contains_key(&key)).then_some(marker))
            .collect();
        for marker in missing_ledger {
            if marker.generation > self.snapshot.generation {
                return Err(ServiceError::CorruptState);
            }
            self.ledger.insert(
                marker.key.clone(),
                LedgerRecord {
                    binding_digest: marker.binding_digest,
                    recovery_reference: marker.recovery_reference.clone(),
                    generation: marker.generation,
                },
            );
            self.reconciliation.insert(
                marker.recovery_reference,
                ReconciliationStatus::Committed {
                    generation: marker.generation,
                },
            );
        }

        let pending_markers: Vec<CommitMarker> = pending.into_values().collect();
        for marker in pending_markers {
            let published = self.snapshot.last_commit.as_ref() == Some(&marker)
                && self.snapshot.generation == marker.generation;
            if published {
                self.append_event(&JournalEvent::Commit(marker.clone()))?;
                self.ledger.insert(
                    marker.key.clone(),
                    LedgerRecord {
                        binding_digest: marker.binding_digest,
                        recovery_reference: marker.recovery_reference.clone(),
                        generation: marker.generation,
                    },
                );
                self.reconciliation.insert(
                    marker.recovery_reference,
                    ReconciliationStatus::Committed {
                        generation: marker.generation,
                    },
                );
            } else {
                self.append_event(&JournalEvent::Abort(marker.clone()))?;
                self.reconciliation
                    .insert(marker.recovery_reference, ReconciliationStatus::Aborted);
            }
        }
        if self.ledger.len() > self.max_retained_requests {
            return Err(ServiceError::RequestCapacityExhausted);
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

impl<B: Barrier> Drop for DurableService<B> {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
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

fn acquire_writer_lock(root: &Path) -> Result<PathBuf, ServiceError> {
    let path = root.join("writer.lock");
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(b"heptabao-durable-service-writer-v1\n")?;
            file.sync_all()?;
            Ok(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(ServiceError::WriterLocked)
        }
        Err(error) => Err(ServiceError::Io(error)),
    }
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
    let plaintext = encode_snapshot(snapshot)?;
    let context = snapshot_context(snapshot.generation);
    let protected = barrier
        .seal(&context, &plaintext)
        .map_err(|_| ServiceError::BarrierFailure)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(SNAPSHOT_MAGIC);
    write_u64(&mut encoded, snapshot.generation);
    write_bytes(&mut encoded, &protected)?;
    let checksum = digest32(b"heptabao.durable-service.snapshot-frame.v1", &encoded);
    encoded.extend_from_slice(&checksum);
    atomic_write(root, &snapshot_path(root), &encoded)
}

fn load_snapshot<B: Barrier>(root: &Path, barrier: &B) -> Result<Snapshot, ServiceError> {
    let encoded = read_bounded(&snapshot_path(root))?;
    if encoded.len() < 4 + 8 + 4 + 32 || &encoded[..4] != SNAPSHOT_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let frame_len = encoded
        .len()
        .checked_sub(32)
        .ok_or(ServiceError::CorruptState)?;
    let expected = digest32(
        b"heptabao.durable-service.snapshot-frame.v1",
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
    let snapshot = decode_snapshot(&plaintext)?;
    if snapshot.generation != generation {
        return Err(ServiceError::CorruptState);
    }
    Ok(snapshot)
}

fn initialize_journal(root: &Path) -> Result<(), ServiceError> {
    let path = journal_path(root);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(JOURNAL_MAGIC)?;
    file.sync_all()?;
    sync_parent(root)
}

fn append_journal_record<B: Barrier>(
    root: &Path,
    barrier: &B,
    sequence: u64,
    event: &JournalEvent,
) -> Result<(), ServiceError> {
    let plaintext = encode_journal_event(event)?;
    let protected = barrier
        .seal(&journal_context(sequence), &plaintext)
        .map_err(|_| ServiceError::BarrierFailure)?;
    let mut frame = Vec::new();
    write_u64(&mut frame, sequence);
    write_bytes(&mut frame, &protected)?;
    let checksum = digest32(b"heptabao.durable-service.journal-frame.v1", &frame);
    frame.extend_from_slice(&checksum);
    let frame_len = u32::try_from(frame.len()).map_err(|_| ServiceError::CorruptState)?;
    let path = journal_path(root);
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(&frame_len.to_le_bytes())?;
    file.write_all(&frame)?;
    file.sync_all()?;
    Ok(())
}

fn load_journal<B: Barrier>(
    root: &Path,
    barrier: &B,
) -> Result<(u64, Vec<JournalEvent>), ServiceError> {
    let encoded = read_bounded(&journal_path(root))?;
    if encoded.len() < JOURNAL_MAGIC.len() || &encoded[..4] != JOURNAL_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&encoded[4..]);
    let mut expected_sequence = 1_u64;
    let mut events = Vec::new();
    while !cursor.is_finished() {
        let frame_len =
            usize::try_from(cursor.read_u32()?).map_err(|_| ServiceError::CorruptState)?;
        if !(8 + 4 + 32..=MAX_FILE_BYTES).contains(&frame_len) {
            return Err(ServiceError::CorruptState);
        }
        let frame = cursor.read_exact(frame_len)?;
        let payload_len = frame_len
            .checked_sub(32)
            .ok_or(ServiceError::CorruptState)?;
        let expected = digest32(
            b"heptabao.durable-service.journal-frame.v1",
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
    }
    Ok((expected_sequence.saturating_sub(1), events))
}

fn persist_ledger<B: Barrier>(
    root: &Path,
    barrier: &B,
    generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<(), ServiceError> {
    let plaintext = encode_ledger(ledger)?;
    let protected = barrier
        .seal(&ledger_context(generation), &plaintext)
        .map_err(|_| ServiceError::BarrierFailure)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(LEDGER_MAGIC);
    write_u64(&mut encoded, generation);
    write_bytes(&mut encoded, &protected)?;
    let checksum = digest32(b"heptabao.durable-service.ledger-frame.v1", &encoded);
    encoded.extend_from_slice(&checksum);
    atomic_write(root, &ledger_path(root), &encoded)
}

fn load_ledger<B: Barrier>(
    root: &Path,
    barrier: &B,
) -> Result<BTreeMap<RequestKey, LedgerRecord>, ServiceError> {
    let encoded = read_bounded(&ledger_path(root))?;
    if encoded.len() < 4 + 8 + 4 + 32 || &encoded[..4] != LEDGER_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let frame_len = encoded
        .len()
        .checked_sub(32)
        .ok_or(ServiceError::CorruptState)?;
    let expected = digest32(
        b"heptabao.durable-service.ledger-frame.v1",
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
    decode_ledger(&plaintext)
}

fn atomic_write(root: &Path, target: &Path, bytes: &[u8]) -> Result<(), ServiceError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ServiceError::CorruptState);
    }
    let temporary = target.with_extension("tmp");
    let mut file = OpenOptions::new()
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
    File::open(path)?.read_to_end(&mut bytes)?;
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
    for (key, value) in &snapshot.entries {
        encode_string_checked(&mut bytes, key)?;
        write_bytes(&mut bytes, value)?;
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
        let key = cursor.read_string(MAX_STRING_BYTES * 2)?;
        let value = cursor.read_bytes(MAX_SECRET_BYTES)?.to_vec();
        if entries.insert(key, value).is_some() {
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
    }
    Ok(bytes)
}

fn decode_journal_event(bytes: &[u8]) -> Result<JournalEvent, ServiceError> {
    let mut cursor = Cursor::new(bytes);
    let kind = cursor.read_u8()?;
    let marker = decode_marker(&mut cursor)?;
    cursor.finish()?;
    match kind {
        1 => Ok(JournalEvent::Intent(marker)),
        2 => Ok(JournalEvent::Commit(marker)),
        3 => Ok(JournalEvent::Abort(marker)),
        _ => Err(ServiceError::CorruptState),
    }
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
    context_with_u64(b"heptabao.durable-service.snapshot.v1", generation)
}

fn journal_context(sequence: u64) -> Vec<u8> {
    context_with_u64(b"heptabao.durable-service.journal.v1", sequence)
}

fn ledger_context(generation: u64) -> Vec<u8> {
    context_with_u64(b"heptabao.durable-service.ledger.v1", generation)
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
}
