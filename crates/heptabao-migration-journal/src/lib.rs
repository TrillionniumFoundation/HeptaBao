#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Durable, fail-closed migration transaction journal.
//!
//! The journal provides an authenticated append-only state machine for moving
//! one logical object at a time. A commit whose client-visible outcome is
//! uncertain can only transition to committed after an explicit reconciliation
//! proof binds the observed target digest. Torn tails are repaired under the
//! single-writer lock; authenticated-prefix corruption is rejected.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use ring::{digest, hmac};

const MAGIC: &[u8; 5] = b"HBMJ1";
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_OBJECT_ID_BYTES: usize = 512;
const TAG_BYTES: usize = 32;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct MigrationObjectId(String);

impl MigrationObjectId {
    pub fn parse(value: impl Into<String>) -> Result<Self, JournalError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_OBJECT_ID_BYTES
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains("//")
            || value.split('/').any(|segment| {
                segment.is_empty()
                    || segment == "."
                    || segment == ".."
                    || !segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
                    })
            })
        {
            return Err(JournalError::InvalidObjectId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MigrationObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MigrationObjectId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for MigrationObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MigrationPhase {
    Planned = 1,
    Staged = 2,
    Verified = 3,
    CommitPending = 4,
    Committed = 5,
    RollbackPending = 6,
    RolledBack = 7,
}

impl MigrationPhase {
    fn decode(value: u8) -> Result<Self, JournalError> {
        match value {
            1 => Ok(Self::Planned),
            2 => Ok(Self::Staged),
            3 => Ok(Self::Verified),
            4 => Ok(Self::CommitPending),
            5 => Ok(Self::Committed),
            6 => Ok(Self::RollbackPending),
            7 => Ok(Self::RolledBack),
            _ => Err(JournalError::InvalidRecord),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationRecord {
    pub sequence: u64,
    pub operation_id: [u8; 16],
    pub object_id: MigrationObjectId,
    pub phase: MigrationPhase,
    pub source_digest: [u8; 32],
    pub target_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationProof {
    pub committed: bool,
    pub observed_target_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    InvalidRoot,
    InvalidKey,
    InvalidObjectId,
    InvalidRecord,
    InvalidTransition,
    WriterBusy,
    Tampered,
    SequenceOverflow,
    OutcomeUnknown,
    Io,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRoot => "migration journal root is invalid",
            Self::InvalidKey => "migration journal authentication key is invalid",
            Self::InvalidObjectId => "migration object identifier is invalid",
            Self::InvalidRecord => "migration journal record is invalid",
            Self::InvalidTransition => "migration state transition is invalid",
            Self::WriterBusy => "migration journal already has a writer",
            Self::Tampered => "migration journal authentication failed",
            Self::SequenceOverflow => "migration journal sequence overflow",
            Self::OutcomeUnknown => "migration journal write outcome is unknown",
            Self::Io => "migration journal I/O failed",
        })
    }
}

impl Error for JournalError {}

#[derive(Debug)]
struct WriterLock {
    path: PathBuf,
    _file: File,
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Debug)]
pub struct MigrationJournal {
    root: PathBuf,
    journal_path: PathBuf,
    lock_path: PathBuf,
    journal: File,
    _lock: WriterLock,
    key: [u8; 32],
    next_sequence: u64,
    previous_tag: [u8; TAG_BYTES],
    latest: BTreeMap<MigrationObjectId, MigrationRecord>,
}

impl MigrationJournal {
    pub fn open(root: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, JournalError> {
        if key == [0; 32] {
            return Err(JournalError::InvalidKey);
        }
        let root = root.as_ref().to_path_buf();
        validate_root(&root)?;
        create_private_root(&root)?;
        let lock_path = root.join("writer.lock");
        let journal_path = root.join("migration.journal");
        let lock = create_lock(&lock_path)?;
        let mut journal = open_journal(&journal_path)?;
        let decoded = recover_records(&mut journal, key)?;
        if decoded.valid_bytes < journal.metadata().map_err(|_| JournalError::Io)?.len() {
            journal
                .set_len(decoded.valid_bytes)
                .and_then(|()| journal.sync_all())
                .map_err(|_| JournalError::Io)?;
        }
        journal
            .seek(SeekFrom::End(0))
            .map_err(|_| JournalError::Io)?;
        let next_sequence = decoded
            .last_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        Ok(Self {
            root,
            journal_path,
            lock_path,
            journal,
            _lock: lock,
            key,
            next_sequence,
            previous_tag: decoded.previous_tag,
            latest: decoded.latest,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub fn latest(&self, object_id: &MigrationObjectId) -> Option<&MigrationRecord> {
        self.latest.get(object_id)
    }

    pub fn begin(
        &mut self,
        operation_id: [u8; 16],
        object_id: MigrationObjectId,
        source_digest: [u8; 32],
    ) -> Result<MigrationRecord, JournalError> {
        if operation_id == [0; 16] || source_digest == [0; 32] {
            return Err(JournalError::InvalidRecord);
        }
        if let Some(record) = self.latest.get(&object_id) {
            if record.operation_id == operation_id
                && record.phase == MigrationPhase::Planned
                && record.source_digest == source_digest
            {
                return Ok(record.clone());
            }
            if record.phase != MigrationPhase::RolledBack {
                return Err(JournalError::InvalidTransition);
            }
        }
        self.append(MigrationRecord {
            sequence: 0,
            operation_id,
            object_id,
            phase: MigrationPhase::Planned,
            source_digest,
            target_digest: [0; 32],
        })
    }

    pub fn mark_staged(
        &mut self,
        object_id: &MigrationObjectId,
        target_digest: [u8; 32],
    ) -> Result<MigrationRecord, JournalError> {
        if target_digest == [0; 32] {
            return Err(JournalError::InvalidRecord);
        }
        self.transition(
            object_id,
            MigrationPhase::Planned,
            MigrationPhase::Staged,
            target_digest,
        )
    }

    pub fn mark_verified(
        &mut self,
        object_id: &MigrationObjectId,
    ) -> Result<MigrationRecord, JournalError> {
        let current = self.require(object_id, MigrationPhase::Staged)?.clone();
        self.append(MigrationRecord {
            sequence: 0,
            phase: MigrationPhase::Verified,
            ..current
        })
    }

    pub fn mark_commit_pending(
        &mut self,
        object_id: &MigrationObjectId,
    ) -> Result<MigrationRecord, JournalError> {
        let current = self.require(object_id, MigrationPhase::Verified)?.clone();
        self.append(MigrationRecord {
            sequence: 0,
            phase: MigrationPhase::CommitPending,
            ..current
        })
    }

    pub fn reconcile_commit(
        &mut self,
        object_id: &MigrationObjectId,
        proof: ReconciliationProof,
    ) -> Result<MigrationRecord, JournalError> {
        let current = self
            .require(object_id, MigrationPhase::CommitPending)?
            .clone();
        if !proof.committed || proof.observed_target_digest != current.target_digest {
            return Err(JournalError::InvalidTransition);
        }
        self.append(MigrationRecord {
            sequence: 0,
            phase: MigrationPhase::Committed,
            ..current
        })
    }

    pub fn mark_rollback_pending(
        &mut self,
        object_id: &MigrationObjectId,
    ) -> Result<MigrationRecord, JournalError> {
        let current = self
            .latest
            .get(object_id)
            .ok_or(JournalError::InvalidTransition)?
            .clone();
        if !matches!(
            current.phase,
            MigrationPhase::Planned
                | MigrationPhase::Staged
                | MigrationPhase::Verified
                | MigrationPhase::CommitPending
        ) {
            return Err(JournalError::InvalidTransition);
        }
        self.append(MigrationRecord {
            sequence: 0,
            phase: MigrationPhase::RollbackPending,
            ..current
        })
    }

    pub fn reconcile_rollback(
        &mut self,
        object_id: &MigrationObjectId,
        target_absent: bool,
    ) -> Result<MigrationRecord, JournalError> {
        let current = self
            .require(object_id, MigrationPhase::RollbackPending)?
            .clone();
        if !target_absent {
            return Err(JournalError::InvalidTransition);
        }
        self.append(MigrationRecord {
            sequence: 0,
            phase: MigrationPhase::RolledBack,
            ..current
        })
    }

    fn transition(
        &mut self,
        object_id: &MigrationObjectId,
        expected: MigrationPhase,
        phase: MigrationPhase,
        target_digest: [u8; 32],
    ) -> Result<MigrationRecord, JournalError> {
        let current = self.require(object_id, expected)?.clone();
        self.append(MigrationRecord {
            sequence: 0,
            phase,
            target_digest,
            ..current
        })
    }

    fn require(
        &self,
        object_id: &MigrationObjectId,
        expected: MigrationPhase,
    ) -> Result<&MigrationRecord, JournalError> {
        let current = self
            .latest
            .get(object_id)
            .ok_or(JournalError::InvalidTransition)?;
        if current.phase != expected {
            return Err(JournalError::InvalidTransition);
        }
        Ok(current)
    }

    fn append(&mut self, mut record: MigrationRecord) -> Result<MigrationRecord, JournalError> {
        record.sequence = self.next_sequence;
        let body = encode_body(&record, self.previous_tag)?;
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        let tag = hmac::sign(&signing_key, &body);
        let mut frame = Vec::with_capacity(4 + body.len() + TAG_BYTES);
        let frame_len = body
            .len()
            .checked_add(TAG_BYTES)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(JournalError::InvalidRecord)?;
        frame.extend_from_slice(&frame_len.to_be_bytes());
        frame.extend_from_slice(&body);
        frame.extend_from_slice(tag.as_ref());
        if self.journal.write_all(&frame).is_err()
            || self.journal.flush().is_err()
            || self.journal.sync_all().is_err()
        {
            return Err(JournalError::OutcomeUnknown);
        }
        self.previous_tag.copy_from_slice(tag.as_ref());
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        self.latest.insert(record.object_id.clone(), record.clone());
        Ok(record)
    }
}

impl Drop for MigrationJournal {
    fn drop(&mut self) {
        self.key.fill(0);
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[derive(Debug)]
struct DecodedJournal {
    valid_bytes: u64,
    last_sequence: u64,
    previous_tag: [u8; TAG_BYTES],
    latest: BTreeMap<MigrationObjectId, MigrationRecord>,
}

fn recover_records(journal: &mut File, key: [u8; 32]) -> Result<DecodedJournal, JournalError> {
    journal
        .seek(SeekFrom::Start(0))
        .map_err(|_| JournalError::Io)?;
    let mut bytes = Vec::new();
    journal
        .read_to_end(&mut bytes)
        .map_err(|_| JournalError::Io)?;
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
    let mut offset = 0_usize;
    let mut expected_sequence = 1_u64;
    let mut previous_tag = [0_u8; TAG_BYTES];
    let mut latest = BTreeMap::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            break;
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| JournalError::InvalidRecord)?,
        ) as usize;
        if !(TAG_BYTES..=MAX_RECORD_BYTES).contains(&length) {
            return Err(JournalError::Tampered);
        }
        if bytes.len() - offset - 4 < length {
            break;
        }
        let frame_start = offset + 4;
        let body_end = frame_start + length - TAG_BYTES;
        let frame_end = frame_start + length;
        let body = &bytes[frame_start..body_end];
        let tag = &bytes[body_end..frame_end];
        hmac::verify(&signing_key, body, tag).map_err(|_| JournalError::Tampered)?;
        let (record, recorded_previous) = decode_body(body)?;
        if record.sequence != expected_sequence || recorded_previous != previous_tag {
            return Err(JournalError::Tampered);
        }
        previous_tag.copy_from_slice(tag);
        latest.insert(record.object_id.clone(), record);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        offset = frame_end;
    }
    Ok(DecodedJournal {
        valid_bytes: offset as u64,
        last_sequence: expected_sequence - 1,
        previous_tag,
        latest,
    })
}

fn encode_body(
    record: &MigrationRecord,
    previous_tag: [u8; TAG_BYTES],
) -> Result<Vec<u8>, JournalError> {
    let id = record.object_id.as_str().as_bytes();
    let id_len = u16::try_from(id.len()).map_err(|_| JournalError::InvalidRecord)?;
    let mut body = Vec::with_capacity(5 + 8 + 16 + 1 + 2 + id.len() + 32 + 32 + TAG_BYTES);
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&record.sequence.to_be_bytes());
    body.extend_from_slice(&record.operation_id);
    body.push(record.phase as u8);
    body.extend_from_slice(&id_len.to_be_bytes());
    body.extend_from_slice(id);
    body.extend_from_slice(&record.source_digest);
    body.extend_from_slice(&record.target_digest);
    body.extend_from_slice(&previous_tag);
    if body.len() + TAG_BYTES > MAX_RECORD_BYTES {
        return Err(JournalError::InvalidRecord);
    }
    Ok(body)
}

fn decode_body(body: &[u8]) -> Result<(MigrationRecord, [u8; TAG_BYTES]), JournalError> {
    const FIXED_BEFORE_ID: usize = 5 + 8 + 16 + 1 + 2;
    const FIXED_AFTER_ID: usize = 32 + 32 + TAG_BYTES;
    if body.len() < FIXED_BEFORE_ID + FIXED_AFTER_ID || &body[..5] != MAGIC {
        return Err(JournalError::InvalidRecord);
    }
    let mut cursor = 5;
    let sequence = u64::from_be_bytes(
        body[cursor..cursor + 8]
            .try_into()
            .map_err(|_| JournalError::InvalidRecord)?,
    );
    cursor += 8;
    let operation_id = body[cursor..cursor + 16]
        .try_into()
        .map_err(|_| JournalError::InvalidRecord)?;
    cursor += 16;
    let phase = MigrationPhase::decode(body[cursor])?;
    cursor += 1;
    let id_len = u16::from_be_bytes(
        body[cursor..cursor + 2]
            .try_into()
            .map_err(|_| JournalError::InvalidRecord)?,
    ) as usize;
    cursor += 2;
    if id_len == 0 || id_len > MAX_OBJECT_ID_BYTES || cursor + id_len + FIXED_AFTER_ID != body.len()
    {
        return Err(JournalError::InvalidRecord);
    }
    let object_id = MigrationObjectId::parse(
        std::str::from_utf8(&body[cursor..cursor + id_len])
            .map_err(|_| JournalError::InvalidRecord)?
            .to_owned(),
    )?;
    cursor += id_len;
    let source_digest = body[cursor..cursor + 32]
        .try_into()
        .map_err(|_| JournalError::InvalidRecord)?;
    cursor += 32;
    let target_digest = body[cursor..cursor + 32]
        .try_into()
        .map_err(|_| JournalError::InvalidRecord)?;
    cursor += 32;
    let previous_tag = body[cursor..cursor + TAG_BYTES]
        .try_into()
        .map_err(|_| JournalError::InvalidRecord)?;
    if sequence == 0 || operation_id == [0; 16] || source_digest == [0; 32] {
        return Err(JournalError::InvalidRecord);
    }
    Ok((
        MigrationRecord {
            sequence,
            operation_id,
            object_id,
            phase,
            source_digest,
            target_digest,
        },
        previous_tag,
    ))
}

fn validate_root(path: &Path) -> Result<(), JournalError> {
    if !path.is_absolute() {
        return Err(JournalError::InvalidRoot);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
                if current == Path::new("/") || !current.exists() {
                    continue;
                }
                let metadata =
                    fs::symlink_metadata(&current).map_err(|_| JournalError::InvalidRoot)?;
                if metadata.file_type().is_symlink() {
                    return Err(JournalError::InvalidRoot);
                }
            }
            Component::CurDir | Component::ParentDir => return Err(JournalError::InvalidRoot),
        }
    }
    Ok(())
}

fn create_private_root(root: &Path) -> Result<(), JournalError> {
    if root.exists() {
        if !root.is_dir() {
            return Err(JournalError::InvalidRoot);
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(root).map_err(|_| JournalError::Io)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(root).map_err(|_| JournalError::Io)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root)
            .map_err(|_| JournalError::Io)?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(JournalError::InvalidRoot);
        }
    }
    Ok(())
}

fn create_lock(path: &Path) -> Result<WriterLock, JournalError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut lock = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            JournalError::WriterBusy
        } else {
            JournalError::Io
        }
    })?;
    lock.write_all(b"heptabao-migration-writer-v1\n")
        .and_then(|()| lock.sync_all())
        .map_err(|_| JournalError::Io)?;
    Ok(WriterLock {
        path: path.to_path_buf(),
        _file: lock,
    })
}

fn open_journal(path: &Path) -> Result<File, JournalError> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|_| JournalError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(JournalError::InvalidRoot);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(JournalError::InvalidRoot);
            }
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0o400000 | 0o2000000);
    }
    options.open(path).map_err(|_| JournalError::Io)
}

pub fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 output is always 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "heptabao-migration-journal-{name}-{}-{nonce}",
            std::process::id()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&root).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir(&root).unwrap();
        root
    }

    fn object() -> MigrationObjectId {
        MigrationObjectId::parse("secret/data/application").unwrap()
    }

    #[test]
    fn restart_recovers_verified_transaction_and_requires_reconciliation() {
        let root = root("restart");
        let key = [7; 32];
        let source = digest_bytes(b"source");
        let target = digest_bytes(b"target");
        {
            let mut journal = MigrationJournal::open(&root, key).unwrap();
            journal.begin([1; 16], object(), source).unwrap();
            journal.mark_staged(&object(), target).unwrap();
            journal.mark_verified(&object()).unwrap();
            journal.mark_commit_pending(&object()).unwrap();
        }
        let mut reopened = MigrationJournal::open(&root, key).unwrap();
        assert_eq!(
            reopened.latest(&object()).unwrap().phase,
            MigrationPhase::CommitPending
        );
        assert_eq!(
            reopened.reconcile_commit(
                &object(),
                ReconciliationProof {
                    committed: true,
                    observed_target_digest: digest_bytes(b"wrong")
                }
            ),
            Err(JournalError::InvalidTransition)
        );
        let committed = reopened
            .reconcile_commit(
                &object(),
                ReconciliationProof {
                    committed: true,
                    observed_target_digest: target,
                },
            )
            .unwrap();
        assert_eq!(committed.phase, MigrationPhase::Committed);
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn torn_tail_is_truncated_but_authenticated_corruption_is_rejected() {
        let root = root("tail");
        let key = [8; 32];
        {
            let mut journal = MigrationJournal::open(&root, key).unwrap();
            journal
                .begin([2; 16], object(), digest_bytes(b"source"))
                .unwrap();
        }
        let path = root.join("migration.journal");
        let valid = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0, 0, 1])
            .unwrap();
        let recovered = MigrationJournal::open(&root, key).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), valid);
        drop(recovered);
        let mut bytes = fs::read(&path).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 0x40;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            MigrationJournal::open(&root, key),
            Err(JournalError::Tampered) | Err(JournalError::InvalidRecord)
        ));
        assert!(!root.join("writer.lock").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn single_writer_and_state_machine_are_fail_closed() {
        let root = root("writer");
        let key = [9; 32];
        let mut first = MigrationJournal::open(&root, key).unwrap();
        assert!(matches!(
            MigrationJournal::open(&root, key),
            Err(JournalError::WriterBusy)
        ));
        first
            .begin([3; 16], object(), digest_bytes(b"source"))
            .unwrap();
        assert_eq!(
            first.mark_verified(&object()),
            Err(JournalError::InvalidTransition)
        );
        first.mark_rollback_pending(&object()).unwrap();
        assert_eq!(
            first.reconcile_rollback(&object(), false),
            Err(JournalError::InvalidTransition)
        );
        first.reconcile_rollback(&object(), true).unwrap();
        drop(first);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn permissive_existing_journal_is_rejected() {
        let root = root("permissions");
        let path = root.join("migration.journal");
        fs::write(&path, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                MigrationJournal::open(&root, [11; 32]),
                Err(JournalError::InvalidRoot)
            ));
            assert!(!root.join("writer.lock").exists());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_begin_is_idempotent_for_exact_operation() {
        let root = root("idempotent");
        let key = [10; 32];
        let mut journal = MigrationJournal::open(&root, key).unwrap();
        let first = journal
            .begin([4; 16], object(), digest_bytes(b"source"))
            .unwrap();
        let second = journal
            .begin([4; 16], object(), digest_bytes(b"source"))
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.sequence, 1);
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }
}

const MAX_MIGRATION_OBJECTS_V2_4: usize = 1_000_000;
const MAX_OBJECT_DEPENDENCIES_V2_4: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MigrationObjectKindV24 {
    Namespace,
    Policy,
    AuthMount,
    SecretMount,
    IdentityEntity,
    IdentityGroup,
    IdentityAlias,
    TokenRole,
    TransitKey,
    PkiIssuer,
    PkiRole,
    DatabaseRole,
    DynamicLease,
    AuditDevice,
    SealMetadata,
    RaftMetadata,
}

impl MigrationObjectKindV24 {
    pub const fn all_required_for_complete_profile() -> [Self; 16] {
        [
            Self::Namespace,
            Self::Policy,
            Self::AuthMount,
            Self::SecretMount,
            Self::IdentityEntity,
            Self::IdentityGroup,
            Self::IdentityAlias,
            Self::TokenRole,
            Self::TransitKey,
            Self::PkiIssuer,
            Self::PkiRole,
            Self::DatabaseRole,
            Self::DynamicLease,
            Self::AuditDevice,
            Self::SealMetadata,
            Self::RaftMetadata,
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationObjectV24 {
    pub object_id: MigrationObjectId,
    pub kind: MigrationObjectKindV24,
    pub source_digest: [u8; 32],
    pub dependencies: BTreeSet<MigrationObjectId>,
}

impl MigrationObjectV24 {
    pub fn new(
        object_id: MigrationObjectId,
        kind: MigrationObjectKindV24,
        source_digest: [u8; 32],
        dependencies: BTreeSet<MigrationObjectId>,
    ) -> Result<Self, MigrationInventoryErrorV24> {
        if source_digest == [0; 32]
            || dependencies.len() > MAX_OBJECT_DEPENDENCIES_V2_4
            || dependencies.contains(&object_id)
        {
            return Err(MigrationInventoryErrorV24::InvalidObject);
        }
        Ok(Self {
            object_id,
            kind,
            source_digest,
            dependencies,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationInventoryV24 {
    objects: BTreeMap<MigrationObjectId, MigrationObjectV24>,
    required_kinds: BTreeSet<MigrationObjectKindV24>,
    topological_order: Vec<MigrationObjectId>,
}

impl MigrationInventoryV24 {
    pub fn complete_profile(
        objects: impl IntoIterator<Item = MigrationObjectV24>,
    ) -> Result<Self, MigrationInventoryErrorV24> {
        Self::new(
            objects,
            MigrationObjectKindV24::all_required_for_complete_profile(),
        )
    }

    pub fn new(
        objects: impl IntoIterator<Item = MigrationObjectV24>,
        required_kinds: impl IntoIterator<Item = MigrationObjectKindV24>,
    ) -> Result<Self, MigrationInventoryErrorV24> {
        let required_kinds = required_kinds.into_iter().collect::<BTreeSet<_>>();
        if required_kinds.is_empty() {
            return Err(MigrationInventoryErrorV24::EmptyRequiredKinds);
        }
        let mut by_id = BTreeMap::new();
        for object in objects {
            if by_id.len() >= MAX_MIGRATION_OBJECTS_V2_4 {
                return Err(MigrationInventoryErrorV24::InventoryTooLarge);
            }
            if by_id.insert(object.object_id.clone(), object).is_some() {
                return Err(MigrationInventoryErrorV24::DuplicateObject);
            }
        }
        if by_id.is_empty() {
            return Err(MigrationInventoryErrorV24::EmptyInventory);
        }
        for object in by_id.values() {
            if object
                .dependencies
                .iter()
                .any(|dependency| !by_id.contains_key(dependency))
            {
                return Err(MigrationInventoryErrorV24::MissingDependency);
            }
        }
        let observed_kinds = by_id
            .values()
            .map(|object| object.kind)
            .collect::<BTreeSet<_>>();
        if !required_kinds.is_subset(&observed_kinds) {
            return Err(MigrationInventoryErrorV24::MissingRequiredKind);
        }
        let topological_order = migration_topological_order_v2_4(&by_id)?;
        Ok(Self {
            objects: by_id,
            required_kinds,
            topological_order,
        })
    }

    pub fn objects(&self) -> impl Iterator<Item = &MigrationObjectV24> {
        self.topological_order
            .iter()
            .filter_map(|object_id| self.objects.get(object_id))
    }

    pub fn topological_order(&self) -> &[MigrationObjectId] {
        &self.topological_order
    }

    pub fn required_kinds(&self) -> &BTreeSet<MigrationObjectKindV24> {
        &self.required_kinds
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationInventoryErrorV24 {
    InvalidObject,
    EmptyRequiredKinds,
    EmptyInventory,
    InventoryTooLarge,
    DuplicateObject,
    MissingDependency,
    MissingRequiredKind,
    DependencyCycle,
}

impl fmt::Display for MigrationInventoryErrorV24 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidObject => "migration inventory object is invalid",
            Self::EmptyRequiredKinds => "migration inventory required-kind set is empty",
            Self::EmptyInventory => "migration inventory is empty",
            Self::InventoryTooLarge => "migration inventory exceeds its bound",
            Self::DuplicateObject => "migration inventory object is duplicated",
            Self::MissingDependency => "migration inventory dependency is missing",
            Self::MissingRequiredKind => "migration inventory omits a required object kind",
            Self::DependencyCycle => "migration inventory contains a dependency cycle",
        })
    }
}

impl Error for MigrationInventoryErrorV24 {}

fn migration_topological_order_v2_4(
    objects: &BTreeMap<MigrationObjectId, MigrationObjectV24>,
) -> Result<Vec<MigrationObjectId>, MigrationInventoryErrorV24> {
    let mut remaining = objects
        .iter()
        .map(|(object_id, object)| (object_id.clone(), object.dependencies.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut order = Vec::with_capacity(objects.len());
    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .filter(|(_, dependencies)| dependencies.is_empty())
            .map(|(object_id, _)| object_id.clone())
            .collect::<Vec<_>>();
        if ready.is_empty() {
            return Err(MigrationInventoryErrorV24::DependencyCycle);
        }
        for object_id in &ready {
            remaining.remove(object_id);
            order.push(object_id.clone());
        }
        for dependencies in remaining.values_mut() {
            for object_id in &ready {
                dependencies.remove(object_id);
            }
        }
    }
    Ok(order)
}

#[cfg(test)]
mod migration_inventory_v2_4_tests {
    use super::*;

    fn object(id: &str, kind: MigrationObjectKindV24, dependencies: &[&str]) -> MigrationObjectV24 {
        MigrationObjectV24::new(
            MigrationObjectId::parse(id).unwrap(),
            kind,
            [id.as_bytes()[0]; 32],
            dependencies
                .iter()
                .map(|value| MigrationObjectId::parse(*value).unwrap())
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn deterministic_dependency_order_is_enforced() {
        let namespace = object("namespace/root", MigrationObjectKindV24::Namespace, &[]);
        let policy = object(
            "policy/default",
            MigrationObjectKindV24::Policy,
            &["namespace/root"],
        );
        let mount = object(
            "mount/kv",
            MigrationObjectKindV24::SecretMount,
            &["namespace/root", "policy/default"],
        );
        let inventory = MigrationInventoryV24::new(
            [mount, policy, namespace],
            [
                MigrationObjectKindV24::Namespace,
                MigrationObjectKindV24::Policy,
                MigrationObjectKindV24::SecretMount,
            ],
        )
        .unwrap();
        let order = inventory
            .topological_order()
            .iter()
            .map(MigrationObjectId::as_str)
            .collect::<Vec<_>>();
        assert_eq!(order, ["namespace/root", "policy/default", "mount/kv"]);
    }

    #[test]
    fn missing_kind_dependency_and_cycle_fail_closed() {
        let namespace = object("namespace/root", MigrationObjectKindV24::Namespace, &[]);
        assert_eq!(
            MigrationInventoryV24::new(
                [namespace.clone()],
                [
                    MigrationObjectKindV24::Namespace,
                    MigrationObjectKindV24::Policy
                ],
            ),
            Err(MigrationInventoryErrorV24::MissingRequiredKind)
        );
        let missing = object(
            "policy/default",
            MigrationObjectKindV24::Policy,
            &["namespace/missing"],
        );
        assert_eq!(
            MigrationInventoryV24::new(
                [namespace.clone(), missing],
                [MigrationObjectKindV24::Namespace]
            ),
            Err(MigrationInventoryErrorV24::MissingDependency)
        );
        let first = object(
            "cycle/first",
            MigrationObjectKindV24::Policy,
            &["cycle/second"],
        );
        let second = object(
            "cycle/second",
            MigrationObjectKindV24::Policy,
            &["cycle/first"],
        );
        assert_eq!(
            MigrationInventoryV24::new([first, second], [MigrationObjectKindV24::Policy]),
            Err(MigrationInventoryErrorV24::DependencyCycle)
        );
    }

    #[test]
    fn complete_profile_enumerates_all_required_object_kinds() {
        let objects = MigrationObjectKindV24::all_required_for_complete_profile()
            .into_iter()
            .enumerate()
            .map(|(index, kind)| object(&format!("kind/object-{index}"), kind, &[]))
            .collect::<Vec<_>>();
        let inventory = MigrationInventoryV24::complete_profile(objects).unwrap();
        assert_eq!(inventory.required_kinds().len(), 16);
    }
}
