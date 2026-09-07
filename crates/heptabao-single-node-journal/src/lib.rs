#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Fail-closed descriptor-anchored chained journal implementation.
//!
//! Every committed record is an immutable file. A separately synchronized
//! `TAIL` pointer publishes the contiguous authenticated prefix. One exact next
//! orphan may be reconciled explicitly after a crash between entry persistence
//! and tail publication. The Linux development profile holds an exclusive
//! directory writer fence and resolves every journal object through the opened
//! directory descriptor. It is not a production audit device or rollback
//! anchor.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use heptabao_filesystem_guard::{DirectoryGuardError, ExclusiveDirectory};
use heptabao_journal_api::{
    AppendReceipt, AuthenticatorId, DurableJournal, JournalAuthenticator, JournalContractError,
    JournalDomain, JournalOpenMode, JournalPayload, JournalRecord, JournalSequence, JournalTag,
    JournalTail, MAX_JOURNAL_PAYLOAD_BYTES,
};

const MARKER_NAME: &str = "heptabao-journal.marker";
const TAIL_NAME: &str = "TAIL";
const MARKER_MAGIC: &[u8] = b"HEPTABAO-JOURNAL-MARKER-V1\0";
const TAIL_MAGIC: &[u8] = b"HEPTABAO-JOURNAL-TAIL-V1\0";
const ENTRY_MAGIC: &[u8] = b"HEPTABAO-JOURNAL-ENTRY-V1\0";
const MAX_CONTROL_FILE_BYTES: usize = 64 * 1024;
const ENTRY_OVERHEAD_BOUND: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_os = "linux")]
const O_CLOEXEC: i32 = 0o2000000;
pub const MAX_JOURNAL_RECORDS: u64 = 65_536;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub struct FileDurableJournal<A: JournalAuthenticator> {
    root: ExclusiveDirectory,
    domain: JournalDomain,
    authenticator: A,
    open_mode: JournalOpenMode,
    tail: Option<JournalTail>,
}

impl<A: JournalAuthenticator> fmt::Debug for FileDurableJournal<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileDurableJournal")
            .field("root", &"[REDACTED_ABSOLUTE_PATH]")
            .field("domain", &self.domain)
            .field("authenticator", &self.authenticator.authenticator_id())
            .field("open_mode", &self.open_mode)
            .field("tail", &self.tail)
            .finish()
    }
}

impl<A: JournalAuthenticator> FileDurableJournal<A> {
    pub fn create_new(
        root: impl AsRef<Path>,
        domain: JournalDomain,
        authenticator: A,
    ) -> Result<Self, FileJournalError<A::Error>> {
        let root = ExclusiveDirectory::open(root).map_err(map_directory_guard_error)?;
        if !directory_is_empty(root.access_path())? {
            return Err(FileJournalError::DirectoryNotEmpty);
        }
        let mut marker = encode_marker(&domain, authenticator.authenticator_id())?;
        let publish = atomic_replace(&root, MARKER_NAME, &marker);
        marker.fill(0);
        if let Err(error) = publish {
            return if error.published {
                Err(FileJournalError::InitializationOutcomeUnknown)
            } else {
                Err(FileJournalError::Io(error.source))
            };
        }
        Ok(Self {
            root,
            domain,
            authenticator,
            open_mode: JournalOpenMode::CreateNew,
            tail: None,
        })
    }

    pub fn reopen_existing(
        root: impl AsRef<Path>,
        domain: JournalDomain,
        authenticator: A,
    ) -> Result<Self, FileJournalError<A::Error>> {
        let root = ExclusiveDirectory::open(root).map_err(map_directory_guard_error)?;
        let mut journal = Self {
            root,
            domain,
            authenticator,
            open_mode: JournalOpenMode::ReopenExisting,
            tail: None,
        };
        journal.validate_marker()?;
        journal.tail = journal.read_optional_tail()?;
        let _ = journal.validate_layout()?;
        let replayed = journal.replay_internal()?;
        if tail_from_records(&replayed) != journal.tail {
            return Err(FileJournalError::CorruptJournal);
        }
        Ok(journal)
    }

    pub fn root(&self) -> &Path {
        self.root.original_path()
    }

    pub fn root_identity(&self) -> heptabao_filesystem_guard::DirectoryIdentity {
        self.root.identity()
    }

    pub fn reconcile_next_orphan(&mut self) -> Result<AppendReceipt, FileJournalError<A::Error>> {
        self.root.verify().map_err(map_directory_guard_error)?;
        self.validate_marker()?;
        let disk_tail = self.read_optional_tail()?;
        if disk_tail != self.tail {
            return Err(FileJournalError::TailConflict {
                expected: self.tail.map(|tail| tail.sequence),
                actual: disk_tail.map(|tail| tail.sequence),
            });
        }
        let orphan = self
            .validate_layout()?
            .ok_or(FileJournalError::NoPendingOrphan)?;
        let previous_tail = self.tail;
        let record = self.read_and_verify_entry(orphan, previous_tail.map(|tail| tail.tag))?;
        let appended = JournalTail {
            sequence: record.sequence,
            tag: record.tag,
        };
        self.publish_tail(appended)?;
        let verified = self
            .read_optional_tail()?
            .ok_or(FileJournalError::TailMissing)?;
        if verified != appended {
            return Err(FileJournalError::AppendOutcomeUnknown);
        }
        self.tail = Some(appended);
        Ok(AppendReceipt {
            previous_tail,
            appended,
        })
    }

    fn marker_path(&self) -> PathBuf {
        self.root.access_path().join(MARKER_NAME)
    }

    fn tail_path(&self) -> PathBuf {
        self.root.access_path().join(TAIL_NAME)
    }

    fn entry_path(&self, sequence: JournalSequence) -> PathBuf {
        self.root.access_path().join(entry_file_name(sequence))
    }

    fn validate_marker(&self) -> Result<(), FileJournalError<A::Error>> {
        let bytes = read_regular_file(&self.marker_path(), MAX_CONTROL_FILE_BYTES)
            .map_err(map_marker_error)?;
        let marker = decode_marker(&bytes).map_err(|_| FileJournalError::MarkerMismatch)?;
        if marker.domain != self.domain.as_str()
            || marker.authenticator != self.authenticator.authenticator_id().as_str()
        {
            return Err(FileJournalError::MarkerMismatch);
        }
        Ok(())
    }

    fn read_optional_tail(&self) -> Result<Option<JournalTail>, FileJournalError<A::Error>> {
        match fs::symlink_metadata(self.tail_path()) {
            Ok(_) => {
                let bytes = read_regular_file(&self.tail_path(), MAX_CONTROL_FILE_BYTES)?;
                decode_tail(&bytes)
                    .map(Some)
                    .map_err(|_| FileJournalError::CorruptJournal)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(FileJournalError::Io(error)),
        }
    }

    fn validate_layout(&self) -> Result<Option<JournalSequence>, FileJournalError<A::Error>> {
        let mut sequences = BTreeSet::new();
        for entry in fs::read_dir(self.root.access_path()).map_err(FileJournalError::Io)? {
            let entry = entry.map_err(FileJournalError::Io)?;
            let file_type = entry.file_type().map_err(FileJournalError::Io)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(FileJournalError::UnexpectedEntry)?;
            if name.contains(".tmp-") {
                return Err(FileJournalError::UnresolvedTemporaryArtifact);
            }
            if name == MARKER_NAME || name == TAIL_NAME {
                if file_type.is_symlink() || !file_type.is_file() {
                    return Err(FileJournalError::UnsafeFileType);
                }
                continue;
            }
            let sequence = parse_entry_file_name(name)
                .map_err(|_| FileJournalError::CorruptJournal)?
                .ok_or(FileJournalError::UnexpectedEntry)?;
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(FileJournalError::UnsafeFileType);
            }
            if !sequences.insert(sequence) {
                return Err(FileJournalError::CorruptJournal);
            }
        }

        let committed_count = self.tail.map_or(0, |tail| tail.sequence.get());
        if committed_count > MAX_JOURNAL_RECORDS {
            return Err(FileJournalError::RecordLimitExceeded);
        }
        for value in 1..=committed_count {
            let sequence = JournalSequence::new(value).map_err(FileJournalError::Contract)?;
            if !sequences.remove(&sequence) {
                return Err(FileJournalError::CorruptJournal);
            }
        }
        let next_value = committed_count
            .checked_add(1)
            .ok_or(FileJournalError::RecordLimitExceeded)?;
        let next = JournalSequence::new(next_value).map_err(FileJournalError::Contract)?;
        let orphan = if sequences.remove(&next) {
            Some(next)
        } else {
            None
        };
        if !sequences.is_empty() {
            return Err(FileJournalError::CorruptJournal);
        }
        Ok(orphan)
    }

    fn inspect_current_layout(
        &self,
    ) -> Result<Option<JournalSequence>, FileJournalError<A::Error>> {
        self.root.verify().map_err(map_directory_guard_error)?;
        self.validate_marker()?;
        let disk_tail = self.read_optional_tail()?;
        if disk_tail != self.tail {
            return Err(FileJournalError::TailConflict {
                expected: self.tail.map(|tail| tail.sequence),
                actual: disk_tail.map(|tail| tail.sequence),
            });
        }
        self.validate_layout()
    }

    fn read_and_verify_entry(
        &self,
        sequence: JournalSequence,
        expected_previous_tag: Option<JournalTag>,
    ) -> Result<JournalRecord, FileJournalError<A::Error>> {
        let maximum = MAX_JOURNAL_PAYLOAD_BYTES
            .checked_add(ENTRY_OVERHEAD_BOUND)
            .ok_or(FileJournalError::CorruptJournal)?;
        let bytes = read_regular_file(&self.entry_path(sequence), maximum)?;
        let record = decode_entry(&bytes).map_err(|_| FileJournalError::CorruptJournal)?;
        if record.sequence != sequence || record.previous_tag != expected_previous_tag {
            return Err(FileJournalError::ChainMismatch);
        }
        let expected_tag = self
            .authenticator
            .authenticate(
                &self.domain,
                record.sequence,
                record.previous_tag,
                record.payload.as_bytes(),
            )
            .map_err(FileJournalError::Authenticator)?;
        if expected_tag != record.tag {
            return Err(FileJournalError::AuthenticationFailed);
        }
        Ok(record)
    }

    fn replay_internal(&self) -> Result<Vec<JournalRecord>, FileJournalError<A::Error>> {
        let count = self.tail.map_or(0, |tail| tail.sequence.get());
        if count > MAX_JOURNAL_RECORDS {
            return Err(FileJournalError::RecordLimitExceeded);
        }
        let capacity = usize::try_from(count).map_err(|_| FileJournalError::RecordLimitExceeded)?;
        let mut records = Vec::with_capacity(capacity);
        let mut previous_tag = None;
        for value in 1..=count {
            let sequence = JournalSequence::new(value).map_err(FileJournalError::Contract)?;
            let record = self.read_and_verify_entry(sequence, previous_tag)?;
            previous_tag = Some(record.tag);
            records.push(record);
        }
        Ok(records)
    }

    fn publish_tail(&self, tail: JournalTail) -> Result<(), FileJournalError<A::Error>> {
        let mut encoded = encode_tail(tail);
        let result = atomic_replace(&self.root, TAIL_NAME, &encoded);
        encoded.fill(0);
        match result {
            Ok(()) => Ok(()),
            Err(error) if error.published => Err(FileJournalError::AppendOutcomeUnknown),
            Err(error) => Err(FileJournalError::Io(error.source)),
        }
    }
}

impl<A> DurableJournal for FileDurableJournal<A>
where
    A: JournalAuthenticator + 'static,
{
    type Error = FileJournalError<A::Error>;

    fn domain(&self) -> &JournalDomain {
        &self.domain
    }

    fn open_mode(&self) -> JournalOpenMode {
        self.open_mode
    }

    fn tail(&self) -> Option<JournalTail> {
        self.tail
    }

    fn replay(&self) -> Result<Vec<JournalRecord>, Self::Error> {
        if self.inspect_current_layout()?.is_some() {
            return Err(FileJournalError::PendingOrphan);
        }
        let records = self.replay_internal()?;
        if tail_from_records(&records) != self.tail {
            return Err(FileJournalError::CorruptJournal);
        }
        Ok(records)
    }

    fn recover_authoritative(&mut self) -> Result<Vec<JournalRecord>, Self::Error> {
        self.root.verify().map_err(map_directory_guard_error)?;
        self.validate_marker()?;
        self.tail = self.read_optional_tail()?;
        if self.validate_layout()?.is_some() {
            let _ = self.reconcile_next_orphan()?;
        }
        let records = self.replay_internal()?;
        if tail_from_records(&records) != self.tail {
            return Err(FileJournalError::CorruptJournal);
        }
        Ok(records)
    }

    fn append(
        &mut self,
        expected_tail: Option<JournalSequence>,
        payload: JournalPayload,
    ) -> Result<AppendReceipt, Self::Error> {
        if self.inspect_current_layout()?.is_some() {
            return Err(FileJournalError::PendingOrphan);
        }
        let actual_sequence = self.tail.map(|tail| tail.sequence);
        if expected_tail != actual_sequence {
            return Err(FileJournalError::TailConflict {
                expected: expected_tail,
                actual: actual_sequence,
            });
        }
        let previous_tail = self.tail;
        let sequence = match previous_tail {
            Some(tail) => tail
                .sequence
                .checked_next()
                .map_err(FileJournalError::Contract)?,
            None => JournalSequence::INITIAL,
        };
        if sequence.get() > MAX_JOURNAL_RECORDS {
            return Err(FileJournalError::RecordLimitExceeded);
        }
        let previous_tag = previous_tail.map(|tail| tail.tag);
        let tag = self
            .authenticator
            .authenticate(&self.domain, sequence, previous_tag, payload.as_bytes())
            .map_err(FileJournalError::Authenticator)?;
        let record = JournalRecord {
            sequence,
            previous_tag,
            tag,
            payload,
        };
        let mut encoded = encode_entry(&record)?;
        let entry_name = entry_file_name(sequence);
        let write_result = write_new_file_and_sync_parent(&self.root, &entry_name, &encoded);
        encoded.fill(0);
        if let Err(error) = write_result {
            if error.kind() == io::ErrorKind::AlreadyExists {
                return Err(FileJournalError::EntryAlreadyExists(sequence));
            }
            return Err(FileJournalError::Io(error));
        }
        let appended = JournalTail { sequence, tag };
        self.publish_tail(appended)?;
        let verified_tail = self
            .read_optional_tail()?
            .ok_or(FileJournalError::AppendOutcomeUnknown)?;
        if verified_tail != appended {
            return Err(FileJournalError::AppendOutcomeUnknown);
        }
        let _ = self.read_and_verify_entry(sequence, previous_tag)?;
        self.tail = Some(appended);
        Ok(AppendReceipt {
            previous_tail,
            appended,
        })
    }
}

#[derive(Debug)]
pub enum FileJournalError<E>
where
    E: Error + Send + Sync + 'static,
{
    Contract(JournalContractError),
    Authenticator(E),
    Io(io::Error),
    RootMustBeAbsolute,
    UnsupportedPlatform,
    UnsafeRoot,
    WriterBusy,
    DirectoryNotEmpty,
    MarkerMissing,
    MarkerMismatch,
    TailMissing,
    UnsafeFileType,
    UnexpectedEntry,
    UnresolvedTemporaryArtifact,
    CorruptJournal,
    ChainMismatch,
    AuthenticationFailed,
    RecordLimitExceeded,
    EntryAlreadyExists(JournalSequence),
    TailConflict {
        expected: Option<JournalSequence>,
        actual: Option<JournalSequence>,
    },
    PendingOrphan,
    NoPendingOrphan,
    InitializationOutcomeUnknown,
    AppendOutcomeUnknown,
}

impl<E> fmt::Display for FileJournalError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "journal contract failure: {error}"),
            Self::Authenticator(error) => {
                write!(formatter, "journal authenticator failure: {error}")
            }
            Self::Io(error) => write!(formatter, "journal I/O failure: {error}"),
            Self::RootMustBeAbsolute => formatter.write_str("journal root must be absolute"),
            Self::UnsupportedPlatform => {
                formatter.write_str("descriptor-anchored journal is unsupported on this platform")
            }
            Self::UnsafeRoot => formatter.write_str("journal root path is unsafe"),
            Self::WriterBusy => {
                formatter.write_str("another process holds the journal writer fence")
            }
            Self::DirectoryNotEmpty => formatter.write_str("new journal root must be empty"),
            Self::MarkerMissing => formatter.write_str("journal marker is missing"),
            Self::MarkerMismatch => formatter.write_str("journal marker is invalid"),
            Self::TailMissing => formatter.write_str("journal tail is missing"),
            Self::UnsafeFileType => formatter.write_str("journal path is not a regular file"),
            Self::UnexpectedEntry => {
                formatter.write_str("journal directory has an unexpected entry")
            }
            Self::UnresolvedTemporaryArtifact => {
                formatter.write_str("journal has an unresolved temporary artifact")
            }
            Self::CorruptJournal => formatter.write_str("journal structure is corrupt"),
            Self::ChainMismatch => {
                formatter.write_str("journal authentication chain is discontinuous")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("journal record authentication failed")
            }
            Self::RecordLimitExceeded => formatter.write_str("journal record bound is exceeded"),
            Self::EntryAlreadyExists(sequence) => {
                write!(formatter, "journal entry {} already exists", sequence.get())
            }
            Self::TailConflict { expected, actual } => {
                write!(
                    formatter,
                    "journal tail conflict: expected {expected:?}, actual {actual:?}"
                )
            }
            Self::PendingOrphan => {
                formatter.write_str("journal has a pending next entry that requires reconciliation")
            }
            Self::NoPendingOrphan => formatter.write_str("journal has no pending next entry"),
            Self::InitializationOutcomeUnknown => formatter
                .write_str("journal initialization may have published; reopen before retrying"),
            Self::AppendOutcomeUnknown => formatter.write_str(
                "journal tail publication may have occurred; reopen and reconcile before retrying",
            ),
        }
    }
}

impl<E> Error for FileJournalError<E> where E: Error + Send + Sync + 'static {}

impl<E> From<JournalContractError> for FileJournalError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn from(error: JournalContractError) -> Self {
        Self::Contract(error)
    }
}

impl<E> From<io::Error> for FileJournalError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug)]
struct MarkerRecord {
    domain: String,
    authenticator: String,
}

#[derive(Debug)]
struct AtomicReplaceError {
    source: io::Error,
    published: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeError {
    Truncated,
    Trailing,
    InvalidMagic,
    InvalidLength,
    InvalidUtf8,
    InvalidSequence,
    InvalidTag,
    InvalidPreviousTag,
    InvalidPayload,
}

fn map_directory_guard_error<E>(error: DirectoryGuardError) -> FileJournalError<E>
where
    E: Error + Send + Sync + 'static,
{
    match error {
        DirectoryGuardError::RootMustBeAbsolute => FileJournalError::RootMustBeAbsolute,
        DirectoryGuardError::UnsupportedPlatform => FileJournalError::UnsupportedPlatform,
        DirectoryGuardError::WriterBusy => FileJournalError::WriterBusy,
        DirectoryGuardError::UnsafeRoot
        | DirectoryGuardError::RootIdentityChanged
        | DirectoryGuardError::DescriptorPathUnavailable
        | DirectoryGuardError::InvalidLeafName => FileJournalError::UnsafeRoot,
        DirectoryGuardError::Io(error) => FileJournalError::Io(error),
    }
}

fn directory_is_empty<E>(root: &Path) -> Result<bool, FileJournalError<E>>
where
    E: Error + Send + Sync + 'static,
{
    let mut entries = fs::read_dir(root).map_err(FileJournalError::Io)?;
    match entries.next() {
        None => Ok(true),
        Some(Ok(_)) => Ok(false),
        Some(Err(error)) => Err(FileJournalError::Io(error)),
    }
}

fn map_marker_error<E>(error: FileJournalError<E>) -> FileJournalError<E>
where
    E: Error + Send + Sync + 'static,
{
    match error {
        FileJournalError::Io(io_error) if io_error.kind() == io::ErrorKind::NotFound => {
            FileJournalError::MarkerMissing
        }
        other => other,
    }
}

fn read_regular_file<E>(path: &Path, maximum: usize) -> Result<Vec<u8>, FileJournalError<E>>
where
    E: Error + Send + Sync + 'static,
{
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW | O_CLOEXEC);
    let file = options.open(path).map_err(FileJournalError::Io)?;
    let metadata = file.metadata().map_err(FileJournalError::Io)?;
    if !metadata.is_file() {
        return Err(FileJournalError::UnsafeFileType);
    }
    let maximum_u64 = u64::try_from(maximum).map_err(|_| FileJournalError::CorruptJournal)?;
    if metadata.len() > maximum_u64 {
        return Err(FileJournalError::CorruptJournal);
    }
    let bound = maximum_u64
        .checked_add(1)
        .ok_or(FileJournalError::CorruptJournal)?;
    let mut limited = file.take(bound);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(FileJournalError::Io)?;
    if bytes.len() > maximum {
        bytes.fill(0);
        return Err(FileJournalError::CorruptJournal);
    }
    Ok(bytes)
}

fn secure_create_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW | O_CLOEXEC);
    options.open(path)
}

fn write_new_file_and_sync_parent(
    root: &ExclusiveDirectory,
    leaf_name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    root.verify().map_err(io::Error::other)?;
    let path = root.leaf_path(leaf_name).map_err(io::Error::other)?;
    let mut file = secure_create_new(&path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    root.sync_all().map_err(io::Error::other)
}

fn atomic_replace(
    root: &ExclusiveDirectory,
    target_name: &str,
    bytes: &[u8],
) -> Result<(), AtomicReplaceError> {
    if let Err(error) = root.verify() {
        return Err(AtomicReplaceError {
            source: io::Error::other(error),
            published: false,
        });
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!(".{target_name}.tmp-{}-{sequence:016x}", std::process::id());
    let temporary_path = match root.leaf_path(&temporary_name) {
        Ok(path) => path,
        Err(error) => {
            return Err(AtomicReplaceError {
                source: io::Error::other(error),
                published: false,
            });
        }
    };
    let target_path = match root.leaf_path(target_name) {
        Ok(path) => path,
        Err(error) => {
            return Err(AtomicReplaceError {
                source: io::Error::other(error),
                published: false,
            });
        }
    };
    let write_result = (|| -> io::Result<()> {
        let mut file = secure_create_new(&temporary_path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()
    })();
    if let Err(source) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(AtomicReplaceError {
            source,
            published: false,
        });
    }
    if let Err(source) = fs::rename(&temporary_path, &target_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(AtomicReplaceError {
            source,
            published: false,
        });
    }
    if let Err(error) = root.sync_all() {
        return Err(AtomicReplaceError {
            source: io::Error::other(error),
            published: true,
        });
    }
    Ok(())
}

fn entry_file_name(sequence: JournalSequence) -> String {
    format!("entry-{:020}.hbj", sequence.get())
}

fn parse_entry_file_name(name: &str) -> Result<Option<JournalSequence>, DecodeError> {
    let Some(digits) = name
        .strip_prefix("entry-")
        .and_then(|value| value.strip_suffix(".hbj"))
    else {
        return Ok(None);
    };
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DecodeError::InvalidLength);
    }
    let value = digits
        .parse::<u64>()
        .map_err(|_| DecodeError::InvalidSequence)?;
    let sequence = JournalSequence::new(value).map_err(|_| DecodeError::InvalidSequence)?;
    if entry_file_name(sequence) != name {
        return Err(DecodeError::InvalidSequence);
    }
    Ok(Some(sequence))
}

fn encode_marker<E>(
    domain: &JournalDomain,
    authenticator: &AuthenticatorId,
) -> Result<Vec<u8>, FileJournalError<E>>
where
    E: Error + Send + Sync + 'static,
{
    let domain_len =
        u16::try_from(domain.as_str().len()).map_err(|_| FileJournalError::CorruptJournal)?;
    let authenticator_len = u16::try_from(authenticator.as_str().len())
        .map_err(|_| FileJournalError::CorruptJournal)?;
    let mut output = Vec::new();
    output.extend_from_slice(MARKER_MAGIC);
    output.extend_from_slice(&domain_len.to_be_bytes());
    output.extend_from_slice(&authenticator_len.to_be_bytes());
    output.extend_from_slice(domain.as_str().as_bytes());
    output.extend_from_slice(authenticator.as_str().as_bytes());
    Ok(output)
}

fn decode_marker(bytes: &[u8]) -> Result<MarkerRecord, DecodeError> {
    let mut cursor = SliceCursor::new(bytes);
    if cursor.take(MARKER_MAGIC.len())? != MARKER_MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    let domain_len = usize::from(cursor.take_u16()?);
    let authenticator_len = usize::from(cursor.take_u16()?);
    if domain_len == 0 || authenticator_len == 0 {
        return Err(DecodeError::InvalidLength);
    }
    let domain = std::str::from_utf8(cursor.take(domain_len)?)
        .map_err(|_| DecodeError::InvalidUtf8)?
        .to_owned();
    let authenticator = std::str::from_utf8(cursor.take(authenticator_len)?)
        .map_err(|_| DecodeError::InvalidUtf8)?
        .to_owned();
    if !cursor.is_finished() {
        return Err(DecodeError::Trailing);
    }
    Ok(MarkerRecord {
        domain,
        authenticator,
    })
}

fn encode_tail(tail: JournalTail) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(TAIL_MAGIC);
    output.extend_from_slice(&tail.sequence.get().to_be_bytes());
    output.extend_from_slice(&tail.tag.bytes());
    output
}

fn decode_tail(bytes: &[u8]) -> Result<JournalTail, DecodeError> {
    let mut cursor = SliceCursor::new(bytes);
    if cursor.take(TAIL_MAGIC.len())? != TAIL_MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    let sequence =
        JournalSequence::new(cursor.take_u64()?).map_err(|_| DecodeError::InvalidSequence)?;
    let mut tag = [0_u8; 32];
    tag.copy_from_slice(cursor.take(32)?);
    let tag = JournalTag::new(tag).map_err(|_| DecodeError::InvalidTag)?;
    if !cursor.is_finished() {
        return Err(DecodeError::Trailing);
    }
    Ok(JournalTail { sequence, tag })
}

fn encode_entry<E>(record: &JournalRecord) -> Result<Vec<u8>, FileJournalError<E>>
where
    E: Error + Send + Sync + 'static,
{
    let payload_len =
        u32::try_from(record.payload.len()).map_err(|_| FileJournalError::CorruptJournal)?;
    let mut output = Vec::new();
    output.extend_from_slice(ENTRY_MAGIC);
    output.extend_from_slice(&record.sequence.get().to_be_bytes());
    match record.previous_tag {
        Some(tag) => {
            output.push(1);
            output.extend_from_slice(&tag.bytes());
        }
        None => {
            output.push(0);
            output.extend_from_slice(&[0; 32]);
        }
    }
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(&record.tag.bytes());
    output.extend_from_slice(record.payload.as_bytes());
    Ok(output)
}

fn decode_entry(bytes: &[u8]) -> Result<JournalRecord, DecodeError> {
    let mut cursor = SliceCursor::new(bytes);
    if cursor.take(ENTRY_MAGIC.len())? != ENTRY_MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    let sequence =
        JournalSequence::new(cursor.take_u64()?).map_err(|_| DecodeError::InvalidSequence)?;
    let previous_present = cursor.take_u8()?;
    let mut previous_bytes = [0_u8; 32];
    previous_bytes.copy_from_slice(cursor.take(32)?);
    let previous_tag = match previous_present {
        0 if previous_bytes == [0; 32] => None,
        1 => Some(JournalTag::new(previous_bytes).map_err(|_| DecodeError::InvalidPreviousTag)?),
        _ => return Err(DecodeError::InvalidPreviousTag),
    };
    let payload_len =
        usize::try_from(cursor.take_u32()?).map_err(|_| DecodeError::InvalidLength)?;
    if payload_len == 0 || payload_len > MAX_JOURNAL_PAYLOAD_BYTES {
        return Err(DecodeError::InvalidLength);
    }
    let mut tag_bytes = [0_u8; 32];
    tag_bytes.copy_from_slice(cursor.take(32)?);
    let tag = JournalTag::new(tag_bytes).map_err(|_| DecodeError::InvalidTag)?;
    let payload = JournalPayload::new(cursor.take(payload_len)?.to_vec())
        .map_err(|_| DecodeError::InvalidPayload)?;
    if !cursor.is_finished() {
        return Err(DecodeError::Trailing);
    }
    Ok(JournalRecord {
        sequence,
        previous_tag,
        tag,
        payload,
    })
}

fn tail_from_records(records: &[JournalRecord]) -> Option<JournalTail> {
    records.last().map(|record| JournalTail {
        sequence: record.sequence,
        tag: record.tag,
    })
}

#[derive(Debug)]
struct SliceCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DecodeError::InvalidLength)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DecodeError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, DecodeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take_u32(&mut self) -> Result<u32, DecodeError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn take_u64(&mut self) -> Result<u64, DecodeError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestAuthError {
        Contract(JournalContractError),
    }

    impl fmt::Display for TestAuthError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Contract(error) => write!(formatter, "test authenticator: {error}"),
            }
        }
    }

    impl Error for TestAuthError {}

    #[derive(Debug)]
    struct TestAuthenticator {
        id: AuthenticatorId,
    }

    impl TestAuthenticator {
        fn new() -> Result<Self, JournalContractError> {
            Ok(Self {
                id: AuthenticatorId::new("test-journal-mac-v1".to_owned())?,
            })
        }
    }

    impl JournalAuthenticator for TestAuthenticator {
        type Error = TestAuthError;

        fn authenticator_id(&self) -> &AuthenticatorId {
            &self.id
        }

        fn authenticate(
            &self,
            domain: &JournalDomain,
            sequence: JournalSequence,
            previous_tag: Option<JournalTag>,
            payload: &[u8],
        ) -> Result<JournalTag, Self::Error> {
            let mut output = [0_u8; 32];
            let previous = previous_tag.map_or([0; 32], JournalTag::bytes);
            for (index, byte) in domain
                .as_str()
                .as_bytes()
                .iter()
                .copied()
                .chain(sequence.get().to_be_bytes())
                .chain(previous)
                .chain(payload.iter().copied())
                .enumerate()
            {
                let slot = index % output.len();
                output[slot] = output[slot]
                    .wrapping_add(byte)
                    .rotate_left((slot % 7) as u32);
            }
            if output == [0; 32] {
                output[0] = 1;
            }
            JournalTag::new(output).map_err(TestAuthError::Contract)
        }
    }

    #[derive(Debug)]
    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> io::Result<Self> {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "heptabao-single-node-journal-{}-{sequence:016x}-{nanos:x}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self { path })
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn domain() -> Result<JournalDomain, JournalContractError> {
        JournalDomain::new("heptabao/test-journal".to_owned())
    }

    #[test]
    fn create_append_replay_and_reopen_round_trip() {
        let temporary = TempDirectory::new();
        let domain = domain();
        let authenticator = TestAuthenticator::new();
        if let (Ok(temporary), Ok(domain), Ok(authenticator)) = (temporary, domain, authenticator) {
            let journal =
                FileDurableJournal::create_new(&temporary.path, domain.clone(), authenticator);
            assert!(journal.is_ok());
            if let Ok(mut journal) = journal {
                let first = JournalPayload::new(b"accepted".to_vec());
                let second = JournalPayload::new(b"committed".to_vec());
                if let (Ok(first), Ok(second)) = (first, second) {
                    assert!(journal.append(None, first).is_ok());
                    assert!(
                        journal
                            .append(Some(JournalSequence::INITIAL), second)
                            .is_ok()
                    );
                }
                let replayed = journal.replay();
                assert!(replayed.is_ok());
                if let Ok(replayed) = replayed {
                    assert_eq!(replayed.len(), 2);
                    assert_eq!(replayed[0].payload.as_bytes(), b"accepted");
                    assert_eq!(replayed[1].payload.as_bytes(), b"committed");
                }
            }
            let reopened = TestAuthenticator::new().map(|authenticator| {
                FileDurableJournal::reopen_existing(&temporary.path, domain, authenticator)
            });
            assert!(matches!(reopened, Ok(Ok(_))));
        }
    }

    #[test]
    fn stale_tail_is_rejected() {
        let temporary = TempDirectory::new();
        let domain = domain();
        let authenticator = TestAuthenticator::new();
        if let (Ok(temporary), Ok(domain), Ok(authenticator)) = (temporary, domain, authenticator) {
            let journal = FileDurableJournal::create_new(&temporary.path, domain, authenticator);
            if let Ok(mut journal) = journal {
                let payload = JournalPayload::new(b"first".to_vec());
                if let Ok(payload) = payload {
                    assert!(journal.append(None, payload).is_ok());
                }
                let stale = JournalPayload::new(b"stale".to_vec());
                if let Ok(stale) = stale {
                    assert!(matches!(
                        journal.append(None, stale),
                        Err(FileJournalError::TailConflict { .. })
                    ));
                }
            }
        }
    }

    #[test]
    fn tampered_entry_fails_authentication() {
        let temporary = TempDirectory::new();
        let domain = domain();
        let authenticator = TestAuthenticator::new();
        if let (Ok(temporary), Ok(domain), Ok(authenticator)) = (temporary, domain, authenticator) {
            let journal =
                FileDurableJournal::create_new(&temporary.path, domain.clone(), authenticator);
            if let Ok(mut journal) = journal {
                let payload = JournalPayload::new(b"original".to_vec());
                if let Ok(payload) = payload {
                    assert!(journal.append(None, payload).is_ok());
                }
            }
            let entry = temporary
                .path
                .join(entry_file_name(JournalSequence::INITIAL));
            let bytes = fs::read(&entry);
            assert!(bytes.is_ok());
            if let Ok(mut bytes) = bytes {
                if let Some(last) = bytes.last_mut() {
                    *last ^= 0x01;
                }
                assert!(fs::write(&entry, bytes).is_ok());
            }
            let reopened = TestAuthenticator::new().map(|authenticator| {
                FileDurableJournal::reopen_existing(&temporary.path, domain, authenticator)
            });
            assert!(matches!(
                reopened,
                Ok(Err(FileJournalError::AuthenticationFailed))
            ));
        }
    }

    #[test]
    fn exact_next_orphan_requires_explicit_reconciliation() {
        let temporary = TempDirectory::new();
        let domain = domain();
        let authenticator = TestAuthenticator::new();
        if let (Ok(temporary), Ok(domain), Ok(authenticator)) = (temporary, domain, authenticator) {
            let journal =
                FileDurableJournal::create_new(&temporary.path, domain.clone(), authenticator);
            if let Ok(mut journal) = journal {
                let payload = JournalPayload::new(b"persisted-before-tail".to_vec());
                if let Ok(payload) = payload {
                    assert!(journal.append(None, payload).is_ok());
                }
            }
            assert!(fs::remove_file(temporary.path.join(TAIL_NAME)).is_ok());
            let reopened = TestAuthenticator::new().map(|authenticator| {
                FileDurableJournal::reopen_existing(&temporary.path, domain, authenticator)
            });
            assert!(matches!(reopened, Ok(Ok(_))));
            if let Ok(Ok(mut reopened)) = reopened {
                assert!(reopened.tail().is_none());
                assert!(matches!(
                    reopened.replay(),
                    Err(FileJournalError::PendingOrphan)
                ));
                assert!(reopened.recover_authoritative().is_ok());
                assert_eq!(
                    reopened.tail().map(|tail| tail.sequence),
                    Some(JournalSequence::INITIAL)
                );
            }
        }
    }

    #[test]
    fn authoritative_recovery_refreshes_stale_cached_tail() {
        let temporary = TempDirectory::new();
        let domain = domain();
        let authenticator = TestAuthenticator::new();
        if let (Ok(temporary), Ok(domain), Ok(authenticator)) = (temporary, domain, authenticator) {
            let journal = FileDurableJournal::create_new(&temporary.path, domain, authenticator);
            assert!(journal.is_ok());
            if let Ok(mut journal) = journal {
                let payload = JournalPayload::new(b"published-before-error".to_vec());
                assert!(payload.is_ok());
                if let Ok(payload) = payload {
                    assert!(journal.append(None, payload).is_ok());
                    journal.tail = None;
                    assert!(matches!(
                        journal.replay(),
                        Err(FileJournalError::TailConflict { .. })
                    ));
                    let recovered = journal.recover_authoritative();
                    assert!(recovered.is_ok());
                    if let Ok(recovered) = recovered {
                        assert_eq!(recovered.len(), 1);
                    }
                    assert_eq!(
                        journal.tail().map(|tail| tail.sequence),
                        Some(JournalSequence::INITIAL)
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let parent = TempDirectory::new();
        let target = TempDirectory::new();
        let domain = domain();
        let authenticator = TestAuthenticator::new();
        if let (Ok(parent), Ok(target), Ok(domain), Ok(authenticator)) =
            (parent, target, domain, authenticator)
        {
            let link = parent.path.join("journal-link");
            assert!(symlink(&target.path, &link).is_ok());
            let result = FileDurableJournal::create_new(link, domain, authenticator);
            assert!(matches!(result, Err(FileJournalError::UnsafeRoot)));
        }
    }

    #[cfg(unix)]
    #[test]
    fn journal_files_are_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDirectory::new();
        let domain = domain();
        let authenticator = TestAuthenticator::new();
        if let (Ok(temporary), Ok(domain), Ok(authenticator)) = (temporary, domain, authenticator) {
            let journal = FileDurableJournal::create_new(&temporary.path, domain, authenticator);
            assert!(journal.is_ok());
            if let Ok(mut journal) = journal {
                let payload = JournalPayload::new(b"permission-check".to_vec());
                if let Ok(payload) = payload {
                    assert!(journal.append(None, payload).is_ok());
                }
            }
            for path in [
                temporary.path.join(MARKER_NAME),
                temporary.path.join(TAIL_NAME),
                temporary
                    .path
                    .join(entry_file_name(JournalSequence::INITIAL)),
            ] {
                let metadata = fs::symlink_metadata(path);
                assert!(metadata.is_ok());
                if let Ok(metadata) = metadata {
                    assert_eq!(metadata.permissions().mode() & 0o077, 0);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn second_journal_writer_is_fenced() {
        let temporary = TempDirectory::new();
        let domain = domain();
        let authenticator = TestAuthenticator::new();
        if let (Ok(temporary), Ok(domain), Ok(authenticator)) = (temporary, domain, authenticator) {
            let first =
                FileDurableJournal::create_new(&temporary.path, domain.clone(), authenticator);
            assert!(first.is_ok());
            let second = TestAuthenticator::new().map(|authenticator| {
                FileDurableJournal::reopen_existing(&temporary.path, domain, authenticator)
            });
            assert!(matches!(second, Ok(Err(FileJournalError::WriterBusy))));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_journal_remains_bound_after_root_path_replacement() {
        let temporary = TempDirectory::new();
        let domain = domain();
        let authenticator = TestAuthenticator::new();
        if let (Ok(temporary), Ok(domain), Ok(authenticator)) = (temporary, domain, authenticator) {
            let journal = FileDurableJournal::create_new(&temporary.path, domain, authenticator);
            assert!(journal.is_ok());
            if let Ok(mut journal) = journal {
                let moved = temporary.path.with_file_name(format!(
                    "{}-moved",
                    temporary
                        .path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("heptabao-journal")
                ));
                assert!(fs::rename(&temporary.path, &moved).is_ok());
                assert!(fs::create_dir(&temporary.path).is_ok());
                let payload = JournalPayload::new(b"descriptor-bound".to_vec());
                assert!(payload.is_ok());
                if let Ok(payload) = payload {
                    assert!(journal.append(None, payload).is_ok());
                    assert!(moved.join(TAIL_NAME).is_file());
                    assert!(!temporary.path.join(TAIL_NAME).exists());
                }
                drop(journal);
                let _ = fs::remove_dir_all(&moved);
            }
        }
    }
}
