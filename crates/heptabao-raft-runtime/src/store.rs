use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::ops::RangeBounds;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::state_machine::{
    ApplicationResponse as ClientResponse, StateMachine as MemStoreStateMachine, TypeConfig,
};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use futures::{Stream, TryStreamExt};
use openraft::alias::{EntryOf, LogIdOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf, VoteOf};
use openraft::entry::RaftEntry;
use openraft::storage::{
    EntryResponder, IOFlushed, LogState, RaftLogReader, RaftLogStorage, RaftSnapshotBuilder,
    RaftStateMachine,
};
use openraft::{EntryPayload, OptionalSend};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

const MAX_DURABLE_ARTIFACT_BYTES: usize = 128 * 1024 * 1024;
const ENVELOPE_OVERHEAD_BYTES: usize = 20;
const COMPACT_STATE_BUNDLE_FORMAT: u16 = 2;

const LOG_MAGIC: [u8; 8] = *b"HBRLOG01";
const LOG_JOURNAL_MAGIC: [u8; 8] = *b"HBRLJ001";
const LOG_EVENT_MAGIC: [u8; 8] = *b"HBRLE001";
const STATE_BUNDLE_MAGIC: [u8; 8] = *b"HBRSB001";
const STATE_JOURNAL_MAGIC: [u8; 8] = *b"HBRSJ001";
const STATE_EVENT_MAGIC: [u8; 8] = *b"HBRSE001";
const INITIALIZATION_MAGIC: [u8; 8] = *b"HBRINI01";
const INITIALIZATION_MARKER_FILE: &str = "initialized.bin";
const LOG_DOMAIN: &str = "raft-log";
const STATE_MACHINE_DOMAIN: &str = "state-machine";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn crc32(bytes: &[u8]) -> u32 {
    // IEEE CRC32, identical to the persisted frame format. Avoid eight scalar
    // polynomial rounds per byte while holding the state-machine writer.
    crc32fast::hash(bytes)
}

fn encode_envelope(magic: [u8; 8], payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u64::try_from(payload.len()).map_err(|_| invalid("payload length overflow"))?;
    let mut encoded = Vec::with_capacity(8 + 8 + payload.len() + 4);
    encoded.extend_from_slice(&magic);
    encoded.extend_from_slice(&length.to_le_bytes());
    encoded.extend_from_slice(payload);
    encoded.extend_from_slice(&crc32(payload).to_le_bytes());
    Ok(encoded)
}

fn decode_envelope(magic: [u8; 8], bytes: &[u8]) -> io::Result<Vec<u8>> {
    if bytes.len() < 20 {
        return Err(invalid("durable envelope is truncated"));
    }
    if bytes[..8] != magic {
        return Err(invalid("durable envelope magic mismatch"));
    }
    let length = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| invalid("invalid durable envelope length field"))?,
    );
    let length =
        usize::try_from(length).map_err(|_| invalid("durable envelope length overflow"))?;
    let expected = 8_usize
        .checked_add(8)
        .and_then(|value| value.checked_add(length))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| invalid("durable envelope size overflow"))?;
    if bytes.len() != expected {
        return Err(invalid(format!(
            "durable envelope length mismatch: expected {expected}, got {}",
            bytes.len()
        )));
    }
    let payload = &bytes[16..16 + length];
    let stored_crc = u32::from_le_bytes(
        bytes[16 + length..expected]
            .try_into()
            .map_err(|_| invalid("invalid durable envelope checksum field"))?,
    );
    let actual_crc = crc32(payload);
    if stored_crc != actual_crc {
        return Err(invalid(format!(
            "durable envelope checksum mismatch: stored {stored_crc:08x}, actual {actual_crc:08x}"
        )));
    }
    Ok(payload.to_vec())
}

fn ensure_real_directory(path: &Path, label: &str) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(invalid(format!("{label} is not a real directory"))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_dir() {
                Ok(())
            } else {
                Err(invalid(format!("{label} is not a real directory")))
            }
        }
        Err(error) => Err(error),
    }
}

fn regular_file_status(path: &Path, label: &str) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(invalid(format!("{label} is not a regular file"))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn require_real_directory(path: &Path, label: &str) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(invalid(format!("{label} is not a real directory"))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(invalid(format!("{label} does not exist")))
        }
        Err(error) => Err(error),
    }
}

fn replacement_candidates(path: &Path, suffix: &str) -> io::Result<Vec<PathBuf>> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid(format!("{} has no parent directory", path.display())))?;
    require_real_directory(parent, "durable replacement parent directory")?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid("durable file name is not valid UTF-8"))?;
    let prefix = format!(".{file_name}.");
    let mut candidates = Vec::new();
    for entry in fs::read_dir(parent)? {
        let candidate = entry?.path();
        let matches = candidate
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(suffix));
        if matches {
            candidates.push(candidate);
        }
    }
    candidates.sort();
    Ok(candidates)
}

fn recover_interrupted_replace(path: &Path) -> io::Result<()> {
    if regular_file_status(path, "durable replacement target")? {
        return Ok(());
    }
    let previous = replacement_candidates(path, ".previous")?;
    match previous.as_slice() {
        [] => Ok(()),
        [candidate] => {
            if !regular_file_status(candidate, "interrupted replacement candidate")? {
                return Err(invalid("interrupted replacement candidate disappeared"));
            }
            fs::rename(candidate, path)?;
            sync_parent(path)
        }
        _ => Err(invalid(format!(
            "multiple interrupted replacement candidates for {}",
            path.display()
        ))),
    }
}

fn discard_stale_previous_after_validation(path: &Path) -> io::Result<()> {
    if !regular_file_status(path, "validated durable current generation")? {
        return Err(invalid(format!(
            "cannot retire replacement history without current generation: {}",
            path.display()
        )));
    }
    let previous = replacement_candidates(path, ".previous")?;
    match previous.as_slice() {
        [] => Ok(()),
        [candidate] => {
            if !regular_file_status(candidate, "stale replacement candidate")? {
                return Err(invalid("stale replacement candidate is not a regular file"));
            }
            fs::remove_file(candidate)?;
            sync_parent(path)
        }
        _ => Err(invalid(format!(
            "multiple stale replacement candidates for {}",
            path.display()
        ))),
    }
}

fn ensure_create_location_is_fresh(root: &Path, data_path: &Path) -> io::Result<()> {
    let entries = fs::read_dir(root)?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<io::Result<Vec<_>>>()?;
    if !entries.is_empty() {
        return Err(invalid(format!(
            "create-new refused nonempty store directory for {}: {}",
            data_path.display(),
            entries
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}

fn read_payload(path: &Path, magic: [u8; 8]) -> io::Result<Vec<u8>> {
    recover_interrupted_replace(path)?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_DURABLE_ARTIFACT_BYTES as u64 {
        return Err(invalid("durable artifact exceeds 128 MiB safety bound"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take((MAX_DURABLE_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DURABLE_ARTIFACT_BYTES {
        return Err(invalid("durable artifact exceeds 128 MiB safety bound"));
    }
    decode_envelope(magic, &bytes)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid(format!("{} has no parent directory", path.display())))?;
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

fn atomic_write(path: &Path, magic: [u8; 8], payload: &[u8]) -> io::Result<()> {
    validate_artifact_payload_len(payload.len(), MAX_DURABLE_ARTIFACT_BYTES)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid(format!("{} has no parent directory", path.display())))?;
    require_real_directory(parent, "durable write parent directory")?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid("durable file name is not valid UTF-8"))?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    // Keep the existing frame bytes without allocating another full artifact.
    let length = u64::try_from(payload.len()).map_err(|_| invalid("payload length overflow"))?;
    let checksum = crc32(payload).to_le_bytes();
    let current_exists = regular_file_status(path, "durable current generation")?;

    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&magic)?;
        file.write_all(&length.to_le_bytes())?;
        file.write_all(payload)?;
        file.write_all(&checksum)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);

        #[cfg(windows)]
        if current_exists {
            let previous = parent.join(format!(
                ".{file_name}.{}.{}.previous",
                std::process::id(),
                sequence
            ));
            fs::rename(path, &previous)?;
            if let Err(error) = fs::rename(&temporary, path) {
                let _ = fs::rename(&previous, path);
                return Err(error);
            }
            let _ = fs::remove_file(previous);
        } else {
            fs::rename(&temporary, path)?;
        }

        #[cfg(not(windows))]
        {
            let _ = current_exists;
            fs::rename(&temporary, path)?;
        }

        sync_parent(path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_write_raw(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid(format!("{} has no parent directory", path.display())))?;
    require_real_directory(parent, "durable raw write parent directory")?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid("durable raw file name is not valid UTF-8"))?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let current_exists = regular_file_status(path, "durable raw current generation")?;
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        #[cfg(windows)]
        if current_exists {
            let previous = parent.join(format!(
                ".{file_name}.{}.{}.previous",
                std::process::id(),
                sequence
            ));
            fs::rename(path, &previous)?;
            if let Err(error) = fs::rename(&temporary, path) {
                let _ = fs::rename(&previous, path);
                return Err(error);
            }
            let _ = fs::remove_file(previous);
        } else {
            fs::rename(&temporary, path)?;
        }
        #[cfg(not(windows))]
        {
            let _ = current_exists;
            fs::rename(&temporary, path)?;
        }
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_json<T>(path: &Path, magic: [u8; 8]) -> io::Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let payload = read_payload(path, magic)?;
    serde_json::from_slice(&payload).map_err(|error| invalid(error.to_string()))
}

fn write_json<T>(path: &Path, magic: [u8; 8], value: &T) -> io::Result<()>
where
    T: Serialize,
{
    write_json_with_bound(path, magic, value, MAX_DURABLE_ARTIFACT_BYTES)
}

fn validate_artifact_payload_len(payload_len: usize, artifact_bound: usize) -> io::Result<()> {
    if payload_len
        .checked_add(ENVELOPE_OVERHEAD_BYTES)
        .is_none_or(|size| size > artifact_bound)
    {
        return Err(invalid("durable artifact exceeds serialized safety bound"));
    }
    Ok(())
}

/// Count actual JSON bytes during serialization, including base64 and string
/// escaping. Reject before opening a temporary file or replacing a good bundle.
fn write_json_with_bound<T: Serialize>(
    path: &Path,
    magic: [u8; 8],
    value: &T,
    artifact_bound: usize,
) -> io::Result<()> {
    struct BoundedJson {
        bytes: Vec<u8>,
        maximum: usize,
    }
    impl Write for BoundedJson {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            if self
                .bytes
                .len()
                .checked_add(input.len())
                .is_none_or(|size| size > self.maximum)
            {
                return Err(invalid("durable artifact exceeds serialized safety bound"));
            }
            self.bytes.extend_from_slice(input);
            Ok(input.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let maximum = artifact_bound
        .checked_sub(ENVELOPE_OVERHEAD_BYTES)
        .ok_or_else(|| invalid("durable artifact bound cannot contain envelope"))?;
    let mut writer = BoundedJson {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut writer, value).map_err(|error| invalid(error.to_string()))?;
    validate_artifact_payload_len(writer.bytes.len(), artifact_bound)?;
    atomic_write(path, magic, &writer.bytes)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistentInitializationMarker {
    format_version: u16,
    domain: String,
    authoritative_file: String,
}

impl PersistentInitializationMarker {
    fn new(domain: &str, authoritative_file: &str) -> Self {
        Self {
            format_version: 1,
            domain: domain.to_owned(),
            authoritative_file: authoritative_file.to_owned(),
        }
    }

    fn validate(&self, expected_domain: &str, expected_file: &str) -> io::Result<()> {
        if self.format_version != 1 {
            return Err(invalid("unsupported initialization marker version"));
        }
        if self.domain != expected_domain {
            return Err(invalid(format!(
                "initialization marker domain mismatch: expected {expected_domain}, got {}",
                self.domain
            )));
        }
        if self.authoritative_file != expected_file {
            return Err(invalid(format!(
                "initialization marker file mismatch: expected {expected_file}, got {}",
                self.authoritative_file
            )));
        }
        Ok(())
    }
}

fn initialization_marker_path(root: &Path) -> PathBuf {
    root.join(INITIALIZATION_MARKER_FILE)
}

fn read_initialization_marker(
    root: &Path,
    expected_domain: &str,
    expected_file: &str,
) -> io::Result<Option<PersistentInitializationMarker>> {
    let path = initialization_marker_path(root);
    recover_interrupted_replace(&path)?;
    if !regular_file_status(&path, "initialization marker")? {
        return Ok(None);
    }
    let marker: PersistentInitializationMarker = read_json(&path, INITIALIZATION_MAGIC)?;
    marker.validate(expected_domain, expected_file)?;
    discard_stale_previous_after_validation(&path)?;
    Ok(Some(marker))
}

fn persist_initialization_marker(
    root: &Path,
    domain: &str,
    authoritative_file: &str,
) -> io::Result<()> {
    write_json(
        &initialization_marker_path(root),
        INITIALIZATION_MAGIC,
        &PersistentInitializationMarker::new(domain, authoritative_file),
    )
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PersistentLogState {
    #[serde(default)]
    journal_format: u16,
    #[serde(default)]
    journal_epoch: u64,
    last_purged_log_id: Option<LogIdOf<TypeConfig>>,
    committed: Option<LogIdOf<TypeConfig>>,
    vote: Option<VoteOf<TypeConfig>>,
    log: BTreeMap<u64, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum LogJournalEvent {
    Vote(VoteOf<TypeConfig>),
    Committed(Option<LogIdOf<TypeConfig>>),
    Append(Vec<(u64, String)>),
    Truncate { start: u64 },
    Purge { log_id: LogIdOf<TypeConfig> },
}

fn log_journal_path(state_path: &Path) -> PathBuf {
    state_path.with_file_name("raft-log.journal")
}

fn initialize_log_journal(path: &Path, epoch: u64) -> io::Result<()> {
    if epoch == 0 {
        return Err(invalid("raft log journal epoch must be nonzero"));
    }
    let mut header = Vec::with_capacity(LOG_JOURNAL_MAGIC.len() + 8);
    header.extend_from_slice(&LOG_JOURNAL_MAGIC);
    header.extend_from_slice(&epoch.to_le_bytes());
    atomic_write_raw(path, &header)
}

fn log_journal_epoch(path: &Path) -> io::Result<u64> {
    if !regular_file_status(path, "raft log delta journal")? {
        return Err(invalid("raft log delta journal is missing"));
    }
    let mut file = File::open(path)?;
    let mut header = [0_u8; 16];
    file.read_exact(&mut header)?;
    if header[..8] != LOG_JOURNAL_MAGIC {
        return Err(invalid("raft log delta journal magic mismatch"));
    }
    let epoch = u64::from_le_bytes(
        header[8..16]
            .try_into()
            .map_err(|_| invalid("invalid raft log journal epoch"))?,
    );
    if epoch == 0 {
        return Err(invalid("raft log journal epoch is zero"));
    }
    Ok(epoch)
}

fn append_log_journal(path: &Path, expected_epoch: u64, event: &LogJournalEvent) -> io::Result<()> {
    if log_journal_epoch(path)? != expected_epoch {
        return Err(invalid("raft log checkpoint/journal epoch mismatch"));
    }
    let payload = serde_json::to_vec(event).map_err(|error| invalid(error.to_string()))?;
    if payload.len() > 16 * 1024 * 1024 {
        return Err(invalid("raft log delta event exceeds 16 MiB"));
    }
    let frame = encode_envelope(LOG_EVENT_MAGIC, &payload)?;
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(&frame)?;
    file.flush()?;
    file.sync_all()
}

fn apply_log_journal_event(
    state: &mut PersistentLogState,
    event: LogJournalEvent,
) -> io::Result<()> {
    match event {
        LogJournalEvent::Vote(vote) => state.vote = Some(vote),
        LogJournalEvent::Committed(committed) => state.committed = committed,
        LogJournalEvent::Append(entries) => {
            for (index, serialized) in entries {
                if let Some(existing) = state.log.get(&index) {
                    if existing != &serialized {
                        return Err(invalid(format!(
                            "journal attempts conflicting overwrite at log index {index}"
                        )));
                    }
                } else {
                    state.log.insert(index, serialized);
                }
            }
        }
        LogJournalEvent::Truncate { start } => {
            let remove = state
                .log
                .range(start..)
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            for index in remove {
                state.log.remove(&index);
            }
        }
        LogJournalEvent::Purge { log_id } => {
            if state.last_purged_log_id.is_some_and(|last| last > log_id) {
                return Err(invalid("purge log id regressed"));
            }
            let remove = state
                .log
                .range(..=log_id.index)
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            for index in remove {
                state.log.remove(&index);
            }
            state.last_purged_log_id = Some(log_id);
        }
    }
    Ok(())
}

fn replay_log_journal(path: &Path, state: &mut PersistentLogState) -> io::Result<()> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > 256 * 1024 * 1024 {
        return Err(invalid("raft log delta journal exceeds 256 MiB"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    if bytes.len() < 16 || bytes[..8] != LOG_JOURNAL_MAGIC {
        return Err(invalid(
            "raft log delta journal header is truncated or invalid",
        ));
    }
    let journal_epoch = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| invalid("invalid raft log journal epoch"))?,
    );
    if journal_epoch < state.journal_epoch {
        // The checkpoint was durably replaced before the previous journal could
        // be collapsed. The newer checkpoint already includes every old event.
        initialize_log_journal(path, state.journal_epoch)?;
        return state.validate();
    }
    if journal_epoch != state.journal_epoch {
        return Err(invalid("raft log journal leads its checkpoint epoch"));
    }
    let mut offset = 16;
    let mut last_good = offset;
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            break;
        }
        if bytes[offset..offset + 8] != LOG_EVENT_MAGIC {
            return Err(invalid("raft log delta event magic mismatch"));
        }
        let length = usize::try_from(u64::from_le_bytes(
            bytes[offset + 8..offset + 16]
                .try_into()
                .map_err(|_| invalid("invalid raft log event length"))?,
        ))
        .map_err(|_| invalid("raft log event length overflow"))?;
        if length > 16 * 1024 * 1024 {
            return Err(invalid("raft log delta event exceeds 16 MiB"));
        }
        let frame_len = 16_usize
            .checked_add(length)
            .and_then(|value| value.checked_add(4))
            .ok_or_else(|| invalid("raft log event size overflow"))?;
        if bytes.len() - offset < frame_len {
            break;
        }
        let payload = &bytes[offset + 16..offset + 16 + length];
        let stored_crc = u32::from_le_bytes(
            bytes[offset + 16 + length..offset + frame_len]
                .try_into()
                .map_err(|_| invalid("invalid raft log event checksum"))?,
        );
        if crc32(payload) != stored_crc {
            return Err(invalid("raft log delta event checksum mismatch"));
        }
        let event: LogJournalEvent =
            serde_json::from_slice(payload).map_err(|error| invalid(error.to_string()))?;
        apply_log_journal_event(state, event)?;
        offset += frame_len;
        last_good = offset;
    }
    if last_good != bytes.len() {
        let file = OpenOptions::new().write(true).open(path)?;
        file.set_len(u64::try_from(last_good).map_err(|_| invalid("journal offset overflow"))?)?;
        file.sync_all()?;
    }
    state.validate()
}

impl PersistentLogState {
    fn validate(&self) -> io::Result<()> {
        if self.journal_format > 1 || (self.journal_format == 1 && self.journal_epoch == 0) {
            return Err(invalid("unsupported or zero raft log journal epoch"));
        }
        let mut previous = self.last_purged_log_id.as_ref().map(|log_id| log_id.index);
        for index in self.log.keys().copied() {
            if let Some(previous) = previous {
                let expected = previous
                    .checked_add(1)
                    .ok_or_else(|| invalid("log index overflow while validating continuity"))?;
                if index != expected {
                    return Err(invalid(format!(
                        "log hole detected: expected index {expected}, observed {index}"
                    )));
                }
            }
            previous = Some(index);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DurableLogStore {
    state_path: PathBuf,
    state: Arc<Mutex<PersistentLogState>>,
}

impl DurableLogStore {
    pub fn create(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        ensure_real_directory(root, "raft log store root")?;
        let state_path = root.join("raft-log.bin");
        ensure_create_location_is_fresh(root, &state_path)?;
        let state = PersistentLogState {
            journal_format: 1,
            journal_epoch: 1,
            ..Default::default()
        };
        write_json(&state_path, LOG_MAGIC, &state)?;
        initialize_log_journal(&log_journal_path(&state_path), state.journal_epoch)?;
        persist_initialization_marker(root, LOG_DOMAIN, "raft-log.bin")?;
        Ok(Self {
            state_path,
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn open_existing(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        require_real_directory(root, "raft log store root")?;
        let state_path = root.join("raft-log.bin");
        let marker = read_initialization_marker(root, LOG_DOMAIN, "raft-log.bin")?;
        if marker.is_none() {
            return Err(invalid(
                "raft log store is not initialized; explicit legacy adoption is required",
            ));
        }
        recover_interrupted_replace(&state_path)?;
        if !regular_file_status(&state_path, "authoritative raft log generation")? {
            return Err(invalid(
                "initialized raft log store is missing its authoritative generation",
            ));
        }
        let mut state: PersistentLogState = read_json(&state_path, LOG_MAGIC)?;
        state.validate()?;
        let journal_path = log_journal_path(&state_path);
        if state.journal_format == 0 {
            state.journal_epoch = 1;
            if !regular_file_status(&journal_path, "legacy raft log delta journal")? {
                initialize_log_journal(&journal_path, state.journal_epoch)?;
            }
            replay_log_journal(&journal_path, &mut state)?;
            state.journal_format = 1;
            write_json(&state_path, LOG_MAGIC, &state)?;
            initialize_log_journal(&journal_path, state.journal_epoch)?;
        } else if state.journal_format == 1 {
            if !regular_file_status(&journal_path, "raft log delta journal")? {
                return Err(invalid(
                    "initialized raft log checkpoint requires its delta journal",
                ));
            }
            replay_log_journal(&journal_path, &mut state)?;
        } else {
            return Err(invalid("unsupported raft log journal format"));
        }
        discard_stale_previous_after_validation(&state_path)?;
        Ok(Self {
            state_path,
            state: Arc::new(Mutex::new(state)),
        })
    }

    #[cfg(test)]
    pub fn adopt_legacy(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        require_real_directory(root, "legacy raft log store root")?;
        let state_path = root.join("raft-log.bin");
        if read_initialization_marker(root, LOG_DOMAIN, "raft-log.bin")?.is_some() {
            return Err(invalid(
                "raft log store already has an initialization marker; use open_existing",
            ));
        }
        if !replacement_candidates(&initialization_marker_path(root), ".tmp")?.is_empty() {
            return Err(invalid(
                "legacy adoption refused unresolved initialization-marker temporary artifacts",
            ));
        }
        if !replacement_candidates(&state_path, ".tmp")?.is_empty() {
            return Err(invalid(
                "legacy adoption refused unresolved raft-log temporary artifacts",
            ));
        }
        recover_interrupted_replace(&state_path)?;
        if !regular_file_status(&state_path, "legacy authoritative raft log generation")? {
            return Err(invalid(
                "legacy raft log store has no authoritative generation",
            ));
        }
        let mut state: PersistentLogState = read_json(&state_path, LOG_MAGIC)?;
        state.validate()?;
        state.journal_format = 1;
        state.journal_epoch = 1;
        initialize_log_journal(&log_journal_path(&state_path), state.journal_epoch)?;
        write_json(&state_path, LOG_MAGIC, &state)?;
        discard_stale_previous_after_validation(&state_path)?;
        persist_initialization_marker(root, LOG_DOMAIN, "raft-log.bin")?;
        Ok(Self {
            state_path,
            state: Arc::new(Mutex::new(state)),
        })
    }

    fn persist(&self, state: &PersistentLogState) -> io::Result<()> {
        state.validate()?;
        write_json(&self.state_path, LOG_MAGIC, state)
    }

    #[cfg(test)]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }
}

impl RaftLogReader<TypeConfig> for DurableLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<EntryOf<TypeConfig>>, io::Error> {
        let state = self.state.lock().await;
        let serialized = state
            .log
            .range(range)
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        serialized
            .into_iter()
            .map(|value| serde_json::from_str(&value).map_err(|error| invalid(error.to_string())))
            .collect()
    }

    async fn limited_get_log_entries(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Vec<EntryOf<TypeConfig>>, io::Error> {
        if start >= end {
            return Ok(Vec::new());
        }
        let budget = crate::replication_bounds::entry_payload_budget()?;
        let state = self.state.lock().await;
        let mut entries = Vec::new();
        let mut encoded_bytes = 0_usize;
        let mut expected = start;
        for (&index, serialized) in state.log.range(start..end) {
            if index != expected {
                return Err(invalid("replication log range has a hole"));
            }
            let next = encoded_bytes
                .checked_add(serialized.len())
                .and_then(|n| n.checked_add(usize::from(!entries.is_empty())))
                .ok_or_else(|| invalid("replication payload size overflow"))?;
            if next > budget {
                if entries.is_empty() {
                    return Err(invalid("single Raft entry exceeds remote wire budget"));
                }
                break;
            }
            let entry: EntryOf<TypeConfig> =
                serde_json::from_str(serialized).map_err(|error| invalid(error.to_string()))?;
            if entry.index() != index {
                return Err(invalid("replication entry index mismatch"));
            }
            entries.push(entry);
            encoded_bytes = next;
            expected = index
                .checked_add(1)
                .ok_or_else(|| invalid("replication index overflow"))?;
        }
        if entries.is_empty() {
            return Err(invalid("replication log range is absent"));
        }
        Ok(entries)
    }

    async fn read_vote(&mut self) -> Result<Option<VoteOf<TypeConfig>>, io::Error> {
        Ok(self.state.lock().await.vote)
    }
}

impl RaftLogStorage<TypeConfig> for DurableLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, io::Error> {
        let state = self.state.lock().await;
        let last_log_id = match state.log.iter().next_back() {
            Some((_, serialized)) => {
                let entry: EntryOf<TypeConfig> =
                    serde_json::from_str(serialized).map_err(|error| invalid(error.to_string()))?;
                Some(entry.log_id())
            }
            None => state.last_purged_log_id,
        };
        Ok(LogState {
            last_purged_log_id: state.last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &VoteOf<TypeConfig>) -> Result<(), io::Error> {
        let mut state = self.state.lock().await;
        let event = LogJournalEvent::Vote(*vote);
        append_log_journal(
            &log_journal_path(&self.state_path),
            state.journal_epoch,
            &event,
        )?;
        apply_log_journal_event(&mut state, event)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogIdOf<TypeConfig>>,
    ) -> Result<(), io::Error> {
        let mut state = self.state.lock().await;
        let event = LogJournalEvent::Committed(committed);
        append_log_journal(
            &log_journal_path(&self.state_path),
            state.journal_epoch,
            &event,
        )?;
        apply_log_journal_event(&mut state, event)
    }

    async fn read_committed(&mut self) -> Result<Option<LogIdOf<TypeConfig>>, io::Error> {
        Ok(self.state.lock().await.committed)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: IOFlushed<TypeConfig>,
    ) -> Result<(), io::Error>
    where
        I: IntoIterator<Item = EntryOf<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut state = self.state.lock().await;
        let mut serialized = Vec::new();
        let mut last = state
            .log
            .keys()
            .next_back()
            .copied()
            .or_else(|| state.last_purged_log_id.map(|value| value.index));
        for entry in entries {
            let index = entry.index();
            let value =
                serde_json::to_string(&entry).map_err(|error| invalid(error.to_string()))?;
            if let Some(existing) = state.log.get(&index) {
                if existing != &value {
                    let error = invalid(format!(
                        "attempted to overwrite log index {index} without truncate"
                    ));
                    callback.io_completed(Err(io::Error::new(error.kind(), error.to_string())));
                    return Err(error);
                }
                continue;
            }
            if let Some(previous) = last {
                let expected = previous
                    .checked_add(1)
                    .ok_or_else(|| invalid("log append index overflow"))?;
                if index != expected {
                    let error = invalid(format!(
                        "log append would create a hole: expected {expected}, observed {index}"
                    ));
                    callback.io_completed(Err(io::Error::new(error.kind(), error.to_string())));
                    return Err(error);
                }
            }
            last = Some(index);
            serialized.push((index, value));
        }
        if serialized.is_empty() {
            callback.io_completed(Ok(()));
            return Ok(());
        }
        let event = LogJournalEvent::Append(serialized);
        match append_log_journal(
            &log_journal_path(&self.state_path),
            state.journal_epoch,
            &event,
        ) {
            Ok(()) => {
                apply_log_journal_event(&mut state, event)?;
                callback.io_completed(Ok(()));
                Ok(())
            }
            Err(error) => {
                callback.io_completed(Err(io::Error::new(error.kind(), error.to_string())));
                Err(error)
            }
        }
    }

    async fn truncate_after(
        &mut self,
        last_log_id: Option<LogIdOf<TypeConfig>>,
    ) -> Result<(), io::Error> {
        let start = match last_log_id {
            Some(log_id) => log_id
                .index
                .checked_add(1)
                .ok_or_else(|| invalid("truncate index overflow"))?,
            None => 0,
        };
        let mut state = self.state.lock().await;
        let event = LogJournalEvent::Truncate { start };
        append_log_journal(
            &log_journal_path(&self.state_path),
            state.journal_epoch,
            &event,
        )?;
        apply_log_journal_event(&mut state, event)
    }

    async fn purge(&mut self, log_id: LogIdOf<TypeConfig>) -> Result<(), io::Error> {
        let mut state = self.state.lock().await;
        if state.last_purged_log_id.is_some_and(|last| last > log_id) {
            return Err(invalid("purge log id regressed"));
        }
        // A follower may install a snapshot (or receive a purge request after
        // reconnecting) whose frontier is ahead of the locally retained log.
        // The Raft storage contract permits advancing the purge marker across
        // that gap; rejecting it permanently shuts down a node during restart
        // instead of allowing the subsequent snapshot/log reconciliation.
        let event = LogJournalEvent::Purge { log_id };
        append_log_journal(
            &log_journal_path(&self.state_path),
            state.journal_epoch,
            &event,
        )?;
        let mut candidate = state.clone();
        apply_log_journal_event(&mut candidate, event)?;
        candidate.journal_epoch = candidate
            .journal_epoch
            .checked_add(1)
            .ok_or_else(|| invalid("raft log journal epoch overflow"))?;
        self.persist(&candidate)?;
        initialize_log_journal(&log_journal_path(&self.state_path), candidate.journal_epoch)?;
        *state = candidate;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotEncoding {
    LegacyBytes,
    CompactBase64,
}

#[derive(Clone, Debug)]
struct PersistentSnapshot {
    meta: SnapshotMetaOf<TypeConfig>,
    data: Vec<u8>,
    encoding: SnapshotEncoding,
}

impl Serialize for PersistentSnapshot {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut fields = serializer.serialize_struct("PersistentSnapshot", 2)?;
        fields.serialize_field("meta", &self.meta)?;
        match self.encoding {
            SnapshotEncoding::LegacyBytes => fields.serialize_field("data", &self.data)?,
            SnapshotEncoding::CompactBase64 => {
                fields.serialize_field("data", &STANDARD_NO_PAD.encode(&self.data))?
            }
        }
        fields.end()
    }
}

impl<'de> Deserialize<'de> for PersistentSnapshot {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Data {
            Legacy(Vec<u8>),
            Compact(String),
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            meta: SnapshotMetaOf<TypeConfig>,
            data: Data,
        }
        let wire = Wire::deserialize(deserializer)?;
        let (data, encoding) = match wire.data {
            Data::Legacy(data) => (data, SnapshotEncoding::LegacyBytes),
            Data::Compact(encoded) => {
                let data = STANDARD_NO_PAD
                    .decode(&encoded)
                    .map_err(|_| serde::de::Error::custom("invalid compact snapshot base64"))?;
                if STANDARD_NO_PAD.encode(&data) != encoded {
                    return Err(serde::de::Error::custom(
                        "noncanonical compact snapshot base64",
                    ));
                }
                (data, SnapshotEncoding::CompactBase64)
            }
        };
        if data.len() > MAX_DURABLE_ARTIFACT_BYTES {
            return Err(serde::de::Error::custom(
                "decoded snapshot exceeds safety bound",
            ));
        }
        Ok(Self {
            meta: wire.meta,
            data,
            encoding,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistentStateBundle {
    format_version: u16,
    #[serde(default)]
    journal_format: u16,
    generation: u64,
    state: MemStoreStateMachine,
    current_snapshot: Option<PersistentSnapshot>,
}

impl Default for PersistentStateBundle {
    fn default() -> Self {
        Self {
            format_version: 1,
            journal_format: 0,
            generation: 1,
            state: MemStoreStateMachine::default(),
            current_snapshot: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum StateJournalEvent {
    Apply { generation: u64, entry: String },
}

fn state_journal_path(bundle_path: &Path) -> PathBuf {
    bundle_path.with_file_name("state-machine.journal")
}

fn initialize_state_journal(path: &Path) -> io::Result<()> {
    atomic_write_raw(path, &STATE_JOURNAL_MAGIC)
}

fn append_state_journal(path: &Path, event: &StateJournalEvent) -> io::Result<()> {
    if !regular_file_status(path, "raft state-machine delta journal")? {
        return Err(invalid("raft state-machine delta journal is missing"));
    }
    let payload = serde_json::to_vec(event).map_err(|error| invalid(error.to_string()))?;
    if payload.len() > 16 * 1024 * 1024 {
        return Err(invalid("raft state-machine delta event exceeds 16 MiB"));
    }
    let frame = encode_envelope(STATE_EVENT_MAGIC, &payload)?;
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(&frame)?;
    file.flush()?;
    file.sync_all()
}

fn apply_state_entry(
    state: &mut MemStoreStateMachine,
    entry: &EntryOf<TypeConfig>,
) -> ClientResponse {
    state.last_applied_log = Some(entry.log_id);
    match &entry.payload {
        EntryPayload::Blank => ClientResponse::blank(),
        EntryPayload::Normal(data) => state.apply(data),
        EntryPayload::Membership(membership) => {
            state.last_membership =
                StoredMembershipOf::<TypeConfig>::new(Some(entry.log_id), membership.clone());
            ClientResponse::blank()
        }
    }
}

fn apply_state_journal_event(
    bundle: &mut PersistentStateBundle,
    event: StateJournalEvent,
) -> io::Result<Option<ClientResponse>> {
    match event {
        StateJournalEvent::Apply { generation, entry } => {
            let entry: EntryOf<TypeConfig> =
                serde_json::from_str(&entry).map_err(|error| invalid(error.to_string()))?;
            if generation <= bundle.generation {
                let checkpoint_index = bundle
                    .state
                    .last_applied_log
                    .map(|log_id| log_id.index)
                    .ok_or_else(|| invalid("checkpoint generation covers no applied log"))?;
                if entry.log_id.index > checkpoint_index {
                    return Err(invalid(
                        "checkpoint generation claims an unapplied state-machine event",
                    ));
                }
                return Ok(None);
            }
            let expected_generation = bundle.next_generation()?;
            if generation != expected_generation {
                return Err(invalid(format!(
                    "state-machine journal generation gap: expected {expected_generation}, observed {generation}"
                )));
            }
            if let Some(previous) = bundle.state.last_applied_log {
                let expected_index = previous
                    .index
                    .checked_add(1)
                    .ok_or_else(|| invalid("state-machine log index overflow"))?;
                if entry.log_id.index != expected_index {
                    return Err(invalid(format!(
                        "state-machine journal log gap: expected {expected_index}, observed {}",
                        entry.log_id.index
                    )));
                }
            }
            let response = apply_state_entry(&mut bundle.state, &entry);
            bundle.generation = generation;
            if bundle.state.records_v5.is_some() {
                bundle.format_version = 3;
            }
            Ok(Some(response))
        }
    }
}

fn replay_state_journal(path: &Path, bundle: &mut PersistentStateBundle) -> io::Result<()> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > 256 * 1024 * 1024 {
        return Err(invalid("raft state-machine delta journal exceeds 256 MiB"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    if bytes.len() < STATE_JOURNAL_MAGIC.len() || bytes[..8] != STATE_JOURNAL_MAGIC {
        return Err(invalid("raft state-machine delta journal magic mismatch"));
    }
    let mut offset = STATE_JOURNAL_MAGIC.len();
    let mut last_good = offset;
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            break;
        }
        if bytes[offset..offset + 8] != STATE_EVENT_MAGIC {
            return Err(invalid("raft state-machine delta event magic mismatch"));
        }
        let length = usize::try_from(u64::from_le_bytes(
            bytes[offset + 8..offset + 16]
                .try_into()
                .map_err(|_| invalid("invalid state-machine event length"))?,
        ))
        .map_err(|_| invalid("state-machine event length overflow"))?;
        if length > 16 * 1024 * 1024 {
            return Err(invalid("raft state-machine delta event exceeds 16 MiB"));
        }
        let frame_len = 16_usize
            .checked_add(length)
            .and_then(|value| value.checked_add(4))
            .ok_or_else(|| invalid("state-machine event size overflow"))?;
        if bytes.len() - offset < frame_len {
            break;
        }
        let payload = &bytes[offset + 16..offset + 16 + length];
        let stored_crc = u32::from_le_bytes(
            bytes[offset + 16 + length..offset + frame_len]
                .try_into()
                .map_err(|_| invalid("invalid state-machine event checksum"))?,
        );
        if crc32(payload) != stored_crc {
            return Err(invalid("raft state-machine delta event checksum mismatch"));
        }
        let event: StateJournalEvent =
            serde_json::from_slice(payload).map_err(|error| invalid(error.to_string()))?;
        let _ = apply_state_journal_event(bundle, event)?;
        offset += frame_len;
        last_good = offset;
    }
    if last_good != bytes.len() {
        let file = OpenOptions::new().write(true).open(path)?;
        file.set_len(
            u64::try_from(last_good).map_err(|_| invalid("state journal offset overflow"))?,
        )?;
        file.sync_all()?;
    }
    bundle.validate()
}

impl PersistentStateBundle {
    fn next_generation(&self) -> io::Result<u64> {
        self.generation
            .checked_add(1)
            .ok_or_else(|| invalid("state bundle generation overflow"))
    }

    fn validate_header(&self) -> io::Result<()> {
        if !matches!(self.format_version, 1 | COMPACT_STATE_BUNDLE_FORMAT | 3)
            || self.journal_format > 1
            || self.generation == 0
        {
            return Err(invalid("unsupported or zero state bundle generation"));
        }
        if (self.format_version == 3) != self.state.records_v5.is_some() {
            return Err(invalid("state bundle records/version mismatch"));
        }
        Ok(())
    }

    fn validate(&self) -> io::Result<()> {
        self.validate_header()?;
        self.state
            .validate()
            .map_err(|_| invalid("invalid state object graph"))?;
        if let Some(snapshot) = &self.current_snapshot {
            let expected = if self.format_version == 1 {
                SnapshotEncoding::LegacyBytes
            } else {
                SnapshotEncoding::CompactBase64
            };
            if self.format_version != 3 && snapshot.encoding != expected {
                return Err(invalid(
                    "state bundle snapshot encoding does not match format",
                ));
            }
            let snapshot_state = MemStoreStateMachine::from_snapshot(&snapshot.data)?;
            if snapshot_state.records_v5.is_some()
                && (self.format_version != 3
                    || snapshot.encoding != SnapshotEncoding::CompactBase64)
            {
                return Err(invalid(
                    "records snapshot lacks compact bundle version fence",
                ));
            }
            if snapshot_state.last_applied_log != snapshot.meta.last_log_id {
                return Err(invalid("snapshot state and metadata last-applied mismatch"));
            }
            let state_membership = serde_json::to_vec(&snapshot_state.last_membership)
                .map_err(|error| invalid(error.to_string()))?;
            let meta_membership = serde_json::to_vec(&snapshot.meta.last_membership)
                .map_err(|error| invalid(error.to_string()))?;
            if state_membership != meta_membership {
                return Err(invalid("snapshot state and metadata membership mismatch"));
            }
        }
        Ok(())
    }
}

/// A checkpoint whose bytes and metadata are constructed from the same locked,
/// validated state. Unlike received or reopened snapshots, its payload cannot
/// be supplied independently of that state. Keep this constructor private;
/// there is deliberately no caller-controlled "trusted" validation flag.
#[derive(Serialize)]
struct GeneratedSnapshotCheckpoint<'a> {
    format_version: u16,
    journal_format: u16,
    generation: u64,
    state: &'a MemStoreStateMachine,
    // An always-present object serializes exactly like the durable bundle's
    // Some(snapshot), without needing a second owned state-machine candidate.
    current_snapshot: PersistentSnapshot,
}

impl<'a> GeneratedSnapshotCheckpoint<'a> {
    fn new(bundle: &'a PersistentStateBundle) -> io::Result<Self> {
        bundle.validate_header()?;
        bundle
            .state
            .validate()
            .map_err(|_| invalid("invalid state object graph"))?;
        let generation = bundle.next_generation()?;
        let state = &bundle.state;
        let data = state
            .snapshot_bytes()
            .map_err(|error| invalid(error.to_string()))?;
        let meta = SnapshotMetaOf::<TypeConfig> {
            last_log_id: state.last_applied_log,
            last_membership: state.last_membership.clone(),
        };
        Ok(Self {
            format_version: if state.records_v5.is_some() {
                3
            } else {
                COMPACT_STATE_BUNDLE_FORMAT
            },
            journal_format: 1,
            generation,
            state,
            current_snapshot: PersistentSnapshot {
                meta,
                data,
                encoding: SnapshotEncoding::CompactBase64,
            },
        })
    }
}

#[derive(Clone, Debug)]
pub struct DurableStateMachine {
    bundle_path: PathBuf,
    bundle: Arc<Mutex<PersistentStateBundle>>,
    #[cfg(test)]
    artifact_bound: usize,
}

impl DurableStateMachine {
    pub fn create(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        ensure_real_directory(root, "state-machine store root")?;
        let bundle_path = root.join("state-bundle.bin");
        ensure_create_location_is_fresh(root, &bundle_path)?;
        let bundle = PersistentStateBundle {
            journal_format: 1,
            ..Default::default()
        };
        write_json(&bundle_path, STATE_BUNDLE_MAGIC, &bundle)?;
        initialize_state_journal(&state_journal_path(&bundle_path))?;
        persist_initialization_marker(root, STATE_MACHINE_DOMAIN, "state-bundle.bin")?;
        Ok(Self {
            bundle_path,
            bundle: Arc::new(Mutex::new(bundle)),
            #[cfg(test)]
            artifact_bound: MAX_DURABLE_ARTIFACT_BYTES,
        })
    }

    pub fn open_existing(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        require_real_directory(root, "state-machine store root")?;
        let bundle_path = root.join("state-bundle.bin");
        let marker = read_initialization_marker(root, STATE_MACHINE_DOMAIN, "state-bundle.bin")?;
        if marker.is_none() {
            return Err(invalid(
                "state machine is not initialized; explicit legacy adoption is required",
            ));
        }
        recover_interrupted_replace(&bundle_path)?;
        if !regular_file_status(&bundle_path, "authoritative state-machine generation")? {
            return Err(invalid(
                "initialized state machine is missing its authoritative generation",
            ));
        }
        let mut bundle: PersistentStateBundle = read_json(&bundle_path, STATE_BUNDLE_MAGIC)?;
        bundle.validate()?;
        let journal_path = state_journal_path(&bundle_path);
        if bundle.journal_format == 0 {
            if !regular_file_status(&journal_path, "legacy state-machine delta journal")? {
                initialize_state_journal(&journal_path)?;
            }
            replay_state_journal(&journal_path, &mut bundle)?;
            bundle.journal_format = 1;
            write_json(&bundle_path, STATE_BUNDLE_MAGIC, &bundle)?;
            initialize_state_journal(&journal_path)?;
        } else if bundle.journal_format == 1 {
            if !regular_file_status(&journal_path, "state-machine delta journal")? {
                return Err(invalid(
                    "initialized state-machine checkpoint requires its delta journal",
                ));
            }
            replay_state_journal(&journal_path, &mut bundle)?;
        } else {
            return Err(invalid("unsupported state-machine journal format"));
        }
        discard_stale_previous_after_validation(&bundle_path)?;
        Ok(Self {
            bundle_path,
            bundle: Arc::new(Mutex::new(bundle)),
            #[cfg(test)]
            artifact_bound: MAX_DURABLE_ARTIFACT_BYTES,
        })
    }

    #[cfg(test)]
    pub fn adopt_legacy(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        require_real_directory(root, "legacy state-machine store root")?;
        let bundle_path = root.join("state-bundle.bin");
        if read_initialization_marker(root, STATE_MACHINE_DOMAIN, "state-bundle.bin")?.is_some() {
            return Err(invalid(
                "state machine already has an initialization marker; use open_existing",
            ));
        }
        if !replacement_candidates(&initialization_marker_path(root), ".tmp")?.is_empty() {
            return Err(invalid(
                "legacy adoption refused unresolved initialization-marker temporary artifacts",
            ));
        }
        if !replacement_candidates(&bundle_path, ".tmp")?.is_empty() {
            return Err(invalid(
                "legacy adoption refused unresolved state-bundle temporary artifacts",
            ));
        }
        recover_interrupted_replace(&bundle_path)?;
        if !regular_file_status(
            &bundle_path,
            "legacy authoritative state-machine generation",
        )? {
            return Err(invalid(
                "legacy state machine has no authoritative generation",
            ));
        }
        let mut bundle: PersistentStateBundle = read_json(&bundle_path, STATE_BUNDLE_MAGIC)?;
        bundle.validate()?;
        bundle.journal_format = 1;
        initialize_state_journal(&state_journal_path(&bundle_path))?;
        write_json(&bundle_path, STATE_BUNDLE_MAGIC, &bundle)?;
        discard_stale_previous_after_validation(&bundle_path)?;
        persist_initialization_marker(root, STATE_MACHINE_DOMAIN, "state-bundle.bin")?;
        Ok(Self {
            bundle_path,
            bundle: Arc::new(Mutex::new(bundle)),
            #[cfg(test)]
            artifact_bound: MAX_DURABLE_ARTIFACT_BYTES,
        })
    }

    fn artifact_bound(&self) -> usize {
        #[cfg(test)]
        {
            self.artifact_bound
        }
        #[cfg(not(test))]
        {
            MAX_DURABLE_ARTIFACT_BYTES
        }
    }

    fn persist_bundle(&self, bundle: &PersistentStateBundle) -> io::Result<()> {
        bundle.validate()?;
        write_json_with_bound(
            &self.bundle_path,
            STATE_BUNDLE_MAGIC,
            bundle,
            self.artifact_bound(),
        )
    }

    pub async fn get_state_machine(&self) -> MemStoreStateMachine {
        self.bundle.lock().await.state.clone()
    }

    /// Borrow the map under the state lock and copy only the selected status.
    /// Decoding and authenticating the returned envelope stay with the caller,
    /// outside the lock; unrelated retained application chunks are not copied.
    pub(crate) async fn client_status(&self, client: &str) -> Option<String> {
        self.bundle
            .lock()
            .await
            .state
            .client_status
            .get(client)
            .cloned()
    }

    pub(crate) async fn last_applied_log_index(&self) -> Option<u64> {
        self.bundle
            .lock()
            .await
            .state
            .last_applied_log
            .map(|log_id| log_id.index)
    }

    /// The generation and value belong to one locked observation. Every apply,
    /// checkpoint and snapshot install advances this local generation.
    pub(crate) async fn client_status_at_generation(&self, client: &str) -> (u64, Option<String>) {
        let bundle = self.bundle.lock().await;
        (
            bundle.generation,
            bundle.state.client_status.get(client).cloned(),
        )
    }

    pub(crate) async fn record_object(
        &self,
        reference: &crate::RecordObjectRef,
    ) -> Result<Option<crate::SealedRecordObject>, crate::RecordRejection> {
        self.bundle
            .lock()
            .await
            .state
            .records_v5
            .as_ref()
            .map(|records| records.object(reference))
            .transpose()
            .map(Option::flatten)
    }
    pub(crate) async fn record_root_at_generation(
        &self,
    ) -> (u64, Option<crate::PublishedRecordRoot>) {
        let bundle = self.bundle.lock().await;
        (
            bundle.generation,
            bundle
                .state
                .records_v5
                .as_ref()
                .and_then(crate::records::RecordState::published),
        )
    }
    pub(crate) async fn record_inventory(
        &self,
        after: Option<crate::RecordObjectId>,
        limit: usize,
    ) -> Result<(u64, Vec<crate::RecordObjectRef>), crate::RecordRejection> {
        if limit == 0 || limit > 256 {
            return Err(crate::RecordRejection::Invalid);
        }
        let bundle = self.bundle.lock().await;
        let refs = bundle
            .state
            .records_v5
            .as_ref()
            .map(|records| records.inventory(after, limit))
            .transpose()?
            .unwrap_or_default();
        Ok((bundle.generation, refs))
    }
    pub(crate) async fn record_usage(
        &self,
    ) -> Result<(u64, crate::RecordUsage), crate::RecordRejection> {
        let mut bundle = self.bundle.lock().await;
        let usage = bundle.state.record_usage()?;
        Ok((bundle.generation, usage))
    }
    pub(crate) async fn prunable_records(
        &self,
        expected_root: [u8; 32],
        limit: usize,
    ) -> Result<Vec<crate::RecordObjectId>, crate::RecordRejection> {
        if limit == 0 || limit > 256 {
            return Err(crate::RecordRejection::Invalid);
        }
        let bundle = self.bundle.lock().await;
        let current = bundle
            .state
            .records_v5
            .as_ref()
            .and_then(crate::records::RecordState::published_digest)
            .unwrap_or([0; 32]);
        if current != expected_root {
            return Err(crate::RecordRejection::StaleRoot);
        }
        bundle
            .state
            .records_v5
            .as_ref()
            .map(|records| records.prunable(limit))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    pub async fn has_current_snapshot(&self) -> bool {
        self.bundle.lock().await.current_snapshot.is_some()
    }

    pub async fn generation(&self) -> u64 {
        self.bundle.lock().await.generation
    }

    #[cfg(test)]
    pub fn state_path(&self) -> &Path {
        &self.bundle_path
    }

    pub fn snapshot_path(&self) -> &Path {
        &self.bundle_path
    }
}

impl RaftSnapshotBuilder<TypeConfig> for DurableStateMachine {
    type SnapshotData = Cursor<Vec<u8>>;

    async fn build_snapshot(
        &mut self,
    ) -> Result<SnapshotOf<TypeConfig, Self::SnapshotData>, io::Error> {
        let mut bundle = self.bundle.lock().await;
        let checkpoint = GeneratedSnapshotCheckpoint::new(&bundle)?;
        // Preserve the actual encoded artifact bound, including the current
        // state, base64 snapshot and frame. No disk or in-memory publication
        // occurs if serialization/preflight fails.
        write_json_with_bound(
            &self.bundle_path,
            STATE_BUNDLE_MAGIC,
            &checkpoint,
            self.artifact_bound(),
        )?;
        initialize_state_journal(&state_journal_path(&self.bundle_path))?;
        let GeneratedSnapshotCheckpoint {
            format_version,
            journal_format,
            generation,
            current_snapshot,
            ..
        } = checkpoint;
        let meta = current_snapshot.meta.clone();
        // OpenRaft needs an owned Cursor while the durable store retains its
        // snapshot. Delay that unavoidable byte copy until after persistence;
        // the full state itself was borrowed throughout, never cloned.
        let data = current_snapshot.data.clone();
        bundle.format_version = format_version;
        bundle.journal_format = journal_format;
        bundle.generation = generation;
        bundle.current_snapshot = Some(current_snapshot);
        Ok(SnapshotOf::<TypeConfig, Cursor<Vec<u8>>> {
            meta,
            snapshot: Cursor::new(data),
        })
    }
}

impl RaftStateMachine<TypeConfig> for DurableStateMachine {
    type SnapshotData = Cursor<Vec<u8>>;
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogIdOf<TypeConfig>>, StoredMembershipOf<TypeConfig>), io::Error> {
        let bundle = self.bundle.lock().await;
        Ok((
            bundle.state.last_applied_log,
            bundle.state.last_membership.clone(),
        ))
    }

    async fn apply<Strm>(&mut self, mut entries: Strm) -> Result<(), io::Error>
    where
        Strm: Stream<Item = Result<EntryResponder<TypeConfig>, io::Error>> + Unpin + OptionalSend,
    {
        while let Some((entry, responder)) = entries.try_next().await? {
            let response = {
                let mut bundle = self.bundle.lock().await;
                let generation = bundle.next_generation()?;
                let serialized =
                    serde_json::to_string(&entry).map_err(|error| invalid(error.to_string()))?;
                let event = StateJournalEvent::Apply {
                    generation,
                    entry: serialized,
                };
                append_state_journal(&state_journal_path(&self.bundle_path), &event)?;
                apply_state_journal_event(&mut bundle, event)?
                    .ok_or_else(|| invalid("fresh state-machine event was not applied"))?
            };
            if let Some(responder) = responder {
                responder.send(response);
            }
        }
        Ok(())
    }

    async fn try_create_snapshot_builder(&mut self, _force: bool) -> Option<Self::SnapshotBuilder> {
        Some(self.clone())
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMetaOf<TypeConfig>,
        snapshot: Self::SnapshotData,
    ) -> Result<(), io::Error> {
        let data = snapshot.into_inner();
        let state = MemStoreStateMachine::from_snapshot(&data)?;
        if state.last_applied_log != meta.last_log_id {
            return Err(invalid("snapshot last-applied log does not match metadata"));
        }
        let state_membership = serde_json::to_vec(&state.last_membership)
            .map_err(|error| invalid(error.to_string()))?;
        let meta_membership = serde_json::to_vec(&meta.last_membership)
            .map_err(|error| invalid(error.to_string()))?;
        if state_membership != meta_membership {
            return Err(invalid("snapshot membership does not match metadata"));
        }
        let persisted = PersistentSnapshot {
            meta: meta.clone(),
            data,
            encoding: SnapshotEncoding::CompactBase64,
        };
        let mut bundle = self.bundle.lock().await;
        let candidate = PersistentStateBundle {
            format_version: if state.records_v5.is_some() {
                3
            } else {
                COMPACT_STATE_BUNDLE_FORMAT
            },
            journal_format: 1,
            generation: bundle.next_generation()?,
            state,
            current_snapshot: Some(persisted),
        };
        self.persist_bundle(&candidate)?;
        initialize_state_journal(&state_journal_path(&self.bundle_path))?;
        *bundle = candidate;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<SnapshotOf<TypeConfig, Self::SnapshotData>>, io::Error> {
        Ok(self
            .bundle
            .lock()
            .await
            .current_snapshot
            .clone()
            .map(|snapshot| SnapshotOf::<TypeConfig, Cursor<Vec<u8>>> {
                meta: snapshot.meta,
                snapshot: Cursor::new(snapshot.data),
            }))
    }
}

#[cfg(test)]
pub fn flip_first_payload_byte(path: &Path) -> io::Result<()> {
    let mut bytes = fs::read(path)?;
    if bytes.len() <= 20 {
        return Err(invalid("cannot corrupt an empty durable envelope"));
    }
    bytes[16] ^= 0x80;
    fs::write(path, bytes)?;
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DurableLogStore, DurableStateMachine, INITIALIZATION_MAGIC, INITIALIZATION_MARKER_FILE,
        LOG_DOMAIN, LOG_MAGIC, PersistentInitializationMarker, PersistentLogState,
        PersistentStateBundle, RaftLogStorage, RaftSnapshotBuilder, STATE_BUNDLE_MAGIC,
        flip_first_payload_byte, read_json, write_json,
    };
    use crate::TypeConfig;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{self, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::Mutex;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[tokio::test]
    async fn replication_prefixes_respect_real_wire_budget_and_do_not_skip_entries()
    -> io::Result<()> {
        use openraft::alias::EntryOf;
        use openraft::storage::RaftLogReader;
        let path = root("bounded-replication-prefix");
        let mut store = DurableLogStore::create(&path)?;
        {
            let mut state = store.state.lock().await;
            for index in 0..7 {
                let entry = EntryOf::<TypeConfig> {
                    log_id: openraft::LogId {
                        leader_id: openraft::impls::leader_id_adv::LeaderId {
                            term: 1,
                            node_id: 1,
                        },
                        index,
                    },
                    payload: openraft::EntryPayload::Normal(
                        openraft_memstore::ClientRequest {
                            client: "synthetic".into(),
                            serial: index,
                            status: "x".repeat(280 * 1024),
                        }
                        .into(),
                    ),
                };
                state.log.insert(
                    index,
                    serde_json::to_string(&entry).map_err(io::Error::other)?,
                );
            }
        }
        let mut next = 0;
        let mut batches = 0;
        while next < 7 {
            let entries = store.limited_get_log_entries(next, 7).await?;
            assert!(!entries.is_empty());
            for entry in &entries {
                assert_eq!(entry.log_id.index, next);
                next += 1;
            }
            let request = openraft::raft::AppendEntriesRequest::<TypeConfig> {
                vote: openraft::Vote::new_committed(u64::MAX, u64::MAX),
                prev_log_id: entries.first().map(|e| e.log_id),
                leader_commit: entries.last().map(|e| e.log_id),
                entries,
            };
            assert!(
                serde_json::to_vec(&request)
                    .map_err(io::Error::other)?
                    .len()
                    <= crate::replication_bounds::MAX_REMOTE_RPC_BYTES
            );
            batches += 1;
        }
        assert!(batches > 1 && batches < 7);
        assert_eq!(store.try_get_log_entries(0..7).await?.len(), 7);
        store.state.lock().await.log.remove(&0);
        assert!(store.limited_get_log_entries(0, 7).await.is_err());
        let mut entry = store.try_get_log_entries(1..2).await?.remove(0);
        entry.payload = openraft::EntryPayload::Normal(
            openraft_memstore::ClientRequest {
                client: "synthetic".into(),
                serial: 1,
                status: "x".repeat(crate::replication_bounds::MAX_REMOTE_RPC_BYTES),
            }
            .into(),
        );
        store
            .state
            .lock()
            .await
            .log
            .insert(1, serde_json::to_string(&entry).map_err(io::Error::other)?);
        assert!(store.limited_get_log_entries(1, 2).await.is_err());
        drop(store);
        fs::remove_dir_all(path)?;
        Ok(())
    }

    #[test]
    fn durable_crc_matches_independent_ieee_vectors_and_legacy_frames() {
        assert_eq!(super::crc32(b"123456789"), 0xcbf4_3926);
        for (length, expected) in [
            (0, 0x00000000),
            (1, 0xd202ef8d),
            (31, 0x4d786d77),
            (32, 0x91267e8a),
            (63, 0xdbdea683),
            (64, 0x100ece8c),
            (255, 0xd32f9ba0),
            (256, 0x29058c73),
            (4096, 0xa2912082),
            (65539, 0xbbcc862a),
        ] {
            let bytes: Vec<u8> = (0..length).map(|n| (n % 256) as u8).collect();
            assert_eq!(super::crc32(&bytes), expected);
            // Construct a historical frame with its independent checksum.
            let mut frame = Vec::new();
            frame.extend_from_slice(&super::STATE_BUNDLE_MAGIC);
            frame.extend_from_slice(&(length as u64).to_le_bytes());
            frame.extend_from_slice(&bytes);
            frame.extend_from_slice(&expected.to_le_bytes());
            assert_eq!(
                super::decode_envelope(super::STATE_BUNDLE_MAGIC, &frame).expect("legacy CRC"),
                bytes
            );
        }
    }

    #[test]
    fn atomic_artifact_writer_preserves_exact_historical_frame_bytes() {
        let root = root("segmented-artifact-frame");
        fs::create_dir_all(&root).expect("create fixture");
        let path = root.join("artifact.bin");
        for size in [0, 31, 4096, 65539] {
            let payload: Vec<u8> = (0..size).map(|n| (n % 256) as u8).collect();
            super::atomic_write(&path, super::STATE_BUNDLE_MAGIC, &payload)
                .expect("write artifact");
            assert_eq!(
                fs::read(&path).expect("read frame"),
                super::encode_envelope(super::STATE_BUNDLE_MAGIC, &payload)
                    .expect("old frame shape")
            );
        }
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn payload_corruption_helper_produces_rejected_envelope() {
        let log_root = root("payload-corruption-helper");
        let log = DurableLogStore::create(&log_root).expect("create log store");
        drop(log);
        flip_first_payload_byte(&log_root.join("raft-log.bin"))
            .expect("corrupt one authenticated envelope byte");
        DurableLogStore::open_existing(&log_root).expect_err("corrupted envelope must fail closed");
        fs::remove_dir_all(log_root).expect("remove payload corruption fixture");
    }

    fn root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "heptabao-{label}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn read_generation_advances_for_apply_membership_blank_snapshot_and_reopen() {
        let root = root("read-generation");
        let mut store = DurableStateMachine::create(&root).expect("create state machine");
        assert_eq!(
            store.client_status_at_generation("selected").await,
            (1, None)
        );
        let payloads = [
            openraft::EntryPayload::Blank,
            openraft::EntryPayload::Normal(
                openraft_memstore::ClientRequest {
                    client: "selected".into(),
                    serial: 1,
                    status: "same-manifest".into(),
                }
                .into(),
            ),
            openraft::EntryPayload::Membership(
                openraft::Membership::new(
                    vec![std::collections::BTreeSet::from([1_u64])],
                    BTreeMap::from([(1_u64, ())]),
                )
                .expect("valid membership"),
            ),
        ];
        for (offset, payload) in payloads.into_iter().enumerate() {
            let index = offset as u64 + 1;
            let entry = openraft::alias::EntryOf::<TypeConfig> {
                log_id: openraft::LogId {
                    leader_id: openraft::impls::leader_id_adv::LeaderId {
                        term: 1_u64,
                        node_id: 1_u64,
                    },
                    index,
                },
                payload,
            };
            super::RaftStateMachine::apply(
                &mut store,
                futures::stream::iter([Ok::<_, io::Error>((entry, None))]),
            )
            .await
            .expect("apply advances generation");
            let (generation, status) = store.client_status_at_generation("selected").await;
            assert_eq!(generation, index + 1);
            assert_eq!(status.as_deref(), (index >= 2).then_some("same-manifest"));
        }
        let snapshot = store.build_snapshot().await.expect("checkpoint");
        assert_eq!(store.generation().await, 5);
        super::RaftStateMachine::install_snapshot(&mut store, &snapshot.meta, snapshot.snapshot)
            .await
            .expect("install snapshot advances local generation");
        assert_eq!(
            store.client_status_at_generation("selected").await,
            (6, Some("same-manifest".into()))
        );
        drop(store);
        let reopened = DurableStateMachine::open_existing(&root).expect("reopen");
        assert_eq!(
            reopened.client_status_at_generation("selected").await,
            (6, Some("same-manifest".into()))
        );
        drop(reopened);
        fs::remove_dir_all(root).expect("remove generation fixture");
    }

    #[tokio::test]
    async fn read_generation_never_wraps_or_reuses_a_value() {
        let root = root("read-generation-overflow");
        let mut store = DurableStateMachine::create(&root).expect("create state machine");
        store.bundle.lock().await.generation = u64::MAX;
        let before = fs::read(root.join("state-machine.journal")).expect("journal before");
        let entry = openraft::alias::EntryOf::<TypeConfig> {
            log_id: openraft::LogId {
                leader_id: openraft::impls::leader_id_adv::LeaderId {
                    term: 1_u64,
                    node_id: 1_u64,
                },
                index: 1,
            },
            payload: openraft::EntryPayload::Blank,
        };
        assert!(
            super::RaftStateMachine::apply(
                &mut store,
                futures::stream::iter([Ok::<_, io::Error>((entry, None))])
            )
            .await
            .is_err()
        );
        assert_eq!(store.generation().await, u64::MAX);
        assert_eq!(store.last_applied_log_index().await, None);
        assert_eq!(
            fs::read(root.join("state-machine.journal")).expect("journal after"),
            before
        );
        assert!(store.build_snapshot().await.is_err());
        assert_eq!(store.generation().await, u64::MAX);
        drop(store);
        fs::remove_dir_all(root).expect("remove overflow fixture");
    }

    #[tokio::test]
    async fn point_status_reads_preserve_missing_and_independent_value_semantics() {
        let root = root("point-status-read");
        let store = DurableStateMachine::create(&root).expect("create state machine");
        assert_eq!(store.client_status("selected").await, None);
        assert_eq!(store.last_applied_log_index().await, None);
        {
            let mut bundle = store.bundle.lock().await;
            bundle
                .state
                .client_status
                .insert("selected".into(), "first".into());
            bundle
                .state
                .client_status
                .insert("Selected".into(), "case-sensitive".into());
            bundle
                .state
                .client_status
                .insert("empty".into(), String::new());
            // Retained chunks can dwarf the selected manifest. They must not
            // affect point-read results or turn absence into an empty value.
            for index in 0..16 {
                bundle
                    .state
                    .client_status
                    .insert(format!("unrelated-{index}"), "x".repeat(256 * 1024));
            }
        }
        let mut returned = store
            .client_status("selected")
            .await
            .expect("selected value");
        returned.push_str("-caller-change");
        assert_eq!(
            store.client_status("selected").await.as_deref(),
            Some("first")
        );
        assert_eq!(
            store.client_status("Selected").await.as_deref(),
            Some("case-sensitive")
        );
        assert_eq!(store.client_status("empty").await, Some(String::new()));
        assert_eq!(store.client_status("missing").await, None);
        store
            .bundle
            .lock()
            .await
            .state
            .client_status
            .insert("selected".into(), "second".into());
        assert_eq!(returned, "first-caller-change");
        assert_eq!(
            store.client_status("selected").await.as_deref(),
            Some("second")
        );
        assert_eq!(
            store.bundle.lock().await.state.client_status["unrelated-15"].len(),
            256 * 1024
        );
        drop(store);
        fs::remove_dir_all(root).expect("remove point-read fixture");
    }

    #[tokio::test]
    async fn point_reads_follow_durable_checkpoint_and_snapshot_install() {
        let source_root = root("point-read-source");
        let target_root = root("point-read-target");
        let mut source = DurableStateMachine::create(&source_root).expect("create source");
        let mut target = DurableStateMachine::create(&target_root).expect("create target");
        {
            let mut bundle = source.bundle.lock().await;
            bundle.state.last_applied_log = Some(openraft::LogId {
                leader_id: openraft::impls::leader_id_adv::LeaderId {
                    term: 3_u64,
                    node_id: 2_u64,
                },
                index: 41,
            });
            bundle
                .state
                .client_status
                .insert("selected".into(), "checkpoint-value".into());
        }
        let snapshot = source
            .build_snapshot()
            .await
            .expect("publish snapshot checkpoint");
        assert_eq!(source.last_applied_log_index().await, Some(41));
        super::RaftStateMachine::install_snapshot(&mut target, &snapshot.meta, snapshot.snapshot)
            .await
            .expect("install snapshot");
        assert_eq!(target.last_applied_log_index().await, Some(41));
        assert_eq!(
            target.client_status("selected").await.as_deref(),
            Some("checkpoint-value")
        );
        drop(source);
        drop(target);
        for path in [&source_root, &target_root] {
            let reopened = DurableStateMachine::open_existing(path).expect("reopen checkpoint");
            assert_eq!(reopened.last_applied_log_index().await, Some(41));
            assert_eq!(
                reopened.client_status("selected").await.as_deref(),
                Some("checkpoint-value")
            );
            assert_eq!(reopened.client_status("missing").await, None);
        }
        fs::remove_dir_all(source_root).expect("remove source");
        fs::remove_dir_all(target_root).expect("remove target");
    }

    #[tokio::test]
    async fn point_status_reads_leave_invalid_envelopes_for_fail_closed_decoding() {
        let root = root("point-status-invalid-envelope");
        let store = DurableStateMachine::create(&root).expect("create state machine");
        let envelope = crate::ReplicatedEnvelope::new("test-operation", [7; 32], vec![9; 128])
            .expect("construct envelope");
        {
            let mut bundle = store.bundle.lock().await;
            bundle
                .state
                .client_status
                .insert("good".into(), envelope.encoded_status());
            bundle
                .state
                .client_status
                .insert("bad".into(), "hbr3:malformed".into());
        }
        let encoded = store.client_status("good").await.expect("good status");
        assert!(
            crate::ReplicatedEnvelope::decode_status(&encoded).expect("decode envelope")
                == envelope
        );
        let invalid = store
            .client_status("bad")
            .await
            .expect("invalid status remains present");
        assert!(crate::ReplicatedEnvelope::decode_status(&invalid).is_err());
        assert_eq!(store.client_status("absent").await, None);
        drop(store);
        fs::remove_dir_all(root).expect("remove envelope fixture");
    }

    #[tokio::test]
    async fn purge_can_advance_past_a_reconnected_follower_log_frontier() {
        let root = root("purge-ahead-of-local-frontier");
        let mut store = DurableLogStore::create(&root).expect("create log store");
        let purge = openraft::LogId {
            leader_id: openraft::impls::leader_id_adv::LeaderId {
                term: 2_u64,
                node_id: 1_u64,
            },
            index: 7,
        };
        RaftLogStorage::purge(&mut store, purge)
            .await
            .expect("snapshot purge may advance an empty follower frontier");
        let state = RaftLogStorage::get_log_state(&mut store)
            .await
            .expect("read purged frontier");
        assert_eq!(state.last_purged_log_id, Some(purge));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn failed_log_persist_does_not_publish_candidate_state() {
        let root = root("log-persist-failure");
        fs::create_dir_all(&root).expect("test root");
        let blocking_parent = root.join("not-a-directory");
        fs::write(&blocking_parent, b"block").expect("blocking file");
        let mut log = BTreeMap::new();
        log.insert(1, "synthetic-entry".to_owned());
        let state = PersistentLogState {
            log,
            ..PersistentLogState::default()
        };
        let mut store = DurableLogStore {
            state_path: blocking_parent.join("raft-log.bin"),
            state: Arc::new(Mutex::new(state)),
        };

        let result = store.truncate_after(None).await;
        assert!(result.is_err());
        assert!(store.state.lock().await.log.contains_key(&1));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn failed_snapshot_persist_does_not_publish_snapshot_or_generation() {
        let root = root("snapshot-persist-failure");
        fs::create_dir_all(&root).expect("test root");
        let blocking_parent = root.join("not-a-directory");
        fs::write(&blocking_parent, b"block").expect("blocking file");
        let initial = PersistentStateBundle::default();
        let mut state_machine = DurableStateMachine {
            bundle_path: blocking_parent.join("state-bundle.bin"),
            bundle: Arc::new(Mutex::new(initial)),
            artifact_bound: super::MAX_DURABLE_ARTIFACT_BYTES,
        };

        let result = state_machine.build_snapshot().await;
        assert!(result.is_err());
        let bundle = state_machine.bundle.lock().await;
        assert_eq!(bundle.generation, 1);
        assert!(bundle.current_snapshot.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_previous_file_is_recovered_fail_closed() {
        let root = root("replace-recovery");
        fs::create_dir_all(&root).expect("test root");
        let target = root.join("state-bundle.bin");
        let previous = root.join(".state-bundle.bin.1.1.previous");
        let expected = PersistentStateBundle::default();
        write_json(&previous, STATE_BUNDLE_MAGIC, &expected).expect("write previous");

        let recovered: PersistentStateBundle =
            read_json(&target, STATE_BUNDLE_MAGIC).expect("recover previous");
        assert_eq!(recovered.generation, expected.generation);
        assert!(target.is_file());
        assert!(!previous.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn initialized_delta_journals_are_required() {
        let log_root = root("missing-log-journal");
        DurableLogStore::create(&log_root).expect("create log store");
        fs::remove_file(log_root.join("raft-log.journal")).expect("remove log journal");
        let error = DurableLogStore::open_existing(&log_root)
            .expect_err("format-1 log checkpoint must require its journal");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let state_root = root("missing-state-journal");
        DurableStateMachine::create(&state_root).expect("create state machine");
        fs::remove_file(state_root.join("state-machine.journal")).expect("remove state journal");
        let error = DurableStateMachine::open_existing(&state_root)
            .expect_err("format-1 state checkpoint must require its journal");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let _ = fs::remove_dir_all(log_root);
        let _ = fs::remove_dir_all(state_root);
    }

    #[test]
    fn incomplete_delta_journal_tails_are_repaired_only_to_last_complete_frame() {
        let log_root = root("log-tail-repair");
        DurableLogStore::create(&log_root).expect("create log store");
        let log_journal = log_root.join("raft-log.journal");
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&log_journal)
                .expect("open log journal");
            file.write_all(b"HBR").expect("append truncated log frame");
            file.sync_all().expect("sync truncated log frame");
        }
        DurableLogStore::open_existing(&log_root).expect("repair truncated log tail");
        assert_eq!(
            fs::metadata(&log_journal)
                .expect("log journal metadata")
                .len(),
            16
        );

        let state_root = root("state-tail-repair");
        DurableStateMachine::create(&state_root).expect("create state machine");
        let state_journal = state_root.join("state-machine.journal");
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&state_journal)
                .expect("open state journal");
            file.write_all(b"HBRS")
                .expect("append truncated state frame");
            file.sync_all().expect("sync truncated state frame");
        }
        DurableStateMachine::open_existing(&state_root).expect("repair truncated state tail");
        assert_eq!(
            fs::metadata(&state_journal)
                .expect("state journal metadata")
                .len(),
            8
        );

        let _ = fs::remove_dir_all(log_root);
        let _ = fs::remove_dir_all(state_root);
    }

    #[test]
    fn fully_framed_bad_delta_events_fail_closed() {
        let log_root = root("log-bad-event");
        DurableLogStore::create(&log_root).expect("create log store");
        let log_frame =
            super::encode_envelope(super::LOG_EVENT_MAGIC, b"not-json").expect("encode log frame");
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(log_root.join("raft-log.journal"))
                .expect("open log journal");
            file.write_all(&log_frame).expect("append log frame");
            file.sync_all().expect("sync log frame");
        }
        assert!(
            DurableLogStore::open_existing(&log_root).is_err(),
            "complete invalid log event must not be truncated as an incomplete tail"
        );

        let state_root = root("state-bad-event");
        DurableStateMachine::create(&state_root).expect("create state machine");
        let state_frame = super::encode_envelope(super::STATE_EVENT_MAGIC, b"not-json")
            .expect("encode state frame");
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(state_root.join("state-machine.journal"))
                .expect("open state journal");
            file.write_all(&state_frame).expect("append state frame");
            file.sync_all().expect("sync state frame");
        }
        assert!(
            DurableStateMachine::open_existing(&state_root).is_err(),
            "complete invalid state event must fail closed"
        );

        let _ = fs::remove_dir_all(log_root);
        let _ = fs::remove_dir_all(state_root);
    }

    #[test]
    fn newer_log_checkpoint_retires_stale_precheckpoint_journal() {
        let root = root("log-stale-journal");
        let store = DurableLogStore::create(&root).expect("create log store");
        drop(store);

        let state_path = root.join("raft-log.bin");
        let mut state: PersistentLogState =
            read_json(&state_path, LOG_MAGIC).expect("read log checkpoint");
        assert_eq!(state.journal_epoch, 1);
        state.journal_epoch = 2;
        write_json(&state_path, LOG_MAGIC, &state).expect("publish newer checkpoint");

        DurableLogStore::open_existing(&root)
            .expect("newer checkpoint must retire stale old-epoch journal");
        assert_eq!(
            super::log_journal_epoch(&root.join("raft-log.journal"))
                .expect("read repaired log journal epoch"),
            2
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fresh_create_and_existing_reopen_are_explicit() {
        let log_root = root("fresh-log-lifecycle");
        let log = DurableLogStore::create(&log_root).expect("create log store");
        assert!(log.state_path().is_file());
        assert!(log_root.join(INITIALIZATION_MARKER_FILE).is_file());
        DurableLogStore::open_existing(&log_root).expect("reopen log store");

        let state_root = root("fresh-state-lifecycle");
        let state = DurableStateMachine::create(&state_root).expect("create state machine");
        assert!(state.state_path().is_file());
        assert!(state_root.join(INITIALIZATION_MARKER_FILE).is_file());
        DurableStateMachine::open_existing(&state_root).expect("reopen state machine");

        let _ = fs::remove_dir_all(log_root);
        let _ = fs::remove_dir_all(state_root);
    }

    #[test]
    fn create_new_rejects_nonempty_directory() {
        let root = root("create-nonempty");
        fs::create_dir_all(&root).expect("test root");
        fs::write(root.join("unexpected"), b"occupied").expect("occupy root");
        let error =
            DurableLogStore::create(&root).expect_err("create-new must reject an occupied root");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_initialized_log_generation_fails_closed() {
        let root = root("missing-log-generation");
        let store = DurableLogStore::create(&root).expect("create log store");
        fs::remove_file(store.state_path()).expect("remove authoritative log generation");
        let error = DurableLogStore::open_existing(&root)
            .expect_err("initialized log store must reject missing generation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_initialized_state_generation_fails_closed() {
        let root = root("missing-state-generation");
        let state = DurableStateMachine::create(&root).expect("create state machine");
        fs::remove_file(state.state_path()).expect("remove authoritative state generation");
        let error = DurableStateMachine::open_existing(&root)
            .expect_err("initialized state machine must reject missing generation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deleted_store_directory_is_not_silently_recreated_on_reopen() {
        let root = root("deleted-store-directory");
        DurableLogStore::create(&root).expect("create log store");
        fs::remove_dir_all(&root).expect("remove store directory");
        let error = DurableLogStore::open_existing(&root)
            .expect_err("reopen must not recreate a deleted store");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn active_log_persist_does_not_recreate_deleted_store_root() {
        let root = root("active-log-deleted-root");
        let mut store = DurableLogStore::create(&root).expect("create log store");
        fs::remove_dir_all(&root).expect("remove active log root");

        let error = store
            .save_committed(None)
            .await
            .expect_err("active persistence must not recreate a deleted root");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn active_state_persist_does_not_recreate_deleted_store_root() {
        let root = root("active-state-deleted-root");
        let mut state = DurableStateMachine::create(&root).expect("create state machine");
        fs::remove_dir_all(&root).expect("remove active state root");

        let error = state
            .build_snapshot()
            .await
            .expect_err("active persistence must not recreate a deleted root");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!root.exists());
    }

    #[test]
    fn legacy_log_adoption_rejects_unresolved_data_temporary_file() {
        let root = root("legacy-log-temporary");
        fs::create_dir_all(&root).expect("test root");
        write_json(
            &root.join("raft-log.bin"),
            LOG_MAGIC,
            &PersistentLogState::default(),
        )
        .expect("legacy log generation");
        fs::write(root.join(".raft-log.bin.1.1.tmp"), b"unresolved").expect("legacy log temporary");

        let error = DurableLogStore::adopt_legacy(&root)
            .expect_err("legacy adoption must reject unresolved data temporary files");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!root.join(INITIALIZATION_MARKER_FILE).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_state_adoption_rejects_unresolved_data_temporary_file() {
        let root = root("legacy-state-temporary");
        fs::create_dir_all(&root).expect("test root");
        write_json(
            &root.join("state-bundle.bin"),
            STATE_BUNDLE_MAGIC,
            &PersistentStateBundle::default(),
        )
        .expect("legacy state generation");
        fs::write(root.join(".state-bundle.bin.1.1.tmp"), b"unresolved")
            .expect("legacy state temporary");

        let error = DurableStateMachine::adopt_legacy(&root)
            .expect_err("legacy adoption must reject unresolved data temporary files");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!root.join(INITIALIZATION_MARKER_FILE).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_generation_requires_explicit_validated_adoption() {
        let root = root("legacy-generation-adoption");
        fs::create_dir_all(&root).expect("test root");
        let path = root.join("raft-log.bin");
        write_json(&path, LOG_MAGIC, &PersistentLogState::default()).expect("legacy state");
        assert!(!root.join(INITIALIZATION_MARKER_FILE).exists());
        assert!(DurableLogStore::open_existing(&root).is_err());

        let store = DurableLogStore::adopt_legacy(&root).expect("adopt legacy generation");
        assert!(store.state_path().is_file());
        assert!(root.join(INITIALIZATION_MARKER_FILE).is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn state_legacy_generation_requires_explicit_validated_adoption() {
        let root = root("legacy-state-generation-adoption");
        fs::create_dir_all(&root).expect("test root");
        let path = root.join("state-bundle.bin");
        write_json(&path, STATE_BUNDLE_MAGIC, &PersistentStateBundle::default())
            .expect("legacy state bundle");
        assert!(DurableStateMachine::open_existing(&root).is_err());
        DurableStateMachine::adopt_legacy(&root).expect("adopt legacy state bundle");
        assert!(root.join(INITIALIZATION_MARKER_FILE).is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn valid_current_generation_discards_one_stale_previous() {
        let root = root("stale-previous-cleanup");
        let store = DurableLogStore::create(&root).expect("create log store");
        let previous = root.join(".raft-log.bin.1.1.previous");
        fs::copy(store.state_path(), &previous).expect("copy stale previous");
        DurableLogStore::open_existing(&root).expect("validate current generation");
        assert!(!previous.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_current_generation_never_falls_back_to_previous() {
        let root = root("corrupt-current-no-rollback");
        let store = DurableLogStore::create(&root).expect("create log store");
        let previous = root.join(".raft-log.bin.1.1.previous");
        fs::copy(store.state_path(), &previous).expect("copy previous generation");
        flip_first_payload_byte(store.state_path()).expect("corrupt current generation");

        assert!(DurableLogStore::open_existing(&root).is_err());
        assert!(store.state_path().is_file());
        assert!(previous.is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn multiple_previous_generations_are_ambiguous_and_fail_closed() {
        let root = root("ambiguous-previous-generations");
        let store = DurableLogStore::create(&root).expect("create log store");
        let first = root.join(".raft-log.bin.1.1.previous");
        let second = root.join(".raft-log.bin.1.2.previous");
        fs::copy(store.state_path(), &first).expect("copy first previous");
        fs::copy(store.state_path(), &second).expect("copy second previous");
        fs::remove_file(store.state_path()).expect("remove current generation");

        assert!(DurableLogStore::open_existing(&root).is_err());
        assert!(first.is_file());
        assert!(second.is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_initialization_marker_fails_closed() {
        let root = root("corrupt-initialization-marker");
        DurableStateMachine::create(&root).expect("create state machine");
        flip_first_payload_byte(&root.join(INITIALIZATION_MARKER_FILE))
            .expect("corrupt initialization marker");
        assert!(DurableStateMachine::open_existing(&root).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn marker_domain_or_authoritative_file_drift_is_rejected() {
        let root = root("marker-domain-drift");
        fs::create_dir_all(&root).expect("test root");
        write_json(
            &root.join("raft-log.bin"),
            LOG_MAGIC,
            &PersistentLogState::default(),
        )
        .expect("write log generation");
        write_json(
            &root.join(INITIALIZATION_MARKER_FILE),
            INITIALIZATION_MAGIC,
            &PersistentInitializationMarker::new("state-machine", "state-bundle.bin"),
        )
        .expect("write wrong marker");
        assert!(DurableLogStore::open_existing(&root).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_marker_previous_file_is_recovered() {
        let root = root("marker-replace-recovery");
        fs::create_dir_all(&root).expect("test root");
        write_json(
            &root.join("raft-log.bin"),
            LOG_MAGIC,
            &PersistentLogState::default(),
        )
        .expect("write log generation");
        let previous = root.join(format!(".{INITIALIZATION_MARKER_FILE}.1.1.previous"));
        write_json(
            &previous,
            INITIALIZATION_MAGIC,
            &PersistentInitializationMarker::new(LOG_DOMAIN, "raft-log.bin"),
        )
        .expect("write previous marker");
        DurableLogStore::open_existing(&root).expect("recover marker previous file");
        assert!(root.join(INITIALIZATION_MARKER_FILE).is_file());
        assert!(!previous.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn non_regular_authoritative_generation_is_rejected() {
        let root = root("non-regular-generation");
        fs::create_dir_all(root.join("raft-log.bin")).expect("generation directory");
        let error = DurableLogStore::adopt_legacy(&root)
            .expect_err("directory cannot be an authoritative generation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_storage_root_is_rejected() {
        use std::os::unix::fs::symlink;
        let target = root("symlink-root-target");
        let link = root("symlink-root-link");
        fs::create_dir_all(&target).expect("target root");
        symlink(&target, &link).expect("create root symlink");
        assert!(DurableLogStore::create(&link).is_err());
        let _ = fs::remove_file(link);
        let _ = fs::remove_dir_all(target);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_initialization_marker_is_rejected() {
        use std::os::unix::fs::symlink;
        let root = root("symlink-marker");
        let store = DurableLogStore::create(&root).expect("create log store");
        let marker = root.join(INITIALIZATION_MARKER_FILE);
        fs::remove_file(&marker).expect("remove marker");
        symlink(store.state_path(), &marker).expect("create marker symlink");
        assert!(DurableLogStore::open_existing(&root).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_authoritative_generation_is_rejected() {
        use std::os::unix::fs::symlink;
        let root = root("symlink-generation");
        let store = DurableLogStore::create(&root).expect("create log store");
        let state_path = store.state_path().to_path_buf();
        let saved = root.join("saved-generation.bin");
        fs::rename(&state_path, &saved).expect("move generation");
        symlink(&saved, &state_path).expect("create generation symlink");
        assert!(DurableLogStore::open_existing(&root).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn log_envelope_round_trip_remains_bounded() {
        let root = root("log-roundtrip");
        fs::create_dir_all(&root).expect("test root");
        let path = root.join("raft-log.bin");
        let expected = PersistentLogState::default();
        write_json(&path, LOG_MAGIC, &expected).expect("write log");
        let _: PersistentLogState = read_json(&path, LOG_MAGIC).expect("read log");
        let _ = fs::remove_dir_all(root);
    }
}

#[cfg(test)]
#[path = "snapshot_encoding_tests.rs"]
mod snapshot_encoding_tests;

#[cfg(test)]
#[path = "record_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod record_store_tests;
