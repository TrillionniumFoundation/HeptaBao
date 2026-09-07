use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::ops::RangeBounds;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::{Stream, TryStreamExt};
use openraft::alias::{EntryOf, LogIdOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf, VoteOf};
use openraft::entry::RaftEntry;
use openraft::storage::{
    EntryResponder, IOFlushed, LogState, RaftLogReader, RaftLogStorage, RaftSnapshotBuilder,
    RaftStateMachine,
};
use openraft::{EntryPayload, OptionalSend};
use openraft_memstore::{ClientResponse, MemStoreStateMachine, TypeConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

const LOG_MAGIC: [u8; 8] = *b"HBRLOG01";
const STATE_BUNDLE_MAGIC: [u8; 8] = *b"HBRSB001";
const INITIALIZATION_MAGIC: [u8; 8] = *b"HBRINI01";
const INITIALIZATION_MARKER_FILE: &str = "initialized.bin";
const LOG_DOMAIN: &str = "raft-log";
const STATE_MACHINE_DOMAIN: &str = "state-machine";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
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
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > 128 * 1024 * 1024 {
        return Err(invalid("durable artifact exceeds 128 MiB safety bound"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
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
    let encoded = encode_envelope(magic, payload)?;
    let current_exists = regular_file_status(path, "durable current generation")?;

    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&encoded)?;
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
    let payload = serde_json::to_vec(value).map_err(|error| invalid(error.to_string()))?;
    atomic_write(path, magic, &payload)
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
    last_purged_log_id: Option<LogIdOf<TypeConfig>>,
    committed: Option<LogIdOf<TypeConfig>>,
    vote: Option<VoteOf<TypeConfig>>,
    log: BTreeMap<u64, String>,
}

impl PersistentLogState {
    fn validate(&self) -> io::Result<()> {
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
        let state = PersistentLogState::default();
        write_json(&state_path, LOG_MAGIC, &state)?;
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
        let state: PersistentLogState = read_json(&state_path, LOG_MAGIC)?;
        state.validate()?;
        discard_stale_previous_after_validation(&state_path)?;
        Ok(Self {
            state_path,
            state: Arc::new(Mutex::new(state)),
        })
    }

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
        let state: PersistentLogState = read_json(&state_path, LOG_MAGIC)?;
        state.validate()?;
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
        let mut candidate = state.clone();
        candidate.vote = Some(*vote);
        self.persist(&candidate)?;
        *state = candidate;
        Ok(())
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogIdOf<TypeConfig>>,
    ) -> Result<(), io::Error> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.committed = committed;
        self.persist(&candidate)?;
        *state = candidate;
        Ok(())
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
        let mut candidate = state.clone();
        for entry in entries {
            let index = entry.index();
            let serialized =
                serde_json::to_string(&entry).map_err(|error| invalid(error.to_string()))?;
            if let Some(existing) = candidate.log.get(&index) {
                if existing != &serialized {
                    let error = invalid(format!(
                        "attempted to overwrite log index {index} without truncate"
                    ));
                    callback.io_completed(Err(io::Error::new(error.kind(), error.to_string())));
                    return Err(error);
                }
            } else {
                candidate.log.insert(index, serialized);
            }
        }
        match self.persist(&candidate) {
            Ok(()) => {
                *state = candidate;
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
        let mut candidate = state.clone();
        let remove = candidate
            .log
            .range(start..)
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        for index in remove {
            candidate.log.remove(&index);
        }
        self.persist(&candidate)?;
        *state = candidate;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogIdOf<TypeConfig>) -> Result<(), io::Error> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        if candidate
            .last_purged_log_id
            .is_some_and(|last| last > log_id)
        {
            return Err(invalid("purge log id regressed"));
        }
        let remove = candidate
            .log
            .range(..=log_id.index)
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        for index in remove {
            candidate.log.remove(&index);
        }
        candidate.last_purged_log_id = Some(log_id);
        self.persist(&candidate)?;
        *state = candidate;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistentSnapshot {
    meta: SnapshotMetaOf<TypeConfig>,
    data: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistentStateBundle {
    format_version: u16,
    generation: u64,
    state: MemStoreStateMachine,
    current_snapshot: Option<PersistentSnapshot>,
}

impl Default for PersistentStateBundle {
    fn default() -> Self {
        Self {
            format_version: 1,
            generation: 1,
            state: MemStoreStateMachine::default(),
            current_snapshot: None,
        }
    }
}

impl PersistentStateBundle {
    fn next_generation(&self) -> io::Result<u64> {
        self.generation
            .checked_add(1)
            .ok_or_else(|| invalid("state bundle generation overflow"))
    }

    fn validate(&self) -> io::Result<()> {
        if self.format_version != 1 || self.generation == 0 {
            return Err(invalid("unsupported or zero state bundle generation"));
        }
        if let Some(snapshot) = &self.current_snapshot {
            let snapshot_state: MemStoreStateMachine = serde_json::from_slice(&snapshot.data)
                .map_err(|error| invalid(error.to_string()))?;
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

#[derive(Clone, Debug)]
pub struct DurableStateMachine {
    bundle_path: PathBuf,
    bundle: Arc<Mutex<PersistentStateBundle>>,
}

impl DurableStateMachine {
    pub fn create(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        ensure_real_directory(root, "state-machine store root")?;
        let bundle_path = root.join("state-bundle.bin");
        ensure_create_location_is_fresh(root, &bundle_path)?;
        let bundle = PersistentStateBundle::default();
        write_json(&bundle_path, STATE_BUNDLE_MAGIC, &bundle)?;
        persist_initialization_marker(root, STATE_MACHINE_DOMAIN, "state-bundle.bin")?;
        Ok(Self {
            bundle_path,
            bundle: Arc::new(Mutex::new(bundle)),
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
        let bundle: PersistentStateBundle = read_json(&bundle_path, STATE_BUNDLE_MAGIC)?;
        bundle.validate()?;
        discard_stale_previous_after_validation(&bundle_path)?;
        Ok(Self {
            bundle_path,
            bundle: Arc::new(Mutex::new(bundle)),
        })
    }

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
        let bundle: PersistentStateBundle = read_json(&bundle_path, STATE_BUNDLE_MAGIC)?;
        bundle.validate()?;
        discard_stale_previous_after_validation(&bundle_path)?;
        persist_initialization_marker(root, STATE_MACHINE_DOMAIN, "state-bundle.bin")?;
        Ok(Self {
            bundle_path,
            bundle: Arc::new(Mutex::new(bundle)),
        })
    }

    fn persist_bundle(&self, bundle: &PersistentStateBundle) -> io::Result<()> {
        bundle.validate()?;
        write_json(&self.bundle_path, STATE_BUNDLE_MAGIC, bundle)
    }

    pub async fn get_state_machine(&self) -> MemStoreStateMachine {
        self.bundle.lock().await.state.clone()
    }

    pub async fn has_current_snapshot(&self) -> bool {
        self.bundle.lock().await.current_snapshot.is_some()
    }

    pub async fn generation(&self) -> u64 {
        self.bundle.lock().await.generation
    }

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
        let state = bundle.state.clone();
        let data = serde_json::to_vec(&state).map_err(|error| invalid(error.to_string()))?;
        let meta = SnapshotMetaOf::<TypeConfig> {
            last_log_id: state.last_applied_log,
            last_membership: state.last_membership.clone(),
        };
        let snapshot = PersistentSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        let mut candidate = bundle.clone();
        candidate.generation = candidate.next_generation()?;
        candidate.current_snapshot = Some(snapshot);
        self.persist_bundle(&candidate)?;
        *bundle = candidate;
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
                let mut candidate = bundle.clone();
                candidate.generation = candidate.next_generation()?;
                candidate.state.last_applied_log = Some(entry.log_id);
                let response = match entry.payload {
                    EntryPayload::Blank => ClientResponse(None),
                    EntryPayload::Normal(ref data) => {
                        let previous = candidate
                            .state
                            .client_status
                            .insert(data.client.clone(), data.status.clone());
                        ClientResponse(previous)
                    }
                    EntryPayload::Membership(ref membership) => {
                        candidate.state.last_membership = StoredMembershipOf::<TypeConfig>::new(
                            Some(entry.log_id),
                            membership.clone(),
                        );
                        ClientResponse(None)
                    }
                };
                self.persist_bundle(&candidate)?;
                *bundle = candidate;
                response
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
        let state: MemStoreStateMachine =
            serde_json::from_slice(&data).map_err(|error| invalid(error.to_string()))?;
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
        };
        let mut bundle = self.bundle.lock().await;
        let mut candidate = bundle.clone();
        candidate.generation = candidate.next_generation()?;
        candidate.state = state;
        candidate.current_snapshot = Some(persisted);
        self.persist_bundle(&candidate)?;
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
    use std::collections::BTreeMap;
    use std::fs;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::Mutex;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "heptabao-{label}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
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
