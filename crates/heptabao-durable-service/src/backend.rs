//! Physical persistence boundary for [`super::DurableService`].
//!
//! The backend deals only in barrier-sealed bytes.  It does not decode the
//! snapshot, replay ledger, or journal and therefore cannot accidentally log
//! application state.  The service remains responsible for authentication,
//! replay, and crash recovery; this module only gives those bytes durable
//! storage and a writer fence.

use heptabao_filesystem_guard::{DirectoryGuardError, ExclusiveDirectory};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Maximum encoded size of one physical artifact.  The service applies the
/// same limit before sealing; the backend repeats it before any write.
pub const MAX_BACKEND_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

const SNAPSHOT_LEAF: &str = "state.hbs";
const JOURNAL_LEAF: &str = "journal.hbj";
const LEDGER_LEAF: &str = "ledger.hbl";

/// One physical view of the durable service.
///
/// The fields are sealed bytes, not logical state. Keeping all three values
/// together is a transport grouping: a database backend can read them under
/// one snapshot, while the file backend may expose a crash-time prefix during
/// checkpoint publication. The service still performs cross-artifact
/// validation after loading them.
#[derive(Clone, Eq, PartialEq)]
pub struct BackendBundle {
    pub snapshot: Vec<u8>,
    pub ledger: Vec<u8>,
    pub journal: Vec<u8>,
}

impl BackendBundle {
    /// Build a bundle after checking physical bounds.  No format bytes are
    /// interpreted here; an empty journal is valid for a caller that supplies
    /// its own initialization marker.
    pub fn new(snapshot: Vec<u8>, ledger: Vec<u8>, journal: Vec<u8>) -> Result<Self, BackendError> {
        let bundle = Self {
            snapshot,
            ledger,
            journal,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    fn validate(&self) -> Result<(), BackendError> {
        for bytes in [&self.snapshot, &self.ledger, &self.journal] {
            if bytes.len() > MAX_BACKEND_ARTIFACT_BYTES {
                return Err(BackendError::Capacity);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for BackendBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendBundle")
            .field("snapshot_bytes", &self.snapshot.len())
            .field("ledger_bytes", &self.ledger.len())
            .field("journal_bytes", &self.journal.len())
            .finish()
    }
}

/// Bounded errors deliberately contain no path, SQL, credential, or sealed
/// payload.  `OutcomeUnknown` means a write may have reached stable storage;
/// callers must reopen and reconcile before retrying.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendError {
    InvalidRoot,
    RootNotEmpty,
    MissingArtifact,
    Corrupt,
    Io,
    Unavailable,
    Unsupported,
    WriterLocked,
    StaleWriter,
    Capacity,
    OutcomeUnknown,
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRoot => "invalid durable backend root",
            Self::RootNotEmpty => "durable backend root is not empty",
            Self::MissingArtifact => "durable backend artifact is missing",
            Self::Corrupt => "durable backend artifact is invalid",
            Self::Io => "durable backend I/O failed",
            Self::Unavailable => "durable backend is unavailable",
            Self::Unsupported => "durable backend profile is unsupported",
            Self::WriterLocked => "durable backend writer is already active",
            Self::StaleWriter => "durable backend writer revision is stale",
            Self::Capacity => "durable backend capacity exhausted",
            Self::OutcomeUnknown => "durable backend write outcome is unknown",
        })
    }
}

impl std::error::Error for BackendError {}

/// A backend for the three existing durable-service files.
pub trait DurableBackend: Send {
    fn verify(&self) -> Result<(), BackendError>;
    /// Return one bounded view while holding the backend's writer fence.
    fn load(&mut self) -> Result<BackendBundle, BackendError>;

    /// Establish a new store from the service's initial sealed artifacts.
    fn initialize_empty(&mut self, initial: &BackendBundle) -> Result<(), BackendError>;

    /// Append one complete journal frame at the expected byte offset.
    fn append_journal(&mut self, expected_len: usize, frame: &[u8]) -> Result<usize, BackendError>;

    /// Remove a physically incomplete tail after the service has validated
    /// that no complete frame is being discarded.
    fn truncate_journal(&mut self, expected_len: usize, new_len: usize)
    -> Result<(), BackendError>;

    /// Publish a checkpoint after checking `expected` against the current
    /// artifacts. A database may publish all three artifacts atomically. A
    /// file backend instead makes the snapshot durable, then the ledger, then
    /// the journal; recovery must accept these intermediate checkpoint prefixes.
    /// Success means every artifact is durable. An interrupted publication may
    /// leave a prefix of `replacement` alongside the remaining old artifacts.
    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError>;

    /// Release the writer fence.  Implementations must not send a best-effort
    /// remote rollback because an unknown result must remain unknown.
    fn close(self) -> Result<(), BackendError>
    where
        Self: Sized;
}

/// Descriptor-bound filesystem implementation of [`DurableBackend`].
pub struct FileBackend {
    directory: ExclusiveDirectory,
}

impl fmt::Debug for FileBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileBackend")
            .field("root", &"[REDACTED]")
            .field("writer_fence", &"EXCLUSIVE_HELD")
            .finish()
    }
}

impl FileBackend {
    /// Open an already existing backend root and acquire its writer fence.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BackendError> {
        let root = validate_root(root.as_ref(), false)?;
        let directory = ExclusiveDirectory::open(&root).map_err(map_guard_error)?;
        cleanup_stale_temps(directory.access_path())?;
        Ok(Self { directory })
    }

    /// Create an empty directory and acquire its writer fence.  Artifact
    /// publication is explicit through [`Self::initialize_empty`].
    pub fn create_new(root: impl AsRef<Path>) -> Result<Self, BackendError> {
        let requested = root.as_ref();
        let root = validate_root(requested, true)?;
        let directory = ExclusiveDirectory::open(&root).map_err(map_guard_error)?;
        let access_path = directory.access_path().to_path_buf();
        cleanup_stale_temps(&access_path)?;
        if fs::read_dir(&access_path)
            .map_err(|_| BackendError::Io)?
            .next()
            .transpose()
            .map_err(|_| BackendError::Io)?
            .is_some()
        {
            return Err(BackendError::RootNotEmpty);
        }
        Ok(Self { directory })
    }

    /// Compatibility constructor for callers that already created the root.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, BackendError> {
        Self::open(root)
    }

    /// Verify the descriptor anchor and writer fence without reading payloads.
    pub fn verify(&self) -> Result<(), BackendError> {
        self.directory.verify().map_err(map_guard_error)
    }

    fn path(&self, leaf: &str) -> Result<PathBuf, BackendError> {
        self.directory.leaf_path(leaf).map_err(map_guard_error)
    }

    fn open_artifact(
        &self,
        leaf: &str,
        options: &mut OpenOptions,
    ) -> Result<(File, usize), BackendError> {
        self.verify()?;
        let path = self.path(leaf)?;
        let file = options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BackendError::MissingArtifact
            } else {
                BackendError::Io
            }
        })?;
        // Inspect the descriptor that will actually be read or written. A
        // path metadata check followed by open can validate a different file.
        let metadata = file.metadata().map_err(|_| BackendError::Io)?;
        if !metadata.is_file() {
            return Err(BackendError::Corrupt);
        }
        let length = usize::try_from(metadata.len()).map_err(|_| BackendError::Corrupt)?;
        if length > MAX_BACKEND_ARTIFACT_BYTES {
            return Err(BackendError::Capacity);
        }
        Ok((file, length))
    }

    fn read_artifact(&self, leaf: &str) -> Result<Vec<u8>, BackendError> {
        let (file, length) = self.open_artifact(leaf, nofollow_options().read(true))?;
        let mut bytes = Vec::with_capacity(length);
        file.take((MAX_BACKEND_ARTIFACT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| BackendError::Io)?;
        if bytes.len() != length {
            return Err(BackendError::Corrupt);
        }
        Ok(bytes)
    }

    fn read_bundle(&self) -> Result<BackendBundle, BackendError> {
        let bundle = BackendBundle {
            snapshot: self.read_artifact(SNAPSHOT_LEAF)?,
            ledger: self.read_artifact(LEDGER_LEAF)?,
            journal: self.read_artifact(JOURNAL_LEAF)?,
        };
        self.verify()?;
        bundle.validate()?;
        Ok(bundle)
    }

    fn write_temp(&self, leaf: &str, bytes: &[u8]) -> Result<PathBuf, BackendError> {
        if bytes.len() > MAX_BACKEND_ARTIFACT_BYTES {
            return Err(BackendError::Capacity);
        }
        let target = self.path(leaf)?;
        let temporary = target.with_extension("tmp");
        // The exclusive writer fence makes a previous writer's temporary
        // leaf disposable. Unlink it rather than truncate it: stale symlinks
        // and hard links must never redirect a write to another file.
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(BackendError::Io),
        }
        let mut file = nofollow_options()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| BackendError::Io)?;
        if file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(&temporary);
            return Err(BackendError::Io);
        }
        Ok(temporary)
    }

    fn replace_bundle(
        &self,
        replacement: &BackendBundle,
        require_absent: bool,
    ) -> Result<(), BackendError> {
        replacement.validate()?;
        self.verify()?;
        if require_absent {
            for leaf in [SNAPSHOT_LEAF, LEDGER_LEAF, JOURNAL_LEAF] {
                let path = self.path(leaf)?;
                match fs::symlink_metadata(path) {
                    Ok(_) => return Err(BackendError::RootNotEmpty),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(BackendError::Io),
                }
            }
        }
        let snapshot = self.write_temp(SNAPSHOT_LEAF, &replacement.snapshot)?;
        let ledger = match self.write_temp(LEDGER_LEAF, &replacement.ledger) {
            Ok(path) => path,
            Err(error) => {
                let _ = fs::remove_file(snapshot);
                return Err(error);
            }
        };
        let journal = match self.write_temp(JOURNAL_LEAF, &replacement.journal) {
            Ok(path) => path,
            Err(error) => {
                let _ = fs::remove_file(snapshot);
                let _ = fs::remove_file(ledger);
                return Err(error);
            }
        };
        let targets = [
            (snapshot, self.path(SNAPSHOT_LEAF)?),
            (ledger, self.path(LEDGER_LEAF)?),
            (journal, self.path(JOURNAL_LEAF)?),
        ];
        for (published, (temporary, target)) in targets.iter().enumerate() {
            if fs::rename(temporary, target).is_err() {
                for (remaining, _) in targets.iter().skip(published) {
                    let _ = fs::remove_file(remaining);
                }
                if published != 0 {
                    return Err(BackendError::OutcomeUnknown);
                }
                return Err(BackendError::Io);
            }
            // Recovery relies on this order: the new journal must never be
            // durable before the snapshot and ledger that justify discarding
            // its old frames. One directory sync after all three renames does
            // not establish that ordering across a crash.
            if self.directory.sync_all().is_err() {
                return Err(BackendError::OutcomeUnknown);
            }
        }
        Ok(())
    }
}

impl DurableBackend for FileBackend {
    fn verify(&self) -> Result<(), BackendError> {
        self.verify()
    }

    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.read_bundle()
    }

    fn initialize_empty(&mut self, initial: &BackendBundle) -> Result<(), BackendError> {
        self.replace_bundle(initial, true)
    }

    fn append_journal(&mut self, expected_len: usize, frame: &[u8]) -> Result<usize, BackendError> {
        if frame.is_empty() || frame.len() > MAX_BACKEND_ARTIFACT_BYTES {
            return Err(BackendError::Capacity);
        }
        let next = expected_len
            .checked_add(frame.len())
            .ok_or(BackendError::Capacity)?;
        if next > MAX_BACKEND_ARTIFACT_BYTES {
            return Err(BackendError::Capacity);
        }
        let (mut file, current_len) =
            self.open_artifact(JOURNAL_LEAF, nofollow_options().append(true))?;
        if current_len != expected_len {
            return Err(BackendError::StaleWriter);
        }
        if file
            .write_all(frame)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            return Err(BackendError::OutcomeUnknown);
        }
        let actual_len = file
            .metadata()
            .map_err(|_| BackendError::OutcomeUnknown)?
            .len();
        if actual_len != next as u64 {
            return Err(BackendError::OutcomeUnknown);
        }
        Ok(next)
    }

    fn truncate_journal(
        &mut self,
        expected_len: usize,
        new_len: usize,
    ) -> Result<(), BackendError> {
        if new_len > expected_len || expected_len > MAX_BACKEND_ARTIFACT_BYTES {
            return Err(BackendError::Capacity);
        }
        let (file, current_len) =
            self.open_artifact(JOURNAL_LEAF, nofollow_options().write(true))?;
        if current_len != expected_len {
            return Err(BackendError::StaleWriter);
        }
        if file
            .set_len(new_len as u64)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            return Err(BackendError::OutcomeUnknown);
        }
        if file
            .metadata()
            .map_err(|_| BackendError::OutcomeUnknown)?
            .len()
            != new_len as u64
        {
            return Err(BackendError::OutcomeUnknown);
        }
        Ok(())
    }

    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        expected.validate()?;
        replacement.validate()?;
        let current = self.read_bundle()?;
        if &current != expected {
            return Err(BackendError::StaleWriter);
        }
        self.replace_bundle(replacement, false)
    }

    fn close(self) -> Result<(), BackendError> {
        Ok(())
    }
}

fn validate_root(root: &Path, create: bool) -> Result<PathBuf, BackendError> {
    if !root.is_absolute() {
        return Err(BackendError::InvalidRoot);
    }
    if root.exists() {
        let metadata = fs::symlink_metadata(root).map_err(|_| BackendError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BackendError::InvalidRoot);
        }
    } else if create {
        fs::create_dir_all(root).map_err(|_| BackendError::Io)?;
    } else {
        return Err(BackendError::InvalidRoot);
    }
    Ok(root.to_path_buf())
}

fn map_guard_error(error: DirectoryGuardError) -> BackendError {
    match error {
        DirectoryGuardError::WriterBusy => BackendError::WriterLocked,
        DirectoryGuardError::UnsupportedPlatform
        | DirectoryGuardError::DescriptorPathUnavailable => BackendError::Unsupported,
        DirectoryGuardError::Io(_) => BackendError::Io,
        _ => BackendError::InvalidRoot,
    }
}

fn cleanup_stale_temps(access_path: &Path) -> Result<(), BackendError> {
    for leaf in ["state.tmp", "ledger.tmp", "journal.tmp"] {
        let path = access_path.join(leaf);
        match fs::symlink_metadata(&path) {
            Ok(_) => fs::remove_file(path).map_err(|_| BackendError::Io)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(BackendError::Io),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn nofollow_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    // Nonblocking open lets descriptor metadata reject a FIFO without waiting
    // for a peer. It has no effect on the regular files accepted above.
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options
}

#[cfg(not(target_os = "linux"))]
fn nofollow_options() -> OpenOptions {
    OpenOptions::new()
}

#[cfg(test)]
mod tests {
    use super::{BackendBundle, BackendError, DurableBackend, FileBackend};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "heptabao-backend-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn initial() -> Result<BackendBundle, BackendError> {
        BackendBundle::new(
            b"snapshot".to_vec(),
            b"ledger".to_vec(),
            b"journal".to_vec(),
        )
    }

    #[test]
    fn initialize_load_append_and_stale_offset() -> Result<(), BackendError> {
        let root = temp_root("append");
        let result = (|| {
            let mut backend = FileBackend::create_new(&root)?;
            let initial = initial()?;
            backend.initialize_empty(&initial)?;
            assert_eq!(backend.load()?, initial);
            let next = backend.append_journal(initial.journal.len(), b"frame")?;
            assert_eq!(next, initial.journal.len() + 5);
            assert_eq!(
                backend.append_journal(initial.journal.len(), b"again"),
                Err(BackendError::StaleWriter)
            );
            Ok(())
        })();
        let _ = fs::remove_dir_all(&root);
        result
    }

    #[test]
    fn checkpoint_requires_exact_bundle() -> Result<(), BackendError> {
        let root = temp_root("checkpoint");
        let result = (|| {
            let mut backend = FileBackend::create_new(&root)?;
            let initial = initial()?;
            backend.initialize_empty(&initial)?;
            let replacement = BackendBundle::new(
                b"new-snapshot".to_vec(),
                b"new-ledger".to_vec(),
                b"new-journal".to_vec(),
            )?;
            backend.publish_checkpoint(&initial, &replacement)?;
            assert_eq!(backend.load()?, replacement);
            assert_eq!(
                backend.publish_checkpoint(&initial, &initial),
                Err(BackendError::StaleWriter)
            );
            Ok(())
        })();
        let _ = fs::remove_dir_all(&root);
        result
    }

    #[test]
    fn create_new_cleans_only_known_stale_temps() -> Result<(), BackendError> {
        let root = temp_root("stale-temp");
        let result = (|| {
            fs::create_dir_all(&root).map_err(|_| BackendError::Io)?;
            fs::write(root.join("state.tmp"), b"stale").map_err(|_| BackendError::Io)?;
            let mut backend = FileBackend::create_new(&root)?;
            backend.initialize_empty(&initial()?)?;
            drop(backend);
            fs::write(root.join("journal.tmp"), b"stale").map_err(|_| BackendError::Io)?;
            let _backend = FileBackend::open(&root)?;
            assert!(!root.join("state.tmp").exists());
            assert!(!root.join("journal.tmp").exists());
            Ok(())
        })();
        let _ = fs::remove_dir_all(&root);
        result
    }
}
