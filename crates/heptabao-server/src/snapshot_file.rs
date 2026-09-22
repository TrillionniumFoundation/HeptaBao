//! Private descriptor-backed transfer files; no ambient temporary directory.
use heptabao_filesystem_guard::ExclusiveDirectory;
#[cfg(target_os = "linux")]
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt},
};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

pub(crate) const MAX_NATIVE_STATE: u64 = 130 * 1024 * 1024;
pub(crate) const MAX_NATIVE_ARCHIVE: u64 = MAX_NATIVE_STATE + 1024 * 1024;
#[cfg(target_os = "linux")]
const DIRECTORY: &str = ".snapshot-transfer";

pub(crate) struct SnapshotSpool {
    #[cfg(target_os = "linux")]
    parent: File,
    #[cfg(target_os = "linux")]
    original: PathBuf,
    directory: ExclusiveDirectory,
    busy: AtomicBool,
}

fn invalid() -> io::Error {
    io::Error::other("snapshot transfer storage is unavailable")
}
fn guard(error: impl std::fmt::Display) -> io::Error {
    let _ = error;
    invalid()
}

impl SnapshotSpool {
    pub(crate) fn open(path: &Path) -> io::Result<Arc<Self>> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err(invalid())
        }
        #[cfg(target_os = "linux")]
        {
            if !path.is_absolute() {
                return Err(invalid());
            }
            let parent = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(path)?;
            let anchored = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
            let child = anchored.join(DIRECTORY);
            match fs::create_dir(&child) {
                Ok(()) => {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&child, fs::Permissions::from_mode(0o700))?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            if fs::symlink_metadata(&child)?.file_type().is_symlink() {
                return Err(invalid());
            }
            // The guard rejects every symlink ancestor, including /proc's
            // descriptor links. Acquire through the original absolute path,
            // then bind it to the child created through our held parent.
            let directory = ExclusiveDirectory::open(path.join(DIRECTORY)).map_err(guard)?;
            let anchored_child = fs::symlink_metadata(&child)?;
            if !anchored_child.is_dir()
                || anchored_child.file_type().is_symlink()
                || anchored_child.dev() != directory.identity().device()
                || anchored_child.ino() != directory.identity().inode()
            {
                return Err(invalid());
            }
            let spool = Arc::new(Self {
                parent,
                original: path.to_owned(),
                directory,
                busy: AtomicBool::new(false),
            });
            spool.verify()?;
            // Only interrupted create-before-unlink leaves can survive a crash.
            // No authority or arbitrary application filename is ever removed.
            for entry in fs::read_dir(spool.directory.access_path())? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    return Err(invalid());
                };
                if !name.strip_prefix("transfer-").is_some_and(|tail| {
                    tail.len() == 32 && tail.bytes().all(|b| b.is_ascii_hexdigit())
                }) {
                    return Err(invalid());
                }
                let metadata = entry.metadata()?;
                if !metadata.is_file() || metadata.nlink() != 1 || entry.file_type()?.is_symlink() {
                    return Err(invalid());
                }
                fs::remove_file(spool.directory.leaf_path(name).map_err(guard)?)?;
            }
            Ok(spool)
        }
    }

    fn verify(&self) -> io::Result<()> {
        self.directory.verify().map_err(guard)?;
        #[cfg(target_os = "linux")]
        {
            let held = self.parent.metadata()?;
            let current = fs::symlink_metadata(&self.original)?;
            if !current.is_dir()
                || current.file_type().is_symlink()
                || held.dev() != current.dev()
                || held.ino() != current.ino()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(crate) fn lease(self: &Arc<Self>) -> io::Result<Arc<SnapshotLease>> {
        self.verify()?;
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "snapshot transfer is already active",
                )
            })?;
        Ok(Arc::new(SnapshotLease {
            spool: Arc::clone(self),
        }))
    }
}

pub(crate) struct SnapshotLease {
    spool: Arc<SnapshotSpool>,
}
impl Drop for SnapshotLease {
    fn drop(&mut self) {
        self.spool.busy.store(false, Ordering::Release);
    }
}
impl SnapshotLease {
    /// Read only the committed seal metadata, through the already-held parent
    /// capability. Never resolve an archive-supplied path or a replaced parent.
    pub(crate) fn read_seal_metadata(
        &self,
        deadline: Instant,
    ) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = deadline;
            Err(invalid())
        }
        #[cfg(target_os = "linux")]
        {
            const LIMIT: usize = 64 * 1024;
            self.spool.verify()?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "snapshot transfer deadline exceeded",
                ));
            }
            let path = PathBuf::from(format!("/proc/self/fd/{}", self.spool.parent.as_raw_fd()))
                .join("seal.json");
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0
                || metadata.uid() != self.spool.parent.metadata()?.uid()
                || metadata.len() > LIMIT as u64
            {
                return Err(invalid());
            }
            let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(LIMIT + 1));
            file.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
            if bytes.len() > LIMIT {
                return Err(invalid());
            }
            self.spool.verify()?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "snapshot transfer deadline exceeded",
                ));
            }
            Ok(bytes)
        }
    }

    pub(crate) fn file(
        self: &Arc<Self>,
        maximum: u64,
        deadline: Instant,
    ) -> io::Result<SnapshotFile> {
        self.spool.verify()?;
        let nonce = crate::crypto::random::<16>().map_err(|_| invalid())?;
        let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = self
            .spool
            .directory
            .leaf_path(&format!("transfer-{suffix}"))
            .map_err(guard)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(target_os = "linux")]
        {
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path)?;
        // Open descriptor is the capability. Cancel, panic, reset, timeout and
        // process death all close it; there is no named uploaded state to adopt.
        if fs::remove_file(&path).is_err() {
            drop(file);
            return Err(invalid());
        }
        self.spool.verify()?;
        Ok(SnapshotFile {
            file,
            lease: Arc::clone(self),
            maximum,
            length: 0,
            deadline,
        })
    }
}

pub(crate) struct SnapshotFile {
    file: File,
    lease: Arc<SnapshotLease>,
    maximum: u64,
    length: u64,
    deadline: Instant,
}
impl SnapshotFile {
    pub(crate) fn len(&self) -> u64 {
        self.length
    }
    pub(crate) fn rewind_checked(&mut self) -> io::Result<()> {
        self.lease.spool.verify()?;
        self.seek(SeekFrom::Start(0))?;
        Ok(())
    }
    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "snapshot transfer deadline exceeded",
            ));
        }
        Ok(())
    }
}
impl Read for SnapshotFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        self.file.read(bytes)
    }
}
impl Write for SnapshotFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        let position = self.file.stream_position()?;
        if position
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.maximum)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot transfer bound exceeded",
            ));
        }
        let count = self.file.write(bytes)?;
        self.length = self.length.max(position + count as u64);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.file.flush()
    }
}
impl Seek for SnapshotFile {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.check()?;
        self.file.seek(from)
    }
}
