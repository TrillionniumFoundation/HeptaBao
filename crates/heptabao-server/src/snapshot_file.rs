//! Private descriptor-backed transfer files; no ambient temporary directory.
use heptabao_filesystem_guard::{ExclusiveDirectory, FileAccess};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::path::PathBuf;
use std::{
    fs::{self, File},
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
#[cfg(unix)]
const DIRECTORY: &str = ".snapshot-transfer";

pub(crate) struct SnapshotSpool {
    #[cfg(unix)]
    parent: File,
    #[cfg(unix)]
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
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(invalid())
        }
        #[cfg(unix)]
        {
            if !path.is_absolute() {
                return Err(invalid());
            }
            use rustix::fs::{Mode, OFlags, mkdirat, openat};
            let parent = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(path)
                .map_err(guard)?;
            match mkdirat(&parent, DIRECTORY, Mode::RWXU) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            let child = File::from(openat(
                &parent,
                DIRECTORY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let anchored_child = child.metadata()?;
            if anchored_child.mode() & 0o077 != 0
                || anchored_child.uid() != parent.metadata()?.uid()
            {
                return Err(invalid());
            }
            // The separately locked spool must be the exact child opened from
            // our read-only parent. The durable-state writer remains untouched.
            let directory = ExclusiveDirectory::open(path.join(DIRECTORY)).map_err(guard)?;
            if !anchored_child.is_dir()
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
            for name in spool.directory.entries()? {
                let name = name?;
                let Some(name) = name.to_str() else {
                    return Err(invalid());
                };
                if !name.strip_prefix("transfer-").is_some_and(|tail| {
                    tail.len() == 32 && tail.bytes().all(|b| b.is_ascii_hexdigit())
                }) {
                    return Err(invalid());
                }
                // open_file rejects symlinks, hard links and non-regular files.
                let file = spool.directory.open_file(name, FileAccess::Read)?;
                spool.directory.remove_file(name)?;
                drop(file);
            }
            Ok(spool)
        }
    }

    fn verify(&self) -> io::Result<()> {
        self.directory.verify().map_err(guard)?;
        #[cfg(unix)]
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
        #[cfg(not(unix))]
        {
            let _ = deadline;
            Err(invalid())
        }
        #[cfg(unix)]
        {
            const LIMIT: usize = 64 * 1024;
            self.spool.verify()?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "snapshot transfer deadline exceeded",
                ));
            }
            let file = File::from(rustix::fs::openat(
                &self.spool.parent,
                "seal.json",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )?);
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
        let name = format!("transfer-{suffix}");
        let file = self
            .spool
            .directory
            .open_file(&name, FileAccess::CreateNewReadWrite)?;
        // Open descriptor is the capability. Cancel, panic, reset, timeout and
        // process death all close it; there is no named uploaded state to adopt.
        if self.spool.directory.remove_file(&name).is_err() {
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
