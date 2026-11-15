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

#[path = "snapshot_seal_reader.rs"]
mod seal_reader;
pub(crate) use seal_reader::SnapshotSealReader;

pub(crate) const MAX_NATIVE_STATE: u64 = 130 * 1024 * 1024;
// Legacy HBB2 state remains bounded to 130 MiB. Only the explicit native-V6
// build accepts the separately bounded external-object pack transport.
#[cfg(feature = "native-v6-storage")]
pub(crate) const MAX_V6_SNAPSHOT_STATE: u64 =
    MAX_NATIVE_STATE + 1024 * 1024 * 1024 + 65_536 * 4 + 4132;
// HA carries both the independent local pack and shared-key typed closure.
// Keep this explicit transport bound below the 8 GiB ustar size-field limit;
// each constituent retains its own stricter validation and source limit.
#[cfg(feature = "native-v6-ha")]
pub(crate) const MAX_V6_HA_SNAPSHOT_STATE: u64 = 2 * MAX_V6_SNAPSHOT_STATE + 64 * 1024 * 1024;
#[cfg(feature = "native-v6-ha")]
pub(crate) const MAX_SNAPSHOT_ENTRY: u64 = MAX_V6_HA_SNAPSHOT_STATE;
#[cfg(all(feature = "native-v6-storage", not(feature = "native-v6-ha")))]
pub(crate) const MAX_SNAPSHOT_ENTRY: u64 = MAX_V6_SNAPSHOT_STATE;
#[cfg(not(feature = "native-v6-storage"))]
pub(crate) const MAX_SNAPSHOT_ENTRY: u64 = MAX_NATIVE_STATE;
pub(crate) const MAX_NATIVE_ARCHIVE: u64 = MAX_SNAPSHOT_ENTRY + 1024 * 1024;
#[cfg(unix)]
const DIRECTORY: &str = ".snapshot-transfer";

pub(crate) struct SnapshotSpool {
    #[cfg(unix)]
    parent: File,
    // A private held directory descriptor cannot change its device/inode.
    // This is its immutable identity, never a cached UID, mode or path result.
    #[cfg(unix)]
    parent_identity: (u64, u64),
    #[cfg(unix)]
    original: PathBuf,
    directory: ExclusiveDirectory,
    busy: AtomicBool,
}

fn invalid() -> io::Error {
    io::Error::other("snapshot transfer storage is unavailable")
}

#[cfg(unix)]
const SEAL_METADATA_LIMIT: usize = 64 * 1024;

// The stat size is only an allocation hint: a concurrent length change still
// gets the same bounded physical read. Grow by replacing a Zeroizing owner so
// no old secret allocation is discarded by Vec's implicit reallocation.
#[cfg(unix)]
fn read_seal_bytes(
    mut reader: impl Read,
    length_hint: u64,
) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let maximum = SEAL_METADATA_LIMIT + 1;
    let initial = usize::try_from(length_hint)
        .unwrap_or(maximum)
        .saturating_add(1)
        .min(maximum);
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(initial));
    loop {
        let start = bytes.len();
        if start == maximum {
            return Ok(bytes);
        }
        if start == bytes.capacity() {
            let capacity = bytes.capacity().saturating_mul(2).min(maximum);
            let mut grown = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
            grown.extend_from_slice(&bytes);
            bytes = grown;
        }
        let end = bytes.capacity().min(maximum);
        bytes.resize(end, 0);
        match reader.read(&mut bytes[start..]) {
            Ok(count) => {
                bytes.truncate(start + count);
                if count == 0 {
                    return Ok(bytes);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => bytes.truncate(start),
            Err(error) => return Err(error),
        }
    }
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
            let parent_metadata = parent.metadata()?;
            if anchored_child.mode() & 0o077 != 0 || anchored_child.uid() != parent_metadata.uid() {
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
                parent_identity: (parent_metadata.dev(), parent_metadata.ino()),
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
        #[cfg(unix)]
        {
            self.verify_with_parent().map(|_| ())
        }
        #[cfg(not(unix))]
        {
            self.directory.verify().map_err(guard)
        }
    }

    #[cfg(unix)]
    fn verify_with_parent(&self) -> io::Result<fs::Metadata> {
        self.directory.verify().map_err(guard)?;
        let current = fs::symlink_metadata(&self.original)?;
        if !current.is_dir()
            || current.file_type().is_symlink()
            || self.parent_identity != (current.dev(), current.ino())
        {
            return Err(invalid());
        }
        // This is a fresh name observation of the same held parent inode.
        // Callers may use its current UID without a redundant fstat, but no
        // observation is retained across a read or authorization boundary.
        Ok(current)
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
                || metadata.len() > SEAL_METADATA_LIMIT as u64
            {
                return Err(invalid());
            }
            let bytes = read_seal_bytes(file, metadata.len())?;
            if bytes.len() > SEAL_METADATA_LIMIT {
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

    /// Coalesce only private export output. The exclusive borrow prevents any
    /// other seek/write while the logical cursor differs from the descriptor.
    /// Every logical write retains this file's original deadline and bound.
    #[cfg(feature = "native-v6-storage")]
    pub(crate) fn buffered_writer(&mut self) -> io::Result<SnapshotBufferedWriter<'_>> {
        self.check()?;
        let position = self.file.stream_position()?;
        Ok(SnapshotBufferedWriter {
            inner: self,
            pending: zeroize::Zeroizing::new(Vec::with_capacity(EXPORT_WRITE_BUFFER)),
            position,
            failed: false,
        })
    }
}

#[cfg(feature = "native-v6-storage")]
const EXPORT_WRITE_BUFFER: usize = 64 * 1024;

/// This buffer has no Drop flush. A failed/cancelled export erases its pending
/// plaintext without attempting more I/O or releasing any response authority.
#[cfg(feature = "native-v6-storage")]
pub(crate) struct SnapshotBufferedWriter<'a> {
    inner: &'a mut SnapshotFile,
    pending: zeroize::Zeroizing<Vec<u8>>,
    position: u64,
    failed: bool,
}

#[cfg(feature = "native-v6-storage")]
impl SnapshotBufferedWriter<'_> {
    fn ready(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(invalid());
        }
        if let Err(error) = self.inner.check() {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }

    fn drain(&mut self) -> io::Result<()> {
        self.ready()?;
        if let Err(error) = self.inner.write_all(self.pending.as_slice()) {
            self.failed = true;
            return Err(error);
        }
        // Erase initialized bytes BEFORE clear: Vec's unused capacity must
        // never retain an earlier plaintext fragment after a successful flush.
        use zeroize::Zeroize;
        self.pending.as_mut_slice().zeroize();
        self.pending.clear();
        Ok(())
    }

    pub(crate) fn finish(mut self) -> io::Result<()> {
        self.flush()
    }
}

#[cfg(feature = "native-v6-storage")]
impl Write for SnapshotBufferedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.ready()?;
        let Some(end) = self.position.checked_add(bytes.len() as u64) else {
            self.failed = true;
            return Err(invalid());
        };
        if end > self.inner.maximum {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot transfer bound exceeded",
            ));
        }
        if bytes.len() >= EXPORT_WRITE_BUFFER {
            self.drain()?;
            return match self.inner.write(bytes) {
                Ok(count) => {
                    self.position += count as u64;
                    Ok(count)
                }
                Err(error) => {
                    self.failed = true;
                    Err(error)
                }
            };
        }
        if self.pending.len() + bytes.len() > EXPORT_WRITE_BUFFER {
            self.drain()?;
        }
        self.ready()?;
        self.pending.extend_from_slice(bytes);
        self.position = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain()?;
        if let Err(error) = self.inner.flush() {
            self.failed = true;
            return Err(error);
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

#[cfg(all(test, unix, feature = "native-v6-storage"))]
#[path = "snapshot_file_buffer_tests.rs"]
mod buffer_tests;

#[cfg(all(test, unix, feature = "native-v6-storage"))]
#[path = "snapshot_seal_read_tests.rs"]
mod seal_read_tests;
