//! A request-scoped descriptor for the live seal leaf. Only the descriptor
//! identity is retained: every check reads fresh bytes, validates the current
//! name and permissions, and keeps the original transfer deadline.
use super::*;
#[cfg(unix)]
use std::os::unix::fs::FileExt;

pub(crate) struct SnapshotSealReader<'a> {
    lease: &'a SnapshotLease,
    #[cfg(unix)]
    file: File,
    #[cfg(unix)]
    identity: (u64, u64),
}

impl SnapshotLease {
    pub(crate) fn seal_reader(&self, deadline: Instant) -> io::Result<SnapshotSealReader<'_>> {
        #[cfg(not(unix))]
        {
            let _ = deadline;
            Err(invalid())
        }
        #[cfg(unix)]
        {
            self.spool.verify()?;
            check_deadline(deadline)?;
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
            let reader = SnapshotSealReader {
                lease: self,
                identity: (metadata.dev(), metadata.ino()),
                file,
            };
            reader.verify_current(deadline)?;
            Ok(reader)
        }
    }
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "snapshot transfer deadline exceeded",
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn same_observation(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

impl SnapshotSealReader<'_> {
    #[cfg(unix)]
    fn verify_current(&self, deadline: Instant) -> io::Result<Option<rustix::fs::Stat>> {
        check_deadline(deadline)?;
        let parent = self.lease.spool.verify_with_parent()?;
        // Check the current name before the old descriptor's link count:
        // atomic replacement legitimately unlinks that old descriptor.
        let named = rustix::fs::statat(
            &self.lease.spool.parent,
            "seal.json",
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
        if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile {
            return Err(invalid());
        }
        if (named.st_dev as u64, named.st_ino as u64) != self.identity {
            return Ok(None);
        }
        // The live File cannot change device/inode or permit that inode to be
        // reused. A fresh named stat matching this held identity therefore
        // observes the held file itself; a second fstat adds no new authority.
        // Read the name again after the physical bytes and compare every
        // mutable witness, including nanosecond modification/change times.
        if named.st_nlink != 1
            || named.st_mode & 0o077 != 0
            || named.st_uid != parent.uid()
            || u64::try_from(named.st_size).map_err(|_| invalid())? > SEAL_METADATA_LIMIT as u64
        {
            return Err(invalid());
        }
        check_deadline(deadline)?;
        Ok(Some(named))
    }

    pub(crate) fn read_metadata(
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
            let Some(before) = self.verify_current(deadline)? else {
                // Only a regular replacement leaf takes the original open/read
                // path. Its fresh bytes still face the caller's admitted seal
                // and authorization checks under the same original deadline.
                return self.lease.read_seal_metadata(deadline);
            };
            // Positioned reads have no shared cursor across scoped workers.
            // A new zeroizing buffer is filled from byte zero on EVERY check.
            let bytes = read_seal_bytes(
                PositionedSealRead {
                    file: &self.file,
                    offset: 0,
                    deadline,
                },
                u64::try_from(before.st_size).map_err(|_| invalid())?,
            )?;
            if bytes.len() > SEAL_METADATA_LIMIT {
                return Err(invalid());
            }
            let after = self.verify_current(deadline)?.ok_or_else(invalid)?;
            if !same_observation(&before, &after) {
                return Err(invalid());
            }
            Ok(bytes)
        }
    }
}

#[cfg(unix)]
struct PositionedSealRead<'a> {
    file: &'a File,
    offset: u64,
    deadline: Instant,
}

#[cfg(unix)]
impl Read for PositionedSealRead<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        check_deadline(self.deadline)?;
        let read = self.file.read_at(bytes, self.offset)?;
        check_deadline(self.deadline)?;
        self.offset = self.offset.checked_add(read as u64).ok_or_else(invalid)?;
        Ok(read)
    }
}

#[cfg(all(test, unix))]
#[path = "snapshot_seal_reader_tests.rs"]
mod tests;
