//! Watch the held inode through its descriptor; never reopen an original leaf.
use super::{FileIdentity, Observation, Removal, WatchId, refused};
use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
use std::os::unix::fs::MetadataExt;
use std::{fs::File, io, os::fd::AsRawFd};

const MAX_DRAIN_READS: usize = 64;
const EVENT_HEADER_BYTES: usize = 16;
const BUFFER_BYTES: usize = 4096;
pub(super) struct Queue {
    fd: rustix::fd::OwnedFd,
}
pub(super) struct Registration {
    watch: i32,
}
impl Registration {
    pub(super) fn id(&self) -> WatchId {
        self.watch as WatchId
    }
}
impl Queue {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            fd: inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)?,
        })
    }
    pub(super) fn register(&mut self, file: &File) -> io::Result<Registration> {
        // Follow the kernel magic link of this still-borrowed fd. IN_DONT_FOLLOW
        // would watch the proc link instead. Missing procfs must refuse.
        let path = format!("/proc/self/fd/{}", file.as_raw_fd());
        let identity = FileIdentity::read(file)?;
        let check_path = || -> io::Result<()> {
            let actual = std::fs::metadata(&path)?;
            if !actual.is_file()
                || actual.nlink() != 1
                || actual.dev() != identity.device
                || actual.ino() != identity.inode
            {
                return Err(refused());
            }
            Ok(())
        };
        check_path()?;
        let watch = inotify::add_watch(
            &self.fd,
            path.as_str(),
            WatchFlags::MODIFY
                | WatchFlags::ATTRIB
                | WatchFlags::DELETE_SELF
                | WatchFlags::MOVE_SELF,
        )?;
        if watch < 0 {
            return Err(refused());
        }
        check_path()?;
        Ok(Registration { watch })
    }
    pub(super) fn remove(&mut self, registration: &Registration) -> io::Result<Removal> {
        inotify::remove_watch(&self.fd, registration.watch)?;
        Ok(Removal::AwaitIgnored)
    }
    pub(super) fn drain(
        &mut self,
        observe: &mut impl FnMut(Observation) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut buffer = [0u8; BUFFER_BYTES];
        for _ in 0..MAX_DRAIN_READS {
            let count = match rustix::io::read(&self.fd, &mut buffer[..]) {
                Ok(count) => count,
                Err(rustix::io::Errno::AGAIN) => return Ok(()),
                Err(_) => return Err(refused()),
            };
            if count == 0 || count > buffer.len() {
                return Err(refused());
            }
            decode(&buffer[..count], observe)?;
        }
        // Exhausting the work bound is never interpreted as an empty queue.
        Err(refused())
    }
}
pub(super) fn decode(
    bytes: &[u8],
    observe: &mut impl FnMut(Observation) -> io::Result<()>,
) -> io::Result<()> {
    let mut position = 0usize;
    while position < bytes.len() {
        let end = position
            .checked_add(EVENT_HEADER_BYTES)
            .ok_or_else(refused)?;
        let header = bytes.get(position..end).ok_or_else(refused)?;
        let watch = i32::from_ne_bytes(header[0..4].try_into().map_err(|_| refused())?);
        let mask = u32::from_ne_bytes(header[4..8].try_into().map_err(|_| refused())?);
        let cookie = u32::from_ne_bytes(header[8..12].try_into().map_err(|_| refused())?);
        let name_len = u32::from_ne_bytes(header[12..16].try_into().map_err(|_| refused())?);
        // Only regular-inode self events are requested: no names or rename-pair
        // cookies. Overflow has wd=-1. Unknown bits poison the entire broker.
        let known = libc::IN_MODIFY
            | libc::IN_ATTRIB
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_UNMOUNT
            | libc::IN_IGNORED;
        if watch < 0 || mask == 0 || mask & !known != 0 || cookie != 0 || name_len != 0 {
            return Err(refused());
        }
        observe(Observation {
            watch: watch as WatchId,
            removed: mask & libc::IN_IGNORED != 0,
        })?;
        position = end;
    }
    Ok(())
}
