#![cfg(target_os = "macos")]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
//! The narrow owning Darwin vnode-event boundary used by filesystem-guard.
//! Only fixed EVFILT_VNODE events are accepted. No raw descriptor or pointer
//! escapes this API. A failed unregister closes the queue BEFORE any watched
//! descriptor can be released. These events are not a universal file generation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
};

const EVENT_BATCH: usize = 64;
static NEXT_QUEUE_ID: AtomicU64 = AtomicU64::new(1);
const VNODE_MASK: u32 = libc::NOTE_WRITE
    | libc::NOTE_EXTEND
    | libc::NOTE_ATTRIB
    | libc::NOTE_LINK
    | libc::NOTE_DELETE
    | libc::NOTE_RENAME
    | libc::NOTE_REVOKE;

fn refused() -> io::Error {
    io::Error::other("Darwin vnode event ownership or observation failed")
}

/// Opaque identifier scoped to its originating queue; never a raw fd.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WatchId {
    queue: u64,
    sequence: u64,
}
impl WatchId {
    pub const fn value(self) -> u64 {
        self.sequence
    }
}

/// Owns both the kqueue and EVERY file descriptor registered in it.
pub struct VnodeMutationQueue {
    // Declaration order also makes ordinary Drop close the queue first.
    queue: Option<OwnedFd>,
    files: BTreeMap<WatchId, File>,
    owner_id: u64,
    next_id: u64,
}
impl fmt::Debug for VnodeMutationQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VnodeMutationQueue([OWNED_QUEUE_AND_DESCRIPTORS])")
    }
}

impl VnodeMutationQueue {
    pub fn new() -> io::Result<Self> {
        let owner_id = NEXT_QUEUE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| refused())?;
        // SAFETY: kqueue takes no pointer arguments. A successful returned fd
        // is immediately transferred into exactly one OwnedFd below.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is the newly created fd above, not borrowed or duplicated
        // from a caller. No other Rust owner has been constructed for it.
        let queue = unsafe { OwnedFd::from_raw_fd(raw) };
        // Darwin's kqueue(2) contract says queues are not inherited across fork.
        // The separate fcntl is not claimed to be an atomic creation primitive.
        // SAFETY: this owned fd is live, F_SETFD takes an integer third arg, and
        // FD_CLOEXEC is its documented flag. No pointer crosses this call.
        if unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            queue: Some(queue),
            files: BTreeMap::new(),
            owner_id,
            next_id: 1,
        })
    }

    fn poison(&mut self) {
        // Kernel registrations disappear when the queue closes. Only THEN may
        // registered fds close or their numbers be recycled in this process.
        drop(self.queue.take());
        self.files.clear();
    }

    fn event(id: WatchId, file: &File, flags: u16) -> io::Result<libc::kevent> {
        let opaque = usize::try_from(id.sequence).map_err(|_| refused())?;
        Ok(libc::kevent {
            ident: file.as_raw_fd() as usize,
            filter: libc::EVFILT_VNODE,
            flags,
            fflags: VNODE_MASK,
            data: 0,
            // A numeric token only; neither the kernel nor this crate ever
            // dereferences it or accepts a caller-supplied pointer.
            udata: ptr::without_provenance_mut(opaque),
        })
    }

    fn receipt(&self, change: &libc::kevent) -> io::Result<()> {
        let queue = self.queue.as_ref().ok_or_else(refused)?;
        let mut response = *change;
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: queue and every referenced file are owned by self and remain
        // live for this call. Exactly one initialized input/output element is
        // passed, their pointers are valid, and the timeout is a live zero
        // timespec. Only fixed EVFILT_VNODE with numeric opaque udata is used.
        let count = unsafe { libc::kevent(queue.as_raw_fd(), change, 1, &mut response, 1, &zero) };
        if count != 1
            || response.ident != change.ident
            || response.filter != libc::EVFILT_VNODE
            || response.udata != change.udata
            || response.flags & libc::EV_ERROR == 0
            || response.flags & !(change.flags | libc::EV_ERROR) != 0
            || response.data != 0
        {
            return Err(refused());
        }
        Ok(())
    }

    pub fn register(&mut self, file: &File) -> io::Result<WatchId> {
        if self.queue.is_none() {
            return Err(refused());
        }
        let id = WatchId {
            queue: self.owner_id,
            sequence: self.next_id,
        };
        self.next_id = self.next_id.checked_add(1).ok_or_else(refused)?;
        let owned = file.try_clone()?;
        let change = Self::event(id, &owned, libc::EV_ADD | libc::EV_CLEAR | libc::EV_RECEIPT)?;
        // The fd owner is installed BEFORE the syscall can register it. Any
        // ambiguous registration failure closes the whole queue before it.
        if self.files.insert(id, owned).is_some() {
            self.poison();
            return Err(refused());
        }
        if self.receipt(&change).is_err() {
            self.poison();
            return Err(refused());
        }
        Ok(id)
    }

    pub fn remove(&mut self, id: WatchId) -> io::Result<()> {
        if id.queue != self.owner_id {
            return Err(refused());
        }
        let result = (|| {
            let file = self.files.get(&id).ok_or_else(refused)?;
            let change = Self::event(id, file, libc::EV_DELETE | libc::EV_RECEIPT)?;
            self.receipt(&change)
        })();
        if result.is_err() {
            self.poison();
            return Err(refused());
        }
        // EV_RECEIPT uniquely acknowledged successful removal. Only now can
        // this owned duplicate close; a stale fd number cannot stay watched.
        self.files.remove(&id);
        Ok(())
    }

    /// One nonblocking bounded poll. Empty means this poll saw no pending
    /// event; the filesystem guard owns the complete-drain and failure latch.
    pub fn poll(&mut self) -> io::Result<Vec<WatchId>> {
        let result = self.poll_inner();
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn poll_inner(&self) -> io::Result<Vec<WatchId>> {
        let queue = self.queue.as_ref().ok_or_else(refused)?;
        let empty = libc::kevent {
            ident: 0,
            filter: libc::EVFILT_VNODE,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: ptr::null_mut(),
        };
        let mut events = [empty; EVENT_BATCH];
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: queue is owned/live, no changes are submitted, and the output
        // pointer spans EVENT_BATCH initialized kevent slots. The zero timeout
        // is valid for the call. All registered fds remain in self.files.
        let count = unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                ptr::null(),
                0,
                events.as_mut_ptr(),
                EVENT_BATCH as i32,
                &zero,
            )
        };
        let count = usize::try_from(count).map_err(|_| refused())?;
        if count > EVENT_BATCH {
            return Err(refused());
        }
        let mut observed = Vec::with_capacity(count);
        for event in &events[..count] {
            let id = WatchId {
                queue: self.owner_id,
                sequence: event.udata.addr() as u64,
            };
            let file = self.files.get(&id).ok_or_else(refused)?;
            let allowed_flags = libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR | libc::EV_RECEIPT;
            if event.filter != libc::EVFILT_VNODE
                || event.ident != file.as_raw_fd() as usize
                || event.flags & !allowed_flags != 0
                || event.fflags == 0
                || event.fflags & !VNODE_MASK != 0
                || event.data != 0
            {
                return Err(refused());
            }
            observed.push(id);
        }
        Ok(observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{Seek, SeekFrom, Write},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    struct Root(PathBuf);
    impl Root {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().canonicalize()?.join(format!(
                "heptabao-vnode-owner-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn file(root: &Root) -> io::Result<File> {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(root.0.join("leaf"))
    }

    #[test]
    fn vnode_real_events_and_receipted_removal_preserve_caller_file() -> TestResult {
        let root = Root::new()?;
        let mut file = file(&root)?;
        file.write_all(b"original-A")?;
        let mut queue = VnodeMutationQueue::new()?;
        let first = queue.register(&file)?;
        assert!(queue.poll()?.is_empty());
        file.seek(SeekFrom::Start(0))?;
        file.write_all(b"differentB")?;
        file.sync_all()?;
        assert_eq!(queue.poll()?, vec![first]);
        assert!(queue.poll()?.is_empty());
        queue.remove(first)?;
        assert!(queue.files.is_empty());
        assert_eq!(file.metadata()?.len(), 10); // caller's descriptor stays live
        let second = queue.register(&file)?;
        assert_ne!(first, second);
        assert!(queue.poll()?.is_empty());
        file.seek(SeekFrom::Start(0))?;
        file.write_all(b"original-A")?;
        assert_eq!(queue.poll()?, vec![second]);
        queue.remove(second)?;
        assert_eq!(fs::read(root.0.join("leaf"))?, b"original-A");
        Ok(())
    }

    #[test]
    fn vnode_ambiguous_removal_poison_closes_queue_before_owned_duplicates() -> TestResult {
        let root = Root::new()?;
        let file = file(&root)?;
        let mut queue = VnodeMutationQueue::new()?;
        let id = queue.register(&file)?;
        assert!(
            queue
                .remove(WatchId {
                    queue: id.queue,
                    sequence: id.sequence + 1
                })
                .is_err()
        );
        assert!(queue.queue.is_none());
        assert!(queue.files.is_empty());
        assert!(queue.poll().is_err());
        assert!(queue.register(&file).is_err());
        file.metadata()?; // poison never closes a borrowed caller descriptor
        Ok(())
    }

    #[test]
    fn vnode_watch_token_from_another_queue_cannot_remove_same_sequence() -> TestResult {
        let root = Root::new()?;
        let file = file(&root)?;
        let mut first = VnodeMutationQueue::new()?;
        let mut second = VnodeMutationQueue::new()?;
        let a = first.register(&file)?;
        let b = second.register(&file)?;
        assert_eq!(a.sequence, b.sequence);
        assert_ne!(a, b);
        assert!(second.remove(a).is_err());
        assert_eq!(second.files.len(), 1);
        assert!(second.queue.is_some());
        second.remove(b)?;
        first.remove(a)?;
        Ok(())
    }
}
