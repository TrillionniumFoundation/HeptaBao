//! Retained kernel events supplement the original metadata, contents, owner
//! and strong-sync checks. Linux inotify does not observe all mmap writes or
//! remote filesystem changes. A clean queue is NOT an inode generation.
use super::ExclusiveDirectory;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io,
    sync::{Arc, Mutex},
};

#[cfg(target_os = "linux")]
#[path = "mutation_linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "mutation_macos.rs"]
mod platform;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[path = "mutation_unsupported.rs"]
mod platform;

type WatchId = u64;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileIdentity {
    device: u64,
    inode: u64,
}
impl FileIdentity {
    fn read(file: &File) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(refused());
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Err(refused())
        }
    }
}
fn refused() -> io::Error {
    io::Error::other("immutable file mutation witness is unavailable or changed")
}

/// ONE queue per directory owner, shared by all outstanding inode witnesses.
/// Once poisoned the owner never replaces it with a new clean queue.
pub(crate) struct MutationMonitor {
    broker: Mutex<Option<Arc<Mutex<Broker>>>>,
}
impl MutationMonitor {
    pub(crate) fn new() -> Self {
        Self {
            broker: Mutex::new(None),
        }
    }
    fn acquire(&self, file: &File) -> io::Result<FileMutationWitness> {
        let identity = FileIdentity::read(file)?;
        let broker = {
            let mut owner = self.broker.lock().map_err(|_| refused())?;
            if owner.is_none() {
                *owner = Some(Arc::new(Mutex::new(Broker::new()?)));
            }
            owner.as_ref().ok_or_else(refused)?.clone()
        };
        let watch = {
            let mut state = broker.lock().map_err(|_| refused())?;
            state.acquire(file, identity)?
        };
        let witness = FileMutationWitness(Arc::new(Lease {
            broker,
            watch,
            identity,
        }));
        // Register before checking the original fd again; never adopt a later
        // pathname/metadata sample as the identity of the registered inode.
        witness.verify_file(file)?;
        Ok(witness)
    }
}
impl fmt::Debug for MutationMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MutationMonitor([OWNER_SCOPED_KERNEL_QUEUE])")
    }
}

/// Clones retain the SAME registration and latched failures. This alone is
/// neither a durability receipt nor authority to publish an application root.
#[derive(Clone)]
pub struct FileMutationWitness(Arc<Lease>);
impl fmt::Debug for FileMutationWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileMutationWitness([ORIGINAL_INODE_EVENT_REGISTRATION])")
    }
}
impl FileMutationWitness {
    /// Fully drain the nonblocking queue. Lost watches, overflow, malformed
    /// events, incomplete drains and earlier mutations all refuse admission.
    pub fn verify_file(&self, file: &File) -> io::Result<()> {
        if FileIdentity::read(file)? != self.0.identity {
            return Err(refused());
        }
        let mut state = self.0.broker.lock().map_err(|_| refused())?;
        state.drain()?;
        state.check(self.0.watch, self.0.identity)?;
        if FileIdentity::read(file)? != self.0.identity {
            return Err(refused());
        }
        // A write during the second identity observation cannot be left queued
        // while returning a clean observation to the application.
        state.drain()?;
        state.check(self.0.watch, self.0.identity)
    }
}
impl ExclusiveDirectory {
    /// Start before the original full read and synchronization. The caller
    /// retains every name/owner gate; no original-path fallback is attempted.
    pub fn watch_file_mutations(&self, file: &File) -> io::Result<FileMutationWitness> {
        self.verify().map_err(io::Error::other)?;
        let witness = self.mutation_monitor.acquire(file)?;
        self.verify().map_err(io::Error::other)?;
        Ok(witness)
    }
}
struct Lease {
    broker: Arc<Mutex<Broker>>,
    watch: WatchId,
    identity: FileIdentity,
}
impl Drop for Lease {
    fn drop(&mut self) {
        // Only our kernel registration is removed; no file/writer is changed.
        if let Ok(mut state) = self.broker.lock() {
            state.release(self.watch, self.identity);
        }
    }
}
struct Entry {
    identity: FileIdentity,
    leases: usize,
    changed: bool,
    registered: bool,
    registration: platform::Registration,
}
struct Broker {
    queue: platform::Queue,
    by_inode: BTreeMap<FileIdentity, WatchId>,
    entries: BTreeMap<WatchId, Entry>,
    poisoned: bool,
}
struct Observation {
    watch: WatchId,
    removed: bool,
}
enum Removal {
    #[cfg(not(target_os = "linux"))]
    Complete,
    #[cfg(target_os = "linux")]
    AwaitIgnored,
}

impl Broker {
    fn new() -> io::Result<Self> {
        Ok(Self {
            queue: platform::Queue::new()?,
            by_inode: BTreeMap::new(),
            entries: BTreeMap::new(),
            poisoned: false,
        })
    }
    fn drain(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(refused());
        }
        let entries = &mut self.entries;
        let result = self.queue.drain(&mut |event| {
            let entry = entries.get_mut(&event.watch).ok_or_else(refused)?;
            // Every subscribed event invalidates the original observation.
            // Coalescing is harmless; no timestamp or event count is needed.
            entry.changed = true;
            if event.removed {
                entry.registered = false;
                if entry.leases == 0 {
                    entries.remove(&event.watch);
                }
            }
            Ok(())
        });
        if result.is_err() {
            // Lost/unparseable data can hide mutations for any active entry.
            self.poisoned = true;
            return Err(refused());
        }
        Ok(())
    }
    fn check(&self, watch: WatchId, identity: FileIdentity) -> io::Result<()> {
        let entry = self.entries.get(&watch).ok_or_else(refused)?;
        if self.poisoned
            || entry.identity != identity
            || entry.leases == 0
            || entry.changed
            || !entry.registered
        {
            return Err(refused());
        }
        Ok(())
    }
    fn acquire(&mut self, file: &File, identity: FileIdentity) -> io::Result<WatchId> {
        self.drain()?;
        if let Some(watch) = self.by_inode.get(&identity).copied() {
            self.check(watch, identity)?;
            let entry = self.entries.get_mut(&watch).ok_or_else(refused)?;
            entry.leases = entry.leases.checked_add(1).ok_or_else(refused)?;
            return Ok(watch);
        }
        let registration = match self.queue.register(file) {
            Ok(registration) => registration,
            Err(_) => {
                self.poisoned = true;
                return Err(refused());
            }
        };
        let watch = registration.id();
        if self.entries.contains_key(&watch) {
            // Includes an inotify id still awaiting its previous IN_IGNORED.
            // Never relabel an old queued event as belonging to a fresh inode.
            self.poisoned = true;
            return Err(refused());
        }
        self.entries.insert(
            watch,
            Entry {
                identity,
                leases: 1,
                changed: false,
                registered: true,
                registration,
            },
        );
        self.by_inode.insert(identity, watch);
        Ok(watch)
    }
    fn release(&mut self, watch: WatchId, identity: FileIdentity) {
        // A delete/unmount may already have removed this watch in the kernel.
        // Consume its owned IN_IGNORED before deciding whether rm_watch applies.
        let _ = self.drain();
        let Some(entry) = self.entries.get_mut(&watch) else {
            self.poisoned = true;
            return;
        };
        if entry.identity != identity || entry.leases == 0 {
            self.poisoned = true;
            return;
        }
        entry.leases -= 1;
        if entry.leases != 0 {
            return;
        }
        self.by_inode.remove(&identity);
        if !entry.registered {
            self.entries.remove(&watch);
            return;
        }
        match self.queue.remove(&entry.registration) {
            #[cfg(not(target_os = "linux"))]
            Ok(Removal::Complete) => {
                self.entries.remove(&watch);
            }
            #[cfg(target_os = "linux")]
            Ok(Removal::AwaitIgnored) => {
                // Reserve the old id until its kernel removal is consumed.
                // The next acquisition must finish a complete drain as well.
                let _ = self.drain();
            }
            Err(_) => {
                self.poisoned = true;
            }
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "mutation_tests.rs"]
mod tests;
