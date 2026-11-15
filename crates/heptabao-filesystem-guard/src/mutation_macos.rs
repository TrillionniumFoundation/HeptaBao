use super::{Observation, Removal, WatchId, refused};
use heptabao_darwin_vnode_events::{VnodeMutationQueue, WatchId as NativeWatchId};
use std::{fs::File, io};

const MAX_DRAIN_POLLS: usize = 64;
pub(super) struct Queue {
    native: VnodeMutationQueue,
}
pub(super) struct Registration {
    watch: NativeWatchId,
}
impl Registration {
    pub(super) fn id(&self) -> WatchId {
        self.watch.value()
    }
}
impl Queue {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            native: VnodeMutationQueue::new()?,
        })
    }
    pub(super) fn register(&mut self, file: &File) -> io::Result<Registration> {
        Ok(Registration {
            watch: self.native.register(file)?,
        })
    }
    pub(super) fn remove(&mut self, registration: &Registration) -> io::Result<Removal> {
        self.native.remove(registration.watch)?;
        Ok(Removal::Complete)
    }
    pub(super) fn drain(
        &mut self,
        observe: &mut impl FnMut(Observation) -> io::Result<()>,
    ) -> io::Result<()> {
        for _ in 0..MAX_DRAIN_POLLS {
            let events = self.native.poll()?;
            if events.is_empty() {
                return Ok(());
            }
            for watch in events {
                observe(Observation {
                    watch: watch.value(),
                    removed: false,
                })?;
            }
        }
        Err(refused())
    }
}
