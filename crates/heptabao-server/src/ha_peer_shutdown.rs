//! A single process-owned shutdown supervisor, used only when the last
//! HaProcess owner is released by one of its own peer workers. It owns the
//! original handles and runtime dependencies; queued work is never detached.
use super::*;
use std::collections::VecDeque;
use std::sync::{Condvar, OnceLock, PoisonError};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct WorkerJoinSummary {
    pub(super) joined: usize,
    pub(super) panicked: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeShutdown {
    Absent,
    Shared,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerNodeShutdownSummary {
    workers: WorkerJoinSummary,
    node: NodeShutdown,
}

// A peer/node completion observation. Runtime lifetime is separately owned
// and remains ordered after all peers and node shutdown; this type does not
// represent final Runtime destruction or whole-process shutdown.
#[derive(Default)]
pub(super) struct PeerNodeShutdownReceipt {
    terminal: Mutex<Option<PeerNodeShutdownSummary>>,
    changed: Condvar,
}
impl PeerNodeShutdownReceipt {
    fn complete(&self, summary: PeerNodeShutdownSummary) {
        if summary.workers.panicked != 0 || summary.node == NodeShutdown::Failed {
            let _ = writeln!(
                std::io::stderr().lock(),
                "HBHA-PEER-SHUTDOWN joined={} worker_panics={} node_shutdown_failed={}",
                summary.workers.joined,
                summary.workers.panicked,
                summary.node == NodeShutdown::Failed,
            );
        }
        *self.terminal.lock().unwrap_or_else(PoisonError::into_inner) = Some(summary);
        self.changed.notify_all();
    }
}

pub(super) struct OwnedHaShutdown {
    pub(super) listener: Option<PeerListener>,
    #[cfg(feature = "native-v6-ha")]
    pub(super) native_v6: Option<Arc<native_v6_runtime::NativeV6Runtime>>,
    pub(super) node: Option<Arc<ProcessRaftNode>>,
    pub(super) runtime: Arc<Runtime>,
    pub(super) receipt: Arc<PeerNodeShutdownReceipt>,
}
impl OwnedHaShutdown {
    pub(super) fn complete(mut self) {
        let workers = self
            .listener
            .as_mut()
            .map_or_else(WorkerJoinSummary::default, PeerListener::stop_and_join);
        // No worker is now able to retain a borrowed Runtime handle or run a
        // native closure. Keep the original listener -> native -> node ->
        // Runtime destruction order, including the actual node shutdown wait.
        drop(self.listener.take());
        #[cfg(feature = "native-v6-ha")]
        drop(self.native_v6.take());
        let node = match self.node.take() {
            None => NodeShutdown::Absent,
            Some(node) => match Arc::try_unwrap(node) {
                Err(_) => NodeShutdown::Shared,
                Ok(node) => match self.runtime.block_on(node.shutdown()) {
                    Ok(()) => NodeShutdown::Completed,
                    Err(_) => NodeShutdown::Failed,
                },
            },
        };
        let Self {
            runtime, receipt, ..
        } = self;
        drop(runtime);
        // The receipt observes all original peer joins and the node shutdown
        // result only. It is not a claim that every Runtime Arc was destroyed:
        // normal HaProcess::drop still owns its original Arc until its fields
        // drop after this call. The deferred self-worker path cannot complete
        // its joins until that original owner and worker have already exited.
        receipt.complete(PeerNodeShutdownSummary { workers, node });
    }
}

#[derive(Default)]
struct ShutdownQueue {
    pending: Mutex<VecDeque<OwnedHaShutdown>>,
    ready: Condvar,
}

pub(super) struct PeerShutdownSupervisor {
    queue: Arc<ShutdownQueue>,
    // The process-lifetime owner retains this one supervisor handle. It is
    // never a peer, never calls Service and never waits with the queue locked.
    _worker: JoinHandle<()>,
}
impl PeerShutdownSupervisor {
    pub(super) fn global() -> Result<&'static Self, String> {
        static SUPERVISOR: OnceLock<Result<PeerShutdownSupervisor, &'static str>> = OnceLock::new();
        match SUPERVISOR.get_or_init(Self::start) {
            Ok(owner) => Ok(owner),
            Err(error) => Err((*error).to_owned()),
        }
    }

    fn start() -> Result<Self, &'static str> {
        let queue = Arc::new(ShutdownQueue::default());
        let worker_queue = Arc::clone(&queue);
        let worker = thread::Builder::new()
            .name("heptabao-ha-shutdown".into())
            .spawn(move || {
                loop {
                    let next = {
                        let mut pending = worker_queue
                            .pending
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner);
                        while pending.is_empty() {
                            pending = worker_queue
                                .ready
                                .wait(pending)
                                .unwrap_or_else(PoisonError::into_inner);
                        }
                        pending.pop_front()
                    };
                    if let Some(shutdown) = next {
                        shutdown.complete();
                    }
                }
            })
            .map_err(|_| "cannot start owned HA shutdown supervisor")?;
        Ok(Self {
            queue,
            _worker: worker,
        })
    }

    pub(super) fn defer(&self, shutdown: OwnedHaShutdown) {
        // There is no fallible channel send which could discard the batch. The
        // queue owns only already-created process resources, with one batch per
        // final HaProcess drop; it creates no peer or background request work.
        self.queue
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(shutdown);
        self.queue.ready.notify_one();
    }
}

#[cfg(test)]
#[path = "ha_peer_shutdown_tests.rs"]
mod tests;

// Explicit finite maintenance owners need the existing shutdown observation,
// not a new stopping protocol. Drop still owns the original worker joins,
// native store release and actual Raft node shutdown in exactly that order.
#[cfg(feature = "native-v6-ha")]
impl HaProcess {
    pub(crate) fn close_owned_native(self) -> Result<usize, &'static str> {
        if self.native_v6.is_none() {
            return Err("native maintenance owner is absent");
        }
        let listener = self
            .listener
            .as_ref()
            .ok_or("native peer listener is absent")?;
        if listener.owns_current_worker() {
            return Err("maintenance shutdown cannot run on its own peer worker");
        }
        let receipt = Arc::clone(&listener.shutdown_receipt);
        drop(self);
        let summary = (*receipt
            .terminal
            .lock()
            .map_err(|_| "peer shutdown observation poisoned")?)
        .ok_or("peer shutdown observation incomplete")?;
        if summary.workers.panicked != 0 || summary.node != NodeShutdown::Completed {
            return Err("original peer or Raft node shutdown did not complete cleanly");
        }
        Ok(summary.workers.joined)
    }
}
