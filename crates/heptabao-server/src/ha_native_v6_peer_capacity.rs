//! Explicit candidate-only capacity for native ciphertext work and ReadIndex.
//! Each class can await consensus, so none may consume its reserved workers.
use super::*;

const NATIVE_WORKERS: usize = 2;
const READ_INDEX_WORKERS: usize = 2;

pub(super) struct NativePeerCapacity {
    pub(super) workers: usize,
    pub(super) native: Arc<Semaphore>,
    pub(super) read_index: Arc<Semaphore>,
}

impl NativePeerCapacity {
    pub(super) fn for_budget(ordinary: &PeerWorkerBudget) -> Self {
        // The ordinary pool already reserves two consensus workers. Add real
        // threads for BOTH new permit classes; merely adding semaphores would
        // let blocked handlers exhaust the same old shared worker pool.
        Self {
            workers: ordinary.workers + NATIVE_WORKERS + READ_INDEX_WORKERS,
            native: Arc::new(Semaphore::new(NATIVE_WORKERS)),
            read_index: Arc::new(Semaphore::new(READ_INDEX_WORKERS)),
        }
    }
}

#[cfg(test)]
#[path = "ha_native_v6_peer_capacity_tests.rs"]
mod tests;
