//! Explicit candidate-only capacity for native ciphertext work and ReadIndex.
//! Each class can await consensus, so none may consume its reserved workers.
use super::*;

const NATIVE_WORKERS: usize = 2;
// One recovery may send four requests to each of two healthy donors. Every
// request obtains its own real ReadIndex, so the recovering leader reserves
// the complete global-eight fanout in addition to the original two read slots.
const ROOT_PULL_WORKERS: usize = heptabao_ha_service::NATIVE_V6_ROOT_PULL_REQUESTS_PER_DONOR;
const READ_INDEX_WORKERS: usize = 2 + heptabao_ha_service::NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES;

pub(super) struct NativePeerCapacity {
    pub(super) workers: usize,
    pub(super) native: Arc<Semaphore>,
    pub(super) root_pull: Arc<Semaphore>,
    pub(super) read_index: Arc<Semaphore>,
}

impl NativePeerCapacity {
    pub(super) fn for_budget(ordinary: &PeerWorkerBudget) -> Self {
        // The ordinary pool already reserves two consensus workers. Add real
        // threads for every permit class; merely adding semaphores would let
        // blocked handlers exhaust the same old shared worker pool. Root repair
        // cannot consume push, read or ordinary reserved consensus capacity.
        Self {
            workers: ordinary.workers + NATIVE_WORKERS + ROOT_PULL_WORKERS + READ_INDEX_WORKERS,
            native: Arc::new(Semaphore::new(NATIVE_WORKERS)),
            root_pull: Arc::new(Semaphore::new(ROOT_PULL_WORKERS)),
            read_index: Arc::new(Semaphore::new(READ_INDEX_WORKERS)),
        }
    }
}

#[cfg(test)]
#[path = "ha_native_v6_peer_capacity_tests.rs"]
mod tests;
