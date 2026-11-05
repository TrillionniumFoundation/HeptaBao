//! Share the bounded listener pool without starving consensus acknowledgements.
const RESERVED_CONSENSUS_WORKERS: usize = 2;

pub(super) struct PeerWorkerBudget {
    pub(super) workers: usize,
    pub(super) forwarding: usize,
}

impl PeerWorkerBudget {
    pub(super) fn for_limit(max_inflight: usize) -> Self {
        let workers = max_inflight.clamp(4, 16);
        Self {
            workers,
            forwarding: workers - RESERVED_CONSENSUS_WORKERS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[test]
    fn peer_worker_budget_admits_two_standbys_and_preserves_consensus_capacity() {
        let budget = PeerWorkerBudget::for_limit(32);
        let slots = Arc::new(Semaphore::new(budget.forwarding));
        let first = slots.clone().try_acquire_owned();
        let second = slots.clone().try_acquire_owned();
        assert!(first.is_ok());
        assert!(
            second.is_ok(),
            "two ordinary standbys must not contend for one forward slot"
        );
        assert!(budget.workers - budget.forwarding >= RESERVED_CONSENSUS_WORKERS);
    }

    #[test]
    fn peer_worker_budget_never_allocates_reserved_consensus_workers_to_forwarding() {
        for configured in [0, 1, 2, 3, 4, 5, 8, 16, 32, 64, 1024, usize::MAX] {
            let budget = PeerWorkerBudget::for_limit(configured);
            assert!((4..=16).contains(&budget.workers));
            assert_eq!(
                budget.forwarding,
                budget.workers - RESERVED_CONSENSUS_WORKERS
            );
            let slots = Arc::new(Semaphore::new(budget.forwarding));
            let held = (0..budget.forwarding)
                .map(|_| slots.clone().try_acquire_owned())
                .collect::<Vec<_>>();
            assert!(held.iter().all(Result::is_ok));
            assert!(slots.clone().try_acquire_owned().is_err());
            drop(held);
            assert_eq!(slots.available_permits(), budget.forwarding);
        }
    }
}
