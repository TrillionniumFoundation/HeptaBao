//! Fixed, payload-free observations for a single committed-root pull scope.
//! A scope is entered only on the synchronous blocking controller. Socket
//! futures carry an explicit cloned Context; no thread-local guard crosses an
//! await. The copied original deadline only measures remaining time. Nothing
//! here grants a witness, changes a budget, retries a peer or controls I/O.
#![cfg_attr(not(feature = "private-forward-stage-diagnostic"), allow(dead_code))]

use std::cell::RefCell;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static NEXT_OBSERVATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Side {
    Consumer,
    Donor,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Phase {
    ReadOrRecover,
    ReadExisting,
    ExistingReopen,
    Recover,
    RecoveryReopen,
    ReadIndex,
    WitnessVerify,
    AvailableObjects,
    AvailableRead,
    ExistingSyncBatch,
    FrameCapacity,
    FrameExchange,
    ReplyVerify,
    ControllerWait,
    ReadyBatch,
    FinishLocal,
    FinishRead,
    PersistClosure,
    DonorRequest,
    DonorReopen,
    DonorObjectRead,
}

const PHASE_NAMES: [&str; 21] = [
    "read_or_recover_inclusive",
    "read_existing_inclusive",
    "existing_reopen_inclusive",
    "recover_inclusive",
    "recovery_reopen_inclusive",
    "read_index",
    "witness_verify",
    "available_objects_inclusive",
    "available_read_inclusive",
    "existing_sync_batch_inclusive",
    "frame_capacity",
    "frame_exchange_inclusive",
    "reply_verify",
    "controller_wait_inclusive",
    "ready_batch_inclusive",
    "finish_local_inclusive",
    "finish_read",
    "persist_closure_inclusive",
    "donor_request_inclusive",
    "donor_reopen_inclusive",
    "donor_object_read_inclusive",
];

#[derive(Clone, Copy, Debug)]
pub(super) enum Counter {
    Available,
    Missing,
    ManifestReply,
    ObjectReply,
    DuplicateObject,
    PersistedReady,
    RetiredTasks,
    CancelledTasks,
}

const COUNTER_NAMES: [&str; 8] = [
    "available_objects",
    "missing_objects",
    "manifest_replies",
    "object_replies",
    "duplicate_objects",
    "persisted_ready_objects",
    "retired_socket_tasks",
    "cancelled_socket_tasks",
];

#[derive(Debug)]
struct Bucket {
    calls: AtomicU64,
    failed: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
    min_remaining_ns: AtomicU64,
}

impl Bucket {
    fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
            min_remaining_ns: AtomicU64::new(u64::MAX),
        }
    }
}

#[derive(Debug)]
struct Stats {
    observation: u64,
    side: Side,
    phases: [Bucket; PHASE_NAMES.len()],
    counts: [AtomicU64; COUNTER_NAMES.len()],
    bytes: [AtomicU64; COUNTER_NAMES.len()],
}

impl Stats {
    fn new(side: Side) -> Arc<Self> {
        Arc::new(Self {
            observation: NEXT_OBSERVATION.fetch_add(1, Ordering::Relaxed),
            side,
            phases: std::array::from_fn(|_| Bucket::new()),
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            bytes: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }
}

impl Drop for Stats {
    fn drop(&mut self) {
        // Final observer Drop emits at most 21 phase and 8 counter rows. No
        // payload, root/peer identifier, key, path or raw error is retained.
        let side = match self.side {
            Side::Consumer => "consumer",
            Side::Donor => "donor",
        };
        let mut out = std::io::stderr().lock();
        for (name, bucket) in PHASE_NAMES.iter().zip(&self.phases) {
            let calls = bucket.calls.load(Ordering::Relaxed);
            if calls == 0 {
                continue;
            }
            let _ = writeln!(
                out,
                "HBHA-PRIVATE-ROOT-PULL-TIMING observation={} side={} phase={} calls={} failed={} total_ns={} max_ns={} min_original_remaining_ns={}",
                self.observation,
                side,
                name,
                calls,
                bucket.failed.load(Ordering::Relaxed),
                bucket.total_ns.load(Ordering::Relaxed),
                bucket.max_ns.load(Ordering::Relaxed),
                bucket.min_remaining_ns.load(Ordering::Relaxed)
            );
        }
        for (index, name) in COUNTER_NAMES.iter().enumerate() {
            let count = self.counts[index].load(Ordering::Relaxed);
            if count != 0 {
                let _ = writeln!(
                    out,
                    "HBHA-PRIVATE-ROOT-PULL-COUNTS observation={} side={} kind={} count={} bytes={}",
                    self.observation,
                    side,
                    name,
                    count,
                    self.bytes[index].load(Ordering::Relaxed)
                );
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Context {
    stats: Arc<Stats>,
    deadline: Instant,
}

thread_local! {
    static CURRENT: RefCell<Option<Context>> = const { RefCell::new(None) };
}

pub(super) fn capture() -> Option<Context> {
    CURRENT.with(|slot| slot.borrow().clone())
}

pub(super) struct Scope {
    previous: Option<Context>,
}

impl Scope {
    pub(super) fn enter(side: Side, deadline: Instant) -> Self {
        let context = match capture().filter(|context| context.stats.side == side) {
            Some(mut context) => {
                context.deadline = context.deadline.min(deadline);
                context
            }
            None => Context {
                stats: Stats::new(side),
                deadline,
            },
        };
        Self {
            previous: CURRENT.with(|slot| slot.replace(Some(context))),
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let _ = CURRENT.try_with(|slot| slot.replace(previous));
    }
}

pub(super) fn count(kind: Counter, count: u64, bytes: u64) {
    if let Some(context) = capture() {
        context.stats.counts[kind as usize].fetch_add(count, Ordering::Relaxed);
        context.stats.bytes[kind as usize].fetch_add(bytes, Ordering::Relaxed);
    }
}

pub(super) struct Span {
    context: Context,
    phase: Phase,
    started: Instant,
    finished: bool,
}

impl Span {
    pub(super) fn start(phase: Phase) -> Option<Self> {
        Self::from_context(capture(), phase)
    }

    pub(super) fn from_context(context: Option<Context>, phase: Phase) -> Option<Self> {
        context.map(|context| Self {
            context,
            phase,
            started: Instant::now(),
            finished: false,
        })
    }

    pub(super) fn finish(mut self, passed: bool) {
        self.record(passed);
        self.finished = true;
    }

    fn record(&self, passed: bool) {
        let now = Instant::now();
        let nanos = |value: u128| u64::try_from(value).unwrap_or(u64::MAX);
        let elapsed = nanos(now.saturating_duration_since(self.started).as_nanos());
        let bucket = &self.context.stats.phases[self.phase as usize];
        bucket.calls.fetch_add(1, Ordering::Relaxed);
        bucket
            .failed
            .fetch_add(u64::from(!passed), Ordering::Relaxed);
        bucket.total_ns.fetch_add(elapsed, Ordering::Relaxed);
        bucket.max_ns.fetch_max(elapsed, Ordering::Relaxed);
        bucket.min_remaining_ns.fetch_min(
            nanos(
                self.context
                    .deadline
                    .saturating_duration_since(now)
                    .as_nanos(),
            ),
            Ordering::Relaxed,
        );
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if !self.finished {
            self.record(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn nested_consumer_stages_share_one_observation_without_extending_deadline() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let _scope = Scope::enter(Side::Consumer, deadline);
        let first = capture().unwrap();
        {
            let _nested = Scope::enter(Side::Consumer, deadline + Duration::from_secs(30));
            let nested = capture().unwrap();
            assert!(Arc::ptr_eq(&first.stats, &nested.stats));
            assert_eq!(nested.deadline, deadline);
            Span::start(Phase::ExistingReopen).unwrap().finish(false);
        }
        Span::start(Phase::RecoveryReopen).unwrap().finish(true);
        assert_eq!(
            first.stats.phases[Phase::ExistingReopen as usize]
                .failed
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            first.stats.phases[Phase::RecoveryReopen as usize]
                .failed
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn explicit_socket_context_is_retained_without_thread_local_authority() {
        let _scope = Scope::enter(Side::Consumer, Instant::now() + Duration::from_secs(5));
        let original = capture().unwrap();
        let worker = original.clone();
        std::thread::spawn(move || {
            assert!(capture().is_none());
            Span::from_context(Some(worker), Phase::FrameExchange)
                .unwrap()
                .finish(true);
            assert!(capture().is_none());
        })
        .join()
        .unwrap();
        assert_eq!(
            original.stats.phases[Phase::FrameExchange as usize]
                .calls
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            original.stats.phases[Phase::FrameExchange as usize]
                .failed
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn early_drop_is_failed_and_an_expired_original_deadline_stays_zero() {
        let _scope = Scope::enter(Side::Consumer, Instant::now() - Duration::from_secs(1));
        let context = capture().unwrap();
        drop(Span::start(Phase::ReadyBatch));
        let bucket = &context.stats.phases[Phase::ReadyBatch as usize];
        assert_eq!(bucket.calls.load(Ordering::Relaxed), 1);
        assert_eq!(bucket.failed.load(Ordering::Relaxed), 1);
        assert_eq!(bucket.min_remaining_ns.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn separate_donor_scope_restores_consumer_and_keeps_scalar_counts_separate() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let _scope = Scope::enter(Side::Consumer, deadline);
        let consumer = capture().unwrap();
        count(Counter::Available, 3, 1024);
        {
            let _donor = Scope::enter(Side::Donor, deadline);
            let donor = capture().unwrap();
            assert!(!Arc::ptr_eq(&consumer.stats, &donor.stats));
            count(Counter::ManifestReply, 1, 32);
            assert_eq!(
                donor.stats.counts[Counter::Available as usize].load(Ordering::Relaxed),
                0
            );
        }
        assert!(Arc::ptr_eq(&consumer.stats, &capture().unwrap().stats));
        assert_eq!(
            consumer.stats.counts[Counter::Available as usize].load(Ordering::Relaxed),
            3
        );
        assert_eq!(
            consumer.stats.bytes[Counter::Available as usize].load(Ordering::Relaxed),
            1024
        );
    }
}
