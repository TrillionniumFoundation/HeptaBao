//! Private timing only. No payload, peer identity, key, nonce, or raw error is
//! retained. Fixed atomic buckets are reported once when their last observer
//! drops, including a real socket worker which outlives a cancelled collector.
//! The copied deadline is used only to observe remaining time, never to admit
//! work, refresh a clock, change a timeout, or construct any custody receipt.
use std::cell::RefCell;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static NEXT_OBSERVATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
pub(super) enum Phase {
    CollectorAdmission,
    SourcePreflight,
    FrameCapacity,
    FramePayload,
    WorkerQueue,
    ClientConnect,
    ClientHandshake,
    FrameWriteHeader,
    FrameWriteBody,
    FrameFlush,
    FrameReadHeader,
    FrameReadBody,
    ServerHandshake,
    ReceiverAdmission,
    ReceiverVerify,
    ReceiverOwnerLock,
    ReceiverEnsure,
    ReceiverBatchPrepare,
    ReceiverStorage,
    ReceiverStorageGate,
    ReceiverBatchPost,
    FinalizeManifest,
    ReplyVerify,
    FrameWait,
    FinalAdmission,
    FinalVerify,
}

const PHASE_NAMES: [&str; 26] = [
    "collector_admission",
    "source_preflight",
    "frame_capacity",
    "frame_payload",
    "worker_queue",
    "client_connect",
    "client_handshake",
    "frame_write_header",
    "frame_write_body",
    "frame_flush",
    "frame_read_header",
    "frame_read_body",
    "server_handshake",
    "receiver_admission",
    "receiver_verify",
    "receiver_owner_lock",
    "receiver_ensure",
    "receiver_batch_prepare",
    "receiver_storage_inclusive",
    "receiver_storage_gate",
    "receiver_batch_post",
    "finalize_manifest",
    "reply_verify",
    "frame_wait_inclusive",
    "final_admission",
    "final_verify",
];

#[derive(Debug)]
struct Bucket {
    calls: AtomicU64,
    failed: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
    bounded: AtomicU64,
    min_remaining_ns: AtomicU64,
}

impl Bucket {
    fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
            bounded: AtomicU64::new(0),
            min_remaining_ns: AtomicU64::new(u64::MAX),
        }
    }
}

#[derive(Debug)]
pub(super) struct Stats {
    observation: u64,
    side: &'static str,
    phases: [Bucket; PHASE_NAMES.len()],
    frames: [AtomicU64; 9],
    payload_bytes: [AtomicU64; 9],
}

impl Stats {
    pub(super) fn new(side: &'static str) -> Arc<Self> {
        Arc::new(Self {
            observation: NEXT_OBSERVATION.fetch_add(1, Ordering::Relaxed),
            side,
            phases: std::array::from_fn(|_| Bucket::new()),
            frames: std::array::from_fn(|_| AtomicU64::new(0)),
            payload_bytes: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }
}

impl Drop for Stats {
    fn drop(&mut self) {
        // Report only fixed labels and scalar observations. Logging failures
        // must not replace an original result or panic a peer owner on Drop.
        let mut out = std::io::stderr().lock();
        for (name, bucket) in PHASE_NAMES.iter().zip(&self.phases) {
            let calls = bucket.calls.load(Ordering::Relaxed);
            if calls == 0 {
                continue;
            }
            let bounded = bucket.bounded.load(Ordering::Relaxed);
            let remaining = if bounded == 0 {
                0
            } else {
                bucket.min_remaining_ns.load(Ordering::Relaxed)
            };
            let _ = writeln!(
                out,
                "HBHA-PRIVATE-CLOSURE-TIMING observation={} side={} phase={} calls={} failed={} total_ns={} max_ns={} bounded_calls={} min_original_remaining_ns={}",
                self.observation,
                self.side,
                name,
                calls,
                bucket.failed.load(Ordering::Relaxed),
                bucket.total_ns.load(Ordering::Relaxed),
                bucket.max_ns.load(Ordering::Relaxed),
                bounded,
                remaining,
            );
        }
        for kind in 0..self.frames.len() {
            let frames = self.frames[kind].load(Ordering::Relaxed);
            if frames != 0 {
                let _ = writeln!(
                    out,
                    "HBHA-PRIVATE-CLOSURE-FRAMES observation={} side={} kind={} frames={} payload_bytes={}",
                    self.observation,
                    self.side,
                    kind,
                    frames,
                    self.payload_bytes[kind].load(Ordering::Relaxed),
                );
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Context {
    stats: Arc<Stats>,
    deadline: Option<Instant>,
}

thread_local! {
    static CURRENT: RefCell<Option<Context>> = const { RefCell::new(None) };
}

pub(super) fn capture() -> Option<Context> {
    CURRENT.with(|slot| slot.borrow().clone())
}

#[derive(Debug)]
pub(super) struct Scope {
    previous: Option<Context>,
}

impl Scope {
    pub(super) fn enter(stats: Arc<Stats>, deadline: Option<Instant>) -> Self {
        Self::attach(Some(Context { stats, deadline }))
    }

    pub(super) fn attach(context: Option<Context>) -> Self {
        Self {
            previous: CURRENT.with(|slot| slot.replace(context)),
        }
    }

    pub(super) fn original_bound(deadline: Instant) -> Self {
        let mut context = capture();
        if let Some(context) = &mut context {
            context.deadline = Some(context.deadline.map_or(deadline, |old| old.min(deadline)));
        }
        Self::attach(context)
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let _ = CURRENT.try_with(|slot| slot.replace(previous));
    }
}

pub(super) fn frame(kind: u8, payload_bytes: usize) {
    if let Some(context) = capture() {
        let index = usize::from(kind).min(8);
        context.stats.frames[index].fetch_add(1, Ordering::Relaxed);
        context.stats.payload_bytes[index].fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub(super) struct Span {
    context: Context,
    phase: Phase,
    started: Instant,
    finished: bool,
}

impl Span {
    pub(super) fn start(phase: Phase) -> Option<Self> {
        Self::since(phase, Instant::now())
    }

    pub(super) fn since(phase: Phase, started: Instant) -> Option<Self> {
        capture().map(|context| Self {
            context,
            phase,
            started,
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
        if let Some(deadline) = self.context.deadline {
            bucket.bounded.fetch_add(1, Ordering::Relaxed);
            bucket.min_remaining_ns.fetch_min(
                nanos(deadline.saturating_duration_since(now).as_nanos()),
                Ordering::Relaxed,
            );
        }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if !self.finished {
            // An early original `?`, cancellation or panic cannot be counted
            // as a completed phase. This creates no new error or side effect.
            self.record(false);
        }
    }
}
