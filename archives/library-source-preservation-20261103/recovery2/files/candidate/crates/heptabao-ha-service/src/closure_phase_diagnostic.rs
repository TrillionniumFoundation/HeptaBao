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

// Diagnostic-only observation AFTER an original operation returned Err.
// The active collector context already crosses into this owned socket worker.
// Numeric target/kind and HaError's fieldless variant bind the failure without
// logging any nonce, intent/object digest, ciphertext, credential or path.
// Cancellation is sampled here; it does not assert an earlier event order.
pub(super) fn failed_peer_return(
    phase: &'static str,
    target: u64,
    kind: u8,
    error: crate::HaError,
    deadline: Instant,
    cancelled: bool,
) {
    let Some(context) = capture() else {
        return;
    };
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_nanos();
    let _ = writeln!(
        std::io::stderr().lock(),
        "HBHA-PRIVATE-PEER-RETURN observation={} side={} phase={} target={} kind={} error={:?} cancelled_at_observation={} original_remaining_ns={}",
        context.stats.observation,
        context.stats.side,
        phase,
        target,
        kind,
        error,
        cancelled,
        remaining,
    );
}

// Test-owned request association for the fixed missing-only fixture. Nothing
// here supplies admission, deadlines, a reply, a retry, or a storage witness.
// The operation digest is classified in memory; only seven authored cases,
// a per-receiver request ordinal and fixed scalar fields are printed.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct MissingOnlyRequest {
    request: u64,
    case: u8,
    target: u64,
    kind: u8,
}

#[cfg(test)]
impl MissingOnlyRequest {
    pub(super) fn new(request: u64, operation: &[u8; 32], target: u64, kind: u8) -> Self {
        let case = [
            (1, 0x71_u8),
            (2, 0x72),
            (3, 0x73),
            (4, 0x77),
            (5, 0x74),
            (6, 0x75),
            (7, 0x76),
        ]
        .into_iter()
        .find_map(|(case, tag)| (*operation == [tag; 32]).then_some(case))
        .unwrap_or(0);
        Self {
            request,
            case,
            target,
            kind,
        }
    }

    pub(super) fn event(
        self,
        event: &'static str,
        error: Option<crate::HaError>,
        fault: Option<u64>,
    ) {
        let error = error.map_or_else(|| "none".to_owned(), |error| format!("{error:?}"));
        let fault = fault.map_or_else(|| "none".to_owned(), |fault| fault.to_string());
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-MISSING-RECEIVER request={} case={} target={} kind={} event={} error={} fault={}",
            self.request,
            self.case,
            self.target,
            self.kind,
            event,
            error,
            fault
        );
    }
}

#[cfg(test)]
thread_local! {
    static MISSING_ONLY_REQUEST: RefCell<Option<MissingOnlyRequest>> = const { RefCell::new(None) };
}

#[cfg(test)]
pub(super) struct MissingOnlyScope(Option<MissingOnlyRequest>);

#[cfg(test)]
impl MissingOnlyScope {
    pub(super) fn enter(request: MissingOnlyRequest) -> Self {
        Self(MISSING_ONLY_REQUEST.with(|slot| slot.replace(Some(request))))
    }
}

#[cfg(test)]
impl Drop for MissingOnlyScope {
    fn drop(&mut self) {
        MISSING_ONLY_REQUEST.with(|slot| {
            slot.replace(self.0);
        });
    }
}

// Test-only association for the original live local receiver. A fresh serve
// slot prevents accept/parse failures from inheriting the previous request.
// Only the existing parsed operation is classified; no frame is parsed twice.
#[cfg(test)]
thread_local! {
    static MISSING_ONLY_LIVE_SERVE: std::cell::Cell<Option<Option<MissingOnlyRequest>>> = const { std::cell::Cell::new(None) };
    static MISSING_ONLY_LIVE_SEQUENCE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) struct MissingOnlyLiveServe(Option<Option<MissingOnlyRequest>>);

#[cfg(test)]
impl MissingOnlyLiveServe {
    pub(super) fn enter() -> Self {
        Self(MISSING_ONLY_LIVE_SERVE.with(|slot| slot.replace(Some(None))))
    }

    pub(super) fn event(&self, event: &'static str, error: Option<crate::HaError>) {
        if let Some(request) = MISSING_ONLY_LIVE_SERVE.with(|slot| slot.get().flatten()) {
            request.event(event, error, None);
        }
    }
}

#[cfg(test)]
impl Drop for MissingOnlyLiveServe {
    fn drop(&mut self) {
        MISSING_ONLY_LIVE_SERVE.with(|slot| slot.set(self.0));
    }
}

#[cfg(test)]
pub(super) fn missing_only_live_parsed(
    operation: &[u8; 32],
    target: u64,
    kind: u8,
) -> Option<MissingOnlyScope> {
    if target != 1
        || MISSING_ONLY_REQUEST.with(|slot| slot.borrow().is_some())
        || !MISSING_ONLY_LIVE_SERVE.with(|slot| matches!(slot.get(), Some(None)))
    {
        return None;
    }
    let mut request = MissingOnlyRequest::new(0, operation, target, kind);
    if request.case == 0 {
        return None;
    }
    request.request = MISSING_ONLY_LIVE_SEQUENCE.with(|slot| {
        let next = slot.get().checked_add(1);
        if let Some(next) = next {
            slot.set(next);
        }
        next.unwrap_or(0)
    });
    // Ordinal zero is only an overflow diagnostic rejected by the parser;
    // it does not replace any original product Result or invoke a new gate.
    MISSING_ONLY_LIVE_SERVE.with(|slot| slot.set(Some(Some(request))));
    request.event("enter", None, None);
    Some(MissingOnlyScope::enter(request))
}

#[cfg(test)]
pub(super) fn missing_only_failure_phase(phase: &'static str, deadline: Instant) {
    let request = MISSING_ONLY_REQUEST.with(|slot| *slot.borrow());
    if let Some(request) = request {
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-MISSING-RECEIVER-PHASE request={} case={} target={} kind={} phase={} original_remaining_ns={}",
            request.request,
            request.case,
            request.target,
            request.kind,
            phase,
            deadline
                .saturating_duration_since(Instant::now())
                .as_nanos()
        );
    }
}

#[cfg(test)]
pub(super) fn missing_only_binding_rejection(present: bool, equal: bool) {
    let request = MISSING_ONLY_REQUEST.with(|slot| *slot.borrow());
    if let Some(request) = request {
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-MISSING-RECEIVER-BINDING request={} case={} target={} kind={} incoming_present={} binding_equal={}",
            request.request,
            request.case,
            request.target,
            request.kind,
            present,
            equal
        );
    }
}

// One fixed projection AFTER the existing Ensure helper returned Err. Count
// only its original admission callbacks; never call a gate, retry I/O, rebase
// a mutation witness, replace an error, or expose a raw error/string/path.
#[cfg(test)]
pub(super) fn missing_only_storage_error(
    deadline: Instant,
    objects: usize,
    gate_calls: u64,
    gate_passed: u64,
    counter_overflow: bool,
    error: &heptabao_raft_runtime::LocalV6BlobError,
) {
    use heptabao_raft_runtime::LocalV6BlobError;
    let request = MISSING_ONLY_REQUEST.with(|slot| *slot.borrow());
    if let Some(request) = request {
        let error_class = match error {
            LocalV6BlobError::InvalidCiphertext => "InvalidCiphertext",
            LocalV6BlobError::InvalidClosure => "InvalidClosure",
            LocalV6BlobError::InvalidRoot => "InvalidRoot",
            LocalV6BlobError::CorruptOrChanged => "CorruptOrChanged",
            LocalV6BlobError::Guard(_) => "Guard",
            LocalV6BlobError::Io(_) => "Io",
            LocalV6BlobError::Publication(_) => "Publication",
        };
        // This is ONLY the direct Io variant. Wrapped Guard/Publication
        // internals are not guessed, formatted, traversed, or unwrapped.
        let (io_kind, errno) = match error {
            LocalV6BlobError::Io(error) => {
                use std::io::ErrorKind;
                let kind = match error.kind() {
                    ErrorKind::NotFound => "not_found",
                    ErrorKind::PermissionDenied => "permission_denied",
                    ErrorKind::AlreadyExists => "already_exists",
                    ErrorKind::WouldBlock => "would_block",
                    ErrorKind::InvalidInput => "invalid_input",
                    ErrorKind::InvalidData => "invalid_data",
                    ErrorKind::TimedOut => "timed_out",
                    ErrorKind::WriteZero => "write_zero",
                    ErrorKind::Interrupted => "interrupted",
                    ErrorKind::Unsupported => "unsupported",
                    ErrorKind::UnexpectedEof => "unexpected_eof",
                    ErrorKind::OutOfMemory => "out_of_memory",
                    ErrorKind::Other => "other",
                    _ => "other_kind",
                };
                (kind, error.raw_os_error())
            }
            _ => ("none", None),
        };
        let errno = errno.map_or_else(|| "none".to_owned(), |code| code.to_string());
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-MISSING-RECEIVER-STORAGE-ERROR request={} case={} target={} kind={} stage=ensure_sync_existing_batch objects={} gate_calls={} gate_passed={} gate_failed={} counter_overflow={} error={} io_kind={} errno={} original_remaining_ns={}",
            request.request,
            request.case,
            request.target,
            request.kind,
            objects,
            gate_calls,
            gate_passed,
            gate_calls != gate_passed,
            counter_overflow,
            error_class,
            io_kind,
            errno,
            deadline
                .saturating_duration_since(Instant::now())
                .as_nanos(),
        );
    }
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
