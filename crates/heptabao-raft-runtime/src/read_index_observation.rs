//! Opt-in, payload-free ReadIndex observations. These values are diagnostics,
//! never read capabilities. Only follower_read creates successful events.
//! HB_READ_INDEX_OBSERVATION_V1 is a deployment-owned 32-lower-hex launch ID.
//! Normal CLI startup initializes a private, create-new log before listening.
//! Requests only enqueue bounded records; missing/lost records never qualify.
use crate::state_machine::TypeConfig;
use openraft::type_config::alias::LogIdOf;
use serde::Serialize;
use std::cell::RefCell;
use std::fs::File;
use std::future::Future;
use std::io::Write;
use std::marker::PhantomData;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};
use std::time::Instant;

pub const MAX_EVENTS: usize = 64;
pub const MAX_RECORD_BYTES: usize = 32 * 1024;
const MAX_RECORDS: u64 = 4096;
const MAX_OUTPUT_BYTES: u64 = 32 * 1024 * 1024;
const QUEUE_RECORDS: usize = 64;
const LOG_PREFIX: &str = "HBHA-READ-OBSERVATION ";
const ENVIRONMENT_KEY: &str = "HB_READ_INDEX_OBSERVATION_V1";

#[derive(Default)]
struct SinkHealth {
    lost: AtomicU64,
    failed: AtomicBool,
}
struct Sink {
    launch_id: String,
    sender: mpsc::SyncSender<String>,
    health: Arc<SinkHealth>,
    records: AtomicU64,
    bytes: AtomicU64,
}
static SINK: OnceLock<Result<Option<Sink>, &'static str>> = OnceLock::new();

fn valid_launch(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Invoke only at normal process startup, before any peer or HTTP listener.
// No file creation, environment lookup, thread creation, or filesystem wait
// is hidden in a request's first observation. An absent key leaves output off.
pub fn initialize_from_environment() -> Result<(), &'static str> {
    match SINK.get_or_init(|| {
        let launch_id = match std::env::var(ENVIRONMENT_KEY) {
            Ok(value) if valid_launch(&value) => value,
            Ok(_) | Err(std::env::VarError::NotUnicode(_)) => {
                return Err("invalid ReadIndex observation launch identity");
            }
            Err(std::env::VarError::NotPresent) => return Ok(None),
        };
        start_sink(&launch_id, Path::new(".")).map(Some)
    }) {
        Ok(_) => Ok(()),
        Err(reason) => Err(reason),
    }
}
#[derive(Serialize)]
struct FileIdentity {
    cwd_device: u64,
    cwd_inode: u64,
    file_device: u64,
    file_inode: u64,
    file_uid: u32,
    file_mode: u32,
    file_nlink: u64,
}
#[cfg(unix)]
fn create_private_file(
    launch_id: &str,
    directory: &Path,
) -> Result<(File, FileIdentity), &'static str> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !valid_launch(launch_id) {
        return Err("invalid ReadIndex observation launch identity");
    }
    // Production supplies ".". Its kernel-owned cwd reference cannot be
    // redirected by replacing a parent path between these operations.
    let before = std::fs::symlink_metadata(directory)
        .map_err(|_| "cannot inspect ReadIndex observation directory")?;
    if !before.is_dir() || before.file_type().is_symlink() || before.mode() & 0o7777 != 0o700 {
        return Err("ReadIndex observation directory must be private");
    }
    let path = directory.join(format!("read-index-observation-{launch_id}.log"));
    // create_new rejects every pre-existing object, including a symlink or a
    // hard link; there is no append, truncation, inherited path or fd2 access.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| "cannot create private ReadIndex observation log")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect ReadIndex observation log")?;
    let named = std::fs::symlink_metadata(&path)
        .map_err(|_| "cannot inspect named ReadIndex observation log")?;
    let after = std::fs::symlink_metadata(directory)
        .map_err(|_| "cannot reinspect ReadIndex observation directory")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != before.uid()
        || !named.is_file()
        || named.file_type().is_symlink()
        || named.dev() != metadata.dev()
        || named.ino() != metadata.ino()
        || named.nlink() != 1
        || named.uid() != metadata.uid()
        || !after.is_dir()
        || after.file_type().is_symlink()
        || after.mode() & 0o7777 != 0o700
        || after.uid() != before.uid()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
    {
        return Err("ReadIndex observation file custody changed");
    }
    Ok((
        file,
        FileIdentity {
            cwd_device: before.dev(),
            cwd_inode: before.ino(),
            file_device: metadata.dev(),
            file_inode: metadata.ino(),
            file_uid: metadata.uid(),
            file_mode: metadata.mode() & 0o7777,
            file_nlink: metadata.nlink(),
        },
    ))
}
#[cfg(not(unix))]
fn create_private_file(
    _launch_id: &str,
    _directory: &Path,
) -> Result<(File, FileIdentity), &'static str> {
    Err("ReadIndex observation file custody requires Unix")
}
fn launch_line(launch_id: &str, identity: &FileIdentity) -> Result<String, &'static str> {
    let value = serde_json::json!({
        "schema":"heptabao.read-index-observation.v1",
        "launch_id":launch_id,"process_id":std::process::id(),
        "record_sequence":1,"kind":"launch",
        "body":{
            "observer_profile":"on",
            "cwd_device":identity.cwd_device,"cwd_inode":identity.cwd_inode,
            "file_device":identity.file_device,"file_inode":identity.file_inode,
            "file_uid":identity.file_uid,"file_mode":identity.file_mode,"file_nlink":identity.file_nlink,
            "limits":{"records":MAX_RECORDS,"record_bytes":MAX_RECORD_BYTES,
                "output_bytes":MAX_OUTPUT_BYTES,"queue_records":QUEUE_RECORDS,"events_per_request":MAX_EVENTS}
        },
        "log_lost_before":0,"log_writer_failed":false,"diagnostic_only":true
    });
    let encoded =
        serde_json::to_string(&value).map_err(|_| "cannot encode ReadIndex observation launch")?;
    let line = format!("{LOG_PREFIX}{encoded}\n");
    if line.len() > MAX_RECORD_BYTES || line.len() as u64 > MAX_OUTPUT_BYTES {
        return Err("ReadIndex observation launch exceeds output bound");
    }
    Ok(line)
}
fn persist_line(file: &mut File, line: &str) -> std::io::Result<()> {
    file.write_all(line.as_bytes())?;
    file.sync_data()
}
fn start_sink(launch_id: &str, directory: &Path) -> Result<Sink, &'static str> {
    let (mut file, identity) = create_private_file(launch_id, directory)?;
    let initial = launch_line(launch_id, &identity)?;
    // Startup may wait for this independent file before listeners exist.
    // Thereafter only its background owner writes or syncs it. No stderr
    // lock, fd2 flags, shared open-file-description or request-side I/O.
    persist_line(&mut file, &initial).map_err(|_| "cannot persist ReadIndex observation launch")?;
    let initial_bytes = initial.len() as u64;
    let (sender, receiver) = mpsc::sync_channel::<String>(QUEUE_RECORDS);
    let health = Arc::new(SinkHealth::default());
    let writer_health = Arc::clone(&health);
    std::thread::Builder::new()
        .name("heptabao-read-observation".into())
        .spawn(move || {
            while let Ok(line) = receiver.recv() {
                if persist_line(&mut file, &line).is_err() {
                    writer_health.failed.store(true, Ordering::Relaxed);
                    writer_health.lost.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        })
        .map_err(|_| "cannot start ReadIndex observation file writer")?;
    Ok(Sink {
        launch_id: launch_id.to_owned(),
        sender,
        health,
        records: AtomicU64::new(1),
        bytes: AtomicU64::new(initial_bytes),
    })
}
fn sink() -> Option<&'static Sink> {
    // Deliberately not get_or_init: normal startup owns initialization.
    SINK.get()?.as_ref().ok()?.as_ref()
}
pub fn launch_id() -> Option<&'static str> {
    sink().map(|sink| sink.launch_id.as_str())
}
pub fn log_loss() -> (u64, bool) {
    sink().map_or((0, false), |sink| {
        (
            sink.health.lost.load(Ordering::Relaxed),
            sink.health.failed.load(Ordering::Relaxed),
        )
    })
}
fn emit_to_sink(sink: &Sink, kind: &'static str, body: serde_json::Value) {
    if sink.health.failed.load(Ordering::Relaxed) {
        sink.health.lost.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let sequence = match sink
        .records
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < MAX_RECORDS).then_some(n + 1)
        }) {
        Ok(n) => n + 1,
        Err(_) => {
            sink.health.lost.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let value = serde_json::json!({
        "schema": "heptabao.read-index-observation.v1",
        "launch_id": sink.launch_id, "process_id": std::process::id(),
        "record_sequence": sequence, "kind": kind, "body": body,
        "log_lost_before": sink.health.lost.load(Ordering::Relaxed),
        "log_writer_failed": sink.health.failed.load(Ordering::Relaxed),
        "diagnostic_only": true
    });
    let Ok(encoded) = serde_json::to_string(&value) else {
        sink.health.lost.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let line = format!("{LOG_PREFIX}{encoded}\n");
    let bytes = line.len();
    if bytes > MAX_RECORD_BYTES
        || sink
            .bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_add(bytes as u64)
                    .filter(|next| *next <= MAX_OUTPUT_BYTES)
            })
            .is_err()
    {
        sink.health.lost.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if sink.sender.try_send(line).is_err() {
        sink.health.lost.fetch_add(1, Ordering::Relaxed);
    }
}
fn emit(kind: &'static str, body: serde_json::Value) {
    if let Some(sink) = sink() {
        emit_to_sink(sink, kind, body);
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub(crate) struct LogValue {
    term: u64,
    node: u64,
    index: u64,
}
impl LogValue {
    fn from_log(value: LogIdOf<TypeConfig>) -> Self {
        Self {
            term: value.committed_leader_id().term,
            node: value.committed_leader_id().node_id,
            index: value.index(),
        }
    }
    fn compact(self) -> [u64; 3] {
        [self.term, self.node, self.index]
    }
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Success,
    NotLeader,
    Deadline,
    Unavailable,
    RpcTransport,
    RpcDecode,
    Cancelled,
}
impl Outcome {
    fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::NotLeader => 1,
            Self::Deadline => 2,
            Self::Unavailable => 3,
            Self::RpcTransport => 4,
            Self::RpcDecode => 5,
            Self::Cancelled => 6,
        }
    }
}
#[derive(Clone, Serialize)]
struct Selection {
    application_generation: u64,
    application_applied: LogValue,
    root_generation: Option<u64>,
    replay_epoch: Option<u64>,
    publication_log: Option<LogValue>,
    verification_successes: u32,
    verification_failures: u32,
    stages: u8,
    inconsistent: bool,
}
impl Selection {
    fn new(application_generation: u64, application_applied: LogValue) -> Self {
        Self {
            application_generation,
            application_applied,
            root_generation: None,
            replay_epoch: None,
            publication_log: None,
            verification_successes: 0,
            verification_failures: 0,
            stages: 0,
            inconsistent: false,
        }
    }
    fn compact(&self) -> serde_json::Value {
        serde_json::json!([
            self.application_generation,
            self.application_applied.compact(),
            self.root_generation,
            self.replay_epoch,
            self.publication_log.map(LogValue::compact),
            self.verification_successes,
            self.verification_failures,
            self.stages,
            self.inconsistent
        ])
    }
}
#[derive(Clone, Serialize)]
struct Event {
    ordinal: u64,
    node: u64,
    leader: Option<u64>,
    term: Option<u64>,
    rpc_source: Option<u64>,
    rpc_target: Option<u64>,
    rpc_request_id: Option<u64>,
    read_log_id: Option<LogValue>,
    leader_applied: Option<LogValue>,
    local_applied: Option<LogValue>,
    state_machine_applied_index: Option<u64>,
    read_policy_calls: u32,
    outcome: Outcome,
    elapsed_us: u64,
    original_budget_us: u64,
    original_deadline_expired: bool,
    selection: Option<Selection>,
}
impl Event {
    fn compact(&self) -> serde_json::Value {
        serde_json::json!([
            self.ordinal,
            self.node,
            self.leader,
            self.term,
            self.rpc_source,
            self.rpc_target,
            self.rpc_request_id,
            self.read_log_id.map(LogValue::compact),
            self.leader_applied.map(LogValue::compact),
            self.local_applied.map(LogValue::compact),
            self.state_machine_applied_index,
            self.read_policy_calls,
            self.outcome.code(),
            self.elapsed_us,
            self.original_budget_us,
            self.original_deadline_expired,
            self.selection.as_ref().map(Selection::compact)
        ])
    }
}
fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
#[derive(Default)]
struct Collection {
    next: u64,
    completed: u64,
    events: Vec<Event>,
    dropped: u64,
    closed: bool,
}
/// A closed copy of numeric diagnostic fields; it cannot be constructed from
/// user JSON and is never consumed by any authority or application-read API.
#[derive(Clone, Serialize)]
pub struct Snapshot {
    complete: bool,
    started: u64,
    completed: u64,
    dropped: u64,
    events: Vec<Event>,
    busy: bool,
}
impl Snapshot {
    pub fn compact(&self) -> serde_json::Value {
        serde_json::json!({
            "v":1, "complete":self.complete, "started":self.started,
            "completed":self.completed, "dropped":self.dropped,
            "collector_busy":self.busy,
            "events":self.events.iter().map(Event::compact).collect::<Vec<_>>()
        })
    }
    pub fn incomplete_header(&self) -> serde_json::Value {
        serde_json::json!({
            "v":1,"complete":false,"reason":"header_capacity",
            "started":self.started,"completed":self.completed,"dropped":self.dropped
        })
    }
}
#[derive(Clone)]
pub struct Collector {
    inner: Arc<Mutex<Collection>>,
    contention: Arc<AtomicU64>,
}
impl Collector {
    pub fn new() -> Option<Self> {
        launch_id()?;
        Some(Self::empty())
    }
    fn empty() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Collection::default())),
            contention: Arc::new(AtomicU64::new(0)),
        }
    }
    fn reserve(&self) -> Option<u64> {
        let Ok(mut inner) = self.inner.try_lock() else {
            self.contention.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        if inner.closed {
            inner.dropped = inner.dropped.saturating_add(1);
            return None;
        }
        inner.next = inner.next.saturating_add(1);
        if inner.next > MAX_EVENTS as u64 {
            inner.dropped = inner.dropped.saturating_add(1);
            return None;
        }
        Some(inner.next)
    }
    fn push(&self, event: Event) {
        let Ok(mut inner) = self.inner.try_lock() else {
            self.contention.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if inner.closed || inner.events.len() >= MAX_EVENTS {
            inner.dropped = inner.dropped.saturating_add(1);
            return;
        }
        inner.completed = inner.completed.saturating_add(1);
        inner.events.push(event);
    }
    /// A synchronous bounded metadata copy, not a refreshed ReadIndex.
    /// Complete says every started diagnostic is present; zero events never
    /// proves that this request executed ReadIndex.
    pub fn snapshot(&self) -> Snapshot {
        let Ok(inner) = self.inner.try_lock() else {
            return Snapshot {
                complete: false,
                started: 0,
                completed: 0,
                dropped: 1,
                events: Vec::new(),
                busy: true,
            };
        };
        let dropped = inner
            .dropped
            .saturating_add(self.contention.load(Ordering::Relaxed));
        Snapshot {
            complete: !inner.closed && dropped == 0 && inner.next == inner.completed,
            started: inner.next,
            completed: inner.completed,
            dropped,
            events: inner.events.clone(),
            busy: false,
        }
    }
    pub fn close(&self) {
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.closed = true;
        } else {
            self.contention.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A nonpersistent reference to one diagnostic event. No constructor, equality,
/// hash, serialization, store grant or deadline extension is exposed. This value
/// is not consulted by any existing witness/capability comparison.
#[derive(Clone)]
pub struct ReadIdentity {
    collection: Weak<Mutex<Collection>>,
    contention: Weak<AtomicU64>,
    ordinal: u64,
    original_deadline: Instant,
}
impl ReadIdentity {
    fn from_collector(collector: &Collector, ordinal: u64, original_deadline: Instant) -> Self {
        Self {
            collection: Arc::downgrade(&collector.inner),
            contention: Arc::downgrade(&collector.contention),
            ordinal,
            original_deadline,
        }
    }
    fn lost(&self) {
        if let Some(contention) = self.contention.upgrade() {
            contention.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn update(&self, edit: impl FnOnce(&mut Event)) {
        let Some(collection) = self.collection.upgrade() else {
            return;
        };
        if let Some(current) = capture_collector()
            && !Arc::ptr_eq(&collection, &current.inner)
        {
            current.contention.fetch_add(1, Ordering::Relaxed);
            self.lost();
            return;
        }
        let Ok(mut inner) = collection.try_lock() else {
            self.lost();
            return;
        };
        if inner.closed {
            inner.dropped = inner.dropped.saturating_add(1);
            return;
        }
        let Some(event) = inner
            .events
            .iter_mut()
            .find(|event| event.ordinal == self.ordinal)
        else {
            inner.dropped = inner.dropped.saturating_add(1);
            return;
        };
        edit(event);
    }
    pub(crate) fn selected(
        &self,
        application_generation: u64,
        applied: LogIdOf<TypeConfig>,
        root: Option<(u64, u64, LogIdOf<TypeConfig>)>,
        stage: u8,
    ) {
        self.update(|event| {
            let applied = LogValue::from_log(applied);
            let selected = event
                .selection
                .get_or_insert_with(|| Selection::new(application_generation, applied));
            if selected.application_generation != application_generation
                || selected.application_applied != applied
            {
                selected.inconsistent = true;
            }
            if let Some((generation, epoch, publication)) = root {
                let publication = LogValue::from_log(publication);
                if publication > applied {
                    selected.inconsistent = true;
                }
                if selected
                    .root_generation
                    .is_some_and(|value| value != generation)
                    || selected.replay_epoch.is_some_and(|value| value != epoch)
                    || selected
                        .publication_log
                        .is_some_and(|value| value != publication)
                {
                    selected.inconsistent = true;
                }
                selected.root_generation = Some(generation);
                selected.replay_epoch = Some(epoch);
                selected.publication_log = Some(publication);
            }
            if stage == 0 || stage & !15 != 0 {
                selected.inconsistent = true;
            }
            selected.stages |= stage;
        });
    }
    pub(crate) fn verified(
        &self,
        application_generation: u64,
        applied: LogIdOf<TypeConfig>,
        success: bool,
    ) {
        self.update(|event| {
            let applied = LogValue::from_log(applied);
            let selected = event
                .selection
                .get_or_insert_with(|| Selection::new(application_generation, applied));
            if selected.application_generation != application_generation
                || selected.application_applied != applied
            {
                selected.inconsistent = true;
            }
            if success {
                selected.verification_successes = selected.verification_successes.saturating_add(1);
            } else {
                selected.verification_failures = selected.verification_failures.saturating_add(1);
            }
        });
    }
    /// Only the currently owned HTTP collector may bind a real payload to this
    /// same completed event. Numeric tuples and IDs from another request fail.
    pub fn current_payload_ordinal(&self) -> Option<u64> {
        self.current_payload_ordinal_at(Instant::now())
    }
    fn current_payload_ordinal_at(&self, now: Instant) -> Option<u64> {
        if now >= self.original_deadline {
            return None;
        }
        let current = capture_collector()?;
        let collection = self.collection.upgrade()?;
        if !Arc::ptr_eq(&collection, &current.inner) {
            current.contention.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let Ok(inner) = collection.try_lock() else {
            self.lost();
            return None;
        };
        if inner.closed {
            return None;
        }
        let event = inner
            .events
            .iter()
            .find(|event| event.ordinal == self.ordinal)?;
        let selected = event.selection.as_ref()?;
        if !matches!(event.outcome, Outcome::Success)
            || event.original_deadline_expired
            || selected.inconsistent
            || selected.verification_successes == 0
            || selected.verification_failures != 0
            || selected.stages & 15 != 15
            || selected.root_generation.is_none()
            || selected.replay_epoch.is_none()
            || selected.publication_log.is_none()
        {
            return None;
        }
        Some(self.ordinal)
    }
}

#[derive(Clone)]
struct ThreadEntry {
    collector: Option<Collector>,
    active: Arc<AtomicBool>,
}
thread_local! {
    static THREAD_COLLECTOR: RefCell<Option<ThreadEntry>> = const { RefCell::new(None) };
}
tokio::task_local! {
    static TASK_COLLECTOR: Collector;
}
/// Only the caller's explicitly owned HTTP scope supplies this collector.
/// Explicit capture at a synchronous/async call boundary. A spawned task has no
/// inherited task-local scope; a different OS thread has no HTTP thread scope.
pub fn capture_collector() -> Option<Collector> {
    TASK_COLLECTOR
        .try_with(Clone::clone)
        .ok()
        .or_else(current_thread_collector)
}
pub fn current_thread_collector() -> Option<Collector> {
    THREAD_COLLECTOR.with(|slot| {
        slot.try_borrow().ok().and_then(|s| {
            s.as_ref()
                .filter(|entry| entry.active.load(Ordering::Relaxed))
                .and_then(|entry| entry.collector.clone())
        })
    })
}
pub struct ThreadScope {
    previous: Option<ThreadEntry>,
    installed: Arc<AtomicBool>,
    attached: bool,
    _thread_bound: PhantomData<Rc<()>>,
}
pub fn enter_thread(collector: Option<Collector>) -> ThreadScope {
    let mut previous = None;
    let installed = Arc::new(AtomicBool::new(true));
    let attached = THREAD_COLLECTOR.with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut() {
            previous = slot.replace(ThreadEntry {
                collector,
                active: Arc::clone(&installed),
            });
            true
        } else {
            false
        }
    });
    ThreadScope {
        previous,
        installed,
        attached,
        _thread_bound: PhantomData,
    }
}
impl Drop for ThreadScope {
    fn drop(&mut self) {
        self.installed.store(false, Ordering::Relaxed);
        if self.attached {
            THREAD_COLLECTOR.with(|slot| {
                if let Ok(mut slot) = slot.try_borrow_mut()
                    && slot
                        .as_ref()
                        .is_some_and(|entry| Arc::ptr_eq(&entry.active, &self.installed))
                {
                    *slot = self
                        .previous
                        .take()
                        .filter(|entry| entry.active.load(Ordering::Relaxed));
                }
            });
        }
    }
}
/// This task-local follows the future through awaits and is not inherited by
/// spawned background tasks. It changes neither the operation nor its deadline.
pub async fn scope<F: Future>(collector: Option<Collector>, operation: F) -> F::Output {
    match collector {
        Some(collector) => TASK_COLLECTOR.scope(collector, operation).await,
        None => operation.await,
    }
}

enum Destination {
    Http(Collector),
    Peer,
}
pub(crate) struct Attempt {
    destination: Option<Destination>,
    began: Instant,
    deadline: Instant,
    event: Event,
    finished: bool,
}
impl Attempt {
    pub(crate) fn local(node: u64, deadline: Instant) -> Option<Self> {
        let collector = capture_collector()?;
        let ordinal = collector.reserve()?;
        Some(Self::new(
            node,
            deadline,
            ordinal,
            Destination::Http(collector),
        ))
    }
    pub(crate) fn peer(node: u64, source: u64, deadline: Instant) -> Option<Self> {
        launch_id()?;
        let mut attempt = Self::new(node, deadline, 0, Destination::Peer);
        attempt.event.rpc_source = Some(source);
        attempt.event.rpc_target = Some(node);
        Some(attempt)
    }
    fn new(node: u64, deadline: Instant, ordinal: u64, destination: Destination) -> Self {
        let began = Instant::now();
        Self {
            destination: Some(destination),
            began,
            deadline,
            finished: false,
            event: Event {
                ordinal,
                node,
                leader: None,
                term: None,
                rpc_source: None,
                rpc_target: None,
                rpc_request_id: None,
                read_log_id: None,
                leader_applied: None,
                local_applied: None,
                state_machine_applied_index: None,
                read_policy_calls: 0,
                outcome: Outcome::Cancelled,
                elapsed_us: 0,
                original_budget_us: micros(deadline.saturating_duration_since(began)),
                original_deadline_expired: false,
                selection: None,
            },
        }
    }
    pub(crate) fn identity(&self) -> Option<ReadIdentity> {
        match self.destination.as_ref() {
            Some(Destination::Http(collector)) => Some(ReadIdentity::from_collector(
                collector,
                self.event.ordinal,
                self.deadline,
            )),
            _ => None,
        }
    }
    pub(crate) fn bind(&mut self, leader: u64, term: u64) {
        self.event.leader = Some(leader);
        self.event.term = Some(term);
    }
    pub(crate) fn rpc(&mut self, source: u64, target: u64, request_id: u64) {
        self.event.rpc_source = Some(source);
        self.event.rpc_target = Some(target);
        self.event.rpc_request_id = Some(request_id);
    }
    pub(crate) fn policy_entered(&mut self) {
        self.event.read_policy_calls = self.event.read_policy_calls.saturating_add(1);
    }
    pub(crate) fn failure_stage(&mut self, outcome: Outcome) {
        self.event.outcome = outcome;
    }
    pub(crate) fn applied(
        &mut self,
        read: LogIdOf<TypeConfig>,
        leader_applied: LogIdOf<TypeConfig>,
        local_applied: LogIdOf<TypeConfig>,
        state_applied: Option<u64>,
    ) {
        self.event.read_log_id = Some(LogValue::from_log(read));
        self.event.leader_applied = Some(LogValue::from_log(leader_applied));
        self.event.local_applied = Some(LogValue::from_log(local_applied));
        self.event.state_machine_applied_index = state_applied;
    }
    fn success_metadata_complete(&self) -> bool {
        let event = &self.event;
        let (Some(leader), Some(term), Some(read), Some(leader_applied), Some(local_applied)) = (
            event.leader,
            event.term,
            event.read_log_id,
            event.leader_applied,
            event.local_applied,
        ) else {
            return false;
        };
        if event.node == 0
            || leader == 0
            || read.term != term
            || read.node != leader
            || leader_applied < read
            || local_applied < read
        {
            return false;
        }
        if event.node == leader {
            event.read_policy_calls > 0
                && match (event.rpc_source, event.rpc_target, event.rpc_request_id) {
                    (None, None, None) => true,
                    (Some(source), Some(target), Some(request)) => {
                        source != 0 && source != event.node && target == event.node && request != 0
                    }
                    _ => false,
                }
        } else {
            event.read_policy_calls == 0
                && event.rpc_source == Some(event.node)
                && event.rpc_target == Some(leader)
                && event.rpc_request_id.is_some_and(|request| request != 0)
                && event
                    .state_machine_applied_index
                    .is_some_and(|index| index >= read.index)
        }
    }
    pub(crate) fn finish(&mut self, outcome: Outcome) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.event.outcome = outcome;
        self.event.elapsed_us = micros(self.began.elapsed());
        self.event.original_deadline_expired = Instant::now() >= self.deadline;
        // Even a caller mistake cannot advertise a late operation as success.
        if matches!(self.event.outcome, Outcome::Success) {
            if self.event.original_deadline_expired {
                self.event.outcome = Outcome::Deadline;
            } else if !self.success_metadata_complete() {
                self.event.outcome = Outcome::Unavailable;
            }
        }
        match self.destination.take() {
            Some(Destination::Http(collector)) => collector.push(self.event.clone()),
            Some(Destination::Peer) => {
                if let Ok(value) = serde_json::to_value(&self.event) {
                    emit("authenticated_peer_read_index", value);
                }
            }
            None => {}
        }
    }
    pub(crate) fn finish_error(&mut self, outcome: Outcome) {
        let selected = match self.event.outcome {
            Outcome::Cancelled => outcome,
            _ => self.event.outcome,
        };
        self.finish(selected);
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(Outcome::Cancelled);
        }
    }
}
/// Closed server-owned metadata only. No caller-supplied paths, token or error
/// bytes are accepted here. The snapshot is diagnostic and never read authority.
pub fn emit_http_terminal(
    attempt_hex: &str,
    protocol: &'static str,
    status: Option<u16>,
    writer_outcome: &'static str,
    accepted_bytes: u64,
    flush_attempted: bool,
    elapsed_us: u64,
    original_deadline_expired: bool,
    transcript: &Snapshot,
    header_complete: bool,
    payload_binding_state: u8,
    payload_ordinal: Option<u64>,
) {
    if !valid_launch(attempt_hex)
        || !matches!(protocol, "http1" | "http2")
        || !matches!(writer_outcome, "complete" | "failed" | "abandoned")
        || payload_binding_state > 4
        || (payload_binding_state != 1 && payload_ordinal.is_some())
    {
        return;
    }
    emit(
        "http_terminal",
        serde_json::json!({
            "attempt_id":attempt_hex,"protocol":protocol,"http_status":status,
            "writer_outcome":writer_outcome,"accepted_bytes":accepted_bytes,
            "flush_attempted":flush_attempted,"elapsed_us":elapsed_us,
            "original_deadline_expired":original_deadline_expired,
            "client_delivery_observed":false,"header_complete":header_complete,"transcript":transcript,
            "payload_binding_state":payload_binding_state,"payload_ordinal":payload_ordinal,
            "accepted_byte_scope":if protocol=="http1" {"http1_plaintext"} else {"http2_data"}
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn launch_id_accepts_only_bounded_lower_hex() {
        assert!(valid_launch("0123456789abcdef0123456789abcdef"));
        for value in [
            "",
            "0123456789ABCDEF0123456789ABCDEF",
            "../token",
            "0123456789abcdef0123456789abcdef0",
        ] {
            assert!(!valid_launch(value));
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn explicit_collector_scope_does_not_leak_to_spawned_tasks()
    -> Result<(), Box<dyn std::error::Error>> {
        let collector = Collector::empty();
        scope(Some(collector.clone()), async {
            assert!(TASK_COLLECTOR.try_with(|_| ()).is_ok());
            tokio::task::yield_now().await;
            assert!(TASK_COLLECTOR.try_with(|_| ()).is_ok());
            assert!(tokio::spawn(async { TASK_COLLECTOR.try_with(|_| ()).is_err() }).await?);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?;
        assert!(TASK_COLLECTOR.try_with(|_| ()).is_err());
        Ok(())
    }
    #[test]
    fn incomplete_cancelled_and_overflowed_collections_never_look_complete() {
        let collector = Collector::empty();
        assert_eq!(collector.reserve(), Some(1));
        assert_eq!(collector.snapshot().compact()["complete"], false);
        for _ in 0..MAX_EVENTS {
            collector.reserve();
        }
        let value = collector.snapshot().compact();
        assert_eq!(value["complete"], false);
        assert_eq!(value["dropped"], 1);
        collector.close();
        assert_eq!(collector.snapshot().compact()["complete"], false);
    }
    #[test]
    fn observation_success_requires_real_complete_fields_and_original_deadline() {
        let collector = Collector::empty();
        let mut attempt = Attempt::new(
            1,
            Instant::now() + std::time::Duration::from_secs(1),
            collector.reserve().unwrap_or(0),
            Destination::Http(collector.clone()),
        );
        attempt.bind(1, 2);
        attempt.finish(Outcome::Success);
        let value = collector.snapshot().compact();
        assert_eq!(value["events"][0][12], 3);
        assert_eq!(value["events"][0][11], 0);
        let expired = Collector::empty();
        let mut attempt = Attempt::new(
            1,
            Instant::now(),
            expired.reserve().unwrap_or(0),
            Destination::Http(expired.clone()),
        );
        attempt.finish(Outcome::Success);
        assert_eq!(expired.snapshot().compact()["events"][0][12], 2);
    }
    fn selected_test_identity(collector: &Collector) -> ReadIdentity {
        selected_test_identity_at(
            collector,
            Instant::now() + std::time::Duration::from_secs(1),
        )
    }
    fn selected_test_identity_at(collector: &Collector, deadline: Instant) -> ReadIdentity {
        let ordinal = collector.reserve().unwrap_or(0);
        let mut attempt = Attempt::new(1, deadline, ordinal, Destination::Http(collector.clone()));
        attempt.bind(1, 2);
        attempt.event.read_log_id = Some(LogValue {
            term: 2,
            node: 1,
            index: 5,
        });
        attempt.event.leader_applied = Some(LogValue {
            term: 2,
            node: 1,
            index: 5,
        });
        attempt.event.local_applied = Some(LogValue {
            term: 2,
            node: 1,
            index: 5,
        });
        attempt.policy_entered();
        let identity = ReadIdentity::from_collector(collector, ordinal, deadline);
        attempt.finish(Outcome::Success);
        identity.update(|event| {
            event.selection = Some(Selection {
                application_generation: 11,
                application_applied: LogValue {
                    term: 2,
                    node: 1,
                    index: 5,
                },
                root_generation: Some(4),
                replay_epoch: Some(1),
                publication_log: Some(LogValue {
                    term: 2,
                    node: 1,
                    index: 4,
                }),
                verification_successes: 2,
                verification_failures: 0,
                stages: 15,
                inconsistent: false,
            })
        });
        identity
    }
    #[test]
    fn completed_selection_never_binds_at_or_after_its_original_deadline() {
        let collector = Collector::empty();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let identity = selected_test_identity_at(&collector, deadline);
        let _scope = enter_thread(Some(collector));
        assert_eq!(
            identity.current_payload_ordinal_at(deadline - std::time::Duration::from_nanos(1)),
            Some(1)
        );
        assert!(identity.current_payload_ordinal_at(deadline).is_none());
        assert!(
            identity
                .current_payload_ordinal_at(deadline + std::time::Duration::from_nanos(1))
                .is_none()
        );
        assert_eq!(identity.original_deadline, deadline);
    }
    #[test]
    fn payload_identity_refuses_other_http_scope_and_incomplete_selection() {
        let a = Collector::empty();
        let identity = selected_test_identity(&a);
        {
            let _scope = enter_thread(Some(a.clone()));
            assert_eq!(identity.current_payload_ordinal(), Some(1));
        }
        let b = Collector::empty();
        {
            let _scope = enter_thread(Some(b.clone()));
            assert!(identity.current_payload_ordinal().is_none());
        }
        assert!(!b.snapshot().complete);
        {
            let _scope = enter_thread(Some(a.clone()));
            identity.update(|event| event.selection.as_mut().unwrap().verification_failures += 1);
            assert!(identity.current_payload_ordinal().is_none());
        }
        let c = Collector::empty();
        let identity = selected_test_identity(&c);
        {
            let _scope = enter_thread(Some(c));
            identity.update(|event| event.selection.as_mut().unwrap().stages = 7);
            assert!(identity.current_payload_ordinal().is_none());
        }
    }
    #[test]
    fn closed_or_inconsistent_selection_never_binds_payload() {
        let collector = Collector::empty();
        let identity = selected_test_identity(&collector);
        let _scope = enter_thread(Some(collector.clone()));
        identity.update(|event| event.selection.as_mut().unwrap().inconsistent = true);
        assert!(identity.current_payload_ordinal().is_none());
        collector.close();
        assert!(identity.current_payload_ordinal().is_none());
        assert!(!collector.snapshot().complete);
    }
    #[test]
    fn out_of_order_thread_guards_do_not_revive_retired_scope() {
        let outer = enter_thread(Some(Collector::empty()));
        let inner = enter_thread(Some(Collector::empty()));
        drop(outer);
        assert!(current_thread_collector().is_some());
        drop(inner);
        assert!(current_thread_collector().is_none());
    }

    #[cfg(unix)]
    struct PrivateLogDirectory(std::path::PathBuf);
    #[cfg(unix)]
    impl PrivateLogDirectory {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "heptabao-read-observation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("private test directory");
            Self(path)
        }
    }
    #[cfg(unix)]
    impl Drop for PrivateLogDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    #[cfg(unix)]
    fn private_log_file_refuses_existing_linked_and_nonprivate_targets() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = PrivateLogDirectory::new();
        let launch = "0123456789abcdef0123456789abcdef";
        let target = directory
            .0
            .join(format!("read-index-observation-{launch}.log"));
        let original = directory.0.join("original");
        std::fs::write(&original, b"unchanged").expect("original");
        symlink(&original, &target).expect("symlink");
        assert!(create_private_file(launch, &directory.0).is_err());
        assert_eq!(std::fs::read(&original).expect("original"), b"unchanged");
        std::fs::remove_file(&target).expect("remove test symlink");
        std::fs::hard_link(&original, &target).expect("hard link");
        assert!(create_private_file(launch, &directory.0).is_err());
        assert_eq!(std::fs::read(&original).expect("original"), b"unchanged");
        std::fs::remove_file(&target).expect("remove test hard link");
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o750))
            .expect("permissions");
        assert!(create_private_file(launch, &directory.0).is_err());
        assert!(!target.exists());
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let (_file, _identity) = create_private_file(launch, &directory.0).expect("private log");
        assert!(create_private_file(launch, &directory.0).is_err());
    }
    #[test]
    #[cfg(unix)]
    fn private_log_sink_persists_launch_identity_without_stderr() {
        use std::os::unix::fs::MetadataExt;
        let directory = PrivateLogDirectory::new();
        let launch = "abcdef0123456789abcdef0123456789";
        let (mut file, identity) = create_private_file(launch, &directory.0).expect("private log");
        let line = launch_line(launch, &identity).expect("launch line");
        persist_line(&mut file, &line).expect("durable private line");
        let path = directory
            .0
            .join(format!("read-index-observation-{launch}.log"));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read private line"),
            line
        );
        let metadata = std::fs::symlink_metadata(&path).expect("metadata");
        let directory_metadata = std::fs::metadata(&directory.0).expect("directory metadata");
        assert_eq!((metadata.mode() & 0o7777, metadata.nlink()), (0o600, 1));
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            (identity.file_device, identity.file_inode)
        );
        assert_eq!(metadata.uid(), directory_metadata.uid());
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix(LOG_PREFIX).expect("marker")).expect("json");
        assert_eq!(value["record_sequence"], 1);
        assert_eq!(value["kind"], "launch");
        assert_eq!(value["launch_id"], launch);
        assert_eq!(value["process_id"], std::process::id());
        assert_eq!(value["body"]["limits"]["output_bytes"], MAX_OUTPUT_BYTES);
        assert_eq!(value["body"]["limits"]["records"], MAX_RECORDS);
        assert_eq!(value["body"]["file_inode"], metadata.ino());
        assert!(line.len() <= MAX_RECORD_BYTES);
    }
    #[test]
    fn private_log_sink_enforces_record_and_byte_limits() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let sink = Sink {
            launch_id: "abcdef0123456789abcdef0123456789".into(),
            sender,
            health: Arc::new(SinkHealth::default()),
            records: AtomicU64::new(MAX_RECORDS),
            bytes: AtomicU64::new(0),
        };
        emit_to_sink(&sink, "test", serde_json::json!({}));
        assert!(receiver.try_recv().is_err());
        assert_eq!(sink.records.load(Ordering::Relaxed), MAX_RECORDS);
        assert_eq!(sink.health.lost.load(Ordering::Relaxed), 1);
        sink.records.store(1, Ordering::Relaxed);
        sink.bytes.store(MAX_OUTPUT_BYTES - 1, Ordering::Relaxed);
        emit_to_sink(&sink, "test", serde_json::json!({}));
        assert!(receiver.try_recv().is_err());
        assert_eq!(sink.bytes.load(Ordering::Relaxed), MAX_OUTPUT_BYTES - 1);
        sink.bytes.store(0, Ordering::Relaxed);
        emit_to_sink(
            &sink,
            "test",
            serde_json::json!({"oversized":"x".repeat(MAX_RECORD_BYTES)}),
        );
        assert!(receiver.try_recv().is_err());
        assert_eq!(sink.bytes.load(Ordering::Relaxed), 0);
        emit_to_sink(&sink, "test", serde_json::json!({}));
        emit_to_sink(&sink, "test", serde_json::json!({}));
        assert_eq!(sink.health.lost.load(Ordering::Relaxed), 4);
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_err());
        sink.health.failed.store(true, Ordering::Relaxed);
        emit_to_sink(&sink, "test", serde_json::json!({}));
        assert_eq!(sink.health.lost.load(Ordering::Relaxed), 5);
        assert!(receiver.try_recv().is_err());
    }
}
