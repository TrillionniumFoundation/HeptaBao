//! Request-local bounded read-ahead for the existing ordered payload decoder.
//! The source retains physical custody. Buffered bytes grant no delivery
//! authority: before_delivery is called again for every consumed ObjectRef.
use crate::request_deadline::{self, RequestDeadlineScope};
use crate::state_records::{ObjectKind, ObjectRef, RecordError, RecordReader};
use crate::v6_native_custody::OriginalDeadline;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::iter::Peekable;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

type ReadResult<T> = std::result::Result<T, RecordError>;
type ExportResult<T> = std::result::Result<T, crate::engines::EngineError>;
pub(super) const MAX_WORKERS: usize = 4;
pub(super) const MAX_OUTSTANDING: usize = 32;
pub(super) const MAX_ENCODED_BYTES: usize = 4 * 1024 * 1024;
const WAKE_INTERVAL: Duration = Duration::from_millis(2);

struct Job {
    sequence: usize,
    reference: ObjectRef,
}
struct Completion {
    sequence: usize,
    reference: ObjectRef,
    bytes: Zeroizing<Vec<u8>>,
}
struct Pending {
    sequence: usize,
    reference: ObjectRef,
    bytes: Option<Zeroizing<Vec<u8>>>,
}

fn checked(
    deadline: OriginalDeadline,
    stop: &AtomicBool,
    check: &(impl Fn() -> ReadResult<()> + Sync),
) -> ReadResult<()> {
    let result = (|| {
        if stop.load(Ordering::Acquire) {
            return Err(RecordError::Invalid);
        }
        deadline.check().map_err(|_| RecordError::Invalid)?;
        check()?;
        deadline.check().map_err(|_| RecordError::Invalid)?;
        if stop.load(Ordering::Acquire) {
            return Err(RecordError::Invalid);
        }
        Ok(())
    })();
    if result.is_err() {
        stop.store(true, Ordering::Release);
    }
    result
}

struct Window<I: Iterator<Item = ReadResult<ObjectRef>>> {
    references: Peekable<I>,
    pending: VecDeque<Pending>,
    encoded_bytes: usize,
    next_sequence: usize,
    jobs: Option<SyncSender<Job>>,
    results: Option<Receiver<Completion>>,
}
impl<I: Iterator<Item = ReadResult<ObjectRef>>> Window<I> {
    fn fill(
        &mut self,
        deadline: OriginalDeadline,
        stop: &AtomicBool,
        check: &(impl Fn() -> ReadResult<()> + Sync),
    ) -> ReadResult<()> {
        while self.pending.len() < MAX_OUTSTANDING {
            checked(deadline, stop, check)?;
            let Some(next) = self.references.peek() else {
                break;
            };
            let reference = next.as_ref().map_err(|error| *error)?;
            let encoded = reference.encoded_bytes as usize;
            if reference.kind != ObjectKind::Block || encoded == 0 {
                return Err(RecordError::Corrupt);
            }
            if encoded > MAX_ENCODED_BYTES {
                return Err(RecordError::TooLarge);
            }
            let total = self
                .encoded_bytes
                .checked_add(encoded)
                .ok_or(RecordError::TooLarge)?;
            if total > MAX_ENCODED_BYTES {
                break;
            }
            let reference = self.references.next().ok_or(RecordError::Corrupt)??;
            let sequence = self.next_sequence;
            self.next_sequence = sequence.checked_add(1).ok_or(RecordError::TooLarge)?;
            self.pending.push_back(Pending {
                sequence,
                reference: reference.clone(),
                bytes: None,
            });
            self.encoded_bytes = total;
            // Admission accounts for queued, executing and buffered results
            // together. Capacity therefore cannot require a blocking send.
            self.jobs
                .as_ref()
                .ok_or(RecordError::Invalid)?
                .try_send(Job {
                    sequence,
                    reference,
                })
                .map_err(|_| RecordError::Invalid)?;
        }
        Ok(())
    }

    fn close(&mut self) {
        self.jobs.take();
        self.results.take();
        self.pending.clear();
        self.encoded_bytes = 0;
    }
}

pub(super) struct PrefetchReader<'a, I: Iterator<Item = ReadResult<ObjectRef>>, D, C> {
    window: RefCell<Window<I>>,
    before_delivery: &'a D,
    check: &'a C,
    deadline: OriginalDeadline,
    effective_deadline: Instant,
    stop: &'a AtomicBool,
    completed: Cell<bool>,
}
impl<I, D, C> PrefetchReader<'_, I, D, C>
where
    I: Iterator<Item = ReadResult<ObjectRef>>,
    D: Fn() -> ReadResult<()> + Sync,
    C: Fn() -> ReadResult<()> + Sync,
{
    fn fill(&self) -> ReadResult<()> {
        self.window
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?
            .fill(self.deadline, self.stop, self.check)
    }

    fn read(&self, wanted: &ObjectRef) -> ReadResult<Zeroizing<Vec<u8>>> {
        checked(self.deadline, self.stop, self.check)?;
        let mut window = self
            .window
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        // Only the unchanged descriptor.read loop consumes this reader. Its
        // previous encoded block is dropped before the next read_object call.
        // Refill here, never after removing the block returned to that loop:
        // the currently delivered encoded bytes then remain within the same
        // admitted 4 MiB window rather than adding one extra block.
        window.fill(self.deadline, self.stop, self.check)?;
        if window
            .pending
            .front()
            .is_none_or(|pending| &pending.reference != wanted)
        {
            return Err(RecordError::Corrupt);
        }
        while window
            .pending
            .front()
            .is_some_and(|pending| pending.bytes.is_none())
        {
            checked(self.deadline, self.stop, self.check)?;
            let remaining = self
                .effective_deadline
                .checked_duration_since(Instant::now())
                .ok_or(RecordError::Invalid)?;
            let completion = match window
                .results
                .as_ref()
                .ok_or(RecordError::Invalid)?
                .recv_timeout(remaining.min(WAKE_INTERVAL))
            {
                Ok(completion) => completion,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return Err(RecordError::Invalid),
            };
            if completion.bytes.len() != completion.reference.encoded_bytes as usize {
                return Err(RecordError::Corrupt);
            }
            let pending = window
                .pending
                .iter_mut()
                .find(|pending| pending.sequence == completion.sequence)
                .ok_or(RecordError::Corrupt)?;
            if pending.reference != completion.reference || pending.bytes.is_some() {
                return Err(RecordError::Corrupt);
            }
            pending.bytes = Some(completion.bytes);
        }
        checked(self.deadline, self.stop, self.check)?;
        (self.before_delivery)()?;
        checked(self.deadline, self.stop, self.check)?;
        let mut pending = window.pending.pop_front().ok_or(RecordError::Corrupt)?;
        window.encoded_bytes = window
            .encoded_bytes
            .checked_sub(pending.reference.encoded_bytes as usize)
            .ok_or(RecordError::Corrupt)?;
        pending.bytes.take().ok_or(RecordError::Corrupt)
    }

    fn finish(&self) -> ReadResult<()> {
        checked(self.deadline, self.stop, self.check)?;
        let mut window = self
            .window
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        if !window.pending.is_empty()
            || window.encoded_bytes != 0
            || window.references.next().is_some()
        {
            return Err(RecordError::Corrupt);
        }
        checked(self.deadline, self.stop, self.check)
    }
}
impl<I, D, C> RecordReader for PrefetchReader<'_, I, D, C>
where
    I: Iterator<Item = ReadResult<ObjectRef>>,
    D: Fn() -> ReadResult<()> + Sync,
    C: Fn() -> ReadResult<()> + Sync,
{
    fn read_object(&self, reference: &ObjectRef) -> ReadResult<Zeroizing<Vec<u8>>> {
        let result = self.read(reference);
        if result.is_err() {
            self.stop.store(true, Ordering::Release);
        }
        result
    }
}
impl<I: Iterator<Item = ReadResult<ObjectRef>>, D, C> Drop for PrefetchReader<'_, I, D, C> {
    fn drop(&mut self) {
        if !self.completed.get() {
            self.stop.store(true, Ordering::Release);
        }
        // Closing both directions before scoped joins also handles unwinding:
        // a worker never needs the abandoned consumer to drain a full queue.
        self.window.get_mut().close();
    }
}

struct WorkerFailure<'a> {
    stop: &'a AtomicBool,
    armed: bool,
}
impl Drop for WorkerFailure<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.stop.store(true, Ordering::Release);
        }
    }
}

fn worker(
    jobs: &Mutex<Receiver<Job>>,
    results: &SyncSender<Completion>,
    source: &(impl Fn(&ObjectRef) -> ReadResult<Zeroizing<Vec<u8>>> + Sync),
    check: &(impl Fn() -> ReadResult<()> + Sync),
    deadline: OriginalDeadline,
    effective_deadline: Instant,
    stop: &AtomicBool,
) -> ReadResult<()> {
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        checked(deadline, stop, check)?;
        let remaining = effective_deadline
            .checked_duration_since(Instant::now())
            .ok_or(RecordError::Invalid)?;
        let next = {
            let receiver = request_deadline::lock_until(jobs, effective_deadline)
                .map_err(|_| RecordError::Invalid)?;
            receiver.recv_timeout(remaining.min(WAKE_INTERVAL))
        };
        let job = match next {
            Ok(job) => job,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        };
        checked(deadline, stop, check)?;
        let bytes = source(&job.reference)?;
        if bytes.len() != job.reference.encoded_bytes as usize {
            return Err(RecordError::Corrupt);
        }
        checked(deadline, stop, check)?;
        results
            .try_send(Completion {
                sequence: job.sequence,
                reference: job.reference,
                bytes,
            })
            .map_err(|_| RecordError::Invalid)?;
    }
}

pub(super) fn with_reader<'a, I, S, D, C, T>(
    references: I,
    source: &'a S,
    before_delivery: &'a D,
    check: &'a C,
    deadline: OriginalDeadline,
    stop: &'a AtomicBool,
    consume: impl FnOnce(&PrefetchReader<'a, I, D, C>) -> ExportResult<T>,
) -> ExportResult<T>
where
    I: Iterator<Item = ReadResult<ObjectRef>>,
    S: Fn(&ObjectRef) -> ReadResult<Zeroizing<Vec<u8>>> + Sync,
    D: Fn() -> ReadResult<()> + Sync,
    C: Fn() -> ReadResult<()> + Sync,
{
    checked(deadline, stop, check).map_err(|_| super::rejected())?;
    // Preserve a shorter current nested scope as well as the original owner;
    // never recapture a fresh budget on a worker.
    let effective_deadline = request_deadline::current()
        .ok_or_else(super::rejected)?
        .min(deadline.instant());
    let (job_sender, job_receiver) = mpsc::sync_channel(MAX_OUTSTANDING);
    let (result_sender, result_receiver) = mpsc::sync_channel(MAX_OUTSTANDING);
    let jobs = Mutex::new(job_receiver);
    std::thread::scope(|scope| {
        let reader = PrefetchReader {
            window: RefCell::new(Window {
                references: references.peekable(),
                pending: VecDeque::new(),
                encoded_bytes: 0,
                next_sequence: 0,
                jobs: Some(job_sender),
                results: Some(result_receiver),
            }),
            before_delivery,
            check,
            deadline,
            effective_deadline,
            stop,
            completed: Cell::new(false),
        };
        reader.fill().map_err(|_| super::rejected())?;
        let worker_count = reader.window.borrow().pending.len().min(MAX_WORKERS);
        let mut workers = Vec::with_capacity(worker_count);
        let mut spawn_failed = false;
        for index in 0..worker_count {
            let jobs = &jobs;
            let result_sender = &result_sender;
            let spawned = std::thread::Builder::new()
                .name(format!("kv2-export-{index}"))
                .spawn_scoped(scope, move || {
                    let mut failure = WorkerFailure { stop, armed: true };
                    let _scope = RequestDeadlineScope::enter(effective_deadline);
                    if worker(
                        jobs,
                        result_sender,
                        source,
                        check,
                        deadline,
                        effective_deadline,
                        stop,
                    )
                    .is_err()
                    {
                        stop.store(true, Ordering::Release);
                    }
                    failure.armed = false;
                });
            match spawned {
                Ok(worker) => workers.push(worker),
                Err(_) => {
                    stop.store(true, Ordering::Release);
                    spawn_failed = true;
                    break;
                }
            }
        }
        let mut result = if spawn_failed {
            Err(super::rejected())
        } else {
            consume(&reader)
        };
        if result.is_ok() && reader.finish().is_err() {
            result = Err(super::rejected());
        }
        if result.is_err() {
            stop.store(true, Ordering::Release);
        }
        reader.window.borrow_mut().close();
        for worker in workers {
            if worker.join().is_err() {
                stop.store(true, Ordering::Release);
                if result.is_ok() {
                    result = Err(super::rejected());
                }
            }
        }
        if result.is_ok() && checked(deadline, stop, check).is_err() {
            result = Err(super::rejected());
        }
        if result.is_ok() {
            reader.completed.set(true);
        }
        result
    })
}

#[cfg(test)]
#[path = "kv2_native_lossless_prefetch_tests.rs"]
mod tests;
