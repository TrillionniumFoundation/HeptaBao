//! The synchronous HTTP/Service request's original deadline. No request data
//! is stored in Service/HaProcess or persisted. Async ReadIndex calls receive
//! an explicit task-local copy at the HaProcess block_on boundary.
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

thread_local! {
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

#[must_use]
pub(crate) struct RequestDeadlineScope {
    previous: Option<Instant>,
    // A thread-local guard must never move to another thread or async task.
    _thread: PhantomData<Rc<()>>,
}

impl RequestDeadlineScope {
    pub(crate) fn enter(deadline: Instant) -> Self {
        let previous = DEADLINE.with(|scope| {
            let previous = scope.get();
            scope.set(Some(previous.map_or(deadline, |outer| outer.min(deadline))));
            previous
        });
        Self {
            previous,
            _thread: PhantomData,
        }
    }
}
impl Drop for RequestDeadlineScope {
    fn drop(&mut self) {
        DEADLINE.with(|scope| scope.set(self.previous));
    }
}

pub(crate) fn current() -> Option<Instant> {
    DEADLINE.with(Cell::get)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockWaitError {
    Busy,
    Poisoned,
}

// Shared with the existing HTTP Service-writer acquisition. Keeping the check
// on both sides prevents an uncontended late lock from admitting a result.
pub(crate) fn lock_until<T>(
    mutex: &Mutex<T>,
    deadline: Instant,
) -> Result<MutexGuard<'_, T>, LockWaitError> {
    let deadline = current().map_or(deadline, |outer| outer.min(deadline));
    loop {
        if Instant::now() >= deadline {
            return Err(LockWaitError::Busy);
        }
        match mutex.try_lock() {
            Ok(guard) => {
                if Instant::now() >= deadline {
                    return Err(LockWaitError::Busy);
                }
                return Ok(guard);
            }
            Err(TryLockError::Poisoned(_)) => return Err(LockWaitError::Poisoned),
            Err(TryLockError::WouldBlock) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(LockWaitError::Busy);
                }
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(2)),
                );
            }
        }
    }
}

/// Only the Service's HA control lock participates in this implicit scope.
/// Other subsystem locks and all write completion semantics are unchanged.
pub(crate) trait HaLock {
    fn lock_for_request(&self) -> Result<MutexGuard<'_, crate::ha::HaProcess>, LockWaitError>;
}
impl HaLock for Mutex<crate::ha::HaProcess> {
    fn lock_for_request(&self) -> Result<MutexGuard<'_, crate::ha::HaProcess>, LockWaitError> {
        match current() {
            Some(deadline) => lock_until(self, deadline),
            // Lifecycle/startup callers have no HTTP request. Preserve their
            // locking behavior; ReadIndex still has the runtime 8s bound.
            None => self.lock().map_err(|_| LockWaitError::Poisoned),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_restore_after_early_return_unwind_and_do_not_cross_threads()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(current().is_none());
        let outer = Instant::now() + Duration::from_secs(30);
        let guard = RequestDeadlineScope::enter(outer);
        let shorter = Instant::now() + Duration::from_secs(1);
        fn early_return(
            deadline: Instant,
            result: Result<(), &'static str>,
        ) -> Result<(), &'static str> {
            let _inner = RequestDeadlineScope::enter(deadline);
            assert_eq!(current(), Some(deadline));
            result?;
            Ok(())
        }
        let early = early_return(shorter, Err("early return"));
        assert!(early.is_err());
        assert_eq!(current(), Some(outer));
        let unwind = std::panic::catch_unwind(|| {
            let _inner = RequestDeadlineScope::enter(shorter);
            let _cannot_extend = RequestDeadlineScope::enter(outer);
            assert_eq!(current(), Some(shorter));
            std::panic::resume_unwind(Box::new("deadline unwind test"));
        });
        assert!(unwind.is_err());
        assert_eq!(current(), Some(outer));
        let isolated = std::thread::spawn(current)
            .join()
            .map_err(|_| "thread failed")?;
        assert!(isolated.is_none());
        drop(guard);
        assert!(current().is_none());
        Ok(())
    }
}
