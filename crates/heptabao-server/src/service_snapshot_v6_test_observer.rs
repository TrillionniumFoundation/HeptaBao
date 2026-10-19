//! Read-only test observation of the actual committed bundle, before an outer
//! terminal clock/audit write can hide a missing restore-time floor.
use super::*;

thread_local! {
    static COMMITTED: RefCell<Option<Box<dyn FnOnce(&Service)>>> = RefCell::new(None);
}

pub(in crate::service) struct SnapshotCommitObservation;
impl Drop for SnapshotCommitObservation {
    fn drop(&mut self) {
        COMMITTED.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

impl Service {
    pub(in crate::service) fn observe_next_native_snapshot_commit_for_test(
        observe: impl FnOnce(&Service) + 'static,
    ) -> Result<SnapshotCommitObservation, &'static str> {
        COMMITTED.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return Err("native snapshot observer already armed");
            }
            *slot = Some(Box::new(observe));
            Ok(SnapshotCommitObservation)
        })
    }
}

pub(super) fn committed(service: &Service) {
    let observe = COMMITTED.with(|slot| slot.borrow_mut().take());
    if let Some(observe) = observe {
        observe(service);
    }
}
