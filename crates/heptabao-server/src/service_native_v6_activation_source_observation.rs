//! Test-only observation of the actual admitted V5 source before migration.
//! No production route, mutation, clock override or publication authority.
use crate::service::Service;
use crate::state_record_root::StateIdentity;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

thread_local! {
    static OBSERVED: RefCell<Option<Option<StateIdentity>>> = const { RefCell::new(None) };
}

// A guard cannot move to another thread and observe or clear another request.
pub(crate) struct ObservationGuard {
    _same_thread: PhantomData<Rc<()>>,
}
pub(crate) fn arm() -> Result<ObservationGuard, &'static str> {
    OBSERVED.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("activation source observation already armed");
        }
        *slot = Some(None);
        Ok(ObservationGuard { _same_thread: PhantomData })
    })
}
pub(super) fn record(service: &Service) {
    OBSERVED.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(observed) = slot.as_mut() else {
            return;
        };
        assert!(observed.is_none(), "one activation observation cannot record two requests");
        let identity = match service.current_state_identity() {
            Ok(identity) => identity,
            Err(_) => panic!("actual admitted activation source is unavailable"),
        };
        assert!(matches!(identity, StateIdentity::RecordsV5(_)));
        assert!(service.native_root.is_none());
        *observed = Some(identity);
    });
}
impl ObservationGuard {
    pub(crate) fn take(self) -> Result<StateIdentity, &'static str> {
        OBSERVED.with(|slot| slot.borrow_mut().take().flatten())
            .ok_or("actual activation boundary was not observed")
    }
}
impl Drop for ObservationGuard {
    fn drop(&mut self) {
        OBSERVED.with(|slot| { slot.borrow_mut().take(); });
    }
}
