//! One same-thread observation of an actual terminal clock publication.
//! This collector creates no receipt, actor, deadline or publication authority.
//! The original writer owns construction of the non-clone affine receipt.
use super::{Service, TerminalClockReceipt, plugin};
use crate::state_record_root::StateIdentity;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Weak, atomic::AtomicBool};

pub(in crate::service) type Checkpoint = (StateIdentity, plugin::PublicationGeneration);
struct Slot {
    owner: Weak<AtomicBool>,
    data_dir: PathBuf,
    expected: Checkpoint,
    receipt: Option<TerminalClockReceipt>,
    invalid: bool,
}
impl Slot {
    fn matches(&self, service: &Service) -> bool {
        self.owner
            .ptr_eq(&Arc::downgrade(&service.native_kv2_large_flight))
            && self.data_dir == service.data_dir
    }
}
thread_local! {
    static SLOT: RefCell<Option<Slot>> = const { RefCell::new(None) };
}

pub(in crate::service) struct Scope {
    active: bool,
    _thread: PhantomData<Rc<()>>,
}
impl Scope {
    pub(in crate::service) fn enter(service: &Service, expected: Checkpoint) -> Result<Self, ()> {
        SLOT.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| ())?;
            if let Some(prior) = slot.as_mut() {
                prior.invalid = true;
                return Err(());
            }
            *slot = Some(Slot {
                owner: Arc::downgrade(&service.native_kv2_large_flight),
                data_dir: service.data_dir.clone(),
                expected,
                receipt: None,
                invalid: false,
            });
            Ok(Self {
                active: true,
                _thread: PhantomData,
            })
        })
    }
    pub(in crate::service) fn finish(mut self, service: &Service) -> Result<bool, ()> {
        let captured = SLOT.with(|slot| slot.try_borrow_mut().map_err(|_| ())?.take().ok_or(()));
        let mut captured = captured?;
        self.active = false;
        if captured.invalid || !captured.matches(service) {
            return Err(());
        }
        let mut checkpoint = Some(captured.expected);
        let advanced = captured.receipt.is_some();
        if let Some(receipt) = captured.receipt.take() {
            receipt.advance(&mut checkpoint);
        }
        let actual = (
            service.current_state_identity().map_err(|_| ())?,
            service.external_effect_generation().map_err(|_| ())?,
        );
        if checkpoint != Some(actual) {
            return Err(());
        }
        Ok(advanced)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if self.active {
            SLOT.with(|slot| {
                if let Ok(mut slot) = slot.try_borrow_mut() {
                    slot.take();
                }
            });
        }
    }
}

pub(super) fn requested(service: &Service) -> bool {
    SLOT.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return false;
        };
        let Some(slot) = slot.as_mut() else {
            return false;
        };
        if !slot.matches(service) {
            slot.invalid = true;
            return false;
        }
        !slot.invalid
    })
}
pub(super) fn record(service: &Service, receipt: TerminalClockReceipt) {
    SLOT.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return;
        };
        let Some(slot) = slot.as_mut() else {
            return;
        };
        if slot.invalid
            || !slot.matches(service)
            || slot.receipt.is_some()
            || receipt.before != slot.expected
            || receipt.before == receipt.after
        {
            slot.invalid = true;
            return;
        }
        slot.receipt = Some(receipt);
    });
}
