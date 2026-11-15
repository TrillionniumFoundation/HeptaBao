//! Test-only interleaving after the actual native response audit. No clock,
//! actor, publication receipt or consensus proof is constructed here.
use super::*;
use std::cell::RefCell;
type AfterAudit = Box<dyn FnOnce(&mut Service, &mut Response)>;
thread_local! { static AFTER_AUDIT: RefCell<Option<AfterAudit>> = RefCell::new(None); }

pub(super) fn after_actual_audit(service: &mut Service, response: &mut Response) {
    let hook = AFTER_AUDIT.with(|slot| slot.borrow_mut().take());
    crate::service::tests::run_after_actual_native_audit(service, response, hook);
}

pub(in crate::service) struct HookGuard;
impl Drop for HookGuard {
    fn drop(&mut self) {
        AFTER_AUDIT.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

pub(in crate::service) fn after_audit(
    hook: impl FnOnce(&mut Service, &mut Response) + 'static,
) -> Result<HookGuard, Box<dyn std::error::Error>> {
    AFTER_AUDIT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("native batch audit hook already armed".into());
        }
        *slot = Some(Box::new(hook));
        Ok(HookGuard)
    })
}
