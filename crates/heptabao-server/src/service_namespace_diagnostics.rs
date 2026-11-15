//! Test-only fixed namespace rejection stages. No body, error text, identity,
//! path, key, registration or provider input is read or written here.
use super::Response;
use std::cell::Cell;

thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
}

pub(super) struct Scope {
    previous: bool,
}
impl Scope {
    pub(super) fn enter() -> Self {
        Self {
            previous: ENABLED.with(|enabled| enabled.replace(true)),
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        ENABLED.with(|enabled| enabled.set(self.previous));
    }
}

pub(super) fn record<T>(stage: &'static str, result: &Result<T, Response>) {
    if let Err(error) = result {
        record_status(stage, error.status);
    }
}

pub(super) fn record_status(stage: &'static str, status: u16) {
    if ENABLED.with(Cell::get) {
        eprintln!("HBNAMESPACE-Q09 stage={stage} status={status}");
    }
}
