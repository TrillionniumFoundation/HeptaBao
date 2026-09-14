//! Idle expiry uses exactly the existing Service writer and Raft commit path.
//! This is not a general external-provider revocation executor. No HTTP caller
//! can choose its time, broaden its operation, or pass a bearer credential.
use super::*;
use std::{
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

impl Service {
    pub(super) fn maintain_lifetimes_at(&mut self, now: u64) -> Result<bool, &'static str> {
        if self.state.is_none() {
            return Ok(false);
        }
        if self.recovery_required || self.audit_failed {
            return Err("lifecycle maintenance requires recovery");
        }
        if let Some(ha) = &self.ha {
            let ha = ha.lock().map_err(|_| "lifecycle HA lock unavailable")?;
            let local = ha
                .local_id()
                .map_err(|_| "lifecycle HA identity unavailable")?;
            if ha.leader().map_err(|_| "lifecycle leader unavailable")? != Some(local) {
                return Ok(false);
            }
            drop(ha);
            self.sync_from_ha()
                .map_err(|_| "lifecycle ReadIndex unavailable")?;
        }
        let Some(mut next) = self.state.clone() else {
            return Ok(false);
        };
        if !next.auth.has_live_wrappers() && !next.engines.has_live_leases() {
            return Ok(false);
        }
        let changed = Self::reconcile_lease_owners(&mut next, now)
            | (next.auth.has_live_wrappers() && next.auth.advance_wrapping_clock(now));
        if !changed {
            return Ok(false);
        }
        let fingerprint = self.request_fingerprint("INTERNAL", "lifecycle/expiry", "", "");
        self.audit_event("lifecycle-request", &fingerprint, now, None)
            .map_err(|_| "lifecycle request audit unavailable")?;
        next.schema = CURRENT_STATE_SCHEMA;
        let result = self.commit_state(&next);
        if result.is_ok() {
            self.state = Some(next);
        }
        let status = if result.is_ok() { 204 } else { 503 };
        if self
            .audit_event("lifecycle-response", &fingerprint, now, Some(status))
            .is_err()
        {
            self.recovery_required = true;
            return Err("lifecycle result audit unavailable; recovery required");
        }
        result.map_err(|_| "lifecycle commit failed; no success inferred")?;
        Ok(true)
    }
}

/// One host-owned worker, no unbounded queue or detached retry tasks. Drop wakes
/// and joins it. try_lock avoids waiting behind an active request. A tick only
/// invalidates expired/revoked local leases and erases expired wrapped payloads.
pub(crate) struct LifecycleWorker {
    stop: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
}
impl Drop for LifecycleWorker {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
pub(crate) fn start_lifecycle_worker(
    service: &Arc<Mutex<Service>>,
    interval: Duration,
) -> Result<Option<LifecycleWorker>, String> {
    if interval.is_zero() {
        return Ok(None);
    }
    if interval < Duration::from_secs(1) || interval > Duration::from_secs(60) {
        return Err("lifecycle interval exceeds bounds".into());
    }
    let service = Arc::downgrade(service);
    let (stop, receiver) = mpsc::channel();
    let join = thread::Builder::new()
        .name("heptabao-lifecycle".into())
        .spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) = receiver.recv_timeout(interval) {
                let Some(service) = service.upgrade() else {
                    break;
                };
                let Ok(mut writer) = service.try_lock() else {
                    continue;
                };
                // Clock failure is not time zero and may not undo an observed expiry.
                let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                    continue;
                };
                if writer.maintain_lifetimes_at(now.as_secs()).is_err() {
                    // Fixed text only. The Service recovery fence decides whether
                    // another bounded tick may attempt a transient ReadIndex failure.
                    eprintln!("heptabao-lifecycle: maintenance unavailable");
                }
            }
        })
        .map_err(|_| "cannot start lifecycle worker")?;
    Ok(Some(LifecycleWorker {
        stop,
        join: Some(join),
    }))
}
