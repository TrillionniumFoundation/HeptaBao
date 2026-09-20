//! Idle expiry uses exactly the existing Service writer and Raft commit path.
//! Separate registered database reconciliation and Raft administration use the
//! same worker and writer. No HTTP caller can choose worker time or pass a bearer.
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
        let Some(current) = self.state.as_ref() else {
            return Ok(false);
        };
        if !current.auth.has_live_wrappers()
            && !current.engines.has_live_leases()
            && !current.engines.has_auto_rotate_keys()
        {
            return Ok(false);
        }
        let mut next = current.clone();
        let changed = Self::reconcile_lease_owners(&mut next, now)
            | (next.auth.has_live_wrappers() && next.auth.advance_wrapping_clock(now))
            | next
                .engines
                .maintain_auto_rotation(now)
                .map_err(|_| "transit auto-rotation failed")?;
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
/// advances at most one enrolled DB effect, one guarded consensus change and
/// the existing local expiry pass. Provider failure cannot suppress local expiry.
pub(crate) struct LifecycleWorker {
    stop: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
}

enum ProviderMaintenance {
    Database(database::DatabaseMaintenance),
    OpenLdap(openldap_secret::OpenLdapMaintenance),
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
                // Clock failure is not time zero and may not undo an observed expiry.
                let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                    continue;
                };
                let now = now.as_secs();
                let pending_provider = {
                    let Ok(mut writer) = service.try_lock() else {
                        continue;
                    };
                    if writer.maintain_raft_admin().is_err() {
                        eprintln!("heptabao-lifecycle: autopilot transition pending");
                    }
                    let prefer_openldap = writer.lifecycle_provider_cursor;
                    writer.lifecycle_provider_cursor = !prefer_openldap;
                    let pending = if prefer_openldap {
                        match writer.prepare_openldap_maintenance(now) {
                            Ok(Some(value)) => Some(ProviderMaintenance::OpenLdap(value)),
                            Ok(None) | Err(_) => match writer.prepare_database_maintenance(now) {
                                Ok(Some(value)) => Some(ProviderMaintenance::Database(value)),
                                Ok(None) | Err(_) => None,
                            },
                        }
                    } else {
                        match writer.prepare_database_maintenance(now) {
                            Ok(Some(value)) => Some(ProviderMaintenance::Database(value)),
                            Ok(None) | Err(_) => match writer.prepare_openldap_maintenance(now) {
                                Ok(Some(value)) => Some(ProviderMaintenance::OpenLdap(value)),
                                Ok(None) | Err(_) => None,
                            },
                        }
                    };
                    // Local expiry is deliberately completed before any remote
                    // provider wait. A failed or slow provider cannot suppress it.
                    if writer.maintain_lifetimes_at(now).is_err() {
                        eprintln!("heptabao-lifecycle: maintenance unavailable");
                    }
                    pending
                };
                let Some(pending) = pending_provider else {
                    continue;
                };
                // No Service writer is held while provider I/O/readback runs.
                match pending {
                    ProviderMaintenance::Database(pending) => {
                        let result = pending.execute();
                        let Ok(mut writer) = service.try_lock() else {
                            eprintln!("heptabao-lifecycle: provider finalize deferred");
                            continue;
                        };
                        if writer.finish_database_maintenance(pending, result).is_err() {
                            eprintln!("heptabao-lifecycle: provider reconciliation pending");
                        }
                    }
                    ProviderMaintenance::OpenLdap(pending) => {
                        let result = pending.plan.execute();
                        let Ok(mut writer) = service.try_lock() else {
                            eprintln!("heptabao-lifecycle: OpenLDAP finalize deferred");
                            continue;
                        };
                        if writer.finish_openldap_maintenance(pending, result).is_err() {
                            eprintln!("heptabao-lifecycle: OpenLDAP reconciliation pending");
                        }
                    }
                }
            }
        })
        .map_err(|_| "cannot start lifecycle worker")?;
    Ok(Some(LifecycleWorker {
        stop,
        join: Some(join),
    }))
}
