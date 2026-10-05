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
    #[cfg(test)]
    pub(super) fn maintain_lifetimes_at(&mut self, now: u64) -> Result<bool, &'static str> {
        self.maintain_lifetimes_with_clock(now, None)
    }
    fn maintain_lifetimes_with_clock(
        &mut self,
        now: u64,
        clock: Option<RequestClock>,
    ) -> Result<bool, &'static str> {
        if self.state.is_none() {
            return Ok(false);
        }
        if self.recovery_required || self.audit_failed {
            return Err("lifecycle maintenance requires recovery");
        }
        if let Some(ha) = &self.ha {
            let ha = ha
                .lock_for_request()
                .map_err(|_| "lifecycle HA lock unavailable")?;
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
            && !current.engines.has_local_pki_crl_state()
        {
            return Ok(false);
        }
        // Refresh the original trusted clock after ReadIndex/lock acquisition.
        // Provider execution below cannot supply or reset this authority time.
        let time = match clock {
            Some(clock) => AuthorityTime::Precise(
                clock
                    .with_seconds_floor(now)
                    .and_then(RequestClock::observed_at)
                    .map_err(|_| "lifecycle precise clock unavailable")?,
            ),
            None => AuthorityTime::Coarse(now),
        };
        let now = time.seconds();
        let mut next = current.clone();
        let changed = Self::reconcile_lease_owners_observed(&mut next, time)
            .map_err(|_| "lease and PKI CRL maintenance failed")?
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
        next.schema = next.writer_schema();
        let result = self.commit_state(&mut next);
        if result.is_ok() {
            self.state = Some(next);
        }
        let status = if result.is_ok() { 204 } else { 503 };
        if self
            .audit_event("lifecycle-response", &fingerprint, now, Some(status))
            .is_err()
        {
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Sdk(Box<sdk_backend::Plan>),
    Database(Box<database::DatabaseMaintenance>),
    DatabaseRotation(Box<database::DatabaseRotationMaintenance>),
    OpenLdap(Box<openldap_secret::OpenLdapMaintenance>),
}
fn prepare_database_provider(
    writer: &mut Service,
    now: u64,
    clock: RequestClock,
) -> Option<ProviderMaintenance> {
    let prefer_rotation = writer.lifecycle_database_rotation_cursor;
    writer.lifecycle_database_rotation_cursor = !prefer_rotation;
    if prefer_rotation {
        match writer.prepare_database_rotation_maintenance(now) {
            Ok(Some(value)) => Some(ProviderMaintenance::DatabaseRotation(Box::new(value))),
            Ok(None) | Err(_) => writer
                .prepare_database_maintenance_with_clock(now, Some(clock))
                .ok()
                .flatten()
                .map(|value| ProviderMaintenance::Database(Box::new(value))),
        }
    } else {
        match writer.prepare_database_maintenance_with_clock(now, Some(clock)) {
            Ok(Some(value)) => Some(ProviderMaintenance::Database(Box::new(value))),
            Ok(None) | Err(_) => writer
                .prepare_database_rotation_maintenance(now)
                .ok()
                .flatten()
                .map(|value| ProviderMaintenance::DatabaseRotation(Box::new(value))),
        }
    }
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
            let mut next_interval = interval;
            while let Err(mpsc::RecvTimeoutError::Timeout) = receiver.recv_timeout(next_interval) {
                let Some(service) = service.upgrade() else {
                    break;
                };
                // Clock failure is not time zero and may not undo an observed expiry.
                let started = std::time::Instant::now();
                let Ok(wall) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                    continue;
                };
                let Ok(clock) = RequestClock::anchored(wall, started) else {
                    continue;
                };
                let now = wall.as_secs();
                let pending_provider = {
                    let _read_scope = crate::request_deadline::RequestDeadlineScope::enter(
                        std::time::Instant::now()
                            + crate::request_deadline::IDLE_MAINTENANCE_READ_BUDGET,
                    );
                    // One absolute read budget covers this idle pass. Timeout
                    // releases an observation attempt, never a started durable
                    // effect, and cannot authorize a cached or stale state.
                    let Ok(mut writer) = service.try_lock() else {
                        continue;
                    };
                    // Pending SDK cleanup keeps the same host-owned worker awake;
                    // every attempt still captures its own native affine clock.
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    {
                        next_interval = if writer
                            .state
                            .as_ref()
                            .is_some_and(|state| state.engines.has_live_sdk_leases())
                        {
                            interval.min(Duration::from_secs(1))
                        } else {
                            interval
                        };
                    }
                    if writer.maintain_raft_admin().is_err() {
                        eprintln!("heptabao-lifecycle: autopilot transition pending");
                    }
                    // Local expiry is deliberately completed before any remote
                    // provider wait. A failed or slow provider cannot suppress it.
                    if writer
                        .maintain_lifetimes_with_clock(now, Some(clock))
                        .is_err()
                    {
                        eprintln!("heptabao-lifecycle: maintenance unavailable");
                    }
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    let sdk_preferred = {
                        writer.lifecycle_sdk_cursor = (writer.lifecycle_sdk_cursor + 1) % 3;
                        if writer.lifecycle_sdk_cursor == 0 {
                            writer
                                .prepare_sdk_expiry(clock)
                                .ok()
                                .flatten()
                                .map(|plan| ProviderMaintenance::Sdk(Box::new(plan)))
                        } else {
                            None
                        }
                    };
                    let prefer_openldap = writer.lifecycle_provider_cursor;
                    writer.lifecycle_provider_cursor = !prefer_openldap;
                    let mut other = || {
                        if prefer_openldap {
                            match writer.prepare_openldap_maintenance_with_clock(now, Some(clock)) {
                                Ok(Some(value)) => {
                                    Some(ProviderMaintenance::OpenLdap(Box::new(value)))
                                }
                                Ok(None) | Err(_) => {
                                    prepare_database_provider(&mut writer, now, clock)
                                }
                            }
                        } else {
                            match prepare_database_provider(&mut writer, now, clock) {
                                Some(value) => Some(value),
                                None => match writer
                                    .prepare_openldap_maintenance_with_clock(now, Some(clock))
                                {
                                    Ok(Some(value)) => {
                                        Some(ProviderMaintenance::OpenLdap(Box::new(value)))
                                    }
                                    Ok(None) | Err(_) => None,
                                },
                            }
                        }
                    };
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    let pending = match sdk_preferred {
                        Some(value) => Some(value),
                        None => other().or_else(|| {
                            writer
                                .prepare_sdk_expiry(clock)
                                .ok()
                                .flatten()
                                .map(|plan| ProviderMaintenance::Sdk(Box::new(plan)))
                        }),
                    };
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    let pending = other();
                    pending
                };
                let Some(pending) = pending_provider else {
                    continue;
                };
                // No Service writer is held while provider I/O/readback runs.
                match pending {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    ProviderMaintenance::Sdk(plan) => {
                        let result = plan.execute(&service, plan.deadline);
                        // An owned SDK attempt retains its exact Plan until the
                        // Service writer observes and audits its terminal result.
                        let _scope =
                            crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
                        let Ok(mut writer) = sdk_backend::writer_before(&service, plan.deadline)
                        else {
                            continue;
                        };
                        if writer.finish_sdk_expiry(*plan, result).is_err() {
                            eprintln!("heptabao-lifecycle: SDK revoke remains pending");
                        }
                    }
                    ProviderMaintenance::Database(pending) => {
                        let result = pending.execute();
                        let Ok(mut writer) = service.try_lock() else {
                            eprintln!("heptabao-lifecycle: provider finalize deferred");
                            continue;
                        };
                        if writer
                            .finish_database_maintenance(*pending, result)
                            .is_err()
                        {
                            eprintln!("heptabao-lifecycle: provider reconciliation pending");
                        }
                    }
                    ProviderMaintenance::DatabaseRotation(pending) => {
                        let result = pending.execute();
                        let Ok(mut writer) = service.try_lock() else {
                            eprintln!("heptabao-lifecycle: database rotation finalize deferred");
                            continue;
                        };
                        if writer
                            .finish_database_rotation_maintenance(*pending, result)
                            .is_err()
                        {
                            eprintln!("heptabao-lifecycle: database rotation pending");
                        }
                    }
                    ProviderMaintenance::OpenLdap(pending) => {
                        let result = pending.plan.execute();
                        let Ok(mut writer) = service.try_lock() else {
                            eprintln!("heptabao-lifecycle: OpenLDAP finalize deferred");
                            continue;
                        };
                        if writer
                            .finish_openldap_maintenance(*pending, result)
                            .is_err()
                        {
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
