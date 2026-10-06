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

/// Two host-owned workers, each with at most one admitted effect and no task queue.
/// Public ACME network proof cannot block lease cleanup. Drop wakes and joins
/// both workers. try_lock avoids waiting behind an active request. The lifecycle
/// worker advances at most one provider effect, consensus administration and
/// local expiry per tick; the proof worker owns one original ACME attempt.
pub(crate) struct LifecycleWorker {
    stop: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
    acme_stop: mpsc::Sender<()>,
    acme_join: Option<JoinHandle<()>>,
}

pub(super) enum ProviderMaintenance {
    Acme(Box<pki_acme::ChallengeAttempt>),
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

// SDK callback I/O has its own configured entry budget. It is fixed before
// any SDK cleanup authority is issued, from the same native clock's accepted
// start; no deadline is refreshed after a plan or effect has been admitted.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prepare_sdk_provider(writer: &mut Service, clock: RequestClock) -> Option<ProviderMaintenance> {
    let config = writer.sdk_configuration.as_ref()?;
    let deadline = clock
        .started()
        .checked_add(Duration::from_millis(config.timeout_ms))?;
    if std::time::Instant::now() >= deadline {
        return None;
    }
    let _sdk_scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    writer
        .prepare_sdk_expiry(clock)
        .ok()
        .flatten()
        .map(|plan| ProviderMaintenance::Sdk(Box::new(plan)))
}

fn prepare_provider_maintenance(
    writer: &mut Service,
    now: u64,
    clock: RequestClock,
    generic_deadline: std::time::Instant,
    include_acme: bool,
) -> Option<ProviderMaintenance> {
    let prefer_acme = writer.lifecycle_acme_preferred;
    writer.lifecycle_acme_preferred = !prefer_acme;
    if include_acme
        && prefer_acme
        && let Ok(Some(plan)) = writer.prepare_acme_maintenance(clock)
    {
        return Some(ProviderMaintenance::Acme(Box::new(plan)));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let sdk_preferred = {
        writer.lifecycle_sdk_cursor = (writer.lifecycle_sdk_cursor + 1) % 3;
        if writer.lifecycle_sdk_cursor == 0 {
            prepare_sdk_provider(writer, clock)
        } else {
            None
        }
    };
    let prefer_openldap = writer.lifecycle_provider_cursor;
    writer.lifecycle_provider_cursor = !prefer_openldap;
    let mut other = || {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(generic_deadline);
        if prefer_openldap {
            match writer.prepare_openldap_maintenance_with_clock(now, Some(clock)) {
                Ok(Some(value)) => Some(ProviderMaintenance::OpenLdap(Box::new(value))),
                Ok(None) | Err(_) => prepare_database_provider(writer, now, clock),
            }
        } else {
            match prepare_database_provider(writer, now, clock) {
                Some(value) => Some(value),
                None => match writer.prepare_openldap_maintenance_with_clock(now, Some(clock)) {
                    Ok(Some(value)) => Some(ProviderMaintenance::OpenLdap(Box::new(value))),
                    Ok(None) | Err(_) => None,
                },
            }
        }
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let pending = match sdk_preferred {
        Some(value) => Some(value),
        None => other().or_else(|| prepare_sdk_provider(writer, clock)),
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let pending = other();
    pending.or_else(|| {
        if !include_acme {
            return None;
        }
        writer
            .prepare_acme_maintenance(clock)
            .ok()
            .flatten()
            .map(|plan| ProviderMaintenance::Acme(Box::new(plan)))
    })
}

impl Drop for LifecycleWorker {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        let _ = self.acme_stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        if let Some(join) = self.acme_join.take() {
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
    let acme_service = service.clone();
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
                    let generic_deadline =
                        started + crate::request_deadline::IDLE_MAINTENANCE_READ_BUDGET;
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
                        next_interval = if writer.state.as_ref().is_some_and(|state| {
                            state.engines.has_live_sdk_leases()
                                || state.engines.has_pending_acme_challenges()
                        }) {
                            interval.min(Duration::from_secs(1))
                        } else {
                            interval
                        };
                    }
                    {
                        let _read_scope =
                            crate::request_deadline::RequestDeadlineScope::enter(generic_deadline);
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
                    }
                    // ACME admission happens only on the independent public-proof
                    // worker. Never create and discard an ACME or SDK Plan here.
                    prepare_provider_maintenance(&mut writer, now, clock, generic_deadline, false)
                };
                let Some(pending) = pending_provider else {
                    continue;
                };
                // No Service writer is held while provider I/O/readback runs.
                match pending {
                    ProviderMaintenance::Acme(plan) => {
                        let result = plan.execute(&service);
                        let Ok(mut writer) = service.try_lock() else {
                            continue;
                        };
                        if writer.finish_acme_maintenance(*plan, result).is_err() {
                            eprintln!("heptabao-lifecycle: ACME verification remains pending");
                        }
                    }
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
    let (acme_stop, acme_receiver) = mpsc::channel();
    let acme_join = thread::Builder::new()
        .name("heptabao-acme-proof".into())
        .spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) =
                acme_receiver.recv_timeout(interval.min(Duration::from_secs(1)))
            {
                let Some(service) = acme_service.upgrade() else {
                    break;
                };
                let started = std::time::Instant::now();
                let Ok(wall) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                    continue;
                };
                let Ok(clock) = RequestClock::anchored(wall, started) else {
                    continue;
                };
                let plan = {
                    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                        started + crate::request_deadline::IDLE_MAINTENANCE_READ_BUDGET,
                    );
                    let Ok(mut writer) = service.try_lock() else {
                        continue;
                    };
                    match writer.prepare_acme_maintenance(clock) {
                        Ok(Some(plan)) => plan,
                        Ok(None) | Err(_) => continue,
                    }
                };
                // Move the one admitted Plan with its original affine clock,
                // deadline, attempt identity and queue owner through I/O and
                // publication. There is no detached task or authority refresh.
                let result = plan.execute(&service);
                if acme_receiver.try_recv().is_ok() {
                    break;
                }
                let Ok(mut writer) = service.try_lock() else {
                    continue;
                };
                if writer.finish_acme_maintenance(plan, result).is_err() {
                    eprintln!("heptabao-acme-proof: verification remains pending");
                }
            }
        });
    let acme_join = match acme_join {
        Ok(value) => value,
        Err(_) => {
            let _ = stop.send(());
            let _ = join.join();
            return Err("cannot start ACME proof worker".into());
        }
    };
    Ok(Some(LifecycleWorker {
        stop,
        join: Some(join),
        acme_stop,
        acme_join: Some(acme_join),
    }))
}
