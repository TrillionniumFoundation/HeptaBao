//! Accepted AppRole cleanup runs under its own native clock and mount owner.
//! The HTTP actor is retained only through admission and mandatory response audit.
use super::*;
use crate::auth::approle_tidy::{AppRoleTidyOwner, Cursor};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

const STARTED: &str = "Tidy operation successfully started. Any information from the operation will be printed to OpenBao's server logs.";
const BUSY: &str = "Tidy operation already in progress.";
const PERIOD: Duration = Duration::from_secs(60);
const TASK_BUDGET: Duration = Duration::from_secs(60);
const MAX_JOBS: usize = 128;

fn unavailable() -> Response {
    Response::error(503, "AppRole tidy native owner unavailable")
}
fn auth_error(error: crate::auth::AuthError) -> Response {
    Response::error(error.status, &error.message)
}
fn seal_digest(service: &Service) -> Result<[u8; 32], Response> {
    let seal = service.seal.as_ref().ok_or_else(unavailable)?;
    let bytes = zeroize::Zeroizing::new(
        crate::secret_serde::to_vec(seal, 512 * 1024).map_err(|_| unavailable())?,
    );
    Ok(crypto::digest(&bytes))
}
fn barrier_digest(service: &Service) -> Result<[u8; 32], Response> {
    service
        .barrier_key
        .as_ref()
        .map(|key| crypto::digest(key.as_ref()))
        .ok_or_else(unavailable)
}
struct BusyGuard(Arc<AtomicBool>);
impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
pub(in crate::service) struct Slot {
    owner: AppRoleTidyOwner,
    busy: Weak<AtomicBool>,
}
pub(in crate::service) struct Accepted {
    actor: plugin::PluginResponseAuthority,
    task: Option<Task>,
}
/// Non-cloneable, non-serialized native task; never carries a Principal.
pub(in crate::service) struct Task {
    owner: AppRoleTidyOwner,
    _guard: BusyGuard,
    clock: RequestClock,
    deadline: Instant,
    cluster: String,
    incarnation: Option<u64>,
    delivery: namespace_runtime::DeliveryBinding,
    leases: namespace_runtime::Leases,
    nonce: String,
    seal: [u8; 32],
    barrier: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
    role: Option<(u64, u64)>,
    cursor: Option<Cursor>,
    checked: usize,
    removed: usize,
    fingerprint: String,
}
impl Task {
    fn capture(
        service: &Service,
        owner: AppRoleTidyOwner,
        guard: BusyGuard,
        clock: RequestClock,
        deadline: Instant,
    ) -> Result<Self, Response> {
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let role = if let Some(ha) = &service.ha {
            let node = ha.lock_for_request().map_err(|_| unavailable())?;
            let value = node.leader_status().map_err(|_| unavailable())?;
            if !value.local_is_leader || value.leader != Some(value.local_id) {
                return Err(unavailable());
            }
            Some((value.local_id, value.term))
        } else {
            None
        };
        let task = Self {
            incarnation: state.namespaces.incarnation(owner.namespace()),
            delivery: namespace_runtime::DeliveryBinding::capture(state, owner.namespace()),
            leases: state.namespace_leases.clone(),
            cluster: state.cluster_id.clone(),
            nonce: service.unseal_nonce.clone(),
            seal: seal_digest(service)?,
            barrier: barrier_digest(service)?,
            ha: service.ha.clone(),
            role,
            fingerprint: hex(&crypto::random::<32>().map_err(|_| unavailable())?),
            owner,
            _guard: guard,
            clock,
            deadline,
            cursor: None,
            checked: 0,
            removed: 0,
        };
        task.check(service)?;
        Ok(task)
    }
    fn check_deadline(&self) -> Result<(), Response> {
        self.clock.observed_at().map_err(|_| unavailable())?;
        if Instant::now() >= self.deadline {
            return Err(unavailable());
        }
        Ok(())
    }
    fn time(&self, auth: &AuthState) -> Result<Timestamp, Response> {
        self.check_deadline()?;
        auth.token_api_observed_time(AuthorityTime::Precise(
            self.clock.observed_at().map_err(|_| unavailable())?,
        ))
        .exact()
        .ok_or_else(unavailable)
    }
    fn check_role(&self, service: &Service) -> Result<(), Response> {
        self.check_deadline()?;
        match (&self.ha, &service.ha, self.role) {
            (None, None, None) => Ok(()),
            (Some(original), Some(current), Some(expected)) if Arc::ptr_eq(original, current) => {
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
                let node = current.lock_for_request().map_err(|_| unavailable())?;
                let before = node.leader_status().map_err(|_| unavailable())?;
                if !before.local_is_leader
                    || before.leader != Some(before.local_id)
                    || (before.local_id, before.term) != expected
                {
                    return Err(unavailable());
                }
                node.ensure_application_identity(service.current_state_identity()?)
                    .map_err(|_| unavailable())?;
                let after = node.leader_status().map_err(|_| unavailable())?;
                if !after.local_is_leader
                    || after.leader != Some(after.local_id)
                    || (after.local_id, after.term) != expected
                {
                    return Err(unavailable());
                }
                Ok(())
            }
            _ => Err(unavailable()),
        }
    }
    fn check_state(&self, service: &Service, state: &State) -> Result<(), Response> {
        self.check_deadline()?;
        self.leases.validate()?;
        state.namespace_leases.validate()?;
        state.validate_namespace_deletion_state()?;
        let namespace = self.owner.namespace();
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.nonce
            || seal_digest(service)? != self.seal
            || barrier_digest(service)? != self.barrier
            || state.cluster_id != self.cluster
            || !state.namespace_exists(namespace)
            || state.namespace_is_tainted(namespace)
            || state.namespace_is_sealed(namespace)
            || state.namespaces.incarnation(namespace) != self.incarnation
            || namespace_runtime::DeliveryBinding::capture(state, namespace) != self.delivery
            || state.namespaces.inherited_owner(namespace).is_some()
                && !service.namespace_runtime.is_loaded(namespace)
        {
            return Err(unavailable());
        }
        self.owner.check(&state.auth).map_err(auth_error)
    }
    fn check(&self, service: &Service) -> Result<(), Response> {
        self.check_role(service)?;
        self.check_state(service, service.state.as_ref().ok_or_else(unavailable)?)
    }
    fn step(&mut self, service: &mut Service) -> Result<bool, Response> {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
        // A synchronization cannot adopt a new leader, term, mount, clock or deadline.
        self.check_role(service)?;
        if self.ha.is_some() {
            service.sync_from_ha_with_anchor(false)?;
        }
        self.check(service)?;
        let current = service.state.as_ref().ok_or_else(unavailable)?;
        let expected = service.current_state_identity()?;
        let at = self.time(&current.auth)?;
        service
            .audit_event(
                "approle-tidy-task-request",
                &self.fingerprint,
                at.seconds(),
                None,
            )
            .map_err(|_| unavailable())?;
        let mut candidate = service.state.as_ref().ok_or_else(unavailable)?.clone();
        let batch = candidate
            .auth
            .native_approle_tidy_batch(&self.owner, self.cursor.as_ref(), at)
            .map_err(auth_error)?;
        if batch.changed {
            service.prepare_approle_tidy_record_root(&mut candidate)?;
            candidate.schema = candidate.writer_schema();
            candidate.validate_format()?;
            let plan = service.prepare_record_plan(&mut candidate)?;
            self.check(service)?;
            self.check_state(service, &candidate)?;
            if service.current_state_identity()? != expected {
                return Err(unavailable());
            }
            service.commit_record_plan_with_native_role(
                &candidate,
                plan,
                self.role,
                |live_auth| {
                    self.check_deadline()?;
                    self.owner.check(live_auth).map_err(auth_error)?;
                    candidate.namespace_leases.validate()?;
                    candidate.validate_namespace_deletion_state()?;
                    if namespace_runtime::DeliveryBinding::capture(
                        &candidate,
                        self.owner.namespace(),
                    ) != self.delivery
                    {
                        return Err(unavailable());
                    }
                    self.check_deadline()
                },
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )?;
            // Cursor progress follows only this actual durable publication.
            service.state = Some(candidate);
            self.check(service)?;
        }
        self.checked = self
            .checked
            .checked_add(batch.checked)
            .ok_or_else(unavailable)?;
        self.removed = self
            .removed
            .checked_add(batch.removed)
            .ok_or_else(unavailable)?;
        let complete = batch.cursor.is_none();
        self.cursor = batch.cursor;
        let at = self.time(&service.state.as_ref().ok_or_else(unavailable)?.auth)?;
        if service
            .audit_event(
                "approle-tidy-task-response",
                &self.fingerprint,
                at.seconds(),
                Some(200),
            )
            .is_err()
        {
            service.recovery_required = true;
            service.ha_activation = None;
            return Err(unavailable());
        }
        self.check(service)?;
        Ok(complete)
    }
}
impl Service {
    fn reserve_approle_tidy(
        &mut self,
        owner: &AppRoleTidyOwner,
    ) -> Result<Option<BusyGuard>, Response> {
        self.approle_tidy_slots
            .retain(|_, slot| slot.busy.strong_count() != 0);
        let key = (owner.namespace().into(), owner.mount().into());
        let busy = self
            .approle_tidy_slots
            .get(&key)
            .filter(|slot| slot.owner == *owner)
            .and_then(|slot| slot.busy.upgrade())
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        if busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(None);
        }
        let guard = BusyGuard(Arc::clone(&busy));
        if self.approle_tidy_jobs.len() >= MAX_JOBS {
            return Err(Response::error(507, "AppRole tidy task capacity exhausted"));
        }
        self.approle_tidy_slots.insert(
            key,
            Slot {
                owner: owner.clone(),
                busy: Arc::downgrade(&busy),
            },
        );
        Ok(Some(guard))
    }
    pub(in crate::service) fn stage_approle_tidy(
        &mut self,
        admitted: &State,
        actor: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let result = (|| {
            let owner = admitted
                .auth
                .admit_approle_tidy(
                    actor.as_ref(),
                    request.namespace,
                    request.method,
                    request.path,
                    request.body,
                    request.token_time()?,
                )
                .map_err(auth_error)?;
            let actor = actor.ok_or_else(|| Response::error(403, "permission denied"))?;
            let mut authority = plugin::PluginResponseAuthority::new(
                actor,
                admitted,
                request,
                "update",
                false,
                &self.unseal_nonce,
            );
            self.validate_plugin_response(&mut authority)?;
            let (task, mut response) = if let Some(guard) = self.reserve_approle_tidy(&owner)? {
                // A distinct native span starts from trusted admission time, not
                // client-selected wall time or the original HTTP deadline.
                let at = request.token_time()?.exact().ok_or_else(unavailable)?;
                let started = Instant::now();
                let clock = RequestClock::anchored(at.duration_since_epoch(), started)
                    .map_err(|_| unavailable())?;
                let task = Task::capture(self, owner, guard, clock, started + TASK_BUDGET)?;
                (
                    Some(task),
                    Response {
                        status: 202,
                        body: json!({"warnings":[STARTED]}),
                        response_headers: Default::default(),
                        consistency_index: None,
                        unwrapped_json: None,
                    },
                )
            } else {
                (None, Response::ok(json!({"warnings":[BUSY]})))
            };
            if let Some(ttl) = request.wrap_ttl_seconds.filter(|ttl| *ttl > 0) {
                // Use the actual foreground wrapping publisher while retaining the
                // same private task capsule. Only post-response audit activates it.
                let mut candidate = admitted.clone();
                let wrapped = candidate
                    .auth
                    .wrap_response(
                        request.namespace,
                        request.path,
                        ttl,
                        &response.body,
                        request.now,
                    )
                    .map_err(auth_error)?;
                candidate.schema = candidate.writer_schema();
                self.commit_state(&mut candidate)?;
                self.state = Some(candidate);
                response = Response {
                    status: wrapped.status,
                    body: wrapped.body,
                    response_headers: Default::default(),
                    consistency_index: None,
                    unwrapped_json: None,
                };
            }
            self.pending_approle_tidy = Some(Accepted {
                actor: authority,
                task,
            });
            Ok(response)
        })();
        result.unwrap_or_else(|error| error)
    }
    pub(in crate::service) fn complete_approle_tidy_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let mut accepted = match (expected, self.pending_approle_tidy.take()) {
            (false, None) => return response,
            (true, Some(accepted)) => accepted,
            _ => {
                erase_json(&mut response.body);
                response.response_headers.clear();
                response.consistency_index = None;
                self.recovery_required = true;
                self.ha_activation = None;
                return unavailable();
            }
        };
        let result = if response.status >= 300 {
            Err(unavailable())
        } else {
            self.validate_plugin_response(&mut accepted.actor)
                .and_then(|()| {
                    accepted
                        .task
                        .as_ref()
                        .map_or(Ok(()), |task| task.check(self))
                })
        };
        if let Err(error) = result {
            erase_json(&mut response.body);
            response.response_headers.clear();
            response.consistency_index = None;
            if self
                .audit_event(
                    "approle-tidy-ack-veto",
                    fingerprint,
                    accepted.actor.now(),
                    Some(error.status),
                )
                .is_err()
            {
                self.recovery_required = true;
                self.ha_activation = None;
            }
            return error;
        }
        if let Some(task) = accepted.task {
            self.approle_tidy_jobs.push_back(task);
        }
        response
    }
    fn prepare_approle_tidy_record_root(&self, state: &mut State) -> Result<(), Response> {
        if state.engines.record_root().is_some() {
            return Ok(());
        }
        if self.record_root.is_some() {
            return Err(unavailable());
        }
        let key = crypto::random::<32>().map_err(|_| unavailable())?;
        state.engines = state
            .engines
            .migrate_kv1_records(crate::state_records::AddressKey::from_bytes(key))
            .map_err(Response::from_engine_error)?
            .into();
        Ok(())
    }
    pub(in crate::service) fn maintain_approle_tidies(&mut self) -> bool {
        let Some(mut task) = self.approle_tidy_jobs.pop_front() else {
            return false;
        };
        match task.step(self) {
            Ok(false) => self.approle_tidy_jobs.push_back(task),
            Ok(true) => eprintln!(
                "heptabao-approle-tidy: completed checked={} removed={}",
                task.checked, task.removed
            ),
            Err(_) => {
                let now = task.clock.observed_at().map_or(0, |at| at.seconds());
                if self
                    .audit_event(
                        "approle-tidy-task-stopped",
                        &task.fingerprint,
                        now,
                        Some(503),
                    )
                    .is_err()
                {
                    self.recovery_required = true;
                    self.ha_activation = None;
                }
                eprintln!(
                    "heptabao-approle-tidy: stopped checked={} removed={} completed=false",
                    task.checked, task.removed
                );
                // RAII releases only this task's mount CAS; no task is re-armed.
            }
        }
        true
    }
    pub(in crate::service) fn queue_periodic_approle_tidies(
        &mut self,
        clock: RequestClock,
    ) -> Result<usize, Response> {
        let Some(current) = self.state.as_ref() else {
            return Ok(0);
        };
        if self.recovery_required || self.audit_failed {
            return Err(unavailable());
        }
        if let Some(ha) = &self.ha {
            let node = ha.lock_for_request().map_err(|_| unavailable())?;
            if !node.is_leader().map_err(|_| unavailable())? {
                return Ok(0);
            }
        }
        let mut mounts = current.auth.approle_tidy_mounts();
        if let Some(previous) = &self.approle_tidy_periodic_cursor {
            let split = mounts.partition_point(|key| key <= previous);
            mounts.rotate_left(split);
        }
        let mut queued = 0;
        for (namespace, mount) in mounts.into_iter().take(MAX_JOBS) {
            self.approle_tidy_periodic_cursor = Some((namespace.clone(), mount.clone()));
            let current = self.state.as_ref().ok_or_else(unavailable)?;
            if !current.namespace_exists(&namespace)
                || current.namespace_is_sealed(&namespace)
                || current.namespace_is_tainted(&namespace)
                || current.namespaces.inherited_owner(&namespace).is_some()
                    && !self.namespace_runtime.is_loaded(&namespace)
            {
                continue;
            }
            let owner = current
                .auth
                .approle_tidy_owner(&namespace, &mount)
                .map_err(auth_error)?
                .ok_or_else(unavailable)?;
            let Some(guard) = self.reserve_approle_tidy(&owner)? else {
                continue;
            };
            let task = Task::capture(self, owner, guard, clock, clock.started() + TASK_BUDGET)?;
            self.approle_tidy_jobs.push_back(task);
            queued += 1;
        }
        Ok(queued)
    }
}
pub(crate) struct Worker {
    stop: std::sync::mpsc::Sender<()>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
pub(crate) fn start_worker(service: &Arc<Mutex<Service>>) -> Result<Worker, String> {
    let service = Arc::downgrade(service);
    let (stop, receiver) = std::sync::mpsc::channel();
    let join = std::thread::Builder::new()
        .name("heptabao-approle-tidy".into())
        .spawn(move || {
            let mut next_periodic = Instant::now() + PERIOD;
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                receiver.recv_timeout(Duration::from_millis(25))
            {
                let Some(service) = service.upgrade() else {
                    break;
                };
                let Ok(mut writer) = service.try_lock() else {
                    continue;
                };
                if Instant::now() >= next_periodic {
                    let started = Instant::now();
                    if let Ok(wall) =
                        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                        && let Ok(clock) = RequestClock::anchored(wall, started)
                    {
                        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                            started + TASK_BUDGET,
                        );
                        if writer.queue_periodic_approle_tidies(clock).is_err() {
                            eprintln!("heptabao-approle-tidy: periodic admission stopped");
                        }
                    }
                    next_periodic = started + PERIOD;
                }
                writer.maintain_approle_tidies();
            }
        })
        .map_err(|_| "cannot start AppRole tidy worker".to_owned())?;
    Ok(Worker {
        stop,
        join: Some(join),
    })
}
#[cfg(test)]
#[path = "service_approle_tidy_tests.rs"]
mod tests;
