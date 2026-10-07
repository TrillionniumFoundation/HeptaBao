//! Actual accepted native moves, with a separate ACK actor and task ownership.
//! RAM status is metadata; it cannot authorize a move or replay an unknown task.
use super::*;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const QUEUED_WARNING: &str = "Mount move has been queued. Progress will be reported in OpenBao's server log, tagged with the returned migration_id";

#[derive(Clone, Copy)]
enum Phase {
    InProgress,
    Success,
    Failure,
}
impl Phase {
    fn literal(self) -> &'static str {
        match self {
            Self::InProgress => "in-progress",
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}
pub(in crate::service) struct Status {
    namespace: String,
    incarnation: Option<u64>,
    delivery: namespace_runtime::DeliveryBinding,
    cluster: String,
    from: String,
    to: String,
    phase: Phase,
}
enum Owner {
    Auth(crate::auth::NativeRemountOwner),
    Engine(crate::engines::NativeRemountOwner),
}
/// No Actor, Clone, Deserialize or provider callback. Consumed once by the worker.
pub(in crate::service) struct Task {
    id: String,
    namespace: String,
    incarnation: Option<u64>,
    delivery: namespace_runtime::DeliveryBinding,
    cluster: String,
    from: String,
    to: String,
    cas: Option<u64>,
    owner: Owner,
    clock: RequestClock,
    deadline: Instant,
    nonce: String,
    seal: [u8; 32],
    barrier: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
}
pub(in crate::service) struct AcceptedMove {
    actor: plugin::PluginResponseAuthority,
    task: Option<Task>,
}
fn auth_error(error: crate::auth::AuthError) -> Response {
    Response::error(error.status, &error.message)
}
fn seal_digest(service: &Service) -> Result<[u8; 32], Response> {
    let seal = service
        .seal
        .as_ref()
        .ok_or_else(|| Response::error(503, "native move seal unavailable"))?;
    let bytes = zeroize::Zeroizing::new(
        crate::secret_serde::to_vec(seal, 512 * 1024)
            .map_err(|_| Response::error(503, "native move seal owner unavailable"))?,
    );
    Ok(crypto::digest(&bytes))
}
fn barrier_digest(service: &Service) -> Result<[u8; 32], Response> {
    service
        .barrier_key
        .as_ref()
        .map(|key| crypto::digest(key.as_ref()))
        .ok_or_else(|| Response::error(503, "native move barrier unavailable"))
}
fn migration_id() -> Result<String, Response> {
    let text = hex(&crypto::random::<16>().map_err(|error| Response::error(503, error))?);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    ))
}
fn no_callback_owners(state: &State) -> Result<(), Response> {
    if state.engines.has_live_leases()
        || state.engines.has_live_sdk_leases()
        || !state.database.all_lease_owners().is_empty()
        || state
            .auth
            .sdk_credential_owners()
            .iter()
            .any(|(namespace, _)| state.auth.sdk_credential_namespace_pending(namespace))
    {
        return Err(Response::error(
            409,
            "native remount requires completed dynamic cleanup owners",
        ));
    }
    Ok(())
}
impl Task {
    fn check_deadline(&self) -> Result<(), Response> {
        if Instant::now() >= self.deadline {
            return Err(Response::error(
                503,
                "native move original task deadline expired",
            ));
        }
        self.clock
            .observed_at()
            .map_err(|_| Response::error(503, "native move original clock unavailable"))?;
        Ok(())
    }
    fn check_base(&self, service: &Service, state: &State) -> Result<(), Response> {
        self.check_deadline()?;
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.nonce
            || seal_digest(service)? != self.seal
            || barrier_digest(service)? != self.barrier
            || state.cluster_id != self.cluster
            || state.namespace_is_tainted(&self.namespace)
            || state.namespace_is_sealed(&self.namespace)
            || state.namespaces.incarnation(&self.namespace) != self.incarnation
            || namespace_runtime::DeliveryBinding::capture(state, &self.namespace) != self.delivery
            || (state.namespaces.inherited_owner(&self.namespace).is_some()
                && !service.namespace_runtime.is_loaded(&self.namespace))
        {
            return Err(Response::error(
                503,
                "native move accepted activation or namespace changed",
            ));
        }
        state.namespace_leases.validate()?;
        state.validate_namespace_deletion_state()?;
        match (&self.ha, &service.ha) {
            (None, None) => {}
            (Some(original), Some(current)) if Arc::ptr_eq(original, current) => {
                if !current
                    .lock_for_request()
                    .map_err(|_| Response::error(503, "native move HA unavailable"))?
                    .is_leader()
                    .map_err(|_| Response::error(503, "native move leader unavailable"))?
                {
                    return Err(Response::error(
                        503,
                        "native move requires current original leader",
                    ));
                }
            }
            _ => return Err(Response::error(503, "native move HA activation changed")),
        }
        self.check_deadline()
    }
    fn check_source(&self, service: &Service, state: &State) -> Result<(), Response> {
        self.check_base(service, state)?;
        no_callback_owners(state)?;
        match &self.owner {
            Owner::Auth(owner) => {
                if state
                    .auth
                    .native_remount_owner(&self.namespace, &self.from, &self.to)
                    .map_err(auth_error)?
                    .as_ref()
                    != Some(owner)
                {
                    return Err(Response::error(
                        503,
                        "native move original auth mount changed",
                    ));
                }
            }
            Owner::Engine(owner) => {
                if state
                    .engines
                    .native_remount_owner(&self.namespace, &self.from, &self.to)
                    .map_err(Response::from_engine_error)?
                    .as_ref()
                    != Some(owner)
                {
                    return Err(Response::error(
                        503,
                        "native move original engine mount changed",
                    ));
                }
            }
        }
        self.check_deadline()
    }
    fn move_current(&self, state: &mut State) -> Result<Owner, Response> {
        match &self.owner {
            Owner::Auth(owner) => {
                state
                    .auth
                    .remount_native_accepted(&self.namespace, &self.from, &self.to, self.cas, owner)
                    .map_err(auth_error)?;
                state
                    .auth
                    .native_remount_owner(&self.namespace, &self.to, &self.from)
                    .map_err(auth_error)?
                    .map(Owner::Auth)
                    .ok_or_else(|| Response::error(503, "native move resulting auth owner missing"))
            }
            Owner::Engine(_) => {
                state
                    .engines
                    .remount(&self.namespace, &self.from, &self.to, self.cas)
                    .map_err(Response::from_engine_error)?;
                state
                    .engines
                    .native_remount_owner(&self.namespace, &self.to, &self.from)
                    .map_err(Response::from_engine_error)?
                    .map(Owner::Engine)
                    .ok_or_else(|| {
                        Response::error(503, "native move resulting engine owner missing")
                    })
            }
        }
    }
    fn check_terminal(
        &self,
        service: &Service,
        state: &State,
        terminal: &Owner,
    ) -> Result<(), Response> {
        self.check_base(service, state)?;
        match terminal {
            Owner::Auth(owner) => {
                if state
                    .auth
                    .native_remount_owner(&self.namespace, &self.to, &self.from)
                    .map_err(auth_error)?
                    .as_ref()
                    != Some(owner)
                    || !state
                        .auth
                        .remount_source_absent(&self.namespace, &self.from)
                {
                    return Err(Response::error(
                        503,
                        "native move terminal auth owner changed",
                    ));
                }
            }
            Owner::Engine(owner) => {
                if state
                    .engines
                    .native_remount_owner(&self.namespace, &self.to, &self.from)
                    .map_err(Response::from_engine_error)?
                    .as_ref()
                    != Some(owner)
                    || !state
                        .engines
                        .remount_source_absent(&self.namespace, &format!("{}/", self.from))
                {
                    return Err(Response::error(
                        503,
                        "native move terminal engine owner changed",
                    ));
                }
            }
        }
        self.check_deadline()
    }
    fn execute(self, service: &mut Service) {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
        let fingerprint = hex(&crypto::digest(self.id.as_bytes()));
        let result = (|| {
            self.check_deadline()?;
            if service.ha.is_some() {
                service.sync_from_ha_with_anchor(false)?;
            }
            let current = service
                .state
                .as_ref()
                .ok_or_else(|| Response::error(503, "native move state unavailable"))?;
            self.check_source(service, current)?;
            let expected = service.current_state_identity()?;
            let mut candidate = current.clone();
            let terminal = self.move_current(&mut candidate)?;
            service.prepare_native_move_record_root(&mut candidate)?;
            candidate.schema = candidate.writer_schema();
            candidate.validate_format()?;
            let publication = service.prepare_record_plan(&mut candidate)?;
            self.check_source(
                service,
                service
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "native move predecessor missing"))?,
            )?;
            self.check_terminal(service, &candidate, &terminal)?;
            if service.current_state_identity()? != expected {
                return Err(Response::error(
                    503,
                    "native move source changed before publication",
                ));
            }
            service.commit_record_plan_with_before_publish(
                &candidate,
                publication,
                |live_auth| {
                    self.check_deadline()?;
                    candidate.namespace_leases.validate()?;
                    candidate.validate_namespace_deletion_state()?;
                    if candidate.namespace_is_tainted(&self.namespace)
                        || namespace_runtime::DeliveryBinding::capture(&candidate, &self.namespace)
                            != self.delivery
                    {
                        return Err(Response::error(
                            503,
                            "native move namespace changed at publication",
                        ));
                    }
                    if let Owner::Auth(owner) = &self.owner
                        && live_auth
                            .native_remount_owner(&self.namespace, &self.from, &self.to)
                            .map_err(auth_error)?
                            .as_ref()
                            != Some(owner)
                    {
                        return Err(Response::error(
                            503,
                            "native move auth owner changed at publication",
                        ));
                    }
                    self.check_deadline()
                },
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )?;
            // Only this actual successful publication changes the current state.
            service.state = Some(candidate);
            self.check_terminal(
                service,
                service
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "native move publication missing"))?,
                &terminal,
            )?;
            Ok(terminal)
        })();
        let now = self.clock.observed_at().map_or(0, |at| at.seconds());
        let audit = service.audit_event(
            "native-remount-task-response",
            &fingerprint,
            now,
            Some(
                result
                    .as_ref()
                    .map_or_else(|error: &Response| error.status, |_| 200),
            ),
        );
        let success = match (result, audit) {
            (Ok(terminal), Ok(())) => service
                .state
                .as_ref()
                .is_some_and(|state| self.check_terminal(service, state, &terminal).is_ok()),
            (_, Err(_)) => {
                service.recovery_required = true;
                service.ha_activation = None;
                false
            }
            (Err(_), Ok(())) => false,
        };
        if let Some(status) = service.native_remount_statuses.get_mut(&self.id) {
            status.phase = if success {
                Phase::Success
            } else {
                Phase::Failure
            };
        }
        // Never re-arm a consumed task, including a committed late audit veto.
    }
}
impl Service {
    pub(in crate::service) fn native_remount_handles(
        &self,
        state: &State,
        request: &RequestView<'_>,
    ) -> bool {
        if let Some(id) = request.path.strip_prefix("sys/remount/status/") {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if self.sdk_migrations.contains_key(id) {
                return false;
            }
            return true;
        }
        if request.path != "sys/remount" {
            return false;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(from) = request.body.get("from").and_then(Value::as_str) {
            let from = format!("{}/", from.trim_end_matches('/'));
            if state
                .engines
                .sdk_mount_binding(request.namespace, &from)
                .is_some_and(|(actual, _)| actual == from)
            {
                return false;
            }
        }
        true
    }
    pub(in crate::service) fn native_remount_route(
        &mut self,
        state: State,
        actor: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let run = (|| {
            let actor = actor.ok_or_else(|| Response::error(403, "permission denied"))?;
            crate::request_deadline::current().ok_or_else(|| {
                Response::error(503, "native remount original HTTP deadline required")
            })?;
            let status_route = request.path.starts_with("sys/remount/status/");
            if !(status_route && matches!(request.method, "GET" | "HEAD")
                || !status_route && matches!(request.method, "POST" | "PUT"))
            {
                return Err(Response::error(405, "unsupported remount method"));
            }
            if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
                return Err(Response::error(
                    501,
                    "native remount response wrapping is not implemented",
                ));
            }
            let mut authority = plugin::PluginResponseAuthority::new(
                actor,
                &state,
                request,
                if status_route { "read" } else { "update" },
                !status_route,
                &self.unseal_nonce,
            );
            self.validate_plugin_response(&mut authority)?;
            let current = self
                .state
                .as_ref()
                .ok_or_else(|| Response::error(503, "native remount state unavailable"))?;
            if let Some(id) = request.path.strip_prefix("sys/remount/status/") {
                let Some(status) = self.native_remount_statuses.get(id).filter(|status| {
                    status.namespace == request.namespace
                        && status.cluster == current.cluster_id
                        && status.incarnation == current.namespaces.incarnation(request.namespace)
                        && status.delivery
                            == namespace_runtime::DeliveryBinding::capture(
                                current,
                                request.namespace,
                            )
                }) else {
                    return Ok(Response {
                        status: 404,
                        body: json!({"errors":[]}),
                        response_headers: Default::default(),
                        consistency_index: None,
                    });
                };
                let response = Response::ok(json!({"data":{"migration_id":id,"migration_info":{
                    "source_mount":status.from,"target_mount":status.to,"status":status.phase.literal()}}}));
                self.pending_native_remount = Some(AcceptedMove {
                    actor: authority,
                    task: None,
                });
                return Ok(response);
            }
            let object = request
                .body
                .as_object()
                .ok_or_else(|| Response::error(400, "remount requires a JSON object"))?;
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "from" | "to" | "cas_revision"))
            {
                return Err(Response::error(400, "unsupported remount parameter"));
            }
            let from = object
                .get("from")
                .and_then(Value::as_str)
                .ok_or_else(|| Response::error(400, "remount from is required"))?
                .trim_end_matches('/');
            let to = object
                .get("to")
                .and_then(Value::as_str)
                .ok_or_else(|| Response::error(400, "remount to is required"))?
                .trim_end_matches('/');
            if from.starts_with('/') || to.starts_with('/') {
                return Err(Response::error(
                    400,
                    "remount paths must be relative to the request namespace",
                ));
            }
            let cas = object
                .get("cas_revision")
                .map(|value| {
                    value.as_u64().ok_or_else(|| {
                        Response::error(400, "cas_revision must be a nonnegative integer")
                    })
                })
                .transpose()?;
            let (from, to, owner) = match (from.strip_prefix("auth/"), to.strip_prefix("auth/")) {
                (Some(from), Some(to)) => (
                    from,
                    to,
                    Owner::Auth(
                        current
                            .auth
                            .native_remount_owner(request.namespace, from, to)
                            .map_err(auth_error)?
                            .ok_or_else(|| {
                                Response::error(
                                    409,
                                    "native remount auth callback owner not supported",
                                )
                            })?,
                    ),
                ),
                (None, None) => (
                    from,
                    to,
                    Owner::Engine(
                        current
                            .engines
                            .native_remount_owner(request.namespace, from, to)
                            .map_err(Response::from_engine_error)?
                            .ok_or_else(|| {
                                Response::error(
                                    409,
                                    "native remount external or missing engine owner not supported",
                                )
                            })?,
                    ),
                ),
                _ => return Err(Response::error(400, "remount cannot change mount class")),
            };
            no_callback_owners(current)?;
            if self.native_remount_statuses.len() >= 128 {
                return Err(Response::error(
                    507,
                    "native remount status capacity exhausted",
                ));
            }
            let clock = request
                .token_clock
                .ok_or_else(|| {
                    Response::error(503, "native remount original precise clock required")
                })?
                .with_seconds_floor(request.now)
                .map_err(|_| Response::error(503, "native remount clock unavailable"))?;
            let id = migration_id()?;
            if self.native_remount_statuses.contains_key(&id) {
                return Err(Response::error(503, "native remount identity collision"));
            }
            let task = Task {
                id: id.clone(),
                namespace: request.namespace.into(),
                incarnation: current.namespaces.incarnation(request.namespace),
                delivery: namespace_runtime::DeliveryBinding::capture(current, request.namespace),
                cluster: current.cluster_id.clone(),
                from: from.into(),
                to: to.into(),
                cas,
                owner,
                clock,
                deadline: request.admission_started
                    + crate::request_deadline::IDLE_MAINTENANCE_READ_BUDGET,
                nonce: self.unseal_nonce.clone(),
                seal: seal_digest(self)?,
                barrier: barrier_digest(self)?,
                ha: self.ha.clone(),
            };
            task.check_source(self, current)?;
            let mut preview = current.clone();
            task.move_current(&mut preview)?;
            let prefix = if matches!(task.owner, Owner::Auth(_)) {
                "auth/"
            } else {
                ""
            };
            self.native_remount_statuses.insert(
                id.clone(),
                Status {
                    namespace: task.namespace.clone(),
                    incarnation: task.incarnation,
                    delivery: task.delivery.clone(),
                    cluster: task.cluster.clone(),
                    from: format!("{prefix}{from}/"),
                    to: format!("{prefix}{to}/"),
                    phase: Phase::InProgress,
                },
            );
            self.pending_native_remount = Some(AcceptedMove {
                actor: authority,
                task: Some(task),
            });
            Ok(Response::ok(
                json!({"data":{"migration_id":id},"warnings":[QUEUED_WARNING]}),
            ))
        })();
        run.unwrap_or_else(|error| error)
    }
    fn prepare_native_move_record_root(&self, state: &mut State) -> Result<(), Response> {
        if state.engines.record_root().is_some() {
            return Ok(());
        }
        if self.record_root.is_some() {
            return Err(Response::error(
                503,
                "native move cannot downgrade a record root",
            ));
        }
        let key = crypto::random::<32>().map_err(|error| Response::error(503, error))?;
        state.engines = state
            .engines
            .migrate_kv1_records(crate::state_records::AddressKey::from_bytes(key))
            .map_err(Response::from_engine_error)?
            .into();
        Ok(())
    }
    pub(in crate::service) fn complete_native_remount_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let mut accepted = match (expected, self.pending_native_remount.take()) {
            (false, None) => return response,
            (true, Some(owner)) => owner,
            _ => {
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "native remount ACK capsule lost");
            }
        };
        let gate = if response.status >= 300 {
            Err(Response::error(
                response.status,
                "native remount ACK failed",
            ))
        } else {
            self.validate_plugin_response(&mut accepted.actor)
                .and_then(|()| {
                    accepted.task.as_ref().map_or(Ok(()), |task| {
                        task.check_source(
                            self,
                            self.state.as_ref().ok_or_else(|| {
                                Response::error(503, "native move ACK state missing")
                            })?,
                        )
                    })
                })
        };
        if let Err(error) = gate {
            if let Some(task) = &accepted.task {
                if let Some(status) = self.native_remount_statuses.get_mut(&task.id) {
                    status.phase = Phase::Failure;
                }
            }
            erase_json(&mut response.body);
            response.response_headers.clear();
            response.consistency_index = None;
            if self
                .audit_event(
                    "native-remount-ack-veto",
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
            self.native_remount_jobs.push_back(task);
        }
        response
    }
    pub(in crate::service) fn maintain_native_remounts(&mut self) -> bool {
        let Some(task) = self.native_remount_jobs.pop_front() else {
            return false;
        };
        task.execute(self);
        true
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
        .name("heptabao-native-remount".into())
        .spawn(move || {
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                receiver.recv_timeout(Duration::from_millis(25))
            {
                let Some(service) = service.upgrade() else {
                    break;
                };
                if let Ok(mut writer) = service.try_lock() {
                    writer.maintain_native_remounts();
                }
            }
        })
        .map_err(|_| "cannot start native remount worker".to_owned())?;
    Ok(Worker {
        stop,
        join: Some(join),
    })
}

#[cfg(test)]
#[path = "service_native_remount_tests.rs"]
pub(in crate::service) mod tests;
