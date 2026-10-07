//! Global deletion metadata stays visible when namespace payloads are closed.
//! Structural saved-owner validation is separate from runtime cleanup authority.
use super::*;

impl State {
    pub(in crate::service) fn has_namespace_deletion_state(&self) -> bool {
        self.namespaces.deletions.is_some() || self.auth.namespace_deletion_ledger().is_some()
    }
    pub(in crate::service) fn namespace_is_tainted(&self, namespace: &str) -> bool {
        self.namespaces
            .deletions
            .as_ref()
            .is_some_and(|ledger| ledger.is_tainted(namespace))
    }
    pub(in crate::service) fn validate_namespace_deletion_state(&self) -> Result<(), Response> {
        match (
            &self.namespaces.deletions,
            self.auth.namespace_deletion_ledger(),
        ) {
            (None, None) => return Ok(()),
            (Some(actual), Some(auth))
                if actual == auth && self.schema >= NAMESPACE_DELETION_STATE_SCHEMA => {}
            _ => {
                return Err(Response::error(
                    503,
                    "namespace deletion requires matching format 106 owners",
                ));
            }
        }
        let ledger = self
            .namespaces
            .deletions
            .as_ref()
            .ok_or_else(|| Response::error(503, "namespace deletion ledger is unavailable"))?;
        ledger.validate(&self.cluster_id).map_err(auth_error)?;
        let lifecycle = self.namespaces.batch_lifecycle.as_ref().ok_or_else(|| {
            Response::error(503, "namespace deletion lacks actual namespace lifecycle")
        })?;
        for (path, binding) in ledger.pending() {
            let expected = crate::namespace_custody::Binding::new(
                self.cluster_id.clone(),
                path.clone(),
                namespaces::namespace_id(&self.cluster_id, path, binding.incarnation()),
                binding.incarnation(),
            )
            .map_err(|_| Response::error(503, "namespace deletion binding is invalid"))?;
            if *binding != expected
                || lifecycle.current_incarnation(path) != Some(binding.incarnation())
                || lifecycle.active_paths().any(|child| {
                    child
                        .strip_prefix(path)
                        .is_some_and(|tail| tail.starts_with('/'))
                })
            {
                return Err(Response::error(
                    503,
                    "pending namespace deletion lacks a leaf incarnation",
                ));
            }
        }
        for (path, incarnation) in ledger.retired() {
            if !lifecycle.knows_retired_incarnation(path, *incarnation) {
                return Err(Response::error(
                    503,
                    "namespace deletion lacks actual retirement frontier",
                ));
            }
        }
        Ok(())
    }
    pub(in crate::service) fn begin_namespace_deletion(
        &mut self,
        binding: crate::namespace_custody::Binding,
    ) -> Result<(), Response> {
        self.ensure_namespace_batch_registry()?;
        let ledger = self
            .namespaces
            .deletions
            .get_or_insert_with(Default::default);
        ledger
            .begin(binding, &self.cluster_id)
            .map_err(auth_error)?;
        self.sync_namespace_deletion_ledger()?;
        self.schema = self.writer_schema();
        self.validate_namespace_deletion_state()
    }
    pub(in crate::service) fn complete_namespace_deletion(
        &mut self,
        binding: &crate::namespace_custody::Binding,
    ) -> Result<(), Response> {
        self.namespaces
            .deletions
            .as_mut()
            .ok_or_else(|| Response::error(503, "namespace deletion intent is missing"))?
            .complete(binding, &self.cluster_id)
            .map_err(auth_error)?;
        self.sync_namespace_deletion_ledger()?;
        self.schema = self.writer_schema();
        self.validate_namespace_deletion_state()
    }
    fn sync_namespace_deletion_ledger(&mut self) -> Result<(), Response> {
        let ledger = self
            .namespaces
            .deletions
            .as_ref()
            .ok_or_else(|| Response::error(503, "namespace deletion intent is missing"))?;
        self.auth
            .install_namespace_deletion_ledger(ledger, &self.cluster_id)
            .map_err(auth_error)
    }
}

fn auth_error(error: crate::auth::AuthError) -> Response {
    Response::error(error.status, &error.message)
}

use crate::namespace_custody::{Binding, Frontier};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One native, subtractive local task; never serializable or cloneable.
struct LocalCleanup {
    binding: Binding,
    original_clock: RequestClock,
    deadline: Instant,
    unseal_nonce: String,
    seal_digest: [u8; 32],
    barrier_digest: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
    delivery_binding: namespace_runtime::DeliveryBinding,
}
impl LocalCleanup {
    fn capture(
        service: &Service,
        state: &State,
        binding: Binding,
        clock: RequestClock,
    ) -> Result<Self, Response> {
        let deadline = crate::request_deadline::current().ok_or_else(|| {
            Response::error(503, "namespace cleanup original deadline is required")
        })?;
        let owner = Self {
            binding: binding.clone(),
            original_clock: clock,
            deadline,
            unseal_nonce: service.unseal_nonce.clone(),
            seal_digest: seal_digest(service)?,
            barrier_digest: barrier_digest(service)?,
            ha: service.ha.clone(),
            delivery_binding: namespace_runtime::DeliveryBinding::capture(
                state,
                binding.namespace(),
            ),
        };
        owner.check_base(service)?;
        owner.check_pending(state)?;
        Ok(owner)
    }
    fn check_deadline(&self) -> Result<(), Response> {
        if Instant::now() >= self.deadline {
            return Err(Response::error(
                503,
                "namespace cleanup original deadline expired",
            ));
        }
        self.original_clock
            .observed_at()
            .map_err(|_| Response::error(503, "namespace cleanup original clock unavailable"))?;
        Ok(())
    }
    fn check_base(&self, service: &Service) -> Result<(), Response> {
        self.check_deadline()?;
        if service.recovery_required
            || service.audit_failed
            || self.unseal_nonce != service.unseal_nonce
            || self.seal_digest != seal_digest(service)?
            || self.barrier_digest != barrier_digest(service)?
        {
            return Err(Response::error(503, "namespace cleanup activation changed"));
        }
        match (&service.ha, &self.ha) {
            (None, None) => {}
            (Some(current), Some(original)) if Arc::ptr_eq(current, original) => {
                let node = current
                    .lock_for_request()
                    .map_err(|_| Response::error(503, "namespace cleanup HA owner unavailable"))?;
                if !node
                    .is_leader()
                    .map_err(|_| Response::error(503, "namespace cleanup leader unavailable"))?
                {
                    return Err(Response::error(
                        503,
                        "namespace cleanup requires current leader",
                    ));
                }
            }
            _ => return Err(Response::error(503, "namespace cleanup HA owner changed")),
        }
        self.check_deadline()
    }
    fn check_pending(&self, state: &State) -> Result<(), Response> {
        self.check_deadline()?;
        state.validate_namespace_deletion_state()?;
        state.namespace_leases.validate()?;
        if state
            .namespaces
            .deletions
            .as_ref()
            .and_then(|ledger| ledger.pending().get(self.binding.namespace()))
            != Some(&self.binding)
            || state
                .namespaces
                .custody_binding(&state.cluster_id, self.binding.namespace())?
                != self.binding
            || state.namespace_is_sealed(self.binding.namespace())
            || namespace_runtime::DeliveryBinding::capture(state, self.binding.namespace())
                != self.delivery_binding
        {
            return Err(Response::error(
                503,
                "namespace cleanup original intent or custody changed",
            ));
        }
        Ok(())
    }
    fn check_terminal(&self, state: &State, floor: Option<&Frontier>) -> Result<(), Response> {
        self.check_deadline()?;
        state.validate_namespace_deletion_state()?;
        state.namespace_leases.validate()?;
        Service::namespace_retirement_owner_gate(state, &self.binding, floor)?;
        if state
            .namespaces
            .deletions
            .as_ref()
            .and_then(|ledger| ledger.retired().get(self.binding.namespace()))
            != Some(&self.binding.incarnation())
        {
            return Err(Response::error(
                503,
                "namespace cleanup terminal intent changed",
            ));
        }
        Ok(())
    }
}
fn barrier_digest(service: &Service) -> Result<[u8; 32], Response> {
    service
        .barrier_key
        .as_ref()
        .map(|key| crypto::digest(key.as_ref()))
        .ok_or_else(|| Response::error(503, "namespace cleanup barrier unavailable"))
}
fn seal_digest(service: &Service) -> Result<[u8; 32], Response> {
    let seal = service
        .seal
        .as_ref()
        .ok_or_else(|| Response::error(503, "namespace cleanup seal unavailable"))?;
    let bytes = crate::secret_serde::to_vec(seal, 512 * 1024)
        .map_err(|_| Response::error(503, "namespace cleanup seal binding unavailable"))?;
    Ok(crypto::digest(&bytes))
}

impl Service {
    fn namespace_taint_gate(
        state: &State,
        principal: &Principal,
        request: &RequestView<'_>,
        caller_incarnation: u64,
        binding: &Binding,
    ) -> Result<(), Response> {
        namespace_runtime::request_live()?;
        state.validate_namespace_deletion_state()?;
        state.namespace_leases.validate()?;
        if state.namespaces.incarnation(request.namespace) != Some(caller_incarnation)
            || state.namespace_is_sealed(request.namespace)
            || state
                .namespaces
                .custody_binding(&state.cluster_id, binding.namespace())?
                != *binding
            || state
                .namespaces
                .deletions
                .as_ref()
                .and_then(|ledger| ledger.pending().get(binding.namespace()))
                != Some(binding)
        {
            return Err(Response::error(
                503,
                "namespace deletion admission owner changed",
            ));
        }
        state
            .auth
            .authorize_request(
                principal,
                request.namespace,
                request.path,
                "delete",
                external_pki::publication_now(request.now),
            )
            .map_err(auth_error)
    }
    fn prepare_namespace_deletion_record_root(&self, state: &mut State) -> Result<(), Response> {
        if state.engines.record_root().is_some() {
            return Ok(());
        }
        if self.record_root.is_some() {
            return Err(Response::error(
                503,
                "namespace deletion cannot downgrade a record root",
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
    pub(in crate::service) fn stage_local_namespace_deletion(
        &mut self,
        mut state: State,
        actor: Principal,
        request: &RequestView<'_>,
        caller_incarnation: u64,
        binding: Binding,
    ) -> Response {
        let run = (|| {
            let expected = self.current_state_identity()?;
            state.begin_namespace_deletion(binding.clone())?;
            // Every response binding is captured before publication with the
            // original affine admission, never rebuilt from completed state.
            let authority = AcceptedDelete::capture(actor, self, &state, request, binding.clone())?;
            Self::namespace_taint_gate(
                &state,
                &authority.actor,
                request,
                caller_incarnation,
                &binding,
            )?;
            self.prepare_namespace_deletion_record_root(&mut state)?;
            let publication = self.prepare_record_plan(&mut state)?;
            authority.check_state(self, &state)?;
            if self.current_state_identity()? != expected {
                return Err(Response::error(503, "namespace deletion source changed"));
            }
            self.commit_record_plan_with_before_publish(
                &state,
                publication,
                |auth| {
                    namespace_runtime::request_live()?;
                    // The prepared intent belongs to this immutable candidate.
                    // The hook supplies predecessor live Auth only for the
                    // original actor gate; a first intent cannot exist there.
                    state.validate_namespace_deletion_state()?;
                    if state
                        .auth
                        .namespace_deletion_ledger()
                        .and_then(|ledger| ledger.pending().get(binding.namespace()))
                        != Some(&binding)
                    {
                        return Err(Response::error(
                            503,
                            "namespace deletion intent changed before publication",
                        ));
                    }
                    authority.check_actor(auth)
                },
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )?;
            // The durable taint survives a late response veto.
            self.state = Some(state);
            authority.check(self)?;
            self.pending_namespace_deletion = Some(authority);
            Ok(Response::ok(json!({"data":{"status":"in-progress"}})))
        })();
        run.unwrap_or_else(|error| error)
    }

    /// Current finite task supports actual native account/token/identity/KV owners.
    /// Every other backend retains its original admission rejection.
    pub(in crate::service) fn maintain_namespace_deletions(
        &mut self,
        clock: RequestClock,
    ) -> Result<bool, Response> {
        if self.recovery_required || self.audit_failed || self.state.is_none() {
            return Ok(false);
        }
        if let Some(ha) = &self.ha {
            let node = ha
                .lock_for_request()
                .map_err(|_| Response::error(503, "namespace cleanup HA owner unavailable"))?;
            if !node
                .is_leader()
                .map_err(|_| Response::error(503, "namespace cleanup leader unavailable"))?
            {
                return Ok(false);
            }
            drop(node);
            self.sync_from_ha_with_anchor(false)?;
        }
        let Some(binding) = self
            .state
            .as_ref()
            .and_then(|state| state.namespaces.deletions.as_ref())
            .and_then(|ledger| ledger.pending().values().next())
            .cloned()
        else {
            return Ok(false);
        };
        let source = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "namespace cleanup state unavailable"))?
            .clone();
        let actual = binding.namespace();
        if !source.namespace_has_only_native_local_deletion_owners(actual) {
            return Ok(false);
        }
        if source.namespaces.inherited_owner(actual).is_some()
            && !self.namespace_runtime.is_loaded(actual)
        {
            return Ok(false);
        }
        let authority = LocalCleanup::capture(self, &source, binding.clone(), clock)?;
        let expected = self.current_state_identity()?;
        let now = clock
            .observed_at()
            .map_err(|_| Response::error(503, "namespace cleanup clock unavailable"))?
            .seconds();
        let fingerprint = self.request_fingerprint("INTERNAL", "namespace-cleanup", actual, "");
        self.audit_event("namespace-cleanup-request", &fingerprint, now, None)
            .map_err(|_| Response::error(503, "namespace cleanup audit unavailable"))?;
        let result = (|| {
            let mut next = source.clone();
            if self.namespace_runtime.has_loaded_within(actual) {
                next = self.namespace_runtime.closed_candidate(&next, actual)?;
            }
            if next.namespaces.custody_owner(actual).is_none()
                && next.namespaces.inherited_owner(actual).is_none()
            {
                let key = self
                    .barrier_key
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "namespace cleanup barrier unavailable"))?;
                next = self
                    .namespace_runtime
                    .inherited_closed_candidate(&next, actual, key)?;
            }
            let owner_binding = next
                .namespaces
                .custody_owner(actual)
                .map(|owner| owner.binding().clone())
                .or_else(|| {
                    next.namespaces
                        .inherited_owner(actual)
                        .map(|owner| owner.binding().clone())
                })
                .ok_or_else(|| Response::error(503, "namespace cleanup closed owner missing"))?;
            if owner_binding != binding {
                return Err(Response::error(
                    503,
                    "namespace cleanup closed binding changed",
                ));
            }
            let retired_floor = next
                .namespaces
                .custody_frontiers
                .get(actual)
                .map(Frontier::retirement)
                .ok_or_else(|| {
                    Response::error(503, "namespace cleanup retirement floor missing")
                })?;
            next.engines
                .retire_namespace_record_cells(&binding)
                .map_err(Response::from_engine_error)?;
            next.namespaces.remove(actual)?;
            next.sync_namespace_batch_registry()?;
            next.auth.remove_fresh_namespace_auth_defaults(actual);
            next.engines
                .remove_empty_namespace(actual)
                .map_err(Response::from_engine_error)?;
            next.complete_namespace_deletion(&binding)?;
            next.schema = next.writer_schema();
            next.validate_format()?;
            self.prepare_namespace_deletion_record_root(&mut next)?;
            let publication = self.prepare_record_plan(&mut next)?;
            authority.check_base(self)?;
            authority.check_pending(
                self.state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "namespace cleanup source missing"))?,
            )?;
            authority.check_terminal(&next, Some(&retired_floor))?;
            if self.current_state_identity()? != expected {
                return Err(Response::error(
                    503,
                    "namespace cleanup source changed before publication",
                ));
            }
            self.commit_record_plan_with_before_publish(
                &next,
                publication,
                |_| authority.check_terminal(&next, Some(&retired_floor)),
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )?;
            self.namespace_runtime.close(actual);
            self.state = Some(next);
            authority.check_base(self)?;
            authority.check_terminal(
                self.state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "namespace cleanup terminal missing"))?,
                Some(&retired_floor),
            )?;
            Ok(retired_floor)
        })();
        if self
            .audit_event(
                "namespace-cleanup-response",
                &fingerprint,
                now,
                Some(
                    result
                        .as_ref()
                        .map_or_else(|error: &Response| error.status, |_| 200),
                ),
            )
            .is_err()
        {
            self.recovery_required = true;
            self.ha_activation = None;
            return Err(Response::error(
                503,
                "namespace cleanup response audit unavailable",
            ));
        }
        // Mandatory audit may consume the remainder of the original native budget.
        let retired_floor = result?;
        authority.check_base(self)?;
        authority.check_terminal(
            self.state
                .as_ref()
                .ok_or_else(|| Response::error(503, "namespace cleanup terminal missing"))?,
            Some(&retired_floor),
        )?;
        Ok(true)
    }
}
impl State {
    pub(in crate::service) fn namespace_has_only_native_local_deletion_owners(
        &self,
        namespace: &str,
    ) -> bool {
        self.auth
            .namespace_has_only_native_deletion_owners(namespace)
            && self
                .engines
                .namespace_has_only_native_local_deletion_owners(namespace)
            && self.database.namespace_is_empty(namespace)
            && self.namespaces.workflows.namespace_is_empty(namespace)
    }
}

/// Namespace deletion is an explicit accepted task, independent of the optional
/// periodic token/provider maintenance setting.
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
        .name("heptabao-ns-delete".into())
        .spawn(move || {
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                receiver.recv_timeout(Duration::from_millis(250))
            {
                let Some(service) = service.upgrade() else {
                    break;
                };
                let started = Instant::now();
                let Ok(mut writer) = service.try_lock() else {
                    continue;
                };
                if !writer.state.as_ref().is_some_and(|state| {
                    state
                        .namespaces
                        .deletions
                        .as_ref()
                        .is_some_and(|ledger| !ledger.pending().is_empty())
                }) {
                    continue;
                }
                let Ok(wall) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                else {
                    continue;
                };
                let Ok(clock) = RequestClock::anchored(wall, started) else {
                    continue;
                };
                let deadline = started + crate::request_deadline::IDLE_MAINTENANCE_READ_BUDGET;
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
                if writer.maintain_namespace_deletions(clock).is_err() {
                    eprintln!("heptabao-namespace: deletion remains pending");
                }
            }
        })
        .map_err(|_| "cannot start namespace deletion worker".to_owned())?;
    Ok(Worker {
        stop,
        join: Some(join),
    })
}

/// The original delete actor is moved through mandatory audit exactly once.
pub(in crate::service) struct AcceptedDelete {
    actor: Principal,
    binding: Binding,
    caller: String,
    caller_incarnation: u64,
    caller_delivery: namespace_runtime::DeliveryBinding,
    path: String,
    parameters: Value,
    clock: Option<RequestClock>,
    now: u64,
    started: Instant,
    deadline: Option<Instant>,
    cluster: String,
    nonce: String,
    seal_digest: [u8; 32],
    barrier_digest: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
}
impl Drop for AcceptedDelete {
    fn drop(&mut self) {
        erase_json(&mut self.parameters);
    }
}
impl AcceptedDelete {
    fn capture(
        actor: Principal,
        service: &Service,
        state: &State,
        request: &RequestView<'_>,
        binding: Binding,
    ) -> Result<Self, Response> {
        let owner = Self {
            actor,
            binding,
            caller: request.namespace.to_owned(),
            caller_incarnation: state
                .namespaces
                .incarnation(request.namespace)
                .ok_or_else(|| Response::error(503, "namespace delete caller unavailable"))?,
            caller_delivery: namespace_runtime::DeliveryBinding::capture(state, request.namespace),
            path: request.path.to_owned(),
            parameters: request.body.clone(),
            clock: request.token_clock,
            now: request.now,
            started: request.admission_started,
            deadline: crate::request_deadline::current(),
            cluster: state.cluster_id.clone(),
            nonce: service.unseal_nonce.clone(),
            seal_digest: seal_digest(service)?,
            barrier_digest: barrier_digest(service)?,
            ha: service.ha.clone(),
        };
        owner.check_state(service, state)?;
        Ok(owner)
    }
    fn check(&self, service: &Service) -> Result<(), Response> {
        let state = service
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "namespace deletion response state unavailable"))?;
        self.check_state(service, state)
    }
    fn check_state(&self, service: &Service, state: &State) -> Result<(), Response> {
        let _scope = self
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        namespace_runtime::request_live()?;
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.nonce
            || seal_digest(service)? != self.seal_digest
            || barrier_digest(service)? != self.barrier_digest
        {
            return Err(Response::error(
                503,
                "namespace deletion response activation changed",
            ));
        }
        match (&self.ha, &service.ha) {
            (None, None) => {}
            (Some(original), Some(actual)) if Arc::ptr_eq(original, actual) => {
                if !actual
                    .lock_for_request()
                    .map_err(|_| Response::error(503, "namespace deletion HA unavailable"))?
                    .is_leader()
                    .map_err(|_| Response::error(503, "namespace deletion leader unavailable"))?
                {
                    return Err(Response::error(
                        503,
                        "namespace deletion response requires original leader",
                    ));
                }
            }
            _ => {
                return Err(Response::error(
                    503,
                    "namespace deletion HA activation changed",
                ));
            }
        }
        state.validate_namespace_deletion_state()?;
        state.namespace_leases.validate()?;
        if state.cluster_id != self.cluster
            || state.namespace_is_tainted(&self.caller)
            || state.namespace_is_sealed(&self.caller)
            || state.namespaces.incarnation(&self.caller) != Some(self.caller_incarnation)
            || namespace_runtime::DeliveryBinding::capture(state, &self.caller)
                != self.caller_delivery
            || state
                .namespaces
                .custody_binding(&state.cluster_id, self.binding.namespace())?
                != self.binding
            || state
                .auth
                .namespace_deletion_ledger()
                .and_then(|ledger| ledger.pending().get(self.binding.namespace()))
                != Some(&self.binding)
        {
            return Err(Response::error(
                503,
                "namespace deletion response owner changed",
            ));
        }
        self.check_actor(&state.auth)
    }
    fn check_actor(&self, auth: &AuthState) -> Result<(), Response> {
        namespace_runtime::request_live()?;
        let time = match self.clock {
            Some(clock) => AuthorityTime::Precise(
                clock
                    .with_seconds_floor(self.now)
                    .and_then(RequestClock::observed_at)
                    .map_err(|_| {
                        Response::error(503, "namespace deletion original clock unavailable")
                    })?,
            ),
            None => {
                AuthorityTime::Coarse(self.now.saturating_add(self.started.elapsed().as_secs()))
            }
        };
        let time = auth.token_api_observed_time(time);
        auth.authorize_request_parameters_observed(
            &self.actor,
            &self.caller,
            "DELETE",
            &self.path,
            &self.parameters,
            time,
        )
        .map_err(auth_error)?;
        auth.authorize_request_observed(&self.actor, &self.caller, &self.path, "delete", time)
            .map_err(auth_error)?;
        namespace_runtime::request_live()
    }
}
impl Service {
    pub(in crate::service) fn complete_namespace_deletion_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let owner = match (expected, self.pending_namespace_deletion.take()) {
            (false, None) => return response,
            (true, Some(owner)) => owner,
            _ => {
                erase_json(&mut response.body);
                response.response_headers.clear();
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "namespace deletion response capsule lost");
            }
        };
        if response.status >= 300 {
            return response;
        }
        if let Err(error) = owner.check(self) {
            erase_json(&mut response.body);
            response.response_headers.clear();
            response.consistency_index = None;
            if self
                .audit_event(
                    "namespace-deletion-delivery-veto",
                    fingerprint,
                    owner.now.saturating_add(owner.started.elapsed().as_secs()),
                    Some(error.status),
                )
                .is_err()
            {
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "namespace deletion veto audit failed");
            }
            return error;
        }
        response
    }
}

#[cfg(test)]
#[path = "service_namespace_deletion_tests.rs"]
mod tests;
