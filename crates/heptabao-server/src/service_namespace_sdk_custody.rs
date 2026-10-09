//! Process-local handoff to one already Attempted SDK Auth callback.
//! Locators never construct this receipt. There is no serde/Clone key owner,
//! loaded namespace slot, fresh Clock, caller reconstruction or redispatch.
use super::*;
use crate::auth::sdk::Binding as SdkBinding;
use std::sync::Weak;

struct Maintenance {
    keys: BTreeMap<String, (Owner, Key)>,
}
pub(in crate::service) struct Original {
    binding: SdkBinding,
    job: String,
    resource: String,
    entered: std::sync::atomic::AtomicBool,
    namespace_incarnation: u64,
    clock: crate::auth::RequestClock,
    admitted_at: crate::auth::Timestamp,
    deadline: std::time::Instant,
    activation: String,
    cluster: String,
    seal: [u8; 32],
    barrier: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
    role: Option<(u64, u64)>,
    delivery: DeliveryBinding,
    control: Arc<sdk_backend::Control>,
    storage: Mutex<Option<crate::auth::sdk::StorageWitness>>,
    selected: Mutex<crate::auth::sdk_retirement::Job>,
    completion: Mutex<Option<crate::auth::sdk_retirement::Job>>,
    handoff: Mutex<Option<Arc<Mutex<Maintenance>>>>,
}
pub(in crate::service) struct RetirementPermit {
    original: Arc<Original>,
}
pub(in crate::service) struct RetirementView {
    private: State,
    base: crate::state_record_root::StateIdentity,
    maintenance: Arc<Mutex<Maintenance>>,
    original: Arc<Original>,
}
fn failed() -> Response {
    Response::error(503, "SDK namespace original Attempted custody unavailable")
}
fn same_ha(a: &Option<Arc<Mutex<HaProcess>>>, b: &Option<Arc<Mutex<HaProcess>>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}
impl Original {
    fn deadline(&self) -> Result<(), Response> {
        self.clock.observed_at().map_err(|_| failed())?;
        if std::time::Instant::now() >= self.deadline {
            return Err(failed());
        }
        Ok(())
    }
    fn check_role(&self, service: &Service) -> Result<(), Response> {
        self.deadline()?;
        if !same_ha(&self.ha, &service.ha) {
            return Err(failed());
        }
        match (&self.ha, self.role) {
            (None, None) => Ok(()),
            (Some(ha), Some(expected)) => {
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
                let node = ha.lock_for_request().map_err(|_| failed())?;
                let before = node.leader_status().map_err(|_| failed())?;
                if !before.local_is_leader
                    || before.leader != Some(before.local_id)
                    || (before.local_id, before.term) != expected
                {
                    return Err(failed());
                }
                node.ensure_application_identity(service.current_state_identity()?)
                    .map_err(|_| failed())?;
                let after = node.leader_status().map_err(|_| failed())?;
                if !after.local_is_leader
                    || after.leader != Some(after.local_id)
                    || (after.local_id, after.term) != expected
                {
                    return Err(failed());
                }
                self.deadline()
            }
            _ => Err(failed()),
        }
    }
    fn check_service(&self, service: &Service) -> Result<(), Response> {
        self.deadline()?;
        let state = service.state.as_ref().ok_or_else(failed)?;
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.activation
            || state.cluster_id != self.cluster
            || namespace_deletion::seal_digest(service)? != self.seal
            || namespace_deletion::barrier_digest(service)? != self.barrier
            || service
                .sdk_hosts
                .get(&sdk_backend::auth100::sdk_auth_key(
                    &self.cluster,
                    &self.binding,
                )?)
                .map_or_else(
                    || self.completion.lock().map_or(true, |value| value.is_none()),
                    |current| !Arc::ptr_eq(current, &self.control),
                )
        {
            return Err(failed());
        }
        self.check_role(service)
    }
}
impl RetirementPermit {
    pub(in crate::service) fn original_resource(&self) -> &str {
        &self.original.resource
    }
    pub(in crate::service) fn dispatched(&self) {
        self.original
            .entered
            .store(true, std::sync::atomic::Ordering::Release);
    }
    pub(in crate::service) fn check_service(&self, service: &Service) -> Result<(), Response> {
        self.original.check_service(service)
    }
    pub(in crate::service) fn handed_off(&self) -> Result<bool, Response> {
        Ok(self
            .original
            .handoff
            .lock()
            .map_err(|_| failed())?
            .is_some())
    }
    pub(in crate::service) fn role(&self) -> Option<(u64, u64)> {
        self.original.role
    }
    pub(in crate::service) fn open(&self, service: &Service) -> Result<RetirementView, Response> {
        self.original.check_service(service)?;
        let maintenance = self
            .original
            .handoff
            .lock()
            .map_err(|_| failed())?
            .as_ref()
            .cloned()
            .ok_or_else(failed)?;
        let mut private = service.state.as_ref().ok_or_else(failed)?.clone();
        private.namespace_protected = None;
        private.namespace_leases = Leases::default();
        let keys = maintenance.lock().map_err(|_| failed())?;
        let mut paths = keys.keys.keys().cloned().collect::<Vec<_>>();
        paths.sort_by_key(|path| (path.split('/').count(), path.clone()));
        for actual in paths {
            let (expected, key) = keys.keys.get(&actual).ok_or_else(failed)?;
            let owner = Owner::actual(&private, &actual)?;
            if owner != *expected || !key.matches_binding(owner.binding()) {
                return Err(failed());
            }
            let opened = owner
                .open_assets(owner.binding(), key)
                .map_err(|_| failed())?;
            let assets = serde_json::from_slice(&opened).map_err(|_| failed())?;
            let cells = private
                .engines
                .namespace_record_cells(owner.binding())
                .map_err(|_| failed())?;
            private = private.restore_namespace_assets(&actual, key, assets, &cells)?;
            private.namespaces.set_sealed(&actual, false)?;
        }
        drop(keys);
        if private
            .namespaces
            .incarnation(&self.original.binding.namespace)
            != Some(self.original.namespace_incarnation)
            || private.namespace_is_sealed(&self.original.binding.namespace)
        {
            return Err(failed());
        }
        let job = private
            .auth
            .sdk_auth_retirement_job(&self.original.job)
            .ok_or_else(failed)?;
        if job != &*self.original.selected.lock().map_err(|_| failed())? {
            return Err(failed());
        }
        if !job.completed() {
            private
                .auth
                .sdk_auth_owner_gate(&self.original.binding)
                .map_err(|e| Response::error(e.status, &e.message))?;
            private
                .auth
                .sdk_auth_retirement_namespace_gate(
                    &self.original.binding,
                    Some(&self.original.resource),
                )
                .map_err(|e| Response::error(e.status, &e.message))?;
        } else if self
            .original
            .completion
            .lock()
            .map_err(|_| failed())?
            .as_ref()
            != Some(job)
        {
            return Err(failed());
        }
        if job.binding() != &self.original.binding
            || !matches!(
                job.phase(&self.original.resource),
                Some(
                    crate::auth::sdk_retirement::ResourcePhase::Attempted
                        | crate::auth::sdk_retirement::ResourcePhase::Terminal
                )
            )
        {
            return Err(failed());
        }
        private.validate_format()?;
        self.original.check_service(service)?;
        Ok(RetirementView {
            private,
            base: service.current_state_identity()?,
            maintenance,
            original: Arc::clone(&self.original),
        })
    }
}
impl RetirementView {
    pub(in crate::service) fn state(&self) -> &State {
        &self.private
    }
    pub(in crate::service) fn role(&self) -> Option<(u64, u64)> {
        self.original.role
    }
    pub(in crate::service) fn matches_original(
        &self,
        activation: &str,
        cluster: &str,
        namespace: &str,
        incarnation: Option<u64>,
        delivery: &DeliveryBinding,
    ) -> Result<(), Response> {
        if activation != self.original.activation
            || cluster != self.original.cluster
            || namespace != self.original.binding.namespace
            || incarnation != Some(self.original.namespace_incarnation)
            || delivery != &self.original.delivery
        {
            return Err(failed());
        }
        self.original.deadline()
    }
    pub(in crate::service) fn check_current(&self, service: &Service) -> Result<(), Response> {
        self.original.check_service(service)?;
        if service.current_state_identity()? != self.base {
            return Err(failed());
        }
        Ok(())
    }
    pub(in crate::service) fn check_storage(&self) -> Result<(), Response> {
        self.original
            .storage
            .lock()
            .map_err(|_| failed())?
            .as_ref()
            .ok_or_else(failed)?
            .check(&self.private.auth, &self.original.binding)
            .map_err(|e| Response::error(e.status, &e.message))
    }
    pub(in crate::service) fn merge_storage(
        &self,
        target: &mut AuthState,
        incoming: &AuthState,
    ) -> Result<(), Response> {
        let storage = self.original.storage.lock().map_err(|_| failed())?;
        target
            .merge_sdk_auth_storage(
                &self.original.binding,
                storage.as_ref().ok_or_else(failed)?,
                incoming,
            )
            .map_err(|e| Response::error(e.status, &e.message))
    }
}
impl Runtime {
    pub(in crate::service) fn register_sdk_retirement(
        &mut self,
        state: &State,
        binding: &SdkBinding,
        job: &str,
        resource: &str,
        clock: crate::auth::RequestClock,
        deadline: std::time::Instant,
        control: Arc<sdk_backend::Control>,
        activation: String,
        seal: [u8; 32],
        barrier: [u8; 32],
        ha: Option<Arc<Mutex<HaProcess>>>,
        role: Option<(u64, u64)>,
    ) -> Result<RetirementPermit, Response> {
        if binding.namespace.is_empty() || std::time::Instant::now() >= deadline {
            return Err(failed());
        }
        clock.observed_at().map_err(|_| failed())?;
        state.validate_format()?;
        let selected = state.auth.sdk_auth_retirement_job(job).ok_or_else(failed)?;
        if selected.binding() != binding
            || selected.completed()
            || selected.phase(resource)
                != Some(crate::auth::sdk_retirement::ResourcePhase::Attempted)
        {
            return Err(failed());
        }
        let incarnation = state
            .namespaces
            .incarnation(&binding.namespace)
            .ok_or_else(failed)?;
        let original = Arc::new(Original {
            binding: binding.clone(),
            job: job.into(),
            resource: resource.into(),
            entered: std::sync::atomic::AtomicBool::new(false),
            namespace_incarnation: incarnation,
            clock,
            admitted_at: clock.observed_at().map_err(|_| failed())?,
            deadline,
            activation,
            cluster: state.cluster_id.clone(),
            seal,
            barrier,
            ha,
            role,
            delivery: DeliveryBinding::capture(state, &binding.namespace),
            control,
            storage: Mutex::new(Some(
                state
                    .auth
                    .sdk_auth_storage_witness(binding)
                    .map_err(|e| Response::error(e.status, &e.message))?,
            )),
            selected: Mutex::new(selected.clone()),
            completion: Mutex::new(None),
            handoff: Mutex::new(None),
        });
        self.sdk_retirements.retain(|weak| weak.strong_count() > 0);
        if self.sdk_retirements.len() >= 256 {
            return Err(failed());
        }
        self.sdk_retirements.push(Arc::downgrade(&original));
        Ok(RetirementPermit { original })
    }
    pub(in crate::service) fn retire_sdk_handoffs(&mut self) {
        for original in self.sdk_retirements.iter().filter_map(Weak::upgrade) {
            original
                .handoff
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        }
        self.sdk_retirements.clear();
        for original in self.sdk_cleanups.iter().filter_map(Weak::upgrade) {
            original
                .handoff
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        }
        self.sdk_cleanups.clear();
    }
}

impl Service {
    pub(in crate::service) fn capture_namespace_sdk_retirement(
        &mut self,
        state: &State,
        binding: &SdkBinding,
        job: &str,
        resource: &str,
        clock: crate::auth::RequestClock,
        deadline: std::time::Instant,
        control: Arc<sdk_backend::Control>,
    ) -> Result<RetirementPermit, Response> {
        let role = if let Some(ha) = &self.ha {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
            let node = ha.lock_for_request().map_err(|_| failed())?;
            let before = node.leader_status().map_err(|_| failed())?;
            if !before.local_is_leader || before.leader != Some(before.local_id) {
                return Err(failed());
            }
            node.ensure_application_identity(self.current_state_identity()?)
                .map_err(|_| failed())?;
            let after = node.leader_status().map_err(|_| failed())?;
            if !after.local_is_leader
                || after.leader != Some(after.local_id)
                || (after.local_id, after.term) != (before.local_id, before.term)
            {
                return Err(failed());
            }
            Some((before.local_id, before.term))
        } else {
            None
        };
        let seal = namespace_deletion::seal_digest(self)?;
        let barrier = namespace_deletion::barrier_digest(self)?;
        self.namespace_runtime.register_sdk_retirement(
            state,
            binding,
            job,
            resource,
            clock,
            deadline,
            control,
            self.unseal_nonce.clone(),
            seal,
            barrier,
            self.ha.clone(),
            role,
        )
    }
}
impl SealPublication {
    pub(in crate::service) fn handoff_into_closed(
        self,
        runtime: &mut Runtime,
        activation: &str,
        seal: [u8; 32],
        barrier: [u8; 32],
    ) -> Result<State, Response> {
        let paths = self
            .cuts
            .iter()
            .map(|cut| cut.actual.as_str())
            .collect::<Vec<_>>();
        let selected = runtime
            .sdk_retirements
            .iter()
            .filter_map(Weak::upgrade)
            .map(Handoff::Retirement)
            .chain(
                runtime
                    .sdk_cleanups
                    .iter()
                    .filter_map(Weak::upgrade)
                    .map(Handoff::Cleanup),
            )
            .filter(|original| {
                original.namespace().is_ok_and(|namespace| {
                    paths.iter().any(|actual| {
                        namespace == *actual
                            || namespace
                                .strip_prefix(*actual)
                                .is_some_and(|tail| tail.starts_with('/'))
                    })
                })
            })
            .filter(|original| {
                original.eligible(
                    activation,
                    seal,
                    barrier,
                    &self.closed.cluster_id,
                    &self.ha,
                    self.native_role,
                )
            })
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Ok(self.into_closed());
        }
        // All original slots are checked before taking any sole Key.
        self.check_original_custody()?;
        let mut retained = Vec::<Arc<Mutex<Maintenance>>>::new();
        for original in &selected {
            if let Some(previous) = original.handoff().lock().map_err(|_| failed())?.as_ref()
                && !retained.iter().any(|other| Arc::ptr_eq(other, previous))
            {
                retained.push(Arc::clone(previous));
            }
        }
        let mut keys = BTreeMap::new();
        for previous in retained {
            let mut previous = previous.lock().map_err(|_| failed())?;
            for (actual, value) in std::mem::take(&mut previous.keys) {
                if keys.insert(actual, value).is_some() {
                    return Err(failed());
                }
            }
        }
        for cut in self.cuts {
            let key = match cut.key {
                SealKey::FreshInherited(key) => key,
                SealKey::Original { lease, owner } => {
                    let mut slot = lease.0.lock().map_err(|_| failed())?;
                    if slot.binding != *owner.binding()
                        || slot.key_epoch != owner.key_epoch()
                        || slot.frontier != owner.seal_frontier()
                        || slot.parent.as_ref() != owner.parent()
                    {
                        return Err(failed());
                    }
                    slot.key.take().ok_or_else(failed)?
                }
            };
            if !key.matches_binding(cut.owner.binding())
                || keys.insert(cut.actual, (cut.owner, key)).is_some()
            {
                return Err(failed());
            }
        }
        let maintenance = Arc::new(Mutex::new(Maintenance { keys }));
        for original in selected {
            *original.handoff().lock().map_err(|_| failed())? = Some(Arc::clone(&maintenance));
        }
        Ok(self.closed)
    }
}

/// An affine, real MAC-opened SDK successor. This value cannot be reconstructed
/// from the durable locator, serialized, or installed as a loaded namespace.
pub(in crate::service) struct RetirementPublication {
    view: RetirementView,
    logical: State,
    closed: State,
    owners: BTreeMap<String, Owner>,
}
fn wire(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, Response> {
    owner_store::serialize_owner(value).map_err(state_serialization_error)
}
impl Original {
    fn check_observation(
        &self,
        auth: &AuthState,
        at: crate::auth::Timestamp,
    ) -> Result<(), Response> {
        self.deadline()?;
        if at < self.admitted_at
            || auth.sdk_auth_clock_floor().is_some_and(|floor| at < floor)
            || at > self.time(auth)?
        {
            return Err(failed());
        }
        self.deadline()
    }
    fn time(&self, auth: &AuthState) -> Result<crate::auth::Timestamp, Response> {
        self.deadline()?;
        let clock = auth
            .sdk_auth_clock_floor()
            .map_or(self.clock, |floor| self.clock.with_timestamp_floor(floor));
        auth.token_api_observed_time(AuthorityTime::Precise(
            clock.observed_at().map_err(|_| failed())?,
        ))
        .exact()
        .ok_or_else(failed)
    }
}
impl RetirementView {
    pub(in crate::service) fn resource(&self) -> &str {
        &self.original.resource
    }

    pub(in crate::service) fn clock_publication(
        self,
        service: &Service,
        candidate: State,
        at: crate::auth::Timestamp,
    ) -> Result<RetirementPublication, Response> {
        namespace_diagnostic!("custody.view.current", self.check_current(service))?;
        self.check_storage()?;
        namespace_diagnostic!("retirement.callback.clock", self.original.check_observation(&self.private.auth, at))?;
        let mut expected = self.private.auth.clone();
        expected.observe_sdk_auth_clock(at);
        self.close_publication(service, candidate, &expected)
    }
    pub(in crate::service) fn callback_publication(
        self,
        service: &Service,
        candidate: State,
        incoming: &AuthState,
        at: crate::auth::Timestamp,
    ) -> Result<RetirementPublication, Response> {
        namespace_diagnostic!("custody.view.current", self.check_current(service))?;
        self.check_storage()?;
        namespace_diagnostic!("retirement.callback.clock", self.original.check_observation(&self.private.auth, at))?;
        let mut expected = self.private.auth.clone();
        namespace_diagnostic!("retirement.callback.storage_merge", self.merge_storage(&mut expected, incoming))?;
        let mut record = expected
            .sdk_credential_record(&self.original.binding.namespace, &self.original.resource)
            .ok_or_else(failed)?;
        if record.backend != self.original.binding {
            return Err(failed());
        }
        record.revoke();
        expected.observe_sdk_auth_clock(at);
        expected
            .store_sdk_credential(record)
            .map_err(|e| Response::error(e.status, &e.message))?;
        expected
            .complete_sdk_auth_retirement_resource(&self.original.job, &self.original.resource, at)
            .map_err(|e| Response::error(e.status, &e.message))?;
        self.close_publication(service, candidate, &expected)
    }
    pub(in crate::service) fn native_removal_publication(
        self,
        service: &Service,
        selected: &crate::auth::sdk_retirement::RecoverySelection,
    ) -> Result<RetirementPublication, Response> {
        namespace_diagnostic!("custody.view.current", self.check_current(service))?;
        selected
            .check(&self.private.auth)
            .map_err(|e| Response::error(e.status, &e.message))?;
        if selected.id() != self.original.job
            || selected.binding() != &self.original.binding
            || selected.completed()
        {
            return Err(failed());
        }
        let mut candidate = self.private.clone();
        let at = self.original.time(&candidate.auth)?;
        candidate.auth.observe_sdk_auth_clock(at);
        candidate
            .auth
            .remove_sdk_auth_retirement_mount(selected, at)
            .map_err(|e| Response::error(e.status, &e.message))?;
        let expected = candidate.auth.clone();
        self.close_publication(service, candidate, &expected)
    }
    pub(in crate::service) fn removal_publication(
        self,
        service: &Service,
        caller: &mut plugin::PluginResponseAuthority,
        body: &Value,
    ) -> Result<RetirementPublication, Response> {
        namespace_diagnostic!("custody.view.current", self.check_current(service))?;
        let job = self
            .private
            .auth
            .sdk_auth_retirement_job(&self.original.job)
            .ok_or_else(failed)?;
        if job.completed() {
            return Err(failed());
        }
        let mut candidate = self.private.clone();
        if !candidate
            .auth
            .sdk_credential_mount_records(&self.original.binding)
            .map_err(|e| Response::error(e.status, &e.message))?
            .is_empty()
        {
            return Err(failed());
        }
        let response = candidate
            .auth
            .handle_with_connection_clock(
                Some(caller.principal()),
                &self.original.binding.namespace,
                "DELETE",
                &format!("sys/auth/{}", self.original.binding.mount),
                body,
                caller.token_time()?,
                Some(self.original.clock),
                None,
                None,
            )
            .map_err(|e| Response::error(e.status, &e.message))?;
        if response.is_none_or(|r| r.status != 204) {
            return Err(failed());
        }
        let at = self.original.time(&candidate.auth)?;
        candidate.auth.observe_sdk_auth_clock(at);
        candidate
            .auth
            .complete_sdk_auth_retirement_mount(&self.original.job, at)
            .map_err(|e| Response::error(e.status, &e.message))?;
        let expected = candidate.auth.clone();
        self.close_publication(service, candidate, &expected)
    }
    fn close_publication(
        self,
        service: &Service,
        mut logical: State,
        expected: &AuthState,
    ) -> Result<RetirementPublication, Response> {
        namespace_diagnostic!("custody.view.current", self.check_current(service))?;
        if wire(&logical.auth)? != wire(expected)? {
            #[cfg(test)]
            crate::service::namespace_diagnostics::record_status("retirement.callback.auth_equal", 503);
            return Err(failed());
        }
        // The only permissible application delta is the factory's exact Auth
        // effect. Other complete owners and replay/cluster identity stay current.
        let mut unchanged = logical.clone();
        unchanged.auth = self.private.auth.clone();
        unchanged.schema = self.private.schema;
        unchanged.namespace_leases = Leases::default();
        unchanged.namespace_protected = None;
        if wire(&unchanged)? != wire(&self.private)? {
            #[cfg(test)]
            crate::service::namespace_diagnostics::record_status("retirement.callback.other_owner_equal", 503);
            return Err(failed());
        }
        logical.schema = logical.writer_schema();
        logical.namespace_leases = Leases::default();
        logical.namespace_protected = None;
        namespace_diagnostic!("custody.logical.publication", logical.validate_publication_schema(Some(&self.private)))?;
        namespace_diagnostic!("custody.logical.format", logical.validate_format())?;
        let mut closed = logical.clone();
        let keys = self.maintenance.lock().map_err(|_| failed())?;
        let mut paths = keys.keys.keys().cloned().collect::<Vec<_>>();
        paths.sort_by_key(|path| (std::cmp::Reverse(path.split('/').count()), path.clone()));
        let mut owners = BTreeMap::new();
        for actual in paths {
            let (previous, key) = keys.keys.get(&actual).ok_or_else(failed)?;
            if !key.matches_binding(previous.binding()) {
                return Err(failed());
            }
            closed = closed
                .partition_namespace_assets(&actual, key)?
                .finish_with_owner(|next, assets, cells| {
                    let bytes = wire(assets)?;
                    let prior = previous
                        .open_assets(previous.binding(), key)
                        .map_err(|_| failed())?;
                    let owner = if prior.as_slice() == bytes.as_slice() {
                        previous.clone()
                    } else {
                        previous
                            .replace_assets(previous.binding(), key, &bytes)
                            .map_err(|_| failed())?
                    };
                    // Same original binding, key epoch, frontier and parent.
                    if owner.binding() != previous.binding()
                        || owner.key_epoch() != previous.key_epoch()
                        || owner.seal_frontier() != previous.seal_frontier()
                        || owner.parent() != previous.parent()
                    {
                        return Err(failed());
                    }
                    next.engines
                        .publish_namespace_record_cells(previous.binding(), cells)
                        .map_err(|_| failed())?;
                    owner.install(next, &actual)?;
                    owners.insert(actual.clone(), owner);
                    Ok(())
                })?;
        }
        drop(keys);
        // Keep only the service's real unrelated runtime leases. No private
        // maintenance Key is made into a Slot, Lease or loaded route grant.
        closed.namespace_leases = service
            .state
            .as_ref()
            .ok_or_else(failed)?
            .namespace_leases
            .clone();
        namespace_diagnostic!("custody.closed.prepare", service.namespace_runtime.prepare(&mut closed))?;
        let proof = RetirementPublication {
            view: self,
            logical,
            closed,
            owners,
        };
        namespace_diagnostic!("custody.proof.validate", proof.validate(service))?;
        Ok(proof)
    }
}
impl RetirementPublication {
    pub(in crate::service) fn state(&self) -> &State {
        &self.closed
    }
    pub(in crate::service) fn logical_before(&self) -> &AuthState {
        &self.view.private.auth
    }
    pub(in crate::service) fn role(&self) -> Option<(u64, u64)> {
        self.view.role()
    }
    pub(in crate::service) fn check_original(&self) -> Result<(), Response> {
        self.view.original.deadline()?;
        self.closed.namespace_leases.validate()?;
        let keys = self.view.maintenance.lock().map_err(|_| failed())?;
        if keys.keys.len() != self.owners.len() {
            return Err(failed());
        }
        for (actual, (expected, key)) in &keys.keys {
            let old = Owner::actual(&self.view.private, actual)?;
            let next = self.owners.get(actual).ok_or_else(failed)?;
            if &old != expected
                || !key.matches_binding(next.binding())
                || old.binding() != next.binding()
                || old.key_epoch() != next.key_epoch()
                || old.seal_frontier() != next.seal_frontier()
                || old.parent() != next.parent()
            {
                return Err(failed());
            }
        }
        self.view.original.deadline()
    }
    pub(in crate::service) fn validate(&self, service: &Service) -> Result<(), Response> {
        self.view.check_current(service)?;
        namespace_diagnostic!("custody.original", self.check_original())?;
        self.logical
            .validate_publication_schema(Some(&self.view.private))?;
        namespace_diagnostic!("custody.proof.logical_format", self.logical.validate_format())?;
        let physical = self.closed.protected_state()?;
        namespace_diagnostic!("custody.proof.physical_format", physical.validate_format())?;
        physical.namespaces.validate_custody_successor(
            &service
                .state
                .as_ref()
                .ok_or_else(failed)?
                .protected_state()?
                .namespaces,
        )?;
        // Reopen the exact new descriptor and cells using the same sole Keys.
        // Compare the complete logical graph, never the locator projection.
        let keys = self.view.maintenance.lock().map_err(|_| failed())?;
        let mut restored = self.closed.clone();
        restored.namespace_leases = Leases::default();
        restored.namespace_protected = None;
        let mut paths = self.owners.keys().cloned().collect::<Vec<_>>();
        paths.sort_by_key(|path| (path.split('/').count(), path.clone()));
        for actual in paths {
            let next = self.owners.get(&actual).ok_or_else(failed)?;
            if Owner::actual(&restored, &actual)? != *next {
                return Err(failed());
            }
            let key = &keys.keys.get(&actual).ok_or_else(failed)?.1;
            let bytes = next
                .open_assets(next.binding(), key)
                .map_err(|_| failed())?;
            let assets = serde_json::from_slice(&bytes).map_err(|_| failed())?;
            let cells = restored
                .engines
                .namespace_record_cells(next.binding())
                .map_err(|_| failed())?;
            restored = restored.restore_namespace_assets(&actual, key, assets, &cells)?;
            restored.namespaces.set_sealed(&actual, false)?;
        }
        drop(keys);
        namespace_diagnostic!("custody.restored.format", restored.validate_format())?;
        if wire(&restored)? != wire(&self.logical)? {
            #[cfg(test)]
            {
                // Fixed component equality only. No values or paths are emitted.
                for (stage, equal) in [
                    ("custody.component.schema", restored.schema == self.logical.schema),
                    ("custody.component.replay", restored.replay_epoch == self.logical.replay_epoch),
                    ("custody.component.cluster", restored.cluster_id == self.logical.cluster_id),
                    ("custody.component.auth", wire(&restored.auth).and_then(|a| wire(&self.logical.auth).map(|b| a == b)).unwrap_or(false)),
                    ("custody.component.engines", wire(&restored.engines).and_then(|a| wire(&self.logical.engines).map(|b| a == b)).unwrap_or(false)),
                    ("custody.component.database", wire(&restored.database).and_then(|a| wire(&self.logical.database).map(|b| a == b)).unwrap_or(false)),
                    ("custody.component.raft_admin", wire(&restored.raft_admin).and_then(|a| wire(&self.logical.raft_admin).map(|b| a == b)).unwrap_or(false)),
                    ("custody.component.namespaces", wire(&restored.namespaces).and_then(|a| wire(&self.logical.namespaces).map(|b| a == b)).unwrap_or(false)),
                ] {
                    crate::service::namespace_diagnostics::record_status(stage, if equal { 200 } else { 503 });
                }
                for actual in self.owners.keys() {
                    let pair = Owner::actual(&restored, actual).and_then(|new| Owner::actual(&self.logical, actual).map(|old| (new, old)));
                    if let Ok((new, old)) = pair {
                        for (stage, equal) in [
                            ("custody.component.owner_equal", new == old),
                            ("custody.component.owner_binding", new.binding() == old.binding()),
                            ("custody.component.owner_epoch", new.key_epoch() == old.key_epoch()),
                            ("custody.component.owner_frontier", new.seal_frontier() == old.seal_frontier()),
                            ("custody.component.owner_parent", new.parent() == old.parent()),
                        ] {
                            crate::service::namespace_diagnostics::record_status(stage, if equal { 200 } else { 503 });
                        }
                    } else {
                        crate::service::namespace_diagnostics::record_status("custody.component.owner_lookup", 503);
                    }
                }
            }
            #[cfg(test)]
            crate::service::namespace_diagnostics::record_status("custody.proof.restored_equal", 503);
            return Err(failed());
        }
        self.view.check_current(service)?;
        self.check_original()
    }
    pub(in crate::service) fn installed(self, service: &Service) -> Result<State, Response> {
        namespace_diagnostic!("custody.original", self.check_original())?;
        let mut keys = self.view.maintenance.lock().map_err(|_| failed())?;
        for (actual, next) in &self.owners {
            keys.keys.get_mut(actual).ok_or_else(failed)?.0 = next.clone();
        }
        drop(keys);
        let job = self
            .logical
            .auth
            .sdk_auth_retirement_job(&self.view.original.job)
            .ok_or_else(failed)?
            .clone();
        *self.view.original.selected.lock().map_err(|_| failed())? = job.clone();
        if job.completed() {
            *self.view.original.completion.lock().map_err(|_| failed())? = Some(job);
            self.view
                .original
                .storage
                .lock()
                .map_err(|_| failed())?
                .take();
        } else {
            *self.view.original.storage.lock().map_err(|_| failed())? = Some(
                self.logical
                    .auth
                    .sdk_auth_storage_witness(&self.view.original.binding)
                    .map_err(|e| Response::error(e.status, &e.message))?,
            );
        }
        self.view.original.deadline()?;
        // The new root is already durable; callers install only this closed
        // physical/current runtime view. Logical is private validation output.
        let _ = service;
        Ok(self.closed)
    }
}

pub(in crate::service) struct CleanupOriginal {
    captured: namespace_sdk_cleanup::CapturedCleanup,
    entered: std::sync::atomic::AtomicBool,
    handoff: Mutex<Option<Arc<Mutex<Maintenance>>>>,
}
pub(in crate::service) struct CleanupPermit {
    original: Arc<CleanupOriginal>,
}
pub(in crate::service) struct CleanupView {
    private: State,
    base: crate::state_record_root::StateIdentity,
    maintenance: Arc<Mutex<Maintenance>>,
    original: Arc<CleanupOriginal>,
}
enum Handoff {
    Retirement(Arc<Original>),
    Cleanup(Arc<CleanupOriginal>),
}
impl Handoff {
    fn namespace(&self) -> Result<String, Response> {
        match self {
            Self::Retirement(original) => Ok(original.binding.namespace.clone()),
            Self::Cleanup(original) => original.captured.namespace(),
        }
    }
    fn handoff(&self) -> &Mutex<Option<Arc<Mutex<Maintenance>>>> {
        match self {
            Self::Retirement(v) => &v.handoff,
            Self::Cleanup(v) => &v.handoff,
        }
    }
    fn eligible(
        &self,
        activation: &str,
        seal: [u8; 32],
        barrier: [u8; 32],
        cluster: &str,
        ha: &Option<Arc<Mutex<HaProcess>>>,
        role: Option<(u64, u64)>,
    ) -> bool {
        match self {
            Self::Retirement(v) => {
                v.entered.load(std::sync::atomic::Ordering::Acquire)
                    && v.activation == activation
                    && v.cluster == cluster
                    && v.seal == seal
                    && v.barrier == barrier
                    && same_ha(&v.ha, ha)
                    && v.role == role
                    && v.deadline().is_ok()
            }
            Self::Cleanup(v) => {
                v.entered.load(std::sync::atomic::Ordering::Acquire)
                    && v.captured
                        .eligible_for_seal(activation, seal, barrier, cluster, ha, role)
            }
        }
    }
}
impl Runtime {
    pub(in crate::service) fn register_namespace_cleanup(
        &mut self,
        captured: namespace_sdk_cleanup::CapturedCleanup,
    ) -> Result<CleanupPermit, Response> {
        captured.deadline()?;
        if captured.namespace()?.is_empty() {
            return Err(failed());
        }
        let original = Arc::new(CleanupOriginal {
            captured,
            entered: std::sync::atomic::AtomicBool::new(false),
            handoff: Mutex::new(None),
        });
        self.sdk_cleanups.retain(|weak| weak.strong_count() > 0);
        if self.sdk_cleanups.len() >= 1024 {
            return Err(failed());
        }
        self.sdk_cleanups.push(Arc::downgrade(&original));
        Ok(CleanupPermit { original })
    }
}
impl CleanupPermit {
    pub(in crate::service) fn dispatched(&self) {
        self.original
            .entered
            .store(true, std::sync::atomic::Ordering::Release);
    }
    pub(in crate::service) fn handed_off(&self) -> Result<bool, Response> {
        Ok(self
            .original
            .handoff
            .lock()
            .map_err(|_| failed())?
            .is_some())
    }
    pub(in crate::service) fn open(&self, service: &Service) -> Result<CleanupView, Response> {
        namespace_diagnostic!("cleanup.private.service", self.original.captured.check_service(service))?;
        let maintenance = self
            .original
            .handoff
            .lock()
            .map_err(|_| failed())?
            .as_ref()
            .cloned()
            .ok_or_else(failed)?;
        let mut private = service.state.as_ref().ok_or_else(failed)?.clone();
        private.namespace_protected = None;
        private.namespace_leases = Leases::default();
        let keys = maintenance.lock().map_err(|_| failed())?;
        let mut paths = keys.keys.keys().cloned().collect::<Vec<_>>();
        paths.sort_by_key(|path| (path.split('/').count(), path.clone()));
        for actual in paths {
            let (expected, key) = keys.keys.get(&actual).ok_or_else(failed)?;
            let owner = Owner::actual(&private, &actual)?;
            if owner != *expected || !key.matches_binding(owner.binding()) {
                return Err(failed());
            }
            let opened = owner
                .open_assets(owner.binding(), key)
                .map_err(|_| failed())?;
            let assets = serde_json::from_slice(&opened).map_err(|_| failed())?;
            let cells = private
                .engines
                .namespace_record_cells(owner.binding())
                .map_err(|_| failed())?;
            private = private.restore_namespace_assets(&actual, key, assets, &cells)?;
            private.namespaces.set_sealed(&actual, false)?;
        }
        drop(keys);
        private.validate_format()?;
        self.original.captured.check_graph(&private)?;
        namespace_diagnostic!("cleanup.private.service", self.original.captured.check_service(service))?;
        Ok(CleanupView {
            private,
            base: service.current_state_identity()?,
            maintenance,
            original: Arc::clone(&self.original),
        })
    }
}
impl CleanupView {
    pub(in crate::service) fn state(&self) -> &State {
        &self.private
    }
    pub(in crate::service) fn matches_origin(
        &self,
        namespace: &str,
        incarnation: Option<u64>,
        cluster: &str,
        activation: &str,
        ha: &Option<Arc<Mutex<HaProcess>>>,
        delivery: &DeliveryBinding,
        clock: crate::auth::RequestClock,
        deadline: std::time::Instant,
    ) -> Result<(), Response> {
        self.original.captured.matches_origin(
            namespace,
            incarnation,
            cluster,
            activation,
            ha,
            delivery,
            clock,
            deadline,
        )
    }

    pub(in crate::service) fn role(&self) -> Option<(u64, u64)> {
        self.original.captured.role()
    }
    pub(in crate::service) fn matches_authority(
        &self,
        work: &namespace_sdk_cleanup::Authority,
    ) -> Result<(), Response> {
        self.original.captured.matches_authority(work)
    }
    pub(in crate::service) fn check_current(&self, service: &Service) -> Result<(), Response> {
        namespace_diagnostic!("cleanup.private.service", self.original.captured.check_service(service))?;
        namespace_diagnostic!("cleanup.private.graph", self.original.captured.check_graph(&self.private))?;
        if service.current_state_identity()? != self.base {
            return Err(failed());
        }
        Ok(())
    }
    pub(in crate::service) fn merge_storage(
        &self,
        current: &mut State,
        incoming: &State,
    ) -> Result<(), Response> {
        self.original
            .captured
            .merge_owned_storage(current, incoming)
    }
    pub(in crate::service) fn clock_publication(
        self,
        service: &Service,
        at: crate::auth::Timestamp,
    ) -> Result<CleanupPublication, Response> {
        namespace_diagnostic!("custody.view.current", self.check_current(service))?;
        namespace_diagnostic!("cleanup.private.storage", self.original.captured.check_storage(&self.private))?;
        let logical = self.original.captured.clock_candidate(&self.private, at)?;
        self.close_publication(service, logical)
    }
    pub(in crate::service) fn callback_publication(
        self,
        service: &Service,
        candidate: State,
        incoming: &State,
        at: crate::auth::Timestamp,
    ) -> Result<CleanupPublication, Response> {
        namespace_diagnostic!("custody.view.current", self.check_current(service))?;
        namespace_diagnostic!("cleanup.private.storage", self.original.captured.check_storage(&self.private))?;
        let expected = namespace_diagnostic!("cleanup.callback.factory", self
            .original
            .captured
            .callback_candidate(&self.private, incoming, at))?;
        let mut actual = candidate;
        actual.schema = expected.writer_schema();
        let mut expected = expected;
        expected.schema = actual.schema;
        if wire(&actual)? != wire(&expected)? {
            #[cfg(test)]
            crate::service::namespace_diagnostics::record_status("cleanup.callback.full_candidate_equal", 503);
            return Err(failed());
        }
        self.close_publication(service, actual)
    }
}
pub(in crate::service) struct CleanupPublication {
    view: CleanupView,
    logical: State,
    closed: State,
    owners: BTreeMap<String, Owner>,
}

impl CleanupView {
    fn close_publication(
        self,
        service: &Service,
        mut logical: State,
    ) -> Result<CleanupPublication, Response> {
        namespace_diagnostic!("custody.view.current", self.check_current(service))?;
        logical.schema = logical.writer_schema();
        logical.namespace_leases = Leases::default();
        logical.namespace_protected = None;
        namespace_diagnostic!("custody.logical.publication", logical.validate_publication_schema(Some(&self.private)))?;
        namespace_diagnostic!("custody.logical.format", logical.validate_format())?;
        let mut closed = logical.clone();
        let keys = self.maintenance.lock().map_err(|_| failed())?;
        let mut paths = keys.keys.keys().cloned().collect::<Vec<_>>();
        paths.sort_by_key(|path| (std::cmp::Reverse(path.split('/').count()), path.clone()));
        let mut owners = BTreeMap::new();
        for actual in paths {
            let (previous, key) = keys.keys.get(&actual).ok_or_else(failed)?;
            if !key.matches_binding(previous.binding()) {
                return Err(failed());
            }
            closed = closed
                .partition_namespace_assets(&actual, key)?
                .finish_with_owner(|next, assets, cells| {
                    let bytes = wire(assets)?;
                    let prior = previous
                        .open_assets(previous.binding(), key)
                        .map_err(|_| failed())?;
                    let owner = if prior.as_slice() == bytes.as_slice() {
                        previous.clone()
                    } else {
                        previous
                            .replace_assets(previous.binding(), key, &bytes)
                            .map_err(|_| failed())?
                    };
                    // Same original binding, key epoch, frontier and parent.
                    if owner.binding() != previous.binding()
                        || owner.key_epoch() != previous.key_epoch()
                        || owner.seal_frontier() != previous.seal_frontier()
                        || owner.parent() != previous.parent()
                    {
                        return Err(failed());
                    }
                    next.engines
                        .publish_namespace_record_cells(previous.binding(), cells)
                        .map_err(|_| failed())?;
                    owner.install(next, &actual)?;
                    owners.insert(actual.clone(), owner);
                    Ok(())
                })?;
        }
        drop(keys);
        // Keep only the service's real unrelated runtime leases. No private
        // maintenance Key is made into a Slot, Lease or loaded route grant.
        closed.namespace_leases = service
            .state
            .as_ref()
            .ok_or_else(failed)?
            .namespace_leases
            .clone();
        namespace_diagnostic!("custody.closed.prepare", service.namespace_runtime.prepare(&mut closed))?;
        let proof = CleanupPublication {
            view: self,
            logical,
            closed,
            owners,
        };
        namespace_diagnostic!("custody.proof.validate", proof.validate(service))?;
        Ok(proof)
    }
}

impl CleanupPublication {
    pub(in crate::service) fn state(&self) -> &State {
        &self.closed
    }
    pub(in crate::service) fn logical_before(&self) -> &State {
        &self.view.private
    }
    pub(in crate::service) fn role(&self) -> Option<(u64, u64)> {
        self.view.role()
    }
    pub(in crate::service) fn check_original(&self) -> Result<(), Response> {
        self.view.original.captured.deadline()?;
        self.closed.namespace_leases.validate()?;
        let keys = self.view.maintenance.lock().map_err(|_| failed())?;
        if keys.keys.len() != self.owners.len() {
            return Err(failed());
        }
        for (actual, (expected, key)) in &keys.keys {
            let old = Owner::actual(&self.view.private, actual)?;
            let next = self.owners.get(actual).ok_or_else(failed)?;
            if &old != expected
                || !key.matches_binding(next.binding())
                || old.binding() != next.binding()
                || old.key_epoch() != next.key_epoch()
                || old.seal_frontier() != next.seal_frontier()
                || old.parent() != next.parent()
            {
                return Err(failed());
            }
        }
        self.view.original.captured.deadline()
    }
    pub(in crate::service) fn validate(&self, service: &Service) -> Result<(), Response> {
        self.view.check_current(service)?;
        namespace_diagnostic!("custody.original", self.check_original())?;
        self.logical
            .validate_publication_schema(Some(&self.view.private))?;
        namespace_diagnostic!("custody.proof.logical_format", self.logical.validate_format())?;
        let physical = self.closed.protected_state()?;
        namespace_diagnostic!("custody.proof.physical_format", physical.validate_format())?;
        physical.namespaces.validate_custody_successor(
            &service
                .state
                .as_ref()
                .ok_or_else(failed)?
                .protected_state()?
                .namespaces,
        )?;
        // Reopen the exact new descriptor and cells using the same sole Keys.
        // Compare the complete logical graph, never the locator projection.
        let keys = self.view.maintenance.lock().map_err(|_| failed())?;
        let mut restored = self.closed.clone();
        restored.namespace_leases = Leases::default();
        restored.namespace_protected = None;
        let mut paths = self.owners.keys().cloned().collect::<Vec<_>>();
        paths.sort_by_key(|path| (path.split('/').count(), path.clone()));
        for actual in paths {
            let next = self.owners.get(&actual).ok_or_else(failed)?;
            if Owner::actual(&restored, &actual)? != *next {
                return Err(failed());
            }
            let key = &keys.keys.get(&actual).ok_or_else(failed)?.1;
            let bytes = next
                .open_assets(next.binding(), key)
                .map_err(|_| failed())?;
            let assets = serde_json::from_slice(&bytes).map_err(|_| failed())?;
            let cells = restored
                .engines
                .namespace_record_cells(next.binding())
                .map_err(|_| failed())?;
            restored = restored.restore_namespace_assets(&actual, key, assets, &cells)?;
            restored.namespaces.set_sealed(&actual, false)?;
        }
        drop(keys);
        namespace_diagnostic!("custody.restored.format", restored.validate_format())?;
        if wire(&restored)? != wire(&self.logical)? {
            #[cfg(test)]
            {
                // Fixed component equality only. No values or paths are emitted.
                for (stage, equal) in [
                    ("custody.component.schema", restored.schema == self.logical.schema),
                    ("custody.component.replay", restored.replay_epoch == self.logical.replay_epoch),
                    ("custody.component.cluster", restored.cluster_id == self.logical.cluster_id),
                    ("custody.component.auth", wire(&restored.auth).and_then(|a| wire(&self.logical.auth).map(|b| a == b)).unwrap_or(false)),
                    ("custody.component.engines", wire(&restored.engines).and_then(|a| wire(&self.logical.engines).map(|b| a == b)).unwrap_or(false)),
                    ("custody.component.database", wire(&restored.database).and_then(|a| wire(&self.logical.database).map(|b| a == b)).unwrap_or(false)),
                    ("custody.component.raft_admin", wire(&restored.raft_admin).and_then(|a| wire(&self.logical.raft_admin).map(|b| a == b)).unwrap_or(false)),
                    ("custody.component.namespaces", wire(&restored.namespaces).and_then(|a| wire(&self.logical.namespaces).map(|b| a == b)).unwrap_or(false)),
                ] {
                    crate::service::namespace_diagnostics::record_status(stage, if equal { 200 } else { 503 });
                }
                for actual in self.owners.keys() {
                    let pair = Owner::actual(&restored, actual).and_then(|new| Owner::actual(&self.logical, actual).map(|old| (new, old)));
                    if let Ok((new, old)) = pair {
                        for (stage, equal) in [
                            ("custody.component.owner_equal", new == old),
                            ("custody.component.owner_binding", new.binding() == old.binding()),
                            ("custody.component.owner_epoch", new.key_epoch() == old.key_epoch()),
                            ("custody.component.owner_frontier", new.seal_frontier() == old.seal_frontier()),
                            ("custody.component.owner_parent", new.parent() == old.parent()),
                        ] {
                            crate::service::namespace_diagnostics::record_status(stage, if equal { 200 } else { 503 });
                        }
                    } else {
                        crate::service::namespace_diagnostics::record_status("custody.component.owner_lookup", 503);
                    }
                }
            }
            #[cfg(test)]
            crate::service::namespace_diagnostics::record_status("custody.proof.restored_equal", 503);
            return Err(failed());
        }
        self.view.check_current(service)?;
        self.check_original()
    }
    pub(in crate::service) fn installed(self, _service: &Service) -> Result<State, Response> {
        namespace_diagnostic!("custody.original", self.check_original())?;
        let mut keys = self.view.maintenance.lock().map_err(|_| failed())?;
        for (actual, next) in &self.owners {
            keys.keys.get_mut(actual).ok_or_else(failed)?.0 = next.clone();
        }
        drop(keys);
        namespace_diagnostic!("cleanup.installed.receipt", self.view.original.captured.installed(&self.logical))?;
        Ok(self.closed)
    }
}
