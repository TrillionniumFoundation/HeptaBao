//! An affine native Revoke attempt for one durable Namespace SDK job.
//! No caller Principal, retry permission or Namespace HTTP grant is retained.
use super::*;
use crate::auth::namespace_sdk_cleanup::{Kind, Record, Stage};
use crate::namespace_custody::Binding;
use std::time::{Duration, Instant};

pub(in crate::service) struct Authority {
    key: String,
    selected: Record,
    clock: RequestClock,
    deadline: Instant,
    cluster: String,
    nonce: String,
    seal: [u8; 32],
    barrier: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
    native_role: Option<(u64, u64)>,
    delivery: namespace_runtime::DeliveryBinding,
    original_leases: namespace_runtime::Leases,
}
impl Authority {
    pub(in crate::service) fn capture(
        service: &Service,
        key: String,
        clock: RequestClock,
        deadline: Instant,
    ) -> Result<Self, Response> {
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let selected = state.namespace_sdk_cleanup_record(&key)?;
        if selected.stage() != &Stage::Attempted {
            return Err(unavailable());
        }
        let namespace = selected.binding().namespace();
        let native_role = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
            match &service.ha {
                None => None,
                Some(ha) => {
                    let node = ha.lock_for_request().map_err(|_| unavailable())?;
                    let observed = node.leader_status().map_err(|_| unavailable())?;
                    if !observed.local_is_leader || observed.leader != Some(observed.local_id) {
                        return Err(unavailable());
                    }
                    Some((observed.local_id, observed.term))
                }
            }
        };
        let value = Self {
            key,
            selected: selected.clone(),
            clock,
            deadline,
            cluster: state.cluster_id.clone(),
            nonce: service.unseal_nonce.clone(),
            seal: namespace_deletion::seal_digest(service)?,
            barrier: namespace_deletion::barrier_digest(service)?,
            ha: service.ha.clone(),
            native_role,
            delivery: namespace_runtime::DeliveryBinding::capture(state, namespace),
            original_leases: state.namespace_leases.clone(),
        };
        value.check(service)?;
        Ok(value)
    }
    pub(in crate::service) fn check_deadline(&self) -> Result<(), Response> {
        self.clock.observed_at().map_err(|_| unavailable())?;
        if Instant::now() >= self.deadline {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(in crate::service) fn check_auth(&self, auth: &AuthState) -> Result<(), Response> {
        self.check_deadline()?;
        if auth.sdk_auth_retirement_namespace_pending(self.selected.binding().namespace()) {
            return Err(unavailable());
        }
        let ledger = auth.namespace_deletion_ledger().ok_or_else(unavailable)?;
        if ledger.pending().get(self.selected.binding().namespace())
            != Some(self.selected.binding())
            || ledger
                .sdk_cleanup()
                .and_then(|jobs| jobs.records().get(&self.key))
                != Some(&self.selected)
        {
            return Err(unavailable());
        }
        Ok(())
    }
    fn check_ha_role(&self, service: &Service) -> Result<Option<(u64, u64)>, Response> {
        self.check_deadline()?;
        let actual = match (&self.ha, &service.ha) {
            (None, None) => Ok(None),
            (Some(original), Some(current)) if Arc::ptr_eq(original, current) => {
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
                let node = current.lock_for_request().map_err(|_| unavailable())?;
                let observation = node.leader_status().map_err(|_| unavailable())?;
                if !observation.local_is_leader || observation.leader != Some(observation.local_id)
                {
                    return Err(unavailable());
                }
                Ok(Some((observation.local_id, observation.term)))
            }
            _ => Err(unavailable()),
        }?;
        if actual != self.native_role {
            return Err(unavailable());
        }
        Ok(actual)
    }
    pub(in crate::service) fn sync_before_setup(
        &self,
        service: &mut Service,
    ) -> Result<(), Response> {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
        self.check_ha_role(service)?;
        if self.ha.is_some() {
            service.sync_from_ha_with_anchor(false)?;
        }
        // This checks the actual synchronized graph, saved job/lease, original
        // custody slots and nonce, and the same real leader/current prefix.
        self.check(service)
    }
    pub(in crate::service) fn check(&self, service: &Service) -> Result<(), Response> {
        self.check_deadline()?;
        self.original_leases.validate()?;
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.nonce
            || namespace_deletion::seal_digest(service)? != self.seal
            || namespace_deletion::barrier_digest(service)? != self.barrier
        {
            return Err(unavailable());
        }
        let role = self.check_ha_role(service)?;
        if let Some(ha) = &self.ha {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
            let node = ha.lock_for_request().map_err(|_| unavailable())?;
            node.ensure_application_identity(service.current_state_identity()?)
                .map_err(|_| unavailable())?;
        }
        if self.check_ha_role(service)? != role {
            return Err(unavailable());
        }
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        state.namespace_leases.validate()?;
        self.check_auth(&state.auth)?;
        state.validate_namespace_deletion_state()?;
        let namespace = self.selected.binding().namespace();
        if state.cluster_id != self.cluster
            || !state.namespace_is_tainted(namespace)
            || state.namespace_is_sealed(namespace)
            || !state.namespace_exists(namespace)
            || state
                .namespaces
                .custody_binding(&state.cluster_id, namespace)?
                != *self.selected.binding()
            || (state.namespaces.inherited_owner(namespace).is_some()
                && !service.namespace_runtime.is_loaded(namespace))
            || namespace_runtime::DeliveryBinding::capture(state, namespace) != self.delivery
        {
            return Err(unavailable());
        }
        let terminal = matches!(self.selected.stage(), Stage::Terminal { .. });
        match self.selected.kind() {
            Kind::Logical => {
                let record = state
                    .engines
                    .sdk_lease(namespace, self.selected.lease_id())
                    .ok_or_else(unavailable)?;
                self.selected
                    .check_logical(&record, terminal)
                    .map_err(auth_error)?;
            }
            Kind::Credential => {
                let record = state
                    .auth
                    .sdk_credential_record(namespace, self.selected.lease_id())
                    .ok_or_else(unavailable)?;
                self.selected
                    .check_credential(&record, terminal)
                    .map_err(auth_error)?;
            }
        }
        self.check_deadline()
    }
    fn logical_owner(
        &self,
        service: &Service,
        namespace: &str,
        mount: &str,
        owner: &crate::engines::sdk::MountOwner,
    ) -> Result<(), Response> {
        self.check(service)?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let lease = state
            .engines
            .sdk_lease(namespace, self.selected.lease_id())
            .ok_or_else(unavailable)?;
        if self.selected.kind() != Kind::Logical
            || self.selected.binding().namespace() != namespace
            || lease.namespace != namespace
            || lease.mount != mount
            || !lease.same_backend(owner)
        {
            return Err(unavailable());
        }
        Ok(())
    }
    fn credential_owner(
        &self,
        service: &Service,
        binding: &crate::auth::sdk::Binding,
    ) -> Result<(), Response> {
        self.check(service)?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let lease = state
            .auth
            .sdk_credential_record(&binding.namespace, self.selected.lease_id())
            .ok_or_else(unavailable)?;
        if self.selected.kind() != Kind::Credential
            || self.selected.binding().namespace() != binding.namespace
            || lease.backend != *binding
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(in crate::service) fn logical_native_role(
        &self,
        service: &Service,
        namespace: &str,
        mount: &str,
        owner: &crate::engines::sdk::MountOwner,
    ) -> Result<NativeRole, Response> {
        self.logical_owner(service, namespace, mount, owner)?;
        Ok(NativeRole {
            role: self.native_role,
        })
    }
    pub(in crate::service) fn credential_native_role(
        &self,
        service: &Service,
        binding: &crate::auth::sdk::Binding,
    ) -> Result<NativeRole, Response> {
        self.credential_owner(service, binding)?;
        Ok(NativeRole {
            role: self.native_role,
        })
    }
    pub(in crate::service) fn logical_storage_cut(
        &self,
        service: &Service,
        namespace: &str,
        mount: &str,
        owner: &crate::engines::sdk::MountOwner,
    ) -> Result<LogicalStorageCut, Response> {
        self.logical_owner(service, namespace, mount, owner)?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        Ok(LogicalStorageCut {
            original: state.engines.clone(),
            namespace: namespace.to_owned(),
            mount: mount.to_owned(),
            owner: owner.clone(),
        })
    }
    pub(in crate::service) fn credential_storage_cut(
        &self,
        service: &Service,
        binding: &crate::auth::sdk::Binding,
    ) -> Result<CredentialStorageCut, Response> {
        self.credential_owner(service, binding)?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        Ok(CredentialStorageCut {
            binding: binding.clone(),
            original: state
                .auth
                .sdk_auth_storage_witness(binding)
                .map_err(auth_error)?,
        })
    }
    pub(in crate::service) fn finish_logical(
        &self,
        state: &mut State,
        lease: &crate::engines::sdk_lease::Lease,
    ) -> Result<(), Response> {
        self.check_auth(&state.auth)?;
        state.finish_namespace_sdk_logical(&self.key, lease)
    }
    pub(in crate::service) fn finish_credential(
        &self,
        state: &mut State,
        lease: &crate::auth::sdk_credential::Record,
    ) -> Result<(), Response> {
        self.check_auth(&state.auth)?;
        state.finish_namespace_sdk_credential(&self.key, lease)
    }
    pub(in crate::service) fn after_publication(
        &mut self,
        auth: &AuthState,
    ) -> Result<(), Response> {
        self.check_deadline()?;
        let current = auth
            .namespace_deletion_ledger()
            .and_then(|ledger| ledger.sdk_cleanup())
            .and_then(|jobs| jobs.records().get(&self.key))
            .ok_or_else(unavailable)?;
        if current.work_id().map_err(auth_error)? != self.key
            || !current.is_terminal_successor(&self.selected)
        {
            return Err(unavailable());
        }
        self.selected = current.clone();
        self.check_auth(auth)
    }
}
// These affine receipts have no Clone or bearer/Principal projection. Their
// only constructors require the actual native job Authority and owned backend.
pub(in crate::service) struct NativeRole {
    role: Option<(u64, u64)>,
}
impl NativeRole {
    pub(in crate::service) fn captured(&self) -> Option<(u64, u64)> {
        self.role
    }
}
pub(in crate::service) struct LogicalStorageCut {
    original: CowOwner<EngineState>,
    namespace: String,
    mount: String,
    owner: crate::engines::sdk::MountOwner,
}
impl LogicalStorageCut {
    pub(in crate::service) fn check(
        &self,
        current: &EngineState,
        namespace: &str,
        mount: &str,
        owner: &crate::engines::sdk::MountOwner,
    ) -> Result<(), Response> {
        if self.namespace != namespace
            || self.mount != mount
            || self.owner != *owner
            || !current
                .sdk_storage_observations_match(&self.original, namespace, mount, owner)
                .map_err(Response::from_engine_error)?
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(in crate::service) fn merge(
        &self,
        current: &mut EngineState,
        working: &EngineState,
        namespace: &str,
        mount: &str,
        owner: &crate::engines::sdk::MountOwner,
    ) -> Result<(), Response> {
        self.check(current, namespace, mount, owner)?;
        current
            .sdk_merge_admitted_storage(&self.original, working, namespace, mount, owner)
            .map(|_| ())
            .map_err(Response::from_engine_error)
    }
}
pub(in crate::service) struct CredentialStorageCut {
    binding: crate::auth::sdk::Binding,
    original: crate::auth::sdk::StorageWitness,
}
impl CredentialStorageCut {
    pub(in crate::service) fn check(
        &self,
        current: &AuthState,
        binding: &crate::auth::sdk::Binding,
    ) -> Result<(), Response> {
        if self.binding != *binding {
            return Err(unavailable());
        }
        self.original.check(current, binding).map_err(auth_error)
    }
    pub(in crate::service) fn merge(
        &self,
        current: &mut AuthState,
        working: &AuthState,
        binding: &crate::auth::sdk::Binding,
    ) -> Result<(), Response> {
        self.check(current, binding)?;
        current
            .merge_sdk_auth_storage(binding, &self.original, working)
            .map_err(auth_error)
    }
}
fn unavailable() -> Response {
    Response::error(503, "namespace SDK cleanup owner unavailable")
}
fn auth_error(error: crate::auth::AuthError) -> Response {
    Response::error(error.status, &error.message)
}
impl State {
    pub(in crate::service) fn namespace_sdk_cleanup_record(
        &self,
        key: &str,
    ) -> Result<Record, Response> {
        self.validate_namespace_deletion_state()?;
        self.namespaces
            .deletions
            .as_ref()
            .and_then(|ledger| ledger.sdk_cleanup())
            .and_then(|jobs| jobs.records().get(key))
            .cloned()
            .ok_or_else(unavailable)
    }
    pub(in crate::service) fn attempt_namespace_sdk_cleanup(
        &mut self,
        key: &str,
    ) -> Result<(), Response> {
        self.namespaces
            .deletions
            .as_mut()
            .ok_or_else(unavailable)?
            .attempt_sdk_cleanup(key, &self.cluster_id)
            .map_err(auth_error)?;
        self.sync_namespace_deletion_ledger()?;
        self.schema = self.writer_schema();
        self.validate_namespace_deletion_state()
    }
    fn finish_namespace_sdk_logical(
        &mut self,
        key: &str,
        lease: &crate::engines::sdk_lease::Lease,
    ) -> Result<(), Response> {
        self.namespaces
            .deletions
            .as_mut()
            .ok_or_else(unavailable)?
            .finish_logical_sdk_cleanup(key, lease, &self.cluster_id)
            .map_err(auth_error)?;
        self.sync_namespace_deletion_ledger()?;
        self.schema = self.writer_schema();
        self.validate_namespace_deletion_state()
    }
    fn finish_namespace_sdk_credential(
        &mut self,
        key: &str,
        lease: &crate::auth::sdk_credential::Record,
    ) -> Result<(), Response> {
        self.namespaces
            .deletions
            .as_mut()
            .ok_or_else(unavailable)?
            .finish_credential_sdk_cleanup(key, lease, &self.cluster_id)
            .map_err(auth_error)?;
        self.sync_namespace_deletion_ledger()?;
        self.schema = self.writer_schema();
        self.validate_namespace_deletion_state()
    }
}
pub(in crate::service) enum Plan {
    Logical(Box<sdk_backend::Plan>),
    Credential(Box<sdk_backend::auth100::Plan>),
}
impl Plan {
    pub(in crate::service) fn execute(self, service: &Arc<Mutex<Service>>) -> Result<(), Response> {
        match self {
            Self::Logical(plan) => {
                let result = plan.execute(service, plan.deadline);
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
                let mut writer = namespace_diagnostic!(
                    "logical.execute.writer",
                    sdk_backend::writer_before(service, plan.deadline)
                )?;
                writer.finish_sdk_expiry(*plan, result)
            }
            Self::Credential(plan) => {
                let result = plan.execute(service, plan.deadline);
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
                let mut writer = sdk_backend::writer_before(service, plan.deadline)?;
                writer.finish_sdk_credential_expiry(*plan, result)
            }
        }
    }
}
impl Service {
    pub(in crate::service) fn namespace_sdk_cleanup_deadline(
        &self,
        clock: RequestClock,
    ) -> Option<Instant> {
        self.sdk_configuration
            .as_ref()
            .map(|config| clock.started() + Duration::from_millis(config.timeout_ms))
    }
    pub(in crate::service) fn prepare_namespace_sdk_cleanup(
        &mut self,
        clock: RequestClock,
    ) -> Result<Option<Plan>, Response> {
        let Some(state) = self.state.as_ref() else {
            return Ok(None);
        };
        state.validate_namespace_deletion_state()?;
        let selected =
            state.queued_namespace_sdk_cleanup(self.namespace_sdk_cleanup_cursor.as_deref());
        let Some((key, kind)) = selected else {
            return Ok(None);
        };
        self.namespace_sdk_cleanup_cursor = Some(key.clone());
        match kind {
            Kind::Logical => self
                .prepare_namespace_sdk_logical(clock, key)
                .map(|plan| plan.map(|p| Plan::Logical(Box::new(p)))),
            Kind::Credential => self
                .prepare_namespace_sdk_credential(clock, key)
                .map(|plan| plan.map(|p| Plan::Credential(Box::new(p)))),
        }
    }
}

impl State {
    fn queued_namespace_sdk_cleanup(&self, after: Option<&str>) -> Option<(String, Kind)> {
        let jobs = self.namespaces.deletions.as_ref()?.sdk_cleanup()?;
        jobs.records()
            .iter()
            .find(|(key, job)| {
                job.stage() == &Stage::Queued
                    && after.is_none_or(|previous| key.as_str() > previous)
            })
            .or_else(|| {
                jobs.records()
                    .iter()
                    .find(|(_, job)| job.stage() == &Stage::Queued)
            })
            .map(|(key, job)| (key.clone(), job.kind()))
    }
    pub(in crate::service) fn namespace_sdk_deletion_eligible(
        &self,
        namespace: &str,
    ) -> Result<bool, Response> {
        if self.auth.sdk_auth_retirement_namespace_pending(namespace) {
            return Ok(false);
        }
        let auth = self
            .auth
            .namespace_sdk_native_deletion_projection(namespace)
            .map_err(auth_error)?;
        let engines = self
            .engines
            .namespace_sdk_native_deletion_projection(namespace)
            .map_err(Response::from_engine_error)?;
        if !auth.namespace_has_only_native_deletion_owners(namespace)
            || !engines.namespace_has_only_native_local_deletion_owners(namespace)
            || !self.database.namespace_is_empty(namespace)
            || !self.namespaces.workflows.namespace_is_empty(namespace)
        {
            return Ok(false);
        }
        let logical = self
            .engines
            .namespace_sdk_deletion_records(namespace)
            .map_err(Response::from_engine_error)?;
        let credential = self
            .auth
            .namespace_sdk_deletion_records(namespace)
            .map_err(auth_error)?;
        // Historical Pending does not prove that no callback was sent.
        if logical
            .iter()
            .any(|record| record.phase == crate::engines::sdk_lease::Phase::PendingRevoke)
            || credential
                .iter()
                .any(|record| record.phase == crate::engines::sdk_lease::Phase::PendingRevoke)
        {
            return Ok(false);
        }
        Ok(true)
    }
    pub(in crate::service) fn queue_namespace_sdk_deletion(
        &mut self,
        binding: &Binding,
    ) -> Result<(), Response> {
        let namespace = binding.namespace();
        if self.auth.sdk_auth_retirement_namespace_pending(namespace) {
            return Err(unavailable());
        }
        let logical = self
            .engines
            .namespace_sdk_deletion_records(namespace)
            .map_err(Response::from_engine_error)?;
        let credential = self
            .auth
            .namespace_sdk_deletion_records(namespace)
            .map_err(auth_error)?;
        let refined = self
            .namespaces
            .deletions
            .as_ref()
            .is_some_and(|ledger| ledger.sdk_cleanup().is_some());
        if refined
            || !logical.is_empty()
            || !credential.is_empty()
            || !self
                .engines
                .namespace_sdk_mount_bindings(namespace)
                .map_err(Response::from_engine_error)?
                .is_empty()
            || !self
                .auth
                .namespace_sdk_auth_bindings(namespace)
                .map_err(auth_error)?
                .is_empty()
        {
            self.engines.ensure_sdk_logical_history();
            let history = self
                .engines
                .sdk_logical_history_projection()
                .map_err(Response::from_engine_error)?
                .ok_or_else(unavailable)?;
            self.namespaces
                .deletions
                .as_mut()
                .ok_or_else(unavailable)?
                .ensure_sdk_cleanup(history, &self.cluster_id)
                .map_err(auth_error)?;
        }
        for mut lease in logical {
            if lease.phase == crate::engines::sdk_lease::Phase::Revoked {
                continue;
            }
            if lease.phase != crate::engines::sdk_lease::Phase::Active {
                return Err(unavailable());
            }
            lease.phase = crate::engines::sdk_lease::Phase::PendingRevoke;
            let job = Record::logical(binding.clone(), &lease).map_err(auth_error)?;
            self.engines
                .store_sdk_lease(lease)
                .map_err(Response::from_engine_error)?;
            self.namespaces
                .deletions
                .as_mut()
                .ok_or_else(unavailable)?
                .queue_sdk_cleanup(job, &self.cluster_id)
                .map_err(auth_error)?;
        }
        for mut lease in credential {
            if lease.phase == crate::engines::sdk_lease::Phase::Revoked {
                continue;
            }
            if lease.phase != crate::engines::sdk_lease::Phase::Active {
                return Err(unavailable());
            }
            lease.phase = crate::engines::sdk_lease::Phase::PendingRevoke;
            let job = Record::credential(binding.clone(), &lease).map_err(auth_error)?;
            self.auth.store_sdk_credential(lease).map_err(auth_error)?;
            self.namespaces
                .deletions
                .as_mut()
                .ok_or_else(unavailable)?
                .queue_sdk_cleanup(job, &self.cluster_id)
                .map_err(auth_error)?;
        }
        if let Some(ledger) = self.namespaces.deletions.as_mut()
            && ledger.sdk_cleanup().is_some()
        {
            ledger.seal_sdk_selection(binding).map_err(auth_error)?;
        }
        self.sync_namespace_deletion_ledger()?;
        self.schema = self.writer_schema();
        self.validate_namespace_deletion_state()
    }
    pub(in crate::service) fn namespace_sdk_deletion_terminal(
        &self,
        namespace: &str,
    ) -> Result<bool, Response> {
        self.validate_namespace_deletion_state()?;
        let logical = self
            .engines
            .namespace_sdk_deletion_records(namespace)
            .map_err(Response::from_engine_error)?;
        let credential = self
            .auth
            .namespace_sdk_deletion_records(namespace)
            .map_err(auth_error)?;
        if logical
            .iter()
            .any(|record| record.phase != crate::engines::sdk_lease::Phase::Revoked)
            || credential
                .iter()
                .any(|record| record.phase != crate::engines::sdk_lease::Phase::Revoked)
        {
            return Ok(false);
        }
        if let Some(jobs) = self
            .namespaces
            .deletions
            .as_ref()
            .and_then(|ledger| ledger.sdk_cleanup())
        {
            for job in jobs
                .records()
                .values()
                .filter(|job| job.binding().namespace() == namespace)
            {
                if !matches!(job.stage(), Stage::Terminal { .. }) {
                    return Ok(false);
                }
                match job.kind() {
                    Kind::Logical => job
                        .check_logical(
                            &self
                                .engines
                                .sdk_lease(namespace, job.lease_id())
                                .ok_or_else(unavailable)?,
                            true,
                        )
                        .map_err(auth_error)?,
                    Kind::Credential => job
                        .check_credential(
                            &self
                                .auth
                                .sdk_credential_record(namespace, job.lease_id())
                                .ok_or_else(unavailable)?,
                            true,
                        )
                        .map_err(auth_error)?,
                }
            }
        }
        let auth = self
            .auth
            .namespace_sdk_native_deletion_projection(namespace)
            .map_err(auth_error)?;
        let engines = self
            .engines
            .namespace_sdk_native_deletion_projection(namespace)
            .map_err(Response::from_engine_error)?;
        Ok(auth.namespace_has_only_native_deletion_owners(namespace)
            && engines.namespace_has_only_native_local_deletion_owners(namespace)
            && self.database.namespace_is_empty(namespace)
            && self.namespaces.workflows.namespace_is_empty(namespace))
    }
}

#[cfg(test)]
#[path = "service_namespace_sdk_cleanup_tests.rs"]
mod tests;

// This process-local value can only be made by the actual owning Authority.
// It is neither a saved-record reader nor an SDK admission or retry grant.
pub(in crate::service) struct CapturedCleanup {
    key: String,
    selected: Mutex<Record>,
    resource: Mutex<CleanupResource>,
    storage: Mutex<CleanupStorage>,
    clock: RequestClock,
    deadline: Instant,
    cluster: String,
    nonce: String,
    seal: [u8; 32],
    barrier: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
    native_role: Option<(u64, u64)>,
    delivery: namespace_runtime::DeliveryBinding,
    control: Arc<sdk_backend::Control>,
    host_key: String,
}
enum CleanupResource {
    Logical(crate::engines::sdk_lease::Lease),
    Credential(crate::auth::sdk_credential::Record),
}
enum CleanupStorage {
    Logical(LogicalStorageCut),
    Credential(CredentialStorageCut),
}
impl Authority {
    pub(in crate::service) fn logical_native_role_private(
        &self,
        service: &Service,
        view: &namespace_runtime::CleanupView,
        namespace: &str,
        mount: &str,
        owner: &crate::engines::sdk::MountOwner,
    ) -> Result<NativeRole, Response> {
        self.check_private_graph(service, view)?;
        let lease = view
            .state()
            .engines
            .sdk_lease(namespace, self.selected.lease_id())
            .ok_or_else(unavailable)?;
        if self.selected.kind() != Kind::Logical
            || self.selected.binding().namespace() != namespace
            || lease.mount != mount
            || !lease.same_backend(owner)
        {
            return Err(unavailable());
        }
        Ok(NativeRole {
            role: self.native_role,
        })
    }
    pub(in crate::service) fn logical_storage_cut_private(
        &self,
        service: &Service,
        view: &namespace_runtime::CleanupView,
        namespace: &str,
        mount: &str,
        owner: &crate::engines::sdk::MountOwner,
    ) -> Result<LogicalStorageCut, Response> {
        self.logical_native_role_private(service, view, namespace, mount, owner)?;
        Ok(LogicalStorageCut {
            original: view.state().engines.clone(),
            namespace: namespace.into(),
            mount: mount.into(),
            owner: owner.clone(),
        })
    }
    pub(in crate::service) fn capture_logical_custody(
        &self,
        service: &mut Service,
        namespace: &str,
        mount: &str,
        owner: &crate::engines::sdk::MountOwner,
        control: Arc<sdk_backend::Control>,
    ) -> Result<namespace_runtime::CleanupPermit, Response> {
        self.logical_owner(service, namespace, mount, owner)?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let lease = state
            .engines
            .sdk_lease(namespace, self.selected.lease_id())
            .ok_or_else(unavailable)?;
        self.selected
            .check_logical(&lease, false)
            .map_err(auth_error)?;
        let storage =
            CleanupStorage::Logical(self.logical_storage_cut(service, namespace, mount, owner)?);
        let captured = self.capture_private(
            service,
            CleanupResource::Logical(lease),
            storage,
            control,
            service.sdk_host_key(namespace, mount, owner),
        )?;
        service
            .namespace_runtime
            .register_namespace_cleanup(captured)
    }
    pub(in crate::service) fn capture_credential_custody(
        &self,
        service: &mut Service,
        binding: &crate::auth::sdk::Binding,
        control: Arc<sdk_backend::Control>,
    ) -> Result<namespace_runtime::CleanupPermit, Response> {
        self.credential_owner(service, binding)?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let lease = state
            .auth
            .sdk_credential_record(&binding.namespace, self.selected.lease_id())
            .ok_or_else(unavailable)?;
        self.selected
            .check_credential(&lease, false)
            .map_err(auth_error)?;
        let storage = CleanupStorage::Credential(self.credential_storage_cut(service, binding)?);
        let captured = self.capture_private(
            service,
            CleanupResource::Credential(lease),
            storage,
            control,
            sdk_backend::auth100::sdk_auth_key(&self.cluster, binding)?,
        )?;
        service
            .namespace_runtime
            .register_namespace_cleanup(captured)
    }
    fn capture_private(
        &self,
        service: &Service,
        resource: CleanupResource,
        storage: CleanupStorage,
        control: Arc<sdk_backend::Control>,
        host_key: String,
    ) -> Result<CapturedCleanup, Response> {
        self.check(service)?;
        if self.selected.stage() != &Stage::Attempted
            || self.selected.work_id().map_err(auth_error)? != self.key
            || service
                .sdk_hosts
                .get(&host_key)
                .is_none_or(|current| !Arc::ptr_eq(current, &control))
        {
            return Err(unavailable());
        }
        Ok(CapturedCleanup {
            key: self.key.clone(),
            selected: Mutex::new(self.selected.clone()),
            resource: Mutex::new(resource),
            storage: Mutex::new(storage),
            clock: self.clock,
            deadline: self.deadline,
            cluster: self.cluster.clone(),
            nonce: self.nonce.clone(),
            seal: self.seal,
            barrier: self.barrier,
            ha: self.ha.clone(),
            native_role: self.native_role,
            delivery: self.delivery.clone(),
            control,
            host_key,
        })
    }
    pub(in crate::service) fn check_private_graph(
        &self,
        service: &Service,
        view: &namespace_runtime::CleanupView,
    ) -> Result<(), Response> {
        view.matches_authority(self)?;
        view.check_current(service)?;
        self.check_auth(&view.state().auth)?;
        self.check_deadline()
    }
}
impl CapturedCleanup {
    pub(in crate::service) fn namespace(&self) -> Result<String, Response> {
        Ok(self
            .selected
            .lock()
            .map_err(|_| unavailable())?
            .binding()
            .namespace()
            .into())
    }
    pub(in crate::service) fn role(&self) -> Option<(u64, u64)> {
        self.native_role
    }
    pub(in crate::service) fn matches_origin(
        &self,
        namespace: &str,
        incarnation: Option<u64>,
        cluster: &str,
        activation: &str,
        ha: &Option<Arc<Mutex<HaProcess>>>,
        delivery: &namespace_runtime::DeliveryBinding,
        clock: RequestClock,
        deadline: Instant,
    ) -> Result<(), Response> {
        let selected = self.selected.lock().map_err(|_| unavailable())?;
        if namespace != selected.binding().namespace()
            || incarnation != Some(selected.binding().incarnation())
            || cluster != self.cluster
            || activation != self.nonce
            || !same_ha(ha, &self.ha)
            || delivery != &self.delivery
            || clock.started() != self.clock.started()
            || deadline != self.deadline
        {
            return Err(unavailable());
        }
        self.deadline()
    }

    pub(in crate::service) fn deadline(&self) -> Result<(), Response> {
        self.clock.observed_at().map_err(|_| unavailable())?;
        if Instant::now() >= self.deadline {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(in crate::service) fn matches_authority(&self, work: &Authority) -> Result<(), Response> {
        self.deadline()?;
        if work.key != self.key
            || work.selected != *self.selected.lock().map_err(|_| unavailable())?
            || work.clock.started() != self.clock.started()
            || work.clock.admitted_at() != self.clock.admitted_at()
            || work.deadline != self.deadline
            || work.cluster != self.cluster
            || work.nonce != self.nonce
            || work.seal != self.seal
            || work.barrier != self.barrier
            || !same_ha(&work.ha, &self.ha)
            || work.native_role != self.native_role
            || work.delivery != self.delivery
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(in crate::service) fn eligible_for_seal(
        &self,
        activation: &str,
        seal: [u8; 32],
        barrier: [u8; 32],
        cluster: &str,
        ha: &Option<Arc<Mutex<HaProcess>>>,
        role: Option<(u64, u64)>,
    ) -> bool {
        self.nonce == activation
            && self.seal == seal
            && self.barrier == barrier
            && self.cluster == cluster
            && same_ha(&self.ha, ha)
            && self.native_role == role
            && self.deadline().is_ok()
    }
    pub(in crate::service) fn check_service(&self, service: &Service) -> Result<(), Response> {
        self.deadline()?;
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.nonce
            || service
                .state
                .as_ref()
                .is_none_or(|state| state.cluster_id != self.cluster)
            || namespace_deletion::seal_digest(service)? != self.seal
            || namespace_deletion::barrier_digest(service)? != self.barrier
            || !same_ha(&self.ha, &service.ha)
            || service
                .sdk_hosts
                .get(&self.host_key)
                .is_none_or(|current| !Arc::ptr_eq(current, &self.control))
        {
            return Err(unavailable());
        }
        if let Some(ha) = &self.ha {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
            let node = ha.lock_for_request().map_err(|_| unavailable())?;
            for observed in [node.leader_status().map_err(|_| unavailable())?] {
                if !observed.local_is_leader
                    || observed.leader != Some(observed.local_id)
                    || Some((observed.local_id, observed.term)) != self.native_role
                {
                    return Err(unavailable());
                }
            }
            node.ensure_application_identity(service.current_state_identity()?)
                .map_err(|_| unavailable())?;
            let observed = node.leader_status().map_err(|_| unavailable())?;
            if !observed.local_is_leader
                || observed.leader != Some(observed.local_id)
                || Some((observed.local_id, observed.term)) != self.native_role
            {
                return Err(unavailable());
            }
        } else if self.native_role.is_some() {
            return Err(unavailable());
        }
        self.deadline()
    }
    pub(in crate::service) fn check_graph(&self, state: &State) -> Result<(), Response> {
        self.deadline()?;
        state.validate_namespace_deletion_state()?;
        let selected = self.selected.lock().map_err(|_| unavailable())?;
        let current = state.namespace_sdk_cleanup_record(&self.key)?;
        if current != *selected
            || current.work_id().map_err(auth_error)? != self.key
            || state.cluster_id != self.cluster
            || !state.namespace_is_tainted(current.binding().namespace())
            || state.namespace_is_sealed(current.binding().namespace())
            || !state.namespace_exists(current.binding().namespace())
            || state
                .namespaces
                .custody_binding(&state.cluster_id, current.binding().namespace())?
                != *current.binding()
            || state
                .auth
                .sdk_auth_retirement_namespace_pending(current.binding().namespace())
        {
            return Err(unavailable());
        }
        let terminal = matches!(selected.stage(), Stage::Terminal { .. });
        match &*self.resource.lock().map_err(|_| unavailable())? {
            CleanupResource::Logical(original) => {
                let actual = state
                    .engines
                    .sdk_lease(&original.namespace, &original.id)
                    .ok_or_else(unavailable)?;
                selected
                    .check_logical(&actual, terminal)
                    .map_err(auth_error)?;
                if resource_digest(&actual)? != resource_digest(original)? {
                    return Err(unavailable());
                }
            }
            CleanupResource::Credential(original) => {
                let actual = state
                    .auth
                    .sdk_credential_record(&original.namespace, &original.id)
                    .ok_or_else(unavailable)?;
                selected
                    .check_credential(&actual, terminal)
                    .map_err(auth_error)?;
                if resource_digest(&actual)? != resource_digest(original)? {
                    return Err(unavailable());
                }
            }
        }
        self.deadline()
    }
    pub(in crate::service) fn merge_owned_storage(
        &self,
        current: &mut State,
        incoming: &State,
    ) -> Result<(), Response> {
        self.check_graph(current)?;
        match &*self.storage.lock().map_err(|_| unavailable())? {
            CleanupStorage::Logical(cut) => cut.merge(
                &mut current.engines,
                &incoming.engines,
                &cut.namespace,
                &cut.mount,
                &cut.owner,
            )?,
            CleanupStorage::Credential(cut) => {
                cut.merge(&mut current.auth, &incoming.auth, &cut.binding)?
            }
        }
        Ok(())
    }
    pub(in crate::service) fn check_storage(&self, state: &State) -> Result<(), Response> {
        self.check_graph(state)?;
        match &*self.storage.lock().map_err(|_| unavailable())? {
            CleanupStorage::Logical(cut) => {
                cut.check(&state.engines, &cut.namespace, &cut.mount, &cut.owner)
            }
            CleanupStorage::Credential(cut) => cut.check(&state.auth, &cut.binding),
        }
    }
    pub(in crate::service) fn clock_candidate(
        &self,
        state: &State,
        at: Timestamp,
    ) -> Result<State, Response> {
        self.deadline()?;
        self.check_storage(state)?;
        let floor = match &*self.resource.lock().map_err(|_| unavailable())? {
            CleanupResource::Logical(_) => state.engines.sdk_lease_clock_floor(),
            CleanupResource::Credential(_) => state.auth.sdk_auth_clock_floor(),
        };
        let observed = floor
            .map_or(self.clock, |floor| self.clock.with_timestamp_floor(floor))
            .observed_at()
            .map_err(|_| unavailable())?;
        if at < self.clock.admitted_at() || floor.is_some_and(|floor| at < floor) || at > observed {
            return Err(unavailable());
        }
        let mut candidate = state.clone();
        match &*self.resource.lock().map_err(|_| unavailable())? {
            CleanupResource::Logical(_) => {
                candidate.engines.observe_sdk_lease_clock(at);
            }
            CleanupResource::Credential(_) => {
                candidate.auth.observe_sdk_auth_clock(at);
            }
        }
        self.deadline()?;
        Ok(candidate)
    }
    pub(in crate::service) fn callback_candidate(
        &self,
        original: &State,
        incoming: &State,
        at: Timestamp,
    ) -> Result<State, Response> {
        self.deadline()?;
        let floor = match &*self.resource.lock().map_err(|_| unavailable())? {
            CleanupResource::Logical(_) => original.engines.sdk_lease_clock_floor(),
            CleanupResource::Credential(_) => original.auth.sdk_auth_clock_floor(),
        };
        let observed = floor
            .map_or(self.clock, |floor| self.clock.with_timestamp_floor(floor))
            .observed_at()
            .map_err(|_| unavailable())?;
        if at < self.clock.admitted_at() || at > observed || floor.is_some_and(|floor| at < floor) {
            return Err(unavailable());
        }
        let mut expected = original.clone();
        self.merge_owned_storage(&mut expected, incoming)?;
        match &*self.resource.lock().map_err(|_| unavailable())? {
            CleanupResource::Logical(lease) => {
                let mut terminal = lease.clone();
                terminal.revoke();
                expected.engines.observe_sdk_lease_clock(at);
                expected
                    .engines
                    .store_sdk_lease(terminal.clone())
                    .map_err(Response::from_engine_error)?;
                expected.finish_namespace_sdk_logical(&self.key, &terminal)?;
            }
            CleanupResource::Credential(lease) => {
                let mut terminal = lease.clone();
                terminal.revoke();
                expected.auth.observe_sdk_auth_clock(at);
                expected
                    .auth
                    .store_sdk_credential(terminal.clone())
                    .map_err(auth_error)?;
                expected.finish_namespace_sdk_credential(&self.key, &terminal)?;
            }
        }
        self.deadline()?;
        Ok(expected)
    }
    pub(in crate::service) fn installed(&self, state: &State) -> Result<(), Response> {
        self.deadline()?;
        let next = state.namespace_sdk_cleanup_record(&self.key)?;
        let mut selected = self.selected.lock().map_err(|_| unavailable())?;
        if next != *selected && !next.is_terminal_successor(&selected) {
            return Err(unavailable());
        }
        let terminal = matches!(next.stage(), Stage::Terminal { .. });
        let mut resource = self.resource.lock().map_err(|_| unavailable())?;
        match &mut *resource {
            CleanupResource::Logical(old) => {
                let next = state
                    .engines
                    .sdk_lease(&old.namespace, &old.id)
                    .ok_or_else(unavailable)?;
                let mut expected = old.clone();
                if terminal {
                    expected.revoke();
                }
                if resource_digest(&next)? != resource_digest(&expected)? {
                    return Err(unavailable());
                }
                let cut = LogicalStorageCut {
                    original: state.engines.clone(),
                    namespace: old.namespace.clone(),
                    mount: old.mount.clone(),
                    owner: old.backend.clone(),
                };
                *self.storage.lock().map_err(|_| unavailable())? = CleanupStorage::Logical(cut);
                *old = next;
            }
            CleanupResource::Credential(old) => {
                let next = state
                    .auth
                    .sdk_credential_record(&old.namespace, &old.id)
                    .ok_or_else(unavailable)?;
                let mut expected = old.clone();
                if terminal {
                    expected.revoke();
                }
                if resource_digest(&next)? != resource_digest(&expected)? {
                    return Err(unavailable());
                }
                let cut = CredentialStorageCut {
                    binding: old.backend.clone(),
                    original: state
                        .auth
                        .sdk_auth_storage_witness(&old.backend)
                        .map_err(auth_error)?,
                };
                *self.storage.lock().map_err(|_| unavailable())? = CleanupStorage::Credential(cut);
                *old = next;
            }
        }
        *selected = next;
        drop(resource);
        drop(selected);
        self.deadline()
    }
}
fn same_ha(a: &Option<Arc<Mutex<HaProcess>>>, b: &Option<Arc<Mutex<HaProcess>>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}
fn resource_digest(value: &impl Serialize) -> Result<[u8; 32], Response> {
    let wire =
        Zeroizing::new(crate::secret_serde::to_vec(value, 512 * 1024).map_err(|_| unavailable())?);
    Ok(crypto::digest(&wire))
}
