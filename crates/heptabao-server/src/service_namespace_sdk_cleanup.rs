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
        match (&self.ha, &service.ha) {
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
        }
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
                let mut writer = sdk_backend::writer_before(service, plan.deadline)?;
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
