//! One native task from actual accepted107 intent; no reconstructed caller.
use super::*;
use crate::auth::sdk_retirement::RecoverySelection;

pub(in crate::service) struct Authority {
    pub(super) selected: RecoverySelection,
    clock: RequestClock,
    deadline: Instant,
    cluster: String,
    nonce: String,
    seal: [u8; 32],
    barrier: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
    role: Option<(u64, u64)>,
    delivery: namespace_runtime::DeliveryBinding,
    leases: namespace_runtime::Leases,
    storage: Option<StorageWitness>,
}
fn unavailable() -> Response {
    Response::error(503, "SDK Auth native retirement owner unavailable")
}
impl Authority {
    pub(in crate::service) fn role_for_custody(&self) -> Option<(u64, u64)> {
        self.role
    }
    fn capture(
        service: &Service,
        selected: RecoverySelection,
        clock: RequestClock,
        deadline: Instant,
    ) -> Result<Self, Response> {
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let binding = selected.binding();
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
        let value = Self {
            storage: Some(
                state
                    .auth
                    .sdk_auth_storage_witness(binding)
                    .map_err(auth_error)?,
            ),
            cluster: state.cluster_id.clone(),
            nonce: service.unseal_nonce.clone(),
            seal: namespace_deletion::seal_digest(service)?,
            barrier: namespace_deletion::barrier_digest(service)?,
            ha: service.ha.clone(),
            role,
            delivery: namespace_runtime::DeliveryBinding::capture(state, &binding.namespace),
            leases: state.namespace_leases.clone(),
            selected,
            clock,
            deadline,
        };
        value.check(service)?;
        Ok(value)
    }
    pub(in crate::service) fn time(&self, auth: &AuthState) -> Result<Timestamp, Response> {
        self.deadline()?;
        let clock = auth
            .sdk_auth_clock_floor()
            .map_or(self.clock, |floor| self.clock.with_timestamp_floor(floor));
        auth.token_api_observed_time(AuthorityTime::Precise(
            clock.observed_at().map_err(|_| unavailable())?,
        ))
        .exact()
        .ok_or_else(unavailable)
    }
    fn deadline(&self) -> Result<(), Response> {
        self.clock.observed_at().map_err(|_| unavailable())?;
        if Instant::now() >= self.deadline {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(in crate::service) fn check_auth(&self, auth: &AuthState) -> Result<(), Response> {
        self.deadline()?;
        self.selected.check(auth).map_err(auth_error)?;
        if let Some(storage) = &self.storage {
            storage
                .check(auth, self.selected.binding())
                .map_err(auth_error)?;
        }
        if !self.selected.completed()
            && auth.sdk_auth_retirement_has_live_issuer(self.selected.binding(), self.time(auth)?)
        {
            return Err(unavailable());
        }
        Ok(())
    }
    fn check_role(&self, service: &Service) -> Result<(), Response> {
        self.deadline()?;
        match (&self.ha, &service.ha, self.role) {
            (None, None, None) => Ok(()),
            (Some(original), Some(current), Some(expected)) if Arc::ptr_eq(original, current) => {
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
                let node = current.lock_for_request().map_err(|_| unavailable())?;
                let role = node.leader_status().map_err(|_| unavailable())?;
                if !role.local_is_leader
                    || role.leader != Some(role.local_id)
                    || (role.local_id, role.term) != expected
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
    pub(in crate::service) fn sync_before_setup(
        &self,
        service: &mut Service,
    ) -> Result<(), Response> {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.deadline);
        // Check the original role before sync; sync cannot adopt a replacement
        // leader term or refresh this task's one original deadline.
        self.check_role(service)?;
        if self.ha.is_some() {
            service.sync_from_ha_with_anchor(false)?;
        }
        self.check(service)
    }
    pub(in crate::service) fn check(&self, service: &Service) -> Result<(), Response> {
        self.deadline()?;
        self.leases.validate()?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        state.namespace_leases.validate()?;
        let namespace = &self.selected.binding().namespace;
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.nonce
            || namespace_deletion::seal_digest(service)? != self.seal
            || namespace_deletion::barrier_digest(service)? != self.barrier
            || state.cluster_id != self.cluster
            || !state.namespace_exists(namespace)
            || state.namespace_is_sealed(namespace)
            || namespace_runtime::DeliveryBinding::capture(state, namespace) != self.delivery
            || state.namespaces.inherited_owner(namespace).is_some()
                && !service.namespace_runtime.is_loaded(namespace)
        {
            return Err(unavailable());
        }
        self.check_role(service)?;
        self.check_auth(&state.auth)
    }
    pub(super) fn published_attempt(
        &mut self,
        service: &Service,
        id: &str,
        at: Timestamp,
    ) -> Result<(), Response> {
        let auth = &service.state.as_ref().ok_or_else(unavailable)?.auth;
        self.selected
            .published_attempt(auth, id, at)
            .map_err(auth_error)?;
        self.check(service)
    }
    pub(super) fn published_terminal(
        &mut self,
        auth: &AuthState,
        id: &str,
        at: Timestamp,
    ) -> Result<(), Response> {
        self.selected
            .published_terminal(auth, id, at)
            .map_err(auth_error)?;
        // This is called only after the exact Revoke callback candidate was
        // installed. Its Terminal successor proves the only owned Storage cut.
        self.storage = Some(
            auth.sdk_auth_storage_witness(self.selected.binding())
                .map_err(auth_error)?,
        );
        self.check_auth(auth)
    }
    pub(in crate::service) fn published_private_removal(
        &mut self,
        auth: &AuthState,
        at: Timestamp,
    ) -> Result<(), Response> {
        self.selected
            .published_removal(auth, at)
            .map_err(auth_error)?;
        self.storage = None;
        self.check_auth(auth)
    }
    pub(super) fn published_removal(
        &mut self,
        service: &Service,
        at: Timestamp,
    ) -> Result<(), Response> {
        let auth = &service.state.as_ref().ok_or_else(unavailable)?.auth;
        self.selected
            .published_removal(auth, at)
            .map_err(auth_error)?;
        self.storage = None;
        self.check(service)
    }
}

pub(in crate::service) struct FinalRemoval {
    authority: Authority,
    control: Option<Arc<Control>>,
}
pub(in crate::service) enum RecoveryWork {
    Callback(Box<Plan>),
    Final(Box<FinalRemoval>),
}
impl RecoveryWork {
    pub(in crate::service) fn execute(self, service: &Arc<Mutex<Service>>) -> Result<(), Response> {
        match self {
            Self::Callback(mut plan) => {
                let result = plan.execute(service, plan.deadline);
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
                let mut writer = writer_before(service, plan.deadline)?;
                let correlation = plan
                    .retirement
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .lock()
                    .map_err(|_| unavailable())?
                    .native
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .selected
                    .correlation()
                    .to_owned();
                let response = writer.finalize_sdk_auth(&mut plan, result);
                let at = plan.time(&writer.state.as_ref().ok_or_else(unavailable)?.auth)?;
                writer.audit_sdk_auth_recovery_response(&correlation, at, response.status)?;
                let response = writer.complete_sdk_auth_delivery(&plan, response, &correlation);
                if response.status >= 400 {
                    return Err(response);
                }
                Ok(())
            }
            Self::Final(mut work) => {
                let deadline = work.authority.deadline;
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
                let mut writer = writer_before(service, deadline)?;
                work.authority.sync_before_setup(&mut writer)?;
                writer.check_sdk_auth_final_control(&work)?;
                let mut state = writer.state.clone().ok_or_else(unavailable)?;
                let at = work.authority.time(&state.auth)?;
                let expected = writer.current_state_identity()?;
                state.auth.observe_sdk_auth_clock(at);
                state
                    .auth
                    .remove_sdk_auth_retirement_mount(&work.authority.selected, at)
                    .map_err(auth_error)?;
                writer.commit_sdk_auth_recovery_state(&mut state, &work.authority, &expected)?;
                work.authority.published_removal(&writer, at)?;
                let key = sdk_auth_key(&work.authority.cluster, work.authority.selected.binding())?;
                if let Some(host) = writer.sdk_hosts.remove(&key) {
                    host.retire();
                }
                writer.audit_sdk_auth_recovery_response(
                    work.authority.selected.correlation(),
                    at,
                    204,
                )?;
                work.authority.check(&writer)?;
                Ok(())
            }
        }
    }
}
impl Service {
    fn audit_sdk_auth_recovery_response(
        &mut self,
        correlation: &str,
        at: Timestamp,
        status: u16,
    ) -> Result<(), Response> {
        if self
            .audit_event(
                "sdk-auth-retirement-recovery-response",
                correlation,
                at.seconds(),
                Some(status),
            )
            .is_err()
        {
            self.recovery_required = true;
            self.ha_activation = None;
            self.retire_sdk_hosts();
            return Err(Response::error(
                503,
                "SDK Auth recovery response audit failed",
            ));
        }
        Ok(())
    }
    pub(super) fn commit_sdk_auth_recovery_state(
        &mut self,
        state: &mut State,
        authority: &Authority,
        expected: &crate::state_record_root::StateIdentity,
    ) -> Result<(), Response> {
        authority.sync_before_setup(self)?;
        if self.current_state_identity()? != *expected {
            return Err(unavailable());
        }
        state.schema = state.writer_schema();
        let publication = self.prepare_record_plan(state)?;
        authority.check(self)?;
        if self.current_state_identity()? != *expected {
            return Err(unavailable());
        }
        self.commit_record_plan_with_before_publish(
            state,
            publication,
            |auth| authority.check_auth(auth),
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        )?;
        self.state = Some(state.clone());
        Ok(())
    }
    fn check_sdk_auth_final_control(&self, work: &FinalRemoval) -> Result<(), Response> {
        work.authority.check(self)?;
        let key = sdk_auth_key(&work.authority.cluster, work.authority.selected.binding())?;
        match (&work.control, self.sdk_hosts.get(&key)) {
            (None, None) => Ok(()),
            (Some(original), Some(current))
                if Arc::ptr_eq(original, current)
                    && !current.busy.load(Ordering::Acquire)
                    && current.retiring.load(Ordering::Acquire) =>
            {
                Ok(())
            }
            _ => Err(unavailable()),
        }
    }
    pub(in crate::service) fn prepare_sdk_auth_retirement_recovery(
        &mut self,
        clock: RequestClock,
    ) -> Result<Option<RecoveryWork>, Response> {
        if self.pending_sdk_auth_request.is_some() || self.recovery_required || self.audit_failed {
            return Ok(None);
        }
        let Some(timeout) = self
            .sdk_configuration
            .as_ref()
            .map(|config| config.timeout_ms)
        else {
            return Ok(None);
        };
        let budget = clock
            .started()
            .checked_add(Duration::from_millis(timeout))
            .ok_or_else(unavailable)?;
        let deadline = crate::request_deadline::current().map_or(budget, |outer| outer.min(budget));
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        if let Some(ha) = &self.ha {
            let node = ha.lock_for_request().map_err(|_| unavailable())?;
            let role = node.leader_status().map_err(|_| unavailable())?;
            if !role.local_is_leader || role.leader != Some(role.local_id) {
                return Ok(None);
            }
            drop(node);
            self.sync_from_ha_with_anchor(false)?;
        }
        let Some(state) = self.state.clone() else {
            return Ok(None);
        };
        for selected in state
            .auth
            .sdk_auth_retirement_recovery_selections()
            .map_err(auth_error)?
        {
            let binding = selected.binding().clone();
            let namespace = &binding.namespace;
            if !state.namespace_exists(namespace)
                || state.namespace_is_sealed(namespace)
                || state.namespaces.inherited_owner(namespace).is_some()
                    && !self.namespace_runtime.is_loaded(namespace)
            {
                continue;
            }
            let key = sdk_auth_key(&state.cluster_id, &binding)?;
            let control = self.sdk_hosts.get(&key).cloned();
            if control
                .as_ref()
                .is_some_and(|host| host.busy.load(Ordering::Acquire))
            {
                continue;
            }
            let remaining: VecDeque<Record> = selected
                .queued_records(&state.auth)
                .map_err(auth_error)?
                .into();
            let mut authority = Authority::capture(self, selected, clock, deadline)?;
            if let Some(host) = &control {
                host.retiring.store(true, Ordering::Release);
                if host.busy.load(Ordering::Acquire) {
                    continue;
                }
            }
            let at = authority.time(&state.auth)?;
            self.audit_event(
                "sdk-auth-retirement-recovery-request",
                authority.selected.correlation(),
                at.seconds(),
                None,
            )
            .map_err(|_| Response::error(503, "SDK Auth recovery request audit failed"))?;
            let Some(first) = remaining.front().cloned() else {
                return Ok(Some(RecoveryWork::Final(Box::new(FinalRemoval {
                    authority,
                    control,
                }))));
            };
            let id = first.id.clone();
            let path = first
                .path
                .strip_prefix(&first.mount)
                .ok_or_else(unavailable)?
                .to_owned();
            let expected = self.current_state_identity()?;
            let mut candidate = self.state.clone().ok_or_else(unavailable)?;
            candidate.auth.observe_sdk_auth_clock(at);
            candidate
                .auth
                .attempt_sdk_auth_retirement_resource(authority.selected.id(), &id, at)
                .map_err(auth_error)?;
            self.commit_sdk_auth_recovery_state(&mut candidate, &authority, &expected)?;
            authority.published_attempt(self, &id, at)?;
            let current = self.state.clone().ok_or_else(unavailable)?;
            let body = json!({});
            let request = RequestView {
                method: "INTERNAL",
                path: &first.path,
                namespace,
                token: "",
                body: &body,
                now: at.seconds(),
                admission_started: clock.started(),
                token_clock: Some(clock),
                allow_forward: false,
                enforce_namespace: true,
                wrap_ttl_seconds: None,
                origin_peer: None,
                client_certificates: None,
            };
            let context =
                credential::context(self, &current, &request, clock.with_timestamp_floor(at));
            let retirement = Retirement {
                remaining,
                job: authority.selected.id().to_owned(),
                sent: BTreeSet::new(),
                body: json!({}),
                completed: None,
                native: Some(authority),
            };
            let response = self.stage_sdk_auth(
                &current,
                &request,
                StageTarget {
                    binding: binding.clone(),
                    caller: None,
                    context,
                    operation: "revoke",
                    path: &path,
                    deadline,
                    renewal: None,
                    retirement: Some(retirement),
                },
            );
            let Some(plan) = self.pending_sdk_auth_request.take() else {
                if let Some(host) = self.sdk_hosts.remove(&key) {
                    host.retire();
                }
                return Err(response);
            };
            return Ok(Some(RecoveryWork::Callback(Box::new(plan))));
        }
        Ok(None)
    }
}
