//! An actual sudo caller owns synchronous Credential Revoke before Auth removal.
//! Durable control is paired with this process-local single-invocation receipt.
use super::*;
use crate::auth::sdk_credential::Record;
use crate::engines::sdk_lease::Phase;
use std::collections::VecDeque;
#[path = "service_sdk_auth_recovery.rs"]
mod recovery;
pub(in crate::service) use recovery::RecoveryWork;
pub(super) struct Retirement {
    pub(super) remaining: VecDeque<Record>,
    pub(super) job: String,
    pub(super) sent: BTreeSet<String>,
    pub(super) body: Value,
    pub(super) completed: Option<Vec<(String, [u8; 32])>>,
    pub(super) native: Option<recovery::Authority>,
}
impl Drop for Retirement {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}
fn digest(record: &Record) -> Result<[u8; 32], Response> {
    let bytes = Zeroizing::new(
        crate::secret_serde::to_vec(record, 512 * 1024)
            .map_err(|_| Response::error(503, "SDK retirement record encoding unavailable"))?,
    );
    Ok(crypto::digest(&bytes))
}
impl Retirement {
    pub(super) fn check_attempt(
        &self,
        auth: &AuthState,
        binding: &Binding,
    ) -> Result<(), Response> {
        let job = auth
            .sdk_auth_retirement_job(&self.job)
            .ok_or_else(|| Response::error(503, "SDK retirement durable job absent"))?;
        let first = self
            .remaining
            .front()
            .ok_or_else(|| Response::error(503, "SDK retirement attempted resource absent"))?;
        auth.sdk_auth_retirement_namespace_gate(binding, Some(&first.id))
            .map_err(auth_error)?;
        if job.binding() != binding
            || job.completed()
            || job.phase(&first.id) != Some(crate::auth::sdk_retirement::ResourcePhase::Attempted)
        {
            return Err(Response::error(
                503,
                "SDK retirement Setup lacks durable Attempted",
            ));
        }
        Ok(())
    }
}
impl Plan {
    pub(super) fn has_native_retirement(&self) -> Result<bool, Response> {
        self.retirement
            .as_ref()
            .map(|value| {
                value
                    .lock()
                    .map(|value| value.native.is_some())
                    .map_err(|_| Response::error(503, "SDK retirement native scope unavailable"))
            })
            .transpose()
            .map(|value| value.unwrap_or(false))
    }
    pub(super) fn sync_native_retirement(&self, service: &mut Service) -> Result<(), Response> {
        if let Some(value) = &self.retirement {
            let value = value
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement native scope unavailable"))?;
            if let Some(native) = &value.native {
                native.sync_before_setup(service)?;
                if !native.selected.completed() {
                    let key = sdk_auth_key(&self.context.cluster, &self.binding)?;
                    if service
                        .sdk_hosts
                        .get(&key)
                        .is_none_or(|host| !Arc::ptr_eq(host, &self.control))
                    {
                        return Err(Response::error(
                            503,
                            "SDK retirement native Control changed",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn retirement_native_after_callback(
        &self,
        auth: &AuthState,
        at: Timestamp,
    ) -> Result<(), Response> {
        if let Some(value) = &self.retirement {
            let mut value = value
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement native scope unavailable"))?;
            let id = value.remaining.front().map(|record| record.id.clone());
            if let Some(native) = &mut value.native {
                native.published_terminal(
                    auth,
                    &id.ok_or_else(|| {
                        Response::error(503, "SDK retirement native callback resource absent")
                    })?,
                    at,
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn check_retirement_control(&self, auth: &AuthState) -> Result<(), Response> {
        let Some(retirement) = &self.retirement else {
            return Ok(());
        };
        let retirement = retirement
            .lock()
            .map_err(|_| Response::error(503, "SDK retirement control unavailable"))?;
        let job = auth
            .sdk_auth_retirement_job(&retirement.job)
            .ok_or_else(|| Response::error(503, "SDK retirement durable job absent"))?;
        if !job.completed() {
            // Includes an empty fixed set or all Terminal before mount Completion.
            auth.sdk_auth_retirement_namespace_gate(&self.binding, None)
                .map_err(auth_error)?;
            for record in &retirement.remaining {
                auth.sdk_auth_retirement_namespace_gate(&self.binding, Some(&record.id))
                    .map_err(auth_error)?;
            }
        }
        if let Some(native) = &retirement.native {
            native.check_auth(auth)?;
        }
        if job.binding() != &self.binding || job.completed() != retirement.completed.is_some() {
            return Err(Response::error(
                503,
                "SDK retirement durable control changed",
            ));
        }
        Ok(())
    }
    pub(super) fn retirement_resource_completed(
        &self,
        auth: &mut AuthState,
        id: &str,
        at: Timestamp,
    ) -> Result<(), Response> {
        if let Some(retirement) = &self.retirement {
            let retirement = retirement
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement control unavailable"))?;
            auth.complete_sdk_auth_retirement_resource(&retirement.job, id, at)
                .map_err(auth_error)?;
        }
        Ok(())
    }

    pub(super) fn retirement_completed(&self) -> Result<bool, Response> {
        self.retirement
            .as_ref()
            .map(|retirement| {
                retirement
                    .lock()
                    .map(|retirement| retirement.completed.is_some())
                    .map_err(|_| Response::error(503, "SDK retirement owner unavailable"))
            })
            .transpose()
            .map(|v| v.unwrap_or(false))
    }
    pub(super) fn retirement_delivery_gate(&self, auth: &AuthState) -> Result<(), Response> {
        let retirement = self
            .retirement
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
            .lock()
            .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?;
        let records = retirement
            .completed
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK retirement completion absent"))?;
        if !retirement.remaining.is_empty()
            || auth.sdk_auth_owned_mount(&self.binding.namespace, &self.binding.mount)
            || auth
                .sdk_auth_descriptor(
                    &self.binding.descriptor().name,
                    &self.binding.descriptor().version,
                )
                .as_ref()
                != Some(self.binding.descriptor())
            || auth.sdk_credential_mount_pending(&self.binding)
        {
            return Err(Response::error(
                503,
                "SDK retirement terminal mount owner changed",
            ));
        }
        for (id, expected) in records {
            let current = auth
                .sdk_credential_record(&self.binding.namespace, id)
                .ok_or_else(|| Response::error(503, "SDK retirement retained record absent"))?;
            if current.phase != Phase::Revoked || digest(&current)? != *expected {
                return Err(Response::error(
                    503,
                    "SDK retirement terminal record changed",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn execute_retirement(
        &self,
        service: &Arc<Mutex<Service>>,
        deadline: Instant,
    ) -> Result<Option<Value>, Response> {
        loop {
            let record = self
                .retirement
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?
                .remaining
                .front()
                .cloned();
            let Some(record) = record else {
                return Ok(None);
            };
            *self
                .lease
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement callback unavailable"))? =
                Some(credential::Call {
                    record: record.clone(),
                    action: "revoke",
                    increment: 0,
                });
            while self.control.busy.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    return Err(Response::error(
                        503,
                        "SDK retirement original deadline expired",
                    ));
                }
                std::thread::park_timeout(Duration::from_millis(1));
            }
            {
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
                let mut writer = writer_before(service, deadline).map_err(|_| {
                    Response::error(503, "SDK retirement attempt writer unavailable")
                })?;
                writer.prepare_sdk_auth_retirement_attempt(self, &record.id)?;
            }
            {
                let mut retirement = self
                    .retirement
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
                    .lock()
                    .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?;
                if !retirement.sent.insert(record.id.clone()) {
                    return Err(Response::error(
                        503,
                        "SDK retirement callback cannot be resent",
                    ));
                }
            }
            let result = self.execute_once(service, deadline);
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
            let mut writer = writer_before(service, deadline)
                .map_err(|_| Response::error(503, "SDK retirement writer unavailable"))?;
            let mut value = result?;
            let finished = writer.finish_sdk_auth_candidate(self, value.as_ref());
            if let Some(value) = value.as_mut() {
                erase_json(value);
            }
            let mut response = finished?;
            let at = self.time(
                &writer
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK retirement owner sealed"))?
                    .auth,
            )?;
            let fingerprint = writer.request_fingerprint(
                "INTERNAL",
                "sdk-auth-retirement/revoke",
                &self.binding.namespace,
                "",
            );
            if writer
                .audit_event(
                    "sdk-auth-retirement-revoke-response",
                    &fingerprint,
                    at.seconds(),
                    Some(response.status),
                )
                .is_err()
            {
                erase_json(&mut response.body);
                response.response_headers.clear();
                response.consistency_index = None;
                writer.recovery_required = true;
                writer.ha_activation = None;
                writer.retire_sdk_hosts();
                return Err(Response::error(
                    503,
                    "SDK retirement revoke audit failed; recovery required",
                ));
            }
            response = writer.complete_sdk_auth_delivery(self, response, &fingerprint);
            if response.status != 204 {
                return Err(response);
            }
            let current = writer
                .state
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK retirement current state unavailable"))?
                .auth
                .sdk_credential_record(&record.namespace, &record.id)
                .ok_or_else(|| Response::error(503, "SDK retirement terminal record absent"))?;
            let mut expected = record.clone();
            expected.revoke();
            if digest(&current)? != digest(&expected)? {
                return Err(Response::error(
                    503,
                    "SDK retirement terminal record differs",
                ));
            }
            let mut transaction = self
                .transaction
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement transaction unavailable"))?;
            if writer.current_state_identity()? != transaction.identity {
                return Err(Response::error(
                    503,
                    "SDK retirement root advanced after callback",
                ));
            }
            transaction.auth = writer
                .state
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK retirement state sealed"))?
                .auth
                .clone();
            drop(transaction);
            self.retirement
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?
                .remaining
                .pop_front();
        }
    }
}
impl Service {
    pub(super) fn stage_sdk_auth_retirement(
        &mut self,
        mut state: State,
        mut caller: plugin::PluginResponseAuthority,
        request: &RequestView<'_>,
        binding: Binding,
        context: Context,
        deadline: Instant,
    ) -> Response {
        let result = (|| {
            let records = state
                .auth
                .sdk_credential_mount_records(&binding)
                .map_err(auth_error)?;
            let mut preview = state.clone();
            for record in &records {
                let mut retired = record.clone();
                retired.revoke();
                preview
                    .auth
                    .store_sdk_credential(retired)
                    .map_err(auth_error)?;
            }
            let response = preview
                .auth
                .handle_with_connection_clock(
                    Some(caller.principal()),
                    request.namespace,
                    request.method,
                    request.path,
                    request.body,
                    request
                        .token_time()
                        .unwrap_or(AuthorityTime::Coarse(request.now)),
                    Some(context.clock),
                    request.client_certificates,
                    request.origin_peer,
                )
                .map_err(auth_error)?;
            if response.is_none_or(|response| response.status != 204) {
                return Err(Response::error(
                    503,
                    "SDK retirement native preflight unavailable",
                ));
            }
            let key = sdk_auth_key(&state.cluster_id, &binding)?;
            let reservation = self.sdk_hosts.get(&key).cloned();
            if let Some(control) = &reservation {
                if control.busy.load(Ordering::Acquire)
                    || control
                        .retiring
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                {
                    return Err(Response::error(
                        409,
                        "SDK Auth mount is busy before retirement",
                    ));
                }
                if control.busy.load(Ordering::Acquire) {
                    control.retiring.store(false, Ordering::Release);
                    return Err(Response::error(
                        409,
                        "SDK Auth mount is busy before retirement",
                    ));
                }
            }
            let publish = (|| {
                let expected = self.current_state_identity()?;
                self.validate_plugin_response(&mut caller)?;
                let at = context.clock.observed_at().map_err(|_| {
                    Response::error(503, "SDK retirement original clock unavailable")
                })?;
                let at = state
                    .auth
                    .sdk_auth_clock_floor()
                    .map_or(at, |floor| at.max(floor));
                state.auth.observe_sdk_auth_clock(at);
                let mut remaining = VecDeque::new();
                for mut record in records {
                    record.phase = Phase::PendingRevoke;
                    state
                        .auth
                        .store_sdk_credential(record.clone())
                        .map_err(auth_error)?;
                    remaining.push_back(record);
                }
                if !binding.namespace.is_empty() {
                    state.ensure_namespace_batch_registry()?;
                }
                let job = hex(&crypto::random::<16>()
                    .map_err(|_| Response::error(503, "SDK retirement entropy unavailable"))?);
                let fingerprint = self.request_fingerprint(
                    request.method,
                    request.path,
                    request.namespace,
                    request.token,
                );
                state
                    .auth
                    .begin_sdk_auth_retirement(
                        job.clone(),
                        &state.cluster_id,
                        binding.clone(),
                        at,
                        fingerprint,
                    )
                    .map_err(auth_error)?;
                self.sdk_auth_commit_control(&mut state, &mut caller, &expected, context.clock)?;
                self.state = Some(state.clone());
                if let Some(first) = remaining.front() {
                    // start_worker_typed may call external Setup. Attempted is durable first.
                    let expected = self.current_state_identity()?;
                    state
                        .auth
                        .attempt_sdk_auth_retirement_resource(&job, &first.id, at)
                        .map_err(auth_error)?;
                    self.sdk_auth_commit_control(
                        &mut state,
                        &mut caller,
                        &expected,
                        context.clock,
                    )?;
                    self.state = Some(state.clone());
                    let path = first
                        .path
                        .strip_prefix(&first.mount)
                        .ok_or_else(|| {
                            Response::error(503, "SDK retirement callback path owner changed")
                        })?
                        .to_owned();
                    let retirement = Retirement {
                        remaining,
                        job,
                        sent: BTreeSet::new(),
                        body: request.body.clone(),
                        completed: None,
                        native: None,
                    };
                    let response = self.stage_sdk_auth(
                        &state,
                        request,
                        StageTarget {
                            binding,
                            caller: Some(caller),
                            context,
                            operation: "revoke",
                            path: &path,
                            deadline,
                            renewal: None,
                            retirement: Some(retirement),
                        },
                    );
                    if self.pending_sdk_auth_request.is_none() {
                        return Err(response);
                    }
                    Ok(empty_response())
                } else {
                    // No Setup or callback is necessary for an empty genuine fixed set.
                    let expected = self.current_state_identity()?;
                    let response = state
                        .auth
                        .handle_with_connection_clock(
                            Some(caller.principal()),
                            request.namespace,
                            request.method,
                            request.path,
                            request.body,
                            caller.token_time()?,
                            Some(context.clock),
                            request.client_certificates,
                            request.origin_peer,
                        )
                        .map_err(auth_error)?;
                    if response.is_none_or(|response| response.status != 204) {
                        return Err(Response::error(
                            503,
                            "SDK retirement empty mount removal failed",
                        ));
                    }
                    state
                        .auth
                        .complete_sdk_auth_retirement_mount(&job, at)
                        .map_err(auth_error)?;
                    self.sdk_auth_commit_control(
                        &mut state,
                        &mut caller,
                        &expected,
                        context.clock,
                    )?;
                    self.state = Some(state);
                    self.pending_sdk_control_authority = Some(caller);
                    if let Some(host) = self.sdk_hosts.remove(&key) {
                        host.retire();
                    }
                    Ok(empty_response())
                }
            })();
            if publish.is_err()
                && let Some(control) = reservation
            {
                control.retire();
            }
            publish
        })();
        result.unwrap_or_else(|error| error)
    }
    fn prepare_sdk_auth_retirement_attempt(
        &mut self,
        plan: &Plan,
        id: &str,
    ) -> Result<(), Response> {
        self.sdk_auth_gate(plan)?;
        let job = plan
            .retirement
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
            .lock()
            .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?
            .job
            .clone();
        let mut state = self
            .state
            .clone()
            .ok_or_else(|| Response::error(503, "SDK retirement state unavailable"))?;
        let current = state
            .auth
            .sdk_auth_retirement_job(&job)
            .ok_or_else(|| Response::error(503, "SDK retirement job absent"))?;
        match current.phase(id) {
            Some(crate::auth::sdk_retirement::ResourcePhase::Attempted) => return Ok(()),
            Some(crate::auth::sdk_retirement::ResourcePhase::Queued) => {}
            _ => {
                return Err(Response::error(
                    503,
                    "SDK retirement callback was already terminal",
                ));
            }
        }
        let at = plan.time(&state.auth)?;
        state.auth.observe_sdk_auth_clock(at);
        state
            .auth
            .attempt_sdk_auth_retirement_resource(&job, id, at)
            .map_err(auth_error)?;
        let expected = self.current_state_identity()?;
        {
            let mut retirement = plan
                .retirement
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?;
            if let Some(native) = &mut retirement.native {
                self.commit_sdk_auth_recovery_state(&mut state, native, &expected)?;
                native.published_attempt(self, id, at)?;
            } else {
                let mut caller = plan
                    .caller
                    .lock()
                    .map_err(|_| Response::error(503, "SDK retirement caller unavailable"))?;
                let caller = caller
                    .as_mut()
                    .ok_or_else(|| Response::error(503, "SDK retirement caller absent"))?;
                self.sdk_auth_commit_control(&mut state, caller, &expected, plan.context.clock)?;
                self.state = Some(state);
            }
        }
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| Response::error(503, "SDK retirement transaction unavailable"))?;
        transaction.auth = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK retirement publication absent"))?
            .auth
            .clone();
        transaction.identity = self.current_state_identity()?;
        Ok(())
    }
    pub(super) fn finalize_sdk_auth_retirement(
        &mut self,
        plan: &Plan,
    ) -> Result<Response, Response> {
        self.sdk_auth_gate(plan)?;
        let mut retirement = plan
            .retirement
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
            .lock()
            .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?;
        if !retirement.remaining.is_empty() || retirement.completed.is_some() {
            return Err(Response::error(503, "SDK retirement callbacks incomplete"));
        }
        let mut state = self
            .state
            .clone()
            .ok_or_else(|| Response::error(503, "SDK retirement current state unavailable"))?;
        if !state
            .auth
            .sdk_credential_mount_records(&plan.binding)
            .map_err(auth_error)?
            .is_empty()
        {
            return Err(Response::error(
                503,
                "SDK retirement acquired another lease",
            ));
        }
        let retired = state
            .auth
            .sdk_credential_retired_mount_records(&plan.binding)
            .map_err(auth_error)?
            .into_iter()
            .map(|r| Ok((r.id.clone(), digest(&r)?)))
            .collect::<Result<Vec<_>, Response>>()?;
        let expected = self.current_state_identity()?;
        if let Some(native) = &mut retirement.native {
            let at = plan.time(&state.auth)?;
            state.auth.observe_sdk_auth_clock(at);
            state
                .auth
                .remove_sdk_auth_retirement_mount(&native.selected, at)
                .map_err(auth_error)?;
            self.commit_sdk_auth_recovery_state(&mut state, native, &expected)?;
            native.published_removal(self, at)?;
            retirement.completed = Some(retired);
            let key = sdk_auth_key(&plan.context.cluster, &plan.binding)?;
            if let Some(host) = self.sdk_hosts.remove(&key) {
                if !Arc::ptr_eq(&host, &plan.control) {
                    return Err(Response::error(
                        503,
                        "SDK retirement native Control changed",
                    ));
                }
                host.retire();
            }
            return Ok(empty_response());
        }
        let mut caller = plan
            .caller
            .lock()
            .map_err(|_| Response::error(503, "SDK retirement actual caller unavailable"))?;
        let caller = caller
            .as_mut()
            .ok_or_else(|| Response::error(503, "SDK retirement caller absent"))?;
        let response = state
            .auth
            .handle_with_connection_clock(
                Some(caller.principal()),
                &plan.binding.namespace,
                "DELETE",
                &format!("sys/auth/{}", plan.binding.mount),
                &retirement.body,
                caller.token_time()?,
                Some(plan.context.clock),
                None,
                None,
            )
            .map_err(auth_error)?;
        if response.is_none_or(|r| r.status != 204) {
            return Err(Response::error(
                503,
                "SDK retirement native removal unavailable",
            ));
        }
        let at = plan.time(&state.auth)?;
        state.auth.observe_sdk_auth_clock(at);
        state
            .auth
            .complete_sdk_auth_retirement_mount(&retirement.job, at)
            .map_err(auth_error)?;
        self.sdk_auth_commit_control(&mut state, caller, &expected, plan.context.clock)?;
        self.state = Some(state);
        retirement.completed = Some(retired);
        if let Some(host) = self
            .sdk_hosts
            .remove(&sdk_auth_key(&plan.context.cluster, &plan.binding)?)
        {
            if !Arc::ptr_eq(&host, &plan.control) {
                return Err(Response::error(503, "SDK retirement control changed"));
            }
            host.retire();
        }
        Ok(empty_response())
    }
}
