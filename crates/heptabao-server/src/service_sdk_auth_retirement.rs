//! An actual sudo caller owns synchronous Credential Revoke before Auth removal.
//! This private completion receipt is neither a Principal nor a durable taint.
use super::*;
use crate::auth::sdk_credential::Record;
use crate::engines::sdk_lease::Phase;
use std::collections::VecDeque;
pub(super) struct Retirement {
    pub(super) remaining: VecDeque<Record>,
    pub(super) body: Value,
    pub(super) completed: Option<Vec<(String, [u8; 32])>>,
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
impl Plan {
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
        caller: plugin::PluginResponseAuthority,
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
            let first = records
                .first()
                .ok_or_else(|| Response::error(503, "SDK retirement has no registered record"))?
                .clone();
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
            if response.is_none_or(|r| r.status != 204) {
                return Err(Response::error(
                    503,
                    "SDK retirement native preflight unavailable",
                ));
            }
            let path = first
                .path
                .strip_prefix(&first.mount)
                .ok_or_else(|| Response::error(503, "SDK retirement path owner changed"))?
                .to_owned();
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
                },
            );
            let mut plan = self.pending_sdk_auth_request.take().ok_or(response)?;
            if plan.control.busy.load(Ordering::Acquire)
                || plan
                    .control
                    .retiring
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                return Err(Response::error(
                    409,
                    "SDK Auth mount is busy before retirement",
                ));
            }
            let pending = (|| {
                let expected = self.current_state_identity()?;
                let mut authority = plan.caller.lock().map_err(|_| {
                    Response::error(503, "SDK retirement actual caller unavailable")
                })?;
                let authority = authority
                    .as_mut()
                    .ok_or_else(|| Response::error(503, "SDK retirement actual caller absent"))?;
                self.validate_plugin_response(authority)?;
                let at = plan.time(&state.auth)?;
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
                self.sdk_auth_commit_control(&mut state, authority, &expected, plan.context.clock)?;
                self.state = Some(state);
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
                Ok(remaining)
            })();
            match pending {
                Ok(remaining) => {
                    plan.retirement = Some(Mutex::new(Retirement {
                        remaining,
                        body: request.body.clone(),
                        completed: None,
                    }));
                    self.pending_sdk_auth_request = Some(plan);
                    Ok(empty_response())
                }
                Err(error) => {
                    plan.control.retire();
                    Err(error)
                }
            }
        })();
        result.unwrap_or_else(|error| error)
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
