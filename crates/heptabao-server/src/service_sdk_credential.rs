//! Credential-family Secret registration and callbacks retain the real Auth
//! backend, original entrance, and current encrypted Storage owner.
use super::*;
use crate::auth::sdk_credential::Record;
use crate::engines::sdk_lease::{Binding as LeaseBinding, Lease, Phase};
use crate::engines::sdk_registration::Registration;
#[derive(Clone)]
pub(super) struct Call {
    record: Record,
    action: &'static str,
    increment: u64,
}
impl Call {
    pub(super) fn callback(&self) -> Result<SdkLeaseCallback, Response> {
        Ok(SdkLeaseCallback {
            secret: self.record.callback(),
            issue_time_ns: self
                .record
                .issue_ns()
                .map_err(Response::from_engine_error)?,
            increment_ns: self.increment,
        })
    }
    pub(super) fn check(&self, auth: &AuthState, at: Timestamp) -> Result<(), Response> {
        let current = auth
            .sdk_credential_record(&self.record.namespace, &self.record.id)
            .ok_or_else(|| Response::error(503, "SDK credential saved lease owner absent"))?;
        if digest(&current)? != digest(&self.record)? {
            return Err(Response::error(
                503,
                "SDK credential original callback record changed",
            ));
        }
        if self.action == "renew"
            && (at >= current.expires
                || current.phase != Phase::Active
                || current
                    .parent_cleanup_required(auth, at)
                    .map_err(Response::from_engine_error)?)
        {
            return Err(Response::error(
                400,
                "SDK credential lease expired during callback",
            ));
        }
        Ok(())
    }
}
pub(super) struct Cleanup {
    clock: RequestClock,
    deadline: Instant,
    expected: [u8; 32],
}
impl Cleanup {
    pub(super) fn check(&self, call: &Call) -> Result<(), Response> {
        self.clock
            .observed_at()
            .map_err(|_| Response::error(503, "SDK credential cleanup clock unavailable"))?;
        if Instant::now() >= self.deadline
            || call.action != "revoke"
            || digest(&call.record)? != self.expected
        {
            return Err(Response::error(
                503,
                "SDK credential original cleanup authority changed",
            ));
        }
        Ok(())
    }
}
fn digest(record: &Record) -> Result<[u8; 32], Response> {
    let bytes = zeroize::Zeroizing::new(
        crate::secret_serde::to_vec(record, 512 * 1024)
            .map_err(|_| Response::error(503, "SDK credential lease encoding failed"))?,
    );
    Ok(crypto::digest(&bytes))
}
pub(super) fn issue(
    plan: &Plan,
    candidate: &mut State,
    value: &Value,
    at: Timestamp,
) -> Result<Response, Response> {
    let admission = plan
        .admission
        .as_ref()
        .ok_or_else(|| Response::error(500, "SDK credential issuer absent"))?;
    let entry = admission
        .entry
        .as_ref()
        .ok_or_else(|| Response::error(501, "SDK credential entrance issuer unsupported"))?;
    let secret = value
        .get("secret")
        .cloned()
        .ok_or_else(|| Response::error(502, "SDK credential Secret absent"))?;
    let data = value.get("data").cloned().unwrap_or_else(|| json!({}));
    let grant = super::super::secret_lease::grant(secret, data, at)?;
    let mount = format!("auth/{}/", plan.binding.mount);
    let path = format!("{mount}{}", plan.path);
    let id = super::super::secret_lease::new_lease_id(candidate, &plan.context.namespace, &path)?;
    let mut record = Lease::new(
        LeaseBinding {
            id,
            namespace: plan.context.namespace.clone(),
            cluster: candidate.cluster_id.clone(),
            mount,
            path,
            backend: plan.binding.clone(),
            issuer: entry.issuer.owner.clone(),
        },
        grant,
    )
    .map_err(Response::from_engine_error)?;
    let registration = Registration::from_entry(
        entry,
        admission.accepted,
        at,
        admission.final_use,
        &candidate.auth,
        &plan.context.namespace,
        plan.context.incarnation,
    )
    .map_err(Response::from_engine_error)?;
    record
        .register(registration)
        .map_err(Response::from_engine_error)?;
    let namespace_owner = if plan.context.namespace.is_empty() {
        None
    } else {
        candidate.ensure_namespace_batch_registry()?;
        Some(
            candidate
                .auth
                .namespace_batch_registry()
                .ok_or_else(|| {
                    Response::error(503, "SDK credential actual namespace lifecycle absent")
                })?
                .binding(&plan.context.namespace)
                .map_err(auth_error)?,
        )
    };
    let record = Record::new(record, namespace_owner);
    candidate.auth.observe_sdk_auth_clock(at);
    candidate
        .auth
        .store_sdk_credential(record.clone())
        .map_err(auth_error)?;
    if admission.final_use {
        return Ok(Response::error(
            400,
            "1 error occurred:\n\t* cannot create a lease with a token that has a restricted number of uses and is on its final use\n\n",
        ));
    }
    Ok(Response::ok(json!({"lease_id":record.id,
        "lease_duration":record.public_duration(at).map_err(Response::from_engine_error)?,
        "renewable":record.renewable,"data":record.response_data()})))
}
pub(super) fn finish_callback(
    plan: &Plan,
    candidate: &mut State,
    value: Option<&Value>,
    at: Timestamp,
) -> Result<Response, Response> {
    let call = plan
        .lease
        .lock()
        .map_err(|_| Response::error(503, "SDK credential callback unavailable"))?;
    let call = call
        .as_ref()
        .ok_or_else(|| Response::error(503, "SDK credential callback owner absent"))?;
    call.check(&candidate.auth, at)?;
    if value.is_some_and(|v| {
        v.get("auth").is_some_and(|v| !v.is_null())
            || v.get("redirect")
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
    }) {
        return Err(Response::error(
            502,
            "SDK credential callback returned unsupported authority",
        ));
    }
    let mut record = call.record.clone();
    let response = if call.action == "renew" {
        let value = value
            .ok_or_else(|| Response::error(400, "SDK credential renewal returned no Secret"))?;
        let secret = value
            .get("secret")
            .cloned()
            .filter(|v| !v.is_null())
            .ok_or_else(|| Response::error(400, "SDK credential renewal returned no Secret"))?;
        let data = value.get("data").cloned().unwrap_or_else(|| json!({}));
        record
            .renew(super::super::secret_lease::renewal_grant(
                secret,
                data,
                at,
                call.increment,
            )?)
            .map_err(Response::from_engine_error)?;
        Response::ok(
            json!({"lease_id":record.id,"lease_duration":record.public_duration(at).map_err(Response::from_engine_error)?,
            "renewable":record.renewable,"data":record.response_data()}),
        )
    } else {
        if value.is_some_and(|v| v.get("secret").is_some_and(|v| !v.is_null())) {
            return Err(Response::error(
                502,
                "SDK credential revoke returned Secret",
            ));
        }
        record.revoke();
        empty_response()
    };
    candidate.auth.observe_sdk_auth_clock(at);
    candidate
        .auth
        .store_sdk_credential(record)
        .map_err(auth_error)?;
    Ok(response)
}
pub(super) fn after_publication(plan: &Plan, auth: &AuthState) -> Result<(), Response> {
    let mut call = plan
        .lease
        .lock()
        .map_err(|_| Response::error(503, "SDK credential callback unavailable"))?;
    if let Some(call) = call.as_mut() {
        call.record = auth
            .sdk_credential_record(&call.record.namespace, &call.record.id)
            .ok_or_else(|| Response::error(503, "SDK credential published record absent"))?;
        if let Some(cleanup) = plan
            .cleanup
            .lock()
            .map_err(|_| Response::error(503, "SDK credential cleanup unavailable"))?
            .as_mut()
        {
            if call.record.phase != Phase::Revoked {
                return Err(Response::error(
                    503,
                    "SDK credential cleanup terminal record rejected",
                ));
            }
            cleanup.expected = digest(&call.record)?;
        }
    }
    Ok(())
}
fn context(
    service: &Service,
    state: &State,
    request: &RequestView<'_>,
    clock: RequestClock,
) -> Context {
    Context {
        namespace: request.namespace.into(),
        incarnation: state.namespaces.incarnation(request.namespace),
        delivery: namespace_runtime::DeliveryBinding::capture(state, request.namespace),
        cluster: state.cluster_id.clone(),
        activation: service.unseal_nonce.clone(),
        ha: service.ha.clone(),
        clock,
        namespace_required: request.enforce_namespace,
    }
}
impl Service {
    pub(in crate::service) fn sdk_credential_handles(
        &self,
        state: &State,
        request: &RequestView<'_>,
    ) -> bool {
        super::super::secret_lease::body_action(request).is_some_and(|(_, id)| {
            state
                .auth
                .sdk_credential_record(request.namespace, id)
                .is_some()
        })
    }
    pub(in crate::service) fn sdk_credential_route(
        &mut self,
        mut state: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "permission denied");
        };
        let Some((action, id)) = super::super::secret_lease::body_action(request) else {
            return Response::error(400, "lease_id is required");
        };
        let Some(clock) = request.token_clock else {
            return Response::error(503, "SDK credential original clock required");
        };
        if !matches!(request.method, "POST" | "PUT") {
            return Response::error(405, "SDK lease administration requires POST or PUT");
        }
        let fields = match action {
            "renew" => &["lease_id", "increment"][..],
            "revoke" => &["lease_id", "sync"][..],
            _ => &["lease_id"][..],
        };
        if request
            .body
            .as_object()
            .is_none_or(|o| o.keys().any(|key| !fields.contains(&key.as_str())))
            || request.body.get("sync").is_some_and(|v| !v.is_boolean())
        {
            return Response::error(400, "invalid SDK lease request fields");
        }
        if (request.path.starts_with("sys/leases/renew/")
            || request.path.starts_with("sys/leases/revoke/"))
            && request
                .body
                .get("lease_id")
                .and_then(Value::as_str)
                .is_some_and(|body| !request.path.ends_with(&format!("/{body}")))
        {
            return Response::error(400, "lease_id conflicts with authorized path");
        }
        let mut authority = plugin::PluginResponseAuthority::new(
            principal,
            &state,
            request,
            "update",
            false,
            &self.unseal_nonce,
        )
        .with_sdk_clock();
        if let Err(error) = self.validate_plugin_response(&mut authority) {
            return error;
        }
        if let Err(error) = authority.apply_sdk_auth_clock_floor(&state.auth) {
            return error;
        }
        let at = match authority.token_time().and_then(|time| {
            state
                .auth
                .token_api_observed_time(time)
                .exact()
                .ok_or_else(|| Response::error(503, "SDK credential original precise clock absent"))
        }) {
            Ok(at) => at,
            Err(error) => return error,
        };
        let Some(record) = state.auth.sdk_credential_record(request.namespace, id) else {
            return Response::error(400, "invalid lease");
        };
        if record.cluster != state.cluster_id {
            return Response::error(503, "SDK credential cluster owner rejected");
        }
        if action == "lookup" {
            let body = match record.lookup(at) {
                Ok(body) => body,
                Err(error) => return Response::from_engine_error(error),
            };
            state.auth.observe_sdk_auth_clock(at);
            state.schema = state.writer_schema();
            let publication = match self.prepare_record_plan(&mut state) {
                Ok(plan) => plan,
                Err(error) => return error,
            };
            if let Err(error) = self.commit_record_plan_with_before_publish(
                &state,
                publication,
                |auth| authority.validate_live_auth(auth),
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            ) {
                return error;
            }
            self.state = Some(state);
            self.pending_sdk_control_authority = Some(authority);
            return Response::ok(json!({"data":body}));
        }
        if record.phase == Phase::Revoked {
            if action == "revoke" {
                self.pending_sdk_control_authority = Some(authority);
                return empty_response();
            }
            return Response::error(400, "lease not found");
        }
        let parent_ended = match record.parent_cleanup_required(&state.auth, at) {
            Ok(value) => value,
            Err(error) => return Response::from_engine_error(error),
        };
        if action == "renew" && (at >= record.expires || !record.renewable || parent_ended) {
            return Response::error(400, "lease is expired, revoked or not renewable");
        }
        let increment = match request.body.get("increment").map_or(Ok(0), |v| {
            v.as_u64()
                .and_then(|n| n.checked_mul(1_000_000_000))
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or_else(|| Response::error(400, "invalid lease increment"))
        }) {
            Ok(n) => n,
            Err(error) => return error,
        };
        let Some(config) = self.sdk_configuration.as_ref() else {
            return Response::error(503, "SDK credential runtime unavailable");
        };
        let deadline = crate::request_deadline::current()
            .unwrap_or(clock.started() + Duration::from_millis(config.timeout_ms));
        let binding = record.backend.clone();
        if let Err(error) = state.auth.sdk_auth_owner_gate(&binding) {
            return auth_error(error);
        }
        let path = match record.path.strip_prefix(&record.mount) {
            Some(path) => path.to_owned(),
            None => return Response::error(503, "SDK credential saved path rejected"),
        };
        let response = self.stage_sdk_auth(
            &state,
            request,
            StageTarget {
                binding,
                caller: Some(authority),
                context: context(self, &state, request, clock),
                operation: action,
                path: &path,
                deadline,
                renewal: None,
            },
        );
        if let Some(plan) = self.pending_sdk_auth_request.as_mut() {
            match plan.lease.lock() {
                Ok(mut call) => {
                    *call = Some(Call {
                        record,
                        action,
                        increment,
                    })
                }
                Err(_) => return Response::error(503, "SDK credential callback unavailable"),
            }
        }
        response
    }
    pub(in crate::service) fn prepare_sdk_credential_expiry(
        &mut self,
        clock: RequestClock,
    ) -> Result<Option<Plan>, Response> {
        if self.pending_sdk_auth_request.is_some()
            || self.recovery_required
            || self.audit_failed
            || self.sdk_configuration.is_none()
        {
            return Ok(None);
        }
        if let Some(ha) = &self.ha {
            let node = ha
                .lock_for_request()
                .map_err(|_| Response::error(503, "SDK credential cleanup HA unavailable"))?;
            if node
                .leader()
                .map_err(|_| Response::error(503, "SDK credential cleanup leader unavailable"))?
                != Some(
                    node.local_id().map_err(|_| {
                        Response::error(503, "SDK credential cleanup node unavailable")
                    })?,
                )
            {
                return Ok(None);
            }
            drop(node);
            self.sync_from_ha_with_anchor(false)?;
        }
        let Some(mut state) = self.state.clone() else {
            return Ok(None);
        };
        let at = clock
            .observed_at()
            .map_err(|_| Response::error(503, "SDK credential cleanup clock unavailable"))?;
        let at = state
            .auth
            .sdk_auth_clock_floor()
            .map_or(at, |floor| at.max(floor));
        let Some(mut record) = state
            .auth
            .next_sdk_credential_cleanup(at, self.sdk_credential_cleanup_cursor.as_deref())
            .map_err(auth_error)?
        else {
            return Ok(None);
        };
        self.sdk_credential_cleanup_cursor = Some(record.id.clone());
        let namespace = record.namespace.clone();
        if !state.namespace_exists(&namespace)
            || state.namespace_is_sealed(&namespace)
            || state.namespaces.inherited_owner(&namespace).is_some()
                && !self.namespace_runtime.is_loaded(&namespace)
        {
            return Ok(None);
        }
        state
            .auth
            .sdk_auth_owner_gate(&record.backend)
            .map_err(auth_error)?;
        let key = sdk_auth_key(&state.cluster_id, &record.backend)?;
        if self.sdk_hosts.get(&key).is_some_and(|control| {
            control.busy.load(Ordering::Acquire) || control.retiring.load(Ordering::Acquire)
        }) {
            return Ok(None);
        }
        let config = self
            .sdk_configuration
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK credential runtime unavailable"))?;
        let deadline = (clock.started() + Duration::from_millis(config.timeout_ms)).min(
            crate::request_deadline::current()
                .unwrap_or(clock.started() + Duration::from_millis(config.timeout_ms)),
        );
        if Instant::now() >= deadline {
            return Err(Response::error(
                503,
                "SDK credential cleanup original deadline expired",
            ));
        }
        let fingerprint = self.request_fingerprint(
            "INTERNAL",
            "sdk-credential-lifecycle/revoke",
            &namespace,
            "",
        );
        self.audit_event(
            "sdk-credential-lifecycle-request",
            &fingerprint,
            at.seconds(),
            None,
        )
        .map_err(|_| Response::error(503, "SDK credential cleanup request audit failed"))?;
        record.phase = Phase::PendingRevoke;
        state.auth.observe_sdk_auth_clock(at);
        state
            .auth
            .store_sdk_credential(record.clone())
            .map_err(auth_error)?;
        state.schema = state.writer_schema();
        let original = self.current_state_identity()?;
        let publication = self.prepare_record_plan(&mut state)?;
        if original != self.current_state_identity()? {
            return Err(Response::error(
                503,
                "SDK credential cleanup candidate changed",
            ));
        }
        self.commit_record_plan_with_before_publish(
            &state,
            publication,
            |_| {
                clock.observed_at().map_err(|_| {
                    Response::error(503, "SDK credential cleanup clock unavailable")
                })?;
                if Instant::now() >= deadline {
                    return Err(Response::error(
                        503,
                        "SDK credential cleanup publication deadline expired",
                    ));
                }
                Ok(())
            },
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        )?;
        self.state = Some(state.clone());
        let path = record
            .path
            .strip_prefix(&record.mount)
            .ok_or_else(|| Response::error(503, "SDK credential saved path rejected"))?
            .to_owned();
        let body = json!({});
        let request = RequestView {
            method: "INTERNAL",
            path: &record.path,
            namespace: &namespace,
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
        let response = self.stage_sdk_auth(
            &state,
            &request,
            StageTarget {
                binding: record.backend.clone(),
                caller: None,
                context: context(self, &state, &request, clock.with_timestamp_floor(at)),
                operation: "revoke",
                path: &path,
                deadline,
                renewal: None,
            },
        );
        let Some(plan) = self.pending_sdk_auth_request.take() else {
            return Err(response);
        };
        *plan
            .lease
            .lock()
            .map_err(|_| Response::error(503, "SDK credential callback unavailable"))? =
            Some(Call {
                record: record.clone(),
                action: "revoke",
                increment: 0,
            });
        *plan
            .cleanup
            .lock()
            .map_err(|_| Response::error(503, "SDK credential cleanup unavailable"))? =
            Some(Cleanup {
                clock,
                deadline,
                expected: digest(&record)?,
            });
        Ok(Some(plan))
    }
    pub(in crate::service) fn finish_sdk_credential_expiry(
        &mut self,
        mut plan: Plan,
        result: Result<Option<Value>, Response>,
    ) -> Result<(), Response> {
        let response = self.finalize_sdk_auth(&mut plan, result);
        let now = plan
            .time(
                &self
                    .state
                    .as_ref()
                    .ok_or_else(|| {
                        Response::error(503, "SDK credential cleanup owner unavailable")
                    })?
                    .auth,
            )?
            .seconds();
        let fingerprint = self.request_fingerprint(
            "INTERNAL",
            "sdk-credential-lifecycle/revoke",
            &plan.context.namespace,
            "",
        );
        if self
            .audit_event(
                "sdk-credential-lifecycle-response",
                &fingerprint,
                now,
                Some(response.status),
            )
            .is_err()
        {
            self.recovery_required = true;
            self.ha_activation = None;
            self.retire_sdk_hosts();
            return Err(Response::error(
                503,
                "SDK credential cleanup response audit failed",
            ));
        }
        let response = self.complete_sdk_auth_delivery(&plan, response, &fingerprint);
        if response.status >= 400 {
            return Err(response);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_sdk_credential_tests.rs"]
mod tests;
