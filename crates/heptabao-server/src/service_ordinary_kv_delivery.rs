//! Limited ordinary KV delivery authority. Sensitive non-KV routes retain
//! their separate completion contracts; this module does not qualify them.
use super::records::RecordPlan;
use super::*;

// A negative storage observation is not delivery authority. Its constructor
// accepts the durable primitive's typed error; JSON/status/fence flags cannot
// populate it. The binding belongs to the original affine request capsule.
#[derive(PartialEq, Eq)]
struct OrdinaryKvRequestBinding {
    started: std::time::Instant,
    namespace: String,
    path: String,
    method: String,
    activation_nonce: String,
}

struct IndeterminateCommitNotice {
    binding: OrdinaryKvRequestBinding,
    error: &'static str,
    recovery_reference: String,
}

// Temporarily carries only the negative observation while the original
// capsule is moved into the existing before-Publish closure. It conveys no
// Principal, clock, deadline, admission or right to release a private body.
pub(super) struct OrdinaryKvCommitNoticeCapture {
    binding: OrdinaryKvRequestBinding,
    notice: Option<IndeterminateCommitNotice>,
}

/// One original admission capability; neither this capsule nor Principal is
/// cloned, serialized or reconstructed from a bearer after dispatch.
pub(super) struct OrdinaryKvAuthority {
    principal: Principal,
    namespace: String,
    namespace_incarnation: Option<u64>,
    // Trusted ingress contract; HTTP and forwarded ingress require catalog
    // membership. Historical native calls can own an uncataloged namespace,
    // but still bind its actual Auth/Engine and the exact None/Some incarnation.
    namespace_catalog_required: bool,
    mount_path: String,
    mount_incarnation: u64,
    mount_revision: u64,
    cluster_id: String,
    activation_nonce: String,
    path: String,
    method: String,
    parameters: Value,
    capability: &'static str,
    admitted_at: u64,
    token_clock: Option<RequestClock>,
    started: std::time::Instant,
    deadline: Option<std::time::Instant>,
    indeterminate_commit: Option<IndeterminateCommitNotice>,
    audited_fingerprint: Option<String>,
}

impl Drop for OrdinaryKvAuthority {
    fn drop(&mut self) {
        erase_json(&mut self.parameters);
    }
}

impl OrdinaryKvAuthority {
    pub(super) fn new(
        principal: Principal,
        state: &State,
        request: &RequestView<'_>,
        activation_nonce: &str,
    ) -> Result<Self, Response> {
        let (mount_path, mount_incarnation, mount_revision) = state
            .engines
            .ordinary_kv_mount_binding(request.namespace, request.path)
            .ok_or_else(|| Response::error(503, "ordinary KV owner is unavailable"))?;
        let method = kv_authorization_method(request.method, request.body);
        let capability = state
            .engines
            .required_capability(request.namespace, method, request.path)
            .ok_or_else(|| Response::error(503, "ordinary KV capability is unavailable"))?;
        let mut authority = Self {
            principal,
            namespace: request.namespace.to_owned(),
            namespace_incarnation: state.namespaces.incarnation(request.namespace),
            namespace_catalog_required: request.enforce_namespace,
            mount_path: mount_path.to_owned(),
            mount_incarnation,
            mount_revision,
            cluster_id: state.cluster_id.clone(),
            activation_nonce: activation_nonce.to_owned(),
            path: request.path.to_owned(),
            method: method.to_owned(),
            parameters: request.body.clone(),
            capability,
            admitted_at: request.now,
            token_clock: request.token_clock,
            started: request.admission_started,
            deadline: crate::request_deadline::current(),
            indeterminate_commit: None,
            audited_fingerprint: None,
        };
        authority.check(state, &state.auth, activation_nonce)?;
        Ok(authority)
    }

    fn request_binding(&self) -> OrdinaryKvRequestBinding {
        OrdinaryKvRequestBinding {
            started: self.started,
            namespace: self.namespace.clone(),
            path: self.path.clone(),
            method: self.method.clone(),
            activation_nonce: self.activation_nonce.clone(),
        }
    }

    pub(super) fn mark_response_audited(&mut self, fingerprint: &str) {
        self.audited_fingerprint = Some(fingerprint.to_owned());
    }

    pub(super) fn principal(&self) -> &Principal {
        &self.principal
    }

    fn deadline_expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }

    fn token_time(&self, auth: &AuthState) -> Result<AuthorityTime, Response> {
        let time = match self.token_clock {
            Some(clock) => clock
                .with_seconds_floor(self.admitted_at)
                .and_then(RequestClock::observed_at)
                .map(AuthorityTime::Precise)
                .map_err(|_| Response::error(503, "trusted token clock is unavailable"))?,
            None => AuthorityTime::Coarse(
                std::time::Duration::from_secs(self.admitted_at)
                    .saturating_add(self.started.elapsed())
                    .as_secs(),
            ),
        };
        Ok(auth.token_api_observed_time(time))
    }

    pub(super) fn observe_candidate(&self, state: &mut State) -> Result<(), Response> {
        let time = self.token_time(&state.auth)?;
        state
            .auth
            .observe_token_api_time(time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        Ok(())
    }

    /// Authorize the original operation, rather than classify a newly created
    /// key as an update and ask the admitted create-only actor for a new grant.
    /// The caller supplies the exact publication candidate and, at the existing
    /// pre-Publish hook, its current authoritative AuthState.
    pub(super) fn check(
        &mut self,
        state: &State,
        auth: &AuthState,
        activation_nonce: &str,
    ) -> Result<(), Response> {
        if self.deadline_expired()
            || activation_nonce != self.activation_nonce
            || state.cluster_id != self.cluster_id
            || self.namespace_catalog_required && !state.namespace_exists(&self.namespace)
            || state.namespace_is_sealed(&self.namespace)
            || state.namespaces.incarnation(&self.namespace) != self.namespace_incarnation
            || state
                .engines
                .ordinary_kv_mount_binding(&self.namespace, &self.path)
                != Some((
                    self.mount_path.as_str(),
                    self.mount_incarnation,
                    self.mount_revision,
                ))
        {
            return Err(Response::error(
                503,
                "ordinary KV delivery owner or deadline changed",
            ));
        }
        Service::bind_identity_principal(state, &mut self.principal, &self.namespace)?;
        let time = self.token_time(auth)?;
        auth.authorize_request_parameters_observed(
            &self.principal,
            &self.namespace,
            &self.method,
            &self.path,
            &self.parameters,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        auth.authorize_request_observed(
            &self.principal,
            &self.namespace,
            &self.path,
            self.capability,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        if self.deadline_expired() {
            return Err(Response::error(
                503,
                "ordinary KV delivery deadline exceeded",
            ));
        }
        Ok(())
    }
}

impl Service {
    pub(super) fn capture_ordinary_kv_outcome_unknown(
        &mut self,
        error: &ServiceError,
        record_owner: bool,
    ) {
        let ServiceError::OutcomeUnknown { recovery_reference } = error else {
            return;
        };
        let error = if record_owner {
            "record durable outcome unknown; do not blindly retry"
        } else {
            "durable outcome unknown; do not blindly retry"
        };
        if let Some(authority) = self.pending_ordinary_kv_authority.as_mut() {
            authority.indeterminate_commit = Some(IndeterminateCommitNotice {
                binding: authority.request_binding(),
                error,
                recovery_reference: recovery_reference.clone(),
            });
        } else if let Some(capture) = self.pending_ordinary_kv_commit_notice.as_mut() {
            capture.notice = Some(IndeterminateCommitNotice {
                binding: OrdinaryKvRequestBinding {
                    started: capture.binding.started,
                    namespace: capture.binding.namespace.clone(),
                    path: capture.binding.path.clone(),
                    method: capture.binding.method.clone(),
                    activation_nonce: capture.binding.activation_nonce.clone(),
                },
                error,
                recovery_reference: recovery_reference.clone(),
            });
        }
    }

    /// Keep the original request deadline through the existing publication
    /// hook. The capsule remains owned until mandatory response audit/stamping
    /// has finished; this method does not discharge delivery authority.
    pub(super) fn commit_ordinary_kv_record_plan(
        &mut self,
        state: &State,
        plan: RecordPlan,
    ) -> Result<(), Response> {
        if self.pending_ordinary_kv_commit_notice.is_some() {
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            return Err(Response::error(
                503,
                "ordinary KV commit observation is unavailable",
            ));
        }
        let mut authority = self.pending_ordinary_kv_authority.take();
        let token_authority = self.pending_token_api_authority.take();
        self.pending_ordinary_kv_commit_notice =
            authority
                .as_ref()
                .map(|authority| OrdinaryKvCommitNoticeCapture {
                    binding: authority.request_binding(),
                    notice: None,
                });
        let mut result = if let Some(authority) = authority.as_mut() {
            let activation_nonce = self.unseal_nonce.clone();
            self.commit_record_plan_with_before_publish(
                state,
                plan,
                |auth| authority.check(state, auth, &activation_nonce),
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )
        } else if let Some(authority) = token_authority.as_ref() {
            let activation = self.unseal_nonce.clone();
            self.commit_record_plan_with_before_publish(
                state,
                plan,
                |auth| authority.check_token_api_candidate(state, auth, &activation),
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )
        } else {
            self.commit_record_plan(state, plan)
        };
        let capture = self.pending_ordinary_kv_commit_notice.take();
        match (authority.as_mut(), capture) {
            (Some(authority), Some(capture)) if capture.binding == authority.request_binding() => {
                authority.indeterminate_commit = capture.notice;
            }
            (None, None) => {}
            _ => {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                result = Err(Response::error(
                    503,
                    "ordinary KV commit observation was lost",
                ));
            }
        }
        self.pending_ordinary_kv_authority = authority;
        self.pending_token_api_authority = token_authority;
        result
    }

    pub(super) fn complete_ordinary_kv_delivery(
        &mut self,
        mut authority: OrdinaryKvAuthority,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        if let Some(notice) = authority.indeterminate_commit.take() {
            erase_json(&mut response.body);
            response.consistency_index = None;
            if notice.binding != authority.request_binding()
                || authority.audited_fingerprint.as_deref() != Some(fingerprint)
            {
                return Response::error(503, "ordinary KV indeterminate notice was not audited");
            }
            // This is exclusively a public negative storage observation. Never
            // reuse the handler/audit body or stamp an index; it proves no grant.
            return Response {
                response_headers: Default::default(),
                consistency_index: None,
                status: 503,
                body: json!({"errors":[notice.error],
                             "recovery_reference":notice.recovery_reference}),
            };
        }
        let planned_success = (200..300).contains(&response.status);
        let _deadline_scope = authority
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        let checked = (|| {
            if authority.deadline_expired() || self.recovery_required || self.state.is_none() {
                return Err(Response::error(503, "ordinary KV delivery is fenced"));
            }
            // Install actual HA state, including revocations or namespace/mount
            // retirement committed while audit or publication was blocking.
            if self.ha.is_some() && self.sync_from_ha_with_anchor(false).is_err() {
                return Err(Response::error(
                    503,
                    "ordinary KV delivery synchronization failed",
                ));
            }
            if self.recovery_required {
                return Err(Response::error(503, "ordinary KV delivery is fenced"));
            }
            let state = self
                .state
                .as_ref()
                .ok_or_else(|| Response::error(503, "ordinary KV delivery is sealed"))?;
            authority.check(state, &state.auth, &self.unseal_nonce)
        })();
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            let now = self.state.as_ref().map_or(authority.admitted_at, |state| {
                authority
                    .token_time(&state.auth)
                    .map_or(authority.admitted_at, AuthorityTime::seconds)
            });
            if planned_success
                && self
                    .audit_event(
                        "ordinary-kv-delivery-veto",
                        fingerprint,
                        now,
                        Some(error.status),
                    )
                    .is_err()
            {
                // This records a negative delivery observation after the private
                // body was erased. Failure cannot deliver data, extend the
                // original deadline or initiate another KV effect.
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(
                    503,
                    "ordinary KV delivery veto audit failed; authoritative recovery required",
                );
            }
            return error;
        }
        response
    }
}

#[cfg(test)]
#[path = "service_ordinary_kv_delivery_tests.rs"]
mod tests;
