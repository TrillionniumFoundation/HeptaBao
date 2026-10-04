//! Limited ordinary KV delivery authority. Sensitive non-KV routes retain
//! their separate completion contracts; this module does not qualify them.
use super::records::RecordPlan;
use super::*;

/// One original admission capability; neither this capsule nor Principal is
/// cloned, serialized or reconstructed from a bearer after dispatch.
pub(super) struct OrdinaryKvAuthority {
    principal: Principal,
    namespace: String,
    namespace_incarnation: Option<u64>,
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
        };
        authority.check(state, &state.auth, activation_nonce)?;
        Ok(authority)
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
            || !state.namespace_exists(&self.namespace)
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
    /// Keep the original request deadline through the existing publication
    /// hook. The capsule remains owned until mandatory response audit/stamping
    /// has finished; this method does not discharge delivery authority.
    pub(super) fn commit_ordinary_kv_record_plan(
        &mut self,
        state: &State,
        plan: RecordPlan,
    ) -> Result<(), Response> {
        let mut authority = self.pending_ordinary_kv_authority.take();
        let result = if let Some(authority) = authority.as_mut() {
            let activation_nonce = self.unseal_nonce.clone();
            self.commit_record_plan_with_before_publish(
                state,
                plan,
                |auth| authority.check(state, auth, &activation_nonce),
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )
        } else {
            self.commit_record_plan(state, plan)
        };
        self.pending_ordinary_kv_authority = authority;
        result
    }

    pub(super) fn complete_ordinary_kv_delivery(
        &mut self,
        mut authority: OrdinaryKvAuthority,
        mut response: Response,
    ) -> Response {
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
            return error;
        }
        response
    }
}

#[cfg(test)]
#[path = "service_ordinary_kv_delivery_tests.rs"]
mod tests;
