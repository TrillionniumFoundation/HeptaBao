//! HELP owns its original metadata admission through mandatory response audit.
//! This authority can validate a metadata response, never authorize data I/O.
use super::*;

enum Admission {
    Opened(Box<Principal>),
    Closed(Box<namespace_runtime::ClosedAuthAdmission>),
}

pub(super) struct HelpResponseAuthority {
    admission: Admission,
    namespace: String,
    incarnation: Option<u64>,
    delivery: namespace_runtime::DeliveryBinding,
    closed_delivery: Option<namespace_runtime::DeliveryBinding>,
    cluster_id: String,
    activation: String,
    path: String,
    now: u64,
    started: std::time::Instant,
    clock: Option<RequestClock>,
    deadline: Option<std::time::Instant>,
}

impl HelpResponseAuthority {
    fn capture(
        admission: Admission,
        state: &State,
        request: &RequestView<'_>,
        namespace: &str,
        activation: &str,
    ) -> Self {
        let closed_delivery = match &admission {
            Admission::Closed(admission) => Some(namespace_runtime::DeliveryBinding::capture(
                state,
                admission.actual(),
            )),
            Admission::Opened(_) => None,
        };
        Self {
            admission,
            closed_delivery,
            namespace: namespace.to_owned(),
            incarnation: state.namespaces.incarnation(namespace),
            delivery: namespace_runtime::DeliveryBinding::capture(state, namespace),
            cluster_id: state.cluster_id.clone(),
            activation: activation.to_owned(),
            path: request.path.to_owned(),
            now: request.now,
            started: request.admission_started,
            clock: request.token_clock,
            deadline: crate::request_deadline::current(),
        }
    }
    pub(super) fn opened(
        principal: Principal,
        state: &State,
        request: &RequestView<'_>,
        activation: &str,
    ) -> Self {
        Self::capture(
            Admission::Opened(Box::new(principal)),
            state,
            request,
            request.namespace,
            activation,
        )
    }
    pub(super) fn closed(
        admission: namespace_runtime::ClosedAuthAdmission,
        state: &State,
        request: &RequestView<'_>,
        namespace: &str,
        activation: &str,
    ) -> Self {
        Self::capture(
            Admission::Closed(Box::new(admission)),
            state,
            request,
            namespace,
            activation,
        )
    }
    fn now(&self) -> u64 {
        self.now.saturating_add(self.started.elapsed().as_secs())
    }
    fn time(&self, state: &State) -> Result<AuthorityTime, Response> {
        let time = match self.clock {
            Some(clock) => clock
                .with_seconds_floor(self.now)
                .and_then(RequestClock::observed_at)
                .map(AuthorityTime::Precise)
                .map_err(|_| Response::error(503, "HELP original clock unavailable"))?,
            None => AuthorityTime::Coarse(external_pki::publication_now(self.now())),
        };
        Ok(state.auth.token_api_observed_time(time))
    }
    fn check(&mut self, service: &mut Service) -> Result<(), Response> {
        let _scope = self
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        if self
            .deadline
            .is_some_and(|end| std::time::Instant::now() >= end)
            || service.recovery_required
            || service.unseal_nonce != self.activation
        {
            return Err(Response::error(
                503,
                "HELP response deadline or activation changed",
            ));
        }
        if service.ha.is_some() {
            service.sync_from_ha_with_anchor(false)?;
        }
        let state = service
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "HELP response state unavailable"))?;
        state.namespace_leases.validate()?;
        if service.recovery_required
            || service.unseal_nonce != self.activation
            || state.cluster_id != self.cluster_id
            || !state.namespace_exists(&self.namespace)
            || state.namespace_is_sealed(&self.namespace)
            || state.namespace_is_tainted(&self.namespace)
            || state.namespaces.incarnation(&self.namespace) != self.incarnation
            || namespace_runtime::DeliveryBinding::capture(state, &self.namespace) != self.delivery
        {
            return Err(Response::error(
                503,
                "HELP response namespace owner changed",
            ));
        }
        let time = self.time(state)?;
        match &mut self.admission {
            Admission::Opened(actor) => {
                if state.namespaces.inherited_owner(&self.namespace).is_some()
                    && !service.namespace_runtime.is_loaded(&self.namespace)
                {
                    return Err(Response::error(503, "HELP metadata owner closed"));
                }
                Service::bind_identity_principal(state, actor, &self.namespace)?;
                state
                    .auth
                    .validate_help_actor_observed(actor, &self.namespace, time)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            Admission::Closed(admission) => {
                if service.namespace_runtime.is_loaded(admission.actual())
                    || state.namespace_is_sealed(admission.actual())
                    || self.closed_delivery.as_ref()
                        != Some(&namespace_runtime::DeliveryBinding::capture(
                            state,
                            admission.actual(),
                        ))
                    || state
                        .namespaces
                        .custody_binding(&state.cluster_id, admission.actual())?
                        != *admission.binding()
                {
                    return Err(Response::error(503, "HELP closed admission owner changed"));
                }
                // This is the same exclusive private typed parcel and consumed
                // actor. No key registration, bearer reopening or second use.
                admission.validate_actor(state, time)?;
            }
        }
        if self
            .deadline
            .is_some_and(|end| std::time::Instant::now() >= end)
        {
            return Err(Response::error(503, "HELP response deadline expired"));
        }
        Ok(())
    }
}

impl Drop for HelpResponseAuthority {
    fn drop(&mut self) {
        self.path.zeroize();
    }
}

impl Service {
    pub(super) fn complete_pending_help_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let mut authority = match (expected, self.pending_help_authority.take()) {
            (true, Some(authority)) => authority,
            (false, None) => return response,
            (false, Some(_)) if response.status >= 300 => return response,
            _ => {
                erase_json(&mut response.body);
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "HELP delivery capsule was lost");
            }
        };
        if response.status >= 300 {
            return response;
        }
        if let Err(error) = authority.check(self) {
            erase_json(&mut response.body);
            response.consistency_index = None;
            if self
                .audit_event(
                    "help-delivery-veto",
                    fingerprint,
                    authority.now(),
                    Some(error.status),
                )
                .is_err()
            {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "HELP delivery veto audit failed; recovery required");
            }
            return error;
        }
        response
    }
}
