//! Authentication of one actual closed inherited owner. The verifier only
//! selects a candidate; full private typed custody and actual token admission
//! are required. This path cannot dispatch a loaded resource or remote effect.
use super::*;

fn unavailable() -> Response {
    Response::error(503, "closed namespace authentication owner is unavailable")
}

fn authority_time(request: &RequestView<'_>) -> Result<AuthorityTime, Response> {
    match request.token_time()? {
        // Retain historical publication-time fencing without inventing an
        // exact clock for explicit coarse callers.
        AuthorityTime::Coarse(now) => Ok(AuthorityTime::Coarse(external_pki::publication_now(now))),
        AuthorityTime::Precise(at) => Ok(AuthorityTime::Precise(at)),
    }
}

impl Service {
    pub(super) fn closed_namespace_token_response(
        &mut self,
        admitted: &State,
        request: &RequestView<'_>,
        help_body: Option<&Value>,
    ) -> Option<Response> {
        let verifier = AuthState::namespace_token_route_verifier(request.token)?;
        let binding = admitted.namespaces.closed_auth_route(&verifier)?.clone();
        let actual = binding.namespace();
        // A hidden/retired hint never creates a route or an actor. Public
        // anonymous classifications and original header guards ran beforehand.
        if admitted
            .namespaces
            .custody_binding(&admitted.cluster_id, actual)
            .ok()
            .as_ref()
            != Some(&binding)
        {
            return Some(Response::error(403, "permission denied"));
        }
        if admitted.namespace_is_sealed(actual) {
            return Some(Response::error(
                503,
                "error performing token check: failed to read entry: Vault is sealed",
            ));
        }
        if admitted.namespaces.inherited_owner(actual).is_none()
            || self.namespace_runtime.is_loaded(actual)
        {
            return None;
        }
        Some(self.closed_namespace_token_response_inner(admitted, request, help_body, actual))
    }

    fn closed_namespace_token_response_inner(
        &mut self,
        admitted: &State,
        request: &RequestView<'_>,
        help_body: Option<&Value>,
        actual: &str,
    ) -> Response {
        let activation = self.unseal_nonce.clone();
        let delivery = namespace_runtime::DeliveryBinding::capture(admitted, actual);
        let Some(root_key) = self.barrier_key.as_ref() else {
            return unavailable();
        };
        let time = match authority_time(request) {
            Ok(time) => time,
            Err(response) => return response,
        };
        let mut admission = match self.namespace_runtime.closed_auth_attempt_observed(
            admitted,
            actual,
            root_key,
            request.token,
            time,
            request.origin_peer,
        ) {
            Ok(admission) => admission,
            Err(response) => return response,
        };
        if let Err(response) = admission.bind_request_clock(request.token_clock) {
            return response;
        }
        let gate = |service: &Self, state: &State| -> Result<(), Response> {
            namespace_runtime::request_live()?;
            if service.recovery_required
                || service.unseal_nonce != activation
                || service.namespace_runtime.is_loaded(admission.actual())
                || state.namespace_is_sealed(admission.actual())
                || state
                    .namespaces
                    .custody_binding(&state.cluster_id, admission.actual())?
                    != *admission.binding()
                || namespace_runtime::DeliveryBinding::capture(state, admission.actual())
                    != delivery
            {
                return Err(unavailable());
            }
            if admission.actor().is_ok() {
                admission.validate_actor(state, authority_time(request)?)?;
            }
            Ok(())
        };
        if let Err(response) = gate(self, admitted) {
            return response;
        }
        if admission.needs_commit() {
            let mut candidate = match admission.candidate(&self.namespace_runtime) {
                Ok(candidate) => candidate,
                Err(response) => return response,
            };
            // The original owner, actor, activation and deadline are checked
            // on both sides of the actual durable publication. No key slot is
            // registered and no credential response is delivered on failure.
            let Some(current) = self.state.as_ref() else {
                return unavailable();
            };
            if let Err(response) = gate(self, current) {
                return response;
            }
            candidate.schema = candidate.writer_schema();
            if let Err(response) = self.commit_state(&mut candidate) {
                return response;
            }
            self.state = Some(candidate);
            #[cfg(test)]
            external_pki::delay_after_publication_for_test();
        }
        let Some(current) = self.state.as_ref() else {
            return unavailable();
        };
        if let Err(response) = gate(self, current) {
            return response;
        }
        let actor = match admission.actor() {
            Ok(actor) => actor,
            Err(response) => return response,
        };
        let namespace = if matches!(
            request.path,
            "auth/token/lookup-self" | "auth/token/renew-self" | "auth/token/revoke-self"
        ) {
            actor.namespace()
        } else {
            request.namespace
        };
        if request.enforce_namespace && !current.namespace_exists(namespace) {
            return Response::error(404, "namespace not found");
        }
        if request.enforce_namespace && current.namespace_is_sealed(namespace) {
            return Response::error(503, "namespace is sealed");
        }
        let resource_route = namespaces::owns(request.path)
            || request.path == "sys/mounts"
            || request.path.starts_with("sys/mounts/")
            || request.path.starts_with("auth/")
            || !request.path.starts_with("sys/");
        let unloaded = resource_route
            && current.namespaces.inherited_owner(namespace).is_some()
            && !self.namespace_runtime.is_loaded(namespace);
        if request.method == "HELP" {
            if unloaded {
                return namespace_runtime::unloaded_route(request.path);
            }
            let response = help_body.map_or_else(
                || Response::error(404, "help route not found"),
                |body| {
                    let mut body = body.clone();
                    if request.path == "auth/token/lookup-self"
                        && let Some(object) = body.as_object_mut()
                    {
                        object.insert("id".into(), Value::String(request.token.to_owned()));
                    }
                    Response {
                        response_headers: Default::default(),
                        consistency_index: None,
                        status: 200,
                        body,
                    }
                },
            );
            if response.status < 300 {
                // End the actor-derived borrow before moving the one affine
                // closed admission and its private key into the audit capsule.
                let namespace = namespace.to_owned();
                self.pending_help_authority = Some(help_delivery::HelpResponseAuthority::closed(
                    admission,
                    current,
                    request,
                    &namespace,
                    &activation,
                ));
            }
            return response;
        }
        if let Err(response) = admission.authorize(
            current,
            namespace,
            kv_authorization_method(request.method, request.body),
            request.path,
            request.body,
            match authority_time(request) {
                Ok(time) => time,
                Err(response) => return response,
            },
        ) {
            return response;
        }
        if unloaded {
            return namespace_runtime::unloaded_route(request.path);
        }
        // This first bounded slice never dispatches other ordinary owners,
        // target-token writes, wrapper payloads or external effects.
        unavailable()
    }
}
