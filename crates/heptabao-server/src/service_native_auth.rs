//! Local AuthBus operations use the existing Auth dispatcher and V6 root transaction.
//! The request owner survives publication and the ordinary mandatory response audit.
use super::*;
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
use crate::v6_native_custody::OriginalDeadline;

fn rejected() -> Response {
    Response::error(503, "native authentication publication or delivery unavailable")
}

pub(super) struct NativeAuthDelivery {
    principal: Option<Principal>,
    method: String,
    path: String,
    body: Value,
    clock: RequestClock,
    deadline: OriginalDeadline,
    source_auth_digest: [u8; 32],
    // Preserve pre-operation actor and target lifetimes. A committed renewal
    // cannot extend the authority of the request that produced that renewal.
    source_auth: CowOwner<AuthState>,
    cluster_id: String,
    activation: String,
    data_dir: PathBuf,
    origin_peer: Option<std::net::IpAddr>,
    issued_token: Option<Zeroizing<String>>,
    publication_generation: u64,
}

impl Drop for NativeAuthDelivery {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

impl NativeAuthDelivery {
    fn time(&self, auth: &AuthState) -> Result<AuthorityTime, Response> {
        self.deadline.check().map_err(|_| rejected())?;
        let at = self.clock.observed_at().map_err(|_| rejected())?;
        Ok(auth.token_api_observed_time(AuthorityTime::Precise(at)))
    }

    fn check_source(&self, auth: &AuthState) -> Result<(), Response> {
        let time = self.time(auth)?;
        let bytes = owner_store::serialize_owner(auth).map_err(|_| rejected())?;
        if crypto::digest(&bytes) != self.source_auth_digest {
            return Err(rejected());
        }
        if let Some(principal) = self.principal.as_ref() {
            // The actual native handler already checked its operation-specific
            // ACL. Exact source equality preserves that decision; observe the
            // original actor's lifetime and request parameters again at fsync.
            auth.authorize_request_parameters_observed(
                principal,
                "",
                &self.method,
                &self.path,
                &self.body,
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
            if self.path.starts_with("auth/token/")
                && !self.path.strip_prefix("auth/token/").is_some_and(|operation| operation.starts_with("revoke"))
            {
                auth.authorize_request_observed(
                    principal, "", &self.path,
                    token_delivery::capability(&self.method, &self.path), time,
                ).map_err(|error| Response::error(error.status, &error.message))?;
                auth.validate_token_api_delivery_target(
                    principal, "", &self.path, &self.body, time,
                ).map_err(|error| Response::error(error.status, &error.message))?;
            }
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_owner(&self, service: &mut Service) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        if service.recovery_required
            || service.audit_failed
            || service.ha.is_some()
            || service.unseal_nonce != self.activation
            || service.data_dir != self.data_dir
            || service.native_root.is_none()
            || service.state.as_ref().is_none_or(|state| state.cluster_id != self.cluster_id)
        {
            return Err(rejected());
        }
        let durable = service.durable.as_mut().ok_or_else(rejected)?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        if durable.generation() < self.publication_generation {
            return Err(rejected());
        }
        self.deadline.check().map_err(|_| rejected())
    }
}

fn auth_only_root_change(prior: &RecordStateRootV6, next: &RecordStateRootV6) -> Result<(), Response> {
    if next.state_schema < prior.state_schema
        || next.reader_floor.minimum_state_schema < prior.reader_floor.minimum_state_schema
    {
        return Err(rejected());
    }
    let mut normalized = next.clone();
    normalized.state_schema = prior.state_schema;
    normalized.reader_floor.minimum_state_schema = prior.reader_floor.minimum_state_schema;
    for (old, new) in prior.owners.iter().zip(normalized.owners.iter_mut()) {
        if old.domain == new.domain && matches!(old.domain, OwnerDomain::Auth | OwnerDomain::Engines) {
            *new = old.clone();
        }
    }
    if normalized.encode().map_err(|_| rejected())?.as_slice()
        != prior.encode().map_err(|_| rejected())?.as_slice()
    {
        return Err(Response::error(501, "native authentication cannot change other storage owners"));
    }
    Ok(())
}

impl Service {
    pub(super) fn dispatch_native_auth_request(
        &mut self,
        mut candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
        token_fields: Option<&crate::http::token_fields::Carrier<'_>>,
    ) -> Response {
        if self.pending_native_auth_delivery.is_some()
            || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
            || !request.namespace.is_empty()
            || self.require_native_root_candidate(&candidate).is_err()
        {
            return Response::error(501, "native local authentication requires an unwrapped root-namespace request");
        }
        let Some(clock) = request.token_clock else {
            return rejected();
        };
        let Ok(deadline) = OriginalDeadline::capture() else {
            return rejected();
        };
        let Some(source) = self.state.as_ref() else {
            return rejected();
        };
        let source_auth = match owner_store::serialize_owner(&source.auth) {
            Ok(bytes) => bytes,
            Err(_) => return rejected(),
        };
        let public_login = source.auth.is_public_login("", request.method, request.path);
        if principal.is_none() && !public_login {
            return Response::error(403, "missing client token");
        }
        let mut delivery = NativeAuthDelivery {
            principal,
            method: request.method.to_owned(),
            path: request.path.to_owned(),
            body: request.body.clone(),
            clock,
            deadline,
            source_auth_digest: crypto::digest(&source_auth),
            source_auth: source.auth.clone(),
            cluster_id: source.cluster_id.clone(),
            activation: self.unseal_nonce.clone(),
            data_dir: self.data_dir.clone(),
            origin_peer: request.origin_peer,
            issued_token: None,
            publication_generation: self.durable.as_ref().map_or(0, |durable| durable.generation()),
        };
        if let Err(error) = delivery.check_source(&source.auth) {
            return error;
        }
        // This is the real domain dispatcher: AppRole/cert authentication,
        // identity bindings, SecretID consumption and ACLs are unchanged.
        let mut consumption = None;
        let mut response = Self::dispatch_authorized_subrequest(
            &mut candidate,
            delivery.principal.as_ref(),
            "",
            request.method,
            request.path,
            request.body,
            token_fields,
            None,
            request.now,
            request.token_clock,
            request.client_certificates,
            request.origin_peer,
            &mut consumption,
        );
        if response.status >= 400
            && let Some(consumption) = consumption
            && let Err(error) = consumption.apply(&mut candidate.auth)
        {
            erase_json(&mut response.body);
            return Response::error(error.status, &error.message);
        }
        candidate.schema = candidate.writer_schema();
        let result = (|| -> Result<(), Response> {
            if !self.state.as_ref().ok_or_else(rejected)?.engines.native_auth_identity_only_change(
                &candidate.engines, &|| delivery.deadline.check().is_ok(),
            ) {
                return Err(Response::error(501, "native authentication cannot change non-identity engine state"));
            }
            let plan = self.prepare_native_live_root_checked(&candidate, &mut |auth| delivery.check_source(auth))?;
            let prior = self.native_root.as_ref().ok_or_else(rejected)?;
            auth_only_root_change(prior, &plan.root)?;
            if plan.root.identity().map_err(|_| rejected())? != prior.identity().map_err(|_| rejected())? {
                candidate = self.commit_native_root_plan(
                    &candidate, plan, false, "auth", &mut |auth| delivery.check_source(auth),
                )?;
                self.state = Some(candidate);
            }
            delivery.publication_generation = self.durable.as_ref().ok_or_else(rejected)?.generation();
            delivery.check_owner(self)
        })();
        if let Err(error) = result {
            erase_json(&mut response.body);
            return error;
        }
        if response.status == 200 {
            let echo = match request.path {
                "auth/token/renew-self" => Some(request.token),
                "auth/token/renew" => request.body.get("token").and_then(Value::as_str),
                _ => None,
            };
            if let (Some(token), Some(auth)) = (echo, response.body.get_mut("auth").and_then(Value::as_object_mut)) {
                auth.insert("client_token".into(), json!(token));
            }
            let lookup = match request.path {
                "auth/token/lookup-self" => Some(request.token),
                "auth/token/lookup" => Some(request.body.get("token").and_then(Value::as_str).filter(|raw| !raw.is_empty()).unwrap_or(request.token)),
                "auth/token/lookup-accessor" => Some(""),
                _ => None,
            };
            if let (Some(token), Some(data)) = (lookup, response.body.get_mut("data").and_then(Value::as_object_mut)) {
                data.insert("id".into(), json!(token));
            }
            if public_login || matches!(request.path, "auth/token/create" | "auth/token/create-orphan")
                || request.path.starts_with("auth/token/create/")
            {
                delivery.issued_token = response.body.get("auth")
                    .and_then(|auth| auth.get("client_token"))
                    .and_then(Value::as_str)
                    .filter(|token| !token.is_empty())
                    .map(|token| Zeroizing::new(token.to_owned()));
            }
        }
        self.pending_native_auth_delivery = Some(delivery);
        response
    }

    pub(super) fn complete_native_auth_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let delivery = match (expected, self.pending_native_auth_delivery.take()) {
            (false, None) => return response,
            (true, Some(delivery)) => delivery,
            _ => {
                erase_json(&mut response.body);
                self.recovery_required = true;
                return rejected();
            }
        };
        if response.status >= 300 {
            return response;
        }
        let checked = (|| -> Result<(), Response> {
            delivery.check_owner(self)?;
            delivery.check_source(&delivery.source_auth)?;
            let state = self.state.as_ref().ok_or_else(rejected)?;
            let time = delivery.time(&state.auth)?;
            // A successful empty revoke/policy response may intentionally have
            // removed its own actor. It carries no credential or private payload.
            if response.status != 204 && let Some(principal) = delivery.principal.as_ref() {
                state.auth.authorize_request_parameters_observed(
                    principal, "", &delivery.method, &delivery.path, &delivery.body, time,
                ).map_err(|error| Response::error(error.status, &error.message))?;
                if delivery.path.starts_with("auth/token/") {
                    state.auth.authorize_request_observed(
                        principal, "", &delivery.path,
                        token_delivery::capability(&delivery.method, &delivery.path), time,
                    ).map_err(|error| Response::error(error.status, &error.message))?;
                    state.auth.validate_token_api_delivery_target(
                        principal, "", &delivery.path, &delivery.body, time,
                    ).map_err(|error| Response::error(error.status, &error.message))?;
                }
            }
            if let Some(token) = delivery.issued_token.as_ref() {
                // Verify reply viability on a throw-away Auth copy so a finite
                // new token loses no actual use before reaching its client.
                let mut checked = state.auth.clone();
                checked.authenticate_from_observed(token, time, delivery.origin_peer)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            delivery.deadline.check().map_err(|_| rejected())
        })();
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            if self.audit_event("native-auth-delivery-veto", fingerprint, delivery.clock.admitted_at().seconds(), Some(error.status)).is_err() {
                self.recovery_required = true;
                return rejected();
            }
            return error;
        }
        response
    }
}

#[cfg(test)]
#[path = "service_native_auth_tests.rs"]
mod tests;
