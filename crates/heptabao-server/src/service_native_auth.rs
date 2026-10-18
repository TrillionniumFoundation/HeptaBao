//! AuthBus operations use the existing Auth dispatcher and V6 root transaction.
//! The request owner survives publication and the ordinary mandatory response audit.
use super::*;
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
use crate::v6_native_custody::OriginalDeadline;

fn rejected() -> Response {
    Response::error(
        503,
        "native authentication publication or delivery unavailable",
    )
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
    cert_lifetime: Option<crate::auth::NativeV6CertLifetime>,
    cluster_id: String,
    activation: String,
    data_dir: PathBuf,
    origin_peer: Option<std::net::IpAddr>,
    issued_token: Option<Zeroizing<String>>,
    publication_generation: u64,
    // The actual post-Auth local/Raft frontier. Only the affine receipt from
    // this request's terminal observation may advance it before proof capture.
    delivery_checkpoint: Option<(
        crate::state_record_root::StateIdentity,
        plugin::PublicationGeneration,
    )>,
    // This is the actual request's process owner, never a reconstructed node ID.
    ha: Option<Arc<Mutex<HaProcess>>>,
    // Only HA delivery needs this additional consensus proof. It is minted once
    // after the terminal observation publication, before audit, and never
    // renewed after audit. The checkpoint above is not itself this proof.
    proof: Option<native_v6_reader::NativeProof>,
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
        auth.validate_native_v6_approle_login_lifetime_observed(
            "",
            &self.method,
            &self.path,
            &self.body,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        if let Some(lifetime) = self.cert_lifetime.as_ref() {
            lifetime
                .check_at(time)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
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
                && !self
                    .path
                    .strip_prefix("auth/token/")
                    .is_some_and(|operation| operation.starts_with("revoke"))
            {
                auth.authorize_request_observed(
                    principal,
                    "",
                    &self.path,
                    token_delivery::capability(&self.method, &self.path),
                    time,
                )
                .map_err(|error| Response::error(error.status, &error.message))?;
                auth.validate_token_api_delivery_target(
                    principal, "", &self.path, &self.body, time,
                )
                .map_err(|error| Response::error(error.status, &error.message))?;
            }
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_environment(&self, service: &mut Service) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.activation
            || service.data_dir != self.data_dir
            || service.native_root.is_none()
            || service
                .state
                .as_ref()
                .is_none_or(|state| state.cluster_id != self.cluster_id)
        {
            return Err(rejected());
        }
        match (&self.ha, &service.ha) {
            (None, None) => {}
            #[cfg(feature = "experimental-native-v6-ha")]
            (Some(original), Some(current)) if Arc::ptr_eq(original, current) => {}
            _ => return Err(rejected()),
        }
        let durable = service.durable.as_mut().ok_or_else(rejected)?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        let generation = durable.generation();
        if self.ha.is_some() && generation != self.publication_generation
            // Keep the existing standalone delivery contract; it has no HA
            // proof and independently validates current Auth at final delivery.
            || self.ha.is_none() && generation < self.publication_generation
        {
            return Err(rejected());
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_owner(&self, service: &mut Service) -> Result<(), Response> {
        self.check_environment(service)?;
        match (&self.ha, &self.proof) {
            (None, None) => Ok(()),
            #[cfg(feature = "experimental-native-v6-ha")]
            (Some(_), Some(proof @ native_v6_reader::NativeProof::Ha(_))) => {
                proof.check_warm(service)
            }
            _ => Err(rejected()),
        }
    }

    fn current_checkpoint(
        service: &Service,
    ) -> Result<
        (
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        ),
        Response,
    > {
        let identity = service.current_state_identity()?;
        if !matches!(
            identity,
            crate::state_record_root::StateIdentity::RecordsV6(_)
        ) {
            return Err(rejected());
        }
        Ok((identity, service.external_effect_generation()?))
    }

    fn stage_publication(&mut self, service: &mut Service) -> Result<(), Response> {
        if self.ha.is_none() || self.delivery_checkpoint.is_some() || self.proof.is_some() {
            return Err(rejected());
        }
        self.check_environment(service)?;
        self.check_source(&self.source_auth)?;
        self.delivery_checkpoint = Some(Self::current_checkpoint(service)?);
        self.check_checkpoint(service)
    }

    fn check_checkpoint(&self, service: &mut Service) -> Result<(), Response> {
        self.check_environment(service)?;
        self.check_source(&self.source_auth)?;
        if self.ha.is_none()
            || self.delivery_checkpoint.as_ref() != Some(&Self::current_checkpoint(service)?)
        {
            return Err(rejected());
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn bind_after_terminal_observation(
        &mut self,
        service: &mut Service,
        receipt: Option<token_precision::TerminalClockReceipt>,
    ) -> Result<(), Response> {
        if self.ha.is_none() || self.proof.is_some() || self.delivery_checkpoint.is_none() {
            return Err(rejected());
        }
        self.check_source(&self.source_auth)?;
        if let Some(receipt) = receipt {
            receipt.advance_native_auth(&mut self.delivery_checkpoint)?;
            // Current local state must be exactly the receipt's resulting
            // identity/frontier before its generation may replace the prior
            // one. Reading a newer integer alone would admit unrelated work.
            if self.delivery_checkpoint.as_ref() != Some(&Self::current_checkpoint(service)?) {
                return Err(rejected());
            }
            self.publication_generation =
                service.durable.as_ref().ok_or_else(rejected)?.generation();
        }
        self.check_checkpoint(service)?;
        self.bind_publication(service)?;
        self.check_checkpoint(service)
    }

    fn bind_publication(&mut self, service: &mut Service) -> Result<(), Response> {
        let _original_deadline =
            crate::request_deadline::RequestDeadlineScope::enter(self.deadline.instant());
        self.check_environment(service)?;
        if self.proof.is_some() {
            return Err(rejected());
        }
        #[cfg(feature = "experimental-native-v6-ha")]
        if self.ha.is_some() {
            // Capture under the same thread-local original request budget and
            // the retained pre-operation Auth owner. A successful renewal does
            // not extend that owner; a public login does not invent an Actor.
            let proof = service
                .capture_native_request_proof(&mut || self.check_source(&self.source_auth))?
                .ok_or_else(rejected)?;
            if !matches!(&proof, native_v6_reader::NativeProof::Ha(_))
                || proof.generation() != self.publication_generation
            {
                return Err(rejected());
            }
            self.proof = Some(proof);
        }
        self.check_owner(service)
    }

    fn check_reply_auth(&self, auth: &AuthState, status: u16) -> Result<(), Response> {
        let time = self.time(auth)?;
        // A successful empty revoke/policy response may intentionally have
        // removed its own actor. It carries no credential or private payload.
        if status != 204
            && let Some(principal) = self.principal.as_ref()
        {
            auth.authorize_request_parameters_observed(
                principal,
                "",
                &self.method,
                &self.path,
                &self.body,
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
            if self.path.starts_with("auth/token/") {
                auth.authorize_request_observed(
                    principal,
                    "",
                    &self.path,
                    token_delivery::capability(&self.method, &self.path),
                    time,
                )
                .map_err(|error| Response::error(error.status, &error.message))?;
                auth.validate_token_api_delivery_target(
                    principal, "", &self.path, &self.body, time,
                )
                .map_err(|error| Response::error(error.status, &error.message))?;
            }
        }
        if let Some(token) = self.issued_token.as_ref() {
            // Verify reply viability on a throw-away Auth copy so a finite new
            // token loses no actual use before reaching its client.
            let mut checked = auth.clone();
            checked
                .authenticate_from_observed(token, time, self.origin_peer)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        self.deadline.check().map_err(|_| rejected())
    }
}

fn auth_only_root_change(
    prior: &RecordStateRootV6,
    next: &RecordStateRootV6,
) -> Result<(), Response> {
    if next.state_schema < prior.state_schema
        || next.reader_floor.minimum_state_schema < prior.reader_floor.minimum_state_schema
    {
        return Err(rejected());
    }
    let mut normalized = next.clone();
    normalized.state_schema = prior.state_schema;
    normalized.reader_floor.minimum_state_schema = prior.reader_floor.minimum_state_schema;
    for (old, new) in prior.owners.iter().zip(normalized.owners.iter_mut()) {
        if old.domain == new.domain
            && matches!(old.domain, OwnerDomain::Auth | OwnerDomain::Engines)
        {
            *new = old.clone();
        }
    }
    if normalized.encode().map_err(|_| rejected())?.as_slice()
        != prior.encode().map_err(|_| rejected())?.as_slice()
    {
        return Err(Response::error(
            501,
            "native authentication cannot change other storage owners",
        ));
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
            return Response::error(
                501,
                "native local authentication requires an unwrapped root-namespace request",
            );
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
        let public_login = source
            .auth
            .is_public_login("", request.method, request.path);
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
            cert_lifetime: None,
            cluster_id: source.cluster_id.clone(),
            activation: self.unseal_nonce.clone(),
            data_dir: self.data_dir.clone(),
            origin_peer: request.origin_peer,
            issued_token: None,
            publication_generation: self
                .durable
                .as_ref()
                .map_or(0, |durable| durable.generation()),
            delivery_checkpoint: None,
            ha: self.ha.clone(),
            proof: None,
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
        if public_login && response.status == 200 {
            // Capture only after the real handler has authenticated the actual
            // TLS leaf. Its original validity remains binding through publish
            // and audited response delivery; it grants no additional authority.
            let captured = delivery.time(&delivery.source_auth).and_then(|time| {
                delivery
                    .source_auth
                    .capture_native_v6_cert_login_lifetime(
                        "",
                        request.method,
                        request.path,
                        request.client_certificates,
                        time,
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
            });
            match captured {
                Ok(lifetime) => delivery.cert_lifetime = lifetime,
                Err(error) => {
                    erase_json(&mut response.body);
                    return error;
                }
            }
            #[cfg(test)]
            tests::login_tests::before_native_login_publication(request.path);
        }
        if !public_login && response.status == 200 {
            if let Some(principal) = delivery.principal.as_ref() {
                let captured = delivery.time(&delivery.source_auth).and_then(|time| {
                    delivery
                        .source_auth
                        .capture_native_v6_cert_renewal_lifetime(
                            principal,
                            "",
                            request.method,
                            request.path,
                            request.body,
                            request.client_certificates,
                            time,
                        )
                        .map_err(|error| Response::error(error.status, &error.message))
                });
                match captured {
                    Ok(lifetime) => delivery.cert_lifetime = lifetime,
                    Err(error) => {
                        erase_json(&mut response.body);
                        return error;
                    }
                }
                #[cfg(test)]
                if delivery.cert_lifetime.is_some() {
                    tests::cert_renewal_tests::before_native_cert_renewal_publication(request.path);
                }
            }
        }
        if response.status >= 400
            && let Some(consumption) = consumption
            && let Err(error) = consumption.apply(&mut candidate.auth)
        {
            erase_json(&mut response.body);
            return Response::error(error.status, &error.message);
        }
        candidate.schema = candidate.writer_schema();
        let result = (|| -> Result<(), Response> {
            if !self
                .state
                .as_ref()
                .ok_or_else(rejected)?
                .engines
                .native_auth_identity_only_change(&candidate.engines, &|| {
                    delivery.deadline.check().is_ok()
                })
            {
                return Err(Response::error(
                    501,
                    "native authentication cannot change non-identity engine state",
                ));
            }
            let plan = self.prepare_native_live_root_checked(&candidate, &mut |auth| {
                delivery.check_source(auth)
            })?;
            let prior = self.native_root.as_ref().ok_or_else(rejected)?;
            auth_only_root_change(prior, &plan.root)?;
            if plan.root.identity().map_err(|_| rejected())?
                != prior.identity().map_err(|_| rejected())?
            {
                candidate =
                    self.commit_native_root_plan(&candidate, plan, false, "auth", &mut |auth| {
                        delivery.check_source(auth)
                    })?;
                self.state = Some(candidate);
            }
            delivery.publication_generation =
                self.durable.as_ref().ok_or_else(rejected)?.generation();
            delivery.check_environment(self)
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
            if let (Some(token), Some(auth)) = (
                echo,
                response.body.get_mut("auth").and_then(Value::as_object_mut),
            ) {
                auth.insert("client_token".into(), json!(token));
            }
            let lookup = match request.path {
                "auth/token/lookup-self" => Some(request.token),
                "auth/token/lookup" => Some(
                    request
                        .body
                        .get("token")
                        .and_then(Value::as_str)
                        .filter(|raw| !raw.is_empty())
                        .unwrap_or(request.token),
                ),
                "auth/token/lookup-accessor" => Some(""),
                _ => None,
            };
            if let (Some(token), Some(data)) = (
                lookup,
                response.body.get_mut("data").and_then(Value::as_object_mut),
            ) {
                data.insert("id".into(), json!(token));
            }
            if public_login
                || matches!(
                    request.path,
                    "auth/token/create" | "auth/token/create-orphan"
                )
                || request.path.starts_with("auth/token/create/")
            {
                delivery.issued_token = response
                    .body
                    .get("auth")
                    .and_then(|auth| auth.get("client_token"))
                    .and_then(Value::as_str)
                    .filter(|token| !token.is_empty())
                    .map(|token| Zeroizing::new(token.to_owned()));
            }
        }
        let staged = if delivery.ha.is_some() {
            // Retain exact post-operation provenance before the terminal
            // observation. The sole HA proof is captured after that write and
            // before mandatory audit, never in the final response handler.
            delivery.stage_publication(self)
        } else {
            delivery.bind_publication(self)
        };
        if let Err(error) = staged {
            erase_json(&mut response.body);
            response.consistency_index = None;
            return error;
        }
        self.pending_native_auth_delivery = Some(delivery);
        response
    }

    pub(super) fn native_auth_terminal_deadline(&self) -> Option<Instant> {
        self.pending_native_auth_delivery
            .as_ref()
            .filter(|delivery| delivery.ha.is_some())
            .map(|delivery| delivery.deadline.instant())
    }

    pub(super) fn check_pending_native_auth_before_terminal(&mut self) -> Result<(), Response> {
        let Some(delivery) = self.pending_native_auth_delivery.take() else {
            return Ok(());
        };
        let result = if delivery.ha.is_some() {
            if delivery.proof.is_some() || self.pending_forward_delivery.is_some() {
                Err(rejected())
            } else {
                delivery.check_checkpoint(self)
            }
        } else {
            Ok(())
        };
        self.pending_native_auth_delivery = Some(delivery);
        result
    }

    pub(super) fn bind_pending_native_auth_before_audit(
        &mut self,
        receipt: Option<token_precision::TerminalClockReceipt>,
    ) -> Result<(), Response> {
        let Some(mut delivery) = self.pending_native_auth_delivery.take() else {
            return Err(rejected());
        };
        let result = delivery.bind_after_terminal_observation(self, receipt);
        // A rejected bind still owns the original capsule. The terminal
        // response path consumes it normally rather than inventing a missing
        // delivery, repeating the operation, or recapturing after audit.
        self.pending_native_auth_delivery = Some(delivery);
        result
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
            if let Some(proof) = delivery.proof.as_ref() {
                // No fresh ReadIndex is acquired here. Inspect the actual local
                // typed closure under the same pre-audit consensus witness,
                // then validate the response against its authenticated Auth.
                proof.check_with(self, |installed, metadata, native, root, deadline| {
                    delivery.check_source(&delivery.source_auth)?;
                    Self::check_native_installed(installed, metadata, native, root, deadline)?;
                    delivery.check_reply_auth(&metadata.auth, response.status)?;
                    delivery.check_source(&delivery.source_auth)
                })?;
                delivery.check_owner(self)?;
                delivery.check_source(&delivery.source_auth)?;
                delivery.check_reply_auth(
                    &self.state.as_ref().ok_or_else(rejected)?.auth,
                    response.status,
                )?;
            } else {
                let state = self.state.as_ref().ok_or_else(rejected)?;
                delivery.check_reply_auth(&state.auth, response.status)?;
            }
            delivery.deadline.check().map_err(|_| rejected())
        })();
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            if self
                .audit_event(
                    "native-auth-delivery-veto",
                    fingerprint,
                    delivery.clock.admitted_at().seconds(),
                    Some(error.status),
                )
                .is_err()
            {
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
