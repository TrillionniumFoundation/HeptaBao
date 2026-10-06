//! ACME is a public JWS account protocol, not token authentication. One original
//! request owns nonce consumption, publication and its post-audit delivery cut.
use super::*;
use crate::auth::Timestamp;
use crate::engines::{AcmeBinding, AcmeParsedJws, AcmeView};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const MAX_NONCES: usize = 8192;
struct Nonce {
    owner: AcmeBinding,
    activation: String,
    expires: Timestamp,
    monotonic: std::time::Instant,
}
#[derive(Default)]
pub(super) struct Nonces(BTreeMap<String, Nonce>);
impl Drop for Nonces {
    fn drop(&mut self) {
        for (mut nonce, mut grant) in std::mem::take(&mut self.0) {
            nonce.zeroize();
            grant.activation.zeroize();
        }
    }
}
impl Nonces {
    fn mint(
        &mut self,
        owner: &AcmeBinding,
        activation: &str,
        at: Timestamp,
    ) -> Result<String, Response> {
        self.0.retain(|_, v| {
            v.expires >= at
                && std::time::Instant::now() <= v.monotonic
                && v.activation == activation
        });
        if self.0.len() >= MAX_NONCES {
            return Err(Response::error(503, "ACME nonce capacity exhausted"));
        }
        let expires = at
            .seconds()
            .checked_add(90)
            .and_then(|seconds| Timestamp::whole(seconds).ok())
            .ok_or_else(|| Response::error(503, "ACME nonce deadline unavailable"))?;
        // Nonces are opaque protocol strings. Public shape matches vault0's
        // 46-byte format; genuine secrets and redemption remain process-local.
        let mut bytes = Vec::from(b"vault0".as_slice());
        bytes.extend_from_slice(
            &crypto::random::<40>()
                .map_err(|_| Response::error(503, "ACME nonce generation unavailable"))?,
        );
        let value = URL_SAFE_NO_PAD.encode(bytes);
        if self.0.contains_key(&value) {
            return Err(Response::error(503, "ACME nonce collision rejected"));
        }
        self.0.insert(
            value.clone(),
            Nonce {
                owner: owner.clone(),
                activation: activation.to_owned(),
                expires,
                monotonic: std::time::Instant::now() + Duration::from_secs(90),
            },
        );
        Ok(value)
    }
    fn redeem(
        &mut self,
        value: &str,
        owner: &AcmeBinding,
        activation: &str,
        at: Timestamp,
    ) -> bool {
        self.0.remove(value).is_some_and(|nonce| {
            nonce.owner == *owner
                && nonce.activation == activation
                && nonce.expires >= at
                && std::time::Instant::now() <= nonce.monotonic
        })
    }
}

pub(super) struct Authority {
    owner: AcmeBinding,
    path: String,
    mount_revision: u64,
    fingerprint: [u8; 32],
    activation: String,
    delivery: namespace_runtime::DeliveryBinding,
    clock: Option<RequestClock>,
    at: u64,
    started: std::time::Instant,
    deadline: Option<std::time::Instant>,
    nonce: Option<String>,
    nonce_deadline: Option<(Timestamp, std::time::Instant)>,
    operator: Option<plugin::PluginResponseAuthority>,
    external_delivery: Option<crate::engines::AcmeExternalDelivery>,
}
impl Drop for Authority {
    fn drop(&mut self) {
        self.path.zeroize();
        self.activation.zeroize();
        if let Some(nonce) = self.nonce.as_mut() {
            nonce.zeroize();
        }
    }
}
impl Authority {
    pub(super) fn capture(
        state: &State,
        view: &AcmeView,
        request: &RequestView<'_>,
        activation: &str,
        nonce: Option<String>,
    ) -> Self {
        Self {
            owner: view.owner.clone(),
            path: request.path.to_owned(),
            mount_revision: view.revision,
            fingerprint: view.fingerprint,
            activation: activation.to_owned(),
            delivery: namespace_runtime::DeliveryBinding::capture(state, request.namespace),
            clock: request.token_clock,
            at: request.now,
            started: request.admission_started,
            deadline: crate::request_deadline::current(),
            nonce,
            nonce_deadline: None,
            operator: None,
            external_delivery: None,
        }
    }
    pub(super) fn with_operator(mut self, operator: plugin::PluginResponseAuthority) -> Self {
        self.operator = Some(operator);
        self
    }
    pub(super) fn observe_operator(&self, state: &mut State) -> Result<AuthorityTime, Response> {
        self.operator
            .as_ref()
            .ok_or_else(|| Response::error(503, "EAB operator authority missing"))?
            .observe_candidate_time(state)
    }
    pub(super) fn validate_operator_auth(&self, auth: &AuthState) -> Result<(), Response> {
        match &self.operator {
            Some(operator) => operator.validate_live_auth(auth),
            None => Ok(()),
        }
    }
    pub(super) fn bind_external_delivery(
        &mut self,
        delivery: crate::engines::AcmeExternalDelivery,
    ) {
        self.external_delivery = Some(delivery);
    }
    pub(super) fn deadline(&self) -> Option<std::time::Instant> {
        self.deadline
    }
    pub(super) fn observed_at(&self) -> Result<Timestamp, Response> {
        match self.clock {
            Some(clock) => clock
                .with_seconds_floor(self.at)
                .and_then(RequestClock::observed_at)
                .map_err(|_| Response::error(503, "ACME original request clock unavailable")),
            None => Timestamp::from_wall(
                Duration::from_secs(self.at).saturating_add(self.started.elapsed()),
            )
            .map_err(|_| Response::error(503, "ACME original request time unavailable")),
        }
    }
    pub(super) fn check_state(&self, state: &State) -> Result<(), Response> {
        if self
            .deadline
            .is_some_and(|at| std::time::Instant::now() >= at)
        {
            return Err(Response::error(
                503,
                "ACME original publication deadline expired",
            ));
        }
        self.validate_operator_auth(&state.auth)?;
        state.namespace_leases.validate()?;
        if !state.namespace_exists(&self.owner.namespace)
            || state.namespace_is_sealed(&self.owner.namespace)
            || state.namespaces.incarnation(&self.owner.namespace)
                != self.owner.namespace_incarnation
            || state.cluster_id != self.owner.cluster_id
            || namespace_runtime::DeliveryBinding::capture(state, &self.owner.namespace)
                != self.delivery
        {
            return Err(Response::error(
                503,
                "ACME response namespace owner changed",
            ));
        }
        let view = state
            .engines
            .acme_view(
                &self.owner.namespace,
                &self.path,
                &state.cluster_id,
                self.owner.namespace_incarnation,
            )
            .map_err(Response::from_engine_error)?
            .ok_or_else(|| Response::error(503, "ACME response mount owner changed"))?;
        if view.owner != self.owner
            || view.revision != self.mount_revision
            || view.fingerprint != self.fingerprint
        {
            return Err(Response::error(
                503,
                "ACME account or mount response owner changed",
            ));
        }
        let at = self.observed_at()?;
        if let Some(delivery) = &self.external_delivery {
            delivery
                .validate(&state.engines, at)
                .map_err(Response::from_engine_error)?;
        }
        if self.nonce_deadline.is_some_and(|(expires, monotonic)| {
            at > expires || std::time::Instant::now() > monotonic
        }) {
            return Err(Response::error(
                503,
                "ACME nonce expired before publication or delivery",
            ));
        }
        namespace_runtime::request_live()
    }
    pub(super) fn bind_candidate(&mut self, state: &State) -> Result<(), Response> {
        // Preserve the admitted clock, deadline and namespace/mount ownership.
        // Only the fingerprint of this request's validated candidate can change.
        let view = state
            .engines
            .acme_view(
                &self.owner.namespace,
                &self.path,
                &state.cluster_id,
                state.namespaces.incarnation(&self.owner.namespace),
            )
            .map_err(Response::from_engine_error)?
            .ok_or_else(|| Response::error(503, "ACME candidate mount unavailable"))?;
        if view.owner != self.owner
            || view.revision != self.mount_revision
            || namespace_runtime::DeliveryBinding::capture(state, &self.owner.namespace)
                != self.delivery
        {
            return Err(Response::error(503, "ACME candidate owner changed"));
        }
        self.fingerprint = view.fingerprint;
        self.check_state(state)
    }
    pub(super) fn check(&self, service: &mut Service) -> Result<(), Response> {
        let _scope = self
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        if service.recovery_required
            || service.unseal_nonce != self.activation
            || self
                .deadline
                .is_some_and(|at| std::time::Instant::now() >= at)
        {
            return Err(Response::error(
                503,
                "ACME response authority expired or changed",
            ));
        }
        if service.ha.is_some() {
            service.sync_from_ha_with_anchor(false)?;
        }
        let state = service
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "ACME response state unavailable"))?;
        self.check_state(state)?;
        let at = self.observed_at()?;
        if let Some(nonce) = &self.nonce
            && service.acme_nonces.0.get(nonce).is_none_or(|grant| {
                grant.expires < at
                    || std::time::Instant::now() > grant.monotonic
                    || grant.owner != self.owner
                    || grant.activation != self.activation
            })
        {
            return Err(Response::error(503, "ACME nonce expired before delivery"));
        }
        namespace_runtime::request_live()
    }
}

pub(super) fn wire(
    status: u16,
    body: Option<Value>,
    problem: bool,
    headers: ResponseHeaders,
) -> Response {
    Response {
        status,
        body: json!({"__heptabao_acme":body,"media":if problem {"problem"} else if body.is_none() {"empty"} else {"json"}}),
        response_headers: headers,
        consistency_index: None,
    }
}
fn problem(status: u16, kind: &str, detail: &str) -> Response {
    wire(
        status,
        Some(json!({"type":format!("urn:ietf:params:acme:error:{kind}"),"detail":detail})),
        true,
        Default::default(),
    )
}
fn engine_problem(error: crate::engines::EngineError) -> Response {
    let kind = if error.message.contains("account does not exist")
        || error
            .message
            .starts_with("an account with this key does not exist:")
    {
        "accountDoesNotExist"
    } else if error
        .message
        .ends_with("an identifier is of an unsupported type")
    {
        "unsupportedIdentifier"
    } else if error
        .message
        .starts_with("server will not issue certificates for the identifier:")
    {
        "rejectedIdentifier"
    } else if error.message
        == "the request must include a value for the 'externalAccountBinding' field"
    {
        "externalAccountRequired"
    } else if error
        .message
        .ends_with("the revocation reason provided is not allowed by the server")
    {
        "badRevocationReason"
    } else if error.message.ends_with(
        "the request specified a certificate to be revoked that has already been revoked",
    ) {
        "alreadyRevoked"
    } else if error.message.starts_with("the CSR is unacceptable:") {
        "badCSR"
    } else if error.message.starts_with(
        "the request attempted to finalize an order that is not ready to be finalized:",
    ) {
        "orderNotReady"
    } else if error.status == 401 {
        "unauthorized"
    } else if error.status >= 500 {
        "serverInternal"
    } else {
        "malformed"
    };
    problem(error.status, kind, &error.message)
}

impl Service {
    pub(super) fn handle_pki_acme(
        &mut self,
        request: &RequestView<'_>,
        admitted: &mut State,
    ) -> Option<Response> {
        let view = match admitted.engines.acme_view(
            request.namespace,
            request.path,
            &admitted.cluster_id,
            admitted.namespaces.incarnation(request.namespace),
        ) {
            Ok(Some(view)) => view,
            Ok(None) => return None,
            Err(error) => return Some(Response::from_engine_error(error)),
        };
        // EAB key administration belongs to the ordinary authenticated Vault
        // API. It must never enter the public JWS dispatcher.
        if view.endpoint == "new-eab" || view.endpoint == "eab" || view.endpoint.starts_with("eab/")
        {
            return None;
        }
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl != 0) {
            return Some(Response::error(
                400,
                "ACME response wrapping is unsupported",
            ));
        }
        let identity = match self.current_state_identity() {
            Ok(identity) => identity,
            Err(error) => return Some(error),
        };
        let mut authority = Some(Authority::capture(
            admitted,
            &view,
            request,
            &self.unseal_nonce,
            None,
        ));
        // Bao 2.7 advertises keyChange and exempts it from token ACLs, but
        // registers no handler. The unsupported route does not redeem JWS.
        let mut response = if view.endpoint == "key-change" {
            Response::error(404, "unsupported path")
        } else if !view.enabled {
            wire(404, None, false, Default::default())
        } else if let Err(error) = admitted.engines.acme_directory_gate(&view) {
            engine_problem(error)
        } else if view.endpoint == "directory" && request.method == "GET" {
            wire(
                200,
                Some(
                    json!({"newNonce":format!("{}new-nonce",view.base),"newAccount":format!("{}new-account",view.base),"newOrder":format!("{}new-order",view.base),"revokeCert":format!("{}revoke-cert",view.base),"keyChange":format!("{}key-change",view.base),"meta":{"externalAccountRequired":view.eab_required}}),
                ),
                false,
                Default::default(),
            )
        } else if view.endpoint == "new-nonce" && matches!(request.method, "GET" | "HEAD") {
            wire(
                if request.method == "GET" { 204 } else { 200 },
                None,
                false,
                Default::default(),
            )
        } else if view.endpoint == "new-account"
            || view
                .endpoint
                .strip_prefix("account/")
                .is_some_and(|id| !id.is_empty() && !id.contains('/'))
            || view.endpoint == "new-order"
            || view.endpoint == "orders"
            || view.endpoint == "revoke-cert"
            || view
                .endpoint
                .strip_prefix("challenge/")
                .is_some_and(|rest| {
                    rest.split_once('/')
                        .is_some_and(|(a, k)| !a.is_empty() && !k.is_empty() && !k.contains('/'))
                })
            || view
                .endpoint
                .strip_prefix("order/")
                .is_some_and(|rest| match rest.split_once('/') {
                    None => !rest.is_empty(),
                    Some((id, action)) => !id.is_empty() && matches!(action, "finalize" | "cert"),
                })
            || view
                .endpoint
                .strip_prefix("authorization/")
                .is_some_and(|id| !id.is_empty() && !id.contains('/'))
        {
            if request.method != "POST" {
                Response::error(405, "unsupported operation")
            } else {
                self.acme_signed_account(request, admitted, &view, &mut authority)
            }
        } else if view
            .endpoint
            .strip_prefix("account/")
            .is_some_and(|rest| rest.ends_with("/orders"))
        {
            // The official descriptor's account/<uuid>/orders alias is not an
            // unauthenticated ACME route; the actual signed list route is orders.
            Response::error(403, "permission denied")
        } else if matches!(view.endpoint.as_str(), "directory" | "new-nonce") {
            Response::error(405, "unsupported operation")
        } else {
            problem(
                501,
                "serverInternal",
                "ACME order, challenge and certificate operation is not implemented",
            )
        };
        if self.pending_acme_external.is_some() {
            return Some(response);
        }
        let Some(mut authority) = authority else {
            return Some(Response::error(
                503,
                "ACME original response authority was lost",
            ));
        };
        let mut issued_nonce = None;
        // The genuine wrapper adds nonce metadata only after a successful
        // handler. Problems consume the submitted nonce without a replacement.
        if view.enabled
            && response.status < 400
            && (view.endpoint == "new-nonce" && matches!(request.method, "GET" | "HEAD")
                || request.method == "POST"
                    && (view.endpoint == "new-account"
                        || view.endpoint.starts_with("account/")
                        || view.endpoint == "new-order"
                        || view.endpoint == "orders"
                        || view.endpoint == "revoke-cert"
                        || view.endpoint.starts_with("order/")
                        || view.endpoint.starts_with("authorization/")
                        || view.endpoint.starts_with("challenge/")))
        {
            let at = match request.token_time().and_then(|time| {
                time.exact()
                    .or_else(|| Timestamp::whole(time.seconds()).ok())
                    .ok_or_else(|| Response::error(503, "ACME original clock unavailable"))
            }) {
                Ok(at) => at,
                Err(error) => return Some(error),
            };
            match admitted
                .engines
                .acme_activate_nonce_owner(&view.owner, at)
                .map_err(Response::from_engine_error)
                .and_then(|at| self.acme_nonces.mint(&view.owner, &self.unseal_nonce, at))
            {
                Ok(nonce) => {
                    let headers = json!({"Replay-Nonce":[nonce],"Link":[format!("<{}directory>;rel=\"index\"",view.base)]});
                    if response
                        .response_headers
                        .append_from_sdk(Some(&headers), &view.headers)
                        .is_err()
                    {
                        return Some(Response::error(503, "ACME response metadata rejected"));
                    }
                    issued_nonce = headers["Replay-Nonce"][0].as_str().map(str::to_owned);
                }
                Err(error) => return Some(error),
            }
        }
        // The admitted capsule exists before parsing or effects. The final
        // root Publish checks its original time, rather than creating authority
        // from a state that has already committed.
        if let Err(error) = authority.check(self) {
            return Some(error);
        }
        match self.current_state_identity() {
            Ok(current) if current == identity => {}
            _ => {
                return Some(Response::error(
                    503,
                    "ACME transaction changed before publication",
                ));
            }
        }
        authority.nonce_deadline = issued_nonce
            .as_ref()
            .and_then(|nonce| self.acme_nonces.0.get(nonce))
            .map(|grant| (grant.expires, grant.monotonic));
        authority.nonce = issued_nonce;
        if admitted.engines.has_pki_acme_state() {
            admitted.schema = admitted.writer_schema();
            if admitted.engines.record_root().is_none() {
                if self.record_root.is_some() {
                    return Some(Response::error(
                        503,
                        "ACME cannot downgrade an authenticated record root",
                    ));
                }
                let key = match crypto::random::<32>() {
                    Ok(key) => key,
                    Err(error) => return Some(Response::error(503, error)),
                };
                admitted.engines = match admitted
                    .engines
                    .migrate_kv1_records(crate::state_records::AddressKey::from_bytes(key))
                {
                    Ok(engines) => engines.into(),
                    Err(error) => return Some(Response::from_engine_error(error)),
                };
            }
            let plan = match self.prepare_record_plan(admitted) {
                Ok(plan) => plan,
                Err(error) => return Some(error),
            };
            if let Err(error) = authority.bind_candidate(admitted) {
                return Some(error);
            }
            if let Err(error) = self.commit_record_plan_with_before_publish(
                admitted,
                plan,
                |_| authority.check_state(admitted),
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            ) {
                return Some(error);
            }
            *admitted = self.install_committed_namespace_view(admitted.clone());
        } else if let Err(error) = authority.bind_candidate(admitted) {
            return Some(error);
        }
        self.pending_acme_authority = Some(authority);
        Some(response)
    }
    fn acme_signed_account(
        &mut self,
        request: &RequestView<'_>,
        admitted: &mut State,
        view: &AcmeView,
        authority: &mut Option<Authority>,
    ) -> Response {
        let parsed = match AcmeParsedJws::parse(request.body) {
            Ok(parsed) => parsed,
            Err(error) => return engine_problem(error),
        };
        let key = match (&parsed.embedded_key, &parsed.kid) {
            (Some(key), None) => key.clone(),
            (None, Some(kid)) => match admitted.engines.acme_account_key(view, kid) {
                Ok(key) => key,
                Err(error) => return engine_problem(error),
            },
            _ => return problem(400, "malformed", "invalid ACME account key"),
        };
        let at = match request.token_time() {
            Ok(time) => match time
                .exact()
                .or_else(|| Timestamp::whole(time.seconds()).ok())
            {
                Some(at) => at,
                None => return Response::error(503, "ACME original clock unavailable"),
            },
            Err(error) => return error,
        };
        let at = admitted.engines.acme_observed_time(at);
        if !self
            .acme_nonces
            .redeem(&parsed.nonce, &view.owner, &self.unseal_nonce, at)
        {
            return problem(
                400,
                "badNonce",
                "invalid or reused nonce: the client sent an unacceptable anti-replay nonce",
            );
        }
        if parsed.url != format!("{}{}", view.base, view.endpoint) {
            return problem(
                401,
                "unauthorized",
                &format!(
                    "invalid value for 'url' in 'protected': got '{}' expected '{}{}': the client lacks sufficient authorization",
                    parsed.url, view.base, view.endpoint
                ),
            );
        }
        let kid = parsed.kid.clone();
        let verified = match parsed.verify(&key) {
            Ok(verified) => verified,
            Err(error) => return engine_problem(error),
        };
        if let Err(error) = namespace_runtime::request_live() {
            return error;
        }
        match admitted.engines.prepare_acme_external_finalize(
            view,
            &verified,
            kid.as_deref(),
            at,
            request.token_clock,
        ) {
            Ok(Some(plan)) => return self.stage_acme_external(admitted, view, authority, plan),
            Ok(None) => {}
            Err(error) => return engine_problem(error),
        }
        let result = if view.endpoint == "new-account" || view.endpoint.starts_with("account/") {
            admitted
                .engines
                .acme_account_request(view, key, &verified, kid.as_deref(), at)
                .map(|(status, body, location)| (status, body, Some(location)))
        } else if view.endpoint == "revoke-cert" {
            admitted.engines.acme_revoke_request(
                view,
                crate::engines::AcmeRevocationRequest {
                    key: &key,
                    proof: &verified,
                    kid: kid.as_deref(),
                    at,
                    clock: request.token_clock,
                },
                || {
                    namespace_runtime::request_live().map_err(|_| crate::engines::EngineError {
                        status: 503,
                        message: "ACME revocation original request expired".into(),
                    })
                },
            )
        } else {
            admitted.engines.acme_order_request(
                view,
                &verified,
                kid.as_deref(),
                at,
                request.token_clock,
            )
        };
        match result {
            Ok((status, body, location)) => {
                let mut metadata = json!({});
                if let Some(location) = location {
                    metadata["Location"] = json!([location]);
                }
                if let Some((auth, _)) = view
                    .endpoint
                    .strip_prefix("challenge/")
                    .and_then(|rest| rest.split_once('/'))
                {
                    metadata["Link"] =
                        json!([format!("<{}authorization/{auth}>;rel=\"up\"", view.base)]);
                }
                let headers = Some(metadata);
                match ResponseHeaders::from_sdk(headers.as_ref(), &view.headers) {
                    Ok(headers)
                        if view.endpoint.starts_with("order/")
                            && view.endpoint.ends_with("/cert") =>
                    {
                        if status != 200 || !body.is_string() {
                            return Response::error(503, "ACME certificate response rejected");
                        }
                        Response {
                            status,
                            body: json!({"__heptabao_acme":body,"media":"certificate"}),
                            response_headers: headers,
                            consistency_index: None,
                        }
                    }
                    Ok(headers) => wire(status, Some(body), false, headers),
                    Err(()) => Response::error(503, "ACME account response metadata rejected"),
                }
            }
            Err(error) => engine_problem(error),
        }
    }
    pub(super) fn decorate_acme_external_success(
        &mut self,
        authority: &mut Authority,
        state: &mut State,
        view: &AcmeView,
        response: &mut Response,
    ) -> Result<(), Response> {
        let at = authority.observed_at()?;
        let at = state
            .engines
            .acme_activate_nonce_owner(&view.owner, at)
            .map_err(Response::from_engine_error)?;
        let nonce = self.acme_nonces.mint(&view.owner, &self.unseal_nonce, at)?;
        let headers = json!({"Replay-Nonce":[nonce],"Link":[format!("<{}directory>;rel=\"index\"",view.base)]});
        response
            .response_headers
            .append_from_sdk(Some(&headers), &view.headers)
            .map_err(|_| Response::error(503, "ACME external response metadata rejected"))?;
        authority.nonce_deadline = self
            .acme_nonces
            .0
            .get(&nonce)
            .map(|grant| (grant.expires, grant.monotonic));
        authority.nonce = Some(nonce);
        Ok(())
    }
    pub(super) fn complete_pending_acme_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let authority = match (expected, self.pending_acme_authority.take()) {
            (true, Some(authority)) => authority,
            (false, None) => return response,
            _ => {
                erase_json(&mut response.body);
                response.response_headers.clear();
                return Response::error(503, "ACME response authority was lost");
            }
        };
        if let Err(error) = authority.check(self) {
            erase_json(&mut response.body);
            response.response_headers.clear();
            response.consistency_index = None;
            if let Some(nonce) = authority.nonce.as_ref() {
                self.acme_nonces.0.remove(nonce);
            }
            if self
                .audit_event(
                    "acme-delivery-veto",
                    fingerprint,
                    authority.at,
                    Some(error.status),
                )
                .is_err()
            {
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "ACME response veto audit failed");
            }
            return error;
        }
        response
    }
}

#[cfg(test)]
#[path = "service_pki_acme_tests.rs"]
mod tests;

/// Durable queue identity is public protocol state, never a Caller or Principal.
#[derive(Clone)]
pub(crate) struct QueuedChallenge {
    pub owner: AcmeBinding,
    pub account: String,
    pub thumbprint: String,
    pub directory: String,
    pub authorization: String,
    pub host: String,
    pub challenge: crate::engines::AcmeChallenge,
    pub mount_revision: u64,
    pub dns_resolver: String,
}
pub(super) struct ChallengeAttempt {
    queued: QueuedChallenge,
    clock: RequestClock,
    attempt_started: Timestamp,
    deadline: std::time::Instant,
    activation: String,
    delivery: namespace_runtime::DeliveryBinding,
}
impl ChallengeAttempt {
    fn observed(&self) -> Result<Timestamp, Response> {
        if std::time::Instant::now() >= self.deadline {
            return Err(Response::error(
                503,
                "ACME background attempt deadline expired",
            ));
        }
        self.clock
            .observed_at()
            .map_err(|_| Response::error(503, "ACME background original clock unavailable"))
    }
    fn check_state(&self, state: &State, original: bool) -> Result<(), Response> {
        self.observed()?;
        state.namespace_leases.validate()?;
        if state.cluster_id != self.queued.owner.cluster_id
            || !state.namespace_exists(&self.queued.owner.namespace)
            || state.namespace_is_sealed(&self.queued.owner.namespace)
            || state.namespaces.incarnation(&self.queued.owner.namespace)
                != self.queued.owner.namespace_incarnation
            || namespace_runtime::DeliveryBinding::capture(state, &self.queued.owner.namespace)
                != self.delivery
        {
            return Err(Response::error(
                503,
                "ACME background namespace owner changed",
            ));
        }
        let path = format!(
            "{}{}challenge/{}/{}",
            self.queued.owner.mount,
            self.queued.directory,
            self.queued.authorization,
            self.queued.challenge.kind
        );
        let view = state
            .engines
            .acme_view(
                &self.queued.owner.namespace,
                &path,
                &state.cluster_id,
                state.namespaces.incarnation(&self.queued.owner.namespace),
            )
            .map_err(Response::from_engine_error)?
            .ok_or_else(|| Response::error(503, "ACME background mount unavailable"))?;
        if view.owner != self.queued.owner
            || view.revision != self.queued.mount_revision
            || !view.enabled
        {
            return Err(Response::error(503, "ACME background mount owner changed"));
        }
        state
            .engines
            .acme_directory_gate(&view)
            .map_err(Response::from_engine_error)?;
        state
            .engines
            .check_acme_challenge_state(&self.queued, original)
            .map_err(Response::from_engine_error)?;
        Ok(())
    }
    fn check(&self, service: &Service) -> Result<(), Response> {
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.activation
        {
            return Err(Response::error(503, "ACME background activation changed"));
        }
        self.check_state(
            service
                .state
                .as_ref()
                .ok_or_else(|| Response::error(503, "ACME background state unavailable"))?,
            true,
        )
    }
    pub(super) fn execute(&self, service: &Arc<Mutex<Service>>) -> Result<(), String> {
        {
            let writer = crate::request_deadline::lock_until(service, self.deadline)
                .map_err(|_| "ACME background writer unavailable".to_owned())?;
            self.check(&writer)
                .map_err(|_| "ACME background owner changed before network proof".to_owned())?;
        }
        self.execute_port(80)
    }
    fn execute_port(&self, port: u16) -> Result<(), String> {
        self.observed()
            .map_err(|_| "ACME background attempt deadline expired".to_owned())?;
        if self.queued.challenge.kind == "dns-01" {
            return crate::outbound::verify_dns01(
                &self.queued.host,
                &self.queued.challenge.token,
                &self.queued.thumbprint,
                &self.queued.dns_resolver,
                self.deadline
                    .min(std::time::Instant::now() + Duration::from_secs(30)),
            );
        }
        if self.queued.challenge.kind == "tls-alpn-01" && self.queued.dns_resolver.is_empty() {
            return crate::outbound::verify_tlsalpn01(
                &self.queued.host,
                &self.queued.challenge.token,
                &self.queued.thumbprint,
                self.deadline
                    .min(std::time::Instant::now() + Duration::from_secs(30)),
            );
        }
        if !self.queued.dns_resolver.is_empty() {
            return Err("ACME explicit DNS resolver transport is not implemented".into());
        }
        crate::outbound::verify_http01(
            &self.queued.host,
            port,
            &self.queued.challenge.token,
            &self.queued.thumbprint,
            self.deadline
                .min(std::time::Instant::now() + Duration::from_secs(10)),
        )
    }
}
impl Service {
    pub(super) fn prepare_acme_maintenance(
        &mut self,
        clock: RequestClock,
    ) -> Result<Option<ChallengeAttempt>, Response> {
        let deadline = clock
            .started()
            .checked_add(Duration::from_secs(60))
            .ok_or_else(|| Response::error(503, "ACME host attempt deadline overflow"))?;
        if std::time::Instant::now() >= deadline {
            return Err(Response::error(503, "ACME host attempt deadline expired"));
        }
        let _read_scope = crate::request_deadline::RequestDeadlineScope::enter(
            deadline.min(clock.started() + crate::request_deadline::IDLE_MAINTENANCE_READ_BUDGET),
        );
        if self.recovery_required || self.audit_failed || self.state.is_none() {
            return Ok(None);
        }
        if let Some(ha) = &self.ha {
            let ha = ha
                .lock_for_request()
                .map_err(|_| Response::error(503, "ACME maintenance HA unavailable"))?;
            if ha
                .leader()
                .map_err(|_| Response::error(503, "ACME maintenance leader unavailable"))?
                != Some(
                    ha.local_id().map_err(|_| {
                        Response::error(503, "ACME maintenance identity unavailable")
                    })?,
                )
            {
                return Ok(None);
            }
            drop(ha);
            self.sync_from_ha_with_anchor(false)?;
        }
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "ACME background state unavailable"))?;
        let at = state.engines.acme_observed_time(
            clock
                .observed_at()
                .map_err(|_| Response::error(503, "ACME host clock unavailable"))?,
        );
        let Some(queued) = state.engines.next_acme_challenge(at) else {
            return Ok(None);
        };
        let plan = ChallengeAttempt {
            attempt_started: at,
            clock: clock
                .with_seconds_floor(at.seconds())
                .map_err(|_| Response::error(503, "ACME host clock floor unavailable"))?,
            deadline,
            activation: self.unseal_nonce.clone(),
            delivery: namespace_runtime::DeliveryBinding::capture(state, &queued.owner.namespace),
            queued,
        };
        plan.check(self)?;
        let fingerprint = self.request_fingerprint(
            "INTERNAL",
            "pki/acme/challenge-validation",
            &plan.queued.owner.namespace,
            "",
        );
        if self
            .audit_event("acme-validation-request", &fingerprint, at.seconds(), None)
            .is_err()
        {
            self.recovery_required = true;
            self.ha_activation = None;
            return Err(Response::error(
                503,
                "ACME background request audit unavailable",
            ));
        }
        Ok(Some(plan))
    }
    pub(super) fn finish_acme_maintenance(
        &mut self,
        plan: ChallengeAttempt,
        result: Result<(), String>,
    ) -> Result<(), Response> {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        if self.ha.is_some() {
            self.sync_from_ha_with_anchor(false)?;
        }
        plan.check(self)?;
        let at = plan.observed()?;
        let mut next = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "ACME background state unavailable"))?
            .clone();
        let id = format!(
            "{}-{}",
            plan.queued.authorization, plan.queued.challenge.kind
        );
        let result = result.map_err(|detail| {
            if plan.queued.challenge.kind == "tls-alpn-01" {
                return format!("response received didn't match the challenge's requirements: error validating tls-alpn-01 challenge {id}: {detail}");
            }
            format!(
                "response received didn't match the challenge's requirements: error validating {} challenge {id}: {detail}; this may occur if the validation target was misconfigured: check that challenge responses are available at the required locations and retry.", plan.queued.challenge.kind
            )
        });
        next.engines
            .finish_acme_challenge(&plan.queued, result, at, plan.attempt_started)
            .map_err(Response::from_engine_error)?;
        next.schema = next.writer_schema();
        let record = self.prepare_record_plan(&mut next)?;
        plan.check(self)?;
        plan.check_state(&next, false)?;
        self.commit_record_plan_with_before_publish(
            &next,
            record,
            |_| plan.check_state(&next, false),
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        )?;
        self.state = Some(self.install_committed_namespace_view(next));
        let fingerprint = self.request_fingerprint(
            "INTERNAL",
            "pki/acme/challenge-validation",
            &plan.queued.owner.namespace,
            "",
        );
        if self
            .audit_event(
                "acme-validation-response",
                &fingerprint,
                at.seconds(),
                Some(204),
            )
            .is_err()
        {
            self.recovery_required = true;
            self.ha_activation = None;
            return Err(Response::error(
                503,
                "ACME background result audit unavailable",
            ));
        }
        plan.observed()?;
        Ok(())
    }
}
