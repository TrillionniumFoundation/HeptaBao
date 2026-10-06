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
    fn capture(
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
        }
    }
    fn observed_at(&self) -> Result<Timestamp, Response> {
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
    fn check_state(&self, state: &State) -> Result<(), Response> {
        if self
            .deadline
            .is_some_and(|at| std::time::Instant::now() >= at)
        {
            return Err(Response::error(
                503,
                "ACME original publication deadline expired",
            ));
        }
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
    fn bind_candidate(&mut self, state: &State) -> Result<(), Response> {
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
    fn check(&self, service: &mut Service) -> Result<(), Response> {
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

fn wire(status: u16, body: Option<Value>, problem: bool, headers: ResponseHeaders) -> Response {
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
    } else if error.status == 401 {
        "unauthorized"
    } else if error.message.contains("binding is required") {
        "externalAccountRequired"
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
        let mut authority = Authority::capture(admitted, &view, request, &self.unseal_nonce, None);
        let mut response = if !view.enabled {
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
        {
            if request.method != "POST" {
                Response::error(405, "unsupported operation")
            } else {
                self.acme_signed_account(request, admitted, &view)
            }
        } else if matches!(view.endpoint.as_str(), "directory" | "new-nonce") {
            Response::error(405, "unsupported operation")
        } else {
            problem(
                501,
                "serverInternal",
                "ACME order, challenge and certificate operation is not implemented",
            )
        };
        let mut issued_nonce = None;
        // The genuine wrapper adds nonce metadata only after a successful
        // handler. Problems consume the submitted nonce without a replacement.
        if view.enabled
            && response.status < 400
            && (view.endpoint == "new-nonce" && matches!(request.method, "GET" | "HEAD")
                || request.method == "POST"
                    && (view.endpoint == "new-account" || view.endpoint.starts_with("account/")))
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
        match admitted
            .engines
            .acme_account_request(view, key, &verified, kid.as_deref(), at)
        {
            Ok((status, body, location)) => {
                let headers = json!({"Location":[location]});
                match ResponseHeaders::from_sdk(Some(&headers), &view.headers) {
                    Ok(headers) => wire(status, Some(body), false, headers),
                    Err(()) => Response::error(503, "ACME account response metadata rejected"),
                }
            }
            Err(error) => engine_problem(error),
        }
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
