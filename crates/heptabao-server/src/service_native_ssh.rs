//! Root-local SSH requests retain their source, original clock, actual
//! authenticated identity, one domain execution and exact published reply.
//! NativeAuthDelivery owns the source proof, terminal observation and audit.
//! Shared local lease maintenance remains independently admitted.
use super::*;

fn unavailable() -> Response {
    Response::error(503, "native local SSH publication or delivery unavailable")
}
fn owner_digest<T: serde::Serialize>(owner: &T) -> Result<[u8; 32], Response> {
    let bytes = owner_store::serialize_owner(owner).map_err(|_| unavailable())?;
    Ok(crypto::digest(&bytes))
}
fn unchanged_state_owners(
    source: &State,
    candidate: &State,
    allow_auth: bool,
) -> Result<(), Response> {
    if candidate.cluster_id != source.cluster_id
        || candidate.replay_epoch != source.replay_epoch
        || candidate.global_lossless_json_format != source.global_lossless_json_format
        || candidate.namespace_protected.is_some()
        || !candidate.namespace_leases.is_empty()
        || owner_digest(&candidate.namespaces)? != owner_digest(&source.namespaces)?
        || owner_digest(&candidate.database)? != owner_digest(&source.database)?
        || owner_digest(&candidate.raft_admin)? != owner_digest(&source.raft_admin)?
        || !allow_auth && owner_digest(&candidate.auth)? != owner_digest(&source.auth)?
    {
        return Err(unavailable());
    }
    Ok(())
}

pub(super) struct NativeSshOwner {
    source: State,
    method: String,
    path: String,
    body: Value,
    public: bool,
    public_key: bool,
    verify: bool,
    verified: bool,
    executed: bool,
    verify_target: Option<(crate::auth::LeaseOwner, String, u64)>,
    public_reply: Option<crate::auth::NativeSshPublicReplyOwner>,
    help: bool,
    capability: &'static str,
    sudo: bool,
    issuer: Option<crate::auth::ResolvedLeaseOwner>,
    issued_expires: Option<u64>,
    deadline: OriginalDeadline,
    engine: crate::engines::NativeSshEngineOwner,
    reply: Option<[u8; 32]>,
}
impl Drop for NativeSshOwner {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}
impl NativeSshOwner {
    pub(super) fn prepare(
        source: &State,
        root: &RecordStateRootV6,
        actor: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Result<Self, Response> {
        if !request.namespace.is_empty() || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Err(Response::error(
                501,
                "native local SSH requires an unwrapped root request",
            ));
        }
        let mounted = source.engines.native_local_ssh_route("", request.path);
        let registry =
            source
                .engines
                .native_ssh_registry_route(request.method, request.path, request.body);
        if !mounted && !registry {
            return Err(unavailable());
        }
        let help = mounted && request.method == "HELP";
        let public_key = source
            .engines
            .is_public_ssh_key_read("", request.method, request.path);
        let verify = source
            .engines
            .is_ssh_verification("", request.method, request.path);
        let public = public_key
            || verify
            || help
                && source
                    .engines
                    .help_projection("", request.path)
                    .map_err(Response::from_engine_error)?
                    .is_some_and(|help| help.anonymous);
        if !public && actor.is_none() {
            return Err(Response::error(403, "missing client token"));
        }
        let method = kv_authorization_method(request.method, request.body);
        let lease = source.engines.is_ssh_service_route("", request.path);
        let capability = if lease {
            if method == "LIST" { "list" } else { "update" }
        } else if registry {
            match method {
                "GET" | "HEAD" => "read",
                "LIST" => "list",
                "DELETE" => "delete",
                _ => "update",
            }
        } else {
            source
                .engines
                .required_capability("", method, request.path)
                .ok_or_else(unavailable)?
        };
        let sudo = registry && !matches!(request.method, "GET" | "LIST" | "HEAD");
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let time = request.token_time()?;
        let issuer = if lease && !verify {
            Some(
                source
                    .auth
                    .typed_lease_issuer_observed(actor.ok_or_else(unavailable)?, "", time)
                    .map_err(|e| Response::error(e.status, &e.message))?,
            )
        } else {
            None
        };
        let owner = Self {
            source: source.clone(),
            method: request.method.to_owned(),
            path: request.path.to_owned(),
            body: request.body.clone(),
            public,
            public_key,
            verify,
            verified: false,
            executed: false,
            verify_target: if verify {
                request
                    .body
                    .get("otp")
                    .and_then(Value::as_str)
                    .and_then(|raw| {
                        source
                            .engines
                            .native_ssh_otp_lease(request.path, raw, false)
                    })
            } else {
                None
            },
            public_reply: None,
            help,
            capability,
            sudo,
            issuer,
            issued_expires: None,
            deadline,
            engine: source
                .engines
                .capture_native_ssh_engine_owner(
                    request.method,
                    request.path,
                    request.body,
                    public,
                    root,
                    &|| deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)?,
            reply: None,
        };
        owner.authorize(&source.auth, actor, time)?;
        Ok(owner)
    }
    pub(super) fn public(&self) -> bool {
        self.public
    }
    pub(super) fn read_only(&self) -> bool {
        self.engine.read_only()
    }
    pub(super) fn authorization_method(&self) -> &str {
        kv_authorization_method(&self.method, &self.body)
    }
    pub(super) fn authorize(
        &self,
        auth: &AuthState,
        actor: Option<&Principal>,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        if self.verified {
            let (owner, _, expires) = self.verify_target.as_ref().ok_or_else(unavailable)?;
            if time.seconds() >= *expires
                || auth.resolve_lease_owner_observed(owner, "", time).is_none()
            {
                return Err(Response::error(
                    403,
                    "original SSH OTP issuer or lease is no longer live",
                ));
            }
        }
        if self.public {
            return Ok(());
        }
        let actor = actor.ok_or_else(unavailable)?;
        auth.authorize_request_parameters_observed(
            actor,
            "",
            self.authorization_method(),
            &self.path,
            &self.body,
            time,
        )
        .and_then(|()| {
            auth.authorize_request_observed(actor, "", &self.path, self.capability, time)
        })
        .and_then(|()| {
            if self.sudo {
                auth.authorize_request_observed(actor, "", &self.path, "sudo", time)
            } else {
                Ok(())
            }
        })
        .map_err(|e| Response::error(e.status, &e.message))?;
        if let Some(original) = self.issuer.as_ref() {
            let current = auth
                .typed_lease_issuer_observed(actor, "", time)
                .map_err(|e| Response::error(e.status, &e.message))?;
            if !original.owner.same_credential(&current.owner)
                || original
                    .precise_expires_at
                    .is_some_and(|end| time.exact().is_none_or(|at| at > end))
                || original.precise_expires_at.is_none()
                    && original.expires_at.is_some_and(|end| time.seconds() >= end)
                || self.issued_expires.is_some_and(|end| time.seconds() >= end)
            {
                return Err(Response::error(
                    403,
                    "original SSH issuer or OTP is no longer live",
                ));
            }
        }
        self.deadline.check().map_err(|_| unavailable())
    }
    pub(super) fn authorize_current(
        &self,
        state: &State,
        actor: Option<&mut Principal>,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        if self.public {
            self.authorize(&state.auth, None, time)?;
            if self.verified {
                let (owner, _, _) = self.verify_target.as_ref().ok_or_else(unavailable)?;
                let current = state
                    .auth
                    .resolve_lease_owner_observed(owner, "", time)
                    .ok_or_else(unavailable)?;
                if let Some(id) = current.entity_id.as_deref() {
                    let identity = state
                        .engines
                        .identity_projection("", id)
                        .map_err(Response::from_engine_error)?;
                    if identity.disabled {
                        return Err(Response::error(
                            403,
                            "original SSH OTP identity is disabled",
                        ));
                    }
                }
            }
            return Ok(());
        }
        let actor = actor.ok_or_else(unavailable)?;
        let result = Service::bind_identity_principal(state, actor, "")
            .and_then(|()| self.authorize(&state.auth, Some(actor), time));
        Service::bind_identity_principal(&self.source, actor, "")?;
        result
    }
    pub(super) fn check_source(&self, engines: &EngineState) -> Result<(), Response> {
        self.engine
            .check_source(engines, &|| self.deadline.check().is_ok())
            .map_err(Response::from_engine_error)
    }
    pub(super) fn execute(
        &mut self,
        candidate: &mut State,
        actor: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let result = (|| -> Result<Response, Response> {
            if self.executed || self.reply.is_some() {
                return Err(unavailable());
            }
            self.check_source(&candidate.engines)?;
            unchanged_state_owners(&self.source, candidate, false)?;
            if request.method != self.method
                || request.path != self.path
                || request.body != &self.body
            {
                return Err(unavailable());
            }
            self.authorize(&candidate.auth, actor, request.token_time()?)?;
            self.executed = true;
            let mut consumption = None;
            let mut response = if self.help {
                if crate::http::help::request(&self.method, &self.path, &self.body).is_none() {
                    return Err(unavailable());
                }
                let help = candidate
                    .engines
                    .help_projection("", &self.path)
                    .map_err(Response::from_engine_error)?
                    .filter(|help| help.anonymous)
                    .ok_or_else(unavailable)?;
                Response {
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    status: 200,
                    body: help.body,
                }
            } else {
                // Preserve the actual principal, identity-template inputs and
                // original domain operation. No response or signature is predicted.
                Service::dispatch_native_authorized_subrequest(
                    candidate,
                    actor,
                    "",
                    &self.method,
                    &self.path,
                    &self.body,
                    None,
                    None,
                    request.now,
                    request.token_clock,
                    request.client_certificates,
                    request.origin_peer,
                    &mut consumption,
                    None,
                )
            };
            let checked = (|| -> Result<(), Response> {
                if consumption.is_some() {
                    return Err(unavailable());
                }
                unchanged_state_owners(&self.source, candidate, false)?;
                self.engine
                    .bind_executed(&candidate.engines, &|| self.deadline.check().is_ok())
                    .map_err(Response::from_engine_error)?;
                if response.status == 200 && self.issuer.is_some() {
                    let raw = response.body["data"]["key"]
                        .as_str()
                        .ok_or_else(unavailable)?;
                    let (owner, id, expires) = candidate
                        .engines
                        .native_ssh_otp_lease(&self.path, raw, false)
                        .ok_or_else(unavailable)?;
                    if response.body["lease_id"].as_str() != Some(id.as_str())
                        || !owner
                            .same_credential(&self.issuer.as_ref().ok_or_else(unavailable)?.owner)
                    {
                        return Err(unavailable());
                    }
                    self.issued_expires = Some(expires);
                    self.authorize(&candidate.auth, actor, request.token_time()?)?;
                }
                if response.status == 200 && self.verify {
                    let raw = self.body["otp"].as_str().ok_or_else(unavailable)?;
                    let actual = candidate
                        .engines
                        .native_ssh_otp_lease(&self.path, raw, true)
                        .ok_or_else(unavailable)?;
                    let expected = self.verify_target.as_ref().ok_or_else(unavailable)?;
                    if !actual.0.same_credential(&expected.0)
                        || actual.1 != expected.1
                        || actual.2 != expected.2
                    {
                        return Err(unavailable());
                    }
                    self.verified = true;
                    self.authorize(&candidate.auth, None, request.token_time()?)?;
                }
                if response.status == 200 && self.public_key {
                    let raw = response.unwrapped_json.as_mut().ok_or_else(unavailable)?;
                    self.public_reply = Some(
                        raw.bind_native_ssh_public_reply(&response.body, self.deadline)
                            .map_err(|error| Response::error(error.status, &error.message))?,
                    );
                } else if response.unwrapped_json.is_some() {
                    return Err(unavailable());
                }
                self.reply = Some(transit_reply_digest(
                    response.status,
                    &response.body,
                    self.deadline,
                )?);
                Ok(())
            })();
            if let Err(error) = checked {
                erase_json(&mut response.body);
                return Err(error);
            }
            Ok(response)
        })();
        result.unwrap_or_else(|error| error)
    }
    pub(super) fn admit_candidate(&self, candidate: &State) -> Result<(), Response> {
        if self.reply.is_none() {
            return Err(unavailable());
        }
        unchanged_state_owners(&self.source, candidate, false)?;
        self.engine
            .admit_candidate(&candidate.engines, &|| self.deadline.check().is_ok())
            .map_err(Response::from_engine_error)
    }
    pub(super) fn admit_root(
        &mut self,
        prior: &RecordStateRootV6,
        candidate: &State,
        root: &RecordStateRootV6,
    ) -> Result<(), Response> {
        self.admit_candidate(candidate)?;
        self.engine
            .admit_root(prior, root, &|| self.deadline.check().is_ok())
            .map_err(Response::from_engine_error)
    }
    pub(super) fn disabled_mount(&self) -> Option<(&str, &str)> {
        self.engine.disabled_mount()
    }

    pub(super) fn admit_root_with_quota_retirement(
        &mut self,
        prior: &RecordStateRootV6,
        candidate: &State,
        root: &RecordStateRootV6,
        retirement: crate::auth::rate_limit_quotas::MountRetirement,
    ) -> Result<(), Response> {
        if self.reply.is_none() || self.engine.disabled_mount().is_none() {
            return Err(unavailable());
        }
        retirement
            .check_auth_candidates(&self.source.auth, &candidate.auth, &|| {
                self.deadline.check().is_ok()
            })
            .map_err(|error| Response::error(error.status, &error.message))?;
        unchanged_state_owners(&self.source, candidate, true)?;
        self.engine
            .admit_candidate(&candidate.engines, &|| self.deadline.check().is_ok())
            .map_err(Response::from_engine_error)?;
        self.engine
            .admit_root_with_quota_retirement(prior, root, retirement, &|| {
                self.deadline.check().is_ok()
            })
            .map_err(Response::from_engine_error)
    }

    pub(super) fn check_installed(
        &self,
        state: &State,
        root: &RecordStateRootV6,
    ) -> Result<(), Response> {
        self.engine
            .check_installed(&state.engines, root, &|| self.deadline.check().is_ok())
            .map_err(Response::from_engine_error)
    }
    pub(super) fn bind_terminal(
        &mut self,
        state: &State,
        root: &RecordStateRootV6,
        written: bool,
    ) -> Result<(), Response> {
        self.engine
            .bind_terminal(&state.engines, root, written, &|| {
                self.deadline.check().is_ok()
            })
            .map_err(Response::from_engine_error)
    }
    pub(super) fn check_reply(&self, response: &Response) -> Result<(), Response> {
        if self.reply
            != Some(transit_reply_digest(
                response.status,
                &response.body,
                self.deadline,
            )?)
            || !response.response_headers.is_empty()
        {
            return Err(unavailable());
        }
        match (&self.public_reply, &response.unwrapped_json) {
            (Some(owner), Some(raw)) if response.status == 200 && self.public_key => {
                owner
                    .check(raw, &response.body)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            (None, None) => {}
            _ => return Err(unavailable()),
        }
        Ok(())
    }
}

impl Service {
    pub(in crate::service) fn dispatch_native_ssh_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let owner = match (self.state.as_ref(), self.native_root.as_ref()) {
            (Some(source), Some(root)) => {
                NativeSshOwner::prepare(source, root, principal.as_ref(), request)
            }
            _ => Err(unavailable()),
        };
        match owner {
            Ok(owner) => self.dispatch_native_owner_request(
                candidate,
                principal,
                request,
                None,
                NativeLocalOwner::Ssh(Box::new(owner)),
            ),
            Err(error) => error,
        }
    }
}
