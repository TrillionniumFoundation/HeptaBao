//! A local PKI request and a lease-maintenance pass each retain their actual
//! source, original clock, one domain execution and exact published result.
//! They cannot authorize ACME or an external signer, or re-sign to synthesize
//! an expected candidate. NativeAuthDelivery owns the audit/reply frontier.
use super::*;

fn unavailable() -> Response {
    Response::error(503, "native local PKI publication or delivery unavailable")
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

pub(super) struct NativePkiOwner {
    source: State,
    method: String,
    path: String,
    body: Value,
    public: bool,
    help: bool,
    capability: &'static str,
    sudo: bool,
    issuer: Option<crate::auth::ResolvedLeaseOwner>,
    issued_expires: Option<u64>,
    deadline: OriginalDeadline,
    engine: crate::engines::NativePkiEngineOwner,
    reply: Option<[u8; 32]>,
}
impl Drop for NativePkiOwner {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}
impl NativePkiOwner {
    pub(super) fn prepare(
        source: &State,
        root: &RecordStateRootV6,
        actor: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Result<Self, Response> {
        if !request.namespace.is_empty() || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Err(Response::error(
                501,
                "native local PKI requires an unwrapped root request",
            ));
        }
        let mounted = source.engines.native_local_pki_route("", request.path);
        let registry =
            source
                .engines
                .native_pki_registry_route(request.method, request.path, request.body);
        let leases = source.engines.native_pki_lease_route("", request.path);
        if !mounted && !registry && !leases {
            return Err(unavailable());
        }
        let help = mounted && request.method == "HELP";
        let public = source
            .engines
            .is_public_pki_read("", request.method, request.path)
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
        let lease = leases || source.engines.is_lease_service_route("", request.path);
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
        let sudo = registry && !matches!(request.method, "GET" | "LIST" | "HEAD")
            || request.path.starts_with("sys/leases/lookup/")
            || request.path.starts_with("sys/leases/revoke-prefix/");
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let time = request.token_time()?;
        let issuer = if source.engines.is_pki_issue_route("", request.path) {
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
            help,
            capability,
            sudo,
            issuer,
            issued_expires: None,
            deadline,
            engine: source
                .engines
                .capture_native_pki_engine_owner(
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
                    "original PKI issuer or leaf is no longer live",
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
            return self.authorize(&state.auth, None, time);
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
        role_fields: Option<&crate::http::pki_role_fields::Carrier<'_>>,
    ) -> Response {
        let result = (|| -> Result<Response, Response> {
            if self.reply.is_some() {
                return Err(unavailable());
            }
            self.check_source(&candidate.engines)?;
            unchanged_state_owners(&self.source, candidate, false)?;
            if request.method != self.method
                || request.path != self.path
                || request.body != &self.body
                || role_fields.is_some_and(|carrier| carrier.original != &self.body)
            {
                return Err(unavailable());
            }
            self.authorize(&candidate.auth, actor, request.token_time()?)?;
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
                // The original ACL uses the original Value. Only its real PKI
                // branch restores HTTP numeric spelling from this same carrier.
                Service::dispatch_native_authorized_subrequest(
                    candidate,
                    actor,
                    "",
                    &self.method,
                    &self.path,
                    &self.body,
                    None,
                    role_fields,
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
                if !self.public && !self.help {
                    // Preserve the original Service finalizer in this same
                    // candidate. Lease/prefix revocation can dirty a CRL;
                    // a successful reply cannot defer its signing to a later
                    // request. This is the original maintenance operation,
                    // not a second execution used to predict signed bytes.
                    candidate
                        .engines
                        .maintain_local_pki_crl(request.now)
                        .map_err(Response::from_engine_error)?;
                }
                unchanged_state_owners(&self.source, candidate, false)?;
                self.engine
                    .bind_executed(&candidate.engines, &|| self.deadline.check().is_ok())
                    .map_err(Response::from_engine_error)?;
                if self.issuer.is_some() && response.status == 200 {
                    // no_store legitimately has no persisted IssuedCertificate.
                    // The expiry is taken only from this actual signed reply,
                    // never from a request claim or a synthetic stored lease.
                    self.issued_expires = Some(
                        response.body["data"]["expiration"]
                            .as_u64()
                            .ok_or_else(unavailable)?,
                    );
                    self.authorize(&candidate.auth, actor, request.token_time()?)?;
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
            || response.unwrapped_json.is_some()
            || !response.response_headers.is_empty()
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

/// Maintenance is an actual original operation with no invented Actor. It
/// cannot be deserialized, cloned or used to submit an arbitrary candidate.
struct NativePkiReconciliation {
    source: State,
    root: RecordStateRootV6,
    clock: RequestClock,
    fixed: AuthorityTime,
    deadline: OriginalDeadline,
    engine: crate::engines::NativePkiEngineOwner,
    executed_auth: Option<[u8; 32]>,
}
impl NativePkiReconciliation {
    fn check_source_auth(&self, auth: &AuthState) -> Result<(), Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        let observed = self.clock.observed_at().map_err(|_| unavailable())?;
        if self.fixed.exact().is_none_or(|fixed| observed < fixed)
            || owner_digest(auth)? != owner_digest(&self.source.auth)?
        {
            return Err(unavailable());
        }
        self.deadline.check().map_err(|_| unavailable())
    }
    fn execute(&mut self, candidate: &mut State) -> Result<bool, Response> {
        if self.executed_auth.is_some() {
            return Err(unavailable());
        }
        self.check_source_auth(&candidate.auth)?;
        self.engine
            .check_source(&candidate.engines, &|| self.deadline.check().is_ok())
            .map_err(Response::from_engine_error)?;
        unchanged_state_owners(&self.source, candidate, false)?;
        // This is the sole call that may retire leases or sign new CRL bytes.
        let changed = Service::reconcile_lease_owners_observed(candidate, self.fixed)?;
        if changed {
            let time = candidate
                .engines
                .kubernetes_artifact_time(self.fixed)
                .map_err(Response::from_engine_error)?;
            let time = candidate.auth.token_api_observed_time(time);
            candidate
                .auth
                .advance_control_group_observed(time)
                .map_err(|e| Response::error(e.status, &e.message))?;
            candidate.schema = candidate.writer_schema();
        } else {
            // A no-op result cannot smuggle an unreported owner mutation.
            unchanged_state_owners(&self.source, candidate, false)?;
            self.engine
                .check_source(&candidate.engines, &|| self.deadline.check().is_ok())
                .map_err(Response::from_engine_error)?;
        }
        unchanged_state_owners(&self.source, candidate, true)?;
        self.engine
            .bind_executed(&candidate.engines, &|| self.deadline.check().is_ok())
            .map_err(Response::from_engine_error)?;
        self.executed_auth = Some(owner_digest(&candidate.auth)?);
        self.check_source_auth(&self.source.auth)?;
        Ok(changed)
    }
    fn check_candidate(&self, candidate: &State) -> Result<(), Response> {
        unchanged_state_owners(&self.source, candidate, true)?;
        if self.executed_auth != Some(owner_digest(&candidate.auth)?) {
            return Err(unavailable());
        }
        self.engine
            .admit_candidate(&candidate.engines, &|| self.deadline.check().is_ok())
            .map_err(Response::from_engine_error)
    }
    fn check_published_auth(&self, auth: &AuthState) -> Result<(), Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        let observed = self.clock.observed_at().map_err(|_| unavailable())?;
        if self.fixed.exact().is_none_or(|at| observed < at)
            || self.executed_auth != Some(owner_digest(auth)?)
        {
            return Err(unavailable());
        }
        self.deadline.check().map_err(|_| unavailable())
    }
}

/// Only the actual maintenance pass can construct this affine checkpoint.
/// A continuation to Transit retains the original clock and proves that the
/// complete PKI/Auth result is still installed after the original idle audit.
pub(in crate::service) struct NativePkiIdleCheckpoint {
    owner: NativePkiReconciliation,
    proof: native_v6_reader::NativeProof,
    idle_audit_obligation_satisfied: bool,
}
impl NativePkiIdleCheckpoint {
    fn check(&self, service: &mut Service) -> Result<(), Response> {
        self.proof
            .check_with(service, |installed, metadata, native, root, original| {
                self.owner.check_published_auth(&metadata.auth)?;
                self.owner.check_candidate(installed)?;
                Service::check_native_installed(installed, metadata, native, root, original)?;
                self.owner
                    .engine
                    .check_installed(&installed.engines, root, &|| {
                        self.owner.deadline.check().is_ok()
                    })
                    .map_err(Response::from_engine_error)
            })?;
        self.proof.check_warm(service)?;
        self.owner.deadline.check().map_err(|_| unavailable())
    }
    pub(in crate::service) fn check_for_transit(
        &self,
        service: &mut Service,
    ) -> Result<(u64, RequestClock), Response> {
        if !self.idle_audit_obligation_satisfied {
            return Err(unavailable());
        }
        self.check(service)?;
        // The continuation receives this retained clock, not a caller's
        // replacement clock that happens to share an Instant or a floor.
        Ok((self.owner.fixed.seconds(), self.owner.clock))
    }
}

impl Service {
    pub(in crate::service) fn dispatch_native_pki_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
        role_fields: Option<&crate::http::pki_role_fields::Carrier<'_>>,
    ) -> Response {
        let owner = match (self.state.as_ref(), self.native_root.as_ref()) {
            (Some(source), Some(root)) => {
                NativePkiOwner::prepare(source, root, principal.as_ref(), request)
            }
            _ => Err(unavailable()),
        };
        match owner {
            Ok(owner) => self.dispatch_native_owner_request_with_pki(
                candidate,
                principal,
                request,
                None,
                role_fields,
                NativeLocalOwner::Pki(Box::new(owner)),
            ),
            Err(error) => error,
        }
    }

    pub(in crate::service) fn reconcile_native_pki_owners(
        &mut self,
        admitted: &mut State,
        request: &RequestView<'_>,
    ) -> Result<(), Response> {
        let clock = request.token_clock.ok_or_else(unavailable)?;
        let (_changed, _checkpoint) =
            self.run_native_pki_reconciliation(request.now, clock, request.token_time()?, false)?;
        *admitted = self.state.as_ref().ok_or_else(unavailable)?.clone();
        Ok(())
    }

    pub(in crate::service) fn maintain_native_pki_lifetimes(
        &mut self,
        now: u64,
        clock: Option<RequestClock>,
    ) -> Result<bool, &'static str> {
        // A PKI capsule does not retire a response-wrapping owner. Such a
        // composition must be admitted by that owner's independent capsule.
        if self
            .state
            .as_ref()
            .is_none_or(|state| state.auth.has_live_wrappers())
        {
            return Err("native PKI idle maintenance requires its own unwrapped owner");
        }
        let original_clock = clock.ok_or("native PKI trusted idle clock missing")?;
        let at = original_clock
            .with_seconds_floor(now)
            .and_then(RequestClock::observed_at)
            .map_err(|_| "native PKI original idle clock unavailable")?;
        let (changed, checkpoint) = self
            .run_native_pki_reconciliation(now, original_clock, AuthorityTime::Precise(at), true)
            .map_err(|_| "native PKI idle maintenance unavailable; no success inferred")?;
        // The original Transit operation is still the sole rotation owner.
        // Both passes remain inside the same worker's original deadline.
        let rotated = self.maintain_native_transit_after_pki(checkpoint)?;
        Ok(changed | rotated)
    }

    fn run_native_pki_reconciliation(
        &mut self,
        now: u64,
        original_clock: RequestClock,
        original_time: AuthorityTime,
        idle: bool,
    ) -> Result<(bool, NativePkiIdleCheckpoint), Response> {
        let source = self.state.as_ref().ok_or_else(unavailable)?.clone();
        let root = self.native_root.as_ref().ok_or_else(unavailable)?.clone();
        self.require_native_root_candidate(&source)?;
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let floor = source.engines.lease_clock();
        let clock = original_clock
            .with_seconds_floor(now.max(floor))
            .map_err(|_| unavailable())?;
        let fixed = original_time
            .with_seconds_floor(floor)
            .map_err(|_| unavailable())?;
        let mut owner = NativePkiReconciliation {
            source: source.clone(),
            root: root.clone(),
            clock,
            fixed,
            deadline,
            engine: source
                .engines
                .capture_native_pki_maintenance(&root, &|| deadline.check().is_ok())
                .map_err(Response::from_engine_error)?,
            executed_auth: None,
        };
        owner.check_source_auth(&source.auth)?;
        // Source selection is authenticated before local signer material is
        // opened. Planning later repeats the original native proof gate.
        let proof = self
            .capture_native_request_proof(&mut || owner.check_source_auth(&source.auth))?
            .ok_or_else(unavailable)?;
        proof.check_warm(self)?;
        let mut candidate = source.clone();
        let changed = owner.execute(&mut candidate)?;
        proof.check_warm(self)?;
        owner.check_source_auth(&source.auth)?;
        owner.check_candidate(&candidate)?;
        let fingerprint = self.request_fingerprint("INTERNAL", "lifecycle/expiry", "", "");
        if idle && changed {
            self.audit_event("lifecycle-request", &fingerprint, fixed.seconds(), None)
                .map_err(|_| unavailable())?;
        }
        let published = (|| -> Result<native_v6_reader::NativeProof, Response> {
            if !changed {
                owner
                    .engine
                    .admit_root(&owner.root, &owner.root, &|| deadline.check().is_ok())
                    .map_err(Response::from_engine_error)?;
                return Ok(proof);
            }
            let plan = self.prepare_native_live_root_checked(&candidate, &mut |auth| {
                owner.check_source_auth(auth)
            })?;
            owner.check_candidate(&plan.candidate)?;
            owner
                .engine
                .admit_root(&owner.root, &plan.root, &|| deadline.check().is_ok())
                .map_err(Response::from_engine_error)?;
            let installed = self.commit_native_root_plan(
                &candidate,
                plan,
                false,
                "pki-lease-observation",
                &mut |auth| owner.check_source_auth(auth),
            )?;
            // This capsule only owns the root state, never a protected child
            // namespace view. Install exactly as the other native root owners.
            self.state = Some(installed);
            let installed = self.state.as_ref().ok_or_else(unavailable)?;
            owner
                .engine
                .check_installed(
                    &installed.engines,
                    self.native_root.as_ref().ok_or_else(unavailable)?,
                    &|| deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)?;
            owner.check_candidate(installed)?;
            let installed_auth = installed.auth.clone();
            self.capture_native_request_proof(&mut || owner.check_published_auth(&installed_auth))?
                .ok_or_else(unavailable)
        })();
        if idle
            && changed
            && self
                .audit_event(
                    "lifecycle-response",
                    &fingerprint,
                    fixed.seconds(),
                    Some(if published.is_ok() { 204 } else { 503 }),
                )
                .is_err()
        {
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            return Err(unavailable());
        }
        // The exact pre-audit proof is retained. There is no replacement read
        // witness or re-execution of a random CRL signature after audit.
        // An unchanged pass follows the original idle worker's no-audit rule;
        // this private obligation marker does not assert that an event existed.
        let checkpoint = NativePkiIdleCheckpoint {
            owner,
            proof: published?,
            idle_audit_obligation_satisfied: idle,
        };
        if let Err(error) = checkpoint.check(self) {
            if idle
                && changed
                && self
                    .audit_event(
                        "native-pki-maintenance-veto",
                        &fingerprint,
                        fixed.seconds(),
                        Some(503),
                    )
                    .is_err()
            {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
            }
            return Err(error);
        }
        Ok((changed, checkpoint))
    }
}
