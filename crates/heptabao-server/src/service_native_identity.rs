//! One local namespace-bound Identity operation, retained through native publication and
//! audited delivery. This owner cannot select MFA, OIDC, aliases, merge, foreign
//! namespaces, wrapping, or another engine through a generic Identity prefix.
use super::*;

fn unavailable() -> Response {
    Response::error(503, "native Identity ownership or delivery unavailable")
}

pub(super) fn route(method: &str, path: &str) -> bool {
    if !matches!(
        method,
        "GET" | "HEAD" | "LIST" | "SCAN" | "POST" | "PUT" | "PATCH" | "DELETE"
    ) {
        return false;
    }
    let base = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    matches!(
        base,
        "identity/entity"
            | "identity/entity/id"
            | "identity/entity/name"
            | "identity/group"
            | "identity/group/id"
            | "identity/group/name"
            | "identity/lookup/entity"
            | "identity/lookup/group"
    ) || [
        "identity/entity/id/",
        "identity/entity/name/",
        "identity/group/id/",
        "identity/group/name/",
    ]
    .iter()
    .any(|prefix| {
        base.strip_prefix(prefix)
            .is_some_and(|suffix| !suffix.is_empty())
    })
}

/// Non-cloneable, in-memory authority for exactly the original local request.
/// The source state is a COW view, never a newly serialized plaintext image.
pub(super) struct NativeIdentityOwner {
    scope: namespaces::native_plain::PlainNamespaceScope,
    method: String,
    path: String,
    body: Value,
    capability: &'static str,
    read_only: bool,
    deadline: OriginalDeadline,
    source: State,
    source_root: RecordStateRootV6,
    installed_engines: Option<CowOwner<EngineState>>,
    installed_root: Option<RecordStateRootV6>,
    reply: Option<[u8; 32]>,
    terminal_bound: bool,
}

impl Drop for NativeIdentityOwner {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

impl NativeIdentityOwner {
    fn prepare(
        state: &State,
        root: &RecordStateRootV6,
        actor: &Principal,
        request: &RequestView<'_>,
    ) -> Result<Self, Response> {
        if !route(request.method, request.path)
            || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
        {
            return Err(Response::error(
                501,
                "native Identity requires an unwrapped entity or group request",
            ));
        }
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let capability = state
            .engines
            .required_capability(
                request.namespace,
                kv_authorization_method(request.method, request.body),
                request.path,
            )
            .ok_or_else(unavailable)?;
        let base = request
            .path
            .split('?')
            .next()
            .unwrap_or(request.path)
            .trim_end_matches('/');
        let read_only = matches!(request.method, "GET" | "HEAD" | "LIST" | "SCAN")
            || matches!(base, "identity/lookup/entity" | "identity/lookup/group");
        let owner = Self {
            scope: namespaces::native_plain::PlainNamespaceScope::capture(
                state,
                request.namespace,
            )?,
            method: request.method.to_owned(),
            path: request.path.to_owned(),
            body: request.body.clone(),
            capability,
            read_only,
            deadline,
            source: state.clone(),
            source_root: root.clone(),
            installed_engines: None,
            installed_root: None,
            reply: None,
            terminal_bound: false,
        };
        owner.authorize(&state.auth, actor, request.token_time()?)?;
        owner.check_source(&state.engines)?;
        Ok(owner)
    }

    pub(super) fn read_only(&self) -> bool {
        self.read_only
    }

    pub(super) fn authorization_method(&self) -> &str {
        kv_authorization_method(&self.method, &self.body)
    }

    pub(super) fn authorize(
        &self,
        auth: &AuthState,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        auth.authorize_request_parameters_observed(
            actor,
            self.scope.namespace(),
            self.authorization_method(),
            &self.path,
            &self.body,
            time,
        )
        .and_then(|()| {
            auth.authorize_request_observed(
                actor,
                self.scope.namespace(),
                &self.path,
                self.capability,
                time,
            )
        })
        .map_err(|error| Response::error(error.status, &error.message))
    }

    /// Rebind the same affine Principal only for the current Identity check,
    /// then restore its original source projection before any source gate.
    /// No credential is authenticated again and no finite use is consumed.
    pub(super) fn authorize_current(
        &self,
        state: &State,
        actor: &mut Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        self.scope.check(state)?;
        let result = Service::bind_identity_principal(state, actor, self.scope.namespace())
            .and_then(|()| self.authorize(&state.auth, actor, time));
        Service::bind_identity_principal(&self.source, actor, self.scope.namespace())?;
        result
    }

    fn metadata_digest(&self, engines: &EngineState) -> Result<[u8; 32], Response> {
        engines
            .native_identity_metadata_digest(&|| self.deadline.check().is_ok())
            .ok_or_else(unavailable)
    }

    pub(super) fn check_source(&self, engines: &EngineState) -> Result<(), Response> {
        if self.metadata_digest(engines)? != self.metadata_digest(&self.source.engines)? {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(super) fn execute(
        &mut self,
        candidate: &mut State,
        actor: &Principal,
        now: u64,
        clock: RequestClock,
    ) -> Response {
        let result = (|| -> Result<Response, Response> {
            if self.installed_engines.is_some() || self.reply.is_some() {
                return Err(unavailable());
            }
            self.scope.check(candidate)?;
            self.check_source(&candidate.engines)?;
            let source_auth =
                owner_store::serialize_owner(&candidate.auth).map_err(|_| unavailable())?;
            let mut consumption = None;
            // Preserve the real domain's ACL, identifier rules and graph
            // mutation. The retained path/body cannot select another owner.
            let mut response = Service::dispatch_authorized_subrequest(
                candidate,
                Some(actor),
                self.scope.namespace(),
                &self.method,
                &self.path,
                &self.body,
                None,
                None,
                now,
                Some(clock),
                None,
                None,
                &mut consumption,
            );
            let checked = (|| -> Result<(), Response> {
                if consumption.is_some()
                    || source_auth.as_slice()
                        != owner_store::serialize_owner(&candidate.auth)
                            .map_err(|_| unavailable())?
                            .as_slice()
                    || !self.source.engines.native_namespace_identity_only_change(
                        self.scope.namespace(),
                        &candidate.engines,
                        &|| self.deadline.check().is_ok(),
                    )
                    || ((self.read_only || response.status >= 300)
                        && self.metadata_digest(&candidate.engines)?
                            != self.metadata_digest(&self.source.engines)?)
                {
                    return Err(unavailable());
                }
                self.reply = Some(transit_reply_digest(
                    response.status,
                    &response.body,
                    self.deadline,
                )?);
                self.installed_engines = Some(candidate.engines.clone());
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
        self.scope.check(candidate)?;
        let expected = self.installed_engines.as_ref().ok_or_else(unavailable)?;
        if self.metadata_digest(&candidate.engines)? != self.metadata_digest(expected)? {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(super) fn admit_root(
        &mut self,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
    ) -> Result<(), Response> {
        if self.installed_engines.is_none()
            || self.installed_root.is_some()
            || prior.encode().map_err(|_| unavailable())?
                != self.source_root.encode().map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        auth_only_root_change(prior, next, true)?;
        if self.read_only
            && prior.identity().map_err(|_| unavailable())?
                != next.identity().map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        self.installed_root = Some(next.clone());
        Ok(())
    }

    pub(super) fn check_installed(
        &self,
        state: &State,
        root: &RecordStateRootV6,
    ) -> Result<(), Response> {
        self.admit_candidate(state)?;
        if root.encode().map_err(|_| unavailable())?
            != self
                .installed_root
                .as_ref()
                .ok_or_else(unavailable)?
                .encode()
                .map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(super) fn bind_terminal(
        &mut self,
        state: &State,
        root: &RecordStateRootV6,
        actual_receipt_consumed: bool,
    ) -> Result<(), Response> {
        if self.terminal_bound {
            return Err(unavailable());
        }
        if actual_receipt_consumed {
            let before = self.installed_root.as_ref().ok_or_else(unavailable)?;
            let engines = self.installed_engines.as_ref().ok_or_else(unavailable)?;
            auth_only_root_change(before, root, true)?;
            if !engines.native_identity_terminal_clock_successor(&state.engines, &|| {
                self.deadline.check().is_ok()
            }) {
                return Err(unavailable());
            }
            self.installed_engines = Some(state.engines.clone());
            self.installed_root = Some(root.clone());
        }
        self.check_installed(state, root)?;
        self.terminal_bound = true;
        Ok(())
    }

    pub(super) fn check_reply(&self, response: &Response) -> Result<(), Response> {
        if !self.terminal_bound
            || self.reply
                != Some(transit_reply_digest(
                    response.status,
                    &response.body,
                    self.deadline,
                )?)
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

impl Service {
    pub(in crate::service) fn dispatch_native_identity_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(actor) = principal.as_ref() else {
            return Response::error(403, "missing client token");
        };
        let Some(root) = self.native_root.as_ref() else {
            return unavailable();
        };
        let owner = match NativeIdentityOwner::prepare(&candidate, root, actor, request) {
            Ok(owner) => owner,
            Err(error) => return error,
        };
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::Identity(Box::new(owner)),
        )
    }
}
