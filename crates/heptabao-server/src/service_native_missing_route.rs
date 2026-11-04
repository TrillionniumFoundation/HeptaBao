//! A negative result for a genuinely absent mount is still an observed read.
//! Retain its original Actor, namespace incarnation and ancestors, catalog,
//! immutable root and exact dispatcher reply through the ordinary terminal
//! clock and mandatory response audit.
use super::*;

fn unavailable() -> Response {
    Response::error(
        503,
        "native missing-route ownership or delivery unavailable",
    )
}

// Test-only phase observations contain no token, request body or error text.
// One fixed-size line per boundary; diagnostics never change the result.
#[cfg(test)]
pub(super) fn record_stage(
    stage: &'static str,
    status: Option<u16>,
    clock: RequestClock,
    deadline: OriginalDeadline,
) {
    use std::io::Write as _;
    let observed = Instant::now();
    let _ = writeln!(
        std::io::stderr().lock(),
        "HBHA-DIAG-MISSING stage={stage} status={status:?} elapsed_us={} remaining_us={} thread={:?}",
        observed
            .saturating_duration_since(clock.started())
            .as_micros(),
        deadline
            .instant()
            .checked_duration_since(observed)
            .map_or(0, |remaining| remaining.as_micros()),
        std::thread::current().id(),
    );
}

/// Non-cloneable custody for one original request, not a general 404 fallback.
pub(super) struct NativeMissingRouteOwner {
    scope: namespaces::native_plain::PlainNamespaceScope,
    method: String,
    path: String,
    body: Value,
    capability: &'static str,
    deadline: OriginalDeadline,
    source: State,
    source_root: RecordStateRootV6,
    installed_engines: Option<CowOwner<EngineState>>,
    installed_root: Option<RecordStateRootV6>,
    reply: Option<[u8; 32]>,
    terminal_bound: bool,
}

impl Drop for NativeMissingRouteOwner {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

impl NativeMissingRouteOwner {
    fn prepare(
        state: &State,
        root: &RecordStateRootV6,
        actor: &Principal,
        request: &RequestView<'_>,
    ) -> Result<Self, Response> {
        let method = kv_authorization_method(request.method, request.body);
        if !state
            .engines
            .native_missing_mount_read(request.namespace, method, request.path)
            || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
        {
            return Err(Response::error(
                501,
                "native missing-route observation requires an unwrapped absent mount",
            ));
        }
        // The engine dispatcher accepts only object or null request parameters.
        // Invalid input does not manufacture a successful negative observation.
        if !request.body.is_null() && !request.body.is_object() {
            return Err(Response::error(400, "request body must be an object"));
        }
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        // Engine absence alone cannot grant a namespace or rebind a retained
        // owner after that namespace or any ancestor was removed/recreated.
        let scope =
            namespaces::native_plain::PlainNamespaceScope::capture(state, request.namespace)?;
        let capability = match method {
            "GET" | "HEAD" => "read",
            "LIST" => "list",
            _ => return Err(unavailable()),
        };
        let owner = Self {
            scope,
            method: method.to_owned(),
            path: request.path.to_owned(),
            body: request.body.clone(),
            capability,
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

    pub(super) fn authorize_current(
        &self,
        state: &State,
        actor: &mut Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        self.scope.check(state)?;
        let result = Service::bind_identity_principal(state, actor, self.scope.namespace())
            .and_then(|()| self.authorize(&state.auth, actor, time));
        // Keep the same affine Actor, including an already consumed finite use.
        // A current Identity projection must never replace its source authority.
        Service::bind_identity_principal(&self.source, actor, self.scope.namespace())?;
        result
    }

    fn metadata_digest(&self, engines: &EngineState) -> Result<[u8; 32], Response> {
        engines
            .native_identity_metadata_digest(&|| self.deadline.check().is_ok())
            .ok_or_else(unavailable)
    }

    fn absent_in(&self, engines: &EngineState) -> bool {
        engines.native_missing_mount_read(self.scope.namespace(), &self.method, &self.path)
    }

    pub(super) fn check_source(&self, engines: &EngineState) -> Result<(), Response> {
        if !self.absent_in(engines)
            || self.metadata_digest(engines)? != self.metadata_digest(&self.source.engines)?
        {
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
            // Execute the original dispatcher. No new 404 body or replacement
            // route is synthesized by this owner, even for an absent mount.
            #[cfg(test)]
            record_stage("domain-before", None, clock, self.deadline);
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
            #[cfg(test)]
            record_stage(
                "domain-returned",
                Some(response.status),
                clock,
                self.deadline,
            );
            let checked = (|| -> Result<(), Response> {
                self.scope.check(candidate)?;
                if consumption.is_some()
                    || source_auth.as_slice()
                        != owner_store::serialize_owner(&candidate.auth)
                            .map_err(|_| unavailable())?
                            .as_slice()
                    || !self.absent_in(&candidate.engines)
                    || self.metadata_digest(&candidate.engines)?
                        != self.metadata_digest(&self.source.engines)?
                    || response.status != 404
                    || response.body != json!({"errors":["unsupported path"]})
                    || response.unwrapped_json.is_some()
                    || !response.response_headers.is_empty()
                    || response.consistency_index.is_some()
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
                #[cfg(test)]
                record_stage(
                    "domain-owner-veto",
                    Some(error.status),
                    clock,
                    self.deadline,
                );
                erase_json(&mut response.body);
                return Err(error);
            }
            #[cfg(test)]
            record_stage(
                "domain-owner-accepted",
                Some(response.status),
                clock,
                self.deadline,
            );
            Ok(response)
        })();
        result.unwrap_or_else(|error| error)
    }

    pub(super) fn admit_candidate(&self, candidate: &State) -> Result<(), Response> {
        self.scope.check(candidate)?;
        let expected = self.installed_engines.as_ref().ok_or_else(unavailable)?;
        if !self.absent_in(&candidate.engines)
            || self.metadata_digest(&candidate.engines)? != self.metadata_digest(expected)?
        {
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
            || next.encode().map_err(|_| unavailable())?
                != prior.encode().map_err(|_| unavailable())?
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
        self.scope.check(state)?;
        if actual_receipt_consumed {
            let before = self.installed_root.as_ref().ok_or_else(unavailable)?;
            let engines = self.installed_engines.as_ref().ok_or_else(unavailable)?;
            // The caller has already consumed this operation's real affine
            // TerminalClockReceipt and matched its exact resulting checkpoint.
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
            || response.status != 404
            || response.body != json!({"errors":["unsupported path"]})
            || response.unwrapped_json.is_some()
            || !response.response_headers.is_empty()
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
    pub(in crate::service) fn dispatch_native_missing_route_request(
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
        let owner = match NativeMissingRouteOwner::prepare(&candidate, root, actor, request) {
            Ok(owner) => owner,
            Err(error) => return error,
        };
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::MissingRoute(Box::new(owner)),
        )
    }
}
