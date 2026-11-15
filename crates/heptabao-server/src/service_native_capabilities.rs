//! Read-only policy inspection retains the original actor, actual inspected
//! credential, Auth/Identity snapshot and native read proof through audit.
//! A target is never promoted to an execution Principal or charged a token use.
use super::*;

fn unavailable() -> Response {
    Response::error(
        503,
        "native capabilities observation or delivery unavailable",
    )
}

pub(super) fn route(path: &str) -> bool {
    matches!(
        path,
        "sys/capabilities" | "sys/capabilities-self" | "sys/capabilities-accessor"
    )
}

pub(super) struct NativeCapabilitiesOwner {
    method: String,
    path: String,
    body: Value,
    // Original HTTP number spelling belongs to the real request carrier. ACLs
    // retain body above; the backend sees this independently owned projection.
    backend_body: crate::http::ocsp::CarrierBody,
    deadline: OriginalDeadline,
    clock: RequestClock,
    source: State,
    source_root: RecordStateRootV6,
    observation: Option<crate::auth::InspectionObservation>,
    installed_engines: Option<CowOwner<EngineState>>,
    installed_root: Option<RecordStateRootV6>,
    reply: Option<[u8; 32]>,
    terminal_bound: bool,
}

impl Drop for NativeCapabilitiesOwner {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

impl NativeCapabilitiesOwner {
    fn prepare(
        state: &State,
        root: &RecordStateRootV6,
        actor: &Principal,
        request: &RequestView<'_>,
        token_fields: Option<&crate::http::token_fields::Carrier<'_>>,
    ) -> Result<Self, Response> {
        if !request.namespace.is_empty()
            || !actor.namespace().is_empty()
            || !route(request.path)
            || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
        {
            return Err(Response::error(
                501,
                "native capabilities requires an unwrapped root inspection request",
            ));
        }
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let clock = request.token_clock.ok_or_else(unavailable)?;
        // Authorization sees the original numeric Values before the real
        // transport carrier restores weak string spellings for this backend.
        let time = request.token_time()?;
        state
            .auth
            .authorize_request_parameters_observed(
                actor,
                "",
                request.method,
                request.path,
                request.body,
                time,
            )
            .and_then(|()| {
                state
                    .auth
                    .authorize_request_observed(actor, "", request.path, "update", time)
            })
            .map_err(|error| Response::error(error.status, &error.message))?;
        let backend_body = match token_fields {
            Some(carrier) => {
                if carrier.original != request.body {
                    return Err(unavailable());
                }
                carrier.backend_body()
            }
            None => crate::http::ocsp::CarrierBody(request.body.clone()),
        };
        let owner = Self {
            method: request.method.to_owned(),
            path: request.path.to_owned(),
            body: request.body.clone(),
            backend_body,
            deadline,
            clock,
            source: state.clone(),
            source_root: root.clone(),
            observation: None,
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
        &self.method
    }

    pub(super) fn authorize(
        &self,
        auth: &AuthState,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        let time = actor
            .request_authority_time(time)
            .map_err(|_| unavailable())?;
        auth.authorize_request_parameters_observed(
            actor,
            "",
            &self.method,
            &self.path,
            &self.body,
            time,
        )
        .and_then(|()| auth.authorize_request_observed(actor, "", &self.path, "update", time))
        .map_err(|error| Response::error(error.status, &error.message))?;
        if let Some(original) = self.observation.as_ref() {
            original.check_at(time).map_err(|_| unavailable())?;
            // Self and foreign targets use the same original inspection rules;
            // neither lookup charges a second use. An admitted final-use self
            // returns the original backend 400 and never acquires a target.
            // Rechecking a target never reruns the capability-result computation.
            let current = Service::capabilities_inspection_target_observed(
                auth,
                actor,
                "",
                &self.path,
                &self.backend_body.0,
                time,
            )
            .map_err(|_| unavailable())?;
            if &current != original.target() {
                return Err(unavailable());
            }
        }
        self.deadline.check().map_err(|_| unavailable())
    }

    pub(super) fn authorize_current(
        &self,
        state: &State,
        actor: &mut Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        let result = Service::bind_identity_principal(state, actor, "")
            .and_then(|()| self.authorize(&state.auth, actor, time));
        // Refresh only the projection on this same affine actor, then restore
        // its original source projection. No current root can replace custody.
        Service::bind_identity_principal(&self.source, actor, "")?;
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
        candidate: &State,
        actor: &Principal,
        now: u64,
        clock: RequestClock,
    ) -> Response {
        let result = (|| -> Result<Response, Response> {
            if self.installed_engines.is_some() || self.reply.is_some() {
                return Err(unavailable());
            }
            self.check_source(&candidate.engines)?;
            if clock.started() != self.clock.started() {
                return Err(unavailable());
            }
            let observed = self
                .clock
                .with_seconds_floor(now)
                .map_err(|_| unavailable())?
                .observed_at()
                .map_err(|_| unavailable())?;
            let time = candidate
                .auth
                .token_api_observed_time(AuthorityTime::Precise(observed));
            // This is the original public backend, including path spelling,
            // target conversion, current Identity policies and error semantics.
            // Its immutable State argument grants no additional write or use.
            let (mut response, observation) = Service::capabilities_route_observed(
                candidate,
                Some(actor),
                "",
                &self.method,
                &self.path,
                &self.backend_body.0,
                time,
            );
            let checked = (|| -> Result<(), Response> {
                if response.unwrapped_json.is_some()
                    || !response.response_headers.is_empty()
                    || response.consistency_index.is_some()
                {
                    return Err(unavailable());
                }
                if (response.status == 200) != observation.is_some() {
                    return Err(unavailable());
                }
                self.observation = observation;
                if response.status == 200 {
                    // Retain the exact target and policy cutoff from the one
                    // backend computation, then refresh only its validity.
                    self.authorize(&candidate.auth, actor, time)?;
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
        if actual_receipt_consumed {
            let before = self.installed_root.as_ref().ok_or_else(unavailable)?;
            let engines = self.installed_engines.as_ref().ok_or_else(unavailable)?;
            // The caller has consumed this exact request's affine receipt and
            // matched its resulting checkpoint. This allows only clock effects.
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
        if let Some(observation) = &self.observation {
            let time = AuthorityTime::Precise(self.clock.observed_at().map_err(|_| unavailable())?);
            observation.check_at(time).map_err(|_| unavailable())?;
        }
        if !self.terminal_bound
            || (response.status == 200) != self.observation.is_some()
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
    pub(in crate::service) fn dispatch_native_capabilities_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
        token_fields: Option<&crate::http::token_fields::Carrier<'_>>,
    ) -> Response {
        let Some(actor) = principal.as_ref() else {
            return Response::error(403, "missing client token");
        };
        let Some(root) = self.native_root.as_ref() else {
            return unavailable();
        };
        let owner = match NativeCapabilitiesOwner::prepare(
            &candidate,
            root,
            actor,
            request,
            token_fields,
        ) {
            Ok(owner) => owner,
            Err(error) => return error,
        };
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::Capabilities(Box::new(owner)),
        )
    }
}
