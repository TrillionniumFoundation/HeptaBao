//! Ordinary response wrapping in the native Auth owner. These types select no
//! Control Group, SDK workflow or engine operation. They retain the actual
//! domain result, original clock and private one-use response until delivery.
use super::*;
use crate::service::Response;
use crate::v6_native_custody::OriginalDeadline;

fn unavailable() -> AuthError {
    err(
        503,
        "native ordinary wrapping ownership or delivery unavailable",
    )
}

fn digest<T: Serialize>(value: &T, deadline: OriginalDeadline) -> Result<[u8; 32], AuthError> {
    deadline.check().map_err(|_| unavailable())?;
    let bytes = crate::secret_serde::to_vec(value, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| unavailable())?;
    let result = crate::crypto::digest(&bytes);
    deadline.check().map_err(|_| unavailable())?;
    Ok(result)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Wrap,
    Lookup,
    Unwrap,
    Rewrap,
}
impl Operation {
    fn select(path: &str) -> Option<Self> {
        match path {
            "sys/wrapping/wrap" => Some(Self::Wrap),
            "sys/wrapping/lookup" => Some(Self::Lookup),
            "sys/wrapping/unwrap" => Some(Self::Unwrap),
            "sys/wrapping/rewrap" => Some(Self::Rewrap),
            _ => None,
        }
    }
    fn permits_method(self, method: &str) -> bool {
        matches!(method, "POST" | "PUT") || self == Self::Lookup && method == "GET"
    }
}

/// No raw token or wrapped payload is copied into this retained target. Both
/// hashes are made from the actual source/result token, not a reconstructed
/// bearer or an accessor pretending to be a credential.
struct Target {
    id: String,
    source: [u8; 32],
    result: [u8; 32],
    expires_at: u64,
}
impl Target {
    fn capture(
        source: &AuthState,
        id: String,
        deadline: OriginalDeadline,
    ) -> Result<Self, AuthError> {
        let token = source.tokens.get(&id).ok_or_else(unavailable)?;
        let source = digest(token, deadline)?;
        Ok(Self {
            id,
            source,
            result: source,
            expires_at: token.expires_at.ok_or_else(unavailable)?,
        })
    }
    fn observe_result(
        &mut self,
        auth: &AuthState,
        deadline: OriginalDeadline,
    ) -> Result<(), AuthError> {
        self.result = digest(auth.tokens.get(&self.id).ok_or_else(unavailable)?, deadline)?;
        Ok(())
    }
    fn check(
        &self,
        auth: &AuthState,
        time: AuthorityTime,
        source: bool,
        deadline: OriginalDeadline,
    ) -> Result<(), AuthError> {
        if time.seconds().max(auth.wrapping_clock) >= self.expires_at {
            return Err(unavailable());
        }
        let expected = if source { self.source } else { self.result };
        if digest(auth.tokens.get(&self.id).ok_or_else(unavailable)?, deadline)? != expected {
            return Err(unavailable());
        }
        Ok(())
    }
}

/// Non-cloneable operation capsule. Only execute() may acquire a candidate and
/// response binding, after the original ordinary domain dispatcher has run once.
pub(crate) struct NativeWrappingOwner {
    operation: Operation,
    method: String,
    path: String,
    body: Value,
    header: Zeroizing<String>,
    wrap_ttl: Option<u64>,
    clock: RequestClock,
    deadline: OriginalDeadline,
    source: [u8; 32],
    executed: bool,
    candidate: Option<[u8; 32]>,
    target: Option<Target>,
    issued: Option<Target>,
    reply: Option<[u8; 32]>,
    reply_status: Option<u16>,
    unwrap_nonce: Option<[u8; 32]>,
}
impl Drop for NativeWrappingOwner {
    fn drop(&mut self) {
        crate::service::erase_json(&mut self.body);
    }
}
impl NativeWrappingOwner {
    pub(crate) fn route(path: &str) -> bool {
        Operation::select(path).is_some()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        auth: &AuthState,
        method: &str,
        path: &str,
        body: &Value,
        header: &str,
        wrap_ttl: Option<u64>,
        clock: RequestClock,
    ) -> Result<Self, AuthError> {
        let operation = Operation::select(path).ok_or_else(unavailable)?;
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let source = digest(auth, deadline)?;
        Ok(Self {
            operation,
            method: method.to_owned(),
            path: path.to_owned(),
            body: body.clone(),
            header: Zeroizing::new(header.to_owned()),
            wrap_ttl,
            clock,
            deadline,
            source,
            executed: false,
            candidate: None,
            target: None,
            issued: None,
            reply: None,
            reply_status: None,
            unwrap_nonce: None,
        })
    }

    pub(crate) fn read_only(&self) -> bool {
        self.operation == Operation::Lookup && self.wrap_ttl.is_none_or(|ttl| ttl == 0)
    }

    fn time(&self, auth: &AuthState) -> Result<AuthorityTime, AuthError> {
        self.deadline.check().map_err(|_| unavailable())?;
        let at = self.clock.observed_at().map_err(|_| unavailable())?;
        Ok(auth.token_api_observed_time(AuthorityTime::Precise(at)))
    }

    /// The header used for anonymous lookup is the original request input. No
    /// authentication or new Principal is performed by these late checks.
    fn requested_target<'a>(&'a self, actor: Option<&'a Principal>) -> Option<&'a str> {
        if self.operation == Operation::Wrap {
            return None;
        }
        if self.operation == Operation::Lookup {
            return match self.body.get("token") {
                Some(Value::String(raw)) if !raw.is_empty() => Some(raw),
                None => Some(self.header.as_str()),
                _ => None,
            };
        }
        if actor
            .and_then(Principal::service_token)
            .is_some_and(|token| token.wrapping.is_some())
        {
            None // The affine self-unwrap actor, already consumed at admission.
        } else {
            self.body.get("token").and_then(Value::as_str)
        }
    }

    fn capture_target(
        &self,
        auth: &AuthState,
        actor: Option<&Principal>,
        time: AuthorityTime,
    ) -> Result<Option<Target>, AuthError> {
        if self.operation == Operation::Wrap || !self.operation.permits_method(&self.method) {
            return Ok(None);
        }
        if self.operation == Operation::Unwrap
            && let Some(actor) = actor
            && actor
                .service_token()
                .is_some_and(|token| token.wrapping.is_some())
        {
            // The durable source is spent. Its original private payload remains
            // only in this same affine Principal; no reauthentication occurs.
            if !actor.consumed_use() || self.body.get("token").is_some() {
                return Ok(None);
            }
            return Target::capture(auth, actor.digest.clone(), self.deadline).map(Some);
        }
        let Some(raw) = self.requested_target(actor) else {
            return Ok(None);
        };
        if auth.wrapping_target(raw, "", time.seconds()).is_err() {
            return Ok(None); // Preserve the original domain's exact public error.
        }
        Target::capture(auth, hash(raw), self.deadline).map(Some)
    }

    pub(crate) fn check_source(
        &self,
        auth: &AuthState,
        actor: Option<&Principal>,
    ) -> Result<(), AuthError> {
        let time = self.time(auth)?;
        if digest(auth, self.deadline)? != self.source {
            return Err(unavailable());
        }
        if self.reply_status.is_some_and(|status| status < 300) {
            self.authorize(auth, actor, time)?;
            if let Some(target) = &self.target {
                target.check(auth, time, true, self.deadline)?;
            }
        }
        Ok(())
    }

    fn authorize(
        &self,
        auth: &AuthState,
        actor: Option<&Principal>,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        if self.operation != Operation::Lookup {
            let actor = actor.ok_or_else(denied)?;
            auth.authorize_request_parameters_observed(
                actor,
                "",
                &self.method,
                &self.path,
                &self.body,
                time,
            )?;
            auth.authorize_request_observed(actor, "", &self.path, "update", time)?;
        }
        Ok(())
    }

    fn response_digest(&self, response: &Response) -> Result<[u8; 32], AuthError> {
        let private = match (&response.unwrapped_json, self.unwrap_nonce) {
            (None, None) => None,
            (Some(unwrapped), Some(nonce)) => {
                if unwrapped.state.native_owner != Some(nonce)
                    || unwrapped.state.workflow_output_failure.is_some()
                {
                    return Err(unavailable());
                }
                // Validate the immutable actual stored projection; the ordinary
                // mandatory audit may legitimately add its selected ingress.
                unwrapped.framing_wire(&response.body)?;
                Some((nonce, unwrapped.stored_reply()))
            }
            _ => return Err(unavailable()),
        };
        digest(&(response.status, &response.body, private), self.deadline)
    }

    pub(crate) fn execute(
        &mut self,
        auth: &mut AuthState,
        actor: Option<&Principal>,
    ) -> Result<Response, AuthError> {
        self.check_source(auth, actor)?;
        if self.executed {
            return Err(unavailable());
        }
        self.executed = true;
        let time = self.time(auth)?;
        let mut target = self.capture_target(auth, actor, time)?;
        let mut transaction = auth.clone();
        let result =
            if self.operation == Operation::Wrap && self.wrap_ttl.is_none_or(|ttl| ttl == 0) {
                Err(bad("endpoint requires response wrapping to be used"))
            } else if self.operation == Operation::Lookup {
                if self
                    .requested_target(actor)
                    .is_some_and(|raw| auth.is_control_group_token(raw))
                {
                    // Control Groups keep their separate approval and spent-token
                    // contract. Ordinary wrapping cannot borrow those capabilities.
                    Err(err(
                        501,
                        "native ordinary lookup requires an ordinary wrapper",
                    ))
                } else {
                    transaction.lookup_wrapping_request_observed(
                        &self.header,
                        "",
                        &self.method,
                        &self.body,
                        time,
                    )
                }
            } else {
                transaction.wrapping_route(
                    actor,
                    "",
                    &self.method,
                    &self.path,
                    &self.body,
                    time.seconds(),
                )
            };
        let mut response = match result {
            Ok(value) => Response {
                status: value.status,
                body: value.body,
                unwrapped_json: value.unwrapped_json,
                response_headers: Default::default(),
                consistency_index: None,
            },
            Err(error) => Response::error(error.status, &error.message),
        };
        if response.status < 300
            && response.status != 204
            && !response.body.is_null()
            && response.body.get("wrap_info").is_none_or(Value::is_null)
            && let Some(ttl) = self.wrap_ttl.filter(|ttl| *ttl > 0)
        {
            // The original domain output and its new wrapper stay in this one
            // private transaction. Failed wrapping never rolls back the earlier
            // separately committed finite-use admission.
            response = match transaction.wrap_logical_response(
                "",
                &self.path,
                ttl,
                &response.body,
                time.seconds(),
            ) {
                Ok(value) => Response {
                    status: value.status,
                    body: value.body,
                    unwrapped_json: value.unwrapped_json,
                    response_headers: Default::default(),
                    consistency_index: None,
                },
                Err(error) => Response::error(error.status, &error.message),
            };
        }
        if response.status < 300 {
            transaction.validate_wrapping_state()?;
            transaction.validate_raw_wrapped_reply_successor(auth)?;
            if self.operation != Operation::Wrap && target.is_none() {
                return Err(unavailable());
            }
            if let Some(target) = &mut target {
                target.observe_result(&transaction, self.deadline)?;
            }
            if let Some(raw) = response
                .body
                .get("wrap_info")
                .and_then(|v| v.get("token"))
                .and_then(Value::as_str)
            {
                transaction.wrapping_target(raw, "", time.seconds())?;
                self.issued = Some(Target::capture(&transaction, hash(raw), self.deadline)?);
            }
            if let Some(unwrapped) = response.unwrapped_json.as_mut() {
                if self.operation != Operation::Unwrap || unwrapped.state.native_owner.is_some() {
                    return Err(unavailable());
                }
                let nonce = crate::crypto::random::<32>().map_err(|_| unavailable())?;
                unwrapped.state.native_owner = Some(nonce);
                self.unwrap_nonce = Some(nonce);
            }
            self.target = target;
            self.candidate = Some(digest(&transaction, self.deadline)?);
        } else {
            // Same rollback contract as dispatch_authorized_subrequest: errors
            // cannot install a half-consumed body token or a partial rewrap.
            self.candidate = Some(digest(auth, self.deadline)?);
        }
        self.reply_status = Some(response.status);
        self.reply = Some(self.response_digest(&response)?);
        self.check_source(auth, actor)?;
        if response.status < 300 {
            *auth = transaction;
        }
        self.admit_candidate(auth)?;
        Ok(response)
    }

    pub(crate) fn admit_candidate(&self, auth: &AuthState) -> Result<(), AuthError> {
        if !self.executed
            || self.reply.is_none()
            || self.candidate != Some(digest(auth, self.deadline)?)
        {
            return Err(unavailable());
        }
        if !auth.native_wrapping_storage_supported() {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(crate) fn check_reply(&self, response: &Response) -> Result<(), AuthError> {
        if self.reply.is_none() || self.reply != Some(self.response_digest(response)?) {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(crate) fn authorize_reply(
        &self,
        auth: &AuthState,
        actor: Option<&Principal>,
    ) -> Result<(), AuthError> {
        let time = self.time(auth)?;
        // An original error cannot be rewritten as a credential response. Its
        // exact bytes and native proof remain mandatory, but an invalid target
        // need not become valid merely to deliver its already-bound 400.
        if self.reply_status.is_some_and(|status| status < 300) {
            self.authorize(auth, actor, time)?;
            if let Some(target) = &self.target {
                target.check(auth, time, false, self.deadline)?;
            }
            if let Some(issued) = &self.issued {
                issued.check(auth, time, false, self.deadline)?;
            }
        }
        Ok(())
    }
}

/// Exact observation-only predecessor of an ordinary wrapper access. It owns
/// the former wrapping and CG clock preludes together, never a resource route.
pub(crate) struct NativeWrappingObservation {
    clock: RequestClock,
    deadline: OriginalDeadline,
    at: AuthorityTime,
    source: [u8; 32],
    candidate: [u8; 32],
}
impl NativeWrappingObservation {
    pub(crate) fn observe(
        auth: &AuthState,
        clock: RequestClock,
    ) -> Result<(Self, AuthState, bool), AuthError> {
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let at = AuthorityTime::Precise(clock.observed_at().map_err(|_| unavailable())?);
        let mut candidate = auth.clone();
        let mut changed = candidate.advance_wrapping_clock(at.seconds());
        changed |= candidate.advance_control_group_observed(at)?;
        candidate.validate_wrapping_state()?;
        candidate.validate_raw_wrapped_reply_successor(auth)?;
        let binding = Self {
            clock,
            deadline,
            at,
            source: digest(auth, deadline)?,
            candidate: digest(&candidate, deadline)?,
        };
        binding.check_candidate(auth, &candidate)?;
        Ok((binding, candidate, changed))
    }
    pub(crate) fn check_candidate(
        &self,
        auth: &AuthState,
        candidate: &AuthState,
    ) -> Result<(), AuthError> {
        self.deadline.check().map_err(|_| unavailable())?;
        if self
            .clock
            .observed_at()
            .map_err(|_| unavailable())?
            .seconds()
            < self.at.seconds()
            || digest(auth, self.deadline)? != self.source
            || digest(candidate, self.deadline)? != self.candidate
        {
            return Err(unavailable());
        }
        let mut expected = auth.clone();
        expected.advance_wrapping_clock(self.at.seconds());
        expected.advance_control_group_observed(self.at)?;
        if digest(&expected, self.deadline)? != self.candidate {
            return Err(unavailable());
        }
        self.deadline.check().map_err(|_| unavailable())
    }
}

impl AuthState {
    pub(crate) fn native_wrapping_storage_supported(&self) -> bool {
        self.validate_wrapping_state().is_ok()
            && self.tokens.values().all(|token| {
                token
                    .wrapping
                    .as_ref()
                    .is_none_or(|wrapped| !wrapped.has_sdk_origin())
            })
    }
}
