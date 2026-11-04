//! Output custody for one already executed native KV/Auth operation. This
//! capsule owns no Principal, resource route, dispatcher or publication grant.
//! The original business owner remains responsible for its actual candidate.
use super::*;
use crate::service::Response;
use crate::v6_native_custody::OriginalDeadline;

fn unavailable() -> AuthError {
    err(503, "native response wrapping composition unavailable")
}

fn digest<T: Serialize>(value: &T, deadline: OriginalDeadline) -> Result<[u8; 32], AuthError> {
    deadline.check().map_err(|_| unavailable())?;
    let bytes = crate::secret_serde::to_vec(value, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| unavailable())?;
    let value = crate::crypto::digest(&bytes);
    deadline.check().map_err(|_| unavailable())?;
    Ok(value)
}

fn reply_digest(response: &Response, deadline: OriginalDeadline) -> Result<[u8; 32], AuthError> {
    // Ordinary unwrap, SDK and raw transports retain their separate origins.
    // A public JSON value cannot stand in for their private output ownership.
    if let Some(origin) = &response.unwrapped_json {
        let projection = origin.static_kv1_lease().ok_or_else(unavailable)?;
        if response.status != 200 { return Err(unavailable()); }
        projection.validate(&response.body)?;
        return digest(&("static-kv1-lease-v1", response.status, &response.body, projection), deadline);
    }
    digest(&(response.status, &response.body), deadline)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Pending,
    Passthrough,
    Wrapped,
    WrapperFailed,
    RollbackBound,
}

struct IssuedWrapper {
    id: String,
    token: [u8; 32],
    expires_at: u64,
}

impl AuthState {
    /// This output adapter has its own closed selector. Extending the native
    /// Auth dispatcher later (for example Userpass/batch) must not silently
    /// enroll that new business owner in response composition.
    pub(crate) fn native_response_wrapping_route(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        if !self.native_v6_local_auth_route(namespace, method, path, body) {
            return false;
        }
        if path == "sys/policy"
            || path.starts_with("sys/policy/")
            || path == "sys/policies/acl"
            || path.starts_with("sys/policies/acl/")
            || path == "sys/quotas/config"
            || path == "sys/quotas/rate-limit"
            || path.starts_with("sys/quotas/rate-limit/")
            || path == "cubbyhole"
            || path.starts_with("cubbyhole/")
            || path.starts_with("auth/token/")
        {
            return true;
        }
        let mounts = self.effective_auth_mounts(namespace);
        if let Some(suffix) = path.strip_prefix("sys/auth/") {
            let mount = suffix.strip_suffix("/tune").unwrap_or(suffix);
            return mounts
                .get(mount)
                .is_some_and(|entry| matches!(entry.kind.as_str(), "approle" | "cert"))
                || (matches!(method, "POST" | "PUT")
                    && !suffix.ends_with("/tune")
                    && body
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| matches!(kind, "approle" | "cert")));
        }
        let Some(path) = path.strip_prefix("auth/") else {
            return false;
        };
        mounts.iter().any(|(mount, entry)| {
            let Some(suffix) = path.strip_prefix(&format!("{mount}/")) else {
                return false;
            };
            match entry.kind.as_str() {
                "approle" => suffix == "login" || suffix == "role" || suffix.starts_with("role/"),
                "cert" => {
                    suffix == "login"
                        || suffix == "config"
                        || suffix == "certs"
                        || suffix.starts_with("certs/")
                }
                _ => false,
            }
        })
    }
}

/// The actual inner Response moves here; it is never reconstructed from a
/// digest, reexecuted operation or wrapper accessor. Response::drop erases it.
/// The stored Auth wrapper is the only durable copy of its logical payload.
pub(crate) struct NativeResponseWrappingOwner {
    path: String,
    ttl: u64,
    clock: RequestClock,
    deadline: OriginalDeadline,
    source_auth: [u8; 32],
    domain_auth: Option<[u8; 32]>,
    candidate_auth: Option<[u8; 32]>,
    inner: Option<Box<Response>>,
    inner_digest: Option<[u8; 32]>,
    outer_digest: Option<[u8; 32]>,
    issued: Option<IssuedWrapper>,
    outcome: Outcome,
}

impl NativeResponseWrappingOwner {
    pub(crate) fn prepare(
        source: &AuthState,
        namespace: &str,
        path: &str,
        ttl: u64,
        clock: RequestClock,
    ) -> Result<Self, AuthError> {
        if !namespace.is_empty() || ttl == 0 || path.starts_with("sys/wrapping/") {
            return Err(unavailable());
        }
        validate_path(path, false)?;
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        Ok(Self {
            path: path.to_owned(),
            ttl,
            clock,
            deadline,
            source_auth: digest(source, deadline)?,
            domain_auth: None,
            candidate_auth: None,
            inner: None,
            inner_digest: None,
            outer_digest: None,
            issued: None,
            outcome: Outcome::Pending,
        })
    }

    fn time(&self, auth: &AuthState) -> Result<AuthorityTime, AuthError> {
        self.deadline.check().map_err(|_| unavailable())?;
        let at = self.clock.observed_at().map_err(|_| unavailable())?;
        Ok(auth.token_api_observed_time(AuthorityTime::Precise(at)))
    }

    pub(crate) fn check_source(&self, source: &AuthState) -> Result<(), AuthError> {
        self.time(source)?;
        if digest(source, self.deadline)? != self.source_auth {
            return Err(unavailable());
        }
        Ok(())
    }

    /// Called once, after the original business owner has admitted its actual
    /// domain candidate and finished its response-only bearer echo. The only
    /// mutable input is that candidate's Auth; no other owner can change here.
    pub(crate) fn compose(
        &mut self,
        auth: &mut AuthState,
        response: Response,
    ) -> Result<Response, AuthError> {
        if self.outcome != Outcome::Pending || self.domain_auth.is_some() {
            return Err(unavailable());
        }
        let time = self.time(auth)?;
        self.domain_auth = Some(digest(auth, self.deadline)?);
        self.inner_digest = Some(reply_digest(&response, self.deadline)?);
        if !(200..300).contains(&response.status)
            || response.status == 204
            || response.body.is_null()
            || response
                .body
                .get("wrap_info")
                .is_some_and(|value| !value.is_null())
        {
            self.outcome = Outcome::Passthrough;
            self.candidate_auth = self.domain_auth;
            self.outer_digest = self.inner_digest;
            return Ok(response);
        }

        let mut wrapped_auth = auth.clone();
        let wrapped = if let Some(projection) = response.unwrapped_json.as_ref()
            .and_then(|origin| origin.static_kv1_lease())
        {
            wrapped_auth.wrap_static_kv1_response("", &self.path, self.ttl,
                &response.body, time.seconds(), projection)
        } else {
            wrapped_auth.wrap_logical_response("", &self.path, self.ttl,
                &response.body, time.seconds())
        };
        self.inner = Some(Box::new(response));
        let response = match wrapped {
            Ok(wrapped) => {
                wrapped_auth.validate_wrapping_state()?;
                wrapped_auth.validate_raw_wrapped_reply_successor(auth)?;
                let raw = wrapped
                    .body
                    .get("wrap_info")
                    .and_then(|value| value.get("token"))
                    .and_then(Value::as_str)
                    .ok_or_else(unavailable)?;
                wrapped_auth.wrapping_target(raw, "", time.seconds())?;
                let id = hash(raw);
                let token = wrapped_auth.tokens.get(&id).ok_or_else(unavailable)?;
                let stored = token.wrapping.as_ref().ok_or_else(unavailable)?;
                let inner = self.inner.as_deref().ok_or_else(unavailable)?;
                if stored.creation_path != self.path
                    || stored.creation_ttl != self.ttl
                    || stored.response != inner.body
                    || stored.has_sdk_origin()
                {
                    return Err(unavailable());
                }
                if let Some(reply) = &stored.stored_reply {
                    reply.validate_owner(&stored.response, &self.path)?;
                }
                self.issued = Some(IssuedWrapper {
                    id,
                    token: digest(token, self.deadline)?,
                    expires_at: token.expires_at.ok_or_else(unavailable)?,
                });
                self.candidate_auth = Some(digest(&wrapped_auth, self.deadline)?);
                self.outcome = Outcome::Wrapped;
                *auth = wrapped_auth;
                Response {
                    status: wrapped.status,
                    body: wrapped.body,
                    unwrapped_json: wrapped.unwrapped_json,
                    response_headers: Default::default(),
                    consistency_index: None,
                }
            }
            Err(error) => {
                // The caller must discard the complete private domain State,
                // then supply the original admitted source to the affine
                // rollback below. No partial wrapping mutation was installed.
                self.outcome = Outcome::WrapperFailed;
                Response::error(error.status, &error.message)
            }
        };
        self.outer_digest = Some(reply_digest(&response, self.deadline)?);
        Ok(response)
    }

    pub(crate) fn construction_failed(&self) -> bool {
        matches!(
            self.outcome,
            Outcome::WrapperFailed | Outcome::RollbackBound
        )
    }

    /// Consume only the original authenticated finite SecretID transition.
    /// apply() checks the actual old mount/role/credential and consumes self;
    /// it is not idempotent and is never copied or applied twice here.
    pub(crate) fn bind_failure_rollback(
        &mut self,
        source: &AuthState,
        rolled_back: &mut AuthState,
        consumption: Option<Box<crate::auth::AppRoleSecretIdConsumption>>,
    ) -> Result<(), AuthError> {
        if self.outcome != Outcome::WrapperFailed || self.candidate_auth.is_some() {
            return Err(unavailable());
        }
        self.check_source(source)?;
        if digest(rolled_back, self.deadline)? != self.source_auth {
            return Err(unavailable());
        }
        if let Some(consumption) = consumption {
            consumption.apply(rolled_back)?;
        }
        self.candidate_auth = Some(digest(rolled_back, self.deadline)?);
        self.outcome = Outcome::RollbackBound;
        Ok(())
    }

    pub(crate) fn admit_candidate(&self, auth: &AuthState) -> Result<(), AuthError> {
        if !matches!(
            self.outcome,
            Outcome::Passthrough | Outcome::Wrapped | Outcome::RollbackBound
        ) || self.outer_digest.is_none()
            || self.candidate_auth != Some(digest(auth, self.deadline)?)
            || !auth.native_wrapping_storage_supported()
        {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(crate) fn domain_response<'a>(&'a self, outer: &'a Response) -> &'a Response {
        self.inner.as_deref().unwrap_or(outer)
    }

    pub(crate) fn check_reply(&self, outer: &Response) -> Result<(), AuthError> {
        if !matches!(
            self.outcome,
            Outcome::Passthrough | Outcome::Wrapped | Outcome::RollbackBound
        ) || self.outer_digest != Some(reply_digest(outer, self.deadline)?)
            || self.inner_digest != Some(reply_digest(self.domain_response(outer), self.deadline)?)
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// The actual post-terminal Auth projection may advance observation clocks,
    /// but it cannot replace, consume, revoke or extend this issued wrapper.
    /// Business-actor and inner-issued-credential checks remain outside here.
    pub(crate) fn check_current_auth(&self, auth: &AuthState) -> Result<(), AuthError> {
        let time = self.time(auth)?;
        if let Some(issued) = &self.issued {
            if self.outcome != Outcome::Wrapped
                || time.seconds().max(auth.wrapping_clock) >= issued.expires_at
                || digest(
                    auth.tokens.get(&issued.id).ok_or_else(unavailable)?,
                    self.deadline,
                )? != issued.token
            {
                return Err(unavailable());
            }
        } else if self.outcome == Outcome::Wrapped {
            return Err(unavailable());
        }
        Ok(())
    }
}
