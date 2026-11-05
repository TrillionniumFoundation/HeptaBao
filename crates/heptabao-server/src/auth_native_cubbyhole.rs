//! Request-local root cubbyhole custody for the native Auth owner writer.
//! Only the real domain dispatcher mutates the candidate. This affine value
//! preserves its original ACL capability and independently limits its delta.
use super::*;
use zeroize::Zeroize;

pub(crate) struct NativeCubbyholeOwner {
    token_digest: String,
    relative: String,
    acl_path: String,
    method: String,
    capability: &'static str,
    final_use: bool,
    clock: RequestClock,
    deadline: crate::v6_native_custody::OriginalDeadline,
}

impl AuthState {
    pub(crate) fn capture_native_cubbyhole_owner(
        &self,
        actor: &Principal,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<NativeCubbyholeOwner, AuthError> {
        if actor.original_request_clock().is_none()
            || (path != "cubbyhole" && !path.starts_with("cubbyhole/"))
        {
            return Err(bad("native cubbyhole route mismatch"));
        }
        let clock = actor.original_request_clock().ok_or_else(denied)?;
        let deadline = crate::v6_native_custody::OriginalDeadline::capture()
            .map_err(|_| err(503, "original cubbyhole request deadline unavailable"))?;
        self.check_principal_observed(actor, "", time)?;
        let snapshot = actor.require_service("cubbyhole requires a service token")?;
        if !snapshot.namespace.is_empty() {
            return Err(denied());
        }
        let relative = path.strip_prefix("cubbyhole/").unwrap_or("");
        let method =
            if method == "GET" && body.get("list").is_some_and(|v| v == true || v == "true") {
                "LIST"
            } else {
                method
            };
        let final_use = snapshot.uses_remaining == Some(0);
        let view = if final_use {
            &snapshot.cubbyhole
        } else {
            &self.tokens.get(&actor.digest).ok_or_else(denied)?.cubbyhole
        };
        let existing = view
            .native_root_entries()
            .and_then(|entries| entries.get(relative))
            .is_some();
        let capability = match method {
            "GET" | "HEAD" => "read",
            "LIST" => "list",
            "POST" | "PUT" if existing => "update",
            "POST" | "PUT" => "create",
            "DELETE" => "delete",
            _ => return Err(bad("native cubbyhole method mismatch")),
        };
        let acl_path = if path == "cubbyhole" || method == "LIST" && !path.ends_with('/') {
            format!("{path}/")
        } else {
            path.to_owned()
        };
        self.authorize_request_observed(actor, "", &acl_path, capability, time)?;
        Ok(NativeCubbyholeOwner {
            token_digest: actor.digest.clone(),
            relative: relative.to_owned(),
            acl_path,
            method: method.to_owned(),
            capability,
            final_use,
            clock,
            deadline,
        })
    }
}

impl NativeCubbyholeOwner {
    pub(crate) fn authorize(
        &self,
        auth: &AuthState,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        self.live()?;
        if actor.digest != self.token_digest
            || actor.original_request_clock().is_none_or(|clock| {
                clock.started() != self.clock.started()
                    || clock.admitted_at() != self.clock.admitted_at()
            })
        {
            return Err(denied());
        }
        auth.authorize_request_observed(actor, "", &self.acl_path, self.capability, time)?;
        self.live()
    }

    pub(crate) fn admit_candidate(
        &self,
        source: &AuthState,
        candidate: &AuthState,
        body: &Value,
        status: u16,
    ) -> Result<(), AuthError> {
        self.live()?;
        if !matches!(status, 200 | 204) {
            return Err(bad("native cubbyhole response mismatch"));
        }
        let prior = source.tokens.get(&self.token_digest).ok_or_else(denied)?;
        let actual = candidate
            .tokens
            .get(&self.token_digest)
            .ok_or_else(denied)?;
        let mut expected = prior.cubbyhole.clone();
        if !self.final_use {
            expected.native_root_delta(&self.method, &self.relative, body)?;
        }
        let encode = |value: &cubbyhole::TokenCubbyhole| {
            crate::secret_serde::to_vec(value, crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| err(503, "native cubbyhole owner encoding unavailable"))
        };
        if encode(&expected)?.as_slice() != encode(&actual.cubbyhole)?.as_slice() {
            return Err(denied());
        }
        // Every other token and Auth field must remain exactly the admitted
        // source. In particular no issuance, policy, use or clock is inferred.
        let mut normalized = candidate.clone();
        normalized
            .tokens
            .get_mut(&self.token_digest)
            .ok_or_else(denied)?
            .cubbyhole = prior.cubbyhole.clone();
        let expected = crate::secret_serde::to_vec(source, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| err(503, "native cubbyhole Auth source unavailable"))?;
        let actual = crate::secret_serde::to_vec(&normalized, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| err(503, "native cubbyhole Auth candidate unavailable"))?;
        if expected.as_slice() != actual.as_slice() {
            return Err(denied());
        }
        self.live()
    }

    fn live(&self) -> Result<(), AuthError> {
        self.deadline
            .check()
            .map_err(|_| err(503, "original cubbyhole request deadline expired"))
    }
}

impl Drop for NativeCubbyholeOwner {
    fn drop(&mut self) {
        self.token_digest.zeroize();
        self.relative.zeroize();
        self.acl_path.zeroize();
    }
}
