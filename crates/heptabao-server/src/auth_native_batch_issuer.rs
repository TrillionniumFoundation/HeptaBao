//! Typed custody for real, unwrapped AppRole and Token API batch issuance.
//! The ordinary dispatcher alone authenticates, consumes and seals. This child
//! of batch may inspect its actual sealed payload without turning issuance of
//! an inert Token API credential into a new authentication or a renewed grant.
use super::super::*;
use super::VerifiedBatchClaims;

fn unavailable() -> AuthError {
    err(503, "native batch issuer custody changed")
}

fn digest<T: Serialize>(value: &T) -> Result<[u8; 32], AuthError> {
    let bytes = crate::secret_serde::to_vec(value, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| unavailable())?;
    Ok(crate::crypto::digest(&bytes))
}

enum Issuer {
    AppRole {
        role_name: String,
        role_id: Zeroizing<String>,
        secret_hash: Option<Zeroizing<String>>,
        role_digest: [u8; 32],
    },
    TokenApi {
        actor_digest: Zeroizing<String>,
        actor_state: [u8; 32],
        role: Option<(String, [u8; 32])>,
        issued_role: Option<token_roles::IssuedRole>,
        orphan: bool,
        bound_cidrs: Vec<String>,
    },
}

/// Not Clone, Deserialize or a Principal. It can bind one actual domain grant;
/// it cannot manufacture an issuer, reauthenticate or consume another use.
pub(crate) struct NativeBatchIssuerOwner {
    mount: String,
    mount_identity: AuthMount,
    path: String,
    earliest_issuance: u64,
    issuer: Issuer,
    issued: Option<VerifiedBatchClaims>,
}

impl AuthState {
    /// Closed selection only. Invalid input still reaches the original domain
    /// error path. A missing owner never grants permission to expose a batch.
    pub(crate) fn capture_native_batch_issuer(
        &self,
        actor: Option<&Principal>,
        method: &str,
        path: &str,
        body: &Value,
        clock: RequestClock,
    ) -> Result<Option<NativeBatchIssuerOwner>, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(None);
        }
        let mounts = self.effective_auth_mounts("");
        let earliest_issuance = self
            .token_api_observed_time(AuthorityTime::Precise(clock.admitted_at()))
            .seconds();
        if let Some((mount, binding)) = mounts
            .iter()
            .find(|(mount, entry)| entry.kind == "approle" && path == format!("auth/{mount}/login"))
        {
            let Some(role_id) = body.get("role_id").and_then(Value::as_str).map(str::trim) else {
                return Ok(None);
            };
            let scope = AuthScope {
                namespace: "",
                mount,
            };
            let Some((name, role)) = self
                .roles_at(scope)
                .and_then(|roles| roles.iter().find(|(_, role)| role.role_id == role_id))
            else {
                return Ok(None);
            };
            if !self.approle_uses_batch(scope, role) {
                return Ok(None);
            }
            let secret_hash = if role.bind_secret_id {
                body.get("secret_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .map(hash)
                    .map(Zeroizing::new)
            } else {
                None
            };
            return Ok(Some(NativeBatchIssuerOwner {
                mount: mount.clone(),
                mount_identity: binding.clone(),
                path: path.into(),
                earliest_issuance,
                issuer: Issuer::AppRole {
                    role_name: name.clone(),
                    role_id: Zeroizing::new(role_id.into()),
                    secret_hash,
                    role_digest: digest(role)?,
                },
                issued: None,
            }));
        }
        if !matches!(path, "auth/token/create" | "auth/token/create-orphan")
            && !path.starts_with("auth/token/create/")
        {
            return Ok(None);
        }
        let Some(actor) = actor else { return Ok(None) };
        let Some(parent) = self.tokens.get(&actor.digest) else {
            return Ok(None);
        };
        let Ok(selected_role) = self.selected_token_role("", path) else {
            return Ok(None);
        };
        let role = selected_role.as_ref().map(|(_, role)| role);
        let batch = match role {
            Some(role) => role.batch(body).unwrap_or(false),
            None => body.get("type").and_then(Value::as_str) == Some("batch"),
        };
        if !batch {
            return Ok(None);
        }
        let Ok(requested_orphan) = token_policies::weak_boolean(body.get("no_parent"), "no_parent")
        else {
            return Ok(None);
        };
        let orphan = role.map_or(
            path == "auth/token/create-orphan" || requested_orphan,
            token_roles::Role::orphan,
        );
        let bound_cidrs = role.map_or_else(
            || {
                if orphan {
                    Vec::new()
                } else {
                    parent.bound_cidrs.clone()
                }
            },
            token_roles::Role::bound_cidrs,
        );
        let Some(binding) = mounts.get("token").filter(|entry| entry.kind == "token") else {
            return Ok(None);
        };
        let issued_role = selected_role
            .as_ref()
            .map(|(name, role)| role.issued(name, path));
        let role_binding = selected_role
            .as_ref()
            .map(|(name, role)| digest(role).map(|value| (name.clone(), value)))
            .transpose()?;
        Ok(Some(NativeBatchIssuerOwner {
            mount: "token".into(),
            mount_identity: binding.clone(),
            path: path.into(),
            earliest_issuance,
            issuer: Issuer::TokenApi {
                actor_digest: Zeroizing::new(actor.digest.clone()),
                actor_state: digest(parent)?,
                role: role_binding,
                issued_role,
                orphan,
                bound_cidrs,
            },
            issued: None,
        }))
    }
}

impl NativeBatchIssuerOwner {
    pub(crate) fn check_source(&self, source: &AuthState) -> Result<(), AuthError> {
        if source.effective_auth_mounts("").get(&self.mount) != Some(&self.mount_identity) {
            return Err(unavailable());
        }
        match &self.issuer {
            Issuer::AppRole {
                role_name,
                role_id,
                role_digest,
                ..
            } => {
                let scope = AuthScope {
                    namespace: "",
                    mount: &self.mount,
                };
                let role = source
                    .roles_at(scope)
                    .and_then(|roles| roles.get(role_name))
                    .ok_or_else(unavailable)?;
                if role.role_id != role_id.as_str()
                    || digest(role)? != *role_digest
                    || !source.approle_uses_batch(scope, role)
                {
                    return Err(unavailable());
                }
            }
            Issuer::TokenApi {
                actor_digest,
                actor_state,
                role,
                ..
            } => {
                let actor = source
                    .tokens
                    .get(actor_digest.as_str())
                    .ok_or_else(unavailable)?;
                if digest(actor)? != *actor_state {
                    return Err(unavailable());
                }
                if let Some((name, expected)) = role {
                    let current = source
                        .token_roles
                        .get("")
                        .and_then(|roles| roles.get(name))
                        .ok_or_else(unavailable)?;
                    if digest(current)? != *expected {
                        return Err(unavailable());
                    }
                }
            }
        }
        Ok(())
    }

    /// Bind the actual sealed output once, after the original domain's exact
    /// Identity/namespace finalizer. No password, SID, bearer or TTL is reissued.
    pub(crate) fn bind_batch_reply(
        &mut self,
        source: &AuthState,
        candidate: &AuthState,
        body: &Value,
        time: AuthorityTime,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<(), AuthError> {
        self.check_source(source)?;
        if self.issued.is_some() || body["auth"]["token_type"].as_str() != Some("batch") {
            return Err(unavailable());
        }
        let raw = body["auth"]["client_token"]
            .as_str()
            .ok_or_else(unavailable)?;
        let claims = candidate
            .batch_authority
            .as_ref()
            .ok_or_else(unavailable)?
            .open_authenticated_payload(raw)
            .map_err(|_| unavailable())?;
        if !claims.namespace().is_empty()
            || claims.namespace_binding().is_none()
            || claims.policies().contains("root")
            || candidate.tokens.contains_key(&hash(raw))
            || claims.issued_at() < self.earliest_issuance
            || claims.issued_at() > time.seconds()
            || body["auth"]["accessor"].as_str() != Some("")
            || body["auth"]["renewable"].as_bool() != Some(false)
        {
            return Err(unavailable());
        }
        candidate.check_batch_namespace_binding(claims.namespace_binding(), "")?;
        match &self.issuer {
            Issuer::AppRole {
                role_name,
                role_id,
                secret_hash,
                ..
            } => {
                let scope = AuthScope {
                    namespace: "",
                    mount: &self.mount,
                };
                let role = source
                    .roles_at(scope)
                    .and_then(|roles| roles.get(role_name))
                    .ok_or_else(unavailable)?;
                let mut expected_role = role.clone();
                let mut metadata = approle_metadata::Metadata::default();
                let mut constraints = None;
                if role.bind_secret_id {
                    let id = secret_hash.as_ref().ok_or_else(unavailable)?;
                    let old = role
                        .approle_secrets()?
                        .get(id.as_str())
                        .ok_or_else(unavailable)?;
                    metadata =
                        approle_metadata::Metadata::new(old.metadata.clone().unwrap_or_default());
                    constraints = Some(approle_secret_id_cidrs::Constraints::from_secret(old));
                    match old.uses_remaining {
                        Some(0) => return Err(unavailable()),
                        Some(1) => {
                            expected_role.approle_secrets_mut()?.remove(id.as_str());
                        }
                        Some(remaining) => {
                            let next = expected_role
                                .approle_secrets_mut()?
                                .get_mut(id.as_str())
                                .ok_or_else(unavailable)?;
                            next.uses_remaining = Some(remaining - 1);
                            if let Some(issuance) = next.issuance.as_mut() {
                                issuance.record_use(claims.issued_at());
                            }
                        }
                        None => {}
                    }
                }
                metadata.insert("role_name".into(), role_name.clone());
                let current = candidate
                    .roles_at(scope)
                    .and_then(|roles| roles.get(role_name))
                    .ok_or_else(unavailable)?;
                let bound_cidrs =
                    approle_secret_id_cidrs::login(role, constraints.as_ref(), origin_peer)
                        .and_then(|cidrs| {
                            security_contract::bind_login_ip(role, cidrs, origin_peer)
                        })?;
                let explicit = (role.token_explicit_max_ttl > 0)
                    .then(|| checked_expiry(claims.issued_at(), role.token_explicit_max_ttl))
                    .transpose()?;
                let expires = source.approle_token_expiry(
                    scope,
                    role,
                    claims.issued_at(),
                    explicit,
                    0,
                    claims.issued_at(),
                )?;
                if current.role_id != role_id.as_str()
                    || digest(current)? != digest(&expected_role)?
                    || claims.path() != self.path
                    || claims.display_name() != format!("approle-{role_name}")
                    || claims.parent().is_some()
                    || claims.public_origin().is_some()
                    || claims.token_role().is_some()
                    || claims.precision().is_some()
                    || claims.entity_id().is_none()
                    || claims.metadata() != &metadata.0
                    || claims.policies() != &approle_no_default::issued_policies(role)
                    || claims.bound_cidrs() != bound_cidrs
                    || claims.expires_at() != expires
                {
                    return Err(unavailable());
                }
                candidate.check_batch_claims_observed(&claims, "", time)?;
            }
            Issuer::TokenApi {
                actor_digest,
                issued_role,
                orphan,
                bound_cidrs,
                ..
            } => {
                let expected_path = issued_role
                    .as_ref()
                    .map_or(self.path.as_str(), |role| role.path.as_str());
                let expected_parent = (!*orphan).then_some(actor_digest.as_str());
                if claims.path() != expected_path
                    || claims.parent() != expected_parent
                    || digest(&claims.token_role())? != digest(&issued_role.as_ref())?
                    || claims.bound_cidrs() != bound_cidrs
                    || claims.precision().is_none()
                    || claims
                        .public_origin()
                        .is_none_or(|origin| origin.sdk_binding().is_some())
                {
                    return Err(unavailable());
                }
                // The real Token API finalizer already checked the original
                // issuer. Inspect that same parent's present liveness, without
                // treating a newly issued inert credential as an admitted actor.
                if let Some(parent) = expected_parent {
                    candidate
                        .lease_issuer_by_digest_observed(parent, "", time)
                        .ok_or_else(denied)?;
                }
            }
        }
        self.issued = Some(claims);
        Ok(())
    }

    pub(crate) fn owns_issued_reply(&self, raw: &str) -> bool {
        self.issued
            .as_ref()
            .is_some_and(|claims| claims.token_digest() == hash(raw))
    }

    /// Recheck the one captured sealed grant under the selected current Auth.
    /// The Service independently checks original actor/Identity/ACL, the exact
    /// terminal receipt, unchanged reply bytes and its pre-audit File/HA proof.
    pub(crate) fn check_current(
        &self,
        auth: &AuthState,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        let Some(claims) = self.issued.as_ref() else {
            return Ok(());
        };
        auth.check_batch_namespace_binding(claims.namespace_binding(), "")?;
        let authority = auth.batch_authority.as_ref().ok_or_else(unavailable)?;
        authority.validate().map_err(|_| unavailable())?;
        let key = authority
            .find_key(claims.authority_id(), claims.key_id())
            .map_err(|_| unavailable())?;
        if claims.issued_at() < key.created_at || auth.tokens.contains_key(claims.token_digest()) {
            return Err(unavailable());
        }
        match &self.issuer {
            Issuer::AppRole { .. } => auth.check_batch_claims_observed(claims, "", time),
            Issuer::TokenApi { .. } => {
                if let Some(parent) = claims.parent() {
                    auth.lease_issuer_by_digest_observed(parent, "", time)
                        .ok_or_else(denied)?;
                }
                Ok(())
            }
        }
    }
}
