//! Issuance decisions and transient grants. No bearer is sealed until Service
//! finishes Identity projection on the same candidate that will be committed.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(super) enum UserTokenType {
    #[default]
    Default,
    Service,
    Batch,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(super) enum MountTokenType {
    #[default]
    DefaultService,
    DefaultBatch,
    Service,
    Batch,
}
impl UserTokenType {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Service => "service",
            Self::Batch => "batch",
        }
    }
    pub(super) fn parse(value: &Value) -> Result<Self, AuthError> {
        match value.as_str().or_else(|| value.is_null().then_some("")) {
            Some("" | "default") => Ok(Self::Default),
            Some("service") => Ok(Self::Service),
            Some("batch") => Ok(Self::Batch),
            _ => Err(bad("invalid 'token_type' value")),
        }
    }
}
impl MountTokenType {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::DefaultService => "default-service",
            Self::DefaultBatch => "default-batch",
            Self::Service => "service",
            Self::Batch => "batch",
        }
    }
    pub(super) fn parse(value: &Value) -> Result<Self, AuthError> {
        match value.as_str() {
            Some("default-service") => Ok(Self::DefaultService),
            Some("default-batch") => Ok(Self::DefaultBatch),
            Some("service") => Ok(Self::Service),
            Some("batch") => Ok(Self::Batch),
            _ => Err(bad("invalid mount token_type")),
        }
    }
    pub(super) fn resolves_batch(self, user: UserTokenType) -> bool {
        match self {
            Self::Batch => true,
            Self::Service => false,
            Self::DefaultService => user == UserTokenType::Batch,
            Self::DefaultBatch => user != UserTokenType::Service,
        }
    }
}

// This one-use proof is confined to its pending Token API grant. It is not a
// second Principal: it cannot authorize another operation or be deserialized.
struct TokenApiBatchPublication {
    actor_digest: String,
    accessor: String,
    entity_id: Option<String>,
    origin_peer: Option<std::net::IpAddr>,
}
impl Drop for TokenApiBatchPublication {
    fn drop(&mut self) {
        self.actor_digest.zeroize();
        self.accessor.zeroize();
        self.entity_id.zeroize();
    }
}
pub(crate) struct PendingBatchGrant {
    claims: batch::BatchClaims,
    login_mount: Option<String>,
    // Transient native Token API publication proof; never serialized, returned
    // to the client, or accepted from an opaque/provider response.
    token_api_publication: Option<TokenApiBatchPublication>,
}
impl Drop for PendingBatchGrant {
    fn drop(&mut self) {
        self.login_mount.zeroize();
    }
}
impl PendingBatchGrant {
    pub(super) fn bind_token_api_publication(
        &mut self,
        auth: &AuthState,
        actor: &Principal,
        namespace: &str,
        path: &str,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        if self.claims.token_api_precision.is_none()
            || self.token_api_publication.is_some()
            || self.claims.namespace != namespace
            || time.exact().is_none()
        {
            return Err(err(503, "precise batch publication proof is unavailable"));
        }
        auth.authorize_request_observed(actor, namespace, path, "update", time)?;
        let issuer = auth
            .check_principal_observed(actor, namespace, time)?
            .service()?;
        self.token_api_publication = Some(TokenApiBatchPublication {
            actor_digest: actor.digest.clone(),
            accessor: issuer.accessor.clone(),
            entity_id: issuer.entity_id.clone(),
            origin_peer: actor.origin_peer,
        });
        Ok(())
    }
    pub(super) fn response(
        claims: batch::BatchClaims,
        login_mount: Option<String>,
    ) -> AuthResponse {
        let body = json!({"auth":{
            "accessor":"", "policies":claims.policies, "token_policies":claims.policies,
            "entity_id":claims.entity_id.as_deref().unwrap_or(""), "metadata":claims.public_origin.as_ref().map_or_else(|| json!(claims.metadata), |origin| origin.issued_json(&claims.metadata)),
            "lease_duration":claims.token_api_precision.as_ref().map_or(claims.expires_at-claims.issued_at, |lease|lease.granted_ttl.public_seconds()), "renewable":false,
            "token_type":"batch", "orphan":claims.parent.is_none(), "num_uses":0
        }});
        AuthResponse {
            approle_secret_consumption: None,
            pending_batch: Some(Self {
                claims,
                login_mount,
                token_api_publication: None,
            }),
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body,
        }
    }
}

pub(super) fn update_user_type(user: &mut User, body: &Value) -> Result<(), AuthError> {
    if let Some(value) = body.get("token_type") {
        user.token_type = Some(UserTokenType::parse(value)?);
    }
    validate_user_type(user)
}
fn validate_user_type(user: &User) -> Result<(), AuthError> {
    if user.token_type == Some(UserTokenType::Batch) {
        if user.token_period != 0 {
            return Err(bad(
                "'token_type' cannot be 'batch' or 'default_batch' when set to generate periodic tokens",
            ));
        }
        if user.token_num_uses != 0 {
            return Err(bad(
                "'token_type' cannot be 'batch' or 'default_batch' when set to generate tokens with limited use count",
            ));
        }
    }
    Ok(())
}

impl AuthState {
    #[cfg(test)]
    pub(crate) fn remove_unused_batch_authority_for_legacy_format_test(&mut self) {
        assert!(!self.has_batch_issuance_state());
        assert!(
            self.batch_authority
                .as_ref()
                .is_none_or(|authority| { authority.is_unused_for_legacy_fixture() })
        );
        self.batch_authority = None;
    }
    pub(crate) fn has_batch_issuance_state(&self) -> bool {
        self.auth_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| mount.token_type.is_some())
            || self
                .users
                .values()
                .flat_map(|users| users.values())
                .any(|user| user.token_type.is_some())
            || self.has_jwt_batch_state()
            || self.has_cert_batch_state()
            || self
                .mounted_users
                .values()
                .flat_map(|mounts| mounts.values())
                .flat_map(|users| users.values())
                .any(|user| user.token_type.is_some())
    }
    pub(crate) fn validate_batch_issuance_state(&self) -> Result<(), AuthError> {
        self.validate_batch_authority()?;
        self.validate_cert_batch_state()?;
        for mounts in self.auth_mounts.values() {
            for mount in mounts.values() {
                if mount.token_type.is_some()
                    && !matches!(mount.kind.as_str(), "userpass" | "approle" | "jwt" | "cert")
                {
                    return Err(bad(
                        "token_type requires a native userpass, AppRole, JWT or cert mount",
                    ));
                }
            }
        }
        for (namespace, users) in &self.users {
            for user in users.values() {
                validate_user_type(user)?;
                if user.token_type.is_some()
                    && !self.online_mount_enabled(namespace, "userpass", "userpass")
                {
                    return Err(bad("native token type has no userpass mount"));
                }
            }
        }
        for (namespace, mounts) in &self.mounted_users {
            for (mount, users) in mounts {
                for user in users.values() {
                    validate_user_type(user)?;
                    if user.token_type.is_some()
                        && !self.online_mount_enabled(namespace, mount, "userpass")
                    {
                        return Err(bad("native token type has no userpass mount"));
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn userpass_uses_batch(&self, scope: AuthScope<'_>, user: &User) -> bool {
        self.effective_auth_mounts(scope.namespace)
            .get(scope.mount)
            .is_some_and(|mount| {
                mount.kind == "userpass"
                    && mount
                        .token_type
                        .unwrap_or_default()
                        .resolves_batch(user.token_type.unwrap_or_default())
            })
    }
    pub(super) fn bind_pending_batch_entity(
        response: &mut AuthResponse,
        namespace: &str,
        mount: &str,
        entity_id: &str,
    ) -> Result<bool, AuthError> {
        let Some(pending) = response.pending_batch.as_mut() else {
            return Ok(false);
        };
        if pending.claims.namespace != namespace
            || pending.login_mount.as_deref() != Some(mount)
            || pending.claims.entity_id.is_some()
        {
            return Err(denied());
        }
        pending.claims.entity_id = Some(entity_id.into());
        response.body["auth"]["entity_id"] = json!(entity_id);
        Ok(true)
    }
    #[cfg(test)]
    pub(crate) fn finish_pending_batch(
        &mut self,
        response: &mut AuthResponse,
        namespace: &str,
        now: u64,
    ) -> Result<(), AuthError> {
        self.finish_pending_batch_observed(response, namespace, now, AuthorityTime::Coarse(now))
    }

    pub(crate) fn finish_pending_batch_observed(
        &mut self,
        response: &mut AuthResponse,
        namespace: &str,
        now: u64,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        let time = self.token_api_observed_time(time);
        let Some(pending) = response.pending_batch.take() else {
            return Ok(());
        };
        let precision = pending.claims.token_api_precision.as_ref();
        let issuance_seconds = if precision.is_some() {
            pending.claims.issued_at
        } else {
            now
        };
        let valid_publication = if precision.is_some() {
            // Creating an inert opaque credential remains a successful Token
            // API operation. Its original whole CreationTime/exact TTL never
            // moves, and all later admission/owner resolution still checks it.
            time.exact().is_some() && time.seconds() >= issuance_seconds
        } else {
            pending.claims.expires_at > now
                && time.batch_live(None, pending.claims.issued_at, pending.claims.expires_at)
        };
        if pending.claims.namespace != namespace
            || pending.claims.issued_at != issuance_seconds
            || !valid_publication
            || pending.login_mount.is_some() && pending.claims.entity_id.is_none()
        {
            return Err(denied());
        }
        if response.body["auth"]["policies"]
            .as_array()
            .is_some_and(|policies| policies.iter().any(|p| p.as_str() == Some("root")))
        {
            return Err(bad("batch tokens cannot have root policy"));
        }
        if precision.is_some() {
            let proof = pending
                .token_api_publication
                .as_ref()
                .ok_or_else(|| err(503, "precise batch publication proof is unavailable"))?;
            // The admitted last use may finish its operation. This does not
            // permit an exhausted ancestor, replaced issuer or changed CIDRs.
            let issuer = self.active_token_observed(&proof.actor_digest, time, false)?;
            token_cidrs::check(&issuer.bound_cidrs, proof.origin_peer)?;
            if issuer.accessor != proof.accessor
                || issuer.entity_id != proof.entity_id
                || !issuer.root && issuer.namespace != namespace
            {
                return Err(denied());
            }
        }
        // These are a fresh grant's original parent/namespace, not a target
        // inspection. Parent liveness remains authoritative through publication.
        if let Some(parent) = pending.claims.parent.as_deref() {
            self.lease_issuer_by_digest_observed(parent, namespace, time)
                .ok_or_else(denied)?;
        }
        let mut authority = match &self.batch_authority {
            Some(authority) => authority.clone(),
            None => batch::BatchKeyAuthority::new(issuance_seconds)
                .map_err(|_| err(503, "batch authority unavailable"))?,
        };
        let raw = authority
            .seal(pending.claims.clone(), issuance_seconds)
            .map_err(|_| err(503, "batch sealing unavailable"))?;
        response.body["auth"]["client_token"] = json!(raw.as_str());
        if pending.claims.public_origin.is_some() {
            self.public_origin_floor = Some(public_origin::Floor::V1);
        }
        self.batch_authority = Some(authority);
        response.mutated = true;
        Ok(())
    }
}
