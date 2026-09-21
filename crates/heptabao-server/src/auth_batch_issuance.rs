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
    fn parse(value: &Value) -> Result<Self, AuthError> {
        match value.as_str().or_else(|| value.is_null().then_some("")) {
            Some("" | "default") => Ok(Self::Default),
            Some("service") => Ok(Self::Service),
            Some("batch") => Ok(Self::Batch),
            _ => Err(bad("invalid token_type")),
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
    fn resolves_batch(self, user: UserTokenType) -> bool {
        match self {
            Self::Batch => true,
            Self::Service => false,
            Self::DefaultService => user == UserTokenType::Batch,
            Self::DefaultBatch => user != UserTokenType::Service,
        }
    }
}

pub(crate) struct PendingBatchGrant {
    claims: batch::BatchClaims,
    login_mount: Option<String>,
}
impl Drop for PendingBatchGrant {
    fn drop(&mut self) {
        self.login_mount.zeroize();
    }
}
impl PendingBatchGrant {
    pub(super) fn response(
        claims: batch::BatchClaims,
        login_mount: Option<String>,
    ) -> AuthResponse {
        let body = json!({"auth":{
            "accessor":"", "policies":claims.policies, "token_policies":claims.policies,
            "entity_id":claims.entity_id.as_deref().unwrap_or(""), "metadata":claims.metadata,
            "lease_duration":claims.expires_at-claims.issued_at, "renewable":false,
            "token_type":"batch", "orphan":claims.parent.is_none(), "num_uses":0
        }});
        AuthResponse {
            pending_batch: Some(Self {
                claims,
                login_mount,
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
    if user.token_type == Some(UserTokenType::Batch)
        && (user.token_period != 0 || user.token_num_uses != 0)
    {
        return Err(bad("batch user tokens cannot have period or num_uses"));
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
            || self
                .mounted_users
                .values()
                .flat_map(|mounts| mounts.values())
                .flat_map(|users| users.values())
                .any(|user| user.token_type.is_some())
    }
    pub(crate) fn validate_batch_issuance_state(&self) -> Result<(), AuthError> {
        self.validate_batch_authority()?;
        for mounts in self.auth_mounts.values() {
            for mount in mounts.values() {
                if mount.token_type.is_some() && mount.kind != "userpass" {
                    return Err(bad("token_type requires a native userpass mount"));
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
    pub(crate) fn finish_pending_batch(
        &mut self,
        response: &mut AuthResponse,
        namespace: &str,
        now: u64,
    ) -> Result<(), AuthError> {
        let Some(pending) = response.pending_batch.take() else {
            return Ok(());
        };
        if pending.claims.namespace != namespace
            || pending.claims.issued_at != now
            || pending.claims.expires_at <= now
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
        // These are a fresh grant's original parent/namespace, not a target
        // inspection. Parent liveness remains authoritative through publication.
        if let Some(parent) = pending.claims.parent.as_deref() {
            self.lease_issuer_by_digest(parent, namespace, now)
                .ok_or_else(denied)?;
        }
        let mut authority = match &self.batch_authority {
            Some(authority) => authority.clone(),
            None => batch::BatchKeyAuthority::new(now)
                .map_err(|_| err(503, "batch authority unavailable"))?,
        };
        let raw = authority
            .seal(pending.claims.clone(), now)
            .map_err(|_| err(503, "batch sealing unavailable"))?;
        response.body["auth"]["client_token"] = json!(raw.as_str());
        self.batch_authority = Some(authority);
        response.mutated = true;
        Ok(())
    }
}
