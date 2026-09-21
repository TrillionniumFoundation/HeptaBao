//! Persisted system defaults separate old inherited one-hour state from native
//! installations. Mount overrides remain live; only explicit issued token caps
//! (including ambiguous historical caps) remain absolute deadlines.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SystemLeaseDefaults {
    default_ttl: u64,
    max_ttl: u64,
}

impl SystemLeaseDefaults {
    pub(super) fn native() -> Self {
        Self {
            default_ttl: MAX_TTL,
            max_ttl: MAX_TTL,
        }
    }

    fn legacy() -> Self {
        Self {
            default_ttl: LEGACY_DEFAULT_TTL,
            max_ttl: MAX_TTL,
        }
    }

    fn validate(self) -> Result<Self, AuthError> {
        if self.default_ttl == 0
            || self.max_ttl == 0
            || self.default_ttl > self.max_ttl
            || self.max_ttl > MAX_TTL
        {
            return Err(bad("invalid persisted system lease defaults"));
        }
        Ok(self)
    }
}

impl AuthState {
    /// Older-format unit fixtures must omit fields unavailable to that binary.
    /// Actual process upgrade coverage uses a preserved historical binary.
    #[cfg(test)]
    pub(crate) fn omit_lease_metadata_for_legacy_fixture(&mut self) {
        self.system_lease_defaults = None;
        for token in self.tokens.values_mut() {
            token.token_api_lease_ttl = None;
        }
    }

    pub(crate) fn has_system_lease_defaults(&self) -> bool {
        self.system_lease_defaults.is_some()
            || self
                .tokens
                .values()
                .any(|token| token.token_api_lease_ttl.is_some())
    }

    pub(crate) fn validate_system_lease_defaults(&self) -> Result<(), AuthError> {
        self.system_lease_defaults()?;
        for token in self.tokens.values() {
            if let Some(ttl) = token.token_api_lease_ttl
                && (ttl == 0
                    || ttl > MAX_TTL
                    || !matches!(token.auth_provenance, Some(TokenAuthProvenance::TokenApi))
                    || token.expires_at.is_none()
                    || token.wrapping.is_some())
            {
                return Err(bad("invalid Token API renewal lease metadata"));
            }
        }
        Ok(())
    }

    pub(super) fn system_lease_defaults(&self) -> Result<SystemLeaseDefaults, AuthError> {
        self.system_lease_defaults
            .unwrap_or_else(SystemLeaseDefaults::legacy)
            .validate()
    }

    /// The API reports inherited mount values before issuance-time truncation.
    /// A mount maximum below the inherited default is valid and caps issuance.
    pub(super) fn auth_mount_lease_defaults(
        &self,
        scope: AuthScope<'_>,
    ) -> Result<(u64, u64), AuthError> {
        let system = self.system_lease_defaults()?;
        let mount = self
            .effective_auth_mounts(scope.namespace)
            .get(scope.mount)
            .cloned()
            .ok_or_else(|| err(404, "auth mount not found"))?;
        if mount.default_lease_ttl > MAX_TTL
            || mount.max_lease_ttl > MAX_TTL
            || mount.default_lease_ttl > 0
                && mount.max_lease_ttl > 0
                && mount.default_lease_ttl > mount.max_lease_ttl
        {
            return Err(bad("invalid persisted auth mount TTL limits"));
        }
        Ok((
            if mount.default_lease_ttl == 0 {
                system.default_ttl
            } else {
                mount.default_lease_ttl
            },
            if mount.max_lease_ttl == 0 {
                system.max_ttl
            } else {
                mount.max_lease_ttl
            },
        ))
    }

    pub(super) fn renew_token_api_token(
        &mut self,
        namespace: &str,
        target: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<AuthResponse>, AuthError> {
        let token = self.tokens.get(target).ok_or_else(denied)?;
        if !matches!(token.auth_provenance, Some(TokenAuthProvenance::TokenApi)) {
            return Ok(None);
        }
        if token.namespace != namespace {
            return Err(denied());
        }
        if !token.renewable {
            return Err(bad("token is not renewable"));
        }
        let increment = duration(body, "increment", 0)?;
        let expires_at = self.native_token_expiry(
            AuthScope {
                namespace,
                mount: "token",
            },
            NativeTokenLimits {
                // The native token backend returns the previous grant, not
                // the current mount default. Old state has no grant history;
                // keep its former one-hour omitted-increment semantics.
                ttl: token.token_api_lease_ttl.unwrap_or(LEGACY_DEFAULT_TTL),
                max_ttl: 0,
                period: token.period,
            },
            token.created_at,
            token.max_expires_at,
            increment,
            now,
        )?;
        let system_defaults = self.system_lease_defaults()?;
        let token = self.tokens.get_mut(target).ok_or_else(denied)?;
        token.expires_at = Some(expires_at);
        token.token_api_lease_ttl = Some(expires_at - now);
        let response = AuthResponse {
            approle_secret_consumption: None,
            pending_batch: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: json!({"auth": {
                "accessor":token.accessor,"policies":token.policies,"token_policies":token.policies,
                "entity_id":token.entity_id.as_deref().unwrap_or(""),
                "lease_duration":expires_at-now,"renewable":true,"token_type":"service"
            }}),
        };
        self.system_lease_defaults.get_or_insert(system_defaults);
        Ok(Some(response))
    }
}
