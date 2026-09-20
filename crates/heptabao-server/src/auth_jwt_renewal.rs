//! JWT assertions authenticate login only. Native JWT service-token renewal
//! rereads its issuing role and lifetime limits without revalidating the JWT,
//! contacting its issuer or comparing the role's current policy/claim bindings.
use super::*;

impl AuthState {
    pub(crate) fn has_jwt_renewal_state(&self) -> bool {
        self.tokens
            .values()
            .any(|token| matches!(token.auth_provenance, Some(TokenAuthProvenance::Jwt { .. })))
            || self
                .jwt_mounts
                .values()
                .flat_map(|mounts| mounts.values())
                .flat_map(|mount| mount.roles.values())
                .any(|role| role.token_period > 0 || role.token_explicit_max_ttl > 0)
    }

    pub(crate) fn validate_jwt_renewal_state(&self) -> Result<(), AuthError> {
        for role in self
            .jwt_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .flat_map(|mount| mount.roles.values())
        {
            if role.token_period > MAX_TTL || role.token_explicit_max_ttl > MAX_TTL {
                return Err(bad("invalid JWT role renewal limits"));
            }
        }
        for token in self.tokens.values() {
            if let Some(TokenAuthProvenance::Jwt { role_name }) = &token.auth_provenance
                && (token.root
                    || token.parent.is_some()
                    || !token.auth_origin_known
                    || token.wrapping.is_some()
                    || !valid_name(role_name)
                    || token.period > MAX_TTL
                    || token.policies.contains("root")
                    || token.auth_cert_role.is_some()
                    || token.auth_cert_sha256.is_some()
                    || !token.auth_mount.as_ref().is_some_and(|mount| {
                        self.online_mount_enabled(&token.namespace, mount, "jwt")
                    }))
            {
                return Err(bad("invalid JWT renewal provenance"));
            }
        }
        Ok(())
    }

    pub(super) fn renew_jwt_token(
        &mut self,
        namespace: &str,
        target: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<AuthResponse>, AuthError> {
        let token = self.tokens.get(target).ok_or_else(denied)?;
        let Some(TokenAuthProvenance::Jwt { role_name }) = token.auth_provenance.as_ref() else {
            if token.auth_provenance.is_none()
                && token.parent.is_none()
                && token
                    .auth_mount
                    .as_ref()
                    .is_some_and(|mount| self.online_mount_enabled(&token.namespace, mount, "jwt"))
            {
                return Err(bad(
                    "legacy JWT token has no issuing role provenance; log in again",
                ));
            }
            return Ok(None);
        };
        if token.namespace != namespace {
            return Err(denied());
        }
        if !token.renewable {
            return Err(bad("token is not renewable"));
        }
        let mount = token.auth_mount.as_deref().ok_or_else(denied)?;
        let scope = AuthScope { namespace, mount };
        if !self.online_mount_enabled(namespace, mount, "jwt") {
            return Err(denied());
        }
        // Missing native roles are an internal renewal error in OpenBao 2.6.2.
        // Policy, subject, group, audience, key and issuer changes are not a
        // renewal predicate; the existing token keeps its issued policies.
        let role = self
            .jwt_at(scope)
            .and_then(|state| state.roles.get(role_name))
            .ok_or_else(|| err(500, "JWT role does not exist during renewal"))?;
        let increment = duration(body, "increment", 0)?;
        let expires_at = self.jwt_token_expiry(
            scope,
            role,
            token.created_at,
            token.max_expires_at,
            increment,
            now,
        )?;
        let token = self.tokens.get_mut(target).ok_or_else(denied)?;
        token.expires_at = Some(expires_at);
        Ok(Some(AuthResponse {
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: json!({"auth": {
                "accessor":token.accessor,"policies":token.policies,"token_policies":token.policies,
                "entity_id":token.entity_id.as_deref().unwrap_or(""),
                "lease_duration":expires_at-now,"renewable":true,"token_type":"service"
            }}),
        }))
    }

    pub(super) fn jwt_token_expiry(
        &self,
        scope: AuthScope<'_>,
        role: &JwtRole,
        issued_at: u64,
        explicit_max_expires_at: Option<u64>,
        increment: u64,
        now: u64,
    ) -> Result<u64, AuthError> {
        self.native_token_expiry(
            scope,
            NativeTokenLimits {
                ttl: role.token_ttl,
                max_ttl: role.token_max_ttl,
                period: role.token_period,
            },
            issued_at,
            explicit_max_expires_at,
            increment,
            now,
        )
    }
}
