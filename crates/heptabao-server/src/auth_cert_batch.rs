//! Certificate roles share native mount token-type precedence. The leaf still
//! authenticates through the existing certificate verifier before any grant.
use super::*;

pub(super) fn validate_role_type(role: &CertRole) -> Result<(), AuthError> {
    if role.token_type == Some(batch_issuance::UserTokenType::Batch) && role.token_num_uses != 0 {
        return Err(bad(
            "'token_type' cannot be 'batch' when set to generate tokens with limited use count",
        ));
    }
    Ok(())
}

impl AuthState {
    /// Parent integration must reject this independent state below schema48,
    /// including explicit default/service and mount-only type configuration.
    pub(crate) fn has_cert_batch_state(&self) -> bool {
        self.has_cert_issued_metadata()
            || self
                .cert_roles
                .values()
                .flat_map(|mounts| mounts.values())
                .flat_map(|roles| roles.values())
                .any(|role| role.token_type.is_some() || cert_ttl::has_native_shape(role))
            || self.tokens.values().any(|token| {
                token.auth_cert_role.is_some()
                    && token.parent.is_none()
                    && token.period > 0
                    && !matches!(
                        token.auth_provenance,
                        Some(TokenAuthProvenance::TokenApi { .. })
                    )
            })
            || self
                .auth_mounts
                .values()
                .flat_map(|mounts| mounts.values())
                .any(|mount| mount.kind == "cert" && mount.token_type.is_some())
    }

    pub(crate) fn validate_cert_batch_state(&self) -> Result<(), AuthError> {
        self.validate_cert_issued_metadata()?;
        for (namespace, mounts) in &self.cert_roles {
            for (mount, roles) in mounts {
                for role in roles.values() {
                    validate_role_type(role)?;
                    cert_ttl::validate_limits(role)?;
                    if role.token_type == Some(batch_issuance::UserTokenType::Batch)
                        && role.token_period > 0
                        && role.legacy_period != role.token_period
                    {
                        return Err(bad("invalid persisted certificate batch period"));
                    }
                    for (shadow, native) in [
                        (role.legacy_ttl, role.token_ttl),
                        (role.legacy_max_ttl, role.token_max_ttl),
                        (role.legacy_period, role.token_period),
                    ] {
                        if shadow > 0 && shadow != native {
                            return Err(bad("invalid certificate TTL alias shadow"));
                        }
                    }
                    if (role.token_type.is_some() || cert_ttl::has_native_shape(role))
                        && !self.online_mount_enabled(namespace, mount, "cert")
                    {
                        return Err(bad("native cert token type has no cert mount"));
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn cert_uses_batch(&self, scope: AuthScope<'_>, role: &CertRole) -> bool {
        self.effective_auth_mounts(scope.namespace)
            .get(scope.mount)
            .is_some_and(|mount| {
                mount.kind == "cert"
                    && mount
                        .token_type
                        .unwrap_or_default()
                        .resolves_batch(role.token_type.unwrap_or_default())
            })
    }
}
