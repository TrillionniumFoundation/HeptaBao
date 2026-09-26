//! Ordinary JWT roles use generic token types. OIDC has its own role and login
//! lifecycle and is deliberately not selected by these predicates.
use super::*;

pub(super) fn validate_role_type(role: &JwtRole) -> Result<(), AuthError> {
    if role.token_type == Some(batch_issuance::UserTokenType::Batch) {
        if role.token_period != 0 {
            return Err(bad(
                "'token_type' cannot be 'batch' or 'default_batch' when set to generate periodic tokens",
            ));
        }
        if role.token_num_uses != 0 {
            return Err(bad(
                "'token_type' cannot be 'batch' or 'default_batch' when set to generate tokens with limited use count",
            ));
        }
    }
    Ok(())
}

impl AuthState {
    pub(crate) fn has_jwt_batch_state(&self) -> bool {
        self.jwt_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .flat_map(|mount| mount.roles.values())
            .any(|role| role.token_type.is_some())
            || self
                .auth_mounts
                .values()
                .flat_map(|mounts| mounts.values())
                .any(|mount| mount.kind == "jwt" && mount.token_type.is_some())
    }

    pub(crate) fn validate_jwt_batch_state(&self) -> Result<(), AuthError> {
        for (namespace, mounts) in &self.jwt_mounts {
            for (mount, state) in mounts {
                for role in state.roles.values() {
                    validate_role_type(role)?;
                    if role.token_type.is_some()
                        && !self.online_mount_enabled(namespace, mount, "jwt")
                    {
                        return Err(bad("native JWT token type has no JWT mount"));
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn jwt_uses_batch(&self, scope: AuthScope<'_>, role: &JwtRole) -> bool {
        self.effective_auth_mounts(scope.namespace)
            .get(scope.mount)
            .is_some_and(|mount| {
                mount.kind == "jwt"
                    && mount
                        .token_type
                        .unwrap_or_default()
                        .resolves_batch(role.token_type.unwrap_or_default())
            })
    }
}
