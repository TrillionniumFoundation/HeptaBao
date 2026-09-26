//! Token API lookup reports the immutable initial grant, independently of the
//! previous renewal grant and the live token mount's default/max TTL.
use super::*;

impl AuthState {
    pub(crate) fn has_token_api_creation_ttl(&self) -> bool {
        self.tokens.values().any(|token| {
            matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::TokenApi {
                    issued_creation_ttl: Some(_),
                })
            )
        })
    }

    pub(crate) fn validate_token_api_creation_ttl(&self) -> Result<(), AuthError> {
        for token in self.tokens.values() {
            let Some(TokenAuthProvenance::TokenApi {
                issued_creation_ttl: Some(ttl),
            }) = &token.auth_provenance
            else {
                continue;
            };
            // Direct-login provenance and wrappers cannot acquire this field.
            if *ttl > MAX_TTL
                || token.wrapping.is_some()
                || token.auth_cert_role.is_some()
                || token.auth_cert_sha256.is_some()
                || token.period > MAX_TTL
            {
                return Err(bad("invalid Token API creation TTL"));
            }
            if *ttl == 0 {
                if !token.root
                    || token.policies.len() != 1
                    || !token.policies.contains("root")
                    || !token.namespace.is_empty()
                    || token.expires_at.is_some()
                    || token.max_expires_at.is_some()
                    || token.period != 0
                    || token.renewable
                    || !token.bound_cidrs.is_empty()
                    || token.token_api_lease_ttl.is_some()
                {
                    return Err(bad("invalid non-expiring Token API creation TTL"));
                }
            } else {
                let initial_expiry = token
                    .created_at
                    .checked_add(*ttl)
                    .ok_or_else(|| bad("invalid Token API initial expiry"))?;
                if token.expires_at.is_none()
                    || token
                        .max_expires_at
                        .is_some_and(|maximum| initial_expiry > maximum)
                {
                    return Err(bad("invalid Token API initial expiry"));
                }
                // A later renewal can shorten or extend the active expiry.
                // Neither that expiry nor the current mount settings can
                // reconstruct or invalidate this captured issuance grant.
            }
        }
        Ok(())
    }
}
