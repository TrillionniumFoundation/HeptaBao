//! AppRole renewal reads the live role's ordinary TTL/maximum/period, while
//! retaining only the explicit cap captured at issue. Old persisted caps stay
//! conservative because finite legacy state cannot distinguish cap sources.
use super::*;

impl AuthState {
    pub(super) fn renew_approle_token(
        &mut self,
        namespace: &str,
        target: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<AuthResponse>, AuthError> {
        let token = self.tokens.get(target).ok_or_else(denied)?;
        let Some(TokenAuthProvenance::AppRole { role_name }) = token.auth_provenance.as_ref()
        else {
            return Ok(None);
        };
        if token.namespace != namespace || token.parent.is_some() {
            return Err(denied());
        }
        if !token.renewable {
            return Err(bad("token is not renewable"));
        }
        let mount = token.auth_mount.as_deref().ok_or_else(denied)?;
        let scope = AuthScope { namespace, mount };
        if !self.online_mount_enabled(namespace, mount, "approle") {
            return Err(denied());
        }
        let role = self
            .roles_at(scope)
            .and_then(|roles| roles.get(role_name))
            .ok_or_else(|| err(500, "AppRole role does not exist during renewal"))?;
        let increment = duration(body, "increment", 0)?;
        let expires_at = self.approle_token_expiry(
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
                "accessor": token.accessor, "policies": token.policies, "token_policies": token.policies,
                "entity_id": token.entity_id.as_deref().unwrap_or(""),
                "lease_duration": expires_at - now, "renewable": true, "token_type": "service"
            }}),
        }))
    }

    pub(super) fn approle_token_expiry(
        &self,
        scope: AuthScope<'_>,
        role: &Role,
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
