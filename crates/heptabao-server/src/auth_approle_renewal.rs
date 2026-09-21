//! AppRole renewal reads the live role's ordinary TTL/maximum/period, while
//! retaining only the explicit cap captured at issue. Old persisted caps stay
//! conservative because finite legacy state cannot distinguish cap sources.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecretIdIssuance {
    ttl: u64,
    created_at: u64,
    last_updated_at: u64,
}

impl SecretIdIssuance {
    pub(super) fn new(ttl: u64, now: u64) -> Self {
        Self {
            ttl,
            created_at: now,
            last_updated_at: now,
        }
    }

    pub(super) fn record_use(&mut self, now: u64) {
        self.last_updated_at = self.last_updated_at.max(now);
    }
}

pub(super) fn secret_id_info(secret: &SecretId) -> Value {
    let mut info = json!({
        "secret_id_accessor": secret.accessor,
        "secret_id_num_uses": secret.uses_remaining.unwrap_or(0),
        "expiration_time_unix": secret.expires_at,
        "expiration_time": secret.expires_at.map(crate::engines::timestamp)
            .unwrap_or_else(|| "0001-01-01T00:00:00Z".into()),
        "metadata": {}, "cidr_list": null, "token_bound_cidrs": []
    });
    if let Some(issued) = &secret.issuance {
        info["secret_id_ttl"] = json!(issued.ttl);
        info["creation_time"] = json!(crate::engines::timestamp(issued.created_at));
        info["last_updated_time"] = json!(crate::engines::timestamp(issued.last_updated_at));
    }
    info
}

pub(super) fn role_duration(body: &Value, field: &str, previous: u64) -> Result<u64, AuthError> {
    if body.get(field).is_none_or(Value::is_null) {
        Ok(previous)
    } else {
        duration(body, field, previous)
    }
}

pub(super) fn role_count(body: &Value, field: &str, previous: u64) -> Result<u64, AuthError> {
    if body.get(field).is_some_and(Value::is_null) {
        Ok(0)
    } else {
        number(body, field, previous)
    }
}

pub(super) fn validate_role_limits(role: &Role) -> Result<(), AuthError> {
    if role.token_ttl > MAX_TTL
        || role.token_max_ttl > MAX_TTL
        || role.token_max_ttl > 0 && role.token_ttl > role.token_max_ttl
        || role.token_period > MAX_TTL
        || role.token_explicit_max_ttl > MAX_TTL
        || role.secret_id_ttl > MAX_TTL
    {
        return Err(bad("AppRole TTL is outside bounds"));
    }
    Ok(())
}

impl AuthState {
    pub(crate) fn has_approle_native_defaults(&self) -> bool {
        self.roles
            .values()
            .flat_map(|roles| roles.values())
            .chain(
                self.mounted_roles
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|roles| roles.values()),
            )
            .any(|role| {
                role.token_ttl == 0
                    || role.token_max_ttl == 0
                    || role
                        .secret_ids
                        .values()
                        .any(|secret| secret.issuance.is_some())
            })
    }

    pub(crate) fn validate_approle_native_defaults(&self) -> Result<(), AuthError> {
        for role in self.roles.values().flat_map(|roles| roles.values()).chain(
            self.mounted_roles
                .values()
                .flat_map(|mounts| mounts.values())
                .flat_map(|roles| roles.values()),
        ) {
            validate_role_limits(role)?;
            for secret in role.secret_ids.values() {
                if let Some(issued) = &secret.issuance
                    && (issued.ttl > MAX_TTL
                        || issued.last_updated_at < issued.created_at
                        || if issued.ttl == 0 {
                            secret.expires_at.is_some()
                        } else {
                            secret.expires_at.is_none_or(|expiry| {
                                expiry <= issued.created_at
                                    || expiry - issued.created_at > issued.ttl
                            })
                        })
                {
                    return Err(bad("invalid native SecretID issuance metadata"));
                }
            }
        }
        Ok(())
    }

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
            pending_batch: None,
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
