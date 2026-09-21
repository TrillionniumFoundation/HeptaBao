//! Userpass renews from the issuing account's current token limits and policy
//! set. Passwords and MFA authenticate login only; they are never retained in
//! token provenance or inferred from a mutable display name.
use super::*;

pub(super) fn update_token_limits(user: &mut User, body: &Value) -> Result<(), AuthError> {
    user.token_ttl = jwt_renewal::role_duration(
        body,
        if body.get("token_ttl").is_some() {
            "token_ttl"
        } else {
            "ttl"
        },
        user.token_ttl,
    )?;
    user.token_max_ttl = jwt_renewal::role_duration(
        body,
        if body.get("token_max_ttl").is_some() {
            "token_max_ttl"
        } else {
            "max_ttl"
        },
        user.token_max_ttl,
    )?;
    user.token_period = jwt_renewal::role_duration(body, "token_period", user.token_period)?;
    user.token_explicit_max_ttl =
        jwt_renewal::role_duration(body, "token_explicit_max_ttl", user.token_explicit_max_ttl)?;
    user.token_num_uses = if body.get("token_num_uses").is_some_and(Value::is_null) {
        0
    } else {
        number(body, "token_num_uses", user.token_num_uses)?
    };
    validate_limits(user)
}

fn validate_limits(user: &User) -> Result<(), AuthError> {
    if user.token_ttl > MAX_TTL
        || user.token_max_ttl > MAX_TTL
        || user.token_max_ttl > 0 && user.token_ttl > user.token_max_ttl
        || user.token_period > MAX_TTL
        || user.token_explicit_max_ttl > MAX_TTL
    {
        return Err(bad("invalid userpass token TTL limits"));
    }
    Ok(())
}

impl AuthState {
    fn native_userpass_accounts(&self) -> impl Iterator<Item = &User> {
        self.users
            .iter()
            .filter(|(namespace, _)| self.online_mount_enabled(namespace, "userpass", "userpass"))
            .flat_map(|(_, users)| users.values())
            .chain(
                self.mounted_users
                    .iter()
                    .flat_map(move |(namespace, mounts)| {
                        mounts
                            .iter()
                            .filter(move |(mount, _)| {
                                self.online_mount_enabled(namespace, mount, "userpass")
                            })
                            .flat_map(|(_, users)| users.values())
                    }),
            )
    }

    pub(crate) fn has_userpass_native_tokens(&self) -> bool {
        self.native_userpass_accounts().any(|user| {
            user.token_ttl == 0
                || user.token_max_ttl == 0
                || user.token_period > 0
                || user.token_explicit_max_ttl > 0
                || !user.policies.contains("default")
        }) || self
            .users
            .values()
            .flat_map(|users| users.values())
            .chain(
                self.mounted_users
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|users| users.values()),
            )
            .any(|user| user.token_period > 0 || user.token_explicit_max_ttl > 0)
            || self.tokens.values().any(|token| {
                matches!(
                    token.auth_provenance,
                    Some(TokenAuthProvenance::Userpass { .. })
                )
            })
    }

    pub(crate) fn validate_userpass_native_tokens(&self) -> Result<(), AuthError> {
        for user in self.users.values().flat_map(|users| users.values()).chain(
            self.mounted_users
                .values()
                .flat_map(|mounts| mounts.values())
                .flat_map(|users| users.values()),
        ) {
            validate_limits(user)?;
        }
        for (namespace, users) in &self.users {
            if !self.online_mount_enabled(namespace, "userpass", "userpass")
                && users
                    .values()
                    .any(|user| user.token_period > 0 || user.token_explicit_max_ttl > 0)
            {
                return Err(bad("native userpass parameters have no userpass mount"));
            }
        }
        for (namespace, mounts) in &self.mounted_users {
            for (mount, users) in mounts {
                if !self.online_mount_enabled(namespace, mount, "userpass")
                    && users
                        .values()
                        .any(|user| user.token_period > 0 || user.token_explicit_max_ttl > 0)
                {
                    return Err(bad("native userpass parameters have no userpass mount"));
                }
            }
        }
        for token in self.tokens.values() {
            if let Some(TokenAuthProvenance::Userpass { username }) = &token.auth_provenance
                && (token.root
                    || token.parent.is_some()
                    || !token.auth_origin_known
                    || token.wrapping.is_some()
                    || !valid_name(username)
                    || token.period > MAX_TTL
                    || token.policies.contains("root")
                    || token.auth_cert_role.is_some()
                    || token.auth_cert_sha256.is_some()
                    || !token.auth_mount.as_ref().is_some_and(|mount| {
                        self.online_mount_enabled(&token.namespace, mount, "userpass")
                    }))
            {
                return Err(bad("invalid userpass token provenance"));
            }
        }
        Ok(())
    }

    pub(super) fn renew_userpass_token(
        &mut self,
        namespace: &str,
        target: &str,
        operation: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<AuthResponse>, AuthError> {
        let token = self.tokens.get(target).ok_or_else(denied)?;
        let Some(TokenAuthProvenance::Userpass { username }) = token.auth_provenance.as_ref()
        else {
            if token.auth_provenance.is_none()
                && token.parent.is_none()
                && token.auth_mount.as_ref().is_some_and(|mount| {
                    self.online_mount_enabled(&token.namespace, mount, "userpass")
                })
            {
                return Err(bad(
                    "legacy userpass token has no issuing account provenance; log in again",
                ));
            }
            return Ok(None);
        };
        if token.namespace != namespace || token.parent.is_some() {
            return Err(denied());
        }
        if !token.renewable {
            return Err(bad("token is not renewable"));
        }
        let mount = token.auth_mount.as_deref().ok_or_else(denied)?;
        if !self.online_mount_enabled(namespace, mount, "userpass") {
            return Err(denied());
        }
        let scope = AuthScope { namespace, mount };
        let Some(user) = self.users_at(scope).and_then(|users| users.get(username)) else {
            // OpenBao's backend returns no response for a removed account.
            // The accessor route requires auth data; bearer routes return 204.
            return if operation == "renew-accessor" {
                Err(err(500, "userpass account no longer exists during renewal"))
            } else {
                Ok(Some(empty(false)))
            };
        };
        if !provider_renewal::same_policies(&user.policies, &token.policies) {
            return Err(err(500, "userpass policies changed during renewal"));
        }
        let increment = duration(body, "increment", 0)?;
        let expires_at = self.userpass_token_expiry(
            scope,
            user,
            token.created_at,
            token.max_expires_at,
            increment,
            now,
        )?;
        let username = username.clone();
        let token = self.tokens.get_mut(target).ok_or_else(denied)?;
        token.expires_at = Some(expires_at);
        Ok(Some(AuthResponse {
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: json!({"auth": {
                "accessor": token.accessor, "policies": token.policies, "token_policies": token.policies,
                "entity_id":token.entity_id.as_deref().unwrap_or(""), "metadata":{"username":username},
                "lease_duration":expires_at-now,"renewable":true,"token_type":"service"
            }}),
        }))
    }

    pub(super) fn userpass_token_expiry(
        &self,
        scope: AuthScope<'_>,
        user: &User,
        issued_at: u64,
        explicit_max_expires_at: Option<u64>,
        increment: u64,
        now: u64,
    ) -> Result<u64, AuthError> {
        self.native_token_expiry(
            scope,
            NativeTokenLimits {
                ttl: user.token_ttl,
                max_ttl: user.token_max_ttl,
                period: user.token_period,
            },
            issued_at,
            explicit_max_expires_at,
            increment,
            now,
        )
    }
}
