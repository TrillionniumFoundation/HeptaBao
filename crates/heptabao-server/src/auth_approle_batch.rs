//! AppRole batch selection and the independently committed consumption of an
//! authenticated finite SecretID when outer Identity/wrapping denies issuance.
use super::*;

/// An authenticated, single-credential transition. This is transient authority,
/// never serialized, cloned, or logged. It cannot install an auth/engine candidate.
pub(crate) struct AppRoleSecretIdConsumption {
    namespace: String,
    mount: String,
    mount_identity: AuthMount,
    role_name: String,
    role_id: String,
    secret_hash: String,
    old: SecretId,
    next: Option<SecretId>,
}
impl Drop for AppRoleSecretIdConsumption {
    fn drop(&mut self) {
        self.namespace.zeroize();
        self.mount.zeroize();
        self.role_name.zeroize();
        self.role_id.zeroize();
        self.secret_hash.zeroize();
        self.old.accessor.zeroize();
        if let Some(next) = self.next.as_mut() {
            next.accessor.zeroize();
        }
    }
}
impl AppRoleSecretIdConsumption {
    pub(crate) fn apply(self, auth: &mut AuthState) -> Result<(), AuthError> {
        let scope = AuthScope {
            namespace: &self.namespace,
            mount: &self.mount,
        };
        if auth.effective_auth_mounts(&self.namespace).get(&self.mount)
            != Some(&self.mount_identity)
        {
            return Err(err(
                409,
                "AppRole mount changed during credential consumption",
            ));
        }
        let role = auth
            .roles_at(scope)
            .and_then(|roles| roles.get(&self.role_name))
            .ok_or_else(|| err(409, "AppRole changed during credential consumption"))?;
        if role.role_id != self.role_id || role.secret_ids.get(&self.secret_hash) != Some(&self.old)
        {
            return Err(err(409, "AppRole credential changed during consumption"));
        }
        let role = auth
            .roles_at_mut(scope)
            .get_mut(&self.role_name)
            .ok_or_else(|| err(409, "AppRole changed during credential consumption"))?;
        if let Some(next) = self.next.as_ref() {
            role.secret_ids
                .insert(self.secret_hash.clone(), next.clone());
        } else if let Some((mut key, mut secret)) = role.secret_ids.remove_entry(&self.secret_hash)
        {
            key.zeroize();
            secret.accessor.zeroize();
        }
        Ok(())
    }
}

pub(super) fn update_role_type(
    role: &mut Role,
    body: &Value,
) -> Result<Option<&'static str>, AuthError> {
    let mut warning = None;
    if let Some(value) = body.get("token_type") {
        // The pinned Go AppRole handler panics on null before tokenutil sees
        // it. Refuse it explicitly rather than reproducing an HTTP disconnect.
        let value = value
            .as_str()
            .ok_or_else(|| bad("token_type must be a string"))?;
        let kind = match value {
            "default-service" => {
                warning = Some("default-service has no useful meaning; adjusting to service");
                batch_issuance::UserTokenType::Service
            }
            "default-batch" => {
                warning = Some("default-batch has no useful meaning; adjusting to batch");
                batch_issuance::UserTokenType::Batch
            }
            _ => batch_issuance::UserTokenType::parse(&Value::String(value.into()))?,
        };
        role.token_type = Some(kind);
    }
    validate_role_type(role)?;
    Ok(warning)
}
fn validate_role_type(role: &Role) -> Result<(), AuthError> {
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
    pub(crate) fn has_approle_batch_state(&self) -> bool {
        self.roles
            .values()
            .flat_map(|roles| roles.values())
            .chain(
                self.mounted_roles
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|roles| roles.values()),
            )
            .any(|role| role.token_type.is_some())
            || self
                .auth_mounts
                .values()
                .flat_map(|mounts| mounts.values())
                .any(|mount| mount.kind == "approle" && mount.token_type.is_some())
    }
    pub(crate) fn validate_approle_batch_state(&self) -> Result<(), AuthError> {
        for role in self.roles.values().flat_map(|roles| roles.values()).chain(
            self.mounted_roles
                .values()
                .flat_map(|mounts| mounts.values())
                .flat_map(|roles| roles.values()),
        ) {
            validate_role_type(role)?;
        }
        for (namespace, roles) in &self.roles {
            if roles.values().any(|role| role.token_type.is_some())
                && !self.online_mount_enabled(namespace, "approle", "approle")
            {
                return Err(bad("native AppRole token type has no AppRole mount"));
            }
        }
        for (namespace, mounts) in &self.mounted_roles {
            for (mount, roles) in mounts {
                if roles.values().any(|role| role.token_type.is_some())
                    && !self.online_mount_enabled(namespace, mount, "approle")
                {
                    return Err(bad("native AppRole token type has no AppRole mount"));
                }
            }
        }
        Ok(())
    }
    pub(super) fn approle_uses_batch(&self, scope: AuthScope<'_>, role: &Role) -> bool {
        self.effective_auth_mounts(scope.namespace)
            .get(scope.mount)
            .is_some_and(|mount| {
                mount.kind == "approle"
                    && mount
                        .token_type
                        .unwrap_or_default()
                        .resolves_batch(role.token_type.unwrap_or_default())
            })
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn approle_secret_id_consumption(
        &self,
        scope: AuthScope<'_>,
        role_name: &str,
        role_id: &str,
        secret_hash: &str,
        old: SecretId,
        next: Option<SecretId>,
        now: u64,
    ) -> Result<AppRoleSecretIdConsumption, AuthError> {
        let remaining = old
            .uses_remaining
            .filter(|value| *value > 0)
            .ok_or_else(|| err(500, "invalid finite SecretID transition"))?;
        let expected = if remaining == 1 {
            None
        } else {
            let mut secret = old.clone();
            secret.uses_remaining = Some(remaining - 1);
            if let Some(issuance) = secret.issuance.as_mut() {
                issuance.record_use(now);
            }
            Some(secret)
        };
        if expected != next {
            return Err(err(500, "invalid finite SecretID transition"));
        }
        let mount_identity = self
            .effective_auth_mounts(scope.namespace)
            .get(scope.mount)
            .filter(|mount| mount.kind == "approle")
            .cloned()
            .ok_or_else(|| err(409, "AppRole mount is unavailable"))?;
        Ok(AppRoleSecretIdConsumption {
            namespace: scope.namespace.into(),
            mount: scope.mount.into(),
            mount_identity,
            role_name: role_name.into(),
            role_id: role_id.into(),
            secret_hash: secret_hash.into(),
            old,
            next,
        })
    }
}

fn human_seconds(seconds: u64) -> String {
    if seconds >= 3600 {
        format!(
            "{}h{}m{}s",
            seconds / 3600,
            seconds % 3600 / 60,
            seconds % 60
        )
    } else if seconds >= 60 {
        format!("{}m{}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
#[test]
fn duration_warning_uses_go_integer_second_format() {
    for (seconds, expected) in [
        (0, "0s"),
        (59, "59s"),
        (60, "1m0s"),
        (61, "1m1s"),
        (3599, "59m59s"),
        (3600, "1h0m0s"),
        (3601, "1h0m1s"),
        (3660, "1h1m0s"),
        (86400, "24h0m0s"),
    ] {
        assert_eq!(human_seconds(seconds), expected);
    }
}

impl AuthState {
    pub(super) fn approle_issuance_warning(
        &self,
        scope: AuthScope<'_>,
        role: &Role,
        granted: u64,
    ) -> Result<Option<String>, AuthError> {
        let (mount_default, _) = self.auth_mount_lease_defaults(scope)?;
        let (label, proposed) = if role.token_period > 0 {
            ("period", role.token_period)
        } else {
            (
                "TTL",
                if role.token_ttl > 0 {
                    role.token_ttl
                } else {
                    mount_default
                },
            )
        };
        Ok((proposed>granted).then(||format!("{label} of \"{}\" exceeded the effective max_ttl of \"{}\"; {label} value is capped accordingly",human_seconds(proposed),human_seconds(granted))))
    }
}
