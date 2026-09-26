//! Userpass source constraints bind both password-authenticated issuance and
//! the resulting token. Current account edits never rebind issued tokens.
use super::*;

pub(super) fn update(user: &mut User, body: &Value) -> Result<(), AuthError> {
    // The framework validates both alias field types even when the new value
    // wins. Do not parse the ignored old address value or let it override new.
    if let Some(value) = body.get("bound_cidrs") {
        let valid = match value {
            Value::Null | Value::String(_) => true,
            Value::Array(values) => values.iter().all(Value::is_string),
            _ => false,
        };
        if !valid {
            return Err(bad("bound_cidrs must be a list or comma-separated string"));
        }
    }
    if let Some(value) = body.get("token_bound_cidrs") {
        let parsed = token_cidrs::field(&json!({"token_bound_cidrs":value}))?;
        user.bound_cidrs = if body.get("bound_cidrs").is_some() {
            parsed.clone()
        } else {
            Vec::new()
        };
        user.token_bound_cidrs = parsed;
    } else if let Some(value) = body.get("bound_cidrs") {
        let parsed = token_cidrs::field(&json!({"token_bound_cidrs":value}))?;
        user.bound_cidrs = parsed.clone();
        user.token_bound_cidrs = parsed;
    }
    Ok(())
}

fn constrained(user: &User) -> bool {
    !user.token_bound_cidrs.is_empty() || !user.bound_cidrs.is_empty()
}
fn validate_user(user: &User) -> Result<(), AuthError> {
    token_cidrs::validate(&user.token_bound_cidrs)?;
    token_cidrs::validate(&user.bound_cidrs)?;
    if !user.bound_cidrs.is_empty() && user.bound_cidrs != user.token_bound_cidrs {
        return Err(bad("inconsistent userpass source constraint aliases"));
    }
    Ok(())
}

impl AuthState {
    pub(crate) fn has_userpass_token_bound_cidrs(&self) -> bool {
        self.users
            .values()
            .flat_map(|users| users.values())
            .chain(
                self.mounted_users
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|users| users.values()),
            )
            .any(constrained)
            || self.tokens.values().any(|token| {
                !token.bound_cidrs.is_empty()
                    && matches!(
                        token.auth_provenance,
                        Some(TokenAuthProvenance::Userpass { .. })
                    )
            })
    }

    pub(crate) fn validate_userpass_token_bound_cidrs(&self) -> Result<(), AuthError> {
        for (namespace, users) in &self.users {
            for user in users.values() {
                validate_user(user)?;
                if constrained(user)
                    && !self.online_mount_enabled(namespace, "userpass", "userpass")
                {
                    return Err(bad("userpass source constraints have no userpass mount"));
                }
            }
        }
        for (namespace, mounts) in &self.mounted_users {
            for (mount, users) in mounts {
                for user in users.values() {
                    validate_user(user)?;
                    if constrained(user) && !self.online_mount_enabled(namespace, mount, "userpass")
                    {
                        return Err(bad("userpass source constraints have no userpass mount"));
                    }
                }
            }
        }
        Ok(())
    }
}
