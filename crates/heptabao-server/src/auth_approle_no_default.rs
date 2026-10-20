//! AppRole keeps configured policy lists separate from issuance defaults.
//!
//! OpenBao 2.7.1 TokenParams stores the raw list and adds the default policy at
//! issuance unless token_no_default_policy is true. None on a historical Role
//! means its list was already normalized; never guess which default was explicit.
use super::*;

pub(crate) const STATE_SCHEMA: u32 = 135;

pub(super) fn update(role: &mut Role, body: &Value) -> Result<(), AuthError> {
    if let Some(value) = body.get("token_no_default_policy") {
        let flag = token_policies::weak_boolean(Some(value), "token_no_default_policy")
            .map_err(|error| {
                bad(error
                    .message
                    .strip_prefix("Field validation failed: ")
                    .unwrap_or(&error.message))
            })?;
        role.token_no_default_policy = Some(flag);
    }
    let field = if body.get("token_policies").is_some() {
        "token_policies"
    } else {
        "policies"
    };
    if let Some(value) = body.get(field) {
        role.policies = if value.is_null() {
            BTreeSet::new()
        } else {
            policies(body, field, &role.policies, false)?
        };
        // An explicit replacement establishes a raw list. A flag-only update
        // never removes a historical default from the unknown-origin list.
        role.token_no_default_policy.get_or_insert(false);
    }
    Ok(())
}

pub(super) fn issued_policies(role: &Role) -> BTreeSet<String> {
    let mut policies = role.policies.clone();
    if !role.token_no_default_policy.unwrap_or(false) {
        policies.insert("default".into());
    }
    policies
}

pub(super) fn omit_empty_token_policies(response: &mut AuthResponse) {
    if response.body["auth"]["token_policies"]
        .as_array()
        .is_some_and(Vec::is_empty)
        && let Some(auth) = response.body["auth"].as_object_mut()
    {
        auth.remove("token_policies");
    }
}

impl AuthState {
    pub(crate) fn has_approle_no_default_policy(&self) -> bool {
        self.roles
            .values()
            .flat_map(|roles| roles.values())
            .chain(
                self.mounted_roles
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|roles| roles.values()),
            )
            .any(|role| role.token_no_default_policy.is_some())
            || self.tokens.values().any(|token| {
                matches!(
                    token.auth_provenance,
                    Some(TokenAuthProvenance::AppRole { .. })
                ) && !token.policies.contains("default")
            })
    }

    pub(crate) fn validate_approle_no_default_policy(&self) -> Result<(), AuthError> {
        for (namespace, roles) in &self.roles {
            if roles
                .values()
                .any(|role| role.token_no_default_policy.is_some())
                && !self.online_mount_enabled(namespace, "approle", "approle")
            {
                return Err(bad("AppRole policy metadata has no AppRole mount"));
            }
        }
        for (namespace, mounts) in &self.mounted_roles {
            for (mount, roles) in mounts {
                if roles
                    .values()
                    .any(|role| role.token_no_default_policy.is_some())
                    && !self.online_mount_enabled(namespace, mount, "approle")
                {
                    return Err(bad("AppRole policy metadata has no AppRole mount"));
                }
            }
        }
        Ok(())
    }
}
