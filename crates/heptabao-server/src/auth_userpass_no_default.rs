//! Policy-list provenance preserves the upstream nil/empty renewal distinction.
//! Existing normalized lists remain unknown (None); reads/login never guess it.
use super::*;
pub(super) fn update(user: &mut User, body: &Value) -> Result<(), AuthError> {
    if let Some(value) = body.get("token_no_default_policy") {
        user.token_no_default_policy = if value.is_null() {
            false
        } else {
            boolean(
                body,
                "token_no_default_policy",
                user.token_no_default_policy,
            )?
        };
    }
    if body.get("token_policies").is_some() || body.get("policies").is_some() {
        user.token_policies_configured = Some(true);
    }
    Ok(())
}
pub(super) fn nil_policy_mismatch(user: &User, issued: &BTreeSet<String>) -> bool {
    user.token_policies_configured == Some(false) && user.policies.is_empty() && issued.is_empty()
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
fn modern(user: &User) -> bool {
    user.token_no_default_policy || user.token_policies_configured.is_some()
}
fn validate(user: &User) -> Result<(), AuthError> {
    if user.token_policies_configured == Some(false) && !user.policies.is_empty() {
        return Err(bad("nonempty userpass policies cannot be an omitted list"));
    }
    Ok(())
}
impl AuthState {
    pub(crate) fn has_userpass_no_default_policy(&self) -> bool {
        self.users
            .values()
            .flat_map(|u| u.values())
            .chain(
                self.mounted_users
                    .values()
                    .flat_map(|m| m.values())
                    .flat_map(|u| u.values()),
            )
            .any(modern)
            || self.tokens.values().any(|token| {
                matches!(
                    token.auth_provenance,
                    Some(TokenAuthProvenance::Userpass { .. })
                ) && !token.policies.contains("default")
            })
    }
    pub(crate) fn validate_userpass_no_default_policy(&self) -> Result<(), AuthError> {
        for (namespace, users) in &self.users {
            for user in users.values() {
                validate(user)?;
                if modern(user) && !self.online_mount_enabled(namespace, "userpass", "userpass") {
                    return Err(bad("userpass policy metadata has no userpass mount"));
                }
            }
        }
        for (namespace, mounts) in &self.mounted_users {
            for (mount, users) in mounts {
                for user in users.values() {
                    validate(user)?;
                    if modern(user) && !self.online_mount_enabled(namespace, mount, "userpass") {
                        return Err(bad("userpass policy metadata has no userpass mount"));
                    }
                }
            }
        }
        Ok(())
    }
}
