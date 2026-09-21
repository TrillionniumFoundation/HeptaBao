//! Fresh native userpass mounts use canonical account keys. An absent durable
//! mode retains exact historical names, including old renewal provenance.
use super::*;
use std::borrow::Cow;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UserpassNameMode {
    AsciiLowerV1,
}

pub(super) fn fresh_default_auth_mounts() -> BTreeMap<String, AuthMount> {
    let mut mounts = legacy_auth_mounts();
    if let Some(userpass) = mounts.get_mut("userpass") {
        userpass.userpass_name_mode = Some(UserpassNameMode::AsciiLowerV1);
    }
    mounts
}

impl AuthState {
    /// Called only for a newly initialized root or newly created namespace;
    /// never from deserialization, implicit legacy lookup or unrelated writes.
    pub(crate) fn initialize_fresh_namespace_auth(
        &mut self,
        namespace: &str,
    ) -> Result<(), AuthError> {
        if self.auth_mounts.contains_key(namespace) || !self.namespace_is_empty(namespace) {
            return Err(err(409, "new namespace already has authentication state"));
        }
        self.auth_mounts
            .insert(namespace.into(), fresh_default_auth_mounts());
        Ok(())
    }

    /// The caller already proved the whole namespace empty and removed its
    /// registry entry. Only untouched factory metadata is eligible for removal.
    pub(crate) fn remove_fresh_namespace_auth_defaults(&mut self, namespace: &str) {
        if self
            .auth_mounts
            .get(namespace)
            .is_some_and(|mounts| *mounts == fresh_default_auth_mounts())
        {
            self.auth_mounts.remove(namespace);
        }
    }

    fn has_native_userpass_names(&self, scope: AuthScope<'_>) -> bool {
        self.auth_mounts
            .get(scope.namespace)
            .and_then(|mounts| mounts.get(scope.mount))
            .is_some_and(|mount| {
                mount.kind == "userpass"
                    && mount.userpass_name_mode == Some(UserpassNameMode::AsciiLowerV1)
            })
    }

    pub(super) fn userpass_account_key<'a>(
        &self,
        scope: AuthScope<'_>,
        name: &'a str,
    ) -> Cow<'a, str> {
        if self.has_native_userpass_names(scope)
            && name.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            Cow::Owned(name.to_ascii_lowercase())
        } else {
            Cow::Borrowed(name)
        }
    }

    #[cfg(test)]
    pub(crate) fn remove_name_modes_for_legacy_format_test(&mut self) {
        // Historical bootstrap used implicit factory mounts. Preserve changed
        // registries, but do not introduce an explicit one into schema-1 fixtures.
        let factory = fresh_default_auth_mounts();
        self.auth_mounts.retain(|_, mounts| *mounts != factory);
        for mount in self
            .auth_mounts
            .values_mut()
            .flat_map(|mounts| mounts.values_mut())
        {
            mount.userpass_name_mode = None;
        }
    }

    pub(crate) fn has_userpass_name_modes(&self) -> bool {
        self.auth_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| mount.userpass_name_mode.is_some())
    }

    pub(crate) fn validate_userpass_name_modes(&self) -> Result<(), AuthError> {
        for (namespace, mounts) in &self.auth_mounts {
            for (name, mount) in mounts {
                if mount.userpass_name_mode.is_none() {
                    continue;
                }
                if mount.kind != "userpass" {
                    return Err(bad("userpass name mode requires a userpass mount"));
                }
                let scope = AuthScope {
                    namespace,
                    mount: name,
                };
                if self.users_at(scope).is_some_and(|users| {
                    users.keys().any(|key| {
                        !valid_name(key) || key.bytes().any(|byte| byte.is_ascii_uppercase())
                    })
                }) {
                    return Err(bad("native userpass contains a noncanonical account"));
                }
            }
        }
        for token in self.tokens.values() {
            if let (Some(mount), Some(TokenAuthProvenance::Userpass { username })) =
                (token.auth_mount.as_deref(), token.auth_provenance.as_ref())
                && self.has_native_userpass_names(AuthScope {
                    namespace: &token.namespace,
                    mount,
                })
                && username.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                return Err(bad(
                    "native userpass contains noncanonical token provenance",
                ));
            }
        }
        Ok(())
    }
}
