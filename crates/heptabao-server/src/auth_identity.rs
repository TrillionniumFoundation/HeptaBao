//! Auth-owned token binding. Policy projection remains request-local, never a
//! copied grant in a durable token or a substitute for token-policy attenuation.
use super::*;

pub(crate) struct LoginIdentity {
    pub(crate) mount: String,
    pub(crate) alias: String,
}

pub(crate) struct ExternalGroups {
    pub(crate) mount: String,
    pub(crate) alias: String,
    pub(crate) names: BTreeSet<String>,
}

impl Principal {
    pub(crate) fn entity_id(&self) -> Option<&str> {
        self.token.entity_id.as_deref()
    }

    pub(crate) fn bind_identity_policies(&mut self, policies: BTreeSet<String>) {
        self.identity_policies = policies;
        self.identity_checked = true;
    }
}

impl AuthState {
    pub(crate) fn has_live_identity_state(&self) -> bool {
        self.tokens.values().any(|token| token.entity_id.is_some())
            || self
                .auth_mounts
                .values()
                .flat_map(|mounts| mounts.values())
                .any(|mount| mount.accessor.is_some())
    }

    pub(crate) fn mount_accessor(&self, namespace: &str, mount: &str) -> Result<String, AuthError> {
        self.effective_auth_mounts(namespace)
            .get(mount)
            .and_then(|entry| entry.accessor.clone())
            .ok_or_else(denied)
    }

    pub(crate) fn has_mount_accessor(&self, namespace: &str, accessor: &str) -> bool {
        self.effective_auth_mounts(namespace)
            .values()
            .any(|entry| entry.accessor.as_deref() == Some(accessor))
    }

    pub(crate) fn bind_issued_entity(
        &mut self,
        response: &mut AuthResponse,
        namespace: &str,
        mount: &str,
        entity_id: &str,
    ) -> Result<(), AuthError> {
        let raw = response.body["auth"]["client_token"]
            .as_str()
            .ok_or_else(denied)?;
        let token = self.tokens.get_mut(&hash(raw)).ok_or_else(denied)?;
        if token.namespace != namespace
            || token.root
            || token.auth_mount.as_deref() != Some(mount)
            || token.entity_id.is_some()
        {
            return Err(denied());
        }
        token.entity_id = Some(entity_id.to_owned());
        response.body["auth"]["entity_id"] = Value::String(entity_id.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_bound_principal_requires_service_projection_before_authorization()
    -> Result<(), AuthError> {
        let (mut state, raw) = AuthState::bootstrap(100)?;
        let id = hash(&raw);
        let token = state.tokens.get_mut(&id).ok_or_else(denied)?;
        token.root = false;
        token.policies = BTreeSet::from(["default".into()]);
        token.entity_id = Some("e-00000000000000000000000000000001".into());
        let mut principal = state.authenticate(&raw, 100)?;
        assert!(
            state
                .authorize_request(&principal, "", "auth/token/lookup-self", "read", 100)
                .is_err()
        );
        principal.bind_identity_policies(BTreeSet::new());
        assert!(
            state
                .authorize_request(&principal, "", "auth/token/lookup-self", "read", 100)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn identity_legacy_token_and_mount_fields_remain_readable_without_invented_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let (state, raw) = AuthState::bootstrap(100)?;
        let mut value = serde_json::to_value(&state)?;
        value["tokens"]
            .as_object_mut()
            .ok_or("missing tokens")?
            .values_mut()
            .for_each(|token| {
                if let Some(token) = token.as_object_mut() {
                    token.remove("entity_id");
                }
            });
        let mut restored: AuthState = serde_json::from_value(value)?;
        assert!(restored.authenticate(&raw, 100)?.entity_id().is_none());
        assert_eq!(
            state.mount_accessor("", "approle")?,
            restored.mount_accessor("", "approle")?
        );
        assert_ne!(
            state.mount_accessor("", "approle")?,
            state.mount_accessor("tenant", "approle")?
        );
        Ok(())
    }
}
