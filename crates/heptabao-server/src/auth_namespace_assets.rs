//! Exact typed namespace auth partition. Root recovery, batch authority,
//! inherited lease defaults and the global wrapping clock stay in AuthState.
//! No JSON field name or caller marker selects this owner.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceAssets {
    namespace: String,
    tokens: BTreeMap<String, Token>,
    policies: Option<BTreeMap<String, Policy>>,
    token_roles: Option<BTreeMap<String, token_roles::Role>>,
    password_policies: Option<BTreeMap<String, password_policy::PasswordPolicy>>,
    users: Option<BTreeMap<String, User>>,
    roles: Option<BTreeMap<String, Role>>,
    mounted_users: Option<BTreeMap<String, BTreeMap<String, User>>>,
    mounted_roles: Option<BTreeMap<String, BTreeMap<String, Role>>>,
    auth_mounts: Option<BTreeMap<String, AuthMount>>,
    jwt_mounts: Option<BTreeMap<String, JwtMountState>>,
    kubernetes_mounts: Option<BTreeMap<String, kubernetes::KubernetesMount>>,
    oidc_mounts: Option<BTreeMap<String, oidc::OidcMount>>,
    ldap_mounts: Option<BTreeMap<String, LdapMount>>,
    ldap_groups: Option<BTreeMap<String, BTreeMap<String, BTreeSet<String>>>>,
    ldap_native_users: Option<BTreeMap<String, BTreeMap<String, LdapNativeUser>>>,
    radius_mounts: Option<BTreeMap<String, RadiusMount>>,
    radius_native_users: Option<BTreeMap<String, BTreeMap<String, BTreeSet<String>>>>,
    kerberos_mounts: Option<BTreeMap<String, kerberos::KerberosMount>>,
    plugin_auth_mounts: Option<BTreeMap<String, PluginAuthMount>>,
    cert_roles: Option<BTreeMap<String, BTreeMap<String, CertRole>>>,
}

impl NamespaceAssets {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
    pub(crate) fn validate(&self, actual: &str) -> Result<(), AuthError> {
        if actual.is_empty()
            || self.namespace != actual
            || self.tokens.values().any(|token| token.namespace != actual)
        {
            return Err(err(503, "namespace auth owner binding rejected"));
        }
        Ok(())
    }
}

impl AuthState {
    /// Stored verifiers identify a candidate owner only; no token backing leaves it.
    pub(crate) fn namespace_token_verifiers(&self, actual: &str) -> Vec<String> {
        self.tokens
            .iter()
            .filter(|(_, token)| token.namespace == actual)
            .map(|(verifier, _)| verifier.clone())
            .collect()
    }

    pub(crate) fn namespace_token_route_verifier(raw: &str) -> Option<String> {
        (raw.len() <= 256 && raw.starts_with("hvs.")).then(|| hash(raw))
    }

    /// Refresh every other owner from current admitted auth. The sole private
    /// namespace backing remains in this disposable context, never the live state.
    pub(crate) fn closed_auth_context(
        &self,
        current: &Self,
        actual: &str,
    ) -> Result<Self, AuthError> {
        let mut private = self.clone();
        let assets = private.detach_namespace(actual)?;
        let mut context = current.clone();
        context.attach_namespace(actual, assets)?;
        Ok(context)
    }

    pub(crate) fn validate_closed_actor(
        &self,
        actor: &Principal,
        now: u64,
    ) -> Result<(), AuthError> {
        if actor.entity_id().is_some() {
            return Err(err(503, "closed namespace identity owner is not available"));
        }
        self.check_principal(actor, actor.namespace(), now)
            .map(|_| ())
    }

    pub(crate) fn detach_namespace(
        &mut self,
        namespace: &str,
    ) -> Result<NamespaceAssets, AuthError> {
        if namespace.is_empty() {
            return Err(err(503, "root authentication cannot be partitioned"));
        }
        let owned = self
            .tokens
            .iter()
            .filter(|(_, token)| token.namespace == namespace)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let mut tokens = BTreeMap::new();
        for id in owned {
            let token = self
                .tokens
                .remove(&id)
                .ok_or_else(|| err(503, "namespace token disappeared"))?;
            tokens.insert(id, token);
        }
        Ok(NamespaceAssets {
            namespace: namespace.to_owned(),
            tokens,
            policies: self.policies.remove(namespace),
            token_roles: self.token_roles.remove(namespace),
            password_policies: self.password_policies.remove(namespace),
            users: self.users.remove(namespace),
            roles: self.roles.remove(namespace),
            mounted_users: self.mounted_users.remove(namespace),
            mounted_roles: self.mounted_roles.remove(namespace),
            auth_mounts: self.auth_mounts.remove(namespace),
            jwt_mounts: self.jwt_mounts.remove(namespace),
            kubernetes_mounts: self.kubernetes_mounts.remove(namespace),
            oidc_mounts: self.oidc_mounts.remove(namespace),
            ldap_mounts: self.ldap_mounts.remove(namespace),
            ldap_groups: self.ldap_groups.remove(namespace),
            ldap_native_users: self.ldap_native_users.remove(namespace),
            radius_mounts: self.radius_mounts.remove(namespace),
            radius_native_users: self.radius_native_users.remove(namespace),
            kerberos_mounts: self.kerberos_mounts.remove(namespace),
            plugin_auth_mounts: self.plugin_auth_mounts.remove(namespace),
            cert_roles: self.cert_roles.remove(namespace),
        })
    }

    pub(crate) fn attach_namespace(
        &mut self,
        actual: &str,
        assets: NamespaceAssets,
    ) -> Result<(), AuthError> {
        assets.validate(actual)?;
        // Complete collision checks precede every mutation, so a rejected
        // parcel cannot partially replace tokens, policies or auth providers.
        if assets.tokens.keys().any(|id| self.tokens.contains_key(id))
            || self.policies.contains_key(actual)
            || self.token_roles.contains_key(actual)
            || self.password_policies.contains_key(actual)
            || self.users.contains_key(actual)
            || self.roles.contains_key(actual)
            || self.mounted_users.contains_key(actual)
            || self.mounted_roles.contains_key(actual)
            || self.auth_mounts.contains_key(actual)
            || self.jwt_mounts.contains_key(actual)
            || self.kubernetes_mounts.contains_key(actual)
            || self.oidc_mounts.contains_key(actual)
            || self.ldap_mounts.contains_key(actual)
            || self.ldap_groups.contains_key(actual)
            || self.ldap_native_users.contains_key(actual)
            || self.radius_mounts.contains_key(actual)
            || self.radius_native_users.contains_key(actual)
            || self.kerberos_mounts.contains_key(actual)
            || self.plugin_auth_mounts.contains_key(actual)
            || self.cert_roles.contains_key(actual)
        {
            return Err(err(503, "namespace auth owner is already loaded"));
        }
        self.tokens.extend(assets.tokens);
        if let Some(value) = assets.policies {
            self.policies.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.token_roles {
            self.token_roles.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.password_policies {
            self.password_policies.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.users {
            self.users.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.roles {
            self.roles.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.mounted_users {
            self.mounted_users.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.mounted_roles {
            self.mounted_roles.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.auth_mounts {
            self.auth_mounts.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.jwt_mounts {
            self.jwt_mounts.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.kubernetes_mounts {
            self.kubernetes_mounts.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.oidc_mounts {
            self.oidc_mounts.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.ldap_mounts {
            self.ldap_mounts.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.ldap_groups {
            self.ldap_groups.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.ldap_native_users {
            self.ldap_native_users.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.radius_mounts {
            self.radius_mounts.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.radius_native_users {
            self.radius_native_users.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.kerberos_mounts {
            self.kerberos_mounts.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.plugin_auth_mounts {
            self.plugin_auth_mounts.insert(actual.to_owned(), value);
        }
        if let Some(value) = assets.cert_roles {
            self.cert_roles.insert(actual.to_owned(), value);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    #[test]
    fn namespace_auth_partition_covers_all_typed_maps_and_retains_root_authority() -> TestResult {
        let (mut state, root) = AuthState::bootstrap(100)?;
        state.wrapping_clock = 42;
        state.policies.insert("custody".into(), BTreeMap::new());
        state.token_roles.insert("custody".into(), BTreeMap::new());
        state
            .password_policies
            .insert("custody".into(), BTreeMap::new());
        state.users.insert("custody".into(), BTreeMap::new());
        state.roles.insert("custody".into(), BTreeMap::new());
        state
            .mounted_users
            .insert("custody".into(), BTreeMap::new());
        state
            .mounted_roles
            .insert("custody".into(), BTreeMap::new());
        state.auth_mounts.insert("custody".into(), BTreeMap::new());
        state.jwt_mounts.insert("custody".into(), BTreeMap::new());
        state
            .kubernetes_mounts
            .insert("custody".into(), BTreeMap::new());
        state.oidc_mounts.insert("custody".into(), BTreeMap::new());
        state.ldap_mounts.insert("custody".into(), BTreeMap::new());
        state.ldap_groups.insert("custody".into(), BTreeMap::new());
        state
            .ldap_native_users
            .insert("custody".into(), BTreeMap::new());
        state
            .radius_mounts
            .insert("custody".into(), BTreeMap::new());
        state
            .radius_native_users
            .insert("custody".into(), BTreeMap::new());
        state
            .kerberos_mounts
            .insert("custody".into(), BTreeMap::new());
        state
            .plugin_auth_mounts
            .insert("custody".into(), BTreeMap::new());
        state.cert_roles.insert("custody".into(), BTreeMap::new());
        let original = crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "private auth serialization")?;
        let batch =
            crate::secret_serde::to_vec(&state.batch_authority, crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| "private root batch serialization")?;
        let assets = state.detach_namespace("custody")?;
        assert!(
            state.namespace_is_empty("custody") && state.authenticate_read_only(&root, 100).is_ok(),
            "all namespace auth maps unload without transferring root authority"
        );
        let retained_batch =
            crate::secret_serde::to_vec(&state.batch_authority, crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| "private root batch serialization")?;
        assert!(
            batch.as_slice() == retained_batch.as_slice()
                && state.wrapping_clock == 42
                && state.system_lease_defaults.is_some(),
            "root batch authority, inherited defaults and clock remain root owned"
        );
        assert!(
            state.attach_namespace("other", assets.clone()).is_err(),
            "wrong actual namespace fails"
        );
        state.attach_namespace("custody", assets.clone())?;
        let restored = crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "private auth serialization")?;
        assert!(
            original.as_slice() == restored.as_slice(),
            "all nineteen typed maps restore without changing root fields"
        );
        assert!(
            state.attach_namespace("custody", assets).is_err()
                && state.detach_namespace("").is_err(),
            "collisions and root partition are rejected"
        );
        let after = crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "private auth serialization")?;
        assert!(
            after.as_slice() == restored.as_slice(),
            "failed restoration cannot partially change authority"
        );
        Ok(())
    }
}
