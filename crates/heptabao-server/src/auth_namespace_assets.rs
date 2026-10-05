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
        for token in self.tokens.values() {
            token.validate_public_origin()?;
        }
        Ok(())
    }
}

impl AuthState {
    /// Stateless batch claims currently bind a namespace path, not its actual
    /// incarnation. Retire neither an empty nor populated namespace after any
    /// observed batch signing; leave global keys and siblings unchanged.
    pub(crate) fn namespace_batch_retirement_safe(&self) -> bool {
        self.batch_authority
            .as_ref()
            .is_none_or(BatchKeyAuthority::has_no_issued_claims)
    }

    /// Local Token API cleanup is only admitted under the Service's genuine
    /// loaded namespace owner. Provider authentication, wrapped deliveries and
    /// cross-namespace descendants require their existing cleanup transactions.
    pub(crate) fn namespace_has_only_local_token_owners(&self, actual: &str) -> bool {
        if actual.is_empty() {
            return false;
        }
        let owned = self
            .namespace_token_verifiers(actual)
            .into_iter()
            .collect::<BTreeSet<_>>();
        if self.tokens.iter().any(|(id, token)| {
            (owned.contains(id)
                && (token.root
                    || token.entity_id.is_some()
                    || token.wrapping.is_some()
                    || !matches!(
                        token.auth_provenance,
                        Some(TokenAuthProvenance::TokenApi { .. })
                    )))
                || (token.namespace != actual
                    && token
                        .parent
                        .as_ref()
                        .is_some_and(|parent| owned.contains(parent)))
        }) {
            return false;
        }
        let mut remaining = self.clone();
        remaining.tokens.retain(|id, _| !owned.contains(id));
        remaining.policies.remove(actual);
        remaining.token_roles.remove(actual);
        remaining.namespace_is_empty(actual)
    }

    /// Typed fixture of a genuine stored Token API lease; never available to
    /// production or serialized input, and never changes the issuer flag.
    #[cfg(test)]
    pub(crate) fn install_namespace_precise_lease_for_test(
        &mut self,
        actual: &str,
        bearer: &str,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<(), AuthError> {
        use super::token_precision::{DurationNanos, ServicePrecision};
        let grant = expires_at
            .duration_since_epoch()
            .checked_sub(issued_at.duration_since_epoch())
            .and_then(|span| u64::try_from(span.as_nanos()).ok())
            .ok_or_else(|| err(503, "invalid precise namespace fixture interval"))?;
        let grant = DurationNanos::checked(grant).map_err(|_| err(503, "precise fixture grant"))?;
        let token = self
            .tokens
            .get_mut(&hash(bearer))
            .ok_or_else(|| err(503, "genuine fixture token missing"))?;
        if actual.is_empty()
            || token.namespace != actual
            || token.public_origin.is_none()
            || token.wrapping.is_some()
            || issued_at.seconds() != token.created_at
            || !matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::TokenApi { .. })
            )
        {
            return Err(err(
                503,
                "genuine namespace Token API fixture owner rejected",
            ));
        }
        token.token_api_precision = Some(ServicePrecision {
            issued_at,
            grant_started_at: issued_at,
            expires_at: Some(expires_at),
            last_renewed_at: None,
            previous_grant: grant,
            creation_grant: grant,
            requested_period: DurationNanos::checked(0).map_err(|_| err(503, "fixture period"))?,
            requested_explicit_max: DurationNanos::checked(0)
                .map_err(|_| err(503, "fixture max"))?,
        });
        token.expires_at = Some(
            expires_at
                .ceil_seconds()
                .map_err(|_| err(503, "fixture expiry"))?,
        );
        token.token_api_lease_ttl = Some(grant.ceil_seconds());
        token.auth_provenance = Some(TokenAuthProvenance::TokenApi {
            issued_creation_ttl: Some(grant.public_seconds()),
        });
        self.token_api_precision_state = true;
        self.token_api_observed_at = Some(
            self.token_api_observed_at
                .map_or(issued_at, |at| at.max(issued_at)),
        );
        self.validate_system_lease_defaults()
    }

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

    pub(crate) fn validate_closed_actor_observed(
        &self,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        if actor.entity_id().is_some() {
            return Err(err(503, "closed namespace identity owner is not available"));
        }
        self.check_principal_observed(actor, actor.namespace(), time)
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
        if self.public_origin_floor.is_none()
            && assets.tokens.values().any(Token::has_public_origin)
        {
            return Err(err(503, "namespace public origin floor is missing"));
        }
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
    fn closed_namespace_actor_preserves_fractional_expiry_after_full_partition() -> TestResult {
        use super::super::token_precision::{DurationNanos, ServicePrecision};
        let (mut state, root) = AuthState::bootstrap(100)?;
        state.initialize_fresh_namespace_auth("custody")?;
        let root_actor = state.authenticate(&root, 100)?;
        let issued = state
            .handle(
                Some(&root_actor),
                "custody",
                "POST",
                "auth/token/create",
                &json!({"policies":["default"],"ttl":"2s"}),
                100,
            )?
            .ok_or("issued token")?;
        let bearer = issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("actual bearer")?;
        let issued_at = Timestamp::checked(100, 200_000_000)?;
        let expires_at = Timestamp::checked(100, 700_000_000)?;
        let grant = DurationNanos::checked(500_000_000)?;
        state.token_api_precision_state = true;
        state.token_api_observed_at = Some(issued_at);
        let token = state
            .tokens
            .get_mut(&hash(bearer))
            .ok_or("actual issued token")?;
        token.token_api_precision = Some(ServicePrecision {
            issued_at,
            grant_started_at: issued_at,
            expires_at: Some(expires_at),
            last_renewed_at: None,
            previous_grant: grant,
            creation_grant: grant,
            requested_period: DurationNanos::checked(0)?,
            requested_explicit_max: DurationNanos::checked(0)?,
        });
        token.expires_at = Some(101);
        token.token_api_lease_ttl = Some(1);
        token.auth_provenance = Some(TokenAuthProvenance::TokenApi {
            issued_creation_ttl: Some(0),
        });
        state.validate_system_lease_defaults()?;
        let assets = state.detach_namespace("custody")?;
        let bytes = crate::secret_serde::to_vec(&assets, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "full private namespace owner")?;
        let restored: NamespaceAssets = serde_json::from_slice(&bytes)?;
        let mut private = state.clone();
        private.attach_namespace("custody", restored)?;
        private.validate_system_lease_defaults()?;
        let live = AuthorityTime::Precise(Timestamp::checked(100, 600_000_000)?);
        let actor = private.authenticate_from_observed(bearer, live, None)?;
        let context = private.closed_auth_context(&state, "custody")?;
        context.validate_closed_actor_observed(&actor, live)?;
        context.validate_closed_actor_observed(&actor, AuthorityTime::Precise(expires_at))?;
        assert!(
            context
                .validate_closed_actor_observed(&actor, AuthorityTime::Coarse(100))
                .is_err()
        );
        assert!(
            context
                .validate_closed_actor_observed(
                    &actor,
                    AuthorityTime::Precise(Timestamp::checked(100, 700_000_001)?)
                )
                .is_err()
        );
        assert!(state.namespace_is_empty("custody"));
        Ok(())
    }
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
    #[test]
    fn public_origin_namespace_full_partition_requires_retained_floor_before_attach() -> TestResult
    {
        let (mut state, root) = AuthState::bootstrap(100)?;
        state.initialize_fresh_namespace_auth("custody")?;
        let actor = state
            .authenticate_read_only(&root, 100)?
            .ok_or("actual root principal")?;
        let policy = state
            .handle(
                Some(&actor),
                "custody",
                "PUT",
                "sys/policies/acl/public-origin-reader",
                &json!({"policy":"path \"*\" { capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\", \"patch\"] }"}),
                100,
            )?
            .ok_or("actual reader policy producer")?;
        assert_eq!(policy.status, 204);
        let minted = state
            .handle(
                Some(&actor),
                "custody",
                "POST",
                "auth/token/create",
                &json!({"policies":["public-origin-reader"],"no_default_policy":true,"meta":{}}),
                100,
            )?
            .ok_or("actual token producer")?;
        let bearer = Zeroizing::new(
            minted.body["auth"]["client_token"]
                .as_str()
                .ok_or("actual native bearer")?
                .to_owned(),
        );
        assert!(state.has_public_origin_state());
        let original = crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "complete auth owner")?;
        let assets = state.detach_namespace("custody")?;
        assert!(state.public_origin_floor.is_some() && state.namespace_is_empty("custody"));
        let bytes = crate::secret_serde::to_vec(&assets, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "complete namespace owner")?;
        let restored: NamespaceAssets = serde_json::from_slice(&bytes)?;
        let mut missing_floor = state.clone();
        missing_floor.public_origin_floor = None;
        let before =
            crate::secret_serde::to_vec(&missing_floor, crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| "missing floor before")?;
        assert!(
            missing_floor
                .attach_namespace("custody", restored.clone())
                .is_err()
        );
        assert_eq!(
            crate::secret_serde::to_vec(&missing_floor, crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| "missing floor after")?
                .as_slice(),
            before.as_slice()
        );
        state.attach_namespace("custody", restored)?;
        state.validate_public_origin_state()?;
        assert_eq!(
            crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| "restored auth")?
                .as_slice(),
            original.as_slice()
        );
        let genuine = state
            .authenticate_read_only(&bearer, 100)?
            .ok_or("actual restored principal")?;
        assert_eq!(genuine.namespace(), "custody");
        let lookup = state
            .handle(
                Some(&genuine),
                "custody",
                "GET",
                "auth/token/lookup-self",
                &json!({}),
                100,
            )?
            .ok_or("actual lookup")?;
        assert_eq!(lookup.body["data"]["meta"], json!({}));
        Ok(())
    }
}
