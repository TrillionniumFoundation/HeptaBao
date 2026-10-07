//! Durable namespace taint and completed retirement. Metadata grants no actor,
//! key, callback or clock. Actual cleanup remains Service-owned.
use super::*;
use crate::namespace_custody::Binding;

const MAX_PATHS: usize = 4096;

#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ledger {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pending: BTreeMap<String, Binding>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    retired: BTreeMap<String, u64>,
}

impl Ledger {
    pub(crate) fn pending(&self) -> &BTreeMap<String, Binding> {
        &self.pending
    }
    pub(crate) fn retired(&self) -> &BTreeMap<String, u64> {
        &self.retired
    }
    pub(crate) fn is_tainted(&self, namespace: &str) -> bool {
        self.pending.keys().any(|path| {
            namespace == path
                || namespace
                    .strip_prefix(path)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
    }
    pub(crate) fn validate(&self, cluster: &str) -> Result<(), AuthError> {
        if self.pending.len() > MAX_PATHS || self.retired.len() > MAX_PATHS {
            return Err(err(503, "namespace deletion ledger exceeds bounds"));
        }
        for (path, binding) in &self.pending {
            binding
                .validate_cluster_namespace(cluster, path)
                .map_err(|_| err(503, "invalid pending namespace deletion binding"))?;
            if self
                .retired
                .get(path)
                .is_some_and(|old| *old >= binding.incarnation())
            {
                return Err(err(
                    503,
                    "namespace deletion incarnation is already retired",
                ));
            }
        }
        for (path, incarnation) in &self.retired {
            validate_namespace(path)?;
            if path.is_empty() || *incarnation == 0 || *incarnation == u64::MAX {
                return Err(err(503, "invalid namespace deletion retirement frontier"));
            }
        }
        Ok(())
    }
    pub(crate) fn begin(&mut self, binding: Binding, cluster: &str) -> Result<(), AuthError> {
        let path = binding.namespace().to_owned();
        if self.pending.get(&path).is_some_and(|old| old != &binding)
            || self
                .retired
                .get(&path)
                .is_some_and(|old| *old >= binding.incarnation())
        {
            return Err(err(
                503,
                "namespace deletion owner conflicts with lifecycle",
            ));
        }
        self.pending.insert(path, binding);
        self.validate(cluster)
    }
    pub(crate) fn complete(&mut self, binding: &Binding, cluster: &str) -> Result<(), AuthError> {
        let path = binding.namespace();
        if self.pending.get(path) != Some(binding) {
            return Err(err(
                503,
                "namespace deletion completion lacks original intent",
            ));
        }
        self.pending.remove(path);
        self.retired
            .entry(path.to_owned())
            .and_modify(|old| *old = (*old).max(binding.incarnation()))
            .or_insert(binding.incarnation());
        self.validate(cluster)
    }
    pub(crate) fn validate_successor(&self, old: &Self, cluster: &str) -> Result<(), AuthError> {
        self.validate(cluster)?;
        old.validate(cluster)?;
        if old
            .retired
            .iter()
            .any(|(path, incarnation)| self.retired.get(path).is_none_or(|next| next < incarnation))
        {
            return Err(err(503, "namespace deletion frontier cannot decrease"));
        }
        for (path, binding) in &old.pending {
            if self.pending.get(path) == Some(binding) {
                continue;
            }
            if self
                .retired
                .get(path)
                .is_none_or(|next| *next < binding.incarnation())
                || self
                    .pending
                    .get(path)
                    .is_some_and(|next| next.incarnation() <= binding.incarnation())
            {
                return Err(err(503, "namespace taint disappeared without retirement"));
            }
        }
        Ok(())
    }
}

impl AuthState {
    pub(crate) fn namespace_deletion_ledger(&self) -> Option<&Ledger> {
        self.namespace_deletions.as_ref()
    }
    pub(crate) fn namespace_is_tainted(&self, namespace: &str) -> bool {
        self.namespace_deletions
            .as_ref()
            .is_some_and(|ledger| ledger.is_tainted(namespace))
    }
    pub(super) fn require_active_namespace(&self, namespace: &str) -> Result<(), AuthError> {
        if self.namespace_is_tainted(namespace) {
            return Err(denied());
        }
        Ok(())
    }
    pub(crate) fn install_namespace_deletion_ledger(
        &mut self,
        ledger: &Ledger,
        cluster: &str,
    ) -> Result<(), AuthError> {
        ledger.validate(cluster)?;
        if let Some(old) = &self.namespace_deletions {
            ledger.validate_successor(old, cluster)?;
        }
        self.namespace_deletions = Some(ledger.clone());
        Ok(())
    }
    pub(crate) fn validate_namespace_deletion_successor(
        &self,
        old: &Self,
        cluster: &str,
    ) -> Result<(), AuthError> {
        match (&self.namespace_deletions, &old.namespace_deletions) {
            (Some(next), Some(old)) => next.validate_successor(old, cluster),
            (None, Some(_)) => Err(err(503, "namespace deletion ledger cannot retire")),
            (Some(next), None) => next.validate(cluster),
            (None, None) => Ok(()),
        }
    }

    /// First finite scope: native local token/userpass/AppRole owners only.
    /// Unsupported callback issuers are rejected before any taint is committed.
    pub(crate) fn namespace_has_only_native_deletion_owners(&self, namespace: &str) -> bool {
        if namespace.is_empty()
            || self.sdk_credential_namespace_pending(namespace)
            || self.auth_mounts.get(namespace).is_some_and(|mounts| {
                mounts
                    .values()
                    .any(|mount| !matches!(mount.kind.as_str(), "token" | "userpass" | "approle"))
            })
        {
            return false;
        }
        if self.jwt_mounts.contains_key(namespace)
            || self.kubernetes_mounts.contains_key(namespace)
            || self.oidc_mounts.contains_key(namespace)
            || self.ldap_mounts.contains_key(namespace)
            || self.ldap_groups.contains_key(namespace)
            || self.ldap_native_users.contains_key(namespace)
            || self.radius_mounts.contains_key(namespace)
            || self.radius_native_users.contains_key(namespace)
            || self.kerberos_mounts.contains_key(namespace)
            || self.plugin_auth_mounts.contains_key(namespace)
            || self.cert_roles.contains_key(namespace)
        {
            return false;
        }
        let owned: BTreeSet<_> = self
            .tokens
            .iter()
            .filter(|(_, token)| token.namespace == namespace)
            .map(|(id, _)| id.as_str())
            .collect();
        if self.tokens.iter().any(|(id, token)| {
            (owned.contains(id.as_str())
                && (token.root
                    || token.wrapping.is_some()
                    || !matches!(
                        token.auth_provenance,
                        Some(
                            TokenAuthProvenance::TokenApi { .. }
                                | TokenAuthProvenance::Userpass { .. }
                                | TokenAuthProvenance::AppRole { .. }
                        )
                    )))
                || (!owned.contains(id.as_str())
                    && token
                        .parent
                        .as_deref()
                        .is_some_and(|parent| owned.contains(parent)))
        }) {
            return false;
        }
        if self.namespace_has_only_local_token_owners(namespace) {
            return true;
        }
        let mut candidate = self.clone();
        match candidate.detach_namespace(namespace) {
            Ok(_) => candidate.namespace_is_empty(namespace),
            Err(_) => false,
        }
    }
}
