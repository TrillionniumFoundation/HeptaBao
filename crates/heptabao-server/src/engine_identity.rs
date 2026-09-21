//! Live projection and provider observations in the namespace-owned Identity store.
//! Observations bind membership, while policy contents remain live administrative records.
use super::*;

pub(crate) struct IdentityProjection {
    pub(crate) entity_id: String,
    pub(crate) policies: BTreeSet<String>,
    pub(crate) disabled: bool,
}

impl EngineState {
    pub(crate) fn validate_identity_alias_state(&self) -> Result<()> {
        for state in self.namespaces.values() {
            state.identity.validate_aliases()?;
        }
        Ok(())
    }

    pub(crate) fn has_opaque_identity_aliases(&self) -> bool {
        self.namespaces
            .values()
            .any(|state| state.identity.has_opaque_aliases())
    }

    pub(crate) fn has_login_alias_metadata_state(&self) -> bool {
        // Alias records can outlive the auth mount that originally created them.
        self.namespaces
            .values()
            .any(|state| state.identity.has_login_metadata())
    }

    pub(crate) fn has_extended_login_alias_metadata_state(&self) -> bool {
        self.namespaces
            .values()
            .any(|state| state.identity.has_extended_login_metadata())
    }

    pub(crate) fn has_approle_login_alias_metadata_state(&self) -> bool {
        self.namespaces
            .values()
            .any(|state| state.identity.has_approle_login_metadata())
    }

    /// Check backend metadata before creating an Identity. Existing aliases,
    /// including aliases with no prior backend metadata, use the update rules.
    pub(crate) fn validate_login_alias_metadata(
        &self,
        namespace: &str,
        accessor: &str,
        alias: &str,
        metadata: &BTreeMap<String, String>,
    ) -> Result<()> {
        if let Some(state) = self.namespaces.get(namespace) {
            state
                .identity
                .validate_login_metadata_for_alias(accessor, alias, metadata)
        } else {
            identity::IdentityState::default()
                .validate_login_metadata_for_alias(accessor, alias, metadata)
        }
    }

    pub(crate) fn update_login_alias_metadata(
        &mut self,
        namespace: &str,
        accessor: &str,
        alias: &str,
        metadata: &BTreeMap<String, String>,
        now: u64,
    ) -> Result<()> {
        self.namespaces
            .get_mut(namespace)
            .ok_or_else(|| error(403, "identity unavailable"))?
            .identity
            .update_login_metadata(accessor, alias, metadata, now)
    }

    pub(crate) fn bind_login_identity(
        &mut self,
        namespace: &str,
        accessor: &str,
        alias: &str,
        now: u64,
    ) -> Result<IdentityProjection> {
        self.namespaces
            .entry(namespace.to_owned())
            .or_default()
            .identity
            .bind_login(accessor, alias, now)
    }

    /// Only the authenticated AppRole login dispatcher may publish this narrow
    /// native side effect when an existing entity is disabled. No new binding
    /// or token authority is created by this operation.
    pub(crate) fn refresh_disabled_approle_alias_metadata(
        &mut self,
        namespace: &str,
        accessor: &str,
        alias: &str,
        metadata: &BTreeMap<String, String>,
        now: u64,
    ) -> Result<bool> {
        let Some(state) = self.namespaces.get_mut(namespace) else {
            return Ok(false);
        };
        state
            .identity
            .refresh_disabled_login_metadata(accessor, alias, metadata, now)
    }

    pub(crate) fn verify_external_group_identity(
        &self,
        namespace: &str,
        entity_id: &str,
        mount_accessor: &str,
        username: &str,
    ) -> Result<()> {
        self.namespaces
            .get(namespace)
            .ok_or_else(|| error(403, "identity unavailable"))?
            .identity
            .verify_external_identity(entity_id, mount_accessor, username)
    }

    /// Only call after provider success and a live mount/accessor fence.
    pub(crate) fn refresh_external_group_membership(
        &mut self,
        namespace: &str,
        entity_id: &str,
        mount_accessor: &str,
        observed_names: &BTreeSet<String>,
        now: u64,
    ) -> Result<IdentityProjection> {
        self.namespaces
            .get_mut(namespace)
            .ok_or_else(|| error(403, "identity unavailable"))?
            .identity
            .refresh_external_groups(entity_id, mount_accessor, observed_names, now)
    }

    pub(crate) fn revoke_external_group_membership(
        &mut self,
        namespace: &str,
        mount_accessor: &str,
        now: u64,
    ) -> Result<()> {
        if let Some(state) = self.namespaces.get_mut(namespace) {
            state.identity.revoke_external_groups(mount_accessor, now)?;
        }
        Ok(())
    }

    pub(crate) fn has_external_group_membership(&self) -> bool {
        self.namespaces
            .values()
            .any(|state| state.identity.has_external_groups())
    }

    pub(crate) fn identity_projection(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<IdentityProjection> {
        self.namespaces
            .get(namespace)
            .ok_or_else(|| error(403, "identity unavailable"))?
            .identity
            .project(id)
    }
}
