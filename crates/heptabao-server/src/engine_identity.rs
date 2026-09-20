//! Live projection and provider observations in the namespace-owned Identity store.
//! Observations bind membership, while policy contents remain live administrative records.
use super::*;

pub(crate) struct IdentityProjection {
    pub(crate) entity_id: String,
    pub(crate) policies: BTreeSet<String>,
    pub(crate) disabled: bool,
}

impl EngineState {
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
