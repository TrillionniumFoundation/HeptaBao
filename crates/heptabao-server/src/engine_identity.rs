//! A projection from the existing namespace-owned Identity store. No new store,
//! cache, background authority or persisted policy grant is introduced.
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
