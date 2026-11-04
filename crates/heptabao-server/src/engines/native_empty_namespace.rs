//! A namespace catalog entry may own only pristine
//! Engine metadata. It cannot install mounts, identity epochs or secret graphs.
use super::*;
use std::collections::BTreeSet;

impl EngineState {
    pub(crate) fn native_empty_namespace_engine_profile(&self, paths: &BTreeSet<String>) -> bool {
        if self
            .namespaces
            .keys()
            .filter(|path| !path.is_empty())
            .cloned()
            .collect::<BTreeSet<_>>()
            != *paths
            || paths.iter().any(|path| {
                path.is_empty()
                    || self
                        .namespaces
                        .get(path)
                        .is_none_or(|namespace| !namespace.is_pristine())
            })
        {
            return false;
        }
        let mut root = self.clone();
        root.namespaces.retain(|name, _| name.is_empty());
        // Original root profile still checks SDK/external/secret owners.
        root.supports_native_v6_root_storage()
    }
}

impl EngineState {
    /// Closed ordinary child resources; catalog completeness is mandatory.
    pub(crate) fn native_plain_namespace_engine_profile(&self, paths: &BTreeSet<String>) -> bool {
        self.sdk_catalog.is_empty()
            && self.sdk_retired_logical.is_none()
            && self.namespace_record_owners.is_empty()
            && self
                .namespaces
                .keys()
                .filter(|name| !name.is_empty())
                .cloned()
                .collect::<BTreeSet<_>>()
                == *paths
            && self.namespaces.iter().all(|(name, owner)| {
                (name.is_empty() || paths.contains(name))
                    && owner.sdk_owners.is_empty()
                    && owner.sdk_leases.is_empty()
                    && owner.external_keys.is_empty()
                    && owner.mounts.values().all(|mount| match &mount.backend {
                        Backend::Kv1(_)
                        | Backend::Kv1Records
                        | Backend::Kv2(_)
                        | Backend::Kv2Native(_) => true,
                        Backend::Transit(engine) if name.is_empty() => !engine.has_external_state(),
                        Backend::Totp(_) if name.is_empty() => true,
                        Backend::Pki(engine) if name.is_empty() => engine.native_local_profile(),
                        _ => false,
                    })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pristine_namespace_metadata_is_not_an_implicit_secret_mount() {
        let mut engines = EngineState::initialized_empty();
        let names = BTreeSet::from(["cg-other".to_owned()]);
        engines.ensure_empty_namespace("cg-other");
        assert!(engines.native_empty_namespace_engine_profile(&names));
        assert!(!engines.native_empty_namespace_engine_profile(&BTreeSet::new()));
        assert!(
            !engines
                .native_empty_namespace_engine_profile(&BTreeSet::from(["missing".to_owned(),]))
        );
    }

    #[test]
    fn retired_mount_frontier_never_becomes_pristine_metadata()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut engines = EngineState::initialized_empty();
        engines.ensure_empty_namespace("cg-other");
        engines
            .namespaces
            .get_mut("cg-other")
            .ok_or("namespace")?
            .mount_epochs
            .insert("retired".to_owned(), 2);
        assert!(
            !engines
                .native_empty_namespace_engine_profile(&BTreeSet::from(["cg-other".to_owned(),]))
        );
        Ok(())
    }
}
