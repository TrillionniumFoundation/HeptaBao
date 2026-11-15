//! Pristine engine metadata and exact retired namespace cleanup.
//! Cleanup requires the enclosing catalog incarnation retirement; it never
//! turns mount history into pristine metadata or removes live secret graphs.
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

    /// Retire an already-disabled plain namespace's engine metadata only after
    /// the catalog and paired Auth ledger have retired its exact incarnation.
    /// Mount epochs are not pristine: the enclosing retired namespace now
    /// fences every old mount owner. No live payload or external owner is removed.
    pub(crate) fn retire_native_flat_namespace_engines(
        &mut self,
        cluster_id: &str,
        binding: &crate::namespace_custody::Binding,
        lifecycle: &crate::auth::batch_namespace::Registry,
    ) -> Result<()> {
        let namespace = binding.namespace();
        binding
            .validate_cluster_namespace(cluster_id, namespace)
            .map_err(|_| error(503, "namespace engine retirement binding changed"))?;
        lifecycle
            .validate(cluster_id)
            .map_err(|_| error(503, "namespace engine retirement ledger changed"))?;
        if lifecycle.current_incarnation(namespace).is_some()
            || !lifecycle.knows_retired_incarnation(namespace, binding.incarnation())
        {
            return Err(error(503, "namespace engine owner has not retired"));
        }
        let owner = self
            .namespaces
            .get(namespace)
            .ok_or_else(|| error(503, "namespace engine owner missing"))?;
        if !owner.mounts.is_empty()
            || !owner.sdk_owners.is_empty()
            || !owner.sdk_leases.is_empty()
            || !owner.identity.is_pristine()
            || !owner.external_keys.is_empty()
        {
            return Err(error(409, "namespace still contains owned resources"));
        }
        // An absent mount is insufficient evidence that its record payload
        // disappeared. Check both authenticated views without rewriting them.
        if let Some(runtime) = &self.records {
            for view in [&runtime.index, &runtime.protected] {
                view.visit_keys(|key| {
                    kv_versioning::deadline()
                        .map_err(|_| crate::state_records::RecordError::Invalid)?;
                    if key.namespace() == namespace {
                        return Err(crate::state_records::RecordError::Corrupt);
                    }
                    Ok(())
                })
                .map_err(kv1_records::record_error)?;
            }
        }
        kv_versioning::deadline()?;
        self.namespaces.remove(namespace);
        Ok(())
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
                        Backend::Totp(_) | Backend::Ssh(_) if name.is_empty() => true,
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
