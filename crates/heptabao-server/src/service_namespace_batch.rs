//! Actual lifecycle evidence remains global when the routing catalog closes.
use super::*;
use crate::auth::{AuthResponse, batch_namespace::Registry};

impl CatalogAssets {
    pub(in crate::service) fn batch_hydrated_paths(
        &self,
        current: &NamespaceRegistry,
        actual: &str,
    ) -> Result<BTreeSet<String>, Response> {
        let prefix = format!("{actual}/");
        if self.namespace != actual
            || self.entries.iter().any(|(path, entry)| {
                !path.starts_with(&prefix)
                    || current.entries.get(path).is_none_or(|visible| {
                        visible.id != entry.id || visible.incarnation != entry.incarnation
                    })
            })
            || self.next_incarnation.iter().any(|(path, next)| {
                current
                    .next_incarnation
                    .get(path)
                    .is_none_or(|visible| visible < next)
            })
            || self.retired_custody.iter().any(|(path, retired)| {
                current
                    .retired_custody
                    .get(path)
                    .is_none_or(|visible| !retired.admits(visible))
            })
        {
            return Err(Response::error(
                503,
                "batch migration requires complete authenticated catalog",
            ));
        }
        Ok(self.entries.keys().cloned().collect())
    }
}

impl NamespaceRegistry {
    pub(in crate::service) fn batch_custody_paths(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.custody.is_some() || entry.inherited.is_some())
            .map(|(path, _)| path.clone())
            .collect()
    }

    pub(in crate::service) fn batch_visible_paths(&self) -> BTreeSet<String> {
        self.entries.keys().cloned().collect()
    }

    fn visible_batch_catalog(&self) -> BTreeMap<String, u64> {
        self.entries
            .iter()
            .map(|(path, entry)| (path.clone(), entry.incarnation))
            .collect()
    }

    pub(in crate::service) fn ensure_batch_lifecycle(
        &mut self,
        cluster_id: &str,
        leases: &namespace_runtime::Leases,
    ) -> Result<&Registry, Response> {
        if self.batch_lifecycle.is_none() {
            // An actual captured key must open every retained catalog before
            // its visible rows can be used as complete lifecycle evidence.
            // Sealed flags and runtime map membership confer no completeness.
            leases.validate_full_batch_catalog(self, cluster_id)?;
            let registry = Registry::adopt_visible(
                cluster_id,
                self.visible_batch_catalog(),
                self.next_incarnation.clone(),
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
            self.batch_lifecycle = Some(registry);
        }
        self.validate_batch_lifecycle(cluster_id)?;
        self.batch_lifecycle
            .as_ref()
            .ok_or_else(|| Response::error(503, "namespace lifecycle unavailable"))
    }

    pub(in crate::service) fn validate_batch_lifecycle(
        &self,
        cluster_id: &str,
    ) -> Result<(), Response> {
        let Some(registry) = &self.batch_lifecycle else {
            return Ok(());
        };
        registry
            .validate(cluster_id)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if !registry.matches_catalog(&self.visible_batch_catalog(), &self.next_incarnation) {
            return Err(Response::error(
                503,
                "namespace batch lifecycle differs from actual catalog",
            ));
        }
        for path in registry
            .active_paths()
            .filter(|path| !path.is_empty() && !self.entries.contains_key(*path))
        {
            let mut parent = parent_path(path);
            let mut actual_closed_owner = false;
            while !parent.is_empty() {
                if self
                    .entries
                    .get(parent)
                    .is_some_and(|entry| entry.custody.is_some() || entry.inherited.is_some())
                {
                    actual_closed_owner = true;
                    break;
                }
                parent = parent_path(parent);
            }
            if !actual_closed_owner {
                return Err(Response::error(
                    503,
                    "namespace batch lifecycle lacks actual encrypted catalog owner",
                ));
            }
        }
        Ok(())
    }
}

impl State {
    fn has_namespace_bound_batch_owners(&self) -> bool {
        self.engines
            .all_lease_owners()
            .into_iter()
            .chain(self.database.all_lease_owners())
            .chain(self.auth.sdk_credential_owners())
            .any(|(_, owner)| {
                owner
                    .batch_claims()
                    .is_some_and(|claims| claims.namespace_binding().is_some())
            })
    }

    pub(in crate::service) fn has_namespace_batch_state(&self) -> bool {
        self.auth.namespace_batch_registry().is_some()
            || self.namespaces.batch_lifecycle.is_some()
            || self.has_namespace_bound_batch_owners()
    }

    pub(in crate::service) fn validate_namespace_batch_state(&self) -> Result<(), Response> {
        self.namespaces.validate_batch_lifecycle(&self.cluster_id)?;
        match (
            &self.namespaces.batch_lifecycle,
            self.auth.namespace_batch_registry(),
        ) {
            (None, None) if !self.has_namespace_bound_batch_owners() => Ok(()),
            (Some(actual), Some(auth))
                if actual == auth && self.schema >= NAMESPACE_BATCH_STATE_SCHEMA =>
            {
                Ok(())
            }
            _ => Err(Response::error(
                503,
                "namespace batch ownership requires matching schema 91 lifecycle",
            )),
        }
    }

    pub(in crate::service) fn ensure_namespace_batch_registry(&mut self) -> Result<(), Response> {
        let registry = self
            .namespaces
            .ensure_batch_lifecycle(&self.cluster_id, &self.namespace_leases)?
            .clone();
        self.auth
            .install_namespace_batch_registry(&registry)
            .map_err(|error| Response::error(error.status, &error.message))?;
        // The first actual ledger must carry its writer floor before existing
        // typed partition/closure helpers validate an intermediate candidate.
        self.schema = self.writer_schema();
        Ok(())
    }

    pub(in crate::service) fn sync_namespace_batch_registry(&mut self) -> Result<(), Response> {
        let registry = self
            .namespaces
            .batch_lifecycle
            .as_ref()
            .ok_or_else(|| Response::error(503, "actual namespace lifecycle missing"))?;
        self.auth
            .install_namespace_batch_registry(registry)
            .map_err(|error| Response::error(error.status, &error.message))
    }
}

impl Service {
    /// The original caller's candidate auth and catalog move together only after
    /// the existing identity/batch finalizer succeeds. Caller body selects no
    /// cluster, namespace incarnation, ledger row or retirement operation.
    pub(in crate::service) fn prepare_identity_batch_namespace(
        auth: &mut AuthState,
        namespaces: &mut NamespaceRegistry,
        cluster_id: &str,
        leases: &namespace_runtime::Leases,
        response: &AuthResponse,
    ) -> Result<(), Response> {
        if response.pending_batch.is_some() {
            let actual = namespaces.ensure_batch_lifecycle(cluster_id, leases)?;
            auth.install_namespace_batch_registry(actual)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        Ok(())
    }

    pub(in crate::service) fn finish_state_identity_response(
        state: &mut State,
        response: &mut AuthResponse,
        namespace: &str,
        now: u64,
    ) -> Result<(), Response> {
        let mut namespaces = state.namespaces.clone();
        Self::prepare_identity_batch_namespace(
            &mut state.auth,
            &mut namespaces,
            &state.cluster_id,
            &state.namespace_leases,
            response,
        )?;
        Self::finish_identity_response(
            &mut state.auth,
            &mut state.engines,
            response,
            &namespaces,
            namespace,
            now,
        )?;
        if response.mutated {
            state.namespaces = namespaces;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_namespace_batch_tests.rs"]
mod tests;
