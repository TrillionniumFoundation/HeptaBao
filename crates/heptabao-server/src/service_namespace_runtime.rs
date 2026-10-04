//! Process-local custody and canonical publication view. Candidate leases share
//! a revocable slot, never an Arc<Key>; revocation drops and zeroizes the sole
//! key even while an old prepared candidate keeps the slot alive.
use super::*;
use crate::namespace_custody::{Binding, Descriptor, Key};
use std::sync::{Arc, Mutex};

fn unavailable() -> Response {
    Response::error(503, "namespace custody lease is unavailable or retired")
}

struct Slot {
    key: Option<Key>,
    binding: Binding,
    key_epoch: u64,
    frontier: u64,
}

#[derive(Clone)]
struct Lease(Arc<Mutex<Slot>>);

impl Lease {
    fn validate(&self) -> Result<(), Response> {
        if self.0.lock().map_err(|_| unavailable())?.key.is_none() {
            return Err(unavailable());
        }
        Ok(())
    }

    fn with_key<T>(
        &self,
        descriptor: &Descriptor,
        apply: impl FnOnce(&Key) -> Result<T, Response>,
    ) -> Result<T, Response> {
        let slot = self.0.lock().map_err(|_| unavailable())?;
        if slot.binding != *descriptor.binding()
            || slot.key_epoch != descriptor.key_epoch()
            || slot.frontier != descriptor.seal_frontier()
        {
            return Err(unavailable());
        }
        let key = slot.key.as_ref().ok_or_else(unavailable)?;
        apply(key)
    }

    fn revoke(&self) {
        // A poisoned lock is fail-closed for admission, but its key still must
        // be dropped on closure instead of waiting for the last stale Arc.
        let mut slot = self.0.lock().unwrap_or_else(|error| error.into_inner());
        slot.key.take();
    }
}

#[derive(Clone, Default)]
pub(super) struct Leases(Vec<Lease>);

impl Leases {
    pub(super) fn validate(&self) -> Result<(), Response> {
        for lease in &self.0 {
            lease.validate()?;
        }
        Ok(())
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Default)]
pub(super) struct Runtime {
    loaded: BTreeMap<String, Lease>,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.clear();
    }
}

impl Runtime {
    pub(super) fn clear(&mut self) {
        for lease in self.loaded.values() {
            lease.revoke();
        }
        self.loaded.clear();
    }

    pub(super) fn close(&mut self, namespace: &str) {
        let prefix = format!("{namespace}/");
        self.loaded.retain(|actual, lease| {
            let retain = actual != namespace && !actual.starts_with(&prefix);
            if !retain {
                lease.revoke();
            }
            retain
        });
    }

    /// Restore only after descriptor/typed assets/private record graph have all
    /// authenticated under the actual durable owner. Installing a key is never
    /// sufficient by itself to give a caller a principal or namespace grant.
    pub(super) fn restore(
        &mut self,
        state: &State,
        actual: &str,
        key: Key,
    ) -> Result<State, Response> {
        if self.loaded.len() >= 1024 || self.loaded.contains_key(actual) {
            return Err(unavailable());
        }
        let descriptor = state
            .namespaces
            .custody_owner(actual)
            .ok_or_else(unavailable)?;
        let binding = state
            .namespaces
            .custody_binding(&state.cluster_id, actual)?;
        let bytes = descriptor
            .open_assets(&binding, &key)
            .map_err(|_| unavailable())?;
        let assets = serde_json::from_slice::<namespace_assets::NamespaceAssets>(&bytes)
            .map_err(|_| unavailable())?;
        let cells = state
            .engines
            .namespace_record_cells(&binding)
            .map_err(|_| unavailable())?;
        let mut candidate = state.restore_namespace_assets(actual, &key, assets, &cells)?;
        candidate.namespaces.set_sealed(actual, false)?;
        let lease = Lease(Arc::new(Mutex::new(Slot {
            key: Some(key),
            binding,
            key_epoch: descriptor.key_epoch(),
            frontier: descriptor.seal_frontier(),
        })));
        let mut protected = state.clone();
        // A root/ancestor may already be loaded. Keep its canonical protected
        // owner, rather than copying its plaintext logical assets into a view.
        if let Some(previous) = &state.namespace_protected {
            protected = previous.as_ref().clone();
        }
        self.loaded.insert(actual.to_owned(), lease);
        candidate.namespace_leases = Leases(self.loaded.values().cloned().collect());
        candidate.namespace_protected = Some(Arc::new(protected));
        Ok(candidate)
    }

    /// Build one protected candidate from deepest independent child first.
    /// Its closed child descriptor/catalog becomes an ordinary encrypted asset
    /// of the parent; its independent key is never given to that parent.
    pub(super) fn prepare(&self, state: &mut State) -> Result<(), Response> {
        state.namespace_leases.validate()?;
        if self.loaded.is_empty() {
            if !state.namespace_leases.is_empty() {
                return Err(unavailable());
            }
            state.namespace_protected = None;
            return Ok(());
        }
        let mut paths = self.loaded.keys().cloned().collect::<Vec<_>>();
        paths.sort_by(|left, right| {
            right
                .split('/')
                .count()
                .cmp(&left.split('/').count())
                .then_with(|| left.cmp(right))
        });
        let mut protected = state.clone();
        for actual in &paths {
            let descriptor = protected
                .namespaces
                .custody_owner(actual)
                .cloned()
                .ok_or_else(unavailable)?;
            let binding = protected
                .namespaces
                .custody_binding(&protected.cluster_id, actual)?;
            let lease = self.loaded.get(actual).ok_or_else(unavailable)?;
            protected = lease.with_key(&descriptor, |key| {
                let (mut next, assets, cells) =
                    protected.partition_namespace_assets(actual, key)?;
                let bytes =
                    owner_store::serialize_owner(&assets).map_err(state_serialization_error)?;
                let previous = descriptor
                    .open_assets(&binding, key)
                    .map_err(|_| unavailable())?;
                let next_descriptor = if previous.as_slice() == bytes.as_slice() {
                    descriptor.clone()
                } else {
                    descriptor
                        .replace_assets(&binding, key, &bytes)
                        .map_err(|_| unavailable())?
                };
                next.engines
                    .publish_namespace_record_cells(&binding, &cells)
                    .map_err(|_| unavailable())?;
                next.namespaces
                    .install_custody_owner(&next.cluster_id, actual, next_descriptor)?;
                next.namespaces.set_sealed(actual, true)?;
                next.schema = next.writer_schema();
                next.validate_format()?;
                Ok(next)
            })?;
        }
        protected.namespace_leases = Leases::default();
        protected.namespace_protected = None;
        let canonical = Arc::new(protected.clone());
        // Recreate the logical view from exactly the serialized protected
        // parcels, parent before child. This is also the publication preflight.
        let mut logical = protected;
        for actual in paths.iter().rev() {
            let descriptor = logical
                .namespaces
                .custody_owner(actual)
                .cloned()
                .ok_or_else(unavailable)?;
            let binding = logical
                .namespaces
                .custody_binding(&logical.cluster_id, actual)?;
            let lease = self.loaded.get(actual).ok_or_else(unavailable)?;
            logical = lease.with_key(&descriptor, |key| {
                let bytes = descriptor
                    .open_assets(&binding, key)
                    .map_err(|_| unavailable())?;
                let assets = serde_json::from_slice::<namespace_assets::NamespaceAssets>(&bytes)
                    .map_err(|_| unavailable())?;
                let cells = logical
                    .engines
                    .namespace_record_cells(&binding)
                    .map_err(|_| unavailable())?;
                let mut next = logical.restore_namespace_assets(actual, key, assets, &cells)?;
                next.namespaces.set_sealed(actual, false)?;
                Ok(next)
            })?;
        }
        logical.namespace_protected = Some(canonical);
        logical.namespace_leases = Leases(self.loaded.values().cloned().collect());
        *state = logical;
        Ok(())
    }
}

impl State {
    /// Durable/HA/snapshot serializers and per-owner serializers must use this
    /// same view. A loaded candidate without a prepared view fails closed.
    pub(super) fn protected_state(&self) -> Result<&Self, Response> {
        self.namespace_leases.validate()?;
        match &self.namespace_protected {
            Some(protected) => Ok(protected),
            None if self.namespace_leases.is_empty() => Ok(self),
            None => Err(unavailable()),
        }
    }
}

impl Clone for State {
    fn clone(&self) -> Self {
        Self {
            schema: self.schema,
            cluster_id: self.cluster_id.clone(),
            replay_epoch: self.replay_epoch,
            namespaces: self.namespaces.clone(),
            auth: self.auth.clone(),
            engines: self.engines.clone(),
            database: self.database.clone(),
            raft_admin: self.raft_admin.clone(),
            namespace_protected: None,
            namespace_leases: self.namespace_leases.clone(),
        }
    }
}

// Keep the old field names/order/empty-field omission for an ordinary state.
// Recursive serializers cannot accidentally put loaded credentials into the
// root owner: a loaded state delegates only to its prepared closed view.
#[derive(Serialize)]
struct Wire<'a> {
    schema: u32,
    cluster_id: &'a str,
    #[serde(skip_serializing_if = "replay_epoch_is_zero")]
    replay_epoch: u64,
    #[serde(skip_serializing_if = "namespaces::NamespaceRegistry::is_empty")]
    namespaces: &'a namespaces::NamespaceRegistry,
    auth: &'a AuthState,
    engines: &'a EngineState,
    #[serde(skip_serializing_if = "database::DatabaseState::is_empty")]
    database: &'a database::DatabaseState,
    #[serde(skip_serializing_if = "raft_admin::RaftAdminState::is_default")]
    raft_admin: &'a raft_admin::RaftAdminState,
}
impl Serialize for State {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let state = self.protected_state().map_err(|_| {
            serde::ser::Error::custom(
                "namespace loaded state has no valid protected publication view",
            )
        })?;
        Wire {
            schema: state.schema,
            cluster_id: &state.cluster_id,
            replay_epoch: state.replay_epoch,
            namespaces: &state.namespaces,
            auth: &state.auth,
            engines: &state.engines,
            database: &state.database,
            raft_admin: &state.raft_admin,
        }
        .serialize(serializer)
    }
}

impl Service {
    pub(super) fn prepare_namespace_publication(&self, state: &mut State) -> Result<(), Response> {
        self.namespace_runtime.prepare(state)
    }
}
