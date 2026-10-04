//! Process-local custody and canonical publication view. Candidate leases share
//! a revocable slot, never an Arc<Key>; revocation drops and zeroizes the sole
//! key even while an old prepared candidate keeps the slot alive.
use super::*;
use crate::namespace_custody::{Binding, Descriptor, Key, Progress, Submission};
use std::sync::{Arc, Mutex};

fn unavailable() -> Response {
    Response::error(503, "namespace custody lease is unavailable or retired")
}

pub(super) fn request_live() -> Result<(), Response> {
    if crate::request_deadline::current()
        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        return Err(Response::error(
            503,
            "namespace custody request deadline expired",
        ));
    }
    Ok(())
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
    progress: BTreeMap<String, Progress>,
}

pub(super) struct Fresh {
    pub(super) candidate: State,
    pub(super) shares: Vec<zeroize::Zeroizing<Vec<u8>>>,
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
        self.progress.clear();
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
        self.progress
            .retain(|actual, _| actual != namespace && !actual.starts_with(&prefix));
    }

    pub(super) fn status(&self, state: &State, actual: &str) -> Result<Response, Response> {
        let descriptor = state
            .namespaces
            .custody_owner(actual)
            .ok_or_else(|| Response::error(400, "namespace is not sealable"))?;
        let sealed = !self.loaded.contains_key(actual);
        let progress = sealed.then(|| self.progress.get(actual)).flatten();
        Ok(Response::ok(json!({"data":{
            "type":"shamir", "initialized":true, "sealed":sealed,
            "t":descriptor.threshold(), "n":descriptor.share_count(),
            "progress":progress.map_or(0, Progress::count),
            "nonce":progress.map_or("", Progress::nonce),
        }})))
    }

    pub(super) fn reset_progress(&mut self, actual: &str) {
        self.progress.remove(actual);
    }

    pub(super) fn has_loaded_within(&self, actual: &str) -> bool {
        let prefix = format!("{actual}/");
        self.loaded
            .keys()
            .any(|path| path == actual || path.starts_with(&prefix))
    }

    pub(super) fn submit(
        &mut self,
        state: &State,
        actual: &str,
        fragment: &[u8],
    ) -> Result<Option<State>, Response> {
        if let Err(error) = request_live() {
            self.progress.remove(actual);
            return Err(error);
        }
        let descriptor = state
            .namespaces
            .custody_owner(actual)
            .ok_or_else(|| Response::error(400, "namespace is not sealable"))?;
        let expected = if descriptor.threshold() == 1 { 32 } else { 33 };
        if fragment.len() != expected {
            return Err(Response::error(400, "invalid namespace key share length"));
        }
        if self.loaded.contains_key(actual) {
            return Ok(None);
        }
        if !self.progress.contains_key(actual) {
            if self.progress.len() >= 1024 {
                return Err(unavailable());
            }
            let binding = state
                .namespaces
                .custody_binding(&state.cluster_id, actual)?;
            self.progress.insert(
                actual.to_owned(),
                Progress::new(binding, descriptor).map_err(|_| unavailable())?,
            );
        }
        let result = self
            .progress
            .get_mut(actual)
            .ok_or_else(unavailable)?
            .submit(descriptor, fragment);
        if let Err(error) = request_live() {
            self.progress.remove(actual);
            return Err(error);
        }
        match result {
            Ok(Submission::Pending) => Ok(None),
            Ok(Submission::Unlocked { key, .. }) => {
                self.progress.remove(actual);
                self.restore(state, actual, key).map(Some)
            }
            Err(error) => {
                self.progress.remove(actual);
                match error {
                    crate::namespace_custody::Error::InvalidKey
                    | crate::namespace_custody::Error::InvalidShare => {
                        Err(Response::error(400, "invalid namespace unseal key"))
                    }
                    _ => Err(unavailable()),
                }
            }
        }
    }

    /// Fresh namespace keys are private candidate material. This function does
    /// not install a slot. The caller can return shares only after the complete
    /// descriptor, opaque records and asset removal have durably committed.
    pub(super) fn fresh_candidate(
        state: &State,
        actual: &str,
        shares: u8,
        threshold: u8,
    ) -> Result<Fresh, Response> {
        request_live()?;
        let binding = state
            .namespaces
            .custody_binding(&state.cluster_id, actual)?;
        let created = Descriptor::create(binding.clone(), shares, threshold, b"{}")
            .map_err(|_| unavailable())?;
        let mut progress =
            Progress::new(binding.clone(), &created.descriptor).map_err(|_| unavailable())?;
        let mut key = None;
        for share in created.shares.iter().take(usize::from(threshold)) {
            if let Submission::Unlocked { key: unlocked, .. } = progress
                .submit(&created.descriptor, share)
                .map_err(|_| unavailable())?
            {
                key = Some(unlocked);
            }
        }
        let key = key.ok_or_else(unavailable)?;
        let (mut candidate, assets, cells) = state.partition_namespace_assets(actual, &key)?;
        let bytes = zeroize::Zeroizing::new(
            owner_store::serialize_owner(&assets).map_err(state_serialization_error)?,
        );
        let descriptor = created
            .descriptor
            .replace_assets(&binding, &key, &bytes)
            .map_err(|_| unavailable())?;
        candidate
            .engines
            .publish_namespace_record_cells(&binding, &cells)
            .map_err(|_| unavailable())?;
        candidate
            .namespaces
            .install_custody_owner(&candidate.cluster_id, actual, descriptor)?;
        candidate.namespaces.set_sealed(actual, true)?;
        candidate.schema = candidate.writer_schema();
        candidate.validate_format()?;
        request_live()?;
        Ok(Fresh {
            candidate,
            shares: created.shares,
        })
    }

    pub(super) fn closed_candidate(&self, state: &State, actual: &str) -> Result<State, Response> {
        let mut candidate = state.clone();
        self.prepare(&mut candidate)?;
        let prefix = format!("{actual}/");
        let mut paths = self
            .loaded
            .keys()
            .filter(|path| path.as_str() == actual || path.starts_with(&prefix))
            .cloned()
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return Err(unavailable());
        }
        paths.sort_by_key(|path| std::cmp::Reverse(path.split('/').count()));
        for path in paths {
            let descriptor = candidate
                .namespaces
                .custody_owner(&path)
                .cloned()
                .ok_or_else(unavailable)?;
            let binding = candidate
                .namespaces
                .custody_binding(&candidate.cluster_id, &path)?;
            let lease = self.loaded.get(&path).ok_or_else(unavailable)?;
            candidate = lease.with_key(&descriptor, |key| {
                let (mut next, assets, cells) = candidate.partition_namespace_assets(&path, key)?;
                let bytes =
                    owner_store::serialize_owner(&assets).map_err(state_serialization_error)?;
                let previous = descriptor
                    .open_assets(&binding, key)
                    .map_err(|_| unavailable())?;
                let updated = if previous.as_slice() == bytes.as_slice() {
                    descriptor.clone()
                } else {
                    descriptor
                        .replace_assets(&binding, key, &bytes)
                        .map_err(|_| unavailable())?
                };
                let closed = updated
                    .advance_seal_frontier(&binding, key)
                    .map_err(|_| unavailable())?;
                next.engines
                    .publish_namespace_record_cells(&binding, &cells)
                    .map_err(|_| unavailable())?;
                next.namespaces
                    .install_custody_owner(&next.cluster_id, &path, closed)?;
                next.namespaces.set_sealed(&path, true)?;
                next.namespace_leases
                    .0
                    .retain(|candidate| !Arc::ptr_eq(&candidate.0, &lease.0));
                Ok(next)
            })?;
        }
        self.prepare(&mut candidate)?;
        Ok(candidate)
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
        request_live()?;
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
        request_live()?;
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
        if state.namespace_leases.is_empty() {
            state.namespace_protected = None;
            return Ok(());
        }
        let mut paths = Vec::with_capacity(state.namespace_leases.0.len());
        for lease in &state.namespace_leases.0 {
            let slot = lease.0.lock().map_err(|_| unavailable())?;
            let actual = slot.binding.namespace();
            if self
                .loaded
                .get(actual)
                .is_none_or(|current| !Arc::ptr_eq(&current.0, &lease.0))
            {
                return Err(unavailable());
            }
            if paths.iter().any(|path| path == actual) {
                return Err(unavailable());
            }
            paths.push(actual.to_owned());
        }
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
        logical.namespace_leases = Leases(
            paths
                .iter()
                .map(|path| self.loaded.get(path).cloned().ok_or_else(unavailable))
                .collect::<Result<Vec<_>, _>>()?,
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_custody::{Created, Progress, Submission};
    use crate::service::tests::{Root, bootstrap_unmounted, call};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    impl Service {
        fn namespace_fixture_at(
            &mut self,
            method: &str,
            path: &str,
            namespace: &str,
            token: &str,
            body: Value,
            now: u64,
        ) -> Response {
            self.handle_at_mode(RequestDispatch {
                method,
                path,
                namespace,
                token,
                body,
                now,
                allow_forward: true,
                enforce_namespace: true,
                wrap_ttl_seconds: None,
                origin_peer: None,
                client_certificates: None,
            })
        }
    }

    fn key(descriptor: &Descriptor, created: &Created) -> TestResult<Key> {
        let mut progress = Progress::new(descriptor.binding().clone(), descriptor)?;
        match progress.submit(descriptor, &created.shares[0])? {
            Submission::Unlocked { key, .. } => Ok(key),
            Submission::Pending => Err("threshold did not authenticate".into()),
        }
    }

    fn install(service: &mut Service, actual: &str) -> TestResult<Created> {
        let mut loaded = service.state.clone().ok_or("state")?;
        service
            .prepare_namespace_publication(&mut loaded)
            .map_err(|_| "predecessor protection")?;
        let state = loaded
            .protected_state()
            .map_err(|_| "predecessor owner")?
            .clone();
        let binding = state
            .namespaces
            .custody_binding(&state.cluster_id, actual)
            .map_err(|_| "binding")?;
        let created = Descriptor::create(binding.clone(), 1, 1, b"{}")?;
        let key = key(&created.descriptor, &created)?;
        let (mut closed, assets, cells) = state
            .partition_namespace_assets(actual, &key)
            .map_err(|_| "partition")?;
        let bytes = owner_store::serialize_owner(&assets)?;
        let descriptor = created.descriptor.replace_assets(&binding, &key, &bytes)?;
        closed
            .engines
            .publish_namespace_record_cells(&binding, &cells)
            .map_err(|_| "cipher cells")?;
        closed
            .namespaces
            .install_custody_owner(&closed.cluster_id, actual, descriptor)
            .map_err(|_| "descriptor")?;
        closed
            .namespaces
            .set_sealed(actual, true)
            .map_err(|_| "closed routing owner")?;
        closed.schema = closed.writer_schema();
        service
            .commit_state(&mut closed)
            .map_err(|_| "actual protected publication")?;
        service.namespace_runtime.close(actual);
        service.state = Some(closed);
        restore(service, actual, &created)?;
        Ok(created)
    }

    fn restore(service: &mut Service, actual: &str, created: &Created) -> TestResult {
        let state = service.state.as_ref().ok_or("state")?;
        let descriptor = state.namespaces.custody_owner(actual).ok_or("descriptor")?;
        let key = key(descriptor, created)?;
        let candidate = service
            .namespace_runtime
            .restore(state, actual, key)
            .map_err(|_| "actual typed restore")?;
        service.state = Some(candidate);
        Ok(())
    }

    fn new_namespace(service: &mut Service, root: &str, parent: &str, name: &str) -> TestResult {
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    &format!("sys/namespaces/{name}"),
                    parent,
                    root,
                    json!({}),
                    100
                )
                .status
                == 200,
            "actual namespace created"
        );
        Ok(())
    }

    fn mounted_record(
        service: &mut Service,
        root: &str,
        namespace: &str,
        marker: &str,
    ) -> TestResult {
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    "sys/mounts/records",
                    namespace,
                    root,
                    json!({"type":"kv", "options":{"version":"1"}}),
                    100
                )
                .status
                == 204,
            "actual KV owner mounted"
        );
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    "records/value",
                    namespace,
                    root,
                    json!({"marker":marker, "large":"x".repeat(4096)}),
                    100
                )
                .status
                == 204,
            "actual bounded record written"
        );
        Ok(())
    }

    #[test]
    fn loaded_namespace_publication_keeps_root_ciphertext_and_rejects_stale_plan() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap_unmounted(&mut service)?;
        new_namespace(&mut service, &token, "", "custody")?;
        new_namespace(&mut service, &token, "custody", "child")?;
        mounted_record(&mut service, &token, "", "unrelated-root-record")?;
        mounted_record(&mut service, &token, "custody", "protected-live-marker")?;
        mounted_record(
            &mut service,
            &token,
            "custody/child",
            "protected-child-marker",
        )?;
        let created = install(&mut service, "custody")?;
        assert!(
            service
                .namespace_fixture_at("GET", "records/value", "custody", &token, json!({}), 100)
                .status
                == 200,
            "actual loaded KV route accepts the real root principal"
        );
        let identity = service.current_state_identity().map_err(|_| "identity")?;
        assert!(
            service
                .namespace_fixture_at("GET", "records/value", "custody", &token, json!({}), 100)
                .status
                == 200
                && service.current_state_identity().map_err(|_| "identity")? == identity,
            "read does not randomize ciphertext or allocate a publication"
        );
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    "records/value",
                    "custody",
                    &token,
                    json!({"marker":"new-protected-live-marker", "large":"y".repeat(4096)}),
                    100
                )
                .status
                == 204,
            "actual mutation passes the protected publication boundary"
        );
        let logical = service.state.as_ref().ok_or("logical")?;
        let encoded = owner_store::serialize_owner(logical)?;
        for marker in [
            "protected-live-marker",
            "new-protected-live-marker",
            "protected-child-marker",
        ] {
            assert!(
                !encoded
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes()),
                "root serialized owner contains no loaded namespace plaintext"
            );
        }
        let manifest = service.record_root.as_ref().ok_or("record root")?;
        let persisted = Service::materialize_record_state(
            manifest,
            &records::DurableReader(service.durable.as_ref().ok_or("durable")?),
        )
        .map_err(|_| "actual reopen")?;
        assert!(
            persisted.namespace_is_sealed("custody")
                && !persisted.namespace_exists("custody/child")
                && persisted.engines.namespace_is_empty("custody")
                && persisted.auth.namespace_is_empty("custody"),
            "genuine V5 durable graph has only the closed namespace owner"
        );
        let mut old = service.state.clone().ok_or("old candidate")?;
        let stale = service
            .prepare_record_plan(&mut old)
            .map_err(|_| "old plan")?;
        let mut closed = service
            .namespace_runtime
            .closed_candidate(service.state.as_ref().ok_or("state")?, "custody")
            .map_err(|_| "manual closure candidate")?;
        service
            .commit_state(&mut closed)
            .map_err(|_| "manual closure publication")?;
        service.namespace_runtime.close("custody");
        service.state = Some(closed);
        let closed_identity = service.current_state_identity().map_err(|_| "identity")?;
        assert!(
            old.namespace_leases.validate().is_err()
                && owner_store::serialize_owner(&old).is_err()
                && service.commit_record_plan(&old, stale).is_err()
                && service.current_state_identity().map_err(|_| "identity")? == closed_identity,
            "revocation reaches a pinned stale State and plan before publication"
        );
        assert!(
            service
                .namespace_fixture_at("GET", "records/value", "custody", &token, json!({}), 100)
                .status
                == 503
                && service
                    .namespace_fixture_at("GET", "records/value", "", &token, json!({}), 100)
                    .status
                    == 200,
            "manual namespace closure preserves the unrelated root owner"
        );
        restore(&mut service, "custody", &created)?;
        let response =
            service.namespace_fixture_at("GET", "records/value", "custody", &token, json!({}), 100);
        assert!(
            response.status == 200
                && response.body["data"]["marker"] == "new-protected-live-marker",
            "fresh original shares restore the last actually committed namespace value"
        );
        Ok(())
    }

    #[test]
    fn ancestor_closure_retires_independent_child_slot_and_restores_each_owner_separately()
    -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap_unmounted(&mut service)?;
        new_namespace(&mut service, &token, "", "outer")?;
        new_namespace(&mut service, &token, "outer", "inner")?;
        new_namespace(&mut service, &token, "outer/inner", "child")?;
        for (namespace, marker) in [
            ("outer", "outer-secret"),
            ("outer/inner", "inner-secret"),
            ("outer/inner/child", "inner-child-secret"),
        ] {
            mounted_record(&mut service, &token, namespace, marker)?;
        }
        let inner = install(&mut service, "outer/inner")?;
        let outer = install(&mut service, "outer")?;
        restore(&mut service, "outer/inner", &inner)?;
        let mut pinned_inner = service.state.clone().ok_or("pinned independent child")?;
        let stale = service
            .prepare_record_plan(&mut pinned_inner)
            .map_err(|_| "child plan")?;
        let mut closed = service
            .namespace_runtime
            .closed_candidate(service.state.as_ref().ok_or("state")?, "outer")
            .map_err(|_| "ancestor candidate")?;
        service
            .commit_state(&mut closed)
            .map_err(|_| "ancestor publication")?;
        service.namespace_runtime.close("outer");
        service.state = Some(closed);
        assert!(
            pinned_inner.namespace_leases.validate().is_err()
                && service.commit_record_plan(&pinned_inner, stale).is_err(),
            "ancestor closure retires the child's independently held slot"
        );
        restore(&mut service, "outer", &outer)?;
        assert!(
            service
                .namespace_fixture_at("GET", "records/value", "outer", &token, json!({}), 100)
                .status
                == 200
                && service
                    .namespace_fixture_at(
                        "GET",
                        "records/value",
                        "outer/inner",
                        &token,
                        json!({}),
                        100
                    )
                    .status
                    == 503
                && !service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .namespace_exists("outer/inner/child"),
            "parent shares restore parent resources and the still-closed independent child descriptor"
        );
        restore(&mut service, "outer/inner", &inner)?;
        for namespace in ["outer/inner", "outer/inner/child"] {
            assert!(
                service
                    .namespace_fixture_at("GET", "records/value", namespace, &token, json!({}), 100)
                    .status
                    == 200,
                "child's own shares restore its resources and ordinary child assets"
            );
        }
        let encoded = owner_store::serialize_owner(service.state.as_ref().ok_or("state")?)?;
        assert!(
            !encoded
                .windows("inner-secret".len())
                .any(|window| window == b"inner-secret"),
            "parent canonical owner cannot contain the independently restored child's plaintext"
        );
        let _ = call(&mut service, "GET", "sys/health", &token, json!({}));
        Ok(())
    }
}
