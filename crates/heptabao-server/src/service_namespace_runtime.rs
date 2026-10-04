//! Process-local custody and canonical publication view. Candidate leases share
//! a revocable slot, never an Arc<Key>; revocation drops and zeroizes the sole
//! key even while an old prepared candidate keeps the slot alive.
use super::*;
use crate::namespace_custody::{
    Binding, Descriptor, InheritedDescriptor, InheritedParent, Key, Progress, Submission,
};
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

#[derive(Clone)]
enum Owner {
    Independent(Descriptor),
    Inherited(InheritedDescriptor),
}

/// Process-local response fencing only. These public owner fields never grant
/// a key or actor and do not include a generation changed by unrelated writes.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct DeliveryBinding(Vec<(Binding, u64, u64, Option<InheritedParent>)>);

impl DeliveryBinding {
    pub(super) fn capture(state: &State, actual: &str) -> Self {
        let mut path = String::new();
        let mut owners = Vec::new();
        for component in actual.split('/').filter(|part| !part.is_empty()) {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(component);
            if let Ok(owner) = Owner::actual(state, &path) {
                owners.push((
                    owner.binding().clone(),
                    owner.key_epoch(),
                    owner.seal_frontier(),
                    owner.parent().cloned(),
                ));
            }
        }
        Self(owners)
    }
}

impl Owner {
    fn actual(state: &State, actual: &str) -> Result<Self, Response> {
        match (
            state.namespaces.custody_owner(actual),
            state.namespaces.inherited_owner(actual),
        ) {
            (Some(owner), None) => Ok(Self::Independent(owner.clone())),
            (None, Some(owner)) => Ok(Self::Inherited(owner.clone())),
            _ => Err(unavailable()),
        }
    }
    fn binding(&self) -> &Binding {
        match self {
            Self::Independent(owner) => owner.binding(),
            Self::Inherited(owner) => owner.binding(),
        }
    }
    fn key_epoch(&self) -> u64 {
        match self {
            Self::Independent(owner) => owner.key_epoch(),
            Self::Inherited(_) => 1,
        }
    }
    fn seal_frontier(&self) -> u64 {
        match self {
            Self::Independent(owner) => owner.seal_frontier(),
            Self::Inherited(owner) => owner.seal_frontier(),
        }
    }
    fn parent(&self) -> Option<&InheritedParent> {
        match self {
            Self::Independent(_) => None,
            Self::Inherited(owner) => Some(owner.parent()),
        }
    }
    fn open_assets(
        &self,
        binding: &Binding,
        key: &Key,
    ) -> Result<Zeroizing<Vec<u8>>, crate::namespace_custody::Error> {
        match self {
            Self::Independent(owner) => owner.open_assets(binding, key),
            Self::Inherited(owner) => owner.open_assets(binding, key),
        }
    }
    fn replace_assets(
        &self,
        binding: &Binding,
        key: &Key,
        bytes: &[u8],
    ) -> Result<Self, crate::namespace_custody::Error> {
        match self {
            Self::Independent(owner) => owner
                .replace_assets(binding, key, bytes)
                .map(Self::Independent),
            Self::Inherited(owner) => owner
                .replace_assets(binding, key, bytes)
                .map(Self::Inherited),
        }
    }
    fn advance_seal_frontier(
        &self,
        binding: &Binding,
        key: &Key,
    ) -> Result<Self, crate::namespace_custody::Error> {
        match self {
            Self::Independent(owner) => owner
                .advance_seal_frontier(binding, key)
                .map(Self::Independent),
            Self::Inherited(owner) => owner
                .advance_seal_frontier(binding, key)
                .map(Self::Inherited),
        }
    }
    fn install(&self, state: &mut State, actual: &str) -> Result<(), Response> {
        match self {
            Self::Independent(owner) => {
                state
                    .namespaces
                    .install_custody_owner(&state.cluster_id, actual, owner.clone())?;
                state.namespaces.set_sealed(actual, true)
            }
            Self::Inherited(owner) => {
                state.namespaces.install_inherited_owner(
                    &state.cluster_id,
                    actual,
                    owner.clone(),
                )?;
                state.namespaces.set_sealed(actual, false)
            }
        }
    }
}

struct Slot {
    key: Option<Key>,
    binding: Binding,
    key_epoch: u64,
    frontier: u64,
    parent: Option<InheritedParent>,
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
        descriptor: &Owner,
        apply: impl FnOnce(&Key) -> Result<T, Response>,
    ) -> Result<T, Response> {
        let slot = self.0.lock().map_err(|_| unavailable())?;
        if slot.binding != *descriptor.binding()
            || slot.key_epoch != descriptor.key_epoch()
            || slot.frontier != descriptor.seal_frontier()
            || slot.parent.as_ref() != descriptor.parent()
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

// Exclusive temporary typed view. It cannot be serialized, published as a
// logical State or registered as a loaded/shared key. Public entry points below
// expose only a typed database cleanup operation and a cfg-test observation.
struct ClosedInheritedParcel {
    actual: String,
    binding: Binding,
    owner: InheritedDescriptor,
    key: Key,
    private: State,
}

/// One disposable authentication view of one verified closed inherited owner.
/// Neither its complete typed state nor its key can leave this module.
pub(super) struct ClosedAuthAdmission {
    parcel: ClosedInheritedParcel,
    principal: Result<Principal, Response>,
    needs_commit: bool,
}

impl ClosedAuthAdmission {
    pub(super) fn needs_commit(&self) -> bool {
        self.needs_commit
    }
    pub(super) fn actual(&self) -> &str {
        &self.parcel.actual
    }
    pub(super) fn binding(&self) -> &Binding {
        &self.parcel.binding
    }
    pub(super) fn candidate(&self, runtime: &Runtime) -> Result<State, Response> {
        runtime.close_inherited_parcel(&self.parcel)
    }
    pub(super) fn actor(&self) -> Result<&Principal, Response> {
        self.principal.as_ref().map_err(|error| {
            Response::error(error.status, "closed namespace token admission rejected")
        })
    }
    fn current_auth(&self, current: &State) -> Result<AuthState, Response> {
        self.parcel
            .private
            .auth
            .closed_auth_context(&current.auth, &self.parcel.actual)
            .map_err(|error| Response::error(error.status, &error.message))
    }
    pub(super) fn validate_actor(&self, current: &State, now: u64) -> Result<(), Response> {
        self.current_auth(current)?
            .validate_closed_actor(self.actor()?, now)
            .map_err(|error| Response::error(error.status, &error.message))
    }
    pub(super) fn authorize(
        &self,
        current: &State,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<(), Response> {
        self.current_auth(current)?
            .authorize_request_parameters(self.actor()?, namespace, method, path, body, now)
            .map_err(|error| Response::error(error.status, &error.message))
    }
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

    pub(super) fn is_loaded(&self, actual: &str) -> bool {
        self.loaded.contains_key(actual)
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
        late: impl FnOnce(&State) -> Result<(), Response>,
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
            Ok(Submission::Pending) => {
                if let Err(error) = late(state) {
                    self.progress.remove(actual);
                    return Err(error);
                }
                Ok(None)
            }
            Ok(Submission::Unlocked { key, .. }) => {
                self.progress.remove(actual);
                self.restore_checked(state, actual, key, late).map(Some)
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
        let verifiers = state.auth.namespace_token_verifiers(actual);
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
        candidate
            .namespaces
            .capture_closed_auth_routes(&binding, verifiers)?;
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
        Self::retire_pending_delivery(&mut candidate, actual)?;
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
            let descriptor = Owner::actual(&candidate, &path)?;
            let binding = candidate
                .namespaces
                .custody_binding(&candidate.cluster_id, &path)?;
            let lease = self.loaded.get(&path).ok_or_else(unavailable)?;
            candidate = lease.with_key(&descriptor, |key| {
                let mut routed = candidate.clone();
                routed.namespaces.capture_closed_auth_routes(
                    &binding,
                    routed.auth.namespace_token_verifiers(&path),
                )?;
                let (mut next, assets, cells) = routed.partition_namespace_assets(&path, key)?;
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
                closed.install(&mut next, &path)?;
                next.namespace_leases
                    .0
                    .retain(|candidate| !Arc::ptr_eq(&candidate.0, &lease.0));
                Ok(next)
            })?;
        }
        self.prepare(&mut candidate)?;
        Ok(candidate)
    }

    /// Ordinary namespaces use their actual longest owner key. No independent
    /// share, unseal progress or caller-selected parent is manufactured here.
    pub(super) fn inherited_closed_candidate(
        &self,
        state: &State,
        actual: &str,
        root_key: &[u8; 32],
    ) -> Result<State, Response> {
        request_live()?;
        let mut candidate = state.clone();
        Self::retire_pending_delivery(&mut candidate, actual)?;
        self.prepare(&mut candidate)?;
        if candidate.namespaces.custody_owner(actual).is_some() {
            return Err(unavailable());
        }
        if candidate.namespaces.inherited_owner(actual).is_some() {
            return if self.has_loaded_within(actual) {
                self.closed_candidate(&candidate, actual)
            } else {
                Ok(candidate)
            };
        }
        if self.has_loaded_within(actual) {
            candidate = self.closed_candidate(&candidate, actual)?;
        }
        let binding = candidate
            .namespaces
            .custody_binding(&candidate.cluster_id, actual)?;
        let (owner, key) =
            if let Some(parent) = candidate.namespaces.closest_independent_ancestor(actual) {
                let descriptor = Owner::actual(&candidate, parent)?;
                let lease = self.loaded.get(parent).ok_or_else(unavailable)?;
                lease.with_key(&descriptor, |parent_key| {
                    InheritedDescriptor::create_namespace(binding.clone(), parent_key, b"{}")
                        .map_err(|_| unavailable())
                })?
            } else {
                InheritedDescriptor::create_root(binding.clone(), root_key, b"{}")
                    .map_err(|_| unavailable())?
            };
        // A legacy ordinary boolean flag is never a key. Clear it only in this
        // private candidate, where real assets are immediately encrypted and
        // detached before any publication or runtime grant is possible.
        candidate.namespaces.set_sealed(actual, false)?;
        let verifiers = candidate.auth.namespace_token_verifiers(actual);
        let (mut closed, assets, cells) = candidate.partition_namespace_assets(actual, &key)?;
        let bytes = owner_store::serialize_owner(&assets).map_err(state_serialization_error)?;
        let descriptor = owner
            .replace_assets(&binding, &key, &bytes)
            .map_err(|_| unavailable())?;
        closed
            .engines
            .publish_namespace_record_cells(&binding, &cells)
            .map_err(|_| unavailable())?;
        Owner::Inherited(descriptor).install(&mut closed, actual)?;
        closed
            .namespaces
            .capture_closed_auth_routes(&binding, verifiers)?;
        closed.schema = closed.writer_schema();
        closed.validate_format()?;
        request_live()?;
        Ok(closed)
    }

    fn retire_pending_delivery(state: &mut State, actual: &str) -> Result<(), Response> {
        // Only actual loaded typed owners are visited. Independently closed
        // descendant parcels already carry their own retired admission.
        for namespace in state.namespaces.partition_paths(actual)? {
            state.engines.retire_namespace_pending_delivery(&namespace);
            Service::retire_namespace_pending_database(state, &namespace)?;
        }
        Ok(())
    }

    fn closed_inherited_parcel(
        &self,
        state: &State,
        actual: &str,
        root_key: &[u8; 32],
    ) -> Result<ClosedInheritedParcel, Response> {
        request_live()?;
        if actual.is_empty() || self.is_loaded(actual) {
            return Err(unavailable());
        }
        let mut prepared = state.clone();
        self.prepare(&mut prepared)?;
        prepared.namespaces.validate(&prepared.cluster_id)?;
        let binding = prepared
            .namespaces
            .custody_binding(&prepared.cluster_id, actual)?;
        let owner = prepared
            .namespaces
            .inherited_owner(actual)
            .cloned()
            .ok_or_else(unavailable)?;
        if !prepared
            .namespaces
            .matches_inherited_frontier(actual, &owner)
        {
            return Err(unavailable());
        }
        let (key, bytes) =
            if let Some(parent) = prepared.namespaces.closest_independent_ancestor(actual) {
                let parent_owner = Owner::actual(&prepared, parent)?;
                if owner.parent()
                    != &(InheritedParent::Namespace {
                        binding: parent_owner.binding().clone(),
                        key_epoch: parent_owner.key_epoch(),
                    })
                {
                    return Err(unavailable());
                }
                self.loaded.get(parent).ok_or_else(unavailable)?.with_key(
                    &parent_owner,
                    |parent_key| {
                        owner
                            .open_namespace(&binding, parent_key)
                            .map_err(|_| unavailable())
                    },
                )?
            } else {
                if owner.parent()
                    != &(InheritedParent::Root {
                        cluster_id: prepared.cluster_id.clone(),
                    })
                {
                    return Err(unavailable());
                }
                owner
                    .open_root(&binding, root_key)
                    .map_err(|_| unavailable())?
            };
        let assets = serde_json::from_slice::<namespace_assets::NamespaceAssets>(&bytes)
            .map_err(|_| unavailable())?;
        let cells = prepared
            .engines
            .namespace_record_cells(&binding)
            .map_err(|_| unavailable())?;
        let private = prepared.restore_namespace_assets(actual, &key, assets, &cells)?;
        request_live()?;
        Ok(ClosedInheritedParcel {
            actual: actual.to_owned(),
            binding,
            owner,
            key,
            private,
        })
    }

    pub(super) fn closed_auth_attempt(
        &self,
        state: &State,
        actual: &str,
        root_key: &[u8; 32],
        raw: &str,
        now: u64,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<ClosedAuthAdmission, Response> {
        let mut parcel = self.closed_inherited_parcel(state, actual, root_key)?;
        let clock_changed = parcel.private.auth.is_wrapping_token(raw)
            && parcel.private.auth.advance_wrapping_clock(now);
        let principal = parcel
            .private
            .auth
            .authenticate_from(raw, now, origin_peer)
            .map_err(|error| Response::error(error.status, &error.message))
            .and_then(|actor| {
                if actor.namespace() != actual {
                    return Err(unavailable());
                }
                Ok(actor)
            });
        let needs_commit = clock_changed || principal.as_ref().is_ok_and(Principal::consumed_use);
        Ok(ClosedAuthAdmission {
            parcel,
            principal,
            needs_commit,
        })
    }

    pub(super) fn compensate_closed_database(
        &self,
        state: &State,
        actual: &str,
        root_key: &[u8; 32],
        plan: &database::DatabaseEffectPlan,
    ) -> Result<State, Response> {
        let mut parcel = self.closed_inherited_parcel(state, actual, root_key)?;
        if !plan.matches_namespace_binding(&parcel.binding) {
            return Err(unavailable());
        }
        Service::compensate_closed_database_intent(&mut parcel.private, plan)?;
        self.close_inherited_parcel(&parcel)
    }

    fn close_inherited_parcel(&self, parcel: &ClosedInheritedParcel) -> Result<State, Response> {
        let (mut closed, assets, cells) = parcel
            .private
            .partition_namespace_assets(&parcel.actual, &parcel.key)?;
        let bytes = owner_store::serialize_owner(&assets).map_err(state_serialization_error)?;
        let previous = parcel
            .owner
            .open_assets(&parcel.binding, &parcel.key)
            .map_err(|_| unavailable())?;
        let updated = if previous.as_slice() == bytes.as_slice() {
            parcel.owner.clone()
        } else {
            parcel
                .owner
                .replace_assets(&parcel.binding, &parcel.key, &bytes)
                .map_err(|_| unavailable())?
        };
        // Cleanup changes only generation. The manual closure and actual
        // parent stay closed; no loaded slot or new lease is manufactured.
        if updated.seal_frontier() != parcel.owner.seal_frontier()
            || updated.parent() != parcel.owner.parent()
        {
            return Err(unavailable());
        }
        closed
            .engines
            .publish_namespace_record_cells(&parcel.binding, &cells)
            .map_err(|_| unavailable())?;
        Owner::Inherited(updated).install(&mut closed, &parcel.actual)?;
        self.prepare(&mut closed)?;
        closed.validate_format()?;
        request_live()?;
        Ok(closed)
    }

    #[cfg(test)]
    pub(super) fn inspect_closed_database_cleanup(
        &self,
        state: &State,
        actual: &str,
        root_key: &[u8; 32],
        id: &str,
    ) -> Result<bool, Response> {
        let parcel = self.closed_inherited_parcel(state, actual, root_key)?;
        Ok(parcel.private.database.has_subtractive_cleanup(actual, id))
    }

    /// Restore only after descriptor/typed assets/private record graph have all
    /// authenticated under the actual durable owner. Installing a key is never
    /// sufficient by itself to give a caller a principal or namespace grant.
    #[cfg(test)]
    pub(super) fn restore(
        &mut self,
        state: &State,
        actual: &str,
        key: Key,
    ) -> Result<State, Response> {
        self.restore_checked(state, actual, key, |_| Ok(()))
    }

    fn restore_checked(
        &mut self,
        state: &State,
        actual: &str,
        key: Key,
        late: impl FnOnce(&State) -> Result<(), Response>,
    ) -> Result<State, Response> {
        let mut pending = BTreeMap::new();
        let mut candidate = self.restore_unpublished(state, actual, key, &mut pending)?;
        self.restore_inherited_children(&mut candidate, actual, None, &mut pending)?;
        self.publish_restored(candidate, pending, late)
    }

    /// Restore a root-key derived owner only during actual barrier activation.
    /// A temporary batch owns all new keys until every typed descendant and the
    /// original activation deadline have passed. No child slot is visible early.
    pub(super) fn restore_root_inherited(
        &mut self,
        state: &State,
        root_key: &[u8; 32],
        late: impl FnOnce(&State) -> Result<(), Response>,
    ) -> Result<State, Response> {
        let mut candidate = state.clone();
        let mut pending = BTreeMap::new();
        self.restore_inherited_children(&mut candidate, "", Some(root_key), &mut pending)?;
        self.publish_restored(candidate, pending, late)
    }

    fn publish_restored(
        &mut self,
        mut candidate: State,
        pending: BTreeMap<String, Lease>,
        late: impl FnOnce(&State) -> Result<(), Response>,
    ) -> Result<State, Response> {
        self.prepare_with_loaded(&mut candidate, &pending)?;
        if !candidate
            .namespaces
            .legacy_ordinary_sealed_paths()
            .is_empty()
        {
            return Err(Response::error(
                503,
                "legacy ordinary sealed owner requires authenticated ciphertext migration",
            ));
        }
        late(&candidate)?;
        request_live()?;
        // All fallible checks precede this batch installation. Dropping a failed
        // exclusive batch drops/zeroizes its keys without revoking existing slots.
        self.loaded.extend(pending);
        candidate.namespace_leases = Leases(self.loaded.values().cloned().collect());
        Ok(candidate)
    }

    fn restore_unpublished(
        &self,
        state: &State,
        actual: &str,
        key: Key,
        pending: &mut BTreeMap<String, Lease>,
    ) -> Result<State, Response> {
        request_live()?;
        if self.loaded.len() + pending.len() >= 1024
            || self.loaded.contains_key(actual)
            || pending.contains_key(actual)
        {
            return Err(unavailable());
        }
        let mut prepared = state.clone();
        self.prepare_with_loaded(&mut prepared, pending)?;
        let state = &prepared;
        state.namespaces.validate(&state.cluster_id)?;
        let descriptor = Owner::actual(state, actual)?;
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
        let protected = state.protected_state()?.clone();
        let lease = Lease(Arc::new(Mutex::new(Slot {
            key: Some(key),
            binding,
            key_epoch: descriptor.key_epoch(),
            frontier: descriptor.seal_frontier(),
            parent: descriptor.parent().cloned(),
        })));
        pending.insert(actual.to_owned(), lease);
        candidate.namespace_leases = Leases(
            self.loaded
                .values()
                .chain(pending.values())
                .cloned()
                .collect(),
        );
        candidate.namespace_protected = Some(Arc::new(protected));
        Ok(candidate)
    }

    fn restore_inherited_children(
        &self,
        candidate: &mut State,
        within: &str,
        root_key: Option<&[u8; 32]>,
        pending: &mut BTreeMap<String, Lease>,
    ) -> Result<(), Response> {
        let prefix = format!("{within}/");
        loop {
            let mut paths = candidate.namespaces.inherited_paths();
            paths.sort_by_key(|path| (path.split('/').count(), path.clone()));
            let mut restored = false;
            for actual in paths {
                if (!within.is_empty() && !actual.starts_with(&prefix))
                    || self.loaded.contains_key(&actual)
                    || pending.contains_key(&actual)
                {
                    continue;
                }
                let descriptor = candidate
                    .namespaces
                    .inherited_owner(&actual)
                    .cloned()
                    .ok_or_else(unavailable)?;
                let binding = candidate
                    .namespaces
                    .custody_binding(&candidate.cluster_id, &actual)?;
                let key = if let Some(parent) =
                    candidate.namespaces.closest_independent_ancestor(&actual)
                {
                    let owner = Owner::actual(candidate, parent)?;
                    if descriptor.parent()
                        != &(InheritedParent::Namespace {
                            binding: owner.binding().clone(),
                            key_epoch: owner.key_epoch(),
                        })
                    {
                        return Err(unavailable());
                    }
                    let Some(lease) = pending.get(parent).or_else(|| self.loaded.get(parent))
                    else {
                        continue;
                    };
                    lease.with_key(&owner, |parent_key| {
                        descriptor
                            .open_namespace(&binding, parent_key)
                            .map(|(key, _)| key)
                            .map_err(|_| unavailable())
                    })?
                } else {
                    let expected = InheritedParent::Root {
                        cluster_id: candidate.cluster_id.clone(),
                    };
                    if descriptor.parent() != &expected {
                        return Err(unavailable());
                    }
                    let Some(root_key) = root_key else {
                        continue;
                    };
                    descriptor
                        .open_root(&binding, root_key)
                        .map(|(key, _)| key)
                        .map_err(|_| unavailable())?
                };
                *candidate = self.restore_unpublished(candidate, &actual, key, pending)?;
                restored = true;
            }
            if !restored {
                return Ok(());
            }
        }
    }

    /// Build one protected candidate from deepest independent child first.
    /// Its closed child descriptor/catalog becomes an ordinary encrypted asset
    /// of the parent; its independent key is never given to that parent.
    pub(super) fn prepare(&self, state: &mut State) -> Result<(), Response> {
        self.prepare_with_loaded(state, &BTreeMap::new())
    }

    fn prepare_with_loaded(
        &self,
        state: &mut State,
        pending: &BTreeMap<String, Lease>,
    ) -> Result<(), Response> {
        let loaded = |actual: &str| pending.get(actual).or_else(|| self.loaded.get(actual));
        state.namespace_leases.validate()?;
        if state.namespace_leases.is_empty() {
            state.namespace_protected = None;
            return Ok(());
        }
        let mut paths = Vec::with_capacity(state.namespace_leases.0.len());
        for lease in &state.namespace_leases.0 {
            let slot = lease.0.lock().map_err(|_| unavailable())?;
            let actual = slot.binding.namespace();
            if loaded(actual).is_none_or(|current| !Arc::ptr_eq(&current.0, &lease.0)) {
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
            let descriptor = Owner::actual(&protected, actual)?;
            let binding = protected
                .namespaces
                .custody_binding(&protected.cluster_id, actual)?;
            let lease = loaded(actual).ok_or_else(unavailable)?;
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
                next_descriptor.install(&mut next, actual)?;
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
            let descriptor = Owner::actual(&logical, actual)?;
            let binding = logical
                .namespaces
                .custody_binding(&logical.cluster_id, actual)?;
            let lease = loaded(actual).ok_or_else(unavailable)?;
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
                .map(|path| loaded(path).cloned().ok_or_else(unavailable))
                .collect::<Result<Vec<_>, _>>()?,
        );
        *state = logical;
        Ok(())
    }
}

impl Service {
    pub(super) fn activate_inherited_namespaces(
        &mut self,
        key: &[u8; 32],
        deadline: Option<std::time::Instant>,
    ) -> Result<(), Response> {
        let mut candidate = self.state.clone().ok_or_else(unavailable)?;
        let mut legacy = candidate.namespaces.legacy_ordinary_sealed_paths();
        legacy.sort_by_key(|path| (path.split('/').count(), path.clone()));
        let mut migrated = false;
        for actual in legacy {
            if !candidate.namespace_exists(&actual) {
                continue;
            }
            candidate = self
                .namespace_runtime
                .inherited_closed_candidate(&candidate, &actual, key)?;
            migrated = true;
        }
        if migrated {
            // A legacy boolean containing root-owned plaintext never reopens by
            // clearing that flag. Publish genuine typed ciphertext before any key
            // slot can be installed. Nested legacy flags still fail closed.
            self.commit_state(&mut candidate)?;
            self.state = Some(candidate.clone());
        }
        let candidate = self
            .namespace_runtime
            .restore_root_inherited(&candidate, key, |_| {
                if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                    return Err(unavailable());
                }
                request_live()
            })?;
        self.state = Some(candidate);
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
        // Existing canonical targets include closed descendant descriptors.
        // A new child hidden by its loaded ancestor exists only in the logical
        // candidate; publication must then re-protect that actual ancestor.
        let protected = loaded.protected_state().map_err(|_| "predecessor owner")?;
        let state = if protected.namespace_exists(actual) {
            protected.clone()
        } else {
            loaded
        };
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

    #[test]
    fn ordinary_http_unloads_real_resources_and_root_restart_restores_canonical_ciphertext()
    -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (root_share, token) = bootstrap_unmounted(&mut service)?;
        new_namespace(&mut service, &token, "", "plain")?;
        new_namespace(&mut service, &token, "plain", "child")?;
        mounted_record(&mut service, &token, "plain", "ordinary-secret")?;
        mounted_record(&mut service, &token, "plain/child", "ordinary-child-secret")?;
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    "sys/namespaces/plain/seal",
                    "",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 204,
            "real ordinary seal acknowledgement"
        );
        let closed = service.state.as_ref().ok_or("closed")?;
        assert!(
            closed.namespaces.inherited_owner("plain").is_some()
                && !closed.namespace_is_sealed("plain")
                && closed.engines.namespace_is_empty("plain")
                && closed.auth.namespace_is_empty("plain")
                && !closed.namespace_exists("plain/child"),
            "ordinary seal unloads assets without inventing an independent barrier flag"
        );
        assert!(
            service
                .namespace_fixture_at("GET", "records/value", "plain", &token, json!({}), 100)
                .status
                == 404,
            "root sees the genuine unloaded owner route"
        );
        assert!(
            service
                .namespace_fixture_at(
                    "GET",
                    "records/value",
                    "plain/child",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 404,
            "child catalog is unloaded"
        );
        assert!(
            service
                .namespace_fixture_at(
                    "GET",
                    "sys/namespaces/plain/seal-status",
                    "",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 400,
            "ordinary owner has no Shamir status"
        );
        let encoded = owner_store::serialize_owner(service.state.as_ref().ok_or("closed")?)?;
        assert!(
            !encoded
                .windows(b"ordinary-secret".len())
                .any(|bytes| bytes == b"ordinary-secret"),
            "closed durable root excludes real plaintext"
        );
        let identity = service
            .current_state_identity()
            .map_err(|_| "closed identity")?;
        drop(service);
        let mut service = root.service()?;
        assert!(
            call(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":root_share})
            )
            .status
                == 200,
            "actual root barrier key restores ordinary runtime after restart"
        );
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "restored identity")?
                == identity,
            "runtime restoration preserves durable identity instantly"
        );
        assert!(
            owner_store::serialize_owner(service.state.as_ref().ok_or("restored")?)?.as_slice()
                == encoded.as_slice(),
            "same actual protected bytes are retained after root restoration"
        );
        for namespace in ["plain", "plain/child"] {
            assert!(
                service
                    .namespace_fixture_at("GET", "records/value", namespace, &token, json!({}), 100)
                    .status
                    == 200,
                "genuine ordinary resources restore under the actual root key"
            );
        }
        let mut stale = service.state.clone().ok_or("loaded candidate")?;
        let plan = service
            .prepare_record_plan(&mut stale)
            .map_err(|_| "loaded plan")?;
        let before = stale
            .namespaces
            .inherited_owner("plain")
            .ok_or("inherited")?
            .seal_frontier();
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    "sys/namespaces/plain/seal",
                    "",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 204,
            "manual ordinary close commits"
        );
        assert!(
            stale.namespace_leases.validate().is_err()
                && service.commit_record_plan(&stale, plan).is_err(),
            "manual ordinary close destroys keys held by stale prepared leases"
        );
        assert!(
            service
                .state
                .as_ref()
                .ok_or("closed again")?
                .namespaces
                .inherited_owner("plain")
                .ok_or("owner")?
                .seal_frontier()
                > before,
            "manual seal advances the real exact frontier"
        );
        Ok(())
    }

    #[test]
    fn ordinary_child_uses_actual_independent_parent_and_keeps_independent_grandchild_closed()
    -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap_unmounted(&mut service)?;
        new_namespace(&mut service, &token, "", "outer")?;
        let parent = install(&mut service, "outer")?;
        new_namespace(&mut service, &token, "outer", "plain")?;
        new_namespace(&mut service, &token, "outer/plain", "independent")?;
        mounted_record(
            &mut service,
            &token,
            "outer/plain",
            "ordinary-under-independent",
        )?;
        mounted_record(
            &mut service,
            &token,
            "outer/plain/independent",
            "independent-grandchild",
        )?;
        let grandchild = install(&mut service, "outer/plain/independent")?;
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    "sys/namespaces/plain/seal",
                    "outer",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 204,
            "ordinary child seal uses actual parent custody"
        );
        let state = service.state.as_ref().ok_or("state")?;
        let owner = state
            .namespaces
            .inherited_owner("outer/plain")
            .ok_or("child owner")?;
        let parent_owner = state
            .namespaces
            .custody_owner("outer")
            .ok_or("actual independent parent")?;
        assert!(
            owner.parent()
                == &(InheritedParent::Namespace {
                    binding: parent_owner.binding().clone(),
                    key_epoch: parent_owner.key_epoch()
                }),
            "true parent binding and key epoch are durable, never inferred from a path or caller"
        );
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    "sys/namespaces/outer/seal",
                    "",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 204,
            "parent closes its typed descendants"
        );
        assert!(
            service.namespace_runtime.loaded.is_empty(),
            "all actual parent and descendant slots are revoked"
        );
        let response = service.namespace_fixture_at(
            "POST",
            "sys/namespaces/outer/unseal",
            "",
            &token,
            json!({"key":hex(&parent.shares[0])}),
            100,
        );
        assert!(
            response.status == 200 && response.body["data"]["sealed"] == false,
            "actual parent share restores the complete owned batch"
        );
        assert!(
            service
                .namespace_fixture_at(
                    "GET",
                    "records/value",
                    "outer/plain",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 200,
            "parent key restores its ordinary child resources"
        );
        assert!(
            service
                .namespace_fixture_at(
                    "GET",
                    "records/value",
                    "outer/plain/independent",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 503,
            "parent key cannot unlock independent grandchild"
        );
        let response = service.namespace_fixture_at(
            "POST",
            "sys/namespaces/independent/unseal",
            "outer/plain",
            &token,
            json!({"key":hex(&grandchild.shares[0])}),
            100,
        );
        assert!(
            response.status == 200,
            "grandchild requires its own actual key share"
        );
        assert!(
            service
                .namespace_fixture_at(
                    "GET",
                    "records/value",
                    "outer/plain/independent",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 200,
            "independent resources restore only after their own key proof"
        );
        Ok(())
    }

    #[test]
    fn failed_inherited_restore_batch_releases_no_slot_and_preserves_durable_owner() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap_unmounted(&mut service)?;
        new_namespace(&mut service, &token, "", "plain")?;
        mounted_record(&mut service, &token, "plain", "no-premature-runtime-grant")?;
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    "sys/namespaces/plain/seal",
                    "",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 204,
            "real ordinary closed state"
        );
        let state = service.state.as_ref().ok_or("closed")?;
        let before = owner_store::serialize_owner(state)?;
        let root_key = service.barrier_key.as_ref().ok_or("actual root key")?;
        let mut runtime = Runtime::default();
        assert!(
            runtime
                .restore_root_inherited(state, root_key, |_| Err(Response::error(
                    403,
                    "expired actual actor"
                )))
                .is_err()
                && runtime.loaded.is_empty(),
            "late authority rejection installs no batch key slot"
        );
        assert!(
            runtime
                .restore_root_inherited(state, &[0u8; 32], |_| Ok(()))
                .is_err()
                && runtime.loaded.is_empty(),
            "failed genuine MAC validation installs no batch key slot"
        );
        assert!(
            owner_store::serialize_owner(state)?.as_slice() == before.as_slice(),
            "failed attempts cannot mutate canonical owner or resource catalog"
        );
        let actual_deadline = std::time::Instant::now() + std::time::Duration::from_millis(5);
        let _budget = crate::request_deadline::RequestDeadlineScope::enter(actual_deadline);
        assert!(
            runtime
                .restore_root_inherited(state, root_key, |_| {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    Ok(())
                })
                .is_err()
                && runtime.loaded.is_empty(),
            "original deadline expiration discards the entire unpublished key batch"
        );
        assert!(
            crate::request_deadline::current() == Some(actual_deadline),
            "restoration never renews request budget"
        );
        Ok(())
    }

    #[test]
    fn ordinary_delete_recreate_commits_retirement_and_revokes_inherited_slots() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (root_share, token) = bootstrap_unmounted(&mut service)?;
        // A genuine unrelated KV mutation installs V5 record ownership. An
        // otherwise empty legacy root has no RecordPlan/address key to pin.
        mounted_record(&mut service, &token, "", "unrelated-root-record")?;
        new_namespace(&mut service, &token, "", "empty")?;
        assert!(
            service
                .namespace_fixture_at(
                    "POST",
                    "sys/namespaces/empty/seal",
                    "",
                    &token,
                    json!({}),
                    100
                )
                .status
                == 204,
            "empty actual ordinary owner closes"
        );
        drop(service);
        let mut service = root.service()?;
        assert!(
            call(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":root_share})
            )
            .status
                == 200,
            "genuine root barrier restores empty inherited runtime"
        );
        let mut stale = service.state.clone().ok_or("loaded empty")?;
        let first = stale
            .namespaces
            .custody_binding(&stale.cluster_id, "empty")
            .map_err(|_| "first actual binding")?;
        let plan = service
            .prepare_record_plan(&mut stale)
            .map_err(|_| "old empty plan")?;
        let canonical_before =
            owner_store::serialize_owner(service.state.as_ref().ok_or("state")?)?;
        let durable = service.durable.take();
        let rejected = service.namespace_fixture_at(
            "DELETE",
            "sys/namespaces/empty",
            "",
            &token,
            json!({}),
            100,
        );
        assert!(
            rejected.status == 503
                && service.recovery_required
                && service.record_writes_since_gc >= 64
                && service.namespace_runtime.is_loaded("empty")
                && stale.namespace_leases.validate().is_ok()
                && owner_store::serialize_owner(service.state.as_ref().ok_or("retained")?)?
                    == canonical_before,
            "failed actual retirement commit retains ciphertext, live key and prepared lease"
        );
        service.durable = durable;
        let fenced = service.namespace_fixture_at(
            "DELETE",
            "sys/namespaces/empty",
            "",
            &token,
            json!({}),
            100,
        );
        assert!(
            fenced.status == 503
                && fenced.body["errors"][0]
                    == "authoritative recovery required; unseal with the stored key before retry",
            "restoring a test storage handle cannot clear actual recovery authority"
        );
        // Root restore schedules authenticated record GC. Its real missing
        // storage failure fences the service; never clear that flag or retry a
        // state publication by reinstalling a handle in the old process.
        drop(service);
        assert!(
            stale.namespace_leases.validate().is_err(),
            "process closure revokes old slots"
        );
        let mut service = root.service()?;
        assert!(
            call(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":root_share})
            )
            .status
                == 200,
            "genuine root share restores authority after the actual storage failure"
        );
        assert!(
            service.commit_record_plan(&stale, plan).is_err(),
            "old plan cannot survive actual reopen"
        );
        let mut stale = service.state.clone().ok_or("recovered owner")?;
        assert!(
            stale
                .namespaces
                .custody_binding(&stale.cluster_id, "empty")
                .map_err(|_| "recovered binding")?
                == first,
            "genuine recovery retains the same actual namespace incarnation"
        );
        let plan = service
            .prepare_record_plan(&mut stale)
            .map_err(|_| "recovered plan")?;
        let response = service.namespace_fixture_at(
            "DELETE",
            "sys/namespaces/empty",
            "",
            &token,
            json!({}),
            100,
        );
        let retained = service.state.as_ref().ok_or("delete retained state")?;
        assert!(
            response.status == 200,
            "empty delete status={} auth_empty={} engine_empty={} db_empty={} workflow_empty={} loaded={}",
            response.status,
            retained.auth.namespace_is_empty("empty"),
            retained.engines.namespace_is_empty("empty"),
            retained.database.namespace_is_empty("empty"),
            retained.namespaces.workflows.namespace_is_empty("empty"),
            service.namespace_runtime.is_loaded("empty")
        );
        assert!(
            !service.namespace_runtime.is_loaded("empty")
                && stale.namespace_leases.validate().is_err()
                && service.commit_record_plan(&stale, plan).is_err(),
            "delete destroys the real key slot and stale prepared permission"
        );
        new_namespace(&mut service, &token, "", "empty")?;
        let state = service.state.as_ref().ok_or("recreated")?;
        let next = state
            .namespaces
            .custody_binding(&state.cluster_id, "empty")
            .map_err(|_| "new actual binding")?;
        assert!(
            next != first && state.namespaces.inherited_owner("empty").is_none(),
            "new incarnation cannot inherit the retired key or descriptor"
        );
        Ok(())
    }

    #[test]
    fn failed_ordinary_ciphertext_commit_keeps_live_assets_and_publishes_no_owner() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap_unmounted(&mut service)?;
        new_namespace(&mut service, &token, "", "plain")?;
        mounted_record(
            &mut service,
            &token,
            "plain",
            "commit-failure-retains-live-assets",
        )?;
        let mut state = service.state.clone().ok_or("live candidate")?;
        let principal = state.auth.authenticate(&token, 100)?;
        let before = owner_store::serialize_owner(service.state.as_ref().ok_or("live")?)?;
        service.durable = None;
        let response = service.namespace_route(
            state,
            Some(&principal),
            &RequestView {
                method: "POST",
                path: "sys/namespaces/plain/seal",
                namespace: "",
                token: &token,
                body: &json!({}),
                now: 100,
                admission_started: std::time::Instant::now(),
                allow_forward: true,
                enforce_namespace: true,
                wrap_ttl_seconds: None,
                origin_peer: None,
                client_certificates: None,
            },
        );
        assert!(
            response.status >= 400,
            "actual missing writer rejects ordinary publication"
        );
        let retained = service.state.as_ref().ok_or("retained live owner")?;
        assert!(
            retained.namespaces.inherited_owner("plain").is_none()
                && !retained.engines.namespace_is_empty("plain")
                && owner_store::serialize_owner(retained)?.as_slice() == before.as_slice(),
            "failed real commit neither unloads live assets nor publishes a ciphertext grant"
        );
        Ok(())
    }
}
