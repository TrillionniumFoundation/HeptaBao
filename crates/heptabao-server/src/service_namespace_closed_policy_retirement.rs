//! One fixed lazy-policy retirement in an already admitted closed Auth owner.
//! The original private key stays in its affine admission. Finite-use admission
//! publishes separately before this source can match; its validator is unchanged.
use super::*;
use crate::auth::policy_retirement::PolicyRetirement;
use std::time::Instant;

fn rejected() -> Response {
    Response::error(503, "closed namespace policy retirement owner changed")
}

fn state_digest(state: &State) -> Result<[u8; 32], Response> {
    request_live()?;
    // State's normal serializer delegates to its prepared closed view. Bind
    // that view AND the actual logical owners, so retaining a valid protected
    // view cannot hide a caller's mutation of a loaded sibling or root field.
    let logical = owner_store::serialize_owner(&Wire {
        schema: state.schema,
        global_lossless_json_format: state.global_lossless_json_format,
        cluster_id: &state.cluster_id,
        replay_epoch: state.replay_epoch,
        namespaces: &state.namespaces,
        auth: &state.auth,
        engines: &state.engines,
        database: &state.database,
        raft_admin: &state.raft_admin,
    })
    .map_err(|_| rejected())?;
    let logical_digest = crate::crypto::digest(&logical);
    request_live()?;
    let canonical = owner_store::serialize_owner(state).map_err(|_| rejected())?;
    let canonical_digest = crate::crypto::digest(&canonical);
    let mut digests = [0u8; 64];
    digests[..32].copy_from_slice(&logical_digest);
    digests[32..].copy_from_slice(&canonical_digest);
    let digest = crate::crypto::digest(&digests);
    request_live()?;
    Ok(digest)
}

#[derive(PartialEq)]
struct StateBinding {
    serialized: [u8; 32],
    logical_records: Option<[u8; 32]>,
    protected_records: Option<[u8; 32]>,
}

fn state_binding(state: &State) -> Result<StateBinding, Response> {
    let serialized = state_digest(state)?;
    // EngineState deliberately skips its KV1 runtime in Serialize. Bind both
    // actual key/value views and ownership as well: a loaded sibling's edit may
    // change only its logical index. Page shape and cleared publication objects
    // do not change either logical view. Advance only the existing deadline.
    let logical_records = state
        .engines
        .record_view_binding(|| request_live().is_ok())
        .map_err(|_| rejected())?;
    let protected_records = state
        .protected_state()?
        .engines
        .record_view_binding(|| request_live().is_ok())
        .map_err(|_| rejected())?;
    request_live()?;
    Ok(StateBinding {
        serialized,
        logical_records,
        protected_records,
    })
}

fn auth_bytes(auth: &AuthState) -> Result<Zeroizing<Vec<u8>>, Response> {
    request_live()?;
    let bytes = crate::secret_serde::to_vec(auth, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| rejected())?;
    request_live()?;
    Ok(bytes)
}

/// No caller selects a private Auth candidate or receives a key. The only
/// constructor below derives a fixed batch from the actual original actor.
pub(in crate::service) struct ClosedPolicyRetirement<'a> {
    admission: &'a ClosedAuthAdmission,
    batch: PolicyRetirement<'a>,
    source_owner: InheritedDescriptor,
    candidate_owner: InheritedDescriptor,
    source_auth: AuthState,
    candidate_auth: AuthState,
    source_binding: StateBinding,
    candidate_binding: StateBinding,
    candidate: State,
    deadline: Option<Instant>,
}

impl ClosedAuthAdmission {
    pub(in crate::service) fn policy_retirement<'a>(
        &'a self,
        runtime: &Runtime,
        current: &State,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<Option<ClosedPolicyRetirement<'a>>, Response> {
        request_live()?;
        // The original response path retains its own cross-namespace refusal.
        // It cannot select another private owner for a policy mutation.
        if namespace != self.actual() {
            return Ok(None);
        }
        let actor = self.actor()?;
        let time = actor
            .request_authority_time(time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        let expected_auth = self.current_auth(current)?;
        let batch = expected_auth
            .actor_policy_retirement(actor, namespace, time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if batch.is_empty() {
            return Ok(None);
        }
        let deadline = crate::request_deadline::current();
        let source_binding = state_binding(current)?;
        if runtime.is_loaded(self.actual()) || current.namespace_is_sealed(self.actual()) {
            return Err(rejected());
        }
        let mut prepared = current.clone();
        runtime.prepare(&mut prepared)?;
        let binding = prepared
            .namespaces
            .custody_binding(&prepared.cluster_id, self.actual())?;
        let source_owner = prepared
            .namespaces
            .inherited_owner(self.actual())
            .cloned()
            .ok_or_else(rejected)?;
        if binding != self.parcel.binding
            || source_owner.binding() != &binding
            || source_owner.parent() != self.parcel.owner.parent()
            || source_owner.seal_frontier() != self.parcel.owner.seal_frontier()
            || !prepared
                .namespaces
                .matches_inherited_frontier(self.actual(), &source_owner)
        {
            return Err(rejected());
        }
        // Use the same original private key, but the actual CURRENT descriptor.
        // After finite-use publication this is its new generation; using the
        // admission's old descriptor here would reuse the previous generation.
        let raw = source_owner
            .open_assets(&binding, &self.parcel.key)
            .map_err(|_| rejected())?;
        let assets: namespace_assets::NamespaceAssets =
            serde_json::from_slice(&raw).map_err(|_| rejected())?;
        let cells = prepared
            .engines
            .namespace_record_cells(&binding)
            .map_err(|_| rejected())?;
        let private =
            prepared.restore_namespace_assets(self.actual(), &self.parcel.key, assets, &cells)?;
        if auth_bytes(&private.auth)?.as_slice() != auth_bytes(&expected_auth)?.as_slice() {
            // In particular, an uncommitted finite-use decrement cannot be
            // bundled into this separate policy publication.
            return Err(rejected());
        }
        let mut candidate_private = private.clone();
        if !batch
            .apply(&mut candidate_private.auth)
            .map_err(|error| Response::error(error.status, &error.message))?
        {
            return Err(rejected());
        }
        let current_time = actor
            .request_authority_time(time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        batch
            .validate_candidate(&private.auth, &candidate_private.auth, current_time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        let candidate_auth = (*candidate_private.auth).clone();
        let mut candidate = candidate_private
            .partition_namespace_assets(self.actual(), &self.parcel.key)?
            .finish_with_owner(|closed, assets, cells| {
                let bytes =
                    owner_store::serialize_owner(assets).map_err(state_serialization_error)?;
                let updated = source_owner
                    .replace_assets(&binding, &self.parcel.key, &bytes)
                    .map_err(|_| rejected())?;
                if updated.binding() != &binding
                    || updated.parent() != source_owner.parent()
                    || updated.seal_frontier() != source_owner.seal_frontier()
                {
                    return Err(rejected());
                }
                closed
                    .engines
                    .publish_namespace_record_cells(&binding, cells)
                    .map_err(|_| rejected())?;
                Owner::Inherited(updated).install(closed, self.actual())
            })?;
        candidate.prepare_global_lossless_json_state(Some(current))?;
        candidate.schema = candidate.writer_schema();
        runtime.prepare(&mut candidate)?;
        candidate.validate_format()?;
        let candidate_owner = candidate
            .namespaces
            .inherited_owner(self.actual())
            .cloned()
            .ok_or_else(rejected)?;
        let candidate_binding = state_binding(&candidate)?;
        // The sole logical mutation above is the closed PolicyRetirement batch
        // in the authenticated private Auth clone. The existing partition and
        // prepare paths may reseal a loaded ancestor around that changed child.
        // Freeze that one actual candidate; never independently reseal another
        // expected graph and compare randomized ancestor ciphertexts.
        let plan = ClosedPolicyRetirement {
            admission: self,
            batch,
            source_owner,
            candidate_owner,
            source_auth: (*private.auth).clone(),
            candidate_auth,
            source_binding,
            candidate_binding,
            candidate,
            deadline,
        };
        plan.check_source(current, time)?;
        Ok(Some(plan))
    }
}

impl ClosedPolicyRetirement<'_> {
    fn live(&self) -> Result<(), Response> {
        request_live()?;
        if crate::request_deadline::current() != self.deadline
            || self.deadline.is_some_and(|end| Instant::now() >= end)
        {
            return Err(rejected());
        }
        Ok(())
    }

    fn source_actor_live(&self, current: &State, time: AuthorityTime) -> Result<(), Response> {
        self.live()?;
        // Advance only the original actor's ingress clock. The batch keeps its
        // original cutoff; a time sampled before construction must not be used
        // to validate its later precise observation.
        let time = self
            .admission
            .actor()?
            .request_authority_time(time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.admission.validate_actor(current, time)?;
        self.batch
            .validate_candidate(&self.source_auth, &self.candidate_auth, time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.live()
    }

    fn check_source(&self, current: &State, time: AuthorityTime) -> Result<(), Response> {
        self.source_actor_live(current, time)?;
        if current.namespaces.inherited_owner(self.admission.actual()) != Some(&self.source_owner)
            || state_binding(current)? != self.source_binding
        {
            return Err(rejected());
        }
        // A full record view may take time to inspect. Reobserve only the
        // actor's original request clock before admitting this fixed source.
        self.source_actor_live(current, time)
    }

    pub(in crate::service) fn candidate(&self) -> State {
        // A normal mutable State clone deliberately clears the protected
        // publication view. This is an exact copy of a fixed candidate, like
        // install_committed_namespace_view_copy, until check_candidate passes.
        let mut candidate = self.candidate.clone();
        candidate.namespace_protected = self.candidate.namespace_protected.clone();
        candidate
    }

    pub(in crate::service) fn check_candidate(
        &self,
        current: &State,
        candidate: &State,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        self.check_source(current, time)?;
        if state_binding(candidate)? != self.candidate_binding {
            return Err(rejected());
        }
        self.source_actor_live(current, time)
    }

    pub(in crate::service) fn check_committed(
        &self,
        current: &State,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        self.live()?;
        let time = self
            .admission
            .actor()?
            .request_authority_time(time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.admission.validate_actor(current, time)?;
        self.batch
            .check_actor(&self.candidate_auth, time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if current.namespaces.inherited_owner(self.admission.actual())
            != Some(&self.candidate_owner)
            || state_binding(current)? != self.candidate_binding
        {
            return Err(rejected());
        }
        let time = self
            .admission
            .actor()?
            .request_authority_time(time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.admission.validate_actor(current, time)?;
        self.batch
            .check_actor(&self.candidate_auth, time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.live()
    }
}

#[cfg(test)]
#[path = "service_namespace_closed_policy_retirement_tests.rs"]
mod tests;
