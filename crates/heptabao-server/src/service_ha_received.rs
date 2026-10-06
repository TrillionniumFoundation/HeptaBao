//! Admission of an already committed HA owner is distinct from a local writer.
//! Tokens own the authenticated target; callers cannot substitute a state or
//! opt out of the local writer's Recovery commit-intent requirement.
use super::*;
use crate::ha::{CommittedApplicationState, CommittedRecordState, CommittedStateRead};
use crate::state_record_root::StateIdentity;
use heptabao_raft_runtime::ApplicationReadWitness;
use std::time::Instant;

// This private result can be constructed only after the same authenticated
// local publication owner proved supersession. It carries the original public
// denial for ordinary callers; it never grants delivery or a new publication.
pub(super) enum HaSyncProgress {
    Current,
    Superseded(Response),
}
impl HaSyncProgress {
    pub(super) fn from_record_publication(progress: HaRecordPublicationProgress) -> Self {
        match progress {
            HaRecordPublicationProgress::Current => Self::Current,
            HaRecordPublicationProgress::UnpublishedSuperseded => Self::Superseded(
                Response::error(503, "HA received target advanced before local publication"),
            ),
            HaRecordPublicationProgress::CompletedSuperseded => Self::Superseded(Response::error(
                503,
                "HA local publication is catching up to a newer committed target",
            )),
        }
    }
    pub(super) fn into_result(self) -> Result<(), Response> {
        match self {
            Self::Current => Ok(()),
            Self::Superseded(error) => Err(error),
        }
    }
}

// A selected complete application and its coeval opaque runtime witness.
// Materialized transition envelopes intentionally retain exact-current checks.
struct SelectedSupersedingApplication {
    state: State,
    identity: StateIdentity,
    witness: Option<ApplicationReadWitness>,
}

pub(super) struct ReceivedHaState {
    state: State,
    // Canonical bytes of this immutable received target; never a live proof.
    logical: Zeroizing<Vec<u8>>,
    identity: StateIdentity,
    previous: StateIdentity,
    generation: u64,
    seal: Option<SealMetadata>,
    deadline: Option<Instant>,
    publication: ReceivedPublication,
    source_witness: Option<ApplicationReadWitness>,
    shamir_owner: Option<ShamirLocalPublicationOwner>,
}

/// Private admission of this exact local Shamir instance. It is neither wire
/// metadata nor a Wrapper recovery-index owner, and grants no response delivery.
struct ShamirLocalPublicationOwner {
    ha: Arc<Mutex<crate::ha::HaProcess>>,
    seal: SealMetadata,
    unseal_nonce: Zeroizing<String>,
    barrier_digest: [u8; 32],
    deadline: Instant,
}
impl ShamirLocalPublicationOwner {
    fn capture(
        service: &Service,
        state: &State,
        deadline: Option<Instant>,
    ) -> Result<Option<Self>, Response> {
        let Some(deadline) = deadline else {
            return Ok(None);
        };
        let seal = service.seal.as_ref().ok_or_else(rejected)?;
        if seal.is_wrapper() || state.auth.has_recovery_state() {
            return Ok(None);
        }
        seal.validate().map_err(|_| rejected())?;
        if seal.schema != 1 || service.openbao_wrapper_owner.is_some() {
            return Err(rejected());
        }
        let key = service.barrier_key.as_ref().ok_or_else(rejected)?;
        let ha = service.ha.as_ref().ok_or_else(rejected)?;
        live(Some(deadline))?;
        Ok(Some(Self {
            ha: Arc::clone(ha),
            seal: seal.clone(),
            unseal_nonce: Zeroizing::new(service.unseal_nonce.clone()),
            barrier_digest: crypto::digest(key.as_slice()),
            deadline,
        }))
    }

    fn verify_instance(
        &self,
        receipt: &ReceivedHaState,
        service: &Service,
    ) -> Result<(), Response> {
        live(Some(self.deadline))?;
        if receipt.deadline != Some(self.deadline)
            || receipt.state.auth.has_recovery_state()
            || service.recovery_required
            || service.openbao_wrapper_owner.is_some()
            || self.seal.schema != 1
            || service.seal.as_ref() != Some(&self.seal)
            || receipt.seal.as_ref() != Some(&self.seal)
            || service.unseal_nonce != *self.unseal_nonce
            || service
                .ha
                .as_ref()
                .is_none_or(|ha| !Arc::ptr_eq(ha, &self.ha))
            || service
                .barrier_key
                .as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != self.barrier_digest)
        {
            return Err(rejected());
        }
        self.seal.validate().map_err(|_| rejected())?;
        receipt.verify_local_seal(service)?;
        live(Some(self.deadline))
    }

    fn verify(&self, receipt: &ReceivedHaState, service: &mut Service) -> Result<(), Response> {
        live(Some(self.deadline))?;
        // Only the immutable target is reused. The service and durable graph
        // are still independently read and checked at every original gate.
        let logical = receipt.logical.as_slice();
        if receipt.deadline != Some(self.deadline)
            || receipt.state.auth.has_recovery_state()
            || service.recovery_required
            || service.openbao_wrapper_owner.is_some()
            || self.seal.schema != 1
            || service.seal.as_ref() != Some(&self.seal)
            || receipt.seal.as_ref() != Some(&self.seal)
            || service.unseal_nonce != *self.unseal_nonce
            || service
                .ha
                .as_ref()
                .is_none_or(|ha| !Arc::ptr_eq(ha, &self.ha))
            || service
                .barrier_key
                .as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != self.barrier_digest)
            || service.current_state_identity()? != receipt.identity
            || owner_store::serialize_owner(service.state.as_ref().ok_or_else(rejected)?)
                .map_err(state_serialization_error)?
                .as_slice()
                != logical
        {
            return Err(rejected());
        }
        self.seal.validate().map_err(|_| rejected())?;
        receipt.verify_local_seal(service)?;
        receipt.verify_local_publication_with_logical(service, logical)?;
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        live(Some(self.deadline))
    }
}

/// A readonly owner of the complete original local A, before any B write.
/// This is not a CompletedLocalPublication and cannot repair an index or grant
/// delivery. Its only result is withholding this received B for a later sync.
struct UnpublishedLocalAdmission {
    identity: StateIdentity,
    generation: u64,
    logical: Zeroizing<Vec<u8>>,
    published: Zeroizing<Vec<u8>>,
}
impl UnpublishedLocalAdmission {
    fn capture(receipt: &ReceivedHaState, service: &mut Service) -> Result<Self, Response> {
        let owner = receipt.shamir_owner.as_ref().ok_or_else(rejected)?;
        owner.verify_instance(receipt, service)?;
        let durable = service.durable.as_ref().ok_or_else(rejected)?;
        let publication = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        let local = Self {
            identity: service.current_state_identity()?,
            generation: durable.generation(),
            logical: owner_store::serialize_owner(service.state.as_ref().ok_or_else(rejected)?)
                .map_err(state_serialization_error)?,
            published: Zeroizing::new(publication.expose().to_vec()),
        };
        local.verify(receipt, service)?;
        Ok(local)
    }

    fn verify(&self, receipt: &ReceivedHaState, service: &mut Service) -> Result<(), Response> {
        live(receipt.deadline)?;
        receipt
            .shamir_owner
            .as_ref()
            .ok_or_else(rejected)?
            .verify_instance(receipt, service)?;
        if self.identity != receipt.previous
            || self.generation != receipt.generation
            || service.current_state_identity()? != self.identity
            || owner_store::serialize_owner(service.state.as_ref().ok_or_else(rejected)?)
                .map_err(state_serialization_error)?
                .as_slice()
                != self.logical.as_slice()
        {
            return Err(rejected());
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        let durable = service.durable.as_ref().ok_or_else(rejected)?;
        if durable.recovery_required() || durable.generation() != self.generation {
            return Err(rejected());
        }
        let publication = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        if publication.expose() != self.published.as_slice() {
            return Err(rejected());
        }
        // Authenticate every durable owner/object, including the Records graph.
        // Neither a warm logical digest nor an unchanged generation is enough.
        let (loaded, _, _) = Service::load_state_from_durable(durable)?;
        if owner_store::serialize_owner(&loaded)
            .map_err(state_serialization_error)?
            .as_slice()
            != self.logical.as_slice()
            || durable.replay_epoch() != loaded.replay_epoch
        {
            return Err(rejected());
        }
        match self.identity {
            StateIdentity::Legacy(digest) => {
                if records::decode_root(publication.expose())?.is_some()
                    || crypto::digest(&self.logical) != digest
                {
                    return Err(rejected());
                }
                if let Some(manifest) =
                    owner_store::decode_manifest(publication.expose()).map_err(|_| rejected())?
                {
                    manifest
                        .verify_logical(&self.logical)
                        .map_err(|_| rejected())?;
                }
            }
            StateIdentity::RecordsV5(_) => {
                let root = RecordStateRoot::decode(publication.expose()).map_err(|_| rejected())?;
                if root.identity().map_err(|_| rejected())? != self.identity
                    || root.state_schema != loaded.schema
                    || root.cluster_id != loaded.cluster_id
                    || root.replay_epoch != loaded.replay_epoch
                {
                    return Err(rejected());
                }
            }
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        if service.durable.as_ref().ok_or_else(rejected)?.generation() != self.generation {
            return Err(rejected());
        }
        receipt
            .shamir_owner
            .as_ref()
            .ok_or_else(rejected)?
            .verify_instance(receipt, service)?;
        live(receipt.deadline)
    }
}

/// Negative integrity observation of the same complete local Shamir owner.
/// This is never a received, completed, quorum, or response authority. Its only
/// consumer may retain loaded buffers and withhold a failed no-write request.
// A canonical local graph digest is not the digest of a historical HA wire
// envelope. It is private, non-transferable and only supports a negative
// integrity observation after the actual durable bundle has authenticated.
struct LocalCanonicalDigest([u8; 32]);
impl LocalCanonicalDigest {
    fn of(bytes: &[u8]) -> Self {
        Self(crypto::digest(bytes))
    }
    fn matches(&self, bytes: &[u8]) -> bool {
        self.0 == crypto::digest(bytes)
    }
}

pub(super) struct UnchangedShamirLocalOwner {
    ha: Arc<Mutex<crate::ha::HaProcess>>,
    seal: SealMetadata,
    unseal_nonce: Zeroizing<String>,
    barrier_digest: [u8; 32],
    original_deadline: Instant,
    identity: StateIdentity,
    local_digest: LocalCanonicalDigest,
    generation: u64,
    logical: Zeroizing<Vec<u8>>,
    published: Zeroizing<Vec<u8>>,
}
impl UnchangedShamirLocalOwner {
    pub(super) fn capture(
        service: &mut Service,
        deadline: Option<Instant>,
    ) -> Result<Option<Self>, Response> {
        let Some(original_deadline) = deadline else {
            return Ok(None);
        };
        live(Some(original_deadline))?;
        let state = service.state.as_ref().ok_or_else(rejected)?;
        let seal = service.seal.as_ref().ok_or_else(rejected)?;
        if seal.is_wrapper() || state.auth.has_recovery_state() {
            return Ok(None);
        }
        if seal.schema != 1 || service.openbao_wrapper_owner.is_some() {
            return Err(rejected());
        }
        let durable = service.durable.as_ref().ok_or_else(rejected)?;
        let publication = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        let logical = owner_store::serialize_owner(state).map_err(state_serialization_error)?;
        let local_digest = LocalCanonicalDigest::of(&logical);
        let owner = Self {
            ha: Arc::clone(service.ha.as_ref().ok_or_else(rejected)?),
            seal: seal.clone(),
            unseal_nonce: Zeroizing::new(service.unseal_nonce.clone()),
            barrier_digest: crypto::digest(
                service
                    .barrier_key
                    .as_ref()
                    .ok_or_else(rejected)?
                    .as_slice(),
            ),
            original_deadline,
            identity: service.current_state_identity()?,
            local_digest,
            generation: durable.generation(),
            logical,
            published: Zeroizing::new(publication.expose().to_vec()),
        };
        owner.verify_negative(service, deadline)?;
        Ok(Some(owner))
    }

    // The original request may have exhausted its budget. These reads cannot
    // admit any response or write, renew that budget, or establish current HA
    // authority; they only distinguish intact unchanged local buffers from a
    // corrupted/changed owner. Every later request needs its own fresh gates.
    pub(super) fn verify_negative(
        &self,
        service: &mut Service,
        deadline: Option<Instant>,
    ) -> Result<(), Response> {
        if deadline != Some(self.original_deadline)
            || service.recovery_required
            || service.audit_failed
            || service.openbao_wrapper_owner.is_some()
            || service.seal.as_ref() != Some(&self.seal)
            || service.unseal_nonce != *self.unseal_nonce
            || service
                .ha
                .as_ref()
                .is_none_or(|ha| !Arc::ptr_eq(ha, &self.ha))
            || service
                .barrier_key
                .as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != self.barrier_digest)
            || service.current_state_identity()? != self.identity
        {
            return Err(rejected());
        }
        let state = service.state.as_ref().ok_or_else(rejected)?;
        if self.seal.schema != 1
            || self.seal.is_wrapper()
            || state.auth.has_recovery_state()
            || owner_store::serialize_owner(state)
                .map_err(state_serialization_error)?
                .as_slice()
                != self.logical.as_slice()
        {
            return Err(rejected());
        }
        self.seal.validate().map_err(|_| rejected())?;
        if load_seal_metadata(&service.data_dir)
            .ok()
            .flatten()
            .as_ref()
            != Some(&self.seal)
        {
            return Err(rejected());
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_negative_current_publication()
            .map_err(|_| rejected())?;
        let durable = service.durable.as_ref().ok_or_else(rejected)?;
        if durable.recovery_required() || durable.generation() != self.generation {
            return Err(rejected());
        }
        let publication = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        if publication.expose() != self.published.as_slice() {
            return Err(rejected());
        }
        let (loaded, _, _) = Service::load_state_from_durable(durable)?;
        let loaded_logical =
            owner_store::serialize_owner(&loaded).map_err(state_serialization_error)?;
        if loaded_logical.as_slice() != self.logical.as_slice()
            || !self.local_digest.matches(&loaded_logical)
            || durable.replay_epoch() != loaded.replay_epoch
        {
            return Err(rejected());
        }
        match self.identity {
            StateIdentity::Legacy(_) => {
                // The exact remote identity remains checked before and after
                // this observation. Local canonical bytes were independently
                // bound to the actual authenticated publication above.
                if records::decode_root(publication.expose())?.is_some() {
                    return Err(rejected());
                }
                if let Some(manifest) =
                    owner_store::decode_manifest(publication.expose()).map_err(|_| rejected())?
                {
                    manifest
                        .verify_logical(&self.logical)
                        .map_err(|_| rejected())?;
                }
            }
            StateIdentity::RecordsV5(_) => {
                let root = RecordStateRoot::decode(publication.expose()).map_err(|_| rejected())?;
                if root.identity().map_err(|_| rejected())? != self.identity
                    || root.state_schema != loaded.schema
                    || root.cluster_id != loaded.cluster_id
                    || root.replay_epoch != loaded.replay_epoch
                {
                    return Err(rejected());
                }
            }
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        if service.durable.as_ref().ok_or_else(rejected)?.generation() != self.generation
            || service.current_state_identity()? != self.identity
            || service.seal.as_ref() != Some(&self.seal)
            || service.unseal_nonce != *self.unseal_nonce
            || service
                .ha
                .as_ref()
                .is_none_or(|ha| !Arc::ptr_eq(ha, &self.ha))
            || service
                .barrier_key
                .as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != self.barrier_digest)
            || load_seal_metadata(&service.data_dir)
                .ok()
                .flatten()
                .as_ref()
                != Some(&self.seal)
        {
            return Err(rejected());
        }
        Ok(())
    }
}

enum ReceivedPublication {
    Materialized {
        owner_manifest_digest: Option<[u8; 32]>,
    },
    Records {
        root_bytes: Zeroizing<Vec<u8>>,
    },
}

pub(super) struct ReceivedHaRecords {
    owner: ReceivedHaState,
    plan: records::RecordPlan,
}

impl ReceivedHaRecords {
    pub(super) fn owner(&self) -> &ReceivedHaState {
        &self.owner
    }
}

/// Only complete local seal, typed durable publication and live writer
/// readback may construct this token. Unknown write outcomes never enter it.
pub(super) struct CompletedLocalPublication<'a> {
    receipt: &'a ReceivedHaState,
}

/// A readonly proof of this live Wrapper's already complete durable B. It
/// grants no HA authority until paired with an independently received target.
pub(super) struct ExistingLocalPublication {
    identity: StateIdentity,
    generation: u64,
    seal: SealMetadata,
    logical: Zeroizing<Vec<u8>>,
    published: Zeroizing<Vec<u8>>,
    deadline: Option<Instant>,
}

impl ExistingLocalPublication {
    fn verify(&self, service: &mut Service) -> Result<(), Response> {
        live(self.deadline)?;
        if service.recovery_required
            || service.openbao_wrapper_owner.is_none()
            || !self.seal.is_wrapper()
            || service.current_state_identity()? != self.identity
            || service.seal.as_ref() != Some(&self.seal)
            || load_seal_metadata(&service.data_dir)
                .ok()
                .flatten()
                .as_ref()
                != Some(&self.seal)
            || owner_store::serialize_owner(service.state.as_ref().ok_or_else(rejected)?)
                .map_err(state_serialization_error)?
                .as_slice()
                != self.logical.as_slice()
        {
            return Err(rejected());
        }
        self.seal.validate().map_err(|_| rejected())?;
        let binding_valid = {
            #[cfg(target_os = "linux")]
            {
                let envelope =
                    openbao_wrapper::barrier::Envelope::decode(&self.seal.wrapped_barrier_key)
                        .map_err(|_| rejected())?;
                envelope.binding().map_err(|_| rejected())?
                    == service.wrapper_barrier_binding().map_err(|_| rejected())?
                    && envelope.generation() == self.seal.generation
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        };
        if !binding_valid {
            return Err(rejected());
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        let durable = service.durable.as_ref().ok_or_else(rejected)?;
        if durable.recovery_required() || durable.generation() != self.generation {
            return Err(rejected());
        }
        let publication = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        if publication.expose() != self.published.as_slice() {
            return Err(rejected());
        }
        // Read every actual durable owner/object. A warm logical digest cannot
        // stand in for the typed V4 manifest or the complete Records graph.
        let (loaded, _, _) = Service::load_state_from_durable(durable)?;
        if owner_store::serialize_owner(&loaded)
            .map_err(state_serialization_error)?
            .as_slice()
            != self.logical.as_slice()
            || durable.replay_epoch() != loaded.replay_epoch
        {
            return Err(rejected());
        }
        if loaded.auth.has_recovery_state() {
            loaded
                .auth
                .validate_recovery_credential(&loaded.cluster_id)
                .map_err(|_| rejected())?;
            let credential = loaded
                .auth
                .recovery_credential
                .as_ref()
                .ok_or_else(rejected)?;
            // Existing-complete means the public local index already names B.
            // This readonly constructor cannot perform A-to-B repair.
            if openbao_wrapper::barrier::seal_with_recovery(&self.seal, credential)
                .map_err(|_| rejected())?
                != self.seal
            {
                return Err(rejected());
            }
        }
        match self.identity {
            StateIdentity::Legacy(digest) => {
                if records::decode_root(publication.expose())?.is_some()
                    || crypto::digest(&self.logical) != digest
                {
                    return Err(rejected());
                }
                if let Some(manifest) =
                    owner_store::decode_manifest(publication.expose()).map_err(|_| rejected())?
                {
                    manifest
                        .verify_logical(&self.logical)
                        .map_err(|_| rejected())?;
                } else if loaded.auth.has_recovery_state() {
                    return Err(rejected());
                }
            }
            StateIdentity::RecordsV5(_) => {
                let root = RecordStateRoot::decode(publication.expose()).map_err(|_| rejected())?;
                if root.identity().map_err(|_| rejected())? != self.identity
                    || root.state_schema != loaded.schema
                    || root.cluster_id != loaded.cluster_id
                    || root.replay_epoch != loaded.replay_epoch
                {
                    return Err(rejected());
                }
            }
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        if service.durable.as_ref().ok_or_else(rejected)?.generation() != self.generation {
            return Err(rejected());
        }
        live(self.deadline)
    }

    pub(super) fn after_received<'a>(
        &self,
        receipt: &'a ReceivedHaState,
        service: &mut Service,
    ) -> Result<CompletedLocalPublication<'a>, Response> {
        self.verify(service)?;
        if receipt.previous != self.identity
            || receipt.identity != self.identity
            || receipt.generation != self.generation
            || receipt.seal.as_ref() != Some(&self.seal)
            || receipt.deadline != self.deadline
            || receipt.source_witness.is_none()
            || receipt.logical.as_slice() != self.logical.as_slice()
        {
            return Err(rejected());
        }
        // This also binds the exact durable kind/manifest/root to the complete
        // actual HA receipt, rather than normalizing its logical owners.
        let completed = receipt.after_publication(service)?;
        self.verify(service)?;
        Ok(completed)
    }
}

/// The index write/readback proof and typed completed local B publication are
/// both required. This private token never authorizes serving B or writing C.
pub(super) struct KnownIndexPublicationCompleted<'a> {
    receipt: &'a ReceivedHaState,
    publication: super::recovery_keys::ReadbackRecoveryIndexPublication,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HaLocalPublicationProgress {
    Current,
    Superseded,
}

// Records admission distinguishes an unpublished withholding from an actual
// completed local target. Neither withheld result authorizes response delivery.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum HaRecordPublicationProgress {
    Current,
    CompletedSuperseded,
    UnpublishedSuperseded,
}

// This proof never installs or writes the newer target. The next owned pass
// obtains its own current receipt and admits the complete newer publication.
struct SupersedingHaTarget {
    identity: StateIdentity,
    prefix: heptabao_raft_runtime::CommittedApplicationPrefix,
}

fn select_superseding_application(
    receipt: &ReceivedHaState,
    service: &Service,
) -> Result<SelectedSupersedingApplication, Response> {
    live(receipt.deadline)?;
    let ha = service.ha.as_ref().ok_or_else(rejected)?;
    let (committed, selected_witness) = {
        let process = ha.lock_for_request().map_err(|_| rejected())?;
        match process
            .record_application_witness()
            .map_err(|_| rejected())?
        {
            Some((records, witness)) => (
                CommittedStateRead::Records(Box::new(records)),
                Some(witness),
            ),
            None => (
                process
                    .latest_committed_state_if_changed(None)
                    .map_err(|_| rejected())?,
                None,
            ),
        }
    };
    let (state, identity) = match committed {
        CommittedStateRead::Materialized(committed) => {
            if crypto::digest(&committed.bytes) != committed.digest {
                return Err(rejected());
            }
            let state: State = serde_json::from_slice(&committed.bytes).map_err(|_| rejected())?;
            if state.auth.has_recovery_state()
                && (committed.owner_manifest_digest.is_none()
                    || committed.changed_owner_mask.is_none())
            {
                return Err(rejected());
            }
            if let Some(expected) = committed.owner_manifest_digest {
                let canonical =
                    owner_store::serialize_owner(&state).map_err(state_serialization_error)?;
                if canonical.as_slice() != committed.bytes.as_slice() {
                    return Err(rejected());
                }
                let operation = "validated-ha-superseding-owner";
                let binding = Service::prepare_initial_owner_plan(&state, &canonical, operation)
                    .map_err(|_| rejected())?
                    .publication_binding(operation, &canonical)
                    .map_err(|_| rejected())?;
                if binding.owner_manifest_digest() != expected {
                    return Err(rejected());
                }
            }
            (state, StateIdentity::Legacy(committed.digest))
        }
        CommittedStateRead::Records(committed) => {
            let (state, plan) = Service::materialize_committed_ha_records(ha, &committed).inspect_err(|error| {
                    eprintln!("heptabao-shamir-terminal-diagnostic: stage=superseding_materialize status={}", error.status);
                })?;
            if plan.root.identity().map_err(|_| rejected())? != committed.identity
                || plan.root.encode().map_err(|_| rejected())?.as_slice()
                    != committed.root_bytes.as_slice()
            {
                return Err(rejected());
            }
            (state, committed.identity)
        }
        _ => return Err(rejected()),
    };
    live(receipt.deadline)?;
    Ok(SelectedSupersedingApplication {
        state,
        identity,
        witness: selected_witness,
    })
}

fn verify_superseding_application(
    receipt: &ReceivedHaState,
    service: &Service,
    selected: SelectedSupersedingApplication,
) -> Result<SupersedingHaTarget, Response> {
    live(receipt.deadline)?;
    let SelectedSupersedingApplication {
        state,
        identity,
        witness: selected_witness,
    } = selected;
    if identity == receipt.identity {
        return Err(rejected());
    }
    validate_received_transition(&state, &receipt.state).inspect_err(|error| {
        eprintln!(
            "heptabao-shamir-terminal-diagnostic: stage=superseding_transition status={}",
            error.status
        );
    })?;
    let ha = service.ha.as_ref().ok_or_else(rejected)?;
    let process = ha.lock_for_request().map_err(|_| rejected())?;
    if state.cluster_id != process.cluster_id() {
        return Err(rejected());
    }
    let (current, witness) = process.application_identity_witness().map_err(|_| {
        eprintln!("heptabao-shamir-terminal-diagnostic: stage=superseding_witness");
        rejected()
    })?;
    let previous = receipt.source_witness.as_ref().ok_or_else(rejected)?;
    let covered = selected_witness
        .as_ref()
        .map_or(current == identity, |selected| {
            witness.covers_application_witness(selected)
        });
    if !covered || !witness.supersedes(previous) {
        eprintln!(
            "heptabao-shamir-terminal-diagnostic: stage=superseding_final_binding same_identity={} supersedes={} selected_digest={:02x?} current_digest={:02x?} previous_prefix={:?} current_prefix={:?}",
            current == identity,
            witness.supersedes(previous),
            identity.digest(),
            current.digest(),
            previous.completed_prefix(),
            witness.completed_prefix()
        );
        return Err(rejected());
    }
    live(receipt.deadline)?;
    Ok(SupersedingHaTarget {
        identity,
        // Associate C's identity only with its own atomic applied prefix,
        // never with a later D prefix. D covers C but grants no installation.
        prefix: selected_witness.as_ref().map_or_else(
            || witness.completed_prefix(),
            ApplicationReadWitness::completed_prefix,
        ),
    })
}

impl CompletedLocalPublication<'_> {
    pub(super) fn identity(&self) -> StateIdentity {
        self.receipt.identity
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.receipt.deadline
    }

    pub(super) fn verify_local_publication(&self, service: &mut Service) -> Result<(), Response> {
        self.receipt.verify_local_publication(service)
    }

    pub(super) fn complete_index_publication(
        &self,
        service: &mut Service,
        publication: super::recovery_keys::ReadbackRecoveryIndexPublication,
    ) -> Result<KnownIndexPublicationCompleted<'_>, Response> {
        KnownIndexPublicationCompleted::verify_parts(self.receipt, &publication, service)?;
        Ok(KnownIndexPublicationCompleted {
            receipt: self.receipt,
            publication,
        })
    }

    fn superseding_target(&self, service: &Service) -> Result<SupersedingHaTarget, Response> {
        let selected = self.select_superseding_application(service)?;
        self.verify_superseding_application(service, selected)
    }

    fn select_superseding_application(
        &self,
        service: &Service,
    ) -> Result<SelectedSupersedingApplication, Response> {
        select_superseding_application(self.receipt, service)
    }
    fn verify_superseding_application(
        &self,
        service: &Service,
        selected: SelectedSupersedingApplication,
    ) -> Result<SupersedingHaTarget, Response> {
        verify_superseding_application(self.receipt, service, selected)
    }

    /// Known local Shamir completion can be retained only as a temporary
    /// synchronization rejection. It never supplies Wrapper index authority,
    /// actor admission, an old response body, or another publication attempt.
    pub(super) fn publication_progress(
        &self,
        service: &mut Service,
    ) -> Result<HaLocalPublicationProgress, Response> {
        let Some(owner) = self.receipt.shamir_owner.as_ref() else {
            return self.progress(service);
        };
        owner.verify(self.receipt, service).inspect_err(|error| {
            eprintln!(
                "heptabao-shamir-terminal-diagnostic: stage=progress_original_owner status={}",
                error.status
            );
        })?;
        let (identity, _) = owner
            .ha
            .lock_for_request()
            .map_err(|_| rejected())?
            .application_identity_witness()
            .map_err(|_| rejected())?;
        let progress = if identity == self.receipt.identity {
            HaLocalPublicationProgress::Current
        } else {
            let target = self.superseding_target(service)?;
            // This is the actual authenticated complete C/D target and its
            // same-store quorum/applied witness, never a naked index comparison.
            eprintln!(
                "heptabao-ha-shamir-completed: source_prefix={:?} target_prefix={:?} received_digest={:02x?} target_digest={:02x?}",
                self.receipt
                    .source_witness
                    .as_ref()
                    .ok_or_else(rejected)?
                    .completed_prefix(),
                target.prefix,
                self.receipt.identity.digest(),
                target.identity.digest()
            );
            HaLocalPublicationProgress::Superseded
        };
        // A remembered newer target cannot mask subsequent local key, slot,
        // durable owner or object damage while that proof was being obtained.
        owner.verify(self.receipt, service).inspect_err(|error| {
            eprintln!("heptabao-shamir-terminal-diagnostic: stage=progress_original_owner_final status={}", error.status);
        })?;
        if progress == HaLocalPublicationProgress::Superseded {
            service.ha_activation = None;
            service.ha_read_cache = None;
        }
        Ok(progress)
    }

    pub(super) fn progress(
        &self,
        service: &mut Service,
    ) -> Result<HaLocalPublicationProgress, Response> {
        live(self.receipt.deadline)?;
        let ha = service.ha.as_ref().ok_or_else(rejected)?;
        let (identity, _) = ha
            .lock_for_request()
            .map_err(|_| rejected())?
            .application_identity_witness()
            .map_err(|_| {
                eprintln!("heptabao-ha-completed: stage=post_local_readindex");
                rejected()
            })?;
        let progress = if identity == self.receipt.identity {
            HaLocalPublicationProgress::Current
        } else {
            // Retention belongs only to the same admitted Wrapper owner. A
            // Shamir receiver retains its existing permanent fence policy.
            if service.recovery_required
                || !service.seal.as_ref().is_some_and(SealMetadata::is_wrapper)
                || service.openbao_wrapper_owner.is_none()
            {
                return Err(rejected());
            }
            self.superseding_target(service)
                .inspect_err(|_| eprintln!("heptabao-ha-completed: stage=unproved_supersession"))?;
            HaLocalPublicationProgress::Superseded
        };
        self.receipt.verify_local_seal(service)?;
        self.receipt.verify_local_publication(service)?;
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        live(self.receipt.deadline)?;
        if progress == HaLocalPublicationProgress::Superseded {
            service.ha_activation = None;
            service.ha_read_cache = None;
        }
        Ok(progress)
    }
}

impl KnownIndexPublicationCompleted<'_> {
    fn verify_completed(&self, service: &mut Service) -> Result<(), Response> {
        Self::verify_parts(self.receipt, &self.publication, service)
    }

    fn verify_parts(
        receipt: &ReceivedHaState,
        publication: &super::recovery_keys::ReadbackRecoveryIndexPublication,
        service: &mut Service,
    ) -> Result<(), Response> {
        live(receipt.deadline)?;
        let source = publication.source();
        let target = publication.target();
        if service.recovery_required
            || service.openbao_wrapper_owner.is_none()
            || receipt.seal.as_ref() != Some(source)
            || service.seal.as_ref() != Some(source)
            || !source.is_wrapper()
            || !target.is_wrapper()
            || publication.observed() == receipt.identity
            || !publication
                .witness()
                .supersedes(receipt.source_witness.as_ref().ok_or_else(rejected)?)
            || service.current_state_identity()? != receipt.identity
        {
            return Err(rejected());
        }
        source.validate().map_err(|_| rejected())?;
        target.validate().map_err(|_| rejected())?;
        let credential = receipt
            .state
            .auth
            .recovery_credential
            .as_ref()
            .ok_or_else(rejected)?;
        receipt
            .state
            .auth
            .validate_recovery_credential(&receipt.state.cluster_id)
            .map_err(|_| rejected())?;
        let derived = openbao_wrapper::barrier::seal_with_recovery(source, credential)
            .map_err(|_| rejected())?;
        if &derived != target
            || !openbao_wrapper::barrier::same_provider_material(source, target)
                .map_err(|_| rejected())?
            || load_seal_metadata(&service.data_dir)
                .ok()
                .flatten()
                .as_ref()
                != Some(target)
            || owner_store::serialize_owner(service.state.as_ref().ok_or_else(rejected)?)
                .map_err(state_serialization_error)?
                .as_slice()
                != receipt.logical.as_slice()
        {
            return Err(rejected());
        }
        let binding_valid = {
            #[cfg(target_os = "linux")]
            {
                let envelope =
                    openbao_wrapper::barrier::Envelope::decode(&target.wrapped_barrier_key)
                        .map_err(|_| rejected())?;
                envelope.binding().map_err(|_| rejected())?
                    == service.wrapper_barrier_binding().map_err(|_| rejected())?
                    && envelope.generation() == target.generation
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        };
        if !binding_valid {
            return Err(rejected());
        }
        receipt.verify_local_publication(service)?;
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        live(receipt.deadline)
    }

    pub(super) fn retain_if_superseded(self, service: &mut Service) -> Result<(), Response> {
        self.verify_completed(service)?;
        // An observed changed digest alone is insufficient. Authenticate the
        // complete current C/D target and its actual strict-newer applied log.
        CompletedLocalPublication {
            receipt: self.receipt,
        }
        .superseding_target(service)?;
        self.verify_completed(service)?;
        service.seal = Some(self.publication.target().clone());
        service.ha_activation = None;
        service.ha_read_cache = None;
        Ok(())
    }
}

fn rejected() -> Response {
    Response::error(503, "HA received authority admission rejected")
}
fn live(deadline: Option<Instant>) -> Result<(), Response> {
    let deadline = match (deadline, crate::request_deadline::current()) {
        (Some(original), Some(current)) => Some(original.min(current)),
        (original, current) => original.or(current),
    };
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(rejected());
    }
    Ok(())
}

// This validates a received transition only. The caller must first authenticate
// its complete target against an actual current ReadIndex identity.
fn validate_received_transition(state: &State, previous: &State) -> Result<(), Response> {
    state.validate_format()?;
    if state.cluster_id != previous.cluster_id
        || state.schema < previous.schema
        || state.replay_epoch < previous.replay_epoch
    {
        return Err(rejected());
    }
    match (
        &previous.auth.recovery_credential,
        &state.auth.recovery_credential,
    ) {
        (Some(_), None) => return Err(rejected()),
        (Some(old), Some(new))
            if new.generation() < old.generation()
                || new.generation() == old.generation() && new != old =>
        {
            return Err(rejected());
        }
        _ => {}
    }
    Ok(())
}

impl ReceivedHaState {
    fn capture(
        service: &Service,
        state: State,
        identity: StateIdentity,
        publication: ReceivedPublication,
    ) -> Result<Self, Response> {
        let deadline = crate::request_deadline::current();
        live(deadline)?;
        let previous = service.state.as_ref().ok_or_else(rejected)?;
        validate_received_transition(&state, previous)?;
        let ha = service.ha.as_ref().ok_or_else(rejected)?;
        if state.cluster_id != ha.lock_for_request().map_err(|_| rejected())?.cluster_id() {
            return Err(rejected());
        }
        let (observed, witness) = ha
            .lock_for_request()
            .map_err(|_| rejected())?
            .application_identity_witness()
            .map_err(|_| rejected())?;
        if observed != identity {
            return Err(rejected());
        }
        let durable = service.durable.as_ref().ok_or_else(rejected)?;
        if durable.recovery_required() || service.recovery_required {
            return Err(rejected());
        }
        let shamir_owner = ShamirLocalPublicationOwner::capture(service, &state, deadline)?;
        let logical = owner_store::serialize_owner(&state).map_err(state_serialization_error)?;
        live(deadline)?;
        let token = Self {
            state,
            logical,
            identity,
            previous: service.current_state_identity()?,
            generation: durable.generation(),
            seal: service.seal.clone(),
            deadline,
            publication,
            source_witness: Some(witness),
            shamir_owner,
        };
        token.verify_local_seal(service)?;
        live(deadline)?;
        Ok(token)
    }

    pub(super) fn state(&self) -> &State {
        &self.state
    }

    pub(super) fn operation_id(&self) -> Result<String, Response> {
        live(self.deadline)?;
        // A logical digest names content, not a publication event. A→B→A must
        // not be mistaken for the first A's already completed local request.
        crypto::random::<16>()
            .map(|value| format!("hasync-{}-{}", hex(&self.identity.digest()), hex(&value)))
            .map_err(|_| rejected())
    }

    fn verify_local_seal(&self, service: &Service) -> Result<(), Response> {
        if service.seal != self.seal
            || load_seal_metadata(&service.data_dir).ok().flatten() != self.seal
        {
            return Err(rejected());
        }
        if self.state.auth.has_recovery_state() {
            let seal = self
                .seal
                .as_ref()
                .filter(|seal| seal.is_wrapper())
                .ok_or_else(rejected)?;
            seal.validate().map_err(|_| rejected())?;
            #[cfg(target_os = "linux")]
            {
                let envelope =
                    openbao_wrapper::barrier::Envelope::decode(&seal.wrapped_barrier_key)
                        .map_err(|_| rejected())?;
                if envelope.binding().map_err(|_| rejected())?
                    != service.wrapper_barrier_binding().map_err(|_| rejected())?
                    || envelope.generation() != seal.generation
                {
                    return Err(rejected());
                }
            }
            #[cfg(not(target_os = "linux"))]
            return Err(rejected());
        }
        Ok(())
    }

    pub(super) fn before_publication(&self, service: &mut Service) -> Result<(), Response> {
        live(self.deadline)?;
        self.verify_local_seal(service)?;
        if service.current_state_identity()? != self.previous
            || service.durable.as_ref().ok_or_else(rejected)?.generation() != self.generation
        {
            return Err(rejected());
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        service
            .verify_ha_state_identity(self.identity)
            .inspect_err(|_| {
                eprintln!("heptabao-ha-completed: stage=before_local_publication_identity")
            })?;
        live(self.deadline)
    }

    fn before_record_publication(&self, service: &mut Service) -> Result<bool, Response> {
        live(self.deadline)?;
        self.verify_local_seal(service)?;
        if service.current_state_identity()? != self.previous
            || service.durable.as_ref().ok_or_else(rejected)?.generation() != self.generation
        {
            return Err(rejected());
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        // Wrapper/legacy owners retain their existing strict admission. Only a
        // captured actual Shamir instance can prove an unpublished local A.
        let Some(owner) = self.shamir_owner.as_ref() else {
            service.verify_ha_state_identity(self.identity)?;
            live(self.deadline)?;
            return Ok(true);
        };
        owner.verify_instance(self, service)?;
        let (current, _) = owner
            .ha
            .lock_for_request()
            .map_err(|_| rejected())?
            .application_identity_witness()
            .map_err(|_| rejected())?;
        if current == self.identity {
            live(self.deadline)?;
            return Ok(true);
        }
        let original = UnpublishedLocalAdmission::capture(self, service)?;
        let selected = select_superseding_application(self, service)?;
        let target = verify_superseding_application(self, service, selected)?;
        // Revalidate the complete original A after all quorum/decryption work.
        // No B staging, epoch activation, local index write or durable effect has
        // been attempted on this path.
        original.verify(self, service)?;
        live(self.deadline)?;
        service.ha_activation = None;
        service.ha_read_cache = None;
        eprintln!(
            "heptabao-ha-unpublished: source_prefix={:?} target_prefix={:?} local_digest={:02x?} withheld_digest={:02x?} target_digest={:02x?}",
            self.source_witness
                .as_ref()
                .ok_or_else(rejected)?
                .completed_prefix(),
            target.prefix,
            original.identity.digest(),
            self.identity.digest(),
            target.identity.digest()
        );
        Ok(false)
    }

    fn verify_local_publication(&self, service: &mut Service) -> Result<(), Response> {
        live(self.deadline)?;
        self.verify_local_publication_with_logical(service, self.logical.as_slice())
    }

    fn verify_local_publication_with_logical(
        &self,
        service: &mut Service,
        logical: &[u8],
    ) -> Result<(), Response> {
        live(self.deadline)?;
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        let durable = service.durable.as_ref().ok_or_else(rejected)?;
        let generation = durable.generation();
        if durable.replay_epoch() != self.state.replay_epoch {
            return Err(rejected());
        }
        let published = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        match &self.publication {
            ReceivedPublication::Materialized {
                owner_manifest_digest,
            } => {
                match owner_store::decode_manifest(published.expose()).map_err(|_| rejected())? {
                    Some(manifest) => {
                        manifest.verify_logical(logical).map_err(|_| rejected())?;
                        if manifest.state_schema() != self.state.schema
                            || manifest.cluster_id() != self.state.cluster_id
                            || manifest.replay_epoch() != self.state.replay_epoch
                            || owner_manifest_digest.is_some_and(|expected| {
                                manifest.canonical_digest().ok() != Some(expected)
                            })
                        {
                            return Err(rejected());
                        }
                    }
                    None if owner_manifest_digest.is_none() => {
                        // A record root cannot prove a materialized receipt,
                        // even when its logical owners encode identical bytes.
                        if records::decode_root(published.expose())?.is_some() {
                            return Err(rejected());
                        }
                        // Preserve the historical unbound HA format projection.
                        // An owner-bound receipt must always read back as V4.
                        let (loaded, _, _) = Service::load_state_from_durable(durable)?;
                        if owner_store::serialize_owner(&loaded)
                            .map_err(state_serialization_error)?
                            .as_slice()
                            != logical
                            || loaded.schema != self.state.schema
                            || loaded.cluster_id != self.state.cluster_id
                            || loaded.replay_epoch != self.state.replay_epoch
                        {
                            return Err(rejected());
                        }
                    }
                    None => return Err(rejected()),
                }
            }
            ReceivedPublication::Records { root_bytes } => {
                let root = RecordStateRoot::decode(published.expose()).map_err(|_| rejected())?;
                if published.expose() != root_bytes.as_slice()
                    || root.identity().map_err(|_| rejected())? != self.identity
                    || root.state_schema != self.state.schema
                    || root.cluster_id != self.state.cluster_id
                    || root.replay_epoch != self.state.replay_epoch
                {
                    return Err(rejected());
                }
            }
        }
        // The typed root/manifest names a graph, not proof that its actual
        // reachable owner/object bytes remain intact after publication. Reload
        // all of that graph from this live writer at its CURRENT generation.
        let (loaded, _, rewrite) = Service::load_state_from_durable(durable)?;
        if rewrite
            || loaded.schema != self.state.schema
            || loaded.cluster_id != self.state.cluster_id
            || loaded.replay_epoch != self.state.replay_epoch
            || durable.recovery_required()
            || owner_store::serialize_owner(&loaded)
                .map_err(state_serialization_error)?
                .as_slice()
                != logical
        {
            return Err(rejected());
        }
        live(self.deadline)?;
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        if service.durable.as_ref().ok_or_else(rejected)?.generation() != generation {
            return Err(rejected());
        }
        live(self.deadline)
    }

    pub(super) fn after_publication<'a>(
        &'a self,
        service: &mut Service,
    ) -> Result<CompletedLocalPublication<'a>, Response> {
        live(self.deadline)?;
        self.verify_local_seal(service)?;
        self.verify_local_publication(service).inspect_err(|_| {
            eprintln!("heptabao-ha-completed: stage=local_publication_readback")
        })?;
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        live(self.deadline)?;
        Ok(CompletedLocalPublication { receipt: self })
    }
}

impl Service {
    pub(super) fn capture_existing_ha_publication(
        &mut self,
    ) -> Result<ExistingLocalPublication, Response> {
        let result = (|| {
            let state = self.state.as_ref().ok_or_else(rejected)?;
            let durable = self.durable.as_ref().ok_or_else(rejected)?;
            let publication = durable
                .get("system", "state")
                .map_err(|_| rejected())?
                .ok_or_else(rejected)?;
            let local = ExistingLocalPublication {
                identity: self.current_state_identity()?,
                generation: durable.generation(),
                seal: self.seal.clone().ok_or_else(rejected)?,
                logical: owner_store::serialize_owner(state).map_err(state_serialization_error)?,
                published: Zeroizing::new(publication.expose().to_vec()),
                deadline: crate::request_deadline::current(),
            };
            local.verify(self)?;
            Ok(local)
        })();
        if result.is_err() {
            self.fence_recovery_delivery();
        }
        result
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn reconcile_existing_ha_publication(
        &mut self,
        local: &ExistingLocalPublication,
        receipt: &ReceivedHaState,
    ) -> Result<(), Response> {
        match self.reconcile_existing_ha_publication_progress(local, receipt)? {
            HaLocalPublicationProgress::Current => Ok(()),
            HaLocalPublicationProgress::Superseded => Err(Response::error(
                503,
                "HA existing publication is catching up to a newer committed target",
            )),
        }
    }

    pub(super) fn reconcile_existing_ha_publication_progress(
        &mut self,
        local: &ExistingLocalPublication,
        receipt: &ReceivedHaState,
    ) -> Result<HaLocalPublicationProgress, Response> {
        let result = (|| {
            let completed = local.after_received(receipt, self)?;
            let progress = completed.publication_progress(self)?;
            if progress == HaLocalPublicationProgress::Superseded {
                return Ok(progress);
            }
            self.reconcile_completed_ha_recovery_index(&completed)
        })();
        match result {
            Ok(progress) => Ok(progress),
            Err(error) => {
                self.fence_recovery_delivery();
                Err(error)
            }
        }
    }

    pub(super) fn receive_materialized_ha_state(
        &self,
        committed: &CommittedApplicationState,
    ) -> Result<ReceivedHaState, Response> {
        if crypto::digest(&committed.bytes) != committed.digest {
            return Err(rejected());
        }
        let state: State = serde_json::from_slice(&committed.bytes).map_err(|_| rejected())?;
        if state.auth.has_recovery_state()
            && (committed.owner_manifest_digest.is_none() || committed.changed_owner_mask.is_none())
        {
            return Err(rejected());
        }
        ReceivedHaState::capture(
            self,
            state,
            StateIdentity::Legacy(committed.digest),
            ReceivedPublication::Materialized {
                owner_manifest_digest: committed.owner_manifest_digest,
            },
        )
    }

    pub(super) fn receive_ha_records(
        &self,
        ha: &Arc<Mutex<HaProcess>>,
        committed: &CommittedRecordState,
    ) -> Result<ReceivedHaRecords, Response> {
        // Materialization validates every owner and reachable engine object from
        // the root bound to this actual ReadIndex. No caller-supplied State enters.
        let (state, plan) = Self::materialize_committed_ha_records(ha, committed)?;
        if plan.root.identity().map_err(|_| rejected())? != committed.identity
            || plan.root.encode().map_err(|_| rejected())?.as_slice()
                != committed.root_bytes.as_slice()
        {
            return Err(rejected());
        }
        let owner = ReceivedHaState::capture(
            self,
            state,
            committed.identity,
            ReceivedPublication::Records {
                root_bytes: committed.root_bytes.clone(),
            },
        )?;
        Ok(ReceivedHaRecords { owner, plan })
    }

    pub(super) fn install_committed_ha_records(
        &mut self,
        received: ReceivedHaRecords,
    ) -> Result<HaRecordPublicationProgress, Response> {
        if !received.owner.before_record_publication(self)? {
            return Ok(HaRecordPublicationProgress::UnpublishedSuperseded);
        }
        // Capacity is checked before immutable object staging; a failure is an
        // already committed HA owner that this node cannot yet materialize.
        self.validate_loaded_capacity(received.owner.state(), Some(&received.plan.root))?;
        let activation = self.prepare_epoch_activation(received.owner.state.replay_epoch, true)?;
        let operation = crypto::random::<16>()
            .map(|value| format!("hasync-record-{}", hex(&value)))
            .map_err(|_| rejected())?;
        self.persist_record_plan_local(&received.plan, &operation, true)
            .map_err(|_| rejected())?;
        let completed = received.owner.after_publication(self)?;
        self.record_root = Some(received.plan.root);
        self.state_digest = Some(received.owner.identity.digest());
        self.state = Some(received.owner.state.clone());
        if completed.publication_progress(self)? == HaLocalPublicationProgress::Superseded {
            return Ok(HaRecordPublicationProgress::CompletedSuperseded);
        }
        if self.reconcile_completed_ha_recovery_index(&completed)?
            == HaLocalPublicationProgress::Superseded
        {
            return Ok(HaRecordPublicationProgress::CompletedSuperseded);
        }
        self.finish_completed_ha_publication(&completed, activation)
            .map(|progress| match progress {
                HaLocalPublicationProgress::Current => HaRecordPublicationProgress::Current,
                HaLocalPublicationProgress::Superseded => {
                    HaRecordPublicationProgress::CompletedSuperseded
                }
            })
    }

    // Keep the terminal observation under the same actual publication owner.
    // A later authenticated committed prefix cannot turn completed local bytes
    // into durable corruption. It grants no response or publication replay.
    fn finish_completed_ha_publication(
        &mut self,
        completed: &CompletedLocalPublication<'_>,
        activation: Option<String>,
    ) -> Result<HaLocalPublicationProgress, Response> {
        live(completed.deadline())?;
        if self.current_state_identity()? != completed.identity() {
            return Err(rejected());
        }
        let progress = completed.publication_progress(self)?;
        live(completed.deadline())?;
        if progress == HaLocalPublicationProgress::Superseded {
            return Ok(progress);
        }
        // Original nonce is checked by the completed owner before the prepared
        // replay-epoch invalidation is deliberately installed.
        self.install_epoch_activation(activation);
        self.record_writes_since_gc = 64;
        live(completed.deadline())?;
        Ok(HaLocalPublicationProgress::Current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::RecoveryCredential;
    use crate::service::tests::{Root, bootstrap};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn protected(generation: u64, shares: u8, threshold: u8) -> Result<State, std::io::Error> {
        let (auth, _) = AuthState::bootstrap(1).map_err(|_| std::io::Error::other("bootstrap"))?;
        let mut state = State {
            schema: INDEXED_RECOVERY_WIRE_STATE_SCHEMA,
            cluster_id: "received-ha-test-cluster".into(),
            replay_epoch: 0,
            namespaces: namespaces::NamespaceRegistry::default().into(),
            auth: auth.into(),
            engines: EngineState::initialized_empty().into(),
            database: database::DatabaseState::default().into(),
            raft_admin: raft_admin::RaftAdminState::default().into(),
            namespace_protected: None,
            namespace_leases: namespace_runtime::Leases::default(),
        };
        let (credential, _) = RecoveryCredential::generate(
            crypto::digest(state.cluster_id.as_bytes()),
            generation,
            shares,
            threshold,
        )
        .map_err(|_| std::io::Error::other("credential"))?;
        state.auth.recovery_credential = Some(credential);
        Ok(state)
    }

    #[test]
    fn committed_receiver_can_miss_intent_but_local_writer_still_requires_it() -> TestResult {
        let old = protected(1, 5, 3)?;
        for generation in [2, 3] {
            let new = protected(generation, 3, 2)?;
            assert!(new.auth.recovery_intent.is_none());
            assert!(validate_received_transition(&new, &old).is_ok());
            assert!(new.validate_publication_schema(Some(&old)).is_err());
        }
        Ok(())
    }

    #[test]
    fn receiver_rejects_same_generation_authority_change_deletion_and_downgrade() -> TestResult {
        let old = protected(2, 5, 3)?;
        assert!(validate_received_transition(&old.clone(), &old).is_ok());
        // Same counts still derive a distinct protected authorization verifier.
        assert!(validate_received_transition(&protected(2, 5, 3)?, &old).is_err());
        assert!(validate_received_transition(&protected(2, 3, 2)?, &old).is_err());
        assert!(validate_received_transition(&protected(1, 5, 3)?, &old).is_err());
        let mut deleted = old.clone();
        deleted.auth.recovery_credential = None;
        assert!(validate_received_transition(&deleted, &old).is_err());
        let mut wrong_cluster = protected(3, 5, 3)?;
        wrong_cluster.cluster_id = "different-cluster".into();
        assert!(validate_received_transition(&wrong_cluster, &old).is_err());
        let mut floor = old.clone();
        floor.schema = CURRENT_STATE_SCHEMA;
        assert!(validate_received_transition(&floor, &old).is_err());
        // The generic schema comparison remains active without Recovery state.
        let mut no_recovery = deleted.clone();
        no_recovery.schema = INDEXED_RECOVERY_WIRE_STATE_SCHEMA;
        let mut lower = no_recovery.clone();
        lower.schema = LOCAL_TYPED_PKI_STATE_SCHEMA;
        assert!(lower.validate_format().is_ok());
        assert!(validate_received_transition(&lower, &no_recovery).is_err());
        Ok(())
    }

    #[test]
    fn forged_materialized_identity_and_unbound_recovery_do_not_create_admission() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        bootstrap(&mut service)?;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let state = protected(2, 3, 2)?;
        let bytes = owner_store::serialize_owner(&state)?;
        let mut committed = CommittedApplicationState {
            digest: [0; 32],
            bytes,
            legacy_whole_state: false,
            read_cursor: None,
            owner_manifest_digest: Some([0; 32]),
            changed_owner_mask: Some(31),
        };
        assert!(service.receive_materialized_ha_state(&committed).is_err());
        committed.digest = crypto::digest(&committed.bytes);
        committed.owner_manifest_digest = None;
        committed.changed_owner_mask = None;
        assert!(service.receive_materialized_ha_state(&committed).is_err());
        committed.owner_manifest_digest = Some([0; 32]);
        committed.changed_owner_mask = Some(31);
        // A correctly hashed serialization without an actual HA ReadIndex is not authority.
        assert!(service.receive_materialized_ha_state(&committed).is_err());
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        Ok(())
    }

    #[test]
    fn durable_readback_is_required_without_a_cursor_and_rejects_a_different_target() -> TestResult
    {
        let root = Root::new();
        let mut service = root.service()?;
        crate::service::tests::bootstrap_unmounted(&mut service)?;
        let state = service.state.clone().ok_or("state")?;
        let durable = service.durable.as_ref().ok_or("durable")?;
        let published = durable.get("system", "state")?.ok_or("publication")?;
        let manifest = owner_store::decode_manifest(published.expose())?.ok_or("V4")?;
        let mut receipt = ReceivedHaState {
            state: state.clone(),
            logical: owner_store::serialize_owner(&state)?,
            identity: service.current_state_identity().map_err(|_| "identity")?,
            previous: service.current_state_identity().map_err(|_| "identity")?,
            generation: durable.generation(),
            seal: service.seal.clone(),
            deadline: None,
            source_witness: None,
            shamir_owner: None,
            publication: ReceivedPublication::Materialized {
                owner_manifest_digest: Some(manifest.canonical_digest()?),
            },
        };
        assert!(service.ha_read_cache.is_none());
        assert!(receipt.verify_local_publication(&mut service).is_ok());
        receipt.publication = ReceivedPublication::Materialized {
            owner_manifest_digest: Some([0; 32]),
        };
        assert!(receipt.verify_local_publication(&mut service).is_err());
        receipt.publication = ReceivedPublication::Materialized {
            owner_manifest_digest: None,
        };
        assert!(receipt.verify_local_publication(&mut service).is_ok());
        receipt.state.cluster_id = "different-target".into();
        receipt.logical = owner_store::serialize_owner(&receipt.state)?;
        assert!(receipt.verify_local_publication(&mut service).is_err());
        receipt.state = state.clone();
        receipt.logical = owner_store::serialize_owner(&receipt.state)?;
        receipt.state.schema -= 1;
        receipt.logical = owner_store::serialize_owner(&receipt.state)?;
        assert!(receipt.verify_local_publication(&mut service).is_err());
        receipt.state = state.clone();
        receipt.logical = owner_store::serialize_owner(&receipt.state)?;
        receipt.state.replay_epoch += 1;
        receipt.logical = owner_store::serialize_owner(&receipt.state)?;
        assert!(receipt.verify_local_publication(&mut service).is_err());
        // Staging a Records root really changes the durable publication. A
        // previous materialized receipt cannot pass merely on a cached cursor.
        let mut record_state = state.clone();
        record_state.engines = record_state
            .engines
            .migrate_kv1_records(crate::state_records::AddressKey::from_bytes([29; 32]))?
            .into();
        let plan = service
            .prepare_record_plan(&mut record_state)
            .map_err(|_| "plan")?;
        let root_bytes = plan.bytes.clone();
        let identity = plan.identity;
        service
            .persist_record_plan_local(&plan, "received-readback-test", true)
            .map_err(|_| "publish received record plan")?;
        receipt.state = state.clone();
        receipt.logical = owner_store::serialize_owner(&receipt.state)?;
        assert!(receipt.verify_local_publication(&mut service).is_err());
        receipt.state = record_state;
        receipt.logical = owner_store::serialize_owner(&receipt.state)?;
        receipt.identity = identity;
        receipt.publication = ReceivedPublication::Records {
            root_bytes: root_bytes.clone(),
        };
        assert!(receipt.verify_local_publication(&mut service).is_ok());
        receipt.identity = StateIdentity::RecordsV5([0; 32]);
        assert!(receipt.verify_local_publication(&mut service).is_err());
        receipt.identity = identity;
        receipt.publication = ReceivedPublication::Records {
            root_bytes: Zeroizing::new(vec![0]),
        };
        assert!(receipt.verify_local_publication(&mut service).is_err());
        Ok(())
    }

    #[test]
    fn content_revisit_duplicate_is_rejected_and_fresh_receipt_operation_publishes() -> TestResult {
        fn write(
            service: &mut Service,
            state: &State,
            operation: &str,
        ) -> Result<MutationOutcome, Box<dyn std::error::Error>> {
            let bytes = owner_store::serialize_owner(state)?;
            let plan = Service::prepare_initial_owner_plan(state, &bytes, operation)
                .map_err(|_| "plan")?;
            let result = Service::persist_owner_state_batch(
                service.durable.as_mut().ok_or("durable")?,
                state,
                &bytes,
                operation,
                state.schema,
                state.replay_epoch,
                OwnerBatchInput {
                    options: PersistOwnerStateOptions {
                        compact_before_entry: true,
                        allow_epoch_catchup: true,
                        reuse: OwnerReuseHint::default(),
                    },
                    prepared_plan: Some(plan),
                },
            )?;
            Ok(result)
        }
        let root = Root::new();
        let mut service = root.service()?;
        crate::service::tests::bootstrap_unmounted(&mut service)?;
        let a = service.state.clone().ok_or("state")?;
        let a_bytes = owner_store::serialize_owner(&a)?;
        let fixed = format!("hasync-{}", hex(&crypto::digest(&a_bytes)));
        assert!(matches!(
            write(&mut service, &a, &fixed)?,
            MutationOutcome::Committed { .. }
        ));
        let mut b = a.clone();
        b.engines
            .handle("", "POST", "sys/mounts/revisit", &json!({"type":"kv"}), 100)?;
        assert!(matches!(
            write(&mut service, &b, "actual-B-event")?,
            MutationOutcome::Committed { .. }
        ));
        let binding = Service::prepare_initial_owner_plan(&a, &a_bytes, &fixed)
            .map_err(|_| "A plan")?
            .publication_binding(&fixed, &a_bytes)?;
        let receipt = ReceivedHaState {
            state: a.clone(),
            logical: owner_store::serialize_owner(&a)?,
            identity: StateIdentity::Legacy(crypto::digest(&a_bytes)),
            previous: service.current_state_identity().map_err(|_| "identity")?,
            generation: service.durable.as_ref().ok_or("durable")?.generation(),
            seal: service.seal.clone(),
            deadline: None,
            source_witness: None,
            shamir_owner: None,
            publication: ReceivedPublication::Materialized {
                owner_manifest_digest: Some(binding.owner_manifest_digest()),
            },
        };
        assert!(matches!(
            write(&mut service, &a, &fixed)?,
            MutationOutcome::Duplicate { .. }
        ));
        assert!(receipt.verify_local_publication(&mut service).is_err());
        let first = receipt.operation_id().map_err(|_| "fresh event")?;
        let second = receipt.operation_id().map_err(|_| "another event")?;
        assert_ne!(first, second);
        assert!(matches!(
            write(&mut service, &a, &first)?,
            MutationOutcome::Committed { .. }
        ));
        assert!(receipt.verify_local_publication(&mut service).is_ok());
        Ok(())
    }

    #[test]
    fn real_raft_completed_publication_proves_strict_newer_c_and_d_but_shamir_still_fences()
    -> TestResult {
        fn commit(
            cluster: &crate::ha::snapshot_test_support::Cluster,
            state: &State,
            previous: [u8; 32],
            operation: &str,
        ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
            let bytes = owner_store::serialize_owner(state)?;
            let binding = Service::prepare_initial_owner_plan(state, &bytes, operation)
                .map_err(|_| "owner plan")?
                .publication_binding(operation, &bytes)?;
            cluster.processes[0]
                .lock()
                .map_err(|_| "HA")?
                .commit_state_with_owner_binding(operation, previous, &bytes, binding)?;
            Ok(crypto::digest(&bytes))
        }
        let root = Root::new();
        let mut service = root.service()?;
        crate::service::tests::bootstrap_unmounted(&mut service)?;
        let a = service.state.clone().ok_or("state")?;
        let cluster =
            crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &a.cluster_id)?;
        service.ha = Some(Arc::clone(&cluster.processes[0]));
        service.sync_from_ha().map_err(|_| "anchor")?;
        // The receiver obtains every ReadIndex over the production peer RPC
        // codec and waits for its own actual applied log, rather than a leader
        // pointer or hand-made digest/term/generation.
        service.ha = Some(Arc::clone(&cluster.processes[1]));
        let mut b = a.clone();
        b.engines.handle(
            "",
            "POST",
            "sys/mounts/completed-b",
            &json!({"type":"kv"}),
            100,
        )?;
        let a_identity = service.current_state_digest().map_err(|_| "A")?;
        let b_identity = commit(&cluster, &b, a_identity, "real-completed-B")?;
        let committed = cluster.processes[1]
            .lock()
            .map_err(|_| "HA")?
            .latest_committed_state()?
            .ok_or("B committed")?;
        assert_eq!(committed.digest, b_identity);
        let receipt = service
            .receive_materialized_ha_state(&committed)
            .map_err(|_| "B admission")?;
        receipt
            .before_publication(&mut service)
            .map_err(|_| "B before")?;
        let bytes = owner_store::serialize_owner(&b)?;
        let operation = receipt.operation_id().map_err(|_| "operation")?;
        let plan =
            Service::prepare_initial_owner_plan(&b, &bytes, &operation).map_err(|_| "B plan")?;
        Service::persist_owner_state_batch(
            service.durable.as_mut().ok_or("durable")?,
            &b,
            &bytes,
            &operation,
            b.schema,
            b.replay_epoch,
            OwnerBatchInput {
                options: PersistOwnerStateOptions {
                    compact_before_entry: true,
                    allow_epoch_catchup: true,
                    reuse: OwnerReuseHint::default(),
                },
                prepared_plan: Some(plan),
            },
        )?;
        let completed = receipt
            .after_publication(&mut service)
            .map_err(|_| "B local readback")?;
        // Same target and warm generation are not a strict-newer log proof.
        assert!(completed.superseding_target(&service).is_err());
        assert_eq!(
            completed.progress(&mut service).map_err(|_| "B current")?,
            HaLocalPublicationProgress::Current
        );
        let stored_b = service
            .durable
            .as_ref()
            .ok_or("durable")?
            .get("system", "state")?;
        let generation_b = service.durable.as_ref().ok_or("durable")?.generation();
        let mut c = b.clone();
        c.replay_epoch += 1;
        c.engines.handle(
            "",
            "POST",
            "sys/mounts/completed-c",
            &json!({"type":"kv"}),
            100,
        )?;
        let c_identity = commit(&cluster, &c, b_identity, "real-completed-C")?;
        assert!(completed.superseding_target(&service).is_ok());
        let selected_c = completed
            .select_superseding_application(&service)
            .map_err(|_| "actual Materialized C")?;
        assert!(selected_c.witness.is_none());
        let mut d = c.clone();
        d.replay_epoch += 1;
        d.engines.handle(
            "",
            "POST",
            "sys/mounts/completed-d",
            &json!({"type":"kv"}),
            100,
        )?;
        let d_identity = commit(&cluster, &d, c_identity, "real-completed-D")?;
        assert_ne!(d_identity, b_identity);
        // Materialized legacy envelopes retain exact-current identity. Their C
        // has no atomic RecordsV5 witness and cannot borrow a newer D proof.
        assert!(
            completed
                .verify_superseding_application(&service, selected_c)
                .is_err()
        );
        assert!(completed.superseding_target(&service).is_ok());
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation_b
        );
        assert_eq!(
            service
                .durable
                .as_ref()
                .ok_or("durable")?
                .get("system", "state")?,
            stored_b
        );
        assert!(service.ha_read_cache.is_none());
        // The pure full-target proof borrows Service immutably; activation
        // changes only through actual Wrapper progress or the caller's fence.
        // Even a remembered complete D cannot bypass a new unavailable quorum.
        cluster.isolate_all_peers(true);
        {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                Instant::now() + Duration::from_millis(250),
            );
            assert!(completed.superseding_target(&service).is_err());
        }
        cluster.isolate_all_peers(false);
        {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                Instant::now() - Duration::from_millis(1),
            );
            assert!(completed.superseding_target(&service).is_err());
        }
        assert!(completed.progress(&mut service).is_err());
        // This fixture has actual Shamir metadata. It proves the log/complete
        // target machinery, and explicitly denies Wrapper retention authority.
        let durable_paths = ["state.hbs", "journal.hbj", "ledger.hbl", "seal.json"];
        let before_fence = durable_paths
            .iter()
            .map(|name| {
                let path = service.data_dir.join(name);
                fs::read(&path).map(|bytes| (path, bytes))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        service.fence_recovery_delivery();
        assert!(service.recovery_required);
        assert!(service.state.is_none());
        assert!(service.ha_activation.is_none());
        assert!(service.ha_read_cache.is_none());
        assert!(service.durable.is_none());
        assert!(service.barrier_key.is_none());
        for (path, bytes) in before_fence {
            assert_eq!(fs::read(path)?, bytes);
        }
        Ok(())
    }

    fn actual_shamir_completion_case(case: &str) -> TestResult {
        fn commit(
            cluster: &crate::ha::snapshot_test_support::Cluster,
            state: &State,
            previous: [u8; 32],
            operation: &str,
        ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
            let bytes = owner_store::serialize_owner(state)?;
            let binding = Service::prepare_initial_owner_plan(state, &bytes, operation)
                .map_err(|_| "owner plan")?
                .publication_binding(operation, &bytes)?;
            cluster.processes[0]
                .lock()
                .map_err(|_| "HA")?
                .commit_state_with_owner_binding(operation, previous, &bytes, binding)?;
            Ok(crypto::digest(&bytes))
        }
        let root = Root::new();
        let mut service = root.service()?;
        crate::service::tests::bootstrap_unmounted(&mut service)?;
        let a = service.state.clone().ok_or("A")?;
        let cluster =
            crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &a.cluster_id)?;
        service.ha = Some(Arc::clone(&cluster.processes[0]));
        service.sync_from_ha().map_err(|_| "actual anchor")?;
        service.ha = Some(Arc::clone(&cluster.processes[1]));
        let _admitted = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let mut b = a.clone();
        b.engines.handle(
            "",
            "POST",
            "sys/mounts/owned-shamir-b",
            &json!({"type":"kv"}),
            100,
        )?;
        let a_identity = service.current_state_digest().map_err(|_| "A identity")?;
        let b_identity = commit(&cluster, &b, a_identity, "owned-shamir-B")?;
        let committed = cluster.processes[1]
            .lock()
            .map_err(|_| "HA")?
            .latest_committed_state()?
            .ok_or("actual B")?;
        assert_eq!(committed.digest, b_identity);
        let receipt = service
            .receive_materialized_ha_state(&committed)
            .map_err(|_| "B admission")?;
        assert!(receipt.shamir_owner.is_some());
        receipt
            .before_publication(&mut service)
            .map_err(|_| "B before")?;
        let bytes = owner_store::serialize_owner(&b)?;
        let operation = receipt.operation_id().map_err(|_| "actual operation")?;
        let plan =
            Service::prepare_initial_owner_plan(&b, &bytes, &operation).map_err(|_| "B plan")?;
        Service::persist_owner_state_batch(
            service.durable.as_mut().ok_or("durable")?,
            &b,
            &bytes,
            &operation,
            b.schema,
            b.replay_epoch,
            OwnerBatchInput {
                options: PersistOwnerStateOptions {
                    compact_before_entry: true,
                    allow_epoch_catchup: true,
                    reuse: OwnerReuseHint::default(),
                },
                prepared_plan: Some(plan),
            },
        )?;
        let completed = receipt
            .after_publication(&mut service)
            .map_err(|_| "actual encrypted B readback")?;
        // Match the production materialized install after actual publication.
        service.record_root = None;
        service.state_digest = Some(b_identity);
        service.state = Some(b.clone());
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let stored_b = service
            .durable
            .as_ref()
            .ok_or("durable")?
            .get("system", "state")?;
        if case == "terminal_gate" {
            assert_eq!(
                service
                    .reconcile_completed_ha_recovery_index(&completed)
                    .map_err(|_| "B completed index")?,
                HaLocalPublicationProgress::Current
            );
        }
        let mut c = b.clone();
        c.replay_epoch += 1;
        c.engines.handle(
            "",
            "POST",
            "sys/mounts/owned-shamir-c",
            &json!({"type":"kv"}),
            100,
        )?;
        let record_case = case.starts_with("record_");
        let c_identity = if record_case {
            c.engines = c
                .engines
                .migrate_kv1_records(crate::state_records::AddressKey::from_bytes([37; 32]))?
                .into();
            let plan = service
                .prepare_record_plan(&mut c)
                .map_err(|_| "C record plan")?;
            cluster.processes[0]
                .lock()
                .map_err(|_| "HA")?
                .commit_record_state(
                    "owned-shamir-record-C",
                    &receipt.identity,
                    &plan.bytes,
                    &plan.objects,
                )?;
            plan.identity.digest()
        } else {
            commit(&cluster, &c, b_identity, "owned-shamir-C")?
        };
        assert_ne!(b_identity, c_identity);
        // The legacy Wrapper-only API still cannot mint Shamir retention.
        assert!(completed.progress(&mut service).is_err());
        match case {
            "record_covered" | "record_quorum" | "record_damage" => {
                let selected = completed
                    .select_superseding_application(&service)
                    .map_err(|_| "actual atomic C selection")?;
                assert!(selected.witness.is_some());
                assert_eq!(selected.identity.digest(), c_identity);
                let c_prefix = selected
                    .witness
                    .as_ref()
                    .ok_or("C witness")?
                    .completed_prefix();
                let mut d = c.clone();
                d.engines.handle(
                    "",
                    "POST",
                    "sys/mounts/owned-shamir-d",
                    &json!({"type":"kv"}),
                    100,
                )?;
                let plan = service
                    .prepare_record_plan(&mut d)
                    .map_err(|_| "D record plan")?;
                cluster.processes[0]
                    .lock()
                    .map_err(|_| "HA")?
                    .commit_record_state(
                        "owned-shamir-record-D",
                        &selected.identity,
                        &plan.bytes,
                        &plan.objects,
                    )?;
                let (current_d, witness_d) = cluster.processes[1]
                    .lock()
                    .map_err(|_| "HA")?
                    .application_identity_witness()?;
                assert_eq!(current_d, plan.identity);
                assert_ne!(current_d, selected.identity);
                assert!(
                    witness_d
                        .covers_application_witness(selected.witness.as_ref().ok_or("C witness")?)
                );
                let (_, other_store) = cluster.processes[2]
                    .lock()
                    .map_err(|_| "HA")?
                    .application_identity_witness()?;
                assert!(
                    !other_store
                        .covers_application_witness(selected.witness.as_ref().ok_or("C witness")?)
                );
                if case == "record_quorum" {
                    cluster.isolate_all_peers(true);
                    {
                        let _bounded = crate::request_deadline::RequestDeadlineScope::enter(
                            Instant::now() + Duration::from_millis(250),
                        );
                        assert!(
                            completed
                                .verify_superseding_application(&service, selected)
                                .is_err()
                        );
                    }
                    cluster.isolate_all_peers(false);
                    let selected = completed
                        .select_superseding_application(&service)
                        .map_err(|_| "fresh D selection")?;
                    let expired = Instant::now() - Duration::from_millis(1);
                    let _expired = crate::request_deadline::RequestDeadlineScope::enter(expired);
                    // The server's thread scope is not an implicit runtime
                    // task-local scope. Propagate the same original deadline
                    // explicitly, exactly as HaProcess::block_on_read does.
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let selected_witness = selected.witness.as_ref().ok_or("D witness")?;
                    let covered = runtime.block_on(
                        heptabao_raft_runtime::with_read_index_deadline(expired, async {
                            witness_d.covers_application_witness(selected_witness)
                        }),
                    );
                    assert!(!covered);
                    assert!(
                        completed
                            .verify_superseding_application(&service, selected)
                            .is_err()
                    );
                } else if case == "record_damage" {
                    let mut damaged = selected;
                    damaged.state.cluster_id.push('x');
                    assert!(
                        completed
                            .verify_superseding_application(&service, damaged)
                            .is_err()
                    );
                } else {
                    let target = completed
                        .verify_superseding_application(&service, selected)
                        .map_err(|_| "actual current D covers complete C")?;
                    assert_eq!(target.identity.digest(), c_identity);
                    assert_eq!(target.prefix, c_prefix);
                    assert_eq!(
                        completed
                            .publication_progress(&mut service)
                            .map_err(|_| "temporary actual D")?,
                        HaLocalPublicationProgress::Superseded
                    );
                    assert!(!service.recovery_required);
                    assert!(service.ha_activation.is_none());
                    assert!(service.ha_read_cache.is_none());
                }
                assert_eq!(
                    service.current_state_identity().map_err(|_| "local B")?,
                    receipt.identity
                );
                assert_eq!(
                    service.durable.as_ref().ok_or("durable")?.generation(),
                    generation
                );
                assert_eq!(
                    service
                        .durable
                        .as_ref()
                        .ok_or("durable")?
                        .get("system", "state")?,
                    stored_b
                );
                if case == "record_covered" {
                    service
                        .sync_from_ha()
                        .map_err(|_| "next independent sync D")?;
                    assert_eq!(
                        service.current_state_identity().map_err(|_| "current D")?,
                        plan.identity
                    );
                    assert!(!service.recovery_required);
                }
            }
            "known_completed" | "terminal_gate" => {
                let progress = if case == "terminal_gate" {
                    // The old naked terminal identity check rejects C even
                    // after B's complete local/index publication succeeded.
                    assert!(service.verify_ha_state_identity(receipt.identity).is_err());
                    service.finish_completed_ha_publication(&completed, None)
                } else {
                    completed.publication_progress(&mut service)
                }
                .map_err(|_| "actual owned Shamir newer prefix")?;
                assert_eq!(progress, HaLocalPublicationProgress::Superseded);
                assert!(!service.recovery_required);
                assert!(service.ha_activation.is_none());
                assert!(service.ha_read_cache.is_none());
                assert_eq!(
                    service.current_state_identity().map_err(|_| "local B")?,
                    receipt.identity
                );
                assert_eq!(
                    service.durable.as_ref().ok_or("durable")?.generation(),
                    generation
                );
                assert_eq!(
                    service
                        .durable
                        .as_ref()
                        .ok_or("durable")?
                        .get("system", "state")?,
                    stored_b
                );
                // Retention grants no response and does not replay B. A new
                // independent request must synchronize and authenticate C.
                service
                    .sync_from_ha()
                    .map_err(|_| "next independent sync C")?;
                assert_eq!(
                    service.current_state_digest().map_err(|_| "current C")?,
                    c_identity
                );
                assert!(!service.recovery_required);
                let (loaded, _, _) =
                    Service::load_state_from_durable(service.durable.as_ref().ok_or("durable")?)
                        .map_err(|_| "actual encrypted C")?;
                assert_eq!(
                    owner_store::serialize_owner(&loaded)?.as_slice(),
                    owner_store::serialize_owner(&c)?.as_slice()
                );
            }
            "binding_and_damage" => {
                service.unseal_nonce.push('x');
                assert!(completed.publication_progress(&mut service).is_err());
                service.unseal_nonce.pop();
                service.barrier_key.as_mut().ok_or("key")?[0] ^= 1;
                assert!(completed.publication_progress(&mut service).is_err());
                service.barrier_key.as_mut().ok_or("key")?[0] ^= 1;
                service.ha = Some(Arc::clone(&cluster.processes[0]));
                assert!(completed.publication_progress(&mut service).is_err());
                service.ha = Some(Arc::clone(&cluster.processes[1]));
                service
                    .durable
                    .as_mut()
                    .ok_or("durable")?
                    .put(PutRequest::new(
                        "owned-shamir-negative",
                        "system",
                        "actual-damaged-publication",
                        "state",
                        crypto::digest(b"invalid-local-publication"),
                        Secret::new(b"invalid-local-publication".to_vec())?,
                    )?)?;
                assert!(completed.publication_progress(&mut service).is_err());
            }
            "quorum_and_deadline" => {
                cluster.isolate_all_peers(true);
                {
                    let _bounded = crate::request_deadline::RequestDeadlineScope::enter(
                        Instant::now() + Duration::from_millis(250),
                    );
                    assert!(completed.publication_progress(&mut service).is_err());
                }
                cluster.isolate_all_peers(false);
                {
                    let _expired = crate::request_deadline::RequestDeadlineScope::enter(
                        Instant::now() - Duration::from_millis(1),
                    );
                    assert!(completed.publication_progress(&mut service).is_err());
                }
                assert_eq!(
                    service.durable.as_ref().ok_or("durable")?.generation(),
                    generation
                );
                assert_eq!(
                    service
                        .durable
                        .as_ref()
                        .ok_or("durable")?
                        .get("system", "state")?,
                    stored_b
                );
            }
            _ => return Err("unknown actual Shamir test case".into()),
        }
        Ok(())
    }

    #[test]
    fn real_raft_owned_shamir_completed_publication_retains_only_for_next_independent_sync()
    -> TestResult {
        actual_shamir_completion_case("known_completed")
    }

    #[test]
    fn real_raft_owned_shamir_completed_publication_rejects_changed_binding_and_local_damage()
    -> TestResult {
        actual_shamir_completion_case("binding_and_damage")
    }

    #[test]
    fn real_raft_owned_shamir_completed_publication_cannot_bypass_lost_quorum_or_original_deadline()
    -> TestResult {
        actual_shamir_completion_case("quorum_and_deadline")
    }

    #[test]
    fn real_raft_shamir_terminal_gate_after_completed_index_keeps_current_prefix_temporary()
    -> TestResult {
        actual_shamir_completion_case("terminal_gate")
    }

    #[test]
    fn real_raft_complete_record_c_is_covered_by_current_d_without_republishing_b() -> TestResult {
        actual_shamir_completion_case("record_covered")
    }

    #[test]
    fn real_raft_record_c_coverage_cannot_bypass_quorum_or_original_deadline() -> TestResult {
        actual_shamir_completion_case("record_quorum")
    }

    #[test]
    fn real_raft_record_c_coverage_rejects_changed_complete_owner_graph() -> TestResult {
        actual_shamir_completion_case("record_damage")
    }

    #[test]
    fn received_deadline_cannot_be_extended_by_a_later_scope() {
        let expired = Instant::now() - Duration::from_millis(1);
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        assert!(live(Some(expired)).is_err());
        assert!(live(Some(Instant::now() + Duration::from_secs(1))).is_ok());
        let _narrow = crate::request_deadline::RequestDeadlineScope::enter(expired);
        assert!(live(Some(Instant::now() + Duration::from_secs(15))).is_err());
    }
    fn actual_unpublished_shamir_case(case: &str) -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        crate::service::tests::bootstrap_unmounted(&mut service)?;
        let cluster = crate::ha::snapshot_test_support::Cluster::new(
            &root.path.join("raft"),
            &service.state.as_ref().ok_or("A")?.cluster_id,
        )?;
        service.ha = Some(Arc::clone(&cluster.processes[0]));
        service.sync_from_ha().map_err(|_| "actual A anchor")?;
        service.ha = Some(Arc::clone(&cluster.processes[1]));
        let _admitted = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let a = service.state.clone().ok_or("A")?;
        let a_identity = service.current_state_identity().map_err(|_| "A identity")?;
        let mut b = a.clone();
        b.engines.handle(
            "",
            "POST",
            "sys/mounts/unpublished-b",
            &json!({"type":"kv"}),
            100,
        )?;
        b.engines = b
            .engines
            .migrate_kv1_records(crate::state_records::AddressKey::from_bytes([41; 32]))?
            .into();
        let b_plan = service.prepare_record_plan(&mut b).map_err(|_| "B plan")?;
        cluster.processes[0]
            .lock()
            .map_err(|_| "HA")?
            .commit_record_state("unpublished-B", &a_identity, &b_plan.bytes, &b_plan.objects)?;
        let committed_b = {
            let process = cluster.processes[1].lock().map_err(|_| "HA")?;
            process.record_application_witness()?.ok_or("actual B")?.0
        };
        let received = service
            .receive_ha_records(&cluster.processes[1], &committed_b)
            .map_err(|_| "actual B receipt")?;
        assert!(received.owner.shamir_owner.is_some());
        let generation_a = service.durable.as_ref().ok_or("durable")?.generation();
        let stored_a = service
            .durable
            .as_ref()
            .ok_or("durable")?
            .get("system", "state")?;
        let mut c = b.clone();
        c.engines.handle(
            "",
            "POST",
            "sys/mounts/unpublished-c",
            &json!({"type":"kv"}),
            100,
        )?;
        let c_plan = service.prepare_record_plan(&mut c).map_err(|_| "C plan")?;
        cluster.processes[0]
            .lock()
            .map_err(|_| "HA")?
            .commit_record_state(
                "unpublished-C",
                &b_plan.identity,
                &c_plan.bytes,
                &c_plan.objects,
            )?;
        match case {
            "forward" | "forward_expired" | "forward_quorum" => {
                let publication = service
                    .install_committed_ha_records(received)
                    .map_err(|_| "actual unpublished B withholding")?;
                assert_eq!(
                    publication,
                    HaRecordPublicationProgress::UnpublishedSuperseded
                );
                assert_eq!(
                    service.current_state_identity().map_err(|_| "same A")?,
                    a_identity
                );
                assert_eq!(
                    service.durable.as_ref().ok_or("durable")?.generation(),
                    generation_a
                );
                let progress = HaSyncProgress::from_record_publication(publication);
                let deadline = crate::request_deadline::current().ok_or("original deadline")?;
                if case == "forward" {
                    service
                        .continue_forward_local_sync(progress, deadline)
                        .map_err(|_| "same deadline local C catch-up")?;
                    assert_eq!(
                        service.current_state_identity().map_err(|_| "C")?,
                        c_plan.identity
                    );
                    let (loaded, _, _) = Service::load_state_from_durable(
                        service.durable.as_ref().ok_or("durable")?,
                    )
                    .map_err(|_| "actual encrypted C")?;
                    assert_eq!(
                        owner_store::serialize_owner(&loaded)?.as_slice(),
                        owner_store::serialize_owner(&c)?.as_slice()
                    );
                } else {
                    let _bounded = if case == "forward_expired" {
                        crate::request_deadline::RequestDeadlineScope::enter(
                            Instant::now() - Duration::from_millis(1),
                        )
                    } else {
                        cluster.isolate_all_peers(true);
                        crate::request_deadline::RequestDeadlineScope::enter(
                            Instant::now() + Duration::from_millis(250),
                        )
                    };
                    assert!(
                        service
                            .continue_forward_local_sync(
                                progress,
                                crate::request_deadline::current().ok_or("same bound")?
                            )
                            .is_err()
                    );
                    assert_eq!(
                        service.current_state_identity().map_err(|_| "same A")?,
                        a_identity
                    );
                    assert_eq!(
                        service.durable.as_ref().ok_or("durable")?.generation(),
                        generation_a
                    );
                    assert_eq!(
                        service
                            .durable
                            .as_ref()
                            .ok_or("durable")?
                            .get("system", "state")?,
                        stored_a
                    );
                }
            }
            "positive" => {
                assert_eq!(
                    service
                        .install_committed_ha_records(received)
                        .map_err(|_| "actual unpublished B withholding")?,
                    HaRecordPublicationProgress::UnpublishedSuperseded,
                );
                assert!(!service.recovery_required);
                assert!(service.ha_activation.is_none());
                assert!(service.ha_read_cache.is_none());
                assert_eq!(
                    service.current_state_identity().map_err(|_| "same A")?,
                    a_identity
                );
                assert_eq!(
                    service.durable.as_ref().ok_or("durable")?.generation(),
                    generation_a
                );
                assert_eq!(
                    service
                        .durable
                        .as_ref()
                        .ok_or("durable")?
                        .get("system", "state")?,
                    stored_a
                );
                // Only a fresh independent ordinary sync may install C.
                service
                    .sync_from_ha()
                    .map_err(|_| "next independent C sync")?;
                assert_eq!(
                    service.current_state_identity().map_err(|_| "C")?,
                    c_plan.identity
                );
                let (loaded, _, _) =
                    Service::load_state_from_durable(service.durable.as_ref().ok_or("durable")?)
                        .map_err(|_| "actual encrypted C")?;
                assert_eq!(
                    owner_store::serialize_owner(&loaded)?.as_slice(),
                    owner_store::serialize_owner(&c)?.as_slice()
                );
            }
            "binding" => {
                service.unseal_nonce.push('x');
                assert!(
                    received
                        .owner
                        .before_record_publication(&mut service)
                        .is_err()
                );
                service.unseal_nonce.pop();
                service.barrier_key.as_mut().ok_or("barrier")?[0] ^= 1;
                assert!(
                    received
                        .owner
                        .before_record_publication(&mut service)
                        .is_err()
                );
                service.barrier_key.as_mut().ok_or("barrier")?[0] ^= 1;
                service.ha = Some(Arc::clone(&cluster.processes[2]));
                assert!(
                    received
                        .owner
                        .before_record_publication(&mut service)
                        .is_err()
                );
                service.ha = Some(Arc::clone(&cluster.processes[1]));
                // Destroy the private original B witness: a digest difference
                // cannot mint an unpublished-superseded proof.
                let mut missing = received;
                let original_witness = missing.owner.source_witness.take();
                assert!(original_witness.is_some());
                assert!(
                    missing
                        .owner
                        .before_record_publication(&mut service)
                        .is_err()
                );
                assert_eq!(
                    service.durable.as_ref().ok_or("durable")?.generation(),
                    generation_a
                );
                assert_eq!(
                    service
                        .durable
                        .as_ref()
                        .ok_or("durable")?
                        .get("system", "state")?,
                    stored_a
                );
                // Restore the same affine B witness and independently prove
                // valid A before damaging its actual durable publication.
                missing.owner.source_witness = original_witness;
                assert!(
                    !missing
                        .owner
                        .before_record_publication(&mut service)
                        .map_err(|_| "restored original witness with valid A")?
                );
                service
                    .durable
                    .as_mut()
                    .ok_or("durable")?
                    .put(PutRequest::new(
                        "unpublished-negative",
                        "system",
                        "damaged-A",
                        "state",
                        crypto::digest(b"damaged-A"),
                        Secret::new(b"damaged-A".to_vec())?,
                    )?)?;
                assert!(
                    missing
                        .owner
                        .before_record_publication(&mut service)
                        .is_err()
                );
            }
            "quorum" => {
                cluster.isolate_all_peers(true);
                {
                    let _bounded = crate::request_deadline::RequestDeadlineScope::enter(
                        Instant::now() + Duration::from_millis(250),
                    );
                    assert!(
                        received
                            .owner
                            .before_record_publication(&mut service)
                            .is_err()
                    );
                }
                cluster.isolate_all_peers(false);
                {
                    let _expired = crate::request_deadline::RequestDeadlineScope::enter(
                        Instant::now() - Duration::from_millis(1),
                    );
                    assert!(
                        received
                            .owner
                            .before_record_publication(&mut service)
                            .is_err()
                    );
                }
                assert_eq!(
                    service.durable.as_ref().ok_or("durable")?.generation(),
                    generation_a
                );
                assert_eq!(
                    service
                        .durable
                        .as_ref()
                        .ok_or("durable")?
                        .get("system", "state")?,
                    stored_a
                );
            }
            _ => return Err("unknown unpublished test case".into()),
        }
        Ok(())
    }

    #[test]
    fn completed_forward_local_catchup_installs_real_newer_c_without_replaying_effect() -> TestResult
    {
        actual_unpublished_shamir_case("forward")
    }
    #[test]
    fn completed_forward_local_catchup_keeps_original_expired_deadline() -> TestResult {
        actual_unpublished_shamir_case("forward_expired")
    }
    #[test]
    fn completed_forward_local_catchup_rejects_real_lost_quorum_without_publication() -> TestResult
    {
        actual_unpublished_shamir_case("forward_quorum")
    }

    #[test]
    fn real_raft_unpublished_b_preserves_complete_a_and_next_independent_sync_installs_c()
    -> TestResult {
        actual_unpublished_shamir_case("positive")
    }
    #[test]
    fn real_raft_unpublished_b_rejects_original_binding_witness_loss_and_local_damage() -> TestResult
    {
        actual_unpublished_shamir_case("binding")
    }
    #[test]
    fn real_raft_unpublished_b_cannot_bypass_quorum_or_original_deadline() -> TestResult {
        actual_unpublished_shamir_case("quorum")
    }
}
