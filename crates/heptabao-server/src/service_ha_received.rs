//! Admission of an already committed HA owner is distinct from a local writer.
//! Tokens own the authenticated target; callers cannot substitute a state or
//! opt out of the local writer's Recovery commit-intent requirement.
use super::*;
use crate::ha::{CommittedApplicationState, CommittedRecordState, CommittedStateRead};
use crate::state_record_root::StateIdentity;
use heptabao_raft_runtime::ApplicationReadWitness;
use std::time::Instant;

pub(super) struct ReceivedHaState {
    state: State,
    identity: StateIdentity,
    previous: StateIdentity,
    generation: u64,
    seal: Option<SealMetadata>,
    deadline: Option<Instant>,
    publication: ReceivedPublication,
    source_witness: Option<ApplicationReadWitness>,
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
            || owner_store::serialize_owner(&receipt.state)
                .map_err(state_serialization_error)?
                .as_slice()
                != self.logical.as_slice()
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

// This proof never installs or writes the newer target. The next owned pass
// obtains its own current receipt and admits the complete newer publication.
struct SupersedingHaTarget;

impl CompletedLocalPublication<'_> {
    pub(super) fn identity(&self) -> StateIdentity {
        self.receipt.identity
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.receipt.deadline
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
        live(self.receipt.deadline)?;
        let ha = service.ha.as_ref().ok_or_else(rejected)?;
        let committed = ha
            .lock_for_request()
            .map_err(|_| rejected())?
            .latest_committed_state_if_changed(None)
            .map_err(|_| rejected())?;
        let (state, identity) = match committed {
            CommittedStateRead::Materialized(committed) => {
                if crypto::digest(&committed.bytes) != committed.digest {
                    return Err(rejected());
                }
                let state: State =
                    serde_json::from_slice(&committed.bytes).map_err(|_| rejected())?;
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
                    let binding =
                        Service::prepare_initial_owner_plan(&state, &canonical, operation)
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
                let (state, plan) = Service::materialize_committed_ha_records(ha, &committed)?;
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
        if identity == self.receipt.identity {
            return Err(rejected());
        }
        validate_received_transition(&state, &self.receipt.state)?;
        let process = ha.lock_for_request().map_err(|_| rejected())?;
        if state.cluster_id != process.cluster_id() {
            return Err(rejected());
        }
        let (current, witness) = process
            .application_identity_witness()
            .map_err(|_| rejected())?;
        let previous = self.receipt.source_witness.as_ref().ok_or_else(rejected)?;
        if current != identity || !witness.supersedes(previous) {
            return Err(rejected());
        }
        live(self.receipt.deadline)?;
        Ok(SupersedingHaTarget)
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
                != owner_store::serialize_owner(&receipt.state)
                    .map_err(state_serialization_error)?
                    .as_slice()
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
        let token = Self {
            state,
            identity,
            previous: service.current_state_identity()?,
            generation: durable.generation(),
            seal: service.seal.clone(),
            deadline,
            publication,
            source_witness: Some(witness),
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

    fn verify_local_publication(&self, service: &Service) -> Result<(), Response> {
        let durable = service.durable.as_ref().ok_or_else(rejected)?;
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
                let logical =
                    owner_store::serialize_owner(&self.state).map_err(state_serialization_error)?;
                match owner_store::decode_manifest(published.expose()).map_err(|_| rejected())? {
                    Some(manifest) => {
                        manifest.verify_logical(&logical).map_err(|_| rejected())?;
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
                            != logical.as_slice()
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
        Ok(())
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

    pub(super) fn reconcile_existing_ha_publication(
        &mut self,
        local: &ExistingLocalPublication,
        receipt: &ReceivedHaState,
    ) -> Result<(), Response> {
        let result = (|| {
            let completed = local.after_received(receipt, self)?;
            let progress = completed.progress(self)?;
            if progress == HaLocalPublicationProgress::Superseded {
                return Ok(progress);
            }
            self.reconcile_completed_ha_recovery_index(&completed)
        })();
        match result {
            Ok(HaLocalPublicationProgress::Current) => Ok(()),
            Ok(HaLocalPublicationProgress::Superseded) => Err(Response::error(
                503,
                "HA existing publication is catching up to a newer committed target",
            )),
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
    ) -> Result<HaLocalPublicationProgress, Response> {
        received.owner.before_publication(self)?;
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
        if completed.progress(self)? == HaLocalPublicationProgress::Superseded {
            return Ok(HaLocalPublicationProgress::Superseded);
        }
        if self.reconcile_completed_ha_recovery_index(&completed)?
            == HaLocalPublicationProgress::Superseded
        {
            return Ok(HaLocalPublicationProgress::Superseded);
        }
        self.install_epoch_activation(activation);
        self.record_writes_since_gc = 64;
        live(received.owner.deadline)?;
        if self.current_state_identity()? != received.owner.identity {
            return Err(rejected());
        }
        self.verify_ha_state_identity(received.owner.identity)?;
        live(received.owner.deadline)?;
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
            identity: service.current_state_identity().map_err(|_| "identity")?,
            previous: service.current_state_identity().map_err(|_| "identity")?,
            generation: durable.generation(),
            seal: service.seal.clone(),
            deadline: None,
            source_witness: None,
            publication: ReceivedPublication::Materialized {
                owner_manifest_digest: Some(manifest.canonical_digest()?),
            },
        };
        assert!(service.ha_read_cache.is_none());
        assert!(receipt.verify_local_publication(&service).is_ok());
        receipt.publication = ReceivedPublication::Materialized {
            owner_manifest_digest: Some([0; 32]),
        };
        assert!(receipt.verify_local_publication(&service).is_err());
        receipt.publication = ReceivedPublication::Materialized {
            owner_manifest_digest: None,
        };
        assert!(receipt.verify_local_publication(&service).is_ok());
        receipt.state.cluster_id = "different-target".into();
        assert!(receipt.verify_local_publication(&service).is_err());
        receipt.state = state.clone();
        receipt.state.schema -= 1;
        assert!(receipt.verify_local_publication(&service).is_err());
        receipt.state = state.clone();
        receipt.state.replay_epoch += 1;
        assert!(receipt.verify_local_publication(&service).is_err());
        // Staging a Records root really changes the durable publication. A
        // previous materialized receipt cannot pass merely on a cached cursor.
        let mut record_state = state.clone();
        record_state.engines = record_state
            .engines
            .migrate_kv1_records(crate::state_records::AddressKey::from_bytes([29; 32]))?
            .into();
        let plan = service
            .prepare_record_plan(&record_state)
            .map_err(|_| "plan")?;
        let root_bytes = plan.bytes.clone();
        let identity = plan.identity;
        service
            .persist_record_plan_local(&plan, "received-readback-test", true)
            .map_err(|_| "publish received record plan")?;
        receipt.state = state.clone();
        assert!(receipt.verify_local_publication(&service).is_err());
        receipt.state = record_state;
        receipt.identity = identity;
        receipt.publication = ReceivedPublication::Records {
            root_bytes: root_bytes.clone(),
        };
        assert!(receipt.verify_local_publication(&service).is_ok());
        receipt.identity = StateIdentity::RecordsV5([0; 32]);
        assert!(receipt.verify_local_publication(&service).is_err());
        receipt.identity = identity;
        receipt.publication = ReceivedPublication::Records {
            root_bytes: Zeroizing::new(vec![0]),
        };
        assert!(receipt.verify_local_publication(&service).is_err());
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
            identity: StateIdentity::Legacy(crypto::digest(&a_bytes)),
            previous: service.current_state_identity().map_err(|_| "identity")?,
            generation: service.durable.as_ref().ok_or("durable")?.generation(),
            seal: service.seal.clone(),
            deadline: None,
            source_witness: None,
            publication: ReceivedPublication::Materialized {
                owner_manifest_digest: Some(binding.owner_manifest_digest()),
            },
        };
        assert!(matches!(
            write(&mut service, &a, &fixed)?,
            MutationOutcome::Duplicate { .. }
        ));
        assert!(receipt.verify_local_publication(&service).is_err());
        let first = receipt.operation_id().map_err(|_| "fresh event")?;
        let second = receipt.operation_id().map_err(|_| "another event")?;
        assert_ne!(first, second);
        assert!(matches!(
            write(&mut service, &a, &first)?,
            MutationOutcome::Committed { .. }
        ));
        assert!(receipt.verify_local_publication(&service).is_ok());
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
}
