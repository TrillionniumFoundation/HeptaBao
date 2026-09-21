//! Record publication is a separate authority boundary: immutable object batches
//! may be durable without becoming application state. Only the final root put
//! makes a candidate visible. All readers pin a fully authenticated graph.
use super::*;
use crate::state_record_root::{
    self, OWNER_CHUNK_BYTES, OWNER_NAMES, OpaqueOwnerRef, RecordStateRoot, StateIdentity,
};
use crate::state_records::{
    Kv1Index, ObjectId, ObjectRef, RecordError, RecordReader, StagedObject,
};
use std::collections::BTreeSet;

pub(super) struct RecordPlan {
    pub root: RecordStateRoot,
    pub bytes: Zeroizing<Vec<u8>>,
    pub identity: StateIdentity,
    pub objects: Vec<Arc<StagedObject>>,
}

/// Keep the first occurrence in child-first order, but reject an ID that hides
/// conflicting authenticated metadata or bytes. A pending batch is not yet in
/// durable.get, so admission and execution must consume the same unique set.
fn unique_object_positions<'a>(
    objects: impl IntoIterator<Item = (&'a ObjectRef, &'a [u8])>,
) -> Result<Vec<usize>, ServiceError> {
    let mut seen = BTreeMap::<ObjectId, (&ObjectRef, &[u8])>::new();
    let mut positions = Vec::new();
    for (position, (reference, bytes)) in objects.into_iter().enumerate() {
        if let Some((prior_reference, prior_bytes)) = seen.get(&reference.id) {
            if *prior_reference != reference || *prior_bytes != bytes {
                return Err(ServiceError::CorruptState);
            }
        } else {
            seen.insert(reference.id, (reference, bytes));
            positions.push(position);
        }
    }
    Ok(positions)
}

fn unique_record_objects(
    objects: &[Arc<StagedObject>],
) -> Result<Vec<Arc<StagedObject>>, ServiceError> {
    unique_object_positions(
        objects
            .iter()
            .map(|object| (object.reference(), object.bytes())),
    )
    .map(|positions| {
        positions
            .into_iter()
            .map(|i| Arc::clone(&objects[i]))
            .collect()
    })
}

fn unavailable() -> Response {
    Response::error(503, "record state failed authenticated validation")
}
fn engine_error(error: crate::engines::EngineError) -> Response {
    Response::error(error.status, &error.message)
}
fn root_error(error: state_record_root::RootError) -> Response {
    match error {
        state_record_root::RootError::TooLarge => {
            Response::error(507, "record owner capacity exhausted")
        }
        _ => unavailable(),
    }
}

pub(super) fn decode_root(bytes: &[u8]) -> Result<Option<RecordStateRoot>, Response> {
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        storage_format: Option<String>,
    }
    let probe: Probe = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
    if probe.storage_format.as_deref() != Some(state_record_root::STORAGE_FORMAT) {
        return Ok(None);
    }
    RecordStateRoot::decode(bytes).map(Some).map_err(root_error)
}

pub(super) fn existing_plan(root: RecordStateRoot) -> Result<RecordPlan, Response> {
    let bytes = root.encode().map_err(root_error)?;
    let identity = root.identity().map_err(root_error)?;
    Ok(RecordPlan {
        root,
        bytes,
        identity,
        objects: Vec::new(),
    })
}

/// One-time migration compares the old canonical identity without allocating
/// another whole State image. A legal first record write may cross the old
/// 16MiB serialized-state bound; the eventual owner/graph/durable preflights,
/// rather than this discarded legacy representation, decide admission.
pub(super) fn legacy_candidate_digest(state: &State) -> Result<[u8; 32], Response> {
    struct HashWriter {
        context: ring::digest::Context,
        count: usize,
        overflow: bool,
    }
    impl std::io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let limit = MAX_STATE_BYTES
                + crate::state_records::MAX_VALUE_BYTES
                + crate::state_record_root::MAX_ROOT_BYTES;
            let Some(next) = self
                .count
                .checked_add(bytes.len())
                .filter(|next| *next <= limit)
            else {
                self.overflow = true;
                return Err(std::io::Error::other("migration candidate capacity"));
            };
            self.context.update(bytes);
            self.count = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter {
        context: ring::digest::Context::new(&ring::digest::SHA256),
        count: 0,
        overflow: false,
    };
    if serde_json::to_writer(&mut writer, state).is_err() {
        return Err(Response::error(
            if writer.overflow { 507 } else { 500 },
            "migration candidate serialization rejected",
        ));
    }
    writer
        .context
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| unavailable())
}

pub(super) struct DurableReader<'a>(pub &'a DurableService<AeadBarrier>);
impl RecordReader for DurableReader<'_> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let record = self
            .0
            .get("system", &reference.resource())
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        Ok(Zeroizing::new(record.expose().to_vec()))
    }
}

fn owner_bytes(
    root: &RecordStateRoot,
    owner: &OpaqueOwnerRef,
    reader: &impl RecordReader,
) -> Result<Zeroizing<Vec<u8>>, Response> {
    let key = root.address_key();
    let length = usize::try_from(owner.total_bytes).map_err(|_| unavailable())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    for reference in &owner.chunks {
        let encoded = reader.read_object(reference).map_err(|_| unavailable())?;
        let payload = reference
            .owner_chunk_payload(&key, &encoded)
            .map_err(|_| unavailable())?;
        if bytes
            .len()
            .checked_add(payload.len())
            .is_none_or(|size| size > length)
        {
            return Err(unavailable());
        }
        bytes.extend_from_slice(payload);
    }
    if bytes.len() != length
        || root.owner_digest(&owner.name, &bytes).map_err(root_error)? != owner.digest
    {
        return Err(unavailable());
    }
    Ok(bytes)
}

impl Service {
    pub(super) fn current_state_identity(&self) -> Result<StateIdentity, Response> {
        let digest = self.current_state_digest()?;
        match &self.record_root {
            Some(root) => {
                let identity = root.identity().map_err(root_error)?;
                if identity.digest() != digest {
                    return Err(unavailable());
                }
                Ok(identity)
            }
            None => Ok(StateIdentity::Legacy(digest)),
        }
    }

    pub(super) fn materialize_record_state(
        root: &RecordStateRoot,
        reader: &impl RecordReader,
    ) -> Result<State, Response> {
        root.validate().map_err(root_error)?;
        let owners = root
            .owners
            .iter()
            .map(|owner| owner_bytes(root, owner, reader))
            .collect::<Result<Vec<_>, _>>()?;
        let mut state = State {
            schema: root.state_schema,
            cluster_id: root.cluster_id.clone(),
            replay_epoch: root.replay_epoch,
            namespaces: serde_json::from_slice(&owners[0]).map_err(|_| unavailable())?,
            auth: serde_json::from_slice(&owners[1]).map_err(|_| unavailable())?,
            engines: serde_json::from_slice(&owners[2]).map_err(|_| unavailable())?,
            database: serde_json::from_slice(&owners[3]).map_err(|_| unavailable())?,
            raft_admin: serde_json::from_slice(&owners[4]).map_err(|_| unavailable())?,
        };
        for (index, expected) in owners.iter().enumerate() {
            let canonical = match index {
                0 => owner_store::serialize_owner(&state.namespaces),
                1 => owner_store::serialize_owner(&state.auth),
                2 => owner_store::serialize_owner(&state.engines),
                3 => owner_store::serialize_owner(&state.database),
                _ => owner_store::serialize_owner(&state.raft_admin),
            }
            .map_err(state_serialization_error)?;
            if canonical.as_slice() != expected.as_slice() {
                return Err(unavailable());
            }
        }
        let key = root.address_key();
        let index = Kv1Index::open(Arc::clone(&key), root.kv1.clone(), reader)
            .map_err(|_| unavailable())?;
        state
            .engines
            .install_record_index(key, index)
            .map_err(engine_error)?;
        state.validate_format()?;
        Ok(state)
    }

    pub(super) fn prepare_record_plan(&self, state: &State) -> Result<RecordPlan, Response> {
        let key = state.engines.record_address_key().ok_or_else(unavailable)?;
        let kv1 = state.engines.record_root().ok_or_else(unavailable)?;
        let reuse = OwnerReuseHint::between(self.state.as_ref(), state);
        let reuse = [
            reuse.namespaces,
            reuse.auth,
            reuse.engines,
            reuse.database,
            reuse.raft_admin,
        ];
        let mut objects = state.engines.record_objects().map_err(engine_error)?;
        let mut owners = Vec::with_capacity(5);
        for (index, name) in OWNER_NAMES.into_iter().enumerate() {
            if reuse[index]
                && let Some(previous) = &self.record_root
            {
                if previous.address_key().expose() != key.expose() {
                    return Err(unavailable());
                }
                owners.push(previous.owners[index].clone());
                continue;
            }
            let bytes = match index {
                0 => owner_store::serialize_owner(&state.namespaces),
                1 => owner_store::serialize_owner(&state.auth),
                2 => owner_store::serialize_owner(&state.engines),
                3 => owner_store::serialize_owner(&state.database),
                _ => owner_store::serialize_owner(&state.raft_admin),
            }
            .map_err(state_serialization_error)?;
            let mut chunks = Vec::new();
            for bytes in bytes.chunks(OWNER_CHUNK_BYTES) {
                let object = StagedObject::owner_chunk(&key, bytes).map_err(|_| unavailable())?;
                chunks.push(object.reference().clone());
                objects.push(object);
            }
            owners.push(OpaqueOwnerRef {
                name: name.to_owned(),
                total_bytes: bytes.len() as u64,
                chunks,
                digest: state_record_root::digest_owner(&key, name, &bytes).map_err(root_error)?,
            });
        }
        let owners = owners.try_into().map_err(|_| unavailable())?;
        let root = RecordStateRoot::new(
            state.schema,
            state.cluster_id.clone(),
            state.replay_epoch,
            owners,
            kv1,
            *key.expose(),
        )
        .map_err(root_error)?;
        let bytes = root.encode().map_err(root_error)?;
        let identity = root.identity().map_err(root_error)?;
        // Multiple edits can leave intermediate roots in the finite candidate
        // delta. Prune that delta only, never traverse the shared old graph.
        let mut staged = BTreeMap::<ObjectId, Arc<StagedObject>>::new();
        for object in objects {
            if let Some(prior) = staged.insert(object.reference().id, Arc::clone(&object))
                && (prior.reference() != object.reference() || prior.bytes() != object.bytes())
            {
                return Err(unavailable());
            }
        }
        fn visit(
            reference: &ObjectRef,
            staged: &BTreeMap<ObjectId, Arc<StagedObject>>,
            seen: &mut BTreeSet<ObjectId>,
            out: &mut Vec<Arc<StagedObject>>,
        ) -> Result<(), Response> {
            if !seen.insert(reference.id) {
                return Ok(());
            }
            if let Some(object) = staged.get(&reference.id) {
                if object.reference() != reference {
                    return Err(unavailable());
                }
                for child in object.children() {
                    visit(child, staged, seen, out)?;
                }
                out.push(Arc::clone(object));
            }
            Ok(())
        }
        let mut objects = Vec::new();
        let mut seen = BTreeSet::new();
        for reference in root.references() {
            visit(reference, &staged, &mut seen, &mut objects)?;
        }
        Ok(RecordPlan {
            root,
            bytes,
            identity,
            objects,
        })
    }

    /// Only the authenticated, explicitly permitted Absent→anchor path uses
    /// this full closure. Normal commits never re-emit the committed graph.
    pub(super) fn full_existing_record_plan(&self, state: &State) -> Result<RecordPlan, Response> {
        let root = self.record_root.clone().ok_or_else(unavailable)?;
        if state.engines.record_root().as_ref() != Some(&root.kv1)
            || root.identity().map_err(root_error)? != self.current_state_identity()?
        {
            return Err(unavailable());
        }
        let durable = self.durable.as_ref().ok_or_else(unavailable)?;
        let stored = durable
            .get("system", "state")
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if stored.expose() != root.encode().map_err(root_error)?.as_slice() {
            return Err(unavailable());
        }
        let mut plan = existing_plan(root)?;
        state
            .engines
            .visit_record_objects(|object| {
                plan.objects.push(Arc::clone(object));
                Ok(())
            })
            .map_err(engine_error)?;
        let mut seen = plan
            .objects
            .iter()
            .map(|object| object.reference().id)
            .collect::<BTreeSet<_>>();
        let key = plan.root.address_key();
        let reader = DurableReader(durable);
        for owner in &plan.root.owners {
            for reference in &owner.chunks {
                if !seen.insert(reference.id) {
                    continue;
                }
                let bytes = reader.read_object(reference).map_err(|_| unavailable())?;
                let payload = reference
                    .owner_chunk_payload(&key, &bytes)
                    .map_err(|_| unavailable())?;
                let object = StagedObject::owner_chunk(&key, payload).map_err(|_| unavailable())?;
                if object.reference() != reference {
                    return Err(unavailable());
                }
                plan.objects.push(object);
            }
        }
        Ok(plan)
    }

    pub(super) fn commit_record_plan(
        &mut self,
        state: &State,
        plan: RecordPlan,
    ) -> Result<(), Response> {
        self.commit_record_plan_checked(
            state,
            plan,
            None::<fn(&AuthState) -> Result<(), Response>>,
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        )
    }

    pub(super) fn commit_record_plan_with_before_publish(
        &mut self,
        state: &State,
        plan: RecordPlan,
        before_publish: impl FnOnce(&AuthState) -> Result<(), Response>,
        #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
        restore_fault: Option<crate::fixture_native_restore::NativeRestoreFaultContext>,
    ) -> Result<(), Response> {
        self.commit_record_plan_checked(
            state,
            plan,
            Some(before_publish),
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            restore_fault,
        )
    }

    fn commit_record_plan_checked(
        &mut self,
        state: &State,
        plan: RecordPlan,
        before_publish: Option<impl FnOnce(&AuthState) -> Result<(), Response>>,
        #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
        mut restore_fault: Option<crate::fixture_native_restore::NativeRestoreFaultContext>,
    ) -> Result<(), Response> {
        state.validate_format()?;
        if state.schema != plan.root.state_schema
            || state.cluster_id != plan.root.cluster_id
            || state.replay_epoch != plan.root.replay_epoch
            || state.engines.record_root().as_ref() != Some(&plan.root.kv1)
            || state
                .engines
                .record_address_key()
                .is_none_or(|key| key.expose() != plan.root.address_key().expose())
        {
            return Err(unavailable());
        }
        #[cfg(test)]
        if self.state_capacity != MAX_STATE_BYTES {
            let payload = plan
                .root
                .owners
                .iter()
                .map(|owner| owner.total_bytes)
                .sum::<u64>()
                .saturating_add(
                    plan.root
                        .kv1
                        .reference
                        .as_ref()
                        .map_or(0, |reference| reference.payload_bytes),
                );
            if payload > self.state_capacity as u64 {
                return Err(Response::error(507, "state capacity exhausted"));
            }
        }
        let activation = self.prepare_epoch_activation(state.replay_epoch, false)?;
        let base = self.current_state_identity()?;
        let operation = format!(
            "record-{}",
            hex(&crypto::random::<16>().map_err(|e| Response::error(503, e))?)
        );
        // GC never observes the uncommitted candidate. All current readers own
        // an Arc graph and do not depend on disk objects after admission.
        // Replay retirement must remain possible even with a full old ledger;
        // do not consume a maintenance identity before that transition.
        if self
            .record_root
            .as_ref()
            .is_none_or(|root| root.replay_epoch == plan.root.replay_epoch)
        {
            self.maybe_collect_record_objects()?;
        }
        let durable = self.durable.as_ref().ok_or_else(unavailable)?;
        let objects = plan
            .objects
            .iter()
            .map(|object| (object.reference().resource(), object.bytes()))
            .collect::<Vec<_>>();
        durable
            .preflight_immutable_publication(heptabao_durable_service::ImmutablePublication {
                replay_epoch: plan.root.replay_epoch,
                principal: "heptabao-server",
                namespace: "system",
                operation_id: &operation,
                authorization_digest: plan.identity.digest(),
                objects: &objects,
                root_resource: "state",
                root_bytes: &plan.bytes,
            })
            .map_err(|error| self.record_storage_error(error))?;
        if let Some(ha) = &self.ha {
            let process = ha.lock_for_request().map_err(|_| unavailable())?;
            if activation.is_some() {
                process
                    .preflight_record_replacement(&operation, &base, &plan.bytes, &plan.objects)
                    .map_err(|error| match error {
                        crate::ha::RecordPublicationPreflightError::Capacity => {
                            Response::error(507, "HA replacement capacity exhausted before staging")
                        }
                        crate::ha::RecordPublicationPreflightError::Unavailable => unavailable(),
                    })?;
            }
            let live_auth = &self.state.as_ref().ok_or_else(unavailable)?.auth;
            let mut authority_rejection = None;
            let result = if let Some(before_publish) = before_publish {
                process.commit_record_state_with_before_publish(
                    &operation,
                    &base,
                    &plan.bytes,
                    &plan.objects,
                    #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                    restore_fault.as_mut(),
                    || {
                        before_publish(live_auth).map_err(|response| {
                            authority_rejection = Some(response);
                            "record publication authority rejected before Publish".to_owned()
                        })
                    },
                )
            } else {
                process.commit_record_state(&operation, &base, &plan.bytes, &plan.objects)
            };
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            if let Some(error) = restore_fault
                .as_mut()
                .and_then(|context| context.take_prepublication_error())
            {
                return Err(Response::error(503, error));
            }
            if let Some(response) = authority_rejection {
                // Staging/GC may already be replicated, but the guard proves
                // Publish was never submitted. Preserve the old root and the
                // original denial; do not label this a committed outcome.
                return Err(response);
            }
            if result.is_err() {
                // Publication may have committed despite a missing response.
                if activation.is_some() {
                    self.recovery_required = true;
                }
                return Err(Response::error(
                    503,
                    "HA record publication failed; no response released",
                ));
            }
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            if let Some(context) = restore_fault.as_mut() {
                let receipt = result.map_err(|_| unavailable())?;
                let gated = self
                    .durable
                    .as_ref()
                    .ok_or("fixture committed local generation unavailable")
                    .and_then(|durable| context.after_commit(&receipt, durable.generation()));
                if let Err(error) = gated {
                    self.recovery_required = true;
                    self.ha_read_cache = None;
                    return Err(Self::ha_committed_local_failure(Response::error(
                        503, error,
                    )));
                }
            }
        } else if let Some(before_publish) = before_publish {
            before_publish(&self.state.as_ref().ok_or_else(unavailable)?.auth)?;
        }
        let result = self.persist_record_plan_local(&plan, &operation, false);
        if let Err(error) = result {
            if self.ha.is_some() {
                self.recovery_required = true;
                return Err(Self::ha_committed_local_failure(error));
            }
            return Err(error);
        }
        self.record_root = Some(plan.root.clone());
        self.state_digest = Some(plan.identity.digest());
        self.install_epoch_activation(activation);
        // A poisoned bookkeeping lock cannot make the just-published state
        // appear rolled back. Fence and require reload instead.
        if let Err(error) = state.engines.clear_published_record_objects(&plan.root.kv1) {
            self.recovery_required = true;
            return Err(engine_error(error));
        }
        self.record_writes_since_gc = self.record_writes_since_gc.saturating_add(1);
        Ok(())
    }

    pub(super) fn persist_record_plan_local(
        &mut self,
        plan: &RecordPlan,
        operation: &str,
        allow_epoch_catchup: bool,
    ) -> Result<(), Response> {
        let durable = self.durable.as_mut().ok_or_else(unavailable)?;
        let prior_epoch = durable.replay_epoch();
        let target = plan.root.replay_epoch;
        if target < prior_epoch
            || (target > prior_epoch
                && !allow_epoch_catchup
                && prior_epoch.checked_add(1) != Some(target))
        {
            return Err(unavailable());
        }
        let result = Self::persist_record_batch(durable, plan, operation);
        if durable.recovery_required() || (result.is_err() && durable.replay_epoch() != prior_epoch)
        {
            self.recovery_required = true;
        }
        match result {
            Ok(()) => Ok(()),
            Err(ServiceError::OutcomeUnknown { recovery_reference }) => {
                self.recovery_required = true;
                Err(Response {
                    status: 503,
                    body: json!({"errors":["record durable outcome unknown; do not blindly retry"],"recovery_reference":recovery_reference}),
                })
            }
            Err(
                ServiceError::RequestCapacityExhausted | ServiceError::JournalCapacityExhausted,
            ) => Err(Response::error(
                507,
                "record durable capacity exhausted; no response released",
            )),
            Err(_) => Err(unavailable()),
        }
    }

    pub(super) fn persist_record_batch(
        durable: &mut DurableService<AeadBarrier>,
        plan: &RecordPlan,
        operation: &str,
    ) -> Result<(), ServiceError> {
        if plan
            .root
            .encode()
            .map_err(|_| ServiceError::CorruptState)?
            .as_slice()
            != plan.bytes.as_slice()
            || plan
                .root
                .identity()
                .map_err(|_| ServiceError::CorruptState)?
                != plan.identity
        {
            return Err(ServiceError::CorruptState);
        }
        let target = plan.root.replay_epoch;
        if target < durable.replay_epoch() {
            return Err(ServiceError::ReplayEpochMismatch);
        }
        let unique_objects = unique_record_objects(&plan.objects)?;
        let objects = unique_objects
            .iter()
            .map(|object| (object.reference().resource(), object.bytes()))
            .collect::<Vec<_>>();
        durable.preflight_immutable_publication(
            heptabao_durable_service::ImmutablePublication {
                replay_epoch: target,
                principal: "heptabao-server",
                namespace: "system",
                operation_id: operation,
                authorization_digest: plan.identity.digest(),
                objects: &objects,
                root_resource: "state",
                root_bytes: &plan.bytes,
            },
        )?;

        while durable.replay_epoch() < target {
            durable.retire_replay_epoch()?;
        }
        let key = plan.root.address_key();
        let mut mutations = Vec::new();
        let mut batch = 0_usize;
        for object in &unique_objects {
            let reference = object.reference();
            reference
                .verify(&key, object.bytes())
                .map_err(|_| ServiceError::CorruptState)?;
            let resource = reference.resource();
            if let Some(existing) = durable.get("system", &resource)? {
                if existing.expose() != object.bytes() {
                    return Err(ServiceError::CorruptState);
                }
                continue;
            }
            mutations.push((resource, Some(Secret::new(object.bytes().to_vec())?)));
            if mutations.len() == heptabao_durable_service::MAX_ATOMIC_MUTATIONS {
                durable.apply_batch_with_compaction_in_replay_epoch(
                    target,
                    "heptabao-server",
                    "system",
                    format!("{operation}-objects-{batch}"),
                    plan.identity.digest(),
                    std::mem::take(&mut mutations),
                )?;
                batch += 1;
            }
        }
        mutations.push(("state".into(), Some(Secret::new(plan.bytes.to_vec())?)));
        durable.apply_batch_with_compaction_in_replay_epoch(
            target,
            "heptabao-server",
            "system",
            format!("{operation}-root"),
            plan.identity.digest(),
            mutations,
        )?;
        Ok(())
    }

    pub(super) fn sync_record_state_from_ha(
        &mut self,
        ha: &Arc<Mutex<HaProcess>>,
        committed: crate::ha::CommittedRecordState,
    ) -> Result<(), Response> {
        if self.current_state_identity()? == committed.identity {
            return self.cache_verified_ha_records(&committed);
        }
        struct HaReader<'a> {
            ha: &'a HaProcess,
            root: &'a RecordStateRoot,
        }
        impl RecordReader for HaReader<'_> {
            fn read_object(
                &self,
                reference: &ObjectRef,
            ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
                self.ha
                    .read_record_object(self.root, reference)
                    .map_err(|_| RecordError::Corrupt)
            }
        }
        let (state, objects) = {
            let process = ha.lock_for_request().map_err(|_| unavailable())?;
            if committed.root.cluster_id != process.cluster_id() {
                return Err(unavailable());
            }
            let reader = HaReader {
                ha: &process,
                root: &committed.root,
            };
            let state = Self::materialize_record_state(&committed.root, &reader)?;
            let mut objects = Vec::new();
            state
                .engines
                .visit_record_objects(|object| {
                    objects.push(Arc::clone(object));
                    Ok(())
                })
                .map_err(engine_error)?;
            let key = committed.root.address_key();
            for owner in &committed.root.owners {
                for reference in &owner.chunks {
                    let bytes = reader.read_object(reference).map_err(|_| unavailable())?;
                    let payload = reference
                        .owner_chunk_payload(&key, &bytes)
                        .map_err(|_| unavailable())?;
                    let object =
                        StagedObject::owner_chunk(&key, payload).map_err(|_| unavailable())?;
                    if object.reference() != reference {
                        return Err(unavailable());
                    }
                    objects.push(object);
                }
            }
            let objects = unique_record_objects(&objects).map_err(|_| unavailable())?;
            (state, objects)
        };
        let plan = RecordPlan {
            root: committed.root.clone(),
            bytes: committed.root_bytes.clone(),
            identity: committed.identity,
            objects,
        };
        self.install_received_record_state(state, plan)?;
        if let Err(error) = self.cache_verified_ha_records(&committed) {
            self.recovery_required = true;
            return Err(error);
        }
        self.recovery_required = false;
        Ok(())
    }

    // The caller has authenticated the complete committed graph. Keep local
    // publication and activation installation together, including HA catch-up
    // across more than one missed epoch.
    pub(super) fn install_received_record_state(
        &mut self,
        state: State,
        plan: RecordPlan,
    ) -> Result<(), Response> {
        let activation = self.prepare_epoch_activation(state.replay_epoch, true)?;
        let operation = match crypto::random::<16>() {
            Ok(value) => format!("hasync-record-{}", hex(&value)),
            Err(error) => {
                self.recovery_required = true;
                return Err(Response::error(503, error));
            }
        };
        if let Err(error) = self.persist_record_plan_local(&plan, &operation, true) {
            self.recovery_required = true;
            return Err(Self::ha_committed_local_failure(error));
        }
        self.record_root = Some(plan.root);
        self.state_digest = Some(plan.identity.digest());
        self.state = Some(state);
        self.install_epoch_activation(activation);
        self.record_writes_since_gc = 64;
        Ok(())
    }

    fn record_storage_error(&mut self, error: ServiceError) -> Response {
        match error {
            ServiceError::RequestCapacityExhausted | ServiceError::JournalCapacityExhausted => {
                Response::error(
                    507,
                    "record storage capacity exhausted; no response released",
                )
            }
            ServiceError::OutcomeUnknown { recovery_reference } => {
                self.recovery_required = true;
                Response {
                    status: 503,
                    body: json!({"errors":["record durable outcome unknown; reopen and reconcile; do not blindly retry"],
                    "recovery_reference":recovery_reference,"recovery_required":true,"retry_allowed":false}),
                }
            }
            _ => {
                self.recovery_required = true;
                Response::error(
                    503,
                    "record durable validation failed; reopen and reconcile",
                )
            }
        }
    }

    fn maybe_collect_record_objects(&mut self) -> Result<(), Response> {
        let result = self.collect_record_objects_if_due();
        if result.as_ref().is_err_and(|error| error.status == 503) {
            self.recovery_required = true;
        }
        result
    }

    fn collect_record_objects_if_due(&mut self) -> Result<(), Response> {
        let Some(root) = &self.record_root else {
            return Ok(());
        };
        if self.record_writes_since_gc < 64 {
            return Ok(());
        }
        let durable = self.durable.as_ref().ok_or_else(unavailable)?;
        let stored = durable
            .get("system", "state")
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if root.encode().map_err(root_error)?.as_slice() != stored.expose() {
            return Err(unavailable());
        }
        let mut reachable = root
            .references()
            .map(ObjectRef::resource)
            .collect::<BTreeSet<_>>();
        self.state
            .as_ref()
            .ok_or_else(unavailable)?
            .engines
            .visit_record_objects(|object| {
                reachable.insert(object.reference().resource());
                Ok(())
            })
            .map_err(engine_error)?;
        let mut deletes = Vec::new();
        let mut prefixes = vec![
            "state-records/v5".to_owned(),
            "state-owners".to_owned(),
            "state-chunks".to_owned(),
        ];
        while let Some(prefix) = prefixes.pop() {
            for name in durable.list("system", &prefix).map_err(|_| unavailable())? {
                let resource = format!("{prefix}/{name}");
                if resource.ends_with('/') {
                    prefixes.push(resource.trim_end_matches('/').to_owned());
                } else if !reachable.contains(&resource) {
                    deletes.push(resource);
                }
            }
        }
        let identity = root.identity().map_err(root_error)?.digest();
        let operation = format!(
            "record-gc-{}",
            hex(&crypto::random::<16>().map_err(|e| Response::error(503, e))?)
        );
        let durable = self.durable.as_mut().ok_or_else(unavailable)?;
        for (number, chunk) in deletes
            .chunks(heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
            .enumerate()
        {
            if let Err(error) = durable.apply_batch_with_compaction_in_replay_epoch(
                root.replay_epoch,
                "heptabao-server",
                "system",
                format!("{operation}-{number}"),
                identity,
                chunk
                    .iter()
                    .map(|resource| (resource.clone(), None))
                    .collect(),
            ) {
                self.recovery_required |= durable.recovery_required();
                return Err(self.record_storage_error(error));
            }
        }
        self.record_writes_since_gc = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Root, bootstrap, call};
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn mount(service: &mut Service, token: &str) {
        assert_eq!(
            call(
                service,
                "POST",
                "sys/mounts/records",
                token,
                json!({"type":"kv","options":{"version":"1"}})
            )
            .status,
            204
        );
    }
    #[test]
    fn object_dedup_preserves_order_and_rejects_reference_or_byte_conflicts() -> TestResult {
        let key = crate::state_records::AddressKey::from_bytes([71; 32]);
        let first = StagedObject::owner_chunk(&key, b"first")?;
        let second = StagedObject::owner_chunk(&key, b"second")?;
        let input = vec![Arc::clone(&first), Arc::clone(&second), Arc::clone(&first)];
        let unique = unique_record_objects(&input)?;
        assert_eq!(unique.len(), 2);
        assert!(Arc::ptr_eq(&unique[0], &first));
        assert!(Arc::ptr_eq(&unique[1], &second));
        let mut changed_reference = first.reference().clone();
        changed_reference.payload_bytes += 1;
        assert!(matches!(
            unique_object_positions([
                (first.reference(), first.bytes()),
                (&changed_reference, first.bytes()),
            ]),
            Err(ServiceError::CorruptState)
        ));
        let mut changed_bytes = Zeroizing::new(first.bytes().to_vec());
        *changed_bytes.last_mut().ok_or("empty object")? ^= 1;
        assert!(matches!(
            unique_object_positions([
                (first.reference(), first.bytes()),
                (first.reference(), changed_bytes.as_slice()),
            ]),
            Err(ServiceError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn duplicate_unpersisted_objects_publish_once_and_reopen_the_same_graph() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (key, token) = bootstrap(&mut service)?;
        mount(&mut service, &token);
        let mut next = service.state.clone().ok_or("state")?;
        next.engines
            .handle("", "PUT", "records/shared", &json!({"value":"kept"}), 100)?;
        let mut plan = service.prepare_record_plan(&next).map_err(|_| "plan")?;
        assert!(!plan.objects.is_empty());
        assert!(plan.objects.len() < heptabao_durable_service::MAX_ATOMIC_MUTATIONS / 2);
        let duplicates = plan.objects.clone();
        plan.objects.extend(duplicates);
        let durable = service.durable.as_mut().ok_or("durable")?;
        let generation = durable.generation();
        Service::persist_record_batch(durable, &plan, "duplicate-object-sync")?;
        assert_eq!(durable.generation(), generation + 1);
        let restored = Service::materialize_record_state(&plan.root, &DurableReader(durable))
            .map_err(|_| "published graph")?;
        assert_eq!(restored.engines.record_root(), next.engines.record_root());
        drop(service);
        let mut reopened = directory.service()?;
        assert_eq!(
            call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            call(&mut reopened, "GET", "records/shared", &token, json!({})).body["data"]["value"],
            "kept"
        );
        Ok(())
    }

    #[test]
    fn first_dispatch_mutation_publishes_one_atomic_root_and_reopens() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (key, token) = bootstrap(&mut service)?;
        assert!(service.record_root.is_none());
        let before = service.durable.as_ref().ok_or("durable")?.generation();
        assert_eq!(
            call(&mut service, "GET", "sys/mounts", &token, json!({})).status,
            200
        );
        assert!(service.record_root.is_none());
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            before
        );
        mount(&mut service, &token);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            before + 1
        );
        assert!(service.record_root.is_some());
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "records/a",
                &token,
                json!({"payload":"retained"})
            )
            .status,
            204
        );
        let identity = service.current_state_identity().map_err(|_| "identity")?;
        let count = service.durable.as_ref().ok_or("durable")?.generation();
        drop(service);
        let mut service = directory.service()?;
        assert_eq!(
            call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            identity
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            count
        );
        let state = service.state.as_ref().ok_or("state")?;
        assert!(state.engines.record_objects()?.is_empty());
        assert!(
            service
                .prepare_record_plan(state)
                .map_err(|_| "delta")?
                .objects
                .is_empty()
        );
        let anchor = service
            .full_existing_record_plan(state)
            .map_err(|_| "anchor")?;
        assert!(!anchor.objects.is_empty());
        struct AnchorReader(BTreeMap<ObjectId, Arc<StagedObject>>);
        impl RecordReader for AnchorReader {
            fn read_object(
                &self,
                reference: &ObjectRef,
            ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
                self.0
                    .get(&reference.id)
                    .map(|object| Zeroizing::new(object.bytes().to_vec()))
                    .ok_or(RecordError::Missing)
            }
        }
        let reader = AnchorReader(
            anchor
                .objects
                .iter()
                .map(|object| (object.reference().id, Arc::clone(object)))
                .collect(),
        );
        let restored = Service::materialize_record_state(&anchor.root, &reader)
            .map_err(|_| "anchor closure")?;
        assert_eq!(restored.engines.record_root(), state.engines.record_root());
        assert_eq!(
            call(&mut service, "GET", "records/a", &token, json!({})).body["data"]["payload"],
            "retained"
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/internal/capacity",
                &token,
                json!({})
            )
            .body["data"]["state_storage_format"],
            state_record_root::STORAGE_FORMAT
        );
        Ok(())
    }
    #[test]
    fn small_put_reuses_opaque_owners_and_contains_only_new_path_objects() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (_, token) = bootstrap(&mut service)?;
        mount(&mut service, &token);
        // Build a sizeable committed graph through one real publication, then
        // inspect the exact next write-set rather than timing a fake serializer.
        let mut candidate = service.state.clone().ok_or("state")?;
        for index in 0..96 {
            candidate.engines.handle(
                "",
                "PUT",
                &format!("records/key-{index:03}"),
                &json!({"payload":"x".repeat(8192),"key":index}),
                100,
            )?;
        }
        service
            .commit_state(&candidate)
            .map_err(|_| "publish graph")?;
        service.state = Some(candidate);
        let previous = service.record_root.clone().ok_or("root")?;
        let mut next = service.state.clone().ok_or("state")?;
        next.engines.handle(
            "",
            "PUT",
            "records/key-048",
            &json!({"payload":"small replacement"}),
            100,
        )?;
        let plan = service.prepare_record_plan(&next).map_err(|_| "plan")?;
        assert_eq!(plan.root.owners, previous.owners);
        assert!(
            plan.objects.len() <= 8,
            "point update must not stage the old closure"
        );
        assert!(plan.objects.iter().map(|o| o.bytes().len()).sum::<usize>() < 128 * 1024);
        assert_ne!(plan.root.kv1, previous.kv1);
        let before = service.durable.as_ref().ok_or("durable")?.generation();
        service
            .commit_record_plan(&next, plan)
            .map_err(|_| "publish point")?;
        service.state = Some(next);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            before + 1
        );
        assert_eq!(
            call(&mut service, "GET", "records/key-047", &token, json!({})).body["data"]["key"],
            47
        );
        Ok(())
    }
    #[test]
    fn interrupted_many_object_staging_does_not_publish_and_can_resume_with_new_operation()
    -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (_, token) = bootstrap(&mut service)?;
        mount(&mut service, &token);
        let old_root = service.record_root.clone().ok_or("root")?;
        let mut next = service.state.clone().ok_or("state")?;
        for index in 0..120 {
            next.engines.handle(
                "",
                "PUT",
                &format!("records/item-{index:03}"),
                // Keep this fault fixture larger than the inline threshold so
                // it still interrupts a real multi-batch object publication.
                &json!({"unique":index,"payload":"x".repeat(1025)}),
                100,
            )?;
        }
        let plan = service.prepare_record_plan(&next).map_err(|_| "plan")?;
        assert!(plan.objects.len() > heptabao_durable_service::MAX_ATOMIC_MUTATIONS);
        let first = plan
            .objects
            .iter()
            .take(heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
            .map(|o| {
                Ok((
                    o.reference().resource(),
                    Some(Secret::new(o.bytes().to_vec())?),
                ))
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        let durable = service.durable.as_mut().ok_or("durable")?;
        durable.apply_batch_with_compaction_in_replay_epoch(
            old_root.replay_epoch,
            "heptabao-server",
            "system",
            "interrupted-record-objects-0",
            plan.identity.digest(),
            first,
        )?;
        let (loaded, bytes, rewrite) =
            Service::load_state_from_durable(durable).map_err(|_| "old root reload")?;
        assert!(!rewrite);
        assert_eq!(
            bytes.as_slice(),
            old_root.encode().map_err(|_| "encode")?.as_slice()
        );
        assert_eq!(loaded.engines.record_root(), Some(old_root.kv1.clone()));
        assert_eq!(
            call(&mut service, "GET", "records/item-000", &token, json!({})).status,
            404
        );
        service
            .commit_record_plan(&next, plan)
            .map_err(|_| "resume new operation")?;
        service.state = Some(next);
        assert_eq!(
            call(&mut service, "GET", "records/item-119", &token, json!({})).body["data"]["unique"],
            119
        );
        Ok(())
    }
    #[test]
    fn record_root_rejects_old_schema_and_public_zero_address_key() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (_, token) = bootstrap(&mut service)?;
        mount(&mut service, &token);
        let root = service.record_root.as_ref().ok_or("root")?;
        assert!(
            RecordStateRoot::new(
                35,
                root.cluster_id.clone(),
                root.replay_epoch,
                root.owners.clone(),
                root.kv1.clone(),
                *root.address_key().expose()
            )
            .is_err()
        );
        assert!(
            RecordStateRoot::new(
                36,
                root.cluster_id.clone(),
                root.replay_epoch,
                root.owners.clone(),
                root.kv1.clone(),
                [0; 32]
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn oversize_owner_refuses_before_any_record_stage_or_root_publication() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (_, token) = bootstrap(&mut service)?;
        mount(&mut service, &token);
        let identity = service.current_state_identity().map_err(|_| "identity")?;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let response = call(
            &mut service,
            "PUT",
            "secret/data/oversize",
            &token,
            json!({"data":{"payload":"x".repeat(MAX_STATE_BYTES)}}),
        );
        assert_eq!(response.status, 507);
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            identity
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "secret/data/oversize",
                &token,
                json!({})
            )
            .status,
            404
        );
        Ok(())
    }
    #[test]
    fn missing_authenticated_object_never_falls_back_to_legacy_state() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (_, token) = bootstrap(&mut service)?;
        mount(&mut service, &token);
        assert_eq!(
            call(&mut service, "PUT", "records/a", &token, json!({"value":1})).status,
            204
        );
        let root = service.record_root.clone().ok_or("root")?;
        let reference = root.kv1.reference.as_ref().ok_or("kv root")?;
        let durable = service.durable.as_mut().ok_or("durable")?;
        durable.apply_batch_with_compaction_in_replay_epoch(
            root.replay_epoch,
            "heptabao-server",
            "system",
            "remove-record-object",
            root.identity().map_err(|_| "identity")?.digest(),
            vec![(reference.resource(), None)],
        )?;
        assert!(Service::load_state_from_durable(durable).is_err());
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_record_schema_tests.rs"]
mod schema_tests;
