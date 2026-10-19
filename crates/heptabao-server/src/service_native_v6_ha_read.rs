//! Local native HA recovery and request-scoped exact-current read proofs.
//! A cold load catches up to the actual committed root and grants no delivery.
//! A request proof separately requires the same fresh opaque ReadIndex.
use super::*;

#[path = "service_native_v6_ha_snapshot.rs"]
mod snapshot;

#[path = "service_native_v6_ha_archive_source.rs"]
mod archive_source;
pub(crate) use archive_source::NativeHaArchiveRepairSource;

pub(crate) struct ColdNativeHaRead {
    pub(in crate::service) metadata: State,
    pub(in crate::service) native: BTreeMap<MountScope, NativeReadView>,
    pub(in crate::service) root: RecordStateRootV6,
}

fn fingerprints(state: &State, deadline: OriginalDeadline) -> Result<[[u8; 32]; 4], Response> {
    fn one(value: &impl Serialize, deadline: OriginalDeadline) -> Result<[u8; 32], Response> {
        live(deadline)?;
        let bytes = owner_store::serialize_owner(value).map_err(|_| unavailable())?;
        live(deadline)?;
        let result = crypto::digest(&bytes);
        live(deadline)?;
        Ok(result)
    }
    Ok([
        one(&state.namespaces, deadline)?,
        one(&state.auth, deadline)?,
        one(&state.database, deadline)?,
        one(&state.raft_admin, deadline)?,
    ])
}

// The opt-in diagnostic build reports fixed recovery stages and runtime
// errors only. It never prints barrier material, payloads or Auth credentials.
fn cold_stage_failed(phase: &'static str) {
    #[cfg(feature = "private-ha-forward-diagnostic")]
    eprintln!("HBHA-PRIVATE-COLD-NATIVE phase={phase} result=refused");
    #[cfg(not(feature = "private-ha-forward-diagnostic"))]
    let _ = phase;
}

// Cold unseal has an actual provided local barrier key, but it intentionally
// has not installed that key or State into Service yet. This cannot be used by
// a warm request, and its result must go through the existing HA sync/audit gate.
pub(crate) fn load_cold_native_ha(
    service: &Service,
    durable: &mut DurableService<AeadBarrier>,
    key: &[u8; 32],
    deadline: OriginalDeadline,
) -> Result<Option<ColdNativeHaRead>, Response> {
    live(deadline)?;
    let bytes = durable
        .get("system", "state")
        .map_err(storage_rejected)?
        .ok_or_else(unavailable)?;
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        storage_format: Option<String>,
    }
    let probe: Probe = serde_json::from_slice(bytes.expose()).map_err(|_| unavailable())?;
    if probe.storage_format.as_deref() != Some(crate::state_record_root_v6::STORAGE_FORMAT) {
        return Ok(None);
    }
    let ha = service.ha.as_ref().ok_or_else(unavailable)?;
    let environment = LocalHaEnvironment::capture(service, ha, key, deadline)
        .inspect_err(|_| cold_stage_failed("environment"))?;
    let process = ha.lock_for_request().map_err(|_| {
        cold_stage_failed("process_lock");
        unavailable()
    })?;
    if !process.native_v6_enabled() {
        return Err(unavailable());
    }
    let committed = process
        .native_v6_committed_read(deadline)
        .map_err(|error| {
            #[cfg(feature = "private-ha-forward-diagnostic")]
            eprintln!("HBHA-PRIVATE-COLD-NATIVE phase=committed_read reason={error:?}");
            #[cfg(not(feature = "private-ha-forward-diagnostic"))]
            let _ = error;
            unavailable()
        })?
        .ok_or_else(|| {
            cold_stage_failed("committed_root_absent");
            unavailable()
        })?;
    let mut selected = LocalSelection::read(durable, &committed)
        .inspect_err(|_| cold_stage_failed("local_selection"))?;
    let root = selected.native.as_ref().ok_or_else(unavailable)?;
    if root.cluster_id != process.cluster_id()
        || root.replay_epoch != durable.replay_epoch()
        || root.reader_floor.native_kv2_format != 2
    {
        cold_stage_failed("local_root_binding");
        return Err(unavailable());
    }
    let mut gate = || {
        environment
            .check_cold(service, key)
            .inspect_err(|_| cold_stage_failed("original_cold_owner"))
            .map_err(|_| ServiceError::BarrierFailure)?;
        process
            .verify_native_v6_committed_read(&committed)
            .inspect_err(|_| cold_stage_failed("original_read_witness"))
            .map_err(|_| ServiceError::BarrierFailure)?;
        deadline.check().map_err(|_| ServiceError::BarrierFailure)
    };
    if root.identity().map_err(|_| unavailable())?.digest() != committed.published().root_digest() {
        // The local HA cursor proves which prior root this real barrier owner
        // selected. A cold catch-up installs the actual current closure without
        // needing readable obsolete payloads or a fabricated warm State.
        let published = Cell::new(false);
        let result = process
            .with_native_v6_source(&committed, |codec, store| {
                service.install_native_v6_replica_inner(
                    durable, &selected, &committed, codec, store, &mut gate, &published,
                )
            })
            .map_err(|_| {
                cold_stage_failed("replica_source");
                unavailable()
            })?;
        if result.is_err() && (published.get() || durable.recovery_required()) {
            return Err(Response::error(
                503,
                "native V6 HA cold publication requires reconciliation",
            ));
        }
        result.inspect_err(|_| cold_stage_failed("replica_install"))?;
        selected = LocalSelection::read(durable, &committed)
            .inspect_err(|_| cold_stage_failed("installed_local_selection"))?;
    }
    let root = selected.native.as_ref().ok_or_else(unavailable)?;
    NativeHaCursor::decode(selected.ha_bytes.as_ref().ok_or_else(unavailable)?.expose())?
        .matches_current(&committed)
        .inspect_err(|_| cold_stage_failed("current_cursor"))?;
    let (metadata, native) = match materialize_local(durable, root, deadline, &mut gate) {
        Ok(local) => local,
        Err(_) => {
            // Only exact-current registered metadata is eligible for a missing
            // physical-file repair. Existing bad bytes remain untouched.
            process
                .with_native_v6_source(&committed, |codec, store| {
                    repair_current_local_objects(
                        durable, &selected, &committed, codec, store, &mut gate,
                    )
                })
                .map_err(|_| {
                    cold_stage_failed("repair_source");
                    unavailable()
                })?
                .inspect_err(|_| cold_stage_failed("physical_repair"))?;
            materialize_local(durable, root, deadline, &mut gate)
                .inspect_err(|_| cold_stage_failed("materialize_after_repair"))?
        }
    };
    root_namespace_only(&metadata).inspect_err(|_| cold_stage_failed("root_namespace"))?;
    let owner_bytes = root
        .owners
        .iter()
        .try_fold(0u64, |sum, owner| sum.checked_add(owner.owner.total_bytes))
        .ok_or_else(unavailable)?;
    if owner_bytes > service.opaque_owner_limit() as u64 {
        return Err(Response::error(
            507,
            "native opaque owner capacity exhausted",
        ));
    }
    selected
        .check(durable, selected.initial_generation)
        .inspect_err(|_| cold_stage_failed("final_local_generation"))
        .map_err(storage_rejected)?;
    gate().map_err(storage_rejected)?;
    // This cold owner has not installed State or a local barrier key into
    // Service, completed unseal audit, or authorized any business principal.
    Ok(Some(ColdNativeHaRead {
        metadata,
        native,
        root: root.clone(),
    }))
}

/// Affine process-local proof of the exact native root installed in this actual
/// local barrier owner. It grants no resource ACL or TTL extension. The request
/// delivery owner still retains its original Actor/clock and mandatory audit.
pub(crate) struct NativeHaReadProof {
    environment: LocalHaEnvironment,
    selected: LocalSelection,
    committed: CommittedNativeV6Read,
    identity: StateIdentity,
    owner_fingerprints: [[u8; 32]; 4],
}
impl NativeHaReadProof {
    pub(crate) fn generation(&self) -> u64 {
        self.selected.initial_generation
    }
    pub(crate) fn identity(&self) -> StateIdentity {
        self.identity
    }
    fn check_instance(&self, service: &Service) -> Result<(), Response> {
        self.environment.check(service)?;
        if service.current_state_identity()? != self.identity || service.record_root.is_some() {
            return Err(unavailable());
        }
        let root = service.native_root.as_ref().ok_or_else(unavailable)?;
        if root.encode().map_err(|_| unavailable())?.as_slice() != self.selected.root_bytes.expose()
            || root.identity().map_err(|_| unavailable())? != self.identity
        {
            return Err(unavailable());
        }
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        root_namespace_only(state)?;
        if state.schema != root.state_schema
            || state.cluster_id != root.cluster_id
            || state.replay_epoch != root.replay_epoch
            || state.global_lossless_json_format != root.global_lossless_json_format
            || fingerprints(state, self.environment.deadline)? != self.owner_fingerprints
        {
            return Err(unavailable());
        }
        live(self.environment.deadline)
    }
    pub(crate) fn check_warm(&self, service: &Service) -> Result<(), Response> {
        self.check_instance(service)?;
        let durable = service.durable.as_ref().ok_or_else(unavailable)?;
        if durable.recovery_required()
            || durable.generation() != self.selected.initial_generation
            || durable.replay_epoch() != self.committed.enrollment().epoch()
        {
            return Err(unavailable());
        }
        for condition in self.selected.conditions() {
            let actual = durable
                .get("system", &condition.resource)
                .map_err(storage_rejected)?;
            if actual.as_ref().map(Secret::expose)
                != condition.expected.as_ref().map(Secret::expose)
            {
                return Err(unavailable());
            }
        }
        // StateIdentity and the four opaque owners do not authenticate a
        // mutated warm engine cache. Bind its KV1 address key and every native
        // mount root to the same selected typed graph before returning even a
        // bounded warm check. Actual disk reads remain check_with()'s duty.
        let root = service.native_root.as_ref().ok_or_else(unavailable)?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let key = root.kv1_key().map_err(|_| unavailable())?;
        if state.engines.record_root().as_ref() != Some(&root.kv1)
            || state
                .engines
                .record_address_key()
                .is_none_or(|actual| actual.expose() != key.expose())
        {
            return Err(unavailable());
        }
        let parent = root.kv2_parent_key().map_err(|_| unavailable())?;
        state
            .engines
            .validate_native_roots(&parent, &root.kv2, &|| {
                self.environment
                    .deadline
                    .check()
                    .map_err(|_| crate::state_records::RecordError::Invalid)
            })
            .map_err(|_| unavailable())?;
        let process = self
            .environment
            .ha
            .lock_for_request()
            .map_err(|_| unavailable())?;
        process
            .verify_native_v6_committed_read(&self.committed)
            .map_err(|_| unavailable())?;
        self.check_instance(service)
    }
    pub(in crate::service) fn check_with(
        &self,
        service: &mut Service,
        check_installed: impl FnOnce(
            &State,
            &State,
            &BTreeMap<MountScope, NativeReadView>,
            &RecordStateRootV6,
            OriginalDeadline,
        ) -> Result<(), Response>,
    ) -> Result<(), Response> {
        self.check_instance(service)?;
        let process = self
            .environment
            .ha
            .lock_for_request()
            .map_err(|_| unavailable())?;
        process
            .verify_native_v6_committed_read(&self.committed)
            .map_err(|_| unavailable())?;
        let mut durable = service.durable.take().ok_or_else(unavailable)?;
        let result = (|| {
            self.selected
                .check(&mut durable, self.selected.initial_generation)
                .map_err(storage_rejected)?;
            let root = self.selected.native.as_ref().ok_or_else(unavailable)?;
            let mut gate = || {
                self.check_instance(service)
                    .map_err(|_| ServiceError::BarrierFailure)?;
                process
                    .verify_native_v6_committed_read(&self.committed)
                    .map_err(|_| ServiceError::BarrierFailure)?;
                self.environment
                    .deadline
                    .check()
                    .map_err(|_| ServiceError::BarrierFailure)
            };
            let (metadata, native) =
                materialize_local(&mut durable, root, self.environment.deadline, &mut gate)?;
            if fingerprints(&metadata, self.environment.deadline)? != self.owner_fingerprints {
                return Err(unavailable());
            }
            check_installed(
                service.state.as_ref().ok_or_else(unavailable)?,
                &metadata,
                &native,
                root,
                self.environment.deadline,
            )?;
            self.selected
                .check(&mut durable, self.selected.initial_generation)
                .map_err(storage_rejected)?;
            gate().map_err(storage_rejected)
        })();
        service.durable = Some(durable);
        result?;
        self.check_instance(service)
    }

    /// Caller-supplied check is always additional to the retained custody and
    /// consensus proof. It cannot refresh the original deadline or replace Actor.
    #[cfg(test)]
    pub(in crate::service) fn check_checked(
        &self,
        service: &mut Service,
        original_actor: &mut impl FnMut() -> Result<(), Response>,
    ) -> Result<(), Response> {
        original_actor()?;
        self.check_with(service, |installed, metadata, native, root, deadline| {
            original_actor()?;
            Service::check_native_installed(installed, metadata, native, root, deadline)?;
            original_actor()
        })?;
        original_actor()
    }
}

impl Service {
    pub(crate) fn capture_native_ha_request_proof(
        &mut self,
        original_actor: &mut impl FnMut() -> Result<(), Response>,
    ) -> Result<Option<NativeHaReadProof>, Response> {
        if self.native_root.is_none() {
            return Ok(None);
        }
        original_actor()?;
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let ha = self.ha.as_ref().ok_or_else(unavailable)?.clone();
        let key = Zeroizing::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?);
        let environment = LocalHaEnvironment::capture(self, &ha, &key, deadline)?;
        let process = ha.lock_for_request().map_err(|_| unavailable())?;
        if !process.native_v6_enabled() {
            return Err(unavailable());
        }
        let committed = process
            .native_v6_committed_read(deadline)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let identity = self.current_state_identity()?;
        if identity != StateIdentity::RecordsV6(committed.published().root_digest()) {
            return Err(unavailable());
        }
        let mut durable = self.durable.take().ok_or_else(unavailable)?;
        let result = (|| {
            let selected = LocalSelection::read(&mut durable, &committed)?;
            NativeHaCursor::decode(selected.ha_bytes.as_ref().ok_or_else(unavailable)?.expose())?
                .matches_current(&committed)?;
            let root = selected.native.as_ref().ok_or_else(unavailable)?;
            let mut gate = || {
                environment
                    .check(self)
                    .map_err(|_| ServiceError::BarrierFailure)?;
                original_actor().map_err(|_| ServiceError::BarrierFailure)?;
                process
                    .verify_native_v6_committed_read(&committed)
                    .map_err(|_| ServiceError::BarrierFailure)?;
                deadline.check().map_err(|_| ServiceError::BarrierFailure)
            };
            let (metadata, native) = materialize_local(&mut durable, root, deadline, &mut gate)?;
            Self::check_native_installed(
                self.state.as_ref().ok_or_else(unavailable)?,
                &metadata,
                &native,
                root,
                deadline,
            )?;
            selected
                .check(&mut durable, selected.initial_generation)
                .map_err(storage_rejected)?;
            gate().map_err(storage_rejected)?;
            let owner_fingerprints = fingerprints(&metadata, deadline)?;
            Ok((selected, owner_fingerprints))
        })();
        self.durable = Some(durable);
        let (selected, owner_fingerprints) = result?;
        original_actor()?;
        process
            .verify_native_v6_committed_read(&committed)
            .map_err(|_| unavailable())?;
        drop(process);
        let proof = NativeHaReadProof {
            environment,
            selected,
            committed,
            identity,
            owner_fingerprints,
        };
        proof.check_warm(self)?;
        original_actor()?;
        Ok(Some(proof))
    }
    pub(crate) fn capture_native_ha_unseal_proof(
        &mut self,
    ) -> Result<Option<NativeHaReadProof>, Response> {
        self.capture_native_ha_request_proof(&mut || Ok(()))
    }
}
