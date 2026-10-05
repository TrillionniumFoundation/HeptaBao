//! Each HA node owns its Wrapper envelope. Raft owns the application authority;
//! an opaque provider blob is never copied between deployment bindings.
use super::*;
use crate::ha::CommittedStateRead;
use crate::state_record_root::StateIdentity;

const BINDING_FILE: &str = "ha-initialization.v1";

fn unavailable(message: &str) -> Response {
    Response::error(503, message)
}
fn live(deadline: Option<std::time::Instant>) -> Result<(), Response> {
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        return Err(unavailable(
            "HA Wrapper publication caller deadline expired",
        ));
    }
    Ok(())
}

pub(super) fn pending_path(data_dir: &Path) -> io::Result<PathBuf> {
    let parent = data_dir
        .parent()
        .ok_or_else(|| io::Error::other("missing parent"))?;
    let mut identity = b"heptabao.ha-initialization-path.v1\0".to_vec();
    identity.extend_from_slice(data_dir.as_os_str().as_encoded_bytes());
    Ok(parent.join(format!(
        ".heptabao-ha-init-{}",
        hex(&crypto::digest(&identity))
    )))
}
pub(super) fn pending_exists(data_dir: &Path) -> Result<bool, &'static str> {
    path_present(&pending_path(data_dir).map_err(|_| "invalid HA initialization path")?)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialBinding {
    schema: u8,
    operation_id: String,
    logical_digest: [u8; 32],
    owner_manifest_digest: [u8; 32],
    changed_owner_mask: u8,
}

/// Holds the actual local writer until provider decryption and candidate
/// authentication complete. A request cannot replace this with a path or PID.
#[cfg(target_os = "linux")]
pub(super) struct PendingInitialization {
    path: PathBuf,
    local: FileBackend,
    bundle: BackendBundle,
    pub(super) seal: SealMetadata,
    protected: Zeroizing<Vec<u8>>,
    recovery: Option<Zeroizing<Vec<u8>>>,
}

#[cfg(target_os = "linux")]
pub(super) struct JoinAdmission {
    state: State,
    records: Option<records::RecordPlan>,
    identity: StateIdentity,
}

fn context(
    data_dir: &Path,
    cluster_id: &str,
    seal: &SealMetadata,
    bundle: &BackendBundle,
    recovery: Option<&[u8]>,
) -> Result<Vec<u8>, Response> {
    let seal_bytes = owner_store::serialize_owner(seal).map_err(state_serialization_error)?;
    let mut context = b"heptabao.ha-initialization-binding.v1\0".to_vec();
    for bytes in [
        data_dir.as_os_str().as_encoded_bytes(),
        cluster_id.as_bytes(),
        seal_bytes.as_slice(),
        &bundle.snapshot,
        &bundle.ledger,
        &bundle.journal,
        recovery.unwrap_or_default(),
    ] {
        context.extend_from_slice(&crypto::digest(bytes));
    }
    Ok(context)
}

#[cfg(target_os = "linux")]
pub(super) fn load_pending(data_dir: &Path) -> Result<PendingInitialization, Response> {
    let path = pending_path(data_dir).map_err(|_| unavailable("invalid HA initialization path"))?;
    private_directory(&path).map_err(|_| unavailable("unsafe HA initialization candidate"))?;
    let mut local = FileBackend::open(&path)
        .map_err(|_| unavailable("HA initialization candidate is unavailable or busy"))?;
    let bundle = local
        .load()
        .map_err(|_| unavailable("HA initialization candidate is incomplete"))?;
    let seal = load_seal_metadata(&path)
        .ok()
        .flatten()
        .filter(SealMetadata::is_wrapper)
        .ok_or_else(|| unavailable("HA initialization Wrapper seal is unavailable"))?;
    if load_durable_profile(&path).map_err(unavailable)?.is_some() {
        return Err(unavailable(
            "HA initialization cannot use a shared PostgreSQL writer",
        ));
    }
    let protected = read_private_initialization_file(&path, BINDING_FILE)
        .map_err(|_| unavailable("HA initialization binding is unavailable"))?
        .ok_or_else(|| unavailable("HA initialization binding is absent"))?;
    let recovery = read_initialization_recovery(&path)
        .map_err(|_| unavailable("HA initialization recovery response is unavailable"))?;
    local
        .verify()
        .map_err(|_| unavailable("HA initialization owner changed"))?;
    Ok(PendingInitialization {
        path,
        local,
        bundle,
        seal,
        protected,
        recovery,
    })
}

impl InitializationStage {
    fn retain_ha_pending(
        &mut self,
        data_dir: &Path,
        parent: &ExclusiveDirectory,
    ) -> io::Result<()> {
        verify_initialization_parent(parent)?;
        let pending = pending_path(data_dir)?;
        if parent.entry_exists(initialization_leaf_name(parent, &pending)?)? {
            return Err(io::Error::other(
                "HA initialization candidate already exists",
            ));
        }
        File::open(&self.path)?.sync_all()?;
        parent.rename(
            initialization_leaf_name(parent, &self.path)?,
            initialization_leaf_name(parent, &pending)?,
        )?;
        self.path = pending;
        self.retain_on_drop = true;
        parent.sync_all().map_err(io::Error::other)
    }
}

impl Service {
    #[cfg(target_os = "linux")]
    pub(super) fn ha_initial_response_identity(
        &self,
        key: &[u8; 32],
    ) -> Result<StateIdentity, Response> {
        let barrier =
            AeadBarrier::new(*key).map_err(|_| unavailable("HA response barrier unavailable"))?;
        let durable = DurableService::reopen(&self.data_dir, barrier, MAX_OPERATIONS)
            .map_err(|_| unavailable("HA response local owner authentication failed"))?;
        let (state, bytes, rewrite) = Self::load_state_from_durable(&durable)?;
        if rewrite || state.engines.record_root().is_some() || state.replay_epoch != 0 {
            return Err(unavailable(
                "HA initial response candidate identity changed",
            ));
        }
        let identity = StateIdentity::Legacy(crypto::digest(&bytes));
        self.verify_ha_state_identity(identity)?;
        Ok(identity)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn prepare_ha_local_join(&self) -> Result<Option<JoinAdmission>, Response> {
        let Some(ha) = self.ha.as_ref() else {
            return Ok(None);
        };
        if self.postgres_durable.is_some()
            || self.durable_profile.is_some()
            || pending_exists(&self.data_dir).unwrap_or(true)
        {
            return Err(unavailable(
                "HA join requires a fresh node-local durable owner",
            ));
        }
        let (cluster, observed) = {
            let process = ha
                .lock_for_request()
                .map_err(|_| unavailable("HA control state unavailable"))?;
            let observed = process
                .latest_committed_state_if_changed(None)
                .map_err(|_| unavailable("HA join ReadIndex unavailable"))?;
            (process.cluster_id().to_owned(), observed)
        };
        let admission = match observed {
            CommittedStateRead::Absent => return Ok(None),
            CommittedStateRead::Unchanged => {
                return Err(unavailable("HA join cannot reuse an absent cursor"));
            }
            CommittedStateRead::Materialized(committed) => {
                let state: State = serde_json::from_slice(&committed.bytes)
                    .map_err(|_| unavailable("HA join state schema invalid"))?;
                state.validate_format()?;
                let canonical =
                    owner_store::serialize_owner(&state).map_err(state_serialization_error)?;
                if crypto::digest(&committed.bytes) != committed.digest
                    || state.engines.record_root().is_some()
                {
                    return Err(unavailable("HA join materialized identity invalid"));
                }
                match (
                    committed.owner_manifest_digest,
                    committed.changed_owner_mask,
                ) {
                    (Some(expected), Some(mask)) if mask & !0x1f == 0 => {
                        if canonical.as_slice() != committed.bytes.as_slice() {
                            return Err(unavailable("HA join owner-bound state is noncanonical"));
                        }
                        let operation = format!("hajoin-{}", hex(&committed.digest));
                        let plan =
                            Self::prepare_initial_owner_plan(&state, &canonical, &operation)?;
                        let binding = plan
                            .publication_binding(&operation, &canonical)
                            .map_err(|_| unavailable("HA join owner binding invalid"))?;
                        if binding.owner_manifest_digest() != expected {
                            return Err(unavailable("HA join canonical owner identity diverges"));
                        }
                    }
                    (None, None) => {}
                    _ => return Err(unavailable("HA join owner binding incomplete")),
                }
                JoinAdmission {
                    state,
                    records: None,
                    identity: StateIdentity::Legacy(committed.digest),
                }
            }
            CommittedStateRead::Records(committed) => {
                let (state, plan) = Self::materialize_committed_ha_records(ha, &committed)?;
                JoinAdmission {
                    state,
                    identity: plan.identity,
                    records: Some(plan),
                }
            }
        };
        if admission.state.cluster_id != cluster {
            return Err(unavailable("HA join cluster mismatch"));
        }
        self.validate_loaded_capacity(
            &admission.state,
            admission.records.as_ref().map(|plan| &plan.root),
        )?;
        self.verify_ha_state_identity(admission.identity)?;
        Ok(Some(admission))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn finish_ha_local_join(
        &mut self,
        admission: JoinAdmission,
        material: openbao_wrapper::barrier::PreparedMaterial,
    ) -> Result<(), Response> {
        let deadline = material.deadline;
        live(deadline)?;
        if self.initialized()
            || self.seal.is_some()
            || self.state.is_some()
            || self.recovery_required
            || pending_exists(&self.data_dir).unwrap_or(true)
        {
            return Err(unavailable("HA join local owner or store changed"));
        }
        let parent = self
            .data_dir
            .parent()
            .map(ExclusiveDirectory::open)
            .ok_or_else(|| unavailable("HA join parent absent"))?
            .map_err(|_| unavailable("HA join parent unsafe or busy"))?;
        verify_initialization_parent(&parent).map_err(|_| unavailable("HA join parent changed"))?;
        self.verify_ha_state_identity(admission.identity)?;
        let seal = match admission.state.auth.recovery_credential.as_ref() {
            Some(credential) => {
                openbao_wrapper::barrier::seal_with_recovery(&material.seal, credential)
                    .map_err(|_| unavailable("HA join local recovery index invalid"))?
            }
            None => material.seal,
        };
        let barrier = AeadBarrier::new(*material.key)
            .map_err(|_| unavailable("HA join barrier unavailable"))?;
        let mut stage = InitializationStage::create(&self.data_dir)
            .map_err(|_| unavailable("HA join stage creation failed"))?;
        let mut durable = DurableService::create_new(&stage.path, barrier, MAX_OPERATIONS)
            .map_err(|_| unavailable("HA join local durable owner unavailable"))?;
        let operation = format!("hajoin-{}", hex(&admission.identity.digest()));
        match &admission.records {
            Some(plan) => Self::persist_record_batch(&mut durable, plan, &operation)
                .map_err(|_| unavailable("HA join local record publication failed"))?,
            None => {
                let bytes = owner_store::serialize_owner(&admission.state)
                    .map_err(state_serialization_error)?;
                Self::persist_owner_state_batch(
                    &mut durable,
                    &admission.state,
                    &bytes,
                    &operation,
                    admission.state.schema,
                    admission.state.replay_epoch,
                    OwnerBatchInput {
                        options: PersistOwnerStateOptions {
                            compact_before_entry: false,
                            allow_epoch_catchup: true,
                            reuse: OwnerReuseHint::default(),
                        },
                        prepared_plan: None,
                    },
                )
                .map_err(|_| unavailable("HA join local owner publication failed"))?;
            }
        }
        persist_seal_metadata(&stage.path, &seal)
            .map_err(|_| unavailable("HA join seal preparation failed"))?;
        durable
            .verify_live_ownership()
            .map_err(|_| unavailable("HA join local writer fence lost"))?;
        live(deadline)?;
        self.verify_ha_state_identity(admission.identity)?;
        drop(durable);
        if !stage
            .publish(&self.data_dir, &parent)
            .map_err(|_| unavailable("HA join local publication failed"))?
        {
            return Err(unavailable("HA join local publication durability unknown"));
        }
        self.seal = Some(seal);
        self.activate_barrier_with_deadline(&material.key, deadline)?;
        live(deadline)?;
        self.verify_ha_state_identity(self.current_state_identity()?)?;
        live(deadline)?;
        Ok(())
    }

    pub(super) fn ha_initial_cluster(&self) -> Result<String, Response> {
        if self.postgres_durable.is_some() || self.durable_profile.is_some() {
            return Err(unavailable(
                "HA Wrapper requires a node-local durable owner",
            ));
        }
        let ha = self
            .ha
            .as_ref()
            .ok_or_else(|| unavailable("HA process is absent"))?
            .lock_for_request()
            .map_err(|_| unavailable("HA control state is unavailable"))?;
        if !ha.bootstrap_ready() || !ha.is_leader().unwrap_or(false) {
            return Err(unavailable(
                "HA initialization requires the elected ready leader",
            ));
        }
        match ha
            .latest_committed_state_if_changed(None)
            .map_err(|_| unavailable("HA initialization ReadIndex is unavailable"))?
        {
            CommittedStateRead::Absent => Ok(ha.cluster_id().to_owned()),
            _ => Err(Response::error(
                400,
                "HA application is already initialized",
            )),
        }
    }

    pub(super) fn verify_ha_state_identity(&self, identity: StateIdentity) -> Result<(), Response> {
        let Some(ha) = self.ha.as_ref() else {
            return Ok(());
        };
        let ha = ha
            .lock_for_request()
            .map_err(|_| unavailable("HA control state is unavailable"))?;
        ha.ensure_application_identity(identity)
            .map_err(|_| unavailable("HA recovery application identity is not current"))
    }

    pub(super) fn prepare_initial_owner_plan(
        state: &State,
        bytes: &[u8],
        operation_id: &str,
    ) -> Result<owner_store::OwnerWritePlan, Response> {
        let owners = vec![
            (
                "namespaces",
                Some(
                    owner_store::serialize_owner(&state.namespaces)
                        .map_err(state_serialization_error)?,
                ),
            ),
            (
                "auth",
                Some(owner_store::serialize_owner(&state.auth).map_err(state_serialization_error)?),
            ),
            (
                "engines",
                Some(
                    owner_store::serialize_owner(&state.engines)
                        .map_err(state_serialization_error)?,
                ),
            ),
            (
                "database",
                Some(
                    owner_store::serialize_owner(&state.database)
                        .map_err(state_serialization_error)?,
                ),
            ),
            (
                "raft_admin",
                Some(
                    owner_store::serialize_owner(&state.raft_admin)
                        .map_err(state_serialization_error)?,
                ),
            ),
        ];
        owner_store::OwnerWritePlan::new_with_reuse(
            bytes,
            operation_id,
            state.schema,
            &state.cluster_id,
            state.replay_epoch,
            owners,
            None,
            Vec::new(),
        )
        .map_err(|_| unavailable("HA initial owner plan is invalid"))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn publish_ha_initialization(
        &mut self,
        mut stage: InitializationStage,
        state: &State,
        bytes: &[u8],
        operation_id: &str,
        binding: owner_store::OwnerPublicationBinding,
        seal: SealMetadata,
        key: &[u8; 32],
        response: Response,
        parent: &ExclusiveDirectory,
        deadline: Option<std::time::Instant>,
    ) -> (Response, bool) {
        let result = (|| -> Result<(), Response> {
            live(deadline)?;
            let mut backend = FileBackend::open(&stage.path)
                .map_err(|_| unavailable("HA initial local owner is unavailable"))?;
            let bundle = backend
                .load()
                .map_err(|_| unavailable("HA initial local bundle is unavailable"))?;
            let recovery = read_initialization_recovery(&stage.path)
                .map_err(|_| unavailable("HA initial response is unavailable"))?;
            let aad = context(
                &self.data_dir,
                &state.cluster_id,
                &seal,
                &bundle,
                recovery.as_deref().map(Vec::as_slice),
            )?;
            let metadata = InitialBinding {
                schema: 1,
                operation_id: operation_id.to_owned(),
                logical_digest: crypto::digest(bytes),
                owner_manifest_digest: binding.owner_manifest_digest(),
                changed_owner_mask: binding.changed_owner_mask(),
            };
            let plaintext = Zeroizing::new(
                serde_json::to_vec(&metadata)
                    .map_err(|_| unavailable("HA initialization binding serialization failed"))?,
            );
            let barrier = AeadBarrier::new(*key)
                .map_err(|_| unavailable("HA initialization barrier unavailable"))?;
            let protected = barrier
                .seal(&aad, &plaintext)
                .map_err(|_| unavailable("HA initialization binding encryption failed"))?;
            write_private_initialization_file(&stage.path, BINDING_FILE, &protected)
                .map_err(|_| unavailable("HA initialization binding publication failed"))?;
            backend
                .verify()
                .map_err(|_| unavailable("HA initial local owner changed"))?;
            drop(backend);
            stage
                .retain_ha_pending(&self.data_dir, parent)
                .map_err(|_| {
                    unavailable(
                        "HA initialization durability unknown; inspect the retained candidate",
                    )
                })?;
            live(deadline)?;
            self.commit_or_match_ha_initial(state, bytes, operation_id, binding)?;
            live(deadline)?;
            let synced = stage.publish(&self.data_dir, parent).map_err(|_| {
                unavailable("HA committed initialization remains pending local publication")
            })?;
            if !synced {
                return Err(unavailable(
                    "HA local initialization publication durability unknown",
                ));
            }
            live(deadline)?;
            self.verify_ha_state_identity(StateIdentity::Legacy(crypto::digest(bytes)))?;
            self.seal = Some(seal);
            self.durable_profile = None;
            Ok(())
        })();
        match result {
            Ok(()) => (response, false),
            Err(error) => {
                self.fence_recovery_delivery();
                (error, false)
            }
        }
    }

    fn commit_or_match_ha_initial(
        &self,
        state: &State,
        bytes: &[u8],
        operation_id: &str,
        binding: owner_store::OwnerPublicationBinding,
    ) -> Result<(), Response> {
        let ha = self
            .ha
            .as_ref()
            .ok_or_else(|| unavailable("HA process is absent"))?
            .lock_for_request()
            .map_err(|_| unavailable("HA control state is unavailable"))?;
        if state.cluster_id != ha.cluster_id() {
            return Err(unavailable("HA initialization cluster changed"));
        }
        match ha
            .latest_committed_state_if_changed(None)
            .map_err(|_| unavailable("HA initialization ReadIndex is unavailable"))?
        {
            CommittedStateRead::Absent => {
                if !ha.bootstrap_ready() || !ha.is_leader().unwrap_or(false) {
                    return Err(unavailable(
                        "HA initialization requires the elected ready leader",
                    ));
                }
                ha.commit_state_with_owner_binding(operation_id, [0; 32], bytes, binding)
                    .map_err(|_| {
                        unavailable(
                            "HA initialization commit outcome unknown; retain the exact candidate",
                        )
                    })?;
            }
            CommittedStateRead::Materialized(committed)
                if committed.digest == crypto::digest(bytes)
                    && committed.bytes.as_slice() == bytes
                    && committed.owner_manifest_digest == Some(binding.owner_manifest_digest())
                    && committed.changed_owner_mask == Some(binding.changed_owner_mask()) => {}
            _ => {
                return Err(Response::error(
                    409,
                    "HA initialization candidate conflicts with committed authority",
                ));
            }
        }
        ha.ensure_application_identity(StateIdentity::Legacy(crypto::digest(bytes)))
            .map_err(|_| unavailable("HA initialized application identity is unconfirmed"))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn finish_pending_ha_initialization(
        &mut self,
        mut pending: PendingInitialization,
        key: &[u8; 32],
        body: &Value,
        deadline: Option<std::time::Instant>,
    ) -> Result<Response, Response> {
        live(deadline)?;
        let parent = self
            .data_dir
            .parent()
            .map(ExclusiveDirectory::open)
            .ok_or_else(|| unavailable("HA initialization parent is absent"))?
            .map_err(|_| unavailable("HA initialization parent is unsafe or busy"))?;
        verify_initialization_parent(&parent)
            .map_err(|_| unavailable("HA initialization parent changed"))?;
        pending
            .local
            .verify()
            .map_err(|_| unavailable("HA pending owner changed"))?;
        let actual = pending
            .local
            .load()
            .map_err(|_| unavailable("HA pending bundle unavailable"))?;
        if actual != pending.bundle
            || load_seal_metadata(&pending.path).ok().flatten().as_ref() != Some(&pending.seal)
            || read_private_initialization_file(&pending.path, BINDING_FILE)
                .ok()
                .flatten()
                .as_ref()
                != Some(&pending.protected)
            || read_initialization_recovery(&pending.path)
                .ok()
                .flatten()
                .as_ref()
                != pending.recovery.as_ref()
        {
            return Err(unavailable("HA pending candidate changed"));
        }
        let cluster = self
            .ha
            .as_ref()
            .ok_or_else(|| unavailable("HA process is absent"))?
            .lock_for_request()
            .map_err(|_| unavailable("HA control state unavailable"))?
            .cluster_id()
            .to_owned();
        let barrier =
            AeadBarrier::new(*key).map_err(|_| unavailable("HA pending barrier unavailable"))?;
        let aad = context(
            &self.data_dir,
            &cluster,
            &pending.seal,
            &actual,
            pending.recovery.as_deref().map(Vec::as_slice),
        )?;
        let plaintext = Zeroizing::new(
            barrier
                .open(&aad, &pending.protected)
                .map_err(|_| unavailable("HA pending candidate authentication failed"))?,
        );
        let metadata: InitialBinding = serde_json::from_slice(&plaintext)
            .map_err(|_| unavailable("HA pending binding is invalid"))?;
        let durable = DurableService::reopen_with_backend(
            Box::new(pending.local) as Box<dyn DurableBackend>,
            barrier,
            MAX_OPERATIONS,
        )
        .map_err(|_| unavailable("HA pending durable authentication failed"))?;
        let (state, bytes, rewrite) = Self::load_state_from_durable(&durable)?;
        if rewrite
            || state.engines.record_root().is_some()
            || state.cluster_id != cluster
            || metadata.schema != 1
            || metadata.logical_digest != crypto::digest(&bytes)
        {
            return Err(unavailable("HA pending state identity is invalid"));
        }
        let plan = Self::prepare_initial_owner_plan(&state, &bytes, &metadata.operation_id)?;
        let binding = plan
            .publication_binding(&metadata.operation_id, &bytes)
            .map_err(|_| unavailable("HA pending owner binding invalid"))?;
        if binding.owner_manifest_digest() != metadata.owner_manifest_digest
            || binding.changed_owner_mask() != metadata.changed_owner_mask
        {
            return Err(unavailable("HA pending owner identity changed"));
        }
        let stored = durable
            .get("system", "state")
            .map_err(|_| unavailable("HA pending manifest unavailable"))?
            .ok_or_else(|| unavailable("HA pending manifest absent"))?;
        if stored.expose() != plan.manifest_bytes.as_slice() {
            return Err(unavailable(
                "HA pending manifest does not bind initial plan",
            ));
        }
        let response = match (&pending.recovery, body.get("recovery_nonce")) {
            (Some(recovery), Some(value)) => {
                let secret = decode_initialization_secret(value)
                    .map_err(|message| Response::error(400, message))?;
                let (provider, aad) = initialization_recovery_barrier(&secret, &pending.seal)
                    .map_err(|_| unavailable("HA response provider unavailable"))?;
                let plaintext = Zeroizing::new(provider.open(&aad, recovery).map_err(|_| {
                    Response::error(403, "HA initialization response authentication failed")
                })?);
                Response::ok(
                    serde_json::from_slice(&plaintext)
                        .map_err(|_| unavailable("HA initialization response is corrupt"))?,
                )
            }
            (Some(_), None) => {
                return Err(Response::error(
                    400,
                    "original recovery_nonce is required to recover this initialization",
                ));
            }
            (None, Some(_)) => {
                return Err(Response::error(
                    400,
                    "HA initialization has no response retrieval credential",
                ));
            }
            (None, None) => Response::error(
                400,
                "HA application is already initialized; original response was not retained",
            ),
        };
        live(deadline)?;
        self.commit_or_match_ha_initial(&state, &bytes, &metadata.operation_id, binding)?;
        drop(durable);
        let mut stage = InitializationStage {
            path: pending.path,
            retain_on_drop: true,
        };
        live(deadline)?;
        if !stage
            .publish(&self.data_dir, &parent)
            .map_err(|_| unavailable("HA committed initialization remains pending publication"))?
        {
            return Err(unavailable(
                "HA initialization directory sync outcome unknown",
            ));
        }
        self.seal = Some(pending.seal);
        self.durable_profile = None;
        self.activate_barrier_with_deadline(key, deadline)?;
        live(deadline)?;
        let initial_identity = StateIdentity::Legacy(metadata.logical_digest);
        if self.current_state_identity()? != initial_identity {
            return Err(unavailable(
                "HA initialization authority advanced before response delivery",
            ));
        }
        self.verify_ha_state_identity(initial_identity)?;
        live(deadline)?;
        Ok(response)
    }
}
