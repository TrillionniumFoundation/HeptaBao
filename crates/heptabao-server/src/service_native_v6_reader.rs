//! Explicit single-node root-namespace candidate admission from actual barrier custody.
//! Profiles, cursors and graph inspection alone never grant a request or writer.
use super::*;
use crate::engines::kv2_native_records::NativeReadView;
use crate::state_record_root::{RecordStateRoot, StateIdentity};
use crate::state_record_root_v6::{MountScope, ObjectDomain, RecordStateRootV6};
use crate::state_records::{ObjectRef, RecordError, RecordReader};
use crate::v6_native_custody::OriginalDeadline;
use crate::v6_read_validation::{ObjectSource, ReadContext, ReadIdentity};

pub(super) const ACTIVE_CURSOR_RESOURCE: &str = "state-native-v6/active-publication-cursor";
pub(super) const ACTIVE_SOURCE_ROOT_RESOURCE: &str = "state-native-v6/active-source-root";
pub(super) const ACTIVE_CURSOR_FORMAT: &str = "heptabao-native-v6-active-publication-cursor-v1";

fn unavailable() -> Response {
    Response::error(
        503,
        "native V6 Service candidate custody or publication rejected",
    )
}
fn live(deadline: OriginalDeadline) -> Result<(), Response> {
    deadline.check().map_err(|_| unavailable())
}

// This is eligibility configuration only. Construction cannot open storage,
// admit a reader, authenticate a principal or extend the original deadline.
// No Clone, serde, public fields or caller-selected data directory.
pub(super) struct NativeCandidateProfile {
    data_dir: PathBuf,
}
impl NativeCandidateProfile {
    pub(super) fn capture(service: &Service) -> Result<Self, Response> {
        if service.state.is_some()
            || service.durable.is_some()
            || service.barrier_key.is_some()
            || service.ha.is_some()
            || service.postgres_durable.is_some()
            || service.durable_profile.is_some()
            || service.openbao_wrapper_owner.is_some()
            || service.seal.as_ref().is_some_and(SealMetadata::is_wrapper)
        {
            return Err(unavailable());
        }
        Ok(Self {
            data_dir: service.data_dir.clone(),
        })
    }

    pub(super) fn check_environment(&self, service: &Service) -> Result<(), Response> {
        if service.data_dir != self.data_dir
            || service.ha.is_some()
            || service.postgres_durable.is_some()
            || service.durable_profile.is_some()
            || service.openbao_wrapper_owner.is_some()
            || service.audit_failed
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

// This cursor is authenticated durable data, not a capability. Only the
// active publisher may atomically retain the V5 source and replace state.
// Side-snapshot cursor formats and resources are deliberately distinct.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeActiveCursor {
    format: String,
    cluster_id: String,
    replay_epoch: u64,
    source_generation: u64,
    source_root_digest: [u8; 32],
    publication_generation: u64,
    root_digest: [u8; 32],
    state_schema: u32,
    reader_record_format: u32,
    reader_minimum_state_schema: u32,
    reader_native_kv2_format: u32,
}
impl NativeActiveCursor {
    pub(super) fn for_migration(
        source: &RecordStateRoot,
        source_generation: u64,
        root: &RecordStateRootV6,
        publication_generation: u64,
    ) -> Result<Self, Response> {
        source.validate().map_err(|_| unavailable())?;
        root.validate().map_err(|_| unavailable())?;
        let cursor = Self {
            format: ACTIVE_CURSOR_FORMAT.into(),
            cluster_id: root.cluster_id.clone(),
            replay_epoch: root.replay_epoch,
            source_generation,
            source_root_digest: source.identity().map_err(|_| unavailable())?.digest(),
            publication_generation,
            root_digest: root.identity().map_err(|_| unavailable())?.digest(),
            state_schema: root.state_schema,
            reader_record_format: root.reader_floor.record_format,
            reader_minimum_state_schema: root.reader_floor.minimum_state_schema,
            reader_native_kv2_format: root.reader_floor.native_kv2_format,
        };
        cursor.validate(source, root, publication_generation)?;
        Ok(cursor)
    }

    pub(super) fn advance(
        &self,
        root: &RecordStateRootV6,
        publication_generation: u64,
    ) -> Result<Self, Response> {
        root.validate().map_err(|_| unavailable())?;
        if self.format != ACTIVE_CURSOR_FORMAT
            || root.cluster_id != self.cluster_id
            || root.replay_epoch < self.replay_epoch
            || root.state_schema < self.state_schema
            || root.reader_floor.record_format != self.reader_record_format
            || root.reader_floor.native_kv2_format != self.reader_native_kv2_format
            || root.reader_floor.minimum_state_schema < self.reader_minimum_state_schema
            || publication_generation <= self.publication_generation
            || self.source_generation == 0
            || self.source_generation >= self.publication_generation
            || !supported_reader_schema(root.state_schema)
            || !supported_reader_schema(root.reader_floor.minimum_state_schema)
        {
            return Err(unavailable());
        }
        Ok(Self {
            format: ACTIVE_CURSOR_FORMAT.into(),
            cluster_id: self.cluster_id.clone(),
            replay_epoch: root.replay_epoch,
            source_generation: self.source_generation,
            source_root_digest: self.source_root_digest,
            publication_generation,
            root_digest: root.identity().map_err(|_| unavailable())?.digest(),
            state_schema: root.state_schema,
            reader_record_format: root.reader_floor.record_format,
            reader_minimum_state_schema: root.reader_floor.minimum_state_schema,
            reader_native_kv2_format: root.reader_floor.native_kv2_format,
        })
    }

    pub(super) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Response> {
        crate::secret_serde::to_vec(self, crate::state_record_root::MAX_ROOT_BYTES)
            .map_err(|_| unavailable())
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Response> {
        if bytes.len() > crate::state_record_root::MAX_ROOT_BYTES {
            return Err(unavailable());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
        if value.encode()?.as_slice() != bytes {
            return Err(unavailable());
        }
        Ok(value)
    }

    pub(super) fn validate(
        &self,
        source: &RecordStateRoot,
        root: &RecordStateRootV6,
        current_generation: u64,
    ) -> Result<(), Response> {
        source.validate().map_err(|_| unavailable())?;
        root.validate().map_err(|_| unavailable())?;
        if self.format != ACTIVE_CURSOR_FORMAT
            || source.cluster_id != root.cluster_id
            || source.state_schema > root.state_schema
            || source.replay_epoch > root.replay_epoch
            || self.cluster_id != root.cluster_id
            || self.replay_epoch != root.replay_epoch
            || self.state_schema != root.state_schema
            || self.reader_record_format != root.reader_floor.record_format
            || self.reader_minimum_state_schema != root.reader_floor.minimum_state_schema
            || self.reader_native_kv2_format != root.reader_floor.native_kv2_format
            || self.source_generation == 0
            || self.source_generation >= self.publication_generation
            || self.publication_generation > current_generation
            || self.source_root_digest != source.identity().map_err(|_| unavailable())?.digest()
            || self.root_digest != root.identity().map_err(|_| unavailable())?.digest()
            || !matches!(
                source.identity().map_err(|_| unavailable())?,
                StateIdentity::RecordsV5(_)
            )
            || !matches!(
                root.identity().map_err(|_| unavailable())?,
                StateIdentity::RecordsV6(_)
            )
            || !supported_reader_schema(source.state_schema)
            || !supported_reader_schema(root.state_schema)
            || !supported_reader_schema(root.reader_floor.minimum_state_schema)
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

// Facts captured from the actual Service activation. No serialized key,
// principal, external receipt, candidate-supplied clock or membership grant.
struct ActivationEnvironment {
    data_dir: PathBuf,
    seal: SealMetadata,
    nonce: Zeroizing<String>,
    barrier_digest: [u8; 32],
    deadline: OriginalDeadline,
    observations: Arc<super::native_blob_source::PayloadObservations>,
}
impl ActivationEnvironment {
    fn capture(
        service: &Service,
        profile: &NativeCandidateProfile,
        key: &[u8; 32],
        deadline: OriginalDeadline,
    ) -> Result<Self, Response> {
        live(deadline)?;
        profile.check_environment(service)?;
        let seal = service.seal.clone().ok_or_else(unavailable)?;
        if seal.is_wrapper() || key == &[0; 32] {
            return Err(unavailable());
        }
        seal.validate().map_err(|_| unavailable())?;
        live(deadline)?;
        if load_seal_metadata(&service.data_dir)
            .map_err(|_| unavailable())?
            .as_ref()
            != Some(&seal)
        {
            return Err(unavailable());
        }
        live(deadline)?;
        Ok(Self {
            data_dir: service.data_dir.clone(),
            seal,
            nonce: Zeroizing::new(service.unseal_nonce.clone()),
            barrier_digest: crypto::digest(key),
            deadline,
            observations: Arc::clone(&service.native_payload_observations),
        })
    }

    fn check_seal(&self) -> Result<(), Response> {
        live(self.deadline)?;
        if load_seal_metadata(&self.data_dir)
            .map_err(|_| unavailable())?
            .as_ref()
            != Some(&self.seal)
        {
            return Err(unavailable());
        }
        live(self.deadline)
    }
}

// The actual owned durable instance and authenticated publication mint this
// private affine permit. A profile, decoded cursor or inspection cannot do so.
struct ReaderPermit {
    activation: ActivationEnvironment,
    generation: u64,
    replay_epoch: u64,
    identity: StateIdentity,
    root_bytes: Zeroizing<Vec<u8>>,
    cursor_bytes: Zeroizing<Vec<u8>>,
    source_bytes: Zeroizing<Vec<u8>>,
}
impl ReaderPermit {
    fn check(&self, durable: &mut DurableService<AeadBarrier>) -> Result<(), Response> {
        live(self.activation.deadline)?;
        self.activation.check_seal()?;
        durable.verify_live_ownership().map_err(|_| unavailable())?;
        live(self.activation.deadline)?;
        if durable.recovery_required()
            || durable.generation() != self.generation
            || durable.replay_epoch() != self.replay_epoch
        {
            return Err(unavailable());
        }
        for (resource, expected) in [
            ("state", self.root_bytes.as_slice()),
            (ACTIVE_CURSOR_RESOURCE, self.cursor_bytes.as_slice()),
            (ACTIVE_SOURCE_ROOT_RESOURCE, self.source_bytes.as_slice()),
        ] {
            live(self.activation.deadline)?;
            let observed = durable
                .get("system", resource)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if observed.expose() != expected {
                return Err(unavailable());
            }
            live(self.activation.deadline)?;
        }
        durable.verify_live_ownership().map_err(|_| unavailable())?;
        self.activation.check_seal()?;
        if durable.generation() != self.generation || durable.replay_epoch() != self.replay_epoch {
            return Err(unavailable());
        }
        live(self.activation.deadline)
    }
}

struct CheckedSource<'a> {
    durable: &'a DurableService<AeadBarrier>,
    deadline: OriginalDeadline,
}
impl RecordReader for CheckedSource<'_> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        let bytes = records::DurableReader(self.durable).read_object(reference)?;
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        Ok(bytes)
    }
}
impl ObjectSource for CheckedSource<'_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        let value = self
            .durable
            .get("system", &v6_records::native_resource(domain, reference))
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        let bytes = Zeroizing::new(value.expose().to_vec());
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        Ok(bytes)
    }
}

fn root_namespace_only(state: &State) -> Result<(), Response> {
    if state.namespace_protected.is_some()
        || !state.namespace_leases.is_empty()
        || !state.namespaces.is_empty()
        || state
            .engines
            .v6_namespace_paths()
            .any(|path| !path.is_empty())
    {
        return Err(unavailable());
    }
    state.validate_format().map_err(|_| unavailable())
}

// Four bounded owners are compared separately. Native engines must additionally
// pass the mandatory installed-engine check below; no full State image is made.
fn bounded_owner_fingerprints(
    state: &State,
    deadline: OriginalDeadline,
) -> Result<[[u8; 32]; 4], Response> {
    fn fingerprint(
        value: &impl Serialize,
        deadline: OriginalDeadline,
    ) -> Result<[u8; 32], Response> {
        live(deadline)?;
        let bytes = owner_store::serialize_owner(value).map_err(|_| unavailable())?;
        live(deadline)?;
        let digest = crypto::digest(&bytes);
        live(deadline)?;
        Ok(digest)
    }
    Ok([
        fingerprint(&state.namespaces, deadline)?,
        fingerprint(&state.auth, deadline)?,
        fingerprint(&state.database, deadline)?,
        fingerprint(&state.raft_admin, deadline)?,
    ])
}

pub(super) struct ColdNativeRead {
    pub(super) metadata: State,
    pub(super) native: BTreeMap<MountScope, NativeReadView>,
    pub(super) root: RecordStateRootV6,
    pub(super) proof: NativeProof,
}

// Used only by local unseal completion through normal mandatory audit. This
// cannot qualify a business response, actor, lease, HA epoch or request writer.
pub(super) struct NativeProof {
    permit: ReaderPermit,
    owner_fingerprints: [[u8; 32]; 4],
}
impl NativeProof {
    pub(super) fn generation(&self) -> u64 {
        self.permit.generation
    }
    pub(super) fn identity(&self) -> StateIdentity {
        self.permit.identity
    }

    fn check_instance(&self, service: &Service) -> Result<(), Response> {
        let activation = &self.permit.activation;
        live(activation.deadline)?;
        let profile = service
            .native_candidate_profile
            .as_ref()
            .ok_or_else(unavailable)?;
        profile.check_environment(service)?;
        let root = service.native_root.as_ref().ok_or_else(unavailable)?;
        if service.recovery_required
            || service.record_root.is_some()
            || service.data_dir != activation.data_dir
            || service.seal.as_ref() != Some(&activation.seal)
            || service.unseal_nonce != *activation.nonce
            || service
                .barrier_key
                .as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != activation.barrier_digest)
            || root.encode().map_err(|_| unavailable())?.as_slice()
                != self.permit.root_bytes.as_slice()
            || root.identity().map_err(|_| unavailable())? != self.permit.identity
            || service.current_state_identity()? != self.permit.identity
        {
            return Err(unavailable());
        }
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        root_namespace_only(state)?;
        if state.schema != root.state_schema
            || state.cluster_id != root.cluster_id
            || state.replay_epoch != root.replay_epoch
            || state.global_lossless_json_format != root.global_lossless_json_format
            || bounded_owner_fingerprints(state, activation.deadline)? != self.owner_fingerprints
        {
            return Err(unavailable());
        }
        activation.check_seal()
    }

    // Bounded instance/warm-cache verification only. Mandatory audit delivery
    // still requires check_with() and reauthenticated typed roots/metadata plus
    // bounded actual ciphertext locator custody for floor2. Payload AEAD/address
    // verification remains mandatory at the selected point read.
    pub(super) fn check_warm(&self, service: &Service) -> Result<(), Response> {
        self.check_instance(service)?;
        let deadline = self.permit.activation.deadline;
        let durable = service.durable.as_ref().ok_or_else(unavailable)?;
        if durable.recovery_required()
            || durable.generation() != self.permit.generation
            || durable.replay_epoch() != self.permit.replay_epoch
        {
            return Err(unavailable());
        }
        let root = service.native_root.as_ref().ok_or_else(unavailable)?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let key = root.kv1_key().map_err(|_| unavailable())?;
        if state.engines.record_root().as_ref() != Some(&root.kv1)
            || state
                .engines
                .record_address_key()
                .is_none_or(|observed| observed.expose() != key.expose())
        {
            return Err(unavailable());
        }
        live(deadline)?;
        let parent = root.kv2_parent_key().map_err(|_| unavailable())?;
        state
            .engines
            .validate_native_roots(&parent, &root.kv2, &|| {
                deadline.check().map_err(|_| RecordError::Invalid)
            })
            .map_err(|_| unavailable())?;
        live(deadline)?;
        let durable = service.durable.as_ref().ok_or_else(unavailable)?;
        if durable.recovery_required()
            || durable.generation() != self.permit.generation
            || durable.replay_epoch() != self.permit.replay_epoch
        {
            return Err(unavailable());
        }
        self.check_instance(service)
    }

    // There is intentionally no unchecked full-closure check() alternative. The mandatory
    // adapter compares the actual installed native engines and their point-edit
    // graph cache with the freshly authenticated metadata and graph roots.
    pub(super) fn check_with(
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
        let profile = service
            .native_candidate_profile
            .as_ref()
            .ok_or_else(unavailable)?;
        let key = Zeroizing::new(**service.barrier_key.as_ref().ok_or_else(unavailable)?);
        let environment = ActivationEnvironment::capture(
            service,
            profile,
            &key,
            self.permit.activation.deadline,
        )?;
        let loaded = load_from_environment(
            environment,
            service.durable.as_mut().ok_or_else(unavailable)?,
        )?
        .ok_or_else(unavailable)?;
        if loaded.proof.permit.generation != self.permit.generation
            || loaded.proof.permit.identity != self.permit.identity
            || loaded.proof.permit.root_bytes != self.permit.root_bytes
            || loaded.proof.permit.cursor_bytes != self.permit.cursor_bytes
            || loaded.proof.permit.source_bytes != self.permit.source_bytes
            || loaded.proof.owner_fingerprints != self.owner_fingerprints
        {
            return Err(unavailable());
        }
        live(self.permit.activation.deadline)?;
        check_installed(
            service.state.as_ref().ok_or_else(unavailable)?,
            &loaded.metadata,
            &loaded.native,
            &loaded.root,
            self.permit.activation.deadline,
        )?;
        self.permit
            .check(service.durable.as_mut().ok_or_else(unavailable)?)?;
        self.check_instance(service)
    }
}

pub(super) fn load_cold_root(
    service: &Service,
    profile: &NativeCandidateProfile,
    durable: &mut DurableService<AeadBarrier>,
    key: &[u8; 32],
    deadline: OriginalDeadline,
) -> Result<Option<ColdNativeRead>, Response> {
    let environment = ActivationEnvironment::capture(service, profile, key, deadline)?;
    load_from_environment(environment, durable)
}

fn load_from_environment(
    activation: ActivationEnvironment,
    durable: &mut DurableService<AeadBarrier>,
) -> Result<Option<ColdNativeRead>, Response> {
    load_from_environment_checked(activation, durable, true, &mut || Ok(()))
}

fn load_from_environment_checked(
    activation: ActivationEnvironment,
    durable: &mut DurableService<AeadBarrier>,
    full_payloads: bool,
    original_gate: &mut impl FnMut() -> Result<(), Response>,
) -> Result<Option<ColdNativeRead>, Response> {
    original_gate()?;
    live(activation.deadline)?;
    durable.verify_live_ownership().map_err(|_| unavailable())?;
    live(activation.deadline)?;
    let generation = durable.generation();
    let replay_epoch = durable.replay_epoch();
    original_gate()?;
    let root_bytes = durable
        .get("system", "state")
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    live(activation.deadline)?;
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        storage_format: Option<String>,
    }
    let probe: Probe = serde_json::from_slice(root_bytes.expose()).map_err(|_| unavailable())?;
    live(activation.deadline)?;
    if probe.storage_format.as_deref() != Some(crate::state_record_root_v6::STORAGE_FORMAT) {
        // The ordinary loader remains responsible for every other root format.
        return Ok(None);
    }
    let root = RecordStateRootV6::decode(root_bytes.expose()).map_err(|_| unavailable())?;
    live(activation.deadline)?;
    if root.replay_epoch != replay_epoch
        || root
            .kv2
            .iter()
            .any(|graph| !graph.scope.namespace.is_empty())
    {
        return Err(unavailable());
    }
    original_gate()?;
    let cursor_bytes = durable
        .get("system", ACTIVE_CURSOR_RESOURCE)
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    live(activation.deadline)?;
    original_gate()?;
    let source_bytes = durable
        .get("system", ACTIVE_SOURCE_ROOT_RESOURCE)
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    live(activation.deadline)?;
    let source = RecordStateRoot::decode(source_bytes.expose()).map_err(|_| unavailable())?;
    live(activation.deadline)?;
    let cursor = NativeActiveCursor::decode(cursor_bytes.expose())?;
    live(activation.deadline)?;
    cursor.validate(&source, &root, generation)?;
    live(activation.deadline)?;
    let identity = root.identity().map_err(|_| unavailable())?;
    let permit = ReaderPermit {
        activation,
        generation,
        replay_epoch,
        identity,
        root_bytes: Zeroizing::new(root_bytes.expose().to_vec()),
        cursor_bytes: Zeroizing::new(cursor_bytes.expose().to_vec()),
        source_bytes: Zeroizing::new(source_bytes.expose().to_vec()),
    };
    original_gate()?;
    permit.check(durable)?;
    if full_payloads && root.reader_floor.native_kv2_format == 1 {
        let reader = CheckedSource {
            durable,
            deadline: permit.activation.deadline,
        };
        // Actual cold activation authenticates the retained V5 owner/record
        // closure once. Hot checks bind the same retained root bytes and active
        // publication to the already installed original instance.
        let source_state = Service::materialize_record_state(&source, &reader)?;
        live(permit.activation.deadline)?;
        root_namespace_only(&source_state)?;
        live(permit.activation.deadline)?;
    }
    let StateIdentity::RecordsV6(digest) = identity else {
        return Err(unavailable());
    };
    let context = ReadContext {
        expected_identity: ReadIdentity::RecordsV6(digest),
        cluster_id: &source.cluster_id,
        replay_epoch,
        minimum_state_schema: source.state_schema,
        maximum_state_schema: root.state_schema,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    };
    let source = super::native_blob_source::NativeSource::new_checked(
        durable, permit.activation.deadline,
        || original_gate().map_err(|_| ServiceError::BarrierFailure),
    ).map_err(|_| unavailable())?
        .with_observations(Arc::clone(&permit.activation.observations));
    let (metadata, native) = if full_payloads && root.reader_floor.native_kv2_format == 1 {
        v6_records::materialize_for_service(&root, context, &source)
    } else {
        v6_records::materialize_metadata_for_service(&root, context, &source)
    }.map_err(|_| unavailable())?;
    if full_payloads && root.reader_floor.native_kv2_format == 2 {
        for (scope, view) in &native {
            view.visit_paged_payload_references(
                |reference| source.pin_payload_location(&ObjectDomain::Kv2(scope.clone()), reference),
                &|| permit.activation.deadline.check().map_err(|_| RecordError::Invalid),
            ).map_err(|_| unavailable())?;
        }
    }
    drop(source);
    live(permit.activation.deadline)?;
    root_namespace_only(&metadata)?;
    live(permit.activation.deadline)?;
    let owner_fingerprints = bounded_owner_fingerprints(&metadata, permit.activation.deadline)?;
    live(permit.activation.deadline)?;
    original_gate()?;
    permit.check(durable)?;
    Ok(Some(ColdNativeRead {
        metadata,
        native,
        root,
        proof: NativeProof {
            permit,
            owner_fingerprints,
        },
    }))
}

impl Service {
    pub(super) fn capture_native_request_proof(
        &mut self,
        original_gate: &mut impl FnMut() -> Result<(), Response>,
    ) -> Result<Option<NativeProof>, Response> {
        if self.native_root.is_none() {
            return Ok(None);
        }
        original_gate()?;
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let key = Zeroizing::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?);
        let mut durable = self.durable.take().ok_or_else(unavailable)?;
        let result = (|| {
            let profile = self.native_candidate_profile.as_ref().ok_or_else(unavailable)?;
            let environment = ActivationEnvironment::capture(self, profile, &key, deadline)?;
            let loaded = load_from_environment_checked(environment, &mut durable, false, original_gate)?
                .ok_or_else(unavailable)?;
            Self::check_native_installed(
                self.state.as_ref().ok_or_else(unavailable)?, &loaded.metadata,
                &loaded.native, &loaded.root, deadline,
            )?;
            Ok(Some(loaded.proof))
        })();
        self.durable = Some(durable);
        original_gate()?;
        live(deadline)?;
        result
    }

    pub(super) fn capture_native_unseal_proof(&mut self) -> Result<Option<NativeProof>, Response> {
        if self.native_root.is_none() {
            return Ok(None);
        }
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        live(deadline)?;
        let key = Zeroizing::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?);
        let mut durable = self.durable.take().ok_or_else(unavailable)?;
        let result = (|| {
            let profile = self
                .native_candidate_profile
                .as_ref()
                .ok_or_else(unavailable)?;
            let loaded = load_cold_root(self, profile, &mut durable, &key, deadline)?
                .ok_or_else(unavailable)?;
            Self::check_native_installed(
                self.state.as_ref().ok_or_else(unavailable)?,
                &loaded.metadata,
                &loaded.native,
                &loaded.root,
                deadline,
            )?;
            Ok(Some(loaded.proof))
        })();
        self.durable = Some(durable);
        live(deadline)?;
        result
    }

    pub(super) fn check_native_installed(
        installed: &State,
        metadata: &State,
        native: &BTreeMap<MountScope, NativeReadView>,
        root: &RecordStateRootV6,
        deadline: OriginalDeadline,
    ) -> Result<(), Response> {
        live(deadline)?;
        root_namespace_only(installed)?;
        if installed.schema != root.state_schema
            || installed.global_lossless_json_format != root.global_lossless_json_format
            || installed.cluster_id != root.cluster_id
            || installed.replay_epoch != root.replay_epoch
            || bounded_owner_fingerprints(installed, deadline)?
                != bounded_owner_fingerprints(metadata, deadline)?
            || native.len() != root.kv2.len()
        {
            return Err(unavailable());
        }
        let key = root.kv1_key().map_err(|_| unavailable())?;
        if installed.engines.record_root().as_ref() != Some(&root.kv1)
            || installed
                .engines
                .record_address_key()
                .is_none_or(|observed| observed.expose() != key.expose())
        {
            return Err(unavailable());
        }
        let parent = root.kv2_parent_key().map_err(|_| unavailable())?;
        let check = || deadline.check().map_err(|_| RecordError::Invalid);
        installed
            .engines
            .validate_native_roots(&parent, &root.kv2, &check)
            .map_err(|_| unavailable())?;
        let (opaque, graphs) = if root.reader_floor.native_kv2_format == 2 {
            installed.engines.project_v6_native_paged(&parent, &check, |_, _| check())
        } else {
            installed.engines.project_v6_native(&parent, &check, |_, _| check())
        }.map_err(|_| unavailable())?;
        if crate::secret_serde::to_vec(&graphs, crate::state_record_root::MAX_ROOT_BYTES)
            .map_err(|_| unavailable())?
            .as_slice()
            != crate::secret_serde::to_vec(&root.kv2, crate::state_record_root::MAX_ROOT_BYTES)
                .map_err(|_| unavailable())?
                .as_slice()
            || owner_store::serialize_owner(&opaque)
                .map_err(|_| unavailable())?
                .as_slice()
                != owner_store::serialize_owner(&metadata.engines)
                    .map_err(|_| unavailable())?
                    .as_slice()
        {
            return Err(unavailable());
        }
        live(deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_record_root::{OWNER_NAMES, OpaqueOwnerRef};
    use crate::state_record_root_v6::{AddressMaterial, OwnerDomain, ReaderFloor, RoleOwner};
    use crate::state_records::{AddressKey, Kv1Root, StagedObject};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    // Small canonical root fixtures exercise cursor provenance only. There is
    // no durable publication, Service grant, native writer or closure receipt.
    fn roots() -> TestResult<(RecordStateRoot, RecordStateRootV6)> {
        let key = AddressKey::from_bytes([73; 32]);
        let mut owners = Vec::new();
        for name in OWNER_NAMES {
            let object = StagedObject::owner_chunk(&key, b"{}")?;
            owners.push(OpaqueOwnerRef {
                name: name.into(),
                total_bytes: 2,
                chunks: vec![object.reference().clone()],
                digest: crate::state_record_root::digest_owner(&key, name, b"{}")
                    .map_err(|_| "source digest")?,
            });
        }
        let source = RecordStateRoot::new(
            65,
            "native-cursor-fixture".into(),
            0,
            owners.try_into().map_err(|_| "owner count")?,
            Kv1Root::default(),
            [73; 32],
        )
        .map_err(|_| "source root")?;
        let mut root = RecordStateRootV6 {
            storage_format: crate::state_record_root_v6::STORAGE_FORMAT.into(),
            state_schema: 65,
            reader_floor: ReaderFloor {
                record_format: 6,
                minimum_state_schema: 65,
                native_kv2_format: 1,
            },
            global_lossless_json_format: None,
            cluster_id: source.cluster_id.clone(),
            replay_epoch: 0,
            owners: OwnerDomain::ALL.map(|domain| RoleOwner {
                domain,
                owner: source.owners[domain as usize].clone(),
            }),
            kv1: Kv1Root::default(),
            kv2: Vec::new(),
            object_address_key: AddressMaterial([74; 32]),
        };
        for (index, domain) in OwnerDomain::ALL.into_iter().enumerate() {
            let object = StagedObject::owner_chunk(
                root.owner_key(domain).map_err(|_| "owner key")?.as_ref(),
                b"{}",
            )?;
            root.owners[index].owner = OpaqueOwnerRef {
                name: domain.name().into(),
                total_bytes: 2,
                chunks: vec![object.reference().clone()],
                digest: root
                    .owner_digest(domain, b"{}")
                    .map_err(|_| "owner digest")?,
            };
        }
        root.validate().map_err(|_| "native root")?;
        Ok((source, root))
    }

    #[test]
    fn active_cursor_rejects_side_format_and_unbound_source_or_publication() -> TestResult {
        let (source, root) = roots()?;
        let cursor =
            NativeActiveCursor::for_migration(&source, 4, &root, 9).map_err(|_| "valid cursor")?;
        let bytes = cursor.encode().map_err(|_| "encoding")?;
        NativeActiveCursor::decode(&bytes)
            .map_err(|_| "canonical cursor")?
            .validate(&source, &root, 9)
            .map_err(|_| "frontier")?;
        for (field, replacement) in [
            (
                "format",
                json!("heptabao-native-v6-side-publication-cursor-v1"),
            ),
            ("cluster_id", json!("different-cluster")),
            ("source_generation", json!(0)),
            ("source_generation", json!(9)),
            ("publication_generation", json!(10)),
            ("replay_epoch", json!(1)),
            ("state_schema", json!(66)),
            ("reader_record_format", json!(5)),
            ("reader_minimum_state_schema", json!(66)),
            ("reader_native_kv2_format", json!(2)),
            ("source_root_digest", json!(vec![0_u8; 32])),
            ("root_digest", json!(vec![0_u8; 32])),
        ] {
            let mut wire = serde_json::to_value(&cursor)?;
            wire[field] = replacement;
            let changed: NativeActiveCursor = serde_json::from_value(wire)?;
            assert!(changed.validate(&source, &root, 9).is_err(), "{field}");
        }
        let mut noncanonical = bytes.to_vec();
        noncanonical.push(b'\n');
        assert!(NativeActiveCursor::decode(&noncanonical).is_err());
        Ok(())
    }

    #[test]
    fn active_cursor_advance_cannot_reuse_generation_or_lower_reader_frontier() -> TestResult {
        let (source, root) = roots()?;
        let first = NativeActiveCursor::for_migration(&source, 4, &root, 9)
            .map_err(|_| "initial cursor")?;
        assert!(first.advance(&root, 9).is_err());
        let mut raised = root.clone();
        raised.state_schema = 66;
        raised.reader_floor.minimum_state_schema = 66;
        raised.replay_epoch = 1;
        let next = first.advance(&raised, 10).map_err(|_| "raised cursor")?;
        next.validate(&source, &raised, 10)
            .map_err(|_| "raised frontier")?;
        assert!(next.advance(&root, 11).is_err());
        let mut lowered_floor = raised.clone();
        lowered_floor.reader_floor.minimum_state_schema = 65;
        assert!(next.advance(&lowered_floor, 11).is_err());
        assert_eq!(next.source_generation, first.source_generation);
        assert_eq!(next.source_root_digest, first.source_root_digest);
        Ok(())
    }

    #[test]
    fn candidate_profile_is_sealed_configuration_and_stays_bound_to_original_directory()
    -> TestResult {
        let root = super::super::tests::Root::new();
        let mut service = root.service()?;
        let profile = NativeCandidateProfile::capture(&service).map_err(|_| "profile")?;
        assert!(service.state.is_none());
        assert!(service.durable.is_none());
        assert!(service.barrier_key.is_none());
        assert!(service.native_root.is_none());
        assert!(service.native_candidate_profile.is_none());
        let original = service.data_dir.clone();
        service.data_dir = original.join("different-candidate");
        assert!(profile.check_environment(&service).is_err());
        service.data_dir = original;
        super::super::tests::bootstrap(&mut service)?;
        assert!(NativeCandidateProfile::capture(&service).is_err());
        Ok(())
    }

    #[test]
    fn cold_reader_rejects_expired_original_context_before_any_durable_effect() -> TestResult {
        let root = super::super::tests::Root::new();
        let mut service = root.service()?;
        let profile = NativeCandidateProfile::capture(&service).map_err(|_| "profile")?;
        super::super::tests::bootstrap(&mut service)?;
        let key = Zeroizing::new(**service.barrier_key.as_ref().ok_or("key")?);
        let mut durable = service.durable.take().ok_or("durable")?;
        let before = durable.generation();
        let original_scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(5),
        );
        let deadline = OriginalDeadline::capture().map_err(|_| "original deadline")?;
        drop(original_scope);
        let _expired = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() - Duration::from_secs(1),
        );
        assert!(load_cold_root(&service, &profile, &mut durable, &key, deadline).is_err());
        assert_eq!(durable.generation(), before);
        service.durable = Some(durable);
        Ok(())
    }
}
