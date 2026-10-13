//! Authenticated V6 read kernel. No mutable Service installation/publication.
use super::*;
use crate::engines::kv2_native_records::NativeReadView;
use crate::state_record_root_v6::{ENGINE_FORMAT, MountScope, ObjectDomain, RecordStateRootV6};
use crate::state_records::{Kv1Index, ObjectId, ObjectRef, RecordError, RecordReader};
use crate::v6_read_validation::{ObjectSource, ReadContext, ReadError, ReadReceipt};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineMetadata {
    format: String,
    opaque: EngineState,
    kv2_scopes: Vec<MountScope>,
}

fn preflight_metadata(bytes: &[u8]) -> Result<(), ReadError> {
    #[derive(Deserialize)]
    struct Raw<'a> {
        #[serde(borrow)]
        opaque: &'a serde_json::value::RawValue,
        #[serde(borrow)]
        kv2_scopes: &'a serde_json::value::RawValue,
    }
    #[derive(Deserialize)]
    struct RawScope<'a> {
        #[serde(borrow)]
        namespace: &'a serde_json::value::RawValue,
        #[serde(borrow)]
        mount: &'a serde_json::value::RawValue,
        incarnation: u64,
    }
    struct Scopes;
    impl<'de> serde::de::Visitor<'de> for Scopes {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded V6 mount scopes")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
            let mut count = 0;
            while let Some(raw) = sequence.next_element::<RawScope<'de>>()? {
                count += 1;
                if count > crate::state_record_root_v6::MAX_KV2_MOUNTS
                    || raw.incarnation == 0
                    || raw.namespace.get().len() > 6 * 1024 + 2
                    || raw.mount.get().len() > 6 * 1024 + 2
                {
                    return Err(serde::de::Error::custom("V6 scope bound exceeded"));
                }
            }
            Ok(())
        }
    }
    let raw: Raw<'_> = serde_json::from_slice(bytes).map_err(|_| ReadError::State)?;
    let mut decoder = serde_json::Deserializer::from_str(raw.kv2_scopes.get());
    serde::Deserializer::deserialize_seq(&mut decoder, Scopes).map_err(|_| ReadError::State)?;
    crate::engines::kv2_native_records::preflight_v6_kv2_metadata(raw.opaque.get().as_bytes())?;
    Ok(())
}

pub(crate) fn validate_frontier(
    root: &RecordStateRootV6,
    context: ReadContext<'_>,
) -> Result<(), ReadError> {
    root.validate()?;
    if context.reader_format != crate::state_record_root_v6::READER_FORMAT
        || root.state_schema < context.minimum_state_schema
        || root.state_schema > context.maximum_state_schema
        || root.reader_floor.minimum_state_schema > context.maximum_state_schema
        || !supported_reader_schema(root.state_schema)
        || !supported_reader_schema(root.reader_floor.minimum_state_schema)
    {
        return Err(ReadError::ReaderFloor);
    }
    if root.cluster_id != context.cluster_id
        || root.replay_epoch != context.replay_epoch
        || root.identity()? != context.expected_identity.typed()
    {
        return Err(ReadError::Authentication);
    }
    Ok(())
}

#[derive(Default)]
struct Usage {
    seen: BTreeSet<(ObjectDomain, ObjectId)>,
    owners: usize,
    kv1: usize,
    kv2: usize,
}
impl Usage {
    fn account(
        &mut self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
        bytes: usize,
    ) -> Result<(), RecordError> {
        if self.seen.contains(&(domain.clone(), reference.id)) {
            return Ok(());
        }
        let (total, limit) = match domain {
            ObjectDomain::Owner(_) => (&mut self.owners, MAX_STATE_BYTES + 16 * 1024),
            ObjectDomain::Kv1 => (&mut self.kv1, crate::state_records::MAX_GRAPH_BYTES),
            ObjectDomain::Kv2(_) => (&mut self.kv2, crate::state_records::MAX_GRAPH_BYTES),
        };
        *total = total
            .checked_add(bytes)
            .filter(|size| *size <= limit)
            .ok_or(RecordError::TooLarge)?;
        self.seen.insert((domain.clone(), reference.id));
        Ok(())
    }
}
struct DomainReader<'a, S> {
    source: &'a S,
    domain: ObjectDomain,
    usage: &'a RefCell<Usage>,
}
impl<S: ObjectSource> RecordReader for DomainReader<'_, S> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let bytes = self.source.read(&self.domain, reference)?;
        self.usage
            .try_borrow_mut()
            .map_err(|_| RecordError::Corrupt)?
            .account(&self.domain, reference, bytes.len())?;
        Ok(bytes)
    }
}
fn owner_bytes(
    root: &RecordStateRootV6,
    index: usize,
    source: &impl ObjectSource,
    usage: &RefCell<Usage>,
) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let role = &root.owners[index];
    let reader = DomainReader {
        source,
        domain: ObjectDomain::Owner(role.domain),
        usage,
    };
    let key = root.owner_key(role.domain)?;
    let length = usize::try_from(role.owner.total_bytes).map_err(|_| ReadError::TooLarge)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    for reference in &role.owner.chunks {
        let encoded = reader.read_object(reference)?;
        let payload = reference.owner_chunk_payload(&key, &encoded)?;
        if bytes
            .len()
            .checked_add(payload.len())
            .is_none_or(|size| size > length)
        {
            return Err(ReadError::Invalid);
        }
        bytes.extend_from_slice(payload);
    }
    if bytes.len() != length || root.owner_digest(role.domain, &bytes)? != role.owner.digest {
        return Err(ReadError::Authentication);
    }
    Ok(bytes)
}
fn canonical(value: &impl Serialize, bytes: &[u8]) -> Result<(), ReadError> {
    let encoded =
        crate::secret_serde::to_vec(value, MAX_STATE_BYTES).map_err(|_| ReadError::State)?;
    if encoded.as_slice() != bytes {
        return Err(ReadError::Invalid);
    }
    Ok(())
}

// Separate native views are immutable and never installed into a writable
// Backend::Kv2 or a live Service. The protected State remains metadata-only.
struct ReadState {
    protected: State,
    native: BTreeMap<MountScope, NativeReadView>,
    objects: usize,
    bytes: usize,
}
fn materialize(
    root: &RecordStateRootV6,
    context: ReadContext<'_>,
    source: &impl ObjectSource,
) -> Result<ReadState, ReadError> {
    validate_frontier(root, context)?;
    let usage = RefCell::new(Usage::default());
    let owners = (0..5)
        .map(|index| owner_bytes(root, index, source, &usage))
        .collect::<Result<Vec<_>, _>>()?;
    AuthState::predecode_raw_reply_owner(&owners[1], root.state_schema)
        .map_err(|_| ReadError::State)?;
    preflight_metadata(&owners[2])?;
    let metadata: EngineMetadata =
        serde_json::from_slice(&owners[2]).map_err(|_| ReadError::State)?;
    canonical(&metadata, &owners[2])?;
    let scopes: Vec<_> = root.kv2.iter().map(|graph| graph.scope.clone()).collect();
    if metadata.format != ENGINE_FORMAT || metadata.kv2_scopes != scopes {
        return Err(ReadError::Invalid);
    }
    metadata
        .opaque
        .validate_v6_kv2_placeholders(&scopes)
        .map_err(|_| ReadError::State)?;
    let mut state = State {
        schema: root.state_schema,
        global_lossless_json_format: root.global_lossless_json_format,
        cluster_id: root.cluster_id.clone(),
        replay_epoch: root.replay_epoch,
        namespace_protected: None,
        namespace_leases: namespace_runtime::Leases::default(),
        namespaces: serde_json::from_slice(&owners[0]).map_err(|_| ReadError::State)?,
        auth: serde_json::from_slice(&owners[1]).map_err(|_| ReadError::State)?,
        engines: metadata.opaque.into(),
        database: serde_json::from_slice(&owners[3]).map_err(|_| ReadError::State)?,
        raft_admin: serde_json::from_slice(&owners[4]).map_err(|_| ReadError::State)?,
    };
    canonical(&state.namespaces, &owners[0])?;
    canonical(&state.auth, &owners[1])?;
    canonical(&state.database, &owners[3])?;
    canonical(&state.raft_admin, &owners[4])?;
    if state
        .engines
        .v6_namespace_paths()
        .any(|namespace| !namespace.is_empty() && !state.namespaces.contains(namespace))
    {
        return Err(ReadError::State);
    }
    let reader = DomainReader {
        source,
        domain: ObjectDomain::Kv1,
        usage: &usage,
    };
    let key = root.kv1_key()?;
    let index = Kv1Index::open(Arc::clone(&key), root.kv1.clone(), &reader)?;
    state
        .engines
        .install_record_index(key, index)
        .map_err(|_| ReadError::State)?;
    state.validate_format().map_err(|_| ReadError::State)?;
    let parent = root.kv2_parent_key()?;
    let mut native = BTreeMap::new();
    for graph in &root.kv2 {
        let reader = DomainReader {
            source,
            domain: ObjectDomain::Kv2(graph.scope.clone()),
            usage: &usage,
        };
        let view =
            NativeReadView::open(&parent, graph.scope.borrowed(), graph.root.clone(), &reader)?;
        if view.has_lossless_state()
            && (!state.engines.has_kv2_lossless_state()
                || root.state_schema < KV2_LOSSLESS_STATE_SCHEMA)
        {
            return Err(ReadError::ReaderFloor);
        }
        native.insert(graph.scope.clone(), view);
    }
    let usage = usage.into_inner();
    if source
        .object_count()
        .is_some_and(|count| count != usage.seen.len())
    {
        return Err(ReadError::Invalid);
    }
    Ok(ReadState {
        protected: state,
        native,
        objects: usage.seen.len(),
        bytes: usage.owners + usage.kv1 + usage.kv2,
    })
}

pub(crate) fn inspect(
    root: &RecordStateRootV6,
    context: ReadContext<'_>,
    source: &impl ObjectSource,
) -> Result<ReadReceipt, ReadError> {
    let state = materialize(root, context, source)?;
    let mut paths = 0;
    let mut versions = 0;
    let mut payloads = 0;
    for view in state.native.values() {
        // Exercise the actual logical reader without exposing secret bodies.
        let response = view
            .read(
                "GET",
                "config",
                &json!({}),
                crate::auth::Timestamp::whole(0).map_err(|_| ReadError::State)?,
            )
            .map_err(|_| ReadError::State)?;
        if response.status != 200 {
            return Err(ReadError::State);
        }
        let (p, v, d) = view.counts();
        paths += p;
        versions += v;
        payloads += d;
    }
    if state.protected.cluster_id != root.cluster_id
        || state.protected.replay_epoch != root.replay_epoch
    {
        return Err(ReadError::Authentication);
    }
    Ok(ReadReceipt {
        storage_format: crate::state_record_root_v6::STORAGE_FORMAT,
        graph_roots: root.references().count(),
        kv2_mounts: state.native.len(),
        paths,
        retained_versions: versions,
        payload_records: payloads,
        objects_read: state.objects,
        encoded_bytes_read: state.bytes,
        service_reader_admitted: false,
        namespace_custody_qualified: false,
        membership_reader_fence_qualified: false,
        production_writer_admitted: false,
        migration_admitted: false,
        replacement_authority: false,
    })
}

#[cfg(test)]
#[path = "service_records_v6_tests.rs"]
mod tests;

/// Actual Service source projection. Publication and reader admission remain
/// closed until the guarded publisher and restart path consume this plan.
pub(super) struct NativeRootMigrationPlan {
    pub root: RecordStateRootV6,
    pub bytes: Zeroizing<Vec<u8>>,
    pub candidate: State,
    pub objects: BTreeMap<(ObjectDomain, ObjectId), Arc<crate::state_records::StagedObject>>,
    pub source_generation: u64,
    pub conditions: Vec<heptabao_durable_service::PublicationCondition>,
}

impl Service {
    pub(super) fn prepare_native_root_migration(
        &mut self,
        check: &impl Fn() -> Result<(), RecordError>,
    ) -> Result<NativeRootMigrationPlan, Response> {
        let rejected = || Response::error(503, "native migration source or custody rejected");
        if self.ha.is_some() || self.recovery_required {
            return Err(rejected());
        }
        check().map_err(|_| rejected())?;
        let mut candidate = self.state.as_ref().ok_or_else(rejected)?.clone();
        if candidate.namespace_protected.is_some()
            || candidate
                .engines
                .v6_namespace_paths()
                .any(|path| !path.is_empty())
        {
            return Err(Response::error(
                503,
                "native migration requires independent namespace custody",
            ));
        }
        candidate.validate_format()?;
        let old = self.record_root.as_ref().ok_or_else(rejected)?.clone();
        if old.state_schema != candidate.schema
            || old.cluster_id != candidate.cluster_id
            || old.replay_epoch != candidate.replay_epoch
            || candidate.engines.record_root().as_ref() != Some(&old.kv1)
            || candidate
                .engines
                .record_address_key()
                .is_none_or(|key| key.expose() != old.address_key().expose())
        {
            return Err(rejected());
        }
        // Authenticate all five actual source owners, not a caller's detached
        // replacement or merely the KV2 graph.
        let source_owners = [
            owner_store::serialize_owner(&candidate.namespaces),
            owner_store::serialize_owner(&candidate.auth),
            owner_store::serialize_owner(&candidate.engines),
            owner_store::serialize_owner(&candidate.database),
            owner_store::serialize_owner(&candidate.raft_admin),
        ];
        for (index, bytes) in source_owners.into_iter().enumerate() {
            let bytes = bytes.map_err(|_| rejected())?;
            let reference = &old.owners[index];
            let digest =
                crate::state_record_root::digest_owner(&old.address_key(), &reference.name, &bytes)
                    .map_err(|_| rejected())?;
            if digest != reference.digest || bytes.len() as u64 != reference.total_bytes {
                return Err(rejected());
            }
            check().map_err(|_| rejected())?;
        }
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        let source = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        if old.encode().map_err(|_| rejected())?.as_slice() != source.expose()
            || durable
                .get("system", "state-native-v6/publication-cursor")
                .map_err(|_| rejected())?
                .is_some()
        {
            return Err(rejected());
        }
        let source_generation = durable.generation();
        if source_generation == 0 {
            return Err(rejected());
        }
        use crate::state_record_root::OpaqueOwnerRef;
        use crate::state_record_root_v6::{AddressMaterial, OwnerDomain, ReaderFloor, RoleOwner};
        let mut root = RecordStateRootV6 {
            storage_format: crate::state_record_root_v6::STORAGE_FORMAT.into(),
            state_schema: candidate.schema,
            reader_floor: ReaderFloor {
                record_format: 6,
                minimum_state_schema: candidate.schema,
                native_kv2_format: 1,
            },
            global_lossless_json_format: candidate.global_lossless_json_format,
            cluster_id: candidate.cluster_id.clone(),
            replay_epoch: candidate.replay_epoch,
            owners: OwnerDomain::ALL.map(|domain| RoleOwner {
                domain,
                owner: OpaqueOwnerRef {
                    name: domain.name().into(),
                    total_bytes: 0,
                    chunks: Vec::new(),
                    digest: [0; 32],
                },
            }),
            kv1: crate::state_records::Kv1Root::default(),
            kv2: Vec::new(),
            object_address_key: AddressMaterial(crypto::random::<32>().map_err(|_| rejected())?),
        };
        let recorded = candidate
            .engines
            .rekey_root_records_checked(root.kv1_key().map_err(|_| rejected())?, check)
            .map_err(|_| rejected())?;
        root.kv1 = recorded.record_root().ok_or_else(rejected)?;
        let mut objects = BTreeMap::new();
        fn stage(
            objects: &mut BTreeMap<
                (ObjectDomain, ObjectId),
                Arc<crate::state_records::StagedObject>,
            >,
            domain: ObjectDomain,
            object: &Arc<crate::state_records::StagedObject>,
        ) -> Result<(), RecordError> {
            let key = (domain, object.reference().id);
            if let Some(prior) = objects.get(&key) {
                if prior.reference() != object.reference() || prior.bytes() != object.bytes() {
                    return Err(RecordError::Corrupt);
                }
            } else {
                objects.insert(key, Arc::clone(object));
            }
            Ok(())
        }
        recorded
            .visit_record_objects(|object| {
                check()?;
                stage(&mut objects, ObjectDomain::Kv1, object)?;
                check()
            })
            .map_err(|_| rejected())?;
        let parent = root.kv2_parent_key().map_err(|_| rejected())?;
        let (opaque, graphs) = recorded
            .project_v6_native(&parent, check, |scope, object| {
                stage(&mut objects, ObjectDomain::Kv2(scope.clone()), object)
            })
            .map_err(|_| rejected())?;
        root.kv2 = graphs;
        let metadata = EngineMetadata {
            format: ENGINE_FORMAT.into(),
            opaque,
            kv2_scopes: root.kv2.iter().map(|graph| graph.scope.clone()).collect(),
        };
        candidate.engines = recorded.into();
        let owners = [
            owner_store::serialize_owner(&candidate.namespaces),
            owner_store::serialize_owner(&candidate.auth),
            owner_store::serialize_owner(&metadata),
            owner_store::serialize_owner(&candidate.database),
            owner_store::serialize_owner(&candidate.raft_admin),
        ];
        for (index, bytes) in owners.into_iter().enumerate() {
            check().map_err(|_| rejected())?;
            let bytes = bytes.map_err(|_| rejected())?;
            let domain = OwnerDomain::ALL[index];
            let key = root.owner_key(domain).map_err(|_| rejected())?;
            let mut chunks = Vec::new();
            for chunk in bytes.chunks(crate::state_record_root::OWNER_CHUNK_BYTES) {
                check().map_err(|_| rejected())?;
                let object = crate::state_records::StagedObject::owner_chunk(&key, chunk)
                    .map_err(|_| rejected())?;
                chunks.push(object.reference().clone());
                stage(&mut objects, ObjectDomain::Owner(domain), &object)
                    .map_err(|_| rejected())?;
                check().map_err(|_| rejected())?;
            }
            root.owners[index].owner = OpaqueOwnerRef {
                name: domain.name().into(),
                total_bytes: bytes.len() as u64,
                chunks,
                digest: root.owner_digest(domain, &bytes).map_err(|_| rejected())?,
            };
        }
        let bytes = root.encode().map_err(|_| rejected())?;
        check().map_err(|_| rejected())?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        if durable.generation() != source_generation
            || durable
                .get("system", "state")
                .map_err(|_| rejected())?
                .is_none_or(|current| current.expose() != source.expose())
        {
            return Err(rejected());
        }
        Ok(NativeRootMigrationPlan {
            root,
            bytes,
            candidate,
            objects,
            source_generation,
            conditions: vec![
                heptabao_durable_service::PublicationCondition {
                    resource: "state".into(),
                    expected: Some(source),
                },
                heptabao_durable_service::PublicationCondition {
                    resource: "state-native-v6/publication-cursor".into(),
                    expected: None,
                },
            ],
        })
    }
}
