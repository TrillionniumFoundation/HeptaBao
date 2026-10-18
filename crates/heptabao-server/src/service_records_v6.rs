//! Authenticated V6 kernel with guarded root-only fixture admission and side snapshots.
//! Default Service, namespace, HA and production migration admission remain closed.
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
    external: usize,
    paged_scopes: BTreeSet<MountScope>,
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
        let external = matches!(domain, ObjectDomain::Kv2(scope) if self.paged_scopes.contains(scope))
            && reference.kind == crate::state_records::ObjectKind::Block;
        let (total, limit) = if external {
            (
                &mut self.external,
                crate::engines::kv2_native_records::MAX_PAGED_LOGICAL_BYTES as usize
                    + 25 * (crate::state_record_root_v6::MAX_KV2_RECORDS as usize
                        + (crate::engines::kv2_native_records::MAX_PAGED_LOGICAL_BYTES as usize)
                            .div_ceil(crate::state_records::BLOCK_BYTES)),
            )
        } else {
            match domain {
                ObjectDomain::Owner(_) => (&mut self.owners, MAX_STATE_BYTES + 16 * 1024),
                ObjectDomain::Kv1 => (&mut self.kv1, crate::state_records::MAX_GRAPH_BYTES),
                ObjectDomain::Kv2(_) => (&mut self.kv2, crate::state_records::MAX_GRAPH_BYTES),
            }
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
    materialize_mode(root, context, source, true)
}

// Metadata-only opening is private to an already admitted live instance. It
// authenticates every typed metadata object but does not claim full payload
// closure. The caller must verify incremental descriptors against its actual
// previously admitted view before this state can be installed.
fn materialize_mode(
    root: &RecordStateRootV6,
    context: ReadContext<'_>,
    source: &impl ObjectSource,
    full_payloads: bool,
) -> Result<ReadState, ReadError> {
    validate_frontier(root, context)?;
    let usage = RefCell::new(Usage {
        paged_scopes: root
            .kv2
            .iter()
            .filter(|graph| {
                graph.graph_format == crate::engines::kv2_native_records::PAGED_NATIVE_FORMAT
            })
            .map(|graph| graph.scope.clone())
            .collect(),
        ..Usage::default()
    });
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
        let view = if graph.graph_format == crate::engines::kv2_native_records::PAGED_NATIVE_FORMAT
        {
            let view = NativeReadView::open_paged(
                &parent,
                graph.scope.borrowed(),
                graph.root.clone(),
                &reader,
            )?;
            if full_payloads {
                view.verify_paged_payloads(&reader, &|| Ok(()))?;
            }
            if view.logical_payload_bytes()? != graph.logical_payload_bytes {
                return Err(ReadError::Authentication);
            }
            view
        } else {
            NativeReadView::open(&parent, graph.scope.borrowed(), graph.root.clone(), &reader)?
        };
        if view.has_lossless_state()
            && (!state.engines.has_kv2_lossless_state()
                || root.state_schema < KV2_LOSSLESS_STATE_SCHEMA)
        {
            return Err(ReadError::ReaderFloor);
        }
        native.insert(graph.scope.clone(), view);
    }
    let usage = usage.into_inner();
    if full_payloads
        && source
            .object_count()
            .is_some_and(|count| count != usage.seen.len())
    {
        return Err(ReadError::Invalid);
    }
    Ok(ReadState {
        protected: state,
        native,
        objects: usage.seen.len(),
        bytes: usage.owners + usage.kv1 + usage.kv2 + usage.external,
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
#[cfg(any(test, feature = "fixture-native-v6-service"))]
pub(super) struct NativeRootMigrationPlan {
    pub root: RecordStateRootV6,
    pub bytes: Zeroizing<Vec<u8>>,
    pub candidate: State,
    pub objects: BTreeMap<(ObjectDomain, ObjectId), Arc<crate::state_records::StagedObject>>,
    pub source_generation: u64,
    pub deadline: crate::v6_native_custody::OriginalDeadline,
    pub conditions: Vec<heptabao_durable_service::PublicationCondition>,
}

// Fail-closed private prepublication reader. It consumes only this plan's
// immutable staged objects and never loads loose files or changes Service.
#[cfg(any(test, feature = "fixture-native-v6-service"))]
struct NativeMigrationObjects<'a> {
    objects: &'a BTreeMap<(ObjectDomain, ObjectId), Arc<crate::state_records::StagedObject>>,
    deadline: crate::v6_native_custody::OriginalDeadline,
    fallback: Option<&'a dyn ObjectSource>,
}
#[cfg(any(test, feature = "fixture-native-v6-service"))]
impl ObjectSource for NativeMigrationObjects<'_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        let Some(object) = self.objects.get(&(domain.clone(), reference.id)) else {
            return self
                .fallback
                .ok_or(RecordError::Missing)?
                .read(domain, reference);
        };
        if object.reference() != reference {
            return Err(RecordError::Corrupt);
        }
        let bytes = Zeroizing::new(object.bytes().to_vec());
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        Ok(bytes)
    }
    fn object_count(&self) -> Option<usize> {
        if self.fallback.is_some() {
            None
        } else {
            Some(self.objects.len())
        }
    }
}

// The root being syntactically valid cannot prove its entire closure is
// readable under the signed identity, per-domain keys, source owner schema,
// or the native KV2 reader. Reopen everything *before* a writer can receive
// the immutable migration candidate, including on the initial V5->V6 move.
#[cfg(any(test, feature = "fixture-native-v6-service"))]
fn validate_native_root_migration_plan(
    plan: &NativeRootMigrationPlan,
    fallback: Option<&dyn ObjectSource>,
) -> Result<(), ReadError> {
    plan.deadline.check().map_err(|_| ReadError::Invalid)?;
    if plan.root.encode()?.as_slice() != plan.bytes.as_slice() {
        return Err(ReadError::Authentication);
    }
    let crate::state_record_root::StateIdentity::RecordsV6(identity) = plan.root.identity()? else {
        return Err(ReadError::Authentication);
    };
    let context = ReadContext {
        expected_identity: crate::v6_read_validation::ReadIdentity::RecordsV6(identity),
        cluster_id: &plan.root.cluster_id,
        replay_epoch: plan.root.replay_epoch,
        minimum_state_schema: plan.root.state_schema,
        maximum_state_schema: plan.root.state_schema,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    };
    let _ = materialize(
        &plan.root,
        context,
        &NativeMigrationObjects {
            objects: &plan.objects,
            deadline: plan.deadline,
            fallback,
        },
    )?;
    plan.deadline.check().map_err(|_| ReadError::Invalid)?;
    Ok(())
}

impl Service {
    #[cfg(test)]
    pub(super) fn prepare_native_root_migration(
        &mut self,
        check: &impl Fn() -> Result<(), RecordError>,
    ) -> Result<NativeRootMigrationPlan, Response> {
        self.prepare_native_root_migration_mode(check, false)
    }

    #[cfg(feature = "fixture-native-v6-service")]
    pub(super) fn prepare_native_root_migration_paged(
        &mut self,
        check: &impl Fn() -> Result<(), RecordError>,
    ) -> Result<NativeRootMigrationPlan, Response> {
        self.prepare_native_root_migration_mode(check, true)
    }

    #[cfg(any(test, feature = "fixture-native-v6-service"))]
    fn prepare_native_root_migration_mode(
        &mut self,
        check: &impl Fn() -> Result<(), RecordError>,
        paged: bool,
    ) -> Result<NativeRootMigrationPlan, Response> {
        let rejected = || Response::error(503, "native migration source or custody rejected");
        // Capture the real original request before any projection work. A caller's
        // successful check closure cannot create or extend a request budget.
        let deadline =
            crate::v6_native_custody::OriginalDeadline::capture().map_err(|_| rejected())?;
        let check = || {
            deadline.check().map_err(|_| RecordError::Invalid)?;
            check()?;
            deadline.check().map_err(|_| RecordError::Invalid)
        };
        if self.recovery_required {
            return Err(rejected());
        }
        if self.ha.is_some() {
            #[cfg(feature = "experimental-native-v6-ha")]
            self.require_native_ha_environment()?;
            #[cfg(not(feature = "experimental-native-v6-ha"))]
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
            || durable
                .get("system", NATIVE_SIDE_ROOT)
                .map_err(|_| rejected())?
                .is_some()
        {
            return Err(rejected());
        }
        let source_generation = durable.generation();
        // Warm owners and an unchanged root do not prove the durable source.
        // Authenticate every source owner chunk and the entire KV1 closure with
        // the same original budget, including missing/corrupt durable objects.
        struct CheckedSource<'a, C> {
            durable: &'a DurableService<AeadBarrier>,
            check: &'a C,
        }
        impl<C: Fn() -> Result<(), RecordError>> RecordReader for CheckedSource<'_, C> {
            fn read_object(
                &self,
                reference: &ObjectRef,
            ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
                (self.check)()?;
                let bytes = records::DurableReader(self.durable).read_object(reference)?;
                (self.check)()?;
                Ok(bytes)
            }
        }
        check().map_err(|_| rejected())?;
        records::verify_received_record_graph(
            &old,
            &CheckedSource {
                durable,
                check: &check,
            },
            &candidate,
        )
        .map_err(|_| rejected())?;
        check().map_err(|_| rejected())?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        if source_generation == 0 || durable.generation() != source_generation {
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
                native_kv2_format: if paged { 2 } else { 1 },
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
            .rekey_root_records_checked(root.kv1_key().map_err(|_| rejected())?, &check)
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
        let mut visit = |scope: &MountScope, object: &Arc<crate::state_records::StagedObject>| {
            stage(&mut objects, ObjectDomain::Kv2(scope.clone()), object)
        };
        let (opaque, graphs) = if paged {
            recorded.project_v6_native_paged(&parent, &check, &mut visit)
        } else {
            recorded.project_v6_native(&parent, &check, &mut visit)
        }
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
        // Final ownership/root I/O must not return a plan after the captured
        // original request budget has elapsed.
        check().map_err(|_| rejected())?;
        let plan = NativeRootMigrationPlan {
            root,
            bytes,
            candidate,
            objects,
            source_generation,
            deadline,
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
        };
        // A prepared plan is not allowed to leave Service unless the *real*
        // V6 reader authenticates the complete staged object closure.
        validate_native_root_migration_plan(&plan, None).map_err(|_| rejected())?;
        check().map_err(|_| rejected())?;
        Ok(plan)
    }
}

#[cfg(any(test, feature = "fixture-native-v6-service"))]
pub(super) fn native_resource(domain: &ObjectDomain, reference: &ObjectRef) -> String {
    let role = match domain {
        ObjectDomain::Owner(role) => format!("owner/{}", role.name()),
        ObjectDomain::Kv1 => "kv1".into(),
        ObjectDomain::Kv2(_) => "kv2".into(),
    };
    // IDs already authenticate the role/scoped address key. A V5 collector
    // must never collect a staged or published V6 object.
    format!(
        "state-records/v6/{role}/{}",
        reference.resource().trim_start_matches("state-records/v5/")
    )
}
#[cfg(any(test, feature = "fixture-native-v6-service"))]
const NATIVE_SIDE_ROOT: &str = "state-native-v6/root";

#[cfg(test)]
struct NativeDurableSource<'a> {
    durable: &'a DurableService<AeadBarrier>,
    deadline: crate::v6_native_custody::OriginalDeadline,
}
#[cfg(test)]
impl ObjectSource for NativeDurableSource<'_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        let value = self
            .durable
            .get("system", &native_resource(domain, reference))
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        let bytes = Zeroizing::new(value.expose().to_vec());
        self.deadline.check().map_err(|_| RecordError::Invalid)?;
        Ok(bytes)
    }
}
#[cfg(test)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativePublicationCursor {
    format: String,
    cluster_id: String,
    replay_epoch: u64,
    source_generation: u64,
    source_root_digest: [u8; 32],
    generation: u64,
    root_digest: [u8; 32],
}
#[cfg(test)]
pub(super) struct NativeSidePublicationReceipt {
    pub source_identity: crate::state_record_root::StateIdentity,
    pub source_generation: u64,
    pub identity: crate::state_record_root::StateIdentity,
    pub publication_generation: u64,
}
impl Service {
    /// Publish an encrypted immutable side snapshot of a verified V5 source.
    /// Its cursor and root never replace application `state` or admit a V6
    /// request reader/writer. This private primitive has no HTTP route and
    /// grants no business-request audit, HA or activated migration authority.
    #[cfg(test)]
    pub(super) fn publish_native_root_side_snapshot(
        &mut self,
        plan: NativeRootMigrationPlan,
        check: &impl Fn() -> Result<(), RecordError>,
    ) -> Result<NativeSidePublicationReceipt, Response> {
        let deadline = plan.deadline;
        let check = || {
            deadline.check().map_err(|_| RecordError::Invalid)?;
            check()?;
            deadline.check().map_err(|_| RecordError::Invalid)
        };
        let rejected = || {
            Response::error(
                503,
                "native side snapshot rejected; active migration remains closed",
            )
        };
        check().map_err(|_| rejected())?;
        if self.ha.is_some()
            || self.recovery_required
            || self.audit_failed
            || plan.conditions.len() != 2
            || plan.conditions[0].resource != "state"
            || plan.conditions[1].resource != "state-native-v6/publication-cursor"
            || plan.conditions[1].expected.is_some()
            || plan.root.encode().map_err(|_| rejected())?.as_slice() != plan.bytes.as_slice()
        {
            return Err(rejected());
        }
        check().map_err(|_| rejected())?;
        let identity = plan.root.identity().map_err(|_| rejected())?;
        let crate::state_record_root::StateIdentity::RecordsV6(id) = identity else {
            return Err(rejected());
        };
        let context = ReadContext {
            expected_identity: crate::v6_read_validation::ReadIdentity::RecordsV6(id),
            cluster_id: &plan.root.cluster_id,
            replay_epoch: plan.root.replay_epoch,
            minimum_state_schema: plan.root.state_schema,
            maximum_state_schema: plan.root.state_schema,
            reader_format: 6,
        };
        let verified = materialize(
            &plan.root,
            context,
            &NativeMigrationObjects {
                objects: &plan.objects,
                deadline,
                fallback: None,
            },
        )
        .map_err(|_| rejected())?;
        check().map_err(|_| rejected())?;
        let current = self.state.as_ref().ok_or_else(rejected)?;
        // Bind the actual authenticated policy/token owner before any effect.
        let actual = owner_store::serialize_owner(&current.auth).map_err(|_| rejected())?;
        let expected =
            owner_store::serialize_owner(&verified.protected.auth).map_err(|_| rejected())?;
        if actual.as_slice() != expected.as_slice() {
            return Err(rejected());
        }
        let base_identity = self.current_state_identity()?;
        let anchor_generation = plan.source_generation.checked_add(1).ok_or_else(rejected)?;
        let operation = format!(
            "native6-{}",
            hex(&crypto::random::<16>().map_err(|_| rejected())?)
        );
        let mut cursor = NativePublicationCursor {
            format: "heptabao-native-v6-side-publication-cursor-v1".into(),
            cluster_id: plan.root.cluster_id.clone(),
            replay_epoch: plan.root.replay_epoch,
            source_generation: plan.source_generation,
            source_root_digest: base_identity.digest(),
            generation: anchor_generation,
            root_digest: base_identity.digest(),
        };
        let anchor = owner_store::serialize_owner(&cursor).map_err(|_| rejected())?;
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        if durable.generation() != plan.source_generation {
            return Err(rejected());
        }
        check().map_err(|_| rejected())?;
        let mut conditions = plan.conditions;
        conditions.push(heptabao_durable_service::PublicationCondition {
            resource: NATIVE_SIDE_ROOT.into(),
            expected: None,
        });
        fn copied(
            conditions: &[heptabao_durable_service::PublicationCondition],
        ) -> Vec<heptabao_durable_service::PublicationCondition> {
            conditions
                .iter()
                .map(|condition| heptabao_durable_service::PublicationCondition {
                    resource: condition.resource.clone(),
                    expected: condition.expected.clone(),
                })
                .collect()
        }
        let mut gate = || check().map_err(|_| ServiceError::BarrierFailure);
        let result = (|| -> Result<u64, ServiceError> {
            durable.apply_batch_conditionally_before_publish(
                heptabao_durable_service::BatchPublication {
                    replay_epoch: plan.root.replay_epoch,
                    principal: "heptabao-server".into(),
                    namespace: "system".into(),
                    request_id: format!("{operation}-anchor"),
                    authorization_digest: id,
                    mutations: vec![(
                        "state-native-v6/publication-cursor".into(),
                        Some(Secret::new(anchor.to_vec())?),
                    )],
                },
                copied(&conditions),
                &mut gate,
            )?;
            conditions[1].expected = Some(Secret::new(anchor.to_vec())?);
            let objects = plan.objects.iter().collect::<Vec<_>>();
            for (number, chunk) in objects
                .chunks(heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
                .enumerate()
            {
                check().map_err(|_| ServiceError::BarrierFailure)?;
                let mutations = chunk
                    .iter()
                    .map(|((domain, _), object)| {
                        Ok((
                            native_resource(domain, object.reference()),
                            Some(Secret::new(object.bytes().to_vec())?),
                        ))
                    })
                    .collect::<Result<Vec<_>, ServiceError>>()?;
                durable.apply_batch_conditionally_before_publish(
                    heptabao_durable_service::BatchPublication {
                        replay_epoch: plan.root.replay_epoch,
                        principal: "heptabao-server".into(),
                        namespace: "system".into(),
                        request_id: format!("{operation}-objects-{number}"),
                        authorization_digest: id,
                        mutations,
                    },
                    copied(&conditions),
                    &mut gate,
                )?;
            }
            // Read the actual encrypted staged objects before publishing a root.
            materialize(
                &plan.root,
                context,
                &NativeDurableSource { durable, deadline },
            )
            .map_err(|_| ServiceError::CorruptState)?;
            check().map_err(|_| ServiceError::BarrierFailure)?;
            // Each encrypted object batch advances the durable journal once.
            // Bind the final cursor to the *actual* next journal generation,
            // not a fixed offset from the migration's starting generation.
            let publication_generation = durable
                .generation()
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?;
            cursor.generation = publication_generation;
            cursor.root_digest = id;
            let cursor_bytes =
                owner_store::serialize_owner(&cursor).map_err(|_| ServiceError::CorruptState)?;
            durable.apply_batch_conditionally_before_publish(
                heptabao_durable_service::BatchPublication {
                    replay_epoch: plan.root.replay_epoch,
                    principal: "heptabao-server".into(),
                    namespace: "system".into(),
                    request_id: format!("{operation}-root"),
                    authorization_digest: id,
                    mutations: vec![
                        (
                            NATIVE_SIDE_ROOT.into(),
                            Some(Secret::new(plan.bytes.to_vec())?),
                        ),
                        (
                            "state-native-v6/publication-cursor".into(),
                            Some(Secret::new(cursor_bytes.to_vec())?),
                        ),
                    ],
                },
                copied(&conditions),
                &mut gate,
            )?;
            if durable.generation() != publication_generation {
                return Err(ServiceError::CorruptState);
            }
            // Reauthenticate the actually persisted side root, cursor and
            // referenced closure before issuing a migration receipt. The
            // source V5 root remains selected and this grants no V6 runtime.
            materialize_native_side_snapshot(durable, base_identity, context, deadline)
                .map_err(|_| ServiceError::CorruptState)?;
            Ok(publication_generation)
        })();
        // A partial side artifact never selects application state. Unknown
        // journal outcomes still fence the whole durable owner; an ordinary
        // prepublication rejection can leave the authenticated V5 runtime live.
        let unknown = matches!(&result, Err(ServiceError::RecoveryRequired))
            || durable.capacity_status().recovery_required;
        if unknown {
            self.recovery_required = true;
            self.ha_activation = None;
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
        }
        let publication_generation = result.map_err(|_| rejected())?;
        check().map_err(|_| rejected())?;
        Ok(NativeSidePublicationReceipt {
            source_identity: base_identity,
            source_generation: plan.source_generation,
            identity,
            publication_generation,
        })
    }
}

#[cfg(test)]
fn materialize_native_side_snapshot(
    durable: &DurableService<AeadBarrier>,
    source_identity: crate::state_record_root::StateIdentity,
    context: ReadContext<'_>,
    deadline: crate::v6_native_custody::OriginalDeadline,
) -> Result<ReadState, ReadError> {
    deadline.check().map_err(|_| ReadError::Invalid)?;
    if !matches!(
        source_identity,
        crate::state_record_root::StateIdentity::RecordsV5(_)
    ) {
        return Err(ReadError::Authentication);
    }
    let bytes = durable
        .get("system", NATIVE_SIDE_ROOT)
        .map_err(|_| ReadError::State)?
        .ok_or(ReadError::Missing)?;
    deadline.check().map_err(|_| ReadError::Invalid)?;
    let root = RecordStateRootV6::decode(bytes.expose())?;
    validate_frontier(&root, context)?;
    let bytes = durable
        .get("system", "state-native-v6/publication-cursor")
        .map_err(|_| ReadError::State)?
        .ok_or(ReadError::Missing)?;
    deadline.check().map_err(|_| ReadError::Invalid)?;
    if bytes.expose().len() > crate::state_record_root::MAX_ROOT_BYTES {
        return Err(ReadError::TooLarge);
    }
    let cursor: NativePublicationCursor =
        serde_json::from_slice(bytes.expose()).map_err(|_| ReadError::Invalid)?;
    if owner_store::serialize_owner(&cursor)
        .map_err(|_| ReadError::Invalid)?
        .as_slice()
        != bytes.expose()
        || cursor.format != "heptabao-native-v6-side-publication-cursor-v1"
        || cursor.cluster_id != root.cluster_id
        || cursor.replay_epoch != root.replay_epoch
        || cursor.source_generation == 0
        || cursor.source_generation >= cursor.generation
        || cursor.generation > durable.generation()
        || cursor.source_root_digest != source_identity.digest()
        || cursor.root_digest != root.identity()?.digest()
    {
        return Err(ReadError::Authentication);
    }
    let state = materialize(&root, context, &NativeDurableSource { durable, deadline })?;
    deadline.check().map_err(|_| ReadError::Invalid)?;
    Ok(state)
}

#[cfg(feature = "fixture-native-v6-service")]
pub(super) fn materialize_for_service(
    root: &RecordStateRootV6,
    context: ReadContext<'_>,
    source: &impl ObjectSource,
) -> Result<(State, BTreeMap<MountScope, NativeReadView>), ReadError> {
    let read = materialize(root, context, source)?;
    Ok((read.protected, read.native))
}

#[cfg(feature = "fixture-native-v6-service")]
pub(super) fn materialize_metadata_for_service(
    root: &RecordStateRootV6,
    context: ReadContext<'_>,
    source: &impl ObjectSource,
) -> Result<(State, BTreeMap<MountScope, NativeReadView>), ReadError> {
    let read = materialize_mode(root, context, source, false)?;
    Ok((read.protected, read.native))
}

#[cfg(feature = "fixture-native-v6-service")]
fn verify_incremental_views(
    plan: &NativeRootMigrationPlan,
    native: &BTreeMap<MountScope, NativeReadView>,
    prior: &State,
) -> Result<(), ReadError> {
    struct StagedOnly<'a> {
        plan: &'a NativeRootMigrationPlan,
        scope: &'a MountScope,
    }
    impl RecordReader for StagedOnly<'_> {
        fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
            self.plan
                .deadline
                .check()
                .map_err(|_| RecordError::Invalid)?;
            let object = self
                .plan
                .objects
                .get(&(ObjectDomain::Kv2(self.scope.clone()), reference.id))
                .ok_or(RecordError::Missing)?;
            if object.reference() != reference {
                return Err(RecordError::Corrupt);
            }
            Ok(Zeroizing::new(object.bytes().to_vec()))
        }
    }
    for (scope, view) in native {
        if view.is_paged() {
            let reader = StagedOnly { plan, scope };
            let prior = prior.engines.native_paged_view(scope);
            view.verify_paged_transition(prior, &reader, &|| {
                plan.deadline.check().map_err(|_| RecordError::Invalid)
            })?;
        }
    }
    plan.deadline.check().map_err(|_| ReadError::Invalid)
}

#[cfg(feature = "fixture-native-v6-service")]
fn validate_native_live_plan(
    plan: &NativeRootMigrationPlan,
    fallback: Option<&dyn ObjectSource>,
    prior: &State,
) -> Result<(), ReadError> {
    plan.deadline.check().map_err(|_| ReadError::Invalid)?;
    if plan.root.encode()?.as_slice() != plan.bytes.as_slice() {
        return Err(ReadError::Authentication);
    }
    let crate::state_record_root::StateIdentity::RecordsV6(identity) = plan.root.identity()? else {
        return Err(ReadError::Authentication);
    };
    let context = ReadContext {
        expected_identity: crate::v6_read_validation::ReadIdentity::RecordsV6(identity),
        cluster_id: &plan.root.cluster_id,
        replay_epoch: plan.root.replay_epoch,
        minimum_state_schema: plan.root.state_schema,
        maximum_state_schema: plan.root.state_schema,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    };
    let read = materialize_mode(
        &plan.root,
        context,
        &NativeMigrationObjects {
            objects: &plan.objects,
            deadline: plan.deadline,
            fallback,
        },
        false,
    )?;
    verify_incremental_views(plan, &read.native, prior)
}

#[cfg(feature = "fixture-native-v6-service")]
impl Service {
    pub(super) fn prepare_native_live_root(
        &mut self,
        candidate: &State,
    ) -> Result<NativeRootMigrationPlan, Response> {
        let mut authority = self.pending_ordinary_kv_authority.take();
        let token_authority = self.pending_token_api_authority.take();
        let nonce = self.unseal_nonce.clone();
        let result = if let Some(authority) = authority.as_mut() {
            self.prepare_native_live_root_checked(candidate, &mut |auth| {
                authority.check(candidate, auth, &nonce)
            })
        } else if let Some(authority) = token_authority.as_ref() {
            self.prepare_native_live_root_checked(candidate, &mut |auth| {
                authority.check_token_api_candidate(candidate, auth, &nonce)
            })
        } else {
            Err(Response::error(
                503,
                "native preparation requires original request authority",
            ))
        };
        self.pending_ordinary_kv_authority = authority;
        self.pending_token_api_authority = token_authority;
        result
    }

    pub(super) fn prepare_native_live_root_checked(
        &mut self,
        candidate: &State,
        original_gate: &mut impl FnMut(&AuthState) -> Result<(), Response>,
    ) -> Result<NativeRootMigrationPlan, Response> {
        let rejected = || Response::error(503, "native live candidate custody rejected");
        let deadline =
            crate::v6_native_custody::OriginalDeadline::capture().map_err(|_| rejected())?;
        let check = || deadline.check().map_err(|_| RecordError::Invalid);
        check().map_err(|_| rejected())?;
        self.require_native_root_candidate(candidate)?;
        candidate.validate_publication_schema(self.state.as_ref())?;
        candidate.validate_format()?;
        let actual_auth = self.state.as_ref().ok_or_else(rejected)?.auth.clone();
        original_gate(&actual_auth)?;
        let proof = self
            .capture_native_request_proof(&mut || original_gate(&actual_auth))?
            .ok_or_else(rejected)?;
        proof.check_warm(self)?;
        let mut candidate = candidate.clone();
        let mut root = self.native_root.as_ref().ok_or_else(rejected)?.clone();
        if root.replay_epoch != candidate.replay_epoch || root.cluster_id != candidate.cluster_id {
            return Err(rejected());
        }
        root.state_schema = candidate.schema;
        root.reader_floor.minimum_state_schema = candidate.schema;
        root.global_lossless_json_format = candidate.global_lossless_json_format;
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        let source = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        let prior = self
            .native_root
            .as_ref()
            .ok_or_else(rejected)?
            .encode()
            .map_err(|_| rejected())?;
        if prior.as_slice() != source.expose() {
            return Err(rejected());
        }
        let cursor = durable
            .get("system", native_v6_reader::ACTIVE_CURSOR_RESOURCE)
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        let retained = durable
            .get("system", native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE)
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        let source_generation = durable.generation();
        use crate::state_record_root::OpaqueOwnerRef;
        use crate::state_record_root_v6::OwnerDomain;
        let recorded = (*candidate.engines).clone();
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
        let mut visit = |scope: &MountScope, object: &Arc<crate::state_records::StagedObject>| {
            stage(&mut objects, ObjectDomain::Kv2(scope.clone()), object)
        };
        let (opaque, graphs) = if root.reader_floor.native_kv2_format == 2 {
            recorded.project_v6_native_paged(&parent, &check, &mut visit)
        } else {
            recorded.project_v6_native(&parent, &check, &mut visit)
        }
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
        if durable.generation() != source_generation {
            return Err(rejected());
        }
        let plan = NativeRootMigrationPlan {
            root,
            bytes,
            candidate,
            objects,
            source_generation,
            deadline,
            conditions: vec![
                heptabao_durable_service::PublicationCondition {
                    resource: "state".into(),
                    expected: Some(source),
                },
                heptabao_durable_service::PublicationCondition {
                    resource: native_v6_reader::ACTIVE_CURSOR_RESOURCE.into(),
                    expected: Some(cursor),
                },
                heptabao_durable_service::PublicationCondition {
                    resource: native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE.into(),
                    expected: Some(retained),
                },
            ],
        };
        let source =
            super::native_blob_source::NativeSource::new_checked(durable, deadline, || {
                original_gate(&actual_auth).map_err(|_| ServiceError::BarrierFailure)
            })
            .map_err(|_| rejected())?;
        validate_native_live_plan(
            &plan,
            Some(&source),
            self.state.as_ref().ok_or_else(rejected)?,
        )
        .map_err(|_| rejected())?;
        drop(source);
        check().map_err(|_| rejected())?;
        Ok(plan)
    }

    pub(super) fn install_prepared_native_candidate(
        &mut self,
        plan: &NativeRootMigrationPlan,
        original_gate: &mut impl FnMut(&AuthState) -> Result<(), Response>,
    ) -> Result<State, Response> {
        let rejected = || Response::error(503, "native staged candidate installation rejected");
        plan.deadline.check().map_err(|_| rejected())?;
        let crate::state_record_root::StateIdentity::RecordsV6(identity) =
            plan.root.identity().map_err(|_| rejected())?
        else {
            return Err(rejected());
        };
        let context = ReadContext {
            expected_identity: crate::v6_read_validation::ReadIdentity::RecordsV6(identity),
            cluster_id: &plan.root.cluster_id,
            replay_epoch: plan.root.replay_epoch,
            minimum_state_schema: plan.root.state_schema,
            maximum_state_schema: plan.root.state_schema,
            reader_format: crate::state_record_root_v6::READER_FORMAT,
        };
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        let current = self.state.as_ref().ok_or_else(rejected)?;
        let actual_auth = current.auth.clone();
        original_gate(&actual_auth)?;
        let source =
            super::native_blob_source::NativeSource::new_checked(durable, plan.deadline, || {
                original_gate(&actual_auth).map_err(|_| ServiceError::BarrierFailure)
            })
            .map_err(|_| rejected())?;
        let (mut metadata, native) = materialize_metadata_for_service(
            &plan.root,
            context,
            &NativeMigrationObjects {
                objects: &plan.objects,
                deadline: plan.deadline,
                fallback: Some(&source),
            },
        )
        .map_err(|_| rejected())?;
        verify_incremental_views(plan, &native, current).map_err(|_| rejected())?;
        drop(source);
        metadata
            .engines
            .install_native_views(native)
            .map_err(Response::from_engine_error)?;
        let installed_auth =
            owner_store::serialize_owner(&metadata.auth).map_err(|_| rejected())?;
        let expected_auth =
            owner_store::serialize_owner(&plan.candidate.auth).map_err(|_| rejected())?;
        if installed_auth.as_slice() != expected_auth.as_slice() {
            return Err(rejected());
        }
        metadata
            .auth
            .retain_quota_runtime_owner(&plan.candidate.auth)
            .map_err(|_| rejected())?;
        metadata.validate_format()?;
        plan.deadline.check().map_err(|_| rejected())?;
        Ok(metadata)
    }
}

#[cfg(feature = "fixture-native-v6-service")]
pub(super) fn verify_durable_native_candidate(
    root: &RecordStateRootV6,
    durable: &mut DurableService<AeadBarrier>,
    deadline: crate::v6_native_custody::OriginalDeadline,
    gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<(), ReadError> {
    deadline.check().map_err(|_| ReadError::Invalid)?;
    let crate::state_record_root::StateIdentity::RecordsV6(identity) = root.identity()? else {
        return Err(ReadError::Authentication);
    };
    let context = ReadContext {
        expected_identity: crate::v6_read_validation::ReadIdentity::RecordsV6(identity),
        cluster_id: &root.cluster_id,
        replay_epoch: root.replay_epoch,
        minimum_state_schema: root.state_schema,
        maximum_state_schema: root.state_schema,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    };
    let source = super::native_blob_source::NativeSource::new_checked(durable, deadline, gate)?;
    let _ = materialize_mode(root, context, &source, false)?;
    drop(source);
    deadline.check().map_err(|_| ReadError::Invalid)?;
    Ok(())
}
