//! Rebuild one authenticated historical typed graph for a new replay epoch.
//! This data projection cannot enroll peers, publish, retire replay, or deliver.
use super::*;

pub(in crate::service) fn prepare_historical_native_root(
    archived_root: &RecordStateRootV6,
    mut candidate: State,
    next_epoch: u64,
    source_generation: u64,
    conditions: Vec<heptabao_durable_service::PublicationCondition>,
    deadline: crate::v6_native_custody::OriginalDeadline,
    fallback: &dyn ObjectSource,
    original: &mut impl FnMut() -> Result<(), Response>,
) -> Result<NativeRootMigrationPlan, Response> {
    let rejected = || Response::error(400, "historical native typed projection is invalid");
    let check = || deadline.check().map_err(|_| RecordError::Invalid);
    original()?;
    if archived_root.replay_epoch >= next_epoch
        || archived_root.cluster_id != candidate.cluster_id
        || candidate.replay_epoch != next_epoch
        || archived_root.reader_floor.native_kv2_format != 2
        || conditions.len() != 4
    { return Err(rejected()); }
    candidate.validate_format()?;
    let mut root = archived_root.clone();
    root.replay_epoch = next_epoch;
    root.state_schema = candidate.schema;
    root.reader_floor.minimum_state_schema = candidate.schema;
    root.global_lossless_json_format = candidate.global_lossless_json_format;
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

    original()?;
    let bytes = root.encode().map_err(|_| rejected())?;
    let plan = NativeRootMigrationPlan { root, bytes, candidate, objects,
        source_generation, deadline, conditions };
    let context = ReadContext {
        expected_identity: crate::v6_read_validation::ReadIdentity::RecordsV6(
            plan.root.identity().map_err(|_| rejected())?.digest()),
        cluster_id: &plan.root.cluster_id, replay_epoch: plan.root.replay_epoch,
        minimum_state_schema: plan.root.state_schema, maximum_state_schema: plan.root.state_schema,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    };
    // Every retained KV payload is really read under its original keyed graph
    // binding. Only its new shared cipher is epoch-bound; typed object address
    // keys intentionally remain cluster/domain bound and therefore reusable.
    let (metadata, native) = materialize_for_service(&plan.root, context, &NativeMigrationObjects {
        objects: &plan.objects, deadline, fallback: Some(fallback),
    }).map_err(|_| rejected())?;
    Service::check_native_installed(&plan.candidate, &metadata, &native, &plan.root, deadline)?;
    original()?;
    Ok(plan)
}
