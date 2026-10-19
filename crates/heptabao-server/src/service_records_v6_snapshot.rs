//! A private typed owner projection inside one authenticated native snapshot.
//! No caller authority, source rebinding or durable publication lives here.
use super::*;
use crate::state_record_root::OpaqueOwnerRef;
use crate::state_record_root_v6::OwnerDomain;
use crate::v6_native_custody::OriginalDeadline;

pub(in crate::service) struct SnapshotRootProjection {
    pub root: RecordStateRootV6,
    pub bytes: Zeroizing<Vec<u8>>,
    pub candidate: State,
    pub objects: BTreeMap<(ObjectDomain, ObjectId), Arc<crate::state_records::StagedObject>>,
}

pub(in crate::service) fn project_snapshot_native_root(
    archived: &RecordStateRootV6,
    candidate: State,
    next_epoch: u64,
    deadline: OriginalDeadline,
    fallback: &dyn ObjectSource,
    original: &mut impl FnMut() -> Result<(), Response>,
) -> Result<SnapshotRootProjection, Response> {
    let rejected = || Response::error(400, "native snapshot clock projection is invalid");
    let check = || deadline.check().map_err(|_| RecordError::Invalid);
    original()?;
    if archived.replay_epoch >= next_epoch
        || archived.cluster_id != candidate.cluster_id
        || archived.state_schema != candidate.schema
        || archived.global_lossless_json_format != candidate.global_lossless_json_format
        || candidate.replay_epoch != next_epoch
        || archived.reader_floor.native_kv2_format != 2
    {
        return Err(rejected());
    }
    candidate.validate_format()?;
    let mut root = archived.clone();
    root.replay_epoch = next_epoch;
    // Keep the already authenticated native descriptors. This path cannot
    // create, parse, round or re-encode a KV payload while inheriting clocks.
    if candidate.engines.record_root().as_ref() != Some(&archived.kv1) {
        return Err(rejected());
    }
    let parent = root.kv2_parent_key().map_err(|_| rejected())?;
    let (opaque, graphs) = candidate
        .engines
        .project_checked_native_roots(
            &parent,
            &archived.kv2,
            archived.reader_floor.native_kv2_format,
            &check,
        )
        .map_err(|_| rejected())?;
    if crate::secret_serde::to_vec(&graphs, crate::state_record_root::MAX_ROOT_BYTES)
        .map_err(|_| rejected())?
        .as_slice()
        != crate::secret_serde::to_vec(&archived.kv2, crate::state_record_root::MAX_ROOT_BYTES)
            .map_err(|_| rejected())?
            .as_slice()
    {
        return Err(rejected());
    }
    let metadata = EngineMetadata {
        format: ENGINE_FORMAT.into(),
        opaque,
        kv2_scopes: archived
            .kv2
            .iter()
            .map(|graph| graph.scope.clone())
            .collect(),
    };
    let owners = [
        owner_store::serialize_owner(&candidate.namespaces),
        owner_store::serialize_owner(&candidate.auth),
        owner_store::serialize_owner(&metadata),
        owner_store::serialize_owner(&candidate.database),
        owner_store::serialize_owner(&candidate.raft_admin),
    ];
    let mut objects = BTreeMap::new();
    for (index, bytes) in owners.into_iter().enumerate() {
        original()?;
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
            let object_key = (ObjectDomain::Owner(domain), object.reference().id);
            if let Some(prior) = objects.get(&object_key) {
                let prior: &Arc<crate::state_records::StagedObject> = prior;
                if prior.reference() != object.reference() || prior.bytes() != object.bytes() {
                    return Err(rejected());
                }
            } else {
                objects.insert(object_key, object);
            }
        }
        root.owners[index].owner = OpaqueOwnerRef {
            name: domain.name().into(),
            total_bytes: bytes.len() as u64,
            chunks,
            digest: root.owner_digest(domain, &bytes).map_err(|_| rejected())?,
        };
        original()?;
    }
    // Check the entire encoded root, allowing only the two clock-bearing
    // owners and the fresh epoch to differ from the authenticated archive.
    let mut unaffected = root.clone();
    unaffected.replay_epoch = archived.replay_epoch;
    for (index, owner) in unaffected.owners.iter_mut().enumerate() {
        if matches!(owner.domain, OwnerDomain::Auth | OwnerDomain::Engines) {
            *owner = archived.owners[index].clone();
        }
    }
    if unaffected.encode().map_err(|_| rejected())?.as_slice()
        != archived.encode().map_err(|_| rejected())?.as_slice()
    {
        return Err(rejected());
    }
    let bytes = root.encode().map_err(|_| rejected())?;
    let context = ReadContext {
        expected_identity: crate::v6_read_validation::ReadIdentity::RecordsV6(
            root.identity().map_err(|_| rejected())?.digest(),
        ),
        cluster_id: &root.cluster_id,
        replay_epoch: root.replay_epoch,
        minimum_state_schema: root.state_schema,
        maximum_state_schema: root.state_schema,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    };
    // Independently reopen the entire derived typed graph. All original KV
    // bytes still come from the SAME affine authenticated incoming archive.
    let (metadata, native) = materialize_for_service(
        &root,
        context,
        &NativeMigrationObjects {
            objects: &objects,
            deadline,
            fallback: Some(fallback),
        },
    )
    .map_err(|_| rejected())?;
    Service::check_native_installed(&candidate, &metadata, &native, &root, deadline)?;
    original()?;
    Ok(SnapshotRootProjection {
        root,
        bytes,
        candidate,
        objects,
    })
}
