//! Complete historical typed-resource DATA under actual retained Raft roots.
//! Every root and all typed payloads pass the production full materializer.
//! This cannot authorize local .hbo removal: it neither intersects the actual
//! registered local catalog nor accounts for local side/backup/restore roots.
use super::*;
use crate::ha_state::native_v6::NativeV6RetainedCipherRead;
use heptabao_raft_runtime::{NativeV6BlobQuiescence, NativeV6RetainedRootCatalog};
use std::collections::BTreeSet;

const MAX_TYPED_RESOURCES: usize = 1_000_000;

/// Complete mark DATA, produced only by this module's full typed walk. It is
/// deliberately not Clone/Deserialize or a deletion/cold recovery capability.
pub(crate) struct NativeV6TypedRetainedResources {
    catalog_sha256: [u8; 32],
    roots: usize,
    resources: BTreeSet<String>,
}
impl NativeV6TypedRetainedResources {
    pub(crate) fn catalog_sha256(&self) -> [u8; 32] {
        self.catalog_sha256
    }
    pub(crate) fn root_count(&self) -> usize {
        self.roots
    }
    pub(crate) fn resources(&self) -> &BTreeSet<String> {
        &self.resources
    }
}

struct RetainedSource<'a, 'guard, 'actor> {
    codec: &'a ClusterStateCodec,
    closure: &'a NativeV6RetainedCipherRead<'guard>,
    gate: &'a RefCell<OriginalGate<'actor>>,
    reached: &'a RefCell<BTreeSet<String>>,
}
impl ObjectSource for RetainedSource<'_, '_, '_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        check(self.gate).map_err(record_error)?;
        let bytes = self
            .closure
            .read_object(self.codec, domain, reference, &mut || check(self.gate))
            .map_err(record_error)?;
        check(self.gate).map_err(record_error)?;
        let resource = v6_records::native_resource(domain, reference);
        let mut reached = self
            .reached
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        if !reached.contains(&resource) && reached.len() >= MAX_TYPED_RESOURCES {
            return Err(RecordError::TooLarge);
        }
        reached.insert(resource);
        drop(reached);
        check(self.gate).map_err(record_error)?;
        Ok(bytes)
    }
    fn object_count(&self) -> Option<usize> {
        Some(self.closure.object_count())
    }
}

pub(crate) fn mark_native_v6_retained_roots(
    codec: &ClusterStateCodec,
    store: &LocalV6BlobStage,
    catalog: &NativeV6RetainedRootCatalog<'_>,
    exclusive: &NativeV6BlobQuiescence,
    deadline: OriginalDeadline,
    original_actor: &mut impl FnMut() -> CodecResult<()>,
) -> CodecResult<NativeV6TypedRetainedResources> {
    let gate = RefCell::new(OriginalGate {
        deadline,
        actor: original_actor,
    });
    check(&gate)?;
    let fingerprint = catalog
        .fingerprint()
        .map_err(|_| NativeV6CodecError::Storage)?;
    let count = catalog.roots().len();
    if count == 0 {
        return Err(NativeV6CodecError::Directory);
    }
    let reached = RefCell::new(BTreeSet::new());
    for root in catalog.roots() {
        check(&gate)?;
        root.verify_shared_ownership(store, exclusive)
            .map_err(|_| NativeV6CodecError::Storage)?;
        let selected = store
            .reopen_retained_root_closure(root, exclusive, &mut || {
                check(&gate).map_err(|_| heptabao_raft_runtime::LocalV6BlobError::CorruptOrChanged)
            })
            .map_err(|_| NativeV6CodecError::Storage)?;
        let closure = codec.open_native_v6_retained_read(selected, &mut || check(&gate))?;
        let root = closure.root();
        let context = ReadContext {
            expected_identity: ReadIdentity::RecordsV6(closure.root_digest()),
            cluster_id: &root.cluster_id,
            replay_epoch: root.replay_epoch,
            minimum_state_schema: root.state_schema,
            maximum_state_schema: root.state_schema,
            reader_format: crate::state_record_root_v6::READER_FORMAT,
        };
        let source = RetainedSource {
            codec,
            closure: &closure,
            gate: &gate,
            reached: &reached,
        };
        // This validates owner domains, KV1, every KV2 history/paged payload,
        // canonical addresses, object counts and protected floors. Historical
        // state is not compared to the current Service installed checkpoint.
        let materialized = v6_records::materialize_for_service(root, context, &source)
            .map_err(|_| NativeV6CodecError::Directory)?;
        drop(materialized);
        closure.verify()?;
        check(&gate)?;
    }
    if catalog
        .fingerprint()
        .map_err(|_| NativeV6CodecError::Storage)?
        != fingerprint
    {
        return Err(NativeV6CodecError::Storage);
    }
    check(&gate)?;
    let resources = reached.into_inner();
    if resources.is_empty() {
        return Err(NativeV6CodecError::Directory);
    }
    Ok(NativeV6TypedRetainedResources {
        catalog_sha256: fingerprint,
        roots: count,
        resources,
    })
}
