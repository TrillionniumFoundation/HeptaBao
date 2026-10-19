//! A closed lossless import becomes a detached typed graph, never a legacy
//! EngineState owner. Only the Service publisher can install these objects.
use super::*;
use crate::state_record_root_v6::{Kv2GraphRef, MountScope};

/// Fresh immutable objects for exactly one imported graph. Its private fields
/// bind the source of every payload to the projected mount incarnation/root.
/// This is preparation evidence, not a durable publication receipt.
pub(crate) struct NativeKv2GraphImport {
    scope: MountScope,
    root: Kv1Root,
    logical_bytes: u64,
    objects: BTreeMap<ObjectId, Arc<StagedObject>>,
}

impl NativeKv2GraphImport {
    pub(crate) fn visit_for(
        &self,
        roots: &[Kv2GraphRef],
        check: &impl Fn() -> CodecResult<()>,
        mut visit: impl FnMut(&MountScope, &Arc<StagedObject>) -> CodecResult<()>,
    ) -> CodecResult<()> {
        check()?;
        let mut selected = roots.iter().filter(|root| root.scope == self.scope);
        let root = selected.next().ok_or(RecordError::Missing)?;
        if selected.next().is_some()
            || root.graph_format != PAGED_NATIVE_FORMAT
            || root.root != self.root
            || root.logical_payload_bytes != self.logical_bytes
        {
            return Err(RecordError::Corrupt);
        }
        for object in self.objects.values() {
            check()?;
            visit(&self.scope, object)?;
            check()?;
        }
        check()
    }
}

impl NativeReadView {
    /// The old view must be the real pristine paged destination. Payloads exist
    /// only during closed decoding and per-value graph encoding. Before the
    /// returned view can enter an EngineState, it holds metadata/descriptors
    /// only; fresh payload bytes are bounded, immutable typed objects.
    pub(in crate::engines) fn prepare_lossless_graph_import(
        &self,
        bundle: &[u8],
        parent: &AddressKey,
        input: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> Result<(Self, NativeKv2GraphImport)> {
        self.prepare_graph_import(parent, input, check, || Kv2::from_lossless_import_json(bundle))
    }

    #[cfg(feature = "fixture-native-v6-service")]
    pub(in crate::engines) fn prepare_native_large_graph_import(
        &self,
        bundle: &crate::engines::kv2_native_large::NativeLargeBundle,
        parent: &AddressKey,
        input: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> Result<(Self, NativeKv2GraphImport)> {
        self.prepare_graph_import(parent, input, check, || Kv2::from_native_large_import(bundle, check))
    }

    pub(in crate::engines) fn check_graph_import_destination(
        &self,
        parent: &AddressKey,
        input: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> Result<()> {
        let rejected = || error(503, "native KV2 import graph custody rejected");
        check().map_err(|_| rejected())?;
        let scope = MountScope {
            namespace: input.namespace.into(),
            mount: input.mount.into(),
            incarnation: input.incarnation,
        };
        if !self.is_paged()
            || !self.cached_scope_matches(scope.borrowed()).map_err(|_| rejected())?
        {
            return Err(rejected());
        }
        if !self.owner.is_pristine_for_import() {
            return Err(error(409, "KV2 import requires a pristine empty mount"));
        }
        // Re-encode the empty selected cache under the actual parent/scope.
        // An invented scope, pending edit, or foreign graph key cannot become
        // the owner of otherwise valid imported objects.
        let prior = self.encode_paged(parent, scope.borrowed(), check)
            .map_err(|_| rejected())?;
        if self.graph.as_ref().is_none_or(|graph| graph.index.root() != prior.root()) {
            return Err(rejected());
        }
        check().map_err(|_| rejected())?;
        Ok(())
    }

    fn prepare_graph_import(
        &self,
        parent: &AddressKey,
        input: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
        decode: impl FnOnce() -> Result<Kv2>,
    ) -> Result<(Self, NativeKv2GraphImport)> {
        self.check_graph_import_destination(parent, input, check)?;
        let rejected = || error(503, "native KV2 import graph custody rejected");
        let scope = MountScope {
            namespace: input.namespace.into(),
            mount: input.mount.into(),
            incarnation: input.incarnation,
        };
        let owner = decode()?;
        check().map_err(|_| rejected())?;
        let mut candidate = Self {
            owner: DetachedOwner(owner),
            graph: None,
            pending: mutation::PendingPaths::default(),
        };
        let graph = candidate.encode_paged(parent, scope.borrowed(), check)
            .map_err(|cause| match cause {
                RecordError::TooLarge => error(507, "native KV2 import graph exceeds capacity"),
                _ => rejected(),
            })?;
        let root = graph.root();
        let logical_bytes = graph.logical_payload_bytes().map_err(|_| rejected())?;
        let mut objects = BTreeMap::<ObjectId, Arc<StagedObject>>::new();
        graph.visit_objects(|object| {
            let id = object.reference().id;
            if let Some(prior) = objects.get(&id) {
                if prior.reference() != object.reference() || prior.bytes() != object.bytes() {
                    return Err(RecordError::Corrupt);
                }
            } else {
                objects.insert(id, Arc::clone(object));
            }
            Ok(())
        }, check).map_err(|_| rejected())?;
        candidate.graph = Some(graph.0);
        candidate.clear_hydrated_payloads()?;
        candidate.graph.as_mut()
            .and_then(|graph| graph.paged.as_mut())
            .ok_or_else(rejected)?
            .clear_new_blocks();
        candidate.validate_lossless_state()?;
        check().map_err(|_| rejected())?;
        Ok((candidate, NativeKv2GraphImport { scope, root, logical_bytes, objects }))
    }
}

#[cfg(test)]
#[path = "kv2_native_import_tests.rs"]
mod tests;
