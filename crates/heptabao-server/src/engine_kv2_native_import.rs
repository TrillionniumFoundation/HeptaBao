//! Native import preparation is separate from the aggregate legacy importer.
use super::*;
use crate::engines::kv2_native_records::NativeKv2GraphImport;
use crate::state_record_root_v6::MountScope;
use crate::state_records::{AddressKey, RecordError};

impl EngineState {
    /// Replace only a detached native view after the complete import has been
    /// checked. Returned objects still require the actual Service transaction.
    pub(crate) fn stage_openbao_kv2_native_import(
        &mut self,
        namespace: &str,
        requested: &str,
        bundle: &[u8],
        parent: &AddressKey,
        check: &impl Fn() -> std::result::Result<(), RecordError>,
    ) -> Result<NativeKv2GraphImport> {
        let canonical = canonical_secret_mount(requested.trim_end_matches('/'))?;
        if requested != canonical && requested != format!("{canonical}/") {
            return Err(bad("KV2 import mount must be canonical"));
        }
        check().map_err(|_| error(503, "native KV2 import original budget exhausted"))?;
        self.validate_kv2_lossless_state(None)?;
        let name = format!("{canonical}/");
        let mount = self.namespaces.get(namespace)
            .and_then(|owner| owner.mounts.get(&name))
            .ok_or_else(not_found)?;
        let Backend::Kv2Native(current) = &mount.backend else {
            return Err(bad("native graph import requires an active native KV2 mount"));
        };
        let scope = MountScope {
            namespace: namespace.into(),
            mount: name.clone(),
            incarnation: mount.incarnation,
        };
        let revision = next_mount_revision(mount.revision)?;
        let (view, objects) = current.prepare_lossless_graph_import(
            bundle, parent, scope.borrowed(), check,
        )?;
        let mut candidate = self.clone();
        let mount = candidate.namespaces.get_mut(namespace)
            .and_then(|owner| owner.mounts.get_mut(&name))
            .ok_or_else(not_found)?;
        mount.backend = Backend::Kv2Native(view);
        mount.revision = revision;
        candidate.kv2_lossless_format = Some(1);
        candidate.validate_kv2_lossless_state(Some(self))?;
        check().map_err(|_| error(503, "native KV2 import original budget exhausted"))?;
        // NativeReadView deliberately refuses aggregate serialization. The
        // Service planner projects small opaque mount metadata separately.
        *self = candidate;
        Ok(objects)
    }
}
