//! Root-namespace native mount selection for an already authorized Service read.
use super::*;
use crate::state_record_root_v6::MountScope;
use crate::state_records::{ObjectRef, RecordError, RecordReader};
use zeroize::Zeroizing;

struct ScopedReader<'a, F> {
    scope: &'a MountScope,
    source: &'a F,
}
impl<F: Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>>
    RecordReader for ScopedReader<'_, F>
{
    fn read_object(&self, reference: &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError> {
        (self.source)(self.scope, reference)
    }
}

impl EngineState {
    pub(crate) fn native_kv2_storage_witness(
        &self,
        mount: &str,
        path: &str,
        version: u64,
        source: impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>,
        check: &impl Fn() -> std::result::Result<(), RecordError>,
    ) -> Result<Value> {
        check().map_err(|_| error(503, "native storage witness request expired"))?;
        let canonical = canonical_secret_mount(mount)?;
        let mount_path = format!("{canonical}/");
        if mount != canonical && mount != mount_path {
            return Err(bad("storage witness mount is not canonical"));
        }
        let current = self.namespaces.get("").ok_or_else(not_found)?
            .mounts.get(&mount_path).ok_or_else(not_found)?;
        let Backend::Kv2Native(view) = &current.backend else {
            return Err(error(501, "storage witness requires a native KV2 mount"));
        };
        let scope = MountScope {
            namespace: String::new(), mount: mount_path, incarnation: current.incarnation,
        };
        let reader = ScopedReader { scope: &scope, source: &source };
        let mut result = view.storage_version_witness(path, version, &reader, check)?;
        result["mount"] = json!(mount);
        result["mount_incarnation"] = json!(scope.incarnation);
        check().map_err(|_| error(503, "native storage witness request expired"))?;
        Ok(result)
    }
}
