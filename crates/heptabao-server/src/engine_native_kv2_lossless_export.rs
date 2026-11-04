//! Select one root KV2 owner after actual Service authorization.
use super::*;
use crate::state_record_root_v6::MountScope;
use crate::state_records::{ObjectRef, RecordError, RecordReader};
use std::io::Write;
use zeroize::Zeroizing;

/// Borrow the caller's existing deadline and cancellation flag. This grouping
/// creates no new budget and does not change any source or delivery gate.
#[cfg(any(test, feature = "native-v6-storage"))]
pub(crate) struct NativeKv2LosslessExportBudget<'a> {
    pub(crate) deadline: crate::v6_native_custody::OriginalDeadline,
    pub(crate) stop: &'a std::sync::atomic::AtomicBool,
}

struct ScopedReader<'a, F> {
    scope: &'a MountScope,
    source: &'a F,
}
impl<F: Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>>
    RecordReader for ScopedReader<'_, F>
{
    fn read_object(
        &self,
        reference: &ObjectRef,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError> {
        (self.source)(self.scope, reference)
    }
}

impl EngineState {
    pub(crate) fn write_native_kv2_lossless_export(
        &self,
        mount: &str,
        output: &mut impl Write,
        source: impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>,
        check: &impl Fn() -> std::result::Result<(), RecordError>,
    ) -> Result<()> {
        check().map_err(|_| error(503, "native lossless export request expired"))?;
        let canonical = canonical_secret_mount(mount)?;
        let mount_path = format!("{canonical}/");
        if mount != canonical && mount != mount_path {
            return Err(bad("lossless export mount is not canonical"));
        }
        let current = self
            .namespaces
            .get("")
            .ok_or_else(not_found)?
            .mounts
            .get(&mount_path)
            .ok_or_else(not_found)?;
        let Backend::Kv2Native(view) = &current.backend else {
            return Err(error(501, "lossless export requires a native KV2 mount"));
        };
        let scope = MountScope {
            namespace: String::new(),
            mount: mount_path,
            incarnation: current.incarnation,
        };
        let reader = ScopedReader {
            scope: &scope,
            source: &source,
        };
        view.write_lossless_export(output, &reader, check)?;
        check().map_err(|_| error(503, "native lossless export request expired"))
    }

    /// Only a source with a separately admitted concurrent File read view can
    /// call this entry. Actor/session ownership remains with the Service.
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn write_native_kv2_lossless_export_parallel(
        &self,
        mount: &str,
        output: &mut impl Write,
        source: &(
             impl Fn(&MountScope, &ObjectRef) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError>
             + Sync
         ),
        before_delivery: &(impl Fn() -> std::result::Result<(), RecordError> + Sync),
        check: &(impl Fn() -> std::result::Result<(), RecordError> + Sync),
        budget: NativeKv2LosslessExportBudget<'_>,
    ) -> Result<()> {
        let NativeKv2LosslessExportBudget { deadline, stop } = budget;
        let result = (|| {
            check().map_err(|_| error(503, "native lossless export request expired"))?;
            let canonical = canonical_secret_mount(mount)?;
            let mount_path = format!("{canonical}/");
            if mount != canonical && mount != mount_path {
                return Err(bad("lossless export mount is not canonical"));
            }
            let current = self
                .namespaces
                .get("")
                .ok_or_else(not_found)?
                .mounts
                .get(&mount_path)
                .ok_or_else(not_found)?;
            let Backend::Kv2Native(view) = &current.backend else {
                return Err(error(501, "lossless export requires a native KV2 mount"));
            };
            let scope = MountScope {
                namespace: String::new(),
                mount: mount_path,
                incarnation: current.incarnation,
            };
            view.write_lossless_export_parallel(
                output,
                &|reference| source(&scope, reference),
                before_delivery,
                check,
                deadline,
                stop,
            )?;
            check().map_err(|_| error(503, "native lossless export request expired"))
        })();
        if result.is_err() {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
}
