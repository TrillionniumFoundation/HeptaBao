//! Exact-current logical payload reads under the actual committed HA proof.
//! This file grants neither archive restore nor replica durability authority.
use super::*;
use crate::state_record_root_v6::ObjectDomain;
use crate::state_records::RecordError;

impl NativeHaReadProof {
    pub(in crate::service) fn export_kv2_lossless(
        &self,
        service: &mut Service,
        mount: &str,
        mut output: SnapshotFile,
        original_actor: &mut impl FnMut(&Service) -> Result<(), Response>,
    ) -> Result<SnapshotFile, Response> {
        original_actor(service)?;
        self.check_warm(service)?;
        let deadline = self.environment.deadline;
        let process = self
            .environment
            .ha
            .lock_for_request()
            .map_err(|_| unavailable())?;
        process
            .verify_native_v6_committed_read(&self.committed)
            .map_err(|_| unavailable())?;
        let mut durable = service.durable.take().ok_or_else(unavailable)?;
        let result = (|| {
            self.selected
                .check(&mut durable, self.selected.initial_generation)
                .map_err(storage_rejected)?;
            let root = self.selected.native.as_ref().ok_or_else(unavailable)?;
            if root.reader_floor.native_kv2_format != 2 {
                return Err(unavailable());
            }
            let borrowed = BorrowedSnapshotProof::capture(self, service)?;
            let mut gate = || {
                original_actor(borrowed.service()).map_err(|_| ServiceError::BarrierFailure)?;
                borrowed
                    .check_live()
                    .map_err(|_| ServiceError::BarrierFailure)?;
                process
                    .verify_native_v6_committed_read(&self.committed)
                    .map_err(|_| ServiceError::BarrierFailure)?;
                deadline.check().map_err(|_| ServiceError::BarrierFailure)
            };
            // As for an ordinary warm read, authenticate the exact typed owner
            // and real ciphertext locations. The selected export below then
            // decrypts and validates every retained payload of that mount.
            let (metadata, native) =
                materialize_current_local_request(&mut durable, root, deadline, &mut gate)?;
            Service::check_native_installed(
                borrowed.service().state.as_ref().ok_or_else(unavailable)?,
                &metadata,
                &native,
                root,
                deadline,
            )?;
            {
                let source = native_blob_source::NativeSource::new_checked(
                    &mut durable,
                    deadline,
                    &mut gate,
                )
                .map_err(|_| unavailable())?;
                let mut writer = output.buffered_writer().map_err(|_| unavailable())?;
                borrowed
                    .service()
                    .state
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .engines
                    .write_native_kv2_lossless_export(
                        mount,
                        &mut writer,
                        |scope, reference| {
                            source.read_paged_payload(&ObjectDomain::Kv2(scope.clone()), reference)
                        },
                        &|| deadline.check().map_err(|_| RecordError::Invalid),
                    )
                    .map_err(Response::from_engine_error)?;
                writer.finish().map_err(|_| unavailable())?;
            }
            self.selected
                .check(&mut durable, self.selected.initial_generation)
                .map_err(storage_rejected)?;
            gate().map_err(storage_rejected)?;
            output.rewind_checked().map_err(|_| unavailable())?;
            let length = output.len();
            crate::engines::kv2_lossless_export::check_export_syntax(&mut output, length, &|| {
                deadline.check().map_err(|_| RecordError::Invalid)
            })
            .map_err(Response::from_engine_error)?;
            gate().map_err(storage_rejected)?;
            borrowed.check_complete()?;
            output.rewind_checked().map_err(|_| unavailable())?;
            Ok(())
        })();
        service.durable = Some(durable);
        drop(process);
        if let Err(response) = result {
            return Err(original_actor(service).err().unwrap_or(response));
        }
        self.check_warm(service)?;
        original_actor(service)?;
        Ok(output)
    }
}
