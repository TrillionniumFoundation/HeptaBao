//! Native paged V6 snapshot graph validation inside the existing Service owner.
//! No independent actor, public raw-storage API, or HA admission is introduced.
use super::*;
use crate::state_record_root::RecordStateRoot;
use crate::state_record_root_v6::{ObjectDomain, RecordStateRootV6};
use crate::state_records::{ObjectRef, RecordError};
use crate::v6_native_custody::OriginalDeadline;
use crate::v6_read_validation::{ObjectSource, ReadContext, ReadIdentity};
use heptabao_durable_service::PreparedV6Restore;
use std::cell::RefCell;
use std::io::{Read, Seek};

#[cfg(feature = "experimental-native-v6-ha")]
#[path = "service_snapshot_v6_ha.rs"]
mod ha;
#[cfg(feature = "experimental-native-v6-ha")]
pub(super) use ha::NativeHaHistoricalReceipt;
#[path = "service_native_v6_staging_repair.rs"]
mod staging_repair;
#[cfg(test)]
#[path = "service_snapshot_v6_test_observer.rs"]
mod test_observer;

// Redacted phase duration only: never request paths, identities or object bytes.
struct SnapshotPhaseObservation {
    phase: &'static str,
    started: Instant,
}
impl SnapshotPhaseObservation {
    fn enter(phase: &'static str) -> Self {
        Self {
            phase,
            started: Instant::now(),
        }
    }
}
impl Drop for SnapshotPhaseObservation {
    fn drop(&mut self) {
        let _ = writeln!(
            std::io::stderr(),
            "HBV6-SNAPSHOT-PHASE phase={} elapsed_ms={}",
            self.phase,
            self.started.elapsed().as_millis()
        );
    }
}

fn invalid() -> Response {
    Response::error(400, "V6 snapshot graph or source binding is invalid")
}
fn unavailable() -> Response {
    Response::error(503, "V6 snapshot original authority is unavailable")
}
fn storage_error(error: ServiceError) -> Response {
    match error {
        ServiceError::CorruptState
        | ServiceError::BarrierFailure
        | ServiceError::InvalidResource => invalid(),
        ServiceError::RequestCapacityExhausted => {
            Response::error(413, "V6 snapshot transport bound exceeded")
        }
        _ => unavailable(),
    }
}

// A selected object is read only from this prepared, authenticated input archive.
// Typed keys/grammar are checked by the actual V6 graph materializer, not inferred
// from an address string or an untrusted directory listing.
struct IncomingObjects<'a, R> {
    durable: &'a DurableService<AeadBarrier>,
    archive: RefCell<&'a mut PreparedV6Restore<R>>,
    root_bytes: &'a [u8],
    gate: RefCell<&'a mut dyn FnMut() -> Result<(), ServiceError>>,
    io_gate: RefCell<&'a mut dyn FnMut() -> Result<(), ServiceError>>,
}
impl<R: Read + Seek> ObjectSource for IncomingObjects<'_, R> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let mut gate = self
            .gate
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        gate().map_err(|_| RecordError::Invalid)?;
        let mut archive = self
            .archive
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        let resource = v6_records::native_resource(domain, reference);
        let slot = archive
            .state()
            .get("system", &resource)
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        native_blob_source::validate_archive_slot(self.root_bytes, slot, reference)?;
        let mut io_gate = self
            .io_gate
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        let bytes = self
            .durable
            .read_v6_restore_object_with_io_gate(
                &mut archive,
                &resource,
                &mut || gate(),
                &mut || io_gate(),
            )
            .map_err(|_| RecordError::Corrupt)?;
        gate().map_err(|_| RecordError::Invalid)?;
        if bytes.len() != reference.encoded_bytes as usize {
            return Err(RecordError::Corrupt);
        }
        Ok(bytes)
    }
}

// Only this module constructs this after authenticating the entire incoming
// native root and its full typed graph. Not Clone or serializable.
struct IncomingNative {
    archive: PreparedV6Restore<SnapshotFile>,
    state: State,
    root: RecordStateRootV6,
    digest: [u8; 32],
    source_generation: u64,
    source_replay_epoch: u64,
}

impl Service {
    fn check_v6_snapshot_owner(&self, plan: &SnapshotTransferPlan) -> Result<(), Response> {
        if Instant::now() >= plan.deadline
            || self.audit_failed
            || self.recovery_required
            || self.barrier_key.is_none()
            || self.unseal_nonce != plan.activation
            || self.ha.is_some()
            || plan.ha.is_some()
            || self.current_state_identity().ok() != Some(plan.base)
        {
            return Err(unavailable());
        }
        self.native_candidate_profile
            .as_ref()
            .ok_or_else(unavailable)?
            .check_environment(self)?;
        let state = self.state.as_ref().ok_or_else(unavailable)?;
        if !plan.actor.is_root() || !plan.namespace.is_empty() {
            return Err(Response::error(403, "permission denied"));
        }
        let now = snapshot_observed_time(plan.now, plan.started.elapsed());
        state
            .auth
            .authorize_request(
                &plan.actor,
                &plan.namespace,
                &plan.path,
                if plan.is_download { "read" } else { "update" },
                now,
            )
            .map_err(|e| Response::error(e.status, &e.message))?;
        if self.current_snapshot_seal_identity_for_plan(plan)? != plan.seal_identity {
            return Err(Response::error(409, "V6 snapshot live seal changed"));
        }
        if Instant::now() >= plan.deadline {
            return Err(unavailable());
        }
        Ok(())
    }

    // Preserve the original live denial/expiry rather than relabeling a late
    // request-gate failure as malformed archive bytes.
    fn v6_storage_failure(&self, plan: &SnapshotTransferPlan, error: ServiceError) -> Response {
        self.check_v6_snapshot_owner(plan)
            .err()
            .unwrap_or_else(|| storage_error(error))
    }

    pub(super) fn prepare_v6_snapshot_download(
        &mut self,
        plan: &mut SnapshotTransferPlan,
    ) -> Result<DownloadSource, Response> {
        #[cfg(feature = "experimental-native-v6-ha")]
        if self.ha.is_some() || plan.ha.is_some() {
            return self.prepare_native_ha_snapshot_download(plan);
        }
        self.check_v6_snapshot_owner(plan)?;
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let key = Zeroizing::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?);
        let mut durable = self.durable.take().ok_or_else(unavailable)?;
        let result = (|| {
            let profile = self
                .native_candidate_profile
                .as_ref()
                .ok_or_else(unavailable)?;
            let cold =
                native_v6_reader::load_cold_root(self, profile, &mut durable, &key, deadline)?
                    .ok_or_else(invalid)?;
            if cold.root.reader_floor.native_kv2_format != 2 {
                return Err(invalid());
            }
            Self::check_native_installed(
                self.state.as_ref().ok_or_else(unavailable)?,
                &cold.metadata,
                &cold.native,
                &cold.root,
                deadline,
            )?;
            self.check_v6_snapshot_owner(plan)?;
            let context = ReadContext {
                expected_identity: ReadIdentity::RecordsV6(
                    cold.root.identity().map_err(|_| invalid())?.digest(),
                ),
                cluster_id: &cold.root.cluster_id,
                replay_epoch: cold.root.replay_epoch,
                minimum_state_schema: cold.root.state_schema,
                maximum_state_schema: cold.root.state_schema,
                reader_format: crate::state_record_root_v6::READER_FORMAT,
            };
            {
                let source =
                    native_blob_source::NativeSource::new_checked(&mut durable, deadline, || {
                        self.check_v6_snapshot_owner(plan)
                            .map_err(|_| ServiceError::BarrierFailure)
                    })
                    .map_err(|_| invalid())?;
                // Unlike ordinary cold opening, export verifies every retained
                // selected payload, including keyed hashes and JSON descriptors.
                let (metadata, native) =
                    v6_records::materialize_for_service(&cold.root, context, &source)
                        .map_err(|_| invalid())?;
                Self::check_native_installed(
                    self.state.as_ref().ok_or_else(unavailable)?,
                    &metadata,
                    &native,
                    &cold.root,
                    deadline,
                )?;
            }
            let mut gate = || {
                self.check_v6_snapshot_owner(plan)
                    .map_err(|_| ServiceError::BarrierFailure)
            };
            let source = durable
                .prepare_v6_backup(&mut gate)
                .map_err(|error| self.v6_storage_failure(plan, error))?;
            let mut state = plan
                .lease
                .file(crate::snapshot_file::MAX_V6_SNAPSHOT_STATE, plan.deadline)
                .map_err(|_| unavailable())?;
            let mut output = snapshot_archive::HashWriter {
                writer: &mut state,
                hash: Sha256::new(),
            };
            // Full typed graph was just verified from the original live source;
            // the source-bound pack checks every current ciphertext again.
            let size = durable
                .export_v6_backup_to(source, &mut output, &mut gate, &mut |_, _| Ok(()))
                .map_err(|error| self.v6_storage_failure(plan, error))?;
            let digest: [u8; 32] = output.hash.finalize().into();
            let metadata = serde_json::to_vec(&Metadata::new_v6(
                size.generation,
                size.archive_bytes,
                &plan.seal_identity,
            ))
            .map_err(|_| invalid())?;
            let sums = snapshot_archive::sums(&metadata, &digest);
            let barrier = AeadBarrier::new(*key).map_err(|_| unavailable())?;
            let sealed_sums = barrier
                .seal(snapshot_archive::CHECKSUM_CONTEXT, &sums)
                .map_err(|_| unavailable())?;
            self.check_v6_snapshot_owner(plan)?;
            state.rewind_checked().map_err(|_| unavailable())?;
            Ok(DownloadSource {
                state,
                metadata,
                sums,
                sealed_sums,
            })
        })();
        self.durable = Some(durable);
        result
    }

    fn prepare_incoming_v6(
        &self,
        file: SnapshotFile,
        plan: &SnapshotTransferPlan,
    ) -> Result<IncomingNative, Response> {
        self.check_v6_snapshot_owner(plan)?;
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let length = file.len();
        let durable = self.durable.as_ref().ok_or_else(unavailable)?;
        let mut gate = || {
            self.check_v6_snapshot_owner(plan)
                .map_err(|_| ServiceError::BarrierFailure)
        };
        // A full Actor/ACL/live-seal check surrounds each selected ciphertext
        // object. Bounded physical reads retain the ORIGINAL deadline and
        // live in-memory stop state, never an authority to publish or decrypt.
        let mut bounded_archive_io_gate = || {
            if Instant::now() >= plan.deadline
                || self.audit_failed
                || self.recovery_required
                || self.barrier_key.is_none()
                || self.unseal_nonce != plan.activation
                || self.ha.is_some()
                || plan.ha.is_some()
                || self.current_state_identity().ok() != Some(plan.base)
            {
                return Err(ServiceError::BarrierFailure);
            }
            Ok(())
        };
        // The complete pack is authenticated before typed graph admission.
        let mut archive = {
            let _phase = SnapshotPhaseObservation::enter("authenticate-pack");
            durable
                .prepare_v6_restore_from_reader_with_io_gate(
                    file,
                    length,
                    &mut gate,
                    &mut bounded_archive_io_gate,
                    &mut |_, _, _| Ok(()),
                )
                .map_err(|error| self.v6_storage_failure(plan, error))?
        };
        let root_bytes = Zeroizing::new(
            archive
                .state()
                .get("system", "state")
                .map_err(|error| self.v6_storage_failure(plan, error))?
                .ok_or_else(invalid)?
                .to_vec(),
        );
        let root = RecordStateRootV6::decode(&root_bytes).map_err(|_| invalid())?;
        let current = self.state.as_ref().ok_or_else(unavailable)?;
        if root.reader_floor.native_kv2_format != 2
            || root.cluster_id != current.cluster_id
            || root.replay_epoch != archive.state().metadata().replay_epoch
            || root
                .kv2
                .iter()
                .any(|graph| !graph.scope.namespace.is_empty())
        {
            return Err(invalid());
        }
        let old = archive
            .state()
            .get("system", native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE)
            .map_err(|error| self.v6_storage_failure(plan, error))?
            .ok_or_else(invalid)?;
        let retained = RecordStateRoot::decode(old).map_err(|_| invalid())?;
        let cursor = archive
            .state()
            .get("system", native_v6_reader::ACTIVE_CURSOR_RESOURCE)
            .map_err(|error| self.v6_storage_failure(plan, error))?
            .ok_or_else(invalid)?;
        let cursor = native_v6_reader::NativeActiveCursor::decode(cursor)?;
        cursor.validate(&retained, &root, archive.state().metadata().generation)?;
        let digest = root.identity().map_err(|_| invalid())?.digest();
        let context = ReadContext {
            expected_identity: ReadIdentity::RecordsV6(digest),
            cluster_id: &root.cluster_id,
            replay_epoch: root.replay_epoch,
            minimum_state_schema: root.state_schema,
            maximum_state_schema: root.state_schema,
            reader_format: crate::state_record_root_v6::READER_FORMAT,
        };
        let (mut state, native) = {
            let _phase = SnapshotPhaseObservation::enter("validate-typed-graph");
            // The request is exclusively owned by this Service until terminal
            // completion: no other request can concurrently modify its auth,
            // state identity or seal owner. Do a FULL owner/ACL/physical-seal
            // check per selected object, rather than reopening seal.json for
            // every bounded 256 KiB I/O. The cheap I/O gate still tests the
            // ORIGINAL instant deadline and all in-memory stop conditions.
            // SnapshotFile separately checks the original deadline on seek/read.
            let mut bounded_io_gate = || {
                if Instant::now() >= plan.deadline
                    || self.audit_failed
                    || self.recovery_required
                    || self.barrier_key.is_none()
                    || self.unseal_nonce != plan.activation
                    || self.ha.is_some()
                    || plan.ha.is_some()
                    || self.current_state_identity().ok() != Some(plan.base)
                {
                    return Err(ServiceError::BarrierFailure);
                }
                Ok(())
            };
            let objects = IncomingObjects {
                durable,
                archive: RefCell::new(&mut archive),
                root_bytes: &root_bytes,
                gate: RefCell::new(&mut gate),
                io_gate: RefCell::new(&mut bounded_io_gate),
            };
            v6_records::materialize_for_service(&root, context, &objects).map_err(|_| invalid())?
        };
        state
            .engines
            .install_native_views(native)
            .map_err(Response::from_engine_error)?;
        self.require_native_root_candidate(&state)?;
        state.validate_format()?;
        // A real admitted request can advance the live monotone clock after
        // the snapshot was exported. Inherit ONLY the existing clock facts;
        // formats, token/credential catalogs, retirement, revocation and every
        // protected owner still have to pass their original successor checks.
        state
            .auth
            .inherit_native_snapshot_clocks(&current.auth)
            .map_err(|error| Response::error(400, &error.message))?;
        state
            .engines
            .inherit_native_snapshot_clocks(&current.engines)
            .map_err(Response::from_engine_error)?;
        Self::validate_snapshot_protected_floor(current, &state)?;
        if !state.database.is_empty() || state.engines.has_openldap_mount() {
            return Err(Response::error(
                409,
                "snapshot contains external provider identities",
            ));
        }
        let owner_bytes = root
            .owners
            .iter()
            .try_fold(0u64, |sum, owner| sum.checked_add(owner.owner.total_bytes))
            .ok_or_else(invalid)?;
        if owner_bytes > self.opaque_owner_limit() as u64 {
            return Err(Response::error(
                507,
                "native opaque owner capacity exhausted",
            ));
        }
        self.check_v6_snapshot_owner(plan)?;
        let source_generation = archive.size().generation;
        let source_replay_epoch = archive.state().metadata().replay_epoch;
        let target = durable
            .v6_restore_projection_target(&archive)
            .map_err(|error| self.v6_storage_failure(plan, error))?;
        // The archived label was checked above. A new checkpoint, strictly
        // after both frontiers, retires archived replay identities rather than
        // attaching a changed root to an old generation or request ledger.
        state.replay_epoch = target.1;
        let projected = {
            let _phase = SnapshotPhaseObservation::enter("derive-clock-bound-graph");
            let objects = IncomingObjects {
                durable,
                archive: RefCell::new(&mut archive),
                root_bytes: &root_bytes,
                gate: RefCell::new(&mut gate),
                io_gate: RefCell::new(&mut bounded_archive_io_gate),
            };
            v6_records::project_snapshot_native_root(
                &root,
                state,
                target.1,
                deadline,
                &objects,
                &mut || self.check_v6_snapshot_owner(plan),
            )
            .map_err(|error| self.check_v6_snapshot_owner(plan).err().unwrap_or(error))?
        };
        let owner_bytes = projected
            .root
            .owners
            .iter()
            .try_fold(0u64, |sum, owner| sum.checked_add(owner.owner.total_bytes))
            .ok_or_else(invalid)?;
        if owner_bytes > self.opaque_owner_limit() as u64 {
            return Err(Response::error(
                507,
                "native opaque owner capacity exhausted",
            ));
        }
        let next_cursor = cursor.advance(&projected.root, target.0)?;
        next_cursor.validate(&retained, &projected.root, target.0)?;
        let objects = projected
            .objects
            .iter()
            .map(|((domain, _), object)| {
                Ok((
                    v6_records::native_resource(domain, object.reference()),
                    Secret::new(object.bytes().to_vec())?,
                ))
            })
            .collect::<Result<Vec<_>, ServiceError>>()
            .map_err(|error| self.v6_storage_failure(plan, error))?;
        durable
            .project_v6_restore_before_install(
                &mut archive,
                target,
                &root_bytes,
                Secret::new(projected.bytes.to_vec())
                    .map_err(|error| self.v6_storage_failure(plan, error))?,
                Secret::new(next_cursor.encode()?.to_vec())
                    .map_err(|error| self.v6_storage_failure(plan, error))?,
                objects,
                &mut gate,
            )
            .map_err(|error| self.v6_storage_failure(plan, error))?;
        let digest = projected.root.identity().map_err(|_| invalid())?.digest();
        self.check_v6_snapshot_owner(plan)?;
        Ok(IncomingNative {
            archive,
            state: projected.candidate,
            root: projected.root,
            digest,
            source_generation,
            source_replay_epoch,
        })
    }

    pub(super) fn finish_v6_snapshot_upload(
        &mut self,
        imported: Import,
        plan: &SnapshotTransferPlan,
        live_seal: [u8; 32],
    ) -> Response {
        let prepared = (|| {
            self.check_v6_snapshot_owner(plan)?;
            if !imported.metadata.is_v6() {
                return Err(invalid());
            }
            let binding = imported.metadata.seal_identity().ok_or_else(invalid)?;
            let barrier = AeadBarrier::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
            let sums = Zeroizing::new(
                barrier
                    .open(snapshot_archive::CHECKSUM_CONTEXT, &imported.sealed_sums)
                    .map_err(|_| invalid())?,
            );
            if sums.as_slice() != imported.sums.as_slice() || !binding.matches(&live_seal) {
                return Err(invalid());
            }
            let expected_generation = imported.metadata.generation();
            let prepared = self.prepare_incoming_v6(imported.state, plan)?;
            if prepared.archive.size().generation != expected_generation
                || prepared.source_generation != expected_generation
            {
                return Err(invalid());
            }
            Ok(prepared)
        })();
        let prepared = match prepared {
            Ok(value) => value,
            Err(error) => return error,
        };
        self.commit_incoming_v6(prepared, plan)
    }

    fn commit_incoming_v6(
        &mut self,
        prepared: IncomingNative,
        plan: &SnapshotTransferPlan,
    ) -> Response {
        if let Err(error) = self.check_v6_snapshot_owner(plan) {
            return error;
        }
        let next_activation = match crypto::random::<16>() {
            Ok(value) => hex(&value),
            Err(_) => return unavailable(),
        };
        let mut durable = match self.durable.take() {
            Some(value) => value,
            None => return unavailable(),
        };
        let phase = SnapshotPhaseObservation::enter("stage-objects-and-commit");
        let result = durable.restore_v6_prepared_with_io_gate(
            prepared.archive,
            true,
            &mut || {
                self.check_v6_snapshot_owner(plan)
                    .map_err(|_| ServiceError::BarrierFailure)
            },
            &mut || {
                // The original request deadline and all live stop state are
                // tested on each bounded seek/read. FULL seal/Actor/ACL checks
                // still surround each object, publication and terminal root.
                if Instant::now() >= plan.deadline
                    || self.audit_failed
                    || self.recovery_required
                    || self.barrier_key.is_none()
                    || self.unseal_nonce != plan.activation
                    || self.ha.is_some()
                    || plan.ha.is_some()
                    || self.current_state_identity().ok() != Some(plan.base)
                {
                    return Err(ServiceError::BarrierFailure);
                }
                Ok(())
            },
        );
        drop(phase);
        let fenced = durable.recovery_required();
        self.durable = Some(durable);
        let outcome = match result {
            Ok(value) => value,
            Err(error) => {
                if fenced {
                    self.recovery_required = true;
                    self.ha_activation = None;
                }
                return self.v6_storage_failure(plan, error);
            }
        };
        // Only infallible moves follow canonical publication. The validated
        // native view is installed rather than re-decoding under a new budget.
        let replay_epoch = prepared.state.replay_epoch;
        self.state = Some(prepared.state);
        self.record_root = None;
        self.native_root = Some(prepared.root);
        self.state_digest = Some(prepared.digest);
        self.unseal_nonce = next_activation;
        self.record_writes_since_gc = 64;
        self.ha_read_cache = None;
        self.recovery_required = false;
        #[cfg(test)]
        test_observer::committed(self);
        Response::ok(
            json!({"data":{"previous_generation":outcome.previous_generation,
            "restored_generation":outcome.restored_generation,"retained_requests":outcome.retained_requests,
            "source_generation":prepared.source_generation,
            "source_replay_epoch":prepared.source_replay_epoch,"replay_epoch":replay_epoch,
            "rollback":prepared.source_generation<outcome.previous_generation}}),
        )
    }
}

#[cfg(test)]
#[path = "service_snapshot_v6_tests.rs"]
mod tests;
