//! Historical data restoration under the original live snapshot Actor.
//! Restores do not install an archive ledger, captured Raft state or epoch.
//! The complete local pack is decoded, protected clocks inherit live floors,
//! and an actual Begin/Stage/fsync-quorum/CAS publishes a new root and epoch.
use super::*;
use crate::engines::kv2_native_records::PagedPayloadValidationMemo;
use crate::ha::native_v6_backup::{
    ColdNativeV6ArchiveFacts, HistoricalNativeV6ArchiveFacts, NativeV6ArchiveError,
    NativeV6ArchiveSelection, validate_cold_native_v6_archive,
    validate_historical_native_v6_archive,
};
use crate::ha_state::native_v6::NativeV6CodecError;
#[cfg(feature = "private-ha-forward-diagnostic")]
use crate::service::native_v6_ha_install::NativeHaPhaseTimer;
use crate::service::native_v6_ha_install::{BorrowedArchiveRepairSource, NativeHaReadProof};
use std::cell::Cell;

// Force permits authenticated old DATA from another membership lineage. It
// never turns that lineage into a current Raft proof. The original live Actor,
// barrier, cluster, next-epoch transaction and every publication gate remain
// mandatory. Cross-seal recovery is not admitted by this same-barrier path.
enum RestoreArchiveFacts {
    Historical(HistoricalNativeV6ArchiveFacts),
    Cold(ColdNativeV6ArchiveFacts),
}
impl RestoreArchiveFacts {
    fn replay_epoch(&self) -> u64 {
        match self {
            Self::Historical(facts) => facts.replay_epoch(),
            Self::Cold(facts) => facts.replay_epoch(),
        }
    }
    fn root_digest(&self) -> [u8; 32] {
        match self {
            Self::Historical(facts) => facts.root_digest(),
            Self::Cold(facts) => facts.root_digest(),
        }
    }
}

/// Affine ownership of THIS completed restore before terminal-clock/audit.
/// Only the actual successful coordinator plus local epoch installation and
/// fresh business proof can construct it. Original Actor/Auth are retained
/// separately from the newly installed historical Auth owner.
pub(in crate::service::snapshot_transfer) struct NativeHaHistoricalReceipt {
    operation_digest: [u8; 32],
    original_auth: CowOwner<AuthState>,
    original_identity: StateIdentity,
    original_activation: String,
    restored_identity: StateIdentity,
    restored_generation: plugin::PublicationGeneration,
    restored_epoch: u64,
    restored_activation: String,
    proof: NativeHaReadProof,
}

// An operation reference identifies the actual Raft restore transition. It is
// retained through local installation and response audit, and grants no retry
// or restore authority to a caller that receives an uncertain outcome.
fn historical_recovery_reference(operation: [u8; 32]) -> String {
    format!("native-v6-restore-{}", hex(&operation))
}

// An archive object remains data even after authentication. Every selected
// read checks the original live journal owner before and after its immutable
// source borrow. Cipher staging occurs only after this borrow has ended, so
// its callbacks retain the actual mutable Durable owner on every shared I/O.
struct HistoricalObjects<'a> {
    owner: &'a BorrowedNativeHaSnapshotOwner<'a>,
    source: &'a BorrowedArchiveRepairSource<'a>,
    durable: &'a RefCell<DurableService<AeadBarrier>>,
    archive: RefCell<&'a mut PreparedV6Restore<SnapshotFile>>,
    root_bytes: &'a [u8],
}
impl HistoricalObjects<'_> {
    fn gate(&self) -> Result<(), ServiceError> {
        self.owner
            .check()
            .map_err(|_| ServiceError::BarrierFailure)?;
        self.source
            .check_taken(
                &mut *self
                    .durable
                    .try_borrow_mut()
                    .map_err(|_| ServiceError::BarrierFailure)?,
            )
            .map_err(|_| ServiceError::BarrierFailure)
    }
}
impl ObjectSource for HistoricalObjects<'_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.gate().map_err(|_| RecordError::Invalid)?;
        let result = {
            let durable = self
                .durable
                .try_borrow()
                .map_err(|_| RecordError::Invalid)?;
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
            let mut gate = || self.owner.check().map_err(|_| ServiceError::BarrierFailure);
            let mut io_gate = || {
                self.owner
                    .check_io()
                    .map_err(|_| ServiceError::BarrierFailure)
            };
            durable
                .read_v6_restore_object_with_io_gate(
                    &mut archive,
                    &resource,
                    &mut gate,
                    &mut io_gate,
                )
                .map_err(|_| RecordError::Corrupt)?
        };
        #[cfg(test)]
        if !result.is_empty() && result.len() == reference.encoded_bytes as usize {
            historical_prepare_observer::after_archive_object_read(
                self.owner.service,
                &self.owner.plan.actor,
                self.owner.plan.base,
                self.owner.plan.deadline,
            );
        }
        self.gate().map_err(|_| RecordError::Invalid)?;
        if result.len() != reference.encoded_bytes as usize {
            return Err(RecordError::Corrupt);
        }
        Ok(result)
    }
}

fn archive_error(error: NativeV6ArchiveError) -> Response {
    match error {
        NativeV6ArchiveError::WrongSelection => Response::error(
            400,
            "historical archive belongs to different cluster, seal or replay history",
        ),
        NativeV6ArchiveError::Invalid | NativeV6ArchiveError::Corrupt => invalid(),
        NativeV6ArchiveError::TooLarge => {
            Response::error(413, "historical archive exceeds its bound")
        }
        _ => unavailable(),
    }
}
fn actor_original(auth: &AuthState, plan: &SnapshotTransferPlan) -> Result<(), Response> {
    if Instant::now() >= plan.deadline
        || plan.is_download
        || !matches!(plan.method.as_str(), "POST" | "PUT")
        || !matches!(
            plan.path.as_str(),
            "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
        )
        || !plan.namespace.is_empty()
    {
        return Err(unavailable());
    }
    auth.authorize_request(
        &plan.actor,
        &plan.namespace,
        &plan.path,
        "update",
        snapshot_observed_time(plan.now, plan.started.elapsed()),
    )
    .map_err(|error| Response::error(error.status, &error.message))
}

impl Service {
    #[cfg(test)]
    pub(in crate::service) fn observe_historical_prepare_original_source_once(
        &self,
        until: Instant,
        callback: impl FnOnce(&Service, &crate::auth::Principal, StateIdentity, Instant) + 'static,
    ) -> Result<historical_prepare_observer::Scope, Response> {
        Ok(historical_prepare_observer::arm(
            historical_prepare_observer::Stage::BeforeSource,
            self.current_state_identity()?,
            until,
            callback,
        ))
    }

    #[cfg(test)]
    pub(in crate::service) fn observe_historical_prepare_archive_read_once(
        &self,
        until: Instant,
        callback: impl FnOnce(&Service, &crate::auth::Principal, StateIdentity, Instant) + 'static,
    ) -> Result<historical_prepare_observer::Scope, Response> {
        Ok(historical_prepare_observer::arm(
            historical_prepare_observer::Stage::AfterArchiveObjectRead,
            self.current_state_identity()?,
            until,
            callback,
        ))
    }

    pub(in crate::service::snapshot_transfer) fn prepare_native_ha_historical_upload(
        &mut self,
        plan: &mut SnapshotTransferPlan,
    ) -> Result<(), Response> {
        self.check_native_ha_snapshot_owner(plan)?;
        if plan.is_download
            || !matches!(
                plan.path.as_str(),
                "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
            )
            || plan.native_ha_restore_source.is_some()
            || plan.native_ha_repair.is_some()
        {
            return Err(unavailable());
        }
        // This occurs after ordinary authentication and any real finite-use
        // debit. It captures that new current source; never revives old uses.
        let source = self.capture_native_ha_archive_repair_source()?;
        self.check_native_ha_snapshot_owner(plan)?;
        source.check_local(self)?;
        plan.native_ha_restore_source = Some(source);
        Ok(())
    }

    pub(in crate::service::snapshot_transfer) fn finish_native_ha_pending_restore_reconciliation(
        &mut self,
        plan: &mut SnapshotTransferPlan,
        result: Result<Observation, Response>,
    ) -> Response {
        let checked = (|| -> Result<Response, Response> {
            self.check_native_ha_snapshot_owner(plan)?;
            if plan.is_download
                || plan.path != "sys/storage/raft/snapshot"
                || plan.native_ha_source.is_some()
                || plan.native_ha_restored.is_some()
                || plan.native_ha_repair.is_some()
            {
                return Err(unavailable());
            }
            let request = plan.native_ha_pending_restore.ok_or_else(unavailable)?;
            if !matches!(result?, Observation::PendingRestore) {
                return Err(Response::error(
                    400,
                    "pending restore reconciliation requires an empty body",
                ));
            }
            let source = plan
                .native_ha_restore_source
                .take()
                .ok_or_else(unavailable)?;
            let (proof, outcome, observed_pending) =
                source.reconcile_pending_restore(self, request.operation(), &mut |service| {
                    service.check_native_ha_snapshot_owner(plan)
                })?;
            self.check_native_ha_snapshot_owner(plan)?;
            let epoch = self.state.as_ref().ok_or_else(unavailable)?.replay_epoch;
            // Use the existing unchanged-root snapshot response custody through
            // terminal-clock persistence, mandatory audit and the original
            // live Actor check. This operation never creates a restore receipt.
            plan.native_ha_source = Some(proof);
            Ok(Response::ok(json!({"data":{
                "recovery_reference":request.operation().or(observed_pending).map(historical_recovery_reference),
                "state":outcome, "cancelled":outcome == "cancelled",
                "restore_performed":false, "replay_epoch":epoch,
                "selected_root":hex(&plan.base.digest()),
            }, "retry_allowed":false, "restore_performed":false})))
        })();
        checked.unwrap_or_else(|error| error)
    }

    pub(in crate::service::snapshot_transfer) fn finish_native_ha_historical_upload(
        &mut self,
        plan: &mut SnapshotTransferPlan,
        result: Result<Observation, Response>,
    ) -> Response {
        let root_attempted = Cell::new(false);
        let operation_reference = Cell::new(None);
        let checked = (|| -> Result<Response, Response> {
            self.check_native_ha_snapshot_owner(plan)?;
            if plan.is_download
                || !matches!(
                    plan.path.as_str(),
                    "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
                )
                || plan.native_ha_source.is_some()
                || plan.native_ha_restored.is_some()
                || plan.native_ha_pending_restore.is_some()
            {
                return Err(unavailable());
            }
            let source = plan
                .native_ha_restore_source
                .take()
                .ok_or_else(unavailable)?;
            source.check_local(self)?;
            let imported = match result? {
                Observation::Upload(imported) => imported,
                _ => return Err(unavailable()),
            };
            if !imported.metadata.is_v6_ha() {
                return Err(invalid());
            }
            let binding = imported.metadata.seal_identity().ok_or_else(invalid)?;
            if !binding.matches(&plan.seal_identity) {
                return Err(invalid());
            }
            let barrier = AeadBarrier::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
            let sums = Zeroizing::new(
                barrier
                    .open(snapshot_archive::CHECKSUM_CONTEXT, &imported.sealed_sums)
                    .map_err(|_| invalid())?,
            );
            if sums.as_slice() != imported.sums.as_slice() {
                return Err(invalid());
            }
            let original_auth = self.state.as_ref().ok_or_else(unavailable)?.auth.clone();
            actor_original(&original_auth, plan)?;
            let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
            let next_epoch = source
                .restore_anchor()
                .enrollment()
                .epoch()
                .checked_add(1)
                .ok_or_else(|| Response::error(507, "native replay epoch exhausted"))?;
            let current_selection = NativeV6ArchiveSelection::from_committed(
                source.restore_anchor().enrollment(),
                source.restore_anchor().published(),
            )
            .map_err(archive_error)?;
            // Request-local pure semantics only. Preparation and installation
            // independently reopen/authenticate their current objects, source,
            // keyed payload digest and all original live authority gates.
            let payload_validation = RefCell::new(PagedPayloadValidationMemo::default());
            let durable = RefCell::new(self.durable.take().ok_or_else(unavailable)?);
            let prepared = (|| {
                // Keep this proof inside the existing result scope so every
                // refusal restores the same taken Durable owner below. Only
                // ordinary in-memory values are fixed by its shared borrow;
                // all original caller and external-state gates remain live.
                let borrowed_source = source.borrow_for_prepare(self)?;
                let borrowed_owner = BorrowedNativeHaSnapshotOwner::capture(self, plan)?;
                let mut original = || {
                    borrowed_owner.check()?;
                    actor_original(&original_auth, plan)?;
                    #[cfg(test)]
                    historical_prepare_observer::before_source(
                        self,
                        &plan.actor,
                        plan.base,
                        plan.deadline,
                    );
                    borrowed_source
                        .check_taken(&mut *durable.try_borrow_mut().map_err(|_| unavailable())?)
                };
                original()?;
                #[cfg(feature = "private-ha-forward-diagnostic")]
                let phase = NativeHaPhaseTimer::start(
                    "historical_restore_validate_archive",
                    plan.deadline,
                    0,
                    0,
                    0,
                );
                let (mut archive, facts) = if plan.path == "sys/storage/raft/snapshot-force" {
                    let (archive, facts) = validate_cold_native_v6_archive(
                        imported.state,
                        plan.seal_identity,
                        &barrier,
                        deadline,
                        &mut || original().map_err(|_| NativeV6ArchiveError::Gate),
                    )
                    .map_err(archive_error)?;
                    (archive, RestoreArchiveFacts::Cold(facts))
                } else {
                    let (archive, facts) = validate_historical_native_v6_archive(
                        imported.state,
                        &current_selection,
                        plan.seal_identity,
                        &barrier,
                        deadline,
                        &mut || original().map_err(|_| NativeV6ArchiveError::Gate),
                    )
                    .map_err(archive_error)?;
                    (archive, RestoreArchiveFacts::Historical(facts))
                };
                #[cfg(feature = "private-ha-forward-diagnostic")]
                phase.finish(true);
                if archive.report().local.generation != imported.metadata.generation() {
                    return Err(invalid());
                }
                let imported_generation = archive.report().local.generation;
                #[cfg(feature = "private-ha-forward-diagnostic")]
                let phase = NativeHaPhaseTimer::start(
                    "historical_restore_local_pack_copy",
                    plan.deadline,
                    imported_generation,
                    0,
                    0,
                );
                let mut local_pack = plan
                    .lease
                    .file(crate::snapshot_file::MAX_V6_SNAPSHOT_STATE, plan.deadline)
                    .map_err(|_| unavailable())?;
                archive
                    .copy_local_pack_to(&mut local_pack, &mut || {
                        original().map_err(|_| NativeV6ArchiveError::Gate)
                    })
                    .map_err(archive_error)?;
                local_pack.rewind_checked().map_err(|_| unavailable())?;
                let length = local_pack.len();
                original()?;
                #[cfg(feature = "private-ha-forward-diagnostic")]
                phase.finish(true);
                #[cfg(feature = "private-ha-forward-diagnostic")]
                let phase = NativeHaPhaseTimer::start(
                    "historical_restore_authenticate_local_pack",
                    plan.deadline,
                    imported_generation,
                    0,
                    length,
                );
                let mut local = {
                    // The journal owner is held across the complete incoming
                    // pack authentication. This read performs no local write.
                    let durable = durable.try_borrow().map_err(|_| unavailable())?;
                    let mut gate = || {
                        borrowed_owner
                            .check()
                            .map_err(|_| ServiceError::BarrierFailure)
                    };
                    let mut io_gate = || {
                        borrowed_owner
                            .check_io()
                            .map_err(|_| ServiceError::BarrierFailure)
                    };
                    durable
                        .prepare_v6_restore_from_reader_with_io_gate(
                            local_pack,
                            length,
                            &mut gate,
                            &mut io_gate,
                            &mut |_, _, _| Ok(()),
                        )
                        .map_err(storage_error)?
                };
                original()?;
                #[cfg(feature = "private-ha-forward-diagnostic")]
                phase.finish(true);
                let root_bytes = Zeroizing::new(
                    local
                        .state()
                        .get("system", "state")
                        .map_err(storage_error)?
                        .ok_or_else(invalid)?
                        .to_vec(),
                );
                let root = RecordStateRootV6::decode(&root_bytes).map_err(|_| invalid())?;
                if local.state().metadata().generation != imported_generation
                    || local.state().metadata().replay_epoch != facts.replay_epoch()
                    || root.identity().map_err(|_| invalid())?.digest() != facts.root_digest()
                    || root.replay_epoch != facts.replay_epoch()
                    || root.reader_floor.native_kv2_format != 2
                    || root.cluster_id != self.state.as_ref().ok_or_else(unavailable)?.cluster_id
                    || (root.state_schema < NATIVE_PLAIN_NAMESPACE_STATE_SCHEMA
                        && root
                            .kv2
                            .iter()
                            .any(|graph| !graph.scope.namespace.is_empty()))
                {
                    return Err(invalid());
                }
                let retained = RecordStateRoot::decode(
                    local
                        .state()
                        .get("system", native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE)
                        .map_err(storage_error)?
                        .ok_or_else(invalid)?,
                )
                .map_err(|_| invalid())?;
                let active_cursor = local
                    .state()
                    .get("system", native_v6_reader::ACTIVE_CURSOR_RESOURCE)
                    .map_err(storage_error)?
                    .ok_or_else(invalid)?;
                let ha_cursor = local
                    .state()
                    .get(
                        "system",
                        crate::service::native_v6_ha_install::HA_CURSOR_RESOURCE,
                    )
                    .map_err(storage_error)?
                    .ok_or_else(invalid)?;
                match &facts {
                    RestoreArchiveFacts::Historical(facts) => {
                        crate::service::native_v6_ha_install::validate_historical_archive_cursor(
                            &root,
                            &retained,
                            active_cursor,
                            ha_cursor,
                            imported_generation,
                            source.restore_anchor().published().native_origin_epoch(),
                            facts,
                        )?;
                    }
                    RestoreArchiveFacts::Cold(facts) => {
                        crate::service::native_v6_ha_install::validate_cold_archive_cursor(
                            &root,
                            &retained,
                            active_cursor,
                            ha_cursor,
                            imported_generation,
                            facts,
                        )?;
                    }
                }
                #[cfg(feature = "private-ha-forward-diagnostic")]
                let phase = NativeHaPhaseTimer::start(
                    "historical_restore_typed_graph",
                    plan.deadline,
                    imported_generation,
                    0,
                    length,
                );
                let objects = HistoricalObjects {
                    owner: &borrowed_owner,
                    source: &borrowed_source,
                    durable: &durable,
                    archive: RefCell::new(&mut local),
                    root_bytes: &root_bytes,
                };
                let context = ReadContext {
                    expected_identity: ReadIdentity::RecordsV6(facts.root_digest()),
                    cluster_id: &root.cluster_id,
                    replay_epoch: root.replay_epoch,
                    minimum_state_schema: root.state_schema,
                    maximum_state_schema: root.state_schema,
                    reader_format: crate::state_record_root_v6::READER_FORMAT,
                };
                // Every traversal reads the actual historical objects,
                // authenticates all blocks and checks the full keyed payload
                // digest under its current owner format and original live gates.
                let (mut incoming, native) =
                    v6_records::materialize_for_service_with_payload_validation(
                        &root,
                        context,
                        &objects,
                        &payload_validation,
                    )
                    .map_err(|_| invalid())?;
                incoming
                    .engines
                    .install_native_views(native)
                    .map_err(Response::from_engine_error)?;
                incoming.validate_format()?;
                self.require_native_root_candidate(&incoming)?;
                #[cfg(feature = "private-ha-forward-diagnostic")]
                phase.finish(true);
                let current = self.state.as_ref().ok_or_else(unavailable)?;
                if !current.database.is_empty()
                    || current.engines.has_openldap_mount()
                    || !incoming.database.is_empty()
                    || incoming.engines.has_openldap_mount()
                    || *incoming.raft_admin != *current.raft_admin
                {
                    return Err(Response::error(
                        409,
                        "historical restore cannot replace external providers or live Raft administration",
                    ));
                }
                original()?;
                #[cfg(feature = "private-ha-forward-diagnostic")]
                let phase = NativeHaPhaseTimer::start(
                    "historical_restore_project_root",
                    plan.deadline,
                    imported_generation,
                    0,
                    length,
                );
                // Only authenticated LIVE current clock floors enter this
                // merge. Format labels, catalogs, retirement/tombstone owners
                // and every original successor guard remain unchanged. In
                // particular an old schema is never normalized past a guard.
                incoming
                    .auth
                    .inherit_native_snapshot_clocks(&current.auth)
                    .map_err(|error| Response::error(error.status, &error.message))?;
                incoming
                    .engines
                    .inherit_native_snapshot_clocks(&current.engines)
                    .map_err(Response::from_engine_error)?;
                incoming.validate_format()?;
                // The same fully authenticated config-only exception retains
                // only the actual live global KV2 producer floor. The HA
                // projection still needs its original Actor/Raft conditions,
                // fresh epoch and every protected successor check below.
                let _retained_empty_floor = v6_records::retain_empty_snapshot_kv2_floor(
                    &root,
                    &mut incoming,
                    current,
                    deadline,
                    &mut original,
                )?;
                Self::validate_snapshot_protected_floor(current, &incoming)?;
                incoming.schema = incoming.writer_schema();
                incoming.replay_epoch = next_epoch;
                incoming.auth.discard_restored_oidc_sessions();
                incoming.validate_format()?;
                let candidate = v6_records::prepare_historical_native_root(
                    &root,
                    incoming,
                    v6_records::HistoricalProjectionTarget {
                        next_epoch,
                        source_generation: source.restore_generation(),
                        conditions: source.restore_conditions(),
                        deadline,
                    },
                    &objects,
                    &mut original,
                    &payload_validation,
                )?;
                #[cfg(feature = "private-ha-forward-diagnostic")]
                phase.finish(true);
                let owner_bytes = candidate
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
                let digest = candidate.root.identity().map_err(|_| invalid())?.digest();
                original()?;
                let ha = plan.ha.as_ref().ok_or_else(unavailable)?;
                let process = ha.lock_for_request().map_err(|_| unavailable())?;
                #[cfg(feature = "private-ha-forward-diagnostic")]
                let phase = NativeHaPhaseTimer::start(
                    "historical_restore_publish_epoch",
                    plan.deadline,
                    imported_generation,
                    0,
                    length,
                );
                let published = process.publish_native_v6_historical_restore(
                    source.restore_anchor(),
                    digest,
                    |codec, enrollment, store, gate| {
                        crate::service::native_v6_ha_objects::prepare_native_v6_ha_objects_with_payload_validation(
                            &candidate,
                            crate::service::native_v6_ha_objects::NativeV6ObjectStorage { codec, store },
                            enrollment,
                            Some(&objects),
                            None,
                            &mut || gate(),
                            Some(&payload_validation),
                        )
                    },
                    &mut || original().map_err(|_| NativeV6CodecError::Gate),
                );
                #[cfg(feature = "private-ha-forward-diagnostic")]
                phase.finish(published.is_ok());
                let committed = published.map_err(|error| {
                    root_attempted.set(error.root_attempted());
                    operation_reference.set(error.operation_digest());
                    Response {
                        status: 503,
                        body: json!({"errors":[error.to_string()],
                        "recovery_reference":error.reference_id(), "retry_allowed":false,
                        "root_attempted":error.root_attempted()}),
                        unwrapped_json: None,
                        response_headers: Default::default(),
                        consistency_index: None,
                    }
                })?;
                root_attempted.set(true);
                let operation = committed.published().intent().operation_digest;
                operation_reference.set(Some(operation));
                original()?;
                borrowed_source.check_complete()?;
                borrowed_owner.check_complete()?;
                Ok((committed, digest, imported_generation, operation))
            })();
            // The original affine Durable owner returns on EVERY path.
            self.durable = Some(durable.into_inner());
            let (committed, digest, imported_generation, operation) = prepared?;
            source.check_local(self)?;
            self.check_native_ha_snapshot_owner(plan)?;
            let ha = plan.ha.as_ref().ok_or_else(unavailable)?.clone();
            #[cfg(feature = "private-ha-forward-diagnostic")]
            let phase = NativeHaPhaseTimer::start(
                "historical_restore_local_install",
                plan.deadline,
                imported_generation,
                0,
                0,
            );
            self.sync_native_v6_from_ha_with_payload_validation(
                &ha,
                committed,
                &mut |_| actor_original(&original_auth, plan),
                &payload_validation,
            )?;
            drop(payload_validation);
            #[cfg(feature = "private-ha-forward-diagnostic")]
            phase.finish(true);
            actor_original(&original_auth, plan)?;
            if self.unseal_nonce == plan.activation
                || self.current_state_identity()? != StateIdentity::RecordsV6(digest)
                || self.state.as_ref().ok_or_else(unavailable)?.replay_epoch != next_epoch
            {
                return Err(unavailable());
            }
            let proof = self
                .capture_native_ha_request_proof(&mut || actor_original(&original_auth, plan))?
                .ok_or_else(unavailable)?;
            proof.check_warm(self)?;
            actor_original(&original_auth, plan)?;
            let generation = self.external_effect_generation()?;
            let published_local_generation =
                self.durable.as_ref().ok_or_else(unavailable)?.generation();
            let receipt = NativeHaHistoricalReceipt {
                operation_digest: operation,
                original_auth,
                original_identity: plan.base,
                original_activation: plan.activation.clone(),
                restored_identity: StateIdentity::RecordsV6(digest),
                restored_generation: generation,
                restored_epoch: next_epoch,
                restored_activation: self.unseal_nonce.clone(),
                proof,
            };
            self.check_native_ha_historical_delivery(plan, &receipt, receipt.restored_identity)?;
            plan.native_ha_restored = Some(receipt);
            Ok(Response::ok(
                json!({"data":{ "imported_generation":imported_generation,
                "previous_local_generation":source.restore_generation(),
                "published_local_generation":published_local_generation, "replay_epoch":next_epoch,
                "restored_root":hex(&digest), "cluster_coordinated":true }}),
            ))
        })();
        plan.native_ha_restore_attempt = operation_reference
            .get()
            .map(|operation| (operation, root_attempted.get()));
        match checked {
            Ok(response) => response,
            Err(mut error) => {
                if root_attempted.get() {
                    self.recovery_required = true;
                    self.ha_activation = None;
                    self.ha_read_cache = None;
                    if let Some(body) = error.body.as_object_mut() {
                        body.insert("recovery_required".into(), json!(true));
                        body.insert("retry_allowed".into(), json!(false));
                        body.insert("root_attempted".into(), json!(true));
                        if let Some(operation) = operation_reference.get() {
                            body.insert(
                                "recovery_reference".into(),
                                json!(historical_recovery_reference(operation)),
                            );
                        }
                    }
                }
                error
            }
        }
    }

    fn check_native_ha_historical_delivery(
        &self,
        plan: &SnapshotTransferPlan,
        restored: &NativeHaHistoricalReceipt,
        expected: StateIdentity,
    ) -> Result<(), Response> {
        let same_ha = match (&plan.ha, &self.ha) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        };
        if !same_ha
            || plan.base != restored.original_identity
            || plan.activation != restored.original_activation
            || restored.original_activation == restored.restored_activation
            || self.unseal_nonce != restored.restored_activation
            || self.current_state_identity().ok() != Some(expected)
            || self
                .state
                .as_ref()
                .is_none_or(|state| state.replay_epoch != restored.restored_epoch)
            || self
                .durable
                .as_ref()
                .is_none_or(|durable| durable.replay_epoch() != restored.restored_epoch)
            || self.audit_failed
            || self.recovery_required
            || self.barrier_key.is_none()
            || self.native_root.is_none()
            || self.record_root.is_some()
            || self.postgres_durable.is_some()
            || self.durable_profile.is_some()
            || self.openbao_wrapper_owner.is_some()
            || self.native_candidate_profile.is_some()
            || Instant::now() >= plan.deadline
        {
            return Err(unavailable());
        }
        actor_original(&restored.original_auth, plan)?;
        if self.current_snapshot_seal_identity_for_plan(plan)? != plan.seal_identity {
            return Err(unavailable());
        }
        actor_original(&restored.original_auth, plan)
    }

    pub(in crate::service::snapshot_transfer) fn complete_native_ha_historical_delivery(
        &mut self,
        plan: &SnapshotTransferPlan,
        mut response: Response,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
    ) -> Response {
        let restored = match plan.native_ha_restored.as_ref() {
            Some(restored) => restored,
            None => return unavailable(),
        };
        let checkpoint = (restored.restored_identity, restored.restored_generation);
        if response.status < 400
            && (self.external_effect_generation().ok() != Some(checkpoint.1)
                || self
                    .check_native_ha_historical_delivery(plan, restored, checkpoint.0)
                    .is_err())
        {
            response = unavailable();
        }
        // The SAME admitted RequestClock commits before the mandatory response
        // audit. Its affine receipt may authorize only this observation-only
        // successor; it cannot manufacture another historical restore epoch.
        let (mut response, clock_receipt) = self.audit_completed_response_with_clock_receipt(
            fingerprint,
            clock,
            response,
            || {},
            true,
        );
        let checked: Result<(), Response> = (|| {
            // The epoch/root has already committed. An audit, clock or final
            // original-owner failure is an uncertain delivery, never evidence
            // that the historical restore had no effect or may be retried.
            if response.status >= 400 {
                return Err(unavailable());
            }
            if let Some(receipt) = clock_receipt {
                let terminal = receipt.bind_native_snapshot(checkpoint)?;
                if self.external_effect_generation()? != terminal.1 {
                    return Err(unavailable());
                }
                self.check_native_ha_historical_delivery(plan, restored, terminal.0)?;
                let current = self
                    .capture_native_ha_request_proof(&mut || {
                        actor_original(&restored.original_auth, plan)
                    })?
                    .ok_or_else(unavailable)?;
                restored
                    .proof
                    .check_snapshot_terminal_successor(self, &current)?;
                self.check_native_ha_historical_delivery(plan, restored, terminal.0)?;
            } else {
                if self.external_effect_generation()? != checkpoint.1 {
                    return Err(unavailable());
                }
                restored
                    .proof
                    .check_with(self, Service::check_native_installed)?;
                self.check_native_ha_historical_delivery(plan, restored, checkpoint.0)?;
            }
            Ok(())
        })();
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            let _ = self.audit_event(
                "native-ha-historical-restore-delivery-veto",
                fingerprint,
                snapshot_observed_time(plan.now, plan.started.elapsed()),
                Some(error.status),
            );
            self.recovery_required = true;
            self.ha_activation = None;
            self.ha_read_cache = None;
            return Response {
                status: 503,
                body: json!({"errors":["historical restore delivery requires reconciliation"],
                "recovery_required":true,"retry_allowed":false,"root_attempted":true,
                "recovery_reference":historical_recovery_reference(restored.operation_digest)}),
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
            };
        }
        response
    }
}

// Test-only observation at either an existing original-source gate or after
// one actual nonempty archive object read and before its existing tail gate.
// It cannot return a result, replace a gate, borrow a mutable Service, or
// construct any authority.
#[cfg(test)]
mod historical_prepare_observer {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    type Callback = Box<dyn FnOnce(&Service, &crate::auth::Principal, StateIdentity, Instant)>;

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) enum Stage {
        BeforeSource,
        AfterArchiveObjectRead,
    }

    struct Pending {
        stage: Stage,
        identity: StateIdentity,
        until: Instant,
        owner: Rc<()>,
        callback: Callback,
    }

    thread_local! {
        static NEXT: RefCell<Option<Pending>> = const { RefCell::new(None) };
    }

    pub(in crate::service) struct Scope(Rc<()>);

    pub(super) fn arm(
        stage: Stage,
        identity: StateIdentity,
        until: Instant,
        callback: impl FnOnce(&Service, &crate::auth::Principal, StateIdentity, Instant) + 'static,
    ) -> Scope {
        let owner = Rc::new(());
        NEXT.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none(), "one historical source observation only");
            *slot = Some(Pending {
                stage,
                identity,
                until,
                owner: Rc::clone(&owner),
                callback: Box::new(callback),
            });
        });
        Scope(owner)
    }

    pub(super) fn before_source(
        service: &Service,
        actor: &crate::auth::Principal,
        identity: StateIdentity,
        until: Instant,
    ) {
        observe(Stage::BeforeSource, service, actor, identity, until);
    }

    pub(super) fn after_archive_object_read(
        service: &Service,
        actor: &crate::auth::Principal,
        identity: StateIdentity,
        until: Instant,
    ) {
        observe(
            Stage::AfterArchiveObjectRead,
            service,
            actor,
            identity,
            until,
        );
    }

    fn observe(
        stage: Stage,
        service: &Service,
        actor: &crate::auth::Principal,
        identity: StateIdentity,
        until: Instant,
    ) {
        let pending = NEXT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().is_some_and(|pending| {
                pending.stage == stage && pending.identity == identity && pending.until == until
            }) {
                slot.take()
            } else {
                None
            }
        });
        if let Some(pending) = pending {
            (pending.callback)(service, actor, identity, until);
        }
    }

    impl Drop for Scope {
        fn drop(&mut self) {
            NEXT.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot
                    .as_ref()
                    .is_some_and(|pending| Rc::ptr_eq(&pending.owner, &self.0))
                {
                    slot.take();
                }
            });
        }
    }
}
