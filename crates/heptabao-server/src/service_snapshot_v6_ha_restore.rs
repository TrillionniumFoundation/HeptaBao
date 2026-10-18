//! Historical data restoration under the original live snapshot Actor.
//! Restores do not install an archive ledger, captured Raft state or epoch.
//! The complete local pack is decoded, protected clocks inherit live floors,
//! and an actual Begin/Stage/fsync-quorum/CAS publishes a new root and epoch.
use super::*;
use crate::ha::native_v6_backup::{NativeV6ArchiveError, NativeV6ArchiveSelection,
    validate_historical_native_v6_archive};
use crate::ha_state::native_v6::NativeV6CodecError;
use crate::service::native_v6_ha_install::{NativeHaArchiveRepairSource, NativeHaReadProof};
use std::cell::Cell;

/// Affine ownership of THIS completed restore before terminal-clock/audit.
/// Only the actual successful coordinator plus local epoch installation and
/// fresh business proof can construct it. Original Actor/Auth are retained
/// separately from the newly installed historical Auth owner.
pub(in crate::service::snapshot_transfer) struct NativeHaHistoricalReceipt {
    original_auth: AuthState,
    original_identity: StateIdentity,
    original_activation: String,
    restored_identity: StateIdentity,
    restored_generation: u64,
    restored_epoch: u64,
    restored_activation: String,
    proof: NativeHaReadProof,
}

// An archive object remains data even after authentication. Every selected
// read checks the original live journal owner before and after its immutable
// source borrow. Cipher staging occurs only after this borrow has ended, so
// its callbacks retain the actual mutable Durable owner on every shared I/O.
struct HistoricalObjects<'a> {
    service: &'a Service,
    plan: &'a SnapshotTransferPlan,
    source: &'a NativeHaArchiveRepairSource,
    durable: &'a RefCell<DurableService<AeadBarrier>>,
    archive: RefCell<&'a mut PreparedV6Restore<SnapshotFile>>,
    root_bytes: &'a [u8],
}
impl HistoricalObjects<'_> {
    fn gate(&self) -> Result<(), ServiceError> {
        self.service.check_native_ha_snapshot_owner(self.plan)
            .map_err(|_| ServiceError::BarrierFailure)?;
        self.source.check_taken(self.service,
            &mut self.durable.try_borrow_mut().map_err(|_| ServiceError::BarrierFailure)?)
            .map_err(|_| ServiceError::BarrierFailure)
    }
}
impl ObjectSource for HistoricalObjects<'_> {
    fn read(&self, domain: &ObjectDomain, reference: &ObjectRef)
        -> Result<Zeroizing<Vec<u8>>, RecordError>
    {
        self.gate().map_err(|_| RecordError::Invalid)?;
        let result = {
            let durable = self.durable.try_borrow().map_err(|_| RecordError::Invalid)?;
            let mut archive = self.archive.try_borrow_mut().map_err(|_| RecordError::Invalid)?;
            let resource = v6_records::native_resource(domain, reference);
            let slot = archive.state().get("system", &resource)
                .map_err(|_| RecordError::Corrupt)?.ok_or(RecordError::Missing)?;
            native_blob_source::validate_archive_slot(self.root_bytes, slot, reference)?;
            let mut gate = || self.service.check_native_ha_snapshot_owner(self.plan)
                .map_err(|_| ServiceError::BarrierFailure);
            let mut io_gate = || self.service.check_native_ha_snapshot_owner(self.plan)
                .map_err(|_| ServiceError::BarrierFailure);
            durable.read_v6_restore_object_with_io_gate(
                &mut archive, &resource, &mut gate, &mut io_gate,
            ).map_err(|_| RecordError::Corrupt)?
        };
        self.gate().map_err(|_| RecordError::Invalid)?;
        if result.len() != reference.encoded_bytes as usize { return Err(RecordError::Corrupt); }
        Ok(result)
    }
}

fn archive_error(error: NativeV6ArchiveError) -> Response {
    match error {
        NativeV6ArchiveError::WrongSelection => Response::error(400, "historical archive belongs to different cluster, seal or replay history"),
        NativeV6ArchiveError::Invalid | NativeV6ArchiveError::Corrupt => invalid(),
        NativeV6ArchiveError::TooLarge => Response::error(413, "historical archive exceeds its bound"),
        _ => unavailable(),
    }
}
fn actor_original(auth: &AuthState, plan: &SnapshotTransferPlan) -> Result<(), Response> {
    if Instant::now() >= plan.deadline || !plan.actor.is_root() || !plan.namespace.is_empty() {
        return Err(unavailable());
    }
    auth.authorize_request(&plan.actor, &plan.namespace, &plan.path, "update",
        snapshot_observed_time(plan.now, plan.started.elapsed()))
        .map_err(|error| Response::error(error.status, &error.message))
}

impl Service {
    pub(in crate::service::snapshot_transfer) fn prepare_native_ha_historical_upload(
        &mut self, plan: &mut SnapshotTransferPlan,
    ) -> Result<(), Response> {
        self.check_native_ha_snapshot_owner(plan)?;
        if plan.is_download || plan.path != "sys/storage/raft/snapshot"
            || plan.native_ha_restore_source.is_some() || plan.native_ha_repair.is_some()
        { return Err(unavailable()); }
        // This occurs after ordinary authentication and any real finite-use
        // debit. It captures that new current source; never revives old uses.
        let source = self.capture_native_ha_archive_repair_source()?;
        self.check_native_ha_snapshot_owner(plan)?;
        source.check_local(self)?;
        plan.native_ha_restore_source = Some(source);
        Ok(())
    }

    pub(in crate::service::snapshot_transfer) fn finish_native_ha_historical_upload(
        &mut self, plan: &mut SnapshotTransferPlan, result: Result<Observation, Response>,
    ) -> Response {
        let root_attempted = Cell::new(false);
        let checked = (|| -> Result<Response, Response> {
            self.check_native_ha_snapshot_owner(plan)?;
            if plan.is_download || plan.path != "sys/storage/raft/snapshot"
                || plan.native_ha_source.is_some() || plan.native_ha_restored.is_some()
            { return Err(unavailable()); }
            let source = plan.native_ha_restore_source.take().ok_or_else(unavailable)?;
            source.check_local(self)?;
            let imported = match result? {
                Observation::Upload(imported) => imported,
                Observation::Download => return Err(unavailable()),
            };
            if !imported.metadata.is_v6_ha() { return Err(invalid()); }
            let binding = imported.metadata.seal_identity().ok_or_else(invalid)?;
            if !binding.matches(&plan.seal_identity) { return Err(invalid()); }
            let barrier = AeadBarrier::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
            let sums = Zeroizing::new(barrier.open(snapshot_archive::CHECKSUM_CONTEXT,
                &imported.sealed_sums).map_err(|_| invalid())?);
            if sums.as_slice() != imported.sums.as_slice() { return Err(invalid()); }
            let original_auth = self.state.as_ref().ok_or_else(unavailable)?.auth.clone();
            actor_original(&original_auth, plan)?;
            let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
            let next_epoch = source.restore_anchor().enrollment().epoch().checked_add(1)
                .ok_or_else(|| Response::error(507, "native replay epoch exhausted"))?;
            let current_selection = NativeV6ArchiveSelection::from_committed(
                source.restore_anchor().enrollment(), source.restore_anchor().published(),
            ).map_err(archive_error)?;
            let durable = RefCell::new(self.durable.take().ok_or_else(unavailable)?);
            let prepared = (|| {
                let mut original = || {
                    self.check_native_ha_snapshot_owner(plan)?;
                    actor_original(&original_auth, plan)?;
                    source.check_taken(self, &mut durable.try_borrow_mut().map_err(|_| unavailable())?)
                };
                original()?;
                let (mut archive, facts) = validate_historical_native_v6_archive(
                    imported.state, &current_selection, plan.seal_identity, &barrier, deadline,
                    &mut || original().map_err(|_| NativeV6ArchiveError::Gate),
                ).map_err(archive_error)?;
                if archive.report().local.generation != imported.metadata.generation() {
                    return Err(invalid());
                }
                let imported_generation = archive.report().local.generation;
                let mut local_pack = plan.lease.file(crate::snapshot_file::MAX_V6_SNAPSHOT_STATE,
                    plan.deadline).map_err(|_| unavailable())?;
                archive.copy_local_pack_to(&mut local_pack,
                    &mut || original().map_err(|_| NativeV6ArchiveError::Gate))
                    .map_err(archive_error)?;
                local_pack.rewind_checked().map_err(|_| unavailable())?;
                let length = local_pack.len();
                original()?;
                let mut local = {
                    // The journal owner is held across the complete incoming
                    // pack authentication. This read performs no local write.
                    let durable = durable.try_borrow().map_err(|_| unavailable())?;
                    let mut gate = || self.check_native_ha_snapshot_owner(plan)
                        .map_err(|_| ServiceError::BarrierFailure);
                    let mut io_gate = || self.check_native_ha_snapshot_owner(plan)
                        .map_err(|_| ServiceError::BarrierFailure);
                    durable.prepare_v6_restore_from_reader_with_io_gate(local_pack, length,
                        &mut gate, &mut io_gate, &mut |_, _, _| Ok(()))
                        .map_err(storage_error)?
                };
                original()?;
                let root_bytes = Zeroizing::new(local.state().get("system", "state")
                    .map_err(storage_error)?.ok_or_else(invalid)?.to_vec());
                let root = RecordStateRootV6::decode(&root_bytes).map_err(|_| invalid())?;
                if local.state().metadata().generation != imported_generation
                    || local.state().metadata().replay_epoch != facts.replay_epoch()
                    || root.identity().map_err(|_| invalid())?.digest() != facts.root_digest()
                    || root.replay_epoch != facts.replay_epoch()
                    || root.reader_floor.native_kv2_format != 2
                    || root.cluster_id != self.state.as_ref().ok_or_else(unavailable)?.cluster_id
                    || root.kv2.iter().any(|graph| !graph.scope.namespace.is_empty())
                { return Err(invalid()); }
                let retained = RecordStateRoot::decode(local.state().get("system",
                    native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE).map_err(storage_error)?
                    .ok_or_else(invalid)?).map_err(|_| invalid())?;
                crate::service::native_v6_ha_install::validate_historical_archive_cursor(
                    &root, &retained,
                    local.state().get("system", native_v6_reader::ACTIVE_CURSOR_RESOURCE)
                        .map_err(storage_error)?.ok_or_else(invalid)?,
                    local.state().get("system", crate::service::native_v6_ha_install::HA_CURSOR_RESOURCE)
                        .map_err(storage_error)?.ok_or_else(invalid)?,
                    imported_generation, source.restore_anchor().published().native_origin_epoch(), &facts,
                )?;
                let objects = HistoricalObjects { service: self, plan, source: &source,
                    durable: &durable, archive: RefCell::new(&mut local), root_bytes: &root_bytes };
                let context = ReadContext {
                    expected_identity: ReadIdentity::RecordsV6(facts.root_digest()),
                    cluster_id: &root.cluster_id, replay_epoch: root.replay_epoch,
                    minimum_state_schema: root.state_schema, maximum_state_schema: root.state_schema,
                    reader_format: crate::state_record_root_v6::READER_FORMAT,
                };
                let (mut incoming, native) = v6_records::materialize_for_service(&root, context, &objects)
                    .map_err(|_| invalid())?;
                incoming.engines.install_native_views(native).map_err(Response::from_engine_error)?;
                incoming.validate_format()?;
                self.require_native_root_candidate(&incoming)?;
                let current = self.state.as_ref().ok_or_else(unavailable)?;
                if !current.database.is_empty() || current.engines.has_openldap_mount()
                    || !incoming.database.is_empty() || incoming.engines.has_openldap_mount()
                    || *incoming.raft_admin != *current.raft_admin
                { return Err(Response::error(409, "historical restore cannot replace external providers or live Raft administration")); }
                original()?;
                // Only authenticated LIVE current clock floors enter this
                // merge. Format labels, catalogs, retirement/tombstone owners
                // and every original successor guard remain unchanged. In
                // particular an old schema is never normalized past a guard.
                incoming.auth.inherit_native_snapshot_clocks(&current.auth)
                    .map_err(|error| Response::error(error.status, &error.message))?;
                incoming.engines.inherit_native_snapshot_clocks(&current.engines)
                    .map_err(Response::from_engine_error)?;
                incoming.validate_format()?;
                Self::validate_snapshot_protected_floor(current, &incoming)?;
                incoming.schema = incoming.writer_schema();
                incoming.replay_epoch = next_epoch;
                incoming.auth.discard_restored_oidc_sessions();
                incoming.validate_format()?;
                let candidate = v6_records::prepare_historical_native_root(&root, incoming, next_epoch,
                    source.restore_generation(), source.restore_conditions(), deadline, &objects, &mut original)?;
                let owner_bytes = candidate.root.owners.iter().try_fold(0u64,
                    |sum, owner| sum.checked_add(owner.owner.total_bytes)).ok_or_else(invalid)?;
                if owner_bytes > self.opaque_owner_limit() as u64 {
                    return Err(Response::error(507, "native opaque owner capacity exhausted"));
                }
                let digest = candidate.root.identity().map_err(|_| invalid())?.digest();
                original()?;
                let ha = plan.ha.as_ref().ok_or_else(unavailable)?;
                let process = ha.lock_for_request().map_err(|_| unavailable())?;
                let published = process.publish_native_v6_historical_restore(
                    source.restore_anchor(), digest,
                    |codec, enrollment, store, gate| {
                        crate::service::native_v6_ha_objects::prepare_native_v6_ha_objects(
                            &candidate, codec, enrollment, store, Some(&objects), None, &mut || gate(),
                        )
                    },
                    &mut || original().map_err(|_| NativeV6CodecError::Gate),
                );
                let committed = published.map_err(|error| {
                    root_attempted.set(error.root_attempted());
                    Response { status: 503, body: json!({"errors":[error.to_string()],
                        "recovery_reference":error.reference_id(), "retry_allowed":false,
                        "root_attempted":error.root_attempted()}), unwrapped_json: None,
                        response_headers: Default::default(), consistency_index: None }
                })?;
                root_attempted.set(true);
                original()?;
                Ok((committed, digest, imported_generation))
            })();
            // The original affine Durable owner returns on EVERY path.
            self.durable = Some(durable.into_inner());
            let (committed, digest, imported_generation) = prepared?;
            source.check_local(self)?;
            self.check_native_ha_snapshot_owner(plan)?;
            let ha = plan.ha.as_ref().ok_or_else(unavailable)?.clone();
            self.sync_native_v6_from_ha_checked(&ha, committed, &mut |_| actor_original(&original_auth, plan))?;
            actor_original(&original_auth, plan)?;
            if self.unseal_nonce == plan.activation
                || self.current_state_identity()? != StateIdentity::RecordsV6(digest)
                || self.state.as_ref().ok_or_else(unavailable)?.replay_epoch != next_epoch
            { return Err(unavailable()); }
            let proof = self.capture_native_ha_request_proof(&mut || actor_original(&original_auth, plan))?
                .ok_or_else(unavailable)?;
            proof.check_warm(self)?;
            actor_original(&original_auth, plan)?;
            let generation = self.external_effect_generation()?;
            let receipt = NativeHaHistoricalReceipt { original_auth,
                original_identity: plan.base, original_activation: plan.activation.clone(),
                restored_identity: StateIdentity::RecordsV6(digest), restored_generation: generation,
                restored_epoch: next_epoch, restored_activation: self.unseal_nonce.clone(), proof };
            self.check_native_ha_historical_delivery(plan, &receipt, receipt.restored_identity)?;
            plan.native_ha_restored = Some(receipt);
            Ok(Response::ok(json!({"data":{ "imported_generation":imported_generation,
                "previous_local_generation":source.restore_generation(),
                "published_local_generation":generation, "replay_epoch":next_epoch,
                "restored_root":hex(&digest), "cluster_coordinated":true }})))
        })();
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
                    }
                }
                error
            }
        }
    }

    fn check_native_ha_historical_delivery(&self, plan: &SnapshotTransferPlan,
        restored: &NativeHaHistoricalReceipt, expected: StateIdentity) -> Result<(), Response>
    {
        let same_ha = match (&plan.ha, &self.ha) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right), _ => false,
        };
        if !same_ha || plan.base != restored.original_identity || plan.activation != restored.original_activation
            || restored.original_activation == restored.restored_activation
            || self.unseal_nonce != restored.restored_activation
            || self.current_state_identity().ok() != Some(expected)
            || self.state.as_ref().is_none_or(|state| state.replay_epoch != restored.restored_epoch)
            || self.durable.as_ref().is_none_or(|durable| durable.replay_epoch() != restored.restored_epoch)
            || self.audit_failed || self.recovery_required || self.barrier_key.is_none()
            || self.native_root.is_none() || self.record_root.is_some()
            || self.postgres_durable.is_some() || self.durable_profile.is_some()
            || self.openbao_wrapper_owner.is_some() || self.native_candidate_profile.is_some()
            || Instant::now() >= plan.deadline
        { return Err(unavailable()); }
        actor_original(&restored.original_auth, plan)?;
        if self.current_snapshot_seal_identity_for_plan(plan)? != plan.seal_identity {
            return Err(unavailable());
        }
        actor_original(&restored.original_auth, plan)
    }

    pub(in crate::service::snapshot_transfer) fn complete_native_ha_historical_delivery(
        &mut self, plan: &SnapshotTransferPlan, mut response: Response,
        fingerprint: &str, clock: (u64, Option<RequestClock>),
    ) -> Response {
        let restored = match plan.native_ha_restored.as_ref() {
            Some(restored) => restored, None => return unavailable(),
        };
        let checkpoint = (restored.restored_identity, restored.restored_generation);
        if response.status < 400 && (self.external_effect_generation().ok() != Some(checkpoint.1)
            || self.check_native_ha_historical_delivery(plan, restored, checkpoint.0).is_err())
        { response = unavailable(); }
        // The SAME admitted RequestClock commits before the mandatory response
        // audit. Its affine receipt may authorize only this observation-only
        // successor; it cannot manufacture another historical restore epoch.
        let (mut response, clock_receipt) = self.audit_completed_response_with_clock_receipt(
            fingerprint, clock, response, || {}, true,
        );
        let checked: Result<(), Response> = (|| {
            // The epoch/root has already committed. An audit, clock or final
            // original-owner failure is an uncertain delivery, never evidence
            // that the historical restore had no effect or may be retried.
            if response.status >= 400 { return Err(unavailable()); }
            if let Some(receipt) = clock_receipt {
                let terminal = receipt.bind_native_snapshot(checkpoint)?;
                if self.external_effect_generation()? != terminal.1 { return Err(unavailable()); }
                self.check_native_ha_historical_delivery(plan, restored, terminal.0)?;
                let current = self.capture_native_ha_request_proof(
                    &mut || actor_original(&restored.original_auth, plan),
                )?.ok_or_else(unavailable)?;
                restored.proof.check_snapshot_terminal_successor(self, &current)?;
                self.check_native_ha_historical_delivery(plan, restored, terminal.0)?;
            } else {
                if self.external_effect_generation()? != checkpoint.1 { return Err(unavailable()); }
                restored.proof.check_with(self, Service::check_native_installed)?;
                self.check_native_ha_historical_delivery(plan, restored, checkpoint.0)?;
            }
            Ok(())
        })();
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            let _ = self.audit_event("native-ha-historical-restore-delivery-veto", fingerprint,
                snapshot_observed_time(plan.now, plan.started.elapsed()), Some(error.status));
            self.recovery_required = true;
            self.ha_activation = None;
            self.ha_read_cache = None;
            return Response { status: 503, body: json!({"errors":["historical restore delivery requires reconciliation"],
                "recovery_required":true,"retry_allowed":false}), unwrapped_json: None,
                response_headers: Default::default(), consistency_index: None };
        }
        response
    }
}
