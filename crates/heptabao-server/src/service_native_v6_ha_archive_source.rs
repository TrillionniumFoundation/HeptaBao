//! Warm, exact-current local authority for an authenticated archive repair.
//! No peer pull runs at admission: every donor may have lost the shared files.
//! The retained complete local graph, four journal conditions, original Actor
//! and actual Raft selection must all survive the upload. This is not a cold
//! unseal owner, an archived Auth owner, or a business-read capability.
use super::*;
use crate::ha::NativeV6ArchiveRootAnchor;
use crate::ha::native_v6_backup::{NativeV6ArchiveError, NativeV6ArchiveReport};
use crate::ha_state::native_v6::NativeV6CodecError;
use crate::snapshot_file::SnapshotFile;
use heptabao_raft_runtime::NativeV6PeerEnrollment;

pub(crate) struct NativeHaArchiveRepairSource {
    environment: LocalHaEnvironment,
    selected: LocalSelection,
    anchor: NativeV6ArchiveRootAnchor,
    identity: StateIdentity,
    owner_fingerprints: [[u8; 32]; 4],
}

// Only a raw ACTUAL ReadIndex callback may call this constructor. All four
// resources must already describe its exact current root; stale local A is
// never sufficient to authenticate a repair of current B.
fn current_local_selection(
    durable: &mut DurableService<AeadBarrier>,
    enrollment: &NativeV6PeerEnrollment,
    published: &NativeV6PublishedRoot,
    deadline: OriginalDeadline,
) -> Result<LocalSelection, Response> {
    live(deadline)?;
    durable.verify_live_ownership().map_err(storage_rejected)?;
    if durable.recovery_required() || durable.replay_epoch() != enrollment.epoch() {
        return Err(unavailable());
    }
    let initial_generation = durable.generation();
    let root_bytes = durable.get("system", "state").map_err(storage_rejected)?
        .ok_or_else(unavailable)?;
    let active_bytes = durable.get("system", ACTIVE_CURSOR_RESOURCE).map_err(storage_rejected)?;
    let source_bytes = durable.get("system", ACTIVE_SOURCE_ROOT_RESOURCE).map_err(storage_rejected)?;
    let ha_bytes = durable.get("system", HA_CURSOR_RESOURCE).map_err(storage_rejected)?;
    let root = RecordStateRootV6::decode(root_bytes.expose()).map_err(|_| unavailable())?;
    let source = RecordStateRoot::decode(source_bytes.as_ref().ok_or_else(unavailable)?.expose())
        .map_err(|_| unavailable())?;
    let active = NativeActiveCursor::decode(active_bytes.as_ref().ok_or_else(unavailable)?.expose())?;
    active.validate(&source, &root, initial_generation)?;
    let selected = LocalSelection {
        root_bytes, active_bytes, source_bytes, ha_bytes,
        source, active: Some(active), native: Some(root), initial_generation,
        local_epoch: durable.replay_epoch(),
    };
    matches_current(&selected, enrollment, published)?;
    selected.check(durable, initial_generation).map_err(storage_rejected)?;
    live(deadline)?;
    Ok(selected)
}

fn matches_current(
    selected: &LocalSelection,
    enrollment: &NativeV6PeerEnrollment,
    published: &NativeV6PublishedRoot,
) -> Result<(), Response> {
    let root = selected.native.as_ref().ok_or_else(unavailable)?;
    let cursor = NativeHaCursor::decode(selected.ha_bytes.as_ref().ok_or_else(unavailable)?.expose())?;
    if cursor.cluster_digest != enrollment.cluster_digest()
        || cursor.enrollment_digest != enrollment.digest()
        || cursor.replay_epoch != enrollment.epoch()
        || cursor.raft_generation != published.generation()
        || cursor.publication_log != ExactLog::root(published)
        || cursor.intent_log != ExactLog::intent(published)
        || cursor.migration_log != ExactLog::migration(published)
        || cursor.migration_digest != published.migration_source().0
        || cursor.root_digest != published.root_digest()
        || cursor.root_digest != root.identity().map_err(|_| unavailable())?.digest()
        || cursor.migration_digest != selected.source.identity().map_err(|_| unavailable())?.digest()
        || cursor.local_publication_generation > selected.initial_generation
        || cursor.local_publication_generation
            != active_generation(selected.active_bytes.as_ref().ok_or_else(unavailable)?.expose())?
        || selected.source.replay_epoch != published.native_origin_epoch()
        || selected.local_epoch != enrollment.epoch()
        || root.replay_epoch != enrollment.epoch()
        || root.reader_floor.native_kv2_format != 2
    {
        return Err(unavailable());
    }
    Ok(())
}

impl NativeHaArchiveRepairSource {
    pub(in crate::service) fn check_instance(&self, service: &Service) -> Result<(), Response> {
        self.environment.check(service)?;
        if service.record_root.is_some() || service.current_state_identity()? != self.identity {
            return Err(unavailable());
        }
        let root = service.native_root.as_ref().ok_or_else(unavailable)?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        root_namespace_only(state)?;
        if root.encode().map_err(|_| unavailable())?.as_slice() != self.selected.root_bytes.expose()
            || state.schema != root.state_schema
            || state.cluster_id != root.cluster_id
            || state.replay_epoch != root.replay_epoch
            || state.global_lossless_json_format != root.global_lossless_json_format
            || fingerprints(state, self.environment.deadline)? != self.owner_fingerprints
        {
            return Err(unavailable());
        }
        live(self.environment.deadline)
    }

    pub(in crate::service) fn check_local(&self, service: &Service) -> Result<(), Response> {
        self.check_instance(service)?;
        let durable = service.durable.as_ref().ok_or_else(unavailable)?;
        if durable.recovery_required()
            || durable.generation() != self.selected.initial_generation
            || durable.replay_epoch() != self.selected.local_epoch
        {
            return Err(unavailable());
        }
        for condition in self.selected.conditions() {
            let actual = durable.get("system", &condition.resource).map_err(storage_rejected)?;
            if actual.as_ref().map(Secret::expose) != condition.expected.as_ref().map(Secret::expose) {
                return Err(unavailable());
            }
        }
        self.check_instance(service)
    }

    // Restore shares the same authenticated original local capture. These
    // accessors expose comparison data only; they do not construct a business
    // read or replace the independently actual epoch-restore coordinator.
    pub(in crate::service) fn restore_anchor(&self) -> &NativeV6ArchiveRootAnchor { &self.anchor }
    pub(in crate::service) fn restore_generation(&self) -> u64 { self.selected.initial_generation }
    pub(in crate::service) fn restore_conditions(&self) -> Vec<PublicationCondition> {
        self.selected.conditions()
    }
    pub(in crate::service) fn check_taken(
        &self, service: &Service, durable: &mut DurableService<AeadBarrier>,
    ) -> Result<(), Response> {
        self.check_instance(service)?;
        self.selected.check(durable, self.selected.initial_generation).map_err(storage_rejected)?;
        self.check_instance(service)
    }

    pub(in crate::service) fn reconcile_pending_restore(
        self,
        service: &mut Service,
        operation: Option<[u8; 32]>,
        actor: &mut impl FnMut(&Service) -> Result<(), Response>,
    ) -> Result<(NativeHaReadProof, &'static str, Option<[u8; 32]>), Response> {
        actor(service)?;
        self.check_local(service)?;
        let process = self.environment.ha.lock_for_request().map_err(|_| unavailable())?;
        // None requests read-only discovery. A supplied operation reference
        // is only a selector: current local custody, the original live Actor
        // and an actual pending-read witness independently authorize its one
        // cancellation. Neither request consults an archive or replays a CAS.
        let mut durable = service.durable.take().ok_or_else(unavailable)?;
        let reconciled = process.reconcile_native_v6_historical_restore(
            &self.anchor, operation, &mut || {
                actor(service).map_err(|_| NativeV6CodecError::Gate)?;
                self.check_taken(service, &mut durable).map_err(|_| NativeV6CodecError::Gate)
            },
        );
        // Restore the actual affine journal owner before every error path can
        // reach the existing terminal clock and mandatory audit writer.
        service.durable = Some(durable);
        let (committed, outcome) = reconciled.map_err(|error| {
            let mut response = Response::error(503, "pending restore reconciliation is uncertain");
            if let Some(body) = response.body.as_object_mut() {
                body.insert("recovery_reference".into(), json!(error.reference_id()));
                body.insert("retry_allowed".into(), json!(false));
                body.insert("restore_performed".into(), json!(false));
            }
            response
        })?;
        self.check_local(service)?;
        actor(service)?;
        matches_current(&self.selected, committed.enrollment(), committed.published())?;
        drop(process);
        let proof = NativeHaReadProof {
            environment: self.environment,
            selected: self.selected,
            committed,
            identity: self.identity,
            owner_fingerprints: self.owner_fingerprints,
        };
        // Cancellation changes only pending Raft metadata. The response still
        // needs a new actual read of the complete unchanged current graph,
        // and the existing terminal-delivery checks retain this exact proof.
        proof.check_with(service, Service::check_native_installed)?;
        actor(service)?;
        proof.check_warm(service)?;
        Ok((proof, outcome.as_str(), outcome.pending_operation()))
    }

    pub(in crate::service) fn repair(
        self,
        service: &mut Service,
        file: SnapshotFile,
        seal_identity: [u8; 32],
        actor: &mut impl FnMut(&Service) -> Result<(), Response>,
    ) -> Result<(NativeHaReadProof, NativeV6ArchiveReport), Response> {
        actor(service)?;
        self.check_local(service)?;
        // Reopen the complete local typed graph after out-of-writer upload.
        // A matching root hash cannot authenticate a changed warm KV cache.
        let mut durable = service.durable.take().ok_or_else(unavailable)?;
        let checked = (|| {
            self.selected.check(&mut durable, self.selected.initial_generation)
                .map_err(storage_rejected)?;
            let root = self.selected.native.as_ref().ok_or_else(unavailable)?;
            let mut gate = || {
                actor(service).map_err(|_| ServiceError::BarrierFailure)?;
                self.check_instance(service).map_err(|_| ServiceError::BarrierFailure)
            };
            let (metadata, native) = materialize_local(
                &mut durable, root, self.environment.deadline, &mut gate,
            )?;
            Service::check_native_installed(
                service.state.as_ref().ok_or_else(unavailable)?, &metadata, &native,
                root, self.environment.deadline,
            )?;
            self.selected.check(&mut durable, self.selected.initial_generation)
                .map_err(storage_rejected)?;
            gate().map_err(storage_rejected)
        })();
        service.durable = Some(durable);
        checked?;
        let barrier = AeadBarrier::new(**service.barrier_key.as_ref().ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
        let process = self.environment.ha.lock_for_request().map_err(|_| unavailable())?;
        // Keep the actual mutable journal owner through every shared I/O gate.
        // Byte equality alone cannot prove that its directory/lock ownership
        // survived the out-of-writer body transfer or a later file operation.
        let mut durable = service.durable.take().ok_or_else(unavailable)?;
        let repaired = process.repair_native_v6_current_closure_from_admitted_archive(
            file, seal_identity, &barrier, &self.anchor,
            &mut |enrollment, published| {
                actor(service).map_err(|_| NativeV6ArchiveError::Gate)?;
                self.check_instance(service).map_err(|_| NativeV6ArchiveError::Gate)?;
                self.selected.check(&mut durable, self.selected.initial_generation)
                    .map_err(|_| NativeV6ArchiveError::Gate)?;
                matches_current(&self.selected, enrollment, published)
                    .map_err(|_| NativeV6ArchiveError::WrongSelection)
            },
        );
        // Restore the affine journal owner on every success/error path before
        // the existing terminal clock and mandatory audit boundary resumes.
        service.durable = Some(durable);
        let repaired = repaired.map_err(|error| match error {
            NativeV6ArchiveError::WrongSelection => Response::error(409, "archive is not the admitted current native HA root"),
            NativeV6ArchiveError::Invalid | NativeV6ArchiveError::Corrupt =>
                Response::error(400, "native HA archive authentication failed"),
            NativeV6ArchiveError::TooLarge => Response::error(413, "native HA archive exceeds its bound"),
            _ => unavailable(),
        })?;
        let (committed, report) = repaired.into_parts();
        self.check_local(service)?;
        actor(service)?;
        drop(process);
        let proof = NativeHaReadProof {
            environment: self.environment,
            selected: self.selected,
            committed,
            identity: self.identity,
            owner_fingerprints: self.owner_fingerprints,
        };
        // Only the repaired, freshly verified closure can now produce the
        // existing business proof. The archived core/ledger was never installed.
        proof.check_with(service, Service::check_native_installed)?;
        actor(service)?;
        proof.check_warm(service)?;
        Ok((proof, report))
    }
}

impl Service {
    pub(in crate::service) fn capture_native_ha_archive_repair_source(
        &mut self,
    ) -> Result<NativeHaArchiveRepairSource, Response> {
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let ha = self.ha.as_ref().ok_or_else(unavailable)?.clone();
        let key = Zeroizing::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?);
        let environment = LocalHaEnvironment::capture(self, &ha, &key, deadline)?;
        let identity = self.current_state_identity()?;
        let process = ha.lock_for_request().map_err(|_| unavailable())?;
        if !process.native_v6_enabled() || !process.is_leader().unwrap_or(false) {
            return Err(unavailable());
        }
        let cluster_id = process.cluster_id().to_owned();
        let mut durable = self.durable.take().ok_or_else(unavailable)?;
        let captured = process.with_native_v6_archive_root(deadline, |enrollment, published, actual| {
            let selected = current_local_selection(&mut durable, enrollment, published, deadline)
                .map_err(|_| NativeV6ArchiveError::WrongSelection)?;
            let root = selected.native.as_ref().ok_or(NativeV6ArchiveError::WrongSelection)?;
            if identity != StateIdentity::RecordsV6(published.root_digest()) || root.cluster_id != cluster_id {
                return Err(NativeV6ArchiveError::WrongSelection);
            }
            let mut gate = || {
                environment.check(self).map_err(|_| ServiceError::BarrierFailure)?;
                actual().map_err(|_| ServiceError::BarrierFailure)
            };
            let (metadata, native) = materialize_local(&mut durable, root, deadline, &mut gate)
                .map_err(|_| NativeV6ArchiveError::Storage)?;
            Service::check_native_installed(
                self.state.as_ref().ok_or(NativeV6ArchiveError::Gate)?,
                &metadata, &native, root, deadline,
            ).map_err(|_| NativeV6ArchiveError::WrongSelection)?;
            selected.check(&mut durable, selected.initial_generation)
                .map_err(|_| NativeV6ArchiveError::Storage)?;
            gate().map_err(|_| NativeV6ArchiveError::Gate)?;
            let owner_fingerprints = fingerprints(&metadata, deadline)
                .map_err(|_| NativeV6ArchiveError::Gate)?;
            Ok((selected, owner_fingerprints))
        });
        self.durable = Some(durable);
        drop(process);
        let ((selected, owner_fingerprints), anchor) = captured.map_err(|_| unavailable())?;
        let source = NativeHaArchiveRepairSource {
            environment, selected, anchor, identity, owner_fingerprints,
        };
        source.check_local(self)?;
        Ok(source)
    }
}
