//! Dual-pack export under the original native request proof. The archive is
//! only data: the retained affine proof, not its provenance bytes or hashes,
//! must also survive actual Service finalization before HTTP delivery.
use super::*;

#[path = "service_native_v6_ha_lossless_export.rs"]
mod lossless_export;
use crate::ha::native_v6_backup::{
    NativeV6ArchiveError, NativeV6ArchiveReport, NativeV6ArchiveSelection,
    prepare_native_v6_local_pack, write_native_v6_archive,
};
use crate::ha_state::native_v6::NativeV6CodecError;
use crate::snapshot_file::SnapshotFile;

// An export keeps one shared Service borrow while its durable owner is taken
// separately. The ordinary root, State, opaque owners, nonce and barrier key
// cannot change during that borrow. Authenticate those exact fields at both
// ends instead of serializing the same root and owners at every file gate.
// This guard grants no Actor, Raft, file or durability authority: the original
// caller check and consensus witness remain independent at every old gate.
struct BorrowedSnapshotProof<'a> {
    proof: &'a NativeHaReadProof,
    service: &'a Service,
}

impl<'a> BorrowedSnapshotProof<'a> {
    fn capture(proof: &'a NativeHaReadProof, service: &'a Service) -> Result<Self, Response> {
        proof.check_instance(service)?;
        Ok(Self { proof, service })
    }

    fn service(&self) -> &Service {
        self.service
    }

    fn check_live(&self) -> Result<(), Response> {
        // The actual seal file can change and the original deadline can expire
        // during this shared borrow, so retain their real check at every gate.
        self.proof.environment.check_seal()
    }

    fn check_complete(&self) -> Result<(), Response> {
        self.proof.check_instance(self.service)
    }
}

impl NativeHaReadProof {
    /// Only data from this actual committed selection. In particular, the
    /// logical publication generation is never the local journal generation
    /// returned by generation(), which can differ across physical replicas.
    pub(in crate::service) fn snapshot_clock_shared_state(
        &self,
    ) -> crate::ha::snapshot_clock::SharedSnapshotClockState {
        use crate::ha::snapshot_clock::{SharedSnapshotClockState, SnapshotClockLogId};
        let published = self.committed.published();
        let log = published.publication_log_id();
        SharedSnapshotClockState {
            epoch: self.committed.enrollment().epoch(),
            enrollment_digest: self.committed.enrollment().digest(),
            root_digest: published.root_digest(),
            logical_generation: published.generation(),
            publication_log: SnapshotClockLogId {
                term: log.committed_leader_id().term,
                node_id: log.committed_leader_id().node_id,
                index: log.index,
            },
            auth_sha256: self.owner_fingerprints[1],
        }
    }

    pub(in crate::service) fn snapshot_clock_enrollment(
        &self,
    ) -> &heptabao_raft_runtime::NativeV6PeerEnrollment {
        self.committed.enrollment()
    }

    // Observe only the original consensus component for refusal attribution.
    // This mints no proof, refreshes no ReadIndex, and checks no local Seal grant.
    #[cfg(test)]
    pub(in crate::service) fn observe_snapshot_original_consensus_for_test(
        &self,
    ) -> Result<(), Response> {
        live(self.environment.deadline)?;
        self.environment
            .ha
            .lock_for_request()
            .map_err(|_| unavailable())?
            .verify_native_v6_committed_read(&self.committed)
            .map_err(|_| unavailable())?;
        live(self.environment.deadline)
    }

    #[cfg(test)]
    pub(in crate::service) fn observe_snapshot_after_local_graph_once(
        &self,
        callback: impl FnOnce(&Service, StateIdentity, Instant) + 'static,
    ) -> impl Drop {
        export_observer::arm(self.identity, self.environment.deadline.instant(), callback)
    }

    /// The Service calls this only after consuming its exact terminal-clock
    /// receipt. The archive retains this proof's A identity; the new proof
    /// independently authenticates the one observed-clock successor B.
    pub(in crate::service) fn check_snapshot_terminal_successor(
        &self,
        service: &Service,
        successor: &Self,
    ) -> Result<(), Response> {
        self.environment.check(service)?;
        if self.environment.deadline.instant() != successor.environment.deadline.instant()
            || !Arc::ptr_eq(&self.environment.ha, &successor.environment.ha)
            || self.committed.enrollment() != successor.committed.enrollment()
        {
            return Err(unavailable());
        }
        let original = self.committed.published();
        let current = successor.committed.published();
        let intent = current.intent();
        if intent.epoch != original.intent().epoch
            || intent.prior_root_digest != original.root_digest()
            || intent.prior_generation != original.generation()
            || intent.expected_previous_commit_index != original.publication_log_id().index
            || original.generation().checked_add(1) != Some(current.generation())
            || current.migration_source() != original.migration_source()
            || successor.identity != StateIdentity::RecordsV6(current.root_digest())
        {
            return Err(unavailable());
        }
        successor.check_warm(service)?;
        self.environment.check(service)
    }

    /// Both files come from the original descriptor-owned snapshot lease.
    /// No callback receives a raw root, enrollment, store or publication grant.
    pub(in crate::service) fn export_snapshot_archive(
        &self,
        service: &mut Service,
        local_file: SnapshotFile,
        mut archive_file: SnapshotFile,
        seal_identity: [u8; 32],
        original_actor: &mut impl FnMut(&Service) -> Result<(), Response>,
    ) -> Result<(SnapshotFile, NativeV6ArchiveReport), Response> {
        original_actor(service)?;
        self.check_warm(service)?;
        let key = Zeroizing::new(**service.barrier_key.as_ref().ok_or_else(unavailable)?);
        let barrier = AeadBarrier::new(*key).map_err(|_| unavailable())?;
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
            // Capture inside the result scope: any refusal still returns the
            // same taken durable owner before it leaves this export attempt.
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
            // This is the full typed materializer, including retained payload
            // history and every paged block, under the local barrier owner.
            let (metadata, native) = materialize_local(&mut durable, root, deadline, &mut gate)?;
            Service::check_native_installed(
                borrowed.service().state.as_ref().ok_or_else(unavailable)?,
                &metadata,
                &native,
                root,
                deadline,
            )?;
            #[cfg(test)]
            export_observer::after_local_graph(
                borrowed.service(),
                self.identity,
                deadline.instant(),
            );
            let report = process
                .with_native_v6_source(&self.committed, |codec, store| {
                    let mut codec_gate = || gate().map_err(|_| NativeV6CodecError::Gate);
                    // Independently open the shared-key directory and its
                    // complete typed closure; matching counts cannot do this.
                    let received = open_native_v6_ha_objects(
                        codec,
                        self.committed.enrollment(),
                        self.committed.published(),
                        store,
                        context(root)?,
                        deadline,
                        &mut codec_gate,
                    )
                    .map_err(|_| unavailable())?;
                    if received.root_bytes() != self.selected.root_bytes.expose() {
                        return Err(unavailable());
                    }
                    let (shared_state, shared_native, _) = received
                        .into_detached_parts(&mut codec_gate)
                        .map_err(|_| unavailable())?;
                    Service::check_native_installed(
                        borrowed.service().state.as_ref().ok_or_else(unavailable)?,
                        &shared_state,
                        &shared_native,
                        root,
                        deadline,
                    )?;
                    let selection = NativeV6ArchiveSelection::from_committed(
                        self.committed.enrollment(),
                        self.committed.published(),
                    )
                    .map_err(|_| unavailable())?;
                    let mut archive_gate = || gate().map_err(|_| NativeV6ArchiveError::Gate);
                    let local = prepare_native_v6_local_pack(
                        &mut durable,
                        &selection,
                        local_file,
                        deadline,
                        &mut archive_gate,
                        // The complete typed local graph was just checked.
                        // Durable export independently AEAD-checks every
                        // registered ciphertext under its held source session.
                        &mut |_, _| Ok(()),
                    )
                    .map_err(|_| unavailable())?;
                    write_native_v6_archive(
                        &selection,
                        local,
                        store,
                        seal_identity,
                        &barrier,
                        &mut archive_file,
                        &mut archive_gate,
                    )
                    .map_err(|_| unavailable())
                })
                .map_err(|_| unavailable())??;
            self.selected
                .check(&mut durable, self.selected.initial_generation)
                .map_err(storage_rejected)?;
            gate().map_err(storage_rejected)?;
            borrowed.check_complete()?;
            if archive_file.len() != report.archive_bytes {
                return Err(unavailable());
            }
            archive_file.rewind_checked().map_err(|_| unavailable())?;
            Ok(report)
        })();
        service.durable = Some(durable);
        drop(process);
        // Every failure leaves only lease-owned transfer files, never a root
        // mutation, fsync ACK or substitute consensus selection.
        let report = result?;
        self.check_warm(service)?;
        original_actor(service)?;
        Ok((archive_file, report))
    }
}

// Only tests may observe this exact boundary. The callback cannot return a
// result, replace a gate, borrow a mutable Service, or construct any custody.
// It is bound to this original root/deadline and is consumed at most once.
#[cfg(test)]
mod export_observer {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    type Callback = Box<dyn FnOnce(&Service, StateIdentity, Instant)>;

    struct Pending {
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
        identity: StateIdentity,
        until: Instant,
        callback: impl FnOnce(&Service, StateIdentity, Instant) + 'static,
    ) -> Scope {
        let owner = Rc::new(());
        NEXT.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none(), "one snapshot export observation only");
            *slot = Some(Pending {
                identity,
                until,
                owner: Rc::clone(&owner),
                callback: Box::new(callback),
            });
        });
        Scope(owner)
    }

    pub(super) fn after_local_graph(service: &Service, identity: StateIdentity, until: Instant) {
        let pending = NEXT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot
                .as_ref()
                .is_some_and(|pending| pending.identity == identity && pending.until == until)
            {
                slot.take()
            } else {
                None
            }
        });
        if let Some(pending) = pending {
            (pending.callback)(service, identity, until);
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
