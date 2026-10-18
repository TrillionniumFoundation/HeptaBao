//! Exact-current archive repair under an actual running Native V6 Raft owner.
//!
//! This child of `ha_native_v6_runtime` is wired into internal compilation.
//! No Service coordinator or HTTP recovery route invokes it yet. Only that
//! actual owner can select a root before recovering missing external ciphertext.
//! The archive is data. Its provenance never constructs or renews a read,
//! enrollment, publication, quorum receipt, Actor, local core or replay ledger.
//!
//! The eventual Service coordinator must retain and check its original Actor,
//! source Auth, clock, seal/activation, barrier and local-generation custody in
//! `original_owner`. The callback receives the actual selection's enrollment
//! and root so it can bind that local source exactly, never authorize a stale
//! local A for a different current B. Those values alone are not live rights.
//! The callback must not acquire the already-borrowed HaProcess lock. This
//! primitive independently owns every consensus check.
use super::*;
use crate::crypto::AeadBarrier;
use crate::ha::native_v6_backup::{
    ArchiveResult, NativeV6ArchiveError, NativeV6ArchiveReport, NativeV6ArchiveSelection,
    validate_native_v6_archive,
};
use heptabao_raft_runtime::{LocalV6BlobError, LocalV6ClosureReceipt};
use std::cell::RefCell;
use std::io::{Read, Seek};

fn original_operation(deadline: OriginalDeadline) -> ArchiveResult<()> {
    // Do not enter a blocking ReadIndex with a captured longer bound after a
    // caller has tightened the current scope. The helper accepts only the
    // exact request whose deadline it retains, never an old/fresh substitute.
    if crate::request_deadline::current() != Some(deadline.instant()) {
        return Err(NativeV6ArchiveError::Gate);
    }
    deadline.check().map_err(|_| NativeV6ArchiveError::Gate)
}

/// No Clone/Serde and no constructor outside this owner. The returned read is
/// a NEW real same-selection ReadIndex after all local fsyncs. As with every
/// CommittedNativeV6Read, it grants neither an Actor nor installation/delivery.
pub(crate) struct NativeV6ArchiveRepair {
    read: CommittedNativeV6Read,
    archive: NativeV6ArchiveReport,
}

impl NativeV6ArchiveRepair {
    pub(crate) fn into_parts(self) -> (CommittedNativeV6Read, NativeV6ArchiveReport) {
        (self.read, self.archive)
    }
}

/// The first actual handle remains the immutable comparison anchor even if its
/// capped ReadIndex lifetime expires. Only a separately acquired, verified
/// actual read may then provide liveness. A changed store, applied generation,
/// leader, term, enrollment, publication/full LogId or original operation
/// deadline is rejected by the runtime's existing strict `same_selection`.
struct ActualArchiveRoot<'a, G> {
    process: &'a HaProcess,
    native: &'a NativeV6Runtime,
    initial: NativeV6CommittedRootRead,
    active: Option<NativeV6CommittedRootRead>,
    deadline: OriginalDeadline,
    original_owner: &'a mut G,
}

impl<G: FnMut(&NativeV6PeerEnrollment, &NativeV6PublishedRoot) -> ArchiveResult<()>>
    ActualArchiveRoot<'_, G>
{
    fn owner(&mut self) -> ArchiveResult<()> {
        original_operation(self.deadline)?;
        let selected = self.active.as_ref().unwrap_or(&self.initial);
        (self.original_owner)(selected.enrollment(), selected.root())?;
        original_operation(self.deadline)
    }

    fn fresh_same(&mut self) -> ArchiveResult<NativeV6CommittedRootRead> {
        self.owner()?;
        let node = self
            .process
            .node
            .as_ref()
            .ok_or(NativeV6ArchiveError::Gate)?;
        let fresh = self
            .process
            .runtime
            .block_on(node.native_v6_committed_root_read(self.deadline.instant()))
            .map_err(|_| NativeV6ArchiveError::Gate)?
            .ok_or(NativeV6ArchiveError::WrongSelection)?;
        if !fresh.same_selection(&self.initial)
            || fresh.operation_deadline() != self.deadline.instant()
        {
            return Err(NativeV6ArchiveError::WrongSelection);
        }
        self.native
            .validate_enrollment(&self.process.codec, fresh.enrollment())
            .map_err(|_| NativeV6ArchiveError::WrongSelection)?;
        self.process
            .runtime
            .block_on(node.verify_native_v6_committed_root_read(&fresh))
            .map_err(|_| NativeV6ArchiveError::Gate)?;
        self.owner()?;
        Ok(fresh)
    }

    fn check(&mut self) -> ArchiveResult<()> {
        self.owner()?;
        // This does not retry a failed currentness check. Only expiry of the
        // original capped witness permits asking for a new actual observation;
        // that observation must still match the untouched initial selection.
        if Instant::now()
            >= self
                .active
                .as_ref()
                .unwrap_or(&self.initial)
                .read_index_deadline()
        {
            self.active = Some(self.fresh_same()?);
        }
        let selected = self.active.as_ref().unwrap_or(&self.initial);
        if selected.operation_deadline() != self.deadline.instant() {
            return Err(NativeV6ArchiveError::WrongSelection);
        }
        self.native
            .validate_enrollment(&self.process.codec, selected.enrollment())
            .map_err(|_| NativeV6ArchiveError::WrongSelection)?;
        let node = self
            .process
            .node
            .as_ref()
            .ok_or(NativeV6ArchiveError::Gate)?;
        self.process
            .runtime
            .block_on(node.verify_native_v6_committed_root_read(selected))
            .map_err(|_| NativeV6ArchiveError::Gate)?;
        self.owner()
    }
}

fn local_gate<G: FnMut(&NativeV6PeerEnrollment, &NativeV6PublishedRoot) -> ArchiveResult<()>>(
    owner: &RefCell<ActualArchiveRoot<'_, G>>,
) -> Result<(), LocalV6BlobError> {
    owner
        .try_borrow_mut()
        .map_err(|_| LocalV6BlobError::CorruptOrChanged)?
        .check()
        .map_err(|_| LocalV6BlobError::CorruptOrChanged)
}

fn archive_gate<G: FnMut(&NativeV6PeerEnrollment, &NativeV6PublishedRoot) -> ArchiveResult<()>>(
    owner: &RefCell<ActualArchiveRoot<'_, G>>,
) -> ArchiveResult<()> {
    owner
        .try_borrow_mut()
        .map_err(|_| NativeV6ArchiveError::Gate)?
        .check()
}

impl HaProcess {
    /// Repair only the exact CURRENT root's original ciphertext while its real
    /// quorum exists. This intentionally bypasses only the normal *peer pull*
    /// attempt, which cannot succeed when all donors lost these external files.
    /// Actual configured pins, consensus and archive authentication still hold.
    ///
    /// The method makes no Raft write and does not install either archived pack,
    /// local core, old replay ledger, cursor or epoch. Existing corrupt leaves
    /// remain unchanged and cause failure. Checked no-replace staging writes a
    /// missing destination or reauthenticates/fsyncs an exact existing file.
    /// Failed attempts can leave exact immutable local bytes; they return no
    /// completed repair/read and those bytes are never quorum acknowledgments.
    pub(crate) fn repair_native_v6_current_closure_from_archive<R: Read + Seek>(
        &self,
        reader: R,
        expected_seal_identity: [u8; 32],
        archive_barrier: &AeadBarrier,
        deadline: OriginalDeadline,
        original_owner: &mut impl FnMut(
            &NativeV6PeerEnrollment,
            &NativeV6PublishedRoot,
        ) -> ArchiveResult<()>,
    ) -> ArchiveResult<NativeV6ArchiveRepair> {
        original_operation(deadline)?;
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(NativeV6ArchiveError::Gate);
        }
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or(NativeV6ArchiveError::Gate)?;
        let node = self.node.as_ref().ok_or(NativeV6ArchiveError::Gate)?;
        let initial = self
            .runtime
            .block_on(node.native_v6_committed_root_read(deadline.instant()))
            .map_err(|_| NativeV6ArchiveError::Gate)?
            .ok_or(NativeV6ArchiveError::WrongSelection)?;
        if initial.operation_deadline() != deadline.instant() {
            return Err(NativeV6ArchiveError::WrongSelection);
        }
        native
            .validate_enrollment(&self.codec, initial.enrollment())
            .map_err(|_| NativeV6ArchiveError::WrongSelection)?;
        original_owner(initial.enrollment(), initial.root())?;
        original_operation(deadline)?;
        let expected =
            NativeV6ArchiveSelection::from_committed(initial.enrollment(), initial.root())?;
        let intent = initial.root().intent();
        let storage = native.storage.get().ok_or(NativeV6ArchiveError::Storage)?;
        let owner = RefCell::new(ActualArchiveRoot {
            process: self,
            native,
            initial,
            active: None,
            deadline,
            original_owner,
        });
        let mut archive = validate_native_v6_archive(
            reader,
            &expected,
            expected_seal_identity,
            archive_barrier,
            deadline,
            &mut || archive_gate(&owner),
        )?;
        let report = archive.report();
        let references = archive.references().to_vec();
        // Revisit every selected archive leaf using the decoder's digest and
        // original per-I/O gate. No caller can exchange the validated reader
        // for an ambient path or supply independent bytes/counts at this stage.
        archive.visit_shared_ciphertext(
            &mut || archive_gate(&owner),
            &mut |reference, bytes| {
                archive_gate(&owner)?;
                let receipt = storage
                    .stage_received_replica_checked(reference, bytes, &mut || local_gate(&owner))
                    .map_err(|_| NativeV6ArchiveError::Storage)?;
                if receipt.reference() != reference {
                    return Err(NativeV6ArchiveError::Corrupt);
                }
                archive_gate(&owner)
            },
        )?;
        let local: LocalV6ClosureReceipt = storage
            .persist_local_closure(&references, &mut || local_gate(&owner))
            .map_err(|_| NativeV6ArchiveError::Storage)?;
        if local.manifest_sha256() != intent.closure_manifest_sha256
            || local.object_count() as u64 != intent.object_count
            || local.ciphertext_bytes() != intent.ciphertext_bytes
            || report.shared_object_count != intent.object_count
            || report.shared_ciphertext_bytes != intent.ciphertext_bytes
        {
            return Err(NativeV6ArchiveError::WrongSelection);
        }
        // A canonical manifest fsync is not a substitute for the leaf fsyncs
        // above. Reopen both the exact installed manifest and its full closure
        // under actual held-directory/read gates before the final fresh read.
        let (manifest, reopened) = {
            let selected = owner
                .try_borrow()
                .map_err(|_| NativeV6ArchiveError::Gate)?
                .initial
                .root()
                .clone();
            storage
                .reopen_root_closure_archive(&selected, &mut || local_gate(&owner))
                .map_err(|_| NativeV6ArchiveError::Storage)?
        };
        if manifest.as_slice() != archive.manifest() || reopened != references {
            return Err(NativeV6ArchiveError::Corrupt);
        }
        // This unconditional final NEW ReadIndex is necessary even if the
        // active intermediate witness still fits inside its own eight seconds.
        let selected = owner
            .try_borrow_mut()
            .map_err(|_| NativeV6ArchiveError::Gate)?
            .fresh_same()?;
        let read = CommittedNativeV6Read {
            instance: native.identity.clone(),
            selected,
            deadline,
        };
        self.verify_native_v6_committed_read(&read)
            .map_err(|_| NativeV6ArchiveError::Gate)?;
        owner
            .try_borrow_mut()
            .map_err(|_| NativeV6ArchiveError::Gate)?
            .owner()?;
        Ok(NativeV6ArchiveRepair {
            read,
            archive: report,
        })
    }
}
