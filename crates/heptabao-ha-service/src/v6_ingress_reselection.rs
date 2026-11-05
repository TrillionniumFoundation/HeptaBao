//! A first, read-only closure observation. No repair callback can be entered
//! here. Only an actual successful successor ReadIndex can produce Superseded.
use super::*;
use std::cell::Cell;

pub enum NativeV6IngressClosureRead {
    Complete(NativeV6CommittedRootRead),
    NeedsOriginalRepair(NativeV6CommittedRootRead),
    Superseded(NativeV6IngressSupersededRead),
}

// No constructor, Clone, Serde or public fields. The two actual selections,
// held staging instance and operation owner survive until the one continuation.
pub struct NativeV6IngressSupersededRead {
    previous: Box<NativeV6CommittedRootRead>,
    fresh: NativeV6CommittedRootRead,
    storage: Arc<LocalV6BlobStage>,
    _operation: heptabao_raft_runtime::NativeV6BlobOperation,
    _historical_data: HistoricalClosureData,
}

// Formatting exposes fixed type/variant labels, never retained authority data.
impl std::fmt::Debug for NativeV6IngressClosureRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Complete(_) => "NativeV6IngressClosureRead::Complete(..)",
            Self::NeedsOriginalRepair(_) => "NativeV6IngressClosureRead::NeedsOriginalRepair(..)",
            Self::Superseded(_) => "NativeV6IngressClosureRead::Superseded(..)",
        })
    }
}

impl std::fmt::Debug for NativeV6IngressSupersededRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeV6IngressSupersededRead(..)")
    }
}

// A complete DATA-only validation, never an application read or fsync receipt.
// Its constructor below cannot return after a failed/partial physical pass.
struct HistoricalClosureData {
    _root: [u8; 32],
    _objects: usize,
}

impl NativeV6IngressSupersededRead {
    pub fn previous_root(&self) -> &heptabao_raft_runtime::NativeV6PublishedRoot {
        self.previous.root()
    }
    pub fn operation_deadline(&self) -> Instant {
        self.previous.operation_deadline()
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.previous.read_index_deadline()
    }
    pub fn enrollment(&self) -> &heptabao_raft_runtime::NativeV6PeerEnrollment {
        self.fresh.enrollment()
    }

    /// Consumed once, after the Service's separate fresh-ingress permission.
    /// This is an ordinary complete reopen/repair of this NEW actual root;
    /// the old strict helper may not adopt another different publication.
    pub fn complete(
        self,
        raft: &ProcessRaftNode,
        runtime: &Handle,
        transport: &MutualTlsPeerTransport,
        routes: &BTreeMap<u64, NodeId>,
        storage: &Arc<LocalV6BlobStage>,
    ) -> Result<NativeV6CommittedRootRead, HaError> {
        check_deadline(self.original_read_deadline().min(self.operation_deadline()))?;
        if !Arc::ptr_eq(&self.storage, storage)
            || self.fresh.operation_deadline() != self.previous.operation_deadline()
            || self.fresh.read_index_deadline() > self.previous.read_index_deadline()
        {
            return Err(unknown());
        }
        read_or_recover_native_v6_committed_closure(
            raft,
            runtime,
            transport,
            routes,
            &self.storage,
            self.fresh,
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    None,
    Witness,
    Other,
}

pub fn read_native_v6_fresh_ingress_closure(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    routes: &BTreeMap<u64, NodeId>,
    storage: Arc<LocalV6BlobStage>,
    selected: NativeV6CommittedRootRead,
) -> Result<NativeV6IngressClosureRead, HaError> {
    read_native_v6_fresh_ingress_closure_inner(
        raft,
        runtime,
        routes,
        storage,
        selected,
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
pub(in crate::v6_closure_quorum) fn read_native_v6_fresh_ingress_closure_observed(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    routes: &BTreeMap<u64, NodeId>,
    storage: Arc<LocalV6BlobStage>,
    selected: NativeV6CommittedRootRead,
    observer: &mut dyn FnMut(usize) -> Result<(), HaError>,
) -> Result<NativeV6IngressClosureRead, HaError> {
    read_native_v6_fresh_ingress_closure_inner(
        raft,
        runtime,
        routes,
        storage,
        selected,
        Some(observer),
    )
}

fn read_native_v6_fresh_ingress_closure_inner(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    routes: &BTreeMap<u64, NodeId>,
    storage: Arc<LocalV6BlobStage>,
    selected: NativeV6CommittedRootRead,
    #[cfg(test)] mut observer: Option<&mut dyn FnMut(usize) -> Result<(), HaError>>,
) -> Result<NativeV6IngressClosureRead, HaError> {
    require_blocking_worker()?;
    check_deadline(
        selected
            .operation_deadline()
            .min(selected.read_index_deadline()),
    )?;
    let pins = selected.enrollment().pins();
    if !pins.contains_key(&raft.id())
        || routes.keys().copied().collect::<BTreeSet<_>>() != pins.keys().copied().collect()
        || routes.values().collect::<BTreeSet<_>>().len() != routes.len()
    {
        return Err(HaError::InvalidMembership);
    }
    let operation = storage
        .begin_native_operation()
        .map_err(|_| HaError::Transport)?;
    let refusal = Cell::new(Refusal::None);
    #[cfg(test)]
    let mut gates = 0;
    let mut gate = || {
        if refusal.get() == Refusal::Other {
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        #[cfg(test)]
        {
            gates += 1;
            if let Some(observer) = observer.as_mut()
                && observer(gates).is_err()
            {
                refusal.set(Refusal::Other);
                return Err(LocalV6BlobError::CorruptOrChanged);
            }
        }
        if check_deadline(
            selected
                .operation_deadline()
                .min(selected.read_index_deadline()),
        )
        .is_err()
        {
            refusal.set(Refusal::Other);
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        let verified = runtime.block_on(raft.verify_native_v6_committed_root_read(&selected));
        // Verification itself may wait until its capped deadline and report
        // Consensus. Such a timeout is not an application-progress refusal.
        if check_deadline(
            selected
                .operation_deadline()
                .min(selected.read_index_deadline()),
        )
        .is_err()
        {
            refusal.set(Refusal::Other);
            return Err(LocalV6BlobError::CorruptOrChanged);
        }
        match verified {
            Ok(()) => Ok(()),
            Err(heptabao_raft_runtime::RemoteRaftError::Consensus(_)) => {
                // This is explicitly a historical ciphertext DATA pass, not a
                // current-read gate. Finish physical validation independently
                // so a post-read witness refusal cannot mask an earlier EIO,
                // Interrupted, short EOF, parse or digest failure.
                refusal.set(Refusal::Witness);
                Ok(())
            }
            Err(_) => {
                refusal.set(Refusal::Other);
                Err(LocalV6BlobError::CorruptOrChanged)
            }
        }
    };
    // Unlike reopen_root_closure's current-read contract, the archive primitive
    // explicitly returns historical DATA only. All strict readers remain
    // unchanged. No live handle is returned from this pass alone.
    let reopened = storage.reopen_root_closure_archive(selected.root(), &mut gate);
    let historical_data = match reopened {
        Ok((_manifest, references)) => {
            wire::exact_manifest(&references, &selected.root().intent())?;
            gate().map_err(|_| unknown())?;
            HistoricalClosureData {
                _root: selected.root().root_digest(),
                _objects: references.len(),
            }
        }
        Err(_) if refusal.get() != Refusal::Other => {
            // The original exact-root repair is still available, but it can
            // never return this no-effects supersession token after entry.
            return Ok(NativeV6IngressClosureRead::NeedsOriginalRepair(selected));
        }
        Err(_) => return Err(unknown()),
    };
    let witness_only = refusal.get() == Refusal::Witness;
    // An I/O/timeout error here is terminal. Do not reclassify it by subsequently
    // checking whether the old witness also happened to become invalid.
    let fresh = runtime
        .block_on(raft.native_v6_fresh_ingress_selection_read(&selected))
        .map_err(|_| unknown())?;
    let advanced = fresh.application_generation() > selected.application_generation();
    if !advanced {
        if witness_only || fresh.root() != selected.root() {
            return Err(unknown());
        }
        return Ok(NativeV6IngressClosureRead::Complete(fresh));
    }
    check_deadline(
        selected
            .operation_deadline()
            .min(selected.read_index_deadline()),
    )?;
    // A successful NEW quorum read must come first. Only then confirm that
    // the original opaque witness is actually refused; a network failure is
    // never replaced by an unrelated old-witness observation.
    match runtime.block_on(raft.verify_native_v6_committed_root_read(&selected)) {
        Err(heptabao_raft_runtime::RemoteRaftError::Consensus(_)) => {}
        Ok(()) | Err(_) => return Err(unknown()),
    }
    check_deadline(
        selected
            .operation_deadline()
            .min(selected.read_index_deadline()),
    )?;
    Ok(NativeV6IngressClosureRead::Superseded(
        NativeV6IngressSupersededRead {
            previous: Box::new(selected),
            fresh,
            storage,
            _operation: operation,
            _historical_data: historical_data,
        },
    ))
}
