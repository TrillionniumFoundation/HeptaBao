//! Scoped repair of an already committed native closure. This path only reads
//! enrolled peers and stages exact immutable ciphertext locally. It submits no
//! Raft write, creates no quorum ACK and grants no Actor or local install right.
use super::*;
use crate::{AuthenticatedPeerFrame, serve_one_mtls_authenticated_peer_frame};
use heptabao_raft_runtime::{LocalV6BlobReceipt, LocalV6ClosureReceipt, NativeV6CommittedRootRead};
use ring::rand::{SecureRandom, SystemRandom};
use std::pin::Pin;
use std::sync::RwLock;
use tokio::sync::OwnedSemaphorePermit;

#[path = "v6_ingress_reselection.rs"]
mod ingress_reselection;
#[cfg(test)]
pub(super) use ingress_reselection::read_native_v6_fresh_ingress_closure_observed;
pub use ingress_reselection::{
    NativeV6IngressClosureRead, NativeV6IngressSupersededRead, read_native_v6_fresh_ingress_closure,
};

#[path = "v6_committed_root_pull_wire.rs"]
mod pull_wire;
use pull_wire::{Kind as PullKind, RootBinding};

#[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
#[path = "v6_root_pull_diagnostic.rs"]
mod root_diagnostic;

// These macros only observe the original expression. In default production
// builds no timing state, clock read, counter, or log emission is generated.
#[cfg(feature = "private-forward-stage-diagnostic")]
macro_rules! root_phase {
    ($phase:ident, $work:expr) => {{
        let phase = root_diagnostic::Span::start(root_diagnostic::Phase::$phase);
        let result = $work;
        if let Some(phase) = phase {
            phase.finish(result.is_ok());
        }
        result
    }};
    (context $context:expr, $phase:ident, $work:expr) => {{
        let phase =
            root_diagnostic::Span::from_context($context.clone(), root_diagnostic::Phase::$phase);
        let result = $work;
        if let Some(phase) = phase {
            phase.finish(result.is_ok());
        }
        result
    }};
}

#[cfg(feature = "private-forward-stage-diagnostic")]
macro_rules! root_phase_begin {
    ($binding:ident, $phase:ident) => {
        let $binding = root_diagnostic::Span::start(root_diagnostic::Phase::$phase);
    };
}

#[cfg(not(feature = "private-forward-stage-diagnostic"))]
macro_rules! root_phase_begin {
    ($binding:ident, $phase:ident) => {};
}

#[cfg(feature = "private-forward-stage-diagnostic")]
macro_rules! root_phase_finish {
    ($binding:ident, $work:expr) => {{
        let result = $work;
        if let Some(phase) = $binding {
            phase.finish(result.is_ok());
        }
        result
    }};
}

#[cfg(not(feature = "private-forward-stage-diagnostic"))]
macro_rules! root_phase_finish {
    ($binding:ident, $work:expr) => {
        $work
    };
}

#[cfg(not(feature = "private-forward-stage-diagnostic"))]
macro_rules! root_phase {
    ($phase:ident, $work:expr) => {
        $work
    };
    (context $context:expr, $phase:ident, $work:expr) => {
        $work
    };
}

#[cfg(feature = "private-forward-stage-diagnostic")]
macro_rules! root_count {
    ($kind:ident, $count:expr, $bytes:expr) => {
        root_diagnostic::count(
            root_diagnostic::Counter::$kind,
            $count as u64,
            $bytes as u64,
        )
    };
}

#[cfg(not(feature = "private-forward-stage-diagnostic"))]
macro_rules! root_count {
    ($kind:ident, $count:expr, $bytes:expr) => {};
}

/// Classification alone grants no authenticated ingress or selected-root right.
pub fn is_native_v6_root_pull_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(b"HBVP2")
}

struct SourceManifest {
    binding: RootBinding,
    generation: u64,
    references: Vec<RecordObjectRef>,
}

/// Read-only ciphertext source on an actual enrolled ProcessRaftNode. Its
/// configured opaque enrollment only selects initial pins. EVERY request must
/// match a fresh actual applied native root under the accepted socket deadline.
pub struct NativeV6CommittedRootSource {
    raft: Arc<ProcessRaftNode>,
    runtime: Handle,
    storage: Arc<LocalV6BlobStage>,
    pinned: PinnedClientCertificateMap,
    voters: BTreeMap<[u8; 32], u64>,
    initial_enrollment: NativeV6PeerEnrollment,
    // One bounded immutable-reference cache, not a read or fsync capability.
    manifest: RwLock<Option<Arc<SourceManifest>>>,
}

impl fmt::Debug for NativeV6CommittedRootSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6CommittedRootSource")
            .field("voter", &self.raft.id())
            .field("enrolled_voters", &self.voters.len())
            .finish_non_exhaustive()
    }
}

impl NativeV6CommittedRootSource {
    pub fn new(
        raft: Arc<ProcessRaftNode>,
        runtime: Handle,
        storage: Arc<LocalV6BlobStage>,
        enrollment: &NativeV6PeerEnrollment,
    ) -> Result<Self, HaError> {
        if !enrollment.pins().contains_key(&raft.id()) || enrollment.pins().len() < 3 {
            return Err(HaError::InvalidMembership);
        }
        let mut pins = BTreeMap::new();
        let mut voters = BTreeMap::new();
        for (&voter, &pin) in enrollment.pins() {
            if pins.insert(pin, private_peer_name(voter)?).is_some()
                || voters.insert(pin, voter).is_some()
            {
                return Err(HaError::InvalidMembership);
            }
        }
        Ok(Self {
            raft,
            runtime,
            storage,
            pinned: PinnedClientCertificateMap::new(pins)?,
            voters,
            initial_enrollment: enrollment.clone(),
            manifest: RwLock::new(None),
        })
    }

    pub fn serve_one_mtls(
        &self,
        listener: &TcpListener,
        server: Arc<rustls::ServerConfig>,
        timeout: Duration,
    ) -> Result<(), HaError> {
        require_blocking_worker()?;
        serve_one_mtls_authenticated_peer_frame(
            listener,
            server,
            &self.pinned,
            timeout,
            false,
            |frame| self.handle_authenticated(frame),
        )
    }

    /// Native repair accepts any actually enrolled requesting voter, including
    /// a new leader whose local closure is absent. It does not infer leadership
    /// from that client's leaf. The selected root/full LogIds/term must equal
    /// this source's own fresh real ReadIndex observation before bytes leave.
    pub fn handle_authenticated(&self, frame: AuthenticatedPeerFrame) -> Result<Vec<u8>, HaError> {
        #[cfg(feature = "private-forward-stage-diagnostic")]
        let _root_observation =
            root_diagnostic::Scope::enter(root_diagnostic::Side::Donor, frame.deadline());
        root_phase_begin!(root_total, DonorRequest);
        let _native_operation = self
            .storage
            .begin_native_operation()
            .map_err(|_| HaError::Transport)?;
        require_blocking_worker()?;
        check_deadline(frame.deadline())?;
        if !frame.has_strict_raft_alpn() {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let actual_voter = self
            .voters
            .get(&frame.actual_leaf_sha256())
            .copied()
            .ok_or(HaError::UnknownPeer)?;
        let request = pull_wire::parse(frame.payload())?;
        if request.requester != actual_voter || request.target != self.raft.id() {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let read = root_phase!(
            ReadIndex,
            self.runtime
                .block_on(self.raft.native_v6_committed_root_read(frame.deadline()))
        )
        .map_err(|_| unknown())?
        .ok_or_else(unknown)?;
        if !read
            .enrollment()
            .same_peer_configuration(&self.initial_enrollment)
            || RootBinding::observed(&read) != request.binding
            || read.enrollment().pins().get(&actual_voter) != Some(&frame.actual_leaf_sha256())
        {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let verify = || {
            check_deadline(frame.deadline())?;
            root_phase!(
                WitnessVerify,
                self.runtime
                    .block_on(self.raft.verify_native_v6_committed_root_read(&read))
            )
            .map_err(|_| unknown())?;
            check_deadline(frame.deadline())
        };
        verify()?;
        // Concurrent single-object reads share only immutable references. The
        // cache never holds an authority, and no lock spans per-object payload
        // I/O or the final fresh-witness check. A cache replacement cannot invalidate
        // the request's owned reference snapshot or extend its actual witness.
        let cached = self.manifest.try_read().map_err(|_| unknown())?;
        let selected = cached
            .as_ref()
            .filter(|cached| {
                cached.binding == request.binding
                    && cached.generation == read.application_generation()
            })
            .cloned();
        drop(cached);
        let selected = if let Some(selected) = selected {
            selected
        } else {
            let mut manifest = self.manifest.try_write().map_err(|_| unknown())?;
            if let Some(selected) = manifest.as_ref().filter(|cached| {
                cached.binding == request.binding
                    && cached.generation == read.application_generation()
            }) {
                selected.clone()
            } else {
                // Rebuilding a cache reopens the actual full manifest/closure under
                // this new witness; no cached generation ever becomes authority.
                let mut gate = || verify().map_err(|_| LocalV6BlobError::CorruptOrChanged);
                let references = root_phase!(
                    DonorReopen,
                    self.storage.reopen_root_closure(read.root(), &mut gate)
                )
                .map_err(|_| unknown())?;
                wire::exact_manifest(&references, &request.binding.intent)?;
                let selected = Arc::new(SourceManifest {
                    binding: request.binding.clone(),
                    generation: read.application_generation(),
                    references,
                });
                *manifest = Some(selected.clone());
                selected
            }
        };
        let payload = match request.kind {
            PullKind::Manifest => {
                if request.payload.len() != 4 {
                    return Err(HaError::InvalidFrame);
                }
                let offset = u32::from_be_bytes(
                    request
                        .payload
                        .try_into()
                        .map_err(|_| HaError::InvalidFrame)?,
                ) as usize;
                if offset >= selected.references.len() {
                    return Err(HaError::InvalidFrame);
                }
                let end = offset
                    .saturating_add(wire::PAGE_OBJECTS)
                    .min(selected.references.len());
                wire::manifest_page(offset, &selected.references[offset..end])?
            }
            PullKind::Object => {
                let reference = wire::parse_reference(request.payload)?;
                let index = selected
                    .references
                    .binary_search_by_key(&reference.id, |item| item.id)
                    .map_err(|_| HaError::InvalidFrame)?;
                if selected.references.get(index) != Some(&reference) {
                    return Err(HaError::InvalidFrame);
                }
                verify()?;
                root_phase!(DonorObjectRead, self.storage.read_local(&reference))
                    .map_err(|_| unknown())?
            }
        };
        verify()?;
        root_phase_finish!(root_total, pull_wire::reply(&request, &payload))
    }
}

/// A locally fsynced exact closure plus a NEW, actually verified same-root
/// ReadIndex handle. This contains no remote quorum receipts and cannot be
/// passed as NativeV6ClosureQuorum. The Service still owns Actor/barrier/install.
pub struct RecoveredNativeV6LocalClosure {
    selected: NativeV6CommittedRootRead,
    local: LocalV6ClosureReceipt,
}

impl fmt::Debug for RecoveredNativeV6LocalClosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredNativeV6LocalClosure")
            .field("selected", &self.selected)
            .field("object_count", &self.local.object_count())
            .finish_non_exhaustive()
    }
}

impl RecoveredNativeV6LocalClosure {
    pub fn read(&self) -> &NativeV6CommittedRootRead {
        &self.selected
    }
    pub fn local_receipt(&self) -> &LocalV6ClosureReceipt {
        &self.local
    }
    pub fn into_parts(self) -> (NativeV6CommittedRootRead, LocalV6ClosureReceipt) {
        (self.selected, self.local)
    }
}

fn fresh_same(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    selected: &NativeV6CommittedRootRead,
) -> Result<NativeV6CommittedRootRead, HaError> {
    check_deadline(selected.operation_deadline())?;
    let fresh = root_phase!(
        ReadIndex,
        runtime.block_on(raft.native_v6_fresh_same_selection_read(selected))
    )
    .map_err(|_| unknown())?;
    if !fresh.same_selection(selected) {
        return Err(unknown());
    }
    root_phase!(
        WitnessVerify,
        runtime.block_on(raft.verify_native_v6_committed_root_read(&fresh))
    )
    .map_err(|_| unknown())?;
    check_deadline(selected.operation_deadline())?;
    Ok(fresh)
}

fn finish_local(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    storage: &LocalV6BlobStage,
    selected: NativeV6CommittedRootRead,
    references: &[RecordObjectRef],
    fsynced: &[bool],
) -> Result<RecoveredNativeV6LocalClosure, HaError> {
    root_phase_begin!(root_total, FinishLocal);
    if references.len() != fsynced.len() {
        return Err(HaError::InvalidFrame);
    }
    wire::exact_manifest(references, &selected.root().intent())?;
    let fresh = fresh_same(raft, runtime, &selected)?;
    let mut gate = || {
        check_deadline(selected.operation_deadline())
            .and_then(|()| {
                root_phase!(
                    WitnessVerify,
                    runtime.block_on(raft.verify_native_v6_committed_root_read(&fresh))
                )
                .map_err(|_| unknown())
            })
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)
    };
    let mut pending = Vec::with_capacity(LocalV6BlobStage::MAX_CHECKED_BATCH_OBJECTS);
    let mut pending_bytes = 0usize;
    for (reference, already_fsynced) in references.iter().zip(fsynced) {
        if !already_fsynced {
            let expected_bytes =
                usize::try_from(reference.encoded_bytes).map_err(|_| HaError::InvalidFrame)?;
            if expected_bytes > LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES {
                return Err(HaError::InvalidFrame);
            }
            if !pending.is_empty()
                && (pending.len() == LocalV6BlobStage::MAX_CHECKED_BATCH_OBJECTS
                    || pending_bytes.checked_add(expected_bytes).is_none_or(|sum| {
                        sum > LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES
                    }))
            {
                synchronize_existing_pull_batch(storage, &pending, &mut gate)?;
                pending.clear();
                pending_bytes = 0;
            }
            gate().map_err(|_| unknown())?;
            let ciphertext =
                root_phase!(FinishRead, storage.read_local(reference)).map_err(|_| unknown())?;
            if ciphertext.len() != expected_bytes {
                return Err(unknown());
            }
            pending_bytes = pending_bytes
                .checked_add(ciphertext.len())
                .filter(|sum| *sum <= LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES)
                .ok_or_else(unknown)?;
            pending.push((reference.clone(), ciphertext));
        }
    }
    synchronize_existing_pull_batch(storage, &pending, &mut gate)?;
    let local = root_phase!(
        PersistClosure,
        storage.persist_local_closure(references, &mut gate)
    )
    .map_err(|_| unknown())?;
    let intent = selected.root().intent();
    if local.manifest_sha256() != intent.closure_manifest_sha256
        || local.object_count() as u64 != intent.object_count
        || local.ciphertext_bytes() != intent.ciphertext_bytes
    {
        return Err(unknown());
    }
    gate().map_err(|_| unknown())?;
    // This new read may have a new capped ReadIndex deadline, but the old
    // witness is never edited and the original operation deadline is identical.
    let selected = fresh_same(raft, runtime, &selected)?;
    root_phase_finish!(
        root_total,
        Ok(RecoveredNativeV6LocalClosure { selected, local })
    )
}

fn synchronize_existing_pull_batch(
    storage: &LocalV6BlobStage,
    pending: &[(RecordObjectRef, Vec<u8>)],
    gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
) -> Result<(), HaError> {
    root_phase_begin!(root_total, ExistingSyncBatch);
    if pending.is_empty() {
        return root_phase_finish!(root_total, Ok(()));
    }
    let objects: Vec<_> = pending
        .iter()
        .map(|(reference, ciphertext)| (reference, ciphertext.as_slice()))
        .collect();
    let receipts = storage
        .sync_existing_replicas_batch_checked(&objects, gate)
        .map_err(|_| unknown())?;
    if receipts.len() != pending.len()
        || receipts
            .iter()
            .zip(pending)
            .any(|(receipt, (reference, _))| receipt.reference() != reference)
    {
        return Err(unknown());
    }
    root_phase_finish!(root_total, Ok(()))
}

// A committed manifest may differ by one small leaf after this voter was
// offline. Authenticate and physically re-admit its existing exact leaves in
// bounded batches before asking peers for missing ciphertext. Presence is no
// receipt: only the original checked fsync path sets a bit, and any error on a
// present leaf is terminal rather than being reclassified as an absent leaf.
fn synchronize_available_pull_objects(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    storage: &LocalV6BlobStage,
    selected: &NativeV6CommittedRootRead,
    references: &[RecordObjectRef],
    fsynced: &mut [bool],
) -> Result<(), HaError> {
    root_phase_begin!(root_total, AvailableObjects);
    if references.len() != fsynced.len() || fsynced.iter().any(|done| *done) {
        return Err(HaError::InvalidFrame);
    }
    wire::exact_manifest(references, &selected.root().intent())?;
    let mut offset = 0;
    while offset < references.len() {
        let mut end = offset;
        let mut batch_bytes = 0usize;
        while let Some(reference) = references.get(end) {
            let bytes =
                usize::try_from(reference.encoded_bytes).map_err(|_| HaError::InvalidFrame)?;
            if bytes > LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES {
                return Err(HaError::InvalidFrame);
            }
            if end - offset == LocalV6BlobStage::MAX_CHECKED_BATCH_OBJECTS
                || batch_bytes.checked_add(bytes).is_none_or(|total| {
                    total > LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES
                })
            {
                break;
            }
            batch_bytes += bytes;
            end += 1;
        }
        let fresh = fresh_same(raft, runtime, selected)?;
        let mut gate = || {
            check_deadline(selected.operation_deadline())
                .and_then(|()| {
                    root_phase!(
                        WitnessVerify,
                        runtime.block_on(raft.verify_native_v6_committed_root_read(&fresh))
                    )
                    .map_err(|_| unknown())
                })
                .map_err(|_| LocalV6BlobError::CorruptOrChanged)
        };
        let mut pending = Vec::with_capacity(end - offset);
        let mut indices = Vec::with_capacity(end - offset);
        for (index, reference) in references.iter().enumerate().take(end).skip(offset) {
            if let Some(ciphertext) = root_phase!(
                AvailableRead,
                storage.read_local_if_present_checked(reference, &mut gate)
            )
            .map_err(|_| unknown())?
            {
                root_count!(Available, 1, ciphertext.len());
                pending.push((reference.clone(), ciphertext));
                indices.push(index);
            } else {
                root_count!(Missing, 1, reference.encoded_bytes);
            }
        }
        synchronize_existing_pull_batch(storage, &pending, &mut gate)?;
        gate().map_err(|_| unknown())?;
        for index in indices {
            fsynced[index] = true;
        }
        offset = end;
    }
    root_phase_finish!(root_total, Ok(()))
}

// A payload keeps its capacity charge until the sole consumer processes or
// drops it. Completed socket replies therefore cannot accumulate beyond the
// same eight-frame budget while slow local fsync blocks the controller.
struct VerifiedPullReply {
    payload: Vec<u8>,
    #[cfg(test)]
    _observation: Option<observation::Frame>,
    _permit: OwnedSemaphorePermit,
}

#[cfg(test)]
mod observation {
    use super::*;
    use std::cell::RefCell;

    #[derive(Clone, Debug, Default)]
    pub(crate) struct PullTaskCounts {
        pub(crate) spawned: usize,
        pub(crate) joined: usize,
        pub(crate) active_frames: usize,
        pub(crate) peak_frames: usize,
        pub(crate) per_donor_peak_frames: BTreeMap<u64, usize>,
        pub(crate) object_submissions: Vec<(u64, [u8; 32])>,
        per_donor_active_frames: BTreeMap<u64, usize>,
    }

    #[derive(Clone, Debug, Default)]
    pub(super) struct Observation(Arc<Mutex<PullTaskCounts>>);
    thread_local! {
        static CURRENT: RefCell<Option<Observation>> = const { RefCell::new(None) };
    }
    pub(super) fn current() -> Option<Observation> {
        CURRENT.with(|value| value.borrow().clone())
    }
    impl Observation {
        pub(super) fn spawned(&self, target: u64, object: Option<[u8; 32]>) {
            if let Ok(mut counts) = self.0.lock() {
                counts.spawned += 1;
                if let Some(id) = object {
                    counts.object_submissions.push((target, id));
                }
            }
        }
        pub(super) fn joined(&self) {
            if let Ok(mut counts) = self.0.lock() {
                counts.joined += 1;
            }
        }
        pub(super) fn frame(&self, target: u64) -> Frame {
            if let Ok(mut counts) = self.0.lock() {
                counts.active_frames += 1;
                counts.peak_frames = counts.peak_frames.max(counts.active_frames);
                let active = counts.per_donor_active_frames.entry(target).or_default();
                *active += 1;
                let active = *active;
                let peak = counts.per_donor_peak_frames.entry(target).or_default();
                *peak = (*peak).max(active);
            }
            Frame {
                observation: self.clone(),
                target,
            }
        }
    }
    #[derive(Debug)]
    pub(super) struct Frame {
        observation: Observation,
        target: u64,
    }
    impl Drop for Frame {
        fn drop(&mut self) {
            if let Ok(mut counts) = self.observation.0.lock() {
                counts.active_frames -= 1;
                if let Some(active) = counts.per_donor_active_frames.get_mut(&self.target) {
                    *active -= 1;
                }
            }
        }
    }
    pub(crate) fn observe_pull_tasks<T>(
        operation: impl FnOnce() -> T,
    ) -> Result<(T, PullTaskCounts), HaError> {
        struct Restore(Option<Observation>);
        impl Drop for Restore {
            fn drop(&mut self) {
                CURRENT.with(|value| {
                    value.replace(self.0.take());
                });
            }
        }
        let observation = Observation::default();
        let _scope = Restore(CURRENT.with(|value| value.replace(Some(observation.clone()))));
        let result = operation();
        let counts = observation.0.lock().map_err(|_| unknown())?.clone();
        Ok((result, counts))
    }
}
#[cfg(test)]
pub(crate) use observation::observe_pull_tasks;

/// Fixed per-donor request capacity for committed-root recovery. This is a
/// resource bound only; it grants no ingress, freshness or durability authority.
pub const NATIVE_V6_ROOT_PULL_REQUESTS_PER_DONOR: usize = 4;
/// All private closure operations share this existing ciphertext-frame charge.
pub const NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES: usize = MAX_INFLIGHT_CLOSURE_FRAMES;

#[derive(Clone, Copy)]
enum PullStep {
    Manifest(usize),
    Object(usize),
}

struct PendingPull {
    target: u64,
    step: PullStep,
    operation: tokio::task::JoinHandle<Result<VerifiedPullReply, HaError>>,
}

// Own every asynchronous socket task until its actual JoinHandle completes.
// The controller runs only on a blocking worker. Cancellation drops the task's
// sole connect/TLS/socket future; joining it does not wait for a blackhole's
// original deadline or issue another request. No task is detached on ANY exit.
struct OwnedPulls<'a> {
    runtime: &'a Handle,
    pending: Vec<PendingPull>,
    #[cfg(test)]
    observation: Option<observation::Observation>,
}

impl OwnedPulls<'_> {
    // Poll only already submitted object tasks, exactly once per call. Pending
    // sockets never delay a ready batch: in particular, no full-window barrier
    // can let one silent donor hold the other donor's verified replies hostage.
    fn take_ready_object(&mut self) -> Option<(u64, usize, Result<VerifiedPullReply, HaError>)> {
        let ready = self.runtime.block_on(poll_fn(|cx| {
            for (index, pending) in self.pending.iter_mut().enumerate() {
                let PullStep::Object(object_index) = pending.step else {
                    continue;
                };
                if let Poll::Ready(result) = Pin::new(&mut pending.operation).poll(cx) {
                    return Poll::Ready(Some((
                        index,
                        object_index,
                        result.map_err(|_| unknown()).flatten(),
                    )));
                }
            }
            Poll::Ready(None)
        }));
        let (index, object_index, result) = ready?;
        let completed = self.pending.swap_remove(index);
        #[cfg(test)]
        if let Some(observation) = &self.observation {
            observation.joined();
        }
        Some((completed.target, object_index, result))
    }

    fn retire(&mut self, target: u64) {
        root_count!(
            RetiredTasks,
            self.pending
                .iter()
                .filter(|entry| entry.target == target)
                .count(),
            0
        );
        let mut retired = Vec::new();
        let mut index = 0;
        while index < self.pending.len() {
            if self.pending[index].target == target {
                let operation = self.pending.swap_remove(index).operation;
                operation.abort();
                retired.push(operation);
            } else {
                index += 1;
            }
        }
        self.runtime.block_on(async {
            for operation in retired {
                let _ = operation.await;
                #[cfg(test)]
                if let Some(observation) = &self.observation {
                    observation.joined();
                }
            }
        });
    }

    fn cancel_and_join(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        root_count!(CancelledTasks, self.pending.len(), 0);
        for pending in &self.pending {
            pending.operation.abort();
        }
        self.runtime.block_on(async {
            for pending in self.pending.drain(..) {
                let _ = pending.operation.await;
                #[cfg(test)]
                if let Some(observation) = &self.observation {
                    observation.joined();
                }
            }
        });
    }
}

impl Drop for OwnedPulls<'_> {
    fn drop(&mut self) {
        self.cancel_and_join();
    }
}

// Immutable selection and nonce inputs shared by a pull round. This is only
// a borrowed request scope: every actual wire reply and fresh ReadIndex gate
// below is still required, under the selected operation's original deadline.
struct PullRequestContext<'a> {
    runtime: &'a Handle,
    transport: &'a MutualTlsPeerTransport,
    routes: &'a BTreeMap<u64, NodeId>,
    pins: &'a BTreeMap<u64, [u8; 32]>,
    binding: &'a RootBinding,
    requester: u64,
    round: [u8; 32],
    deadline: Instant,
    #[cfg(test)]
    observation: Option<observation::Observation>,
}

fn pending_pull(
    context: &PullRequestContext<'_>,
    target: u64,
    step: PullStep,
    references: &[RecordObjectRef],
) -> Result<PendingPull, HaError> {
    let runtime = context.runtime;
    let transport = context.transport;
    let routes = context.routes;
    let pins = context.pins;
    let binding = context.binding;
    let requester = context.requester;
    let round = context.round;
    let deadline = context.deadline;
    #[cfg(test)]
    let observation = context.observation.clone();
    let (kind, payload) = match step {
        PullStep::Manifest(offset) => (
            PullKind::Manifest,
            u32::try_from(offset)
                .map_err(|_| HaError::InvalidFrame)?
                .to_be_bytes()
                .to_vec(),
        ),
        PullStep::Object(index) => (
            PullKind::Object,
            wire::reference_payload(references.get(index).ok_or(HaError::InvalidFrame)?)?,
        ),
    };
    let transport = transport.clone();
    let route = routes.get(&target).ok_or(HaError::UnknownPeer)?.clone();
    let pin = *pins.get(&target).ok_or(HaError::UnknownPeer)?;
    let binding = binding.clone();
    #[cfg(feature = "private-forward-stage-diagnostic")]
    let diagnostic_context = root_diagnostic::capture();
    let operation = runtime.spawn(async move {
        check_deadline(deadline)?;
        let capacity = CLOSURE_FRAME_CAPACITY
            .get_or_init(|| Arc::new(Semaphore::new(MAX_INFLIGHT_CLOSURE_FRAMES)))
            .clone();
        let permit = root_phase!(context diagnostic_context, FrameCapacity, tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            capacity.acquire_owned(),
        )
        .await
        .map_err(|_| unknown())?
        .map_err(|_| unknown()))?;
        #[cfg(test)]
        let frame_observation = observation.as_ref().map(|value| value.frame(target));
        check_deadline(deadline)?;
        let request = pull_wire::encode(&binding, requester, target, round, kind, &payload)?;
        let response = root_phase!(context diagnostic_context, FrameExchange, transport
            .exchange_root_pull_before_pinned_server(&route, &request, deadline, pin)
            .await)
            .map_err(|_| unknown())?;
        check_deadline(deadline)?;
        let payload = root_phase!(context diagnostic_context, ReplyVerify, pull_wire::verified_payload(&request, response))?;
        Ok(VerifiedPullReply {
            payload,
            _permit: permit,
            #[cfg(test)]
            _observation: frame_observation,
        })
    });
    #[cfg(test)]
    if let Some(observation) = &context.observation {
        // The sole controller records actual task submission before returning to
        // its next assignment. Concurrent TLS handlers may observe another order.
        let object = match step {
            PullStep::Manifest(_) => None,
            PullStep::Object(index) => references.get(index).map(|reference| reference.id),
        };
        observation.spawned(target, object);
    }
    Ok(PendingPull {
        target,
        step,
        operation,
    })
}

// Only a donor whose actual manifest reply was authenticated can enter the
// object window. In-flight objects never set fsynced. Different donors may race
// an object, preserving the original mandatory duplicate-digest validation.
fn fill_object_window(
    pulls: &mut OwnedPulls<'_>,
    context: &PullRequestContext<'_>,
    target: u64,
    references: &[RecordObjectRef],
    fsynced: &[bool],
) -> Result<(), HaError> {
    loop {
        let active = pulls
            .pending
            .iter()
            .filter(|pending| pending.target == target)
            .count();
        if active >= NATIVE_V6_ROOT_PULL_REQUESTS_PER_DONOR {
            return Ok(());
        }
        // Spend the bounded windows on distinct missing objects first. A
        // second healthy donor must not repeatedly consume capacity for the
        // same early leaves while unassigned work remains. These assignments
        // grant no completion: only checked durable receipts set fsynced.
        let unassigned = fsynced.iter().enumerate().find_map(|(index, done)| {
            (!*done && !pulls.pending.iter().any(|pending| {
                matches!(pending.step, PullStep::Object(pending_index) if pending_index == index)
            })).then_some(index)
        });
        // Once every remaining leaf has an outstanding request, retain the
        // original cross-donor race. A silent donor cannot reserve its leaves
        // for the rest of the original operation deadline. Every duplicate
        // still passes the original exact-byte checks before it is discarded.
        let next = unassigned.or_else(|| {
            fsynced.iter().enumerate().find_map(|(index, done)| {
                (!*done && !pulls.pending.iter().any(|pending| {
                    pending.target == target
                        && matches!(pending.step, PullStep::Object(pending_index) if pending_index == index)
                })).then_some(index)
            })
        });
        let Some(index) = next else {
            return Ok(());
        };
        pulls.pending.push(pending_pull(
            context,
            target,
            PullStep::Object(index),
            references,
        )?);
    }
}

// A reply retains its existing global frame charge until the batch is dropped.
// Validate every byte against the complete selected reference BEFORE storage,
// including a duplicate of a durable leaf or another entry in this ready batch.
fn append_ready_pull_object(
    ready: &mut Vec<(usize, VerifiedPullReply)>,
    references: &[RecordObjectRef],
    fsynced: &[bool],
    index: usize,
    response: VerifiedPullReply,
) -> Result<(), HaError> {
    root_count!(ObjectReply, 1, response.payload.len());
    let reference = references.get(index).ok_or(HaError::InvalidFrame)?;
    if references.len() != fsynced.len()
        || response.payload.len() != reference.encoded_bytes as usize
    {
        return Err(HaError::InvalidFrame);
    }
    let object = heptabao_raft_runtime::SealedRecordObject::new_native_v6_ciphertext_chunk(
        response.payload.clone(),
    )
    .map_err(|_| HaError::InvalidFrame)?;
    if object.reference() != reference {
        return Err(HaError::InvalidFrame);
    }
    if fsynced[index] || ready.iter().any(|(seen, _)| *seen == index) {
        root_count!(DuplicateObject, 1, response.payload.len());
        return Ok(());
    }
    if ready.len() >= NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES {
        return Err(HaError::InvalidFrame);
    }
    ready.push((index, response));
    Ok(())
}

// This final bookkeeping accepts actual opaque local receipts only. Check the
// entire set before changing any bit, so missing/misordered/duplicate receipts
// cannot turn physically present bytes into a partial delivery permission.
fn accept_ready_pull_receipts(
    references: &[RecordObjectRef],
    indices: &[usize],
    receipts: &[LocalV6BlobReceipt],
    fsynced: &mut [bool],
) -> Result<(), HaError> {
    if references.len() != fsynced.len()
        || indices.is_empty()
        || indices.len() != receipts.len()
        || indices.len() > NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES
        || indices.iter().copied().collect::<BTreeSet<_>>().len() != indices.len()
        || indices.iter().zip(receipts).any(|(index, receipt)| {
            references.get(*index) != Some(receipt.reference())
                || fsynced.get(*index) != Some(&false)
        })
    {
        return Err(HaError::InvalidFrame);
    }
    for &index in indices {
        fsynced[index] = true;
    }
    Ok(())
}

fn persist_ready_pull_batch(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    storage: &LocalV6BlobStage,
    fresh: &NativeV6CommittedRootRead,
    references: &[RecordObjectRef],
    fsynced: &mut [bool],
    ready: &[(usize, VerifiedPullReply)],
) -> Result<(), HaError> {
    root_phase_begin!(root_total, ReadyBatch);
    if ready.is_empty() {
        return root_phase_finish!(root_total, Ok(()));
    }
    // The original leaf contract is 25..=256KiB; at most eight frame-charged
    // replies therefore fit the existing 32-object / 4MiB physical batch.
    if ready.len() > NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES
        || ready.len() > LocalV6BlobStage::MAX_CHECKED_BATCH_OBJECTS
        || ready
            .iter()
            .try_fold(0usize, |total, (_, reply)| {
                total.checked_add(reply.payload.len())
            })
            .is_none_or(|bytes| bytes > LocalV6BlobStage::MAX_CHECKED_BATCH_CIPHERTEXT_BYTES)
    {
        return Err(HaError::InvalidFrame);
    }
    let mut gate = || {
        check_deadline(fresh.operation_deadline())
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        root_phase!(
            WitnessVerify,
            runtime.block_on(raft.verify_native_v6_committed_root_read(fresh))
        )
        .map_err(|_| LocalV6BlobError::CorruptOrChanged)
    };
    let ciphertexts: Vec<_> = ready
        .iter()
        .map(|(_, response)| response.payload.as_slice())
        .collect();
    let receipts = storage
        .stage_local_batch_checked(&ciphertexts, &mut gate)
        .map_err(|_| unknown())?;
    gate().map_err(|_| unknown())?;
    let indices: Vec<_> = ready.iter().map(|(index, _)| *index).collect();
    accept_ready_pull_receipts(references, &indices, &receipts, fsynced)?;
    root_count!(
        PersistedReady,
        ready.len(),
        ready
            .iter()
            .map(|(_, reply)| reply.payload.len())
            .sum::<usize>()
    );
    root_phase_finish!(root_total, Ok(()))
}

/// Read an existing exact committed closure without issuing a new local
/// durability receipt. Every manifest and ciphertext byte is reopened and
/// checked under the held directory and fresh, unchanged consensus selection.
/// A failed reopen retains the original immutable repair and fsync path.
pub fn read_or_recover_native_v6_committed_closure(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    transport: &MutualTlsPeerTransport,
    routes: &BTreeMap<u64, NodeId>,
    storage: &LocalV6BlobStage,
    selected: NativeV6CommittedRootRead,
) -> Result<NativeV6CommittedRootRead, HaError> {
    #[cfg(feature = "private-forward-stage-diagnostic")]
    let _root_observation = root_diagnostic::Scope::enter(
        root_diagnostic::Side::Consumer,
        selected.operation_deadline(),
    );
    root_phase_begin!(root_total, ReadOrRecover);
    let _native_operation = storage
        .begin_native_operation()
        .map_err(|_| HaError::Transport)?;
    require_blocking_worker()?;
    check_deadline(selected.operation_deadline())?;
    let pins = selected.enrollment().pins();
    if !pins.contains_key(&raft.id())
        || routes.keys().copied().collect::<BTreeSet<_>>() != pins.keys().copied().collect()
        || routes.values().collect::<BTreeSet<_>>().len() != routes.len()
    {
        return Err(HaError::InvalidMembership);
    }
    let selected =
        match read_existing_with_progress_once(raft, runtime, storage, selected, || Ok(()))? {
            ExistingLocalRead::Complete(read) => return root_phase_finish!(root_total, Ok(read)),
            ExistingLocalRead::Repair(selected) => selected,
        };
    // Reopen errors are not reclassified as "missing". The original repair
    // rejects corrupt existing files through checked no-replace publication.
    let recovered =
        recover_native_v6_committed_closure(raft, runtime, transport, routes, storage, selected)?;
    root_phase_finish!(root_total, Ok(recovered.into_parts().0))
}

// Classification comes only from an actual failed opaque witness check.
// Storage, an injected callback, and missing/corrupt bytes cannot request a
// new observation. The fresh read must retain both old bounds and the exact
// root/enrollment/leader/term/store; it never authorizes a changed publication.
#[derive(Debug)]
pub(super) enum ExistingLocalRead {
    Complete(NativeV6CommittedRootRead),
    Repair(NativeV6CommittedRootRead),
}

pub(super) fn read_existing_with_progress_once(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    storage: &LocalV6BlobStage,
    selected: NativeV6CommittedRootRead,
    after_reopen: impl FnOnce() -> Result<(), HaError>,
) -> Result<ExistingLocalRead, HaError> {
    let refused = std::cell::Cell::new(false);
    let first = read_existing_committed_closure_checked(
        raft,
        runtime,
        storage,
        &selected,
        after_reopen,
        &refused,
    );
    if !refused.get() {
        return first.map(|read| match read {
            Some(read) => ExistingLocalRead::Complete(read),
            None => ExistingLocalRead::Repair(selected),
        });
    }
    // One read-only continuation is allowed after actual application progress.
    // A physical error or a second supersession remains terminal. The original
    // selected handle remains invalid and is never modified or used for repair.
    let fresh = runtime
        .block_on(raft.native_v6_same_root_progress_read(&selected))
        .map_err(|_| unknown())?;
    let read = read_existing_committed_closure(raft, runtime, storage, &fresh, || Ok(()))?;
    Ok(match read {
        Some(read) => ExistingLocalRead::Complete(read),
        None => ExistingLocalRead::Repair(fresh),
    })
}

// The additional gate permits deterministic real-Raft failure observations in
// this module's tests. It supplies no witness, deadline or replacement root.
pub(super) fn read_existing_committed_closure(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    storage: &LocalV6BlobStage,
    selected: &NativeV6CommittedRootRead,
    after_reopen: impl FnOnce() -> Result<(), HaError>,
) -> Result<Option<NativeV6CommittedRootRead>, HaError> {
    read_existing_committed_closure_checked(
        raft,
        runtime,
        storage,
        selected,
        after_reopen,
        &std::cell::Cell::new(false),
    )
}

fn read_existing_committed_closure_checked(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    storage: &LocalV6BlobStage,
    selected: &NativeV6CommittedRootRead,
    after_reopen: impl FnOnce() -> Result<(), HaError>,
    witness_refused: &std::cell::Cell<bool>,
) -> Result<Option<NativeV6CommittedRootRead>, HaError> {
    #[cfg(feature = "private-forward-stage-diagnostic")]
    let _root_observation = root_diagnostic::Scope::enter(
        root_diagnostic::Side::Consumer,
        selected.operation_deadline(),
    );
    root_phase_begin!(root_total, ReadExisting);
    let _native_operation = storage
        .begin_native_operation()
        .map_err(|_| HaError::Transport)?;
    // The caller already obtained this actual ReadIndex selection. Use that
    // still-live opaque witness for every physical read instead of issuing a
    // second quorum read before the same I/O. Its capped read bound is never
    // extended, and the terminal fresh ReadIndex below remains mandatory.
    check_deadline(selected.operation_deadline())?;
    root_phase!(
        WitnessVerify,
        runtime.block_on(raft.verify_native_v6_committed_root_read(selected))
    )
    .map_err(|_| {
        witness_refused.set(true);
        unknown()
    })?;
    let complete = {
        let mut gate = || {
            check_deadline(selected.operation_deadline())
                .and_then(|()| {
                    root_phase!(
                        WitnessVerify,
                        runtime.block_on(raft.verify_native_v6_committed_root_read(selected))
                    )
                    .map_err(|_| {
                        witness_refused.set(true);
                        unknown()
                    })
                })
                .map_err(|_| LocalV6BlobError::CorruptOrChanged)
        };
        match root_phase!(
            ExistingReopen,
            storage.reopen_root_closure(selected.root(), &mut gate)
        ) {
            Ok(references) => {
                wire::exact_manifest(&references, &selected.root().intent())?;
                gate().map_err(|_| unknown())?;
                true
            }
            Err(_) => false,
        }
    };
    if !complete {
        return root_phase_finish!(root_total, Ok(None));
    }
    after_reopen()?;
    // A new ReadIndex must still select this exact process/generation/term/root.
    // Its capped read budget never changes the original operation deadline.
    let fresh = fresh_same(raft, runtime, selected).inspect_err(|_| {
        if runtime
            .block_on(raft.verify_native_v6_committed_root_read(selected))
            .is_err()
        {
            witness_refused.set(true);
        }
    })?;
    root_phase_finish!(root_total, Ok(Some(fresh)))
}

/// Consume one selected actual root and repair only that root's exact external
/// closure. Parallel donors prevent a blackholed first peer from spending the
/// healthy peer's whole original deadline. All destination bytes go through
/// the real checked immutable file+directory fsync path. The selected local
/// Raft generation, full root/enrollment/leader/term remain STRICTLY unchanged.
pub fn recover_native_v6_committed_closure(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    transport: &MutualTlsPeerTransport,
    routes: &BTreeMap<u64, NodeId>,
    storage: &LocalV6BlobStage,
    selected: NativeV6CommittedRootRead,
) -> Result<RecoveredNativeV6LocalClosure, HaError> {
    #[cfg(feature = "private-forward-stage-diagnostic")]
    let _root_observation = root_diagnostic::Scope::enter(
        root_diagnostic::Side::Consumer,
        selected.operation_deadline(),
    );
    root_phase_begin!(root_total, Recover);
    let _native_operation = storage
        .begin_native_operation()
        .map_err(|_| HaError::Transport)?;
    require_blocking_worker()?;
    let deadline = selected.operation_deadline();
    check_deadline(deadline)?;
    root_phase!(
        WitnessVerify,
        runtime.block_on(raft.verify_native_v6_committed_root_read(&selected))
    )
    .map_err(|_| unknown())?;
    let pins = selected.enrollment().pins();
    if !pins.contains_key(&raft.id())
        || routes.keys().copied().collect::<BTreeSet<_>>() != pins.keys().copied().collect()
        || routes.values().collect::<BTreeSet<_>>().len() != routes.len()
    {
        return Err(HaError::InvalidMembership);
    }
    let mut initial_gate = || {
        root_phase!(
            WitnessVerify,
            runtime.block_on(raft.verify_native_v6_committed_root_read(&selected))
        )
        .map_err(|_| LocalV6BlobError::CorruptOrChanged)
    };
    if let Ok(references) = root_phase!(
        RecoveryReopen,
        storage.reopen_root_closure(selected.root(), &mut initial_gate)
    ) {
        let fsynced = vec![false; references.len()];
        return root_phase_finish!(
            root_total,
            finish_local(raft, runtime, storage, selected, &references, &fsynced)
        );
    }
    root_phase!(
        WitnessVerify,
        runtime.block_on(raft.verify_native_v6_committed_root_read(&selected))
    )
    .map_err(|_| unknown())?;
    let binding = RootBinding::observed(&selected);
    let count = usize::try_from(binding.intent.object_count).map_err(|_| HaError::InvalidFrame)?;
    if count == 0 || count > wire::MAX_OBJECTS {
        return Err(HaError::InvalidFrame);
    }
    let mut round = [0u8; 32];
    SystemRandom::new()
        .fill(&mut round)
        .map_err(|_| HaError::Transport)?;
    let mut references = Vec::with_capacity(count);
    let mut fsynced = vec![false; count];
    let mut local_examined = false;
    let mut pulls = OwnedPulls {
        runtime,
        pending: Vec::new(),
        #[cfg(test)]
        observation: observation::current(),
    };
    let mut object_donors = BTreeSet::new();
    let context = PullRequestContext {
        runtime,
        transport,
        routes,
        pins,
        binding: &binding,
        requester: raft.id(),
        round,
        deadline,
        #[cfg(test)]
        observation: pulls.observation.clone(),
    };
    for &target in routes.keys().filter(|id| **id != raft.id()) {
        pulls.pending.push(pending_pull(
            &context,
            target,
            PullStep::Manifest(0),
            &references,
        )?);
    }
    loop {
        check_deadline(deadline)?;
        for &target in &object_donors {
            fill_object_window(&mut pulls, &context, target, &references, &fsynced)?;
        }
        if pulls.pending.is_empty() {
            return Err(unknown());
        }
        let (index, result) = root_phase!(
            ControllerWait,
            runtime.block_on(async {
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    poll_fn(|cx| {
                        for (index, operation) in pulls.pending.iter_mut().enumerate() {
                            if let Poll::Ready(result) = Pin::new(&mut operation.operation).poll(cx)
                            {
                                return Poll::Ready((
                                    index,
                                    result.map_err(|_| unknown()).flatten(),
                                ));
                            }
                        }
                        Poll::Pending
                    }),
                )
                .await
                .map_err(|_| unknown())
            })
        )?;
        let completed = pulls.pending.swap_remove(index);
        #[cfg(test)]
        if let Some(observation) = &pulls.observation {
            observation.joined();
        }
        let target = completed.target;
        let step = completed.step;
        let completed_object = matches!(step, PullStep::Object(_));
        drop(completed);
        let Ok(response) = result else {
            // A failed donor is never automatically retried. Cancel and join
            // its other entries before continuing with another donor. Invalid
            // authenticated object bytes below remain terminal for the round.
            object_donors.remove(&target);
            pulls.retire(target);
            continue;
        };
        check_deadline(deadline)?;
        let next = match step {
            PullStep::Manifest(expected_offset) => {
                root_count!(ManifestReply, 1, response.payload.len());
                let (offset, page) = wire::parse_manifest_page(&response.payload)?;
                let end = offset
                    .checked_add(page.len())
                    .ok_or(HaError::InvalidFrame)?;
                if offset != expected_offset || end > count {
                    return Err(HaError::InvalidFrame);
                }
                if offset < references.len() {
                    if references.get(offset..end) != Some(page.as_slice()) {
                        return Err(HaError::InvalidFrame);
                    }
                } else if offset == references.len() {
                    if references
                        .last()
                        .is_some_and(|last: &RecordObjectRef| last.id >= page[0].id)
                    {
                        return Err(HaError::InvalidFrame);
                    }
                    references.extend(page);
                } else {
                    return Err(HaError::InvalidFrame);
                }
                let next = if references.len() == count {
                    wire::exact_manifest(&references, &binding.intent)?;
                    if !local_examined {
                        synchronize_available_pull_objects(
                            raft,
                            runtime,
                            storage,
                            &selected,
                            &references,
                            &mut fsynced,
                        )?;
                        local_examined = true;
                    }
                    PullStep::Object(0)
                } else {
                    PullStep::Manifest(end)
                };
                drop(response);
                next
            }
            PullStep::Object(index) => {
                let mut ready = Vec::with_capacity(NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES);
                append_ready_pull_object(&mut ready, &references, &fsynced, index, response)?;
                if ready.is_empty() {
                    // A fully checked durable duplicate adds no receipt or
                    // progress. The original finish path already handles the
                    // iteration that sets the last bit; do not spend another
                    // ReadIndex on this duplicate or retain its frame permit.
                    continue;
                }
                // The first exact new reply already owes this fresh quorum
                // read. Let the existing window progress during that read,
                // then drain only replies that are ready, without waiting to
                // fill a batch. The same opaque witness gates every I/O below.
                let fresh = fresh_same(raft, runtime, &selected)?;
                let mut terminal_error = None;
                for _ in 1..NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES {
                    check_deadline(deadline)?;
                    let Some((ready_target, ready_index, result)) = pulls.take_ready_object()
                    else {
                        break;
                    };
                    let Ok(response) = result else {
                        // Preserve the original one-attempt donor retirement.
                        // Already verified replies retain only immutable bytes;
                        // no new request is submitted while collecting a batch.
                        object_donors.remove(&ready_target);
                        pulls.retire(ready_target);
                        continue;
                    };
                    if let Err(error) = append_ready_pull_object(
                        &mut ready,
                        &references,
                        &fsynced,
                        ready_index,
                        response,
                    ) {
                        // Preserve the original ordered successful prefix:
                        // earlier exact replies still owe their real gates and
                        // fsync before this later invalid reply is refused.
                        // The invalid bytes never enter the physical batch.
                        terminal_error = Some(error);
                        break;
                    }
                }
                persist_ready_pull_batch(
                    raft,
                    runtime,
                    storage,
                    &fresh,
                    &references,
                    &mut fsynced,
                    &ready,
                )?;
                if let Some(error) = terminal_error {
                    // Never refill, finish a closure, or retry after refusal.
                    // OwnedPulls still cancels and joins every outstanding task.
                    return Err(error);
                }
                PullStep::Object(0)
            }
        };
        // Keep fsync/consensus work outside an entered Tokio runtime. Socket
        // workers own no borrowed Raft, storage, Service or Actor handle.
        if references.len() == count {
            if fsynced.iter().all(|done| *done) {
                pulls.cancel_and_join();
                check_deadline(deadline)?;
                return root_phase_finish!(
                    root_total,
                    finish_local(raft, runtime, storage, selected, &references, &fsynced)
                );
            }
            if !completed_object {
                object_donors.insert(target);
            }
        } else {
            pulls
                .pending
                .push(pending_pull(&context, target, next, &references)?);
        }
    }
}

#[cfg(all(test, unix))]
#[path = "v6_committed_root_pull_ready_batch_unit_tests.rs"]
mod ready_batch_unit_tests;
