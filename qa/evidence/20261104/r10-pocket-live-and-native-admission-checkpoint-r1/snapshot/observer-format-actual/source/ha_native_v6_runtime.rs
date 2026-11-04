//! Explicit native HA custody over this running process's real Raft instance.
//! A read handle grants neither an Actor nor a local publication or response.
use super::*;
use crate::v6_native_custody::OriginalDeadline;
use heptabao_ha_service::{
    AuthenticatedPeerFrame, HaError, NativeV6ClosureReceiver, NativeV6CommittedRootSource,
    is_native_v6_closure_frame, is_native_v6_root_pull_frame,
    read_or_recover_native_v6_committed_closure,
};
use heptabao_ha_service::{
    NativeV6IngressClosureRead, NativeV6IngressSupersededRead,
    read_native_v6_fresh_ingress_closure, recover_native_v6_committed_closure,
};
use heptabao_raft_runtime::{
    LocalV6BlobStage, NativeV6CommittedRootRead, NativeV6PeerEnrollment, NativeV6PublishedRoot,
};
use std::sync::OnceLock;

#[path = "ha_native_v6_archive_repair.rs"]
mod archive_repair;
pub(crate) use archive_repair::NativeV6ArchiveRootAnchor;

#[path = "ha_native_v6_publication.rs"]
mod publication;
pub(crate) use publication::NativeHaPublicationError;

#[path = "ha_native_v6_epoch_restore.rs"]
mod epoch_restore;

#[path = "ha_native_v6_migration_source.rs"]
mod migration_source;

#[path = "ha_native_v6_retention.rs"]
mod retention;
pub(super) use retention::is_admission_frame as is_native_v6_retention_admission_frame;
pub(crate) use retention::{
    NativeHaCommittedIntentRetirement, NativeHaIntentReadObservation,
    NativeHaPreparedIntentRetirement,
};

#[cfg(test)]
#[path = "ha_native_v6_install_test_support.rs"]
pub(super) mod install_test_support;

// Private phase observations only. They inspect the result of the original
// call and its original deadline; they grant no custody and run no live gate.
#[cfg(feature = "private-ha-forward-diagnostic")]
fn observe_committed_read_phase(
    phase: &'static str,
    began: Instant,
    original_until: Instant,
    completed: bool,
) {
    use std::io::Write as _;
    let observed = Instant::now();
    let _ = writeln!(
        std::io::stderr().lock(),
        "HBHA-PRIVATE-COMMITTED-READ phase={} elapsed_us={} completed={} original_deadline_expired={} original_remaining_ns={} scoped_remaining_ns={:?}",
        phase,
        observed.duration_since(began).as_micros(),
        completed,
        observed >= original_until,
        original_until
            .saturating_duration_since(observed)
            .as_nanos(),
        crate::request_deadline::current()
            .map(|until| until.saturating_duration_since(observed).as_nanos()),
    );
}

// A bounded, thread-owned diagnostic for one synchronous request. These data
// never leave memory on success and grant no deadline, source, or read authority.
const NATIVE_TIMING_BUCKETS: usize = 64;

#[derive(serde::Serialize)]
struct NativeTimingBucket {
    scope: &'static str,
    phase: &'static str,
    calls: u64,
    advanced: u64,
    completed: u64,
    failed: u64,
    elapsed_us: u128,
    maximum_elapsed_us: u128,
    first_entry_remaining_ns: u128,
    last_exit_remaining_ns: u128,
    minimum_entry_remaining_ns: u128,
    minimum_exit_remaining_ns: u128,
}

#[derive(Clone, Copy)]
enum NativeTimingOutcome {
    Advanced,
    Completed,
    Failed,
}

struct NativeTimingState {
    began: Instant,
    deadline: Instant,
    request_class: &'static str,
    forwarded: bool,
    open: bool,
    buckets: Vec<NativeTimingBucket>,
    bucket_bound_reached: bool,
}

type NativeTimingContext = std::rc::Rc<std::cell::RefCell<NativeTimingState>>;

#[derive(serde::Serialize)]
struct NativeTimingFailureReport {
    schema: &'static str,
    request_class: &'static str,
    forwarded: bool,
    status: u16,
    elapsed_us: u128,
    entry_remaining_ns: u128,
    exit_remaining_ns: u128,
    bucket_limit: usize,
    bucket_bound_reached: bool,
    phases: Vec<NativeTimingBucket>,
}

thread_local! {
    static NATIVE_REQUEST_TIMING: std::cell::RefCell<Option<NativeTimingContext>> = const { std::cell::RefCell::new(None) };
}

// The Rc deliberately prevents transfer to another thread. Nested observations
// restore the exact previous scope and never attach a later request to it.
pub(crate) struct NativeV6RequestObservation {
    state: NativeTimingContext,
    previous: Option<NativeTimingContext>,
    attached: bool,
}

impl NativeV6RequestObservation {
    pub(crate) fn start(deadline: Instant, request_class: &'static str, forwarded: bool) -> Self {
        let state = std::rc::Rc::new(std::cell::RefCell::new(NativeTimingState {
            began: Instant::now(),
            deadline,
            request_class,
            forwarded,
            open: true,
            buckets: Vec::with_capacity(NATIVE_TIMING_BUCKETS),
            bucket_bound_reached: false,
        }));
        let previous = NATIVE_REQUEST_TIMING.with(|slot| slot.replace(Some(state.clone())));
        Self {
            state,
            previous,
            attached: true,
        }
    }

    fn detach(&mut self) {
        if self.attached {
            self.state.borrow_mut().open = false;
            NATIVE_REQUEST_TIMING.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot
                    .as_ref()
                    .is_some_and(|active| std::rc::Rc::ptr_eq(active, &self.state))
                {
                    *slot = self
                        .previous
                        .take()
                        .filter(|previous| previous.borrow().open);
                }
            });
            self.attached = false;
        }
    }

    fn failure_report(mut self, status: Option<u16>) -> Option<NativeTimingFailureReport> {
        self.detach();
        let status = status.filter(|status| *status >= 500)?;
        let observed = Instant::now();
        let mut state = self.state.borrow_mut();
        Some(NativeTimingFailureReport {
            schema: "heptabao.native-ha.request-failure-timing.v1",
            request_class: state.request_class,
            forwarded: state.forwarded,
            status,
            elapsed_us: observed.saturating_duration_since(state.began).as_micros(),
            entry_remaining_ns: state
                .deadline
                .saturating_duration_since(state.began)
                .as_nanos(),
            exit_remaining_ns: state
                .deadline
                .saturating_duration_since(observed)
                .as_nanos(),
            bucket_limit: NATIVE_TIMING_BUCKETS,
            bucket_bound_reached: state.bucket_bound_reached,
            phases: std::mem::take(&mut state.buckets),
        })
    }

    pub(crate) fn finish(self, status: Option<u16>) {
        if let Some(report) = self.failure_report(status)
            && let Ok(encoded) = serde_json::to_string(&report)
        {
            let _ = writeln!(
                std::io::stderr().lock(),
                "HBHA-REQUEST-TIMING-FAIL {encoded}"
            );
        }
    }
}

impl Drop for NativeV6RequestObservation {
    fn drop(&mut self) {
        // Unwinding must not leave any observations attached to a later request.
        self.detach();
    }
}

fn record_native_timing_for(
    state: &std::cell::RefCell<NativeTimingState>,
    scope: &'static str,
    phase: &'static str,
    began: Instant,
    observed: Instant,
    deadline: Instant,
    outcome: NativeTimingOutcome,
) {
    let mut state = state.borrow_mut();
    if !state.open {
        return;
    }
    let elapsed = observed.saturating_duration_since(began).as_micros();
    let entry = deadline.saturating_duration_since(began).as_nanos();
    let exit = deadline.saturating_duration_since(observed).as_nanos();
    let advanced = u64::from(matches!(outcome, NativeTimingOutcome::Advanced));
    let completed = u64::from(matches!(outcome, NativeTimingOutcome::Completed));
    let failed = u64::from(matches!(outcome, NativeTimingOutcome::Failed));
    if let Some(bucket) = state
        .buckets
        .iter_mut()
        .find(|bucket| bucket.scope == scope && bucket.phase == phase)
    {
        bucket.calls = bucket.calls.saturating_add(1);
        bucket.advanced = bucket.advanced.saturating_add(advanced);
        bucket.completed = bucket.completed.saturating_add(completed);
        bucket.failed = bucket.failed.saturating_add(failed);
        bucket.elapsed_us = bucket.elapsed_us.saturating_add(elapsed);
        bucket.maximum_elapsed_us = bucket.maximum_elapsed_us.max(elapsed);
        bucket.last_exit_remaining_ns = exit;
        bucket.minimum_entry_remaining_ns = bucket.minimum_entry_remaining_ns.min(entry);
        bucket.minimum_exit_remaining_ns = bucket.minimum_exit_remaining_ns.min(exit);
    } else if state.buckets.len() < NATIVE_TIMING_BUCKETS {
        state.buckets.push(NativeTimingBucket {
            scope,
            phase,
            calls: 1,
            advanced,
            completed,
            failed,
            elapsed_us: elapsed,
            maximum_elapsed_us: elapsed,
            first_entry_remaining_ns: entry,
            last_exit_remaining_ns: exit,
            minimum_entry_remaining_ns: entry,
            minimum_exit_remaining_ns: exit,
        });
    } else {
        state.bucket_bound_reached = true;
    }
}

pub(crate) struct NativeV6TimingSpan {
    state: NativeTimingContext,
    scope: &'static str,
    phase: &'static str,
    began: Instant,
    deadline: Instant,
    completed: bool,
}

impl NativeV6TimingSpan {
    pub(crate) fn start(
        scope: &'static str,
        phase: &'static str,
        original_until: Option<Instant>,
    ) -> Option<Self> {
        NATIVE_REQUEST_TIMING.with(|slot| {
            let state = slot.borrow().as_ref()?.clone();
            let request_until = state.borrow().deadline;
            // Observe the strictest existing limit only. This neither enters a
            // deadline scope nor changes the deadline used by the operation.
            let scoped_until = crate::request_deadline::current().unwrap_or(request_until);
            let deadline = original_until
                .map_or(scoped_until, |until| until.min(scoped_until))
                .min(request_until);
            Some(Self {
                state,
                scope,
                phase,
                began: Instant::now(),
                deadline,
                completed: false,
            })
        })
    }

    pub(crate) fn finish(mut self, completed: bool) {
        self.completed = completed;
    }
}

impl Drop for NativeV6TimingSpan {
    fn drop(&mut self) {
        record_native_timing_for(
            &self.state,
            self.scope,
            self.phase,
            self.began,
            Instant::now(),
            self.deadline,
            if self.completed {
                NativeTimingOutcome::Completed
            } else {
                NativeTimingOutcome::Failed
            },
        );
    }
}

// Failure-only observations for the ordinary native HA path. This owns no
// source, Actor, Raft witness or deadline authority. Success emits nothing;
// returning an error preserves the original value and all original checks.
// Only fixed phase/code labels, time quantities and an error digest are emitted.
pub(crate) struct NativeV6FailureObservation {
    timing: Option<NativeTimingContext>,
    scope: &'static str,
    phase: std::cell::Cell<&'static str>,
    began: Instant,
    phase_began: std::cell::Cell<Instant>,
    original_until: Instant,
    code: std::cell::Cell<&'static str>,
    reason_sha: std::cell::Cell<Option<[u8; 32]>>,
    completed: std::cell::Cell<bool>,
}

impl NativeV6FailureObservation {
    pub(crate) fn start(phase: &'static str, original_until: Instant) -> Self {
        let began = Instant::now();
        Self {
            timing: NATIVE_REQUEST_TIMING.with(|slot| slot.borrow().clone()),
            scope: phase,
            phase: std::cell::Cell::new(phase),
            began,
            phase_began: std::cell::Cell::new(began),
            original_until,
            code: std::cell::Cell::new("scope_not_completed"),
            reason_sha: std::cell::Cell::new(None),
            completed: std::cell::Cell::new(false),
        }
    }

    pub(crate) fn step(&self, phase: &'static str) {
        let observed = Instant::now();
        self.record_timing(
            self.phase.get(),
            self.phase_began.get(),
            observed,
            NativeTimingOutcome::Advanced,
        );
        self.phase.set(phase);
        self.phase_began.set(observed);
    }

    fn record_timing(
        &self,
        phase: &'static str,
        began: Instant,
        observed: Instant,
        outcome: NativeTimingOutcome,
    ) {
        if let Some(state) = &self.timing {
            record_native_timing_for(
                state,
                self.scope,
                phase,
                began,
                observed,
                self.original_until,
                outcome,
            );
        }
    }

    pub(crate) fn refused(&self, code: &'static str, reason: &str) {
        self.code.set(code);
        self.reason_sha
            .set(Some(crate::crypto::digest(reason.as_bytes())));
    }

    pub(crate) fn complete(self) {
        self.completed.set(true);
    }
}

impl Drop for NativeV6FailureObservation {
    fn drop(&mut self) {
        let observed = Instant::now();
        let outcome = if self.completed.get() {
            NativeTimingOutcome::Completed
        } else {
            NativeTimingOutcome::Failed
        };
        self.record_timing(self.phase.get(), self.phase_began.get(), observed, outcome);
        self.record_timing("scope_total", self.began, observed, outcome);
        if self.completed.get() {
            return;
        }
        let reason_sha = match self.reason_sha.get() {
            Some(bytes) => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                bytes
                    .into_iter()
                    .flat_map(|byte| {
                        [
                            char::from(HEX[usize::from(byte >> 4)]),
                            char::from(HEX[usize::from(byte & 15)]),
                        ]
                    })
                    .collect::<String>()
            }
            None => "-".to_owned(),
        };
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-NATIVE-SYNC-FAIL step={} code={} reason_sha={} elapsed_us={} step_elapsed_us={} original_deadline_expired={} original_remaining_ns={} panicking={}",
            self.phase.get(),
            self.code.get(),
            reason_sha,
            observed.duration_since(self.began).as_micros(),
            observed.duration_since(self.phase_began.get()).as_micros(),
            observed >= self.original_until,
            self.original_until
                .saturating_duration_since(observed)
                .as_nanos(),
            std::thread::panicking(),
        );
    }
}

pub(super) struct NativeV6Runtime {
    identity: Arc<()>,
    root: PathBuf,
    storage: OnceLock<Arc<LocalV6BlobStage>>,
    receiver: OnceLock<Arc<NativeV6ClosureReceiver>>,
    root_source: OnceLock<Arc<NativeV6CommittedRootSource>>,
    configured_pins: BTreeMap<u64, [u8; 32]>,
    configured_nodes: BTreeMap<u64, NodeId>,
    pub(super) transport: MutualTlsPeerTransport,
    eligible: bool,
}

enum NativeV6ReadRecapture<'a> {
    SameSelection(&'a heptabao_raft_runtime::NativeV6CommittedRootRead),
    ApplicationProgress(&'a heptabao_raft_runtime::NativeV6CommittedRootRead),
}

impl NativeV6Runtime {
    pub(super) fn configured(
        config: &HaProcessConfig,
        client: Arc<ClientConfig>,
        local_leaf: [u8; 32],
    ) -> Result<Self, String> {
        let parsed = parse_peers(config)?;
        let configured_pins = parsed
            .iter()
            .map(|peer| (peer.id, peer.certificate_sha256))
            .collect();
        // Self is an actual TLS destination. It never becomes an implicit vote.
        let endpoints = parsed
            .iter()
            .map(|peer| (peer.node.clone(), peer.endpoint.clone()))
            .collect();
        let transport = MutualTlsPeerTransport::new(
            endpoints,
            client,
            Duration::from_millis(config.forward_timeout_ms),
        )
        .map_err(|error| error.to_string())?;
        let eligible = !config.allow_legacy_peer_v1
            && !config.outbound_legacy_peer_v1()
            && parsed.len() >= 3
            && parsed
                .iter()
                .all(|peer| peer.certificate_sha256_next.is_none())
            && parsed
                .iter()
                .any(|peer| peer.id == config.node_id && peer.certificate_sha256 == local_leaf);
        Ok(Self {
            identity: Arc::new(()),
            root: config.raft_dir.join("native-v6-ciphertext"),
            storage: OnceLock::new(),
            receiver: OnceLock::new(),
            root_source: OnceLock::new(),
            configured_pins,
            configured_nodes: parsed
                .iter()
                .map(|peer| (peer.id, peer.node.clone()))
                .collect(),
            transport,
            eligible,
        })
    }

    fn enabled(&self) -> bool {
        self.eligible && self.storage.get().is_some()
    }

    pub(super) fn enable(&self) -> Result<(), String> {
        if !self.eligible || self.storage.get().is_some() {
            return Err("native HA requires an explicit fresh eligibility installation".into());
        }
        // The immutable store retains the no-symlink descriptor and exclusive
        // writer lock; subsequent reads and writes never reopen by pathname.
        let parent = self
            .root
            .parent()
            .ok_or("native HA storage parent absent")?;
        let directory = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(parent)
            .map_err(|_| "native HA storage parent custody unavailable")?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&self.root) {
            Ok(()) => {
                directory
                    .sync_all()
                    .map_err(|_| "native HA storage parent fsync unavailable")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("native HA ciphertext store creation unavailable".into()),
        }
        let storage = LocalV6BlobStage::open_existing(&self.root)
            .map_err(|_| "native HA ciphertext custody unavailable")?;
        self.storage
            .set(Arc::new(storage))
            .map_err(|_| "native HA eligibility was concurrently installed".to_owned())
    }

    fn validate_enrollment(
        &self,
        codec: &ClusterStateCodec,
        enrollment: &NativeV6PeerEnrollment,
    ) -> Result<(), String> {
        self.validate_enrollment_binding(codec.native_v6_cluster_digest(), enrollment)
    }

    fn validate_enrollment_binding(
        &self,
        cluster_digest: [u8; 32],
        enrollment: &NativeV6PeerEnrollment,
    ) -> Result<(), String> {
        if !self.enabled()
            || enrollment.cluster_digest() != cluster_digest
            || enrollment.pins() != &self.configured_pins
        {
            return Err("native HA committed enrollment differs from configured custody".into());
        }
        Ok(())
    }

    /// Only the shared listener's actual TLS handle can reach native ingress.
    /// Initial pins come from an actual committed enrollment, never the wire.
    /// Each receiver/source subsequently obtains its own fresh applied proof.
    pub(super) fn handle_authenticated(
        &self,
        frame: AuthenticatedPeerFrame,
        node: &Arc<ProcessRaftNode>,
        handle: &tokio::runtime::Handle,
        cluster_digest: [u8; 32],
    ) -> Result<Vec<u8>, HaError> {
        if !self.enabled() || Instant::now() >= frame.deadline() || !frame.has_strict_raft_alpn() {
            return Err(HaError::PeerAuthenticationFailed);
        }
        if is_native_v6_retention_admission_frame(frame.payload()) {
            return self.handle_retention_admission(frame, node, handle, cluster_digest);
        }
        let push = is_native_v6_closure_frame(frame.payload());
        let pull = is_native_v6_root_pull_frame(frame.payload());
        if !push && !pull {
            return Err(HaError::InvalidFrame);
        }
        if push && self.receiver.get().is_none() || pull && self.root_source.get().is_none() {
            let (witness, enrollment, _) = handle
                .block_on(node.native_v6_application_read_witness(frame.deadline()))
                .map_err(|_| HaError::OutcomeUnknown)?;
            let enrollment = enrollment.ok_or(HaError::InvalidMembership)?;
            self.validate_enrollment_binding(cluster_digest, &enrollment)
                .map_err(|_| HaError::InvalidMembership)?;
            let storage = self.storage.get().ok_or(HaError::Transport)?;
            if push {
                let receiver = NativeV6ClosureReceiver::new(
                    node.clone(),
                    handle.clone(),
                    storage.clone(),
                    &enrollment,
                )?;
                // A concurrent initializer may win. Both came from actual
                // committed enrollment; the retained receiver rechecks it.
                let _ = self.receiver.set(Arc::new(receiver));
            } else {
                let source = NativeV6CommittedRootSource::new(
                    node.clone(),
                    handle.clone(),
                    storage.clone(),
                    &enrollment,
                )?;
                let _ = self.root_source.set(Arc::new(source));
            }
            handle
                .block_on(heptabao_raft_runtime::with_read_index_deadline(
                    frame.deadline(),
                    node.verify_application_read_witness(&witness),
                ))
                .map_err(|_| HaError::OutcomeUnknown)?;
        }
        if push {
            self.receiver
                .get()
                .ok_or(HaError::Transport)?
                .handle_authenticated(frame)
        } else {
            self.root_source
                .get()
                .ok_or(HaError::Transport)?
                .handle_authenticated(frame)
        }
    }
}

/// Only this process's actual committed-root observation constructs the handle.
/// Keeping the instance identity alive prevents pointer reuse after a reopen.
pub(crate) struct CommittedNativeV6Read {
    _operation: heptabao_raft_runtime::NativeV6BlobOperation,
    instance: Arc<()>,
    selected: NativeV6CommittedRootRead,
    deadline: OriginalDeadline,
}

pub(crate) enum NativeV6IngressRead {
    Ready(CommittedNativeV6Read),
    Superseded(NativeV6IngressSuperseded),
}

pub(crate) struct NativeV6IngressSuperseded {
    _operation: heptabao_raft_runtime::NativeV6BlobOperation,
    instance: Arc<()>,
    selected: NativeV6IngressSupersededRead,
    deadline: OriginalDeadline,
    request_attempt: Arc<()>,
}
impl NativeV6IngressSuperseded {
    pub(crate) fn previous_root_digest(&self) -> [u8; 32] {
        self.selected.previous_root().root_digest()
    }
    pub(crate) fn operation_deadline(&self) -> Instant {
        self.deadline.instant()
    }
    pub(crate) fn read_deadline(&self) -> Instant {
        self.selected.original_read_deadline()
    }
    pub(crate) fn same_request_attempt(&self, expected: &Arc<()>) -> bool {
        Arc::ptr_eq(expected, &self.request_attempt)
    }
}

impl HaProcess {
    // Only the separately typed fresh Service ingress may select this entry.
    // The original writer/health/terminal/migration APIs below remain strict.
    pub(crate) fn native_v6_committed_fresh_ingress_read(
        &self,
        deadline: OriginalDeadline,
        local_root: [u8; 32],
        permission: &crate::service::native_v6_ha_install::NativeIngressSelectionPermit,
    ) -> Result<Option<NativeV6IngressRead>, String> {
        let failure =
            NativeV6FailureObservation::start("fresh_ingress_permission", deadline.instant());
        let result = (|| {
            permission.check_initial_read(deadline, local_root)?;
            failure.step("fresh_ingress_runtime");
            let native = self
                .native_v6
                .as_ref()
                .filter(|native| native.enabled())
                .ok_or("native HA was not explicitly enabled")?;
            let node = self.node.as_ref().ok_or("HA process is shut down")?;
            let storage = native
                .storage
                .get()
                .ok_or("native ciphertext store absent")?;
            failure.step("fresh_ingress_storage_operation");
            let operation = storage
                .begin_native_operation()
                .map_err(|e| e.to_string())?;
            failure.step("fresh_ingress_read_index");
            let selected = self
                .runtime
                .block_on(node.native_v6_committed_root_read(deadline.instant()))
                .map_err(|e| e.to_string())?;
            let Some(selected) = selected else {
                return Ok(None);
            };
            failure.step("fresh_ingress_enrollment");
            native.validate_enrollment(&self.codec, selected.enrollment())?;
            let selected = if selected.root().root_digest() == local_root {
                failure.step("fresh_ingress_same_root_closure");
                match read_native_v6_fresh_ingress_closure(
                    node,
                    self.runtime.handle(),
                    &self.peers,
                    Arc::clone(storage),
                    selected,
                )
                .map_err(|e| e.to_string())?
                {
                    NativeV6IngressClosureRead::Complete(read) => read,
                    NativeV6IngressClosureRead::NeedsOriginalRepair(read) => {
                        // This is the first original repair, never a no-effects
                        // continuation. No supersession token can escape it.
                        failure.step("fresh_ingress_original_repair");
                        permission.refuse_reselection();
                        recover_native_v6_committed_closure(
                            node,
                            self.runtime.handle(),
                            &native.transport,
                            &self.peers,
                            storage,
                            read,
                        )
                        .map_err(|e| e.to_string())?
                        .into_parts()
                        .0
                    }
                    NativeV6IngressClosureRead::Superseded(selected) => {
                        return Ok(Some(NativeV6IngressRead::Superseded(
                            NativeV6IngressSuperseded {
                                _operation: operation,
                                instance: Arc::clone(&native.identity),
                                selected,
                                deadline,
                                request_attempt: permission.attempt_identity(),
                            },
                        )));
                    }
                }
            } else {
                // The initial actual selection already differs: retain the one
                // original full catch-up, with no changed-root reselection token.
                failure.step("fresh_ingress_changed_root_recover");
                permission.refuse_reselection();
                read_or_recover_native_v6_committed_closure(
                    node,
                    self.runtime.handle(),
                    &native.transport,
                    &self.peers,
                    storage,
                    selected,
                )
                .map_err(|e| e.to_string())?
            };
            let read = CommittedNativeV6Read {
                _operation: operation,
                instance: Arc::clone(&native.identity),
                selected,
                deadline,
            };
            failure.step("fresh_ingress_final_witness");
            self.verify_native_v6_committed_read(&read)?;
            Ok(Some(NativeV6IngressRead::Ready(read)))
        })();
        if let Err(reason) = &result {
            failure.refused("fresh_ingress_read_refused", reason);
            permission.refuse_reselection();
        } else {
            failure.complete();
        }
        result
    }

    pub(crate) fn complete_native_v6_ingress_reselection(
        &self,
        source: NativeV6IngressSuperseded,
        permission: &crate::service::native_v6_ha_install::NativeIngressSelectionPermit,
    ) -> Result<CommittedNativeV6Read, String> {
        permission.check_superseded_read(&source)?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or("native HA runtime unavailable")?;
        if !Arc::ptr_eq(&native.identity, &source.instance)
            || crate::request_deadline::current() != Some(source.deadline.instant())
        {
            return Err("native ingress process or original deadline changed".into());
        }
        native.validate_enrollment(&self.codec, source.selected.enrollment())?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        let storage = native
            .storage
            .get()
            .ok_or("native ciphertext store absent")?;
        let selected = source
            .selected
            .complete(
                node,
                self.runtime.handle(),
                &native.transport,
                &self.peers,
                storage,
            )
            .map_err(|e| e.to_string())?;
        let read = CommittedNativeV6Read {
            _operation: source._operation,
            instance: source.instance,
            selected,
            deadline: source.deadline,
        };
        self.verify_native_v6_committed_read(&read)?;
        Ok(read)
    }
}
impl CommittedNativeV6Read {
    pub(crate) fn enrollment(&self) -> &NativeV6PeerEnrollment {
        self.selected.enrollment()
    }
    pub(crate) fn published(&self) -> &NativeV6PublishedRoot {
        self.selected.root()
    }
    pub(crate) fn deadline(&self) -> OriginalDeadline {
        self.deadline
    }
    #[cfg(test)]
    pub(crate) fn read_index_deadline(&self) -> Instant {
        self.selected.read_index_deadline()
    }
    /// Only the owning HaProcess may reduce its verified native selection to
    /// the original applied witness; no replacement observation is minted.
    pub(super) fn into_application_witness(self) -> heptabao_raft_runtime::ApplicationReadWitness {
        self.selected.into_application_witness()
    }
}

impl HaProcess {
    pub(super) fn ensure_native_v6_application_identity(
        &self,
        expected: crate::state_record_root::StateIdentity,
    ) -> Result<(), String> {
        let deadline = OriginalDeadline::capture().map_err(|error| error.to_string())?;
        // The actual typed local identity only selects the read-only reopen.
        // A different selected root retains full recovery and the exact
        // comparison below; this hint never grants application authority.
        let read = self
            .native_v6_committed_read_for_local_root(deadline, expected.digest())?
            .ok_or("native HA application root absent")?;
        if !matches!(
            expected,
            crate::state_record_root::StateIdentity::RecordsV6(_)
        ) || expected.digest() != read.published().root_digest()
        {
            return Err("native HA local identity is not the committed root".into());
        }
        self.with_native_v6_source(&read, |codec, store| {
            let closure = codec
                .open_native_v6_committed_read(
                    read.enrollment(),
                    read.published(),
                    store,
                    &mut || {
                        self.verify_native_v6_committed_read(&read)
                            .map_err(|_| crate::ha_state::native_v6::NativeV6CodecError::Gate)
                    },
                )
                .map_err(|_| "native HA authenticated closure unavailable")?;
            if closure
                .root()
                .identity()
                .map_err(|_| "native HA root identity invalid")?
                != expected
            {
                return Err("native HA root identity differs".to_owned());
            }
            self.verify_native_v6_committed_read(&read)
        })?
    }

    /// Startup eligibility only. HTTP root activation separately authenticates
    /// the current Actor, exact migration source and original request deadline.
    #[cfg(any(test, feature = "experimental-native-v6-ha"))]
    pub fn enable_native_v6_candidate(&mut self) -> Result<(), String> {
        if self.node.is_none() {
            return Err("HA process is shut down".into());
        }
        if self
            .listener
            .as_ref()
            .is_none_or(|listener| !listener.native_capacity_installed)
        {
            return Err(
                "native HA requires explicit candidate startup with reserved peer workers".into(),
            );
        }
        if self.native_v6_enabled() {
            return Ok(());
        }
        self.native_v6
            .as_ref()
            .ok_or("native HA runtime absent")?
            .enable()
    }

    pub(crate) fn native_v6_enabled(&self) -> bool {
        self.node.is_some()
            && self
                .native_v6
                .as_ref()
                .is_some_and(|runtime| runtime.enabled())
    }

    /// Fixture-only readiness observation, without fetching or repairing any
    /// shared ciphertext. Returned data grants no Service/local-install/Actor
    /// authority; the actual cold unseal still owes complete graph validation.
    #[cfg(test)]
    pub(crate) fn observe_native_v6_root_without_materialization_for_test(
        &self,
        deadline: OriginalDeadline,
    ) -> Result<Option<(u64, NativeV6PublishedRoot)>, String> {
        deadline.check().map_err(|error| error.to_string())?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or("native HA was not explicitly enabled")?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        let selected = self
            .runtime
            .block_on(node.native_v6_committed_root_read(deadline.instant()))
            .map_err(|error| error.to_string())?;
        let Some(selected) = selected else {
            deadline.check().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        native.validate_enrollment(&self.codec, selected.enrollment())?;
        self.runtime
            .block_on(heptabao_raft_runtime::with_read_index_deadline(
                deadline.instant(),
                node.verify_native_v6_committed_root_read(&selected),
            ))
            .map_err(|error| error.to_string())?;
        deadline.check().map_err(|error| error.to_string())?;
        Ok(Some((
            selected.enrollment().epoch(),
            selected.root().clone(),
        )))
    }

    pub(crate) fn native_v6_committed_read(
        &self,
        deadline: OriginalDeadline,
    ) -> Result<Option<CommittedNativeV6Read>, String> {
        self.native_v6_committed_read_inner(deadline, None)
    }

    /// The digest selects a read optimization, never a read/install authority.
    /// Ordinary sync and a publication's already-bound local source use this
    /// entry. A changed selected root also reopens every real manifest/leaf
    /// under the actual fresh selection; missing or corrupt bytes retain the
    /// original checked durable repair path. The hint grants no authority.
    pub(crate) fn native_v6_committed_read_for_local_root(
        &self,
        deadline: OriginalDeadline,
        local_root_digest: [u8; 32],
    ) -> Result<Option<CommittedNativeV6Read>, String> {
        self.native_v6_committed_read_inner(deadline, Some(local_root_digest))
    }

    /// A completed local predecessor install may consume most of the first
    /// capped ReadIndex lifetime. Obtain a NEW actual read at that successful
    /// phase boundary, under the unchanged original operation deadline. The
    /// old handle must still verify before this begins; a failed/expired read
    /// never triggers a retry. No Actor, local owner or publication is created.
    pub(crate) fn recapture_native_v6_same_selection(
        &self,
        original: &CommittedNativeV6Read,
    ) -> Result<CommittedNativeV6Read, String> {
        let deadline = original.deadline();
        if crate::request_deadline::current() != Some(deadline.instant()) {
            return Err("native read phase boundary differs from original deadline".into());
        }
        self.verify_native_v6_committed_read(original)?;
        let current = self
            .native_v6_committed_read_inner_bound(
                deadline,
                Some(original.published().root_digest()),
                Some(NativeV6ReadRecapture::SameSelection(&original.selected)),
            )?
            .ok_or("native read phase boundary has no committed selection")?;
        // same_selection includes the actual store instance, applied generation,
        // leader, term, complete root/enrollment and exact operation deadline.
        // A merely equal digest or a changed-but-newer root is insufficient.
        if !Arc::ptr_eq(&original.instance, &current.instance)
            || !original.selected.same_selection(&current.selected)
        {
            return Err("native read phase boundary changed the original selection".into());
        }
        self.verify_native_v6_committed_read(&current)?;
        deadline.check().map_err(|error| error.to_string())?;
        Ok(current)
    }

    /// Read back this operation's actually prepared and published ciphertext.
    /// The single production caller retains this exact proposal through local
    /// preparation, actual fsync quorum and root CAS on this HaProcess. The
    /// proposal alone is not a storage-owner capability, installed root or ACK.
    /// Complete reads still reopen every leaf under fresh consensus witnesses;
    /// any missing or invalid closure keeps the original checked repair path.
    pub(crate) fn native_v6_committed_read_for_published_proposal(
        &self,
        deadline: OriginalDeadline,
        proposal: &crate::service::native_v6_ha_objects::NativeV6HaProposal,
        published: &NativeV6PublishedRoot,
    ) -> Result<CommittedNativeV6Read, String> {
        deadline.check().map_err(|error| error.to_string())?;
        if proposal.original_deadline().instant() != deadline.instant()
            || proposal.intent() != published.intent()
            || proposal.sealed_root() != published.sealed_root()
            || proposal
                .root()
                .identity()
                .map_err(|_| "native HA proposal root identity invalid")?
                .digest()
                != published.root_digest()
        {
            return Err("native HA readback differs from the original proposal".into());
        }
        let read = self
            .native_v6_committed_read_inner(deadline, Some(published.root_digest()))?
            .ok_or("native HA committed root absent after root invocation")?;
        if read.published() != published {
            return Err("native HA proposal publication was superseded or differs".into());
        }
        deadline.check().map_err(|error| error.to_string())?;
        Ok(read)
    }

    /// Read-only phase continuation after an intervening application apply.
    /// An expired witness, changed root/enrollment/leader/process or extended
    /// operation/read bound is terminal. This creates no Actor or publication.
    pub(crate) fn recapture_native_v6_same_root_after_progress(
        &self,
        original: &CommittedNativeV6Read,
    ) -> Result<CommittedNativeV6Read, String> {
        let deadline = original.deadline();
        let read_until = original.selected.read_index_deadline();
        let native = self.native_v6.as_ref().ok_or("native HA runtime absent")?;
        if crate::request_deadline::current() != Some(deadline.instant())
            || !Arc::ptr_eq(&original.instance, &native.identity)
            || Instant::now() >= read_until
            || self.verify_native_v6_committed_read(original).is_ok()
        {
            return Err("native same-root progress requires a live superseded observation".into());
        }
        deadline.check().map_err(|error| error.to_string())?;
        let current = self
            .native_v6_committed_read_inner_bound(
                deadline,
                Some(original.published().root_digest()),
                Some(NativeV6ReadRecapture::ApplicationProgress(
                    &original.selected,
                )),
            )?
            .ok_or("native same-root progress has no committed selection")?;
        if !Arc::ptr_eq(&original.instance, &current.instance)
            || current.deadline().instant() != deadline.instant()
            || current.selected.read_index_deadline() > read_until
        {
            return Err("native same-root progress changed its original source or bound".into());
        }
        self.verify_native_v6_committed_read(&current)?;
        Ok(current)
    }

    fn native_v6_committed_read_inner(
        &self,
        deadline: OriginalDeadline,
        complete_root_hint: Option<[u8; 32]>,
    ) -> Result<Option<CommittedNativeV6Read>, String> {
        self.native_v6_committed_read_inner_bound(deadline, complete_root_hint, None)
    }

    fn native_v6_committed_read_inner_bound(
        &self,
        deadline: OriginalDeadline,
        complete_root_hint: Option<[u8; 32]>,
        recapture: Option<NativeV6ReadRecapture<'_>>,
    ) -> Result<Option<CommittedNativeV6Read>, String> {
        let failure = NativeV6FailureObservation::start("committed_read_entry", deadline.instant());
        deadline.check().map_err(|error| error.to_string())?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or("native HA was not explicitly enabled")?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        let native_operation = native
            .storage
            .get()
            .ok_or("native ciphertext store absent")?
            .begin_native_operation()
            .map_err(|error| error.to_string())?;
        failure.step("committed_read_index");
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let read_started = Instant::now();
        let selected = self.runtime.block_on(async {
            match recapture {
                Some(NativeV6ReadRecapture::ApplicationProgress(previous)) => node
                    .native_v6_same_root_progress_read(previous)
                    .await
                    .map(Some),
                Some(NativeV6ReadRecapture::SameSelection(previous)) => node
                    .native_v6_fresh_same_selection_read(previous)
                    .await
                    .map(Some),
                None => node.native_v6_committed_root_read(deadline.instant()).await,
            }
        });
        #[cfg(feature = "private-ha-forward-diagnostic")]
        observe_committed_read_phase(
            "read_index",
            read_started,
            deadline.instant(),
            selected.is_ok(),
        );
        let selected = selected.map_err(|error| {
            let reason = error.to_string();
            failure.refused("read_index_refused", &reason);
            reason
        })?;
        let Some(selected) = selected else {
            deadline.check().map_err(|error| error.to_string())?;
            failure.complete();
            return Ok(None);
        };
        failure.step("committed_enrollment");
        native.validate_enrollment(&self.codec, selected.enrollment())?;
        // The selected process handle is consumed. A complete local closure is
        // physically reopened even when Service has not installed this root
        // yet: its old root digest says nothing about locally staged ciphertext.
        // The shared reader verifies every manifest/leaf and a terminal fresh
        // same-selection ReadIndex. Incomplete/corrupt closures retain the
        // original immutable repair; neither path creates a Raft command/ACK.
        let storage = native
            .storage
            .get()
            .ok_or("native HA ciphertext store unavailable")?;
        let selected = if complete_root_hint == Some(selected.root().root_digest()) {
            failure.step("committed_same_root_reopen");
            #[cfg(feature = "private-ha-forward-diagnostic")]
            let read_started = Instant::now();
            let selected = read_or_recover_native_v6_committed_closure(
                node,
                self.runtime.handle(),
                &native.transport,
                &self.peers,
                storage,
                selected,
            );
            #[cfg(feature = "private-ha-forward-diagnostic")]
            observe_committed_read_phase(
                "same_root_read_or_recover",
                read_started,
                deadline.instant(),
                selected.is_ok(),
            );
            selected.map_err(|error| {
                let reason = error.to_string();
                failure.refused("same_root_reopen_refused", &reason);
                reason
            })?
        } else {
            failure.step("committed_changed_root_recover");
            #[cfg(feature = "private-ha-forward-diagnostic")]
            let read_started = Instant::now();
            let selected = read_or_recover_native_v6_committed_closure(
                node,
                self.runtime.handle(),
                &native.transport,
                &self.peers,
                storage,
                selected,
            );
            #[cfg(feature = "private-ha-forward-diagnostic")]
            observe_committed_read_phase(
                "changed_root_recover",
                read_started,
                deadline.instant(),
                selected.is_ok(),
            );
            selected.map_err(|error| {
                let reason = error.to_string();
                failure.refused("changed_root_recover_refused", &reason);
                reason
            })?
        };
        let read = CommittedNativeV6Read {
            _operation: native_operation,
            instance: native.identity.clone(),
            selected,
            deadline,
        };
        failure.step("committed_final_witness");
        self.verify_native_v6_committed_read(&read)
            .inspect_err(|reason| failure.refused("final_witness_refused", reason))?;
        failure.complete();
        Ok(Some(read))
    }

    pub(crate) fn verify_native_v6_committed_read(
        &self,
        read: &CommittedNativeV6Read,
    ) -> Result<(), String> {
        read.deadline.check().map_err(|error| error.to_string())?;
        let native = self.native_v6.as_ref().ok_or("native HA runtime absent")?;
        if !Arc::ptr_eq(&read.instance, &native.identity) {
            return Err("native HA read belongs to a different process instance".into());
        }
        native.validate_enrollment(&self.codec, read.enrollment())?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        self.runtime
            .block_on(heptabao_raft_runtime::with_read_index_deadline(
                read.deadline.instant(),
                node.verify_native_v6_committed_root_read(&read.selected),
            ))
            .map_err(|error| {
                // Failure observation only. Keep the same opaque witness,
                // original operation/read bounds and original error result.
                #[cfg(any(test, feature = "private-ha-forward-diagnostic"))]
                {
                    use std::io::Write as _;
                    let observed = std::time::Instant::now();
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "HBHA-PRIVATE-READ-WITNESS-FAIL operation_expired={} read_index_expired={} generation={}",
                        observed >= read.deadline.instant(),
                        observed >= read.selected.read_index_deadline(),
                        read.selected.application_generation(),
                    );
                }
                error.to_string()
            })?;
        read.deadline.check().map_err(|error| error.to_string())
    }

    /// The caller keeps the same HaProcess borrow for gates inside the closure.
    /// There is deliberately no fallible post-callback wrapper: that could hide
    /// a local publication's precise unknown/superseded result.
    pub(crate) fn with_native_v6_source<T>(
        &self,
        read: &CommittedNativeV6Read,
        f: impl FnOnce(&ClusterStateCodec, &LocalV6BlobStage) -> T,
    ) -> Result<T, String> {
        self.verify_native_v6_committed_read(read)?;
        let store = self
            .native_v6
            .as_ref()
            .and_then(|native| native.storage.get())
            .ok_or("native HA ciphertext store unavailable")?;
        Ok(f(&self.codec, store))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod request_timing_tests {
    use super::*;

    fn span(scope: &'static str, phase: &'static str) -> NativeV6TimingSpan {
        NativeV6TimingSpan::start(scope, phase, None).expect("active request observation")
    }

    #[test]
    fn native_request_timing_success_and_external_leave_no_report_or_context() {
        for status in [None, Some(200), Some(204), Some(400), Some(499)] {
            let observation = NativeV6RequestObservation::start(
                Instant::now() + Duration::from_secs(8),
                "ordinary",
                false,
            );
            span("test", "completed").finish(true);
            assert!(observation.failure_report(status).is_none());
            assert!(NativeV6TimingSpan::start("test", "next", None).is_none());
        }
    }

    #[test]
    fn native_request_timing_failure_has_only_bounded_static_metadata() {
        let deadline = Instant::now() + Duration::from_secs(10);
        let observation = NativeV6RequestObservation::start(deadline, "ordinary", true);
        let began = deadline - Duration::from_secs(10);
        record_native_timing_for(
            &observation.state,
            "stage",
            "test_read",
            began,
            began + Duration::from_millis(3),
            deadline,
            NativeTimingOutcome::Completed,
        );
        record_native_timing_for(
            &observation.state,
            "stage",
            "test_read",
            began + Duration::from_millis(1),
            began + Duration::from_millis(6),
            deadline,
            NativeTimingOutcome::Failed,
        );
        let report = observation.failure_report(Some(503)).unwrap();
        assert_eq!(report.phases.len(), 1);
        let row = &report.phases[0];
        assert_eq!(
            (row.calls, row.advanced, row.completed, row.failed),
            (2, 0, 1, 1)
        );
        assert_eq!((row.elapsed_us, row.maximum_elapsed_us), (8_000, 5_000));
        assert_eq!(row.first_entry_remaining_ns, 10_000_000_000);
        assert_eq!(row.minimum_entry_remaining_ns, 9_999_000_000);
        assert_eq!(row.last_exit_remaining_ns, 9_994_000_000);
        assert_eq!(row.minimum_exit_remaining_ns, 9_994_000_000);
        let encoded = serde_json::to_value(report).unwrap();
        let fields: BTreeSet<_> = encoded
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            BTreeSet::from([
                "schema",
                "request_class",
                "forwarded",
                "status",
                "elapsed_us",
                "entry_remaining_ns",
                "exit_remaining_ns",
                "bucket_limit",
                "bucket_bound_reached",
                "phases",
            ])
        );
        assert_eq!(
            encoded["schema"],
            "heptabao.native-ha.request-failure-timing.v1"
        );
        assert_eq!(encoded["request_class"], "ordinary");
        assert_eq!(encoded["forwarded"], true);
        assert_eq!(encoded["status"], 503);
        assert_eq!(encoded["phases"][0].as_object().unwrap().len(), 12);
        assert!(NativeV6TimingSpan::start("test", "next", None).is_none());
    }

    #[test]
    fn native_request_timing_sixty_four_buckets_preserve_existing_aggregates() {
        const PHASES: [&str; 65] = [
            "b00", "b01", "b02", "b03", "b04", "b05", "b06", "b07", "b08", "b09", "b10", "b11",
            "b12", "b13", "b14", "b15", "b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
            "b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31", "b32", "b33", "b34", "b35",
            "b36", "b37", "b38", "b39", "b40", "b41", "b42", "b43", "b44", "b45", "b46", "b47",
            "b48", "b49", "b50", "b51", "b52", "b53", "b54", "b55", "b56", "b57", "b58", "b59",
            "b60", "b61", "b62", "b63", "b64",
        ];
        let observation = NativeV6RequestObservation::start(
            Instant::now() + Duration::from_secs(8),
            "ordinary",
            false,
        );
        for phase in PHASES {
            span("bound", phase).finish(true);
        }
        span("bound", "b00").finish(false);
        let report = observation.failure_report(Some(503)).unwrap();
        assert_eq!(report.bucket_limit, 64);
        assert_eq!(report.phases.len(), 64);
        assert!(report.bucket_bound_reached);
        assert!(report.phases.iter().all(|row| row.phase != "b64"));
        assert_eq!(report.phases[0].calls, 2);
        assert_eq!(report.phases[0].failed, 1);
    }

    #[test]
    fn native_request_timing_nested_requests_restore_only_their_own_context() {
        let deadline = Instant::now() + Duration::from_secs(8);
        let outer = NativeV6RequestObservation::start(deadline, "ordinary", false);
        span("outer", "before").finish(true);
        let inner = NativeV6RequestObservation::start(deadline, "health", true);
        span("inner", "only").finish(false);
        let inner = inner.failure_report(Some(503)).unwrap();
        assert_eq!(inner.phases.len(), 1);
        assert_eq!(inner.phases[0].scope, "inner");
        span("outer", "after").finish(true);
        let outer = outer.failure_report(Some(503)).unwrap();
        assert_eq!(outer.phases.len(), 2);
        assert!(outer.phases.iter().all(|row| row.scope == "outer"));
        assert!(NativeV6TimingSpan::start("test", "next", None).is_none());
    }

    #[test]
    fn native_request_timing_detached_spans_never_follow_a_new_request() {
        let deadline = Instant::now() + Duration::from_secs(8);
        let first = NativeV6RequestObservation::start(deadline, "ordinary", false);
        let old_span = span("old", "pending");
        assert!(first.failure_report(None).is_none());
        let second = NativeV6RequestObservation::start(deadline, "ordinary", false);
        old_span.finish(false);
        let report = second.failure_report(Some(503)).unwrap();
        assert!(report.phases.is_empty());
        assert!(NativeV6TimingSpan::start("test", "next", None).is_none());
    }

    #[test]
    fn native_request_timing_out_of_order_drop_cannot_revive_a_closed_request() {
        let deadline = Instant::now() + Duration::from_secs(8);
        let outer = NativeV6RequestObservation::start(deadline, "ordinary", false);
        let inner = NativeV6RequestObservation::start(deadline, "health", false);
        drop(outer);
        span("inner", "active").finish(true);
        assert_eq!(inner.failure_report(Some(503)).unwrap().phases.len(), 1);
        assert!(NativeV6TimingSpan::start("test", "next", None).is_none());
    }

    #[test]
    fn native_request_timing_unwinding_restores_the_previous_scope() {
        let deadline = Instant::now() + Duration::from_secs(8);
        let outer = NativeV6RequestObservation::start(deadline, "ordinary", false);
        let caught = std::panic::catch_unwind(|| {
            let _inner = NativeV6RequestObservation::start(deadline, "health", false);
            let _span = span("inner", "unwind");
            panic!("fixed timing test unwind");
        });
        assert!(caught.is_err());
        span("outer", "after_unwind").finish(true);
        let report = outer.failure_report(Some(503)).unwrap();
        assert_eq!(report.phases.len(), 1);
        assert_eq!(report.phases[0].scope, "outer");
    }

    #[test]
    fn native_request_timing_thread_local_context_is_not_inherited() {
        let deadline = Instant::now() + Duration::from_secs(8);
        let parent = NativeV6RequestObservation::start(deadline, "ordinary", false);
        let report = std::thread::spawn(move || {
            assert!(NativeV6TimingSpan::start("test", "foreign", None).is_none());
            let child = NativeV6RequestObservation::start(deadline, "health", true);
            span("child", "only").finish(true);
            child.failure_report(Some(503)).unwrap()
        })
        .join()
        .unwrap();
        assert_eq!(report.phases.len(), 1);
        assert_eq!(report.phases[0].scope, "child");
        span("parent", "only").finish(true);
        let report = parent.failure_report(Some(503)).unwrap();
        assert_eq!(report.phases.len(), 1);
        assert_eq!(report.phases[0].scope, "parent");
    }

    #[test]
    fn native_request_timing_observes_deadlines_but_preserves_once_only_results() {
        let deadline = Instant::now() + Duration::from_secs(8);
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        let original = OriginalDeadline::capture().unwrap();
        let request = NativeV6RequestObservation::start(deadline, "ordinary", false);
        let earlier = deadline - Duration::from_secs(1);
        let timing = NativeV6TimingSpan::start("test", "earlier", Some(earlier)).unwrap();
        assert_eq!(timing.deadline, earlier);
        assert_eq!(crate::request_deadline::current(), Some(deadline));
        timing.finish(true);
        let calls = std::cell::Cell::new(0);
        let error = Box::new(71_u64);
        let identity = std::ptr::from_ref(error.as_ref());
        let result: Result<(), Box<u64>> =
            crate::ha::observe_native_v6_timing("test", "exact_error", Some(earlier), || {
                calls.set(calls.get() + 1);
                Err(error)
            });
        let returned = result.unwrap_err();
        assert_eq!(std::ptr::from_ref(returned.as_ref()), identity);
        assert_eq!(calls.get(), 1);
        let already_expired = Instant::now() - Duration::from_secs(1);
        let result: Result<u64, ()> = crate::ha::observe_native_v6_timing(
            "test",
            "expired_observation",
            Some(already_expired),
            || {
                calls.set(calls.get() + 1);
                Ok(72)
            },
        );
        assert_eq!(result, Ok(72));
        assert_eq!(calls.get(), 2);
        assert_eq!(crate::request_deadline::current(), Some(original.instant()));
        assert!(original.check().is_ok());
        assert!(request.failure_report(None).is_none());
        let result: Result<u64, ()> =
            crate::ha::observe_native_v6_timing("test", "without_context", None, || {
                calls.set(calls.get() + 1);
                Ok(73)
            });
        assert_eq!(result, Ok(73));
        assert_eq!(calls.get(), 3);
        assert_eq!(crate::request_deadline::current(), Some(original.instant()));
    }

    #[test]
    fn native_request_timing_phase_advance_is_distinct_from_operation_success() {
        let deadline = Instant::now() + Duration::from_secs(8);
        let request = NativeV6RequestObservation::start(deadline, "ordinary", false);
        let operation = NativeV6FailureObservation::start("entry", deadline);
        operation.step("work");
        operation.complete();
        let report = request.failure_report(Some(503)).unwrap();
        let entry = report
            .phases
            .iter()
            .find(|row| row.phase == "entry")
            .unwrap();
        assert_eq!((entry.advanced, entry.completed, entry.failed), (1, 0, 0));
        let work = report
            .phases
            .iter()
            .find(|row| row.phase == "work")
            .unwrap();
        assert_eq!((work.advanced, work.completed, work.failed), (0, 1, 0));
        let total = report
            .phases
            .iter()
            .find(|row| row.phase == "scope_total")
            .unwrap();
        assert_eq!((total.advanced, total.completed, total.failed), (0, 1, 0));
    }
}
