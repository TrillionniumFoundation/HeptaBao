//! Native snapshot admission, out-of-writer transfer, and affine finalization.
use super::*;
use crate::{
    snapshot_archive::{self, DownloadSource, Import, Metadata},
    snapshot_file::{
        MAX_NATIVE_ARCHIVE, MAX_NATIVE_STATE, SnapshotFile, SnapshotLease, SnapshotSpool,
    },
    state_record_root::StateIdentity,
};
use sha2::{Digest, Sha256};
use std::time::Instant;

pub(super) const NATIVE_HA_REPAIR_PATH: &str = "sys/storage/raft/snapshot-repair";

#[cfg(feature = "native-v6-ha")]
#[derive(Clone, Copy)]
enum PendingRestoreRequest {
    Inspect,
    Cancel([u8; 32]),
}
#[cfg(feature = "native-v6-ha")]
impl PendingRestoreRequest {
    fn operation(self) -> Option<[u8; 32]> {
        match self {
            Self::Inspect => None,
            Self::Cancel(operation) => Some(operation),
        }
    }
}

#[cfg(feature = "native-v6-ha")]
fn pending_restore_query(
    body: &Value,
    enabled: bool,
) -> Result<Option<PendingRestoreRequest>, Response> {
    let invalid = || Response::error(400, "unsupported native snapshot query fields");
    let fields = body.as_object().ok_or_else(invalid)?;
    if fields.is_empty() {
        return Ok(None);
    }
    if !enabled || fields.len() != 1 {
        return Err(invalid());
    }
    if fields.get("inspect_pending_restore") == Some(&Value::Bool(true)) {
        return Ok(Some(PendingRestoreRequest::Inspect));
    }
    let raw = fields
        .get("cancel_pending_restore")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("native-v6-restore-"))
        .ok_or_else(invalid)?;
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid());
    }
    let mut operation = [0; 32];
    for (index, byte) in operation.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    if operation == [0; 32] {
        return Err(invalid());
    }
    Ok(Some(PendingRestoreRequest::Cancel(operation)))
}

#[cfg(feature = "native-v6-storage")]
#[path = "service_snapshot_lossless_export.rs"]
mod lossless_export;
#[cfg(feature = "native-v6-storage")]
#[path = "service_snapshot_v6.rs"]
mod v6;

#[cfg(feature = "native-v6-ha")]
#[path = "service_snapshot_denial.rs"]
mod denial;

#[cfg(feature = "native-v6-ha")]
enum StandbySnapshotAdmission {
    Redirect,
    Authenticated {
        actor: Box<Principal>,
        clock: (Instant, Duration),
    },
    Denied(Box<denial::StandbySnapshotDenial>),
}

// A routing hint is deliberately not an application read/write capability.
// Only this module can construct one, from a configured HA peer API origin.
pub(crate) struct TrustedSnapshotOrigin(String);
impl TrustedSnapshotOrigin {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) enum NativeSnapshotAdmission {
    Execute(RequestExecution),
    Redirect(TrustedSnapshotOrigin),
}

// One authenticated admission identity and its physically observed seal bytes.
// The wrapped key bytes are erased when the affine transfer plan is dropped.
type AdmittedSnapshotSealIdentity = ([u8; 32], SealMetadata, Zeroizing<Vec<u8>>);

#[cfg(feature = "native-v6-ha")]
struct StandbySnapshotClockRequest {
    operation: crate::ha::snapshot_clock::SnapshotClockOperation,
    method: String,
    token: Zeroizing<String>,
    origin_peer: Option<std::net::IpAddr>,
    ingress: [u8; 16],
}

#[cfg(feature = "native-v6-ha")]
impl StandbySnapshotClockRequest {
    fn capture(request: &RequestView<'_>) -> Result<Self, Response> {
        use crate::ha::snapshot_clock::SnapshotClockOperation;
        let operation = match (request.method, request.path) {
            ("GET" | "HEAD", "sys/storage/raft/snapshot") => SnapshotClockOperation::Download,
            ("POST" | "PUT", "sys/storage/raft/snapshot") => SnapshotClockOperation::ValidateUpload,
            ("POST" | "PUT", "sys/storage/raft/snapshot-force") => {
                SnapshotClockOperation::ValidateForceUpload
            }
            _ => {
                return Err(Response::error(
                    503,
                    "standby clock operation is unavailable",
                ));
            }
        };
        let ingress = crate::auth::current_ingress()
            .ok_or_else(|| Response::error(503, "standby clock requires original HTTP ingress"))?
            .attempt_id();
        Ok(Self {
            operation,
            method: request.method.to_owned(),
            token: Zeroizing::new(request.token.to_owned()),
            origin_peer: request.origin_peer,
            ingress,
        })
    }
}

pub(super) struct SnapshotTransferPlan {
    actor: Principal,
    path: String,
    namespace: String,
    activation: String,
    seal_identity: [u8; 32],
    // Admission-authenticated raw seal bytes: a byte-identical live read need
    // not re-parse JSON or re-hash the wrapped key 15,000 times. The real
    // held-parent read and full caller's Actor/ACL/clock checks NEVER skip.
    seal_metadata_at_admission: SealMetadata,
    seal_bytes_at_admission: Zeroizing<Vec<u8>>,
    ha: Option<Arc<Mutex<HaProcess>>>,
    base: StateIdentity,
    #[cfg(feature = "native-v6-storage")]
    native_root_contents: Option<crate::state_record_root_v6::NativeRootContentIdentity>,
    deadline: Instant,
    started: Instant,
    now: Duration,
    lease: Arc<SnapshotLease>,
    download: Option<DownloadSource>,
    #[cfg(feature = "native-v6-storage")]
    lossless_download: Option<SnapshotFile>,
    is_download: bool,
    // Only actual non-consuming standby admission sets this. Download and
    // upload validation retain a read proof; neither can restore or publish.
    standby_read: bool,
    #[cfg(feature = "native-v6-ha")]
    standby_clock: Option<StandbySnapshotClockRequest>,
    // Native negative-outcome custody belongs to this pending request, not
    // the idle Service. Dropping a cancelled transfer must not poison the
    // next unrelated request; finalization restores exactly the original one.
    #[cfg(feature = "native-v6-storage")]
    native_request_binding: Option<native_v6_writer::NativeRequestBinding>,
    #[cfg(feature = "native-v6-ha")]
    native_ha_source: Option<native_v6_ha_install::NativeHaReadProof>,
    #[cfg(feature = "native-v6-ha")]
    native_ha_repair: Option<native_v6_ha_install::NativeHaArchiveRepairSource>,
    #[cfg(feature = "native-v6-ha")]
    native_ha_restore_source: Option<native_v6_ha_install::NativeHaArchiveRepairSource>,
    #[cfg(feature = "native-v6-ha")]
    native_ha_pending_restore: Option<PendingRestoreRequest>,
    #[cfg(feature = "native-v6-ha")]
    native_ha_restore_attempt: Option<([u8; 32], bool)>,
    #[cfg(feature = "native-v6-ha")]
    native_ha_restored: Option<v6::NativeHaHistoricalReceipt>,
}
impl SnapshotTransferPlan {
    pub(super) fn original_deadline(&self) -> Instant {
        self.deadline
    }
}

// Only this module can construct the capability, after native archive and
// live-seal authentication. It contains the exact validated restore candidate.
pub(super) struct VerifiedNativeRestore {
    prepared: backup_restore::PreparedSnapshotRestore,
    clock: (Duration, Instant),
}
impl VerifiedNativeRestore {
    pub(super) fn clock(&self) -> (Duration, Instant) {
        self.clock
    }
    pub(super) fn into_prepared(self) -> backup_restore::PreparedSnapshotRestore {
        self.prepared
    }
}

pub(in crate::service) fn canonical_seal_identity(
    seal: &SealMetadata,
) -> Result<[u8; 32], &'static str> {
    seal.validate()?;
    let associated = seal.associated_data();
    let wrapped = Zeroizing::new(
        STANDARD
            .decode(&seal.wrapped_barrier_key)
            .map_err(|_| "invalid seal envelope")?,
    );
    let mut hash = Sha256::new();
    hash.update(b"heptabao.native-snapshot.seal-metadata.v1\0");
    hash.update((associated.len() as u64).to_le_bytes());
    hash.update(&associated);
    hash.update((wrapped.len() as u64).to_le_bytes());
    hash.update(wrapped.as_slice());
    Ok(hash.finalize().into())
}

pub(crate) enum Observation {
    Download,
    Upload(Import),
    #[cfg(feature = "native-v6-ha")]
    PendingRestore,
}

// Retain the wall-clock fraction captured at admission. Rounding only after
// adding monotonic elapsed time avoids expiring one-second leases early and
// does not consult a wall clock that could have moved backward during I/O.
fn snapshot_observed_time(wall_anchor: Duration, elapsed: Duration) -> u64 {
    wall_anchor.saturating_add(elapsed).as_secs()
}

impl PendingExternalRequest {
    #[cfg(feature = "native-v6-storage")]
    pub(crate) fn has_lossless_download(&self) -> bool {
        matches!(&self.effect, ExternalEffectPlan::SnapshotTransfer(plan)
            if plan.is_download && plan.lossless_download.is_some())
    }

    pub(crate) fn execute_snapshot_transfer(
        &mut self,
        reader: &mut impl Read,
    ) -> (ExternalEffectResult, Option<SnapshotFile>) {
        let ExternalEffectPlan::SnapshotTransfer(plan) = &mut self.effect else {
            return (
                ExternalEffectResult::SnapshotTransfer(Err(Response::error(
                    503,
                    "snapshot transfer plan mismatch",
                ))),
                None,
            );
        };
        #[cfg(feature = "native-v6-storage")]
        if plan.is_download && plan.path == crate::engines::kv2_lossless_export::PATH {
            return match plan.lossless_download.take() {
                Some(file) => (
                    ExternalEffectResult::SnapshotTransfer(Ok(Observation::Download)),
                    Some(file),
                ),
                None => (
                    ExternalEffectResult::SnapshotTransfer(Err(Response::error(
                        503,
                        "lossless export already consumed",
                    ))),
                    None,
                ),
            };
        }
        let result = if plan.is_download {
            match plan
                .download
                .take()
                .ok_or_else(|| io::Error::other("snapshot source already consumed"))
                .and_then(|source| snapshot_archive::export(source, &plan.lease, plan.deadline))
            {
                Ok(file) => {
                    return (
                        ExternalEffectResult::SnapshotTransfer(Ok(Observation::Download)),
                        Some(file),
                    );
                }
                Err(_) => Err(Response::error(503, "snapshot download preparation failed")),
            }
        } else {
            (|| {
                #[cfg(feature = "native-v6-ha")]
                if plan.native_ha_pending_restore.is_some() {
                    if Instant::now() >= plan.deadline {
                        return Err(Response::error(503, "snapshot transfer deadline exceeded"));
                    }
                    let mut byte = [0; 1];
                    let count = reader
                        .read(&mut byte)
                        .map_err(|_| Response::error(400, "incomplete snapshot body"))?;
                    if Instant::now() >= plan.deadline {
                        return Err(Response::error(503, "snapshot transfer deadline exceeded"));
                    }
                    return if count == 0 {
                        Ok(Observation::PendingRestore)
                    } else {
                        Err(Response::error(
                            400,
                            "pending restore reconciliation requires an empty body",
                        ))
                    };
                }
                let mut archive = plan
                    .lease
                    .file(MAX_NATIVE_ARCHIVE, plan.deadline)
                    .map_err(|_| Response::error(507, "snapshot staging is unavailable"))?;
                let mut buffer = Zeroizing::new([0; 64 * 1024]);
                loop {
                    if Instant::now() >= plan.deadline {
                        return Err(Response::error(503, "snapshot transfer deadline exceeded"));
                    }
                    let count = reader
                        .read(&mut *buffer)
                        .map_err(|_| Response::error(400, "incomplete snapshot body"))?;
                    if count == 0 {
                        break;
                    }
                    archive.write_all(&buffer[..count]).map_err(|_| {
                        Response::error(413, "snapshot archive exceeds transfer bound")
                    })?;
                }
                snapshot_archive::import(archive, &plan.lease, plan.deadline)
                    .map(Observation::Upload)
                    .map_err(|_| {
                        Response::error(
                            if matches!(
                                plan.path.as_str(),
                                "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
                            ) {
                                500
                            } else {
                                400
                            },
                            "invalid native snapshot archive",
                        )
                    })
            })()
        };
        (ExternalEffectResult::SnapshotTransfer(result), None)
    }
}

impl Service {
    fn current_snapshot_seal_identity_and_raw(
        &self,
        lease: &SnapshotLease,
        deadline: Instant,
    ) -> Result<AdmittedSnapshotSealIdentity, Response> {
        let bytes = lease
            .read_seal_metadata(deadline)
            .map_err(|_| Response::error(503, "snapshot seal metadata is unavailable"))?;
        let seal: SealMetadata = serde_json::from_slice(&bytes)
            .map_err(|_| Response::error(503, "snapshot seal metadata is invalid"))?;
        if self.seal.as_ref() != Some(&seal) {
            return Err(Response::error(409, "snapshot seal metadata changed"));
        }
        let identity = canonical_seal_identity(&seal)
            .map_err(|_| Response::error(503, "snapshot seal metadata is invalid"))?;
        Ok((identity, seal, bytes))
    }

    // An equal snapshot of the BYTES from the checked parent descriptor proves
    // the same canonical metadata authenticated at admission. When ANY bytes
    // differ, preserve the prior full JSON, in-memory seal and canonical SHA
    // identity semantics (including accepting harmless JSON reencoding).
    fn snapshot_seal_identity_checked_against_admission(
        bytes: &[u8],
        admitted_bytes: &[u8],
        admitted_seal: &SealMetadata,
        current_seal: Option<&SealMetadata>,
        admitted_identity: [u8; 32],
    ) -> Result<[u8; 32], Response> {
        if bytes == admitted_bytes && current_seal == Some(admitted_seal) {
            return Ok(admitted_identity);
        }
        let seal: SealMetadata = serde_json::from_slice(bytes)
            .map_err(|_| Response::error(503, "snapshot seal metadata is invalid"))?;
        if current_seal != Some(&seal) {
            return Err(Response::error(409, "snapshot seal metadata changed"));
        }
        canonical_seal_identity(&seal)
            .map_err(|_| Response::error(503, "snapshot seal metadata is invalid"))
    }

    #[cfg(feature = "native-v6-storage")]
    fn current_identity_matches_snapshot_plan(
        &self,
        plan: &SnapshotTransferPlan,
        target: StateIdentity,
    ) -> bool {
        let same_contents = self.state.is_some()
            && self.record_root.is_none()
            && plan.native_root_contents.as_ref().is_some_and(|contents| {
                self.native_root.as_ref().is_some_and(|root| {
                    self.current_state_digest().ok().is_some_and(|digest| {
                        contents
                            .matches_current(root, target, digest)
                            .unwrap_or(false)
                    })
                })
            });
        same_contents || self.current_state_identity().ok() == Some(target)
    }

    fn current_snapshot_seal_identity_for_plan(
        &self,
        plan: &SnapshotTransferPlan,
    ) -> Result<[u8; 32], Response> {
        // NEVER omit the real descriptor-anchored physical read, type/owner/
        // size/mode checks or deadline. Only the repeated JSON/crypto work is
        // avoided for strictly byte-identical validated metadata.
        let bytes = plan
            .lease
            .read_seal_metadata(plan.deadline)
            .map_err(|_| Response::error(503, "snapshot seal metadata is unavailable"))?;
        Self::snapshot_seal_identity_checked_against_admission(
            bytes.as_slice(),
            plan.seal_bytes_at_admission.as_slice(),
            &plan.seal_metadata_at_admission,
            self.seal.as_ref(),
            plan.seal_identity,
        )
    }

    pub(crate) fn begin_native_snapshot_before(
        &mut self,
        mut request: ServiceRequest<'_>,
        deadline: Instant,
    ) -> NativeSnapshotAdmission {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        if crate::request_deadline::current().is_none_or(|limit| Instant::now() >= limit) {
            erase_json(&mut request.body);
            return NativeSnapshotAdmission::Execute(RequestExecution::Complete(Response::error(
                503,
                "snapshot admission deadline exceeded",
            )));
        }
        let accepted = matches!(
            request.path,
            "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force" | NATIVE_HA_REPAIR_PATH
        );
        #[cfg(feature = "native-v6-storage")]
        let accepted = accepted
            || (request.path == crate::engines::kv2_lossless_export::PATH
                && matches!(request.method, "GET" | "HEAD"));
        if !accepted {
            erase_json(&mut request.body);
            return NativeSnapshotAdmission::Execute(RequestExecution::Complete(Response::error(
                400,
                "invalid native snapshot route",
            )));
        }
        #[cfg(feature = "native-v6-ha")]
        let (mut standby_actor, mut standby_observation) = (None, None);
        #[cfg(not(feature = "native-v6-ha"))]
        let (standby_actor, standby_observation): (Option<Principal>, Option<(Instant, Duration)>) =
            (None, None);
        // This is before authentication/finite-use persistence, staging and
        // JSON HA forwarding. The receiving leader independently authorizes
        // the original request; observing a leader never grants authority.
        match self.native_snapshot_destination() {
            Ok(Some(origin)) => {
                #[cfg(feature = "native-v6-ha")]
                match self.prepare_native_standby_snapshot_read(&request) {
                    Ok(StandbySnapshotAdmission::Redirect) => {}
                    Ok(StandbySnapshotAdmission::Authenticated { actor, clock }) => {
                        standby_actor = Some(*actor);
                        standby_observation = Some(clock);
                    }
                    Ok(StandbySnapshotAdmission::Denied(denied)) => {
                        erase_json(&mut request.body);
                        return NativeSnapshotAdmission::Execute(RequestExecution::Complete(
                            self.complete_standby_snapshot_denial(*denied),
                        ));
                    }
                    Err(response) => {
                        erase_json(&mut request.body);
                        return NativeSnapshotAdmission::Execute(RequestExecution::Complete(
                            response,
                        ));
                    }
                }
                if standby_actor.is_none() {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::ZERO)
                        .as_secs();
                    let fingerprint = self.request_fingerprint(
                        request.method,
                        request.path,
                        request.namespace,
                        request.token,
                    );
                    erase_json(&mut request.body);
                    if self
                        .audit_event("request", &fingerprint, now, None)
                        .is_err()
                    {
                        return NativeSnapshotAdmission::Execute(RequestExecution::Complete(
                            Response::error(503, "snapshot redirect audit unavailable"),
                        ));
                    }
                    if self
                        .audit_event("response", &fingerprint, now, Some(307))
                        .is_err()
                    {
                        crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                        self.recovery_required = true;
                        self.ha_activation = None;
                        return NativeSnapshotAdmission::Execute(RequestExecution::Complete(
                            Response::error(503, "snapshot redirect response audit unavailable"),
                        ));
                    }
                    return NativeSnapshotAdmission::Redirect(origin);
                }
            }
            Err(response) => {
                erase_json(&mut request.body);
                return NativeSnapshotAdmission::Execute(RequestExecution::Complete(response));
            }
            Ok(None) => {}
        }
        // Pair wall time and the monotonic anchor before reconciliation, audit,
        // authentication and finite-use persistence can spend admission time.
        let (started, now) = standby_observation.unwrap_or_else(|| {
            let started = Instant::now();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO);
            (started, now)
        });
        let previous_clock = self.native_snapshot_clock.replace((started, now));
        let previous = self.native_snapshot_transport;
        let previous_standby = self.native_snapshot_standby_read;
        let previous_actor =
            std::mem::replace(&mut self.native_snapshot_standby_actor, standby_actor);
        self.native_snapshot_standby_read = self.native_snapshot_standby_actor.is_some();
        self.native_snapshot_transport = true;
        let result = self.begin_request_before(request, deadline, false);
        self.native_snapshot_transport = previous;
        self.native_snapshot_standby_read = previous_standby;
        self.native_snapshot_standby_actor = previous_actor;
        self.native_snapshot_clock = previous_clock;
        NativeSnapshotAdmission::Execute(result)
    }

    pub(super) fn native_snapshot_destination(
        &self,
    ) -> Result<Option<TrustedSnapshotOrigin>, Response> {
        let Some(process) = self.ha.as_ref() else {
            return Ok(None);
        };
        if self.state.is_none() {
            return Err(Response::error(503, "server is sealed"));
        }
        let process = process
            .lock_for_request()
            .map_err(|_| Response::error(503, "HA process lock is unavailable"))?;
        let observation = process
            .leader_status()
            .map_err(|_| Response::error(503, "HA leader state is unavailable"))?;
        let leader = observation
            .leader
            .ok_or_else(|| Response::error(503, "HA cluster has no elected leader"))?;
        if leader == observation.local_id {
            return Ok(None);
        }
        process
            .api_address(leader)
            .map(|origin| Some(TrustedSnapshotOrigin(origin.to_owned())))
            .ok_or_else(|| Response::error(503, "HA leader API address is unavailable"))
    }

    pub(super) fn native_standby_snapshot_is_read_eligible(&self) -> bool {
        #[cfg(feature = "native-v6-ha")]
        if self.native_root.is_some() && self.ha.is_some() {
            return self.state.as_ref().is_some_and(|state| {
                !state.auth.has_control_group_state()
                    && !state.auth.has_policy_expiration_state()
                    && !state.engines.has_kubernetes_opaque_artifact_state()
                    && !state.engines.has_live_leases()
            });
        }
        false
    }

    #[cfg(feature = "native-v6-ha")]
    fn prepare_native_standby_snapshot_read(
        &mut self,
        request: &ServiceRequest<'_>,
    ) -> Result<StandbySnapshotAdmission, Response> {
        if !self.native_ha_snapshot_transport_enabled()
            || !matches!(
                (request.method, request.path),
                ("GET" | "HEAD", "sys/storage/raft/snapshot")
                    | (
                        "POST" | "PUT",
                        "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
                    )
            )
            || !request.namespace.is_empty()
            || request.wrap_ttl_seconds.is_some()
            || request.body.as_object().is_none_or(|body| !body.is_empty())
        {
            return Ok(StandbySnapshotAdmission::Redirect);
        }
        // Actual synchronization and ReadIndex precede token inspection.
        // A routing hint cannot select stale credentials or spend a use.
        self.sync_from_ha_with_anchor(false)?;
        if !self.native_standby_snapshot_is_read_eligible() {
            return Ok(StandbySnapshotAdmission::Redirect);
        }
        let started = Instant::now();
        let observed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Response::error(503, "trusted snapshot clock is unavailable"))?;
        let clock = RequestClock::anchored(observed, started)
            .map_err(|_| Response::error(503, "trusted snapshot clock is unavailable"))?;
        let at = clock
            .observed_at()
            .map_err(|_| Response::error(503, "trusted snapshot clock is unavailable"))?;
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let mut actor = match state.auth.authenticate_read_only_from_observed(
            request.token,
            AuthorityTime::Precise(at),
            request.origin_peer,
        ) {
            Ok(Some(actor)) => actor,
            // Missing, invalid, finite-use and wrapping credentials still
            // redirect without consumption; only a real unlimited Actor can
            // select local ACL handling.
            _ => return Ok(StandbySnapshotAdmission::Redirect),
        };
        let admission = Self::bind_identity_principal(state, &mut actor, request.namespace)
            .and_then(|()| {
                state
                    .auth
                    .authorize_request_parameters_observed(
                        &actor,
                        request.namespace,
                        request.method,
                        request.path,
                        &request.body,
                        AuthorityTime::Precise(at),
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
            })
            .and_then(|()| {
                state
                    .auth
                    .authorize_request_observed(
                        &actor,
                        request.namespace,
                        request.path,
                        if matches!(request.method, "GET" | "HEAD") {
                            "read"
                        } else {
                            "update"
                        },
                        AuthorityTime::Precise(at),
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
            });
        if state.has_token_api_precision_state() && crate::auth::current_ingress().is_none() {
            return Err(Response::error(
                503,
                "standby clock requires original HTTP ingress",
            ));
        }
        match admission {
            Ok(()) => Ok(StandbySnapshotAdmission::Authenticated {
                actor: Box::new(actor),
                clock: (started, observed),
            }),
            Err(response) if response.status == 403 => self
                .prepare_standby_snapshot_denial(request, actor, response, clock, observed, started)
                .map(|denied| StandbySnapshotAdmission::Denied(Box::new(denied))),
            Err(response) => Err(response),
        }
    }

    pub(super) fn stage_snapshot_transfer(
        &mut self,
        actor: Principal,
        request: &RequestView<'_>,
    ) -> Response {
        if !request.namespace.is_empty() || !request.body.is_object() {
            return Response::error(
                400,
                "native snapshot requires the root namespace and no query fields",
            );
        }
        #[cfg(feature = "native-v6-storage")]
        let lossless_mount = if request.path == crate::engines::kv2_lossless_export::PATH {
            match lossless_export::mount_query(request) {
                Ok(mount) => Some(mount),
                Err(response) => return response,
            }
        } else {
            None
        };
        #[cfg(not(feature = "native-v6-storage"))]
        let lossless_mount: Option<&str> = None;
        let empty_query = json!({});
        let snapshot_query = if lossless_mount.is_some() {
            &empty_query
        } else {
            request.body
        };
        #[cfg(feature = "native-v6-ha")]
        let native_ha_pending_restore = match pending_restore_query(
            snapshot_query,
            self.native_ha_snapshot_transport_enabled()
                && request.path == "sys/storage/raft/snapshot"
                && matches!(request.method, "POST" | "PUT"),
        ) {
            Ok(operation) => operation,
            Err(response) => return response,
        };
        #[cfg(not(feature = "native-v6-ha"))]
        if snapshot_query
            .as_object()
            .is_none_or(|object| !object.is_empty())
        {
            return Response::error(
                400,
                "native snapshot requires the root namespace and no query fields",
            );
        }
        if !actor.is_root()
            && !matches!(
                request.path,
                "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
            )
        {
            return Response::error(403, "permission denied");
        }
        #[cfg(feature = "native-v6-ha")]
        if !actor.is_root() && native_ha_pending_restore.is_some() {
            return Response::error(403, "permission denied");
        }
        let Some((started, now)) = self.native_snapshot_clock else {
            return Response::error(503, "snapshot admission clock unavailable");
        };
        if now.as_secs() != request.now {
            return Response::error(503, "snapshot admission clock differs");
        }
        let download = matches!(request.method, "GET" | "HEAD")
            && (request.path == "sys/storage/raft/snapshot" || lossless_mount.is_some());
        let repair = request.path == NATIVE_HA_REPAIR_PATH;
        if !download && !matches!(request.method, "POST" | "PUT") {
            return Response::error(405, "snapshot restore requires POST or PUT");
        }
        // Public snapshot policy tokens must pass the same real read/update
        // ACL before any V5/V6 export, validation lease or restore preparation.
        // Internal repair/lossless/pending-restore operations remain root-only.
        let time = match request.token_time() {
            Ok(time) => time,
            Err(error) => return error,
        };
        let Some(state) = self.state.as_ref() else {
            return Response::error(503, "server is sealed");
        };
        if let Err(error) = state.auth.authorize_request_observed(
            &actor,
            request.namespace,
            request.path,
            if download { "read" } else { "update" },
            time,
        ) {
            return Response::error(error.status, &error.message);
        }
        if !download
            && !repair
            && self.state.as_ref().is_some_and(|state| {
                !state.database.is_empty() || state.engines.has_openldap_mount()
            })
        {
            return Response::error(
                409,
                "external provider state cannot be rolled back with a local snapshot",
            );
        }
        let deadline = match crate::request_deadline::current() {
            Some(value) if value > Instant::now() => value,
            _ => return Response::error(503, "snapshot deadline unavailable"),
        };
        let base = match self.current_state_identity() {
            Ok(value) => value,
            Err(error) => return error,
        };
        #[cfg(feature = "native-v6-ha")]
        let standby_clock = if self.native_snapshot_standby_read
            && self
                .state
                .as_ref()
                .is_some_and(State::has_token_api_precision_state)
        {
            match StandbySnapshotClockRequest::capture(request) {
                Ok(context) => Some(context),
                Err(error) => return error,
            }
        } else {
            None
        };
        #[cfg(feature = "native-v6-storage")]
        let native_root_contents = if lossless_mount.is_some() && self.ha.is_none() {
            match self
                .native_root
                .as_ref()
                .map(|root| {
                    crate::state_record_root_v6::NativeRootContentIdentity::capture(root, base)
                })
                .transpose()
            {
                Ok(value) => value,
                Err(_) => return Response::error(503, "native identity rejected"),
            }
        } else {
            None
        };
        let spool = match self.snapshot_spool.as_ref() {
            Some(value) => Arc::clone(value),
            None => match SnapshotSpool::open(&self.data_dir) {
                Ok(value) => {
                    self.snapshot_spool = Some(Arc::clone(&value));
                    value
                }
                Err(_) => return Response::error(503, "snapshot staging is unavailable"),
            },
        };
        let lease = match spool.lease() {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Response::error(429, "snapshot transfer is already active");
            }
            Err(_) => return Response::error(503, "snapshot staging is unavailable"),
        };
        let (seal_identity, seal_metadata_at_admission, seal_bytes_at_admission) =
            match self.current_snapshot_seal_identity_and_raw(&lease, deadline) {
                Ok(value) => value,
                Err(response) => return response,
            };
        let mut plan = SnapshotTransferPlan {
            actor,
            path: request.path.to_owned(),
            namespace: request.namespace.to_owned(),
            activation: self.unseal_nonce.clone(),
            seal_identity,
            seal_metadata_at_admission,
            seal_bytes_at_admission,
            ha: self.ha.clone(),
            base,
            #[cfg(feature = "native-v6-storage")]
            native_root_contents,
            deadline,
            started,
            now,
            lease: Arc::clone(&lease),
            download: None,
            #[cfg(feature = "native-v6-storage")]
            lossless_download: None,
            is_download: download,
            standby_read: self.native_snapshot_standby_read,
            #[cfg(feature = "native-v6-ha")]
            standby_clock,
            #[cfg(feature = "native-v6-storage")]
            native_request_binding: None,
            #[cfg(feature = "native-v6-ha")]
            native_ha_source: None,
            #[cfg(feature = "native-v6-ha")]
            native_ha_repair: None,
            #[cfg(feature = "native-v6-ha")]
            native_ha_restore_source: None,
            #[cfg(feature = "native-v6-ha")]
            native_ha_pending_restore,
            #[cfg(feature = "native-v6-ha")]
            native_ha_restore_attempt: None,
            #[cfg(feature = "native-v6-ha")]
            native_ha_restored: None,
        };
        #[cfg(feature = "native-v6-storage")]
        if let Some(mount) = lossless_mount {
            plan.lossless_download =
                match self.prepare_native_kv2_lossless_download(&mut plan, mount) {
                    Ok(file) => Some(file),
                    Err(error) => return error,
                };
        }
        let source = if download && lossless_mount.is_none() {
            let result = (|| -> Result<DownloadSource, Response> {
                #[cfg(feature = "native-v6-storage")]
                if self.native_root.is_some() {
                    return self.prepare_v6_snapshot_download(&mut plan);
                }
                #[cfg(feature = "native-v6-storage")]
                self.repair_unreachable_native_migration_slots_before_v5_snapshot(&plan)?;
                let durable = self
                    .durable
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "server is sealed"))?;
                let mut state = lease
                    .file(MAX_NATIVE_STATE, deadline)
                    .map_err(|_| Response::error(507, "snapshot staging is unavailable"))?;
                let mut output = snapshot_archive::HashWriter {
                    writer: &mut state,
                    hash: Sha256::new(),
                };
                let length = durable
                    .export_backup_to(&mut output)
                    .map_err(|_| Response::error(503, "cannot export durable snapshot"))?;
                let digest: [u8; 32] = output.hash.finalize().into();
                let metadata = serde_json::to_vec(&Metadata::new(
                    durable.generation(),
                    length,
                    &seal_identity,
                ))
                .map_err(|_| Response::error(503, "snapshot metadata unavailable"))?;
                let sums = snapshot_archive::sums(&metadata, &digest);
                let key = self
                    .barrier_key
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "server is sealed"))?;
                let barrier = AeadBarrier::new(**key)
                    .map_err(|_| Response::error(503, "snapshot seal unavailable"))?;
                let sealed_sums = barrier
                    .seal(snapshot_archive::CHECKSUM_CONTEXT, &sums)
                    .map_err(|_| Response::error(503, "snapshot seal unavailable"))?;
                state
                    .rewind_checked()
                    .map_err(|_| Response::error(503, "snapshot staging unavailable"))?;
                Ok(DownloadSource {
                    state,
                    metadata,
                    sums,
                    sealed_sums,
                })
            })();
            match result {
                Ok(value) => Some(value),
                Err(error) => return error,
            }
        } else {
            None
        };
        plan.download = source;
        #[cfg(feature = "native-v6-ha")]
        if plan.standby_read
            && !download
            && let Err(error) = self.prepare_native_ha_standby_snapshot_validation(&mut plan)
        {
            return error;
        }
        #[cfg(feature = "native-v6-ha")]
        if !download
            && !plan.standby_read
            && self.native_ha_snapshot_transport_enabled()
            && matches!(
                plan.path.as_str(),
                "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
            )
            && let Err(error) = self.prepare_native_ha_historical_upload(&mut plan)
        {
            return error;
        }
        #[cfg(feature = "native-v6-storage")]
        {
            plan.native_request_binding = self.native_request_binding.take();
        }
        self.pending_snapshot_transfer = Some(plan);
        Response::ok(Value::Null)
    }

    fn revalidate_native_snapshot_ha_leader(&mut self) -> Result<(), Response> {
        let Some(ha) = self.ha.clone() else {
            return Ok(());
        };
        // Drop each HA guard before synchronization: that path takes the same
        // control lock and performs an authenticated, deadline-bound ReadIndex.
        if !ha
            .lock_for_request()
            .map_err(|_| Response::error(503, "snapshot HA authority unavailable"))?
            .is_leader()
            .unwrap_or(false)
        {
            return Err(Response::error(503, "snapshot HA leader changed"));
        }
        self.sync_from_ha_with_anchor(false)?;
        if !ha
            .lock_for_request()
            .map_err(|_| Response::error(503, "snapshot HA authority unavailable"))?
            .is_leader()
            .unwrap_or(false)
        {
            return Err(Response::error(503, "snapshot HA leader changed"));
        }
        Ok(())
    }

    // Snapshot owns its capsule until terminal clock persistence, mandatory
    // audit and the final original-Actor/selection check have all completed.
    pub(super) fn complete_snapshot_transfer(
        &mut self,
        mut plan: SnapshotTransferPlan,
        result: Result<Observation, Response>,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
    ) -> Response {
        let response = self.finalize_snapshot_transfer(&mut plan, result);
        #[cfg(feature = "native-v6-ha")]
        let mut response = if plan.native_ha_restored.is_some() {
            self.complete_native_ha_historical_delivery(&plan, response, fingerprint, clock)
        } else if plan.native_ha_source.is_some() {
            self.complete_native_ha_snapshot_delivery(&plan, response, fingerprint, clock)
        } else if plan.path == crate::engines::kv2_lossless_export::PATH {
            self.complete_native_kv2_lossless_delivery(&plan, response, fingerprint, clock)
        } else {
            self.audit_completed_response(fingerprint, clock.0, clock.1, response)
        };
        #[cfg(all(feature = "native-v6-storage", not(feature = "native-v6-ha")))]
        let response = if plan.path == crate::engines::kv2_lossless_export::PATH {
            self.complete_native_kv2_lossless_delivery(&plan, response, fingerprint, clock)
        } else {
            self.audit_completed_response(fingerprint, clock.0, clock.1, response)
        };
        #[cfg(not(feature = "native-v6-storage"))]
        let response = self.audit_completed_response(fingerprint, clock.0, clock.1, response);
        #[cfg(feature = "native-v6-ha")]
        if let Some((operation, root_attempted)) = plan.native_ha_restore_attempt {
            // A committed Begin or uncertain root CAS remains identifiable
            // even if the generic failure audit overwrites its first response.
            // These bytes grant no restore, retry or current-read authority.
            if let Some(body) = response.body.as_object_mut() {
                body.insert(
                    "recovery_reference".into(),
                    json!(format!("native-v6-restore-{}", hex(&operation))),
                );
                body.insert("root_attempted".into(), json!(root_attempted));
                body.insert("retry_allowed".into(), json!(false));
            }
        }
        #[cfg(feature = "native-v6-ha")]
        if let Some(operation) = plan
            .native_ha_pending_restore
            .and_then(PendingRestoreRequest::operation)
        {
            // Cancellation delivery can also be uncertain after an actual
            // Raft write. Retain its exact query reference even when terminal
            // clock or mandatory audit replaces the original response.
            if let Some(body) = response.body.as_object_mut() {
                body.insert(
                    "recovery_reference".into(),
                    json!(format!("native-v6-restore-{}", hex(&operation))),
                );
                body.insert("restore_performed".into(), json!(false));
                body.insert("retry_allowed".into(), json!(false));
            }
        }
        #[cfg(feature = "native-v6-storage")]
        self.retire_native_external_binding(fingerprint, clock.1);
        response
    }

    #[cfg(feature = "native-v6-storage")]
    pub(super) fn native_ha_snapshot_transport_enabled(&self) -> bool {
        #[cfg(feature = "native-v6-ha")]
        if self.native_root.is_some()
            && self.native_candidate_profile.is_none()
            && self.ha.as_ref().is_some_and(|ha| {
                ha.lock_for_request()
                    .is_ok_and(|process| process.native_v6_enabled())
            })
        {
            return true;
        }
        false
    }

    pub(super) fn finalize_snapshot_transfer(
        &mut self,
        plan: &mut SnapshotTransferPlan,
        result: Result<Observation, Response>,
    ) -> Response {
        #[cfg(feature = "native-v6-storage")]
        {
            if self.native_request_binding.is_some() || self.native_failure_notice.is_some() {
                self.recovery_required = true;
                return Response::error(
                    503,
                    "snapshot completion found unrelated native request custody",
                );
            }
            self.native_request_binding = plan.native_request_binding.take();
        }
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        if Instant::now() >= plan.deadline {
            return Response::error(503, "snapshot transfer deadline elapsed");
        }
        let same_ha = match (&plan.ha, &self.ha) {
            (None, None) => true,
            (Some(previous), Some(current)) => Arc::ptr_eq(previous, current),
            _ => false,
        };
        if !same_ha {
            return Response::error(409, "snapshot HA transfer authority changed");
        }
        if self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || self.unseal_nonce != plan.activation
        {
            return Response::error(409, "snapshot transfer authority changed");
        }
        #[cfg(feature = "native-v6-ha")]
        if plan.native_ha_repair.is_some() {
            // Normal HA synchronization first pulls the missing shared leaves.
            // This dedicated owner independently verifies the actual selection
            // and its complete local Auth graph before repairing those leaves.
            return self.finish_native_ha_snapshot_repair(plan, result);
        }
        #[cfg(feature = "native-v6-ha")]
        if plan.native_ha_pending_restore.is_some() {
            return self.finish_native_ha_pending_restore_reconciliation(plan, result);
        }
        #[cfg(feature = "native-v6-ha")]
        if plan.native_ha_restore_source.is_some() {
            // Restore owns the original exact local/Actor/ReadIndex anchor.
            // The new epoch is derived by actual Raft; it is not a local
            // restore of captured consensus or replay-ledger bytes.
            return self.finish_native_ha_historical_upload(plan, result);
        }
        let authority = if plan.standby_read {
            #[cfg(feature = "native-v6-ha")]
            {
                if !matches!(
                    plan.path.as_str(),
                    "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
                ) || plan.native_ha_source.is_none()
                {
                    return Response::error(
                        503,
                        "standby snapshot original read proof is unavailable",
                    );
                }
                self.sync_from_ha_with_anchor(false)
            }
            #[cfg(not(feature = "native-v6-ha"))]
            {
                Err(Response::error(
                    503,
                    "standby snapshot requires native HA read proof",
                ))
            }
        } else {
            self.revalidate_native_snapshot_ha_leader()
        };
        if let Err(response) = authority {
            return response;
        }
        if Instant::now() >= plan.deadline {
            return Response::error(503, "snapshot transfer deadline elapsed");
        }
        // ReadIndex can spend the remaining request budget. Revalidate actor
        // expiry using the clock after that wait, never its admission time.
        let now = snapshot_observed_time(plan.now, plan.started.elapsed());
        if self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || self.unseal_nonce != plan.activation
            || self.current_state_identity().ok() != Some(plan.base)
        {
            return Response::error(409, "snapshot transfer authority changed");
        }
        let Some(state) = self.state.as_ref() else {
            return Response::error(503, "server is sealed");
        };
        if let Err(error) = state.auth.authorize_request(
            &plan.actor,
            &plan.namespace,
            &plan.path,
            if plan.is_download { "read" } else { "update" },
            now,
        ) {
            return Response::error(error.status, &error.message);
        }
        let live_seal = match self.current_snapshot_seal_identity_for_plan(plan) {
            Ok(value) => value,
            Err(response) => return response,
        };
        if live_seal != plan.seal_identity {
            return Response::error(409, "snapshot transfer seal identity changed");
        }
        let observation = match result {
            Ok(value) => value,
            Err(error) => return error,
        };
        match observation {
            Observation::Download if plan.is_download => {
                #[cfg(feature = "native-v6-ha")]
                if plan.native_ha_source.is_some() {
                    return self.finish_native_ha_snapshot_download(plan);
                }
                Response::ok(Value::Null)
            }
            Observation::Upload(mut imported) if !plan.is_download => {
                if plan.standby_read {
                    // Actual local parsing precedes the forwarding decision,
                    // as on an OpenBao 2.7.1 read-enabled standby. A validated
                    // archive is still only data: this branch never reaches a
                    // restore writer, Begin, epoch change or publication.
                    return match self.native_snapshot_destination() {
                        Ok(Some(origin)) => Response {
                            unwrapped_json: None,
                            response_headers: ResponseHeaders::validated_snapshot_redirect(origin),
                            consistency_index: None,
                            status: 307,
                            body: Value::Null,
                        },
                        Ok(None) => {
                            Response::error(503, "HA role changed during snapshot validation")
                        }
                        Err(error) => error,
                    };
                }
                #[cfg(feature = "native-v6-storage")]
                if self.native_root.is_some() && !imported.metadata.is_v6() {
                    // The V5 installer cannot retire V6 external-object custody.
                    return Response::error(
                        409,
                        "active V6 requires an object-complete V6 snapshot",
                    );
                }
                #[cfg(feature = "native-v6-storage")]
                if imported.metadata.is_v6() {
                    return self.finish_v6_snapshot_upload(imported, plan, live_seal);
                }
                let result = (|| -> Result<backup_restore::PreparedSnapshotRestore, Response> {
                    let binding = imported.metadata.seal_identity().ok_or_else(|| {
                        Response::error(
                            400,
                            "native snapshot v1 has no seal binding; restore is unsupported",
                        )
                    })?;
                    let key = self
                        .barrier_key
                        .as_ref()
                        .ok_or_else(|| Response::error(503, "server is sealed"))?;
                    let barrier = AeadBarrier::new(**key)
                        .map_err(|_| Response::error(503, "snapshot seal unavailable"))?;
                    let opened = Zeroizing::new(
                        barrier
                            .open(snapshot_archive::CHECKSUM_CONTEXT, &imported.sealed_sums)
                            .map_err(|_| {
                                Response::error(400, "snapshot checksum authentication failed")
                            })?,
                    );
                    if opened.as_slice() != imported.sums.as_slice() {
                        return Err(Response::error(
                            400,
                            "snapshot authenticated checksums differ",
                        ));
                    }
                    if !binding.matches(&live_seal) {
                        return Err(Response::error(
                            400,
                            if plan.path == "sys/storage/raft/snapshot-force" {
                                "cross-seal native snapshot force restore is unsupported"
                            } else {
                                "native snapshot seal identity differs"
                            },
                        ));
                    }
                    let length = imported.state.len();
                    let prepared =
                        self.prepare_snapshot_restore_from_reader(&mut imported.state, length)?;
                    if prepared.generation() != imported.metadata.generation() {
                        return Err(Response::error(400, "snapshot metadata generation differs"));
                    }
                    if Instant::now() >= plan.deadline {
                        return Err(Response::error(
                            503,
                            "snapshot restore preparation exceeded deadline",
                        ));
                    }
                    Ok(prepared)
                })();
                let prepared = match result {
                    Ok(value) => value,
                    Err(error) => return error,
                };
                let body = json!({});
                let now = snapshot_observed_time(plan.now, plan.started.elapsed());
                let request = RequestView {
                    method: "POST",
                    path: &plan.path,
                    namespace: &plan.namespace,
                    token: "",
                    body: &body,
                    now,
                    admission_started: Instant::now(),
                    token_clock: None,
                    allow_forward: false,
                    enforce_namespace: true,
                    wrap_ttl_seconds: None,
                    origin_peer: None,
                    client_certificates: None,
                };
                self.commit_native_snapshot_restore(
                    VerifiedNativeRestore {
                        prepared,
                        clock: (plan.now, plan.started),
                    },
                    &plan.actor,
                    &request,
                )
            }
            _ => Response::error(503, "snapshot transfer observation mismatch"),
        }
    }
}

#[cfg(test)]
#[path = "service_snapshot_transfer_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service_snapshot_ha_tests.rs"]
mod ha_tests;

#[cfg(test)]
#[path = "service_snapshot_redirect_tests.rs"]
mod redirect_tests;

// Append to authentic Source825 service_snapshot_transfer.rs, not production
// HTTP routing. The normal before/stream importer/metadata-check sequence is
// retained; this private cfg(test) seam returns only the native parser's affine
// validated candidate just before the writer final commit.
#[cfg(all(test, target_os = "linux"))]
impl Service {
    pub(super) fn fixture_begin_native_snapshot_upload(
        &mut self,
        request: ServiceRequest<'_>,
        deadline: Instant,
    ) -> Result<PendingExternalRequest, Response> {
        self.fixture_require_live_recovery_wrapper()?;
        if request.method != "POST"
            || request.path != "sys/storage/raft/snapshot"
            || !request.namespace.is_empty()
        {
            return Err(Response::error(
                400,
                "fixture requires the real local native snapshot upload route",
            ));
        }
        match self.begin_native_snapshot_before(request, deadline) {
            NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(*pending),
            NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => Err(response),
            NativeSnapshotAdmission::Redirect(_) => Err(Response::error(
                501,
                "fixture refuses a redirected native upload",
            )),
        }
    }

    // Call PendingExternalRequest::execute_snapshot_transfer(actual_archive_reader)
    // once outside the Service writer, preserving its actual raw archive. No
    // JSON, prepared State, checksum, binding, base identity or generation is
    // supplied through this interface and no caller can construct Verified.
    pub(super) fn fixture_prepare_verified_native_restore(
        &mut self,
        pending: PendingExternalRequest,
        observed: ExternalEffectResult,
    ) -> Result<VerifiedNativeRestore, Response> {
        let (plan, result) = match (pending.effect, observed) {
            (
                ExternalEffectPlan::SnapshotTransfer(plan),
                ExternalEffectResult::SnapshotTransfer(result),
            ) => (*plan, result),
            _ => {
                return Err(Response::error(
                    503,
                    "fixture native transport observation mismatch",
                ));
            }
        };
        if plan.is_download {
            return Err(Response::error(
                400,
                "fixture requires an actual native upload",
            ));
        }
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        if Instant::now() >= plan.deadline {
            return Err(Response::error(503, "snapshot transfer deadline elapsed"));
        }
        let same_ha = match (&plan.ha, &self.ha) {
            (None, None) => true,
            (Some(previous), Some(current)) => Arc::ptr_eq(previous, current),
            _ => false,
        };
        if !same_ha {
            return Err(Response::error(
                409,
                "snapshot HA transfer authority changed",
            ));
        }
        if self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || self.unseal_nonce != plan.activation
        {
            return Err(Response::error(409, "snapshot transfer authority changed"));
        }
        self.revalidate_native_snapshot_ha_leader()?;
        if Instant::now() >= plan.deadline {
            return Err(Response::error(503, "snapshot transfer deadline elapsed"));
        }
        // ReadIndex can spend the remaining request budget. Revalidate actor
        // expiry using the clock after that wait, never its admission time.
        let now = snapshot_observed_time(plan.now, plan.started.elapsed());
        if self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || self.unseal_nonce != plan.activation
            || self.current_state_identity().ok() != Some(plan.base)
        {
            return Err(Response::error(409, "snapshot transfer authority changed"));
        }
        let Some(state) = self.state.as_ref() else {
            return Err(Response::error(503, "server is sealed"));
        };
        if let Err(error) = state.auth.authorize_request(
            &plan.actor,
            &plan.namespace,
            &plan.path,
            if plan.is_download { "read" } else { "update" },
            now,
        ) {
            return Err(Response::error(error.status, &error.message));
        }
        let live_seal = self.current_snapshot_seal_identity_for_plan(&plan)?;
        if live_seal != plan.seal_identity {
            return Err(Response::error(
                409,
                "snapshot transfer seal identity changed",
            ));
        }
        let mut imported = match result {
            Ok(Observation::Upload(value)) => value,
            Ok(_) => {
                return Err(Response::error(
                    503,
                    "fixture native upload observation mismatch",
                ));
            }
            Err(error) => return Err(error),
        };
        let result = (|| -> Result<backup_restore::PreparedSnapshotRestore, Response> {
            let binding = imported.metadata.seal_identity().ok_or_else(|| {
                Response::error(
                    400,
                    "native snapshot v1 has no seal binding; restore is unsupported",
                )
            })?;
            let key = self
                .barrier_key
                .as_ref()
                .ok_or_else(|| Response::error(503, "server is sealed"))?;
            let barrier = AeadBarrier::new(**key)
                .map_err(|_| Response::error(503, "snapshot seal unavailable"))?;
            let opened = Zeroizing::new(
                barrier
                    .open(snapshot_archive::CHECKSUM_CONTEXT, &imported.sealed_sums)
                    .map_err(|_| Response::error(400, "snapshot checksum authentication failed"))?,
            );
            if opened.as_slice() != imported.sums.as_slice() {
                return Err(Response::error(
                    400,
                    "snapshot authenticated checksums differ",
                ));
            }
            if !binding.matches(&live_seal) {
                return Err(Response::error(
                    400,
                    if plan.path == "sys/storage/raft/snapshot-force" {
                        "cross-seal native snapshot force restore is unsupported"
                    } else {
                        "native snapshot seal identity differs"
                    },
                ));
            }
            let length = imported.state.len();
            let prepared =
                self.prepare_snapshot_restore_from_reader(&mut imported.state, length)?;
            if prepared.generation() != imported.metadata.generation() {
                return Err(Response::error(400, "snapshot metadata generation differs"));
            }
            if Instant::now() >= plan.deadline {
                return Err(Response::error(
                    503,
                    "snapshot restore preparation exceeded deadline",
                ));
            }
            Ok(prepared)
        })();
        let prepared = result?;
        Ok(VerifiedNativeRestore {
            prepared,
            clock: (plan.now, plan.started),
        })
    }
}
