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

#[cfg(feature = "fixture-native-v6-service")]
#[path = "service_snapshot_v6.rs"]
mod v6;

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
    deadline: Instant,
    started: Instant,
    now: Duration,
    lease: Arc<SnapshotLease>,
    download: Option<DownloadSource>,
    is_download: bool,
    // Native negative-outcome custody belongs to this pending request, not
    // the idle Service. Dropping a cancelled transfer must not poison the
    // next unrelated request; finalization restores exactly the original one.
    #[cfg(feature = "fixture-native-v6-service")]
    native_request_binding: Option<native_v6_writer::NativeRequestBinding>,
    #[cfg(feature = "experimental-native-v6-ha")]
    native_ha_source: Option<native_v6_ha_install::NativeHaReadProof>,
    #[cfg(feature = "experimental-native-v6-ha")]
    native_ha_repair: Option<native_v6_ha_install::NativeHaArchiveRepairSource>,
    #[cfg(feature = "experimental-native-v6-ha")]
    native_ha_restore_source: Option<native_v6_ha_install::NativeHaArchiveRepairSource>,
    #[cfg(feature = "experimental-native-v6-ha")]
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

fn canonical_seal_identity(seal: &SealMetadata) -> Result<[u8; 32], &'static str> {
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
}

// Retain the wall-clock fraction captured at admission. Rounding only after
// adding monotonic elapsed time avoids expiring one-second leases early and
// does not consult a wall clock that could have moved backward during I/O.
fn snapshot_observed_time(wall_anchor: Duration, elapsed: Duration) -> u64 {
    wall_anchor.saturating_add(elapsed).as_secs()
}

impl PendingExternalRequest {
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
                    .map_err(|_| Response::error(400, "invalid native snapshot archive"))
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
        if !matches!(
            request.path,
            "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force" | NATIVE_HA_REPAIR_PATH
        ) {
            erase_json(&mut request.body);
            return NativeSnapshotAdmission::Execute(RequestExecution::Complete(Response::error(
                400,
                "invalid native snapshot route",
            )));
        }
        // This is before authentication/finite-use persistence, staging and
        // JSON HA forwarding. The receiving leader independently authorizes
        // the original request; observing a leader never grants authority.
        match self.native_snapshot_destination() {
            Ok(Some(origin)) => {
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
            Err(response) => {
                erase_json(&mut request.body);
                return NativeSnapshotAdmission::Execute(RequestExecution::Complete(response));
            }
            Ok(None) => {}
        }
        // Pair wall time and the monotonic anchor before reconciliation, audit,
        // authentication and finite-use persistence can spend admission time.
        let started = Instant::now();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let previous_clock = self.native_snapshot_clock.replace((started, now));
        let previous = self.native_snapshot_transport;
        self.native_snapshot_transport = true;
        let result = self.begin_request_before(request, deadline, false);
        self.native_snapshot_transport = previous;
        self.native_snapshot_clock = previous_clock;
        NativeSnapshotAdmission::Execute(result)
    }

    fn native_snapshot_destination(&self) -> Result<Option<TrustedSnapshotOrigin>, Response> {
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

    pub(super) fn stage_snapshot_transfer(
        &mut self,
        actor: Principal,
        request: &RequestView<'_>,
    ) -> Response {
        if !request.namespace.is_empty()
            || request
                .body
                .as_object()
                .is_none_or(|object| !object.is_empty())
        {
            return Response::error(
                400,
                "native snapshot requires the root namespace and no query fields",
            );
        }
        let Some((started, now)) = self.native_snapshot_clock else {
            return Response::error(503, "snapshot admission clock unavailable");
        };
        if now.as_secs() != request.now {
            return Response::error(503, "snapshot admission clock differs");
        }
        let download =
            request.path == "sys/storage/raft/snapshot" && matches!(request.method, "GET" | "HEAD");
        let repair = request.path == NATIVE_HA_REPAIR_PATH;
        if !download && !matches!(request.method, "POST" | "PUT") {
            return Response::error(405, "snapshot restore requires POST or PUT");
        }
        if !download && !repair
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
            deadline,
            started,
            now,
            lease: Arc::clone(&lease),
            download: None,
            is_download: download,
            #[cfg(feature = "fixture-native-v6-service")]
            native_request_binding: None,
            #[cfg(feature = "experimental-native-v6-ha")]
            native_ha_source: None,
            #[cfg(feature = "experimental-native-v6-ha")]
            native_ha_repair: None,
            #[cfg(feature = "experimental-native-v6-ha")]
            native_ha_restore_source: None,
            #[cfg(feature = "experimental-native-v6-ha")]
            native_ha_restored: None,
        };
        let source = if download {
            let result = (|| -> Result<DownloadSource, Response> {
                #[cfg(feature = "fixture-native-v6-service")]
                if self.native_root.is_some() {
                    return self.prepare_v6_snapshot_download(&mut plan);
                }
                #[cfg(feature = "fixture-native-v6-service")]
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
        #[cfg(feature = "experimental-native-v6-ha")]
        if !download && self.native_ha_snapshot_transport_enabled()
            && plan.path == "sys/storage/raft/snapshot"
            && let Err(error) = self.prepare_native_ha_historical_upload(&mut plan)
        {
            return error;
        }
        #[cfg(feature = "fixture-native-v6-service")]
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
        #[cfg(feature = "experimental-native-v6-ha")]
        let response = if plan.native_ha_restored.is_some() {
            self.complete_native_ha_historical_delivery(&plan, response, fingerprint, clock)
        } else if plan.native_ha_source.is_some() {
            self.complete_native_ha_snapshot_delivery(&plan, response, fingerprint, clock)
        } else {
            self.audit_completed_response(fingerprint, clock.0, clock.1, response)
        };
        #[cfg(not(feature = "experimental-native-v6-ha"))]
        let response = self.audit_completed_response(fingerprint, clock.0, clock.1, response);
        #[cfg(feature = "fixture-native-v6-service")]
        self.retire_native_external_binding(fingerprint, clock.1);
        response
    }

    #[cfg(feature = "fixture-native-v6-service")]
    pub(super) fn native_ha_snapshot_transport_enabled(&self) -> bool {
        #[cfg(feature = "experimental-native-v6-ha")]
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
        #[cfg(feature = "fixture-native-v6-service")]
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
        #[cfg(feature = "experimental-native-v6-ha")]
        if plan.native_ha_repair.is_some() {
            // Normal HA synchronization first pulls the missing shared leaves.
            // This dedicated owner independently verifies the actual selection
            // and its complete local Auth graph before repairing those leaves.
            return self.finish_native_ha_snapshot_repair(plan, result);
        }
        #[cfg(feature = "experimental-native-v6-ha")]
        if plan.native_ha_restore_source.is_some() {
            // Restore owns the original exact local/Actor/ReadIndex anchor.
            // The new epoch is derived by actual Raft; it is not a local
            // restore of captured consensus or replay-ledger bytes.
            return self.finish_native_ha_historical_upload(plan, result);
        }
        if let Err(response) = self.revalidate_native_snapshot_ha_leader() {
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
                #[cfg(feature = "experimental-native-v6-ha")]
                if plan.native_ha_source.is_some() {
                    return self.finish_native_ha_snapshot_download(plan);
                }
                Response::ok(Value::Null)
            }
            Observation::Upload(mut imported) if !plan.is_download => {
                #[cfg(feature = "fixture-native-v6-service")]
                if self.native_root.is_some() && !imported.metadata.is_v6() {
                    // The V5 installer cannot retire V6 external-object custody.
                    return Response::error(
                        409,
                        "active V6 requires an object-complete V6 snapshot",
                    );
                }
                #[cfg(feature = "fixture-native-v6-service")]
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
            Ok(Observation::Download) => {
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
