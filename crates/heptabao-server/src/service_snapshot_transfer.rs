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

pub(super) struct SnapshotTransferPlan {
    actor: Principal,
    path: String,
    namespace: String,
    activation: String,
    seal_identity: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
    base: StateIdentity,
    deadline: Instant,
    started: Instant,
    now: Duration,
    lease: Arc<SnapshotLease>,
    download: Option<DownloadSource>,
    is_download: bool,
}
// Only this module can construct the capability, after native archive and
// live-seal authentication. It contains the exact validated restore candidate.
pub(super) struct VerifiedNativeRestore {
    prepared: backup_restore::PreparedSnapshotRestore,
}
impl VerifiedNativeRestore {
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
    fn current_snapshot_seal_identity(
        &self,
        lease: &SnapshotLease,
        deadline: Instant,
    ) -> Result<[u8; 32], Response> {
        let bytes = lease
            .read_seal_metadata(deadline)
            .map_err(|_| Response::error(503, "snapshot seal metadata is unavailable"))?;
        let seal: SealMetadata = serde_json::from_slice(&bytes)
            .map_err(|_| Response::error(503, "snapshot seal metadata is invalid"))?;
        if self.seal.as_ref() != Some(&seal) {
            return Err(Response::error(409, "snapshot seal metadata changed"));
        }
        canonical_seal_identity(&seal)
            .map_err(|_| Response::error(503, "snapshot seal metadata is invalid"))
    }

    pub(crate) fn begin_native_snapshot_before(
        &mut self,
        request: ServiceRequest<'_>,
        deadline: Instant,
    ) -> RequestExecution {
        if !matches!(
            request.path,
            "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
        ) {
            return RequestExecution::Complete(Response::error(
                400,
                "invalid native snapshot route",
            ));
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
        result
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
        if !download && !matches!(request.method, "POST" | "PUT") {
            return Response::error(405, "snapshot restore requires POST or PUT");
        }
        if !download
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
        let seal_identity = match self.current_snapshot_seal_identity(&lease, deadline) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let source = if download {
            let result = (|| -> Result<DownloadSource, Response> {
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
        self.pending_snapshot_transfer = Some(SnapshotTransferPlan {
            actor,
            path: request.path.to_owned(),
            namespace: request.namespace.to_owned(),
            activation: self.unseal_nonce.clone(),
            seal_identity,
            ha: self.ha.clone(),
            base,
            deadline,
            started,
            now,
            lease,
            download: source,
            is_download: download,
        });
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

    pub(super) fn finalize_snapshot_transfer(
        &mut self,
        plan: SnapshotTransferPlan,
        result: Result<Observation, Response>,
    ) -> Response {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        if Instant::now() >= plan.deadline {
            return Response::error(503, "snapshot transfer deadline elapsed");
        }
        let same_ha = match (&plan.ha, &self.ha) {
            (None, None) => true,
            (Some(previous), Some(current)) => Arc::ptr_eq(previous, current),
            _ => false,
        };
        if !same_ha || (self.ha.is_some() && !plan.is_download) {
            return Response::error(409, "snapshot HA transfer authority changed");
        }
        if self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || self.unseal_nonce != plan.activation
        {
            return Response::error(409, "snapshot transfer authority changed");
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
        let live_seal = match self.current_snapshot_seal_identity(&plan.lease, plan.deadline) {
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
            Observation::Download if plan.is_download => Response::ok(Value::Null),
            Observation::Upload(mut imported) if !plan.is_download => {
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
                    allow_forward: false,
                    enforce_namespace: true,
                    wrap_ttl_seconds: None,
                    origin_peer: None,
                    client_certificates: None,
                };
                self.commit_native_snapshot_restore(
                    VerifiedNativeRestore { prepared },
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
