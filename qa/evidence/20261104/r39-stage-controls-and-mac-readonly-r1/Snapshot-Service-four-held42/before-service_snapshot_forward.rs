//! Native snapshot forwarding owns its original request, original Auth view,
//! private files and the one authenticated peer exchange through final audit.
//! No ordinary JSON completion or retained-KV exception authorizes this path.
use super::*;
use heptabao_ha_service::{
    SnapshotBodyLimits, SnapshotPeerResponse, VerifiedSnapshotBody,
};
use heptabao_raft_runtime::{ApplicationReadWitness, CommittedApplicationPrefix};
use std::io;

#[path = "service_snapshot_forward_wire.rs"]
mod wire;
#[path = "service_snapshot_forward_file.rs"]
mod file;
#[path = "service_snapshot_forward_client.rs"]
mod client;
#[path = "service_snapshot_forward_source.rs"]
mod source;

pub(crate) use client::SnapshotForwardPlan;

pub(super) fn unavailable() -> Response {
    Response::error(503, "native snapshot forwarding requires reconciliation")
}
fn live(deadline: Instant) -> Result<(), Response> {
    if Instant::now() >= deadline
        || crate::request_deadline::current().is_some_and(|bound| Instant::now() >= bound)
    {
        return Err(unavailable());
    }
    Ok(())
}

/// Selection is data-only and happens before original Actor admission.
/// Explicit no-forward, query operations, repair and non-native profiles keep
/// the original local redirect path; they cannot enter the binary protocol.
pub(super) fn eligible(request: &ServiceRequest<'_>) -> Result<bool, Response> {
    let operation = matches!(
        (request.method, request.path),
        ("GET" | "HEAD", "sys/storage/raft/snapshot")
            | ("POST" | "PUT", "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force")
    );
    let logical = crate::request_metadata::current(
        request.method, request.path, request.namespace, &request.body,
    ).map_err(|_| unavailable())?;
    Ok(operation
        && request.namespace.is_empty()
        && request.body.as_object().is_some_and(serde_json::Map::is_empty)
        && request.wrap_ttl_seconds.is_none_or(|ttl| ttl == 0)
        && logical.as_ref().is_none_or(|data| !data.no_request_forwarding()))
}

/// Actual local filesystem and Service owner. Epoch installation may only be
/// performed by the existing native synchronizer; it cannot replace these pins.
struct LocalOwner {
    ha: Arc<Mutex<HaProcess>>,
    lease: Arc<SnapshotLease>,
    barrier: [u8; 32],
    seal_identity: [u8; 32],
    seal_metadata: SealMetadata,
    seal_bytes: Zeroizing<Vec<u8>>,
    deadline: Instant,
}
impl LocalOwner {
    fn capture(service: &mut Service, deadline: Instant) -> Result<Self, Response> {
        live(deadline)?;
        if !service.native_ha_snapshot_transport_enabled() {
            return Err(unavailable());
        }
        let ha = service.ha.as_ref().ok_or_else(unavailable)?.clone();
        let spool = match service.snapshot_spool.as_ref() {
            Some(spool) => Arc::clone(spool),
            None => {
                let spool = SnapshotSpool::open(&service.data_dir).map_err(|_| unavailable())?;
                service.snapshot_spool = Some(Arc::clone(&spool));
                spool
            }
        };
        let lease = spool.lease().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                Response::error(429, "snapshot transfer is already active")
            } else {
                unavailable()
            }
        })?;
        let (seal_identity, seal_metadata, seal_bytes) =
            service.current_snapshot_seal_identity_and_raw(&lease, deadline)?;
        let barrier = wire::digest(service.barrier_key.as_ref().ok_or_else(unavailable)?.as_slice());
        let result = Self { ha, lease, barrier, seal_identity, seal_metadata, seal_bytes, deadline };
        result.check(service)?;
        Ok(result)
    }

    fn check(&self, service: &Service) -> Result<(), Response> {
        live(self.deadline)?;
        if service.ha.as_ref().is_none_or(|ha| !Arc::ptr_eq(ha, &self.ha))
            || service.state.is_none()
            || service.native_root.is_none()
            || service.record_root.is_some()
            || service.postgres_durable.is_some()
            || service.durable_profile.is_some()
            || service.openbao_wrapper_owner.is_some()
            || service.native_candidate_profile.is_some()
            || service.recovery_required
            || service.audit_failed
            || service.durable.as_ref().is_none_or(|store| store.recovery_required())
            || service.barrier_key.as_ref().is_none_or(|key| wire::digest(key.as_slice()) != self.barrier)
        {
            return Err(unavailable());
        }
        let bytes = self.lease.read_seal_metadata(self.deadline).map_err(|_| unavailable())?;
        if Service::snapshot_seal_identity_checked_against_admission(
            &bytes, &self.seal_bytes, &self.seal_metadata, service.seal.as_ref(), self.seal_identity,
        )? != self.seal_identity {
            return Err(unavailable());
        }
        live(self.deadline)
    }

    fn key<'a>(&self, service: &'a Service) -> Result<&'a [u8], Response> {
        self.check(service)?;
        Ok(service.barrier_key.as_ref().ok_or_else(unavailable)?.as_slice())
    }
}

fn authority_time(clock: RequestClock) -> Result<AuthorityTime, Response> {
    clock.observed_at().map(AuthorityTime::Precise).map_err(|_| unavailable())
}

fn original_actor(
    auth: &AuthState, actor: &crate::auth::ForwardActorWitness,
    clock: RequestClock, deadline: Instant,
) -> Result<(), Response> {
    live(deadline)?;
    auth.validate_snapshot_forward_actor(actor, authority_time(clock)?)
        .map_err(|error| Response::error(error.status, &error.message))?;
    live(deadline)
}

fn source_key(service: &Service) -> Result<&[u8], Response> {
    if service.recovery_required || service.audit_failed || !service.ha_activation_permitted()
        || service.durable.as_ref().is_none_or(|store| store.recovery_required())
    {
        return Err(unavailable());
    }
    Ok(service.barrier_key.as_ref().ok_or_else(unavailable)?.as_slice())
}

/// Actual ReadIndex, typed full local materialization and prefix are distinct.
/// This helper obtains both from this Service, preserving the original Actor
/// and deadline around every blocking/native read.
fn fresh_native(
    service: &mut Service,
    ha: &Arc<Mutex<HaProcess>>,
    auth: &AuthState,
    actor: &crate::auth::ForwardActorWitness,
    clock: RequestClock,
    deadline: Instant,
) -> Result<(StateIdentity, ApplicationReadWitness), Response> {
    original_actor(auth, actor, clock, deadline)?;
    let proof = service.capture_native_ha_request_proof(
        &mut || original_actor(auth, actor, clock, deadline),
    )?.ok_or_else(unavailable)?;
    proof.check_with(service, Service::check_native_installed)?;
    original_actor(auth, actor, clock, deadline)?;
    let identity = service.current_state_identity()?;
    let (observed, witness) = ha.lock_for_request().map_err(|_| unavailable())?
        .application_identity_witness_for_local_root(identity).map_err(|_| unavailable())?;
    if observed != identity || proof.identity() != identity {
        return Err(unavailable());
    }
    original_actor(auth, actor, clock, deadline)?;
    Ok((identity, witness))
}

fn sync_prefix(
    service: &mut Service, owner: &LocalOwner, admission: &wire::AdmissionData,
    prefix: &CommittedApplicationPrefix,
) -> Result<(), Response> {
    owner.check(service)?;
    owner.ha.lock_for_request().map_err(|_| unavailable())?
        .wait_snapshot_prefix(
            &admission.cluster, admission.leader, admission.ingress, prefix, owner.deadline,
        ).map_err(|_| unavailable())?;
    let progress = service.sync_from_ha_with_anchor_progress(false)?;
    service.continue_forward_local_sync(progress, owner.deadline)?;
    owner.check(service)
}

fn floor_covers(service: &Service, data: &wire::CompletionData) -> bool {
    service.state.as_ref().is_some_and(|state| {
        matches!((state.auth.terminal_token_clock_floor(), data.floor),
            (Some(current), Some(original)) if current >= original)
            || state.auth.terminal_token_clock_floor().is_none() && data.floor.is_none()
    })
}

fn failed_delivery(
    service: &mut Service, fingerprint: &str, now: u64, mut error: Response,
    audit_veto: impl FnOnce() -> Response,
) -> Response {
    if service.audit_event("native-snapshot-forward-delivery-veto", fingerprint, now, Some(error.status)).is_err() {
        erase_json(&mut error.body);
        service.recovery_required = true;
        service.ha_activation = None;
        service.ha_read_cache = None;
        // The caller supplies a fixed conservative or already authenticated
        // failure. No field of the discarded response grants root authority.
        return audit_veto();
    }
    error
}
