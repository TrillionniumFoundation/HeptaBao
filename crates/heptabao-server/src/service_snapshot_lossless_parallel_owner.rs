//! Immutable borrows from the actual standalone snapshot owner. This view
//! cannot outlive either Service or its affine plan and cannot publish, clone
//! an Actor, recapture a source, or authorize a later request.
use super::*;
use crate::auth::AuthState;
use crate::state_record_root_v6::{NativeRootContentIdentity, RecordStateRootV6};

pub(super) struct SnapshotReadOwner<'a> {
    audit_failed: &'a bool,
    recovery_required: &'a bool,
    barrier_live: bool,
    unseal_nonce: &'a str,
    profile: &'a native_v6_reader::NativeCandidateProfile,
    data_dir: &'a std::path::Path,
    ha_present: bool,
    postgres_present: bool,
    durable_profile_present: bool,
    wrapper_present: bool,
    auth: &'a AuthState,
    digest: &'a Option<[u8; 32]>,
    native_root: &'a RecordStateRootV6,
    current_seal: &'a Option<SealMetadata>,
    actor: &'a Principal,
    path: &'a str,
    namespace: &'a str,
    activation: &'a str,
    base: &'a StateIdentity,
    native_root_contents: &'a Option<NativeRootContentIdentity>,
    plan_ha_present: bool,
    deadline: &'a Instant,
    started: &'a Instant,
    now: &'a Duration,
    seal_reader: crate::snapshot_file::SnapshotSealReader<'a>,
    admitted_seal: &'a SealMetadata,
    admitted_bytes: &'a [u8],
    seal_identity: &'a [u8; 32],
}
impl<'a> SnapshotReadOwner<'a> {
    pub(super) fn new(
        service: &'a Service,
        plan: &'a SnapshotTransferPlan,
    ) -> Result<Self, Response> {
        service.check_v6_snapshot_owner(plan)?;
        if !plan.is_download || service.record_root.is_some() {
            return Err(unavailable());
        }
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let native_root = service.native_root.as_ref().ok_or_else(unavailable)?;
        if native_root.reader_floor.native_kv2_format != 2 {
            return Err(unavailable());
        }
        let view = Self {
            audit_failed: &service.audit_failed,
            recovery_required: &service.recovery_required,
            barrier_live: service.barrier_key.is_some(),
            unseal_nonce: &service.unseal_nonce,
            profile: service
                .native_candidate_profile
                .as_ref()
                .ok_or_else(unavailable)?,
            data_dir: &service.data_dir,
            // These Option presences cannot change while this method's borrow
            // of the original Service is alive. Their interior owners are never
            // shared with workers; all must remain absent for this File path.
            ha_present: service.ha.is_some(),
            postgres_present: service.postgres_durable.is_some(),
            durable_profile_present: service.durable_profile.is_some(),
            wrapper_present: service.openbao_wrapper_owner.is_some(),
            auth: &state.auth,
            digest: &service.state_digest,
            native_root,
            current_seal: &service.seal,
            actor: &plan.actor,
            path: &plan.path,
            namespace: &plan.namespace,
            activation: &plan.activation,
            base: &plan.base,
            native_root_contents: &plan.native_root_contents,
            plan_ha_present: plan.ha.is_some(),
            deadline: &plan.deadline,
            started: &plan.started,
            now: &plan.now,
            seal_reader: plan
                .lease
                .seal_reader(plan.deadline)
                .map_err(|_| unavailable())?,
            admitted_seal: &plan.seal_metadata_at_admission,
            admitted_bytes: plan.seal_bytes_at_admission.as_slice(),
            seal_identity: &plan.seal_identity,
        };
        view.check()?;
        Ok(view)
    }

    fn identity_matches(&self) -> bool {
        let Some(digest) = *self.digest else {
            return false;
        };
        let same_contents = self.native_root_contents.as_ref().is_some_and(|contents| {
            contents
                .matches_current(self.native_root, *self.base, digest)
                .unwrap_or(false)
        });
        // new() borrows an actual live State/native root and rejects any
        // record-root coexistence. This is the same native fallback performed
        // by Service::current_state_identity after the content fast path.
        same_contents
            || self
                .native_root
                .identity()
                .is_ok_and(|identity| identity.digest() == digest && identity == *self.base)
    }

    pub(super) fn check(&self) -> Result<(), Response> {
        if Instant::now() >= *self.deadline
            || *self.audit_failed
            || *self.recovery_required
            || !self.barrier_live
            || self.unseal_nonce != self.activation
            || self.ha_present
            || self.plan_ha_present
            || !self.identity_matches()
        {
            return Err(unavailable());
        }
        self.profile.check_borrowed_environment(
            self.data_dir,
            self.ha_present,
            self.postgres_present,
            self.durable_profile_present,
            self.wrapper_present,
            *self.audit_failed,
        )?;
        if !self.actor.is_root() || !self.namespace.is_empty() {
            return Err(Response::error(403, "permission denied"));
        }
        let now = snapshot_observed_time(*self.now, self.started.elapsed());
        self.auth
            .authorize_request(self.actor, self.namespace, self.path, "read", now)
            .map_err(|error| Response::error(error.status, &error.message))?;
        // Every invocation reads fresh seal bytes through the request's held
        // descriptor and revalidates its current name, owner, mode and length.
        // No byte, metadata, authorization or deadline result is cached.
        let bytes = self
            .seal_reader
            .read_metadata(*self.deadline)
            .map_err(|_| Response::error(503, "snapshot seal metadata is unavailable"))?;
        let observed = Service::snapshot_seal_identity_checked_against_admission(
            bytes.as_slice(),
            self.admitted_bytes,
            self.admitted_seal,
            self.current_seal.as_ref(),
            *self.seal_identity,
        )?;
        if observed != *self.seal_identity {
            return Err(Response::error(409, "V6 snapshot live seal changed"));
        }
        if Instant::now() >= *self.deadline {
            return Err(unavailable());
        }
        Ok(())
    }
}
