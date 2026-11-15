//! Host-owned due rotation under the existing original idle-worker deadline.
//! This path never mints a Principal or uses a decoded graph as a writer grant.
use super::*;
use crate::v6_native_custody::OriginalDeadline;

enum NativeTransitLifetimeInput {
    Original(u64, Option<RequestClock>),
    AfterPki(Box<native_auth::NativePkiIdleCheckpoint>),
}

impl Service {
    pub(super) fn maintain_native_transit_lifetimes(
        &mut self,
        now: u64,
        clock: Option<RequestClock>,
    ) -> Result<bool, &'static str> {
        self.maintain_native_transit_lifetimes_owned(NativeTransitLifetimeInput::Original(
            now, clock,
        ))
    }

    pub(super) fn maintain_native_transit_after_pki(
        &mut self,
        checkpoint: native_auth::NativePkiIdleCheckpoint,
    ) -> Result<bool, &'static str> {
        self.maintain_native_transit_lifetimes_owned(NativeTransitLifetimeInput::AfterPki(
            Box::new(checkpoint),
        ))
    }

    fn maintain_native_transit_lifetimes_owned(
        &mut self,
        input: NativeTransitLifetimeInput,
    ) -> Result<bool, &'static str> {
        let (now, clock) = match &input {
            NativeTransitLifetimeInput::Original(now, clock) => (*now, *clock),
            NativeTransitLifetimeInput::AfterPki(checkpoint) => {
                let (now, clock) = checkpoint
                    .check_for_transit(self)
                    .map_err(|_| "native rotation PKI checkpoint unavailable")?;
                (now, Some(clock))
            }
        };
        let after_pki = matches!(&input, NativeTransitLifetimeInput::AfterPki(_));
        let deadline =
            OriginalDeadline::capture().map_err(|_| "native rotation original deadline missing")?;
        let source = self
            .state
            .clone()
            .ok_or("native rotation source is sealed")?;
        self.require_native_root_candidate(&source)
            .map_err(|_| "native rotation storage owner unavailable")?;
        if source.auth.has_live_wrappers()
            || !after_pki
                && (source.engines.has_live_leases() || source.engines.has_local_pki_crl_state())
        {
            return Err("native rotation cannot retire another owner");
        }
        let clock = clock
            .ok_or("native rotation trusted clock missing")?
            .with_seconds_floor(now.max(source.engines.lease_clock()))
            .map_err(|_| "native rotation original clock unavailable")?;
        let at = clock
            .observed_at()
            .map_err(|_| "native rotation original clock unavailable")?;
        let bytes = owner_store::serialize_owner(&source.auth)
            .map_err(|_| "native rotation Auth source unavailable")?;
        let auth_digest = crypto::digest(&bytes);
        drop(bytes);
        let check_auth = |auth: &AuthState| -> Result<(), Response> {
            let rejected = || Response::error(503, "native rotation source custody changed");
            deadline.check().map_err(|_| rejected())?;
            if clock.observed_at().map_err(|_| rejected())? < at {
                return Err(rejected());
            }
            let bytes = owner_store::serialize_owner(auth).map_err(|_| rejected())?;
            if crypto::digest(&bytes) != auth_digest {
                return Err(rejected());
            }
            deadline.check().map_err(|_| rejected())
        };
        let proof = self
            .capture_native_request_proof(&mut || check_auth(&source.auth))
            .map_err(|_| "native rotation source proof unavailable")?
            .ok_or("native rotation source proof missing")?;
        let root = self
            .native_root
            .as_ref()
            .ok_or("native rotation source root missing")?;
        let rotation = source
            .engines
            .prepare_native_transit_rotation(at, root, &|| deadline.check().is_ok())
            .map_err(|_| "native rotation domain operation failed")?;
        proof
            .check_warm(self)
            .map_err(|_| "native rotation source changed during operation")?;
        let Some(mut rotation) = rotation else {
            return Ok(false);
        };
        rotation
            .check_source(
                &self
                    .state
                    .as_ref()
                    .ok_or("native rotation source lost")?
                    .engines,
                &|| deadline.check().is_ok(),
            )
            .map_err(|_| "native rotation source changed")?;
        let fingerprint = self.request_fingerprint("INTERNAL", "lifecycle/expiry", "", "");
        self.audit_event("lifecycle-request", &fingerprint, at.seconds(), None)
            .map_err(|_| "lifecycle request audit unavailable")?;
        let result = (|| -> Result<native_v6_reader::NativeProof, Response> {
            let rejected = || Response::error(503, "native rotation publication unavailable");
            let mut next = source.clone();
            next.engines = rotation.candidate().clone().into();
            next.schema = next.writer_schema();
            let plan =
                self.prepare_native_live_root_checked(&next, &mut |auth| check_auth(auth))?;
            rotation
                .admit_root(
                    self.native_root.as_ref().ok_or_else(rejected)?,
                    &plan.root,
                    &|| deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)?;
            let installed = self.commit_native_root_plan(
                &next,
                plan,
                false,
                "transit-auto-rotation",
                &mut |auth| check_auth(auth),
            )?;
            self.state = Some(installed);
            rotation
                .check_installed(
                    &self.state.as_ref().ok_or_else(rejected)?.engines,
                    self.native_root.as_ref().ok_or_else(rejected)?,
                    &|| deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)?;
            self.capture_native_request_proof(&mut || check_auth(&source.auth))?
                .ok_or_else(rejected)
        })();
        let status = if result.is_ok() { 204 } else { 503 };
        if self
            .audit_event(
                "lifecycle-response",
                &fingerprint,
                at.seconds(),
                Some(status),
            )
            .is_err()
        {
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            return Err("lifecycle result audit unavailable; recovery required");
        }
        let proof = result.map_err(|_| "native rotation commit failed; no success inferred")?;
        let checked = proof
            .check_with(self, |installed, metadata, native, root, original| {
                check_auth(&metadata.auth)?;
                Self::check_native_installed(installed, metadata, native, root, original)?;
                rotation
                    .check_installed(&installed.engines, root, &|| deadline.check().is_ok())
                    .map_err(Response::from_engine_error)
            })
            .and_then(|()| proof.check_warm(self));
        if checked.is_err() {
            if self
                .audit_event(
                    "native-transit-maintenance-veto",
                    &fingerprint,
                    at.seconds(),
                    Some(503),
                )
                .is_err()
            {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
            }
            return Err("native rotation audited completion unavailable");
        }
        deadline
            .check()
            .map_err(|_| "native rotation original deadline expired")?;
        Ok(true)
    }
}
