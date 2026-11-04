//! The leader's private terminal observation for one original standby snapshot.
//! It accepts no caller clock, floor, archive, replacement Actor or generic
//! operation. Its sealed result is created only after the actual clock writer.
use super::*;
use crate::ha::snapshot_clock::{
    AuthenticatedSnapshotClockRequest, SharedSnapshotClockState, SnapshotClockDisposition,
    SnapshotClockOperation,
};

// Neither serde nor a public field/constructor can turn shared root metadata
// into this completion. Only the real writer path below constructs it, and the
// authenticated transport consumes it once before emitting its bounded reply.
pub(crate) struct SnapshotClockObservation {
    source: SharedSnapshotClockState,
    successor: Option<SharedSnapshotClockState>,
    disposition: SnapshotClockDisposition,
}

impl SnapshotClockObservation {
    pub(crate) fn into_parts(
        self,
    ) -> (
        SharedSnapshotClockState,
        Option<SharedSnapshotClockState>,
        SnapshotClockDisposition,
    ) {
        (self.source, self.successor, self.disposition)
    }
}

fn unavailable() -> Response {
    Response::error(503, "snapshot terminal clock authority is unavailable")
}

// A real authentication/ACL outcome, retained through the actual terminal
// writer. A denied admission can never be converted into a resource plan.
struct SnapshotClockActor {
    actor: Option<Principal>,
    denied_before_floor: bool,
}

impl Service {
    fn admit_snapshot_clock_actor(
        state: &State,
        request: &AuthenticatedSnapshotClockRequest,
        clock: RequestClock,
        capability: &str,
    ) -> Result<SnapshotClockActor, Response> {
        let time = AuthorityTime::Precise(clock.observed_at().map_err(|_| unavailable())?);
        let mut actor = match state.auth.authenticate_read_only_from_observed(
            request.token(),
            time,
            request.origin_peer(),
        ) {
            Ok(Some(actor)) => actor,
            // Finite-use/wrapping eligibility is not an authenticated Actor.
            Ok(None) => return Err(Response::error(403, "permission denied")),
            Err(error) if error.status == 403 => {
                return Ok(SnapshotClockActor {
                    actor: None,
                    denied_before_floor: true,
                });
            }
            Err(error) => return Err(Response::error(error.status, &error.message)),
        };
        actor
            .bind_request_clock(Some(clock))
            .map_err(|error| Response::error(error.status, &error.message))?;
        let admission =
            Self::authorize_snapshot_clock_actor(state, &mut actor, request, capability, time);
        let denied_before_floor = match admission {
            Ok(()) => false,
            Err(error) if error.status == 403 => true,
            Err(error) => return Err(error),
        };
        Ok(SnapshotClockActor {
            actor: Some(actor),
            denied_before_floor,
        })
    }

    fn authorize_snapshot_clock_actor(
        state: &State,
        actor: &mut Principal,
        request: &AuthenticatedSnapshotClockRequest,
        capability: &str,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        Self::bind_identity_principal(state, actor, request.namespace())?;
        let parameters = json!({});
        state
            .auth
            .authorize_request_parameters_observed(
                actor,
                request.namespace(),
                request.method(),
                request.path(),
                &parameters,
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        state
            .auth
            .authorize_request_observed(
                actor,
                request.namespace(),
                request.path(),
                capability,
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))
    }

    fn finish_snapshot_clock_actor(
        &self,
        admitted: &mut SnapshotClockActor,
        request: &AuthenticatedSnapshotClockRequest,
        capability: &str,
        clock: RequestClock,
    ) -> Result<SnapshotClockDisposition, Response> {
        let state = self.state.as_ref().ok_or_else(unavailable)?;
        let time = AuthorityTime::Precise(clock.observed_at().map_err(|_| unavailable())?);
        let denied_now = if let Some(actor) = admitted.actor.as_mut() {
            match Self::authorize_snapshot_clock_actor(state, actor, request, capability, time) {
                Ok(()) => false,
                Err(error) if error.status == 403 => true,
                Err(error) => return Err(error),
            }
        } else {
            // This is the same real rejected bearer. Reauthentication cannot
            // replace a previously admitted affine Actor or grant any output.
            match state.auth.authenticate_read_only_from_observed(
                request.token(),
                time,
                request.origin_peer(),
            ) {
                Err(error) if error.status == 403 => true,
                Err(error) => return Err(Response::error(error.status, &error.message)),
                Ok(_) => return Err(unavailable()),
            }
        };
        match (admitted.denied_before_floor, denied_now) {
            (false, false) => Ok(SnapshotClockDisposition::Allowed),
            (true, true) => Ok(SnapshotClockDisposition::Denied),
            // A new expiry observed only after the writer is not covered by
            // this earlier observation receipt. Refuse without another write,
            // replay, stale output, or manufactured Denied completion.
            _ => Err(unavailable()),
        }
    }

    fn check_snapshot_clock_leader(
        &self,
        request: &AuthenticatedSnapshotClockRequest,
    ) -> Result<(), Response> {
        if self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || !self.native_ha_snapshot_transport_enabled()
            || !self.native_standby_snapshot_is_read_eligible()
            || crate::request_deadline::current() != Some(request.deadline())
            || Instant::now() >= request.deadline()
        {
            return Err(unavailable());
        }
        let process = self
            .ha
            .as_ref()
            .ok_or_else(unavailable)?
            .lock_for_request()
            .map_err(|_| unavailable())?;
        let role = process.leader_status().map_err(|_| unavailable())?;
        if !role.local_is_leader
            || role.local_id != request.leader_node()
            || role.leader != Some(request.leader_node())
            || role.term != request.leader_term()
        {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(crate) fn observe_snapshot_terminal_clock(
        &mut self,
        request: AuthenticatedSnapshotClockRequest,
    ) -> Result<SnapshotClockObservation, Response> {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(request.deadline());
        self.check_snapshot_clock_leader(&request)?;
        if self.has_pending_external_dispatch()
            || self.native_request_binding.is_some()
            || self.native_failure_notice.is_some()
        {
            return Err(unavailable());
        }
        let started = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| unavailable())?;
        // The wire carries no time. This is the leader's real paired wall and
        // monotonic observation, captured before reconciliation and audit.
        let clock = RequestClock::anchored(wall, started).map_err(|_| unavailable())?;
        let raw_fingerprint = self.request_fingerprint(
            request.method(),
            request.path(),
            request.namespace(),
            request.token(),
        );
        let mut binding = hmac::Context::with_key(&self.audit_key);
        binding.update(b"heptabao.audit.snapshot-terminal-clock.v1\0");
        binding.update(raw_fingerprint.as_bytes());
        binding.update(&request.ingress());
        binding.update(&request.source().enrollment_digest);
        binding.update(&request.source().root_digest);
        binding.update(&request.source().auth_sha256);
        let fingerprint = STANDARD.encode(binding.sign().as_ref());
        if self
            .audit_event("snapshot-clock-request", &fingerprint, wall.as_secs(), None)
            .is_err()
        {
            return Err(unavailable());
        }
        self.bind_native_request_failure(&fingerprint, Some(clock), started, request.path());
        let result = self.observe_snapshot_terminal_clock_bound(
            &request,
            clock,
            wall.as_secs(),
            &fingerprint,
        );
        let failure = self.take_native_failure_response(&fingerprint, Some(clock));
        self.retire_native_external_binding(&fingerprint, Some(clock));
        if let Some(failure) = failure {
            return Err(failure);
        }
        result
    }

    fn observe_snapshot_terminal_clock_bound(
        &mut self,
        request: &AuthenticatedSnapshotClockRequest,
        clock: RequestClock,
        now: u64,
        fingerprint: &str,
    ) -> Result<SnapshotClockObservation, Response> {
        self.sync_from_ha_with_anchor(false)?;
        self.check_snapshot_clock_leader(request)?;
        // This proof selects actual A only. It grants no resource delivery:
        // the independent real bearer/ACL admission below remains mandatory.
        // The terminal observation also persists failed-auth expiry, just as
        // the existing terminal writer does for ordinary rejected requests.
        let original = self
            .capture_native_ha_request_proof(&mut || {
                if Instant::now() >= request.deadline() {
                    Err(unavailable())
                } else {
                    Ok(())
                }
            })?
            .ok_or_else(unavailable)?;
        request.check_enrollment(original.snapshot_clock_enrollment())?;
        let source = original.snapshot_clock_shared_state();
        if source != *request.source() {
            return Err(Response::error(
                409,
                "snapshot terminal observation source changed",
            ));
        }
        let capability = match request.operation() {
            SnapshotClockOperation::Download => "read",
            SnapshotClockOperation::ValidateUpload
            | SnapshotClockOperation::ValidateForceUpload => "update",
        };
        let admitted = Self::admit_snapshot_clock_actor(
            self.state.as_ref().ok_or_else(unavailable)?,
            request,
            clock,
            capability,
        );
        let status = admitted.as_ref().map_or_else(
            |error| error.status,
            |actor| if actor.denied_before_floor { 403 } else { 200 },
        );
        if self
            .audit_event("snapshot-clock-response", fingerprint, now, Some(status))
            .is_err()
        {
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            return Err(unavailable());
        }
        self.check_snapshot_clock_leader(request)?;
        original.check_warm(self)?;
        let before = (
            self.current_state_identity()?,
            self.external_effect_generation()?,
        );
        // The existing writer fixes its own trusted observation after audit,
        // validates a clock-only delta against original Auth allocation, and
        // performs the normal Raft publication. No client/peer floor is used.
        let receipt = self.persist_terminal_token_clock_with_receipt(Some(clock), now, true)?;
        self.check_snapshot_clock_leader(request)?;
        // Both dispositions first authenticate real B. A policy/expiry
        // refusal cannot bypass the receipt or turn shared metadata into proof.
        let current = self
            .capture_native_ha_request_proof(&mut || {
                if Instant::now() >= request.deadline() {
                    Err(unavailable())
                } else {
                    Ok(())
                }
            })?
            .ok_or_else(unavailable)?;
        request.check_enrollment(current.snapshot_clock_enrollment())?;
        let actual = current.snapshot_clock_shared_state();
        let after = (
            self.current_state_identity()?,
            self.external_effect_generation()?,
        );
        let successor = match receipt {
            Some(receipt) => {
                // These before/after checkpoints are LEADER-local. They are
                // consumed here and never serialized or substituted for a
                // different replica's durable/publication generation.
                if receipt.bind_native_snapshot(before)? != after {
                    return Err(unavailable());
                }
                original.check_snapshot_terminal_successor(self, &current)?;
                Some(actual)
            }
            None => {
                if actual != source
                    || after != before
                    || original.generation() != current.generation()
                {
                    return Err(unavailable());
                }
                original.check_with(self, Service::check_native_installed)?;
                current.check_warm(self)?;
                None
            }
        };
        let mut admitted = admitted?;
        let disposition =
            self.finish_snapshot_clock_actor(&mut admitted, request, capability, clock)?;
        self.check_snapshot_clock_leader(request)?;
        if self.current_state_identity()? != after.0
            || self.external_effect_generation()? != after.1
        {
            return Err(unavailable());
        }
        Ok(SnapshotClockObservation {
            source,
            successor,
            disposition,
        })
    }
}
