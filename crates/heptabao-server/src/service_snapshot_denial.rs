//! One authenticated standby snapshot refusal, never a transfer capability.
//! It retains the original Actor, real source A, physical seal and deadline.
//! Only an authenticated leader clock receipt plus real local B proof can
//! finish a precise-time denial. No archive or resource writer is reachable.
use super::*;

pub(super) struct StandbySnapshotDenial {
    actor: Principal,
    response: Response,
    method: String,
    path: String,
    namespace: String,
    fingerprint: String,
    clock: RequestClock,
    now: Duration,
    started: Instant,
    deadline: Instant,
    activation: String,
    ha: Arc<Mutex<HaProcess>>,
    base: StateIdentity,
    original: native_v6_ha_install::NativeHaReadProof,
    clock_request: Option<StandbySnapshotClockRequest>,
    spool: Arc<SnapshotSpool>,
    seal_identity: [u8; 32],
    seal_metadata: SealMetadata,
    seal_bytes: Zeroizing<Vec<u8>>,
}

fn unavailable() -> Response {
    Response::error(503, "standby snapshot denial authority is unavailable")
}

impl Service {
    pub(in crate::service::snapshot_transfer) fn prepare_standby_snapshot_denial(
        &mut self,
        request: &ServiceRequest<'_>,
        mut actor: Principal,
        response: Response,
        clock: RequestClock,
        now: Duration,
        started: Instant,
    ) -> Result<StandbySnapshotDenial, Response> {
        if response.status != 403
            || !request.namespace.is_empty()
            || request.wrap_ttl_seconds.is_some()
            || request.body.as_object().is_none_or(|body| !body.is_empty())
            || self.has_pending_external_dispatch()
            || self.native_request_binding.is_some()
            || self.native_failure_notice.is_some()
        {
            return Err(unavailable());
        }
        let deadline = crate::request_deadline::current().ok_or_else(unavailable)?;
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        actor
            .bind_request_clock(Some(clock))
            .map_err(|error| Response::error(error.status, &error.message))?;
        let view = RequestView {
            method: request.method,
            path: request.path,
            namespace: request.namespace,
            token: request.token,
            body: &request.body,
            now: now.as_secs(),
            admission_started: started,
            token_clock: Some(clock),
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: request.origin_peer,
            client_certificates: request.client_certificates,
        };
        let clock_request = if self
            .state
            .as_ref()
            .is_some_and(State::has_token_api_precision_state)
        {
            Some(StandbySnapshotClockRequest::capture(&view)?)
        } else {
            None
        };
        let base = self.current_state_identity()?;
        // This proof authenticates only shared metadata for a refusal. It is
        // never returned as an export, restore or ordinary KV capability.
        let original = self
            .capture_native_ha_request_proof(&mut || {
                if Instant::now() >= deadline {
                    Err(unavailable())
                } else {
                    Ok(())
                }
            })?
            .ok_or_else(unavailable)?;
        if base != StateIdentity::RecordsV6(original.snapshot_clock_shared_state().root_digest) {
            return Err(unavailable());
        }
        let spool = match self.snapshot_spool.as_ref() {
            Some(spool) => Arc::clone(spool),
            None => {
                let spool = SnapshotSpool::open(&self.data_dir).map_err(|_| unavailable())?;
                self.snapshot_spool = Some(Arc::clone(&spool));
                spool
            }
        };
        let seal_bytes = spool.read_seal_metadata(deadline).map_err(|_| unavailable())?;
        let seal_metadata: SealMetadata =
            serde_json::from_slice(&seal_bytes).map_err(|_| unavailable())?;
        if self.seal.as_ref() != Some(&seal_metadata) {
            return Err(unavailable());
        }
        let seal_identity = canonical_seal_identity(&seal_metadata).map_err(|_| unavailable())?;
        let mut denied = StandbySnapshotDenial {
            actor,
            response,
            method: request.method.to_owned(),
            path: request.path.to_owned(),
            namespace: request.namespace.to_owned(),
            fingerprint: self.request_fingerprint(
                request.method,
                request.path,
                request.namespace,
                request.token,
            ),
            clock,
            now,
            started,
            deadline,
            activation: self.unseal_nonce.clone(),
            ha: self.ha.as_ref().ok_or_else(unavailable)?.clone(),
            base,
            original,
            clock_request,
            spool,
            seal_identity,
            seal_metadata,
            seal_bytes,
        };
        self.check_standby_snapshot_denial_environment(&denied, base)?;
        self.check_standby_snapshot_actor_is_denied(&mut denied)?;
        denied.original.check_warm(self)?;
        Ok(denied)
    }

    fn check_standby_snapshot_denial_environment(
        &self,
        denied: &StandbySnapshotDenial,
        expected: StateIdentity,
    ) -> Result<(), Response> {
        if !self.ha.as_ref().is_some_and(|ha| Arc::ptr_eq(ha, &denied.ha))
            || self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || self.unseal_nonce != denied.activation
            || !self.native_ha_snapshot_transport_enabled()
            || !self.native_standby_snapshot_is_read_eligible()
            || crate::request_deadline::current() != Some(denied.deadline)
            || Instant::now() >= denied.deadline
            || self.current_state_identity()? != expected
        {
            return Err(unavailable());
        }
        let bytes = denied
            .spool
            .read_seal_metadata(denied.deadline)
            .map_err(|_| unavailable())?;
        if Self::snapshot_seal_identity_checked_against_admission(
            &bytes,
            &denied.seal_bytes,
            &denied.seal_metadata,
            self.seal.as_ref(),
            denied.seal_identity,
        )? != denied.seal_identity
        {
            return Err(unavailable());
        }
        if let Some(request) = &denied.clock_request
            && crate::auth::current_ingress().map(|ingress| ingress.attempt_id())
                != Some(request.ingress)
        {
            return Err(unavailable());
        }
        Ok(())
    }

    fn check_standby_snapshot_actor_is_denied(
        &self,
        denied: &mut StandbySnapshotDenial,
    ) -> Result<(), Response> {
        let state = self.state.as_ref().ok_or_else(unavailable)?;
        let time = AuthorityTime::Precise(denied.clock.observed_at().map_err(|_| unavailable())?);
        let parameters = json!({});
        let decision = Self::bind_identity_principal(state, &mut denied.actor, &denied.namespace)
            .and_then(|()| {
                state
                    .auth
                    .authorize_request_parameters_observed(
                        &denied.actor,
                        &denied.namespace,
                        &denied.method,
                        &denied.path,
                        &parameters,
                        time,
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
            })
            .and_then(|()| {
                state
                    .auth
                    .authorize_request_observed(
                        &denied.actor,
                        &denied.namespace,
                        &denied.path,
                        if matches!(denied.method.as_str(), "GET" | "HEAD") {
                            "read"
                        } else {
                            "update"
                        },
                        time,
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
            });
        match decision {
            Err(error) if error.status == 403 => Ok(()),
            Err(error) => Err(error),
            Ok(()) => Err(unavailable()),
        }
    }

    pub(in crate::service::snapshot_transfer) fn complete_standby_snapshot_denial(
        &mut self,
        mut denied: StandbySnapshotDenial,
    ) -> Response {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(denied.deadline);
        let mut response_audited = false;
        let result: Result<(), Response> = (|| {
            self.check_standby_snapshot_denial_environment(&denied, denied.base)?;
            denied.original.check_warm(self)?;
            self.check_standby_snapshot_actor_is_denied(&mut denied)?;
            if self
                .audit_event("request", &denied.fingerprint, denied.now.as_secs(), None)
                .is_err()
            {
                return Err(unavailable());
            }
            if self
                .audit_event(
                    "response",
                    &denied.fingerprint,
                    denied.now.as_secs(),
                    Some(403),
                )
                .is_err()
            {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return Err(unavailable());
            }
            response_audited = true;
            // Mandatory response audit precedes the one leader observation.
            self.check_standby_snapshot_denial_environment(&denied, denied.base)?;
            denied.original.check_warm(self)?;
            if let Some(request) = &denied.clock_request {
                let source = denied.original.snapshot_clock_shared_state();
                let context = crate::ha::snapshot_clock::SnapshotClockContext {
                    operation: request.operation,
                    method: &request.method,
                    token: &request.token,
                    origin_peer: request.origin_peer,
                    ingress: request.ingress,
                    source,
                    enrollment: denied.original.snapshot_clock_enrollment(),
                    deadline: denied.deadline,
                };
                let completion = {
                    let process = denied.ha.lock_for_request().map_err(|_| unavailable())?;
                    let receipt = process.observe_snapshot_terminal_clock(context)?;
                    receipt.consume(&process, context)?
                };
                self.sync_from_ha_with_anchor(false)?;
                let expected = completion.successor().unwrap_or(source);
                let expected_identity = StateIdentity::RecordsV6(expected.root_digest);
                self.check_standby_snapshot_denial_environment(&denied, expected_identity)?;
                // Even a 403 is unavailable until the actual replica has B.
                // Actor refusal never short-circuits this proof.
                let current = self
                    .capture_native_ha_request_proof(&mut || {
                        if Instant::now() >= denied.deadline {
                            Err(unavailable())
                        } else {
                            Ok(())
                        }
                    })?
                    .ok_or_else(unavailable)?;
                if current.snapshot_clock_shared_state() != expected {
                    return Err(unavailable());
                }
                if completion.successor().is_some() {
                    denied.original.check_snapshot_terminal_successor(self, &current)?;
                } else {
                    denied.original.check_with(self, Service::check_native_installed)?;
                    current.check_warm(self)?;
                }
                let checkpoint = (
                    self.current_state_identity()?,
                    self.external_effect_generation()?,
                );
                self.check_standby_snapshot_denial_environment(&denied, expected_identity)?;
                self.check_standby_snapshot_actor_is_denied(&mut denied)?;
                if !completion.is_denied()
                    || self.current_state_identity()? != checkpoint.0
                    || self.external_effect_generation()? != checkpoint.1
                {
                    return Err(unavailable());
                }
                completion.finish_denied()?;
            } else {
                if self
                    .state
                    .as_ref()
                    .is_none_or(State::has_token_api_precision_state)
                {
                    return Err(unavailable());
                }
                denied.original.check_with(self, Service::check_native_installed)?;
                self.check_standby_snapshot_denial_environment(&denied, denied.base)?;
                self.check_standby_snapshot_actor_is_denied(&mut denied)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            erase_json(&mut denied.response.body);
            denied.response.consistency_index = None;
            if response_audited
                && self
                    .audit_event(
                        "native-ha-snapshot-denial-veto",
                        &denied.fingerprint,
                        snapshot_observed_time(denied.now, denied.started.elapsed()),
                        Some(error.status),
                    )
                    .is_err()
            {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return unavailable();
            }
            return error;
        }
        crate::ha_forward_completion::audited(Some(denied.clock));
        self.stamp_consistency_index(&mut denied.response);
        denied.response
    }
}
