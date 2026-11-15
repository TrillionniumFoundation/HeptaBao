//! Point payload reads retain the already consumed affine request owner.
use super::*;
use crate::state_record_root_v6::ObjectDomain;

// Admission rejection proves that no domain operation was completed. Domain
// failure/success is a separate typed outcome; no HTTP status guesses dispatch.
pub(super) enum NativePagedOutcome {
    AdmissionRejected(Response),
    Dispatched(Response),
}

impl Service {
    pub(super) fn dispatch_native_paged_request(
        &mut self,
        candidate: &mut State,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
        request: &RequestView<'_>,
    ) -> Response {
        match self.dispatch_native_paged_outcome(candidate, authority, request) {
            NativePagedOutcome::AdmissionRejected(response)
            | NativePagedOutcome::Dispatched(response) => response,
        }
    }
    pub(super) fn dispatch_native_paged_outcome(
        &mut self,
        candidate: &mut State,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
        request: &RequestView<'_>,
    ) -> NativePagedOutcome {
        #[cfg(all(feature = "native-v6-ha", feature = "private-ha-forward-diagnostic"))]
        let phase = crate::request_deadline::current().map(|until| {
            native_v6_ha_install::NativeHaPhaseTimer::start(
                "request_paged_dispatch",
                until,
                0,
                0,
                0,
            )
        });
        let rejected = || Response::error(503, "native paged request custody rejected");
        let actual_auth = match self.state.as_ref() {
            Some(state) => state.auth.clone(),
            None => return NativePagedOutcome::AdmissionRejected(rejected()),
        };
        if let Err(error) = authority.check(candidate, &actual_auth, &self.unseal_nonce) {
            return NativePagedOutcome::AdmissionRejected(error);
        }
        let original_nonce = self.unseal_nonce.clone();
        let proof = match self.capture_native_request_proof(&mut || {
            authority.check(candidate, &actual_auth, &original_nonce)
        }) {
            Ok(Some(proof)) => proof,
            _ => return NativePagedOutcome::AdmissionRejected(rejected()),
        };
        if proof.check_warm(self).is_err() {
            return NativePagedOutcome::AdmissionRejected(rejected());
        }
        let deadline = match crate::v6_native_custody::OriginalDeadline::capture() {
            Ok(deadline) => deadline,
            Err(_) => return NativePagedOutcome::AdmissionRejected(rejected()),
        };
        let time = match request.token_time() {
            Ok(time) => time,
            Err(error) => return NativePagedOutcome::AdmissionRejected(error),
        };
        let at = match Self::kv2_request_timestamp(time) {
            Ok(at) => at,
            Err(error) => return NativePagedOutcome::AdmissionRejected(error),
        };
        // All immutable request/mount/identity metadata is captured from the
        // actual admitted candidate. It contains no hydrated historical value.
        let checked = candidate.clone();
        let nonce = self.unseal_nonce.clone();
        let observations = Arc::clone(&self.native_payload_observations);
        let durable = match self.durable.as_mut() {
            Some(durable) => durable,
            None => return NativePagedOutcome::AdmissionRejected(rejected()),
        };
        let source = match native_blob_source::NativeSource::new_checked(durable, deadline, || {
            authority
                .check(&checked, &actual_auth, &nonce)
                .map_err(|_| ServiceError::BarrierFailure)
        }) {
            Ok(source) => source.with_observations(observations),
            Err(_) => return NativePagedOutcome::AdmissionRejected(rejected()),
        };
        #[cfg(all(feature = "native-v6-ha", feature = "private-ha-forward-diagnostic"))]
        let payload_phase = crate::request_deadline::current().map(|until| {
            native_v6_ha_install::NativeHaPhaseTimer::start("request_paged_payload", until, 0, 0, 0)
        });
        let result = candidate.engines.dispatch_native_paged_completion(
            request.namespace,
            request.method,
            request.path,
            request.body,
            at,
            |scope, reference| {
                source.read_paged_payload(&ObjectDomain::Kv2(scope.clone()), reference)
            },
        );
        #[cfg(all(feature = "native-v6-ha", feature = "private-ha-forward-diagnostic"))]
        if let Some(payload_phase) = payload_phase {
            payload_phase.finish(result.is_ok());
        }
        drop(source);
        if let Err(error) = authority.check(candidate, &actual_auth, &nonce) {
            return NativePagedOutcome::AdmissionRejected(error);
        }
        #[cfg(all(feature = "native-v6-ha", feature = "private-ha-forward-diagnostic"))]
        if let Some(phase) = phase {
            phase.finish(true);
        }
        NativePagedOutcome::Dispatched(match result {
            Ok((mut dispatched, completed)) => {
                let response = Response {
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    status: dispatched.status,
                    body: std::mem::take(&mut dispatched.body),
                };
                if request.method == "GET"
                    && request.wrap_ttl_seconds.is_none()
                    && let Some(completed) = completed
                {
                    crate::ha_forward_completion::native_data_read_completed(completed, &response);
                }
                response
            }
            Err(error) => Response::from_engine_error(error),
        })
    }
}
