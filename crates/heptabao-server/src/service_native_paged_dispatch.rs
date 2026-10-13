//! Point payload reads retain the already consumed affine request owner.
use super::*;
use crate::state_record_root_v6::ObjectDomain;
use crate::v6_read_validation::ObjectSource;

impl Service {
    pub(super) fn dispatch_native_paged_request(
        &mut self,
        candidate: &mut State,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
        request: &RequestView<'_>,
    ) -> Response {
        let rejected = || Response::error(503, "native paged request custody rejected");
        let actual_auth = match self.state.as_ref() {
            Some(state) => state.auth.clone(),
            None => return rejected(),
        };
        if let Err(error) = authority.check(candidate, &actual_auth, &self.unseal_nonce) {
            return error;
        }
        let original_nonce = self.unseal_nonce.clone();
        let proof = match self.capture_native_request_proof(&mut || authority.check(candidate, &actual_auth, &original_nonce)) {
            Ok(Some(proof)) => proof,
            _ => return rejected(),
        };
        if proof.check_warm(self).is_err() {
            return rejected();
        }
        let deadline = match crate::v6_native_custody::OriginalDeadline::capture() {
            Ok(deadline) => deadline,
            Err(_) => return rejected(),
        };
        let time = match request.token_time() {
            Ok(time) => time,
            Err(error) => return error,
        };
        let at = match Self::kv2_request_timestamp(time) {
            Ok(at) => at,
            Err(error) => return error,
        };
        // All immutable request/mount/identity metadata is captured from the
        // actual admitted candidate. It contains no hydrated historical value.
        let checked = candidate.clone();
        let nonce = self.unseal_nonce.clone();
        let observations = Arc::clone(&self.native_payload_observations);
        let durable = match self.durable.as_mut() {
            Some(durable) => durable,
            None => return rejected(),
        };
        let source = match native_blob_source::NativeSource::new_checked(durable, deadline, || {
            authority
                .check(&checked, &actual_auth, &nonce)
                .map_err(|_| ServiceError::BarrierFailure)
        }) {
            Ok(source) => source.with_observations(observations),
            Err(_) => return rejected(),
        };
        let result = candidate.engines.dispatch_native_paged(
            request.namespace,
            request.method,
            request.path,
            request.body,
            at,
            |scope, reference| source.read(&ObjectDomain::Kv2(scope.clone()), reference),
        );
        drop(source);
        if let Err(error) = authority.check(candidate, &actual_auth, &nonce) {
            return error;
        }
        match result {
            Ok(mut response) => Response {
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
                status: response.status,
                body: std::mem::take(&mut response.body),
            },
            Err(error) => Response::from_engine_error(error),
        }
    }
}
