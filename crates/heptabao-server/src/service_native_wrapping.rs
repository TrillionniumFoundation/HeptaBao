//! The ordinary Wrapping dispatcher and its two observation-only clock preludes.
//! No generic wrapping prefix acquires resource publication authority here.
use super::*;
use crate::auth::{NativeWrappingObservation, NativeWrappingOwner};

fn auth_error(error: crate::auth::AuthError) -> Response {
    Response::error(error.status, &error.message)
}

impl Service {
    pub(in crate::service) fn observe_native_wrapping(
        &mut self,
        clock: RequestClock,
    ) -> Result<(), Response> {
        let source = self.state.as_ref().cloned().ok_or_else(rejected)?;
        let (binding, auth, changed) =
            NativeWrappingObservation::observe(&source.auth, clock).map_err(auth_error)?;
        if !changed {
            return Ok(());
        }
        let mut candidate = source.clone();
        candidate.auth = auth.into();
        candidate.schema = candidate.writer_schema();
        candidate.prepare_global_lossless_json_state(Some(&source))?;
        binding
            .check_candidate(&source.auth, &candidate.auth)
            .map_err(auth_error)?;
        let plan = self.prepare_native_live_root_checked(&candidate, &mut |auth| {
            binding
                .check_candidate(auth, &candidate.auth)
                .map_err(auth_error)
        })?;
        auth_only_root_change(
            self.native_root.as_ref().ok_or_else(rejected)?,
            &plan.root,
            false,
        )?;
        let installed = self.commit_native_root_plan(
            &candidate,
            plan,
            false,
            "ordinary-wrapping-observation",
            &mut |auth| {
                binding
                    .check_candidate(auth, &candidate.auth)
                    .map_err(auth_error)
            },
        )?;
        self.state = Some(installed);
        Ok(())
    }

    pub(in crate::service) fn dispatch_native_wrapping_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        if !request.namespace.is_empty() || !NativeWrappingOwner::route(request.path) {
            return rejected();
        }
        let Some(clock) = request.token_clock else {
            return rejected();
        };
        let owner = match NativeWrappingOwner::prepare(
            &candidate.auth,
            request.method,
            request.path,
            request.body,
            request.token,
            request.wrap_ttl_seconds,
            clock,
        ) {
            Ok(owner) => owner,
            Err(error) => return auth_error(error),
        };
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::Wrapping(Box::new(owner)),
        )
    }
}
