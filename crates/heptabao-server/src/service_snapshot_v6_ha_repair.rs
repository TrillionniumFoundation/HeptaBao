//! Explicit current-root repair; the ordinary snapshot restore route keeps
//! its separate historical restore contract. No archived Auth or replay state
//! is ever installed by this operation.
use super::*;

impl Service {
    pub(in crate::service) fn admit_native_ha_snapshot_repair(
        &mut self,
        request: &RequestView<'_>,
    ) -> Response {
        let admitted = (|| {
            if !self.native_ha_snapshot_transport_enabled()
                || request.path != NATIVE_HA_REPAIR_PATH
                || !self.native_snapshot_transport
            {
                return Err(Response::error(501, "current-root repair requires an active native HA owner"));
            }
            if !matches!(request.method, "POST" | "PUT") {
                return Err(Response::error(405, "current-root repair requires POST or PUT"));
            }
            if !request.namespace.is_empty()
                || request.body.as_object().is_none_or(|body| !body.is_empty())
            {
                return Err(Response::error(400, "current-root repair requires the root namespace and no query fields"));
            }
            if self.audit_failed || self.recovery_required || request.token_clock.is_none() {
                return Err(unavailable());
            }
            // This path must not try peer recovery or publish lease/clock
            // maintenance before the shared leaves have been repaired. It
            // instead authenticates the entire CURRENT local graph under a
            // fresh actual ReadIndex, preserving all four journal conditions.
            let source = self.capture_native_ha_archive_repair_source()?;
            let mut state = self.state.as_ref().ok_or_else(unavailable)?.clone();
            let time = request.token_time()?;
            let mut actor = state.auth.authenticate_from_observed(
                request.token, time, request.origin_peer,
            ).map_err(|error| Response::error(error.status, &error.message))?;
            actor.bind_request_clock(request.token_clock)
                .map_err(|error| Response::error(error.status, &error.message))?;
            actor.bind_request_wrapping_ttl(request.wrap_ttl_seconds);
            Self::bind_identity_principal(&state, &mut actor, request.namespace)?;
            if !actor.is_root() {
                return Err(Response::error(403, "permission denied"));
            }
            // Finite-use consumption is a real root publication. Do not lose
            // its consumption or perform that write with an absent closure.
            // A bounded-TTL root Actor with unlimited uses remains supported.
            if actor.consumed_use() {
                return Err(Response::error(409, "current-root repair requires a root credential without a use limit"));
            }
            state.auth.authorize_request_parameters_observed(
                &actor, request.namespace, request.method, request.path, request.body, time,
            ).map_err(|error| Response::error(error.status, &error.message))?;
            state.auth.authorize_request(
                &actor, request.namespace, request.path, "update", request.now,
            ).map_err(|error| Response::error(error.status, &error.message))?;
            // The observed clock is persisted by the unchanged terminal writer
            // before mandatory response audit. This candidate Auth clone is
            // never installed or substituted for the original source owner.
            source.check_local(self)?;
            Ok((actor, source))
        })();
        let (actor, source) = match admitted {
            Ok(value) => value,
            Err(error) => return error,
        };
        let response = self.stage_snapshot_transfer(actor, request);
        if response.status >= 400 {
            return response;
        }
        let Some(plan) = self.pending_snapshot_transfer.as_mut() else {
            return unavailable();
        };
        if plan.is_download || plan.path != NATIVE_HA_REPAIR_PATH || plan.native_ha_repair.is_some() {
            return unavailable();
        }
        plan.native_ha_repair = Some(source);
        response
    }

    pub(in crate::service::snapshot_transfer) fn finish_native_ha_snapshot_repair(
        &mut self,
        plan: &mut SnapshotTransferPlan,
        result: Result<Observation, Response>,
    ) -> Response {
        let checked = (|| {
            self.check_native_ha_snapshot_owner(plan)?;
            if plan.is_download || plan.path != NATIVE_HA_REPAIR_PATH || plan.native_ha_source.is_some() {
                return Err(unavailable());
            }
            let source = plan.native_ha_repair.take().ok_or_else(unavailable)?;
            source.check_local(self)?;
            let imported = match result? {
                Observation::Upload(imported) => imported,
                Observation::Download => return Err(unavailable()),
            };
            if !imported.metadata.is_v6_ha() {
                return Err(Response::error(400, "current-root repair requires a native HA dual-pack archive"));
            }
            let binding = imported.metadata.seal_identity().ok_or_else(invalid)?;
            if !binding.matches(&plan.seal_identity) {
                return Err(Response::error(400, "native HA repair archive seal differs"));
            }
            let barrier = AeadBarrier::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
            let opened = Zeroizing::new(barrier.open(
                snapshot_archive::CHECKSUM_CONTEXT, &imported.sealed_sums,
            ).map_err(|_| invalid())?);
            if opened.as_slice() != imported.sums.as_slice() {
                return Err(invalid());
            }
            self.check_native_ha_snapshot_owner(plan)?;
            let (proof, report) = source.repair(
                self, imported.state, plan.seal_identity,
                &mut |service| service.check_native_ha_snapshot_owner(plan),
            )?;
            if report.local.generation != imported.metadata.generation() {
                return Err(invalid());
            }
            self.check_native_ha_snapshot_owner(plan)?;
            plan.native_ha_source = Some(proof);
            Ok(Response::ok(json!({"data":{
                "repaired_root": hex(&plan.base.digest()),
                "shared_object_count": report.shared_object_count,
            }})))
        })();
        checked.unwrap_or_else(|error| error)
    }
}
