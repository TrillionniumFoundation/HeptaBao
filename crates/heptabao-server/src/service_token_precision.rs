//! Persist observed private time at the existing terminal writer boundary.
//! This is observation state, never a new actor/provider publication grant.
use super::*;

impl Service {
    pub(super) fn persist_terminal_token_clock(
        &mut self,
        token_clock: Option<RequestClock>,
        now: u64,
    ) -> Result<(), Response> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };
        // Historical stores do not acquire an extra write or private floor.
        let precise_token = state.has_token_api_precision_state();
        let opaque_artifact = state.engines.has_kubernetes_opaque_artifact_state();
        if !precise_token && !opaque_artifact {
            return Ok(());
        }
        if self.recovery_required || (precise_token && !state.auth.has_token_api_precision_state())
        {
            return Err(Response::error(
                503,
                "Token API observation authority is unavailable",
            ));
        }
        let clock = token_clock
            .ok_or_else(|| Response::error(503, "trusted token clock is required"))?
            .with_seconds_floor(now.max(state.engines.lease_clock()))
            .map_err(|_| Response::error(503, "trusted token clock is unavailable"))?;
        let at = clock
            .observed_at()
            .map_err(|_| Response::error(503, "trusted token clock is unavailable"))?;
        let mut candidate = state.clone();
        let time = candidate
            .engines
            .kubernetes_artifact_time(AuthorityTime::Precise(at))
            .map_err(|error| Response::error(503, &error.message))?;
        let time = candidate.auth.token_api_observed_time(time);
        let mut changed = candidate
            .auth
            .observe_token_api_time(time)
            .map_err(|error| Response::error(503, &error.message))?;
        changed |= candidate
            .engines
            .observe_kubernetes_artifact_time(time)
            .map_err(|error| Response::error(503, &error.message))?;
        if !changed {
            return Ok(());
        }
        candidate.schema = candidate.writer_schema();
        // Existing State/RecordPlan publication validates the same current
        // owner and floor. No ReadIndex, audit or provider deadline is renewed.
        if self.commit_state(&candidate).is_err() {
            return Err(Response::error(
                503,
                "Token API observation floor was not committed",
            ));
        }
        self.state = Some(candidate);
        Ok(())
    }
}
