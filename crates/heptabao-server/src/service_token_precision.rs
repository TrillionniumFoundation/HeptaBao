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
        if !state.has_token_api_precision_state() {
            return Ok(());
        }
        if self.recovery_required || !state.auth.has_token_api_precision_state() {
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
        let changed = candidate
            .auth
            .observe_token_api_time(AuthorityTime::Precise(at))
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
