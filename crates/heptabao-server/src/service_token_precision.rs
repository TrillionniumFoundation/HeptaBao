//! Persist observed private time at the existing terminal writer boundary.
//! This is observation state, never a new actor/provider publication grant.
use super::*;

// An affine receipt for this one terminal observation-only write. Fields and
// construction stay private to the writer; it cannot authorize a provider effect.
pub(super) struct TerminalClockReceipt {
    before: (
        crate::state_record_root::StateIdentity,
        plugin::PublicationGeneration,
    ),
    after: (
        crate::state_record_root::StateIdentity,
        plugin::PublicationGeneration,
    ),
}
impl TerminalClockReceipt {
    pub(super) fn advance(
        self,
        checkpoint: &mut Option<(
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        )>,
    ) {
        if checkpoint
            .as_ref()
            .is_some_and(|prior| *prior == self.before)
        {
            *checkpoint = Some(self.after);
        }
    }
}

impl Service {
    pub(super) fn persist_terminal_token_clock(
        &mut self,
        token_clock: Option<RequestClock>,
        now: u64,
    ) -> Result<(), Response> {
        self.persist_terminal_token_clock_with_receipt(token_clock, now, false)
            .map(drop)
    }

    pub(super) fn persist_terminal_token_clock_with_receipt(
        &mut self,
        token_clock: Option<RequestClock>,
        now: u64,
        retain_receipt: bool,
    ) -> Result<Option<TerminalClockReceipt>, Response> {
        let Some(state) = self.state.as_ref() else {
            return Ok(None);
        };
        // Historical stores do not acquire an extra write or private floor.
        let precise_token = state.has_token_api_precision_state();
        let opaque_artifact = state.engines.has_kubernetes_opaque_artifact_state();
        if !precise_token && !opaque_artifact {
            return Ok(None);
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
            return Ok(None);
        }
        candidate.schema = candidate.writer_schema();
        // Existing State/RecordPlan publication validates the same current
        // owner and floor. No ReadIndex, audit or provider deadline is renewed.
        let before = if retain_receipt {
            Some((
                self.current_state_identity()?,
                self.external_effect_generation()?,
            ))
        } else {
            None
        };
        if self.commit_state(&mut candidate).is_err() {
            return Err(Response::error(
                503,
                "Token API observation floor was not committed",
            ));
        }
        self.state = Some(candidate);
        before
            .map(|before| {
                Ok(TerminalClockReceipt {
                    before,
                    after: (
                        self.current_state_identity()?,
                        self.external_effect_generation()?,
                    ),
                })
            })
            .transpose()
    }
}
