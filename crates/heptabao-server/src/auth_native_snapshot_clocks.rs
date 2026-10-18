//! Data-only monotone clock inheritance for an authenticated historical graph.
//! No catalog, token, credential, retirement or schema is synthesized here.
//! The Service must independently own the current typed root/four resources
//! and run every existing protected-floor validator after this narrow merge.
use super::*;

impl AuthState {
    pub(crate) fn inherit_native_snapshot_clocks(&mut self, current: &Self) -> Result<(), AuthError> {
        self.sdk_auth_clock = self.sdk_auth_clock.max(current.sdk_auth_clock);
        self.token_api_observed_at = self.token_api_observed_at.max(current.token_api_observed_at);
        self.wrapping_clock = self.wrapping_clock.max(current.wrapping_clock);
        self.inherit_native_snapshot_control_group_clock(current)?;
        self.validate_sdk_auth_clock(Some(current))?;
        self.validate_token_api_clock_floor(Some(current))?;
        self.validate_control_group_clock_floor(Some(current))
    }
}
