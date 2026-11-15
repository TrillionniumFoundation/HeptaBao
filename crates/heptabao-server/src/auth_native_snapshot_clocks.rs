//! Data-only monotone observation and producer-floor inheritance for an
//! authenticated historical graph.
//! No catalog, token, credential, retirement or schema is synthesized here.
//! The Service must independently own the current typed root/four resources
//! and run every existing protected-floor validator after this narrow merge.
use super::*;

impl AuthState {
    pub(crate) fn inherit_native_snapshot_clocks(
        &mut self,
        current: &Self,
    ) -> Result<(), AuthError> {
        // Both authenticated states must already own valid precision facts.
        // Do not heal a malformed marker/floor pair by merging the other one.
        self.validate_token_api_precision_state()?;
        current.validate_token_api_precision_state()?;
        self.validate_public_origin_state()?;
        current.validate_public_origin_state()?;
        self.sdk_auth_clock = self.sdk_auth_clock.max(current.sdk_auth_clock);
        // The sticky precision owner accompanies its retained timestamp, even
        // when the archive predates Token API issuance. No token is imported.
        self.token_api_precision_state |= current.token_api_precision_state;
        // Retain only the existing sticky producer-format owner. Public
        // token metadata, credentials and lease authority remain archived.
        self.public_origin_floor = self.public_origin_floor.or(current.public_origin_floor);
        self.token_api_observed_at = self
            .token_api_observed_at
            .max(current.token_api_observed_at);
        self.wrapping_clock = self.wrapping_clock.max(current.wrapping_clock);
        self.inherit_native_snapshot_control_group_clock(current)?;
        self.validate_sdk_auth_clock(Some(current))?;
        self.validate_token_api_clock_floor(Some(current))?;
        self.validate_public_origin_successor(current)?;
        self.validate_control_group_clock_floor(Some(current))
    }
}

#[cfg(test)]
#[path = "auth_native_snapshot_clock_floor_tests.rs"]
mod clock_floor_tests;
