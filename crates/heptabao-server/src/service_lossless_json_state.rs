//! Sticky format custody for non-KV2 user JSON on the original State owner.
use super::*;

impl State {
    pub(super) fn has_global_lossless_json_state(&self) -> bool {
        self.auth.has_lossless_json_state()
            || self.engines.has_non_kv2_lossless_json_state()
            || self.namespaces.workflows.has_lossless_json_state()
    }

    pub(super) fn validate_global_lossless_json_state(
        &self,
        previous: Option<&State>,
    ) -> Result<(), Response> {
        if self
            .global_lossless_json_format
            .is_some_and(|format| format != 1)
            || self.global_lossless_json_format.is_some()
                && self.schema < GLOBAL_LOSSLESS_JSON_STATE_SCHEMA
            || self.has_global_lossless_json_state() && self.global_lossless_json_format != Some(1)
            || previous.is_some_and(|state| state.global_lossless_json_format.is_some())
                && self.global_lossless_json_format != Some(1)
        {
            return Err(Response::error(
                503,
                "global lossless JSON format custody is invalid",
            ));
        }
        Ok(())
    }

    /// Called on this candidate before its existing namespace projection and
    /// publication. Preserve existing custody; never repair a torn prior marker.
    pub(super) fn prepare_global_lossless_json_state(
        &mut self,
        previous: Option<&State>,
    ) -> Result<(), Response> {
        if previous.is_some_and(|state| state.global_lossless_json_format.is_some())
            && self.global_lossless_json_format != Some(1)
        {
            return Err(Response::error(
                503,
                "global lossless JSON format custody is missing",
            ));
        }
        if self.global_lossless_json_format.is_none() && self.has_global_lossless_json_state() {
            self.global_lossless_json_format = Some(1);
            self.schema = self.writer_schema();
        }
        self.validate_global_lossless_json_state(previous)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "service_lossless_state_tests.rs"]
mod tests;
