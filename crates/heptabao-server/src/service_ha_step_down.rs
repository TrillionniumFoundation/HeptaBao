//! The current leader finishes its terminal write and audit before handoff.
use super::*;

pub(super) struct StepDownPlan {
    process: Arc<Mutex<HaProcess>>,
    authority: plugin::PluginResponseAuthority,
    deadline: Option<std::time::Instant>,
}
impl StepDownPlan {
    pub(super) fn new(
        process: Arc<Mutex<HaProcess>>,
        authority: plugin::PluginResponseAuthority,
    ) -> Self {
        Self {
            process,
            authority,
            deadline: crate::request_deadline::current(),
        }
    }
}

impl Service {
    pub(super) fn complete_ha_step_down(
        &mut self,
        expected: bool,
        plan: Option<StepDownPlan>,
        response: Response,
        fingerprint: &str,
    ) -> Response {
        self.complete_ha_step_down_observed(expected, plan, response, fingerprint, || {})
    }

    fn complete_ha_step_down_observed(
        &mut self,
        expected: bool,
        plan: Option<StepDownPlan>,
        mut response: Response,
        fingerprint: &str,
        after_transfer: impl FnOnce(),
    ) -> Response {
        let mut plan = match (expected, plan) {
            (true, Some(plan)) => plan,
            (false, None) => return response,
            _ => {
                erase_json(&mut response.body);
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "HA step-down admission capsule was lost");
            }
        };
        // A failed floor write or mandatory audit never triggers the handoff.
        if response.status != 204 {
            return response;
        }
        if let Err(error) = self.transfer_ha_step_down(&mut plan, after_transfer) {
            if self
                .audit_event(
                    "ha-step-down-veto",
                    fingerprint,
                    plan.authority.now(),
                    Some(error.status),
                )
                .is_err()
            {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "HA step-down veto audit failed; recovery required");
            }
            return error;
        }
        Response {
            response_headers: Default::default(),
            consistency_index: None,
            status: 204,
            body: Value::Null,
        }
    }

    fn transfer_ha_step_down(
        &mut self,
        plan: &mut StepDownPlan,
        after_transfer: impl FnOnce(),
    ) -> Result<(), Response> {
        let _original_scope = plan
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        if self
            .ha
            .as_ref()
            .is_none_or(|process| !Arc::ptr_eq(process, &plan.process))
        {
            return Err(Response::error(503, "HA step-down process owner changed"));
        }
        self.validate_plugin_response(&mut plan.authority)?;
        let process = plan
            .process
            .lock_for_request()
            .map_err(|_| Response::error(503, "HA process lock is unavailable"))?;
        // Waiting for the original process lock must not preserve an actor who
        // expired while waiting, authenticate again, or spend another use.
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "HA step-down server sealed before handoff"))?;
        plan.authority.validate_live_auth(&state.auth)?;
        let transfer = process.step_down();
        drop(process);
        // Any attempted RPC can have changed leadership, including a timeout
        // or late success. Never reuse the old leader admission afterwards.
        self.ha_activation = None;
        transfer.map_err(|_| Response::error(503, "HA leadership transfer failed"))?;
        after_transfer();
        // Leadership is already transferred. Withhold success if the original
        // actor or budget expired during handoff, without another writer floor,
        // authentication, use consumption, or an attempted transfer rollback.
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "HA step-down server sealed after handoff"))?;
        plan.authority.validate_live_auth(&state.auth)
    }
}

#[cfg(test)]
#[path = "service_ha_step_down_tests.rs"]
mod tests;
