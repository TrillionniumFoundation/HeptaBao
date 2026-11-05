//! Only an actual active lifecycle may recreate an expired root default.
//! Ordinary reads and standby materialization never choose this transition.
use super::*;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Activation {
    nonce: String,
    leader: Option<ha_activation::ActivationKey>,
}

fn rejected() -> Response {
    Response::error(503, "default policy active initialization is unavailable")
}

impl Service {
    fn policy_default_activation(&self) -> Result<Option<Activation>, Response> {
        if !self.ha_activation_permitted() {
            return Err(rejected());
        }
        let leader = if self.ha.is_some() {
            let Some(key) = self.local_activation_key() else {
                return Ok(None);
            };
            if !self
                .ha_activation
                .as_ref()
                .is_some_and(|event| event.matches(key))
            {
                return Ok(None);
            }
            Some(key)
        } else {
            None
        };
        Ok(Some(Activation {
            nonce: self.unseal_nonce.clone(),
            leader,
        }))
    }

    // Public readiness may observe a new actual leader before the owned
    // activation worker reaches its default-policy startup step. Observing
    // health must not publish Auth or mark that step complete on its behalf.
    pub(super) fn default_policy_activation_pending(&self) -> bool {
        if self
            .state
            .as_ref()
            .is_none_or(|state| !state.auth.default_policy_activation_needs_clock())
        {
            return false;
        }
        match self.policy_default_activation() {
            Ok(Some(activation)) => self.policy_default_activation.as_ref() != Some(&activation),
            Ok(None) | Err(_) => true,
        }
    }

    pub(super) fn complete_default_policy_activation(
        &mut self,
        clock: Option<RequestClock>,
    ) -> Result<(), Response> {
        if self.state.is_none() || self.barrier_key.is_none() {
            return Ok(());
        }
        let Some(activation) = self.policy_default_activation()? else {
            return Ok(());
        };
        if self.policy_default_activation.as_ref() == Some(&activation) {
            return Ok(());
        }
        let source = self.state.as_ref().ok_or_else(rejected)?;
        if !source.auth.default_policy_activation_needs_clock() {
            self.policy_default_activation = Some(activation);
            return Ok(());
        }
        let mut clock = clock.ok_or_else(rejected)?;
        if let Some(floor) = source.auth.terminal_token_clock_floor() {
            clock = clock.with_timestamp_floor(floor);
        }
        let at = clock.observed_at().map_err(|_| rejected())?;
        let Some(reset) = source
            .auth
            .capture_default_policy_reset(AuthorityTime::Precise(at))
            .map_err(|error| Response::error(error.status, &error.message))?
        else {
            // An unexpired configured default is retained for this activation.
            // Its later expiry cannot cause an ordinary request to restore it.
            self.policy_default_activation = Some(activation);
            return Ok(());
        };
        let mut candidate = source.clone();
        reset
            .apply(&mut candidate.auth)
            .map_err(|error| Response::error(error.status, &error.message))?;
        candidate.schema = candidate.writer_schema();
        reset
            .validate_candidate(&source.auth, &candidate.auth)
            .map_err(|error| Response::error(error.status, &error.message))?;
        #[cfg(feature = "native-v6-storage")]
        let source_auth = owner_store::serialize_owner(&source.auth).map_err(|_| rejected())?;
        #[cfg(feature = "native-v6-storage")]
        let expected_auth = candidate.auth.clone();
        let deadline = crate::request_deadline::current();
        let ha = self.ha.clone();
        let gate = || {
            if deadline.is_some_and(|end| Instant::now() >= end)
                || clock.observed_at().map_err(|_| rejected())? < reset.observed_at()
            {
                return Err(rejected());
            }
            if let Some(process) = &ha {
                let process = process.lock_for_request().map_err(|_| rejected())?;
                if !process.bootstrap_ready()
                    || ha_activation::ActivationKey::from_observation(
                        process.leader_status().map_err(|_| rejected())?,
                    ) != activation.leader
                {
                    return Err(rejected());
                }
            }
            Ok(())
        };
        gate()?;
        let fingerprint = self.request_fingerprint("POLICY-ACTIVATION", "default", "", "");
        self.audit_event(
            "policy-default-activation",
            &fingerprint,
            at.seconds(),
            None,
        )
        .map_err(|_| rejected())?;
        gate()?;
        #[cfg(feature = "native-v6-storage")]
        if self.native_root.is_some() {
            let native_deadline =
                crate::v6_native_custody::OriginalDeadline::capture().map_err(|_| rejected())?;
            // candidate was cloned inside this lifecycle from the actual source;
            // the only mutation is the closed root-default reset constructor.
            // No caller supplies an Auth candidate or an arbitrary policy body.
            let mut original_gate = |auth: &AuthState| {
                native_deadline.check().map_err(|_| rejected())?;
                gate()?;
                if owner_store::serialize_owner(auth)
                    .map_err(|_| rejected())?
                    .as_slice()
                    != source_auth.as_slice()
                {
                    return Err(rejected());
                }
                reset
                    .validate_candidate(auth, &expected_auth)
                    .map_err(|error| Response::error(error.status, &error.message))?;
                gate()
            };
            let plan = self.prepare_native_live_root_checked(&candidate, &mut original_gate)?;
            candidate = self.commit_native_root_plan(
                &candidate,
                plan,
                false,
                "policy-default-activation",
                &mut original_gate,
            )?;
        } else {
            self.commit_state(&mut candidate)?;
        }
        #[cfg(not(feature = "native-v6-storage"))]
        {
            reset
                .validate_candidate(
                    &self.state.as_ref().ok_or_else(rejected)?.auth,
                    &candidate.auth,
                )
                .map_err(|error| Response::error(error.status, &error.message))?;
            self.commit_state(&mut candidate)?;
        }
        let _ = self.install_committed_namespace_view(candidate);
        gate()?;
        if self.policy_default_activation()? != Some(activation.clone()) {
            return Err(rejected());
        }
        self.audit_event(
            "policy-default-activated",
            &fingerprint,
            at.seconds(),
            Some(204),
        )
        .map_err(|_| rejected())?;
        gate()?;
        if self.policy_default_activation()? != Some(activation.clone()) {
            return Err(rejected());
        }
        self.policy_default_activation = Some(activation);
        Ok(())
    }

    pub(super) fn maintain_default_policy_activation(&mut self, clock: Option<RequestClock>) {
        if self.state.is_none() || self.recovery_required || self.audit_failed {
            return;
        }
        if self.complete_default_policy_activation(clock).is_err() {
            // A committed-unknown result keeps the existing recovery fence.
            // A prepublication error leaves activation incomplete for a later
            // fresh lifecycle pass; it does not replay a previous write owner.
            self.ha_activation = None;
        }
    }
}

#[cfg(test)]
#[path = "service_policy_startup_tests.rs"]
mod tests;
