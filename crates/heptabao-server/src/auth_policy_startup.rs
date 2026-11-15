//! The active Core startup creates a missing default policy after GetPolicy
//! has retired an expired one. This constructor cannot select another name,
//! namespace, policy body or an unexpired default.
use super::*;

fn rejected() -> AuthError {
    err(503, "default policy activation owner changed")
}

fn digest<T: Serialize>(value: &T) -> Result<[u8; 32], AuthError> {
    let bytes = crate::secret_serde::to_vec(value, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| rejected())?;
    Ok(crate::crypto::digest(&bytes))
}

pub(crate) struct DefaultPolicyReset {
    before: [u8; 32],
    replacement: Policy,
    observed_at: Timestamp,
}

impl AuthState {
    /// Construct a new unpublished root owner with the current built-in policy.
    /// This accepts no existing Auth owner and never repairs loaded old stores.
    pub(crate) fn bootstrap_current_root_with_default_policy(
        time: AuthorityTime,
    ) -> Result<(Self, String), AuthError> {
        let default = security_contract::prepare_policy(
            None,
            &json!({"policy": default_policy_source(), "cas": -1}),
            false,
            false,
            time,
        )?;
        let (mut auth, token) = Self::bootstrap(time.seconds())?;
        auth.policies
            .entry(String::new())
            .or_default()
            .insert("default".into(), default);
        Ok((auth, token))
    }

    pub(crate) fn default_policy_activation_needs_clock(&self) -> bool {
        self.policies
            .get("")
            .and_then(|entries| entries.get("default"))
            .is_some_and(|policy| policy.expired_default || policy.expiration.is_some())
    }

    // A missing historical default and every time-dependent policy retain the
    // original cold capture path, chosen before startup can attempt any write.
    pub(crate) fn cold_unseal_has_stable_default(&self) -> bool {
        self.policies
            .get("")
            .and_then(|entries| entries.get("default"))
            .is_some_and(|policy| !policy.expired_default && policy.expiration.is_none())
    }

    pub(crate) fn capture_default_policy_reset(
        &self,
        time: AuthorityTime,
    ) -> Result<Option<DefaultPolicyReset>, AuthError> {
        let time = self.token_api_observed_time(time);
        let Some(previous) = self
            .policies
            .get("")
            .and_then(|entries| entries.get("default"))
        else {
            // Historical absence already denotes this owner's built-in policy.
            return Ok(None);
        };
        if !previous.expired_default && previous.live(time)? {
            return Ok(None);
        }
        let observed_at = time.exact().ok_or_else(rejected)?;
        let replacement = security_contract::prepare_policy(
            None,
            &json!({"policy":default_policy_source()}),
            false,
            false,
            time,
        )?;
        Ok(Some(DefaultPolicyReset {
            before: digest(previous)?,
            replacement,
            observed_at,
        }))
    }
}

impl DefaultPolicyReset {
    pub(crate) fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    pub(crate) fn apply(&self, auth: &mut AuthState) -> Result<(), AuthError> {
        let entries = auth.policies.get_mut("").ok_or_else(rejected)?;
        let previous = entries.get("default").ok_or_else(rejected)?;
        if digest(previous)? != self.before
            || (!previous.expired_default
                && previous.live(AuthorityTime::Precise(self.observed_at))?)
        {
            return Err(rejected());
        }
        entries.insert("default".into(), self.replacement.clone());
        Ok(())
    }

    pub(crate) fn validate_candidate(
        &self,
        source: &AuthState,
        candidate: &AuthState,
    ) -> Result<(), AuthError> {
        let mut expected = source.clone();
        self.apply(&mut expected)?;
        let actual = crate::secret_serde::to_vec(candidate, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| rejected())?;
        let expected = crate::secret_serde::to_vec(&expected, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| rejected())?;
        if actual.as_slice() != expected.as_slice() {
            return Err(rejected());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_policy_startup_tests.rs"]
mod tests;
