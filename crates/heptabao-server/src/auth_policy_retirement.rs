//! Fixed lazy GetPolicy deletion, bound to one admitted actor and observation.
//! This is not an ACL grant, a token-use delta, or a new authentication path.
use super::*;

/// Only the two checked constructors below can select policy names. Keep the
/// original affine actor borrowed until the ordinary/native writer finishes.
pub(crate) struct PolicyRetirement<'a> {
    actor: &'a Principal,
    namespace: String,
    observed_at: AuthorityTime,
    actor_identity_policies: BTreeSet<String>,
    target: Option<InspectionTarget>,
    entries: BTreeMap<String, Zeroizing<Vec<u8>>>,
}

fn rejected() -> AuthError {
    err(503, "original policy retirement observation is unavailable")
}

fn live() -> Result<(), AuthError> {
    if crate::request_deadline::current()
        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        return Err(rejected());
    }
    Ok(())
}

fn encoded_policy(policy: &Policy) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    live()?;
    let encoded = crate::secret_serde::to_vec(policy, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| rejected())?;
    live()?;
    Ok(encoded)
}

impl<'a> PolicyRetirement<'a> {
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn actor(&self) -> &Principal {
        self.actor
    }

    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) fn target(&self) -> Option<&InspectionTarget> {
        self.target.as_ref()
    }

    #[cfg(feature = "native-v6-storage")]
    pub(crate) fn observed_at(&self) -> AuthorityTime {
        self.observed_at
    }

    pub(crate) fn check_actor(
        &self,
        source: &AuthState,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        live()?;
        let ordered = match (self.observed_at, time) {
            (AuthorityTime::Precise(before), AuthorityTime::Precise(now)) => now >= before,
            (AuthorityTime::Coarse(before), AuthorityTime::Coarse(now)) => now >= before,
            (AuthorityTime::Coarse(before), AuthorityTime::Precise(now)) => now.seconds() >= before,
            (AuthorityTime::Precise(_), AuthorityTime::Coarse(_)) => false,
        };
        if !ordered || self.actor.identity_policies != self.actor_identity_policies {
            return Err(rejected());
        }
        source.check_principal_observed(self.actor, &self.namespace, time)?;
        Ok(())
    }

    fn check_entries(&self, source: &AuthState) -> Result<(), AuthError> {
        // Validate every preimage before changing any owner. A fresh rewrite,
        // an already applied batch, or a different namespace never matches.
        for (name, original) in &self.entries {
            live()?;
            let current = source
                .policies
                .get(&self.namespace)
                .and_then(|policies| policies.get(name))
                .ok_or_else(rejected)?;
            if current.expiration.is_none()
                || current.expired_default
                || current.live(self.observed_at)?
                || encoded_policy(current)?.as_slice() != original.as_slice()
            {
                return Err(rejected());
            }
        }
        Ok(())
    }

    pub(crate) fn apply(&self, candidate: &mut AuthState) -> Result<bool, AuthError> {
        self.check_entries(candidate)?;
        if self.entries.is_empty() {
            return Ok(false);
        }
        let policies = candidate
            .policies
            .get_mut(&self.namespace)
            .ok_or_else(rejected)?;
        live()?;
        for name in self.entries.keys() {
            if name == "default" {
                // The running process must not regain the compiled fallback.
                // Active unseal recreation is a separate startup operation.
                policies.insert(name.clone(), Policy::expired_default());
            } else {
                policies.remove(name);
            }
        }
        Ok(true)
    }

    /// The complete candidate Auth owner must equal this one fixed batch.
    /// Finite-use consumption and terminal-clock deltas remain separate.
    pub(crate) fn validate_candidate(
        &self,
        source: &AuthState,
        candidate: &AuthState,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        self.check_actor(source, time)?;
        let mut expected = source.clone();
        if !self.apply(&mut expected)? {
            return Err(rejected());
        }
        let expected = crate::secret_serde::to_vec(&expected, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| rejected())?;
        let actual = crate::secret_serde::to_vec(candidate, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| rejected())?;
        live()?;
        if expected.as_slice() != actual.as_slice() {
            return Err(rejected());
        }
        Ok(())
    }
}

impl AuthState {
    pub(crate) fn actor_policy_retirement<'a>(
        &self,
        actor: &'a Principal,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<PolicyRetirement<'a>, AuthError> {
        let time = actor.request_authority_time(time)?;
        let token = self.check_principal_observed(actor, namespace, time)?;
        // These admitted synthetic authorities do not consult stored ACLs.
        // In particular, a control-group unwrap retains its deferred exact
        // one-use transaction rather than passing through this writer.
        let names = if token.is_root()
            || token.is_wrapping()
            || self.control_groups_token_permission(actor, "sys/wrapping/unwrap", "update")
        {
            BTreeSet::new()
        } else {
            token
                .policies()
                .union(&actor.identity_policies)
                .cloned()
                .collect()
        };
        self.capture_policy_retirement(actor, namespace, None, &names, time)
    }

    /// `target` can only be constructed by the existing read-only inspection
    /// selector. Service has already checked the original request fields and
    /// the actual target Identity projection before supplying its policy set.
    pub(crate) fn inspection_policy_retirement<'a>(
        &self,
        actor: &'a Principal,
        namespace: &str,
        target: InspectionTarget,
        identity_policies: &BTreeSet<String>,
        time: AuthorityTime,
    ) -> Result<PolicyRetirement<'a>, AuthError> {
        let time = actor.request_authority_time(time)?;
        self.check_principal_observed(actor, namespace, time)?;
        let names = target
            .retirement_policies()
            .map_or_else(BTreeSet::new, |policies| {
                policies.union(identity_policies).cloned().collect()
            });
        self.capture_policy_retirement(actor, namespace, Some(target), &names, time)
    }

    fn capture_policy_retirement<'a>(
        &self,
        actor: &'a Principal,
        namespace: &str,
        target: Option<InspectionTarget>,
        names: &BTreeSet<String>,
        time: AuthorityTime,
    ) -> Result<PolicyRetirement<'a>, AuthError> {
        let mut entries = BTreeMap::new();
        for name in names {
            live()?;
            let Some(policy) = self
                .policies
                .get(namespace)
                .and_then(|policies| policies.get(name))
            else {
                continue;
            };
            // Path expiry changes evaluation, not the stored whole policy.
            // An existing default tombstone is an exact empty delta.
            if policy.expiration.is_some() && !policy.live(time)? {
                entries.insert(name.clone(), encoded_policy(policy)?);
            }
        }
        Ok(PolicyRetirement {
            actor,
            namespace: namespace.to_owned(),
            observed_at: time,
            actor_identity_policies: actor.identity_policies.clone(),
            target,
            entries,
        })
    }
}

#[cfg(test)]
#[path = "auth_policy_retirement_tests.rs"]
mod tests;
