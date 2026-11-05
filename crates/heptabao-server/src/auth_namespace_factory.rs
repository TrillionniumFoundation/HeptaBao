//! Durable provenance for one genuine new child namespace's default policy.
//! The marker is a structural owner invariant, never request authority. Only
//! the actual Service catalog creation owner may install a prepared seed.
use super::*;
use crate::namespace_custody::Binding;

pub(crate) const STATE_SCHEMA: u32 = 144;

fn rejected() -> AuthError {
    err(503, "namespace default factory owner changed")
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CreationTime {
    Coarse { seconds: u64 },
    Precise { at: Timestamp },
}

impl CreationTime {
    fn from_authority(time: AuthorityTime) -> Self {
        match time {
            AuthorityTime::Coarse(seconds) => Self::Coarse { seconds },
            AuthorityTime::Precise(at) => Self::Precise { at },
        }
    }

    fn authority(self) -> AuthorityTime {
        match self {
            Self::Coarse { seconds } => AuthorityTime::Coarse(seconds),
            Self::Precise { at } => AuthorityTime::Precise(at),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Origin {
    format: u32,
    binding: Binding,
    created: CreationTime,
}

fn default_at(time: AuthorityTime) -> Result<Policy, AuthError> {
    security_contract::prepare_policy(
        None,
        &json!({"policy": default_policy_source(), "cas": -1}),
        false,
        false,
        time,
    )
}

fn policies_equal(left: &Policy, right: &Policy) -> Result<bool, AuthError> {
    let left = crate::secret_serde::to_vec(left, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| rejected())?;
    let right = crate::secret_serde::to_vec(right, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| rejected())?;
    Ok(left.as_slice() == right.as_slice())
}

impl Policy {
    pub(super) fn validate_namespace_factory(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), AuthError> {
        let Some(origin) = &self.namespace_factory else {
            return Ok(());
        };
        if namespace.is_empty()
            || name != "default"
            || origin.format != 1
            || origin.binding.namespace() != namespace
            || origin.binding.incarnation() == 0
        {
            return Err(rejected());
        }
        let expected = default_at(origin.created.authority())?;
        let mut actual = self.clone();
        actual.namespace_factory = None;
        if !policies_equal(&actual, &expected)? {
            return Err(rejected());
        }
        Ok(())
    }
}

/// Captured once from the original successful creation authorization. Repeated
/// native candidate/check calls reuse these identical bytes; no clock is read.
pub(crate) struct PreparedChild {
    policy: Policy,
}

impl PreparedChild {
    pub(crate) fn new(binding: Binding, time: AuthorityTime) -> Result<Self, AuthError> {
        if binding.namespace().is_empty() || binding.incarnation() == 0 {
            return Err(rejected());
        }
        let mut policy = default_at(time)?;
        policy.namespace_factory = Some(Origin {
            format: 1,
            binding,
            created: CreationTime::from_authority(time),
        });
        Ok(Self { policy })
    }

    pub(crate) fn install(&self, auth: &mut AuthState, actual: &Binding) -> Result<(), AuthError> {
        if self
            .policy
            .namespace_factory
            .as_ref()
            .is_none_or(|origin| &origin.binding != actual)
        {
            return Err(rejected());
        }
        self.policy
            .validate_namespace_factory(actual.namespace(), "default")?;
        // Keep the original strict empty/absent Auth guard. This never repairs
        // an existing namespace, explicit policy or legacy implicit default.
        auth.initialize_fresh_namespace_auth(actual.namespace())?;
        auth.policies
            .entry(actual.namespace().to_owned())
            .or_default()
            .insert("default".into(), self.policy.clone());
        Ok(())
    }
}

impl AuthState {
    pub(crate) fn has_namespace_factory_state(&self) -> bool {
        self.policies
            .values()
            .flat_map(BTreeMap::values)
            .any(|policy| policy.namespace_factory.is_some())
    }

    pub(crate) fn validate_namespace_factory_state(
        &self,
        mut actual_binding: impl FnMut(&str) -> Result<Binding, ()>,
    ) -> Result<(), AuthError> {
        for (namespace, policies) in &self.policies {
            for (name, policy) in policies {
                policy.validate_namespace_factory(namespace, name)?;
                if let Some(origin) = &policy.namespace_factory
                    && actual_binding(namespace).map_err(|_| rejected())? != origin.binding
                {
                    return Err(rejected());
                }
            }
        }
        Ok(())
    }

    pub(super) fn remove_factory_default_from_candidate(
        &mut self,
        actual: &Binding,
    ) -> Result<bool, AuthError> {
        let namespace = actual.namespace();
        let Some(policy) = self
            .policies
            .get(namespace)
            .and_then(|entries| entries.get("default"))
        else {
            return Ok(false);
        };
        let Some(origin) = &policy.namespace_factory else {
            return Ok(false);
        };
        policy.validate_namespace_factory(namespace, "default")?;
        if &origin.binding != actual {
            return Err(rejected());
        }
        let policies = self.policies.get_mut(namespace).ok_or_else(rejected)?;
        policies.remove("default");
        if policies.is_empty() {
            self.policies.remove(namespace);
        }
        Ok(true)
    }

    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn without_namespace_factory_defaults(
        &self,
        actual: &BTreeMap<String, Binding>,
    ) -> Result<Self, AuthError> {
        let mut normalized = self.clone();
        for (namespace, binding) in actual {
            if namespace != binding.namespace() {
                return Err(rejected());
            }
            normalized.remove_factory_default_from_candidate(binding)?;
        }
        Ok(normalized)
    }

    /// The caller additionally proves the original engine/database/workflow
    /// emptiness and owns the complete catalog retirement transaction.
    pub(crate) fn retire_empty_namespace_factory_default(
        &mut self,
        actual: &Binding,
    ) -> Result<bool, AuthError> {
        let mut normalized = self.clone();
        if !normalized.remove_factory_default_from_candidate(actual)?
            || !normalized.namespace_is_empty(actual.namespace())
        {
            return Ok(false);
        }
        *self = normalized;
        Ok(true)
    }
}

#[cfg(test)]
#[path = "auth_namespace_factory_tests.rs"]
mod tests;
