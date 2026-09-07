#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Deterministic default-deny path policy evaluation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use heptabao_domain::{CanonicalPath, Id};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    Create,
    Read,
    Update,
    Delete,
    List,
    Sudo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    path_prefix: CanonicalPath,
    capabilities: BTreeSet<Capability>,
}

impl PolicyRule {
    pub fn new(
        path_prefix: CanonicalPath,
        capabilities: BTreeSet<Capability>,
    ) -> Result<Self, PolicyError> {
        if capabilities.is_empty() {
            return Err(PolicyError::EmptyCapabilities);
        }
        Ok(Self {
            path_prefix,
            capabilities,
        })
    }

    pub fn path_prefix(&self) -> &CanonicalPath {
        &self.path_prefix
    }

    pub fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }

    fn permits(&self, capability: Capability, path: &CanonicalPath) -> bool {
        path.matches_prefix(&self.path_prefix)
            && (self.capabilities.contains(&capability)
                || self.capabilities.contains(&Capability::Sudo))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    id: Id,
    rules: Vec<PolicyRule>,
}

impl Policy {
    pub fn new(id: Id, rules: Vec<PolicyRule>) -> Result<Self, PolicyError> {
        if rules.is_empty() {
            return Err(PolicyError::EmptyRules);
        }
        Ok(Self { id, rules })
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }
}

#[derive(Debug, Default)]
pub struct PolicyStore {
    policies: BTreeMap<Id, Policy>,
}

impl PolicyStore {
    pub fn insert(&mut self, policy: Policy) -> Result<(), PolicyError> {
        if self.policies.contains_key(policy.id()) {
            return Err(PolicyError::DuplicatePolicy);
        }
        self.policies.insert(policy.id().clone(), policy);
        Ok(())
    }

    pub fn remove(&mut self, id: &Id) -> Result<Policy, PolicyError> {
        self.policies.remove(id).ok_or(PolicyError::MissingPolicy)
    }

    pub fn get(&self, id: &Id) -> Result<&Policy, PolicyError> {
        self.policies.get(id).ok_or(PolicyError::MissingPolicy)
    }

    pub fn authorize(
        &self,
        policy_ids: &BTreeSet<Id>,
        capability: Capability,
        path: &CanonicalPath,
    ) -> bool {
        policy_ids.iter().any(|id| {
            self.policies.get(id).is_some_and(|policy| {
                policy
                    .rules()
                    .iter()
                    .any(|rule| rule.permits(capability, path))
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    EmptyCapabilities,
    EmptyRules,
    DuplicatePolicy,
    MissingPolicy,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyCapabilities => "policy rule has no capabilities",
            Self::EmptyRules => "policy has no rules",
            Self::DuplicatePolicy => "policy already exists",
            Self::MissingPolicy => "policy does not exist",
        })
    }
}

impl Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_is_default_deny_and_segment_bounded() -> Result<(), Box<dyn Error>> {
        let policy_id = Id::parse("reader")?;
        let mut capabilities = BTreeSet::new();
        capabilities.insert(Capability::Read);
        let rule = PolicyRule::new(CanonicalPath::parse("/secret/app")?, capabilities)?;
        let policy = Policy::new(policy_id.clone(), vec![rule])?;
        let mut store = PolicyStore::default();
        store.insert(policy)?;

        let mut assigned = BTreeSet::new();
        assigned.insert(policy_id);
        assert!(store.authorize(
            &assigned,
            Capability::Read,
            &CanonicalPath::parse("/secret/app/config")?
        ));
        assert!(!store.authorize(
            &assigned,
            Capability::Update,
            &CanonicalPath::parse("/secret/app/config")?
        ));
        assert!(!store.authorize(
            &assigned,
            Capability::Read,
            &CanonicalPath::parse("/secret/application")?
        ));
        assert!(!store.authorize(
            &BTreeSet::new(),
            Capability::Read,
            &CanonicalPath::parse("/secret/app")?
        ));
        Ok(())
    }

    #[test]
    fn duplicate_policy_is_rejected() -> Result<(), Box<dyn Error>> {
        let id = Id::parse("operator")?;
        let mut capabilities = BTreeSet::new();
        capabilities.insert(Capability::Sudo);
        let rule = PolicyRule::new(CanonicalPath::root(), capabilities)?;
        let policy = Policy::new(id, vec![rule])?;
        let mut store = PolicyStore::default();
        store.insert(policy.clone())?;
        assert_eq!(Err(PolicyError::DuplicatePolicy), store.insert(policy));
        Ok(())
    }
}
