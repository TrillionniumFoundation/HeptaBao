//! Global authenticated batch scope. Routing catalogs may be detached while
//! closed; only actual namespace creation and retirement change this ledger.
use super::*;

const MAX_LIFECYCLE_PATHS: usize = 4096;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    cluster_id: String,
    namespace: String,
    incarnation: u64,
}

impl Drop for Binding {
    fn drop(&mut self) {
        self.cluster_id.zeroize();
        self.namespace.zeroize();
    }
}

impl Binding {
    pub(super) fn incarnation(&self) -> u64 {
        self.incarnation
    }

    pub(crate) fn validate(&self, namespace: &str) -> Result<(), AuthError> {
        validate_namespace(&self.namespace)?;
        if self.namespace != namespace
            || self.cluster_id.is_empty()
            || self.cluster_id.len() > 128
            || !self.cluster_id.bytes().all(|byte| byte.is_ascii_graphic())
            || (namespace.is_empty() && self.incarnation != 0)
            || (!namespace.is_empty() && self.incarnation == 0)
        {
            return Err(err(503, "invalid batch namespace binding"));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    cluster_id: String,
    active: BTreeMap<String, u64>,
    next_incarnation: BTreeMap<String, u64>,
    /// Legacy claims have no incarnation. Once retired, that path can never
    /// accept them again, including after a new namespace uses the same name.
    retired_legacy_paths: BTreeSet<String>,
}

impl Registry {
    /// The Service must prove that every actual catalog is visible before
    /// adopting a historical ledger. This constructor never infers hidden rows.
    pub(crate) fn adopt_visible(
        cluster_id: &str,
        mut active: BTreeMap<String, u64>,
        next_incarnation: BTreeMap<String, u64>,
    ) -> Result<Self, AuthError> {
        active.insert(String::new(), 0);
        let value = Self {
            cluster_id: cluster_id.to_owned(),
            active,
            retired_legacy_paths: next_incarnation.keys().cloned().collect(),
            next_incarnation,
        };
        value.validate(cluster_id)?;
        Ok(value)
    }

    pub(crate) fn validate(&self, cluster_id: &str) -> Result<(), AuthError> {
        if self.cluster_id != cluster_id
            || cluster_id.is_empty()
            || cluster_id.len() > 128
            || !cluster_id.bytes().all(|byte| byte.is_ascii_graphic())
            || self.active.get("") != Some(&0)
            || self.active.len() > MAX_LIFECYCLE_PATHS
            || self.next_incarnation.len() > MAX_LIFECYCLE_PATHS
            || self.retired_legacy_paths.len() > MAX_LIFECYCLE_PATHS
        {
            return Err(err(503, "invalid namespace batch lifecycle registry"));
        }
        for (path, incarnation) in &self.active {
            self.binding(path)?.validate(path)?;
            if !path.is_empty() {
                let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
                if !self.active.contains_key(parent)
                    || self
                        .next_incarnation
                        .get(path)
                        .is_some_and(|next| next <= incarnation)
                {
                    return Err(err(503, "invalid namespace batch active frontier"));
                }
            }
        }
        for (path, next) in &self.next_incarnation {
            validate_namespace(path)?;
            if path.is_empty() || *next < 2 {
                return Err(err(503, "invalid namespace batch next incarnation"));
            }
        }
        for path in &self.retired_legacy_paths {
            validate_namespace(path)?;
            if path.is_empty() || !self.next_incarnation.contains_key(path) {
                return Err(err(503, "batch legacy retirement lacks actual frontier"));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_successor(&self, old: &Self) -> Result<(), AuthError> {
        self.validate(&old.cluster_id)?;
        old.validate(&old.cluster_id)?;
        if !old
            .retired_legacy_paths
            .is_subset(&self.retired_legacy_paths)
            || old.next_incarnation.iter().any(|(path, frontier)| {
                self.next_incarnation
                    .get(path)
                    .is_none_or(|next| next < frontier)
            })
        {
            return Err(err(
                503,
                "namespace batch retirement frontier cannot decrease",
            ));
        }
        for (path, incarnation) in &old.active {
            match self.active.get(path) {
                Some(next) if next == incarnation => {}
                Some(next) if next > incarnation => {
                    if !self.retired_legacy_paths.contains(path)
                        || self
                            .next_incarnation
                            .get(path)
                            .is_none_or(|frontier| frontier <= next)
                    {
                        return Err(err(503, "batch reincarnation lacks actual retirement"));
                    }
                }
                None if !path.is_empty() => {
                    if !self.retired_legacy_paths.contains(path)
                        || self
                            .next_incarnation
                            .get(path)
                            .is_none_or(|next| next <= incarnation)
                    {
                        return Err(err(
                            503,
                            "batch scope disappeared without actual retirement",
                        ));
                    }
                }
                _ => return Err(err(503, "namespace batch incarnation cannot decrease")),
            }
        }
        Ok(())
    }

    pub(crate) fn binding(&self, namespace: &str) -> Result<Binding, AuthError> {
        let incarnation = self.active.get(namespace).copied().ok_or_else(denied)?;
        Ok(Binding {
            cluster_id: self.cluster_id.clone(),
            namespace: namespace.to_owned(),
            incarnation,
        })
    }

    /// Retired owners remain valid saved cleanup records. The known actual
    /// frontier proves an issued incarnation; it confers no current liveness.
    fn validate_saved_binding(&self, binding: &Binding, namespace: &str) -> Result<(), AuthError> {
        binding.validate(namespace)?;
        if binding.cluster_id != self.cluster_id
            || !(self.active.get(namespace) == Some(&binding.incarnation)
                || self
                    .next_incarnation
                    .get(namespace)
                    .is_some_and(|next| !namespace.is_empty() && binding.incarnation < *next))
        {
            return Err(err(
                503,
                "saved batch namespace owner lacks actual frontier",
            ));
        }
        Ok(())
    }

    pub(crate) fn check(
        &self,
        binding: Option<&Binding>,
        namespace: &str,
    ) -> Result<(), AuthError> {
        let current = self.binding(namespace)?;
        match binding {
            Some(binding) if binding == &current => binding.validate(namespace),
            None if !self.retired_legacy_paths.contains(namespace) => Ok(()),
            _ => Err(denied()),
        }
    }

    pub(crate) fn matches_catalog(
        &self,
        visible: &BTreeMap<String, u64>,
        next_incarnation: &BTreeMap<String, u64>,
    ) -> bool {
        &self.next_incarnation == next_incarnation
            && visible
                .iter()
                .all(|(path, incarnation)| self.active.get(path) == Some(incarnation))
    }

    pub(crate) fn active_paths(&self) -> impl Iterator<Item = &str> {
        self.active.keys().map(String::as_str)
    }

    pub(crate) fn record_create(
        &mut self,
        path: &str,
        incarnation: u64,
        next: Option<u64>,
    ) -> Result<(), AuthError> {
        if path.is_empty()
            || self.active.contains_key(path)
            || self
                .next_incarnation
                .get(path)
                .is_some_and(|old| incarnation < *old)
        {
            return Err(err(
                503,
                "namespace batch creation conflicts with actual lifecycle",
            ));
        }
        self.active.insert(path.to_owned(), incarnation);
        if let Some(next) = next {
            self.next_incarnation.insert(path.to_owned(), next);
        }
        self.validate(&self.cluster_id)
    }

    pub(crate) fn record_remove(
        &mut self,
        path: &str,
        incarnation: u64,
        next: u64,
    ) -> Result<(), AuthError> {
        let prefix = format!("{path}/");
        if path.is_empty()
            || self.active.get(path) != Some(&incarnation)
            || incarnation.checked_add(1) != Some(next)
            || self.active.keys().any(|child| child.starts_with(&prefix))
        {
            return Err(err(
                503,
                "namespace batch retirement conflicts with actual lifecycle",
            ));
        }
        self.active.remove(path);
        self.next_incarnation.insert(path.to_owned(), next);
        self.retired_legacy_paths.insert(path.to_owned());
        self.validate(&self.cluster_id)
    }
}

impl AuthState {
    pub(crate) fn namespace_batch_registry(&self) -> Option<&Registry> {
        self.namespace_batch_registry.as_ref()
    }

    pub(crate) fn install_namespace_batch_registry(
        &mut self,
        next: &Registry,
    ) -> Result<(), AuthError> {
        if let Some(old) = &self.namespace_batch_registry {
            next.validate_successor(old)?;
        }
        self.namespace_batch_registry = Some(next.clone());
        Ok(())
    }

    pub(crate) fn validate_namespace_batch_successor(
        &self,
        previous: &Self,
    ) -> Result<(), AuthError> {
        match (
            &self.namespace_batch_registry,
            &previous.namespace_batch_registry,
        ) {
            (Some(next), Some(old)) => next.validate_successor(old),
            (None, Some(_)) => Err(err(503, "namespace batch registry cannot retire")),
            _ => Ok(()),
        }
    }

    pub(super) fn validate_batch_namespace_owner_structure(
        &self,
        binding: Option<&Binding>,
        namespace: &str,
    ) -> Result<(), AuthError> {
        match (binding, &self.namespace_batch_registry) {
            (None, _) => Ok(()),
            (Some(binding), Some(registry)) => registry.validate_saved_binding(binding, namespace),
            (Some(_), None) => Err(err(503, "saved batch namespace owner requires lifecycle")),
        }
    }

    pub(super) fn check_batch_namespace_binding(
        &self,
        binding: Option<&Binding>,
        namespace: &str,
    ) -> Result<(), AuthError> {
        match &self.namespace_batch_registry {
            Some(registry) => registry.check(binding, namespace),
            None if binding.is_none() => Ok(()),
            None => Err(denied()),
        }
    }
}
