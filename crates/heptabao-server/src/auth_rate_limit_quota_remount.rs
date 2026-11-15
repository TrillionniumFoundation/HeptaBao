//! Move only quota factors bound to the actual selected mount. The caller
//! publishes this Auth candidate in the same transaction as the mount graph.
use super::*;

impl Registry {
    fn relocated_mount(&self, namespace: &str, from: &str, to: &str) -> Result<Self, AuthError> {
        self.validate()?;
        validate_namespace(namespace)?;
        if from == to || !from.ends_with('/') || !to.ends_with('/') {
            return Err(bad("quota remount requires distinct canonical mounts"));
        }
        validate_path(from.trim_end_matches('/'), false)?;
        validate_path(to.trim_end_matches('/'), false)?;
        let selected = self
            .definitions
            .values()
            .filter_map(|definition| match self.selector_for(definition) {
                Ok(selector) if selector.namespace() == namespace && selector.mount() == from => {
                    Some(Ok((definition.name.clone(), selector)))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut candidate = self.clone();
        for (name, selected) in selected {
            let selector = selected.relocated_mount(to)?;
            let revision = candidate.next_revision;
            candidate.next_revision = revision
                .checked_add(1)
                .ok_or_else(|| err(507, "quota revision exhausted"))?;
            let definition = candidate
                .definitions
                .get_mut(&name)
                .ok_or_else(|| err(503, "quota remount definition changed"))?;
            definition.path = selector.path();
            definition.revision = revision;
            selector.validate(definition)?;
            if let std::collections::btree_map::Entry::Occupied(mut entry) =
                candidate.selectors.entry(name)
            {
                entry.insert(selector);
            } else {
                // A legacy 134/137 AppRole factor remains on its old reader
                // contract. Generic/child factors already carry schema139.
                definition.validate()?;
            }
        }
        // Exact factor collisions and capacity failures reject the detached
        // candidate before either owner can be published.
        candidate.validate()?;
        Ok(candidate)
    }
}

impl AuthState {
    pub(in crate::auth) fn relocated_rate_limit_quotas(
        &self,
        namespace: &str,
        from: &str,
        to: &str,
    ) -> Result<Option<Registry>, AuthError> {
        self.rate_limit_quotas
            .as_ref()
            .map(|registry| registry.relocated_mount(namespace, from, to))
            .transpose()
    }

    pub(crate) fn relocate_rate_limit_quotas(
        &mut self,
        namespace: &str,
        from: &str,
        to: &str,
    ) -> Result<(), AuthError> {
        let candidate = self.relocated_rate_limit_quotas(namespace, from, to)?;
        self.rate_limit_quotas = candidate;
        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_rate_limit_quota_remount_tests.rs"]
mod tests;
