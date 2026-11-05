//! Exact fresh namespace Auth metadata, no credentials. The caller's actual
//! native plan and terminal delivery owner remain independently mandatory.
use super::*;
use std::collections::BTreeSet;

impl AuthState {
    /// Remove only a selected child's quota factors and exact fresh factory
    /// defaults. Any credential, policy, history, lease, MFA or pending owner
    /// keeps the original deletion fence. This mutates a detached candidate;
    /// the actual namespace capsule still supplies the full delta proof.
    pub(crate) fn retire_native_flat_namespace_auth(
        &mut self,
        namespace: &str,
        binding: &crate::namespace_custody::Binding,
    ) -> Result<(), AuthError> {
        if binding.namespace() != namespace {
            return Err(err(503, "namespace factory retirement binding changed"));
        }
        let mut next = self.clone();
        next.remove_factory_default_from_candidate(binding)?;
        next.prune_rate_limit_quotas_namespace(namespace)?;
        if !next.namespace_is_empty(namespace)
            || next
                .native_remount_epochs
                .keys()
                .any(|(scope, _)| scope == namespace)
            || next
                .approle_tidy_epochs
                .keys()
                .any(|(scope, _)| scope == namespace)
            || next.auth_mounts.get(namespace) != Some(&userpass_names::fresh_default_auth_mounts())
        {
            return Err(err(
                409,
                "namespace contains an Auth owner requiring separate cleanup",
            ));
        }
        next.remove_fresh_namespace_auth_defaults(namespace);
        next.validate_rate_limit_quota_state(Some(self))?;
        *self = next;
        Ok(())
    }

    pub(crate) fn native_empty_namespace_auth_profile(&self, paths: &BTreeSet<String>) -> bool {
        let mut root = self.clone();
        for path in paths {
            if path.is_empty()
                || !self.namespace_is_empty(path)
                || self.auth_mounts.get(path) != Some(&userpass_names::fresh_default_auth_mounts())
            {
                return false;
            }
            // Only exact freshly issued factory metadata is normalized. No
            // token, role, lease, policy, history or retired owner is removed.
            root.auth_mounts.remove(path);
        }
        // The caller must name every actual child. The broader capability
        // predicate must not make an omitted catalog path invisible here.
        root.auth_mounts.keys().all(String::is_empty) && root.supports_native_v6_root_storage()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_empty_namespace_defaults_do_not_grant_a_credential()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut auth, _) = AuthState::bootstrap(1)?;
        let names = BTreeSet::from(["cg-other".to_owned()]);
        auth.initialize_fresh_namespace_auth("cg-other")?;
        assert!(auth.native_empty_namespace_auth_profile(&names));
        assert!(auth.namespace_is_empty("cg-other"));
        assert!(!auth.native_empty_namespace_auth_profile(&BTreeSet::new()));
        Ok(())
    }

    #[test]
    fn historical_factory_mounts_are_not_fresh_native_empty_namespace_defaults()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut auth, _) = AuthState::bootstrap(1)?;
        auth.auth_mounts.insert(
            "cg-other".to_owned(),
            userpass_names::prior_native_default_auth_mounts(),
        );
        assert!(
            !auth.native_empty_namespace_auth_profile(&BTreeSet::from(["cg-other".to_owned(),]))
        );
        Ok(())
    }
}
