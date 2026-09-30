//! Mount discovery reveals registry metadata, never grants a data capability.
use super::*;

fn intersects_mount(pattern: &str, mount: &str) -> bool {
    let mount = mount.trim_end_matches('/');
    let glob = pattern.ends_with('*');
    let stem = pattern.strip_suffix('*').unwrap_or(pattern);
    let components: Vec<_> = stem.split('/').collect();
    let target: Vec<_> = mount.split('/').collect();
    for (index, value) in target.iter().enumerate() {
        let Some(component) = components.get(index) else {
            return glob;
        };
        if glob && index == components.len() - 1 {
            return *component == "+" || value.starts_with(component);
        }
        if *component != "+" && component != value {
            return false;
        }
    }
    // An exact mount-root rule or any descendant rule reveals the mount.
    true
}

impl AuthState {
    pub(crate) fn ui_auth_mounts(&self, namespace: &str) -> BTreeMap<String, Value> {
        self.effective_auth_mounts(namespace)
            .into_iter()
            .map(|(name, mount)| (format!("auth/{name}/"), mount.descriptor()))
            .collect()
    }

    pub(crate) fn ui_mount_visible(
        &self,
        principal: &Principal,
        namespace: &str,
        mount: &str,
        now: u64,
    ) -> Result<bool, AuthError> {
        validate_path(mount.trim_end_matches('/'), false)?;
        let token = self.check_principal(principal, namespace, now)?;
        if token.is_wrapping() {
            return Ok(false);
        }
        if token.is_root() {
            return Ok(true);
        }
        // Public 2.7 black-box observations include deny-only rules in mount
        // discovery. Actual requests continue through the normal ACL evaluator.
        for name in token.policies().iter().chain(&principal.identity_policies) {
            if let Some(policy) = self
                .policies
                .get(namespace)
                .and_then(|entries| entries.get(name))
            {
                for rule in &policy.rules {
                    if let Some(pattern) =
                        acl_template::render(&rule.path, &principal.identity_templates)?
                        && intersects_mount(&pattern, mount)
                    {
                        return Ok(true);
                    }
                }
            } else if name == "default"
                && acl::DEFAULT_RULES
                    .iter()
                    .any(|(pattern, _)| intersects_mount(pattern, mount))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::intersects_mount;

    #[test]
    fn policy_mount_intersection_respects_segments_globs_and_nested_mounts() {
        for pattern in [
            "secret",
            "secret/",
            "secret/data/item",
            "secret/*",
            "+/data/item",
            "*",
        ] {
            assert!(intersects_mount(pattern, "secret/"));
        }
        for pattern in [
            "secrets/data/item",
            "other/*",
            "secret",
            "+",
            "+/different/*",
        ] {
            assert!(!intersects_mount(pattern, "secret/nested/"));
        }
        assert!(intersects_mount("secret*", "secret/nested/"));
        assert!(intersects_mount("+/nested/data/item", "secret/nested/"));
        assert!(!intersects_mount("auth/userpass/login/*", "auth/approle/"));
    }
}
