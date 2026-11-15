//! Persisted quota factors are separate from the public concatenated path.
//! A catalog-derived target is not an ACL or a storage publication grant.
use super::*;

#[derive(Clone, Serialize, Deserialize, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selector {
    namespace: String,
    mount: String,
    suffix: String,
}

impl Selector {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) fn mount(&self) -> &str {
        &self.mount
    }

    pub(super) fn relocated_mount(&self, mount: &str) -> Result<Self, AuthError> {
        let mut next = self.clone();
        next.mount = mount.into();
        next.validate_shape()?;
        Ok(next)
    }

    pub(crate) fn path(&self) -> String {
        let prefix = if self.namespace.is_empty() {
            String::new()
        } else {
            format!("{}/", self.namespace)
        };
        format!("{prefix}{}{}", self.mount, self.suffix)
    }

    fn validate_shape(&self) -> Result<(), AuthError> {
        validate_namespace(&self.namespace)?;
        if self.namespace.len() > 512
            || self.mount.len() > 2048
            || self.suffix.len() > 4096
            || self.mount.chars().any(char::is_control)
            || self.suffix.chars().any(char::is_control)
            || self.mount.starts_with('/')
            || self.mount.contains("//")
        {
            return Err(bad("invalid persisted quota selector"));
        }
        if self.mount.is_empty() {
            if !self.suffix.is_empty() {
                return Err(bad("namespace quota cannot contain a path suffix"));
            }
        } else if !self.mount.ends_with('/') {
            return Err(bad("quota mount must retain its canonical delimiter"));
        }
        Ok(())
    }

    pub(super) fn validate(&self, definition: &Definition) -> Result<(), AuthError> {
        self.validate_shape()?;
        definition.validate_limits()?;
        if definition.path != self.path()
            || (!definition.role.is_empty()
                && (!self.suffix.is_empty() || !self.mount.starts_with("auth/")))
        {
            return Err(bad("quota selector does not match its public definition"));
        }
        Ok(())
    }

    pub(super) fn legacy(definition: &Definition) -> Result<Self, AuthError> {
        definition.validate()?;
        let (mount, suffix) = if definition.path.is_empty() {
            (String::new(), String::new())
        } else if let Some(mount) = definition.path.strip_suffix("/login") {
            (format!("{mount}/"), "login".to_owned())
        } else {
            (definition.path.clone(), String::new())
        };
        Ok(Self {
            namespace: String::new(),
            mount,
            suffix,
        })
    }
}

/// Only the Service's live catalog resolver supplies this value. The Auth
/// handler still checks the actual bearer, namespace and operation capability.
/// It is moved into that single operation and cannot be restored from JSON.
pub(crate) struct Target {
    selector: Selector,
    native_approle: bool,
    role_supported: bool,
}

impl Target {
    pub(crate) fn from_catalog(
        namespace: &str,
        mount: &str,
        suffix: &str,
        native_approle: bool,
        role_supported: bool,
    ) -> Result<Self, AuthError> {
        let selector = Selector {
            namespace: namespace.into(),
            mount: mount.into(),
            suffix: suffix.into(),
        };
        selector.validate_shape()?;
        if native_approle && (!mount.starts_with("auth/") || !role_supported) {
            return Err(bad("invalid native AppRole quota catalog binding"));
        }
        Ok(Self {
            selector,
            native_approle,
            role_supported,
        })
    }

    pub(crate) fn selector(&self) -> &Selector {
        &self.selector
    }

    pub(super) fn default_inheritable(&self) -> bool {
        self.selector.namespace.is_empty() && self.selector.mount.is_empty()
    }

    pub(super) fn admit_role(&self, role: &str) -> Result<(), AuthError> {
        if !role.is_empty() && (!self.role_supported || !self.selector.suffix.is_empty()) {
            return Err(bad(
                "quota role requires an actual role-resolving auth mount",
            ));
        }
        Ok(())
    }

    pub(super) fn requires_scoped_reader(&self, definition: &Definition) -> bool {
        if !self.selector.namespace.is_empty() {
            return true;
        }
        if self.selector.mount.is_empty() {
            return false;
        }
        !self.native_approle
            || definition.inheritable
            || !(self.selector.suffix.is_empty()
                || self.selector.suffix == "login" && definition.role.is_empty())
    }

    pub(super) fn into_selector(self) -> Selector {
        self.selector
    }
}

impl Registry {
    pub(crate) fn has_role_scope(&self, namespace: &str, mount: &str) -> Result<bool, AuthError> {
        for definition in self
            .definitions
            .values()
            .filter(|definition| !definition.role.is_empty())
        {
            let selector = self.selector_for(definition)?;
            if selector.namespace == namespace && selector.mount == mount {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn scoped_selectors(&self) -> impl Iterator<Item = (&str, &Selector)> {
        self.selectors
            .iter()
            .map(|(name, selector)| (name.as_str(), selector))
    }

    pub(super) fn selector_for(&self, definition: &Definition) -> Result<Selector, AuthError> {
        self.selectors
            .get(&definition.name)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| Selector::legacy(definition))
    }

    /// OpenBao 2.7.1 selects a single bucket. It never also debits a less
    /// specific namespace or mount bucket after a more specific match.
    pub(crate) fn select(
        &self,
        namespace: &str,
        mount: Option<&str>,
        path: &str,
        role: &str,
    ) -> Result<Option<&Definition>, AuthError> {
        let suffix = mount
            .map(|mount| path.strip_prefix(mount).unwrap_or(""))
            .map(|suffix| suffix.strip_suffix('/').unwrap_or(suffix));
        let mut selected: Option<((u8, usize), &Definition)> = None;
        for definition in self.definitions.values() {
            let selector = self.selector_for(definition)?;
            if selector.namespace != namespace {
                continue;
            }
            let rank = if !definition.role.is_empty() {
                (mount == Some(selector.mount.as_str())
                    && !role.is_empty()
                    && definition.role == role)
                    .then_some((5, 0))
            } else if !selector.suffix.is_empty() {
                if mount != Some(selector.mount.as_str()) {
                    None
                } else if suffix == Some(selector.suffix.as_str()) {
                    Some((4, 0))
                } else {
                    selector
                        .suffix
                        .strip_suffix('*')
                        .filter(|prefix| suffix.is_some_and(|suffix| suffix.starts_with(*prefix)))
                        .map(|prefix| (3, prefix.len()))
                }
            } else if !selector.mount.is_empty() {
                (mount == Some(selector.mount.as_str())).then_some((2, 0))
            } else {
                Some((1, 0))
            };
            if let Some(rank) = rank
                && selected.as_ref().is_none_or(|(prior, _)| rank > *prior)
            {
                selected = Some((rank, definition));
            }
        }
        if let Some((_, definition)) = selected {
            return Ok(Some(definition));
        }
        let mut ancestor = namespace;
        while !ancestor.is_empty() {
            ancestor = ancestor.rsplit_once('/').map_or("", |(parent, _)| parent);
            for definition in self.definitions.values() {
                let selector = self.selector_for(definition)?;
                if selector.namespace == ancestor
                    && selector.mount.is_empty()
                    && definition.inheritable
                {
                    return Ok(Some(definition));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_139_preserves_old_literal_exemption_encoding_until_explicit_adoption()
    -> Result<(), Box<dyn std::error::Error>> {
        // These strings were accepted by the original 134/137 byte-based
        // validator. A new generic selector must not reinterpret that history.
        let historical = json!({
            "config": {
                "rate_limit_exempt_paths": ["sys/health*", "!literal", "unicode/\u{85}"],
                "enable_rate_limit_audit_logging": false,
                "enable_rate_limit_response_headers": false
            },
            "definitions": {},
            "next_revision": 1
        });
        let mut registry: Registry = serde_json::from_value(historical.clone())?;
        registry.validate()?;
        assert_eq!(serde_json::to_value(&registry)?, historical);
        assert!(!registry.exempt("sys/health"));
        assert!(registry.exempt("sys/health*literal"));
        assert!(registry.exempt("!literal/path"));
        registry.scoped_reader = true;
        registry.validate()?;
        assert!(!registry.exempt("sys/health"));
        assert!(registry.exempt("!literal/path"));
        registry.path_manager_exemptions = true;
        registry.validate()?;
        assert!(registry.exempt("sys/health"));
        assert!(!registry.exempt("!literal/path"));
        assert!(!registry.exempt("literal/path"));
        Ok(())
    }
}
