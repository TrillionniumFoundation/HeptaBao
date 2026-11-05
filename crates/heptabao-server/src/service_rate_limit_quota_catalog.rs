//! Read-only quota routing factors from the currently admitted State catalog.
//! This lookup performs no login, provider call, token use or storage mutation.
use super::*;
use crate::auth::AuthError;
use crate::auth::rate_limit_quotas::Target;

fn invalid() -> AuthError {
    AuthError {
        status: 400,
        message: "quota path does not identify an actual namespace or mount".into(),
    }
}

fn role_resolving_kind(kind: &str) -> bool {
    matches!(kind, "approle" | "cert" | "jwt" | "oidc" | "kubernetes")
}

pub(super) struct QuotaRoutingFactors<'a> {
    pub(super) namespace: &'a str,
    pub(super) mount: Option<String>,
}

impl State {
    pub(super) fn rate_limit_quota_routing_factors<'a>(
        &self,
        namespace: &'a str,
        path: &str,
    ) -> QuotaRoutingFactors<'a> {
        if !self.namespace_exists(namespace) {
            // 2.7.1's namespace resolver returns (nil, "") for an unresolved
            // namespace header. Its quota wrapper substitutes root but keeps
            // an empty mount, even when the original path names a root mount.
            // The logical request keeps its original namespace and rejection.
            return QuotaRoutingFactors {
                namespace: "",
                mount: None,
            };
        }
        QuotaRoutingFactors {
            namespace,
            mount: self
                .rate_limit_quota_mount(namespace, path)
                .map(|(mount, _)| mount),
        }
    }

    pub(super) fn rate_limit_quota_mount(
        &self,
        namespace: &str,
        path: &str,
    ) -> Option<(String, String)> {
        let mut mounts = self.engines.ui_secret_mounts(namespace);
        mounts.extend(self.auth.ui_auth_mounts(namespace));
        mounts
            .into_iter()
            .filter(|(mount, _)| path.starts_with(mount.as_str()))
            .max_by_key(|(mount, _)| mount.len())
            .and_then(|(mount, entry)| {
                entry
                    .get("type")
                    .and_then(Value::as_str)
                    .map(|kind| (mount, kind.to_owned()))
            })
    }

    pub(super) fn rate_limit_quota_target(
        &self,
        namespace: &str,
        body: &Value,
    ) -> Result<Target, AuthError> {
        let supplied = body
            .get("path")
            .map(|value| value.as_str().ok_or_else(invalid))
            .transpose()?
            .unwrap_or("");
        if supplied.len() > 4096 || !namespace.is_empty() {
            return Err(invalid());
        }
        // Quota management is root-only. Match 2.7.1 sanitizePath: add one
        // trailing delimiter when absent, then remove one leading delimiter.
        // Its absolute public path can identify an existing child catalog.
        let sanitized = if supplied.ends_with('/') {
            supplied.to_owned()
        } else {
            format!("{supplied}/")
        };
        let sanitized = sanitized.strip_prefix('/').unwrap_or(&sanitized);
        let combined = sanitized.to_owned();
        let mut selected_namespace = "";
        for (index, byte) in combined.bytes().enumerate() {
            if byte == b'/' {
                let candidate = &combined[..index];
                if candidate.len() >= selected_namespace.len() && self.namespace_exists(candidate) {
                    selected_namespace = candidate;
                }
            }
        }
        let relative = if selected_namespace.is_empty() {
            combined.as_str()
        } else {
            combined
                .strip_prefix(selected_namespace)
                .and_then(|value| value.strip_prefix('/'))
                .ok_or_else(invalid)?
        };
        if relative.is_empty() {
            return Target::from_catalog(selected_namespace, "", "", false, false);
        }
        let (mount, kind) = self
            .rate_limit_quota_mount(selected_namespace, relative)
            .ok_or_else(invalid)?;
        let suffix = relative.strip_prefix(&mount).ok_or_else(invalid)?;
        let suffix = suffix.strip_suffix('/').unwrap_or(suffix);
        Target::from_catalog(
            selected_namespace,
            &mount,
            suffix,
            kind == "approle",
            role_resolving_kind(&kind),
        )
    }

    pub(super) fn validate_rate_limit_quota_catalog(&self) -> Result<(), Response> {
        let Some(registry) = self.auth.rate_limit_quota_registry() else {
            return Ok(());
        };
        for (name, selector) in registry.scoped_selectors() {
            let reject = || {
                Response::error(
                    503,
                    "persisted quota selector has no matching catalog owner",
                )
            };
            if !self.namespace_exists(selector.namespace()) {
                return Err(reject());
            }
            if selector.mount().is_empty() {
                continue;
            }
            let (mount, kind) = self
                .rate_limit_quota_mount(selector.namespace(), selector.mount())
                .ok_or_else(reject)?;
            let definition = registry.definitions.get(name).ok_or_else(reject)?;
            if mount != selector.mount()
                || (!definition.role.is_empty() && !role_resolving_kind(&kind))
            {
                return Err(reject());
            }
        }
        Ok(())
    }
}
