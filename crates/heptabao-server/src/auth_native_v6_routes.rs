//! Select only in-process Auth owners for the native V6 writer.
//! Selection is not authentication; the existing domain dispatcher still owns ACLs.
use super::*;

impl AuthState {
    pub(crate) fn native_v6_local_auth_route(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        if !namespace.is_empty() {
            return false;
        }
        if path == "sys/policy"
            || path.starts_with("sys/policy/")
            || path == "sys/policies/acl"
            || path.starts_with("sys/policies/acl/")
            || path.starts_with("auth/token/")
        {
            return true;
        }
        let mounts = self.effective_auth_mounts(namespace);
        if let Some(suffix) = path.strip_prefix("sys/auth/") {
            let mount = suffix.strip_suffix("/tune").unwrap_or(suffix);
            return mounts
                .get(mount)
                .is_some_and(|entry| matches!(entry.kind.as_str(), "approle" | "cert"))
                || (matches!(method, "POST" | "PUT")
                    && !suffix.ends_with("/tune")
                    && body
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| matches!(kind, "approle" | "cert")));
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return false;
        };
        mounts.iter().any(|(mount, entry)| {
            let Some(suffix) = auth_path.strip_prefix(&format!("{mount}/")) else {
                return false;
            };
            match entry.kind.as_str() {
                "approle" => suffix == "login" || suffix == "role" || suffix.starts_with("role/"),
                "cert" => {
                    suffix == "login"
                        || suffix == "config"
                        || suffix == "certs"
                        || suffix.starts_with("certs/")
                }
                _ => false,
            }
        })
    }
}
