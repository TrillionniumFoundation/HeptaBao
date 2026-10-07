//! Read the existing AppRole credential without cloning its containing role.
//! Expiry is observed by tidy, not inferred by this administrative projection.
use super::*;

pub(crate) struct AppRoleSecretLookupOwner {
    namespace: String,
    mount: String,
    accessor: Option<String>,
    revision: u64,
    epoch: u64,
    control: std::sync::Arc<()>,
}
impl AppRoleSecretLookupOwner {
    pub(crate) fn check(&self, auth: &AuthState) -> Result<(), AuthError> {
        let current = auth
            .effective_auth_mounts(&self.namespace)
            .remove(&self.mount)
            .filter(|entry| entry.kind == "approle")
            .ok_or_else(|| err(503, "AppRole lookup mount changed"))?;
        if current.accessor != self.accessor
            || current.revision != self.revision
            || auth
                .approle_tidy_epochs
                .get(&(self.namespace.clone(), self.mount.clone()))
                .copied()
                .unwrap_or(0)
                != self.epoch
            || !std::sync::Arc::ptr_eq(&self.control, &auth.native_remount_control)
        {
            return Err(err(503, "AppRole lookup mount changed"));
        }
        Ok(())
    }
}

impl AuthState {
    pub(crate) fn approle_lookup_can_skip_maintenance(&self) -> bool {
        self.sdk_auth_catalog.is_none() && self.sdk_credential_leases.is_none()
    }
    pub(crate) fn approle_secret_lookup_owner(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
    ) -> Option<AppRoleSecretLookupOwner> {
        let mount = self.approle_secret_lookup_mount(namespace, method, path)?;
        let current = self.effective_auth_mounts(namespace).remove(&mount)?;
        Some(AppRoleSecretLookupOwner {
            namespace: namespace.to_owned(),
            accessor: current.accessor,
            revision: current.revision,
            epoch: self
                .approle_tidy_epochs
                .get(&(namespace.to_owned(), mount.clone()))
                .copied()
                .unwrap_or(0),
            control: std::sync::Arc::clone(&self.native_remount_control),
            mount,
        })
    }

    pub(crate) fn approle_secret_lookup_mount(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
    ) -> Option<String> {
        if !matches!(method, "POST" | "PUT") {
            return None;
        }
        let auth_path = path.strip_prefix("auth/")?;
        let mounts = self.effective_auth_mounts(namespace);
        let (mount, entry, suffix) = mounts.iter().find_map(|(mount, entry)| {
            auth_path
                .strip_prefix(&format!("{mount}/"))
                .map(|suffix| (mount, entry, suffix))
        })?;
        if entry.kind != "approle" {
            return None;
        }
        let (name, operation) = suffix.strip_prefix("role/")?.split_once('/')?;
        if name.is_empty() || !matches!(operation, "secret-id/lookup" | "secret-id-accessor/lookup")
        {
            return None;
        }
        Some(mount.clone())
    }

    pub(crate) fn handle_approle_secret_lookup_immutable(
        &self,
        principal: &Principal,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<Option<AuthResponse>, AuthError> {
        let Some(mount) = self.approle_secret_lookup_mount(namespace, method, path) else {
            return Ok(None);
        };
        validate_namespace(namespace)?;
        validate_path(path, false)?;
        let suffix = path
            .strip_prefix(&format!("auth/{mount}/role/"))
            .ok_or_else(|| bad("invalid role route"))?;
        let (name, operation) = suffix
            .split_once('/')
            .ok_or_else(|| bad("invalid role route"))?;
        self.authorize_request_parameters_observed(principal, namespace, method, path, body, time)?;
        self.permission(Some(principal), namespace, path, "update", time.seconds())?;
        if !valid_name(name) {
            return Err(bad("invalid role name"));
        }
        self.approle_secret_lookup_response(
            AuthScope {
                namespace,
                mount: &mount,
            },
            name,
            operation,
            body,
        )
        .map(Some)
    }

    pub(super) fn approle_secret_lookup_response(
        &self,
        scope: AuthScope<'_>,
        name: &str,
        operation: &str,
        body: &Value,
    ) -> Result<AuthResponse, AuthError> {
        let roles = self
            .roles_at(scope)
            .ok_or_else(|| err(404, "role not found"))?;
        let role = roles.get(name).ok_or_else(|| err(404, "role not found"))?;
        let by_accessor = operation == "secret-id-accessor/lookup";
        reject_unknown(
            body,
            if by_accessor {
                &["secret_id_accessor"]
            } else {
                &["secret_id"]
            },
        )?;
        let secret = if by_accessor {
            let wanted = string_field(body, "secret_id_accessor")?;
            if wanted.is_empty() {
                return Err(bad("missing secret_id_accessor"));
            }
            match role
                .secret_ids
                .values()
                .find(|secret| secret.accessor == wanted)
            {
                Some(secret) => Some(secret),
                None => {
                    // The accessor storage owner is this actual namespace and
                    // mount. A live accessor belonging to another role yields
                    // nil/nil; other mounts and namespaces cannot supply it.
                    let elsewhere = roles.values().any(|other| {
                        other.secret_ids.values().any(|secret| {
                            secret.accessor == wanted && secret.uses_remaining != Some(0)
                        })
                    });
                    return Ok(if elsewhere {
                        empty(false)
                    } else {
                        approle_renewal::missing_secret_id_accessor(wanted)
                    });
                }
            }
        } else {
            role.secret_ids.get(&hash(string_field(body, "secret_id")?))
        };
        let Some(secret) = secret else {
            return Ok(empty(false));
        };
        if secret.uses_remaining == Some(0) {
            return Ok(if by_accessor {
                approle_renewal::missing_secret_id_accessor(string_field(
                    body,
                    "secret_id_accessor",
                )?)
            } else {
                empty(false)
            });
        }
        Ok(response(approle_renewal::secret_id_info(secret), false))
    }
}
