//! Native AppRole tidy binding and bounded credential cleanup. No serialized
//! work item or client field can create this owner.
use super::*;

#[derive(Clone)]
pub(crate) struct AppRoleTidyOwner {
    namespace: String,
    mount: String,
    accessor: Option<String>,
    epoch: u64,
    control: std::sync::Arc<()>,
}
impl PartialEq for AppRoleTidyOwner {
    fn eq(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            && self.mount == other.mount
            && self.accessor == other.accessor
            && self.epoch == other.epoch
            && std::sync::Arc::ptr_eq(&self.control, &other.control)
    }
}
impl Eq for AppRoleTidyOwner {}
impl AppRoleTidyOwner {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
    pub(crate) fn mount(&self) -> &str {
        &self.mount
    }
    pub(crate) fn check(&self, auth: &AuthState) -> Result<(), AuthError> {
        if auth
            .approle_tidy_owner(&self.namespace, &self.mount)?
            .as_ref()
            != Some(self)
        {
            return Err(err(503, "AppRole tidy original mount changed"));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct Cursor {
    role: String,
    verifier: String,
}
impl Drop for Cursor {
    fn drop(&mut self) {
        self.role.zeroize();
        self.verifier.zeroize();
    }
}
pub(crate) struct Batch {
    pub(crate) cursor: Option<Cursor>,
    pub(crate) checked: usize,
    pub(crate) removed: usize,
    pub(crate) changed: bool,
}
impl AuthState {
    pub(super) fn advance_approle_tidy_epochs(
        &mut self,
        namespace: &str,
        mounts: &[&str],
    ) -> Result<(), AuthError> {
        let mut next = Vec::with_capacity(mounts.len());
        for mount in mounts {
            let key = (namespace.to_owned(), (*mount).to_owned());
            let value = self
                .approle_tidy_epochs
                .get(&key)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| err(507, "AppRole tidy mount epoch exhausted"))?;
            next.push((key, value));
        }
        self.approle_tidy_epochs.extend(next);
        Ok(())
    }
    pub(crate) fn approle_tidy_route_mount(&self, namespace: &str, path: &str) -> Option<String> {
        let route = path.strip_prefix("auth/")?;
        self.effective_auth_mounts(namespace)
            .into_iter()
            .filter(|(mount, _)| route.starts_with(&format!("{mount}/")))
            .max_by_key(|(mount, _)| mount.len())
            .filter(|(mount, entry)| {
                entry.kind == "approle"
                    && route.strip_prefix(&format!("{mount}/")) == Some("tidy/secret-id")
            })
            .map(|(mount, _)| mount)
    }
    pub(crate) fn approle_tidy_owner(
        &self,
        namespace: &str,
        mount: &str,
    ) -> Result<Option<AppRoleTidyOwner>, AuthError> {
        let Some(identity) = self
            .effective_auth_mounts(namespace)
            .remove(mount)
            .filter(|entry| entry.kind == "approle")
        else {
            return Ok(None);
        };
        Ok(Some(AppRoleTidyOwner {
            namespace: namespace.into(),
            mount: mount.into(),
            accessor: identity.accessor,
            epoch: self
                .approle_tidy_epochs
                .get(&(namespace.into(), mount.into()))
                .copied()
                .unwrap_or(0),
            control: std::sync::Arc::clone(&self.native_remount_control),
        }))
    }
    pub(crate) fn approle_tidy_mounts(&self) -> Vec<(String, String)> {
        let namespaces: BTreeSet<&str> = std::iter::once("")
            .chain(self.auth_mounts.keys().map(String::as_str))
            .chain(self.roles.keys().map(String::as_str))
            .chain(self.mounted_roles.keys().map(String::as_str))
            .collect();
        namespaces
            .into_iter()
            .flat_map(|namespace| {
                self.effective_auth_mounts(namespace)
                    .into_iter()
                    .filter(|(_, entry)| entry.kind == "approle")
                    .map(move |(mount, _)| (namespace.into(), mount))
            })
            .collect()
    }
    pub(crate) fn admit_approle_tidy(
        &self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<AppRoleTidyOwner, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &[])?;
        self.permission_observed(principal, namespace, path, "update", time)?;
        let mount = self
            .approle_tidy_route_mount(namespace, path)
            .ok_or_else(|| err(404, "AppRole tidy mount not found"))?;
        self.approle_tidy_owner(namespace, &mount)?
            .ok_or_else(|| err(503, "AppRole tidy owner unavailable"))
    }
    pub(crate) fn native_approle_tidy_batch(
        &mut self,
        owner: &AppRoleTidyOwner,
        cursor: Option<&Cursor>,
        at: Timestamp,
    ) -> Result<Batch, AuthError> {
        owner.check(self)?;
        let time = self.token_api_observed_time(AuthorityTime::Precise(at));
        let now = time.seconds();
        let scope = AuthScope {
            namespace: owner.namespace(),
            mount: owner.mount(),
        };
        // The single native SID map owns each accessor with its credential.
        // There is no independent accessor index to sweep or synthesize.
        let mut items: Vec<(String, String)> = Vec::new();
        if let Some(roles) = self.roles_at(scope) {
            use std::ops::Bound;
            let first = cursor.map_or(Bound::Unbounded, |previous| {
                Bound::Included(previous.role.as_str())
            });
            'roles: for (name, role) in roles.range::<str, _>((first, Bound::Unbounded)) {
                let first = cursor
                    .filter(|previous| previous.role == *name)
                    .map_or(Bound::Unbounded, |previous| {
                        Bound::Excluded(previous.verifier.as_str())
                    });
                for verifier in role
                    .secret_ids
                    .range::<str, _>((first, Bound::Unbounded))
                    .map(|(verifier, _)| verifier)
                {
                    items.push((name.clone(), verifier.clone()));
                    if items.len() == 257 {
                        break 'roles;
                    }
                }
            }
        }
        let more = items.len() > 256;
        if more {
            if let Some((mut role, mut verifier)) = items.pop() {
                role.zeroize();
                verifier.zeroize();
            }
        }
        let next_cursor = if more {
            items.last().map(|(role, verifier)| Cursor {
                role: role.clone(),
                verifier: verifier.clone(),
            })
        } else {
            None
        };
        let checked = items.len();
        let mut removed = 0;
        for (mut role_name, mut verifier) in items {
            if let Some(role) = self.roles_at_mut(scope).get_mut(&role_name)
                && role.secret_ids.get(&verifier).is_some_and(|secret| {
                    secret.uses_remaining == Some(0)
                        || secret.expires_at.is_some_and(|expiry| expiry <= now)
                })
                && let Some((mut stored, mut secret)) = role.secret_ids.remove_entry(&verifier)
            {
                stored.zeroize();
                secret.accessor.zeroize();
                removed += 1;
            }
            role_name.zeroize();
            verifier.zeroize();
        }
        let floor_changed = self.observe_token_api_time(time)?;
        Ok(Batch {
            cursor: next_cursor,
            checked,
            removed,
            changed: removed != 0 || floor_changed,
        })
    }
}
