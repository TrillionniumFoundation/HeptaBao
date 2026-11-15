//! OpenBao's local SecretID prefix is owned by a cluster, not by a node.
//! Local and ordinary credentials never share a map or fall back to one another.
use super::*;

pub(crate) const STATE_SCHEMA: u32 = 142;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Partition {
    owner_cluster_id: String,
    secret_ids: BTreeMap<String, SecretId>,
}

impl Drop for Partition {
    fn drop(&mut self) {
        for (mut verifier, _) in std::mem::take(&mut self.secret_ids) {
            verifier.zeroize();
        }
    }
}

fn invalid() -> AuthError {
    err(503, "invalid cluster-local AppRole SecretID ownership")
}

pub(super) fn initialize_role(role: &mut Role, cluster_id: Option<&str>) -> Result<(), AuthError> {
    if security_contract::role_local_secret_ids(role) && role.local_secret_ids.is_none() {
        let owner = cluster_id
            .filter(|value| !value.is_empty())
            .ok_or_else(invalid)?;
        if !role.secret_ids.is_empty() {
            return Err(invalid());
        }
        role.local_secret_ids = Some(Partition {
            owner_cluster_id: owner.to_owned(),
            secret_ids: BTreeMap::new(),
        });
    }
    validate_role_layout(role)
}

pub(super) fn validate_role_layout(role: &Role) -> Result<(), AuthError> {
    match (
        security_contract::role_local_secret_ids(role),
        &role.local_secret_ids,
    ) {
        (false, None) => Ok(()),
        (true, Some(partition))
            if !partition.owner_cluster_id.is_empty() && role.secret_ids.is_empty() =>
        {
            Ok(())
        }
        _ => Err(invalid()),
    }
}

impl Role {
    /// The persisted role flag chooses exactly one prefix. Invalid layouts
    /// cannot accidentally use a credential from the other prefix.
    pub(super) fn approle_secrets(&self) -> Result<&BTreeMap<String, SecretId>, AuthError> {
        validate_role_layout(self)?;
        match &self.local_secret_ids {
            Some(partition) => Ok(&partition.secret_ids),
            None => Ok(&self.secret_ids),
        }
    }

    pub(super) fn approle_secrets_mut(
        &mut self,
    ) -> Result<&mut BTreeMap<String, SecretId>, AuthError> {
        validate_role_layout(self)?;
        match &mut self.local_secret_ids {
            Some(partition) => Ok(&mut partition.secret_ids),
            None => Ok(&mut self.secret_ids),
        }
    }

    // Format validators must inspect both owners even if a malformed input
    // populated the inactive prefix. The layout check rejects that input.
    pub(super) fn all_approle_secrets(&self) -> impl Iterator<Item = &SecretId> {
        self.secret_ids.values().chain(
            self.local_secret_ids
                .iter()
                .flat_map(|partition| partition.secret_ids.values()),
        )
    }

    pub(super) fn approle_secret_owner(&self) -> Option<&str> {
        self.local_secret_ids
            .as_ref()
            .map(|partition| partition.owner_cluster_id.as_str())
    }
}

impl AuthState {
    pub(crate) fn has_cluster_local_approle_state(&self) -> bool {
        self.roles
            .values()
            .flat_map(BTreeMap::values)
            .chain(
                self.mounted_roles
                    .values()
                    .flat_map(BTreeMap::values)
                    .flat_map(BTreeMap::values),
            )
            .any(|role| {
                security_contract::role_local_secret_ids(role) || role.local_secret_ids.is_some()
            })
    }

    pub(crate) fn validate_cluster_local_approle_state(
        &self,
        cluster_id: &str,
    ) -> Result<(), AuthError> {
        for (namespace, roles) in &self.roles {
            self.validate_cluster_local_approle_partition(namespace, "approle", roles, cluster_id)?;
        }
        for (namespace, mounts) in &self.mounted_roles {
            for (mount, roles) in mounts {
                self.validate_cluster_local_approle_partition(namespace, mount, roles, cluster_id)?;
            }
        }
        Ok(())
    }

    fn validate_cluster_local_approle_partition(
        &self,
        namespace: &str,
        mount: &str,
        roles: &BTreeMap<String, Role>,
        cluster_id: &str,
    ) -> Result<(), AuthError> {
        for role in roles.values() {
            validate_role_layout(role)?;
            if let Some(partition) = &role.local_secret_ids
                && (partition.owner_cluster_id != cluster_id
                    || !self.online_mount_enabled(namespace, mount, "approle"))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_approle_local_tests.rs"]
mod tests;
