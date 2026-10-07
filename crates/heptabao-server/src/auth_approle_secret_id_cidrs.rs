//! Per-SecretID restrictions preserve their issuance spelling. The source
//! subset is checked again against the current role at login; token overrides
//! are checked against the role only when the SecretID is created.
use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) struct Constraints {
    pub(super) source: Option<Vec<String>>,
    pub(super) token: Option<Vec<String>>,
}

impl Constraints {
    pub(super) fn from_secret(secret: &SecretId) -> Self {
        Self {
            source: secret.cidr_list.clone(),
            token: secret.token_bound_cidrs.clone(),
        }
    }
}

fn subset_error() -> AuthError {
    err(
        500,
        "failed to verify subset relationship between CIDR blocks on the role and CIDR blocks on the secret ID",
    )
}

fn masked(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask))
        }
        IpAddr::V6(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
        }
    }
}

fn subset_network(value: &str) -> Result<(IpAddr, u8), AuthError> {
    let (ip, prefix) = approle_secret_cidrs::network(value).map_err(|_| subset_error())?;
    // Pinned cidrutil.Subset rejects a nonzero address with a /0 mask,
    // even though net.ParseCIDR accepts it. Other host bits are retained.
    let zero = match ip {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => {
            ip.is_unspecified() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_unspecified())
        }
    };
    if prefix == 0 && !zero {
        return Err(subset_error());
    }
    Ok((ip, prefix))
}

fn subset(children: &[String], parents: &[String]) -> Result<(), AuthError> {
    if children.is_empty() || parents.is_empty() {
        return Ok(());
    }
    for child in children {
        let mut allowed = false;
        for parent in parents {
            // This is the upstream AppRole helper's exact mask restoration,
            // including its /32 spelling for a stored address without '/'.
            let parent = if parent.contains('/') {
                parent.clone()
            } else {
                format!("{parent}/32")
            };
            let (network, parent_prefix) = subset_network(&parent)?;
            let (ip, prefix) = subset_network(child)?;
            if prefix >= parent_prefix
                && approle_secret_cidrs::contains(network, parent_prefix, masked(ip, prefix))
            {
                allowed = true;
                break;
            }
        }
        // Every child must fit one parent. A union of adjacent parent ranges
        // must not widen this check.
        if !allowed {
            return Err(subset_error());
        }
    }
    Ok(())
}

pub(super) fn issue(role: &Role, body: &Value) -> Result<Constraints, AuthError> {
    let source = body
        .get("cidr_list")
        .map(|value| approle_secret_cidrs::parse(value, 500))
        .transpose()?;
    subset(
        source.as_deref().unwrap_or_default(),
        role.secret_id_bound_cidrs.as_deref().unwrap_or_default(),
    )?;
    let token = body
        .get("token_bound_cidrs")
        .map(|value| approle_secret_cidrs::parse(value, 500))
        .transpose()?;
    subset(
        token.as_deref().unwrap_or_default(),
        role.token_bound_cidrs.as_deref().unwrap_or_default(),
    )?;
    Ok(Constraints { source, token })
}

pub(super) fn login(
    role: &Role,
    secret: Option<&Constraints>,
    peer: Option<IpAddr>,
) -> Result<Vec<String>, AuthError> {
    if let Some(source) = secret
        .and_then(|secret| secret.source.as_deref())
        .filter(|values| !values.is_empty())
    {
        subset(
            source,
            role.secret_id_bound_cidrs.as_deref().unwrap_or_default(),
        )?;
        let peer = peer.ok_or_else(|| err(500, "failed to get connection information"))?;
        let mut allowed = false;
        for value in source {
            let (network, prefix) = approle_secret_cidrs::network(value)?;
            if approle_secret_cidrs::contains(network, prefix, peer) {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(bad(
                "source address unauthorized by CIDR restrictions on the secret ID",
            ));
        }
    }
    approle_secret_cidrs::check(role, peer)?;
    if let Some(overrides) = secret
        .and_then(|secret| secret.token.as_ref())
        .filter(|values| !values.is_empty())
    {
        // SID lookup retains the raw prefix spelling. Issued tokens use the
        // same go-sockaddr-compatible normalization as role token CIDRs.
        token_cidrs::field(&json!({"token_bound_cidrs":overrides}))
    } else {
        Ok(role.token_bound_cidrs.clone().unwrap_or_default())
    }
}

impl AuthState {
    pub(crate) fn has_approle_secret_id_cidrs(&self) -> bool {
        self.roles
            .values()
            .flat_map(|roles| roles.values())
            .chain(
                self.mounted_roles
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|roles| roles.values()),
            )
            .any(|role| {
                role.secret_ids
                    .values()
                    .any(|secret| secret.cidr_list.is_some() || secret.token_bound_cidrs.is_some())
            })
    }

    pub(crate) fn validate_approle_secret_id_cidrs(&self) -> Result<(), AuthError> {
        for (namespace, roles) in &self.roles {
            self.validate_secret_id_cidr_roles(namespace, "approle", roles)?;
        }
        for (namespace, mounts) in &self.mounted_roles {
            for (mount, roles) in mounts {
                self.validate_secret_id_cidr_roles(namespace, mount, roles)?;
            }
        }
        Ok(())
    }

    fn validate_secret_id_cidr_roles(
        &self,
        namespace: &str,
        mount: &str,
        roles: &BTreeMap<String, Role>,
    ) -> Result<(), AuthError> {
        for secret in roles.values().flat_map(|role| role.secret_ids.values()) {
            for values in [&secret.cidr_list, &secret.token_bound_cidrs]
                .into_iter()
                .flatten()
            {
                if values.len() > 128 || !self.online_mount_enabled(namespace, mount, "approle") {
                    return Err(bad("invalid persisted SecretID CIDR restrictions"));
                }
                for value in values {
                    approle_secret_cidrs::network(value)?;
                }
            }
        }
        // A later role change may intentionally make a SID source no longer a
        // subset. Such records must remain loadable so login can consume/reject
        // them, and admins can restore the role or destroy the credential.
        Ok(())
    }
}
