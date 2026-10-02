//! Login-source restrictions are independent of issued-token source snapshots.
use super::*;
use std::net::{IpAddr, Ipv4Addr};

const FIELD: &str = "secret_id_bound_cidrs";
const ALIAS: &str = "bound_cidr_list";
const DEPRECATED: &str = "The \"bound_cidr_list\" field is deprecated and will be removed. Please use \"secret_id_bound_cidrs\" instead.";

pub(super) fn network(value: &str) -> Result<(IpAddr, u8), AuthError> {
    if value.len() > 64 || !value.is_ascii() {
        return Err(bad("invalid SecretID source CIDR"));
    }
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| bad("SecretID source requires a CIDR prefix"))?;
    let ip: IpAddr = address
        .parse()
        .map_err(|_| bad("invalid SecretID source address"))?;
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("invalid SecretID CIDR prefix"));
    }
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| bad("invalid SecretID CIDR prefix"))?;
    if prefix > if ip.is_ipv4() { 32 } else { 128 } {
        return Err(bad("invalid SecretID CIDR prefix"));
    }
    Ok((ip, prefix))
}
pub(super) fn parse(value: &Value, invalid_status: u16) -> Result<Vec<String>, AuthError> {
    let values: Vec<&str> = match value {
        Value::Null => Vec::new(),
        Value::String(value) => value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect(),
        Value::Array(values) => values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::trim)
                    .ok_or_else(|| bad("CIDRs must be strings"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(bad("CIDRs must be a list or comma-separated string")),
    };
    if values.len() > 128 {
        return Err(bad("too many SecretID source CIDRs"));
    }
    values
        .into_iter()
        .map(|value| {
            network(value).map_err(|error| err(invalid_status, &error.message))?;
            Ok(value.to_owned())
        })
        .collect()
}

pub(super) fn update(role: &mut Role, body: &Value) -> Result<(), AuthError> {
    // Presence, even explicit null, gives the native field precedence.
    if let Some(value) = body.get(FIELD).or_else(|| body.get(ALIAS)) {
        role.secret_id_bound_cidrs = Some(parse(value, 500)?);
    }
    Ok(())
}

fn ipv4_in(network: Ipv4Addr, prefix: u8, peer: Ipv4Addr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(network) & mask == u32::from(peer) & mask
}

pub(super) fn contains(ip: IpAddr, prefix: u8, peer: IpAddr) -> bool {
    let peer_v4 = match peer {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    };
    match ip {
        IpAddr::V4(ip) => peer_v4.is_some_and(|peer| ipv4_in(ip, prefix, peer)),
        IpAddr::V6(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            // ParseCIDR masks the network before IPNet.Contains applies To4.
            let ip = std::net::Ipv6Addr::from(u128::from(ip) & mask);
            match ip.to_ipv4_mapped() {
                // net.IPNet uses the last four mask bytes for mapped networks.
                Some(ip) => {
                    peer_v4.is_some_and(|peer| ipv4_in(ip, prefix.saturating_sub(96), peer))
                }
                None => match peer {
                    IpAddr::V6(peer) if peer.to_ipv4_mapped().is_none() => {
                        let mask = if prefix == 0 {
                            0
                        } else {
                            u128::MAX << (128 - prefix)
                        };
                        u128::from(ip) & mask == u128::from(peer) & mask
                    }
                    _ => false,
                },
            }
        }
    }
}

pub(super) fn check(role: &Role, peer: Option<IpAddr>) -> Result<(), AuthError> {
    let Some(values) = role
        .secret_id_bound_cidrs
        .as_ref()
        .filter(|values| !values.is_empty())
    else {
        return Ok(());
    };
    let peer = peer.ok_or_else(|| err(500, "failed to get connection information"))?;
    for value in values {
        let (ip, prefix) = network(value)?;
        let allowed = contains(ip, prefix, peer);
        if allowed {
            return Ok(());
        }
    }
    Err(bad(
        "source address unauthorized by CIDR restrictions on the role",
    ))
}

impl AuthState {
    pub(super) fn approle_secret_cidrs_route(
        &mut self,
        scope: AuthScope<'_>,
        name: &str,
        capability: &str,
        body: &Value,
        existing: Option<Role>,
        legacy: bool,
    ) -> Result<AuthResponse, AuthError> {
        let Some(mut role) = existing else {
            return match capability {
                "read" => Ok(AuthResponse {
                    status: 404,
                    body: json!({"errors":[]}),
                    ..empty(false)
                }),
                "delete" => Ok(empty(false)),
                "update" => Err(err(404, "role not found")),
                _ => Err(err(405, "method not allowed")),
            };
        };
        match capability {
            "read" if legacy => Ok(AuthResponse {
                body: json!({"data":{"bound_cidr_list":Value::Null},"warnings":[DEPRECATED]}),
                ..response(Value::Null, false)
            }),
            "read" => Ok(response(
                json!({"secret_id_bound_cidrs":role.secret_id_bound_cidrs}),
                false,
            )),
            "update" => {
                if !body.is_object() {
                    return Err(bad("request body must be an object"));
                }
                if let Some(value) = body.get(if legacy { ALIAS } else { FIELD }) {
                    let cidrs = parse(value, 400)?;
                    if cidrs.is_empty() {
                        return Err(bad("missing bound_cidr_list"));
                    }
                    role.secret_id_bound_cidrs = Some(cidrs);
                }
                approle_cidrs::validate_constraints(&role)?;
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(empty(true))
            }
            "delete" => {
                // The deprecated endpoint deletes its historical field, which
                // this implementation never invents from the native value.
                if !legacy {
                    role.secret_id_bound_cidrs = None;
                }
                approle_cidrs::validate_constraints(&role)?;
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(empty(true))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    pub(crate) fn has_approle_secret_bound_cidrs(&self) -> bool {
        self.roles
            .values()
            .flat_map(|roles| roles.values())
            .chain(
                self.mounted_roles
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|roles| roles.values()),
            )
            .any(|role| role.secret_id_bound_cidrs.is_some())
    }
    pub(crate) fn validate_approle_secret_bound_cidrs(&self) -> Result<(), AuthError> {
        for (namespace, roles) in &self.roles {
            self.validate_secret_cidr_roles(namespace, "approle", roles)?;
        }
        for (namespace, mounts) in &self.mounted_roles {
            for (mount, roles) in mounts {
                self.validate_secret_cidr_roles(namespace, mount, roles)?;
            }
        }
        Ok(())
    }
    fn validate_secret_cidr_roles(
        &self,
        namespace: &str,
        mount: &str,
        roles: &BTreeMap<String, Role>,
    ) -> Result<(), AuthError> {
        for role in roles.values() {
            if let Some(values) = &role.secret_id_bound_cidrs {
                if values.len() > 128 || !self.online_mount_enabled(namespace, mount, "approle") {
                    return Err(bad("invalid persisted AppRole source restrictions"));
                }
                for value in values {
                    network(value)?;
                }
            }
        }
        Ok(())
    }
}
