//! Stateful SSH OTP and CA profiles. No shell or password database is invoked.
//! Verification is online and single-use; the Service owns authorization,
//! issuer revocation checks and durable commit before delivery.
use super::*;
use crate::auth::{LeaseOwner, ServiceOwnerProfile};
use crate::crypto;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use zeroize::Zeroizing;

fn digest_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn valid_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err(bad("invalid SSH role name"));
    }
    Ok(())
}
fn integer(body: &Value, field: &str, default: u64) -> Result<u64> {
    body.get(field)
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| bad("field must be a nonnegative integer"))
        })
        .transpose()
        .map(|v| v.unwrap_or(default))
}

use std::net::IpAddr;

pub(super) const MAX_LEASE_TTL: u64 = 32 * 24 * 3600;
const MAX_ROLES: usize = 128;
const MAX_LEASES: usize = 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Role {
    default_user: String,
    allowed_users: String,
    cidr_list: String,
    exclude_cidr_list: String,
    port: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lease {
    pub(super) id: String,
    pub(super) owner: LeaseOwner,
    pub(super) path: String,
    pub(super) issued: u64,
    pub(super) expires: u64,
    consumed: bool,
    ip: IpAddr,
    username: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SshOtp {
    roles: BTreeMap<String, Role>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca: Option<super::ssh_ca::CaState>,
    pub(super) leases: BTreeMap<String, Lease>,
    pub(super) default_ttl: u64,
    pub(super) max_ttl: u64,
}

impl Default for SshOtp {
    fn default() -> Self {
        Self {
            roles: BTreeMap::new(),
            ca: None,
            leases: BTreeMap::new(),
            default_ttl: 600,
            max_ttl: MAX_LEASE_TTL,
        }
    }
}

fn username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-$".contains(&c))
}

fn cidrs(value: &str) -> Result<Vec<(IpAddr, u8)>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() > 4096 {
        return Err(bad("CIDR policy exceeds bound"));
    }
    let entries: Vec<_> = value.split(',').collect();
    if entries.len() > 64 {
        return Err(bad("too many CIDR entries"));
    }
    entries
        .into_iter()
        .map(|entry| {
            let (ip, prefix) = entry
                .trim()
                .split_once('/')
                .ok_or_else(|| bad("CIDR prefix is required"))?;
            let ip: IpAddr = ip.parse().map_err(|_| bad("invalid CIDR address"))?;
            let bits: u8 = prefix.parse().map_err(|_| bad("invalid CIDR prefix"))?;
            if u32::from(bits) > if ip.is_ipv4() { 32 } else { 128 } {
                return Err(bad("CIDR prefix exceeds address size"));
            }
            Ok((ip, bits))
        })
        .collect()
}

fn contains(network: &(IpAddr, u8), ip: IpAddr) -> bool {
    match (network.0, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(network.1)).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(network.1))
                .unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

impl Role {
    fn validate(&self) -> Result<()> {
        if !username(&self.default_user) || self.port == 0 || self.allowed_users.len() > 4096 {
            return Err(bad("invalid SSH OTP role"));
        }
        if !self.allowed_users.is_empty() && self.allowed_users != "*" {
            let users: Vec<_> = self.allowed_users.split(',').collect();
            if users.len() > 64 || users.iter().any(|u| !username(u.trim())) {
                return Err(bad("invalid allowed users"));
            }
        }
        if cidrs(&self.cidr_list)?.is_empty() {
            return Err(bad("OTP role requires a CIDR policy"));
        }
        cidrs(&self.exclude_cidr_list)?;
        Ok(())
    }
    fn allows_ip(&self, ip: IpAddr) -> Result<bool> {
        Ok(cidrs(&self.cidr_list)?
            .iter()
            .any(|network| contains(network, ip))
            && !cidrs(&self.exclude_cidr_list)?
                .iter()
                .any(|network| contains(network, ip)))
    }
    fn allows_user(&self, user: &str) -> bool {
        username(user)
            && (self.allowed_users.is_empty()
                || self.allowed_users == "*"
                || user == self.default_user
                || self
                    .allowed_users
                    .split(',')
                    .any(|entry| entry.trim() == user))
    }
    fn descriptor(&self) -> Value {
        json!({"key_type":"otp","default_user":self.default_user,"allowed_users":self.allowed_users,
            "cidr_list":self.cidr_list,"exclude_cidr_list":self.exclude_cidr_list,"port":self.port})
    }
}

impl SshOtp {
    pub(super) fn has_ca_state(&self) -> bool {
        self.ca.is_some()
    }
    pub(super) fn public_ca_key(&self, reference: &str) -> Result<&str> {
        self.ca
            .as_ref()
            .ok_or_else(not_found)?
            .public_key(reference)
    }
    pub(super) fn tune(&mut self, body: &Value) -> Result<()> {
        let parse = |value: &Value, default| -> Result<u64> {
            let ttl = match value {
                Value::Number(_) => value.as_u64().ok_or_else(|| bad("invalid lease TTL"))?,
                Value::String(_) => duration_seconds(value)?,
                _ => return Err(bad("invalid lease TTL")),
            };
            Ok(if ttl == 0 { default } else { ttl })
        };
        let default = body
            .get("default_lease_ttl")
            .map(|v| parse(v, 600))
            .transpose()?
            .unwrap_or(self.default_ttl);
        let max = body
            .get("max_lease_ttl")
            .map(|v| parse(v, MAX_LEASE_TTL))
            .transpose()?
            .unwrap_or(self.max_ttl);
        if default == 0 || default > max || max > MAX_LEASE_TTL {
            return Err(bad("lease TTL policy is outside bounds"));
        }
        self.default_ttl = default;
        self.max_ttl = max;
        Ok(())
    }
    pub(super) fn validate(&self, namespace: &str, mount: &str, clock: u64) -> Result<()> {
        if self.default_ttl == 0
            || self.default_ttl > self.max_ttl
            || self.max_ttl > MAX_LEASE_TTL
            || self.roles.len() > MAX_ROLES
            || self.leases.len() > MAX_LEASES
        {
            return Err(bad("invalid SSH OTP state bounds"));
        }
        if let Some(ca) = &self.ca {
            ca.validate()?;
            if self
                .roles
                .len()
                .checked_add(ca.role_count())
                .is_none_or(|count| count > MAX_ROLES)
                || ca.roles().any(|name| self.roles.contains_key(name))
            {
                return Err(bad("invalid combined SSH role state"));
            }
        }
        for (name, role) in &self.roles {
            valid_name(name)?;
            role.validate()?;
        }
        let mut ids = BTreeSet::new();
        for (digest, lease) in &self.leases {
            let prefix = format!("{mount}creds/");
            if digest.len() != 64
                || !digest.bytes().all(|c| c.is_ascii_hexdigit())
                || lease
                    .owner
                    .validate_scope(namespace, ServiceOwnerProfile::DigestAlphabet)
                    .is_err()
                || lease.owner.batch_claims().is_some_and(|claims| {
                    lease.issued < claims.issued_at() || lease.expires > claims.expires_at()
                })
                || !lease.path.starts_with(&prefix)
                || lease.path[prefix.len()..].contains('/')
                || lease
                    .id
                    .strip_prefix(&format!("{}/", lease.path))
                    .is_none_or(|s| s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()))
                || lease.issued > clock
                || lease.expires <= lease.issued
                || lease.expires - lease.issued > MAX_LEASE_TTL
                || !username(&lease.username)
                || !ids.insert(&lease.id)
            {
                return Err(bad("invalid SSH OTP lease binding"));
            }
            valid_path(&lease.path)?;
            valid_name(&lease.path[prefix.len()..])?;
        }
        Ok(())
    }

    pub(super) fn authenticated_ca_sources(
        &self,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<Vec<String>>> {
        let Some(name) = path
            .strip_prefix("sign/")
            .or_else(|| path.strip_prefix("issue/"))
        else {
            return Ok(None);
        };
        if !write_method(method) {
            return Ok(None);
        }
        valid_name(name)?;
        let Some(ca) = &self.ca else {
            return Ok(None);
        };
        if !ca.needs_authenticated_request(name) {
            return Ok(None);
        }
        ca.authenticated_template_sources(name, body).map(Some)
    }

    pub(super) fn handle_role_authenticated(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
        display_name: &str,
        identity: &super::ssh_templates::RequestIdentity,
    ) -> Result<EngineResponse> {
        let name = path
            .strip_prefix("sign/")
            .or_else(|| path.strip_prefix("issue/"))
            .ok_or_else(not_found)?;
        if !write_method(method) {
            return Err(unsupported());
        }
        valid_name(name)?;
        let ca = self.ca.as_mut().ok_or_else(not_found)?;
        ca.sign_authenticated(
            body,
            &super::ssh_ca_policy::SigningContext {
                role_name: name,
                display_name,
                now,
                default_ttl: self.default_ttl,
                max_ttl: self.max_ttl,
            },
            path.starts_with("issue/"),
            identity,
        )
    }

    pub(super) fn handle_role(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
        display_name: &str,
    ) -> Result<EngineResponse> {
        if path == "config/ca"
            || path == "config/issuers"
            || path == "issuers"
            || path == "issuers/"
            || path.starts_with("issuer/")
            || path == "issuers/import"
            || path.starts_with("issuers/import/")
        {
            let ca = self.ca.get_or_insert_with(Default::default);
            return ca.handle_admin(method, path, body)?.ok_or_else(not_found);
        }
        if let Some(name) = path
            .strip_prefix("sign/")
            .or_else(|| path.strip_prefix("issue/"))
        {
            if !write_method(method) {
                return Err(unsupported());
            }
            valid_name(name)?;
            let ca = self.ca.as_mut().ok_or_else(not_found)?;
            return ca.sign(
                body,
                &super::ssh_ca_policy::SigningContext {
                    role_name: name,
                    display_name,
                    now,
                    default_ttl: self.default_ttl,
                    max_ttl: self.max_ttl,
                },
                path.starts_with("issue/"),
            );
        }
        if path == "public_key" {
            return Err(error(
                501,
                "SSH public key requires the typed public HTTP dispatcher",
            ));
        }
        if path == "roles" || path == "roles/" {
            if method != "LIST" {
                return Err(unsupported());
            }
            reject_unknown(body, &["after", "limit"])?;
            let after = body
                .get("after")
                .map(|v| v.as_str().ok_or_else(|| bad("invalid pagination cursor")))
                .transpose()?
                .unwrap_or("");
            let limit = integer(body, "limit", 0)?;
            if limit > MAX_ROLES as u64 {
                return Err(bad("role page exceeds bound"));
            }
            let count = if limit == 0 {
                MAX_ROLES
            } else {
                limit as usize
            };
            let all_keys: BTreeSet<_> = self
                .roles
                .keys()
                .chain(self.ca.iter().flat_map(|ca| ca.roles()))
                .cloned()
                .collect();
            let keys: Vec<_> = all_keys
                .iter()
                .filter(|key| key.as_str() > after)
                .take(count)
                .cloned()
                .collect();
            return listing(keys);
        }
        if path == "lookup" && write_method(method) {
            reject_unknown(body, &["ip"])?;
            let ip = string(body, "ip")?
                .parse()
                .map_err(|_| bad("invalid IP address"))?;
            let mut roles = Vec::new();
            for (name, role) in &self.roles {
                if role.allows_ip(ip)? {
                    roles.push(name.clone());
                }
            }
            return Ok(ok(json!({"roles":roles}), false));
        }
        let name = path
            .strip_prefix("roles/")
            .ok_or_else(|| error(501, "SSH CA and unsupported OTP routes are not implemented"))?;
        valid_name(name)?;
        let ca_write =
            write_method(method) && body.get("key_type").and_then(Value::as_str) == Some("ca");
        let ca_existing = self.ca.as_ref().is_some_and(|ca| ca.contains_role(name));
        if ca_write {
            let total = self.roles.len() + self.ca.as_ref().map_or(0, |ca| ca.role_count());
            if !self.roles.contains_key(name) && !ca_existing && total >= MAX_ROLES {
                return Err(error(507, "SSH role capacity exhausted"));
            }
            let response = self
                .ca
                .get_or_insert_with(Default::default)
                .put_role(name, body)?;
            self.roles.remove(name);
            return Ok(response);
        }
        if ca_existing && matches!(method, "GET" | "DELETE") {
            reject_unknown(body, &[])?;
            let ca = self.ca.as_mut().ok_or_else(not_found)?;
            return if method == "GET" {
                ca.role_descriptor(name)
            } else {
                Ok(empty(ca.remove_role(name)))
            };
        }
        match method {
            "GET" => {
                reject_unknown(body, &[])?;
                Ok(ok(
                    self.roles.get(name).ok_or_else(not_found)?.descriptor(),
                    false,
                ))
            }
            "DELETE" => {
                reject_unknown(body, &[])?;
                Ok(empty(self.roles.remove(name).is_some()))
            }
            "POST" | "PUT" => {
                reject_unknown(
                    body,
                    &[
                        "key_type",
                        "default_user",
                        "allowed_users",
                        "cidr_list",
                        "exclude_cidr_list",
                        "port",
                    ],
                )?;
                if string(body, "key_type")? != "otp" {
                    return Err(bad("invalid SSH role key type"));
                }
                let value = |key, default: &str| -> Result<String> {
                    Ok(body
                        .get(key)
                        .map(|v| v.as_str().ok_or_else(|| bad("role field must be a string")))
                        .transpose()?
                        .unwrap_or(default)
                        .into())
                };
                let role = Role {
                    default_user: value("default_user", "")?,
                    allowed_users: value("allowed_users", "")?,
                    cidr_list: value("cidr_list", "")?,
                    exclude_cidr_list: value("exclude_cidr_list", "")?,
                    port: u16::try_from(integer(body, "port", 22)?)
                        .map_err(|_| bad("invalid SSH port"))?,
                };
                role.validate()?;
                let combined = self.roles.len() + self.ca.as_ref().map_or(0, |ca| ca.role_count());
                let existing = self.roles.contains_key(name)
                    || self.ca.as_ref().is_some_and(|ca| ca.contains_role(name));
                if !existing && combined >= MAX_ROLES {
                    return Err(error(507, "SSH role capacity exhausted"));
                }
                if let Some(ca) = &mut self.ca {
                    ca.remove_role(name);
                }
                self.roles.insert(name.into(), role);
                Ok(empty(true))
            }
            _ => Err(unsupported()),
        }
    }
    pub(super) fn issue(
        &mut self,
        mount: &str,
        name: &str,
        body: &Value,
        owner: &LeaseOwner,
        owner_expiry: Option<u64>,
        now: u64,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &["ip", "username"])?;
        valid_name(name)?;
        let role = self.roles.get(name).ok_or_else(not_found)?;
        let ip: IpAddr = string(body, "ip")?
            .parse()
            .map_err(|_| bad("invalid IP address"))?;
        let user = body
            .get("username")
            .map(|v| v.as_str().ok_or_else(|| bad("username must be a string")))
            .transpose()?
            .unwrap_or(&role.default_user);
        if !role.allows_ip(ip)? || !role.allows_user(user) {
            return Err(bad("target is outside the SSH role policy"));
        }
        if self.leases.len() >= MAX_LEASES {
            return Err(error(507, "SSH lease capacity exhausted"));
        }
        let expires = now
            .checked_add(self.default_ttl.min(self.max_ttl))
            .ok_or_else(|| bad("lease timestamp overflow"))?;
        let expires = owner_expiry.map_or(expires, |limit| expires.min(limit));
        if expires <= now {
            return Err(error(403, "issuer no longer has a live lease window"));
        }
        let raw = Zeroizing::new(BASE64.encode(
            crypto::random::<32>().map_err(|_| error(503, "secure randomness unavailable"))?,
        ));
        let id = format!(
            "{mount}creds/{name}/{}",
            digest_hex(
                &crypto::random::<32>().map_err(|_| error(503, "secure randomness unavailable"))?
            )
        );
        let digest = digest_hex(raw.as_bytes());
        if self.leases.contains_key(&digest) || self.leases.values().any(|v| v.id == id) {
            return Err(error(503, "OTP identity collision"));
        }
        let path = format!("{mount}creds/{name}");
        valid_path(&path)?;
        valid_path(&id)?;
        let result = EngineResponse {
            status: 200,
            mutated: true,
            body: json!({"lease_id":id,"renewable":false,
            "lease_duration":expires-now,"data":{"ip":ip.to_string(),"username":user,"key_type":"otp","port":role.port,"key":raw.as_str()}}),
        };
        self.leases.insert(
            digest,
            Lease {
                id,
                owner: owner.clone(),
                path,
                issued: now,
                expires,
                consumed: false,
                ip,
                username: user.into(),
            },
        );
        Ok(result)
    }
    pub(super) fn verify(&mut self, body: &Value, now: u64) -> Result<EngineResponse> {
        reject_unknown(body, &["otp"])?;
        let raw = string(body, "otp")?;
        if raw.is_empty() || raw.len() > 256 {
            return Err(bad("invalid one-time credential"));
        }
        let digest = digest_hex(raw.as_bytes());
        let lease = self
            .leases
            .get(&digest)
            .ok_or_else(|| bad("one-time credential is invalid or no longer live"))?;
        if now >= lease.expires || lease.consumed {
            return Err(bad("one-time credential is invalid or no longer live"));
        }
        let result = ok(
            json!({"ip":lease.ip.to_string(),"username":lease.username,
                "role_name":lease.path.rsplit('/').next().ok_or_else(||bad("invalid stored role binding"))?}),
            true,
        );
        // Consumption is separate from lease registration: keep metadata until
        // explicit revocation or expiry, but never accept the OTP a second time.
        self.leases.get_mut(&digest).ok_or_else(not_found)?.consumed = true;
        Ok(result)
    }
}
