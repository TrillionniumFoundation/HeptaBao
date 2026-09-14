//! Bounded internal PKI engine. The CA private key and issued private keys are
//! persisted only through the Service encrypted state boundary; issued leaf
//! private keys are released once in the successful response and are not kept.
//! Revocation is represented durably and published through a signed CRL.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_ROLES: usize = 256;
const MAX_ISSUED: usize = 4096;
const MAX_TTL: u64 = 10 * 365 * 24 * 3600;
const DEFAULT_ROOT_TTL: u64 = 365 * 24 * 3600;
const DEFAULT_LEAF_TTL: u64 = 24 * 3600;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Pki {
    #[serde(default = "default_leaf_ttl")]
    pub(super) default_ttl: u64,
    #[serde(default = "max_pki_ttl")]
    pub(super) max_ttl: u64,
    root: Option<RootCa>,
    roles: BTreeMap<String, Role>,
    pub(super) issued: BTreeMap<String, IssuedCertificate>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RootCa {
    common_name: String,
    pkcs8: Vec<u8>,
    certificate_der: Vec<u8>,
    serial: String,
    not_before: u64,
    not_after: u64,
}

impl Drop for RootCa {
    fn drop(&mut self) {
        self.pkcs8.zeroize();
        self.certificate_der.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
struct Role {
    allowed_domains: BTreeSet<String>,
    allow_subdomains: bool,
    max_ttl: u64,
    generate_lease: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct IssuedCertificate {
    #[serde(default)]
    pub(super) leased: bool,
    pub(super) lease_id: String,
    pub(super) owner: String,
    pub(super) path: String,
    pub(super) issued: u64,
    pub(super) expires: u64,
    pub(super) revoked_at: Option<u64>,
    common_name: String,
    certificate_der: Vec<u8>,
}

impl Drop for IssuedCertificate {
    fn drop(&mut self) {
        self.certificate_der.zeroize();
    }
}

fn default_leaf_ttl() -> u64 {
    DEFAULT_LEAF_TTL
}
fn max_pki_ttl() -> u64 {
    MAX_TTL
}

impl Default for Pki {
    fn default() -> Self {
        Self {
            default_ttl: DEFAULT_LEAF_TTL,
            max_ttl: MAX_TTL,
            root: None,
            roles: BTreeMap::new(),
            issued: BTreeMap::new(),
        }
    }
}

impl Pki {
    pub(super) fn tune(&mut self, body: &Value) -> Result<()> {
        let default = body
            .get("default_lease_ttl")
            .map(|v| ttl_value(v, self.default_ttl))
            .transpose()?
            .unwrap_or(self.default_ttl);
        let max = body
            .get("max_lease_ttl")
            .map(|v| ttl_value(v, self.max_ttl))
            .transpose()?
            .unwrap_or(self.max_ttl);
        if default == 0 || default > max || max > MAX_TTL {
            return Err(bad("PKI mount lease TTL policy is outside bounds"));
        }
        self.default_ttl = default;
        self.max_ttl = max;
        Ok(())
    }

    pub(super) fn validate(&self, mount: &str, clock: u64) -> Result<()> {
        if self.default_ttl == 0
            || self.default_ttl > self.max_ttl
            || self.max_ttl > MAX_TTL
            || self.roles.len() > MAX_ROLES
            || self.issued.len() > MAX_ISSUED
        {
            return Err(bad("invalid PKI state bounds"));
        }
        if let Some(root) = &self.root {
            if !valid_common_name(&root.common_name)
                || root.pkcs8.is_empty()
                || root.pkcs8.len() > 4096
                || root.certificate_der.is_empty()
                || root.certificate_der.len() > 64 * 1024
                || root.not_before >= root.not_after
                || root.not_after - root.not_before > MAX_TTL + 120
                || serial_bytes(&root.serial).is_err()
            {
                return Err(bad("invalid PKI root state"));
            }
            Ed25519KeyPair::from_pkcs8(&root.pkcs8).map_err(|_| bad("invalid PKI root key"))?;
        }
        for (name, role) in &self.roles {
            valid_name(name)?;
            role.validate()?;
        }
        let prefix = format!("{mount}issue/");
        let mut leases = BTreeSet::new();
        for (serial, issued) in &self.issued {
            if serial_bytes(serial).is_err()
                || !valid_common_name(&issued.common_name)
                || issued.owner.len() != 43
                || !issued
                    .owner
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                || !issued.path.starts_with(&prefix)
                || issued.path[prefix.len()..].contains('/')
                || issued.lease_id != format!("{}/{}", issued.path, serial)
                || issued.issued > clock
                || issued.expires <= issued.issued
                || issued.expires - issued.issued > MAX_TTL
                || issued
                    .revoked_at
                    .is_some_and(|v| v < issued.issued || v > clock)
                || issued.certificate_der.is_empty()
                || issued.certificate_der.len() > 64 * 1024
                || issued.leased && !leases.insert(&issued.lease_id)
            {
                return Err(bad("invalid PKI issued-certificate state"));
            }
        }
        Ok(())
    }

    pub(super) fn has_live_leases(&self, clock: u64) -> bool {
        self.issued
            .values()
            .any(|v| v.leased && v.revoked_at.is_none() && v.expires > clock)
    }

    pub(super) fn active_owners(&self, clock: u64) -> impl Iterator<Item = &String> {
        self.issued
            .values()
            .filter(move |v| v.leased && v.revoked_at.is_none() && v.expires > clock)
            .map(|v| &v.owner)
    }

    pub(super) fn reconcile(
        &mut self,
        clock: u64,
        namespace: &str,
        live: &BTreeSet<(String, String)>,
    ) -> bool {
        let mut changed = false;
        for issued in self.issued.values_mut() {
            if issued.leased
                && issued.revoked_at.is_none()
                && issued.expires > clock
                && !live.contains(&(namespace.to_owned(), issued.owner.clone()))
            {
                issued.revoked_at = Some(clock);
                changed = true;
            }
        }
        changed
    }

    pub(super) fn lease_location(&self, id: &str) -> Option<String> {
        self.issued
            .iter()
            .find(|(_, issued)| issued.leased && issued.lease_id == id)
            .map(|(serial, _)| serial.clone())
    }

    pub(super) fn lease_lookup(&self, serial: &str, clock: u64) -> Result<Value> {
        let lease = self.issued.get(serial).ok_or_else(not_found)?;
        if !lease.leased || lease.revoked_at.is_some() || lease.expires <= clock {
            return Err(not_found());
        }
        Ok(json!({
            "id": lease.lease_id,
            "path": lease.path,
            "issue_time": timestamp(lease.issued),
            "expire_time": timestamp(lease.expires),
            "last_renewal": Value::Null,
            "renewable": false,
            "ttl": lease.expires.saturating_sub(clock),
        }))
    }

    pub(super) fn revoke_lease(&mut self, serial: &str, clock: u64) -> Result<bool> {
        let Some(lease) = self.issued.get_mut(serial) else {
            return Ok(false);
        };
        if !lease.leased || lease.revoked_at.is_some() || lease.expires <= clock {
            return Ok(false);
        }
        lease.revoked_at = Some(clock.max(lease.issued));
        Ok(true)
    }

    pub(super) fn revoke_prefix(&mut self, prefix: &str, clock: u64) -> bool {
        let boundary = format!("{prefix}/");
        let mut changed = false;
        for lease in self.issued.values_mut() {
            if lease.leased
                && (lease.lease_id == prefix || lease.lease_id.starts_with(&boundary))
                && lease.revoked_at.is_none()
                && lease.expires > clock
            {
                lease.revoked_at = Some(clock.max(lease.issued));
                changed = true;
            }
        }
        changed
    }

    pub(super) fn lease_ids<'a>(&'a self) -> impl Iterator<Item = &'a str> + 'a {
        self.issued
            .values()
            .filter(|v| v.leased)
            .map(|v| v.lease_id.as_str())
    }

    pub(super) fn handle_admin(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if path == "root/generate/internal" {
            if !write_method(method) {
                return Err(unsupported());
            }
            reject_unknown(body, &["common_name", "ttl", "key_type"])?;
            if body
                .get("key_type")
                .is_some_and(|value| value.as_str() != Some("ed25519"))
            {
                return Err(bad("bounded PKI root supports only key_type=ed25519"));
            }
            if self.root.is_some() {
                return Err(bad("PKI root already exists"));
            }
            let common_name = string(body, "common_name")?;
            if !valid_common_name(common_name) {
                return Err(bad("invalid PKI common name"));
            }
            let ttl = ttl_field(body, "ttl", DEFAULT_ROOT_TTL)?;
            if ttl == 0 || ttl > self.max_ttl {
                return Err(bad("PKI root TTL is outside bounds"));
            }
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| error(503, "PKI root key generation failed"))?;
            let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                .map_err(|_| error(503, "PKI root key generation failed"))?;
            let serial = random_serial()?;
            let not_before = now.saturating_sub(60);
            let not_after = now
                .checked_add(ttl)
                .ok_or_else(|| bad("PKI root TTL overflow"))?;
            let certificate_der = certificate_der(
                &pair,
                CertificateSpec {
                    serial: &serial,
                    issuer_cn: common_name,
                    subject_cn: common_name,
                    public_key: pair.public_key().as_ref(),
                    not_before,
                    not_after,
                    is_ca: true,
                    alt_names: &[],
                },
            )?;
            let certificate = pem("CERTIFICATE", &certificate_der);
            self.root = Some(RootCa {
                common_name: common_name.into(),
                pkcs8: pkcs8.as_ref().to_vec(),
                certificate_der,
                serial: serial.clone(),
                not_before,
                not_after,
            });
            return Ok(ok(
                json!({
                    "certificate": certificate,
                    "issuing_ca": certificate,
                    "serial_number": serial,
                    "expiration": not_after,
                }),
                true,
            ));
        }
        if path == "root/delete" {
            if !write_method(method) {
                return Err(unsupported());
            }
            reject_unknown(body, &[])?;
            let changed = self.root.take().is_some();
            return Ok(empty(changed));
        }
        if path == "cert/ca" && method == "GET" {
            reject_unknown(body, &[])?;
            let root = self.root.as_ref().ok_or_else(not_found)?;
            return Ok(ok(
                json!({"certificate": pem("CERTIFICATE", &root.certificate_der)}),
                false,
            ));
        }
        if path == "cert/crl" && method == "GET" {
            reject_unknown(body, &[])?;
            let root = self.root.as_ref().ok_or_else(not_found)?;
            let der = self.crl_der(root, now)?;
            return Ok(ok(json!({"certificate": pem("X509 CRL", &der)}), false));
        }
        if let Some(serial) = path.strip_prefix("cert/") {
            if method != "GET" {
                return Err(unsupported());
            }
            reject_unknown(body, &[])?;
            if serial == "ca" || serial == "crl" {
                return Err(not_found());
            }
            let serial = normalize_serial(serial)?;
            let cert = self.issued.get(&serial).ok_or_else(not_found)?;
            return Ok(ok(
                json!({
                    "certificate": pem("CERTIFICATE", &cert.certificate_der),
                    "revocation_time": cert.revoked_at.unwrap_or(0),
                }),
                false,
            ));
        }
        if path == "roles" || path == "roles/" {
            if method != "LIST" {
                return Err(unsupported());
            }
            reject_unknown(body, &["after", "limit"])?;
            let keys = list_keys(self.roles.keys(), "", false, body)?;
            return listing(keys);
        }
        if let Some(name) = path.strip_prefix("roles/") {
            valid_name(name)?;
            match method {
                "GET" => {
                    reject_unknown(body, &[])?;
                    let role = self.roles.get(name).ok_or_else(not_found)?;
                    return Ok(ok(role.descriptor(), false));
                }
                "DELETE" => {
                    reject_unknown(body, &[])?;
                    return Ok(empty(self.roles.remove(name).is_some()));
                }
                "POST" | "PUT" => {
                    reject_unknown(
                        body,
                        &[
                            "allowed_domains",
                            "allow_subdomains",
                            "max_ttl",
                            "generate_lease",
                            "key_type",
                        ],
                    )?;
                    if body
                        .get("key_type")
                        .is_some_and(|value| value.as_str() != Some("ed25519"))
                    {
                        return Err(bad("bounded PKI roles support only key_type=ed25519"));
                    }
                    let role = Role::from_body(body)?;
                    if !self.roles.contains_key(name) && self.roles.len() >= MAX_ROLES {
                        return Err(error(507, "PKI role capacity exhausted"));
                    }
                    let changed = self.roles.get(name) != Some(&role);
                    let response = role.descriptor();
                    self.roles.insert(name.into(), role);
                    return Ok(ok(response, changed));
                }
                _ => return Err(unsupported()),
            }
        }
        if path == "revoke" {
            if !write_method(method) {
                return Err(unsupported());
            }
            reject_unknown(body, &["serial_number"])?;
            let serial = normalize_serial(string(body, "serial_number")?)?;
            let changed = self.revoke_lease(&serial, now)?;
            return Ok(ok(
                json!({"revocation_time": self.issued.get(&serial).and_then(|v| v.revoked_at).unwrap_or(0)}),
                changed,
            ));
        }
        if path == "tidy" {
            if !write_method(method) {
                return Err(unsupported());
            }
            reject_unknown(body, &["safety_buffer"])?;
            let buffer = ttl_field(body, "safety_buffer", 72 * 3600)?;
            if buffer > 30 * 24 * 3600 {
                return Err(bad("PKI tidy safety buffer exceeds 30 days"));
            }
            let before = self.issued.len();
            self.issued
                .retain(|_, cert| cert.expires.saturating_add(buffer) > now);
            return Ok(empty(before != self.issued.len()));
        }
        Err(error(404, "PKI path is not implemented"))
    }

    pub(super) fn issue(
        &mut self,
        mount: &str,
        role_name: &str,
        body: &Value,
        owner: &str,
        owner_expires: Option<u64>,
        now: u64,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &["common_name", "alt_names", "ttl"])?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| error(503, "PKI root is not configured"))?;
        if now >= root.not_after {
            return Err(error(503, "PKI root has expired"));
        }
        let role = self.roles.get(role_name).ok_or_else(not_found)?.clone();
        let common_name = string(body, "common_name")?;
        if !valid_common_name(common_name) || !role.allows(common_name) {
            return Err(error(403, "common name is not allowed by PKI role"));
        }
        let alt_names = string_list(body.get("alt_names"))?;
        if alt_names.len() > 32
            || alt_names
                .iter()
                .any(|name| !valid_common_name(name) || !role.allows(name))
        {
            return Err(error(
                403,
                "subject alternative name is not allowed by PKI role",
            ));
        }
        if self.issued.len() >= MAX_ISSUED {
            return Err(error(507, "PKI issued-certificate capacity exhausted"));
        }
        let requested = ttl_field(body, "ttl", self.default_ttl)?
            .min(role.max_ttl)
            .min(self.max_ttl);
        let owner_limit = owner_expires.unwrap_or(u64::MAX).saturating_sub(now);
        let root_limit = root.not_after.saturating_sub(now);
        let ttl = requested.min(owner_limit).min(root_limit);
        if ttl == 0 {
            return Err(error(403, "issuer no longer has a live PKI lease window"));
        }
        let leaf_pkcs8 = Zeroizing::new(
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| error(503, "PKI leaf key generation failed"))?
                .as_ref()
                .to_vec(),
        );
        let leaf = Ed25519KeyPair::from_pkcs8(&leaf_pkcs8)
            .map_err(|_| error(503, "PKI leaf key generation failed"))?;
        let root_pair = Ed25519KeyPair::from_pkcs8(&root.pkcs8)
            .map_err(|_| error(500, "stored PKI root key is invalid"))?;
        let serial = random_serial()?;
        let not_before = now.saturating_sub(60).max(root.not_before);
        let expires = now
            .checked_add(ttl)
            .ok_or_else(|| bad("PKI lease TTL overflow"))?;
        let certificate_der = certificate_der(
            &root_pair,
            CertificateSpec {
                serial: &serial,
                issuer_cn: &root.common_name,
                subject_cn: common_name,
                public_key: leaf.public_key().as_ref(),
                not_before,
                not_after: expires,
                is_ca: false,
                alt_names: &alt_names,
            },
        )?;
        let path = format!("{mount}issue/{role_name}");
        let lease_id = format!("{path}/{serial}");
        if self.issued.contains_key(&serial) || self.issued.values().any(|v| v.lease_id == lease_id)
        {
            return Err(error(503, "PKI serial collision"));
        }
        let private_key = pem("PRIVATE KEY", &leaf_pkcs8);
        let certificate = pem("CERTIFICATE", &certificate_der);
        let issuing_ca = pem("CERTIFICATE", &root.certificate_der);
        self.issued.insert(
            serial.clone(),
            IssuedCertificate {
                leased: role.generate_lease,
                lease_id: lease_id.clone(),
                owner: owner.into(),
                path,
                issued: now,
                expires,
                revoked_at: None,
                common_name: common_name.into(),
                certificate_der,
            },
        );
        Ok(EngineResponse {
            status: 200,
            body: json!({
                "request_id":"",
                "lease_id": if role.generate_lease { lease_id } else { String::new() },
                "renewable": false,
                "lease_duration": if role.generate_lease { ttl } else { 0 },
                "data": {
                    "certificate": certificate,
                    "issuing_ca": issuing_ca,
                    "private_key": private_key,
                    "private_key_type": "ed25519",
                    "serial_number": serial,
                    "expiration": expires,
                }
            }),
            mutated: true,
        })
    }

    fn crl_der(&self, root: &RootCa, now: u64) -> Result<Vec<u8>> {
        let pair = Ed25519KeyPair::from_pkcs8(&root.pkcs8)
            .map_err(|_| error(500, "stored PKI root key is invalid"))?;
        let mut revoked = Vec::new();
        for (serial, cert) in &self.issued {
            let Some(at) = cert.revoked_at else { continue };
            if cert.expires <= now {
                continue;
            }
            revoked.push(seq(&[integer(&serial_bytes(serial)?), time(at)]));
        }
        let mut parts = vec![
            integer(&[1]),
            algorithm_ed25519(),
            name(&root.common_name),
            time(now),
            time(now.saturating_add(24 * 3600)),
        ];
        if !revoked.is_empty() {
            parts.push(seq(&revoked));
        }
        let tbs = seq(&parts);
        let signature = pair.sign(&tbs);
        Ok(seq(&[
            tbs,
            algorithm_ed25519(),
            bit_string(signature.as_ref(), 0),
        ]))
    }
}

impl Role {
    fn from_body(body: &Value) -> Result<Self> {
        let allowed_domains = string_list(body.get("allowed_domains"))?;
        if allowed_domains.is_empty()
            || allowed_domains.len() > 64
            || allowed_domains.iter().any(|v| !valid_domain(v))
        {
            return Err(bad("allowed_domains must contain 1..=64 DNS domains"));
        }
        let role = Self {
            allowed_domains: allowed_domains.into_iter().collect(),
            allow_subdomains: optional_bool(body, "allow_subdomains")?.unwrap_or(false),
            max_ttl: ttl_field(body, "max_ttl", DEFAULT_LEAF_TTL)?,
            generate_lease: optional_bool(body, "generate_lease")?.unwrap_or(false),
        };
        role.validate()?;
        Ok(role)
    }
    fn validate(&self) -> Result<()> {
        if self.allowed_domains.is_empty()
            || self.allowed_domains.len() > 64
            || self.allowed_domains.iter().any(|v| !valid_domain(v))
            || self.max_ttl == 0
            || self.max_ttl > MAX_TTL
        {
            return Err(bad("invalid PKI role"));
        }
        Ok(())
    }
    fn allows(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.allowed_domains.iter().any(|domain| {
            let domain = domain.to_ascii_lowercase();
            name == domain || self.allow_subdomains && name.ends_with(&format!(".{domain}"))
        })
    }
    fn descriptor(&self) -> Value {
        json!({
            "allowed_domains": self.allowed_domains,
            "allow_subdomains": self.allow_subdomains,
            "max_ttl": self.max_ttl,
            "generate_lease": self.generate_lease,
            "key_type": "ed25519",
        })
    }
}

fn ttl_value(value: &Value, default: u64) -> Result<u64> {
    let ttl = match value {
        Value::Number(_) => value.as_u64().ok_or_else(|| bad("invalid PKI TTL"))?,
        Value::String(_) => duration_seconds(value)?,
        _ => return Err(bad("invalid PKI TTL")),
    };
    Ok(if ttl == 0 { default } else { ttl })
}

fn ttl_field(body: &Value, field: &str, default: u64) -> Result<u64> {
    body.get(field)
        .map(|value| match value {
            Value::Number(_) => value.as_u64().ok_or_else(|| bad("invalid PKI TTL")),
            Value::String(_) => duration_seconds(value),
            _ => Err(bad("invalid PKI TTL")),
        })
        .transpose()
        .map(|v| v.unwrap_or(default))
}

fn string_list(value: Option<&Value>) -> Result<Vec<String>> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::String(value)) => {
            if value.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(value.split(',').map(|v| v.trim().to_owned()).collect())
            }
        }
        Some(Value::Array(values)) => values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| bad("expected an array of strings"))
            })
            .collect(),
        Some(_) => Err(bad("expected a string or array of strings")),
    }
}

fn valid_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err(bad("invalid PKI role name"));
    }
    Ok(())
}
fn valid_domain(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
fn valid_common_name(name: &str) -> bool {
    valid_domain(name)
}

fn random_serial() -> Result<String> {
    let mut serial =
        crate::crypto::random::<16>().map_err(|_| error(503, "PKI serial generation failed"))?;
    serial[0] &= 0x7f;
    if serial.iter().all(|v| *v == 0) {
        serial[15] = 1;
    }
    Ok(serial.iter().map(|b| format!("{b:02x}")).collect())
}
fn normalize_serial(value: &str) -> Result<String> {
    let compact: String = value
        .chars()
        .filter(|c| *c != ':' && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    serial_bytes(&compact)?;
    Ok(compact)
}
fn serial_bytes(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > 64
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err(bad("invalid certificate serial number"));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| bad("invalid certificate serial number"))
        })
        .collect()
}

struct CertificateSpec<'a> {
    serial: &'a str,
    issuer_cn: &'a str,
    subject_cn: &'a str,
    public_key: &'a [u8],
    not_before: u64,
    not_after: u64,
    is_ca: bool,
    alt_names: &'a [String],
}

fn certificate_der(signer: &Ed25519KeyPair, spec: CertificateSpec<'_>) -> Result<Vec<u8>> {
    let CertificateSpec {
        serial,
        issuer_cn,
        subject_cn,
        public_key,
        not_before,
        not_after,
        is_ca,
        alt_names,
    } = spec;
    if public_key.len() != 32 {
        return Err(error(500, "invalid Ed25519 public key"));
    }
    let mut extensions = Vec::new();
    let basic = if is_ca {
        seq(&[boolean(true)])
    } else {
        seq(&[])
    };
    extensions.push(extension(&[0x55, 0x1d, 0x13], true, &basic));
    let usage_byte = if is_ca { 0x06 } else { 0x80 };
    let unused = if is_ca { 1 } else { 7 };
    extensions.push(extension(
        &[0x55, 0x1d, 0x0f],
        true,
        &bit_string(&[usage_byte], unused),
    ));
    let mut names = Vec::new();
    names.push(context_primitive(2, subject_cn.as_bytes()));
    for name in alt_names {
        names.push(context_primitive(2, name.as_bytes()));
    }
    extensions.push(extension(&[0x55, 0x1d, 0x11], false, &seq(&names)));
    let tbs = seq(&[
        context_explicit(0, &integer(&[2])),
        integer(&serial_bytes(serial)?),
        algorithm_ed25519(),
        name(issuer_cn),
        seq(&[time(not_before), time(not_after)]),
        name(subject_cn),
        seq(&[algorithm_ed25519(), bit_string(public_key, 0)]),
        context_explicit(3, &seq(&extensions)),
    ]);
    let signature = signer.sign(&tbs);
    Ok(seq(&[
        tbs,
        algorithm_ed25519(),
        bit_string(signature.as_ref(), 0),
    ]))
}

fn extension(oid_value: &[u8], critical: bool, value_der: &[u8]) -> Vec<u8> {
    let mut parts = vec![oid(oid_value)];
    if critical {
        parts.push(boolean(true));
    }
    parts.push(octet_string(value_der));
    seq(&parts)
}
fn algorithm_ed25519() -> Vec<u8> {
    seq(&[oid(&[0x2b, 0x65, 0x70])])
}
fn name(common_name: &str) -> Vec<u8> {
    seq(&[set(&[seq(&[
        oid(&[0x55, 0x04, 0x03]),
        utf8(common_name.as_bytes()),
    ])])])
}
fn time(seconds: u64) -> Vec<u8> {
    let stamp = timestamp(seconds);
    let bytes = stamp.as_bytes();
    let year: u32 = stamp[0..4].parse().unwrap_or(2050);
    if (1950..2050).contains(&year) {
        let mut value = Vec::with_capacity(13);
        value.extend_from_slice(&bytes[2..4]);
        value.extend_from_slice(&bytes[5..7]);
        value.extend_from_slice(&bytes[8..10]);
        value.extend_from_slice(&bytes[11..13]);
        value.extend_from_slice(&bytes[14..16]);
        value.extend_from_slice(&bytes[17..19]);
        value.push(b'Z');
        der(0x17, &value)
    } else {
        let mut value = Vec::with_capacity(15);
        value.extend_from_slice(&bytes[0..4]);
        value.extend_from_slice(&bytes[5..7]);
        value.extend_from_slice(&bytes[8..10]);
        value.extend_from_slice(&bytes[11..13]);
        value.extend_from_slice(&bytes[14..16]);
        value.extend_from_slice(&bytes[17..19]);
        value.push(b'Z');
        der(0x18, &value)
    }
}
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        let bytes = (content.len() as u64).to_be_bytes();
        let first = bytes
            .iter()
            .position(|v| *v != 0)
            .unwrap_or(bytes.len() - 1);
        let len = bytes.len() - first;
        out.push(0x80 | len as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(content);
    out
}
fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flat_map(|v| v.iter().copied()).collect()
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &concat(parts))
}
fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x31, &concat(parts))
}
fn oid(value: &[u8]) -> Vec<u8> {
    der(0x06, value)
}
fn utf8(value: &[u8]) -> Vec<u8> {
    der(0x0c, value)
}
fn boolean(value: bool) -> Vec<u8> {
    der(0x01, &[if value { 0xff } else { 0x00 }])
}
fn octet_string(value: &[u8]) -> Vec<u8> {
    der(0x04, value)
}
fn integer(value: &[u8]) -> Vec<u8> {
    let mut body = value
        .iter()
        .skip_while(|v| **v == 0)
        .copied()
        .collect::<Vec<_>>();
    if body.is_empty() {
        body.push(0);
    }
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    der(0x02, &body)
}
fn bit_string(value: &[u8], unused: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(value.len() + 1);
    body.push(unused);
    body.extend_from_slice(value);
    der(0x03, &body)
}
fn context_explicit(tag: u8, value: &[u8]) -> Vec<u8> {
    der(0xa0 | tag, value)
}
fn context_primitive(tag: u8, value: &[u8]) -> Vec<u8> {
    der(0x80 | tag, value)
}
fn pem(label: &str, der: &[u8]) -> String {
    let encoded = BASE64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_root_issue_revoke_and_crl_are_der_structured()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut pki = Pki::default();
        let root = pki.handle_admin(
            "POST",
            "root/generate/internal",
            &json!({"common_name":"ca.example.test","ttl":"48h"}),
            1_700_000_000,
        )?;
        assert!(
            root.body["data"]["certificate"]
                .as_str()
                .unwrap_or("")
                .contains("BEGIN CERTIFICATE")
        );
        pki.handle_admin(
            "POST",
            "roles/web",
            &json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"2h","generate_lease":true}),
            1_700_000_001,
        )?;
        let issued = pki.issue(
            "pki/",
            "web",
            &json!({"common_name":"api.example.test","alt_names":["www.example.test"],"ttl":"1h"}),
            &"a".repeat(43),
            Some(1_700_010_000),
            1_700_000_002,
        )?;
        let serial = issued.body["data"]["serial_number"]
            .as_str()
            .ok_or("serial")?
            .to_owned();
        assert_eq!(issued.body["renewable"], false);
        assert!(
            issued.body["data"]["private_key"]
                .as_str()
                .unwrap_or("")
                .contains("BEGIN PRIVATE KEY")
        );
        let revoked = pki.handle_admin(
            "POST",
            "revoke",
            &json!({"serial_number":serial}),
            1_700_000_100,
        )?;
        assert_eq!(revoked.body["data"]["revocation_time"], 1_700_000_100);
        let crl = pki.handle_admin("GET", "cert/crl", &json!({}), 1_700_000_101)?;
        assert!(
            crl.body["data"]["certificate"]
                .as_str()
                .unwrap_or("")
                .contains("BEGIN X509 CRL")
        );
        Ok(())
    }
}
