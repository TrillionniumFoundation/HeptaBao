//! Bounded internal PKI engine. The CA private key and issued private keys are
//! persisted only through the Service encrypted state boundary; issued leaf
//! private keys are released once in the successful response and are not kept.
//! Revocation is represented durably and published through a signed CRL.
use super::*;
use crate::auth::{LeaseOwner, ServiceOwnerProfile};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::net::{IpAddr, SocketAddr};
use zeroize::{Zeroize, Zeroizing};

const MAX_ROLES: usize = 256;
const MAX_ISSUED: usize = 4096;
const MAX_TTL: u64 = 10 * 365 * 24 * 3600;
const DEFAULT_ROOT_TTL: u64 = 365 * 24 * 3600;
const DEFAULT_LEAF_TTL: u64 = 24 * 3600;
const MAX_ACME_LIST: usize = 64;
const MAX_ACME_CONFIG_STRING: usize = 2048;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
struct AcmeConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_acme_wildcard")]
    allowed_issuers: Vec<String>,
    #[serde(default = "default_acme_wildcard")]
    allowed_roles: Vec<String>,
    #[serde(default)]
    allow_role_ext_key_usage: bool,
    #[serde(default = "default_acme_directory_policy")]
    default_directory_policy: String,
    #[serde(default)]
    dns_resolver: String,
    #[serde(default = "default_acme_eab_policy")]
    eab_policy: String,
}

fn default_acme_wildcard() -> Vec<String> {
    vec!["*".into()]
}

fn default_acme_directory_policy() -> String {
    "sign-verbatim".into()
}

fn default_acme_eab_policy() -> String {
    "not-required".into()
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_issuers: default_acme_wildcard(),
            allowed_roles: default_acme_wildcard(),
            allow_role_ext_key_usage: false,
            default_directory_policy: default_acme_directory_policy(),
            dns_resolver: String::new(),
            eab_policy: default_acme_eab_policy(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Pki {
    #[serde(default = "default_leaf_ttl")]
    pub(super) default_ttl: u64,
    #[serde(default = "max_pki_ttl")]
    pub(super) max_ttl: u64,
    #[serde(default)]
    cluster_path: String,
    #[serde(default)]
    aia_path: String,
    #[serde(default)]
    acme: Box<AcmeConfig>,
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
    #[serde(default)]
    allow_ip_sans: bool,
    max_ttl: u64,
    generate_lease: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct IssuedCertificate {
    #[serde(default)]
    pub(super) leased: bool,
    pub(super) lease_id: String,
    pub(super) owner: LeaseOwner,
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
            cluster_path: String::new(),
            aia_path: String::new(),
            acme: Box::new(AcmeConfig::default()),
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

    pub(super) fn validate(&self, namespace: &str, mount: &str, clock: u64) -> Result<()> {
        if self.default_ttl == 0
            || self.default_ttl > self.max_ttl
            || self.max_ttl > MAX_TTL
            || self.roles.len() > MAX_ROLES
            || self.issued.len() > MAX_ISSUED
        {
            return Err(bad("invalid PKI state bounds"));
        }
        validate_uri(&self.cluster_path, "PKI cluster path")?;
        validate_uri(&self.aia_path, "PKI AIA path")?;
        validate_acme_config(&self.acme, &self.roles)?;
        if self.acme.enabled && self.cluster_path.is_empty() {
            return Err(bad("enabled PKI ACME requires a configured cluster path"));
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
                || issued
                    .owner
                    .validate_scope(namespace, ServiceOwnerProfile::DigestAlphabet)
                    .is_err()
                || issued.owner.batch_claims().is_some_and(|claims| {
                    issued.issued < claims.issued_at() || issued.expires > claims.expires_at()
                })
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

    pub(super) fn active_owners(&self, clock: u64) -> impl Iterator<Item = &LeaseOwner> {
        self.issued
            .values()
            .filter(move |v| v.leased && v.revoked_at.is_none() && v.expires > clock)
            .map(|v| &v.owner)
    }

    pub(super) fn all_owners(&self) -> impl Iterator<Item = &LeaseOwner> {
        self.issued.values().map(|issued| &issued.owner)
    }

    pub(super) fn reconcile(
        &mut self,
        clock: u64,
        namespace: &str,
        live: &BTreeSet<(String, LeaseOwner)>,
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
        if path == "config/cluster" {
            return self.handle_cluster_config(method, body);
        }
        if path == "config/acme" {
            return self.handle_acme_config(method, body);
        }
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
                    ip_sans: &[],
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
                            "allow_ip_sans",
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

    fn handle_cluster_config(&mut self, method: &str, body: &Value) -> Result<EngineResponse> {
        match method {
            "GET" => {
                reject_unknown(body, &[])?;
                return Ok(ok(
                    json!({"path": self.cluster_path, "aia_path": self.aia_path}),
                    false,
                ));
            }
            "POST" | "PUT" => {}
            _ => return Err(unsupported()),
        }
        reject_unknown(body, &["path", "aia_path"])?;
        let mut cluster_path = self.cluster_path.clone();
        let mut aia_path = self.aia_path.clone();
        if let Some(value) = body.get("path") {
            cluster_path = value
                .as_str()
                .ok_or_else(|| bad("PKI cluster path must be a string"))?
                .to_owned();
        }
        if let Some(value) = body.get("aia_path") {
            aia_path = value
                .as_str()
                .ok_or_else(|| bad("PKI AIA path must be a string"))?
                .to_owned();
        }
        validate_uri(&cluster_path, "PKI cluster path")?;
        validate_uri(&aia_path, "PKI AIA path")?;
        if self.acme.enabled && cluster_path.is_empty() {
            return Err(bad("enabled PKI ACME requires a configured cluster path"));
        }
        let changed = self.cluster_path != cluster_path || self.aia_path != aia_path;
        self.cluster_path = cluster_path;
        self.aia_path = aia_path;
        Ok(ok(
            json!({"path": self.cluster_path, "aia_path": self.aia_path}),
            changed,
        ))
    }

    fn handle_acme_config(&mut self, method: &str, body: &Value) -> Result<EngineResponse> {
        if method == "GET" {
            reject_unknown(body, &[])?;
            return Ok(ok(self.acme.descriptor(), false));
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        reject_unknown(
            body,
            &[
                "enabled",
                "allowed_issuers",
                "allowed_roles",
                "allow_role_ext_key_usage",
                "default_directory_policy",
                "dns_resolver",
                "eab_policy",
            ],
        )?;
        let mut config = (*self.acme).clone();
        if let Some(value) = body.get("enabled") {
            config.enabled = value
                .as_bool()
                .ok_or_else(|| bad("ACME enabled must be a boolean"))?;
        }
        if let Some(value) = body.get("allowed_issuers") {
            config.allowed_issuers = string_list(Some(value))?;
        }
        if let Some(value) = body.get("allowed_roles") {
            config.allowed_roles = string_list(Some(value))?;
        }
        if let Some(value) = body.get("allow_role_ext_key_usage") {
            config.allow_role_ext_key_usage = value
                .as_bool()
                .ok_or_else(|| bad("ACME allow_role_ext_key_usage must be a boolean"))?;
        }
        if let Some(value) = body.get("default_directory_policy") {
            config.default_directory_policy = value
                .as_str()
                .ok_or_else(|| bad("ACME default_directory_policy must be a string"))?
                .to_owned();
        }
        if let Some(value) = body.get("dns_resolver") {
            config.dns_resolver = value
                .as_str()
                .ok_or_else(|| bad("ACME dns_resolver must be a string"))?
                .to_owned();
        }
        if let Some(value) = body.get("eab_policy") {
            config.eab_policy = value
                .as_str()
                .ok_or_else(|| bad("ACME eab_policy must be a string"))?
                .to_owned();
        }
        validate_acme_config(&config, &self.roles)?;
        if config.enabled && self.cluster_path.is_empty() {
            return Err(bad("enabled PKI ACME requires a configured cluster path"));
        }
        let changed = self.acme.as_ref() != &config;
        *self.acme = config;
        Ok(ok(self.acme.descriptor(), changed))
    }

    pub(super) fn issue(
        &mut self,
        mount: &str,
        role_name: &str,
        body: &Value,
        owner: &LeaseOwner,
        owner_expires: Option<u64>,
        now: u64,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &["common_name", "alt_names", "ip_sans", "ttl"])?;
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
        let ip_sans = ip_list(body.get("ip_sans"))?;
        if ip_sans.len() > 32 || !role.allow_ip_sans && !ip_sans.is_empty() {
            return Err(error(
                403,
                "IP subject alternative names are not allowed by PKI role",
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
                ip_sans: &ip_sans,
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
                owner: owner.clone(),
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
            allow_ip_sans: optional_bool(body, "allow_ip_sans")?.unwrap_or(false),
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
            "allow_ip_sans": self.allow_ip_sans,
            "max_ttl": self.max_ttl,
            "generate_lease": self.generate_lease,
            "key_type": "ed25519",
        })
    }
}

impl AcmeConfig {
    fn descriptor(&self) -> Value {
        json!({
            "allowed_roles": self.allowed_roles,
            "allow_role_ext_key_usage": self.allow_role_ext_key_usage,
            "allowed_issuers": self.allowed_issuers,
            "default_directory_policy": self.default_directory_policy,
            "enabled": self.enabled,
            "dns_resolver": self.dns_resolver,
            "eab_policy": self.eab_policy,
        })
    }
}

fn validate_acme_config(config: &AcmeConfig, roles: &BTreeMap<String, Role>) -> Result<()> {
    validate_acme_names(&config.allowed_roles, "allowed_roles")?;
    if config.allowed_issuers.is_empty()
        || config.allowed_issuers.len() > MAX_ACME_LIST
        || config
            .allowed_issuers
            .iter()
            .any(|issuer| issuer.is_empty() || issuer.len() > 128)
    {
        return Err(bad("invalid ACME allowed_issuers"));
    }
    if config.allowed_issuers.len() != 1 || config.allowed_issuers[0] != "*" {
        return Err(error(
            501,
            "PKI ACME issuer selection is not implemented; allowed_issuers must remain ['*']",
        ));
    }
    for role in config
        .allowed_roles
        .iter()
        .filter(|role| role.as_str() != "*")
    {
        if !roles.contains_key(role) {
            return Err(bad("ACME allowed role does not exist"));
        }
    }
    match config.default_directory_policy.as_str() {
        "forbid" | "sign-verbatim" => {}
        value
            if value.strip_prefix("role:").is_some_and(|name| {
                !name.is_empty()
                    && roles.contains_key(name)
                    && (config.allowed_roles.len() == 1 && config.allowed_roles[0] == "*"
                        || config.allowed_roles.iter().any(|role| role == name))
            }) => {}
        _ => return Err(bad("invalid ACME default_directory_policy")),
    }
    if config.dns_resolver.len() > MAX_ACME_CONFIG_STRING {
        return Err(bad("ACME dns_resolver is too long"));
    }
    if !config.dns_resolver.is_empty() {
        let address = config
            .dns_resolver
            .parse::<SocketAddr>()
            .map_err(|_| bad("ACME dns_resolver must be an IP address and port"))?;
        if address.port() == 0 {
            return Err(bad("ACME dns_resolver port must be nonzero"));
        }
    }
    if config.default_directory_policy.len() > MAX_ACME_CONFIG_STRING
        || config.eab_policy.len() > MAX_ACME_CONFIG_STRING
    {
        return Err(bad("ACME configuration string is too long"));
    }
    if !matches!(
        config.eab_policy.as_str(),
        "not-required" | "new-account-required" | "always-required"
    ) {
        return Err(bad("invalid ACME eab_policy"));
    }
    if config.enabled && config.allowed_roles.is_empty() {
        return Err(bad("ACME allowed_roles must not be empty"));
    }
    Ok(())
}

fn validate_acme_names(values: &[String], field: &str) -> Result<()> {
    if values.is_empty() || values.len() > MAX_ACME_LIST {
        return Err(bad("ACME name list is outside bounds"));
    }
    if values.iter().any(|value| {
        value == "*" && values.len() != 1 || value != "*" && valid_name(value).is_err()
    }) {
        return Err(bad(if field == "allowed_roles" {
            "invalid ACME allowed_roles"
        } else {
            "invalid ACME name list"
        }));
    }
    Ok(())
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

fn ip_list(value: Option<&Value>) -> Result<Vec<IpAddr>> {
    string_list(value)?
        .into_iter()
        .map(|value| {
            value
                .parse()
                .map_err(|_| bad("expected valid IP subject alternative names"))
        })
        .collect()
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

fn validate_uri(value: &str, field: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > MAX_ACME_CONFIG_STRING
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(bad("PKI URL is outside bounds"));
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err(bad(field));
    };
    if !matches!(scheme, "http" | "https") {
        return Err(bad(field));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(bad(field));
    }
    Ok(())
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
    ip_sans: &'a [IpAddr],
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
        ip_sans,
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
    for ip in ip_sans {
        let bytes = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        names.push(context_primitive(7, &bytes));
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
            &serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?,
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

    #[test]
    fn ip_sans_are_role_gated_and_encoded_as_general_name_ip()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut pki = Pki::default();
        pki.handle_admin(
            "POST",
            "root/generate/internal",
            &json!({"common_name":"ca.example.test","ttl":"48h"}),
            1_700_000_000,
        )?;
        pki.handle_admin(
            "POST",
            "roles/web",
            &json!({"allowed_domains":["example.test"]}),
            1_700_000_001,
        )?;
        let denied = pki.issue(
            "pki/",
            "web",
            &json!({"common_name":"api.example.test","ip_sans":["127.0.0.1"]}),
            &serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?,
            None,
            1_700_000_002,
        );
        let denied_status = match denied {
            Ok(_) => {
                return Err("role without allow_ip_sans unexpectedly issued a certificate".into());
            }
            Err(error) => error.status,
        };
        assert_eq!(denied_status, 403);
        pki.handle_admin(
            "POST",
            "roles/web-ip",
            &json!({"allowed_domains":["example.test"],"allow_subdomains":true,"allow_ip_sans":true}),
            1_700_000_003,
        )?;
        let issued = pki.issue(
            "pki/",
            "web-ip",
            &json!({"common_name":"api.example.test","ip_sans":["127.0.0.1","2001:db8::1"]}),
            &serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?,
            None,
            1_700_000_004,
        )?;
        let cert = issued.body["data"]["certificate"]
            .as_str()
            .ok_or("certificate")?;
        let der = BASE64.decode(
            cert.strip_prefix("-----BEGIN CERTIFICATE-----\n")
                .ok_or("pem begin")?
                .strip_suffix("-----END CERTIFICATE-----\n")
                .ok_or("pem end")?
                .lines()
                .collect::<String>(),
        )?;
        assert!(der.windows(6).any(|v| v == [0x87, 0x04, 127, 0, 0, 1]));
        assert!(der.windows(18).any(|v| v[0] == 0x87 && v[1] == 0x10));
        Ok(())
    }

    #[test]
    fn acme_configuration_is_bounded_and_serde_stable()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut pki = Pki::default();
        let cluster = pki.handle_admin(
            "POST",
            "config/cluster",
            &json!({
                "path":"https://acme.example.test/v1/pki",
                "aia_path":"http://cdn.example.test/pki"
            }),
            1_700_000_000,
        )?;
        assert_eq!(
            cluster.body["data"]["path"],
            "https://acme.example.test/v1/pki"
        );
        let acme = pki.handle_admin(
            "POST",
            "config/acme",
            &json!({"enabled":true,"eab_policy":"new-account-required"}),
            1_700_000_000,
        )?;
        assert_eq!(acme.body["data"]["enabled"], true);
        assert_eq!(acme.body["data"]["eab_policy"], "new-account-required");
        let before = pki.handle_admin("GET", "config/acme", &json!({}), 1_700_000_000)?;
        for (path, body, status) in [
            (
                "config/acme",
                json!({"enabled":false,"unknown":"must-not-persist"}),
                400,
            ),
            (
                "config/cluster",
                json!({"path":"file:///secret-location"}),
                400,
            ),
            ("config/acme", json!({"allowed_issuers":["issuer-a"]}), 501),
        ] {
            let rejected = pki.handle_admin("POST", path, &body, 1_700_000_000);
            assert_eq!(
                rejected
                    .as_ref()
                    .map(|v| v.status)
                    .unwrap_or_else(|v| v.status),
                status
            );
            if let Ok(response) = rejected {
                assert!(response.body.get("data").is_none());
            }
        }
        assert_eq!(
            pki.handle_admin("GET", "config/acme", &json!({}), 1_700_000_000)?
                .body,
            before.body
        );
        let mut restored: Pki = serde_json::from_slice(&serde_json::to_vec(&pki)?)?;
        assert_eq!(
            restored
                .handle_admin("GET", "config/cluster", &json!({}), 1_700_000_000)?
                .body["data"],
            cluster.body["data"]
        );
        assert_eq!(
            restored
                .handle_admin("GET", "config/acme", &json!({}), 1_700_000_000)?
                .body["data"],
            before.body["data"]
        );
        Ok(())
    }
}
