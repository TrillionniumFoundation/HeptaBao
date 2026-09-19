//! Durable authentication and a deliberately bounded, fail-closed ACL dialect.
//!
//! Every public service request owns one affine principal and durably commits any
//! finite-use decrement before dispatch. Raw authorization remains crate-internal.
use crate::federated_auth::{JwtAlgorithm, JwtVerifier, TrustPolicy, VerificationKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    digest, hmac, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::BufReader,
    num::NonZeroU32,
};
use x509_parser::{
    asn1_rs::{Any, FromDer},
    extensions::{GeneralName, ParsedExtension},
    parse_x509_certificate,
    utils::format_serial,
};
use zeroize::{Zeroize, Zeroizing};

#[path = "auth_oidc.rs"]
mod oidc;

#[path = "auth_kubernetes.rs"]
mod kubernetes;

pub(crate) use kubernetes::{KubernetesLoginObservation, KubernetesLoginPlan};
pub(crate) use oidc::{OidcBeginObservation, OidcBeginPlan, OidcExchange, OidcLoginObservation};

#[path = "auth_remote.rs"]
mod remote;
use remote::RemoteJwtSource;
pub(crate) use remote::{RemoteJwtLoginObservation, RemoteJwtLoginPlan};

#[path = "auth_acl.rs"]
mod acl;
#[path = "auth_capabilities.rs"]
mod capabilities;
#[path = "auth_cubbyhole.rs"]
mod cubbyhole;
#[path = "auth_identity.rs"]
mod identity;
#[path = "auth_wrapping.rs"]
mod wrapping;
pub(crate) use capabilities::InspectionTarget;
use identity::LoginIdentity;

const DEFAULT_TTL: u64 = 3600;
const MAX_TTL: u64 = 32 * 24 * 3600;
const PASSWORD_ROUNDS: u32 = 600_000;
const MFA_SEED_BYTES: usize = 32;
const MFA_PERIOD_SECONDS: u64 = 30;
const MFA_DIGITS: usize = 6;
const MFA_DRIFT_STEPS: u64 = 1;
const MAX_EXTERNAL_REPLAY_ENTRIES: usize = 32_000;
const CAPABILITIES: &[&str] = &[
    "create", "read", "update", "delete", "list", "patch", "sudo", "deny",
];
const MAX_CERT_ROLE_MATCH_VALUES: usize = 32;
const MAX_CERT_ROLE_MATCH_VALUE_BYTES: usize = 256;
const MAX_CERT_EXTENSION_VALUE_BYTES: usize = 4096;

fn default_bind_secret_id() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthState {
    #[serde(default, skip_serializing_if = "is_zero")]
    wrapping_clock: u64,
    tokens: BTreeMap<String, Token>,
    policies: BTreeMap<String, BTreeMap<String, Policy>>,
    users: BTreeMap<String, BTreeMap<String, User>>,
    roles: BTreeMap<String, BTreeMap<String, Role>>,
    // The original fixed mounts retain their exact persisted representation.
    // Custom mounts add a structural dimension; namespace strings are never
    // concatenated with mount names to manufacture storage keys.
    #[serde(default)]
    mounted_users: BTreeMap<String, BTreeMap<String, BTreeMap<String, User>>>,
    #[serde(default)]
    mounted_roles: BTreeMap<String, BTreeMap<String, BTreeMap<String, Role>>>,
    #[serde(default)]
    auth_mounts: BTreeMap<String, BTreeMap<String, AuthMount>>,
    #[serde(default)]
    jwt_mounts: BTreeMap<String, BTreeMap<String, JwtMountState>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    kubernetes_mounts: BTreeMap<String, BTreeMap<String, kubernetes::KubernetesMount>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    oidc_mounts: BTreeMap<String, BTreeMap<String, oidc::OidcMount>>,
    /// Bounded LDAP directory profile. Password verification and optional group
    /// membership are observed from the enrolled directory; local user/group
    /// records retain the policy, TTL and MFA authority issued by this server.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    ldap_mounts: BTreeMap<String, BTreeMap<String, LdapMount>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    ldap_groups: BTreeMap<String, BTreeMap<String, BTreeMap<String, BTreeSet<String>>>>,
    /// Deployment-enrolled authentication plugins never choose token authority.
    /// This durable map binds a mount to one admitted plugin id and server-owned
    /// policy/TTL limits. The plugin returns only an authentication decision and
    /// a bounded external alias.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    plugin_auth_mounts: BTreeMap<String, BTreeMap<String, PluginAuthMount>>,
    /// Certificate-auth roles are bound to an exact leaf digest and may carry
    /// bounded subject/SAN selectors. Certificate bytes never enter durable
    /// application state; TLS owns chain, EKU and CRL validation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    cert_roles: BTreeMap<String, BTreeMap<String, BTreeMap<String, CertRole>>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct CertRole {
    certificate_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_common_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_dns_sans: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_email_sans: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_uri_sans: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_organizational_units: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required_extensions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_metadata_extensions: Vec<String>,
    policies: BTreeSet<String>,
    token_ttl: u64,
    token_max_ttl: u64,
    token_num_uses: u64,
}

#[derive(Debug)]
struct PresentedCertificate {
    sha256: String,
}

#[derive(Default)]
struct CertificateAttributes {
    common_names: Vec<String>,
    dns_sans: Vec<String>,
    email_sans: Vec<String>,
    uri_sans: Vec<String>,
    organizational_units: Vec<String>,
    extensions: BTreeMap<String, String>,
    /// OpenBao exposes these stable certificate identity fields as login
    /// metadata. Keep them derived from the presented leaf and never persist
    /// the certificate bytes in application state.
    serial_number: String,
    subject_key_id: Option<String>,
    authority_key_id: Option<String>,
}

impl CertRole {
    fn has_certificate_constraints(&self) -> bool {
        !self.allowed_names.is_empty()
            || !self.allowed_common_names.is_empty()
            || !self.allowed_dns_sans.is_empty()
            || !self.allowed_email_sans.is_empty()
            || !self.allowed_uri_sans.is_empty()
            || !self.allowed_organizational_units.is_empty()
            || !self.required_extensions.is_empty()
            || !self.allowed_metadata_extensions.is_empty()
    }
}

fn certificate_sha256(der: &[u8]) -> String {
    digest::digest(&digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn normalized_certificate_sha256(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    (normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(normalized)
}

fn parse_presented_certificate(chain: &[Vec<u8>]) -> Result<PresentedCertificate, AuthError> {
    if chain.is_empty()
        || chain.len() > 8
        || chain
            .iter()
            .any(|cert| cert.is_empty() || cert.len() > 64 * 1024)
    {
        return Err(denied());
    }
    let leaf = chain.first().ok_or_else(denied)?;
    Ok(PresentedCertificate {
        sha256: certificate_sha256(leaf),
    })
}

fn parse_certificate_attributes(der: &[u8]) -> Option<CertificateAttributes> {
    let (remaining, certificate) = parse_x509_certificate(der).ok()?;
    if !remaining.is_empty() {
        return None;
    }

    let mut attributes = CertificateAttributes {
        serial_number: certificate.tbs_certificate.serial.to_str_radix(10),
        ..CertificateAttributes::default()
    };
    let mut seen_extension_oids = BTreeSet::new();
    for value in certificate
        .subject()
        .iter_common_name()
        .filter_map(|value| value.as_str().ok())
    {
        if value.len() <= MAX_CERT_ROLE_MATCH_VALUE_BYTES {
            attributes.common_names.push(value.to_owned());
        }
    }
    for value in certificate
        .subject()
        .iter_organizational_unit()
        .filter_map(|value| value.as_str().ok())
    {
        if value.len() <= MAX_CERT_ROLE_MATCH_VALUE_BYTES {
            attributes.organizational_units.push(value.to_owned());
        }
    }
    // x509-parser rejects malformed or duplicate SAN extensions through this
    // accessor. A constrained role must fail closed when SAN parsing is not
    // unambiguous.
    let subject_alt_names = certificate.subject_alternative_name().ok()?;
    if let Some(subject_alt_names) = subject_alt_names {
        for name in &subject_alt_names.value.general_names {
            let (target, value) = match name {
                GeneralName::DNSName(value) => (&mut attributes.dns_sans, *value),
                GeneralName::RFC822Name(value) => (&mut attributes.email_sans, *value),
                GeneralName::URI(value) => (&mut attributes.uri_sans, *value),
                GeneralName::Invalid(_, _) => return None,
                _ => continue,
            };
            if value.is_empty() || value.len() > MAX_CERT_ROLE_MATCH_VALUE_BYTES {
                return None;
            }
            target.push(value.to_owned());
        }
    }
    for extension in certificate.extensions() {
        if extension.parsed_extension().error().is_some() {
            return None;
        }
        let oid = extension.oid.to_id_string();
        if !seen_extension_oids.insert(oid.clone()) {
            return None;
        }
        if extension.value.len() <= MAX_CERT_EXTENSION_VALUE_BYTES
            && let Some(value) = der_extension_value(extension.value)
            && attributes.extensions.insert(oid, value).is_some()
        {
            return None;
        }
        match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(key_id) => {
                attributes.subject_key_id = Some(format_serial(key_id.0));
            }
            ParsedExtension::AuthorityKeyIdentifier(key_id) => {
                attributes.authority_key_id = key_id
                    .key_identifier
                    .as_ref()
                    .map(|value| format_serial(value.0));
            }
            _ => {}
        }
    }
    Some(attributes)
}

fn der_extension_value(value: &[u8]) -> Option<String> {
    let (remaining, value) = Any::from_der(value).ok()?;
    if !remaining.is_empty() {
        return None;
    }
    let bytes = value.data;
    match value.tag().0 {
        // OpenBao's cert backend unmarshals ASN.1 string extensions into a Go
        // string. Keep the same bounded string family and reject binary values.
        0x0c | 0x12 | 0x13 | 0x14 | 0x16 | 0x1a => {
            let text = std::str::from_utf8(bytes).ok()?;
            (!text.is_empty() && text.len() <= MAX_CERT_EXTENSION_VALUE_BYTES)
                .then_some(text.to_owned())
        }
        0x1e if bytes.len() % 2 == 0 => {
            let units = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
            let text = String::from_utf16(units.collect::<Vec<_>>().as_slice()).ok()?;
            (!text.is_empty() && text.len() <= MAX_CERT_EXTENSION_VALUE_BYTES).then_some(text)
        }
        _ => None,
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut pattern_index, mut value_index) = (0_usize, 0_usize);
    let (mut star_index, mut star_value_index) = (None, 0_usize);
    while value_index < value.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == value[value_index] {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn matches_any(values: &[String], patterns: &[String]) -> bool {
    patterns.is_empty()
        || patterns
            .iter()
            .any(|pattern| values.iter().any(|value| wildcard_match(pattern, value)))
}

fn matches_cert_role(
    presented: &PresentedCertificate,
    attributes: Option<&CertificateAttributes>,
    role: &CertRole,
) -> bool {
    if role.certificate_sha256 != presented.sha256 {
        return false;
    }
    if !role.has_certificate_constraints() {
        return true;
    }
    let Some(attributes) = attributes else {
        return false;
    };
    let mut names = attributes.common_names.clone();
    names.extend(attributes.dns_sans.iter().cloned());
    names.extend(attributes.email_sans.iter().cloned());
    if !matches_any(&names, &role.allowed_names)
        || !matches_any(&attributes.common_names, &role.allowed_common_names)
        || !matches_any(&attributes.dns_sans, &role.allowed_dns_sans)
        || !matches_any(&attributes.email_sans, &role.allowed_email_sans)
        || !matches_any(&attributes.uri_sans, &role.allowed_uri_sans)
        || !matches_any(
            &attributes.organizational_units,
            &role.allowed_organizational_units,
        )
    {
        return false;
    }
    role.required_extensions.iter().all(|requirement| {
        let Some((oid, pattern)) = requirement.split_once(':') else {
            return false;
        };
        attributes
            .extensions
            .get(oid)
            .is_some_and(|value| wildcard_match(pattern, value))
    })
}

fn certificate_metadata(
    attributes: Option<&CertificateAttributes>,
    role_name: &str,
    role: &CertRole,
) -> BTreeMap<String, String> {
    let Some(attributes) = attributes else {
        return BTreeMap::new();
    };
    let mut metadata = BTreeMap::from([
        ("cert_name".into(), role_name.into()),
        (
            "common_name".into(),
            attributes.common_names.first().cloned().unwrap_or_default(),
        ),
        ("serial_number".into(), attributes.serial_number.clone()),
        (
            "subject_key_id".into(),
            attributes.subject_key_id.clone().unwrap_or_default(),
        ),
        (
            "authority_key_id".into(),
            attributes.authority_key_id.clone().unwrap_or_default(),
        ),
    ]);
    for oid in &role.allowed_metadata_extensions {
        if let Some(value) = attributes.extensions.get(oid) {
            metadata.insert(oid.replace('.', "-"), value.clone());
        }
    }
    metadata
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct LdapMount {
    url: String,
    bind_dn: String,
    user_dn_template: String,
    #[serde(default)]
    starttls: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    group_dn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    group_attr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    group_name_attr: String,
}

impl LdapMount {
    fn group_attr(&self) -> &str {
        if self.group_attr.is_empty() {
            "member"
        } else {
            &self.group_attr
        }
    }
    fn group_name_attr(&self) -> &str {
        if self.group_name_attr.is_empty() {
            "cn"
        } else {
            &self.group_name_attr
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct PluginAuthMount {
    plugin_id: String,
    policies: BTreeSet<String>,
    token_ttl: u64,
    token_max_ttl: u64,
    token_num_uses: u64,
}

#[derive(Clone)]
pub(crate) struct PluginAuthLoginPlan {
    namespace: String,
    mount: String,
    config: PluginAuthMount,
    now: u64,
}

impl PluginAuthLoginPlan {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
    pub(crate) fn mount(&self) -> &str {
        &self.mount
    }
    pub(crate) fn plugin_id(&self) -> &str {
        &self.config.plugin_id
    }
    pub(crate) fn now(&self) -> u64 {
        self.now
    }
}

fn valid_ldap_attribute_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

pub(crate) struct LdapLoginPlan {
    namespace: String,
    mount: String,
    name: String,
    dn: String,
    config: LdapMount,
    password: Zeroizing<String>,
    totp_code: Option<Zeroizing<String>>,
    now: u64,
    started: std::time::Instant,
}

pub(crate) struct LdapLoginObservation {
    groups: BTreeSet<String>,
}

impl LdapLoginPlan {
    pub(crate) fn execute(
        &self,
        outbound: &crate::outbound::Outbound,
    ) -> Result<LdapLoginObservation, AuthError> {
        match outbound.ldap_bind_and_search_groups(
            &self.config.url,
            &self.dn,
            self.password.as_str(),
            &self.config.group_dn,
            self.config.group_attr(),
            self.config.group_name_attr(),
        ) {
            Ok(Some(groups)) => Ok(LdapLoginObservation { groups }),
            Ok(None) => Err(denied()),
            Err(_) => Err(err(503, "LDAP provider bind or group search unavailable")),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct JwtKeyRecord {
    algorithm: String,
    bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct JwtConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote: Option<RemoteJwtSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jwt_supported_algs: Option<BTreeSet<String>>,
    issuer: String,
    audiences: BTreeSet<String>,
    required_namespace: Option<String>,
    clock_skew_seconds: u64,
    maximum_token_lifetime_seconds: u64,
    keys: BTreeMap<String, JwtKeyRecord>,
}

fn valid_jwt_kid(kid: &str) -> bool {
    !kid.is_empty() && kid.len() <= 1024 && !kid.chars().any(char::is_control)
}

fn insert_jwt_key(
    keys: &mut BTreeMap<String, JwtKeyRecord>,
    kid: &str,
    algorithm: &str,
    bytes: Vec<u8>,
) -> Result<(), AuthError> {
    if !valid_jwt_kid(kid) || keys.contains_key(kid) {
        return Err(bad("invalid or duplicate JWT key id"));
    }
    if !matches!(algorithm, "EdDSA" | "ES256" | "RS256") {
        return Err(bad("unsupported JWT algorithm"));
    }
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(bad("JWT key is outside bounds"));
    }
    keys.insert(
        kid.into(),
        JwtKeyRecord {
            algorithm: algorithm.into(),
            bytes,
        },
    );
    Ok(())
}

fn parse_legacy_jwt_keys(values: &[Value]) -> Result<BTreeMap<String, JwtKeyRecord>, AuthError> {
    if values.is_empty() || values.len() > 64 {
        return Err(bad("JWT key count is outside bounds"));
    }
    let mut keys = BTreeMap::new();
    for value in values {
        reject_unknown(value, &["kid", "algorithm", "key_base64"])?;
        let kid = string_field(value, "kid")?;
        let algorithm = string_field(value, "algorithm")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(string_field(value, "key_base64")?)
            .map_err(|_| bad("invalid JWT key encoding"))?;
        insert_jwt_key(&mut keys, kid, algorithm, bytes)?;
    }
    Ok(keys)
}

/// Parse the public-key subset of RFC 7517 needed by the bounded JWT verifier.
/// Only explicit signature keys are admitted; symmetric keys, private material,
/// unknown curves and duplicate key IDs are rejected before state mutation.
fn parse_jwks(jwks: &Value) -> Result<BTreeMap<String, JwtKeyRecord>, AuthError> {
    reject_unknown(jwks, &["keys"])?;
    let values = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("jwks.keys must be an array"))?;
    if values.is_empty() || values.len() > 64 {
        return Err(bad("JWT key count is outside bounds"));
    }
    let mut keys = BTreeMap::new();
    for value in values {
        let object = value
            .as_object()
            .ok_or_else(|| bad("JWK must be an object"))?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "kid" | "kty" | "crv" | "x" | "y" | "n" | "e" | "alg" | "use" | "key_ops"
            )
        }) {
            return Err(bad("unsupported JWK member"));
        }
        let kid = string_field(value, "kid")?;
        if object.get("use").is_some_and(|v| v.as_str() != Some("sig")) {
            return Err(bad("JWK use must be sig when present"));
        }
        if let Some(ops) = object.get("key_ops") {
            let ops = ops
                .as_array()
                .ok_or_else(|| bad("JWK key_ops must be an array"))?;
            if ops.is_empty() || ops.len() > 8 || ops.iter().any(|op| op.as_str() != Some("verify"))
            {
                return Err(bad("JWK key_ops must contain only verify"));
            }
        }
        let kty = string_field(value, "kty")?;
        let alg = string_field(value, "alg")?;
        if kty == "RSA" {
            if alg != "RS256" || ["crv", "x", "y"].iter().any(|k| object.contains_key(*k)) {
                return Err(bad("unsupported RSA JWK profile"));
            }
            let n = URL_SAFE_NO_PAD
                .decode(string_field(value, "n")?)
                .map_err(|_| bad("invalid RSA modulus"))?;
            let e = URL_SAFE_NO_PAD
                .decode(string_field(value, "e")?)
                .map_err(|_| bad("invalid RSA exponent"))?;
            if !(256..=512).contains(&n.len())
                || n.first().is_none_or(|v| *v < 0x80)
                || e != [1, 0, 1]
            {
                return Err(bad("RSA key must use 2048..4096 bits and exponent 65537"));
            }
            let mut bytes = Vec::with_capacity(n.len() + 5);
            bytes.extend_from_slice(&(n.len() as u16).to_be_bytes());
            bytes.extend(n);
            bytes.extend(e);
            insert_jwt_key(&mut keys, kid, alg, bytes)?;
            continue;
        }
        if object.contains_key("n") || object.contains_key("e") {
            return Err(bad("RSA fields on non-RSA key"));
        }
        let crv = string_field(value, "crv")?;
        let x = URL_SAFE_NO_PAD
            .decode(string_field(value, "x")?)
            .map_err(|_| bad("invalid JWK x coordinate"))?;
        let bytes = match (kty, crv, alg) {
            ("OKP", "Ed25519", "EdDSA") if x.len() == 32 && !object.contains_key("y") => x,
            ("EC", "P-256", "ES256") if x.len() == 32 => {
                let y = URL_SAFE_NO_PAD
                    .decode(string_field(value, "y")?)
                    .map_err(|_| bad("invalid JWK y coordinate"))?;
                if y.len() != 32 {
                    return Err(bad("invalid P-256 JWK coordinate size"));
                }
                let mut point = Vec::with_capacity(65);
                point.push(4);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                point
            }
            _ => return Err(bad("unsupported JWK key type, curve or algorithm")),
        };
        insert_jwt_key(&mut keys, kid, alg, bytes)?;
    }
    Ok(keys)
}

impl JwtConfig {
    fn verifier(&self) -> Result<JwtVerifier, AuthError> {
        let policy = TrustPolicy::new(
            self.issuer.clone(),
            self.audiences.clone(),
            self.required_namespace
                .clone()
                .filter(|value| !value.is_empty()),
            self.clock_skew_seconds,
            self.maximum_token_lifetime_seconds,
        )
        .map_err(|_| bad("invalid JWT trust policy"))?;
        let mut keys = Vec::with_capacity(self.keys.len());
        for (key_id, record) in &self.keys {
            if self
                .jwt_supported_algs
                .as_ref()
                .is_some_and(|algs| !algs.contains(&record.algorithm))
            {
                continue;
            }
            let algorithm = match record.algorithm.as_str() {
                "EdDSA" => JwtAlgorithm::Ed25519,
                "ES256" => JwtAlgorithm::Es256,
                "RS256" => JwtAlgorithm::Rs256,
                _ => return Err(bad("unsupported JWT algorithm")),
            };
            keys.push(
                VerificationKey::new(key_id.clone(), algorithm, record.bytes.clone())
                    .map_err(|_| bad("invalid JWT verification key"))?,
            );
        }
        JwtVerifier::new(policy, keys).map_err(|_| bad("invalid JWT verifier configuration"))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct JwtRole {
    bound_groups: BTreeSet<String>,
    #[serde(default)]
    bound_subject: Option<String>,
    #[serde(default)]
    bound_audiences: BTreeSet<String>,
    policies: BTreeSet<String>,
    token_ttl: u64,
    token_max_ttl: u64,
    token_num_uses: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct ExternalIdentity {
    issuer: String,
    subject: String,
    namespace: String,
    groups: BTreeSet<String>,
    last_seen: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct JwtMountState {
    config: Option<JwtConfig>,
    roles: BTreeMap<String, JwtRole>,
    identities: BTreeMap<String, ExternalIdentity>,
    replay: BTreeMap<String, u64>,
    // Once expired replay records are pruned, a clock rollback must not revive
    // them. This watermark commits atomically with replay and issued tokens.
    last_admission_time: u64,
}

impl Drop for JwtMountState {
    fn drop(&mut self) {
        for (mut fingerprint, _) in std::mem::take(&mut self.replay) {
            fingerprint.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct AuthMount {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accessor: Option<String>,
    #[serde(default = "auth_mount_revision_one")]
    revision: u64,
    kind: String,
    description: String,
    #[serde(default)]
    default_lease_ttl: u64,
    #[serde(default)]
    max_lease_ttl: u64,
}

#[derive(Clone, Copy)]
struct AuthScope<'a> {
    namespace: &'a str,
    mount: &'a str,
}

const fn auth_mount_revision_one() -> u64 {
    1
}

impl AuthMount {
    fn new(kind: &str, description: &str) -> Self {
        Self {
            accessor: None,
            revision: 1,
            kind: kind.into(),
            description: description.into(),
            default_lease_ttl: 0,
            max_lease_ttl: 0,
        }
    }

    fn descriptor(&self) -> Value {
        json!({
            "type": self.kind,
            "accessor": self.accessor.as_deref().unwrap_or(""),
            "revision": self.revision,
            "description": self.description,
            "local": false,
            "seal_wrap": false,
            "options": {},
            "config": {
                "default_lease_ttl": self.default_lease_ttl,
                "max_lease_ttl": self.max_lease_ttl,
                "force_no_cache": false
            }
        })
    }
}

fn legacy_auth_mounts() -> BTreeMap<String, AuthMount> {
    BTreeMap::from([
        (
            "token".into(),
            AuthMount::new("token", "token based credentials"),
        ),
        (
            "userpass".into(),
            AuthMount::new("userpass", "username and password credentials"),
        ),
        (
            "approle".into(),
            AuthMount::new("approle", "machine role credentials"),
        ),
    ])
}

impl Drop for AuthState {
    fn drop(&mut self) {
        for (mut verifier, _) in std::mem::take(&mut self.tokens) {
            verifier.zeroize();
        }
        // Nested User and Role destructors clear their owned verifier buffers.
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Token {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrapping: Option<wrapping::WrappedResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entity_id: Option<String>,
    #[serde(default)]
    cubbyhole: cubbyhole::TokenCubbyhole,
    accessor: String,
    namespace: String,
    policies: BTreeSet<String>,
    root: bool,
    parent: Option<String>,
    created_at: u64,
    expires_at: Option<u64>,
    max_expires_at: Option<u64>,
    period: u64,
    renewable: bool,
    uses_remaining: Option<u64>,
    display_name: String,
    /// Authentication mount provenance, inherited by derived tokens. Old
    /// snapshots lack it and require conservative revocation on legacy unmount.
    #[serde(default)]
    auth_mount: Option<String>,
    #[serde(default)]
    auth_origin_known: bool,
    /// Certificate login provenance is retained as a digest and role name so
    /// renewal can fail closed when the role or its policies are removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_cert_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_cert_sha256: Option<String>,
}

impl Drop for Token {
    fn drop(&mut self) {
        if let Some(parent) = &mut self.parent {
            parent.zeroize();
        }
    }
}

/// An affine capability owned by exactly one service dispatcher invocation.
/// It is non-cloneable, non-serializable and never crosses the public API.
pub(super) struct Principal {
    identity_policies: BTreeSet<String>,
    identity_checked: bool,
    digest: String,
    token: Token,
    #[cfg(test)]
    request_time: u64,
}

impl Drop for Principal {
    fn drop(&mut self) {
        self.digest.zeroize();
    }
}

impl Principal {
    pub(super) fn is_root(&self) -> bool {
        self.token.root
    }
    fn policies(&self) -> &BTreeSet<String> {
        &self.token.policies
    }
    pub(super) fn consumed_use(&self) -> bool {
        self.token.uses_remaining.is_some()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Policy {
    source: String,
    rules: Vec<Rule>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Rule {
    path: String,
    capabilities: BTreeSet<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct User {
    salt: Vec<u8>,
    verifier: Vec<u8>,
    rounds: u32,
    policies: BTreeSet<String>,
    token_ttl: u64,
    token_max_ttl: u64,
    token_num_uses: u64,
    #[serde(default)]
    mfa: Option<TotpEnrollment>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpEnrollment {
    secret: Vec<u8>,
    period_seconds: u64,
    digits: u8,
    last_accepted_counter: Option<u64>,
}

impl Drop for TotpEnrollment {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for User {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.verifier.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Role {
    role_id: String,
    #[serde(default = "default_bind_secret_id")]
    bind_secret_id: bool,
    policies: BTreeSet<String>,
    token_ttl: u64,
    token_max_ttl: u64,
    token_num_uses: u64,
    secret_id_ttl: u64,
    secret_id_num_uses: u64,
    secret_ids: BTreeMap<String, SecretId>,
}

impl Drop for Role {
    fn drop(&mut self) {
        for (mut verifier, _) in std::mem::take(&mut self.secret_ids) {
            verifier.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SecretId {
    accessor: String,
    expires_at: Option<u64>,
    uses_remaining: Option<u64>,
}

pub struct AuthResponse {
    pub(super) login_identity: Option<LoginIdentity>,
    pub status: u16,
    pub body: Value,
    pub mutated: bool,
}

#[derive(Clone, Debug)]
pub struct AuthError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for AuthError {}

fn err(status: u16, message: &str) -> AuthError {
    AuthError {
        status,
        message: message.into(),
    }
}
fn bad(message: &str) -> AuthError {
    err(400, message)
}
fn denied() -> AuthError {
    err(403, "permission denied")
}
fn response(data: Value, mutated: bool) -> AuthResponse {
    AuthResponse {
        login_identity: None,
        status: 200,
        body: json!({"data": data}),
        mutated,
    }
}
fn empty(mutated: bool) -> AuthResponse {
    AuthResponse {
        login_identity: None,
        status: 204,
        body: Value::Null,
        mutated,
    }
}
fn random_bytes(len: usize) -> Result<Vec<u8>, AuthError> {
    let mut bytes = vec![0; len];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| err(500, "secure randomness unavailable"))?;
    Ok(bytes)
}
fn random_id(prefix: &str) -> Result<String, AuthError> {
    let bytes = Zeroizing::new(random_bytes(32)?);
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));
    Ok(format!("{prefix}{}", encoded.as_str()))
}
fn hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, value.as_bytes()).as_ref())
}
fn checked_expiry(now: u64, ttl: u64) -> Result<u64, AuthError> {
    now.checked_add(ttl)
        .ok_or_else(|| bad("TTL overflows timestamp"))
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn unlimited_zero(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}

fn validate_namespace(namespace: &str) -> Result<(), AuthError> {
    if namespace.is_empty() {
        return Ok(());
    }
    if namespace.len() > 512 || namespace.split('/').any(|s| !valid_name(s)) {
        return Err(bad("invalid namespace"));
    }
    Ok(())
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}
fn validate_path(path: &str, pattern: bool) -> Result<(), AuthError> {
    if path.is_empty()
        || path.len() > 2048
        || path.starts_with('/')
        || path.contains("//")
        || path
            .bytes()
            .any(|b| b < 0x21 || b == 0x7f || b == b'\\' || b == b'%')
        || path.split('/').any(|s| s == "." || s == "..")
    {
        return Err(bad("invalid ACL path"));
    }
    if pattern {
        if path.contains("{{")
            || path.contains("${")
            || path.matches('*').count() > 1
            || path.contains('*') && !path.ends_with('*')
            || path.split('/').any(|s| s.contains('+') && s != "+")
        {
            return Err(bad(
                "only whole-segment + and terminal * ACL wildcards are supported",
            ));
        }
    } else if path.contains('*') || path.contains('+') {
        return Err(bad("wildcards are not permitted in request paths"));
    }
    Ok(())
}

fn string_field<'a>(body: &'a Value, field: &str) -> Result<&'a str, AuthError> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| bad("required string field missing or invalid"))
}
fn number(body: &Value, field: &str, default: u64) -> Result<u64, AuthError> {
    match body.get(field) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| bad("expected nonnegative integer")),
    }
}
fn boolean(body: &Value, field: &str, default: bool) -> Result<bool, AuthError> {
    match body.get(field) {
        None => Ok(default),
        Some(value) => value.as_bool().ok_or_else(|| bad("expected boolean")),
    }
}
fn optional_auth_revision(body: &Value) -> Result<Option<u64>, AuthError> {
    body.get("cas_revision")
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| bad("cas_revision must be a nonnegative integer"))
        })
        .transpose()
}
fn require_auth_revision(expected: Option<u64>, current: u64) -> Result<(), AuthError> {
    if expected.is_some_and(|value| value != current) {
        return Err(err(409, "stale auth mount revision; no state was changed"));
    }
    Ok(())
}
fn require_absent_auth_revision(expected: Option<u64>) -> Result<(), AuthError> {
    if expected.is_some_and(|value| value != 0) {
        return Err(err(
            409,
            "auth mount is absent; cas_revision must be zero for creation",
        ));
    }
    Ok(())
}
fn next_auth_revision(current: u64) -> Result<u64, AuthError> {
    current
        .max(1)
        .checked_add(1)
        .ok_or_else(|| err(507, "auth mount revision exhausted"))
}
fn duration(body: &Value, field: &str, default: u64) -> Result<u64, AuthError> {
    match body.get(field) {
        None => Ok(default),
        Some(value) if value.is_u64() => value.as_u64().ok_or_else(|| bad("invalid duration")),
        Some(Value::String(value)) => {
            if let Ok(seconds) = value.parse::<u64>() {
                return Ok(seconds);
            }
            let (digits, multiplier) = match value.as_bytes().last() {
                Some(b's') => (&value[..value.len() - 1], 1),
                Some(b'm') => (&value[..value.len() - 1], 60),
                Some(b'h') => (&value[..value.len() - 1], 3600),
                Some(b'd') => (&value[..value.len() - 1], 86400),
                _ => return Err(bad("duration must be whole seconds or integer s/m/h/d")),
            };
            digits
                .parse::<u64>()
                .ok()
                .and_then(|n| n.checked_mul(multiplier))
                .ok_or_else(|| bad("invalid duration"))
        }
        _ => Err(bad("invalid duration")),
    }
}
fn reject_unknown(body: &Value, allowed: &[&str]) -> Result<(), AuthError> {
    let object = body
        .as_object()
        .ok_or_else(|| bad("request body must be an object"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(bad("unsupported request field"));
    }
    Ok(())
}
fn policies(
    body: &Value,
    field: &str,
    default: &BTreeSet<String>,
    add_default: bool,
) -> Result<BTreeSet<String>, AuthError> {
    let mut result = match body.get(field) {
        None => default.clone(),
        Some(Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| bad("policies must contain strings"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(bad("policies must be an array or comma-separated string")),
    };
    if result.iter().any(|name| !valid_name(name)) {
        return Err(bad("invalid policy name"));
    }
    if add_default && !result.contains("root") {
        result.insert("default".into());
    }
    Ok(result)
}

fn claim_values(body: &Value, name: &str) -> Result<BTreeSet<String>, AuthError> {
    let values: Vec<&str> = match body.get(name) {
        None => Vec::new(),
        Some(Value::String(value)) => value.split(',').map(str::trim).collect(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("claim bindings must be strings"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(bad("claim bindings must be a string or array")),
    };
    if values.len() > 64
        || values.iter().any(|value| {
            value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control)
        })
    {
        return Err(bad(
            "claim bindings exceed bounds or contain invalid strings",
        ));
    }
    Ok(values.into_iter().map(str::to_owned).collect())
}

fn bounded_string_list(
    body: &Value,
    field: &str,
    max_values: usize,
    max_bytes: usize,
) -> Result<Vec<String>, AuthError> {
    let Some(value) = body.get(field) else {
        return Ok(Vec::new());
    };
    let values: Vec<&str> = match value {
        Value::String(value) => vec![value.as_str()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("certificate role selector values must be strings"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(bad("certificate role selectors must be a string or array")),
    };
    if values.len() > max_values
        || values.iter().any(|value| {
            value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control)
        })
    {
        return Err(bad("certificate role selectors exceed their bounds"));
    }
    Ok(values.into_iter().map(str::to_owned).collect())
}

fn valid_oid(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let first_arc = match first {
        "0" => 0_u8,
        "1" => 1,
        "2" => 2,
        _ => return false,
    };
    !value.is_empty()
        && value.len() <= 64
        && !second.is_empty()
        && second.len() <= 8
        && second.bytes().all(|byte| byte.is_ascii_digit())
        && (second == "0" || !second.starts_with('0'))
        && (first_arc == 2 || second.parse::<u16>().is_ok_and(|arc| arc <= 39))
        && parts.all(|part| {
            !part.is_empty()
                && part.len() <= 8
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'))
        })
}

fn certificate_extension_requirements(body: &Value, field: &str) -> Result<Vec<String>, AuthError> {
    let values = bounded_string_list(body, field, MAX_CERT_ROLE_MATCH_VALUES, 320)?;
    for value in &values {
        let Some((oid, pattern)) = value.split_once(':') else {
            return Err(bad(
                "certificate extension requirements must be oid:pattern",
            ));
        };
        if !valid_oid(oid) || pattern.is_empty() || pattern.len() > MAX_CERT_ROLE_MATCH_VALUE_BYTES
        {
            return Err(bad("invalid certificate extension requirement"));
        }
    }
    Ok(values)
}

fn certificate_metadata_extensions(body: &Value, field: &str) -> Result<Vec<String>, AuthError> {
    let values = bounded_string_list(body, field, MAX_CERT_ROLE_MATCH_VALUES, 64)?;
    if values.iter().any(|value| !valid_oid(value)) {
        return Err(bad("invalid certificate metadata extension OID"));
    }
    Ok(values)
}

impl AuthState {
    pub(super) fn known_namespaces(&self) -> BTreeSet<String> {
        let mut namespaces = BTreeSet::new();
        for token in self.tokens.values() {
            if !token.namespace.is_empty() {
                namespaces.insert(token.namespace.clone());
            }
        }
        namespaces.extend(
            self.policies
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(self.users.keys().filter(|value| !value.is_empty()).cloned());
        namespaces.extend(self.roles.keys().filter(|value| !value.is_empty()).cloned());
        namespaces.extend(
            self.mounted_users
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(
            self.mounted_roles
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(
            self.auth_mounts
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(
            self.jwt_mounts
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(
            self.kubernetes_mounts
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(
            self.oidc_mounts
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(
            self.ldap_mounts
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(
            self.ldap_groups
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(
            self.plugin_auth_mounts
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces.extend(
            self.cert_roles
                .keys()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        namespaces
    }

    pub(super) fn namespace_is_empty(&self, namespace: &str) -> bool {
        !self
            .tokens
            .values()
            .any(|token| token.namespace == namespace)
            && self
                .policies
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .users
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .roles
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .mounted_users
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .mounted_roles
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .auth_mounts
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .jwt_mounts
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .kubernetes_mounts
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .oidc_mounts
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .ldap_mounts
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .ldap_groups
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .plugin_auth_mounts
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
            && self
                .cert_roles
                .get(namespace)
                .is_none_or(|entries| entries.is_empty())
    }

    pub(super) fn bootstrap(now: u64) -> Result<(Self, String), AuthError> {
        let mut state = Self {
            wrapping_clock: 0,
            tokens: BTreeMap::new(),
            policies: BTreeMap::new(),
            users: BTreeMap::new(),
            roles: BTreeMap::new(),
            mounted_users: BTreeMap::new(),
            mounted_roles: BTreeMap::new(),
            auth_mounts: BTreeMap::new(),
            jwt_mounts: BTreeMap::new(),
            kubernetes_mounts: BTreeMap::new(),
            oidc_mounts: BTreeMap::new(),
            ldap_mounts: BTreeMap::new(),
            ldap_groups: BTreeMap::new(),
            plugin_auth_mounts: BTreeMap::new(),
            cert_roles: BTreeMap::new(),
        };
        let token = Token {
            wrapping: None,
            entity_id: None,
            cubbyhole: cubbyhole::TokenCubbyhole::default(),
            accessor: random_id("a.")?,
            namespace: String::new(),
            policies: BTreeSet::from(["root".into()]),
            root: true,
            parent: None,
            created_at: now,
            expires_at: None,
            max_expires_at: None,
            period: 0,
            renewable: false,
            uses_remaining: None,
            display_name: "root".into(),
            auth_mount: None,
            auth_origin_known: true,
            auth_cert_role: None,
            auth_cert_sha256: None,
        };
        let raw = random_id("hvs.")?;
        state.tokens.insert(hash(&raw), token);
        Ok((state, raw))
    }

    fn active_token(&self, id: &str, now: u64, consume_check: bool) -> Result<&Token, AuthError> {
        let token = self.tokens.get(id).ok_or_else(denied)?;
        let now = if token.wrapping.is_some() {
            now.max(self.wrapping_clock)
        } else {
            now
        };
        if token.expires_at.is_some_and(|t| now >= t)
            || consume_check && token.uses_remaining == Some(0)
        {
            return Err(denied());
        }
        let mut seen = BTreeSet::new();
        seen.insert(id.to_owned());
        let mut parent = token.parent.as_deref();
        while let Some(parent_id) = parent {
            if !seen.insert(parent_id.to_owned()) {
                return Err(denied());
            }
            let ancestor = self.tokens.get(parent_id).ok_or_else(denied)?;
            if ancestor.expires_at.is_some_and(|t| now >= t) || ancestor.uses_remaining == Some(0) {
                return Err(denied());
            }
            parent = ancestor.parent.as_deref();
        }
        Ok(token)
    }

    /// A read-only capability is available only for an unlimited ordinary token.
    /// Finite-use and wrapping tokens must enter the durable admission path.
    pub(super) fn authenticate_read_only(
        &self,
        raw: &str,
        now: u64,
    ) -> Result<Option<Principal>, AuthError> {
        if raw.len() > 256 || !raw.starts_with("hvs.") {
            return Err(denied());
        }
        let id = hash(raw);
        let token = self.active_token(&id, now, true)?;
        if token.uses_remaining.is_some() || token.wrapping.is_some() {
            return Ok(None);
        }
        Ok(Some(Self::request_principal(id, token.clone(), now)))
    }

    fn request_principal(id: String, token: Token, _now: u64) -> Principal {
        Principal {
            identity_policies: BTreeSet::new(),
            identity_checked: false,
            digest: id,
            token,
            #[cfg(test)]
            request_time: _now,
        }
    }

    pub(super) fn authenticate(&mut self, raw: &str, now: u64) -> Result<Principal, AuthError> {
        if raw.len() > 256 || !raw.starts_with("hvs.") {
            return Err(denied());
        }
        let id = hash(raw);
        self.active_token(&id, now, true)?;
        let token = self.tokens.get_mut(&id).ok_or_else(denied)?;
        if let Some(remaining) = &mut token.uses_remaining {
            *remaining -= 1;
        }
        // Retain the last-use view only in this affine request capability.
        // Durable admission destroys its stored cubbyhole before any secret
        // can leave the service. A failed response cannot make it reusable.
        let request_token = token.clone();
        if token.uses_remaining == Some(0) {
            token.cubbyhole = cubbyhole::TokenCubbyhole::default();
            token.wrapping = None;
        }
        Ok(Self::request_principal(id, request_token, now))
    }

    fn check_principal<'a>(
        &'a self,
        principal: &Principal,
        namespace: &str,
        now: u64,
    ) -> Result<&'a Token, AuthError> {
        validate_namespace(namespace)?;
        let token = self.active_token(&principal.digest, now, false)?;
        if token.accessor != principal.token.accessor
            || token.entity_id != principal.token.entity_id
            || token.entity_id.is_some() && !principal.identity_checked
            || !token.root && token.namespace != namespace
        {
            return Err(denied());
        }
        Ok(token)
    }

    pub(super) fn authorize_request(
        &self,
        principal: &Principal,
        namespace: &str,
        path: &str,
        capability: &str,
        now: u64,
    ) -> Result<(), AuthError> {
        validate_path(path, false)?;
        if !CAPABILITIES.contains(&capability) || capability == "deny" {
            return Err(denied());
        }
        let token = self.check_principal(principal, namespace, now)?;
        if principal.token.wrapping.is_some() {
            return if path == "sys/wrapping/unwrap" && capability == "update" {
                Ok(())
            } else {
                Err(denied())
            };
        }
        if token.root {
            return Ok(());
        }
        if self.policy_allows(
            namespace,
            path,
            capability,
            &token.policies,
            &principal.identity_policies,
        ) {
            Ok(())
        } else {
            Err(denied())
        }
    }

    pub(super) fn authorize_sudo_request(
        &self,
        principal: &Principal,
        namespace: &str,
        path: &str,
        capability: &str,
        now: u64,
    ) -> Result<(), AuthError> {
        self.authorize_request(principal, namespace, path, capability, now)?;
        self.authorize_request(principal, namespace, path, "sudo", now)
    }

    fn policy_allows(
        &self,
        namespace: &str,
        path: &str,
        capability: &str,
        policies: &BTreeSet<String>,
        identity_policies: &BTreeSet<String>,
    ) -> bool {
        let mut decision = acl::Decision::default();
        for policy_name in policies.iter().chain(identity_policies) {
            let explicit = self
                .policies
                .get(namespace)
                .and_then(|entries| entries.get(policy_name));
            if let Some(policy) = explicit {
                for rule in &policy.rules {
                    decision.consider(
                        &rule.path,
                        rule.capabilities.iter().map(String::as_str),
                        path,
                        capability,
                    );
                }
            } else if policy_name == "default" {
                for (pattern, capabilities) in acl::DEFAULT_RULES {
                    decision.consider(pattern, capabilities.iter().copied(), path, capability);
                }
            }
        }
        decision.allowed()
    }

    #[cfg(test)]
    fn authorize_for_unit_test(
        &self,
        principal: &Principal,
        namespace: &str,
        path: &str,
        capability: &str,
    ) -> Result<(), AuthError> {
        self.authorize_request(
            principal,
            namespace,
            path,
            capability,
            principal.request_time,
        )
    }

    fn permission<'principal>(
        &self,
        principal: Option<&'principal Principal>,
        namespace: &str,
        path: &str,
        cap: &str,
        now: u64,
    ) -> Result<&'principal Principal, AuthError> {
        let principal = principal.ok_or_else(denied)?;
        self.authorize_request(principal, namespace, path, cap, now)?;
        Ok(principal)
    }

    fn prepare_issue(token: Token, now: u64) -> Result<(String, Token, AuthResponse), AuthError> {
        let raw = Zeroizing::new(random_id("hvs.")?);
        let token_id = hash(&raw);
        let result = AuthResponse {
            login_identity: None,
            status: 200,
            mutated: true,
            body: json!({"auth": {
                "client_token": raw.as_str(), "accessor": token.accessor, "policies": token.policies,
                "token_policies": token.policies, "entity_id": token.entity_id.as_deref().unwrap_or(""), "metadata": {}, "lease_duration": token.expires_at.map(|expiry| expiry.saturating_sub(now)).unwrap_or(0),
                "renewable": token.renewable, "token_type": "service", "orphan": token.parent.is_none(), "num_uses": token.uses_remaining.unwrap_or(0)
            }}),
        };
        Ok((token_id, token, result))
    }

    fn issue(&mut self, token: Token, now: u64) -> Result<AuthResponse, AuthError> {
        let (token_id, token, result) = Self::prepare_issue(token, now)?;
        self.tokens.insert(token_id, token);
        Ok(result)
    }

    fn revoke(&mut self, id: &str) {
        let mut removed = BTreeSet::from([id.to_owned()]);
        loop {
            let children: Vec<String> = self
                .tokens
                .iter()
                .filter(|(_, token)| token.parent.as_ref().is_some_and(|p| removed.contains(p)))
                .map(|(id, _)| id.clone())
                .collect();
            let old_len = removed.len();
            removed.extend(children);
            if removed.len() == old_len {
                break;
            }
        }
        for mut id in removed {
            if let Some((mut stored_id, _)) = self.tokens.remove_entry(&id) {
                stored_id.zeroize();
            }
            id.zeroize();
        }
    }

    fn effective_auth_mounts(&self, namespace: &str) -> BTreeMap<String, AuthMount> {
        let mut entries = self
            .auth_mounts
            .get(namespace)
            .cloned()
            .unwrap_or_else(legacy_auth_mounts);
        for (name, entry) in &mut entries {
            if entry.accessor.is_none() {
                // Preserve legacy mount identity without a read-side mutation.
                // Re-enabled mounts receive random new incarnation accessors.
                entry.accessor = Some(format!(
                    "auth_legacy_{}",
                    hash(&format!(
                        "heptabao-legacy-auth-mount-v1\0{namespace}\0{name}\0{}",
                        entry.kind
                    ))
                ));
            }
        }
        entries
    }

    fn users_at(&self, scope: AuthScope<'_>) -> Option<&BTreeMap<String, User>> {
        if scope.mount == "userpass" {
            self.users.get(scope.namespace)
        } else {
            self.mounted_users.get(scope.namespace)?.get(scope.mount)
        }
    }

    fn users_at_mut(&mut self, scope: AuthScope<'_>) -> &mut BTreeMap<String, User> {
        if scope.mount == "userpass" {
            self.users.entry(scope.namespace.into()).or_default()
        } else {
            self.mounted_users
                .entry(scope.namespace.into())
                .or_default()
                .entry(scope.mount.into())
                .or_default()
        }
    }

    fn roles_at(&self, scope: AuthScope<'_>) -> Option<&BTreeMap<String, Role>> {
        if scope.mount == "approle" {
            self.roles.get(scope.namespace)
        } else {
            self.mounted_roles.get(scope.namespace)?.get(scope.mount)
        }
    }

    fn roles_at_mut(&mut self, scope: AuthScope<'_>) -> &mut BTreeMap<String, Role> {
        if scope.mount == "approle" {
            self.roles.entry(scope.namespace.into()).or_default()
        } else {
            self.mounted_roles
                .entry(scope.namespace.into())
                .or_default()
                .entry(scope.mount.into())
                .or_default()
        }
    }

    fn ldap_groups_at(&self, scope: AuthScope<'_>) -> Option<&BTreeMap<String, BTreeSet<String>>> {
        self.ldap_groups.get(scope.namespace)?.get(scope.mount)
    }

    fn ldap_groups_at_mut(
        &mut self,
        scope: AuthScope<'_>,
    ) -> &mut BTreeMap<String, BTreeSet<String>> {
        self.ldap_groups
            .entry(scope.namespace.into())
            .or_default()
            .entry(scope.mount.into())
            .or_default()
    }

    fn disable_auth_mount(&mut self, scope: AuthScope<'_>) {
        if let Some(mounts) = self.oidc_mounts.get_mut(scope.namespace) {
            mounts.remove(scope.mount);
        }
        if let Some(mounts) = self.kubernetes_mounts.get_mut(scope.namespace) {
            mounts.remove(scope.mount);
        }
        self.users_at_mut(scope).clear();
        self.roles_at_mut(scope).clear();
        if let Some(mounts) = self.jwt_mounts.get_mut(scope.namespace) {
            mounts.remove(scope.mount);
        }
        if let Some(mounts) = self.ldap_mounts.get_mut(scope.namespace) {
            mounts.remove(scope.mount);
        }
        if let Some(mounts) = self.ldap_groups.get_mut(scope.namespace) {
            mounts.remove(scope.mount);
        }
        if let Some(mounts) = self.plugin_auth_mounts.get_mut(scope.namespace) {
            mounts.remove(scope.mount);
        }
        if let Some(mounts) = self.cert_roles.get_mut(scope.namespace) {
            mounts.remove(scope.mount);
        }
        let revoke: Vec<String> = self
            .tokens
            .iter()
            .filter(|(_, token)| {
                token.namespace == scope.namespace
                    && !token.root
                    && (token.auth_mount.as_deref() == Some(scope.mount)
                        || (!token.auth_origin_known
                            && matches!(scope.mount, "userpass" | "approle")))
            })
            .map(|(digest, _)| digest.clone())
            .collect();
        for digest in revoke {
            self.revoke(&digest);
        }
    }

    fn jwt_at(&self, scope: AuthScope<'_>) -> Option<&JwtMountState> {
        self.jwt_mounts.get(scope.namespace)?.get(scope.mount)
    }

    fn jwt_at_mut(&mut self, scope: AuthScope<'_>) -> &mut JwtMountState {
        self.jwt_mounts
            .entry(scope.namespace.into())
            .or_default()
            .entry(scope.mount.into())
            .or_default()
    }

    fn admit_external_replay(
        &mut self,
        scope: AuthScope<'_>,
        fingerprint: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<(), AuthError> {
        let state = self.jwt_at_mut(scope);
        if expires_at <= now || now < state.last_admission_time {
            return Err(denied());
        }
        let mut key = URL_SAFE_NO_PAD.encode(fingerprint);
        if state.replay.get(&key).is_some_and(|expiry| *expiry > now) {
            key.zeroize();
            return Err(denied());
        }
        if state
            .replay
            .values()
            .filter(|expiry| **expiry > now)
            .count()
            >= MAX_EXTERNAL_REPLAY_ENTRIES
        {
            key.zeroize();
            return Err(err(503, "external replay registry capacity exhausted"));
        }
        // All fallible checks precede the mutation, including randomness for
        // token creation at the caller; Service owns the durable transaction.
        let mut retained = BTreeMap::new();
        for (mut id, expiry) in std::mem::take(&mut state.replay) {
            if expiry > now {
                retained.insert(id, expiry);
            } else {
                id.zeroize();
            }
        }
        retained.insert(key, expires_at);
        state.replay = retained;
        state.last_admission_time = now;
        Ok(())
    }

    #[cfg(test)]
    fn auth_mount_enabled(&self, namespace: &str, mount: &str, kind: &str) -> bool {
        self.auth_mounts.get(namespace).map_or_else(
            || {
                legacy_auth_mounts()
                    .get(mount)
                    .is_some_and(|entry| entry.kind == kind)
            },
            |entries| entries.get(mount).is_some_and(|entry| entry.kind == kind),
        )
    }

    pub(super) fn remount_mount(
        &mut self,
        namespace: &str,
        from: &str,
        to: &str,
        cas_revision: Option<u64>,
    ) -> Result<AuthResponse, AuthError> {
        if from.is_empty()
            || to.is_empty()
            || from == to
            || from.len() > 256
            || to.len() > 256
            || !from.split('/').all(valid_name)
            || !to.split('/').all(valid_name)
        {
            return Err(bad(
                "auth remount paths must be distinct canonical segments",
            ));
        }
        if from == "token" || to == "token" {
            return Err(bad("the built-in token auth method cannot be remounted"));
        }
        let mut entries = self.effective_auth_mounts(namespace);
        let mut moved = entries
            .get(from)
            .cloned()
            .ok_or_else(|| err(404, "auth mount not found"))?;
        require_auth_revision(cas_revision, moved.revision)?;
        if entries.keys().any(|name| {
            name != from
                && (name == to
                    || name.starts_with(&format!("{to}/"))
                    || to.starts_with(&format!("{name}/")))
        }) {
            return Err(bad(
                "auth remount destination conflicts with an existing mount",
            ));
        }
        entries.remove(from);
        moved.revision = next_auth_revision(moved.revision)?;
        let revision = moved.revision;
        let accessor = moved.accessor.clone().unwrap_or_default();
        entries.insert(to.into(), moved);
        self.auth_mounts.insert(namespace.into(), entries);

        if from == "userpass" {
            if let Some(users) = self.users.remove(namespace) {
                self.mounted_users
                    .entry(namespace.into())
                    .or_default()
                    .insert(to.into(), users);
            }
        } else if let Some(users) = self
            .mounted_users
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.mounted_users
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), users);
        }
        if from == "approle" {
            if let Some(roles) = self.roles.remove(namespace) {
                self.mounted_roles
                    .entry(namespace.into())
                    .or_default()
                    .insert(to.into(), roles);
            }
        } else if let Some(roles) = self
            .mounted_roles
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.mounted_roles
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), roles);
        }
        if let Some(value) = self
            .jwt_mounts
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.jwt_mounts
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        if let Some(value) = self
            .kubernetes_mounts
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.kubernetes_mounts
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        if let Some(value) = self
            .oidc_mounts
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.oidc_mounts
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        if let Some(value) = self
            .ldap_mounts
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.ldap_mounts
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        if let Some(value) = self
            .ldap_groups
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.ldap_groups
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        if let Some(value) = self
            .plugin_auth_mounts
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.plugin_auth_mounts
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        if let Some(value) = self
            .cert_roles
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.cert_roles
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        for token in self.tokens.values_mut() {
            if token.namespace == namespace && token.auth_mount.as_deref() == Some(from) {
                token.auth_mount = Some(to.into());
            }
        }
        Ok(response(
            json!({"from":format!("auth/{from}/"),"to":format!("auth/{to}/"),
                "revision":revision,"accessor":accessor}),
            true,
        ))
    }

    fn auth_mount_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let suffix = path
            .strip_prefix("sys/auth")
            .ok_or_else(|| bad("invalid auth mount path"))?;
        if suffix.is_empty() || suffix == "/" {
            if !matches!(method, "GET" | "LIST") {
                return Err(err(405, "method not allowed"));
            }
            self.permission(principal, namespace, "sys/auth", "read", now)?;
            reject_unknown(body, &[])?;
            let entries = self
                .effective_auth_mounts(namespace)
                .into_iter()
                .map(|(name, mount)| (format!("{name}/"), mount.descriptor()))
                .collect();
            return Ok(response(Value::Object(entries), false));
        }
        let requested = suffix.trim_start_matches('/').trim_end_matches('/');
        let (mount, tune) = requested
            .strip_suffix("/tune")
            .map_or((requested, false), |mount| (mount, true));
        if mount.is_empty() || mount.len() > 256 || !mount.split('/').all(valid_name) {
            return Err(bad("auth mount path must contain canonical segments"));
        }
        let route = if tune {
            format!("sys/auth/{mount}/tune")
        } else {
            format!("sys/auth/{mount}")
        };
        if tune {
            return match method {
                "GET" => {
                    let actor = self.permission(principal, namespace, &route, "read", now)?;
                    self.authorize_request(actor, namespace, &route, "sudo", now)?;
                    reject_unknown(body, &[])?;
                    let entry = self
                        .effective_auth_mounts(namespace)
                        .get(mount)
                        .cloned()
                        .ok_or_else(|| err(404, "auth mount not found"))?;
                    Ok(response(
                        json!({
                            "default_lease_ttl":entry.default_lease_ttl,
                            "description":entry.description,
                            "force_no_cache":false,
                            "max_lease_ttl":entry.max_lease_ttl,
                            "token_type":"default-service",
                            "revision":entry.revision,
                            "accessor":entry.accessor.as_deref().unwrap_or("")
                        }),
                        false,
                    ))
                }
                "POST" | "PUT" => {
                    let actor = self.permission(principal, namespace, &route, "update", now)?;
                    self.authorize_request(actor, namespace, &route, "sudo", now)?;
                    reject_unknown(
                        body,
                        &[
                            "description",
                            "default_lease_ttl",
                            "max_lease_ttl",
                            "cas_revision",
                        ],
                    )?;
                    let mut entries = self.effective_auth_mounts(namespace);
                    let mut entry = entries
                        .get(mount)
                        .cloned()
                        .ok_or_else(|| err(404, "auth mount not found"))?;
                    require_auth_revision(optional_auth_revision(body)?, entry.revision)?;
                    let mut changed = false;
                    if let Some(description) = body.get("description") {
                        let description = description
                            .as_str()
                            .ok_or_else(|| bad("description must be a string"))?;
                        if description.len() > 512 || description.chars().any(char::is_control) {
                            return Err(bad("invalid auth mount description"));
                        }
                        if entry.description != description {
                            entry.description = description.into();
                            changed = true;
                        }
                    }
                    let default_lease_ttl =
                        duration(body, "default_lease_ttl", entry.default_lease_ttl)?;
                    let max_lease_ttl = duration(body, "max_lease_ttl", entry.max_lease_ttl)?;
                    if default_lease_ttl > MAX_TTL
                        || max_lease_ttl > MAX_TTL
                        || default_lease_ttl > 0
                            && max_lease_ttl > 0
                            && default_lease_ttl > max_lease_ttl
                    {
                        return Err(bad("invalid auth mount TTL limits"));
                    }
                    if entry.default_lease_ttl != default_lease_ttl {
                        entry.default_lease_ttl = default_lease_ttl;
                        changed = true;
                    }
                    if entry.max_lease_ttl != max_lease_ttl {
                        entry.max_lease_ttl = max_lease_ttl;
                        changed = true;
                    }
                    if changed {
                        entry.revision = next_auth_revision(entry.revision)?;
                        entries.insert(mount.into(), entry);
                        self.auth_mounts.insert(namespace.into(), entries);
                    }
                    Ok(empty(changed))
                }
                _ => Err(err(405, "method not allowed")),
            };
        }
        match method {
            "GET" => {
                self.permission(principal, namespace, &route, "read", now)?;
                reject_unknown(body, &[])?;
                let entry = self
                    .effective_auth_mounts(namespace)
                    .get(mount)
                    .cloned()
                    .ok_or_else(|| err(404, "auth mount not found"))?;
                Ok(response(entry.descriptor(), false))
            }
            "POST" | "PUT" => {
                let actor = self.permission(principal, namespace, &route, "update", now)?;
                self.authorize_request(actor, namespace, &route, "sudo", now)?;
                reject_unknown(body, &["type", "description", "cas_revision"])?;
                let kind = body
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("auth mount type is required"))?;
                if !matches!(
                    kind,
                    "userpass"
                        | "approle"
                        | "jwt"
                        | "kubernetes"
                        | "oidc"
                        | "ldap"
                        | "plugin"
                        | "cert"
                ) {
                    return Err(err(501, "auth method type is not implemented"));
                }
                let description = body
                    .get("description")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| bad("description must be a string"))
                    })
                    .transpose()?
                    .unwrap_or("");
                if description.len() > 512 || description.chars().any(char::is_control) {
                    return Err(bad("invalid auth mount description"));
                }
                let mut entries = self.effective_auth_mounts(namespace);
                let existing = entries.get(mount).cloned();
                if mount == "token" || existing.as_ref().is_some_and(|old| old.kind != kind) {
                    return Err(bad("auth mount is already in use by another method"));
                }
                if entries.keys().any(|name| {
                    name != mount
                        && (name.starts_with(&format!("{mount}/"))
                            || mount.starts_with(&format!("{name}/")))
                }) {
                    return Err(bad("auth mount paths cannot overlap"));
                }
                match existing.as_ref() {
                    Some(old) => {
                        require_auth_revision(optional_auth_revision(body)?, old.revision)?
                    }
                    None => require_absent_auth_revision(optional_auth_revision(body)?)?,
                }
                let mut next = AuthMount::new(kind, description);
                if let Some(old) = existing.as_ref() {
                    next.accessor = old.accessor.clone();
                    next.revision = old.revision;
                    if old.description != description {
                        next.revision = next_auth_revision(old.revision)?;
                    }
                } else {
                    next.accessor = Some(random_id("auth_")?);
                }
                let mutated = existing.as_ref() != Some(&next);
                entries.insert(mount.into(), next);
                self.auth_mounts.insert(namespace.into(), entries);
                Ok(empty(mutated))
            }
            "DELETE" => {
                let actor = self.permission(principal, namespace, &route, "update", now)?;
                self.authorize_request(actor, namespace, &route, "sudo", now)?;
                reject_unknown(body, &["cas_revision"])?;
                if mount == "token" {
                    return Err(bad("the built-in token auth method cannot be disabled"));
                }
                let mut entries = self.effective_auth_mounts(namespace);
                let current = entries
                    .get(mount)
                    .cloned()
                    .ok_or_else(|| err(404, "auth mount not found"))?;
                require_auth_revision(optional_auth_revision(body)?, current.revision)?;
                entries.remove(mount);
                self.auth_mounts.insert(namespace.into(), entries);
                self.disable_auth_mount(AuthScope { namespace, mount });
                Ok(empty(true))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    /// Login credentials, not an unrelated bearer header, authenticate these
    /// exact mounted endpoints. Never classify a route by an arbitrary `/login`
    /// suffix: mount kind, namespace, operation and suffix all bind this decision.
    pub(super) fn is_public_login(&self, namespace: &str, method: &str, path: &str) -> bool {
        if !matches!(method, "POST" | "PUT") {
            return false;
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return false;
        };
        self.effective_auth_mounts(namespace)
            .iter()
            .any(|(mount, entry)| {
                let Some(suffix) = auth_path.strip_prefix(&format!("{mount}/")) else {
                    return false;
                };
                match entry.kind.as_str() {
                    "userpass" | "ldap" => suffix.strip_prefix("login/").is_some_and(valid_name),
                    "approle" | "jwt" | "kubernetes" => suffix == "login",
                    "oidc" => matches!(suffix, "oidc/auth_url" | "oidc/callback"),
                    "cert" => suffix == "login",
                    "plugin" => suffix == "login",
                    _ => false,
                }
            })
    }

    /// Returns None only for routes owned by another service subsystem.
    pub(super) fn handle(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<AuthResponse>, AuthError> {
        self.handle_with_client_certificates(principal, namespace, method, path, body, now, None)
    }

    // The request fields stay separate here to keep the anonymous-login and
    // TLS peer boundary explicit; each is independently validated below.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_with_client_certificates(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
        peer_certificates: Option<&[Vec<u8>]>,
    ) -> Result<Option<AuthResponse>, AuthError> {
        validate_namespace(namespace)?;
        validate_path(path, false)?;
        if path.starts_with("sys/wrapping/") {
            return self
                .wrapping_route(principal, namespace, method, path, body, now)
                .map(Some);
        }
        if path == "cubbyhole" || path.starts_with("cubbyhole/") {
            return self
                .cubbyhole_route(principal, namespace, method, path, body, now)
                .map(Some);
        }
        if path == "sys/auth" || path.starts_with("sys/auth/") {
            return self
                .auth_mount_route(principal, namespace, method, path, body, now)
                .map(Some);
        }
        if let Some(auth_path) = path.strip_prefix("auth/") {
            let mounts = self.effective_auth_mounts(namespace);
            let (mount, entry, suffix) = mounts
                .iter()
                .find_map(|(mount, entry)| {
                    auth_path
                        .strip_prefix(&format!("{mount}/"))
                        .map(|suffix| (mount, entry, suffix))
                })
                .ok_or_else(|| err(404, "auth mount not found"))?;
            let scope = AuthScope { namespace, mount };
            let result = match entry.kind.as_str() {
                "token" if mount == "token" => {
                    self.token_route(principal, namespace, method, path, body, now)
                }
                "userpass" if suffix.starts_with("login/") => {
                    self.login_userpass(scope, method, &suffix[6..], body, now)
                }
                "ldap" if suffix.starts_with("login/") => {
                    self.login_ldap(scope, method, &suffix[6..], body, now)
                }
                "userpass" | "ldap" if suffix == "users" || suffix.starts_with("users/") => {
                    self.user_route(principal, scope, method, path, body, now)
                }
                "ldap" if suffix == "groups" || suffix.starts_with("groups/") => {
                    self.ldap_group_route(principal, scope, method, path, body, now)
                }
                "approle" if suffix == "login" => self.login_approle(scope, method, body, now),
                "approle" if suffix == "tidy/secret-id" => {
                    self.tidy_secret_ids(principal, scope, method, path, body, now)
                }
                "approle" if suffix == "role" || suffix.starts_with("role/") => {
                    self.role_route(principal, scope, method, path, body, now)
                }
                "jwt" => self.jwt_route(principal, scope, method, path, body, now),
                "cert" => self.cert_route(
                    principal,
                    scope,
                    method,
                    suffix,
                    body,
                    now,
                    peer_certificates,
                ),
                "oidc" => self.oidc_route(principal, scope, method, suffix, body, now),
                "kubernetes" => self.kubernetes_route(principal, scope, method, suffix, body, now),
                "ldap" => self.ldap_route(principal, scope, method, suffix, body, now),
                "plugin" if suffix == "config" => {
                    self.plugin_auth_route(principal, scope, method, body, now)
                }
                "plugin" if suffix == "login" => Err(err(
                    503,
                    "plugin login requires the Service external-effect dispatcher",
                )),
                _ => Err(err(404, "unsupported auth route")),
            };
            return result.map(Some);
        }
        if path == "sys/policies/acl"
            || path.starts_with("sys/policies/acl/")
            || path == "sys/policy"
            || path.starts_with("sys/policy/")
        {
            return self
                .policy_route(principal, namespace, method, path, body, now)
                .map(Some);
        }
        Ok(None)
    }

    pub(crate) fn has_plugin_auth_state(&self) -> bool {
        self.plugin_auth_mounts
            .values()
            .any(|mounts| !mounts.is_empty())
    }

    pub(crate) fn validate_plugin_auth_state(&self) -> Result<(), AuthError> {
        for (namespace, mounts) in &self.plugin_auth_mounts {
            validate_namespace(namespace)?;
            let effective = self.effective_auth_mounts(namespace);
            for (mount, config) in mounts {
                if mount.is_empty()
                    || mount.len() > 256
                    || !mount.split('/').all(valid_name)
                    || !effective
                        .get(mount)
                        .is_some_and(|entry| entry.kind == "plugin")
                    || !valid_name(&config.plugin_id)
                    || config.policies.contains("root")
                    || config.policies.iter().any(|policy| !valid_name(policy))
                    || config.token_ttl > MAX_TTL
                    || config.token_max_ttl > MAX_TTL
                    || config.token_ttl > 0
                        && config.token_max_ttl > 0
                        && config.token_ttl > config.token_max_ttl
                {
                    return Err(err(503, "invalid persisted authentication plugin state"));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_plugin_auth_login(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<PluginAuthLoginPlan>, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(None);
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return Ok(None);
        };
        let mounts = self.effective_auth_mounts(namespace);
        let Some((mount, entry, suffix)) = mounts.iter().find_map(|(mount, entry)| {
            auth_path
                .strip_prefix(&format!("{mount}/"))
                .map(|suffix| (mount, entry, suffix))
        }) else {
            return Ok(None);
        };
        if entry.kind != "plugin" || suffix != "login" {
            return Ok(None);
        }
        if body.as_object().is_none() {
            return Err(bad("plugin login requires a JSON object"));
        }
        let encoded =
            serde_json::to_vec(body).map_err(|_| bad("plugin login request encoding failed"))?;
        if encoded.len() > 256 * 1024 {
            return Err(err(413, "plugin login request exceeds bound"));
        }
        let config = self
            .plugin_auth_mounts
            .get(namespace)
            .and_then(|entries| entries.get(mount))
            .cloned()
            .ok_or_else(|| err(503, "plugin authentication is not configured"))?;
        Ok(Some(PluginAuthLoginPlan {
            namespace: namespace.into(),
            mount: mount.clone(),
            config,
            now,
        }))
    }

    pub(crate) fn finish_plugin_auth_login(
        &mut self,
        plan: PluginAuthLoginPlan,
        alias: &str,
    ) -> Result<AuthResponse, AuthError> {
        if alias.is_empty() || alias.len() > 1024 || alias.chars().any(char::is_control) {
            return Err(denied());
        }
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        let current = self
            .plugin_auth_mounts
            .get(&plan.namespace)
            .and_then(|entries| entries.get(&plan.mount))
            .ok_or_else(|| err(409, "plugin authentication configuration changed"))?;
        if current != &plan.config
            || !self
                .effective_auth_mounts(&plan.namespace)
                .get(&plan.mount)
                .is_some_and(|entry| entry.kind == "plugin")
        {
            return Err(err(409, "plugin authentication binding changed"));
        }
        if plan.config.policies.contains("root") {
            return Err(denied());
        }
        let (token_ttl, token_max_ttl) =
            self.auth_mount_token_limits(scope, plan.config.token_ttl, plan.config.token_max_ttl)?;
        let alias_hash = hash(alias);
        let suffix = alias_hash.get(..16).unwrap_or(alias_hash.as_str());
        let mut token = login_token(
            &plan.namespace,
            plan.config.policies.clone(),
            token_ttl,
            token_max_ttl,
            plan.config.token_num_uses,
            format!("plugin-{suffix}"),
            plan.now,
        )?;
        token.auth_mount = Some(plan.mount.clone());
        let (token_id, token, mut response) = Self::prepare_issue(token, plan.now)?;
        response.login_identity = Some(LoginIdentity {
            mount: plan.mount,
            alias: alias.into(),
        });
        self.tokens.insert(token_id, token);
        Ok(response)
    }

    fn plugin_auth_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let path = format!("auth/{}/config", scope.mount);
        let capability = route_capability(method, false)?;
        let actor = self.permission(principal, scope.namespace, &path, capability, now)?;
        match method {
            "GET" => {
                reject_unknown(body, &[])?;
                let config = self
                    .plugin_auth_mounts
                    .get(scope.namespace)
                    .and_then(|entries| entries.get(scope.mount))
                    .ok_or_else(|| err(404, "plugin authentication is not configured"))?;
                Ok(response(
                    json!({
                        "plugin_id": config.plugin_id,
                        "policies": config.policies,
                        "token_policies": config.policies,
                        "token_ttl": config.token_ttl,
                        "token_max_ttl": config.token_max_ttl,
                        "token_num_uses": config.token_num_uses
                    }),
                    false,
                ))
            }
            "POST" | "PUT" => {
                self.authorize_request(actor, scope.namespace, &path, "sudo", now)?;
                reject_unknown(
                    body,
                    &[
                        "plugin_id",
                        "policies",
                        "token_policies",
                        "token_ttl",
                        "token_max_ttl",
                        "token_num_uses",
                    ],
                )?;
                reject_alias_pair(body, "policies", "token_policies")?;
                let plugin_id = string_field(body, "plugin_id")?;
                if !valid_name(plugin_id) {
                    return Err(bad("invalid plugin identifier"));
                }
                let policy_field = if body.get("token_policies").is_some() {
                    "token_policies"
                } else {
                    "policies"
                };
                let configured_policies = policies(body, policy_field, &BTreeSet::new(), true)?;
                if configured_policies.contains("root") {
                    return Err(bad("plugin authentication cannot grant root policy"));
                }
                let token_ttl = duration(body, "token_ttl", 0)?;
                let token_max_ttl = duration(body, "token_max_ttl", 0)?;
                let token_num_uses = number(body, "token_num_uses", 0)?;
                if token_ttl > MAX_TTL
                    || token_max_ttl > MAX_TTL
                    || token_ttl > 0 && token_max_ttl > 0 && token_ttl > token_max_ttl
                {
                    return Err(bad("invalid plugin authentication token TTL limits"));
                }
                let next = PluginAuthMount {
                    plugin_id: plugin_id.into(),
                    policies: configured_policies,
                    token_ttl,
                    token_max_ttl,
                    token_num_uses,
                };
                let changed = self
                    .plugin_auth_mounts
                    .entry(scope.namespace.into())
                    .or_default()
                    .insert(scope.mount.into(), next.clone())
                    .as_ref()
                    != Some(&next);
                Ok(empty(changed))
            }
            "DELETE" => {
                self.authorize_request(actor, scope.namespace, &path, "sudo", now)?;
                reject_unknown(body, &[])?;
                let removed = self
                    .plugin_auth_mounts
                    .entry(scope.namespace.into())
                    .or_default()
                    .remove(scope.mount);
                if removed.is_some() {
                    Ok(empty(true))
                } else {
                    Err(err(404, "plugin authentication is not configured"))
                }
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    fn ldap_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        suffix: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let path = format!("auth/{}/{}", scope.mount, suffix);
        if suffix != "config" {
            return Err(err(404, "unsupported LDAP route"));
        }
        let actor = self.permission(
            principal,
            scope.namespace,
            &path,
            route_capability(method, false)?,
            now,
        )?;
        match method {
            "GET" => {
                reject_unknown(body, &[])?;
                let config = self
                    .ldap_mounts
                    .get(scope.namespace)
                    .and_then(|m| m.get(scope.mount))
                    .ok_or_else(|| err(404, "LDAP auth is not configured"))?;
                Ok(response(
                    json!({"url": config.url, "bind_dn": config.bind_dn,
                        "user_dn_template": config.user_dn_template, "starttls": config.starttls,
                        "group_dn": config.group_dn, "group_attr": config.group_attr(),
                        "group_name_attr": config.group_name_attr()}),
                    false,
                ))
            }
            "POST" | "PUT" => {
                self.authorize_request(actor, scope.namespace, &path, "sudo", now)?;
                reject_unknown(
                    body,
                    &[
                        "url",
                        "bind_dn",
                        "user_dn_template",
                        "starttls",
                        "group_dn",
                        "group_attr",
                        "group_name_attr",
                    ],
                )?;
                let url = string_field(body, "url")?;
                let authority = url
                    .strip_prefix("ldaps://")
                    .or_else(|| url.strip_prefix("ldap://"));
                if authority.is_none_or(|host| {
                    host.is_empty()
                        || host.starts_with('/')
                        || host
                            .chars()
                            .any(|c| matches!(c, '?' | '(' | ')' | '*' | '|'))
                }) || url.len() > 2048
                    || url.chars().any(char::is_control)
                {
                    return Err(bad("LDAP url must be ldap:// or ldaps:// with a host"));
                }
                let bind_dn = string_field(body, "bind_dn")?;
                let user_dn_template = string_field(body, "user_dn_template")?;
                if bind_dn.is_empty()
                    || bind_dn.len() > 1024
                    || bind_dn.chars().any(char::is_control)
                {
                    return Err(bad("invalid LDAP bind_dn"));
                }
                if user_dn_template.len() > 1024
                    || !user_dn_template.contains("{{username}}")
                    || user_dn_template.chars().any(char::is_control)
                {
                    return Err(bad(
                        "user_dn_template must contain {{username}} and no control characters",
                    ));
                }
                let starttls = boolean(body, "starttls", false)?;
                let group_dn = body
                    .get("group_dn")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| bad("group_dn must be a string"))
                    })
                    .transpose()?
                    .unwrap_or("");
                if group_dn.len() > 1024 || group_dn.chars().any(char::is_control) {
                    return Err(bad("invalid LDAP group_dn"));
                }
                let group_attr = body
                    .get("group_attr")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| bad("group_attr must be a string"))
                    })
                    .transpose()?
                    .unwrap_or("member");
                let group_name_attr = body
                    .get("group_name_attr")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| bad("group_name_attr must be a string"))
                    })
                    .transpose()?
                    .unwrap_or("cn");
                if !valid_ldap_attribute_name(group_attr)
                    || !valid_ldap_attribute_name(group_name_attr)
                {
                    return Err(bad("invalid LDAP group attribute name"));
                }
                let next = LdapMount {
                    url: url.into(),
                    bind_dn: bind_dn.into(),
                    user_dn_template: user_dn_template.into(),
                    starttls,
                    group_dn: group_dn.into(),
                    group_attr: if group_attr == "member" {
                        String::new()
                    } else {
                        group_attr.into()
                    },
                    group_name_attr: if group_name_attr == "cn" {
                        String::new()
                    } else {
                        group_name_attr.into()
                    },
                };
                let changed = self
                    .ldap_mounts
                    .entry(scope.namespace.into())
                    .or_default()
                    .insert(scope.mount.into(), next.clone())
                    .as_ref()
                    != Some(&next);
                Ok(empty(changed))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    fn ldap_group_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let prefix = format!("auth/{}/groups", scope.mount);
        let name = path
            .strip_prefix(&prefix)
            .ok_or_else(|| bad("invalid LDAP group route"))?
            .trim_start_matches('/');
        let capability = route_capability(method, name.is_empty())?;
        let actor = self.permission(principal, scope.namespace, path, capability, now)?;
        if name.is_empty() {
            if capability != "list" {
                return Err(err(405, "method not allowed"));
            }
            reject_unknown(body, &[])?;
            let keys = self
                .ldap_groups_at(scope)
                .map(|groups| groups.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            return Ok(response(json!({"keys": keys}), false));
        }
        if !valid_name(name) {
            return Err(bad("invalid LDAP group name"));
        }
        match capability {
            "read" => {
                reject_unknown(body, &[])?;
                let mapped = self
                    .ldap_groups_at(scope)
                    .and_then(|groups| groups.get(name))
                    .cloned()
                    .ok_or_else(|| err(404, "LDAP group not found"))?;
                Ok(response(
                    json!({"policies": mapped, "token_policies": mapped}),
                    false,
                ))
            }
            "delete" => {
                reject_unknown(body, &[])?;
                self.authorize_request(actor, scope.namespace, path, "sudo", now)?;
                let removed = self.ldap_groups_at_mut(scope).remove(name);
                if removed.is_some() {
                    Ok(empty(true))
                } else {
                    Err(err(404, "LDAP group not found"))
                }
            }
            "update" => {
                self.authorize_request(actor, scope.namespace, path, "sudo", now)?;
                reject_unknown(body, &["policies", "token_policies"])?;
                reject_alias_pair(body, "policies", "token_policies")?;
                let current = self
                    .ldap_groups_at(scope)
                    .and_then(|groups| groups.get(name))
                    .cloned()
                    .unwrap_or_default();
                let field = if body.get("token_policies").is_some() {
                    "token_policies"
                } else {
                    "policies"
                };
                let mapped = policies(body, field, &current, false)?;
                self.validate_assignment(actor, &mapped)?;
                let changed = self
                    .ldap_groups_at_mut(scope)
                    .insert(name.into(), mapped.clone())
                    .as_ref()
                    != Some(&mapped);
                Ok(empty(changed))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    pub(crate) fn prepare_ldap_login(
        &self,
        namespace: &str,
        mount: &str,
        name: &str,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<LdapLoginPlan, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        validate_namespace(namespace)?;
        if !valid_name(name)
            || !self
                .effective_auth_mounts(namespace)
                .get(mount)
                .is_some_and(|entry| entry.kind == "ldap")
        {
            return Err(denied());
        }
        reject_unknown(body, &["password", "totp_code"])?;
        let password = string_field(body, "password")?;
        if password.is_empty() || password.len() > 1024 || password.contains('\0') {
            return Err(denied());
        }
        let scope = AuthScope { namespace, mount };
        let config = self
            .ldap_mounts
            .get(namespace)
            .and_then(|mounts| mounts.get(mount))
            .cloned()
            .ok_or_else(|| err(503, "LDAP auth is not configured"))?;
        if !config.url.starts_with("ldaps://") || config.starttls {
            return Err(err(
                503,
                "external LDAP login requires a host-enrolled LDAPS endpoint",
            ));
        }
        let dn = config.user_dn_template.replace("{{username}}", name);
        if dn.is_empty() || dn.len() > 1024 || dn.bytes().any(|byte| byte == 0 || byte < 0x20) {
            return Err(bad("LDAP user DN is outside bounds"));
        }
        let totp_code = body
            .get("totp_code")
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| value.len() <= 64 && !value.contains('\0'))
                    .map(|value| Zeroizing::new(value.to_owned()))
                    .ok_or_else(denied)
            })
            .transpose()?;
        // Policy/token mapping remains a local administrative object, but the
        // password verifier is deliberately not consulted for LDAP login.
        let _ = self.users_at(scope).and_then(|users| users.get(name));
        Ok(LdapLoginPlan {
            namespace: namespace.into(),
            mount: mount.into(),
            name: name.into(),
            dn,
            config,
            password: Zeroizing::new(password.to_owned()),
            totp_code,
            now,
            started: std::time::Instant::now(),
        })
    }

    pub(crate) fn finish_ldap_login(
        &mut self,
        plan: LdapLoginPlan,
        observation: LdapLoginObservation,
    ) -> Result<AuthResponse, AuthError> {
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        if !self
            .effective_auth_mounts(&plan.namespace)
            .get(&plan.mount)
            .is_some_and(|entry| entry.kind == "ldap")
            || self
                .ldap_mounts
                .get(&plan.namespace)
                .and_then(|mounts| mounts.get(&plan.mount))
                != Some(&plan.config)
        {
            return Err(err(409, "LDAP configuration changed during bind"));
        }
        let mut user = self
            .users_at(scope)
            .and_then(|users| users.get(&plan.name))
            .cloned()
            .ok_or_else(denied)?;
        let elapsed = plan.started.elapsed();
        let now = plan.now.saturating_add(
            elapsed
                .as_secs()
                .saturating_add(u64::from(elapsed.subsec_nanos() > 0)),
        );
        let accepted_counter = match user.mfa.as_ref() {
            Some(enrollment) => Some(verify_totp(
                enrollment,
                plan.totp_code
                    .as_ref()
                    .map(|value| value.as_str())
                    .ok_or_else(denied)?,
                now,
            )?),
            None => {
                if plan.totp_code.is_some() {
                    return Err(bad("MFA is not configured for this LDAP user"));
                }
                None
            }
        };
        let (token_ttl, token_max_ttl) =
            self.auth_mount_token_limits(scope, user.token_ttl, user.token_max_ttl)?;
        let mut effective_policies = user.policies.clone();
        if let Some(mappings) = self.ldap_groups_at(scope) {
            for group in &observation.groups {
                if let Some(mapped) = mappings.get(group) {
                    effective_policies.extend(mapped.iter().cloned());
                }
            }
        }
        let mut token = login_token(
            &plan.namespace,
            effective_policies,
            token_ttl,
            token_max_ttl,
            user.token_num_uses,
            format!("ldap-{}", plan.name),
            now,
        )?;
        token.auth_mount = Some(plan.mount.clone());
        let (token_id, token, mut response) = Self::prepare_issue(token, now)?;
        response.login_identity = Some(LoginIdentity {
            mount: plan.mount.clone(),
            alias: plan.name.clone(),
        });
        if let Some(counter) = accepted_counter {
            let enrollment = user
                .mfa
                .as_mut()
                .ok_or_else(|| err(500, "LDAP MFA enrollment disappeared during login"))?;
            enrollment.last_accepted_counter = Some(counter);
        }
        self.users_at_mut(scope).insert(plan.name, user);
        self.tokens.insert(token_id, token);
        Ok(response)
    }

    fn login_ldap(
        &mut self,
        _scope: AuthScope<'_>,
        _method: &str,
        _name: &str,
        _body: &Value,
        _now: u64,
    ) -> Result<AuthResponse, AuthError> {
        Err(err(
            503,
            "LDAP login requires the Service online-auth dispatcher",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn cert_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        suffix: &str,
        body: &Value,
        now: u64,
        peer_certificates: Option<&[Vec<u8>]>,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        let route = format!("auth/{mount}/{suffix}");
        if suffix == "login" {
            if !matches!(method, "POST" | "PUT") {
                return Err(err(405, "method not allowed"));
            }
            let requested_role = match body.get("name") {
                None => None,
                Some(value) => Some(
                    value
                        .as_str()
                        .filter(|name| valid_name(name))
                        .ok_or_else(|| bad("certificate role name must be a valid string"))?,
                ),
            };
            reject_unknown(body, &["name"])?;
            let presented = parse_presented_certificate(peer_certificates.ok_or_else(denied)?)?;
            let roles = self
                .cert_roles
                .get(namespace)
                .and_then(|mounts| mounts.get(mount))
                .ok_or_else(denied)?;
            // Parse the leaf whenever it is a valid X.509 certificate so the
            // login response can expose OpenBao-compatible certificate
            // metadata. A malformed synthetic/legacy leaf remains usable for
            // an unconstrained exact-digest role; constrained roles still
            // fail closed through `matches_cert_role`.
            let attributes = peer_certificates
                .and_then(|chain| chain.first())
                .and_then(|leaf| parse_certificate_attributes(leaf));
            let (role_name, role) = match requested_role {
                Some(name) => roles
                    .get(name)
                    .filter(|role| matches_cert_role(&presented, attributes.as_ref(), role))
                    .map(|role| (name, role))
                    .ok_or_else(denied)?,
                None => roles
                    .iter()
                    .find(|(_, role)| matches_cert_role(&presented, attributes.as_ref(), role))
                    .map(|(name, role)| (name.as_str(), role))
                    .ok_or_else(denied)?,
            };
            let (token_ttl, token_max_ttl) =
                self.auth_mount_token_limits(scope, role.token_ttl, role.token_max_ttl)?;
            let display_suffix = presented.sha256.get(..16).unwrap_or(&presented.sha256);
            let mut token = login_token(
                namespace,
                role.policies.clone(),
                token_ttl,
                token_max_ttl,
                role.token_num_uses,
                format!("cert-{display_suffix}"),
                now,
            )?;
            token.auth_mount = Some(mount.into());
            token.auth_cert_role = Some(role_name.to_owned());
            token.auth_cert_sha256 = Some(presented.sha256.clone());
            let (token_id, token, mut response) = Self::prepare_issue(token, now)?;
            response.login_identity = Some(LoginIdentity {
                mount: mount.into(),
                alias: role_name.to_owned(),
            });
            let metadata = certificate_metadata(attributes.as_ref(), role_name, role);
            if !metadata.is_empty() {
                response.body["auth"]["metadata"] = json!(metadata);
            }
            self.tokens.insert(token_id, token);
            return Ok(response);
        }
        let Some(name) = suffix.strip_prefix("certs/") else {
            if suffix == "certs" && matches!(method, "GET" | "LIST") {
                self.permission(principal, namespace, &route, "list", now)?;
                reject_unknown(body, &[])?;
                let keys = self
                    .cert_roles
                    .get(namespace)
                    .and_then(|mounts| mounts.get(mount))
                    .map(|roles| roles.keys().map(String::as_str).collect::<Vec<_>>())
                    .unwrap_or_default();
                return Ok(response(json!({"keys":keys}), false));
            }
            return Err(err(404, "unsupported certificate auth route"));
        };
        if !valid_name(name) {
            return Err(bad("invalid certificate role name"));
        }
        let role_path = format!("auth/{mount}/certs/{name}");
        match method {
            "GET" => {
                self.permission(principal, namespace, &role_path, "read", now)?;
                reject_unknown(body, &[])?;
                let role = self
                    .cert_roles
                    .get(namespace)
                    .and_then(|mounts| mounts.get(mount))
                    .and_then(|roles| roles.get(name))
                    .ok_or_else(|| err(404, "certificate role not found"))?;
                Ok(response(
                    json!({
                        "certificate_sha256": role.certificate_sha256,
                        "token_policies": role.policies,
                        "token_ttl": role.token_ttl,
                        "token_max_ttl": role.token_max_ttl,
                        "token_num_uses": role.token_num_uses,
                        "allowed_names": role.allowed_names,
                        "allowed_common_names": role.allowed_common_names,
                        "allowed_dns_sans": role.allowed_dns_sans,
                        "allowed_email_sans": role.allowed_email_sans,
                        "allowed_uri_sans": role.allowed_uri_sans,
                        "allowed_organizational_units": role.allowed_organizational_units,
                        "required_extensions": role.required_extensions,
                        "allowed_metadata_extensions": role.allowed_metadata_extensions,
                    }),
                    false,
                ))
            }
            "POST" | "PUT" => {
                let actor = self.permission(principal, namespace, &role_path, "update", now)?;
                self.authorize_request(actor, namespace, &role_path, "sudo", now)?;
                reject_unknown(
                    body,
                    &[
                        "certificate",
                        "certificate_sha256",
                        "token_policies",
                        "policies",
                        "token_ttl",
                        "token_max_ttl",
                        "token_num_uses",
                        "allowed_names",
                        "allowed_common_names",
                        "allowed_dns_sans",
                        "allowed_email_sans",
                        "allowed_uri_sans",
                        "allowed_organizational_units",
                        "required_extensions",
                        "allowed_metadata_extensions",
                    ],
                )?;
                let certificate_sha256 =
                    match (body.get("certificate"), body.get("certificate_sha256")) {
                        (Some(_), Some(_)) => {
                            return Err(bad(
                                "certificate and certificate_sha256 are mutually exclusive",
                            ));
                        }
                        (Some(value), None) => {
                            let pem = value
                                .as_str()
                                .ok_or_else(|| bad("certificate must be PEM text"))?;
                            let certificates =
                                rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
                                    .collect::<Result<Vec<_>, _>>()
                                    .map_err(|_| bad("invalid certificate PEM"))?;
                            let der = certificates
                                .first()
                                .ok_or_else(|| bad("certificate is required"))?;
                            if certificates.len() != 1 {
                                return Err(bad(
                                    "certificate role accepts exactly one leaf certificate",
                                ));
                            }
                            certificate_sha256(der.as_ref())
                        }
                        (None, Some(value)) => normalized_certificate_sha256(
                            value
                                .as_str()
                                .ok_or_else(|| bad("certificate_sha256 must be a hex string"))?,
                        )
                        .ok_or_else(|| bad("certificate_sha256 must be 64 hex characters"))?,
                        (None, None) => {
                            return Err(bad("certificate or certificate_sha256 is required"));
                        }
                    };
                let mut policies = policies(
                    body,
                    if body.get("token_policies").is_some() {
                        "token_policies"
                    } else {
                        "policies"
                    },
                    &BTreeSet::from(["default".into()]),
                    true,
                )?;
                self.validate_assignment(actor, &policies)?;
                policies.remove("root");
                let (mount_default_ttl, mount_max_ttl) =
                    self.auth_mount_token_limits(scope, 0, 0)?;
                let token_ttl = duration(body, "token_ttl", mount_default_ttl)?;
                let token_max_ttl = duration(body, "token_max_ttl", mount_max_ttl)?;
                let allowed_names = bounded_string_list(
                    body,
                    "allowed_names",
                    MAX_CERT_ROLE_MATCH_VALUES,
                    MAX_CERT_ROLE_MATCH_VALUE_BYTES,
                )?;
                let allowed_common_names = bounded_string_list(
                    body,
                    "allowed_common_names",
                    MAX_CERT_ROLE_MATCH_VALUES,
                    MAX_CERT_ROLE_MATCH_VALUE_BYTES,
                )?;
                let allowed_dns_sans = bounded_string_list(
                    body,
                    "allowed_dns_sans",
                    MAX_CERT_ROLE_MATCH_VALUES,
                    MAX_CERT_ROLE_MATCH_VALUE_BYTES,
                )?;
                let allowed_email_sans = bounded_string_list(
                    body,
                    "allowed_email_sans",
                    MAX_CERT_ROLE_MATCH_VALUES,
                    MAX_CERT_ROLE_MATCH_VALUE_BYTES,
                )?;
                let allowed_uri_sans = bounded_string_list(
                    body,
                    "allowed_uri_sans",
                    MAX_CERT_ROLE_MATCH_VALUES,
                    MAX_CERT_ROLE_MATCH_VALUE_BYTES,
                )?;
                let allowed_organizational_units = bounded_string_list(
                    body,
                    "allowed_organizational_units",
                    MAX_CERT_ROLE_MATCH_VALUES,
                    MAX_CERT_ROLE_MATCH_VALUE_BYTES,
                )?;
                let required_extensions =
                    certificate_extension_requirements(body, "required_extensions")?;
                let allowed_metadata_extensions =
                    certificate_metadata_extensions(body, "allowed_metadata_extensions")?;
                let mut role = CertRole {
                    certificate_sha256,
                    allowed_names,
                    allowed_common_names,
                    allowed_dns_sans,
                    allowed_email_sans,
                    allowed_uri_sans,
                    allowed_organizational_units,
                    required_extensions,
                    allowed_metadata_extensions,
                    policies,
                    token_ttl,
                    token_max_ttl,
                    token_num_uses: number(body, "token_num_uses", 0)?,
                };
                normalize_ttl(&mut role.token_ttl, &mut role.token_max_ttl)?;
                self.cert_roles
                    .entry(namespace.into())
                    .or_default()
                    .entry(mount.into())
                    .or_default()
                    .insert(name.into(), role);
                Ok(empty(true))
            }
            "DELETE" => {
                let actor = self.permission(principal, namespace, &role_path, "delete", now)?;
                self.authorize_request(actor, namespace, &role_path, "sudo", now)?;
                reject_unknown(body, &[])?;
                let removed = self
                    .cert_roles
                    .get_mut(namespace)
                    .and_then(|mounts| mounts.get_mut(mount))
                    .and_then(|roles| roles.remove(name))
                    .is_some();
                if !removed {
                    return Err(err(404, "certificate role not found"));
                }
                Ok(empty(true))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    fn jwt_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        if path == format!("auth/{mount}/config") {
            return self.jwt_config_route(principal, scope, method, body, now);
        }
        if path == format!("auth/{mount}/login") {
            if !matches!(method, "POST" | "PUT") {
                return Err(err(405, "method not allowed"));
            }
            reject_unknown(body, &["role", "jwt"])?;
            let role_name = string_field(body, "role")?;
            if !valid_name(role_name) {
                return Err(bad("invalid JWT role name"));
            }
            let jwt = string_field(body, "jwt")?;
            let config = self
                .jwt_at(scope)
                .and_then(|state| state.config.as_ref())
                .cloned()
                .ok_or_else(|| err(503, "JWT auth is not configured"))?;
            let role = self
                .jwt_at(scope)
                .map(|state| &state.roles)
                .and_then(|roles| roles.get(role_name))
                .cloned()
                .ok_or_else(denied)?;
            let mut verification_config = config.clone();
            if verification_config.audiences.is_empty() {
                verification_config.audiences = role.bound_audiences.clone();
            }
            let verified = verification_config
                .verifier()?
                .verify(jwt, now)
                .map_err(|_| denied())?;
            let claimed_namespace = verified.namespace.as_deref().unwrap_or("");
            if claimed_namespace != namespace
                || !role.bound_groups.is_subset(&verified.groups)
                || role
                    .bound_subject
                    .as_ref()
                    .is_some_and(|subject| subject != &verified.subject)
                || !role.bound_audiences.is_empty()
                    && role.bound_audiences.is_disjoint(&verified.audiences)
                || role.policies.contains("root")
            {
                return Err(denied());
            }
            let remaining = verified.expires_at.saturating_sub(now);
            if remaining == 0 {
                return Err(denied());
            }
            let ttl = role.token_ttl.min(remaining).max(1);
            let max_ttl = role.token_max_ttl.min(remaining).max(ttl);
            let (ttl, max_ttl) = self.auth_mount_token_limits(scope, ttl, max_ttl)?;
            let fingerprint = verified.replay_fingerprint();
            let identity_key = hash(&format!("{}\0{}", verified.issuer, verified.subject));
            let identity = ExternalIdentity {
                issuer: verified.issuer.clone(),
                subject: verified.subject.clone(),
                namespace: namespace.into(),
                groups: verified.groups.clone(),
                last_seen: now,
            };
            let display_hash = hash(&verified.subject);
            let display_suffix = display_hash.get(..16).unwrap_or(display_hash.as_str());
            let token = Token {
                wrapping: None,
                entity_id: None,
                cubbyhole: cubbyhole::TokenCubbyhole::default(),
                accessor: random_id("a.")?,
                namespace: namespace.into(),
                policies: role.policies,
                root: false,
                parent: None,
                created_at: now,
                expires_at: Some(checked_expiry(now, ttl)?),
                max_expires_at: Some(checked_expiry(now, max_ttl)?),
                period: 0,
                renewable: true,
                uses_remaining: unlimited_zero(role.token_num_uses),
                display_name: format!("jwt-{display_suffix}"),
                auth_mount: Some(mount.into()),
                auth_origin_known: true,
                auth_cert_role: None,
                auth_cert_sha256: None,
            };
            let (token_id, token, mut response) = Self::prepare_issue(token, now)?;
            response.login_identity = Some(LoginIdentity {
                mount: mount.into(),
                alias: verified.subject.clone(),
            });
            if let Err(error) =
                self.admit_external_replay(scope, fingerprint, verified.expires_at, now)
            {
                crate::service::erase_json(&mut response.body);
                return Err(error);
            }
            self.jwt_at_mut(scope)
                .identities
                .insert(identity_key, identity);
            self.tokens.insert(token_id, token);
            return Ok(response);
        }
        if path == format!("auth/{mount}/role") {
            if !matches!(method, "GET" | "LIST") {
                return Err(err(405, "method not allowed"));
            }
            self.permission(principal, namespace, path, "list", now)?;
            reject_unknown(body, &[])?;
            let keys: Vec<&str> = self
                .jwt_at(scope)
                .map(|state| &state.roles)
                .map(|roles| roles.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys": keys}), false));
        }
        if let Some(name) = path.strip_prefix(&format!("auth/{mount}/role/")) {
            if !valid_name(name) {
                return Err(bad("invalid JWT role name"));
            }
            return self.jwt_role_route(principal, scope, method, name, body, now);
        }
        Err(err(404, "JWT auth path is not implemented"))
    }

    fn jwt_config_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        let path = format!("auth/{mount}/config");
        let path = path.as_str();
        match method {
            "GET" => {
                self.permission(principal, namespace, path, "read", now)?;
                reject_unknown(body, &[])?;
                let config = self
                    .jwt_at(scope)
                    .and_then(|state| state.config.as_ref())
                    .ok_or_else(|| err(404, "JWT auth is not configured"))?;
                let keys: Vec<Value> = config
                    .keys
                    .iter()
                    .map(|(kid, key)| json!({"kid": kid, "algorithm": key.algorithm}))
                    .collect();
                Ok(response(
                    json!({
                        "jwks_url": config.remote.as_ref().and_then(|s| s.jwks_url.as_deref()),
                        "oidc_discovery_url": config.remote.as_ref().and_then(|s| s.oidc_discovery_url.as_deref()),
                        "issuer": config.issuer,
                        "jwt_supported_algs": config.jwt_supported_algs,
                        "audiences": config.audiences,
                        "required_namespace": config.required_namespace,
                        "clock_skew_seconds": config.clock_skew_seconds,
                        "maximum_token_lifetime_seconds": config.maximum_token_lifetime_seconds,
                        "keys": keys
                    }),
                    false,
                ))
            }
            "POST" | "PUT" => {
                let actor = self.permission(principal, namespace, path, "update", now)?;
                self.authorize_request(actor, namespace, path, "sudo", now)?;
                reject_unknown(
                    body,
                    &[
                        "issuer",
                        "audiences",
                        "required_namespace",
                        "clock_skew_seconds",
                        "maximum_token_lifetime_seconds",
                        "keys",
                        "jwks",
                        "jwks_url",
                        "oidc_discovery_url",
                        "bound_issuer",
                        "jwt_supported_algs",
                    ],
                )?;
                reject_alias_pair(body, "issuer", "bound_issuer")?;
                let issuer = string_field(
                    body,
                    if body.get("issuer").is_some() {
                        "issuer"
                    } else {
                        "bound_issuer"
                    },
                )?
                .to_owned();
                let audiences = claim_values(body, "audiences")?;
                let required_namespace = body
                    .get("required_namespace")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| bad("required_namespace must be a string"))
                    })
                    .transpose()?
                    .map(str::to_owned);
                if required_namespace
                    .as_deref()
                    .is_some_and(|value| value != namespace)
                {
                    return Err(bad(
                        "required_namespace must equal the configured auth namespace",
                    ));
                }
                let clock_skew_seconds = number(body, "clock_skew_seconds", 30)?;
                let maximum_token_lifetime_seconds =
                    number(body, "maximum_token_lifetime_seconds", 3600)?;
                if body.get("keys").is_some() && body.get("jwks").is_some() {
                    return Err(bad("configure either JWT keys or jwks, not both"));
                }
                let jwt_supported_algs = if body.get("jwt_supported_algs").is_some() {
                    let values = claim_values(body, "jwt_supported_algs")?;
                    if values.is_empty()
                        || values
                            .iter()
                            .any(|v| !matches!(v.as_str(), "EdDSA" | "ES256" | "RS256"))
                    {
                        return Err(bad("unsupported JWT algorithm allowlist"));
                    }
                    Some(values)
                } else {
                    None
                };
                let remote = RemoteJwtSource::parse(body)?;
                let keys = if remote.is_some() {
                    BTreeMap::new()
                } else if let Some(jwks) = body.get("jwks") {
                    parse_jwks(jwks)?
                } else {
                    let key_values = body
                        .get("keys")
                        .and_then(Value::as_array)
                        .ok_or_else(|| bad("JWT keys or jwks are required"))?;
                    parse_legacy_jwt_keys(key_values)?
                };
                let config = JwtConfig {
                    remote,
                    jwt_supported_algs,
                    issuer,
                    audiences,
                    required_namespace,
                    clock_skew_seconds,
                    maximum_token_lifetime_seconds,
                    keys,
                };
                if config.remote.is_none() {
                    config.verifier()?;
                } else {
                    let mut audiences = config.audiences.clone();
                    if audiences.is_empty() {
                        audiences.insert("configuration-shape-only".into());
                    }
                    TrustPolicy::new(
                        config.issuer.clone(),
                        audiences,
                        config.required_namespace.clone().filter(|s| !s.is_empty()),
                        config.clock_skew_seconds,
                        config.maximum_token_lifetime_seconds,
                    )
                    .map_err(|_| bad("invalid remote JWT trust policy"))?;
                }
                let mutated =
                    self.jwt_at(scope).and_then(|state| state.config.as_ref()) != Some(&config);
                self.jwt_at_mut(scope).config = Some(config);
                Ok(empty(mutated))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    fn jwt_role_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        name: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        let path = format!("auth/{mount}/role/{name}");
        match method {
            "GET" => {
                self.permission(principal, namespace, &path, "read", now)?;
                reject_unknown(body, &[])?;
                let role = self
                    .jwt_at(scope)
                    .map(|state| &state.roles)
                    .and_then(|roles| roles.get(name))
                    .ok_or_else(|| err(404, "JWT role not found"))?;
                Ok(response(
                    json!({
                        "bound_groups": role.bound_groups,
                        "bound_subject": role.bound_subject,
                        "bound_audiences": role.bound_audiences,
                        "policies": role.policies,
                        "token_ttl": role.token_ttl,
                        "token_max_ttl": role.token_max_ttl,
                        "token_num_uses": role.token_num_uses
                    }),
                    false,
                ))
            }
            "POST" | "PUT" => {
                let actor = self.permission(principal, namespace, &path, "update", now)?;
                self.authorize_request(actor, namespace, &path, "sudo", now)?;
                reject_unknown(
                    body,
                    &[
                        "role_type",
                        "user_claim",
                        "bound_groups",
                        "bound_subject",
                        "bound_audiences",
                        "policies",
                        "token_policies",
                        "token_ttl",
                        "token_max_ttl",
                        "token_num_uses",
                    ],
                )?;
                if body
                    .get("role_type")
                    .is_some_and(|v| v.as_str() != Some("jwt"))
                    || body
                        .get("user_claim")
                        .is_some_and(|v| v.as_str() != Some("sub"))
                {
                    return Err(err(
                        501,
                        "only role_type jwt with sub identity is implemented",
                    ));
                }
                let bound_groups = claim_values(body, "bound_groups")?;
                let bound_audiences = claim_values(body, "bound_audiences")?;
                let bound_subject = body
                    .get("bound_subject")
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|value| {
                                !value.is_empty()
                                    && value.len() <= 1024
                                    && !value.chars().any(char::is_control)
                            })
                            .map(str::to_owned)
                            .ok_or_else(|| bad("invalid bound subject"))
                    })
                    .transpose()?;
                reject_alias_pair(body, "policies", "token_policies")?;
                let role_policies = policies(
                    body,
                    if body.get("token_policies").is_some() {
                        "token_policies"
                    } else {
                        "policies"
                    },
                    &BTreeSet::new(),
                    true,
                )?;
                self.validate_assignment(actor, &role_policies)?;
                let token_ttl = duration(body, "token_ttl", DEFAULT_TTL)?;
                let token_max_ttl = duration(body, "token_max_ttl", token_ttl)?;
                let token_num_uses = number(body, "token_num_uses", 0)?;
                if token_ttl == 0
                    || token_ttl > MAX_TTL
                    || token_max_ttl < token_ttl
                    || token_max_ttl > MAX_TTL
                {
                    return Err(bad("JWT role token TTL is outside bounds"));
                }
                let role = JwtRole {
                    bound_groups,
                    bound_subject,
                    bound_audiences,
                    policies: role_policies,
                    token_ttl,
                    token_max_ttl,
                    token_num_uses,
                };
                let roles = &mut self.jwt_at_mut(scope).roles;
                let mutated = roles.get(name) != Some(&role);
                roles.insert(name.into(), role);
                Ok(empty(mutated))
            }
            "DELETE" => {
                let actor = self.permission(principal, namespace, &path, "update", now)?;
                self.authorize_request(actor, namespace, &path, "sudo", now)?;
                reject_unknown(body, &[])?;
                let removed = self.jwt_at_mut(scope).roles.remove(name);
                if removed.is_some() {
                    Ok(empty(true))
                } else {
                    Err(err(404, "JWT role not found"))
                }
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    fn tidy_secret_ids(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &[])?;
        let actor = self.permission(principal, scope.namespace, path, "update", now)?;
        self.authorize_request(actor, scope.namespace, path, "sudo", now)?;
        let mut removed = 0;
        for role in self.roles_at_mut(scope).values_mut() {
            let stale: Vec<String> = role
                .secret_ids
                .iter()
                .filter(|(_, secret)| {
                    secret.uses_remaining == Some(0)
                        || secret.expires_at.is_some_and(|expiry| expiry <= now)
                })
                .map(|(id, _)| id.clone())
                .collect();
            for mut id in stale {
                if let Some((mut stored_id, _)) = role.secret_ids.remove_entry(&id) {
                    stored_id.zeroize();
                    removed += 1;
                }
                id.zeroize();
            }
        }
        Ok(response(
            json!({"removed_secret_ids": removed}),
            removed > 0,
        ))
    }

    fn token_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let operation = path
            .strip_prefix("auth/token/")
            .ok_or_else(|| bad("invalid token path"))?;
        let allowed_method = match operation {
            "lookup-self" => matches!(method, "GET" | "POST"),
            "lookup" | "lookup-accessor" => matches!(method, "GET" | "POST"),
            "accessors" => matches!(method, "LIST" | "GET"),
            _ => matches!(method, "POST" | "PUT"),
        };
        if !allowed_method {
            return Err(err(405, "method not allowed"));
        }
        let capability = match operation {
            "lookup-self" | "lookup" | "lookup-accessor" => "read",
            "accessors" => "list",
            _ => "update",
        };
        let actor = self.permission(principal, namespace, path, capability, now)?;
        match operation {
            "create" | "create-orphan" => self.create_token(
                actor,
                namespace,
                path,
                body,
                now,
                operation == "create-orphan",
            ),
            "lookup-self" => {
                reject_unknown(body, &[])?;
                let token = self.tokens.get(&actor.digest).ok_or_else(denied)?;
                Ok(response(token_info(token, now), false))
            }
            "lookup" | "lookup-accessor" => {
                reject_unknown(
                    body,
                    if operation == "lookup" {
                        &["token"]
                    } else {
                        &["accessor"]
                    },
                )?;
                let id = self.target_token(namespace, body, operation.ends_with("accessor"))?;
                let token = self.active_token(&id, now, true)?;
                Ok(response(token_info(token, now), false))
            }
            "accessors" => {
                self.authorize_request(actor, namespace, path, "sudo", now)?;
                let keys: Vec<&str> = self
                    .tokens
                    .values()
                    .filter(|t| t.namespace == namespace && !t.expires_at.is_some_and(|e| e <= now))
                    .map(|t| t.accessor.as_str())
                    .collect();
                Ok(response(json!({"keys": keys}), false))
            }
            "tidy" => {
                reject_unknown(body, &[])?;
                self.authorize_request(actor, namespace, path, "sudo", now)?;
                let stale: Vec<String> = self
                    .tokens
                    .iter()
                    .filter(|(id, token)| {
                        token.namespace == namespace && self.active_token(id, now, true).is_err()
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                let removed = stale.len();
                for mut id in stale {
                    if let Some((mut stored_id, _)) = self.tokens.remove_entry(&id) {
                        stored_id.zeroize();
                    }
                    id.zeroize();
                }
                Ok(response(json!({"removed_tokens": removed}), removed > 0))
            }
            "revoke-self" => {
                reject_unknown(body, &[])?;
                self.revoke(&actor.digest);
                Ok(empty(true))
            }
            "revoke" | "revoke-accessor" => {
                reject_unknown(
                    body,
                    if operation == "revoke" {
                        &["token"]
                    } else {
                        &["accessor"]
                    },
                )?;
                let id = self.target_token(namespace, body, operation.ends_with("accessor"))?;
                self.revoke(&id);
                Ok(empty(true))
            }
            "renew-self" | "renew" | "renew-accessor" => {
                let id = if operation == "renew-self" {
                    reject_unknown(body, &["increment"])?;
                    actor.digest.clone()
                } else {
                    reject_unknown(
                        body,
                        if operation == "renew" {
                            &["token", "increment"]
                        } else {
                            &["accessor", "increment"]
                        },
                    )?;
                    self.target_token(namespace, body, operation.ends_with("accessor"))?
                };
                self.active_token(&id, now, false)?;
                let cert_role_limits = self.cert_renewal_limits(&id)?;
                let cert_role_limits = cert_role_limits
                    .map(|(mount, token_ttl, token_max_ttl)| {
                        self.auth_mount_token_limits(
                            AuthScope {
                                namespace,
                                mount: &mount,
                            },
                            token_ttl,
                            token_max_ttl,
                        )
                    })
                    .transpose()?;
                let mut ancestor_limit: Option<u64> = None;
                let mut parent_id = self
                    .tokens
                    .get(&id)
                    .and_then(|token| token.parent.as_deref());
                while let Some(parent) = parent_id {
                    let ancestor = self.tokens.get(parent).ok_or_else(denied)?;
                    if let Some(expiry) = ancestor.expires_at {
                        ancestor_limit = Some(
                            ancestor_limit
                                .map(|limit| limit.min(expiry))
                                .unwrap_or(expiry),
                        );
                    }
                    parent_id = ancestor.parent.as_deref();
                }
                let increment = duration(body, "increment", DEFAULT_TTL)?;
                let token = self.tokens.get_mut(&id).ok_or_else(denied)?;
                if !token.renewable {
                    return Err(bad("token is not renewable"));
                }
                let ttl = if token.period > 0 {
                    token.period
                } else if increment == 0 {
                    cert_role_limits.map_or(DEFAULT_TTL, |(token_ttl, _)| token_ttl)
                } else {
                    increment
                        .min(cert_role_limits.map_or(MAX_TTL, |(_, token_max_ttl)| token_max_ttl))
                };
                let proposed = checked_expiry(now, ttl)?;
                let expires_at = token
                    .max_expires_at
                    .map(|max| proposed.min(max))
                    .unwrap_or(proposed);
                let expires_at = ancestor_limit
                    .map(|limit| expires_at.min(limit))
                    .unwrap_or(expires_at);
                let cert_max_expiry = cert_role_limits
                    .map(|(_, token_max_ttl)| checked_expiry(now, token_max_ttl))
                    .transpose()?;
                let expires_at = cert_max_expiry
                    .map(|max| expires_at.min(max))
                    .unwrap_or(expires_at);
                if expires_at <= now {
                    return Err(denied());
                }
                token.expires_at = Some(expires_at);
                Ok(AuthResponse {
                    login_identity: None,
                    status: 200,
                    mutated: true,
                    body: json!({"auth": {
                        "accessor": token.accessor, "policies": token.policies, "token_policies": token.policies,
                        "entity_id": token.entity_id.as_deref().unwrap_or(""),
                        "lease_duration": expires_at - now, "renewable": true, "token_type": "service"
                    }}),
                })
            }
            _ => Err(err(404, "unsupported token operation")),
        }
    }

    fn target_token(
        &self,
        namespace: &str,
        body: &Value,
        accessor: bool,
    ) -> Result<String, AuthError> {
        let id = if accessor {
            let wanted = string_field(body, "accessor")?;
            self.tokens
                .iter()
                .find(|(_, t)| t.namespace == namespace && t.accessor == wanted)
                .map(|(id, _)| id.clone())
                .ok_or_else(denied)?
        } else {
            hash(string_field(body, "token")?)
        };
        if self
            .tokens
            .get(&id)
            .is_none_or(|token| token.namespace != namespace)
        {
            return Err(denied());
        }
        Ok(id)
    }

    fn cert_renewal_limits(&self, id: &str) -> Result<Option<(String, u64, u64)>, AuthError> {
        let token = self.tokens.get(id).ok_or_else(denied)?;
        let Some(role_name) = token.auth_cert_role.as_deref() else {
            return Ok(None);
        };
        let mount = token.auth_mount.as_deref().ok_or_else(denied)?;
        let digest = token.auth_cert_sha256.as_deref().ok_or_else(denied)?;
        let role = self
            .cert_roles
            .get(&token.namespace)
            .and_then(|mounts| mounts.get(mount))
            .and_then(|roles| roles.get(role_name))
            .ok_or_else(denied)?;
        if role.certificate_sha256 != digest || role.policies != token.policies {
            return Err(denied());
        }
        Ok(Some((mount.into(), role.token_ttl, role.token_max_ttl)))
    }

    fn create_token(
        &mut self,
        actor: &Principal,
        namespace: &str,
        path: &str,
        body: &Value,
        now: u64,
        force_orphan: bool,
    ) -> Result<AuthResponse, AuthError> {
        reject_unknown(
            body,
            &[
                "policies",
                "ttl",
                "explicit_max_ttl",
                "period",
                "num_uses",
                "renewable",
                "no_parent",
                "no_default_policy",
                "display_name",
                "type",
            ],
        )?;
        if body
            .get("type")
            .is_some_and(|value| value.as_str() != Some("service"))
        {
            return Err(bad("only service tokens are supported"));
        }
        let parent = self.check_principal(actor, namespace, now)?.clone();
        if parent.uses_remaining.is_some() {
            return Err(bad("limited-use tokens cannot create child tokens"));
        }
        let add_default = !boolean(body, "no_default_policy", false)?;
        let requested = policies(body, "policies", &parent.policies, add_default)?;
        if !parent.root && (!requested.is_subset(&parent.policies) || requested.contains("root")) {
            return Err(denied());
        }
        let root = requested.contains("root");
        if root && (requested.len() != 1 || !namespace.is_empty()) {
            return Err(bad("root policy must be exclusive and in root namespace"));
        }
        let no_parent = force_orphan || boolean(body, "no_parent", false)?;
        let period = duration(body, "period", 0)?;
        if no_parent || period > 0 {
            self.authorize_request(actor, namespace, path, "sudo", now)?;
        }
        if period > MAX_TTL {
            return Err(bad("period exceeds maximum TTL"));
        }
        let ttl = duration(body, "ttl", DEFAULT_TTL)?;
        let ttl = if period > 0 {
            period
        } else if ttl == 0 && !root {
            DEFAULT_TTL
        } else {
            ttl
        };
        if ttl > MAX_TTL {
            return Err(bad("TTL exceeds maximum"));
        }
        let explicit_max = duration(body, "explicit_max_ttl", 0)?;
        if explicit_max > MAX_TTL {
            return Err(bad("explicit maximum TTL exceeds service maximum"));
        }
        let max_expires_at = if explicit_max > 0 {
            Some(checked_expiry(now, explicit_max)?)
        } else if period == 0 && !(root && ttl == 0) {
            Some(checked_expiry(now, MAX_TTL)?)
        } else {
            None
        };
        let mut expires_at = if root && ttl == 0 {
            None
        } else {
            Some(checked_expiry(now, ttl)?)
        };
        if let (Some(expiry), Some(max)) = (expires_at, max_expires_at) {
            expires_at = Some(expiry.min(max));
        }
        if !no_parent && let Some(parent_expiry) = parent.expires_at {
            expires_at = Some(
                expires_at
                    .map(|e| e.min(parent_expiry))
                    .unwrap_or(parent_expiry),
            );
        }
        let display_name = body
            .get("display_name")
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| bad("display name must be a string"))
            })
            .transpose()?
            .unwrap_or("token");
        if display_name.len() > 128 {
            return Err(bad("display name too long"));
        }
        self.issue(
            Token {
                wrapping: None,
                entity_id: parent.entity_id.clone(),
                cubbyhole: cubbyhole::TokenCubbyhole::default(),
                accessor: random_id("a.")?,
                namespace: namespace.into(),
                policies: requested,
                root,
                parent: if no_parent {
                    None
                } else {
                    Some(actor.digest.clone())
                },
                created_at: now,
                expires_at,
                max_expires_at,
                period,
                renewable: boolean(body, "renewable", true)? && expires_at.is_some(),
                uses_remaining: unlimited_zero(number(body, "num_uses", 0)?),
                display_name: display_name.into(),
                auth_mount: parent.auth_mount.clone(),
                auth_origin_known: parent.root || parent.auth_origin_known,
                auth_cert_role: parent.auth_cert_role.clone(),
                auth_cert_sha256: parent.auth_cert_sha256.clone(),
            },
            now,
        )
    }

    fn policy_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let suffix = path
            .strip_prefix("sys/policies/acl")
            .or_else(|| path.strip_prefix("sys/policy"))
            .ok_or_else(|| bad("invalid policy route"))?;
        let name = suffix.strip_prefix('/').unwrap_or(suffix);
        let capability = match method {
            "GET" if name.is_empty() => "list",
            "GET" => "read",
            "LIST" => "list",
            "DELETE" => "delete",
            "POST" | "PUT" => "update",
            _ => return Err(err(405, "method not allowed")),
        };
        let actor = self.permission(principal, namespace, path, capability, now)?;
        if name.is_empty() {
            if capability != "list" {
                return Err(bad("policy name required"));
            }
            let mut keys: BTreeSet<String> = self
                .policies
                .get(namespace)
                .map(|p| p.keys().cloned().collect())
                .unwrap_or_default();
            keys.insert("default".into());
            if namespace.is_empty() {
                keys.insert("root".into());
            }
            return Ok(response(json!({"keys": keys, "policies": keys}), false));
        }
        if !valid_name(name) {
            return Err(bad("invalid policy name"));
        }
        if name == "root" {
            return Err(bad("root policy cannot be read, changed, or deleted"));
        }
        if capability == "read" {
            let source = match self
                .policies
                .get(namespace)
                .and_then(|entries| entries.get(name))
            {
                Some(policy) => policy.source.clone(),
                None if name == "default" => default_policy_source(),
                None => return Err(err(404, "policy not found")),
            };
            return Ok(response(
                json!({"name": name, "policy": source, "rules": source}),
                false,
            ));
        }
        self.authorize_request(actor, namespace, path, "sudo", now)?;
        if capability == "delete" {
            if name == "default" {
                return Err(bad("default policy cannot be deleted"));
            }
            if let Some(entries) = self.policies.get_mut(namespace) {
                entries.remove(name);
            }
            return Ok(empty(true));
        }
        if capability != "update" {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &["policy"])?;
        let input = body
            .get("policy")
            .ok_or_else(|| bad("policy is required"))?;
        let policy = parse_policy(input)?;
        self.policies
            .entry(namespace.into())
            .or_default()
            .insert(name.into(), policy);
        Ok(empty(true))
    }

    fn user_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        let suffix = path
            .strip_prefix(&format!("auth/{mount}/users"))
            .ok_or_else(|| bad("invalid user route"))?
            .trim_start_matches('/');
        let (name, subpath) = suffix.split_once('/').unwrap_or((suffix, ""));
        let capability = route_capability(method, suffix.is_empty())?;
        let actor = self.permission(principal, namespace, path, capability, now)?;
        if name.is_empty() && capability == "list" {
            let keys: Vec<&str> = self
                .users_at(scope)
                .map(|users| users.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys": keys}), false));
        }
        if !valid_name(name) || !["", "password", "policies", "mfa"].contains(&subpath) {
            return Err(bad("invalid user route"));
        }
        let existing = self
            .users_at(scope)
            .and_then(|users| users.get(name))
            .cloned();
        if subpath == "mfa" {
            let mut user = existing.ok_or_else(|| err(404, "user not found"))?;
            match capability {
                "read" => {
                    reject_unknown(body, &[])?;
                    let enrollment = user
                        .mfa
                        .as_ref()
                        .ok_or_else(|| err(404, "MFA enrollment not found"))?;
                    return Ok(response(
                        json!({
                            "enabled": true,
                            "type": "totp",
                            "algorithm": "SHA256",
                            "digits": enrollment.digits,
                            "period": enrollment.period_seconds,
                            "last_counter_present": enrollment.last_accepted_counter.is_some()
                        }),
                        false,
                    ));
                }
                "delete" => {
                    reject_unknown(body, &[])?;
                    self.authorize_request(actor, namespace, path, "sudo", now)?;
                    let changed = user.mfa.take().is_some();
                    self.users_at_mut(scope).insert(name.into(), user);
                    return Ok(empty(changed));
                }
                "update" => {
                    reject_unknown(body, &["regenerate"])?;
                    self.authorize_request(actor, namespace, path, "sudo", now)?;
                    let regenerate = boolean(body, "regenerate", false)?;
                    if user.mfa.is_some() && !regenerate {
                        return Err(bad(
                            "MFA is already enrolled; explicit regenerate=true is required",
                        ));
                    }
                    let secret = random_bytes(MFA_SEED_BYTES)?;
                    let secret_base32 = Zeroizing::new(base32_no_padding(&secret));
                    user.mfa = Some(TotpEnrollment {
                        secret,
                        period_seconds: MFA_PERIOD_SECONDS,
                        digits: u8::try_from(MFA_DIGITS)
                            .map_err(|_| err(500, "invalid MFA digit configuration"))?,
                        last_accepted_counter: None,
                    });
                    self.users_at_mut(scope).insert(name.into(), user);
                    return Ok(response(
                        json!({
                            "enabled": true,
                            "type": "totp",
                            "algorithm": "SHA256",
                            "digits": MFA_DIGITS,
                            "period": MFA_PERIOD_SECONDS,
                            "secret_base32": secret_base32.as_str()
                        }),
                        true,
                    ));
                }
                _ => return Err(err(405, "method not allowed")),
            }
        }
        if capability == "read" && subpath.is_empty() {
            let user = existing.ok_or_else(|| err(404, "user not found"))?;
            return Ok(response(
                json!({"policies": user.policies, "token_policies": user.policies, "token_ttl": user.token_ttl, "token_max_ttl": user.token_max_ttl, "token_num_uses": user.token_num_uses}),
                false,
            ));
        }
        if capability == "delete" && subpath.is_empty() {
            self.users_at_mut(scope).remove(name);
            return Ok(empty(true));
        }
        if capability != "update" {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(
            body,
            &[
                "password",
                "policies",
                "token_policies",
                "ttl",
                "max_ttl",
                "token_ttl",
                "token_max_ttl",
                "token_num_uses",
            ],
        )?;
        if subpath == "password"
            && (body.as_object().is_none_or(|o| o.len() != 1) || body.get("password").is_none())
        {
            return Err(bad("password endpoint accepts only password"));
        }
        if subpath == "policies"
            && body
                .as_object()
                .is_some_and(|o| o.keys().any(|k| k != "policies" && k != "token_policies"))
        {
            return Err(bad("policies endpoint accepts only policy fields"));
        }
        let (mount_default_ttl, mount_max_ttl) = self.auth_mount_token_limits(scope, 0, 0)?;
        let mut user = existing.clone().unwrap_or(User {
            salt: vec![],
            verifier: vec![],
            rounds: PASSWORD_ROUNDS,
            policies: BTreeSet::from(["default".into()]),
            token_ttl: mount_default_ttl,
            token_max_ttl: mount_max_ttl,
            token_num_uses: 0,
            mfa: None,
        });
        if let Some(password) = body.get("password") {
            let password = password
                .as_str()
                .ok_or_else(|| bad("password must be a string"))?;
            if password.len() < 12 || password.len() > 1024 {
                return Err(bad("password must be 12 to 1024 bytes"));
            }
            user.salt.zeroize();
            user.verifier.zeroize();
            user.salt = random_bytes(32)?;
            user.verifier = vec![0; digest::SHA256_OUTPUT_LEN];
            user.rounds = PASSWORD_ROUNDS;
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA256,
                NonZeroU32::new(PASSWORD_ROUNDS)
                    .ok_or_else(|| err(500, "invalid password parameters"))?,
                &user.salt,
                password.as_bytes(),
                &mut user.verifier,
            );
        } else if existing.is_none() {
            return Err(bad("password is required for new user"));
        }
        reject_alias_pair(body, "policies", "token_policies")?;
        reject_alias_pair(body, "ttl", "token_ttl")?;
        reject_alias_pair(body, "max_ttl", "token_max_ttl")?;
        user.policies = policies(
            body,
            if body.get("token_policies").is_some() {
                "token_policies"
            } else {
                "policies"
            },
            &user.policies,
            true,
        )?;
        self.validate_assignment(actor, &user.policies)?;
        user.token_ttl = duration(
            body,
            if body.get("token_ttl").is_some() {
                "token_ttl"
            } else {
                "ttl"
            },
            user.token_ttl,
        )?;
        user.token_max_ttl = duration(
            body,
            if body.get("token_max_ttl").is_some() {
                "token_max_ttl"
            } else {
                "max_ttl"
            },
            user.token_max_ttl,
        )?;
        normalize_ttl(&mut user.token_ttl, &mut user.token_max_ttl)?;
        user.token_num_uses = number(body, "token_num_uses", user.token_num_uses)?;
        self.users_at_mut(scope).insert(name.into(), user);
        Ok(empty(true))
    }

    fn auth_mount_token_limits(
        &self,
        scope: AuthScope<'_>,
        ttl: u64,
        max_ttl: u64,
    ) -> Result<(u64, u64), AuthError> {
        let mount = self
            .effective_auth_mounts(scope.namespace)
            .get(scope.mount)
            .cloned()
            .ok_or_else(|| err(404, "auth mount not found"))?;
        let mount_default = if mount.default_lease_ttl == 0 {
            DEFAULT_TTL
        } else {
            mount.default_lease_ttl
        };
        let mount_max = if mount.max_lease_ttl == 0 {
            MAX_TTL
        } else {
            mount.max_lease_ttl
        };
        if mount_default == 0 || mount_default > mount_max || mount_max > MAX_TTL {
            return Err(bad("invalid persisted auth mount TTL limits"));
        }
        let mut effective_ttl = if ttl == 0 { mount_default } else { ttl };
        let mut effective_max = if max_ttl == 0 { mount_max } else { max_ttl };
        effective_max = effective_max.min(mount_max);
        effective_ttl = effective_ttl.min(effective_max);
        if effective_ttl == 0 || effective_ttl > effective_max {
            return Err(bad("invalid effective auth token TTL limits"));
        }
        Ok((effective_ttl, effective_max))
    }

    fn validate_assignment(
        &self,
        actor: &Principal,
        requested: &BTreeSet<String>,
    ) -> Result<(), AuthError> {
        if requested.contains("root") || !actor.is_root() && !requested.is_subset(actor.policies())
        {
            return Err(denied());
        }
        Ok(())
    }

    fn login_userpass(
        &mut self,
        scope: AuthScope<'_>,
        method: &str,
        name: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        if !valid_name(name) {
            return Err(denied());
        }
        reject_unknown(body, &["password", "totp_code"])?;
        let password = string_field(body, "password")?;
        if password.len() > 1024 {
            return Err(denied());
        }
        let user = self
            .users_at(scope)
            .and_then(|users| users.get(name))
            .cloned();
        // A nonexistent account still performs the same password KDF.
        let dummy_salt = [0u8; 32];
        let dummy_verifier = [0u8; 32];
        let (rounds, salt, verifier) = user
            .as_ref()
            .map(|u| (u.rounds, u.salt.as_slice(), u.verifier.as_slice()))
            .unwrap_or((PASSWORD_ROUNDS, &dummy_salt, &dummy_verifier));
        let rounds = NonZeroU32::new(rounds).ok_or_else(denied)?;
        let verified = pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            rounds,
            salt,
            password.as_bytes(),
            verifier,
        )
        .is_ok();
        let mut user = user.filter(|_| verified).ok_or_else(denied)?;
        let accepted_counter = match user.mfa.as_ref() {
            Some(enrollment) => Some(verify_totp(
                enrollment,
                body.get("totp_code")
                    .and_then(Value::as_str)
                    .ok_or_else(denied)?,
                now,
            )?),
            None => {
                if body.get("totp_code").is_some() {
                    return Err(bad("MFA is not configured for this user"));
                }
                None
            }
        };
        let (token_ttl, token_max_ttl) =
            self.auth_mount_token_limits(scope, user.token_ttl, user.token_max_ttl)?;
        let mut token = login_token(
            namespace,
            user.policies.clone(),
            token_ttl,
            token_max_ttl,
            user.token_num_uses,
            format!("userpass-{name}"),
            now,
        )?;
        token.auth_mount = Some(mount.into());
        let (token_id, token, mut response) = Self::prepare_issue(token, now)?;
        response.login_identity = Some(LoginIdentity {
            mount: mount.into(),
            alias: name.into(),
        });
        if let Some(counter) = accepted_counter {
            let enrollment = user
                .mfa
                .as_mut()
                .ok_or_else(|| err(500, "MFA enrollment disappeared during login"))?;
            enrollment.last_accepted_counter = Some(counter);
        }
        self.users_at_mut(scope).insert(name.into(), user);
        self.tokens.insert(token_id, token);
        Ok(response)
    }

    fn role_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        let suffix = path
            .strip_prefix(&format!("auth/{mount}/role"))
            .ok_or_else(|| bad("invalid role route"))?
            .trim_start_matches('/');
        let (name, operation) = suffix.split_once('/').unwrap_or((suffix, ""));
        let capability = route_capability(
            method,
            suffix.is_empty() || operation == "secret-id" && method == "LIST",
        )?;
        let actor = self.permission(principal, namespace, path, capability, now)?;
        if name.is_empty() && capability == "list" {
            let keys: Vec<&str> = self
                .roles_at(scope)
                .map(|roles| roles.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys": keys}), false));
        }
        if !valid_name(name) {
            return Err(bad("invalid role name"));
        }
        let existing = self
            .roles_at(scope)
            .and_then(|roles| roles.get(name))
            .cloned();
        if operation.is_empty() {
            if capability == "read" {
                let role = existing.ok_or_else(|| err(404, "role not found"))?;
                return Ok(response(
                    json!({"bind_secret_id": role.bind_secret_id, "token_policies": role.policies, "token_ttl": role.token_ttl,
                    "token_max_ttl": role.token_max_ttl, "token_num_uses": role.token_num_uses, "secret_id_ttl": role.secret_id_ttl, "secret_id_num_uses": role.secret_id_num_uses}),
                    false,
                ));
            }
            if capability == "delete" {
                self.roles_at_mut(scope).remove(name);
                return Ok(empty(true));
            }
            if capability != "update" {
                return Err(err(405, "method not allowed"));
            }
            reject_unknown(
                body,
                &[
                    "bind_secret_id",
                    "policies",
                    "token_policies",
                    "token_ttl",
                    "token_max_ttl",
                    "token_num_uses",
                    "secret_id_ttl",
                    "secret_id_num_uses",
                ],
            )?;
            reject_alias_pair(body, "policies", "token_policies")?;
            let (mount_default_ttl, mount_max_ttl) = self.auth_mount_token_limits(scope, 0, 0)?;
            let mut role = existing.unwrap_or(Role {
                role_id: random_id("role.")?,
                bind_secret_id: true,
                policies: BTreeSet::from(["default".into()]),
                token_ttl: mount_default_ttl,
                token_max_ttl: mount_max_ttl,
                token_num_uses: 0,
                secret_id_ttl: DEFAULT_TTL,
                secret_id_num_uses: 1,
                secret_ids: BTreeMap::new(),
            });
            role.bind_secret_id = boolean(body, "bind_secret_id", role.bind_secret_id)?;
            role.policies = policies(
                body,
                if body.get("token_policies").is_some() {
                    "token_policies"
                } else {
                    "policies"
                },
                &role.policies,
                true,
            )?;
            self.validate_assignment(actor, &role.policies)?;
            role.token_ttl = duration(body, "token_ttl", role.token_ttl)?;
            role.token_max_ttl = duration(body, "token_max_ttl", role.token_max_ttl)?;
            normalize_ttl(&mut role.token_ttl, &mut role.token_max_ttl)?;
            role.token_num_uses = number(body, "token_num_uses", role.token_num_uses)?;
            role.secret_id_ttl = duration(body, "secret_id_ttl", role.secret_id_ttl)?;
            if role.secret_id_ttl > MAX_TTL {
                return Err(bad("secret_id TTL exceeds maximum"));
            }
            role.secret_id_num_uses = number(body, "secret_id_num_uses", role.secret_id_num_uses)?;
            self.roles_at_mut(scope).insert(name.into(), role);
            return Ok(empty(true));
        }
        let mut role = existing.ok_or_else(|| err(404, "role not found"))?;
        match (operation, capability) {
            ("role-id", "read") => Ok(response(json!({"role_id": role.role_id}), false)),
            ("role-id", "update") => {
                reject_unknown(body, &["role_id"])?;
                let value = string_field(body, "role_id")?;
                if value.is_empty()
                    || value.len() > 256
                    || self.roles_at(scope).is_some_and(|roles| {
                        roles
                            .iter()
                            .any(|(other, role)| other != name && role.role_id == value)
                    })
                {
                    return Err(bad("invalid or duplicate role_id"));
                }
                role.role_id = value.into();
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(empty(true))
            }
            ("secret-id", "list") => {
                let keys: Vec<&str> = role
                    .secret_ids
                    .values()
                    .filter(|secret| {
                        !secret.expires_at.is_some_and(|t| t <= now)
                            && secret.uses_remaining != Some(0)
                    })
                    .map(|secret| secret.accessor.as_str())
                    .collect();
                Ok(response(json!({"keys": keys}), false))
            }
            ("secret-id", "update") => {
                reject_unknown(body, &["ttl", "num_uses"])?;
                let ttl = duration(body, "ttl", role.secret_id_ttl)?;
                let num_uses = number(body, "num_uses", role.secret_id_num_uses)?;
                if ttl > MAX_TTL
                    || role.secret_id_ttl > 0 && (ttl == 0 || ttl > role.secret_id_ttl)
                    || role.secret_id_num_uses > 0
                        && (num_uses == 0 || num_uses > role.secret_id_num_uses)
                {
                    return Err(bad("secret_id constraints exceed role limits"));
                }
                let raw = Zeroizing::new(random_id("secret.")?);
                let accessor = random_id("sa.")?;
                let expires_at = if ttl == 0 {
                    None
                } else {
                    Some(checked_expiry(now, ttl)?)
                };
                role.secret_ids.insert(
                    hash(&raw),
                    SecretId {
                        accessor: accessor.clone(),
                        expires_at,
                        uses_remaining: unlimited_zero(num_uses),
                    },
                );
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(response(
                    json!({"secret_id": raw.as_str(), "secret_id_accessor": accessor, "secret_id_ttl": ttl, "secret_id_num_uses": num_uses}),
                    true,
                ))
            }
            ("secret-id/lookup", "update")
            | ("secret-id-accessor/lookup", "update")
            | ("secret-id/destroy", "update")
            | ("secret-id-accessor/destroy", "update") => {
                let by_accessor = operation.starts_with("secret-id-accessor/");
                reject_unknown(
                    body,
                    if by_accessor {
                        &["secret_id_accessor"]
                    } else {
                        &["secret_id"]
                    },
                )?;
                let id = if by_accessor {
                    let wanted = string_field(body, "secret_id_accessor")?;
                    role.secret_ids
                        .iter()
                        .find(|(_, secret)| secret.accessor == wanted)
                        .map(|(id, _)| id.clone())
                        .ok_or_else(|| err(404, "secret_id not found"))?
                } else {
                    hash(string_field(body, "secret_id")?)
                };
                let secret = role
                    .secret_ids
                    .get(&id)
                    .ok_or_else(|| err(404, "secret_id not found"))?;
                if operation.ends_with("/lookup") {
                    return Ok(response(
                        json!({"secret_id_accessor": secret.accessor, "secret_id_num_uses": secret.uses_remaining.unwrap_or(0), "expiration_time_unix": secret.expires_at}),
                        false,
                    ));
                }
                if let Some((mut stored_id, _)) = role.secret_ids.remove_entry(&id) {
                    stored_id.zeroize();
                }
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(empty(true))
            }
            _ => Err(err(404, "unsupported AppRole operation")),
        }
    }

    fn login_approle(
        &mut self,
        scope: AuthScope<'_>,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &["role_id", "secret_id"])?;
        let role_id = string_field(body, "role_id")?;
        let secret_id = body.get("secret_id").and_then(Value::as_str);
        if role_id.len() > 256 || secret_id.is_some_and(|value| value.len() > 256) {
            return Err(denied());
        }
        let (name, mut role) = self
            .roles_at(scope)
            .and_then(|roles| roles.iter().find(|(_, role)| role.role_id == role_id))
            .map(|(name, role)| (name.clone(), role.clone()))
            .ok_or_else(denied)?;
        if role.bind_secret_id {
            let secret_id = secret_id.ok_or_else(denied)?;
            let id = hash(secret_id);
            let secret = role.secret_ids.get_mut(&id).ok_or_else(denied)?;
            if secret.expires_at.is_some_and(|expiry| now >= expiry)
                || secret.uses_remaining == Some(0)
            {
                return Err(denied());
            }
            if let Some(remaining) = &mut secret.uses_remaining {
                *remaining -= 1;
            }
        }
        let (token_ttl, token_max_ttl) =
            self.auth_mount_token_limits(scope, role.token_ttl, role.token_max_ttl)?;
        let mut token = login_token(
            namespace,
            role.policies.clone(),
            token_ttl,
            token_max_ttl,
            role.token_num_uses,
            format!("approle-{name}"),
            now,
        )?;
        token.auth_mount = Some(mount.into());
        let mut issued = self.issue(token, now)?;
        issued.login_identity = Some(LoginIdentity {
            mount: mount.into(),
            alias: role_id.into(),
        });
        self.roles_at_mut(scope).insert(name, role);
        Ok(issued)
    }
}

fn base32_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((buffer >> bits) & 0x1f).unwrap_or(0);
            output.push(char::from(ALPHABET[index]));
        }
    }
    if bits > 0 {
        let index = usize::try_from((buffer << (5 - bits)) & 0x1f).unwrap_or(0);
        output.push(char::from(ALPHABET[index]));
    }
    output
}

fn totp_code(secret: &[u8], counter: u64) -> [u8; MFA_DIGITS] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = usize::from(bytes[bytes.len() - 1] & 0x0f);
    let binary = (u32::from(bytes[offset]) & 0x7f) << 24
        | u32::from(bytes[offset + 1]) << 16
        | u32::from(bytes[offset + 2]) << 8
        | u32::from(bytes[offset + 3]);
    let mut value = binary % 1_000_000;
    let mut code = [b'0'; MFA_DIGITS];
    for position in (0..MFA_DIGITS).rev() {
        code[position] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
    }
    code
}

fn verify_totp(enrollment: &TotpEnrollment, supplied: &str, now: u64) -> Result<u64, AuthError> {
    if enrollment.secret.len() != MFA_SEED_BYTES
        || enrollment.period_seconds != MFA_PERIOD_SECONDS
        || usize::from(enrollment.digits) != MFA_DIGITS
        || supplied.len() != MFA_DIGITS
        || !supplied.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(denied());
    }
    let current = now / enrollment.period_seconds;
    let start = current.saturating_sub(MFA_DRIFT_STEPS);
    let end = current.saturating_add(MFA_DRIFT_STEPS);
    let mut accepted = None;
    for counter in start..=end {
        if enrollment
            .last_accepted_counter
            .is_some_and(|last| counter <= last)
        {
            continue;
        }
        let expected = totp_code(&enrollment.secret, counter);
        let comparison_key = hmac::Key::new(hmac::HMAC_SHA256, &enrollment.secret);
        let expected_tag = hmac::sign(&comparison_key, &expected);
        if hmac::verify(&comparison_key, supplied.as_bytes(), expected_tag.as_ref()).is_ok() {
            accepted = Some(accepted.map_or(counter, |found: u64| found.max(counter)));
        }
    }
    accepted.ok_or_else(denied)
}

fn route_capability(method: &str, collection: bool) -> Result<&'static str, AuthError> {
    match method {
        "GET" if collection => Ok("list"),
        "GET" => Ok("read"),
        "LIST" => Ok("list"),
        "POST" | "PUT" => Ok("update"),
        "DELETE" => Ok("delete"),
        _ => Err(err(405, "method not allowed")),
    }
}
fn reject_alias_pair(body: &Value, a: &str, b: &str) -> Result<(), AuthError> {
    if body.get(a).is_some() && body.get(b).is_some() {
        return Err(bad("conflicting aliases"));
    }
    Ok(())
}
fn normalize_ttl(ttl: &mut u64, max_ttl: &mut u64) -> Result<(), AuthError> {
    if *ttl == 0 {
        *ttl = DEFAULT_TTL;
    }
    if *max_ttl == 0 {
        *max_ttl = MAX_TTL;
    }
    if *ttl > *max_ttl || *max_ttl > MAX_TTL {
        return Err(bad("invalid token TTL limits"));
    }
    Ok(())
}
fn login_token(
    namespace: &str,
    policies: BTreeSet<String>,
    ttl: u64,
    max_ttl: u64,
    uses: u64,
    display_name: String,
    now: u64,
) -> Result<Token, AuthError> {
    if policies.contains("root") {
        return Err(denied());
    }
    Ok(Token {
        wrapping: None,
        entity_id: None,
        cubbyhole: cubbyhole::TokenCubbyhole::default(),
        accessor: random_id("a.")?,
        namespace: namespace.into(),
        policies,
        root: false,
        parent: None,
        created_at: now,
        expires_at: Some(checked_expiry(now, ttl)?),
        max_expires_at: Some(checked_expiry(now, max_ttl)?),
        period: 0,
        renewable: true,
        uses_remaining: unlimited_zero(uses),
        display_name,
        auth_mount: None,
        auth_origin_known: true,
        auth_cert_role: None,
        auth_cert_sha256: None,
    })
}
fn token_info(token: &Token, now: u64) -> Value {
    json!({"accessor": token.accessor, "policies": token.policies, "display_name": token.display_name,
        "creation_time": token.created_at, "ttl": token.expires_at.map(|t| t.saturating_sub(now)).unwrap_or(0),
        "expire_time_unix": token.expires_at, "explicit_max_ttl": token.max_expires_at.map(|t| t.saturating_sub(token.created_at)).unwrap_or(0),
        "period": token.period, "num_uses": token.uses_remaining.unwrap_or(0), "renewable": token.renewable,
        "orphan": token.parent.is_none(), "type": "service", "namespace": token.namespace,
        "entity_id": token.entity_id.as_deref().unwrap_or("")})
}

fn default_policy_source() -> String {
    acl::DEFAULT_RULES
        .iter()
        .map(|(path, caps)| {
            let caps = caps
                .iter()
                .map(|cap| format!("\"{cap}\""))
                .collect::<Vec<_>>()
                .join(", ");
            format!("path \"{path}\" {{ capabilities = [{caps}] }}\n")
        })
        .collect()
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let prefix = pattern.strip_suffix('*');
    let pattern = prefix.unwrap_or(pattern);
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    if prefix.is_none() && pattern_parts.len() != path_parts.len() {
        return false;
    }
    if path_parts.len() < pattern_parts.len() {
        return false;
    }
    for (index, segment) in pattern_parts.iter().enumerate() {
        let Some(actual) = path_parts.get(index) else {
            return false;
        };
        if prefix.is_some() && index + 1 == pattern_parts.len() {
            if *segment == "+" {
                return !actual.is_empty();
            }
            return actual.starts_with(segment);
        }
        if *segment == "+" {
            if actual.is_empty() {
                return false;
            }
        } else if segment != actual {
            return false;
        }
    }
    true
}

/// Decode JSON without permitting duplicate object keys at any depth. The
/// caller owns clearing a successful Value; partial values clear on parse errors.
pub(crate) fn parse_strict_json(bytes: &[u8]) -> Result<Value, AuthError> {
    let mut parsed = serde_json::from_slice::<StrictJson>(bytes)
        .map_err(|_| bad("invalid JSON or duplicate object key"))?;
    Ok(std::mem::take(&mut parsed.0))
}

struct StrictJson(Value);
impl Drop for StrictJson {
    fn drop(&mut self) {
        erase_parsed_json(&mut self.0);
    }
}
fn erase_parsed_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                erase_parsed_json(value);
            }
        }
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                erase_parsed_json(&mut value);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> serde::de::Visitor<'de> for JsonVisitor {
            type Value = StrictJson;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(value.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(value.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| StrictJson(Value::Number(n)))
                    .ok_or_else(|| serde::de::Error::custom("invalid JSON number"))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::String(value.into())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::String(value)))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = StrictJson(Value::Array(Vec::new()));
                let values = result
                    .0
                    .as_array_mut()
                    .ok_or_else(|| serde::de::Error::custom("invalid JSON array"))?;
                while let Some(mut value) = seq.next_element::<StrictJson>()? {
                    values.push(std::mem::take(&mut value.0));
                }
                Ok(result)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = StrictJson(Value::Object(serde_json::Map::new()));
                let values = result
                    .0
                    .as_object_mut()
                    .ok_or_else(|| serde::de::Error::custom("invalid JSON object"))?;
                while let Some(key) = map.next_key::<String>()? {
                    let mut key = Zeroizing::new(key);
                    if values.contains_key(key.as_str()) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let mut value = map.next_value::<StrictJson>()?;
                    values.insert(std::mem::take(&mut *key), std::mem::take(&mut value.0));
                }
                Ok(result)
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

fn parse_policy(input: &Value) -> Result<Policy, AuthError> {
    let source = if let Some(source) = input.as_str() {
        source.to_owned()
    } else {
        serde_json::to_string(input).map_err(|_| bad("invalid policy"))?
    };
    if source.len() > 256 * 1024 {
        return Err(bad("policy too large"));
    }
    let trimmed = source.trim();
    let rules = if trimmed.starts_with('{') {
        let parsed = parse_strict_json(trimmed.as_bytes())?;
        reject_unknown(&parsed, &["path"])?;
        let paths = parsed
            .get("path")
            .and_then(Value::as_object)
            .ok_or_else(|| bad("policy path object is required"))?;
        let mut rules = Vec::new();
        for (path, config) in paths {
            reject_unknown(config, &["capabilities"])?;
            let caps = config
                .get("capabilities")
                .and_then(Value::as_array)
                .ok_or_else(|| bad("capabilities array is required"))?;
            let caps = caps
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| bad("capability must be a string"))
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            rules.push(rule(path.clone(), caps)?);
        }
        rules
    } else {
        let tokens = lex_hcl(trimmed)?;
        let mut cursor = 0;
        let mut rules = Vec::new();
        let mut seen = BTreeSet::new();
        while cursor < tokens.len() {
            take(&tokens, &mut cursor, Lex::Word("path".into()))?;
            let path = take_string(&tokens, &mut cursor)?;
            if !seen.insert(path.clone()) {
                return Err(bad("duplicate ACL path"));
            }
            take(&tokens, &mut cursor, Lex::Symbol('{'))?;
            take(&tokens, &mut cursor, Lex::Word("capabilities".into()))?;
            take(&tokens, &mut cursor, Lex::Symbol('='))?;
            take(&tokens, &mut cursor, Lex::Symbol('['))?;
            let mut caps = BTreeSet::new();
            if tokens.get(cursor) != Some(&Lex::Symbol(']')) {
                loop {
                    caps.insert(take_string(&tokens, &mut cursor)?);
                    if tokens.get(cursor) != Some(&Lex::Symbol(',')) {
                        break;
                    }
                    cursor += 1;
                    if tokens.get(cursor) == Some(&Lex::Symbol(']')) {
                        break;
                    }
                }
            }
            take(&tokens, &mut cursor, Lex::Symbol(']'))?;
            take(&tokens, &mut cursor, Lex::Symbol('}'))?;
            rules.push(rule(path, caps)?);
        }
        rules
    };
    if rules.len() > 4096 {
        return Err(bad("too many policy rules"));
    }
    Ok(Policy { source, rules })
}
fn rule(path: String, capabilities: BTreeSet<String>) -> Result<Rule, AuthError> {
    validate_path(&path, true)?;
    if capabilities
        .iter()
        .any(|capability| !CAPABILITIES.contains(&capability.as_str()))
    {
        return Err(bad("unsupported ACL capability"));
    }
    Ok(Rule { path, capabilities })
}

#[derive(Clone, PartialEq)]
enum Lex {
    Word(String),
    String(String),
    Symbol(char),
}
fn take(tokens: &[Lex], cursor: &mut usize, wanted: Lex) -> Result<(), AuthError> {
    if tokens.get(*cursor) != Some(&wanted) {
        return Err(bad("unsupported or malformed HCL policy"));
    }
    *cursor += 1;
    Ok(())
}
fn take_string(tokens: &[Lex], cursor: &mut usize) -> Result<String, AuthError> {
    if let Some(Lex::String(value)) = tokens.get(*cursor) {
        *cursor += 1;
        Ok(value.clone())
    } else {
        Err(bad("quoted string required in HCL policy"))
    }
}
fn lex_hcl(source: &str) -> Result<Vec<Lex>, AuthError> {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut result = Vec::new();
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes[index] == b'#' || bytes[index..].starts_with(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            index += 2;
            while index + 1 < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            if index + 1 >= bytes.len() {
                return Err(bad("unterminated HCL comment"));
            }
            index += 2;
            continue;
        }
        if b"{}[]=,".contains(&bytes[index]) {
            result.push(Lex::Symbol(bytes[index] as char));
            index += 1;
            continue;
        }
        if bytes[index] == b'"' {
            let start = index;
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                if bytes[index] == b'"' && !escaped {
                    break;
                }
                escaped = bytes[index] == b'\\' && !escaped;
                index += 1;
            }
            if index >= bytes.len() {
                return Err(bad("unterminated HCL string"));
            }
            index += 1;
            let value: String = serde_json::from_str(&source[start..index])
                .map_err(|_| bad("invalid HCL string escape"))?;
            result.push(Lex::String(value));
            continue;
        }
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            result.push(Lex::Word(source[start..index].into()));
            continue;
        }
        return Err(bad("unsupported character in HCL policy"));
    }
    Ok(result)
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;

// A bounded issuer reference is metadata, not a reusable execution Principal.
pub(crate) struct LeaseIssuer {
    pub(crate) digest: String,
    pub(crate) expires_at: Option<u64>,
    pub(crate) entity_id: Option<String>,
}
impl AuthState {
    pub(crate) fn lease_issuer(
        &self,
        actor: &Principal,
        namespace: &str,
        now: u64,
    ) -> Result<LeaseIssuer, AuthError> {
        self.check_principal(actor, namespace, now)?;
        self.lease_issuer_by_digest(&actor.digest, namespace, now)
            .ok_or_else(denied)
    }
    pub(crate) fn lease_issuer_by_digest(
        &self,
        id: &str,
        namespace: &str,
        now: u64,
    ) -> Option<LeaseIssuer> {
        let token = self.active_token(id, now, true).ok()?;
        if !token.root && token.namespace != namespace {
            return None;
        }
        let mut expires = token.expires_at;
        let mut parent = token.parent.as_deref();
        // active_token already rejected cycles, missing or expired ancestors.
        while let Some(id) = parent {
            let ancestor = self.tokens.get(id)?;
            if let Some(limit) = ancestor.expires_at {
                expires = Some(expires.map_or(limit, |current| current.min(limit)));
            }
            parent = ancestor.parent.as_deref();
        }
        Some(LeaseIssuer {
            digest: id.into(),
            expires_at: expires,
            entity_id: token.entity_id.clone(),
        })
    }
}
