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

#[path = "pki_external.rs"]
mod external;
pub(crate) use external::{ExternalPkiMaterial, ExternalPkiPublicKey, ExternalPkiTemplate};
#[path = "pki_local_key.rs"]
mod local_key;
#[path = "pki_public.rs"]
mod public;
use local_key::{LocalKeyKind, LocalPrivateMaterial, LocalPublicKey};
#[path = "pki_role_leaf_profile.rs"]
mod role_leaf_profile;
#[path = "pki_role_names.rs"]
mod role_names;
#[path = "pki_role_time.rs"]
mod role_time;
use role_names::RoleNamePolicy;
#[path = "pki_role_csr.rs"]
mod role_csr;
#[path = "pki_role_signatures.rs"]
mod role_signatures;
#[path = "pki_role_subjects.rs"]
mod role_subjects;
#[path = "pki_role_templates.rs"]
mod role_templates;
use role_signatures::LeafSignature;
use role_time::RoleTimePolicy;
#[path = "pki_issuer_time.rs"]
mod issuer_time;
use issuer_time::IssuerLeafNotAfterBehavior;
#[path = "pki_root_fields.rs"]
mod root_fields;
use role_leaf_profile::{LeafProfilePublicEvidence, RoleLeafProfile};
use root_fields::{LocalRootMetadata, RootFields};
#[path = "pki_local_issuers.rs"]
mod local_issuers;
use local_issuers::LocalIssuers;
#[path = "pki_local_crl.rs"]
mod local_crl;
use local_crl::LocalCrlState;
#[path = "pki_local_intermediate.rs"]
mod local_intermediate;
use local_intermediate::{LocalCaChain, LocalIntermediateState};
#[path = "pki_local_ocsp.rs"]
pub(crate) mod local_ocsp;

#[path = "pki_precise_time.rs"]
pub(in crate::engines) mod precise_time;
use precise_time::PkiInstant;

const MAX_ROLES: usize = 256;
const MAX_ISSUED: usize = 4096;
const MAX_TTL: u64 = 10 * 365 * 24 * 3600;
const DEFAULT_ROOT_TTL: u64 = 32 * 24 * 3600;
const DEFAULT_LEAF_TTL: u64 = 24 * 3600;
const MAX_ACME_LIST: usize = 64;
const MAX_ACME_CONFIG_STRING: usize = 2048;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootOutputFormat {
    Pem,
    Der,
    PemBundle,
}

impl RootOutputFormat {
    fn from_body(body: &Value) -> Result<Self> {
        match body.get("format") {
            None => Ok(Self::Pem),
            Some(Value::String(value)) if value == "pem" => Ok(Self::Pem),
            Some(Value::String(value)) if value == "der" => Ok(Self::Der),
            Some(Value::String(value)) if value == "pem_bundle" => Ok(Self::PemBundle),
            _ => Err(bad("invalid PKI root certificate format")),
        }
    }

    fn certificate(self, certificate_der: &[u8]) -> String {
        self.public("CERTIFICATE", certificate_der)
    }

    fn public(self, label: &str, der: &[u8]) -> String {
        match self {
            Self::Der => BASE64.encode(der),
            Self::Pem | Self::PemBundle => {
                // A non-exported root or KMS CSR bundle has only its public
                // object. The genuine 2.7 output omits exactly its final LF.
                let mut certificate = pem(label, der);
                if certificate.ends_with('\n') {
                    certificate.pop();
                }
                certificate
            }
        }
    }
}

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

impl AcmeConfig {
    fn is_default(value: &Self) -> bool {
        value == &Self::default()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Pki {
    #[serde(default = "default_leaf_ttl")]
    pub(super) default_ttl: u64,
    #[serde(default = "max_pki_ttl")]
    pub(super) max_ttl: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    cluster_path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    aia_path: String,
    #[serde(default, skip_serializing_if = "AcmeConfig::is_default")]
    acme: Box<AcmeConfig>,
    root: Option<RootCa>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_issuers: Option<Box<LocalIssuers>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_crl: Option<Box<LocalCrlState>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_intermediate: Option<Box<LocalIntermediateState>>,
    #[serde(default, skip_serializing_if = "external::ExternalState::is_empty")]
    external: Box<external::ExternalState>,
    roles: BTreeMap<String, Role>,
    pub(super) issued: BTreeMap<String, IssuedCertificate>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RootCa {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    leaf_not_after_behavior: Option<IssuerLeafNotAfterBehavior>,
    common_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    issuer_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_fields: Option<Box<LocalRootMetadata>>,
    pkcs8: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_material: Option<LocalPrivateMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_chain: Option<Box<LocalCaChain>>,
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

impl RootCa {
    fn is_external(&self) -> bool {
        self.pkcs8.is_empty() && self.local_material.is_none()
    }

    fn local_key(&self) -> Result<LocalPrivateMaterial> {
        match &self.local_material {
            Some(material) if self.pkcs8.is_empty() && material.kind() != LocalKeyKind::Ed25519 => {
                material.public()?;
                Ok(material.clone())
            }
            None if !self.pkcs8.is_empty() => Ok(LocalPrivateMaterial::Pkcs8 {
                kind: LocalKeyKind::Ed25519,
                der: self.pkcs8.clone(),
            }),
            _ => Err(error(503, "invalid local PKI root ownership")),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
struct Role {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_name_policy: Option<RoleNamePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_time_policy: Option<RoleTimePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_leaf_profile: Option<RoleLeafProfile>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    issuer_ref: String,
    allowed_domains: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "role_false")]
    allow_any_name: bool,
    // None is the historical candidate contract; new API creates store their
    // explicit effective value so an older reader cannot silently widen it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_bare_domains: Option<bool>,
    // None is the historical candidate contract. A new API role explicitly
    // owns its wildcard choice, including the official default true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_wildcard_certificates: Option<bool>,
    allow_subdomains: bool,
    #[serde(default)]
    allow_ip_sans: bool,
    max_ttl: u64,
    generate_lease: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_key_kind: Option<LocalKeyKind>,
}

fn role_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct IssuedCertificate {
    #[serde(default, skip_serializing_if = "role_false")]
    role_names_owned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer_not_after_behavior: Option<IssuerLeafNotAfterBehavior>,
    #[serde(default, skip_serializing_if = "role_false")]
    signed_role_time_owned: bool,
    #[serde(default, skip_serializing_if = "role_false")]
    role_time_owned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_leaf_profile: Option<LeafProfilePublicEvidence>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    local_issuer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_issuer_owner: Option<external::ExternalLeafIssuerOwner>,
    #[serde(default)]
    pub(super) leased: bool,
    pub(super) lease_id: String,
    pub(super) owner: LeaseOwner,
    pub(super) path: String,
    pub(super) issued: u64,
    pub(super) expires: u64,
    pub(super) revoked_at: Option<u64>,
    common_name: String,
    // A real leaf producer captures wildcard CN/SAN ownership before its
    // typed template is consumed. Historical false stays omitted byte-for-byte.
    #[serde(default, skip_serializing_if = "role_false")]
    wildcard_names: bool,
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
            default_ttl: DEFAULT_ROOT_TTL,
            max_ttl: DEFAULT_ROOT_TTL,
            cluster_path: String::new(),
            aia_path: String::new(),
            acme: Box::new(AcmeConfig::default()),
            root: None,
            local_issuers: None,
            local_crl: None,
            local_intermediate: None,
            external: Box::default(),
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

    pub(in crate::engines) fn has_role_wildcard_state(&self) -> bool {
        self.roles
            .values()
            .any(|role| role.allow_wildcard_certificates.is_some())
            || self
                .issued
                .values()
                .any(|issued| issued.wildcard_names || issued.common_name.contains('*'))
    }

    pub(in crate::engines) fn has_role_bare_domain_state(&self) -> bool {
        self.roles
            .values()
            .any(|role| role.allow_bare_domains.is_some())
    }

    pub(in crate::engines) fn has_role_any_name_state(&self) -> bool {
        self.roles.values().any(|role| role.allow_any_name)
    }

    pub(super) fn has_extension_state(&self) -> bool {
        !self.cluster_path.is_empty()
            || !self.aia_path.is_empty()
            || !AcmeConfig::is_default(&self.acme)
    }

    pub(in crate::engines) fn has_local_typed_key_state(&self) -> bool {
        self.root
            .as_ref()
            .is_some_and(|root| root.local_material.is_some())
            || self
                .roles
                .values()
                .any(|role| role.local_key_kind.is_some())
            || self.has_typed_leaf_subjects()
    }

    pub(in crate::engines) fn has_local_identifier_state(&self) -> bool {
        self.root
            .as_ref()
            .is_some_and(|root| !root.issuer_id.is_empty() || !root.key_id.is_empty())
    }

    pub(in crate::engines) fn has_local_root_fields_state(&self) -> bool {
        self.root
            .as_ref()
            .is_some_and(|root| root.local_fields.is_some())
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
            if !external::common_name_valid(&root.common_name)
                || root.is_external() && !self.has_external_state()
                || root.pkcs8.len() > 4096
                || root.certificate_der.is_empty()
                || root.certificate_der.len() > 64 * 1024
                || root.not_before >= root.not_after
                || root.local_chain.is_none()
                    && root.not_after - root.not_before
                        > if root.local_fields.is_some() {
                            MAX_TTL * 2
                        } else {
                            MAX_TTL + 120
                        }
                || serial_bytes(&root.serial).is_err()
                || !valid_pki_id(&root.issuer_id)
                || !valid_pki_id(&root.key_id)
                || root.issuer_id.is_empty() != root.key_id.is_empty()
            {
                return Err(bad("invalid PKI root state"));
            }
            if let Some(fields) = &root.local_fields {
                fields.validate()?;
                if root.is_external() || root.issuer_id.is_empty() {
                    return Err(bad("invalid local PKI root field ownership"));
                }
            }
            if !root.is_external() {
                root.validate_local_certificate()?;
            }
        }
        self.validate_external_state()?;
        self.validate_local_issuers()?;
        self.validate_profile_local_leaves()?;
        self.validate_local_intermediate(clock)?;
        self.validate_external_consumption(clock)?;
        for (name, role) in &self.roles {
            valid_name(name)?;
            role.validate()?;
        }
        let prefix = format!("{mount}issue/");
        let sign_prefix = format!("{mount}sign/");
        let mut leases = BTreeSet::new();
        for (serial, issued) in &self.issued {
            if (!issued.local_issuer_id.is_empty() && !valid_pki_id(&issued.local_issuer_id))
                || serial_bytes(serial).is_err()
                || !(if issued.role_names_owned {
                    role_names::bounded_subject(&issued.common_name)
                } else {
                    valid_common_name(&issued.common_name)
                })
                || issued.role_names_owned
                    && issued
                        .role_leaf_profile
                        .as_ref()
                        .is_none_or(|evidence| evidence.role_name_policy.is_none())
                || issued.common_name.contains('*') && !issued.wildcard_names
                || issued
                    .owner
                    .validate_scope(namespace, ServiceOwnerProfile::DigestAlphabet)
                    .is_err()
                || issued.owner.batch_claims().is_some_and(|claims| {
                    issued.issued < claims.issued_at() || issued.expires > claims.expires_at()
                })
                || !(if issued.path.starts_with(&prefix) {
                    !issued.path[prefix.len()..].contains('/')
                } else if issued.role_names_owned && issued.path.starts_with(&sign_prefix) {
                    !issued.path[sign_prefix.len()..].is_empty()
                        && !issued.path[sign_prefix.len()..].contains('/')
                } else {
                    issued.path.strip_prefix(mount).is_some_and(|path| {
                        Self::issuer_issue_route(path).is_some()
                            || issued.role_names_owned && Self::issuer_sign_route(path).is_some()
                    })
                })
                || issued.lease_id != format!("{}/{}", issued.path, serial)
                || issued.issued > clock
                || issued.signed_role_time_owned && !issued.role_time_owned
                || issued.role_time_owned && issued.role_leaf_profile.is_none()
                || issued.issuer_not_after_behavior.is_some() && !issued.role_time_owned
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
        self.validate_local_crls(clock)?;
        Ok(())
    }

    // Historical issuer paths remain format-bearing after revocation or expiry.
    // Selection at request time is separate from this closed persisted grammar.
    pub(super) fn has_issuer_path_state(&self, mount: &str) -> bool {
        self.issued.values().any(|issued| {
            issued.path.strip_prefix(mount).is_some_and(|relative| {
                Self::issuer_issue_route(relative).is_some()
                    || Self::issuer_sign_route(relative).is_some()
            })
        })
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
        if changed {
            self.mark_local_crl_dirty();
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
        self.local_revocation_changed(clock)?;
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
        if changed {
            self.mark_local_crl_dirty();
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
        if let Some(response) = self.handle_local_intermediate(method, path, body, now)? {
            return Ok(response);
        }
        if let Some(response) = self.handle_local_crl(method, path, body, now)? {
            return Ok(response);
        }
        if path == "config/cluster" {
            return self.handle_cluster_config(method, body);
        }
        if path == "config/acme" {
            return self.handle_acme_config(method, body);
        }
        if path == "keys"
            && method == "LIST"
            && !self.root.as_ref().is_some_and(RootCa::is_external)
        {
            return self.local_key_list(body);
        }
        if path == "certs" && method == "LIST" {
            return self.certificate_list(body);
        }
        if method == "DELETE"
            && let Some(reference) = path.strip_prefix("issuer/")
            && !reference.contains('/')
            && !reference.is_empty()
        {
            let response = self.local_issuer_delete(reference, body)?;
            self.maintain_local_crl(now)?;
            return Ok(response);
        }
        if path == "config/issuers" {
            return self.local_issuer_config(method, body);
        }
        if matches!(path, "root/generate/internal" | "root/generate/exported") {
            if !write_method(method) {
                return Err(unsupported());
            }
            reject_unknown(
                body,
                &[
                    "common_name",
                    "ttl",
                    "key_type",
                    "key_bits",
                    "format",
                    "private_key_format",
                    "alt_names",
                    "ip_sans",
                    "uri_sans",
                    "exclude_cn_from_sans",
                    "ou",
                    "organization",
                    "country",
                    "locality",
                    "province",
                    "street_address",
                    "postal_code",
                    "serial_number",
                    "not_before_duration",
                    "not_after",
                    "max_path_length",
                    "issuer_name",
                    "key_name",
                ],
            )?;
            let kind = LocalKeyKind::from_body(body)?;
            let output_format = RootOutputFormat::from_body(body)?;
            if matches!(
                body.get("private_key_format"),
                Some(Value::Array(_) | Value::Object(_))
            ) {
                return Err(bad("invalid PKI private key format"));
            }
            let exported = path == "root/generate/exported";
            // Internal generation ignores this field, matching the oracle.
            // The oracle converts only the literal PKCS8 choice. Other scalar
            // values, including an unknown string and null, retain legacy DER.
            let export_pkcs8 = exported
                && matches!(body.get("private_key_format"), Some(Value::String(value)) if value == "pkcs8");
            let common_name = string(body, "common_name")?;
            // A root subject CN is a distinguished-name value, not a DNS SAN.
            if !external::common_name_valid(common_name) {
                return Err(bad("invalid PKI common name"));
            }
            let fields = RootFields::from_body(body, common_name)?;
            self.admit_local_root_names(&fields)?;
            let (not_after, mut warnings) =
                root_fields::root_expiration_capped(body, now, self.max_ttl, self.default_ttl)?;
            let material = LocalPrivateMaterial::generate(kind)?;
            let public = material.public()?;
            let key_identifier = root_fields::subject_key_identifier(&public.spki()?)?;
            let serial = random_serial()?;
            let not_before = now.saturating_sub(fields.backdate);
            let certificate_der = certificate_der_local(
                &material,
                &public,
                CertificateSpec {
                    serial: &serial,
                    issuer_cn: common_name,
                    subject_cn: common_name,
                    issuer_name_der: Some(&fields.subject_der),
                    subject_name_der: Some(&fields.subject_der),
                    public_key: &[],
                    authority_key_id: Some(&key_identifier),
                    not_before: role_time::signed_epoch(not_before)?,
                    not_after,
                    is_ca: true,
                    alt_names: &fields.dns_sans,
                    email_sans: &fields.email_sans,
                    ip_sans: &fields.ip_sans,
                    uri_sans: &fields.uri_sans,
                    exclude_cn_from_sans: fields.exclude_cn,
                    max_path_length: fields.max_path_length,
                    permitted_dns_domains: &[],
                    role_leaf_profile: None,
                },
            )?;
            let issuing_ca = output_format.certificate(&certificate_der);
            let issuer_id = random_pki_id()?;
            let key_id = random_pki_id()?;
            let mut data = json!({
                "certificate": issuing_ca,
                "issuing_ca": issuing_ca,
                "serial_number": serial,
                "expiration": not_after,
                "issuer_id": issuer_id,
                "issuer_name": fields.metadata.as_ref().map_or("", |meta| meta.issuer_name.as_str()),
                "key_id": key_id,
                "key_name": fields.metadata.as_ref().map_or("", |meta| meta.key_name.as_str()),
            });
            if exported {
                let (private_der, label) = material.root_export_der(export_pkcs8)?;
                let private_key = if output_format == RootOutputFormat::Der {
                    Zeroizing::new(BASE64.encode(private_der.as_slice()))
                } else {
                    private_key_pem(label, &private_der)?
                };
                if output_format == RootOutputFormat::PemBundle {
                    // The oracle builds the bundle before converting the
                    // separate private_key field to PKCS8.
                    let (legacy_der, legacy_label) = material.root_export_der(false)?;
                    let legacy_key = private_key_pem(legacy_label, &legacy_der)?;
                    data["certificate"] =
                        Value::String(format!("{}\n{}", legacy_key.as_str(), issuing_ca));
                }
                data["private_key"] = Value::String(private_key.to_string());
                data["private_key_type"] = Value::String(kind.key_type().into());
            }
            let (pkcs8, local_material) = if kind == LocalKeyKind::Ed25519 {
                (material.private_der()?.to_vec(), None)
            } else {
                (Vec::new(), Some(material))
            };
            self.publish_local_root(RootCa {
                leaf_not_after_behavior: None,
                common_name: common_name.into(),
                issuer_id,
                key_id,
                local_fields: fields.metadata.map(Box::new),
                pkcs8,
                local_material,
                local_chain: None,
                certificate_der,
                serial: serial.clone(),
                not_before,
                not_after,
            })?;
            self.rebuild_local_crls(now, false)?;
            // The current local root builder emits no AIA extension. Preserve
            // the observed warning from the actual certificate it just built.
            let mut response = ok(data, true);
            warnings.push("This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information.".into());
            response.body["warnings"] = json!(warnings);
            return Ok(response);
        }
        if path == "root/delete" || path == "root" && method == "DELETE" {
            if method != "DELETE" && !write_method(method) {
                return Err(unsupported());
            }
            reject_unknown(body, &[])?;
            let changed = if self.root.as_ref().is_some_and(RootCa::is_external) {
                self.retire_external_leaf_issuer(now)?;
                self.root.take().is_some()
            } else {
                self.delete_local_roots()?
            };
            self.external.clear_root();
            if self.local_crl.is_some() {
                self.rebuild_local_crls(now, false)?;
            }
            let mut response = ok(Value::Null, changed);
            if path == "root" {
                response.body["warnings"] = json!([
                    "DELETE /root deletes all keys and issuers; prefer the new DELETE /key/:key_ref and DELETE /issuer/:issuer_ref for finer granularity, unless removal of all keys and issuers is desired."
                ]);
            }
            return Ok(response);
        }
        if let Some(route) = self.public_read_route(method, path) {
            return self.handle_public_read(route, body, now);
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
                    let Some(role) = self.roles.get(name) else {
                        return Ok(EngineResponse {
                            status: 404,
                            body: json!({"errors":[]}),
                            mutated: false,
                        });
                    };
                    return Ok(ok(role.descriptor(), false));
                }
                "DELETE" => {
                    reject_unknown(body, &[])?;
                    return Ok(empty(self.roles.remove(name).is_some()));
                }
                "POST" | "PUT" | "PATCH" => {
                    reject_unknown(
                        body,
                        &[
                            "allowed_domains",
                            "allow_any_name",
                            "allow_bare_domains",
                            "allow_wildcard_certificates",
                            "allow_subdomains",
                            "allow_ip_sans",
                            "max_ttl",
                            "ttl",
                            "not_before_duration",
                            "not_before",
                            "not_before_bound",
                            "not_after",
                            "not_after_bound",
                            "generate_lease",
                            "key_type",
                            "key_bits",
                            "issuer_ref",
                            "server_flag",
                            "client_flag",
                            "code_signing_flag",
                            "email_protection_flag",
                            "key_usage",
                            "ext_key_usage",
                            "ext_key_usage_oids",
                            "country",
                            "province",
                            "locality",
                            "street_address",
                            "postal_code",
                            "organization",
                            "ou",
                            "basic_constraints_valid_for_non_ca",
                            "allow_token_displayname",
                            "allow_localhost",
                            "require_cn",
                            "enforce_hostnames",
                            "cn_validations",
                            "allow_glob_domains",
                            "allowed_ip_sans_cidr",
                            "allowed_uri_sans",
                            "no_store",
                            "allowed_domains_template",
                            "allowed_uri_sans_template",
                            "allow_globs_in_identity_templates",
                            "signature_bits",
                            "use_pss",
                            "use_csr_common_name",
                            "use_csr_sans",
                            "allowed_serial_numbers",
                            "allowed_user_ids",
                            "allowed_other_sans",
                            "policy_identifiers",
                        ],
                    )?;
                    let role_result = if method == "PATCH" {
                        let Some(previous) = self.roles.get(name) else {
                            return Err(bad("Unable to fetch role entry to patch"));
                        };
                        Role::from_patch(previous, body)
                    } else {
                        Role::from_body(body)
                    };
                    let role = match role_result {
                        Ok(role) => role,
                        Err(cause) => {
                            return Ok(EngineResponse {
                                status: cause.status,
                                body: json!({"errors":[cause.message]}),
                                mutated: false,
                            });
                        }
                    };
                    if !self.roles.contains_key(name) && self.roles.len() >= MAX_ROLES {
                        return Err(error(507, "PKI role capacity exhausted"));
                    }
                    let changed = self.roles.get(name) != Some(&role);
                    let missing_default_issuer =
                        role.issuer_ref.is_empty() && self.selected_issuer("default").is_err();
                    let no_store_lease_warning = role
                        .role_name_policy
                        .as_ref()
                        .is_some_and(|policy| policy.no_store)
                        && role_optional_bool(body, "generate_lease")?.unwrap_or(false);
                    let generated_lease = role.generate_lease;
                    let response = role.descriptor();
                    self.roles.insert(name.into(), role);
                    let mut result = ok(response, changed);
                    let mut warnings = Vec::new();
                    if body.get("allow_token_displayname").is_some() {
                        warnings.push("Endpoint ignored these unrecognized parameters: [allow_token_displayname]");
                    }
                    if missing_default_issuer {
                        warnings.push(
                            "Issuing Certificate was set to default, but no default issuing certificate (configurable at /config/issuers) is currently set"
                        );
                    }
                    if no_store_lease_warning {
                        warnings.push("mutually exclusive values no_store=true and generate_lease=true were both specified; no_store=true takes priority");
                    }
                    if generated_lease {
                        warnings.push(
                            "it is encouraged to disable generate_lease and rely on PKI's native capabilities when possible; this option can cause instance-wide issues with large numbers of issued certificates"
                        );
                    }
                    if !warnings.is_empty() {
                        result.body["warnings"] = json!(warnings);
                    }
                    return Ok(result);
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
            if let Some(response) = self.revoke_signed_ca(&serial, now)? {
                return Ok(response);
            }
            let cert = self.issued.get(&serial).ok_or_else(not_found)?;
            if cert.revoked_at.is_none()
                && cert.expires < now.saturating_add(2)
                && !self.local_expired_revocation_allowed()
            {
                return Ok(EngineResponse {
                    status: 200,
                    body: json!({"warnings":["certificate already expired; refusing to add to CRL"]}),
                    mutated: false,
                });
            }
            let cert = self.issued.get_mut(&serial).ok_or_else(not_found)?;
            let changed = cert.revoked_at.is_none();
            if changed {
                cert.revoked_at = Some(now.max(cert.issued));
            }
            let at = cert.revoked_at.unwrap_or(0);
            if changed {
                self.local_revocation_changed(now)?;
            }
            return Ok(ok(
                json!({"revocation_time":at,
                    "revocation_time_rfc3339":timestamp(at),"state":"revoked"}),
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
            self.reconcile_external_leaf_projections();
            if before != self.issued.len() && self.local_crl.is_some() {
                self.rebuild_local_crls(now, false)?;
            }
            return Ok(empty(before != self.issued.len()));
        }
        Err(error(404, "PKI path is not implemented"))
    }

    #[cfg(test)]
    pub(super) fn fixture_insert_historical_role(
        &mut self,
        name: &str,
        value: &Value,
    ) -> Result<()> {
        valid_name(name)?;
        let role: Role = serde_json::from_value(value.clone())
            .map_err(|_| bad("historical typed role fixture"))?;
        if role.role_time_policy.is_some()
            || role.max_ttl == 0
            || role.role_leaf_profile.is_some()
            || role.allow_bare_domains.is_some()
            || role.allow_wildcard_certificates.is_some()
            || role.allow_any_name
        {
            return Err(bad("historical fixture cannot install a new role owner"));
        }
        role.validate()?;
        self.roles.insert(name.to_owned(), role);
        Ok(())
    }

    // Original pre-name profile role wire contract, created before any new
    // name owner publication. Never create a current role and strip its owner.
    // The only later migration in these tests is an actual production PATCH.
    #[cfg(test)]
    pub(super) fn fixture_insert_pre_names_profile_role(
        &mut self,
        name: &str,
        value: &Value,
    ) -> Result<()> {
        valid_name(name)?;
        if !self.roles.is_empty()
            || !self.issued.is_empty()
            || self.has_role_names_state()
            || self.has_role_time_state()
            || self.has_external_state()
        {
            return Err(bad(
                "pre-name profile fixture requires an empty actual local role graph",
            ));
        }
        let role: Role = serde_json::from_value(value.clone())
            .map_err(|_| bad("original pre-name profile role wire contract"))?;
        if role.role_name_policy.is_some()
            || role.role_time_policy.is_some()
            || role.role_leaf_profile.as_ref() != Some(&RoleLeafProfile::default())
            || role.allow_bare_domains != Some(false)
            || role.allow_wildcard_certificates != Some(true)
            || role.allow_any_name
            || !role.allow_subdomains
            || !role.allow_ip_sans
            || role.max_ttl != 3600
            || role.generate_lease
            || role.local_key_kind != Some(LocalKeyKind::Ec256)
            || !role.issuer_ref.is_empty()
            || role.allowed_domains != BTreeSet::from(["example.test".to_owned()])
        {
            return Err(bad(
                "pre-name fixture requires the complete original profile88 role",
            ));
        }
        role.validate()?;
        self.roles.insert(name.to_owned(), role);
        Ok(())
    }

    // A typed schema85 role-only predecessor input, before any88 publication.
    // It owns the original85 base/wildcard fields but no later leaf profile.
    #[cfg(test)]
    pub(super) fn fixture_promote_historical_role_to85(&mut self, name: &str) -> Result<()> {
        if !self.issued.is_empty()
            || self.has_role_leaf_profile_state()
            || self.has_role_time_state()
        {
            return Err(bad("schema85 role fixture cannot strip signed evidence"));
        }
        let role = self.roles.get_mut(name).ok_or_else(not_found)?;
        if role.role_leaf_profile.is_some()
            || role.allow_any_name
            || role.allow_bare_domains.is_some()
            || role.allow_wildcard_certificates.is_some()
        {
            return Err(bad("schema85 role fixture requires the original None role"));
        }
        role.allow_bare_domains = Some(false);
        role.allow_wildcard_certificates = Some(true);
        Ok(())
    }

    // Test-only historical producer input: preserve the generated Ed25519
    // private key and actual root DER, omit only later optional owner fields.
    // This never downgrades a running Service or accepts external ownership.
    #[cfg(test)]
    pub(super) fn fixture_prepare_historical_local_root(&mut self) -> Result<()> {
        if !self.roles.is_empty()
            || !self.issued.is_empty()
            || self.local_issuers.is_some()
            || self.local_intermediate.is_some()
            || self.has_external_state()
        {
            return Err(bad(
                "historical local root fixture requires an empty local graph",
            ));
        }
        let root = self.root.as_mut().ok_or_else(not_found)?;
        if root.local_material.is_some()
            || root.pkcs8.is_empty()
            || root.local_fields.is_some()
            || root.local_chain.is_some()
        {
            return Err(bad(
                "historical local root fixture requires original Ed25519 shape",
            ));
        }
        root.issuer_id.clear();
        root.key_id.clear();
        self.local_crl = None;
        Ok(())
    }

    // Produce real historical None DER under the actual owned local signer.
    // New production issuance always captures Some; this private test producer
    // exists to prove that old signed evidence survives the actual migration.
    #[cfg(test)]
    pub(super) fn fixture_issue_historical_local_leaf(
        &mut self,
        mount: &str,
        body: &Value,
        owner: &LeaseOwner,
        now: u64,
    ) -> Result<EngineResponse> {
        let role = self.roles.get("historical").ok_or_else(not_found)?;
        if role.role_time_policy.is_some()
            || role.max_ttl == 0
            || role.role_leaf_profile.is_some()
            || role.allow_bare_domains.is_some()
            || role.allow_wildcard_certificates.is_some()
            || role.allow_any_name
            || self.has_role_leaf_profile_state()
            || self.has_external_state()
            || owner.batch_claims().is_some()
        {
            return Err(bad(
                "historical leaf fixture requires original local role and service owner",
            ));
        }
        let mut prepared = self.prepare_leaf(mount, "historical", body, owner, None, now)?;
        prepared.role_leaf_profile = None;
        let root = self.selected_issuer("default")?;
        let root_pair = root.local_key()?;
        let leaf = LocalPrivateMaterial::generate(prepared.local_key_kind)?;
        let leaf_public = leaf.public()?;
        let issuer_name = root_fields::certificate_subject(&root.certificate_der)?;
        let authority_key_id = root_fields::certificate_key_identifier(&root.certificate_der)?;
        let certificate = certificate_der_local(
            &root_pair,
            &leaf_public,
            CertificateSpec {
                serial: &prepared.serial,
                issuer_cn: &root.common_name,
                subject_cn: &prepared.common_name,
                issuer_name_der: Some(&issuer_name),
                subject_name_der: None,
                public_key: &[],
                authority_key_id: authority_key_id.as_deref(),
                not_before: prepared.not_before,
                not_after: prepared.expires,
                is_ca: false,
                alt_names: &prepared.alt_names,
                email_sans: &[],
                ip_sans: &prepared.ip_sans,
                uri_sans: &[],
                exclude_cn_from_sans: false,
                max_path_length: None,
                permitted_dns_domains: &[],
                role_leaf_profile: None,
            },
        )?;
        let private = leaf.private_der()?;
        self.publish_leaf(prepared, certificate, &private, &leaf_public, false)
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
        let allowed = [
            "enabled",
            "allowed_issuers",
            "allowed_roles",
            "allow_role_ext_key_usage",
            "default_directory_policy",
            "dns_resolver",
            "eab_policy",
        ];
        let object = body
            .as_object()
            .ok_or_else(|| bad("request body must be an object"))?;
        let unknown = object
            .keys()
            .filter(|key| !allowed.contains(&key.as_str()))
            .cloned()
            .collect::<Vec<_>>();
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
        if unknown.is_empty() {
            Ok(ok(self.acme.descriptor(), changed))
        } else {
            Ok(EngineResponse {
                status: 200,
                body: json!({
                    "data": self.acme.descriptor(),
                    "warnings": [format!(
                        "Endpoint ignored these unrecognized parameters: [{}]",
                        unknown.join(", ")
                    )],
                }),
                mutated: changed,
            })
        }
    }

    #[cfg(test)]
    fn prepare_leaf(
        &self,
        mount: &str,
        role_name: &str,
        body: &Value,
        owner: &LeaseOwner,
        owner_expires: Option<u64>,
        now: u64,
    ) -> Result<LeafTemplate> {
        self.prepare_leaf_route(
            IssuanceRoute {
                mount,
                role: role_name,
                explicit_issuer: None,
                sign: false,
            },
            body,
            LeafAuthority {
                owner,
                owner_expires,
                precise_owner_expires: None,
                time: crate::auth::AuthorityTime::Coarse(now),
                clock: None,
                identity_templates: None,
            },
        )
    }

    fn prepare_leaf_route(
        &self,
        route: IssuanceRoute<'_>,
        body: &Value,
        authority: LeafAuthority<'_>,
    ) -> Result<LeafTemplate> {
        let LeafAuthority {
            owner,
            owner_expires,
            precise_owner_expires,
            time,
            clock,
            identity_templates,
        } = authority;
        let time = precise_time::observe(time, clock, time.seconds())?;
        let now = time.seconds();
        if precise_owner_expires.is_some_and(|end| time.exact().is_none_or(|at| at > end)) {
            return Err(error(403, "issuer no longer has a live PKI lease window"));
        }
        reject_unknown(
            body,
            &[
                "csr",
                "exclude_cn_from_sans",
                "common_name",
                "alt_names",
                "ip_sans",
                "uri_sans",
                "serial_number",
                "user_ids",
                "other_sans",
                "ttl",
                "not_before",
                "not_after",
            ],
        )?;
        let mut role = self
            .roles
            .get(route.role)
            .ok_or_else(|| bad(&format!("unknown role: {}", route.role)))?
            .clone();
        let declared_uri_patterns = role
            .role_name_policy
            .as_ref()
            .is_some_and(|policy| !policy.allowed_uri_sans.is_empty());
        role.resolve_identity_templates(identity_templates);
        let csr = if route.sign {
            Some(role_csr::CsrInput::from_request(&role, body)?)
        } else {
            if body.get("csr").is_some() {
                return Err(bad("csr is only supported by the sign route"));
            }
            None
        };
        let body = csr.as_ref().map_or(body, |csr| &csr.body);
        let reference = route.explicit_issuer.unwrap_or({
            if role.issuer_ref.is_empty() {
                "default"
            } else {
                role.issuer_ref.as_str()
            }
        });
        let root = self.selected_issuer(reference)?;
        if now >= root.not_after {
            return Err(error(503, "PKI root has expired"));
        }
        let common_name = match body.get("common_name") {
            None | Some(Value::Null) => "",
            Some(Value::String(value)) => value,
            _ => return Err(bad("common_name must be a string")),
        };
        let names = role.role_name_policy.as_ref();
        if common_name.is_empty() && names.is_none_or(|policy| policy.require_cn) {
            return Err(bad(
                r#"the common_name field is required, or must be provided in a CSR with "use_csr_common_name" set to true, unless "require_cn" is set to false"#,
            ));
        }
        if !common_name.is_empty()
            && !names.map_or_else(
                || valid_common_name(common_name) && role.allows(common_name),
                |policy| policy.allows_common_name(&role, common_name),
            )
        {
            return Err(bad(&format!(
                "common name {common_name} not allowed by this role"
            )));
        }
        let raw_alt_names = string_list(body.get("alt_names"))?;
        if raw_alt_names.len() > 32 {
            return Err(bad("PKI subject alternative name capacity exceeded"));
        }
        let mut email_sans = Vec::new();
        let mut alt_names = Vec::new();
        for name in raw_alt_names {
            if names.is_some() && name.contains('@') {
                email_sans.push(name);
            } else if (names.is_some() && valid_common_name(&name))
                || (names.is_none() && (!name.contains('*') || wildcard_dns_san(&name)))
            {
                alt_names.push(name);
            }
        }
        for name in alt_names.iter().chain(&email_sans) {
            if !names.map_or_else(
                || valid_common_name(name) && role.allows(name),
                |policy| policy.allows_name(&role, name),
            ) {
                return Err(bad(&format!(
                    "{} {name} not allowed by this role",
                    if name.contains('@') {
                        "email address"
                    } else {
                        "subject alternate name"
                    }
                )));
            }
        }
        if valid_common_name(common_name)
            && names.is_some_and(|policy| !policy.allows_name(&role, common_name))
        {
            return Err(bad(&format!(
                "subject alternate name {common_name} not allowed by this role"
            )));
        }
        let exclude_cn_from_sans = names.is_some()
            && (!valid_common_name(common_name)
                || role_optional_bool(body, "exclude_cn_from_sans")?.unwrap_or(false));
        if names.is_some() && common_name.contains('@') && !exclude_cn_from_sans {
            email_sans.push(common_name.into());
        }
        let uri_sans = string_list(body.get("uri_sans"))?;
        if uri_sans.len() > 32 {
            return Err(bad("PKI URI subject alternative name capacity exceeded"));
        }
        let ip_sans = ip_list(body.get("ip_sans"))?;
        if ip_sans.len() > 32 {
            return Err(bad("PKI IP subject alternative name capacity exceeded"));
        }
        let sans_from_csr = csr.is_some() && names.is_some_and(|policy| policy.use_csr_sans);
        if !role.allow_ip_sans && !ip_sans.is_empty() {
            let source = if sans_from_csr { "CSR" } else { "the API" };
            return Err(bad(&format!(
                "IP Subject Alternative Names are not allowed in this role, but was provided via {source}",
            )));
        }
        if let Some(policy) = names {
            policy.validate_sans_from(&ip_sans, &uri_sans, sans_from_csr, declared_uri_patterns)?;
        } else if !uri_sans.is_empty() {
            return Err(bad(
                "URI Subject Alternative Names are not allowed in this role, but were provided via the API",
            ));
        }
        if !names.is_some_and(|policy| policy.no_store) && self.issued.len() >= MAX_ISSUED {
            return Err(error(507, "PKI issued-certificate capacity exhausted"));
        }
        // CSR verification and identity rendering may consume real elapsed time.
        // Reobserve the original ingress clock immediately at the time producer.
        let time = precise_time::observe(time, clock, now)?;
        let now = time.seconds();
        let resolved = role.role_time_policy.clone().unwrap_or_default().resolve(
            body,
            role.max_ttl,
            self.default_ttl,
            self.max_ttl,
            time,
        )?;
        let not_after = root
            .leaf_not_after_behavior
            .unwrap_or_default()
            .apply(resolved.not_after, root.not_after)?;
        role.role_time_policy
            .clone()
            .unwrap_or_default()
            .validate_final_not_after(not_after)?;
        let owner_boundary = precise_owner_expires
            .map(crate::auth::Timestamp::seconds)
            .or(owner_expires);
        let not_after_seconds = not_after.positive_seconds()?;
        let expires = not_after_seconds.min(owner_boundary.unwrap_or(u64::MAX));
        if expires <= now {
            return Err(error(403, "issuer no longer has a live PKI lease window"));
        }
        let private_after = if owner_boundary.is_some_and(|end| end < not_after_seconds) {
            PkiInstant::whole(expires)?
        } else {
            not_after
        };
        if resolved.not_before > private_after {
            return Err(bad(&format!(
                "The certificate's Not Before ({}) is later than the certificate's Not After ({})",
                resolved.not_before.render(),
                private_after.render()
            )));
        }
        let serial = random_serial()?;
        let operation = if route.sign { "sign" } else { "issue" };
        let path = if let Some(reference) = route.explicit_issuer {
            format!(
                "{}issuer/{reference}/{operation}/{}",
                route.mount, route.role
            )
        } else {
            format!("{}{operation}/{}", route.mount, route.role)
        };
        let lease_id = format!("{path}/{serial}");
        if self.issued.contains_key(&serial) || self.issued.values().any(|v| v.lease_id == lease_id)
        {
            return Err(error(503, "PKI serial collision"));
        }
        Ok(LeafTemplate {
            role_name_policy: role.role_name_policy.clone(),
            no_store: names.is_some_and(|policy| policy.no_store),
            exclude_cn_from_sans,
            email_sans,
            uri_sans,
            signed_role_time_owned: resolved.not_before.seconds() < 0,
            issuer_not_after_behavior: root.leaf_not_after_behavior,
            role_time_owned: root.leaf_not_after_behavior.is_some()
                || role.role_time_policy.is_some()
                || role.max_ttl == 0
                || body.get("not_before").is_some()
                || body.get("not_after").is_some(),
            warnings: {
                let mut warnings = csr
                    .as_ref()
                    .map_or_else(Vec::new, |csr| csr.warnings.clone());
                warnings.extend(resolved.warnings);
                warnings
            },
            role_leaf_profile: Some(if let Some(policy) = names {
                policy.capture_subject(body, role.effective_leaf_profile())?
            } else {
                if ["serial_number", "user_ids", "other_sans"]
                    .iter()
                    .any(|field| body.get(*field).is_some())
                {
                    return Err(bad("historical role has no subject attribute policy"));
                }
                role.effective_leaf_profile()
            }),
            local_issuer_id: if !root.is_external() {
                root.issuer_id.clone()
            } else {
                String::new()
            },
            serial,
            path,
            lease_id,
            owner: owner.clone(),
            owner_expires,
            leased: role.generate_lease,
            common_name: common_name.into(),
            local_key_kind: csr.as_ref().map_or(
                role.local_key_kind.unwrap_or(LocalKeyKind::Ed25519),
                |csr| csr.public.kind(),
            ),
            csr_public_key: csr.map(|csr| csr.public),
            alt_names,
            ip_sans,
            issued: now,
            not_before: resolved.not_before.seconds(),
            publication_time: time,
            publication_clock: clock,
            precise_owner_expires,
            expires,
        })
    }

    #[cfg(test)]
    pub(super) fn issue(
        &mut self,
        mount: &str,
        role_name: &str,
        body: &Value,
        owner: &LeaseOwner,
        owner_expires: Option<u64>,
        now: u64,
    ) -> Result<EngineResponse> {
        self.issue_owned_route(
            IssuanceRoute {
                mount,
                role: role_name,
                explicit_issuer: None,
                sign: false,
            },
            body,
            LeafAuthority {
                owner,
                owner_expires,
                precise_owner_expires: None,
                time: crate::auth::AuthorityTime::Coarse(now),
                clock: None,
                identity_templates: None,
            },
        )
    }

    pub(super) fn issue_route(
        &mut self,
        mount: &str,
        relative: &str,
        body: &Value,
        authority: LeafAuthority<'_>,
    ) -> Result<EngineResponse> {
        let route = if let Some(role) = relative.strip_prefix("issue/") {
            IssuanceRoute {
                mount,
                role,
                explicit_issuer: None,
                sign: false,
            }
        } else if let Some(role) = relative.strip_prefix("sign/") {
            IssuanceRoute {
                mount,
                role,
                explicit_issuer: None,
                sign: true,
            }
        } else if let Some((reference, role)) = Self::issuer_issue_route(relative) {
            IssuanceRoute {
                mount,
                role,
                explicit_issuer: Some(reference),
                sign: false,
            }
        } else if let Some((reference, role)) = Self::issuer_sign_route(relative) {
            IssuanceRoute {
                mount,
                role,
                explicit_issuer: Some(reference),
                sign: true,
            }
        } else {
            return Err(not_found());
        };
        if route.role.is_empty() || route.role.contains('/') {
            return Err(not_found());
        }
        self.issue_owned_route(route, body, authority)
    }

    fn issue_owned_route(
        &mut self,
        route: IssuanceRoute<'_>,
        body: &Value,
        authority: LeafAuthority<'_>,
    ) -> Result<EngineResponse> {
        if self.profile_route_needs_identity(&route)? {
            // Identity promotion and issuance publish together. Any subsequent
            // error drops this owned clone, preserving direct-call atomicity.
            let mut candidate = self.clone();
            candidate.promote_profile_root_identity(&route)?;
            let response = candidate.issue_owned_route(route, body, authority)?;
            *self = candidate;
            return Ok(response);
        }
        let prepared = self.prepare_leaf_route(route, body, authority)?;
        let root = self.selected_issuer(if prepared.local_issuer_id.is_empty() {
            "default"
        } else {
            &prepared.local_issuer_id
        })?;
        if root.is_external() {
            return Err(error(
                501,
                "external PKI leaf issuance requires a qualified signing lane",
            ));
        }
        let (leaf_public, leaf_pkcs8) = if let Some(public) = &prepared.csr_public_key {
            (public.clone(), Zeroizing::new(Vec::new()))
        } else {
            let leaf = LocalPrivateMaterial::generate(prepared.local_key_kind)?;
            (leaf.public()?, leaf.private_der()?)
        };
        let root_pair = root.local_key()?;
        let issuer_name_der = root_fields::certificate_subject(&root.certificate_der)?;
        let authority_key_id = root_fields::certificate_key_identifier(&root.certificate_der)?;
        let certificate_der = certificate_der_local_with_policy(
            &root_pair,
            &leaf_public,
            CertificateSpec {
                serial: &prepared.serial,
                issuer_cn: &root.common_name,
                subject_cn: &prepared.common_name,
                issuer_name_der: Some(&issuer_name_der),
                subject_name_der: None,
                public_key: &[],
                authority_key_id: authority_key_id.as_deref(),
                not_before: prepared.not_before,
                not_after: prepared.expires,
                is_ca: false,
                alt_names: &prepared.alt_names,
                email_sans: &prepared.email_sans,
                ip_sans: &prepared.ip_sans,
                uri_sans: &prepared.uri_sans,
                exclude_cn_from_sans: prepared.exclude_cn_from_sans,
                max_path_length: None,
                permitted_dns_domains: &[],
                role_leaf_profile: prepared.role_leaf_profile.as_ref(),
            },
            prepared.role_name_policy.as_ref(),
        )?;
        self.publish_leaf(prepared, certificate_der, &leaf_pkcs8, &leaf_public, false)
    }

    fn publish_leaf(
        &mut self,
        prepared: LeafTemplate,
        certificate_der: Vec<u8>,
        leaf_pkcs8: &[u8],
        leaf_public: &LocalPublicKey,
        external: bool,
    ) -> Result<EngineResponse> {
        prepared.validate_publication(prepared.issued)?;
        let root = self.selected_issuer(if prepared.local_issuer_id.is_empty() {
            "default"
        } else {
            &prepared.local_issuer_id
        })?;
        if self.issued.contains_key(&prepared.serial) || self.issued.len() >= MAX_ISSUED {
            return Err(error(503, "PKI issuance state changed"));
        }
        if let Some(profile) = &prepared.role_leaf_profile {
            profile.validate_created_leaf_der(&certificate_der)?;
        }
        let certificate = public::stored_pem("CERTIFICATE", &certificate_der);
        let issuing_ca = public::stored_pem("CERTIFICATE", &root.certificate_der);
        let ttl = prepared.expires.saturating_sub(prepared.issued);
        let mut data = json!({"certificate":certificate, "issuing_ca":issuing_ca,
            "serial_number":prepared.serial, "expiration":prepared.expires});
        if prepared.csr_public_key.is_none() {
            let mut private_key =
                LocalPrivateMaterial::private_pem(prepared.local_key_kind, leaf_pkcs8, external)?;
            if private_key.ends_with('\n') {
                private_key.pop();
            }
            data["private_key"] = json!(private_key.as_str());
            data["private_key_type"] = json!(prepared.local_key_kind.key_type());
        } else if !leaf_pkcs8.is_empty() || prepared.csr_public_key.as_ref() != Some(leaf_public) {
            return Err(bad("CSR signed leaf has an unexpected private key owner"));
        }
        data["serial_number"] = json!(external::formatted_serial(&prepared.serial));
        data["ca_chain"] = if external {
            json!([issuing_ca])
        } else {
            json!(
                root.local_ca_chain_pem()
                    .into_iter()
                    .map(|mut pem| {
                        if pem.ends_with('\n') {
                            pem.pop();
                        }
                        pem
                    })
                    .collect::<Vec<_>>()
            )
        };
        data["not_before"] = json!(prepared.not_before);
        let mut response = EngineResponse {
            status: 200,
            body: json!({"request_id":"", "lease_id":if prepared.leased {prepared.lease_id.clone()} else {String::new()},
                "renewable":false,"lease_duration":if prepared.leased {ttl} else {0},"data":data}),
            mutated: true,
        };
        if !prepared.warnings.is_empty() {
            response.body["warnings"] = json!(prepared.warnings);
        }
        if prepared.no_store {
            response.mutated = false;
            return Ok(response);
        }
        let role_leaf_profile = LeafProfilePublicEvidence::capture(&prepared, leaf_public);
        self.issued.insert(
            prepared.serial.clone(),
            IssuedCertificate {
                role_names_owned: prepared.role_name_policy.is_some(),
                issuer_not_after_behavior: prepared.issuer_not_after_behavior,
                signed_role_time_owned: prepared.signed_role_time_owned,
                role_time_owned: prepared.role_time_owned,
                role_leaf_profile,
                local_issuer_id: prepared.local_issuer_id,
                external_issuer_owner: None,
                leased: prepared.leased,
                lease_id: prepared.lease_id,
                owner: prepared.owner,
                path: prepared.path,
                issued: prepared.issued,
                expires: prepared.expires,
                revoked_at: None,
                wildcard_names: prepared.common_name.contains('*')
                    || prepared.alt_names.iter().any(|name| name.contains('*')),
                common_name: prepared.common_name,
                certificate_der,
            },
        );
        Ok(response)
    }

    fn crl_der(&self, root: &RootCa, _now: u64) -> Result<Vec<u8>> {
        if root.is_external() {
            return Err(error(
                501,
                "external PKI CRL requires a qualified signing lane",
            ));
        }
        Ok(self.cached_local_crl(root, false)?.to_vec())
    }
}

// Only the public role input uses the framework's weak boolean conversion.
// Durable Role deserialization still requires actual booleans; request text
// is never retained as an authority marker or copied into the stored owner.
fn role_optional_bool(body: &Value, name: &str) -> Result<Option<bool>> {
    let Some(value) = body.get(name) else {
        return Ok(None);
    };
    let detail = match value {
        Value::Bool(value) => return Ok(Some(*value)),
        Value::Null => return Ok(Some(false)),
        Value::String(value) => match value.as_str() {
            "1" | "t" | "T" | "TRUE" | "true" | "True" => return Ok(Some(true)),
            "" | "0" | "f" | "F" | "FALSE" | "false" | "False" => return Ok(Some(false)),
            _ => "cannot parse value as 'bool': strconv.ParseBool: invalid syntax",
        },
        Value::Number(value) => match value.to_string().as_str() {
            "1" => return Ok(Some(true)),
            "0" => return Ok(Some(false)),
            _ => "cannot parse value as 'bool': strconv.ParseBool: invalid syntax",
        },
        Value::Array(_) => "expected type 'bool', got unconvertible type '[]interface {}'",
        Value::Object(_) => {
            "expected type 'bool', got unconvertible type 'map[string]interface {}'"
        }
    };
    Err(bad(&format!(
        "Field validation failed: error converting input for field \"{name}\": '' {detail}"
    )))
}

impl Role {
    fn effective_leaf_profile(&self) -> RoleLeafProfile {
        self.role_leaf_profile.clone().unwrap_or_default()
    }
    fn from_patch(previous: &Self, patch: &Value) -> Result<Self> {
        let mut merged = SecretJson(previous.descriptor());
        let output = merged
            .as_object_mut()
            .ok_or_else(|| bad("invalid stored PKI role"))?;
        let patch = patch
            .as_object()
            .ok_or_else(|| bad("request body must be an object"))?;
        for (name, value) in patch {
            output.insert(name.clone(), value.clone());
        }
        let mut role = Self::from_body(&merged)?;
        if previous.role_time_policy.is_none()
            && !role_time::ROLE_TIME_FIELDS
                .iter()
                .any(|name| patch.get(*name).is_some())
        {
            role.role_time_policy = None;
        }
        if previous.role_name_policy.is_none()
            && !role_names::ROLE_NAME_FIELDS
                .iter()
                .any(|name| patch.get(*name).is_some())
        {
            role.role_name_policy = None;
        }
        Ok(role)
    }
    fn from_body(body: &Value) -> Result<Self> {
        let allow_any_name = role_optional_bool(body, "allow_any_name")?.unwrap_or(false);
        let names = RoleNamePolicy::from_body(body)?;
        let allowed_domains = string_list(body.get("allowed_domains"))?;
        if allowed_domains.len() > 64
            || allowed_domains.iter().any(|v| !names.valid_domain_entry(v))
        {
            return Err(bad("allowed_domains must contain 1..=64 DNS domains"));
        }
        let max_ttl = role_time::role_duration(body, "max_ttl", 0)?;
        let time_policy = RoleTimePolicy::from_body(body, max_ttl)?;
        let role = Self {
            role_name_policy: Some(names.clone()),
            role_time_policy: role_time::ROLE_TIME_FIELDS
                .iter()
                .any(|name| body.get(*name).is_some())
                .then_some(time_policy),
            role_leaf_profile: Some(RoleLeafProfile::from_body(body)?),
            issuer_ref: match body.get("issuer_ref") {
                None => String::new(),
                Some(Value::String(value)) if value == "default" => String::new(),
                Some(Value::String(value))
                    if !value.is_empty()
                        && value.len() <= 128
                        && !value.contains('/')
                        && !value.chars().any(char::is_control) =>
                {
                    value.clone()
                }
                _ => return Err(bad("invalid PKI role issuer reference")),
            },
            allowed_domains: allowed_domains.into_iter().collect(),
            allow_any_name,
            allow_bare_domains: Some(
                role_optional_bool(body, "allow_bare_domains")?.unwrap_or(false),
            ),
            allow_wildcard_certificates: Some(
                role_optional_bool(body, "allow_wildcard_certificates")?.unwrap_or(true),
            ),
            allow_subdomains: role_optional_bool(body, "allow_subdomains")?.unwrap_or(false),
            allow_ip_sans: role_optional_bool(body, "allow_ip_sans")?.unwrap_or(true),
            max_ttl,
            generate_lease: !names.no_store
                && role_optional_bool(body, "generate_lease")?.unwrap_or(false),
            local_key_kind: match LocalKeyKind::from_body(body)? {
                LocalKeyKind::Ed25519 => None,
                kind => Some(kind),
            },
        };
        role.validate()?;
        Ok(role)
    }
    fn validate(&self) -> Result<()> {
        if let Some(names) = &self.role_name_policy {
            names.validate()?;
        }
        if let Some(profile) = &self.role_leaf_profile {
            profile.validate_role_oid_strings()?;
            if profile.leaf_subject_evidence.is_some() {
                return Err(bad("role cannot carry captured leaf subject evidence"));
            }
        }
        if let Some(policy) = &self.role_time_policy {
            policy.validate(self.max_ttl)?;
        }
        if self.issuer_ref.len() > 128
            || self.issuer_ref.contains('/')
            || self.issuer_ref.chars().any(char::is_control)
            || self.local_key_kind == Some(LocalKeyKind::Ed25519)
            || self.role_name_policy.is_none()
                && !self.allow_any_name
                && self.allowed_domains.is_empty()
            || self.allowed_domains.len() > 64
            || self.allowed_domains.iter().any(|v| {
                !self
                    .role_name_policy
                    .as_ref()
                    .map_or_else(|| valid_domain(v), |policy| policy.valid_domain_entry(v))
            })
            || self.max_ttl > MAX_TTL
        {
            return Err(bad("invalid PKI role"));
        }
        Ok(())
    }
    fn allows(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        let wildcard = wildcard_name(&name);
        if name.contains('*')
            && (self.allow_wildcard_certificates != Some(true) || wildcard.is_none())
        {
            return false;
        }
        self.allow_any_name
            || self.allowed_domains.iter().any(|domain| {
                let domain = domain.to_ascii_lowercase();
                self.allow_bare_domains.unwrap_or(true) && name == domain
                    || self.allow_subdomains
                        && (name.ends_with(&format!(".{domain}"))
                            || wildcard
                                .is_some_and(|(_, reduced)| reduced.eq_ignore_ascii_case(&domain)))
            })
    }
    fn descriptor(&self) -> Value {
        let mut descriptor = json!({
            "issuer_ref": if self.issuer_ref.is_empty() {"default"} else {self.issuer_ref.as_str()},
            "allowed_domains": self.allowed_domains,
            "allow_any_name": self.allow_any_name,
            "allow_bare_domains": self.allow_bare_domains.unwrap_or(true),
            "allow_wildcard_certificates": self.allow_wildcard_certificates.unwrap_or(false),
            "allow_subdomains": self.allow_subdomains,
            "allow_ip_sans": self.allow_ip_sans,
            "max_ttl": self.max_ttl,
            "generate_lease": self.generate_lease,
            "key_type": "ed25519",
        });
        if let Some(kind) = self.local_key_kind {
            descriptor["key_type"] = json!(kind.key_type());
            descriptor["key_bits"] = json!(kind.bits());
        }
        {
            let profile = self.effective_leaf_profile();
            descriptor["allow_token_displayname"] = json!(false);
            if let Some(fields) = profile.descriptor_fields().as_object() {
                for (name, value) in fields {
                    descriptor[name] = value.clone();
                }
            }
        }
        if let Some(fields) = self
            .role_time_policy
            .clone()
            .unwrap_or_default()
            .descriptor()
            .as_object()
        {
            for (name, value) in fields {
                descriptor[name] = value.clone();
            }
        }
        if let Some(names) = &self.role_name_policy
            && let Some(fields) = names.descriptor().as_object()
        {
            for (name, value) in fields {
                descriptor[name] = value.clone();
            }
        }
        descriptor
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
// RFC6125 wildcard syntax: exactly one star in the leftmost label. Each
// nonempty part of that label must itself be a DNS label, and all remaining
// labels remain ordinary DNS names. This does not broaden allowed_domains.
fn wildcard_name(name: &str) -> Option<(&str, &str)> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 || name.bytes().filter(|b| *b == b'*').count() != 1 {
        return None;
    }
    let (label, reduced) = name.split_once('.').unwrap_or((name, ""));
    if label.len() > 63 || !label.contains('*') || !reduced.is_empty() && !valid_domain(reduced) {
        return None;
    }
    let (prefix, suffix) = label.split_once('*')?;
    if [prefix, suffix]
        .into_iter()
        .any(|part| !part.is_empty() && !valid_domain(part))
    {
        return None;
    }
    Some((label, reduced))
}

fn wildcard_dns_san(name: &str) -> bool {
    wildcard_name(name).is_some_and(|(label, reduced)| label == "*" && !reduced.is_empty())
}

fn valid_common_name(name: &str) -> bool {
    valid_domain(name) || wildcard_name(name).is_some()
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
    let invalid_url = || {
        let message = if field == "PKI cluster path" {
            "invalid, non-URL path given to cluster"
        } else {
            "invalid, non-URL path given to AIA"
        };
        // Keep the upstream status without reflecting credentials or private paths.
        error(500, message)
    };
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err(invalid_url());
    };
    if !matches!(scheme, "http" | "https") {
        return Err(invalid_url());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid_url());
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

fn random_pki_id() -> Result<String> {
    let mut bytes = crate::crypto::random::<16>()
        .map_err(|_| error(503, "PKI identifier generation failed"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut value = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        value.push_str(&format!("{byte:02x}"));
    }
    Ok(value)
}

fn valid_pki_id(value: &str) -> bool {
    value.is_empty()
        || value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
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

struct IssuanceRoute<'a> {
    mount: &'a str,
    role: &'a str,
    explicit_issuer: Option<&'a str>,
    sign: bool,
}

pub(super) struct LeafAuthority<'a> {
    pub(super) owner: &'a LeaseOwner,
    pub(super) owner_expires: Option<u64>,
    pub(super) precise_owner_expires: Option<crate::auth::Timestamp>,
    pub(super) time: crate::auth::AuthorityTime,
    pub(super) clock: Option<crate::auth::RequestClock>,
    pub(super) identity_templates: Option<&'a crate::auth::IdentityTemplateValues>,
}

#[derive(Clone)]
struct LeafTemplate {
    csr_public_key: Option<LocalPublicKey>,
    role_name_policy: Option<RoleNamePolicy>,
    no_store: bool,
    exclude_cn_from_sans: bool,
    email_sans: Vec<String>,
    uri_sans: Vec<String>,
    issuer_not_after_behavior: Option<IssuerLeafNotAfterBehavior>,
    signed_role_time_owned: bool,
    role_time_owned: bool,
    warnings: Vec<String>,
    role_leaf_profile: Option<RoleLeafProfile>,
    local_issuer_id: String,
    serial: String,
    path: String,
    lease_id: String,
    owner: LeaseOwner,
    owner_expires: Option<u64>,
    precise_owner_expires: Option<crate::auth::Timestamp>,
    publication_time: crate::auth::AuthorityTime,
    publication_clock: Option<crate::auth::RequestClock>,
    leased: bool,
    common_name: String,
    local_key_kind: LocalKeyKind,
    alt_names: Vec<String>,
    ip_sans: Vec<IpAddr>,
    issued: u64,
    not_before: i64,
    expires: u64,
}

impl LeafTemplate {
    fn validate_publication(&self, floor: u64) -> Result<()> {
        self.validate_publication_observed(crate::auth::AuthorityTime::Coarse(floor))
    }
    fn validate_publication_observed(&self, time: crate::auth::AuthorityTime) -> Result<()> {
        let observed = precise_time::observe(
            self.publication_time,
            self.publication_clock,
            time.seconds(),
        )?;
        let observed = match (observed.exact(), time.exact()) {
            (Some(left), Some(right)) => crate::auth::AuthorityTime::Precise(left.max(right)),
            (None, Some(right)) => crate::auth::AuthorityTime::Precise(right),
            _ => observed,
        };
        if PkiInstant::whole(self.expires)? <= PkiInstant::authority(observed)?
            || self
                .precise_owner_expires
                .is_some_and(|end| observed.exact().is_none_or(|at| at > end))
            || self.precise_owner_expires.is_none()
                && self
                    .owner_expires
                    .is_some_and(|end| observed.seconds() >= end)
        {
            return Err(error(403, "issuer no longer has a live PKI lease window"));
        }
        Ok(())
    }
}

struct CertificateSpec<'a> {
    role_leaf_profile: Option<&'a RoleLeafProfile>,
    serial: &'a str,
    issuer_cn: &'a str,
    subject_cn: &'a str,
    issuer_name_der: Option<&'a [u8]>,
    subject_name_der: Option<&'a [u8]>,
    public_key: &'a [u8],
    authority_key_id: Option<&'a [u8]>,
    not_before: i64,
    not_after: u64,
    is_ca: bool,
    alt_names: &'a [String],
    email_sans: &'a [String],
    ip_sans: &'a [IpAddr],
    uri_sans: &'a [String],
    exclude_cn_from_sans: bool,
    max_path_length: Option<u32>,
    permitted_dns_domains: &'a [String],
}

fn certificate_der(signer: &Ed25519KeyPair, spec: CertificateSpec<'_>) -> Result<Vec<u8>> {
    let tbs = certificate_tbs(spec)?;
    let signature = signer.sign(&tbs);
    Ok(seq(&[
        tbs,
        algorithm_ed25519(),
        bit_string(signature.as_ref(), 0),
    ]))
}

fn certificate_tbs(spec: CertificateSpec<'_>) -> Result<Vec<u8>> {
    if spec.public_key.len() != 32 {
        return Err(error(500, "invalid Ed25519 public key"));
    }
    let spki = seq(&[algorithm_ed25519(), bit_string(spec.public_key, 0)]);
    certificate_tbs_with(spec, &spki, &algorithm_ed25519())
}

fn certificate_der_local(
    signer: &LocalPrivateMaterial,
    subject: &LocalPublicKey,
    spec: CertificateSpec<'_>,
) -> Result<Vec<u8>> {
    if signer.kind() == LocalKeyKind::Ed25519
        && let LocalPublicKey::Ed25519(public) = subject
    {
        let bytes = signer.private_der()?;
        let pair = Ed25519KeyPair::from_pkcs8(&bytes)
            .map_err(|_| error(503, "invalid local PKI signing key"))?;
        return certificate_der(
            &pair,
            CertificateSpec {
                public_key: public,
                ..spec
            },
        );
    }
    let algorithm = signer.kind().signature_algorithm();
    let tbs = certificate_tbs_with(spec, &subject.spki()?, &algorithm)?;
    let signature = signer.sign(&tbs)?;
    if !signer.public()?.verify(&tbs, &signature)? {
        return Err(error(
            503,
            "local PKI certificate signature failed validation",
        ));
    }
    Ok(seq(&[tbs, algorithm, bit_string(&signature, 0)]))
}

fn certificate_der_local_with_policy(
    signer: &LocalPrivateMaterial,
    subject: &LocalPublicKey,
    spec: CertificateSpec<'_>,
    policy: Option<&RoleNamePolicy>,
) -> Result<Vec<u8>> {
    let scheme = LeafSignature::for_key(signer.kind(), policy);
    if matches!(scheme, LeafSignature::Legacy(_)) {
        return certificate_der_local(signer, subject, spec);
    }
    let algorithm = scheme.algorithm();
    let tbs = certificate_tbs_with(spec, &subject.spki()?, &algorithm)?;
    let signature = signer.sign_leaf(&tbs, scheme)?;
    if !signer.public()?.verify_leaf(&tbs, &signature, scheme)? {
        return Err(error(
            503,
            "local PKI certificate signature failed validation",
        ));
    }
    Ok(seq(&[tbs, algorithm, bit_string(&signature, 0)]))
}

fn certificate_tbs_with(
    spec: CertificateSpec<'_>,
    subject_spki: &[u8],
    signature_algorithm: &[u8],
) -> Result<Vec<u8>> {
    let CertificateSpec {
        serial,
        issuer_cn,
        subject_cn,
        issuer_name_der,
        subject_name_der,
        public_key: _,
        authority_key_id,
        not_before,
        not_after,
        is_ca,
        alt_names,
        email_sans,
        ip_sans,
        uri_sans,
        exclude_cn_from_sans,
        max_path_length,
        permitted_dns_domains,
        role_leaf_profile,
    } = spec;
    if is_ca && role_leaf_profile.is_some() {
        return Err(error(
            503,
            "PKI leaf profile cannot control a CA certificate",
        ));
    }
    let subject_der = if let Some(profile) = role_leaf_profile {
        profile.subject_der(subject_cn)?
    } else {
        subject_name_der.map_or_else(|| name(subject_cn), <[u8]>::to_vec)
    };
    let mut extensions = role_leaf_profile
        .map(RoleLeafProfile::leaf_extensions)
        .transpose()?
        .unwrap_or_default();
    let basic = if is_ca {
        let mut fields = vec![boolean(true)];
        if let Some(length) = max_path_length {
            fields.push(integer(&length.to_be_bytes()));
        }
        seq(&fields)
    } else {
        seq(&[])
    };
    if role_leaf_profile.is_none() {
        extensions.push(extension(&[0x55, 0x1d, 0x13], true, &basic));
    }
    if !permitted_dns_domains.is_empty() {
        let subtrees: Vec<_> = permitted_dns_domains
            .iter()
            .map(|domain| seq(&[context_primitive(2, domain.as_bytes())]))
            .collect();
        extensions.push(extension(
            &[0x55, 0x1d, 0x1e],
            true,
            &seq(&[der(0xa0, &subtrees.concat())]),
        ));
    }
    let subject_key_id = root_fields::subject_key_identifier(subject_spki)?;
    extensions.push(extension(
        &[0x55, 0x1d, 0x0e],
        false,
        &octet_string(&subject_key_id),
    ));
    if let Some(authority_key_id) = authority_key_id {
        extensions.push(extension(
            &[0x55, 0x1d, 0x23],
            false,
            &seq(&[context_primitive(0, authority_key_id)]),
        ));
    }
    let usage_byte = if is_ca { 0x06 } else { 0x80 };
    let unused = if is_ca { 1 } else { 7 };
    if role_leaf_profile.is_none() {
        extensions.push(extension(
            &[0x55, 0x1d, 0x0f],
            true,
            &bit_string(&[usage_byte], unused),
        ));
    }
    let captured_subject =
        role_leaf_profile.and_then(|profile| profile.leaf_subject_evidence.as_ref());
    let other_names = captured_subject
        .map(|subject| subject.other_names_der())
        .transpose()?
        .unwrap_or_default();
    let policies = captured_subject
        .map(|subject| subject.policies_der())
        .transpose()?
        .flatten();
    let qualified_policy =
        captured_subject.is_some_and(|subject| subject.policy_uses_extra_extension());
    if !other_names.is_empty()
        && !qualified_policy
        && let Some(policies) = &policies
    {
        extensions.push(policies.clone());
    }
    let mut names = other_names.clone();
    if !exclude_cn_from_sans
        && (role_leaf_profile.is_none() || !subject_cn.is_empty())
        && (is_ca || !subject_cn.contains('*') || wildcard_dns_san(subject_cn))
    {
        names.push(context_primitive(2, subject_cn.as_bytes()));
    }
    for name in alt_names {
        names.push(context_primitive(2, name.as_bytes()));
    }
    for email in email_sans {
        names.push(context_primitive(1, email.as_bytes()));
    }
    for ip in ip_sans {
        let bytes = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        names.push(context_primitive(7, &bytes));
    }
    for uri in uri_sans {
        names.push(context_primitive(6, uri.as_bytes()));
    }
    if !names.is_empty() {
        extensions.push(extension(
            &[0x55, 0x1d, 0x11],
            subject_der.as_slice() == [0x30, 0] && other_names.is_empty(),
            &seq(&names),
        ));
    }
    if (other_names.is_empty() || qualified_policy)
        && let Some(policies) = policies
    {
        extensions.push(policies);
    }
    let tbs = seq(&[
        context_explicit(0, &integer(&[2])),
        integer(&serial_bytes(serial)?),
        signature_algorithm.to_vec(),
        issuer_name_der.map_or_else(|| name(issuer_cn), <[u8]>::to_vec),
        seq(&[time_signed(not_before), time(not_after)]),
        subject_der,
        subject_spki.to_vec(),
        context_explicit(3, &seq(&extensions)),
    ]);
    Ok(tbs)
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
    time_stamp(&timestamp(seconds))
}
fn time_signed(seconds: i64) -> Vec<u8> {
    time_stamp(&role_time::signed_timestamp(seconds))
}
fn time_stamp(stamp: &str) -> Vec<u8> {
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
// Ring generates OneAsymmetricKey (PKCS8 v2). Export PrivateKeyInfo with the
// maintained provider so consumers accepting standard PKCS8 can load the leaf.
// Only the response encoding changes; bind the exporter to the original key.
fn leaf_private_key_pem(pkcs8: &[u8]) -> Result<Zeroizing<String>> {
    let original = Ed25519KeyPair::from_pkcs8(pkcs8)
        .map_err(|_| error(503, "PKI leaf private key export failed"))?;
    let provider = openssl::pkey::PKey::private_key_from_der(pkcs8)
        .map_err(|_| error(503, "PKI leaf private key export failed"))?;
    let public = provider
        .raw_public_key()
        .map_err(|_| error(503, "PKI leaf private key export failed"))?;
    if public.as_slice() != original.public_key().as_ref() {
        return Err(error(503, "PKI leaf private key export failed"));
    }
    let encoded = Zeroizing::new(
        provider
            .private_key_to_pem_pkcs8()
            .map_err(|_| error(503, "PKI leaf private key export failed"))?,
    );
    let text = std::str::from_utf8(&encoded)
        .map_err(|_| error(503, "PKI leaf private key export failed"))?;
    Ok(Zeroizing::new(text.to_owned()))
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

fn private_key_pem(label: &str, der: &[u8]) -> Result<Zeroizing<String>> {
    let encoded = Zeroizing::new(BASE64.encode(der));
    let mut out = Zeroizing::new(format!("-----BEGIN {label}-----\n"));
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(
            std::str::from_utf8(chunk).map_err(|_| error(503, "PKI private key export failed"))?,
        );
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----"));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pki_leaf_private_export_is_standard_pkcs8_with_original_public_key()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let document = Zeroizing::new(
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| "temporary key generation")?
                .as_ref()
                .to_vec(),
        );
        let original =
            Ed25519KeyPair::from_pkcs8(&document).map_err(|_| "original temporary key")?;
        let exported = leaf_private_key_pem(&document)?;
        let loaded = openssl::pkey::PKey::private_key_from_pem(exported.as_bytes())?;
        assert!(
            loaded.raw_public_key()?.as_slice() == original.public_key().as_ref(),
            "standard private export preserves the original leaf public key"
        );
        let message = b"synthetic PKCS8 consumer proof";
        let signature = original.sign(message);
        let mut verifier = openssl::sign::Verifier::new_without_digest(&loaded)?;
        assert!(
            verifier.verify_oneshot(signature.as_ref(), message)?,
            "exported private key verifies the original leaf signature"
        );
        Ok(())
    }

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
                .contains("BEGIN RSA PRIVATE KEY")
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
            &json!({"allowed_domains":["example.test"],"allow_ip_sans":false}),
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
                return Err(
                    "role with explicit allow_ip_sans=false unexpectedly issued a certificate"
                        .into(),
                );
            }
            Err(error) => error.status,
        };
        assert_eq!(denied_status, 400);
        pki.handle_admin(
            "POST",
            "roles/web-ip",
            &json!({"allowed_domains":["example.test"],"allow_subdomains":true,"allow_ip_sans":true}),
            1_700_000_003,
        )?;
        let issued = pki.issue(
            "pki/",
            "web-ip",
            &json!({"common_name":"api.example.test","ip_sans":["127.0.0.1","2001:db8::1"],"ttl":"1h"}),
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
                .strip_suffix("-----END CERTIFICATE-----")
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
        let unknown = pki.handle_admin(
            "POST",
            "config/acme",
            &json!({"enabled":false,"unknown":"must-not-persist"}),
            1_700_000_000,
        )?;
        assert_eq!(unknown.status, 200);
        assert_eq!(unknown.body["data"]["enabled"], false);
        assert_eq!(
            unknown.body["warnings"],
            json!(["Endpoint ignored these unrecognized parameters: [unknown]"])
        );
        assert!(!unknown.body.to_string().contains("must-not-persist"));
        let after_unknown = pki.handle_admin("GET", "config/acme", &json!({}), 1_700_000_000)?;
        assert_eq!(after_unknown.body["data"]["enabled"], false);
        for (path, body, status) in [
            (
                "config/cluster",
                json!({"path":"file:///secret-location"}),
                500,
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
        }
        assert_eq!(
            pki.handle_admin("GET", "config/acme", &json!({}), 1_700_000_000)?
                .body,
            after_unknown.body
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
            after_unknown.body["data"]
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "pki_root_format_tests.rs"]
mod root_format_tests;

#[cfg(test)]
mod bare_domain_legacy_tests {
    use super::*;

    #[test]
    fn pki_role_bare_domain_legacy_bytes_keep_actual_historical_permission() -> Result<()> {
        let legacy = json!({"allowed_domains":["example.test"],"allow_subdomains":false,
                           "allow_ip_sans":false,"max_ttl":3600,"generate_lease":false});
        let historical: Role =
            serde_json::from_value(legacy.clone()).map_err(|_| bad("legacy role fixture"))?;
        historical.validate()?;
        assert!(historical.allow_bare_domains.is_none() && historical.allows("example.test"));
        assert!(
            serde_json::to_value(&historical).map_err(|_| bad("legacy serialization"))? == legacy,
            "historical role JSON stays exact and has no fabricated default field"
        );
        let current = Role::from_body(&legacy)?;
        assert!(current.allow_bare_domains == Some(false) && !current.allows("example.test"));
        let mut body = legacy.clone();
        body["allow_bare_domains"] = json!(true);
        let allowed = Role::from_body(&body)?;
        assert!(allowed.allow_bare_domains == Some(true) && allowed.allows("EXAMPLE.TEST"));
        for wrong in [json!("not_bool"), json!(2), json!([]), json!({})] {
            body["allow_bare_domains"] = wrong;
            assert!(Role::from_body(&body).is_err());
        }
        Ok(())
    }

    #[test]
    fn pki_wildcard_syntax_and_permission_do_not_relax_historical_roles() -> Result<()> {
        let legacy = json!({"allowed_domains":["example.test"],"allow_subdomains":true,
            "allow_ip_sans":false,"max_ttl":3600,"generate_lease":false});
        let historical: Role =
            serde_json::from_value(legacy.clone()).map_err(|_| bad("old role"))?;
        assert!(!historical.allows("*.example.test"));
        assert_eq!(
            serde_json::to_value(&historical).map_err(|_| bad("old role bytes"))?,
            legacy
        );
        let current = Role::from_body(&legacy)?;
        assert_eq!(current.allow_wildcard_certificates, Some(true));
        for name in [
            "*.example.test",
            "f*o.example.test",
            "*foo.example.test",
            "foo*.example.test",
        ] {
            assert!(valid_common_name(name) && current.allows(name));
        }
        for name in [
            "**.example.test",
            "a.*.example.test",
            "f**o.example.test",
            "-f*.example.test",
            "f*-o.example.test",
        ] {
            assert!(!valid_common_name(name) && !current.allows(name));
        }
        assert!(wildcard_dns_san("*.example.test"));
        assert!(!wildcard_dns_san("f*o.example.test"));
        let mut body = json!({"allow_any_name":true,"allow_wildcard_certificates":false});
        let denied = Role::from_body(&body)?;
        assert!(denied.allows("plain.unlisted.test") && !denied.allows("*.unlisted.test"));
        body["allow_wildcard_certificates"] = json!("1");
        assert!(Role::from_body(&body)?.allows("*.unlisted.test"));
        body["allow_wildcard_certificates"] = json!(2);
        assert!(Role::from_body(&body).is_err());
        let mut encoded = serde_json::to_value(&current).map_err(|_| bad("current role bytes"))?;
        encoded["allow_wildcard_certificates"] = json!("true");
        assert!(
            serde_json::from_value::<Role>(encoded).is_err(),
            "wire coercion never relaxes durable typed bool"
        );
        Ok(())
    }
}
