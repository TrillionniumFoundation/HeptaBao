//! Direct external Ed25519 roots and CSR generation. This owns DER construction,
//! not network authority. The Service verifies the actual remote signature and
//! publishes only after its original request and durable generation fences.
use super::*;
use ring::signature::{ED25519, UnparsedPublicKey};
#[path = "pki_external_public_key.rs"]
mod public_key;
pub(crate) use public_key::ExternalPkiPublicKey;
#[path = "pki_external_leaf.rs"]
mod leaf;
use leaf::{ConsumptionMaterial, ConsumptionTemplate, CrlSet, LeafPublic};
#[path = "pki_external_issuer_archive.rs"]
mod issuer_archive;
pub(super) use issuer_archive::ExternalLeafIssuerOwner;
use issuer_archive::ExternalPublicIssuer;

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct ExternalState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root: Option<ExternalKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intermediate: Option<ExternalCsr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crls: Option<CrlSet>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    issued_public: BTreeMap<String, LeafPublic>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    archived_issuers: BTreeMap<String, ExternalPublicIssuer>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalKey {
    reference: String,
    public_key: ExternalPkiPublicKey,
    key_id: String,
    issuer_id: String,
    key_name: String,
    issuer_name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    dns_san: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalCsr {
    key: ExternalKey,
    common_name: String,
    csr_der: Vec<u8>,
}

impl ExternalState {
    pub(super) fn is_empty(&self) -> bool {
        self.root.is_none()
            && self.intermediate.is_none()
            && self.crls.is_none()
            && self.issued_public.is_empty()
            && self.archived_issuers.is_empty()
    }
    pub(super) fn clear_root(&mut self) {
        self.root = None;
        self.crls = None;
        // Verified leaf projections and public signer archives survive retirement.
    }
}

#[derive(Clone)]
pub(crate) struct ExternalPkiTemplate {
    pub(crate) reference: String,
    operation: &'static str,
    common_name: String,
    serial: String,
    not_before: u64,
    not_after: u64,
    key_id: String,
    issuer_id: String,
    key_name: String,
    issuer_name: String,
    dns_san: bool,
    generated_at: u64,
    consumption: Option<ConsumptionTemplate>,
    bound_public: Option<ExternalPkiPublicKey>,
    // Process-local capture from the actual validated root. The Service plan
    // binds this to its namespace, mount incarnation, config, request, state
    // identity, generation and provider enrollment; publication checks it again.
    bound_issuer: Option<ExternalPublicIssuer>,
}

pub(crate) struct ExternalPkiMaterial {
    template: ExternalPkiTemplate,
    public_key: ExternalPkiPublicKey,
    pub(crate) tbs: Vec<u8>,
    extra_tbs: Vec<Vec<u8>>,
    root_crls: Option<CrlSet>,
    consumption: Option<ConsumptionMaterial>,
}

fn reference_valid(reference: &str) -> bool {
    let Some((config, key)) = reference.split_once(':') else {
        return false;
    };
    [config, key].iter().all(|part| {
        !part.is_empty()
            && part.len() <= 128
            && !matches!(*part, "." | "..")
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
    })
}

fn identifier() -> Result<String> {
    let mut bytes = crate::crypto::random::<16>()
        .map_err(|_| error(503, "PKI identifier generation failed"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn optional_name(body: &Value, field: &str) -> Result<String> {
    let name = body
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| bad("PKI name must be a string"))
        })
        .transpose()?
        .unwrap_or("");
    if name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
    {
        return Err(bad("invalid PKI name"));
    }
    Ok(name.into())
}

pub(super) fn common_name_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && !value.chars().any(char::is_control)
}

fn dns_san_extension(common_name: &str) -> Vec<u8> {
    extension(
        &[0x55, 0x1d, 0x11],
        false,
        &seq(&[context_primitive(2, common_name.as_bytes())]),
    )
}

fn csr_info(
    common_name: &str,
    public_key: &ExternalPkiPublicKey,
    dns_san: bool,
) -> Result<Vec<u8>> {
    let attributes = if dns_san {
        // [0] is the IMPLICIT attribute set. Each extensionRequest attribute
        // contains a SET with one canonical Extensions sequence.
        seq(&[
            oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]),
            set(&[seq(&[dns_san_extension(common_name)])]),
        ])
    } else {
        Vec::new()
    };
    Ok(seq(&[
        integer(&[0]),
        name(common_name),
        public_key.spki()?,
        context_explicit(0, &attributes),
    ]))
}

fn signed_der(tbs: &[u8], signature: &[u8], public: &ExternalPkiPublicKey) -> Vec<u8> {
    seq(&[
        tbs.to_vec(),
        public.signature_algorithm(),
        bit_string(signature, 0),
    ])
}

fn external_serial() -> Result<String> {
    let mut bytes = crate::crypto::random::<20>()
        .map_err(|_| error(503, "external PKI serial generation failed"))?;
    bytes[0] &= 0x7f;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[19] = 1;
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(super) fn formatted_serial(serial: &str) -> String {
    serial
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes))
        .collect::<Vec<_>>()
        .join(":")
}

// The pinned 2.7 direct-root blackbox has exactly KeyUsage, BasicConstraints,
// SKI and AKI, plus a DNS SAN when the CN is a valid DNS name. SHA-1 is solely the
// standard public-key identifier construction, never a signature algorithm.
struct ExternalRootSpec<'a> {
    serial: &'a str,
    issuer_cn: &'a str,
    subject_cn: &'a str,
    public_key: &'a ExternalPkiPublicKey,
    not_before: u64,
    not_after: u64,
}
fn external_root_tbs(spec: ExternalRootSpec<'_>, dns_san: bool) -> Result<Vec<u8>> {
    let ExternalRootSpec {
        serial,
        issuer_cn,
        subject_cn,
        public_key,
        not_before,
        not_after,
    } = spec;
    let key_bits = public_key.subject_key_bits()?;
    let key_id = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &key_bits);
    let mut extensions = vec![
        extension(&[0x55, 0x1d, 0x0f], true, &bit_string(&[0x06], 1)),
        extension(&[0x55, 0x1d, 0x13], true, &seq(&[boolean(true)])),
        extension(&[0x55, 0x1d, 0x0e], false, &octet_string(key_id.as_ref())),
        extension(
            &[0x55, 0x1d, 0x23],
            false,
            &seq(&[context_primitive(0, key_id.as_ref())]),
        ),
    ];
    if dns_san {
        extensions.push(dns_san_extension(subject_cn));
    }
    Ok(seq(&[
        context_explicit(0, &integer(&[2])),
        integer(&serial_bytes(serial)?),
        public_key.signature_algorithm(),
        name(issuer_cn),
        seq(&[time(not_before), time(not_after)]),
        name(subject_cn),
        public_key.spki()?,
        context_explicit(3, &seq(&extensions)),
    ]))
}

impl ExternalPkiTemplate {
    pub(crate) fn materialize(
        self,
        public_key: impl Into<ExternalPkiPublicKey>,
    ) -> Result<ExternalPkiMaterial> {
        let public_key = public_key.into();
        public_key.validate()?;
        if self.is_consumption() {
            return self.materialize_consumption(public_key);
        }
        let tbs = if self.operation == "root" {
            external_root_tbs(
                ExternalRootSpec {
                    serial: &self.serial,
                    issuer_cn: &self.common_name,
                    subject_cn: &self.common_name,
                    public_key: &public_key,
                    not_before: self.not_before,
                    not_after: self.not_after,
                },
                self.dns_san,
            )?
        } else {
            csr_info(&self.common_name, &public_key, self.dns_san)?
        };
        let root_crls = (self.operation == "root").then(|| CrlSet::empty(self.generated_at));
        let extra_tbs = root_crls
            .as_ref()
            .map(|crls| crls.tbs(&self.common_name, &public_key))
            .transpose()?
            .unwrap_or_default();
        Ok(ExternalPkiMaterial {
            template: self,
            public_key,
            tbs,
            extra_tbs,
            root_crls,
            consumption: None,
        })
    }
}

impl ExternalPkiMaterial {
    fn leaf_signature(&self) -> LeafSignature {
        let policy =
            self.consumption
                .as_ref()
                .and_then(|consumption| match &consumption.template {
                    ConsumptionTemplate::Leaf(prepared) => prepared.role_name_policy.as_ref(),
                    ConsumptionTemplate::Crl { .. } => None,
                });
        self.public_key.leaf_signature(policy)
    }
    pub(crate) fn signature_algorithm(&self) -> &'static str {
        if self.leaf_signature().pss() {
            "pss"
        } else {
            "pkcs1v15"
        }
    }
    pub(crate) fn signing_input(&self, tbs: &[u8]) -> Result<Vec<u8>> {
        self.public_key
            .signing_input_leaf(tbs, self.leaf_signature())
    }
    pub(crate) fn hash_algorithm(&self) -> Option<&'static str> {
        self.leaf_signature().hash_algorithm()
    }
    pub(crate) fn signature_size_bound(&self) -> usize {
        self.public_key.signature_size_bound()
    }
    pub(crate) fn tbs_parts(&self) -> impl Iterator<Item = &Vec<u8>> {
        std::iter::once(&self.tbs).chain(self.extra_tbs.iter())
    }
    pub(crate) fn verify_at(&self, index: usize, signature: &[u8]) -> Result<()> {
        let tbs = self
            .tbs_parts()
            .nth(index)
            .ok_or_else(|| bad("external PKI signature index"))?;
        if self
            .public_key
            .verify_leaf(tbs, signature, self.leaf_signature())
            .is_err()
        {
            return Err(error(
                503,
                "external PKI unknown after entry: cryptographic signature mismatch; no blind retry",
            ));
        }
        Ok(())
    }
}

impl Pki {
    pub(in crate::engines) fn has_typed_external_pki_state(&self) -> bool {
        self.external
            .root
            .as_ref()
            .is_some_and(|key| key.public_key.is_asymmetric())
            || self
                .external
                .intermediate
                .as_ref()
                .is_some_and(|csr| csr.key.public_key.is_asymmetric())
    }
    pub(in crate::engines::pki) fn public_issuer_metadata(&self) -> Option<(&str, &str, &str)> {
        self.external
            .root
            .as_ref()
            .map(|key| {
                (
                    key.issuer_id.as_str(),
                    key.key_id.as_str(),
                    key.issuer_name.as_str(),
                )
            })
            .or_else(|| {
                self.root
                    .as_ref()
                    .filter(|root| !root.issuer_id.is_empty())
                    .map(|root| {
                        (
                            root.issuer_id.as_str(),
                            root.key_id.as_str(),
                            root.local_fields
                                .as_ref()
                                .map_or("", |fields| fields.issuer_name.as_str()),
                        )
                    })
            })
    }
    // Parse only this closed alias shape. Resolution and authority remain separate;
    // the original request path must never become the canonical issue path.
    pub(in crate::engines) fn issuer_issue_route(path: &str) -> Option<(&str, &str)> {
        let (reference, role) = path.strip_prefix("issuer/")?.split_once("/issue/")?;
        (!reference.is_empty()
            && reference.len() <= 128
            && !reference.contains('/')
            && !role.is_empty()
            && role.len() <= 128
            && !role.contains('/')
            && !path.contains('?'))
        .then_some((reference, role))
    }

    pub(in crate::engines) fn issuer_sign_route(path: &str) -> Option<(&str, &str)> {
        let (reference, role) = path.strip_prefix("issuer/")?.split_once("/sign/")?;
        (!reference.is_empty()
            && reference.len() <= 128
            && !reference.contains('/')
            && !role.is_empty()
            && role.len() <= 128
            && !role.contains('/')
            && !path.contains('?'))
        .then_some((reference, role))
    }

    pub(in crate::engines) fn external_handles(&self, path: &str) -> bool {
        matches!(path, "root/generate/kms" | "intermediate/generate/kms")
            || self.external.root.is_some()
                && (path.starts_with("issue/")
                    || path.starts_with("sign/")
                    || Self::issuer_sign_route(path).is_some()
                    || Self::issuer_issue_route(path).is_some()
                    || matches!(path, "revoke" | "crl/rotate"))
    }

    pub(in crate::engines) fn has_external_state(&self) -> bool {
        !self.external.is_empty()
    }

    pub(in crate::engines) fn prepare_external(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<ExternalPkiTemplate>> {
        if !matches!(path, "root/generate/kms" | "intermediate/generate/kms") {
            return Ok(None);
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        reject_unknown(
            body,
            &[
                "external_key_ref",
                "common_name",
                "ttl",
                "key_type",
                "key_name",
                "issuer_name",
                "format",
            ],
        )?;
        if body
            .get("format")
            .is_some_and(|value| value.as_str() != Some("pem"))
        {
            return Err(error(
                501,
                "external PKI format requires a qualified DER/PEM lane",
            ));
        }
        if body
            .get("key_type")
            .is_some_and(|value| value.as_str() != Some("ed25519"))
        {
            return Err(error(501, "external PKI currently supports Ed25519 only"));
        }
        let operation = if path == "root/generate/kms" {
            "root"
        } else {
            "intermediate"
        };
        if operation == "root" && self.root.is_some() {
            return Err(bad("PKI root already exists"));
        }
        if operation == "intermediate" && self.external.intermediate.is_some() {
            return Err(error(
                501,
                "multiple external intermediate keys require a qualified issuer lane",
            ));
        }
        let reference = string(body, "external_key_ref")?;
        if !reference_valid(reference) {
            return Err(bad("invalid external PKI reference"));
        }
        let common_name = string(body, "common_name")?;
        if !common_name_valid(common_name) {
            return Err(bad("invalid PKI common name"));
        }
        let ttl = ttl_field(body, "ttl", DEFAULT_ROOT_TTL)?;
        if ttl == 0 || ttl > self.max_ttl {
            return Err(bad("PKI root TTL is outside bounds"));
        }
        Ok(Some(ExternalPkiTemplate {
            reference: reference.into(),
            operation,
            common_name: common_name.into(),
            serial: external_serial()?,
            not_before: now.saturating_sub(30),
            not_after: now
                .checked_add(ttl)
                .ok_or_else(|| bad("PKI root TTL overflow"))?,
            key_id: identifier()?,
            issuer_id: identifier()?,
            key_name: optional_name(body, "key_name")?,
            issuer_name: optional_name(body, "issuer_name")?,
            dns_san: valid_domain(common_name),
            generated_at: now,
            consumption: None,
            bound_public: None,
            bound_issuer: None,
        }))
    }

    pub(in crate::engines) fn publish_external(
        &mut self,
        mut material: ExternalPkiMaterial,
        signatures: &[Zeroizing<Vec<u8>>],
        now: u64,
    ) -> Result<EngineResponse> {
        if signatures.len() != material.tbs_parts().count() {
            return Err(bad("external PKI incomplete signing effects"));
        }
        for (index, signature) in signatures.iter().enumerate() {
            material.verify_at(index, signature)?;
        }
        if material.consumption.is_some() {
            return self.publish_consumption(material, signatures, now);
        }
        let mut root_crls = material.root_crls.take();
        if let Some(crls) = root_crls.as_mut() {
            crls.sign(
                &material.template.common_name,
                &material.public_key,
                &signatures[1..],
            )?;
        }
        let template = material.template;
        let key = ExternalKey {
            reference: template.reference,
            public_key: material.public_key,
            key_id: template.key_id,
            issuer_id: template.issuer_id,
            key_name: template.key_name,
            issuer_name: template.issuer_name,
            dns_san: template.dns_san,
        };
        let encoded = signed_der(&material.tbs, &signatures[0], &key.public_key);
        if key.issuer_id == key.key_id
            || self.external_pki_identifiers_in_use(&key.issuer_id, &key.key_id)
            || self.local_pki_identifiers_in_use(&key.issuer_id, &key.key_id)
        {
            return Err(error(503, "external PKI identifier collision"));
        }
        if template.operation == "root" {
            if self.root.is_some() {
                return Err(bad("PKI root already exists"));
            }
            let certificate = public::stored_pem("CERTIFICATE", &encoded);
            let response = json!({"certificate":certificate,"issuing_ca":certificate,
                "serial_number":formatted_serial(&template.serial),"expiration":template.not_after,
                "key_id":key.key_id,"key_name":key.key_name,"issuer_id":key.issuer_id,"issuer_name":key.issuer_name});
            self.root = Some(RootCa {
                leaf_not_after_behavior: None,
                common_name: template.common_name,
                issuer_id: String::new(),
                key_id: String::new(),
                local_fields: None,
                pkcs8: Vec::new(),
                local_chain: None,
                local_material: None,
                certificate_der: encoded,
                serial: template.serial,
                not_before: template.not_before,
                not_after: template.not_after,
            });
            self.external.root = Some(key);
            self.external.crls = root_crls;
            Ok(ok(response, true))
        } else {
            if self.external.intermediate.is_some() {
                return Err(bad("external intermediate already exists"));
            }
            let response = json!({"csr":pem("CERTIFICATE REQUEST", &encoded),"key_id":key.key_id});
            self.external.intermediate = Some(ExternalCsr {
                key,
                common_name: template.common_name,
                csr_der: encoded,
            });
            Ok(ok(response, true))
        }
    }

    pub(super) fn validate_external_state(&self) -> Result<()> {
        if self.root.as_ref().is_some_and(|root| root.is_external()) != self.external.root.is_some()
        {
            return Err(bad("external PKI root ownership mismatch"));
        }
        let validate_key = |key: &ExternalKey| -> Result<()> {
            key.public_key.validate()?;
            if !reference_valid(&key.reference)
                || !valid_identifier(&key.key_id)
                || !valid_identifier(&key.issuer_id)
                || key.key_name.len() > 128
                || key.issuer_name.len() > 128
                || ![&key.key_name, &key.issuer_name].iter().all(|name| {
                    name.bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
                })
            {
                return Err(bad("invalid external PKI key metadata"));
            }
            Ok(())
        };
        if let Some(key) = &self.external.root {
            validate_key(key)?;
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| bad("external PKI root missing"))?;
            if key.dns_san && !valid_domain(&root.common_name) {
                return Err(bad("external PKI DNS SAN subject is invalid"));
            }
            if !root.is_external() {
                return Err(bad("external PKI must not contain local private key"));
            }
            let tbs = external_root_tbs(
                ExternalRootSpec {
                    serial: &root.serial,
                    issuer_cn: &root.common_name,
                    subject_cn: &root.common_name,
                    public_key: &key.public_key,
                    not_before: root.not_before,
                    not_after: root.not_after,
                },
                key.dns_san,
            )?;
            validate_signed_der(&key.public_key, &tbs, &root.certificate_der)?;
        }
        if let Some(csr) = &self.external.intermediate {
            validate_key(&csr.key)?;
            if !common_name_valid(&csr.common_name) {
                return Err(bad("invalid external CSR subject"));
            }
            if csr.key.dns_san && !valid_domain(&csr.common_name) {
                return Err(bad("external CSR DNS SAN subject is invalid"));
            }
            validate_signed_der(
                &csr.key.public_key,
                &csr_info(&csr.common_name, &csr.key.public_key, csr.key.dns_san)?,
                &csr.csr_der,
            )?;
        }
        Ok(())
    }
}

fn take_der(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, tail) = input
        .split_first()
        .ok_or_else(|| bad("invalid external PKI DER"))?;
    let (&length, mut tail) = tail
        .split_first()
        .ok_or_else(|| bad("invalid external PKI DER"))?;
    let size = if length & 0x80 == 0 {
        usize::from(length)
    } else {
        let width = usize::from(length & 0x7f);
        if !(1..=4).contains(&width) || tail.len() < width {
            return Err(bad("invalid external PKI DER length"));
        }
        let (bytes, rest) = tail.split_at(width);
        tail = rest;
        bytes
            .iter()
            .fold(0usize, |size, byte| (size << 8) | usize::from(*byte))
    };
    if size > tail.len() {
        return Err(bad("invalid external PKI DER bounds"));
    }
    let (content, rest) = tail.split_at(size);
    if der(tag, content).as_slice() != &input[..input.len() - rest.len()] {
        return Err(bad("noncanonical external PKI DER"));
    }
    Ok((tag, content, rest))
}

fn validate_signed_der(
    public_key: &ExternalPkiPublicKey,
    tbs: &[u8],
    document: &[u8],
) -> Result<()> {
    validate_signed_der_with_scheme(public_key, tbs, document, public_key.leaf_signature(None))
}

fn signed_der_with_scheme(tbs: &[u8], signature: &[u8], scheme: LeafSignature) -> Vec<u8> {
    seq(&[tbs.to_vec(), scheme.algorithm(), bit_string(signature, 0)])
}

fn validate_signed_der_with_scheme(
    public_key: &ExternalPkiPublicKey,
    tbs: &[u8],
    document: &[u8],
    scheme: LeafSignature,
) -> Result<()> {
    let (tag, fields, rest) = take_der(document)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(bad("invalid external PKI document"));
    }
    let (tag, content, fields) = take_der(fields)?;
    if tag != 0x30 || der(tag, content) != tbs {
        return Err(bad("external PKI TBS mismatch"));
    }
    let (tag, content, fields) = take_der(fields)?;
    if tag != 0x30 || der(tag, content) != scheme.algorithm() {
        return Err(bad("external PKI algorithm mismatch"));
    }
    let (tag, bits, rest) = take_der(fields)?;
    let signature = bits
        .get(1..)
        .ok_or_else(|| bad("invalid external PKI signature"))?;
    if tag != 0x03
        || bits.first() != Some(&0)
        || !rest.is_empty()
        || signed_der_with_scheme(tbs, signature, scheme) != document
        || public_key.verify_leaf(tbs, signature, scheme).is_err()
    {
        return Err(bad("invalid external PKI document or signature"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_pki_legacy_no_san_state_retains_its_signed_semantics() -> Result<()> {
        let pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| bad("test provider key generation"))?;
        let pair = Ed25519KeyPair::from_pkcs8(pair.as_ref())
            .map_err(|_| bad("test provider key decode"))?;
        let public: [u8; 32] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| bad("test provider public decode"))?;
        let mut pki = Pki::default();
        let mut legacy = pki.prepare_external("POST", "root/generate/kms", &json!({
            "external_key_ref":"provider:fixed", "common_name":"legacy-ca.example.test", "ttl":"1h"
        }), 100)?.ok_or_else(|| bad("test template"))?;
        // The old schema-65 writer had no CN-as-DNS SAN. The retained false
        // default preserves those exact signed bytes after a current reopen.
        legacy.dns_san = false;
        let material = legacy.materialize(public)?;
        let signatures = material
            .tbs_parts()
            .map(|tbs| Zeroizing::new(pair.sign(tbs).as_ref().to_vec()))
            .collect::<Vec<_>>();
        pki.publish_external(material, &signatures, 100)?;
        let mut encoded = serde_json::to_value(&pki).map_err(|_| bad("test encode"))?;
        assert!(
            encoded["external"]["root"].get("dns_san").is_none(),
            "legacy metadata shape unchanged"
        );
        let reopened: Pki =
            serde_json::from_value(encoded.clone()).map_err(|_| bad("test reopen"))?;
        reopened.validate("", "legacy/", 100)?;
        encoded["external"]["root"]["dns_san"] = json!(true);
        let altered: Pki =
            serde_json::from_value(encoded).map_err(|_| bad("test altered decode"))?;
        assert!(
            altered.validate("", "legacy/", 100).is_err(),
            "SAN semantic substitution rejected"
        );
        Ok(())
    }
    #[test]
    fn external_legacy_none_projection_retirement_preserves_real_proof_and_unknown_history()
    -> Result<()> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| bad("test provider generation"))?;
        let pair =
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| bad("test provider decode"))?;
        let public: [u8; 32] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| bad("test public key"))?;
        let mut pki = Pki::default();
        let root=pki.prepare_external("POST","root/generate/kms",&json!({
            "external_key_ref":"provider:fixed","common_name":"legacy-ca.example.test","ttl":"1h"
        }),100)?.ok_or_else(||bad("actual root template"))?;
        let material = root.materialize(public)?;
        let signatures = material
            .tbs_parts()
            .map(|tbs| Zeroizing::new(pair.sign(tbs).as_ref().to_vec()))
            .collect::<Vec<_>>();
        pki.publish_external(material, &signatures, 100)?;
        pki.fixture_insert_historical_role(
            "legacy",
            &json!({"allowed_domains":["example.test"],
            "allow_subdomains":true,"allow_ip_sans":false,"max_ttl":3600,"generate_lease":false}),
        )?;
        let owner = crate::auth::ResolvedLeaseOwner {
            precise_expires_at: None,
            owner: LeaseOwner::service(&base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                crate::crypto::digest(b"actual retired-issuer fixture owner"),
            ))
            .map_err(|_| bad("test owner"))?,
            expires_at: None,
            entity_id: None,
        };
        let mut legacy = pki
            .prepare_external_consumption(
                "POST",
                "issue/legacy",
                &json!({
                    "common_name":"leaf.example.test","ttl":"10m"
                }),
                "legacy/",
                crate::engines::PkiRequestContext {
                    owner: Some(&owner),
                    now: 100,
                    identity_templates: None,
                },
            )?
            .ok_or_else(|| bad("actual leaf template"))?;
        // This finite predecessor fixture executes the real old None DER
        // producer and actual provider signature, before any typed new owner.
        let Some(ConsumptionTemplate::Leaf(prepared)) = legacy.consumption.as_mut() else {
            return Err(bad("leaf fixture"));
        };
        prepared.role_leaf_profile = None;
        let material = legacy.materialize(public)?;
        let signatures = material
            .tbs_parts()
            .map(|tbs| Zeroizing::new(pair.sign(tbs).as_ref().to_vec()))
            .collect::<Vec<_>>();
        let response = pki.publish_external(material, &signatures, 100)?;
        let serial = normalize_serial(
            response.body["data"]["serial_number"]
                .as_str()
                .ok_or_else(|| bad("actual leaf serial"))?,
        )?;
        let original_der = pki
            .issued
            .get(&serial)
            .ok_or_else(|| bad("actual old leaf"))?
            .certificate_der
            .clone();
        let mut encoded =
            serde_json::to_value(&pki).map_err(|_| bad("actual predecessor encode"))?;
        encoded["issued"][&serial]
            .as_object_mut()
            .ok_or_else(|| bad("old leaf object"))?
            .remove("external_issuer_owner");
        encoded["external"]["issued_public"][&serial]
            .as_object_mut()
            .ok_or_else(|| bad("old projection"))?
            .remove("issuer_id");
        encoded["external"]
            .as_object_mut()
            .ok_or_else(|| bad("old external state"))?
            .remove("archived_issuers");
        let mut old: Pki = serde_json::from_value(encoded).map_err(|_| bad("actual old decode"))?;
        old.validate("", "legacy/", 100)?;
        assert!(
            !old.has_role_leaf_profile_state(),
            "original None state has no new owner marker"
        );
        let mut unknown = old.clone();
        // Model the previously accepted loss from the original clear_root.
        // No active key, CA or leaf projection survives; original leaf DER stays.
        unknown.root = None;
        *unknown.external = Default::default();
        unknown.validate("", "legacy/", 100)?;
        assert!(
            old.handle_admin("POST", "root/delete", &json!({}), 100)?
                .status
                == 200,
            "actual root/delete succeeds for proven historical None projection"
        );
        old.validate("", "legacy/", 100)?;
        let leaf = old
            .issued
            .get(&serial)
            .ok_or_else(|| bad("retired old leaf"))?;
        assert!(
            leaf.role_leaf_profile.is_none()
                && leaf.local_issuer_id.is_empty()
                && leaf.external_issuer_owner.is_some()
                && leaf.certificate_der == original_der
                && old.has_role_leaf_profile_state()
                && old.external.archived_issuers.len() == 1,
            "real None DER unchanged, independently proven archive binding requires88"
        );
        let bytes = Zeroizing::new(serde_json::to_vec(&old).map_err(|_| bad("retired encode"))?);
        let reopened: Pki = serde_json::from_slice(&bytes).map_err(|_| bad("retired reopen"))?;
        reopened.validate("", "legacy/", 100)?;
        assert!(
            reopened
                .issued
                .get(&serial)
                .is_some_and(|leaf| leaf.certificate_der == original_der),
            "retired None exact signed bytes survive typed reopen"
        );
        unknown.handle_admin(
            "POST",
            "root/generate/internal",
            &json!({
                "common_name":"new-local.example.test","key_type":"ec","key_bits":256,"ttl":"1h"
            }),
            100,
        )?;
        assert!(
            unknown
                .handle_admin("POST", "root/delete", &json!({}), 100)?
                .status
                == 200,
            "unknown legacy ownership neither guesses current local identity nor changes deletion success"
        );
        unknown.validate("", "legacy/", 100)?;
        let leaf = unknown
            .issued
            .get(&serial)
            .ok_or_else(|| bad("unknown old leaf"))?;
        assert!(
            leaf.local_issuer_id.is_empty()
                && leaf.external_issuer_owner.is_none()
                && leaf.role_leaf_profile.is_none()
                && leaf.certificate_der == original_der
                && unknown.external.archived_issuers.is_empty(),
            "unprovable old None history stays explicitly unassigned and is not claimed qualified"
        );
        Ok(())
    }
}
