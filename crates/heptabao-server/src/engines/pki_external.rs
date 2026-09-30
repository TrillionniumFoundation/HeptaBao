//! Direct external Ed25519 roots and CSR generation. This owns DER construction,
//! not network authority. The Service verifies the actual remote signature and
//! publishes only after its original request and durable generation fences.
use super::*;
use ring::signature::{ED25519, UnparsedPublicKey};

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct ExternalState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root: Option<ExternalKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intermediate: Option<ExternalCsr>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalKey {
    reference: String,
    public_key: [u8; 32],
    key_id: String,
    issuer_id: String,
    key_name: String,
    issuer_name: String,
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
        self.root.is_none() && self.intermediate.is_none()
    }
    pub(super) fn clear_root(&mut self) {
        self.root = None;
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
}

pub(crate) struct ExternalPkiMaterial {
    template: ExternalPkiTemplate,
    public_key: [u8; 32],
    pub(crate) tbs: Vec<u8>,
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

fn csr_info(common_name: &str, public_key: &[u8; 32]) -> Vec<u8> {
    seq(&[
        integer(&[0]),
        name(common_name),
        seq(&[algorithm_ed25519(), bit_string(public_key, 0)]),
        context_explicit(0, &[]),
    ])
}

fn signed_der(tbs: &[u8], signature: &[u8]) -> Vec<u8> {
    seq(&[tbs.to_vec(), algorithm_ed25519(), bit_string(signature, 0)])
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

fn formatted_serial(serial: &str) -> String {
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
// SKI and AKI, without an implicit CN-as-DNS SAN. SHA-1 here is solely the
// standard public-key identifier construction, never a signature algorithm.
fn external_root_tbs(spec: CertificateSpec<'_>) -> Result<Vec<u8>> {
    let CertificateSpec {
        serial,
        issuer_cn,
        subject_cn,
        public_key,
        not_before,
        not_after,
        ..
    } = spec;
    if public_key.len() != 32 {
        return Err(bad("external PKI public key length"));
    }
    let key_id = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, public_key);
    let extensions = vec![
        extension(&[0x55, 0x1d, 0x0f], true, &bit_string(&[0x06], 1)),
        extension(&[0x55, 0x1d, 0x13], true, &seq(&[boolean(true)])),
        extension(&[0x55, 0x1d, 0x0e], false, &octet_string(key_id.as_ref())),
        extension(
            &[0x55, 0x1d, 0x23],
            false,
            &seq(&[context_primitive(0, key_id.as_ref())]),
        ),
    ];
    Ok(seq(&[
        context_explicit(0, &integer(&[2])),
        integer(&serial_bytes(serial)?),
        algorithm_ed25519(),
        name(issuer_cn),
        seq(&[time(not_before), time(not_after)]),
        name(subject_cn),
        seq(&[algorithm_ed25519(), bit_string(public_key, 0)]),
        context_explicit(3, &seq(&extensions)),
    ]))
}

impl ExternalPkiTemplate {
    pub(crate) fn materialize(self, public_key: [u8; 32]) -> Result<ExternalPkiMaterial> {
        let tbs = if self.operation == "root" {
            external_root_tbs(CertificateSpec {
                serial: &self.serial,
                issuer_cn: &self.common_name,
                subject_cn: &self.common_name,
                public_key: &public_key,
                not_before: self.not_before,
                not_after: self.not_after,
                is_ca: true,
                alt_names: &[],
                ip_sans: &[],
            })?
        } else {
            csr_info(&self.common_name, &public_key)
        };
        Ok(ExternalPkiMaterial {
            template: self,
            public_key,
            tbs,
        })
    }
}

impl ExternalPkiMaterial {
    pub(crate) fn verify(&self, signature: &[u8]) -> Result<()> {
        if signature.len() != 64
            || UnparsedPublicKey::new(&ED25519, &self.public_key)
                .verify(&self.tbs, signature)
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
    pub(in crate::engines) fn external_handles(&self, path: &str) -> bool {
        matches!(path, "root/generate/kms" | "intermediate/generate/kms")
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
        if !self.external_handles(path) {
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
        if !valid_common_name(common_name) {
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
        }))
    }

    pub(in crate::engines) fn publish_external(
        &mut self,
        material: ExternalPkiMaterial,
        signature: &[u8],
    ) -> Result<EngineResponse> {
        material.verify(signature)?;
        let template = material.template;
        let key = ExternalKey {
            reference: template.reference,
            public_key: material.public_key,
            key_id: template.key_id,
            issuer_id: template.issuer_id,
            key_name: template.key_name,
            issuer_name: template.issuer_name,
        };
        let encoded = signed_der(&material.tbs, signature);
        if template.operation == "root" {
            if self.root.is_some() {
                return Err(bad("PKI root already exists"));
            }
            let certificate = pem("CERTIFICATE", &encoded);
            let response = json!({"certificate":certificate,"issuing_ca":certificate,
                "serial_number":formatted_serial(&template.serial),"expiration":template.not_after,
                "key_id":key.key_id,"key_name":key.key_name,"issuer_id":key.issuer_id,"issuer_name":key.issuer_name});
            self.root = Some(RootCa {
                common_name: template.common_name,
                pkcs8: Vec::new(),
                certificate_der: encoded,
                serial: template.serial,
                not_before: template.not_before,
                not_after: template.not_after,
            });
            self.external.root = Some(key);
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
        if self.root.as_ref().is_some_and(|root| root.pkcs8.is_empty())
            != self.external.root.is_some()
        {
            return Err(bad("external PKI root ownership mismatch"));
        }
        let validate_key = |key: &ExternalKey| -> Result<()> {
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
            if !root.pkcs8.is_empty() {
                return Err(bad("external PKI must not contain local private key"));
            }
            let tbs = external_root_tbs(CertificateSpec {
                serial: &root.serial,
                issuer_cn: &root.common_name,
                subject_cn: &root.common_name,
                public_key: &key.public_key,
                not_before: root.not_before,
                not_after: root.not_after,
                is_ca: true,
                alt_names: &[],
                ip_sans: &[],
            })?;
            validate_signed_der(&key.public_key, &tbs, &root.certificate_der)?;
        }
        if let Some(csr) = &self.external.intermediate {
            validate_key(&csr.key)?;
            if !valid_common_name(&csr.common_name) {
                return Err(bad("invalid external CSR subject"));
            }
            validate_signed_der(
                &csr.key.public_key,
                &csr_info(&csr.common_name, &csr.key.public_key),
                &csr.csr_der,
            )?;
        }
        Ok(())
    }
}

fn validate_signed_der(public_key: &[u8; 32], tbs: &[u8], document: &[u8]) -> Result<()> {
    let signature = document
        .get(document.len().saturating_sub(64)..)
        .ok_or_else(|| bad("invalid external PKI document"))?;
    if signature.len() != 64
        || signed_der(tbs, signature) != document
        || UnparsedPublicKey::new(&ED25519, public_key)
            .verify(tbs, signature)
            .is_err()
    {
        return Err(bad("invalid external PKI document or signature"));
    }
    Ok(())
}
