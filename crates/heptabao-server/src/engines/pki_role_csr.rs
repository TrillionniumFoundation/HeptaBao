//! CSR signature, actual public key and role-owned input precedence.
//! This changes names only; validity continues through the caller's clock lane.
use super::*;
use openssl::{pkey::Id, x509::X509Req};
use x509_parser::extensions::{GeneralName, ParsedExtension};

pub(super) fn default_true() -> bool {
    true
}
pub(super) fn is_true(value: &bool) -> bool {
    *value
}

pub(super) struct CsrInput {
    pub(super) public: LocalPublicKey,
    pub(super) body: Value,
    pub(super) warnings: Vec<String>,
}

impl CsrInput {
    pub(super) fn from_request(role: &Role, body: &Value) -> Result<Self> {
        let policy = role
            .role_name_policy
            .as_ref()
            .ok_or_else(|| bad("historical role has no CSR signing policy"))?;
        let role_kind = role.local_key_kind.unwrap_or(LocalKeyKind::Ed25519);
        let der = local_intermediate::csr_bytes_from_body(body)?;
        reject_small_rsa(&der, role_kind, role.role_key_policy.is_some())?;
        let csr = local_intermediate::parse_csr(&der)?;
        let public = LocalPublicKey::from_spki(csr.certification_request_info.subject_pki.raw)?;
        // Subject key limits are role-owned even when the caller holds its key.
        if role.role_key_policy.is_none() && public.kind().key_type() != role_kind.key_type() {
            return Err(bad(&format!(
                "role requires keys of type {}",
                role_kind.key_type()
            )));
        }
        if role.role_key_policy.is_none() && public.kind().bits() < role_kind.bits() {
            return Err(bad(&format!(
                "role requires a minimum of a {}-bit key, but CSR's key is {} bits",
                role_kind.bits(),
                public.kind().bits()
            )));
        }
        let mut normalized = body.clone();
        normalized
            .as_object_mut()
            .ok_or_else(|| bad("request body must be an object"))?
            .remove("csr");
        let mut warnings = Vec::new();
        if policy.use_csr_common_name {
            if body
                .get("common_name")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            {
                warnings.push("the common_name field was provided but the role is set with \"use_csr_common_name\" set to true".into());
            }
            if let Some(name) = csr
                .certification_request_info
                .subject
                .iter_common_name()
                .last()
            {
                let name = name.as_str().map_err(|_| bad("invalid CSR common name"))?;
                if !name.is_empty() {
                    normalized["common_name"] = json!(name);
                }
            }
        }
        if normalized
            .get("serial_number")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            && let Some(attribute) = csr
                .certification_request_info
                .subject
                .iter_attributes()
                .filter(|attribute| attribute.attr_type().to_id_string() == "2.5.4.5")
                .last()
        {
            normalized["serial_number"] = json!(
                attribute
                    .as_str()
                    .map_err(|_| bad("invalid CSR serial number"))?
            );
        }
        if policy.use_csr_sans {
            if body.get("alt_names").is_some_and(|value| match value {
                Value::String(value) => !value.is_empty(),
                Value::Array(value) => !value.is_empty(),
                _ => false,
            }) {
                warnings.push("the alt_names field was provided but the role is set with \"use_csr_sans\" set to true".into());
            }
            let mut names = Vec::new();
            let mut ips = Vec::new();
            let mut uris = Vec::new();
            let mut other = body
                .get("other_sans")
                .map(|value| role_leaf_profile::weak_comma_list("other_sans", value))
                .transpose()?
                .unwrap_or_default();
            if let Some(extensions) = csr.requested_extensions() {
                for extension in extensions {
                    if let ParsedExtension::SubjectAlternativeName(san) = extension {
                        for name in &san.general_names {
                            match name {
                                GeneralName::DNSName(value) | GeneralName::RFC822Name(value) => {
                                    names.push((*value).to_owned())
                                }
                                GeneralName::URI(value) => uris.push((*value).to_owned()),
                                GeneralName::IPAddress(value) => {
                                    let ip = match value.len() {
                                        4 => IpAddr::from(
                                            <[u8; 4]>::try_from(*value)
                                                .map_err(|_| bad("invalid CSR IP SAN"))?,
                                        ),
                                        16 => IpAddr::from(
                                            <[u8; 16]>::try_from(*value)
                                                .map_err(|_| bad("invalid CSR IP SAN"))?,
                                        ),
                                        _ => return Err(bad("invalid CSR IP SAN")),
                                    };
                                    ips.push(ip.to_string());
                                }
                                GeneralName::OtherName(oid, value) => other.push(format!(
                                    "{};UTF8:{}",
                                    oid.to_id_string(),
                                    other_name_utf8(value)?
                                )),
                                _ => return Err(bad("unsupported CSR SAN kind")),
                            }
                        }
                    }
                }
            }
            // Preserve CSR SAN order. The effective CN follows it, as upstream
            // does before the final stable deduplication of each SAN class.
            if !role_optional_bool(body, "exclude_cn_from_sans")?.unwrap_or(false)
                && let Some(cn) = normalized.get("common_name").and_then(Value::as_str)
                && (valid_common_name(cn) || cn.contains('@'))
                && !names.iter().any(|value| value == cn)
            {
                names.push(cn.to_owned());
            }
            let mut seen = BTreeSet::new();
            names.retain(|value| seen.insert(value.clone()));
            normalized["alt_names"] = json!(names);
            normalized["ip_sans"] = json!(ips);
            normalized["uri_sans"] = json!(uris);
            normalized["other_sans"] = json!(other);
            normalized["exclude_cn_from_sans"] = json!(true);
        }
        Ok(Self {
            public,
            body: normalized,
            warnings,
        })
    }
}

fn der_content(bytes: &[u8], tag: u8) -> Result<&[u8]> {
    let invalid = || bad("CSR otherName must contain a complete UTF8 value");
    if bytes.len() < 2 || bytes[0] != tag {
        return Err(invalid());
    }
    let (header, len) = if bytes[1] < 128 {
        (2, usize::from(bytes[1]))
    } else {
        let count = usize::from(bytes[1] & 0x7f);
        if count == 0 || count > 4 || 2 + count > bytes.len() {
            return Err(invalid());
        }
        let len = bytes[2..2 + count]
            .iter()
            .try_fold(0usize, |len, byte| {
                len.checked_mul(256)?.checked_add(usize::from(*byte))
            })
            .ok_or_else(invalid)?;
        (2 + count, len)
    };
    if header + len != bytes.len() {
        return Err(invalid());
    }
    Ok(&bytes[header..])
}
fn other_name_utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(der_content(der_content(bytes, 0xa0)?, 0x0c)?)
        .map_err(|_| bad("CSR otherName is not UTF8"))
}

// A valid but undersized RSA CSR is bad request input. Reject it before the
// maintained private/public key owner decoder, which correctly has no such
// managed key kind. The ordinary intermediate parser keeps its original guard.
fn reject_small_rsa(bytes: &[u8], role_kind: LocalKeyKind, any: bool) -> Result<()> {
    let Ok(request) = X509Req::from_der(bytes) else {
        return Ok(());
    };
    let Ok(key) = request.public_key() else {
        return Ok(());
    };
    if key.id() != Id::RSA || key.bits() >= 2048 {
        return Ok(());
    }
    if request.to_der().map_err(|_| bad("invalid CSR encoding"))? != bytes
        || !request
            .verify(&key)
            .map_err(|_| bad("request signature invalid"))?
    {
        return Err(bad("request signature invalid"));
    }
    if any {
        return Err(bad("RSA keys < 2048 bits are unsafe and not supported"));
    }
    if role_kind.key_type() != "rsa" {
        return Err(bad(&format!(
            "role requires keys of type {}",
            role_kind.key_type()
        )));
    }
    Err(bad(&format!(
        "role requires a minimum of a {}-bit key, but CSR's key is {} bits",
        role_kind.bits(),
        key.bits()
    )))
}
