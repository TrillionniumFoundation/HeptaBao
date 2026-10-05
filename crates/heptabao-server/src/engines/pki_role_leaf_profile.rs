//! Typed certificate fields captured from an admitted role by the leaf owner.
//!
//! Public decoding follows the captured official weak-input contract.
//! Reader88 protects actual stored role/leaf evidence; native qualification
//! is established separately from enabling this format in the source.
use super::*;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleLeafProfile {
    pub(super) server_flag: bool,
    pub(super) client_flag: bool,
    pub(super) code_signing_flag: bool,
    pub(super) email_protection_flag: bool,
    pub(super) key_usage: Vec<String>,
    pub(super) ext_key_usage: Vec<String>,
    pub(super) ext_key_usage_oids: Vec<String>,
    pub(super) country: Vec<String>,
    pub(super) province: Vec<String>,
    pub(super) locality: Vec<String>,
    pub(super) street_address: Vec<String>,
    pub(super) postal_code: Vec<String>,
    pub(super) organization: Vec<String>,
    pub(super) ou: Vec<String>,
    pub(super) basic_constraints_valid_for_non_ca: bool,
}

impl Default for RoleLeafProfile {
    fn default() -> Self {
        Self {
            server_flag: true,
            client_flag: true,
            code_signing_flag: false,
            email_protection_flag: false,
            key_usage: vec![
                "DigitalSignature".into(),
                "KeyAgreement".into(),
                "KeyEncipherment".into(),
            ],
            ext_key_usage: Vec::new(),
            ext_key_usage_oids: Vec::new(),
            country: Vec::new(),
            province: Vec::new(),
            locality: Vec::new(),
            street_address: Vec::new(),
            postal_code: Vec::new(),
            organization: Vec::new(),
            ou: Vec::new(),
            basic_constraints_valid_for_non_ca: false,
        }
    }
}

impl RoleLeafProfile {
    // Role write validation and certificate DER validity are different upstream
    // boundaries. A stored integer-segment OID is not thereby valid ASN.1.
    pub(super) fn validate_role_oid_strings(&self) -> Result<()> {
        for value in &self.ext_key_usage_oids {
            parse_oid_integer_segments(value).map_err(|_| {
                bad(&format!(
                    "{} could not be parsed as a valid oid for an extended key usage",
                    go_quote(value)
                ))
            })?;
        }
        Ok(())
    }

    pub(super) fn descriptor_fields(&self) -> Value {
        json!({
            "server_flag": self.server_flag,
            "client_flag": self.client_flag,
            "code_signing_flag": self.code_signing_flag,
            "email_protection_flag": self.email_protection_flag,
            "key_usage": self.key_usage,
            "ext_key_usage": self.ext_key_usage,
            "ext_key_usage_oids": self.ext_key_usage_oids,
            "country": self.country,
            "province": self.province,
            "locality": self.locality,
            "street_address": self.street_address,
            "postal_code": self.postal_code,
            "organization": self.organization,
            "ou": self.ou,
            "basic_constraints_valid_for_non_ca": self.basic_constraints_valid_for_non_ca,
        })
    }

    pub(super) fn subject_der(&self, common_name: &str) -> Vec<u8> {
        let mut rdns = Vec::new();
        for (last_oid, values) in [
            (6, &self.country),
            (8, &self.province),
            (7, &self.locality),
            (9, &self.street_address),
            (17, &self.postal_code),
            (10, &self.organization),
            (11, &self.ou),
        ] {
            let mut seen = BTreeSet::new();
            let mut attributes: Vec<_> = values
                .iter()
                .filter(|value| !value.is_empty() && seen.insert(value.as_str()))
                .map(|value| seq(&[oid(&[0x55, 0x04, last_oid]), name_string(value.as_bytes())]))
                .collect();
            if !attributes.is_empty() {
                attributes.sort();
                rdns.push(set(&attributes));
            }
        }
        if !common_name.is_empty() {
            rdns.push(set(&[seq(&[
                oid(&[0x55, 0x04, 3]),
                name_string(common_name.as_bytes()),
            ])]));
        }
        seq(&rdns)
    }

    // This returns the actual three role-controlled extension DER values.
    // The certificate producer inserts them in the observed upstream order
    // alongside its actual SKID, issuer AKID and admitted names. Roots and
    // historical None certificate evidence keeps its existing separate path.
    pub(super) fn leaf_extensions(&self) -> Result<Vec<Vec<u8>>> {
        let mut extensions = Vec::new();
        let usage = self.effective_key_usage();
        if usage != 0 {
            let first = (usage as u8).reverse_bits();
            let second = ((usage >> 8) as u8).reverse_bits();
            let (bytes, unused) = if second != 0 {
                (vec![first, second], second.trailing_zeros() as u8)
            } else {
                (vec![first], first.trailing_zeros() as u8)
            };
            extensions.push(extension(
                &[0x55, 0x1d, 0x0f],
                true,
                &bit_string(&bytes, unused),
            ));
        }
        let mask = self.effective_extended_usage();
        let known = [
            "2.5.29.37.0",
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2",
            "1.3.6.1.5.5.7.3.3",
            "1.3.6.1.5.5.7.3.4",
            "1.3.6.1.5.5.7.3.5",
            "1.3.6.1.5.5.7.3.6",
            "1.3.6.1.5.5.7.3.7",
            "1.3.6.1.5.5.7.3.8",
            "1.3.6.1.5.5.7.3.9",
            "1.3.6.1.4.1.311.10.3.3",
            "2.16.840.1.113730.4.1",
        ];
        let mut eku = Vec::new();
        for (index, value) in known.into_iter().enumerate() {
            if mask & (1 << index) != 0 {
                eku.push(encoded_oid(value)?);
            }
        }
        for value in &self.ext_key_usage_oids {
            eku.push(encoded_oid(value)?);
        }
        if !eku.is_empty() {
            extensions.push(extension(&[0x55, 0x1d, 0x25], false, &seq(&eku)));
        }
        if self.basic_constraints_valid_for_non_ca {
            extensions.push(extension(&[0x55, 0x1d, 0x13], true, &seq(&[])));
        }
        Ok(extensions)
    }

    fn effective_key_usage(&self) -> u16 {
        let mut mask = 0;
        for value in &self.key_usage {
            let index = match simple_lowercase(value).as_str() {
                "digitalsignature" => 0,
                "contentcommitment" => 1,
                "keyencipherment" => 2,
                "dataencipherment" => 3,
                "keyagreement" => 4,
                "certsign" => 5,
                "crlsign" => 6,
                "encipheronly" => 7,
                "decipheronly" => 8,
                _ => continue,
            };
            mask |= 1 << index;
        }
        mask
    }

    fn effective_extended_usage(&self) -> u16 {
        let mut mask = 0;
        for (index, enabled) in [
            (1, self.server_flag),
            (2, self.client_flag),
            (3, self.code_signing_flag),
            (4, self.email_protection_flag),
        ] {
            if enabled {
                mask |= 1 << index;
            }
        }
        for value in &self.ext_key_usage {
            let index = match simple_lowercase(value).as_str() {
                "any" => 0,
                "serverauth" => 1,
                "clientauth" => 2,
                "codesigning" => 3,
                "emailprotection" => 4,
                "ipsecendsystem" => 5,
                "ipsectunnel" => 6,
                "ipsecuser" => 7,
                "timestamping" => 8,
                "ocspsigning" => 9,
                "microsoftservergatedcrypto" => 10,
                "netscapeservergatedcrypto" => 11,
                _ => continue,
            };
            mask |= 1 << index;
        }
        mask
    }
}

fn name_string(value: &[u8]) -> Vec<u8> {
    let printable = value
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(byte));
    der(if printable { 0x13 } else { 0x0c }, value)
}

fn parse_oid_integer_segments(value: &str) -> std::result::Result<Vec<i64>, ()> {
    value
        .split('.')
        .map(|part| part.parse::<i64>().map_err(|_| ()))
        .collect()
}

fn encoded_oid(value: &str) -> Result<Vec<u8>> {
    let bad_encoding = || {
        error(
            500,
            "1 error occurred:\n\t* unable to create certificate: asn1: structure error: invalid object identifier\n\n",
        )
    };
    let segments = parse_oid_integer_segments(value).map_err(|_| bad_encoding())?;
    if segments.len() < 2 || segments[0] > 2 || segments[0] < 2 && segments[1] >= 40 {
        return Err(bad_encoding());
    }
    // Go ASN.1 marshals signed machine-int segments. Negative base128
    // values emit no octets; merged first/second arithmetic wraps at 64 bits.
    // This matches actual -1.2.3 -> 06 01 03 and 1.-2.3 -> 06 02 26 03.
    let first = segments[0].wrapping_mul(40).wrapping_add(segments[1]);
    let mut content = Vec::new();
    for part in std::iter::once(first).chain(segments[2..].iter().copied()) {
        if part < 0 {
            continue;
        }
        let mut value = part as u64;
        let mut encoded = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value != 0 {
            encoded.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        encoded.reverse();
        content.extend(encoded);
    }
    Ok(oid(&content))
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct LeafProfilePublicEvidence {
    pub(super) profile: RoleLeafProfile,
    pub(super) public_key: LocalPublicKey,
    pub(super) not_before: u64,
    pub(super) alt_names: Vec<String>,
    pub(super) ip_sans: Vec<IpAddr>,
}

impl LeafProfilePublicEvidence {
    pub(super) fn capture(prepared: &LeafTemplate, public_key: &LocalPublicKey) -> Option<Self> {
        prepared.role_leaf_profile.clone().map(|profile| Self {
            profile,
            public_key: public_key.clone(),
            not_before: prepared.not_before,
            alt_names: prepared.alt_names.clone(),
            ip_sans: prepared.ip_sans.clone(),
        })
    }
}

impl Pki {
    pub(in crate::engines) fn has_role_leaf_profile_state(&self) -> bool {
        self.roles
            .values()
            .any(|role| role.role_leaf_profile.is_some())
            || self.issued.values().any(|leaf| {
                leaf.role_leaf_profile.is_some() || leaf.external_issuer_owner.is_some()
            })
            || self.has_external_role_leaf_profile_state()
    }

    // New profile leaves bind the entire DER to captured public evidence and
    // the exact live/retired issuer. Historical None DER is never retrofitted.
    pub(super) fn validate_profile_local_leaves(&self) -> Result<()> {
        use x509_parser::prelude::FromDer;
        for (serial, issued) in &self.issued {
            let Some(evidence) = &issued.role_leaf_profile else {
                continue;
            };
            if self.profile_leaf_is_external(serial) {
                continue;
            }
            if issued.local_issuer_id.is_empty() {
                return Err(bad("PKI profile leaf requires an owned issuer identity"));
            }
            let (issuer_der, issuer_public) =
                self.profile_leaf_issuer_evidence(&issued.local_issuer_id)?;
            evidence.profile.validate_role_oid_strings()?;
            evidence.public_key.validate()?;
            if evidence.not_before > issued.issued
                || evidence.alt_names.len() > 32
                || evidence.ip_sans.len() > 32
                || evidence.alt_names.iter().any(|name| {
                    !valid_common_name(name) || name.contains('*') && !issued.wildcard_names
                })
            {
                return Err(bad("invalid PKI profile leaf public evidence"));
            }
            let issuer_name = root_fields::certificate_subject(issuer_der)?;
            let authority_key_id = root_fields::certificate_key_identifier(issuer_der)?;
            let expected = certificate_tbs_with(
                CertificateSpec {
                    serial,
                    issuer_cn: "",
                    subject_cn: &issued.common_name,
                    issuer_name_der: Some(&issuer_name),
                    subject_name_der: None,
                    public_key: &[],
                    authority_key_id: authority_key_id.as_deref(),
                    not_before: evidence.not_before,
                    not_after: issued.expires,
                    is_ca: false,
                    alt_names: &evidence.alt_names,
                    email_sans: &[],
                    ip_sans: &evidence.ip_sans,
                    uri_sans: &[],
                    exclude_cn_from_sans: false,
                    max_path_length: None,
                    permitted_dns_domains: &[],
                    role_leaf_profile: Some(&evidence.profile),
                },
                &evidence.public_key.spki()?,
                &issuer_public.kind().signature_algorithm(),
            )?;
            let (rest, certificate) =
                x509_parser::certificate::X509Certificate::from_der(&issued.certificate_der)
                    .map_err(|_| bad("invalid PKI profile leaf certificate"))?;
            if !rest.is_empty()
                || certificate.signature_value.unused_bits != 0
                || certificate.signature_algorithm != certificate.tbs_certificate.signature
                || certificate.tbs_certificate.as_ref() != expected.as_slice()
                || !issuer_public.verify(&expected, &certificate.signature_value.data)?
            {
                return Err(bad("PKI profile leaf DER and public evidence differ"));
            }
        }
        Ok(())
    }
}

impl RoleLeafProfile {
    pub(super) fn from_body(body: &Value) -> Result<Self> {
        let mut profile = Self::default();
        for (name, output) in [
            ("server_flag", &mut profile.server_flag),
            ("client_flag", &mut profile.client_flag),
            ("code_signing_flag", &mut profile.code_signing_flag),
            ("email_protection_flag", &mut profile.email_protection_flag),
            (
                "basic_constraints_valid_for_non_ca",
                &mut profile.basic_constraints_valid_for_non_ca,
            ),
        ] {
            if let Some(value) = role_optional_bool(body, name)? {
                *output = value;
            }
        }
        for (name, output) in [
            ("key_usage", &mut profile.key_usage),
            ("ext_key_usage", &mut profile.ext_key_usage),
            ("ext_key_usage_oids", &mut profile.ext_key_usage_oids),
            ("country", &mut profile.country),
            ("province", &mut profile.province),
            ("locality", &mut profile.locality),
            ("street_address", &mut profile.street_address),
            ("postal_code", &mut profile.postal_code),
            ("organization", &mut profile.organization),
            ("ou", &mut profile.ou),
        ] {
            if let Some(value) = body.get(name) {
                *output = weak_comma_list(name, value)?;
            }
        }
        profile.validate_role_oid_strings()?;
        Ok(profile)
    }

    // Inspect actual created DER after signing, before publication. Go's x509
    // decoder accepts OID subidentifiers only up to MaxInt32, independently of
    // the role's signed 64-bit integer grammar and ASN.1 marshal boundary.
    pub(super) fn validate_created_leaf_der(&self, der: &[u8]) -> Result<()> {
        use x509_parser::prelude::FromDer;
        let invalid = || {
            error(
                500,
                "1 error occurred:\n\t* unable to parse created certificate: x509: invalid extended key usages\n\n",
            )
        };
        let (rest, certificate) =
            x509_parser::certificate::X509Certificate::from_der(der).map_err(|_| invalid())?;
        if !rest.is_empty() {
            return Err(invalid());
        }
        for extension in certificate.extensions() {
            if extension.oid.to_id_string() != "2.5.29.37" {
                continue;
            }
            let (tag, values, rest) = profile_tlv(extension.value).ok_or_else(invalid)?;
            if tag != 0x30 || !rest.is_empty() {
                return Err(invalid());
            }
            let mut values = values;
            while !values.is_empty() {
                let (tag, content, rest) = profile_tlv(values).ok_or_else(invalid)?;
                if tag != 0x06 || content.is_empty() {
                    return Err(invalid());
                }
                let mut value = 0u64;
                let mut count = 0;
                for &byte in content {
                    if count == 0 && byte == 0x80 || count == 5 {
                        return Err(invalid());
                    }
                    value = (value << 7) | u64::from(byte & 0x7f);
                    count += 1;
                    if byte & 0x80 == 0 {
                        if value > i32::MAX as u64 {
                            return Err(invalid());
                        }
                        count = 0;
                        value = 0;
                    }
                }
                if count != 0 {
                    return Err(invalid());
                }
                values = rest;
            }
        }
        Ok(())
    }
}

fn profile_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *bytes.first()?;
    let first = *bytes.get(1)?;
    let (offset, length) = if first < 0x80 {
        (2, usize::from(first))
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return None;
        }
        let mut length = 0usize;
        for byte in bytes.get(2..2 + count)? {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        (2 + count, length)
    };
    let end = offset.checked_add(length)?;
    Some((tag, bytes.get(offset..end)?, bytes.get(end..)?))
}

// Only JSON request input is weak. Durable fields remain typed Vec<String>.
// Actual HTTP numbers are converted from their original spelling after ACLs;
// trusted in-process callers with a Value use that Value's numeric spelling.
fn weak_comma_list(name: &str, value: &Value) -> Result<Vec<String>> {
    let values: Vec<&Value> = match value {
        Value::Null => return Ok(Vec::new()),
        Value::Object(values) if values.is_empty() => return Ok(Vec::new()),
        Value::String(value) if value.is_empty() => return Ok(Vec::new()),
        Value::String(value) => return Ok(value.split(',').map(|v| v.trim().to_owned()).collect()),
        Value::Array(values) => values.iter().collect(),
        value => vec![value],
    };
    let mut output = Vec::new();
    let mut errors = Vec::new();
    for (index, value) in values.into_iter().enumerate() {
        let text = match value {
            Value::Null => String::new(),
            Value::String(value) => value.clone(),
            Value::Bool(value) => if *value { "1" } else { "0" }.into(),
            Value::Number(value) => value.to_string(),
            Value::Array(_) | Value::Object(_) => {
                let kind = if value.is_array() {
                    "[]interface {}"
                } else {
                    "map[string]interface {}"
                };
                errors.push(format!("* '[{index}]' expected type 'string', got unconvertible type '{kind}', value: '{}'", go_display(value)));
                continue;
            }
        };
        output.push(text.trim().to_owned());
    }
    if !errors.is_empty() {
        errors.sort();
        return Err(bad(&format!(
            "Field validation failed: error converting input for field \"{name}\": {} error(s) decoding:\n\n{}",
            errors.len(),
            errors.join("\n")
        )));
    }
    Ok(output)
}

fn go_display(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".into(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(go_display).collect::<Vec<_>>().join(" ")
        ),
        Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values.iter().collect();
            format!(
                "map[{}]",
                sorted
                    .into_iter()
                    .map(|(key, value)| format!("{key}:{}", go_display(value)))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }
}

fn simple_lowercase(value: &str) -> String {
    // Go strings.ToLower has one simple mapping per rune, including İ -> i.
    value
        .trim()
        .chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect()
}

use crate::auth::go_print;
fn go_quote(value: &str) -> String {
    // Go fmt %q uses printable Unicode and Go string escapes, rather than
    // inventing a different name after the policy-existence lookup.
    let mut quoted = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '\"' => quoted.push_str("\\\""),
            '\x07' => quoted.push_str("\\a"),
            '\x08' => quoted.push_str("\\b"),
            '\x0c' => quoted.push_str("\\f"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\x0b' => quoted.push_str("\\v"),
            character if (character as u32) < 0x20 || character == '\x7f' => {
                quoted.push_str(&format!("\\x{:02x}", character as u32));
            }
            character if !go_print::is_print(character) => {
                let point = character as u32;
                if point < 0x10000 {
                    quoted.push_str(&format!("\\u{point:04x}"));
                } else {
                    quoted.push_str(&format!("\\U{point:08x}"));
                }
            }
            character => quoted.push(character),
        }
    }
    quoted.push('\"');
    quoted
}
