//! Local root certificate fields. The certificate remains the authority for its
//! full issuer DN; aliases are encrypted state and require the extended reader.
use super::*;
use x509_parser::prelude::{FromDer, X509Certificate};

pub(super) const ROOT_FIELDS: &[&str] = &[
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
    "max_path_length",
    "issuer_name",
    "key_name",
];

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LocalRootMetadata {
    pub(super) issuer_name: String,
    pub(super) key_name: String,
}

impl LocalRootMetadata {
    pub(super) fn validate(&self) -> Result<()> {
        for value in [&self.issuer_name, &self.key_name] {
            if !alias_valid(value) {
                return Err(bad("invalid local PKI root alias"));
            }
        }
        Ok(())
    }
}

pub(super) struct RootFields {
    pub(super) subject_der: Vec<u8>,
    pub(super) dns_sans: Vec<String>,
    pub(super) email_sans: Vec<String>,
    pub(super) ip_sans: Vec<IpAddr>,
    pub(super) uri_sans: Vec<String>,
    pub(super) exclude_cn: bool,
    pub(super) backdate: u64,
    pub(super) max_path_length: Option<u32>,
    pub(super) metadata: Option<LocalRootMetadata>,
}

fn alias_valid(value: &str) -> bool {
    value.len() <= 128
        && value != "default"
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

fn alias(body: &Value, field: &str) -> Result<String> {
    let value = body
        .get(field)
        .map(|v| v.as_str().ok_or_else(|| bad("PKI name must be a string")))
        .transpose()?
        .unwrap_or("");
    if !alias_valid(value) {
        return Err(bad("invalid local PKI root alias"));
    }
    Ok(value.into())
}

fn bounded_list(body: &Value, field: &str) -> Result<Vec<String>> {
    let values = string_list(body.get(field))?;
    if values.len() > 64
        || values.iter().any(|value| {
            value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control)
        })
    {
        return Err(bad("PKI certificate field is outside bounds"));
    }
    Ok(values)
}

fn email_valid(value: &str) -> bool {
    value.is_ascii()
        && value.len() <= 254
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !local.contains('@') && valid_domain(domain)
        })
}

fn dns_valid(value: &str) -> bool {
    valid_domain(value.strip_prefix("*.").unwrap_or(value))
}

fn uri_valid(value: &str) -> bool {
    value.is_ascii()
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
        && value.split_once(':').is_some_and(|(scheme, rest)| {
            !rest.is_empty()
                && scheme.bytes().enumerate().all(|(i, b)| {
                    if i == 0 {
                        b.is_ascii_alphabetic()
                    } else {
                        b.is_ascii_alphanumeric() || b"+-.".contains(&b)
                    }
                })
        })
}

fn distinguished_name(body: &Value, common_name: &str) -> Result<Vec<u8>> {
    let mut rdns = Vec::new();
    for (field, last_oid) in [
        ("country", 6),
        ("province", 8),
        ("locality", 7),
        ("street_address", 9),
        ("postal_code", 17),
        ("organization", 10),
        ("ou", 11),
    ] {
        let values = bounded_list(body, field)?;
        if field == "country"
            && values
                .iter()
                .any(|v| v.len() != 2 || !v.bytes().all(|b| b.is_ascii_alphabetic()))
        {
            return Err(bad("invalid PKI country"));
        }
        if !values.is_empty() {
            // DER SET OF is sorted by encoded value. Each same-OID name list
            // is one RDN, as in the pinned Go pkix.Name consumer.
            let mut attrs: Vec<_> = values
                .iter()
                .map(|v| seq(&[oid(&[0x55, 0x04, last_oid]), asn1_name_string(v)]))
                .collect();
            attrs.sort();
            rdns.push(set(&attrs));
        }
    }
    rdns.push(set(&[seq(&[
        oid(&[0x55, 0x04, 3]),
        asn1_name_string(common_name),
    ])]));
    if let Some(value) = body.get("serial_number") {
        let value = value
            .as_str()
            .ok_or_else(|| bad("invalid PKI subject serial number"))?;
        if value.len() > 1024 || value.chars().any(char::is_control) {
            return Err(bad("invalid PKI subject serial number"));
        }
        if !value.is_empty() {
            rdns.push(set(&[seq(&[
                oid(&[0x55, 0x04, 5]),
                asn1_name_string(value),
            ])]));
        }
    }
    Ok(seq(&rdns))
}

fn asn1_name_string(value: &str) -> Vec<u8> {
    let printable = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&b));
    der(if printable { 0x13 } else { 0x0c }, value.as_bytes())
}

impl RootFields {
    pub(super) fn from_body(body: &Value, common_name: &str) -> Result<Self> {
        let extended = ROOT_FIELDS.iter().any(|field| body.get(*field).is_some());
        let exclude_cn = match body.get("exclude_cn_from_sans") {
            None => false,
            Some(Value::Bool(value)) => *value,
            _ => return Err(bad("invalid PKI exclude_cn_from_sans")),
        };
        let mut dns_sans = Vec::new();
        let mut email_sans = Vec::new();
        for value in bounded_list(body, "alt_names")? {
            if value.contains('@') {
                if !email_valid(&value) {
                    return Err(bad("invalid PKI email SAN"));
                }
                if !email_sans.contains(&value) {
                    email_sans.push(value);
                }
            } else {
                if !dns_valid(&value) {
                    return Err(bad("invalid PKI DNS SAN"));
                }
                if value != common_name && !dns_sans.contains(&value) {
                    dns_sans.push(value);
                }
            }
        }
        let mut ip_sans = ip_list(body.get("ip_sans"))?;
        if ip_sans.len() > 64 {
            return Err(bad("PKI IP SAN list is outside bounds"));
        }
        // A DNS CN is emitted by the certificate builder. Other CN types use
        // their actual GeneralName tag, never a DNS tag containing an IP/email.
        if !exclude_cn {
            if let Ok(ip) = common_name.parse::<IpAddr>() {
                if !ip_sans.contains(&ip) {
                    ip_sans.insert(0, ip);
                }
            } else if email_valid(common_name) && !email_sans.iter().any(|s| s == common_name) {
                email_sans.insert(0, common_name.into());
            }
        }
        let uri_sans = bounded_list(body, "uri_sans")?;
        if uri_sans.iter().any(|value| !uri_valid(value)) {
            return Err(bad("invalid PKI URI SAN"));
        }
        let backdate = ttl_field(body, "not_before_duration", 30)?;
        if backdate > MAX_TTL {
            return Err(bad("PKI root backdating is outside bounds"));
        }
        let max_path_length = match body.get("max_path_length") {
            None => None,
            Some(value) => match value.as_i64() {
                Some(-1) => None,
                Some(value) if (0..=i32::MAX as i64).contains(&value) => Some(value as u32),
                _ => return Err(bad("invalid PKI max_path_length")),
            },
        };
        let metadata = if extended {
            Some(LocalRootMetadata {
                issuer_name: alias(body, "issuer_name")?,
                key_name: alias(body, "key_name")?,
            })
        } else {
            None
        };
        Ok(Self {
            subject_der: if extended {
                distinguished_name(body, common_name)?
            } else {
                name(common_name)
            },
            dns_sans,
            email_sans,
            ip_sans,
            uri_sans,
            exclude_cn: exclude_cn
                || !dns_valid(common_name)
                || common_name.parse::<IpAddr>().is_ok(),
            backdate,
            max_path_length,
            metadata,
        })
    }
}

/// The signed certificate owns the issuer's entire DN. Parsing also works for
/// ML-DSA SPKI; the parser does not need to implement its signing algorithm.
pub(super) fn certificate_subject(der: &[u8]) -> Result<Vec<u8>> {
    let (rest, cert) =
        X509Certificate::from_der(der).map_err(|_| error(503, "invalid PKI issuer certificate"))?;
    if !rest.is_empty() {
        return Err(error(503, "invalid PKI issuer certificate"));
    }
    Ok(cert.subject().as_raw().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::{extensions::GeneralName, prelude::CertificateRevocationList};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn complete_root_dn_sans_constraints_and_reopened_leaf_crl_are_real() -> TestResult {
        for (kind, length, backdate, exclude) in [
            (LocalKeyKind::Rsa2048, 2, 90, false),
            (LocalKeyKind::Ec256, 0, 120, false),
            (LocalKeyKind::Ec384, 1, 45, true),
            (LocalKeyKind::Ed25519, 1, 0, false),
            (LocalKeyKind::Mldsa65, 1, 90, false),
        ] {
            let now = 1_700_000_000;
            let mut pki = Pki::default();
            let response = pki.handle_admin("POST", "root/generate/internal", &json!({
                "common_name":"ca.example.test","key_type":kind.key_type(),"key_bits":kind.bits(),
                "ttl":"24h","country":["US"],"province":["Synthetic State"],
                "locality":["Synthetic City"],"street_address":["1 Synthetic Street"],
                "postal_code":["00000"],"organization":["Synthetic Organization"],
                "ou":["Synthetic OU 1","Synthetic OU 2"],"serial_number":"subject-probe-01",
                "alt_names":"root.example.test,email@example.test",
                "ip_sans":"127.0.0.1,::1","uri_sans":"spiffe://heptabao.example.test/root",
                "max_path_length":length,"not_before_duration":backdate,
                "exclude_cn_from_sans":exclude,"issuer_name":"test-issuer","key_name":"test-key"
            }), now)?;
            assert!(
                response.body["data"]["issuer_name"] == "test-issuer",
                "persisted issuer alias"
            );
            assert!(
                response.body["data"]["key_name"] == "test-key",
                "persisted key alias"
            );
            let root = pki.root.as_ref().ok_or("root")?;
            let (_, cert) = X509Certificate::from_der(&root.certificate_der)?;
            let actual: Vec<_> = cert
                .subject()
                .iter_attributes()
                .map(|a| Ok((a.attr_type().to_id_string(), a.as_str()?.to_owned())))
                .collect::<std::result::Result<_, x509_parser::error::X509Error>>()?;
            let expected = [
                ("2.5.4.6", "US"),
                ("2.5.4.8", "Synthetic State"),
                ("2.5.4.7", "Synthetic City"),
                ("2.5.4.9", "1 Synthetic Street"),
                ("2.5.4.17", "00000"),
                ("2.5.4.10", "Synthetic Organization"),
                ("2.5.4.11", "Synthetic OU 1"),
                ("2.5.4.11", "Synthetic OU 2"),
                ("2.5.4.3", "ca.example.test"),
                ("2.5.4.5", "subject-probe-01"),
            ];
            assert!(
                actual
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .eq(expected),
                "actual full signed root DN"
            );
            assert!(cert.issuer() == cert.subject(), "root is self-issued");
            assert!(
                root.not_before == now - backdate && root.not_after == now + 86400,
                "backdating does not reduce requested TTL"
            );
            let basic = cert.basic_constraints()?.ok_or("basic constraints")?;
            assert!(
                basic.value.ca && basic.value.path_len_constraint == Some(length),
                "actual max path length including zero"
            );
            let san = cert.subject_alternative_name()?.ok_or("SAN")?;
            let mut expected = Vec::new();
            if !exclude {
                expected.push(GeneralName::DNSName("ca.example.test"));
            }
            expected.extend([
                GeneralName::DNSName("root.example.test"),
                GeneralName::RFC822Name("email@example.test"),
                GeneralName::IPAddress(&[127, 0, 0, 1]),
                GeneralName::IPAddress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                GeneralName::URI("spiffe://heptabao.example.test/root"),
            ]);
            assert!(
                san.value.general_names == expected,
                "actual typed SAN tags and ordering"
            );
            root.local_key()?
                .public()?
                .validate_certificate(&root.certificate_der)?;
            let root_subject = cert.subject().as_raw().to_vec();
            let issuer_public = root.local_key()?.public()?;
            let bytes = Zeroizing::new(serde_json::to_vec(&pki)?);
            let mut reopened: Pki = serde_json::from_slice(&bytes)?;
            reopened.validate("", "pki/", now)?;
            assert!(
                reopened.has_local_root_fields_state(),
                "extended reader requirement persists"
            );
            assert!(
                reopened.require_public_issuer("test-issuer").is_ok(),
                "reopened alias resolves"
            );
            reopened.handle_admin(
                "POST",
                "roles/web",
                &json!({
                    "allowed_domains":["example.test"],"allow_subdomains":true
                }),
                now,
            )?;
            let issued = reopened.issue(
                "pki/",
                "web",
                &json!({"common_name":"api.example.test"}),
                &serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?,
                None,
                now,
            )?;
            let serial = issued.body["data"]["serial_number"]
                .as_str()
                .ok_or("leaf serial")?;
            let der = &reopened
                .issued
                .get(serial)
                .ok_or("stored leaf")?
                .certificate_der;
            let (_, leaf) = X509Certificate::from_der(der)?;
            assert!(
                leaf.issuer().as_raw() == root_subject,
                "leaf uses the root's full actual DN"
            );
            assert!(
                issuer_public.verify(leaf.tbs_certificate.as_ref(), &leaf.signature_value.data)?,
                "reopened full-DN leaf has real issuer signature"
            );
            reopened.handle_admin("POST", "revoke", &json!({"serial_number":serial}), now + 1)?;
            let root = reopened.root.as_ref().ok_or("reopened root")?;
            let der = reopened.crl_der(root, now + 2)?;
            let (_, crl) = CertificateRevocationList::from_der(&der)?;
            assert!(
                crl.issuer().as_raw() == root_subject,
                "CRL uses the root's full actual DN"
            );
            assert!(
                issuer_public.verify(crl.tbs_cert_list.as_ref(), &crl.signature_value.data)?,
                "reopened full-DN CRL has real issuer signature"
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_root_fields_fail_before_key_or_root_publication() -> TestResult {
        for (field, value) in [
            ("max_path_length", json!(-2)),
            ("not_before_duration", json!(-1)),
            ("ip_sans", json!("not-an-ip")),
            ("uri_sans", json!("missing-uri-scheme")),
            ("ou", json!([1])),
            ("exclude_cn_from_sans", json!({})),
        ] {
            let mut pki = Pki::default();
            let mut body = json!({"common_name":"ca.example.test","key_type":"ec"});
            body[field] = value;
            assert!(
                pki.handle_admin("POST", "root/generate/internal", &body, 100)
                    .is_err(),
                "invalid certificate field rejected"
            );
            assert!(
                pki.root.is_none(),
                "failed root generation does not publish"
            );
        }
        Ok(())
    }
}
