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
    "not_after",
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

#[derive(Clone)]
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
                if (exclude_cn || value != common_name) && !dns_sans.contains(&value) {
                    dns_sans.push(value);
                }
            }
        }
        let ip_sans = ip_list(body.get("ip_sans"))?;
        if ip_sans.len() > 64 {
            return Err(bad("PKI IP SAN list is outside bounds"));
        }
        // The oracle treats an IPv4-shaped CN as a DNS SAN. Explicit ip_sans
        // alone selects the IP GeneralName tag; an email CN uses RFC822Name.
        if !exclude_cn && email_valid(common_name) && !email_sans.iter().any(|s| s == common_name) {
            email_sans.insert(0, common_name.into());
        }
        let uri_sans = bounded_list(body, "uri_sans")?;
        if uri_sans.iter().any(|value| !uri_valid(value)) {
            return Err(bad("invalid PKI URI SAN"));
        }
        let backdate = if matches!(body.get("not_before_duration"), None | Some(Value::Null)) {
            30
        } else {
            match ttl_field(body, "not_before_duration", 30)? {
                0 => 30,
                value => value,
            }
        };
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
            exclude_cn: exclude_cn || !dns_valid(common_name),
            backdate,
            max_path_length,
            metadata,
        })
    }
}

pub(super) fn root_expiration(
    body: &Value,
    now: u64,
    max_ttl: u64,
    default_ttl: u64,
) -> Result<u64> {
    resolve_root_expiration(body, now, max_ttl, default_ttl, false).map(|(expires, _)| expires)
}

pub(super) fn root_expiration_capped(
    body: &Value,
    now: u64,
    max_ttl: u64,
    default_ttl: u64,
) -> Result<(u64, Vec<String>)> {
    resolve_root_expiration(body, now, max_ttl, default_ttl, true)
}

fn resolve_root_expiration(
    body: &Value,
    now: u64,
    max_ttl: u64,
    default_ttl: u64,
    cap_ttl: bool,
) -> Result<(u64, Vec<String>)> {
    let not_after = match body.get("not_after") {
        None | Some(Value::Null) => "",
        Some(Value::String(value)) => value,
        _ => return Err(bad("invalid PKI not_after")),
    };
    let ttl = ttl_field(body, "ttl", 0)?;
    let requested_ttl = if ttl == 0 { default_ttl } else { ttl };
    let mut warnings = Vec::new();
    let ttl = if cap_ttl && not_after.is_empty() && requested_ttl > max_ttl {
        warnings.push(format!(
            "TTL \"{}\" is longer than permitted maxTTL \"{}\", so maxTTL is being used",
            role_time::go_duration(requested_ttl),
            role_time::go_duration(max_ttl)
        ));
        max_ttl
    } else if not_after.is_empty() {
        requested_ttl
    } else {
        ttl
    };
    let expiration = if !not_after.is_empty() {
        if ttl != 0 {
            return Err(bad(
                "Either ttl or not_after must be provided. Both should not be provided.",
            ));
        }
        rfc3339_seconds(not_after)?
    } else {
        now.checked_add(ttl)
            .ok_or_else(|| bad("PKI root TTL overflow"))?
    };
    if expiration <= now || (!cap_ttl && expiration - now > max_ttl) {
        return Err(bad("PKI root TTL is outside bounds"));
    }
    Ok((expiration, warnings))
}

pub(super) fn rfc3339_seconds(value: &str) -> Result<u64> {
    u64::try_from(rfc3339_signed_seconds(value)?).map_err(|_| bad("invalid PKI not_after"))
}

pub(super) fn rfc3339_signed_seconds(value: &str) -> Result<i64> {
    use openssl::asn1::Asn1Time;
    let invalid = || bad("invalid PKI not_after");
    let bytes = value.as_bytes();
    if !value.is_ascii()
        || bytes.len() < 20
        || bytes.len() > 40
        || [4, 7, 10, 13, 16]
            .into_iter()
            .zip(*b"--T::")
            .any(|(i, b)| bytes[i] != b)
        || (0..19)
            .filter(|i| ![4, 7, 10, 13, 16].contains(i))
            .any(|i| !bytes[i].is_ascii_digit())
        || value[17..19].parse::<u8>().map_or(true, |s| s >= 60)
    {
        return Err(invalid());
    }
    let mut zone = 19;
    if bytes[zone] == b'.' {
        zone += 1;
        let start = zone;
        while zone < bytes.len() && bytes[zone].is_ascii_digit() {
            zone += 1;
        }
        if zone == start || zone - start > 9 {
            return Err(invalid());
        }
    }
    let offset = &value[zone..];
    let offset_seconds = if offset == "Z" {
        0i64
    } else {
        let offset_bytes = offset.as_bytes();
        if offset_bytes.len() != 6
            || !matches!(offset_bytes[0], b'+' | b'-')
            || offset_bytes[3] != b':'
            || [1, 2, 4, 5]
                .into_iter()
                .any(|i| !offset_bytes[i].is_ascii_digit())
            || offset[1..3].parse::<u8>().map_or(true, |h| h >= 24)
            || offset[4..6].parse::<u8>().map_or(true, |m| m >= 60)
        {
            return Err(invalid());
        }
        let hours = offset[1..3].parse::<i64>().map_err(|_| invalid())?;
        let minutes = offset[4..6].parse::<i64>().map_err(|_| invalid())?;
        let seconds = hours * 3600 + minutes * 60;
        if offset_bytes[0] == b'+' {
            seconds
        } else {
            -seconds
        }
    };
    // Validate the local Gregorian calendar with the maintained ASN.1 parser,
    // then apply the validated RFC3339 offset. Some OpenSSL releases reject
    // offset-form ASN.1 times. X.509 encodes integer seconds.
    let stamp = format!(
        "{}{}{}{}{}{}Z",
        &value[..4],
        &value[5..7],
        &value[8..10],
        &value[11..13],
        &value[14..16],
        &value[17..19]
    );
    let parsed = Asn1Time::from_str(&stamp).map_err(|_| invalid())?;
    let epoch = Asn1Time::from_unix(0).map_err(|_| invalid())?;
    let diff = epoch.diff(&parsed).map_err(|_| invalid())?;
    let seconds = i64::from(diff.days) * 86400 + i64::from(diff.secs) - offset_seconds;
    if !(-62_167_219_200..=253_402_300_799).contains(&seconds) {
        return Err(invalid());
    }
    Ok(seconds)
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

/// RFC 5280 method 1, also used by the pinned OpenBao certutil implementation.
/// SHA-1 identifies the public key bits; signing authority still requires the
/// owned certificate, actual key binding and full signature verification.
pub(super) fn subject_key_identifier(spki: &[u8]) -> Result<[u8; 20]> {
    let (rest, public) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki)
        .map_err(|_| error(503, "invalid PKI key identifier input"))?;
    if !rest.is_empty() || public.subject_public_key.unused_bits != 0 {
        return Err(error(503, "invalid PKI key identifier input"));
    }
    Ok(openssl::sha::sha1(public.subject_public_key.data.as_ref()))
}

pub(super) fn certificate_key_identifier(der: &[u8]) -> Result<Option<Vec<u8>>> {
    let (rest, cert) =
        X509Certificate::from_der(der).map_err(|_| error(503, "invalid PKI issuer certificate"))?;
    if !rest.is_empty() {
        return Err(error(503, "invalid PKI issuer certificate"));
    }
    let mut identifier = None;
    for extension in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(key) =
            extension.parsed_extension()
        {
            if identifier.is_some() || key.0.is_empty() || key.0.len() > 64 {
                return Err(error(503, "invalid PKI issuer key identifier"));
            }
            identifier = Some(key.0.to_vec());
        }
    }
    Ok(identifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::{extensions::GeneralName, prelude::CertificateRevocationList};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn root_expiry_and_zero_backdating_match_actual_time_oracle() -> TestResult {
        let now = 1_700_000_000;
        for value in ["2023-11-15T22:13:20Z", "2023-11-16T06:13:20+08:00"] {
            let mut pki = Pki::default();
            pki.handle_admin(
                "POST",
                "root/generate/internal",
                &json!({
                    "common_name":"ca.example.test","key_type":"ec","not_after":value
                }),
                now,
            )?;
            let root = pki.root.as_ref().ok_or("root")?;
            assert!(
                root.not_after == now + 86400 && root.not_before == now - 30,
                "actual UTC and timezone expiration select same signed window"
            );
        }
        for value in [Value::Null, json!(0), json!("0")] {
            let mut pki = Pki::default();
            pki.handle_admin(
                "POST",
                "root/generate/internal",
                &json!({
                    "common_name":"ca.example.test","key_type":"ec",
                    "not_before_duration":value,"ttl":0
                }),
                now,
            )?;
            let root = pki.root.as_ref().ok_or("root")?;
            assert!(
                root.not_before == now - 30 && root.not_after == now + 2764800,
                "zero/default root durations match actual 32-day and 30-second defaults"
            );
        }
        for body in [
            json!({"not_after":"2023-11-15T22:13:20Z","ttl":"24h"}),
            json!({"not_after":"2023-02-30T22:13:20Z"}),
            json!({"not_after":"2023-11-15T22:13:60Z"}),
            json!({"not_after":"2023-11-15T22:13:20+25:00"}),
            json!({"not_after":"2022-11-15T22:13:20Z"}),
        ] {
            assert!(
                root_expiration(&body, now, MAX_TTL, DEFAULT_ROOT_TTL).is_err(),
                "conflicting malformed or expired windows rejected"
            );
        }
        for (cn, exclude, expected) in [
            (
                "email@example.test",
                false,
                Some(GeneralName::RFC822Name("email@example.test")),
            ),
            ("email@example.test", true, None),
            ("127.0.0.1", false, Some(GeneralName::DNSName("127.0.0.1"))),
            ("127.0.0.1", true, None),
        ] {
            let mut pki = Pki::default();
            pki.handle_admin(
                "POST",
                "root/generate/internal",
                &json!({
                    "common_name":cn,"key_type":"ec","exclude_cn_from_sans":exclude
                }),
                now,
            )?;
            let root = pki.root.as_ref().ok_or("root")?;
            let (_, cert) = X509Certificate::from_der(&root.certificate_der)?;
            let san = cert.subject_alternative_name()?;
            assert!(
                match (san, expected) {
                    (None, None) => true,
                    (Some(san), Some(expected)) => san.value.general_names == [expected],
                    _ => false,
                },
                "actual email and IPv4-shaped CN SAN behavior"
            );
        }
        Ok(())
    }

    #[test]
    fn root_mount_defaults_cap_warnings_and_absolute_override_match_native() -> TestResult {
        let now = 1_700_000_000;
        let pki = Pki::default();
        assert_eq!((pki.default_ttl, pki.max_ttl), (2_764_800, 2_764_800));
        for (fields, expiration, capped) in [
            (json!({"ttl":"4h"}), now + 600, true),
            (json!({}), now + 300, false),
            (json!({"ttl":0}), now + 300, false),
            (json!({"ttl":"0s"}), now + 300, false),
            (
                json!({"not_after":"2023-11-15T00:13:20Z"}),
                now + 7200,
                false,
            ),
        ] {
            let mut pki = Pki::default();
            pki.tune(&json!({"default_lease_ttl":"5m","max_lease_ttl":"10m"}))?;
            let mut body = json!({"common_name":"ca.example.test","key_type":"ec"});
            body.as_object_mut()
                .ok_or("root body")?
                .extend(fields.as_object().ok_or("root time fields")?.clone());
            let response = pki.handle_admin("POST", "root/generate/internal", &body, now)?;
            assert_eq!(response.body["data"]["expiration"], expiration);
            let warnings = response.body["warnings"]
                .as_array()
                .ok_or("root warnings")?;
            assert_eq!(warnings.len(), if capped { 2 } else { 1 });
            if capped {
                assert_eq!(
                    warnings[0],
                    "TTL \"4h0m0s\" is longer than permitted maxTTL \"10m0s\", so maxTTL is being used"
                );
            }
            let root = pki.root.as_ref().ok_or("stored root")?;
            let (_, cert) = X509Certificate::from_der(&root.certificate_der)?;
            assert_eq!(
                cert.validity().not_after.timestamp(),
                i64::try_from(expiration)?
            );
            root.local_key()?
                .public()?
                .validate_certificate(&root.certificate_der)?;
            let bytes = Zeroizing::new(serde_json::to_vec(&pki)?);
            let reopened: Pki = serde_json::from_slice(&bytes)?;
            reopened.validate("", "pki/", now)?;
            assert_eq!(
                reopened
                    .root
                    .as_ref()
                    .ok_or("reopened root")?
                    .certificate_der,
                root.certificate_der
            );
        }
        Ok(())
    }

    #[test]
    fn complete_root_dn_sans_constraints_and_reopened_leaf_crl_are_real() -> TestResult {
        for (kind, length, backdate, exclude) in [
            (LocalKeyKind::Rsa2048, 2, 90, false),
            (LocalKeyKind::Ec256, 0, 120, false),
            (LocalKeyKind::Ec384, 1, 45, true),
            (LocalKeyKind::Ed25519, 1, 30, false),
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
                &json!({"common_name":"api.example.test","ttl":"1h"}),
                &serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?,
                None,
                now,
            )?;
            let serial = issued.body["data"]["serial_number"]
                .as_str()
                .ok_or("leaf serial")?;
            let der = &reopened
                .issued
                .get(&normalize_serial(serial)?)
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
