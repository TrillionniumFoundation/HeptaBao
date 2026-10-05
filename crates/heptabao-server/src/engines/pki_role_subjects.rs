//! Captured subject attributes, otherName SANs and certificate policy DER.
use super::*;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct LeafSubjectEvidence {
    pub(super) serial_number: String,
    pub(super) user_ids: Vec<String>,
    pub(super) other_sans: BTreeMap<String, Vec<String>>,
    pub(super) policy_identifiers: Vec<String>,
}

impl RoleNamePolicy {
    pub(super) fn capture_subject(
        &self,
        body: &Value,
        mut profile: RoleLeafProfile,
    ) -> Result<RoleLeafProfile> {
        let serial_number = match body.get("serial_number") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(value)) => value.clone(),
            _ => return Err(bad("serial_number must be a string")),
        };
        if !serial_number.is_empty()
            && !self.allowed_serial_numbers.iter().any(|pattern| {
                !pattern.is_empty() && role_names::glob_match(pattern, &serial_number)
            })
        {
            return Err(bad(&format!(
                "serial_number {serial_number} not allowed by this role"
            )));
        }
        let user_ids = request_list(body, "user_ids")?;
        for value in &user_ids {
            if !self.allowed_user_ids.iter().any(|pattern| {
                pattern.eq_ignore_ascii_case(value)
                    || pattern.contains('*') && role_names::glob_match(pattern, value)
            }) {
                return Err(bad(&format!("user_id {value} is not allowed by this role")));
            }
        }
        let other_sans = parse_other_sans(&request_list(body, "other_sans")?).map_err(|cause| {
            bad(&format!(
                "could not parse requested other SAN: {}",
                cause.message
            ))
        })?;
        if self.allowed_other_sans != ["*"] {
            let allowed = parse_other_sans(&self.allowed_other_sans)?;
            for (oid, values) in &other_sans {
                let patterns = allowed
                    .get(oid)
                    .ok_or_else(|| bad(&format!("other SAN OID {oid} not allowed by this role")))?;
                for value in values {
                    if !patterns
                        .iter()
                        .any(|pattern| role_names::glob_match(pattern, value))
                    {
                        return Err(bad(&format!(
                            "other SAN {value} not allowed for OID {oid} by this role"
                        )));
                    }
                }
            }
        }
        let evidence = LeafSubjectEvidence {
            serial_number,
            user_ids,
            other_sans,
            policy_identifiers: self.policy_identifiers.clone(),
        };
        evidence.validate()?;
        if evidence != LeafSubjectEvidence::default() {
            profile.leaf_subject_evidence = Some(evidence);
        }
        Ok(profile)
    }

    pub(super) fn validate_subject_capture(
        &self,
        captured: Option<&LeafSubjectEvidence>,
    ) -> Result<()> {
        let body = if let Some(evidence) = captured {
            json!({"serial_number":evidence.serial_number,"user_ids":evidence.user_ids,
                "other_sans": evidence.other_sans.iter().flat_map(|(oid,values)| values.iter().map(move|value|format!("{oid};UTF8:{value}"))).collect::<Vec<_>>()})
        } else {
            json!({})
        };
        let expected = self.capture_subject(&body, RoleLeafProfile::default())?;
        if captured != expected.leaf_subject_evidence.as_ref() {
            return Err(bad(
                "PKI captured subject policy and signed attributes differ",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_subject_policy(&self) -> Result<()> {
        for values in [
            &self.allowed_serial_numbers,
            &self.allowed_user_ids,
            &self.allowed_other_sans,
            &self.policy_identifiers,
        ] {
            if values.len() > 64
                || values
                    .iter()
                    .any(|value| !role_names::bounded_subject(value))
            {
                return Err(bad("PKI subject policy is outside bounds"));
            }
        }
        if self.allowed_other_sans != ["*"] {
            parse_other_sans(&self.allowed_other_sans).map_err(|cause| {
                bad(&format!(
                    "error parsing allowed_other_sans: {}",
                    cause.message
                ))
            })?;
        }
        policies_der(&self.policy_identifiers)?;
        Ok(())
    }
}

fn request_list(body: &Value, field: &str) -> Result<Vec<String>> {
    body.get(field)
        .map(|value| role_leaf_profile::weak_comma_list(field, value))
        .transpose()
        .map(|value| value.unwrap_or_default())
}

pub(super) fn parse_other_sans(values: &[String]) -> Result<BTreeMap<String, Vec<String>>> {
    let mut parsed = BTreeMap::<String, Vec<String>>::new();
    for value in values {
        let (oid, tail) = value.split_once(';').ok_or_else(|| {
            bad(&format!(
                "expected a semicolon in other SAN {}",
                quote(value)
            ))
        })?;
        let (kind, text) = tail
            .split_once(':')
            .ok_or_else(|| bad(&format!("expected a colon in other SAN {}", quote(value))))?;
        if !kind.eq_ignore_ascii_case("utf8") && !kind.eq_ignore_ascii_case("utf-8") {
            return Err(bad(&format!(
                "only utf8 other SANs are supported; found non-supported type in other SAN {}",
                quote(value)
            )));
        }
        parsed.entry(oid.into()).or_default().push(text.into());
    }
    Ok(parsed)
}

impl LeafSubjectEvidence {
    pub(super) fn validate(&self) -> Result<()> {
        if !role_names::bounded_subject(&self.serial_number)
            || self.user_ids.len() > 32
            || self
                .user_ids
                .iter()
                .any(|value| !role_names::bounded_subject(value))
            || self.other_sans.len() > 32
            || self.other_sans.values().map(Vec::len).sum::<usize>() > 32
            || self
                .other_sans
                .values()
                .flatten()
                .any(|value| !role_names::bounded_subject(value))
        {
            return Err(bad("captured PKI subject is outside bounds"));
        }
        for oid in self.other_sans.keys() {
            role_leaf_profile::encoded_oid(oid)?;
        }
        policies_der(&self.policy_identifiers)?;
        Ok(())
    }
    pub(super) fn subject_der(&self, base: Vec<u8>) -> Result<Vec<u8>> {
        let content = sequence_content(&base)?;
        let mut content = content.to_vec();
        if !self.serial_number.is_empty() {
            content.extend(set(&[seq(&[
                oid(&[0x55, 0x04, 5]),
                role_leaf_profile::name_string(self.serial_number.as_bytes()),
            ])]));
        }
        for user in &self.user_ids {
            content.extend(set(&[seq(&[
                role_leaf_profile::encoded_oid("0.9.2342.19200300.100.1.1")?,
                role_leaf_profile::name_string(user.as_bytes()),
            ])]));
        }
        Ok(der(0x30, &content))
    }
    pub(super) fn other_names_der(&self) -> Result<Vec<Vec<u8>>> {
        self.other_sans
            .iter()
            .flat_map(|(oid, values)| values.iter().map(move |value| (oid, value)))
            .map(|(oid, value)| {
                let mut content = role_leaf_profile::encoded_oid(oid)?;
                content.extend(context_explicit(0, &utf8(value.as_bytes())));
                Ok(der(0xa0, &content))
            })
            .collect()
    }
    // Numeric OIDs use Go's standard policy extension; qualified policies
    // follow the SDK's otherName override in ExtraExtensions.
    pub(super) fn policy_uses_extra_extension(&self) -> bool {
        self.policy_identifiers
            .iter()
            .any(|value| !value.split('.').all(|part| part.parse::<i64>().is_ok()))
    }
    pub(super) fn policies_der(&self) -> Result<Option<Vec<u8>>> {
        policies_der(&self.policy_identifiers)
    }
}

fn sequence_content(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.first() != Some(&0x30) || bytes.len() < 2 {
        return Err(bad("invalid captured subject sequence"));
    }
    let (header, len) = if bytes[1] < 128 {
        (2, usize::from(bytes[1]))
    } else {
        let count = usize::from(bytes[1] & 0x7f);
        if count == 0 || count > 8 || 2 + count > bytes.len() {
            return Err(bad("invalid captured subject length"));
        }
        let len = bytes[2..2 + count]
            .iter()
            .try_fold(0usize, |len, byte| {
                len.checked_mul(256)
                    .and_then(|len| len.checked_add(usize::from(*byte)))
            })
            .ok_or_else(|| bad("captured subject length overflow"))?;
        (2 + count, len)
    };
    if header + len != bytes.len() {
        return Err(bad("invalid captured subject content"));
    }
    Ok(&bytes[header..])
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct PolicyQualifier {
    oid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    cps: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    notice: String,
}

pub(super) fn policy_strings(value: &Value) -> Result<Vec<String>> {
    if let Value::String(text) = value
        && let Ok(entries) = serde_json::from_str::<Vec<PolicyQualifier>>(text)
    {
        return entries
            .into_iter()
            .map(|entry| serde_json::to_string(&entry).map_err(|_| bad("invalid qualified policy")))
            .collect();
    }
    role_leaf_profile::weak_comma_list("policy_identifiers", value)
}

pub(super) fn policies_der(values: &[String]) -> Result<Option<Vec<u8>>> {
    if values.is_empty() {
        return Ok(None);
    }
    let mut policies = Vec::new();
    for value in values {
        if value.is_empty() {
            continue;
        }
        let entry = if value.split('.').all(|part| part.parse::<i64>().is_ok()) {
            PolicyQualifier {
                oid: value.clone(),
                ..Default::default()
            }
        } else {
            serde_json::from_str::<PolicyQualifier>(value).map_err(|_| {
                let segment = value.split('.').find(|part| part.parse::<i64>().is_err()).unwrap_or(value);
                let first = value.trim_start().chars().next().unwrap_or(' ');
                error(500, &format!("1 error occurred:\n\t* policy identifier {} is neither a valid OID: strconv.Atoi: parsing {}: invalid syntax, Nor JSON Policy Identifier: invalid character '{}' looking for beginning of value\n\n", quote(value), quote(segment), first.escape_default()))
            })?
        };
        let mut fields = vec![role_leaf_profile::encoded_oid(&entry.oid)?];
        let mut qualifiers = Vec::new();
        if !entry.cps.is_empty() {
            if !entry.cps.is_ascii() {
                return Err(error(500, "asn1: string not valid"));
            }
            qualifiers.push(seq(&[
                role_leaf_profile::encoded_oid("1.3.6.1.5.5.7.2.1")?,
                der(0x16, entry.cps.as_bytes()),
            ]));
        }
        if !entry.notice.is_empty() {
            qualifiers.push(seq(&[
                role_leaf_profile::encoded_oid("1.3.6.1.5.5.7.2.2")?,
                seq(&[utf8(entry.notice.as_bytes())]),
            ]));
        }
        if !qualifiers.is_empty() {
            fields.push(seq(&qualifiers));
        }
        policies.push(seq(&fields));
    }
    Ok(Some(extension(&[0x55, 0x1d, 0x20], false, &seq(&policies))))
}
fn quote(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_default()
}
