//! Any subject-key policy is a durable role choice, never a private key kind.
//! Signing enforces maintained CSR algorithm minimums; issuing uses the actual
//! request's explicit kind without rewriting the stored role or its clock.
use super::*;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleKeyPolicy {
    // Genuine any roles retain even negative bit values. CSR ignores this field;
    // issue only uses it when the request did not provide an effective override.
    key_bits: i64,
}
impl RoleKeyPolicy {
    pub(super) fn from_body(body: &Value) -> Result<Option<Self>> {
        if Self::kind(body)?.as_deref() != Some("any") {
            return Ok(None);
        }
        Ok(Some(Self {
            key_bits: Self::bits(body)?.unwrap_or(0),
        }))
    }
    fn bits(body: &Value) -> Result<Option<i64>> {
        match body.get("key_bits") {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(0)),
            Some(Value::Bool(value)) => Ok(Some(i64::from(*value))),
            Some(Value::String(value)) if value.is_empty() => Ok(Some(0)),
            Some(Value::String(value)) => Self::parse_integer(value).map(Some),
            Some(Value::Number(value)) => Self::parse_integer(&value.to_string()).map(Some),
            Some(_) => Err(Self::invalid_bits()),
        }
    }
    // Genuine field decoding uses strconv.ParseInt with inferred base and the
    // machine's signed 64-bit integer range. Signs and separators are scalar
    // syntax only; the durable role still holds its unchanged typed i64 value.
    fn parse_integer(value: &str) -> Result<i64> {
        let (negative, digits) = match value.as_bytes().first() {
            Some(b'-') => (true, &value[1..]),
            Some(b'+') => (false, &value[1..]),
            _ => (false, value),
        };
        let (base, digits, prefixed) = if digits.starts_with("0x") || digits.starts_with("0X") {
            (16, &digits[2..], true)
        } else if digits.starts_with("0b") || digits.starts_with("0B") {
            (2, &digits[2..], true)
        } else if digits.starts_with("0o") || digits.starts_with("0O") {
            (8, &digits[2..], true)
        } else if digits.len() > 1 && digits.starts_with('0') {
            (8, &digits[1..], true)
        } else {
            (10, digits, false)
        };
        let mut canonical = String::with_capacity(digits.len());
        let mut after_digit = false;
        for (index, byte) in digits.bytes().enumerate() {
            if byte == b'_' {
                if !after_digit && !(prefixed && index == 0) {
                    return Err(Self::invalid_bits());
                }
                after_digit = false;
                continue;
            }
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err(Self::invalid_bits()),
            };
            if digit >= base {
                return Err(Self::invalid_bits());
            }
            canonical.push(char::from(byte));
            after_digit = true;
        }
        if !after_digit {
            return Err(Self::invalid_bits());
        }
        let magnitude = u64::from_str_radix(&canonical, base).map_err(|error| {
            if matches!(error.kind(), std::num::IntErrorKind::PosOverflow) {
                Self::bits_range_error()
            } else {
                Self::invalid_bits()
            }
        })?;
        if negative {
            if magnitude == (i64::MAX as u64) + 1 {
                Ok(i64::MIN)
            } else {
                i64::try_from(magnitude)
                    .map(|value| -value)
                    .map_err(|_| Self::bits_range_error())
            }
        } else {
            i64::try_from(magnitude).map_err(|_| Self::bits_range_error())
        }
    }
    fn bits_range_error() -> EngineError {
        bad(
            "Field validation failed: error converting input for field \"key_bits\": '' cannot parse value as 'int': strconv.ParseInt: value out of range",
        )
    }
    fn invalid_bits() -> EngineError {
        bad(
            "Field validation failed: error converting input for field \"key_bits\": '' cannot parse value as 'int': strconv.ParseInt: invalid syntax",
        )
    }
    fn kind(body: &Value) -> Result<Option<String>> {
        match body.get("key_type") {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(String::new())),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            Some(Value::Bool(value)) => Ok(Some(u8::from(*value).to_string())),
            Some(Value::Number(value)) => Ok(Some(value.to_string())),
            Some(_) => Err(bad("invalid PKI key type")),
        }
    }
    pub(super) fn validate(&self, role: &Role) -> Result<()> {
        if role.local_key_kind.is_some() || role.role_name_policy.is_none() {
            return Err(bad(
                "any subject-key policy requires its current role owner",
            ));
        }
        Ok(())
    }
    pub(super) fn descriptor(&self, descriptor: &mut Value) {
        descriptor["key_type"] = json!("any");
        descriptor["key_bits"] = json!(self.key_bits);
    }
    fn issue_kind(&self, body: &Value) -> Result<LocalKeyKind> {
        let kind = Self::kind(body)?
            .ok_or_else(|| bad(r#"role key type "any" not allowed for issuing certificates without providing key_type and/or key_bits request parameters"#))?;
        let bits = Self::bits(body)?.unwrap_or(self.key_bits);
        let resolved = match (kind.as_str(), bits) {
            ("rsa", 0 | 2048) => Some(LocalKeyKind::Rsa2048),
            ("rsa", 3072) => Some(LocalKeyKind::Rsa3072),
            ("rsa", 4096) => Some(LocalKeyKind::Rsa4096),
            ("rsa", 8192) => Some(LocalKeyKind::Rsa8192),
            ("ec", 224) => Some(LocalKeyKind::Ec224),
            ("ec", 0 | 256) => Some(LocalKeyKind::Ec256),
            ("ec", 384) => Some(LocalKeyKind::Ec384),
            ("ec", 521) => Some(LocalKeyKind::Ec521),
            ("ed25519", _) => Some(LocalKeyKind::Ed25519),
            ("mldsa", 0 | 44) => Some(LocalKeyKind::Mldsa44),
            ("mldsa", 65) => Some(LocalKeyKind::Mldsa65),
            ("mldsa", 87) => Some(LocalKeyKind::Mldsa87),
            _ => None,
        };
        if let Some(kind) = resolved {
            return Ok(kind);
        }
        let message = match kind.as_str() {
            "rsa" if bits < 2048 && bits != 0 => {
                format!("RSA keys < 2048 bits are unsafe and not supported: got {bits}")
            }
            "rsa" => format!("unsupported bit length for RSA key: {bits}"),
            "ec" => format!("unsupported bit length for EC key: {bits}"),
            "mldsa" => format!("unsupported bit length for ML-DSA key: {bits}"),
            _ => format!("unknown key type {kind}"),
        };
        Err(error(
            500,
            &format!("1 error occurred:\n\t* failed to validate role: {message}\n\n"),
        ))
    }
}
impl Role {
    pub(super) fn issue_key_kind(&self, body: &Value) -> Result<(LocalKeyKind, bool)> {
        if let Some(policy) = &self.role_key_policy {
            return Ok((policy.issue_kind(body)?, false));
        }
        RoleKeyPolicy::bits(body)?;
        RoleKeyPolicy::kind(body)?;
        let warning = body.get("key_type").is_some() || body.get("key_bits").is_some();
        Ok((
            self.local_key_kind.unwrap_or(LocalKeyKind::Ed25519),
            warning,
        ))
    }
}
impl Pki {
    pub(in crate::engines) fn has_key_policy_state(&self) -> bool {
        self.roles
            .values()
            .any(|role| role.role_key_policy.is_some())
    }
}
