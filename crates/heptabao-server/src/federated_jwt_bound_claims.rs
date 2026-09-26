//! Bound claims for native JWT login. These values are interpreted only after
//! signature verification; OIDC UserInfo and the proof API use other contracts.
use super::*;

#[derive(Clone, Copy, Debug, serde::Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NativeJwtBoundClaimsType {
    String,
    Glob,
}

impl NativeJwtBoundClaimsType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Glob => "glob",
        }
    }
}

#[derive(Clone, serde::Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeJwtBoundClaims {
    pub(crate) kind: NativeJwtBoundClaimsType,
    pub(crate) claims: BTreeMap<String, Value>,
}

impl fmt::Debug for NativeJwtBoundClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeJwtBoundClaims")
            .field("kind", &self.kind)
            .field("claim_count", &self.claims.len())
            .finish_non_exhaustive()
    }
}

impl NativeJwtBoundClaims {
    pub(crate) fn matches(&self, claims: &BTreeMap<String, Value>) -> bool {
        self.claims.iter().all(|(selector, expected)| {
            let Some(actual) = selected_claim(claims, selector) else {
                return false;
            };
            let Some(expected_values) = alternatives(expected) else {
                return false;
            };
            let Some(actual_values) = alternatives(actual) else {
                return false;
            };
            // OpenBao converts a scalar float from the signed payload to an
            // integer JSON number. Elements of claim arrays are not converted.
            let scalar_number = actual.is_number();
            for expected in expected_values {
                // A mode-only role update can retain an old nonstring map.
                // The pinned implementation errors when it reaches that
                // expected value; it must not skip forward to a later match.
                if self.kind == NativeJwtBoundClaimsType::Glob && !expected.is_string() {
                    return false;
                }
                if actual_values.iter().any(|actual| match self.kind {
                    NativeJwtBoundClaimsType::String => exact(expected, actual, scalar_number),
                    NativeJwtBoundClaimsType::Glob => match (expected.as_str(), actual.as_str()) {
                        (Some(pattern), Some(value)) => glob(pattern, value),
                        _ => false,
                    },
                }) {
                    return true;
                }
            }
            false
        })
    }
}

fn alternatives(value: &Value) -> Option<&[Value]> {
    match value {
        Value::Array(values) => Some(values),
        Value::String(_) | Value::Bool(_) | Value::Number(_) => Some(std::slice::from_ref(value)),
        // Scalar null is missing, while a null element in a list can match.
        Value::Null | Value::Object(_) => None,
    }
}

fn exact(expected: &Value, actual: &Value, scalar_number: bool) -> bool {
    match (expected, actual) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(expected), Value::Bool(actual)) => expected == actual,
        (Value::String(expected), Value::String(actual)) => expected == actual,
        (Value::Number(expected), Value::Number(actual)) if scalar_number => {
            // Config JSON numbers retain their lexical integer/float category.
            // 42.0, 42e0 and -0 are not the integer JSON number "42" or "0".
            // All payload numbers pass through f64, including JSON integers,
            // matching the pinned verifier's rounding above 2^53.
            let Some(expected) = expected.as_i64() else {
                return false;
            };
            let Some(actual) = actual.as_f64() else {
                return false;
            };
            // Go's out-of-range float-to-int conversion is implementation
            // dependent. Fail closed beyond the supported signed 64-bit range.
            actual.is_finite()
                && (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&actual)
                && expected == actual as i64
        }
        _ => false,
    }
}

/// go-glob v1.0.0 treats only '*' as special, including across path separators.
fn glob(pattern: &str, mut value: &str) -> bool {
    let Some((prefix, rest)) = pattern.split_once('*') else {
        return pattern == value;
    };
    let Some(after_prefix) = value.strip_prefix(prefix) else {
        return false;
    };
    value = after_prefix;
    let mut pieces = rest.split('*').peekable();
    while let Some(piece) = pieces.next() {
        if pieces.peek().is_none() {
            return value.ends_with(piece);
        }
        let Some(offset) = value.find(piece) else {
            return false;
        };
        value = &value[offset + piece.len()..];
    }
    true
}

fn selected_claim<'a>(claims: &'a BTreeMap<String, Value>, selector: &str) -> Option<&'a Value> {
    let Some(pointer) = selector.strip_prefix('/') else {
        return claims.get(selector);
    };
    let mut parts = pointer.split('/');
    let first = parts.next()?.replace("~1", "/").replace("~0", "~");
    let mut value = claims.get(&first)?;
    for part in parts {
        // pointerstructure v1.2.1 preserves unrecognized '~' escapes.
        let part = part.replace("~1", "/").replace("~0", "~");
        value = match value {
            Value::Object(fields) => fields.get(&part)?,
            Value::Array(items) => items.get(pointer_index(&part)?)?,
            _ => return None,
        };
    }
    Some(value)
}

/// pointerstructure's WeakDecode uses strconv.ParseInt with base 0. It also
/// normalizes an empty string to zero, unlike a strict RFC 6901 array parser.
fn pointer_index(value: &str) -> Option<usize> {
    if value.is_empty() {
        return Some(0);
    }
    let (negative, digits) = if let Some(value) = value.strip_prefix('-') {
        (true, value)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    if digits.is_empty() {
        return None;
    }
    let (radix, digits, prefix) = if digits.starts_with("0x") || digits.starts_with("0X") {
        (16, &digits[2..], true)
    } else if digits.starts_with("0b") || digits.starts_with("0B") {
        (2, &digits[2..], true)
    } else if digits.starts_with("0o") || digits.starts_with("0O") {
        (8, &digits[2..], true)
    } else if digits.starts_with('0') {
        (8, digits, false)
    } else {
        (10, digits, false)
    };
    let mut integer = 0u64;
    let mut previous_digit = false;
    for (index, byte) in digits.bytes().enumerate() {
        if byte == b'_' {
            if !(previous_digit || index == 0 && prefix) {
                return None;
            }
            previous_digit = false;
            continue;
        }
        let digit = char::from(byte).to_digit(radix)?;
        integer = integer
            .checked_mul(u64::from(radix))?
            .checked_add(u64::from(digit))?;
        previous_digit = true;
    }
    if !previous_digit || negative && integer != 0 || integer > i64::MAX as u64 {
        return None;
    }
    usize::try_from(integer).ok()
}

#[cfg(test)]
#[path = "federated_jwt_bound_claims_tests.rs"]
mod tests;
