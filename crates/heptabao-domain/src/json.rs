//! Bounded JSON token decoding shared by HTTP, durable owners, and SDK IPC.
//! A user object named like serde_json's private transport remains an object.
use serde::{
    Deserialize,
    de::{MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::fmt;
use zeroize::Zeroize;

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_NODES: usize = MAX_BYTES;
const MAX_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplicatePolicy {
    Reject,
    LastWins,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonError;
impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded lossless JSON rejected")
    }
}
impl std::error::Error for JsonError {}

struct Budget {
    nodes: usize,
    duplicates: DuplicatePolicy,
}
struct Sensitive(Value);
impl Drop for Sensitive {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}
fn erase(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(erase),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                erase(&mut value);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}

fn value(
    raw: &serde_json::value::RawValue,
    budget: &mut Budget,
    depth: usize,
) -> Result<Value, JsonError> {
    if depth > MAX_DEPTH || budget.nodes >= MAX_NODES {
        return Err(JsonError);
    }
    budget.nodes += 1;
    let text = raw.get().trim_matches([' ', '\t', '\n', '\r']);
    let mut decoder = serde_json::Deserializer::from_str(text);
    let first = text.as_bytes().first().copied().ok_or(JsonError)?;
    let decoded = match first {
        b'{' => serde::Deserializer::deserialize_map(&mut decoder, Container { budget, depth })
            .map_err(|_| JsonError)?,
        b'[' => serde::Deserializer::deserialize_seq(&mut decoder, Container { budget, depth })
            .map_err(|_| JsonError)?,
        b'"' => Value::String(serde_json::from_str::<String>(text).map_err(|_| JsonError)?),
        b't' => Value::Bool(true),
        b'f' => Value::Bool(false),
        b'n' => Value::Null,
        _ => {
            // The maintained arbitrary-precision parser reads "-0" through i64
            // and loses its sign. Keep the admitted negative-zero token in the
            // finite float category, while validating every other token normally.
            let number = if text == "-0" {
                serde_json::Number::from_f64(-0.0).ok_or(JsonError)?
            } else {
                serde_json::from_str::<serde_json::Number>(text).map_err(|_| JsonError)?
            };
            Value::Number(number)
        }
    };
    if matches!(first, b'{' | b'[') {
        decoder.end().map_err(|_| JsonError)?;
    }
    Ok(decoded)
}
struct Container<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
impl<'de> Visitor<'de> for Container<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON container")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Sensitive(Value::Array(Vec::new()));
        while let Some(raw) = seq.next_element::<&'de serde_json::value::RawValue>()? {
            let decoded =
                value(raw, self.budget, self.depth + 1).map_err(serde::de::Error::custom)?;
            if let Value::Array(array) = &mut values.0 {
                array.push(decoded);
            }
        }
        Ok(std::mem::take(&mut values.0))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Sensitive(Value::Object(serde_json::Map::new()));
        while let Some(mut key) = map.next_key::<String>()? {
            if self.budget.duplicates == DuplicatePolicy::Reject
                && values
                    .0
                    .as_object()
                    .is_some_and(|object| object.contains_key(&key))
            {
                key.zeroize();
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            let raw = map.next_value::<&'de serde_json::value::RawValue>()?;
            let decoded =
                value(raw, self.budget, self.depth + 1).map_err(serde::de::Error::custom)?;
            if let Value::Object(object) = &mut values.0 {
                // Preserve ordinary last-key semantics only at explicit callers.
                if let Some(mut previous) = object.remove(&key) {
                    erase(&mut previous);
                }
                object.insert(key, decoded);
            }
        }
        Ok(std::mem::take(&mut values.0))
    }
}

/// Strict decoding is the default. This API never samples a clock.
pub fn decode(bytes: &[u8]) -> Result<Value, JsonError> {
    decode_with_policy(bytes, DuplicatePolicy::Reject)
}
pub fn decode_with_policy(bytes: &[u8], duplicates: DuplicatePolicy) -> Result<Value, JsonError> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(JsonError);
    }
    let raw: &serde_json::value::RawValue = serde_json::from_slice(bytes).map_err(|_| JsonError)?;
    value(
        raw,
        &mut Budget {
            nodes: 0,
            duplicates,
        },
        0,
    )
}
/// Capture the actual text tokens before serde's generic Value representation.
/// serde_json's maintained ValueDeserializer also preserves this RawValue
/// newtype by serializing its already trusted Value without map coercion.
pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    if raw.get().len() > MAX_BYTES {
        return Err(serde::de::Error::custom(JsonError));
    }
    value(
        &raw,
        &mut Budget {
            nodes: 0,
            duplicates: DuplicatePolicy::Reject,
        },
        0,
    )
    .map_err(serde::de::Error::custom)
}

// Compare exact decimal values rather than spellings (1e2 equals 100). Accepted
// numbers must survive serde_json's existing number representation unchanged.
fn decimal(text: &str) -> Option<(bool, String, i32)> {
    if text.len() > 128 {
        return None;
    }
    let (negative, text) = text
        .strip_prefix('-')
        .map_or((false, text), |rest| (true, rest));
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
        None => (text, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = format!("{whole}{fraction}");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some((false, "0".into(), 0));
    }
    let coefficient = digits.trim_end_matches('0');
    let exponent = exponent
        .checked_sub(i32::try_from(fraction.len()).ok()?)?
        .checked_add(i32::try_from(digits.len() - coefficient.len()).ok()?)?;
    Some((negative, coefficient.into(), exponent))
}

pub fn requires_lossless_format(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.keys().any(|key| {
                key == "$serde_json::private::Number" || key == "$serde_json::private::RawValue"
            }) || map.values().any(requires_lossless_format)
        }
        Value::Array(values) => values.iter().any(requires_lossless_format),
        Value::Number(number) if number.as_i64().is_none() && number.as_u64().is_none() => {
            let text = number.to_string();
            number
                .as_f64()
                .and_then(serde_json::Number::from_f64)
                .is_none_or(|legacy| {
                    decimal(&text).is_none() || decimal(&text) != decimal(&legacy.to_string())
                })
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
