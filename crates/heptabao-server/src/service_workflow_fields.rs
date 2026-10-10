//! Public SDK2.7 FieldData coercions, bounded before any workflow effects.
//! Input remains data: the original raw parameter ACL and live actor own authorization.
use super::*;
use base64::Engine as _;
use chrono::{Datelike, Timelike};

fn invalid() -> Response {
    bad_profile("workflow field value has an unsupported shape or range")
}
// Go ParseFloat admits decimal/hexadecimal literals with checked underscores.
// Keep this conversion local to the public Float field. The existing workflow
// HTTP payload bound caps exact hex arithmetic; there is no additional
// per-field Float string limit. Round once, nearest with ties to even.
fn finite_go_float(raw: &str) -> Result<f64, Response> {
    if raw.is_empty() || raw.len() > crate::http::MAX_BODY || !raw.is_ascii() {
        return Err(invalid());
    }
    let bytes = raw.as_bytes();
    let start = matches!(bytes.first(), Some(b'+' | b'-')) as usize;
    let hex = bytes.get(start..start + 2).is_some_and(|prefix| {
        prefix[0] == b'0' && matches!(prefix[1], b'x' | b'X')
    });
    let digit = |b: u8| b.is_ascii_digit() || (hex && matches!(b, b'a'..=b'f' | b'A'..=b'F'));
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'_' {
            let previous = index > 0 && digit(bytes[index - 1]);
            let prefix = hex && index == start + 2;
            let next = bytes.get(index + 1).is_some_and(|b| digit(*b));
            if !(previous || prefix) || !next {
                return Err(invalid());
            }
        }
    }
    let clean: String = raw.chars().filter(|c| *c != '_').collect();
    let bytes = clean.as_bytes();
    let start = matches!(bytes.first(), Some(b'+' | b'-')) as usize;
    if !hex {
        let mut at = start;
        let mut digits = 0;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
            digits += 1;
        }
        if bytes.get(at) == Some(&b'.') {
            at += 1;
            while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
                digits += 1;
            }
        }
        if digits == 0 {
            return Err(invalid());
        }
        if bytes.get(at).is_some_and(|b| matches!(b, b'e' | b'E')) {
            at += 1;
            if bytes.get(at).is_some_and(|b| matches!(b, b'+' | b'-')) {
                at += 1;
            }
            let exponent_start = at;
            while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
            }
            if at == exponent_start {
                return Err(invalid());
            }
        }
        if at != bytes.len() {
            return Err(invalid());
        }
        let number = clean.parse::<f64>().map_err(|_| invalid())?;
        return number.is_finite().then_some(number).ok_or_else(invalid);
    }

    let negative = bytes.first() == Some(&b'-');
    let sign = if negative { 1_u64 << 63 } else { 0 };
    let mut at = start + 2;
    let mut point = false;
    let mut fractional = 0_i32;
    let mut bits = Vec::new();
    while let Some(&byte) = bytes.get(at) {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            b'.' if !point => {
                point = true;
                at += 1;
                continue;
            }
            _ => break,
        };
        for bit in (0..4).rev() {
            bits.push(nibble & (1 << bit) != 0);
        }
        if point {
            fractional += 1;
        }
        at += 1;
    }
    if bits.is_empty() || !bytes.get(at).is_some_and(|b| matches!(b, b'p' | b'P')) {
        return Err(invalid());
    }
    at += 1;
    let exponent_negative = bytes.get(at) == Some(&b'-');
    if bytes.get(at).is_some_and(|b| matches!(b, b'+' | b'-')) {
        at += 1;
    }
    let exponent_start = at;
    let mut exponent = 0_i32;
    while let Some(&byte) = bytes.get(at).filter(|b| b.is_ascii_digit()) {
        // This saturation is beyond every representable result under the
        // existing JSON string bound, including exact zero and underflow.
        exponent = (exponent * 10 + i32::from(byte - b'0')).min(1_000_000);
        at += 1;
    }
    if at == exponent_start || at != bytes.len() {
        return Err(invalid());
    }
    if exponent_negative {
        exponent = -exponent;
    }
    let Some(first) = bits.iter().position(|bit| *bit) else {
        return Ok(f64::from_bits(sign));
    };
    let bits = &bits[first..];
    exponent += bits.len() as i32 - 1 - 4 * fractional;
    if exponent > 1023 {
        return Err(invalid());
    }
    if exponent < -1075 {
        return Ok(f64::from_bits(sign));
    }
    let retained = (if exponent < -1022 { exponent + 1075 } else { 53 }) as usize;
    let mut significand = 0_u64;
    for at in 0..retained {
        significand = (significand << 1) | (bits.get(at).copied().unwrap_or(false) as u64);
    }
    let guard = bits.get(retained).copied().unwrap_or(false);
    let sticky = bits.iter().skip(retained + 1).any(|bit| *bit);
    if guard && (sticky || significand & 1 != 0) {
        significand += 1;
    }
    if exponent < -1022 {
        return Ok(f64::from_bits(sign | significand));
    }
    if significand == 1 << 53 {
        significand >>= 1;
        exponent += 1;
    }
    if exponent > 1023 {
        return Err(invalid());
    }
    Ok(f64::from_bits(
        sign | (((exponent + 1023) as u64) << 52) | (significand & ((1 << 52) - 1)),
    ))
}

pub(super) fn weak_string(value: &Value) -> Result<String, Response> {
    let text = match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(value) => if *value { "1" } else { "0" }.into(),
        _ => return Err(invalid()),
    };
    if text.len() > MAX_JSON_STRING_BYTES {
        return Err(invalid());
    }
    Ok(text)
}
fn weak_sequence(value: &Value) -> Result<Vec<String>, Response> {
    let values = match value {
        Value::Null => Vec::new(),
        Value::Object(values) if values.is_empty() => Vec::new(),
        Value::Array(values) => values.iter().map(weak_string).collect::<Result<_, _>>()?,
        _ => vec![weak_string(value)?],
    };
    if values.len() > 64 {
        return Err(invalid());
    }
    Ok(values)
}
fn weak_strings(value: &Value, comma: bool) -> Result<Vec<String>, Response> {
    let values = match value {
        Value::Null => Vec::new(),
        Value::Object(values) if values.is_empty() => Vec::new(),
        Value::String(text) if text.is_empty() => Vec::new(),
        Value::String(text) if comma => text.split(',').map(str::to_owned).collect(),
        Value::Array(values) => values.iter().map(weak_string).collect::<Result<_, _>>()?,
        _ => vec![weak_string(value)?],
    };
    if values.len() > 64 {
        return Err(invalid());
    }
    Ok(values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .collect())
}
pub(super) fn weak_int(value: &Value) -> Result<i64, Response> {
    match value {
        Value::Null => Ok(0),
        Value::Bool(value) => Ok(i64::from(*value)),
        Value::Number(value) => value.as_i64().ok_or_else(invalid),
        Value::String(value) => {
            let raw = if value.is_empty() { "0" } else { value };
            crate::auth::framework_signed_integer(raw).map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}
pub(super) fn weak_bool(value: &Value) -> Result<Value, Response> {
    match value {
        Value::Null => Ok(Value::Bool(false)),
        Value::Bool(value) => Ok(Value::Bool(*value)),
        Value::String(raw) => match raw.as_str() {
            "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(Value::Bool(true)),
            "" | "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(Value::Bool(false)),
            _ => Err(invalid()),
        },
        // Listener numbers retain their JSON lexical kind; ParseBool accepts
        // "0"/"1", not arbitrary nonzero numbers or a fractional spelling.
        Value::Number(raw) => match raw.to_string().as_str() {
            "1" => Ok(Value::Bool(true)),
            "0" => Ok(Value::Bool(false)),
            _ => Err(invalid()),
        },
        _ => Err(invalid()),
    }
}
pub(super) fn weak_map(value: &Value) -> Result<Value, Response> {
    match value {
        Value::Null => Ok(Value::Null),
        Value::Object(_) => Ok(value.clone()),
        Value::Array(values) => {
            // Public WeakDecode merges map elements in sequence order. Validate
            // every element before allocating copied values, so rejection has
            // no partial private map to drop outside an erase owner.
            if values.iter().any(|item| !item.is_object()) {
                return Err(invalid());
            }
            let mut owned = crate::http::ocsp::CarrierBody(json!({}));
            let result = owned.0.as_object_mut().ok_or_else(invalid)?;
            for item in values {
                for (key, value) in item.as_object().ok_or_else(invalid)? {
                    if let Some(mut previous) = result.insert(key.clone(), value.clone()) {
                        erase_json(&mut previous);
                    }
                }
            }
            Ok(std::mem::take(&mut owned.0))
        }
        _ => Err(invalid()),
    }
}
pub(super) fn weak_slice(value: &Value) -> Result<Value, Response> {
    match value {
        Value::Null => Ok(json!([])),
        Value::Array(_) => Ok(value.clone()),
        Value::Object(values) if values.is_empty() => Ok(json!([])),
        _ => Ok(json!([value.clone()])),
    }
}
fn pairs(value: &Value) -> Result<Value, Response> {
    if value.is_null() {
        return Ok(Value::Null);
    }
    let mut result = serde_json::Map::new();
    if let Some(object) = value.as_object() {
        if object.len() > 64 {
            return Err(invalid());
        }
        for (key, value) in object {
            result.insert(key.clone(), Value::String(weak_string(value)?));
        }
    } else {
        // SDK first attempts a weak map, then []string and SplitN("=", 2).
        // The sequence order determines the last value for a duplicate key.
        for pair in weak_sequence(value)? {
            let (key, value) = pair
                .split_once('=')
                .filter(|(key, _)| !key.is_empty())
                .ok_or_else(invalid)?;
            result.insert(key.to_owned(), Value::String(value.to_owned()));
        }
    }
    Ok(Value::Object(result))
}
fn header_name(raw: &str) -> String {
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~".contains(&b) || b == 96)
    {
        return raw.to_owned();
    }
    let mut upper = true;
    raw.chars()
        .map(|c| {
            let value = if upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            upper = c == '-';
            value
        })
        .collect()
}
fn headers(value: &Value) -> Result<Value, Response> {
    let decoded;
    let value = if let Some(text) = value.as_str() {
        if text.len() > MAX_JSON_STRING_BYTES {
            return Err(invalid());
        }
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .unwrap_or_else(|_| text.as_bytes().to_vec()),
        );
        decoded = heptabao_domain::json::decode_with_policy(
            &bytes,
            heptabao_domain::json::DuplicatePolicy::LastWins,
        )
        .map_err(|_| invalid())?;
        &decoded
    } else {
        value
    };
    let mut frame = crate::request_metadata::DataFrame::default();
    let mut add = |name: &str, value: String| {
        let values = frame.headers.entry(header_name(name)).or_default();
        values.push(value);
    };
    if value.is_null() {
        // A nil SDK header converts to a non-nil empty http.Header.
    } else if let Some(object) = value.as_object() {
        if object.len() > 64 {
            return Err(invalid());
        }
        for (name, value) in object {
            let values: Vec<&Value> = match value {
                Value::Array(values) => values.iter().collect(),
                _ => vec![value],
            };
            if values.len() > 64 {
                return Err(invalid());
            }
            for value in values {
                let text = match value {
                    Value::String(text) => text.clone(),
                    Value::Number(number) => number.to_string(),
                    _ => return Err(invalid()),
                };
                add(name, text);
            }
        }
    } else if let Some(values) = value.as_array() {
        if values.len() > 64 {
            return Err(invalid());
        }
        for value in values {
            let pair = value.as_str().ok_or_else(invalid)?;
            let (key, value) = pair
                .split_once(':')
                .filter(|(key, _)| !key.is_empty())
                .ok_or_else(invalid)?;
            add(key, value.to_owned());
        }
    } else {
        return Err(invalid());
    }
    // These are logical values, not raw HTTP lines. Preserve the SDK's data,
    // including CRLF strings; actual ingress and any consumer wire gate remain.
    let result = serde_json::to_value(&frame.headers).map_err(|_| invalid())?;
    let mut bytes = 0;
    bounded_json(&result, 0, &mut bytes).map_err(bad_profile)?;
    Ok(result)
}

#[derive(Clone, Copy)]
pub(super) enum FieldKind {
    Duration,
    SignedDuration,
    CommaStrings,
    Strings,
    Lowercase,
    Name,
    Pairs,
    CommaInts,
    Header,
    Float,
    Time,
}
impl FieldKind {
    pub(super) fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "duration_second" => Self::Duration,
            "signed_duration_second" => Self::SignedDuration,
            "comma_string_slice" => Self::CommaStrings,
            "string_slice" => Self::Strings,
            "lower_case_string" => Self::Lowercase,
            "name_string" => Self::Name,
            "kv_pairs" => Self::Pairs,
            "comma_int_slice" => Self::CommaInts,
            "header" => Self::Header,
            "float" => Self::Float,
            "time" => Self::Time,
            _ => return None,
        })
    }
    pub(super) fn runtime_value(self, value: &Value) -> Result<crate::workflow_runtime::Value, Response> {
        use crate::workflow_runtime::Value as RuntimeValue;
        if !matches!(self, Self::Float) {
            let mut converted = self.value(value)?;
            let result = RuntimeValue::from_json(&converted);
            erase_json(&mut converted);
            return Ok(result);
        }
        let number = match value {
            Value::Null => 0.0,
            Value::Bool(value) => f64::from(u8::from(*value)),
            Value::Number(number) => number.as_f64().filter(|value|value.is_finite()).ok_or_else(invalid)?,
            Value::String(raw) if raw.is_empty() => 0.0,
            Value::String(raw) if raw.len() <= crate::http::MAX_BODY => {
                if raw.eq_ignore_ascii_case("nan") { f64::NAN }
                else if raw.eq_ignore_ascii_case("inf") || raw.eq_ignore_ascii_case("infinity")
                    || raw.eq_ignore_ascii_case("+inf") || raw.eq_ignore_ascii_case("+infinity") { f64::INFINITY }
                else if raw.eq_ignore_ascii_case("-inf") || raw.eq_ignore_ascii_case("-infinity") { f64::NEG_INFINITY }
                else { finite_go_float(raw)? }
            }
            _ => return Err(invalid()),
        };
        Ok(RuntimeValue::float(number))
    }
    pub(super) fn value(self, value: &Value) -> Result<Value, Response> {
        match self {
            Self::Duration | Self::SignedDuration => {
                if value.is_null() {
                    return Ok(json!(0));
                }
                let raw = match value {
                    Value::String(raw) if raw.len() <= 128 => raw.clone(),
                    Value::Number(number) if number.as_i64().is_some() => number.to_string(),
                    _ => return Err(invalid()),
                };
                let ns = crate::auth::transit_rotation_duration(&raw).map_err(|_| invalid())?;
                // SDK uses int(time.Duration.Seconds()); retain its float
                // combination and truncation even close to a large whole second.
                let seconds = ((ns / 1_000_000_000) as f64
                    + (ns % 1_000_000_000) as f64 / 1_000_000_000.0)
                    .trunc() as i64;
                if matches!(self, Self::Duration) && seconds < 0 {
                    return Err(invalid());
                }
                Ok(json!(seconds))
            }
            Self::CommaStrings | Self::Strings => Ok(json!(weak_strings(
                value,
                matches!(self, Self::CommaStrings)
            )?)),
            Self::Lowercase | Self::Name => {
                let text = weak_string(value)?;
                if matches!(self, Self::Lowercase) {
                    // Go's strings.ToLower uses simple Unicode lowercasing.
                    // U+0130 is the one full-lowercase expansion in Rust's char API.
                    let lower: String = text
                        .chars()
                        .flat_map(|c| {
                            if c == '\u{130}' {
                                'i'.to_lowercase()
                            } else {
                                c.to_lowercase()
                            }
                        })
                        .collect();
                    Ok(Value::String(lower))
                } else {
                    let edge = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
                    if text.is_empty()
                        || !text.bytes().next().is_some_and(edge)
                        || !text.bytes().last().is_some_and(edge)
                        || !text.bytes().all(|b| edge(b) || b == b'.' || b == b'-')
                    {
                        return Err(invalid());
                    }
                    Ok(Value::String(text))
                }
            }
            Self::Pairs => pairs(value),
            Self::CommaInts => {
                let owned;
                let values: Vec<&Value> = match value {
                    Value::Null => Vec::new(),
                    Value::Object(values) if values.is_empty() => Vec::new(),
                    Value::String(text) if text.is_empty() => Vec::new(),
                    Value::String(text) => {
                        // Unlike string slices, the SDK does not trim these.
                        owned = text
                            .split(',')
                            .map(|s| Value::String(s.into()))
                            .collect::<Vec<_>>();
                        owned.iter().collect()
                    }
                    Value::Array(values) => values.iter().collect(),
                    _ => vec![value],
                };
                if values.len() > 64 {
                    return Err(invalid());
                }
                let values = values
                    .into_iter()
                    .map(weak_int)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(json!(values))
            }
            Self::Header => headers(value),
            Self::Float => {
                let number = match value {
                    Value::Null => 0.0,
                    Value::Bool(value) => f64::from(u8::from(*value)),
                    Value::Number(number) => number.as_f64().ok_or_else(invalid)?,
                    Value::String(raw) if raw.is_empty() => 0.0,
                    Value::String(raw) if raw.len() <= crate::http::MAX_BODY => {
                        finite_go_float(raw)?
                    }
                    _ => return Err(invalid()),
                };
                // This finite JSON bridge still rejects SDK nonfinite values
                // before effects. That is a known public wire/effect gap;
                // finite literal parsing here does not close that gap.
                if !number.is_finite() {
                    return Err(invalid());
                }
                Ok(json!(number))
            }
            Self::Time => {
                if value.is_null() {
                    return Ok(json!("0001-01-01T00:00:00Z"));
                }
                let time = if let Some(raw) = value.as_str() {
                    if raw.len() > 128 {
                        return Err(invalid());
                    }
                    if let Ok(time) = chrono::DateTime::parse_from_rfc3339(raw) {
                        time.with_timezone(&chrono::Utc)
                    } else {
                        let seconds = raw.parse::<i64>().map_err(|_| invalid())?;
                        chrono::DateTime::from_timestamp(seconds, 0).ok_or_else(invalid)?
                    }
                } else if let Some(seconds) = value.as_i64() {
                    chrono::DateTime::from_timestamp(seconds, 0).ok_or_else(invalid)?
                } else {
                    return Err(invalid());
                };
                if !(0..=9999).contains(&time.year()) || time.nanosecond() >= 1_000_000_000 {
                    return Err(invalid());
                }
                let mut formatted = time.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
                if let Some(point) = formatted.find('.') {
                    let trimmed = formatted[point + 1..formatted.len() - 1].trim_end_matches('0');
                    let end = if trimmed.is_empty() {
                        point
                    } else {
                        point + 1 + trimmed.len()
                    };
                    formatted.truncate(end);
                    formatted.push('Z');
                }
                Ok(Value::String(formatted))
            }
        }
    }
}
