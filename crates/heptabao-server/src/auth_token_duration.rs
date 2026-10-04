//! Pinned parseutil/Go signed duration parser shared by token fields.
//! Callers choose precise ordinary lease semantics or legacy Role-second truncation.
use super::token_policies;

pub(super) fn signed_int(raw: &str, base_zero: bool) -> Result<i64, &'static str> {
    let (negative, value) = if let Some(value) = raw.strip_prefix('-') {
        (true, value)
    } else {
        (false, raw.strip_prefix('+').unwrap_or(raw))
    };
    if value.is_empty() {
        return Err("invalid syntax");
    }
    let (base, digits, prefix) = if base_zero {
        if let Some(rest) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            (16_u32, rest, true)
        } else if let Some(rest) = value
            .strip_prefix("0b")
            .or_else(|| value.strip_prefix("0B"))
        {
            (2, rest, true)
        } else if let Some(rest) = value
            .strip_prefix("0o")
            .or_else(|| value.strip_prefix("0O"))
        {
            (8, rest, true)
        } else if value.len() > 1 && value.starts_with('0') {
            (8, &value[1..], true)
        } else {
            (10, value, false)
        }
    } else {
        (10, value, false)
    };
    if digits.is_empty() {
        return Err("invalid syntax");
    }
    let limit = i64::MAX as u64 + u64::from(negative);
    let mut total = 0_u64;
    let mut previous_digit = prefix;
    let mut saw_digit = false;
    for character in digits.chars() {
        if character == '_' && base_zero && previous_digit {
            previous_digit = false;
            continue;
        }
        let digit = character
            .to_digit(base)
            .filter(|_| character.is_ascii())
            .ok_or("invalid syntax")?;
        total = total
            .checked_mul(u64::from(base))
            .and_then(|value| value.checked_add(u64::from(digit)))
            .filter(|value| *value <= limit)
            .ok_or("value out of range")?;
        previous_digit = true;
        saw_digit = true;
    }
    if !previous_digit || !saw_digit {
        return Err("invalid syntax");
    }
    let signed = if negative {
        -i128::from(total)
    } else {
        i128::from(total)
    };
    i64::try_from(signed).map_err(|_| "value out of range")
}

pub(super) fn parse_duration(raw: &str) -> Result<i64, String> {
    const OVERFLOW: &str =
        "multiplication of durations resulted in overflow, one operand may be too large";
    if raw.is_empty() {
        return Ok(0);
    }
    if let Ok(seconds) = signed_int(raw, false) {
        return seconds
            .checked_mul(1_000_000_000)
            .ok_or_else(|| OVERFLOW.into());
    }
    if let Some(days) = raw.strip_suffix('d') {
        let days = signed_int(days, false).map_err(|error| {
            format!(
                "strconv.ParseInt: parsing {}: {error}",
                token_policies::quote_policy(days)
            )
        })?;
        return days
            .checked_mul(86_400_000_000_000)
            .ok_or_else(|| OVERFLOW.into());
    }
    let invalid = || format!("time: invalid duration {}", time_quote(raw));
    let (negative, mut input) = if let Some(rest) = raw.strip_prefix('-') {
        (true, rest)
    } else {
        (false, raw.strip_prefix('+').unwrap_or(raw))
    };
    if input == "0" {
        return Ok(0);
    }
    if input.is_empty() {
        return Err(invalid());
    }
    let limit = 1_u64 << 63;
    let mut total = 0_u64;
    while !input.is_empty() {
        let count = input.bytes().take_while(u8::is_ascii_digit).count();
        let whole = input[..count]
            .bytes()
            .try_fold(0_u64, |value, digit| {
                value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
            })
            .filter(|value| *value <= limit)
            .ok_or_else(invalid)?;
        input = &input[count..];
        let mut fraction = "";
        if let Some(rest) = input.strip_prefix('.') {
            let end = rest.bytes().take_while(u8::is_ascii_digit).count();
            fraction = &rest[..end];
            input = &rest[end..];
        }
        if count == 0 && fraction.is_empty() {
            return Err(invalid());
        }
        let end = input
            .char_indices()
            .find(|(_, c)| c.is_ascii_digit() || *c == '.')
            .map_or(input.len(), |(index, _)| index);
        if end == 0 {
            return Err(format!(
                "time: missing unit in duration {}",
                time_quote(raw)
            ));
        }
        let unit = match &input[..end] {
            "ns" => 1_u64,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            unit => {
                return Err(format!(
                    "time: unknown unit {} in duration {}",
                    time_quote(unit),
                    time_quote(raw)
                ));
            }
        };
        let mut significant = 0_u64;
        let mut scale = 1_f64;
        for digit in fraction.bytes() {
            if significant > i64::MAX as u64 / 10 {
                break;
            }
            let next = significant * 10 + u64::from(digit - b'0');
            if next > limit {
                break;
            }
            significant = next;
            scale *= 10.0;
        }
        let fractional_nanos = (significant as f64 * (unit as f64 / scale)) as u64;
        let segment = whole
            .checked_mul(unit)
            .and_then(|value| value.checked_add(fractional_nanos))
            .filter(|value| *value <= limit)
            .ok_or_else(invalid)?;
        total = total
            .checked_add(segment)
            .filter(|value| *value <= limit)
            .ok_or_else(invalid)?;
        input = &input[end..];
    }
    let signed = if negative {
        -i128::from(total)
    } else {
        i128::from(total)
    };
    i64::try_from(signed).map_err(|_| invalid())
}

// Go time's diagnostic quote deliberately escapes UTF-8 bytes outside printable
// ASCII; it differs from the Unicode policy warning formatter.
fn time_quote(raw: &str) -> String {
    let mut result = String::from("\"");
    for byte in raw.bytes() {
        if !(0x20..0x80).contains(&byte) {
            result.push_str(&format!("\\x{byte:02x}"));
        } else {
            if byte == b'"' || byte == b'\\' {
                result.push('\\');
            }
            result.push(char::from(byte));
        }
    }
    result.push('"');
    result
}
