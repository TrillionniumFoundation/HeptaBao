//! Bounded listener duration syntax; no floating-point budget inflation.
//! This parser does not change transport deadlines or authorize request retries.
use std::time::Duration;

const MAX_NANOS: u64 = 60_000_000_000;
const INVALID: &str = "invalid consistency_max_index_wait duration";
const OVER_BUDGET: &str = "consistency_max_index_wait exceeds the bounded listener budget";

pub(super) fn parse(raw: &str) -> Result<Duration, &'static str> {
    if raw.is_empty() || raw.len() > 128 {
        return Err(INVALID);
    }
    let mut input = raw.strip_prefix('+').unwrap_or(raw);
    if input == "0" {
        return Ok(Duration::ZERO);
    }
    if input.is_empty() {
        return Err(INVALID);
    }
    let mut total = 0_u64;
    while !input.is_empty() {
        let digits = input.bytes().take_while(u8::is_ascii_digit).count();
        let whole = input[..digits]
            .bytes()
            .try_fold(0_u64, |value, digit| {
                value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
            })
            .ok_or(OVER_BUDGET)?;
        input = &input[digits..];
        let mut fraction = "";
        if let Some(rest) = input.strip_prefix('.') {
            let count = rest.bytes().take_while(u8::is_ascii_digit).count();
            fraction = &rest[..count];
            input = &rest[count..];
        }
        if digits == 0 && fraction.is_empty() {
            return Err(INVALID);
        }
        let end = input
            .char_indices()
            .find(|(_, c)| c.is_ascii_digit() || *c == '.')
            .map_or(input.len(), |(position, _)| position);
        let unit = match &input[..end] {
            "ns" => 1_u64,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(INVALID),
        };
        // Work from right to left to floor the fraction at nanosecond precision.
        // Each carry is smaller than unit; the maximum intermediate is 10*unit.
        // This is exact even for fractions longer than machine integers can hold.
        let fractional_nanos = fraction.bytes().rev().fold(0_u64, |carry, digit| {
            (u64::from(digit - b'0') * unit + carry) / 10
        });
        let segment = whole
            .checked_mul(unit)
            .and_then(|value| value.checked_add(fractional_nanos))
            .ok_or(OVER_BUDGET)?;
        total = total
            .checked_add(segment)
            .filter(|value| *value <= MAX_NANOS)
            .ok_or(OVER_BUDGET)?;
        input = &input[end..];
    }
    Ok(Duration::from_nanos(total))
}
