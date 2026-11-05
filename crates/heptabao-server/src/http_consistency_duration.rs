//! Go-compatible listener duration syntax with checked nanosecond budget bounds.
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
        // Match Go time.ParseDuration's bounded significant fraction and IEEE
        // conversion, including its nanosecond rounding at unit boundaries.
        // Whole components and the final 60-second budget remain checked integers.
        let mut significant = 0_u64;
        let mut scale = 1_f64;
        for digit in fraction.bytes() {
            if significant > (i64::MAX as u64) / 10 {
                break;
            }
            let next = significant * 10 + u64::from(digit - b'0');
            if next > (1_u64 << 63) {
                break;
            }
            significant = next;
            scale *= 10.0;
        }
        // Input length bounds scale below 10^128; unit <= 3.6e12 and the
        // fraction is at most one, so this finite conversion cannot overflow.
        let fractional_nanos = (significant as f64 * (unit as f64 / scale)) as u64;
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
