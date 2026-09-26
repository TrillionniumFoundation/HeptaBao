//! The dedicated sys/leader HTTP handler ignores logical request fields. Its
//! outer OpenBao middleware still validates GET list/scan selectors.
use super::*;

// Go net/http admits every nonempty HTTP token method. The dedicated leader
// handler then returns 405 unless it is exactly GET; other APIs keep their
// narrower method allowlist in read_request_mode.
pub(super) fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn selector_error() -> ParseError {
    ParseError {
        status: 400,
        message: "invalid leader query selector",
        empty_errors: true,
    }
}

pub(super) fn validate_selectors(method: &str, target: &str) -> Result<(), ParseError> {
    if !target.bytes().all(|byte| (33..=126).contains(&byte)) {
        return Err(bad("invalid request target bytes"));
    }
    if method != "GET" {
        return Ok(());
    }
    let query = target.split_once('?').map_or("", |(_, query)| query);
    let (mut list, mut scan) = (None, None);
    // net/url.ParseQuery drops each malformed pair but retains valid pairs;
    // URL.Query ignores its error. Values.Get uses the first valid value, even
    // when that value is empty. A literal semicolon invalidates its whole pair.
    for pair in query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.contains(';'))
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(key), Some(value)) = (unescape(key), unescape(value)) else {
            continue;
        };
        let slot = match key.as_slice() {
            b"list" => &mut list,
            b"scan" => &mut scan,
            _ => continue,
        };
        if slot.is_none() {
            *slot = Some(value);
        }
    }
    let truth = |value: Option<Zeroizing<Vec<u8>>>| match value.as_deref().map(Vec::as_slice) {
        None | Some(b"" | b"0" | b"f" | b"F" | b"false" | b"False" | b"FALSE") => Ok(false),
        Some(b"1" | b"t" | b"T" | b"true" | b"True" | b"TRUE") => Ok(true),
        _ => Err(selector_error()),
    };
    let list = truth(list)?;
    let scan = truth(scan)?;
    if list && scan {
        return Err(selector_error());
    }
    Ok(())
}

// Unlike the ordinary API decoder, Go QueryUnescape accepts arbitrary bytes.
// Only ASCII selector names/boolean values have semantics here. Unknown keys,
// invalid UTF-8 and control bytes are never copied into a response or state.
fn unescape(input: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut result = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        result.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = bytes.next()?;
                let low = bytes.next()?;
                let digit = |byte: u8| (byte as char).to_digit(16).map(|value| value as u8);
                digit(high)?.checked_mul(16)?.checked_add(digit(low)?)?
            }
            other => other,
        });
    }
    Some(result)
}

#[cfg(test)]
#[path = "http_leader_tests.rs"]
mod tests;
