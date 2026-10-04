//! The actual authenticated TokenRequest's opaque result has no JWT authority.
//! It still crosses the original Box, private clock, committed lease and audit.
use super::*;

const ALGORITHMS: &[&str] = &[
    "ES256", "ES384", "ES512", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
];

fn failed(plan: &TokenRequestPlan, detail: &str) -> Response {
    // Existing-SA provider path is the actual chosen account. The official
    // independently generated diagnostic-name template remains a wire gap.
    Response::error(
        500,
        &format!(
            "1 error occurred:\n\t* failed to read TTL of created Kubernetes token for {}/{}: {detail}\n\n",
            plan.kubernetes_namespace, plan.service_account_name
        ),
    )
}

fn claim_int(claims: &Value, key: &str) -> Result<i64, String> {
    let Some(value) = claims.get(key).filter(|value| !value.is_null()) else {
        return Ok(0);
    };
    if let Some(number) = value.as_f64() {
        // R54 proves finite ordinary/fractional values. Extreme Go float-to-int
        // architecture behavior needs the separate pinned numerical oracle.
        if number.is_finite() && number >= i64::MIN as f64 && number < -(i64::MIN as f64) {
            return Ok(number.trunc() as i64);
        }
        return Err(format!(
            "'{key}' numeric value is outside observed int64 bounds"
        ));
    }
    let name = match value {
        Value::String(_) => "string",
        Value::Bool(_) => "bool",
        Value::Array(_) => "[]interface {}",
        Value::Object(_) => "map[string]interface {}",
        _ => "<nil>",
    };
    Err(format!(
        "'{key}' expected type 'int64', got unconvertible type '{name}'"
    ))
}

pub(super) fn metadata(value: &Value, plan: &TokenRequestPlan) -> Result<TokenMetadata, Response> {
    if plan.artifact_contract.is_none() {
        return Err(outcome_unknown(&plan.lease_id));
    }
    let status = value
        .get("status")
        .and_then(Value::as_object)
        .ok_or_else(|| outcome_unknown(&plan.lease_id))?;
    if let Some(expiration) = status
        .get("expirationTimestamp")
        .filter(|value| !value.is_null())
    {
        let valid = expiration.as_str().is_some_and(rfc3339);
        if !valid {
            return Err(Response::error(
                500,
                "Kubernetes TokenRequest expirationTimestamp is not valid RFC3339",
            ));
        }
    }
    let token = status
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if token.len() > 64 * 1024 || !token.is_ascii() {
        return Err(outcome_unknown(&plan.lease_id));
    }
    let pieces = token.split('.').collect::<Vec<_>>();
    if pieces.len() != 3 {
        return Err(failed(
            plan,
            "go-jose/go-jose: compact JWS format must have three parts",
        ));
    }
    let decode = |text: &str| {
        URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| failed(plan, "illegal base64 data in compact JWS"))
    };
    let header_raw = Zeroizing::new(decode(pieces[0])?);
    let header: Value = serde_json::from_slice(&header_raw)
        .map_err(|_| failed(plan, "invalid protected JWS header JSON"))?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !ALGORITHMS.contains(&algorithm) {
        let allowed = ALGORITHMS
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(" ");
        return Err(failed(
            plan,
            &format!("unexpected signature algorithm \"{algorithm}\"; expected [{allowed}]"),
        ));
    }
    let payload = Zeroizing::new(decode(pieces[1])?);
    let _signature = Zeroizing::new(decode(pieces[2])?);
    if payload.len() > 32 * 1024 {
        return Err(outcome_unknown(&plan.lease_id));
    }
    // Public metadata accepts the pinned ordinary JSON last-key semantics;
    // this does not parse or mint any caller/provider authorization.
    let claims: Value = serde_json::from_slice(&payload)
        .map_err(|_| failed(plan, "invalid compact JWS claims JSON"))?;
    let mut errors = Vec::new();
    let exp = match claim_int(&claims, "exp") {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            0
        }
    };
    let iat = match claim_int(&claims, "iat") {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            0
        }
    };
    if !errors.is_empty() {
        return Err(failed(
            plan,
            &format!(
                "decoding failed due to the following error(s):\n\n{}",
                errors.join("\n")
            ),
        ));
    }
    Ok(TokenMetadata {
        token: Zeroizing::new(token.to_owned()),
        expires_at: 0,
        audiences: plan.audiences.clone(),
        artifact_lifetime_nanos: Some(exp.wrapping_sub(iat).wrapping_mul(1_000_000_000)),
    })
}

// Finite typed response validation, not an authorization timestamp. Noncanonical
// Go RFC3339 parser extensions/error text need the remaining wire oracle.
fn rfc3339(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() < 20
        || b.len() > 128
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return false;
    }
    let number = |slice: &[u8]| -> Option<u32> {
        slice.iter().try_fold(0u32, |value, byte| {
            if byte.is_ascii_digit() {
                value.checked_mul(10)?.checked_add(u32::from(*byte - b'0'))
            } else {
                None
            }
        })
    };
    let Some(year) = number(&b[0..4]) else {
        return false;
    };
    let Some(month) = number(&b[5..7]) else {
        return false;
    };
    let Some(day) = number(&b[8..10]) else {
        return false;
    };
    let Some(hour) = number(&b[11..13]) else {
        return false;
    };
    let Some(minute) = number(&b[14..16]) else {
        return false;
    };
    let Some(second) = number(&b[17..19]) else {
        return false;
    };
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let mut zone = 19;
    if b.get(zone) == Some(&b'.') {
        zone += 1;
        let beginning = zone;
        while b.get(zone).is_some_and(u8::is_ascii_digit) {
            zone += 1;
        }
        if zone == beginning {
            return false;
        }
    }
    if b.get(zone) == Some(&b'Z') {
        return b.len() == zone + 1;
    }
    if !matches!(b.get(zone), Some(b'+') | Some(b'-')) || b.len() != zone + 6 || b[zone + 3] != b':'
    {
        return false;
    }
    number(&b[zone + 1..zone + 3]).is_some_and(|value| value < 24)
        && number(&b[zone + 4..zone + 6]).is_some_and(|value| value < 60)
}
