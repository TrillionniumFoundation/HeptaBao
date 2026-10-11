//! Strict URL-encoded AppRole ingress for the default, explicitly known
//! AppRole mount only. Never select a general login/plugin route by suffix.
//! Custom AppRole mounts remain unsupported for this media type until the
//! mounted engine's kind can be established at the authenticated Service layer.
use serde_json::{Map, Value};
use zeroize::Zeroizing;

pub(super) fn selected(method: &str, route: &str, content_type: Option<&str>) -> bool {
    matches!(method, "POST" | "PUT")
        && route == "auth/approle/login"
        && content_type.is_some_and(|value| {
            value.split(';').next().is_some_and(|media| {
                media
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        })
}

fn decode(input: &[u8]) -> Result<String, &'static str> {
    if input.len() > 1024 {
        return Err("AppRole form field exceeds limit");
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut cursor = 0;
    while cursor < input.len() {
        match input[cursor] {
            b'+' => decoded.push(b' '),
            b'%' => {
                if cursor + 2 >= input.len() {
                    return Err("incomplete AppRole form escape");
                }
                let nibble = |v: u8| match v {
                    b'0'..=b'9' => Some(v - b'0'),
                    b'a'..=b'f' => Some(v - b'a' + 10),
                    b'A'..=b'F' => Some(v - b'A' + 10),
                    _ => None,
                };
                let hi = nibble(input[cursor + 1]).ok_or("invalid AppRole form escape")?;
                let lo = nibble(input[cursor + 2]).ok_or("invalid AppRole form escape")?;
                decoded.push(hi * 16 + lo);
                cursor += 2;
            }
            value => decoded.push(value),
        }
        cursor += 1;
    }
    if decoded.iter().any(|value| *value < b' ' || *value == 0x7f) {
        return Err("AppRole form contains control bytes");
    }
    std::str::from_utf8(decoded.as_slice())
        .map(str::to_owned)
        .map_err(|_| "AppRole form must be UTF-8")
}

pub(super) fn parse(payload: &[u8]) -> Result<Value, &'static str> {
    if payload.is_empty() || payload.len() > 2048 {
        return Err("invalid AppRole form length");
    }
    // Never leave partially parsed credentials in a discarded ordinary JSON
    // map when a later field is malformed or duplicated.
    let mut role_id: Option<Zeroizing<String>> = None;
    let mut secret_id: Option<Zeroizing<String>> = None;
    for pair in payload.split(|v| *v == b'&') {
        let index = pair
            .iter()
            .position(|v| *v == b'=')
            .ok_or("AppRole form field requires a value")?;
        let field = Zeroizing::new(decode(&pair[..index])?);
        let value = Zeroizing::new(decode(&pair[index + 1..])?);
        if value.len() > 256 {
            return Err("AppRole credential exceeds limit");
        }
        match field.as_str() {
            "role_id" if role_id.is_none() => role_id = Some(value),
            "secret_id" if secret_id.is_none() => secret_id = Some(value),
            "role_id" | "secret_id" => return Err("duplicate AppRole form field"),
            _ => return Err("unexpected AppRole form field"),
        }
    }
    let role_id = role_id.ok_or("AppRole form is missing role_id")?;
    let mut fields = Map::new();
    fields.insert("role_id".into(), Value::String(role_id.as_str().to_owned()));
    if let Some(secret) = secret_id {
        fields.insert(
            "secret_id".into(),
            Value::String(secret.as_str().to_owned()),
        );
    }
    Ok(Value::Object(fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str, media: &str, form: &[u8]) -> Vec<u8> {
        let mut wire = format!(
            "POST /v1/{path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {media}\r\nContent-Length: {}\r\n\r\n",
            form.len()
        ).into_bytes();
        wire.extend_from_slice(form);
        wire
    }

    #[test]
    fn valid_form_decodes_and_keeps_credential_fields_exact() {
        let result = parse(b"role_id=uuid%2D1&secret_id=p%2Bss+one").unwrap();
        assert_eq!(
            result,
            serde_json::json!({"role_id":"uuid-1","secret_id":"p+ss one"})
        );
        assert_eq!(
            parse(b"role_id=one").unwrap(),
            serde_json::json!({"role_id":"one"})
        );
    }

    #[test]
    fn invalid_duplicates_percent_control_and_unknown_fields_fail_closed() {
        for payload in [
            b"role_id=one&role_id=two".as_slice(),
            b"role_id=one&%72ole_id=two",
            b"role_id=one&secret_id=%ZZ",
            b"role_id=one&secret_id=%",
            b"role_id=one&secret_id=%0D",
            b"role_id=one&unexpected=x",
            b"role_id=one&",
            b"secret_id=alone",
            b"",
        ] {
            assert!(parse(payload).is_err(), "ambiguous form was accepted");
        }
    }

    #[test]
    fn only_default_approle_login_may_select_form_codec() {
        assert!(selected(
            "POST",
            "auth/approle/login",
            Some("application/x-www-form-urlencoded")
        ));
        assert!(selected(
            "PUT",
            "auth/approle/login",
            Some("application/x-www-form-urlencoded; charset=UTF-8")
        ));
        for route in [
            "auth/userpass/login",
            "auth/kubernetes/login",
            "auth/other/login",
            "auth/approle/role",
        ] {
            assert!(!selected(
                "POST",
                route,
                Some("application/x-www-form-urlencoded")
            ));
        }
        assert!(!selected(
            "GET",
            "auth/approle/login",
            Some("application/x-www-form-urlencoded")
        ));
    }

    #[test]
    fn real_http_parser_uses_closed_approle_form_codec() {
        let bytes = request(
            "auth/approle/login",
            "application/x-www-form-urlencoded",
            b"role_id=abc&secret_id=xyz",
        );
        let parsed = super::super::read_request_mode(
            &mut bytes.as_slice(),
            std::time::Duration::from_secs(2),
            false,
        )
        .map_err(|error| error.message)
        .unwrap();
        assert_eq!(
            parsed.body.0,
            serde_json::json!({"role_id":"abc","secret_id":"xyz"})
        );
    }

    #[test]
    fn actual_parser_rejects_ambiguous_form_and_unrelated_auth_mounts() {
        for (path, payload) in [
            ("auth/approle/login", b"role_id=one&role_id=two".as_slice()),
            ("auth/approle/login", b"role_id=one&secret_id=%ZZ"),
            ("auth/other/login", b"role_id=one&secret_id=two"),
            ("auth/userpass/login", b"role_id=one&secret_id=two"),
        ] {
            let bytes = request(path, "application/x-www-form-urlencoded", payload);
            assert!(
                super::super::read_request_mode(
                    &mut bytes.as_slice(),
                    std::time::Duration::from_secs(2),
                    false
                )
                .is_err(),
                "ambiguous or unrelated AppRole form was admitted"
            );
        }
    }

    #[test]
    fn actual_parser_rejects_form_query_and_oversize_values() {
        let query = request(
            "auth/approle/login?role_id=other",
            "application/x-www-form-urlencoded",
            b"role_id=one",
        );
        assert!(
            super::super::read_request_mode(
                &mut query.as_slice(),
                std::time::Duration::from_secs(2),
                false
            )
            .is_err()
        );
        assert!(parse(format!("role_id={}", "x".repeat(257)).as_bytes()).is_err());
    }
}
