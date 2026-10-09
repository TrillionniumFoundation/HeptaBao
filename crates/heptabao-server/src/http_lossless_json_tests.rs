//! Real HTTP framing and raw-carrier boundary controls for lossless JSON.
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn wire(path: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!("POST /v1/{path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
    wire.extend_from_slice(body);
    wire
}

#[test]
fn http_lossless_json_preserves_actual_number_tokens_and_user_private_maps() -> TestResult {
    let raw = br#"{"data":{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"exponent":1.234567890123456789e200,"fake":{"$serde_json::private::Number":"7"},"raw":{"$serde_json::private::RawValue":"[1]"}}}"#;
    let expected = crate::engines::decode_lossless_json(raw)?;
    let input = wire("secret/data/item", raw);
    let request = read_request(&mut input.as_slice(), Duration::from_secs(1))
        .map_err(|_| "ordinary request")?;
    assert_eq!(request.body.0, expected);
    assert_eq!(
        request.body.0["data"]["big"]
            .as_number()
            .ok_or("number")?
            .to_string(),
        "184467440737095516160001"
    );
    assert_eq!(
        request.body.0["data"]["decimal"]
            .as_number()
            .ok_or("number")?
            .to_string(),
        "0.12345678901234567890123456789"
    );
    assert!(request.body.0["data"]["exponent"].is_number());
    assert_eq!(
        request.body.0["data"]["fake"],
        json!({"$serde_json::private::Number":"7"})
    );
    assert_eq!(
        request.body.0["data"]["raw"],
        json!({"$serde_json::private::RawValue":"[1]"})
    );
    let ocsp_wire = wire("secret/ocsp", raw);
    let request = read_request(&mut ocsp_wire.as_slice(), Duration::from_secs(1))
        .map_err(|_| "raw carrier")?;
    let raw_post =
        ocsp::raw_post_request("POST", "secret/ocsp", &request.body.0).ok_or("raw post")?;
    let ordinary = raw_post
        .resolve(false)
        .map_err(|_| "ordinary raw resolution")?;
    assert_eq!(ordinary.0, expected);
    let wrapped_wire = wire("sys/wrapping/wrap", raw);
    let wrapped = read_request(&mut wrapped_wire.as_slice(), Duration::from_secs(1))
        .map_err(|_| "lexical wrap")?;
    assert_eq!(wrapped.body.0, expected);
    assert!(wrapped.lexical_wrapping_body.is_some());
    let api = crate::auth::parse_strict_json(raw)?;
    assert_eq!(api, expected);
    Ok(())
}

#[test]
fn http_lossless_json_keeps_duplicate_unicode_and_framing_rejection_closed() -> TestResult {
    for raw in [
        &br#"{"data":{"a":1,"a":2}}"#[..],
        &br#"{"data":{"$serde_json::private::Number":"7","$serde_json::private::Number":"8"}}"#[..],
        &br#"{"data":{"value":"\ud800"}}"#[..],
        &br#"{"data":{"value":NaN}}"#[..],
        &b"{\"data\":{\"value\":\"\xff\"}}"[..],
        &b"\xff\xfe{\x00}\x00"[..],
        &b"[]"[..],
    ] {
        assert!(
            read_request(
                &mut wire("secret/data/item", raw).as_slice(),
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
    let too_deep = format!("{{\"data\":{}{}}}", "[".repeat(129), "]".repeat(129));
    assert!(
        read_request(
            &mut wire("secret/data/item", too_deep.as_bytes()).as_slice(),
            Duration::from_secs(1)
        )
        .is_err()
    );
    let smuggled = b"POST /v1/secret/data/item HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}";
    assert!(read_request(&mut smuggled.as_slice(), Duration::from_secs(1)).is_err());
    assert!(crate::auth::parse_strict_json(br#"{"nested":{"x":1,"x":2}}"#).is_err());
    assert_eq!(
        crate::auth::parse_strict_json(br#"{"$serde_json::private::Number":"invalid"}"#)?,
        json!({"$serde_json::private::Number":"invalid"})
    );
    Ok(())
}
