//! Actual lexical tokens and explicit duplicate-policy controls.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn lossless_text_tokens_and_user_transport_names_are_distinct() -> TestResult {
    let bytes = br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"exponent":1e309,"fake":{"$serde_json::private::Number":"7"},"raw":{"$serde_json::private::RawValue":"[1]"},"nested":[{"$serde_json::private::Number":"bad"}]}"#;
    let decoded = decode(bytes)?;
    assert_eq!(decoded["big"].to_string(), "184467440737095516160001");
    assert_eq!(
        decoded["decimal"].to_string(),
        "0.12345678901234567890123456789"
    );
    assert!(decoded["exponent"].is_number());
    assert!(decoded["fake"].is_object());
    assert!(decoded["raw"].is_object());
    assert!(decoded["nested"][0].is_object());
    assert!(requires_lossless_format(&decoded));
    assert!(!requires_lossless_format(&decode(
        br#"{"ordinary":42,"same":1e2,"finite":1.25}"#
    )?));
    assert!(requires_lossless_format(&decode(
        br#"{"$serde_json::private::Number":"7"}"#
    )?));
    assert_eq!(decode(&serde_json::to_vec(&decoded)?)?, decoded);
    Ok(())
}

#[test]
fn lossless_duplicate_policy_and_invalid_tokens_remain_explicit() -> TestResult {
    let duplicate =
        br#"{"exp":3,"exp":7,"nested":{"key":1,"key":{"$serde_json::private::Number":"9"}}}"#;
    assert!(decode(duplicate).is_err());
    let decoded = decode_with_policy(duplicate, DuplicatePolicy::LastWins)?;
    assert_eq!(decoded["exp"], 7);
    assert!(decoded["nested"]["key"].is_object());
    for bad in [
        br#"{"x":"\uD800"}"#.as_slice(),
        b"{\"x\":NaN}",
        b"true false",
        &[0xff],
        b"",
    ] {
        assert!(decode_with_policy(bad, DuplicatePolicy::LastWins).is_err());
    }
    let too_deep = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    assert!(decode(too_deep.as_bytes()).is_err());
    assert!(decode(&vec![b' '; MAX_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn lossless_field_deserialization_preserves_text_and_trusted_value_maps() -> TestResult {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Owner {
        #[serde(deserialize_with = "deserialize")]
        body: Value,
    }
    let body = decode(
        br#"{"number":123456789012345678901234567890,"tag":{"$serde_json::private::Number":"5"}}"#,
    )?;
    let original = Owner { body: body.clone() };
    let raw = serde_json::to_vec(&original)?;
    let text: Owner = serde_json::from_slice(&raw)?;
    assert_eq!(text.body, body);
    let trusted: Owner = serde_json::from_value(serde_json::to_value(&original)?)?;
    assert_eq!(trusted.body, body);
    assert_eq!(serde_json::to_vec(&text)?, raw);
    assert!(serde_json::from_slice::<Owner>(br#"{"body":{"x":1,"x":2}}"#).is_err());
    Ok(())
}

#[test]
fn lossless_negative_zero_keeps_float_sign_and_category_at_real_token_boundary() -> TestResult {
    let decoded = decode(br#"{"negative":-0,"decimal":-0.0,"exponent":-0e0,"positive":0,"text":"-0","nested":[-0,{"value":-0}],"tag":{"$serde_json::private::Number":"-0"}}"#)?;
    for number in [
        &decoded["negative"],
        &decoded["decimal"],
        &decoded["exponent"],
        &decoded["nested"][0],
        &decoded["nested"][1]["value"],
    ] {
        assert_eq!(number.as_f64().ok_or("finite signed zero")?.to_bits(), (-0.0_f64).to_bits());
        assert!(number.as_i64().is_none());
        assert!(number.as_u64().is_none());
    }
    assert_eq!(decoded["positive"].as_f64().ok_or("positive zero")?.to_bits(), 0.0_f64.to_bits());
    assert_eq!(decoded["positive"].as_i64(), Some(0));
    assert_eq!(decoded["text"], "-0");
    assert!(decoded["tag"].is_object());
    assert_eq!(decode(&serde_json::to_vec(&decoded)?)?, decoded);
    for bad in [
        br#"{"x":-0,"x":0}"#.as_slice(),
        br#"{"nested":{"x":-0,"x":0}}"#,
        b"-00",
        b"-0.",
        b"-0e",
    ] {
        assert!(decode(bad).is_err());
    }
    assert_eq!(decode_with_policy(br#"{"x":-0,"x":0}"#, DuplicatePolicy::LastWins)?["x"].as_i64(), Some(0));
    Ok(())
}
