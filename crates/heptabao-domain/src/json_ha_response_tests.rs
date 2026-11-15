//! Fixed-purpose response capacity does not relax ordinary JSON entry points.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn bounded_ha_response_keeps_default_sixteen_mib_limit_and_fixed_larger_cap() -> TestResult {
    #[derive(Deserialize)]
    struct OrdinaryOwner {
        #[serde(deserialize_with = "deserialize")]
        body: Value,
    }
    let text = format!("\"{}\"", "x".repeat(MAX_BYTES - 1));
    assert_eq!(text.len(), MAX_BYTES + 1);
    let raw: &serde_json::value::RawValue = serde_json::from_str(&text)?;
    assert!(decode(text.as_bytes()).is_err());
    assert!(decode_with_policy(text.as_bytes(), DuplicatePolicy::LastWins).is_err());
    let wire = format!("{{\"body\":{text}}}");
    assert!(serde_json::from_str::<OrdinaryOwner>(&wire).is_err());
    let large = decode_bounded_ha_response_raw(raw)?;
    assert_eq!(large.as_str().ok_or("large string")?.len(), MAX_BYTES - 1);
    drop(large);
    drop(wire);
    drop(text);
    let small: OrdinaryOwner = serde_json::from_str(r#"{"body":{"value":1}}"#)?;
    assert_eq!(small.body["value"], 1);
    let oversized = format!("\"{}\"", "x".repeat(MAX_BOUNDED_HA_RESPONSE_BYTES - 1));
    let raw: &serde_json::value::RawValue = serde_json::from_str(&oversized)?;
    assert_eq!(raw.get().len(), MAX_BOUNDED_HA_RESPONSE_BYTES + 1);
    assert!(decode_bounded_ha_response_raw(raw).is_err());
    assert_eq!(MAX_BYTES, 16 * 1024 * 1024);
    assert_eq!(MAX_NODES, MAX_BYTES);
    assert_eq!(MAX_DEPTH, 128);
    Ok(())
}

#[test]
fn bounded_ha_response_preserves_lossless_numbers_duplicate_depth_and_node_guards() -> TestResult {
    let text = r#"{"integer":184467440737095516160001,"fraction":0.12345678901234567890123456789,"huge":1e309,"negative_zero":-0,"user":{"$serde_json::private::Number":"not-a-number"}}"#;
    let raw: &serde_json::value::RawValue = serde_json::from_str(text)?;
    let decoded = decode_bounded_ha_response_raw(raw)?;
    assert_eq!(decoded, decode(text.as_bytes())?);
    assert_eq!(decoded["integer"].to_string(), "184467440737095516160001");
    assert_eq!(
        decoded["fraction"].to_string(),
        "0.12345678901234567890123456789"
    );
    assert_eq!(
        decoded["negative_zero"]
            .as_f64()
            .ok_or("negative zero")?
            .to_bits(),
        (-0.0_f64).to_bits()
    );
    assert!(decoded["huge"].is_number() && decoded["user"].is_object());
    let duplicate = r#"{"outer":{"duplicate":1,"duplicate":2}}"#;
    let raw: &serde_json::value::RawValue = serde_json::from_str(duplicate)?;
    assert!(decode_bounded_ha_response_raw(raw).is_err());
    assert!(decode_with_policy(duplicate.as_bytes(), DuplicatePolicy::LastWins).is_ok());
    let deep = format!(
        "{}0{}",
        "[".repeat(MAX_DEPTH + 1),
        "]".repeat(MAX_DEPTH + 1)
    );
    let raw: &serde_json::value::RawValue = serde_json::from_str(&deep)?;
    assert!(decode_bounded_ha_response_raw(raw).is_err());
    let raw: &serde_json::value::RawValue = serde_json::from_str(r#"{"child":1}"#)?;
    let mut exhausted = Budget {
        nodes: MAX_NODES - 1,
        duplicates: DuplicatePolicy::Reject,
    };
    assert!(value(raw, &mut exhausted, 0).is_err());
    assert_eq!(exhausted.nodes, MAX_NODES);
    Ok(())
}
