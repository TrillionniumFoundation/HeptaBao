//! All four real frame body types retain number tokens and ordinary maps.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn ha_lossless_all_current_and_legacy_body_fields_keep_exact_tokens() -> TestResult {
    let body = heptabao_domain::json::decode(br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"}}"#)?;
    let request = json!({"cluster_id":"synthetic-cluster","source":1,"target":2,"method":"POST","path":"secret/data/item","namespace":"","token":"synthetic","body":body});
    let encoded = encode(REQUEST_MAGIC, &request)?;
    let decoded: ForwardRequest = decode(REQUEST_MAGIC, &encoded)?;
    assert_eq!(decoded.body, body);
    let mut legacy = request.clone();
    legacy.as_object_mut().ok_or("object")?.remove("cluster_id");
    let legacy: LegacyForwardRequest = serde_json::from_slice(&serde_json::to_vec(&legacy)?)?;
    assert_eq!(legacy.body, body);
    let response =
        json!({"cluster_id":"synthetic-cluster","source":2,"target":1,"status":200,"body":body});
    let encoded = encode(RESPONSE_MAGIC, &response)?;
    let decoded: ForwardResponse = decode(RESPONSE_MAGIC, &encoded)?;
    assert_eq!(decoded.body, body);
    let mut legacy = response.clone();
    legacy.as_object_mut().ok_or("object")?.remove("cluster_id");
    let legacy: LegacyForwardResponse = serde_json::from_slice(&serde_json::to_vec(&legacy)?)?;
    assert_eq!(legacy.body, body);
    assert!(decode::<ForwardResponse>(REQUEST_MAGIC, &encoded).is_err());
    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(decode::<ForwardResponse>(RESPONSE_MAGIC, &truncated).is_err());
    let duplicate = br#"{"cluster_id":"synthetic-cluster","source":1,"target":2,"method":"POST","path":"secret/data/item","namespace":"","token":"synthetic","body":{"x":1,"x":2}}"#;
    assert!(serde_json::from_slice::<ForwardRequest>(duplicate).is_err());
    let mut wrong_type = request;
    wrong_type["source"] =
        heptabao_domain::json::decode(br#"{"$serde_json::private::Number":"1"}"#)?;
    assert!(serde_json::from_slice::<ForwardRequest>(&serde_json::to_vec(&wrong_type)?).is_err());
    Ok(())
}
