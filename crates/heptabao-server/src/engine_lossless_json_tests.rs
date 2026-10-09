//! Real inline and independent KV1 record candidates, without a new clock.
use super::*;
use crate::state_records::AddressKey;
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn call(
    state: &mut EngineState,
    method: &str,
    path: &str,
    body: &Value,
) -> TestResult<EngineResponse> {
    Ok(state
        .handle("", method, path, body, 100)
        .map_err(|_| "engine")?
        .ok_or("route")?)
}
#[test]
fn engine_lossless_inline_and_real_kv1_record_write_observation_preserve_candidate_isolation()
-> TestResult {
    let mut engine = EngineState::default();
    assert!(!engine.has_lossless_json_state());
    assert_eq!(
        call(
            &mut engine,
            "POST",
            "sys/mounts/lossless-kv1",
            &json!({"type":"kv","options":{"version":"1"}})
        )?
        .status,
        204
    );
    let value = heptabao_domain::json::decode(br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"}}"#)?;
    let mut ordinary = engine
        .migrate_kv1_records(AddressKey::from_bytes([0x72; 32]))
        .map_err(|_| "ordinary migration")?;
    assert!(!ordinary.has_lossless_json_state());
    let before = serde_json::to_vec(&ordinary)?;
    let mut candidate = ordinary.clone();
    assert!(call(&mut candidate, "POST", "lossless-kv1/item", &value)?.mutated);
    assert!(candidate.has_lossless_json_state());
    assert!(!ordinary.has_lossless_json_state());
    assert_eq!(serde_json::to_vec(&ordinary)?, before);
    assert_eq!(
        call(&mut candidate, "GET", "lossless-kv1/item", &json!({}))?.body["data"],
        value
    );
    assert_eq!(
        call(&mut ordinary, "GET", "lossless-kv1/item", &json!({}))?.status,
        404
    );
    assert!(call(&mut engine, "POST", "lossless-kv1/item", &value)?.mutated);
    assert!(engine.has_lossless_json_state());
    let bytes = serde_json::to_vec(&engine)?;
    let mut reopened: EngineState = serde_json::from_slice(&bytes)?;
    assert!(reopened.has_lossless_json_state());
    assert_eq!(
        call(&mut reopened, "GET", "lossless-kv1/item", &json!({}))?.body["data"],
        value
    );
    let migrated = engine
        .migrate_kv1_records(AddressKey::from_bytes([0x73; 32]))
        .map_err(|_| "lossless migration")?;
    assert!(migrated.has_lossless_json_state());
    assert_eq!(serde_json::to_vec(&engine)?, bytes);
    Ok(())
}
