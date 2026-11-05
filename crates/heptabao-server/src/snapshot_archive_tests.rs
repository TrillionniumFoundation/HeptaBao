use super::*;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn v2_metadata_serialization_has_a_required_versioned_seal_binding() -> TestResult {
    let metadata = Metadata::new(17, 60, &[0; 32]);
    let encoded = serde_json::to_vec(&metadata)?;
    assert_eq!(
        encoded.as_slice(),
        br#"{"format":"heptabao-native-snapshot-v2","state_format":"heptabao-encrypted-backup-v1/HBB2","generation":17,"state_bytes":60,"seal_identity":{"format":"heptabao-seal-metadata-digest-v1","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}"#
    );
    let decoded: Metadata = serde_json::from_slice(&encoded)?;
    assert!(decoded.valid());
    assert_eq!(decoded.generation(), 17);
    assert_eq!(decoded.state_bytes(), 60);
    assert!(decoded.seal_identity().ok_or("binding")?.matches(&[0; 32]));
    assert!(!decoded.seal_identity().ok_or("binding")?.matches(&[1; 32]));
    Ok(())
}

#[test]
fn historical_v1_is_recognized_without_inventing_seal_authority() -> TestResult {
    let encoded = br#"{"format":"heptabao-native-snapshot-v1","state_format":"heptabao-encrypted-backup-v1/HBB2","generation":3,"state_bytes":60}"#;
    let metadata: Metadata = serde_json::from_slice(encoded)?;
    assert!(metadata.valid());
    assert_eq!(metadata.generation(), 3);
    assert!(metadata.seal_identity().is_none());
    for value in [
        serde_json::Value::Null,
        json!({"format":"heptabao-seal-metadata-digest-v1","sha256":"0".repeat(64)}),
    ] {
        let mut mixed: serde_json::Value = serde_json::from_slice(encoded)?;
        mixed["seal_identity"] = value;
        assert!(serde_json::from_value::<Metadata>(mixed).is_err());
    }
    Ok(())
}

#[test]
fn v2_metadata_rejects_missing_null_unknown_and_invalid_bindings() -> TestResult {
    let valid = serde_json::to_value(Metadata::new(2, 60, &[0; 32]))?;
    let mut missing = valid.clone();
    missing
        .as_object_mut()
        .ok_or("object")?
        .remove("seal_identity");
    assert!(serde_json::from_value::<Metadata>(missing).is_err());
    let mut null = valid.clone();
    null["seal_identity"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Metadata>(null).is_err());
    for (field, value) in [
        ("format", json!("future-seal-binding")),
        ("sha256", json!("0".repeat(63))),
        ("sha256", json!("A".repeat(64))),
        ("sha256", json!("g".repeat(64))),
    ] {
        let mut bad = valid.clone();
        bad["seal_identity"][field] = value;
        assert!(!serde_json::from_value::<Metadata>(bad)?.valid());
    }
    let mut extra = valid.clone();
    extra["seal_identity"]["allow_force"] = json!(true);
    assert!(serde_json::from_value::<Metadata>(extra).is_err());
    let mut future = valid;
    future["format"] = json!("heptabao-native-snapshot-v3");
    assert!(serde_json::from_value::<Metadata>(future).is_err());
    Ok(())
}
