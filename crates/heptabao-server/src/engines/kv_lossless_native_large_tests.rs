use super::*;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Value {
    json!({
        "schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":1,"cas_required":false,"metadata_cas_required":true,"delete_version_after":"0s"},
        "entries":{"item":{
            "created_time":"1970-01-01T00:01:30.000000113Z",
            "updated_time":"1970-01-01T00:01:30.000000113Z",
            "current_version":1,"current_metadata_version":2,"oldest_version":0,
            "max_versions":1,"cas_required":false,"metadata_cas_required":true,
            "delete_version_after":"0s","custom_metadata":{"one":"two"},
            "versions":{"1":{"created_time":"1970-01-01T00:01:30.000000113Z",
                "deletion_time":"","destroyed":false,"data":{"wide":9007199254740993_u64,
                    "fake":{"$serde_json::private::Number":"7"}}}}
        }}
    })
}
fn encoded(value: &Value) -> Zeroizing<Vec<u8>> {
    match crate::secret_serde::to_vec(value, MAX_BUNDLE_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => panic!("synthetic bounded fixture encoding failed"),
    }
}

#[test]
fn native_large_kv2_codec_rejects_duplicate_tokens_and_keeps_private_name_objects() -> TestResult {
    let bytes = encoded(&fixture());
    let text = std::str::from_utf8(&bytes)?;
    for (from, to) in [
        ("\"schema\":", "\"schema\":\"ignored\",\"schema\":"),
        ("\"wide\":9007199254740993", "\"wide\":0,\"wide\":9007199254740993"),
        ("\"one\":\"two\"", "\"one\":\"ignored\",\"one\":\"two\""),
    ] {
        assert!(text.contains(from));
        let duplicate = Zeroizing::new(text.replacen(from, to, 1).into_bytes());
        assert!(NativeLargeBundle::checked(duplicate, &|| Ok(())).is_err());
    }
    let checked = NativeLargeBundle::checked(bytes, &|| Ok(()))?;
    let owner = Kv2::from_native_large_import(&checked, &|| Ok(()))?;
    let value = owner.handle_read_precise("GET", "data/item", &json!({}), Timestamp::whole(100)?)?;
    assert_eq!(value.body["data"]["data"]["wide"], json!(9007199254740993_u64));
    assert!(value.body["data"]["data"]["fake"].is_object());
    Ok(())
}

#[test]
fn native_large_kv2_codec_enforces_record_bundle_structure_and_original_check() -> TestResult {
    let mut too_large = fixture();
    too_large["entries"]["item"]["versions"]["1"]["data"] = json!({"value":"x".repeat(MAX_RECORD_BYTES)});
    assert!(NativeLargeBundle::checked(encoded(&too_large), &|| Ok(())).is_err());
    drop(too_large);
    assert!(NativeLargeBundle::checked(Zeroizing::new(vec![b' '; MAX_BUNDLE_BYTES + 1]), &|| Ok(())).is_err());
    let deep = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    assert!(NativeLargeBundle::checked(Zeroizing::new(deep.into_bytes()), &|| Ok(())).is_err());
    let checks = std::cell::Cell::new(0_usize);
    assert!(NativeLargeBundle::checked(encoded(&fixture()), &|| {
        let next = checks.get() + 1; checks.set(next);
        if next < 8 { Ok(()) } else { Err(RecordError::Invalid) }
    }).is_err());
    assert_eq!(checks.get(), 8);
    Ok(())
}

#[test]
fn native_large_kv2_codec_opens_only_explicit_profile_above_legacy_byte_bound() -> TestResult {
    let mut bytes = encoded(&fixture());
    bytes.resize(17 * 1024 * 1024, b' ');
    assert!(Kv2::from_lossless_import_json(&bytes).is_err());
    assert!(heptabao_domain::json::decode(&bytes).is_err());
    let checked = NativeLargeBundle::checked(bytes, &|| Ok(()))?;
    let owner = Kv2::from_native_large_import(&checked, &|| Ok(()))?;
    assert_eq!(owner.entries["item"].current_metadata_version, 2);
    Ok(())
}
