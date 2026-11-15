use super::*;
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

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
fn encoded(value: &Value) -> TestResult<Zeroizing<Vec<u8>>> {
    Ok(crate::secret_serde::to_vec(value, MAX_BUNDLE_BYTES)
        .map_err(|_| "synthetic bounded fixture encoding failed")?)
}

#[test]
fn native_large_kv2_codec_rejects_duplicate_tokens_and_keeps_private_name_objects() -> TestResult {
    let bytes = encoded(&fixture())?;
    let text = std::str::from_utf8(&bytes)?;
    for (from, to) in [
        ("\"schema\":", "\"schema\":\"ignored\",\"schema\":"),
        (
            "\"wide\":9007199254740993",
            "\"wide\":0,\"wide\":9007199254740993",
        ),
        ("\"one\":\"two\"", "\"one\":\"ignored\",\"one\":\"two\""),
    ] {
        assert!(text.contains(from));
        let duplicate = Zeroizing::new(text.replacen(from, to, 1).into_bytes());
        assert!(NativeLargeBundle::checked(duplicate, &|| Ok(())).is_err());
    }
    let checked = NativeLargeBundle::checked(bytes, &|| Ok(()))?;
    let owner = Kv2::from_native_large_import(&checked, &|| Ok(()))?;
    let original = fixture();
    let stored = owner
        .entries
        .get("item")
        .ok_or("item")?
        .versions
        .get(&1)
        .ok_or("version")?
        .data
        .as_ref()
        .ok_or("payload")?;
    assert_eq!(
        stored.expose(),
        &original["entries"]["item"]["versions"]["1"]["data"]
    );
    assert_eq!(
        stored.expose()["wide"]
            .as_number()
            .ok_or("stored number")?
            .to_string(),
        "9007199254740993"
    );
    let value =
        owner.handle_read_precise("GET", "data/item", &json!({}), Timestamp::whole(100)?)?;
    // Public OpenBao 2.7.1 GET is a float64 projection. Its observed API
    // integer is distinct from the exact imported owner asserted above.
    assert_eq!(
        value.body["data"]["data"]["wide"],
        json!(9007199254740992_u64)
    );
    assert!(value.body["data"]["data"]["fake"].is_object());
    assert_eq!(
        stored.expose(),
        &original["entries"]["item"]["versions"]["1"]["data"]
    );
    Ok(())
}

#[test]
fn native_large_kv2_codec_enforces_record_bundle_structure_and_original_check() -> TestResult {
    let mut too_large = fixture();
    too_large["entries"]["item"]["versions"]["1"]["data"] =
        json!({"value":"x".repeat(MAX_RECORD_BYTES)});
    assert!(NativeLargeBundle::checked(encoded(&too_large)?, &|| Ok(())).is_err());
    drop(too_large);
    assert!(
        NativeLargeBundle::checked(Zeroizing::new(vec![b' '; MAX_BUNDLE_BYTES + 1]), &|| Ok(()))
            .is_err()
    );
    let deep = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    assert!(NativeLargeBundle::checked(Zeroizing::new(deep.into_bytes()), &|| Ok(())).is_err());
    let checks = std::cell::Cell::new(0_usize);
    assert!(
        NativeLargeBundle::checked(encoded(&fixture())?, &|| {
            let next = checks.get() + 1;
            checks.set(next);
            if next < 8 {
                Ok(())
            } else {
                Err(RecordError::Invalid)
            }
        })
        .is_err()
    );
    assert_eq!(checks.get(), 8);
    Ok(())
}

#[test]
fn native_large_kv2_codec_opens_only_explicit_profile_above_legacy_byte_bound() -> TestResult {
    let mut bytes = encoded(&fixture())?;
    bytes.resize(17 * 1024 * 1024, b' ');
    assert!(Kv2::from_lossless_import_json(&bytes).is_err());
    assert!(heptabao_domain::json::decode(&bytes).is_err());
    let checked = NativeLargeBundle::checked(bytes, &|| Ok(()))?;
    let owner = Kv2::from_native_large_import(&checked, &|| Ok(()))?;
    assert_eq!(owner.entries["item"].current_metadata_version, 2);
    Ok(())
}

#[test]
fn native_large_kv2_capacity_keeps_legacy_and_enforces_joint_records() -> TestResult {
    let mut value = fixture();
    let mut metadata_only = value["entries"]["item"].clone();
    metadata_only["current_version"] = json!(0);
    metadata_only["oldest_version"] = json!(0);
    metadata_only["versions"] = json!({});
    let entries = value["entries"].as_object_mut().ok_or("entries")?;
    entries.clear();
    for index in 0..10_001 {
        entries.insert(format!("key-{index:05}"), metadata_only.clone());
    }
    let bytes = encoded(&value)?;
    assert!(bytes.len() < MAX_IMPORT_BYTES);
    assert!(Kv2::from_lossless_import_json(&bytes).is_err());
    let checked = NativeLargeBundle::checked(bytes, &|| Ok(()))?;
    assert_eq!(
        Kv2::from_native_large_import(&checked, &|| Ok(()))?
            .entries
            .len(),
        10_001
    );
    drop(checked);

    let paths = crate::engines::kv2_native_records::MAX_PATHS;
    assert_eq!(paths, 50_000);
    let entries = value["entries"].as_object_mut().ok_or("entries")?;
    for index in 10_001..paths {
        entries.insert(format!("key-{index:05}"), metadata_only.clone());
    }
    let checked = NativeLargeBundle::checked(encoded(&value)?, &|| Ok(()))?;
    assert_eq!(
        Kv2::from_native_large_import(&checked, &|| Ok(()))?
            .entries
            .len(),
        paths
    );
    drop(checked);
    value["entries"]
        .as_object_mut()
        .ok_or("entries")?
        .insert("one-too-many".into(), metadata_only);
    assert!(NativeLargeBundle::checked(encoded(&value)?, &|| Ok(())).is_err());
    drop(value);

    assert!(ImportProfile::NativeLarge.counts_fit(50_000, 49_999));
    assert!(!ImportProfile::NativeLarge.counts_fit(50_000, 50_000));
    assert!(!ImportProfile::NativeLarge.counts_fit(50_001, 0));
    assert!(!ImportProfile::NativeLarge.counts_fit(1, usize::MAX));
    let mut value = fixture();
    let live = value["entries"]["item"].clone();
    let entries = value["entries"].as_object_mut().ok_or("entries")?;
    entries.clear();
    for index in 0..50_000 {
        entries.insert(format!("live-{index:05}"), live.clone());
    }
    // Each individual path and version count fits. Their complete native
    // record closure (1 + 50,000 + 50,000) must fail before publication.
    assert!(NativeLargeBundle::checked(encoded(&value)?, &|| Ok(())).is_err());
    Ok(())
}

#[test]
fn native_large_kv2_capacity_syntax_budget_is_exact_for_import_and_export() -> TestResult {
    // One array plus MAX_NODES-1 scalars exercises the actual Strict visitor,
    // not a semantic JSON-node estimate made by the migration script.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_NODES * 5 + 8));
    bytes.push(b'[');
    for index in 0..MAX_NODES - 1 {
        if index != 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(b"null");
    }
    bytes.push(b']');
    let check = || Ok(());
    let mut budget = Budget {
        nodes: 0,
        check: &check,
    };
    let mut decoder = serde_json::Deserializer::from_slice(&bytes);
    Strict {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut decoder)?;
    decoder.end()?;
    assert_eq!(budget.nodes, MAX_NODES);
    check_export_syntax(&mut bytes.as_slice(), bytes.len() as u64, &check)?;
    bytes.pop();
    bytes.extend_from_slice(b",null]");
    let mut budget = Budget {
        nodes: 0,
        check: &check,
    };
    let mut decoder = serde_json::Deserializer::from_slice(&bytes);
    assert!(
        Strict {
            budget: &mut budget,
            depth: 0
        }
        .deserialize(&mut decoder)
        .is_err()
    );
    assert_eq!(budget.nodes, MAX_NODES);
    assert!(check_export_syntax(&mut bytes.as_slice(), bytes.len() as u64, &check).is_err());
    Ok(())
}
