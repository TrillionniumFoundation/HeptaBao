//! Real owner construction, mutation, precision, and persistent history controls.
//! Service publication and schema-floor admission are tested by the service owner.
use super::*;
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn at(seconds: u64, nanos: u32) -> TestResult<Timestamp> {
    Ok(Timestamp::checked(seconds, nanos)?)
}
fn wire(seconds: u64, nanos: u32) -> TestResult<String> {
    Ok(at(seconds, nanos)?.rfc3339())
}
fn fixture() -> TestResult<Value> {
    Ok(json!({
        "schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":3,"cas_required":false,"metadata_cas_required":false,"delete_version_after":"0s"},
        "entries":{
            "item":{
                "created_time":wire(100,123456789)?,"updated_time":wire(105,300000001)?,
                "current_version":5,"current_metadata_version":2,"oldest_version":3,
                "max_versions":3,"cas_required":true,"metadata_cas_required":true,
                "delete_version_after":"0s","custom_metadata":{"owner":"fixture"},
                "versions":{
                    "3":{"created_time":wire(103,1)?,"deletion_time":"","destroyed":true,"data":null},
                    "4":{"created_time":wire(104,2)?,"deletion_time":wire(106,500000001)?,"destroyed":false,"data":{"value":"four"}},
                    "5":{"created_time":wire(105,3)?,"deletion_time":"","destroyed":false,"data":{"value":"five"}}
                }
            },
            "scheduled":{
                "created_time":wire(110,7)?,"updated_time":wire(110,7)?,
                "current_version":1,"current_metadata_version":0,"oldest_version":0,
                "max_versions":0,"cas_required":false,"metadata_cas_required":false,
                "delete_version_after":"7200.5s","custom_metadata":null,
                "versions":{
                    "1":{"created_time":wire(110,7)?,"deletion_time":wire(120,500000001)?,"source_deletion_time":wire(7310,7)?,"destroyed":false,"data":{"retained":true}}
                }
            },
            "metadata-only":{
                "created_time":wire(109,1)?,"updated_time":wire(109,1)?,
                "current_version":0,"current_metadata_version":1,"oldest_version":0,
                "max_versions":2,"cas_required":true,"metadata_cas_required":false,
                "delete_version_after":"0s","custom_metadata":{},"versions":{}
            }
        }
    }))
}
fn imported() -> TestResult<Kv2> {
    Ok(Kv2::from_lossless_import_json(&serde_json::to_vec(
        &fixture()?,
    )?)?)
}

#[test]
fn kv2_lossless_import_keeps_subsecond_deadlines_and_persistent_timestamps() -> TestResult {
    let engine = imported()?;
    assert!(engine.has_lossless_import_state());
    engine.validate_lossless_state()?;
    let before =
        engine.handle_read_precise("GET", "data/scheduled", &json!({}), at(120, 500000000)?)?;
    assert_eq!(before.status, 200);
    assert_eq!(before.body["data"]["data"], json!({"retained":true}));
    assert_eq!(
        before.body["data"]["metadata"]["created_time"],
        wire(110, 7)?
    );
    assert_eq!(
        before.body["data"]["metadata"]["deletion_time"],
        wire(120, 500000001)?
    );
    let exact =
        engine.handle_read_precise("GET", "data/scheduled", &json!({}), at(120, 500000001)?)?;
    assert_eq!(exact.status, 404);
    assert_eq!(exact.body["data"]["data"], Value::Null);
    assert_eq!(
        engine
            .handle_read("GET", "data/scheduled", &json!({}), 120)?
            .status,
        200
    );
    assert_eq!(
        engine
            .entries
            .get("scheduled")
            .ok_or("scheduled")?
            .version_precision(1)
            .source_deletion_at,
        Some(at(7310, 7)?)
    );
    let bytes = serde_json::to_vec(&engine)?;
    let reopened: Kv2 = serde_json::from_slice(&bytes)?;
    reopened.validate_lossless_state()?;
    assert_eq!(serde_json::to_vec(&reopened)?, bytes);
    assert_eq!(
        reopened
            .handle_read_precise("GET", "data/scheduled", &json!({}), at(120, 500000001)?)?
            .status,
        404
    );
    assert_eq!(
        reopened
            .handle_read("GET", "metadata/scheduled", &json!({}), 121)?
            .body["data"]["delete_version_after"],
        "7200.5s"
    );
    Ok(())
}

#[test]
fn kv2_lossless_import_preserves_floor_both_cas_counters_and_soft_deleted_data() -> TestResult {
    let mut engine = imported()?;
    let metadata = engine
        .handle_read("GET", "metadata/item", &json!({}), 107)?
        .body["data"]
        .clone();
    assert_eq!(metadata["current_version"], 5);
    assert_eq!(metadata["oldest_version"], 3);
    assert_eq!(metadata["current_metadata_version"], 2);
    assert_eq!(metadata["versions"]["3"]["destroyed"], true);
    assert_eq!(
        metadata["versions"]["4"]["deletion_time"],
        wire(106, 500000001)?
    );
    assert_eq!(metadata["created_time"], wire(100, 123456789)?);
    assert_eq!(metadata["updated_time"], wire(105, 300000001)?);
    assert_eq!(
        engine
            .handle_read("GET", "data/item", &json!({"version":3}), 107)?
            .status,
        404
    );
    assert!(
        engine
            .handle_read("GET", "data/item", &json!({"version":2}), 107)
            .is_err()
    );
    assert_eq!(
        engine
            .handle_read("GET", "data/item", &json!({"version":4}), 107)?
            .status,
        404
    );
    engine.handle_precise(
        "POST",
        "undelete/item",
        &json!({"versions":[4]}),
        at(108, 9)?,
    )?;
    assert_eq!(
        engine
            .handle_read("GET", "data/item", &json!({"version":4}), 109)?
            .body["data"]["data"],
        json!({"value":"four"})
    );
    let snapshot = serde_json::to_vec(&engine)?;
    assert!(
        engine
            .handle("POST", "data/item", &json!({"data":{}}), 109)
            .is_err()
    );
    assert!(
        engine
            .handle(
                "POST",
                "data/item",
                &json!({"data":{},"options":{"cas":4}}),
                109
            )
            .is_err()
    );
    assert!(
        engine
            .handle(
                "POST",
                "metadata/item",
                &json!({"metadata_cas":1,"custom_metadata":{"x":"y"}}),
                109
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&engine)?, snapshot);
    engine.handle_precise(
        "POST",
        "metadata/item",
        &json!({"metadata_cas":2,"custom_metadata":{"x":"y"}}),
        at(109, 4)?,
    )?;
    assert_eq!(
        engine
            .handle_read("GET", "metadata/item", &json!({}), 110)?
            .body["data"]["current_metadata_version"],
        3
    );
    engine.handle_precise(
        "POST",
        "data/item",
        &json!({"data":{"value":"six"},"options":{"cas":5}}),
        at(110, 6)?,
    )?;
    let after = engine
        .handle_read("GET", "metadata/item", &json!({}), 110)?
        .body["data"]
        .clone();
    assert_eq!(after["oldest_version"], 4);
    assert_eq!(after["current_version"], 6);
    assert_eq!(after["current_metadata_version"], 3);
    assert!(after["versions"].get("3").is_none());
    assert_eq!(after["versions"]["6"]["created_time"], wire(110, 6)?);
    let listed = engine.handle_read("LIST", "metadata/", &json!({}), 111)?;
    assert_eq!(
        listed.body["data"]["keys"],
        json!(["item", "metadata-only", "scheduled"])
    );
    assert!(
        engine
            .handle_read("GET", "data/metadata-only", &json!({}), 111)
            .is_err()
    );
    engine.validate_lossless_state()?;
    Ok(())
}

#[test]
fn kv2_lossless_import_validates_all_records_before_candidate_publication() -> TestResult {
    let original = imported()?;
    let saved = serde_json::to_vec(&original)?;
    for change in 0..9 {
        let mut bundle = fixture()?;
        match change {
            0 => bundle["schema"] = json!("unknown"),
            1 => bundle["entries"]["scheduled"]["versions"]["1"]["data"] = Value::Null,
            2 => bundle["entries"]["item"]["versions"]["3"]["data"] = json!({}),
            3 => {
                bundle["entries"]["item"]["versions"]
                    .as_object_mut()
                    .ok_or("versions")?
                    .remove("4");
            }
            4 => bundle["entries"]["scheduled"]["oldest_version"] = json!(2),
            5 => bundle["entries"]["scheduled"]["created_time"] = json!("2026-02-30T00:00:00Z"),
            6 => bundle["entries"]["scheduled"]["delete_version_after"] = json!("0.0000000001s"),
            7 => bundle["entries"]["scheduled"]["delete_version_after"] = json!("315360001s"),
            _ => {
                bundle["entries"]["scheduled"]["versions"]["1"]["created_time"] =
                    json!("1970-01-01T00:01:50.0000000070Z")
            }
        }
        assert!(
            Kv2::from_lossless_import_json(&serde_json::to_vec(&bundle)?).is_err(),
            "case {change}"
        );
        assert_eq!(serde_json::to_vec(&original)?, saved, "case {change}");
    }
    let mut bad_path = fixture()?;
    let value = bad_path["entries"]
        .as_object_mut()
        .ok_or("entries")?
        .remove("scheduled")
        .ok_or("scheduled")?;
    bad_path["entries"]["../escape"] = value;
    assert!(Kv2::from_lossless_import_json(&serde_json::to_vec(&bad_path)?).is_err());
    Ok(())
}

#[test]
fn kv2_lossless_precise_mutations_keep_snapshots_history_and_fractional_retention() -> TestResult {
    let mut engine = imported()?;
    let retained = engine.clone();
    let retained_bytes = serde_json::to_vec(&retained)?;
    engine.handle_precise(
        "POST",
        "data/scheduled",
        &json!({"data":{"next":true}}),
        at(121, 750000000)?,
    )?;
    let written = engine
        .handle_read("GET", "metadata/scheduled", &json!({}), 122)?
        .body["data"]
        .clone();
    assert_eq!(
        written["versions"]["2"]["created_time"],
        wire(121, 750000000)?
    );
    assert_eq!(
        written["versions"]["2"]["deletion_time"],
        wire(7322, 250000000)?
    );
    engine.handle_precise("DELETE", "data/scheduled", &json!({}), at(122, 123)?)?;
    assert_eq!(
        engine
            .handle_read("GET", "metadata/scheduled", &json!({}), 123)?
            .body["data"]["versions"]["2"]["deletion_time"],
        wire(122, 123)?
    );
    engine.handle_precise(
        "POST",
        "undelete/scheduled",
        &json!({"versions":[2]}),
        at(123, 1)?,
    )?;
    assert_eq!(
        engine
            .handle_read("GET", "data/scheduled", &json!({}), 124)?
            .status,
        200
    );
    engine.handle_precise(
        "PATCH",
        "data/scheduled",
        &json!({"data":{"patched":"yes"},"options":{"cas":2}}),
        at(124, 9)?,
    )?;
    assert_eq!(
        engine
            .handle_read("GET", "data/scheduled", &json!({}), 125)?
            .body["data"]["data"],
        json!({"next":true,"patched":"yes"})
    );
    engine.handle_precise(
        "POST",
        "destroy/scheduled",
        &json!({"versions":[2]}),
        at(125, 8)?,
    )?;
    assert_eq!(
        engine
            .handle_read("GET", "data/scheduled", &json!({"version":2}), 126)?
            .status,
        404
    );
    let internal = engine.entries.get("scheduled").ok_or("scheduled")?;
    assert!(internal.versions.get(&2).ok_or("version")?.data.is_none());
    assert_eq!(serde_json::to_vec(&retained)?, retained_bytes);
    engine.validate_lossless_state()?;
    assert_eq!(
        engine
            .entries
            .get("scheduled")
            .ok_or("scheduled")?
            .version_precision(1)
            .source_deletion_at,
        Some(at(7310, 7)?)
    );
    let before_rejection = serde_json::to_vec(&engine)?;
    assert!(
        engine
            .handle_precise(
                "POST",
                "data/new",
                &json!({"data":{}}),
                at(253402300799, 999999999)?
            )
            .is_ok()
    );
    // Existing scheduled config supplies a nonzero duration and must overflow
    // before touching either metadata or the sticky precision marker.
    let before_overflow = serde_json::to_vec(&engine)?;
    assert!(
        engine
            .handle_precise(
                "POST",
                "data/scheduled",
                &json!({"data":{}}),
                at(253402300799, 999999999)?
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&engine)?, before_overflow);
    assert_ne!(before_rejection, before_overflow);
    let mut overflow = Kv2::default();
    overflow.handle(
        "POST",
        "config",
        &json!({"delete_version_after":"1s"}),
        253402300798,
    )?;
    let before = serde_json::to_vec(&overflow)?;
    assert!(
        overflow
            .handle_precise(
                "POST",
                "data/absent",
                &json!({"data":{}}),
                at(253402300799, 1)?
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&overflow)?, before);
    assert!(overflow.entries.is_empty());
    Ok(())
}

#[test]
fn kv2_lossless_json_keeps_big_numbers_and_private_tag_objects_without_coercion() -> TestResult {
    let payload = lossless::decode_lossless_json(br#"{"big":18446744073709551616000000000001,"decimal":0.12345678901234567890123456789012,"exponent":1.234567890123456789e+100,"fake":{"$serde_json::private::Number":"123","x":"keep"},"rawfake":{"$serde_json::private::RawValue":"null"}}"#)?;
    assert_eq!(
        payload["big"].as_number().ok_or("big")?.to_string(),
        "18446744073709551616000000000001"
    );
    assert_eq!(
        payload["decimal"].as_number().ok_or("decimal")?.to_string(),
        "0.12345678901234567890123456789012"
    );
    assert!(payload["fake"].is_object());
    assert_eq!(payload["fake"]["$serde_json::private::Number"], "123");
    assert!(payload["rawfake"].is_object());
    assert!(lossless::decode_lossless_json(br#"{"a":{"a":1,"a":2}}"#).is_err());
    let mut bundle = fixture()?;
    bundle["entries"]["scheduled"]["versions"]["1"]["data"] = payload.clone();
    let engine = Kv2::from_lossless_import_json(&serde_json::to_vec(&bundle)?)?;
    let stored = serde_json::to_vec(&engine)?;
    let reopened: Kv2 = serde_json::from_slice(&stored)?;
    reopened.validate_lossless_state()?;
    assert_eq!(serde_json::to_vec(&reopened)?, stored);
    assert_eq!(
        reopened
            .handle_read("GET", "data/scheduled", &json!({}), 110)?
            .body["data"]["data"],
        payload
    );
    let mut ordinary = Kv2::default();
    ordinary.handle(
        "POST",
        "data/numbers",
        &json!({"data":payload.clone()}),
        111,
    )?;
    assert!(ordinary.has_lossless_import_state());
    ordinary.validate_lossless_state()?;
    assert!(
        ordinary
            .handle(
                "POST",
                "data/numbers",
                &json!({"data":{},"options":{"cas":payload["big"]}}),
                112
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn kv2_lossless_json_and_persistent_format_are_closed_and_legacy_compatible() -> TestResult {
    let mut engine = Kv2::default();
    engine.handle("POST", "data/legacy", &json!({"data":{"small":1}}), 100)?;
    assert!(!engine.has_lossless_import_state());
    let legacy = serde_json::to_vec(&engine)?;
    let reopened: Kv2 = serde_json::from_slice(&legacy)?;
    reopened.validate_lossless_state()?;
    assert_eq!(serde_json::to_vec(&reopened)?, legacy);
    assert!(lossless::decode_lossless_json(br#"{"a":1,"a":2}"#).is_err());
    assert!(lossless::decode_lossless_json(b"{} true").is_err());
    let mut bundle = fixture()?;
    bundle["unexpected"] = json!(true);
    assert!(Kv2::from_lossless_import_json(&serde_json::to_vec(&bundle)?).is_err());
    let mut bundle = fixture()?;
    bundle["entries"]["item"]["unexpected"] = json!(true);
    assert!(Kv2::from_lossless_import_json(&serde_json::to_vec(&bundle)?).is_err());
    let text = String::from_utf8(serde_json::to_vec(&fixture()?)?)?;
    let duplicate = text.replacen(
        "\"schema\":",
        "\"schema\":\"openbao270-kv2-lossless-v1\",\"schema\":",
        1,
    );
    assert!(Kv2::from_lossless_import_json(duplicate.as_bytes()).is_err());
    let mut persisted = lossless::decode_lossless_json(&serde_json::to_vec(&imported()?)?)?;
    persisted
        .as_object_mut()
        .ok_or("persisted")?
        .remove("lossless_format");
    let torn: Kv2 = serde_json::from_value(persisted)?;
    assert!(torn.validate_lossless_state().is_err());
    let mut persisted = lossless::decode_lossless_json(&serde_json::to_vec(&imported()?)?)?;
    persisted["entries"]["scheduled"]["precision"]["created_at"]["seconds"] = json!(111);
    let torn: Kv2 = serde_json::from_value(persisted)?;
    assert!(torn.validate_lossless_state().is_err());
    let mut imported = imported()?;
    for name in ["item", "scheduled", "metadata-only"] {
        imported.handle("DELETE", &format!("metadata/{name}"), &json!({}), 130)?;
    }
    assert!(imported.entries.is_empty());
    assert!(imported.has_lossless_import_state());
    imported.validate_lossless_state()?;
    Ok(())
}

#[test]
fn kv2_lossless_kv1_conversion_stamps_format_for_nonlegacy_payloads() -> TestResult {
    let payload = lossless::decode_lossless_json(
        br#"{"big":184467440737095516160001,"fake":{"$serde_json::private::Number":"7"}}"#,
    )?;
    let entries = BTreeMap::from([("item".into(), SharedJson::from(SecretJson(payload.clone())))]);
    let converted = Kv2::from_v1(entries, 100);
    assert!(converted.has_lossless_import_state());
    converted.validate_lossless_state()?;
    assert_eq!(
        converted
            .handle_read("GET", "data/item", &json!({}), 100)?
            .body["data"]["data"],
        payload
    );
    let bytes = serde_json::to_vec(&converted)?;
    let reopened: Kv2 = serde_json::from_slice(&bytes)?;
    reopened.validate_lossless_state()?;
    assert_eq!(serde_json::to_vec(&reopened)?, bytes);
    let legacy = Kv2::from_v1(
        BTreeMap::from([(
            "item".into(),
            SharedJson::from(SecretJson(json!({"small":1}))),
        )]),
        100,
    );
    assert!(!legacy.has_lossless_import_state());
    legacy.validate_lossless_state()?;
    assert_eq!(
        legacy
            .handle_read("GET", "data/item", &json!({}), 100)?
            .body["data"]["data"],
        json!({"small":1})
    );
    Ok(())
}

#[test]
fn kv2_lossless_undelete_reschedules_from_the_same_precise_request_and_keeps_source_schedule()
-> TestResult {
    let mut engine = imported()?;
    let snapshot = serde_json::to_vec(&engine)?;
    engine.handle_precise(
        "POST",
        "undelete/scheduled",
        &json!({"versions":[1]}),
        at(121, 113)?,
    )?;
    let metadata = engine.handle_read("GET", "metadata/scheduled", &json!({}), 122)?;
    assert_eq!(
        metadata.body["data"]["versions"]["1"]["deletion_time"],
        wire(7321, 500000113)?
    );
    assert_eq!(
        engine
            .entries
            .get("scheduled")
            .ok_or("scheduled")?
            .version_precision(1)
            .source_deletion_at,
        Some(at(7310, 7)?)
    );
    assert_eq!(
        engine
            .handle_read_precise("GET", "data/scheduled", &json!({}), at(7321, 500000112)?)?
            .status,
        200
    );
    assert_eq!(
        engine
            .handle_read_precise("GET", "data/scheduled", &json!({}), at(7321, 500000113)?)?
            .status,
        404
    );
    let installed = serde_json::to_vec(&engine)?;
    let reopened: Kv2 = serde_json::from_slice(&installed)?;
    reopened.validate_lossless_state()?;
    assert_eq!(serde_json::to_vec(&reopened)?, installed);
    let retained: Kv2 = serde_json::from_slice(&snapshot)?;
    assert_eq!(
        retained
            .handle_read("GET", "metadata/scheduled", &json!({}), 122)?
            .body["data"]["versions"]["1"]["deletion_time"],
        wire(120, 500000001)?
    );
    let before = serde_json::to_vec(&engine)?;
    assert!(
        engine
            .handle_precise(
                "POST",
                "undelete/scheduled",
                &json!({"versions":[1]}),
                at(253402300799, 999999999)?
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&engine)?, before);
    Ok(())
}

#[test]
fn kv2_lossless_secret_json_value_deserializer_and_text_tokens_are_equivalent() -> TestResult {
    let payload = lossless::decode_lossless_json(br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"},"raw":{"$serde_json::private::RawValue":"[1]"}}"#)?;
    let from_value: SecretJson = serde_json::from_value(payload.clone())?;
    assert_eq!(from_value.0, payload);
    assert!(from_value.0["fake"].is_object());
    assert!(from_value.0["raw"].is_object());
    let text = serde_json::to_vec(&from_value)?;
    let from_text: SecretJson = serde_json::from_slice(&text)?;
    assert_eq!(from_text.0, payload);
    let mut source = fixture()?;
    source["entries"]["item"]["versions"]["5"]["data"] = payload.clone();
    let engine = Kv2::from_lossless_import_json(&serde_json::to_vec(&source)?)?;
    let trusted_wire = serde_json::to_value(&engine)?;
    let reopened: Kv2 = serde_json::from_value(trusted_wire)?;
    reopened.validate_lossless_state()?;
    assert_eq!(
        reopened
            .handle_read("GET", "data/item", &json!({}), 107)?
            .body["data"]["data"],
        payload
    );
    assert_eq!(serde_json::to_vec(&reopened)?, serde_json::to_vec(&engine)?);
    Ok(())
}
