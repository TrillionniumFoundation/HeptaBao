//! Copy-on-write version history must not change logical KV transactions.
use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn entry<'a>(kv: &'a Kv2, name: &str) -> TestResult<&'a Entry> {
    kv.entries.get(name).ok_or_else(|| "missing entry".into())
}

fn payload<'a>(kv: &'a Kv2, name: &str, version: u64) -> TestResult<&'a SharedJson> {
    entry(kv, name)?
        .versions
        .get(&version)
        .and_then(|version| version.data.as_ref())
        .ok_or_else(|| "missing payload".into())
}

fn value(kv: &Kv2, name: &str, version: u64, now: u64) -> TestResult<Value> {
    let response = kv.handle_read(
        "GET",
        &format!("data/{name}"),
        &json!({"version":version}),
        now,
    )?;
    assert_eq!(response.status, 200);
    Ok(response.body["data"]["data"].clone())
}

#[test]
fn small_update_shares_other_entries_and_unchanged_historical_payloads() -> TestResult {
    let mut kv = Kv2::default();
    kv.handle(
        "POST",
        "data/cold",
        &json!({"data":{"payload":"x".repeat(224 * 1024)}}),
        10,
    )?;
    kv.handle(
        "POST",
        "data/small",
        &json!({"data":{"old":"y".repeat(224 * 1024)}}),
        10,
    )?;
    let snapshot = kv.clone();
    kv.handle(
        "POST",
        "data/small",
        &json!({"data":{"value":"next"},"options":{"cas":1}}),
        11,
    )?;
    assert!(Arc::ptr_eq(
        &entry(&kv, "cold")?.0,
        &entry(&snapshot, "cold")?.0
    ));
    assert!(!Arc::ptr_eq(
        &entry(&kv, "small")?.0,
        &entry(&snapshot, "small")?.0
    ));
    assert!(Arc::ptr_eq(
        &payload(&kv, "small", 1)?.0,
        &payload(&snapshot, "small", 1)?.0
    ));
    assert_eq!(entry(&snapshot, "small")?.current_version, 1);
    assert_eq!(value(&kv, "small", 2, 11)?, json!({"value":"next"}));
    assert_eq!(
        value(&snapshot, "small", 1, 11)?,
        json!({"old":"y".repeat(224 * 1024)})
    );
    drop(kv);
    assert_eq!(
        value(&snapshot, "cold", 1, 11)?,
        json!({"payload":"x".repeat(224 * 1024)})
    );
    Ok(())
}

#[test]
fn patch_metadata_delete_destroy_and_cas_preserve_previous_snapshots() -> TestResult {
    let mut kv = Kv2::default();
    kv.handle(
        "POST",
        "data/item",
        &json!({"data":{"nested":{"keep":"yes","remove":"old"},"other":1}}),
        10,
    )?;
    let snapshot = kv.clone();
    let before = serde_json::to_vec(&snapshot)?;
    assert_eq!(
        kv.handle(
            "POST",
            "data/item",
            &json!({"data":{},"options":{"cas":0}}),
            11
        )
        .err()
        .ok_or("CAS mismatch accepted")?
        .status,
        400
    );
    assert!(Arc::ptr_eq(
        &entry(&kv, "item")?.0,
        &entry(&snapshot, "item")?.0
    ));
    kv.handle(
        "PATCH",
        "data/item",
        &json!({"data":{"nested":{"remove":null,"added":"new"}},"options":{"cas":1}}),
        11,
    )?;
    assert_eq!(
        value(&kv, "item", 2, 11)?,
        json!({"nested":{"keep":"yes","added":"new"},"other":1})
    );
    assert!(Arc::ptr_eq(
        &payload(&kv, "item", 1)?.0,
        &payload(&snapshot, "item", 1)?.0
    ));
    assert!(!Arc::ptr_eq(
        &payload(&kv, "item", 2)?.0,
        &payload(&snapshot, "item", 1)?.0
    ));
    kv.handle(
        "POST",
        "metadata/item",
        &json!({"custom_metadata":{"label":"next"},"metadata_cas":0}),
        12,
    )?;
    assert_eq!(entry(&kv, "item")?.current_metadata_version, 1);
    assert!(entry(&snapshot, "item")?.custom_metadata.is_none());
    kv.handle("DELETE", "data/item", &json!({}), 13)?;
    assert_eq!(
        kv.handle_read("GET", "data/item", &json!({}), 13)?.status,
        404
    );
    kv.handle("POST", "undelete/item", &json!({"versions":[2]}), 14)?;
    assert_eq!(value(&kv, "item", 2, 14)?["nested"]["added"], "new");
    kv.handle("POST", "delete/item", &json!({"versions":[1]}), 15)?;
    kv.handle("POST", "destroy/item", &json!({"versions":[1]}), 16)?;
    assert!(payload(&kv, "item", 1).is_err());
    assert_eq!(value(&snapshot, "item", 1, 16)?["nested"]["remove"], "old");
    assert_eq!(serde_json::to_vec(&snapshot)?, before);
    kv.handle("DELETE", "metadata/item", &json!({}), 17)?;
    assert!(kv.entries.is_empty());
    assert_eq!(serde_json::to_vec(&snapshot)?, before);
    Ok(())
}

#[test]
fn retention_and_reopen_keep_versions_and_ordered_enumeration() -> TestResult {
    let mut kv = Kv2::default();
    kv.handle("POST", "config", &json!({"max_versions":2}), 9)?;
    for key in ["a", "folder/x", "folder/z", "z"] {
        kv.handle(
            "POST",
            &format!("data/{key}"),
            &json!({"data":{"version":1}}),
            10,
        )?;
    }
    let snapshot = kv.clone();
    for version in [2, 3] {
        kv.handle(
            "POST",
            "data/a",
            &json!({"data":{"version":version},"options":{"cas":version-1}}),
            10 + version,
        )?;
    }
    assert!(payload(&kv, "a", 1).is_err());
    assert_eq!(value(&snapshot, "a", 1, 20)?, json!({"version":1}));
    let bytes = serde_json::to_vec(&kv)?;
    let reopened: Kv2 = serde_json::from_slice(&bytes)?;
    assert_eq!(value(&reopened, "a", 2, 20)?, json!({"version":2}));
    assert_eq!(value(&reopened, "a", 3, 20)?, json!({"version":3}));
    assert_eq!(
        reopened
            .handle_read("LIST", "metadata/", &json!({}), 20)?
            .body["data"]["keys"],
        json!(["a", "folder/", "z"])
    );
    assert_eq!(
        reopened
            .handle_read("LIST", "metadata/", &json!({"after":"a","limit":1}), 20)?
            .body["data"]["keys"],
        json!(["folder/"])
    );
    assert_eq!(
        reopened
            .handle_read("SCAN", "metadata/", &json!({"after":"z","limit":1}), 20)?
            .body["data"]["keys"],
        json!(["a", "z", "folder/x", "folder/z"])
    );
    Ok(())
}
