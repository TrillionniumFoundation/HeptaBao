use super::*;
use crate::state_records::AddressKey;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn call(
    state: &mut EngineState,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Result<EngineResponse> {
    state
        .handle(namespace, method, path, &body, now)?
        .ok_or_else(not_found)
}
fn populate() -> Result<EngineState> {
    let mut state = EngineState::default();
    for namespace in ["", "team"] {
        call(
            &mut state,
            namespace,
            "POST",
            "sys/mounts/raw",
            json!({"type":"kv","description":"migration fixture","options":{"version":"1"}}),
            10,
        )?;
        for path in ["leaf", "nested/item", "nested/item/child"] {
            call(
                &mut state,
                namespace,
                "POST",
                &format!("raw/{path}"),
                json!({"value":path,"typed":{"flag":true,"array":[1,null]}}),
                10,
            )?;
        }
    }
    Ok(state)
}
fn tune(state: &mut EngineState, body: Value) -> Result<EngineResponse> {
    call(state, "", "POST", "sys/mounts/raw/tune", body, 100)
}
#[test]
fn legacy_conversion_preserves_values_clock_mount_identity_and_other_namespace() -> TestResult {
    let mut state = populate()?;
    let mut retained = state.clone();
    let old = state.namespaces[""].mounts["raw/"].clone();
    let result = tune(
        &mut state,
        json!({"options":{"version":"2"},"cas_revision":old.revision}),
    )?;
    assert_eq!(result.status, 200);
    assert!(result.mutated);
    let object = result.body.as_object().ok_or("response shape")?;
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "auth",
            "data",
            "lease_duration",
            "lease_id",
            "renewable",
            "request_id",
            "warnings",
            "wrap_info"
        ]
    );
    assert_eq!(result.body["request_id"], "");
    assert_eq!(result.body["lease_id"], "");
    assert_eq!(result.body["lease_duration"], 0);
    assert_eq!(result.body["renewable"], false);
    assert!(
        result.body["auth"].is_null()
            && result.body["data"].is_null()
            && result.body["wrap_info"].is_null()
    );
    assert_eq!(
        result.body["warnings"],
        json!(["KV v1 data was upgraded to KV v2."])
    );
    let new = &state.namespaces[""].mounts["raw/"];
    assert_eq!(new.incarnation, old.incarnation);
    assert_eq!(new.revision, old.revision + 1);
    assert_eq!(new.description, old.description);
    for path in ["leaf", "nested/item", "nested/item/child"] {
        let migrated = call(
            &mut state,
            "",
            "GET",
            &format!("raw/data/{path}"),
            json!({}),
            101,
        )?;
        let original = call(
            &mut retained,
            "",
            "GET",
            &format!("raw/{path}"),
            json!({}),
            101,
        )?;
        assert_eq!(migrated.body["data"]["data"], original.body["data"]);
        assert_eq!(migrated.body["data"]["metadata"]["version"], 1);
        assert_eq!(
            migrated.body["data"]["metadata"]["created_time"],
            timestamp(100)
        );
        assert_eq!(migrated.body["data"]["metadata"]["deletion_time"], "");
        assert_eq!(migrated.body["data"]["metadata"]["destroyed"], false);
        assert_eq!(
            call(
                &mut state,
                "team",
                "GET",
                &format!("raw/{path}"),
                json!({}),
                101
            )?
            .body,
            original.body
        );
    }
    assert_eq!(
        call(&mut state, "", "GET", "raw/leaf", json!({}), 101)
            .err()
            .ok_or("old route")?
            .status,
        404
    );
    let list = call(&mut state, "", "LIST", "raw/metadata/", json!({}), 101)?;
    assert_eq!(list.body["data"]["keys"], json!(["leaf", "nested/"]));
    let stable = crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| "serialize")?;
    assert!(!tune(&mut state, json!({"options":{"version":"2"}}))?.mutated);
    assert_eq!(
        crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "serialize")?,
        stable
    );
    assert_eq!(
        tune(&mut state, json!({"options":{"version":"1"}}))
            .err()
            .ok_or("downgrade")?
            .status,
        400
    );
    assert_eq!(
        crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "serialize")?,
        stable
    );
    Ok(())
}
#[test]
fn record_conversion_crosses_pages_retires_only_its_scope_and_preserves_retained_graph()
-> TestResult {
    let mut legacy = populate()?;
    for number in 0..270 {
        call(
            &mut legacy,
            "",
            "POST",
            &format!("raw/paged/{number:04}"),
            json!({"ordinal":number}),
            10,
        )?;
    }
    let mut state = legacy.migrate_kv1_records(AddressKey::from_bytes([19; 32]))?;
    let mut retained = state.clone();
    let root = retained.record_root().ok_or("root")?;
    let before_objects = retained.record_objects()?.len();
    tune(&mut state, json!({"options":{"version":"2"}}))?;
    state.validate_record_registry()?;
    assert_ne!(state.record_root().ok_or("root")?, root);
    assert_eq!(retained.record_root().ok_or("root")?, root);
    assert_eq!(retained.record_objects()?.len(), before_objects);
    for number in [0, 255, 256, 269] {
        let path = format!("raw/paged/{number:04}");
        assert_eq!(
            call(&mut retained, "", "GET", &path, json!({}), 101)?.body["data"]["ordinal"],
            number
        );
        assert_eq!(
            call(
                &mut state,
                "",
                "GET",
                &path.replacen("raw/", "raw/data/", 1),
                json!({}),
                101
            )?
            .body["data"]["data"]["ordinal"],
            number
        );
    }
    assert_eq!(
        call(&mut state, "team", "GET", "raw/leaf", json!({}), 101)?.body["data"]["value"],
        "leaf"
    );
    assert!(state.has_record_kv1());
    Ok(())
}
#[test]
fn conversion_validates_every_parameter_before_publishing_and_cas_anchors_revision() -> TestResult {
    let mut state = populate()?.migrate_kv1_records(AddressKey::from_bytes([20; 32]))?;
    let root = state.record_root();
    let bytes = crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| "serialize")?;
    for body in [
        json!({"options":{"version":"2"},"unknown":true}),
        json!({"options":{"version":"2"},"description":null}),
        json!({"options":{"version":2}}),
        json!({"options":{"version":"2"},"cas_revision":999}),
        json!({"options":{"version":"2","unknown":true}}),
    ] {
        assert!(tune(&mut state, body).is_err());
        assert_eq!(state.record_root(), root);
        assert_eq!(
            crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| "serialize")?,
            bytes
        );
    }
    Ok(())
}
#[test]
fn conversion_missing_graph_or_expired_deadline_cannot_change_the_mount() -> TestResult {
    let records = populate()?.migrate_kv1_records(AddressKey::from_bytes([21; 32]))?;
    let bytes = crate::secret_serde::to_vec(&records, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| "serialize")?;
    let mut missing: EngineState = serde_json::from_slice(&bytes)?;
    assert_eq!(
        tune(&mut missing, json!({"options":{"version":"2"}}))
            .err()
            .ok_or("missing graph")?
            .status,
        503
    );
    assert_eq!(
        crate::secret_serde::to_vec(&missing, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "serialize")?,
        bytes
    );
    let mut state = records.clone();
    let root = state.record_root();
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(std::time::Instant::now());
    assert_eq!(
        tune(&mut state, json!({"options":{"version":"2"}}))
            .err()
            .ok_or("deadline")?
            .status,
        503
    );
    assert_eq!(state.record_root(), root);
    assert_eq!(
        crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "serialize")?,
        bytes
    );
    Ok(())
}
#[test]
fn conversion_empty_mount_and_cas_start_at_version_one_without_history_fabrication() -> TestResult {
    let mut state = EngineState::default();
    call(
        &mut state,
        "",
        "POST",
        "sys/mounts/raw",
        json!({"type":"kv","options":{"version":"1"}}),
        10,
    )?;
    assert_eq!(
        tune(&mut state, json!({"options":{"version":"2"}}))?.status,
        200
    );
    assert_eq!(
        call(&mut state, "", "GET", "raw/data/absent", json!({}), 100)
            .err()
            .ok_or("missing")?
            .status,
        404
    );
    assert_eq!(
        call(
            &mut state,
            "",
            "POST",
            "raw/data/absent",
            json!({"options":{"cas":0},"data":{"value":"first"}}),
            101
        )?
        .body["data"]["version"],
        1
    );
    assert_eq!(
        call(
            &mut state,
            "",
            "POST",
            "raw/data/absent",
            json!({"options":{"cas":0},"data":{"value":"wrong"}}),
            102
        )
        .err()
        .ok_or("CAS")?
        .status,
        400
    );
    assert_eq!(
        call(
            &mut state,
            "",
            "POST",
            "raw/data/absent",
            json!({"options":{"cas":1},"data":{"value":"second"}}),
            103
        )?
        .body["data"]["version"],
        2
    );
    assert_eq!(
        call(
            &mut state,
            "",
            "GET",
            "raw/data/absent?version=1",
            json!({}),
            104
        )?
        .body["data"]["data"]["value"],
        "first"
    );
    Ok(())
}

#[test]
fn record_conversion_capacity_refusal_preserves_source_graph_and_mount() -> TestResult {
    let mut legacy = populate()?;
    let length = crate::MAX_APPLICATION_STATE_BYTES / 64 - 100;
    for number in 0..64 {
        call(
            &mut legacy,
            "",
            "POST",
            &format!("raw/large/{number:02}"),
            json!({"value":"x".repeat(length)}),
            10,
        )?;
    }
    let mut state = legacy.migrate_kv1_records(AddressKey::from_bytes([22; 32]))?;
    let root = state.record_root();
    let metadata = crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| "metadata")?;
    assert_eq!(
        tune(&mut state, json!({"options":{"version":"2"}}))
            .err()
            .ok_or("capacity")?
            .status,
        507
    );
    assert_eq!(state.record_root(), root);
    assert_eq!(
        crate::secret_serde::to_vec(&state, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "metadata")?,
        metadata
    );
    state.validate_record_registry()?;
    for number in [0, 63] {
        let read = call(
            &mut state,
            "",
            "GET",
            &format!("raw/large/{number:02}"),
            json!({}),
            100,
        )?;
        assert!(
            read.body["data"]["value"]
                .as_str()
                .is_some_and(|value| value.len() == length)
        );
    }
    Ok(())
}
