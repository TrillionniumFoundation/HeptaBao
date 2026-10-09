//! Actual Service owner, durable reopen, ACL scope, and precise KV2 controls.
use super::tests::{Root, bootstrap, call, limited_token};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn stamp(seconds: u64, nanos: u32) -> TestResult<String> {
    Ok(Timestamp::checked(seconds, nanos)?.rfc3339())
}

fn bundle() -> TestResult<Value> {
    let value = crate::engines::decode_lossless_json(br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"},"raw":{"$serde_json::private::RawValue":"[1]"}}"#)?;
    Ok(json!({
        "schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":3,"cas_required":false,"metadata_cas_required":false,"delete_version_after":"0s"},
        "entries":{
            "item":{
                "created_time":stamp(90,113)?,"updated_time":stamp(95,113)?,
                "current_version":5,"current_metadata_version":2,"oldest_version":3,
                "max_versions":3,"cas_required":true,"metadata_cas_required":true,
                "delete_version_after":"0s","custom_metadata":{"owner":"import"},
                "versions":{
                    "3":{"created_time":stamp(93,113)?,"deletion_time":"","destroyed":true,"data":null},
                    "4":{"created_time":stamp(94,113)?,"deletion_time":stamp(96,113)?,"destroyed":false,"data":{"old":true}},
                    "5":{"created_time":stamp(95,113)?,"deletion_time":"","destroyed":false,"data":value}
                }
            },
            "scheduled":{
                "created_time":stamp(95,113)?,"updated_time":stamp(95,113)?,
                "current_version":1,"current_metadata_version":0,"oldest_version":0,
                "max_versions":0,"cas_required":false,"metadata_cas_required":false,
                "delete_version_after":"7200.5s","custom_metadata":null,
                "versions":{"1":{"created_time":stamp(95,113)?,"deletion_time":stamp(200,500000000)?,
                    "source_deletion_time":stamp(7295,113)?,"destroyed":false,"data":{"scheduled":true}}}
            },
            "metadata-only":{
                "created_time":stamp(95,113)?,"updated_time":stamp(95,113)?,
                "current_version":0,"current_metadata_version":1,"oldest_version":0,
                "max_versions":0,"cas_required":false,"metadata_cas_required":true,
                "delete_version_after":"0s","custom_metadata":{},"versions":{}
            }
        }
    }))
}

fn payload() -> TestResult<Value> {
    Ok(json!({"mount":"secret","bundle":bundle()?}))
}

fn engine_bytes(service: &Service) -> TestResult<Vec<u8>> {
    Ok(crate::secret_serde::to_vec(
        &*service.state.as_ref().ok_or("state")?.engines,
        crate::MAX_APPLICATION_STATE_BYTES,
    )
    .map_err(|_| "KV2 engine state encoding failed")?
    .to_vec())
}

fn imported(service: &mut Service, token: &str) -> TestResult {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/migration/openbao/kv2",
            token,
            payload()?
        )
        .status,
        204
    );
    Ok(())
}

#[test]
fn kv2_import_service_rejects_bad_bundle_and_unprivileged_scope_without_engine_changes()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let before = engine_bytes(&service)?;
    let actor = limited_token(
        &mut service,
        &token,
        r#"path "sys/migration/openbao/kv2" { capabilities=["update"] }"#,
    )?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/migration/openbao/kv2",
            &actor,
            payload()?
        )
        .status,
        403
    );
    assert_eq!(engine_bytes(&service)?, before);
    for (index, mut bad) in [payload()?, payload()?, payload()?].into_iter().enumerate() {
        // A valid first record cannot publish when a later record is invalid.
        match index {
            0 => bad["bundle"]["entries"]["scheduled"]["versions"]["1"]["destroyed"] = json!(true),
            1 => bad["bundle"]["entries"]["scheduled"]["unknown"] = json!(true),
            _ => {
                bad["bundle"]["entries"]["item"]["versions"]
                    .as_object_mut()
                    .ok_or("versions")?
                    .remove("4");
            }
        }
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/migration/openbao/kv2",
                &token,
                bad
            )
            .status,
            400
        );
        assert_eq!(engine_bytes(&service)?, before);
    }
    let mut crossing = payload()?;
    crossing["namespace"] = json!("child");
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/migration/openbao/kv2",
            &token,
            crossing
        )
        .status,
        400
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/migration/openbao/kv2",
                "missing",
                &token,
                payload()?,
                100
            )
            .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/migration/openbao/kv2",
            &token,
            payload()?
        )
        .status,
        405
    );
    assert_eq!(engine_bytes(&service)?, before);
    imported(&mut service, &token)?;
    assert_ne!(engine_bytes(&service)?, before);
    Ok(())
}

#[test]
fn kv2_import_service_refuses_existing_data_and_replayed_empty_import() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/existing",
            &token,
            json!({"data":{"retained":true}})
        )
        .status,
        200
    );
    let before = engine_bytes(&service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/migration/openbao/kv2",
            &token,
            payload()?
        )
        .status,
        409
    );
    assert_eq!(engine_bytes(&service)?, before);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/empty",
            &token,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    let mut empty = bundle()?;
    empty["entries"] = json!({});
    empty["config"]["max_versions"] = json!(0);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/migration/openbao/kv2",
            &token,
            json!({"mount":"empty","bundle":empty.clone()})
        )
        .status,
        204
    );
    let installed = engine_bytes(&service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/migration/openbao/kv2",
            &token,
            json!({"mount":"empty","bundle":empty})
        )
        .status,
        409
    );
    assert_eq!(engine_bytes(&service)?, installed);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/existing",
            &token,
            json!({})
        )
        .body["data"]["data"],
        json!({"retained":true})
    );
    Ok(())
}

#[test]
fn kv2_import_service_durable_reopen_preserves_all_history_counters_and_secret_numbers()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    imported(&mut service, &token)?;
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, KV2_LOSSLESS_STATE_SCHEMA);
    state
        .validate_format()
        .map_err(|_| "KV2 state format validation failed")?;
    let before = engine_bytes(&service)?;
    let current = call(&mut service, "GET", "secret/data/item", &token, json!({}));
    assert_eq!(current.status, 200);
    assert_eq!(
        current.body["data"]["metadata"]["created_time"],
        stamp(95, 113)?
    );
    assert_eq!(
        current.body["data"]["data"],
        bundle()?["entries"]["item"]["versions"]["5"]["data"]
    );
    assert!(current.body["data"]["data"]["fake"].is_object());
    assert_eq!(
        current.body["data"]["data"]["big"]
            .as_number()
            .ok_or("number")?
            .to_string(),
        "184467440737095516160001"
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/item",
            &token,
            json!({"version":3})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/item",
            &token,
            json!({"version":4})
        )
        .status,
        404
    );
    let metadata = call(
        &mut service,
        "GET",
        "secret/metadata/item",
        &token,
        json!({}),
    );
    assert_eq!(metadata.body["data"]["oldest_version"], 3);
    assert_eq!(metadata.body["data"]["current_version"], 5);
    assert_eq!(metadata.body["data"]["current_metadata_version"], 2);
    assert_eq!(metadata.body["data"]["versions"]["3"]["destroyed"], true);
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(engine_bytes(&reopened)?, before);
    assert_eq!(
        reopened.state.as_ref().ok_or("reopened")?.schema,
        KV2_LOSSLESS_STATE_SCHEMA
    );
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "secret/data/item",
            &token,
            json!({"data":{"x":1},"options":{"cas":4}})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "secret/metadata/item",
            &token,
            json!({"metadata_cas":1,"custom_metadata":{"x":"y"}})
        )
        .status,
        400
    );
    assert_eq!(engine_bytes(&reopened)?, before);
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "secret/data/item",
            &token,
            json!({"data":{"x":1},"options":{"cas":5}})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn kv2_import_service_snapshot_recovery_keeps_precise_payload_and_sticky_schema() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    imported(&mut service, &token)?;
    let original = engine_bytes(&service)?;
    let backup = call(
        &mut service,
        "GET",
        "sys/storage/raft/snapshot",
        &token,
        json!({}),
    );
    assert_eq!(backup.status, 200);
    let snapshot = backup.body["data"]["snapshot"]
        .as_str()
        .ok_or("snapshot")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/item",
            &token,
            json!({"data":{"new":true},"options":{"cas":5}})
        )
        .status,
        200
    );
    assert_ne!(engine_bytes(&service)?, original);
    let restored = call(
        &mut service,
        "POST",
        "sys/storage/raft/snapshot-force",
        &token,
        json!({"snapshot":snapshot}),
    );
    assert_eq!(restored.status, 200);
    assert_eq!(engine_bytes(&service)?, original);
    let state = service.state.as_ref().ok_or("restored")?;
    assert_eq!(state.schema, KV2_LOSSLESS_STATE_SCHEMA);
    state
        .validate_format()
        .map_err(|_| "KV2 state format validation failed")?;
    Ok(())
}

#[test]
fn kv2_import_service_uses_the_captured_precise_clock_on_read_and_write_dispatch() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    imported(&mut service, &token)?;
    let clock = RequestClock::anchored(
        std::time::Duration::new(110, 113),
        std::time::Instant::now(),
    )?;
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method: "POST",
            path: "secret/data/new",
            namespace: "",
            token: &token,
            body: json!({"data":{"precise":true}}),
            now: 110,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    let written = service.finish_synchronous_request(execution);
    assert_eq!(written.status, 200);
    let text = written.body["data"]["created_time"]
        .as_str()
        .ok_or("created time")?;
    assert!(text.starts_with("1970-01-01T00:01:50."));
    assert_ne!(text, Timestamp::whole(110)?.rfc3339());
    let expired = RequestClock::anchored(
        std::time::Duration::new(200, 600000000),
        std::time::Instant::now(),
    )?;
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method: "GET",
            path: "secret/data/scheduled",
            namespace: "",
            token: &token,
            body: json!({}),
            now: 200,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        expired,
    );
    let read = service.finish_synchronous_request(execution);
    assert_eq!(read.status, 404);
    assert_eq!(read.body["data"]["data"], Value::Null);
    Ok(())
}

#[test]
fn kv2_import_schema_floor_survives_mount_retirement_and_rejects_torn_marker() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    imported(&mut service, &token)?;
    let previous = service.state.as_ref().ok_or("state")?.clone();
    let mut downgrade = previous.clone();
    downgrade.schema = CONTROL_GROUP_STATE_SCHEMA;
    assert!(downgrade.validate_format().is_err());
    assert!(
        downgrade
            .validate_publication_schema(Some(&previous))
            .is_err()
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/secret",
            &token,
            json!({})
        )
        .status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired")?.clone();
    assert_eq!(retired.schema, KV2_LOSSLESS_STATE_SCHEMA);
    assert!(retired.engines.has_kv2_lossless_state());
    retired
        .validate_format()
        .map_err(|_| "retired KV2 state format validation failed")?;
    retired
        .validate_publication_schema(Some(&previous))
        .map_err(|_| "retired KV2 publication validation failed")?;
    let mut wire = serde_json::to_value(&*retired.engines)?;
    wire.as_object_mut()
        .ok_or("engine object")?
        .remove("kv2_lossless_format");
    let mut torn = retired.clone();
    torn.engines = serde_json::from_value::<EngineState>(wire)?.into();
    assert!(torn.validate_format().is_err());
    assert!(torn.validate_publication_schema(Some(&retired)).is_err());
    assert_eq!(torn.writer_schema(), KV2_LOSSLESS_STATE_SCHEMA);
    Ok(())
}
