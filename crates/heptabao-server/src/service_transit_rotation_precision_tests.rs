//! Precise native Transit durations use the existing writer, encrypted restart and snapshot fences.
use super::tests::{Root, bootstrap};
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use zeroize::Zeroizing;
type TestResult = Result<(), &'static str>;

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    service.handle_at(method, path, "", token, body, 100)
}
fn erase_period(value: &mut Value) -> usize {
    match value {
        Value::Object(fields) => {
            let removed = usize::from(fields.remove("auto_rotate_period_nanoseconds").is_some());
            removed + fields.values_mut().map(erase_period).sum::<usize>()
        }
        Value::Array(values) => values.iter_mut().map(erase_period).sum(),
        _ => 0,
    }
}
#[test]
fn rotation124_service_reader_publication_snapshot_restart_and_retired_floor_are_sticky()
-> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "service_failed")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "bootstrap_failed")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "POST",
            "sys/mounts/precise",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "POST",
            "precise/keys/source",
            &admin,
            json!({"type":"aes256-gcm96","allow_plaintext_backup":true,"exportable":true})
        )
        .status
            == 200
    );
    let old = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("durable_missing")?
            .export_backup()
            .map_err(|_| "snapshot_failed")?,
    );
    let exported = call(
        &mut service,
        "GET",
        "precise/backup/source",
        &admin,
        json!({}),
    );
    assert!(exported.status == 200);
    let raw = Zeroizing::new(
        BASE64
            .decode(
                exported.body["data"]["backup"]
                    .as_str()
                    .ok_or("backup_missing")?,
            )
            .map_err(|_| "backup_decode_failed")?,
    );
    let mut wire: Value = serde_json::from_slice(&raw).map_err(|_| "backup_parse_failed")?;
    wire["policy"]["auto_rotate_period"] = json!(1);
    let raw = Zeroizing::new(serde_json::to_vec(&wire).map_err(|_| "backup_encode_failed")?);
    assert!(
        call(
            &mut service,
            "POST",
            "precise/restore/copy",
            &admin,
            json!({"backup":BASE64.encode(raw.as_slice())})
        )
        .status
            == 204
    );
    let current = service.state.as_ref().ok_or("state_missing")?.clone();
    assert!(
        current.schema == TRANSIT_ROTATION_PRECISION_STATE_SCHEMA
            && current.writer_schema() == TRANSIT_ROTATION_PRECISION_STATE_SCHEMA
            && current.engines.has_transit_rotation_precision_state()
            && current.validate_format().is_ok()
    );
    assert!(
        supported_reader_schema(124) && !supported_reader_schema(MAX_SUPPORTED_STATE_SCHEMA + 1)
    );
    for schema in [SYMMETRIC_BACKUP_STATE_SCHEMA, WORKFLOW_DYNAMIC_STATE_SCHEMA] {
        let mut lower = current.clone();
        lower.schema = schema;
        assert!(lower.validate_format().is_err());
        assert!(lower.validate_publication_schema(Some(&current)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&current, &lower).is_err());
    }
    let raw = Zeroizing::new(serde_json::to_vec(&current).map_err(|_| "state_encoding_failed")?);
    let mut erased: Value = serde_json::from_slice(&raw).map_err(|_| "state_parse_failed")?;
    assert!(erase_period(&mut erased) == 1);
    let raw = Zeroizing::new(serde_json::to_vec(&erased).map_err(|_| "state_encoding_failed")?);
    let mut erased: State = serde_json::from_slice(&raw).map_err(|_| "state_parse_failed")?;
    assert!(erased.validate_publication_schema(Some(&current)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&current, &erased).is_err());
    let identity = service
        .current_state_identity()
        .map_err(|_| "identity_failed")?;
    assert!(service.commit_state(&mut erased).is_err());
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "identity_failed")?
            == identity
    );
    assert!(
        service
            .prepare_snapshot_restore(&old)
            .err()
            .is_some_and(|e| e.status == 400)
    );
    drop(service);
    let mut service = root.service().map_err(|_| "restart_failed")?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()})
        )
        .status
            == 200
    );
    let current = service.state.as_ref().ok_or("state_missing")?;
    assert!(
        current.schema == TRANSIT_ROTATION_PRECISION_STATE_SCHEMA
            && current.engines.has_transit_rotation_precision_state()
    );
    let exported = call(
        &mut service,
        "GET",
        "precise/backup/copy",
        &admin,
        json!({}),
    );
    assert!(exported.status == 200);
    let raw = Zeroizing::new(
        BASE64
            .decode(
                exported.body["data"]["backup"]
                    .as_str()
                    .ok_or("backup_missing")?,
            )
            .map_err(|_| "backup_decode_failed")?,
    );
    let output: Value = serde_json::from_slice(&raw).map_err(|_| "backup_parse_failed")?;
    assert!(output["policy"]["auto_rotate_period"] == 1);
    assert!(output["policy"]["keys"] == wire["policy"]["keys"]);
    assert!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/precise",
            &admin,
            json!({})
        )
        .status
            == 204
    );
    let retired = service.state.as_ref().ok_or("state_missing")?.clone();
    assert!(
        !retired.engines.has_transit_rotation_precision_state()
            && retired.schema == TRANSIT_ROTATION_PRECISION_STATE_SCHEMA
            && retired.writer_schema() == TRANSIT_ROTATION_PRECISION_STATE_SCHEMA
    );
    let mut lower = retired.clone();
    lower.schema = WORKFLOW_DYNAMIC_STATE_SCHEMA;
    assert!(lower.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &lower).is_err());
    let identity = service
        .current_state_identity()
        .map_err(|_| "identity_failed")?;
    assert!(service.commit_state(&mut lower).is_err());
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "identity_failed")?
            == identity
    );
    drop(service);
    let mut service = root.service().map_err(|_| "retired_restart_failed")?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()})
        )
        .status
            == 200
    );
    assert!(
        service.state.as_ref().ok_or("state_missing")?.schema
            == TRANSIT_ROTATION_PRECISION_STATE_SCHEMA
    );
    Ok(())
}
