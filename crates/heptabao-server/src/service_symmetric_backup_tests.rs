//! Actual Service publication, encrypted restart, snapshot and retirement fences for schema119.
use super::tests::{Root, bootstrap};
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, &'static str>;

fn call(
    service: &mut Service,
    ns: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> Response {
    service.handle_at(method, path, ns, token, body, 100)
}

#[test]
fn symmetric270_service_namespaced_backup_restore_restart_and_retirement_keep119() -> TestResult {
    let root = Root::new();
    let mut service = root.service().map_err(|_| "service_failed")?;
    let (unseal, admin) = bootstrap(&mut service).map_err(|_| "bootstrap_failed")?;
    let unseal = Zeroizing::new(unseal);
    let admin = Zeroizing::new(admin);
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/mounts/symmetric",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "symmetric/keys/ordinary",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    let ordinary = service.state.as_ref().ok_or("state_missing")?;
    assert!(
        ordinary.schema == CURRENT_STATE_SCHEMA && !ordinary.engines.has_symmetric_backup_state()
    );
    let old = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("durable_missing")?
            .export_backup()
            .map_err(|_| "old_snapshot_failed")?,
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "symmetric/keys/source",
            &admin,
            json!({"type":"xchacha20-poly1305","allow_plaintext_backup":true})
        )
        .status
            == 200
    );
    let state = service.state.as_ref().ok_or("state_missing")?;
    assert!(
        state.schema == SYMMETRIC_BACKUP_STATE_SCHEMA
            && state.writer_schema() == SYMMETRIC_BACKUP_STATE_SCHEMA
            && state.engines.has_symmetric_backup_state()
            && state.validate_format().is_ok()
    );
    for schema in [
        CURRENT_STATE_SCHEMA,
        TRANSIT_BYOK_STATE_SCHEMA,
        STANDARD_ASYMMETRIC_IMPORT_STATE_SCHEMA,
        CONTROL_GROUP_STATE_SCHEMA,
    ] {
        let mut lower = state.clone();
        lower.schema = schema;
        assert!(lower.validate_format().is_err());
        assert!(lower.validate_publication_schema(Some(state)).is_err());
        assert!(Service::validate_snapshot_protected_floor(state, &lower).is_err());
    }
    assert!(
        service
            .prepare_snapshot_restore(&old)
            .err()
            .is_some_and(|e| e.status == 400),
        "authenticated pre119 backup cannot lower the current feature floor"
    );
    let plaintext = BASE64.encode(b"public namespaced backup restoration fixture");
    let encrypted = call(
        &mut service,
        "",
        "POST",
        "symmetric/encrypt/source",
        &admin,
        json!({"plaintext":plaintext}),
    );
    assert!(encrypted.status == 200);
    let ciphertext = Zeroizing::new(
        encrypted.body["data"]["ciphertext"]
            .as_str()
            .ok_or("ciphertext_missing")?
            .to_owned(),
    );
    let backup = call(
        &mut service,
        "",
        "GET",
        "symmetric/backup/source",
        &admin,
        json!({}),
    );
    assert!(backup.status == 200);
    let backup = Zeroizing::new(
        backup.body["data"]["backup"]
            .as_str()
            .ok_or("backup_missing")?
            .to_owned(),
    );
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/namespaces/backup-team",
            &admin,
            json!({})
        )
        .status
            == 200
    );
    assert!(
        call(
            &mut service,
            "backup-team",
            "POST",
            "sys/mounts/symmetric",
            &admin,
            json!({"type":"transit"})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "backup-team",
            "POST",
            "symmetric/restore/copy",
            &admin,
            json!({"backup":backup.as_str()})
        )
        .status
            == 204
    );
    let restored = call(
        &mut service,
        "backup-team",
        "POST",
        "symmetric/decrypt/copy",
        &admin,
        json!({"ciphertext":ciphertext.as_str()}),
    );
    assert!(
        restored.status == 200 && restored.body["data"]["plaintext"] == plaintext,
        "the real namespaced route restores the original encryption material"
    );
    let identity = service
        .current_state_identity()
        .map_err(|_| "identity_failed")?;
    assert!(
        call(
            &mut service,
            "backup-team",
            "POST",
            "symmetric/restore/copy",
            &admin,
            json!({"backup":backup.as_str()})
        )
        .status
            == 500
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "identity_failed")?
            == identity,
        "duplicate restore keeps the authoritative storage identity"
    );
    drop(service);
    let mut service = root.service().map_err(|_| "restart_failed")?;
    assert!(
        call(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()})
        )
        .status
            == 200
    );
    assert!(service.state.as_ref().ok_or("state_missing")?.schema == SYMMETRIC_BACKUP_STATE_SCHEMA);
    let restored = call(
        &mut service,
        "backup-team",
        "POST",
        "symmetric/decrypt/copy",
        &admin,
        json!({"ciphertext":ciphertext.as_str()}),
    );
    assert!(
        restored.status == 200 && restored.body["data"]["plaintext"] == plaintext,
        "encrypted restart retains the schema119 namespaced versions"
    );
    assert!(
        call(
            &mut service,
            "",
            "DELETE",
            "sys/mounts/symmetric",
            &admin,
            json!({})
        )
        .status
            == 204
    );
    assert!(
        call(
            &mut service,
            "backup-team",
            "DELETE",
            "sys/mounts/symmetric",
            &admin,
            json!({})
        )
        .status
            == 204
    );
    let retired = service
        .state
        .as_ref()
        .ok_or("retired_state_missing")?
        .clone();
    assert!(
        !retired.engines.has_symmetric_backup_state()
            && retired.schema == SYMMETRIC_BACKUP_STATE_SCHEMA
            && retired.writer_schema() == SYMMETRIC_BACKUP_STATE_SCHEMA
    );
    let mut lower = retired.clone();
    lower.schema = CONTROL_GROUP_STATE_SCHEMA;
    assert!(lower.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &lower).is_err());
    let identity = service
        .current_state_identity()
        .map_err(|_| "identity_failed")?;
    assert!(
        service.commit_state(&mut lower).is_err(),
        "retired119 cannot remove its sticky writer floor"
    );
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
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal.as_str()})
        )
        .status
            == 200
    );
    let current = service.state.as_ref().ok_or("retired_state_missing")?;
    assert!(
        current.schema == SYMMETRIC_BACKUP_STATE_SCHEMA
            && !current.engines.has_symmetric_backup_state()
    );
    Ok(())
}
