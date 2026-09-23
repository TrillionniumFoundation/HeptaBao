//! Reader-version regressions, not historical-binary upgrade evidence.
use super::tests::{Root, bootstrap, call};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn enroll(service: &mut Service, admin: &str, configured: bool) -> TestResult {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/auth/kerberos",
            admin,
            json!({"type":"kerberos"})
        )
        .status,
        204
    );
    if configured {
        assert_eq!(
            call(
                service,
                "POST",
                "auth/kerberos/config",
                admin,
                json!({
                    "service_account":"HTTP/heptabao.test@HBKRB.TEST",
                    "realm":"HBKRB.TEST", "service":"HTTP",
                    "keytab_path":"/tmp/unused-schema-fixture.keytab",
                    "token_policies":["default"], "token_ttl":120, "token_max_ttl":600
                })
            )
            .status,
            204
        );
    }
    Ok(())
}

#[test]
fn kerberos_schema50_rejects_mount_only_and_config_hidden_under_schema48() -> TestResult {
    for configured in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        enroll(&mut service, &admin, configured)?;
        let state = service.state.as_ref().ok_or("state")?;
        assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
        assert!(state.auth.has_kerberos_state());
        assert!(state.validate_format().is_ok());
        for schema in [48, 49] {
            let mut stored = serde_json::to_value(state)?;
            stored["schema"] = json!(schema);
            let hidden: State = serde_json::from_value(stored)?;
            let rejected = hidden.validate_format().err().ok_or("downgrade admitted")?;
            assert_eq!(rejected.status, 503);
            assert_eq!(
                rejected.body["errors"][0],
                "Kerberos authentication state requires schema 50"
            );
        }
    }
    Ok(())
}

#[test]
fn kerberos_schema50_preserves_legacy48_and_workflow49_absence_and_rejects_unknown51() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, _) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    assert!(!state.auth.has_kerberos_state());
    state.schema = 48;
    assert!(state.validate_format().is_ok());
    let bytes = serde_json::to_vec(&state)?;
    let reopened: State = serde_json::from_slice(&bytes)?;
    assert!(reopened.validate_format().is_ok());
    assert_eq!(bytes, serde_json::to_vec(&reopened)?);
    assert!(
        serde_json::to_value(&reopened.auth)?
            .get("kerberos_mounts")
            .is_none()
    );
    state.schema = 49;
    assert!(state.validate_format().is_ok());
    state.schema = 51;
    assert!(state.validate_format().is_err());
    Ok(())
}

#[test]
fn kerberos_schema50_reader_fence_and_mount_configuration_survive_reopen() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    enroll(&mut service, &admin, true)?;
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    assert!(state.auth.has_kerberos_state());
    assert!(state.validate_format().is_ok());
    assert_eq!(before, serde_json::to_vec(state)?);
    let response = call(
        &mut service,
        "GET",
        "auth/kerberos/config",
        &admin,
        json!({}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["realm"], "HBKRB.TEST");
    assert!(response.body["data"].get("keytab_path").is_none());
    Ok(())
}
