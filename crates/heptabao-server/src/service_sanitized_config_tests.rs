//! OpenBao 2.7.1 sanitized configuration is process-owned, ACL-gated,
//! audited by the original Service request pipeline, and fail-closed.
use super::tests::{Root, bootstrap_unmounted, call};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn sanitized_config_needs_live_bootstrap_projection_and_authenticated_read() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let projection = json!({
        "enable_ui": false,
        "listeners": [{"type":"tcp","config":{"address":"127.0.0.1:8200","tls_disable":0}}],
        "storage": {"type":"pebbledb"}
    });
    assert!(
        service
            .install_sanitized_configuration(projection.clone())
            .is_ok()
    );
    assert!(service.install_sanitized_configuration(json!({})).is_err());
    let (_unseal, admin) = bootstrap_unmounted(&mut service)?;
    assert!(service.install_sanitized_configuration(json!({})).is_err());
    let read = call(
        &mut service,
        "GET",
        "sys/config/state/sanitized",
        &admin,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"], projection);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/config/state/sanitized",
            "",
            json!({})
        )
        .status,
        403,
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/config/state/sanitized",
            "invalid-reader",
            json!({})
        )
        .status,
        403,
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/config/state/sanitized",
            &admin,
            json!({})
        )
        .status,
        405,
    );
    Ok(())
}

#[test]
fn sanitized_config_explicit_read_policy_grants_no_secret_write() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    service.install_sanitized_configuration(json!({"enable_ui":false}))?;
    let (_unseal, admin) = bootstrap_unmounted(&mut service)?;
    let pol = r#"path "sys/config/state/sanitized" { capabilities = ["read"] }"#;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/sanitized-probe",
            &admin,
            json!({"policy":pol})
        )
        .status,
        204
    );
    let child = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["sanitized-probe"],"ttl":"1h"}),
    );
    assert_eq!(child.status, 200);
    let reader = child.body["auth"]["client_token"]
        .as_str()
        .ok_or("reader token")?;
    let authorized = call(
        &mut service,
        "GET",
        "sys/config/state/sanitized",
        reader,
        json!({}),
    );
    assert_eq!(authorized.status, 200);
    assert_eq!(authorized.body["data"]["enable_ui"], false);
    let denied = call(
        &mut service,
        "POST",
        "sys/mounts/forbidden",
        reader,
        json!({"type":"kv"}),
    );
    assert_eq!(denied.status, 403);
    Ok(())
}
