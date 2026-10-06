use super::tests::{Root, bootstrap_unmounted, call};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn auth_mount_options_native_pairs_and_errors_preserve_rejected_state() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    for (label, options, expected) in [
        ("empty", json!({}), json!({})),
        ("null", Value::Null, Value::Null),
        (
            "map",
            json!({"custom":"value","":"value"}),
            json!({"custom":"value","":"value"}),
        ),
        (
            "scalars",
            json!({"flag":true,"zero":false,"n":1,"nil":null}),
            json!({"flag":"1","zero":"0","n":"1","nil":""}),
        ),
        (
            "array",
            json!(["foo=one", "foo=two", "empty="]),
            json!({"foo":"two","empty":""}),
        ),
        ("text", json!("foo=bar,a=b"), json!({"foo":"bar,a=b"})),
        (
            "map-array",
            json!([{"one":1},{"flag":true}]),
            json!({"one":"1","flag":"1"}),
        ),
        ("decoded-null", json!([null]), Value::Null),
        (
            "empty-version",
            json!({"version":null}),
            json!({"version":""}),
        ),
    ] {
        let mounted = call(
            &mut service,
            "POST",
            &format!("sys/auth/{label}"),
            &admin,
            json!({"type":"userpass","options":options}),
        );
        assert_eq!(
            mounted.status,
            204,
            "{label}: {:?}",
            mounted.body.get("errors")
        );
        let read = call(&mut service, "GET", "sys/auth", &admin, json!({}));
        assert_eq!(read.body["data"][format!("{label}/")]["options"], expected);
    }
    for (label, options, error) in [
        (
            "version",
            json!({"version":"2"}),
            "auth method \"userpass\" does not allow setting a version",
        ),
        (
            "scalar",
            json!(42),
            "Field validation failed: error converting input for field \"options\": invalid key pair at index 0 in field \"options\"",
        ),
        (
            "array-value",
            json!({"k":["v"]}),
            "Field validation failed: error converting input for field \"options\": decoding failed due to the following error(s):\n\n'[0]' expected type 'string', got unconvertible type 'map[string]interface {}'",
        ),
    ] {
        let before = service.current_state_identity().map_err(|_| "identity")?;
        let rejected = call(
            &mut service,
            "POST",
            &format!("sys/auth/{label}"),
            &admin,
            json!({"type":"userpass","options":options}),
        );
        assert_eq!(rejected.status, 400);
        assert_eq!(rejected.body, json!({"errors":[error]}));
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            before
        );
    }
    Ok(())
}

#[test]
fn auth_mount_options_encrypted_reopen_revision_and_sticky_snapshot_floor() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap_unmounted(&mut service)?;
    let previous = service.state.clone().ok_or("previous")?;
    let backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let created = call(
        &mut service,
        "POST",
        "sys/auth/options",
        &admin,
        json!({"type":"userpass","options":{"custom":"original"}}),
    );
    assert_eq!(created.status, 204);
    let active = service.state.clone().ok_or("active")?;
    assert_eq!(active.schema, AUTH_MOUNT_OPTIONS_STATE_SCHEMA);
    assert!(active.auth.has_auth_mount_options_state());
    let mut lower = active.clone();
    lower.schema = SDK_ACCEPTED_SECRET_STATE_SCHEMA;
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(&active)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&active, &previous).is_err());
    assert!(service.prepare_snapshot_restore(&backup).is_err());
    let first = call(&mut service, "GET", "sys/auth/options", &admin, json!({}));
    let revision = first.body["data"]["revision"].as_u64().ok_or("revision")?;
    let updated = call(
        &mut service,
        "POST",
        "sys/auth/options",
        &admin,
        json!({"type":"userpass","options":{"custom":"next"},"cas_revision":revision}),
    );
    assert_eq!(updated.status, 204);
    let changed = call(&mut service, "GET", "sys/auth/options", &admin, json!({}));
    assert_eq!(changed.body["data"]["revision"], revision + 1);
    assert_eq!(
        changed.body["data"]["accessor"],
        first.body["data"]["accessor"]
    );
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let stale = call(
        &mut service,
        "POST",
        "sys/auth/options",
        &admin,
        json!({"type":"userpass","options":null,"cas_revision":revision}),
    );
    assert_eq!(stale.status, 409);
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let read = call(&mut reopened, "GET", "sys/auth", &admin, json!({}));
    assert_eq!(
        read.body["data"]["options/"]["options"],
        json!({"custom":"next"})
    );
    assert_eq!(
        call(
            &mut reopened,
            "DELETE",
            "sys/auth/options",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let retired = reopened.state.clone().ok_or("retired")?;
    assert!(!retired.auth.has_auth_mount_options_state());
    assert_eq!(retired.schema, AUTH_MOUNT_OPTIONS_STATE_SCHEMA);
    let mut lower = retired.clone();
    lower.schema = SDK_ACCEPTED_SECRET_STATE_SCHEMA;
    assert!(lower.validate_format().is_ok());
    assert!(lower.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &lower).is_err());
    Ok(())
}

#[test]
fn auth_mount_options_empty_input_preserves_legacy_serialized_auth_shape() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/empty",
            &admin,
            json!({"type":"userpass","options":{}})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert!(!state.auth.has_auth_mount_options_state());
    assert!(state.schema < AUTH_MOUNT_OPTIONS_STATE_SCHEMA);
    let before = serde_json::to_vec(&state.auth)?;
    let decoded: AuthState = serde_json::from_slice(&before)?;
    assert_eq!(serde_json::to_vec(&decoded)?, before);
    assert!(!String::from_utf8(before)?.contains("\"options\""));
    Ok(())
}
