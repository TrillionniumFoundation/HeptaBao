use super::tests::{Root, bootstrap, call};
use super::{RequestClock, Service};
use serde_json::{Value, json};

#[test]
fn openapi_entry_is_authenticated_revocation_aware_and_restart_stable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, root_token) = bootstrap(&mut service)?;

    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/specs/openapi",
            "",
            json!({})
        )
        .status,
        403
    );

    let bounded = call(
        &mut service,
        "POST",
        "sys/internal/specs/openapi",
        &root_token,
        json!({"generic_mount_paths":true}),
    );
    assert_eq!(bounded.status, 200);
    assert_eq!(bounded.body["openapi"], "3.0.2");
    assert_eq!(bounded.body["x-heptabao-bounded"], true);
    let paths = bounded.body["paths"].as_object().ok_or("missing paths")?;
    assert!(paths.contains_key("/sys/health"));
    assert!(paths.contains_key("/sys/internal/specs/openapi"));
    let remount_status = &paths["/sys/remount/status/{migration_id}"];
    assert!(remount_status.get("get").is_some());
    assert!(remount_status.get("x-vault-sudo").is_none());
    assert_eq!(remount_status["parameters"][0]["name"], "migration_id");
    assert!(paths.contains_key("/{secret_mount_path}/data/{path}"));
    assert!(!paths.keys().any(|path| {
        path.contains("cert_mount_path")
            || path.contains("radius")
            || path.contains("kerberos")
            || path.contains("rabbitmq")
            || path.contains("openldap")
    }));

    assert!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/openapi-reader",
            &root_token,
            json!({"policy":r#"path "sys/internal/specs/openapi" { capabilities = ["read"] }"#})
        )
        .status
            < 300
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root_token,
        json!({"policies":["openapi-reader"],"no_default_policy":true}),
    );
    assert_eq!(issued.status, 200);
    let reader = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing reader token")?
        .to_owned();

    let restricted = call(
        &mut service,
        "GET",
        "sys/internal/specs/openapi",
        &reader,
        json!({}),
    );
    assert_eq!(restricted.status, 200);
    assert_eq!(
        restricted.body["x-heptabao-policy-filtering"],
        "fail_closed_non_root_subset"
    );
    let restricted_paths = restricted.body["paths"]
        .as_object()
        .ok_or("missing restricted paths")?;
    assert!(restricted_paths.contains_key("/sys/health"));
    assert!(restricted_paths.contains_key("/sys/internal/specs/openapi"));
    assert!(!restricted_paths.contains_key("/auth/token/create"));
    assert!(!restricted_paths.contains_key("/identity/entity"));
    assert!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &root_token,
            json!({"token":reader.clone()})
        )
        .status
            < 300
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/internal/specs/openapi",
            &reader,
            json!({})
        )
        .status,
        403
    );

    let expected = bounded.body.clone();
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let reopened = call(
        &mut service,
        "POST",
        "sys/internal/specs/openapi",
        &root_token,
        json!({"generic_mount_paths":true}),
    );
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body, expected);

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/internal/specs/openapi",
            &root_token,
            json!({"generic_mount_paths":"true"})
        )
        .status,
        400
    );
    Ok(())
}

#[test]
fn openapi_uses_actual_mounts_after_remount_disable_and_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let fixture_clock =
        RequestClock::anchored(std::time::Duration::new(100, 1), std::time::Instant::now())?;
    let call = |service: &mut Service, method: &str, path: &str, token: &str, body: Value| {
        super::native_remount::tests::call_and_complete(
            service,
            fixture_clock,
            method,
            path,
            token,
            body,
        )
    };

    let (unseal, token) = bootstrap(&mut service)?;
    let initial = call(
        &mut service,
        "GET",
        "sys/internal/specs/openapi",
        &token,
        json!({}),
    );
    assert_eq!(initial.status, 200);
    assert!(
        initial.body["paths"]
            .get("/auth/userpass/login/{username}")
            .is_none()
    );
    assert!(initial.body["paths"].get("/auth/approle/login").is_none());
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/auth/team/login",
            &token,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/mounts/team/plain",
            &token,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    let mounted = call(
        &mut service,
        "GET",
        "sys/internal/specs/openapi",
        &token,
        json!({}),
    );
    assert_eq!(mounted.status, 200);
    assert!(
        mounted.body["paths"]
            .get("/auth/team/login/login/{username}")
            .is_some()
    );
    assert!(mounted.body["paths"].get("/team/plain/{path}").is_some());
    assert!(
        mounted.body["paths"]
            .get("/team/plain/data/{path}")
            .is_none()
    );
    assert!(
        call(
            &mut service,
            "POST",
            "sys/remount",
            &token,
            json!({"from":"auth/team/login/","to":"auth/team/accounts/"})
        )
        .status
            < 300
    );
    let moved = call(
        &mut service,
        "GET",
        "sys/internal/specs/openapi",
        &token,
        json!({}),
    );
    assert_eq!(moved.status, 200);
    assert!(
        moved.body["paths"]
            .get("/auth/team/accounts/login/{username}")
            .is_some()
    );
    assert!(
        moved.body["paths"]
            .get("/auth/team/login/login/{username}")
            .is_none()
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/auth/team/accounts",
            &token,
            json!({})
        )
        .status,
        204
    );
    let disabled = call(
        &mut service,
        "GET",
        "sys/internal/specs/openapi",
        &token,
        json!({}),
    );
    assert!(
        disabled.body["paths"]
            .get("/auth/team/accounts/login/{username}")
            .is_none()
    );
    let expected = disabled.body.clone();
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let reopened = call(
        &mut service,
        "GET",
        "sys/internal/specs/openapi",
        &token,
        json!({}),
    );
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body, expected);
    Ok(())
}
