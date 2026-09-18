use super::tests::{Root, bootstrap, call};
use serde_json::json;

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
    assert!(paths.contains_key("/{kv_mount_path}/data/{path}"));
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
    let restricted_paths = restricted.body["paths"].as_object().ok_or("missing restricted paths")?;
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
