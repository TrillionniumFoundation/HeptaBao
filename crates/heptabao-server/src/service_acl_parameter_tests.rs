//! End-to-end ACL parameter constraints at the real Service boundary.
use super::tests::{Root, bootstrap, call};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PARAMETER_POLICY: &str = r#"
path "acl-param/item" {
  capabilities = ["create", "read", "update", "delete"]
  required_parameters = ["foo"]
  allowed_parameters = {
    "foo" = ["good*"]
    "bar" = [1, 2]
    "flag" = [false]
    "map" = [{"good" = "one"}]
  }
  denied_parameters = {
    "blocked" = []
  }
}
path "acl-param/*" {
  capabilities = ["list", "scan"]
  required_parameters = ["never"]
  denied_parameters = { "*" = [] }
}
"#;

fn setup() -> TestResult<(Root, Service, String, String, String)> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/acl-param",
            &root_token,
            json!({"type":"kv","options":{"version":"1"}}),
        )
        .status,
        204
    );
    let mut legacy = service.state.clone().ok_or("state")?;
    legacy.schema = 57;
    legacy.validate_format().map_err(|_| "legacy format")?;
    crate::service::tests::commit_legacy_state_fixture(&mut service, &legacy)
        .map_err(|_| "publish schema 57")?;
    service.state = Some(legacy);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("schema 57 state")?.schema,
        57,
        "a parameter-free schema-57 state reopens without implicit promotion"
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/parameter-guard",
            &root_token,
            json!({"policy":PARAMETER_POLICY}),
        )
        .status,
        204
    );
    assert_eq!(
        service.state.as_ref().ok_or("schema 58 state")?.schema,
        CURRENT_STATE_SCHEMA,
        "the first constraint-bearing mutation publishes the current schema"
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root_token,
        json!({"policies":["parameter-guard"],"no_default_policy":true,"ttl":"1h"}),
    );
    assert_eq!(issued.status, 200);
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    Ok((root, service, key, root_token, token))
}

#[test]
fn acl_parameters_enforce_required_allowed_denied_and_value_rules_without_effects() -> TestResult {
    let (_root, mut service, _, root_token, token) = setup()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acl-param/item",
            &token,
            json!({"foo":"good-value"}),
        )
        .status,
        204
    );
    let original = call(&mut service, "GET", "acl-param/item", &token, json!({}));
    assert_eq!(
        original.status, 403,
        "required parameters also apply to reads"
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "acl-param/item",
            &root_token,
            json!({})
        )
        .body["data"],
        json!({"foo":"good-value"})
    );
    assert_eq!(
        call(&mut service, "LIST", "acl-param/", &token, json!({})).body["data"]["keys"],
        json!(["item"]),
        "generic request-parameter rules do not apply to list"
    );
    assert_eq!(
        call(&mut service, "SCAN", "acl-param/", &token, json!({})).body["data"]["keys"],
        json!(["item"]),
        "generic request-parameter rules do not apply to scan"
    );
    let list_only_policy = r#"path "acl-param/*" { capabilities = ["list"] }"#;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/list-only",
            &root_token,
            json!({"policy":list_only_policy})
        )
        .status,
        204
    );
    let list_only = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root_token,
        json!({"policies":["list-only"],"no_default_policy":true,"ttl":"1h"}),
    );
    let list_only = list_only.body["auth"]["client_token"]
        .as_str()
        .ok_or("list-only token")?
        .to_owned();
    assert_eq!(
        call(&mut service, "LIST", "acl-param/", &list_only, json!({})).status,
        200
    );
    assert_eq!(
        call(&mut service, "SCAN", "acl-param/", &list_only, json!({})).status,
        403,
        "OpenBao scan is an independent capability, not recursive list authority"
    );
    for body in [
        json!({"bar":1}),
        json!({"foo":"wrong"}),
        json!({"foo":"good-value","unknown":1}),
        json!({"foo":"good-value","blocked":"anything"}),
        json!({"foo":"good-value","bar":3}),
        json!({"foo":"good-value","flag":true}),
    ] {
        assert_eq!(
            call(&mut service, "POST", "acl-param/item", &token, body).status,
            403
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "acl-param/item",
                &root_token,
                json!({})
            )
            .body["data"],
            json!({"foo":"good-value"})
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acl-param/item",
            &token,
            json!({"foo":"good-map","flag":false,"map":{"good":"one"}}),
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "DELETE", "acl-param/item", &token, json!({})).status,
        204,
        "generic request-parameter rules do not apply to delete"
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "acl-param/item",
            &root_token,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acl-param/item",
            &token,
            json!({"foo":"good-after-delete"}),
        )
        .status,
        204
    );
    Ok(())
}

#[test]
fn acl_parameter_state_requires_schema58_and_survives_reopen() -> TestResult {
    let (root, service, key, _root_token, token) = setup()?;
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    let mut downgraded = service.state.clone().ok_or("state")?;
    downgraded.schema = 57;
    assert!(downgraded.validate_format().is_err());
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "acl-param/item",
            &token,
            json!({"foo":"good-after-restart"}),
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "acl-param/item",
            &token,
            json!({"foo":"bad-after-restart"}),
        )
        .status,
        403
    );
    Ok(())
}

#[test]
fn acl_schema58_reopens_under_schema59_and_promotes_only_on_mutation() -> TestResult {
    let (root, mut service, key, root_token, token) = setup()?;
    let mut legacy = service.state.clone().ok_or("state")?;
    legacy.schema = 58;
    assert!(legacy.validate_format().is_ok());
    assert!(legacy.auth.has_acl_parameter_state());
    assert!(!legacy.engines.has_pki_extension_state());
    crate::service::tests::commit_legacy_state_fixture(&mut service, &legacy)
        .map_err(|_| "publish prior ACL schema")?;
    service.state = Some(legacy);
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(reopened.state.as_ref().ok_or("state")?.schema, 58);
    assert_eq!(
        call(
            &mut reopened,
            "GET",
            "sys/policies/acl/parameter-guard",
            &root_token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(reopened.state.as_ref().ok_or("state")?.schema, 58);
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "acl-param/item",
            &token,
            json!({"foo":"good-after-schema58"})
        )
        .status,
        204
    );
    assert_eq!(
        reopened.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "acl-param/item",
            &token,
            json!({"foo":"bad-after-schema58"})
        )
        .status,
        403
    );
    Ok(())
}

#[test]
fn acl_wrapping_ttl_policy_ingress_accepts_native_attributes() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let response = call(
        &mut service,
        "PUT",
        "sys/policies/acl/wrapping-guard",
        &token,
        json!({"policy":r#"path "secret/data/item" { capabilities = ["read"] min_wrapping_ttl = "10s" max_wrapping_ttl = "30s" }"#}),
    );
    assert_eq!(
        response.status, 204,
        "native wrapping constraints must be admitted"
    );
    Ok(())
}

#[path = "service_acl_wrapping_tests.rs"]
mod wrapping;
