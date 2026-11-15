//! Real Service owners, precise original clocks, encrypted reopen and rollback
//! fences. No public request parameter selects time or owner metadata.
use super::tests::{Root, bootstrap};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE: &str =
    r#"path "secret/data/expiration143" { capabilities = ["create", "update", "read"] }"#;

fn call(
    service: &mut Service,
    seconds: u64,
    nanos: u32,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let at = Timestamp::checked(seconds, nanos).map_err(|_| "private test timestamp")?;
    let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
        .map_err(|_| "private test clock")?
        .with_timestamp_floor(at);
    let _explicit = external_pki::PublicationClockScope::explicit();
    Ok(service.handle_request_clock(
        ServiceRequest::new(method, path, "", token, body),
        seconds,
        true,
        Some(clock),
    ))
}

#[test]
fn policy143_real_token_kv_restart_expiration_and_lazy_get_deletion() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            "sys/policies/acl/timed143",
            &admin,
            json!({"policy":SOURCE,"expiration":"1970-01-01T00:05:00.5Z"})
        )?
        .status,
        204
    );
    let issued = call(
        &mut service,
        100,
        0,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["timed143"],"ttl":600,"no_default_policy":true}),
    )?;
    assert_eq!(issued.status, 200);
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("issued token")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            101,
            0,
            "POST",
            "secret/data/expiration143",
            &token,
            json!({"data":{"phase":"before-cold-restart"}})
        )?
        .status,
        200
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        POLICY_EXPIRATION_STATE_SCHEMA
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            102,
            0,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            102,
            0,
            "GET",
            "secret/data/expiration143",
            &token,
            json!({})
        )?
        .body["data"]["data"]["phase"],
        "before-cold-restart"
    );
    assert_eq!(
        call(
            &mut service,
            300,
            500_000_000,
            "GET",
            "secret/data/expiration143",
            &token,
            json!({})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            300,
            500_000_001,
            "POST",
            "secret/data/expiration143",
            &token,
            json!({"data":{"phase":"must-not-publish"}})
        )?
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            301,
            0,
            "GET",
            "sys/policies/acl/timed143",
            &admin,
            json!({})
        )?
        .status,
        404
    );
    let list = call(
        &mut service,
        301,
        0,
        "LIST",
        "sys/policies/acl",
        &admin,
        json!({}),
    )?;
    assert!(
        !list.body["data"]["keys"]
            .as_array()
            .ok_or("policy list")?
            .contains(&json!("timed143"))
    );
    assert_eq!(
        call(
            &mut service,
            301,
            0,
            "GET",
            "secret/data/expiration143",
            &admin,
            json!({})
        )?
        .body["data"]["data"]["phase"],
        "before-cold-restart"
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            302,
            0,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            302,
            0,
            "GET",
            "sys/policies/acl/timed143",
            &admin,
            json!({})
        )?
        .status,
        404
    );
    assert_eq!(
        service.state.as_ref().ok_or("reopened state")?.schema,
        POLICY_EXPIRATION_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn policy143_path_only_state_schema_source_binding_and_restore_floor() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let before = service.state.clone().ok_or("old state")?;
    let source =
        r#"path "secret/data/expiration143" { capabilities = ["read"] expiration = "301" }"#;
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            "sys/policies/acl/path143",
            &admin,
            json!({"policy":source})
        )?
        .status,
        204
    );
    let current = service.state.clone().ok_or("timed state")?;
    assert_eq!(current.schema, POLICY_EXPIRATION_STATE_SCHEMA);
    current
        .validate_format()
        .map_err(|_| "valid expiry format")?;
    current
        .validate_publication_schema(Some(&before))
        .map_err(|_| "valid expiry publication")?;
    let encoded = crate::secret_serde::to_vec(&current, 16 * 1024 * 1024)
        .map_err(|_| "encode expiry owner")?;
    let reopened: State = serde_json::from_slice(&encoded)?;
    reopened
        .validate_format()
        .map_err(|_| "reopen expiry format")?;
    assert!(Service::validate_snapshot_protected_floor(&current, &reopened).is_ok());
    let mut low = current.clone();
    low.schema = APPROLE_LOCAL_STATE_SCHEMA;
    assert!(low.validate_format().is_err());
    assert!(low.validate_publication_schema(Some(&current)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&current, &low).is_err());
    assert_eq!(
        call(
            &mut service,
            101,
            0,
            "DELETE",
            "sys/policies/acl/path143",
            &admin,
            json!({})
        )?
        .status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired state")?;
    assert!(!retired.auth.has_policy_expiration_state());
    assert_eq!(retired.writer_schema(), POLICY_EXPIRATION_STATE_SCHEMA);
    assert!(Service::validate_snapshot_protected_floor(retired, &before).is_err());
    let mut relabeled = retired.clone();
    relabeled.schema = APPROLE_LOCAL_STATE_SCHEMA;
    assert!(
        relabeled
            .validate_publication_schema(Some(retired))
            .is_err()
    );
    Ok(())
}

#[test]
fn policy143_real_capabilities_path_expiry_and_no_target_use_consumption() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let source =
        r#"path "secret/data/expiration143" { capabilities = ["read"] expiration = "101" }"#;
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            "sys/policies/acl/caps143",
            &admin,
            json!({"policy":source})
        )?
        .status,
        204
    );
    let issued = call(
        &mut service,
        100,
        0,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["caps143"],"ttl":600,"num_uses":2,"no_default_policy":true}),
    )?;
    assert_eq!(issued.status, 200);
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("target token")?
        .to_owned();
    let body = json!({"token":token,"paths":["secret/data/expiration143"]});
    let valid = call(
        &mut service,
        101,
        0,
        "POST",
        "sys/capabilities",
        &admin,
        body.clone(),
    )?;
    assert_eq!(valid.status, 200);
    assert_eq!(valid.body["data"]["capabilities"], json!(["read"]));
    let expired = call(
        &mut service,
        101,
        1,
        "POST",
        "sys/capabilities",
        &admin,
        body,
    )?;
    assert_eq!(expired.status, 200);
    assert_eq!(expired.body["data"]["capabilities"], json!(["deny"]));
    let looked = call(
        &mut service,
        102,
        0,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":token}),
    )?;
    assert_eq!(looked.status, 200);
    assert_eq!(looked.body["data"]["num_uses"], 2);
    Ok(())
}
