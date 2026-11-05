//! Actual lookup routes after real Identity DELETE, including cold restore.
use super::*;
use crate::service::tests::{Root, bootstrap};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PATH: &str = "secret/data/missing-lookup143";
const SOURCE: &str =
    r#"path "secret/data/missing-lookup143" { capabilities = ["create", "update", "read"] }"#;

fn call(
    service: &mut Service,
    seconds: u64,
    method: &str,
    path: &str,
    bearer: &str,
    body: Value,
) -> TestResult<Response> {
    let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
        .map_err(|_| "original lookup clock")?
        .with_timestamp_floor(Timestamp::whole(seconds).map_err(|_| "lookup fixture timestamp")?);
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let _explicit = external_pki::PublicationClockScope::explicit();
    Ok(service.handle_request_clock(
        ServiceRequest::new(method, path, "", bearer, body),
        seconds,
        true,
        Some(clock),
    ))
}

fn fixture(native: bool) -> TestResult<(Root, Service, String, String)> {
    let root = Root::new();
    let mut service = root.service()?;
    #[cfg(feature = "native-v6-storage")]
    if native {
        service.configure_native_v6_candidate()?;
    }
    #[cfg(not(feature = "native-v6-storage"))]
    assert!(!native);
    // Native cold loading requires the original request deadline, including
    // the first unseal before activation. Model that HTTP admission explicitly.
    let (key, admin) = {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        bootstrap(&mut service)?
    };
    #[cfg(feature = "native-v6-storage")]
    if native {
        assert_eq!(
            call(
                &mut service,
                100,
                "POST",
                "sys/internal/native-v6/activate",
                &admin,
                json!({})
            )?
            .status,
            204
        );
        assert!(service.native_root.is_some());
    }
    Ok((root, service, key, admin))
}

fn lookup(
    service: &mut Service,
    admin: &str,
    seconds: u64,
    target: (&str, &str, &str),
    remaining: u64,
    present: bool,
) -> TestResult {
    let (token, accessor, entity) = target;
    for (method, path, body) in [
        ("GET", "auth/token/lookup", json!({"token":token})),
        ("POST", "auth/token/lookup", json!({"token":token})),
        (
            "POST",
            "auth/token/lookup-accessor",
            json!({"accessor":accessor}),
        ),
    ] {
        let response = call(service, seconds, method, path, admin, body)?;
        assert_eq!(response.status, 200);
        let data = response.body["data"]
            .as_object()
            .ok_or("actual token lookup data")?;
        assert_eq!(data.get("entity_id"), Some(&json!(entity)));
        assert_eq!(data.get("accessor"), Some(&json!(accessor)));
        assert_eq!(data.get("num_uses"), Some(&json!(remaining)));
        assert_eq!(data.get("policies"), Some(&json!(["lookup-token143"])));
        if present {
            assert_eq!(
                data.get("identity_policies"),
                Some(&json!(["lookup-identity143"]))
            );
        } else {
            assert!(!data.contains_key("identity_policies"));
            assert!(!data.contains_key("external_namespace_policies"));
        }
        assert!(response.body.get("auth").is_none());
    }
    Ok(())
}

fn listed(service: &mut Service, admin: &str, seconds: u64, name: &str) -> TestResult<bool> {
    let response = call(
        service,
        seconds,
        "LIST",
        "sys/policies/acl",
        admin,
        json!({}),
    )?;
    assert_eq!(response.status, 200);
    Ok(response.body["data"]["keys"]
        .as_array()
        .ok_or("actual policy keys")?
        .contains(&json!(name)))
}

fn missing_lookup_target(native: bool) -> TestResult {
    let (root, mut service, key, admin) = fixture(native)?;
    for name in ["lookup-token143", "lookup-identity143"] {
        assert_eq!(
            call(
                &mut service,
                100,
                "POST",
                &format!("sys/policies/acl/{name}"),
                &admin,
                json!({"policy":SOURCE,"expiration":101,"cas_required":true,"cas":-1})
            )?
            .status,
            204
        );
    }
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/auth/approle",
            &admin,
            json!({"type":"approle"})
        )?
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "auth/approle/role/missing-lookup143",
            &admin,
            json!({"token_policies":["lookup-token143"],"token_no_default_policy":true,
               "token_num_uses":4,"token_ttl":600})
        )?
        .status,
        204
    );
    let role = call(
        &mut service,
        100,
        "GET",
        "auth/approle/role/missing-lookup143/role-id",
        &admin,
        json!({}),
    )?;
    let secret = call(
        &mut service,
        100,
        "POST",
        "auth/approle/role/missing-lookup143/secret-id",
        &admin,
        json!({}),
    )?;
    assert_eq!(role.status, 200);
    assert_eq!(secret.status, 200);
    let login = call(
        &mut service,
        100,
        "POST",
        "auth/approle/login",
        "",
        json!({"role_id":role.body["data"]["role_id"],"secret_id":secret.body["data"]["secret_id"]}),
    )?;
    assert_eq!(login.status, 200);
    let token = login.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual AppRole token")?
        .to_owned();
    let accessor = login.body["auth"]["accessor"]
        .as_str()
        .ok_or("actual accessor")?
        .to_owned();
    let entity = login.body["auth"]["entity_id"]
        .as_str()
        .ok_or("actual Identity")?
        .to_owned();
    let entity_path = format!("identity/entity/id/{entity}");
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            &entity_path,
            &admin,
            json!({"policies":["lookup-identity143"]})
        )?
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            PATH,
            &admin,
            json!({"data":{"marker":"original"}})
        )?
        .status,
        200
    );
    assert_eq!(
        call(&mut service, 100, "GET", PATH, &token, json!({}))?.status,
        200
    );
    lookup(
        &mut service,
        &admin,
        100,
        (&token, &accessor, &entity),
        3,
        true,
    )?;

    // Existing disabled-target lookup stays successful; no target execution
    // or policy observation is implied by this administrative description.
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            &entity_path,
            &admin,
            json!({"disabled":true})
        )?
        .status,
        204
    );
    lookup(
        &mut service,
        &admin,
        100,
        (&token, &accessor, &entity),
        3,
        true,
    )?;
    assert_eq!(
        call(&mut service, 100, "DELETE", &entity_path, &admin, json!({}))?.status,
        204
    );
    assert_eq!(
        call(&mut service, 100, "GET", &entity_path, &admin, json!({}))?.status,
        404
    );
    lookup(
        &mut service,
        &admin,
        100,
        (&token, &accessor, &entity),
        3,
        false,
    )?;

    // A separate live credential without lookup permission cannot use this
    // adapter to bypass the real route's actor ACL or inspect the target.
    assert_eq!(call(&mut service, 100, "POST", "sys/policies/acl/lookup-unprivileged143", &admin,
        json!({"policy":r#"path "secret/data/missing-lookup-unrelated143" { capabilities = ["read"] }"#}))?.status, 204);
    let denied = call(
        &mut service,
        100,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["lookup-unprivileged143"],"no_default_policy":true,"ttl":600}),
    )?;
    assert_eq!(denied.status, 200);
    assert_eq!(
        denied.body["auth"]["policies"],
        json!(["lookup-unprivileged143"])
    );
    let inspector = denied.body["auth"]["client_token"]
        .as_str()
        .ok_or("unprivileged actual token")?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "auth/token/lookup",
            inspector,
            json!({"token":token})
        )?
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "auth/token/lookup-accessor",
            inspector,
            json!({"accessor":accessor})
        )?
        .status,
        403
    );
    // The original missing actor itself still fails before backend dispatch
    // and spends exactly its one original use.
    assert_eq!(
        call(
            &mut service,
            100,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({})
        )?
        .status,
        403
    );
    lookup(
        &mut service,
        &admin,
        100,
        (&token, &accessor, &entity),
        2,
        false,
    )?;

    for (path, body) in [
        ("sys/capabilities", json!({"token":token,"paths":[PATH]})),
        (
            "sys/capabilities-accessor",
            json!({"accessor":accessor,"paths":[PATH]}),
        ),
    ] {
        let response = call(&mut service, 102, "POST", path, &admin, body)?;
        assert_eq!(response.status, 400);
        assert!(response.body.get("data").is_none());
    }
    lookup(
        &mut service,
        &admin,
        102,
        (&token, &accessor, &entity),
        2,
        false,
    )?;
    // Token lookup derives Identity policy names; it does not GetPolicy for
    // the target. LIST before any GET must still see these expired policies.
    for name in ["lookup-token143", "lookup-identity143"] {
        assert!(listed(&mut service, &admin, 102, name)?);
        assert_eq!(
            call(
                &mut service,
                102,
                "POST",
                &format!("sys/policies/acl/{name}"),
                &admin,
                json!({"policy":SOURCE,"cas":-1})
            )?
            .status,
            400
        );
    }
    assert!(!service.recovery_required);
    drop(service);
    let mut service = root.service()?;
    #[cfg(feature = "native-v6-storage")]
    if native {
        service.configure_native_v6_candidate()?;
    }
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key})
        )?
        .status,
        200
    );
    #[cfg(feature = "native-v6-storage")]
    if native {
        assert!(service.native_root.is_some());
    }
    assert_eq!(
        call(&mut service, 103, "GET", &entity_path, &admin, json!({}))?.status,
        404
    );
    lookup(
        &mut service,
        &admin,
        103,
        (&token, &accessor, &entity),
        2,
        false,
    )?;
    for name in ["lookup-token143", "lookup-identity143"] {
        assert!(listed(&mut service, &admin, 103, name)?);
    }
    // A post-restart ordinary request remains a denied actor operation and
    // observes only its token policy; lookup still describes the live token.
    assert_eq!(
        call(
            &mut service,
            103,
            "POST",
            PATH,
            &token,
            json!({"data":{"marker":"must-not-publish"}})
        )?
        .status,
        403
    );
    lookup(
        &mut service,
        &admin,
        103,
        (&token, &accessor, &entity),
        1,
        false,
    )?;
    assert!(!listed(&mut service, &admin, 103, "lookup-token143")?);
    assert!(listed(&mut service, &admin, 103, "lookup-identity143")?);
    let stored = call(&mut service, 103, "GET", PATH, &admin, json!({}))?;
    assert_eq!(stored.status, 200);
    assert_eq!(stored.body["data"]["data"]["marker"], "original");
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn lookup143_ordinary_missing_identity_target_is_described_without_consumption() -> TestResult {
    missing_lookup_target(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn lookup143_native_missing_identity_target_is_described_without_consumption() -> TestResult {
    missing_lookup_target(true)
}
