//! Fixed 2.7.1 accessor methods through real ordinary/native Service admission.
use super::*;
use crate::service::tests::{Root, bootstrap};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROUTE: &str = "auth/token/lookup-accessor";
const READ: &str = r#"path "auth/token/lookup-accessor" { capabilities = ["read"] }"#;
const UPDATE: &str = r#"path "auth/token/lookup-accessor" { capabilities = ["update"] }"#;

fn call(
    service: &mut Service,
    seconds: u64,
    method: &str,
    path: &str,
    bearer: &str,
    body: Value,
) -> TestResult<Response> {
    let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
        .map_err(|_| "original accessor request clock")?
        .with_timestamp_floor(Timestamp::whole(seconds).map_err(|_| "accessor fixture timestamp")?);
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

fn reopen(root: &Root, key: &str, native: bool) -> TestResult<Service> {
    let mut service = root.service()?;
    #[cfg(feature = "native-v6-storage")]
    if native {
        service.configure_native_v6_candidate()?;
    }
    #[cfg(not(feature = "native-v6-storage"))]
    assert!(!native);
    assert_eq!(
        call(
            &mut service,
            201,
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
    Ok(service)
}

fn policy(service: &mut Service, admin: &str, name: &str, source: &str, timed: bool) -> TestResult {
    let mut body = json!({"policy":source,"cas_required":true,"cas":-1});
    if timed {
        body["expiration"] = json!(150);
    }
    assert_eq!(
        call(
            service,
            100,
            "POST",
            &format!("sys/policies/acl/{name}"),
            admin,
            body
        )?
        .status,
        204
    );
    Ok(())
}

fn issued(response: Response, policies: &[&str]) -> TestResult<(String, String, String)> {
    assert_eq!(response.status, 200);
    let auth = &response.body["auth"];
    assert_eq!(auth["policies"], json!(policies));
    Ok((
        auth["client_token"]
            .as_str()
            .ok_or("actual issued token")?
            .to_owned(),
        auth["accessor"]
            .as_str()
            .ok_or("actual issued accessor")?
            .to_owned(),
        auth["entity_id"].as_str().unwrap_or_default().to_owned(),
    ))
}

fn token(
    service: &mut Service,
    admin: &str,
    policies: &[&str],
    uses: u64,
) -> TestResult<(String, String, String)> {
    issued(
        call(
            service,
            100,
            "POST",
            "auth/token/create",
            admin,
            json!({"policies":policies,"no_default_policy":true,"num_uses":uses,"ttl":600}),
        )?,
        policies,
    )
}

fn approle(
    service: &mut Service,
    admin: &str,
    name: &str,
    policies: &[&str],
) -> TestResult<(String, String, String)> {
    let role = format!("auth/approle/role/{name}");
    assert_eq!(
        call(
            service,
            100,
            "POST",
            &role,
            admin,
            json!({"token_policies":policies,"token_no_default_policy":true,
               "token_num_uses":4,"token_ttl":600})
        )?
        .status,
        204
    );
    let role_id = call(
        service,
        100,
        "GET",
        &format!("{role}/role-id"),
        admin,
        json!({}),
    )?;
    let secret = call(
        service,
        100,
        "POST",
        &format!("{role}/secret-id"),
        admin,
        json!({}),
    )?;
    assert_eq!(role_id.status, 200);
    assert_eq!(secret.status, 200);
    issued(
        call(
            service,
            100,
            "POST",
            "auth/approle/login",
            "",
            json!({"role_id":role_id.body["data"]["role_id"],
               "secret_id":secret.body["data"]["secret_id"]}),
        )?,
        policies,
    )
}

fn remaining(
    service: &mut Service,
    admin: &str,
    seconds: u64,
    token: &str,
    expected: u64,
) -> TestResult {
    let response = call(
        service,
        seconds,
        "POST",
        "auth/token/lookup",
        admin,
        json!({"token":token}),
    )?;
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["num_uses"], expected);
    Ok(())
}

fn denied(response: Response, status: u16) {
    assert_eq!(response.status, status);
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("auth").is_none());
    if status == 405 {
        assert_eq!(response.body["errors"], json!(["unsupported operation"]));
    }
}

fn description(response: Response, accessor: &str, uses: u64, missing_identity: bool) {
    assert_eq!(response.status, 200);
    let data = &response.body["data"];
    assert!(data["accessor"].as_str() == Some(accessor));
    assert_eq!(data["id"], "");
    assert_eq!(data["num_uses"], uses);
    if missing_identity {
        assert!(data.get("identity_policies").is_none());
        assert!(data.get("external_namespace_policies").is_none());
    }
    assert!(response.body.get("auth").is_none());
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

fn method_matrix(native: bool) -> TestResult {
    let (root, mut service, key, admin) = fixture(native)?;
    policy(&mut service, &admin, "accessor-read143", READ, false)?;
    policy(&mut service, &admin, "accessor-update143", UPDATE, false)?;
    policy(
        &mut service,
        &admin,
        "accessor-required143",
        r#"path "auth/token/lookup-accessor" { capabilities = ["read"] required_parameters = ["accessor"] }"#,
        false,
    )?;
    policy(
        &mut service,
        &admin,
        "accessor-none143",
        r#"path "secret/data/accessor-unrelated143" { capabilities = ["read"] }"#,
        false,
    )?;
    let (target, accessor, _) = token(&mut service, &admin, &["accessor-none143"], 4)?;
    let (reader, _, _) = token(&mut service, &admin, &["accessor-read143"], 12)?;
    let (updater, _, _) = token(&mut service, &admin, &["accessor-update143"], 12)?;
    let (unprivileged, _, _) = token(&mut service, &admin, &["accessor-none143"], 4)?;
    let (required, _, _) = token(&mut service, &admin, &["accessor-required143"], 4)?;

    // GET never decodes an accessor, even for a present actor with Read.
    // Update-only and unprivileged actors fail their original ACL first.
    for body in [
        json!({"accessor":accessor}),
        json!({}),
        json!({"accessor":{}}),
        json!({"accessor":"synthetic-absent-accessor"}),
    ] {
        denied(
            call(&mut service, 100, "GET", ROUTE, &reader, body.clone())?,
            405,
        );
        denied(
            call(&mut service, 100, "GET", ROUTE, &updater, body.clone())?,
            403,
        );
        denied(call(&mut service, 100, "GET", ROUTE, &admin, body)?, 405);
    }
    remaining(&mut service, &admin, 100, &reader, 8)?;
    remaining(&mut service, &admin, 100, &updater, 8)?;
    for method in ["POST", "PUT"] {
        denied(
            call(
                &mut service,
                100,
                method,
                ROUTE,
                &reader,
                json!({"accessor":accessor}),
            )?,
            403,
        );
        description(
            call(
                &mut service,
                100,
                method,
                ROUTE,
                &updater,
                json!({"accessor":accessor}),
            )?,
            &accessor,
            4,
            false,
        );
        denied(
            call(
                &mut service,
                100,
                method,
                ROUTE,
                &updater,
                json!({"accessor":"synthetic-absent-accessor"}),
            )?,
            400,
        );
    }
    remaining(&mut service, &admin, 100, &reader, 6)?;
    remaining(&mut service, &admin, 100, &updater, 4)?;
    remaining(&mut service, &admin, 100, &target, 4)?;
    denied(
        call(&mut service, 100, "GET", ROUTE, &unprivileged, json!({}))?,
        403,
    );
    denied(
        call(
            &mut service,
            100,
            "POST",
            ROUTE,
            &unprivileged,
            json!({"accessor":accessor}),
        )?,
        403,
    );
    remaining(&mut service, &admin, 100, &unprivileged, 2)?;
    denied(call(&mut service, 100, "GET", ROUTE, "", json!({}))?, 403);
    denied(
        call(&mut service, 100, "GET", ROUTE, &required, json!({}))?,
        403,
    );
    denied(
        call(
            &mut service,
            100,
            "GET",
            ROUTE,
            &required,
            json!({"accessor":accessor}),
        )?,
        405,
    );
    remaining(&mut service, &admin, 100, &required, 2)?;

    // Exercise the retained native Userpass owner, not just root or a Token
    // API actor. Its success ACL must also be Update; its error keeps 405.
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            "sys/auth/userpass",
            &admin,
            json!({"type":"userpass"})
        )?
        .status,
        204
    );
    for (name, selected, methods, expected) in [
        (
            "accessor-updater",
            "accessor-update143",
            ["POST", "PUT"],
            200,
        ),
        ("accessor-reader", "accessor-read143", ["GET", "GET"], 405),
    ] {
        assert_eq!(
            call(
                &mut service,
                100,
                "POST",
                &format!("auth/userpass/users/{name}"),
                &admin,
                json!({"password":"synthetic-accessor-method-password","token_policies":[selected],
                   "token_no_default_policy":true,"token_num_uses":4,"token_ttl":600})
            )?
            .status,
            204
        );
        let (actor, _, _) = issued(
            call(
                &mut service,
                100,
                "POST",
                &format!("auth/userpass/login/{name}"),
                "",
                json!({"password":"synthetic-accessor-method-password"}),
            )?,
            &[selected],
        )?;
        for method in methods {
            let body = if method == "GET" {
                json!({})
            } else {
                json!({"accessor":accessor})
            };
            let response = call(&mut service, 100, method, ROUTE, &actor, body)?;
            if expected == 200 {
                description(response, &accessor, 4, false);
            } else {
                denied(response, expected);
            }
        }
        remaining(&mut service, &admin, 100, &actor, 2)?;
    }
    assert!(!service.recovery_required);
    drop(service);
    let mut service = reopen(&root, &key, native)?;
    denied(
        call(
            &mut service,
            201,
            "GET",
            ROUTE,
            &reader,
            json!({"accessor":accessor}),
        )?,
        405,
    );
    description(
        call(
            &mut service,
            201,
            "PUT",
            ROUTE,
            &updater,
            json!({"accessor":accessor}),
        )?,
        &accessor,
        4,
        false,
    );
    remaining(&mut service, &admin, 201, &reader, 5)?;
    remaining(&mut service, &admin, 201, &updater, 3)?;
    remaining(&mut service, &admin, 201, &target, 4)?;
    assert!(!service.recovery_required);
    Ok(())
}

fn identity_and_expiration_order(native: bool) -> TestResult {
    let (root, mut service, key, admin) = fixture(native)?;
    for name in [
        "accessor-actor-token143",
        "accessor-actor-identity143",
        "accessor-expired143",
    ] {
        policy(&mut service, &admin, name, READ, true)?;
    }
    policy(&mut service, &admin, "accessor-target143", READ, true)?;
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
    let (actor, _, entity) = approle(
        &mut service,
        &admin,
        "accessor-actor143",
        &["accessor-actor-token143"],
    )?;
    let actor_entity = format!("identity/entity/id/{entity}");
    assert!(!entity.is_empty());
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            &actor_entity,
            &admin,
            json!({"policies":["accessor-actor-identity143"]})
        )?
        .status,
        204
    );
    let (target, accessor, target_entity) = approle(
        &mut service,
        &admin,
        "accessor-target143",
        &["accessor-target143"],
    )?;
    assert!(!target_entity.is_empty());
    let (expired, _, _) = token(&mut service, &admin, &["accessor-expired143"], 4)?;
    denied(
        call(
            &mut service,
            100,
            "GET",
            ROUTE,
            &actor,
            json!({"accessor":accessor}),
        )?,
        405,
    );
    remaining(&mut service, &admin, 100, &actor, 3)?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            &actor_entity,
            &admin,
            json!({"disabled":true})
        )?
        .status,
        204
    );

    // The original disabled Identity/ACL refusal still precedes backend 405.
    // Actor policies GetPolicy-retire, while administrative target inspection
    // never evaluates the target's expired policy or spends its uses.
    denied(
        call(
            &mut service,
            200,
            "GET",
            ROUTE,
            &actor,
            json!({"accessor":{}}),
        )?,
        403,
    );
    denied(
        call(&mut service, 200, "GET", ROUTE, &expired, json!({}))?,
        403,
    );
    remaining(&mut service, &admin, 200, &actor, 2)?;
    remaining(&mut service, &admin, 200, &expired, 3)?;
    for name in [
        "accessor-actor-token143",
        "accessor-actor-identity143",
        "accessor-expired143",
    ] {
        assert!(!listed(&mut service, &admin, 200, name)?);
    }
    assert!(listed(&mut service, &admin, 200, "accessor-target143")?);
    let target_path = format!("identity/entity/id/{target_entity}");
    assert_eq!(
        call(&mut service, 200, "DELETE", &target_path, &admin, json!({}))?.status,
        204
    );
    assert_eq!(
        call(&mut service, 200, "GET", &target_path, &admin, json!({}))?.status,
        404
    );
    for method in ["POST", "PUT"] {
        description(
            call(
                &mut service,
                200,
                method,
                ROUTE,
                &admin,
                json!({"accessor":accessor}),
            )?,
            &accessor,
            4,
            true,
        );
    }
    denied(
        call(
            &mut service,
            200,
            "GET",
            ROUTE,
            &admin,
            json!({"accessor":accessor}),
        )?,
        405,
    );
    remaining(&mut service, &admin, 200, &target, 4)?;
    assert!(!service.recovery_required);
    drop(service);
    let mut service = reopen(&root, &key, native)?;
    for name in [
        "accessor-actor-token143",
        "accessor-actor-identity143",
        "accessor-expired143",
    ] {
        assert!(!listed(&mut service, &admin, 201, name)?);
    }
    assert!(listed(&mut service, &admin, 201, "accessor-target143")?);
    assert_eq!(
        call(
            &mut service,
            201,
            "POST",
            "sys/policies/acl/accessor-target143",
            &admin,
            json!({"policy":READ,"cas":-1})
        )?
        .status,
        400
    );
    description(
        call(
            &mut service,
            201,
            "PUT",
            ROUTE,
            &admin,
            json!({"accessor":accessor}),
        )?,
        &accessor,
        4,
        true,
    );
    denied(
        call(&mut service, 201, "GET", ROUTE, &actor, json!({}))?,
        403,
    );
    remaining(&mut service, &admin, 201, &actor, 1)?;
    remaining(&mut service, &admin, 201, &target, 4)?;
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn accessor271_ordinary_methods_preserve_acl_single_use_and_cold_restart() -> TestResult {
    method_matrix(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn accessor271_native_methods_preserve_acl_single_use_and_cold_restart() -> TestResult {
    method_matrix(true)
}

#[test]
fn accessor271_ordinary_identity_and_policy_refusal_precede_method_rejection() -> TestResult {
    identity_and_expiration_order(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn accessor271_native_identity_and_policy_refusal_precede_method_rejection() -> TestResult {
    identity_and_expiration_order(true)
}
