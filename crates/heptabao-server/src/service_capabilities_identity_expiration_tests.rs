//! Real AppRole targets retain their policy and use count when Identity is
//! disabled or deleted. The inspection backend rejects before target ACL load.
use super::super::tests::{Root, bootstrap};
use super::*;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ITEM: &str = "secret/data/capabilities-identity143";
const POLICY: &str = "capabilities-identity143";
const POLICY_PATH: &str = "sys/policies/acl/capabilities-identity143";
const SOURCE: &str = r#"path "secret/data/capabilities-identity143" { capabilities = ["read"] }"#;

fn call(
    service: &mut Service,
    seconds: u64,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
        .map_err(|_| "private capabilities clock")?
        .with_timestamp_floor(Timestamp::whole(seconds).map_err(|_| "private capabilities time")?);
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let _explicit = external_pki::PublicationClockScope::explicit();
    Ok(service.handle_request_clock(
        ServiceRequest::new(method, path, "", token, body),
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

fn target_uses(service: &mut Service, admin: &str, token: &str, seconds: u64) -> TestResult {
    let lookup = call(
        service,
        seconds,
        "POST",
        "auth/token/lookup",
        admin,
        json!({"token":token}),
    )?;
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["num_uses"], 3);
    Ok(())
}

fn installed_target_uses(service: &Service, accessor: &str) -> TestResult {
    // Administrative lookup currently has a separate missing-Identity
    // completion boundary. Do not accept multiple HTTP statuses or pretend
    // that boundary is qualified. Read the actual installed Auth owner by the
    // real issued accessor, after proving this same record matches lookup
    // before deletion. No credential or owner candidate is manufactured.
    let state = service.state.as_ref().ok_or("actual installed state")?;
    let bytes = crate::secret_serde::to_vec(&state.auth, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| "actual installed Auth bytes")?;
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| "actual Auth encoding")?;
    let uses = (|| -> Result<u64, &'static str> {
        let tokens = value["tokens"].as_object().ok_or("actual token owners")?;
        let mut matching = tokens.values().filter(|token| {
            token["accessor"].as_str() == Some(accessor) && token["namespace"].as_str() == Some("")
        });
        let uses = matching.next().ok_or("actual issued target owner")?["uses_remaining"]
            .as_u64()
            .ok_or("actual finite target uses")?;
        if matching.next().is_some() {
            return Err("target accessor must be unique");
        }
        Ok(uses)
    })();
    erase_json(&mut value);
    assert_eq!(uses.map_err(|_| "actual target use observation")?, 3);
    Ok(())
}

fn retained_policy(service: &mut Service, admin: &str, seconds: u64) -> TestResult {
    let response = call(
        service,
        seconds,
        "LIST",
        "sys/policies/acl",
        admin,
        json!({}),
    )?;
    assert_eq!(response.status, 200);
    assert!(
        response.body["data"]["keys"]
            .as_array()
            .ok_or("policy keys")?
            .contains(&json!(POLICY))
    );
    // No policy GET can supply a lazy deletion. An unobserved expired entry
    // still exists and retains its old CAS requirement/version on replacement.
    assert_eq!(
        call(
            service,
            seconds,
            "POST",
            POLICY_PATH,
            admin,
            json!({"policy":SOURCE,"cas":-1})
        )?
        .status,
        400
    );
    Ok(())
}

fn rejected_target(
    service: &mut Service,
    admin: &str,
    target: &str,
    accessor: &str,
    seconds: u64,
    missing_entity: bool,
) -> TestResult {
    for (path, body) in [
        ("sys/capabilities", json!({"token":target,"paths":[ITEM]})),
        (
            "sys/capabilities-accessor",
            json!({"accessor":accessor,"paths":[ITEM]}),
        ),
    ] {
        let response = call(service, seconds, "POST", path, admin, body)?;
        assert_eq!(response.status, 400);
        assert_eq!(response.body["errors"], json!(["invalid token"]));
        assert!(response.body.get("data").is_none());
        assert!(!service.recovery_required);
    }
    if !missing_entity {
        target_uses(service, admin, target, seconds)?;
    }
    installed_target_uses(service, accessor)?;
    Ok(())
}

fn identity_refusal(native: bool, delete_entity: bool) -> TestResult {
    let (root, mut service, key, admin) = fixture(native)?;
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            POLICY_PATH,
            &admin,
            json!({"policy":SOURCE,"expiration":150,"cas":-1,"cas_required":true})
        )?
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            100,
            "POST",
            ITEM,
            &admin,
            json!({"data":{"value":"actual-private-target"}})
        )?
        .status,
        200
    );
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
            "auth/approle/role/identity143",
            &admin,
            json!({"token_policies":[POLICY],"token_no_default_policy":true,
            "token_ttl":600,"token_num_uses":4,"secret_id_num_uses":1})
        )?
        .status,
        204
    );
    let role = call(
        &mut service,
        100,
        "GET",
        "auth/approle/role/identity143/role-id",
        &admin,
        json!({}),
    )?;
    let secret = call(
        &mut service,
        100,
        "POST",
        "auth/approle/role/identity143/secret-id",
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
    let target = login.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual target")?
        .to_owned();
    let accessor = login.body["auth"]["accessor"]
        .as_str()
        .ok_or("actual accessor")?
        .to_owned();
    let entity = login.body["auth"]["entity_id"]
        .as_str()
        .ok_or("actual target entity")?;
    let entity_path = format!("identity/entity/id/{entity}");
    let read = call(&mut service, 100, "GET", ITEM, &target, json!({}))?;
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["data"]["value"], "actual-private-target");
    target_uses(&mut service, &admin, &target, 100)?;
    installed_target_uses(&service, &accessor)?;
    let before = call(
        &mut service,
        100,
        "POST",
        "sys/capabilities",
        &admin,
        json!({"token":target,"paths":[ITEM]}),
    )?;
    assert_eq!(before.status, 200);
    assert_eq!(before.body["data"]["capabilities"], json!(["read"]));
    target_uses(&mut service, &admin, &target, 100)?;
    if delete_entity {
        assert_eq!(
            call(&mut service, 100, "DELETE", &entity_path, &admin, json!({}))?.status,
            204
        );
        assert_eq!(
            call(&mut service, 100, "GET", &entity_path, &admin, json!({}))?.status,
            404
        );
    } else {
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
        let entity = call(&mut service, 100, "GET", &entity_path, &admin, json!({}))?;
        assert_eq!(entity.status, 200);
        assert_eq!(entity.body["data"]["disabled"], true);
    }
    rejected_target(&mut service, &admin, &target, &accessor, 200, delete_entity)?;
    retained_policy(&mut service, &admin, 200)?;
    drop(service);

    let mut service = root.service()?;
    #[cfg(feature = "native-v6-storage")]
    if native {
        service.configure_native_v6_candidate()?;
    }
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
    rejected_target(&mut service, &admin, &target, &accessor, 201, delete_entity)?;
    retained_policy(&mut service, &admin, 201)?;
    assert_eq!(
        call(
            &mut service,
            201,
            "POST",
            POLICY_PATH,
            &admin,
            json!({"policy":SOURCE,"cas":1,"cas_required":true})
        )?
        .status,
        204
    );
    let replaced = call(&mut service, 201, "GET", POLICY_PATH, &admin, json!({}))?;
    assert_eq!(replaced.status, 200);
    assert_eq!(replaced.body["data"]["version"], 2);
    assert!(replaced.body["data"].get("expiration").is_none());
    if !delete_entity {
        target_uses(&mut service, &admin, &target, 201)?;
    }
    installed_target_uses(&service, &accessor)?;
    assert_eq!(
        call(&mut service, 201, "GET", ITEM, &admin, json!({}))?.body["data"]["data"]["value"],
        "actual-private-target"
    );
    Ok(())
}

#[test]
fn expiration143_ordinary_disabled_or_missing_capability_entity_preserves_unread_policy_and_target_uses()
-> TestResult {
    identity_refusal(false, false)?;
    identity_refusal(false, true)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn expiration143_native_disabled_or_missing_capability_entity_preserves_unread_policy_and_target_uses()
-> TestResult {
    identity_refusal(true, false)?;
    identity_refusal(true, true)
}
