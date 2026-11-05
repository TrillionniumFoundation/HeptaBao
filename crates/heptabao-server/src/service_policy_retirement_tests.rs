//! Actual Service admission, persistence and CAS after lazy policy retirement.
use super::super::tests::{Root, bootstrap};
use super::*;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PATH: &str = "secret/data/retirement143";
const SOURCE: &str =
    r#"path "secret/data/retirement143" { capabilities = ["create", "update", "read"] }"#;

fn call(
    service: &mut Service,
    seconds: u64,
    nanos: u32,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let at = Timestamp::checked(seconds, nanos).map_err(|_| "private retirement timestamp")?;
    let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
        .map_err(|_| "private retirement clock")?
        .with_timestamp_floor(at);
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
                0,
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
            103,
            0,
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

fn write_policy(
    service: &mut Service,
    admin: &str,
    name: &str,
    source: &str,
    expires: u64,
) -> TestResult {
    assert_eq!(
        call(
            service,
            100,
            0,
            "POST",
            &format!("sys/policies/acl/{name}"),
            admin,
            json!({"policy":source,"expiration":expires,"cas":-1,"cas_required":true})
        )?
        .status,
        204
    );
    Ok(())
}

fn issue(service: &mut Service, admin: &str, names: &[&str], uses: u64) -> TestResult<String> {
    let response = call(
        service,
        100,
        0,
        "POST",
        "auth/token/create",
        admin,
        json!({"policies":names,"num_uses":uses,"ttl":600,"no_default_policy":true}),
    )?;
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("disposable token")?
        .to_owned())
}

fn listed(service: &mut Service, admin: &str, name: &str, seconds: u64) -> TestResult<bool> {
    let response = call(
        service,
        seconds,
        0,
        "LIST",
        "sys/policies/acl",
        admin,
        json!({}),
    )?;
    assert_eq!(response.status, 200);
    Ok(response.body["data"]["keys"]
        .as_array()
        .ok_or("policy keys")?
        .contains(&json!(name)))
}

fn actor_denial_commits_retirement(native: bool) -> TestResult {
    let (root, mut service, key, admin) = fixture(native)?;
    for name in ["observed143", "unread143"] {
        write_policy(&mut service, &admin, name, SOURCE, 101)?;
    }
    let actor = issue(&mut service, &admin, &["observed143"], 2)?;
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            PATH,
            &admin,
            json!({"data":{"phase":"original"}})
        )?
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            102,
            0,
            "POST",
            PATH,
            &actor,
            json!({"data":{"phase":"must-not-publish"}})
        )?
        .status,
        403
    );
    assert!(!listed(&mut service, &admin, "observed143", 102)?);
    assert!(listed(&mut service, &admin, "unread143", 102)?);
    let token = call(
        &mut service,
        102,
        0,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":actor}),
    )?;
    assert_eq!(token.status, 200);
    assert_eq!(token.body["data"]["num_uses"], 1);
    assert_eq!(
        call(&mut service, 102, 0, "GET", PATH, &admin, json!({}))?.body["data"]["data"]["phase"],
        "original"
    );
    drop(service);
    let mut service = reopen(&root, &key, native)?;
    // No policy GET is allowed to supply the missing lazy-deletion effect.
    assert!(!listed(&mut service, &admin, "observed143", 103)?);
    assert!(listed(&mut service, &admin, "unread143", 103)?);
    assert_eq!(
        call(
            &mut service,
            103,
            0,
            "POST",
            "sys/policies/acl/observed143",
            &admin,
            json!({"policy":SOURCE,"cas":-1})
        )?
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            103,
            0,
            "GET",
            "sys/policies/acl/observed143",
            &admin,
            json!({})
        )?
        .body["data"]["version"],
        1
    );
    assert_eq!(
        call(
            &mut service,
            103,
            0,
            "POST",
            "sys/policies/acl/unread143",
            &admin,
            json!({"policy":SOURCE,"cas":-1})
        )?
        .status,
        400
    );
    Ok(())
}

#[test]
fn retirement143_ordinary_denial_persists_exact_one_use_and_cas_reset_after_reopen() -> TestResult {
    actor_denial_commits_retirement(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn retirement143_native_denial_persists_exact_one_use_and_cas_reset_after_reopen() -> TestResult {
    actor_denial_commits_retirement(true)
}

fn capabilities_retirement(native: bool) -> TestResult {
    let (root, mut service, key, admin) = fixture(native)?;
    write_policy(&mut service, &admin, "target143", SOURCE, 101)?;
    let target = issue(&mut service, &admin, &["target143"], 3)?;
    let body = json!({"token":target,"paths":[PATH]});
    assert_eq!(
        call(
            &mut service,
            102,
            0,
            "POST",
            "sys/capabilities",
            &admin,
            json!({"token":target,"paths":{"invalid":"query"}})
        )?
        .status,
        400
    );
    assert!(listed(&mut service, &admin, "target143", 102)?);
    // The target has no inspector grant. Its own actor request observes its
    // policy, so use a separate permanent, unrelated actor for this refusal.
    assert_eq!(
        call(
            &mut service,
            102,
            0,
            "POST",
            "sys/policies/acl/unprivileged143",
            &admin,
            json!({"policy":SOURCE})
        )?
        .status,
        204
    );
    let issued = call(
        &mut service,
        102,
        0,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["unprivileged143"],"ttl":600,"no_default_policy":true}),
    )?;
    assert_eq!(issued.status, 200);
    let unrelated_actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("unprivileged actor")?;
    assert_eq!(
        call(
            &mut service,
            102,
            0,
            "POST",
            "sys/capabilities",
            unrelated_actor,
            body.clone()
        )?
        .status,
        403
    );
    assert!(listed(&mut service, &admin, "target143", 102)?);
    let inspected = call(
        &mut service,
        102,
        0,
        "POST",
        "sys/capabilities",
        &admin,
        body,
    )?;
    assert_eq!(inspected.status, 200);
    assert_eq!(inspected.body["data"]["capabilities"], json!(["deny"]));
    assert!(!listed(&mut service, &admin, "target143", 102)?);
    let looked = call(
        &mut service,
        102,
        0,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":target}),
    )?;
    assert_eq!(looked.status, 200);
    assert_eq!(looked.body["data"]["num_uses"], 3);
    drop(service);
    let mut service = reopen(&root, &key, native)?;
    assert!(!listed(&mut service, &admin, "target143", 103)?);
    assert_eq!(
        call(
            &mut service,
            103,
            0,
            "POST",
            "sys/policies/acl/target143",
            &admin,
            json!({"policy":SOURCE,"cas":-1})
        )?
        .status,
        204
    );
    Ok(())
}

#[test]
fn retirement143_ordinary_foreign_capabilities_requires_valid_authorized_query() -> TestResult {
    capabilities_retirement(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn retirement143_native_foreign_capabilities_precedes_owner_without_target_charge() -> TestResult {
    capabilities_retirement(true)
}

#[test]
fn retirement143_real_identity_policy_is_retired_by_the_credential_request() -> TestResult {
    let (_root, mut service, _key, admin) = fixture(false)?;
    write_policy(&mut service, &admin, "identity143", SOURCE, 101)?;
    assert_eq!(
        call(
            &mut service,
            100,
            0,
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
            0,
            "POST",
            "auth/approle/role/identity143",
            &admin,
            json!({"token_policies":[],"token_no_default_policy":true,"token_ttl":600})
        )?
        .status,
        204
    );
    let role = call(
        &mut service,
        100,
        0,
        "GET",
        "auth/approle/role/identity143/role-id",
        &admin,
        json!({}),
    )?;
    let secret = call(
        &mut service,
        100,
        0,
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
        0,
        "POST",
        "auth/approle/login",
        "",
        json!({"role_id":role.body["data"]["role_id"],"secret_id":secret.body["data"]["secret_id"]}),
    )?;
    assert_eq!(login.status, 200);
    let actor = login.body["auth"]["client_token"]
        .as_str()
        .ok_or("identity actor")?;
    let entity = login.body["auth"]["entity_id"]
        .as_str()
        .ok_or("actual AppRole entity")?;
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            &format!("identity/entity/id/{entity}"),
            &admin,
            json!({"policies":["identity143"]})
        )?
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            PATH,
            &admin,
            json!({"data":{"phase":"identity"}})
        )?
        .status,
        200
    );
    assert_eq!(
        call(&mut service, 101, 0, "GET", PATH, actor, json!({}))?.status,
        200
    );
    assert_eq!(
        call(&mut service, 101, 1, "GET", PATH, actor, json!({}))?.status,
        403
    );
    assert!(!listed(&mut service, &admin, "identity143", 102)?);
    assert_eq!(
        call(
            &mut service,
            102,
            0,
            "POST",
            "sys/policies/acl/identity143",
            &admin,
            json!({"policy":SOURCE,"cas":-1})
        )?
        .status,
        204
    );
    Ok(())
}

fn actual_carrier_retirement(native: bool) -> TestResult {
    fn wire(service: &mut Service, actor: &str, payload: &str) -> TestResult<Response> {
        let wire = Zeroizing::new(format!(
            "POST /v1/sys/capabilities HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {actor}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len(),
        ));
        let started = Instant::now();
        let clock = RequestClock::anchored(Duration::ZERO, started)
            .map_err(|_| "carrier original clock")?
            .with_timestamp_floor(Timestamp::whole(102).map_err(|_| "carrier time")?);
        let deadline = started + Duration::from_secs(30);
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        let _explicit = external_pki::PublicationClockScope::explicit();
        let response =
            crate::http::logical_data_wire_dispatch_fixture(wire.as_bytes(), |request| {
                assert_eq!(request.method, "POST");
                assert_eq!(request.path, "sys/capabilities");
                service.handle_request_clock(request, 102, true, Some(clock))
            })?;
        assert!(Instant::now() < deadline);
        Ok(response)
    }

    let (_root, mut service, _key, admin) = fixture(native)?;
    write_policy(&mut service, &admin, "carrier-target143", SOURCE, 101)?;
    let target = issue(&mut service, &admin, &["carrier-target143"], 3)?;
    let query_policy = r#"path "sys/capabilities" {
        capabilities = ["update"]
        allowed_parameters = { "path" = ["1.00"], "token" = [] }
    }"#;
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            "sys/policies/acl/carrier-inspector143",
            &admin,
            json!({"policy":query_policy})
        )?
        .status,
        204
    );
    let inspector = issue(&mut service, &admin, &["carrier-inspector143"], 0)?;
    // Numeric target text is an invalid credential. It must not select an
    // arbitrary legitimate target or retire that target's expired policy.
    assert_eq!(
        wire(
            &mut service,
            &admin,
            r#"{"token":1E-08,"paths":[1.00,1E+08,-0,9007199254740993]}"#
        )?
        .status,
        400
    );
    assert!(listed(&mut service, &admin, "carrier-target143", 102)?);
    let target_json = serde_json::to_string(&target)?;
    let numeric_denied = format!(r#"{{"token":{target_json},"path":1.00}}"#);
    assert_eq!(wire(&mut service, &inspector, &numeric_denied)?.status, 403);
    assert!(listed(&mut service, &admin, "carrier-target143", 102)?);
    let before = call(
        &mut service,
        102,
        0,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":target}),
    )?;
    assert_eq!(before.status, 200);
    assert_eq!(before.body["data"]["num_uses"], 3);

    let payload = format!(r#"{{"token":{target_json},"paths":[1.00,1E+08,-0,9007199254740993]}}"#);
    let response = wire(&mut service, &admin, &payload)?;
    assert_eq!(response.status, 200);
    for path in ["1.00", "1E+08", "-0", "9007199254740993"] {
        assert_eq!(response.body["data"][path], json!(["deny"]));
    }
    for normalized in ["1", "100000000.0", "0"] {
        assert!(response.body["data"].get(normalized).is_none());
    }
    assert!(!listed(&mut service, &admin, "carrier-target143", 102)?);
    let after = call(
        &mut service,
        102,
        0,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":target}),
    )?;
    assert_eq!(after.status, 200);
    assert_eq!(after.body["data"]["num_uses"], 3);
    Ok(())
}

#[test]
fn retirement143_ordinary_actual_http_carrier_preserves_numbers_and_parameter_acl() -> TestResult {
    actual_carrier_retirement(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn retirement143_native_actual_http_carrier_preserves_numbers_and_parameter_acl() -> TestResult {
    actual_carrier_retirement(true)
}

// The disabled actor is issued while its real AppRole entity is enabled.
// Subsequent requests retain the same credential and its original finite use.
fn disabled_actor_policy_observation(native: bool) -> TestResult {
    let (root, mut service, key, admin) = fixture(native)?;
    for name in [
        "disabled-token143",
        "disabled-identity143",
        "disabled-unread143",
    ] {
        write_policy(&mut service, &admin, name, SOURCE, 101)?;
    }
    write_policy(&mut service, &admin, "disabled-live143", SOURCE, 200)?;
    assert_eq!(
        call(
            &mut service,
            100,
            0,
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
            0,
            "POST",
            "auth/approle/role/disabled143",
            &admin,
            json!({"token_policies":["disabled-token143","disabled-live143"],
               "token_no_default_policy":true,"token_num_uses":4,"token_ttl":600})
        )?
        .status,
        204
    );
    let role = call(
        &mut service,
        100,
        0,
        "GET",
        "auth/approle/role/disabled143/role-id",
        &admin,
        json!({}),
    )?;
    let secret = call(
        &mut service,
        100,
        0,
        "POST",
        "auth/approle/role/disabled143/secret-id",
        &admin,
        json!({}),
    )?;
    assert_eq!(role.status, 200);
    assert_eq!(secret.status, 200);
    let login = call(
        &mut service,
        100,
        0,
        "POST",
        "auth/approle/login",
        "",
        json!({"role_id":role.body["data"]["role_id"],"secret_id":secret.body["data"]["secret_id"]}),
    )?;
    assert_eq!(login.status, 200);
    let actor = login.body["auth"]["client_token"]
        .as_str()
        .ok_or("real finite-use actor")?
        .to_owned();
    let entity = login.body["auth"]["entity_id"]
        .as_str()
        .ok_or("real AppRole entity")?
        .to_owned();
    let entity_path = format!("identity/entity/id/{entity}");
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            &entity_path,
            &admin,
            json!({"policies":["disabled-identity143"]})
        )?
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            PATH,
            &admin,
            json!({"data":{"phase":"disabled-actor-original"}})
        )?
        .status,
        200
    );
    assert_eq!(
        call(&mut service, 100, 0, "GET", PATH, &actor, json!({}))?.status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            &entity_path,
            &admin,
            json!({"policies":["disabled-identity143"],"disabled":true})
        )?
        .status,
        204
    );
    // Before expiry the original refusal still consumes exactly one use and
    // does not delete a live token or Identity policy.
    assert_eq!(
        call(&mut service, 100, 0, "GET", PATH, &actor, json!({}))?.status,
        403
    );
    for name in ["disabled-token143", "disabled-identity143"] {
        assert!(listed(&mut service, &admin, name, 100)?);
    }
    let before = call(
        &mut service,
        100,
        0,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":actor}),
    )?;
    assert_eq!(before.status, 200);
    assert_eq!(before.body["data"]["num_uses"], 2);
    // A live policy still grants this write, so 403 must come from the entity
    // refusal. Its fixed policy observation must nevertheless survive it.
    assert_eq!(
        call(
            &mut service,
            102,
            0,
            "POST",
            PATH,
            &actor,
            json!({"data":{"phase":"must-not-publish"}})
        )?
        .status,
        403
    );
    for name in ["disabled-token143", "disabled-identity143"] {
        assert!(!listed(&mut service, &admin, name, 102)?);
    }
    for name in ["disabled-unread143", "disabled-live143"] {
        assert!(listed(&mut service, &admin, name, 102)?);
    }
    let after = call(
        &mut service,
        102,
        0,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":actor}),
    )?;
    assert_eq!(after.status, 200);
    assert_eq!(after.body["data"]["num_uses"], 1);
    assert_eq!(
        call(&mut service, 102, 0, "GET", PATH, &admin, json!({}))?.body["data"]["data"]["phase"],
        "disabled-actor-original"
    );
    drop(service);
    let mut service = reopen(&root, &key, native)?;
    // LIST is used first, so no administrative GET can manufacture the
    // missing lazy deletion. A new CAS -1 must start each observed name at 1.
    for name in ["disabled-token143", "disabled-identity143"] {
        assert!(!listed(&mut service, &admin, name, 103)?);
        let path = format!("sys/policies/acl/{name}");
        assert_eq!(
            call(
                &mut service,
                103,
                0,
                "POST",
                &path,
                &admin,
                json!({"policy":SOURCE,"cas":-1})
            )?
            .status,
            204
        );
        let recreated = call(&mut service, 103, 0, "GET", &path, &admin, json!({}))?;
        assert_eq!(recreated.status, 200);
        assert_eq!(recreated.body["data"]["version"], 1);
    }
    assert!(listed(&mut service, &admin, "disabled-unread143", 103)?);
    assert_eq!(
        call(
            &mut service,
            103,
            0,
            "POST",
            "sys/policies/acl/disabled-unread143",
            &admin,
            json!({"policy":SOURCE,"cas":-1})
        )?
        .status,
        400
    );
    let restored = call(
        &mut service,
        103,
        0,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":actor}),
    )?;
    assert_eq!(restored.status, 200);
    assert_eq!(restored.body["data"]["num_uses"], 1);
    // Recreating both grants never re-enables the disabled actor, including
    // its final original use after a real cold restart.
    assert_eq!(
        call(
            &mut service,
            103,
            0,
            "POST",
            PATH,
            &actor,
            json!({"data":{"phase":"must-not-publish-after-restart"}})
        )?
        .status,
        403
    );
    assert_eq!(
        call(&mut service, 103, 0, "GET", PATH, &admin, json!({}))?.body["data"]["data"]["phase"],
        "disabled-actor-original"
    );
    Ok(())
}

#[test]
fn retirement143_ordinary_disabled_actor_keeps_denial_after_policy_lookup_and_restart() -> TestResult
{
    disabled_actor_policy_observation(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn retirement143_native_disabled_actor_keeps_denial_after_policy_lookup_and_restart() -> TestResult
{
    disabled_actor_policy_observation(true)
}

fn installed_missing_actor_uses(service: &Service, accessor: &str, expected: u64) -> TestResult {
    // Missing-entity administrative token lookup remains a separate API gate.
    // Observe only this real issued actor's installed owner, after proving the
    // same count through lookup before deletion. Never create a token record.
    let state = service.state.as_ref().ok_or("actual installed state")?;
    let bytes = crate::secret_serde::to_vec(&state.auth, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| "actual installed Auth bytes")?;
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| "actual Auth encoding")?;
    let uses = (|| -> Result<u64, &'static str> {
        let tokens = value["tokens"].as_object().ok_or("actual token owners")?;
        let mut matching = tokens.values().filter(|token| {
            token["accessor"].as_str() == Some(accessor) && token["namespace"].as_str() == Some("")
        });
        let uses = matching.next().ok_or("actual issued actor owner")?["uses_remaining"]
            .as_u64()
            .ok_or("actual finite actor uses")?;
        if matching.next().is_some() {
            return Err("actor accessor must be unique");
        }
        Ok(uses)
    })();
    erase_json(&mut value);
    assert_eq!(uses.map_err(|_| "actual actor use observation")?, expected);
    Ok(())
}

fn missing_actor_policy_observation(native: bool) -> TestResult {
    let (root, mut service, key, admin) = fixture(native)?;
    for name in [
        "missing-token143",
        "missing-identity143",
        "missing-unread143",
    ] {
        write_policy(&mut service, &admin, name, SOURCE, 101)?;
    }
    write_policy(&mut service, &admin, "missing-live143", SOURCE, 200)?;
    assert_eq!(
        call(
            &mut service,
            100,
            0,
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
            0,
            "POST",
            "auth/approle/role/missing143",
            &admin,
            json!({"token_policies":["missing-token143","missing-live143"],
               "token_no_default_policy":true,"token_num_uses":4,"token_ttl":600})
        )?
        .status,
        204
    );
    let role = call(
        &mut service,
        100,
        0,
        "GET",
        "auth/approle/role/missing143/role-id",
        &admin,
        json!({}),
    )?;
    let secret = call(
        &mut service,
        100,
        0,
        "POST",
        "auth/approle/role/missing143/secret-id",
        &admin,
        json!({}),
    )?;
    assert_eq!(role.status, 200);
    assert_eq!(secret.status, 200);
    let login = call(
        &mut service,
        100,
        0,
        "POST",
        "auth/approle/login",
        "",
        json!({"role_id":role.body["data"]["role_id"],"secret_id":secret.body["data"]["secret_id"]}),
    )?;
    assert_eq!(login.status, 200);
    let actor = login.body["auth"]["client_token"]
        .as_str()
        .ok_or("real finite-use actor")?
        .to_owned();
    let accessor = login.body["auth"]["accessor"]
        .as_str()
        .ok_or("real actor accessor")?
        .to_owned();
    let entity = login.body["auth"]["entity_id"]
        .as_str()
        .ok_or("real AppRole entity")?
        .to_owned();
    let entity_path = format!("identity/entity/id/{entity}");
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            &entity_path,
            &admin,
            json!({"policies":["missing-identity143"]})
        )?
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "POST",
            PATH,
            &admin,
            json!({"data":{"phase":"missing-actor-original"}})
        )?
        .status,
        200
    );
    assert_eq!(
        call(&mut service, 100, 0, "GET", PATH, &actor, json!({}))?.status,
        200
    );
    let before = call(
        &mut service,
        100,
        0,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":actor}),
    )?;
    assert_eq!(before.status, 200);
    assert_eq!(before.body["data"]["num_uses"], 3);
    installed_missing_actor_uses(&service, &accessor, 3)?;
    {
        let engines = &service
            .state
            .as_ref()
            .ok_or("actual enabled state")?
            .engines;
        let actual = engines
            .identity_projection_if_present("", &entity)
            .map_err(|_| "actual enabled Identity")?
            .ok_or("real entity exists")?;
        assert!(actual.entity_id == entity && !actual.disabled);
        assert!(actual.policies.contains("missing-identity143"));
        // A missing namespace owner is an error, never successful absence.
        assert!(
            engines
                .identity_projection_if_present("not-loaded-identity143", &entity)
                .is_err()
        );
    }
    assert_eq!(
        call(
            &mut service,
            100,
            0,
            "DELETE",
            &entity_path,
            &admin,
            json!({})
        )?
        .status,
        204
    );
    assert_eq!(
        call(&mut service, 100, 0, "GET", &entity_path, &admin, json!({}))?.status,
        404
    );
    {
        let engines = &service
            .state
            .as_ref()
            .ok_or("actual deleted state")?
            .engines;
        assert!(
            engines
                .identity_projection_if_present("", &entity)
                .map_err(|_| "trusted loaded Identity namespace")?
                .is_none()
        );
        assert!(engines.identity_projection("", &entity).is_err());
    }
    // The still-live token grants cannot bypass Identity denial. Each request
    // nevertheless retains its one original use and token-policy observation.
    assert_eq!(
        call(&mut service, 100, 0, "GET", PATH, &actor, json!({}))?.status,
        403
    );
    installed_missing_actor_uses(&service, &accessor, 2)?;
    for name in [
        "missing-token143",
        "missing-identity143",
        "missing-unread143",
    ] {
        assert!(listed(&mut service, &admin, name, 100)?);
    }
    assert_eq!(
        call(
            &mut service,
            102,
            0,
            "POST",
            PATH,
            &actor,
            json!({"data":{"phase":"must-not-publish"}})
        )?
        .status,
        403
    );
    installed_missing_actor_uses(&service, &accessor, 1)?;
    assert!(!listed(&mut service, &admin, "missing-token143", 102)?);
    // The deleted entity's former Identity grant is not an observation of
    // this request, even though the same actor used it before deletion.
    for name in [
        "missing-identity143",
        "missing-unread143",
        "missing-live143",
    ] {
        assert!(listed(&mut service, &admin, name, 102)?);
    }
    assert_eq!(
        call(&mut service, 102, 0, "GET", PATH, &admin, json!({}))?.body["data"]["data"]["phase"],
        "missing-actor-original"
    );
    assert!(!service.recovery_required);
    drop(service);
    let mut service = reopen(&root, &key, native)?;
    installed_missing_actor_uses(&service, &accessor, 1)?;
    assert_eq!(
        call(&mut service, 103, 0, "GET", &entity_path, &admin, json!({}))?.status,
        404
    );
    assert!(!listed(&mut service, &admin, "missing-token143", 103)?);
    assert_eq!(
        call(
            &mut service,
            103,
            0,
            "POST",
            "sys/policies/acl/missing-token143",
            &admin,
            json!({"policy":SOURCE,"cas":-1})
        )?
        .status,
        204
    );
    let recreated = call(
        &mut service,
        103,
        0,
        "GET",
        "sys/policies/acl/missing-token143",
        &admin,
        json!({}),
    )?;
    assert_eq!(recreated.status, 200);
    assert_eq!(recreated.body["data"]["version"], 1);
    for name in ["missing-identity143", "missing-unread143"] {
        assert!(listed(&mut service, &admin, name, 103)?);
        assert_eq!(
            call(
                &mut service,
                103,
                0,
                "POST",
                &format!("sys/policies/acl/{name}"),
                &admin,
                json!({"policy":SOURCE,"cas":-1})
            )?
            .status,
            400
        );
    }
    // A real cold reopen and recreated token grants cannot revive the entity,
    // including this original actor's final permitted use.
    assert_eq!(
        call(
            &mut service,
            103,
            0,
            "POST",
            PATH,
            &actor,
            json!({"data":{"phase":"must-not-publish-after-restart"}})
        )?
        .status,
        403
    );
    assert_eq!(
        call(&mut service, 103, 0, "GET", PATH, &admin, json!({}))?.body["data"]["data"]["phase"],
        "missing-actor-original"
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn retirement143_ordinary_missing_actor_retires_token_policies_only_and_keeps_one_use() -> TestResult
{
    missing_actor_policy_observation(false)
}

#[cfg(feature = "native-v6-storage")]
#[test]
fn retirement143_native_missing_actor_retires_token_policies_only_and_keeps_one_use() -> TestResult
{
    missing_actor_policy_observation(true)
}
