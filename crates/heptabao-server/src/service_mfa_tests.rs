use super::*;
use crate::service::tests::{Root, bootstrap, call};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn mfa129_real_service_configuration_enrollment_acl_and_encrypted_reopen_keep_sticky_floor()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let ordinary = service.state.clone().ok_or("ordinary state")?;
    assert!(!ordinary.auth.has_identity_mfa_state());
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/mfa_userpass",
            &admin,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/mfa_userpass/users/alice",
            &admin,
            json!({"password":"public-synthetic-mfa-test","token_ttl":20,"token_max_ttl":20})
        )
        .status,
        204
    );
    let login = call(
        &mut service,
        "POST",
        "auth/mfa_userpass/login/alice",
        "",
        json!({"password":"public-synthetic-mfa-test"}),
    );
    assert_eq!(login.status, 200);
    let alice = Zeroizing::new(
        login.body["auth"]["client_token"]
            .as_str()
            .ok_or("native bearer")?
            .to_owned(),
    );
    let entity = login.body["auth"]["entity_id"]
        .as_str()
        .ok_or("native entity")?
        .to_owned();
    assert!(!entity.is_empty());
    let created = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp",
        &admin,
        json!({"issuer":"native-public-fixture","qr_size":0}),
    );
    assert_eq!(created.status, 200);
    let id = created.body["data"]["method_id"]
        .as_str()
        .ok_or("native method")?
        .to_owned();
    let current = service.state.clone().ok_or("MFA state")?;
    assert_eq!(current.schema, USERPASS_ISSUANCE_STATE_SCHEMA);
    assert!(current.auth.has_identity_mfa_state());
    let before =
        crate::secret_serde::to_vec(&current, 16 * 1024 * 1024).map_err(|_| "state encoding")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "identity/mfa/method/totp/admin-generate",
            &alice,
            json!({"method_id":id,"entity_id":entity})
        )
        .status,
        403
    );
    assert!(
        crate::secret_serde::to_vec(service.state.as_ref().ok_or("state")?, 16 * 1024 * 1024)
            .map_err(|_| "state encoding")?
            .as_slice()
            == before.as_slice(),
        "denied enrollment cannot mutate private durable state"
    );
    let generated = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp/admin-generate",
        &admin,
        json!({"method_id":id,"entity_id":entity}),
    );
    assert_eq!(generated.status, 200);
    assert!(generated.body["data"]["barcode"].as_str() == Some(""));
    assert!(
        generated.body["data"]["url"]
            .as_str()
            .is_some_and(|url| url.starts_with("otpauth://totp/"))
    );
    let duplicate = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp/admin-generate",
        &admin,
        json!({"method_id":id,"entity_id":entity}),
    );
    assert_eq!(duplicate.status, 200);
    assert!(duplicate.body["data"].is_null());
    let persisted = service.state.clone().ok_or("persisted")?;
    let mut lower = persisted.clone();
    lower.schema = 127;
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(&persisted)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&persisted, &ordinary).is_err());
    let mut encoded = serde_json::to_value(&persisted.auth)?;
    encoded
        .as_object_mut()
        .ok_or("Auth object")?
        .remove("identity_mfa");
    let mut stripped = persisted.clone();
    let encoded = Zeroizing::new(serde_json::to_vec(&encoded)?);
    stripped.auth = serde_json::from_slice(&encoded)?;
    // The highest 132 label alone cannot identify every erased lower feature.
    // Keep both actual 132 successor/snapshot negatives below, and exercise
    // the standalone 129 reader on a genuinely MFA-only native publication.
    let isolated_files = Root::new();
    let mut isolated = isolated_files.service()?;
    let (_, isolated_admin) = bootstrap(&mut isolated)?;
    let isolated_method = call(
        &mut isolated,
        "POST",
        "identity/mfa/method/totp",
        &isolated_admin,
        json!({"issuer":"isolated-native-reader","qr_size":0}),
    );
    assert_eq!(isolated_method.status, 200);
    let isolated_state = isolated.state.clone().ok_or("actual isolated MFA state")?;
    assert_eq!(isolated_state.schema, IDENTITY_MFA_STATE_SCHEMA);
    assert!(isolated_state.auth.has_identity_mfa_state());
    isolated_state.validate_format().map_err(|_| "actual isolated MFA format")?;
    let mut isolated_auth = serde_json::to_value(&isolated_state.auth)?;
    isolated_auth.as_object_mut().ok_or("actual isolated Auth object")?
        .remove("identity_mfa");
    let isolated_bytes = Zeroizing::new(serde_json::to_vec(&isolated_auth)?);
    let mut isolated_stripped = isolated_state.clone();
    isolated_stripped.auth = serde_json::from_slice(&isolated_bytes)?;
    assert_eq!(isolated_stripped.validate_format().err()
        .ok_or("erased exact129 reader unexpectedly accepted")?.status, 503);
    assert!(isolated_stripped.validate_publication_schema(Some(&isolated_state)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&isolated_state, &isolated_stripped).is_err());
    assert!(
        stripped
            .validate_publication_schema(Some(&persisted))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&persisted, &stripped).is_err());
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let read = call(
        &mut reopened,
        "GET",
        &format!("identity/mfa/method/{id}"),
        &admin,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["namespace_id"], "root");
    assert!(read.body["data"].get("secret").is_none());
    let duplicate = call(
        &mut reopened,
        "POST",
        "identity/mfa/method/totp/admin-generate",
        &admin,
        json!({"method_id":id,"entity_id":entity}),
    );
    assert_eq!(duplicate.status, 200);
    assert!(duplicate.body["data"].is_null());
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "identity/mfa/method/totp/admin-destroy",
            &admin,
            json!({"method_id":id,"entity_id":entity})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut reopened,
            "DELETE",
            &format!("identity/mfa/method/totp/{id}"),
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("retired")?
            .auth
            .has_identity_mfa_state()
    );
    assert_eq!(
        reopened.state.as_ref().ok_or("retired")?.schema,
        USERPASS_ISSUANCE_STATE_SCHEMA
    );
    Ok(())
}

// Exercise the real Service native issuance/identity/commit path under one
// request-owned captured clock. This is a functional control, not OS proof.
fn precise_call(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    seconds: u64,
    nanos: u32,
) -> Response {
    let clock = RequestClock::anchored(Duration::new(seconds, nanos), Instant::now())
        .expect("synthetic captured request clock");
    precise_call_clock(service, method, path, token, body, clock)
}
fn precise_call_clock(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    clock: RequestClock,
) -> Response {
    let seconds = clock.admitted_at().seconds();
    service.handle_request_clock(
        ServiceRequest {
            method,
            path,
            namespace: "",
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: Some("127.0.0.1".parse().expect("synthetic peer")),
            client_certificates: None,
        },
        seconds,
        true,
        Some(clock),
    )
}
fn enrollment_secret(reply: &Response) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let url = reply.body["data"]["url"]
        .as_str()
        .ok_or("native enrollment URL")?;
    let raw = url
        .split_once('?')
        .ok_or("native enrollment query")?
        .1
        .split('&')
        .find_map(|field| field.strip_prefix("secret="))
        .ok_or("native enrollment secret")?;
    let mut result = Zeroizing::new(Vec::new());
    let mut bits = 0u32;
    let mut count = 0u32;
    for character in raw.bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'2'..=b'7' => character - b'2' + 26,
            _ => return Err("native base32 enrollment character".into()),
        };
        bits = (bits << 5) | u32::from(value);
        count += 5;
        if count >= 8 {
            count -= 8;
            result.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if bits != 0 || result.len() != 20 {
        return Err("native enrollment key size".into());
    }
    Ok(result)
}
fn token_count(service: &Service) -> Result<usize, Box<dyn std::error::Error>> {
    let encoded = crate::secret_serde::to_vec(
        &service.state.as_ref().ok_or("native state")?.auth,
        16 * 1024 * 1024,
    )
    .map_err(|_| "private Auth encoding")?;
    let auth = heptabao_domain::json::decode(&encoded)?;
    Ok(auth["tokens"]
        .as_object()
        .ok_or("native token owner")?
        .len())
}
fn mfa_challenge(
    service: &mut Service,
    seconds: u64,
    nanos: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    let clock = RequestClock::anchored(Duration::new(seconds, nanos), Instant::now())
        .expect("synthetic captured challenge clock");
    mfa_challenge_clock(service, clock)
}
fn mfa_challenge_clock(
    service: &mut Service,
    clock: RequestClock,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = precise_call_clock(
        service,
        "POST",
        "auth/mfa_userpass/login/alice",
        "",
        json!({"password":"public-synthetic-mfa-test"}),
        clock,
    );
    assert_eq!(
        response.status, 200,
        "native first factor must return only a challenge"
    );
    assert!(response.body["auth"]["client_token"].as_str() == Some(""));
    assert!(response.body["auth"]["accessor"].as_str() == Some(""));
    assert!(response.body["auth"]["entity_id"].as_str() == Some(""));
    assert_eq!(response.body["auth"]["lease_duration"], 0);
    Ok(response.body["auth"]["mfa_requirement"]["mfa_request_id"]
        .as_str()
        .ok_or("native challenge ID")?
        .to_owned())
}
#[test]
fn mfa129_actual_native_issuance_is_unissued_until_validate_with_fixed_attempt_window_and_replay_custody()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/mfa_userpass",
            &admin,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/mfa_userpass/users/alice",
            &admin,
            json!({"password":"public-synthetic-mfa-test","token_ttl":20,"token_max_ttl":20,
            "token_bound_cidrs":["127.0.0.0/8"]})
        )
        .status,
        204
    );
    let normal = precise_call(
        &mut service,
        "POST",
        "auth/mfa_userpass/login/alice",
        "",
        json!({"password":"public-synthetic-mfa-test"}),
        100,
        0,
    );
    assert_eq!(normal.status, 200);
    let entity = normal.body["auth"]["entity_id"]
        .as_str()
        .ok_or("native entity")?
        .to_owned();
    assert!(!entity.is_empty());
    let created = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp",
        &admin,
        json!({"issuer":"native","qr_size":0,"period":10,"skew":0,"max_validation_attempts":2}),
    );
    assert_eq!(created.status, 200);
    let id = created.body["data"]["method_id"]
        .as_str()
        .ok_or("native method")?
        .to_owned();
    let generated = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp/admin-generate",
        &admin,
        json!({"method_id":id,"entity_id":entity}),
    );
    assert_eq!(generated.status, 200);
    let secret = enrollment_secret(&generated)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "identity/mfa/login-enforcement/native",
            &admin,
            json!({"auth_method_types":["userpass"],"mfa_method_ids":[id]})
        )
        .status,
        204
    );
    let before_tokens = token_count(&service)?;
    let request = mfa_challenge(&mut service, 100, 125_000_000)?;
    assert_eq!(
        token_count(&service)?,
        before_tokens,
        "first factor must not mint or store a bearer"
    );
    let body = |code: &str| json!({"mfa_request_id":request,"mfa_payload":{id.clone():[code]}});
    let checkpoint = service.state.clone().ok_or("native challenge state")?;
    for missing in [
        json!({"mfa_request_id":request}),
        json!({"mfa_request_id":request,"mfa_payload":{}}),
        body("invalid"),
    ] {
        assert_eq!(
            precise_call(
                &mut service,
                "POST",
                "sys/mfa/validate",
                "",
                missing,
                101,
                0
            )
            .status,
            403
        );
    }
    assert_eq!(token_count(&service)?, before_tokens);
    let before = crate::secret_serde::to_vec(&checkpoint, 16 * 1024 * 1024)
        .map_err(|_| "challenge state encoding")?;
    let after =
        crate::secret_serde::to_vec(service.state.as_ref().ok_or("state")?, 16 * 1024 * 1024)
            .map_err(|_| "challenge state encoding")?;
    assert!(
        before.as_slice() == after.as_slice(),
        "malformed/missing credentials cannot mutate attempts"
    );
    let code = Zeroizing::new(
        crate::engines::rfc6238_code(&secret, "SHA1", 6, 10).map_err(|_| "native TOTP")?,
    );
    let wrong = if code.as_str() == "000000" {
        "111111"
    } else {
        "000000"
    };
    assert_eq!(
        precise_call(
            &mut service,
            "POST",
            "sys/mfa/validate",
            "",
            body(wrong),
            101,
            125_000_000
        )
        .status,
        403
    );
    let after_wrong = service.state.clone().ok_or("attempt state")?;
    assert!(Service::validate_snapshot_protected_floor(&after_wrong, &checkpoint).is_err());
    let accepted = precise_call(
        &mut service,
        "POST",
        "sys/mfa/validate",
        "",
        body(&code),
        102,
        125_000_000,
    );
    assert_eq!(accepted.status, 200);
    let bearer = Zeroizing::new(
        accepted.body["auth"]["client_token"]
            .as_str()
            .ok_or("native final bearer")?
            .to_owned(),
    );
    assert!(!bearer.is_empty());
    assert!(accepted.body["auth"]["entity_id"].as_str() == Some(entity.as_str()));
    assert_eq!(token_count(&service)?, before_tokens + 1);
    let lookup = precise_call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &bearer,
        json!({}),
        102,
        200_000_000,
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(
        lookup.body["data"]["creation_time"], 102,
        "native userpass lease starts at validate"
    );
    assert_eq!(lookup.body["data"]["creation_ttl"], 20);
    assert_eq!(
        precise_call(
            &mut service,
            "POST",
            "sys/mfa/validate",
            "",
            body(&code),
            102,
            300_000_000
        )
        .status,
        400
    );
    let replay = mfa_challenge(&mut service, 103, 0)?;
    assert_eq!(
        precise_call(
            &mut service,
            "POST",
            "sys/mfa/validate",
            "",
            json!({"mfa_request_id":replay,"mfa_payload":{id.clone():[code.as_str()]}}),
            104,
            0
        )
        .status,
        403,
        "same native OTP cannot satisfy a fresh challenge"
    );

    // A second genuine method/enrollment provides an independent attempt
    // window on the same actual entity and tests encrypted restart.
    let created = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp",
        &admin,
        json!({"issuer":"native-second","qr_size":0,"period":10,"skew":0,"max_validation_attempts":2}),
    );
    assert_eq!(created.status, 200);
    let second = created.body["data"]["method_id"]
        .as_str()
        .ok_or("second method")?
        .to_owned();
    let generated = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp/admin-generate",
        &admin,
        json!({"method_id":second,"entity_id":entity}),
    );
    assert_eq!(generated.status, 200);
    let second_secret = enrollment_secret(&generated)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "identity/mfa/login-enforcement/native",
            &admin,
            json!({"auth_method_types":["userpass"],"mfa_method_ids":[second]})
        )
        .status,
        204
    );
    let first_attempt_clock = RequestClock::anchored(
        Duration::new(114, 500_000_000), Instant::now(),
    ).map_err(|_| "original first attempt clock")?;
    let request = mfa_challenge_clock(&mut service, first_attempt_clock)?;
    let first_code = Zeroizing::new(
        crate::engines::rfc6238_code(&second_secret, "SHA1", 6, 11).map_err(|_| "native TOTP")?,
    );
    let wrong = if first_code.as_str() == "000000" {
        "111111"
    } else {
        "000000"
    };
    // Reuse the challenge's captured clock for its first same-window
    // validation: reanchoring at 114.5s would regress elapsed nanoseconds.
    for (seconds, clock) in [
        (114, first_attempt_clock),
        (115, RequestClock::anchored(Duration::new(115, 500_000_000), Instant::now())
            .map_err(|_| "second numeric attempt clock")?),
    ] {
        let denied = precise_call_clock(
            &mut service,
            "POST",
            "sys/mfa/validate",
            "",
            json!({"mfa_request_id":request,"mfa_payload":{second.clone():[wrong]}}),
            clock,
        );
        assert_eq!(denied.status, 403, "numeric attempt at {seconds} returned {:?}", denied.body["errors"]);
    }
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        precise_call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key}), 116, 0)
            .status,
        200
    );
    assert_eq!(
        precise_call(
            &mut reopened,
            "POST",
            "sys/mfa/validate",
            "",
            json!({"mfa_request_id":request,"mfa_payload":{second.clone():[first_code.as_str()]}}),
            116,
            0
        )
        .status,
        403,
        "attempt lockout survives encrypted reopen"
    );
    let next_code = Zeroizing::new(
        crate::engines::rfc6238_code(&second_secret, "SHA1", 6, 12).map_err(|_| "native TOTP")?,
    );
    // Both requests advance from this original fixture clock. Re-anchoring
    // validate at the same wall value would regress the captured challenge.
    let rollover_clock = RequestClock::anchored(
        Duration::new(120, 100_000_000), Instant::now(),
    ).map_err(|_| "original rollover clock")?;
    let fresh = mfa_challenge_clock(&mut reopened, rollover_clock)?;
    assert_eq!(
        precise_call_clock(
            &mut reopened,
            "POST",
            "sys/mfa/validate",
            "",
            json!({"mfa_request_id":fresh,"mfa_payload":{second.clone():[next_code.as_str()]}}),
            rollover_clock
        )
        .status,
        403,
        "counter rollover alone cannot reset fixed attempt window"
    );
    let expired_window_clock = RequestClock::anchored(
        Duration::new(124, 600_000_000), Instant::now(),
    ).map_err(|_| "original expired-window clock")?;
    let fresh = mfa_challenge_clock(&mut reopened, expired_window_clock)?;
    let accepted = precise_call_clock(
        &mut reopened,
        "POST",
        "sys/mfa/validate",
        "",
        json!({"mfa_request_id":fresh,"mfa_payload":{second.clone():[next_code.as_str()]}}),
        expired_window_clock,
    );
    assert_eq!(
        accepted.status, 200,
        "original first-numeric period window expires without sliding"
    );
    assert!(
        accepted.body["auth"]["client_token"]
            .as_str()
            .is_some_and(|raw| !raw.is_empty())
    );
    assert!(accepted.body["auth"]["entity_id"].as_str() == Some(entity.as_str()));
    Ok(())
}

#[test]
fn mfa129_native_namespace_terminal_retirement_preserves_floor_and_rejects_old_enrollment_incarnation()
-> TestResult {
    use crate::service::tests::finish_namespace_deletion_fixture;
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/mfa-child",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let first = service
        .state
        .as_ref()
        .ok_or("state")?
        .namespaces
        .mfa_scope("mfa-child")
        .ok_or("native namespace")?;
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/auth/native",
                "mfa-child",
                &admin,
                json!({"type":"userpass"}),
                100
            )
            .status,
        204
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/native/users/alice",
                "mfa-child",
                &admin,
                json!({"password":"public-synthetic-child-mfa"}),
                100
            )
            .status,
        204
    );
    let login = service.handle_at(
        "POST",
        "auth/native/login/alice",
        "mfa-child",
        "",
        json!({"password":"public-synthetic-child-mfa"}),
        100,
    );
    assert_eq!(login.status, 200);
    let entity = login.body["auth"]["entity_id"]
        .as_str()
        .ok_or("native child entity")?
        .to_owned();
    let old_bearer = Zeroizing::new(
        login.body["auth"]["client_token"]
            .as_str()
            .ok_or("native child bearer")?
            .to_owned(),
    );
    let created = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp",
        &admin,
        json!({"issuer":"ancestor","qr_size":0}),
    );
    assert_eq!(created.status, 200);
    let id = created.body["data"]["method_id"]
        .as_str()
        .ok_or("method")?
        .to_owned();
    assert_eq!(
        service
            .handle_at(
                "GET",
                &format!("identity/mfa/method/{id}"),
                "mfa-child",
                &admin,
                json!({}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "identity/mfa/method/totp/admin-generate",
                "mfa-child",
                &admin,
                json!({"method_id":id,"entity_id":entity}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "identity/mfa/login-enforcement/child",
                "mfa-child",
                &admin,
                json!({"auth_method_types":["userpass"],"mfa_method_ids":[id]}),
                100
            )
            .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            &format!("identity/mfa/method/{id}"),
            &admin,
            json!({})
        )
        .status,
        500,
        "ancestor method cannot discard a live child enforcement"
    );
    let original = service.state.clone().ok_or("state")?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/mfa-child",
            &admin,
            json!({})
        )
        .status,
        200
    );
    // The original helper uses exactly one affine 15-second native task and all
    // original namespace binding/terminal/history/ACK checks.
    finish_namespace_deletion_fixture(&mut service, "mfa-child", Duration::from_secs(101))?;
    let retired = service.state.clone().ok_or("terminal state")?;
    assert_eq!(retired.schema, USERPASS_ISSUANCE_STATE_SCHEMA);
    assert!(retired.auth.has_identity_mfa_state());
    assert!(Service::validate_snapshot_protected_floor(&retired, &original).is_err());
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            &format!("identity/mfa/method/{id}"),
            &admin,
            json!({})
        )
        .status,
        204,
        "only actual terminal owner retirement releases the dependency"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/mfa-child",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let next = service
        .state
        .as_ref()
        .ok_or("state")?
        .namespaces
        .mfa_scope("mfa-child")
        .ok_or("recreated namespace")?;
    assert_ne!(first.0, next.0);
    assert!(next.1 > first.1);
    assert_ne!(
        service
            .handle_at(
                "GET",
                "auth/token/lookup-self",
                "mfa-child",
                &old_bearer,
                json!({}),
                102
            )
            .status,
        200,
        "a retired namespace bearer cannot inherit a new incarnation"
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "identity/mfa/method/totp/admin-generate",
                "mfa-child",
                &admin,
                json!({"method_id":id,"entity_id":entity}),
                102
            )
            .status,
        400,
        "old entity and retired enrollment cannot inherit the new namespace"
    );
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        reopened
            .handle_at("POST", "sys/unseal", "", "", json!({"key":key}), 102)
            .status,
        200
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("reopened state")?
            .auth
            .has_identity_mfa_state()
    );
    assert_eq!(
        reopened.state.as_ref().ok_or("reopened state")?.schema,
        USERPASS_ISSUANCE_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn mfa129_actual_closed_namespace_publication_snapshot_and_reopen_preserve_reference_custody()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(call(&mut service, "POST", "sys/namespaces/mfa-closed", &admin, json!({})).status, 200);
    assert_eq!(service.handle_at("POST", "sys/auth/native", "mfa-closed", &admin,
        json!({"type":"userpass"}), 100).status, 204);
    assert_eq!(service.handle_at("POST", "auth/native/users/alice", "mfa-closed", &admin,
        json!({"password":"public-synthetic-closed-mfa"}), 100).status, 204);
    let login = service.handle_at("POST", "auth/native/login/alice", "mfa-closed", "",
        json!({"password":"public-synthetic-closed-mfa"}), 100);
    assert_eq!(login.status, 200);
    let entity = login.body["auth"]["entity_id"].as_str().ok_or("native entity")?.to_owned();
    let created = call(&mut service, "POST", "identity/mfa/method/totp", &admin,
        json!({"issuer":"closed-fixture","qr_size":0}));
    assert_eq!(created.status, 200);
    let id = created.body["data"]["method_id"].as_str().ok_or("method")?.to_owned();
    assert_eq!(service.handle_at("POST", "identity/mfa/method/totp/admin-generate",
        "mfa-closed", &admin, json!({"method_id":id,"entity_id":entity}), 100).status, 200);
    let sealed = match service.begin_request(ServiceRequest {
        method: "POST",
        path: "sys/namespaces/mfa-closed/seal",
        namespace: "",
        token: &admin,
        body: json!({}),
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::Complete(reply) => reply,
        RequestExecution::External(_) => return Err("unexpected external seal effect".into()),
    };
    assert_eq!(sealed.status, 204);
    let original = service.state.as_ref().ok_or("closed state")?.protected_state()
        .map_err(|_| "closed protected owner")?.clone();
    original.validate_format().map_err(|_| "original closed format")?;
    original.validate_publication_schema(Some(&original)).map_err(|_| "original publication")?;
    Service::validate_snapshot_protected_floor(&original, &original)
        .map_err(|_| "original snapshot floor")?;
    let auth_value = serde_json::to_value(&original.auth)?;
    let registry = &auth_value["identity_mfa"];
    assert!(registry["closed_references"].get("mfa-closed").is_some());
    let epoch = registry["mutation_epoch"].as_u64().ok_or("mutation epoch")?;
    let source_bytes = crate::secret_serde::to_vec(
        service.state.as_ref().ok_or("state")?, 16 * 1024 * 1024,
    ).map_err(|_| "closed state encoding")?;
    for kind in ["erase", "id", "incarnation", "methods", "digest"] {
        let mut altered = auth_value.clone();
        altered["identity_mfa"]["mutation_epoch"] = json!(epoch.checked_add(1).ok_or("epoch bound")?);
        let index = &mut altered["identity_mfa"]["closed_references"];
        match kind {
            "erase" => { index.as_object_mut().ok_or("index map")?.remove("mfa-closed"); }
            "id" => index["mfa-closed"]["namespace_id"] = json!("wrong-owner"),
            "incarnation" => {
                let old = index["mfa-closed"]["incarnation"].as_u64().ok_or("incarnation")?;
                index["mfa-closed"]["incarnation"] = json!(old.checked_add(1).ok_or("incarnation bound")?);
            }
            "methods" => index["mfa-closed"]["method_ids"] = json!([]),
            "digest" => {
                let first = index["mfa-closed"]["owner_digest"][0].as_u64().ok_or("digest byte")?;
                index["mfa-closed"]["owner_digest"][0] = json!(first ^ 1);
            }
            _ => return Err("unknown fixed mutation".into()),
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&altered)?);
        let mut torn = original.clone();
        torn.auth = serde_json::from_slice(&bytes)?;
        // The current MAC queue reader may reject the same torn reference
        // before successor validation. Either way both actual final gates MUST
        // reject; do not require acceptance by an earlier, now stricter guard.
        if let Err(error) = torn.auth.validate_identity_mfa_state(None) {
            assert_eq!(error.status, 503);
        }
        assert!(torn.validate_publication_schema(Some(&original)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&original, &torn).is_err());
    }
    let mut fake_retirement = auth_value.clone();
    fake_retirement["identity_mfa"]["mutation_epoch"] = json!(epoch.checked_add(1).ok_or("epoch bound")?);
    let incarnation = fake_retirement["identity_mfa"]["closed_references"]["mfa-closed"]["incarnation"]
        .as_u64().ok_or("incarnation")?;
    fake_retirement["identity_mfa"]["closed_references"].as_object_mut().ok_or("index map")?
        .remove("mfa-closed");
    fake_retirement["identity_mfa"]["retired"]["mfa-closed"] = json!(incarnation);
    let bytes = Zeroizing::new(serde_json::to_vec(&fake_retirement)?);
    let mut torn = original.clone();
    torn.auth = serde_json::from_slice(&bytes)?;
    if let Err(error) = torn.auth.validate_identity_mfa_state(Some(&original.auth)) {
        assert_eq!(error.status, 503);
    }
    assert!(torn.validate_format().is_err(), "a registry floor cannot manufacture native retirement");
    assert!(crate::secret_serde::to_vec(service.state.as_ref().ok_or("state")?, 16 * 1024 * 1024)
        .map_err(|_| "closed state encoding")?.as_slice() == source_bytes.as_slice());
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status, 200);
    let duplicate = reopened.handle_at("POST", "identity/mfa/method/totp/admin-generate",
        "mfa-closed", &admin, json!({"method_id":id,"entity_id":entity}), 101);
    assert_eq!(duplicate.status, 200);
    assert!(duplicate.body["data"].is_null(), "actual encrypted parcel restores the original enrollment");
    Ok(())
}

#[test]
fn mfa129_inert_accessor_configuration_survives_real_mount_deletion_and_encrypted_reopen() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(call(&mut service, "POST", "sys/auth/mfa_inert", &admin,
        json!({"type":"userpass"})).status, 204);
    let mounts = call(&mut service, "GET", "sys/auth", &admin, json!({}));
    assert_eq!(mounts.status, 200);
    let old = mounts.body["data"]["mfa_inert/"]["accessor"]
        .as_str().ok_or("native accessor")?.to_owned();
    let created = call(&mut service, "POST", "identity/mfa/method/totp", &admin,
        json!({"issuer":"public-inert-accessor-fixture","qr_size":0}));
    assert_eq!(created.status, 200);
    let method = created.body["data"]["method_id"].as_str().ok_or("native method")?.to_owned();
    let rule = json!({"auth_method_accessors":[old],"mfa_method_ids":[method]});
    assert_eq!(call(&mut service, "POST", "identity/mfa/login-enforcement/inert", &admin,
        rule.clone()).status, 204);
    let configured = service.state.clone().ok_or("configured state")?;
    assert_eq!(call(&mut service, "DELETE", "sys/auth/mfa_inert", &admin, json!({})).status, 204);
    let removed = call(&mut service, "GET", "sys/auth", &admin, json!({}));
    assert_eq!(removed.status, 200);
    assert!(removed.body["data"].get("mfa_inert/").is_none());
    let inert = call(&mut service, "GET", "identity/mfa/login-enforcement/inert", &admin, json!({}));
    assert_eq!(inert.status, 200);
    assert_eq!(inert.body["data"]["auth_method_accessors"], json!([old]));
    assert_eq!(call(&mut service, "GET", &format!("identity/mfa/method/{method}"), &admin,
        json!({})).status, 200);
    let current = service.state.clone().ok_or("inert state")?;
    current.validate_format().map_err(|_| "actual inert MFA format")?;
    current.validate_publication_schema(Some(&configured))
        .map_err(|_| "actual inert MFA publication")?;
    Service::validate_snapshot_protected_floor(&current, &current)
        .map_err(|_| "actual inert MFA snapshot floor")?;
    let before = crate::secret_serde::to_vec(&current, 16 * 1024 * 1024)
        .map_err(|_| "private State encoding")?;
    for path in ["identity/mfa/login-enforcement/new", "identity/mfa/login-enforcement/inert"] {
        let rejected = call(&mut service, "POST", path, &admin, rule.clone());
        assert_eq!(rejected.status, 400);
        assert_eq!(rejected.body["errors"],
            json!(["one of the auth method accessors provided is invalid"]));
        assert!(crate::secret_serde::to_vec(service.state.as_ref().ok_or("state")?,
            16 * 1024 * 1024).map_err(|_| "private State encoding")?.as_slice() == before.as_slice());
    }
    let old_login = call(&mut service, "POST", "auth/mfa_inert/login/alice", "",
        json!({"password":"public-synthetic-mfa-inert"}));
    assert_eq!(old_login.status, 403);
    assert!(old_login.body.get("auth").is_none());
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status, 200);
    let inert = call(&mut reopened, "GET", "identity/mfa/login-enforcement/inert", &admin, json!({}));
    assert_eq!(inert.status, 200);
    assert_eq!(inert.body["data"]["auth_method_accessors"], json!([old]));
    assert_eq!(call(&mut reopened, "POST", "sys/auth/mfa_inert", &admin,
        json!({"type":"userpass"})).status, 204);
    let mounts = call(&mut reopened, "GET", "sys/auth", &admin, json!({}));
    assert_eq!(mounts.status, 200);
    let replacement = mounts.body["data"]["mfa_inert/"]["accessor"]
        .as_str().ok_or("native replacement accessor")?.to_owned();
    assert_ne!(old, replacement);
    assert_eq!(call(&mut reopened, "POST", "auth/mfa_inert/users/alice", &admin,
        json!({"password":"public-synthetic-mfa-inert"})).status, 204);
    let tokens_before = token_count(&reopened)?;
    let login = call(&mut reopened, "POST", "auth/mfa_inert/login/alice", "",
        json!({"password":"public-synthetic-mfa-inert"}));
    assert_eq!(login.status, 200);
    let bearer = Zeroizing::new(login.body["auth"]["client_token"]
        .as_str().ok_or("actual native bearer")?.to_owned());
    assert!(!bearer.is_empty());
    assert_eq!(token_count(&reopened)?, tokens_before + 1);
    assert!(login.body["auth"]["mfa_requirement"].is_null());
    let inert = call(&mut reopened, "GET", "identity/mfa/login-enforcement/inert", &admin, json!({}));
    assert_eq!(inert.status, 200);
    assert_eq!(inert.body["data"]["auth_method_accessors"], json!([old]));
    let read = call(&mut reopened, "GET", "identity/mfa/login-enforcement", &admin,
        json!({"list":true}));
    assert_eq!(read.status, 200);
    assert!(read.body["data"]["keys"].as_array().ok_or("enforcement keys")?
        .iter().any(|name| name.as_str() == Some("inert")));
    let final_state = reopened.state.as_ref().ok_or("final state")?;
    assert_eq!(final_state.schema, USERPASS_ISSUANCE_STATE_SCHEMA);
    final_state.validate_format().map_err(|_| "actual inert MFA reopened format")?;
    assert!(final_state.auth.has_identity_mfa_state());
    Ok(())
}

// New controls exercise the actual native first-factor grant and commit. The
// fixture holds only its own synthetic enrollment secret and never logs it.
fn janitor_native_fixture() -> Result<
    (Root, Service, Zeroizing<String>, String, Zeroizing<Vec<u8>>),
    Box<dyn std::error::Error>,
> {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/mfa_userpass",
            &admin,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/mfa_userpass/users/alice",
            &admin,
            json!({"password":"public-synthetic-mfa-test","token_ttl":20,
        "token_max_ttl":20,"token_bound_cidrs":["127.0.0.0/8"]})
        )
        .status,
        204
    );
    let normal = precise_call(
        &mut service,
        "POST",
        "auth/mfa_userpass/login/alice",
        "",
        json!({"password":"public-synthetic-mfa-test"}),
        100,
        0,
    );
    assert_eq!(normal.status, 200);
    let entity = normal.body["auth"]["entity_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or("native MFA fixture entity")?
        .to_owned();
    let created = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp",
        &admin,
        json!({"issuer":"native","qr_size":0,"period":10,"skew":0,
        "max_validation_attempts":20}),
    );
    assert_eq!(created.status, 200);
    let method = created.body["data"]["method_id"]
        .as_str()
        .ok_or("native MFA fixture method")?
        .to_owned();
    let generated = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp/admin-generate",
        &admin,
        json!({"method_id":method,"entity_id":entity}),
    );
    assert_eq!(generated.status, 200);
    let secret = enrollment_secret(&generated)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "identity/mfa/login-enforcement/native",
            &admin,
            json!({"auth_method_types":["userpass"],"mfa_method_ids":[method]})
        )
        .status,
        204
    );
    Ok((files, service, Zeroizing::new(key), method, secret))
}
fn janitor_pending_count(service: &Service) -> Result<usize, Box<dyn std::error::Error>> {
    let encoded = crate::secret_serde::to_vec(
        &service.state.as_ref().ok_or("native MFA state")?.auth,
        16 * 1024 * 1024,
    )
    .map_err(|_| "private MFA state encoding")?;
    let auth = heptabao_domain::json::decode(&encoded)?;
    Ok(auth["identity_mfa"]["namespaces"][""]["challenges"]
        .as_object()
        .ok_or("native pending MFA queue")?
        .len())
}
fn janitor_clock(seconds: u64) -> Result<RequestClock, Box<dyn std::error::Error>> {
    RequestClock::anchored(Duration::from_secs(seconds), Instant::now())
        .map_err(|_| "native janitor fixture clock".into())
}

#[test]
fn mfa129_native_queue_keeps_301_and_309_validation_live_then_retires_one_original_head()
-> TestResult {
    let (files, mut service, key, method, secret) = janitor_native_fixture()?;
    let before_tokens = token_count(&service)?;
    let mut requests = Vec::new();
    for seconds in [100, 102, 104, 106] {
        requests.push(mfa_challenge(&mut service, seconds, 0)?);
    }
    assert_eq!(
        janitor_pending_count(&service)?,
        4,
        "new first factors retain distinct original same-entity challenges"
    );
    assert_eq!(token_count(&service)?, before_tokens);
    let pending = service.state.clone().ok_or("original pending state")?;
    for (index, seconds) in [(0, 401), (1, 411)] {
        let code = Zeroizing::new(
            crate::engines::rfc6238_code(&secret, "SHA1", 6, seconds / 10)
                .map_err(|_| "native TOTP")?,
        );
        let accepted = precise_call(
            &mut service,
            "POST",
            "sys/mfa/validate",
            "",
            json!({"mfa_request_id":requests[index],
                "mfa_payload":{method.clone():[code.as_str()]}}),
            seconds,
            0,
        );
        assert_eq!(accepted.status, 200);
        assert!(
            accepted.body["auth"]["client_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
        );
    }
    assert_eq!(janitor_pending_count(&service)?, 2);
    assert_eq!(token_count(&service)?, before_tokens + 2);
    assert!(service.maintain_mfa_challenges_with_clock(janitor_clock(412)?)?);
    assert_eq!(janitor_pending_count(&service)?, 1);
    assert_eq!(
        token_count(&service)?,
        before_tokens + 2,
        "janitor retires private grants without minting a bearer"
    );
    assert_eq!(
        precise_call(
            &mut service,
            "POST",
            "sys/mfa/validate",
            "",
            json!({"mfa_request_id":requests[2]}),
            413,
            0
        )
        .status,
        400
    );
    assert_eq!(
        precise_call(
            &mut service,
            "POST",
            "sys/mfa/validate",
            "",
            json!({"mfa_request_id":requests[3]}),
            414,
            0
        )
        .status,
        403,
        "the second eligible original request remains live after one tick"
    );
    let first_retired = service.state.clone().ok_or("first terminal state")?;
    assert!(first_retired.validate_format().is_ok());
    assert!(Service::validate_snapshot_protected_floor(&first_retired, &pending).is_err());
    assert!(service.maintain_mfa_challenges_with_clock(janitor_clock(417)?)?);
    assert_eq!(janitor_pending_count(&service)?, 0);
    let terminal = service.state.clone().ok_or("terminal queue")?;
    let mut resurrected = pending.clone();
    resurrected.schema = terminal.schema;
    assert!(
        resurrected
            .validate_publication_schema(Some(&terminal))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&terminal, &resurrected).is_err());
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(
        precise_call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()}),
            418,
            0
        )
        .status,
        200
    );
    assert_eq!(janitor_pending_count(&reopened)?, 0);
    assert_eq!(token_count(&reopened)?, before_tokens + 2);
    assert_eq!(
        precise_call(
            &mut reopened,
            "POST",
            "sys/mfa/validate",
            "",
            json!({"mfa_request_id":requests[3]}),
            419,
            0
        )
        .status,
        400
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("reopened MFA state")?
            .validate_publication_schema(Some(&terminal))
            .is_ok()
    );
    Ok(())
}

#[test]
fn mfa129_affine_janitor_head_rejects_foreign_binding_stale_epoch_and_clock_without_effect()
-> TestResult {
    let (_files, mut service, _key, _method, _secret) = janitor_native_fixture()?;
    let _first = mfa_challenge(&mut service, 100, 0)?;
    let _second = mfa_challenge(&mut service, 102, 0)?;
    let current = service.state.as_ref().ok_or("native queue")?;
    let at = AuthorityTime::Precise(Timestamp::whole(403).map_err(|_| "native janitor time")?);
    let mut auth = current.auth.clone();
    let head = auth
        .prepare_mfa_janitor_observed(at)
        .map_err(|_| "native janitor head")?
        .ok_or("eligible head")?;
    let foreign = crate::auth::mfa::NativeMfaBinding::from_native(
        "different-native-cluster",
        "",
        "root",
        0,
        None,
    )
    .map_err(|_| "synthetic foreign native binding")?;
    let before = crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
        .map_err(|_| "private MFA state encoding")?;
    assert!(auth.finish_mfa_janitor_observed(head, foreign, at).is_err());
    let after = crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
        .map_err(|_| "private MFA state encoding")?;
    assert!(
        before.as_slice() == after.as_slice(),
        "foreign owner cannot mutate private state"
    );
    assert!(
        auth.prepare_mfa_janitor_observed(AuthorityTime::Precise(
            Timestamp::whole(99).map_err(|_| "regressed fixture time")?,
        ))
        .is_err()
    );
    let binding = Service::mfa_native_binding(&current.namespaces, &current.cluster_id, "")
        .map_err(|_| "actual native namespace binding")?;
    let first = auth
        .prepare_mfa_janitor_observed(at)
        .map_err(|_| "native first head")?
        .ok_or("first head")?;
    let stale = auth
        .prepare_mfa_janitor_observed(at)
        .map_err(|_| "native stale observation")?
        .ok_or("stale head")?;
    auth.finish_mfa_janitor_observed(first, binding.clone(), at)
        .map_err(|_| "original native head retirement")?;
    let before_stale = crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
        .map_err(|_| "private MFA state encoding")?;
    assert!(
        auth.finish_mfa_janitor_observed(stale, binding, at)
            .is_err()
    );
    let after_stale = crate::secret_serde::to_vec(&auth, 16 * 1024 * 1024)
        .map_err(|_| "private MFA state encoding")?;
    assert!(
        before_stale.as_slice() == after_stale.as_slice(),
        "stale head cannot mutate private state"
    );
    assert!(
        auth.validate_identity_mfa_state(Some(&current.auth))
            .is_ok()
    );
    assert_eq!(
        janitor_pending_count(&service)?,
        2,
        "private candidate observations do not publish the Service state"
    );
    Ok(())
}

#[test]
fn mfa129_host_owned_five_second_worker_has_one_retirement_and_once_joined_weak_stop() -> TestResult
{
    let (_files, mut service, _key, _method, _secret) = janitor_native_fixture()?;
    for seconds in [100, 102, 104] {
        let _request = mfa_challenge(&mut service, seconds, 0)?;
    }
    let before_tokens = token_count(&service)?;
    let service = Arc::new(Mutex::new(service));
    let worker =
        start_mfa_janitor_worker(&service).map_err(|_| "start original MFA janitor worker")?;
    let deadline = Instant::now() + Duration::from_secs(7);
    while worker.successful_retirements() == 0 && Instant::now() < deadline {
        // Observe only the original thread's successful commit, without taking
        // the Service writer precisely when its real try_lock tick arrives.
        std::thread::sleep(Duration::from_millis(2));
    }
    let original_retirements = worker.successful_retirements();
    drop(worker); // wakes and joins the original thread outside the writer lock
    assert_eq!(original_retirements, 1, "one original worker commit must finish");
    let count = {
        let writer = service.lock().map_err(|_| "MFA test writer")?;
        janitor_pending_count(&writer)?
    };
    assert_eq!(
        count, 2,
        "one real five-second tick retires at most one head"
    );
    assert_eq!(
        Arc::strong_count(&service),
        1,
        "the joined worker owns only a Weak Service reference"
    );
    {
        let writer = service.lock().map_err(|_| "MFA test writer")?;
        assert_eq!(janitor_pending_count(&writer)?, 2);
        assert_eq!(token_count(&writer)?, before_tokens);
        assert!(
            writer
                .state
                .as_ref()
                .ok_or("durable MFA retirement")?
                .validate_format()
                .is_ok()
        );
    }
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        janitor_pending_count(&*service.lock().map_err(|_| "MFA test writer")?)?,
        2,
        "stopped original thread cannot publish another retirement"
    );
    Ok(())
}
// Synthetic native owners only. No input fixture contains an issued MFA bearer.
struct ClosedJanitorFixture {
    files: Root,
    service: Service,
    root_key: Zeroizing<String>,
    admin: Zeroizing<String>,
    namespace_key: Zeroizing<String>,
    requests: Vec<String>,
    live_token_count: usize,
    outer_key: Option<Zeroizing<String>>,
}
fn closed_janitor_call(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
    seconds: u64,
) -> Response {
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(seconds), started)
        .expect("synthetic original native clock");
    // Unit callers have no HTTP worker. Keep one original request budget from
    // the same clock anchor, using the existing native namespace fixture's
    // fifteen-second budget. An enclosing earlier deadline remains earlier.
    let _request = crate::request_deadline::RequestDeadlineScope::enter(
        started + Duration::from_secs(15),
    );
    // These fixture strings name an absolute namespace owner. The actual
    // public endpoint accepts one child name relative to the native namespace
    // header, including seal operations. Never relax the production '/' guard.
    let relative;
    let parent;
    let (path, namespace) = if let Some(target) = path.strip_prefix("sys/namespaces/") {
        let (owner, operation) = ["seal", "unseal", "seal-status"].into_iter()
            .find_map(|operation| target.strip_suffix(&format!("/{operation}"))
                .map(|owner| (owner, Some(operation))))
            .unwrap_or((target, None));
        if let Some((base, child)) = owner.rsplit_once('/') {
            parent = if namespace.is_empty() { base.to_owned() }
                else { format!("{namespace}/{base}") };
            relative = operation.map_or_else(|| format!("sys/namespaces/{child}"),
                |operation| format!("sys/namespaces/{child}/{operation}"));
            (relative.as_str(), parent.as_str())
        } else { (path, namespace) }
    } else { (path, namespace) };
    service.handle_request_clock(
        ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: Some("127.0.0.1".parse().expect("synthetic peer")),
            client_certificates: None,
        },
        seconds,
        true,
        Some(clock),
    )
}
fn closed_janitor_fixture(
    independent_outer: bool,
) -> Result<ClosedJanitorFixture, Box<dyn std::error::Error>> {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let outer = call(
        &mut service,
        "POST",
        "sys/namespaces/mfa-queue-outer",
        &admin,
        if independent_outer {
            json!({"seal":"seal \"shamir\" { shares = 1 threshold = 1 }"})
        } else {
            json!({})
        },
    );
    assert_eq!(outer.status, 200);
    let outer_key = if independent_outer {
        let key = Zeroizing::new(
            outer.body["data"]["key_shares"][0]
                .as_str()
                .ok_or("actual enclosing namespace key share")?
                .to_owned(),
        );
        assert_eq!(
            closed_janitor_call(
                &mut service,
                "POST",
                "sys/namespaces/mfa-queue-outer/unseal",
                "",
                &admin,
                json!({"key":key.as_str()}),
                100
            )
            .status,
            200
        );
        Some(key)
    } else {
        None
    };
    let created = closed_janitor_call(
        &mut service,
        "POST",
        "sys/namespaces/mfa-queue-outer/child",
        "",
        &admin,
        json!({"seal":"seal \"shamir\" { shares = 1 threshold = 1 }"}),
        100,
    );
    assert_eq!(created.status, 200);
    let namespace_key = Zeroizing::new(
        created.body["data"]["key_shares"][0]
            .as_str()
            .ok_or("actual native namespace key share")?
            .to_owned(),
    );
    assert_eq!(
        closed_janitor_call(
            &mut service,
            "POST",
            "sys/namespaces/mfa-queue-outer/child/unseal",
            "",
            &admin,
            json!({"key":namespace_key.as_str()}),
            100
        )
        .status,
        200
    );
    let ns = "mfa-queue-outer/child";
    assert_eq!(
        closed_janitor_call(
            &mut service,
            "POST",
            "sys/auth/native",
            ns,
            &admin,
            json!({"type":"userpass"}),
            100
        )
        .status,
        204
    );
    assert_eq!(closed_janitor_call(&mut service,"POST","auth/native/users/alice",ns,&admin,
        json!({"password":"public-synthetic-closed-janitor","token_bound_cidrs":["127.0.0.0/8"]}),100).status,204);
    let first = closed_janitor_call(
        &mut service,
        "POST",
        "auth/native/login/alice",
        ns,
        "",
        json!({"password":"public-synthetic-closed-janitor"}),
        100,
    );
    assert_eq!(first.status, 200);
    let entity = first.body["auth"]["entity_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("real native entity")?
        .to_owned();
    let method = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp",
        &admin,
        json!({"issuer":"closed-janitor","qr_size":0,"period":10,"skew":0}),
    );
    assert_eq!(method.status, 200);
    let id = method.body["data"]["method_id"]
        .as_str()
        .ok_or("real method")?
        .to_owned();
    assert_eq!(
        closed_janitor_call(
            &mut service,
            "POST",
            "identity/mfa/method/totp/admin-generate",
            ns,
            &admin,
            json!({"method_id":id,"entity_id":entity}),
            100
        )
        .status,
        200
    );
    assert_eq!(
        closed_janitor_call(
            &mut service,
            "POST",
            "identity/mfa/login-enforcement/closed",
            ns,
            &admin,
            json!({"auth_method_types":["userpass"],"mfa_method_ids":[id]}),
            100
        )
        .status,
        204
    );
    let mut requests = Vec::new();
    for seconds in [100, 102] {
        let reply = closed_janitor_call(
            &mut service,
            "POST",
            "auth/native/login/alice",
            ns,
            "",
            json!({"password":"public-synthetic-closed-janitor"}),
            seconds,
        );
        assert_eq!(reply.status, 200);
        assert!(reply.body["auth"]["client_token"].as_str() == Some(""));
        requests.push(
            reply.body["auth"]["mfa_requirement"]["mfa_request_id"]
                .as_str()
                .ok_or("real unissued native challenge")?
                .to_owned(),
        );
    }
    assert_ne!(requests[0], requests[1]);
    let live_token_count = token_count(&service)?;
    Ok(ClosedJanitorFixture {
        files,
        service,
        root_key: Zeroizing::new(key),
        admin: Zeroizing::new(admin),
        namespace_key,
        requests,
        live_token_count,
        outer_key,
    })
}
fn closed_janitor_auth(state: &State) -> Result<Value, Box<dyn std::error::Error>> {
    let encoded = crate::secret_serde::to_vec(&state.auth, 16 * 1024 * 1024)
        .map_err(|_| "private MFA encoding")?;
    Ok(heptabao_domain::json::decode(&encoded)?)
}
fn closed_janitor_restore_root(
    fixture: ClosedJanitorFixture,
    seconds: u64,
) -> Result<ClosedJanitorFixture, Box<dyn std::error::Error>> {
    // Drop the original audit writer before opening the same authenticated log.
    // The durable root and independent namespace keys retain their real owner.
    let ClosedJanitorFixture {
        files, service, root_key, admin, namespace_key, requests,
        live_token_count, outer_key,
    } = fixture;
    drop(service);
    let service = files.service()?;
    let mut fixture = ClosedJanitorFixture {
        files, service, root_key, admin, namespace_key, requests,
        live_token_count, outer_key,
    };
    assert_eq!(
        precise_call(
            &mut fixture.service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":fixture.root_key.as_str()}),
            seconds,
            0
        )
        .status,
        200
    );
    assert!(
        !fixture
            .service
            .namespace_runtime
            .is_loaded("mfa-queue-outer/child")
    );
    Ok(fixture)
}

#[test]
fn mfa129_closed_capsule_janitor_commits_receipt_then_authenticates_original_key_before_terminal_reopen()
-> TestResult {
    let mut fixture = closed_janitor_fixture(false)?;
    fixture = closed_janitor_restore_root(fixture, 403)?;
    let before = fixture
        .service
        .state
        .as_ref()
        .ok_or("closed original")?
        .protected_state()
        .map_err(|_| "protected state")?
        .clone();
    let original = closed_janitor_auth(&before)?;
    let original_index =
        original["identity_mfa"]["closed_references"]["mfa-queue-outer/child"].clone();
    let original_stamp = fixture
        .service
        .state
        .as_ref()
        .ok_or("actual restored outer catalog")?
        .sdk_namespace_ciphertext_owner("mfa-queue-outer/child")
        .map_err(|_| "actual original capsule")?;
    assert_eq!(original["identity_mfa"]["format"], 2);
    assert!(original_index["queue_digest"].is_array());
    assert!(
        fixture
            .service
            .maintain_mfa_challenges_with_clock(janitor_clock(403)?)
            .map_err(|_| "actual closed janitor commit")?
    );
    let retired = fixture
        .service
        .state
        .as_ref()
        .ok_or("retired root")?
        .protected_state()
        .map_err(|_| "protected retired state")?
        .clone();
    let retired_auth = closed_janitor_auth(&retired)?;
    assert_eq!(
        retired_auth["identity_mfa"]["closed_references"]["mfa-queue-outer/child"],
        original_index
    );
    assert!(
        fixture
            .service
            .state
            .as_ref()
            .ok_or("retained actual restored outer catalog")?
            .sdk_namespace_ciphertext_owner("mfa-queue-outer/child")
            .map_err(|_| "retained actual capsule")?
            == original_stamp
    );
    let receipts = retired_auth["identity_mfa"]["janitor_custody"]["terminal"]
        .as_array()
        .ok_or("actual terminal receipts")?;
    assert_eq!(receipts.len(), 1);
    let removed = receipts[0]["id"]
        .as_str()
        .ok_or("original removed id")?
        .to_owned();
    assert!(fixture.requests.contains(&removed));
    assert!(
        retired_auth["identity_mfa"]["janitor_custody"]["applied"]
            .as_array()
            .ok_or("unconsumed actual receipts")?
            .is_empty()
    );
    assert!(Service::validate_snapshot_protected_floor(&retired, &before).is_err());
    let count_before = fixture.live_token_count;
    fixture = closed_janitor_restore_root(fixture, 404)?;
    let closed_auth = closed_janitor_auth(
        fixture
            .service
            .state
            .as_ref()
            .ok_or("actual closed owner")?,
    )?;
    let wrong_key = closed_janitor_call(
        &mut fixture.service,
        "POST",
        "sys/namespaces/mfa-queue-outer/child/unseal",
        "",
        &fixture.admin,
        json!({"key":fixture.root_key.as_str()}),
        404,
    );
    assert_eq!(wrong_key.status, 400);
    assert!(wrong_key.body.get("auth").is_none());
    assert!(
        !fixture
            .service
            .namespace_runtime
            .is_loaded("mfa-queue-outer/child")
    );
    assert_eq!(
        closed_janitor_auth(
            fixture
                .service
                .state
                .as_ref()
                .ok_or("unchanged closed owner")?
        )?,
        closed_auth,
        "another owner's key cannot consume the authenticated receipt"
    );
    let status = closed_janitor_call(
        &mut fixture.service,
        "POST",
        "sys/namespaces/mfa-queue-outer/child/unseal",
        "",
        &fixture.admin,
        json!({"key":fixture.namespace_key.as_str()}),
        404,
    );
    assert_eq!(status.status, 200);
    assert!(
        fixture
            .service
            .namespace_runtime
            .is_loaded("mfa-queue-outer/child")
    );
    assert_eq!(token_count(&fixture.service)?, count_before);
    let completed = fixture
        .service
        .state
        .as_ref()
        .ok_or("completed private owner")?;
    let auth = closed_janitor_auth(completed)?;
    let owner = &auth["identity_mfa"]["namespaces"]["mfa-queue-outer/child"];
    assert_eq!(
        owner["challenges"]
            .as_object()
            .ok_or("real remaining queue")?
            .len(),
        1
    );
    assert!(owner["challenges"].get(&removed).is_none());
    assert_eq!(
        owner["terminal"]
            .as_array()
            .ok_or("terminal history")?
            .len(),
        1
    );
    assert_eq!(
        auth["identity_mfa"]["janitor_custody"]["applied"]
            .as_array()
            .ok_or("applied")?
            .len(),
        1
    );
    assert!(completed.validate_format().is_ok());
    assert!(Service::validate_snapshot_protected_floor(completed, &retired).is_err());
    let rejected = closed_janitor_call(
        &mut fixture.service,
        "POST",
        "sys/mfa/validate",
        "mfa-queue-outer/child",
        "",
        json!({"mfa_request_id":removed}),
        405,
    );
    assert_eq!(rejected.status, 400);
    assert!(rejected.body.get("auth").is_none());
    assert_eq!(token_count(&fixture.service)?, count_before);
    // Another actual encrypted cold reopen must not resurrect the private grant.
    fixture = closed_janitor_restore_root(fixture, 406)?;
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-outer/child/unseal",
            "",
            &fixture.admin,
            json!({"key":fixture.namespace_key.as_str()}),
            406
        )
        .status,
        200
    );
    let durable = closed_janitor_auth(fixture.service.state.as_ref().ok_or("durable owner")?)?;
    assert!(
        durable["identity_mfa"]["namespaces"]["mfa-queue-outer/child"]["challenges"]
            .get(&removed)
            .is_none()
    );
    assert_eq!(
        durable["identity_mfa"]["janitor_custody"]["terminal"]
            .as_array()
            .ok_or("sticky terminal")?
            .len(),
        1
    );
    assert_eq!(
        durable["identity_mfa"]["janitor_custody"]["applied"]
            .as_array()
            .ok_or("sticky applied")?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn mfa129_closed_capsule_receipt_erasure_wrong_digest_incarnation_and_duplicate_application_are_denied()
-> TestResult {
    let mut fixture = closed_janitor_fixture(false)?;
    fixture = closed_janitor_restore_root(fixture, 403)?;
    assert!(
        fixture
            .service
            .maintain_mfa_challenges_with_clock(janitor_clock(403)?)
            .map_err(|_| "actual receipt")?
    );
    let original = fixture
        .service
        .state
        .as_ref()
        .ok_or("actual closed")?
        .protected_state()
        .map_err(|_| "actual protected")?
        .clone();
    let value = closed_janitor_auth(&original)?;
    let encoded_original =
        crate::secret_serde::to_vec(&original, 16 * 1024 * 1024).map_err(|_| "original state")?;
    for kind in [
        "remove-ledger",
        "erase-current",
        "erase-terminal",
        "capsule",
        "owner",
        "sequence",
        "id",
        "binding",
        "source",
        "epoch",
        "format",
    ] {
        let mut changed = value.clone();
        let registry = &mut changed["identity_mfa"];
        let epoch = registry["mutation_epoch"].as_u64().ok_or("epoch")?;
        registry["mutation_epoch"] = json!(epoch.checked_add(1).ok_or("epoch bound")?);
        if kind == "format" {
            registry["format"] = json!(1);
        } else if kind == "remove-ledger" {
            registry
                .as_object_mut()
                .ok_or("registry")?
                .remove("janitor_custody");
        } else {
            let book = &mut registry["janitor_custody"];
            match kind {
                "erase-current" => {
                    book["current"].as_object_mut().ok_or("current")?.clear();
                }
                "erase-terminal" => book["terminal"] = json!([]),
                "capsule" => {
                    let descriptor = &mut book["current"]["mfa-queue-outer/child"]["capture"]["ciphertext"]
                        ["descriptor"][0];
                    let byte = descriptor.as_u64().ok_or("actual capsule digest byte")?;
                    *descriptor = json!(byte ^ 1);
                }
                "owner" => {
                    let byte = book["terminal"][0]["capture"]["owner_digest"][0]
                        .as_u64()
                        .ok_or("owner digest byte")?;
                    book["terminal"][0]["capture"]["owner_digest"][0] = json!(byte ^ 1);
                }
                "sequence" => {
                    book["terminal"][0]["capture"]["entries"]
                        .as_object_mut()
                        .ok_or("entries")?
                        .values_mut()
                        .next()
                        .ok_or("entry")?["sequence"] = json!(999999)
                }
                "id" => book["terminal"][0]["id"] = json!("00000000-0000-0000-0000-000000000000"),
                "binding" => book["terminal"][0]["capture"]["incarnation"] = json!(999999),
                "source" => {
                    let byte = book["terminal"][0]["source_capture"][0]
                        .as_u64()
                        .ok_or("source commitment")?;
                    book["terminal"][0]["source_capture"][0] = json!(byte ^ 1);
                }
                "epoch" => book["terminal"][0]["epoch"] = json!(0),
                _ => return Err("unknown fixed mutation".into()),
            }
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&changed)?);
        let mut torn = original.clone();
        torn.auth = serde_json::from_slice(&bytes)?;
        assert!(
            torn.validate_publication_schema(Some(&original)).is_err(),
            "terminal custody cannot be changed"
        );
        assert!(Service::validate_snapshot_protected_floor(&original, &torn).is_err());
    }
    assert!(
        crate::secret_serde::to_vec(&original, 16 * 1024 * 1024)
            .map_err(|_| "original encoding")?
            .as_slice()
            == encoded_original.as_slice()
    );
    // The incapable receipt has not hydrated an owner or minted a bearer.
    let receipts = value["identity_mfa"]["janitor_custody"]["terminal"]
        .as_array()
        .ok_or("actual closed receipts")?;
    assert_eq!(receipts.len(), 1);
    assert!(
        fixture
            .requests
            .iter()
            .any(|id| receipts[0]["id"].as_str() == Some(id.as_str()))
    );
    assert!(
        value["identity_mfa"]["namespaces"]
            .get("mfa-queue-outer/child")
            .is_none()
    );
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-outer/child/unseal",
            "",
            &fixture.admin,
            json!({"key":fixture.namespace_key.as_str()}),
            404
        )
        .status,
        200
    );
    // State::clone intentionally clears its prepared namespace publication view.
    // Exercise the only mutable owner accepted by the receipt consumer instead.
    let state = fixture.service.state.as_ref().ok_or("real complete")?;
    let encoded_state = crate::secret_serde::to_vec(state, 16 * 1024 * 1024)
        .map_err(|_| "committed encoding")?;
    let mut after = state.auth.clone();
    let before =
        crate::secret_serde::to_vec(&after, 16 * 1024 * 1024).map_err(|_| "complete encoding")?;
    assert_eq!(after.consume_authenticated_mfa_terminal_receipts()?, 0);
    assert!(
        crate::secret_serde::to_vec(&after, 16 * 1024 * 1024)
            .map_err(|_| "unchanged encoding")?
            .as_slice()
            == before.as_slice(),
        "the actual receipt is consumed once"
    );
    assert!(
        crate::secret_serde::to_vec(state, 16 * 1024 * 1024)
            .map_err(|_| "unchanged committed encoding")?
            .as_slice()
            == encoded_state.as_slice(),
        "the actual committed full state is unchanged"
    );
    Ok(())
}

#[test]
fn mfa129_hidden_child_queue_uses_actual_enclosing_capsule_and_keeps_terminal_history_through_root_reopen()
-> TestResult {
    let mut fixture = closed_janitor_fixture(true)?;
    // Durable serialization actually encloses the independent child under the
    // ordinary parent, even though the current loaded logical parent is open.
    let protected = fixture
        .service
        .state
        .as_ref()
        .ok_or("live")?
        .protected_state()
        .map_err(|_| "actual physical view")?
        .clone();
    let value = closed_janitor_auth(&protected)?;
    let locator = &value["identity_mfa"]["janitor_custody"]["current"]["mfa-queue-outer/child"];
    assert_eq!(
        locator["enclosures"]
            .as_array()
            .ok_or("actual enclosure")?
            .len(),
        1
    );
    let expected = protected
        .sdk_namespace_ciphertext_owner("mfa-queue-outer")
        .map_err(|_| "actual parent capsule")?;
    assert_eq!(serde_json::to_value(expected)?, locator["enclosures"][0]);
    let incapable = serde_json::to_vec(locator)?;
    assert!(!incapable.windows(b"grant".len()).any(|w| w == b"grant"));
    assert!(!incapable.windows(b"secret".len()).any(|w| w == b"secret"));
    assert!(protected.validate_format().is_ok());
    fixture = closed_janitor_restore_root(fixture, 403)?;
    assert!(
        !fixture
            .service
            .state
            .as_ref()
            .ok_or("actual root reopened")?
            .namespaces
            .contains("mfa-queue-outer/child"),
        "a sealed enclosing catalog is not a visible child routing authority"
    );
    assert!(
        !fixture
            .service
            .namespace_runtime
            .is_loaded("mfa-queue-outer")
    );
    assert!(
        fixture
            .service
            .maintain_mfa_challenges_with_clock(janitor_clock(403)?)
            .map_err(|_| "root receipt")?
    );
    assert!(
        fixture
            .service
            .maintain_mfa_challenges_with_clock(janitor_clock(408)?)
            .map_err(|_| "second root receipt")?
    );
    assert!(
        !fixture
            .service
            .maintain_mfa_challenges_with_clock(janitor_clock(413)?)
            .map_err(|_| "empty actual root head")?
    );
    let enclosing_key = fixture
        .outer_key
        .as_ref()
        .ok_or("actual original enclosing key")?;
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-outer/unseal",
            "",
            &fixture.admin,
            json!({"key":enclosing_key.as_str()}),
            413
        )
        .status,
        200
    );
    assert!(
        !fixture
            .service
            .namespace_runtime
            .is_loaded("mfa-queue-outer/child")
    );
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-outer/child/unseal",
            "",
            &fixture.admin,
            json!({"key":fixture.namespace_key.as_str()}),
            413
        )
        .status,
        200
    );
    let logical = fixture.service.state.as_ref().ok_or("actual restored")?;
    let now = closed_janitor_auth(logical)?;
    assert!(
        now["identity_mfa"]["namespaces"]["mfa-queue-outer/child"]["challenges"]
            .as_object()
            .ok_or("actual consumed private queue")?
            .is_empty()
    );
    assert_eq!(
        now["identity_mfa"]["namespaces"]["mfa-queue-outer/child"]["terminal"]
            .as_array()
            .ok_or("actual terminal owner")?
            .len(),
        2
    );
    assert_eq!(
        now["identity_mfa"]["janitor_custody"]["terminal"]
            .as_array()
            .ok_or("receipts")?
            .len(),
        2
    );
    assert_eq!(
        now["identity_mfa"]["janitor_custody"]["applied"]
            .as_array()
            .ok_or("applied")?
            .len(),
        2
    );
    assert!(logical.validate_format().is_ok());
    fixture = closed_janitor_restore_root(fixture, 414)?;
    assert_eq!(closed_janitor_call(&mut fixture.service, "POST",
        "sys/namespaces/mfa-queue-outer/unseal", "", &fixture.admin,
        json!({"key":fixture.outer_key.as_ref().ok_or("actual durable enclosing key")?.as_str()}),
        414).status, 200);
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-outer/child/unseal",
            "",
            &fixture.admin,
            json!({"key":fixture.namespace_key.as_str()}),
            414
        )
        .status,
        200
    );
    for request in &fixture.requests {
        assert_eq!(
            closed_janitor_call(
                &mut fixture.service,
                "POST",
                "sys/mfa/validate",
                "mfa-queue-outer/child",
                "",
                json!({"mfa_request_id":request}),
                414
            )
            .status,
            400
        );
    }
    Ok(())
}

fn deep_closed_janitor_fixture()
-> Result<(ClosedJanitorFixture, Zeroizing<String>), Box<dyn std::error::Error>> {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let independent_outer = true;
    let top = call(
        &mut service,
        "POST",
        "sys/namespaces/mfa-queue-top",
        &admin,
        json!({"seal":"seal \"shamir\" { shares = 1 threshold = 1 }"}),
    );
    assert_eq!(top.status, 200);
    let top_key = Zeroizing::new(
        top.body["data"]["key_shares"][0]
            .as_str()
            .ok_or("actual grandparent namespace key share")?
            .to_owned(),
    );
    assert_eq!(
        closed_janitor_call(
            &mut service,
            "POST",
            "sys/namespaces/mfa-queue-top/unseal",
            "",
            &admin,
            json!({"key":top_key.as_str()}),
            100
        )
        .status,
        200
    );
    let outer = closed_janitor_call(
        &mut service,
        "POST",
        "sys/namespaces/mfa-queue-top/outer",
        "",
        &admin,
        if independent_outer {
            json!({"seal":"seal \"shamir\" { shares = 1 threshold = 1 }"})
        } else {
            json!({})
        },
        100,
    );
    assert_eq!(outer.status, 200);
    let outer_key = if independent_outer {
        let key = Zeroizing::new(
            outer.body["data"]["key_shares"][0]
                .as_str()
                .ok_or("actual enclosing namespace key share")?
                .to_owned(),
        );
        assert_eq!(
            closed_janitor_call(
                &mut service,
                "POST",
                "sys/namespaces/mfa-queue-top/outer/unseal",
                "",
                &admin,
                json!({"key":key.as_str()}),
                100
            )
            .status,
            200
        );
        Some(key)
    } else {
        None
    };
    let created = closed_janitor_call(
        &mut service,
        "POST",
        "sys/namespaces/mfa-queue-top/outer/child",
        "",
        &admin,
        json!({"seal":"seal \"shamir\" { shares = 1 threshold = 1 }"}),
        100,
    );
    assert_eq!(created.status, 200);
    let namespace_key = Zeroizing::new(
        created.body["data"]["key_shares"][0]
            .as_str()
            .ok_or("actual native namespace key share")?
            .to_owned(),
    );
    assert_eq!(
        closed_janitor_call(
            &mut service,
            "POST",
            "sys/namespaces/mfa-queue-top/outer/child/unseal",
            "",
            &admin,
            json!({"key":namespace_key.as_str()}),
            100
        )
        .status,
        200
    );
    let ns = "mfa-queue-top/outer/child";
    assert_eq!(
        closed_janitor_call(
            &mut service,
            "POST",
            "sys/auth/native",
            ns,
            &admin,
            json!({"type":"userpass"}),
            100
        )
        .status,
        204
    );
    assert_eq!(closed_janitor_call(&mut service,"POST","auth/native/users/alice",ns,&admin,
        json!({"password":"public-synthetic-closed-janitor","token_bound_cidrs":["127.0.0.0/8"]}),100).status,204);
    let first = closed_janitor_call(
        &mut service,
        "POST",
        "auth/native/login/alice",
        ns,
        "",
        json!({"password":"public-synthetic-closed-janitor"}),
        100,
    );
    assert_eq!(first.status, 200);
    let entity = first.body["auth"]["entity_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("real native entity")?
        .to_owned();
    let method = call(
        &mut service,
        "POST",
        "identity/mfa/method/totp",
        &admin,
        json!({"issuer":"closed-janitor","qr_size":0,"period":10,"skew":0}),
    );
    assert_eq!(method.status, 200);
    let id = method.body["data"]["method_id"]
        .as_str()
        .ok_or("real method")?
        .to_owned();
    assert_eq!(
        closed_janitor_call(
            &mut service,
            "POST",
            "identity/mfa/method/totp/admin-generate",
            ns,
            &admin,
            json!({"method_id":id,"entity_id":entity}),
            100
        )
        .status,
        200
    );
    assert_eq!(
        closed_janitor_call(
            &mut service,
            "POST",
            "identity/mfa/login-enforcement/closed",
            ns,
            &admin,
            json!({"auth_method_types":["userpass"],"mfa_method_ids":[id]}),
            100
        )
        .status,
        204
    );
    let mut requests = Vec::new();
    for seconds in [100, 102] {
        let reply = closed_janitor_call(
            &mut service,
            "POST",
            "auth/native/login/alice",
            ns,
            "",
            json!({"password":"public-synthetic-closed-janitor"}),
            seconds,
        );
        assert_eq!(reply.status, 200);
        assert!(reply.body["auth"]["client_token"].as_str() == Some(""));
        requests.push(
            reply.body["auth"]["mfa_requirement"]["mfa_request_id"]
                .as_str()
                .ok_or("real unissued native challenge")?
                .to_owned(),
        );
    }
    assert_ne!(requests[0], requests[1]);
    let live_token_count = token_count(&service)?;
    Ok((
        ClosedJanitorFixture {
            files,
            service,
            root_key: Zeroizing::new(key),
            admin: Zeroizing::new(admin),
            namespace_key,
            requests,
            live_token_count,
            outer_key,
        },
        top_key,
    ))
}

#[test]
fn mfa129_native_retirement_floor_stays_global_through_independent_parent_close_and_encrypted_reopen()
-> TestResult {
    let mut fixture = closed_janitor_fixture(true)?;
    let ns = "mfa-queue-outer/child";
    let original = fixture
        .service
        .state
        .clone()
        .ok_or("live original namespace")?;
    let first = original
        .namespaces
        .mfa_scope(ns)
        .ok_or("original native id")?;
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "DELETE",
            "sys/namespaces/mfa-queue-outer/child",
            "",
            &fixture.admin,
            json!({}),
            110
        )
        .status,
        200
    );
    crate::service::tests::finish_namespace_deletion_fixture(
        &mut fixture.service,
        ns,
        Duration::from_secs(111),
    )?;
    let terminal = fixture
        .service
        .state
        .clone()
        .ok_or("actual terminal owner")?;
    assert!(!terminal.namespaces.contains(ns));
    assert_eq!(terminal.namespaces.mfa_retirement_floor(ns), Some(first.1));
    let terminal_auth = closed_janitor_auth(&terminal)?;
    assert_eq!(
        terminal_auth["identity_mfa"]["retired"][ns].as_u64(),
        Some(first.1)
    );
    assert!(
        terminal_auth["identity_mfa"]["closed_references"]
            .get(ns)
            .is_none()
    );
    assert!(
        terminal_auth["identity_mfa"]["namespaces"]
            .get(ns)
            .is_none()
    );
    assert!(Service::validate_snapshot_protected_floor(&terminal, &original).is_err());
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-outer/seal",
            "",
            &fixture.admin,
            json!({}),
            112
        )
        .status,
        204
    );
    assert!(
        !fixture
            .service
            .namespace_runtime
            .is_loaded("mfa-queue-outer")
    );
    let closed = fixture
        .service
        .state
        .as_ref()
        .ok_or("closed enclosing owner")?
        .protected_state()
        .map_err(|_| "actual encrypted projection")?
        .clone();
    let real_stamp = closed
        .sdk_namespace_ciphertext_owner("mfa-queue-outer")
        .map_err(|_| "actual closed enclosing ciphertext")?;
    assert_eq!(closed.namespaces.mfa_retirement_floor(ns), Some(first.1));
    assert!(closed.validate_format().is_ok());
    let encoded = crate::secret_serde::to_vec(&closed, 16 * 1024 * 1024)
        .map_err(|_| "private original encoding")?;
    for mode in ["erase", "regress"] {
        let mut value = heptabao_domain::json::decode(&encoded)?;
        if mode == "erase" {
            value["namespaces"]["next_incarnation"]
                .as_object_mut()
                .ok_or("actual global incarnation ledger")?
                .remove(ns);
        } else {
            value["namespaces"]["next_incarnation"][ns] = json!(first.1);
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&value)?);
        let torn: State = serde_json::from_slice(&bytes)?;
        assert!(
            torn.auth
                .validate_identity_mfa_bindings(
                    &torn.cluster_id,
                    |path| torn.namespaces.mfa_scope(path),
                    |path| torn.namespaces.mfa_retirement_floor(path),
                    |path| torn.namespaces.custody_owner(path).is_some()
                        || torn.namespaces.inherited_owner(path).is_some()
                )
                .is_err(),
            "the original MFA floor requires actual global native retirement evidence"
        );
        assert!(torn.validate_format().is_err());
        assert!(torn.validate_publication_schema(Some(&closed)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&closed, &torn).is_err());
        assert!(
            torn.sdk_namespace_ciphertext_owner("mfa-queue-outer")
                .map_err(|_| "unchanged actual descriptor")?
                == real_stamp
        );
    }
    fixture = closed_janitor_restore_root(fixture, 113)?;
    let cold = fixture.service.state.as_ref().ok_or("cold durable root")?;
    assert!(
        !fixture
            .service
            .namespace_runtime
            .is_loaded("mfa-queue-outer")
    );
    assert_eq!(cold.namespaces.mfa_retirement_floor(ns), Some(first.1));
    assert_eq!(
        closed_janitor_auth(cold)?["identity_mfa"]["retired"][ns].as_u64(),
        Some(first.1)
    );
    assert!(cold.validate_format().is_ok());
    let outer_key = fixture.outer_key.as_ref().ok_or("original parent key")?;
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-outer/unseal",
            "",
            &fixture.admin,
            json!({"key":outer_key.as_str()}),
            114
        )
        .status,
        200
    );
    assert_eq!(
        fixture
            .service
            .state
            .as_ref()
            .ok_or("restored parent")?
            .namespaces
            .mfa_retirement_floor(ns),
        Some(first.1)
    );
    let recreated = closed_janitor_call(
        &mut fixture.service,
        "POST",
        "sys/namespaces/mfa-queue-outer/child",
        "",
        &fixture.admin,
        json!({"seal":"seal \"shamir\" { shares = 1 threshold = 1 }"}),
        115,
    );
    assert_eq!(recreated.status, 200);
    let next = fixture
        .service
        .state
        .as_ref()
        .ok_or("new native namespace")?
        .namespaces
        .mfa_scope(ns)
        .ok_or("new id")?;
    assert_ne!(first.0, next.0);
    assert!(next.1 > first.1);
    assert_ne!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-outer/child/unseal",
            "",
            &fixture.admin,
            json!({"key":fixture.namespace_key.as_str()}),
            116
        )
        .status,
        200,
        "retired original native key does not open the new incarnation"
    );
    let next_key = Zeroizing::new(
        recreated.body["data"]["key_shares"][0]
            .as_str()
            .ok_or("real successor key")?
            .to_owned(),
    );
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-outer/child/unseal",
            "",
            &fixture.admin,
            json!({"key":next_key.as_str()}),
            117
        )
        .status,
        200
    );
    let tokens = token_count(&fixture.service)?;
    for request in &fixture.requests {
        let denied = closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/mfa/validate",
            ns,
            "",
            json!({"mfa_request_id":request}),
            118,
        );
        assert_eq!(denied.status, 400);
        assert!(denied.body.get("auth").is_none());
    }
    assert_eq!(token_count(&fixture.service)?, tokens);
    assert_eq!(
        fixture
            .service
            .state
            .as_ref()
            .ok_or("new durable state")?
            .namespaces
            .mfa_retirement_floor(ns),
        Some(next.1)
    );
    Ok(())
}
#[test]
fn mfa129_actual_nested_enclosure_chain_mac_rejects_middle_poison_before_publication_or_snapshot()
-> TestResult {
    let (mut fixture, top_key) = deep_closed_janitor_fixture()?;
    let ns = "mfa-queue-top/outer/child";
    let original = fixture
        .service
        .state
        .as_ref()
        .ok_or("actual native nested owner")?
        .protected_state()
        .map_err(|_| "actual encrypted nested graph")?
        .clone();
    let value = closed_janitor_auth(&original)?;
    let chain = value["identity_mfa"]["janitor_custody"]["current"][ns]["enclosures"]
        .as_array()
        .ok_or("actual ordered enclosing descriptors")?;
    assert_eq!(chain.len(), 2);
    let top_stamp = original
        .sdk_namespace_ciphertext_owner("mfa-queue-top")
        .map_err(|_| "actual outermost ciphertext owner")?;
    assert_eq!(serde_json::to_value(&top_stamp)?, chain[1]);
    assert!(original.validate_format().is_ok());
    let original_bytes = crate::secret_serde::to_vec(&original, 16 * 1024 * 1024)
        .map_err(|_| "private original graph")?;
    for mode in [
        "middle-descriptor",
        "middle-key-epoch",
        "middle-frontier",
        "erase-chain-mac",
        "chain-mac",
    ] {
        let mut changed = value.clone();
        let registry = &mut changed["identity_mfa"];
        let epoch = registry["mutation_epoch"]
            .as_u64()
            .ok_or("actual registry epoch")?;
        registry["mutation_epoch"] = json!(epoch.checked_add(1).ok_or("epoch exhausted")?);
        let locator = &mut registry["janitor_custody"]["current"][ns];
        match mode {
            "middle-descriptor" => {
                let byte = locator["enclosures"][0]["descriptor"][0]
                    .as_u64()
                    .ok_or("original middle descriptor byte")?;
                locator["enclosures"][0]["descriptor"][0] = json!(byte ^ 1);
            }
            "middle-key-epoch" => {
                let value = locator["enclosures"][0]["key_epoch"]
                    .as_u64()
                    .ok_or("original epoch")?;
                locator["enclosures"][0]["key_epoch"] =
                    json!(value.checked_add(1).ok_or("epoch bound")?);
            }
            "middle-frontier" => {
                let value = locator["enclosures"][0]["seal_frontier"]
                    .as_u64()
                    .ok_or("original frontier")?;
                locator["enclosures"][0]["seal_frontier"] =
                    json!(value.checked_add(1).ok_or("frontier bound")?);
            }
            "erase-chain-mac" => {
                locator.as_object_mut().ok_or("locator")?.remove("mac");
            }
            "chain-mac" => {
                let byte = locator["mac"][0].as_u64().ok_or("actual chain MAC byte")?;
                locator["mac"][0] = json!(byte ^ 1);
            }
            _ => return Err("unknown fixed poison".into()),
        }
        assert_eq!(
            serde_json::to_value(&top_stamp)?,
            locator["enclosures"][1],
            "the final visible actual owner is preserved in every middle-chain attack"
        );
        let bytes = Zeroizing::new(serde_json::to_vec(&changed)?);
        let decoded = serde_json::from_slice::<crate::auth::AuthState>(&bytes);
        if mode == "erase-chain-mac" {
            assert!(
                decoded.is_err(),
                "the entire-chain authenticated reader field is mandatory"
            );
        } else {
            let mut torn = original.clone();
            torn.auth = decoded?.into();
            assert!(
                torn.auth
                    .validate_identity_mfa_state(Some(&original.auth))
                    .is_err()
            );
            assert!(torn.validate_format().is_err());
            assert!(torn.validate_publication_schema(Some(&original)).is_err());
            assert!(Service::validate_snapshot_protected_floor(&original, &torn).is_err());
            assert!(
                torn.sdk_namespace_ciphertext_owner("mfa-queue-top")
                    .map_err(|_| "unchanged actual visible descriptor")?
                    == top_stamp
            );
        }
    }
    assert!(
        crate::secret_serde::to_vec(&original, 16 * 1024 * 1024)
            .map_err(|_| "retained original encoding")?
            .as_slice()
            == original_bytes.as_slice()
    );
    fixture = closed_janitor_restore_root(fixture, 403)?;
    assert!(
        !fixture
            .service
            .state
            .as_ref()
            .ok_or("root only cold state")?
            .namespaces
            .contains(ns)
    );
    assert!(
        fixture
            .service
            .maintain_mfa_challenges_with_clock(janitor_clock(403)?)
            .map_err(|_| "original closed queue tick")?
    );
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-top/unseal",
            "",
            &fixture.admin,
            json!({"key":top_key.as_str()}),
            404
        )
        .status,
        200
    );
    let outer_key = fixture.outer_key.as_ref().ok_or("original middle key")?;
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-top/outer/unseal",
            "",
            &fixture.admin,
            json!({"key":outer_key.as_str()}),
            405
        )
        .status,
        200
    );
    assert_eq!(
        closed_janitor_call(
            &mut fixture.service,
            "POST",
            "sys/namespaces/mfa-queue-top/outer/child/unseal",
            "",
            &fixture.admin,
            json!({"key":fixture.namespace_key.as_str()}),
            406
        )
        .status,
        200
    );
    let restored = fixture
        .service
        .state
        .as_ref()
        .ok_or("actual nested restored private owner")?;
    assert!(restored.validate_format().is_ok());
    let auth = closed_janitor_auth(restored)?;
    assert_eq!(
        auth["identity_mfa"]["janitor_custody"]["applied"]
            .as_array()
            .ok_or("applied")?
            .len(),
        1
    );
    let consumed = auth["identity_mfa"]["janitor_custody"]["terminal"][0]["id"]
        .as_str()
        .ok_or("one actual terminal request")?
        .to_owned();
    assert!(
        auth["identity_mfa"]["namespaces"][ns]["challenges"]
            .get(&consumed)
            .is_none()
    );
    let tokens = token_count(&fixture.service)?;
    let denied = closed_janitor_call(
        &mut fixture.service,
        "POST",
        "sys/mfa/validate",
        ns,
        "",
        json!({"mfa_request_id":consumed}),
        407,
    );
    assert_eq!(denied.status, 400);
    assert!(denied.body.get("auth").is_none());
    assert_eq!(token_count(&fixture.service)?, tokens);
    Ok(())
}

// These controls use the actual native Service first factor, identity
// projection, unissued grant and encrypted durable owner. The independent
// compiled 2.7 observations require repeated validation across matching rules.
struct MultiMfaFixture {
    files: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    entity: String,
    methods: Vec<String>,
    secrets: Vec<Option<Zeroizing<Vec<u8>>>>,
}
fn multi_mfa_fixture(enroll_both: bool) -> Result<MultiMfaFixture, Box<dyn std::error::Error>> {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/mfa_userpass",
            &admin,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/mfa_userpass/users/alice",
            &admin,
            json!({"password":"public-synthetic-mfa-test","token_ttl":20,
                "token_max_ttl":20,"token_bound_cidrs":["127.0.0.0/8"]})
        )
        .status,
        204
    );
    let initial = precise_call(
        &mut service,
        "POST",
        "auth/mfa_userpass/login/alice",
        "",
        json!({"password":"public-synthetic-mfa-test"}),
        100,
        0,
    );
    assert_eq!(initial.status, 200);
    assert!(
        initial.body["auth"]["client_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    let entity = initial.body["auth"]["entity_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or("actual initial native entity")?
        .to_owned();
    let mut methods = Vec::new();
    for issuer in ["native-multi-one", "native-multi-two"] {
        let created = call(
            &mut service,
            "POST",
            "identity/mfa/method/totp",
            &admin,
            json!({"issuer":issuer,"qr_size":0,"period":10,"skew":0,
                "max_validation_attempts":20}),
        );
        assert_eq!(created.status, 200);
        methods.push(
            created.body["data"]["method_id"]
                .as_str()
                .ok_or("actual native multi method")?
                .to_owned(),
        );
    }
    methods.sort();
    assert_ne!(methods[0], methods[1]);
    let mut secrets = Vec::new();
    for (index, method) in methods.iter().enumerate() {
        if enroll_both || index == 1 {
            let generated = call(
                &mut service,
                "POST",
                "identity/mfa/method/totp/admin-generate",
                &admin,
                json!({"method_id":method,"entity_id":entity}),
            );
            assert_eq!(generated.status, 200);
            secrets.push(Some(enrollment_secret(&generated)?));
        } else {
            secrets.push(None);
        }
    }
    Ok(MultiMfaFixture {
        files,
        service,
        key: Zeroizing::new(key),
        admin: Zeroizing::new(admin),
        entity,
        methods,
        secrets,
    })
}
fn multi_mfa_rule(fixture: &mut MultiMfaFixture, name: &str, methods: Vec<String>) {
    assert_eq!(
        call(
            &mut fixture.service,
            "POST",
            &format!("identity/mfa/login-enforcement/{name}"),
            &fixture.admin,
            json!({"auth_method_types":["userpass"],"mfa_method_ids":methods})
        )
        .status,
        204
    );
}
fn multi_mfa_code(
    fixture: &MultiMfaFixture,
    index: usize,
    seconds: u64,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    Ok(Zeroizing::new(
        crate::engines::rfc6238_code(
            fixture.secrets[index]
                .as_ref()
                .ok_or("actual enrollment missing")?,
            "SHA1",
            6,
            seconds / 10,
        )
        .map_err(|_| "native multi TOTP")?,
    ))
}
fn multi_mfa_attempts(
    service: &Service,
    entity: &str,
    method: &str,
) -> Result<Option<(u64, Option<u64>)>, Box<dyn std::error::Error>> {
    let encoded = crate::secret_serde::to_vec(
        &service.state.as_ref().ok_or("actual multi state")?.auth,
        16 * 1024 * 1024,
    )
    .map_err(|_| "private multi state encoding")?;
    let state = heptabao_domain::json::decode(&encoded)?;
    let enrollment = &state["identity_mfa"]["namespaces"][""]["enrollments"][entity][method];
    if enrollment.is_null() {
        return Ok(None);
    }
    Ok(Some((
        enrollment["attempts"]
            .as_u64()
            .ok_or("actual multi attempt count")?,
        enrollment["last_accepted_counter"].as_u64(),
    )))
}
fn multi_mfa_validate(service: &mut Service, id: &str, payload: Value, seconds: u64) -> Response {
    precise_call(
        service,
        "POST",
        "sys/mfa/validate",
        "",
        json!({"mfa_request_id":id,"mfa_payload":payload}),
        seconds,
        125_000_000,
    )
}
fn multi_mfa_assert_no_bearer(response: &Response) {
    assert!(
        response.body["auth"]["client_token"]
            .as_str()
            .is_none_or(str::is_empty)
    );
}
fn multi_mfa_start(
    fixture: &mut MultiMfaFixture,
    seconds: u64,
    expected: &[(&str, Vec<String>)],
) -> Result<String, Box<dyn std::error::Error>> {
    let tokens = token_count(&fixture.service)?;
    let challenge = precise_call(
        &mut fixture.service,
        "POST",
        "auth/mfa_userpass/login/alice",
        "",
        json!({"password":"public-synthetic-mfa-test"}),
        seconds,
        125_000_000,
    );
    assert_eq!(challenge.status, 200);
    assert!(challenge.body["auth"]["client_token"].as_str() == Some(""));
    assert!(challenge.body["auth"]["accessor"].as_str() == Some(""));
    assert!(challenge.body["auth"]["entity_id"].as_str() == Some(""));
    assert_eq!(challenge.body["auth"]["lease_duration"], 0);
    assert_eq!(token_count(&fixture.service)?, tokens);
    let requirement = &challenge.body["auth"]["mfa_requirement"];
    let constraints = requirement["mfa_constraints"]
        .as_object()
        .ok_or("actual native multi constraints")?;
    assert_eq!(constraints.len(), expected.len());
    for (name, methods) in expected {
        let any = constraints[*name]["any"]
            .as_array()
            .ok_or("actual native any constraint")?;
        let actual = any
            .iter()
            .map(|method| {
                method["id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or("actual constraint method ID")
            })
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        assert!(
            actual
                == methods
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
        );
        assert!(
            any.iter()
                .all(|m| m["type"] == "totp" && m["uses_passcode"] == true)
        );
    }
    Ok(requirement["mfa_request_id"]
        .as_str()
        .ok_or("actual multi request ID")?
        .to_owned())
}

#[test]
fn mfa129_multiple_native_rules_consume_partial_success_and_keep_replay_after_encrypted_reopen()
-> TestResult {
    let mut f = multi_mfa_fixture(true)?;
    let a = f.methods[0].clone();
    let b = f.methods[1].clone();
    multi_mfa_rule(&mut f, "one", vec![a.clone()]);
    multi_mfa_rule(&mut f, "two", vec![b.clone()]);
    let tokens = token_count(&f.service)?;
    let id = multi_mfa_start(
        &mut f,
        100,
        &[("one", vec![a.clone()]), ("two", vec![b.clone()])],
    )?;
    let checkpoint = f.service.state.clone().ok_or("native multi checkpoint")?;
    let code_a = multi_mfa_code(&f, 0, 101)?;
    let code_b = multi_mfa_code(&f, 1, 101)?;
    let malformed = multi_mfa_validate(&mut f.service, &id, json!({a.clone():["invalid"]}), 101);
    assert_eq!(malformed.status, 403);
    multi_mfa_assert_no_bearer(&malformed);
    let before = crate::secret_serde::to_vec(&checkpoint, 16 * 1024 * 1024)
        .map_err(|_| "native multi checkpoint encoding")?;
    let after = crate::secret_serde::to_vec(
        f.service.state.as_ref().ok_or("native multi state")?,
        16 * 1024 * 1024,
    )
    .map_err(|_| "native multi state encoding")?;
    assert!(
        before.as_slice() == after.as_slice(),
        "all malformed/missing rule credentials leave counters and durable grant unchanged"
    );
    let missing_first = multi_mfa_validate(
        &mut f.service,
        &id,
        json!({b.clone():[code_b.as_str()]}),
        101,
    );
    assert_eq!(missing_first.status, 403);
    multi_mfa_assert_no_bearer(&missing_first);
    let after_missing_first = crate::secret_serde::to_vec(
        f.service
            .state
            .as_ref()
            .ok_or("native multi unchanged state")?,
        16 * 1024 * 1024,
    )
    .map_err(|_| "native multi unchanged encoding")?;
    assert!(
        before.as_slice() == after_missing_first.as_slice(),
        "the captured first missing rule fails without consuming a later valid code"
    );
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &b)?,
        Some((0, None))
    );
    let partial = multi_mfa_validate(
        &mut f.service,
        &id,
        json!({a.clone():[code_a.as_str()]}),
        101,
    );
    assert_eq!(partial.status, 403);
    multi_mfa_assert_no_bearer(&partial);
    assert_eq!(token_count(&f.service)?, tokens);
    assert_eq!(janitor_pending_count(&f.service)?, 1);
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &a)?,
        Some((1, Some(10)))
    );
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &b)?,
        Some((0, None))
    );
    let consumed = f
        .service
        .state
        .clone()
        .ok_or("actual consumed multi owner")?;
    assert!(Service::validate_snapshot_protected_floor(&consumed, &checkpoint).is_err());
    drop(f.service);
    f.service = f.files.service()?;
    assert_eq!(
        precise_call(
            &mut f.service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":f.key.as_str()}),
            102,
            0
        )
        .status,
        200
    );
    assert_eq!(janitor_pending_count(&f.service)?, 1);
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &a)?,
        Some((1, Some(10)))
    );
    let retry = multi_mfa_validate(
        &mut f.service,
        &id,
        json!({a.clone():[code_a.as_str()],b.clone():[code_b.as_str()]}),
        102,
    );
    assert_eq!(retry.status, 403);
    multi_mfa_assert_no_bearer(&retry);
    assert_eq!(token_count(&f.service)?, tokens);
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &a)?,
        Some((2, Some(10)))
    );
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &b)?,
        Some((0, None)),
        "after the captured first rule fails replay, the later rule is not evaluated"
    );
    let code_a = multi_mfa_code(&f, 0, 111)?;
    let code_b = multi_mfa_code(&f, 1, 111)?;
    let complete = multi_mfa_validate(
        &mut f.service,
        &id,
        json!({a.clone():[code_a.as_str()],b.clone():[code_b.as_str()]}),
        111,
    );
    assert_eq!(complete.status, 200);
    let bearer = Zeroizing::new(
        complete.body["auth"]["client_token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or("actual complete multi bearer")?
            .to_owned(),
    );
    assert!(complete.body["auth"]["entity_id"].as_str() == Some(f.entity.as_str()));
    assert_eq!(token_count(&f.service)?, tokens + 1);
    assert_eq!(janitor_pending_count(&f.service)?, 0);
    let lookup = precise_call(
        &mut f.service,
        "GET",
        "auth/token/lookup-self",
        &bearer,
        json!({}),
        111,
        250_000_000,
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["creation_time"], 111);
    assert_eq!(lookup.body["data"]["creation_ttl"], 20);
    let replay = multi_mfa_validate(
        &mut f.service,
        &id,
        json!({a.clone():[code_a.as_str()],b.clone():[code_b.as_str()]}),
        112,
    );
    assert_eq!(replay.status, 400);
    multi_mfa_assert_no_bearer(&replay);
    assert_eq!(token_count(&f.service)?, tokens + 1);
    Ok(())
}

#[test]
fn mfa129_fresh_distinct_native_rules_mint_once_only_after_all_requirements_and_keep_live_binding()
-> TestResult {
    let mut f = multi_mfa_fixture(true)?;
    let a = f.methods[0].clone();
    let b = f.methods[1].clone();
    multi_mfa_rule(&mut f, "one", vec![a.clone()]);
    multi_mfa_rule(&mut f, "two", vec![b.clone()]);
    let tokens = token_count(&f.service)?;
    let id = multi_mfa_start(
        &mut f,
        100,
        &[("one", vec![a.clone()]), ("two", vec![b.clone()])],
    )?;
    let code_a = multi_mfa_code(&f, 0, 101)?;
    let code_b = multi_mfa_code(&f, 1, 101)?;
    let complete = multi_mfa_validate(
        &mut f.service,
        &id,
        json!({a.clone():[code_a.as_str()],b.clone():[code_b.as_str()]}),
        101,
    );
    assert_eq!(complete.status, 200);
    assert!(
        complete.body["auth"]["client_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    assert!(complete.body["auth"]["entity_id"].as_str() == Some(f.entity.as_str()));
    assert_eq!(token_count(&f.service)?, tokens + 1);
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &a)?,
        Some((1, Some(10)))
    );
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &b)?,
        Some((1, Some(10)))
    );
    let stale = multi_mfa_start(
        &mut f,
        102,
        &[("one", vec![a.clone()]), ("two", vec![b.clone()])],
    )?;
    assert_eq!(
        precise_call(
            &mut f.service,
            "DELETE",
            "identity/mfa/login-enforcement/two",
            &f.admin,
            json!({}),
            103,
            0
        )
        .status,
        204
    );
    let denied = multi_mfa_validate(
        &mut f.service,
        &stale,
        json!({a.clone():[code_a.as_str()],b.clone():[code_b.as_str()]}),
        103,
    );
    assert_eq!(denied.status, 400);
    multi_mfa_assert_no_bearer(&denied);
    assert_eq!(token_count(&f.service)?, tokens + 1);
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("native terminal schema")?
            .schema,
        USERPASS_ISSUANCE_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn mfa129_repeated_method_across_matching_native_rules_is_not_deduplicated_into_a_bearer()
-> TestResult {
    let mut f = multi_mfa_fixture(true)?;
    let a = f.methods[0].clone();
    multi_mfa_rule(&mut f, "duplicate-one", vec![a.clone()]);
    multi_mfa_rule(&mut f, "duplicate-two", vec![a.clone()]);
    let tokens = token_count(&f.service)?;
    let id = multi_mfa_start(
        &mut f,
        100,
        &[
            ("duplicate-one", vec![a.clone()]),
            ("duplicate-two", vec![a.clone()]),
        ],
    )?;
    let code = multi_mfa_code(&f, 0, 101)?;
    let denied = multi_mfa_validate(&mut f.service, &id, json!({a.clone():[code.as_str()]}), 101);
    assert_eq!(denied.status, 403);
    multi_mfa_assert_no_bearer(&denied);
    assert_eq!(token_count(&f.service)?, tokens);
    assert_eq!(janitor_pending_count(&f.service)?, 1);
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &a)?,
        Some((2, Some(10)))
    );
    drop(f.service);
    f.service = f.files.service()?;
    assert_eq!(
        precise_call(
            &mut f.service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":f.key.as_str()}),
            102,
            0
        )
        .status,
        200
    );
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &a)?,
        Some((2, Some(10)))
    );
    // The first numeric attempt is captured after the original precise
    // request's work, at 101 + nanoseconds. 111 whole seconds is still inside
    // that fixed ten-second window. 112 is past it and remains OTP counter 11.
    let next_counter = multi_mfa_code(&f, 0, 112)?;
    let denied = multi_mfa_validate(
        &mut f.service,
        &id,
        json!({a.clone():[next_counter.as_str()]}),
        112,
    );
    assert_eq!(denied.status, 403);
    multi_mfa_assert_no_bearer(&denied);
    assert_eq!(token_count(&f.service)?, tokens);
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &a)?,
        Some((2, Some(11)))
    );
    Ok(())
}

#[test]
fn mfa129_any_rule_skips_unenrolled_first_candidate_and_accepts_actual_later_native_enrollment()
-> TestResult {
    let mut f = multi_mfa_fixture(false)?;
    let missing = f.methods[0].clone();
    let enrolled = f.methods[1].clone();
    assert!(
        missing < enrolled,
        "unavailable candidate is actually iterated first"
    );
    assert_eq!(multi_mfa_attempts(&f.service, &f.entity, &missing)?, None);
    multi_mfa_rule(&mut f, "any-one", vec![missing.clone(), enrolled.clone()]);
    let tokens = token_count(&f.service)?;
    let id = multi_mfa_start(
        &mut f,
        100,
        &[("any-one", vec![missing.clone(), enrolled.clone()])],
    )?;
    let code = multi_mfa_code(&f, 1, 101)?;
    let complete = multi_mfa_validate(
        &mut f.service,
        &id,
        json!({missing.clone():["000000"],enrolled.clone():[code.as_str()]}),
        101,
    );
    assert_eq!(complete.status, 200);
    assert!(
        complete.body["auth"]["client_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    assert!(complete.body["auth"]["entity_id"].as_str() == Some(f.entity.as_str()));
    assert_eq!(token_count(&f.service)?, tokens + 1);
    assert_eq!(multi_mfa_attempts(&f.service, &f.entity, &missing)?, None);
    assert_eq!(
        multi_mfa_attempts(&f.service, &f.entity, &enrolled)?,
        Some((1, Some(10)))
    );
    assert_eq!(janitor_pending_count(&f.service)?, 0);
    Ok(())
}

fn named_mfa_method(fixture: &mut MultiMfaFixture, method: &str, name: &str) {
    assert_eq!(
        call(
            &mut fixture.service,
            "POST",
            &format!("identity/mfa/method/totp/{method}"),
            &fixture.admin,
            json!({"method_name":name})
        )
        .status,
        204
    );
    let read = call(
        &mut fixture.service,
        "GET",
        &format!("identity/mfa/method/{method}"),
        &fixture.admin,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["name"], name);
}

#[test]
fn mfa129_two_phase_uuid_and_root_method_names_accept_bare_and_passcode_arrays_once()
-> Result<(), Box<dyn std::error::Error>> {
    for use_name in [false, true] {
        for prefix in [false, true] {
            let mut fixture = multi_mfa_fixture(true)?;
            let method = fixture.methods[0].clone();
            named_mfa_method(&mut fixture, &method, "named-native-method");
            multi_mfa_rule(&mut fixture, "named-rule", vec![method.clone()]);
            let id = multi_mfa_start(&mut fixture, 100, &[("named-rule", vec![method.clone()])])?;
            let tokens = token_count(&fixture.service)?;
            let code = multi_mfa_code(&fixture, 0, 101)?;
            let value = Zeroizing::new(if prefix {
                format!("passcode={}", code.as_str())
            } else {
                code.as_str().to_owned()
            });
            let key = if use_name {
                "named-native-method"
            } else {
                &method
            };
            let mut payload = serde_json::Map::new();
            payload.insert(key.to_owned(), json!([value.as_str()]));
            let issued = multi_mfa_validate(&mut fixture.service, &id, Value::Object(payload), 101);
            assert_eq!(issued.status, 200);
            assert_eq!(issued.body["auth"]["entity_id"], fixture.entity);
            assert!(
                issued.body["auth"]["client_token"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty())
            );
            assert!(issued.body["auth"]["mfa_requirement"].is_null());
            assert_eq!(token_count(&fixture.service)?, tokens + 1);
            assert_eq!(
                multi_mfa_attempts(&fixture.service, &fixture.entity, &method)?,
                Some((1, Some(10)))
            );
            let replay = multi_mfa_validate(
                &mut fixture.service,
                &id,
                json!({method.clone():[value.as_str()]}),
                101,
            );
            assert_eq!(replay.status, 400);
            multi_mfa_assert_no_bearer(&replay);
            assert_eq!(token_count(&fixture.service)?, tokens + 1);
        }
    }
    Ok(())
}

#[test]
fn mfa129_scalar_method_payload_is_400_without_attempt_or_durable_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = multi_mfa_fixture(true)?;
    let method = fixture.methods[0].clone();
    named_mfa_method(&mut fixture, &method, "scalar-contract");
    multi_mfa_rule(&mut fixture, "scalar-rule", vec![method.clone()]);
    let id = multi_mfa_start(&mut fixture, 100, &[("scalar-rule", vec![method.clone()])])?;
    let before = crate::secret_serde::to_vec(
        fixture.service.state.as_ref().ok_or("state")?,
        32 * 1024 * 1024,
    )
    .map_err(|_| "private scalar snapshot")?;
    let code = multi_mfa_code(&fixture, 0, 101)?;
    for key in [method.as_str(), "scalar-contract"] {
        let mut payload = serde_json::Map::new();
        payload.insert(key.to_owned(), json!(code.as_str()));
        let denied = multi_mfa_validate(&mut fixture.service, &id, Value::Object(payload), 101);
        assert_eq!(denied.status, 400);
        multi_mfa_assert_no_bearer(&denied);
        assert_eq!(
            before,
            crate::secret_serde::to_vec(
                fixture.service.state.as_ref().ok_or("state")?,
                32 * 1024 * 1024
            )
            .map_err(|_| "private scalar snapshot")?
        );
        assert_eq!(
            multi_mfa_attempts(&fixture.service, &fixture.entity, &method)?,
            Some((0, None))
        );
    }
    let issued = multi_mfa_validate(
        &mut fixture.service,
        &id,
        json!({"scalar-contract":[format!("passcode={}",code.as_str())]}),
        101,
    );
    assert_eq!(issued.status, 200);
    assert_eq!(
        multi_mfa_attempts(&fixture.service, &fixture.entity, &method)?,
        Some((1, Some(10)))
    );
    Ok(())
}

fn mfa_namespace_precise_call(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
    seconds: u64,
) -> Response {
    let clock = RequestClock::anchored(Duration::new(seconds, 125_000_000), Instant::now())
        .expect("synthetic captured namespace MFA clock");
    service.handle_request_clock(
        ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: Some("127.0.0.1".parse().expect("synthetic peer")),
            client_certificates: None,
        },
        seconds,
        true,
        Some(clock),
    )
}

#[test]
fn mfa129_qualified_child_method_names_and_colliding_rule_keys_keep_both_native_requirements()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = multi_mfa_fixture(true)?;
    let parent = fixture.methods[0].clone();
    named_mfa_method(&mut fixture, &parent, "root-named-method");
    let namespace = "mfa-name-child";
    assert_eq!(
        precise_call(
            &mut fixture.service,
            "POST",
            &format!("sys/namespaces/{namespace}"),
            &fixture.admin,
            json!({}),
            100,
            125_000_000
        )
        .status,
        200
    );
    assert_eq!(
        mfa_namespace_precise_call(
            &mut fixture.service,
            "POST",
            "sys/auth/native",
            namespace,
            &fixture.admin,
            json!({"type":"userpass"}),
            100
        )
        .status,
        204
    );
    assert_eq!(
        mfa_namespace_precise_call(
            &mut fixture.service,
            "POST",
            "auth/native/users/alice",
            namespace,
            &fixture.admin,
            json!({"password":"public-synthetic-child-mfa",
            "token_ttl":20,"token_max_ttl":20,"token_bound_cidrs":["127.0.0.0/8"]}),
            100
        )
        .status,
        204
    );
    let initial = mfa_namespace_precise_call(
        &mut fixture.service,
        "POST",
        "auth/native/login/alice",
        namespace,
        "",
        json!({"password":"public-synthetic-child-mfa"}),
        100,
    );
    assert_eq!(initial.status, 200);
    let entity = initial.body["auth"]["entity_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("actual child entity")?
        .to_owned();
    let created = mfa_namespace_precise_call(
        &mut fixture.service,
        "POST",
        "identity/mfa/method/totp",
        namespace,
        &fixture.admin,
        json!({"issuer":"native-child","method_name":"child-method",
            "qr_size":0,"period":10,"skew":0,"max_validation_attempts":20}),
        100,
    );
    assert_eq!(created.status, 200);
    let child = created.body["data"]["method_id"]
        .as_str()
        .ok_or("child method")?
        .to_owned();
    let mut secrets = Vec::new();
    for method in [&parent, &child] {
        let generated = mfa_namespace_precise_call(
            &mut fixture.service,
            "POST",
            "identity/mfa/method/totp/admin-generate",
            namespace,
            &fixture.admin,
            json!({"method_id":method,"entity_id":entity}),
            100,
        );
        assert_eq!(generated.status, 200);
        secrets.push(enrollment_secret(&generated)?);
    }
    multi_mfa_rule(&mut fixture, "same-rule-name", vec![parent.clone()]);
    assert_eq!(
        mfa_namespace_precise_call(
            &mut fixture.service,
            "POST",
            "identity/mfa/login-enforcement/same-rule-name",
            namespace,
            &fixture.admin,
            json!({"auth_method_types":["userpass"],"mfa_method_ids":[child.clone()]}),
            100
        )
        .status,
        204
    );
    let start = mfa_namespace_precise_call(
        &mut fixture.service,
        "POST",
        "auth/native/login/alice",
        namespace,
        "",
        json!({"password":"public-synthetic-child-mfa"}),
        100,
    );
    assert_eq!(start.status, 200);
    multi_mfa_assert_no_bearer(&start);
    let constraints = start.body["auth"]["mfa_requirement"]["mfa_constraints"]
        .as_object()
        .ok_or("actual child constraints")?;
    assert_eq!(constraints.len(), 1);
    assert!(constraints.contains_key("same-rule-name"));
    let selected = constraints["same-rule-name"]["any"][0]["id"]
        .as_str()
        .ok_or("actual exposed colliding method")?
        .to_owned();
    assert!(selected == parent || selected == child);
    let id = start.body["auth"]["mfa_requirement"]["mfa_request_id"]
        .as_str()
        .ok_or("actual child request")?
        .to_owned();
    let code =
        |index: usize, seconds: u64| -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
            Ok(Zeroizing::new(
                crate::engines::rfc6238_code(&secrets[index], "SHA1", 6, seconds / 10)
                    .map_err(|_| "native child TOTP")?,
            ))
        };
    let parent_code = code(0, 101)?;
    let child_code = code(1, 101)?;
    let before = crate::secret_serde::to_vec(
        fixture.service.state.as_ref().ok_or("state")?,
        32 * 1024 * 1024,
    )
    .map_err(|_| "private child snapshot")?;
    let bare = mfa_namespace_precise_call(
        &mut fixture.service,
        "POST",
        "sys/mfa/validate",
        namespace,
        "",
        json!({"mfa_request_id":id,"mfa_payload":{
            "root-named-method":[parent_code.as_str()],"child-method":[child_code.as_str()]}}),
        101,
    );
    assert_eq!(bare.status, 403);
    multi_mfa_assert_no_bearer(&bare);
    assert_eq!(
        before,
        crate::secret_serde::to_vec(
            fixture.service.state.as_ref().ok_or("state")?,
            32 * 1024 * 1024
        )
        .map_err(|_| "private child snapshot")?
    );
    let exposed = if selected == parent {
        parent_code.as_str()
    } else {
        child_code.as_str()
    };
    let hidden = mfa_namespace_precise_call(
        &mut fixture.service,
        "POST",
        "sys/mfa/validate",
        namespace,
        "",
        json!({"mfa_request_id":id,"mfa_payload":{selected:[exposed]}}),
        101,
    );
    assert_eq!(hidden.status, 403);
    multi_mfa_assert_no_bearer(&hidden);
    let next = mfa_namespace_precise_call(
        &mut fixture.service,
        "POST",
        "auth/native/login/alice",
        namespace,
        "",
        json!({"password":"public-synthetic-child-mfa"}),
        110,
    );
    assert_eq!(next.status, 200);
    multi_mfa_assert_no_bearer(&next);
    let id = next.body["auth"]["mfa_requirement"]["mfa_request_id"]
        .as_str()
        .ok_or("next actual child challenge")?;
    let parent_code = code(0, 111)?;
    let child_code = code(1, 111)?;
    let tokens = token_count(&fixture.service)?;
    let issued = mfa_namespace_precise_call(
        &mut fixture.service,
        "POST",
        "sys/mfa/validate",
        namespace,
        "",
        json!({"mfa_request_id":id,"mfa_payload":{
            "root-named-method":[format!("passcode={}",parent_code.as_str())],
            "mfa-name-child/child-method":[format!("passcode={}",child_code.as_str())]}}),
        111,
    );
    assert_eq!(issued.status, 200);
    assert_eq!(issued.body["auth"]["entity_id"], entity);
    assert!(
        issued.body["auth"]["client_token"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert_eq!(token_count(&fixture.service)?, tokens + 1);
    drop(fixture.service);
    fixture.service = fixture.files.service()?;
    assert_eq!(
        mfa_namespace_precise_call(
            &mut fixture.service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":fixture.key.as_str()}),
            111
        )
        .status,
        200
    );
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("child bearer")?;
    let lookup = mfa_namespace_precise_call(
        &mut fixture.service,
        "GET",
        "auth/token/lookup-self",
        namespace,
        token,
        json!({}),
        112,
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["entity_id"], entity);
    Ok(())
}


#[test]
fn userpass132_real_native_login_renew_reopen_and_retirement_keep_initial_ttl_and_reader_floor() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let ordinary = service.state.clone().ok_or("ordinary native state")?;
    assert!(!ordinary.auth.has_userpass_issuance_state());
    assert_eq!(call(&mut service, "POST", "sys/auth/initial_ttl", &admin,
        json!({"type":"userpass"})).status, 204);
    assert_eq!(call(&mut service, "POST", "auth/initial_ttl/users/alice", &admin,
        json!({"password":"public-synthetic-initial-ttl","token_ttl":20,"token_max_ttl":20})).status, 204);
    let login = call(&mut service, "POST", "auth/initial_ttl/login/alice", "",
        json!({"password":"public-synthetic-initial-ttl"}));
    assert_eq!(login.status, 200);
    assert_eq!(login.body["auth"]["lease_duration"], 20);
    let bearer = Zeroizing::new(login.body["auth"]["client_token"].as_str()
        .filter(|s| !s.is_empty()).ok_or("real native bearer")?.to_owned());
    let issued = service.state.clone().ok_or("issued native state")?;
    assert_eq!(issued.schema, USERPASS_ISSUANCE_STATE_SCHEMA);
    assert!(issued.auth.has_userpass_issuance_state());
    assert!(!issued.auth.has_identity_mfa_state(), "ordinary issuer is not an MFA issuer");
    let lookup = precise_call(&mut service, "GET", "auth/token/lookup-self", &bearer, json!({}), 100, 0);
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["creation_ttl"], 20);
    let renewal = precise_call(&mut service, "POST", "auth/token/renew-self", &bearer,
        json!({"increment":5}), 101, 0);
    assert_eq!(renewal.status, 200);
    assert_eq!(renewal.body["auth"]["lease_duration"], 5);
    assert_eq!(precise_call(&mut service, "POST", "auth/initial_ttl/users/alice", &admin,
        json!({"token_ttl":10}), 102, 0).status, 204);
    let renewal = precise_call(&mut service, "POST", "auth/token/renew-self", &bearer,
        json!({"increment":5}), 103, 0);
    assert_eq!(renewal.status, 200);
    assert_eq!(renewal.body["auth"]["lease_duration"], 5);
    let lookup = precise_call(&mut service, "GET", "auth/token/lookup-self", &bearer, json!({}), 103, 0);
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["creation_ttl"], 20);
    drop(service);
    let mut reopened = files.service()?;
    assert_eq!(precise_call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key}), 104, 0).status, 200);
    let lookup = precise_call(&mut reopened, "GET", "auth/token/lookup-self", &bearer, json!({}), 104, 0);
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["creation_ttl"], 20);
    let current = reopened.state.clone().ok_or("encrypted reopened native owner")?;
    current.validate_format().map_err(|_| "native132 format")?;
    let auth_bytes = Zeroizing::new(serde_json::to_vec(&*current.auth)?);
    let auth: Value = serde_json::from_slice(&auth_bytes)?;
    let token_id = auth["tokens"].as_object().ok_or("native token map")?.iter()
        .find(|(_, value)| value["auth_provenance"]["kind"] == "userpass")
        .map(|(id, _)| id.clone()).ok_or("native Userpass stored issuer")?;
    for mutation in ["floor", "grant", "both"] {
        let mut altered = auth.clone();
        if mutation != "grant" { altered.as_object_mut().ok_or("auth owner")?.remove("userpass_issuance_floor"); }
        if mutation != "floor" { altered["tokens"][&token_id]["auth_provenance"].as_object_mut()
            .ok_or("actual Userpass provenance")?.remove("issued_creation_ttl"); }
        let bytes = Zeroizing::new(serde_json::to_vec(&altered)?);
        let mut torn = current.clone();
        torn.auth = serde_json::from_slice(&bytes)?;
        assert!(torn.validate_publication_schema(Some(&current)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&current, &torn).is_err());
        if mutation == "floor" || mutation == "both" { assert!(torn.validate_format().is_err()); }
    }
    let mut lower = current.clone();
    lower.schema = 131;
    assert!(lower.validate_format().is_err());
    assert!(lower.validate_publication_schema(Some(&current)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&current, &lower).is_err());
    assert_eq!(precise_call(&mut reopened, "POST", "auth/token/revoke-self", &bearer, json!({}), 104, 0).status, 204);
    let retired = reopened.state.clone().ok_or("retired native issuer")?;
    assert_eq!(retired.schema, USERPASS_ISSUANCE_STATE_SCHEMA);
    assert!(retired.auth.has_userpass_issuance_state());
    assert!(Service::validate_snapshot_protected_floor(&retired, &ordinary).is_err());
    let bytes = Zeroizing::new(serde_json::to_vec(&*retired.auth)?);
    let mut altered: Value = serde_json::from_slice(&bytes)?;
    altered.as_object_mut().ok_or("retired auth owner")?.remove("userpass_issuance_floor");
    let bytes = Zeroizing::new(serde_json::to_vec(&altered)?);
    let mut erased = retired.clone();
    erased.auth = serde_json::from_slice(&bytes)?;
    assert!(erased.validate_format().is_err());
    assert!(erased.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &erased).is_err());
    Ok(())
}

#[test]
fn userpass132_real_resigned_mfa_unissued_grant_cannot_claim_a_captured_initial_ttl() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(call(&mut service, "POST", "sys/auth/mfa_userpass", &admin,
        json!({"type":"userpass"})).status, 204);
    assert_eq!(call(&mut service, "POST", "auth/mfa_userpass/users/alice", &admin,
        json!({"password":"public-synthetic-mfa-test","token_ttl":20,"token_max_ttl":20})).status, 204);
    let created = call(&mut service, "POST", "identity/mfa/method/totp", &admin,
        json!({"issuer":"public-unissued-shape","qr_size":0}));
    assert_eq!(created.status, 200);
    let method = created.body["data"]["method_id"].as_str()
        .ok_or("real native method")?.to_owned();
    assert_eq!(call(&mut service, "POST", "identity/mfa/login-enforcement/unissued", &admin,
        json!({"auth_method_types":["userpass"],"mfa_method_ids":[method]})).status, 204);
    let before_tokens = token_count(&service)?;
    let request = mfa_challenge(&mut service, 100, 0)?;
    assert_eq!(token_count(&service)?, before_tokens, "genuine first factor mints no bearer");
    let original = service.state.clone().ok_or("actual native pending challenge")?;
    assert_eq!(original.schema, IDENTITY_MFA_STATE_SCHEMA);
    assert!(!original.auth.has_userpass_issuance_state());
    original.validate_format().map_err(|_| "actual unissued reader")?;
    let before = Zeroizing::new(crate::secret_serde::to_vec(&original, 16 * 1024 * 1024)
        .map_err(|_| "original pending encoding")?);
    let mut impossible = original.clone();
    impossible.auth.test_resign_mfa_pending_grant_with_claimed_ttl("", &request, 20)?;
    assert!(!impossible.auth.has_userpass_issuance_state(),
        "an impossible pending fact cannot mint a token or latch final floor132");
    let rejected = impossible.auth.validate_identity_mfa_state(None)
        .err().ok_or("strict pending shape must reject a genuinely resigned claim")?;
    assert_eq!(rejected.status, 503);
    assert_eq!(rejected.message, "MFA private grant has no native unissued userpass owner");
    assert!(impossible.validate_format().is_err());
    assert!(impossible.validate_publication_schema(Some(&original)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&original, &impossible).is_err());
    assert_eq!(token_count(&service)?, before_tokens);
    let after = Zeroizing::new(crate::secret_serde::to_vec(service.state.as_ref().ok_or("same native state")?,
        16 * 1024 * 1024).map_err(|_| "same pending encoding")?);
    assert_eq!(before.as_slice(), after.as_slice(), "counterexample never enters the genuine owner");
    Ok(())
}
