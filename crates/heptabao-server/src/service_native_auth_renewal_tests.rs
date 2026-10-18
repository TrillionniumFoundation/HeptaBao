//! An already committed renewal cannot extend its original delivery authority.
//! These cases retain the real V6 publication and mandatory audit boundary.
use super::*;

fn original_expiry_withholds_committed_renewal(path: &str) -> TestResult {
    let (files, mut service, key, admin) = activated()?;
    let mut issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        // Token API uses explicit_max_ttl for its lifetime ceiling. The
        // initial two-second grant must be extendable by the real renewal.
        json!({"policies":["default"],"ttl":"2s","explicit_max_ttl":"120s"}),
    );
    assert_eq!(issued.status, 200);
    let accessor = Zeroizing::new(
        issued.body["auth"]["accessor"]
            .as_str()
            .ok_or("missing synthetic token accessor")?
            .to_owned(),
    );
    let token = secret_field(&mut issued, "/auth/client_token")?;
    let body = match path {
        "auth/token/renew-self" => json!({"increment":"60s"}),
        "auth/token/renew" => json!({"token":token.as_str(),"increment":"60s"}),
        "auth/token/renew-accessor" => {
            json!({"accessor":accessor.as_str(),"increment":"60s"})
        }
        _ => return Err("unexpected synthetic renewal route".into()),
    };
    let actor = if path == "auth/token/renew-self" {
        token.as_str()
    } else {
        admin.as_str()
    };
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let started = Instant::now();
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
    let scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let response = service.handle_inner(RequestView {
        method: "POST",
        path,
        namespace: "",
        token: actor,
        body: &body,
        now: clock.admitted_at().seconds(),
        admission_started: started,
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    assert_eq!(response.status, 200);
    assert!(
        response.body["auth"]["lease_duration"]
            .as_u64()
            .is_some_and(|ttl| ttl > 2)
    );
    assert!(service.durable.as_ref().ok_or("durable")?.generation() > generation);
    assert!(service.pending_native_auth_delivery.is_some());

    // The audit succeeds while the original request remains within its
    // deadline. Only the pre-renewal token lifetime expires here.
    let response = service.audit_completed_response_with_receipt(
        "native-renewal-original-expiry",
        clock.admitted_at().seconds(),
        Some(clock),
        response,
        || std::thread::sleep(Duration::from_millis(2100)),
    );
    assert_eq!(response.status, 200);
    let response =
        service.complete_native_auth_delivery(true, response, "native-renewal-original-expiry");
    assert!(response.status >= 300);
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("auth").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
    assert!(service.pending_native_auth_delivery.is_none());
    assert!(!service.recovery_required);
    assert!(!service.audit_failed);
    drop(scope);

    // Delivery rejection cannot undo a successfully fsynced renewal or fence
    // the writer. A new, independently admitted request owns the new lifetime.
    let mut lookup = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    assert_eq!(lookup.status, 200);
    assert!(
        lookup.body["data"]["ttl"]
            .as_u64()
            .is_some_and(|ttl| ttl > 2)
    );
    let echoed = secret_field(&mut lookup, "/data/id")?;
    assert!(echoed.as_str() == token.as_str());
    drop(service);

    let mut service = reopened(&files, &key)?;
    let mut lookup = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    assert_eq!(lookup.status, 200);
    assert!(
        lookup.body["data"]["ttl"]
            .as_u64()
            .is_some_and(|ttl| ttl > 2)
    );
    let echoed = secret_field(&mut lookup, "/data/id")?;
    assert!(echoed.as_str() == token.as_str());
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn native_renew_self_original_expiry_survives_real_audit() -> TestResult {
    original_expiry_withholds_committed_renewal("auth/token/renew-self")
}

#[test]
fn native_renew_target_original_expiry_survives_real_audit() -> TestResult {
    original_expiry_withholds_committed_renewal("auth/token/renew")
}

#[test]
fn native_renew_accessor_original_expiry_survives_real_audit() -> TestResult {
    original_expiry_withholds_committed_renewal("auth/token/renew-accessor")
}

#[test]
fn native_approle_identity_keeps_finite_uses_through_delivery_and_cold_reopen() -> TestResult {
    let (files, mut service, key, admin) = activated()?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/native-authbus",
            &admin,
            json!({"policy":SELF_ONLY_POLICY}),
        )
        .status,
        204,
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("sys/auth/{MOUNT}"),
            &admin,
            json!({"type":"approle"}),
        )
        .status,
        204,
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            ROLE,
            &admin,
            json!({
                "token_policies":["native-authbus"],
                "token_ttl":"10m",
                "token_max_ttl":"20m",
                "token_num_uses":2,
                "secret_id_ttl":"10m",
                "secret_id_num_uses":1,
            }),
        )
        .status,
        204,
    );
    let mut role = call(
        &mut service,
        "GET",
        &format!("{ROLE}/role-id"),
        &admin,
        json!({}),
    );
    assert_eq!(role.status, 200);
    let role_id = secret_field(&mut role, "/data/role_id")?;
    let secret_id = issue_secret_id(&mut service, &admin)?;
    let (token, entity) = login(&mut service, &role_id, &secret_id)?;

    // The fresh token's delivery viability check must consume no real use.
    let mut first = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    assert_eq!(first.status, 200);
    assert_eq!(first.body["data"]["num_uses"], 1);
    assert!(first.body["data"]["entity_id"].as_str() == Some(entity.as_str()));
    let echoed = secret_field(&mut first, "/data/id")?;
    assert!(echoed.as_str() == token.as_str());
    drop(service);

    // The original affine principal may finish its last admitted lookup after
    // audit. Neither identity binding nor late revalidation authenticates anew.
    let mut service = reopened(&files, &key)?;
    let mut last = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    assert_eq!(last.status, 200);
    assert_eq!(last.body["data"]["num_uses"], 0);
    assert!(last.body["data"]["entity_id"].as_str() == Some(entity.as_str()));
    let echoed = secret_field(&mut last, "/data/id")?;
    assert!(echoed.as_str() == token.as_str());
    let denied = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    assert_eq!(denied.status, 403);
    assert!(denied.body.get("data").is_none());
    assert!(denied.body.get("auth").is_none());
    assert_consumed(&mut service, &role_id, &secret_id);
    drop(service);

    let mut service = reopened(&files, &key)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({}),
        )
        .status,
        403,
    );
    assert_consumed(&mut service, &role_id, &secret_id);
    assert!(!service.recovery_required);
    Ok(())
}
