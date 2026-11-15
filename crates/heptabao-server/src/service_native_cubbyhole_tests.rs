//! Formal native_v6_file profile, actual Shamir and typed root publication.
//! No fixture candidate selector, provider, production path or real credential.
use super::*;
use crate::configuration::NativeStorageProfile;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ACTIVATE: &str = "sys/storage/native-v6/activate";

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, "", token, body)
}

fn initialize() -> TestResult<(
    super::super::tests::Root,
    Service,
    Zeroizing<String>,
    Zeroizing<String>,
)> {
    let files = super::super::tests::Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let mut initialized = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(initialized.status, 200);
    let key = Zeroizing::new(
        initialized.body["keys"][0]
            .as_str()
            .ok_or("owned Shamir share")?
            .to_owned(),
    );
    let admin = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("owned root token")?
            .to_owned(),
    );
    erase_json(&mut initialized.body);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", &admin, json!({})).status,
        204
    );
    assert_eq!(
        service.native_storage_profile,
        Some(NativeStorageProfile::File)
    );
    // Ordinary native_v6_file startup captures this internal file-custody
    // owner too; its name does not imply use of the fixture-only selector.
    service
        .native_candidate_profile
        .as_ref()
        .ok_or("formal native file custody owner is absent")?
        .check_environment(&service)
        .map_err(|_| "formal native file custody owner is mismatched")?;
    Ok((files, service, key, admin))
}

fn reopen(files: &super::super::tests::Root, key: &str) -> TestResult<Service> {
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(service.native_root.is_some());
    assert!(service.record_root.is_none());
    assert_eq!(
        service.native_storage_profile,
        Some(NativeStorageProfile::File)
    );
    service
        .native_candidate_profile
        .as_ref()
        .ok_or("cold formal native file custody owner is absent")?
        .check_environment(&service)
        .map_err(|_| "cold formal native file custody owner is mismatched")?;
    Ok(service)
}

fn token(service: &mut Service, admin: &str, uses: u64) -> TestResult<Zeroizing<String>> {
    let mut issued = call(
        service,
        "POST",
        "auth/token/create",
        admin,
        json!({"policies":["default"],"ttl":"1h","num_uses":uses}),
    );
    assert_eq!(issued.status, 200);
    let token = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("owned service token")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    Ok(token)
}

#[test]
fn formal_native_cubbyhole_migrates_isolates_and_cold_recovers() -> TestResult {
    let (files, mut service, key, admin) = initialize()?;
    let a = token(&mut service, &admin, 0)?;
    let b = token(&mut service, &admin, 0)?;
    for (owner, value) in [(&a, "token-a"), (&admin, "root-own-value")] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "cubbyhole/item",
                owner,
                json!({"value":value})
            )
            .status,
            204
        );
    }
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    for after_cold in [false, true] {
        if after_cold {
            drop(service);
            service = reopen(&files, &key)?;
        }
        for (owner, value) in [(&a, "token-a"), (&admin, "root-own-value")] {
            let mut response = call(&mut service, "GET", "cubbyhole/item", owner, json!({}));
            assert_eq!(response.status, 200);
            assert_eq!(response.body["data"]["value"], value);
            erase_json(&mut response.body);
        }
        assert_eq!(
            call(&mut service, "GET", "cubbyhole/item", &b, json!({})).status,
            404
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "cubbyhole/item",
            &a,
            json!({"value":"latest"})
        )
        .status,
        204
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    let mut response = call(&mut service, "GET", "cubbyhole/item", &a, json!({}));
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["value"], "latest");
    erase_json(&mut response.body);
    assert_eq!(
        call(&mut service, "DELETE", "cubbyhole/item", &a, json!({})).status,
        204
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(
        call(&mut service, "GET", "cubbyhole/item", &a, json!({})).status,
        404
    );
    Ok(())
}

#[test]
fn formal_native_cubbyhole_final_read_is_affine_and_cold_stays_consumed() -> TestResult {
    let (files, mut service, key, admin) = initialize()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    let limited = token(&mut service, &admin, 2)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "cubbyhole/item",
            &limited,
            json!({"private":"last-use"})
        )
        .status,
        204
    );
    let mut response = call(&mut service, "GET", "cubbyhole/item", &limited, json!({}));
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["private"], "last-use");
    erase_json(&mut response.body);
    assert_eq!(
        call(&mut service, "GET", "cubbyhole/item", &limited, json!({})).status,
        403
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(
        call(&mut service, "GET", "cubbyhole/item", &limited, json!({})).status,
        403
    );
    let bytes = owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.auth)?;
    let auth: Value = serde_json::from_slice(&bytes)?;
    assert!(
        auth["tokens"]
            .as_object()
            .ok_or("token owner")?
            .values()
            .any(|token| {
                token["uses_remaining"] == 0 && token["cubbyhole"]["namespaces"] == json!({})
            })
    );
    Ok(())
}

#[test]
fn formal_native_cubbyhole_post_audit_reply_tamper_has_no_private_delivery() -> TestResult {
    let (_files, mut service, _key, admin) = initialize()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "cubbyhole/item",
            &admin,
            json!({"value":"original"})
        )
        .status,
        204
    );
    let started = Instant::now();
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let body = json!({});
    let response = service.handle_inner(RequestView {
        method: "GET",
        path: "cubbyhole/item",
        namespace: "",
        token: &admin,
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
    let mut response = service.audit_completed_response_with_receipt(
        "native-cubbyhole-tamper",
        clock.admitted_at().seconds(),
        Some(clock),
        response,
        || {},
    );
    assert_eq!(response.status, 200);
    assert!(service.pending_native_auth_delivery.is_some());
    response.body["data"]["value"] = json!("substituted-after-audit");
    let response = service.complete_native_auth_delivery(true, response, "native-cubbyhole-tamper");
    assert!(response.status >= 300);
    assert!(response.body.get("data").is_none());
    assert!(service.pending_native_auth_delivery.is_none());
    Ok(())
}

#[test]
fn formal_native_cubbyhole_audit_failure_has_no_resource_publication() -> TestResult {
    let (files, mut service, key, admin) = initialize()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    service.audit_failed = true;
    let response = call(
        &mut service,
        "POST",
        "cubbyhole/audit-denied",
        &admin,
        json!({"private":"withheld"}),
    );
    assert!(response.status >= 300);
    assert!(response.body.get("data").is_none());
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "cubbyhole/audit-denied",
            &admin,
            json!({})
        )
        .status,
        404
    );
    Ok(())
}

#[test]
fn formal_native_cubbyhole_keeps_original_create_acl_and_directory_list() -> TestResult {
    let (_files, mut service, _key, admin) = initialize()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service, "PUT", "sys/policies/acl/cubby-create", &admin,
            json!({"policy":"path \"cubbyhole/*\" { capabilities = [\"create\", \"read\", \"list\", \"delete\"] }"}),
        ).status,
        204,
    );
    let mut response = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["cubby-create"],"no_default_policy":true,"ttl":"1h"}),
    );
    assert_eq!(response.status, 200);
    let owner = Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .ok_or("owned restricted token")?
            .to_owned(),
    );
    erase_json(&mut response.body);
    for path in ["cubbyhole/dir/b", "cubbyhole/dir/a"] {
        assert_eq!(
            call(&mut service, "POST", path, &owner, json!({"value":"first"})).status,
            204
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "cubbyhole/dir/a",
            &owner,
            json!({"value":"forbidden-update"})
        )
        .status,
        403
    );
    let mut response = call(&mut service, "GET", "cubbyhole/dir/a", &owner, json!({}));
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["value"], "first");
    erase_json(&mut response.body);
    let mut response = call(
        &mut service,
        "GET",
        "cubbyhole/dir",
        &owner,
        json!({"list":true}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["keys"], json!(["a", "b"]));
    erase_json(&mut response.body);
    Ok(())
}

#[test]
fn formal_native_cubbyhole_expired_original_deadline_cannot_rebind_after_audit() -> TestResult {
    let (_files, mut service, _key, admin) = initialize()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "cubbyhole/item",
            &admin,
            json!({"private":"withheld"})
        )
        .status,
        204
    );
    let started = Instant::now();
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(2));
    let body = json!({});
    let response = service.handle_inner(RequestView {
        method: "GET",
        path: "cubbyhole/item",
        namespace: "",
        token: &admin,
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
    let response = service.audit_completed_response_with_receipt(
        "native-cubbyhole-original-deadline",
        clock.admitted_at().seconds(),
        Some(clock),
        response,
        || std::thread::sleep(Duration::from_millis(2100)),
    );
    let _later_ambient = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let response =
        service.complete_native_auth_delivery(true, response, "native-cubbyhole-original-deadline");
    assert!(response.status >= 300);
    assert!(response.body.get("data").is_none());
    assert!(service.pending_native_auth_delivery.is_none());
    Ok(())
}

#[test]
fn formal_native_cubbyhole_lost_actual_root_ack_fences_then_cold_recovers() -> TestResult {
    let (files, mut service, key, admin) = initialize()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    let barrier = Zeroizing::new(**service.barrier_key.as_ref().ok_or("barrier")?);
    drop(service.durable.take().ok_or("durable owner")?);
    let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let backend = super::super::native_v6_writer::tests::LostApplyAck {
        inner: heptabao_durable_service::FileBackend::open(&service.data_dir)?,
        barrier: AeadBarrier::new(*barrier)?,
        lost: Arc::clone(&lost),
        purpose: "cubbyhole",
    };
    service.durable = Some(DurableService::reopen_with_backend(
        Box::new(backend) as Box<dyn heptabao_durable_service::DurableBackend>,
        AeadBarrier::new(*barrier)?,
        MAX_OPERATIONS,
    )?);
    let response = call(
        &mut service,
        "POST",
        "cubbyhole/ack-lost",
        &admin,
        json!({"value":"committed"}),
    );
    assert_eq!(response.status, 503);
    assert!(lost.load(std::sync::atomic::Ordering::SeqCst));
    assert!(service.recovery_required);
    assert!(response.body.get("data").is_none());
    assert!(response.body["recovery_reference"].as_str().is_some());
    assert_eq!(
        call(&mut service, "GET", "cubbyhole/ack-lost", &admin, json!({})).status,
        503
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    let mut response = call(&mut service, "GET", "cubbyhole/ack-lost", &admin, json!({}));
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["value"], "committed");
    erase_json(&mut response.body);
    assert!(!service.recovery_required);
    Ok(())
}
