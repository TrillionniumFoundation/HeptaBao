//! Actual formal File profile, public activation, Service domain operations,
//! durable cold reopens and original audit/Actor/deadline custody. Synthetic
//! credentials and crypto outputs are never included in assertion diagnostics.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::{Root, bootstrap_unmounted};
use std::cell::RefCell;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SECONDS: u64 = 15;
const IMPORTED_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
type AfterAudit = Box<dyn FnOnce(&mut Service, &mut Response)>;
thread_local! { static AFTER_AUDIT: RefCell<Option<AfterAudit>> = RefCell::new(None); }

pub(super) fn after_actual_totp_audit(service: &mut Service, response: &mut Response) {
    let hook = AFTER_AUDIT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        // Interleave an actual second request after actual publication/audit.
        // The outer capsule retains its Actor, proof, clock and checkpoint.
        assert!(service.native_failure_notice.is_none());
        let binding = service.native_request_binding.take();
        assert!(binding.is_some());
        assert!(service.pending_native_auth_delivery.is_none());
        hook(service, response);
        assert!(service.native_request_binding.is_none());
        assert!(service.native_failure_notice.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        service.native_request_binding = binding;
    }
}
pub(in crate::service) struct HookGuard;
impl Drop for HookGuard {
    fn drop(&mut self) {
        AFTER_AUDIT.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
pub(in crate::service) fn after_audit(
    hook: impl FnOnce(&mut Service, &mut Response) + 'static,
) -> TestResult<HookGuard> {
    AFTER_AUDIT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("TOTP audit hook already armed".into());
        }
        *slot = Some(Box::new(hook));
        Ok(HookGuard)
    })
}
fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let began = Instant::now();
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(began + Duration::from_secs(SECONDS));
    let response = service.handle(method, path, "", token, body);
    assert!(
        began.elapsed() < Duration::from_secs(SECONDS),
        "original TOTP request deadline"
    );
    response
}
fn expect(response: Response, status: u16, label: &str) -> TestResult<Response> {
    if response.status != status {
        return Err(format!(
            "native TOTP stage={label} expected={status} observed={}",
            response.status
        )
        .into());
    }
    Ok(response)
}
fn take_secret(response: &mut Response, pointer: &str) -> TestResult<Zeroizing<String>> {
    let value = response
        .body
        .pointer_mut(pointer)
        .ok_or("TOTP response field")?;
    let Value::String(secret) = value.take() else {
        return Err("TOTP response field type".into());
    };
    if secret.is_empty() {
        return Err("TOTP response field empty".into());
    }
    Ok(Zeroizing::new(secret))
}
fn initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    initialized_with_retained_floor(false)
}
fn legacy_initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, root) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(SECONDS),
        );
        bootstrap_unmounted(&mut service)?
    };
    let key = Zeroizing::new(key);
    let root = Zeroizing::new(root);
    for (path, body, status) in [
        ("sys/init/ack", json!({}), 204),
        (
            "sys/mounts/secret",
            json!({"type":"kv","options":{"version":"2"}}),
            204,
        ),
        (
            "secret/data/sentinel",
            json!({"options":{"cas":0},"data":{"kept":"unchanged"}}),
            200,
        ),
    ] {
        expect(
            call(&mut service, "POST", path, &root, body),
            status,
            "formal-File-initialization",
        )?;
    }
    assert!(service.native_root.is_none());
    Ok((files, service, key, root))
}
fn initialized_with_retained_floor(
    retain_floor: bool,
) -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let (files, mut service, key, root) = legacy_initialized()?;
    if retain_floor {
        let started = Instant::now();
        let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
        let mut state = service
            .state
            .as_ref()
            .ok_or("retained-floor legacy state")?
            .clone();
        state
            .engines
            .seed_retired_clock_for_native_mount_fixture(clock.observed_at()?)
            .map_err(|error| error.message)?;
        state.schema = state.writer_schema();
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            started + Duration::from_secs(SECONDS),
        );
        service
            .commit_state(&mut state)
            .map_err(|_| "retained-floor actual legacy commit")?;
        service.state = Some(state);
    }
    expect(
        call(
            &mut service,
            "POST",
            "sys/storage/native-v6/activate",
            &root,
            json!({}),
        ),
        204,
        "formal-public-activation",
    )?;
    assert!(matches!(
        service.native_storage_profile,
        Some(NativeStorageProfile::File)
    ));
    assert!(service.native_root.is_some());
    assert!(!initialization_recovery_pending(&service.data_dir)?);
    Ok((files, service, key, root))
}
fn enable(service: &mut Service, token: &str, mount: &str) -> TestResult {
    expect(
        call(
            service,
            "POST",
            &format!("sys/mounts/{mount}"),
            token,
            json!({"type":"totp","cas_revision":0,"config":{"options":null,"default_lease_ttl":"","max_lease_ttl":"","force_no_cache":false}}),
        ),
        204,
        "formal-TOTP-enable",
    )?;
    Ok(())
}
fn reopen(files: &Root, key: &str) -> TestResult<Service> {
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    expect(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})),
        200,
        "formal-File-cold-unseal",
    )?;
    assert!(service.native_root.is_some());
    Ok(service)
}
fn sentinel(service: &mut Service, root: &str) -> TestResult {
    let response = expect(
        call(service, "GET", "secret/data/sentinel", root, json!({})),
        200,
        "unrelated-KV-sentinel",
    )?;
    assert!(response.body["data"]["data"] == json!({"kept":"unchanged"}));
    assert!(service.pending_native_auth_delivery.is_none());
    assert!(service.native_request_binding.is_none());
    assert!(!service.recovery_required && !service.audit_failed);
    Ok(())
}

fn imported(issuer: &str) -> Value {
    json!({"key":IMPORTED_SEED,"issuer":issuer,"account_name":"synthetic",
        "algorithm":"SHA256","digits":8,"period":3600,"skew":1})
}

fn put_key(service: &mut Service, actor: &str, name: &str, issuer: &str) -> TestResult {
    expect(
        call(
            service,
            "POST",
            &format!("totp/keys/{name}"),
            actor,
            imported(issuer),
        ),
        204,
        "actual-TOTP-import",
    )?;
    Ok(())
}

fn code(service: &mut Service, actor: &str, name: &str) -> TestResult<Zeroizing<String>> {
    let mut response = expect(
        call(
            service,
            "GET",
            &format!("totp/code/{name}"),
            actor,
            json!({}),
        ),
        200,
        "actual-TOTP-code",
    )?;
    take_secret(&mut response, "/data/code")
}

fn validate(
    service: &mut Service,
    actor: &str,
    name: &str,
    submitted: &str,
    valid: bool,
) -> TestResult {
    let mut response = expect(
        call(
            service,
            "POST",
            &format!("totp/code/{name}"),
            actor,
            json!({"code":submitted}),
        ),
        200,
        "actual-TOTP-validation",
    )?;
    assert!(response.body["data"]["valid"] == valid);
    erase_json(&mut response.body);
    Ok(())
}

fn replay_state(service: &Service, name: &str) -> TestResult<(Option<u64>, u64, u32)> {
    service
        .state
        .as_ref()
        .ok_or("TOTP native state")?
        .engines
        .native_totp_replay_observation("totp/", name)
        .ok_or_else(|| "TOTP replay metadata absent".into())
}

fn token(
    service: &mut Service,
    root: &str,
    policy: &str,
    uses: u64,
    ttl: &str,
) -> TestResult<Zeroizing<String>> {
    expect(
        call(
            service,
            "PUT",
            "sys/policies/acl/totp-owner",
            root,
            json!({"policy":policy}),
        ),
        204,
        "actual-TOTP-policy",
    )?;
    let mut issued = expect(
        call(
            service,
            "POST",
            "auth/token/create",
            root,
            json!({"policies":["totp-owner"],"no_default_policy":true,"ttl":ttl,"num_uses":uses}),
        ),
        200,
        "actual-TOTP-actor",
    )?;
    take_secret(&mut issued, "/auth/client_token")
}

#[test]
fn native_totp_legacy_key_and_consumed_counter_migrate_by_public_activation_and_cold_reopen()
-> TestResult {
    let (files, mut service, key, root) = legacy_initialized()?;
    enable(&mut service, &root, "totp")?;
    put_key(&mut service, &root, "migrated", "legacy")?;
    let submitted = code(&mut service, &root, "migrated")?;
    validate(&mut service, &root, "migrated", &submitted, true)?;
    let consumed = replay_state(&service, "migrated")?;
    assert!(consumed.0.is_some());
    assert!(matches!(
        service
            .current_state_identity()
            .map_err(|_| "legacy TOTP identity")?,
        crate::state_record_root::StateIdentity::RecordsV5(_)
    ));
    assert!(service.native_root.is_none());
    expect(
        call(
            &mut service,
            "POST",
            "sys/storage/native-v6/activate",
            &root,
            json!({}),
        ),
        204,
        "existing TOTP owner public activation",
    )?;
    assert!(service.native_root.is_some() && service.record_root.is_none());
    assert_eq!(replay_state(&service, "migrated")?, consumed);
    let metadata = expect(
        call(&mut service, "GET", "totp/keys/migrated", &root, json!({})),
        200,
        "migrated TOTP descriptor",
    )?;
    assert_eq!(metadata.body["data"]["issuer"], "legacy");
    validate(&mut service, &root, "migrated", &submitted, false)?;
    let rejected = replay_state(&service, "migrated")?;
    assert_eq!(rejected.0, consumed.0);
    assert_eq!(rejected.2, 1);
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(replay_state(&service, "migrated")?, rejected);
    validate(&mut service, &root, "migrated", &submitted, false)?;
    assert_eq!(replay_state(&service, "migrated")?.0, consumed.0);
    sentinel(&mut service, &root)
}

#[test]
fn native_totp_formal_file_registry_import_generate_crud_and_two_cold_reopens() -> TestResult {
    let (files, mut service, key, root) = initialized()?;
    let graphs = service
        .native_root
        .as_ref()
        .ok_or("TOTP native root")?
        .kv2
        .clone();
    enable(&mut service, &root, "totp")?;
    put_key(&mut service, &root, "durable", "initial")?;
    let mounted = expect(
        call(&mut service, "GET", "sys/mounts/totp", &root, json!({})),
        200,
        "TOTP registry",
    )?;
    assert_eq!(mounted.body["data"]["type"], "totp");
    assert_eq!(mounted.body["data"]["incarnation"], 1);
    expect(
        call(
            &mut service,
            "POST",
            "sys/mounts/totp/tune",
            &root,
            json!({"description":"owned TOTP","cas_revision":1}),
        ),
        204,
        "TOTP tune",
    )?;
    let metadata = expect(
        call(&mut service, "GET", "totp/keys/durable", &root, json!({})),
        200,
        "TOTP metadata",
    )?;
    assert_eq!(metadata.body["data"]["algorithm"], "SHA256");
    assert_eq!(metadata.body["data"]["period"], 3600);
    for field in ["key", "secret", "url", "barcode", "code"] {
        assert!(metadata.body["data"].get(field).is_none());
    }
    let mut generated = expect(
        call(
            &mut service,
            "POST",
            "totp/keys/generated",
            &root,
            json!({"generate":true,"issuer":"fixture","account_name":"synthetic",
            "algorithm":"SHA512","digits":8,"period":3600,"qr_size":0}),
        ),
        200,
        "TOTP generate",
    )?;
    let url = take_secret(&mut generated, "/data/url")?;
    assert!(url.starts_with("otpauth://totp/"));
    assert!(generated.body["data"].get("barcode").is_none());
    erase_json(&mut generated.body);
    let list = expect(
        call(&mut service, "LIST", "totp/keys", &root, json!({})),
        200,
        "TOTP list",
    )?;
    assert_eq!(list.body["data"]["keys"], json!(["durable", "generated"]));
    let current = code(&mut service, &root, "durable")?;
    validate(&mut service, &root, "durable", &current, true)?;
    let consumed = replay_state(&service, "durable")?;
    assert!(consumed.0.is_some() && consumed.2 == 0);
    assert!(service.native_root.as_ref().ok_or("TOTP native root")?.kv2 == graphs);
    sentinel(&mut service, &root)?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(replay_state(&service, "durable")?, consumed);
    validate(&mut service, &root, "durable", &current, false)?;
    let failed = replay_state(&service, "durable")?;
    assert_eq!(failed.0, consumed.0);
    assert_eq!(failed.2, 1);
    // Re-importing the same seed with different labels may not reset either
    // persisted counter. The assertion observes exact metadata, not expiry.
    put_key(&mut service, &root, "durable", "changed-label")?;
    assert_eq!(replay_state(&service, "durable")?, failed);
    expect(
        call(
            &mut service,
            "DELETE",
            "totp/keys/generated",
            &root,
            json!({}),
        ),
        204,
        "TOTP delete",
    )?;
    let generated_absent = call(&mut service, "GET", "totp/keys/generated", &root, json!({}));
    expect(generated_absent, 404, "TOTP deleted key")?;
    let tuned = expect(
        call(&mut service, "GET", "sys/mounts/totp", &root, json!({})),
        200,
        "cold TOTP registry",
    )?;
    assert_eq!(tuned.body["data"]["revision"], 2);
    enable(&mut service, &root, "retire")?;
    expect(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/retire",
            &root,
            json!({"cas_revision":1}),
        ),
        204,
        "TOTP unmount",
    )?;
    enable(&mut service, &root, "retire")?;
    let recreated = expect(
        call(&mut service, "GET", "sys/mounts/retire", &root, json!({})),
        200,
        "TOTP remount",
    )?;
    assert_eq!(recreated.body["data"]["incarnation"], 2);
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(replay_state(&service, "durable")?, failed);
    let metadata = expect(
        call(&mut service, "GET", "totp/keys/durable", &root, json!({})),
        200,
        "second cold TOTP metadata",
    )?;
    assert_eq!(metadata.body["data"]["issuer"], "changed-label");
    validate(&mut service, &root, "durable", &current, false)?;
    assert_eq!(replay_state(&service, "durable")?.0, consumed.0);
    assert!(service.native_root.as_ref().ok_or("TOTP native root")?.kv2 == graphs);
    sentinel(&mut service, &root)
}

#[test]
fn native_totp_actual_acl_create_only_and_separate_mount_sudo_are_retained() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    enable(&mut service, &root, "totp")?;
    let actor = token(
        &mut service,
        &root,
        r#"path "totp/keys/created" { capabilities=["create"] }
path "sys/mounts/forbidden" { capabilities=["update","read","delete"] }"#,
        0,
        "1h",
    )?;
    put_key(&mut service, &actor, "created", "create-only")?;
    expect(
        call(
            &mut service,
            "POST",
            "totp/keys/created",
            &actor,
            imported("cannot-update"),
        ),
        403,
        "TOTP update denied",
    )?;
    expect(
        call(&mut service, "GET", "totp/code/created", &actor, json!({})),
        403,
        "TOTP code read denied",
    )?;
    expect(
        call(&mut service, "LIST", "totp/keys", &actor, json!({})),
        403,
        "TOTP list denied",
    )?;
    expect(
        call(&mut service, "GET", "totp/code/created", "", json!({})),
        403,
        "TOTP missing actor",
    )?;
    expect(
        call(
            &mut service,
            "POST",
            "sys/mounts/forbidden",
            &actor,
            json!({"type":"totp"}),
        ),
        403,
        "TOTP sudo denied",
    )?;
    expect(
        call(
            &mut service,
            "POST",
            "sys/mounts/totp/tune",
            &root,
            json!({"description":"stale","cas_revision":99}),
        ),
        409,
        "TOTP stale CAS",
    )?;
    let root_code = code(&mut service, &root, "created")?;
    validate(&mut service, &root, "created", &root_code, true)?;
    sentinel(&mut service, &root)
}

#[test]
fn native_totp_finite_actor_read_consumes_once_and_cold_reopen_keeps_replay_state() -> TestResult {
    let (files, mut service, key, root) = initialized_with_retained_floor(true)?;
    enable(&mut service, &root, "totp")?;
    put_key(&mut service, &root, "finite", "fixture")?;
    let before = replay_state(&service, "finite")?;
    let actor = token(
        &mut service,
        &root,
        r#"path "totp/code/finite" { capabilities=["read"] }"#,
        1,
        "1h",
    )?;
    let issued = code(&mut service, &actor, "finite")?;
    assert_eq!(replay_state(&service, "finite")?, before);
    expect(
        call(&mut service, "GET", "totp/code/finite", &actor, json!({})),
        403,
        "TOTP spent actor",
    )?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(replay_state(&service, "finite")?, before);
    expect(
        call(&mut service, "GET", "totp/code/finite", &actor, json!({})),
        403,
        "cold spent TOTP actor",
    )?;
    validate(&mut service, &root, "finite", &issued, true)?;
    sentinel(&mut service, &root)
}

#[test]
fn native_totp_after_actual_audit_revocation_erases_generated_code() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    enable(&mut service, &root, "totp")?;
    put_key(&mut service, &root, "revoked", "fixture")?;
    let actor = token(
        &mut service,
        &root,
        r#"path "totp/code/revoked" { capabilities=["read"] }"#,
        0,
        "1h",
    )?;
    let revoke_root = root.clone();
    let revoke_actor = actor.clone();
    let _hook = after_audit(move |service, response| {
        assert!(response.status == 200 && response.body["data"]["code"].is_string());
        assert_eq!(
            call(
                service,
                "POST",
                "auth/token/revoke",
                &revoke_root,
                json!({"token":revoke_actor.as_str()})
            )
            .status,
            204
        );
    })?;
    let response = expect(
        call(&mut service, "GET", "totp/code/revoked", &actor, json!({})),
        503,
        "TOTP revoked after audit",
    )?;
    assert!(response.body.get("data").is_none());
    expect(
        call(&mut service, "GET", "totp/code/revoked", &actor, json!({})),
        403,
        "TOTP revoked remains denied",
    )?;
    sentinel(&mut service, &root)
}

#[test]
fn native_totp_after_actual_audit_error_status_with_private_body_is_vetoed() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    enable(&mut service, &root, "totp")?;
    put_key(&mut service, &root, "digest", "fixture")?;
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_observed = Arc::clone(&observed);
    let _hook = after_audit(move |_service, response| {
        assert!(response.status == 200 && response.body["data"]["code"].is_string());
        hook_observed.store(true, std::sync::atomic::Ordering::SeqCst);
        // A changed status must not bypass the same final digest/owner check.
        response.status = 503;
    })?;
    let response = expect(
        call(&mut service, "GET", "totp/code/digest", &root, json!({})),
        503,
        "TOTP all-status digest",
    )?;
    assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(response.body.get("data").is_none());
    sentinel(&mut service, &root)
}

#[test]
fn native_totp_after_actual_audit_seal_keeps_consumed_counter_across_cold_restart() -> TestResult {
    let (files, mut service, key, root) = initialized()?;
    enable(&mut service, &root, "totp")?;
    put_key(&mut service, &root, "sealed", "fixture")?;
    let submitted = code(&mut service, &root, "sealed")?;
    let captured = Arc::new(Mutex::new(None));
    let hook_captured = Arc::clone(&captured);
    let seal_root = root.clone();
    let _hook = after_audit(move |service, response| {
        assert!(response.status == 200 && response.body["data"]["valid"] == true);
        let state = replay_state(service, "sealed");
        assert!(state.is_ok());
        if let Ok(state) = state {
            assert!(state.0.is_some());
            if let Ok(mut captured) = hook_captured.lock() {
                *captured = Some(state);
            }
        }
        assert_eq!(
            call(service, "POST", "sys/seal", &seal_root, json!({})).status,
            204
        );
    })?;
    let response = expect(
        call(
            &mut service,
            "POST",
            "totp/code/sealed",
            &root,
            json!({"code":submitted.as_str()}),
        ),
        503,
        "TOTP consumed but sealed",
    )?;
    assert!(response.body.get("data").is_none());
    assert!(service.state.is_none());
    let consumed = captured
        .lock()
        .map_err(|_| "TOTP observed counter lock")?
        .ok_or("actual TOTP audit observation")?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(replay_state(&service, "sealed")?, consumed);
    validate(&mut service, &root, "sealed", &submitted, false)?;
    assert_eq!(replay_state(&service, "sealed")?.0, consumed.0);
    sentinel(&mut service, &root)
}

#[test]
fn native_totp_after_actual_audit_unrelated_published_root_vetoes_old_code_reply() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    enable(&mut service, &root, "totp")?;
    put_key(&mut service, &root, "root-bound", "fixture")?;
    let writer = root.clone();
    let _hook = after_audit(move |service, response| {
        assert!(response.body["data"]["code"].is_string());
        assert_eq!(
            call(
                service,
                "POST",
                "secret/data/sentinel",
                &writer,
                json!({"options":{"cas":1},"data":{"after_audit":true}})
            )
            .status,
            200
        );
    })?;
    let response = expect(
        call(
            &mut service,
            "GET",
            "totp/code/root-bound",
            &root,
            json!({}),
        ),
        503,
        "TOTP original root changed",
    )?;
    assert!(response.body.get("data").is_none());
    let current = expect(
        call(
            &mut service,
            "GET",
            "secret/data/sentinel",
            &root,
            json!({}),
        ),
        200,
        "actual new root",
    )?;
    assert!(current.body["data"]["data"] == json!({"after_audit":true}));
    assert!(
        service.pending_native_auth_delivery.is_none() && service.native_request_binding.is_none()
    );
    Ok(())
}

#[test]
fn native_totp_capsule_cannot_reexecute_rebind_clock_or_change_other_owners() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    enable(&mut service, &root, "totp")?;
    enable(&mut service, &root, "peer")?;
    put_key(&mut service, &root, "source", "fixture")?;
    let source: EngineState = (*service.state.as_ref().ok_or("TOTP state")?.engines).clone();
    let native = service
        .native_root
        .as_ref()
        .ok_or("TOTP native root")?
        .clone();
    let until = Instant::now() + Duration::from_secs(SECONDS);
    let live = || Instant::now() < until;
    let clock = RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )?;
    let at = clock.observed_at()?;
    assert!(
        source
            .capture_native_totp_owner(
                "POST",
                "totp/keys/owned",
                &imported("owner"),
                &native,
                &|| false
            )
            .is_err()
    );
    let mut owner = source
        .capture_native_totp_owner(
            "POST",
            "totp/keys/owned",
            &imported("owner"),
            &native,
            &live,
        )
        .map_err(|error| error.message)?;
    assert!(owner.admit_candidate(&source, &live).is_err());
    assert!(owner.admit_root(&native, &native, &live).is_err());
    let mut candidate = source.clone();
    let response = owner
        .execute(&mut candidate, at, &live)
        .map_err(|error| error.message)?
        .ok_or("TOTP domain result")?;
    assert_eq!(response.status, 204);
    owner
        .admit_candidate(&candidate, &live)
        .map_err(|error| error.message)?;
    assert!(owner.execute(&mut candidate, at, &live).is_err());
    assert!(
        owner
            .check_observed_time(crate::auth::Timestamp::whole(
                at.seconds().saturating_sub(1)
            )?)
            .is_err()
    );
    let mut peer_changed = candidate.clone();
    peer_changed
        .handle(
            "",
            "POST",
            "peer/keys/unrelated",
            &imported("peer"),
            at.seconds(),
        )
        .map_err(|error| error.message)?;
    assert!(owner.admit_candidate(&peer_changed, &live).is_err());
    let mut wrong_root = native.clone();
    wrong_root.replay_epoch = wrong_root
        .replay_epoch
        .checked_add(1)
        .ok_or("TOTP test epoch overflow")?;
    assert!(owner.admit_root(&native, &wrong_root, &live).is_err());
    assert!(owner.admit_candidate(&candidate, &|| false).is_err());
    let mut readonly = source
        .capture_native_totp_owner("GET", "totp/code/source", &json!({}), &native, &live)
        .map_err(|error| error.message)?;
    let mut same = source.clone();
    let mut generated = readonly
        .execute(&mut same, at, &live)
        .map_err(|error| error.message)?
        .ok_or("TOTP read result")?;
    assert_eq!(generated.status, 200);
    erase_json(&mut generated.body);
    readonly
        .admit_candidate(&same, &live)
        .map_err(|error| error.message)?;
    same.handle(
        "",
        "POST",
        "totp/keys/source",
        &imported("changed"),
        at.seconds(),
    )
    .map_err(|error| error.message)?;
    assert!(readonly.admit_candidate(&same, &live).is_err());
    expect(
        call(&mut service, "GET", "totp/keys/owned", &root, json!({})),
        404,
        "unpublished TOTP owner",
    )?;
    sentinel(&mut service, &root)
}
