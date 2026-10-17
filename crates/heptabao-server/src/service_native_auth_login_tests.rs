//! The original public-login credential bounds the whole real request.
//! Test pauses occur only after actual authentication or actual audited commit.
use super::*;
use std::cell::RefCell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

thread_local! {
    static BEFORE_LOGIN_PUBLICATION: RefCell<Option<(Duration, Arc<AtomicBool>)>> =
        const { RefCell::new(None) };
}

struct LoginPublicationPause {
    fired: Arc<AtomicBool>,
}

impl LoginPublicationPause {
    fn once(delay: Duration) -> Self {
        let fired = Arc::new(AtomicBool::new(false));
        BEFORE_LOGIN_PUBLICATION.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some((delay, Arc::clone(&fired)));
        });
        Self { fired }
    }
}

impl Drop for LoginPublicationPause {
    fn drop(&mut self) {
        BEFORE_LOGIN_PUBLICATION.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

// Invoked by the cfg(test) branch only for a successful real public-login
// dispatch, before candidate planning or publication. Each Rust test owns its
// thread-local arm; no production configuration, fabricated clock or alternate
// authentication path can trigger this pause.
pub(crate) fn before_native_login_publication(path: &str) {
    if path != LOGIN {
        return;
    }
    if let Some((delay, fired)) = BEFORE_LOGIN_PUBLICATION.with(|slot| slot.borrow_mut().take()) {
        fired.store(true, Ordering::Release);
        std::thread::sleep(delay);
    }
}

fn prepare_login_role(
    service: &mut Service,
    admin: &str,
    ttl: &str,
) -> TestResult<Zeroizing<String>> {
    assert_eq!(
        call(
            service,
            "POST",
            &format!("sys/auth/{MOUNT}"),
            admin,
            json!({"type":"approle"}),
        )
        .status,
        204,
    );
    assert_eq!(
        call(
            service,
            "POST",
            ROLE,
            admin,
            json!({
                "token_policies":["default"],
                "token_ttl":"10m",
                "token_max_ttl":"20m",
                "secret_id_ttl":ttl,
                "secret_id_num_uses":1,
                "token_type":"service",
            }),
        )
        .status,
        204,
    );
    let mut response = call(service, "GET", &format!("{ROLE}/role-id"), admin, json!({}));
    assert_eq!(response.status, 200);
    secret_field(&mut response, "/data/role_id")
}

fn token_count(service: &mut Service, admin: &str) -> TestResult<usize> {
    let mut response = call(service, "LIST", "auth/token/accessors", admin, json!({}));
    assert_eq!(response.status, 200);
    let count = response.body["data"]["keys"]
        .as_array()
        .ok_or("missing synthetic token accessor list")?
        .len();
    erase_json(&mut response.body);
    Ok(count)
}

fn secret_lookup(service: &mut Service, admin: &str, secret: &str) -> Response {
    call(
        service,
        "POST",
        &format!("{ROLE}/secret-id/lookup"),
        admin,
        json!({"secret_id":secret}),
    )
}

fn assert_no_credentials(response: &Response) {
    assert!(response.status >= 300);
    assert!(response.body.get("auth").is_none());
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("wrap_info").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
}

fn assert_live_token(service: &mut Service, token: &str) -> TestResult {
    let mut response = call(service, "GET", "auth/token/lookup-self", token, json!({}));
    assert_eq!(response.status, 200);
    assert!(
        response.body["data"]["ttl"]
            .as_u64()
            .is_some_and(|ttl| ttl > 2)
    );
    let echoed = secret_field(&mut response, "/data/id")?;
    assert!(echoed.as_str() == token);
    Ok(())
}

#[test]
fn native_approle_original_secret_expiry_before_publication_keeps_source_unconsumed() -> TestResult
{
    let (files, mut service, key, admin) = activated()?;
    let role_id = prepare_login_role(&mut service, &admin, "2s")?;
    let count = token_count(&mut service, &admin)?;
    let secret_id = issue_secret_id(&mut service, &admin)?;
    let pause = LoginPublicationPause::once(Duration::from_millis(2100));
    let response = call(
        &mut service,
        "POST",
        LOGIN,
        "",
        json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()}),
    );
    // The hook is reached only after successful real authentication. Therefore
    // this case cannot accidentally pass on an already-expired initial login.
    assert!(pause.fired.load(Ordering::Acquire));
    drop(pause);
    assert_no_credentials(&response);
    assert!(!service.recovery_required);
    assert!(!service.audit_failed);
    assert_eq!(token_count(&mut service, &admin)?, count);
    let mut original = secret_lookup(&mut service, &admin, &secret_id);
    assert_eq!(original.status, 200);
    assert_eq!(original.body["data"]["secret_id_num_uses"], 1);
    assert_eq!(original.body["data"]["secret_id_ttl"], 2);
    erase_json(&mut original.body);
    drop(service);

    // SecretID lookup intentionally exposes retained expired metadata. Unlike
    // a failed login alone, this proves the rejected candidate consumed no use.
    let mut service = reopened(&files, &key)?;
    assert_eq!(token_count(&mut service, &admin)?, count);
    let mut original = secret_lookup(&mut service, &admin, &secret_id);
    assert_eq!(original.status, 200);
    assert_eq!(original.body["data"]["secret_id_num_uses"], 1);
    assert_eq!(original.body["data"]["secret_id_ttl"], 2);
    erase_json(&mut original.body);
    assert_consumed(&mut service, &role_id, &secret_id);
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn native_approle_original_secret_expiry_after_audit_withholds_committed_login() -> TestResult {
    let (files, mut service, key, admin) = activated()?;
    let role_id = prepare_login_role(&mut service, &admin, "2s")?;
    let count = token_count(&mut service, &admin)?;
    let secret_id = issue_secret_id(&mut service, &admin)?;
    let body = json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()});
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let started = Instant::now();
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
    let scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let response = service.handle_inner(RequestView {
        method: "POST",
        path: LOGIN,
        namespace: "",
        token: "",
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
    // Keep this test-only copy private. The actual successful response remains
    // intact through the mandatory audit, then must lose all credential fields.
    let issued_token = Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or("missing synthetic committed login token")?
            .to_owned(),
    );
    let response = service.audit_completed_response_with_receipt(
        "native-login-original-secret-expiry",
        clock.admitted_at().seconds(),
        Some(clock),
        response,
        || std::thread::sleep(Duration::from_millis(2100)),
    );
    assert_eq!(response.status, 200);
    let response = service.complete_native_auth_delivery(
        true,
        response,
        "native-login-original-secret-expiry",
    );
    assert_no_credentials(&response);
    assert!(service.pending_native_auth_delivery.is_none());
    assert!(!service.recovery_required);
    assert!(!service.audit_failed);
    drop(scope);

    // Response erasure neither rolls back an already committed login nor
    // resurrects its one-time credential. The newly issued token's longer
    // lifetime must not have authorized the original expired-SID response.
    assert_eq!(token_count(&mut service, &admin)?, count + 1);
    assert_eq!(secret_lookup(&mut service, &admin, &secret_id).status, 204);
    assert_live_token(&mut service, &issued_token)?;
    drop(service);

    let mut service = reopened(&files, &key)?;
    assert_eq!(token_count(&mut service, &admin)?, count + 1);
    assert_eq!(secret_lookup(&mut service, &admin, &secret_id).status, 204);
    assert_consumed(&mut service, &role_id, &secret_id);
    assert_live_token(&mut service, &issued_token)?;
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn native_approle_one_time_secret_is_checked_without_consuming_again() -> TestResult {
    let (files, mut service, key, admin) = activated()?;
    let role_id = prepare_login_role(&mut service, &admin, "10m")?;
    let count = token_count(&mut service, &admin)?;
    let secret_id = issue_secret_id(&mut service, &admin)?;
    let (token, _entity) = login(&mut service, &role_id, &secret_id)?;
    assert_eq!(token_count(&mut service, &admin)?, count + 1);
    assert_eq!(secret_lookup(&mut service, &admin, &secret_id).status, 204);
    assert_consumed(&mut service, &role_id, &secret_id);
    assert_live_token(&mut service, &token)?;
    drop(service);

    // Neither root fsync gates nor after-audit source revalidation may run
    // authentication again against the candidate's already-consumed SecretID.
    let mut service = reopened(&files, &key)?;
    assert_eq!(token_count(&mut service, &admin)?, count + 1);
    assert_eq!(secret_lookup(&mut service, &admin, &secret_id).status, 204);
    assert_consumed(&mut service, &role_id, &secret_id);
    assert_live_token(&mut service, &token)?;
    assert!(!service.recovery_required);
    Ok(())
}
