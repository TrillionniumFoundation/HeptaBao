//! Real configured File V6, original domain 404, ACL/finite use, HTTP parser,
//! cold reopen and interleavings after the actual mandatory response audit.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use std::cell::RefCell;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SECONDS: u64 = 15;
type AfterAudit = Box<dyn FnOnce(&mut Service, &mut Response)>;
thread_local! { static AFTER_AUDIT: RefCell<Option<AfterAudit>> = RefCell::new(None); }

pub(super) fn after_actual_missing_route_audit(service: &mut Service, response: &mut Response) {
    let hook = AFTER_AUDIT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
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
            return Err("missing-route audit hook already armed".into());
        }
        *slot = Some(Box::new(hook));
        Ok(HookGuard)
    })
}

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let started = Instant::now();
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        started + Duration::from_secs(SECONDS),
    );
    let response = service.handle(method, path, "", token, body);
    assert!(
        started.elapsed() < Duration::from_secs(SECONDS),
        "original missing-route deadline"
    );
    assert!(service.pending_native_auth_delivery.is_none());
    assert!(service.native_request_binding.is_none());
    response
}
fn expect(response: Response, status: u16, stage: &str) -> TestResult<Response> {
    if response.status != status {
        return Err(format!(
            "native missing-route stage={stage} expected={status} observed={}",
            response.status
        )
        .into());
    }
    Ok(response)
}
fn negative(response: Response) -> TestResult {
    let response = expect(response, 404, "original absent-mount dispatcher")?;
    assert!(response.body == json!({"errors":["unsupported path"]}));
    assert!(response.unwrapped_json.is_none() && response.response_headers.is_empty());
    Ok(())
}
fn take_secret(response: &mut Response, pointer: &str) -> TestResult<Zeroizing<String>> {
    let value = response
        .body
        .pointer_mut(pointer)
        .ok_or("missing fixture credential")?;
    let Value::String(secret) = value.take() else {
        return Err("fixture credential has wrong type".into());
    };
    if secret.is_empty() {
        return Err("fixture credential is empty".into());
    }
    Ok(Zeroizing::new(secret))
}

struct Fixture {
    files: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
}
impl Fixture {
    fn start(with_kv: bool, retained_clock: bool) -> TestResult<Self> {
        let files = Root::new();
        let mut service = files.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        let mut initialized = expect(
            call(
                &mut service,
                "POST",
                "sys/init",
                "",
                json!({"secret_shares":1,"secret_threshold":1}),
            ),
            200,
            "actual file init",
        )?;
        let key = take_secret(&mut initialized, "/keys/0")?;
        let admin = take_secret(&mut initialized, "/root_token")?;
        erase_json(&mut initialized.body);
        expect(
            call(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":key.as_str()}),
            ),
            200,
            "actual file unseal",
        )?;
        expect(
            call(&mut service, "POST", "sys/init/ack", &admin, json!({})),
            204,
            "actual init ack",
        )?;
        if with_kv {
            expect(
                call(
                    &mut service,
                    "POST",
                    "sys/mounts/secret",
                    &admin,
                    json!({"type":"kv","options":{"version":"2"}}),
                ),
                204,
                "legacy KV mount",
            )?;
            expect(
                call(
                    &mut service,
                    "POST",
                    "secret/data/kept",
                    &admin,
                    json!({"options":{"cas":0},"data":{"value":"unchanged"}}),
                ),
                200,
                "legacy KV value",
            )?;
        }
        if retained_clock {
            let started = Instant::now();
            let clock =
                RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
            let mut state = service.state.as_ref().ok_or("legacy clock state")?.clone();
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
                .map_err(|_| "actual legacy retained-floor commit")?;
            service.state = Some(state);
        }
        expect(
            call(
                &mut service,
                "POST",
                native_storage::ACTIVATE_PATH,
                &admin,
                json!({}),
            ),
            204,
            "actual public V6 activation",
        )?;
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::File)
        ));
        assert!(!initialization_recovery_pending(&service.data_dir)?);
        Ok(Self {
            files,
            service,
            key,
            admin,
        })
    }
    fn admin(&mut self, method: &str, path: &str, body: Value) -> Response {
        call(&mut self.service, method, path, &self.admin, body)
    }
    fn actor(&mut self, actor: &str, method: &str, path: &str, body: Value) -> Response {
        call(&mut self.service, method, path, actor, body)
    }
    fn restart(mut self) -> TestResult<Self> {
        drop(self.service);
        self.service = self.files.service()?;
        self.service
            .configure_native_v6_storage(NativeStorageProfile::File)?;
        expect(
            call(
                &mut self.service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":self.key.as_str()}),
            ),
            200,
            "actual cold V6 unseal",
        )?;
        assert!(self.service.native_root.is_some() && self.service.record_root.is_none());
        assert!(!self.service.recovery_required && !self.service.audit_failed);
        Ok(self)
    }
    fn token(&mut self, policy: &str, uses: u64) -> TestResult<Zeroizing<String>> {
        expect(
            self.admin(
                "PUT",
                "sys/policies/acl/missing-route",
                json!({"policy":policy}),
            ),
            204,
            "actual missing-route ACL",
        )?;
        let mut issued = expect(self.admin("POST", "auth/token/create",
            json!({"policies":["missing-route"],"no_default_policy":true,"num_uses":uses,"ttl":"1h"})), 200, "actual missing-route actor")?;
        let token = take_secret(&mut issued, "/auth/client_token")?;
        erase_json(&mut issued.body);
        Ok(token)
    }
    fn root(&self) -> TestResult<RecordStateRootV6> {
        self.service
            .native_root
            .clone()
            .ok_or_else(|| "native missing-route root".into())
    }
    fn sentinel(&mut self) -> TestResult {
        let reply = expect(
            self.admin("GET", "secret/data/kept", json!({})),
            200,
            "unrelated KV read",
        )?;
        assert!(reply.body["data"]["data"] == json!({"value":"unchanged"}));
        assert!(reply.body["data"]["metadata"]["version"] == 1);
        Ok(())
    }
}

#[test]
fn native_missing_route_formal_empty_catalog_http_get_head_list_and_cold_reopen() -> TestResult {
    let mut f = Fixture::start(false, false)?;
    for method in ["GET", "HEAD", "LIST"] {
        negative(f.admin(method, "hbqa-truly-absent", json!({})))?;
    }
    let long_path = format!("hbqa-absent/{}", "x".repeat(1100));
    negative(f.admin("GET", &long_path, json!({})))?;
    let wire = Zeroizing::new(format!(
        "GET /v1/hbqa-truly-absent?list=true HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nUser-Agent: Python-urllib/3.14\r\nConnection: close\r\n\r\n",
        f.admin.as_str(),
    ));
    let deadline = Instant::now() + Duration::from_secs(SECONDS);
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let response = crate::http::logical_data_wire_dispatch_fixture(wire.as_bytes(), |request| {
        assert_eq!(request.method, "LIST");
        assert_eq!(request.path, "hbqa-truly-absent");
        let execution = f.service.begin_request_before(request, deadline, true);
        f.service.finish_synchronous_request(execution)
    })?;
    negative(response)?;
    assert!(Instant::now() < deadline);
    let mut f = f.restart()?;
    negative(f.admin("GET", "hbqa-truly-absent", json!({})))
}

#[test]
fn native_missing_route_preserves_all_kv_graphs_and_then_uses_actual_new_mount() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    let before = f.root()?;
    negative(f.admin("GET", "later/data/value", json!({})))?;
    let after = f.root()?;
    assert!(before.kv1 == after.kv1 && before.kv2 == after.kv2);
    assert_eq!(
        before.reader_floor.native_kv2_format,
        after.reader_floor.native_kv2_format
    );
    f.sentinel()?;
    let mut f = f.restart()?;
    negative(f.admin("GET", "later/data/value", json!({})))?;
    expect(
        f.admin(
            "POST",
            "sys/mounts/later",
            json!({"type":"kv","options":{"version":"2"},"cas_revision":0}),
        ),
        204,
        "new real KV mount",
    )?;
    expect(
        f.admin(
            "POST",
            "later/data/value",
            json!({"options":{"cas":0},"data":{"created":true}}),
        ),
        200,
        "new real KV value",
    )?;
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("native state")?
            .engines
            .native_missing_mount_read("", "GET", "later/data/value")
    );
    let mut f = f.restart()?;
    let read = expect(
        f.admin("GET", "later/data/value", json!({})),
        200,
        "cold actual mounted route",
    )?;
    assert!(read.body["data"]["data"] == json!({"created":true}));
    f.sentinel()
}

#[test]
fn native_missing_route_actual_acl_one_finite_use_and_retained_clock_survive_cold() -> TestResult {
    let mut f = Fixture::start(true, true)?;
    let actor = f.token(r#"path "unmounted/allowed" { capabilities=["read"] }"#, 1)?;
    let before = f.root()?;
    negative(f.actor(&actor, "GET", "unmounted/allowed", json!({})))?;
    assert!(f.root()?.kv2 == before.kv2);
    expect(
        f.actor(&actor, "GET", "unmounted/allowed", json!({})),
        403,
        "finite use consumed once",
    )?;
    let mut f = f.restart()?;
    expect(
        f.actor(&actor, "GET", "unmounted/allowed", json!({})),
        403,
        "cold finite use remains spent",
    )?;
    let actor = f.token(r#"path "unmounted/allowed" { capabilities=["read"] }"#, 0)?;
    negative(f.actor(&actor, "GET", "unmounted/allowed", json!({})))?;
    expect(
        f.actor(&actor, "LIST", "unmounted/allowed", json!({})),
        403,
        "list capability absent",
    )?;
    expect(
        f.actor(&actor, "GET", "unmounted/denied", json!({})),
        403,
        "different path ACL denied",
    )?;
    expect(
        f.actor("", "GET", "unmounted/allowed", json!({})),
        403,
        "missing actor",
    )?;
    // Direct Service callers must use the same logical LIST authority as the
    // actual HTTP parser, for both supported true encodings.
    for list in [json!(true), json!("true")] {
        expect(
            f.actor(&actor, "GET", "unmounted/allowed", json!({"list":list})),
            403,
            "read-only actor cannot use GET-list",
        )?;
    }
    let list_actor = f.token(r#"path "unmounted/allowed" { capabilities=["list"] }"#, 0)?;
    negative(f.actor(&list_actor, "LIST", "unmounted/allowed", json!({})))?;
    for list in [json!(true), json!("true")] {
        negative(f.actor(
            &list_actor,
            "GET",
            "unmounted/allowed",
            json!({"list":list}),
        ))?;
    }
    expect(
        f.actor(&list_actor, "GET", "unmounted/allowed", json!({})),
        403,
        "list-only actor cannot use plain GET",
    )?;
    f.sentinel()
}

#[test]
fn native_missing_route_retains_reserved_and_known_backend_refusals() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    for path in [
        "sys/unimplemented-owner",
        "auth/unmounted/users/a",
        "identity/mfa/method/totp",
        "secret",
    ] {
        expect(
            f.admin("GET", path, json!({})),
            501,
            "known or reserved native scope",
        )?;
    }
    expect(
        f.admin("POST", "truly-absent", json!({})),
        501,
        "no missing-route writer",
    )?;
    expect(
        f.admin("SCAN", "truly-absent", json!({})),
        501,
        "no missing-route scan owner",
    )?;
    for scan in [json!(true), json!("true")] {
        expect(
            f.admin("GET", "truly-absent", json!({"scan":scan})),
            501,
            "GET-scan cannot open an unowned scan operation",
        )?;
    }
    let mut catalog = EngineState::default();
    for (mount, kind) in [
        ("ssh-real", "ssh"),
        ("pki-real", "pki"),
        ("nested/owner", "kv"),
    ] {
        let mounted = catalog
            .handle(
                "",
                "POST",
                &format!("sys/mounts/{mount}"),
                &json!({"type":kind}),
                100,
            )
            .map_err(|error| error.message)?
            .ok_or("actual mount result")?;
        assert_eq!(mounted.status, 204);
        assert!(!catalog.native_missing_mount_read("", "GET", mount));
        assert!(!catalog.native_missing_mount_read("", "GET", &format!("{mount}/unimplemented")));
    }
    assert!(!catalog.native_missing_mount_read("", "GET", "nested"));
    // Engine absence selects an owner; the Service must still capture the
    // actual namespace identity before it can deliver an observation.
    assert!(catalog.native_missing_mount_read("child", "GET", "absent"));
    let child_mount = catalog
        .handle(
            "child",
            "POST",
            "sys/mounts/child-owned",
            &json!({"type":"kv"}),
            100,
        )
        .map_err(|error| error.message)?
        .ok_or("actual child mount result")?;
    assert_eq!(child_mount.status, 204);
    assert!(!catalog.native_missing_mount_read("child", "GET", "child-owned/value"));
    assert!(catalog.native_missing_mount_read("", "GET", "child-owned/value"));
    assert!(catalog.native_missing_mount_read("child", "GET", "ssh-real/value"));
    assert!(catalog.native_missing_mount_read("", "GET", "ssh-real-neighbor"));
    for path in [
        "",
        "/absolute",
        "absent//invalid",
        "absent/../invalid",
        "absent?list=true",
    ] {
        assert!(!catalog.native_missing_mount_read("", "GET", path));
    }
    f.sentinel()
}

#[test]
fn native_missing_route_after_actual_audit_mount_publication_vetoes_stale_absence() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    let writer = f.admin.clone();
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_observed = Arc::clone(&observed);
    let _hook = after_audit(move |service, response| {
        assert!(response.status == 404 && response.body == json!({"errors":["unsupported path"]}));
        hook_observed.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            call(
                service,
                "POST",
                "sys/mounts/late",
                &writer,
                json!({"type":"kv","options":{"version":"2"},"cas_revision":0})
            )
            .status,
            204
        );
    })?;
    let refused = expect(
        f.admin("GET", "late/data/value", json!({})),
        503,
        "catalog changed after actual audit",
    )?;
    assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(refused.body.get("data").is_none());
    expect(
        f.admin(
            "POST",
            "late/data/value",
            json!({"options":{"cas":0},"data":{"owned":true}}),
        ),
        200,
        "new catalog owner writes",
    )?;
    let mut f = f.restart()?;
    let read = expect(
        f.admin("GET", "late/data/value", json!({})),
        200,
        "new catalog owner survives cold",
    )?;
    assert!(read.body["data"]["data"] == json!({"owned":true}));
    f.sentinel()
}

#[test]
fn native_missing_route_after_actual_audit_revoke_rechecks_original_actor() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    let actor = f.token(r#"path "absent/*" { capabilities=["read"] }"#, 0)?;
    let writer = f.admin.clone();
    let revoked = actor.clone();
    let _hook = after_audit(move |service, response| {
        assert!(response.status == 404);
        assert_eq!(
            call(
                service,
                "POST",
                "auth/token/revoke",
                &writer,
                json!({"token":revoked.as_str()})
            )
            .status,
            204
        );
    })?;
    expect(
        f.actor(&actor, "GET", "absent/route", json!({})),
        503,
        "negative reply after actual revoke",
    )?;
    expect(
        f.actor(&actor, "GET", "absent/route", json!({})),
        403,
        "revoked actor remains denied",
    )?;
    f.sentinel()
}

#[test]
fn native_missing_route_error_status_cannot_bypass_post_audit_reply_digest() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    for changed_status in [404, 503] {
        let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_observed = Arc::clone(&observed);
        let _hook = after_audit(move |_service, response| {
            assert!(
                response.status == 404 && response.body == json!({"errors":["unsupported path"]})
            );
            hook_observed.store(true, std::sync::atomic::Ordering::SeqCst);
            response.status = changed_status;
            response.body["data"] = json!({"private":"must-be-withheld"});
        })?;
        let refused = expect(
            f.admin("GET", "absent/digest", json!({})),
            503,
            "all-status negative digest",
        )?;
        assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(refused.body.get("data").is_none());
        assert!(refused.unwrapped_json.is_none() && refused.response_headers.is_empty());
    }
    f.sentinel()
}

#[test]
fn native_missing_route_after_actual_audit_seal_requires_cold_owned_read() -> TestResult {
    let mut f = Fixture::start(true, false)?;
    let writer = f.admin.clone();
    let _hook = after_audit(move |service, response| {
        assert!(response.status == 404);
        assert_eq!(
            call(service, "POST", "sys/seal", &writer, json!({})).status,
            204
        );
    })?;
    expect(
        f.admin("GET", "absent/seal", json!({})),
        503,
        "sealed after actual negative audit",
    )?;
    assert!(f.service.state.is_none());
    let mut f = f.restart()?;
    negative(f.admin("GET", "absent/seal", json!({})))?;
    f.sentinel()
}

#[path = "service_native_missing_route_namespace_tests.rs"]
mod namespace_tests;
