//! Actual configured File V6 and public capability handlers. Credentials and
//! policies are issued through Service, including immutable target inspection,
//! finite-use persistence, cold reopen and real post-response-audit changes.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};

pub(in crate::service) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SECONDS: u64 = 15;
const SELF: &str = "sys/capabilities-self";
const TOKEN: &str = "sys/capabilities";
const ACCESSOR: &str = "sys/capabilities-accessor";
const RESOURCE: &str = "secret/data/kept";
const SUBJECT_POLICY: &str = r#"
path "sys/capabilities-self" { capabilities=["update"] }
path "secret/data/kept" { capabilities=["read"] }
"#;
const INSPECTOR_POLICY: &str = r#"
path "sys/capabilities" { capabilities=["update"] }
path "sys/capabilities-accessor" { capabilities=["update"] }
path "sys/capabilities-self" { capabilities=["update"] }
"#;
const PASSWORD: &str = "capabilities-owned-fixture-password";

type AfterAudit = Box<dyn FnOnce(&mut Service, &mut Response)>;
thread_local! { static AFTER_AUDIT: RefCell<Option<AfterAudit>> = RefCell::new(None); }

pub(super) fn after_actual_capabilities_audit(service: &mut Service, response: &mut Response) {
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
            return Err("capabilities audit hook already armed".into());
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
    assert!(started.elapsed() < Duration::from_secs(SECONDS));
    assert!(service.pending_native_auth_delivery.is_none());
    assert!(service.native_request_binding.is_none());
    response
}

fn expect(response: Response, status: u16, stage: &str) -> TestResult<Response> {
    if response.status != status {
        return Err(format!(
            "native capabilities stage={stage} expected={status} observed={}",
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
        .ok_or("missing actual fixture credential")?;
    let Value::String(secret) = value.take() else {
        return Err("actual fixture credential has wrong type".into());
    };
    if secret.is_empty() {
        return Err("actual fixture credential is empty".into());
    }
    Ok(Zeroizing::new(secret))
}

fn capabilities(response: Response, path: &str, expected: &[&str]) -> TestResult {
    let response = expect(response, 200, "original capability projection")?;
    assert_eq!(response.body["data"][path], json!(expected));
    assert_eq!(response.body[path], json!(expected));
    assert_eq!(response.body["data"]["capabilities"], json!(expected));
    assert_eq!(response.body["capabilities"], json!(expected));
    assert!(response.body.get("auth").is_none());
    assert!(response.unwrapped_json.is_none() && response.response_headers.is_empty());
    Ok(())
}

fn invalid_inspection(response: Response, target: &str) -> TestResult {
    let response = expect(response, 400, "official 2.7.1 invalid inspection target")?;
    assert_eq!(
        response.body["errors"],
        json!([format!("1 error occurred:\n\t* invalid {target}\n\n")])
    );
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("capabilities").is_none());
    assert!(response.unwrapped_json.is_none() && response.response_headers.is_empty());
    Ok(())
}

fn withheld(response: Response) -> TestResult {
    let response = expect(response, 503, "original post-audit inspection veto")?;
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("capabilities").is_none());
    assert!(response.body.get(RESOURCE).is_none());
    assert!(response.unwrapped_json.is_none() && response.response_headers.is_empty());
    assert!(response.consistency_index.is_none());
    Ok(())
}

fn assert_formal_file(service: &Service) -> TestResult {
    assert!(matches!(
        service.native_storage_profile,
        Some(NativeStorageProfile::File)
    ));
    assert!(service.native_root.is_some() && service.record_root.is_none());
    // Ordinary File startup retains this bound custody capsule. The caller
    // has activated through the public route or unsealed the persisted root.
    service
        .native_candidate_profile
        .as_ref()
        .ok_or("actual formal File custody capsule absent")?
        .check_environment(service)
        .map_err(|_| "actual formal File custody environment changed")?;
    assert!(!service.recovery_required && !service.audit_failed);
    Ok(())
}

struct Credential {
    raw: Zeroizing<String>,
    accessor: Zeroizing<String>,
}

struct Fixture {
    files: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
}
impl Fixture {
    fn start() -> TestResult<Self> {
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
            "actual File Shamir init",
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
            "actual File unseal",
        )?;
        expect(
            call(&mut service, "POST", "sys/init/ack", &admin, json!({})),
            204,
            "actual init acknowledgement",
        )?;
        expect(
            call(
                &mut service,
                "POST",
                "sys/mounts/secret",
                &admin,
                json!({"type":"kv","options":{"version":"2"}}),
            ),
            204,
            "actual seed KV2 mount",
        )?;
        expect(
            call(
                &mut service,
                "POST",
                RESOURCE,
                &admin,
                json!({"options":{"cas":0},"data":{"value":"capability-sentinel"}}),
            ),
            200,
            "actual seed KV2 version",
        )?;
        expect(
            call(
                &mut service,
                "POST",
                native_storage::ACTIVATE_PATH,
                &admin,
                json!({}),
            ),
            204,
            "actual configured File V6 activation",
        )?;
        assert_formal_file(&service)?;
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
    fn policy(&mut self, name: &str, text: &str) -> TestResult {
        expect(
            self.admin(
                "PUT",
                &format!("sys/policies/acl/{name}"),
                json!({"policy":text}),
            ),
            204,
            "actual capability policy",
        )?;
        Ok(())
    }
    fn issue(&mut self, policy: &str, uses: u64, ttl: &str) -> TestResult<Credential> {
        let mut issued = expect(
            self.admin(
                "POST",
                "auth/token/create",
                json!({"policies":[policy],"no_default_policy":true,"num_uses":uses,"ttl":ttl}),
            ),
            200,
            "actual capability actor/target",
        )?;
        let raw = take_secret(&mut issued, "/auth/client_token")?;
        let accessor = take_secret(&mut issued, "/auth/accessor")?;
        erase_json(&mut issued.body);
        Ok(Credential { raw, accessor })
    }
    fn remaining(&mut self, credential: &Credential) -> TestResult<u64> {
        let response = expect(
            self.admin(
                "POST",
                "auth/token/lookup-accessor",
                json!({"accessor":credential.accessor.as_str()}),
            ),
            200,
            "actual target count lookup",
        )?;
        response.body["data"]["num_uses"]
            .as_u64()
            .ok_or_else(|| "actual finite-use projection absent".into())
    }
    fn userpass(&mut self, kind: &str) -> TestResult<(Zeroizing<String>, String)> {
        expect(
            self.admin("POST", "sys/auth/cap-up", json!({"type":"userpass"})),
            204,
            "actual Userpass mount",
        )?;
        expect(
            self.admin(
                "POST",
                "auth/cap-up/users/alice",
                json!({"password":PASSWORD,"policies":["subject"],"token_type":kind,
                "token_ttl":120,"token_max_ttl":600,"token_num_uses":0}),
            ),
            204,
            "actual Userpass subject",
        )?;
        let mut login = expect(
            self.actor(
                "",
                "POST",
                "auth/cap-up/login/alice",
                json!({"password":PASSWORD}),
            ),
            200,
            "actual Userpass login",
        )?;
        assert_eq!(login.body["auth"]["token_type"], kind);
        let entity = login.body["auth"]["entity_id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("actual Userpass entity")?
            .to_owned();
        let raw = take_secret(&mut login, "/auth/client_token")?;
        erase_json(&mut login.body);
        Ok((raw, entity))
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
            "actual cold native reopen",
        )?;
        assert_formal_file(&self.service)?;
        Ok(self)
    }
    fn sentinel(&mut self) -> TestResult {
        let response = expect(self.admin("GET", RESOURCE, json!({})), 200, "retained KV")?;
        assert_eq!(
            response.body["data"]["data"],
            json!({"value":"capability-sentinel"})
        );
        assert_eq!(response.body["data"]["metadata"]["version"], 1);
        Ok(())
    }
}

#[test]
fn native_capabilities_formal_file_three_routes_preserve_target_uses_and_cold_policy() -> TestResult
{
    let mut f = Fixture::start()?;
    f.policy("subject", SUBJECT_POLICY)?;
    f.policy("inspector", INSPECTOR_POLICY)?;
    let target = f.issue("subject", 1, "1h")?;
    let actor = f.issue("inspector", 0, "1h")?;
    capabilities(
        f.actor(
            &actor.raw,
            "POST",
            TOKEN,
            json!({"token":target.raw.as_str(),"paths":[RESOURCE]}),
        ),
        RESOURCE,
        &["read"],
    )?;
    capabilities(
        f.actor(
            &actor.raw,
            "PUT",
            ACCESSOR,
            json!({"accessor":target.accessor.as_str(),"path":RESOURCE}),
        ),
        RESOURCE,
        &["read"],
    )?;
    assert_eq!(f.remaining(&target)?, 1);
    let changed = r#"path "sys/capabilities-self" { capabilities=["update"] }
path "secret/data/kept" { capabilities=["read","update"] }"#;
    f.policy("subject", changed)?;
    capabilities(
        f.actor(
            &actor.raw,
            "POST",
            TOKEN,
            json!({"token":target.raw.as_str(),"paths":[RESOURCE]}),
        ),
        RESOURCE,
        &["read", "update"],
    )?;
    assert_eq!(f.remaining(&target)?, 1);
    let mut f = f.restart()?;
    capabilities(
        f.actor(
            &actor.raw,
            "POST",
            ACCESSOR,
            json!({"accessor":target.accessor.as_str(),"paths":[RESOURCE]}),
        ),
        RESOURCE,
        &["read", "update"],
    )?;
    assert_eq!(f.remaining(&target)?, 1);
    // Foreign reads consumed no target uses. Its one self admission now spends
    // that use; actual Bao 2.7.1 returns 400 because self target lookup sees zero.
    invalid_inspection(
        f.actor(&target.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
        "token",
    )?;
    let mut f = f.restart()?;
    expect(
        f.actor(&target.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
        403,
        "last use remains spent after cold reopen",
    )?;
    f.sentinel()
}

#[test]
fn native_capabilities_finite_actor_consumes_once_and_keeps_original_parser_errors() -> TestResult {
    let mut f = Fixture::start()?;
    f.policy("subject", SUBJECT_POLICY)?;
    f.policy("inspector", INSPECTOR_POLICY)?;
    // The official 2.7.1 oracle distinguishes self's target lookup from a
    // one-use inspector querying another credential. Both pay one actor use.
    let two_use = f.issue("subject", 2, "1h")?;
    capabilities(
        f.actor(&two_use.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
        RESOURCE,
        &["read"],
    )?;
    assert_eq!(f.remaining(&two_use)?, 1);
    invalid_inspection(
        f.actor(&two_use.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
        "token",
    )?;
    expect(
        f.actor(&two_use.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
        403,
        "official two-use self sequence is 200 then 400 then 403",
    )?;
    let target = f.issue("subject", 2, "1h")?;
    for path in [TOKEN, ACCESSOR] {
        let actor = f.issue("inspector", 1, "1h")?;
        let body = if path == TOKEN {
            json!({"token":target.raw.as_str(),"paths":RESOURCE})
        } else {
            json!({"accessor":target.accessor.as_str(),"paths":RESOURCE})
        };
        capabilities(
            f.actor(&actor.raw, "POST", path, body.clone()),
            RESOURCE,
            &["read"],
        )?;
        assert_eq!(f.remaining(&target)?, 2);
        expect(
            f.actor(&actor.raw, "POST", path, body),
            403,
            "non-self actor final use spent exactly once",
        )?;
    }
    let actor = f.issue("inspector", 0, "1h")?;
    let scalar = expect(
        f.actor(
            &actor.raw,
            "POST",
            SELF,
            json!({"paths":[17],"token":false,"ignored":true}),
        ),
        200,
        "original weak slice and self selector spelling",
    )?;
    assert_eq!(scalar.body["data"]["17"], json!(["deny"]));
    assert!(scalar.body["warnings"].is_array());
    for (method, path, body, status) in [
        ("POST", SELF, json!({}), 400),
        ("POST", SELF, json!({"paths":[{}]}), 400),
        ("POST", TOKEN, json!({"paths":[RESOURCE],"token":{}}), 400),
        (
            "POST",
            ACCESSOR,
            json!({"paths":[RESOURCE],"accessor":[]}),
            400,
        ),
        (
            "POST",
            ACCESSOR,
            json!({"paths":[RESOURCE],"accessor":"missing"}),
            400,
        ),
        ("GET", SELF, json!({"paths":[RESOURCE]}), 405),
    ] {
        // Use the administrator for method/shape diagnostics so ACL denial
        // cannot substitute for the original backend's 400 or 405.
        expect(
            f.admin(method, path, body),
            status,
            "original capability diagnostics",
        )?;
    }
    let finite_error = f.issue("inspector", 1, "1h")?;
    expect(
        f.actor(&finite_error.raw, "POST", SELF, json!({"paths":[]})),
        400,
        "original malformed self request",
    )?;
    expect(
        f.actor(&finite_error.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
        403,
        "malformed request retains actual finite-use charge",
    )?;
    expect(
        f.actor("", "POST", SELF, json!({"paths":[RESOURCE]})),
        403,
        "missing actor is not root",
    )?;
    expect(
        f.actor(
            &target.raw,
            "POST",
            TOKEN,
            json!({"token":actor.raw.as_str(),"paths":[RESOURCE]}),
        ),
        403,
        "self-only subject cannot inspect another actor",
    )?;
    f.sentinel()
}

#[test]
fn native_capabilities_current_identity_and_real_batch_inspection_survive_cold_reopen() -> TestResult
{
    let mut f = Fixture::start()?;
    f.policy(
        "subject",
        r#"path "sys/capabilities-self" { capabilities=["update"] }"#,
    )?;
    f.policy(
        "identity-reader",
        r#"path "secret/data/kept" { capabilities=["read"] }"#,
    )?;
    f.policy("inspector", INSPECTOR_POLICY)?;
    let actor = f.issue("inspector", 0, "1h")?;
    let (batch, entity) = f.userpass("batch")?;
    assert!(batch.starts_with("hvb."));
    capabilities(
        f.actor(
            &actor.raw,
            "POST",
            TOKEN,
            json!({"token":batch.as_str(),"paths":[RESOURCE]}),
        ),
        RESOURCE,
        &["deny"],
    )?;
    let group = expect(
        f.admin(
            "POST",
            "identity/group",
            json!({"name":"capability-readers","type":"internal","policies":["identity-reader"],
            "member_entity_ids":[entity]}),
        ),
        200,
        "actual Identity group",
    )?;
    let group = group.body["data"]["id"]
        .as_str()
        .ok_or("actual group id")?
        .to_owned();
    capabilities(
        f.actor(&batch, "POST", SELF, json!({"paths":[RESOURCE]})),
        RESOURCE,
        &["read"],
    )?;
    capabilities(
        f.actor(
            &actor.raw,
            "POST",
            TOKEN,
            json!({"token":batch.as_str(),"paths":[RESOURCE]}),
        ),
        RESOURCE,
        &["read"],
    )?;
    let mut f = f.restart()?;
    capabilities(
        f.actor(&batch, "POST", SELF, json!({"paths":[RESOURCE]})),
        RESOURCE,
        &["read"],
    )?;
    expect(
        f.admin(
            "POST",
            &format!("identity/group/id/{group}"),
            json!({"member_entity_ids":[]}),
        ),
        204,
        "actual group removal",
    )?;
    capabilities(
        f.actor(
            &actor.raw,
            "POST",
            TOKEN,
            json!({"token":batch.as_str(),"paths":[RESOURCE]}),
        ),
        RESOURCE,
        &["deny"],
    )?;
    f.sentinel()
}

#[test]
fn native_capabilities_actual_post_audit_policy_and_identity_changes_withhold_results() -> TestResult
{
    for identity_change in [false, true] {
        let mut f = Fixture::start()?;
        f.policy("subject", SUBJECT_POLICY)?;
        f.policy("inspector", INSPECTOR_POLICY)?;
        let actor = f.issue("inspector", 0, "1h")?;
        let (target, entity) = if identity_change {
            f.userpass("service")?
        } else {
            (f.issue("subject", 0, "1h")?.raw, String::new())
        };
        let writer = f.admin.clone();
        let observed = Arc::new(AtomicBool::new(false));
        let hook_observed = Arc::clone(&observed);
        let _hook =
            after_audit(move |service, response| {
                assert_eq!(response.status, 200);
                assert_eq!(response.body["data"][RESOURCE], json!(["read"]));
                hook_observed.store(true, Ordering::SeqCst);
                let changed =
                    if identity_change {
                        service.handle(
                            "POST",
                            &format!("identity/entity/id/{entity}"),
                            "",
                            &writer,
                            json!({"disabled":true}),
                        )
                    } else {
                        service.handle("PUT", "sys/policies/acl/subject", "", &writer,
                    json!({"policy":r#"path "sys/capabilities-self" { capabilities=["update"] }
path "secret/data/kept" { capabilities=["deny"] }"#}))
                    };
                assert_eq!(changed.status, 204);
            })?;
        withheld(f.actor(
            &actor.raw,
            "POST",
            TOKEN,
            json!({"token":target.as_str(),"paths":[RESOURCE]}),
        ))?;
        assert!(observed.load(Ordering::SeqCst));
        let mut f = f.restart()?;
        let response = f.actor(
            &actor.raw,
            "POST",
            TOKEN,
            json!({"token":target.as_str(),"paths":[RESOURCE]}),
        );
        if identity_change {
            // 2.7.1 rejects a disabled target before loading its ACL; a foreign
            // capability lookup exposes the exact invalid-token error. The
            // post-audit result above must still have been withheld with 503.
            let response = expect(response, 400, "disabled target after cold reopen")?;
            assert_eq!(response.body["errors"], json!(["invalid token"]));
            assert!(response.body.get("data").is_none());
            assert!(response.body.get("capabilities").is_none());
            assert!(response.body.get(RESOURCE).is_none());
            assert!(response.body.get("auth").is_none());
            assert!(response.unwrapped_json.is_none() && response.response_headers.is_empty());
        } else {
            capabilities(response, RESOURCE, &["deny"])?;
        }
        f.sentinel()?;
    }
    Ok(())
}

#[test]
fn native_capabilities_actual_post_audit_actor_and_target_revoke_remain_cold() -> TestResult {
    for revoke_actor in [false, true] {
        let mut f = Fixture::start()?;
        f.policy("subject", SUBJECT_POLICY)?;
        f.policy("inspector", INSPECTOR_POLICY)?;
        let target = f.issue("subject", 1, "1h")?;
        let actor = f.issue("inspector", 0, "1h")?;
        let writer = f.admin.clone();
        let revoked = if revoke_actor {
            actor.raw.clone()
        } else {
            target.raw.clone()
        };
        let observed = Arc::new(AtomicBool::new(false));
        let hook_observed = Arc::clone(&observed);
        let _hook = after_audit(move |service, response| {
            assert_eq!(response.status, 200);
            hook_observed.store(true, Ordering::SeqCst);
            let revoked = service.handle(
                "POST",
                "auth/token/revoke",
                "",
                &writer,
                json!({"token":revoked.as_str()}),
            );
            assert_eq!(revoked.status, 204);
        })?;
        withheld(f.actor(
            &actor.raw,
            "POST",
            ACCESSOR,
            json!({"accessor":target.accessor.as_str(),"paths":[RESOURCE]}),
        ))?;
        assert!(observed.load(Ordering::SeqCst));
        let mut f = f.restart()?;
        let revoked = if revoke_actor {
            actor.raw.as_str()
        } else {
            target.raw.as_str()
        };
        expect(
            f.actor(revoked, "POST", SELF, json!({"paths":[RESOURCE]})),
            403,
            "actual revocation survives cold reopen",
        )?;
        if revoke_actor {
            assert_eq!(f.remaining(&target)?, 1);
            invalid_inspection(
                f.actor(&target.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
                "token",
            )?;
            expect(
                f.actor(&target.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
                403,
                "only the later self admission spends the untouched target use",
            )?;
        } else {
            invalid_inspection(
                f.actor(
                    &actor.raw,
                    "POST",
                    TOKEN,
                    json!({"token":target.raw.as_str(),"paths":[RESOURCE]}),
                ),
                "token",
            )?;
            invalid_inspection(
                f.actor(
                    &actor.raw,
                    "POST",
                    ACCESSOR,
                    json!({"accessor":target.accessor.as_str(),"paths":[RESOURCE]}),
                ),
                "accessor",
            )?;
        }
        f.sentinel()?;
    }
    Ok(())
}

#[test]
fn native_capabilities_actual_post_audit_target_renewal_retains_metadata_custody() -> TestResult {
    let mut f = Fixture::start()?;
    f.policy("subject", SUBJECT_POLICY)?;
    f.policy("inspector", INSPECTOR_POLICY)?;
    let target = f.issue("subject", 2, "1h")?;
    let actor = f.issue("inspector", 0, "1h")?;
    let before = expect(
        f.admin(
            "POST",
            "auth/token/lookup-accessor",
            json!({"accessor":target.accessor.as_str()}),
        ),
        200,
        "original target deadline",
    )?;
    let before = before.body["data"]["expire_time_unix"]
        .as_u64()
        .ok_or("original actual target expiry")?;
    let writer = f.admin.clone();
    let renewed = target.raw.clone();
    let observed = Arc::new(AtomicBool::new(false));
    let hook_observed = Arc::clone(&observed);
    let _hook = after_audit(move |service, response| {
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"][RESOURCE], json!(["read"]));
        hook_observed.store(true, Ordering::SeqCst);
        // The result's policies and subject identity do not change. A real
        // target renewal still publishes different Auth metadata and cannot be
        // accepted as this request's one proven terminal-clock successor.
        let mut renewal = service.handle(
            "POST",
            "auth/token/renew",
            "",
            &writer,
            json!({"token":renewed.as_str(),"increment":"30m"}),
        );
        assert_eq!(renewal.status, 200);
        assert_eq!(renewal.body["auth"]["lease_duration"], 1800);
        erase_json(&mut renewal.body);
    })?;
    withheld(f.actor(
        &actor.raw,
        "POST",
        TOKEN,
        json!({"token":target.raw.as_str(),"paths":[RESOURCE]}),
    ))?;
    assert!(observed.load(Ordering::SeqCst));
    let mut f = f.restart()?;
    let after = expect(
        f.admin(
            "POST",
            "auth/token/lookup-accessor",
            json!({"accessor":target.accessor.as_str()}),
        ),
        200,
        "actual renewed target survives cold reopen",
    )?;
    assert!(
        after.body["data"]["expire_time_unix"]
            .as_u64()
            .ok_or("renewed actual target expiry")?
            < before
    );
    assert_eq!(f.remaining(&target)?, 2);
    capabilities(
        f.actor(
            &actor.raw,
            "POST",
            ACCESSOR,
            json!({"accessor":target.accessor.as_str(),"paths":[RESOURCE]}),
        ),
        RESOURCE,
        &["read"],
    )?;
    f.sentinel()
}

#[test]
fn native_capabilities_original_actor_and_target_expire_after_actual_audit() -> TestResult {
    for expire_actor in [false, true] {
        let mut f = Fixture::start()?;
        f.policy("subject", SUBJECT_POLICY)?;
        f.policy("inspector", INSPECTOR_POLICY)?;
        let target = f.issue("subject", 0, if expire_actor { "1h" } else { "3s" })?;
        let actor = f.issue("inspector", 0, if expire_actor { "3s" } else { "1h" })?;
        let observed = Arc::new(AtomicBool::new(false));
        let hook_observed = Arc::clone(&observed);
        let _hook = after_audit(move |_service, response| {
            assert_eq!(response.status, 200);
            hook_observed.store(true, Ordering::SeqCst);
            // Real time crosses the issued three-second grant inside the same
            // original 15-second request. Neither clock nor proof is replaced.
            std::thread::sleep(Duration::from_millis(3100));
        })?;
        withheld(f.actor(
            &actor.raw,
            "POST",
            TOKEN,
            json!({"token":target.raw.as_str(),"paths":[RESOURCE]}),
        ))?;
        assert!(observed.load(Ordering::SeqCst));
        let mut f = f.restart()?;
        let expired = if expire_actor {
            actor.raw.as_str()
        } else {
            target.raw.as_str()
        };
        expect(
            f.actor(expired, "POST", SELF, json!({"paths":[RESOURCE]})),
            403,
            "expired original credential stays expired after cold reopen",
        )?;
        f.sentinel()?;
    }
    Ok(())
}

#[test]
fn native_capabilities_actual_audit_projection_tampering_cannot_replace_owned_reply() -> TestResult
{
    for status_change in [false, true] {
        let mut f = Fixture::start()?;
        f.policy("subject", SUBJECT_POLICY)?;
        let actor = f.issue("subject", 2, "1h")?;
        let observed = Arc::new(AtomicBool::new(false));
        let hook_observed = Arc::clone(&observed);
        let _hook = after_audit(move |_service, response| {
            assert_eq!(response.status, 200);
            hook_observed.store(true, Ordering::SeqCst);
            if status_change {
                response.status = 204;
            } else {
                response.body["data"][RESOURCE] = json!(["root"]);
            }
        })?;
        withheld(f.actor(&actor.raw, "POST", SELF, json!({"paths":[RESOURCE]})))?;
        assert!(observed.load(Ordering::SeqCst));
        let mut f = f.restart()?;
        assert_eq!(f.remaining(&actor)?, 1);
        invalid_inspection(
            f.actor(&actor.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
            "token",
        )?;
        expect(
            f.actor(&actor.raw, "POST", SELF, json!({"paths":[RESOURCE]})),
            403,
            "failed audited delivery does not refund original finite use",
        )?;
        f.sentinel()?;
    }
    Ok(())
}

#[test]
fn native_capabilities_actual_http_number_spelling_and_original_parameter_acl() -> TestResult {
    fn wire(f: &mut Fixture, token: &str, payload: &str) -> TestResult<Response> {
        let wire = Zeroizing::new(format!(
            "POST /v1/sys/capabilities-self HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len(),
        ));
        let deadline = Instant::now() + Duration::from_secs(SECONDS);
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        let response =
            crate::http::logical_data_wire_dispatch_fixture(wire.as_bytes(), |request| {
                assert_eq!(request.method, "POST");
                assert_eq!(request.path, SELF);
                let execution = f.service.begin_request_before(request, deadline, true);
                f.service.finish_synchronous_request(execution)
            })?;
        assert!(Instant::now() < deadline);
        assert!(f.service.pending_native_auth_delivery.is_none());
        Ok(response)
    }
    let mut f = Fixture::start()?;
    f.policy("inspector", INSPECTOR_POLICY)?;
    let actor = f.issue("inspector", 0, "1h")?;
    let response = expect(
        wire(
            &mut f,
            &actor.raw,
            r#"{"paths":[1.00,1E+08,-0,9007199254740993],"token":1E-08}"#,
        )?,
        200,
        "actual HTTP carrier preserves original weak spellings",
    )?;
    for path in ["1.00", "1E+08", "-0", "9007199254740993"] {
        assert_eq!(response.body["data"][path], json!(["deny"]));
    }
    assert!(response.body["data"].get("1").is_none());
    assert!(response.body["data"].get("100000000.0").is_none());
    assert!(response.body["data"].get("0").is_none());
    f.policy(
        "restricted",
        r#"path "sys/capabilities-self" {
capabilities=["update"]
allowed_parameters={"path"=["1.00"]}
}"#,
    )?;
    let restricted = f.issue("restricted", 0, "1h")?;
    // Numeric input cannot acquire string-ACL permission from its transport
    // spelling. The original numeric body must be authorized before conversion.
    expect(
        wire(&mut f, &restricted.raw, r#"{"path":1.00}"#)?,
        403,
        "original numeric parameter remains denied",
    )?;
    capabilities(
        wire(&mut f, &restricted.raw, r#"{"path":"1.00"}"#)?,
        "1.00",
        &["deny"],
    )?;
    f.sentinel()
}
