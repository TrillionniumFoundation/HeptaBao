//! Actual formal File profile, public activation, Service domain operations,
//! durable cold reopens and original audit/Actor/deadline custody. Synthetic
//! credentials and crypto outputs are never included in assertion diagnostics.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::{Root, bootstrap_unmounted};
use std::cell::RefCell;
use std::io::{self, Read};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SECONDS: u64 = 15;
const PLAINTEXT: &str = "c3ludGhldGljLXRyYW5zaXQ=";
type AfterAudit = Box<dyn FnOnce(&mut Service)>;
thread_local! { static AFTER_AUDIT: RefCell<Option<AfterAudit>> = RefCell::new(None); }

pub(super) fn after_actual_transit_audit(service: &mut Service) {
    let hook = AFTER_AUDIT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        // Interleave an actual second request after actual publication/audit.
        // The outer capsule retains its Actor, proof, clock and checkpoint.
        assert!(service.native_failure_notice.is_none());
        let binding = service.native_request_binding.take();
        assert!(binding.is_some());
        assert!(service.pending_native_auth_delivery.is_none());
        hook(service);
        assert!(service.native_request_binding.is_none());
        assert!(service.native_failure_notice.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        service.native_request_binding = binding;
    }
}
struct HookGuard;
impl Drop for HookGuard {
    fn drop(&mut self) {
        AFTER_AUDIT.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn after_audit(hook: impl FnOnce(&mut Service) + 'static) -> TestResult<HookGuard> {
    AFTER_AUDIT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("Transit audit hook already armed".into());
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
        "original Transit request deadline"
    );
    response
}
fn expect(response: Response, status: u16, label: &str) -> TestResult<Response> {
    if response.status != status {
        return Err(format!(
            "native Transit stage={label} expected={status} observed={}",
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
        .ok_or("Transit response field")?;
    let Value::String(secret) = value.take() else {
        return Err("Transit response field type".into());
    };
    if secret.is_empty() {
        return Err("Transit response field empty".into());
    }
    Ok(Zeroizing::new(secret))
}
fn initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    initialized_with_retained_floor(false)
}
fn initialized_with_retained_floor(
    retain_floor: bool,
) -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
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
            json!({"type":"transit","cas_revision":0,"config":{"options":null,"default_lease_ttl":"","max_lease_ttl":"","force_no_cache":false}}),
        ),
        204,
        "formal-Transit-enable",
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
fn encrypt(service: &mut Service, root: &str, key: &str) -> TestResult<Zeroizing<String>> {
    let mut response = expect(
        call(
            service,
            "POST",
            &format!("transit/encrypt/{key}"),
            root,
            json!({"plaintext":PLAINTEXT}),
        ),
        200,
        "actual-encryption",
    )?;
    take_secret(&mut response, "/data/ciphertext")
}
fn decrypt(service: &mut Service, root: &str, key: &str, cipher: &str) -> TestResult {
    let mut response = expect(
        call(
            service,
            "POST",
            &format!("transit/decrypt/{key}"),
            root,
            json!({"ciphertext":cipher}),
        ),
        200,
        "actual-decryption",
    )?;
    assert!(response.body["data"]["plaintext"].as_str() == Some(PLAINTEXT));
    erase_json(&mut response.body);
    Ok(())
}
fn descriptor(service: &mut Service, root: &str, key: &str, version: u64) -> TestResult {
    let response = expect(
        call(
            service,
            "GET",
            &format!("transit/keys/{key}"),
            root,
            json!({}),
        ),
        200,
        "key-descriptor",
    )?;
    assert_eq!(response.body["data"]["latest_version"], version);
    Ok(())
}
fn token(service: &mut Service, root: &str, policy: &str) -> TestResult<Zeroizing<String>> {
    expect(
        call(
            service,
            "PUT",
            "sys/policies/acl/transit-owner",
            root,
            json!({"policy":policy}),
        ),
        204,
        "Transit-policy",
    )?;
    let mut issued = expect(
        call(
            service,
            "POST",
            "auth/token/create",
            root,
            json!({"policies":["transit-owner"],"no_default_policy":true,"ttl":"1h"}),
        ),
        200,
        "actual-Transit-actor",
    )?;
    take_secret(&mut issued, "/auth/client_token")
}

#[test]
fn native_transit_formal_file_registry_crypto_and_two_cold_reopens() -> TestResult {
    let (files, mut service, key, root) = initialized()?;
    let graphs = service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    enable(&mut service, &root, "transit")?;
    let mounted = expect(
        call(&mut service, "GET", "sys/mounts/transit", &root, json!({})),
        200,
        "Transit-registry-read",
    )?;
    assert_eq!(mounted.body["data"]["type"], "transit");
    assert_eq!(mounted.body["data"]["incarnation"], 1);
    assert_eq!(mounted.body["data"]["revision"], 1);
    expect(
        call(
            &mut service,
            "POST",
            "sys/mounts/transit/tune",
            &root,
            json!({"description":"owned local Transit","cas_revision":1}),
        ),
        204,
        "Transit-registry-tune",
    )?;
    let first = encrypt(&mut service, &root, "durable")?;
    expect(
        call(
            &mut service,
            "POST",
            "transit/keys/durable/rotate",
            &root,
            json!({}),
        ),
        200,
        "Transit-rotate",
    )?;
    let second = encrypt(&mut service, &root, "durable")?;
    assert!(first.starts_with("vault:v1:") && second.starts_with("vault:v2:"));
    decrypt(&mut service, &root, "durable", &first)?;
    expect(
        call(
            &mut service,
            "POST",
            "transit/keys/signing",
            &root,
            json!({"type":"ed25519"}),
        ),
        200,
        "Transit-signing-key",
    )?;
    let mut signed = expect(
        call(
            &mut service,
            "POST",
            "transit/sign/signing",
            &root,
            json!({"input":PLAINTEXT}),
        ),
        200,
        "Transit-sign",
    )?;
    let signature = take_secret(&mut signed, "/data/signature")?;
    let verified = expect(
        call(
            &mut service,
            "POST",
            "transit/verify/signing",
            &root,
            json!({"input":PLAINTEXT,"signature":signature.as_str()}),
        ),
        200,
        "Transit-verify",
    )?;
    assert_eq!(verified.body["data"]["valid"], true);
    expect(
        call(
            &mut service,
            "POST",
            "transit/config/cache",
            &root,
            json!({"size":16}),
        ),
        200,
        "Transit-policy-cache",
    )?;
    assert!(service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    sentinel(&mut service, &root)?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    descriptor(&mut service, &root, "durable", 2)?;
    decrypt(&mut service, &root, "durable", &first)?;
    decrypt(&mut service, &root, "durable", &second)?;
    let tuned = expect(
        call(&mut service, "GET", "sys/mounts/transit", &root, json!({})),
        200,
        "cold-registry",
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
        "Transit-disable",
    )?;
    enable(&mut service, &root, "retire")?;
    let recreated = expect(
        call(&mut service, "GET", "sys/mounts/retire", &root, json!({})),
        200,
        "Transit-recreated",
    )?;
    assert_eq!(recreated.body["data"]["incarnation"], 2);
    expect(
        call(
            &mut service,
            "POST",
            "transit/keys/durable/config",
            &root,
            json!({"min_decryption_version":2,"min_encryption_version":2}),
        ),
        200,
        "Transit-key-floor",
    )?;
    expect(
        call(
            &mut service,
            "POST",
            "transit/decrypt/durable",
            &root,
            json!({"ciphertext":first.as_str()}),
        ),
        400,
        "old-key-floor-refusal",
    )?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    decrypt(&mut service, &root, "durable", &second)?;
    expect(
        call(
            &mut service,
            "POST",
            "transit/decrypt/durable",
            &root,
            json!({"ciphertext":first.as_str()}),
        ),
        400,
        "cold-key-floor-refusal",
    )?;
    sentinel(&mut service, &root)
}

#[test]
fn native_transit_partial_batch_commits_success_and_keeps_plaintext_under_authority() -> TestResult
{
    let (files, mut service, key, root) = initialized()?;
    enable(&mut service, &root, "transit")?;
    let mut mixed = expect(
        call(
            &mut service,
            "POST",
            "transit/encrypt/batch",
            &root,
            json!({"batch_input":[{"plaintext":PLAINTEXT},{"plaintext":"!invalid-base64!"}]}),
        ),
        400,
        "mixed-encryption",
    )?;
    assert!(mixed.body["data"]["batch_results"][1]["error"].is_string());
    let cipher = take_secret(&mut mixed, "/data/batch_results/0/ciphertext")?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    descriptor(&mut service, &root, "batch", 1)?;
    let mut plain = expect(
        call(
            &mut service,
            "POST",
            "transit/decrypt/batch",
            &root,
            json!({"batch_input":[{"ciphertext":cipher.as_str()},{"ciphertext":"invalid"}]}),
        ),
        400,
        "mixed-decryption",
    )?;
    assert!(plain.body["data"]["batch_results"][0]["plaintext"].as_str() == Some(PLAINTEXT));
    assert!(plain.body["data"]["batch_results"][1]["error"].is_string());
    erase_json(&mut plain.body);
    sentinel(&mut service, &root)
}

#[test]
fn native_transit_acl_source_create_capability_cas_and_refusal_scope() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    enable(&mut service, &root, "transit")?;
    let actor = token(
        &mut service,
        &root,
        r#"path "transit/keys/created" { capabilities=["create"] }
path "sys/mounts/forbidden" { capabilities=["update","read","delete"] }"#,
    )?;
    expect(
        call(
            &mut service,
            "POST",
            "transit/keys/created",
            &actor,
            json!({}),
        ),
        200,
        "create-only-original-capability",
    )?;
    expect(
        call(
            &mut service,
            "POST",
            "transit/keys/created",
            &actor,
            json!({}),
        ),
        403,
        "existing-key-update-denied",
    )?;
    expect(
        call(
            &mut service,
            "POST",
            "sys/mounts/forbidden",
            &actor,
            json!({"type":"transit"}),
        ),
        403,
        "Transit-mount-sudo-required",
    )?;
    expect(
        call(&mut service, "GET", "transit/keys/created", "", json!({})),
        403,
        "Transit-missing-actor",
    )?;
    let before = service.native_root.as_ref().ok_or("native root")?.clone();
    expect(
        call(
            &mut service,
            "POST",
            "sys/mounts/unsupported",
            &root,
            json!({"type":"kubernetes"}),
        ),
        501,
        "unmigrated-owner-refused",
    )?;
    expect(
        call(
            &mut service,
            "POST",
            "sys/mounts/transit/tune",
            &root,
            json!({"description":"stale","cas_revision":99}),
        ),
        409,
        "Transit-CAS-refused",
    )?;
    expect(
        call(
            &mut service,
            "POST",
            "transit/keys/external",
            &root,
            json!({"type":"external-key"}),
        ),
        400,
        "external-key-source-refused",
    )?;
    let after = service.native_root.as_ref().ok_or("native root")?;
    assert!(before.kv1 == after.kv1 && before.kv2 == after.kv2);
    assert_eq!(before.owners[2].domain, OwnerDomain::Engines);
    assert_eq!(after.owners[2].domain, OwnerDomain::Engines);
    assert!(serde_json::to_vec(&before.owners[2])? == serde_json::to_vec(&after.owners[2])?);
    sentinel(&mut service, &root)
}

#[test]
fn native_transit_after_audit_revocation_vetoes_partial_plaintext() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    enable(&mut service, &root, "transit")?;
    let cipher = encrypt(&mut service, &root, "revocable")?;
    let actor = token(
        &mut service,
        &root,
        r#"path "transit/decrypt/revocable" { capabilities=["update"] }"#,
    )?;
    let revoke_root = root.clone();
    let revoke_actor = actor.clone();
    let _hook = after_audit(move |service| {
        let revoked = call(
            service,
            "POST",
            "auth/token/revoke",
            &revoke_root,
            json!({"token":revoke_actor.as_str()}),
        );
        assert_eq!(revoked.status, 204, "actual post-audit revocation");
    })?;
    let response = expect(
        call(
            &mut service,
            "POST",
            "transit/decrypt/revocable",
            &actor,
            json!({"batch_input":[{"ciphertext":cipher.as_str()},{"ciphertext":"invalid"}]}),
        ),
        503,
        "audited-partial-response-veto",
    )?;
    assert!(response.body.get("data").is_none());
    expect(
        call(
            &mut service,
            "POST",
            "transit/decrypt/revocable",
            &actor,
            json!({"ciphertext":cipher.as_str()}),
        ),
        403,
        "revoked-actor-remains-denied",
    )?;
    decrypt(&mut service, &root, "revocable", &cipher)?;
    sentinel(&mut service, &root)
}

#[test]
fn native_transit_after_audit_seal_keeps_committed_rotation_but_vetoes_reply() -> TestResult {
    let (files, mut service, key, root) = initialized()?;
    enable(&mut service, &root, "transit")?;
    let cipher = encrypt(&mut service, &root, "sealed")?;
    let seal_root = root.clone();
    let _hook = after_audit(move |service| {
        assert_eq!(
            call(service, "POST", "sys/seal", &seal_root, json!({})).status,
            204
        );
    })?;
    let response = expect(
        call(
            &mut service,
            "POST",
            "transit/keys/sealed/rotate",
            &root,
            json!({}),
        ),
        503,
        "post-audit-seal-veto",
    )?;
    assert!(response.body.get("data").is_none());
    assert!(service.state.is_none());
    drop(service);
    let mut service = reopen(&files, &key)?;
    descriptor(&mut service, &root, "sealed", 2)?;
    decrypt(&mut service, &root, "sealed", &cipher)?;
    sentinel(&mut service, &root)
}

#[test]
fn native_transit_capsule_cannot_replay_rebind_or_change_other_owners() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    enable(&mut service, &root, "transit")?;
    enable(&mut service, &root, "peer")?;
    let source: EngineState = (*service.state.as_ref().ok_or("native state")?.engines).clone();
    let native = service.native_root.as_ref().ok_or("native root")?.clone();
    let until = Instant::now() + Duration::from_secs(SECONDS);
    let live = || Instant::now() < until;
    let clock = RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )?;
    let at = clock.observed_at()?;
    assert!(
        source
            .capture_native_transit_owner(
                "POST",
                "transit/keys/owned",
                &json!({}),
                &native,
                &|| false
            )
            .is_err()
    );
    let mut owner = source
        .capture_native_transit_owner("POST", "transit/keys/owned", &json!({}), &native, &live)
        .map_err(|error| error.message)?;
    assert!(owner.admit_candidate(&source, &live).is_err());
    assert!(owner.admit_root(&native, &native, &live).is_err());
    let mut candidate = source.clone();
    let response = owner
        .execute(&mut candidate, at, &live)
        .map_err(|error| error.message)?
        .ok_or("actual local operation")?;
    assert_eq!(response.status, 200);
    owner
        .admit_candidate(&candidate, &live)
        .map_err(|error| error.message)?;
    assert!(owner.execute(&mut candidate, at, &live).is_err());
    let mut peer_changed = candidate.clone();
    peer_changed
        .handle("", "POST", "peer/keys/unrelated", &json!({}), at.seconds())
        .map_err(|error| error.message)?;
    assert!(owner.admit_candidate(&peer_changed, &live).is_err());
    let mut registry_changed = candidate.clone();
    registry_changed
        .handle(
            "",
            "POST",
            "sys/mounts/not-owned",
            &json!({"type":"totp"}),
            at.seconds(),
        )
        .map_err(|error| error.message)?;
    assert!(owner.admit_candidate(&registry_changed, &live).is_err());
    let mut wrong_root = native.clone();
    wrong_root.replay_epoch = wrong_root
        .replay_epoch
        .checked_add(1)
        .ok_or("test epoch overflow")?;
    assert!(owner.admit_root(&native, &wrong_root, &live).is_err());
    assert!(owner.check_installed(&candidate, &native, &live).is_err());
    assert!(owner.admit_candidate(&candidate, &|| false).is_err());
    // No candidate from this negative custody exercise was submitted to storage.
    expect(
        call(&mut service, "GET", "transit/keys/owned", &root, json!({})),
        404,
        "unpublished-candidate-absent",
    )?;
    sentinel(&mut service, &root)
}
fn snapshot(
    service: &mut Service,
    token: &str,
    method: &str,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({})),
        Instant::now() + Duration::from_secs(SECONDS),
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(plan)) => Ok(plan),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Err(format!("Transit snapshot admission status={}", response.status).into())
        }
        NativeSnapshotAdmission::Redirect(_) => Err("unexpected local snapshot redirect".into()),
    }
}
#[test]
fn native_transit_snapshot_restores_kv_without_replacing_transit_keys() -> TestResult {
    let (files, mut service, key, root) = initialized()?;
    enable(&mut service, &root, "transit")?;
    let cipher = encrypt(&mut service, &root, "snapshot")?;
    let mut export = snapshot(&mut service, &root, "GET")?;
    let (result, archive) = export.execute_snapshot_transfer(&mut io::empty());
    expect(
        service.finish_external_request(*export, result),
        200,
        "Transit-snapshot-export",
    )?;
    let mut bytes = Zeroizing::new(Vec::new());
    archive.ok_or("Transit archive")?.read_to_end(&mut bytes)?;
    expect(
        call(
            &mut service,
            "POST",
            "secret/data/sentinel",
            &root,
            json!({"options":{"cas":1},"data":{"after_snapshot":true}}),
        ),
        200,
        "KV-after-snapshot",
    )?;
    let mut restore = snapshot(&mut service, &root, "POST")?;
    let (result, output) = restore.execute_snapshot_transfer(&mut &bytes[..]);
    assert!(output.is_none());
    expect(
        service.finish_external_request(*restore, result),
        200,
        "Transit-snapshot-restore",
    )?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    decrypt(&mut service, &root, "snapshot", &cipher)?;
    sentinel(&mut service, &root)
}
#[test]
fn native_transit_worker_rotation_uses_original_clock_and_persists() -> TestResult {
    let (files, mut service, key, root) = initialized()?;
    enable(&mut service, &root, "transit")?;
    expect(
        call(
            &mut service,
            "POST",
            "transit/keys/automatic",
            &root,
            json!({"auto_rotate_period":"1h"}),
        ),
        200,
        "scheduled-key",
    )?;
    let cipher = encrypt(&mut service, &root, "automatic")?;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let maintain = |service: &mut Service, observed: Duration| -> TestResult<bool> {
        let started = Instant::now();
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            started + Duration::from_secs(SECONDS),
        );
        let clock = RequestClock::anchored(observed, started)?;
        Ok(service.maintain_native_transit_with_clock_for_test(observed.as_secs(), clock)?)
    };
    assert!(!maintain(&mut service, wall)?);
    assert!(maintain(&mut service, wall + Duration::from_secs(3601))?);
    descriptor(&mut service, &root, "automatic", 2)?;
    assert!(!maintain(&mut service, wall)?);
    drop(service);
    let mut service = reopen(&files, &key)?;
    descriptor(&mut service, &root, "automatic", 2)?;
    decrypt(&mut service, &root, "automatic", &cipher)?;
    sentinel(&mut service, &root)
}

#[test]
fn native_transit_finite_actor_terminal_receipt_keeps_retired_clock_successor() -> TestResult {
    let (files, mut service, key, root) = initialized_with_retained_floor(true)?;
    enable(&mut service, &root, "transit")?;
    let actor = token(
        &mut service,
        &root,
        r#"path "transit/keys/affine" { capabilities=["create","read"] }"#,
    )?;
    let floor = |service: &Service| -> TestResult<Timestamp> {
        service
            .state
            .as_ref()
            .ok_or("retained-floor state")?
            .engines
            .kubernetes_artifact_time(AuthorityTime::Precise(Timestamp::whole(0)?))
            .map_err(|error| error.message)?
            .exact()
            .ok_or_else(|| "retained precise floor".into())
    };
    let before = floor(&service)?;
    expect(
        call(
            &mut service,
            "POST",
            "transit/keys/affine",
            &actor,
            json!({}),
        ),
        200,
        "finite-actor-actual-key-create",
    )?;
    let after = floor(&service)?;
    assert!(
        after > before,
        "actual terminal observation advances the retained floor"
    );
    descriptor(&mut service, &actor, "affine", 1)?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert!(floor(&service)? >= after, "terminal successor is durable");
    descriptor(&mut service, &actor, "affine", 1)?;
    sentinel(&mut service, &root)
}
