//! Real single-node Service, FileBackend, encrypted paged records and audit.
use super::*;
use crate::service::tests::{Root, bootstrap};
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const HASH: &str = "8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395";

struct AuditHookGuard;
impl Drop for AuditHookGuard {
    fn drop(&mut self) {
        AFTER_AUDIT_TEST_HOOK.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn audit_hook(hook: impl FnOnce(&mut Service) + 'static) -> TestResult<AuditHookGuard> {
    AFTER_AUDIT_TEST_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("owned witness audit hook already armed".into());
        }
        *slot = Some(Box::new(hook));
        Ok(AuditHookGuard)
    })
}

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, "", token, body)
}
fn request(version: u64) -> Value {
    json!({"mount":"secret","path":"history","version":version})
}
fn bundle() -> TestResult<Value> {
    let data = crate::engines::decode_lossless_json(
        r#"{"z":9007199254740993,"unicode":"凭证迁移试验🧪","nested":[null,true,{"zero":"\\u0000"}],"a":0.123456789012345678901234567890}"#.as_bytes(),
    )?;
    Ok(json!({
        "schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":3,"cas_required":true,"metadata_cas_required":true,"delete_version_after":"0s"},
        "entries":{"history":{
            "created_time":"1970-01-01T00:01:40.000000113Z","updated_time":"1970-01-01T00:01:43.000000113Z",
            "current_version":3,"oldest_version":0,"current_metadata_version":2,
            "max_versions":3,"cas_required":true,"metadata_cas_required":true,
            "delete_version_after":"0s","custom_metadata":{"purpose":"storage witness"},
            "versions":{
                "1":{"created_time":"1970-01-01T00:01:41.000000113Z","deletion_time":"1970-01-01T00:03:20.000000113Z","destroyed":false,"data":data},
                "2":{"created_time":"1970-01-01T00:01:42.000000113Z","deletion_time":"","destroyed":true,"data":null},
                "3":{"created_time":"1970-01-01T00:01:43.000000113Z","deletion_time":"","destroyed":false,"data":data}
            }
        }}
    }))
}
fn initialized() -> TestResult<(
    Root,
    Service,
    Zeroizing<String>,
    Zeroizing<String>,
    Zeroizing<String>,
)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let (key, root) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        bootstrap(&mut service)?
    };
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/keep",
            &root,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "keep/data/sentinel",
            &root,
            json!({"data":{"kept":"unchanged"}})
        )
        .status,
        200
    );
    for (name, capabilities) in [
        ("witness-allowed", "[\"update\",\"sudo\"]"),
        ("witness-no-sudo", "[\"update\"]"),
    ] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                &format!("sys/policies/acl/{name}"),
                &root,
                json!({"policy":format!("path \"{PATH}\" {{ capabilities={capabilities} }}")})
            )
            .status,
            204
        );
    }
    let actor = issue(&mut service, &root, "witness-allowed", "1h")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/internal/native-v6/activate",
            &root,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/migration/openbao/kv2",
            &root,
            json!({"mount":"secret","bundle":bundle()?})
        )
        .status,
        204
    );
    Ok((
        files,
        service,
        Zeroizing::new(key),
        Zeroizing::new(root),
        actor,
    ))
}
fn issue(
    service: &mut Service,
    root: &str,
    policy: &str,
    ttl: &str,
) -> TestResult<Zeroizing<String>> {
    let issued = call(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"policies":[policy],"no_default_policy":true,"ttl":ttl}),
    );
    assert_eq!(issued.status, 200);
    Ok(Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("issued token")?
            .to_owned(),
    ))
}
fn check_history(service: &mut Service, actor: &str, root: &str) -> TestResult {
    for number in 1..=3 {
        let before = service.native_payload_observations.snapshot();
        let read = call(service, "POST", PATH, actor, request(number));
        assert_eq!(read.status, 200, "witness version {number}");
        let observed = service.native_payload_observations.snapshot();
        let data = &read.body["data"];
        assert_eq!(data["schema"], "heptabao-native-kv2-storage-witness-v1");
        assert_eq!(data["canonical_profile"], "heptabao-lossless-json-v1");
        assert_eq!(data["mount"], "secret");
        assert_eq!(data["path"], "history");
        assert_eq!(data["version"], number);
        assert_eq!(
            data["created_time"],
            format!("1970-01-01T00:01:{:02}.000000113Z", 40 + number)
        );
        assert_eq!(
            data["deletion_time"],
            if number == 1 {
                "1970-01-01T00:03:20.000000113Z"
            } else {
                ""
            }
        );
        assert_eq!(data["destroyed"], number == 2);
        assert_eq!(data["payload_present"], number != 2);
        if number == 2 {
            assert!(data["payload_canonical_sha256"].is_null());
            assert_eq!(data["payload_canonical_bytes"], 0);
            assert_eq!(
                observed[1], before[1],
                "destroyed version must not open another payload"
            );
        } else {
            assert_eq!(data["payload_canonical_sha256"], HASH);
            assert_eq!(data["payload_canonical_bytes"], 134);
            assert!(
                observed[1] > before[1],
                "actual immutable payload AEAD read is required"
            );
        }
        assert!(data.get("payload").is_none() && data.get("data").is_none());
        let public = call(
            service,
            "GET",
            "secret/data/history",
            root,
            json!({"version":number}),
        );
        assert_eq!(public.status, if number <= 2 { 404 } else { 200 });
        if number == 3 {
            assert_eq!(
                public.body["data"]["data"]["z"]
                    .as_number()
                    .ok_or("API integer")?
                    .to_string(),
                "9007199254740992"
            );
            assert_eq!(
                public.body["data"]["data"]["a"]
                    .as_number()
                    .ok_or("API decimal")?
                    .to_string(),
                "0.12345678901234568"
            );
        }
    }
    let sentinel = call(service, "GET", "keep/data/sentinel", root, json!({}));
    assert_eq!(sentinel.status, 200);
    assert_eq!(sentinel.body["data"]["data"], json!({"kept":"unchanged"}));
    assert!(service.pending_native_kv2_witness.is_none());
    assert!(service.native_request_binding.is_none());
    Ok(())
}
fn snapshot(
    service: &mut Service,
    token: &str,
    method: &str,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({})),
        Instant::now() + Duration::from_secs(15),
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(plan)) => Ok(plan),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Err(format!("snapshot admission status={}", response.status).into())
        }
        NativeSnapshotAdmission::Redirect(_) => Err("unexpected single-node redirect".into()),
    }
}
fn reopen(files: &Root, key: &str) -> TestResult<Service> {
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    Ok(service)
}
fn negative_zero(service: &mut Service, root: &str) -> TestResult {
    let read = call(service, "GET", "secret/data/negative-zero", root, json!({}));
    assert_eq!(read.status, 200);
    assert_eq!(
        serde_json::to_string(&read.body["data"]["data"])?,
        r#"{"n":-0}"#
    );
    Ok(())
}

fn rejects_clock_copy_without_the_original_precision_owner() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let (key, root) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        bootstrap(&mut service)?
    };
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/clock-floor-veto",
            &root,
            json!({"data":{"selected":"archive"}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/internal/native-v6/activate",
            &root,
            json!({})
        )
        .status,
        204
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("archived State")?
            .has_token_api_precision_state()
    );
    let mut export = snapshot(&mut service, &root, "GET")?;
    let (result, file) = export.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(service.finish_external_request(*export, result).status, 200);
    let mut archive = Zeroizing::new(Vec::new());
    file.ok_or("unprotected snapshot")?
        .read_to_end(&mut archive)?;
    // A real token issuance establishes custody that this older archive did
    // not contain. Copying a later clock cannot synthesize its reader label.
    let issued = issue(&mut service, &root, "root", "1h")?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("protected State")?
            .has_token_api_precision_state()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/clock-floor-veto",
            &root,
            json!({"data":{"selected":"live"}})
        )
        .status,
        200
    );
    let mut restore = snapshot(&mut service, &root, "POST")?;
    let activation = service.unseal_nonce.clone();
    let (result, file) = restore.execute_snapshot_transfer(&mut &archive[..]);
    assert!(file.is_none());
    let rejected = service.finish_external_request(*restore, result);
    assert_eq!(
        rejected.status, 400,
        "clock inheritance must not erase protected format: {}",
        rejected.body
    );
    assert!(rejected.body.get("data").is_none());
    assert_eq!(
        service.unseal_nonce, activation,
        "rejected archive must not install a new owner"
    );
    drop(service);
    let mut cold = reopen(&files, &key)?;
    assert!(
        cold.state
            .as_ref()
            .ok_or("cold protected State")?
            .has_token_api_precision_state()
    );
    let read = call(
        &mut cold,
        "GET",
        "secret/data/clock-floor-veto",
        &root,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["data"], json!({"selected":"live"}));
    assert_eq!(
        call(
            &mut cold,
            "GET",
            "auth/token/lookup-self",
            &issued,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn native_kv2_storage_witness_service_import_cold_and_snapshot_keep_exact_payloads() -> TestResult {
    let (files, mut service, key, root, actor) = initialized()?;
    let signed_zero = crate::engines::decode_lossless_json(br#"{"n":-0}"#)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/negative-zero",
            &root,
            json!({"options":{"cas":0},"data":signed_zero})
        )
        .status,
        200
    );
    check_history(&mut service, &actor, &root)?;
    negative_zero(&mut service, &root)?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    check_history(&mut service, &actor, &root)?;
    negative_zero(&mut service, &root)?;
    let mut export = snapshot(&mut service, &root, "GET")?;
    let archive_floor = service
        .state
        .as_ref()
        .ok_or("export State")?
        .auth
        .terminal_token_clock_floor()
        .ok_or("export precise floor")?;
    let (result, file) = export.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(service.finish_external_request(*export, result).status, 200);
    let mut archive = Zeroizing::new(Vec::new());
    file.ok_or("snapshot")?.read_to_end(&mut archive)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/history",
            &root,
            json!({"options":{"cas":3},"data":{"after_snapshot":true}})
        )
        .status,
        200
    );
    let mut restore = snapshot(&mut service, &root, "POST")?;
    // Capture the real admitted Auth AFTER its ordinary precise-clock entry.
    // Neither the restored root nor the later terminal write is its oracle.
    let admitted_auth = &service.state.as_ref().ok_or("admitted State")?.auth;
    let admitted_floor = admitted_auth
        .terminal_token_clock_floor()
        .ok_or("admitted precise floor")?;
    assert!(
        admitted_floor > archive_floor,
        "the actual restore must inherit a newer live floor"
    );
    let admitted_auth_bytes =
        owner_store::serialize_owner(admitted_auth).map_err(|_| "admitted Auth encoding")?;
    let admitted_generation = service
        .durable
        .as_ref()
        .ok_or("admitted Durable")?
        .generation();
    let admitted_epoch = service.state.as_ref().ok_or("admitted epoch")?.replay_epoch;
    let committed = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&committed);
    let _observer = Service::observe_next_native_snapshot_commit_for_test(move |service| {
        let durable = service.durable.as_ref().expect("committed Durable");
        let stored = durable
            .get("system", "state")
            .expect("committed root read")
            .expect("committed root");
        let root = crate::state_record_root_v6::RecordStateRootV6::decode(stored.expose())
            .map_err(|_| "committed typed root")
            .expect("committed typed root");
        let state = service.state.as_ref().expect("committed State");
        let auth = owner_store::serialize_owner(&state.auth)
            .map_err(|_| "committed Auth encoding")
            .expect("committed Auth encoding");
        assert_eq!(
            state.auth.terminal_token_clock_floor(),
            Some(admitted_floor)
        );
        assert_eq!(
            crypto::digest(&auth),
            crypto::digest(&admitted_auth_bytes),
            "same committed restore must preserve every non-clock archived Auth field"
        );
        let domain = crate::state_record_root_v6::OwnerDomain::Auth;
        let owner = root
            .owners
            .iter()
            .find(|owner| owner.domain == domain)
            .expect("Auth owner");
        assert_eq!(
            root.owner_digest(domain, &auth)
                .map_err(|_| "Auth digest")
                .expect("Auth digest"),
            owner.owner.digest,
            "persisted root must select the inherited Auth bytes before terminal audit"
        );
        assert_eq!(durable.generation(), admitted_generation + 1);
        assert_eq!(durable.replay_epoch(), admitted_epoch + 1);
        assert_eq!(root.replay_epoch, durable.replay_epoch());
        assert_eq!(state.replay_epoch, durable.replay_epoch());
        observed.store(true, Ordering::SeqCst);
    })?;
    let (result, file) = restore.execute_snapshot_transfer(&mut &archive[..]);
    assert!(file.is_none());
    let restored = service.finish_external_request(*restore, result);
    assert_eq!(
        restored.status, 200,
        "synthetic native witness snapshot restore: {}",
        restored.body
    );
    assert!(
        committed.load(Ordering::SeqCst),
        "observe the actual bundle before terminal clock/audit"
    );
    assert_eq!(
        restored.body["data"]["restored_generation"],
        admitted_generation + 1
    );
    assert_eq!(
        restored.body["data"]["previous_generation"],
        admitted_generation
    );
    assert_eq!(restored.body["data"]["replay_epoch"], admitted_epoch + 1);
    assert_eq!(restored.body["data"]["retained_requests"], 1);
    assert_eq!(restored.body["data"]["rollback"], true);
    let delivered_floor = service
        .state
        .as_ref()
        .ok_or("delivered State")?
        .auth
        .terminal_token_clock_floor()
        .ok_or("delivered precise floor")?;
    let delivered_generation = service
        .durable
        .as_ref()
        .ok_or("delivered Durable")?
        .generation();
    let delivered_auth =
        owner_store::serialize_owner(&service.state.as_ref().ok_or("delivered State")?.auth)
            .map_err(|_| "delivered Auth encoding")?;
    drop(service);
    // Pause the REAL cold Service unseal before its outer API terminal clock.
    // No bare-file decoder or second mutation may repair a stale floor here.
    {
        let mut cold = files.service()?;
        cold.configure_native_v6_candidate()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let unsealed = cold.unseal(&json!({"key":key.as_str()}));
        assert_eq!(
            unsealed.status, 200,
            "cold native reader before terminal clock: {}",
            unsealed.body
        );
        let state = cold.state.as_ref().ok_or("cold State")?;
        assert_eq!(
            state.auth.terminal_token_clock_floor(),
            Some(delivered_floor)
        );
        assert_eq!(
            cold.durable.as_ref().ok_or("cold Durable")?.generation(),
            delivered_generation
        );
        assert_eq!(
            cold.durable.as_ref().ok_or("cold Durable")?.replay_epoch(),
            admitted_epoch + 1
        );
        assert_eq!(state.replay_epoch, admitted_epoch + 1);
        let auth = owner_store::serialize_owner(&state.auth).map_err(|_| "cold Auth encoding")?;
        assert_eq!(crypto::digest(&auth), crypto::digest(&delivered_auth));
    }
    let mut service = reopen(&files, &key)?;
    check_history(&mut service, &actor, &root)?;
    negative_zero(&mut service, &root)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/metadata/history",
            &root,
            json!({})
        )
        .body["data"]["current_version"],
        3
    );
    Ok(())
}

#[test]
fn native_kv2_storage_witness_service_rejects_scope_parameters_and_terminal_owner_change()
-> TestResult {
    let (files, mut service, key, root, actor) = initialized()?;
    let limited = issue(&mut service, &root, "witness-no-sudo", "1h")?;
    for token in ["", limited.as_str()] {
        let before = service.native_payload_observations.snapshot();
        assert_eq!(
            call(&mut service, "POST", PATH, token, request(3)).status,
            403
        );
        assert_eq!(service.native_payload_observations.snapshot()[1], before[1]);
    }
    for body in [
        json!({}),
        json!({"mount":"secret","path":"history"}),
        request(0),
        json!({"mount":"secret","path":"history","version":"3"}),
        json!({"mount":"secret","path":"history","version":3,"force":true}),
        json!({"mount":"secret","path":"../history","version":3}),
    ] {
        let before = service.native_payload_observations.snapshot();
        assert_eq!(call(&mut service, "POST", PATH, &root, body).status, 400);
        assert_eq!(service.native_payload_observations.snapshot()[1], before[1]);
    }
    assert_eq!(
        call(&mut service, "GET", PATH, &root, request(3)).status,
        400
    );
    rejects_clock_copy_without_the_original_precision_owner()?;
    let fired = Arc::new(AtomicBool::new(false));
    let changed = Arc::clone(&fired);
    let _hook = audit_hook(move |service| {
        changed.store(true, Ordering::SeqCst);
        service.unseal_nonce.push_str("-different-owner");
    })?;
    let denied = call(&mut service, "POST", PATH, &actor, request(3));
    assert!(
        fired.load(Ordering::SeqCst),
        "veto must occur after the real terminal audit"
    );
    assert_eq!(denied.status, 503);
    assert!(denied.body.get("data").is_none());
    assert!(service.pending_native_kv2_witness.is_none());
    assert!(service.native_request_binding.is_none());
    drop(service);
    let mut service = reopen(&files, &key)?;
    check_history(&mut service, &actor, &root)?;
    Ok(())
}

#[test]
fn native_kv2_storage_witness_service_original_actor_expiry_after_audit_withholds_hash()
-> TestResult {
    let (_files, mut service, _key, root, _actor) = initialized()?;
    let actor = issue(&mut service, &root, "witness-allowed", "6s")?;
    // Successful delivery is an upper bound on this token's mint time. A slow
    // issuing write must not consume the delay intended to expire this Actor.
    let issued_before = Instant::now();
    let fired = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&fired);
    let _hook = audit_hook(move |_| {
        observed.store(true, Ordering::SeqCst);
        // One real request: retain the original Actor/Clock through actual
        // audit, then let its issued TTL expire within the original 15s budget.
        let remaining =
            (issued_before + Duration::from_secs(7)).saturating_duration_since(Instant::now());
        std::thread::sleep(remaining);
    })?;
    let before = service.native_payload_observations.snapshot();
    let denied = call(&mut service, "POST", PATH, &actor, request(3));
    assert!(
        fired.load(Ordering::SeqCst),
        "actor must have reached actual terminal audit first"
    );
    assert!(service.native_payload_observations.snapshot()[1] > before[1]);
    assert_eq!(denied.status, 503);
    assert!(denied.body.get("data").is_none());
    assert!(service.pending_native_kv2_witness.is_none());
    assert!(service.native_request_binding.is_none());
    Ok(())
}
