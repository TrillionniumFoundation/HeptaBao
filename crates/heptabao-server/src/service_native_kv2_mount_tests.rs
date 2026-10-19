//! Actual root Service, FileBackend, native payloads, original ACLs and audit.
use super::*;
use crate::service::tests::{Root, bootstrap};
use crate::state_record_root_v6::Kv2GraphRef;
use sha2::Digest;
use std::cell::RefCell;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SECONDS: u64 = 15;
const WITNESS: &str = "sys/internal/storage/kv2-version-witness";
const PAYLOAD: &[u8] = br#"{"a":0.123456789012345678901234567890,"nested":[null,true,{"zero":"\\u0000"}],"unicode":"credential migration","z":9007199254740993}"#;

thread_local! {
    static AFTER_MOUNT_AUDIT: RefCell<Option<Box<dyn FnOnce(&mut Service)>>> = RefCell::new(None);
}

pub(super) fn after_actual_mount_audit(service: &mut Service) {
    // Consume the hook before a nested real Service call. It supplies no Actor,
    // publication result, timer, response or audit success to the outer request.
    let hook = AFTER_MOUNT_AUDIT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(service);
    }
}

struct HookGuard;
impl Drop for HookGuard {
    fn drop(&mut self) {
        AFTER_MOUNT_AUDIT.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn after_audit(hook: impl FnOnce(&mut Service) + 'static) -> TestResult<HookGuard> {
    AFTER_MOUNT_AUDIT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("owned mount audit hook already armed".into());
        }
        *slot = Some(Box::new(hook));
        Ok(HookGuard)
    })
}

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(SECONDS),
    );
    service.handle(method, path, "", token, body)
}

fn initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    initialized_with_retired_clock(false)
}

fn retained_engine_floor(service: &Service) -> TestResult<Timestamp> {
    // Query the already retained floor; this is not an admitted request clock.
    service
        .state
        .as_ref()
        .ok_or("actual initialized state")?
        .engines
        .kubernetes_artifact_time(AuthorityTime::Precise(Timestamp::whole(0)?))
        .map_err(|error| error.message)?
        .exact()
        .ok_or_else(|| "retained precise engine floor".into())
}

fn initialized_with_retired_clock(
    retain_clock: bool,
) -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let (key, root) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(SECONDS),
        );
        bootstrap(&mut service)?
    };
    if retain_clock {
        // Seed the valid historical metadata left after opaque artifacts were
        // retired. Publish it through the real legacy State writer, then use
        // the ordinary activation route. No operation Clock, Actor or receipt
        // is replaced; this case does not claim Kubernetes provider coverage.
        let started = Instant::now();
        let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
        let at = clock.observed_at()?;
        let mut state = service.state.as_ref().ok_or("actual legacy state")?.clone();
        state
            .engines
            .seed_retired_clock_for_native_mount_fixture(at)
            .map_err(|error| error.message)?;
        state.schema = state.writer_schema();
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            started + Duration::from_secs(SECONDS),
        );
        service.commit_state(&mut state).map_err(|response| {
            format!(
                "retired clock fixture publication status={}",
                response.status
            )
        })?;
        service.state = Some(state);
        assert!(
            service
                .state
                .as_ref()
                .ok_or("actual published state")?
                .engines
                .has_kubernetes_opaque_artifact_state()
        );
        assert_eq!(retained_engine_floor(&service)?, at);
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/sentinel",
            &root,
            json!({"data":{"kept":"unchanged"}})
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
    Ok((files, service, Zeroizing::new(key), Zeroizing::new(root)))
}

fn activated_empty() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let mut initialized = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(initialized.status, 200);
    let root = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("root token")?
            .to_owned(),
    );
    let key = Zeroizing::new(
        initialized.body["keys_base64"][0]
            .as_str()
            .ok_or("unseal key")?
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
        graphs(&service)?.is_empty(),
        "this fixture has no pre-activation KV2 mount"
    );
    Ok((files, service, key, root))
}

fn reopen(files: &Root, key: &str) -> TestResult<Service> {
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let response = call(&mut service, "POST", "sys/unseal", "", json!({"key":key}));
    assert_eq!(
        response.status, 200,
        "actual cold native unseal: {}",
        response.body
    );
    Ok(service)
}

fn graphs(service: &Service) -> TestResult<Vec<Kv2GraphRef>> {
    Ok(service
        .native_root
        .as_ref()
        .ok_or("actual native root")?
        .kv2
        .clone())
}

fn mounted(
    service: &mut Service,
    root: &str,
    mount: &str,
    incarnation: u64,
    revision: u64,
) -> TestResult {
    let response = call(
        service,
        "GET",
        &format!("sys/mounts/{mount}"),
        root,
        json!({}),
    );
    assert_eq!(
        response.status, 200,
        "actual native mount descriptor: {}",
        response.body
    );
    let data = &response.body["data"];
    assert_eq!(data["type"], "kv");
    assert_eq!(data["options"]["version"], "2");
    assert_eq!(data["incarnation"], incarnation);
    assert_eq!(data["revision"], revision);
    let selected = graphs(service)?
        .into_iter()
        .filter(|graph| {
            graph.scope.namespace.is_empty() && graph.scope.mount == format!("{mount}/")
        })
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].scope.incarnation, incarnation);
    assert_eq!(
        selected[0].graph_format,
        crate::engines::kv2_native_records::PAGED_NATIVE_FORMAT
    );
    Ok(())
}

fn exact_history(service: &mut Service, root: &str) -> TestResult {
    let expected_hash = format!("{:x}", sha2::Sha256::digest(PAYLOAD));
    for version in 1..=2 {
        let observed = call(
            service,
            "POST",
            WITNESS,
            root,
            json!({"mount":"runtime","path":"history","version":version}),
        );
        assert_eq!(
            observed.status, 200,
            "actual mount storage witness: {}",
            observed.body
        );
        let data = &observed.body["data"];
        assert_eq!(data["canonical_profile"], "heptabao-lossless-json-v1");
        assert_eq!(data["mount"], "runtime");
        assert_eq!(data["path"], "history");
        assert_eq!(data["version"], version);
        assert_eq!(data["payload_present"], true);
        assert_eq!(data["destroyed"], false);
        assert_eq!(data["payload_canonical_bytes"], PAYLOAD.len());
        assert_eq!(data["payload_canonical_sha256"], expected_hash);
        assert_eq!(
            data["deletion_time"]
                .as_str()
                .ok_or("deletion time")?
                .is_empty(),
            version == 2
        );
        let public = call(
            service,
            "GET",
            "runtime/data/history",
            root,
            json!({"version":version}),
        );
        assert_eq!(public.status, if version == 1 { 404 } else { 200 });
        if version == 2 {
            assert_eq!(
                public.body["data"]["data"]["z"].to_string(),
                "9007199254740992"
            );
            assert_eq!(
                public.body["data"]["data"]["a"].to_string(),
                "0.12345678901234568"
            );
        }
    }
    let metadata = call(service, "GET", "runtime/metadata/history", root, json!({}));
    assert_eq!(metadata.status, 200);
    assert_eq!(metadata.body["data"]["current_version"], 2);
    let sentinel = call(service, "GET", "secret/data/sentinel", root, json!({}));
    assert_eq!(sentinel.status, 200);
    assert_eq!(sentinel.body["data"]["data"], json!({"kept":"unchanged"}));
    assert!(service.pending_native_auth_delivery.is_none());
    assert!(service.native_request_binding.is_none());
    Ok(())
}

fn snapshot(
    service: &mut Service,
    root: &str,
    method: &str,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", root, json!({})),
        Instant::now() + Duration::from_secs(SECONDS),
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(plan)) => Ok(plan),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => Err(format!(
            "actual snapshot admission status={} body={}",
            response.status, response.body
        )
        .into()),
        NativeSnapshotAdmission::Redirect(_) => Err("unexpected single-node redirect".into()),
    }
}

#[test]
fn native_kv2_mount_create_tune_cold_snapshot_delete_and_recreate_keep_precise_history()
-> TestResult {
    let (files, mut service, key, root) = initialized_with_retired_clock(true)?;
    let original_graphs = graphs(&service)?;
    let before_create_floor = retained_engine_floor(&service)?;
    let created = call(
        &mut service,
        "POST",
        "sys/mounts/runtime",
        &root,
        json!({"type":"kv","options":{"version":"2"},"cas_revision":0}),
    );
    assert_eq!(
        created.status, 204,
        "native mount creation after activation: {}",
        created.body
    );
    let created_floor = retained_engine_floor(&service)?;
    assert!(
        created_floor > before_create_floor,
        "the real request must exercise an actual Engine terminal clock advance"
    );
    mounted(&mut service, &root, "runtime", 1, 1)?;
    let mut unrelated = graphs(&service)?;
    unrelated.retain(|graph| graph.scope.mount != "runtime/");
    assert!(
        unrelated == original_graphs,
        "creating one mount cannot rewrite other payload graphs"
    );
    let value = crate::engines::decode_lossless_json(PAYLOAD)?;
    assert_eq!(serde_json::to_vec(&value)?.as_slice(), PAYLOAD);
    for (cas, version) in [(0, 1), (1, 2)] {
        let written = call(
            &mut service,
            "POST",
            "runtime/data/history",
            &root,
            json!({"options":{"cas":cas},"data":value}),
        );
        assert_eq!(written.status, 200);
        assert_eq!(written.body["data"]["version"], version);
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "runtime/delete/history",
            &root,
            json!({"versions":[1]})
        )
        .status,
        204
    );
    let before_tune = graphs(&service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/runtime/tune",
            &root,
            json!({"description":"runtime owned","cas_revision":1})
        )
        .status,
        204
    );
    mounted(&mut service, &root, "runtime", 1, 2)?;
    assert!(
        graphs(&service)? == before_tune,
        "tuning metadata cannot replace secret history"
    );
    exact_history(&mut service, &root)?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert!(
        retained_engine_floor(&service)? >= created_floor,
        "the observed engine floor is durable across a real cold reopen"
    );
    mounted(&mut service, &root, "runtime", 1, 2)?;
    exact_history(&mut service, &root)?;

    let mut export = snapshot(&mut service, &root, "GET")?;
    let (result, archive) = export.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(service.finish_external_request(*export, result).status, 200);
    let mut bytes = Zeroizing::new(Vec::new());
    archive
        .ok_or("actual snapshot archive")?
        .read_to_end(&mut bytes)?;
    assert!(bytes.starts_with(&[0x1f, 0x8b]));
    let archive_hash = sha2::Sha256::digest(bytes.as_slice());
    assert_eq!(
        call(
            &mut service,
            "POST",
            "runtime/data/history",
            &root,
            json!({"options":{"cas":2},"data":{"after_snapshot":true}})
        )
        .status,
        200
    );
    let before_restore_floor = retained_engine_floor(&service)?;
    let mut restore = snapshot(&mut service, &root, "POST")?;
    let (result, output) = restore.execute_snapshot_transfer(&mut &bytes[..]);
    assert!(output.is_none());
    let restored = service.finish_external_request(*restore, result);
    assert_eq!(
        restored.status, 200,
        "actual mount snapshot restore: {}",
        restored.body
    );
    let restored_floor = retained_engine_floor(&service)?;
    assert!(
        restored_floor >= before_restore_floor,
        "snapshot restore cannot roll back the live retired artifact floor"
    );
    assert_eq!(
        sha2::Sha256::digest(bytes.as_slice()),
        archive_hash,
        "restore leaves its archive bytes immutable"
    );
    exact_history(&mut service, &root)?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert!(
        retained_engine_floor(&service)? >= restored_floor,
        "snapshot floor inheritance is persisted in the actual restored root"
    );
    mounted(&mut service, &root, "runtime", 1, 2)?;
    exact_history(&mut service, &root)?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/runtime",
            &root,
            json!({"cas_revision":2})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "GET", "sys/mounts/runtime", &root, json!({})).status,
        404
    );
    assert!(
        graphs(&service)?
            .iter()
            .all(|graph| graph.scope.mount != "runtime/")
    );
    // An absent delete must not increment the retained incarnation twice.
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/runtime",
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
            "sys/mounts/runtime",
            &root,
            json!({"type":"kv","options":{"version":"2"},"cas_revision":0})
        )
        .status,
        204
    );
    mounted(&mut service, &root, "runtime", 2, 1)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "runtime/data/history",
            &root,
            json!({})
        )
        .status,
        404
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    mounted(&mut service, &root, "runtime", 2, 1)?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "runtime/data/history",
            &root,
            json!({})
        )
        .status,
        404
    );
    Ok(())
}

#[test]
fn native_kv2_mount_acl_cas_and_backend_refusals_keep_registry_and_graphs() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    let policy = "path \"sys/mounts/guarded*\" { capabilities=[\"read\",\"update\",\"delete\"] }";
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/mount-without-sudo",
            &root,
            json!({"policy":policy})
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root,
        json!({"policies":["mount-without-sudo"],"no_default_policy":true,"ttl":"1h"}),
    );
    assert_eq!(issued.status, 200);
    let actor = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("actual actor")?
            .to_owned(),
    );
    let before = graphs(&service)?;
    // Sudo is checked before either existence or supported backend inspection.
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/guarded",
            &actor,
            json!({"type":"transit"})
        )
        .status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "sys/mounts/guarded", "", json!({})).status,
        403
    );
    for body in [
        json!({"type":"transit"}),
        json!({"type":"kv","options":{"version":"1"}}),
    ] {
        assert_eq!(
            call(&mut service, "POST", "sys/mounts/guarded", &root, body).status,
            501
        );
    }
    assert!(
        graphs(&service)? == before,
        "permission and backend refusals cannot rewrite payload graphs"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/guarded",
            &root,
            json!({"type":"kv","options":{"version":"2"},"unexpected":true})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/guarded",
            &root,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    let guarded = graphs(&service)?;
    assert_eq!(
        call(&mut service, "GET", "sys/mounts/guarded", &actor, json!({})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/guarded/tune",
            &actor,
            json!({"description":"not allowed"})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/guarded",
            &actor,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/guarded/tune",
            &root,
            json!({"description":"stale","cas_revision":99})
        )
        .status,
        409
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/guarded",
            &root,
            json!({"cas_revision":99})
        )
        .status,
        409
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/guarded/tune",
            &root,
            json!({"options":{"version":"1"}})
        )
        .status,
        400
    );
    assert!(
        graphs(&service)? == guarded,
        "ACL, CAS, and schema refusals cannot rewrite payload graphs"
    );
    mounted(&mut service, &root, "guarded", 1, 1)?;
    assert!(!service.recovery_required && !service.audit_failed);
    Ok(())
}

#[test]
fn native_kv2_mount_seal_after_actual_audit_vetoes_reply_and_cold_recovers_committed_mount()
-> TestResult {
    let (files, mut service, key, root) = activated_empty()?;
    let audit_before = service.audit_sequence;
    let ran = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&ran);
    let seal_root = root.clone();
    let _hook = after_audit(move |service| {
        assert_eq!(
            service.audit_sequence,
            audit_before + 2,
            "actual request and mandatory response audit have completed"
        );
        assert!(!service.audit_failed);
        assert!(
            service
                .native_root
                .as_ref()
                .expect("actual committed root")
                .kv2
                .iter()
                .any(|graph| graph.scope.mount == "sealed-mount/" && graph.scope.incarnation == 1)
        );
        let seal = call(service, "POST", "sys/seal", &seal_root, json!({}));
        assert_eq!(seal.status, 204, "real Service seal after committed mount");
        observed.store(true, Ordering::SeqCst);
    })?;
    let response = call(
        &mut service,
        "POST",
        "sys/mounts/sealed-mount",
        &root,
        json!({"type":"kv","options":{"version":"2"},"cas_revision":0}),
    );
    assert!(
        ran.load(Ordering::SeqCst),
        "actual post-audit hook must execute"
    );
    assert_eq!(
        response.status, 503,
        "the original unseal owner no longer permits a success reply"
    );
    assert!(response.body.get("data").is_none());
    assert!(service.state.is_none());
    assert!(service.pending_native_auth_delivery.is_none());
    drop(service);
    let mut service = reopen(&files, &key)?;
    mounted(&mut service, &root, "sealed-mount", 1, 1)?;
    // Discover the one committed mount after cold reopen; no create is replayed.
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sealed-mount/data/recovered",
            &root,
            json!({"options":{"cas":0},"data":{"actual":"cold recovered"}})
        )
        .status,
        200
    );
    let recovered = call(
        &mut service,
        "GET",
        "sealed-mount/data/recovered",
        &root,
        json!({}),
    );
    assert_eq!(recovered.status, 200);
    assert_eq!(
        recovered.body["data"]["data"],
        json!({"actual":"cold recovered"})
    );
    mounted(&mut service, &root, "sealed-mount", 1, 1)?;

    // A different real publication after audit must not be mistaken for this
    // request's terminal clock successor, even if only Auth changed and the
    // root Actor, selected mount and current unseal nonce all remain valid.
    drop(_hook);
    let audit_before = service.audit_sequence;
    let changed = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&changed);
    let policy_root = root.clone();
    let _unrelated = after_audit(move |service| {
        assert_eq!(service.audit_sequence, audit_before + 2);
        let policy = call(
            service,
            "PUT",
            "sys/policies/acl/unrelated-after-mount-audit",
            &policy_root,
            json!({"policy":"path \"sealed-mount/data/*\" { capabilities=[\"read\"] }"}),
        );
        assert_eq!(
            policy.status, 204,
            "actual unrelated Auth publication after audit"
        );
        observed.store(true, Ordering::SeqCst);
    })?;
    let stale = call(
        &mut service,
        "GET",
        "sys/mounts/sealed-mount",
        &root,
        json!({}),
    );
    assert!(changed.load(Ordering::SeqCst));
    assert_eq!(
        stale.status, 503,
        "a later publication cannot rebind the old terminal receipt"
    );
    assert!(stale.body.get("data").is_none());
    assert!(service.pending_native_auth_delivery.is_none());
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/policies/acl/unrelated-after-mount-audit",
            &root,
            json!({})
        )
        .status,
        200,
        "the separate actual publication remains committed"
    );
    mounted(&mut service, &root, "sealed-mount", 1, 1)?;
    Ok(())
}
