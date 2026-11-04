//! Actual formal three-voter mTLS/Service regressions for snapshot ACL and
//! receipt-bound refusal. These use the existing cfg(test) startup and HTTP
//! parser fixture; public TLS sockets and physical hosts remain separate.
use super::*;
use crate::auth::{IngressReplyScope, Timestamp};
use crate::ha::snapshot_clock::{SnapshotClockContext, SnapshotClockOperation};
use std::os::unix::fs::PermissionsExt;

fn snapshot_policy_token(
    pipeline: &Pipeline,
    leader: usize,
    name: &str,
    update: bool,
    ttl: &str,
) -> TestResult<Zeroizing<String>> {
    let capabilities = if update { r#"["read", "update"]"# } else { r#"["read"]"# };
    let policy = format!(
        r#"path "sys/storage/raft/snapshot" {{ capabilities = {capabilities} }}
path "sys/storage/raft/snapshot-force" {{ capabilities = {capabilities} }}
path "auth/token/lookup-self" {{ capabilities = ["read"] }}"#
    );
    expect(
        pipeline.call(
            leader,
            "POST",
            &format!("sys/policies/acl/{name}"),
            pipeline.admin(),
            json!({"policy":policy}),
        )?,
        204,
        "snapshot-policy-created",
    )?;
    let mut issued = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/create",
            pipeline.admin(),
            json!({"policies":[name],"ttl":ttl,"no_default_policy":true,
                "no_parent":true,"num_uses":0}),
        )?,
        200,
        "snapshot-nonroot-token-created",
    )?;
    let token = secret_field(&mut issued, "/auth/client_token")?;
    let lookup = expect(
        pipeline.call(leader, "GET", "auth/token/lookup-self", &token, json!({}))?,
        200,
        "snapshot-nonroot-token-real-self-lookup",
    )?;
    assert_eq!(lookup.body["data"]["policies"], json!([name]));
    assert_eq!(lookup.body["data"]["num_uses"], 0);
    Ok(token)
}

fn floor(pipeline: &Pipeline, index: usize) -> TestResult<Option<Timestamp>> {
    pipeline.with_service(index, |service| {
        Ok(service.state.as_ref().ok_or("actual snapshot Auth state")?
            .auth.terminal_token_clock_floor())
    })
}

fn no_snapshot_custody(pipeline: &Pipeline, index: usize) -> TestResult {
    pipeline.with_service(index, |service| {
        assert!(service.native_request_binding.is_none());
        assert!(service.native_failure_notice.is_none());
        assert!(service.pending_snapshot_transfer.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        assert!(!service.recovery_required);
        Ok(())
    })
}

#[test]
fn formal_native_nonroot_snapshot_acl_and_historical_restore_use_original_update_actor()
-> TestResult {
    let pipeline = formal_cold_source()?;
    let leader = pipeline.ready_leader()?;
    let migration_source = activate_formal_cold(&pipeline, leader)?;
    let standby = (leader + 1) % 3;
    let reader = snapshot_policy_token(&pipeline, leader, "snapshot-reader", false, "120s")?;
    let writer = snapshot_policy_token(&pipeline, leader, "snapshot-writer", true, "120s")?;

    let archive = wire(&pipeline, leader, "GET", SNAPSHOT, &reader, b"", None)?;
    assert_eq!(archive.status, 200);
    assert!(archive.body.starts_with(&[0x1f, 0x8b]));
    let read = wire(&pipeline, standby, "GET", SNAPSHOT, &reader, b"", Some("false"))?;
    assert_eq!(read.status, 200);
    assert!(read.body.starts_with(&[0x1f, 0x8b]));
    for index in [leader, standby] {
        for path in [SNAPSHOT, "sys/storage/raft/snapshot-force"] {
            let denied = wire(&pipeline, index, "POST", path, &reader, b"not-gzip", None)?;
            assert_eq!(denied.status, 403, "actual update ACL precedes archive parsing");
            assert!(!denied.body.starts_with(&[0x1f, 0x8b]));
            let invalid = wire(&pipeline, index, "POST", path, &writer, b"not-gzip", None)?;
            assert_eq!(invalid.status, 500, "actual authorized parser keeps its error");
            assert_eq!(selection(&pipeline, leader, migration_source)?.0, 0);
        }
    }
    let validated = wire(
        &pipeline, standby, "POST", SNAPSHOT, &writer, &archive.body, None,
    )?;
    redirected(&validated);
    assert_eq!(selection(&pipeline, leader, migration_source)?.0, 0);
    assert!(observed_pending_reference(&pipeline, leader)?.is_none());

    // A public update policy must not grant the internal reconciliation query.
    {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let service = pipeline.services[leader].as_ref().ok_or("actual leader")?;
        let mut service = lock_until(service, until).map_err(|_| "internal query lock")?;
        let refused = service.begin_native_snapshot_before(
            ServiceRequest::new(
                "POST", SNAPSHOT, "", &writer, json!({"inspect_pending_restore":true}),
            ),
            until,
        );
        assert!(matches!(
            refused,
            NativeSnapshotAdmission::Execute(RequestExecution::Complete(response))
                if response.status == 403
        ));
    }

    expect(
        pipeline.call(
            leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":"after-reader-archive"}}),
        )?,
        200,
        "snapshot-after-archive-write",
    )?;
    // This reaches the real historical restore writer and epoch transition;
    // a malformed-upload status alone cannot prove the deep actor guard.
    let restored = wire(
        &pipeline, leader, "POST", SNAPSHOT, &writer, &archive.body, None,
    )?;
    assert_eq!(restored.status, 200);
    let body: Value = serde_json::from_slice(&restored.body)?;
    assert_eq!(body["data"]["replay_epoch"], 1);
    assert_eq!(selection(&pipeline, leader, migration_source)?.0, 1);
    pipeline.assert_history(leader, &[(1, "seed-v5")])?;
    expect(
        pipeline.call(
            leader, "GET", "secret/data/pipeline/history", pipeline.admin(),
            json!({"version":2}),
        )?,
        404,
        "actual-nonroot-restore-removes-later-version",
    )?;
    no_snapshot_custody(&pipeline, leader)?;
    Ok(())
}

#[test]
fn formal_native_standby_acl_denial_commits_floor_without_transfer_lease_and_survives_cold()
-> TestResult {
    let mut pipeline = formal_cold_source()?;
    let leader = pipeline.ready_leader()?;
    activate_formal_cold(&pipeline, leader)?;
    let standby = (leader + 1) % 3;
    let reader = snapshot_policy_token(&pipeline, leader, "denial-reader", false, "120s")?;
    let first = wire(&pipeline, standby, "GET", SNAPSHOT, &reader, b"", None)?;
    assert_eq!(first.status, 200);

    let spool = pipeline.with_service(standby, |service| {
        Ok(Arc::clone(service.snapshot_spool.as_ref().ok_or("actual snapshot spool")?))
    })?;
    let occupied = spool.lease()?;
    let before = pipeline.native_selection(leader)?;
    let old_floor = floor(&pipeline, leader)?.ok_or("actual prior floor")?;
    let refused = wire(
        &pipeline, standby, "POST", SNAPSHOT, &reader, b"not-gzip", None,
    )?;
    assert_eq!(refused.status, 403);
    assert!(!refused.body.starts_with(&[0x1f, 0x8b]));
    assert!(spool.lease().is_err(), "the real transfer lease is still occupied");
    let after = pipeline.native_selection(leader)?;
    let committed = floor(&pipeline, leader)?.ok_or("actual denied clock floor")?;
    assert_eq!(after.0, before.0 + 1, "exactly one real clock-only publication");
    assert!(committed > old_floor);
    assert_eq!(pipeline.native_selection(standby)?, after);
    assert_eq!(floor(&pipeline, standby)?, Some(committed));
    no_snapshot_custody(&pipeline, standby)?;
    drop((occupied, spool, first));

    pipeline.stop_process(standby)?;
    start_formal_process(&mut pipeline, standby)?;
    pipeline.wait_cold_native_readindex_ready(standby)?;
    pipeline.unseal(standby)?;
    assert!(floor(&pipeline, standby)?.is_some_and(|actual| actual >= committed));
    assert_eq!(
        wire(&pipeline, standby, "POST", SNAPSHOT, &reader, b"not-gzip", None)?.status,
        403,
    );

    // A real physical-seal failure cannot be hidden behind the same ACL 403.
    let seal_path = pipeline.with_service(standby, |service| Ok(service.data_dir.join("seal.json")))?;
    let permissions = fs::metadata(&seal_path)?.permissions();
    let before = pipeline.native_selection(leader)?;
    fs::set_permissions(&seal_path, fs::Permissions::from_mode(0o644))?;
    let observed = wire(
        &pipeline, standby, "POST", SNAPSHOT, &reader, b"not-gzip", None,
    );
    fs::set_permissions(&seal_path, permissions)?;
    let refused = observed?;
    assert_eq!(refused.status, 503);
    assert!(!refused.body.starts_with(&[0x1f, 0x8b]));
    assert_eq!(pipeline.native_selection(leader)?, before, "no floor after failed physical seal");
    pipeline.with_service(standby, |service| {
        // A physical corruption may deliberately fence the Service. It must
        // retain no resource delivery or partially admitted transfer owner.
        assert!(service.pending_snapshot_transfer.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    Ok(())
}

#[test]
fn formal_native_standby_original_snapshot_actor_expiry_before_floor_returns_proved_403()
-> TestResult {
    let pipeline = formal_cold_source()?;
    let leader = pipeline.ready_leader()?;
    activate_formal_cold(&pipeline, leader)?;
    let standby = (leader + 1) % 3;
    let reader = snapshot_policy_token(&pipeline, leader, "expiry-reader", false, "6s")?;
    let issued_response = Instant::now();
    let before = pipeline.native_selection(leader)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let ingress = crypto::random::<16>()?;
    let _ingress = IngressReplyScope::listener(&ingress);
    let service = pipeline.services[standby].as_ref().ok_or("expiry standby")?;
    let mut owner = lock_until(service, until).map_err(|_| "expiry admission lock")?;
    let mut pending = admit(&mut owner, "GET", &reader, until)?;
    drop(owner);
    let (observation, archive) = pending.execute_snapshot_transfer(&mut io::empty());
    assert!(archive.is_some(), "actual archive exists privately before delivery");
    let expired_at = issued_response + Duration::from_millis(6100);
    assert!(expired_at < until);
    thread::sleep(expired_at.saturating_duration_since(Instant::now()));
    let mut owner = lock_until(service, until).map_err(|_| "expiry finalizer lock")?;
    let denied = owner.finish_external_request(*pending, observation);
    assert_eq!(denied.status, 403);
    assert!(denied.body.get("data").is_none());
    assert!(Instant::now() < until, "real token expiry, not request deadline");
    assert!(owner.native_request_binding.is_none());
    drop((owner, archive));
    let after = pipeline.native_selection(leader)?;
    assert_eq!(after.0, before.0 + 1);
    assert_eq!(pipeline.native_selection(standby)?, after);
    assert_eq!(floor(&pipeline, standby)?, floor(&pipeline, leader)?);
    no_snapshot_custody(&pipeline, standby)?;
    Ok(())
}

#[test]
fn formal_native_snapshot_clock_actual_mtls_nochange_keeps_full_local_checkpoints()
-> TestResult {
    let pipeline = formal_cold_source()?;
    let leader = pipeline.ready_leader()?;
    activate_formal_cold(&pipeline, leader)?;
    let standby = (leader + 1) % 3;
    assert_eq!(floor(&pipeline, leader)?, None);
    let initial = pipeline.native_selection(leader)?;
    for (token, denied) in [(pipeline.admin(), false), ("invalid-original-bearer", true)] {
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let ingress = crypto::random::<16>()?;
        let _ingress = IngressReplyScope::listener(&ingress);
        let original = pipeline.with_service_mut_for_delivery_test(standby, |service| {
            service.sync_from_ha_with_anchor(false)
                .map_err(|response| format!("NoChange sync HTTP {}", response.status))?;
            service.capture_native_ha_request_proof(&mut || Ok(()))
                .map_err(|response| format!("NoChange original proof HTTP {}", response.status))?
                .ok_or_else(|| "actual NoChange original proof absent".into())
        })?;
        let before = pipeline.with_service(leader, |service| {
            Ok((
                service.current_state_identity().map_err(|_| "leader identity")?,
                service.external_effect_generation().map_err(|_| "leader generation")?,
            ))
        })?;
        let source = original.snapshot_clock_shared_state();
        let context = SnapshotClockContext {
            operation: SnapshotClockOperation::Download,
            method: "GET",
            token,
            origin_peer: None,
            ingress,
            source,
            enrollment: original.snapshot_clock_enrollment(),
            deadline: until,
        };
        let completion = {
            let process = pipeline.processes[standby].as_ref().ok_or("actual caller")?
                .lock_for_request().map_err(|_| "NoChange caller lock")?;
            let receipt = process.observe_snapshot_terminal_clock(context)
                .map_err(|response| format!("actual NoChange exchange HTTP {}", response.status))?;
            receipt.consume(&process, context)
                .map_err(|response| format!("actual NoChange receipt HTTP {}", response.status))?
        };
        assert!(completion.successor().is_none());
        assert_eq!(completion.is_denied(), denied);
        pipeline.with_service_mut_for_delivery_test(standby, |service| {
            service.sync_from_ha_with_anchor(false)
                .map_err(|response| format!("NoChange completion sync HTTP {}", response.status))?;
            let current = service.capture_native_ha_request_proof(&mut || Ok(()))
                .map_err(|response| format!("NoChange current proof HTTP {}", response.status))?
                .ok_or("actual NoChange current proof absent")?;
            assert_eq!(current.snapshot_clock_shared_state(), source);
            original.check_with(service, Service::check_native_installed)
                .map_err(|response| format!("NoChange source proof HTTP {}", response.status))?;
            current.check_warm(service)
                .map_err(|response| format!("NoChange current proof HTTP {}", response.status))?;
            Ok(())
        })?;
        let after = pipeline.with_service(leader, |service| {
            Ok((
                service.current_state_identity().map_err(|_| "leader identity")?,
                service.external_effect_generation().map_err(|_| "leader generation")?,
            ))
        })?;
        assert!(before == after, "strict identity and complete publication generation unchanged");
        if denied {
            completion.finish_denied()
                .map_err(|response| format!("Denied completion HTTP {}", response.status))?;
        } else {
            completion.finish_allowed()
                .map_err(|response| format!("Allowed completion HTTP {}", response.status))?;
        }
        assert_eq!(pipeline.native_selection(leader)?, initial);
        assert_eq!(floor(&pipeline, leader)?, None);
        assert!(Instant::now() < until);
    }
    Ok(())
}
