//! Normal native_v6_raft configuration, real three-node Raft and pinned TLS.
//! This uses parse_server/validate_storage and HaProcess::start_with_storage,
//! not the fixture candidate constructor. Public HTTPS and physical-host
//! failure qualification are not supplied by these process-local tests.
use super::formal_fixture::FormalPipeline as TotpPipeline;
use super::*;
use crate::configuration::NativeStorageProfile;

const IMPORTED_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn selection(pipeline: &Pipeline, index: usize) -> TestResult<(u64, [u8; 32], u64)> {
    let _scope = scope();
    let process = pipeline.processes[index]
        .as_ref()
        .ok_or("TOTP Raft process")?
        .lock_for_request()
        .map_err(|_| "TOTP ReadIndex lock")?;
    let actual = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("TOTP native committed root")?;
    process.verify_native_v6_committed_read(&actual)?;
    Ok((
        actual.published().generation(),
        actual.published().root_digest(),
        actual.published().publication_log_id().index,
    ))
}

fn imported(label: &str) -> Value {
    json!({"key":IMPORTED_SEED,"issuer":label,"account_name":"synthetic",
        "algorithm":"SHA256","digits":8,"period":3600,"skew":1})
}

fn active_pipeline() -> TestResult<(TotpPipeline, usize)> {
    let pipeline = TotpPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let standby = (leader + 1) % 3;
    expect(
        pipeline.call(
            standby,
            "POST",
            "sys/mounts/totp",
            pipeline.admin(),
            json!({"type":"totp","cas_revision":0}),
        )?,
        204,
        "formal-HA-forwarded-TOTP-mount",
    )?;
    expect(
        pipeline.call(
            standby,
            "POST",
            "totp/keys/quorum",
            pipeline.admin(),
            imported("initial"),
        )?,
        204,
        "formal-HA-forwarded-TOTP-import",
    )?;
    Ok((pipeline, leader))
}

fn replay_on(pipeline: &Pipeline, index: usize) -> TestResult<(Option<u64>, u64, u32)> {
    expect(
        pipeline.call(
            index,
            "GET",
            "totp/keys/quorum",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-HA-TOTP-actual-read-before-observation",
    )?;
    pipeline.with_service(index, |service| {
        service
            .state
            .as_ref()
            .ok_or("TOTP native state")?
            .engines
            .native_totp_replay_observation("totp/", "quorum")
            .ok_or_else(|| "TOTP replay state".into())
    })
}

#[test]
fn native_totp_formal_ha_tls_counter_readindex_failover_and_two_cold_rejoins() -> TestResult {
    let (mut pipeline, first) = active_pipeline()?;
    let standby = (first + 1) % 3;
    let graphs = pipeline.with_service(first, |service| {
        Ok(service
            .native_root
            .as_ref()
            .ok_or("TOTP graph")?
            .kv2
            .clone())
    })?;
    let mut generated = expect(
        pipeline.call(
            standby,
            "GET",
            "totp/code/quorum",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-HA-TOTP-code",
    )?;
    let submitted = secret_field(&mut generated, "/data/code")?;
    let accepted = expect(
        pipeline.call(
            standby,
            "POST",
            "totp/code/quorum",
            pipeline.admin(),
            json!({"code":submitted.as_str()}),
        )?,
        200,
        "formal-HA-TOTP-validation",
    )?;
    assert!(accepted.body["data"]["valid"] == true);
    let written = selection(&pipeline, first)?;
    let consumed = replay_on(&pipeline, first)?;
    assert!(consumed.0.is_some() && consumed.2 == 0);
    for index in 0..3 {
        assert_eq!(replay_on(&pipeline, index)?, consumed);
        assert_eq!(selection(&pipeline, index)?, written);
        pipeline.with_service(index, |service| {
            assert!(service.native_root.as_ref().ok_or("TOTP graph")?.kv2 == graphs);
            assert!(matches!(
                service.native_storage_profile,
                Some(NativeStorageProfile::Raft)
            ));
            Ok(())
        })?;
    }
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(first, next);
    assert_eq!(selection(&pipeline, next)?, written);
    let rejected = expect(
        pipeline.call(
            next,
            "POST",
            "totp/code/quorum",
            pipeline.admin(),
            json!({"code":submitted.as_str()}),
        )?,
        200,
        "formal-HA-TOTP-replay-old-leader-absent",
    )?;
    assert!(rejected.body["data"]["valid"] == false);
    let failed = replay_on(&pipeline, next)?;
    assert_eq!(failed.0, consumed.0);
    assert_eq!(failed.2, 1);
    expect(
        pipeline.call(
            next,
            "PUT",
            "totp/keys/quorum",
            pipeline.admin(),
            imported("metadata-only"),
        )?,
        204,
        "formal-HA-same-seed-preserves-replay",
    )?;
    assert_eq!(replay_on(&pipeline, next)?, failed);
    let current = selection(&pipeline, next)?;
    assert!(current.0 > written.0 && current.2 > written.2 && current.1 != written.1);
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    assert_eq!(replay_on(&pipeline, first)?, failed);
    assert_eq!(selection(&pipeline, first)?, current);
    // This second cycle uses only the three real local durable stores. It does
    // not copy a native root, replay receipt, counter, key or ciphertext.
    for index in 0..3 {
        pipeline.stop_process(index)?;
    }
    for index in [1, 2, 0] {
        pipeline.start_formal_process(index)?;
    }
    let leader = pipeline.ready_leader()?;
    for index in std::iter::once(leader).chain((0..3).filter(|index| *index != leader)) {
        pipeline.unseal(index)?;
    }
    for index in 0..3 {
        assert_eq!(replay_on(&pipeline, index)?, failed);
        assert_eq!(selection(&pipeline, index)?, current);
        pipeline.with_service(index, |service| {
            assert!(service.native_root.as_ref().ok_or("TOTP cold graph")?.kv2 == graphs);
            assert!(service.pending_native_auth_delivery.is_none());
            Ok(())
        })?;
        pipeline.assert_history(index, &[(1, "seed-v5")])?;
    }
    Ok(())
}

#[test]
fn native_totp_formal_ha_actual_post_audit_root_change_vetoes_private_code() -> TestResult {
    let (pipeline, leader) = active_pipeline()?;
    let before = selection(&pipeline, leader)?;
    let writer = pipeline.admin.clone();
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_observed = Arc::clone(&observed);
    let _hook = crate::service::native_auth::totp_tests::after_audit(move |service, response| {
        assert!(response.status == 200 && response.body["data"]["code"].is_string());
        hook_observed.store(true, std::sync::atomic::Ordering::SeqCst);
        // A real second quorum publication after actual mandatory audit cannot
        // renew the first request's proof or release its private code.
        let published = service.handle(
            "POST",
            "secret/data/pipeline/history",
            "",
            &writer,
            json!({"options":{"cas":1},"data":{"value":"after-totp-audit"}}),
        );
        assert_eq!(published.status, 200);
    })?;
    let response = expect(
        pipeline.call(
            leader,
            "GET",
            "totp/code/quorum",
            pipeline.admin(),
            json!({}),
        )?,
        503,
        "formal-HA-TOTP-old-proof-after-real-publication",
    )?;
    assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(response.body.get("data").is_none());
    let after = selection(&pipeline, leader)?;
    assert!(after.0 > before.0 && after.2 > before.2 && after.1 != before.1);
    for index in 0..3 {
        pipeline.assert_history(index, &[(1, "seed-v5"), (2, "after-totp-audit")])?;
        assert_eq!(selection(&pipeline, index)?, after);
    }
    Ok(())
}

#[test]
fn native_totp_formal_ha_actual_actor_clock_expiry_after_audit_vetoes_code() -> TestResult {
    const ACTOR_TTL_SECONDS: u64 = 5;
    let (pipeline, leader) = active_pipeline()?;
    expect(
        pipeline.call(
            leader,
            "PUT",
            "sys/policies/acl/totp-expiring",
            pipeline.admin(),
            json!({"policy":"path \"totp/code/quorum\" { capabilities=[\"read\"] }"}),
        )?,
        204,
        "formal-HA-TOTP-expiring-policy",
    )?;
    let mut issued = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/create",
            pipeline.admin(),
            json!({"policies":["totp-expiring"],"no_default_policy":true,"ttl":"5s"}),
        )?,
        200,
        "formal-HA-TOTP-expiring-actor",
    )?;
    assert_eq!(
        issued.body["auth"]["lease_duration"].as_u64(),
        Some(ACTOR_TTL_SECONDS),
    );
    // Issuance and its real HA publication precede this observation. Waiting
    // one full granted lease from here is a conservative real-expiry bound;
    // it does not move the token's grant, Actor or trusted request clock.
    let expired_by =
        Instant::now() + Duration::from_secs(ACTOR_TTL_SECONDS) + Duration::from_millis(100);
    let actor = secret_field(&mut issued, "/auth/client_token")?;
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_observed = Arc::clone(&observed);
    let _hook = crate::service::native_auth::totp_tests::after_audit(move |_service, response| {
        assert!(response.status == 200 && response.body["data"]["code"].is_string());
        let original_deadline = crate::request_deadline::current();
        assert!(
            original_deadline.is_some(),
            "TOTP expiry hook retains the original request deadline",
        );
        assert!(
            original_deadline.is_some_and(|deadline| expired_by < deadline),
            "real actor expiry must fit inside the original 15-second request",
        );
        hook_observed.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wait only inside the original post-audit boundary. Real admission
        // and terminal persistence may consume part of the five-second
        // lease, so wait to the one captured bound instead of resetting it.
        thread::sleep(expired_by.saturating_duration_since(Instant::now()));
        assert!(
            original_deadline.is_some_and(|deadline| Instant::now() < deadline),
            "original request deadline remains after real actor expiry",
        );
    })?;
    let response = expect(
        pipeline.call(leader, "GET", "totp/code/quorum", &actor, json!({}))?,
        503,
        "formal-HA-TOTP-original-actor-expired-after-audit",
    )?;
    assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(response.body.get("data").is_none());
    expect(
        pipeline.call(leader, "GET", "totp/code/quorum", &actor, json!({}))?,
        403,
        "formal-HA-TOTP-expired-actor-stays-denied",
    )?;
    pipeline.assert_history(leader, &[(1, "seed-v5")])?;
    Ok(())
}
