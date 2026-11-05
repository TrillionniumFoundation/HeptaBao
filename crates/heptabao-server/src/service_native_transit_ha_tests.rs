//! Formal native Raft storage and local Transit through the original real TLS
//! Pipeline. This test is not public HTTP or physical power-loss qualification.
use super::*;
use crate::configuration::NativeStorageProfile;
const PLAINTEXT: &str = "c3ludGhldGljLXRyYW5zaXQ=";

fn start_formal(pipeline: &mut Pipeline, index: usize) -> TestResult {
    pipeline.start_process(index)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[index]
        .as_ref()
        .ok_or("Transit formal Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "Transit formal startup deadline")?;
    assert!(writer.state.is_none());
    writer.configure_native_v6_storage(NativeStorageProfile::Raft)?;
    assert!(matches!(
        writer.native_storage_profile,
        Some(NativeStorageProfile::Raft)
    ));
    assert!(writer.native_candidate_profile.is_none());
    assert!(Instant::now() < until);
    Ok(())
}
fn formal_pipeline() -> TestResult<Pipeline> {
    let mut files = Root::new();
    private_directory(&files.path)?;
    files.path = fs::canonicalize(&files.path)?;
    let seed = files.path.join("seed");
    private_directory(&seed)?;
    let mut service = Service::new(seed.join("data"), &seed.join("audit.jsonl"))?;
    let (key, admin) = {
        let _scope = scope();
        crate::service::tests::bootstrap_unmounted(&mut service)?
    };
    let key = Zeroizing::new(key);
    let admin = Zeroizing::new(admin);
    for (path, body, status) in [
        ("sys/init/ack", json!({}), 204),
        (
            "sys/mounts/secret",
            json!({"type":"kv","options":{"version":"2"}}),
            204,
        ),
        (
            "secret/data/pipeline/history",
            json!({"options":{"cas":0},"data":{"value":"seed-v5"}}),
            200,
        ),
    ] {
        let _scope = scope();
        expect(
            service.handle("POST", path, "", &admin, body),
            status,
            "formal-Transit-seed",
        )?;
    }
    assert!(!initialization_recovery_pending(&service.data_dir)?);
    let state = service.state.as_ref().ok_or("Transit seed state")?;
    let cluster_id = state.cluster_id.clone();
    assert!(state.engines.supports_native_v6_root_storage());
    let seed_identity = service
        .current_state_identity()
        .map_err(|_| "Transit seed identity")?;
    assert!(matches!(
        seed_identity,
        crate::state_record_root::StateIdentity::RecordsV5(_)
    ));
    drop(service);
    // Only the preactivation V5 seed is copied. Every native publication and
    // catch-up below uses the actual typed-closure and pinned TLS peers.
    for id in 1..=3 {
        let directory = files.path.join(format!("service-{id}"));
        private_directory(&directory)?;
        copy_cold_directory(&seed.join("data"), &directory.join("data"))?;
    }
    let pins = certificates(&files.path)?;
    let configs = configurations(&files.path, &cluster_id, &pins)?;
    let mut pipeline = Pipeline {
        configured_native_storage: false,
        files,
        configs,
        processes: vec![None, None, None],
        services: vec![None, None, None],
        key,
        admin,
        seed_identity,
    };
    for index in [1, 2, 0] {
        start_formal(&mut pipeline, index)?;
    }
    let leader = pipeline.ready_leader()?;
    for index in std::iter::once(leader).chain((0..3).filter(|index| *index != leader)) {
        pipeline.unseal(index)?;
    }
    Ok(pipeline)
}
fn selection(pipeline: &Pipeline, index: usize) -> TestResult<(u64, [u8; 32], u64)> {
    let _scope = scope();
    let process = pipeline.processes[index]
        .as_ref()
        .ok_or("Transit Raft process")?
        .lock_for_request()
        .map_err(|_| "Transit ReadIndex lock")?;
    let actual = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("Transit native committed root")?;
    process.verify_native_v6_committed_read(&actual)?;
    Ok((
        actual.published().generation(),
        actual.published().root_digest(),
        actual.published().publication_log_id().index,
    ))
}
fn decrypt_on(pipeline: &Pipeline, index: usize, cipher: &str) -> TestResult {
    let mut response = expect(
        pipeline.call(
            index,
            "POST",
            "transit/decrypt/quorum",
            pipeline.admin(),
            json!({"ciphertext":cipher}),
        )?,
        200,
        "formal-HA-Transit-decrypt",
    )?;
    assert!(response.body["data"]["plaintext"].as_str() == Some(PLAINTEXT));
    erase_json(&mut response.body);
    Ok(())
}

#[test]
fn native_transit_formal_ha_tls_readindex_failover_and_two_cold_rejoins() -> TestResult {
    let mut pipeline = formal_pipeline()?;
    let first = pipeline.ready_leader()?;
    expect(
        pipeline.call(
            first,
            "POST",
            "sys/storage/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "formal-HA-public-activation",
    )?;
    let graphs = pipeline.with_service(first, |service| {
        Ok(service
            .native_root
            .as_ref()
            .ok_or("Transit native graph")?
            .kv2
            .clone())
    })?;
    let standby = (first + 1) % 3;
    expect(
        pipeline.call(
            standby,
            "POST",
            "sys/mounts/transit",
            pipeline.admin(),
            json!({"type":"transit","cas_revision":0}),
        )?,
        204,
        "formal-HA-forwarded-Transit-mount",
    )?;
    let mut encrypted = expect(
        pipeline.call(
            standby,
            "POST",
            "transit/encrypt/quorum",
            pipeline.admin(),
            json!({"plaintext":PLAINTEXT}),
        )?,
        200,
        "formal-HA-forwarded-Transit-encrypt",
    )?;
    let cipher = secret_field(&mut encrypted, "/data/ciphertext")?;
    let written = selection(&pipeline, first)?;
    for index in 0..3 {
        decrypt_on(&pipeline, index, &cipher)?;
        assert_eq!(selection(&pipeline, index)?, written);
        pipeline.with_service(index, |service| {
            assert!(
                service
                    .native_root
                    .as_ref()
                    .ok_or("Transit native graph")?
                    .kv2
                    == graphs
            );
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
    expect(
        pipeline.call(
            next,
            "POST",
            "transit/keys/quorum/rotate",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-HA-rotation-old-leader-absent",
    )?;
    let rotated = selection(&pipeline, next)?;
    assert!(rotated.0 > written.0 && rotated.2 > written.2 && rotated.1 != written.1);
    decrypt_on(&pipeline, next, &cipher)?;
    start_formal(&mut pipeline, first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    assert_eq!(selection(&pipeline, first)?, rotated);
    decrypt_on(&pipeline, first, &cipher)?;
    // A second cold cycle retains only each actual local durable owner. No
    // native root/ciphertext or key is transplanted by the test.
    for index in 0..3 {
        pipeline.stop_process(index)?;
    }
    for index in [1, 2, 0] {
        start_formal(&mut pipeline, index)?;
    }
    let leader = pipeline.ready_leader()?;
    for index in std::iter::once(leader).chain((0..3).filter(|index| *index != leader)) {
        pipeline.unseal(index)?;
    }
    for index in 0..3 {
        decrypt_on(&pipeline, index, &cipher)?;
        let descriptor = expect(
            pipeline.call(
                index,
                "GET",
                "transit/keys/quorum",
                pipeline.admin(),
                json!({}),
            )?,
            200,
            "formal-HA-cold-key-version",
        )?;
        assert_eq!(descriptor.body["data"]["latest_version"], 2);
        assert_eq!(selection(&pipeline, index)?, rotated);
        pipeline.assert_history(index, &[(1, "seed-v5")])?;
    }
    Ok(())
}
