//! An authenticated native archive with no Token API precision owner is
//! restored over a genuinely newer owner in a different real TLS/Raft cohort.
//! The original archive, schema gates and 15-second restore budget remain.
use super::*;

fn checked_precision_floor(
    pipeline: &Pipeline,
    index: usize,
) -> TestResult<crate::auth::Timestamp> {
    pipeline.with_service(index, |service| {
        let state = service.state.as_ref().ok_or("clock-floor selected state")?;
        state
            .validate_format()
            .map_err(|_| "clock-floor selected format")?;
        state.auth.validate_token_api_precision_state()?;
        assert!(state.auth.has_token_api_precision_state());
        let floor = state
            .auth
            .terminal_token_clock_floor()
            .ok_or("clock-floor retained precise owner")?;
        assert_eq!(
            state
                .auth
                .token_api_observed_time(AuthorityTime::Precise(crate::auth::Timestamp::whole(0)?))
                .exact(),
            Some(floor)
        );
        Ok(floor)
    })
}

fn checked_unmarked_archive_source(pipeline: &Pipeline, leader: usize) -> TestResult<u32> {
    pipeline.with_service(leader, |service| {
        let state = service.state.as_ref().ok_or("unmarked archive state")?;
        state
            .validate_format()
            .map_err(|_| "unmarked archive format")?;
        state.auth.validate_token_api_precision_state()?;
        assert!(!state.has_token_api_precision_state());
        assert!(state.auth.terminal_token_clock_floor().is_none());
        // Observe a naturally written schema. This test never assigns a
        // schema or promotes the authenticated archive during restoration.
        assert!(state.schema >= TOKEN_API_PRECISION_STATE_SCHEMA);
        assert_eq!(
            service
                .native_root
                .as_ref()
                .ok_or("unmarked archived native root")?
                .state_schema,
            state.schema
        );
        Ok(state.schema)
    })
}

// Test-only immutable payload observation. The public storage-witness route
// deliberately remains single-node-only; this does not call it or manufacture
// an Actor, HTTP response grant, Raft intent, or publication receipt.
fn clock_floor_stored_payload(
    pipeline: &Pipeline,
    index: usize,
    version: u64,
) -> TestResult<Value> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let deadline = OriginalDeadline::capture()?;
    let service = pipeline.services[index]
        .as_ref()
        .ok_or("clock-floor actual storage Service")?;
    let mut service = lock_until(service, until).map_err(|_| "clock-floor storage lock")?;
    assert!(service.ha.is_some());
    assert!(matches!(
        service.native_storage_profile,
        Some(crate::configuration::NativeStorageProfile::Raft)
    ));
    assert!(service.native_candidate_profile.is_none());
    let identity = service
        .current_state_identity()
        .map_err(|_| "clock-floor actual storage identity")?;
    let generation = service
        .durable
        .as_ref()
        .ok_or("clock-floor actual durable")?
        .generation();
    let proof = service
        .capture_native_ha_unseal_proof()
        .map_err(|_| "clock-floor actual HA read proof")?
        .ok_or("clock-floor HA read proof absent")?;
    assert_eq!(proof.identity(), identity);
    assert_eq!(proof.generation(), generation);
    proof
        .check_warm(&service)
        .map_err(|_| "clock-floor initial HA proof")?;
    let process = Arc::clone(
        pipeline.processes[index]
            .as_ref()
            .ok_or("clock-floor actual HA process")?,
    );
    let committed = {
        let process = process
            .lock_for_request()
            .map_err(|_| "clock-floor ReadIndex owner")?;
        let read = process
            .native_v6_committed_read(deadline)?
            .ok_or("clock-floor fresh committed root absent")?;
        process.verify_native_v6_committed_read(&read)?;
        assert_eq!(read.published().root_digest(), identity.digest());
        read
    };
    let verify_read = || -> Result<(), ServiceError> {
        deadline.check().map_err(|_| ServiceError::BarrierFailure)?;
        let process = process
            .lock_for_request()
            .map_err(|_| ServiceError::BarrierFailure)?;
        process
            .verify_native_v6_committed_read(&committed)
            .map_err(|_| ServiceError::BarrierFailure)?;
        deadline.check().map_err(|_| ServiceError::BarrierFailure)
    };
    let engines = service
        .state
        .as_ref()
        .ok_or("clock-floor selected engine state")?
        .engines
        .clone();
    // Only this reader receives these counters, so a background read cannot
    // supply the required actual payload AEAD-open observation.
    let observations = Arc::new(native_blob_source::PayloadObservations::default());
    let durable = service
        .durable
        .as_mut()
        .ok_or("clock-floor selected durable reader")?;
    let source = native_blob_source::NativeSource::new_checked(durable, deadline, &verify_read)
        .map_err(|_| "clock-floor actual immutable source")?
        .with_observations(Arc::clone(&observations));
    let witness = engines
        .native_kv2_storage_witness(
            "secret",
            "pipeline/history",
            version,
            |scope, reference| {
                source.read_paged_payload(
                    &crate::state_record_root_v6::ObjectDomain::Kv2(scope.clone()),
                    reference,
                )
            },
            &|| verify_read().map_err(|_| crate::state_records::RecordError::Invalid),
        )
        .map_err(|_| "clock-floor actual lossless payload read")?;
    drop(source);
    verify_read()?;
    proof
        .check_warm(&service)
        .map_err(|_| "clock-floor final HA proof")?;
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "clock-floor final storage identity")?,
        identity
    );
    assert_eq!(
        service
            .durable
            .as_ref()
            .ok_or("clock-floor retained durable")?
            .generation(),
        generation
    );
    assert!(service.ha.is_some());
    let observed = observations.snapshot();
    assert!(observed[1] > 0 && observed[2] > 0 && observed[3] > 0);
    deadline.check()?;
    assert!(Instant::now() < until);
    Ok(witness)
}

fn assert_clock_floor_history(pipeline: &Pipeline, index: usize) -> TestResult {
    for (version, data, api_data, canonical, expected_hash) in [
        (
            1_u64,
            json!({"value":"seed-v5"}),
            json!({"value":"seed-v5"}),
            br#"{"value":"seed-v5"}"#.as_slice(),
            "e90b0636ccbcae5b8e97c69842dd5913d064e7009a2bbef4bb54c6d9442a5c94",
        ),
        (
            2,
            json!({"value":"unmarked-archive", "exact_integer":9007199254740993_u64}),
            // Independent actual OpenBao 2.7.1 API observation, also retained
            // in full34_api_data. This is not the saved payload expectation.
            json!({"value":"unmarked-archive", "exact_integer":9007199254740992_u64}),
            br#"{"exact_integer":9007199254740993,"value":"unmarked-archive"}"#.as_slice(),
            "cc29d9224d4b5186d9a0c313571dbb8ca87978897f208153e3c4d00177c8f827",
        ),
    ] {
        // Preserve the original complete data expectation at the lossless
        // storage boundary. These independently hashed bytes are not derived
        // from the product's public numeric projection.
        assert!(serde_json::from_slice::<Value>(canonical)? == data);
        let reply = expect(
            pipeline.call(
                index,
                "GET",
                "secret/data/pipeline/history",
                pipeline.admin(),
                json!({"version":version}),
            )?,
            200,
            "clock-floor-restored-history",
        )?;
        assert!(reply.body["data"]["data"] == api_data);
        assert_eq!(reply.body["data"]["metadata"]["version"], version);
        let stored = clock_floor_stored_payload(pipeline, index, version)?;
        assert_eq!(stored["schema"], "heptabao-native-kv2-storage-witness-v1");
        assert_eq!(stored["canonical_profile"], "heptabao-lossless-json-v1");
        assert_eq!(stored["mount"], "secret");
        assert_eq!(stored["path"], "pipeline/history");
        assert_eq!(stored["version"], version);
        assert!(
            stored["mount_incarnation"]
                .as_u64()
                .is_some_and(|id| id > 0)
        );
        for field in ["created_time", "deletion_time", "destroyed"] {
            assert_eq!(stored[field], reply.body["data"]["metadata"][field]);
        }
        assert_eq!(stored["destroyed"], false);
        assert_eq!(stored["payload_present"], true);
        assert_eq!(stored["payload_canonical_bytes"], canonical.len() as u64);
        assert_eq!(stored["payload_canonical_sha256"], expected_hash);
        assert!(stored.get("payload").is_none() && stored.get("data").is_none());
    }
    Ok(())
}

fn assert_temporary_owner_removed(
    pipeline: &Pipeline,
    index: usize,
    temporary_root: &str,
) -> TestResult {
    expect(
        pipeline.call(
            index,
            "GET",
            "auth/token/lookup-self",
            temporary_root,
            json!({}),
        )?,
        403,
        "clock-floor-temporary-token-removed",
    )?;
    expect(
        pipeline.call(
            index,
            "GET",
            "secret/data/clock-floor/temporary",
            pipeline.admin(),
            json!({}),
        )?,
        404,
        "clock-floor-temporary-data-removed",
    )?;
    Ok(())
}

#[test]
fn cold_dr_unmarked_archive_inherits_precision_owner_without_resurrecting_temporary_authority()
-> TestResult {
    let mut source = formal_cold_source()?;
    let leader = source.ready_leader()?;
    let migration = activate_formal_cold(&source, leader)?;
    expect(
        source.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            source.admin(),
            json!({"options":{"cas":1},
                "data":{"value":"unmarked-archive", "exact_integer":9007199254740993_u64}}),
        )?,
        200,
        "clock-floor-actual-source-kv2-publication",
    )?;
    checked_unmarked_archive_source(&source, leader)?;
    let epoch_zero = export(&source, leader, source.admin())?;
    expect(
        restore(&source, leader, source.admin(), &epoch_zero)?,
        200,
        "clock-floor-source-original-lineage-restore",
    )?;
    assert_eq!(selection(&source, leader, migration)?.0, 1);
    assert_clock_floor_history(&source, leader)?;
    let archive_schema = checked_unmarked_archive_source(&source, leader)?;
    let archive = export(&source, leader, source.admin())?;
    assert_eq!(
        checked_unmarked_archive_source(&source, leader)?,
        archive_schema
    );
    // No source auth/token/create, synthetic marker, timestamp, lease,
    // authenticated root, Raft intent or recovery receipt is supplied.
    let seal_bytes = fs::read(source.directory(leader).join("data/seal.json"))?;
    let key = Zeroizing::new(source.key.as_str().to_owned());
    let admin = Zeroizing::new(source.admin.as_str().to_owned());
    let cluster_id = source.with_service(leader, |service| {
        Ok(service
            .state
            .as_ref()
            .ok_or("clock-floor source cluster")?
            .cluster_id
            .clone())
    })?;
    let old_peer_pin = source.configs[0].peers[&1].certificate_sha256.clone();
    let old_shared_key_hash = crypto::digest(&fs::read(&source.configs[0].replication_key_file)?);
    let mut bundle = Root::new();
    private_directory(&bundle.path)?;
    bundle.path = fs::canonicalize(&bundle.path)?;
    let archive_path = bundle.path.join("snapshot.bin");
    let seal_path = bundle.path.join("seal.json");
    let shares_path = bundle.path.join("shares.json");
    private_file(&archive_path, &archive)?;
    private_file(&seal_path, &seal_bytes)?;
    let shares = Zeroizing::new(serde_json::to_vec(&[key.as_str()])?);
    private_file(&shares_path, &shares)?;
    drop(shares);
    let archive_hash = hex(&crypto::digest(&archive));
    let seal_hash = hex(&crypto::digest(&seal_bytes));
    let old_path = source.files.path.clone();
    for index in 0..3 {
        source.stop_process(index)?;
    }
    fs::rename(&old_path, bundle.path.join("old-cluster.quarantined"))?;
    drop(source);
    assert!(!old_path.exists());

    let destination = bundle.path.join("recovered-seed");
    let receipt = crate::service::native_seed::recover_ha_seed(
        &archive_path,
        &seal_path,
        &shares_path,
        &destination,
        &archive_hash,
        &seal_hash,
    )?;
    let receipt = serde_json::to_value(receipt)?;
    assert_eq!(receipt["current_native_data_installed"], false);
    assert_eq!(receipt["ha_qualified"], false);
    assert_eq!(receipt["complete_archive_and_graph_authenticated"], true);
    assert_eq!(receipt["retained_source_replay_epoch"], 0);
    assert_eq!(receipt["native_replay_epoch"], 1);
    assert_eq!(receipt["bootstrap_replay_epoch"], 1);
    assert_eq!(fs::read_dir(&destination)?.count(), 4);
    assert!(fs::read(destination.join("seal.json"))? == seal_bytes);
    let seed_identity =
        StateIdentity::RecordsV5(digest_from_receipt(&receipt, "bootstrap_root_sha256")?);
    let mut target = recovered_pipeline(&destination, &cluster_id, key, admin, seed_identity)?;
    assert!(target.configs[0].peers[&1].certificate_sha256 != old_peer_pin);
    assert_ne!(
        crypto::digest(&fs::read(&target.configs[0].replication_key_file)?),
        old_shared_key_hash
    );
    let leader = target.ready_leader()?;
    let observation = crate::service::native_v6_writer::activation_source_observation::arm()?;
    expect(
        target.call(
            leader,
            "POST",
            "sys/storage/native-v6/activate",
            target.admin(),
            json!({}),
        )?,
        204,
        "clock-floor-new-cohort-real-activation",
    )?;
    let new_migration = observation.take()?;
    assert_eq!(selection(&target, leader, new_migration)?.0, 1);
    checked_unmarked_archive_source(&target, leader)?;
    let temporary_root = root_token(&target, leader, "20m")?;
    let initial_floor = checked_precision_floor(&target, leader)?;
    expect(
        target.call(
            leader,
            "POST",
            "secret/data/clock-floor/temporary",
            target.admin(),
            json!({"data":{"value":"new-cohort-only"}}),
        )?,
        200,
        "clock-floor-current-only-data",
    )?;
    expect(
        restore(&target, leader, target.admin(), &archive)?,
        400,
        "clock-floor-ordinary-lineage-still-refused",
    )?;
    assert_eq!(selection(&target, leader, new_migration)?.0, 1);
    expect(
        target.call(
            leader,
            "GET",
            "secret/data/clock-floor/temporary",
            target.admin(),
            json!({}),
        )?,
        200,
        "clock-floor-ordinary-refusal-keeps-current-data",
    )?;
    let before_force = checked_precision_floor(&target, leader)?;
    assert!(before_force >= initial_floor);
    let began = Instant::now();
    let forced = force_restore(&target, leader, &archive)?;
    let elapsed = began.elapsed();
    eprintln!(
        "heptabao_dr_unmarked_precision_force status={} archive_has_precision=false archive_schema={} current_has_precision=true original_budget_ms=15000 elapsed_ms={}",
        forced.status,
        archive_schema,
        elapsed.as_millis()
    );
    assert!(elapsed < REQUEST_BUDGET);
    let forced = expect(forced, 200, "clock-floor-new-cohort-force-restore")?;
    assert_eq!(forced.body["data"]["replay_epoch"], 2);
    assert_eq!(selection(&target, leader, new_migration)?.0, 2);
    assert!(checked_precision_floor(&target, leader)? >= before_force);
    assert_clock_floor_history(&target, leader)?;
    assert_temporary_owner_removed(&target, leader, &temporary_root)?;
    let before_restart = checked_precision_floor(&target, leader)?;

    for index in 0..3 {
        target.stop_process(index)?;
    }
    for index in [1, 2, 0] {
        start_formal_process(&mut target, index)?;
    }
    let leader = target.ready_leader()?;
    for index in std::iter::once(leader).chain((0..3).filter(|index| *index != leader)) {
        unseal_fresh_current(&target, index, new_migration)?;
    }
    for index in 0..3 {
        assert_clock_floor_history(&target, index)?;
        assert_temporary_owner_removed(&target, index, &temporary_root)?;
        assert!(checked_precision_floor(&target, index)? >= before_restart);
        assert_eq!(selection(&target, index, new_migration)?.0, 2);
    }
    assert!(fs::read(&archive_path)? == archive);
    assert!(fs::read(&seal_path)? == seal_bytes);
    eprintln!(
        "heptabao_dr_unmarked_precision_verified force_status=200 ordinary_status=400 archive_has_precision=false retained_precision=true temporary_token_status=403 temporary_data_status=404 cold_nodes=3 original_budget_ms=15000"
    );
    Ok(())
}
