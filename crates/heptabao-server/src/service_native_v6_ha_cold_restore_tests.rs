//! A complete old HTTP archive and old Shamir envelope rebuild a NEW real
//! three-voter cohort. No old local data, replication key or Raft directory is
//! used by the destination. This is an in-process Service test with actual TLS
//! Raft peers; physical power-loss and public HTTP sockets remain separate.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

// The reusable experimental Pipeline also mounts Transit. Formal root storage
// deliberately supports KV and the local native-ready auth owners only. Build
// the positive cold fixture from the actual unmounted initializer, retain its
// real Shamir credentials, explicitly acknowledge initialization, and bind the
// ordinary Raft profile at every sealed Service startup.
fn start_formal_process(pipeline: &mut Pipeline, index: usize) -> TestResult {
    pipeline.start_process(index)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[index]
        .as_ref()
        .ok_or("formal cold Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "formal cold startup deadline")?;
    assert!(writer.state.is_none());
    writer.configure_native_v6_storage(crate::configuration::NativeStorageProfile::Raft)?;
    assert!(matches!(
        writer.native_storage_profile,
        Some(crate::configuration::NativeStorageProfile::Raft)
    ));
    assert!(writer.native_candidate_profile.is_none());
    assert!(Instant::now() < until);
    Ok(())
}

fn formal_cold_source() -> TestResult<Pipeline> {
    let mut files = Root::new();
    private_directory(&files.path)?;
    files.path = fs::canonicalize(&files.path)?;
    let mut service = Service::new(files.path.join("data"), &files.path.join("audit.jsonl"))?;
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
            json!({"type":"kv","options":{"version":"2"},"description":"Versioned secrets"}),
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
            "formal-cold-seed",
        )?;
    }
    let state = service.state.as_ref().ok_or("formal cold seed state")?;
    assert!(state.engines.supports_native_v6_root_storage());
    assert!(state.auth.supports_native_v6_root_storage());
    assert!(!initialization_recovery_pending(&service.data_dir)?);
    let cluster_id = state.cluster_id.clone();
    let seed_identity = service
        .current_state_identity()
        .map_err(|_| "formal cold seed identity")?;
    assert!(matches!(seed_identity, StateIdentity::RecordsV5(_)));
    drop(service);
    recovered_pipeline(
        &files.path.join("data"),
        &cluster_id,
        key,
        admin,
        seed_identity,
    )
}

fn activate_formal_cold(pipeline: &Pipeline, leader: usize) -> TestResult<StateIdentity> {
    pipeline.with_service(leader, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(crate::configuration::NativeStorageProfile::Raft)
        ));
        assert!(matches!(
            service
                .current_state_identity()
                .map_err(|_| "pre-activation source")?,
            StateIdentity::RecordsV5(_)
        ));
        assert!(service.native_root.is_none());
        Ok(())
    })?;
    let observation = crate::service::native_v6_writer::activation_source_observation::arm()?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/storage/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "historical-native-activation",
    )?;
    let source = observation.take()?;
    assert_eq!(selection(pipeline, leader, source)?.0, 0);
    Ok(source)
}

fn private_file(path: &Path, bytes: &[u8]) -> TestResult {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn digest_from_receipt(value: &Value, name: &str) -> TestResult<[u8; 32]> {
    let text = value[name].as_str().ok_or("cold receipt digest absent")?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("cold receipt digest malformed".into());
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
    }
    Ok(digest)
}

fn recovered_pipeline(
    seed: &Path,
    cluster_id: &str,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    seed_identity: StateIdentity,
) -> TestResult<Pipeline> {
    let mut files = Root::new();
    private_directory(&files.path)?;
    files.path = fs::canonicalize(&files.path)?;
    for id in 1..=3 {
        let directory = files.path.join(format!("service-{id}"));
        private_directory(&directory)?;
        copy_cold_directory(seed, &directory.join("data"))?;
    }
    let pins = certificates(&files.path)?;
    // Production configuration creates a genuinely fresh random shared key,
    // certificates, peer addresses and empty Raft directories for this cohort.
    let configs = configurations(&files.path, cluster_id, &pins)?;
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
        start_formal_process(&mut pipeline, index)?;
    }
    let leader = pipeline.ready_leader()?;
    for index in std::iter::once(leader).chain((0..3).filter(|index| *index != leader)) {
        pipeline.unseal(index)?;
    }
    for index in 0..3 {
        pipeline.with_service(index, |service| {
            assert!(service.native_candidate_profile.is_none());
            assert_eq!(
                service
                    .current_state_identity()
                    .map_err(|_| "new cold seed identity")?,
                seed_identity
            );
            assert!(service.native_root.is_none());
            Ok(())
        })?;
    }
    Ok(pipeline)
}

fn force_restore(pipeline: &Pipeline, leader: usize, bytes: &[u8]) -> TestResult<Response> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[leader]
        .as_ref()
        .ok_or("cold restore Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "cold restore admission writer")?;
    let mut pending = match writer.begin_native_snapshot_before(
        ServiceRequest::new(
            "POST",
            "sys/storage/raft/snapshot-force",
            "",
            pipeline.admin(),
            json!({}),
        ),
        until,
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => pending,
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            return Ok(response);
        }
        NativeSnapshotAdmission::Redirect(_) => {
            return Err("cold force selected leader redirected".into());
        }
    };
    drop(writer);
    let (observation, output) = pending.execute_snapshot_transfer(&mut &bytes[..]);
    assert!(output.is_none());
    let mut writer = lock_until(service, until).map_err(|_| "cold restore completion writer")?;
    let response = writer.finish_external_request(*pending, observation);
    errors_only("cold-force-complete", &response);
    assert!(writer.native_request_binding.is_none());
    assert!(
        Instant::now() < until,
        "cold restore preserves the original request budget"
    );
    Ok(response)
}

fn read_projection(pipeline: &Pipeline, leader: usize, token: &str) -> TestResult<Value> {
    let metadata = expect(
        pipeline.call(
            leader,
            "GET",
            "secret/metadata/pipeline/history",
            token,
            json!({}),
        )?,
        200,
        "cold-history-metadata",
    )?;
    let mut versions = Vec::new();
    for version in 1..=3 {
        let reply = pipeline.call(
            leader,
            "GET",
            "secret/data/pipeline/history",
            token,
            json!({"version":version}),
        )?;
        assert_eq!(reply.status, if version == 3 { 200 } else { 404 });
        versions.push(json!({"status":reply.status,"data":reply.body.get("data")}));
    }
    Ok(json!({"metadata":metadata.body["data"],"versions":versions}))
}

fn unseal_fresh_current(pipeline: &Pipeline, index: usize, source: StateIdentity) -> TestResult {
    // Read-only readiness precedes the one actual unseal mutation; it never
    // retries an unseal or supplies a saved commitment as present authority.
    let until = Instant::now() + Duration::from_secs(8);
    let scope = RequestDeadlineScope::enter(until);
    loop {
        let ready = {
            let process = pipeline.processes[index]
                .as_ref()
                .ok_or("cold reopen process")?
                .lock_for_request()
                .map_err(|_| "cold reopen observer lock")?;
            match process.native_v6_committed_read(OriginalDeadline::capture()?) {
                Ok(Some(read)) => {
                    process.verify_native_v6_committed_read(&read)?;
                    assert_eq!(read.published().migration_source().0, source.digest());
                    true
                }
                Ok(None) | Err(_) => false,
            }
        };
        if Instant::now() >= until {
            return Err("cold reopen actual ReadIndex readiness deadline".into());
        }
        if ready {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    drop(scope);
    pipeline.unseal(index)
}

#[test]
fn cold_dr_complete_archive_old_shamir_new_quorum_and_second_cold_restart() -> TestResult {
    let mut source = formal_cold_source()?;
    let leader = source.ready_leader()?;
    let migration = activate_formal_cold(&source, leader)?;
    for version in 2..=3 {
        expect(source.call(leader, "POST", "secret/data/pipeline/history", source.admin(),
            json!({"options":{"cas":version-1},"data":{"value":format!("cold-current-{version}")}}))?, 200, "cold-source-cas")?;
    }
    expect(
        source.call(
            leader,
            "POST",
            "secret/delete/pipeline/history",
            source.admin(),
            json!({"versions":[1]}),
        )?,
        204,
        "cold-source-delete",
    )?;
    expect(
        source.call(
            leader,
            "POST",
            "secret/destroy/pipeline/history",
            source.admin(),
            json!({"versions":[2]}),
        )?,
        204,
        "cold-source-destroy",
    )?;
    expect(source.call(leader, "POST", "sys/policies/acl/cold-reader", source.admin(),
        json!({"policy":"path \"secret/data/pipeline/history\" { capabilities = [\"read\"] } path \"secret/metadata/pipeline/history\" { capabilities = [\"read\"] }"}))?, 204, "cold-source-reader-policy")?;
    let mut issued = expect(source.call(leader, "POST", "auth/token/create", source.admin(),
        json!({"policies":["cold-reader"],"ttl":"20m","no_default_policy":true,"no_parent":true}))?, 200, "cold-source-reader-token")?;
    let reader = secret_field(&mut issued, "/auth/client_token")?;
    let epoch_zero_archive = export(&source, leader, source.admin())?;
    expect(
        restore(&source, leader, source.admin(), &epoch_zero_archive)?,
        200,
        "cold-source-original-history-restore",
    )?;
    assert_eq!(selection(&source, leader, migration)?.0, 1);
    let expected = read_projection(&source, leader, &reader)?;
    let archive = export(&source, leader, source.admin())?;
    let seal_bytes = fs::read(source.directory(leader).join("data/seal.json"))?;
    let key = Zeroizing::new(source.key.as_str().to_owned());
    let admin = Zeroizing::new(source.admin.as_str().to_owned());
    let cluster_id = source.with_service(leader, |service| {
        Ok(service
            .state
            .as_ref()
            .ok_or("old cluster state")?
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

    // Real encrypted input, wrong credentials/framing/custody: every refusal
    // leaves the requested destination unpublished. No fixture assertion or
    // saved success report is accepted by the recovery implementation.
    use crate::service::native_seed::{ColdSeedError, recover_ha_seed};
    let wrong_shares = bundle.path.join("wrong-shares.json");
    private_file(&wrong_shares, b"[\"not-a-shamir-share\"]")?;
    let rejected = bundle.path.join("wrong-share-result");
    assert!(matches!(
        recover_ha_seed(
            &archive_path,
            &seal_path,
            &wrong_shares,
            &rejected,
            &archive_hash,
            &seal_hash
        ),
        Err(ColdSeedError::SealRejected)
    ));
    assert!(!rejected.exists());
    let truncated = bundle.path.join("truncated-snapshot.bin");
    private_file(&truncated, &archive[..archive.len() - 1])?;
    let rejected = bundle.path.join("truncated-result");
    assert!(matches!(
        recover_ha_seed(
            &truncated,
            &seal_path,
            &shares_path,
            &rejected,
            &hex(&crypto::digest(&archive[..archive.len() - 1])),
            &seal_hash
        ),
        Err(ColdSeedError::ArchiveRejected)
    ));
    assert!(!rejected.exists());
    let linked = bundle.path.join("linked-snapshot.bin");
    std::os::unix::fs::symlink(&archive_path, &linked)?;
    let rejected = bundle.path.join("linked-result");
    assert!(matches!(
        recover_ha_seed(
            &linked,
            &seal_path,
            &shares_path,
            &rejected,
            &archive_hash,
            &seal_hash
        ),
        Err(ColdSeedError::UnsafeOwner)
    ));
    assert!(!rejected.exists());
    let existing = bundle.path.join("already-owned");
    private_directory(&existing)?;
    private_file(&existing.join("sentinel"), b"unchanged")?;
    assert!(matches!(
        recover_ha_seed(
            &archive_path,
            &seal_path,
            &shares_path,
            &existing,
            &archive_hash,
            &seal_hash
        ),
        Err(ColdSeedError::DestinationExists)
    ));
    assert!(fs::read(existing.join("sentinel"))? == b"unchanged");
    let rejected = bundle.path.join("expired-result");
    {
        let _expired = RequestDeadlineScope::enter(Instant::now() - Duration::from_secs(1));
        assert!(matches!(
            recover_ha_seed(
                &archive_path,
                &seal_path,
                &shares_path,
                &rejected,
                &archive_hash,
                &seal_hash
            ),
            Err(ColdSeedError::InvalidInput)
        ));
    }
    assert!(!rejected.exists());

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
    assert!(receipt["bootstrap_root_sha256"] != receipt["retained_source_root_sha256"]);
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
        "cold-new-real-cohort-activation",
    )?;
    let new_migration = observation.take()?;
    assert_eq!(selection(&target, leader, new_migration)?.0, 1);
    let temporary_root = root_token(&target, leader, "20m")?;
    expect(
        target.call(
            leader,
            "POST",
            "secret/data/cold/sentinel",
            target.admin(),
            json!({"data":{"value":"new-cohort-only"}}),
        )?,
        200,
        "cold-new-sentinel",
    )?;
    // Same seal alone does not bypass ordinary provenance comparison.
    expect(
        restore(&target, leader, target.admin(), &archive)?,
        400,
        "cold-ordinary-lineage-refusal",
    )?;
    assert_eq!(selection(&target, leader, new_migration)?.0, 1);
    expect(
        target.call(
            leader,
            "GET",
            "secret/data/cold/sentinel",
            target.admin(),
            json!({}),
        )?,
        200,
        "cold-refusal-retains-current-data",
    )?;
    let forced = expect(
        force_restore(&target, leader, &archive)?,
        200,
        "cold-new-quorum-force-restore",
    )?;
    assert_eq!(forced.body["data"]["replay_epoch"], 2);
    assert_eq!(selection(&target, leader, new_migration)?.0, 2);
    assert!(read_projection(&target, leader, &reader)? == expected);
    expect(
        target.call(
            leader,
            "GET",
            "auth/token/lookup-self",
            &temporary_root,
            json!({}),
        )?,
        403,
        "cold-temporary-authority-removed",
    )?;
    expect(
        target.call(
            leader,
            "GET",
            "secret/data/cold/sentinel",
            target.admin(),
            json!({}),
        )?,
        404,
        "cold-temporary-data-removed",
    )?;
    expect(
        target.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            target.admin(),
            json!({"options":{"cas":3},"data":{"value":"cold-new-write"}}),
        )?,
        200,
        "cold-recovered-cas",
    )?;
    let after_write = read_projection(&target, leader, &reader)?;
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
        let reply = expect(
            target.call(
                index,
                "GET",
                "secret/data/pipeline/history",
                &reader,
                json!({"version":4}),
            )?,
            200,
            "cold-second-restart-new-cas",
        )?;
        assert!(reply.body["data"]["data"]["value"].as_str() == Some("cold-new-write"));
        assert!(read_projection(&target, index, &reader)? == after_write);
        assert_eq!(selection(&target, leader, new_migration)?.0, 2);
    }
    assert!(fs::read(&archive_path)? == archive);
    assert!(fs::read(&seal_path)? == seal_bytes);
    Ok(())
}

// Keep the unsupported owner present in a genuine authenticated archive.
// Experimental migration can produce this shape, but formal cold recovery
// must refuse it before publishing a destination, without deleting its owner.
#[test]
fn cold_dr_unsupported_engine_archive_refused_without_destination_or_source_loss() -> TestResult {
    let source = Pipeline::start()?;
    let leader = source.ready_leader()?;
    // SSH now has a formal native owner. Enabled PKI ACME still lacks one.
    // Keep a real private CA in this unsupported profile, complete-graph
    // rejection and every source-retention assertion. Configuration is local;
    // no ACME account, challenge, provider request or external key is created.
    expect(
        source.call(
            leader,
            "POST",
            "sys/mounts/cold-acme",
            source.admin(),
            json!({"type":"pki"}),
        )?,
        204,
        "unsupported-cold-acme-mount",
    )?;
    expect(
        source.call(
            leader,
            "POST",
            "cold-acme/root/generate/internal",
            source.admin(),
            json!({"common_name":"unsupported-cold.example.test",
                "key_type":"ec","key_bits":256,"ttl":"1h"}),
        )?,
        200,
        "unsupported-cold-acme-key",
    )?;
    for (path, body) in [
        (
            "cold-acme/config/cluster",
            json!({"path":"https://unsupported-cold.example.test/v1/cold-acme"}),
        ),
        ("cold-acme/config/acme", json!({"enabled":true})),
    ] {
        expect(
            source.call(leader, "POST", path, source.admin(), body)?,
            200,
            "unsupported-cold-acme-configuration",
        )?;
    }
    let retained = expect(
        source.call(
            leader,
            "GET",
            "cold-acme/config/acme",
            source.admin(),
            json!({}),
        )?,
        200,
        "unsupported-cold-acme-before",
    )?
    .body["data"]
        .clone();
    assert_eq!(retained["enabled"], true);
    activate(&source, leader)?;
    let archive = export(&source, leader, source.admin())?;
    let seal_bytes = fs::read(source.directory(leader).join("data/seal.json"))?;
    // Native activation deliberately closes this nondefault ACME owner.
    // Observe the same protected configuration route before and after recovery
    // refusal, and inspect the stored EngineState clone below. The authenticated
    // full-state encoding retains both the ACME policy and the private CA.
    let boundary_before = expect(
        source.call(
            leader,
            "GET",
            "cold-acme/config/acme",
            source.admin(),
            json!({}),
        )?,
        501,
        "unsupported-cold-acme-activated-before",
    )?;
    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let inspect_retained = || -> TestResult<(StateIdentity, u64, Zeroizing<Vec<u8>>)> {
        // One original read-only inspection budget, as with Pipeline::with_service.
        // The actual mutable journal is borrowed only to authenticate and export
        // its full native object closure; no application mutation is performed.
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let deadline = OriginalDeadline::capture()?;
        let service = source.services[leader]
            .as_ref()
            .ok_or("unsupported cold source Service")?;
        let mut service = lock_until(service, until).map_err(|_| "unsupported cold source lock")?;
        assert!(service.native_storage_profile.is_none());
        assert!(service.native_candidate_profile.is_none());
        let before = service
            .current_state_identity()
            .map_err(|_| "unsupported cold source identity")?;
        let generation = service
            .durable
            .as_ref()
            .ok_or("unsupported cold source durable")?
            .generation();
        let seal_identity = crate::service::snapshot_transfer::canonical_seal_identity(
            service
                .seal
                .as_ref()
                .ok_or("unsupported cold source seal")?,
        )?;
        let proof = service
            .capture_native_ha_unseal_proof()
            .map_err(|_| "unsupported cold actual source proof")?
            .ok_or("unsupported cold native proof absent")?;
        assert_eq!(proof.identity(), before);
        assert_eq!(proof.generation(), generation);
        let spool = service
            .snapshot_spool
            .as_ref()
            .ok_or("unsupported cold prior export spool")?
            .clone();
        let lease = spool.lease()?;
        let local = lease.file(crate::snapshot_file::MAX_V6_SNAPSHOT_STATE, until)?;
        let output = lease.file(crate::snapshot_file::MAX_V6_HA_SNAPSHOT_STATE, until)?;
        let (_authenticated_archive, report) = proof
            .export_snapshot_archive(&mut service, local, output, seal_identity, &mut |current| {
                deadline
                    .check()
                    .map_err(|_| Response::error(503, "cold inspection deadline"))?;
                if current.current_state_identity()? != before
                    || current.native_storage_profile.is_some()
                    || current.native_candidate_profile.is_some()
                {
                    return Err(Response::error(503, "cold inspection source changed"));
                }
                Ok(())
            })
            .map_err(|_| "unsupported cold complete authenticated snapshot")?;
        assert_eq!(report.local.generation, generation);
        proof
            .check_warm(&service)
            .map_err(|_| "unsupported cold post-export proof")?;
        let state = service
            .state
            .as_ref()
            .ok_or("unsupported cold retained state")?;
        let root = service
            .native_root
            .as_ref()
            .ok_or("unsupported cold retained native root")?;
        let root_bytes = root
            .encode()
            .map_err(|_| "unsupported cold root encoding")?;
        let parent = root
            .kv2_parent_key()
            .map_err(|_| "unsupported cold native parent")?;
        let engines = &state.engines;
        assert!(!engines.supports_native_v6_root_storage());
        // This is the same split representation used by check_native_installed:
        // complete opaque engine metadata plus exact authenticated KV2 graph
        // roots, with every payload already reopened by the real exporter above.
        // Preserve ALL State owners; do not serialize a live NativeReadView or
        // replace native data with an empty engine to make Serde succeed.
        let project = |engines: &crate::engines::EngineState| -> TestResult<Zeroizing<Vec<u8>>> {
            let check = || {
                deadline
                    .check()
                    .map_err(|_| crate::state_records::RecordError::Invalid)
            };
            let (opaque, graphs) = engines
                .project_checked_native_roots(
                    &parent,
                    &root.kv2,
                    root.reader_floor.native_kv2_format,
                    &check,
                )
                .map_err(|_| "unsupported cold native engine projection")?;
            let graph_bytes =
                crate::secret_serde::to_vec(&graphs, crate::state_record_root::MAX_ROOT_BYTES)
                    .map_err(|_| "unsupported cold native graph encoding")?;
            let expected_graph_bytes =
                crate::secret_serde::to_vec(&root.kv2, crate::state_record_root::MAX_ROOT_BYTES)
                    .map_err(|_| "unsupported cold expected graph encoding")?;
            assert!(graph_bytes.as_slice() == expected_graph_bytes.as_slice());
            let mut all_owners = state.clone();
            all_owners.engines = opaque.into();
            let owner_bytes = crate::service::owner_store::serialize_owner(&all_owners)
                .map_err(|_| "unsupported cold all-owner encoding")?;
            let mut snapshot = Zeroizing::new(Vec::new());
            snapshot.extend_from_slice(b"cold-dr-complete-native-state-v1\0");
            snapshot.extend_from_slice(&(root_bytes.len() as u64).to_be_bytes());
            snapshot.extend_from_slice(&root_bytes);
            snapshot.extend_from_slice(&(owner_bytes.len() as u64).to_be_bytes());
            snapshot.extend_from_slice(&owner_bytes);
            deadline.check()?;
            Ok(snapshot)
        };
        let owner_bytes = project(engines)?;
        let mut inspected = engines.clone();
        let response = inspected
            .handle("", "GET", "cold-acme/config/acme", &json!({}), observed_at)?
            .ok_or("unsupported cold retained ACME config route absent")?;
        assert_eq!(response.status, 200);
        assert!(!response.mutated);
        assert!(response.body["data"] == retained);
        let inspected_bytes = project(&inspected)?;
        assert!(owner_bytes.as_slice() == inspected_bytes.as_slice());
        proof
            .check_warm(&service)
            .map_err(|_| "unsupported cold completed source proof")?;
        assert_eq!(
            service
                .current_state_identity()
                .map_err(|_| "unsupported cold completed identity")?,
            before
        );
        assert_eq!(
            service
                .durable
                .as_ref()
                .ok_or("unsupported cold completed durable")?
                .generation(),
            generation
        );
        assert!(Instant::now() < until);
        Ok((before, generation, owner_bytes))
    };
    let (before, generation_before, engine_owner_before) = inspect_retained()?;
    let mut bundle = Root::new();
    private_directory(&bundle.path)?;
    bundle.path = fs::canonicalize(&bundle.path)?;
    let archive_path = bundle.path.join("snapshot.bin");
    let seal_path = bundle.path.join("seal.json");
    let shares_path = bundle.path.join("shares.json");
    private_file(&archive_path, &archive)?;
    private_file(&seal_path, &seal_bytes)?;
    let shares = Zeroizing::new(serde_json::to_vec(&[source.key.as_str()])?);
    private_file(&shares_path, &shares)?;
    let share_hash = crypto::digest(&shares);
    drop(shares);
    let destination = bundle.path.join("must-remain-unpublished");
    use crate::service::native_seed::{ColdSeedError, recover_ha_seed};
    assert!(matches!(
        recover_ha_seed(
            &archive_path,
            &seal_path,
            &shares_path,
            &destination,
            &hex(&crypto::digest(&archive)),
            &hex(&crypto::digest(&seal_bytes))
        ),
        Err(ColdSeedError::GraphRejected)
    ));
    assert!(!destination.exists());
    let (after_identity, generation_after, engine_owner_after) = inspect_retained()?;
    assert_eq!(after_identity, before);
    assert_eq!(generation_after, generation_before);
    assert!(engine_owner_after.as_slice() == engine_owner_before.as_slice());
    assert!(fs::read(&archive_path)? == archive);
    assert!(fs::read(&seal_path)? == seal_bytes);
    assert_eq!(
        crypto::digest(&Zeroizing::new(fs::read(&shares_path)?)),
        share_hash
    );
    let boundary_after = expect(
        source.call(
            leader,
            "GET",
            "cold-acme/config/acme",
            source.admin(),
            json!({}),
        )?,
        501,
        "unsupported-cold-acme-activated-after",
    )?;
    assert!(boundary_after.body == boundary_before.body);
    Ok(())
}

#[path = "service_native_v6_ha_cold_restore_clock_floor_tests.rs"]
mod clock_floor_tests;
