//! Formal File empty archive -> first precise write -> historical empty
//! restore -> cold reopen. All authority comes from actual public requests.
use super::*;

#[test]
fn native_empty_snapshot_formal_file_retains_producer_floor_and_cold_first_write() -> TestResult {
    empty_archive_roundtrip(false)
}

#[test]
fn native_empty_snapshot_formal_file_migrates_actual_pre141_empty_owner_without_losing_floor()
-> TestResult {
    empty_archive_roundtrip(true)
}

fn empty_archive_roundtrip(historical: bool) -> TestResult {
    let root = crate::service::tests::Root::new();
    let mut service = root.service()?;
    let (key, token) = if historical {
        // Publish the historical ordinary factory before selecting File.
        // This is a genuine encrypted predecessor, never a lowered current
        // owner or an old factory invoked inside a selected native profile.
        let (key, token) = crate::service::tests::bootstrap_pre141_unmounted(&mut service)?;
        let key = Zeroizing::new(key);
        let token = Zeroizing::new(token);
        let state = service.state.as_ref().ok_or("historical ordinary owner")?;
        assert!(state.schema < KV2_LOSSLESS_STATE_SCHEMA);
        assert!(!state.auth.has_security_contract_state());
        assert_eq!(
            request(&mut service, "POST", "sys/init/ack", &token, json!({})).status,
            204
        );
        drop(service);
        service = root.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        assert_eq!(
            request(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":key.as_str()})
            )
            .status,
            200
        );
        (key, token)
    } else {
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        initialize(&mut service)?
    };
    mount_kv2(&mut service, &token);
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    let state = service.state.as_ref().ok_or("actual empty state")?;
    assert!(!state.engines.has_kv2_lossless_state());
    let producer_schema = state.schema;
    if historical {
        assert!(producer_schema < KV2_LOSSLESS_STATE_SCHEMA);
        assert!(!state.auth.has_security_contract_state());
    } else {
        assert_eq!(producer_schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
        assert!(state.auth.has_security_contract_state());
    }
    let archived_root = service
        .native_root
        .as_ref()
        .ok_or("actual empty native root")?;
    assert_eq!(archived_root.reader_floor.native_kv2_format, 2);
    assert_eq!(archived_root.state_schema, producer_schema);
    assert_eq!(
        archived_root.reader_floor.minimum_state_schema,
        producer_schema
    );
    let archived_graphs =
        crate::secret_serde::to_vec(&archived_root.kv2, crate::state_record_root::MAX_ROOT_BYTES)
            .map_err(|_| "actual archived KV2 graph encoding")?;
    let archive = download(&mut service, &token)?;
    let archive_digest = crate::crypto::digest(&archive);
    let path = "secret/data/empty-snapshot-retention";
    let written = request(
        &mut service,
        "POST",
        path,
        &token,
        json!({"options":{"cas":0},"data":{"value":"after-empty-archive"}}),
    );
    assert_eq!(written.status, 200);
    assert_eq!(written.body["data"]["version"], 1);
    let live = service.state.as_ref().ok_or("actual first-write state")?;
    assert!(live.engines.has_kv2_lossless_state());
    assert!(live.schema >= producer_schema.max(KV2_LOSSLESS_STATE_SCHEMA));
    let live_epoch = live.replay_epoch;

    // Corrupt the actual parsed checksum observation. The new empty-graph
    // retention must never bypass archive authentication or reach commit.
    let admission = service.begin_native_snapshot_before(
        ServiceRequest::new("POST", "sys/storage/raft/snapshot", "", &token, json!({})),
        std::time::Instant::now() + Duration::from_secs(15),
    );
    let NativeSnapshotAdmission::Execute(RequestExecution::External(mut pending)) = admission
    else {
        return Err("actual empty snapshot negative admission".into());
    };
    let (mut observed, output) = pending.execute_snapshot_transfer(&mut archive.as_slice());
    assert!(output.is_none());
    let ExternalEffectResult::SnapshotTransfer(Ok(
        crate::service::snapshot_transfer::Observation::Upload(ref mut imported),
    )) = observed
    else {
        return Err("actual empty snapshot negative parse".into());
    };
    *imported
        .sealed_sums
        .first_mut()
        .ok_or("actual sealed checksum")? ^= 1;
    let committed = std::rc::Rc::new(std::cell::Cell::new(false));
    let callback = std::rc::Rc::clone(&committed);
    let observer =
        Service::observe_next_native_snapshot_commit_for_test(move |_| callback.set(true))?;
    let refused = service.finish_external_request(*pending, observed);
    drop(observer);
    assert_eq!(refused.status, 400);
    assert!(!committed.get());
    assert_eq!(
        service
            .state
            .as_ref()
            .ok_or("refused actual state")?
            .replay_epoch,
        live_epoch
    );
    let kept = request(&mut service, "GET", path, &token, json!({}));
    assert_eq!(kept.status, 200);
    assert_eq!(kept.body["data"]["data"]["value"], "after-empty-archive");

    // This independently admitted valid archive request is not a retry of an
    // unknown mutation: the distinct tampered input above had a known 400.
    let (restored, output) =
        snapshot_transfer(&mut service, "POST", &token, &mut archive.as_slice())?;
    assert_eq!(restored.status, 200);
    assert!(output.is_none());
    let restored_epoch = service.state.as_ref().ok_or("restored state")?.replay_epoch;
    assert!(restored_epoch > live_epoch);
    assert_eq!(
        service
            .durable
            .as_ref()
            .ok_or("restored durable")?
            .replay_epoch(),
        restored_epoch
    );
    let restored_root = service.native_root.as_ref().ok_or("restored root")?;
    assert!(restored_root.state_schema >= producer_schema.max(KV2_LOSSLESS_STATE_SCHEMA));
    assert!(
        restored_root.reader_floor.minimum_state_schema
            >= producer_schema.max(KV2_LOSSLESS_STATE_SCHEMA)
    );
    assert_eq!(
        crate::secret_serde::to_vec(&restored_root.kv2, crate::state_record_root::MAX_ROOT_BYTES)
            .map_err(|_| "actual restored KV2 graph encoding")?
            .as_slice(),
        archived_graphs.as_slice()
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("restored producer")?
            .engines
            .has_kv2_lossless_state()
    );
    assert_eq!(
        request(&mut service, "GET", path, &token, json!({})).status,
        404
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "secret/metadata/empty-snapshot-retention",
            &token,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(crate::crypto::digest(&archive), archive_digest);
    drop(service);

    let mut cold = root.service()?;
    cold.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut cold,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        cold.state.as_ref().ok_or("cold state")?.replay_epoch,
        restored_epoch
    );
    assert!(
        cold.state
            .as_ref()
            .ok_or("cold producer")?
            .engines
            .has_kv2_lossless_state()
    );
    assert!(
        cold.native_root
            .as_ref()
            .ok_or("cold root")?
            .reader_floor
            .minimum_state_schema
            >= KV2_LOSSLESS_STATE_SCHEMA
    );
    assert_eq!(
        request(&mut cold, "GET", path, &token, json!({})).status,
        404
    );
    let first = request(
        &mut cold,
        "POST",
        path,
        &token,
        json!({"options":{"cas":0},"data":{"value":"first-after-restored-cold"}}),
    );
    assert_eq!(first.status, 200);
    assert_eq!(first.body["data"]["version"], 1);
    let read = request(&mut cold, "GET", path, &token, json!({}));
    assert_eq!(read.status, 200);
    assert_eq!(
        read.body["data"]["data"]["value"],
        "first-after-restored-cold"
    );
    assert!(
        cold.state
            .as_ref()
            .ok_or("cold written producer")?
            .engines
            .has_kv2_lossless_state()
    );
    Ok(())
}
