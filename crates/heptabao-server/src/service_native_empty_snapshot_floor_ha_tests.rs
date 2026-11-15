//! Actual three-node NativeV6Raft empty archive retention, leader election,
//! cold original-directory reopen and first precise write after restore.
//! The peer transport is real pinned TLS. This process-local test does not
//! replace physical-host loss, SIGKILL or public HTTPS qualification.
use super::*;

fn snapshot(
    pipeline: &WrappingPipeline,
    node: usize,
    method: &str,
    input: &[u8],
) -> TestResult<(Response, Zeroizing<Vec<u8>>)> {
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let service = pipeline.services[node]
        .as_ref()
        .ok_or("empty HA snapshot actual Service")?;
    let mut writer =
        lock_until(service, until).map_err(|_| "empty HA snapshot original admission lock")?;
    let admission = writer.begin_native_snapshot_before(
        ServiceRequest::new(
            method,
            "sys/storage/raft/snapshot",
            "",
            pipeline.admin(),
            json!({}),
        ),
        until,
    );
    let NativeSnapshotAdmission::Execute(RequestExecution::External(mut plan)) = admission else {
        return Err("empty HA snapshot actual external admission".into());
    };
    // Production HTTP releases the Service writer for actual streamed I/O,
    // then reacquires that same owner under the same original deadline.
    drop(writer);
    let (result, output) = plan.execute_snapshot_transfer(&mut &input[..]);
    let mut writer =
        lock_until(service, until).map_err(|_| "empty HA snapshot original completion lock")?;
    let response = writer.finish_external_request(*plan, result);
    assert!(writer.native_request_binding.is_none());
    drop(writer);
    let mut bytes = Zeroizing::new(Vec::new());
    if method == "GET" {
        output
            .ok_or("empty HA authenticated archive")?
            .read_to_end(&mut bytes)?;
        assert!(bytes.starts_with(&[0x1f, 0x8b]));
    } else {
        assert!(output.is_none());
    }
    if Instant::now() >= until {
        return Err("empty HA snapshot original 15-second deadline exceeded".into());
    }
    Ok((response, bytes))
}

fn verify_empty(pipeline: &WrappingPipeline, node: usize, epoch: u64, graphs: &[u8]) -> TestResult {
    for path in [
        "secret/data/empty-ha-retention",
        "secret/metadata/empty-ha-retention",
    ] {
        expect(
            pipeline.call(node, "GET", path, pipeline.admin(), json!({}))?,
            404,
            "empty-HA-authenticated-ReadIndex-absence",
        )?;
    }
    pipeline.with_service(node, |service| {
        let state = service
            .state
            .as_ref()
            .ok_or("empty HA actual restored state")?;
        let root = service
            .native_root
            .as_ref()
            .ok_or("empty HA actual restored root")?;
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        assert_eq!(state.replay_epoch, epoch);
        assert_eq!(
            service
                .durable
                .as_ref()
                .ok_or("empty HA actual durable")?
                .replay_epoch(),
            epoch
        );
        assert!(state.engines.has_kv2_lossless_state());
        assert!(state.schema >= KV2_LOSSLESS_STATE_SCHEMA);
        assert!(root.reader_floor.minimum_state_schema >= KV2_LOSSLESS_STATE_SCHEMA);
        let encoded =
            crate::secret_serde::to_vec(&root.kv2, crate::state_record_root::MAX_ROOT_BYTES)
                .map_err(|_| "empty HA actual restored graph encoding")?;
        assert_eq!(encoded.as_slice(), graphs);
        Ok(())
    })
}

fn verify_first_write(pipeline: &WrappingPipeline, node: usize, epoch: u64) -> TestResult {
    let read = expect(
        pipeline.call(
            node,
            "GET",
            "secret/data/empty-ha-retention",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "empty-HA-cold-first-write-ReadIndex",
    )?;
    assert_eq!(read.body["data"]["metadata"]["version"], 1);
    assert_eq!(
        read.body["data"]["data"]["value"],
        "first-after-empty-restore"
    );
    let metadata = expect(
        pipeline.call(
            node,
            "GET",
            "secret/metadata/empty-ha-retention",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "empty-HA-cold-first-write-history",
    )?;
    assert_eq!(metadata.body["data"]["current_version"], 1);
    assert_eq!(
        metadata.body["data"]["versions"]
            .as_object()
            .ok_or("empty HA actual history")?
            .len(),
        1
    );
    pipeline.with_service(node, |service| {
        let state = service
            .state
            .as_ref()
            .ok_or("empty HA cold written state")?;
        assert_eq!(state.replay_epoch, epoch);
        assert!(state.engines.has_kv2_lossless_state());
        assert!(
            service
                .native_root
                .as_ref()
                .ok_or("empty HA cold written root")?
                .reader_floor
                .minimum_state_schema
                >= KV2_LOSSLESS_STATE_SCHEMA
        );
        Ok(())
    })
}

#[test]
fn native_empty_snapshot_formal_ha_retains_floor_election_cold_and_first_write() -> TestResult {
    let mut pipeline = WrappingPipeline::start_empty()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    let (archived_epoch, archived_graphs) = pipeline.with_service(first, |service| {
        let state = service.state.as_ref().ok_or("empty HA archive state")?;
        assert!(!state.engines.has_kv2_lossless_state());
        let root = service
            .native_root
            .as_ref()
            .ok_or("empty HA archive root")?;
        assert_eq!(root.reader_floor.native_kv2_format, 2);
        assert_eq!(root.kv2.len(), 1);
        assert!(root.kv2.iter().all(|graph| graph.scope.namespace.is_empty()
            && graph.scope.mount == "secret/"
            && graph.graph_format == crate::engines::kv2_native_records::PAGED_NATIVE_FORMAT));
        assert!(
            root.kv2
                .iter()
                .all(|graph| graph.logical_payload_bytes == 0)
        );
        let graphs =
            crate::secret_serde::to_vec(&root.kv2, crate::state_record_root::MAX_ROOT_BYTES)
                .map_err(|_| "empty HA archive graph encoding")?;
        Ok((state.replay_epoch, graphs))
    })?;
    let (exported, archive) = snapshot(&pipeline, first, "GET", &[])?;
    expect(exported, 200, "empty-HA-authenticated-export")?;
    let archive_digest = crypto::digest(&archive);
    let written = expect(
        pipeline.call(
            follower,
            "POST",
            "secret/data/empty-ha-retention",
            pipeline.admin(),
            json!({"options":{"cas":0},"data":{"value":"after-empty-archive"}}),
        )?,
        200,
        "empty-HA-forwarded-first-write",
    )?;
    assert_eq!(written.body["data"]["version"], 1);
    let live_epoch = pipeline.with_service(first, |service| {
        let state = service
            .state
            .as_ref()
            .ok_or("empty HA live first-write state")?;
        assert!(state.engines.has_kv2_lossless_state());
        Ok(state.replay_epoch)
    })?;
    // Exactly one historical upload. Any failed/unknown outcome fails this
    // test without retrying the mutation or replacing its original owner.
    let (restored, output) = snapshot(&pipeline, first, "POST", &archive)?;
    assert!(output.is_empty());
    let restored = expect(restored, 200, "empty-HA-actual-historical-restore")?;
    assert_eq!(restored.body["data"]["cluster_coordinated"], true);
    let epoch = restored.body["data"]["replay_epoch"]
        .as_u64()
        .ok_or("empty HA restored epoch")?;
    assert!(epoch > archived_epoch && epoch > live_epoch);
    assert_eq!(crypto::digest(&archive), archive_digest);
    for node in 0..3 {
        verify_empty(&pipeline, node, epoch, &archived_graphs)?;
    }

    pipeline.stop_process(first)?;
    let elected = pipeline.ready_leader()?;
    assert_ne!(elected, first);
    verify_empty(&pipeline, elected, epoch, &archived_graphs)?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    verify_empty(&pipeline, first, epoch, &archived_graphs)?;
    let first_after_restore = expect(
        pipeline.call(
            first,
            "POST",
            "secret/data/empty-ha-retention",
            pipeline.admin(),
            json!({"options":{"cas":0},"data":{"value":"first-after-empty-restore"}}),
        )?,
        200,
        "empty-HA-first-CAS0-after-election-and-cold-restore",
    )?;
    assert_eq!(first_after_restore.body["data"]["version"], 1);
    for node in 0..3 {
        verify_first_write(&pipeline, node, epoch)?;
    }
    pipeline.stop_process(first)?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    verify_first_write(&pipeline, first, epoch)?;
    Ok(())
}
