//! Actual formal NativeV6Raft Service forwarding with two MiB request bodies,
//! peer TLS, fresh ReadIndex, leader loss and same-directory cold recovery.
//! Process-owner drop is not physical-host SIGKILL or public HTTPS evidence.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const DATA_PATH: &str = "secret/data/native-forward-two-mib";
const META_PATH: &str = "secret/metadata/native-forward-two-mib";
const PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

// Observe the original single authenticated handler before Service admission.
// This makes a coincidental local-leader write insufficient to pass the test.
// Cold process owners inherit the same fixture-local immutable observer.
fn forwarded_write_observer(calls: Arc<[AtomicUsize; 2]>) -> WrappingForwardObserver {
    Arc::new(move |request| {
        if request.path == DATA_PATH && matches!(request.method.as_str(), "POST" | "PUT") {
            if !request.native_index_response
                || !request.index_response
                || request.unwrap_response
                || request.legacy_v1
                || request.completion_nonce.is_none()
                || request.body["data"]["value"]
                    .as_str()
                    .is_none_or(|value| value.len() != PAYLOAD_BYTES)
            {
                return Some(Response::error(
                    503,
                    "large write original completed profile differs",
                ));
            }
            // This body cannot fit Q9's unchanged one MiB decoder. The
            // authenticated handler therefore proves actual N1 dispatch.
            calls[usize::from(request.method == "PUT")].fetch_add(1, Ordering::SeqCst);
        }
        None
    })
}

fn verify_versions(pipeline: &WrappingPipeline, node: usize, digests: &[[u8; 32]]) -> TestResult {
    let current = u64::try_from(digests.len())?;
    let read = expect(
        pipeline.call(node, "GET", DATA_PATH, pipeline.admin(), json!({}))?,
        200,
        "large-forward-actual-ReadIndex-current",
    )?;
    assert_eq!(read.body["data"]["metadata"]["version"], current);
    let value = read.body["data"]["data"]["value"]
        .as_str()
        .ok_or("large write current payload")?;
    assert_eq!(value.len(), PAYLOAD_BYTES);
    assert!(crypto::digest(value.as_bytes()) == *digests.last().ok_or("expected history")?);
    for (index, expected) in digests.iter().enumerate() {
        let version = u64::try_from(index + 1)?;
        let history = expect(
            pipeline.call(
                node,
                "GET",
                DATA_PATH,
                pipeline.admin(),
                json!({"version":version}),
            )?,
            200,
            "large-forward-actual-ReadIndex-history",
        )?;
        assert_eq!(history.body["data"]["metadata"]["version"], version);
        let value = history.body["data"]["data"]["value"]
            .as_str()
            .ok_or("large write retained payload")?;
        assert_eq!(value.len(), PAYLOAD_BYTES);
        assert!(crypto::digest(value.as_bytes()) == *expected);
    }
    let metadata = expect(
        pipeline.call(node, "GET", META_PATH, pipeline.admin(), json!({}))?,
        200,
        "large-forward-actual-history-metadata",
    )?;
    assert_eq!(metadata.body["data"]["current_version"], current);
    let versions = metadata.body["data"]["versions"]
        .as_object()
        .ok_or("large write versions")?;
    assert_eq!(versions.len(), digests.len());
    for version in 1..=current {
        let entry = versions
            .get(&version.to_string())
            .ok_or("large write history version")?;
        assert_eq!(entry["destroyed"], false);
        assert_eq!(entry["deletion_time"], "");
    }
    pipeline.with_service(node, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        assert!(service.record_root.is_none() && service.native_root.is_some());
        assert!(service.pending_ordinary_kv_authority.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        assert!(service.native_request_binding.is_none());
        Ok(())
    })
}

fn verify_three_nodes(pipeline: &WrappingPipeline, digests: &[[u8; 32]]) -> TestResult {
    for node in 0..3 {
        verify_versions(pipeline, node, digests)?;
    }
    // These are independently minted actual committed ReadIndex receipts,
    // checked by the existing helper before any root tuple is returned.
    let selected = pipeline.native_selection(0)?;
    for node in 1..3 {
        assert_eq!(pipeline.native_selection(node)?, selected);
    }
    Ok(())
}

#[test]
fn native_kv2_write_formal_ha_two_mib_post_put_readindex_election_and_cold() -> TestResult {
    let calls = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let mut pipeline =
        WrappingPipeline::start_empty_with_observer(forwarded_write_observer(calls.clone()))?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    let post_payload = Zeroizing::new("p".repeat(PAYLOAD_BYTES));
    let post_digest = crypto::digest(post_payload.as_bytes());
    let posted = expect(
        pipeline.call(
            follower,
            "POST",
            DATA_PATH,
            pipeline.admin(),
            json!({"options":{"cas":0},"data":{"value":post_payload.as_str()}}),
        )?,
        200,
        "large-forward-actual-standby-POST-CAS0",
    )?;
    assert_eq!(posted.body["data"]["version"], 1);
    assert_eq!(calls[0].load(Ordering::SeqCst), 1);
    assert_eq!(calls[1].load(Ordering::SeqCst), 0);
    verify_three_nodes(&pipeline, &[post_digest])?;

    pipeline.stop_process(first)?;
    let elected = pipeline.ready_leader()?;
    assert_ne!(elected, first);
    verify_versions(&pipeline, elected, &[post_digest])?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    verify_versions(&pipeline, first, &[post_digest])?;
    let leader = pipeline.ready_leader()?;
    let put_follower = if first != leader {
        first
    } else {
        (leader + 1) % 3
    };
    let put_payload = Zeroizing::new("u".repeat(PAYLOAD_BYTES));
    let put_digest = crypto::digest(put_payload.as_bytes());
    let updated = expect(
        pipeline.call(
            put_follower,
            "PUT",
            DATA_PATH,
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":put_payload.as_str()}}),
        )?,
        200,
        "large-forward-actual-standby-PUT-CAS1-after-election",
    )?;
    assert_eq!(updated.body["data"]["version"], 2);
    assert_eq!(calls[0].load(Ordering::SeqCst), 1);
    assert_eq!(calls[1].load(Ordering::SeqCst), 1);
    verify_three_nodes(&pipeline, &[post_digest, put_digest])?;

    // A second cold owner reuses the exact files and must retain both versions.
    pipeline.stop_process(put_follower)?;
    pipeline.start_formal_process(put_follower)?;
    pipeline.wait_cold_native_readindex_ready(put_follower)?;
    pipeline.unseal(put_follower)?;
    verify_versions(&pipeline, put_follower, &[post_digest, put_digest])?;
    assert_eq!(calls[0].load(Ordering::SeqCst), 1);
    assert_eq!(calls[1].load(Ordering::SeqCst), 1);
    Ok(())
}
