//! Actual Service / pinned peer / durable retained-history mark. These local
//! tests do not qualify public HTTP sockets, physical hosts or local deletion.
use super::*;
use crate::service::native_storage::ha_gc::{LOCAL_MARK_PATH, ROOTS_ACTIVATE_PATH};
use heptabao_raft_runtime::RecordObjectRef;

#[path = "service_native_ha_epoch_mark_tests.rs"]
mod epoch_restore_marks;

pub(super) fn activate_roots(pipeline: &Pipeline, owner: usize) -> TestResult {
    let response = expect(
        pipeline.call(
            owner,
            "POST",
            ROOTS_ACTIVATE_PATH,
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "explicit-actual-Service-retained-root-protocol-activation",
    )?;
    assert_eq!(
        response.body["data"]["scope"],
        "raft-retained-root-provenance-only"
    );
    assert_eq!(
        response.body["data"]["retained_root_activation_observed"],
        true
    );
    assert_eq!(response.body["data"]["physical_deletion_authorized"], false);
    assert_eq!(response.body["data"]["local_barriers_gc_qualified"], false);
    Ok(())
}

#[test]
fn native_ha_root_provenance_actual_service_requires_all_members_and_cold_unknown_only_reconciles()
-> TestResult {
    let (mut pipeline, leader) = configured()?;
    prepare(&pipeline, leader)?;
    let before = crate::service::native_storage::ha_gc::intent_submission_owners_consumed();
    let barriers = barrier_objects(&pipeline.directory(leader).join("data"))?;
    expect(
        pipeline.call(leader, "POST", ROOTS_ACTIVATE_PATH, "", json!({}))?,
        403,
        "root-provenance-original-Actor-required",
    )?;
    let missing = (0..3).find(|member| *member != leader).ok_or("standby")?;
    pipeline.stop_process(missing)?;
    assert_eq!(pipeline.ready_leader()?, leader);
    expect(
        pipeline.call(
            leader,
            "POST",
            ROOTS_ACTIVATE_PATH,
            pipeline.admin(),
            json!({}),
        )?,
        503,
        "root-provenance-cannot-use-majority-as-reader7-admission",
    )?;
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before
    );
    pipeline.start_process(missing)?;
    pipeline.wait_cold_native_readindex_ready(missing)?;
    pipeline.unseal(missing)?;
    expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        503,
        "mark-cannot-enable-root-provenance",
    )?;

    crate::service::native_storage::ha_gc::fail_after_intent_commit_once();
    let original = expect(
        pipeline.call(
            leader,
            "POST",
            ROOTS_ACTIVATE_PATH,
            pipeline.admin(),
            json!({}),
        )?,
        503,
        "root-provenance-original-completion-unknown",
    )?;
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before + 1
    );
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    let status = expect(
        pipeline.call(leader, "GET", INTENTS_PATH, pipeline.admin(), json!({}))?,
        200,
        "cold-new-operation-pending",
    )?;
    assert_eq!(status.body["data"]["retirement"]["pending"], true);
    let digest = status.body["data"]["retirement"]["record_sha256"]
        .as_str()
        .ok_or("pending SHA")?
        .to_owned();
    let serial = status.body["data"]["retirement"]["serial"]
        .as_u64()
        .ok_or("original serial")?;
    expect(
        pipeline.call(
            leader,
            "POST",
            ROOTS_ACTIVATE_PATH,
            pipeline.admin(),
            json!({}),
        )?,
        409,
        "activation-pending-cannot-be-replayed",
    )?;
    expect(
        pipeline.call(
            leader,
            "POST",
            INTENTS_RECONCILE_PATH,
            pipeline.admin(),
            json!({"expected_pending_sha256":"00".repeat(32)}),
        )?,
        409,
        "wrong-activation-pending-selector",
    )?;
    let closed = expect(
        pipeline.call(
            leader,
            "POST",
            INTENTS_RECONCILE_PATH,
            pipeline.admin(),
            json!({"expected_pending_sha256":digest}),
        )?,
        200,
        "activation-new-read-only-reconciliation",
    )?;
    assert_eq!(
        closed.body["data"]["scope"],
        "raft-retained-root-provenance-only"
    );
    assert_eq!(closed.body["data"]["retirement"]["serial"], serial);
    assert_eq!(
        closed.body["data"]["retirement"]["original_pending_sha256"],
        digest
    );
    assert_eq!(closed.body["data"]["physical_deletion_authorized"], false);
    assert_eq!(
        closed.body["data"]["historical_request_outcome_reclassified"],
        false
    );
    assert_eq!(original.status, 503);
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before + 1
    );
    let mark = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        200,
        "fresh-mark-requires-actual-current-reader7-state",
    )?;
    assert_mark(&mark)?;
    for (path, digest) in &barriers {
        assert_eq!(crypto::digest(&fs::read(path)?), *digest);
    }
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    let mark = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        200,
        "second-cold-provenance-mark",
    )?;
    assert_mark(&mark)?;
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before + 1
    );
    Ok(())
}

pub(super) fn current_cipher_references(
    pipeline: &Pipeline,
    owner: usize,
) -> TestResult<Vec<RecordObjectRef>> {
    let _scope = scope();
    let process = pipeline.processes[owner]
        .as_ref()
        .ok_or("owner")?
        .lock_for_request()
        .map_err(|_| "process lock")?;
    let selected = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("native source")?;
    process.native_install_test_with_source(|codec, store| -> TestResult<_> {
        let closure = codec.open_native_v6_committed_read(
            selected.enrollment(),
            selected.published(),
            store,
            &mut || Ok(()),
        )?;
        Ok(closure.references().to_vec())
    })?
}

fn assert_mark(response: &Response) -> TestResult {
    let data = &response.body["data"];
    assert_eq!(
        data["schema"],
        "heptabao-native-ha-historical-local-mark-v1"
    );
    assert!(
        data["retained_roots"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(
        data["historical_typed_resources"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert_eq!(
        data["retained_catalog_sha256"]
            .as_str()
            .ok_or("catalog SHA")?
            .len(),
        64
    );
    assert_eq!(data["historical_shared_typed_union_complete"], true);
    assert_eq!(data["local_registered_catalog_union_complete"], true);
    let current = data["current_local_typed_resources"]
        .as_u64()
        .ok_or("current local mark")?;
    let retained = data["retained_registered_local_resources"]
        .as_u64()
        .ok_or("retained local mark")?;
    let registered = data["registered_local_resources"]
        .as_u64()
        .ok_or("registered local catalog")?;
    assert!(current > 0 && current <= retained && retained <= registered);
    assert_eq!(
        data["unreferenced_registered_resources_observed"].as_u64(),
        Some(registered - retained)
    );
    assert_eq!(data["physical_deletion_authorized"], false);
    assert_eq!(data["local_barrier_objects_retained"], true);
    assert_eq!(data["local_barriers_gc_qualified"], false);
    Ok(())
}

#[test]
fn native_ha_local_mark_actual_service_keeps_original_actor_owner_and_cold_history_without_deletion()
-> TestResult {
    let (mut pipeline, leader) = configured()?;
    expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        503,
        "mark-cannot-enable-retention-protocol",
    )?;
    prepare(&pipeline, leader)?;
    activate_roots(&pipeline, leader)?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":"retained-mark-version-two"}}),
        )?,
        200,
        "ordinary-new-history",
    )?;
    let orphan = orphan(&pipeline, leader, 0xf3)?;
    let untouched = fs::read(&orphan)?;
    let barriers = barrier_objects(&pipeline.directory(leader).join("data"))?;
    let submissions = crate::service::native_storage::ha_gc::intent_submission_owners_consumed();
    expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, "", json!({}))?,
        403,
        "mark-original-Actor-required",
    )?;
    let store = {
        let _scope = scope();
        pipeline.processes[leader]
            .as_ref()
            .ok_or("owner")?
            .lock_for_request()
            .map_err(|_| "owner lock")?
            .native_install_test_store()?
    };
    let reading = store.begin_native_operation()?;
    expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        503,
        "ordinary-reader-blocks-local-mark-exclusive-owner",
    )?;
    drop(reading);
    let response = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        200,
        "fresh-full-typed-retained-mark",
    )?;
    assert_mark(&response)?;
    assert!(
        response.body["data"]["retained_roots"]
            .as_u64()
            .is_some_and(|count| count >= 2)
    );
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        submissions
    );
    assert_eq!(fs::read(&orphan)?, untouched);
    for (path, digest) in &barriers {
        assert_eq!(crypto::digest(&fs::read(path)?), *digest);
    }
    drop(store);
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    let cold = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        200,
        "same-owner-cold-complete-history-mark",
    )?;
    assert_mark(&cold)?;
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5"), (2, "retained-mark-version-two")])?;
    }
    assert_eq!(fs::read(&orphan)?, untouched);
    for (path, digest) in &barriers {
        assert_eq!(crypto::digest(&fs::read(path)?), *digest);
    }
    crate::service::native_storage::ha_gc::invalidate_activation_after_audit_once();
    let late = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        503,
        "original-unseal-owner-late-audit-veto-erases-mark",
    )?;
    assert!(late.body.get("data").is_none());
    assert_eq!(fs::read(&orphan)?, untouched);
    for (path, digest) in &barriers {
        assert_eq!(crypto::digest(&fs::read(path)?), *digest);
    }
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        submissions
    );
    Ok(())
}

#[test]
fn native_ha_local_mark_actual_retained_payload_corruption_holds_while_current_graph_is_readable()
-> TestResult {
    let (pipeline, leader) = configured()?;
    prepare(&pipeline, leader)?;
    activate_roots(&pipeline, leader)?;
    let value = "full-retained-payload".repeat(16_384);
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":value}}),
        )?,
        200,
        "large-old-version",
    )?;
    pipeline.assert_history(leader, &[(1, "seed-v5"), (2, &value)])?;
    let old = current_cipher_references(&pipeline, leader)?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/destroy/pipeline/history",
            pipeline.admin(),
            json!({"versions":[2]}),
        )?,
        204,
        "destroy-from-current-typed-root",
    )?;
    let current = current_cipher_references(&pipeline, leader)?;
    let selected = old
        .iter()
        .find(|old| old.payload_bytes > 128 * 1024 && !current.iter().any(|live| live.id == old.id))
        .ok_or("large historical payload must be absent from current closure")?;
    let path = pipeline.configs[leader]
        .raft_dir
        .join("native-v6-ciphertext")
        .join(format!("v6-{}.blob", hex(&selected.id)));
    let original = fs::read(&path)?;
    assert_eq!(original.len() as u64, selected.payload_bytes);
    let barriers = barrier_objects(&pipeline.directory(leader).join("data"))?;
    let positive = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        200,
        "full-history-before-hostile-payload-change",
    )?;
    assert_mark(&positive)?;
    let mut damaged = original.clone();
    let last = damaged.last_mut().ok_or("historical ciphertext")?;
    *last ^= 1;
    fs::write(&path, &damaged)?;
    // The ordinary selected graph still works. Only a full retained-history
    // payload walk sees this exact old object; metadata/directory-only marking
    // would incorrectly return a successful complete union.
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        503,
        "old-payload-must-be-physically-authenticated",
    )?;
    assert_eq!(
        fs::read(&path)?,
        damaged,
        "failed mark performs no repair or deletion"
    );
    for (path, digest) in &barriers {
        assert_eq!(crypto::digest(&fs::read(path)?), *digest);
    }
    // Explicit fixture repair restores the exact originally captured bytes.
    // A new request must obtain a new guard/FD; no old failed mark is resumed.
    fs::write(&path, &original)?;
    let fresh = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        200,
        "fresh-owned-mark-after-explicit-fixture-repair",
    )?;
    assert_mark(&fresh)?;
    assert_eq!(fs::read(&path)?, original);
    for (path, digest) in &barriers {
        assert_eq!(crypto::digest(&fs::read(path)?), *digest);
    }
    Ok(())
}
