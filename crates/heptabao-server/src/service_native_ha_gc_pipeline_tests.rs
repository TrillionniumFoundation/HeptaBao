//! Actual Service dispatch, pinned peer admission, original shared-file owners,
//! barrier pending/complete records and cold recovery. These local multi-node
//! tests do not qualify a public HTTP socket, physical host, or SIGKILL run.
use super::*;
use crate::service::native_storage::ha_gc::{
    INTENTS_PATH, INTENTS_RECONCILE_PATH, PATH, RECONCILE_PATH,
};

#[path = "service_native_ha_local_mark_tests.rs"]
mod local_marks;

#[path = "service_native_ha_local_retirement_tests.rs"]
mod local_retirement;

fn configured() -> TestResult<(Pipeline, usize)> {
    let pipeline = Pipeline::start_with_configured_storage(true)?;
    let leader = pipeline.ready_leader()?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/storage/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "configured-native-raft-activation",
    )?;
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    Ok((pipeline, leader))
}

fn orphan(pipeline: &Pipeline, owner: usize, value: u8) -> TestResult<PathBuf> {
    let _scope = scope();
    let process = pipeline.processes[owner]
        .as_ref()
        .ok_or("GC owner absent")?
        .lock_for_request()
        .map_err(|_| "GC owner lock")?;
    let store = process.native_install_test_store()?;
    let staged = store.stage_local(&vec![value; 4096])?;
    let path = pipeline.configs[owner]
        .raft_dir
        .join("native-v6-ciphertext")
        .join(format!("v6-{}.blob", hex(&staged.reference().id)));
    assert!(path.is_file());
    Ok(path)
}

// Preparation now traverses actual Service dispatch, original Actor/deadline,
// every enrolled pinned listener and persistent Pending/Complete metadata.
fn prepare(pipeline: &Pipeline, leader: usize) -> TestResult {
    let response = expect(
        pipeline.call(leader, "POST", INTENTS_PATH, pipeline.admin(), json!({}))?,
        200,
        "actual-Service-intent-preparation",
    )?;
    assert_eq!(response.body["data"]["scope"], "raft-intent-metadata-only");
    assert_eq!(
        response.body["data"]["retirement"]["phase"],
        "original-completed"
    );
    assert_eq!(response.body["data"]["physical_deletion_authorized"], false);
    assert_eq!(response.body["data"]["local_barriers_gc_qualified"], false);
    Ok(())
}

fn barrier_objects(directory: &Path) -> TestResult<BTreeMap<PathBuf, [u8; 32]>> {
    fn visit(directory: &Path, result: &mut BTreeMap<PathBuf, [u8; 32]>) -> TestResult {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            assert!(
                !kind.is_symlink(),
                "fixture contains no local object path aliases"
            );
            if kind.is_dir() {
                visit(&entry.path(), result)?;
            } else if entry.file_name().to_string_lossy().ends_with(".hbo") {
                result.insert(entry.path(), crypto::digest(&fs::read(entry.path())?));
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    visit(directory, &mut result)?;
    assert!(
        !result.is_empty(),
        "observe actual local barrier objects before shared-only GC"
    );
    Ok(result)
}

fn cold_reopen(pipeline: &mut Pipeline, owner: usize) -> TestResult {
    pipeline.stop_process(owner)?;
    let _ = pipeline.ready_leader()?;
    pipeline.start_process(owner)?;
    pipeline.wait_cold_native_readindex_ready(owner)?;
    pipeline.unseal(owner)?;
    Ok(())
}

// Physical retirement requires the actual leader's complete local Raft guard.
// Recover the same pending owner using real handoff, never a replaced directory
// or a copied pending record on another node. The third member is rejoined
// before the next all-member admission or physical operation.
fn lead_with_same_owner(pipeline: &mut Pipeline, owner: usize) -> TestResult {
    let current = pipeline.ready_leader()?;
    if current == owner {
        return Ok(());
    }
    let third = (0..3)
        .find(|id| *id != current && *id != owner)
        .ok_or("third voter")?;
    pipeline.stop_process(third)?;
    expect(
        pipeline.call(
            current,
            "POST",
            "sys/step-down",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "handoff-to-original-retirement-owner",
    )?;
    assert_eq!(pipeline.ready_leader()?, owner);
    pipeline.start_process(third)?;
    pipeline.wait_cold_native_readindex_ready(third)?;
    pipeline.unseal(third)?;
    assert_eq!(pipeline.ready_leader()?, owner);
    Ok(())
}

#[test]
fn native_ha_shared_gc_actual_service_keeps_file_gate_barriers_history_and_cold_bytes() -> TestResult
{
    let (mut pipeline, leader) = configured()?;
    let candidate = orphan(&pipeline, leader, 0xb4)?;
    let before = fs::read(&candidate)?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/storage/native-v6/gc",
            pipeline.admin(),
            json!({}),
        )?,
        501,
        "original-File-HA-refusal-preserved",
    )?;
    // New Raft roots must explicitly enter retention protocol 6 first.
    expect(
        pipeline.call(leader, "POST", PATH, pipeline.admin(), json!({}))?,
        503,
        "physical-GC-does-not-implicitly-enable-retention",
    )?;
    assert_eq!(fs::read(&candidate)?, before);
    prepare(&pipeline, leader)?;
    let barriers = barrier_objects(&pipeline.directory(leader).join("data"))?;
    let response = expect(
        pipeline.call(leader, "POST", PATH, pipeline.admin(), json!({}))?,
        200,
        "actual-shared-owner-retirement",
    )?;
    assert!(
        response.body["data"]["removed_blobs"]
            .as_u64()
            .is_some_and(|n| n >= 1)
    );
    assert_eq!(
        response.body["data"]["local_barrier_objects_retained"],
        true
    );
    assert!(!candidate.exists());
    for (path, expected) in barriers {
        assert_eq!(crypto::digest(&fs::read(path)?), expected);
    }
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    cold_reopen(&mut pipeline, leader)?;
    assert!(!candidate.exists());
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    Ok(())
}

#[test]
fn native_ha_shared_gc_requires_every_actual_member_and_active_shared_reader_holds() -> TestResult {
    let (mut pipeline, leader) = configured()?;
    let candidate = orphan(&pipeline, leader, 0xc5)?;
    let missing = (0..3).find(|id| *id != leader).ok_or("standby")?;
    pipeline.stop_process(missing)?;
    assert_eq!(
        pipeline.ready_leader()?,
        leader,
        "a real majority remains writable"
    );
    assert!(
        prepare(&pipeline, leader).is_err(),
        "actual majority cannot admit a missing retention reader through Service"
    );
    assert!(candidate.is_file());
    pipeline.start_process(missing)?;
    pipeline.wait_cold_native_readindex_ready(missing)?;
    pipeline.unseal(missing)?;
    prepare(&pipeline, leader)?;
    let store = {
        let _scope = scope();
        pipeline.processes[leader]
            .as_ref()
            .ok_or("leader")?
            .lock_for_request()
            .map_err(|_| "process lock")?
            .native_install_test_store()?
    };
    let reading = store.begin_native_operation()?;
    expect(
        pipeline.call(leader, "POST", PATH, pipeline.admin(), json!({}))?,
        503,
        "real-shared-reader-prevents-exclusive-retirement",
    )?;
    assert!(candidate.is_file());
    drop(reading);
    expect(
        pipeline.call(leader, "POST", PATH, pipeline.admin(), json!({}))?,
        200,
        "new-request-after-original-reader-released",
    )?;
    assert!(!candidate.exists());
    Ok(())
}

#[test]
fn native_ha_shared_gc_unknown_keeps_exact_pending_and_cold_reconciles_without_replay() -> TestResult
{
    let (mut pipeline, leader) = configured()?;
    prepare(&pipeline, leader)?;
    let candidate = orphan(&pipeline, leader, 0xd6)?;
    crate::service::native_storage::ha_gc::fail_after_physical_once();
    let original = expect(
        pipeline.call(leader, "POST", PATH, pipeline.admin(), json!({}))?,
        503,
        "lost-original-physical-completion-is-unknown",
    )?;
    assert!(
        !candidate.exists(),
        "actual unlink preceded lost ledger completion"
    );
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    let status = expect(
        pipeline.call(leader, "GET", PATH, pipeline.admin(), json!({}))?,
        200,
        "cold-authenticated-pending-status",
    )?;
    assert_eq!(status.body["data"]["retirement"]["pending"], true);
    let expected = status.body["data"]["retirement"]["record_sha256"]
        .as_str()
        .ok_or("pending SHA absent")?
        .to_owned();
    expect(
        pipeline.call(leader, "POST", PATH, pipeline.admin(), json!({}))?,
        409,
        "pending-operation-is-not-replayed",
    )?;
    expect(
        pipeline.call(
            leader,
            "POST",
            RECONCILE_PATH,
            pipeline.admin(),
            json!({"expected_pending_sha256":"00".repeat(32)}),
        )?,
        409,
        "wrong-pending-digest-cannot-reconcile",
    )?;
    let result = expect(
        pipeline.call(
            leader,
            "POST",
            RECONCILE_PATH,
            pipeline.admin(),
            json!({"expected_pending_sha256":expected}),
        )?,
        200,
        "fresh-owner-exact-pending-reconciliation",
    )?;
    assert!(
        result.body["data"]["confirmed_absent_files"]
            .as_u64()
            .is_some_and(|n| n >= 1)
    );
    assert_eq!(
        result.body["data"]["retirement"]["phase"],
        "reconciliation-completed"
    );
    assert_eq!(
        result.body["data"]["historical_request_outcome_reclassified"],
        false
    );
    assert_eq!(
        original.status, 503,
        "new reconciliation does not change the old reply"
    );
    assert!(!candidate.exists());
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    Ok(())
}

#[test]
fn native_ha_intent_gc_actual_service_unknown_cold_observes_without_replay_or_deletion()
-> TestResult {
    let (mut pipeline, leader) = configured()?;
    let candidate = orphan(&pipeline, leader, 0xe7)?;
    let untouched = fs::read(&candidate)?;
    let barriers = barrier_objects(&pipeline.directory(leader).join("data"))?;
    let before = crate::service::native_storage::ha_gc::intent_submission_owners_consumed();
    crate::service::native_storage::ha_gc::fail_after_intent_commit_once();
    let original = expect(
        pipeline.call(leader, "POST", INTENTS_PATH, pipeline.admin(), json!({}))?,
        503,
        "lost-original-metadata-completion-is-unknown",
    )?;
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before + 1
    );
    assert_eq!(
        fs::read(&candidate)?,
        untouched,
        "metadata command does not collect ciphertext"
    );
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    let status = expect(
        pipeline.call(leader, "GET", INTENTS_PATH, pipeline.admin(), json!({}))?,
        200,
        "cold-authenticated-intent-pending",
    )?;
    assert_eq!(status.body["data"]["retirement"]["pending"], true);
    let digest = status.body["data"]["retirement"]["record_sha256"]
        .as_str()
        .ok_or("pending intent SHA")?
        .to_owned();
    let serial = status.body["data"]["retirement"]["serial"]
        .as_u64()
        .ok_or("original serial")?;
    expect(
        pipeline.call(leader, "POST", INTENTS_PATH, pipeline.admin(), json!({}))?,
        409,
        "cold-Pending-never-becomes-new-command",
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
        "foreign-pending-selector-holds",
    )?;
    expect(
        pipeline.call(leader, "POST", PATH, pipeline.admin(), json!({}))?,
        503,
        "physical-GC-holds-during-metadata-Pending",
    )?;
    assert_eq!(fs::read(&candidate)?, untouched);
    let response = expect(
        pipeline.call(
            leader,
            "POST",
            INTENTS_RECONCILE_PATH,
            pipeline.admin(),
            json!({"expected_pending_sha256":digest}),
        )?,
        200,
        "new-read-only-metadata-reconciliation",
    )?;
    // Original terminal-clock/audit writes may have advanced the root. In that
    // case only the strict monotone supersession rule may close this capsule;
    // the response must never invent the old ACK or new physical permission.
    assert!(matches!(
        response.body["data"]["observation"].as_str(),
        Some("effects-observed" | "source-superseded")
    ));
    assert_eq!(response.body["data"]["retirement"]["serial"], serial);
    assert_eq!(
        response.body["data"]["retirement"]["original_pending_sha256"],
        digest
    );
    assert_eq!(response.body["data"]["physical_deletion_authorized"], false);
    assert_eq!(
        response.body["data"]["historical_request_outcome_reclassified"],
        false
    );
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before + 1
    );
    assert_eq!(original.status, 503);
    assert_eq!(fs::read(&candidate)?, untouched);
    for (path, digest) in barriers {
        assert_eq!(crypto::digest(&fs::read(path)?), digest);
    }
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    let status = expect(
        pipeline.call(leader, "GET", INTENTS_PATH, pipeline.admin(), json!({}))?,
        200,
        "second-cold-terminal-observation-persists",
    )?;
    assert_eq!(status.body["data"]["retirement"]["pending"], false);
    assert_eq!(status.body["data"]["retirement"]["serial"], serial);
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before + 1
    );
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, "seed-v5")])?;
    }
    Ok(())
}

#[test]
fn native_ha_intent_gc_original_actor_and_post_audit_activation_veto_success_delivery() -> TestResult
{
    let (mut pipeline, leader) = configured()?;
    let before = crate::service::native_storage::ha_gc::intent_submission_owners_consumed();
    expect(
        pipeline.call(leader, "POST", INTENTS_PATH, "", json!({}))?,
        403,
        "actual-missing-original-Actor-cannot-prepare",
    )?;
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before
    );
    crate::service::native_storage::ha_gc::invalidate_activation_after_audit_once();
    let original = expect(
        pipeline.call(leader, "POST", INTENTS_PATH, pipeline.admin(), json!({}))?,
        503,
        "changed-original-unseal-owner-after-audit-vetoes-delivery",
    )?;
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before + 1
    );
    assert!(
        original.body.get("data").is_none(),
        "known internal completion cannot bypass original delivery owner"
    );
    cold_reopen(&mut pipeline, leader)?;
    lead_with_same_owner(&mut pipeline, leader)?;
    let status = expect(
        pipeline.call(leader, "GET", INTENTS_PATH, pipeline.admin(), json!({}))?,
        200,
        "new-cold-status-distinguishes-metadata-completion-from-old-HTTP-reply",
    )?;
    assert_eq!(
        status.body["data"]["retirement"]["phase"],
        "original-completed"
    );
    assert_eq!(
        status.body["data"]["historical_request_outcome_reclassified"],
        false
    );
    assert_eq!(original.status, 503);
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        before + 1
    );
    Ok(())
}
