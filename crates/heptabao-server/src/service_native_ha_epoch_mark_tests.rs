//! Actual Service archive restore, pinned TLS quorum, durable checkpoint and
//! all-owner cold reopen. Owners shut down normally; this is not SIGKILL or a
//! physical-host result. No local/shared object is deleted by these mark calls.
use super::super::super::historical_restore_tests::{export, restore};
use super::*;
use heptabao_raft_runtime::NativeV6PublishedRoot;

fn actual_selection(
    pipeline: &Pipeline,
    member: usize,
) -> TestResult<(u64, NativeV6PublishedRoot)> {
    let _scope = scope();
    let process = pipeline.processes[member]
        .as_ref()
        .ok_or("epoch mark process")?
        .lock_for_request()
        .map_err(|_| "epoch mark process lock")?;
    let read = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("epoch mark root")?;
    let data = (read.enrollment().epoch(), read.published().clone());
    process.verify_native_v6_committed_read(&read)?;
    Ok(data)
}

fn checkpoint_and_purge_all(pipeline: &Pipeline, through: u64) -> TestResult {
    for member in 0..3 {
        // Each explicit administrative operation has its original budget.
        // The purge observation never restarts or widens that operation.
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let process = pipeline.processes[member]
            .as_ref()
            .ok_or("checkpoint process")?
            .lock_for_request()
            .map_err(|_| "checkpoint lock")?;
        let read = process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("checkpoint source")?;
        process.verify_native_v6_committed_read(&read)?;
        assert!(process.membership()?.applied_index >= Some(through));
        process.trigger_snapshot()?;
        loop {
            if process.membership()?.purged_index >= Some(through) {
                break;
            }
            if Instant::now() >= until {
                return Err("actual checkpoint purge exceeded original request".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(Instant::now() < until);
    }
    Ok(())
}

#[test]
fn native_ha_root_provenance_actual_archives_two_epochs_checkpoint_and_all_owner_cold_mark()
-> TestResult {
    let (mut pipeline, leader) = configured()?;
    prepare(&pipeline, leader)?;
    activate_roots(&pipeline, leader)?;
    let values = [
        "seed-v5",
        "after-first-actual-epoch",
        "after-second-actual-epoch",
    ];
    let mut sources = Vec::new();
    for epoch in 0..2 {
        let archive = export(&pipeline, leader, pipeline.admin())?;
        assert!(!archive.is_empty());
        let (old_epoch, source) = actual_selection(&pipeline, leader)?;
        expect(
            restore(&pipeline, leader, pipeline.admin(), &archive)?,
            200,
            "actual-HA-archive-restore-with-retained-root-protocol",
        )?;
        let (new_epoch, target) = actual_selection(&pipeline, leader)?;
        assert_eq!(new_epoch, old_epoch + 1);
        assert!(target.generation() > source.generation());
        assert_ne!(target.root_digest(), source.root_digest());
        assert_eq!(target.epoch_transitions().len(), epoch + 1);
        let transition = target
            .epoch_transitions()
            .last()
            .ok_or("actual transition")?;
        assert_eq!(transition.source_enrollment().epoch(), old_epoch);
        assert_eq!(transition.target_enrollment().epoch(), new_epoch);
        // The real admission may publish its clock floor after our read-only
        // pre-request observation. Pin the ACTUAL committed transition source,
        // not a timing-dependent assumption that no ordinary root intervened.
        assert!(transition.source_publication_log_id().index >= source.publication_log_id().index);
        if transition.source_publication_log_id().index == source.publication_log_id().index {
            assert_eq!(
                transition.source_publication_log_id(),
                source.publication_log_id()
            );
            assert_eq!(transition.source_intent_log_id(), source.intent_log_id());
            assert_eq!(transition.source_root_digest(), source.root_digest());
        }
        sources.push((
            transition.source_publication_log_id(),
            transition.source_intent_log_id(),
            transition.source_root_digest(),
        ));
        expect(
            pipeline.call(
                leader,
                "POST",
                "secret/data/pipeline/history",
                pipeline.admin(),
                json!({"options":{"cas":epoch + 1},"data":{"value":values[epoch + 1]}}),
            )?,
            200,
            "ordinary-publication-after-each-real-epoch",
        )?;
        let expected: Vec<_> = values[..=epoch + 1]
            .iter()
            .enumerate()
            .map(|(version, value)| (version as u64 + 1, *value))
            .collect();
        for member in 0..3 {
            pipeline.assert_history(member, &expected)?;
        }
    }
    // The command really retires obsolete metadata; protected source/target
    // intents remain even after all actual logs and journals are compacted.
    prepare(&pipeline, leader)?;
    let (_, current) = actual_selection(&pipeline, leader)?;
    assert_eq!(current.epoch_transitions().len(), 2);
    let barriers = barrier_objects(&pipeline.directory(leader).join("data"))?;
    let applied = {
        let _scope = scope();
        pipeline.processes[leader]
            .as_ref()
            .ok_or("metadata applied owner")?
            .lock_for_request()
            .map_err(|_| "metadata applied lock")?
            .membership()?
            .applied_index
            .ok_or("metadata applied frontier")?
    };
    assert!(applied >= current.publication_log_id().index);
    checkpoint_and_purge_all(&pipeline, applied)?;
    let before = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        200,
        "complete-typed-mark-after-real-archive-and-checkpoint",
    )?;
    assert_mark(&before)?;
    assert!(
        before.body["data"]["retained_roots"]
            .as_u64()
            .is_some_and(|count| count >= 5)
    );
    let (_, cold_expected) = actual_selection(&pipeline, leader)?;
    let submissions = crate::service::native_storage::ha_gc::intent_submission_owners_consumed();

    for member in 0..3 {
        pipeline.stop_process(member)?;
    }
    for member in [1, 2, 0] {
        pipeline.start_process(member)?;
    }
    let elected = pipeline.ready_leader()?;
    for member in std::iter::once(elected).chain((0..3).filter(|member| *member != elected)) {
        pipeline.wait_cold_native_readindex_ready(member)?;
        // Inspect cold Raft DATA on every owner before ANY new Service request
        // may legitimately publish a later admission/terminal clock root.
        let (_, cold) = actual_selection(&pipeline, member)?;
        assert_eq!(cold.root_digest(), cold_expected.root_digest());
        assert_eq!(cold.epoch_transitions().len(), 2);
    }
    for member in std::iter::once(elected).chain((0..3).filter(|member| *member != elected)) {
        pipeline.unseal(member)?;
    }
    lead_with_same_owner(&mut pipeline, leader)?;
    for member in 0..3 {
        pipeline.assert_history(member, &[(1, values[0]), (2, values[1]), (3, values[2])])?;
        let (_, cold) = actual_selection(&pipeline, member)?;
        assert_eq!(cold.epoch_transitions().len(), 2);
        for (transition, source) in cold.epoch_transitions().zip(&sources) {
            assert_eq!(transition.source_publication_log_id(), source.0);
            assert_eq!(transition.source_intent_log_id(), source.1);
            assert_eq!(transition.source_root_digest(), source.2);
        }
    }
    let cold = expect(
        pipeline.call(leader, "POST", LOCAL_MARK_PATH, pipeline.admin(), json!({}))?,
        200,
        "full-historical-typed-union-after-all-original-owners-reopen",
    )?;
    assert_mark(&cold)?;
    assert!(
        cold.body["data"]["retained_roots"]
            .as_u64()
            .is_some_and(|count| count >= 5)
    );
    assert_eq!(
        crate::service::native_storage::ha_gc::intent_submission_owners_consumed(),
        submissions
    );
    for (path, digest) in barriers {
        assert_eq!(crypto::digest(&fs::read(path)?), digest);
    }
    Ok(())
}
