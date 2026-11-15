//! Real mTLS/quorum/checkpoint observations. The original failed handle stays
//! invalid; only a fresh exact-root read under both old bounds may continue.
use super::*;

fn active() -> TestResult<(Pipeline, usize)> {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/internal/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "same-root-progress-activation",
    )?;
    Ok((pipeline, leader))
}

#[test]
fn native_ha_same_root_actual_checkpoint_continues_local_read_without_publication() -> TestResult {
    let (pipeline, leader) = active()?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let ha = pipeline.processes[leader]
        .as_ref()
        .ok_or("progress leader absent")?;
    let original = {
        let process = ha.lock_for_request().map_err(|_| "progress process lock")?;
        let original = process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("progress root absent")?;
        assert!(
            process
                .recapture_native_v6_same_root_after_progress(&original)
                .is_err()
        );
        process.native_install_test_checkpoint()?;
        assert!(process.verify_native_v6_committed_read(&original).is_err());
        let fresh = process.recapture_native_v6_same_root_after_progress(&original)?;
        assert_eq!(fresh.published(), original.published());
        assert_eq!(fresh.enrollment(), original.enrollment());
        assert_eq!(fresh.deadline().instant(), until);
        assert!(fresh.read_index_deadline() <= original.read_index_deadline());
        process.verify_native_v6_committed_read(&fresh)?;
        let phase = process.recapture_native_v6_same_selection(&fresh)?;
        assert_eq!(phase.published(), fresh.published());
        assert_eq!(phase.enrollment(), fresh.enrollment());
        assert_eq!(phase.deadline().instant(), until);
        assert!(phase.read_index_deadline() <= original.read_index_deadline());
        process.verify_native_v6_committed_read(&phase)?;
        assert!(process.verify_native_v6_committed_read(&original).is_err());
        original
    };
    let service = pipeline.services[leader]
        .as_ref()
        .ok_or("progress service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "progress service lock")?;
    let generation = writer
        .durable
        .as_ref()
        .ok_or("progress durable absent")?
        .generation();
    let identity = writer
        .current_state_identity()
        .map_err(|_| "progress identity")?;
    let audit_sequence = writer.audit_sequence;
    let progress = writer
        .sync_native_v6_from_ha_checked(ha, original, &mut |_| Ok(()))
        .map_err(|_| "same-root checkpoint continuation rejected")?;
    assert!(matches!(progress, ha_received::HaSyncProgress::Current));
    assert_eq!(
        writer
            .current_state_identity()
            .map_err(|_| "progress final identity")?,
        identity
    );
    assert_eq!(
        writer
            .durable
            .as_ref()
            .ok_or("progress final durable absent")?
            .generation(),
        generation
    );
    assert_eq!(writer.audit_sequence, audit_sequence);
    assert!(!writer.recovery_required);
    assert!(Instant::now() < until);
    Ok(())
}

#[test]
fn native_ha_same_root_progress_rejects_other_owner_changed_root_and_expired_read() -> TestResult {
    let (pipeline, leader) = active()?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let ha = pipeline.processes[leader]
        .as_ref()
        .ok_or("progress leader absent")?;
    let original = {
        let process = ha.lock_for_request().map_err(|_| "progress process lock")?;
        let read = process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("progress original absent")?;
        process.native_install_test_checkpoint()?;
        read
    };
    let other = pipeline.processes[(leader + 1) % 3]
        .as_ref()
        .ok_or("progress other absent")?;
    assert!(
        other
            .lock_for_request()
            .map_err(|_| "progress other lock")?
            .recapture_native_v6_same_root_after_progress(&original)
            .is_err()
    );
    {
        let _changed_scope = RequestDeadlineScope::enter(until - Duration::from_millis(1));
        assert!(
            ha.lock_for_request()
                .map_err(|_| "progress changed deadline lock")?
                .recapture_native_v6_same_root_after_progress(&original)
                .is_err()
        );
    }
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":"same-root-progress-real-new-root"}}),
        )?,
        200,
        "same-root-progress-real-change",
    )?;
    assert!(
        ha.lock_for_request()
            .map_err(|_| "progress changed root lock")?
            .recapture_native_v6_same_root_after_progress(&original)
            .is_err()
    );
    let current = {
        let process = ha.lock_for_request().map_err(|_| "progress expiry lock")?;
        let read = process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("progress expiry read absent")?;
        process.native_install_test_checkpoint()?;
        read
    };
    thread::sleep(Duration::from_millis(8_100));
    assert!(Instant::now() < until);
    assert!(
        ha.lock_for_request()
            .map_err(|_| "progress expired lock")?
            .recapture_native_v6_same_root_after_progress(&current)
            .is_err()
    );
    Ok(())
}

#[test]
fn native_ha_same_root_progress_preserves_actor_denial_and_changed_seal() -> TestResult {
    let (pipeline, leader) = active()?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let ha = pipeline.processes[leader]
        .as_ref()
        .ok_or("progress leader absent")?;
    let select_then_checkpoint = || -> TestResult<crate::ha::CommittedNativeV6Read> {
        let process = ha
            .lock_for_request()
            .map_err(|_| "progress actor process lock")?;
        let read = process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("progress actor root absent")?;
        process.native_install_test_checkpoint()?;
        Ok(read)
    };
    let original = select_then_checkpoint()?;
    let service = pipeline.services[leader]
        .as_ref()
        .ok_or("progress actor service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "progress actor service lock")?;
    let generation = writer
        .durable
        .as_ref()
        .ok_or("progress actor durable absent")?
        .generation();
    let mut calls = 0;
    let denied = writer
        .sync_native_v6_from_ha_checked(ha, original, &mut |_| {
            calls += 1;
            Err(Response::error(403, "progress-test-actor-denied"))
        })
        .err()
        .ok_or("actor denial was swallowed")?;
    assert_eq!(denied.status, 403);
    assert_eq!(calls, 1);
    assert_eq!(
        writer
            .durable
            .as_ref()
            .ok_or("progress actor final durable absent")?
            .generation(),
        generation
    );
    let original = select_then_checkpoint()?;
    let seal_path = writer.data_dir.join("seal.json");
    let old_seal = fs::read(&seal_path)?;
    let mut changed = false;
    let rejected = writer.sync_native_v6_from_ha_checked(ha, original, &mut |_| {
        if !changed {
            fs::write(&seal_path, b"{}\n").map_err(|_| Response::error(503, "test seal write"))?;
            changed = true;
        }
        Ok(())
    });
    fs::write(seal_path, old_seal)?;
    assert!(changed);
    assert!(rejected.is_err());
    assert_eq!(
        writer
            .durable
            .as_ref()
            .ok_or("progress seal final durable absent")?
            .generation(),
        generation
    );
    Ok(())
}

#[test]
fn native_ha_same_root_progress_rejects_replaced_ciphertext_without_repairing_it() -> TestResult {
    let (pipeline, leader) = active()?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let ha = pipeline.processes[leader]
        .as_ref()
        .ok_or("progress corrupt leader absent")?;
    let (original, reference) = {
        let process = ha
            .lock_for_request()
            .map_err(|_| "progress corrupt process lock")?;
        let read = process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("progress corrupt root absent")?;
        let store = process.native_install_test_store()?;
        let references = store.reopen_root_closure(read.published(), &mut || Ok(()))?;
        let reference = references
            .first()
            .ok_or("progress corrupt reference absent")?
            .clone();
        process.native_install_test_checkpoint()?;
        assert!(process.verify_native_v6_committed_read(&read).is_err());
        (read, reference)
    };
    let leaf = pipeline.configs[leader]
        .raft_dir
        .join("native-v6-ciphertext")
        .join(format!("v6-{}.blob", hex(&reference.id)));
    let original_bytes = fs::read(&leaf)?;
    let damaged = b"owned ciphertext replaced during a real checkpoint boundary";
    fs::write(&leaf, damaged)?;
    let service = pipeline.services[leader]
        .as_ref()
        .ok_or("progress corrupt service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "progress corrupt service lock")?;
    let identity = writer
        .current_state_identity()
        .map_err(|_| "progress corrupt identity")?;
    let generation = writer
        .durable
        .as_ref()
        .ok_or("progress corrupt durable absent")?
        .generation();
    let rejected = writer.sync_native_v6_from_ha_checked(ha, original, &mut |_| Ok(()));
    assert!(rejected.is_err());
    assert_eq!(
        writer
            .current_state_identity()
            .map_err(|_| "progress corrupt final identity")?,
        identity
    );
    assert_eq!(
        writer
            .durable
            .as_ref()
            .ok_or("progress corrupt final durable absent")?
            .generation(),
        generation
    );
    assert_eq!(fs::read(&leaf)?.as_slice(), damaged);
    fs::write(leaf, original_bytes)?;
    Ok(())
}
