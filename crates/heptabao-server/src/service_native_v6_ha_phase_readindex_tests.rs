//! A phase-boundary read obtains actual quorum authority for the same root.
//! It never revives a failed witness or changes the original operation bound.
use super::*;

fn activated() -> TestResult<(Pipeline, usize)> {
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
        "phase-readindex-actual-activation",
    )?;
    Ok((pipeline, leader))
}

#[test]
fn native_ha_phase_readindex_same_selection_original_deadline_and_process() -> TestResult {
    let (pipeline, leader) = activated()?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let process = pipeline.processes[leader]
        .as_ref()
        .ok_or("phase-readindex leader absent")?
        .lock_for_request()
        .map_err(|_| "phase-readindex leader lock")?;
    let original = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("phase-readindex committed root absent")?;
    let next = process.recapture_native_v6_same_selection(&original)?;
    assert_eq!(next.deadline().instant(), until);
    assert_eq!(original.deadline().instant(), until);
    assert!(next.published() == original.published());
    assert!(next.enrollment() == original.enrollment());
    process.verify_native_v6_committed_read(&original)?;
    process.verify_native_v6_committed_read(&next)?;

    // A nested operation cannot use this boundary to adopt another deadline.
    {
        let _other_scope = RequestDeadlineScope::enter(until - Duration::from_millis(1));
        assert!(
            process
                .recapture_native_v6_same_selection(&original)
                .is_err()
        );
    }
    process.verify_native_v6_committed_read(&original)?;
    drop(process);

    // Equal replicated bytes do not make this handle belong to another node.
    let other = pipeline.processes[(leader + 1) % 3]
        .as_ref()
        .ok_or("phase-readindex other process absent")?
        .lock_for_request()
        .map_err(|_| "phase-readindex other process lock")?;
    assert!(other.recapture_native_v6_same_selection(&original).is_err());
    assert!(Instant::now() < until);
    Ok(())
}

#[test]
fn native_ha_phase_readindex_changed_application_selection_is_terminal() -> TestResult {
    let (pipeline, leader) = activated()?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let ha = pipeline.processes[leader]
        .as_ref()
        .ok_or("phase-readindex leader absent")?;
    let original = {
        let process = ha
            .lock_for_request()
            .map_err(|_| "phase-readindex original lock")?;
        process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("phase-readindex original root absent")?
    };
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":"phase-readindex-new-root"}}),
        )?,
        200,
        "phase-readindex-actual-application-change",
    )?;
    let process = ha
        .lock_for_request()
        .map_err(|_| "phase-readindex changed lock")?;
    assert!(
        process
            .recapture_native_v6_same_selection(&original)
            .is_err()
    );
    // An independent read verifies the new root; it never rescues the old
    // failed selection or causes another application write.
    let current = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("phase-readindex new root absent")?;
    assert_ne!(
        current.published().root_digest(),
        original.published().root_digest()
    );
    process.verify_native_v6_committed_read(&current)?;
    assert_eq!(current.deadline().instant(), until);
    assert!(Instant::now() < until);
    Ok(())
}

#[test]
fn native_ha_phase_readindex_expired_witness_is_not_renewed_with_live_operation() -> TestResult {
    let (pipeline, leader) = activated()?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let process = pipeline.processes[leader]
        .as_ref()
        .ok_or("phase-readindex leader absent")?
        .lock_for_request()
        .map_err(|_| "phase-readindex leader lock")?;
    let original = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("phase-readindex committed root absent")?;
    // The production ReadIndex cap is eight seconds, independently of the
    // unchanged fifteen-second operation. No mocked expiry or witness fields.
    thread::sleep(Duration::from_millis(8_100));
    assert!(Instant::now() < until);
    assert!(process.verify_native_v6_committed_read(&original).is_err());
    assert!(
        process
            .recapture_native_v6_same_selection(&original)
            .is_err()
    );
    let independent = process
        .native_v6_committed_read(OriginalDeadline::capture()?)?
        .ok_or("phase-readindex independent root absent")?;
    assert!(independent.published() == original.published());
    process.verify_native_v6_committed_read(&independent)?;
    assert_eq!(independent.deadline().instant(), until);
    assert!(Instant::now() < until);
    Ok(())
}
