//! Real three-voter predecessor recovery with one-shot negative read/CAS faults.
//! The faults are scoped to the current test thread and only remove authority.
//! These are read-boundary fault tests, not claims of physical disk corruption
//! or power loss. Original request, ReadIndex and Actor checks remain active.
use super::*;
use crate::service::native_v6_ha_install::HA_CURSOR_RESOURCE;
use crate::service::native_v6_reader::{ACTIVE_CURSOR_RESOURCE, ACTIVE_SOURCE_ROOT_RESOURCE};
use crate::state_record_root::{RecordStateRoot, StateIdentity};
use std::cell::Cell;
use std::rc::Rc;

struct LocalV5 {
    root_bytes: Zeroizing<Vec<u8>>,
    disk_identity: StateIdentity,
    selected_identity: StateIdentity,
    generation: u64,
    epoch: u64,
    recovery_required: bool,
}

fn local_v5(pipeline: &Pipeline, index: usize) -> TestResult<LocalV5> {
    pipeline.with_service(index, |service| {
        let durable = service
            .durable
            .as_ref()
            .ok_or("negative fixture durable owner")?;
        let bytes = durable
            .get("system", "state")?
            .ok_or("negative fixture V5 root")?;
        let root = RecordStateRoot::decode(bytes.expose())
            .map_err(|_| "negative fixture V5 root decode")?;
        assert!(service.record_root.is_some() && service.native_root.is_none());
        for resource in [
            ACTIVE_CURSOR_RESOURCE,
            ACTIVE_SOURCE_ROOT_RESOURCE,
            HA_CURSOR_RESOURCE,
        ] {
            assert!(
                durable.get("system", resource)?.is_none(),
                "a retained V5 owner must not acquire a native publication cursor early"
            );
        }
        Ok(LocalV5 {
            root_bytes: Zeroizing::new(bytes.expose().to_vec()),
            disk_identity: root
                .identity()
                .map_err(|_| "negative fixture V5 root identity")?,
            selected_identity: service
                .current_state_identity()
                .map_err(|_| "negative fixture selected V5")?,
            generation: durable.generation(),
            epoch: durable.replay_epoch(),
            recovery_required: service.recovery_required,
        })
    })
}

fn assert_same_local_v5(before: &LocalV5, after: &LocalV5) {
    // Canonical root bytes contain the address key; never print them on failure.
    assert!(
        before.root_bytes.as_slice() == after.root_bytes.as_slice(),
        "a refused retained read changed the exact local root bytes"
    );
    assert_eq!(before.disk_identity, after.disk_identity);
    assert_eq!(before.selected_identity, after.selected_identity);
    assert_eq!(before.generation, after.generation);
    assert_eq!(before.epoch, after.epoch);
    assert_eq!(before.recovery_required, after.recovery_required);
}

fn rejected_metadata(pipeline: &Pipeline, index: usize) -> TestResult<Response> {
    let response = pipeline.call(
        index,
        "GET",
        &format!("{MOUNT}/metadata/history"),
        pipeline.admin(),
        json!({}),
    )?;
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none() && response.body.get("auth").is_none());
    assert!(response.unwrapped_json.is_none() && response.consistency_index.is_none());
    Ok(response)
}

fn retained_object_fault_refuses_before_staging<S>(
    arm: impl FnOnce(Rc<Cell<bool>>, Rc<Cell<bool>>) -> S,
) -> TestResult {
    let (pipeline, leader) = setup()?;
    let lagger = (leader + 1) % 3;
    let before = local_v5(&pipeline, lagger)?;
    assert_ne!(before.disk_identity, pipeline.seed_identity);
    assert_eq!(before.selected_identity, before.disk_identity);
    assert!(!before.recovery_required);
    let (source, bytes) = fixture(128)?;
    let (response, reads) = upload(&pipeline, leader, pipeline.admin(), &bytes)?;
    expect(
        response,
        204,
        "negative predecessor fixture real native import",
    )?;
    assert!(reads > 0);
    assert_same_local_v5(&before, &local_v5(&pipeline, lagger)?);
    let committed = pipeline.native_selection(lagger)?;

    let observed = Rc::new(Cell::new(false));
    let materialization_refused = Rc::new(Cell::new(false));
    let fault = arm(Rc::clone(&observed), Rc::clone(&materialization_refused));
    let response = rejected_metadata(&pipeline, lagger)?;
    drop(fault);
    assert!(
        observed.get(),
        "fault must reach the real retained V5 reader"
    );
    assert!(
        materialization_refused.get(),
        "the actual retained materializer must reject the injected owner before forwarding"
    );
    // The standby synchronizes the current quota/mount registry before any
    // forwarding attempt. The actual retained-source refusal now terminates
    // that admission stage; it must not be mislabeled as a completed exchange.
    assert_eq!(
        response.body["errors"],
        json!(["record state failed authenticated validation"])
    );
    let refused = local_v5(&pipeline, lagger)?;
    assert_same_local_v5(&before, &refused);
    assert!(
        !refused.recovery_required,
        "no root was committed before the read refusal"
    );
    pipeline.with_service(lagger, |service| {
        assert!(service.ha_activation.is_none() && service.ha_read_cache.is_none());
        assert!(
            !service
                .durable
                .as_ref()
                .ok_or("refused durable")?
                .recovery_required()
        );
        Ok(())
    })?;
    assert_eq!(pipeline.native_selection(lagger)?, committed);

    // This is a fresh read after a one-shot injected read failure, not a retry
    // of any write. It must authenticate the actual retained source again and
    // complete the original strict native installer before returning history.
    assert_history(&pipeline, lagger, &source)?;
    assert_eq!(pipeline.native_selection(lagger)?, committed);
    pipeline.with_service(lagger, |service| {
        assert_eq!(
            service
                .current_state_identity()
                .map_err(|_| "recovered native identity")?,
            StateIdentity::RecordsV6(committed.1)
        );
        assert!(service.record_root.is_none() && service.native_root.is_some());
        assert!(!service.recovery_required && !service.audit_failed);
        assert!(service.native_candidate_profile.is_none());
        Ok(())
    })?;
    Ok(())
}

#[test]
fn native_ha_large_kv2_missing_retained_v5_object_refuses_before_staging() -> TestResult {
    retained_object_fault_refuses_before_staging(Service::test_native_v6_predecessor_missing_once)
}

#[test]
fn native_ha_large_kv2_wrong_retained_v5_bytes_fail_real_address_validation_before_staging()
-> TestResult {
    retained_object_fault_refuses_before_staging(
        Service::test_native_v6_predecessor_wrong_bytes_once,
    )
}

#[test]
fn native_ha_large_kv2_real_predecessor_cas_refusal_fences_until_cold_reopen() -> TestResult {
    let (mut pipeline, leader) = setup()?;
    let lagger = (leader + 1) % 3;
    let before = local_v5(&pipeline, lagger)?;
    assert_ne!(before.disk_identity, pipeline.seed_identity);
    let (source, bytes) = fixture(128)?;
    let (response, reads) = upload(&pipeline, leader, pipeline.admin(), &bytes)?;
    expect(
        response,
        204,
        "post-CAS predecessor fixture real native import",
    )?;
    assert!(reads > 0);
    assert_same_local_v5(&before, &local_v5(&pipeline, lagger)?);
    let committed = pipeline.native_selection(lagger)?;

    let observed = Rc::new(Cell::new(false));
    let fault = Service::test_native_v6_predecessor_post_cas_once(Rc::clone(&observed));
    rejected_metadata(&pipeline, lagger)?;
    drop(fault);
    assert!(
        observed.get(),
        "refusal must follow the actual durable predecessor root CAS"
    );
    let fenced = local_v5(&pipeline, lagger)?;
    assert_eq!(fenced.disk_identity, pipeline.seed_identity);
    assert_ne!(fenced.disk_identity, before.disk_identity);
    assert!(fenced.root_bytes.as_slice() != before.root_bytes.as_slice());
    assert!(fenced.generation > before.generation);
    assert_eq!(fenced.epoch, before.epoch);
    // The failed transition cannot activate its intermediate V5 state. The
    // old cached owner is fenced while the actual disk root already advanced.
    assert_eq!(fenced.selected_identity, before.selected_identity);
    assert!(fenced.recovery_required);
    pipeline.with_service(lagger, |service| {
        assert!(service.ha_activation.is_none() && service.ha_read_cache.is_none());
        assert!(
            !service
                .durable
                .as_ref()
                .ok_or("post-CAS durable")?
                .recovery_required(),
            "the real root publication succeeded; the Service owns the uncertainty fence"
        );
        assert!(!service.audit_failed && service.native_request_binding.is_none());
        Ok(())
    })?;
    assert_eq!(pipeline.native_selection(lagger)?, committed);

    // Consuming the hook cannot clear the fence on a later business request.
    rejected_metadata(&pipeline, lagger)?;
    assert_same_local_v5(&fenced, &local_v5(&pipeline, lagger)?);

    // Stop both actual owners and reopen the exact physical directory. Cold
    // unseal authenticates the committed V5 predecessor and must finish native
    // catch-up under fresh, real ReadIndex authority before any business read.
    pipeline.stop_process(lagger)?;
    cold_rejoin(&mut pipeline, lagger)?;
    assert_history(&pipeline, lagger, &source)?;
    assert_eq!(pipeline.native_selection(lagger)?, committed);
    pipeline.with_service(lagger, |service| {
        assert_eq!(
            service
                .current_state_identity()
                .map_err(|_| "cold post-CAS native identity")?,
            StateIdentity::RecordsV6(committed.1)
        );
        assert!(service.record_root.is_none() && service.native_root.is_some());
        assert!(!service.recovery_required && !service.audit_failed);
        assert!(service.native_candidate_profile.is_none());
        Ok(())
    })?;
    Ok(())
}
