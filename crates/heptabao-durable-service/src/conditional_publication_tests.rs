use super::tests::{TestBarrier, TestRoot, serial_test};
use super::*;

fn batch(id: &str, root: &[u8], cursor: &[u8]) -> Result<BatchPublication, ServiceError> {
    Ok(BatchPublication {
        replay_epoch: 0,
        principal: "writer".into(),
        namespace: "system".into(),
        request_id: id.into(),
        authorization_digest: [9; 32],
        mutations: vec![
            ("state".into(), Some(Secret::new(root.to_vec())?)),
            (
                "publication-cursor".into(),
                Some(Secret::new(cursor.to_vec())?),
            ),
        ],
    })
}
fn conditions(root: &[u8], cursor: &[u8]) -> Result<Vec<PublicationCondition>, ServiceError> {
    Ok(vec![
        PublicationCondition {
            resource: "state".into(),
            expected: Some(Secret::new(root.to_vec())?),
        },
        PublicationCondition {
            resource: "publication-cursor".into(),
            expected: Some(Secret::new(cursor.to_vec())?),
        },
    ])
}
fn initialize(service: &mut DurableService<TestBarrier>) -> Result<(), ServiceError> {
    service.apply_batch_before_publish(batch("initial", b"root-A", b"generation-1")?, || Ok(()))?;
    Ok(())
}

#[test]
fn conditional_publication_rejects_actual_root_aba_and_atomically_reopens_cursor()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("conditional-root-aba")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    initialize(&mut service)?;
    service.apply_batch_conditionally_before_publish(
        batch("to-B", b"root-B", b"generation-2")?,
        conditions(b"root-A", b"generation-1")?,
        || Ok(()),
    )?;
    service.apply_batch_conditionally_before_publish(
        batch("back-A", b"root-A", b"generation-3")?,
        conditions(b"root-B", b"generation-2")?,
        || Ok(()),
    )?;
    let generation = service.generation();
    let journal = fs::read(journal_path(&root.0))?;
    let retained = service.retained_request_count();
    assert!(matches!(
        service.apply_batch_conditionally_before_publish(
            batch("stale", b"forbidden", b"generation-2")?,
            conditions(b"root-A", b"generation-1")?,
            || Ok(())
        ),
        Err(ServiceError::PublicationConditionConflict)
    ));
    assert_eq!(service.generation(), generation);
    assert_eq!(service.retained_request_count(), retained);
    assert_eq!(fs::read(journal_path(&root.0))?, journal);
    service.apply_batch_conditionally_before_publish(
        batch("current", b"root-C", b"generation-4")?,
        conditions(b"root-A", b"generation-3")?,
        || Ok(()),
    )?;
    drop(service);
    let reopened = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
    assert_eq!(
        reopened
            .get("system", "state")?
            .ok_or(ServiceError::CorruptState)?
            .expose(),
        b"root-C"
    );
    assert_eq!(
        reopened
            .get("system", "publication-cursor")?
            .ok_or(ServiceError::CorruptState)?
            .expose(),
        b"generation-4"
    );
    Ok(())
}

#[test]
fn conditional_publication_binds_conditions_and_rechecks_original_gate_on_duplicate()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("conditional-replay")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 16)?;
    initialize(&mut service)?;
    service.apply_batch_conditionally_before_publish(
        batch("write", b"root-B", b"generation-2")?,
        conditions(b"root-A", b"generation-1")?,
        || Ok(()),
    )?;
    assert!(matches!(
        service.apply_batch_conditionally_before_publish(
            batch("write", b"root-B", b"generation-2")?,
            conditions(b"root-A", b"generation-1")?,
            || Ok(())
        )?,
        MutationOutcome::Duplicate { .. }
    ));
    assert!(matches!(
        service.apply_batch_conditionally_before_publish(
            batch("write", b"root-B", b"generation-2")?,
            conditions(b"root-B", b"generation-2")?,
            || Ok(())
        ),
        Err(ServiceError::RequestBindingConflict)
    ));
    let generation = service.generation();
    assert!(matches!(
        service.apply_batch_conditionally_before_publish(
            batch("write", b"root-B", b"generation-2")?,
            conditions(b"root-A", b"generation-1")?,
            || Err(ServiceError::BarrierFailure)
        ),
        Err(ServiceError::BarrierFailure)
    ));
    assert_eq!(service.generation(), generation);
    Ok(())
}

#[test]
fn conditional_publication_keeps_exact_conditions_and_owner_gate_across_compaction()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    let root = TestRoot::new("conditional-compaction")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 64)?;
    initialize(&mut service)?;
    service.journal_limit = 1500;
    let mut prior_cursor = b"generation-1".to_vec();
    let mut compacted = false;
    for number in 2..20 {
        let cursor = format!("generation-{number}").into_bytes();
        let sequence = service.journal_sequence;
        service.apply_batch_conditionally_before_publish(
            batch(&format!("advance-{number}"), b"root-A", &cursor)?,
            conditions(b"root-A", &prior_cursor)?,
            || Ok(()),
        )?;
        compacted |= service.journal_sequence <= sequence;
        prior_cursor = cursor;
    }
    assert!(compacted, "real journal compaction must be exercised");
    let generation = service.generation();
    let called = std::cell::Cell::new(false);
    assert!(matches!(
        service.apply_batch_conditionally_before_publish(
            batch("revoked", b"forbidden", b"forbidden-cursor")?,
            conditions(b"root-A", &prior_cursor)?,
            || {
                called.set(true);
                Err(ServiceError::BarrierFailure)
            }
        ),
        Err(ServiceError::BarrierFailure)
    ));
    assert!(called.get());
    assert_eq!(service.generation(), generation);
    assert_eq!(
        service
            .get("system", "state")?
            .ok_or(ServiceError::CorruptState)?
            .expose(),
        b"root-A"
    );
    assert_eq!(
        service
            .get("system", "publication-cursor")?
            .ok_or(ServiceError::CorruptState)?
            .expose(),
        prior_cursor
    );
    Ok(())
}
