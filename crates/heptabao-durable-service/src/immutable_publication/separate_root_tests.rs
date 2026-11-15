//! Compare admission with real conditional object batches and a separate root.
//! Refused plans must preserve all artifacts before any staging is attempted.
use super::*;

const OLD_ROOT: &[u8] = b"old-root";

fn fixture_objects(count: usize) -> Vec<(String, &'static [u8])> {
    let mut objects = (0..count)
        .map(|index| (format!("objects/{index:03}"), &b"v"[..]))
        .collect::<Vec<_>>();
    if let Some(first) = objects.first().cloned() {
        objects.push(first);
    }
    objects
}

fn seeded(
    name: &str,
    existing: usize,
    limit: usize,
) -> Result<(TestRoot, DurableService<TestBarrier>), ServiceError> {
    assert!(existing < MAX_ATOMIC_MUTATIONS);
    let root = TestRoot::new(name)?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), limit)?;
    let mut mutations = (0..existing)
        .map(|index| {
            Ok((
                format!("objects/{index:03}"),
                Some(Secret::new(b"v".to_vec())?),
            ))
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    mutations.push(("state".into(), Some(Secret::new(OLD_ROOT.to_vec())?)));
    service.apply_batch("server", "system", "seed", [7; 32], mutations)?;
    Ok((root, service))
}

fn old_root_condition() -> Result<Vec<PublicationCondition>, ServiceError> {
    Ok(vec![PublicationCondition {
        resource: "state".into(),
        expected: Some(Secret::new(OLD_ROOT.to_vec())?),
    }])
}

fn stage_objects(
    service: &mut DurableService<TestBarrier>,
    operation: &str,
    objects: &[(String, &[u8])],
) -> Result<usize, ServiceError> {
    let mut pending = BTreeMap::new();
    for (resource, bytes) in objects {
        match service.get("system", resource)? {
            Some(existing) => assert_eq!(existing.expose(), *bytes),
            None => {
                if let Some(previous) = pending.insert(resource.clone(), bytes.to_vec()) {
                    assert_eq!(previous.as_slice(), *bytes);
                }
            }
        }
    }
    let pending = pending.into_iter().collect::<Vec<_>>();
    let mut count = 0;
    for (index, batch) in pending.chunks(MAX_ATOMIC_MUTATIONS).enumerate() {
        service.apply_batch_conditionally_before_publish(
            BatchPublication {
                replay_epoch: 0,
                principal: "server".into(),
                namespace: "system".into(),
                request_id: format!("{operation}-objects-{index}"),
                authorization_digest: [7; 32],
                mutations: batch
                    .iter()
                    .map(|(resource, bytes)| {
                        Ok((resource.clone(), Some(Secret::new(bytes.to_vec())?)))
                    })
                    .collect::<Result<Vec<_>, ServiceError>>()?,
            },
            old_root_condition()?,
            || Ok(()),
        )?;
        assert_eq!(
            service.get("system", "state")?.as_ref().map(Secret::expose),
            Some(OLD_ROOT)
        );
        count += 1;
    }
    Ok(count)
}

fn publish_root(
    service: &mut DurableService<TestBarrier>,
    operation: &str,
    bytes: &[u8],
) -> Result<(), ServiceError> {
    service.apply_batch_conditionally_before_publish(
        BatchPublication {
            replay_epoch: 0,
            principal: "server".into(),
            namespace: "system".into(),
            request_id: format!("{operation}-root"),
            authorization_digest: [7; 32],
            mutations: vec![("state".into(), Some(Secret::new(bytes.to_vec())?))],
        },
        old_root_condition()?,
        || Ok(()),
    )?;
    Ok(())
}

#[test]
fn separate_root_admission_matches_actual_95_96_97_reuse_and_cold_reopen()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    for (total, existing) in [
        (95_usize, 0_usize),
        (96, 0),
        (97, 0),
        (97, 95),
        (95, 95),
        (0, 0),
    ] {
        let (root, mut service) = seeded("separate-root-real", existing, 16)?;
        let objects = fixture_objects(total);
        let before = service.backend.load().map_err(map_backend_error)?;
        let before_counters = counters(&service);
        let plan = service.preflight_immutable_publication_with_separate_root(request(
            0,
            "next",
            &objects,
            b"new-root",
        ))?;
        assert_eq!(plan.new_objects, total - existing);
        assert_eq!(
            plan.batches,
            (total - existing).div_ceil(MAX_ATOMIC_MUTATIONS) + 1
        );
        assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
        assert_eq!(counters(&service), before_counters);
        let staged = stage_objects(&mut service, "next", &objects)?;
        assert_eq!(staged + 1, plan.batches);
        publish_root(&mut service, "next", b"new-root")?;
        assert_eq!(
            service.generation(),
            before_counters.0 + plan.batches as u64
        );
        assert_eq!(service.ledger.len(), plan.retained_requests_after);
        check_caches(&service)?;
        drop(service);
        let service = DurableService::reopen(&root.0, TestBarrier::new(), 16)?;
        assert_eq!(
            service.get("system", "state")?.as_ref().map(Secret::expose),
            Some(&b"new-root"[..])
        );
        for (resource, value) in &objects {
            assert_eq!(
                service
                    .get("system", resource)?
                    .as_ref()
                    .map(Secret::expose),
                Some(*value)
            );
        }
        check_caches(&service)?;
    }
    Ok(())
}

#[test]
fn separate_root_reserves_extra_ledger_slot_before_staging_at_95_96_97_and_reuse()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    for (total, existing) in [(95_usize, 0_usize), (96, 0), (97, 0), (97, 95), (95, 95)] {
        let missing = total - existing;
        let batches = missing.div_ceil(MAX_ATOMIC_MUTATIONS) + 1;
        // One seed is already retained, so this limit is exactly one short
        // of the complete separate-root sequence, including root-only reuse.
        let (_root, mut service) = seeded("separate-root-ledger", existing, batches)?;
        let objects = fixture_objects(total);
        let before = service.backend.load().map_err(map_backend_error)?;
        let before_counters = counters(&service);
        assert!(matches!(
            service.preflight_immutable_publication_with_separate_root(request(
                0,
                "next",
                &objects,
                b"new-root"
            ),),
            Err(ServiceError::RequestCapacityExhausted)
        ));
        if missing % MAX_ATOMIC_MUTATIONS != 0 {
            // The old packing remains valid for its actual combined last
            // object/root batch. It cannot authorize the extra root batch.
            let combined = service.preflight_immutable_publication(request(
                0,
                "next",
                &objects,
                b"new-root",
            ))?;
            assert_eq!(combined.batches + 1, batches);
        }
        assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
        assert_eq!(counters(&service), before_counters);
        assert!(!service.recovery_required());
        service.max_retained_requests += 1;
        let plan = service.preflight_immutable_publication_with_separate_root(request(
            0,
            "next",
            &objects,
            b"new-root",
        ))?;
        assert_eq!(
            stage_objects(&mut service, "next", &objects)? + 1,
            plan.batches
        );
        publish_root(&mut service, "next", b"new-root")?;
        assert_eq!(service.ledger.len(), service.max_retained_requests);
        check_caches(&service)?;
    }
    Ok(())
}

fn minimum_separate_journal(
    service: &mut DurableService<TestBarrier>,
    objects: &[(String, &[u8])],
    value: &[u8],
) -> Result<usize, ServiceError> {
    let mut lower = 0;
    let mut upper = MAX_FILE_BYTES;
    service.journal_limit = upper;
    service.preflight_immutable_publication_with_separate_root(request(
        0, "journal", objects, value,
    ))?;
    while lower + 1 < upper {
        let middle = lower + (upper - lower) / 2;
        service.journal_limit = middle;
        match service.preflight_immutable_publication_with_separate_root(request(
            0, "journal", objects, value,
        )) {
            Ok(_) => upper = middle,
            Err(ServiceError::JournalCapacityExhausted) => lower = middle,
            Err(error) => return Err(error),
        }
    }
    Ok(upper)
}

#[test]
fn separate_root_journal_boundary_rejects_before_staging_and_matches_real_writes()
-> Result<(), ServiceError> {
    let _serial = serial_test();
    for (total, existing) in [(95_usize, 0_usize), (96, 0), (97, 0), (97, 95), (95, 95)] {
        let (_root, mut service) = seeded("separate-root-journal", existing, 16)?;
        let objects = fixture_objects(total);
        let value = vec![b'r'; 16 * 1024];
        let before = service.backend.load().map_err(map_backend_error)?;
        let before_counters = counters(&service);
        let minimum = minimum_separate_journal(&mut service, &objects, &value)?;
        service.journal_limit = minimum - 1;
        assert!(matches!(
            service.preflight_immutable_publication_with_separate_root(request(
                0, "journal", &objects, &value
            ),),
            Err(ServiceError::JournalCapacityExhausted)
        ));
        assert_eq!(service.backend.load().map_err(map_backend_error)?, before);
        assert_eq!(counters(&service), before_counters);
        assert!(!service.recovery_required());

        // Independent real-I/O control: if preflight were ignored, these
        // small objects could stage, but the final root still cannot fit.
        let (_control_root, mut control) = seeded("separate-root-journal-control", existing, 16)?;
        control.journal_limit = minimum - 1;
        stage_objects(&mut control, "journal", &objects)?;
        let generation = control.generation();
        let retained = control.ledger.len();
        assert!(matches!(
            publish_root(&mut control, "journal", &value),
            Err(ServiceError::JournalCapacityExhausted)
        ));
        assert_eq!(control.generation(), generation);
        assert_eq!(control.ledger.len(), retained);
        assert_eq!(
            control.get("system", "state")?.as_ref().map(Secret::expose),
            Some(OLD_ROOT)
        );
        assert!(!control.recovery_required());

        // At the exact admitted boundary, execute the real separate sequence.
        // This checks the prediction against the journal writer, not a second
        // copy of the admission size formula.
        service.journal_limit = minimum;
        let plan = service.preflight_immutable_publication_with_separate_root(request(
            0, "journal", &objects, &value,
        ))?;
        assert_eq!(
            stage_objects(&mut service, "journal", &objects)? + 1,
            plan.batches
        );
        publish_root(&mut service, "journal", &value)?;
        assert_eq!(
            service.get("system", "state")?.as_ref().map(Secret::expose),
            Some(value.as_slice())
        );
        assert_eq!(service.ledger.len(), plan.retained_requests_after);
        assert!(service.journal_bytes <= minimum);
        check_caches(&service)?;
    }
    Ok(())
}
