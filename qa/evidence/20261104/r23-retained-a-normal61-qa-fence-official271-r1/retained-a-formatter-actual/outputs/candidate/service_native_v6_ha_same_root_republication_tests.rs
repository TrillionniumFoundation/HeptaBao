//! Real A -> B -> A publications with two independently owned local barriers.
//! The existing fixture copies ciphertext explicitly, then uses actual Raft
//! publication/ReadIndex and the production local installer. It is not an HTTP
//! quorum transport test. The original 15-second request scopes remain intact.
use super::*;

fn publish_retained_projection(
    plan: &v6_records::NativeRootMigrationPlan,
    cluster: &Cluster,
    enrollment: &NativeV6PeerEnrollment,
    prior_digest: [u8; 32],
    prior_generation: u64,
    previous_index: u64,
) -> TestResult<(NativeV6PublishedRoot, usize)> {
    // The first projection owns its original 15-second deadline. Keeping its
    // graph for A -> B -> A never refreshes that deadline or a publication proof.
    let _scope = RequestDeadlineScope::enter(plan.deadline.instant());
    plan.deadline.check()?;
    let count = plan.objects.len();
    let proposal: NativeV6HaProposal = cluster.processes[0]
        .lock()
        .map_err(|_| "fixture leader lock")?
        .native_install_test_with_source(|codec, store| {
            let prepared = prepare_native_v6_ha_objects(
                plan,
                codec,
                enrollment,
                store,
                None,
                None,
                &mut || Ok(()),
            )?;
            let local = prepared.local_closure();
            let generation = prior_generation + 1;
            let intent = NativeV6CommitIntent {
                cluster_digest: enrollment.cluster_digest(),
                epoch: enrollment.epoch(),
                operation_digest: crypto::digest(
                    format!("native-install-fixture-{generation}").as_bytes(),
                ),
                closure_manifest_sha256: local.manifest_sha256(),
                object_count: local.object_count() as u64,
                ciphertext_bytes: local.ciphertext_bytes(),
                prior_root_digest: prior_digest,
                proposed_root_digest: prepared.root_digest(),
                prior_generation,
                proposed_generation: generation,
                expected_previous_commit_index: previous_index,
            };
            prepared.into_proposal(codec, enrollment, intent, &mut || Ok(()))
        })??;
    let sender = cluster.processes[0]
        .lock()
        .map_err(|_| "fixture leader lock")?
        .native_install_test_store()?;
    for process in &cluster.processes {
        process
            .lock()
            .map_err(|_| "fixture process lock")?
            .native_install_test_copy_ciphertext(&sender, &proposal)?;
    }
    let published = cluster.processes[0]
        .lock()
        .map_err(|_| "fixture leader lock")?
        .native_install_test_publish(&proposal, enrollment)?;
    Ok((published, count))
}

fn old_same_root_selection(
    service: &mut Service,
    ha: &Arc<Mutex<HaProcess>>,
    first: &NativeV6PublishedRoot,
    current: &NativeV6PublishedRoot,
) -> TestResult<LocalSelection> {
    let _scope = scope();
    let read = fresh(ha)?;
    assert_eq!(read.published(), current);
    let selected =
        LocalSelection::read(service.durable.as_mut().ok_or("old local durable")?, &read)
            .map_err(|_| "old local cursor must be authenticated and covered")?;
    let root = selected.native.as_ref().ok_or("old native root")?;
    assert_eq!(
        root.identity().map_err(|_| "old root identity")?.digest(),
        current.root_digest(),
    );
    let cursor =
        NativeHaCursor::decode(selected.ha_bytes.as_ref().ok_or("old HA cursor")?.expose())
            .map_err(|_| "old canonical HA cursor")?;
    cursor
        .covered_by(&read)
        .map_err(|_| "old publication must remain covered")?;
    assert_eq!(cursor.raft_generation, first.generation());
    assert!(cursor.raft_generation < current.generation());
    assert!(
        cursor.matches_current(&read).is_err(),
        "equal content must not erase the older publication binding",
    );
    assert!(
        !service
            .native_v6_same_root_continuation_is_current(&read)
            .map_err(|_| "same-root continuation admission")?,
        "an old publication must not enter the read-only witness continuation",
    );
    Ok(selected)
}

fn current_pair(
    service: &mut Service,
    ha: &Arc<Mutex<HaProcess>>,
    old: &LocalSelection,
    published: &NativeV6PublishedRoot,
) -> TestResult<LocalSelection> {
    let _scope = scope();
    let read = fresh(ha)?;
    assert_eq!(read.published(), published);
    let selected =
        LocalSelection::read(service.durable.as_mut().ok_or("installed durable")?, &read)
            .map_err(|_| "installed local selection")?;
    assert_eq!(selected.root_bytes.expose(), old.root_bytes.expose());
    assert!(selected.initial_generation > old.initial_generation);
    let cursor = NativeHaCursor::decode(
        selected
            .ha_bytes
            .as_ref()
            .ok_or("installed HA cursor")?
            .expose(),
    )
    .map_err(|_| "installed canonical HA cursor")?;
    cursor
        .matches_current(&read)
        .map_err(|_| "installed cursor must match the complete publication")?;
    assert_eq!(cursor.raft_generation, published.generation());
    assert_eq!(
        cursor.local_publication_generation,
        selected.initial_generation,
    );
    let active_bytes = selected.active_bytes.as_ref().ok_or("installed active")?;
    assert_eq!(
        active_generation(active_bytes.expose()).map_err(|_| "paired active generation")?,
        cursor.local_publication_generation,
    );
    assert_ne!(
        selected.ha_bytes.as_ref().ok_or("installed HA")?.expose(),
        old.ha_bytes.as_ref().ok_or("old HA")?.expose(),
    );
    assert_ne!(
        active_bytes.expose(),
        old.active_bytes.as_ref().ok_or("old active")?.expose(),
    );
    assert!(
        service
            .native_v6_same_root_continuation_is_current(&read)
            .map_err(|_| "current continuation admission")?,
    );
    assert!(!service.recovery_required);
    Ok(selected)
}

fn reopen_current_without_publication(
    files: &Root,
    ha: &Arc<Mutex<HaProcess>>,
    barrier: &[u8; 32],
    expected: &LocalSelection,
) -> TestResult {
    let started = Instant::now();
    let (cold, durable, loaded) = cold_load(files, ha, barrier)?;
    assert!(started.elapsed() < REQUEST_BUDGET);
    assert!(cold.state.is_none() && cold.barrier_key.is_none());
    assert_eq!(durable.generation(), expected.initial_generation);
    for (name, bytes) in [
        ("state", &expected.root_bytes),
        (
            ACTIVE_CURSOR_RESOURCE,
            expected.active_bytes.as_ref().ok_or("expected active")?,
        ),
        (
            HA_CURSOR_RESOURCE,
            expected.ha_bytes.as_ref().ok_or("expected HA cursor")?,
        ),
    ] {
        assert_eq!(
            durable
                .get("system", name)?
                .ok_or("reopened resource")?
                .expose(),
            bytes.expose(),
        );
    }
    assert_eq!(
        loaded
            .root
            .identity()
            .map_err(|_| "reopened identity")?
            .digest(),
        expected
            .native
            .as_ref()
            .ok_or("expected native root")?
            .identity()
            .map_err(|_| "expected identity")?
            .digest(),
    );
    Ok(())
}

#[test]
fn native_ha_same_root_republication_advances_warm_and_cold_cursors() -> TestResult {
    let (source_files, mut source_a, _source_key, token) = initialized()?;
    populate(&mut source_a, &token, 112);
    let (_branch_files, mut source_b, _branch_key, _branch_token) = initialized()?;
    seed_different_local_barrier(&source_a, &mut source_b)?;
    let (warm_files, mut warm, _warm_key, _warm_token) = initialized()?;
    seed_different_local_barrier(&source_a, &mut warm)?;
    let (cold_files, mut cold_target, _cold_key, _cold_token) = initialized()?;
    seed_different_local_barrier(&source_a, &mut cold_target)?;
    let source_digest = source_a
        .current_state_identity()
        .map_err(|_| "source identity")?
        .digest();
    let (cluster, enrollment, index) = cluster(
        &source_a,
        &source_files.path.join("same-root-republication-raft"),
    )?;
    let (first, count, first_projection) = {
        let _scope = scope();
        let plan = source_a
            .prepare_native_root_migration_paged(&|| Ok(()))
            .map_err(|_| "actual source A native projection")?;
        let (first, count) = publish_retained_projection(
            &plan,
            &cluster,
            &enrollment,
            source_digest,
            0,
            index,
        )?;
        (first, count, plan)
    };
    assert!(count > heptabao_durable_service::MAX_ATOMIC_MUTATIONS);
    let warm_ha = cluster.processes[1].clone();
    let cold_ha = cluster.processes[2].clone();
    warm.ha = Some(warm_ha.clone());
    cold_target.ha = Some(cold_ha.clone());
    install_warm(&mut warm, &warm_ha, &token)?;
    install_warm(&mut cold_target, &cold_ha, &token)?;

    // Consecutive A -> A intents are invalid. Publish a real intermediate B,
    // then publish the first complete A projection at a later Raft generation.
    // A fresh V5 migration would generate a different random address key and
    // therefore a different V6 root, even though source A did not change.
    assert_eq!(
        call(
            &mut source_b,
            "POST",
            "secret/data/same-root-intermediate",
            &token,
            json!({"options":{"cas":0},"data":{"value":"intermediate-B"}}),
        )
        .status,
        200,
    );
    let (second, _) = publish(
        &mut source_b,
        &cluster,
        &enrollment,
        first.root_digest(),
        first.generation(),
        first.publication_log_id().index,
    )?;
    assert_ne!(second.root_digest(), first.root_digest());
    let (third, _) = publish_retained_projection(
        &first_projection,
        &cluster,
        &enrollment,
        second.root_digest(),
        second.generation(),
        second.publication_log_id().index,
    )?;
    assert_eq!(third.root_digest(), first.root_digest());
    assert_eq!(third.generation(), first.generation() + 2);
    assert_eq!(third.migration_source(), first.migration_source());
    assert!(third.publication_log_id().index > second.publication_log_id().index);
    let old_warm = old_same_root_selection(&mut warm, &warm_ha, &first, &third)?;
    let old_cold = old_same_root_selection(&mut cold_target, &cold_ha, &first, &third)?;

    let warm_started = Instant::now();
    install_warm(&mut warm, &warm_ha, &token)?;
    let warm_elapsed = warm_started.elapsed();
    assert!(warm_elapsed < REQUEST_BUDGET);
    let current_warm = current_pair(&mut warm, &warm_ha, &old_warm, &third)?;
    assert_history_with_real_proof(&mut warm, &token, 4)?;

    let cold_barrier = Zeroizing::new(
        **cold_target
            .barrier_key
            .as_ref()
            .ok_or("cold target barrier")?,
    );
    drop(cold_target);
    let cold_started = Instant::now();
    let (cold, durable, loaded) = cold_load(&cold_files, &cold_ha, &cold_barrier)?;
    let cold_elapsed = cold_started.elapsed();
    assert!(cold_elapsed < REQUEST_BUDGET);
    let mut cold_target = install_cold_owner(cold, durable, loaded, &cold_barrier)?;
    let current_cold = current_pair(&mut cold_target, &cold_ha, &old_cold, &third)?;
    assert_history_with_real_proof(&mut cold_target, &token, 4)?;
    eprintln!(
        "same-root-republication warm_ms={} cold_ms={} per_request_budget_ms={}",
        warm_elapsed.as_millis(),
        cold_elapsed.as_millis(),
        REQUEST_BUDGET.as_millis(),
    );

    let warm_barrier = Zeroizing::new(**warm.barrier_key.as_ref().ok_or("warm barrier")?);
    drop(warm);
    drop(cold_target);
    reopen_current_without_publication(&warm_files, &warm_ha, &warm_barrier, &current_warm)?;
    reopen_current_without_publication(&cold_files, &cold_ha, &cold_barrier, &current_cold)?;
    Ok(())
}
