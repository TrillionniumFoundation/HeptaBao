//! Actual durable Raft and original ciphertext files. In-process consensus
//! routing does not qualify physical hosts, HTTP admission or publication.
use super::super::super::committed_pull::{
    NativeV6IngressClosureRead, read_native_v6_fresh_ingress_closure,
    read_native_v6_fresh_ingress_closure_observed,
};
use super::*;

fn routes() -> TestResult<BTreeMap<u64, NodeId>> {
    (1..=3)
        .map(|id| Ok((id, NodeId::parse(format!("fresh-ingress-{id}"))?)))
        .collect()
}

fn actual_checkpoint(fixture: &CurrentClosureFixture<'_>, node: usize) -> Result<(), HaError> {
    fixture
        .runtime
        .block_on(fixture.nodes[node].snapshot_observed())
        .map(|_| ())
        .map_err(|_| HaError::OutcomeUnknown)
}

fn publish_successor(
    fixture: &CurrentClosureFixture<'_>,
    previous: &heptabao_raft_runtime::NativeV6PublishedRoot,
    until: Instant,
    change: (u8, u8),
) -> TestResult<heptabao_raft_runtime::NativeV6PublishedRoot> {
    let live = LiveReceivers::start(
        fixture.nodes,
        fixture.runtime.handle(),
        fixture.stores,
        fixture.enrollment,
        fixture.tls,
    )?;
    let transport = live.transport(fixture.tls.clients[&1].clone())?;
    let mut next = previous.intent();
    next.operation_digest = [change.0; 32];
    next.prior_root_digest = previous.root_digest();
    next.proposed_root_digest = [change.1; 32];
    next.prior_generation = previous.generation();
    next.proposed_generation = next.prior_generation + 1;
    next.expected_previous_commit_index = previous.publication_log_id().index;
    let staged = fixture.runtime.block_on(async {
        fixture.nodes[0]
            .stage_application_object(
                fixture.nodes[0].next_production_client_serial().await?,
                &SealedRecordObject::new_native_v6_commit_intent(next)?,
            )
            .await
    })?;
    let quorum = replicate_native_v6_closure_to_quorum(
        &fixture.nodes[0],
        fixture.runtime.handle(),
        &transport,
        &live.routes,
        NativeV6ClosureSource {
            source: &fixture.stores[0],
            references: fixture.references,
            intent: &next,
        },
        until,
    )?;
    fixture
        .runtime
        .block_on(quorum.verify_for_publication(&fixture.nodes[0]))?;
    let actual = fixture.runtime.block_on(async {
        fixture.nodes[0]
            .publish_native_v6_root(
                fixture.nodes[0].next_production_client_serial().await?,
                &next,
                &staged,
                fixture.enrollment,
                vec![0x89; 64],
                until,
            )
            .await
    })?;
    assert_eq!(actual.root_digest(), next.proposed_root_digest);
    Ok(actual)
}

#[test]
fn fresh_ingress_full_data_pass_without_progress_returns_actual_current_selection() -> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture.root.0.join("cipher-1");
        let before = read_directory_observation(&path)?;
        let selected = fixture.selected(Instant::now() + Duration::from_secs(15))?;
        let original_bound = selected.operation_deadline();
        let old_read = selected.read_index_deadline();
        let result = read_native_v6_fresh_ingress_closure(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &routes()?,
            Arc::clone(&fixture.stores[0]),
            selected,
        )?;
        let NativeV6IngressClosureRead::Complete(read) = result else {
            return Err("an unchanged actual root needs neither repair nor reselection".into());
        };
        assert_eq!(read.root(), fixture.published);
        assert_eq!(read.operation_deadline(), original_bound);
        assert!(read.read_index_deadline() <= old_read);
        fixture
            .runtime
            .block_on(fixture.nodes[0].verify_native_v6_committed_root_read(&read))?;
        assert_eq!(read_directory_observation(&path)?, before);
        Ok(())
    })
}

#[test]
fn fresh_ingress_actual_publication_can_select_once_but_old_same_root_stays_strict() -> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture.root.0.join("cipher-1");
        let before = read_directory_observation(&path)?;
        let until = Instant::now() + Duration::from_secs(15);
        let strict_old = fixture.selected(until)?;
        let selected = fixture.selected(until)?;
        let old_read = selected.read_index_deadline();
        let changed = std::cell::Cell::new(false);
        let mut after_publisher = None;
        let result = read_native_v6_fresh_ingress_closure_observed(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &routes()?,
            Arc::clone(&fixture.stores[0]),
            selected,
            &mut |gate| {
                if gate == 1 {
                    assert_eq!(
                        read_directory_observation(&path).map_err(|_| HaError::Transport)?,
                        before,
                        "the read prefix must not change the complete directory observation"
                    );
                    publish_successor(&fixture, fixture.published, until, (0x87, 0x88))
                        .map_err(|_| HaError::OutcomeUnknown)?;
                    let observed =
                        read_directory_observation(&path).map_err(|_| HaError::Transport)?;
                    assert_eq!(
                        observed.entries, before.entries,
                        "the injected publisher must preserve all selected ciphertext bytes"
                    );
                    after_publisher = Some(observed);
                    changed.set(true);
                }
                Ok(())
            },
        )?;
        assert!(changed.get(), "the real Raft root must actually publish");
        let after_publisher =
            after_publisher.ok_or("actual publication directory observation absent")?;
        assert!(
            fixture
                .runtime
                .block_on(fixture.nodes[0].native_v6_same_root_progress_read(&strict_old))
                .is_err()
        );
        assert!(
            fixture
                .runtime
                .block_on(fixture.nodes[0].verify_native_v6_committed_root_read(&strict_old))
                .is_err()
        );
        let NativeV6IngressClosureRead::Superseded(source) = result else {
            return Err(
                "a complete old DATA pass plus actual new ReadIndex must yield the opaque source"
                    .into(),
            );
        };
        assert_eq!(source.previous_root(), fixture.published);
        assert_eq!(source.operation_deadline(), until);
        assert_eq!(source.original_read_deadline(), old_read);
        let live = LiveReceivers::start(
            fixture.nodes,
            fixture.runtime.handle(),
            fixture.stores,
            fixture.enrollment,
            fixture.tls,
        )?;
        let transport = live.transport(fixture.tls.clients[&1].clone())?;
        let read = source.complete(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &transport,
            &live.routes,
            &fixture.stores[0],
        )?;
        assert_eq!(read.root().root_digest(), [0x88; 32]);
        assert_eq!(read.operation_deadline(), until);
        assert!(read.read_index_deadline() <= old_read);
        fixture
            .runtime
            .block_on(fixture.nodes[0].verify_native_v6_committed_root_read(&read))?;
        assert_eq!(read_directory_observation(&path)?, after_publisher);
        Ok(())
    })
}

#[test]
fn fresh_ingress_real_short_leaf_read_then_postgate_progress_never_mints_source() -> TestResult {
    with_current_committed_closure(|fixture| {
        // A follower makes a new ReadIndex observable as an actual RPC.
        let node = &fixture.nodes[1];
        let path = fixture.root.0.join("cipher-2");
        let leaf = path.join(immutable_name("v6-", &fixture.references[0].id, ".blob")?);
        let selected = fixture
            .runtime
            .block_on(node.native_v6_committed_root_read(Instant::now() + Duration::from_secs(15)))?
            .ok_or("follower root absent")?;
        let generation = selected.application_generation();
        let before_rpcs = fixture.router.read_index_requests.load(Ordering::Acquire);
        let shortened = std::cell::Cell::new(false);
        let progressed = std::cell::Cell::new(false);
        let after_checkpoint_rpcs = std::cell::Cell::new(None);
        let result = read_native_v6_fresh_ingress_closure_observed(
            node,
            fixture.runtime.handle(),
            &routes()?,
            Arc::clone(&fixture.stores[1]),
            selected,
            &mut |gate| {
                // The three-reference manifest is <64KiB: gates 3/4 metadata,
                // 5/6 bytes, 7/8 EOF. Leaf gates 12/13 hold length, gate 15
                // is immediately before the actual read, gate 16 after it.
                if gate == 15 {
                    assert_eq!(
                        fixture.router.read_index_requests.load(Ordering::Acquire),
                        before_rpcs,
                        "the DATA prefix before the physical short read issues no successor ReadIndex"
                    );
                    let file = fs::OpenOptions::new()
                        .write(true)
                        .open(&leaf)
                        .map_err(|_| HaError::Transport)?;
                    file.set_len(0).map_err(|_| HaError::Transport)?;
                    shortened.set(true);
                } else if gate == 16 {
                    assert_eq!(
                        fixture.router.read_index_requests.load(Ordering::Acquire),
                        before_rpcs,
                        "the failed DATA read issues no successor before the injected checkpoint"
                    );
                    actual_checkpoint(&fixture, 1)?;
                    after_checkpoint_rpcs.set(Some(
                        fixture.router.read_index_requests.load(Ordering::Acquire),
                    ));
                    progressed.set(true);
                }
                Ok(())
            },
        );
        assert!(
            shortened.get() && progressed.get(),
            "both ordered physical stimuli must occur"
        );
        assert_eq!(fs::metadata(&leaf)?.len(), 0);
        assert!(
            matches!(
                result,
                Ok(NativeV6IngressClosureRead::NeedsOriginalRepair(_))
            ),
            "EOF cannot become no-effects source when postgate observes progress"
        );
        assert_eq!(
            fixture.router.read_index_requests.load(Ordering::Acquire),
            after_checkpoint_rpcs
                .get()
                .ok_or("actual checkpoint ReadIndex observation absent")?,
            "failed DATA pass must not issue the successor ReadIndex"
        );
        let after = fixture
            .runtime
            .block_on(node.native_v6_committed_root_read(Instant::now() + Duration::from_secs(15)))?
            .ok_or("root absent after checkpoint")?;
        assert!(after.application_generation() > generation);
        Ok(())
    })
}

#[test]
fn fresh_ingress_missing_or_corrupt_leaf_with_progress_never_mints_source() -> TestResult {
    for missing in [false, true] {
        with_current_committed_closure(|fixture| {
            let leaf = fixture.root.0.join("cipher-1").join(immutable_name(
                "v6-",
                &fixture.references[0].id,
                ".blob",
            )?);
            let selected = fixture.selected(Instant::now() + Duration::from_secs(15))?;
            let damaged = std::cell::Cell::new(false);
            let result = read_native_v6_fresh_ingress_closure_observed(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &routes()?,
                Arc::clone(&fixture.stores[0]),
                selected,
                &mut |gate| {
                    if gate == 1 {
                        if missing {
                            fs::remove_file(&leaf).map_err(|_| HaError::Transport)?;
                        } else {
                            let mut bytes = fs::read(&leaf).map_err(|_| HaError::Transport)?;
                            bytes[0] ^= 1;
                            fs::write(&leaf, bytes).map_err(|_| HaError::Transport)?;
                        }
                        actual_checkpoint(&fixture, 0)?;
                        damaged.set(true);
                    }
                    Ok(())
                },
            );
            assert!(damaged.get());
            assert!(
                matches!(
                    result,
                    Ok(NativeV6IngressClosureRead::NeedsOriginalRepair(_))
                ),
                "an independent physical defect cannot be classified as witness-only"
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn fresh_ingress_postgate_ordinary_error_and_expiry_with_progress_never_mint_source() -> TestResult
{
    for expire in [false, true] {
        with_current_committed_closure(|fixture| {
            let selected = fixture.selected(Instant::now() + Duration::from_secs(15))?;
            let read_until = selected.read_index_deadline();
            let interrupted = std::cell::Cell::new(false);
            let result = read_native_v6_fresh_ingress_closure_observed(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &routes()?,
                Arc::clone(&fixture.stores[0]),
                selected,
                &mut |gate| {
                    if gate == 16 {
                        actual_checkpoint(&fixture, 0)?;
                        interrupted.set(true);
                        if expire {
                            thread::sleep(
                                read_until.saturating_duration_since(Instant::now())
                                    + Duration::from_millis(10),
                            );
                        } else {
                            return Err(HaError::Tampered);
                        }
                    }
                    Ok(())
                },
            );
            assert!(interrupted.get());
            assert!(
                result.is_err(),
                "ordinary errors and the old read bound are sticky failures"
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn fresh_ingress_failed_new_quorum_read_cannot_use_old_witness_as_source() -> TestResult {
    with_current_committed_closure(|fixture| {
        let until = Instant::now() + Duration::from_millis(800);
        let selected = fixture.selected(until)?;
        let changed = std::cell::Cell::new(false);
        let result = read_native_v6_fresh_ingress_closure_observed(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &routes()?,
            Arc::clone(&fixture.stores[0]),
            selected,
            &mut |gate| {
                if gate == 1 {
                    actual_checkpoint(&fixture, 0)?;
                    fixture.runtime.block_on(async {
                        let mut peers = fixture.router.peers.write().await;
                        peers.remove(&2);
                        peers.remove(&3);
                    });
                    changed.set(true);
                }
                Ok(())
            },
        );
        fixture.runtime.block_on(async {
            let mut peers = fixture.router.peers.write().await;
            peers.insert(2, fixture.nodes[1].rpc_service());
            peers.insert(3, fixture.nodes[2].rpc_service());
        });
        assert!(changed.get());
        assert!(
            result.is_err(),
            "a failed fresh ReadIndex cannot mint any continuation"
        );
        Ok(())
    })
}

#[test]
fn fresh_ingress_actual_other_store_cannot_continue_selected_read() -> TestResult {
    with_current_committed_closure(|fixture| {
        let selected = fixture.selected(Instant::now() + Duration::from_secs(15))?;
        let result = read_native_v6_fresh_ingress_closure(
            &fixture.nodes[1],
            fixture.runtime.handle(),
            &routes()?,
            Arc::clone(&fixture.stores[1]),
            selected,
        );
        assert!(
            result.is_err(),
            "real follower files do not alias the selected Raft store"
        );
        Ok(())
    })
}

#[test]
fn fresh_ingress_source_cannot_move_to_another_ciphertext_stage_instance() -> TestResult {
    with_current_committed_closure(|fixture| {
        let selected = fixture.selected(Instant::now() + Duration::from_secs(15))?;
        let result = read_native_v6_fresh_ingress_closure_observed(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &routes()?,
            Arc::clone(&fixture.stores[0]),
            selected,
            &mut |gate| {
                if gate == 1 {
                    actual_checkpoint(&fixture, 0)?;
                }
                Ok(())
            },
        )?;
        let NativeV6IngressClosureRead::Superseded(source) = result else {
            return Err("actual checkpoint did not produce the expected opaque observation".into());
        };
        let live = LiveReceivers::start(
            fixture.nodes,
            fixture.runtime.handle(),
            fixture.stores,
            fixture.enrollment,
            fixture.tls,
        )?;
        let transport = live.transport(fixture.tls.clients[&1].clone())?;
        assert!(
            Instant::now()
                < source
                    .original_read_deadline()
                    .min(source.operation_deadline()),
            "the wrong-stage veto must occur while both original bounds remain live"
        );
        assert!(
            source
                .complete(
                    &fixture.nodes[0],
                    fixture.runtime.handle(),
                    &transport,
                    &live.routes,
                    &fixture.stores[1]
                )
                .is_err(),
            "Raft-store equality cannot replace ciphertext-stage identity"
        );
        Ok(())
    })
}

#[test]
fn fresh_ingress_second_actual_publication_is_not_another_reselection() -> TestResult {
    with_current_committed_closure(|fixture| {
        let until = Instant::now() + Duration::from_secs(15);
        let selected = fixture.selected(until)?;
        let mut first_publication = None;
        let result = read_native_v6_fresh_ingress_closure_observed(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &routes()?,
            Arc::clone(&fixture.stores[0]),
            selected,
            &mut |gate| {
                if gate == 1 {
                    first_publication = Some(
                        publish_successor(&fixture, fixture.published, until, (0x87, 0x88))
                            .map_err(|_| HaError::OutcomeUnknown)?,
                    );
                }
                Ok(())
            },
        )?;
        let NativeV6IngressClosureRead::Superseded(source) = result else {
            return Err("actual first publication did not produce opaque observation".into());
        };
        let first = first_publication.ok_or("actual first publication absent")?;
        assert_eq!(source.previous_root(), fixture.published);
        assert_ne!(first.root_digest(), fixture.published.root_digest());
        // A->B produced this actual source. The second, real B->C publication
        // occurs after the no-effects prefix; final strict read cannot reselect.
        let second = publish_successor(&fixture, &first, until, (0x89, 0x8a))?;
        assert_eq!(second.root_digest(), [0x8a; 32]);
        assert!(second.generation() > first.generation());
        let current = fixture.selected(until)?;
        assert_eq!(current.root(), &second);
        let live = LiveReceivers::start(
            fixture.nodes,
            fixture.runtime.handle(),
            fixture.stores,
            fixture.enrollment,
            fixture.tls,
        )?;
        let transport = live.transport(fixture.tls.clients[&1].clone())?;
        assert!(
            Instant::now()
                < source
                    .original_read_deadline()
                    .min(source.operation_deadline()),
            "the second-publication veto must occur before either original bound expires"
        );
        assert!(
            source
                .complete(
                    &fixture.nodes[0],
                    fixture.runtime.handle(),
                    &transport,
                    &live.routes,
                    &fixture.stores[0]
                )
                .is_err()
        );
        Ok(())
    })
}
