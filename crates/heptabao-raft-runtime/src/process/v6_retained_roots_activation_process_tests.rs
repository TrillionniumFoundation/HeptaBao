//! Real durable three-voter Apply/checkpoint/replay under the parent's
//! synthetic router. Torn persisted-journal images are explicit crash-image
//! injection on stopped fixtures, not a claim of physical SIGKILL or TLS.
use super::*;

async fn publish_epoch(
    node: &ProcessRaftNode,
    operation: u8,
) -> TestResult<crate::NativeV6PublishedRoot> {
    let current = selected(node).await?;
    let intent = next_intent(
        &current,
        current.enrollment().epoch() + 1,
        operation,
        operation + 1,
    );
    let initial = begin(node, &current, &intent).await?;
    let staged = stage(node, intent).await?;
    let exact = pending(node, &initial).await?;
    Ok(node
        .publish_native_v6_epoch_restore(
            node.next_production_client_serial().await?,
            &exact,
            &staged,
            vec![operation; 64],
        )
        .await?)
}

async fn all_applied(fixture: &EpochFixture, index: u64) -> TestResult {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if fixture.nodes.iter().all(|node| {
                node.raft
                    .metrics()
                    .borrow_watched()
                    .last_applied
                    .is_some_and(|log| log.index >= index)
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_provenance_actual_activation_unknown_cold_and_two_epoch_checkpoint_union()
-> TestResult {
    let mut fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        retire_current(node).await?;
        let prepared = node
            .prepare_native_v6_retained_root_activation(selected(node).await?)
            .await?;
        let capsule = prepared
            .recovery()
            .encode()
            .map_err(crate::RaftRuntimeError::RecordRejected)?;
        {
            let receipt = node
                .submit_native_v6_prepared_intent_retirement(prepared)
                .await?;
            all_applied(&fixture, receipt.log_index).await?;
        }
        // Ending this ACK's scope models a lost observation only; the following
        // cold reconciliation cannot reconstruct a prepared command from it.
        let leader = fixture.cold_restart().await?;
        let node = &fixture.nodes[leader];
        let data = crate::NativeV6IntentRetirementRecovery::decode_for_reconciliation(&capsule)
            .map_err(crate::RaftRuntimeError::RecordRejected)?;
        let before = node
            .state_machine
            .get_state_machine()
            .await
            .snapshot_bytes()?;
        {
            let observed = node
                .observe_native_v6_intent_retirement(selected(node).await?, &data)
                .await?;
            assert_eq!(
                observed.resolution(),
                crate::NativeV6IntentRetirementResolution::EffectsObserved
            );
            node.verify_native_v6_intent_retirement_observation(&observed)
                .await?;
        }
        assert_eq!(
            node.state_machine
                .get_state_machine()
                .await
                .snapshot_bytes()?,
            before
        );

        let source_one = selected(node).await?.root().clone();
        let target_one = publish_epoch(node, 101).await?;
        let source_two = publish_next(node, 103).await?;
        let target_two = publish_epoch(node, 105).await?;
        let current = publish_next(node, 107).await?;
        let retired = retire_current(node).await?;
        assert_eq!(
            retired.retired_intents(),
            0,
            "both source and target of each transition remain protected"
        );
        fixture.compact_all(retired.receipt().log_index).await?;
        let leader = fixture.cold_restart().await?;
        for voter in &fixture.nodes {
            let state = voter.state_machine.get_state_machine().await;
            assert_eq!(state.records_format_version(), Some(7));
            let root = state.v6_root.as_ref().ok_or("cold root")?;
            assert_eq!(root.restore_lineage.len(), 2);
            for (index, source, target) in
                [(0, &source_one, &target_one), (1, &source_two, &target_two)]
            {
                let step = &root.restore_lineage[index];
                let retained = step.retained_roots.as_ref().ok_or("cold provenance")?;
                assert_eq!(retained.source.envelope.sealed(), source.sealed_root());
                assert_eq!(retained.target.envelope.sealed(), target.sealed_root());
                assert_eq!(
                    step.pending.command.source.publication_log,
                    source.publication_log_id()
                );
                assert_eq!(step.publication_log, target.publication_log_id());
            }
            assert_eq!(selected(voter).await?.root(), &current);
        }
        let node = &fixture.nodes[leader];
        let actual = selected(node).await?;
        let guard = node.native_v6_retention_guard(&actual).await?;
        let catalog = guard.retained_root_catalog()?;
        assert_eq!(catalog.roots().len(), 5);
        for expected in [&source_one, &target_one, &source_two, &target_two, &current] {
            let entry = catalog
                .roots()
                .find(|entry| entry.publication_log_id() == expected.publication_log_id())
                .ok_or("protected source or target missing from cold actual catalog")?;
            assert_eq!(entry.intent(), expected.intent());
            assert_eq!(entry.sealed_root(), expected.sealed_root());
            entry.verify()?;
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_provenance_actual_snapshot_install_cold_floor_rejects_legacy_and_stripped_state()
-> TestResult {
    use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
    use std::io::Cursor;

    let fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        retire_current(node).await?;
        let mut source = node.state_machine.clone();
        let legacy = source.build_snapshot().await?;
        let legacy_bytes = legacy.snapshot.into_inner();
        assert_eq!(
            crate::StateMachine::from_snapshot(&legacy_bytes)?.records_format_version(),
            Some(6)
        );

        // Positive control: the same actual legacy snapshot installs and cold
        // opens on a fresh destination before that destination receives floor7.
        let directory = fixture.directory.join("retained-root-snapshot-target");
        let mut target = crate::store::DurableStateMachine::create(&directory)?;
        target
            .install_snapshot(&legacy.meta, Cursor::new(legacy_bytes.clone()))
            .await?;
        drop(target);
        let mut target = crate::store::DurableStateMachine::open_existing(&directory)?;
        assert_eq!(
            target.get_state_machine().await.records_format_version(),
            Some(6)
        );

        activate_retained_roots(node).await?;
        let active = source.build_snapshot().await?;
        let active_bytes = active.snapshot.into_inner();
        target
            .install_snapshot(&active.meta, Cursor::new(active_bytes.clone()))
            .await?;
        drop(target);
        let mut target = crate::store::DurableStateMachine::open_existing(&directory)?;
        assert_eq!(
            target.get_state_machine().await.records_format_version(),
            Some(7)
        );
        let generation = target.generation().await;
        let state_before = target.get_state_machine().await.snapshot_bytes()?;
        let bundle_before = fs::read(target.state_path())?;
        let journal_path = target.state_path().with_file_name("state-machine.journal");
        let journal_before = fs::read(&journal_path)?;

        assert!(
            target
                .install_snapshot(&legacy.meta, Cursor::new(legacy_bytes))
                .await
                .is_err()
        );
        // Removing the flag from a genuine current snapshot can produce legal
        // legacy DATA when lineage is empty. Even its unchanged current log
        // metadata cannot erase an already persisted destination reader floor.
        let mut stripped = crate::StateMachine::from_snapshot(&active_bytes)?;
        stripped.v6_retained_root_protocol = None;
        assert_eq!(stripped.records_format_version(), Some(6));
        let stripped = stripped.snapshot_bytes()?;
        assert!(crate::StateMachine::from_snapshot(&stripped).is_ok());
        assert!(
            target
                .install_snapshot(&active.meta, Cursor::new(stripped))
                .await
                .is_err()
        );
        assert_eq!(target.generation().await, generation);
        assert_eq!(
            target.get_state_machine().await.snapshot_bytes()?,
            state_before
        );
        assert_eq!(fs::read(target.state_path())?, bundle_before);
        assert_eq!(fs::read(&journal_path)?, journal_before);
        drop(target);
        let cold = crate::store::DurableStateMachine::open_existing(&directory)?;
        assert_eq!(
            cold.get_state_machine().await.records_format_version(),
            Some(7)
        );
        assert_eq!(
            cold.get_state_machine().await.snapshot_bytes()?,
            state_before
        );
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_provenance_actual_torn_publication_journal_replays_both_roots_atomically()
-> TestResult {
    let mut fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        retire_current(node).await?;
        activate_retained_roots(node).await?;
        let original = selected(node).await?;
        let old_root = original.root().clone();
        let intent = next_intent(&original, original.enrollment().epoch() + 1, 111, 112);
        let initial = begin(node, &original, &intent).await?;
        let staged = stage(node, intent).await?;
        // A real checkpoint owns the active source plus exact staged target.
        // Only the later publication frame will be cut; its full committed
        // Raft log remains available for the actual recovery path.
        fixture.compact_all(staged.log_index).await?;
        let prefixes: Vec<_> = fixture
            .nodes
            .iter()
            .map(|voter| {
                let path = voter
                    .state_machine
                    .state_path()
                    .with_file_name("state-machine.journal");
                Ok::<_, std::io::Error>((path.clone(), fs::read(path)?))
            })
            .collect::<Result<_, _>>()?;
        let exact = pending(node, &initial).await?;
        assert!(initial.same_transition(&exact));
        let published = node
            .publish_native_v6_epoch_restore(
                node.next_production_client_serial().await?,
                &exact,
                &staged,
                vec![0x8d; 64],
            )
            .await?;
        all_applied(&fixture, published.publication_log_id().index).await?;
        let mut images = Vec::new();
        for (path, prefix) in prefixes {
            let full = fs::read(&path)?;
            assert!(full.starts_with(&prefix) && full.len() > prefix.len() + 8);
            images.push((path, prefix, full));
        }
        for voter in &fixture.nodes {
            voter.raft.shutdown().await?;
        }
        fixture.nodes.clear();
        fixture.router.peers.write().await.clear();
        for (member, (path, prefix, full)) in images.iter().enumerate() {
            let cut = match member {
                0 => prefix.len(),
                1 => prefix.len() + 4,
                _ => full.len() - 1,
            };
            let file = fs::OpenOptions::new().write(true).open(path)?;
            file.set_len(cut as u64)?;
            file.sync_all()?;
            assert_eq!(fs::read(path)?, full[..cut]);
        }
        let leader = fixture.cold_restart().await?;
        all_applied(&fixture, published.publication_log_id().index).await?;
        for voter in &fixture.nodes {
            let read = selected(voter).await?;
            assert_eq!(read.root(), &published);
            let state = voter.state_machine.get_state_machine().await;
            assert_eq!(state.records_format_version(), Some(7));
            assert!(state.v6_pending_epoch_restore.is_none());
            let step = &state.v6_root.as_ref().ok_or("root")?.restore_lineage[0];
            let retained = step.retained_roots.as_ref().ok_or("replayed roots")?;
            assert_eq!(retained.source.envelope.sealed(), old_root.sealed_root());
            assert_eq!(retained.target.envelope.sealed(), published.sealed_root());
            assert_eq!(
                step.pending.command.source.publication_log,
                old_root.publication_log_id()
            );
            assert_eq!(step.publication_log, published.publication_log_id());
        }
        let node = &fixture.nodes[leader];
        let actual = selected(node).await?;
        let guard = node.native_v6_retention_guard(&actual).await?;
        assert_eq!(guard.retained_root_catalog()?.roots().len(), 2);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
