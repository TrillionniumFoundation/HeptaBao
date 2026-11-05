//! Actual durable three-voter metadata protocol and retention inventory.
//! The parent router/pins are synthetic. No physical TLS or GC claim follows.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_recovery_actual_prepare_commit_cold_observation_never_replays()
-> TestResult {
    let mut fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let latest = publish_next(node, 81).await?;
        let prepared = node
            .prepare_native_v6_intent_retirement(selected(node).await?, 32)
            .await?;
        let capsule = prepared
            .recovery()
            .encode()
            .map_err(crate::RaftRuntimeError::RecordRejected)?;
        let selected_count = prepared.recovery().selected_intents();
        assert_eq!(selected_count, 1);
        let command_digest = prepared
            .recovery()
            .command_digest()
            .map_err(crate::RaftRuntimeError::RecordRejected)?;
        {
            let actual = node
                .submit_native_v6_prepared_intent_retirement(prepared)
                .await?;
            assert_eq!(actual.envelope_digest, command_digest);
        }
        // The known ACK ends its lexical scope above. Cold recovery has only
        // authenticated ledger DATA and a new real quorum as its inputs.
        let leader = fixture.cold_restart().await?;
        let data = crate::NativeV6IntentRetirementRecovery::decode_for_reconciliation(&capsule)
            .map_err(crate::RaftRuntimeError::RecordRejected)?;
        let node = &fixture.nodes[leader];
        let observation = node
            .observe_native_v6_intent_retirement(selected(node).await?, &data)
            .await?;
        assert_eq!(
            observation.resolution(),
            crate::NativeV6IntentRetirementResolution::EffectsObserved
        );
        assert_eq!(observation.current_root(), &latest);
        assert_eq!(
            observation.capsule_digest(),
            data.capsule_digest()
                .map_err(crate::RaftRuntimeError::RecordRejected)?
        );
        node.verify_native_v6_intent_retirement_observation(&observation)
            .await?;
        let newer = publish_next(node, 83).await?;
        assert!(
            node.verify_native_v6_intent_retirement_observation(&observation)
                .await
                .is_err()
        );
        let fresh = node
            .observe_native_v6_intent_retirement(selected(node).await?, &data)
            .await?;
        assert_eq!(
            fresh.resolution(),
            crate::NativeV6IntentRetirementResolution::SupersededByNewRoot
        );
        assert_eq!(fresh.current_root(), &newer);
        node.verify_native_v6_intent_retirement_observation(&fresh)
            .await?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_recovery_stale_prepared_command_is_consumed_without_submission()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        publish_next(node, 85).await?;
        let prepared = node
            .prepare_native_v6_intent_retirement(selected(node).await?, 32)
            .await?;
        let capsule = prepared
            .recovery()
            .encode()
            .map_err(crate::RaftRuntimeError::RecordRejected)?;
        let newer = publish_next(node, 87).await?;
        assert!(
            node.submit_native_v6_prepared_intent_retirement(prepared)
                .await
                .is_err()
        );
        let data = crate::NativeV6IntentRetirementRecovery::decode_for_reconciliation(&capsule)
            .map_err(crate::RaftRuntimeError::RecordRejected)?;
        let fresh = node
            .observe_native_v6_intent_retirement(selected(node).await?, &data)
            .await?;
        assert_eq!(
            fresh.resolution(),
            crate::NativeV6IntentRetirementResolution::SupersededByNewRoot
        );
        assert_eq!(fresh.current_root(), &newer);
        assert_ne!(
            node.state_machine
                .get_state_machine()
                .await
                .records_format_version(),
            Some(6)
        );
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

async fn publish_next(node: &ProcessRaftNode, op: u8) -> TestResult<crate::NativeV6PublishedRoot> {
    let source = selected(node).await?;
    let intent = next_intent(&source, source.enrollment().epoch(), op, op + 1);
    let staged = stage(node, intent).await?;
    Ok(node
        .publish_native_v6_root(
            node.next_production_client_serial().await?,
            &intent,
            &staged,
            source.enrollment(),
            vec![0x55; 64],
            deadline(),
        )
        .await?)
}
async fn retire_current(
    node: &ProcessRaftNode,
) -> TestResult<crate::NativeV6IntentRetirementOutcome> {
    let current = selected(node).await?;
    Ok(node
        .retire_native_v6_obsolete_intents(
            node.next_production_client_serial().await?,
            &current,
            32,
        )
        .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_real_raft_keeps_old_durable_roots_until_checkpoint_and_purge()
-> TestResult {
    let mut fixture = EpochFixture::create().await?;
    let result = async {
        let first = selected(&fixture.nodes[0]).await?.root().intent();
        let latest = publish_next(&fixture.nodes[0], 40).await?;
        let completed = retire_current(&fixture.nodes[0]).await?;
        assert_eq!(completed.retired_intents(), 1);
        let source = selected(&fixture.nodes[0]).await?;
        assert_eq!(source.root(), &latest);
        let guard = fixture.nodes[0].native_v6_retention_guard(&source).await?;
        assert!(
            guard.retained_intents().any(|intent| *intent == first),
            "retired metadata is still referenced by actual retained durable history"
        );
        assert!(
            guard
                .retained_intents()
                .any(|intent| *intent == latest.intent())
        );
        drop(guard);
        fixture.compact_all(completed.receipt().log_index).await?;
        let source = selected(&fixture.nodes[0]).await?;
        let guard = fixture.nodes[0].native_v6_retention_guard(&source).await?;
        assert!(
            !guard.retained_intents().any(|intent| *intent == first),
            "confirmed checkpoint and purge must make real progress"
        );
        assert_eq!(guard.retained_intents().len(), 1);
        drop(guard);
        let leader = fixture.cold_restart().await?;
        for voter in &fixture.nodes {
            let read = selected(voter).await?;
            assert_eq!(read.root(), &latest);
            voter.verify_native_v6_committed_root_read(&read).await?;
            let state = voter.state_machine.get_state_machine().await;
            assert_eq!(state.records_format_version(), Some(6));
            assert!(
                state
                    .v6_intent_log_id(
                        &SealedRecordObject::new_native_v6_commit_intent(first)?
                            .reference()
                            .id
                    )
                    .is_none()
            );
        }
        let post_cold = publish_next(&fixture.nodes[leader], 42).await?;
        assert_eq!(post_cold.generation(), latest.generation() + 1);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_real_raft_preserves_epoch_lineage_after_retirement_and_cold() -> TestResult
{
    let mut fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let source = selected(node).await?;
        let old_intent = source.root().intent();
        let intent = next_intent(&source, 8, 50, 51);
        let initial = begin(node, &source, &intent).await?;
        let staged = stage(node, intent).await?;
        let sealed = pending(node, &initial).await?;
        let restored = node
            .publish_native_v6_epoch_restore(
                node.next_production_client_serial().await?,
                &sealed,
                &staged,
                vec![0x66; 64],
            )
            .await?;
        let latest = publish_next(node, 52).await?;
        let completed = retire_current(node).await?;
        // The old source, exact restore target and latest current root remain.
        assert_eq!(completed.retired_intents(), 0);
        fixture.compact_all(completed.receipt().log_index).await?;
        let source = selected(node).await?;
        let guard = node.native_v6_retention_guard(&source).await?;
        assert_eq!(guard.retained_intents().len(), 3);
        assert!(guard.retained_root_catalog().is_err(),
            "epoch lineage retains old intents but no old sealed root after real checkpoint/purge; local barriers must HOLD");
        assert!(guard.retained_intents().any(|value| *value == old_intent));
        assert!(
            guard
                .retained_intents()
                .any(|value| *value == restored.intent())
        );
        assert!(
            guard
                .retained_intents()
                .any(|value| *value == latest.intent())
        );
        drop(guard);
        let leader = fixture.cold_restart().await?;
        let read = selected(&fixture.nodes[leader]).await?;
        assert_eq!(read.root().epoch_transitions().len(), 1);
        assert_eq!(read.enrollment().epoch(), 8);
        let guard = fixture.nodes[leader]
            .native_v6_retention_guard(&read)
            .await?;
        assert_eq!(guard.retained_intents().len(), 3);
        assert!(guard.retained_root_catalog().is_err(),
            "cold reopen cannot reconstruct a historical sealed root from lineage tuples");
        drop(guard);
        let unchanged = fixture.nodes[leader].state_machine.get_state_machine().await.snapshot_bytes()?;
        assert!(fixture.nodes[leader]
            .prepare_native_v6_retained_root_activation(selected(&fixture.nodes[leader]).await?)
            .await.is_err(), "explicit actual activation cannot backfill legacy epoch provenance");
        assert_eq!(fixture.nodes[leader].state_machine.get_state_machine().await.snapshot_bytes()?, unchanged);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_real_guard_rejects_previous_artifact_and_foreign_blob_directory()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        retire_current(node).await?;
        let extra = fixture
            .directory
            .join("1/state-machine/.state-bundle.bin.owned.previous");
        fs::write(&extra, b"not an adopted checkpoint")?;
        let before = fs::read(&extra)?;
        let source = selected(node).await?;
        assert!(node.native_v6_retention_guard(&source).await.is_err());
        assert_eq!(
            fs::read(&extra)?,
            before,
            "inventory never repairs or removes retained history"
        );
        fs::remove_file(&extra)?;
        let source = selected(node).await?;
        let guard = node.native_v6_retention_guard(&source).await?;
        let correct_dir = fixture.directory.join("1/native-v6-ciphertext");
        let foreign_dir = fixture.directory.join("foreign-native-v6-ciphertext");
        for directory in [&correct_dir, &foreign_dir] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let correct = LocalV6BlobStage::open_existing(&correct_dir)?;
        let foreign = LocalV6BlobStage::open_existing(&foreign_dir)?;
        let correct_owner = correct.try_native_quiescence()?;
        let foreign_owner = foreign.try_native_quiescence()?;
        correct.verify_retention_ownership(&guard, &correct_owner)?;
        assert!(
            foreign
                .verify_retention_ownership(&guard, &foreign_owner)
                .is_err()
        );
        assert!(
            correct
                .verify_retention_ownership(&guard, &foreign_owner)
                .is_err()
        );
        drop(guard);
        drop(correct_owner);
        drop(foreign_owner);
        drop(correct);
        drop(foreign);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_local_catalog_unpublished_intent_holds_until_real_retire_checkpoint_purge()
-> TestResult {
    let mut fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        retire_current(node).await?;
        activate_retained_roots(node).await?;
        let source = selected(node).await?;
        let staged_only = next_intent(&source, source.enrollment().epoch(), 91, 92);
        stage(node, staged_only).await?;
        let current = selected(node).await?;
        let guard = node.native_v6_retention_guard(&current).await?;
        assert!(
            guard
                .retained_intents()
                .any(|intent| *intent == staged_only)
        );
        assert!(
            guard.retained_root_catalog().is_err(),
            "an intent/manifest without sealed canonical root cannot grant a local locator union"
        );
        drop(guard);
        publish_next(node, 93).await?;
        let latest = publish_next(node, 95).await?;
        let retired = retire_current(node).await?;
        let current = selected(node).await?;
        let guard = node.native_v6_retention_guard(&current).await?;
        assert!(
            guard
                .retained_intents()
                .any(|intent| *intent == staged_only),
            "metadata retirement alone does not erase real durable history"
        );
        assert!(guard.retained_root_catalog().is_err());
        drop(guard);
        fixture.compact_all(retired.receipt().log_index).await?;
        let current = selected(node).await?;
        let guard = node.native_v6_retention_guard(&current).await?;
        {
            let catalog = guard.retained_root_catalog()?;
            assert_eq!(catalog.roots().len(), 1);
            for data in catalog.roots() {
                data.verify()?;
                assert_eq!(data.intent(), latest.intent());
                assert_eq!(data.publication_log_id(), latest.publication_log_id());
                assert_eq!(data.intent_log_id(), latest.intent_log_id());
                assert_eq!(data.enrollment_digest(), latest.enrollment_digest());
                assert_eq!(data.sealed_root(), latest.sealed_root());
            }
            let fingerprint = catalog.fingerprint()?;
            assert_ne!(fingerprint, [0; 32]);
        }
        drop(guard);
        let leader = fixture.cold_restart().await?;
        let source = selected(&fixture.nodes[leader]).await?;
        let guard = fixture.nodes[leader]
            .native_v6_retention_guard(&source)
            .await?;
        let catalog = guard.retained_root_catalog()?;
        assert_eq!(catalog.roots().len(), 1);
        for data in catalog.roots() {
            assert_eq!(data.intent(), latest.intent());
            data.verify()?;
        }
        // Fingerprint includes actual selected enrollment/log owners. Cold
        // equality is not a requirement or a substitute for new guard custody.
        catalog.verify()?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

pub(super) async fn activate_retained_roots(node: &ProcessRaftNode) -> TestResult<CommitReceipt> {
    let prepared = node
        .prepare_native_v6_retained_root_activation(selected(node).await?)
        .await?;
    assert!(prepared.recovery().activates_retained_roots());
    let receipt = node
        .submit_native_v6_prepared_intent_retirement(prepared)
        .await?;
    assert_eq!(
        node.state_machine
            .get_state_machine()
            .await
            .records_format_version(),
        Some(7)
    );
    Ok(receipt)
}

#[path = "v6_retained_roots_activation_process_tests.rs"]
mod roots_activation_tests;
