//! Real three-voter retained Raft history and original-FD filesystem effects.
//! The parent routing/pins are synthetic. The explicit callback below models
//! only the trusted local-ledger integration boundary; actual authenticated
//! Barrier pending/completion is tested separately in durable-service. These
//! tests do not grant Service Actor, peer capability, TLS or local nv6.hbo GC
//! qualification.
use super::*;
use crate::{
    LocalV6BlobError, NativeV6SharedRetirementError, NativeV6SharedRetirementPlan,
    NativeV6SharedRetirementSelection, RecordObjectRef,
};
use std::io::Write as _;

#[path = "v6_retained_root_process_tests.rs"]
mod retained_roots;

fn blob_path(directory: &std::path::Path, reference: &RecordObjectRef) -> std::path::PathBuf {
    let mut leaf = String::from("v6-");
    crate::append_hex(&mut leaf, &reference.id);
    leaf.push_str(".blob");
    directory.join(leaf)
}

fn manifest_path(directory: &std::path::Path, digest: &[u8; 32]) -> std::path::PathBuf {
    let mut leaf = String::from("v6-closure-");
    crate::append_hex(&mut leaf, digest);
    leaf.push_str(".manifest");
    directory.join(leaf)
}

async fn publish_real(
    node: &ProcessRaftNode,
    store: &LocalV6BlobStage,
    references: &[RecordObjectRef],
    op: u8,
) -> TestResult<crate::NativeV6PublishedRoot> {
    let closure = store.persist_local_closure(references, &mut || Ok(()))?;
    let source = selected(node).await?;
    let mut intent = next_intent(&source, source.enrollment().epoch(), op, op + 1);
    intent.closure_manifest_sha256 = closure.manifest_sha256();
    intent.object_count = closure.object_count() as u64;
    intent.ciphertext_bytes = closure.ciphertext_bytes();
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
    let source = selected(node).await?;
    Ok(node
        .retire_native_v6_obsolete_intents(node.next_production_client_serial().await?, &source, 32)
        .await?)
}

async fn actual_live_store(
    fixture: &EpochFixture,
) -> TestResult<(LocalV6BlobStage, RecordObjectRef)> {
    let directory = fixture.directory.join("1/native-v6-ciphertext");
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let store = LocalV6BlobStage::open_existing(&directory)?;
    let live = store.stage_local(&vec![0x91; 4096])?.reference().clone();
    publish_real(&fixture.nodes[0], &store, std::slice::from_ref(&live), 90).await?;
    // The original epoch fixture's fake closure is not a physical authority.
    // Remove its real metadata through the production command, then actually
    // checkpoint/purge every voter before this test can obtain a full mark.
    let retired = retire_current(&fixture.nodes[0]).await?;
    assert_eq!(retired.retired_intents(), 1);
    fixture.compact_all(retired.receipt().log_index).await?;
    Ok((store, live))
}

async fn fresh_plan<'a>(
    node: &ProcessRaftNode,
    store: &'a LocalV6BlobStage,
) -> TestResult<NativeV6SharedRetirementPlan<'a>> {
    let source = selected(node).await?;
    let exclusive = store.try_native_quiescence()?;
    let retained = node.native_v6_retention_guard(&source).await?;
    Ok(store.prepare_shared_retirement(retained, exclusive, &mut || Ok(()))?)
}

async fn fresh_reconcile<'a>(
    node: &ProcessRaftNode,
    store: &'a LocalV6BlobStage,
    prior: &NativeV6SharedRetirementSelection,
) -> TestResult<NativeV6SharedRetirementPlan<'a>> {
    let source = selected(node).await?;
    let exclusive = store.try_native_quiescence()?;
    let retained = node.native_v6_retention_guard(&source).await?;
    Ok(store.prepare_shared_retirement_reconciliation(
        retained,
        exclusive,
        prior,
        &mut || Ok(()),
    )?)
}

fn same_capsule(actual: &[u8], expected: &[u8]) -> Result<(), LocalV6BlobError> {
    if actual == expected {
        Ok(())
    } else {
        Err(LocalV6BlobError::CorruptOrChanged)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_shared_retirement_original_fd_unlink_and_receipt_hold_real_raft_and_shared_owners()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let (store, live) = actual_live_store(&fixture).await?;
        let directory = fixture.directory.join("1/native-v6-ciphertext");
        let live_bytes = store.read_local(&live)?;
        let orphan = store.stage_local(&vec![0xa2; 4096])?.reference().clone();
        let orphan_manifest =
            store.persist_local_closure(std::slice::from_ref(&orphan), &mut || Ok(()))?;
        let temporary = directory.join(".v6-tmp-71-93");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(b"abandoned exact temporary")?;
        file.sync_all()?;
        drop(file);
        let plan = fresh_plan(&fixture.nodes[0], &store).await?;
        assert_eq!(plan.selection().selected_files(), 3);
        let capsule = plan.selection().encode()?;
        let receipt =
            plan.retire_after_known_ledger(&mut |actual| same_capsule(actual, &capsule))?;
        assert_eq!(receipt.outcome().removed_blobs, 1);
        assert_eq!(receipt.outcome().removed_ciphertext_bytes, 4096);
        assert_eq!(receipt.outcome().removed_manifests, 1);
        assert_eq!(receipt.outcome().removed_temporary_files, 1);
        assert_eq!(receipt.outcome().confirmed_absent_files, 0);
        assert_eq!(receipt.outcome().currently_retained_files, 0);
        assert!(!blob_path(&directory, &orphan).exists());
        assert!(!manifest_path(&directory, &orphan_manifest.manifest_sha256()).exists());
        assert!(!temporary.exists());
        assert_eq!(fs::read(blob_path(&directory, &live))?, live_bytes);
        receipt.verify_completed()?;
        assert!(store.begin_native_operation().is_err());
        assert!(store.try_native_quiescence().is_err());
        assert!(
            tokio::time::timeout(
                Duration::from_millis(25),
                fixture.nodes[0].native_v6_committed_root_read(deadline()),
            )
            .await
            .is_err(),
            "terminal receipt must keep the actual Raft state writer held"
        );
        drop(receipt);
        assert_eq!(store.read_local(&live)?, live_bytes);
        selected(&fixture.nodes[0]).await?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_shared_retirement_retained_log_holds_old_bytes_then_checkpoint_purge_and_cold_progress()
-> TestResult {
    let mut fixture = EpochFixture::create().await?;
    let result = async {
        let (store, first) = actual_live_store(&fixture).await?;
        let directory = fixture.directory.join("1/native-v6-ciphertext");
        let original = selected(&fixture.nodes[0]).await?.root().intent();
        let next = store.stage_local(&vec![0xb3; 8192])?.reference().clone();
        let latest =
            publish_real(&fixture.nodes[0], &store, std::slice::from_ref(&next), 94).await?;
        let retired = retire_current(&fixture.nodes[0]).await?;
        assert_eq!(retired.retired_intents(), 1);
        let plan = fresh_plan(&fixture.nodes[0], &store).await?;
        assert_eq!(
            plan.selection().selected_files(),
            0,
            "metadata retirement alone does not discard retained durable history"
        );
        drop(plan);
        assert!(blob_path(&directory, &first).exists());
        assert!(manifest_path(&directory, &original.closure_manifest_sha256).exists());
        fixture.compact_all(retired.receipt().log_index).await?;
        let plan = fresh_plan(&fixture.nodes[0], &store).await?;
        assert_eq!(plan.selection().selected_files(), 2);
        let capsule = plan.selection().encode()?;
        let receipt =
            plan.retire_after_known_ledger(&mut |actual| same_capsule(actual, &capsule))?;
        assert_eq!(receipt.outcome().removed_blobs, 1);
        assert_eq!(receipt.outcome().removed_manifests, 1);
        receipt.verify_completed()?;
        drop(receipt);
        assert!(!blob_path(&directory, &first).exists());
        assert!(!manifest_path(&directory, &original.closure_manifest_sha256).exists());
        assert_eq!(store.read_local(&next)?, vec![0xb3; 8192]);
        drop(store);
        let leader = fixture.cold_restart().await?;
        let source = selected(&fixture.nodes[leader]).await?;
        assert_eq!(source.root(), &latest);
        for voter in &fixture.nodes {
            let source = selected(voter).await?;
            assert_eq!(source.root(), &latest);
            voter.verify_native_v6_committed_root_read(&source).await?;
        }
        let reopened = LocalV6BlobStage::open_existing(&directory)?;
        assert_eq!(reopened.read_local(&next)?, vec![0xb3; 8192]);
        assert!(!blob_path(&directory, &first).exists());
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_shared_retirement_unpublished_actual_intent_still_protects_its_full_closure()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let (store, live) = actual_live_store(&fixture).await?;
        let future = store.stage_local(&vec![0xc4; 4096])?.reference().clone();
        let closure = store.persist_local_closure(std::slice::from_ref(&future), &mut || Ok(()))?;
        let source = selected(&fixture.nodes[0]).await?;
        let current = source.root().clone();
        let mut intent = next_intent(&source, source.enrollment().epoch(), 96, 97);
        intent.closure_manifest_sha256 = closure.manifest_sha256();
        intent.object_count = closure.object_count() as u64;
        intent.ciphertext_bytes = closure.ciphertext_bytes();
        stage(&fixture.nodes[0], intent).await?;
        let retired = retire_current(&fixture.nodes[0]).await?;
        assert_eq!(retired.retired_intents(), 0);
        fixture.compact_all(retired.receipt().log_index).await?;
        let fresh = selected(&fixture.nodes[0]).await?;
        assert_eq!(fresh.root(), &current);
        let exclusive = store.try_native_quiescence()?;
        let retained = fixture.nodes[0].native_v6_retention_guard(&fresh).await?;
        assert!(retained.retained_intents().any(|value| *value == intent));
        let plan = store.prepare_shared_retirement(retained, exclusive, &mut || Ok(()))?;
        assert_eq!(plan.selection().selected_files(), 0);
        drop(plan);
        assert_eq!(store.read_local(&live)?, vec![0x91; 4096]);
        assert_eq!(store.read_local(&future)?, vec![0xc4; 4096]);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_shared_retirement_unknown_unlink_gets_new_absence_barrier_without_replaying_old_plan()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let (store, live) = actual_live_store(&fixture).await?;
        let directory = fixture.directory.join("1/native-v6-ciphertext");
        let orphan = store.stage_local(&vec![0xd5; 4096])?.reference().clone();
        let orphan_path = blob_path(&directory, &orphan);
        let plan = fresh_plan(&fixture.nodes[0], &store).await?;
        assert_eq!(plan.selection().selected_files(), 1);
        let capsule = plan.selection().encode()?;
        let original = plan.retire_after_known_ledger(&mut |actual| {
            same_capsule(actual, &capsule)?;
            if orphan_path.exists() {
                Ok(())
            } else {
                Err(LocalV6BlobError::CorruptOrChanged)
            }
        });
        assert!(matches!(
            original,
            Err(NativeV6SharedRetirementError::OutcomeUnknown(_))
        ));
        assert!(
            !orphan_path.exists(),
            "failure was injected only after the one real unlink"
        );
        let old_data = NativeV6SharedRetirementSelection::decode_for_reconciliation(&capsule)?;
        let plan = fresh_reconcile(&fixture.nodes[0], &store, &old_data).await?;
        assert!(plan.selection().is_reconciliation());
        assert_eq!(
            plan.selection().predecessor_selection_digest(),
            Some(old_data.digest()?)
        );
        let new_capsule = plan.selection().encode()?;
        let current =
            plan.retire_after_known_ledger(&mut |actual| same_capsule(actual, &new_capsule))?;
        assert_eq!(current.outcome().removed_blobs, 0);
        assert_eq!(current.outcome().confirmed_absent_files, 1);
        assert_eq!(current.outcome().currently_retained_files, 0);
        current.verify_completed()?;
        drop(current);
        assert_eq!(store.read_local(&live)?, vec![0x91; 4096]);
        // The new observation has no authority to revise the original error.
        assert!(matches!(
            original,
            Err(NativeV6SharedRetirementError::OutcomeUnknown(_))
        ));
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_shared_retirement_fresh_reconcile_holds_former_candidate_that_is_now_live()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let (store, live) = actual_live_store(&fixture).await?;
        let candidate = store.stage_local(&vec![0xe6; 4096])?.reference().clone();
        let plan = fresh_plan(&fixture.nodes[0], &store).await?;
        assert_eq!(plan.selection().selected_files(), 1);
        let old_data = NativeV6SharedRetirementSelection::decode_for_reconciliation(
            &plan.selection().encode()?,
        )?;
        let original =
            plan.retire_after_known_ledger(&mut |_| Err(LocalV6BlobError::CorruptOrChanged));
        assert!(matches!(
            original,
            Err(NativeV6SharedRetirementError::BeforePhysical(_))
        ));
        let latest = publish_real(
            &fixture.nodes[0],
            &store,
            &[live.clone(), candidate.clone()],
            98,
        )
        .await?;
        let plan = fresh_reconcile(&fixture.nodes[0], &store, &old_data).await?;
        let capsule = plan.selection().encode()?;
        let current =
            plan.retire_after_known_ledger(&mut |actual| same_capsule(actual, &capsule))?;
        assert_eq!(current.outcome().removed_blobs, 0);
        assert_eq!(current.outcome().confirmed_absent_files, 0);
        assert_eq!(current.outcome().currently_retained_files, 1);
        current.verify_completed()?;
        drop(current);
        assert_eq!(store.read_local(&candidate)?, vec![0xe6; 4096]);
        assert_eq!(selected(&fixture.nodes[0]).await?.root(), &latest);
        assert!(matches!(
            original,
            Err(NativeV6SharedRetirementError::BeforePhysical(_))
        ));
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_shared_retirement_missing_live_closure_unknown_leaf_and_changed_fd_fail_closed()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let (store, live) = actual_live_store(&fixture).await?;
        let directory = fixture.directory.join("1/native-v6-ciphertext");
        let live_intent = selected(&fixture.nodes[0]).await?.root().intent();
        let manifest = manifest_path(&directory, &live_intent.closure_manifest_sha256);
        let saved_manifest = fixture.directory.join("held-exact-live-manifest");
        fs::rename(&manifest, &saved_manifest)?;
        assert!(fresh_plan(&fixture.nodes[0], &store).await.is_err());
        fs::rename(&saved_manifest, &manifest)?;
        let foreign = directory.join("unowned-layout.bin");
        fs::write(&foreign, b"must remain")?;
        assert!(fresh_plan(&fixture.nodes[0], &store).await.is_err());
        assert_eq!(fs::read(&foreign)?, b"must remain");
        fs::remove_file(&foreign)?;
        let orphan = store.stage_local(&vec![0xf7; 4096])?.reference().clone();
        let path = blob_path(&directory, &orphan);
        let plan = fresh_plan(&fixture.nodes[0], &store).await?;
        let capsule = plan.selection().encode()?;
        let saved_orphan = fixture.directory.join("held-original-candidate");
        fs::rename(&path, &saved_orphan)?;
        fs::write(&path, vec![0xf7; 4096])?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(plan.verify_prepared().is_err());
        let mut called = 0;
        let result = plan.retire_after_known_ledger(&mut |actual| {
            called += 1;
            same_capsule(actual, &capsule)
        });
        assert!(matches!(
            result,
            Err(NativeV6SharedRetirementError::BeforePhysical(_))
        ));
        assert_eq!(called, 0);
        assert_eq!(fs::read(&path)?, vec![0xf7; 4096]);
        assert_eq!(fs::read(&saved_orphan)?, vec![0xf7; 4096]);
        assert_eq!(store.read_local(&live)?, vec![0x91; 4096]);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_shared_retirement_original_actor_veto_after_first_cipher_read_stops_before_second_read_or_unlink()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let (store, live) = actual_live_store(&fixture).await?;
        let directory = fixture.directory.join("1/native-v6-ciphertext");
        let orphan = store
            .stage_local(&vec![0xb7; 192 * 1024])?
            .reference()
            .clone();
        let old = fs::read(blob_path(&directory, &orphan))?;
        let plan = fresh_plan(&fixture.nodes[0], &store).await?;
        assert_eq!(plan.selection().selected_files(), 1);
        let capsule = plan.selection().encode()?;
        let revoked = std::rc::Rc::new(std::cell::Cell::new(false));
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let observation = crate::v6_replica_blobs::observe_shared_retirement_reads(
            revoked.clone(),
            reads.clone(),
        )?;
        let outcome = plan.retire_after_known_ledger(&mut |actual| {
            same_capsule(actual, &capsule)?;
            if revoked.get() {
                return Err(LocalV6BlobError::CorruptOrChanged);
            }
            Ok(())
        });
        drop(observation);
        assert!(outcome.is_err());
        assert!(revoked.get());
        assert_eq!(
            reads.get(),
            1,
            "revoked original Actor must stop immediately after the first actual bounded read"
        );
        assert_eq!(
            fs::read(blob_path(&directory, &orphan))?,
            old,
            "no unlink or byte replacement after original gate veto"
        );
        assert_eq!(store.read_local(&live)?.len(), 4096);
        selected(&fixture.nodes[0]).await?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
