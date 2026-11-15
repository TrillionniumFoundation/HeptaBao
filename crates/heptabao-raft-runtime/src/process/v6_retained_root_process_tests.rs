//! Actual retained log/state writers, descriptor-bound ciphertext and cold
//! owners. The parent's synthetic transport is not physical TLS/Service proof.
use super::*;
use std::cell::Cell;
use std::rc::Rc;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_local_selected_reader_holds_exact_owners_and_cold_reopens() -> TestResult
{
    let mut fixture = EpochFixture::create().await?;
    let result = async {
        let (store, live) = actual_live_store(&fixture).await?;
        super::super::retention_tests::activate_retained_roots(&fixture.nodes[0]).await?;
        let original = store.read_local(&live)?;
        let orphan = store.stage_local(&vec![0xc7; 8192])?.reference().clone();
        let source = selected(&fixture.nodes[0]).await?;
        {
            let exclusive = store.try_native_quiescence()?;
            let guard = fixture.nodes[0].native_v6_retention_guard(&source).await?;
            let catalog = guard.retained_root_catalog()?;
            assert_eq!(catalog.roots().len(), 1);
            let root = catalog.roots().next().ok_or("selected root")?;
            assert_eq!(
                root.publication_log_id(),
                source.root().publication_log_id()
            );
            let closure = store.reopen_retained_root_closure(root, &exclusive, &mut || Ok(()))?;
            assert_eq!(closure.references(), std::slice::from_ref(&live));
            assert_eq!(closure.read_local(&live, &mut || Ok(()))?, original);
            assert!(closure.read_local(&orphan, &mut || Ok(())).is_err());
            assert!(store.read_local(&live).is_err());
            assert!(store.begin_native_operation().is_err());

            // A real payload read occurs, then the exact same caller gate denies
            // delivery. The selected reader must not return that plaintext/cipher
            // value or continue to a second read after the late denial.
            let revoked = Rc::new(Cell::new(false));
            let reads = Rc::new(Cell::new(0));
            let observation = crate::v6_replica_blobs::observe_shared_retirement_reads(
                revoked.clone(),
                reads.clone(),
            )?;
            let read = closure.read_local(&live, &mut || {
                if revoked.get() {
                    Err(LocalV6BlobError::CorruptOrChanged)
                } else {
                    Ok(())
                }
            });
            drop(observation);
            assert!(read.is_err());
            assert_eq!(reads.get(), 1);
            closure.verify()?;
        }
        assert_eq!(store.read_local(&live)?, original);
        drop(store);

        let leader = fixture.cold_restart().await?;
        if leader != 0 {
            fixture.nodes[leader].transfer_leadership(1).await?;
            fixture.nodes[0]
                .raft
                .wait(Some(Duration::from_secs(7)))
                .metrics(
                    |metrics| metrics.current_leader == Some(1),
                    "cold original retained-closure owner",
                )
                .await?;
            fixture.nodes[0].ensure_linearizable().await?;
        }
        let directory = fixture.directory.join("1/native-v6-ciphertext");
        let store = LocalV6BlobStage::open_existing(&directory)?;
        let source = selected(&fixture.nodes[0]).await?;
        let exclusive = store.try_native_quiescence()?;
        let guard = fixture.nodes[0].native_v6_retention_guard(&source).await?;
        let catalog = guard.retained_root_catalog()?;
        let closure = store.reopen_retained_root_closure(
            catalog.roots().next().ok_or("cold root")?,
            &exclusive,
            &mut || Ok(()),
        )?;
        assert_eq!(closure.read_local(&live, &mut || Ok(()))?, original);
        assert!(closure.read_local(&orphan, &mut || Ok(())).is_err());
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_retention_local_selected_reader_rejects_foreign_owner_and_replaced_manifest()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let (store, live) = actual_live_store(&fixture).await?;
        super::super::retention_tests::activate_retained_roots(&fixture.nodes[0]).await?;
        let directory = fixture.directory.join("1/native-v6-ciphertext");
        let foreign_directory = fixture.directory.join("2/native-v6-ciphertext");
        fs::create_dir(&foreign_directory)?;
        fs::set_permissions(&foreign_directory, fs::Permissions::from_mode(0o700))?;
        let foreign = LocalV6BlobStage::open_existing(&foreign_directory)?;
        let wrong_owner = foreign.try_native_quiescence()?;
        let source = selected(&fixture.nodes[0]).await?;
        let exclusive = store.try_native_quiescence()?;
        let guard = fixture.nodes[0].native_v6_retention_guard(&source).await?;
        let catalog = guard.retained_root_catalog()?;
        assert!(
            store
                .reopen_retained_root_closure(
                    catalog.roots().next().ok_or("root")?,
                    &wrong_owner,
                    &mut || Ok(())
                )
                .is_err()
        );
        assert!(
            foreign
                .reopen_retained_root_closure(
                    catalog.roots().next().ok_or("root")?,
                    &wrong_owner,
                    &mut || Ok(())
                )
                .is_err()
        );
        let closure = store.reopen_retained_root_closure(
            catalog.roots().next().ok_or("root")?,
            &exclusive,
            &mut || Ok(()),
        )?;
        let manifest = manifest_path(&directory, &source.root().intent().closure_manifest_sha256);
        let saved = directory.join("unexpected-saved-retained-manifest");
        let original = fs::read(&manifest)?;
        fs::rename(&manifest, &saved)?;
        fs::write(&manifest, &original)?;
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))?;
        assert!(
            closure.verify().is_err(),
            "identical bytes at a different FD do not restore the original owner"
        );
        assert!(closure.read_local(&live, &mut || Ok(())).is_err());
        assert_eq!(fs::read(&saved)?, original);
        assert!(blob_path(&directory, &live).exists());
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
