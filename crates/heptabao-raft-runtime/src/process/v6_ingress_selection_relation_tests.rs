//! Actual selections and actual replicated transitions; no forged fields.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingress_successor_rejects_actual_other_store_and_real_leader_term_change() -> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let old = selected(node).await?;
        assert!(
            fixture.nodes[1]
                .native_v6_fresh_ingress_selection_read(&old)
                .await
                .is_err(),
            "the actual follower store is not the previous store"
        );
        let old_term = old.term();
        fixture.nodes[1].raft.runtime_config().elect(true);
        fixture.nodes[1].raft.trigger().elect(false).await?;
        fixture.nodes[1]
            .raft
            .wait(Some(Duration::from_secs(5)))
            .metrics(
                |m| m.current_leader == Some(2) && m.current_term > old_term,
                "actual ingress term change",
            )
            .await?;
        node.raft
            .wait(Some(Duration::from_secs(5)))
            .metrics(
                |m| m.current_leader == Some(2) && m.current_term > old_term,
                "old owner observes the actual new term",
            )
            .await?;
        let current = selected(node).await?;
        assert_ne!(current.leader_id(), old.leader_id());
        assert!(current.term() > old.term());
        assert!(
            node.native_v6_fresh_ingress_selection_read(&old)
                .await
                .is_err(),
            "current quorum under a different actual leader/term cannot continue old selection"
        );
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingress_successor_rejects_actual_atomic_epoch_and_enrollment_restore() -> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let old = selected(node).await?;
        let intent = next_intent(&old, old.enrollment().epoch() + 1, 0x61, 0x62);
        let initial = begin(node, &old, &intent).await?;
        let staged = stage(node, intent).await?;
        let sealed = pending(node, &initial).await?;
        let actual = node
            .publish_native_v6_epoch_restore(
                node.next_production_client_serial().await?,
                &sealed,
                &staged,
                vec![0x63; 64],
            )
            .await?;
        let current = selected(node).await?;
        assert_eq!(current.root(), &actual);
        assert_ne!(current.enrollment(), old.enrollment());
        assert_ne!(current.root().intent().epoch, old.root().intent().epoch);
        assert!(
            node.native_v6_fresh_ingress_selection_read(&old)
                .await
                .is_err(),
            "a later actual root does not permit epoch/enrollment reselection"
        );
        assert!(node.native_v6_same_root_progress_read(&old).await.is_err());
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
