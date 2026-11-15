//! Three actual durable OpenRaft nodes over the maintained production RPC
//! codec. The pause only delays return of an already-persisted old snapshot;
//! these controls do not claim TLS, LAN timing or subprocess qualification.
use super::*;
use crate::ReplicatedEnvelope;
use futures::future::BoxFuture;
use openraft::{async_runtime::WatchReceiver, storage::RaftStateMachine};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[derive(Default)]
struct Router {
    peers: RwLock<BTreeMap<u64, RaftRpcService>>,
    reject_append: AtomicBool,
}
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SnapshotObservationRouter")
    }
}
impl RaftPeerRpc for Arc<Router> {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        payload: Vec<u8>,
        _timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        let router = Arc::clone(self);
        Box::pin(async move {
            if kind == RaftRpcKind::AppendEntries && router.reject_append.load(Ordering::SeqCst) {
                return Err(RemoteRaftError::Transport("owned test partition".into()));
            }
            let peer = router
                .peers
                .read()
                .await
                .get(&target)
                .cloned()
                .ok_or(RemoteRaftError::InvalidTopology)?;
            peer.handle(source, kind, payload).await
        })
    }
}
async fn cluster(label: &str) -> TestResult<(PathBuf, Arc<Router>, Vec<ProcessRaftNode>)> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-snapshot-observed-{label}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::SeqCst),
    ));
    let router = Arc::new(Router::default());
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let network = RemoteNetworkFactory::new(
            id,
            BTreeSet::from([1, 2, 3]),
            Arc::new(Arc::clone(&router)),
        )?;
        let node = ProcessRaftNode::create(path.join(id.to_string()), id, network).await?;
        node.raft.runtime_config().elect(false);
        router.peers.write().await.insert(id, node.rpc_service());
        nodes.push(node);
    }
    nodes[0]
        .raft
        .initialize(BTreeMap::from([(1, ()), (2, ()), (3, ())]))
        .await?;
    nodes[0].raft.trigger().elect(false).await?;
    nodes[0]
        .raft
        .wait(Some(Duration::from_secs(5)))
        .metrics(
            |m| m.current_leader == Some(1) && m.last_applied.is_some(),
            "actual first leader applied",
        )
        .await?;
    nodes[0].ensure_linearizable().await?;
    Ok((path, router, nodes))
}
async fn cleanup(path: PathBuf, router: Arc<Router>, nodes: Vec<ProcessRaftNode>) -> TestResult {
    router.reject_append.store(false, Ordering::SeqCst);
    router.peers.write().await.clear();
    for node in nodes {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(path)?;
    Ok(())
}
async fn publish(node: &ProcessRaftNode, label: &str, fill: u8) -> TestResult<ReplicatedEnvelope> {
    let envelope = ReplicatedEnvelope::new(label, [fill; 32], vec![fill; 128])?;
    let serial = node.next_production_client_serial().await?;
    tokio::time::timeout(Duration::from_secs(3), node.replicate(serial, &envelope)).await??;
    node.ensure_linearizable().await?;
    Ok(envelope)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_observation_busy_old_frontier_rearms_within_original_budget_without_business_replay()
-> TestResult {
    let (path, router, nodes) = cluster("busy").await?;
    let result = async {
        let node = &nodes[0];
        let _first = publish(node, "snapshot-old", 1).await?;
        let pause = node.state_machine.pause_next_snapshot_completion()?;
        node.trigger_snapshot().await?;
        let old = tokio::time::timeout(Duration::from_secs(2), pause.captured_index()).await?;
        let second = publish(node, "snapshot-new", 2).await?;
        let required = node
            .membership_observation()
            .await?
            .applied_index
            .ok_or("actual applied frontier")?;
        assert!(required > old && required - old < 128);
        let mut durable = node.state_machine.clone();
        let persisted_old = durable
            .get_current_snapshot()
            .await?
            .ok_or("actual persisted paused snapshot")?;
        assert_eq!(
            persisted_old.meta.last_log_id.as_ref().map(|log| log.index),
            Some(old)
        );
        let before_log = node.raft.metrics().borrow_watched().last_log_index;
        let attempts = pause.trigger_count();
        let start = Instant::now();
        let (observed, released) = tokio::join!(node.snapshot_observed(), async {
            tokio::time::timeout(
                Duration::from_secs(2),
                pause.wait_for_trigger_count(attempts + 1),
            )
            .await?;
            // Same maintained RaftCore queue: the trigger has been handled
            // while the real old builder remains paused before its return.
            node.raft.with_raft_state(|_| ()).await?;
            assert_eq!(
                node.state_machine
                    .clone()
                    .get_current_snapshot()
                    .await?
                    .ok_or("old durable snapshot remains")?
                    .meta
                    .last_log_id
                    .as_ref()
                    .map(|log| log.index),
                Some(old),
            );
            pause.release();
            Ok::<_, Box<dyn std::error::Error>>(())
        },);
        released?;
        let observed = observed?;
        assert_eq!(observed.requested_index, required);
        assert!(observed.persisted_index >= required);
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(
            pause.trigger_count() >= attempts + 2,
            "busy trigger must be re-armed"
        );
        assert_eq!(
            node.raft.metrics().borrow_watched().last_log_index,
            before_log
        );
        assert_eq!(
            node.latest_envelope()
                .await?
                .ok_or("current business value")?
                .digest(),
            second.digest(),
        );
        let final_snapshot = durable
            .get_current_snapshot()
            .await?
            .ok_or("new durable snapshot")?;
        assert_eq!(
            final_snapshot
                .meta
                .last_log_id
                .as_ref()
                .map(|log| log.index),
            Some(observed.persisted_index),
        );
        use sha2::{Digest, Sha256};
        assert_eq!(
            Sha256::digest(final_snapshot.snapshot.into_inner()).as_slice(),
            observed.sha256.as_slice(),
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    cleanup(path, router, nodes).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_observation_busy_build_cannot_renew_original_deadline_or_bypass_lost_quorum()
-> TestResult {
    let (path, router, nodes) = cluster("deadline").await?;
    let result = async {
        let node = &nodes[0];
        publish(node, "deadline-old", 3).await?;
        let pause = node.state_machine.pause_next_snapshot_completion()?;
        node.trigger_snapshot().await?;
        let old = tokio::time::timeout(Duration::from_secs(2), pause.captured_index()).await?;
        let current = publish(node, "deadline-new", 4).await?;
        let before_log = node.raft.metrics().borrow_watched().last_log_index;
        let start = Instant::now();
        let absolute = start + Duration::from_millis(120);
        let expired = crate::with_read_index_deadline(absolute, node.snapshot_observed()).await;
        assert!(expired.is_err());
        assert!(Instant::now() >= absolute);
        assert!(start.elapsed() < Duration::from_millis(500));
        node.raft.with_raft_state(|_| ()).await?;
        assert!(pause.trigger_count() > 0);
        assert_eq!(
            node.state_machine
                .clone()
                .get_current_snapshot()
                .await?
                .ok_or("old paused snapshot")?
                .meta
                .last_log_id
                .as_ref()
                .map(|log| log.index),
            Some(old),
        );
        assert_eq!(node.raft.metrics().borrow_watched().last_log_index, before_log);
        assert_eq!(node.latest_envelope().await?.ok_or("unchanged current value")?.digest(), current.digest());
        pause.release();
        drop(pause);
        node.snapshot_observed().await?;
        router.reject_append.store(true, Ordering::SeqCst);
        let before_snapshot = node.raft.metrics().borrow_watched().snapshot;
        // The local durable generation also advances for checkpoint completion.
        // A snapshot already in flight from the successful pre-partition call
        // can finish after this sample without committing any business write.
        // Compare the actual applied log and application state under one state-
        // machine lock instead of mistaking a checkpoint for a failed ReadIndex
        // publishing a new business generation.
        let before_application = node
            .state_machine
            .application_read_snapshot(crate::records::PRODUCTION_CLIENT)
            .await;
        let denied = crate::with_read_index_deadline(
            Instant::now() + Duration::from_millis(120),
            node.snapshot_observed(),
        )
        .await;
        assert!(matches!(denied, Err(RemoteRaftError::Consensus(ref reason)) if reason == super::node::READ_INDEX_TIMEOUT));
        assert_eq!(node.raft.metrics().borrow_watched().snapshot, before_snapshot);
        let after_application = node
            .state_machine
            .application_read_snapshot(crate::records::PRODUCTION_CLIENT)
            .await;
        assert!(after_application.0 >= before_application.0, "durable generation regressed");
        assert_eq!(after_application.1, before_application.1, "denied observation applied a log entry");
        assert!(after_application.2 == before_application.2, "denied observation changed client state");
        assert!(after_application.3 == before_application.3, "denied observation changed published root");
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    cleanup(path, router, nodes).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_observation_real_checkpoint_write_failure_never_admits_old_snapshot() -> TestResult
{
    let (path, router, nodes) = cluster("io").await?;
    let result = async {
        let node = &nodes[0];
        publish(node, "checkpoint-old", 5).await?;
        let old = node.snapshot_observed().await?;
        publish(node, "checkpoint-new", 6).await?;
        let required = node
            .membership_observation()
            .await?
            .applied_index
            .ok_or("new applied")?;
        assert!(required > old.persisted_index);
        let checkpoint = node.state_machine.snapshot_path();
        // A real path-type error on this test's private checkpoint makes the
        // next actual DurableStateMachine snapshot persistence fail.
        std::fs::remove_file(checkpoint)?;
        std::fs::create_dir(checkpoint)?;
        let denied = tokio::time::timeout(Duration::from_secs(5), node.snapshot_observed()).await?;
        assert!(denied.is_err());
        assert!(
            node.raft
                .metrics()
                .borrow_watched()
                .snapshot
                .as_ref()
                .is_none_or(|log| log.index < required),
            "old snapshot cannot satisfy the fixed new frontier",
        );
        assert!(checkpoint.is_dir());
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    cleanup(path, router, nodes).await?;
    result
}
