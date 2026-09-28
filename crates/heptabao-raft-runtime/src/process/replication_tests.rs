//! Actual OpenRaft nodes and durable stores over the production bounded RPC
//! codec. This synthetic loopback deliberately makes no TLS/process claim.
use super::*;
use crate::ReplicatedEnvelope;
use futures::future::BoxFuture;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Default)]
struct Router {
    peers: RwLock<BTreeMap<u64, RaftRpcService>>,
    paused: RwLock<BTreeSet<u64>>,
    largest_append: AtomicUsize,
    largest_entries: AtomicUsize,
    paced_target: AtomicUsize,
    paced_timeouts: AtomicUsize,
    paced_budget_ms: AtomicUsize,
    snapshot_delay_ms: AtomicUsize,
    snapshot_timeouts: AtomicUsize,
    snapshot_budget_ms: AtomicUsize,
    snapshot_chunks: AtomicUsize,
}
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoundedSyntheticRaftRouter")
    }
}
impl RaftPeerRpc for Arc<Router> {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        let router = Arc::clone(self);
        Box::pin(async move {
            if payload.len() > crate::replication_bounds::MAX_REMOTE_RPC_BYTES {
                return Err(RemoteRaftError::InvalidRpc);
            }
            {
                let paused = router.paused.read().await;
                if paused.contains(&source) || paused.contains(&target) {
                    return Err(RemoteRaftError::Transport("synthetic partition".into()));
                }
            }
            if matches!(kind, RaftRpcKind::AppendEntries) {
                router
                    .largest_append
                    .fetch_max(payload.len(), Ordering::Relaxed);
                let request: openraft::raft::AppendEntriesRequest<crate::TypeConfig> =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                router
                    .largest_entries
                    .fetch_max(request.entries.len(), Ordering::Relaxed);
                if target as usize == router.paced_target.load(Ordering::SeqCst) {
                    router
                        .paced_budget_ms
                        .fetch_max(timeout.as_millis() as usize, Ordering::SeqCst);
                    let transfer = Duration::from_micros(1_000 + payload.len() as u64 / 2);
                    tokio::time::sleep(transfer.min(timeout)).await;
                    if transfer >= timeout {
                        router.paced_timeouts.fetch_add(1, Ordering::SeqCst);
                        return Err(RemoteRaftError::Transport(
                            "bounded synthetic transfer timeout".into(),
                        ));
                    }
                }
            }
            if matches!(kind, RaftRpcKind::SnapshotChunk) && target == 3 {
                router.snapshot_chunks.fetch_add(1, Ordering::SeqCst);
                router
                    .snapshot_budget_ms
                    .fetch_max(timeout.as_millis() as usize, Ordering::SeqCst);
                let delay =
                    Duration::from_millis(router.snapshot_delay_ms.load(Ordering::SeqCst) as u64);
                tokio::time::sleep(delay.min(timeout)).await;
                if delay >= timeout {
                    router.snapshot_timeouts.fetch_add(1, Ordering::SeqCst);
                    return Err(RemoteRaftError::Transport(
                        "bounded synthetic snapshot install timeout".into(),
                    ));
                }
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

async fn leader(node: &ProcessRaftNode, expected: u64) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        while node.current_leader().await != Some(expected) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| "expected leader was not observed")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_log_reconnect_snapshot_then_new_leader_commits_its_blank()
-> Result<(), Box<dyn std::error::Error>> {
    let path =
        std::env::temp_dir().join(format!("heptabao-byte-replication-{}", std::process::id()));
    let router = Arc::new(Router::default());
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let factory = RemoteNetworkFactory::new(
            id,
            BTreeSet::from([1, 2, 3]),
            Arc::new(Arc::clone(&router)),
        )?;
        let node = ProcessRaftNode::create(path.join(id.to_string()), id, factory).await?;
        router.peers.write().await.insert(id, node.rpc_service());
        nodes.push(node);
    }
    let result = async {
        for (from, to) in [(3, 2), (1, 3)] {
            let request = openraft::raft::TransferLeaderRequest::<crate::TypeConfig>::new(
                openraft::Vote::new_committed(1, from),
                to,
                None,
            );
            assert!(matches!(
                nodes[1]
                    .rpc_service()
                    .handle(
                        1,
                        RaftRpcKind::TransferLeader,
                        serde_json::to_vec(&request)?
                    )
                    .await,
                Err(RemoteRaftError::InvalidRpc)
            ));
        }
        nodes[0].initialize_single().await?;
        leader(&nodes[0], 1).await?;
        nodes[0].add_learner(2).await?;
        nodes[0].add_learner(3).await?;
        nodes[0]
            .change_membership(BTreeSet::from([1, 2, 3]))
            .await?;
        // Large individual entries fit, but three together exceed the actual
        // 768KiB RPC limit. The disconnected peer must catch up by prefixes.
        router.paused.write().await.insert(2);
        let mut last = None;
        for serial in 1..=12 {
            let envelope = crate::ReplicatedEnvelope::new(
                format!("bounded-large-{serial}"),
                [serial as u8; 32],
                vec![serial as u8; 220 * 1024],
            )?;
            tokio::time::timeout(
                Duration::from_secs(8),
                nodes[0].replicate(serial, &envelope),
            )
            .await
            .map_err(|_| "large write did not complete")??;
            last = Some(envelope);
        }
        router.paused.write().await.clear();
        let expected = last.as_ref().ok_or("missing envelope")?.digest();
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if nodes[1]
                    .latest_envelope()
                    .await?
                    .is_some_and(|e| e.digest() == expected)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, RemoteRaftError>(())
        })
        .await
        .map_err(|_| "reconnected peer did not apply the final large entry")??;
        // Checkpoint/purge on the old leader before transferring to the peer
        // that has the retained large log. ReadIndex must apply the new no-op.
        nodes[0].snapshot_observed().await?;
        nodes[0].transfer_leadership(3).await?;
        leader(&nodes[2], 3).await?;
        tokio::time::timeout(Duration::from_secs(8), nodes[2].ensure_linearizable())
            .await
            .map_err(|_| "new leader did not confirm its ReadIndex")??;
        let final_envelope =
            crate::ReplicatedEnvelope::new("after-transfer", [99; 32], vec![99; 220 * 1024])?;
        tokio::time::timeout(
            Duration::from_secs(8),
            nodes[2].replicate(99, &final_envelope),
        )
        .await
        .map_err(|_| "new leader write did not complete")??;
        assert_eq!(
            nodes[2]
                .latest_envelope()
                .await?
                .ok_or("missing publication")?
                .digest(),
            final_envelope.digest()
        );
        assert!(
            router.largest_append.load(Ordering::Relaxed)
                <= crate::replication_bounds::MAX_REMOTE_RPC_BYTES
        );
        assert!(
            router.largest_entries.load(Ordering::Relaxed) > 1,
            "must retain useful multi-entry batches"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    router.peers.write().await.clear();
    for node in nodes {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(&path)?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_unready_learner_is_not_promoted_and_can_recover()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-learner-readiness-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_dir_all(&path);
    let router = Arc::new(Router::default());
    let peers = BTreeSet::from([1, 2, 3]);
    let factory = RemoteNetworkFactory::new(1, peers.clone(), Arc::new(Arc::clone(&router)))?;
    let leader_node = ProcessRaftNode::create(path.join("1"), 1, factory).await?;
    router
        .peers
        .write()
        .await
        .insert(1, leader_node.rpc_service());

    let result = async {
        leader_node.initialize_single().await?;
        leader(&leader_node, 1).await?;

        // Enrollment is a durable membership fact even while the target process
        // is absent. Readiness must remain false and promotion must not happen.
        leader_node.enroll_learner(2).await?;
        let enrolled = leader_node.membership_observation().await?;
        assert!(enrolled.nodes.contains(&2));
        assert_eq!(enrolled.voters, BTreeSet::from([1]));
        assert!(
            leader_node
                .wait_for_learner_replication(2, Duration::from_millis(250))
                .await
                .is_err()
        );
        assert_eq!(
            leader_node.membership_observation().await?.voters,
            BTreeSet::from([1])
        );

        // Bring the learner process up later. The committed enrollment is reused;
        // once replication/heartbeat catches up it becomes eligible to promote.
        let factory2 = RemoteNetworkFactory::new(2, peers.clone(), Arc::new(Arc::clone(&router)))?;
        let node2 = ProcessRaftNode::create(path.join("2"), 2, factory2).await?;
        router.peers.write().await.insert(2, node2.rpc_service());
        leader_node
            .wait_for_learner_replication(2, Duration::from_secs(8))
            .await?;

        let factory3 = RemoteNetworkFactory::new(3, peers.clone(), Arc::new(Arc::clone(&router)))?;
        let node3 = ProcessRaftNode::create(path.join("3"), 3, factory3).await?;
        router.peers.write().await.insert(3, node3.rpc_service());
        leader_node.enroll_learner(3).await?;
        leader_node
            .wait_for_learner_replication(3, Duration::from_secs(8))
            .await?;
        leader_node.change_membership(peers.clone()).await?;
        assert_eq!(leader_node.membership_observation().await?.voters, peers);

        router.peers.write().await.remove(&2);
        router.peers.write().await.remove(&3);
        node2.shutdown().await?;
        node3.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    router.peers.write().await.clear();
    leader_node.shutdown().await?;
    let _ = std::fs::remove_dir_all(&path);
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guarded_join_acknowledges_committed_learner_before_replication()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-guarded-join-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_dir_all(&path);
    let router = Arc::new(Router::default());
    let peers = BTreeSet::from([1, 2, 3]);
    let factory = RemoteNetworkFactory::new(1, peers, Arc::new(Arc::clone(&router)))?;
    let node = ProcessRaftNode::create(path.join("1"), 1, factory).await?;
    router.peers.write().await.insert(1, node.rpc_service());

    let result = async {
        node.initialize_single().await?;
        leader(&node, 1).await?;
        let before = node.membership_observation().await?;
        let index = before.membership_index.ok_or("initial membership index")?;

        // Node 2 has no running process and no registered RPC service. Explicit
        // join must still acknowledge its committed learner membership; catch-up
        // and promotion remain separate observations.
        let observed = tokio::time::timeout(
            Duration::from_secs(6),
            node.change_membership_guarded(index, 2, "add_learner"),
        )
        .await
        .map_err(|_| "guarded learner join waited for replication")??;
        assert!(observed.committed);
        assert!(!observed.joint);
        assert!(observed.nodes.contains(&2));
        assert!(!observed.voters.contains(&2));
        assert!(
            node.wait_for_learner_replication(2, Duration::from_millis(250))
                .await
                .is_err(),
            "membership acknowledgement must not fabricate replication readiness"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    router.peers.write().await.clear();
    node.shutdown().await?;
    let _ = std::fs::remove_dir_all(&path);
    result
}

#[tokio::test]
async fn reopen_publishes_recovered_membership_before_returning()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-recovered-membership-{}",
        std::process::id()
    ));
    let router = Arc::new(Router::default());
    let factory =
        || RemoteNetworkFactory::new(1, BTreeSet::from([1, 2, 3]), Arc::new(Arc::clone(&router)));
    let node = ProcessRaftNode::create(&path, 1, factory()?).await?;
    node.initialize_single().await?;
    leader(&node, 1).await?;
    node.ensure_linearizable().await?;
    node.snapshot_observed().await?;
    let baseline = node.membership_observation().await?;
    assert!(baseline.committed && !baseline.joint);
    assert!(baseline.membership_index.is_some());
    assert!(baseline.applied_index.is_some());
    let mut current = Some(node);
    let result = async {
        // A current-thread runtime makes stale initial metrics observable:
        // the caller must not need a scheduling yield after reopen returns.
        for _ in 0..8 {
            current.take().ok_or("missing node")?.shutdown().await?;
            current = Some(ProcessRaftNode::reopen(&path, 1, factory()?).await?);
            let observed = current
                .as_ref()
                .ok_or("missing reopened node")?
                .membership_observation()
                .await?;
            assert!(
                observed.applied_index >= baseline.applied_index,
                "reopen returned before publishing its durable applied frontier"
            );
            assert_eq!(observed.membership_index, baseline.membership_index);
            assert!(observed.committed && !observed.joint);
            assert_eq!(observed.voters, baseline.voters);
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    if let Some(node) = current {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(&path)?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopped_voter_reopens_after_purge_and_reaches_its_own_applied_frontier()
-> Result<(), Box<dyn std::error::Error>> {
    snapshot_reopen_and_transfer(0).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_recovery_has_a_distinct_bounded_install_budget()
-> Result<(), Box<dyn std::error::Error>> {
    snapshot_reopen_and_transfer(250).await
}

async fn snapshot_reopen_and_transfer(delay_ms: usize) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-reopen-purge-{}-{delay_ms}",
        std::process::id(),
    ));
    let router = Arc::new(Router::default());
    router.snapshot_delay_ms.store(delay_ms, Ordering::SeqCst);
    let peers = BTreeSet::from([1, 2, 3]);
    let mut nodes = BTreeMap::new();
    for id in 1..=3 {
        let network = RemoteNetworkFactory::new(id, peers.clone(), Arc::new(Arc::clone(&router)))?;
        let node = ProcessRaftNode::create(path.join(id.to_string()), id, network).await?;
        router.peers.write().await.insert(id, node.rpc_service());
        nodes.insert(id, node);
    }
    let result = async {
        let first = nodes.get(&1).ok_or("first node")?;
        first.initialize_single().await?;
        leader(first, 1).await?;
        first.add_learner(2).await?;
        first.add_learner(3).await?;
        first.change_membership(peers.clone()).await?;
        for serial in 1..=18 {
            let envelope = ReplicatedEnvelope::new(
                format!("pre-stop-{serial}"),
                [serial as u8; 32],
                vec![serial as u8; 12 * 1024],
            )?;
            first.replicate(serial, &envelope).await?;
        }
        router.paused.write().await.insert(3);
        router.peers.write().await.remove(&3);
        let stopped = nodes.remove(&3).ok_or("stopped voter")?;
        stopped.shutdown().await?;
        let first = nodes.get(&1).ok_or("first node")?;
        for serial in 19..=27 {
            let envelope = ReplicatedEnvelope::new(
                format!("offline-{serial}"),
                [serial as u8; 32],
                vec![serial as u8; 12 * 1024],
            )?;
            first.replicate(serial, &envelope).await?;
        }
        let snapshot = first.snapshot_observed().await?;
        // A persisted snapshot is not yet evidence that replay became
        // impossible. Wait for the actual source log-purge frontier before
        // reopening the stale voter; otherwise this test can pass via logs.
        tokio::time::timeout(Duration::from_secs(5), async {
            while first.membership_observation().await?.purged_index
                < Some(snapshot.persisted_index)
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, RemoteRaftError>(())
        }).await.map_err(|_| "source snapshot logs were not purged")??;
        let latest = ReplicatedEnvelope::new("after-snapshot", [28; 32], vec![28; 12 * 1024])?;
        first.replicate(28, &latest).await?;
        first.ensure_linearizable().await?;
        let frontier = first
            .local_leader_observation()?
            .applied_index
            .ok_or("leader frontier")?;
        let network = RemoteNetworkFactory::new(3, peers.clone(), Arc::new(Arc::clone(&router)))?;
        let restored = ProcessRaftNode::reopen(path.join("3"), 3, network).await?;
        router.peers.write().await.insert(3, restored.rpc_service());
        router.paused.write().await.remove(&3);
        nodes.insert(3, restored);
        let restored = nodes.get(&3).ok_or("restored voter")?;
        tokio::time::timeout(Duration::from_secs(10), async {
            while restored.local_leader_observation()?.applied_index < Some(frontier) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, RemoteRaftError>(())
        })
        .await
        .map_err(|_| {
            format!(
                "local snapshot recovery stalled: chunks={} timeouts={} budget_ms={} delay_ms={delay_ms}",
                router.snapshot_chunks.load(Ordering::SeqCst),
                router.snapshot_timeouts.load(Ordering::SeqCst),
                router.snapshot_budget_ms.load(Ordering::SeqCst),
            )
        })??;
        assert!(router.snapshot_chunks.load(Ordering::SeqCst) > 0,
            "catch-up must use the snapshot rather than retained log replay");
        assert_eq!(router.snapshot_timeouts.load(Ordering::SeqCst), 0);
        assert!(router.snapshot_budget_ms.load(Ordering::SeqCst) > delay_ms);
        assert!(router.snapshot_budget_ms.load(Ordering::SeqCst) <= 1_000,
            "snapshot transport must retain a finite install budget");
        assert_eq!(
            restored
                .latest_envelope()
                .await?
                .ok_or("restored envelope")?
                .digest(),
            latest.digest()
        );
        let current = nodes.get(&1).ok_or("current leader")?;
        current.transfer_leadership(3).await?;
        leader(restored, 3).await?;
        restored.ensure_linearizable().await?;
        let final_entry =
            ReplicatedEnvelope::new("after-reopen-transfer", [29; 32], vec![29; 12 * 1024])?;
        restored.replicate(29, &final_entry).await?;
        restored.ensure_linearizable().await?;
        assert_eq!(
            restored
                .latest_envelope()
                .await?
                .ok_or("new leader publication")?
                .digest(),
            final_entry.digest()
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    router.paused.write().await.clear();
    router.peers.write().await.clear();
    for (_, node) in nodes {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(path)?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accumulated_replay_uses_small_batches_inside_unchanged_peer_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("heptabao-paced-replay-{}", std::process::id()));
    let router = Arc::new(Router::default());
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let network = RemoteNetworkFactory::new(
            id,
            BTreeSet::from([1, 2, 3]),
            Arc::new(Arc::clone(&router)),
        )?;
        let node = ProcessRaftNode::create(path.join(id.to_string()), id, network).await?;
        router.peers.write().await.insert(id, node.rpc_service());
        nodes.push(node);
    }
    let result = async {
        let first = &nodes[0];
        first.initialize_single().await?;
        leader(first, 1).await?;
        first.add_learner(2).await?;
        first.add_learner(3).await?;
        first.change_membership(BTreeSet::from([1, 2, 3])).await?;
        router.paused.write().await.insert(3);
        let mut last = None;
        for serial in 1..=45 {
            let envelope = ReplicatedEnvelope::new(
                format!("paced-once-{serial}"),
                [serial as u8; 32],
                vec![serial as u8; 8 * 1024],
            )?;
            first.replicate(serial, &envelope).await?;
            last = Some(envelope);
        }
        let expected = last.ok_or("last expected envelope")?;
        let frontier = first
            .local_leader_observation()?
            .applied_index
            .ok_or("leader frontier")?;
        router.paced_target.store(3, Ordering::SeqCst);
        router.paused.write().await.clear();
        let caught_up = tokio::time::timeout(Duration::from_secs(8), async {
            while nodes[2].local_leader_observation()?.applied_index < Some(frontier) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, RemoteRaftError>(())
        })
        .await;
        if caught_up.is_err() {
            assert!(
                router.paced_timeouts.load(Ordering::SeqCst) > 0,
                "the failing case must actually exhaust the real supplied RPC budget"
            );
        }
        caught_up.map_err(
            |_| "fixed RPC budget repeatedly rejected the same accumulated replay batch",
        )??;
        assert_eq!(
            nodes[2]
                .latest_envelope()
                .await?
                .ok_or("replica state")?
                .digest(),
            expected.digest()
        );
        assert_eq!(
            router.paced_budget_ms.load(Ordering::SeqCst),
            150,
            "replay must not extend the upstream transport budget"
        );
        assert_eq!(router.paced_timeouts.load(Ordering::SeqCst), 0);
        assert!(
            router.largest_entries.load(Ordering::Relaxed) > 1,
            "keep useful multi-entry replication rather than one-entry-only dispatch"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    router.paced_target.store(0, Ordering::SeqCst);
    router.paused.write().await.clear();
    router.peers.write().await.clear();
    for node in nodes {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(path)?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_snapshot_restarts_do_not_exhaust_receive_slots()
-> Result<(), Box<dyn std::error::Error>> {
    use super::snapshot::{SnapshotChunkAck, SnapshotChunkWire, crc32};
    let path = std::env::temp_dir().join(format!(
        "heptabao-snapshot-prefix-restart-{}",
        std::process::id(),
    ));
    let router = Arc::new(Router::default());
    let network =
        RemoteNetworkFactory::new(3, BTreeSet::from([1, 2, 3]), Arc::new(Arc::clone(&router)))?;
    let node = ProcessRaftNode::create(&path, 3, network).await?;
    let service = node.rpc_service();
    let result = async {
        // A sender can obtain a newer snapshot after an interrupted transfer.
        // None of these prefixes constitutes a complete, installable snapshot.
        for generation in 0..12_u8 {
            let request = SnapshotChunkWire {
                transfer_id: format!("interrupted-{generation}"),
                ordinal: 0,
                total_chunks: 2,
                vote: Some(openraft::Vote::new_committed(1, 1)),
                meta: Some(openraft::SnapshotMeta {
                    last_log_id: None,
                    last_membership: Default::default(),
                    snapshot_id: format!("synthetic-prefix-{generation}"),
                }),
                total_bytes: 64,
                whole_crc32: crc32(&[generation; 64]),
                chunk_crc32: crc32(&[generation; 32]),
                chunk: vec![generation; 32],
            };
            let bytes = service
                .handle(1, RaftRpcKind::SnapshotChunk, serde_json::to_vec(&request)?)
                .await
                .map_err(|error| format!("snapshot restart {generation} rejected: {error}"))?;
            let ack: SnapshotChunkAck = serde_json::from_slice(&bytes)?;
            assert_eq!(ack.next_ordinal, 1);
            assert!(!ack.complete && ack.result.is_none());
            assert_eq!(node.local_leader_observation()?.applied_index, None);
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    node.shutdown().await?;
    std::fs::remove_dir_all(path)?;
    result
}
