//! Actual OpenRaft nodes and durable stores over the production bounded RPC
//! codec. This synthetic loopback deliberately makes no TLS/process claim.
use super::*;
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
        _timeout: Duration,
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
