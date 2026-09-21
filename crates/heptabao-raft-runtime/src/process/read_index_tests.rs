//! Real OpenRaft, disk stores and the production RPC codec. The controllable
//! loopback transport proves consensus wait behavior, not TLS or HTTP timing.
use super::*;
use crate::process::{RaftPeerRpc, RaftRpcKind};
use futures::future::BoxFuture;
use openraft::async_runtime::WatchReceiver;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;

const PASS: u8 = 0;
const BLOCK_LOG_ENTRIES: u8 = 1;
const BLOCK_ALL_APPEND: u8 = 2;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct Router {
    peers: RwLock<BTreeMap<u64, RaftRpcService>>,
    mode: AtomicU8,
    blocked_entries: AtomicUsize,
    blocked_probes: AtomicUsize,
}
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadIndexTestRouter")
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
            if kind == RaftRpcKind::AppendEntries {
                let request: openraft::raft::AppendEntriesRequest<crate::TypeConfig> =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                let has_entries = !request.entries.is_empty();
                let blocked = match router.mode.load(Ordering::SeqCst) {
                    BLOCK_LOG_ENTRIES => has_entries,
                    BLOCK_ALL_APPEND => true,
                    _ => false,
                };
                if blocked {
                    if has_entries {
                        router.blocked_entries.fetch_add(1, Ordering::SeqCst);
                    } else {
                        router.blocked_probes.fetch_add(1, Ordering::SeqCst);
                    }
                    // Model an unresponsive peer for its actual RPC budget.
                    // Votes remain available: a leader can be elected without
                    // being able to commit its first blank entry.
                    tokio::time::sleep(timeout).await;
                    return Err(RemoteRaftError::Transport("test link blocked".into()));
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

#[test]
fn default_read_bound_covers_current_peer_and_election_ceilings() -> Result<(), RemoteRaftError> {
    let config = production_config()?;
    // The server currently admits peer_timeout_ms up to 5000. This is a
    // runtime bound, not proof of the listener's (possibly shorter) deadline.
    assert!(MAX_READ_INDEX_WAIT >= Duration::from_millis(5_000 + config.election_timeout_max));
    assert_eq!(MAX_READ_INDEX_WAIT, Duration::from_secs(8));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uncommitted_blank_and_lost_quorum_reads_time_out_then_recover()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-read-index-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
    ));
    let router = Arc::new(Router::default());
    router.mode.store(BLOCK_LOG_ENTRIES, Ordering::SeqCst);
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let factory = RemoteNetworkFactory::new(
            id,
            BTreeSet::from([1, 2, 3]),
            Arc::new(Arc::clone(&router)),
        )?;
        let node = ProcessRaftNode::create(path.join(id.to_string()), id, factory).await?;
        // Keep a deterministic leader while independently controlling quorum
        // reachability; manual election below still uses real votes.
        node.raft.runtime_config().elect(false);
        router.peers.write().await.insert(id, node.rpc_service());
        nodes.push(node);
    }
    let result = async {
        let node = &nodes[0];
        node.raft
            .initialize(BTreeMap::from([(1, ()), (2, ()), (3, ())]))
            .await?;
        node.raft.trigger().elect(false).await?;
        node.raft
            .wait(Some(Duration::from_secs(5)))
            .metrics(
                |m| {
                    m.current_leader == Some(1)
                        && m.last_log_index.is_some_and(|index| index > 0)
                        && m.last_log_index > m.last_applied.as_ref().map(|log| log.index)
                },
                "elected leader has an uncommitted blank entry",
            )
            .await?;

        // Empty AppendEntries still reach a quorum. Thus the missing blank,
        // not failure to obtain a leadership probe, is what blocks readiness.
        let linearizer = tokio::time::timeout(
            Duration::from_secs(2),
            node.raft.get_read_linearizer(ReadPolicy::ReadIndex),
        )
        .await??;
        let required = linearizer.read_log_id().index();
        let before_applied = node.state_machine.last_applied_log_index().await;
        assert!(before_applied < Some(required));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(80),
                node.raft.ensure_linearizable(ReadPolicy::ReadIndex),
            )
            .await
            .is_err(),
            "the actual upstream indefinite wait must be exercised",
        );
        let start = std::time::Instant::now();
        let rejected = tokio::time::timeout(
            Duration::from_secs(2),
            node.ensure_linearizable_with_timeout(Duration::from_millis(80)),
        )
        .await?;
        assert!(matches!(rejected, Err(RemoteRaftError::Consensus(ref reason)) if reason == READ_INDEX_TIMEOUT));
        assert!(start.elapsed() >= Duration::from_millis(80));
        assert_eq!(node.state_machine.last_applied_log_index().await, before_applied);
        assert!(router.blocked_entries.load(Ordering::SeqCst) > 0);
        assert!(node.latest_envelope().await?.is_none());

        router.mode.store(PASS, Ordering::SeqCst);
        node.ensure_linearizable().await?;
        assert!(node.state_machine.last_applied_log_index().await >= Some(required));
        let first = ReplicatedEnvelope::new("read-index-first", [1; 32], vec![1; 128])?;
        tokio::time::timeout(Duration::from_secs(3), node.replicate(1, &first)).await??;
        node.ensure_linearizable().await?;
        assert_eq!(
            node.latest_envelope().await?.ok_or("missing first state")?.digest(),
            first.digest(),
        );

        // Even a healthy, already applied node may not grant a read to a
        // caller with no remaining time.
        let prior_probes = router.blocked_probes.load(Ordering::SeqCst);
        let zero = node.ensure_linearizable_with_timeout(Duration::ZERO).await;
        assert!(matches!(zero, Err(RemoteRaftError::Consensus(ref reason)) if reason == READ_INDEX_TIMEOUT));

        router.mode.store(BLOCK_ALL_APPEND, Ordering::SeqCst);
        let before_log = node.raft.metrics().borrow_watched().last_log_index;
        let generation = node.state_machine.generation().await;
        let failed = tokio::time::timeout(
            Duration::from_secs(2),
            node.ensure_linearizable_with_timeout(Duration::from_millis(50)),
        )
        .await?;
        assert!(failed.is_err(), "a warm state cannot bypass lost quorum");
        assert!(router.blocked_probes.load(Ordering::SeqCst) > prior_probes);
        assert_eq!(node.raft.metrics().borrow_watched().last_log_index, before_log);
        assert_eq!(node.state_machine.generation().await, generation);

        router.mode.store(PASS, Ordering::SeqCst);
        node.ensure_linearizable().await?;
        let second = ReplicatedEnvelope::new("read-index-second", [2; 32], vec![2; 128])?;
        tokio::time::timeout(Duration::from_secs(3), node.replicate(2, &second)).await??;
        node.ensure_linearizable_with_timeout(Duration::from_secs(3)).await?;
        assert_eq!(
            node.latest_envelope().await?.ok_or("missing recovered state")?.digest(),
            second.digest(),
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    router.mode.store(PASS, Ordering::SeqCst);
    router.peers.write().await.clear();
    for node in nodes {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(path)?;
    result
}
