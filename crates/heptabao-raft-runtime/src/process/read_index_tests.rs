//! Real OpenRaft, disk stores and the production RPC codec. The controllable
//! loopback transport proves consensus wait behavior, not TLS or HTTP timing.
use super::*;
use crate::process::{RaftPeerRpc, RaftRpcKind};
use futures::future::BoxFuture;
use openraft::async_runtime::WatchReceiver;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::{Notify, RwLock};

const PASS: u8 = 0;
const BLOCK_LOG_ENTRIES: u8 = 1;
const BLOCK_ALL_APPEND: u8 = 2;
const FAIL_ALL_APPEND_FAST: u8 = 3;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct Router {
    peers: RwLock<BTreeMap<u64, RaftRpcService>>,
    mode: AtomicU8,
    blocked_entries: AtomicUsize,
    blocked_probes: AtomicUsize,
    blocked_target: AtomicU64,
    witness_corruption: AtomicU8,
    read_requests: AtomicUsize,
    pause_read_response: AtomicU8,
    read_response_ready: Notify,
    read_response_release: Notify,
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
                let mode = router.mode.load(Ordering::SeqCst);
                let target_filter = router.blocked_target.load(Ordering::SeqCst);
                let blocked = (target_filter == 0 || target_filter == target)
                    && match mode {
                        BLOCK_LOG_ENTRIES => has_entries,
                        BLOCK_ALL_APPEND | FAIL_ALL_APPEND_FAST => true,
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
                    if mode != FAIL_ALL_APPEND_FAST {
                        tokio::time::sleep(timeout).await;
                    }
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
            if kind == RaftRpcKind::ReadIndex {
                router.read_requests.fetch_add(1, Ordering::SeqCst);
            }
            let response = peer.handle(source, kind, payload).await?;
            if kind == RaftRpcKind::ReadIndex
                && router.pause_read_response.load(Ordering::SeqCst) != 0
            {
                router.read_response_ready.notify_one();
                router.read_response_release.notified().await;
            }
            let corruption = router.witness_corruption.load(Ordering::SeqCst);
            if kind == RaftRpcKind::ReadIndex && corruption != 0 {
                use crate::process::follower_read::{ReadIndexFailure, ReadIndexWitness};
                let mut reply: Result<ReadIndexWitness, ReadIndexFailure> =
                    serde_json::from_slice(&response).map_err(|_| RemoteRaftError::InvalidRpc)?;
                if let Ok(witness) = &mut reply {
                    match corruption {
                        1 => witness.request_id = witness.request_id.saturating_add(1),
                        2 => witness.leader = 3,
                        3 => witness.term = witness.term.saturating_add(1),
                        4 => {
                            witness.leader_applied = openraft::LogId::new(
                                *witness.read_log_id.committed_leader_id(),
                                witness.read_log_id.index().saturating_sub(1),
                            );
                        }
                        _ => return Err(RemoteRaftError::InvalidRpc),
                    }
                }
                return serde_json::to_vec(&reply).map_err(|_| RemoteRaftError::InvalidRpc);
            }
            Ok(response)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_requires_fresh_quorum_own_apply_and_bound_witness_with_one_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-follower-read-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
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
    let result = async {
        let leader = &nodes[0];
        let follower = &nodes[1];
        leader.raft.initialize(BTreeMap::from([(1, ()), (2, ()), (3, ())])).await?;
        leader.raft.trigger().elect(false).await?;
        leader.raft.wait(Some(Duration::from_secs(5))).metrics(
            |m| m.current_leader == Some(1) && m.last_applied.is_some(), "leader committed initial blank",
        ).await?;
        follower.raft.wait(Some(Duration::from_secs(5))).metrics(
            |m| m.current_leader == Some(1) && m.last_applied.is_some(), "follower applied initial blank",
        ).await?;
        follower.ensure_linearizable().await?;
        let warm_generation = follower.state_machine.generation().await;
        let reads_before = router.read_requests.load(Ordering::SeqCst);
        // The leader and third voter can commit while this follower cannot
        // receive entries. Its fresh remote ReadIndex succeeds, but its own
        // apply wait must time out without serving the old application image.
        router.blocked_target.store(2, Ordering::SeqCst);
        router.mode.store(BLOCK_LOG_ENTRIES, Ordering::SeqCst);
        let next = ReplicatedEnvelope::new("follower-read-new", [9; 32], vec![9; 128])?;
        tokio::time::timeout(Duration::from_secs(3), leader.replicate(1, &next)).await??;
        let log_before = leader.raft.metrics().borrow_watched().last_log_index;
        let applied_before = follower.state_machine.last_applied_log_index().await;
        let deadline = std::time::Instant::now() + Duration::from_millis(100);
        let started = std::time::Instant::now();
        let rejected = crate::with_read_index_deadline(deadline, async {
            tokio::time::sleep(Duration::from_millis(40)).await;
            follower.ensure_linearizable_with_timeout(Duration::from_secs(2)).await
        }).await;
        assert!(matches!(rejected, Err(RemoteRaftError::Consensus(ref reason)) if reason == READ_INDEX_TIMEOUT));
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_millis(400), "nested RPC and apply share the absolute caller deadline");
        assert!(router.read_requests.load(Ordering::SeqCst) > reads_before);
        assert_eq!(follower.state_machine.last_applied_log_index().await, applied_before);
        assert_eq!(follower.state_machine.generation().await, warm_generation);
        assert_eq!(leader.raft.metrics().borrow_watched().last_log_index, log_before);
        router.mode.store(PASS, Ordering::SeqCst);
        follower.ensure_linearizable().await?;
        assert_eq!(follower.latest_envelope().await?.ok_or("missing caught-up state")?.digest(), next.digest());
        // A real, authenticated follower witness retains its original 250ms
        // absolute bound during application authentication. Holding the actual
        // production store mutex must reject within that bound; a later scope
        // cannot turn the blocked final generation check into an unbounded wait.
        let started = std::time::Instant::now();
        let original_deadline = started + Duration::from_millis(250);
        let (witness, observed, _) = crate::with_read_index_deadline(
            original_deadline, follower.application_read_witness(),
        ).await?;
        assert_eq!(observed.ok_or("witness application absent")?.digest(), next.digest());
        follower.verify_application_read_witness(&witness).await?;
        let store = follower.state_machine.clone();
        let (acquired, locked) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move { store.hold_application_bundle_until(acquired, released).await; });
        locked.await?;
        let failed = crate::with_read_index_deadline(
            std::time::Instant::now() + Duration::from_secs(5),
            follower.verify_application_read_witness(&witness),
        ).await;
        let elapsed = started.elapsed();
        let _ = release.send(()); holder.await?;
        assert!(matches!(failed, Err(RemoteRaftError::Consensus(ref reason)) if reason == READ_INDEX_TIMEOUT));
        assert!(elapsed >= Duration::from_millis(250));
        assert!(elapsed < Duration::from_millis(650), "held production store cannot extend witness deadline");
        assert!(follower.verify_application_read_witness(&witness).await.is_err(), "released lock cannot revive expired witness");
        // Leader snapshot observation is likewise bounded on the real store.
        let store = leader.state_machine.clone();
        let (acquired, locked) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move { store.hold_application_bundle_until(acquired, released).await; });
        locked.await?;
        let started = std::time::Instant::now();
        let failed = crate::with_read_index_deadline(
            started + Duration::from_millis(250), leader.application_read_witness(),
        ).await;
        let elapsed = started.elapsed();
        let _ = release.send(()); holder.await?;
        assert!(matches!(failed, Err(RemoteRaftError::Consensus(ref reason)) if reason == READ_INDEX_TIMEOUT));
        assert!(elapsed >= Duration::from_millis(250));
        assert!(elapsed < Duration::from_millis(650), "held production store cannot extend initial witness deadline");
        // Each successful read requires a new authenticated request/reply.
        // Corrupt correlation, leader, term, or applied evidence individually;
        // none can substitute for a correctly bound fresh quorum witness.
        for corruption in 1..=4 {
            router.witness_corruption.store(corruption, Ordering::SeqCst);
            assert!(follower.ensure_linearizable_with_timeout(Duration::from_secs(1)).await.is_err());
        }
        router.witness_corruption.store(0, Ordering::SeqCst);
        follower.ensure_linearizable().await?;
        // A warm, fully applied follower is still denied if its real leader
        // loses quorum. ReadIndex cannot become a local-cache fast path.
        router.blocked_target.store(0, Ordering::SeqCst);
        router.mode.store(FAIL_ALL_APPEND_FAST, Ordering::SeqCst);
        let generation = follower.state_machine.generation().await;
        let failed = follower.ensure_linearizable_with_timeout(Duration::from_millis(100)).await;
        assert!(failed.is_err());
        assert_eq!(follower.state_machine.generation().await, generation);
        assert_eq!(leader.raft.metrics().borrow_watched().last_log_index, log_before);
        router.mode.store(PASS, Ordering::SeqCst);
        follower.ensure_linearizable().await?;
        // Pause an actual successful old-leader witness, transfer leadership
        // through OpenRaft's real peer protocol, and deliver that old response
        // only after this follower has observed the new committed term.
        router.pause_read_response.store(1, Ordering::SeqCst);
        let (stale_read, change) = tokio::join!(
            follower.ensure_linearizable_with_timeout(Duration::from_secs(5)),
            async {
                let changed = async {
                    tokio::time::timeout(Duration::from_secs(2), router.read_response_ready.notified()).await?;
                    leader.transfer_leadership(3).await?;
                    nodes[2].raft.wait(Some(Duration::from_secs(3))).metrics(
                        |m| m.state == openraft::ServerState::Leader && m.current_leader == Some(3)
                            && m.vote.committed && m.last_applied.is_some_and(|log| log.committed_leader_id().node_id == 3),
                        "new leader committed its own term",
                    ).await?;
                    follower.raft.wait(Some(Duration::from_secs(3))).metrics(
                        |m| m.current_leader == Some(3) && m.vote.committed,
                        "follower observed leadership change before old reply",
                    ).await?;
                    Ok::<_, Box<dyn std::error::Error>>(())
                }.await;
                router.pause_read_response.store(0, Ordering::SeqCst);
                router.read_response_release.notify_one();
                changed
            }
        );
        change?;
        assert!(matches!(stale_read, Err(RemoteRaftError::Consensus(_))), "old-term real quorum witness cannot authorize after a leader change");
        follower.ensure_linearizable().await?;
        assert_eq!(follower.latest_envelope().await?.ok_or("missing state after leader change")?.digest(), next.digest());
        let invalid = follower.rpc_service().handle(1, RaftRpcKind::ReadIndex, b"{}".to_vec()).await;
        assert!(invalid.is_err(), "malformed or misdirected peer ReadIndex is rejected");
        Ok::<_, Box<dyn std::error::Error>>(())
    }.await;
    router.mode.store(PASS, Ordering::SeqCst);
    router.peers.write().await.clear();
    for node in nodes {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(path)?;
    result
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

        // The same absolute caller deadline covers multiple internal checks,
        // including administration's nested ReadIndex. It cannot restart an
        // eight-second budget when one check or earlier work consumed it.
        let absolute = std::time::Instant::now() + Duration::from_millis(110);
        let snapshot_before = node.raft.metrics().borrow_watched().snapshot;
        tokio::time::timeout(
            Duration::from_secs(2),
            crate::with_read_index_deadline(absolute, async {
                let first = node
                    .ensure_linearizable_with_timeout(Duration::from_millis(40))
                    .await;
                assert!(first.is_err());
                let second = node.snapshot_observed().await;
                assert!(matches!(second, Err(RemoteRaftError::Consensus(ref reason)) if reason == READ_INDEX_TIMEOUT));
                let third = node.change_membership_guarded(0, 2, "remove").await;
                assert!(matches!(third, Err(RemoteRaftError::Consensus(ref reason)) if reason == READ_INDEX_TIMEOUT));
            }),
        )
        .await?;
        assert!(std::time::Instant::now() >= absolute);
        assert_eq!(node.raft.metrics().borrow_watched().snapshot, snapshot_before);
        assert_eq!(node.state_machine.last_applied_log_index().await, before_applied);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transient_quorum_probe_failure_recovers_within_one_read_budget_without_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-read-probe-recovery-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
    ));
    let router = Arc::new(Router::default());
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let factory = RemoteNetworkFactory::new(
            id,
            BTreeSet::from([1, 2, 3]),
            Arc::new(Arc::clone(&router)),
        )?;
        let node = ProcessRaftNode::create(path.join(id.to_string()), id, factory).await?;
        node.raft.runtime_config().elect(false);
        router.peers.write().await.insert(id, node.rpc_service());
        nodes.push(node);
    }
    let result = async {
        let node = &nodes[0];
        node.raft.initialize(BTreeMap::from([(1, ()), (2, ()), (3, ())])).await?;
        node.raft.trigger().elect(false).await?;
        node.raft.wait(Some(Duration::from_secs(5))).metrics(
            |m| m.current_leader == Some(1) && m.last_applied.is_some(),
            "initial leadership and committed blank",).await?;
        node.ensure_linearizable().await?;
        let log_before = node.raft.metrics().borrow_watched().last_log_index;
        let generation_before = node.state_machine.generation().await;
        let probes_before = router.blocked_probes.load(Ordering::SeqCst);
        router.mode.store(FAIL_ALL_APPEND_FAST, Ordering::SeqCst);
        let healer_router = Arc::clone(&router);
        let healer = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), async {
                while healer_router.blocked_probes.load(Ordering::SeqCst) <= probes_before {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }).await?;
            tokio::time::sleep(Duration::from_millis(40)).await;
            healer_router.mode.store(PASS, Ordering::SeqCst);
            Ok::<_, tokio::time::error::Elapsed>(())
        });
        let read = node.ensure_linearizable_with_timeout(Duration::from_secs(2)).await;
        healer.await??;
        read?;
        assert!(router.blocked_probes.load(Ordering::SeqCst) > probes_before);
        assert_eq!(node.raft.metrics().borrow_watched().last_log_index, log_before);
        assert_eq!(node.state_machine.generation().await, generation_before);
        assert!(node.latest_envelope().await?.is_none());

        // A follower obtains a new quorum-backed witness from this actual
        // leader and must apply it locally; it cannot use its warm state alone.
        nodes[1].ensure_linearizable_with_timeout(Duration::from_secs(2)).await?;
        let caller_deadline = std::time::Instant::now() + Duration::from_millis(80);
        router.mode.store(FAIL_ALL_APPEND_FAST, Ordering::SeqCst);
        let rejected = crate::with_read_index_deadline(caller_deadline,
            node.ensure_linearizable_with_timeout(Duration::from_secs(2))).await;
        assert!(matches!(rejected, Err(RemoteRaftError::Consensus(ref reason)) if reason == READ_INDEX_TIMEOUT));
        assert!(std::time::Instant::now() >= caller_deadline);
        assert_eq!(node.raft.metrics().borrow_watched().last_log_index, log_before);
        assert_eq!(node.state_machine.generation().await, generation_before);
        Ok::<_, Box<dyn std::error::Error>>(())
    }.await;
    router.mode.store(PASS, Ordering::SeqCst);
    router.peers.write().await.clear();
    for node in nodes {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(path)?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_current_local_apply_and_metrics_share_original_read_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-leader-own-apply-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
    ));
    let router = Arc::new(Router::default());
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let factory = RemoteNetworkFactory::new(
            id,
            BTreeSet::from([1, 2, 3]),
            Arc::new(Arc::clone(&router)),
        )?;
        let node = ProcessRaftNode::create(path.join(id.to_string()), id, factory).await?;
        node.raft.runtime_config().elect(false);
        router.peers.write().await.insert(id, node.rpc_service());
        nodes.push(node);
    }
    let result = async {
        let leader = &nodes[0];
        leader.raft.initialize(BTreeMap::from([(1, ()), (2, ()), (3, ())])).await?;
        leader.raft.trigger().elect(false).await?;
        leader.raft.wait(Some(Duration::from_secs(5))).metrics(
            |m| m.current_leader == Some(1) && m.last_applied.is_some(), "leader applied initial blank",
        ).await?;
        leader.ensure_linearizable().await?;
        for (learner, expire) in [(4, false), (5, true)] {
            let before_applied = leader.state_machine.last_applied_log_index().await;
            let store = leader.state_machine.clone();
            let (acquired, locked) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            let holder = tokio::spawn(async move { store.hold_application_bundle_until(acquired, released).await; });
            locked.await?;
            let raft = leader.raft.clone();
            let mutation = tokio::spawn(async move { raft.add_learner(learner, (), false).await });
            let committed = leader.raft.wait(Some(Duration::from_secs(3))).metrics(
                |m| m.committed_membership_config.get_node(&learner).is_some()
                    && m.committed_membership_config.log_id().as_ref().is_some_and(|log| Some(log.index) > before_applied),
                "real learner membership committed while leader store is held",
            ).await?;
            let required = committed.committed_membership_config.log_id().as_ref().ok_or("membership log absent")?.index;
            assert!(committed.last_applied.as_ref().map(|log| log.index) < Some(required));
            // This is a genuine successful ReadIndex, independently observed
            // while this leader's real application mutex prevents own apply.
            let probe = tokio::time::timeout(Duration::from_secs(2), leader.raft.get_read_linearizer(ReadPolicy::ReadIndex)).await??;
            assert!(probe.read_log_id().index() >= required);
            assert!(probe.applied().map(|log| log.index) < Some(required));
            let before_log = leader.raft.metrics().borrow_watched().last_log_index;
            let started = std::time::Instant::now();
            let absolute = started + Duration::from_millis(250);
            if expire {
                let denied = crate::with_read_index_deadline(absolute, async {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    leader.ensure_linearizable_with_timeout(Duration::from_secs(2)).await
                }).await;
                assert!(matches!(denied, Err(RemoteRaftError::Consensus(ref reason)) if reason == READ_INDEX_TIMEOUT));
                assert!(started.elapsed() >= Duration::from_millis(250));
                assert!(started.elapsed() < Duration::from_millis(650));
                assert_eq!(leader.raft.metrics().borrow_watched().last_log_index, before_log);
                let _ = release.send(()); holder.await?;
                assert!(crate::with_read_index_deadline(absolute, leader.ensure_linearizable()).await.is_err(), "release cannot renew expired authority");
            } else {
                let releaser = tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    let _ = release.send(());
                });
                crate::with_read_index_deadline(absolute, leader.ensure_linearizable()).await?;
                releaser.await?; holder.await?;
                assert!(started.elapsed() >= Duration::from_millis(150));
                assert!(started.elapsed() < Duration::from_millis(250));
                assert_eq!(leader.raft.metrics().borrow_watched().last_log_index, before_log);
            }
            mutation.await??;
            leader.ensure_linearizable().await?;
            assert!(leader.state_machine.last_applied_log_index().await >= Some(required));
            assert!(leader.raft.metrics().borrow_watched().last_applied.as_ref().map(|log| log.index) >= Some(required));
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }.await;
    router.peers.write().await.clear();
    for node in nodes {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(path)?;
    result
}
