//! Genuine disk Raft campaigns. The transport can reject only unavailable
//! legacy ReadIndex, isolate a voter, or prevent one follower from catching up.
use super::*;
use crate::process::{RaftPeerRpc, RaftRpcKind};
use futures::future::BoxFuture;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[derive(Default)]
struct Router {
    peers: RwLock<BTreeMap<u64, RaftRpcService>>,
    reject_old_read_index: AtomicBool,
    isolate_two: AtomicBool,
    lag_two: AtomicBool,
    halt_append: AtomicBool,
    rejected_lagging_votes: AtomicUsize,
    votes_to_two_peers: AtomicUsize,
    rejected_old_read_index: AtomicUsize,
}
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LegacyUpgradeCampaignRouter")
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
            if kind == RaftRpcKind::ReadIndex
                && target == 1
                && router.reject_old_read_index.load(Ordering::SeqCst)
            {
                router
                    .rejected_old_read_index
                    .fetch_add(1, Ordering::SeqCst);
                return Err(RemoteRaftError::InvalidRpc);
            }
            if kind == RaftRpcKind::AppendEntries && router.halt_append.load(Ordering::SeqCst) {
                return Err(RemoteRaftError::Transport(
                    "owned test heartbeat link blocked".into(),
                ));
            }
            if router.isolate_two.load(Ordering::SeqCst) && (source == 2 || target == 2) {
                return Err(RemoteRaftError::Transport(
                    "owned test link isolated".into(),
                ));
            }
            if router.lag_two.load(Ordering::SeqCst)
                && target == 2
                && kind == RaftRpcKind::AppendEntries
            {
                return Err(RemoteRaftError::Transport(
                    "owned test log link blocked".into(),
                ));
            }
            if source == 2 && kind == RaftRpcKind::Vote {
                let vote: openraft::raft::VoteRequest<crate::TypeConfig> =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                assert!(
                    !vote.leadership_transfer,
                    "upgrade may not forge transfer permission"
                );
                router.votes_to_two_peers.fetch_add(1, Ordering::SeqCst);
            }
            let peer = router
                .peers
                .read()
                .await
                .get(&target)
                .cloned()
                .ok_or(RemoteRaftError::InvalidTopology)?;
            let candidate_log = if source == 2 && kind == RaftRpcKind::Vote {
                let vote: openraft::raft::VoteRequest<crate::TypeConfig> =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                Some(vote.last_log_id)
            } else {
                None
            };
            let response = peer.handle(source, kind, payload).await?;
            if let Some(candidate_log) = candidate_log {
                let observed: Result<
                    openraft::raft::VoteResponse<crate::TypeConfig>,
                    openraft::errors::RaftError<crate::TypeConfig>,
                > = serde_json::from_slice(&response).map_err(|_| RemoteRaftError::InvalidRpc)?;
                if observed.is_ok_and(|observed| {
                    !observed.vote_granted && observed.last_log_id > candidate_log
                }) {
                    router.rejected_lagging_votes.fetch_add(1, Ordering::SeqCst);
                }
            }
            Ok(response)
        })
    }
}
async fn cluster() -> TestResult<(PathBuf, Arc<Router>, Vec<ProcessRaftNode>)> {
    cluster_with_voters(&[1, 2, 3]).await
}
async fn cluster_with_voters(
    voters: &[u64],
) -> TestResult<(PathBuf, Arc<Router>, Vec<ProcessRaftNode>)> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-legacy-upgrade-campaign-{}-{}",
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
    nodes[0]
        .raft
        .initialize(
            voters
                .iter()
                .map(|id| (*id, ()))
                .collect::<BTreeMap<_, _>>(),
        )
        .await?;
    nodes[0].raft.trigger().elect(false).await?;
    for node in &nodes {
        node.raft
            .wait(Some(Duration::from_secs(5)))
            .metrics(
                |m| m.current_leader == Some(1) && m.last_applied.is_some(),
                "actual original leader and applied membership",
            )
            .await?;
    }
    Ok((path, router, nodes))
}
async fn close(path: PathBuf, nodes: Vec<ProcessRaftNode>) -> TestResult {
    for node in nodes {
        node.shutdown().await?;
    }
    std::fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_upgrade_campaign_real_vote_and_read_index_select_capable_leader() -> TestResult {
    let (path, router, nodes) = cluster().await?;
    let result = async {
        let state = crate::ReplicatedEnvelope::new("upgrade-campaign", [5; 32], vec![7; 128])?;
        let receipt = nodes[0].replicate(1, &state).await?;
        for node in &nodes {
            node.raft
                .wait(Some(Duration::from_secs(5)))
                .metrics(
                    |m| m.last_applied.is_some_and(|l| l.index >= receipt.log_index),
                    "actual application before transition",
                )
                .await?;
        }
        let original = nodes[1].membership_observation().await?;
        router.reject_old_read_index.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(8);
        let observed = nodes[1]
            .campaign_for_legacy_upgrade_before(deadline)
            .await?;
        assert_eq!(observed.leader, Some(2));
        assert!(observed.term > original.term);
        assert_eq!(observed.voters, original.voters);
        assert_eq!(observed.membership_index, original.membership_index);
        assert!(observed.committed && !observed.joint);
        assert!(observed.applied_index >= Some(receipt.log_index));
        assert!(Instant::now() < deadline);
        assert!(router.rejected_old_read_index.load(Ordering::SeqCst) > 0);
        assert!(router.votes_to_two_peers.load(Ordering::SeqCst) >= 2);
        let (witness, applied, _) = nodes[1].application_read_witness().await?;
        nodes[1].verify_application_read_witness(&witness).await?;
        assert_eq!(
            applied.ok_or("missing actual application")?.digest(),
            state.digest()
        );
        Ok(())
    }
    .await;
    close(path, nodes).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_upgrade_campaign_lost_quorum_and_original_deadline_never_grant() -> TestResult {
    let (path, router, nodes) = cluster().await?;
    let result = async {
        router.isolate_two.store(true, Ordering::SeqCst);
        let before = nodes[1].membership_observation().await?;
        let deadline = Instant::now() + Duration::from_millis(350);
        assert!(
            nodes[1]
                .campaign_for_legacy_upgrade_before(deadline)
                .await
                .is_err()
        );
        assert!(Instant::now() >= deadline);
        assert!(
            nodes[1]
                .ensure_linearizable_with_timeout(Duration::from_millis(50))
                .await
                .is_err()
        );
        assert_eq!(
            nodes[1].membership_observation().await?.applied_index,
            before.applied_index
        );
        let term = nodes[1].membership_observation().await?.term;
        assert!(
            nodes[1]
                .campaign_for_legacy_upgrade_before(Instant::now())
                .await
                .is_err()
        );
        assert_eq!(nodes[1].membership_observation().await?.term, term);
        Ok(())
    }
    .await;
    close(path, nodes).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_upgrade_campaign_real_lagging_log_is_rejected_by_voters() -> TestResult {
    let (path, router, nodes) = cluster().await?;
    let result = async {
        router.lag_two.store(true, Ordering::SeqCst);
        let state = crate::ReplicatedEnvelope::new("newer-log", [6; 32], vec![9; 128])?;
        let receipt = nodes[0].replicate(1, &state).await?;
        let before = nodes[1].membership_observation().await?;
        assert!(before.applied_index < Some(receipt.log_index));
        router.reject_old_read_index.store(true, Ordering::SeqCst);
        // Stop actual heartbeats and let the real 2000ms maximum lease
        // elapse before the campaign, independently reaching last-log checks.
        router.halt_append.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(2100)).await;
        let deadline = Instant::now() + Duration::from_millis(350);
        assert!(
            nodes[1]
                .campaign_for_legacy_upgrade_before(deadline)
                .await
                .is_err()
        );
        assert_ne!(nodes[1].membership_observation().await?.leader, Some(2));
        assert_eq!(
            nodes[1].membership_observation().await?.applied_index,
            before.applied_index
        );
        assert!(router.votes_to_two_peers.load(Ordering::SeqCst) >= 2);
        assert!(
            router.rejected_lagging_votes.load(Ordering::SeqCst) >= 2,
            "actual voters rejected the older candidate log after leases elapsed"
        );
        Ok(())
    }
    .await;
    close(path, nodes).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_upgrade_campaign_actual_nonvoter_is_refused_without_new_campaign() -> TestResult {
    let (path, router, nodes) = cluster().await?;
    let result = async {
        let prior_term = nodes[1].membership_observation().await?.term;
        // Actual committed membership retains node2 as a learner; no
        // configured peer name can promote it through the upgrade method.
        nodes[0]
            .raft
            .change_membership(BTreeSet::from([1, 3]), true)
            .await?;
        nodes[1]
            .raft
            .wait(Some(Duration::from_secs(5)))
            .metrics(
                |m| {
                    !m.committed_membership_config.voter_ids().any(|id| id == 2)
                        && m.membership_config == m.committed_membership_config
                },
                "actual learner committed",
            )
            .await?;
        let original_votes = router.votes_to_two_peers.load(Ordering::SeqCst);
        assert!(
            nodes[1]
                .campaign_for_legacy_upgrade_before(Instant::now() + Duration::from_secs(1),)
                .await
                .is_err()
        );
        assert_eq!(
            router.votes_to_two_peers.load(Ordering::SeqCst),
            original_votes
        );
        assert_eq!(nodes[1].membership_observation().await?.term, prior_term);
        Ok(())
    }
    .await;
    close(path, nodes).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_upgrade_campaign_actual_unknown_voter_is_not_enrolled_by_names() -> TestResult {
    let (path, router, nodes) = cluster_with_voters(&[1, 2, 3, 4]).await?;
    let result = async {
        let before = nodes[1].membership_observation().await?;
        assert!(before.committed && !before.joint);
        assert!(before.voters.contains(&4));
        let votes = router.votes_to_two_peers.load(Ordering::SeqCst);
        assert!(
            nodes[1]
                .campaign_for_legacy_upgrade_before(Instant::now() + Duration::from_secs(1),)
                .await
                .is_err()
        );
        assert_eq!(nodes[1].membership_observation().await?.term, before.term);
        assert_eq!(router.votes_to_two_peers.load(Ordering::SeqCst), votes);
        Ok(())
    }
    .await;
    close(path, nodes).await?;
    result
}
