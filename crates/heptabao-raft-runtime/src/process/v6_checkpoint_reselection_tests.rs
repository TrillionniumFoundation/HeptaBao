//! Real durable three-voter OpenRaft and RPC codec over an in-process router.
//! This qualifies checkpoint classification and read rejection, not physical
//! hosts, TLS, external-cipher custody or an HTTP publication acknowledgement.
use super::*;
use crate::process::{RaftPeerRpc, RaftRpcKind, RaftRpcService, RemoteNetworkFactory};
use crate::{
    NativeV6CommitIntent, NativeV6PeerEnrollment, PublishedRecordRoot, RecordRootBase,
    SealedRecordObject,
};
use futures::future::BoxFuture;
use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant as StdInstant};
use tokio::sync::RwLock;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct Router {
    peers: RwLock<BTreeMap<u64, RaftRpcService>>,
    block_append: AtomicBool,
}
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GeneratedCheckpointActualRaftTestRouter")
    }
}
impl RaftPeerRpc for Arc<Router> {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        bytes: Vec<u8>,
        timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        let router = Arc::clone(self);
        Box::pin(async move {
            if router.block_append.load(Ordering::SeqCst) && kind == RaftRpcKind::AppendEntries {
                tokio::time::sleep(timeout).await;
                return Err(RemoteRaftError::Transport(
                    "owned test voter unavailable".into(),
                ));
            }
            let peer = router
                .peers
                .read()
                .await
                .get(&target)
                .cloned()
                .ok_or(RemoteRaftError::InvalidTopology)?;
            peer.handle(source, kind, bytes).await
        })
    }
}

struct Fixture {
    root: PathBuf,
    router: Arc<Router>,
    nodes: Vec<ProcessRaftNode>,
    intent: NativeV6CommitIntent,
    staged: CommitReceipt,
    enrollment: NativeV6PeerEnrollment,
}
fn bound() -> StdInstant {
    StdInstant::now() + Duration::from_secs(8)
}
impl Fixture {
    async fn start() -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "hb-checkpoint-reselect-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::SeqCst),
        ));
        std::fs::create_dir(&root)?;
        let router = Arc::new(Router::default());
        let mut nodes = Vec::new();
        for id in 1..=3 {
            let network = RemoteNetworkFactory::new(
                id,
                BTreeSet::from([1, 2, 3]),
                Arc::new(Arc::clone(&router)),
            )?;
            let node = ProcessRaftNode::create(root.join(id.to_string()), id, network).await?;
            node.raft.runtime_config().elect(false);
            router.peers.write().await.insert(id, node.rpc_service());
            nodes.push(node);
        }
        let prepared = async {
            let leader = &nodes[0];
            leader
                .raft
                .initialize(BTreeMap::from([(1, ()), (2, ()), (3, ())]))
                .await?;
            leader.raft.trigger().elect(false).await?;
            leader
                .raft
                .wait(Some(Duration::from_secs(5)))
                .metrics(
                    |m| m.current_leader == Some(1) && m.last_applied.is_some(),
                    "generated checkpoint voters ready",
                )
                .await?;
            leader.ensure_linearizable().await?;
            let v5 = PublishedRecordRoot::new(
                RecordRootBase::Empty,
                ReplicatedEnvelope::new("owned-checkpoint-v5-source", [4; 32], vec![0x44; 32])?,
                Vec::new(),
            )?;
            leader
                .publish_application_root(leader.next_production_client_serial().await?, &v5)
                .await?;
            let source = leader
                .native_v6_migration_source()
                .await
                .ok_or("V5 source missing")?;
            let enrollment = leader
                .enroll_native_v6_peers(
                    leader.next_production_client_serial().await?,
                    [1; 32],
                    7,
                    BTreeMap::from([(1, [11; 32]), (2, [22; 32]), (3, [33; 32])]),
                    bound(),
                )
                .await?;
            let intent = NativeV6CommitIntent {
                cluster_digest: [1; 32],
                epoch: 7,
                operation_digest: [2; 32],
                closure_manifest_sha256: [3; 32],
                object_count: 1,
                ciphertext_bytes: 128,
                prior_root_digest: source.0,
                proposed_root_digest: [5; 32],
                prior_generation: 0,
                proposed_generation: 1,
                expected_previous_commit_index: source.1.index,
            };
            let object = SealedRecordObject::new_native_v6_commit_intent(intent)?;
            let staged = leader
                .stage_application_object(leader.next_production_client_serial().await?, &object)
                .await?;
            Ok::<_, Box<dyn std::error::Error>>((intent, staged, enrollment))
        }
        .await;
        match prepared {
            Ok((intent, staged, enrollment)) => Ok(Self {
                root,
                router,
                nodes,
                intent,
                staged,
                enrollment,
            }),
            Err(error) => {
                router.peers.write().await.clear();
                for node in nodes {
                    let _ = node.shutdown().await;
                }
                let _ = std::fs::remove_dir_all(root);
                Err(error)
            }
        }
    }
    async fn checkpoint(&self) -> TestResult {
        // Invoke the real generated snapshot builder, including durable bundle
        // persistence and journal replacement. No generation/data is supplied.
        let mut store = self.nodes[0].state_machine.clone();
        let snapshot = store.build_snapshot().await?;
        assert_eq!(
            snapshot.meta.last_log_id.map(|log| log.index),
            Some(self.staged.log_index)
        );
        Ok(())
    }
    async fn finish(self) -> TestResult {
        self.router.block_append.store(false, Ordering::SeqCst);
        self.router.peers.write().await.clear();
        let mut failure = None;
        for node in self.nodes {
            if let Err(error) = node.shutdown().await {
                failure = Some(error);
            }
        }
        std::fs::remove_dir_all(self.root)?;
        if let Some(error) = failure {
            return Err(error.into());
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generated_checkpoint_fresh_quorum_keeps_old_witness_invalid_and_exact_stage() -> TestResult
{
    let fixture = Fixture::start().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let (old, enrollment, root) = node.native_v6_application_read_witness(bound()).await?;
        assert_eq!(enrollment.as_ref(), Some(&fixture.enrollment));
        assert!(root.is_none());
        let prefix = old.completed_prefix();
        assert_eq!(prefix.index(), fixture.staged.log_index);
        // Current proof alone is NOT a reason to enter a checkpoint fallback.
        assert!(
            node.native_v6_read_after_generated_checkpoint(&old, bound())
                .await
                .is_err()
        );
        fixture.checkpoint().await?;
        assert!(node.verify_application_read_witness(&old).await.is_err());
        let (fresh, after_enrollment, after_root) = node
            .native_v6_read_after_generated_checkpoint(&old, bound())
            .await?;
        assert_eq!(fresh.completed_prefix(), prefix);
        assert!(fresh.deadline() <= old.deadline());
        assert_eq!(after_enrollment, enrollment);
        assert_eq!(after_root, root);
        node.verify_application_read_witness(&fresh).await?;
        assert!(node.verify_application_read_witness(&old).await.is_err());
        crate::with_read_index_deadline(old.deadline(), async {
            node.reconcile_exact_staged_v6_intent(&fixture.intent, &fixture.staged)
                .await?;
            let admission = node
                .admit_native_v6_closure(&fixture.intent, old.deadline())
                .await?;
            assert_eq!(admission.intent(), &fixture.intent);
            assert_eq!(admission.intent_log_id().index, fixture.staged.log_index);
            assert_eq!(admission.enrollment(), &fixture.enrollment);
            assert!(admission.deadline() <= old.deadline());
            node.verify_native_v6_closure_admission(&admission).await?;
            let mut wrong = fixture.staged.clone();
            wrong.envelope_digest[0] ^= 1;
            assert!(
                node.reconcile_exact_staged_v6_intent(&fixture.intent, &wrong)
                    .await
                    .is_err()
            );
            wrong = fixture.staged.clone();
            wrong.leader_id = 2;
            assert!(
                node.reconcile_exact_staged_v6_intent(&fixture.intent, &wrong)
                    .await
                    .is_err()
            );
            wrong = fixture.staged.clone();
            wrong.log_index -= 1;
            assert!(
                node.reconcile_exact_staged_v6_intent(&fixture.intent, &wrong)
                    .await
                    .is_err()
            );
            let mut different = fixture.intent;
            different.operation_digest[0] ^= 1;
            assert!(
                node.admit_native_v6_closure(&different, old.deadline())
                    .await
                    .is_err()
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?;
        let (last, _, no_root) = node
            .native_v6_application_read_witness(old.deadline())
            .await?;
        assert_eq!(
            last.completed_prefix(),
            prefix,
            "no read may replay Stage or invoke root CAS"
        );
        assert!(no_root.is_none());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generated_checkpoint_other_store_and_same_prefix_install_are_refused() -> TestResult {
    let fixture = Fixture::start().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let (old, _, _) = node.native_v6_application_read_witness(bound()).await?;
        fixture.checkpoint().await?;
        assert!(
            fixture.nodes[1]
                .native_v6_read_after_generated_checkpoint(&old, bound())
                .await
                .is_err()
        );
        let mut store = node.state_machine.clone();
        let snapshot = store
            .get_current_snapshot()
            .await?
            .ok_or("checkpoint snapshot missing")?;
        store
            .install_snapshot(&snapshot.meta, snapshot.snapshot)
            .await?;
        assert!(
            node.native_v6_read_after_generated_checkpoint(&old, bound())
                .await
                .is_err()
        );
        fixture.checkpoint().await?;
        assert!(
            node.native_v6_read_after_generated_checkpoint(&old, bound())
                .await
                .is_err()
        );
        assert!(node.verify_application_read_witness(&old).await.is_err());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generated_checkpoint_intervening_applied_command_cannot_reselect_old_source() -> TestResult
{
    let fixture = Fixture::start().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let (old, _, _) = node.native_v6_application_read_witness(bound()).await?;
        fixture.checkpoint().await?;
        let next = NativeV6CommitIntent {
            operation_digest: [8; 32],
            ..fixture.intent
        };
        let object = SealedRecordObject::new_native_v6_commit_intent(next)?;
        let next_receipt = node
            .stage_application_object(node.next_production_client_serial().await?, &object)
            .await?;
        assert!(next_receipt.log_index > fixture.staged.log_index);
        let mut store = node.state_machine.clone();
        store.build_snapshot().await?;
        assert!(
            node.native_v6_read_after_generated_checkpoint(&old, bound())
                .await
                .is_err()
        );
        assert!(node.verify_application_read_witness(&old).await.is_err());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generated_checkpoint_lost_quorum_keeps_active_original_deadline() -> TestResult {
    let fixture = Fixture::start().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let (old, _, _) = node.native_v6_application_read_witness(bound()).await?;
        fixture.checkpoint().await?;
        assert!(StdInstant::now() < old.deadline());
        fixture.router.block_append.store(true, Ordering::SeqCst);
        let started = StdInstant::now();
        let until = started + Duration::from_millis(400);
        let refused = crate::with_read_index_deadline(
            until,
            node.native_v6_read_after_generated_checkpoint(&old, bound()),
        )
        .await;
        assert!(refused.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(700),
            "400ms authority bound plus 300ms scheduler tolerance; no renewed 8s wait"
        );
        assert!(node.verify_application_read_witness(&old).await.is_err());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generated_checkpoint_expired_witness_cannot_use_later_request_scope() -> TestResult {
    let fixture = Fixture::start().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let selected_until = StdInstant::now() + Duration::from_secs(2);
        let (old, _, _) = node
            .native_v6_application_read_witness(selected_until)
            .await?;
        fixture.checkpoint().await?;
        tokio::time::sleep_until(tokio::time::Instant::from_std(old.deadline())).await;
        let started = StdInstant::now();
        let refused = crate::with_read_index_deadline(
            bound(),
            node.native_v6_read_after_generated_checkpoint(&old, bound()),
        )
        .await;
        assert!(refused.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "expired original proof must not enter a fresh quorum wait"
        );
        assert!(node.verify_application_read_witness(&old).await.is_err());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}
