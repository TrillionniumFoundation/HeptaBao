//! The actual durable 3-voter OpenRaft state machine through its production
//! bounded Raft RPC codec, on an IN-PROCESS synthetic router.  This does NOT
//! qualify physical mTLS, an authenticated membership claim, V6 root CAS, or
//! a client success acknowledgement.
use super::*;
use crate::{NativeV6CommitIntent, RecordObjectKind, SealedRecordObject};
use futures::future::BoxFuture;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

static SEQ: AtomicU64 = AtomicU64::new(0);
#[derive(Default)]
struct Router {
    peers: RwLock<BTreeMap<u64, RaftRpcService>>,
    deny_append: AtomicBool,
}
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateV6CommitIntentInProcessRaftRouter")
    }
}
impl RaftPeerRpc for Arc<Router> {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        bytes: Vec<u8>,
        _timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        let router = Arc::clone(self);
        Box::pin(async move {
            if router.deny_append.load(Ordering::SeqCst)
                && matches!(kind, RaftRpcKind::AppendEntries)
            {
                return Err(RemoteRaftError::Transport(
                    "test-only quorum separation".into(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_real_raft_voters_commit_typed_v6_intent_but_never_publish_v6_root()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "hb-v6-intent-raft-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    let router = Arc::new(Router::default());
    let mut nodes = Vec::new();
    for id in 1..=3_u64 {
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
    let result = async {
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
                "three actual durable voters ready for V6 intent staging",
            )
            .await?;
        nodes[0].ensure_linearizable().await?;
        let prior_applied = nodes[0]
            .membership_observation()
            .await?
            .applied_index
            .ok_or("missing committed Raft predecessor")?;
        let intent = NativeV6CommitIntent {
            cluster_digest: [1; 32],
            epoch: 7,
            operation_digest: [2; 32],
            closure_manifest_sha256: [3; 32],
            object_count: 556,
            ciphertext_bytes: 139 * 1024 * 1024,
            prior_root_digest: [4; 32],
            proposed_root_digest: [5; 32],
            prior_generation: 20,
            proposed_generation: 21,
            expected_previous_commit_index: prior_applied,
        };
        let object = SealedRecordObject::new_native_v6_commit_intent(intent)?;
        assert_eq!(
            object.reference().kind,
            RecordObjectKind::NativeV6CommitIntent
        );
        assert_eq!(
            crate::NativeV6CommitIntent::decode(object.sealed())
                .map_err(|_| "invalid staged intent")?,
            intent
        );
        let serial = nodes[0].next_production_client_serial().await?;
        let receipt = tokio::time::timeout(
            Duration::from_secs(5),
            nodes[0].stage_application_object(serial, &object),
        )
        .await??;
        assert!(receipt.log_index > prior_applied);
        nodes[0]
            .reconcile_exact_staged_v6_intent(&intent, &receipt)
            .await?;
        let mut wrong_slot = receipt.clone();
        wrong_slot.log_index -= 1;
        assert!(
            nodes[0]
                .reconcile_exact_staged_v6_intent(&intent, &wrong_slot)
                .await
                .is_err(),
            "a previous membership or blank log slot cannot launder an intent"
        );
        let mut wrong_digest = receipt.clone();
        wrong_digest.envelope_digest[0] ^= 1;
        assert!(
            nodes[0]
                .reconcile_exact_staged_v6_intent(&intent, &wrong_digest)
                .await
                .is_err()
        );
        let mut wrong_leader = receipt.clone();
        wrong_leader.leader_id = 3;
        assert!(
            nodes[0]
                .reconcile_exact_staged_v6_intent(&intent, &wrong_leader)
                .await
                .is_err()
        );
        let mut wrong_intent = intent;
        wrong_intent.operation_digest[0] ^= 1;
        assert!(
            nodes[0]
                .reconcile_exact_staged_v6_intent(&wrong_intent, &receipt)
                .await
                .is_err()
        );
        // Wait for the actual follower apply path, not merely for one leader
        // acknowledgment. The object is tiny even for 139 MiB of external
        // ciphertext, and still grants no local-custody or root authority.
        tokio::time::timeout(Duration::from_secs(7), async {
            loop {
                let mut all = true;
                for node in &nodes {
                    if node.application_object(object.reference()).await? != Some(object.clone()) {
                        all = false;
                    }
                }
                if all {
                    break Ok::<(), crate::RaftRuntimeError>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        for node in &nodes {
            let (_, root) = node.record_root_at_generation().await?;
            assert!(root.is_none(), "a committed intent MUST NOT publish a root");
        }
        // Losing both follower append paths denies a new linearizable
        // observation.  Prior committed intent stays intact and no root
        // authorization is inferred.
        // A snapshot may retain the application object after purging the exact
        // original Raft log slot.  Neither the durable application object nor
        // an older client receipt can then recreate the missing provenance.
        nodes[0].trigger_snapshot().await?;
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                if nodes[0].membership_observation().await?.purged_index >= Some(receipt.log_index)
                {
                    break Ok::<(), RemoteRaftError>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| "explicit V6 intent source log was not actually purged")??;
        assert_eq!(
            nodes[0].application_object(object.reference()).await?,
            Some(object.clone()),
            "snapshot must retain the committed immutable intent object"
        );
        nodes[0].ensure_linearizable().await?;
        assert!(
            nodes[0]
                .reconcile_exact_staged_v6_intent(&intent, &receipt)
                .await
                .is_err(),
            "an already-purged log entry cannot be reconstructed from only an application object"
        );
        router.deny_append.store(true, Ordering::SeqCst);
        let denied = crate::with_read_index_deadline(
            Instant::now() + Duration::from_millis(120),
            nodes[0].ensure_linearizable(),
        )
        .await;
        assert!(
            denied.is_err(),
            "lost quorum cannot grant new read authority"
        );
        let denied_intent = crate::with_read_index_deadline(
            Instant::now() + Duration::from_millis(120),
            nodes[0].reconcile_exact_staged_v6_intent(&intent, &receipt),
        )
        .await;
        assert!(
            denied_intent.is_err(),
            "existing staged object and old receipt cannot bypass lost quorum"
        );
        for node in &nodes {
            assert!(node.record_root_at_generation().await?.1.is_none());
        }
        router.deny_append.store(false, Ordering::SeqCst);
        Ok::<_, Box<dyn std::error::Error>>(object)
    }
    .await;
    router.deny_append.store(false, Ordering::SeqCst);
    router.peers.write().await.clear();
    for node in nodes {
        node.shutdown().await?;
    }
    // Cold-open every real local state machine independently, including both
    // former followers. Nothing was published to the V5/V6 application root.
    if let Ok(object) = &result {
        for id in 1..=3 {
            let state = crate::store::DurableStateMachine::open_existing(
                root.join(id.to_string()).join("state-machine"),
            )?;
            assert_eq!(
                state
                    .record_object(object.reference())
                    .await
                    .map_err(|_| "invalid stored object")?,
                Some(object.clone())
            );
            assert!(state.record_root_at_generation().await.1.is_none());
        }
    }
    std::fs::remove_dir_all(root)?;
    result.map(|_| ())
}
