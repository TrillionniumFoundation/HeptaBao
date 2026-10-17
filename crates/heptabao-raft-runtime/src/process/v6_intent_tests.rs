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
    isolate_original_leader: AtomicBool,
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
            if router.isolate_original_leader.load(Ordering::SeqCst) && (source == 1 || target == 1)
            {
                return Err(RemoteRaftError::Transport(
                    "test-only original leader disconnected".into(),
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
        // The original applied LogId must survive a *persisted snapshot*
        // after the physical log slot is actually compacted. An object alone
        // or caller-supplied receipt must never fabricate this provenance.
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
        nodes[0]
            .reconcile_exact_staged_v6_intent(&intent, &receipt)
            .await?;
        let mut missing_slot = receipt.clone();
        missing_slot.log_index -= 1;
        assert!(
            nodes[0]
                .reconcile_exact_staged_v6_intent(&intent, &missing_slot)
                .await
                .is_err(),
            "a different purged slot cannot inherit the original snapshot proof"
        );
        let mut false_origin = receipt.clone();
        false_origin.leader_id = 3;
        assert!(
            nodes[0]
                .reconcile_exact_staged_v6_intent(&intent, &false_origin)
                .await
                .is_err(),
            "an unrelated leader cannot assume the original applied identity"
        );
        // The next voter must preserve the same *original* intent LogId
        // through its own physical snapshot and log purge, independent of
        // the first leader's local checkpoint. No V6 application root exists.
        nodes[1].trigger_snapshot().await?;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if nodes[1].membership_observation().await?.purged_index >= Some(receipt.log_index)
                {
                    break Ok::<(), RemoteRaftError>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| "new leader candidate did not compact original intent")??;
        // Deliberately disconnect original leader 1, while voters 2 and 3
        // retain a quorum. A new leader must reestablish fresh ReadIndex
        // instead of reusing the first leader's old client response.
        router.isolate_original_leader.store(true, Ordering::SeqCst);
        // Original setup disables autonomous elections for deterministic
        // bootstrap. Only the survivor is enabled to retry after old leases.
        nodes[1].raft.runtime_config().elect(true);
        nodes[1].raft.trigger().elect(false).await?;
        nodes[1]
            .raft
            .wait(Some(Duration::from_secs(12)))
            .metrics(
                |m| m.current_leader == Some(2),
                "second voter actually wins election after leader isolation",
            )
            .await?;
        nodes[1].ensure_linearizable().await?;
        nodes[1]
            .reconcile_exact_staged_v6_intent(&intent, &receipt)
            .await?;
        // Leader 1 may retain its already committed application and a
        // persisted original-intent snapshot, but cannot supply a new
        // linearizable proof while isolated from all other voters.
        let isolated_old_leader = crate::with_read_index_deadline(
            Instant::now() + Duration::from_millis(120),
            nodes[0].reconcile_exact_staged_v6_intent(&intent, &receipt),
        )
        .await;
        assert!(
            isolated_old_leader.is_err(),
            "original leader's old snapshot cannot grant quorum after failover"
        );
        // The new leader's witness remains valid after that separate refusal.
        nodes[1]
            .reconcile_exact_staged_v6_intent(&intent, &receipt)
            .await?;
        let mut swapped_original = receipt.clone();
        swapped_original.leader_id = 2;
        assert!(
            nodes[1]
                .reconcile_exact_staged_v6_intent(&intent, &swapped_original)
                .await
                .is_err(),
            "new leader must not claim origin of previously committed intent"
        );
        for node in &nodes {
            assert!(node.record_root_at_generation().await?.1.is_none());
        }
        router.deny_append.store(true, Ordering::SeqCst);
        let denied = crate::with_read_index_deadline(
            Instant::now() + Duration::from_millis(120),
            nodes[1].ensure_linearizable(),
        )
        .await;
        assert!(
            denied.is_err(),
            "lost quorum cannot grant new read authority"
        );
        let denied_intent = crate::with_read_index_deadline(
            Instant::now() + Duration::from_millis(120),
            nodes[1].reconcile_exact_staged_v6_intent(&intent, &receipt),
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
        // Full process restart of the SECOND elected leader, not merely
        // opening a read-only state machine after cluster shutdown.
        // Node 1 remains physically isolated; only nodes 2 and 3 may form
        // a fresh quorum after node 2 comes back with its persisted stores.
        //
        // The original V6 intent log entry was physically purged on node 2,
        // so the post-restart proof must come from the original applied
        // LogId preserved in the durable validated state-machine snapshot.
        router.peers.write().await.remove(&2);
        let original_new_leader = nodes.remove(1);
        original_new_leader.shutdown().await?;
        let survivor_without_quorum = crate::with_read_index_deadline(
            Instant::now() + Duration::from_millis(120),
            nodes[1].ensure_linearizable(),
        )
        .await;
        assert!(
            survivor_without_quorum.is_err(),
            "single surviving voter cannot authorize writes or ReadIndex",
        );
        let recovered_network =
            RemoteNetworkFactory::new(2, BTreeSet::from([1, 2, 3]), Arc::new(Arc::clone(&router)))?;
        let recovered = ProcessRaftNode::reopen(root.join("2"), 2, recovered_network).await?;
        recovered.raft.runtime_config().elect(true);
        router
            .peers
            .write()
            .await
            .insert(2, recovered.rpc_service());
        nodes.insert(1, recovered);
        nodes[1].raft.trigger().elect(false).await?;
        nodes[1]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(
                |m| m.current_leader == Some(2),
                "reopened second leader must regain a real surviving quorum",
            )
            .await?;
        nodes[1].ensure_linearizable().await?;
        assert!(
            nodes[1].membership_observation().await?.purged_index >= Some(receipt.log_index),
            "restart cannot silently reconstruct a purged original log entry",
        );
        nodes[1]
            .reconcile_exact_staged_v6_intent(&intent, &receipt)
            .await?;
        assert!(
            nodes[1]
                .reconcile_exact_staged_v6_intent(&intent, &swapped_original)
                .await
                .is_err(),
            "restarted leader 2 cannot claim the old leader 1's LogId",
        );
        let stale_original = crate::with_read_index_deadline(
            Instant::now() + Duration::from_millis(120),
            nodes[0].reconcile_exact_staged_v6_intent(&intent, &receipt),
        )
        .await;
        assert!(
            stale_original.is_err(),
            "original isolated leader remains fenced after new-leader restart",
        );
        for node in &nodes {
            assert!(
                node.record_root_at_generation().await?.1.is_none(),
                "recovered V6 intent is still NOT native V6 root publication",
            );
        }
        Ok::<_, Box<dyn std::error::Error>>((object, receipt))
    }
    .await;
    router.deny_append.store(false, Ordering::SeqCst);
    router
        .isolate_original_leader
        .store(false, Ordering::SeqCst);
    router.peers.write().await.clear();
    for node in nodes {
        node.shutdown().await?;
    }
    // Cold-open every real local state machine independently, including both
    // former followers. Nothing was published to the V5/V6 application root.
    if let Ok((object, receipt)) = &result {
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
            if id == 1 || id == 2 {
                let persisted = state
                    .durable_snapshot_v6_intent_log_id(&object.reference().id, receipt.log_index)
                    .await?
                    .ok_or("persisted intent LogId lost after cold restart")?;
                assert_eq!(persisted.index, receipt.log_index);
                assert_eq!(persisted.committed_leader_id().node_id, receipt.leader_id);
            }
            assert!(state.record_root_at_generation().await.1.is_none());
        }
    }
    std::fs::remove_dir_all(root)?;
    result.map(|_| ())
}
