//! Actual durable Raft root CAS, snapshot/leader restart, and external-object
//! recovery. The RPC router and TLS pins are synthetic; this is not a physical
//! host network, real barrier crypto, quorum-fsync/Actor or HTTP ACK test.
use super::*;
use crate::{
    CommitReceipt, LocalV6BlobStage, NativeV6CommitIntent, PublishedRecordRoot, RecordRootBase,
    ReplicatedEnvelope, SealedRecordObject,
};
use futures::future::BoxFuture;
use openraft::Instant as _;
use openraft::async_runtime::WatchReceiver;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
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
    isolated: AtomicBool,
}
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("V6RootTestRouter")
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
            if router.isolated.load(Ordering::SeqCst) && (source == 1 || target == 1) {
                return Err(RemoteRaftError::Transport(
                    "test leader disconnected".into(),
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
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn receipt(root: &crate::NativeV6PublishedRoot) -> CommitReceipt {
    CommitReceipt {
        leader_id: root.publication_log_id().committed_leader_id().node_id,
        log_index: root.publication_log_id().index,
        envelope_digest: root.root_digest(),
    }
}

/// Fixture readiness only, never a read or publication capability. Restart
/// restores each old committed vote before heartbeat replication has renewed
/// the leader's write lease. A successful ReadIndex does not itself update
/// OpenRaft's replication-heartbeat lease, so neither it nor a remembered
/// current_leader field is sufficient to start the next unique client write.
async fn cold_ready_leader(nodes: &[ProcessRaftNode]) -> Result<usize, Box<dyn std::error::Error>> {
    let until = tokio::time::Instant::now() + Duration::from_secs(7);
    let voters: BTreeSet<_> = nodes.iter().map(ProcessRaftNode::id).collect();
    let selected = tokio::time::timeout_at(until, async {
        loop {
            let observed: Vec<_> = nodes
                .iter()
                .map(|node| node.raft.metrics().borrow_watched().clone())
                .collect();
            for (index, leader) in observed.iter().enumerate() {
                let Some(committed) = leader.local_committed else {
                    continue;
                };
                if leader.state != openraft::ServerState::Leader
                    || !leader.vote.committed
                    || leader.vote.leader_id.node_id != leader.id
                    || leader.vote.leader_id.term != leader.current_term
                    || committed.committed_leader_id().node_id != leader.id
                    || committed.committed_leader_id().term != leader.current_term
                    || !leader
                        .last_quorum_acked
                        .as_ref()
                        .is_some_and(|acked| acked.elapsed() < Duration::from_millis(200))
                    || leader.committed_membership_config.get_joint_config().len() != 1
                    || leader
                        .committed_membership_config
                        .voter_ids()
                        .collect::<BTreeSet<_>>()
                        != voters
                {
                    continue;
                }
                let same_committed_leader = observed.iter().all(|peer| {
                    peer.running_state.is_ok()
                        && peer.vote == leader.vote
                        && peer.current_term == leader.current_term
                        && peer.current_leader == Some(leader.id)
                        && peer.state
                            == if peer.id == leader.id {
                                openraft::ServerState::Leader
                            } else {
                                openraft::ServerState::Follower
                            }
                        && peer.membership_config == peer.committed_membership_config
                        && peer.committed_membership_config
                            == leader.committed_membership_config
                        && peer.local_committed >= Some(committed)
                        && peer.last_applied >= Some(committed)
                });
                if same_committed_leader && tokio::time::Instant::now() < until {
                    eprintln!(
                        "V6 cold fixture ready: leader={} term={} committed={} all_voters_applied=true heartbeat_quorum_acked=true",
                        leader.id, leader.current_term, committed.index
                    );
                    return index;
                }
            }
            tokio::time::sleep_until(
                (tokio::time::Instant::now() + Duration::from_millis(20)).min(until),
            )
            .await;
        }
    })
    .await?;
    Ok(selected)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_real_raft_root_cas_external_34mib_snapshot_failover_and_cold_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "hb-v6-root-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
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
    let mut stage = "initialize and elect actual voters";
    let result = async {
        nodes[0]
            .raft
            .initialize(BTreeMap::from([(1, ()), (2, ()), (3, ())]))
            .await?;
        nodes[0].raft.trigger().elect(false).await?;
        nodes[0]
            .raft
            .wait(Some(Duration::from_secs(7)))
            .metrics(
                |m| m.current_leader == Some(1) && m.last_applied.is_some(),
                "V6 root fixture leader",
            )
            .await?;
        nodes[0].ensure_linearizable().await?;
        stage = "publish original V5 source";
        let v5 = PublishedRecordRoot::new(
            RecordRootBase::Empty,
            ReplicatedEnvelope::new("synthetic-v5-source", [4; 32], vec![0x44; 32])?,
            Vec::new(),
        )?;
        let v5_receipt = nodes[0]
            .publish_application_root(nodes[0].next_production_client_serial().await?, &v5)
            .await?;
        let source = nodes[0]
            .native_v6_migration_source()
            .await
            .ok_or("actual V5 source absent")?;
        assert_eq!(source.0, v5.envelope().digest());
        assert_eq!(source.1.index, v5_receipt.log_index);
        let (before_native, no_enrollment, no_native_root) = nodes[0]
            .native_v6_application_read_witness(deadline())
            .await?;
        assert!(no_enrollment.is_none() && no_native_root.is_none());
        nodes[0]
            .verify_application_read_witness(&before_native)
            .await?;
        assert!(
            nodes[0]
                .native_v6_committed_root_read(deadline())
                .await?
                .is_none()
        );
        let (old_v5_witness, _, old_v5_root) = nodes[0].application_read_witness().await?;
        assert_eq!(old_v5_root.as_ref(), Some(&v5));
        stage = "commit actual membership and pin enrollment";
        let enrollment = nodes[0]
            .enroll_native_v6_peers(
                nodes[0].next_production_client_serial().await?,
                [1; 32],
                7,
                BTreeMap::from([(1, [11; 32]), (2, [22; 32]), (3, [33; 32])]),
                deadline(),
            )
            .await?;
        assert_eq!(
            enrollment.membership_log_id().index,
            0,
            "pinned OpenRaft genesis membership remains bound to its actual zero slot"
        );
        assert_eq!(enrollment.membership_log_id().committed_leader_id().term, 0);
        assert_eq!(
            enrollment.membership_log_id().committed_leader_id().node_id,
            1
        );
        let enrollment_digest = enrollment.digest();
        // A different trusted-config claim cannot silently replace committed pins.
        assert!(
            nodes[0]
                .enroll_native_v6_peers(
                    nodes[0].next_production_client_serial().await?,
                    [1; 32],
                    7,
                    BTreeMap::from([(1, [11; 32]), (2, [22; 32]), (3, [34; 32])]),
                    deadline()
                )
                .await
                .is_err()
        );
        stage = "persist real external 34 MiB closure on each voter";
        let mut refs = Vec::new();
        let mut local_receipt = None;
        for id in 1..=3 {
            let dir = root.join(format!("external-{id}"));
            fs::create_dir(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            let store = LocalV6BlobStage::open_existing(&dir)?;
            let mut selected = Vec::new();
            // A real 34 MiB of opaque ciphertext per replica, not declared bytes.
            for index in 0..136u32 {
                let mut bytes = vec![0x93; 256 * 1024];
                bytes[..4].copy_from_slice(&index.to_be_bytes());
                selected.push(store.stage_local(&bytes)?.reference().clone());
            }
            let observed = store.persist_local_closure(&selected, &mut || Ok(()))?;
            assert_eq!(observed.ciphertext_bytes(), 34 * 1024 * 1024);
            assert_eq!(
                store.persist_local_closure(&selected, &mut || Ok(()))?,
                observed
            );
            if id == 1 {
                refs = selected;
                local_receipt = Some(observed);
            } else {
                assert_eq!(Some(observed), local_receipt);
            }
        }
        let closure = local_receipt.ok_or("missing actual local closure")?;
        stage = "stage first native intent";
        let intent = NativeV6CommitIntent {
            cluster_digest: [1; 32],
            epoch: 7,
            operation_digest: [2; 32],
            closure_manifest_sha256: closure.manifest_sha256(),
            object_count: closure.object_count() as u64,
            ciphertext_bytes: closure.ciphertext_bytes(),
            prior_root_digest: source.0,
            proposed_root_digest: [5; 32],
            prior_generation: 0,
            proposed_generation: 1,
            expected_previous_commit_index: source.1.index,
        };
        let object = SealedRecordObject::new_native_v6_commit_intent(intent)?;
        let staged = nodes[0]
            .stage_application_object(nodes[0].next_production_client_serial().await?, &object)
            .await?;
        stage = "publish first native root CAS";
        let first = nodes[0]
            .publish_native_v6_root(
                nodes[0].next_production_client_serial().await?,
                &intent,
                &staged,
                &enrollment,
                vec![0x55; 64],
                deadline(),
            )
            .await?;
        assert_eq!(first.generation(), 1);
        assert_eq!(first.intent_log_id().index, staged.log_index);
        assert_eq!(first.migration_source(), source);
        assert!(first.publication_log_id().index > staged.log_index);
        assert_eq!(first.enrollment_digest(), enrollment.digest());
        assert!(matches!(nodes[0].application_read_witness().await,
            Err(RemoteRaftError::Consensus(reason))
                if reason == "legacy application read fenced by committed native root"));
        assert!(
            nodes[0]
                .verify_application_read_witness(&old_v5_witness)
                .await
                .is_err()
        );
        assert!(
            nodes[0].record_root_at_generation().await?.1.is_none(),
            "retained V5 migration source is not the current readable application root"
        );
        stage = "stage competing native intents";
        let next = NativeV6CommitIntent {
            operation_digest: [3; 32],
            prior_root_digest: first.root_digest(),
            proposed_root_digest: [6; 32],
            prior_generation: 1,
            proposed_generation: 2,
            expected_previous_commit_index: first.publication_log_id().index,
            ..intent
        };
        let conflicting = NativeV6CommitIntent {
            operation_digest: [8; 32],
            proposed_root_digest: [7; 32],
            ..next
        };
        let next_object = SealedRecordObject::new_native_v6_commit_intent(next)?;
        let next_staged = nodes[0]
            .stage_application_object(
                nodes[0].next_production_client_serial().await?,
                &next_object,
            )
            .await?;
        let conflicting_object = SealedRecordObject::new_native_v6_commit_intent(conflicting)?;
        let conflicting_staged = nodes[0]
            .stage_application_object(
                nodes[0].next_production_client_serial().await?,
                &conflicting_object,
            )
            .await?;
        stage = "publish second native root CAS";
        let current = nodes[0]
            .publish_native_v6_root(
                nodes[0].next_production_client_serial().await?,
                &next,
                &next_staged,
                &enrollment,
                vec![0x66; 64],
                deadline(),
            )
            .await?;
        assert_eq!(current.generation(), 2);
        stage = "reject conflicting CAS and obsolete V5 publication";
        assert!(
            nodes[0]
                .publish_native_v6_root(
                    nodes[0].next_production_client_serial().await?,
                    &conflicting,
                    &conflicting_staged,
                    &enrollment,
                    vec![0x77; 64],
                    deadline()
                )
                .await
                .is_err()
        );
        assert_eq!(
            nodes[0].native_v6_root_at_generation().await.1,
            Some(current.clone())
        );
        assert!(
            nodes[0]
                .publish_application_root(nodes[0].next_production_client_serial().await?, &v5)
                .await
                .is_err()
        );
        let mut wrong = receipt(&current);
        wrong.log_index -= 1;
        assert!(
            nodes[0]
                .reconcile_native_v6_root(&next, &wrong, deadline())
                .await
                .is_err()
        );
        assert_eq!(
            nodes[0].native_v6_root_at_generation().await.1,
            Some(current.clone())
        );
        stage = "replicate and compact native root snapshots on all voters";
        nodes[0].ensure_linearizable().await?;
        let committed = nodes[0]
            .raft
            .metrics()
            .borrow_watched()
            .last_applied
            .ok_or("leader has no applied publication prefix")?;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let mut all = true;
                for node in &nodes {
                    all &= node.native_v6_root_at_generation().await.1 == Some(current.clone());
                    // Include the committed rejection entries after the root,
                    // so root equality alone cannot conceal a lagging voter.
                    all &= node
                        .raft
                        .metrics()
                        .borrow_watched()
                        .last_applied
                        .is_some_and(|applied| applied >= committed);
                }
                if all {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        for node in &nodes {
            let mut state = node.state_machine.get_state_machine().await;
            let snapshot = state.snapshot_bytes()?;
            assert!(
                snapshot.len() < 128 * 1024,
                "34 MiB ciphertext leaked into Raft snapshot"
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&snapshot)?["format_version"],
                4
            );
            assert_eq!(
                state
                    .record_usage()
                    .map_err(crate::RaftRuntimeError::RecordRejected)?
                    .object_count,
                3
            );
            node.trigger_snapshot().await?;
        }
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let mut all = true;
                for node in &nodes {
                    all &= node.membership_observation().await?.purged_index
                        >= Some(current.publication_log_id().index);
                }
                if all {
                    break Ok::<(), RemoteRaftError>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        // Do not keep a warm enrollment handle across failover or reopen. A
        // committed root's pins must be recovered from the actual new store.
        drop(enrollment);
        stage = "disconnect first leader and elect second voter";
        router.isolated.store(true, Ordering::SeqCst);
        nodes[0].raft.shutdown().await?;
        router.peers.write().await.remove(&1);
        // Bootstrap disabled autonomous elections. A one-shot immediate
        // election can be rejected by voter 3's still-live old leader lease.
        // Enable the selected survivor's real election timeout/retry path;
        // do not bypass voter lease/log checks or lengthen the test timeout.
        nodes[1].raft.runtime_config().elect(true);
        nodes[1].raft.trigger().elect(false).await?;
        nodes[1]
            .raft
            .wait(Some(Duration::from_secs(7)))
            .metrics(|m| m.current_leader == Some(2), "V6 root new leader")
            .await?;
        assert_eq!(
            nodes[1]
                .reconcile_native_v6_root(&next, &receipt(&current), deadline())
                .await?,
            current
        );
        let (warm_witness, _, _) = nodes[1]
            .native_v6_application_read_witness(deadline())
            .await?;
        let warm_selected = nodes[1]
            .native_v6_committed_root_read(deadline())
            .await?
            .ok_or("warm committed root absent")?;
        stage = "cold reopen all durable Raft voters";
        for node in nodes.iter().skip(1) {
            node.raft.shutdown().await?;
        }
        nodes.clear();
        router.peers.write().await.clear();
        router.isolated.store(false, Ordering::SeqCst);
        for id in 1..=3 {
            let network = RemoteNetworkFactory::new(
                id,
                BTreeSet::from([1, 2, 3]),
                Arc::new(Arc::clone(&router)),
            )?;
            let node = ProcessRaftNode::reopen(root.join(id.to_string()), id, network).await?;
            node.raft.runtime_config().elect(false);
            router.peers.write().await.insert(id, node.rpc_service());
            nodes.push(node);
        }
        // Let the real recovered cluster select its leader. Do not infer that
        // voter 2 is still writable from its persisted old leadership hint.
        for node in &nodes {
            node.raft.runtime_config().elect(true);
        }
        stage = "observe a real cold leader with committed membership and heartbeat quorum";
        let cold_leader = cold_ready_leader(&nodes).await?;
        // Check the original voter's new process even if another voter won;
        // a changed node ID alone must not make this ownership test pass.
        assert!(
            nodes[1]
                .verify_application_read_witness(&warm_witness)
                .await
                .is_err(),
            "a previous process/store witness cannot authorize the cold process"
        );
        assert!(
            nodes[1]
                .verify_native_v6_committed_root_read(&warm_selected)
                .await
                .is_err()
        );
        assert_eq!(
            nodes[cold_leader]
                .reconcile_native_v6_root(&next, &receipt(&current), deadline())
                .await?,
            current
        );
        stage = "recover committed enrollment through the cold read handle";
        assert!(
            nodes[cold_leader]
                .native_v6_committed_root_read(Instant::now() - Duration::from_millis(1))
                .await
                .is_err()
        );
        let cold_read = nodes[cold_leader]
            .native_v6_committed_root_read(deadline())
            .await?
            .ok_or("cold committed root absent")?;
        let cold_enrollment = cold_read.enrollment().clone();
        let cold_root = cold_read.root().clone();
        assert!(!cold_read.same_selection(&warm_selected));
        assert_eq!(cold_enrollment.digest(), enrollment_digest);
        assert_eq!(cold_root, current);
        assert_eq!(cold_root.enrollment_digest(), cold_enrollment.digest());
        stage = "verify the original cold application read witness";
        nodes[cold_leader]
            .verify_native_v6_committed_root_read(&cold_read)
            .await?;
        let cold_intent = NativeV6CommitIntent {
            operation_digest: [9; 32],
            prior_root_digest: cold_root.root_digest(),
            proposed_root_digest: [10; 32],
            prior_generation: cold_root.generation(),
            proposed_generation: cold_root.generation() + 1,
            expected_previous_commit_index: cold_root.publication_log_id().index,
            ..next
        };
        let cold_object = SealedRecordObject::new_native_v6_commit_intent(cold_intent)?;
        stage = "stage the actual cold intent using the recovered enrollment";
        let cold_staged = nodes[cold_leader]
            .stage_application_object(
                nodes[cold_leader].next_production_client_serial().await?,
                &cold_object,
            )
            .await?;
        assert!(
            nodes[cold_leader]
                .verify_native_v6_committed_root_read(&cold_read)
                .await
                .is_err(),
            "staging advances the real bundle generation and retires the old witness"
        );
        stage = "publish generation three through the cold committed enrollment";
        let current = nodes[cold_leader]
            .publish_native_v6_root(
                nodes[cold_leader].next_production_client_serial().await?,
                &cold_intent,
                &cold_staged,
                &cold_enrollment,
                vec![0x88; 64],
                deadline(),
            )
            .await?;
        assert_eq!(current.generation(), 3);
        assert_eq!(current.migration_source(), source);
        stage = "recover exact committed external closure on each reopened voter";
        for node in &nodes {
            let (witness, enrollment, selected) =
                node.native_v6_application_read_witness(deadline()).await?;
            assert_eq!(selected, Some(current.clone()));
            assert_eq!(
                enrollment
                    .ok_or("reopened voter enrollment absent")?
                    .digest(),
                enrollment_digest
            );
            let store =
                LocalV6BlobStage::open_existing(&root.join(format!("external-{}", node.id())))?;
            let recovered = store.reopen_root_closure(&current, &mut || Ok(()))?;
            assert_eq!(recovered.len(), refs.len());
            node.verify_application_read_witness(&witness).await?;
        }
        // A missing leaf and a corrupted committed manifest each deny local
        // activation, while the actual committed Raft root remains unchanged.
        stage = "reject missing leaf and corrupted external manifest";
        let dir = root.join("external-2");
        let store = LocalV6BlobStage::open_existing(&dir)?;
        let mut leaf = String::from("v6-");
        crate::append_hex(&mut leaf, &refs[0].id);
        leaf.push_str(".blob");
        fs::rename(dir.join(&leaf), dir.join("held-leaf"))?;
        assert!(store.reopen_root_closure(&current, &mut || Ok(())).is_err());
        fs::rename(dir.join("held-leaf"), dir.join(leaf))?;
        let mut manifest = String::from("v6-closure-");
        crate::append_hex(&mut manifest, &current.intent().closure_manifest_sha256);
        manifest.push_str(".manifest");
        let manifest_path = dir.join(manifest);
        let original = fs::read(&manifest_path)?;
        let mut corrupt = original.clone();
        corrupt[16] ^= 1;
        fs::write(&manifest_path, &corrupt)?;
        assert!(store.reopen_root_closure(&current, &mut || Ok(())).is_err());
        fs::write(&manifest_path, &original)?;
        assert_eq!(
            store.reopen_root_closure(&current, &mut || Ok(()))?.len(),
            refs.len()
        );
        assert_eq!(
            nodes[cold_leader].native_v6_root_at_generation().await.1,
            Some(current.clone())
        );
        // The enrollment belongs to its exact actual membership, not merely
        // to some once-configured node IDs. Changing live Raft membership
        // invalidates new publication/read reconciliation under these pins.
        stage = "fence native enrollment after actual membership change";
        let leader_id = nodes[cold_leader].id();
        let other_id = nodes
            .iter()
            .map(ProcessRaftNode::id)
            .find(|id| *id != leader_id)
            .ok_or("cold membership has no other voter")?;
        let remaining_voters = BTreeSet::from([leader_id, other_id]);
        nodes[cold_leader]
            .raft
            .change_membership(remaining_voters.clone(), false)
            .await?;
        nodes[cold_leader]
            .raft
            .wait(Some(Duration::from_secs(7)))
            .metrics(
                |m| {
                    m.membership_config == m.committed_membership_config
                        && m.membership_config.get_joint_config().len() == 1
                        && m.membership_config.voter_ids().collect::<BTreeSet<_>>()
                            == remaining_voters
                },
                "actual membership changed after native publication",
            )
            .await?;
        assert!(
            nodes[cold_leader]
                .native_v6_application_read_witness(deadline())
                .await
                .is_err(),
            "a stale enrollment cannot be returned as current after membership changes"
        );
        assert!(
            nodes[cold_leader]
                .reconcile_native_v6_root(&cold_intent, &receipt(&current), deadline())
                .await
                .is_err()
        );
        assert_eq!(
            nodes[cold_leader].native_v6_root_at_generation().await.1,
            Some(current)
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    if result.is_err() {
        for node in &nodes {
            eprintln!(
                "V6 root regression failure: stage={stage} node={} metrics={:?}",
                node.id(),
                node.raft.metrics().borrow_watched()
            );
        }
    }
    for node in &nodes {
        let _ = node.raft.shutdown().await;
    }
    result.map_err(|error| format!("V6 root regression stage '{stage}': {error}"))?;
    fs::remove_dir_all(root)?;
    Ok(())
}
