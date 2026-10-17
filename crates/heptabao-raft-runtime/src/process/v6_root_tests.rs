//! Actual durable Raft root CAS, snapshot/leader restart, and external-object
//! recovery. The RPC router and TLS pins are synthetic; this is not a physical
//! host network, real barrier crypto, quorum-fsync/Actor or HTTP ACK test.
use super::*;
use crate::{CommitReceipt, LocalV6BlobStage, NativeV6CommitIntent, PublishedRecordRoot,
    RecordRootBase, ReplicatedEnvelope, SealedRecordObject};
use futures::future::BoxFuture;
use openraft::async_runtime::WatchReceiver;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

static SEQ: AtomicU64 = AtomicU64::new(0);
#[derive(Default)]
struct Router { peers: RwLock<BTreeMap<u64, RaftRpcService>>, isolated: AtomicBool }
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("V6RootTestRouter") }
}
impl RaftPeerRpc for Arc<Router> {
    fn exchange(&self, source: u64, target: u64, kind: RaftRpcKind, bytes: Vec<u8>, _timeout: Duration)
    -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        let router = Arc::clone(self);
        Box::pin(async move {
            if router.isolated.load(Ordering::SeqCst) && (source == 1 || target == 1) {
                return Err(RemoteRaftError::Transport("test leader disconnected".into()));
            }
            let peer = router.peers.read().await.get(&target).cloned()
                .ok_or(RemoteRaftError::InvalidTopology)?;
            peer.handle(source, kind, bytes).await
        })
    }
}
fn deadline() -> Instant { Instant::now() + Duration::from_secs(10) }
fn receipt(root: &crate::NativeV6PublishedRoot) -> CommitReceipt {
    CommitReceipt { leader_id: root.publication_log_id().committed_leader_id().node_id,
        log_index: root.publication_log_id().index, envelope_digest: root.root_digest() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_real_raft_root_cas_external_34mib_snapshot_failover_and_cold_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("hb-v6-root-{}-{}", std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)));
    let router = Arc::new(Router::default());
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let network = RemoteNetworkFactory::new(id, BTreeSet::from([1, 2, 3]), Arc::new(Arc::clone(&router)))?;
        let node = ProcessRaftNode::create(root.join(id.to_string()), id, network).await?;
        node.raft.runtime_config().elect(false);
        router.peers.write().await.insert(id, node.rpc_service());
        nodes.push(node);
    }
    let mut stage = "initialize and elect actual voters";
    let result = async {
        nodes[0].raft.initialize(BTreeMap::from([(1, ()), (2, ()), (3, ())])).await?;
        nodes[0].raft.trigger().elect(false).await?;
        nodes[0].raft.wait(Some(Duration::from_secs(7))).metrics(
            |m| m.current_leader == Some(1) && m.last_applied.is_some(), "V6 root fixture leader").await?;
        nodes[0].ensure_linearizable().await?;
        stage = "publish original V5 source";
        let v5 = PublishedRecordRoot::new(RecordRootBase::Empty,
            ReplicatedEnvelope::new("synthetic-v5-source", [4; 32], vec![0x44; 32])?, Vec::new())?;
        let v5_receipt = nodes[0].publish_application_root(nodes[0].next_production_client_serial().await?, &v5).await?;
        let source = nodes[0].native_v6_migration_source().await.ok_or("actual V5 source absent")?;
        assert_eq!(source.0, v5.envelope().digest());
        assert_eq!(source.1.index, v5_receipt.log_index);
        stage = "commit actual membership and pin enrollment";
        let enrollment = nodes[0].enroll_native_v6_peers(
            nodes[0].next_production_client_serial().await?, [1; 32], 7,
            BTreeMap::from([(1, [11; 32]), (2, [22; 32]), (3, [33; 32])]), deadline()).await?;
        assert_eq!(enrollment.membership_log_id().index, 0,
            "pinned OpenRaft genesis membership remains bound to its actual zero slot");
        assert_eq!(enrollment.membership_log_id().committed_leader_id().term, 0);
        assert_eq!(enrollment.membership_log_id().committed_leader_id().node_id, 1);
        // A different trusted-config claim cannot silently replace committed pins.
        assert!(nodes[0].enroll_native_v6_peers(nodes[0].next_production_client_serial().await?, [1; 32], 7,
            BTreeMap::from([(1, [11; 32]), (2, [22; 32]), (3, [34; 32])]), deadline()).await.is_err());
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
            assert_eq!(store.persist_local_closure(&selected, &mut || Ok(()))?, observed);
            if id == 1 { refs = selected; local_receipt = Some(observed); }
            else { assert_eq!(Some(observed), local_receipt); }
        }
        let closure = local_receipt.ok_or("missing actual local closure")?;
        stage = "stage first native intent";
        let intent = NativeV6CommitIntent {
            cluster_digest: [1; 32], epoch: 7, operation_digest: [2; 32],
            closure_manifest_sha256: closure.manifest_sha256(),
            object_count: closure.object_count() as u64, ciphertext_bytes: closure.ciphertext_bytes(),
            prior_root_digest: source.0, proposed_root_digest: [5; 32],
            prior_generation: 0, proposed_generation: 1, expected_previous_commit_index: source.1.index,
        };
        let object = SealedRecordObject::new_native_v6_commit_intent(intent)?;
        let staged = nodes[0].stage_application_object(nodes[0].next_production_client_serial().await?, &object).await?;
        stage = "publish first native root CAS";
        let first = nodes[0].publish_native_v6_root(nodes[0].next_production_client_serial().await?,
            &intent, &staged, &enrollment, vec![0x55; 64], deadline()).await?;
        assert_eq!(first.generation(), 1);
        assert_eq!(first.intent_log_id().index, staged.log_index);
        assert_eq!(first.migration_source(), source);
        assert!(first.publication_log_id().index > staged.log_index);
        assert_eq!(first.enrollment_digest(), enrollment.digest());
        assert!(nodes[0].record_root_at_generation().await?.1.is_none(),
            "retained V5 migration source is not the current readable application root");
        stage = "stage competing native intents";
        let next = NativeV6CommitIntent { operation_digest: [3; 32], prior_root_digest: first.root_digest(),
            proposed_root_digest: [6; 32], prior_generation: 1, proposed_generation: 2,
            expected_previous_commit_index: first.publication_log_id().index, ..intent };
        let conflicting = NativeV6CommitIntent { operation_digest: [8; 32], proposed_root_digest: [7; 32], ..next };
        let next_object = SealedRecordObject::new_native_v6_commit_intent(next)?;
        let next_staged = nodes[0].stage_application_object(nodes[0].next_production_client_serial().await?, &next_object).await?;
        let conflicting_object = SealedRecordObject::new_native_v6_commit_intent(conflicting)?;
        let conflicting_staged = nodes[0].stage_application_object(nodes[0].next_production_client_serial().await?, &conflicting_object).await?;
        stage = "publish second native root CAS";
        let current = nodes[0].publish_native_v6_root(nodes[0].next_production_client_serial().await?,
            &next, &next_staged, &enrollment, vec![0x66; 64], deadline()).await?;
        assert_eq!(current.generation(), 2);
        stage = "reject conflicting CAS and obsolete V5 publication";
        assert!(nodes[0].publish_native_v6_root(nodes[0].next_production_client_serial().await?,
            &conflicting, &conflicting_staged, &enrollment, vec![0x77; 64], deadline()).await.is_err());
        assert_eq!(nodes[0].native_v6_root_at_generation().await.1, Some(current.clone()));
        assert!(nodes[0].publish_application_root(nodes[0].next_production_client_serial().await?, &v5).await.is_err());
        let mut wrong = receipt(&current); wrong.log_index -= 1;
        assert!(nodes[0].reconcile_native_v6_root(&next, &wrong, deadline()).await.is_err());
        assert_eq!(nodes[0].native_v6_root_at_generation().await.1, Some(current.clone()));
        stage = "replicate and compact native root snapshots on all voters";
        nodes[0].ensure_linearizable().await?;
        let committed = nodes[0].raft.metrics().borrow_watched().last_applied
            .ok_or("leader has no applied publication prefix")?;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let mut all = true;
                for node in &nodes {
                    all &= node.native_v6_root_at_generation().await.1 == Some(current.clone());
                    // Include the committed rejection entries after the root,
                    // so root equality alone cannot conceal a lagging voter.
                    all &= node.raft.metrics().borrow_watched().last_applied
                        .is_some_and(|applied| applied >= committed);
                }
                if all { break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await?;
        for node in &nodes {
            let mut state = node.state_machine.get_state_machine().await;
            let snapshot = state.snapshot_bytes()?;
            assert!(snapshot.len() < 128 * 1024, "34 MiB ciphertext leaked into Raft snapshot");
            assert_eq!(serde_json::from_slice::<serde_json::Value>(&snapshot)?["format_version"], 4);
            assert_eq!(state.record_usage().map_err(crate::RaftRuntimeError::RecordRejected)?.object_count, 3);
            node.trigger_snapshot().await?;
        }
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let mut all = true;
                for node in &nodes {
                    all &= node.membership_observation().await?.purged_index >= Some(current.publication_log_id().index);
                }
                if all { break Ok::<(), RemoteRaftError>(()); }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
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
        nodes[1].raft.wait(Some(Duration::from_secs(7))).metrics(
            |m| m.current_leader == Some(2), "V6 root new leader").await?;
        assert_eq!(nodes[1].reconcile_native_v6_root(&next, &receipt(&current), deadline()).await?, current);
        stage = "cold reopen all durable Raft voters";
        for node in nodes.iter().skip(1) { node.raft.shutdown().await?; }
        nodes.clear(); router.peers.write().await.clear(); router.isolated.store(false, Ordering::SeqCst);
        for id in 1..=3 {
            let network = RemoteNetworkFactory::new(id, BTreeSet::from([1, 2, 3]), Arc::new(Arc::clone(&router)))?;
            let node = ProcessRaftNode::reopen(root.join(id.to_string()), id, network).await?;
            node.raft.runtime_config().elect(false);
            router.peers.write().await.insert(id, node.rpc_service()); nodes.push(node);
        }
        nodes[1].raft.runtime_config().elect(true);
        nodes[1].raft.trigger().elect(false).await?;
        nodes[1].raft.wait(Some(Duration::from_secs(7))).metrics(
            |m| m.current_leader == Some(2), "V6 root cold leader").await?;
        assert_eq!(nodes[1].reconcile_native_v6_root(&next, &receipt(&current), deadline()).await?, current);
        stage = "recover exact committed external closure on each reopened voter";
        for node in &nodes {
            assert_eq!(node.native_v6_root_at_generation().await.1, Some(current.clone()));
            let store = LocalV6BlobStage::open_existing(&root.join(format!("external-{}", node.id())))?;
            let recovered = store.reopen_root_closure(&current, &mut || Ok(()))?;
            assert_eq!(recovered.len(), refs.len());
        }
        // A missing leaf and a corrupted committed manifest each deny local
        // activation, while the actual committed Raft root remains unchanged.
        stage = "reject missing leaf and corrupted external manifest";
        let dir = root.join("external-2");
        let store = LocalV6BlobStage::open_existing(&dir)?;
        let mut leaf = String::from("v6-"); crate::append_hex(&mut leaf, &refs[0].id); leaf.push_str(".blob");
        fs::rename(dir.join(&leaf), dir.join("held-leaf"))?;
        assert!(store.reopen_root_closure(&current, &mut || Ok(())).is_err());
        fs::rename(dir.join("held-leaf"), dir.join(leaf))?;
        let mut manifest = String::from("v6-closure-");
        crate::append_hex(&mut manifest, &current.intent().closure_manifest_sha256); manifest.push_str(".manifest");
        let manifest_path = dir.join(manifest);
        let original = fs::read(&manifest_path)?;
        let mut corrupt = original.clone(); corrupt[16] ^= 1; fs::write(&manifest_path, &corrupt)?;
        assert!(store.reopen_root_closure(&current, &mut || Ok(())).is_err());
        fs::write(&manifest_path, &original)?;
        assert_eq!(store.reopen_root_closure(&current, &mut || Ok(()))?.len(), refs.len());
        assert_eq!(nodes[1].native_v6_root_at_generation().await.1, Some(current.clone()));
        // The enrollment belongs to its exact actual membership, not merely
        // to some once-configured node IDs. Changing live Raft membership
        // invalidates new publication/read reconciliation under these pins.
        stage = "fence native enrollment after actual membership change";
        nodes[1].raft.change_membership(BTreeSet::from([2, 3]), false).await?;
        nodes[1].raft.wait(Some(Duration::from_secs(7))).metrics(
            |m| m.membership_config == m.committed_membership_config
                && m.membership_config.get_joint_config().len() == 1
                && m.membership_config.voter_ids().collect::<BTreeSet<_>>() == BTreeSet::from([2, 3]),
            "actual membership changed after native publication").await?;
        assert!(nodes[1].reconcile_native_v6_root(&next, &receipt(&current), deadline()).await.is_err());
        assert_eq!(nodes[1].native_v6_root_at_generation().await.1, Some(current));
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    for node in &nodes { let _ = node.raft.shutdown().await; }
    result.map_err(|error| format!("V6 root regression stage '{stage}': {error}"))?;
    fs::remove_dir_all(root)?;
    Ok(())
}
