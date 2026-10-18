//! Real durable three-node Raft protocol regression. Routing and leaf pins
//! are synthetic; these tests do NOT claim TLS fsync, archive/barrier/Actor or
//! Service HTTP recovery. The production guards at those boundaries stay on.
use super::*;
use crate::{NativeV6CommittedRootRead, NativeV6EpochRestoreRead};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct EpochFixture {
    directory: std::path::PathBuf,
    router: Arc<Router>,
    nodes: Vec<ProcessRaftNode>,
}

impl EpochFixture {
    async fn create() -> TestResult<Self> {
        let directory = std::env::temp_dir().join(format!(
            "hb-v6-epoch-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst),
        ));
        let router = Arc::new(Router::default());
        let mut fixture = Self { directory, router, nodes: Vec::new() };
        for id in 1..=3 {
            let network = RemoteNetworkFactory::new(
                id, BTreeSet::from([1, 2, 3]), Arc::new(Arc::clone(&fixture.router)),
            )?;
            let node = ProcessRaftNode::create(fixture.directory.join(id.to_string()), id, network).await?;
            node.raft.runtime_config().elect(false);
            fixture.router.peers.write().await.insert(id, node.rpc_service());
            fixture.nodes.push(node);
        }
        let first = &fixture.nodes[0];
        first.raft.initialize(BTreeMap::from([(1, ()), (2, ()), (3, ())])).await?;
        first.raft.trigger().elect(false).await?;
        first.raft.wait(Some(Duration::from_secs(7))).metrics(
            |m| m.current_leader == Some(1) && m.last_applied.is_some(),
            "native epoch fixture leader",
        ).await?;
        first.ensure_linearizable().await?;
        let original = PublishedRecordRoot::new(
            RecordRootBase::Empty,
            ReplicatedEnvelope::new("epoch-fixture-v5-source", [4; 32], vec![0x44; 32])?,
            Vec::new(),
        )?;
        first.publish_application_root(first.next_production_client_serial().await?, &original).await?;
        let source = first.native_v6_migration_source().await.ok_or("V5 source absent")?;
        let enrollment = first.enroll_native_v6_peers(
            first.next_production_client_serial().await?, [1; 32], 7,
            BTreeMap::from([(1, [11; 32]), (2, [22; 32]), (3, [33; 32])]), deadline(),
        ).await?;
        let intent = NativeV6CommitIntent {
            cluster_digest: [1; 32], epoch: 7, operation_digest: [2; 32],
            closure_manifest_sha256: [3; 32], object_count: 1, ciphertext_bytes: 64,
            prior_root_digest: source.0, proposed_root_digest: [5; 32],
            prior_generation: 0, proposed_generation: 1,
            expected_previous_commit_index: source.1.index,
        };
        let staged = stage(first, intent).await?;
        first.publish_native_v6_root(
            first.next_production_client_serial().await?, &intent, &staged,
            &enrollment, vec![0x55; 64], deadline(),
        ).await?;
        Ok(fixture)
    }

    async fn compact_all(&self, through: u64) -> TestResult {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let all = self.nodes.iter().all(|node| {
                    node.raft.metrics().borrow_watched().last_applied
                        .is_some_and(|log| log.index >= through)
                });
                if all { break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await?;
        for node in &self.nodes { node.trigger_snapshot().await?; }
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let mut all = true;
                for node in &self.nodes {
                    all &= node.membership_observation().await?.purged_index >= Some(through);
                }
                if all { break Ok::<(), RemoteRaftError>(()); }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
        Ok(())
    }

    async fn cold_restart(&mut self) -> TestResult<usize> {
        for node in &self.nodes { node.raft.shutdown().await?; }
        self.nodes.clear();
        self.router.peers.write().await.clear();
        for id in 1..=3 {
            let network = RemoteNetworkFactory::new(
                id, BTreeSet::from([1, 2, 3]), Arc::new(Arc::clone(&self.router)),
            )?;
            let node = ProcessRaftNode::reopen(self.directory.join(id.to_string()), id, network).await?;
            node.raft.runtime_config().elect(false);
            self.router.peers.write().await.insert(id, node.rpc_service());
            self.nodes.push(node);
        }
        for node in &self.nodes { node.raft.runtime_config().elect(true); }
        cold_ready_leader(&self.nodes).await
    }

    async fn finish(self, result: TestResult) -> TestResult {
        if result.is_err() {
            for node in &self.nodes {
                eprintln!("native epoch failure: voter={} metrics={:?} fixture={}",
                    node.id(), node.raft.metrics().borrow_watched(), self.directory.display());
            }
        }
        for node in &self.nodes { let _ = node.raft.shutdown().await; }
        result?; // Preserve the real durable failure fixture for diagnosis.
        fs::remove_dir_all(self.directory)?;
        Ok(())
    }
}

async fn selected(node: &ProcessRaftNode) -> TestResult<NativeV6CommittedRootRead> {
    Ok(node.native_v6_committed_root_read(deadline()).await?.ok_or("native root absent")?)
}

fn next_intent(read: &NativeV6CommittedRootRead, next_epoch: u64, op: u8, root: u8)
-> NativeV6CommitIntent {
    NativeV6CommitIntent {
        epoch: next_epoch, operation_digest: [op; 32], proposed_root_digest: [root; 32],
        prior_root_digest: read.root().root_digest(), prior_generation: read.root().generation(),
        proposed_generation: read.root().generation() + 1,
        expected_previous_commit_index: read.root().publication_log_id().index,
        ..read.root().intent()
    }
}

async fn stage(node: &ProcessRaftNode, intent: NativeV6CommitIntent) -> TestResult<CommitReceipt> {
    let object = SealedRecordObject::new_native_v6_commit_intent(intent)?;
    Ok(node.stage_application_object(node.next_production_client_serial().await?, &object).await?)
}

async fn begin(
    node: &ProcessRaftNode, source: &NativeV6CommittedRootRead, intent: &NativeV6CommitIntent,
) -> TestResult<NativeV6EpochRestoreRead> {
    Ok(node.begin_native_v6_epoch_restore(
        node.next_production_client_serial().await?, source,
        intent.operation_digest, intent.proposed_root_digest,
    ).await?)
}

async fn pending(node: &ProcessRaftNode, initial: &NativeV6EpochRestoreRead)
-> TestResult<NativeV6EpochRestoreRead> {
    let read = node.native_v6_epoch_restore_read(
        initial.operation_digest(), initial.operation_deadline(),
    ).await?;
    assert!(initial.same_transition(&read));
    node.verify_native_v6_epoch_restore_read(&read).await?;
    Ok(read)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_epoch_restore_real_three_phase_admission_and_atomic_root_enrollment() -> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let original = selected(node).await?;
        let old_root = original.root().clone();
        let old_enrollment = original.enrollment().clone();
        let intent = next_intent(&original, 8, 6, 7);
        assert!(stage(node, intent).await.is_err(), "next epoch cannot Stage before actual Begin");
        assert!(node.admit_native_v6_closure(&intent, deadline()).await.is_err());
        let source = selected(node).await?;
        let initial = begin(node, &source, &intent).await?;
        assert_eq!(initial.target_enrollment().epoch(), 8);
        assert_ne!(initial.target_enrollment().digest(), old_enrollment.digest());
        assert!(initial.target_enrollment().same_peer_configuration(&old_enrollment));
        assert_eq!(initial.intent(), None);
        assert!(node.verify_native_v6_committed_root_read(&source).await.is_err());
        let still_old = selected(node).await?;
        assert_eq!(still_old.root(), &old_root);
        assert_eq!(still_old.enrollment(), &old_enrollment);
        assert!(node.admit_native_v6_closure(&intent, deadline()).await.is_err(),
            "an unsealed Begin never admits ciphertext");
        // Each altered manifest scope must be rejected by actual replicated
        // Stage, rather than receiving a fabricated sealed pending handle.
        for changed in [
            NativeV6CommitIntent { epoch: 9, ..intent },
            NativeV6CommitIntent { operation_digest: [18; 32], ..intent },
            NativeV6CommitIntent { proposed_root_digest: [19; 32], ..intent },
            NativeV6CommitIntent { cluster_digest: [20; 32], ..intent },
        ] {
            assert!(stage(node, changed).await.is_err());
        }
        let staged = stage(node, intent).await?;
        assert!(node.verify_native_v6_epoch_restore_read(&initial).await.is_err(),
            "own Stage invalidates the original bundle witness");
        let sealed = pending(node, &initial).await?;
        assert_eq!(sealed.intent(), Some(intent));
        assert_eq!(sealed.intent_log_id().ok_or("Stage log absent")?.index, staged.log_index);
        assert!(sealed.intent_log_id().ok_or("Stage log absent")? > initial.begin_log_id());
        // Once sealed, no second closure can retarget this same pending op.
        let changed = NativeV6CommitIntent { closure_manifest_sha256: [21; 32], ..intent };
        assert!(stage(node, changed).await.is_err());
        for voter in &fixture.nodes {
            let admission = voter.admit_native_v6_closure(&intent, deadline()).await?;
            assert_eq!(admission.enrollment(), sealed.target_enrollment());
            assert_eq!(admission.intent_log_id(), sealed.intent_log_id().ok_or("Stage log absent")?);
            voter.verify_native_v6_closure_admission(&admission).await?;
            assert_eq!(selected(voter).await?.enrollment().epoch(), 7);
        }
        assert!(node.publish_native_v6_root(
            node.next_production_client_serial().await?, &intent, &staged,
            sealed.target_enrollment(), vec![0x66; 64], initial.operation_deadline(),
        ).await.is_err(), "ordinary root publisher must retain its exact current-epoch guard");
        let sealed = pending(node, &initial).await?;
        let old_admission = node.admit_native_v6_closure(&intent, initial.operation_deadline()).await?;
        let published = node.publish_native_v6_epoch_restore(
            node.next_production_client_serial().await?, &sealed, &staged, vec![0x66; 64],
        ).await?;
        assert_eq!(published.intent(), intent);
        assert_eq!(published.generation(), old_root.generation() + 1);
        assert_eq!(published.migration_source(), old_root.migration_source());
        assert_eq!(published.native_origin_epoch(), 7);
        assert!(node.verify_native_v6_closure_admission(&old_admission).await.is_err());
        assert!(node.verify_native_v6_epoch_restore_read(&sealed).await.is_err());
        assert!(node.native_v6_epoch_restore_read(intent.operation_digest, deadline()).await.is_err());
        let read = selected(node).await?;
        assert_eq!(read.enrollment(), sealed.target_enrollment());
        assert_eq!(read.root(), &published);
        assert_eq!(read.root().epoch_transitions().len(), 1);
        let step = read.root().epoch_transitions().next().ok_or("history absent")?;
        assert_eq!(step.source_enrollment(), old_enrollment);
        assert_eq!(step.source_publication_log_id(), old_root.publication_log_id());
        assert_eq!(step.source_intent_log_id(), old_root.intent_log_id());
        assert_eq!(step.begin_log_id(), initial.begin_log_id());
        assert_eq!(step.intent_log_id(), sealed.intent_log_id());
        assert_eq!(step.publication_log_id(), published.publication_log_id());
        let admission = node.admit_native_v6_closure(&intent, deadline()).await?;
        assert_eq!(admission.enrollment(), sealed.target_enrollment());
        // Old epoch is no longer admitted or writable after the one CAS.
        assert!(node.admit_native_v6_closure(&old_root.intent(), deadline()).await.is_err());
        assert!(stage(node, next_intent(&original, 7, 40, 41)).await.is_err());
        assert_eq!(selected(node).await?.root(), &published);
        let mut state = node.state_machine.get_state_machine().await;
        let bytes = state.snapshot_bytes()?;
        let wire: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(wire["format_version"], 5);
        assert!(wire["state"].get("v6_pending_epoch_restore").is_none());
        assert_eq!(state.record_usage().map_err(crate::RaftRuntimeError::RecordRejected)?.object_count, 2);
        assert!(crate::StateMachine::from_snapshot(&bytes).is_ok());
        Ok(())
    }.await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_epoch_restore_actual_cancel_and_ordinary_write_retire_pending_without_epoch_change()
-> TestResult {
    let fixture = EpochFixture::create().await?;
    let result = async {
        let node = &fixture.nodes[0];
        let source = selected(node).await?;
        let original_root = source.root().clone();
        let original_enrollment = source.enrollment().clone();
        let first_intent = next_intent(&source, 8, 8, 9);
        let first = begin(node, &source, &first_intent).await?;
        let still_old = selected(node).await?;
        let competing = next_intent(&still_old, 8, 10, 11);
        assert!(begin(node, &still_old, &competing).await.is_err());
        let first = pending(node, &first).await?;
        node.cancel_native_v6_epoch_restore(node.next_production_client_serial().await?, &first).await?;
        let after_cancel = selected(node).await?;
        assert_eq!(after_cancel.root(), &original_root);
        assert_eq!(after_cancel.enrollment(), &original_enrollment);
        assert!(node.native_v6_epoch_restore_read(first.operation_digest(), deadline()).await.is_err());
        assert!(stage(node, first_intent).await.is_err());
        let bytes = node.state_machine.get_state_machine().await.snapshot_bytes()?;
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes)?["format_version"], 5,
            "cancellation cannot drop the version floor and let old binaries ignore protocol state");
        let source = selected(node).await?;
        let second = begin(node, &source, &competing).await?;
        let staged = stage(node, competing).await?;
        let second = pending(node, &second).await?;
        // A legitimate write remains available under the active old epoch;
        // its exact source CAS atomically invalidates the pending restore.
        let source = selected(node).await?;
        let ordinary = next_intent(&source, 7, 12, 13);
        let ordinary_staged = stage(node, ordinary).await?;
        let winner = node.publish_native_v6_root(
            node.next_production_client_serial().await?, &ordinary, &ordinary_staged,
            source.enrollment(), vec![0x77; 64], deadline(),
        ).await?;
        assert_eq!(selected(node).await?.enrollment(), &original_enrollment);
        assert_eq!(selected(node).await?.root(), &winner);
        assert!(node.native_v6_epoch_restore_read(second.operation_digest(), deadline()).await.is_err());
        assert!(node.publish_native_v6_epoch_restore(
            node.next_production_client_serial().await?, &second, &staged, vec![0x88; 64],
        ).await.is_err());
        assert!(stage(node, competing).await.is_err());
        assert!(begin(node, &source, &competing).await.is_err(), "cannot silently retarget a stale source");
        assert_eq!(selected(node).await?.root(), &winner);
        Ok(())
    }.await;
    fixture.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_epoch_restore_pending_snapshot_purge_cold_owner_and_committed_lineage_recovery()
-> TestResult {
    let mut fixture = EpochFixture::create().await?;
    let result = async {
        let original = selected(&fixture.nodes[0]).await?;
        let old_root = original.root().clone();
        let old_enrollment = original.enrollment().clone();
        let intent = next_intent(&original, 8, 14, 15);
        let initial = begin(&fixture.nodes[0], &original, &intent).await?;
        let staged = stage(&fixture.nodes[0], intent).await?;
        let sealed = pending(&fixture.nodes[0], &initial).await?;
        let stage_log = sealed.intent_log_id().ok_or("Stage log absent")?;
        // Duplicate Stage is an actual separate Raft entry. It must not rewrite
        // the immutable first provenance retained by pending/snapshot state.
        let duplicate = stage(&fixture.nodes[0], intent).await?;
        assert!(duplicate.log_index > staged.log_index);
        // Generic reconciliation proves the requested ACTUAL Stage log slot.
        // While unpurged, this duplicate slot really does hold the exact same
        // object. That narrow read-only result does not select first-origin
        // provenance and cannot substitute for the pending restore's gate.
        fixture.nodes[0].reconcile_exact_staged_v6_intent(&intent, &duplicate).await?;
        let sealed = pending(&fixture.nodes[0], &initial).await?;
        assert_eq!(sealed.intent_log_id(), Some(stage_log));
        let source_before = selected(&fixture.nodes[0]).await?;
        assert!(fixture.nodes[0].publish_native_v6_epoch_restore(
            fixture.nodes[0].next_production_client_serial().await?,
            &sealed, &duplicate, vec![0x98; 64],
        ).await.is_err(), "a duplicate Stage slot cannot replace the first full LogId at epoch CAS");
        assert_eq!(selected(&fixture.nodes[0]).await?.root(), source_before.root());
        assert_eq!(selected(&fixture.nodes[0]).await?.enrollment(), source_before.enrollment());
        let bytes = fixture.nodes[0].state_machine.get_state_machine().await.snapshot_bytes()?;
        let good: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(good["format_version"], 5);
        for mutation in 0..5 {
            let mut bad = good.clone();
            let item = &mut bad["state"]["v6_pending_epoch_restore"];
            match mutation {
                0 => item["target_enrollment"]["command"]["epoch"] = serde_json::json!(9),
                1 => item["begin_log"]["index"] = serde_json::json!(stage_log.index),
                2 => item["intent"]["log"]["index"] = serde_json::json!(duplicate.log_index),
                3 => item["command"]["source"]["generation"] = serde_json::json!(99),
                _ => bad["format_version"] = serde_json::json!(4),
            }
            assert!(crate::StateMachine::from_snapshot(&serde_json::to_vec(&bad)?).is_err(),
                "mutated pending/snapshot provenance accepted: case={mutation}");
        }
        fixture.compact_all(duplicate.log_index).await?;
        let leader = fixture.cold_restart().await?;
        let node = &fixture.nodes[leader];
        assert!(fixture.nodes[0].verify_native_v6_epoch_restore_read(&sealed).await.is_err(),
            "same voter ID cannot revive the original process witness");
        let cold = node.native_v6_epoch_restore_read(intent.operation_digest, deadline()).await?;
        assert_eq!(cold.begin_log_id(), initial.begin_log_id());
        assert_eq!(cold.intent_log_id(), Some(stage_log));
        assert_eq!(cold.source_root(), &old_root);
        assert_eq!(cold.source_enrollment(), &old_enrollment);
        assert!(!sealed.same_transition(&cold));
        node.reconcile_exact_staged_v6_intent(&intent, &staged).await?;
        assert!(node.reconcile_exact_staged_v6_intent(&intent, &duplicate).await.is_err(),
            "a purged duplicate slot cannot borrow the snapshot's immutable FIRST Stage provenance");
        let cold_for_rejected_duplicate = node.native_v6_epoch_restore_read(intent.operation_digest, deadline()).await?;
        assert!(node.publish_native_v6_epoch_restore(
            node.next_production_client_serial().await?, &cold_for_rejected_duplicate,
            &duplicate, vec![0x98; 64],
        ).await.is_err(), "cold epoch CAS must also retain the first full LogId");
        for voter in &fixture.nodes {
            assert!(voter.membership_observation().await?.purged_index >= Some(stage_log.index));
            let admission = voter.admit_native_v6_closure(&intent, deadline()).await?;
            assert_eq!(admission.intent_log_id(), stage_log);
            assert_eq!(admission.enrollment(), cold.target_enrollment());
            assert_eq!(selected(voter).await?.root(), &old_root);
        }
        let cold = node.native_v6_epoch_restore_read(intent.operation_digest, deadline()).await?;
        let restored = node.publish_native_v6_epoch_restore(
            node.next_production_client_serial().await?, &cold, &staged, vec![0x99; 64],
        ).await?;
        assert_eq!(restored.epoch_transitions().len(), 1);
        fixture.compact_all(restored.publication_log_id().index).await?;
        let leader = fixture.cold_restart().await?;
        let node = &fixture.nodes[leader];
        let read = selected(node).await?;
        assert_eq!(read.root(), &restored);
        assert_eq!(read.enrollment(), cold.target_enrollment());
        assert!(node.native_v6_epoch_restore_read(intent.operation_digest, deadline()).await.is_err());
        let next = next_intent(&read, 9, 16, 17);
        let next_begin = begin(node, &read, &next).await?;
        let next_staged = stage(node, next).await?;
        let next_selected = pending(node, &next_begin).await?;
        let twice = node.publish_native_v6_epoch_restore(
            node.next_production_client_serial().await?, &next_selected, &next_staged, vec![0xaa; 64],
        ).await?;
        assert_eq!(twice.epoch_transitions().len(), 2);
        assert_eq!(twice.native_origin_epoch(), 7);
        assert_eq!(twice.migration_source(), old_root.migration_source());
        let steps: Vec<_> = twice.epoch_transitions().collect();
        assert_eq!(steps[0].source_enrollment(), old_enrollment);
        assert_eq!(steps[0].target_enrollment(), steps[1].source_enrollment());
        assert_eq!(steps[1].source_root_digest(), restored.root_digest());
        assert_eq!(steps[1].source_publication_log_id(), restored.publication_log_id());
        assert_eq!(selected(node).await?.enrollment().epoch(), 9);
        let bytes = node.state_machine.get_state_machine().await.snapshot_bytes()?;
        assert!(crate::StateMachine::from_snapshot(&bytes).is_ok());
        Ok(())
    }.await;
    fixture.finish(result).await
}
