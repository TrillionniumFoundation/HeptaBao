//! Actual follower repair over pinned TLS with a bounded real ReadIndex delay.
//! Consensus is the original durable three-node in-process test router. This
//! test cannot replace the original physical Mac/ROG/Pocket4 110+18 run.
use super::*;

const FOLLOWER_READ_INDEX_DELAY: Duration = Duration::from_millis(35);

#[derive(Clone, Default)]
struct DelayedFollowerReadIndexRouter {
    inner: Router,
    enabled: Arc<AtomicBool>,
    follower_requests: Arc<AtomicU64>,
}

impl fmt::Debug for DelayedFollowerReadIndexRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadyBatchActualFollowerReadIndexRouter")
    }
}

impl RaftPeerRpc for DelayedFollowerReadIndexRouter {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        bytes: Vec<u8>,
        timeout: Duration,
    ) -> futures::future::BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        if kind != RaftRpcKind::ReadIndex || source != 3 || !self.enabled.load(Ordering::Acquire) {
            return self.inner.exchange(source, target, kind, bytes, timeout);
        }
        let this = self.clone();
        Box::pin(async move {
            tokio::time::timeout(timeout, async move {
                // Delay the real RPC, never substitute its response or witness.
                // Ordinary heartbeats, votes and the healthy donor are unchanged.
                tokio::time::sleep(FOLLOWER_READ_INDEX_DELAY).await;
                this.follower_requests.fetch_add(1, Ordering::AcqRel);
                this.inner
                    .exchange(source, target, kind, bytes, timeout)
                    .await
            })
            .await
            .map_err(|_| RemoteRaftError::Transport("actual delayed ReadIndex expired".into()))?
        })
    }
}

async fn open_delayed_follower_nodes(
    path: &Path,
    router: &DelayedFollowerReadIndexRouter,
) -> TestResult<Vec<Arc<ProcessRaftNode>>> {
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let network =
            RemoteNetworkFactory::new(id, BTreeSet::from([1, 2, 3]), Arc::new(router.clone()))?;
        let node = ProcessRaftNode::create(path.join(id.to_string()), id, network).await?;
        router
            .inner
            .peers
            .write()
            .await
            .insert(id, node.rpc_service());
        nodes.push(Arc::new(node));
    }
    Ok(nodes)
}

pub(super) fn committed_root_pull_ready_batch_repairs_actual_follower_with_one_blackhole_in_14s()
-> TestResult {
    let root = Root::new()?;
    let tls = tls_fixture(&root.directory("pki")?)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let router = DelayedFollowerReadIndexRouter::default();
    let nodes = runtime.block_on(open_delayed_follower_nodes(
        &root.directory("raft")?,
        &router,
    ))?;
    runtime.block_on(async {
        nodes[0].initialize_single().await?;
        select_first_leader(&nodes).await?;
        nodes[0].add_learner(2).await?;
        nodes[0].add_learner(3).await?;
        nodes[0]
            .change_membership(BTreeSet::from([1, 2, 3]))
            .await?;
        nodes[0].ensure_linearizable().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let result = (|| -> TestResult {
        let stores = stores(&root, false)?;
        let mut references = Vec::with_capacity(PIPELINE_OBJECTS);
        let mut expected_indices = BTreeMap::new();
        for index in 0..PIPELINE_OBJECTS {
            let reference = stores[0]
                .stage_local_checked(&pipeline_ciphertext(index)?, &mut || Ok(()))?
                .reference()
                .clone();
            assert!(expected_indices.insert(reference.id, index).is_none());
            references.push(reference);
        }
        references.sort_unstable_by_key(|reference| reference.id);
        let local = stores[0].persist_local_closure(&references, &mut || Ok(()))?;
        assert_eq!(local.object_count(), PIPELINE_OBJECTS);
        assert_eq!(local.ciphertext_bytes(), PIPELINE_CIPHERTEXT_BYTES as u64);
        let (v5, enrollment) = runtime.block_on(async {
            let v5 = PublishedRecordRoot::new(
                RecordRootBase::Empty,
                ReplicatedEnvelope::new("ready-follower-original-v5", [0xd1; 32], vec![0xd2; 64])?,
                Vec::new(),
            )?;
            let v5 = nodes[0]
                .publish_application_root(nodes[0].next_production_client_serial().await?, &v5)
                .await?;
            let enrollment = nodes[0]
                .enroll_native_v6_peers(
                    nodes[0].next_production_client_serial().await?,
                    [0xd3; 32],
                    0,
                    tls.pins.clone(),
                    deadline(),
                )
                .await?;
            Ok::<_, Box<dyn std::error::Error>>((v5, enrollment))
        })?;
        let intent = NativeV6CommitIntent {
            cluster_digest: enrollment.cluster_digest(),
            epoch: 0,
            operation_digest: [0xd4; 32],
            closure_manifest_sha256: local.manifest_sha256(),
            object_count: local.object_count() as u64,
            ciphertext_bytes: local.ciphertext_bytes(),
            prior_root_digest: [0xd1; 32],
            proposed_root_digest: [0xd5; 32],
            prior_generation: 0,
            proposed_generation: 1,
            expected_previous_commit_index: v5.log_index,
        };
        let setup_until = Instant::now() + Duration::from_secs(15);
        let live = LiveReceivers::start(&nodes, runtime.handle(), &stores, &enrollment, &tls)?;
        let transport = live.transport(tls.clients[&1].clone())?;
        let staged = runtime.block_on(async {
            nodes[0]
                .stage_application_object(
                    nodes[0].next_production_client_serial().await?,
                    &SealedRecordObject::new_native_v6_commit_intent(intent)?,
                )
                .await
        })?;
        let quorum = replicate_native_v6_closure_to_quorum(
            &nodes[0],
            runtime.handle(),
            &transport,
            &live.routes,
            NativeV6ClosureSource {
                source: &stores[0],
                references: &references,
                intent: &intent,
            },
            setup_until,
        )?;
        assert_eq!(quorum.voter_ids(), &[1, 2]);
        runtime.block_on(quorum.verify_for_publication(&nodes[0]))?;
        let published = runtime.block_on(async {
            nodes[0]
                .publish_native_v6_root(
                    nodes[0].next_production_client_serial().await?,
                    &intent,
                    &staged,
                    &enrollment,
                    vec![0xd6; 64],
                    setup_until,
                )
                .await
        })?;
        assert!(Instant::now() < setup_until);
        drop(quorum);
        drop(live);
        assert_eq!(blob_count(&root.0.join("cipher-3"))?, 0);
        assert!(nodes[0].local_leader_observation()?.local_is_leader);
        assert!(!nodes[2].local_leader_observation()?.local_is_leader);
        let blackhole = TcpBlackhole::start()?;
        router.enabled.store(true, Ordering::Release);
        let started = Instant::now();
        let until = started + Duration::from_secs(14);
        let mut source = ConcurrentPipelineSource::start(
            nodes[1].clone(),
            runtime.handle(),
            stores[1].clone(),
            &enrollment,
            &tls,
            &blackhole,
            until,
        )?;
        let transport = source.transport(tls.clients[&3].clone())?;
        let selected = runtime
            .block_on(nodes[2].native_v6_committed_root_read(until))?
            .ok_or("actual follower's committed root absent")?;
        assert_eq!(selected.root(), &published);
        let generation = selected.application_generation();
        let before_log = runtime
            .block_on(nodes[2].membership_observation())?
            .applied_index;
        let (recovered, tasks) =
            crate::v6_closure_quorum::committed_pull::observe_pull_tasks(|| {
                recover_native_v6_committed_closure(
                    &nodes[2],
                    runtime.handle(),
                    &transport,
                    &source.routes,
                    &stores[2],
                    selected,
                )
            })?;
        let actual_follower_rpcs = router.follower_requests.load(Ordering::Acquire);
        eprintln!(
            "native ready-batch actual follower return: success={} objects={} actual_follower_readindex_rpcs={} rpc_delay_ms=35 elapsed_ms={} spawned={} joined={} active_frames={} original_budget_ms=14000",
            recovered.is_ok(),
            PIPELINE_OBJECTS,
            actual_follower_rpcs,
            started.elapsed().as_millis(),
            tasks.spawned,
            tasks.joined,
            tasks.active_frames,
        );
        assert_eq!(tasks.spawned, tasks.joined);
        assert_eq!(tasks.active_frames, 0);
        assert!(tasks.peak_frames > 1 && tasks.peak_frames <= 8);
        assert!(tasks.per_donor_peak_frames.values().all(|peak| *peak <= 4));
        let recovered = recovered?;
        assert!(blackhole.accepted.load(Ordering::Acquire));
        assert!(Instant::now() < until);
        assert!(actual_follower_rpcs > 0 && actual_follower_rpcs < PIPELINE_OBJECTS as u64);
        assert_eq!(recovered.read().root(), &published);
        assert_eq!(recovered.read().application_generation(), generation);
        assert_eq!(recovered.read().operation_deadline(), until);
        assert_eq!(recovered.local_receipt().object_count(), PIPELINE_OBJECTS);
        assert_eq!(
            recovered.local_receipt().ciphertext_bytes(),
            PIPELINE_CIPHERTEXT_BYTES as u64
        );
        runtime.block_on(nodes[2].verify_native_v6_committed_root_read(recovered.read()))?;
        assert_eq!(
            runtime
                .block_on(nodes[2].membership_observation())?
                .applied_index,
            before_log
        );
        assert!(!nodes[2].local_leader_observation()?.local_is_leader);
        drop(recovered);
        source.stop_and_join()?;
        assert!(Instant::now() < until);
        let elapsed = started.elapsed();
        assert_eq!(
            stores[2].reopen_root_closure(&published, &mut || Ok(()))?,
            references
        );
        for reference in &references {
            assert_eq!(
                stores[2].read_local(reference)?,
                pipeline_ciphertext(expected_indices[&reference.id])?
            );
        }
        eprintln!(
            "native ready-batch actual follower verified: objects={} ciphertext_bytes={} actual_follower_readindex_rpcs={} rpc_delay_ms=35 elapsed_ms={} original_budget_ms=14000",
            PIPELINE_OBJECTS,
            PIPELINE_CIPHERTEXT_BYTES,
            actual_follower_rpcs,
            elapsed.as_millis(),
        );
        Ok(())
    })();
    runtime.block_on(shutdown_nodes(nodes, &router.inner))?;
    result
}

pub(super) fn committed_root_pull_ready_batch_rejects_reply_after_actual_epoch_publication()
-> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture
            .root
            .directory("ready-batch-old-epoch-empty-store")?;
        let storage = LocalV6BlobStage::open_existing(&path)?;
        let live_receivers = LiveReceivers::start(
            fixture.nodes,
            fixture.runtime.handle(),
            fixture.stores,
            fixture.enrollment,
            fixture.tls,
        )?;
        let mutation_transport = live_receivers.transport(fixture.tls.clients[&1].clone())?;
        let mutation_routes = live_receivers.routes.clone();
        let mutation_runtime = fixture.runtime.handle().clone();
        let mutation_node = fixture.nodes[0].clone();
        let mutation_store = fixture.stores[0].clone();
        let mutation_references = fixture.references.to_vec();
        let old_epoch = fixture.enrollment.epoch();
        let next_epoch = old_epoch.checked_add(1).ok_or("epoch overflow")?;
        let mut next = fixture.published.intent();
        next.epoch = next_epoch;
        next.operation_digest = [0xe1; 32];
        next.prior_root_digest = fixture.published.root_digest();
        next.proposed_root_digest = [0xe2; 32];
        next.prior_generation = fixture.published.generation();
        next.proposed_generation = next.prior_generation + 1;
        next.expected_previous_commit_index = fixture.published.publication_log_id().index;
        let expected_root = next.proposed_root_digest;
        let changed = Arc::new(AtomicBool::new(false));
        let actual_changed = changed.clone();
        let once = AtomicBool::new(false);
        let until = Instant::now() + Duration::from_secs(14);
        let filter: RootReplyFilter = Arc::new(move |request, frame_deadline, _reply| {
            if !request.starts_with(b"HBVP2\x02") || once.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            // The old ciphertext reply already passed the actual source proof.
            // Publish a real new epoch before delivering it, using durable
            // Begin/Stage, the existing pinned TLS fsync quorum, and Publish.
            // No synthetic wire epoch or generation integer becomes a handle.
            let mutation_until = until.min(frame_deadline);
            let result = (|| -> TestResult {
                let current = mutation_runtime
                    .block_on(mutation_node.native_v6_committed_root_read(mutation_until))?
                    .ok_or("current epoch source absent")?;
                assert_eq!(current.enrollment().epoch(), old_epoch);
                let initial = mutation_runtime.block_on(async {
                    mutation_node
                        .begin_native_v6_epoch_restore(
                            mutation_node.next_production_client_serial().await?,
                            &current,
                            next.operation_digest,
                            next.proposed_root_digest,
                        )
                        .await
                })?;
                assert_eq!(initial.target_enrollment().epoch(), next_epoch);
                let staged = mutation_runtime.block_on(async {
                    mutation_node
                        .stage_application_object(
                            mutation_node.next_production_client_serial().await?,
                            &SealedRecordObject::new_native_v6_commit_intent(next)?,
                        )
                        .await
                })?;
                let pending = mutation_runtime.block_on(
                    mutation_node
                        .native_v6_epoch_restore_read(next.operation_digest, mutation_until),
                )?;
                assert_eq!(pending.intent(), Some(next));
                assert_eq!(pending.target_enrollment().epoch(), next_epoch);
                let quorum = replicate_native_v6_closure_to_quorum(
                    &mutation_node,
                    &mutation_runtime,
                    &mutation_transport,
                    &mutation_routes,
                    NativeV6ClosureSource {
                        source: &mutation_store,
                        references: &mutation_references,
                        intent: &next,
                    },
                    mutation_until,
                )?;
                mutation_runtime.block_on(quorum.verify_for_publication(&mutation_node))?;
                let current_pending = mutation_runtime.block_on(
                    mutation_node
                        .native_v6_epoch_restore_read(next.operation_digest, mutation_until),
                )?;
                assert!(pending.same_transition(&current_pending));
                let published = mutation_runtime.block_on(async {
                    mutation_node
                        .publish_native_v6_epoch_restore(
                            mutation_node.next_production_client_serial().await?,
                            &current_pending,
                            &staged,
                            vec![0xe3; 64],
                        )
                        .await
                })?;
                assert_eq!(published.root_digest(), expected_root);
                let actual = mutation_runtime
                    .block_on(mutation_node.native_v6_committed_root_read(mutation_until))?
                    .ok_or("published epoch source absent")?;
                assert_eq!(actual.enrollment().epoch(), next_epoch);
                assert_eq!(actual.root().root_digest(), expected_root);
                actual_changed.store(true, Ordering::Release);
                Ok(())
            })();
            result.map_err(|_| HaError::OutcomeUnknown)
        });
        let blackhole = TcpBlackhole::start()?;
        let source = LiveRootSource::start_filtered(
            fixture.nodes[1].clone(),
            fixture.runtime.handle(),
            fixture.stores[1].clone(),
            fixture.enrollment,
            fixture.tls,
            &blackhole,
            (false, Some(filter)),
        )?;
        let transport = source.transport(fixture.tls.clients[&1].clone())?;
        let selected = fixture.selected(until)?;
        let (result, tasks) = crate::v6_closure_quorum::committed_pull::observe_pull_tasks(|| {
            recover_native_v6_committed_closure(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &transport,
                &source.routes,
                &storage,
                selected,
            )
        })?;
        assert!(
            changed.load(Ordering::Acquire),
            "the actual epoch publication must finish"
        );
        assert!(
            result.is_err(),
            "an old-epoch reply cannot install the selected closure"
        );
        assert_eq!(tasks.spawned, tasks.joined);
        assert_eq!(tasks.active_frames, 0);
        assert_eq!(blob_count(&path)?, 0);
        let current = fixture.selected(until)?;
        assert_eq!(current.enrollment().epoch(), next_epoch);
        assert_eq!(current.root().root_digest(), expected_root);
        assert!(
            storage
                .reopen_root_closure(fixture.published, &mut || Ok(()))
                .is_err()
        );
        assert!(
            storage
                .reopen_root_closure(current.root(), &mut || Ok(()))
                .is_err()
        );
        drop(current);
        drop(source);
        drop(blackhole);
        drop(live_receivers);
        assert!(Instant::now() < until);
        Ok(())
    })
}
