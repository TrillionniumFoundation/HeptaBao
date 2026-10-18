//! Real durable Raft and real pinned TLS repair. The consensus RPC router is
//! explicitly in-process; this test does not claim physical-host/Actor proof.
use super::*;
use crate::{NativeV6CommittedRootSource, recover_native_v6_committed_closure};

struct LiveRootSource {
    endpoints: BTreeMap<NodeId, TlsPeerEndpoint>,
    routes: BTreeMap<u64, NodeId>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl LiveRootSource {
    fn start(
        node: Arc<ProcessRaftNode>,
        runtime: &Handle,
        store: Arc<LocalV6BlobStage>,
        enrollment: &NativeV6PeerEnrollment,
        tls: &TlsFixture,
        blackhole: &TcpBlackhole,
        wrong_leaf: bool,
    ) -> TestResult<Self> {
        let id = node.id();
        assert_eq!(id, 2);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let mut routes = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        for voter in 1..=3 {
            let route = NodeId::parse(format!("pull-voter-{voter}"))?;
            let endpoint = if voter == 2 {
                TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?
            } else {
                blackhole.endpoint.clone()
            };
            routes.insert(voter, route.clone());
            endpoints.insert(route, endpoint);
        }
        let source = NativeV6CommittedRootSource::new(node, runtime.clone(), store, enrollment)?;
        let server = tls.servers[&if wrong_leaf { 3 } else { 2 }].clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                let _ = source.serve_one_mtls(&listener, server.clone(), Duration::from_secs(8));
                thread::sleep(Duration::from_millis(1));
            }
        });
        Ok(Self {
            endpoints,
            routes,
            stop,
            worker: Some(worker),
        })
    }
    fn transport(&self, client: Arc<ClientConfig>) -> Result<MutualTlsPeerTransport, HaError> {
        MutualTlsPeerTransport::new(self.endpoints.clone(), client, Duration::from_secs(15))
    }
}
impl Drop for LiveRootSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn blob_count(path: &Path) -> TestResult<usize> {
    Ok(fs::read_dir(path)?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".blob"))
        .count())
}

async fn select_actual_third_leader(nodes: &[Arc<ProcessRaftNode>]) -> TestResult {
    let second = nodes
        .iter()
        .find(|node| node.id() == 2)
        .ok_or("voter 2 absent")?;
    let third = nodes
        .iter()
        .find(|node| node.id() == 3)
        .ok_or("voter 3 absent")?;
    let until = tokio::time::Instant::now() + Duration::from_secs(12);
    let leader = tokio::time::timeout_at(until, async {
        loop {
            match third.current_leader().await {
                Some(leader @ (2 | 3)) => break leader,
                _ => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await?;
    if leader == 2 {
        // This is an actual explicit transfer after the old leader's shutdown,
        // never an old metric/hint treated as leadership of the missing voter.
        second.transfer_leadership(3).await?;
    }
    tokio::time::timeout_at(until, async {
        loop {
            let observation = third.local_leader_observation()?;
            if observation.local_is_leader
                && observation.leader == Some(3)
                && second.current_leader().await == Some(3)
                && third.ensure_linearizable().await.is_ok()
            {
                return Ok::<(), RemoteRaftError>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    Ok(())
}

#[test]
fn committed_root_pull_repairs_missing_new_leader_34mib_over_real_tls_and_original_deadline()
-> TestResult {
    let root = Root::new()?;
    let tls = tls_fixture(&root.directory("pki")?)?;
    let raft_root = root.directory("raft")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let router = Router::default();
    let nodes = runtime.block_on(open_nodes(&raft_root, &router, false))?;
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
    let (published, references) = (|| -> TestResult<_> {
        let stores = stores(&root, false)?;
        let mut references = Vec::new();
        for index in 0u64..136 {
            let mut ciphertext = vec![(index % 251 + 1) as u8; 256 * 1024];
            ciphertext[..8].copy_from_slice(&index.to_be_bytes());
            references.push(
                stores[0]
                    .stage_local_checked(&ciphertext, &mut || Ok(()))?
                    .reference()
                    .clone(),
            );
        }
        references.sort_unstable_by_key(|reference| reference.id);
        let local = stores[0].persist_local_closure(&references, &mut || Ok(()))?;
        assert_eq!(local.ciphertext_bytes(), 34 * 1024 * 1024);
        let (v5, enrollment) = runtime.block_on(async {
            let v5 = PublishedRecordRoot::new(
                RecordRootBase::Empty,
                ReplicatedEnvelope::new("pull-original-v5", [0x51; 32], vec![0x52; 64])?,
                Vec::new(),
            )?;
            let v5 = nodes[0]
                .publish_application_root(nodes[0].next_production_client_serial().await?, &v5)
                .await?;
            let enrollment = nodes[0]
                .enroll_native_v6_peers(
                    nodes[0].next_production_client_serial().await?,
                    [0x53; 32],
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
            operation_digest: [0x54; 32],
            closure_manifest_sha256: local.manifest_sha256(),
            object_count: local.object_count() as u64,
            ciphertext_bytes: local.ciphertext_bytes(),
            prior_root_digest: [0x51; 32],
            proposed_root_digest: [0x55; 32],
            prior_generation: 0,
            proposed_generation: 1,
            expected_previous_commit_index: v5.log_index,
        };
        let live = LiveReceivers::start(&nodes, runtime.handle(), &stores, &enrollment, &tls)?;
        let transport = live.transport(tls.clients[&1].clone())?;
        let started = Instant::now();
        let until = started + Duration::from_secs(15);
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
            &stores[0],
            &references,
            &intent,
            until,
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
                    vec![0x56; 64],
                    until,
                )
                .await
        })?;
        eprintln!(
            "native 34MiB three-leaf TLS batches: {}ms / 15000ms",
            started.elapsed().as_millis()
        );
        assert!(Instant::now() < until);
        assert!(
            stores[2]
                .reopen_root_closure(&published, &mut || Ok(()))
                .is_err()
        );
        assert_eq!(blob_count(&root.0.join("cipher-3"))?, 0);
        drop(quorum);
        drop(live);
        Ok((published, references))
    })()?;
    // All real Raft nodes and ciphertext owners close. Delete the old leader's
    // entire disposable ciphertext store; only voter 2 retains the closure.
    runtime.block_on(shutdown_nodes(nodes, &router))?;
    fs::remove_dir_all(root.0.join("cipher-1"))?;
    root.directory("cipher-1")?;
    let mut nodes = runtime.block_on(open_nodes(&raft_root, &router, true))?;
    runtime.block_on(select_first_leader(&nodes))?;
    let old_leader = nodes.remove(0);
    assert_eq!(old_leader.id(), 1);
    runtime.block_on(async {
        router.peers.write().await.remove(&1);
        Arc::try_unwrap(old_leader)
            .map_err(|_| "old leader leaked an owner")?
            .shutdown()
            .await?;
        select_actual_third_leader(&nodes).await
    })?;
    let result = (|| -> TestResult {
        let stores = stores(&root, true)?;
        assert_eq!(blob_count(&root.0.join("cipher-1"))?, 0);
        assert_eq!(blob_count(&root.0.join("cipher-3"))?, 0);
        let third = nodes
            .iter()
            .find(|node| node.id() == 3)
            .ok_or("new leader missing")?;
        let second = nodes
            .iter()
            .find(|node| node.id() == 2)
            .ok_or("healthy source missing")?;
        assert!(third.local_leader_observation()?.local_is_leader);
        let enrollment = runtime
            .block_on(
                third.native_v6_committed_root_read(Instant::now() + Duration::from_secs(15)),
            )?
            .ok_or("cold root absent")?
            .enrollment()
            .clone();
        let blackhole = TcpBlackhole::start()?;
        let live = LiveRootSource::start(
            second.clone(),
            runtime.handle(),
            stores[1].clone(),
            &enrollment,
            &tls,
            &blackhole,
            false,
        )?;
        let transport = live.transport(tls.clients[&3].clone())?;
        let started = Instant::now();
        let until = started + Duration::from_secs(15);
        let selected = runtime
            .block_on(third.native_v6_committed_root_read(until))?
            .ok_or("selected root absent")?;
        let generation = selected.application_generation();
        let observed_log = runtime
            .block_on(third.membership_observation())?
            .applied_index;
        let recovered = recover_native_v6_committed_closure(
            third,
            runtime.handle(),
            &transport,
            &live.routes,
            &stores[2],
            selected,
        )?;
        eprintln!(
            "native 34MiB cold missing-leader pinned TLS pull: {}ms / 15000ms",
            started.elapsed().as_millis()
        );
        assert!(Instant::now() < until);
        assert!(
            blackhole.accepted.load(Ordering::Acquire),
            "offline peer was a real accepted TCP blackhole"
        );
        assert_eq!(recovered.read().root(), &published);
        assert_eq!(recovered.read().application_generation(), generation);
        assert_eq!(recovered.read().operation_deadline(), until);
        assert_eq!(
            recovered.local_receipt().ciphertext_bytes(),
            34 * 1024 * 1024
        );
        runtime.block_on(third.verify_native_v6_committed_root_read(recovered.read()))?;
        assert_eq!(
            runtime
                .block_on(third.membership_observation())?
                .applied_index,
            observed_log,
            "repair must submit no Raft intent/publication write"
        );
        assert_eq!(
            stores[2].reopen_root_closure(&published, &mut || Ok(()))?,
            references
        );
        drop(recovered);
        drop(live);
        // Actual wrong server leaf cannot stage even one ciphertext under the
        // otherwise valid committed route and freshly selected root.
        let denied_path = root.directory("wrong-pin-target")?;
        let denied_store = LocalV6BlobStage::open_existing(&denied_path)?;
        let bad = LiveRootSource::start(
            second.clone(),
            runtime.handle(),
            stores[1].clone(),
            &enrollment,
            &tls,
            &blackhole,
            true,
        )?;
        let wrong = bad.transport(tls.clients[&3].clone())?;
        let selected = runtime
            .block_on(
                third.native_v6_committed_root_read(Instant::now() + Duration::from_millis(600)),
            )?
            .ok_or("denial root absent")?;
        assert!(
            recover_native_v6_committed_closure(
                third,
                runtime.handle(),
                &wrong,
                &bad.routes,
                &denied_store,
                selected
            )
            .is_err()
        );
        assert_eq!(blob_count(&denied_path)?, 0);
        drop(bad);
        let selected = runtime
            .block_on(
                third.native_v6_committed_root_read(Instant::now() + Duration::from_millis(100)),
            )?
            .ok_or("expiry root absent")?;
        thread::sleep(Duration::from_millis(120));
        assert!(
            recover_native_v6_committed_closure(
                third,
                runtime.handle(),
                &transport,
                &BTreeMap::new(),
                &denied_store,
                selected
            )
            .is_err()
        );
        assert_eq!(blob_count(&denied_path)?, 0);
        drop(blackhole);
        Ok(())
    })();
    runtime.block_on(shutdown_nodes(nodes, &router))?;
    result
}
