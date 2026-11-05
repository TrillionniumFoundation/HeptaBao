//! Real durable Raft and real pinned TLS repair. The consensus RPC router is
//! explicitly in-process; this test does not claim physical-host/Actor proof.
use super::*;
use crate::{
    NativeV6CommittedRootSource, read_or_recover_native_v6_committed_closure,
    recover_native_v6_committed_closure,
};

struct LiveRootSource {
    endpoints: BTreeMap<NodeId, TlsPeerEndpoint>,
    routes: BTreeMap<u64, NodeId>,
    stop: Arc<AtomicBool>,
    object_requests: Arc<Mutex<Vec<[u8; 32]>>>,
    worker: Option<thread::JoinHandle<()>>,
}
type RootReplyFilter =
    Arc<dyn Fn(&[u8], Instant, &mut Vec<u8>) -> Result<(), HaError> + Send + Sync>;
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
        Self::start_filtered(
            node,
            runtime,
            store,
            enrollment,
            tls,
            blackhole,
            (wrong_leaf, None),
        )
    }
    fn start_filtered(
        node: Arc<ProcessRaftNode>,
        runtime: &Handle,
        store: Arc<LocalV6BlobStage>,
        enrollment: &NativeV6PeerEnrollment,
        tls: &TlsFixture,
        blackhole: &TcpBlackhole,
        options: (bool, Option<RootReplyFilter>),
    ) -> TestResult<Self> {
        let (wrong_leaf, filter) = options;
        let id = node.id();
        assert!(matches!(id, 2 | 3));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let mut routes = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        for voter in 1..=3 {
            let route = NodeId::parse(format!("pull-voter-{voter}"))?;
            let endpoint = if voter == id {
                TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?
            } else {
                blackhole.endpoint.clone()
            };
            routes.insert(voter, route.clone());
            endpoints.insert(route, endpoint);
        }
        let source = NativeV6CommittedRootSource::new(node, runtime.clone(), store, enrollment)?;
        let pinned = PinnedClientCertificateMap::new(
            tls.pins
                .iter()
                .map(|(&voter, &pin)| Ok((pin, private_peer_name(voter)?)))
                .collect::<Result<BTreeMap<_, _>, HaError>>()?,
        )?;
        let server = tls.servers[&if wrong_leaf { 3 } else { id }].clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let object_requests = Arc::new(Mutex::new(Vec::new()));
        let observed = object_requests.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                let _ = serve_one_mtls_authenticated_peer_frame(
                    &listener,
                    server.clone(),
                    &pinned,
                    Duration::from_secs(8),
                    false,
                    |frame| {
                        // Observation only: the production source below still
                        // parses and authenticates the whole actual request.
                        let payload = frame.payload();
                        if payload.starts_with(b"HBVP2\x02") && payload.len() >= 36 {
                            let id = payload[payload.len() - 36..payload.len() - 4]
                                .try_into()
                                .map_err(|_| HaError::InvalidFrame)?;
                            observed
                                .lock()
                                .map_err(|_| HaError::OutcomeUnknown)?
                                .push(id);
                        }
                        let request = frame.payload().to_vec();
                        let deadline = frame.deadline();
                        let mut reply = source.handle_authenticated(frame)?;
                        if let Some(filter) = &filter {
                            filter(&request, deadline, &mut reply)?;
                        }
                        Ok(reply)
                    },
                );
                thread::sleep(Duration::from_millis(1));
            }
        });
        Ok(Self {
            endpoints,
            routes,
            stop,
            object_requests,
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
            NativeV6ClosureSource {
                source: &stores[0],
                references: &references,
                intent: &intent,
            },
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

struct CurrentClosureFixture<'a> {
    root: &'a Root,
    runtime: &'a tokio::runtime::Runtime,
    router: &'a Router,
    nodes: &'a [Arc<ProcessRaftNode>],
    stores: &'a [Arc<LocalV6BlobStage>],
    tls: &'a TlsFixture,
    enrollment: &'a NativeV6PeerEnrollment,
    published: &'a heptabao_raft_runtime::NativeV6PublishedRoot,
    references: &'a [RecordObjectRef],
}

impl CurrentClosureFixture<'_> {
    fn selected(
        &self,
        until: Instant,
    ) -> TestResult<heptabao_raft_runtime::NativeV6CommittedRootRead> {
        self.runtime
            .block_on(self.nodes[0].native_v6_committed_root_read(until))?
            .ok_or_else(|| "current committed root absent".into())
    }
}

fn with_current_committed_closure(
    check: impl FnOnce(CurrentClosureFixture<'_>) -> TestResult,
) -> TestResult {
    with_current_committed_closure_population(3, check)
}

fn with_current_committed_closure_population(
    count: usize,
    check: impl FnOnce(CurrentClosureFixture<'_>) -> TestResult,
) -> TestResult {
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
    let result = (|| -> TestResult {
        let stores = stores(&root, false)?;
        let mut references = Vec::new();
        for index in 0..count {
            let byte = 0x91_u8
                .checked_add(u8::try_from(index)?)
                .ok_or("bounded fixture population exceeded")?;
            references.push(
                stores[0]
                    .stage_local_checked(&vec![byte; 32 * 1024], &mut || Ok(()))?
                    .reference()
                    .clone(),
            );
        }
        references.sort_unstable_by_key(|reference| reference.id);
        let local = stores[0].persist_local_closure(&references, &mut || Ok(()))?;
        let (v5, enrollment) = runtime.block_on(async {
            let v5 = PublishedRecordRoot::new(
                RecordRootBase::Empty,
                ReplicatedEnvelope::new("current-read-original-v5", [0x81; 32], vec![0x82; 64])?,
                Vec::new(),
            )?;
            let v5 = nodes[0]
                .publish_application_root(nodes[0].next_production_client_serial().await?, &v5)
                .await?;
            let enrollment = nodes[0]
                .enroll_native_v6_peers(
                    nodes[0].next_production_client_serial().await?,
                    [0x83; 32],
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
            operation_digest: [0x84; 32],
            closure_manifest_sha256: local.manifest_sha256(),
            object_count: local.object_count() as u64,
            ciphertext_bytes: local.ciphertext_bytes(),
            prior_root_digest: [0x81; 32],
            proposed_root_digest: [0x85; 32],
            prior_generation: 0,
            proposed_generation: 1,
            expected_previous_commit_index: v5.log_index,
        };
        let live = LiveReceivers::start(&nodes, runtime.handle(), &stores, &enrollment, &tls)?;
        let transport = live.transport(tls.clients[&1].clone())?;
        let until = Instant::now() + Duration::from_secs(15);
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
            until,
        )?;
        runtime.block_on(quorum.verify_for_publication(&nodes[0]))?;
        let published = runtime.block_on(async {
            nodes[0]
                .publish_native_v6_root(
                    nodes[0].next_production_client_serial().await?,
                    &intent,
                    &staged,
                    &enrollment,
                    vec![0x86; 64],
                    until,
                )
                .await
        })?;
        drop(quorum);
        drop(live);
        check(CurrentClosureFixture {
            root: &root,
            runtime: &runtime,
            router: &router,
            nodes: &nodes,
            stores: &stores,
            tls: &tls,
            enrollment: &enrollment,
            published: &published,
            references: &references,
        })
    })();
    runtime.block_on(shutdown_nodes(nodes, &router))?;
    result
}

#[derive(Debug, Eq, PartialEq)]
struct ReadDirectoryObservation {
    directory: (u64, u64, i64, i64, i64, i64),
    entries: BTreeMap<std::ffi::OsString, (u64, Vec<u8>)>,
}

fn read_directory_observation(path: &Path) -> TestResult<ReadDirectoryObservation> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::metadata(path)?;
    let mut entries = BTreeMap::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let bytes = fs::read(entry.path())?;
        entries.insert(
            entry.file_name(),
            (
                bytes.len() as u64,
                digest(&SHA256, &bytes).as_ref().to_vec(),
            ),
        );
    }
    Ok(ReadDirectoryObservation {
        directory: (
            metadata.dev(),
            metadata.ino(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ),
        entries,
    })
}

fn immutable_name(prefix: &str, id: &[u8; 32], suffix: &str) -> TestResult<String> {
    use std::fmt::Write as _;
    let mut name = prefix.to_owned();
    for byte in id {
        write!(&mut name, "{byte:02x}")?;
    }
    name.push_str(suffix);
    Ok(name)
}

#[test]
fn committed_root_pull_local_leaf_changed_after_fsync_is_rejected_before_closure_receipt()
-> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture.root.directory("local-changed-after-sync")?;
        let target = LocalV6BlobStage::open_existing(&path)?;
        for reference in &fixture.references[..2] {
            let ciphertext = fixture.stores[0].read_local(reference)?;
            target.stage_received_replica_checked(reference, &ciphertext, &mut || Ok(()))?;
        }
        let leaf = path.join(immutable_name("v6-", &fixture.references[0].id, ".blob")?);
        let damaged = vec![0xc7; fixture.references[0].payload_bytes as usize];
        let injected_damage = damaged.clone();
        let changed = Arc::new(AtomicBool::new(false));
        let injected = changed.clone();
        let blackhole = TcpBlackhole::start()?;
        let source = LiveRootSource::start_filtered(
            fixture.nodes[1].clone(),
            fixture.runtime.handle(),
            fixture.stores[1].clone(),
            fixture.enrollment,
            fixture.tls,
            &blackhole,
            (
                false,
                Some(Arc::new(move |request, _, _reply| {
                    if request.starts_with(b"HBVP2\x02") && !injected.swap(true, Ordering::AcqRel) {
                        // Object requests start only after existing local leaves
                        // crossed the actual checked fsync batch. Replace one
                        // of those leaves with a different real inode/content.
                        fs::remove_file(&leaf).map_err(|_| HaError::OutcomeUnknown)?;
                        fs::write(&leaf, &injected_damage).map_err(|_| HaError::OutcomeUnknown)?;
                    }
                    Ok(())
                })),
            ),
        )?;
        let transport = source.transport(fixture.tls.clients[&1].clone())?;
        let until = Instant::now() + Duration::from_secs(15);
        assert!(
            recover_native_v6_committed_closure(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &transport,
                &source.routes,
                &target,
                fixture.selected(until)?,
            )
            .is_err()
        );
        assert!(Instant::now() < until);
        assert!(changed.load(Ordering::Acquire));
        assert_eq!(
            *source
                .object_requests
                .lock()
                .map_err(|_| "request observer poisoned")?,
            vec![fixture.references[2].id]
        );
        assert_eq!(
            fs::read(path.join(immutable_name("v6-", &fixture.references[0].id, ".blob")?))?,
            damaged
        );
        assert!(
            target
                .reopen_root_closure(fixture.published, &mut || Ok(()))
                .is_err()
        );
        assert!(
            !path
                .join(immutable_name(
                    "v6-closure-",
                    &fixture.published.intent().closure_manifest_sha256,
                    ".manifest"
                )?)
                .exists(),
            "final full-closure authentication must fail before manifest publication"
        );
        Ok(())
    })
}

#[test]
fn committed_root_pull_duplicate_donor_bad_digest_is_rejected_after_real_local_receipt()
-> TestResult {
    with_current_committed_closure(|fixture| {
        // Both donors really hold the exact committed closure.
        for reference in fixture.references {
            let ciphertext = fixture.stores[0].read_local(reference)?;
            fixture.stores[2].stage_received_replica_checked(
                reference,
                &ciphertext,
                &mut || Ok(()),
            )?;
        }
        fixture.stores[2].persist_local_closure(fixture.references, &mut || Ok(()))?;
        let blackhole = TcpBlackhole::start()?;
        let second_has_object = Arc::new(AtomicBool::new(false));
        let third_has_next_object = Arc::new(AtomicBool::new(false));
        let bad_duplicate_sent = Arc::new(AtomicBool::new(false));
        let wait = |flag: &AtomicBool, deadline: Instant| -> Result<(), HaError> {
            while !flag.load(Ordering::Acquire) {
                check_deadline(deadline)?;
                thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        };
        let first_seen = second_has_object.clone();
        let next_seen = third_has_next_object.clone();
        let bad_sent = bad_duplicate_sent.clone();
        let second = LiveRootSource::start_filtered(
            fixture.nodes[1].clone(),
            fixture.runtime.handle(),
            fixture.stores[1].clone(),
            fixture.enrollment,
            fixture.tls,
            &blackhole,
            (
                false,
                Some(Arc::new(move |request, deadline, reply| {
                    if request.starts_with(b"HBVP2\x02") {
                        first_seen.store(true, Ordering::Release);
                        wait(&next_seen, deadline)?;
                        let last = reply.last_mut().ok_or(HaError::InvalidFrame)?;
                        *last ^= 1;
                        bad_sent.store(true, Ordering::Release);
                    }
                    Ok(())
                })),
            ),
        )?;
        let first_seen = second_has_object.clone();
        let next_seen = third_has_next_object.clone();
        let requests = Arc::new(AtomicU64::new(0));
        let seen = requests.clone();
        let third = LiveRootSource::start_filtered(
            fixture.nodes[2].clone(),
            fixture.runtime.handle(),
            fixture.stores[2].clone(),
            fixture.enrollment,
            fixture.tls,
            &blackhole,
            (
                false,
                Some(Arc::new(move |request, deadline, _reply| {
                    if request.starts_with(b"HBVP2\x02") {
                        if seen.fetch_add(1, Ordering::AcqRel) == 0 {
                            wait(&first_seen, deadline)?;
                        } else {
                            // This next request proves the controller accepted
                            // and really fsynced donor 3's first object already.
                            next_seen.store(true, Ordering::Release);
                            return Err(HaError::OutcomeUnknown);
                        }
                    }
                    Ok(())
                })),
            ),
        )?;
        let mut endpoints = second.endpoints.clone();
        endpoints.insert(
            third.routes[&3].clone(),
            third.endpoints[&third.routes[&3]].clone(),
        );
        let transport = MutualTlsPeerTransport::new(
            endpoints,
            fixture.tls.clients[&1].clone(),
            Duration::from_secs(15),
        )?;
        let path = fixture.root.directory("duplicate-bad-repair")?;
        let target = LocalV6BlobStage::open_existing(&path)?;
        let until = Instant::now() + Duration::from_secs(15);
        assert!(
            recover_native_v6_committed_closure(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &transport,
                &second.routes,
                &target,
                fixture.selected(until)?,
            )
            .is_err()
        );
        assert!(Instant::now() < until);
        assert!(second_has_object.load(Ordering::Acquire));
        assert!(third_has_next_object.load(Ordering::Acquire));
        assert!(bad_duplicate_sent.load(Ordering::Acquire));
        assert_eq!(
            blob_count(&path)?,
            1,
            "only the first real successful receipt was staged"
        );
        assert!(
            target
                .reopen_root_closure(fixture.published, &mut || Ok(()))
                .is_err(),
            "the corrupt duplicate cannot produce a closure receipt"
        );
        Ok(())
    })
}

#[test]
fn committed_root_pull_reuses_only_authenticated_fsynced_local_objects_and_keeps_corruption_terminal()
-> TestResult {
    with_current_committed_closure(|fixture| {
        let blackhole = TcpBlackhole::start()?;
        let live = LiveRootSource::start(
            fixture.nodes[1].clone(),
            fixture.runtime.handle(),
            fixture.stores[1].clone(),
            fixture.enrollment,
            fixture.tls,
            &blackhole,
            false,
        )?;
        let transport = live.transport(fixture.tls.clients[&1].clone())?;
        let repaired_path = fixture.root.directory("partly-local-repair")?;
        let repaired = LocalV6BlobStage::open_existing(&repaired_path)?;
        for reference in &fixture.references[..2] {
            let ciphertext = fixture.stores[0].read_local(reference)?;
            repaired.stage_received_replica_checked(reference, &ciphertext, &mut || Ok(()))?;
        }
        // There is no manifest in this voter, and one actual leaf is missing.
        assert!(
            repaired
                .reopen_root_closure(fixture.published, &mut || Ok(()))
                .is_err()
        );
        let until = Instant::now() + Duration::from_secs(15);
        let selected = fixture.selected(until)?;
        let generation = selected.application_generation();
        let log = fixture
            .runtime
            .block_on(fixture.nodes[0].membership_observation())?
            .applied_index;
        let recovered = recover_native_v6_committed_closure(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &transport,
            &live.routes,
            &repaired,
            selected,
        )?;
        assert!(Instant::now() < until);
        assert_eq!(recovered.read().operation_deadline(), until);
        assert_eq!(recovered.read().application_generation(), generation);
        assert_eq!(recovered.read().root(), fixture.published);
        assert_eq!(
            recovered.local_receipt().object_count(),
            fixture.references.len()
        );
        assert_eq!(
            recovered.local_receipt().ciphertext_bytes(),
            fixture.published.intent().ciphertext_bytes
        );
        assert_eq!(
            *live
                .object_requests
                .lock()
                .map_err(|_| "request observer poisoned")?,
            vec![fixture.references[2].id],
            "valid existing ciphertext must cross local checked fsync, without network re-download"
        );
        assert!(
            blackhole.accepted.load(Ordering::Acquire),
            "one donor was an actual TCP blackhole"
        );
        assert_eq!(
            fixture
                .runtime
                .block_on(fixture.nodes[0].membership_observation())?
                .applied_index,
            log,
            "repair submits no Raft write"
        );
        drop(recovered);
        drop(repaired);
        let cold = LocalV6BlobStage::open_existing(&repaired_path)?;
        assert_eq!(
            cold.reopen_root_closure(fixture.published, &mut || Ok(()))?,
            fixture.references
        );
        drop(cold);

        let corrupt_path = fixture.root.directory("partly-local-corrupt")?;
        let corrupt = LocalV6BlobStage::open_existing(&corrupt_path)?;
        let reference = &fixture.references[0];
        let ciphertext = fixture.stores[0].read_local(reference)?;
        corrupt.stage_received_replica_checked(reference, &ciphertext, &mut || Ok(()))?;
        let leaf = corrupt_path.join(immutable_name("v6-", &reference.id, ".blob")?);
        let damaged = vec![0xa7; ciphertext.len()];
        fs::write(&leaf, &damaged)?;
        let requests_before = live
            .object_requests
            .lock()
            .map_err(|_| "request observer poisoned")?
            .len();
        assert!(
            recover_native_v6_committed_closure(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &transport,
                &live.routes,
                &corrupt,
                fixture.selected(Instant::now() + Duration::from_secs(15))?,
            )
            .is_err(),
            "present corrupt bytes must fail rather than being fetched over"
        );
        assert_eq!(fs::read(&leaf)?, damaged);
        assert_eq!(
            live.object_requests
                .lock()
                .map_err(|_| "request observer poisoned")?
                .len(),
            requests_before,
            "corruption must fail before any object pull"
        );
        assert!(
            corrupt
                .reopen_root_closure(fixture.published, &mut || Ok(()))
                .is_err()
        );
        Ok(())
    })
}

#[test]
fn committed_read_current_closure_is_read_only_and_repairs_only_through_checked_tls() -> TestResult
{
    with_current_committed_closure(|fixture| {
        let blackhole = TcpBlackhole::start()?;
        let live = LiveRootSource::start(
            fixture.nodes[1].clone(),
            fixture.runtime.handle(),
            fixture.stores[1].clone(),
            fixture.enrollment,
            fixture.tls,
            &blackhole,
            false,
        )?;
        let transport = live.transport(fixture.tls.clients[&1].clone())?;
        let path = fixture.root.0.join("cipher-1");
        let before = read_directory_observation(&path)?;
        let until = Instant::now() + Duration::from_secs(15);
        let selected = fixture.selected(until)?;
        let generation = selected.application_generation();
        let observed_log = fixture
            .runtime
            .block_on(fixture.nodes[0].membership_observation())?
            .applied_index;
        let read = read_or_recover_native_v6_committed_closure(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &transport,
            &live.routes,
            &fixture.stores[0],
            selected,
        )?;
        assert_eq!(read.root(), fixture.published);
        assert_eq!(read.application_generation(), generation);
        assert_eq!(read.operation_deadline(), until);
        fixture
            .runtime
            .block_on(fixture.nodes[0].verify_native_v6_committed_root_read(&read))?;
        assert_eq!(
            read_directory_observation(&path)?,
            before,
            "a complete read must not republish the manifest or change store entries",
        );
        assert_eq!(
            fixture
                .runtime
                .block_on(fixture.nodes[0].membership_observation())?
                .applied_index,
            observed_log,
            "a complete read must submit no Raft write",
        );
        drop(read);
        assert!(
            read_or_recover_native_v6_committed_closure(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &transport,
                &BTreeMap::new(),
                &fixture.stores[0],
                fixture.selected(Instant::now() + Duration::from_secs(2))?,
            )
            .is_err(),
            "an intact closure cannot bypass actual enrolled route binding",
        );
        let repaired_path = fixture.root.directory("current-read-missing")?;
        let repaired = LocalV6BlobStage::open_existing(&repaired_path)?;
        let read = read_or_recover_native_v6_committed_closure(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &transport,
            &live.routes,
            &repaired,
            fixture.selected(Instant::now() + Duration::from_secs(15))?,
        )?;
        assert_eq!(read.root(), fixture.published);
        assert_eq!(
            repaired.reopen_root_closure(fixture.published, &mut || Ok(()))?,
            fixture.references,
        );
        drop(read);
        drop(repaired);
        let cold = LocalV6BlobStage::open_existing(&repaired_path)?;
        assert_eq!(
            cold.reopen_root_closure(fixture.published, &mut || Ok(()))?,
            fixture.references,
            "missing data must use the original fsynced repair and survive reopen",
        );
        drop(cold);
        let leaf = path.join(immutable_name("v6-", &fixture.references[0].id, ".blob")?);
        let original_leaf = fs::read(&leaf)?;
        let damaged_leaf = b"damaged existing immutable ciphertext";
        fs::write(&leaf, damaged_leaf)?;
        assert!(
            read_or_recover_native_v6_committed_closure(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &transport,
                &live.routes,
                &fixture.stores[0],
                fixture.selected(Instant::now() + Duration::from_secs(2))?,
            )
            .is_err(),
        );
        assert_eq!(fs::read(&leaf)?.as_slice(), damaged_leaf);
        // Test-owned restoration follows the observed refusal. The production
        // read/repair path must not overwrite that damaged existing leaf.
        fs::write(&leaf, original_leaf)?;
        let manifest = path.join(immutable_name(
            "v6-closure-",
            &fixture.published.intent().closure_manifest_sha256,
            ".manifest",
        )?);
        let damaged_manifest = b"damaged existing immutable manifest";
        fs::write(&manifest, damaged_manifest)?;
        assert!(
            read_or_recover_native_v6_committed_closure(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &transport,
                &live.routes,
                &fixture.stores[0],
                fixture.selected(Instant::now() + Duration::from_secs(2))?,
            )
            .is_err(),
        );
        assert_eq!(fs::read(&manifest)?.as_slice(), damaged_manifest);
        Ok(())
    })
}

#[test]
fn committed_read_follower_complete_closure_retains_terminal_proof_with_two_actual_readindex_rpcs()
-> TestResult {
    with_current_committed_closure(|fixture| {
        let follower = &fixture.nodes[1];
        assert!(!follower.local_leader_observation()?.local_is_leader);
        assert_eq!(
            fixture.stores[1].reopen_root_closure(fixture.published, &mut || Ok(()))?,
            fixture.references
        );
        let path = fixture.root.0.join("cipher-2");
        let before_directory = read_directory_observation(&path)?;
        let before = fixture.router.read_index_requests.load(Ordering::Acquire);
        let until = Instant::now() + Duration::from_secs(15);
        let selected = fixture
            .runtime
            .block_on(follower.native_v6_committed_root_read(until))?
            .ok_or("follower's actual selected root absent")?;
        assert_eq!(
            fixture.router.read_index_requests.load(Ordering::Acquire),
            before + 1
        );
        let completed = super::super::committed_pull::read_existing_committed_closure(
            follower, fixture.runtime.handle(), &fixture.stores[1], &selected,
            || {
                assert_eq!(fixture.router.read_index_requests.load(Ordering::Acquire), before + 1,
                    "the complete physical read uses its original actual selection without a duplicate quorum RPC");
                Ok(())
            },
        )?.ok_or("complete follower closure was not read")?;
        assert_eq!(
            fixture.router.read_index_requests.load(Ordering::Acquire),
            before + 2,
            "exactly one fresh terminal quorum RPC is still mandatory after the physical read"
        );
        assert!(completed.same_selection(&selected));
        assert_eq!(completed.operation_deadline(), until);
        fixture
            .runtime
            .block_on(follower.verify_native_v6_committed_root_read(&completed))?;
        assert_eq!(read_directory_observation(&path)?, before_directory);
        eprintln!(
            "HBHA-WARM-READINDEX real_follower_rpcs=2 initial=1 redundant_before_read=0 terminal=1"
        );
        Ok(())
    })
}

#[test]
fn committed_read_actual_checkpoint_during_reopen_continues_once_with_both_old_bounds() -> TestResult
{
    with_current_committed_closure(|fixture| {
        let path = fixture.root.0.join("cipher-1");
        let before = read_directory_observation(&path)?;
        let until = Instant::now() + Duration::from_secs(15);
        let selected = fixture.selected(until)?;
        let old_generation = selected.application_generation();
        let old_read_until = selected.read_index_deadline();
        let callback_calls = std::cell::Cell::new(0);
        let result = super::super::committed_pull::read_existing_with_progress_once(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &fixture.stores[0],
            selected,
            || {
                callback_calls.set(callback_calls.get() + 1);
                fixture
                    .runtime
                    .block_on(fixture.nodes[0].snapshot_observed())
                    .map_err(|_| HaError::OutcomeUnknown)?;
                Ok(())
            },
        )?;
        let super::super::committed_pull::ExistingLocalRead::Complete(read) = result else {
            return Err("same-root checkpoint must not request durability repair".into());
        };
        assert_eq!(callback_calls.get(), 1, "no caller callback is replayed");
        assert!(read.application_generation() > old_generation);
        assert_eq!(read.root(), fixture.published);
        assert_eq!(read.enrollment(), fixture.enrollment);
        assert_eq!(read.operation_deadline(), until);
        assert!(read.read_index_deadline() <= old_read_until);
        fixture
            .runtime
            .block_on(fixture.nodes[0].verify_native_v6_committed_root_read(&read))?;
        assert_eq!(read_directory_observation(&path)?, before);
        Ok(())
    })
}

#[test]
fn committed_read_callback_error_never_becomes_a_progress_candidate() -> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture.root.0.join("cipher-1");
        let before = read_directory_observation(&path)?;
        let selected = fixture.selected(Instant::now() + Duration::from_secs(15))?;
        let callback_calls = std::cell::Cell::new(0);
        let result = super::super::committed_pull::read_existing_with_progress_once(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &fixture.stores[0],
            selected,
            || {
                callback_calls.set(callback_calls.get() + 1);
                Err(HaError::Tampered)
            },
        );
        assert!(matches!(result, Err(HaError::Tampered)));
        assert_eq!(callback_calls.get(), 1);
        assert_eq!(read_directory_observation(&path)?, before);
        Ok(())
    })
}

#[test]
fn committed_read_progress_entry_never_renews_an_expired_read_cap() -> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture.root.0.join("cipher-1");
        let before = read_directory_observation(&path)?;
        let until = Instant::now() + Duration::from_secs(15);
        let selected = fixture.selected(until)?;
        let old_read_until = selected.read_index_deadline();
        fixture
            .runtime
            .block_on(fixture.nodes[0].snapshot_observed())?;
        thread::sleep(
            old_read_until.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
        );
        assert!(Instant::now() < until);
        let reopened = std::cell::Cell::new(false);
        let result = super::super::committed_pull::read_existing_with_progress_once(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &fixture.stores[0],
            selected,
            || {
                reopened.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!reopened.get());
        assert_eq!(read_directory_observation(&path)?, before);
        Ok(())
    })
}

#[test]
fn committed_read_expired_original_read_witness_is_not_renewed_inside_live_operation() -> TestResult
{
    with_current_committed_closure(|fixture| {
        let path = fixture.root.0.join("cipher-1");
        let before = read_directory_observation(&path)?;
        let until = Instant::now() + Duration::from_secs(15);
        let selected = fixture.selected(until)?;
        let read_until = selected.read_index_deadline();
        assert!(read_until < until);
        thread::sleep(
            read_until.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
        );
        assert!(
            Instant::now() < until,
            "only the old capped witness expires, not the original operation"
        );
        let reopened = std::cell::Cell::new(false);
        assert!(
            super::super::committed_pull::read_existing_committed_closure(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &fixture.stores[0],
                &selected,
                || {
                    reopened.set(true);
                    Ok(())
                },
            )
            .is_err()
        );
        assert!(
            !reopened.get(),
            "an expired old witness cannot authorize any physical closure read or be silently refreshed"
        );
        assert_eq!(selected.operation_deadline(), until);
        assert_eq!(selected.read_index_deadline(), read_until);
        assert_eq!(read_directory_observation(&path)?, before);
        // A separately obtained actual ReadIndex may still use the original
        // operation's remaining time; it does not mutate the rejected handle.
        let fresh = fixture.selected(until)?;
        let current = super::super::committed_pull::read_existing_committed_closure(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &fixture.stores[0],
            &fresh,
            || Ok(()),
        )?
        .ok_or("fresh real selection did not reopen the complete closure")?;
        assert_eq!(current.operation_deadline(), until);
        assert_eq!(current.root(), fixture.published);
        assert_eq!(read_directory_observation(&path)?, before);
        Ok(())
    })
}

#[test]
fn committed_read_original_live_selection_reads_once_but_partition_refuses_terminal_delivery()
-> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture.root.0.join("cipher-1");
        let before = read_directory_observation(&path)?;
        let until = Instant::now() + Duration::from_millis(600);
        let selected = fixture.selected(until)?;
        let generation = selected.application_generation();
        let read_until = selected.read_index_deadline();
        let reopened = std::cell::Cell::new(false);
        // This is a real selection obtained before the actual network router
        // loses both other voters. No hint or retained metric creates it.
        fixture.runtime.block_on(async {
            let mut peers = fixture.router.peers.write().await;
            peers.remove(&2);
            peers.remove(&3);
        });
        let denied = super::super::committed_pull::read_existing_committed_closure(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &fixture.stores[0],
            &selected,
            || {
                reopened.set(true);
                assert!(Instant::now() < read_until);
                Ok(())
            },
        );
        fixture.runtime.block_on(async {
            let mut peers = fixture.router.peers.write().await;
            peers.insert(2, fixture.nodes[1].rpc_service());
            peers.insert(3, fixture.nodes[2].rpc_service());
        });
        assert!(
            reopened.get(),
            "the original still-live real witness must gate the complete physical closure read without an extra initial quorum round trip"
        );
        assert!(
            denied.is_err(),
            "partition cannot replace the terminal fresh quorum proof with an old selection"
        );
        assert_eq!(selected.operation_deadline(), until);
        assert_eq!(selected.read_index_deadline(), read_until);
        assert_eq!(selected.application_generation(), generation);
        assert_eq!(read_directory_observation(&path)?, before);
        Ok(())
    })
}

#[test]
fn committed_read_current_closure_keeps_changed_root_quorum_and_original_deadline_fences()
-> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture.root.0.join("cipher-1");
        let before = read_directory_observation(&path)?;
        let until = Instant::now() + Duration::from_secs(2);
        let selected = fixture.selected(until)?;
        let reopened = std::cell::Cell::new(false);
        let expired = super::super::committed_pull::read_existing_committed_closure(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &fixture.stores[0],
            &selected,
            || {
                reopened.set(true);
                thread::sleep(
                    until.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
                );
                Ok(())
            },
        );
        assert!(
            reopened.get(),
            "the real complete closure must be read before expiry"
        );
        assert!(
            expired.is_err(),
            "the original operation deadline cannot be renewed"
        );
        assert_eq!(selected.operation_deadline(), until);
        assert_eq!(read_directory_observation(&path)?, before);
        drop(selected);

        let live = LiveReceivers::start(
            fixture.nodes,
            fixture.runtime.handle(),
            fixture.stores,
            fixture.enrollment,
            fixture.tls,
        )?;
        let transport = live.transport(fixture.tls.clients[&1].clone())?;
        let until = Instant::now() + Duration::from_secs(15);
        let selected = fixture.selected(until)?;
        let changed = std::cell::Cell::new(false);
        let rejected = super::super::committed_pull::read_existing_committed_closure(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &fixture.stores[0],
            &selected,
            || {
                let change = (|| -> TestResult {
                    let mut next = fixture.published.intent();
                    next.operation_digest = [0x87; 32];
                    next.prior_root_digest = fixture.published.root_digest();
                    next.proposed_root_digest = [0x88; 32];
                    next.prior_generation = fixture.published.generation();
                    next.proposed_generation = next.prior_generation + 1;
                    next.expected_previous_commit_index =
                        fixture.published.publication_log_id().index;
                    let staged = fixture.runtime.block_on(async {
                        fixture.nodes[0]
                            .stage_application_object(
                                fixture.nodes[0].next_production_client_serial().await?,
                                &SealedRecordObject::new_native_v6_commit_intent(next)?,
                            )
                            .await
                    })?;
                    let quorum = replicate_native_v6_closure_to_quorum(
                        &fixture.nodes[0],
                        fixture.runtime.handle(),
                        &transport,
                        &live.routes,
                        NativeV6ClosureSource {
                            source: &fixture.stores[0],
                            references: fixture.references,
                            intent: &next,
                        },
                        until,
                    )?;
                    fixture
                        .runtime
                        .block_on(quorum.verify_for_publication(&fixture.nodes[0]))?;
                    let actual = fixture.runtime.block_on(async {
                        fixture.nodes[0]
                            .publish_native_v6_root(
                                fixture.nodes[0].next_production_client_serial().await?,
                                &next,
                                &staged,
                                fixture.enrollment,
                                vec![0x89; 64],
                                until,
                            )
                            .await
                    })?;
                    assert_eq!(actual.root_digest(), next.proposed_root_digest);
                    changed.set(true);
                    Ok(())
                })();
                change.map_err(|_| HaError::OutcomeUnknown)
            },
        );
        assert!(
            changed.get(),
            "the test must actually commit the replacement root"
        );
        assert!(
            Instant::now() < until,
            "root-change refusal must precede expiry"
        );
        assert!(
            rejected.is_err(),
            "a new root cannot replace the original selection"
        );
        assert!(
            super::super::committed_pull::read_existing_with_progress_once(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &fixture.stores[0],
                selected,
                || Ok(()),
            )
            .is_err(),
            "an actual root publication cannot be mistaken for application-only progress"
        );
        drop(live);

        let blackhole = TcpBlackhole::start()?;
        let source = LiveRootSource::start(
            fixture.nodes[1].clone(),
            fixture.runtime.handle(),
            fixture.stores[1].clone(),
            fixture.enrollment,
            fixture.tls,
            &blackhole,
            false,
        )?;
        let transport = source.transport(fixture.tls.clients[&1].clone())?;
        let selected = fixture.selected(Instant::now() + Duration::from_millis(600))?;
        fixture.runtime.block_on(async {
            let mut peers = fixture.router.peers.write().await;
            peers.remove(&2);
            peers.remove(&3);
        });
        let no_quorum = read_or_recover_native_v6_committed_closure(
            &fixture.nodes[0],
            fixture.runtime.handle(),
            &transport,
            &source.routes,
            &fixture.stores[0],
            selected,
        );
        fixture.runtime.block_on(async {
            let mut peers = fixture.router.peers.write().await;
            peers.insert(2, fixture.nodes[1].rpc_service());
            peers.insert(3, fixture.nodes[2].rpc_service());
        });
        assert!(
            no_quorum.is_err(),
            "intact files cannot replace a fresh ReadIndex quorum"
        );
        Ok(())
    })
}

#[path = "v6_committed_root_pull_pipeline_tests.rs"]
mod pipeline_tests;

// New regression entry points stay outside the original closed 12-test filter.

pub(super) fn committed_root_pull_ready_batch_repairs_actual_follower_with_one_blackhole_in_14s()
-> TestResult {
    pipeline_tests::committed_root_pull_ready_batch_repairs_actual_follower_with_one_blackhole_in_14s()
}

pub(super) fn committed_root_pull_ready_batch_rejects_reply_after_actual_epoch_publication()
-> TestResult {
    pipeline_tests::committed_root_pull_ready_batch_rejects_reply_after_actual_epoch_publication()
}

#[path = "v6_ingress_reselection_tests.rs"]
mod ingress_reselection_tests;

#[path = "v6_committed_root_pull_donor_window_tests.rs"]
mod donor_window_tests;
