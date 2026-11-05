//! Real pinned TLS / durable Raft regression at the observed 442-leaf scale.
//!
//! The bytes are synthetic opaque ciphertext, not a Service KV page graph or
//! physical-host qualification. The original physical HA suite remains required.
use super::*;
use std::sync::Condvar;
use std::sync::atomic::AtomicUsize;

const PIPELINE_OBJECTS: usize = 442;
const PIPELINE_CIPHERTEXT_BYTES: usize = 36_199_452;
const PIPELINE_DONOR_WORKERS: usize = 4;

fn pipeline_ciphertext(index: usize) -> TestResult<Vec<u8>> {
    // Keep the original 136 * 256KiB payload population and add bounded small
    // leaves. This matches the physical failure's exact count and byte total,
    // without pretending that arbitrary chunks are authenticated Service pages.
    let bytes = match index {
        0..=135 => 256 * 1024,
        136..=440 => 1_790,
        441 => 1_918,
        _ => return Err("pipeline fixture index outside its closed population".into()),
    };
    let mut ciphertext = vec![(index % 251 + 1) as u8; bytes];
    ciphertext[..8].copy_from_slice(&(index as u64).to_be_bytes());
    Ok(ciphertext)
}

#[derive(Default)]
struct FirstObjectWave {
    ids: BTreeSet<[u8; 32]>,
    released: bool,
}

#[derive(Default)]
struct PipelineSourceObservation {
    requests: Mutex<Vec<[u8; 32]>>,
    active: AtomicUsize,
    peak: AtomicUsize,
    completed: AtomicUsize,
    workers_finished: AtomicUsize,
    first_wave: Mutex<FirstObjectWave>,
    changed: Condvar,
}

struct ObservedObject<'a> {
    observed: &'a PipelineSourceObservation,
}

impl Drop for ObservedObject<'_> {
    fn drop(&mut self) {
        self.observed.active.fetch_sub(1, Ordering::AcqRel);
        self.observed.completed.fetch_add(1, Ordering::AcqRel);
    }
}

impl PipelineSourceObservation {
    fn enter(&self, payload: &[u8], until: Instant) -> Result<ObservedObject<'_>, HaError> {
        if !payload.starts_with(b"HBVP2\x02") || payload.len() < 36 {
            return Err(HaError::InvalidFrame);
        }
        let id: [u8; 32] = payload[payload.len() - 36..payload.len() - 4]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?;
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak.fetch_max(active, Ordering::AcqRel);
        let held = ObservedObject { observed: self };
        self.requests
            .lock()
            .map_err(|_| HaError::OutcomeUnknown)?
            .push(id);
        let mut wave = self
            .first_wave
            .lock()
            .map_err(|_| HaError::OutcomeUnknown)?;
        if !wave.released {
            wave.ids.insert(id);
            if wave.ids.len() == PIPELINE_DONOR_WORKERS {
                wave.released = true;
                self.changed.notify_all();
            }
            while !wave.released {
                let remaining = until
                    .checked_duration_since(Instant::now())
                    .ok_or(HaError::OutcomeUnknown)?;
                let (next, _) = self
                    .changed
                    .wait_timeout(wave, remaining)
                    .map_err(|_| HaError::OutcomeUnknown)?;
                wave = next;
            }
        }
        // This barrier only synchronizes already authenticated real socket
        // requests. The unchanged production source still obtains every real
        // ReadIndex, checks full binding and authenticates every returned byte.
        Ok(held)
    }
}

struct ConcurrentPipelineSource {
    endpoints: BTreeMap<NodeId, TlsPeerEndpoint>,
    routes: BTreeMap<u64, NodeId>,
    stop: Arc<AtomicBool>,
    observed: Arc<PipelineSourceObservation>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl ConcurrentPipelineSource {
    fn start(
        node: Arc<ProcessRaftNode>,
        runtime: &Handle,
        store: Arc<LocalV6BlobStage>,
        enrollment: &NativeV6PeerEnrollment,
        tls: &TlsFixture,
        blackhole: &TcpBlackhole,
        until: Instant,
    ) -> TestResult<Self> {
        let id = node.id();
        assert_eq!(id, 2, "this regression has exactly one healthy donor");
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0")?);
        listener.set_nonblocking(true)?;
        let mut routes = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        for voter in 1..=3 {
            let route = NodeId::parse(format!("pull-pipeline-voter-{voter}"))?;
            let endpoint = if voter == id {
                TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?
            } else {
                blackhole.endpoint.clone()
            };
            routes.insert(voter, route.clone());
            endpoints.insert(route, endpoint);
        }
        let source = Arc::new(NativeV6CommittedRootSource::new(
            node,
            runtime.clone(),
            store,
            enrollment,
        )?);
        let pinned = Arc::new(PinnedClientCertificateMap::new(
            tls.pins
                .iter()
                .map(|(&voter, &pin)| Ok((pin, private_peer_name(voter)?)))
                .collect::<Result<BTreeMap<_, _>, HaError>>()?,
        )?);
        let stop = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(PipelineSourceObservation::default());
        let mut workers = Vec::with_capacity(PIPELINE_DONOR_WORKERS);
        for _ in 0..PIPELINE_DONOR_WORKERS {
            let listener = listener.clone();
            let source = source.clone();
            let pinned = pinned.clone();
            let server = tls.servers[&id].clone();
            let stopped = stop.clone();
            let observed = observed.clone();
            workers.push(thread::spawn(move || {
                while !stopped.load(Ordering::Acquire) {
                    let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    let _ = serve_one_mtls_authenticated_peer_frame(
                        &listener,
                        server.clone(),
                        &pinned,
                        remaining.min(Duration::from_secs(8)),
                        false,
                        |frame| {
                            let held = if frame.payload().starts_with(b"HBVP2\x02") {
                                Some(observed.enter(frame.payload(), frame.deadline().min(until))?)
                            } else {
                                None
                            };
                            let reply = source.handle_authenticated(frame);
                            drop(held);
                            reply
                        },
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                observed.workers_finished.fetch_add(1, Ordering::AcqRel);
            }));
        }
        Ok(Self {
            endpoints,
            routes,
            stop,
            observed,
            workers,
        })
    }

    fn transport(&self, client: Arc<ClientConfig>) -> Result<MutualTlsPeerTransport, HaError> {
        MutualTlsPeerTransport::new(self.endpoints.clone(), client, Duration::from_secs(14))
    }

    fn stop_and_join(&mut self) -> TestResult {
        self.stop.store(true, Ordering::Release);
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            // Visit every owned handle even when one worker panics. Returning
            // from Vec::Drain early would detach the remaining source workers.
            panicked |= worker.join().is_err();
        }
        if panicked {
            return Err("real source worker panicked".into());
        }
        assert_eq!(
            self.observed.workers_finished.load(Ordering::Acquire),
            PIPELINE_DONOR_WORKERS,
        );
        assert_eq!(self.observed.active.load(Ordering::Acquire), 0);
        Ok(())
    }
}

impl Drop for ConcurrentPipelineSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[test]
fn committed_root_pull_four_request_pipeline_repairs_442_leaves_within_original_14s() -> TestResult
{
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
    let (published, references, expected_indices) = (|| -> TestResult<_> {
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
                ReplicatedEnvelope::new("pipeline-original-v5", [0xb1; 32], vec![0xb2; 64])?,
                Vec::new(),
            )?;
            let v5 = nodes[0]
                .publish_application_root(nodes[0].next_production_client_serial().await?, &v5)
                .await?;
            let enrollment = nodes[0]
                .enroll_native_v6_peers(
                    nodes[0].next_production_client_serial().await?,
                    [0xb3; 32],
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
            operation_digest: [0xb4; 32],
            closure_manifest_sha256: local.manifest_sha256(),
            object_count: local.object_count() as u64,
            ciphertext_bytes: local.ciphertext_bytes(),
            prior_root_digest: [0xb1; 32],
            proposed_root_digest: [0xb5; 32],
            prior_generation: 0,
            proposed_generation: 1,
            expected_previous_commit_index: v5.log_index,
        };
        let live = LiveReceivers::start(&nodes, runtime.handle(), &stores, &enrollment, &tls)?;
        let transport = live.transport(tls.clients[&1].clone())?;
        // Keep the existing publication path and its original 15s setup bound.
        // The new missing-leader operation below receives one separate 14s bound.
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
        assert_eq!(quorum.voter_ids(), &[1, 2]);
        runtime.block_on(quorum.verify_for_publication(&nodes[0]))?;
        let published = runtime.block_on(async {
            nodes[0]
                .publish_native_v6_root(
                    nodes[0].next_production_client_serial().await?,
                    &intent,
                    &staged,
                    &enrollment,
                    vec![0xb6; 64],
                    until,
                )
                .await
        })?;
        assert!(Instant::now() < until);
        assert!(
            stores[2]
                .reopen_root_closure(&published, &mut || Ok(()))
                .is_err()
        );
        assert_eq!(blob_count(&root.0.join("cipher-3"))?, 0);
        drop(quorum);
        drop(live);
        Ok((published, references, expected_indices))
    })()?;
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
            .ok_or("new leader absent")?;
        let second = nodes
            .iter()
            .find(|node| node.id() == 2)
            .ok_or("healthy donor absent")?;
        assert!(third.local_leader_observation()?.local_is_leader);
        let enrollment = runtime
            .block_on(
                third.native_v6_committed_root_read(Instant::now() + Duration::from_secs(14)),
            )?
            .ok_or("cold committed root absent")?
            .enrollment()
            .clone();
        let blackhole = TcpBlackhole::start()?;
        let started = Instant::now();
        let until = started + Duration::from_secs(14);
        let mut live = ConcurrentPipelineSource::start(
            second.clone(),
            runtime.handle(),
            stores[1].clone(),
            &enrollment,
            &tls,
            &blackhole,
            until,
        )?;
        let transport = live.transport(tls.clients[&3].clone())?;
        let selected = runtime
            .block_on(third.native_v6_committed_root_read(until))?
            .ok_or("selected cold root absent")?;
        let generation = selected.application_generation();
        let observed_log = runtime
            .block_on(third.membership_observation())?
            .applied_index;
        let (result, tasks) = crate::v6_closure_quorum::committed_pull::observe_pull_tasks(|| {
            recover_native_v6_committed_closure(
                third,
                runtime.handle(),
                &transport,
                &live.routes,
                &stores[2],
                selected,
            )
        })?;
        // These counters belong only to this actual repair. Check the failed
        // return path as well: every spawned socket task must already have
        // completed an actual join and released its charged frame.
        assert!(tasks.spawned > 0);
        assert_eq!(tasks.spawned, tasks.joined);
        assert_eq!(tasks.active_frames, 0);
        assert!(tasks.peak_frames > 1 && tasks.peak_frames <= 8);
        assert!(tasks.per_donor_peak_frames.values().all(|peak| *peak <= 4));
        assert_eq!(tasks.per_donor_peak_frames.get(&1), Some(&1));
        assert!(!tasks.per_donor_peak_frames.contains_key(&3));
        let recovered = result?;
        assert_eq!(tasks.per_donor_peak_frames.get(&2), Some(&4));
        assert!(
            Instant::now() < until,
            "original 14s recovery bound is never enlarged"
        );
        assert!(blackhole.accepted.load(Ordering::Acquire));
        assert_eq!(recovered.read().root(), &published);
        assert_eq!(recovered.read().application_generation(), generation);
        assert_eq!(recovered.read().operation_deadline(), until);
        assert_eq!(recovered.local_receipt().object_count(), PIPELINE_OBJECTS);
        assert_eq!(
            recovered.local_receipt().ciphertext_bytes(),
            PIPELINE_CIPHERTEXT_BYTES as u64
        );
        runtime.block_on(third.verify_native_v6_committed_root_read(recovered.read()))?;
        assert_eq!(
            runtime
                .block_on(third.membership_observation())?
                .applied_index,
            observed_log,
            "missing-leaf repair submits no new intent or Raft publication"
        );
        assert_eq!(
            stores[2].reopen_root_closure(&published, &mut || Ok(()))?,
            references
        );
        drop(recovered);
        live.stop_and_join()?;
        assert!(
            Instant::now() < until,
            "actual source worker joins share the original bound"
        );
        let peak = live.observed.peak.load(Ordering::Acquire);
        assert!(peak > 1 && peak <= PIPELINE_DONOR_WORKERS);
        assert_eq!(
            live.observed
                .first_wave
                .lock()
                .map_err(|_| "wave lock poisoned")?
                .ids
                .len(),
            4
        );
        let requested = live
            .observed
            .requests
            .lock()
            .map_err(|_| "request observation poisoned")?;
        assert_eq!(
            requested.len(),
            PIPELINE_OBJECTS,
            "one healthy donor must fetch every absent immutable leaf once"
        );
        assert_eq!(
            requested.iter().copied().collect::<BTreeSet<_>>(),
            expected_indices.keys().copied().collect()
        );
        assert_eq!(
            live.observed.completed.load(Ordering::Acquire),
            PIPELINE_OBJECTS
        );
        drop(requested);
        eprintln!(
            "native 442-leaf / {PIPELINE_CIPHERTEXT_BYTES}B cold pinned TLS pull: {}ms / 14000ms; actual source peak={peak}; source workers joined=4; client tasks spawned={} joined={} active_frames={} peak_frames={}",
            started.elapsed().as_millis(),
            tasks.spawned,
            tasks.joined,
            tasks.active_frames,
            tasks.peak_frames
        );
        drop(live);
        drop(blackhole);
        drop(stores);
        // Close every store handle, reopen the actual fsynced files, and check
        // every byte against the exact original unique synthetic population.
        let reopened = LocalV6BlobStage::open_existing(&root.0.join("cipher-3"))?;
        assert_eq!(
            reopened.reopen_root_closure(&published, &mut || Ok(()))?,
            references
        );
        let mut bytes = 0usize;
        for reference in &references {
            let restored = reopened.read_local(reference)?;
            assert_eq!(
                restored,
                pipeline_ciphertext(expected_indices[&reference.id])?
            );
            bytes += restored.len();
        }
        assert_eq!(bytes, PIPELINE_CIPHERTEXT_BYTES);
        assert_eq!(blob_count(&root.0.join("cipher-3"))?, PIPELINE_OBJECTS);
        Ok(())
    })();
    runtime.block_on(shutdown_nodes(nodes, &router))?;
    result
}

#[derive(Default)]
struct BlackholeSocketObservation {
    accepted: AtomicUsize,
    active: AtomicUsize,
    eof: AtomicUsize,
    errors: AtomicUsize,
    owner_closed: AtomicUsize,
}

/// A real TCP endpoint which consumes TLS ClientHello bytes but never replies.
/// It observes remote EOF; its own shutdown is counted separately and cannot
/// qualify client cancellation. There is no source proof or response fixture.
struct ObservedTcpBlackhole {
    endpoint: TlsPeerEndpoint,
    stop: Arc<AtomicBool>,
    observed: Arc<BlackholeSocketObservation>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ObservedTcpBlackhole {
    fn start() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let observed = Arc::new(BlackholeSocketObservation::default());
        let observation = observed.clone();
        let worker = thread::spawn(move || {
            let mut sockets = Vec::<std::net::TcpStream>::new();
            let mut bytes = [0_u8; 4096];
            while !stopped.load(Ordering::Acquire) {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            observation.accepted.fetch_add(1, Ordering::AcqRel);
                            if stream.set_nonblocking(true).is_err() {
                                observation.errors.fetch_add(1, Ordering::AcqRel);
                                observation.owner_closed.fetch_add(1, Ordering::AcqRel);
                                continue;
                            }
                            observation.active.fetch_add(1, Ordering::AcqRel);
                            sockets.push(stream);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            observation.errors.fetch_add(1, Ordering::AcqRel);
                            break;
                        }
                    }
                }
                let mut index = 0;
                while index < sockets.len() {
                    let mut closed = false;
                    loop {
                        match std::io::Read::read(&mut sockets[index], &mut bytes) {
                            Ok(0) => {
                                observation.eof.fetch_add(1, Ordering::AcqRel);
                                closed = true;
                                break;
                            }
                            Ok(_) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                                continue;
                            }
                            Err(_) => {
                                observation.errors.fetch_add(1, Ordering::AcqRel);
                                closed = true;
                                break;
                            }
                        }
                    }
                    if closed {
                        drop(sockets.swap_remove(index));
                        observation.active.fetch_sub(1, Ordering::AcqRel);
                    } else {
                        index += 1;
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
            observation
                .owner_closed
                .fetch_add(sockets.len(), Ordering::AcqRel);
            observation
                .active
                .fetch_sub(sockets.len(), Ordering::AcqRel);
        });
        Ok(Self {
            endpoint,
            stop,
            observed,
            worker: Some(worker),
        })
    }

    fn join_after_remote_eof(&mut self, expected: usize, until: Instant) -> TestResult {
        // This is only observation of already cancelled sockets, within this
        // test's one absolute 14s bound. It starts no request or renewed owner.
        while Instant::now() < until
            && (self.observed.accepted.load(Ordering::Acquire) != expected
                || self.observed.eof.load(Ordering::Acquire) != expected
                || self.observed.active.load(Ordering::Acquire) != 0)
        {
            if self.observed.errors.load(Ordering::Acquire) != 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| "observed TCP blackhole panicked")?;
        }
        assert!(Instant::now() < until);
        assert_eq!(self.observed.accepted.load(Ordering::Acquire), expected);
        assert_eq!(self.observed.eof.load(Ordering::Acquire), expected);
        assert_eq!(self.observed.active.load(Ordering::Acquire), 0);
        assert_eq!(self.observed.errors.load(Ordering::Acquire), 0);
        assert_eq!(self.observed.owner_closed.load(Ordering::Acquire), 0);
        Ok(())
    }
}

impl Drop for ObservedTcpBlackhole {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn committed_root_pull_deadline_cancels_and_joins_actual_blackhole_sockets() -> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture.root.directory("deadline-empty-repair-store")?;
        let storage = LocalV6BlobStage::open_existing(&path)?;
        let started = Instant::now();
        let observation_until = started + Duration::from_secs(14);
        let operation_until = started + Duration::from_millis(600);
        let mut blackhole = ObservedTcpBlackhole::start()?;
        let mut routes = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        for voter in 1..=3 {
            let route = NodeId::parse(format!("deadline-pull-voter-{voter}"))?;
            endpoints.insert(route.clone(), blackhole.endpoint.clone());
            routes.insert(voter, route);
        }
        let transport = MutualTlsPeerTransport::new(
            endpoints,
            fixture.tls.clients[&1].clone(),
            Duration::from_secs(14),
        )?;
        let selected = fixture.selected(operation_until)?;
        let (result, tasks) = crate::v6_closure_quorum::committed_pull::observe_pull_tasks(|| {
            recover_native_v6_committed_closure(
                &fixture.nodes[0],
                fixture.runtime.handle(),
                &transport,
                &routes,
                &storage,
                selected,
            )
        })?;
        assert!(
            result.is_err(),
            "a TCP accept cannot supply a pinned TLS root proof"
        );
        assert!(
            Instant::now() >= operation_until,
            "the real silent peers reach the original deadline"
        );
        assert_eq!(tasks.spawned, 2);
        assert_eq!(tasks.joined, tasks.spawned);
        assert_eq!(tasks.active_frames, 0);
        assert_eq!(tasks.peak_frames, 2);
        assert_eq!(
            tasks.per_donor_peak_frames,
            BTreeMap::from([(2, 1), (3, 1)])
        );
        blackhole.join_after_remote_eof(2, observation_until)?;
        assert_eq!(blob_count(&path)?, 0);
        assert!(
            storage
                .reopen_root_closure(fixture.published, &mut || Ok(()))
                .is_err()
        );
        assert!(Instant::now() < observation_until);
        eprintln!(
            "native pull timeout: operation_ms=600 client_tasks={} joined={} active_frames={} actual_tcp_eof=2 owner_closed=0 elapsed_ms={}",
            tasks.spawned,
            tasks.joined,
            tasks.active_frames,
            started.elapsed().as_millis(),
        );
        Ok(())
    })
}

#[test]
fn committed_root_pull_changed_actual_root_cancels_and_joins_outstanding_tasks() -> TestResult {
    with_current_committed_closure(|fixture| {
        let path = fixture.root.directory("root-change-empty-repair-store")?;
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
        let mutation_enrollment = fixture.enrollment.clone();
        let mut next = fixture.published.intent();
        next.operation_digest = [0xc1; 32];
        next.prior_root_digest = fixture.published.root_digest();
        next.proposed_root_digest = [0xc2; 32];
        next.prior_generation = fixture.published.generation();
        next.proposed_generation = next.prior_generation + 1;
        next.expected_previous_commit_index = fixture.published.publication_log_id().index;
        let expected_digest = next.proposed_root_digest;
        let changed = Arc::new(AtomicBool::new(false));
        let actual_changed = changed.clone();
        let once = AtomicBool::new(false);
        let started = Instant::now();
        let until = started + Duration::from_secs(14);
        let filter: RootReplyFilter = Arc::new(move |request, frame_deadline, _reply| {
            if !request.starts_with(b"HBVP2\x02") || once.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            // The source has already produced a real checked reply. Change the
            // actual consensus-selected root before that old reply is delivered,
            // through the same stage/quorum/publication path as the old test.
            let mutation_until = until.min(frame_deadline);
            let result = (|| -> TestResult {
                let staged = mutation_runtime.block_on(async {
                    mutation_node
                        .stage_application_object(
                            mutation_node.next_production_client_serial().await?,
                            &SealedRecordObject::new_native_v6_commit_intent(next)?,
                        )
                        .await
                })?;
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
                let published = mutation_runtime.block_on(async {
                    mutation_node
                        .publish_native_v6_root(
                            mutation_node.next_production_client_serial().await?,
                            &next,
                            &staged,
                            &mutation_enrollment,
                            vec![0xc3; 64],
                            mutation_until,
                        )
                        .await
                })?;
                assert_eq!(published.root_digest(), expected_digest);
                assert!(Instant::now() < mutation_until);
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
            "a real replacement root must have committed"
        );
        assert!(
            result.is_err(),
            "a changed root cannot replace the original selection"
        );
        assert!(
            tasks.spawned >= 5,
            "both donor probes and actual object tasks ran"
        );
        assert_eq!(tasks.joined, tasks.spawned);
        assert_eq!(tasks.active_frames, 0);
        assert!(tasks.peak_frames > 1 && tasks.peak_frames <= 8);
        assert!(tasks.per_donor_peak_frames.values().all(|peak| *peak <= 4));
        let current = fixture.selected(until)?;
        assert_eq!(current.root().root_digest(), expected_digest);
        assert_ne!(current.root(), fixture.published);
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
        assert!(
            Instant::now() < until,
            "root-change failure and owned joins retain the original 14s bound"
        );
        eprintln!(
            "native pull actual root change: client_tasks={} joined={} active_frames={} elapsed_ms={} budget_ms=14000",
            tasks.spawned,
            tasks.joined,
            tasks.active_frames,
            started.elapsed().as_millis(),
        );
        Ok(())
    })
}

#[path = "v6_committed_root_pull_ready_batch_tests.rs"]
mod ready_batch_tests;

// New regression entry points stay outside the original closed 12-test filter.

pub(super) fn committed_root_pull_ready_batch_repairs_actual_follower_with_one_blackhole_in_14s()
-> TestResult {
    ready_batch_tests::committed_root_pull_ready_batch_repairs_actual_follower_with_one_blackhole_in_14s()
}

pub(super) fn committed_root_pull_ready_batch_rejects_reply_after_actual_epoch_publication()
-> TestResult {
    ready_batch_tests::committed_root_pull_ready_batch_rejects_reply_after_actual_epoch_publication(
    )
}
