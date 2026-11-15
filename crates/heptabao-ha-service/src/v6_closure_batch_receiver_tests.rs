//! Real durable three-voter Raft and actual pinned TLS. The in-process Raft
//! router is explicit; these are local receiver/disk proofs, never physical HA.
use super::*;
use std::os::unix::fs::MetadataExt;

struct BatchFixture {
    root: Root,
    runtime: tokio::runtime::Runtime,
    router: Router,
    nodes: Vec<Arc<ProcessRaftNode>>,
    local: Vec<Arc<LocalV6BlobStage>>,
    tls: TlsFixture,
    enrollment: NativeV6PeerEnrollment,
    source_index: u64,
    references: Vec<RecordObjectRef>,
    closure_sha: [u8; 32],
    closure_bytes: u64,
}
impl BatchFixture {
    fn intent(&self, tag: u8) -> TestResult<(NativeV6CommitIntent, Binding)> {
        let intent = NativeV6CommitIntent {
            cluster_digest: self.enrollment.cluster_digest(),
            epoch: 0,
            operation_digest: [tag; 32],
            closure_manifest_sha256: self.closure_sha,
            object_count: self.references.len() as u64,
            ciphertext_bytes: self.closure_bytes,
            prior_root_digest: [0x91; 32],
            proposed_root_digest: [0x94; 32],
            prior_generation: 0,
            proposed_generation: 1,
            expected_previous_commit_index: self.source_index,
        };
        self.runtime.block_on(async {
            self.nodes[0]
                .stage_application_object(
                    self.nodes[0].next_production_client_serial().await?,
                    &SealedRecordObject::new_native_v6_commit_intent(intent)?,
                )
                .await
        })?;
        let admission = self
            .runtime
            .block_on(self.nodes[0].admit_native_v6_closure(&intent, deadline()))?;
        Ok((intent, Binding::observed(&admission)))
    }
    fn leaf(&self, reference: &RecordObjectRef) -> PathBuf {
        let id: String = reference
            .id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        self.root.0.join("cipher-2").join(format!("v6-{id}.blob"))
    }
    fn absent_target(&self) -> TestResult {
        for reference in &self.references {
            assert!(
                self.local[1]
                    .read_local_if_present_checked(reference, &mut || Ok(()))?
                    .is_none()
            );
        }
        Ok(())
    }
}
fn with_batch_fixture(run: impl FnOnce(&BatchFixture) -> TestResult) -> TestResult {
    with_sized_batch_fixture(3, 64 * 1024, run)
}
fn with_sized_batch_fixture(
    count: u8,
    object_bytes: usize,
    run: impl FnOnce(&BatchFixture) -> TestResult,
) -> TestResult {
    assert!((1..=32).contains(&count));
    let root = Root::new()?;
    let tls = tls_fixture(&root.directory("pki")?)?;
    let raft = root.directory("raft")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let router = Router::default();
    let nodes = runtime.block_on(open_nodes(&raft, &router, false))?;
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
    let local = stores(&root, false)?;
    let mut references = Vec::new();
    for byte in (0..count).map(|index| 0xb1 + index) {
        references.push(
            local[0]
                .stage_local_checked(&vec![byte; object_bytes], &mut || Ok(()))?
                .reference()
                .clone(),
        );
    }
    references.sort_by_key(|reference| reference.id);
    let closure = local[0].persist_local_closure(&references, &mut || Ok(()))?;
    let (source_index, enrollment) = runtime.block_on(async {
        let source = PublishedRecordRoot::new(
            RecordRootBase::Empty,
            ReplicatedEnvelope::new("batch-receiver-v5-source", [0x91; 32], vec![0x92; 64])?,
            Vec::new(),
        )?;
        let committed = nodes[0]
            .publish_application_root(nodes[0].next_production_client_serial().await?, &source)
            .await?;
        let enrollment = nodes[0]
            .enroll_native_v6_peers(
                nodes[0].next_production_client_serial().await?,
                [0x93; 32],
                0,
                tls.pins.clone(),
                deadline(),
            )
            .await?;
        Ok::<_, Box<dyn std::error::Error>>((committed.log_index, enrollment))
    })?;
    let fixture = BatchFixture {
        root,
        runtime,
        router,
        nodes,
        local,
        tls,
        enrollment,
        source_index,
        references,
        closure_sha: closure.manifest_sha256(),
        closure_bytes: closure.ciphertext_bytes(),
    };
    let result = run(&fixture);
    let BatchFixture {
        root,
        runtime,
        router,
        nodes,
        ..
    } = fixture;
    let closed = runtime.block_on(shutdown_nodes(nodes, &router));
    drop(runtime);
    drop(root);
    closed?;
    result
}
struct BatchReceiver {
    route: NodeId,
    transport: MutualTlsPeerTransport,
    receiver: Arc<NativeV6ClosureReceiver>,
    seen: Arc<Mutex<Vec<Kind>>>,
    fault: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl BatchReceiver {
    fn start(f: &BatchFixture) -> TestResult<Self> {
        let receiver = Arc::new(NativeV6ClosureReceiver::new(
            f.nodes[1].clone(),
            f.runtime.handle().clone(),
            f.local[1].clone(),
            &f.enrollment,
        )?);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let route = NodeId::parse("batch-target-2")?;
        let transport = MutualTlsPeerTransport::new(
            BTreeMap::from([(
                route.clone(),
                TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?,
            )]),
            f.tls.clients[&1].clone(),
            Duration::from_secs(4),
        )?;
        let server = f.tls.servers[&2].clone();
        let actual = receiver.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let observed = seen.clone();
        let fault = Arc::new(AtomicU64::new(0));
        let mode = fault.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                let _ = serve_one_mtls_authenticated_peer_frame(
                    &listener,
                    server.clone(),
                    &actual.pinned,
                    Duration::from_secs(4),
                    false,
                    |frame| {
                        let kind = wire::parse(frame.payload())?.kind;
                        observed.lock().map_err(|_| unknown())?.push(kind);
                        let active = if matches!(
                            kind,
                            Kind::StageBatch | Kind::FsyncExistingBatch | Kind::PackedStageBatch
                        ) {
                            mode.swap(0, Ordering::AcqRel)
                        } else {
                            0
                        };
                        if active == 1 {
                            thread::sleep(
                                frame.deadline().saturating_duration_since(Instant::now())
                                    + Duration::from_millis(10),
                            );
                        }
                        let result = actual.handle_authenticated(frame)?;
                        if active == 2 {
                            return Err(unknown());
                        }
                        Ok(result)
                    },
                );
                thread::sleep(Duration::from_millis(1));
            }
        });
        Ok(Self {
            route,
            transport,
            receiver,
            seen,
            fault,
            stop,
            worker: Some(worker),
        })
    }
    fn send(
        &self,
        f: &BatchFixture,
        binding: &Binding,
        kind: Kind,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), HaError> {
        raw_request(
            &self.transport,
            &self.route,
            2,
            f.tls.pins[&2],
            binding,
            kind,
            payload,
        )
    }
    fn manifest(&self, f: &BatchFixture, binding: &Binding) -> TestResult {
        let (sent, ack) = self.send(
            f,
            binding,
            Kind::Manifest,
            &wire::manifest_page(0, &f.references)?,
        )?;
        wire::verify_reply(&sent, &ack, &(f.references.len() as u64).to_be_bytes())?;
        Ok(())
    }
    fn unsynced(&self) -> TestResult {
        let guard = self
            .receiver
            .incoming
            .lock()
            .map_err(|_| "incoming poisoned")?;
        let state = guard.as_ref().ok_or("manifest missing")?;
        assert_eq!(state.fsynced_count, 0);
        assert!(state.fsynced.iter().all(|done| !done));
        Ok(())
    }
}
impl Drop for BatchReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn receiver_three_leaf_batch_checks_all_expected_digests_before_any_tls_disk_publication()
-> TestResult {
    with_batch_fixture(|f| {
        let live = BatchReceiver::start(f)?;
        let (_, binding) = f.intent(0xc1)?;
        live.manifest(f, &binding)?;
        let mut payload = batch::payload(&f.local[0], &f.references, true, deadline())?;
        *payload.last_mut().ok_or("payload empty")? ^= 1;
        assert!(live.send(f, &binding, Kind::StageBatch, &payload).is_err());
        live.unsynced()?;
        f.absent_target()?;
        assert!(live.send(f, &binding, Kind::Finalize, &[]).is_err());
        assert!(!fs::read_dir(f.root.0.join("cipher-2"))?.any(|entry| {
            entry.is_ok_and(|e| e.file_name().to_string_lossy().starts_with("v6-closure-"))
        }));
        Ok(())
    })
}

#[test]
fn receiver_three_leaf_batch_real_tls_fsync_and_existing_corruption_are_terminal() -> TestResult {
    with_batch_fixture(|f| {
        let live = BatchReceiver::start(f)?;
        // An already-present corrupt last leaf must refuse the WHOLE batch,
        // preserve that inode/bytes and publish neither earlier missing leaf.
        let last = f.references.last().ok_or("references empty")?;
        let bytes = f.local[0].read_local(last)?;
        f.local[1].stage_received_replica_checked(last, &bytes, &mut || Ok(()))?;
        let path = f.leaf(last);
        let corrupt = vec![0x6d; bytes.len()];
        fs::write(&path, &corrupt)?;
        let before = fs::symlink_metadata(&path)?;
        let (_, binding) = f.intent(0xc2)?;
        live.manifest(f, &binding)?;
        let payload = batch::payload(&f.local[0], &f.references, true, deadline())?;
        assert!(live.send(f, &binding, Kind::StageBatch, &payload).is_err());
        live.unsynced()?;
        assert_eq!(fs::read(&path)?, corrupt);
        let after = fs::symlink_metadata(&path)?;
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        for reference in &f.references[..2] {
            assert!(!f.leaf(reference).exists());
        }
        assert!(live.send(f, &binding, Kind::Finalize, &[]).is_err());
        // Explicit test-owned repair precedes a DISTINCT operation; production
        // never overwrites a corrupt leaf or retries the failed mutation.
        fs::write(&path, &bytes)?;
        let (intent, binding) = f.intent(0xc3)?;
        live.manifest(f, &binding)?;
        let (sent, ack) = live.send(f, &binding, Kind::StageBatch, &payload)?;
        wire::verify_reply(&sent, &ack, &batch::expected(&f.references)?)?;
        let (sent, ack) = live.send(f, &binding, Kind::Finalize, &[])?;
        wire::verify_reply(&sent, &ack, &wire::final_payload(&intent))?;
        // Existing-only reconciliation is separate actual file+directory fsync.
        let (_, binding) = f.intent(0xc4)?;
        live.manifest(f, &binding)?;
        let existing = batch::payload(&f.local[0], &f.references, false, deadline())?;
        let (sent, ack) = live.send(f, &binding, Kind::FsyncExistingBatch, &existing)?;
        wire::verify_reply(&sent, &ack, &batch::expected(&f.references)?)?;
        for reference in &f.references {
            assert_eq!(
                f.local[1].read_local(reference)?,
                f.local[0].read_local(reference)?
            );
        }
        let guard = live
            .receiver
            .incoming
            .lock()
            .map_err(|_| "incoming poisoned")?;
        assert_eq!(guard.as_ref().ok_or("manifest absent")?.fsynced_count, 3);
        Ok(())
    })
}

#[test]
fn receiver_three_leaf_batch_expired_and_applied_admissions_never_ack() -> TestResult {
    with_batch_fixture(|f| {
        let live = BatchReceiver::start(f)?;
        let payload = batch::payload(&f.local[0], &f.references, true, deadline())?;
        let (_, binding) = f.intent(0xc5)?;
        live.manifest(f, &binding)?;
        live.fault.store(1, Ordering::Release);
        assert!(live.send(f, &binding, Kind::StageBatch, &payload).is_err());
        // The receiver owns the original accepted frame deadline. Wait only
        // for that already dispatched handler to retire; no second submission.
        thread::sleep(Duration::from_millis(30));
        live.unsynced()?;
        f.absent_target()?;
        let (_, binding) = f.intent(0xc6)?;
        live.manifest(f, &binding)?;
        let until = Instant::now() + Duration::from_secs(8);
        let original = f
            .runtime
            .block_on(f.nodes[1].admit_native_v6_closure(&binding.intent, until))?;
        let (different, _) = f.intent(0xc7)?;
        let _follower_current = f
            .runtime
            .block_on(f.nodes[1].admit_native_v6_closure(&different, until))?;
        assert!(
            f.runtime
                .block_on(f.nodes[1].verify_native_v6_closure_admission(&original),)
                .is_err()
        );
        // This is the actual opaque admission retained by an already
        // dispatched receiver, not a claim that its wire Binding prevents a
        // later request from acquiring a separately valid fresh admission.
        {
            let mut guard = live
                .receiver
                .incoming
                .lock()
                .map_err(|_| "incoming poisoned")?;
            let state = guard.as_mut().ok_or("manifest absent")?;
            assert!(
                live.receiver
                    .receive_batch(state, &original, until, &payload, true)
                    .is_err()
            );
        }
        live.unsynced()?;
        f.absent_target()?;
        Ok(())
    })
}

#[test]
fn receiver_three_leaf_batch_lost_reply_is_unknown_and_does_not_mint_final_ack() -> TestResult {
    with_batch_fixture(|f| {
        let live = BatchReceiver::start(f)?;
        let (_, binding) = f.intent(0xc8)?;
        live.manifest(f, &binding)?;
        let payload = batch::payload(&f.local[0], &f.references, true, deadline())?;
        live.fault.store(2, Ordering::Release);
        assert!(live.send(f, &binding, Kind::StageBatch, &payload).is_err());
        // This test deliberately performs no reconciliation/second Stage and
        // no Finalize after an unknown reply. Real local receipts are only
        // ciphertext custody; neither a quorum nor a root/HTTP success exists.
        let seen = live.seen.lock().map_err(|_| "observation poisoned")?;
        assert_eq!(
            seen.iter()
                .filter(|kind| **kind == Kind::StageBatch)
                .count(),
            1
        );
        assert!(!seen.contains(&Kind::Finalize));
        for reference in &f.references {
            assert_eq!(
                f.local[1].read_local(reference)?,
                f.local[0].read_local(reference)?
            );
        }
        assert!(
            f.runtime
                .block_on(f.nodes[0].native_v6_root_at_generation())
                .1
                .is_none()
        );
        Ok(())
    })
}

#[test]
fn receiver_packed_twelve_leaf_batch_checks_last_digest_before_any_publication() -> TestResult {
    with_sized_batch_fixture(12, 60 * 1024, |f| {
        let live = BatchReceiver::start(f)?;
        let (_, binding) = f.intent(0xd1)?;
        live.manifest(f, &binding)?;
        let mut payload = batch::packed_payload(&f.local[0], &f.references, deadline())?;
        *payload.last_mut().ok_or("payload empty")? ^= 1;
        assert!(
            live.send(f, &binding, Kind::PackedStageBatch, &payload)
                .is_err()
        );
        live.unsynced()?;
        f.absent_target()?;
        assert!(live.send(f, &binding, Kind::Finalize, &[]).is_err());
        assert!(!fs::read_dir(f.root.0.join("cipher-2"))?.any(|entry| {
            entry.is_ok_and(|e| e.file_name().to_string_lossy().starts_with("v6-closure-"))
        }));
        Ok(())
    })
}

#[test]
fn receiver_packed_twelve_leaf_batch_has_distinct_kind_real_sync_and_exact_ack() -> TestResult {
    with_sized_batch_fixture(12, 60 * 1024, |f| {
        let live = BatchReceiver::start(f)?;
        let payload = batch::packed_payload(&f.local[0], &f.references, deadline())?;
        let (_, legacy_binding) = f.intent(0xd2)?;
        live.manifest(f, &legacy_binding)?;
        // The same bounded payload cannot expand legacy kind 5's count cap.
        assert!(
            live.send(f, &legacy_binding, Kind::StageBatch, &payload)
                .is_err()
        );
        live.unsynced()?;
        f.absent_target()?;
        let (intent, binding) = f.intent(0xd3)?;
        let encoded = wire::encode(&binding, 2, Kind::PackedStageBatch, &payload)?;
        assert_eq!(wire::parse(&encoded)?.kind, Kind::PackedStageBatch);
        let mut unsupported = encoded.clone();
        unsupported[5] = 9;
        assert!(wire::parse(&unsupported).is_err());
        live.manifest(f, &binding)?;
        let (sent, ack) = live.send(f, &binding, Kind::PackedStageBatch, &payload)?;
        let expected = batch::packed_expected(&f.references)?;
        assert_eq!(expected.len(), batch::MAX_PACKED_ACK);
        wire::verify_reply(&sent, &ack, &expected)?;
        for reference in &f.references {
            assert_eq!(
                f.local[1].read_local(reference)?,
                f.local[0].read_local(reference)?
            );
        }
        {
            let guard = live
                .receiver
                .incoming
                .lock()
                .map_err(|_| "incoming poisoned")?;
            let state = guard.as_ref().ok_or("manifest absent")?;
            assert_eq!(state.fsynced_count, 12);
            assert!(state.fsynced.iter().all(|done| *done));
        }
        let (sent, ack) = live.send(f, &binding, Kind::Finalize, &[])?;
        wire::verify_reply(&sent, &ack, &wire::final_payload(&intent))?;
        Ok(())
    })
}

#[test]
fn receiver_packed_batch_original_expiry_and_stale_admission_never_ack() -> TestResult {
    with_sized_batch_fixture(12, 60 * 1024, |f| {
        let live = BatchReceiver::start(f)?;
        let payload = batch::packed_payload(&f.local[0], &f.references, deadline())?;
        let (_, binding) = f.intent(0xd4)?;
        live.manifest(f, &binding)?;
        live.fault.store(1, Ordering::Release);
        assert!(
            live.send(f, &binding, Kind::PackedStageBatch, &payload)
                .is_err()
        );
        thread::sleep(Duration::from_millis(30));
        live.unsynced()?;
        f.absent_target()?;
        let (_, binding) = f.intent(0xd5)?;
        live.manifest(f, &binding)?;
        let until = Instant::now() + Duration::from_secs(8);
        let original = f
            .runtime
            .block_on(f.nodes[1].admit_native_v6_closure(&binding.intent, until))?;
        let (different, _) = f.intent(0xd6)?;
        let _follower_current = f
            .runtime
            .block_on(f.nodes[1].admit_native_v6_closure(&different, until))?;
        assert!(
            f.runtime
                .block_on(f.nodes[1].verify_native_v6_closure_admission(&original))
                .is_err()
        );
        {
            let mut guard = live
                .receiver
                .incoming
                .lock()
                .map_err(|_| "incoming poisoned")?;
            let state = guard.as_mut().ok_or("manifest absent")?;
            assert!(
                live.receiver
                    .receive_packed_stage(state, &original, until, &payload)
                    .is_err()
            );
        }
        live.unsynced()?;
        f.absent_target()?;
        Ok(())
    })
}

#[test]
fn receiver_packed_batch_lost_reply_is_unknown_without_replay_or_final_ack() -> TestResult {
    with_sized_batch_fixture(12, 60 * 1024, |f| {
        let live = BatchReceiver::start(f)?;
        let (_, binding) = f.intent(0xd7)?;
        live.manifest(f, &binding)?;
        let payload = batch::packed_payload(&f.local[0], &f.references, deadline())?;
        live.fault.store(2, Ordering::Release);
        assert!(
            live.send(f, &binding, Kind::PackedStageBatch, &payload)
                .is_err()
        );
        let seen = live.seen.lock().map_err(|_| "observation poisoned")?;
        assert_eq!(
            seen.iter()
                .filter(|kind| **kind == Kind::PackedStageBatch)
                .count(),
            1
        );
        assert!(!seen.contains(&Kind::StageBatch));
        assert!(!seen.contains(&Kind::Stage));
        assert!(!seen.contains(&Kind::Finalize));
        for reference in &f.references {
            assert_eq!(
                f.local[1].read_local(reference)?,
                f.local[0].read_local(reference)?
            );
        }
        assert!(
            f.runtime
                .block_on(f.nodes[0].native_v6_root_at_generation())
                .1
                .is_none()
        );
        Ok(())
    })
}
