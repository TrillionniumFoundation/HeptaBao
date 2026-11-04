//! Real pinned TLS and real durable Raft for the bounded packed-frame window.
//! The consensus router is in-process; this is not physical-host HA evidence.
use super::*;

struct ParallelReceiver {
    endpoint: TlsPeerEndpoint,
    receiver: Arc<NativeV6ClosureReceiver>,
    frames: Arc<Mutex<Vec<MissingFrameObservation>>>,
    packed_arrivals: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl ParallelReceiver {
    fn start(
        node: Arc<ProcessRaftNode>,
        runtime: Handle,
        storage: Arc<LocalV6BlobStage>,
        enrollment: &NativeV6PeerEnrollment,
        server: Arc<ServerConfig>,
        lose_first_reply: bool,
    ) -> TestResult<Self> {
        let receiver = Arc::new(NativeV6ClosureReceiver::new(
            node, runtime, storage, enrollment,
        )?);
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0")?);
        listener.set_nonblocking(true)?;
        let mut result = Self {
            endpoint: TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?,
            receiver,
            frames: Arc::new(Mutex::new(Vec::new())),
            packed_arrivals: Arc::new(AtomicU64::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
        };
        for _ in 0..2 {
            let receiver = result.receiver.clone();
            let frames = result.frames.clone();
            let arrivals = result.packed_arrivals.clone();
            let stop = result.stop.clone();
            let listener = listener.clone();
            let server = server.clone();
            result.workers.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let _ = serve_one_mtls_authenticated_peer_frame(
                        &listener,
                        server.clone(),
                        &receiver.pinned,
                        Duration::from_secs(4),
                        false,
                        |frame| {
                            let parsed = wire::parse(frame.payload())?;
                            let packed = parsed.kind == Kind::PackedStageBatch;
                            let number = if packed {
                                arrivals.fetch_add(1, Ordering::AcqRel) + 1
                            } else {
                                0
                            };
                            frames
                                .lock()
                                .map_err(|_| unknown())?
                                .push(MissingFrameObservation {
                                    operation: parsed.binding.intent.operation_digest,
                                    kind: parsed.kind,
                                    payload: parsed.payload.to_vec(),
                                });
                            // Actual admission, checked storage and durable
                            // receipts finish before this test-only ACK fault.
                            let response = receiver.handle_authenticated(frame)?;
                            if number == 1 {
                                let until = Instant::now() + Duration::from_secs(1);
                                while arrivals.load(Ordering::Acquire) < 2 {
                                    if Instant::now() >= until {
                                        return Err(unknown());
                                    }
                                    thread::sleep(Duration::from_millis(1));
                                }
                                if lose_first_reply {
                                    return Err(unknown());
                                }
                            }
                            Ok(response)
                        },
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }));
        }
        Ok(result)
    }
}

impl Drop for ParallelReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[test]
fn packed_pipeline_overlaps_real_tls_without_parallel_storage_and_cold_reads_exact() -> TestResult {
    pipeline_fixture(false)
}

#[test]
fn packed_pipeline_lost_actual_ack_cancels_window_without_replay_or_finalize() -> TestResult {
    pipeline_fixture(true)
}

fn storage_lane_keeps_one_executor_one_waiter_and_original_deadlines(
    receiver: &Arc<NativeV6ClosureReceiver>,
) -> TestResult {
    let original = Instant::now() + Duration::from_secs(1);
    let executing = receiver.enter_storage(Kind::Manifest, original)?;
    let waiting_receiver = receiver.clone();
    let waiter = thread::spawn(move || {
        waiting_receiver
            .enter_storage(Kind::PackedStageBatch, original)
            .map(|_permit| ())
    });
    let observe_until = Instant::now() + Duration::from_millis(75);
    while receiver.incoming_waiter.available_permits() != 0 && Instant::now() < observe_until {
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(receiver.incoming_waiter.available_permits(), 0);
    assert!(
        receiver
            .enter_storage(Kind::PackedStageBatch, original)
            .is_err()
    );
    assert!(receiver.enter_storage(Kind::EnsureBatch, original).is_err());
    assert!(receiver.enter_storage(Kind::Finalize, original).is_err());
    drop(executing);
    waiter.join().map_err(|_| "storage waiter panicked")??;
    assert_eq!(receiver.incoming_storage.available_permits(), 1);
    assert_eq!(receiver.incoming_waiter.available_permits(), 1);

    let executing = receiver.enter_storage(Kind::Manifest, original)?;
    let short = Instant::now() + Duration::from_millis(20);
    assert!(
        receiver
            .enter_storage(Kind::PackedStageBatch, short)
            .is_err()
    );
    assert!(Instant::now() >= short);
    assert!(Instant::now() < original);
    assert_eq!(receiver.incoming_waiter.available_permits(), 1);
    let began = Instant::now();
    assert!(
        receiver
            .enter_storage(Kind::PackedStageBatch, original)
            .is_err()
    );
    assert!(began.elapsed() >= MAX_PACKED_STORAGE_HANDOFF);
    assert!(
        Instant::now() < original,
        "another batch cannot consume the whole frame budget"
    );
    drop(executing);
    assert!(
        receiver
            .enter_storage(Kind::PackedStageBatch, Instant::now())
            .is_err()
    );
    assert_eq!(receiver.incoming_storage.available_permits(), 1);
    assert_eq!(receiver.incoming_waiter.available_permits(), 1);
    Ok(())
}

fn pipeline_fixture(lose_first_reply: bool) -> TestResult {
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
        let local = stores(&root, false)?;
        let mut references = Vec::new();
        let mut payloads = BTreeMap::new();
        // Seven maximum-size leaves require three actual bounded frames.
        for byte in 0x31..=0x37 {
            let payload = vec![byte; wire::MAX_CIPHERTEXT];
            let reference = local[0]
                .stage_local_checked(&payload, &mut || Ok(()))?
                .reference()
                .clone();
            payloads.insert(reference.id, payload);
            references.push(reference);
        }
        references.sort_unstable_by_key(|reference| reference.id);
        assert_eq!(batch::packed_batches(&references)?.len(), 3);
        let closure = local[0].persist_local_closure(&references, &mut || Ok(()))?;
        let (source, enrollment) = runtime.block_on(async {
            let source = PublishedRecordRoot::new(
                RecordRootBase::Empty,
                ReplicatedEnvelope::new("packed-pipeline-real-v5", [0x31; 32], vec![0x32; 64])?,
                Vec::new(),
            )?;
            let committed = nodes[0]
                .publish_application_root(nodes[0].next_production_client_serial().await?, &source)
                .await?;
            let enrollment = nodes[0]
                .enroll_native_v6_peers(
                    nodes[0].next_production_client_serial().await?,
                    [0x33; 32],
                    0,
                    tls.pins.clone(),
                    deadline(),
                )
                .await?;
            Ok::<_, Box<dyn std::error::Error>>((committed, enrollment))
        })?;
        let intent = NativeV6CommitIntent {
            cluster_digest: enrollment.cluster_digest(),
            epoch: 0,
            operation_digest: [if lose_first_reply { 0x34 } else { 0x35 }; 32],
            closure_manifest_sha256: closure.manifest_sha256(),
            object_count: references.len() as u64,
            ciphertext_bytes: closure.ciphertext_bytes(),
            prior_root_digest: [0x31; 32],
            proposed_root_digest: [0x36; 32],
            prior_generation: 0,
            proposed_generation: 1,
            expected_previous_commit_index: source.log_index,
        };
        let staged = runtime.block_on(async {
            nodes[0]
                .stage_application_object(
                    nodes[0].next_production_client_serial().await?,
                    &SealedRecordObject::new_native_v6_commit_intent(intent)?,
                )
                .await
        })?;
        let live = LiveReceivers::start(&nodes, runtime.handle(), &local, &enrollment, &tls)?;
        let observed = ParallelReceiver::start(
            nodes[1].clone(),
            runtime.handle().clone(),
            local[1].clone(),
            &enrollment,
            tls.servers[&2].clone(),
            lose_first_reply,
        )?;
        if !lose_first_reply {
            storage_lane_keeps_one_executor_one_waiter_and_original_deadlines(&observed.receiver)?;
        }
        let mut endpoints = live.endpoints.clone();
        endpoints.insert(live.routes[&2].clone(), observed.endpoint.clone());
        let transport = MutualTlsPeerTransport::new(
            endpoints,
            tls.clients[&1].clone(),
            Duration::from_secs(4),
        )?;
        let before_reads = router.read_index_requests.load(Ordering::Acquire);
        let original = Instant::now() + Duration::from_secs(8);
        let outcome = replicate_native_v6_closure_to_quorum(
            &nodes[0],
            runtime.handle(),
            &transport,
            &live.routes,
            NativeV6ClosureSource {
                source: &local[0],
                references: &references,
                intent: &intent,
            },
            original,
        );
        assert!(Instant::now() < original);
        let arrivals = observed.packed_arrivals.load(Ordering::Acquire);
        assert!(
            arrivals >= 2,
            "the first real ACK waited for a second actual TLS frame"
        );
        let frames = observed.frames.lock().map_err(|_| "frame lock")?.clone();
        let mut transferred = Vec::new();
        for row in frames
            .iter()
            .filter(|row| row.kind == Kind::PackedStageBatch)
        {
            assert_eq!(row.operation, intent.operation_digest);
            assert!(row.payload.len() <= batch::MAX_PAYLOAD);
            let count = usize::from(row.payload[0]);
            assert!((1..=batch::PACKED_OBJECTS).contains(&count));
            let mut at = 1;
            let mut prior = None;
            for _ in 0..count {
                let reference = wire::parse_reference(&row.payload[at..at + 36])?;
                at += 36;
                assert!(prior.is_none_or(|id| id < reference.id));
                prior = Some(reference.id);
                let end = at + reference.encoded_bytes as usize;
                assert_eq!(&row.payload[at..end], payloads[&reference.id].as_slice());
                at = end;
                assert!(
                    !transferred.contains(&reference),
                    "no ciphertext mutation replay"
                );
                transferred.push(reference);
            }
            assert_eq!(at, row.payload.len());
        }
        assert!(router.read_index_requests.load(Ordering::Acquire) >= before_reads + arrivals);
        let published = if lose_first_reply {
            assert!(outcome.is_err());
            assert_eq!(arrivals, 2, "a failed window cannot launch its third frame");
            assert!(!frames.iter().any(|row| row.kind == Kind::Finalize));
            assert!(
                runtime
                    .block_on(nodes[0].native_v6_root_at_generation())
                    .1
                    .is_none()
            );
            None
        } else {
            let quorum = outcome?;
            assert_eq!(quorum.voter_ids(), &[1, 2]);
            assert_eq!(arrivals, 3);
            transferred.sort_unstable_by_key(|reference| reference.id);
            assert_eq!(transferred, references);
            assert_eq!(
                frames
                    .iter()
                    .filter(|row| row.kind == Kind::Finalize)
                    .count(),
                1
            );
            runtime.block_on(quorum.verify_for_publication(&nodes[0]))?;
            Some(runtime.block_on(async {
                nodes[0]
                    .publish_native_v6_root(
                        nodes[0].next_production_client_serial().await?,
                        &intent,
                        &staged,
                        quorum.enrollment(),
                        vec![0x37; 64],
                        original,
                    )
                    .await
            })?)
        };
        let receiver = observed.receiver.clone();
        drop(observed);
        assert_eq!(receiver.incoming_storage.available_permits(), 1);
        assert_eq!(receiver.incoming_waiter.available_permits(), 1);
        assert!(receiver.incoming.try_lock().is_ok());
        drop(receiver);
        drop(live);
        drop(local);
        let cold = stores(&root, true)?;
        if let Some(published) = published {
            assert_eq!(
                cold[1].reopen_root_closure(&published, &mut || Ok(()))?,
                references
            );
            for reference in &references {
                assert_eq!(cold[1].read_local(reference)?, payloads[&reference.id]);
            }
        } else {
            for reference in &references {
                if let Some(bytes) =
                    cold[1].read_local_if_present_checked(reference, &mut || Ok(()))?
                {
                    assert_eq!(bytes, payloads[&reference.id]);
                }
            }
        }
        Ok(())
    })();
    runtime.block_on(shutdown_nodes(nodes, &router))?;
    result
}

// Exercise rustls itself rather than treating Write::write_vectored support as
// an assumption. The physical socket and durable-receiver cases above cover
// the same production helper over TCP and real fsync.
#[test]
fn coalesced_pinned_frame_uses_one_fewer_actual_tls_record() -> TestResult {
    use std::io::{self, Cursor, Read};

    #[derive(Default)]
    struct CiphertextWire(Vec<u8>);
    impl Read for CiphertextWire {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }
    impl Write for CiphertextWire {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buffer);
            Ok(buffer.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn records(wire: &[u8]) -> usize {
        let mut cursor = 0;
        let mut count = 0;
        while cursor < wire.len() {
            assert!(wire.len() - cursor >= 5);
            assert_eq!(wire[cursor], 23, "post-handshake TLS application record");
            let length = u16::from_be_bytes([wire[cursor + 3], wire[cursor + 4]]) as usize;
            cursor += 5 + length;
            assert!(cursor <= wire.len());
            count += 1;
        }
        count
    }
    let root = Root::new()?;
    let fixture = tls_fixture(&root.directory("pki")?)?;
    let mut counts = Vec::new();
    for coalesced in [false, true] {
        let mut client = rustls::ClientConnection::new(
            fixture.clients.get(&1).ok_or("missing client")?.clone(),
            rustls::pki_types::ServerName::try_from("localhost")?,
        )?;
        let mut server = rustls::ServerConnection::new(
            fixture.servers.get(&2).ok_or("missing server")?.clone(),
        )?;
        for _ in 0..16 {
            let mut flight = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut flight)?;
            }
            if !flight.is_empty() {
                server.read_tls(&mut Cursor::new(flight))?;
                server.process_new_packets()?;
            }
            let mut flight = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut flight)?;
            }
            if !flight.is_empty() {
                client.read_tls(&mut Cursor::new(flight))?;
                client.process_new_packets()?;
            }
            if !client.is_handshaking()
                && !server.is_handshaking()
                && !client.wants_write()
                && !server.wants_write()
            {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert_eq!(client.alpn_protocol(), Some(RAFT_ALPN_PROTOCOL));
        assert_eq!(server.alpn_protocol(), Some(RAFT_ALPN_PROTOCOL));
        let leaf = client.peer_certificates().ok_or("missing server chain")?;
        assert_eq!(
            digest(&SHA256, leaf[0].as_ref()).as_ref(),
            fixture.pins.get(&2).ok_or("missing pin")?.as_slice()
        );
        let payload = vec![0x61; 16 * 1024 - 4];
        let mut wire = CiphertextWire::default();
        if coalesced {
            crate::write_coalesced_bounded_frame(
                &mut rustls::Stream::new(&mut client, &mut wire),
                &payload,
            )?;
        } else {
            crate::write_bounded_frame(&mut rustls::Stream::new(&mut client, &mut wire), &payload)?;
        }
        counts.push(records(&wire.0));
        let mut incoming = Cursor::new(wire.0);
        // read_tls may accept only part of one encrypted record. Deliver this
        // finite captured flight completely before asking for its plaintext.
        while incoming.position() < incoming.get_ref().len() as u64 {
            assert!(server.read_tls(&mut incoming)? > 0);
            server.process_new_packets()?;
        }
        let mut plain = vec![0; payload.len() + 4];
        server.reader().read_exact(&mut plain)?;
        assert_eq!(&plain[..4], &(payload.len() as u32).to_be_bytes());
        assert_eq!(&plain[4..], payload);
    }
    assert_eq!(
        counts,
        [2, 1],
        "header must share the first encrypted record"
    );
    Ok(())
}
