//! Actual shared-listener saturation: production HaProcess startup, TLS peer
//! forwarding, follower ReadIndex, complete fsync quorum and one Raft root CAS.
//! Synthetic opaque root/ciphertext here do not claim a Service Actor/typed root.
use super::*;
use crate::request_deadline::RequestDeadlineScope;
use heptabao_ha_service::replicate_native_v6_closure_to_quorum;
use heptabao_raft_runtime::{
    LocalV6BlobStage, NativeV6CommitIntent, NativeV6PeerEnrollment, PublishedRecordRoot,
    RecordRootBase, SealedRecordObject, with_read_index_deadline,
};
use std::sync::{Condvar, mpsc};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[path = "service_native_v6_ha_mtls_fixture.rs"]
mod tls_fixture;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn directory() -> TestResult<Directory> {
    let path = std::env::temp_dir().join(format!(
        "heptabao-native-peer-capacity-{}-{}",
        std::process::id(),
        u64::from_le_bytes(crate::crypto::random::<8>()?),
    ));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path)?;
    Ok(Directory(fs::canonicalize(path)?))
}

fn configurations(root: &Path, pins: &BTreeMap<u64, [u8; 32]>) -> TestResult<Vec<HaProcessConfig>> {
    let listeners = (0..3)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<Result<Vec<_>, _>>()?;
    let addresses = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<Result<Vec<_>, _>>()?;
    let peers = (1..=3)
        .map(|id| {
            (
                id,
                HaPeerConfig {
                    node_name: format!("capacity-voter-{id}"),
                    address: addresses[(id - 1) as usize],
                    api_address: None,
                    cluster_address: None,
                    server_name: "localhost".into(),
                    certificate_sha256: pins[&id]
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    certificate_sha256_next: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    fs::write(root.join("replication.key"), [0x91; 32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for leaf in [
            "replication.key",
            "voter-1.key",
            "voter-2.key",
            "voter-3.key",
        ] {
            fs::set_permissions(root.join(leaf), fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok((1..=3)
        .map(|id| HaProcessConfig {
            node_id: id,
            cluster_id: "native-capacity-real-tls".into(),
            raft_dir: root.join(format!("raft-{id}")),
            listen: addresses[(id - 1) as usize],
            ca_file: root.join("ca.crt"),
            cert_file: root.join(format!("voter-{id}.crt")),
            key_file: root.join(format!("voter-{id}.key")),
            replication_key_file: root.join("replication.key"),
            peers: peers.clone(),
            bootstrap: false,
            initial_voters: None,
            peer_timeout_ms: 750,
            forward_timeout_ms: 15_000,
            max_inflight: 4,
            allow_legacy_peer_v1: false,
            emit_legacy_peer_v1: Some(false),
        })
        .collect())
}

struct SaturatedForwards {
    release: Arc<(Mutex<bool>, Condvar)>,
    entered: mpsc::Receiver<u64>,
    clients: Vec<JoinHandle<Result<(), String>>>,
}
impl SaturatedForwards {
    fn new(processes: &mut [HaProcess], deadline: Instant) -> TestResult<Self> {
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (sender, entered) = mpsc::channel();
        for process in processes.iter_mut() {
            let release = release.clone();
            let sender = sender.clone();
            let id = process.node.as_ref().ok_or("capacity node absent")?.id();
            process.register_forward_handler(Arc::new(move |_| {
                let _ = sender.send(id);
                let (lock, ready) = &*release;
                if let Ok(mut released) = lock.lock() {
                    while !*released {
                        let Some(remaining) = deadline.checked_duration_since(Instant::now())
                        else {
                            break;
                        };
                        match ready.wait_timeout(released, remaining) {
                            Ok((next, _)) => released = next,
                            Err(_) => break,
                        }
                    }
                }
                Response::error(503, "synthetic capacity hold released")
            }))?;
        }
        let mut saturated = Self {
            release,
            entered,
            clients: Vec::new(),
        };
        // Both live hosts are saturated through actual authenticated forwarding
        // sockets. No direct test acquisition of the production semaphores.
        for (source_index, target_index) in [(0, 1), (1, 0)] {
            let source = &processes[source_index];
            let target = &processes[target_index];
            let source_id = source.node.as_ref().ok_or("capacity source absent")?.id();
            let target_id = target.node.as_ref().ok_or("capacity target absent")?.id();
            for ordinal in 0..2 {
                let transport = source.forward_transport.clone();
                let peer = source.peers[&target_id].clone();
                let frame = crate::ha_forward::encode_request_for_cluster(
                    &source.cluster_id,
                    source_id,
                    target_id,
                    "POST",
                    &format!("capacity/hold-{ordinal}"),
                    "",
                    "synthetic-capacity",
                    &serde_json::json!({}),
                    None,
                )?;
                saturated.clients.push(thread::spawn(move || {
                    transport
                        .exchange_before(&peer, &frame, deadline)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }));
            }
        }
        let mut actual = BTreeMap::new();
        for _ in 0..4 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("capacity saturation exhausted original deadline")?;
            *actual
                .entry(saturated.entered.recv_timeout(remaining)?)
                .or_insert(0) += 1;
        }
        assert_eq!(actual, BTreeMap::from([(1, 2), (2, 2)]));
        Ok(saturated)
    }

    fn unblock(&self) {
        let (lock, ready) = &*self.release;
        if let Ok(mut release) = lock.lock() {
            *release = true;
            ready.notify_all();
        }
    }
    fn finish(mut self) -> TestResult {
        self.unblock();
        for client in self.clients.drain(..) {
            client
                .join()
                .map_err(|_| "capacity TLS client panicked")??;
        }
        Ok(())
    }
}
impl Drop for SaturatedForwards {
    fn drop(&mut self) {
        self.unblock();
        for client in self.clients.drain(..) {
            let _ = client.join();
        }
    }
}

#[test]
fn saturated_forwarding_preserves_native_quorum_read_index_and_reserved_consensus() -> TestResult {
    let root = directory()?;
    let tls = tls_fixture::tls_fixture(&root.0)?;
    let configs = configurations(&root.0, &tls.pins)?;
    {
        let mut ordinary = HaProcess::start(configs[0].clone())?;
        assert_eq!(
            ordinary
                .listener
                .as_ref()
                .ok_or("ordinary listener absent")?
                .workers
                .len(),
            4
        );
        assert!(!ordinary.native_v6_enabled());
        assert!(
            ordinary.enable_native_v6_candidate().is_err(),
            "late enable bypassed actual worker installation"
        );
        assert!(!configs[0].raft_dir.join("native-v6-ciphertext").exists());
    }
    let mut processes = configs
        .iter()
        .cloned()
        .map(HaProcess::start_native_v6_candidate)
        .collect::<Result<Vec<_>, _>>()?;
    for process in &processes {
        assert!(process.native_v6_enabled());
        assert_eq!(
            process
                .listener
                .as_ref()
                .ok_or("candidate listener absent")?
                .workers
                .len(),
            8
        );
    }
    let runtime = &processes[0].runtime;
    let node = processes[0].node.as_ref().ok_or("initial node absent")?;
    runtime.block_on(async {
        node.initialize_single().await?;
        node.add_learner(2).await?;
        node.add_learner(3).await?;
        node.change_membership(BTreeSet::from([1, 2, 3])).await?;
        Ok::<_, RemoteRaftError>(())
    })?;
    processes[0].native_install_test_ready()?;
    let storage = processes[0].native_install_test_store()?;
    let mut references = Vec::new();
    for byte in [0x31, 0x32, 0x33] {
        references.push(
            storage
                .stage_local_checked(&vec![byte; 32 * 1024], &mut || Ok(()))?
                .reference()
                .clone(),
        );
    }
    references.sort_unstable_by_key(|reference| reference.id);
    let local = storage.persist_local_closure(&references, &mut || Ok(()))?;
    let setup_deadline = Instant::now() + Duration::from_secs(8);
    let (intent, staged, enrollment) =
        runtime.block_on(with_read_index_deadline(setup_deadline, async {
            let source = PublishedRecordRoot::new(
                RecordRootBase::Empty,
                ReplicatedEnvelope::new("capacity-source", [0x41; 32], vec![0x42; 64])?,
                Vec::new(),
            )?;
            let source = node
                .publish_application_root(node.next_production_client_serial().await?, &source)
                .await?;
            let enrollment = node
                .enroll_native_v6_peers(
                    node.next_production_client_serial().await?,
                    processes[0].codec.native_v6_cluster_digest(),
                    0,
                    tls.pins.clone(),
                    setup_deadline,
                )
                .await?;
            let intent = NativeV6CommitIntent {
                cluster_digest: enrollment.cluster_digest(),
                epoch: 0,
                operation_digest: [0x51; 32],
                closure_manifest_sha256: local.manifest_sha256(),
                object_count: references.len() as u64,
                ciphertext_bytes: local.ciphertext_bytes(),
                prior_root_digest: [0x41; 32],
                proposed_root_digest: [0x52; 32],
                prior_generation: 0,
                proposed_generation: 1,
                expected_previous_commit_index: source.log_index,
            };
            let staged = node
                .stage_application_object(
                    node.next_production_client_serial().await?,
                    &SealedRecordObject::new_native_v6_commit_intent(intent)?,
                )
                .await?;
            Ok::<_, Box<dyn std::error::Error>>((intent, staged, enrollment))
        }))?;
    processes[0].runtime.block_on(
        processes[1]
            .node
            .as_ref()
            .ok_or("follower absent")?
            .admit_native_v6_closure(&intent, setup_deadline),
    )?;
    // A real whole process is stopped, not just a missing synthetic TLS route.
    drop(processes.pop().ok_or("third process absent")?);
    assert!(
        std::net::TcpStream::connect_timeout(&configs[2].listen, Duration::from_millis(50))
            .is_err()
    );

    let started = Instant::now();
    let deadline = started + Duration::from_secs(15);
    let _original = RequestDeadlineScope::enter(deadline);
    let saturated = SaturatedForwards::new(&mut processes, deadline)?;
    let leader = &processes[0];
    let follower = processes[1].node.as_ref().ok_or("live follower absent")?;
    let node = leader.node.as_ref().ok_or("live leader absent")?;
    let transport = &leader
        .native_v6
        .as_ref()
        .ok_or("native runtime absent")?
        .transport;
    // ReadIndex must cross the same saturated real TLS listener. Forwarding
    // slots cannot supply it or launder a passive metric into this proof.
    let (read, _, _) = leader
        .runtime
        .block_on(follower.native_v6_application_read_witness(deadline))?;
    leader
        .runtime
        .block_on(follower.verify_application_read_witness(&read))?;
    assert!(
        replicate_native_v6_closure_to_quorum(
            node,
            leader.runtime.handle(),
            transport,
            &leader.peers,
            &storage,
            &references,
            &intent,
            started
        )
        .is_err()
    );
    let quorum = replicate_native_v6_closure_to_quorum(
        node,
        leader.runtime.handle(),
        transport,
        &leader.peers,
        &storage,
        &references,
        &intent,
        deadline,
    )?;
    assert_eq!(
        quorum.voter_ids(),
        &[1, 2],
        "third/offline voter or implicit local vote was counted"
    );
    let published = leader
        .runtime
        .block_on(with_read_index_deadline(deadline, async {
            quorum.verify_for_publication(node).await?;
            // Exactly one root invocation; no unknown retry or deadline renewal.
            let published = node
                .publish_native_v6_root(
                    node.next_production_client_serial().await?,
                    &intent,
                    &staged,
                    &enrollment,
                    vec![0x53; 80],
                    deadline,
                )
                .await?;
            Ok::<_, Box<dyn std::error::Error>>(published)
        }))?;
    assert_eq!(published.intent(), intent);
    let (_, actual_enrollment, actual_root) = leader
        .runtime
        .block_on(follower.native_v6_application_read_witness(deadline))?;
    assert_eq!(actual_enrollment.as_ref(), Some(&enrollment));
    assert_eq!(actual_root.as_ref(), Some(&published));
    assert!(
        Instant::now() < deadline,
        "saturation or consensus work renewed the original 15-second budget"
    );
    // All four blocking business handlers are still occupied at this point.
    // Release only AFTER successful actual quorum, CAS and follower read.
    assert!(
        !*saturated
            .release
            .0
            .lock()
            .map_err(|_| "capacity gate poisoned")?
    );
    saturated.finish()?;
    eprintln!(
        "native-peer-capacity: actual_tls_forwarders=4 healthy_voters=2 offline_voters=1 root_cas=1 elapsed_ms={} budget_ms=15000",
        started.elapsed().as_millis()
    );
    Ok(())
}
