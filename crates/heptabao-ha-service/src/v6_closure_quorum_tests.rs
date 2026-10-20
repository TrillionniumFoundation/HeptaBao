//! Real durable three-voter Raft with an explicitly in-process consensus
//! router, and ACTUAL TCP/pinned mutual TLS for every counted ciphertext vote.
//! This does not claim physical-host HA or the Service's barrier/Actor path.
use super::*;
use crate::{RAFT_ALPN_PROTOCOL, TlsPeerEndpoint};
use heptabao_raft_runtime::{
    PublishedRecordRoot, RaftPeerRpc, RaftRpcKind, RaftRpcService, RecordRootBase,
    RemoteNetworkFactory, RemoteRaftError, ReplicatedEnvelope, SealedRecordObject,
};
use ring::digest::{SHA256, digest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[path = "v6_committed_root_pull_tests.rs"]
mod committed_root_pull_tests;
struct Root(PathBuf);
impl Root {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "hb-v6-quorum-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
    fn directory(&self, name: &str) -> std::io::Result<PathBuf> {
        let path = self.0.join(name);
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Default)]
struct Router {
    peers: Arc<tokio::sync::RwLock<BTreeMap<u64, RaftRpcService>>>,
    isolate_three: Arc<AtomicBool>,
}
impl fmt::Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClosureQuorumTestRouter")
    }
}
impl RaftPeerRpc for Router {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        bytes: Vec<u8>,
        _timeout: Duration,
    ) -> futures::future::BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        let this = self.clone();
        Box::pin(async move {
            if this.isolate_three.load(Ordering::SeqCst) && (source == 3 || target == 3) {
                return Err(RemoteRaftError::Transport(
                    "isolated synthetic third voter".into(),
                ));
            }
            let peer = this
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
    Instant::now() + Duration::from_secs(25)
}

async fn open_nodes(
    path: &Path,
    router: &Router,
    cold: bool,
) -> TestResult<Vec<Arc<ProcessRaftNode>>> {
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let network =
            RemoteNetworkFactory::new(id, BTreeSet::from([1, 2, 3]), Arc::new(router.clone()))?;
        let node = if cold {
            ProcessRaftNode::reopen(path.join(id.to_string()), id, network).await?
        } else {
            ProcessRaftNode::create(path.join(id.to_string()), id, network).await?
        };
        router.peers.write().await.insert(id, node.rpc_service());
        nodes.push(Arc::new(node));
    }
    Ok(nodes)
}

async fn select_first_leader(nodes: &[Arc<ProcessRaftNode>]) -> TestResult {
    let leader = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if let Some(leader) = nodes[0].current_leader().await {
                break leader;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    if leader != 1 {
        nodes[(leader - 1) as usize].transfer_leadership(1).await?;
    }
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if nodes[0].current_leader().await == Some(1)
                && nodes[0].ensure_linearizable().await.is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    Ok(())
}

async fn shutdown_nodes(nodes: Vec<Arc<ProcessRaftNode>>, router: &Router) -> TestResult {
    for node in nodes {
        Arc::try_unwrap(node)
            .map_err(|_| "test receiver retained a live process owner")?
            .shutdown()
            .await?;
    }
    router.peers.write().await.clear();
    Ok(())
}

fn certificates(path: &Path) -> TestResult<Vec<CertificateDer<'static>>> {
    Ok(
        rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
            .collect::<Result<Vec<_>, _>>()?,
    )
}
fn private_key(path: &Path) -> TestResult<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?
        .ok_or_else(|| "missing disposable TLS key".into())
}
fn openssl(path: &Path, arguments: &[&str]) -> TestResult {
    if !Command::new("openssl")
        .current_dir(path)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        return Err("disposable closure TLS setup failed".into());
    }
    Ok(())
}
struct TlsFixture {
    clients: BTreeMap<u64, Arc<ClientConfig>>,
    servers: BTreeMap<u64, Arc<ServerConfig>>,
    pins: BTreeMap<u64, [u8; 32]>,
}
fn tls_fixture(path: &Path) -> TestResult<TlsFixture> {
    openssl(
        path,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-subj",
            "/CN=NativeClosureTestCA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    )?;
    for id in 1..=3 {
        let name = format!("voter-{id}");
        openssl(
            path,
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN={name}"),
            ],
        )?;
        fs::write(
            path.join(format!("{name}.ext")),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
        )?;
        openssl(
            path,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                &format!("{name}.crt"),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                &format!("{name}.ext"),
            ],
        )?;
    }
    let mut roots = RootCertStore::empty();
    roots.add(certificates(&path.join("ca.crt"))?[0].clone())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut clients = BTreeMap::new();
    let mut servers = BTreeMap::new();
    let mut pins = BTreeMap::new();
    for id in 1..=3 {
        let name = format!("voter-{id}");
        let chain = certificates(&path.join(format!("{name}.crt")))?;
        pins.insert(id, digest(&SHA256, chain[0].as_ref()).as_ref().try_into()?);
        let mut client = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(
                chain.clone(),
                private_key(&path.join(format!("{name}.key")))?,
            )?;
        client.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
        clients.insert(id, Arc::new(client));
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(roots.clone())).build()?,
            )
            .with_single_cert(chain, private_key(&path.join(format!("{name}.key")))?)?;
        server.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
        servers.insert(id, Arc::new(server));
    }
    Ok(TlsFixture {
        clients,
        servers,
        pins,
    })
}

struct LiveReceivers {
    endpoints: BTreeMap<NodeId, TlsPeerEndpoint>,
    routes: BTreeMap<u64, NodeId>,
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
}
impl LiveReceivers {
    fn start(
        nodes: &[Arc<ProcessRaftNode>],
        runtime: &Handle,
        stores: &[Arc<LocalV6BlobStage>],
        enrollment: &NativeV6PeerEnrollment,
        tls: &TlsFixture,
    ) -> TestResult<Self> {
        Self::start_conditioned(nodes, runtime, stores, enrollment, tls, 3, None)
    }

    fn start_conditioned(
        nodes: &[Arc<ProcessRaftNode>],
        runtime: &Handle,
        stores: &[Arc<LocalV6BlobStage>],
        enrollment: &NativeV6PeerEnrollment,
        tls: &TlsFixture,
        unavailable: u64,
        ready: Option<Arc<AtomicBool>>,
    ) -> TestResult<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut result = Self {
            endpoints: BTreeMap::new(),
            routes: BTreeMap::new(),
            stop,
            workers: Vec::new(),
        };
        for id in 1..=3 {
            let name = NodeId::parse(format!("route-{id}"))?;
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            result.routes.insert(id, name.clone());
            result.endpoints.insert(
                name,
                TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?,
            );
            if id == unavailable {
                // No selected ciphertext listener; Raft isolation is separately
                // controlled by Router. Its route is still fully configured.
                drop(listener);
                continue;
            }
            let receiver = NativeV6ClosureReceiver::new(
                nodes[(id - 1) as usize].clone(),
                runtime.clone(),
                stores[(id - 1) as usize].clone(),
                enrollment,
            )?;
            let server = tls.servers[&id].clone();
            let stop = result.stop.clone();
            let ready = ready.clone();
            result.workers.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    if ready
                        .as_ref()
                        .is_some_and(|gate| !gate.load(Ordering::Acquire))
                    {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    let _ =
                        receiver.serve_one_mtls(&listener, server.clone(), Duration::from_secs(4));
                    thread::sleep(Duration::from_millis(1));
                }
            }));
        }
        Ok(result)
    }
    fn transport(&self, client: Arc<ClientConfig>) -> Result<MutualTlsPeerTransport, HaError> {
        MutualTlsPeerTransport::new(self.endpoints.clone(), client, Duration::from_secs(4))
    }
}

// Accepts actual TCP connections and deliberately never completes TLS. This
// models a blackholed forwarded peer without relying on external routing or
// a connection-refused fast failure. No synthetic acknowledgement is sent.
struct TcpBlackhole {
    endpoint: TlsPeerEndpoint,
    accepted: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl TcpBlackhole {
    fn start() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?;
        let accepted = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let seen = accepted.clone();
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            let mut sockets = Vec::new();
            while !stopped.load(Ordering::Acquire) {
                if let Ok((socket, _)) = listener.accept() {
                    sockets.push(socket);
                    seen.store(true, Ordering::Release);
                }
                thread::sleep(Duration::from_millis(1));
            }
        });
        Ok(Self {
            endpoint,
            accepted,
            stop,
            worker: Some(worker),
        })
    }
}
impl Drop for TcpBlackhole {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for LiveReceivers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn stores(root: &Root, cold: bool) -> TestResult<Vec<Arc<LocalV6BlobStage>>> {
    let mut stores = Vec::new();
    for id in 1..=3 {
        let name = format!("cipher-{id}");
        let directory = if cold {
            root.0.join(name)
        } else {
            root.directory(&name)?
        };
        stores.push(Arc::new(LocalV6BlobStage::open_existing(&directory)?));
    }
    Ok(stores)
}

fn raw_request(
    transport: &MutualTlsPeerTransport,
    route: &NodeId,
    target: u64,
    pin: [u8; 32],
    binding: &Binding,
    kind: Kind,
    payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HaError> {
    let request = wire::encode(binding, target, kind, payload)?;
    let response = transport.exchange_before_pinned_server(route, &request, deadline(), pin)?;
    Ok((request, response))
}

fn original_log(admission: &NativeV6ClosureAdmission) -> [u64; 3] {
    let log = admission.intent_log_id();
    [
        log.committed_leader_id().term,
        log.committed_leader_id().node_id,
        log.index,
    ]
}

#[test]
fn accepted_tls_handshake_and_frame_drips_cannot_extend_original_inbound_deadline() -> TestResult {
    let root = Root::new()?;
    let tls = tls_fixture(&root.directory("pki")?)?;
    for after_handshake in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let called = Arc::new(AtomicBool::new(false));
        let invoked = called.clone();
        let identities = PinnedClientCertificateMap::new(BTreeMap::from([(
            tls.pins[&1],
            NodeId::parse("actual-test-voter-1")?,
        )]))?;
        let server = tls.servers[&2].clone();
        let (done, completed) = std::sync::mpsc::channel();
        let receiver = thread::spawn(move || {
            let started = Instant::now();
            let result = serve_one_mtls_authenticated_peer_frame(
                &listener,
                server,
                &identities,
                Duration::from_millis(500),
                false,
                move |_| {
                    invoked.store(true, Ordering::Release);
                    Ok(vec![1])
                },
            );
            let _ = done.send((result, started.elapsed()));
        });
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let client = tls.clients[&1].clone();
        let sender = thread::spawn(move || -> Result<(), String> {
            let send = || -> TestResult {
                let mut socket = TcpStream::connect(address)?;
                socket.set_read_timeout(Some(Duration::from_secs(2)))?;
                socket.set_write_timeout(Some(Duration::from_secs(2)))?;
                let mut connection =
                    rustls::ClientConnection::new(client, "localhost".try_into()?)?;
                if after_handshake {
                    let mut stream = rustls::StreamOwned::new(connection, socket);
                    stream.conn.complete_io(&mut stream.sock)?;
                    stream.write_all(&256u32.to_be_bytes())?;
                    stream.flush()?;
                    // Each valid TLS application record arrives within the
                    // socket timeout; their aggregate request never completes.
                    for _ in 0..256 {
                        if stopped.load(Ordering::Acquire) {
                            break;
                        }
                        if stream
                            .write_all(&[0x31])
                            .and_then(|()| stream.flush())
                            .is_err()
                        {
                            break;
                        }
                        thread::sleep(Duration::from_millis(30));
                    }
                } else {
                    // Produce an ACTUAL valid ClientHello record and drip its
                    // bytes. The server must bound even pre-authentication I/O.
                    let mut hello = Vec::new();
                    connection.write_tls(&mut hello)?;
                    if hello.len() < 32 {
                        return Err("ClientHello fixture missing".into());
                    }
                    for byte in hello {
                        if stopped.load(Ordering::Acquire) {
                            break;
                        }
                        if socket.write_all(&[byte]).is_err() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(30));
                    }
                }
                Ok(())
            };
            send().map_err(|_| "synthetic drip sender failed".to_owned())
        });
        // Capture the deadline result BEFORE stopping the attacker; closing a
        // fixture socket must not be mistaken for the server enforcing a bound.
        let observed = completed.recv_timeout(Duration::from_millis(1100));
        stop.store(true, Ordering::Release);
        let sent = sender.join().map_err(|_| "drip sender panicked")?;
        receiver.join().map_err(|_| "drip receiver panicked")?;
        sent.map_err(|_| "drip sender setup failed")?;
        let (result, elapsed) = observed.map_err(|_| "drip extended inbound deadline")?;
        assert!(result.is_err());
        assert!(!called.load(Ordering::Acquire));
        assert!(elapsed < Duration::from_millis(1000));
    }
    Ok(())
}

#[test]
fn exact_committed_closure_counts_only_final_pinned_fsync_and_recovers_after_compaction()
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

    let (intent, references, intent_origin, publication_index) = (|| -> TestResult<_> {
        let stores = stores(&root, false)?;
        let mut references = Vec::new();
        for byte in [0x71, 0x72, 0x73] {
            references.push(
                stores[0]
                    .stage_local_checked(&vec![byte; 32 * 1024], &mut || Ok(()))?
                    .reference()
                    .clone(),
            );
        }
        references.sort_unstable_by_key(|reference| reference.id);
        let closure = stores[0].persist_local_closure(&references, &mut || Ok(()))?;
        let (source, enrollment) = runtime.block_on(async {
            let source = PublishedRecordRoot::new(
                RecordRootBase::Empty,
                ReplicatedEnvelope::new("closure-real-v5-source", [0x41; 32], vec![0x42; 64])?,
                Vec::new(),
            )?;
            let committed = nodes[0]
                .publish_application_root(nodes[0].next_production_client_serial().await?, &source)
                .await?;
            // The actual Service replay epoch starts at zero. The new path
            // carries that value unchanged, including in committed metadata.
            let enrollment = nodes[0]
                .enroll_native_v6_peers(
                    nodes[0].next_production_client_serial().await?,
                    [0x45; 32],
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
            operation_digest: [0x46; 32],
            closure_manifest_sha256: closure.manifest_sha256(),
            object_count: references.len() as u64,
            ciphertext_bytes: closure.ciphertext_bytes(),
            prior_root_digest: [0x41; 32],
            proposed_root_digest: [0x47; 32],
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
        let follower = runtime.block_on(nodes[1].admit_native_v6_closure(&intent, deadline()))?;
        assert_eq!(follower.leader_id(), 1);
        assert_eq!(follower.intent_log_id().index, staged.log_index);
        runtime.block_on(nodes[1].verify_native_v6_closure_admission(&follower))?;
        assert!(
            runtime
                .block_on(nodes[0].verify_native_v6_closure_admission(&follower))
                .is_err()
        );
        let intent_origin = original_log(&follower);
        let wrong = NativeV6CommitIntent {
            operation_digest: [0x48; 32],
            ..intent
        };
        assert!(
            runtime
                .block_on(nodes[1].admit_native_v6_closure(&wrong, deadline()))
                .is_err()
        );
        assert!(
            runtime
                .block_on(nodes[1].admit_native_v6_closure(&intent, Instant::now()))
                .is_err()
        );
        drop(follower);
        let live = LiveReceivers::start(&nodes, runtime.handle(), &stores, &enrollment, &tls)?;
        let transport = live.transport(tls.clients[&1].clone())?;
        let admission = runtime.block_on(nodes[0].admit_native_v6_closure(&intent, deadline()))?;
        let binding = Binding::observed(&admission);
        drop(admission);

        // Actual data files or a complete declared manifest alone cannot count
        // as this operation's fsync completion at an authenticated voter.
        let page = wire::manifest_page(0, &references)?;
        // A real enrolled follower certificate cannot assert the leader's
        // numeric identity in an otherwise exact committed intent frame.
        let follower_transport = live.transport(tls.clients[&2].clone())?;
        assert!(
            raw_request(
                &follower_transport,
                &live.routes[&2],
                2,
                tls.pins[&2],
                &binding,
                Kind::Manifest,
                &page
            )
            .is_err()
        );
        let (sent, ack) = raw_request(
            &transport,
            &live.routes[&2],
            2,
            tls.pins[&2],
            &binding,
            Kind::Manifest,
            &page,
        )?;
        wire::verify_reply(&sent, &ack, &(references.len() as u64).to_be_bytes())?;
        for reference in &references {
            stores[1].stage_local_checked(&stores[0].read_local(reference)?, &mut || Ok(()))?;
        }
        assert!(
            raw_request(
                &transport,
                &live.routes[&2],
                2,
                tls.pins[&2],
                &binding,
                Kind::Finalize,
                &[]
            )
            .is_err()
        );
        assert_eq!(
            fs::read_dir(root.0.join("cipher-2"))?
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("v6-closure-"))
                .count(),
            0
        );

        {
            let blackhole = TcpBlackhole::start()?;
            let healthy = LiveReceivers::start_conditioned(
                &nodes,
                runtime.handle(),
                &stores,
                &enrollment,
                &tls,
                1,
                Some(blackhole.accepted.clone()),
            )?;
            let mut endpoints = healthy.endpoints.clone();
            endpoints.insert(healthy.routes[&1].clone(), blackhole.endpoint.clone());
            let transport = MutualTlsPeerTransport::new(
                endpoints,
                tls.clients[&1].clone(),
                Duration::from_secs(10),
            )?;
            // The configured first-peer timeout EXCEEDS the entire original
            // caller budget. A sequential collector necessarily exhausts it.
            // Healthy listeners only run AFTER that TCP blackhole is real.
            let original = Instant::now() + Duration::from_secs(5);
            let quorum = replicate_native_v6_closure_to_quorum(
                &nodes[0],
                runtime.handle(),
                &transport,
                &healthy.routes,
                &stores[0],
                &references,
                &intent,
                original,
            )?;
            assert!(blackhole.accepted.load(Ordering::Acquire));
            assert!(Instant::now() < original);
            assert_eq!(quorum.voter_ids(), &[2, 3]);
            runtime.block_on(quorum.verify_for_publication(&nodes[0]))?;
        }
        router.isolate_three.store(true, Ordering::SeqCst);

        // A local source is not an implicit vote. With only voter 2 reachable
        // on TLS, one real final ACK still cannot reach a majority of three.
        let mut no_self = live.endpoints.clone();
        no_self.insert(
            live.routes[&1].clone(),
            live.endpoints[&live.routes[&3]].clone(),
        );
        let no_self =
            MutualTlsPeerTransport::new(no_self, tls.clients[&1].clone(), Duration::from_secs(4))?;
        assert!(
            replicate_native_v6_closure_to_quorum(
                &nodes[0],
                runtime.handle(),
                &no_self,
                &live.routes,
                &stores[0],
                &references,
                &intent,
                deadline()
            )
            .is_err()
        );

        // Distinct route names pointing at one real TLS identity cannot supply
        // two voter receipts; the independently committed target pin rejects it.
        let mut alias = live.endpoints.clone();
        alias.insert(
            live.routes[&2].clone(),
            live.endpoints[&live.routes[&1]].clone(),
        );
        let alias =
            MutualTlsPeerTransport::new(alias, tls.clients[&1].clone(), Duration::from_secs(4))?;
        assert!(
            replicate_native_v6_closure_to_quorum(
                &nodes[0],
                runtime.handle(),
                &alias,
                &live.routes,
                &stores[0],
                &references,
                &intent,
                deadline()
            )
            .is_err()
        );

        let quorum = replicate_native_v6_closure_to_quorum(
            &nodes[0],
            runtime.handle(),
            &transport,
            &live.routes,
            &stores[0],
            &references,
            &intent,
            deadline(),
        )?;
        assert_eq!(quorum.voter_ids(), &[1, 2]);
        runtime.block_on(quorum.verify_for_publication(&nodes[0]))?;
        assert!(
            runtime
                .block_on(nodes[0].native_v6_root_at_generation())
                .1
                .is_none()
        );
        // A captured real response cannot be replayed for a new socket nonce.
        let (sent, ack) = raw_request(
            &transport,
            &live.routes[&2],
            2,
            tls.pins[&2],
            &binding,
            Kind::Finalize,
            &[],
        )?;
        wire::verify_reply(&sent, &ack, &wire::final_payload(&intent))?;
        let another = wire::encode(&binding, 2, Kind::Finalize, &[])?;
        assert!(wire::verify_reply(&another, &ack, &wire::final_payload(&intent)).is_err());
        let mut forged_binding = binding.clone();
        forged_binding.intent_log[0] += 1;
        assert!(
            raw_request(
                &transport,
                &live.routes[&2],
                2,
                tls.pins[&2],
                &forged_binding,
                Kind::Finalize,
                &[]
            )
            .is_err()
        );

        // An actual applied mutation invalidates the old same-generation
        // handle. Reconciliation must gather real fresh per-voter fsync work.
        runtime.block_on(async {
            nodes[0]
                .stage_application_object(
                    nodes[0].next_production_client_serial().await?,
                    &SealedRecordObject::new_native_v6_commit_intent(wrong)?,
                )
                .await
        })?;
        assert!(
            runtime
                .block_on(quorum.verify_for_publication(&nodes[0]))
                .is_err()
        );
        drop(quorum);
        let quorum = reconcile_native_v6_closure_quorum(
            &nodes[0],
            runtime.handle(),
            &transport,
            &live.routes,
            &stores[0],
            &references,
            &intent,
            deadline(),
        )?;
        runtime.block_on(quorum.verify_for_publication(&nodes[0]))?;
        let published = runtime.block_on(async {
            nodes[0]
                .publish_native_v6_root(
                    nodes[0].next_production_client_serial().await?,
                    &intent,
                    &staged,
                    quorum.enrollment(),
                    vec![0x49; 64],
                    deadline(),
                )
                .await
        })?;
        assert_eq!(published.intent_log_id().index, staged.log_index);
        assert_eq!(
            stores[1].reopen_root_closure(&published, &mut || Ok(()))?,
            references
        );
        Ok((
            intent,
            references,
            intent_origin,
            published.publication_log_id().index,
        ))
    })()?;

    router.isolate_three.store(false, Ordering::SeqCst);
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let mut all = true;
                for node in &nodes {
                    all &= node
                        .native_v6_root_at_generation()
                        .await
                        .1
                        .is_some_and(|root| root.publication_log_id().index == publication_index);
                }
                if all {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        for node in &nodes {
            node.trigger_snapshot().await?;
        }
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let mut all = true;
                for node in &nodes {
                    all &= node
                        .membership_observation()
                        .await?
                        .purged_index
                        .is_some_and(|index| index >= publication_index);
                }
                if all {
                    break Ok::<(), RemoteRaftError>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        shutdown_nodes(nodes, &router).await
    })?;

    let nodes = runtime.block_on(open_nodes(&raft_root, &router, true))?;
    runtime.block_on(select_first_leader(&nodes))?;
    let cold_result = (|| -> TestResult {
        let stores = stores(&root, true)?;
        let admission = runtime.block_on(nodes[1].admit_native_v6_closure(&intent, deadline()))?;
        assert_eq!(original_log(&admission), intent_origin);
        let enrollment = admission.enrollment().clone();
        let (witness, _, selected) =
            runtime.block_on(nodes[1].native_v6_application_read_witness(deadline()))?;
        let committed = selected.ok_or("cold native root missing")?;
        assert_eq!(
            stores[1].reopen_root_closure(&committed, &mut || Ok(()))?,
            references
        );
        runtime.block_on(nodes[1].verify_application_read_witness(&witness))?;
        drop(witness);
        drop(admission);
        let live = LiveReceivers::start(&nodes, runtime.handle(), &stores, &enrollment, &tls)?;
        let transport = live.transport(tls.clients[&1].clone())?;
        router.isolate_three.store(true, Ordering::SeqCst);
        let admission = runtime.block_on(nodes[0].admit_native_v6_closure(&intent, deadline()))?;
        let binding = Binding::observed(&admission);
        drop(admission);
        let page = wire::manifest_page(0, &references)?;
        raw_request(
            &transport,
            &live.routes[&2],
            2,
            tls.pins[&2],
            &binding,
            Kind::Manifest,
            &page,
        )?;
        // Even a persisted prior manifest and intact blobs do not resurrect
        // an in-memory final ACK after restart without current physical fsync.
        assert!(
            raw_request(
                &transport,
                &live.routes[&2],
                2,
                tls.pins[&2],
                &binding,
                Kind::Finalize,
                &[]
            )
            .is_err()
        );
        let quorum = reconcile_native_v6_closure_quorum(
            &nodes[0],
            runtime.handle(),
            &transport,
            &live.routes,
            &stores[0],
            &references,
            &intent,
            deadline(),
        )?;
        assert_eq!(quorum.voter_ids(), &[1, 2]);
        runtime.block_on(quorum.verify_for_publication(&nodes[0]))?;
        drop(quorum);

        // A missing/corrupted immutable leaf prevents a NEW majority receipt;
        // a local successful copy cannot fill the unavailable third vote.
        let mut leaf = String::from("v6-");
        for byte in references[0].id {
            use std::fmt::Write as _;
            write!(&mut leaf, "{byte:02x}")?;
        }
        leaf.push_str(".blob");
        fs::write(
            root.0.join("cipher-2").join(leaf),
            b"corrupted disposable ciphertext",
        )?;
        assert!(
            reconcile_native_v6_closure_quorum(
                &nodes[0],
                runtime.handle(),
                &transport,
                &live.routes,
                &stores[0],
                &references,
                &intent,
                deadline()
            )
            .is_err()
        );
        Ok(())
    })();
    runtime.block_on(shutdown_nodes(nodes, &router))?;
    cold_result
}

// These observations are test-owned projections of frames that already passed
// actual pinned mTLS. They never construct an authenticated frame or a quorum.
#[derive(Clone)]
struct MissingFrameObservation {
    operation: [u8; 32],
    kind: Kind,
    payload: Vec<u8>,
}

struct ObservedMissingReceiver {
    endpoint: TlsPeerEndpoint,
    observations: Arc<Mutex<Vec<MissingFrameObservation>>>,
    fault: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ObservedMissingReceiver {
    fn start(
        node: Arc<ProcessRaftNode>,
        runtime: Handle,
        storage: Arc<LocalV6BlobStage>,
        enrollment: &NativeV6PeerEnrollment,
        server: Arc<ServerConfig>,
    ) -> TestResult<Self> {
        let receiver = NativeV6ClosureReceiver::new(node, runtime, storage, enrollment)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let seen = observations.clone();
        let fault = Arc::new(AtomicU64::new(0));
        let active_fault = fault.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                let _ = serve_one_mtls_authenticated_peer_frame(
                    &listener,
                    server.clone(),
                    &receiver.pinned,
                    Duration::from_secs(4),
                    false,
                    |frame| {
                        let observation = {
                            let parsed = wire::parse(frame.payload())?;
                            MissingFrameObservation {
                                operation: parsed.binding.intent.operation_digest,
                                kind: parsed.kind,
                                payload: parsed.payload.to_vec(),
                            }
                        };
                        let kind = observation.kind;
                        seen.lock().map_err(|_| unknown())?.push(observation);
                        // Execute the actual receiver and all filesystem/intent
                        // gates BEFORE a test-only lost or malformed reply.
                        let mut response = receiver.handle_authenticated(frame)?;
                        if kind == Kind::EnsureBatch {
                            match active_fault.swap(0, Ordering::AcqRel) {
                                0 => {}
                                1 => return Err(unknown()),
                                2 => {
                                    *response
                                        .get_mut(wire::HEADER_BYTES - 1)
                                        .ok_or_else(unknown)? ^= 1;
                                }
                                3 => {
                                    *response
                                        .get_mut(wire::HEADER_BYTES + 1)
                                        .ok_or_else(unknown)? ^= 1;
                                }
                                _ => return Err(unknown()),
                            }
                        }
                        Ok(response)
                    },
                );
                thread::sleep(Duration::from_millis(1));
            }
        });
        Ok(Self {
            endpoint,
            observations,
            fault,
            stop,
            worker: Some(worker),
        })
    }

    fn for_operation(&self, operation: [u8; 32]) -> TestResult<Vec<MissingFrameObservation>> {
        Ok(self
            .observations
            .lock()
            .map_err(|_| "observation lock poisoned")?
            .iter()
            .filter(|row| row.operation == operation)
            .cloned()
            .collect())
    }
}
impl Drop for ObservedMissingReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn missing_only_quorum_keeps_real_fsync_cold_bytes_and_unknown_ack_fences() -> TestResult {
    missing_only_quorum_fixture(3, 1, 128 * 1024)
}

#[test]
fn ensure_reference_batches_split_only_missing_ciphertext_and_keep_fault_fences() -> TestResult {
    // Two Ensure frames (64 + 1), with six missing in the first and one in the
    // second. Their actual Stage frames must remain 3 + 3 + 1 leaves, and all
    // original malformed/lost-ACK, corruption and cold-reopen checks still run.
    missing_only_quorum_fixture(65, 7, 64)
}

fn missing_only_quorum_fixture(
    object_count: u8,
    missing_count: usize,
    object_bytes: usize,
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
        let local = stores(&root, false)?;
        let mut references = Vec::new();
        let mut payloads = BTreeMap::new();
        for byte in 0..object_count {
            let bytes = vec![0x61 + byte; object_bytes];
            let reference = local[0]
                .stage_local_checked(&bytes, &mut || Ok(()))?
                .reference()
                .clone();
            payloads.insert(reference.id, bytes);
            references.push(reference);
        }
        references.sort_unstable_by_key(|reference| reference.id);
        let closure = local[0].persist_local_closure(&references, &mut || Ok(()))?;
        // Voter 2 owns the retained prefix already. The declared missing tail
        // can only acquire custody through actual Stage frames and fsync.
        let retained_count = references.len() - missing_count;
        for reference in &references[..retained_count] {
            local[1].stage_received_replica_checked(
                reference,
                &payloads[&reference.id],
                &mut || Ok(()),
            )?;
        }
        let missing = &references[retained_count..];
        let (source, enrollment) = runtime.block_on(async {
            let source = PublishedRecordRoot::new(
                RecordRootBase::Empty,
                ReplicatedEnvelope::new("missing-only-real-v5", [0x51; 32], vec![0x52; 64])?,
                Vec::new(),
            )?;
            let committed = nodes[0]
                .publish_application_root(nodes[0].next_production_client_serial().await?, &source)
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
            Ok::<_, Box<dyn std::error::Error>>((committed, enrollment))
        })?;
        let stage_intent = |tag: u8| -> TestResult<_> {
            let intent = NativeV6CommitIntent {
                cluster_digest: enrollment.cluster_digest(),
                epoch: 0,
                operation_digest: [tag; 32],
                closure_manifest_sha256: closure.manifest_sha256(),
                object_count: references.len() as u64,
                ciphertext_bytes: closure.ciphertext_bytes(),
                prior_root_digest: [0x51; 32],
                proposed_root_digest: [0x54; 32],
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
            Ok((intent, staged))
        };
        let live = LiveReceivers::start(&nodes, runtime.handle(), &local, &enrollment, &tls)?;
        let observed = ObservedMissingReceiver::start(
            nodes[1].clone(),
            runtime.handle().clone(),
            local[1].clone(),
            &enrollment,
            tls.servers[&2].clone(),
        )?;
        let mut endpoints = live.endpoints.clone();
        endpoints.insert(live.routes[&2].clone(), observed.endpoint.clone());
        let transport = MutualTlsPeerTransport::new(
            endpoints,
            tls.clients[&1].clone(),
            Duration::from_secs(4),
        )?;

        // Each fault belongs to a distinct staged synthetic operation. The
        // production call may neither resend EnsureBatch nor send ciphertext
        // after a lost reply, changed nonce, or foreign missing reference.
        let mut foreign = missing[0].clone();
        foreign.id[0] ^= 1;
        assert!(!references.contains(&foreign));
        for fault in 1..=3_u64 {
            let (intent, _) = stage_intent(0x70 + fault as u8)?;
            observed.fault.store(fault, Ordering::Release);
            let original = Instant::now() + Duration::from_secs(8);
            assert!(
                replicate_native_v6_closure_to_quorum(
                    &nodes[0],
                    runtime.handle(),
                    &transport,
                    &live.routes,
                    &local[0],
                    &references,
                    &intent,
                    original
                )
                .is_err()
            );
            assert!(Instant::now() < original);
            let frames = observed.for_operation(intent.operation_digest)?;
            assert_eq!(
                frames
                    .iter()
                    .filter(|row| row.kind == Kind::EnsureBatch)
                    .count(),
                1
            );
            assert!(
                !frames
                    .iter()
                    .any(|row| matches!(row.kind, Kind::StageBatch | Kind::Stage | Kind::Finalize))
            );
            assert!(
                local[1]
                    .read_local_if_present_checked(&missing[0], &mut || Ok(()))?
                    .is_none()
            );
            assert!(
                runtime
                    .block_on(nodes[0].native_v6_root_at_generation())
                    .1
                    .is_none()
            );
        }

        // A corrupt present leaf is an error, never a missing reply or an
        // invitation to overwrite it from another voter.
        let mut leaf = String::from("v6-");
        for byte in references[0].id {
            use std::fmt::Write as _;
            write!(&mut leaf, "{byte:02x}")?;
        }
        leaf.push_str(".blob");
        let leaf = root.0.join("cipher-2").join(leaf);
        let corrupt = vec![0x6f; references[0].encoded_bytes as usize];
        fs::write(&leaf, &corrupt)?;
        let (intent, _) = stage_intent(0x74)?;
        let original = Instant::now() + Duration::from_secs(8);
        assert!(
            replicate_native_v6_closure_to_quorum(
                &nodes[0],
                runtime.handle(),
                &transport,
                &live.routes,
                &local[0],
                &references,
                &intent,
                original
            )
            .is_err()
        );
        assert!(Instant::now() < original);
        assert!(fs::read(&leaf)? == corrupt);
        let frames = observed.for_operation(intent.operation_digest)?;
        assert_eq!(
            frames
                .iter()
                .filter(|row| row.kind == Kind::EnsureBatch)
                .count(),
            1
        );
        assert!(
            !frames
                .iter()
                .any(|row| matches!(row.kind, Kind::StageBatch | Kind::Stage | Kind::Finalize))
        );
        // Explicit fixture repair for the NEXT distinct test operation only.
        fs::write(&leaf, &payloads[&references[0].id])?;

        // The separate lost-final-response reconciliation API stays fsync-only.
        let (intent, _) = stage_intent(0x75)?;
        let original = Instant::now() + Duration::from_secs(8);
        assert!(
            reconcile_native_v6_closure_quorum(
                &nodes[0],
                runtime.handle(),
                &transport,
                &live.routes,
                &local[0],
                &references,
                &intent,
                original
            )
            .is_err()
        );
        assert!(Instant::now() < original);
        let frames = observed.for_operation(intent.operation_digest)?;
        assert!(
            frames
                .iter()
                .any(|row| row.kind == Kind::FsyncExistingBatch)
        );
        assert!(!frames.iter().any(|row| matches!(
            row.kind,
            Kind::EnsureBatch | Kind::StageBatch | Kind::Stage | Kind::Finalize
        )));

        let (intent, staged) = stage_intent(0x76)?;
        let original = Instant::now() + Duration::from_secs(8);
        let quorum = replicate_native_v6_closure_to_quorum(
            &nodes[0],
            runtime.handle(),
            &transport,
            &live.routes,
            &local[0],
            &references,
            &intent,
            original,
        )?;
        assert!(Instant::now() < original);
        assert_eq!(quorum.voter_ids(), &[1, 2]);
        runtime.block_on(quorum.verify_for_publication(&nodes[0]))?;
        let frames = observed.for_operation(intent.operation_digest)?;
        let ensure_frames: Vec<_> = frames
            .iter()
            .filter(|row| row.kind == Kind::EnsureBatch)
            .collect();
        assert_eq!(
            ensure_frames.len(),
            references.len().div_ceil(batch::ENSURE_OBJECTS)
        );
        for (frame, references) in ensure_frames
            .iter()
            .zip(references.chunks(batch::ENSURE_OBJECTS))
        {
            assert_eq!(frame.payload, batch::ensure_expected(references)?);
        }
        let staged_frames: Vec<_> = frames
            .iter()
            .filter(|row| row.kind == Kind::StageBatch)
            .collect();
        let expected_stage_frames: usize = references
            .chunks(batch::ENSURE_OBJECTS)
            .map(|batch| {
                batch
                    .iter()
                    .filter(|reference| missing.contains(reference))
                    .count()
            })
            .map(|count| count.div_ceil(batch::OBJECTS))
            .sum();
        assert_eq!(staged_frames.len(), expected_stage_frames);
        let mut transferred = Vec::new();
        for frame in staged_frames {
            let stage = &frame.payload;
            let count = usize::from(stage[0]);
            assert!((1..=batch::OBJECTS).contains(&count));
            assert!(stage.len() <= batch::MAX_PAYLOAD);
            let mut offset = 1;
            for _ in 0..count {
                let reference = wire::parse_reference(&stage[offset..offset + 36])?;
                offset += 36;
                let end = offset + reference.encoded_bytes as usize;
                assert!(missing.contains(&reference));
                assert!(
                    &stage[offset..end] == payloads[&reference.id].as_slice(),
                    "only the exact missing ciphertext crosses TLS"
                );
                offset = end;
                transferred.push(reference);
            }
            assert_eq!(offset, stage.len());
        }
        assert_eq!(transferred, missing);
        assert_eq!(
            frames
                .iter()
                .filter(|row| row.kind == Kind::Finalize)
                .count(),
            1
        );
        let published = runtime.block_on(async {
            nodes[0]
                .publish_native_v6_root(
                    nodes[0].next_production_client_serial().await?,
                    &intent,
                    &staged,
                    quorum.enrollment(),
                    vec![0x55; 64],
                    original,
                )
                .await
        })?;
        assert!(Instant::now() < original);
        assert_eq!(
            local[1].reopen_root_closure(&published, &mut || Ok(()))?,
            references
        );
        drop(quorum);
        drop(observed);
        drop(live);
        drop(local);
        // Drop and reopen the real exclusive ciphertext owners. No receiver's
        // in-memory fsynced bitmap can discharge these physical cold reads.
        let cold = stores(&root, true)?;
        assert_eq!(
            cold[1].reopen_root_closure(&published, &mut || Ok(()))?,
            references
        );
        for reference in &references {
            assert!(cold[1].read_local(reference)? == payloads[&reference.id]);
        }
        Ok(())
    })();
    runtime.block_on(shutdown_nodes(nodes, &router))?;
    result
}
