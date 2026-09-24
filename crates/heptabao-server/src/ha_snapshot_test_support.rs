//! Three real OpenRaft nodes/durable stores over the production RPC codec.
//! This loopback fixture makes no TLS/listener or multi-process claim.
use super::*;
use heptabao_raft_runtime::RaftRpcService;

#[derive(Default)]
struct Router {
    services: Mutex<BTreeMap<u64, RaftRpcService>>,
    block_append: AtomicBool,
    blocked: AtomicU64,
}
impl fmt::Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeSnapshotRaftTestRouter")
    }
}
#[derive(Clone, Debug)]
struct RpcRouter(Arc<Router>);

impl RaftPeerRpc for RpcRouter {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        let router = Arc::clone(&self.0);
        Box::pin(async move {
            if kind == RaftRpcKind::AppendEntries
                && router
                    .block_append
                    .load(std::sync::atomic::Ordering::SeqCst)
            {
                router
                    .blocked
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(timeout).await;
                return Err(RemoteRaftError::Transport("snapshot test partition".into()));
            }
            let peer = router
                .services
                .lock()
                .map_err(|_| RemoteRaftError::Transport("test router poisoned".into()))?
                .get(&target)
                .cloned()
                .ok_or(RemoteRaftError::InvalidTopology)?;
            peer.handle(source, kind, payload).await
        })
    }
}

pub(crate) struct Cluster {
    pub(crate) processes: Vec<Arc<Mutex<HaProcess>>>,
    router: Arc<Router>,
}
impl Cluster {
    pub(crate) fn new(path: &Path, cluster_id: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::build(path, cluster_id, true)
    }
    pub(crate) fn uninitialized(
        path: &Path,
        cluster_id: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::build(path, cluster_id, false)
    }
    fn build(
        path: &Path,
        cluster_id: &str,
        initialize: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let router = Arc::new(Router::default());
        let mut processes = Vec::new();
        let peers: BTreeMap<u64, NodeId> = (1..=3)
            .map(|id| NodeId::parse(format!("snapshot-node-{id}")).map(|peer| (id, peer)))
            .collect::<Result<_, _>>()?;
        for id in 1..=3 {
            let runtime = RuntimeBuilder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()?;
            let network = RemoteNetworkFactory::new(
                id,
                BTreeSet::from([1, 2, 3]),
                Arc::new(RpcRouter(Arc::clone(&router))),
            )?;
            let node = runtime.block_on(ProcessRaftNode::create(
                path.join(id.to_string()),
                id,
                network,
            ))?;
            router
                .services
                .lock()
                .map_err(|_| "router poisoned")?
                .insert(id, node.rpc_service());
            let client = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
            let endpoints = peers
                .iter()
                .map(|(id, peer)| {
                    TlsPeerEndpoint::new(
                        format!("127.0.0.1:{}", 19_000u64 + *id)
                            .parse()
                            .map_err(|_| "address")?,
                        "snapshot.invalid",
                    )
                    .map(|endpoint| (peer.clone(), endpoint))
                    .map_err(|_| "endpoint")
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            let forward_transport = MutualTlsPeerTransport::new(
                endpoints,
                Arc::new(client),
                Duration::from_millis(50),
            )?;
            processes.push(Arc::new(Mutex::new(HaProcess {
                record_commits_since_gc: AtomicU64::new(0),
                bootstrap_ready: AtomicBool::new(true),
                runtime,
                node: Some(node),
                codec: ClusterStateCodec::new(cluster_id, [19; 32])?,
                cluster_id: cluster_id.to_owned(),
                peers: Arc::new(peers.clone()),
                api_addresses: BTreeMap::new(),
                forward_transport,
                forward_timeout: Duration::from_secs(1),
                allow_legacy_peer_v1: false,
                forward_handler: Arc::new(Mutex::new(None)),
                listener: None,
            })));
        }
        let cluster = Self { processes, router };
        if initialize {
            let first = cluster.processes[0].lock().map_err(|_| "HA poisoned")?;
            let node = first.node.as_ref().ok_or("node")?;
            first.runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(15), async {
                    node.initialize_single().await?;
                    while node.current_leader().await != Some(1) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    node.add_learner(2).await?;
                    node.add_learner(3).await?;
                    node.change_membership(BTreeSet::from([1, 2, 3])).await?;
                    node.ensure_linearizable().await
                })
                .await
            })??;
        }
        Ok(cluster)
    }
    pub(crate) fn configure_api_address(&self, node: u64, origin: &str) -> Result<(), String> {
        let origin = parse_api_address(origin)?;
        for process in &self.processes {
            process
                .lock()
                .map_err(|_| "HA poisoned")?
                .api_addresses
                .insert(node, origin.clone());
        }
        Ok(())
    }
    pub(crate) fn block_quorum(&self, blocked: bool) {
        self.router
            .block_append
            .store(blocked, std::sync::atomic::Ordering::SeqCst);
    }
    pub(crate) fn blocked_probes(&self) -> u64 {
        self.router
            .blocked
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl Drop for Cluster {
    fn drop(&mut self) {
        self.block_quorum(false);
    }
}

impl HaProcess {
    pub(crate) fn snapshot_test_record_usage(
        &self,
    ) -> Result<(u64, heptabao_raft_runtime::RecordUsage), String> {
        self.runtime
            .block_on(self.node.as_ref().ok_or("node")?.application_record_usage())
            .map_err(|error| error.to_string())
    }
}
