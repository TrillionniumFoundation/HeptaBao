use super::*;
use crate::request_deadline::RequestDeadlineScope;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64};

#[derive(Debug)]
struct UnusedPeers;
impl RaftPeerRpc for UnusedPeers {
    fn exchange(
        &self,
        _source: u64,
        _target: u64,
        _kind: RaftRpcKind,
        _payload: Vec<u8>,
        _timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        Box::pin(async { Err(RemoteRaftError::Transport("test peer unavailable".into())) })
    }
}

// Real single-voter OpenRaft/durable state through a real HaProcess. There is
// no listening socket and no TLS claim: peers are unused by single-voter reads.
pub(crate) fn process(path: &Path) -> Result<HaProcess, Box<dyn std::error::Error>> {
    process_with_api(path, None)
}

pub(crate) fn process_with_api(
    path: &Path,
    api: Option<&str>,
) -> Result<HaProcess, Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()?;
    let network = RemoteNetworkFactory::new(
        1,
        std::collections::BTreeSet::from([1, 2, 3]),
        Arc::new(UnusedPeers),
    )?;
    let node = runtime.block_on(ProcessRaftNode::create(path, 1, network))?;
    runtime.block_on(node.initialize_single())?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while node.current_leader().await != Some(1) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    })?;
    let client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
    let peer = NodeId::parse("deadline-node")?;
    let forward_transport = MutualTlsPeerTransport::new(
        BTreeMap::from([(
            peer.clone(),
            TlsPeerEndpoint::new("127.0.0.1:1".parse()?, "deadline.invalid")?,
        )]),
        Arc::new(client),
        Duration::from_millis(50),
    )?;
    Ok(HaProcess {
        record_commits_since_gc: AtomicU64::new(0),
        bootstrap_ready: AtomicBool::new(true),
        bootstrap_voters: None,
        runtime,
        node: Some(node),
        codec: ClusterStateCodec::new("request-deadline", [9; 32])?,
        cluster_id: "request-deadline".into(),
        peers: Arc::new(BTreeMap::from([(1, peer)])),
        api_addresses: api
            .map(parse_api_address)
            .transpose()?
            .into_iter()
            .map(|address| (1, address))
            .collect(),
        forward_transport,
        forward_timeout: Duration::from_secs(1),
        emit_legacy_peer_v1: false,
        forward_handler: Arc::new(Mutex::new(None)),
        listener: None,
    })
}

#[test]
fn ha_block_on_propagates_the_original_deadline_and_drops_it_after_scope()
-> Result<(), Box<dyn std::error::Error>> {
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = Directory(std::env::temp_dir().join(format!(
        "heptabao-ha-deadline-{}-{}",
        std::process::id(),
        u64::from_le_bytes(crate::crypto::random::<8>()?),
    )));
    let process = process(&root.0)?;
    process.ensure_linearizable()?;
    let deadline = Instant::now() + Duration::from_millis(30);
    let scope = RequestDeadlineScope::enter(deadline);
    let node = process.node.as_ref().ok_or("missing test node")?;
    let result = process.block_on_read(async {
        // Work before a nested ReadIndex must consume the same budget.
        tokio::time::sleep(Duration::from_millis(50)).await;
        node.ensure_linearizable().await
    });
    assert!(
        matches!(result, Err(RemoteRaftError::Consensus(ref reason)) if reason == "linearizable read deadline exceeded")
    );
    assert!(process.ensure_linearizable().is_err());
    assert!(process.observed_snapshot().is_err());
    drop(scope);
    assert!(crate::request_deadline::current().is_none());
    process.ensure_linearizable()?;
    Ok(())
}
