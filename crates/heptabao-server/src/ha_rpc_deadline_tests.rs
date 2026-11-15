//! Exercise the production RPC adapter with a real loopback TCP listener.
//! A silent endpoint deliberately cannot finish TLS; these are queue/deadline
//! regressions, not certificate or consensus qualification.
use super::*;
use std::io;
use std::sync::mpsc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(MutualTlsRaftRpc, TcpListener), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
    let peer = NodeId::parse("rpc-deadline-peer")?;
    let transport = MutualTlsPeerTransport::new(
        BTreeMap::from([(
            peer.clone(),
            TlsPeerEndpoint::new(listener.local_addr()?, "rpc-deadline.invalid")?,
        )]),
        Arc::new(client),
        Duration::from_millis(250),
    )?;
    Ok((
        MutualTlsRaftRpc {
            local_id: 1,
            cluster_id: "rpc-deadline-cluster".into(),
            peers: Arc::new(BTreeMap::from([(2, peer)])),
            transport,
            inflight: Arc::new(Semaphore::new(1)),
            emit_legacy_peer_v1: false,
        },
        listener,
    ))
}

fn runtime() -> Result<Runtime, io::Error> {
    RuntimeBuilder::new_current_thread()
        .max_blocking_threads(1)
        .enable_time()
        .build()
}

fn no_connection(listener: &TcpListener) {
    assert!(
        listener
            .accept()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock),
        "an expired or cancelled queued RPC reached the network"
    );
}

// The single blocking worker stays occupied until explicitly released. The
// timeout is a cleanup safety bound, not the mechanism under test.
fn occupy_worker(
    runtime: &Runtime,
) -> Result<(mpsc::Sender<()>, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let (release, receiver) = mpsc::channel();
    let (entered, started) = mpsc::channel();
    let worker = runtime.spawn_blocking(move || {
        let _ = entered.send(());
        let _ = receiver.recv_timeout(Duration::from_secs(5));
    });
    started.recv_timeout(Duration::from_secs(2))?;
    Ok((release, worker))
}

#[test]
fn rpc_deadline_expired_before_first_poll_never_connects() -> TestResult {
    let (rpc, listener) = fixture()?;
    let runtime = runtime()?;
    let operation = rpc.exchange(1, 2, RaftRpcKind::Vote, vec![1], Duration::from_millis(40));
    std::thread::sleep(Duration::from_millis(70));
    assert!(runtime.block_on(operation).is_err());
    no_connection(&listener);
    assert_eq!(rpc.inflight.available_permits(), 1);
    Ok(())
}

#[test]
fn rpc_deadline_timed_out_blocking_queue_never_connects_later() -> TestResult {
    let (rpc, listener) = fixture()?;
    let runtime = runtime()?;
    let (release, worker) = occupy_worker(&runtime)?;
    runtime.block_on(async {
        let result = rpc
            .exchange(1, 2, RaftRpcKind::Vote, vec![1], Duration::from_millis(40))
            .await;
        assert!(result.is_err());
        release.send(())?;
        worker.await?;
        // Drain work queued behind the held worker before checking effects.
        tokio::task::spawn_blocking(|| {}).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    no_connection(&listener);
    assert_eq!(rpc.inflight.available_permits(), 1);
    Ok(())
}

#[test]
fn rpc_deadline_cancelled_blocking_queue_never_connects_later() -> TestResult {
    let (rpc, listener) = fixture()?;
    let runtime = runtime()?;
    let (release, worker) = occupy_worker(&runtime)?;
    runtime.block_on(async {
        let mut operation = rpc.exchange(1, 2, RaftRpcKind::Vote, vec![1], Duration::from_secs(2));
        assert!(futures::poll!(operation.as_mut()).is_pending());
        assert_eq!(rpc.inflight.available_permits(), 0);
        drop(operation);
        release.send(())?;
        worker.await?;
        tokio::task::spawn_blocking(|| {}).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    no_connection(&listener);
    assert_eq!(rpc.inflight.available_permits(), 1);
    Ok(())
}
