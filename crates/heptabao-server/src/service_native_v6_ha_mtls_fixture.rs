//! Disposable real CA/leaf certificates and actual pinned mTLS receivers.
//! Adapted from the already exercised HA quorum test fixture. Only voter 3's
//! ciphertext listener is absent; this fixture does not disconnect Raft RPC.
use super::*;
use heptabao_ha_service::{
    HaError, MutualTlsPeerTransport, NativeV6ClosureReceiver, NodeId, RAFT_ALPN_PROTOCOL,
    TlsPeerEndpoint,
};
use ring::digest::{SHA256, digest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use tokio::runtime::Handle;

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
pub(super) struct TlsFixture {
    pub(super) clients: BTreeMap<u64, Arc<ClientConfig>>,
    pub(super) servers: BTreeMap<u64, Arc<ServerConfig>>,
    pub(super) pins: BTreeMap<u64, [u8; 32]>,
}
pub(super) fn tls_fixture(path: &Path) -> TestResult<TlsFixture> {
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
                WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots.clone()),
                    provider.clone(),
                )
                .build()?,
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

pub(super) struct LiveReceivers {
    endpoints: BTreeMap<NodeId, TlsPeerEndpoint>,
    pub(super) routes: BTreeMap<u64, NodeId>,
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
}
impl LiveReceivers {
    pub(super) fn start(
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
    pub(super) fn transport(
        &self,
        client: Arc<ClientConfig>,
    ) -> Result<MutualTlsPeerTransport, HaError> {
        MutualTlsPeerTransport::new(self.endpoints.clone(), client, Duration::from_secs(4))
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
