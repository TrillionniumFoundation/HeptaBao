//! Only public synthetic fixtures, generated inside this test process. Tonic
//! owns TLS, HTTP/2 and gRPC framing; no product/plugin subprocess is launched.
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::net::TcpListener;
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{Service, http};
use tonic::server::{NamedService, UnaryService};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig};

use super::*;
use crate::handshake::LocalEndpoint;
use crate::transport::{OwnedMutualTlsMaterial, RawCodec, RawFrame, TonicWrapperTransport};

fn identity() -> OwnedPluginIdentity {
    OwnedPluginIdentity {
        uid: 1000,
        pid: 101,
        session_id: 101,
        start_ticks: 200,
        executable_device: 2,
        executable_inode: 3,
        executable_sha256: [1; 32],
        config_device: 2,
        config_inode: 4,
        config_sha256: [2; 32],
        config_mode: 0o600,
    }
}
#[derive(Clone, Debug)]
struct Probe(Arc<Mutex<(OwnedPluginIdentity, HostLifecycle)>>);
impl Probe {
    fn new() -> Self {
        Self(Arc::new(Mutex::new((
            identity(),
            HostLifecycle {
                sealed: true,
                configuration_generation: 1,
            },
        ))))
    }
}
impl IdentityProbe for Probe {
    fn observe(&self) -> Result<(OwnedPluginIdentity, HostLifecycle), BridgeError> {
        self.0
            .lock()
            .map(|v| v.clone())
            .map_err(|_| BridgeError::InvalidBinding)
    }
}
fn limits() -> RpcLimits {
    RpcLimits {
        maximum_request_bytes: 1024,
        maximum_response_bytes: 1024,
        timeout: Duration::from_secs(2),
    }
}
fn options() -> RpcOptions {
    let mut options = RpcOptions::default();
    options.with_disallow_env_vars = true;
    options
}
fn opaque_blob() -> Vec<u8> {
    // Public golden fixture from the exact protobuf schema. Unknown nested
    // KeyInfo field 9 and BlobInfo field 31 must survive the real network.
    vec![
        0x0a, 2, 0xab, 0xcd, 0x12, 1, 8, 0x2a, 7, 0x1a, 1, b'k', 0x4a, 2, 9, 10, 0xfa, 1, 1, 11,
    ]
}
#[derive(Clone, Copy, Debug)]
enum Mode {
    Normal,
    PendingEncrypt,
    OversizedEncrypt,
    OwnerChangedEncrypt,
}
struct State {
    calls: Mutex<Vec<(WrapperMethod, Zeroizing<Vec<u8>>)>>,
    entered_encrypt: Notify,
    mode: Mode,
    probe: Probe,
}
impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoopbackFixtureState([REDACTED])")
    }
}
impl State {
    fn methods(&self) -> Result<Vec<WrapperMethod>, BridgeError> {
        self.calls
            .lock()
            .map(|calls| calls.iter().map(|v| v.0).collect())
            .map_err(|_| BridgeError::InvalidBinding)
    }
}
#[derive(Clone, Debug)]
struct MockWrapper(Arc<State>);
impl NamedService for MockWrapper {
    const NAME: &'static str = "pb.Wrapper";
}
impl Service<http::Request<tonic::body::Body>> for MockWrapper {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let method = match request.uri().path() {
            "/pb.Wrapper/SetConfig" => WrapperMethod::SetConfig,
            "/pb.Wrapper/Type" => WrapperMethod::Type,
            "/pb.Wrapper/KeyId" => WrapperMethod::KeyId,
            "/pb.Wrapper/Init" => WrapperMethod::Init,
            "/pb.Wrapper/Encrypt" => WrapperMethod::Encrypt,
            "/pb.Wrapper/Decrypt" => WrapperMethod::Decrypt,
            "/pb.Wrapper/Finalize" => WrapperMethod::Finalize,
            _ => {
                return Box::pin(async {
                    Ok(tonic::Status::unimplemented("fixture method unavailable").into_http())
                });
            }
        };
        let state = self.0.clone();
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(RawCodec {
                maximum_response_bytes: 4096,
            });
            Ok(grpc.unary(MockRpc { state, method }, request).await)
        })
    }
}
#[derive(Debug)]
struct MockRpc {
    state: Arc<State>,
    method: WrapperMethod,
}
impl UnaryService<RawFrame> for MockRpc {
    type Response = RawFrame;
    type Future =
        Pin<Box<dyn Future<Output = Result<tonic::Response<RawFrame>, tonic::Status>> + Send>>;
    fn call(&mut self, request: tonic::Request<RawFrame>) -> Self::Future {
        let state = self.state.clone();
        let method = self.method;
        Box::pin(async move {
            state
                .calls
                .lock()
                .map_err(|_| tonic::Status::internal("fixture lock failed"))?
                .push((method, request.into_inner().0));
            if method == WrapperMethod::Encrypt {
                state.entered_encrypt.notify_one();
                if matches!(state.mode, Mode::PendingEncrypt) {
                    return std::future::pending().await;
                }
                if matches!(state.mode, Mode::OwnerChangedEncrypt) {
                    state
                        .probe
                        .0
                        .lock()
                        .map_err(|_| tonic::Status::internal("fixture lock failed"))?
                        .0
                        .start_ticks += 1;
                }
            }
            let wire = match method {
                WrapperMethod::SetConfig => protocol::SetConfigResponse {
                    wrapper_id: "public-fixture-wrapper".into(),
                    wrapper_config: Some(Default::default()),
                }
                .encode_to_vec(),
                WrapperMethod::Type => protocol::TypeResponse {
                    r#type: "public-fixture-wrapper-type".into(),
                }
                .encode_to_vec(),
                WrapperMethod::KeyId => protocol::KeyIdResponse {
                    key_id: "public-fixture-key".into(),
                }
                .encode_to_vec(),
                WrapperMethod::Init | WrapperMethod::Finalize => vec![],
                WrapperMethod::Encrypt if matches!(state.mode, Mode::OversizedEncrypt) => {
                    vec![0; 2048]
                }
                WrapperMethod::Encrypt => {
                    let mut wire = vec![];
                    prost::encoding::bytes::encode(10, &opaque_blob(), &mut wire);
                    wire
                }
                WrapperMethod::Decrypt => protocol::DecryptResponse {
                    plaintext: b"PUBLIC_FIXTURE".to_vec(),
                }
                .encode_to_vec(),
            };
            Ok(tonic::Response::new(RawFrame(Zeroizing::new(wire))))
        })
    }
}
type CertificateAndKey = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

struct Certificates {
    server: Zeroizing<Vec<u8>>,
    server_key: Zeroizing<Vec<u8>>,
    client: Zeroizing<Vec<u8>>,
    client_key: Zeroizing<Vec<u8>>,
    wrong_server: Zeroizing<Vec<u8>>,
}
impl Certificates {
    fn generate() -> Result<Self, BridgeError> {
        fn generate(dns: &str) -> Result<CertificateAndKey, BridgeError> {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec![dns.into()])
                    .map_err(|_| BridgeError::InvalidBinding)?;
            Ok((
                Zeroizing::new(cert.pem().into_bytes()),
                Zeroizing::new(signing_key.serialize_pem().into_bytes()),
            ))
        }
        let (server, server_key) = generate("owned-plugin.fixture")?;
        let (client, client_key) = generate("owned-host.fixture")?;
        let (wrong_server, _) = generate("owned-plugin.fixture")?;
        Ok(Self {
            server,
            server_key,
            client,
            client_key,
            wrong_server,
        })
    }
    fn material(&self, wrong_peer: bool, wrong_dns: bool) -> OwnedMutualTlsMaterial {
        OwnedMutualTlsMaterial {
            client_certificate_pem: Zeroizing::new(self.client.to_vec()),
            client_private_key_pem: Zeroizing::new(self.client_key.to_vec()),
            server_certificate_pem: Zeroizing::new(if wrong_peer {
                self.wrong_server.to_vec()
            } else {
                self.server.to_vec()
            }),
            peer_dns_name: if wrong_dns {
                "different.fixture".into()
            } else {
                "owned-plugin.fixture".into()
            },
        }
    }
}
struct Fixture {
    address: std::net::SocketAddr,
    certificates: Certificates,
    state: Arc<State>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
}
impl Fixture {
    async fn start(mode: Mode) -> Result<Self, BridgeError> {
        let certificates = Certificates::generate()?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| BridgeError::BeforeDispatch)?;
        let address = listener
            .local_addr()
            .map_err(|_| BridgeError::BeforeDispatch)?;
        let state = Arc::new(State {
            calls: Default::default(),
            entered_encrypt: Notify::new(),
            mode,
            probe: Probe::new(),
        });
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                certificates.server.as_slice(),
                certificates.server_key.as_slice(),
            ))
            .client_ca_root(Certificate::from_pem(certificates.client.as_slice()))
            .client_auth_optional(false);
        let mut server = Server::builder()
            .tls_config(tls)
            .map_err(|_| BridgeError::InvalidBinding)?;
        let (shutdown, wait) = oneshot::channel();
        let wrapper = MockWrapper(state.clone());
        let task = tokio::spawn(async move {
            server
                .add_service(wrapper)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = wait.await;
                })
                .await
        });
        Ok(Self {
            address,
            certificates,
            state,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }
    async fn connect(
        &self,
        probe: &Probe,
        wrong_peer: bool,
        wrong_dns: bool,
    ) -> Result<TonicWrapperTransport, BridgeError> {
        TonicWrapperTransport::connect_after_owned_launch(
            &identity(),
            probe,
            &LocalEndpoint::Tcp(self.address),
            self.certificates.material(wrong_peer, wrong_dns),
            limits(),
        )
        .await
    }
    async fn session(
        &self,
    ) -> Result<OpenBaoGrpcSession<TonicWrapperTransport, Probe>, BridgeError> {
        let probe = self.state.probe.clone();
        let transport = self.connect(&probe, false, false).await?;
        OpenBaoGrpcSession::admit(transport, probe, identity(), limits())
    }
    async fn finish(mut self) -> Result<(), BridgeError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(mut task) = self.task.take() {
            // A pending RPC intentionally has an unknown outcome. Shutdown must
            // not wait for that synthetic handler forever; abort only this
            // fixture task and await its terminal, never any product task.
            match tokio::time::timeout(Duration::from_secs(2), &mut task).await {
                Ok(result) => {
                    result
                        .map_err(|_| BridgeError::BeforeDispatch)?
                        .map_err(|_| BridgeError::BeforeDispatch)?;
                }
                Err(_) => {
                    task.abort();
                    let terminal = task.await;
                    assert!(
                        terminal.is_err_and(|e| e.is_cancelled()),
                        "owned fixture did not stop"
                    );
                }
            }
        }
        // The awaited task terminal must also release its only listener.
        let released = TcpListener::bind(self.address)
            .await
            .map_err(|_| BridgeError::BeforeDispatch)?;
        drop(released);
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutual_tls_http2_seven_rpc_paths_and_unknown_blob_wire() -> Result<(), BridgeError> {
    let f = Fixture::start(Mode::Normal).await?;
    let result = async {
        let mut session = f.session().await?;
        session.set_config(options()).await?;
        assert!(&*session.wrapper_type().await? == "public-fixture-wrapper-type");
        assert!(&*session.key_id().await? == "public-fixture-key");
        session.init(options()).await?;
        let blob = session
            .encrypt(Zeroizing::new(b"PUBLIC_FIXTURE".to_vec()), options())
            .await?;
        assert!(
            blob.protobuf() == opaque_blob(),
            "unknown BlobInfo wire changed"
        );
        assert!(session.decrypt(&blob, options()).await?.as_slice() == b"PUBLIC_FIXTURE");
        session.finalize(options()).await?;
        assert!(session.state() == SessionState::Finalized);
        let calls = f
            .state
            .calls
            .lock()
            .map_err(|_| BridgeError::InvalidBinding)?;
        assert!(
            calls.iter().map(|c| c.0.path()).collect::<Vec<_>>()
                == [
                    "/pb.Wrapper/SetConfig",
                    "/pb.Wrapper/Type",
                    "/pb.Wrapper/KeyId",
                    "/pb.Wrapper/Init",
                    "/pb.Wrapper/Encrypt",
                    "/pb.Wrapper/Decrypt",
                    "/pb.Wrapper/Finalize"
                ]
        );
        let request = protocol::DecryptRequest::decode(calls[5].1.as_slice())
            .map_err(|_| BridgeError::InvalidResponse)?;
        assert!(
            request.wrapper_id == "public-fixture-wrapper"
                && request
                    .options
                    .as_ref()
                    .is_some_and(|o| o.with_disallow_env_vars)
        );
        assert!(
            calls[5].1.ends_with(&opaque_blob()),
            "unknown nested fields were not sent"
        );
        Ok(())
    }
    .await;
    f.finish().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_peer_wrong_dns_and_missing_client_certificate_never_dispatch()
-> Result<(), BridgeError> {
    let f = Fixture::start(Mode::Normal).await?;
    let result = async {
        for (peer, dns) in [(true, false), (false, true)] {
            assert!(
                f.connect(&Probe::new(), peer, dns).await.is_err(),
                "untrusted TLS peer connected"
            );
        }
        // Explicit hostile client has no client identity. Production has no
        // constructor for this mode. Tonic still owns all network framing.
        let endpoint = Endpoint::from_shared(format!("https://{}", f.address))
            .map_err(|_| BridgeError::InvalidBinding)?
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("owned-plugin.fixture")
                    .ca_certificate(Certificate::from_pem(f.certificates.server.as_slice())),
            )
            .map_err(|_| BridgeError::InvalidBinding)?
            .connect_timeout(limits().timeout);
        let connected = tokio::time::timeout(limits().timeout, endpoint.connect()).await;
        if let Ok(Ok(channel)) = connected {
            let mut grpc = tonic::client::Grpc::new(channel);
            let response = tokio::time::timeout(limits().timeout, async {
                grpc.ready()
                    .await
                    .map_err(|_| BridgeError::BeforeDispatch)?;
                grpc.unary(
                    tonic::Request::new(RawFrame(Zeroizing::new(vec![]))),
                    http::uri::PathAndQuery::from_static("/pb.Wrapper/Type"),
                    RawCodec {
                        maximum_response_bytes: 1024,
                    },
                )
                .await
                .map_err(|_| BridgeError::BeforeDispatch)
            })
            .await;
            assert!(
                !matches!(response, Ok(Ok(_))),
                "client certificate was optional"
            );
        }
        assert!(
            f.state.methods()?.is_empty(),
            "unauthenticated request reached RPC handler"
        );
        Ok(())
    }
    .await;
    f.finish().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_rpc_timeout_fences_and_does_not_replay() -> Result<(), BridgeError> {
    let f = Fixture::start(Mode::PendingEncrypt).await?;
    let result = async {
        let mut s = f.session().await?;
        s.set_config(options()).await?;
        s.init(options()).await?;
        s.limits.timeout = Duration::from_millis(100);
        assert!(s.encrypt(Zeroizing::new(vec![1]), options()).await.is_err());
        assert!(s.state() == SessionState::OutcomeUnknown);
        assert!(matches!(
            s.encrypt(Zeroizing::new(vec![1]), options()).await,
            Err(BridgeError::InvalidState)
        ));
        assert!(
            f.state.methods()?
                == [
                    WrapperMethod::SetConfig,
                    WrapperMethod::Init,
                    WrapperMethod::Encrypt
                ]
        );
        Ok(())
    }
    .await;
    f.finish().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_cancelled_waiter_fences_and_does_not_replay() -> Result<(), BridgeError> {
    let f = Fixture::start(Mode::PendingEncrypt).await?;
    let result = async {
        let mut s = f.session().await?; s.set_config(options()).await?; s.init(options()).await?;
        let mut waiter = Box::pin(s.encrypt(Zeroizing::new(vec![1]), options()));
        tokio::select! {
            _ = f.state.entered_encrypt.notified() => {},
            _ = &mut waiter => return Err(BridgeError::BeforeDispatch),
            _ = tokio::time::sleep(Duration::from_secs(2)) => return Err(BridgeError::BeforeDispatch),
        }
        drop(waiter);
        assert!(s.state() == SessionState::OutcomeUnknown);
        assert!(s.finalize(options()).await == Err(BridgeError::InvalidState));
        assert!(f.state.methods()? == [WrapperMethod::SetConfig, WrapperMethod::Init, WrapperMethod::Encrypt]);
        Ok(())
    }.await;
    f.finish().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_oversized_response_fences_and_does_not_replay() -> Result<(), BridgeError> {
    let f = Fixture::start(Mode::OversizedEncrypt).await?;
    let result = async {
        let mut s = f.session().await?;
        s.set_config(options()).await?;
        s.init(options()).await?;
        assert!(s.encrypt(Zeroizing::new(vec![1]), options()).await.is_err());
        assert!(s.state() == SessionState::OutcomeUnknown);
        assert!(s.key_id().await == Err(BridgeError::InvalidState));
        assert!(
            f.state.methods()?
                == [
                    WrapperMethod::SetConfig,
                    WrapperMethod::Init,
                    WrapperMethod::Encrypt
                ]
        );
        Ok(())
    }
    .await;
    f.finish().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_post_rpc_owner_change_fences_and_never_replays() -> Result<(), BridgeError> {
    let f = Fixture::start(Mode::OwnerChangedEncrypt).await?;
    let result = async {
        let mut s = f.session().await?;
        s.set_config(options()).await?;
        s.init(options()).await?;
        assert!(matches!(
            s.encrypt(Zeroizing::new(vec![1]), options()).await,
            Err(BridgeError::IdentityChanged)
        ));
        assert!(s.state() == SessionState::OutcomeUnknown);
        assert!(s.key_id().await == Err(BridgeError::InvalidState));
        assert!(
            f.state.methods()?
                == [
                    WrapperMethod::SetConfig,
                    WrapperMethod::Init,
                    WrapperMethod::Encrypt
                ]
        );
        Ok(())
    }
    .await;
    f.finish().await?;
    result
}
