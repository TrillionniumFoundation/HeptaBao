use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::*;
use crate::handshake::{LocalEndpoint, PublicHandshake};

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
fn limits() -> RpcLimits {
    RpcLimits {
        maximum_request_bytes: 1024,
        maximum_response_bytes: 1024,
        timeout: Duration::from_millis(20),
    }
}
fn options() -> RpcOptions {
    let mut value = RpcOptions::default();
    value.with_disallow_env_vars = true;
    value
}

#[tokio::test]
async fn expired_session_deadline_never_enters_the_provider() -> Result<(), BridgeError> {
    let (mut session, _) = session(ready_replies(vec![]))?;
    session.set_config(options()).await?;
    session.init(options()).await?;
    let before = session
        .transport
        .calls
        .lock()
        .map_err(|_| BridgeError::BeforeDispatch)?
        .len();
    let expired = Instant::now();
    assert!(matches!(
        session
            .encrypt_before(Zeroizing::new(vec![1]), options(), expired)
            .await,
        Err(BridgeError::BeforeDispatch)
    ));
    let blob = OpaqueBlobInfo::from_protobuf(&[])?;
    assert!(matches!(
        session.decrypt_before(&blob, options(), expired).await,
        Err(BridgeError::BeforeDispatch)
    ));
    assert_eq!(
        session
            .transport
            .calls
            .lock()
            .map_err(|_| BridgeError::BeforeDispatch)?
            .len(),
        before
    );
    assert_eq!(session.state(), SessionState::Initialized);
    Ok(())
}

#[tokio::test]
async fn expired_ready_deadline_does_not_even_poll_readiness() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let readiness_polls = AtomicUsize::new(0);
    let result = ready_before_dispatch(Instant::now(), async {
        readiness_polls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .await;
    assert_eq!(result, Err(BridgeError::BeforeDispatch));
    assert_eq!(readiness_polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn readiness_that_returns_after_deadline_cannot_start_a_provider_call() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let readiness_polls = AtomicUsize::new(0);
    let provider_calls = AtomicUsize::new(0);
    let deadline = Instant::now() + Duration::from_millis(20);
    let result = async {
        ready_before_dispatch(deadline, async {
            readiness_polls.fetch_add(1, Ordering::SeqCst);
            // Deliberately complete the inner future after its deadline. This
            // checks the explicit post-ready guard even when timeout polls it first.
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
            Ok(())
        })
        .await?;
        provider_calls.fetch_add(1, Ordering::SeqCst);
        Ok::<(), BridgeError>(())
    }
    .await;
    assert_eq!(result, Err(BridgeError::BeforeDispatch));
    assert_eq!(readiness_polls.load(Ordering::SeqCst), 1);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
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
    fn update(&self, f: impl FnOnce(&mut (OwnedPluginIdentity, HostLifecycle))) {
        let locked = self.0.lock();
        assert!(locked.is_ok(), "fixture lock failed");
        if let Ok(mut v) = locked {
            f(&mut v);
        }
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
#[derive(Debug)]
enum Reply {
    Message(Vec<u8>),
    Fail,
    Pending,
    OwnerChanged,
}
type RecordedCalls = Arc<Mutex<Vec<(WrapperMethod, Vec<u8>)>>>;

#[derive(Debug)]
struct FakeTransport {
    auth: RpcAuthentication,
    replies: VecDeque<(WrapperMethod, Reply)>,
    calls: RecordedCalls,
    probe: Probe,
    identity: OwnedPluginIdentity,
    generation: u64,
}
impl WrapperRpcTransport for FakeTransport {
    fn authentication(&self) -> RpcAuthentication {
        self.auth
    }
    fn owner_identity(&self) -> &OwnedPluginIdentity {
        &self.identity
    }
    fn configuration_generation(&self) -> u64 {
        self.generation
    }
    async fn unary(
        &mut self,
        method: WrapperMethod,
        request: Zeroizing<Vec<u8>>,
        _deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        self.calls
            .lock()
            .map_err(|_| BridgeError::BeforeDispatch)?
            .push((method, request.to_vec()));
        let (expected, reply) = self
            .replies
            .pop_front()
            .ok_or(BridgeError::BeforeDispatch)?;
        assert!(method == expected, "fixture method mismatch");
        match reply {
            Reply::Message(wire) => Ok(Zeroizing::new(wire)),
            Reply::Fail => Err(BridgeError::OutcomeUnknown),
            Reply::Pending => std::future::pending().await,
            Reply::OwnerChanged => {
                self.probe.update(|v| v.0.start_ticks += 1);
                Ok(Zeroizing::new(vec![]))
            }
        }
    }
}
type Session = OpenBaoGrpcSession<FakeTransport, Probe>;
fn session(replies: Vec<(WrapperMethod, Reply)>) -> Result<(Session, Probe), BridgeError> {
    let probe = Probe::new();
    let fake = FakeTransport {
        auth: RpcAuthentication::PinnedMutualTls,
        replies: replies.into(),
        calls: Default::default(),
        probe: probe.clone(),
        identity: identity(),
        generation: 1,
    };
    let s = OpenBaoGrpcSession::admit(fake, probe.clone(), identity(), limits())?;
    Ok((s, probe))
}
fn configured() -> (WrapperMethod, Reply) {
    (
        WrapperMethod::SetConfig,
        Reply::Message(
            protocol::SetConfigResponse {
                wrapper_id: "public-fixture-wrapper".into(),
                wrapper_config: Some(Default::default()),
            }
            .encode_to_vec(),
        ),
    )
}
fn ready_replies(tail: Vec<(WrapperMethod, Reply)>) -> Vec<(WrapperMethod, Reply)> {
    let mut result = vec![configured(), (WrapperMethod::Init, Reply::Message(vec![]))];
    result.extend(tail);
    result
}

#[test]
fn public_handshake_is_strict_local_grpc_and_not_auto_mtls_admission() -> Result<(), BridgeError> {
    let good = PublicHandshake::parse(b"1|1|tcp|127.0.0.1:15000|grpc\n")?;
    assert!(matches!(good.endpoint(), LocalEndpoint::Tcp(_)));
    assert!(good.automatic_launch_admission() == Err(BridgeError::AutoMtlsWireContractUnavailable));
    assert!(PublicHandshake::parse(b"1|1|tcp|[::1]:15000|grpc").is_ok());
    assert!(PublicHandshake::parse(b"1|1|unix|/owned/private/plugin.sock|grpc").is_ok());
    for bad in [
        b"1|1|tcp|127.0.0.1:15000|grpc|extra".as_slice(),
        b"1|2|tcp|127.0.0.1:15000|grpc",
        b"01|1|tcp|127.0.0.1:15000|grpc",
        b"1|1|tcp|192.0.2.1:15000|grpc",
        b"1|1|tcp|127.0.0.1:0|grpc",
        b"1|1|unix|../plugin.sock|grpc",
        b"1|1|unix|/owned/../plugin.sock|grpc",
        b"1|1|tcp|127.0.0.1:15000|netrpc",
        b"1|1|tcp|127.0.0.1:15000|grpc\nsecret",
        b"1|1|tcp|127.0.0.1:15000|grpc\r\n",
        b"1|1|tcp|localhost:15000|grpc",
    ] {
        assert!(
            PublicHandshake::parse(bad).is_err(),
            "malformed public handshake admitted"
        );
    }
    assert!(handshake::KMS_MAGIC_COOKIE_KEY == "OPENBAO_KMS_PLUGIN");
    assert!(handshake::KMS_MAGIC_COOKIE_VALUE == "39704a18-7da7-4bda-9a2d-f7c488d70328");
    Ok(())
}

#[test]
fn exact_proto_tags_match_independent_golden_bytes() -> Result<(), BridgeError> {
    let o = RpcOptions {
        with_key_id: "k".into(),
        with_aad: vec![1, 2],
        with_config_map: BTreeMap::from([("a".into(), "b".into())]),
        with_disallow_env_vars: true,
    };
    // Manually recorded protobuf golden bytes from the public schema, not a roundtrip-only test.
    assert!(
        o.encode_to_vec()
            == vec![
                0x52, 1, b'k', 0xa2, 1, 2, 1, 2, 0xf2, 1, 6, 0x0a, 1, b'a', 0x12, 1, b'b', 0xd0, 5,
                1
            ],
        "RPCOptions wire contract changed"
    );
    let request = protocol::EncryptRequest {
        wrapper_id: "w".into(),
        plaintext: vec![3],
        options: None,
    };
    assert!(
        request.encode_to_vec() == vec![0x0a, 1, b'w', 0x52, 1, 3],
        "EncryptRequest wire contract changed"
    );
    let blob = protocol::wrapping::BlobInfo {
        ciphertext: vec![4],
        iv: vec![5],
        key_info: Some(protocol::wrapping::KeyInfo {
            mechanism: 7,
            key_id: "k".into(),
            wrapped_key: vec![6],
        }),
    };
    assert!(
        blob.encode_to_vec()
            == vec![
                0x0a, 1, 4, 0x12, 1, 5, 0x2a, 8, 0x08, 7, 0x1a, 1, b'k', 0x2a, 1, 6
            ],
        "BlobInfo wire contract changed"
    );
    let response = protocol::TypeResponse { r#type: "t".into() };
    assert!(response.encode_to_vec() == vec![0x52, 1, b't']);
    let response = protocol::SetConfigResponse {
        wrapper_id: "w".into(),
        wrapper_config: Some(protocol::wrapping::WrapperConfig {
            metadata: BTreeMap::from([("a".into(), "b".into())]),
        }),
    };
    assert!(
        response.encode_to_vec()
            == vec![
                0x0a, 1, b'w', 0x52, 8, 0x52, 6, 0x0a, 1, b'a', 0x12, 1, b'b'
            ]
    );
    Ok(())
}

#[tokio::test]
async fn seven_exact_rpc_paths_options_wrapper_identity_and_opaque_blob_are_used()
-> Result<(), BridgeError> {
    // Unknown nested KeyInfo field 9 and unknown BlobInfo field 31 must survive decrypt.
    let blob = vec![
        0x0a, 2, 0xab, 0xcd, 0x12, 1, 8, 0x2a, 7, 0x1a, 1, b'k', 0x4a, 2, 9, 10, 0xfa, 1, 1, 11,
    ];
    let mut encrypted = vec![];
    prost::encoding::bytes::encode(10, &blob, &mut encrypted);
    let (mut s, _) = session(vec![
        configured(),
        (
            WrapperMethod::Type,
            Reply::Message(
                protocol::TypeResponse {
                    r#type: "pkcs11".into(),
                }
                .encode_to_vec(),
            ),
        ),
        (
            WrapperMethod::KeyId,
            Reply::Message(
                protocol::KeyIdResponse {
                    key_id: "public-fixture-key".into(),
                }
                .encode_to_vec(),
            ),
        ),
        (WrapperMethod::Init, Reply::Message(vec![])),
        (WrapperMethod::Encrypt, Reply::Message(encrypted)),
        (
            WrapperMethod::Decrypt,
            Reply::Message(
                protocol::DecryptResponse {
                    plaintext: b"PUBLIC_FIXTURE".to_vec(),
                }
                .encode_to_vec(),
            ),
        ),
        (WrapperMethod::Finalize, Reply::Message(vec![])),
    ])?;
    s.set_config(options()).await?;
    assert!(&*s.wrapper_type().await? == "pkcs11");
    assert!(&*s.key_id().await? == "public-fixture-key");
    s.init(options()).await?;
    let encrypted = s
        .encrypt(Zeroizing::new(b"PUBLIC_FIXTURE".to_vec()), options())
        .await?;
    assert!(encrypted.protobuf() == blob);
    assert!(encrypted.key_info().is_some());
    let decrypted = s.decrypt(&encrypted, options()).await?;
    assert!(decrypted.as_slice() == b"PUBLIC_FIXTURE");
    s.finalize(options()).await?;
    assert!(s.state() == SessionState::Finalized);
    assert!(s.key_id().await == Err(BridgeError::InvalidState));
    let calls = s
        .transport
        .calls
        .lock()
        .map_err(|_| BridgeError::BeforeDispatch)?;
    assert!(calls.len() == 7);
    let mut wire = calls[5].1.as_slice();
    // Decode identity/options through maintained Prost, and locate the final retained BlobInfo field.
    let decoded =
        protocol::DecryptRequest::decode(wire).map_err(|_| BridgeError::InvalidResponse)?;
    assert!(decoded.wrapper_id == "public-fixture-wrapper");
    assert!(
        decoded
            .options
            .as_ref()
            .is_some_and(|o| o.with_disallow_env_vars)
    );
    let index = wire.len() - blob.len();
    wire = &wire[index..];
    assert!(wire == blob);
    let paths: Vec<_> = calls.iter().map(|(m, _)| m.path()).collect();
    assert!(
        paths
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
    Ok(())
}

#[tokio::test]
async fn timeout_fences_and_never_replays() -> Result<(), BridgeError> {
    let (mut s, _) = session(ready_replies(vec![(
        WrapperMethod::Encrypt,
        Reply::Pending,
    )]))?;
    s.set_config(options()).await?;
    s.init(options()).await?;
    assert!(matches!(
        s.encrypt(Zeroizing::new(vec![1]), options()).await,
        Err(BridgeError::OutcomeUnknown)
    ));
    assert!(s.state() == SessionState::OutcomeUnknown);
    assert!(matches!(
        s.encrypt(Zeroizing::new(vec![1]), options()).await,
        Err(BridgeError::InvalidState)
    ));
    assert!(
        s.transport
            .calls
            .lock()
            .map_err(|_| BridgeError::BeforeDispatch)?
            .len()
            == 3
    );
    Ok(())
}

#[tokio::test]
async fn dropped_rpc_waiter_leaves_unknown_outcome_without_replay() -> Result<(), BridgeError> {
    let (mut s, _) = session(ready_replies(vec![(
        WrapperMethod::Encrypt,
        Reply::Pending,
    )]))?;
    s.set_config(options()).await?;
    s.init(options()).await?;
    let mut future = Box::pin(s.encrypt(Zeroizing::new(vec![1]), options()));
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(future);
    assert!(s.state() == SessionState::OutcomeUnknown);
    assert!(s.finalize(options()).await == Err(BridgeError::InvalidState));
    assert!(
        s.transport
            .calls
            .lock()
            .map_err(|_| BridgeError::BeforeDispatch)?
            .len()
            == 3
    );
    Ok(())
}

#[tokio::test]
async fn failures_and_malformed_responses_fence_without_error_body() -> Result<(), BridgeError> {
    for reply in [
        Reply::Fail,
        Reply::Message(vec![0xff]),
        Reply::Message(vec![0x52, 0, 0x52, 0]),
        Reply::Message(vec![0x52, 0, 0x08, 1]),
    ] {
        let (mut s, _) = session(ready_replies(vec![(WrapperMethod::Encrypt, reply)]))?;
        s.set_config(options()).await?;
        s.init(options()).await?;
        assert!(s.encrypt(Zeroizing::new(vec![]), options()).await.is_err());
        assert!(s.state() == SessionState::OutcomeUnknown);
        assert!(s.key_id().await == Err(BridgeError::InvalidState));
        assert!(
            s.transport
                .calls
                .lock()
                .map_err(|_| BridgeError::BeforeDispatch)?
                .len()
                == 3
        );
    }
    Ok(())
}

#[tokio::test]
async fn complete_process_config_identity_changes_deny_before_dispatch() -> Result<(), BridgeError>
{
    for change in 0..11 {
        let (mut s, p) = session(ready_replies(vec![]))?;
        s.set_config(options()).await?;
        s.init(options()).await?;
        p.update(|v| match change {
            0 => v.0.uid += 1,
            1 => v.0.pid += 1,
            2 => v.0.session_id += 1,
            3 => v.0.start_ticks += 1,
            4 => v.0.executable_device += 1,
            5 => v.0.executable_inode += 1,
            6 => v.0.executable_sha256[0] ^= 1,
            7 => v.0.config_device += 1,
            8 => v.0.config_inode += 1,
            9 => v.0.config_sha256[0] ^= 1,
            _ => v.0.config_mode = 0o644,
        });
        assert!(s.key_id().await == Err(BridgeError::IdentityChanged));
        assert!(
            s.transport
                .calls
                .lock()
                .map_err(|_| BridgeError::BeforeDispatch)?
                .len()
                == 2
        );
    }
    Ok(())
}

#[tokio::test]
async fn post_await_identity_change_is_unknown_and_lifecycle_is_not_reconfigured_unsealed()
-> Result<(), BridgeError> {
    let (mut s, _) = session(ready_replies(vec![(
        WrapperMethod::Encrypt,
        Reply::OwnerChanged,
    )]))?;
    s.set_config(options()).await?;
    s.init(options()).await?;
    assert!(matches!(
        s.encrypt(Zeroizing::new(vec![]), options()).await,
        Err(BridgeError::IdentityChanged)
    ));
    assert!(s.state() == SessionState::OutcomeUnknown);
    let (mut s, p) = session(vec![configured()])?;
    p.update(|v| v.1.sealed = false);
    assert!(matches!(
        s.set_config(options()).await,
        Err(BridgeError::LifecycleDenied)
    ));
    assert!(
        s.transport
            .calls
            .lock()
            .map_err(|_| BridgeError::BeforeDispatch)?
            .is_empty()
    );
    let (mut s, p) = session(ready_replies(vec![]))?;
    s.set_config(options()).await?;
    p.update(|v| v.1.configuration_generation += 1);
    assert!(s.init(options()).await == Err(BridgeError::LifecycleDenied));
    Ok(())
}

#[tokio::test]
async fn unsealed_runtime_allows_existing_crypto_but_does_not_finalize_or_reconfigure()
-> Result<(), BridgeError> {
    let (mut s, p) = session(ready_replies(vec![(
        WrapperMethod::KeyId,
        Reply::Message(vec![]),
    )]))?;
    s.set_config(options()).await?;
    s.init(options()).await?;
    p.update(|v| v.1.sealed = false);
    assert!(s.key_id().await?.is_empty());
    assert!(s.finalize(options()).await == Err(BridgeError::LifecycleDenied));
    assert!(matches!(
        s.set_config(options()).await,
        Err(BridgeError::InvalidState)
    ));
    Ok(())
}

#[test]
fn malformed_limits_options_blob_and_unauthenticated_transport_are_rejected()
-> Result<(), BridgeError> {
    let p = Probe::new();
    let f = FakeTransport {
        auth: RpcAuthentication::Unauthenticated,
        replies: Default::default(),
        calls: Default::default(),
        probe: p.clone(),
        identity: identity(),
        generation: 1,
    };
    assert!(matches!(
        OpenBaoGrpcSession::admit(f, p, identity(), limits()),
        Err(BridgeError::UnauthenticatedTransport)
    ));
    for limit in [
        RpcLimits {
            maximum_request_bytes: 0,
            ..limits()
        },
        RpcLimits {
            maximum_response_bytes: MAX_MESSAGE_BYTES + 1,
            ..limits()
        },
        RpcLimits {
            timeout: Duration::ZERO,
            ..limits()
        },
        RpcLimits {
            timeout: Duration::from_secs(61),
            ..limits()
        },
    ] {
        assert!(limit.validate().is_err());
    }
    assert!(validate_options(&Default::default()).is_err());
    assert!(OpaqueBlobInfo::from_protobuf(&[0xff]).is_err());
    assert!(OpaqueBlobInfo::from_protobuf(&vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
    assert!(single_message_field(&[0x52, 0, 0x52, 0], 10).is_err());
    let mut secret = protocol::EncryptRequest::default();
    secret.plaintext = b"PUBLIC_SECRET_DEBUG_MARKER".to_vec();
    assert!(!format!("{secret:?}").contains("PUBLIC_SECRET_DEBUG_MARKER"));
    let mut o = options();
    o.with_key_id = "PUBLIC_SECRET_DEBUG_MARKER".into();
    assert!(!format!("{o:?}").contains("PUBLIC_SECRET_DEBUG_MARKER"));
    assert!(
        !format!(
            "{:?}",
            WrapperMetadata(BTreeMap::from([(
                "k".into(),
                "PUBLIC_SECRET_DEBUG_MARKER".into()
            )]))
        )
        .contains("PUBLIC_SECRET_DEBUG_MARKER")
    );
    assert!(BridgeError::OutcomeUnknown.to_string() == "plugin RPC outcome is unknown");
    Ok(())
}

#[test]
fn transport_certificate_owner_and_configuration_epoch_cannot_be_mixed() {
    for mutate_epoch in [false, true] {
        let probe = Probe::new();
        let mut transport_owner = identity();
        if !mutate_epoch {
            transport_owner.pid += 1;
        }
        let fake = FakeTransport {
            auth: RpcAuthentication::PinnedMutualTls,
            replies: Default::default(),
            calls: Default::default(),
            probe: probe.clone(),
            identity: transport_owner,
            generation: if mutate_epoch { 2 } else { 1 },
        };
        let result = OpenBaoGrpcSession::admit(fake, probe, identity(), limits());
        assert!(
            matches!(
                result,
                Err(BridgeError::IdentityChanged | BridgeError::LifecycleDenied)
            ),
            "mixed transport admission was accepted"
        );
    }
}

#[tokio::test]
async fn oversized_peer_response_stays_fenced_and_no_request_replay_occurs()
-> Result<(), BridgeError> {
    let (mut s, _) = session(vec![
        configured(),
        (WrapperMethod::KeyId, Reply::Message(vec![0; 1025])),
    ])?;
    s.set_config(options()).await?;
    assert!(s.key_id().await == Err(BridgeError::MessageTooLarge));
    assert!(s.state() == SessionState::OutcomeUnknown);
    assert!(s.key_id().await == Err(BridgeError::InvalidState));
    assert!(
        s.transport
            .calls
            .lock()
            .map_err(|_| BridgeError::BeforeDispatch)?
            .len()
            == 2
    );
    Ok(())
}
