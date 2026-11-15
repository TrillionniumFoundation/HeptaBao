use super::*;
use heptabao_openbao_grpc::{
    HostLifecycle, OwnedPluginIdentity, RpcAuthentication, SessionState, WrapperMethod,
};
use std::sync::atomic::AtomicUsize;

fn valid_options() -> RpcOptions {
    let mut options = RpcOptions::default();
    options.with_disallow_env_vars = true;
    options
}

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

#[derive(Debug)]
struct Probe;
impl IdentityProbe for Probe {
    fn observe(&self) -> Result<(OwnedPluginIdentity, HostLifecycle), BridgeError> {
        Ok((
            identity(),
            HostLifecycle {
                sealed: true,
                configuration_generation: 1,
            },
        ))
    }
}

#[derive(Debug)]
struct ProviderCounter {
    owner: OwnedPluginIdentity,
    business_calls: Arc<AtomicUsize>,
}
impl WrapperRpcTransport for ProviderCounter {
    fn authentication(&self) -> RpcAuthentication {
        RpcAuthentication::PinnedMutualTls
    }
    fn owner_identity(&self) -> &OwnedPluginIdentity {
        &self.owner
    }
    fn configuration_generation(&self) -> u64 {
        1
    }
    async fn unary(
        &mut self,
        method: WrapperMethod,
        _request: Zeroizing<Vec<u8>>,
        _deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        match method {
            // Public SetConfigResponse: field 1 = "fixture"; InitResponse empty.
            WrapperMethod::SetConfig => Ok(Zeroizing::new(b"\x0a\x07fixture".to_vec())),
            WrapperMethod::Init => Ok(Zeroizing::new(vec![])),
            WrapperMethod::Encrypt | WrapperMethod::Decrypt => {
                self.business_calls.fetch_add(1, Ordering::SeqCst);
                Err(BridgeError::OutcomeUnknown)
            }
            _ => Err(BridgeError::BeforeDispatch),
        }
    }
}

#[test]
fn expired_queued_encrypt_and_decrypt_never_call_the_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = ProviderCounter {
        owner: identity(),
        business_calls: calls.clone(),
    };
    let mut session = OpenBaoGrpcSession::admit(
        transport,
        Probe,
        identity(),
        RpcLimits {
            maximum_request_bytes: 1024,
            maximum_response_bytes: 1024,
            timeout: Duration::from_millis(50),
        },
    )?;
    runtime.block_on(async {
        let mut options = RpcOptions::default();
        options.with_disallow_env_vars = true;
        session.set_config(options).await?;
        let mut options = RpcOptions::default();
        options.with_disallow_env_vars = true;
        session.init(options).await
    })?;
    for operation in [
        WrapperOperation::Encrypt {
            plaintext: Zeroizing::new(vec![1]),
            options: valid_options(),
        },
        WrapperOperation::Decrypt {
            blob: OpaqueBlobInfo::from_protobuf(&[])?,
            options: valid_options(),
        },
    ] {
        let (sender, receiver) = mpsc::sync_channel(1);
        let (reply, _reply_receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + Duration::from_millis(20);
        sender.send(Request {
            operation,
            deadline,
            reply,
        })?;
        assert!(
            Instant::now() < deadline,
            "fixture queue admission must precede expiry"
        );
        // Hold the real request in the queue until it has actually expired.
        thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        );
        let request = receiver.recv()?;
        assert!(Instant::now() >= request.deadline);
        let result = runtime.block_on(execute_operation(
            &mut session,
            request.operation,
            request.deadline,
            &AtomicBool::new(false),
        ));
        assert!(matches!(result, Err(BridgeError::BeforeDispatch)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(session.state(), SessionState::Initialized);
    }
    Ok(())
}
