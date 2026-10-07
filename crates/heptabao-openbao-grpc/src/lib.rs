#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! A bounded OpenBao 2.7 Wrapper protobuf/gRPC bridge, separate from HBP1.
//!
//! No launcher or server integration is enabled here. The trusted platform
//! adapter must capture immutable process/config identity and supply fresh
//! observations. Automatic go-plugin mTLS startup fields are not inferred.
//! A dropped, timed-out, invalid, or failed RPC fences the session without replay.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::time::{Duration, Instant};

use prost::Message;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
pub mod automatic_tls;
pub mod handshake;
#[cfg(unix)]
pub mod linux_identity;
pub mod protocol;
pub mod transport;

use protocol::wrapping::RpcOptions;

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    InvalidHandshake,
    AutoMtlsWireContractUnavailable,
    InvalidBinding,
    ProcessObservationUnavailable,
    IdentityChanged,
    LifecycleDenied,
    UnauthenticatedTransport,
    InvalidState,
    InvalidLimits,
    InvalidOptions,
    InvalidResponse,
    MessageTooLarge,
    BeforeDispatch,
    OutcomeUnknown,
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never format transport errors, RPC status text, paths, or secret values.
        f.write_str(match self {
            Self::InvalidHandshake => "invalid plugin handshake",
            Self::AutoMtlsWireContractUnavailable => {
                "automatic mTLS startup contract is unavailable"
            }
            Self::InvalidBinding => "invalid plugin identity binding",
            Self::ProcessObservationUnavailable => "plugin process observation unavailable",
            Self::IdentityChanged => "plugin identity changed",
            Self::LifecycleDenied => "plugin lifecycle denied",
            Self::UnauthenticatedTransport => "plugin mutual TLS is required",
            Self::InvalidState => "plugin session state denied",
            Self::InvalidLimits => "invalid plugin limits",
            Self::InvalidOptions => "invalid plugin RPC options",
            Self::InvalidResponse => "invalid plugin RPC response",
            Self::MessageTooLarge => "plugin message exceeds limit",
            Self::BeforeDispatch => "plugin transport was unavailable before dispatch",
            Self::OutcomeUnknown => "plugin RPC outcome is unknown",
        })
    }
}
impl std::error::Error for BridgeError {}

/// Exact captured Linux process/start and immutable executable/config metadata.
/// This is data, not an OS attestation; IdentityProbe is a trusted adapter boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct OwnedPluginIdentity {
    pub uid: u32,
    pub pid: u32,
    pub session_id: u32,
    pub start_ticks: u64,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub executable_sha256: [u8; 32],
    pub config_device: u64,
    pub config_inode: u64,
    pub config_sha256: [u8; 32],
    pub config_mode: u32,
}
impl fmt::Debug for OwnedPluginIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedPluginIdentity([REDACTED])")
    }
}
impl OwnedPluginIdentity {
    pub fn validate(&self) -> Result<(), BridgeError> {
        if self.pid == 0
            || self.session_id == 0
            || self.start_ticks == 0
            || self.executable_inode == 0
            || self.config_inode == 0
            || self.executable_sha256 == [0; 32]
            || self.config_sha256 == [0; 32]
            || self.config_mode != 0o600
        {
            return Err(BridgeError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostLifecycle {
    pub sealed: bool,
    pub configuration_generation: u64,
}

/// Implementors must observe metadata and the authoritative host lifecycle,
/// not cached endpoint names or process comm. No implementation spawns a process.
pub trait IdentityProbe: fmt::Debug {
    fn observe(&self) -> Result<(OwnedPluginIdentity, HostLifecycle), BridgeError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcAuthentication {
    Unauthenticated,
    PinnedMutualTls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrapperMethod {
    SetConfig,
    Type,
    KeyId,
    Encrypt,
    Decrypt,
    Init,
    Finalize,
}
impl WrapperMethod {
    pub const fn path(self) -> &'static str {
        match self {
            Self::SetConfig => "/pb.Wrapper/SetConfig",
            Self::Type => "/pb.Wrapper/Type",
            Self::KeyId => "/pb.Wrapper/KeyId",
            Self::Encrypt => "/pb.Wrapper/Encrypt",
            Self::Decrypt => "/pb.Wrapper/Decrypt",
            Self::Init => "/pb.Wrapper/Init",
            Self::Finalize => "/pb.Wrapper/Finalize",
        }
    }
    const fn requires_sealed(self) -> bool {
        matches!(self, Self::SetConfig | Self::Init | Self::Finalize)
    }
}

/// A trusted transport must preserve raw protobuf responses, avoid RPC replay,
/// and return only closed errors. The absolute deadline covers channel readiness
/// and the unary dispatch; an expired call must not contact the provider.
/// TonicWrapperTransport always requires mTLS.
pub trait WrapperRpcTransport: fmt::Debug {
    fn authentication(&self) -> RpcAuthentication;
    fn owner_identity(&self) -> &OwnedPluginIdentity;
    fn configuration_generation(&self) -> u64;
    fn unary(
        &mut self,
        method: WrapperMethod,
        request: Zeroizing<Vec<u8>>,
        deadline: Instant,
    ) -> impl Future<Output = Result<Zeroizing<Vec<u8>>, BridgeError>> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcLimits {
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: usize,
    pub timeout: Duration,
}
impl RpcLimits {
    pub fn validate(self) -> Result<Self, BridgeError> {
        if self.maximum_request_bytes == 0
            || self.maximum_request_bytes > MAX_MESSAGE_BYTES
            || self.maximum_response_bytes == 0
            || self.maximum_response_bytes > MAX_MESSAGE_BYTES
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(60)
        {
            return Err(BridgeError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Created,
    Configured,
    Initialized,
    Finalized,
    OutcomeUnknown,
}

/// BlobInfo retains its complete protobuf bytes, including unknown future fields.
/// Known fields can be inspected; they cannot replace the retained decrypt input.
pub struct OpaqueBlobInfo {
    wire: Zeroizing<Vec<u8>>,
    known: protocol::wrapping::BlobInfo,
}
impl fmt::Debug for OpaqueBlobInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueBlobInfo([REDACTED])")
    }
}
impl OpaqueBlobInfo {
    pub fn from_protobuf(wire: &[u8]) -> Result<Self, BridgeError> {
        if wire.len() > MAX_MESSAGE_BYTES {
            return Err(BridgeError::MessageTooLarge);
        }
        let known =
            protocol::wrapping::BlobInfo::decode(wire).map_err(|_| BridgeError::InvalidResponse)?;
        if known
            .key_info
            .as_ref()
            .is_some_and(|k| k.key_id.len() > MAX_TEXT_BYTES)
        {
            return Err(BridgeError::InvalidResponse);
        }
        Ok(Self {
            wire: Zeroizing::new(wire.to_vec()),
            known,
        })
    }
    pub fn protobuf(&self) -> &[u8] {
        self.wire.as_slice()
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.known.ciphertext
    }
    pub fn iv(&self) -> &[u8] {
        &self.known.iv
    }
    pub fn key_info(&self) -> Option<&protocol::wrapping::KeyInfo> {
        self.known.key_info.as_ref()
    }
}

/// SetConfig metadata can contain provider-specific secrets; all Debug is redacted.
pub struct WrapperMetadata(BTreeMap<String, String>);
impl fmt::Debug for WrapperMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrapperMetadata([REDACTED])")
    }
}
impl WrapperMetadata {
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }
}
impl Drop for WrapperMetadata {
    fn drop(&mut self) {
        for (mut key, mut value) in std::mem::take(&mut self.0) {
            key.zeroize();
            value.zeroize();
        }
    }
}

pub struct OpenBaoGrpcSession<T, P> {
    transport: T,
    probe: P,
    identity: OwnedPluginIdentity,
    generation: u64,
    limits: RpcLimits,
    state: SessionState,
    wrapper_id: Zeroizing<String>,
}
impl<T, P> fmt::Debug for OpenBaoGrpcSession<T, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenBaoGrpcSession")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
impl<T: WrapperRpcTransport, P: IdentityProbe> OpenBaoGrpcSession<T, P> {
    pub fn admit(
        transport: T,
        probe: P,
        identity: OwnedPluginIdentity,
        limits: RpcLimits,
    ) -> Result<Self, BridgeError> {
        identity.validate()?;
        if transport.authentication() != RpcAuthentication::PinnedMutualTls {
            return Err(BridgeError::UnauthenticatedTransport);
        }
        if transport.owner_identity() != &identity {
            return Err(BridgeError::IdentityChanged);
        }
        let (current, lifecycle) = probe.observe()?;
        if current != identity {
            return Err(BridgeError::IdentityChanged);
        }
        if !lifecycle.sealed
            || lifecycle.configuration_generation == 0
            || transport.configuration_generation() != lifecycle.configuration_generation
        {
            return Err(BridgeError::LifecycleDenied);
        }
        Ok(Self {
            transport,
            probe,
            identity,
            generation: lifecycle.configuration_generation,
            limits: limits.validate()?,
            state: SessionState::Created,
            wrapper_id: Zeroizing::new(String::new()),
        })
    }
    pub fn transport_kind(&self) -> handshake::TransportKind {
        handshake::TransportKind::OpenBaoGrpcWrapper
    }
    pub fn state(&self) -> SessionState {
        self.state
    }

    fn check_owner(&self, method: WrapperMethod) -> Result<(), BridgeError> {
        let (current, lifecycle) = self.probe.observe()?;
        if current != self.identity {
            return Err(BridgeError::IdentityChanged);
        }
        if lifecycle.configuration_generation != self.generation
            || (method.requires_sealed() && !lifecycle.sealed)
        {
            return Err(BridgeError::LifecycleDenied);
        }
        Ok(())
    }
    async fn call_before(
        &mut self,
        method: WrapperMethod,
        request: Zeroizing<Vec<u8>>,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        let deadline = deadline.min(Instant::now() + self.limits.timeout);
        if self.state == SessionState::OutcomeUnknown || self.state == SessionState::Finalized {
            return Err(BridgeError::InvalidState);
        }
        if request.len() > self.limits.maximum_request_bytes {
            return Err(BridgeError::MessageTooLarge);
        }
        self.check_owner(method)?;
        remaining_before_dispatch(deadline)?;
        // Set before the first await: dropping this future leaves the fence intact.
        // It adds no replay and makes no claim about whether a peer committed.
        self.state = SessionState::OutcomeUnknown;
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.transport.unary(method, request, deadline),
        )
        .await;
        let response = match result {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(BridgeError::OutcomeUnknown),
        };
        if Instant::now() >= deadline {
            return Err(BridgeError::OutcomeUnknown);
        }
        if response.len() > self.limits.maximum_response_bytes {
            return Err(BridgeError::MessageTooLarge);
        }
        self.check_owner(method)?;
        Ok(response)
    }
    pub async fn set_config(
        &mut self,
        options: RpcOptions,
    ) -> Result<WrapperMetadata, BridgeError> {
        self.set_config_before(options, Instant::now() + self.limits.timeout)
            .await
    }
    pub async fn set_config_before(
        &mut self,
        options: RpcOptions,
        deadline: Instant,
    ) -> Result<WrapperMetadata, BridgeError> {
        if self.state != SessionState::Created {
            return Err(BridgeError::InvalidState);
        }
        validate_options(&options)?;
        let request = protocol::SetConfigRequest {
            options: Some(options),
        };
        let response = self
            .call_before(WrapperMethod::SetConfig, encode(&request), deadline)
            .await?;
        let mut decoded = decode::<protocol::SetConfigResponse>(&response)?;
        if !bounded_text(&decoded.wrapper_id, false) {
            return Err(BridgeError::InvalidResponse);
        }
        let metadata = decoded
            .wrapper_config
            .as_mut()
            .map(|m| std::mem::take(&mut m.metadata))
            .unwrap_or_default();
        let metadata = WrapperMetadata(metadata);
        validate_map(metadata.as_map()).map_err(|_| BridgeError::InvalidResponse)?;
        *self.wrapper_id = std::mem::take(&mut decoded.wrapper_id);
        self.state = SessionState::Configured;
        Ok(metadata)
    }
    pub async fn wrapper_type(&mut self) -> Result<Zeroizing<String>, BridgeError> {
        self.wrapper_type_before(Instant::now() + self.limits.timeout)
            .await
    }
    pub async fn wrapper_type_before(
        &mut self,
        deadline: Instant,
    ) -> Result<Zeroizing<String>, BridgeError> {
        let previous = self.configured_state()?;
        let request = protocol::TypeRequest {
            wrapper_id: self.wrapper_id.to_string(),
        };
        let response = self
            .call_before(WrapperMethod::Type, encode(&request), deadline)
            .await?;
        let mut decoded = decode::<protocol::TypeResponse>(&response)?;
        if !bounded_text(&decoded.r#type, false) {
            return Err(BridgeError::InvalidResponse);
        }
        let value = Zeroizing::new(std::mem::take(&mut decoded.r#type));
        self.state = previous;
        Ok(value)
    }
    pub async fn key_id(&mut self) -> Result<Zeroizing<String>, BridgeError> {
        self.key_id_before(Instant::now() + self.limits.timeout)
            .await
    }
    pub async fn key_id_before(
        &mut self,
        deadline: Instant,
    ) -> Result<Zeroizing<String>, BridgeError> {
        let previous = self.configured_state()?;
        let request = protocol::KeyIdRequest {
            wrapper_id: self.wrapper_id.to_string(),
        };
        let response = self
            .call_before(WrapperMethod::KeyId, encode(&request), deadline)
            .await?;
        let mut decoded = decode::<protocol::KeyIdResponse>(&response)?;
        if !bounded_text(&decoded.key_id, true) {
            return Err(BridgeError::InvalidResponse);
        }
        let value = Zeroizing::new(std::mem::take(&mut decoded.key_id));
        self.state = previous;
        Ok(value)
    }
    pub async fn init(&mut self, options: RpcOptions) -> Result<(), BridgeError> {
        self.init_before(options, Instant::now() + self.limits.timeout)
            .await
    }
    pub async fn init_before(
        &mut self,
        options: RpcOptions,
        deadline: Instant,
    ) -> Result<(), BridgeError> {
        if self.state != SessionState::Configured {
            return Err(BridgeError::InvalidState);
        }
        validate_options(&options)?;
        let request = protocol::InitRequest {
            wrapper_id: self.wrapper_id.to_string(),
            options: Some(options),
        };
        let response = self
            .call_before(WrapperMethod::Init, encode(&request), deadline)
            .await?;
        let _decoded = decode::<protocol::InitResponse>(&response)?;
        self.state = SessionState::Initialized;
        Ok(())
    }
    pub async fn encrypt(
        &mut self,
        plaintext: Zeroizing<Vec<u8>>,
        options: RpcOptions,
    ) -> Result<OpaqueBlobInfo, BridgeError> {
        self.encrypt_before(plaintext, options, Instant::now() + self.limits.timeout)
            .await
    }
    pub async fn encrypt_before(
        &mut self,
        plaintext: Zeroizing<Vec<u8>>,
        options: RpcOptions,
        deadline: Instant,
    ) -> Result<OpaqueBlobInfo, BridgeError> {
        if self.state != SessionState::Initialized {
            return Err(BridgeError::InvalidState);
        }
        validate_options(&options)?;
        if plaintext.len() > self.limits.maximum_request_bytes {
            return Err(BridgeError::MessageTooLarge);
        }
        let request = protocol::EncryptRequest {
            wrapper_id: self.wrapper_id.to_string(),
            plaintext: plaintext.to_vec(),
            options: Some(options),
        };
        let response = self
            .call_before(WrapperMethod::Encrypt, encode(&request), deadline)
            .await?;
        // Retain nested bytes before Prost would discard unknown BlobInfo fields.
        let blob_wire = single_message_field(&response, 10)?;
        let blob = OpaqueBlobInfo::from_protobuf(blob_wire)?;
        self.state = SessionState::Initialized;
        Ok(blob)
    }
    pub async fn decrypt(
        &mut self,
        ciphertext: &OpaqueBlobInfo,
        options: RpcOptions,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        self.decrypt_before(ciphertext, options, Instant::now() + self.limits.timeout)
            .await
    }
    pub async fn decrypt_before(
        &mut self,
        ciphertext: &OpaqueBlobInfo,
        options: RpcOptions,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        if self.state != SessionState::Initialized {
            return Err(BridgeError::InvalidState);
        }
        validate_options(&options)?;
        let mut request = encode(&protocol::DecryptRequest {
            wrapper_id: self.wrapper_id.to_string(),
            ciphertext: None,
            options: Some(options),
        });
        // Maintained Prost writes length-delimited field 10 using the exact retained wire.
        prost::encoding::bytes::encode(10, &*ciphertext.wire, &mut *request);
        let response = self
            .call_before(WrapperMethod::Decrypt, request, deadline)
            .await?;
        let mut decoded = decode::<protocol::DecryptResponse>(&response)?;
        let plaintext = Zeroizing::new(std::mem::take(&mut decoded.plaintext));
        self.state = SessionState::Initialized;
        Ok(plaintext)
    }
    pub async fn finalize(&mut self, options: RpcOptions) -> Result<(), BridgeError> {
        self.finalize_before(options, Instant::now() + self.limits.timeout)
            .await
    }
    pub async fn finalize_before(
        &mut self,
        options: RpcOptions,
        deadline: Instant,
    ) -> Result<(), BridgeError> {
        self.configured_state()?;
        validate_options(&options)?;
        let request = protocol::FinalizeRequest {
            wrapper_id: self.wrapper_id.to_string(),
            options: Some(options),
        };
        let response = self
            .call_before(WrapperMethod::Finalize, encode(&request), deadline)
            .await?;
        let _decoded = decode::<protocol::FinalizeResponse>(&response)?;
        self.wrapper_id.zeroize();
        self.state = SessionState::Finalized;
        Ok(())
    }
    fn configured_state(&self) -> Result<SessionState, BridgeError> {
        match self.state {
            SessionState::Configured | SessionState::Initialized => Ok(self.state),
            _ => Err(BridgeError::InvalidState),
        }
    }
}

/// Check immediately before a provider dispatch, rather than relying on a
/// zero-duration Tokio timeout, which may poll its inner future first.
pub(crate) fn remaining_before_dispatch(deadline: Instant) -> Result<Duration, BridgeError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(BridgeError::BeforeDispatch);
    }
    Ok(deadline.duration_since(now))
}

/// Readiness consumes the same absolute budget as the subsequent unary call.
pub(crate) async fn ready_before_dispatch<F>(deadline: Instant, ready: F) -> Result<(), BridgeError>
where
    F: Future<Output = Result<(), BridgeError>>,
{
    remaining_before_dispatch(deadline)?;
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), ready)
        .await
        .map_err(|_| BridgeError::BeforeDispatch)??;
    remaining_before_dispatch(deadline)?;
    Ok(())
}

fn bounded_text(value: &str, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= MAX_TEXT_BYTES
        && !value.chars().any(char::is_control)
}
fn validate_map(map: &BTreeMap<String, String>) -> Result<(), BridgeError> {
    if map.len() > 64
        || map.iter().any(|(k, v)| {
            k.is_empty() || k.len() > 128 || k.chars().any(char::is_control) || v.len() > 16 * 1024
        })
    {
        return Err(BridgeError::InvalidOptions);
    }
    Ok(())
}
fn validate_options(options: &RpcOptions) -> Result<(), BridgeError> {
    if !options.with_disallow_env_vars
        || !bounded_text(&options.with_key_id, true)
        || options.with_aad.len() > MAX_MESSAGE_BYTES
    {
        return Err(BridgeError::InvalidOptions);
    }
    validate_map(&options.with_config_map)
}
fn encode<M: Message>(message: &M) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(message.encode_to_vec())
}
fn decode<M: Message + Default>(wire: &[u8]) -> Result<M, BridgeError> {
    M::decode(wire).map_err(|_| BridgeError::InvalidResponse)
}
fn single_message_field(wire: &[u8], field: u32) -> Result<&[u8], BridgeError> {
    use prost::encoding::{WireType, decode_key, decode_varint};
    let mut remaining = wire;
    let (tag, kind) = decode_key(&mut remaining).map_err(|_| BridgeError::InvalidResponse)?;
    if tag != field || kind != WireType::LengthDelimited {
        return Err(BridgeError::InvalidResponse);
    }
    let count = decode_varint(&mut remaining).map_err(|_| BridgeError::InvalidResponse)?;
    let count: usize = count.try_into().map_err(|_| BridgeError::InvalidResponse)?;
    if count != remaining.len() {
        return Err(BridgeError::InvalidResponse);
    }
    Ok(remaining)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod loopback_tests;
