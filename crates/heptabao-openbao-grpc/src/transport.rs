//! Maintained Tonic HTTP/2 client with explicit mutually authenticated TLS.
//!
//! The SDK AutoMTLS launch wire is deliberately not inferred. The platform must
//! obtain the peer certificate from the exact owned launch, never a global CA,
//! cached endpoint, cookie, or unauthenticated network response. This module does
//! not spawn, reattach, retry, or install a plugin.

use std::fmt;
use std::time::Instant;

use prost::bytes::{Buf, BufMut};
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroizing;

use crate::handshake::LocalEndpoint;
use crate::{
    BridgeError, IdentityProbe, OwnedPluginIdentity, RpcAuthentication, RpcLimits, WrapperMethod,
    WrapperRpcTransport,
};

/// Both certificates are bounded PEM from a single owned launch. The private
/// key is host-generated, never obtained from the plugin. Certificate exchange
/// serialization is a separate, still unsupported launcher responsibility.
pub struct OwnedMutualTlsMaterial {
    pub client_certificate_pem: Zeroizing<Vec<u8>>,
    pub client_private_key_pem: Zeroizing<Vec<u8>>,
    pub server_certificate_pem: Zeroizing<Vec<u8>>,
    pub peer_dns_name: String,
}
impl fmt::Debug for OwnedMutualTlsMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedMutualTlsMaterial([REDACTED])")
    }
}
impl OwnedMutualTlsMaterial {
    fn validate(&self) -> Result<(), BridgeError> {
        let certs = [&self.client_certificate_pem, &self.server_certificate_pem];
        if certs.iter().any(|p| p.is_empty() || p.len() > 16 * 1024)
            || self.client_private_key_pem.is_empty()
            || self.client_private_key_pem.len() > 16 * 1024
            || self.peer_dns_name.is_empty()
            || self.peer_dns_name.len() > 253
            || self
                .peer_dns_name
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
        {
            return Err(BridgeError::InvalidBinding);
        }
        Ok(())
    }
}

/// The only concrete production transport constructor performs mutual TLS;
/// there is no plaintext, custom verifier, root-store fallback, or reattach API.
pub struct TonicWrapperTransport {
    grpc: tonic::client::Grpc<Channel>,
    maximum_response_bytes: usize,
    identity: OwnedPluginIdentity,
    generation: u64,
}
impl fmt::Debug for TonicWrapperTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TonicWrapperTransport([REDACTED])")
    }
}
impl TonicWrapperTransport {
    /// This is an explicit TLS bridge, not a claim of implemented SDK AutoMTLS
    /// startup. The trusted platform is responsible for certificate provenance
    /// and immutable executable admission. In-process mock TLS tests do not
    /// qualify the external SDK launcher or an official plugin connection.
    pub async fn connect_after_owned_launch<P: IdentityProbe>(
        identity: &OwnedPluginIdentity,
        probe: &P,
        address: &LocalEndpoint,
        material: OwnedMutualTlsMaterial,
        limits: RpcLimits,
    ) -> Result<Self, BridgeError> {
        identity.validate()?;
        material.validate()?;
        let limits = limits.validate()?;
        let (before, lifecycle) = probe.observe()?;
        if &before != identity {
            return Err(BridgeError::IdentityChanged);
        }
        if !lifecycle.sealed || lifecycle.configuration_generation == 0 {
            return Err(BridgeError::LifecycleDenied);
        }
        let LocalEndpoint::Tcp(address) = address else {
            return Err(BridgeError::BeforeDispatch);
        };
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(BridgeError::InvalidBinding);
        }
        let tls = ClientTlsConfig::new()
            .domain_name(material.peer_dns_name.clone())
            .ca_certificate(Certificate::from_pem(
                material.server_certificate_pem.as_slice(),
            ))
            .identity(Identity::from_pem(
                material.client_certificate_pem.as_slice(),
                material.client_private_key_pem.as_slice(),
            ));
        let endpoint = Endpoint::from_shared(format!("https://{address}"))
            .map_err(|_| BridgeError::InvalidBinding)?
            .tls_config(tls)
            .map_err(|_| BridgeError::InvalidBinding)?
            .connect_timeout(limits.timeout);
        let channel = tokio::time::timeout(limits.timeout, endpoint.connect())
            .await
            .map_err(|_| BridgeError::BeforeDispatch)?
            .map_err(|_| BridgeError::BeforeDispatch)?;
        let (after, after_lifecycle) = probe.observe()?;
        if &after != identity {
            return Err(BridgeError::IdentityChanged);
        }
        if after_lifecycle != lifecycle {
            return Err(BridgeError::LifecycleDenied);
        }
        Ok(Self {
            grpc: tonic::client::Grpc::new(channel)
                .max_encoding_message_size(limits.maximum_request_bytes)
                .max_decoding_message_size(limits.maximum_response_bytes),
            maximum_response_bytes: limits.maximum_response_bytes,
            identity: identity.clone(),
            generation: lifecycle.configuration_generation,
        })
    }
}
impl WrapperRpcTransport for TonicWrapperTransport {
    fn authentication(&self) -> RpcAuthentication {
        RpcAuthentication::PinnedMutualTls
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
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        crate::ready_before_dispatch(deadline, async {
            self.grpc
                .ready()
                .await
                .map_err(|_| BridgeError::BeforeDispatch)
        })
        .await?;
        let mut request = tonic::Request::new(RawFrame(request));
        request.extensions_mut().insert(tonic::GrpcMethod::new(
            "pb.Wrapper",
            method
                .path()
                .rsplit('/')
                .next()
                .ok_or(BridgeError::BeforeDispatch)?,
        ));
        let path = tonic::codegen::http::uri::PathAndQuery::from_static(method.path());
        let codec = RawCodec {
            maximum_response_bytes: self.maximum_response_bytes,
        };
        request.set_timeout(crate::remaining_before_dispatch(deadline)?);
        let response = self
            .grpc
            .unary(request, path, codec)
            .await
            .map_err(|_| BridgeError::OutcomeUnknown)?;
        if Instant::now() >= deadline {
            return Err(BridgeError::OutcomeUnknown);
        }
        Ok(response.into_inner().0)
    }
}

pub(crate) struct RawFrame(pub(crate) Zeroizing<Vec<u8>>);
impl fmt::Debug for RawFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawFrame([REDACTED])")
    }
}
#[derive(Debug)]
pub(crate) struct RawCodec {
    pub(crate) maximum_response_bytes: usize,
}
#[derive(Debug)]
pub(crate) struct RawEncoder;
#[derive(Debug)]
pub(crate) struct RawDecoder {
    pub(crate) maximum_response_bytes: usize,
}
impl Codec for RawCodec {
    type Encode = RawFrame;
    type Decode = RawFrame;
    type Encoder = RawEncoder;
    type Decoder = RawDecoder;
    fn encoder(&mut self) -> Self::Encoder {
        RawEncoder
    }
    fn decoder(&mut self) -> Self::Decoder {
        RawDecoder {
            maximum_response_bytes: self.maximum_response_bytes,
        }
    }
}
impl Encoder for RawEncoder {
    type Item = RawFrame;
    type Error = tonic::Status;
    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        dst.put_slice(item.0.as_slice());
        Ok(())
    }
}
impl Decoder for RawDecoder {
    type Item = RawFrame;
    type Error = tonic::Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        if src.remaining() > self.maximum_response_bytes {
            return Err(tonic::Status::resource_exhausted(
                "plugin response exceeds limit",
            ));
        }
        let mut bytes = Zeroizing::new(vec![0; src.remaining()]);
        src.copy_to_slice(bytes.as_mut_slice());
        Ok(Some(RawFrame(bytes)))
    }
}
