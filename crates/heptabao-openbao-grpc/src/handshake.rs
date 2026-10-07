//! Public SDK launcher contract. Automatic mTLS wire exchange is not implemented.

use std::net::SocketAddr;
use std::path::{Component, PathBuf};

use crate::BridgeError;

/// A public launcher cookie is intent detection, never transport authentication.
pub const KMS_MAGIC_COOKIE_KEY: &str = "OPENBAO_KMS_PLUGIN";
pub const KMS_MAGIC_COOKIE_VALUE: &str = "39704a18-7da7-4bda-9a2d-f7c488d70328";
pub const KMS_APPLICATION_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    HeptaBaoHbp1,
    OpenBaoGrpcWrapper,
}

#[derive(Clone, Eq, PartialEq)]
pub enum LocalEndpoint {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl std::fmt::Debug for LocalEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalEndpoint([REDACTED])")
    }
}

/// Only the five fields documented by go-plugin v1.8.0's non-Go guide.
/// This does not assert that an endpoint is owned or authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicHandshake {
    endpoint: LocalEndpoint,
}

impl PublicHandshake {
    pub fn parse(line: &[u8]) -> Result<Self, BridgeError> {
        if line.is_empty() || line.len() > 4096 {
            return Err(BridgeError::InvalidHandshake);
        }
        let raw = std::str::from_utf8(line).map_err(|_| BridgeError::InvalidHandshake)?;
        let raw = raw.strip_suffix('\n').unwrap_or(raw);
        if raw.bytes().any(|b| b.is_ascii_control()) {
            return Err(BridgeError::InvalidHandshake);
        }
        let fields: Vec<_> = raw.split('|').collect();
        if fields.len() > 5 {
            // Do not guess an extension or silently accept an unauthenticated peer.
            return Err(BridgeError::AutoMtlsWireContractUnavailable);
        }
        if fields.len() != 5 || fields[0] != "1" || fields[1] != "1" || fields[4] != "grpc" {
            return Err(BridgeError::InvalidHandshake);
        }
        let endpoint = match fields[2] {
            "tcp" => {
                let address: SocketAddr = fields[3]
                    .parse()
                    .map_err(|_| BridgeError::InvalidHandshake)?;
                if !address.ip().is_loopback() || address.port() == 0 {
                    return Err(BridgeError::InvalidHandshake);
                }
                LocalEndpoint::Tcp(address)
            }
            "unix" => {
                let path = PathBuf::from(fields[3]);
                if !path.is_absolute()
                    || path.as_os_str().len() > 1024
                    || path
                        .components()
                        .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
                {
                    return Err(BridgeError::InvalidHandshake);
                }
                LocalEndpoint::Unix(path)
            }
            _ => return Err(BridgeError::InvalidHandshake),
        };
        Ok(Self { endpoint })
    }

    pub fn endpoint(&self) -> &LocalEndpoint {
        &self.endpoint
    }

    /// No process is spawned. A five-field line is insufficient for AutoMTLS.
    pub fn automatic_launch_admission(&self) -> Result<(), BridgeError> {
        Err(BridgeError::AutoMtlsWireContractUnavailable)
    }
}
