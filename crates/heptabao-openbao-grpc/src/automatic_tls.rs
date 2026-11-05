//! Independently written compatibility module for the reviewed HashiCorp
//! go-plugin v1.8.0 AutoMTLS launch contract. Protocol provenance is recorded in
//! docs/compatibility/HEPTABAO_HASHICORP_AUTOMTLS_V180_CONTRACT.md. No OpenBao
//! implementation source or SDK function translation is used here.
//!
//! This is separate from the explicit Tonic/rustls TLS constructor. Each
//! connection uses standard AWS-LC X.509 verification and the single certificate
//! from this owned launch. No verification callback, default trust roots,
//! plaintext IO, or endpoint reconnection is available through this module.

use std::fmt;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use hyper_util::rt::TokioIo;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::ssl::{
    Ssl, SslContextBuilder, SslMethod, SslOptions, SslSessionCacheMode, SslVerifyMode, SslVersion,
};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509CheckFlags, X509VerifyFlags};
use openssl::x509::{X509, X509NameBuilder, X509PurposeId, X509VerifyResult};
use tokio::net::UnixStream;
use tokio_openssl::SslStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;
use zeroize::Zeroizing;

use crate::handshake::LocalEndpoint;
use crate::transport::{RawCodec, RawFrame};
use crate::{
    BridgeError, IdentityProbe, OwnedPluginIdentity, RpcAuthentication, RpcLimits, WrapperMethod,
    WrapperRpcTransport,
};

const MAX_HANDSHAKE: usize = 4096;
const PEER_NAME: &str = "localhost";

/// An endpoint and a certificate observed together from the exact child's
/// startup stdout. Parsing does not authenticate either value.
pub struct AutomaticHandshake {
    endpoint: LocalEndpoint,
    server_certificate: X509,
    server_der: Vec<u8>,
}

impl fmt::Debug for AutomaticHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AutomaticHandshake([REDACTED])")
    }
}

impl AutomaticHandshake {
    pub fn parse(line: &[u8], private_socket_directory: &Path) -> Result<Self, BridgeError> {
        if line.len() > MAX_HANDSHAKE || !line.ends_with(b"\n") {
            return Err(BridgeError::InvalidHandshake);
        }
        let body = std::str::from_utf8(&line[..line.len() - 1])
            .map_err(|_| BridgeError::InvalidHandshake)?;
        if body.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(BridgeError::InvalidHandshake);
        }
        let fields: Vec<_> = body.split('|').collect();
        if fields.len() != 6 || fields[0] != "1" || fields[1] != "1" || fields[4] != "grpc" {
            return Err(BridgeError::InvalidHandshake);
        }
        let endpoint = match fields[2] {
            "unix" => {
                let path = PathBuf::from(fields[3]);
                if !absolute_path(&path) || path.parent() != Some(private_socket_directory) {
                    return Err(BridgeError::InvalidHandshake);
                }
                LocalEndpoint::Unix(path)
            }
            "tcp" => {
                let address: SocketAddr = fields[3]
                    .parse()
                    .map_err(|_| BridgeError::InvalidHandshake)?;
                if !address.ip().is_loopback() || address.port() == 0 {
                    return Err(BridgeError::InvalidHandshake);
                }
                LocalEndpoint::Tcp(address)
            }
            _ => return Err(BridgeError::InvalidHandshake),
        };
        if !absolute_path(private_socket_directory)
            || fields[5].is_empty()
            || fields[5].contains('=')
        {
            return Err(BridgeError::InvalidHandshake);
        }
        let server_der = STANDARD_NO_PAD
            .decode(fields[5])
            .map_err(|_| BridgeError::InvalidHandshake)?;
        if STANDARD_NO_PAD.encode(&server_der) != fields[5] {
            return Err(BridgeError::InvalidHandshake);
        }
        let server_certificate =
            X509::from_der(&server_der).map_err(|_| BridgeError::InvalidHandshake)?;
        if server_certificate
            .to_der()
            .map_err(|_| BridgeError::InvalidHandshake)?
            != server_der
        {
            return Err(BridgeError::InvalidHandshake);
        }
        let key = server_certificate
            .public_key()
            .map_err(|_| BridgeError::InvalidHandshake)?;
        // This exact pinned SDK generates a P-521 self-signed certificate. An
        // unexpected key/profile is not accepted as another launch protocol.
        if key
            .ec_key()
            .map_err(|_| BridgeError::InvalidHandshake)?
            .group()
            .curve_name()
            != Some(Nid::SECP521R1)
            || server_certificate
                .subject_name()
                .to_der()
                .map_err(|_| BridgeError::InvalidHandshake)?
                != server_certificate
                    .issuer_name()
                    .to_der()
                    .map_err(|_| BridgeError::InvalidHandshake)?
            || !server_certificate
                .verify(&key)
                .map_err(|_| BridgeError::InvalidHandshake)?
        {
            return Err(BridgeError::InvalidHandshake);
        }
        Ok(Self {
            endpoint,
            server_certificate,
            server_der,
        })
    }
}

fn absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 1024
        && path.file_name().is_some()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

/// The native key remains in maintained owned PKey storage. Only the public
/// certificate is exposed for the launch environment; Debug never prints it.
pub struct PerLaunchClientIdentity {
    certificate: X509,
    private_key: PKey<Private>,
    certificate_pem: String,
}

impl fmt::Debug for PerLaunchClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PerLaunchClientIdentity([REDACTED])")
    }
}

impl PerLaunchClientIdentity {
    pub fn generate() -> Result<Self, BridgeError> {
        let result = (|| -> Result<Self, openssl::error::ErrorStack> {
            let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
            let private_key = PKey::from_ec_key(EcKey::generate(&group)?)?;
            let mut name = X509NameBuilder::new()?;
            name.append_entry_by_nid(Nid::COMMONNAME, PEER_NAME)?;
            name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "HeptaBao")?;
            let name = name.build();
            let mut serial = [0; 16];
            rand_bytes(&mut serial)?;
            // X.509 serials are positive. No private key is serialized here.
            if serial == [0; 16] {
                serial[15] = 1;
            }
            let serial = BigNum::from_slice(&serial)?.to_asn1_integer()?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| openssl::error::ErrorStack::get())?
                .as_secs();
            let before = Asn1Time::from_unix(
                i64::try_from(now.saturating_sub(30))
                    .map_err(|_| openssl::error::ErrorStack::get())?,
            )?;
            let after = Asn1Time::from_unix(
                i64::try_from(
                    now.checked_add(262_980 * 3600)
                        .ok_or_else(openssl::error::ErrorStack::get)?,
                )
                .map_err(|_| openssl::error::ErrorStack::get())?,
            )?;
            let mut certificate = X509::builder()?;
            certificate.set_version(2)?;
            certificate.set_serial_number(&serial)?;
            certificate.set_subject_name(&name)?;
            certificate.set_issuer_name(&name)?;
            certificate.set_pubkey(&private_key)?;
            certificate.set_not_before(&before)?;
            certificate.set_not_after(&after)?;
            certificate.append_extension(BasicConstraints::new().critical().ca().build()?)?;
            certificate.append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .key_encipherment()
                    .key_agreement()
                    .key_cert_sign()
                    .build()?,
            )?;
            certificate.append_extension(
                ExtendedKeyUsage::new()
                    .client_auth()
                    .server_auth()
                    .build()?,
            )?;
            let san = SubjectAlternativeName::new()
                .dns(PEER_NAME)
                .build(&certificate.x509v3_context(None, None))?;
            certificate.append_extension(san)?;
            certificate.sign(&private_key, MessageDigest::sha512())?;
            let certificate = certificate.build();
            let certificate_pem = String::from_utf8(certificate.to_pem()?)
                .map_err(|_| openssl::error::ErrorStack::get())?;
            Ok(Self {
                certificate,
                private_key,
                certificate_pem,
            })
        })();
        result.map_err(|_| BridgeError::InvalidBinding)
    }

    pub fn public_certificate_pem(&self) -> &str {
        &self.certificate_pem
    }
}

#[derive(Eq, PartialEq)]
struct SocketStamp {
    directory: (u64, u64, u32, u32, i64, i64),
    socket: (u64, u64, u32, u32, i64, i64, i64, i64),
}

fn socket_stamp(path: &Path, uid: u32) -> Result<SocketStamp, BridgeError> {
    let parent = path.parent().ok_or(BridgeError::InvalidBinding)?;
    let directory = std::fs::symlink_metadata(parent).map_err(|_| BridgeError::InvalidBinding)?;
    if !directory.is_dir()
        || directory.file_type().is_symlink()
        || directory.uid() != uid
        || directory.mode() & 0o7777 != 0o700
    {
        return Err(BridgeError::InvalidBinding);
    }
    let socket = std::fs::symlink_metadata(path).map_err(|_| BridgeError::BeforeDispatch)?;
    if !socket.file_type().is_socket() || socket.uid() != uid || socket.nlink() != 1 {
        return Err(BridgeError::InvalidBinding);
    }
    Ok(SocketStamp {
        directory: (
            directory.dev(),
            directory.ino(),
            directory.uid(),
            directory.mode(),
            directory.ctime(),
            directory.ctime_nsec(),
        ),
        socket: (
            socket.dev(),
            socket.ino(),
            socket.uid(),
            socket.mode(),
            socket.ctime(),
            socket.ctime_nsec(),
            socket.mtime(),
            socket.mtime_nsec(),
        ),
    })
}

/// One authenticated Unix connection. The connector can supply its stream once;
/// all later acquisition attempts fail without connecting to any endpoint.
pub struct AutomaticWrapperTransport {
    grpc: tonic::client::Grpc<Channel>,
    maximum_response_bytes: usize,
    identity: OwnedPluginIdentity,
    generation: u64,
}

impl fmt::Debug for AutomaticWrapperTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AutomaticWrapperTransport([REDACTED])")
    }
}

impl AutomaticWrapperTransport {
    pub async fn connect_after_owned_launch<P: IdentityProbe>(
        identity: &OwnedPluginIdentity,
        probe: &P,
        handshake: AutomaticHandshake,
        client: PerLaunchClientIdentity,
        limits: RpcLimits,
        deadline: Instant,
    ) -> Result<Self, BridgeError> {
        identity.validate()?;
        let limits = limits.validate()?;
        let (before, lifecycle) = probe.observe()?;
        if &before != identity {
            return Err(BridgeError::IdentityChanged);
        }
        if !lifecycle.sealed || lifecycle.configuration_generation == 0 {
            return Err(BridgeError::LifecycleDenied);
        }
        let LocalEndpoint::Unix(path) = handshake.endpoint else {
            return Err(BridgeError::BeforeDispatch);
        };
        let stamp = socket_stamp(&path, identity.uid)?;
        let prepare_ssl = (|| -> Result<Ssl, openssl::error::ErrorStack> {
            let mut store = X509StoreBuilder::new()?;
            store.add_cert(handshake.server_certificate)?;
            store.set_flags(X509VerifyFlags::CHECK_SS_SIGNATURE)?;
            store.set_purpose(X509PurposeId::SSL_SERVER)?;
            let mut context = SslContextBuilder::new(SslMethod::tls_client())?;
            context.set_cert_store(store.build());
            context.set_verify(SslVerifyMode::PEER);
            context.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            context.set_session_cache_mode(SslSessionCacheMode::OFF);
            context.set_options(SslOptions::NO_TICKET);
            context.set_alpn_protos(b"\x02h2")?;
            context.set_certificate(&client.certificate)?;
            context.set_private_key(&client.private_key)?;
            context.check_private_key()?;
            let mut ssl = Ssl::new(&context.build())?;
            ssl.set_hostname(PEER_NAME)?;
            ssl.param_mut().set_hostflags(X509CheckFlags::NO_WILDCARDS);
            ssl.param_mut().set_host(PEER_NAME)?;
            ssl.param_mut().set_purpose(X509PurposeId::SSL_SERVER)?;
            Ok(ssl)
        })();
        let ssl = prepare_ssl.map_err(|_| BridgeError::InvalidBinding)?;
        let connect = async {
            let socket = UnixStream::connect(&path)
                .await
                .map_err(|_| BridgeError::BeforeDispatch)?;
            let mut stream =
                SslStream::new(ssl, socket).map_err(|_| BridgeError::BeforeDispatch)?;
            Pin::new(&mut stream)
                .connect()
                .await
                .map_err(|_| BridgeError::UnauthenticatedTransport)?;
            if stream.ssl().verify_result() != X509VerifyResult::OK
                || stream.ssl().selected_alpn_protocol() != Some(b"h2".as_slice())
                || stream
                    .ssl()
                    .peer_certificate()
                    .ok_or(BridgeError::UnauthenticatedTransport)?
                    .to_der()
                    .map_err(|_| BridgeError::UnauthenticatedTransport)?
                    != handshake.server_der
            {
                return Err(BridgeError::UnauthenticatedTransport);
            }
            if socket_stamp(&path, identity.uid)? != stamp {
                return Err(BridgeError::IdentityChanged);
            }
            let (after, after_lifecycle) = probe.observe()?;
            if &after != identity {
                return Err(BridgeError::IdentityChanged);
            }
            if after_lifecycle != lifecycle {
                return Err(BridgeError::LifecycleDenied);
            }
            let stream = Arc::new(Mutex::new(Some(stream)));
            let connector = service_fn(move |_| {
                let result = stream
                    .lock()
                    .ok()
                    .and_then(|mut stream| stream.take())
                    .map(TokioIo::new)
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotConnected));
                std::future::ready(result)
            });
            // IO is already verified TLS. This logical URI carries no network
            // authority: only the single-use connector above supplies IO.
            let endpoint = Endpoint::from_static("http://localhost")
                .connect_timeout(deadline.saturating_duration_since(Instant::now()));
            endpoint
                .connect_with_connector(connector)
                .await
                .map_err(|_| BridgeError::BeforeDispatch)
        };
        let channel =
            tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), connect)
                .await
                .map_err(|_| BridgeError::BeforeDispatch)??;
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
    /// The SDK health service is checked only on the already authenticated
    /// channel. Its payload is public and supplies no launch authority.
    pub async fn authenticated_health_check(
        &mut self,
        deadline: Instant,
    ) -> Result<(), BridgeError> {
        #[derive(prost::Message)]
        struct HealthRequest {
            #[prost(string, tag = "1")]
            service: String,
        }
        #[derive(prost::Message)]
        struct HealthResponse {
            #[prost(int32, tag = "1")]
            status: i32,
        }
        use prost::Message;
        crate::remaining_before_dispatch(deadline)?;
        let future = async {
            crate::ready_before_dispatch(deadline, async {
                self.grpc
                    .ready()
                    .await
                    .map_err(|_| BridgeError::BeforeDispatch)
            })
            .await?;
            let mut request = tonic::Request::new(RawFrame(Zeroizing::new(
                HealthRequest {
                    service: "plugin".to_owned(),
                }
                .encode_to_vec(),
            )));
            let path = tonic::codegen::http::uri::PathAndQuery::from_static(
                "/grpc.health.v1.Health/Check",
            );
            request.set_timeout(crate::remaining_before_dispatch(deadline)?);
            let response = self
                .grpc
                .unary(
                    request,
                    path,
                    RawCodec {
                        maximum_response_bytes: 1024,
                    },
                )
                .await
                .map_err(|_| BridgeError::OutcomeUnknown)?;
            if Instant::now() >= deadline {
                return Err(BridgeError::OutcomeUnknown);
            }
            let result = HealthResponse::decode(response.into_inner().0.as_slice())
                .map_err(|_| BridgeError::InvalidResponse)?;
            if result.status != 1 {
                return Err(BridgeError::InvalidResponse);
            }
            Ok(())
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
            .await
            .map_err(|_| BridgeError::OutcomeUnknown)?
    }
}

impl WrapperRpcTransport for AutomaticWrapperTransport {
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
        let path = tonic::codegen::http::uri::PathAndQuery::from_static(method.path());
        request.set_timeout(crate::remaining_before_dispatch(deadline)?);
        let response = self
            .grpc
            .unary(
                request,
                path,
                RawCodec {
                    maximum_response_bytes: self.maximum_response_bytes,
                },
            )
            .await
            .map_err(|_| BridgeError::OutcomeUnknown)?;
        if Instant::now() >= deadline {
            return Err(BridgeError::OutcomeUnknown);
        }
        Ok(response.into_inner().0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::stack::Stack;
    use openssl::x509::X509StoreContext;

    fn wire(certificate: &X509, endpoint: &str) -> Result<Vec<u8>, BridgeError> {
        let der = certificate
            .to_der()
            .map_err(|_| BridgeError::InvalidBinding)?;
        Ok(format!("1|1|unix|{endpoint}|grpc|{}\n", STANDARD_NO_PAD.encode(der)).into_bytes())
    }

    #[test]
    fn automatic_handshake_has_one_literal_six_field_certificate_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = PerLaunchClientIdentity::generate()?;
        let directory = Path::new("/owned/private-socket");
        let line = wire(&client.certificate, "/owned/private-socket/plugin.sock")?;
        let parsed = AutomaticHandshake::parse(&line, directory)?;
        assert_eq!(parsed.server_der, client.certificate.to_der()?);
        assert_eq!(
            parsed.endpoint,
            LocalEndpoint::Unix(directory.join("plugin.sock"))
        );
        for malformed in [
            line[..line.len() - 1].to_vec(),
            b"1|1|unix|/owned/private-socket/plugin.sock|grpc\n".to_vec(),
            b"1|2|unix|/owned/private-socket/plugin.sock|grpc|x\n".to_vec(),
            b"1|1|unix|/owned/private-socket/plugin.sock|netrpc|x\n".to_vec(),
            wire(&client.certificate, "/other/private-socket/plugin.sock")?,
            wire(&client.certificate, "/owned/private-socket/../plugin.sock")?,
        ] {
            assert!(matches!(
                AutomaticHandshake::parse(&malformed, directory),
                Err(BridgeError::InvalidHandshake)
            ));
        }
        let mut padded = line.clone();
        padded.insert(padded.len() - 1, b'=');
        assert!(AutomaticHandshake::parse(&padded, directory).is_err());
        let mut extra = line.clone();
        extra.splice(extra.len() - 1..extra.len() - 1, b"|false".iter().copied());
        assert!(AutomaticHandshake::parse(&extra, directory).is_err());
        let mut suffix = client.certificate.to_der()?;
        suffix.push(0);
        let suffix = format!(
            "1|1|unix|/owned/private-socket/plugin.sock|grpc|{}\n",
            STANDARD_NO_PAD.encode(suffix)
        );
        assert!(AutomaticHandshake::parse(suffix.as_bytes(), directory).is_err());
        let mut corrupted = client.certificate.to_der()?;
        let last = corrupted.last_mut().ok_or("empty DER")?;
        *last ^= 1;
        let corrupted = format!(
            "1|1|unix|/owned/private-socket/plugin.sock|grpc|{}\n",
            STANDARD_NO_PAD.encode(corrupted)
        );
        assert!(AutomaticHandshake::parse(corrupted.as_bytes(), directory).is_err());
        Ok(())
    }

    #[test]
    fn per_launch_public_environment_contains_no_private_key_and_names_are_verified()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = PerLaunchClientIdentity::generate()?;
        let second = PerLaunchClientIdentity::generate()?;
        assert!(
            first
                .public_certificate_pem()
                .starts_with("-----BEGIN CERTIFICATE-----\n")
        );
        assert!(!first.public_certificate_pem().contains("PRIVATE KEY"));
        assert_ne!(first.certificate.to_der()?, second.certificate.to_der()?);
        assert!(
            first
                .certificate
                .public_key()?
                .public_eq(&first.private_key)
        );
        assert!(
            !first
                .certificate
                .public_key()?
                .public_eq(&second.private_key)
        );
        let mut roots = X509StoreBuilder::new()?;
        roots.add_cert(first.certificate.clone())?;
        roots.set_flags(X509VerifyFlags::CHECK_SS_SIGNATURE)?;
        roots.set_purpose(X509PurposeId::SSL_SERVER)?;
        let mut parameters = openssl::x509::verify::X509VerifyParam::new()?;
        parameters.set_host(PEER_NAME)?;
        roots.set_param(&parameters)?;
        let roots = roots.build();
        let chain = Stack::new()?;
        let mut context = X509StoreContext::new()?;
        assert!(context.init(&roots, &first.certificate, &chain, |context| {
            context.verify_cert()
        })?);
        let mut wrong_roots = X509StoreBuilder::new()?;
        wrong_roots.add_cert(first.certificate.clone())?;
        let mut parameters = openssl::x509::verify::X509VerifyParam::new()?;
        parameters.set_host("another-host.invalid")?;
        parameters.set_purpose(X509PurposeId::SSL_SERVER)?;
        wrong_roots.set_param(&parameters)?;
        let wrong_roots = wrong_roots.build();
        assert!(
            !context.init(&wrong_roots, &first.certificate, &chain, |context| context
                .verify_cert())?
        );
        let mut unrelated = X509StoreBuilder::new()?;
        unrelated.add_cert(second.certificate.clone())?;
        let unrelated = unrelated.build();
        assert!(
            !context.init(&unrelated, &first.certificate, &chain, |context| context
                .verify_cert())?
        );
        let mut expired = X509StoreBuilder::new()?;
        expired.add_cert(first.certificate.clone())?;
        let mut parameters = openssl::x509::verify::X509VerifyParam::new()?;
        parameters.set_host(PEER_NAME)?;
        parameters.set_purpose(X509PurposeId::SSL_SERVER)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        parameters.set_time((now + 262_980 * 3600 + 3600).try_into()?);
        expired.set_param(&parameters)?;
        let expired = expired.build();
        assert!(
            !context.init(&expired, &first.certificate, &chain, |context| context
                .verify_cert())?
        );
        Ok(())
    }
}
