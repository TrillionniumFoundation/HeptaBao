//! Deployment-owned, address-pinned TLS egress. Remote metadata never adds an
//! origin, changes a CA, follows a redirect, invokes DNS, or widens a path scope.
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(crate) const MAX_DOCUMENT: usize = 128 * 1024;
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    pub origin: String,
    pub address: SocketAddr,
    pub server_name: String,
    pub ca_pem: String,
    #[serde(default = "root_prefix")]
    pub path_prefix: String,
}
fn root_prefix() -> String {
    "/".into()
}
#[derive(Clone)]
pub(crate) struct Endpoint {
    address: SocketAddr,
    server_name: String,
    path_prefix: String,
    tls: Arc<ClientConfig>,
}
#[derive(Clone, Default)]
pub(crate) struct Outbound {
    endpoints: BTreeMap<String, Endpoint>,
}

/// Deliberately bounded URL grammar. No userinfo, DNS search, relative URL,
/// redirect, control byte, percent-encoded path separator, query or fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub origin: String,
    pub authority: String,
    pub path: String,
}
impl Target {
    pub fn parse(url: &str, scheme: &str) -> Result<Self, &'static str> {
        if url.len() > 2048
            || !url.is_ascii()
            || url.bytes().any(|c| c <= 32 || c == 127)
            || url.contains(['@', '\\', '#', '?', '%'])
        {
            return Err("invalid outbound URL");
        }
        let rest = url
            .strip_prefix(scheme)
            .and_then(|v| v.strip_prefix("://"))
            .ok_or("outbound URL requires its registered TLS scheme")?;
        let (authority, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or("outbound URL requires an explicit port")?;
        let port: u16 = port.parse().map_err(|_| "invalid outbound port")?;
        if host.is_empty()
            || host.len() > 253
            || port == 0
            || host.starts_with('.')
            || host.ends_with('.')
            || !host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
            || host
                .split('.')
                .any(|s| s.is_empty() || s.starts_with('-') || s.ends_with('-'))
        {
            return Err("invalid canonical outbound authority");
        }
        let path = format!("/{tail}");
        if tail.split('/').any(|p| p == "." || p == "..") || path.contains("//") {
            return Err("invalid outbound path");
        }
        Ok(Self {
            origin: format!("{scheme}://{host}:{port}"),
            authority: authority.into(),
            path,
        })
    }
}
impl Outbound {
    pub fn new(configs: Vec<EndpointConfig>) -> Result<Self, &'static str> {
        if configs.len() > 16 {
            return Err("too many outbound endpoints");
        }
        let mut endpoints = BTreeMap::new();
        for config in configs {
            let scheme = if config.origin.starts_with("postgresql://") {
                "postgresql"
            } else {
                "https"
            };
            let target = Target::parse(&config.origin, scheme)?;
            if target.origin != config.origin
                || config.server_name != target.authority.split(':').next().unwrap_or("")
                || config.address.port() == 0
                || config.address.port()
                    != target
                        .authority
                        .rsplit(':')
                        .next()
                        .unwrap_or("")
                        .parse::<u16>()
                        .unwrap_or(0)
                || config.ca_pem.is_empty()
                || config.ca_pem.len() > 64 * 1024
                || !config.path_prefix.starts_with('/')
                || !config.path_prefix.ends_with('/')
            {
                return Err("invalid outbound enrollment");
            }
            Target::parse(&format!("{}{}", config.origin, config.path_prefix), scheme)?;
            let mut roots = RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut config.ca_pem.as_bytes()) {
                roots
                    .add(cert.map_err(|_| "invalid outbound CA")?)
                    .map_err(|_| "invalid outbound CA")?;
            }
            if roots.is_empty() {
                return Err("empty outbound CA set");
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut tls = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|_| "invalid TLS profile")?
                .with_root_certificates(roots)
                .with_no_client_auth();
            // SCRAM without channel binding never resumes an old TLS session.
            tls.resumption = rustls::client::Resumption::disabled();
            let endpoint = Endpoint {
                address: config.address,
                server_name: config.server_name,
                path_prefix: config.path_prefix,
                tls: Arc::new(tls),
            };
            if endpoints.insert(target.origin, endpoint).is_some() {
                return Err("duplicate outbound origin");
            }
        }
        Ok(Self { endpoints })
    }
    pub fn endpoint(&self, url: &str, scheme: &str) -> Result<(Endpoint, Target), &'static str> {
        let target = Target::parse(url, scheme)?;
        let endpoint = self
            .endpoints
            .get(&target.origin)
            .ok_or("outbound origin is not host-enrolled")?;
        if !target.path.starts_with(&endpoint.path_prefix) {
            return Err("outbound path is not host-enrolled");
        }
        Ok((endpoint.clone(), target))
    }
    pub fn get_json(&self, url: &str) -> Result<Value, &'static str> {
        let (endpoint, target) = self.endpoint(url, "https")?;
        let mut stream = endpoint.tls(endpoint.connect()?)?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json, application/jwk-set+json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            target.path, target.authority
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|_| "outbound HTTP write failed")?;
        stream.flush().map_err(|_| "outbound TLS flush failed")?;
        read_json_response(&mut stream)
    }
}
impl Endpoint {
    pub fn connect(&self) -> Result<DeadlineSocket, &'static str> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(3))
            .map_err(|_| "outbound connection unavailable")?;
        stream
            .set_nodelay(true)
            .map_err(|_| "outbound socket setup failed")?;
        Ok(DeadlineSocket { stream, deadline })
    }
    pub fn tls(&self, socket: DeadlineSocket) -> Result<TlsStream, &'static str> {
        let name =
            ServerName::try_from(self.server_name.clone()).map_err(|_| "invalid TLS name")?;
        let connection = ClientConnection::new(self.tls.clone(), name)
            .map_err(|_| "cannot create outbound TLS session")?;
        let mut stream = StreamOwned::new(connection, socket);
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|_| "outbound TLS identity validation failed")?;
        }
        Ok(stream)
    }
}
pub(crate) type TlsStream = StreamOwned<ClientConnection, DeadlineSocket>;
pub(crate) struct DeadlineSocket {
    stream: TcpStream,
    deadline: Instant,
}
impl DeadlineSocket {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "absolute egress deadline exceeded")
            })
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}
fn line(stream: &mut impl Read, budget: &mut usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    loop {
        if *budget == 0 {
            return Err("outbound HTTP headers exceed bound");
        }
        *budget -= 1;
        let mut b = [0];
        stream
            .read_exact(&mut b)
            .map_err(|_| "truncated outbound HTTP framing")?;
        bytes.push(b[0]);
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return Ok(bytes);
        }
        if b[0] == b'\n' {
            return Err("outbound HTTP framing requires CRLF");
        }
    }
}
fn read_json_response(stream: &mut impl Read) -> Result<Value, &'static str> {
    let mut budget = 16 * 1024;
    let status = line(stream, &mut budget)?;
    let status = std::str::from_utf8(&status).map_err(|_| "invalid outbound HTTP status")?;
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        return Err("outbound HTTP status is not 200; redirects forbidden");
    }
    let mut headers = BTreeMap::new();
    loop {
        let l = line(stream, &mut budget)?;
        if l.is_empty() {
            break;
        }
        let l = std::str::from_utf8(&l).map_err(|_| "invalid outbound HTTP header")?;
        let (k, v) = l.split_once(':').ok_or("invalid outbound HTTP header")?;
        if k.is_empty()
            || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || v.bytes().any(|b| b < 32 && b != 9 || b == 127)
        {
            return Err("invalid outbound HTTP header");
        }
        if headers
            .insert(k.to_ascii_lowercase(), v.trim().to_owned())
            .is_some()
        {
            return Err("duplicate outbound HTTP header");
        }
    }
    let content_type = headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("");
    if !matches!(
        content_type,
        "application/json" | "application/jwk-set+json"
    ) || headers
        .get("content-encoding")
        .is_some_and(|v| v != "identity")
    {
        return Err("outbound JSON content type or encoding rejected");
    }
    let mut body = Zeroizing::new(Vec::new());
    match (
        headers.get("content-length"),
        headers.get("transfer-encoding"),
    ) {
        (Some(_), Some(_)) => return Err("ambiguous outbound HTTP length"),
        (Some(length), None) => {
            if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid outbound body length");
            }
            let n: usize = length.parse().map_err(|_| "invalid outbound body length")?;
            if n > MAX_DOCUMENT {
                return Err("outbound document exceeds bound");
            }
            body.resize(n, 0);
            stream
                .read_exact(&mut body)
                .map_err(|_| "truncated outbound document")?;
        }
        (None, Some(encoding)) if encoding == "chunked" => loop {
            let length = line(stream, &mut budget)?;
            if length.is_empty() || length.len() > 8 || !length.iter().all(u8::is_ascii_hexdigit) {
                return Err("invalid outbound chunk size");
            }
            let n = usize::from_str_radix(
                std::str::from_utf8(&length).map_err(|_| "invalid chunk")?,
                16,
            )
            .map_err(|_| "invalid chunk")?;
            if n == 0 {
                if !line(stream, &mut budget)?.is_empty() {
                    return Err("outbound trailers not supported");
                }
                break;
            }
            if n > MAX_DOCUMENT - body.len() {
                return Err("outbound document exceeds bound");
            }
            let start = body.len();
            body.resize(start + n, 0);
            stream
                .read_exact(&mut body[start..])
                .map_err(|_| "truncated chunk")?;
            if !line(stream, &mut budget)?.is_empty() {
                return Err("invalid chunk terminator");
            }
        },
        (None, None) => {
            stream
                .take((MAX_DOCUMENT + 1) as u64)
                .read_to_end(&mut body)
                .map_err(|_| "outbound document read failed")?;
            if body.len() > MAX_DOCUMENT {
                return Err("outbound document exceeds bound");
            }
        }
        _ => return Err("unsupported outbound transfer encoding"),
    }
    // The same duplicate-key rejecting parser used by the public HTTP boundary.
    crate::auth::parse_strict_json(&body).map_err(|_| "invalid or ambiguous outbound JSON")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn egress_never_accepts_ambiguous_or_unenrolled_destinations() {
        for url in [
            "http://issuer:443/",
            "https://user@issuer:443/",
            "https://issuer/",
            "https://Issuer:443/",
            "https://issuer:443/%2fsecret",
            "https://issuer:443/../private",
            "https://issuer:443//private",
            "https://issuer:443/a?next=b",
            "https://issuer:443/a#b",
        ] {
            assert!(Target::parse(url, "https").is_err());
        }
        assert!(
            Outbound::default()
                .get_json("https://issuer:443/jwks")
                .is_err()
        );
    }
    #[test]
    fn egress_framing_rejects_redirects_duplicates_oversize_and_private_json_shapes() {
        for msg in [
            "HTTP/1.1 302 Found\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"a\":1,\"a\":2}",
        ] {
            assert!(read_json_response(&mut msg.as_bytes()).is_err());
        }
    }
    #[test]
    fn egress_bounded_chunked_json_is_supported() -> Result<(), &'static str> {
        let raw=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(read_json_response(&mut &raw[..])?, serde_json::json!({}));
        Ok(())
    }
}
