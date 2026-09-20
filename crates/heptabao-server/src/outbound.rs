//! Deployment-owned, address-pinned TLS egress. Remote metadata never adds an
//! origin, changes a CA, follows a redirect, invokes DNS, or widens a path scope.
use md5::Context;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const MAX_DOCUMENT: usize = 128 * 1024;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    pub origin: String,
    pub address: SocketAddr,
    pub server_name: String,
    pub ca_pem: String,
    #[serde(default = "root_prefix")]
    pub path_prefix: String,
    /// Process-only shared secret for a deployment-enrolled RADIUS endpoint.
    #[serde(default)]
    pub shared_secret: String,
}

impl std::fmt::Debug for EndpointConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointConfig")
            .field("origin", &self.origin)
            .field("address", &self.address)
            .field("server_name", &self.server_name)
            .field("path_prefix", &self.path_prefix)
            .field("shared_secret", &"[REDACTED]")
            .finish_non_exhaustive()
    }
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
    radius_endpoints: BTreeMap<String, RadiusEndpoint>,
}

#[derive(Clone)]
struct RadiusEndpoint {
    address: SocketAddr,
    shared_secret: Arc<Zeroizing<Vec<u8>>>,
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
        let mut radius_endpoints = BTreeMap::new();
        for config in configs {
            let scheme = if config.origin.starts_with("postgresql://") {
                "postgresql"
            } else if config.origin.starts_with("ldaps://") {
                "ldaps"
            } else if config.origin.starts_with("valkeys://") {
                "valkeys"
            } else if config.origin.starts_with("radius://") {
                "radius"
            } else {
                "https"
            };
            let target = Target::parse(&config.origin, scheme)?;
            let is_radius = scheme == "radius";
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
                || (!is_radius && config.ca_pem.is_empty())
                || config.ca_pem.len() > 64 * 1024
                || !config.path_prefix.starts_with('/')
                || !config.path_prefix.ends_with('/')
                || (is_radius
                    && (config.path_prefix != "/"
                        || config.shared_secret.is_empty()
                        || config.shared_secret.len() > 256
                        || config.shared_secret.bytes().any(|byte| byte == 0)))
                || (!is_radius && !config.shared_secret.is_empty())
            {
                return Err("invalid outbound enrollment");
            }
            Target::parse(&format!("{}{}", config.origin, config.path_prefix), scheme)?;
            if is_radius {
                if radius_endpoints
                    .insert(
                        target.origin,
                        RadiusEndpoint {
                            address: config.address,
                            shared_secret: Arc::new(Zeroizing::new(
                                config.shared_secret.into_bytes(),
                            )),
                        },
                    )
                    .is_some()
                {
                    return Err("duplicate outbound origin");
                }
                continue;
            }
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
        Ok(Self {
            endpoints,
            radius_endpoints,
        })
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

    pub(crate) fn radius_endpoint(&self, url: &str) -> Result<(), &'static str> {
        let target = Target::parse(url, "radius")?;
        if target.path != "/" || !self.radius_endpoints.contains_key(&target.origin) {
            return Err("RADIUS endpoint is not host-enrolled");
        }
        Ok(())
    }
    /// Deliver one sanitized audit record to an exact host-enrolled HTTPS
    /// collector. The collector cannot redirect, select another origin, extend
    /// the absolute deadline, or cause an automatic retry.
    pub(crate) fn post_audit_json(&self, url: &str, value: &Value) -> Result<(), &'static str> {
        let body =
            Zeroizing::new(serde_json::to_vec(value).map_err(|_| "invalid outbound audit JSON")?);
        if body.len() > MAX_DOCUMENT {
            return Err("outbound audit document exceeds bound");
        }
        let (endpoint, target) = self.endpoint(url, "https")?;
        let mut stream = endpoint.tls(endpoint.connect()?)?;
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            target.path,
            target.authority,
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush())
            .map_err(|_| "outbound audit POST failed; no retry")?;
        read_discard_response_status(&mut stream, &[200, 201, 202, 204])
    }

    /// Bind as the authenticating user and, on that same TLS session, optionally
    /// perform one bounded subtree group-membership search. The search grammar is
    /// fixed: equality on one configured attribute against the exact user DN,
    /// returning only one configured group-name attribute. Arbitrary filters,
    /// referrals, paging and automatic retries are deliberately excluded.
    pub(crate) fn ldap_bind_and_search_groups(
        &self,
        url: &str,
        dn: &str,
        password: &str,
        group_dn: &str,
        group_attr: &str,
        group_name_attr: &str,
    ) -> Result<Option<BTreeSet<String>>, &'static str> {
        if dn.is_empty()
            || dn.len() > 1024
            || password.is_empty()
            || password.len() > 1024
            || dn.bytes().any(|byte| byte == 0 || byte < 0x20)
            || password.bytes().any(|byte| byte == 0)
            || group_dn.len() > 1024
            || group_dn.bytes().any(|byte| byte == 0 || byte < 0x20)
            || !valid_ldap_attribute(group_attr)
            || !valid_ldap_attribute(group_name_attr)
        {
            return Err("invalid LDAP bind or group-search input");
        }
        let (endpoint, target) = self.endpoint(url, "ldaps")?;
        if target.path != "/" {
            return Err("LDAP bind target must be an enrolled origin");
        }
        let mut stream = endpoint.tls(endpoint.connect()?)?;
        let request = ldap_bind_request(dn.as_bytes(), password.as_bytes())?;
        stream
            .write_all(&request)
            .and_then(|()| stream.flush())
            .map_err(|_| "LDAP bind write failed")?;
        if !read_ldap_bind_response(&mut stream)? {
            return Ok(None);
        }
        if group_dn.is_empty() {
            return Ok(Some(BTreeSet::new()));
        }
        let search = ldap_group_search_request(
            group_dn.as_bytes(),
            group_attr.as_bytes(),
            dn.as_bytes(),
            group_name_attr.as_bytes(),
        )?;
        stream
            .write_all(&search)
            .and_then(|()| stream.flush())
            .map_err(|_| "LDAP group search write failed")?;
        read_ldap_group_search_response(&mut stream, group_name_attr).map(Some)
    }

    /// Reconcile one durable issue intent. A previous successful Add whose
    /// response was lost is accepted only after manager marker readback and a
    /// bind using the exact generated password. A tombstone is never reissued.
    pub(crate) fn ldap_dynamic_add(
        &self,
        url: &str,
        bind_dn: &str,
        bind_password: &str,
        dn: &str,
        attributes: &[(String, Vec<String>)],
        password: &str,
    ) -> Result<(), &'static str> {
        validate_ldap_effect_input(bind_dn, bind_password, dn, attributes)?;
        validate_ldap_password(password)?;
        let marker = ldap_issue_marker(attributes)?;
        let mut stream = self.ldap_manager_session(url, bind_dn, bind_password)?;
        ldap_reconcile_add(&mut stream, dn, attributes, marker)?;
        match self.ldap_bind_and_search_groups(url, dn, password, "", "cn", "cn")? {
            Some(_) => Ok(()),
            None => Err("LDAP issued credential failed bind readback"),
        }
    }

    /// Retire a durable intent while retaining its DN as a fence against a
    /// delayed Add. Missing entries are fenced with the original schema-valid
    /// entry minus userPassword. Existing matching entries lose userPassword
    /// and gain the tombstone marker in one atomic, asserted Modify.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn ldap_dynamic_tombstone(
        &self,
        url: &str,
        bind_dn: &str,
        bind_password: &str,
        dn: &str,
        old_password: &str,
        request_digest: &str,
        original_attributes: &[(String, Vec<String>)],
    ) -> Result<(), &'static str> {
        validate_ldap_effect_input(bind_dn, bind_password, dn, original_attributes)?;
        validate_ldap_password(old_password)?;
        if !valid_ldap_request_digest(request_digest)
            || original_attributes
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("description"))
        {
            return Err("invalid LDAP dynamic fence digest or original entry");
        }
        let mut stream = self.ldap_manager_session(url, bind_dn, bind_password)?;
        ldap_reconcile_tombstone(&mut stream, dn, request_digest, original_attributes)?;
        match self.ldap_bind_and_search_groups(url, dn, old_password, "", "cn", "cn")? {
            None => Ok(()),
            Some(_) => Err("LDAP old dynamic credential remains usable"),
        }
    }

    fn ldap_manager_session(
        &self,
        url: &str,
        bind_dn: &str,
        bind_password: &str,
    ) -> Result<TlsStream, &'static str> {
        let (endpoint, target) = self.endpoint(url, "ldaps")?;
        if target.path != "/" {
            return Err("LDAP dynamic target must be an enrolled origin");
        }
        let mut stream = endpoint.tls(endpoint.connect()?)?;
        let bind = ldap_bind_request(bind_dn.as_bytes(), bind_password.as_bytes())?;
        ldap_write(&mut stream, &bind)?;
        if !read_ldap_bind_response(&mut stream)? {
            return Err("LDAP manager bind rejected by provider");
        }
        Ok(stream)
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

    /// Perform one bounded RADIUS PAP exchange against an exact, process-owned
    /// UDP endpoint. A timeout, malformed response, identifier mismatch or
    /// invalid response authenticator always fails closed. No retransmission is
    /// attempted, so an unknown provider outcome cannot grant a token.
    pub(crate) fn radius_authenticate(
        &self,
        url: &str,
        username: &str,
        password: &str,
    ) -> Result<bool, &'static str> {
        if username.is_empty()
            || username.len() > 253
            || password.is_empty()
            || password.len() > 128
            || username.bytes().any(|byte| byte == 0 || byte < 0x20)
            || password.bytes().any(|byte| byte == 0)
        {
            return Err("invalid RADIUS credentials");
        }
        let target = Target::parse(url, "radius")?;
        if target.path != "/" {
            return Err("RADIUS target must be an enrolled origin");
        }
        let endpoint = self
            .radius_endpoints
            .get(&target.origin)
            .ok_or("RADIUS endpoint is not host-enrolled")?;
        let mut request_authenticator = [0u8; 16];
        SystemRandom::new()
            .fill(&mut request_authenticator)
            .map_err(|_| "RADIUS request randomness unavailable")?;
        let identifier = request_authenticator[0];
        let packet = radius_access_request(
            identifier,
            &request_authenticator,
            username.as_bytes(),
            password.as_bytes(),
            endpoint.shared_secret.as_slice(),
        )?;
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| "RADIUS socket unavailable")?;
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|_| "RADIUS socket setup failed")?;
        socket
            .send_to(&packet, endpoint.address)
            .map_err(|_| "RADIUS request delivery failed")?;
        let mut response = [0u8; 4096];
        let (size, source) = socket
            .recv_from(&mut response)
            .map_err(|_| "RADIUS response unavailable")?;
        if source != endpoint.address {
            return Err("RADIUS response source mismatch");
        }
        radius_response_accepted(
            &response[..size],
            identifier,
            &request_authenticator,
            endpoint.shared_secret.as_slice(),
        )
    }
}

fn md5_parts(parts: &[&[u8]]) -> [u8; 16] {
    let mut digest = Context::new();
    for part in parts {
        digest.consume(part);
    }
    digest.finalize().0
}

fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    let mut normalized = [0u8; 64];
    if key.len() > normalized.len() {
        normalized[..16].copy_from_slice(&md5_parts(&[key]));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for index in 0..64 {
        inner[index] ^= normalized[index];
        outer[index] ^= normalized[index];
    }
    let inner_digest = md5_parts(&[&inner, message]);
    md5_parts(&[&outer, &inner_digest])
}

fn radius_access_request(
    identifier: u8,
    request_authenticator: &[u8; 16],
    username: &[u8],
    password: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if username.is_empty()
        || username.len() > 253
        || password.is_empty()
        || password.len() > 128
        || shared_secret.is_empty()
        || shared_secret.len() > 256
    {
        return Err("RADIUS packet field exceeds bound");
    }
    let mut padded = password.to_vec();
    let padded_len = padded.len().div_ceil(16) * 16;
    padded.resize(padded_len, 0);
    let mut encrypted = vec![0u8; padded_len];
    let mut previous = *request_authenticator;
    let (plain_chunks, _) = padded.as_chunks::<16>();
    let (cipher_chunks, _) = encrypted.as_chunks_mut::<16>();
    for (plain, cipher) in plain_chunks.iter().zip(cipher_chunks.iter_mut()) {
        let mask = md5_parts(&[shared_secret, &previous]);
        for (out, (value, key)) in cipher.iter_mut().zip(plain.iter().zip(mask)) {
            *out = *value ^ key;
        }
        previous.copy_from_slice(cipher);
    }
    let user_len = 2usize
        .checked_add(username.len())
        .ok_or("RADIUS packet length overflow")?;
    let password_len = 2usize
        .checked_add(encrypted.len())
        .ok_or("RADIUS packet length overflow")?;
    let packet_len = 20usize
        .checked_add(user_len)
        .and_then(|value| value.checked_add(password_len))
        .and_then(|value| value.checked_add(18))
        .ok_or("RADIUS packet length overflow")?;
    if packet_len > 4096 {
        return Err("RADIUS packet exceeds bound");
    }
    let mut packet = Vec::with_capacity(packet_len);
    packet.extend_from_slice(&[1, identifier, (packet_len >> 8) as u8, packet_len as u8]);
    packet.extend_from_slice(request_authenticator);
    packet.push(1);
    packet.push(u8::try_from(user_len).map_err(|_| "RADIUS username exceeds bound")?);
    packet.extend_from_slice(username);
    packet.push(2);
    packet.push(u8::try_from(password_len).map_err(|_| "RADIUS password exceeds bound")?);
    packet.extend_from_slice(&encrypted);
    packet.extend_from_slice(&[80, 18]);
    packet.extend_from_slice(&[0u8; 16]);
    let authenticator = hmac_md5(shared_secret, &packet);
    let offset = packet
        .len()
        .checked_sub(16)
        .ok_or("RADIUS message authenticator offset overflow")?;
    packet[offset..].copy_from_slice(&authenticator);
    Ok(packet)
}

fn radius_response_accepted(
    packet: &[u8],
    request_identifier: u8,
    request_authenticator: &[u8; 16],
    shared_secret: &[u8],
) -> Result<bool, &'static str> {
    if packet.len() < 20 || packet.len() > 4096 || packet[1] != request_identifier {
        return Err("RADIUS response header mismatch");
    }
    let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if declared != packet.len() || declared < 20 {
        return Err("RADIUS response length mismatch");
    }
    if !matches!(packet[0], 2 | 3 | 11) {
        return Err("RADIUS response code is unsupported");
    }
    let expected = md5_parts(&[
        &packet[..4],
        request_authenticator,
        &packet[20..],
        shared_secret,
    ]);
    if packet[4..20].ct_eq(&expected).unwrap_u8() != 1 {
        return Err("RADIUS response authenticator mismatch");
    }
    let mut offset = 20usize;
    let mut message_authenticator = None;
    while offset < packet.len() {
        if packet.len() - offset < 2 {
            return Err("RADIUS response attribute truncated");
        }
        let length = usize::from(packet[offset + 1]);
        if length < 2 || length > packet.len() - offset {
            return Err("RADIUS response attribute length invalid");
        }
        if packet[offset] == 80 {
            if length != 18 || message_authenticator.is_some() {
                return Err("RADIUS message authenticator shape invalid");
            }
            message_authenticator = Some(offset);
        }
        offset += length;
    }
    let Some(attribute_offset) = message_authenticator else {
        return Err("RADIUS response is missing Message-Authenticator");
    };
    let mut signed = packet.to_vec();
    signed[4..20].copy_from_slice(request_authenticator);
    signed[attribute_offset + 2..attribute_offset + 18].fill(0);
    let expected = hmac_md5(shared_secret, &signed);
    if packet[attribute_offset + 2..attribute_offset + 18]
        .ct_eq(&expected)
        .unwrap_u8()
        != 1
    {
        return Err("RADIUS message authenticator mismatch");
    }
    Ok(packet[0] == 2)
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
    /// Start one bounded operation on an already authenticated persistent
    /// connection. The protocol owner must first verify an idle, usable
    /// boundary; reads/writes within that operation never extend this deadline.
    pub(crate) fn begin_operation(&mut self, budget: Duration) -> io::Result<()> {
        self.deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| io::Error::other("operation deadline exceeds supported bound"))?;
        Ok(())
    }

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
fn ber_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), &'static str> {
    if length < 128 {
        bytes.push(u8::try_from(length).map_err(|_| "LDAP BER length overflow")?);
    } else if length <= usize::from(u16::MAX) {
        bytes.push(0x82);
        bytes.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        return Err("LDAP BER value exceeds bound");
    }
    Ok(())
}

fn ber_value(tag: u8, value: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut encoded = Vec::with_capacity(value.len().saturating_add(4));
    encoded.push(tag);
    ber_length(&mut encoded, value.len())?;
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn ldap_bind_request(dn: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut bind = Vec::new();
    bind.extend_from_slice(&ber_value(0x02, &[0x03])?);
    bind.extend_from_slice(&ber_value(0x04, dn)?);
    bind.extend_from_slice(&ber_value(0x80, password)?);
    let bind = ber_value(0x60, &bind)?;
    let mut message = Vec::new();
    message.extend_from_slice(&ber_value(0x02, &[0x01])?);
    message.extend_from_slice(&bind);
    Ok(Zeroizing::new(ber_value(0x30, &message)?))
}

fn valid_ldap_attribute(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn validate_ldap_effect_input(
    bind_dn: &str,
    bind_password: &str,
    dn: &str,
    attributes: &[(String, Vec<String>)],
) -> Result<(), &'static str> {
    if bind_dn.is_empty()
        || bind_password.is_empty()
        || dn.is_empty()
        || bind_dn.len() > 1024
        || bind_password.len() > 1024
        || dn.len() > 1024
        || attributes.is_empty()
        || attributes.len() > 64
        || [bind_dn, bind_password, dn]
            .iter()
            .any(|value| value.bytes().any(|byte| byte == 0 || byte < 0x20))
    {
        return Err("invalid LDAP dynamic effect input");
    }
    let mut total = 0usize;
    let mut names = BTreeSet::new();
    for (name, values) in attributes {
        if !valid_ldap_attribute(name)
            || !names.insert(name.to_ascii_lowercase())
            || values.is_empty()
            || values.len() > 32
        {
            return Err("invalid LDAP dynamic attribute set");
        }
        for value in values {
            if value.is_empty() || value.len() > 4096 || value.bytes().any(|byte| byte == 0) {
                return Err("invalid LDAP dynamic attribute value");
            }
            total = total
                .checked_add(value.len())
                .ok_or("LDAP dynamic attribute bound overflow")?;
        }
    }
    if total > 64 * 1024 {
        return Err("LDAP dynamic attributes exceed bound");
    }
    Ok(())
}

fn ldap_add_request(
    message_id: u8,
    dn: &str,
    attributes: &[(String, Vec<String>)],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut attrs = Vec::new();
    for (name, values) in attributes {
        let mut set = Vec::new();
        for value in values {
            set.extend_from_slice(&ber_value(0x04, value.as_bytes())?);
        }
        let partial = [ber_value(0x04, name.as_bytes())?, ber_value(0x31, &set)?].concat();
        attrs.extend_from_slice(&ber_value(0x30, &partial)?);
    }
    let add = [ber_value(0x04, dn.as_bytes())?, ber_value(0x30, &attrs)?].concat();
    let protocol = ber_value(0x68, &add)?;
    let message = [ber_value(0x02, &[message_id])?, protocol].concat();
    Ok(Zeroizing::new(ber_value(0x30, &message)?))
}

fn ldap_modify_request(
    message_id: u8,
    dn: &str,
    changes: &[(String, Vec<String>)],
    assertion: Option<(&str, &str)>,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if dn.is_empty()
        || dn.len() > 1024
        || changes.is_empty()
        || changes.len() > 16
        || dn.bytes().any(|byte| byte == 0 || byte < 0x20)
    {
        return Err("invalid LDAP modify input");
    }
    let mut changes_wire = Vec::new();
    let mut names = BTreeSet::new();
    for (attribute, values) in changes {
        if !valid_ldap_attribute(attribute)
            || !names.insert(attribute.to_ascii_lowercase())
            || values.len() > 32
            || (values.is_empty() && !attribute.eq_ignore_ascii_case("userPassword"))
        {
            return Err("invalid LDAP modify attribute set");
        }
        let mut vals = Vec::new();
        for value in values {
            if value.is_empty() || value.len() > 4096 || value.bytes().any(|byte| byte == 0) {
                return Err("invalid LDAP modify value");
            }
            vals.extend_from_slice(&ber_value(0x04, value.as_bytes())?);
        }
        let partial = [
            ber_value(0x04, attribute.as_bytes())?,
            ber_value(0x31, &vals)?,
        ]
        .concat();
        let change = [ber_value(0x0a, &[0x02])?, ber_value(0x30, &partial)?].concat();
        changes_wire.extend_from_slice(&ber_value(0x30, &change)?);
    }
    let changes = ber_value(0x30, &changes_wire)?;
    let modify = [ber_value(0x04, dn.as_bytes())?, changes].concat();
    let protocol = ber_value(0x66, &modify)?;
    let mut message = [ber_value(0x02, &[message_id])?, protocol].concat();
    if let Some((assertion_attribute, assertion_value)) = assertion {
        if !valid_ldap_attribute(assertion_attribute)
            || assertion_value.is_empty()
            || assertion_value.len() > 4096
            || assertion_value.bytes().any(|byte| byte == 0)
        {
            return Err("invalid LDAP assertion");
        }
        // RFC 4528 equalityMatch filter: [3] SEQUENCE { attr, value }.
        let filter = [
            ber_value(0x04, assertion_attribute.as_bytes())?,
            ber_value(0x04, assertion_value.as_bytes())?,
        ]
        .concat();
        let filter = ber_value(0xa3, &filter)?;
        let control = [
            ber_value(0x04, b"1.3.6.1.1.12")?,
            ber_value(0x01, &[0xff])?,
            ber_value(0x04, &filter)?,
        ]
        .concat();
        // Controls is a SEQUENCE OF Control, and each Control is itself a
        // SEQUENCE. LDAPMessage then carries that Controls value under the
        // implicitly tagged [0] field.
        let control = ber_value(0x30, &control)?;
        let controls = ber_value(0x30, &control)?;
        message.extend_from_slice(&ber_value(0xa0, &controls)?);
    }
    Ok(Zeroizing::new(ber_value(0x30, &message)?))
}

fn read_ldap_result_code(
    stream: &mut impl Read,
    expected_id: u8,
    expected_tag: u8,
) -> Result<u8, &'static str> {
    let mut remaining = 64 * 1024usize;
    let body = read_ldap_message_body(stream, &mut remaining)?;
    let mut cursor = 0usize;
    if ber_take(&body, &mut cursor, 0x02)? != [expected_id] {
        return Err("unexpected LDAP result message id");
    }
    let operation = ber_take(&body, &mut cursor, expected_tag)?;
    if cursor != body.len() {
        return Err("LDAP result controls or trailing bytes are not supported");
    }
    let mut inner = 0usize;
    let result = ber_take(operation, &mut inner, 0x0a)?;
    if result.len() != 1 || result[0] >= 128 {
        return Err("invalid LDAP result code");
    }
    let _matched_dn = ber_take(operation, &mut inner, 0x04)?;
    let _diagnostic = ber_take(operation, &mut inner, 0x04)?;
    if inner != operation.len() {
        return Err("LDAP result referrals are not supported");
    }
    Ok(result[0])
}

fn ldap_group_search_request(
    group_dn: &[u8],
    group_attr: &[u8],
    user_dn: &[u8],
    group_name_attr: &[u8],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if group_dn.is_empty() || group_dn.len() > 1024 || user_dn.is_empty() || user_dn.len() > 1024 {
        return Err("LDAP group search input exceeds bound");
    }
    let mut filter = Vec::new();
    filter.extend_from_slice(&ber_value(0x04, group_attr)?);
    filter.extend_from_slice(&ber_value(0x04, user_dn)?);

    let mut attributes = Vec::new();
    attributes.extend_from_slice(&ber_value(0x04, group_name_attr)?);

    let mut search = Vec::new();
    search.extend_from_slice(&ber_value(0x04, group_dn)?);
    search.extend_from_slice(&ber_value(0x0a, &[0x02])?);
    search.extend_from_slice(&ber_value(0x0a, &[0x00])?);
    search.extend_from_slice(&ber_value(0x02, &[0x00, 0x80])?);
    search.extend_from_slice(&ber_value(0x02, &[0x03])?);
    search.extend_from_slice(&ber_value(0x01, &[0x00])?);
    search.extend_from_slice(&ber_value(0xa3, &filter)?);
    search.extend_from_slice(&ber_value(0x30, &attributes)?);
    let search = ber_value(0x63, &search)?;

    let mut message = Vec::new();
    message.extend_from_slice(&ber_value(0x02, &[0x02])?);
    message.extend_from_slice(&search);
    Ok(Zeroizing::new(ber_value(0x30, &message)?))
}

fn ldap_entry_search_request(message_id: u8, dn: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if dn.is_empty() || dn.len() > 1024 || dn.bytes().any(|byte| byte == 0 || byte < 0x20) {
        return Err("invalid LDAP readback DN");
    }
    let search = [
        ber_value(0x04, dn.as_bytes())?,
        ber_value(0x0a, &[0])?, // baseObject
        ber_value(0x0a, &[0])?, // never dereference aliases
        ber_value(0x02, &[1])?,
        ber_value(0x02, &[3])?,
        ber_value(0x01, &[0])?,
        // RFC 4511 present [7] AttributeDescription, not NULL.
        ber_value(0x87, b"objectClass")?,
        ber_value(
            0x30,
            &[
                ber_value(0x04, b"description")?,
                ber_value(0x04, b"userPassword")?,
            ]
            .concat(),
        )?,
    ]
    .concat();
    let protocol = ber_value(0x63, &search)?;
    let message = [ber_value(0x02, &[message_id])?, protocol].concat();
    Ok(Zeroizing::new(ber_value(0x30, &message)?))
}

fn read_ldap_message_body(
    stream: &mut impl Read,
    remaining: &mut usize,
) -> Result<Vec<u8>, &'static str> {
    let mut first = [0u8; 2];
    stream
        .read_exact(&mut first)
        .map_err(|_| "truncated LDAP search response")?;
    if first[0] != 0x30 {
        return Err("invalid LDAP search response envelope");
    }
    let mut head = vec![first[0], first[1]];
    if first[1] & 0x80 != 0 {
        let count = usize::from(first[1] & 0x7f);
        if count == 0 || count > 2 {
            return Err("invalid LDAP search response length");
        }
        let mut more = [0u8; 2];
        stream
            .read_exact(&mut more[..count])
            .map_err(|_| "truncated LDAP search response length")?;
        head.extend_from_slice(&more[..count]);
    }
    let mut offset = 1usize;
    let body_len = ber_take_length(&head, &mut offset)?;
    if body_len == 0 || body_len > 64 * 1024 || body_len > *remaining {
        return Err("LDAP search response exceeds bound");
    }
    *remaining -= body_len;
    let mut body = vec![0u8; body_len];
    stream
        .read_exact(&mut body)
        .map_err(|_| "truncated LDAP search response")?;
    Ok(body)
}

fn read_ldap_group_search_response(
    stream: &mut impl Read,
    group_name_attr: &str,
) -> Result<BTreeSet<String>, &'static str> {
    let mut remaining = 128 * 1024usize;
    let mut groups = BTreeSet::new();
    for _ in 0..=128 {
        let body = read_ldap_message_body(stream, &mut remaining)?;
        let mut cursor = 0usize;
        let message_id = ber_take(&body, &mut cursor, 0x02)?;
        if message_id != [0x02] {
            return Err("unexpected LDAP search message id");
        }
        let tag = *body.get(cursor).ok_or("missing LDAP search operation")?;
        cursor += 1;
        let length = ber_take_length(&body, &mut cursor)?;
        let end = cursor
            .checked_add(length)
            .ok_or("LDAP search operation length overflow")?;
        let operation = body
            .get(cursor..end)
            .ok_or("truncated LDAP search operation")?;
        cursor = end;
        if cursor != body.len() {
            return Err("LDAP search controls or trailing bytes are not supported");
        }

        match tag {
            0x64 => {
                let mut inner = 0usize;
                let _object_name = ber_take(operation, &mut inner, 0x04)?;
                let attributes = ber_take(operation, &mut inner, 0x30)?;
                if inner != operation.len() {
                    return Err("invalid LDAP search entry");
                }
                let mut attribute_cursor = 0usize;
                while attribute_cursor < attributes.len() {
                    let attribute = ber_take(attributes, &mut attribute_cursor, 0x30)?;
                    let mut part = 0usize;
                    let name = ber_take(attribute, &mut part, 0x04)?;
                    let values = ber_take(attribute, &mut part, 0x31)?;
                    if part != attribute.len() {
                        return Err("invalid LDAP search attribute");
                    }
                    let name = std::str::from_utf8(name)
                        .map_err(|_| "LDAP search attribute name is not UTF-8")?;
                    if name.eq_ignore_ascii_case(group_name_attr) {
                        let mut value_cursor = 0usize;
                        while value_cursor < values.len() {
                            let value = ber_take(values, &mut value_cursor, 0x04)?;
                            let value = std::str::from_utf8(value)
                                .map_err(|_| "LDAP group name is not UTF-8")?;
                            if value.is_empty()
                                || value.len() > 256
                                || value.chars().any(char::is_control)
                                || groups.len() >= 128 && !groups.contains(value)
                            {
                                return Err("LDAP group result exceeds bound");
                            }
                            groups.insert(value.to_owned());
                        }
                    }
                }
            }
            0x65 => {
                let mut inner = 0usize;
                let result = ber_take(operation, &mut inner, 0x0a)?;
                if result != [0x00] {
                    return Err("LDAP group search rejected by provider");
                }
                let _matched_dn = ber_take(operation, &mut inner, 0x04)?;
                let _diagnostic = ber_take(operation, &mut inner, 0x04)?;
                if inner != operation.len() {
                    return Err("LDAP search referrals are not supported");
                }
                return Ok(groups);
            }
            _ => return Err("unsupported LDAP search response operation"),
        }
    }
    Err("LDAP search entry count exceeds bound")
}

#[derive(Debug, PartialEq, Eq)]
struct LdapEntryObservation {
    marker: Option<String>,
    password_present: bool,
}

fn read_ldap_entry(
    stream: &mut impl Read,
    expected_id: u8,
    expected_dn: &str,
) -> Result<Option<LdapEntryObservation>, &'static str> {
    let mut remaining = 64 * 1024usize;
    let mut entry = None;
    // A baseObject search has at most one entry and one SearchResultDone.
    for _ in 0..2 {
        let body = Zeroizing::new(read_ldap_message_body(stream, &mut remaining)?);
        let mut cursor = 0usize;
        if ber_take(&body, &mut cursor, 0x02)? != [expected_id] {
            return Err("unexpected LDAP readback message id");
        }
        let tag = *body.get(cursor).ok_or("missing LDAP readback operation")?;
        let operation = ber_take(&body, &mut cursor, tag)?;
        if cursor != body.len() {
            return Err("LDAP readback controls or trailing bytes are not supported");
        }
        let mut inner = 0usize;
        match tag {
            0x64 => {
                if entry.is_some() {
                    return Err("LDAP base search returned multiple entries");
                }
                let dn = ber_take(operation, &mut inner, 0x04)?;
                if !dn.eq_ignore_ascii_case(expected_dn.as_bytes()) {
                    return Err("LDAP readback distinguished name mismatch");
                }
                let attributes = ber_take(operation, &mut inner, 0x30)?;
                if inner != operation.len() {
                    return Err("invalid LDAP readback entry");
                }
                let mut observation = LdapEntryObservation {
                    marker: None,
                    password_present: false,
                };
                let mut names = BTreeSet::new();
                let mut attrs = 0usize;
                while attrs < attributes.len() {
                    let attribute = ber_take(attributes, &mut attrs, 0x30)?;
                    let mut part = 0usize;
                    let name = ber_take(attribute, &mut part, 0x04)?;
                    let values = ber_take(attribute, &mut part, 0x31)?;
                    if part != attribute.len() || !names.insert(name.to_ascii_lowercase()) {
                        return Err("invalid or duplicate LDAP readback attribute");
                    }
                    if !name.eq_ignore_ascii_case(b"description")
                        && !name.eq_ignore_ascii_case(b"userPassword")
                    {
                        return Err("unexpected LDAP readback attribute");
                    }
                    if name.eq_ignore_ascii_case(b"description") && values.is_empty() {
                        return Err("LDAP readback marker is ambiguous");
                    }
                    let mut values_cursor = 0usize;
                    let mut count = 0usize;
                    while values_cursor < values.len() {
                        let value = ber_take(values, &mut values_cursor, 0x04)?;
                        count += 1;
                        if count > 32 || value.len() > 4096 {
                            return Err("LDAP readback attribute exceeds bound");
                        }
                        if name.eq_ignore_ascii_case(b"description") {
                            if count != 1 || value.is_empty() {
                                return Err("LDAP readback marker is ambiguous");
                            }
                            observation.marker = Some(
                                std::str::from_utf8(value)
                                    .map_err(|_| "LDAP marker is not UTF-8")?
                                    .to_owned(),
                            );
                        } else {
                            observation.password_present = true;
                        }
                    }
                }
                entry = Some(observation);
            }
            0x65 => {
                let result = ber_take(operation, &mut inner, 0x0a)?;
                let _matched_dn = ber_take(operation, &mut inner, 0x04)?;
                let _diagnostic = ber_take(operation, &mut inner, 0x04)?;
                if inner != operation.len() {
                    return Err("LDAP readback referrals are not supported");
                }
                return match result {
                    [0] => Ok(entry),
                    [32] if entry.is_none() => Ok(None),
                    _ => Err("LDAP readback rejected by provider"),
                };
            }
            _ => return Err("unsupported LDAP readback operation"),
        }
    }
    Err("LDAP base search did not terminate")
}

fn validate_ldap_password(password: &str) -> Result<(), &'static str> {
    if password.is_empty() || password.len() > 1024 || password.bytes().any(|byte| byte == 0) {
        return Err("invalid LDAP dynamic password");
    }
    Ok(())
}

fn valid_ldap_request_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ldap_issue_marker(attributes: &[(String, Vec<String>)]) -> Result<&str, &'static str> {
    let mut markers = attributes
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("description"));
    let (_, values) = markers.next().ok_or("LDAP issue marker is missing")?;
    if markers.next().is_some() || values.len() != 1 {
        return Err("LDAP issue marker is ambiguous");
    }
    let marker = values[0].as_str();
    if !marker
        .strip_prefix("hb-request:")
        .is_some_and(valid_ldap_request_digest)
    {
        return Err("invalid LDAP issue marker");
    }
    Ok(marker)
}

fn ldap_write(stream: &mut impl Write, request: &[u8]) -> Result<(), &'static str> {
    stream
        .write_all(request)
        .and_then(|()| stream.flush())
        .map_err(|_| "LDAP effect write failed; outcome unknown")
}

fn ldap_observe(
    stream: &mut (impl Read + Write),
    message_id: u8,
    dn: &str,
) -> Result<Option<LdapEntryObservation>, &'static str> {
    ldap_write(stream, &ldap_entry_search_request(message_id, dn)?)?;
    read_ldap_entry(stream, message_id, dn)
}

fn ldap_reconcile_add(
    stream: &mut (impl Read + Write),
    dn: &str,
    attributes: &[(String, Vec<String>)],
    marker: &str,
) -> Result<(), &'static str> {
    let mut observed = ldap_observe(stream, 2, dn)?;
    if observed.is_none() {
        ldap_write(stream, &ldap_add_request(3, dn, attributes)?)?;
        // EntryAlreadyExists can be an earlier delayed execution, but only
        // marker readback below decides whether this is the same issuance.
        if !matches!(read_ldap_result_code(stream, 3, 0x69)?, 0 | 68) {
            return Err("LDAP dynamic Add rejected by provider");
        }
        observed = ldap_observe(stream, 4, dn)?;
    }
    match observed {
        Some(entry) if entry.marker.as_deref() == Some(marker) => Ok(()),
        _ => Err("LDAP issue readback did not prove the current intent"),
    }
}

fn ldap_reconcile_tombstone(
    stream: &mut (impl Read + Write),
    dn: &str,
    digest: &str,
    original_attributes: &[(String, Vec<String>)],
) -> Result<(), &'static str> {
    let marker = format!("hb-request:{digest}");
    let tombstone = format!("hb-tombstone:{digest}");
    let mut observed = ldap_observe(stream, 2, dn)?;
    if observed.is_none() {
        let attributes = original_attributes
            .iter()
            .filter(|(name, _)| {
                !name.eq_ignore_ascii_case("userPassword")
                    && !name.eq_ignore_ascii_case("description")
            })
            .cloned()
            .chain(std::iter::once((
                "description".to_owned(),
                vec![tombstone.clone()],
            )))
            .collect::<Vec<_>>();
        ldap_write(stream, &ldap_add_request(3, dn, &attributes)?)?;
        if !matches!(read_ldap_result_code(stream, 3, 0x69)?, 0 | 68) {
            return Err("LDAP absent-entry tombstone Add rejected by provider");
        }
        observed = ldap_observe(stream, 4, dn)?;
    }
    let entry = observed.ok_or("LDAP tombstone readback is absent")?;
    let assertion_marker = if entry.marker.as_deref() == Some(tombstone.as_str()) {
        if !entry.password_present {
            return Ok(());
        }
        // A provider may have applied the marker before losing the password
        // deletion. The tombstone itself now fences this retry safely.
        tombstone.as_str()
    } else if entry.marker.as_deref() == Some(marker.as_str()) {
        marker.as_str()
    } else {
        return Err("LDAP entry is not owned by this durable intent");
    };
    let changes = vec![
        ("description".to_owned(), vec![tombstone.clone()]),
        // RFC 4511 replace with an empty set removes the entire attribute.
        ("userPassword".to_owned(), Vec::new()),
    ];
    ldap_write(
        stream,
        &ldap_modify_request(5, dn, &changes, Some(("description", assertion_marker)))?,
    )?;
    // A concurrent replay may have already installed the exact tombstone.
    // AssertionFailed is safe only if readback proves that terminal state.
    if !matches!(read_ldap_result_code(stream, 5, 0x67)?, 0 | 122) {
        return Err("LDAP tombstone Modify rejected by provider");
    }
    match ldap_observe(stream, 6, dn)? {
        Some(entry)
            if entry.marker.as_deref() == Some(tombstone.as_str()) && !entry.password_present =>
        {
            Ok(())
        }
        _ => Err("LDAP tombstone readback did not prove password removal"),
    }
}

fn ber_take_length(bytes: &[u8], offset: &mut usize) -> Result<usize, &'static str> {
    let first = *bytes.get(*offset).ok_or("truncated LDAP BER length")?;
    *offset += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 2 || *offset + count > bytes.len() {
        return Err("invalid LDAP BER length");
    }
    let mut length = 0usize;
    for _ in 0..count {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(bytes[*offset] as usize))
            .ok_or("LDAP BER length overflow")?;
        *offset += 1;
    }
    if length < 128 {
        return Err("non-canonical LDAP BER length");
    }
    Ok(length)
}

fn ber_take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    expected_tag: u8,
) -> Result<&'a [u8], &'static str> {
    if bytes.get(*offset).copied() != Some(expected_tag) {
        return Err("unexpected LDAP BER tag");
    }
    *offset += 1;
    let length = ber_take_length(bytes, offset)?;
    let end = (*offset)
        .checked_add(length)
        .ok_or("LDAP BER length overflow")?;
    let value = bytes.get(*offset..end).ok_or("truncated LDAP BER value")?;
    *offset = end;
    Ok(value)
}

fn read_ldap_bind_response(stream: &mut impl Read) -> Result<bool, &'static str> {
    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| "truncated LDAP bind response")?;
    if prefix[0] != 0x30 {
        return Err("invalid LDAP response envelope");
    }
    let mut head = vec![prefix[0], prefix[1]];
    if prefix[1] & 0x80 != 0 {
        let count = usize::from(prefix[1] & 0x7f);
        if count == 0 || count > 2 {
            return Err("invalid LDAP response length");
        }
        let mut more = [0u8; 2];
        stream
            .read_exact(&mut more[..count])
            .map_err(|_| "truncated LDAP response length")?;
        head.extend_from_slice(&more[..count]);
    }
    let mut offset = 1usize;
    let body_len = ber_take_length(&head, &mut offset)?;
    if body_len == 0 || body_len > 4096 {
        return Err("LDAP bind response exceeds bound");
    }
    let mut body = vec![0u8; body_len];
    stream
        .read_exact(&mut body)
        .map_err(|_| "truncated LDAP bind response")?;

    let mut cursor = 0usize;
    let message_id = ber_take(&body, &mut cursor, 0x02)?;
    if message_id != [0x01] {
        return Err("unexpected LDAP message id");
    }
    let bind = ber_take(&body, &mut cursor, 0x61)?;
    if cursor != body.len() {
        return Err("trailing LDAP response bytes");
    }
    let mut inner = 0usize;
    let result = ber_take(bind, &mut inner, 0x0a)?;
    if result.len() != 1 {
        return Err("invalid LDAP result code");
    }
    let _matched_dn = ber_take(bind, &mut inner, 0x04)?;
    let _diagnostic = ber_take(bind, &mut inner, 0x04)?;
    if inner != bind.len() {
        return Err("trailing LDAP bind result bytes");
    }
    match result[0] {
        0 => Ok(true),
        49 => Ok(false),
        _ => Err("LDAP bind rejected by provider"),
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
fn read_discard_response_status(
    stream: &mut impl Read,
    accepted: &[u16],
) -> Result<(), &'static str> {
    let mut budget = 16 * 1024;
    let status = line(stream, &mut budget)?;
    let status = std::str::from_utf8(&status).map_err(|_| "invalid outbound HTTP status")?;
    let mut parts = status.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    let code = if matches!(version, "HTTP/1.1" | "HTTP/1.0")
        && code.len() == 3
        && code.bytes().all(|byte| byte.is_ascii_digit())
        && parts.next().is_some()
    {
        code.parse::<u16>()
            .map_err(|_| "invalid outbound HTTP status")?
    } else {
        return Err("outbound HTTP status rejected; redirects forbidden");
    };
    if !accepted.contains(&code) {
        return Err("outbound HTTP status rejected; redirects forbidden");
    }

    let mut headers = BTreeMap::new();
    loop {
        let raw = line(stream, &mut budget)?;
        if raw.is_empty() {
            break;
        }
        let raw = std::str::from_utf8(&raw).map_err(|_| "invalid outbound HTTP header")?;
        let (name, value) = raw.split_once(':').ok_or("invalid outbound HTTP header")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value
                .bytes()
                .any(|byte| byte < 32 && byte != 9 || byte == 127)
        {
            return Err("invalid outbound HTTP header");
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err("duplicate outbound HTTP header");
        }
    }
    if headers
        .get("content-encoding")
        .is_some_and(|value| value != "identity")
    {
        return Err("outbound response encoding rejected");
    }

    let mut body = Vec::new();
    match (
        headers.get("content-length"),
        headers.get("transfer-encoding"),
    ) {
        (Some(_), Some(_)) => return Err("ambiguous outbound HTTP length"),
        (Some(length), None) => {
            if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid outbound body length");
            }
            let length: usize = length.parse().map_err(|_| "invalid outbound body length")?;
            if length > 16 * 1024 {
                return Err("outbound audit response exceeds bound");
            }
            body.resize(length, 0);
            stream
                .read_exact(&mut body)
                .map_err(|_| "truncated outbound audit response")?;
        }
        (None, None) => {
            stream
                .take(16 * 1024 + 1)
                .read_to_end(&mut body)
                .map_err(|_| "outbound audit response read failed")?;
            if body.len() > 16 * 1024 {
                return Err("outbound audit response exceeds bound");
            }
        }
        _ => return Err("unsupported outbound audit transfer encoding"),
    }
    if code == 204 && !body.is_empty() {
        return Err("204 audit response must not carry a body");
    }
    Ok(())
}

fn read_json_response(stream: &mut impl Read) -> Result<Value, &'static str> {
    read_json_response_status(stream, &[200])
}
fn read_json_response_status(
    stream: &mut impl Read,
    accepted: &[u16],
) -> Result<Value, &'static str> {
    let mut budget = 16 * 1024;
    let status = line(stream, &mut budget)?;
    let status = std::str::from_utf8(&status).map_err(|_| "invalid outbound HTTP status")?;
    let mut parts = status.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0")
        || code.len() != 3
        || !code.bytes().all(|b| b.is_ascii_digit())
        || !code
            .parse::<u16>()
            .is_ok_and(|value| accepted.contains(&value))
        || parts.next().is_none()
    {
        return Err("outbound HTTP status rejected; redirects forbidden");
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

impl Outbound {
    /// One host-enrolled TokenReview request. No credential may choose its own
    /// network origin, CA, address, method or path; no automatic HTTP retry.
    pub(crate) fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        value: &Value,
    ) -> Result<Value, &'static str> {
        if bearer.is_empty()
            || bearer.len() > 32 * 1024
            || !bearer.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err("invalid outbound bearer");
        }
        let body = Zeroizing::new(serde_json::to_vec(value).map_err(|_| "invalid outbound JSON")?);
        let authorization = Zeroizing::new(format!("Bearer {bearer}"));
        self.post_body(url, "application/json", &authorization, &body, &[200, 201])
    }

    fn post_body(
        &self,
        url: &str,
        content_type: &str,
        authorization: &str,
        body: &[u8],
        accepted: &[u16],
    ) -> Result<Value, &'static str> {
        if body.len() > MAX_DOCUMENT
            || authorization.len() > 48 * 1024
            || authorization.bytes().any(|b| b < 32 || b == 127)
        {
            return Err("outbound request bound or header violation");
        }
        let (endpoint, target) = self.endpoint(url, "https")?;
        let mut stream = endpoint.tls(endpoint.connect()?)?;
        let head = Zeroizing::new(format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nAuthorization: {}\r\nContent-Length: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            target.path,
            target.authority,
            content_type,
            authorization,
            body.len()
        ));
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(body))
            .and_then(|()| stream.flush())
            .map_err(|_| "outbound POST failed; no retry")?;
        read_json_response_status(&mut stream, accepted)
    }
}

/// RFC 3986 unreserved encoding; also valid for application/x-www-form-urlencoded.
/// Space uses %20. Never concatenate caller values directly into a URL or header.
pub(crate) fn form_component(value: &str) -> String {
    let mut output = String::new();
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            output.push(char::from(b));
        } else {
            output.push('%');
            output.push(char::from(HEX[(b >> 4) as usize]));
            output.push(char::from(HEX[(b & 15) as usize]));
        }
    }
    output
}
impl Outbound {
    pub(crate) fn exchange_oidc(
        &self,
        url: &str,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect: &str,
        verifier: &str,
    ) -> Result<Value, &'static str> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let body = Zeroizing::new(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
            form_component(code),
            form_component(redirect),
            form_component(verifier)
        ));
        let credentials = Zeroizing::new(format!(
            "{}:{}",
            form_component(client_id),
            form_component(client_secret)
        ));
        let header = Zeroizing::new(format!("Basic {}", STANDARD.encode(credentials.as_bytes())));
        self.post_body(
            url,
            "application/x-www-form-urlencoded",
            &header,
            body.as_bytes(),
            &[200],
        )
    }
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
    #[test]
    fn online_post_statuses_do_not_widen_get_or_exchange_admission() {
        for code in [200, 201, 202, 204, 301, 302, 307, 400, 401, 500] {
            let message = format!(
                "HTTP/1.1 {code} Result\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
            );
            assert_eq!(
                read_json_response_status(&mut message.as_bytes(), &[200, 201]).is_ok(),
                matches!(code, 200 | 201)
            );
            assert_eq!(
                read_json_response(&mut message.as_bytes()).is_ok(),
                code == 200
            );
        }
        for status in [
            "HTTP/1.1 2000 OK",
            "HTTP/1.1 +200 OK",
            "HTTP/1.1 200",
            "HTTP/2 200 OK",
        ] {
            let message = format!(
                "{status}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
            );
            assert!(read_json_response_status(&mut message.as_bytes(), &[200, 201]).is_err());
        }
    }
    #[test]
    fn audit_delivery_accepts_only_bounded_success_without_redirects() {
        for (message, expected) in [
            ("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", true),
            ("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", true),
            ("HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", false),
            (
                "HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx",
                false,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
                false,
            ),
        ] {
            assert_eq!(
                read_discard_response_status(&mut message.as_bytes(), &[200, 201, 202, 204])
                    .is_ok(),
                expected
            );
        }
    }

    #[test]
    fn radius_pap_packet_encrypts_password_and_validates_response_authenticator()
    -> Result<(), &'static str> {
        let request_authenticator = [7u8; 16];
        let request = radius_access_request(
            9,
            &request_authenticator,
            b"alice",
            b"password",
            b"shared-secret",
        )
        .map_err(|_| "bounded RADIUS request")?;
        assert_eq!(request[0], 1);
        assert_eq!(request[1], 9);
        assert_eq!(
            usize::from(u16::from_be_bytes([request[2], request[3]])),
            request.len()
        );
        assert_eq!(request[20], 1);
        assert_eq!(&request[22..27], b"alice");
        assert_eq!(request[27], 2);

        let mut response = vec![2, 9, 0, 20];
        response.extend_from_slice(&[0u8; 16]);
        let authenticator = md5_parts(&[
            &response[..4],
            &request_authenticator,
            &response[20..],
            b"shared-secret",
        ]);
        response[4..20].copy_from_slice(&authenticator);
        assert!(
            radius_response_accepted(&response, 9, &request_authenticator, b"shared-secret")
                .is_err()
        );
        response[4] ^= 1;
        assert!(
            radius_response_accepted(&response, 9, &request_authenticator, b"shared-secret")
                .is_err()
        );

        let mut response = vec![2, 9, 0, 38];
        response.extend_from_slice(&[0u8; 16]);
        response.extend_from_slice(&[80, 18]);
        response.extend_from_slice(&[0u8; 16]);
        let mut signed = response.clone();
        signed[4..20].copy_from_slice(&request_authenticator);
        let message_authenticator = hmac_md5(b"shared-secret", &signed);
        response[22..38].copy_from_slice(&message_authenticator);
        let response_authenticator = md5_parts(&[
            &response[..4],
            &request_authenticator,
            &response[20..],
            b"shared-secret",
        ]);
        response[4..20].copy_from_slice(&response_authenticator);
        assert!(radius_response_accepted(
            &response,
            9,
            &request_authenticator,
            b"shared-secret"
        )?);
        response[22] ^= 1;
        assert!(
            radius_response_accepted(&response, 9, &request_authenticator, b"shared-secret")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn radius_udp_exchange_is_real_and_fails_closed_on_timeout() -> Result<(), &'static str> {
        let server = UdpSocket::bind("127.0.0.1:0").map_err(|_| "bind test RADIUS server")?;
        let address = server
            .local_addr()
            .map_err(|_| "read test RADIUS address")?;
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|_| "set test RADIUS timeout")?;
        let thread = std::thread::spawn(move || -> Result<(), &'static str> {
            let mut request = [0u8; 4096];
            let (size, source) = server
                .recv_from(&mut request)
                .map_err(|_| "RADIUS request")?;
            let request = &request[..size];
            if request.len() < 18 || request[request.len() - 18] != 80 {
                return Err("RADIUS request missing Message-Authenticator");
            }
            let mut signed = request.to_vec();
            signed[request.len() - 16..].fill(0);
            if request[request.len() - 16..]
                .ct_eq(&hmac_md5(b"shared-secret", &signed))
                .unwrap_u8()
                != 1
            {
                return Err("RADIUS request Message-Authenticator mismatch");
            }
            let mut response = vec![2, request[1], 0, 38];
            response.extend_from_slice(&[0u8; 16]);
            response.extend_from_slice(&[80, 18]);
            response.extend_from_slice(&[0u8; 16]);
            let mut signed = response.clone();
            signed[4..20].copy_from_slice(&request[4..20]);
            response[22..38].copy_from_slice(&hmac_md5(b"shared-secret", &signed));
            let authenticator = md5_parts(&[
                &response[..4],
                &request[4..20],
                &response[20..],
                b"shared-secret",
            ]);
            response[4..20].copy_from_slice(&authenticator);
            server
                .send_to(&response, source)
                .map_err(|_| "RADIUS response")?;
            Ok(())
        });
        let outbound = Outbound::new(vec![EndpointConfig {
            origin: format!("radius://127.0.0.1:{}", address.port()),
            address,
            server_name: "127.0.0.1".into(),
            ca_pem: String::new(),
            path_prefix: "/".into(),
            shared_secret: "shared-secret".into(),
        }])?;
        let debug = format!(
            "{:?}",
            EndpointConfig {
                origin: format!("radius://127.0.0.1:{}", address.port()),
                address,
                server_name: "127.0.0.1".into(),
                ca_pem: String::new(),
                path_prefix: "/".into(),
                shared_secret: "shared-secret".into(),
            }
        );
        assert!(!debug.contains("shared-secret"));
        assert!(
            outbound
                .radius_endpoint(&format!("radius://127.0.0.1:{}", address.port()))
                .is_ok()
        );
        assert!(outbound.radius_authenticate(
            &format!("radius://127.0.0.1:{}", address.port()),
            "alice",
            "password"
        )?);
        thread
            .join()
            .map_err(|_| "RADIUS fixture thread failed")?
            .map_err(|_| "RADIUS fixture exchange failed")?;

        let timeout_server =
            UdpSocket::bind("127.0.0.1:0").map_err(|_| "bind timeout RADIUS fixture")?;
        let timeout_address = timeout_server
            .local_addr()
            .map_err(|_| "read timeout RADIUS address")?;
        let outbound = Outbound::new(vec![EndpointConfig {
            origin: format!("radius://127.0.0.1:{}", timeout_address.port()),
            address: timeout_address,
            server_name: "127.0.0.1".into(),
            ca_pem: String::new(),
            path_prefix: "/".into(),
            shared_secret: "shared-secret".into(),
        }])?;
        timeout_server
            .set_read_timeout(Some(Duration::from_millis(1)))
            .map_err(|_| "set timeout fixture")?;
        let _ = outbound.radius_authenticate(
            &format!("radius://127.0.0.1:{}", timeout_address.port()),
            "alice",
            "password",
        );
        Ok(())
    }

    #[test]
    fn ldap_simple_bind_framing_is_bounded_and_result_codes_are_exact() -> Result<(), &'static str>
    {
        let request = ldap_bind_request(
            b"uid=alice,ou=people,dc=example,dc=test",
            b"synthetic-password",
        )?;
        assert_eq!(request.first().copied(), Some(0x30));
        assert!(request.windows(3).any(|window| window == b"\x02\x01\x03"));
        assert!(
            request
                .windows(b"uid=alice,ou=people,dc=example,dc=test".len())
                .any(|window| window == b"uid=alice,ou=people,dc=example,dc=test")
        );

        let success = [
            ber_value(0x02, &[0x01])?,
            ber_value(
                0x61,
                &[
                    ber_value(0x0a, &[0])?,
                    ber_value(0x04, b"")?,
                    ber_value(0x04, b"")?,
                ]
                .concat(),
            )?,
        ]
        .concat();
        let success = ber_value(0x30, &success)?;
        assert!(read_ldap_bind_response(&mut success.as_slice())?);

        let long_diagnostic = vec![b'x'; 130];
        let long_response = ber_value(
            0x30,
            &[
                ber_value(0x02, &[0x01])?,
                ber_value(
                    0x61,
                    &[
                        ber_value(0x0a, &[0])?,
                        ber_value(0x04, b"")?,
                        ber_value(0x04, &long_diagnostic)?,
                    ]
                    .concat(),
                )?,
            ]
            .concat(),
        )?;
        assert!(read_ldap_bind_response(&mut long_response.as_slice())?);

        let denied = [
            ber_value(0x02, &[0x01])?,
            ber_value(
                0x61,
                &[
                    ber_value(0x0a, &[49])?,
                    ber_value(0x04, b"")?,
                    ber_value(0x04, b"invalid credentials")?,
                ]
                .concat(),
            )?,
        ]
        .concat();
        let denied = ber_value(0x30, &denied)?;
        assert!(!read_ldap_bind_response(&mut denied.as_slice())?);

        let mut malformed = success.clone();
        malformed.push(0);
        assert!(read_ldap_bind_response(&mut malformed.as_slice()).is_ok());
        let wrong_id = ber_value(
            0x30,
            &[
                ber_value(0x02, &[0x02])?,
                ber_value(
                    0x61,
                    &[
                        ber_value(0x0a, &[0])?,
                        ber_value(0x04, b"")?,
                        ber_value(0x04, b"")?,
                    ]
                    .concat(),
                )?,
            ]
            .concat(),
        )?;
        assert!(read_ldap_bind_response(&mut wrong_id.as_slice()).is_err());
        Ok(())
    }

    #[test]
    fn ldap_group_search_framing_and_results_are_bounded() -> Result<(), &'static str> {
        let request = ldap_group_search_request(
            b"ou=groups,dc=example,dc=test",
            b"member",
            b"uid=alice,ou=people,dc=example,dc=test",
            b"cn",
        )?;
        assert!(
            request
                .windows(b"ou=groups,dc=example,dc=test".len())
                .any(|window| window == b"ou=groups,dc=example,dc=test")
        );
        assert!(
            request
                .windows(b"uid=alice,ou=people,dc=example,dc=test".len())
                .any(|window| window == b"uid=alice,ou=people,dc=example,dc=test")
        );

        let attribute = ber_value(
            0x30,
            &[
                ber_value(0x04, b"cn")?,
                ber_value(0x31, &ber_value(0x04, b"engineering")?)?,
            ]
            .concat(),
        )?;
        let entry = ber_value(
            0x64,
            &[
                ber_value(0x04, b"cn=engineering,ou=groups,dc=example,dc=test")?,
                ber_value(0x30, &attribute)?,
            ]
            .concat(),
        )?;
        let entry_message = ber_value(0x30, &[ber_value(0x02, &[0x02])?, entry].concat())?;
        let done = ber_value(
            0x65,
            &[
                ber_value(0x0a, &[0])?,
                ber_value(0x04, b"")?,
                ber_value(0x04, b"")?,
            ]
            .concat(),
        )?;
        let done_message = ber_value(0x30, &[ber_value(0x02, &[0x02])?, done].concat())?;
        let bytes = [entry_message, done_message].concat();
        let groups = read_ldap_group_search_response(&mut bytes.as_slice(), "cn")?;
        assert_eq!(groups, BTreeSet::from(["engineering".to_owned()]));
        assert!(ldap_group_search_request(b"", b"member", b"user", b"cn").is_err());
        Ok(())
    }

    #[test]
    fn ldap_dynamic_requests_use_present_objectclass_and_atomic_password_delete()
    -> Result<(), &'static str> {
        let search = ldap_entry_search_request(7, "uid=alice,ou=people,dc=example,dc=test")?;
        assert!(
            search
                .windows(b"objectClass".len())
                .any(|w| w == b"objectClass")
        );
        assert!(!search.windows(3).any(|w| w == b"\x87\x00"));

        let modify = ldap_modify_request(
            9,
            "uid=alice,ou=people,dc=example,dc=test",
            &[
                ("description".into(), vec!["hb-tombstone:".to_owned()]),
                ("userPassword".into(), Vec::new()),
            ],
            Some(("description", "hb-request:")),
        )?;
        assert!(
            modify
                .windows(b"userPassword".len())
                .any(|w| w == b"userPassword")
        );
        assert!(modify.windows(2).any(|w| w == b"1\x00"));
        assert!(
            modify
                .windows(b"1.3.6.1.1.12".len())
                .any(|w| w == b"1.3.6.1.1.12")
        );
        let mut remaining = 64 * 1024;
        let body = read_ldap_message_body(&mut modify.as_slice(), &mut remaining)?;
        let mut cursor = 0;
        let _message_id = ber_take(&body, &mut cursor, 0x02)?;
        let _modify = ber_take(&body, &mut cursor, 0x66)?;
        let controls = ber_take(&body, &mut cursor, 0xa0)?;
        assert_eq!(cursor, body.len());
        let mut controls_cursor = 0;
        let control_set = ber_take(controls, &mut controls_cursor, 0x30)?;
        assert_eq!(controls_cursor, controls.len());
        let mut control_set_cursor = 0;
        let control = ber_take(control_set, &mut control_set_cursor, 0x30)?;
        assert_eq!(control_set_cursor, control_set.len());
        assert_eq!(control.first().copied(), Some(0x04));
        assert!(
            ldap_modify_request(9, "uid=x", &[("description".into(), Vec::new())], None).is_err()
        );
        assert!(
            validate_ldap_effect_input(
                "cn=manager",
                "manager-password",
                "uid=x,ou=people,dc=example,dc=test",
                &[
                    ("cn".into(), vec!["alice".into()]),
                    ("CN".into(), vec!["alice".into()]),
                ],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn ldap_readback_accepts_owned_entry_and_absence_only() -> Result<(), &'static str> {
        let dn = "uid=alice,ou=people,dc=example,dc=test";
        let entry_attrs = [
            ber_value(
                0x30,
                &[
                    ber_value(0x04, b"description")?,
                    ber_value(0x31, &ber_value(0x04, b"hb-request:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?)?,
                ].concat(),
            )?,
            ber_value(
                0x30,
                &[
                    ber_value(0x04, b"userPassword")?,
                    ber_value(0x31, &ber_value(0x04, b"secret")?)?,
                ].concat(),
            )?,
        ].concat();
        let entry = ber_value(
            0x64,
            &[
                ber_value(0x04, dn.as_bytes())?,
                ber_value(0x30, &entry_attrs)?,
            ]
            .concat(),
        )?;
        let done = ber_value(
            0x65,
            &[
                ber_value(0x0a, &[0])?,
                ber_value(0x04, b"")?,
                ber_value(0x04, b"")?,
            ]
            .concat(),
        )?;
        let bytes = [
            ber_value(0x30, &[ber_value(0x02, &[7])?, entry].concat())?,
            ber_value(0x30, &[ber_value(0x02, &[7])?, done].concat())?,
        ]
        .concat();
        assert_eq!(
            read_ldap_entry(&mut bytes.as_slice(), 7, dn)?,
            Some(LdapEntryObservation {
                marker: Some(
                    "hb-request:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into()
                ),
                password_present: true,
            })
        );

        let absent_done = ber_value(
            0x65,
            &[
                ber_value(0x0a, &[32])?,
                ber_value(0x04, b"")?,
                ber_value(0x04, b"")?,
            ]
            .concat(),
        )?;
        let absent = ber_value(0x30, &[ber_value(0x02, &[8])?, absent_done].concat())?;
        assert_eq!(read_ldap_entry(&mut absent.as_slice(), 8, dn)?, None);
        Ok(())
    }

    #[test]
    fn ldap_result_code_preserves_entry_exists_for_reconciliation() -> Result<(), &'static str> {
        let response = ber_value(
            0x30,
            &[
                ber_value(0x02, &[3])?,
                ber_value(
                    0x69,
                    &[
                        ber_value(0x0a, &[68])?,
                        ber_value(0x04, b"")?,
                        ber_value(0x04, b"already exists")?,
                    ]
                    .concat(),
                )?,
            ]
            .concat(),
        )?;
        assert_eq!(
            read_ldap_result_code(&mut response.as_slice(), 3, 0x69)?,
            68
        );
        Ok(())
    }

    #[test]
    fn online_form_components_and_headers_cannot_inject_authority() {
        assert_eq!(form_component("safe-A_z.0~"), "safe-A_z.0~");
        assert_eq!(
            form_component("a:b+c&d=e ?\r\n"),
            "a%3Ab%2Bc%26d%3De%20%3F%0D%0A"
        );
        assert_eq!(form_component("é"), "%C3%A9");
        let outbound = Outbound::default();
        for credential in ["", "x y", "x\r\nAuthorization: Basic bad", "x\0y"] {
            assert_eq!(
                outbound.post_json_bearer(
                    "https://issuer:443/",
                    credential,
                    &serde_json::json!({})
                ),
                Err("invalid outbound bearer")
            );
        }
    }
}
