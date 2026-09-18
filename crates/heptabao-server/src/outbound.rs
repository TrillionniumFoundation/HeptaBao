//! Deployment-owned, address-pinned TLS egress. Remote metadata never adds an
//! origin, changes a CA, follows a redirect, invokes DNS, or widens a path scope.
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
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
            } else if config.origin.starts_with("ldaps://") {
                "ldaps"
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

    /// Perform one LDAPv3 simple bind over an exactly enrolled LDAPS endpoint.
    /// This is intentionally narrower than a general LDAP client: no DNS,
    /// StartTLS upgrade, referrals, search, SASL, redirect, or automatic retry.
    pub(crate) fn ldap_simple_bind(
        &self,
        url: &str,
        dn: &str,
        password: &str,
    ) -> Result<bool, &'static str> {
        Ok(self
            .ldap_bind_and_search_groups(url, dn, password, "", "member", "cn")?
            .is_some())
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
    let mut prefix = [0u8; 4];
    stream
        .read_exact(&mut prefix[..2])
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
        stream
            .read_exact(&mut prefix[..count])
            .map_err(|_| "truncated LDAP response length")?;
        head.extend_from_slice(&prefix[..count]);
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
        assert_eq!(read_ldap_bind_response(&mut success.as_slice())?, true);

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
        assert_eq!(read_ldap_bind_response(&mut denied.as_slice())?, false);

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
