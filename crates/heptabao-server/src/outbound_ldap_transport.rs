//! Administrator-configured LDAP transport. This is deliberately separate from
//! deployment-enrolled egress used by the other outbound protocols.
use super::*;
use serde::Serialize;
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock, mpsc};

const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_ADDRESSES: usize = 16;
const DNS_WORKERS: usize = 4;
const DNS_QUEUE: usize = 16;
const MAX_TIMEOUT_SECONDS: u64 = 300;

/// Entire transport authority is cloned with the authentication effect plan.
/// `None` at the owning config layer preserves the old enrolled-only behavior.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct LdapTransportConfig {
    pub(crate) certificate: String,
    pub(crate) connection_timeout: u64,
    pub(crate) request_timeout: u64,
}

impl Default for LdapTransportConfig {
    fn default() -> Self {
        Self {
            certificate: String::new(),
            connection_timeout: 30,
            request_timeout: 90,
        }
    }
}

impl LdapTransportConfig {
    /// No DNS, filesystem, sockets or system trust-store access. In particular,
    /// an empty certificate means system trust at execution, not enrollment.
    pub(crate) fn validate_configuration(&self, url: &str) -> Result<(), &'static str> {
        let _ = LdapTarget::parse(url)?;
        if !(1..=MAX_TIMEOUT_SECONDS).contains(&self.connection_timeout)
            || !(1..=MAX_TIMEOUT_SECONDS).contains(&self.request_timeout)
            || self.certificate.len() > MAX_CERTIFICATE_BYTES
        {
            return Err("invalid LDAP transport bounds");
        }
        if !self.certificate.is_empty() {
            let _ = explicit_roots(&self.certificate)?;
        }
        Ok(())
    }

    pub(super) fn connect(&self, url: &str) -> Result<TlsStream, &'static str> {
        self.validate_configuration(url)?;
        let target = LdapTarget::parse(url)?;
        let start = Instant::now();
        let operation_deadline = start + Duration::from_secs(self.request_timeout);
        let connection_deadline =
            operation_deadline.min(start + Duration::from_secs(self.connection_timeout));
        let configured_tls = if self.certificate.is_empty() {
            None
        } else {
            Some(client_config(explicit_roots(&self.certificate)?)?)
        };
        // Explicit CA + IP literal needs neither the resolver pool nor system
        // trust. All potentially blocking platform lookups use bounded workers.
        let prepared = if let (Ok(address), Some(_)) =
            (target.host.parse::<IpAddr>(), &configured_tls)
        {
            PreparedTarget {
                addresses: vec![SocketAddr::new(address, target.port)],
                system_tls: None,
            }
        } else {
            preparation_pool()?.request(&target, configured_tls.is_none(), connection_deadline)?
        };
        let tls = configured_tls
            .or(prepared.system_tls)
            .ok_or("LDAP trust unavailable")?;
        // The resolved address list is owned by this operation. Neither DNS nor
        // a config lookup can change its peer or trust during the exchange.
        for address in prepared.addresses {
            let budget = remaining(connection_deadline)?;
            let Ok(stream) = TcpStream::connect_timeout(&address, budget) else {
                continue;
            };
            if stream.set_nodelay(true).is_err() {
                continue;
            }
            let endpoint = Endpoint {
                address,
                server_name: target.host.clone(),
                path_prefix: "/".into(),
                tls: tls.clone(),
            };
            let socket = DeadlineSocket {
                stream,
                deadline: connection_deadline,
            };
            if let Ok(mut stream) = endpoint.tls(socket) {
                remaining(connection_deadline)?;
                remaining(operation_deadline)?;
                // One overall budget from the original start, not a fresh
                // request budget after each bind, search or TLS handshake.
                stream.sock.deadline = operation_deadline;
                return Ok(stream);
            }
        }
        Err("LDAP TLS connection unavailable")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LdapTarget {
    host: String,
    port: u16,
}

impl LdapTarget {
    fn parse(url: &str) -> Result<Self, &'static str> {
        if url.len() > 2048
            || !url.is_ascii()
            || url
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            || url
                .bytes()
                .any(|b| matches!(b, b'@' | b'\\' | b'?' | b'#' | b'%'))
            || !url
                .get(..8)
                .is_some_and(|s| s.eq_ignore_ascii_case("ldaps://"))
        {
            return Err("invalid LDAP TLS URL");
        }
        let authority = url[8..].strip_suffix('/').unwrap_or(&url[8..]);
        if authority.is_empty() || authority.contains('/') {
            return Err("LDAP TLS URL must be an origin");
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, suffix) = bracketed.split_once(']').ok_or("invalid LDAP IPv6 URL")?;
            let address = host
                .parse::<Ipv6Addr>()
                .map_err(|_| "invalid LDAP IPv6 URL")?;
            let port = if suffix.is_empty() {
                636
            } else {
                parse_port(suffix.strip_prefix(':').ok_or("invalid LDAP TLS port")?)?
            };
            (address.to_string(), port)
        } else {
            let (host, port) = if let Some((host, port)) = authority.split_once(':') {
                (host, parse_port(port)?)
            } else {
                (authority, 636)
            };
            let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
            if host.is_empty()
                || host.len() > 253
                || host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err("invalid LDAP TLS host");
            }
            (host, port)
        };
        ServerName::try_from(host.clone()).map_err(|_| "invalid LDAP TLS name")?;
        Ok(Self { host, port })
    }
}

fn parse_port(value: &str) -> Result<u16, &'static str> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid LDAP TLS port");
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or("invalid LDAP TLS port")
}

fn explicit_roots(certificate: &str) -> Result<RootCertStore, &'static str> {
    if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
        return Err("invalid LDAP CA size");
    }
    let mut roots = RootCertStore::empty();
    let mut rest = certificate.trim_matches(|c: char| c.is_ascii_whitespace());
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    while !rest.is_empty() {
        if !rest.starts_with(BEGIN) {
            return Err("invalid LDAP CA PEM contents");
        }
        let end = rest.find(END).ok_or("invalid LDAP CA PEM contents")? + END.len();
        let mut input = &rest.as_bytes()[..end];
        let mut certificates = rustls_pemfile::certs(&mut input);
        let certificate = certificates
            .next()
            .ok_or("empty LDAP CA set")?
            .map_err(|_| "invalid LDAP CA PEM contents")?;
        if certificates.next().is_some() {
            return Err("invalid LDAP CA PEM contents");
        }
        roots
            .add(certificate)
            .map_err(|_| "invalid LDAP CA certificate")?;
        rest = rest[end..].trim_matches(|c: char| c.is_ascii_whitespace());
    }
    if roots.is_empty() {
        return Err("empty LDAP CA set");
    }
    Ok(roots)
}

fn client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, &'static str> {
    if roots.is_empty() {
        return Err("empty LDAP CA set");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "invalid LDAP TLS profile")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(tls))
}

fn system_client_config() -> Result<Arc<ClientConfig>, &'static str> {
    static SYSTEM_TLS: OnceLock<Result<Arc<ClientConfig>, &'static str>> = OnceLock::new();
    SYSTEM_TLS
        .get_or_init(|| {
            // Platform trust is immutable for this process once loaded. No API can
            // alter its environment or merge explicit mount roots into this cache.
            let result = rustls_native_certs::load_native_certs();
            let mut roots = RootCertStore::empty();
            for certificate in result.certs {
                roots
                    .add(certificate)
                    .map_err(|_| "invalid system LDAP CA")?;
            }
            client_config(roots)
        })
        .clone()
}

struct PreparedTarget {
    addresses: Vec<SocketAddr>,
    system_tls: Option<Arc<ClientConfig>>,
}

struct PreparationJob {
    target: LdapTarget,
    system_roots: bool,
    deadline: Instant,
    reply: mpsc::SyncSender<Result<PreparedTarget, &'static str>>,
}

struct PreparationPool {
    sender: mpsc::SyncSender<PreparationJob>,
}

impl PreparationPool {
    fn start(
        worker_count: usize,
        queue_capacity: usize,
        prepare: impl Fn(&LdapTarget, bool, Instant) -> Result<PreparedTarget, &'static str>
        + Send
        + Sync
        + 'static,
    ) -> Result<Self, &'static str> {
        let (sender, receiver) = mpsc::sync_channel::<PreparationJob>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let prepare = Arc::new(prepare);
        for _ in 0..worker_count {
            let receiver = receiver.clone();
            let prepare = prepare.clone();
            let _worker = std::thread::Builder::new()
                .name("ldap-resolver".into())
                .spawn(move || {
                    loop {
                        let job = match receiver.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(job) = job else {
                            return;
                        };
                        // Timed-out queued jobs must not start a new platform lookup.
                        let result = remaining(job.deadline).and_then(|_| {
                            let result = prepare(&job.target, job.system_roots, job.deadline)?;
                            remaining(job.deadline)?;
                            Ok(result)
                        });
                        // A caller timeout releases only its waiter. A blocked OS
                        // lookup still owns this worker; it never spawns a replacement.
                        let _ = job.reply.try_send(result);
                    }
                })
                .map_err(|_| "LDAP resolver worker unavailable")?;
        }
        Ok(Self { sender })
    }

    fn request(
        &self,
        target: &LdapTarget,
        system_roots: bool,
        deadline: Instant,
    ) -> Result<PreparedTarget, &'static str> {
        remaining(deadline)?;
        let (reply, result) = mpsc::sync_channel(1);
        self.sender
            .try_send(PreparationJob {
                target: target.clone(),
                system_roots,
                deadline,
                reply,
            })
            .map_err(|_| "LDAP resolver capacity unavailable")?;
        result
            .recv_timeout(remaining(deadline)?)
            .map_err(|_| "LDAP resolver deadline exceeded")?
    }
}

fn preparation_pool() -> Result<&'static PreparationPool, &'static str> {
    static POOL: OnceLock<Result<PreparationPool, &'static str>> = OnceLock::new();
    POOL.get_or_init(|| PreparationPool::start(DNS_WORKERS, DNS_QUEUE, prepare_target))
        .as_ref()
        .map_err(|error| *error)
}

fn prepare_target(
    target: &LdapTarget,
    system_roots: bool,
    deadline: Instant,
) -> Result<PreparedTarget, &'static str> {
    let system_tls = if system_roots {
        Some(system_client_config()?)
    } else {
        None
    };
    remaining(deadline)?;
    let addresses = if let Ok(address) = target.host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, target.port)]
    } else {
        bounded_addresses(
            (target.host.as_str(), target.port)
                .to_socket_addrs()
                .map_err(|_| "LDAP DNS resolution unavailable")?,
        )?
    };
    Ok(PreparedTarget {
        addresses,
        system_tls,
    })
}

fn bounded_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, &'static str> {
    let mut result = Vec::with_capacity(MAX_ADDRESSES);
    // Bound raw observations as well as unique peers, rather than walking an
    // unlimited duplicate list supplied by a resolver.
    for (index, address) in addresses.into_iter().enumerate() {
        if index == MAX_ADDRESSES {
            return Err("LDAP DNS address limit exceeded");
        }
        if !result.contains(&address) {
            result.push(address);
        }
    }
    if result.is_empty() {
        return Err("LDAP DNS returned no addresses");
    }
    Ok(result)
}

fn remaining(deadline: Instant) -> Result<Duration, &'static str> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or("LDAP operation deadline exceeded")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::{
        Condvar,
        atomic::{AtomicUsize, Ordering},
    };

    const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIDKzCCAhOgAwIBAgIUFUXFkdS4brx3/V1+H4FaACtNtW8wDQYJKoZIhvcNAQEL\nBQAwJTEjMCEGA1UEAwwaSGVwdGFCYW8tdHJhbnNwb3J0LXRlc3QtQ0EwHhcNMjYw\nOTIwMjAyMTM5WhcNMzYwOTE3MjAyMTM5WjAlMSMwIQYDVQQDDBpIZXB0YUJhby10\ncmFuc3BvcnQtdGVzdC1DQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\nALIBwI6wZmvNhyebLZeCHFT29c69vvWCLyvTUcP1L/jkkVNz0GuJbsP0GjDhZugg\nTC6erH13QGsA00VvTE6pnpPz1rf72igYAdcRp6eFVarMFTocaEjKTmAlU37dGYSS\neyxLIjBWLENa8x1g2o6cb28kbqdJW/0sxivHYgE9Cdln0IqWNaUuk0rcKQtcXWmG\nRu8PCJtJ9fhlQ2MFTEGbkIFoecjkpF2ol2dXgfV+bT+e5sx48+kEFeU32WSoQjgZ\nD9dSXb/kANF1GiXEV/a1/QygP6Ofvy+qe8P50cZA1Y91dnTr2LsV75+GtAZYTfYd\nv6HW8kWUkjq3soCkuCqPntUCAwEAAaNTMFEwHQYDVR0OBBYEFN+h1L6HdOzSxL/W\nZNK1y/Y93Tj8MB8GA1UdIwQYMBaAFN+h1L6HdOzSxL/WZNK1y/Y93Tj8MA8GA1Ud\nEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADChHU7Qxz73PGZeBXz5qtTT\n+NnFYuoY83/IesNqof1uqfYpLH/hRIkA5cewyEuxzWp7XnsjBnYZA9LtQS5gsnWW\n7snA+L257pHYo2TVP+N6y1yAcOKOSmDAssWzbizgtVlF14hIqnBWfl54H+gh6aH4\nVkzN4ZaClrBwLX+czYwCI9zKpCnc5holVqxXXzB6TkBAfhSf90ud3PQj+47xMW3F\n1gdJ2ApHICxPxntjU3/1ucl/7mk13P12hvYSxUcXfiMLhyGxUnjigFkk9+8Hhz9Y\nf52X0M/K8/+9PyMbMO9L440+0NVSZeEyw6SwERp3bLLkeNWhqiPCss8UONw34dg=\n-----END CERTIFICATE-----\n";

    #[test]
    fn standard_defaults_and_serialization_are_owned() {
        let config: LdapTransportConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config, LdapTransportConfig::default());
        assert_eq!(config.connection_timeout, 30);
        assert_eq!(config.request_timeout, 90);
        let original = LdapTransportConfig {
            certificate: CA.into(),
            ..config
        };
        let encoded = serde_json::to_vec(&original).unwrap();
        let snapshot: LdapTransportConfig = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(snapshot, original);
        assert!(serde_json::from_str::<LdapTransportConfig>(r#"{"insecure_tls":true}"#).is_err());
    }

    #[test]
    fn standard_ldaps_targets_have_default_port_and_typed_ip_names() {
        for (url, host, port) in [
            ("ldaps://ldap.example", "ldap.example", 636),
            ("LDAPS://LDAP.EXAMPLE./", "ldap.example", 636),
            ("ldaps://localhost:1636", "localhost", 1636),
            ("ldaps://127.0.0.1/", "127.0.0.1", 636),
            ("ldaps://[::1]", "::1", 636),
            ("ldaps://[2001:db8::1]:1636/", "2001:db8::1", 1636),
        ] {
            let target = LdapTarget::parse(url).unwrap();
            assert_eq!(target.host, host);
            assert_eq!(target.port, port);
        }
        assert!(matches!(
            ServerName::try_from("127.0.0.1"),
            Ok(ServerName::IpAddress(_))
        ));
        assert!(matches!(
            ServerName::try_from("::1"),
            Ok(ServerName::IpAddress(_))
        ));
    }

    #[test]
    fn malformed_or_expanded_authority_is_rejected_without_io() {
        for url in [
            "",
            "ldaps:",
            "ldap://localhost",
            "https://localhost",
            "ldaps://",
            "ldaps://host:0",
            "ldaps://host:65536",
            "ldaps://host:+636",
            "ldaps://host:",
            "ldaps://user@host",
            "ldaps://host/path",
            "ldaps://host//",
            "ldaps://host?x",
            "ldaps://host#x",
            "ldaps://host%2fother",
            "ldaps://host\\other",
            "ldaps://host\n",
            "ldaps://[::1",
            "ldaps://::1",
            "ldaps://[::1]junk",
            "ldaps://[fe80::1%en0]",
            "ldaps://[127.0.0.1]",
            "ldaps://a..b",
            "ldaps://-host",
            "ldaps://host-",
            "ldaps://host_name",
            "ldaps://host,other",
            "ldaps://例子.test",
        ] {
            assert!(
                LdapTransportConfig::default()
                    .validate_configuration(url)
                    .is_err(),
                "{url:?}"
            );
        }
    }

    #[test]
    fn config_validation_is_pure_even_for_unresolvable_host_and_system_roots() {
        let config = LdapTransportConfig::default();
        assert!(
            config
                .validate_configuration("ldaps://must-not-resolve.invalid")
                .is_ok()
        );
        // No validation-time attempt to open a root store or contact this peer.
        assert!(config.validate_configuration("ldaps://192.0.2.1").is_ok());
    }

    #[test]
    fn timeout_bounds_are_explicit_not_silently_clamped() {
        for value in [0, 301, u64::MAX] {
            let config = LdapTransportConfig {
                connection_timeout: value,
                ..Default::default()
            };
            assert!(config.validate_configuration("ldaps://localhost").is_err());
            let config = LdapTransportConfig {
                request_timeout: value,
                ..Default::default()
            };
            assert!(config.validate_configuration("ldaps://localhost").is_err());
        }
        for value in [1, 300] {
            let config = LdapTransportConfig {
                connection_timeout: value,
                request_timeout: value,
                ..Default::default()
            };
            assert!(config.validate_configuration("ldaps://localhost").is_ok());
        }
    }

    #[test]
    fn explicit_ca_only_accepts_nonempty_certificate_pem_blocks() {
        assert_eq!(explicit_roots(CA).unwrap().len(), 1);
        assert_eq!(
            explicit_roots(&format!(" \n{CA}\n{CA}\t")).unwrap().len(),
            2
        );
        for certificate in [
            String::new(),
            " \n\t".into(),
            "garbage".into(),
            format!("garbage{CA}"),
            format!("{CA}garbage"),
            format!("{CA}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----".into(),
            CA.replace("-----END CERTIFICATE-----", ""),
            "a".repeat(MAX_CERTIFICATE_BYTES + 1),
        ] {
            assert!(explicit_roots(&certificate).is_err());
        }
        let config = LdapTransportConfig {
            certificate: " ".into(),
            ..Default::default()
        };
        assert!(config.validate_configuration("ldaps://localhost").is_err());
    }

    #[test]
    fn explicit_ca_failure_cannot_fall_back_to_system_or_enrollment() {
        let config = LdapTransportConfig {
            certificate: "bad CA".into(),
            ..Default::default()
        };
        assert!(matches!(
            config.connect("ldaps://127.0.0.1:1"),
            Err("invalid LDAP CA PEM contents")
        ));
    }

    #[test]
    fn resolved_addresses_are_bounded_deduplicated_and_ordered() {
        let first: SocketAddr = "127.0.0.1:636".parse().unwrap();
        let second: SocketAddr = "[::1]:636".parse().unwrap();
        assert_eq!(
            bounded_addresses([first, first, second]).unwrap(),
            vec![first, second]
        );
        assert!(bounded_addresses([]).is_err());
        assert_eq!(
            bounded_addresses([first; MAX_ADDRESSES]).unwrap(),
            vec![first]
        );
        assert!(bounded_addresses([first; MAX_ADDRESSES + 1]).is_err());
    }

    #[test]
    fn literal_preparation_preserves_port_without_dns_or_system_trust() {
        for url in ["ldaps://127.0.0.1:1636", "ldaps://[::1]:1636"] {
            let target = LdapTarget::parse(url).unwrap();
            let prepared =
                prepare_target(&target, false, Instant::now() + Duration::from_secs(1)).unwrap();
            assert_eq!(
                prepared.addresses,
                vec![SocketAddr::new(target.host.parse().unwrap(), 1636)]
            );
            assert!(prepared.system_tls.is_none());
        }
    }

    #[test]
    fn resolver_retains_capacity_after_caller_abandons_and_skips_expired_queue() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let worker_calls = calls.clone();
        let worker_gate = gate.clone();
        let pool = PreparationPool::start(1, 1, move |target, _, _| {
            worker_calls.fetch_add(1, Ordering::SeqCst);
            entered_tx.send(()).unwrap();
            let (lock, changed) = &*worker_gate;
            let released = lock.lock().unwrap();
            let _released = changed.wait_while(released, |released| !*released).unwrap();
            Ok(PreparedTarget {
                addresses: vec![SocketAddr::new("127.0.0.1".parse().unwrap(), target.port)],
                system_tls: None,
            })
        })
        .unwrap();
        let target = LdapTarget::parse("ldaps://test.invalid").unwrap();
        let (reply, abandoned) = mpsc::sync_channel(1);
        pool.sender
            .try_send(PreparationJob {
                target: target.clone(),
                system_roots: false,
                deadline: Instant::now() + Duration::from_secs(10),
                reply,
            })
            .unwrap_or_else(|_| panic!("first job not accepted"));
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // Abandonment must not free a worker that is still in the OS resolver.
        drop(abandoned);
        let (reply, expired) = mpsc::sync_channel(1);
        pool.sender
            .try_send(PreparationJob {
                target: target.clone(),
                system_roots: false,
                deadline: Instant::now() - Duration::from_secs(1),
                reply,
            })
            .unwrap_or_else(|_| panic!("queued job not accepted"));
        assert!(matches!(
            pool.request(&target, false, Instant::now() + Duration::from_secs(1)),
            Err("LDAP resolver capacity unavailable")
        ));
        let (lock, changed) = &*gate;
        *lock.lock().unwrap() = true;
        changed.notify_all();
        assert!(matches!(
            expired.recv_timeout(Duration::from_secs(2)).unwrap(),
            Err("LDAP operation deadline exceeded")
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expired_request_never_enters_worker() {
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = calls.clone();
        let pool = PreparationPool::start(1, 1, move |_, _, _| {
            worker_calls.fetch_add(1, Ordering::SeqCst);
            Err("unexpected resolver execution")
        })
        .unwrap();
        let target = LdapTarget::parse("ldaps://test.invalid").unwrap();
        assert!(matches!(
            pool.request(&target, false, Instant::now() - Duration::from_secs(1)),
            Err("LDAP operation deadline exceeded")
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn resolver_result_is_an_owned_observation() {
        let pool = PreparationPool::start(1, 1, |target, system_roots, _| {
            assert!(!system_roots);
            Ok(PreparedTarget {
                addresses: vec![SocketAddr::new("127.0.0.1".parse().unwrap(), target.port)],
                system_tls: None,
            })
        })
        .unwrap();
        let mut target = LdapTarget::parse("ldaps://test.invalid:1636").unwrap();
        let prepared = pool
            .request(&target, false, Instant::now() + Duration::from_secs(2))
            .unwrap();
        target.port = 2636;
        assert_eq!(prepared.addresses[0].port(), 1636);
    }
}
