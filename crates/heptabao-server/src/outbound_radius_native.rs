//! Native PAP parameters over either legacy process enrollment or explicit API
//! target authority. One request, no retries after sending; the read deadline
//! covers DNS, connect and the entire authenticated exchange without refreshing.
use super::*;
use std::net::{IpAddr, Ipv6Addr};

pub(crate) const MAX_RADIUS_TIMEOUT_SECONDS: u64 = 60;

/// Borrowed, intentionally not Debug/Clone: the owner zeroizes the durable secret.
pub(crate) struct RadiusNativeOptions<'a> {
    pub(crate) secret: &'a str,
    pub(crate) nas_port: i64,
    pub(crate) nas_identifier: &'a str,
    pub(crate) dial_timeout: u64,
    pub(crate) read_timeout: u64,
}

impl RadiusNativeOptions<'_> {
    /// Check the explicitly bounded profile without opening a socket.
    pub(crate) fn validate_configuration(&self) -> Result<(), &'static str> {
        if self.secret.is_empty()
            || self.secret.len() > 256
            || self.secret.as_bytes().contains(&0)
            || self.nas_identifier.len() > 253
            || self.dial_timeout > MAX_RADIUS_TIMEOUT_SECONDS
            || self.read_timeout > MAX_RADIUS_TIMEOUT_SECONDS
        {
            return Err("native RADIUS configuration exceeds bounds");
        }
        Ok(())
    }
}

/// Validate the standard configuration's bare host without DNS, sockets or TLS.
/// The API owns case normalization and keeps the signed configured port intact;
/// only an effective URL at execution must have a usable positive u16 port.
pub(crate) fn validate_radius_native_host(host: &str) -> Result<(), &'static str> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("invalid native RADIUS host");
    }
    Ok(())
}

pub(crate) fn validate_radius_target(url: &str) -> Result<RadiusTarget, &'static str> {
    RadiusTarget::parse(url)
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RadiusTarget {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl RadiusTarget {
    fn parse(url: &str) -> Result<Self, &'static str> {
        if url.len() > 2048
            || !url.is_ascii()
            || url
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            || url
                .bytes()
                .any(|byte| matches!(byte, b'@' | b'\\' | b'?' | b'#' | b'%'))
            || !url
                .get(..9)
                .is_some_and(|value| value.eq_ignore_ascii_case("radius://"))
        {
            return Err("invalid native RADIUS target");
        }
        let authority = url[9..].strip_suffix('/').unwrap_or(&url[9..]);
        if authority.contains('/') {
            return Err("RADIUS target must be an origin");
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, suffix) = bracketed
                .split_once(']')
                .ok_or("invalid RADIUS IPv6 target")?;
            let address = host
                .parse::<Ipv6Addr>()
                .map_err(|_| "invalid RADIUS IPv6 target")?;
            (
                address.to_string(),
                suffix.strip_prefix(':').ok_or("missing RADIUS port")?,
            )
        } else {
            let (host, port) = authority.split_once(':').ok_or("missing RADIUS port")?;
            validate_radius_native_host(host)?;
            (host.to_ascii_lowercase(), port)
        };
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("invalid RADIUS port");
        }
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or("invalid RADIUS port")?;
        Ok(Self { host, port })
    }
}

impl Outbound {
    pub(crate) fn radius_authenticate_native(
        &self,
        url: &str,
        options: &RadiusNativeOptions<'_>,
        api_transport: bool,
        username: &str,
        password: &str,
    ) -> Result<bool, &'static str> {
        options.validate_configuration()?;
        if username.is_empty()
            || username.len() > 253
            || username.bytes().any(|byte| byte == 0 || byte < 0x20)
            || password.is_empty()
            || password.len() > 128
            || password.as_bytes().contains(&0)
        {
            return Err("invalid RADIUS credentials");
        }
        // OpenBao WithTimeout(ctx, 0) expires before sending any request. Keep
        // this before resolution so the zero case cannot consume DNS capacity.
        if options.read_timeout == 0 {
            return Err("RADIUS operation deadline exceeded");
        }
        let start = Instant::now();
        let deadline = start
            .checked_add(Duration::from_secs(options.read_timeout))
            .ok_or("RADIUS operation deadline exceeds bounds")?;
        let dial_deadline = if options.dial_timeout == 0 {
            deadline
        } else {
            start
                .checked_add(Duration::from_secs(options.dial_timeout))
                .ok_or("RADIUS connect deadline exceeds bounds")?
                .min(deadline)
        };
        let addresses = if api_transport {
            let target = super::validate_radius_target(url)?;
            super::ldap_transport::resolve_addresses(&target.host, target.port, dial_deadline)
                .map_err(|_| "RADIUS DNS resolution unavailable")?
        } else {
            // No DNS or additional authority for persisted legacy native mounts.
            let target = Target::parse(url, "radius")?;
            if target.path != "/" {
                return Err("RADIUS target must be an enrolled origin");
            }
            let endpoint = self
                .radius_endpoints
                .get(&target.origin)
                .ok_or("RADIUS endpoint is not host-enrolled")?;
            vec![endpoint.address]
        };
        authenticate_resolved(
            &addresses,
            options,
            username,
            password,
            deadline,
            dial_deadline,
        )
    }
}

fn authenticate_resolved(
    addresses: &[SocketAddr],
    options: &RadiusNativeOptions<'_>,
    username: &str,
    password: &str,
    deadline: Instant,
    dial_deadline: Instant,
) -> Result<bool, &'static str> {
    let (socket, address) = connect_peer(addresses, dial_deadline)?;
    let mut authenticator = [0u8; 16];
    SystemRandom::new()
        .fill(&mut authenticator)
        .map_err(|_| "RADIUS request randomness unavailable")?;
    let identifier = authenticator[0];
    let packet = Zeroizing::new(radius_access_request_with_nas(
        identifier,
        &authenticator,
        username.as_bytes(),
        password.as_bytes(),
        options.secret.as_bytes(),
        Some((options.nas_port, options.nas_identifier)),
    )?);
    // Once the first PAP is sent its outcome may be unknown. Never select a
    // second resolved address or retry this packet after any send/receive error.
    socket
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|_| "RADIUS socket setup failed")?;
    if socket
        .send(&packet)
        .map_err(|_| "RADIUS request delivery failed")?
        != packet.len()
    {
        return Err("RADIUS request delivery was incomplete");
    }
    socket
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|_| "RADIUS socket setup failed")?;
    // One extra byte detects truncation of an overlong UDP datagram whose first
    // 4096 bytes would otherwise look like a complete valid packet.
    let mut response = Zeroizing::new([0u8; 4097]);
    let (size, source) = socket
        .recv_from(response.as_mut())
        .map_err(|_| "RADIUS response unavailable")?;
    remaining(deadline)?;
    if size > 4096 || source != address {
        return Err("RADIUS response source or length mismatch");
    }
    let accepted = radius_response_accepted(
        &response[..size],
        identifier,
        &authenticator,
        options.secret.as_bytes(),
    )?;
    remaining(deadline)?;
    Ok(accepted)
}

fn connect_peer(
    addresses: &[SocketAddr],
    deadline: Instant,
) -> Result<(UdpSocket, SocketAddr), &'static str> {
    for address in addresses {
        remaining(deadline)?;
        let local = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let Ok(socket) = UdpSocket::bind(local) else {
            continue;
        };
        socket
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| "RADIUS socket setup failed")?;
        if socket.connect(address).is_err() {
            continue;
        }
        remaining(deadline)?;
        // UDP connect does not verify provider availability. The first locally
        // connected peer stays selected even if it never answers the request.
        return Ok((socket, *address));
    }
    Err("RADIUS connect failed")
}

fn remaining(deadline: Instant) -> Result<Duration, &'static str> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or("RADIUS operation deadline exceeded")
}

#[cfg(test)]
#[path = "outbound_radius_native_tests.rs"]
mod tests;
