//! Native PAP parameters over a deployment-enrolled, fixed UDP address.
//! One request, no retries; the configured read deadline bounds the entire
//! exchange and never refreshes. No DNS, credential fallback or address discovery.
use super::*;

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

impl Outbound {
    pub(crate) fn radius_authenticate_native(
        &self,
        url: &str,
        options: &RadiusNativeOptions<'_>,
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
        let target = Target::parse(url, "radius")?;
        if target.path != "/" {
            return Err("RADIUS target must be an enrolled origin");
        }
        let endpoint = self
            .radius_endpoints
            .get(&target.origin)
            .ok_or("RADIUS endpoint is not host-enrolled")?;
        // OpenBao WithTimeout(ctx, 0) expires before sending any request.
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
        // UDP connect has no remote handshake or DNS. Binding the fixed peer
        // also lets the kernel reject packets from any other source address.
        let local = if endpoint.address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local).map_err(|_| "RADIUS socket unavailable")?;
        socket
            .set_write_timeout(Some(remaining(dial_deadline)?))
            .map_err(|_| "RADIUS socket setup failed")?;
        socket
            .connect(endpoint.address)
            .map_err(|_| "RADIUS connect failed")?;
        let _ = remaining(dial_deadline)?;
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
        // One extra byte detects truncation of an overlong UDP datagram whose
        // first 4096 bytes would otherwise look like a complete valid packet.
        let mut response = Zeroizing::new([0u8; 4097]);
        let (size, source) = socket
            .recv_from(response.as_mut())
            .map_err(|_| "RADIUS response unavailable")?;
        let _ = remaining(deadline)?;
        if size > 4096 || source != endpoint.address {
            return Err("RADIUS response source or length mismatch");
        }
        radius_response_accepted(
            &response[..size],
            identifier,
            &authenticator,
            options.secret.as_bytes(),
        )
    }
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
