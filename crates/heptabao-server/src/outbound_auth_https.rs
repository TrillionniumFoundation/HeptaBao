//! HTTPS authority scoped to administrator-configured JWT/OIDC mounts. None
//! retains the deployment-enrolled route; generic outbound APIs are unchanged.
use super::*;
use serde::Serialize;
use std::net::Ipv6Addr;

const AUTH_HTTPS_SECONDS: u64 = 30;

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthHttpsTransport {
    pub(crate) certificate: String,
}

pub(crate) fn auth_https_deadline() -> Instant {
    Instant::now() + Duration::from_secs(AUTH_HTTPS_SECONDS)
}

impl AuthHttpsTransport {
    pub(crate) fn validate_configuration(&self, url: &str) -> Result<(), &'static str> {
        let _ = api_target(url)?;
        ldap_transport::validate_certificate(&self.certificate)
    }
}

struct ApiTarget {
    target: Target,
    host: String,
    port: u16,
}

/// Parsing has no filesystem, DNS, root-store or network side effects.
pub(crate) fn parse_auth_https_target(
    url: &str,
    transport: Option<&AuthHttpsTransport>,
) -> Result<Target, &'static str> {
    if transport.is_none() {
        return Target::parse(url, "https");
    }
    Ok(api_target(url)?.target)
}

fn api_target(url: &str) -> Result<ApiTarget, &'static str> {
    if url.len() > 2048
        || !url.is_ascii()
        || url.bytes().any(|b| b <= 32 || b == 127)
        || url.contains(['\\', '#'])
        || !url
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
    {
        return Err("invalid authentication HTTPS URL");
    }
    let rest = &url[8..];
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..split];
    if authority.is_empty() || authority.contains(['@', '%']) {
        return Err("invalid authentication HTTPS authority");
    }
    let tail = &rest[split..];
    let path = if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    };
    // Percent encoding stays encoded in the request target; malformed escapes
    // are rejected and no decoded CR/LF can become an HTTP header delimiter.
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err("invalid authentication HTTPS path encoding");
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let parse_port = |value: &str| -> Result<u16, &'static str> {
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid HTTPS port");
        }
        value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or("invalid HTTPS port")
    };
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (address, suffix) = bracketed
            .split_once(']')
            .ok_or("invalid HTTPS IPv6 authority")?;
        let address = address
            .parse::<Ipv6Addr>()
            .map_err(|_| "invalid HTTPS IPv6 authority")?;
        let port = if suffix.is_empty() {
            443
        } else {
            parse_port(suffix.strip_prefix(':').ok_or("invalid HTTPS port")?)?
        };
        (address.to_string(), port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .map_or(Ok((authority, 443)), |(host, port)| {
                parse_port(port).map(|port| (host, port))
            })?;
        validate_radius_native_host(host)?;
        if host.contains(':') {
            return Err("HTTPS IPv6 requires brackets");
        }
        (host.to_ascii_lowercase(), port)
    };
    ServerName::try_from(host.clone()).map_err(|_| "invalid authentication TLS name")?;
    let host_header = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let authority = if port == 443 {
        host_header.clone()
    } else {
        format!("{host_header}:{port}")
    };
    let origin = format!("https://{host_header}:{port}");
    Ok(ApiTarget {
        target: Target {
            origin,
            authority,
            path,
        },
        host,
        port,
    })
}

fn remaining(deadline: Instant) -> Result<Duration, &'static str> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or("authentication HTTPS deadline exceeded")
}

impl Outbound {
    fn auth_https_connection(
        &self,
        url: &str,
        transport: Option<&AuthHttpsTransport>,
        deadline: Instant,
    ) -> Result<(TlsStream, Target), &'static str> {
        remaining(deadline)?;
        if let Some(config) = transport {
            config.validate_configuration(url)?;
            let target = api_target(url)?;
            let connection_deadline = deadline.min(Instant::now() + Duration::from_secs(10));
            let stream = ldap_transport::connect_verified_tls(
                &target.host,
                target.port,
                &config.certificate,
                connection_deadline,
                deadline,
            )?;
            return Ok((stream, target.target));
        }
        let (endpoint, target) = self.endpoint(url, "https")?;
        let deadline = deadline.min(Instant::now() + Duration::from_secs(3));
        let stream = TcpStream::connect_timeout(&endpoint.address, remaining(deadline)?)
            .map_err(|_| "enrolled authentication HTTPS unavailable")?;
        stream
            .set_nodelay(true)
            .map_err(|_| "authentication socket setup failed")?;
        let stream = endpoint.tls(DeadlineSocket { stream, deadline })?;
        remaining(deadline)?;
        Ok((stream, target))
    }

    pub(crate) fn get_auth_json(
        &self,
        url: &str,
        transport: Option<&AuthHttpsTransport>,
        deadline: Instant,
    ) -> Result<Value, &'static str> {
        let (mut stream, target) = self.auth_https_connection(url, transport, deadline)?;
        let head = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json, application/jwk-set+json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            target.path, target.authority
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|_| "authentication HTTPS write failed")?;
        let value = read_json_response(&mut stream)?;
        stream
            .sock
            .remaining()
            .map_err(|_| "authentication HTTPS connection deadline exceeded")?;
        remaining(deadline)?;
        Ok(value)
    }

    /// Fetches a provider-owned JSON resource with the access token in the
    /// Authorization header. The caller supplies the discovery-bound URL;
    /// this helper never follows redirects or accepts a caller-controlled
    /// host. It is used for OIDC UserInfo, whose response is not itself a
    /// credential and must still be validated by the caller.
    pub(crate) fn get_auth_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        transport: Option<&AuthHttpsTransport>,
        deadline: Instant,
    ) -> Result<Value, &'static str> {
        if bearer.is_empty()
            || bearer.len() > 32 * 1024
            || !bearer.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("invalid authentication bearer");
        }
        let (mut stream, target) = self.auth_https_connection(url, transport, deadline)?;
        let mut head = Zeroizing::new(String::with_capacity(
            192 + target.path.len() + target.authority.len() + bearer.len(),
        ));
        head.push_str("GET ");
        head.push_str(&target.path);
        head.push_str(" HTTP/1.1\r\nHost: ");
        head.push_str(&target.authority);
        head.push_str("\r\nAuthorization: Bearer ");
        head.push_str(bearer);
        head.push_str("\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|_| "authentication GET failed; no retry")?;
        let mut value = read_json_response_status(&mut stream, &[200])?;
        if stream.sock.remaining().is_err() || remaining(deadline).is_err() {
            crate::service::erase_json(&mut value);
            return Err("authentication GET deadline exceeded");
        }
        Ok(value)
    }

    /// Scoped authentication POST. The administrator's owned configuration
    /// supplies the target and trust; a bearer can never redirect the request.
    pub(crate) fn post_auth_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        value: &Value,
        transport: Option<&AuthHttpsTransport>,
        deadline: Instant,
    ) -> Result<Value, &'static str> {
        if bearer.is_empty()
            || bearer.len() > 32 * 1024
            || !bearer.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("invalid authentication bearer");
        }
        let body = bounded_auth_json(value)?;
        let (mut stream, target) = self.auth_https_connection(url, transport, deadline)?;
        let length = body.len().to_string();
        let mut head = Zeroizing::new(String::with_capacity(
            256 + target.path.len() + target.authority.len() + bearer.len() + length.len(),
        ));
        head.push_str("POST ");
        head.push_str(&target.path);
        head.push_str(" HTTP/1.1\r\nHost: ");
        head.push_str(&target.authority);
        head.push_str("\r\nContent-Type: application/json\r\nAuthorization: Bearer ");
        head.push_str(bearer);
        head.push_str("\r\nContent-Length: ");
        head.push_str(&length);
        head.push_str("\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush())
            .map_err(|_| "authentication POST failed; no retry")?;
        let mut response = read_json_response_status(&mut stream, &[200, 201])?;
        if stream.sock.remaining().is_err() || remaining(deadline).is_err() {
            crate::service::erase_json(&mut response);
            return Err("authentication POST deadline exceeded");
        }
        Ok(response)
    }

    pub(crate) fn exchange_auth_oidc(
        &self,
        url: &str,
        exchange: AuthOidcExchange<'_>,
        transport: Option<&AuthHttpsTransport>,
        deadline: Instant,
    ) -> Result<Value, &'static str> {
        let (body, authorization) = oidc_exchange_request(exchange)?;
        let (mut stream, target) = self.auth_https_connection(url, transport, deadline)?;
        let length = body.len().to_string();
        let mut head = Zeroizing::new(String::with_capacity(
            256 + target.path.len()
                + target.authority.len()
                + authorization.as_ref().map_or(0, |value| value.len())
                + length.len(),
        ));
        head.push_str("POST ");
        head.push_str(&target.path);
        head.push_str(" HTTP/1.1\r\nHost: ");
        head.push_str(&target.authority);
        head.push_str("\r\nContent-Type: application/x-www-form-urlencoded\r\n");
        if let Some(authorization) = authorization {
            head.push_str("Authorization: ");
            head.push_str(&authorization);
            head.push_str("\r\n");
        }
        head.push_str("Content-Length: ");
        head.push_str(&length);
        head.push_str("\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(body.as_bytes()))
            .and_then(|()| stream.flush())
            .map_err(|_| "OIDC POST failed; no retry")?;
        let mut value = read_json_response_status(&mut stream, &[200])?;
        if stream.sock.remaining().is_err() {
            crate::service::erase_json(&mut value);
            return Err("OIDC connection deadline exceeded");
        }
        if let Err(error) = remaining(deadline) {
            crate::service::erase_json(&mut value);
            return Err(error);
        }
        Ok(value)
    }
}

fn oidc_exchange_request(
    exchange: AuthOidcExchange<'_>,
) -> Result<(Zeroizing<String>, Option<Zeroizing<String>>), &'static str> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let fields = [
        exchange.client_id,
        exchange.client_secret,
        exchange.code,
        exchange.redirect,
        exchange.verifier,
    ];
    if fields.iter().any(|value| value.len() > 16 * 1024) {
        return Err("OIDC exchange field exceeds bound");
    }
    let mut body = Zeroizing::new(String::with_capacity(
        80 + 3 * (exchange.code.len() + exchange.redirect.len() + exchange.verifier.len()),
    ));
    body.push_str("grant_type=authorization_code&");
    if exchange.client_auth_method == "none" {
        body.push_str("client_id=");
        append_form(&mut body, exchange.client_id);
        body.push('&');
    }
    body.push_str("code=");
    append_form(&mut body, exchange.code);
    body.push_str("&redirect_uri=");
    append_form(&mut body, exchange.redirect);
    body.push_str("&code_verifier=");
    append_form(&mut body, exchange.verifier);
    let authorization = if exchange.client_auth_method == "none" {
        None
    } else if exchange.client_auth_method == "client_secret_basic" {
        let mut credentials = Zeroizing::new(String::with_capacity(
            1 + 3 * (exchange.client_id.len() + exchange.client_secret.len()),
        ));
        append_form(&mut credentials, exchange.client_id);
        credentials.push(':');
        append_form(&mut credentials, exchange.client_secret);
        let mut authorization =
            Zeroizing::new(String::with_capacity(6 + 4 * credentials.len().div_ceil(3)));
        authorization.push_str("Basic ");
        STANDARD.encode_string(credentials.as_bytes(), &mut authorization);
        Some(authorization)
    } else {
        return Err("unsupported OIDC client authentication method");
    };
    if body.len() > MAX_DOCUMENT
        || authorization
            .as_ref()
            .is_some_and(|value| value.len() > 48 * 1024)
    {
        return Err("OIDC exchange exceeds bound");
    }
    Ok((body, authorization))
}

/// Borrowed from the owned OIDC effect; never Debug or copied into a log.
pub(crate) struct AuthOidcExchange<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) client_secret: &'a str,
    pub(crate) client_auth_method: &'a str,
    pub(crate) code: &'a str,
    pub(crate) redirect: &'a str,
    pub(crate) verifier: &'a str,
}

/// Never allow the serializer to reallocate a buffer that held a credential.
fn bounded_auth_json(value: &Value) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    struct Body(Zeroizing<Vec<u8>>);
    impl std::io::Write for Body {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_DOCUMENT.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other(
                    "authentication request exceeds bound",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut body = Body(Zeroizing::new(Vec::with_capacity(MAX_DOCUMENT)));
    serde_json::to_writer(&mut body, value)
        .map_err(|_| "invalid or oversized authentication JSON")?;
    Ok(body.0)
}

fn append_form(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 15) as usize]));
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn api_url_defaults_and_literal_addresses_are_pure_and_legacy_stays_strict() {
        let transport = AuthHttpsTransport::default();
        for (url, origin, path) in [
            (
                "https://EXAMPLE.test/keys",
                "https://example.test:443",
                "/keys",
            ),
            (
                "https://[::1]/keys?version=2",
                "https://[::1]:443",
                "/keys?version=2",
            ),
            (
                "https://example.test.:444/a%2Fb",
                "https://example.test.:444",
                "/a%2Fb",
            ),
        ] {
            let target = parse_auth_https_target(url, Some(&transport)).unwrap();
            assert_eq!(target.origin, origin);
            assert_eq!(target.path, path);
            assert!(parse_auth_https_target(url, None).is_err());
        }
        assert!(
            transport
                .validate_configuration("https://unresolvable.invalid/keys")
                .is_ok()
        );
    }
    #[test]
    fn invalid_authorities_never_reach_dns() {
        for url in [
            "http://example.test/keys",
            "https://a@b/keys",
            "https://[::1%25zone]/keys",
            "https://::1/keys",
            "https://127.0.0.1./keys",
            "https://example.test:0/keys",
            "https://example.test/keys#fragment",
            "https://example.test/%Q0",
            "https://example.test/\r\nInjected",
        ] {
            assert!(api_target(url).is_err(), "{url}");
        }
    }
    #[test]
    fn explicit_invalid_roots_and_elapsed_deadline_do_not_fall_back() {
        let transport = AuthHttpsTransport {
            certificate: "not a certificate".into(),
        };
        assert!(
            transport
                .validate_configuration("https://localhost/keys")
                .is_err()
        );
        let deadline = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert!(
            Outbound::default()
                .get_auth_json(
                    "https://localhost/keys",
                    Some(&AuthHttpsTransport::default()),
                    deadline
                )
                .is_err()
        );
    }
    #[test]
    fn scoped_bearer_post_rejects_bad_header_bounds_and_elapsed_budget_before_io() {
        let outbound = Outbound::default();
        let deadline = auth_https_deadline();
        for bearer in ["", "x y", "x\r\nHost: other", "x\0y"] {
            assert_eq!(
                outbound.post_auth_json_bearer(
                    "https://unresolvable.invalid/",
                    bearer,
                    &serde_json::json!({}),
                    None,
                    deadline
                ),
                Err("invalid authentication bearer")
            );
        }
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert!(
            outbound
                .post_auth_json_bearer(
                    "https://unresolvable.invalid/",
                    "synthetic-reviewer",
                    &serde_json::json!({"spec":{"token":"synthetic-presented"}}),
                    Some(&AuthHttpsTransport::default()),
                    expired
                )
                .is_err()
        );
        let oversized = serde_json::json!({"token":"x".repeat(MAX_DOCUMENT)});
        assert_eq!(
            outbound.post_auth_json_bearer(
                "https://unresolvable.invalid/",
                "synthetic-reviewer",
                &oversized,
                None,
                deadline
            ),
            Err("invalid or oversized authentication JSON")
        );
    }

    #[test]
    fn scoped_bearer_get_rejects_bad_header_before_network_io() {
        let outbound = Outbound::default();
        let deadline = auth_https_deadline();
        for bearer in ["", "x y", "x\r\nHost: other", "x\0y"] {
            assert_eq!(
                outbound.get_auth_json_bearer(
                    "https://unresolvable.invalid/",
                    bearer,
                    None,
                    deadline,
                ),
                Err("invalid authentication bearer")
            );
        }
    }

    #[test]
    fn scoped_json_body_retains_one_bounded_allocation() {
        let value = serde_json::json!({"spec":{"token":"\"\\\n".repeat(1000)}});
        let encoded = bounded_auth_json(&value).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&encoded).unwrap(), value);
        assert_eq!(encoded.capacity(), MAX_DOCUMENT);
        assert!(bounded_auth_json(&serde_json::json!("x".repeat(MAX_DOCUMENT))).is_err());
    }

    #[test]
    fn oidc_public_exchange_uses_pkce_client_id_without_basic_secret() {
        let (body, authorization) = oidc_exchange_request(AuthOidcExchange {
            client_id: "public client",
            client_secret: "",
            client_auth_method: "none",
            code: "one-use-code",
            redirect: "https://client.example:443/callback",
            verifier: "verifier",
        })
        .unwrap();
        assert!(authorization.is_none());
        assert_eq!(
            body.as_str(),
            "grant_type=authorization_code&client_id=public%20client&code=one-use-code&redirect_uri=https%3A%2F%2Fclient.example%3A443%2Fcallback&code_verifier=verifier"
        );
    }

    #[test]
    fn oidc_confidential_exchange_keeps_basic_client_authentication() {
        let (body, authorization) = oidc_exchange_request(AuthOidcExchange {
            client_id: "client",
            client_secret: "secret",
            client_auth_method: "client_secret_basic",
            code: "code",
            redirect: "http://127.0.0.1:8259/oidc/callback",
            verifier: "verifier",
        })
        .unwrap();
        assert!(!body.contains("client_id="));
        assert_eq!(
            authorization.as_ref().map(|value| value.as_str()),
            Some("Basic Y2xpZW50OnNlY3JldA==")
        );
    }
}
