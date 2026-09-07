#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Bounded local proxy contracts with credential replacement and header-smuggling defenses.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use heptabao_domain::SecretValue;

pub const MAX_HEADER_NAME_BYTES: usize = 64;
pub const MAX_HEADER_VALUE_BYTES: usize = 8192;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-heptabao-token",
    "x-vault-token",
];

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HeaderName(String);

impl HeaderName {
    pub fn parse(value: impl Into<String>) -> Result<Self, ProxyError> {
        let value = value.into().to_ascii_lowercase();
        if value.is_empty()
            || value.len() > MAX_HEADER_NAME_BYTES
            || !value.bytes().all(is_header_name_byte)
        {
            return Err(ProxyError::InvalidHeaderName);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HeaderName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("HeaderName").field(&self.0).finish()
    }
}

#[derive(Eq, PartialEq)]
pub struct HeaderValue(Vec<u8>);

impl HeaderValue {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProxyError> {
        if bytes.len() > MAX_HEADER_VALUE_BYTES
            || bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        {
            return Err(ProxyError::InvalidHeaderValue);
        }
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    fn as_ascii(&self) -> Result<&str, ProxyError> {
        std::str::from_utf8(&self.0).map_err(|_| ProxyError::InvalidHeaderValue)
    }
}

impl fmt::Debug for HeaderValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderValue")
            .field("bytes", &"[REDACTED]")
            .field("length", &self.0.len())
            .finish()
    }
}

impl Drop for HeaderValue {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProxyRequest {
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body_bytes: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ForwardPlan {
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body_bytes: usize,
    pub upstream_timeout_ticks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyPolicy {
    allowed_request_headers: BTreeSet<HeaderName>,
    allowed_response_headers: BTreeSet<HeaderName>,
    maximum_request_bytes: usize,
    maximum_response_bytes: usize,
    upstream_timeout_ticks: u64,
}

impl ProxyPolicy {
    pub fn new(
        allowed_request_headers: impl IntoIterator<Item = HeaderName>,
        allowed_response_headers: impl IntoIterator<Item = HeaderName>,
        maximum_request_bytes: usize,
        maximum_response_bytes: usize,
        upstream_timeout_ticks: u64,
    ) -> Result<Self, ProxyError> {
        if maximum_request_bytes == 0 || maximum_response_bytes == 0 || upstream_timeout_ticks == 0
        {
            return Err(ProxyError::InvalidPolicy);
        }
        let allowed_request_headers = allowed_request_headers.into_iter().collect();
        let allowed_response_headers = allowed_response_headers.into_iter().collect();
        Ok(Self {
            allowed_request_headers,
            allowed_response_headers,
            maximum_request_bytes,
            maximum_response_bytes,
            upstream_timeout_ticks,
        })
    }

    pub fn plan_request(
        &self,
        request: ProxyRequest,
        server_token: SecretValue,
    ) -> Result<ForwardPlan, ProxyError> {
        if request.body_bytes > self.maximum_request_bytes {
            return Err(ProxyError::RequestTooLarge);
        }
        let nominated = connection_nominations(&request.headers)?;
        let mut seen = BTreeSet::new();
        let mut forwarded = Vec::new();
        for (name, value) in request.headers {
            if !seen.insert(name.clone()) {
                return Err(ProxyError::DuplicateHeader);
            }
            if is_hop_by_hop(&name) || nominated.contains(&name) || is_credential_header(&name) {
                continue;
            }
            if self.allowed_request_headers.contains(&name) {
                forwarded.push((name, value));
            }
        }
        let authorization = authorization_value(server_token)?;
        forwarded.push((HeaderName::parse("authorization")?, authorization));
        Ok(ForwardPlan {
            headers: forwarded,
            body_bytes: request.body_bytes,
            upstream_timeout_ticks: self.upstream_timeout_ticks,
        })
    }

    pub fn plan_response(
        &self,
        headers: Vec<(HeaderName, HeaderValue)>,
        body_bytes: usize,
    ) -> Result<ForwardPlan, ProxyError> {
        if body_bytes > self.maximum_response_bytes {
            return Err(ProxyError::ResponseTooLarge);
        }
        let nominated = connection_nominations(&headers)?;
        let mut seen = BTreeSet::new();
        let mut forwarded = Vec::new();
        for (name, value) in headers {
            if !seen.insert(name.clone()) {
                return Err(ProxyError::DuplicateHeader);
            }
            if is_hop_by_hop(&name) || nominated.contains(&name) || is_credential_header(&name) {
                continue;
            }
            if self.allowed_response_headers.contains(&name) {
                forwarded.push((name, value));
            }
        }
        Ok(ForwardPlan {
            headers: forwarded,
            body_bytes,
            upstream_timeout_ticks: self.upstream_timeout_ticks,
        })
    }
}

fn connection_nominations(
    headers: &[(HeaderName, HeaderValue)],
) -> Result<BTreeSet<HeaderName>, ProxyError> {
    let mut nominations = BTreeSet::new();
    let mut connection_seen = false;
    for (name, value) in headers {
        if name.as_str() != "connection" {
            continue;
        }
        if connection_seen {
            return Err(ProxyError::DuplicateHeader);
        }
        connection_seen = true;
        for item in value.as_ascii()?.split(',') {
            let item = item.trim();
            if item.is_empty() {
                return Err(ProxyError::InvalidConnectionHeader);
            }
            nominations.insert(HeaderName::parse(item)?);
        }
    }
    Ok(nominations)
}

fn authorization_value(server_token: SecretValue) -> Result<HeaderValue, ProxyError> {
    let mut value = Vec::with_capacity(7 + server_token.len());
    value.extend_from_slice(b"Bearer ");
    value.extend_from_slice(server_token.expose());
    HeaderValue::new(value)
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

fn is_credential_header(name: &HeaderName) -> bool {
    CREDENTIAL_HEADERS.contains(&name.as_str())
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|'
        )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyError {
    InvalidPolicy,
    InvalidHeaderName,
    InvalidHeaderValue,
    DuplicateHeader,
    InvalidConnectionHeader,
    RequestTooLarge,
    ResponseTooLarge,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "proxy policy is invalid",
            Self::InvalidHeaderName => "proxy header name is invalid",
            Self::InvalidHeaderValue => "proxy header value is invalid",
            Self::DuplicateHeader => "proxy header is duplicated",
            Self::InvalidConnectionHeader => "proxy Connection header is invalid",
            Self::RequestTooLarge => "proxy request body exceeds its bound",
            Self::ResponseTooLarge => "proxy response body exceeds its bound",
        })
    }
}

impl Error for ProxyError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> Result<HeaderName, ProxyError> {
        HeaderName::parse(value)
    }

    fn value(value: &str) -> Result<HeaderValue, ProxyError> {
        HeaderValue::new(value.as_bytes().to_vec())
    }

    fn policy() -> Result<ProxyPolicy, ProxyError> {
        ProxyPolicy::new(
            [
                name("accept")?,
                name("content-type")?,
                name("x-request-id")?,
            ],
            [name("content-type")?, name("cache-control")?],
            1024,
            2048,
            50,
        )
    }

    #[test]
    fn inbound_credentials_are_replaced_by_the_server_token() -> Result<(), Box<dyn Error>> {
        let plan = policy()?.plan_request(
            ProxyRequest {
                headers: vec![
                    (name("authorization")?, value("Bearer attacker")?),
                    (name("x-vault-token")?, value("attacker-token")?),
                    (name("accept")?, value("application/json")?),
                ],
                body_bytes: 0,
            },
            SecretValue::new(b"server-token".to_vec())?,
        )?;
        let authorization = plan
            .headers
            .iter()
            .find(|(header, _)| header.as_str() == "authorization")
            .ok_or_else(|| std::io::Error::other("authorization was not injected"))?;
        assert_eq!(b"Bearer server-token", authorization.1.expose());
        assert_eq!(
            1,
            plan.headers
                .iter()
                .filter(|(header, _)| header.as_str() == "authorization")
                .count()
        );
        Ok(())
    }

    #[test]
    fn connection_nominated_headers_cannot_be_smuggled() -> Result<(), Box<dyn Error>> {
        let plan = policy()?.plan_request(
            ProxyRequest {
                headers: vec![
                    (name("connection")?, value("x-request-id")?),
                    (name("x-request-id")?, value("must-not-forward")?),
                    (name("accept")?, value("application/json")?),
                ],
                body_bytes: 1,
            },
            SecretValue::new(b"server-token".to_vec())?,
        )?;
        assert!(
            plan.headers
                .iter()
                .all(|(header, _)| header.as_str() != "x-request-id")
        );
        Ok(())
    }

    #[test]
    fn duplicate_and_oversized_requests_fail_closed() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            Err(ProxyError::DuplicateHeader),
            policy()?.plan_request(
                ProxyRequest {
                    headers: vec![
                        (name("accept")?, value("one")?),
                        (name("accept")?, value("two")?),
                    ],
                    body_bytes: 0,
                },
                SecretValue::new(b"server-token".to_vec())?,
            )
        );
        assert_eq!(
            Err(ProxyError::RequestTooLarge),
            policy()?.plan_request(
                ProxyRequest {
                    headers: Vec::new(),
                    body_bytes: 1025,
                },
                SecretValue::new(b"server-token".to_vec())?,
            )
        );
        Ok(())
    }

    #[test]
    fn debug_output_never_contains_header_values() -> Result<(), Box<dyn Error>> {
        let request = ProxyRequest {
            headers: vec![(name("authorization")?, value("Bearer hidden")?)],
            body_bytes: 0,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("Bearer hidden"));
        assert!(rendered.contains("[REDACTED]"));
        Ok(())
    }
}
