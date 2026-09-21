//! Shared numeric IP/CIDR token constraints. The peer is supplied by a trusted
//! listener or authenticated HA frame, never inferred from an HTTP header.
use super::*;
use std::net::IpAddr;

const MAX_BOUND_CIDRS: usize = 128;

fn canonical_peer(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(peer),
        _ => peer,
    }
}

fn parse(value: &str) -> Result<(IpAddr, u8, u16), AuthError> {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return Err(bad("invalid token bound CIDR"));
    }
    if !value.contains('/')
        && !value.contains('%')
        && let Ok(socket) = value.parse::<std::net::SocketAddr>()
    {
        let ip = canonical_peer(socket.ip());
        return Ok((ip, if ip.is_ipv4() { 32 } else { 128 }, socket.port()));
    }
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(ip, bits)| (ip, Some(bits)));
    let address: IpAddr = address
        .parse()
        .map_err(|_| bad("invalid token bound CIDR"))?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        None => width,
        Some(bits) if !bits.is_empty() && bits.bytes().all(|b| b.is_ascii_digit()) => bits
            .parse::<u8>()
            .map_err(|_| bad("invalid token CIDR prefix"))?,
        _ => return Err(bad("invalid token CIDR prefix")),
    };
    if prefix > width {
        return Err(bad("invalid token CIDR prefix"));
    }
    if let IpAddr::V6(ip) = address
        && let Some(ip) = ip.to_ipv4_mapped()
    {
        // go-sockaddr v1.0.7 tries IPv4 first. A mapped IPv6 CIDR uses
        // prefix-96 for /96..128, otherwise the first 32 mask bits.
        let prefix = if prefix >= 96 {
            prefix - 96
        } else {
            prefix.min(32)
        };
        return Ok((IpAddr::V4(ip), prefix, 0));
    }
    Ok((address, prefix, 0))
}

fn canonical(value: &str) -> Result<String, AuthError> {
    let (address, prefix, port) = parse(value)?;
    if port != 0 {
        return Ok(std::net::SocketAddr::new(address, port).to_string());
    }
    if prefix == if address.is_ipv4() { 32 } else { 128 } {
        Ok(address.to_string())
    } else {
        // Preserve host bits for API readback; containment masks both operands.
        Ok(format!("{address}/{prefix}"))
    }
}

pub(super) fn field(body: &Value) -> Result<Vec<String>, AuthError> {
    let values = match body.get("token_bound_cidrs") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .collect(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::trim)
                    .ok_or_else(|| bad("token bound CIDRs must contain strings"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(bad(
                "token bound CIDRs must be a list or comma-separated string",
            ));
        }
    };
    if values.len() > MAX_BOUND_CIDRS {
        return Err(bad("too many token bound CIDRs"));
    }
    values.into_iter().map(canonical).collect()
}

pub(super) fn validate(values: &[String]) -> Result<(), AuthError> {
    if values.len() > MAX_BOUND_CIDRS {
        return Err(bad("too many token bound CIDRs"));
    }
    for value in values {
        if canonical(value)? != *value {
            return Err(bad("noncanonical stored token bound CIDR"));
        }
    }
    Ok(())
}

pub(super) fn check(values: &[String], peer: Option<IpAddr>) -> Result<(), AuthError> {
    if values.is_empty() {
        return Ok(());
    }
    let peer = canonical_peer(peer.ok_or_else(denied)?);
    for value in values {
        let (network, prefix, _) = parse(value).map_err(|_| denied())?;
        let allowed = match (network, peer) {
            (IpAddr::V4(network), IpAddr::V4(peer)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(network) & mask == u32::from(peer) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(peer)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(network) & mask == u128::from(peer) & mask
            }
            _ => false,
        };
        if allowed {
            return Ok(());
        }
    }
    Err(denied())
}

impl AuthState {
    pub(crate) fn has_token_bound_cidrs(&self) -> bool {
        self.tokens
            .values()
            .any(|token| !token.bound_cidrs.is_empty())
            || self.radius_mounts.values().any(|mounts| {
                mounts.values().any(|mount| {
                    mount
                        .native
                        .as_ref()
                        .is_some_and(|config| config.has_bound_cidrs())
                })
            })
            || self.has_ldap_token_bound_cidrs()
            || self.has_kube_role_bound_cidrs()
            || self.has_userpass_token_bound_cidrs()
    }
    pub(crate) fn has_ldap_token_bound_cidrs(&self) -> bool {
        self.ldap_mounts.values().any(|mounts| {
            mounts.values().any(|mount| {
                mount
                    .native
                    .as_ref()
                    .is_some_and(|config| config.has_bound_cidrs())
            })
        }) || self.tokens.values().any(|token| {
            !token.bound_cidrs.is_empty()
                && matches!(
                    token.auth_provenance.as_ref(),
                    Some(TokenAuthProvenance::LdapNative { .. })
                )
        })
    }
    pub(super) fn validate_token_bound_cidrs(&self) -> Result<(), AuthError> {
        for token in self.tokens.values() {
            validate(&token.bound_cidrs)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn cidr_host_bits_full_prefixes_and_families_are_preserved() -> TestResult {
        let values =
            field(&json!({"token_bound_cidrs":["127.0.0.2/24","::1/128","2001:DB8::a/64"]}))?;
        assert_eq!(values, ["127.0.0.2/24", "::1", "2001:db8::a/64"]);
        validate(&values)?;
        check(&values, Some("127.0.0.1".parse()?))?;
        check(&values, Some("2001:db8::ffff".parse()?))?;
        assert!(check(&values, Some("2001:db9::a".parse()?)).is_err());
        assert!(check(&values, None).is_err());
        assert!(check(&values, Some("127.0.1.1".parse()?)).is_err());
        check(
            &field(&json!({"token_bound_cidrs":["0.0.0.0/0"]}))?,
            Some("203.0.113.5".parse()?),
        )?;
        assert!(
            check(
                &field(&json!({"token_bound_cidrs":["0.0.0.0/0"]}))?,
                Some("::1".parse()?)
            )
            .is_err()
        );
        check(&[], None)?;
        Ok(())
    }

    #[test]
    fn mapped_ipv6_and_numeric_ports_match_pinned_sockaddr_semantics() -> TestResult {
        for (input, expected) in [
            ("::ffff:127.0.0.1", "127.0.0.1"),
            ("::ffff:127.0.0.1/128", "127.0.0.1"),
            ("::ffff:127.0.0.2/120", "127.0.0.2/24"),
            ("::ffff:127.0.0.2/80", "127.0.0.2"),
            ("::ffff:127.0.0.2/24", "127.0.0.2/24"),
            ("::ffff:127.0.0.2/0", "127.0.0.2/0"),
            ("[::ffff:127.0.0.1]:999", "127.0.0.1:999"),
            ("[::1]:999", "[::1]:999"),
        ] {
            assert_eq!(canonical(input)?, expected);
        }
        check(&["127.0.0.1:999".into()], Some("::ffff:127.0.0.1".parse()?))?;
        check(&["[::1]:999".into()], Some("::1".parse()?))?;
        assert!(check(&["::/0".into()], Some("::ffff:127.0.0.1".parse()?)).is_err());
        assert!(check(&["127.0.0.2".into()], Some("::ffff:127.0.0.1".parse()?)).is_err());
        Ok(())
    }

    #[test]
    fn malformed_and_oversize_cidrs_fail_closed_and_null_clears() -> TestResult {
        for value in [
            "localhost",
            "127.0.0.1/33",
            "::1/129",
            "::1/-1",
            "[::1]",
            "fe80::1%eth0",
            "10.0.0.1/1/1",
        ] {
            assert!(field(&json!({"token_bound_cidrs":[value]})).is_err());
        }
        assert!(field(&json!({"token_bound_cidrs":vec!["127.0.0.1"; MAX_BOUND_CIDRS+1]})).is_err());
        assert!(validate(&["127.0.0.1/32".into()]).is_err());
        assert!(field(&json!({"token_bound_cidrs":null}))?.is_empty());
        assert!(field(&json!({"token_bound_cidrs":[]}))?.is_empty());
        Ok(())
    }
}
