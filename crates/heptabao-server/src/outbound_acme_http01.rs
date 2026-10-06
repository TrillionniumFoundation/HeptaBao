//! ACME HTTP01 is public proof fetching, without enrollment tokens or a Vault actor.
//! All DNS/connect/write/header/body work retains one host-owned attempt deadline.
use super::*;
fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "http-01: attempt deadline exceeded".into())
}
pub(crate) fn verify_http01(
    host: &str,
    port: u16,
    token: &str,
    thumbprint: &str,
    deadline: Instant,
) -> Result<(), String> {
    let addresses = ldap_transport::resolve_addresses(host, port, deadline)
        .map_err(|_| "http-01: failed resolving challenge destination".to_owned())?;
    let mut socket = None;
    for address in addresses {
        if let Ok(stream) =
            TcpStream::connect_timeout(&address, remaining(deadline)?.min(Duration::from_secs(10)))
        {
            socket = Some(stream);
            break;
        }
    }
    let stream = socket.ok_or_else(|| "http-01: failed to fetch challenge path".to_owned())?;
    let mut stream = DeadlineSocket { stream, deadline };
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let head = format!(
        "GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {authority}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| "http-01: failed to fetch challenge path".to_owned())?;
    let mut budget = 16 * 1024;
    let status = line(&mut stream, &mut budget)
        .map_err(|_| "http-01: invalid response headers".to_owned())?;
    let status =
        std::str::from_utf8(&status).map_err(|_| "http-01: invalid response status".to_owned())?;
    let mut parts = status.splitn(3, ' ');
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || !parts
            .next()
            .is_some_and(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_digit()))
        || parts.next().is_none()
    {
        return Err("http-01: invalid response status".into());
    }
    let mut headers = BTreeMap::new();
    loop {
        let raw = line(&mut stream, &mut budget)
            .map_err(|_| "http-01: invalid response headers".to_owned())?;
        if raw.is_empty() {
            break;
        }
        let raw =
            std::str::from_utf8(&raw).map_err(|_| "http-01: invalid response header".to_owned())?;
        let (key, value) = raw
            .split_once(':')
            .ok_or_else(|| "http-01: invalid response header".to_owned())?;
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b < 32 && b != 9 || b == 127)
        {
            return Err("http-01: invalid response header".into());
        }
        let key = key.to_ascii_lowercase();
        // Only framing duplicates can alter the accepted body boundary.
        if headers
            .insert(key.clone(), value.trim().to_owned())
            .is_some()
            && matches!(key.as_str(), "content-length" | "transfer-encoding")
        {
            return Err("http-01: ambiguous response framing".into());
        }
    }
    let mut body = Vec::new();
    match (
        headers.get("content-length"),
        headers.get("transfer-encoding"),
    ) {
        (Some(_), Some(_)) => return Err("http-01: ambiguous response framing".into()),
        (Some(length), None) => {
            let n = length
                .parse::<usize>()
                .map_err(|_| "http-01: invalid response length".to_owned())?;
            if n > 512 {
                return Err(format!(
                    "http-01: response too large: received {n} > 512 bytes"
                ));
            }
            body.resize(n, 0);
            stream
                .read_exact(&mut body)
                .map_err(|_| "http-01: unexpected error while reading body".to_owned())?;
        }
        (None, Some(encoding)) if encoding.eq_ignore_ascii_case("chunked") => loop {
            let raw = line(&mut stream, &mut budget)
                .map_err(|_| "http-01: invalid chunk framing".to_owned())?;
            let raw = std::str::from_utf8(&raw)
                .map_err(|_| "http-01: invalid chunk framing".to_owned())?;
            let n = usize::from_str_radix(raw.split(';').next().unwrap_or(""), 16)
                .map_err(|_| "http-01: invalid chunk framing".to_owned())?;
            if n == 0 {
                loop {
                    if line(&mut stream, &mut budget)
                        .map_err(|_| "http-01: invalid trailer".to_owned())?
                        .is_empty()
                    {
                        break;
                    }
                }
                break;
            }
            if n > 512 - body.len() {
                return Err("http-01: response too large: received 513 > 512 bytes".into());
            }
            let start = body.len();
            body.resize(start + n, 0);
            stream
                .read_exact(&mut body[start..])
                .map_err(|_| "http-01: unexpected error while reading body".to_owned())?;
            if !line(&mut stream, &mut budget)
                .map_err(|_| "http-01: invalid chunk framing".to_owned())?
                .is_empty()
            {
                return Err("http-01: invalid chunk framing".into());
            }
        },
        (None, None) => {
            stream
                .take(513)
                .read_to_end(&mut body)
                .map_err(|_| "http-01: unexpected error while reading body".to_owned())?;
            if body.len() > 512 {
                return Err("http-01: response too large: received 513 > 512 bytes".into());
            }
        }
        _ => return Err("http-01: unsupported response encoding".into()),
    }
    remaining(deadline)?;
    let expected = token.len() + 1 + thumbprint.len();
    if body.len() < expected {
        return Err(format!(
            "http-01: response too small: received {} < {expected} bytes",
            body.len()
        ));
    }
    let proof = std::str::from_utf8(&body)
        .map_err(|_| "key authorization was invalid".to_owned())?
        .trim();
    let parts = proof.split('.').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err(format!(
            "invalid authorization: got {} parts, expected 2",
            parts.len()
        ));
    }
    if parts[0] != token || parts[1] != thumbprint {
        return Err("key authorization was invalid".into());
    }
    Ok(())
}
