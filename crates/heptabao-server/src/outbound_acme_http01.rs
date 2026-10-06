//! ACME HTTP01 is public proof fetching, without enrollment tokens or a Vault actor.
//! All DNS/connect/write/header/body work retains one host-owned attempt deadline.
use super::*;
fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "http-01: attempt deadline exceeded".into())
}
trait ProofStream: Read + Write {}
impl<T: Read + Write> ProofStream for T {}

#[derive(Clone, Debug)]
struct ProofTarget {
    scheme: String,
    authority: String,
    host: String,
    port: u16,
    path: String,
}
impl ProofTarget {
    fn parse(value: &str) -> Result<Self, String> {
        let uri: http::Uri = value.parse().map_err(|_| "http-01: invalid redirect URL")?;
        let scheme = uri.scheme_str().ok_or("http-01: invalid redirect scheme")?;
        if !matches!(scheme, "http" | "https") {
            return Err("http-01: unsupported redirect scheme".into());
        }
        let authority = uri
            .authority()
            .ok_or("http-01: missing redirect authority")?;
        if authority.as_str().contains('@') {
            return Err("http-01: redirect userinfo is unsupported".into());
        }
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        if host.is_empty() || !host.is_ascii() {
            return Err("http-01: invalid redirect host".into());
        }
        if authority.port().is_some() && authority.port_u16().is_none() {
            return Err("http-01: invalid redirect port".into());
        }
        let port = authority
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        if port == 0 {
            return Err("http-01: invalid redirect port".into());
        }
        Ok(Self {
            scheme: scheme.into(),
            authority: authority.as_str().into(),
            host: host.into(),
            port,
            path: uri.path_and_query().map_or("/", |p| p.as_str()).into(),
        })
    }
    fn redirect(&self, location: &str) -> Result<Self, String> {
        // net/http counts the full resolved URL, including any fragment, before fetching.
        let (location, fragment) = location
            .split_once('#')
            .map_or((location, None), |p| (p.0, Some(p.1)));
        let value = if location.starts_with("http://") || location.starts_with("https://") {
            location.to_owned()
        } else if location.starts_with("//") {
            format!("{}:{location}", self.scheme)
        } else {
            if location
                .split('/')
                .next()
                .is_some_and(|part| part.contains(':'))
            {
                return Err("http-01: unsupported redirect scheme".into());
            }
            let path = if location.is_empty() {
                self.path.clone()
            } else if location.starts_with('/') {
                location.to_owned()
            } else if location.starts_with('?') {
                format!("{}{location}", self.path.split('?').next().unwrap_or("/"))
            } else {
                let current = self.path.split('?').next().unwrap_or("/");
                let directory = current.rsplit_once('/').map_or("/", |p| p.0);
                format!("{directory}/{location}")
            };
            let (path, query) = path
                .split_once('?')
                .map_or((path.as_str(), None), |p| (p.0, Some(p.1)));
            let mut components = Vec::new();
            for component in path.split('/') {
                match component {
                    "." => {}
                    ".." => {
                        if components.len() > 1 {
                            components.pop();
                        }
                    }
                    _ => components.push(component),
                }
            }
            if path.ends_with("/.") || path.ends_with("/..") {
                components.push("");
            }
            let mut path = components.join("/");
            if let Some(query) = query {
                path.push('?');
                path.push_str(query);
            }
            format!("{}://{}{path}", self.scheme, self.authority)
        };
        let resolved_length = value.len()
            + fragment
                .filter(|f| !f.is_empty())
                .map_or(0, |f| f.len() + 1);
        if resolved_length > 2000 {
            return Err(format!(
                "http-01: redirect url length too long: {}",
                resolved_length
            ));
        }
        Self::parse(&value)
    }
    fn connect(&self, deadline: Instant) -> Result<Box<dyn ProofStream>, String> {
        let addresses = ldap_transport::resolve_addresses(&self.host, self.port, deadline)
            .map_err(|_| "http-01: failed resolving challenge destination".to_owned())?;
        let mut socket = None;
        for address in addresses {
            if let Ok(stream) = TcpStream::connect_timeout(
                &address,
                remaining(deadline)?.min(Duration::from_secs(10)),
            ) {
                socket = Some(stream);
                break;
            }
        }
        let stream = socket.ok_or_else(|| "http-01: failed to fetch challenge path".to_owned())?;
        let socket = DeadlineSocket { stream, deadline };
        if self.scheme == "http" {
            return Ok(Box::new(socket));
        }
        // ACME proof HTTPS follows OpenBao's InsecureSkipVerify transport. This connector
        // carries no actor, provider credential, enrollment or client certificate.
        let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .map_err(|_| "http-01: failed to configure proof TLS".to_owned())?;
        builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
        builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::OFF);
        builder
            .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
            .map_err(|_| "http-01: failed to configure proof TLS".to_owned())?;
        let mut configuration = builder
            .build()
            .configure()
            .map_err(|_| "http-01: failed to configure proof TLS".to_owned())?;
        configuration.set_verify_hostname(false);
        let stream = configuration
            .connect(&self.host, socket)
            .map_err(|_| "http-01: failed proof TLS handshake".to_owned())?;
        remaining(deadline)?;
        Ok(Box::new(stream))
    }
}
pub(crate) fn verify_http01(
    host: &str,
    port: u16,
    token: &str,
    thumbprint: &str,
    deadline: Instant,
) -> Result<(), String> {
    let authority = if host.contains(':') {
        if port == 80 {
            format!("[{host}]")
        } else {
            format!("[{host}]:{port}")
        }
    } else if port == 80 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let mut target = ProofTarget::parse(&format!(
        "http://{authority}/.well-known/acme-challenge/{token}"
    ))?;
    let mut redirect_count = 0;
    loop {
        remaining(deadline)?;
        let mut stream = target.connect(deadline)?;
        let head = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            target.path, target.authority
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|_| "http-01: failed to fetch challenge path".to_owned())?;
        let mut budget = 16 * 1024;
        let status = line(&mut stream, &mut budget)
            .map_err(|_| "http-01: invalid response headers".to_owned())?;
        let status = std::str::from_utf8(&status)
            .map_err(|_| "http-01: invalid response status".to_owned())?;
        let mut parts = status.splitn(3, ' ');
        let version = parts.next();
        let code = parts
            .next()
            .filter(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_digit()));
        if !matches!(version, Some("HTTP/1.0" | "HTTP/1.1"))
            || code.is_none()
            || parts.next().is_none()
        {
            return Err("http-01: invalid response status".into());
        }
        let code = code
            .unwrap_or("")
            .parse::<u16>()
            .map_err(|_| "http-01: invalid response status")?;
        let mut headers = BTreeMap::new();
        loop {
            let raw = line(&mut stream, &mut budget)
                .map_err(|_| "http-01: invalid response headers".to_owned())?;
            if raw.is_empty() {
                break;
            }
            let raw = std::str::from_utf8(&raw)
                .map_err(|_| "http-01: invalid response header".to_owned())?;
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
            if headers
                .insert(key.clone(), value.trim().to_owned())
                .is_some()
                && matches!(key.as_str(), "content-length" | "transfer-encoding")
            {
                return Err("http-01: ambiguous response framing".into());
            }
        }
        if matches!(code, 301 | 302 | 303 | 307 | 308)
            && let Some(location) = headers.get("location").filter(|s| !s.is_empty())
        {
            redirect_count += 1;
            if redirect_count + 1 >= 10 {
                return Err(format!(
                    "http-01: too many redirects: {}",
                    redirect_count + 1
                ));
            }
            target = target.redirect(location)?;
            continue;
        }
        return verify_body(stream, headers, budget, token, thumbprint, deadline);
    }
}
fn verify_body(
    mut stream: Box<dyn ProofStream>,
    headers: BTreeMap<String, String>,
    mut budget: usize,
    token: &str,
    thumbprint: &str,
    deadline: Instant,
) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    fn request(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 2048);
        }
        String::from_utf8(bytes).unwrap()
    }
    #[test]
    fn pki_acme99_http01_eight_redirects_and_ninth_refusal_real_network() {
        for redirects in [8, 9] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = thread::spawn(move || {
                let mut paths = Vec::new();
                for step in 0..=8 {
                    let (mut socket, _) = listener.accept().unwrap();
                    paths.push(request(&mut socket));
                    let response = if step < redirects {
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: /step/{}/token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            step + 1
                        )
                    } else {
                        "HTTP/1.1 500 Result\r\nContent-Length: 11\r\nConnection: close\r\n\r\ntoken.thumb".to_owned()
                    };
                    socket.write_all(response.as_bytes()).unwrap();
                }
                paths
            });
            let result = verify_http01(
                "127.0.0.1",
                port,
                "token",
                "thumb",
                Instant::now() + Duration::from_secs(5),
            );
            if redirects == 8 {
                assert!(result.is_ok(), "{result:?}");
            } else {
                assert_eq!(result.unwrap_err(), "http-01: too many redirects: 10");
            }
            let paths = server.join().unwrap();
            assert_eq!(paths.len(), 9);
            assert!(paths[0].starts_with("GET /.well-known/acme-challenge/token HTTP/1.1"));
            assert!(paths[8].starts_with("GET /step/8/token HTTP/1.1"));
        }
    }
    #[test]
    fn pki_acme99_http01_relative_query_url_bound_and_same_attempt_deadline() {
        let target =
            ProofTarget::parse("http://127.0.0.1:80/.well-known/acme-challenge/token").unwrap();
        let relative = target.redirect("../proof/token?exact=unchanged").unwrap();
        assert_eq!(relative.path, "/.well-known/proof/token?exact=unchanged");
        assert_eq!(
            target.redirect("?q=exact").unwrap().path,
            "/.well-known/acme-challenge/token?q=exact"
        );
        assert!(
            target
                .redirect(&format!("/proof?{}", "x".repeat(2001)))
                .unwrap_err()
                .contains("url length too long")
        );
        assert!(
            target
                .redirect(&format!("/proof#{}", "x".repeat(2001)))
                .unwrap_err()
                .contains("url length too long")
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            request(&mut first);
            first.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /slow-proof\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            let (mut second, _) = listener.accept().unwrap();
            assert!(request(&mut second).starts_with("GET /slow-proof HTTP/1.1"));
            thread::sleep(Duration::from_millis(200));
            let _ = second.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\ntoken.thumb",
            );
        });
        let deadline = Instant::now() + Duration::from_millis(100);
        assert!(verify_http01("127.0.0.1", port, "token", "thumb", deadline).is_err());
        assert!(Instant::now() >= deadline);
        server.join().unwrap();
    }
}
