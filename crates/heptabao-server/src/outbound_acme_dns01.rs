//! Public DNS01 proof uses one queued attempt deadline and never a Vault actor.
use super::*;
use base64::Engine;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "dns-01: attempt deadline exceeded".into())
}
fn resolvers(configured: &str) -> Result<Vec<SocketAddr>, String> {
    if !configured.is_empty() {
        return configured
            .parse::<SocketAddr>()
            .map(|a| vec![a])
            .map_err(|_| "dns-01: invalid configured resolver".into());
    }
    let mut config = String::new();
    std::fs::File::open("/etc/resolv.conf")
        .and_then(|file| file.take(128 * 1024 + 1).read_to_string(&mut config))
        .map_err(|_| "dns-01: system resolver configuration unavailable")?;
    if config.len() > 128 * 1024 {
        return Err("dns-01: resolver configuration exceeds bound".into());
    }
    let servers = config
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| {
                    fields
                        .next()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .map(|ip| SocketAddr::new(ip, 53))
                })
                .flatten()
        })
        .take(3)
        .collect::<Vec<_>>();
    if servers.is_empty() {
        return Err("dns-01: no system resolver available".into());
    }
    Ok(servers)
}
fn wire_name(name: &str) -> Result<Vec<u8>, String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.len() > 253 || name.is_empty() || !name.is_ascii() {
        return Err("dns-01: invalid DNS name".into());
    }
    let mut out = Vec::new();
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || label.bytes().any(|b| b <= 32 || b >= 127) {
            return Err("dns-01: invalid DNS label".into());
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}
fn query(name: &str) -> Result<(Vec<u8>, [u8; 2]), String> {
    let id = crate::crypto::random::<2>().map_err(|_| "dns-01: query randomness unavailable")?;
    let mut out = id.to_vec();
    out.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend(wire_name(name)?);
    out.extend_from_slice(&[0, 16, 0, 1]);
    Ok((out, id))
}
fn number(raw: &[u8], at: usize) -> Result<u16, String> {
    raw.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| "dns-01: truncated DNS message".into())
}
fn name(raw: &[u8], offset: &mut usize) -> Result<String, String> {
    let mut at = *offset;
    let mut consumed = None;
    let mut labels = Vec::new();
    let mut seen = BTreeSet::new();
    let mut size = 0;
    loop {
        if !seen.insert(at) || seen.len() > 128 {
            return Err("dns-01: invalid DNS compression".into());
        }
        let length = *raw.get(at).ok_or("dns-01: truncated DNS name")?;
        at += 1;
        if length == 0 {
            *offset = consumed.unwrap_or(at);
            break;
        }
        if length & 0xc0 == 0xc0 {
            let tail = *raw.get(at).ok_or("dns-01: truncated DNS pointer")?;
            at += 1;
            consumed.get_or_insert(at);
            at = ((length as usize & 0x3f) << 8) | tail as usize;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err("dns-01: invalid DNS label length".into());
        }
        let part = raw
            .get(at..at + length as usize)
            .ok_or("dns-01: truncated DNS label")?;
        if !part.is_ascii() || part.iter().any(|b| *b <= 32 || *b >= 127) {
            return Err("dns-01: invalid DNS name bytes".into());
        }
        at += length as usize;
        size += part.len() + 1;
        if size > 254 {
            return Err("dns-01: DNS name exceeds bound".into());
        }
        labels.push(String::from_utf8_lossy(part).to_ascii_lowercase());
    }
    Ok(labels.join("."))
}
fn parse(raw: &[u8], id: [u8; 2], question: &str) -> Result<Vec<String>, String> {
    if raw.len() < 12 || raw[..2] != id {
        return Err("dns-01: invalid DNS transaction".into());
    }
    let flags = number(raw, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0xf != 0 || number(raw, 4)? != 1 {
        return Err("dns-01: DNS response rejected".into());
    }
    let question = question.trim_end_matches('.').to_ascii_lowercase();
    let mut at = 12;
    if name(raw, &mut at)? != question || number(raw, at)? != 16 || number(raw, at + 2)? != 1 {
        return Err("dns-01: DNS question mismatch".into());
    }
    at += 4;
    let answers = number(raw, 6)? as usize;
    let total = answers + number(raw, 8)? as usize + number(raw, 10)? as usize;
    if total > 2048 {
        return Err("dns-01: excessive DNS record count".into());
    }
    let mut txt = Vec::new();
    let mut aliases = Vec::new();
    for index in 0..total {
        let owner = name(raw, &mut at)?;
        let kind = number(raw, at)?;
        let class = number(raw, at + 2)?;
        let size = number(raw, at + 8)? as usize;
        at += 10;
        let end = at
            .checked_add(size)
            .filter(|end| *end <= raw.len())
            .ok_or("dns-01: truncated DNS record")?;
        if index < answers && class == 1 && kind == 5 {
            let mut value = at;
            let alias = name(raw, &mut value)?;
            if value != end {
                return Err("dns-01: invalid CNAME framing".into());
            }
            aliases.push((owner.clone(), alias));
        }
        if index < answers && class == 1 && kind == 16 {
            let mut text = Vec::new();
            let mut value = at;
            while value < end {
                let size = raw[value] as usize;
                value += 1;
                let next = value
                    .checked_add(size)
                    .filter(|n| *n <= end)
                    .ok_or("dns-01: invalid TXT framing")?;
                text.extend_from_slice(&raw[value..next]);
                value = next;
            }
            txt.push((owner, String::from_utf8_lossy(&text).into_owned()));
        }
        at = end;
    }
    if at != raw.len() {
        return Err("dns-01: trailing DNS data".into());
    }
    let mut owner = question;
    let mut seen = BTreeSet::new();
    for _ in 0..16 {
        if !seen.insert(owner.clone()) {
            return Err("dns-01: CNAME cycle".into());
        }
        if let Some((_, next)) = aliases.iter().find(|(name, _)| name == &owner) {
            owner = next.clone();
        } else {
            break;
        }
    }
    if aliases.iter().any(|(name, _)| name == &owner) {
        return Err("dns-01: CNAME chain exceeds bound".into());
    }
    Ok(txt
        .into_iter()
        .filter(|(name, _)| name == &owner)
        .map(|(_, text)| text)
        .collect())
}
fn exchange(address: SocketAddr, query: &[u8], deadline: Instant) -> Result<Vec<u8>, String> {
    let bind = SocketAddr::new(
        if address.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        },
        0,
    );
    let socket = UdpSocket::bind(bind).map_err(|_| "dns-01: resolver socket unavailable")?;
    socket
        .connect(address)
        .map_err(|_| "dns-01: resolver unavailable")?;
    socket
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|_| "dns-01: resolver timeout unavailable")?;
    socket
        .send(query)
        .map_err(|_| "dns-01: DNS request failed")?;
    socket
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|_| "dns-01: resolver timeout unavailable")?;
    let mut raw = vec![0; 65535];
    let n = socket
        .recv(&mut raw)
        .map_err(|_| "dns-01: DNS response unavailable")?;
    raw.truncate(n);
    if raw.len() < 12 || raw[..2] != query[..2] || number(&raw, 2)? & 0x8000 == 0 {
        return Err("dns-01: invalid DNS transaction".into());
    }
    if number(&raw, 2)? & 0x0200 != 0 {
        let stream = TcpStream::connect_timeout(&address, remaining(deadline)?)
            .map_err(|_| "dns-01: resolver TCP unavailable")?;
        let mut stream = DeadlineSocket { stream, deadline };
        let length = u16::try_from(query.len()).map_err(|_| "dns-01: query exceeds bound")?;
        stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| stream.write_all(query))
            .map_err(|_| "dns-01: TCP query failed")?;
        let mut size = [0; 2];
        stream
            .read_exact(&mut size)
            .map_err(|_| "dns-01: TCP response unavailable")?;
        raw.resize(u16::from_be_bytes(size) as usize, 0);
        stream
            .read_exact(&mut raw)
            .map_err(|_| "dns-01: truncated TCP response")?;
    }
    remaining(deadline)?;
    Ok(raw)
}
fn validate_records(
    records: &[String],
    token: &str,
    thumbprint: &str,
    deadline: Instant,
) -> Result<(), String> {
    let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::crypto::digest(
        format!("{token}.{thumbprint}").as_bytes(),
    ));
    let matched = records.iter().any(|record| record == &proof);
    remaining(deadline)?;
    if matched {
        Ok(())
    } else {
        Err(format!(
            "dns-01: challenge failed against {} records",
            records.len()
        ))
    }
}
pub(crate) fn verify_dns01(
    host: &str,
    token: &str,
    thumbprint: &str,
    resolver: &str,
    deadline: Instant,
) -> Result<(), String> {
    let question = format!("_acme-challenge.{host}");
    let (message, id) = query(&question)?;
    let mut last = "dns-01: no resolver completed".to_owned();
    for address in resolvers(resolver)? {
        match exchange(address, &message, deadline).and_then(|raw| parse(&raw, id, &question)) {
            Ok(records) => return validate_records(&records, token, thumbprint, deadline),
            Err(error) => last = error,
        }
        remaining(deadline)?;
    }
    Err(format!(
        "dns-01: failed to lookup TXT records for domain ({question}) via resolver {resolver}: {last}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    pub(super) fn answer(query: &[u8], records: &[Vec<&str>], truncated: bool) -> Vec<u8> {
        let mut out = query[..2].to_vec();
        out.extend_from_slice(&(if truncated { 0x8380u16 } else { 0x8180u16 }).to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(if truncated { 0 } else { records.len() as u16 }).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&query[12..]);
        if !truncated {
            for chunks in records {
                let data = chunks
                    .iter()
                    .flat_map(|s| std::iter::once(s.len() as u8).chain(s.bytes()))
                    .collect::<Vec<_>>();
                out.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 30]);
                out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                out.extend(data);
            }
        }
        out
    }
    #[test]
    fn pki_acme99_dns01_actual_udp_txt_split_multiple_tcp_and_wrong_proof() -> TestResult {
        for mode in ["plain", "split", "multiple", "TCP", "wrong"] {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            let address = socket.local_addr()?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            let tcp = if mode == "TCP" {
                Some(TcpListener::bind(address)?)
            } else {
                None
            };
            let server = std::thread::spawn(move || -> io::Result<()> {
                let mut bytes = vec![0; 2048];
                let (size, peer) = socket.recv_from(&mut bytes)?;
                bytes.truncate(size);
                let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(crate::crypto::digest(b"token.thumb"));
                let records = match mode {
                    "split" => vec![vec![&proof[..13], &proof[13..]]],
                    "multiple" => vec![vec!["wrong"], vec![proof.as_str()]],
                    "wrong" => vec![vec!["wrong"]],
                    _ => vec![vec![proof.as_str()]],
                };
                socket.send_to(&answer(&bytes, &records, mode == "TCP"), peer)?;
                if let Some(tcp) = tcp {
                    let (mut stream, _) = tcp.accept()?;
                    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                    let mut length = [0; 2];
                    stream.read_exact(&mut length)?;
                    let mut request = vec![0; u16::from_be_bytes(length) as usize];
                    stream.read_exact(&mut request)?;
                    assert_eq!(request, bytes);
                    let response = answer(&request, &records, false);
                    stream.write_all(&(response.len() as u16).to_be_bytes())?;
                    stream.write_all(&response)?;
                }
                Ok(())
            });
            let result = verify_dns01(
                "proof.example",
                "token",
                "thumb",
                &address.to_string(),
                Instant::now() + Duration::from_secs(3),
            );
            server.join().map_err(|_| "DNS fixture thread failed")??;
            if mode == "wrong" {
                assert_eq!(
                    result.as_ref().err().map(String::as_str),
                    Some("dns-01: challenge failed against 1 records")
                );
            } else {
                assert!(result.is_ok(), "{result:?}");
            }
        }
        Ok(())
    }
    #[test]
    fn pki_acme99_dns01_question_transaction_compression_and_original_timeout() -> TestResult {
        let (message, id) = query("_acme-challenge.proof.example")?;
        let raw = answer(&message, &[vec!["proof"]], false);
        assert_eq!(
            parse(&raw, id, "_acme-challenge.proof.example")?,
            vec!["proof"]
        );
        assert!(parse(&raw, [id[0] ^ 1, id[1]], "_acme-challenge.proof.example").is_err());
        assert!(parse(&raw, id, "_acme-challenge.other.example").is_err());
        let mut cycle = raw.clone();
        let offset = message.len();
        cycle[offset] = 0xc0 | ((offset >> 8) as u8 & 0x3f);
        cycle[offset + 1] = offset as u8;
        assert!(parse(&cycle, id, "_acme-challenge.proof.example").is_err());
        let mut trailing = raw;
        trailing.push(0);
        assert!(parse(&trailing, id, "_acme-challenge.proof.example").is_err());
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let deadline = Instant::now() + Duration::from_millis(60);
        assert!(
            verify_dns01(
                "proof.example",
                "token",
                "thumb",
                &socket.local_addr()?.to_string(),
                deadline
            )
            .is_err()
        );
        assert!(Instant::now() >= deadline);
        Ok(())
    }
}

#[cfg(test)]
mod final_deadline_tests {
    use super::*;
    #[test]
    fn pki_acme99_dns01_parsed_actual_txt_cannot_succeed_after_original_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(crate::crypto::digest(b"token.thumb"));
        let (message, id) = query("_acme-challenge.proof.example")?;
        let response =
            super::tests::answer(&message, &[vec!["wrong TXT"], vec![proof.as_str()]], false);
        let records = parse(&response, id, "_acme-challenge.proof.example")?;
        assert!(
            validate_records(
                &records,
                "token",
                "thumb",
                Instant::now() + Duration::from_secs(1)
            )
            .is_ok()
        );
        let original_deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .ok_or("clock underflow")?;
        assert_eq!(
            validate_records(&records, "token", "thumb", original_deadline).as_deref(),
            Err("dns-01: attempt deadline exceeded")
        );
        Ok(())
    }
}
