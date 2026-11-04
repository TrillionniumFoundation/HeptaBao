//! Real parser/dispatch helpers; these tests make no public TLS or LAN claim.
use super::*;
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(crate) struct Wire {
    pub(crate) status: u16,
    pub(crate) headers: BTreeMap<String, Vec<String>>,
    pub(crate) body: Vec<u8>,
}

impl Wire {
    pub(crate) fn header(&self, name: &str) -> &[String] {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map_or(&[], Vec::as_slice)
    }
    pub(crate) fn json(&self) -> TestResult<Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

pub(crate) fn decode_wire(bytes: Vec<u8>) -> TestResult<Wire> {
    let boundary = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or("complete fixture HTTP head")?;
    let header = std::str::from_utf8(&bytes[..boundary])?;
    let mut lines = header.split("\r\n");
    let first = lines.next().ok_or("status line")?;
    let mut status = first.splitn(3, ' ');
    assert_eq!(status.next(), Some("HTTP/1.1"));
    let status = status.next().ok_or("status code")?.parse::<u16>()?;
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    for line in lines {
        let (name, value) = line.split_once(": ").ok_or("header line")?;
        headers
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(value.to_owned());
    }
    let body = bytes[boundary + 4..].to_vec();
    assert!(
        !headers.contains_key("transfer-encoding"),
        "fixture replies are deliberately small"
    );
    if let Some(lengths) = headers.get("content-length") {
        assert_eq!(lengths.len(), 1);
        assert_eq!(lengths[0].parse::<usize>()?, body.len());
    } else {
        assert!(matches!(status, 204 | 304) || (100..200).contains(&status));
        assert!(body.is_empty());
    }
    Ok(Wire {
        status,
        headers,
        body,
    })
}

pub(crate) fn wire(
    service: &Arc<Mutex<Service>>,
    raw: &[u8],
    attempt: &[u8; 16],
    deadline: Instant,
) -> TestResult<Wire> {
    let _original = RequestDeadlineScope::enter(deadline);
    let mut input = raw;
    let parsed = read_request_with_ui(
        &mut input,
        deadline.saturating_duration_since(Instant::now()),
        true,
        false,
    );
    let (reply, head, namespace) = process_parsed_request(
        service,
        None,
        parsed,
        &mut input,
        None,
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        attempt,
        consistency::Settings::default(),
        deadline,
    );
    let mut bytes = Vec::new();
    reply.write_with_namespace(&mut bytes, head, &namespace)?;
    decode_wire(bytes)
}

pub(crate) fn project_response(response: Response) -> TestResult<Wire> {
    let reply = snapshot::project_local_redirect(snapshot::NativeReply::Json(response));
    let mut bytes = Vec::new();
    reply.write(&mut bytes, false)?;
    decode_wire(bytes)
}

pub(crate) fn request(
    method: &str,
    target: &str,
    token: &str,
    headers: &str,
    body: &Value,
) -> Vec<u8> {
    let body = serde_json::to_vec(body).expect("synthetic JSON object");
    let mut bytes = format!("{method} {target} HTTP/1.1\r\nHost: attacker.invalid\r\nX-Forwarded-Host: attacker.invalid\r\nX-Forwarded-Proto: http\r\nX-Vault-Token: {token}\r\n{headers}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(&body);
    bytes
}

#[test]
fn no_forward271_header_uses_first_value_and_preserves_original_target() -> TestResult {
    let target = "/v1/secret/data/target?version=1&ordinary=a%2Fb+z&encoded=x%26y";
    for (fields, expected) in [
        ("", false),
        ("X-Vault-No-Request-Forwarding: \r\n", false),
        ("X-Vault-No-Request-Forwarding: 1\r\n", true),
        ("X-Vault-No-Request-Forwarding: false\r\n", true),
        ("X-Vault-No-Request-Forwarding: 0\r\n", true),
        ("x-VaUlT-nO-rEqUeSt-FoRwArDiNg:\t false \t\r\n", true),
        (
            "X-Vault-No-Request-Forwarding: \r\nx-vault-no-request-forwarding: 1\r\n",
            false,
        ),
        (
            "X-Vault-No-Request-Forwarding: 1\r\nx-vault-no-request-forwarding: \r\n",
            true,
        ),
    ] {
        let bytes = request("GET", target, "synthetic", fields, &json!({}));
        let parsed = read_request_mode(&mut bytes.as_slice(), Duration::from_secs(5), true)
            .map_err(|_| "actual no-forward parser")?;
        assert_eq!(
            parsed
                .logical_data
                .as_ref()
                .is_some_and(|data| data.no_request_forwarding()),
            expected
        );
        assert_eq!(
            parsed
                .no_forward_target
                .as_ref()
                .map(|target| target.as_str()),
            expected.then_some(target)
        );
    }
    for fields in [
        "X-Repeat: 1\r\nX-Repeat: 2\r\n",
        "X-Vault-Unimplemented: 1\r\n",
    ] {
        let bytes = request("GET", target, "synthetic", fields, &json!({}));
        assert!(read_request_mode(&mut bytes.as_slice(), Duration::from_secs(5), true).is_err());
    }
    for bad in [
        "https://attacker.invalid/v1/secret",
        "//attacker.invalid/v1/secret",
        "/v1/secret#fragment",
        "/v1/secret\r\nLocation:evil",
    ] {
        assert!(crate::request_metadata::CheckedLocalRedirectTarget::checked(bad).is_err());
    }
    assert!(
        crate::request_metadata::CheckedLocalRedirectTarget::checked(&format!(
            "/v1/{}",
            "x".repeat(8192)
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn no_forward271_binding_and_wire_metadata_cannot_replay_original_ingress() -> TestResult {
    use crate::request_metadata::{CheckedLocalRedirectTarget, DataFrame, Scope};
    let body = json!({"data":{"value":"bound"}});
    let target = "/v1/secret/data/target?encoded=a%2Fb+z&next=x%26y";
    let original = [0x51; 16];
    let ingress = crate::auth::IngressReplyScope::listener(&original);
    let mut frame = DataFrame::default();
    frame.headers.insert(
        crate::request_metadata::NO_FORWARD_HEADER.to_owned(),
        vec!["1".to_owned()],
    );
    let old_bytes = serde_json::to_vec(&frame)?;
    frame.bind_local_redirect(
        CheckedLocalRedirectTarget::checked(target)?,
        ("POST", "secret/data/target", "", &body),
        &original,
    )?;
    assert_eq!(
        serde_json::to_vec(&frame)?,
        old_bytes,
        "local-only profile never changes the old peer frame"
    );
    let decoded: DataFrame = serde_json::from_slice(&old_bytes)?;
    assert!(
        decoded.local_redirect.is_none(),
        "wire fields cannot mint local provenance"
    );
    let forged = serde_json::from_value::<DataFrame>(json!({
        "headers":{"x-vault-no-request-forwarding":["1"]},
        "local_redirect":{"target":target,"binding":vec![0;32],"ingress":vec![0;16]},
    }));
    assert!(
        forged.is_err()
            || forged
                .as_ref()
                .is_ok_and(|frame| frame.local_redirect.is_none())
    );
    let profile = frame
        .local_redirect
        .as_ref()
        .ok_or("bound profile")?
        .clone();
    let scope = Scope::enter(Some(frame.clone()), "POST", "secret/data/target", "", &body)?;
    assert!(profile.matches_current());
    for (method, path, namespace, changed) in [
        ("PUT", "secret/data/target", "", body.clone()),
        ("POST", "secret/data/other", "", body.clone()),
        ("POST", "secret/data/target", "team", body.clone()),
        (
            "POST",
            "secret/data/target",
            "",
            json!({"data":{"value":"changed"}}),
        ),
    ] {
        assert!(Scope::enter(Some(frame.clone()), method, path, namespace, &changed).is_err());
    }
    {
        let _wrong = crate::auth::IngressReplyScope::listener(&[0x52; 16]);
        assert!(!profile.matches_current());
        assert!(
            Scope::enter(Some(frame.clone()), "POST", "secret/data/target", "", &body).is_err()
        );
    }
    assert!(profile.matches_current());
    drop(scope);
    assert!(!profile.matches_current());
    drop(ingress);
    Ok(())
}
