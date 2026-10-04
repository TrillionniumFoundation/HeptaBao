//! The real HTTP parser and Service share the same original carrier through
//! audit, namespace and actual mount admission before interpreting OCSP bytes.
use super::*;
use base64::Engine as _;
use openssl::{
    hash::MessageDigest,
    ocsp::{OcspCertId, OcspRequest, OcspResponse, OcspResponseStatus},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn now() -> TestResult<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
fn wire(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    media: Option<&str>,
    body: &[u8],
) -> TestResult<Response> {
    let mut header = format!(
        "{method} /v1/{path} HTTP/1.1\r\nHost: localhost\r\nX-Vault-Namespace: {namespace}\r\nX-Vault-Token: {token}\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(media) = media {
        header.push_str(&format!("Content-Type: {media}\r\n"));
    }
    header.push_str("\r\n");
    let mut bytes = Zeroizing::new(header.into_bytes());
    bytes.extend_from_slice(body);
    let mut request = match read_request(&mut bytes.as_slice(), Duration::from_secs(1)) {
        Ok(request) => request,
        Err(error) => return Ok(Response::error(error.status, error.message)),
    };
    Ok(service.handle_at(
        &request.method,
        &request.path,
        &request.namespace,
        request.token.as_str(),
        std::mem::take(&mut request.body.0),
        now()?,
    ))
}
fn admin(service: &mut Service, root: &str, path: &str, body: Value) -> TestResult<Response> {
    let bytes = Zeroizing::new(serde_json::to_vec(&body)?);
    wire(
        service,
        "POST",
        path,
        "",
        root,
        Some("application/json"),
        &bytes,
    )
}
fn text(value: &Value, pointer: &str) -> TestResult<String> {
    Ok(value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or("missing response field")?
        .to_owned())
}
fn verify(response: &Response, issuer: &openssl::x509::X509) -> TestResult {
    assert_eq!(response.status, 200);
    let bytes = crate::engines::raw_ocsp_response(response.status, &response.body)
        .ok_or("raw OCSP response")?;
    let parsed = OcspResponse::from_der(&bytes)?;
    assert_eq!(parsed.status(), OcspResponseStatus::SUCCESSFUL);
    let mut issuers = openssl::stack::Stack::new()?;
    issuers.push(issuer.clone())?;
    let mut trust = openssl::x509::store::X509StoreBuilder::new()?;
    trust.add_cert(issuer.clone())?;
    parsed
        .basic()?
        .verify(&issuers, &trust.build(), openssl::ocsp::OcspFlag::empty())?;
    Ok(())
}
#[test]
fn ocsp_http_actual_mount_raw_media_control_fallback_and_disabled_priority() -> TestResult {
    let directory = Directory(std::env::temp_dir().join(format!(
        "heptabao-ocsp-http-{}-{}",
        std::process::id(),
        u64::from_le_bytes(crypto::random::<8>()?)
    )));
    std::fs::create_dir(&directory.0)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut service = Service::new(directory.0.join("data"), &directory.0.join("audit.jsonl"))?;
    let initialized = admin(
        &mut service,
        "",
        "sys/init",
        json!({"secret_shares":1,"secret_threshold":1}),
    )?;
    assert_eq!(initialized.status, 200);
    let root = text(&initialized.body, "/root_token")?;
    let key = text(&initialized.body, "/keys_base64/0")?;
    assert_eq!(
        admin(&mut service, "", "sys/unseal", json!({"key":key}))?.status,
        200
    );
    // The literal control path ends in /ocsp, but selects no PKI mount yet.
    assert_eq!(
        admin(
            &mut service,
            &root,
            "sys/mounts/ocsp",
            json!({"type":"pki"})
        )?
        .status,
        204
    );
    assert_eq!(admin(&mut service, &root, "ocsp/root/generate/internal",
        json!({"common_name":"transport.example.test","key_type":"ec","key_bits":256,"ttl":"48h"}))?.status, 200);
    assert_eq!(admin(&mut service, &root, "ocsp/roles/web",
        json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","max_ttl":"2h"}))?.status, 200);
    let issued = admin(
        &mut service,
        &root,
        "ocsp/issue/web",
        json!({"common_name":"leaf.example.test","ttl":"1h"}),
    )?;
    assert_eq!(issued.status, 200);
    let leaf = openssl::x509::X509::from_pem(text(&issued.body, "/data/certificate")?.as_bytes())?;
    let issuer = openssl::x509::X509::from_pem(text(&issued.body, "/data/issuing_ca")?.as_bytes())?;
    let mut request = OcspRequest::new()?;
    request.add_id(OcspCertId::from_cert(
        MessageDigest::sha256(),
        &leaf,
        &issuer,
    )?)?;
    let request = request.to_der()?;
    for media in [
        Some("application/ocsp-request"),
        Some("Application/OCSP-Request"),
        Some("application/ocsp-request; charset=binary"),
        Some("application/ocsp-request; note=\"a b\""),
    ] {
        let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, &request)?;
        verify(&response, &issuer)?;
    }
    let encoded_query_request = base64::engine::general_purpose::STANDARD.encode(&request);
    for query in [
        "foo=bar",
        "foo=a&foo=b",
        "request=AA==",
        "__heptabao_pki_ocsp_get_path=other",
        "__heptabao_pki_ocsp_request=AA==",
        "unused=%GG",
        "list=false",
        "scan=0",
    ] {
        let path = format!("ocsp/ocsp/{encoded_query_request}?{query}");
        verify(
            &wire(&mut service, "GET", &path, "", "", None, &[])?,
            &issuer,
        )?;
        let post = format!("ocsp/ocsp?{query}");
        verify(
            &wire(
                &mut service,
                "POST",
                &post,
                "",
                "",
                Some("application/ocsp-request"),
                &request,
            )?,
            &issuer,
        )?;
        let json = wire(
            &mut service,
            "POST",
            &post,
            "",
            "",
            Some("application/json"),
            b"{}",
        )?;
        assert_eq!(json.status, 400);
        assert!(crate::engines::raw_ocsp_response(json.status, &json.body).is_some());
    }
    for query in ["list=true", "scan=1"] {
        let path = format!("ocsp/ocsp/{encoded_query_request}?{query}");
        let response = wire(&mut service, "GET", &path, "", "", None, &[])?;
        assert_eq!(response.status, 405);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
        verify(
            &wire(
                &mut service,
                "POST",
                &format!("ocsp/ocsp?{query}"),
                "",
                "",
                Some("application/ocsp-request"),
                &request,
            )?,
            &issuer,
        )?;
    }
    for media in [
        None,
        Some("application/json"),
        Some("text/plain"),
        Some("application/octet-stream"),
        Some("application/ocsp-request; invalid"),
    ] {
        let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, &request)?;
        assert_eq!(response.status, 400);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
    }
    for media in [
        None,
        Some("application/json"),
        Some("text/plain"),
        Some("application/ocsp-request; invalid"),
    ] {
        let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, b"{}")?;
        assert_eq!(response.status, 400);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_some());
    }
    assert_eq!(
        admin(
            &mut service,
            &root,
            "sys/mounts/secret",
            json!({"type":"kv","options":{"version":"1"}})
        )?
        .status,
        204
    );
    let sentinel = json!({"__heptabao_pki_ocsp_request":base64::engine::general_purpose::STANDARD.encode(&request),
        "__heptabao_pki_ocsp_raw_post":{"path":"secret/ocsp","encoded":"secret bytes","content_type":"application/ocsp-request"},
        "__heptabao_pki_ocsp_json_post":{"path":"secret/ocsp","original_body":{"other":"data"}},
        "__heptabao_pki_ocsp_get_path":"secret/ocsp/AA=="});
    assert_eq!(
        admin(&mut service, &root, "secret/ocsp", sentinel.clone())?.status,
        204
    );
    let stored = wire(&mut service, "GET", "secret/ocsp", "", &root, None, &[])?;
    assert_eq!(stored.status, 200);
    assert_eq!(stored.body["data"], sentinel);
    let query_write = wire(
        &mut service,
        "POST",
        "secret/ocsp?limit=2",
        "",
        &root,
        Some("application/json"),
        &serde_json::to_vec(&sentinel)?,
    )?;
    assert_eq!(query_write.status, 204);
    let stored = wire(&mut service, "GET", "secret/ocsp", "", &root, None, &[])?;
    let mut expected = sentinel.clone();
    expected
        .as_object_mut()
        .ok_or("sentinel object")?
        .insert("limit".into(), json!(2));
    assert_eq!(stored.body["data"], expected);
    let bad_query = wire(
        &mut service,
        "POST",
        "secret/ocsp?foo=bar",
        "",
        &root,
        Some("application/json"),
        b"{\"changed\":true}",
    )?;
    assert_eq!(bad_query.status, 400);
    assert_eq!(
        wire(&mut service, "GET", "secret/ocsp", "", &root, None, &[])?.body["data"],
        expected
    );
    // A lexical /ocsp/ segment does not own a legal KV key or control path.
    // Compare the candidate with the same ordinary route without that segment.
    for path in [
        "secret/ocsp/plainkey",
        "secret/plain/plainkey",
        "secret/ocsp/branch/child",
        "secret/plain/branch/child",
    ] {
        assert_eq!(
            admin(&mut service, &root, path, sentinel.clone())?.status,
            204
        );
    }
    for query in ["", "?limit=2", "?list=false"] {
        let response = wire(
            &mut service,
            "GET",
            &format!("secret/ocsp/plainkey{query}"),
            "",
            &root,
            Some("text/plain"),
            b"ignored GET body",
        )?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"], sentinel);
    }
    for query in ["foo=bar", "limit=2&limit=3", "limit=%GG"] {
        assert_eq!(
            wire(
                &mut service,
                "GET",
                &format!("secret/ocsp/plainkey?{query}"),
                "",
                &root,
                None,
                &[]
            )?
            .status,
            400
        );
    }
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "secret/ocsp/plainkey",
            "",
            "",
            None,
            &[]
        )?
        .status,
        403
    );
    for query in ["list=true", "scan=true&limit=2"] {
        let candidate = wire(
            &mut service,
            "GET",
            &format!("secret/ocsp/branch?{query}"),
            "",
            &root,
            None,
            &[],
        )?;
        let ordinary = wire(
            &mut service,
            "GET",
            &format!("secret/plain/branch?{query}"),
            "",
            &root,
            None,
            &[],
        )?;
        assert_eq!(candidate.status, 200);
        assert_eq!(candidate.status, ordinary.status);
        assert_eq!(candidate.body["data"], ordinary.body["data"]);
    }
    assert_eq!(
        admin(
            &mut service,
            &root,
            "sys/mounts/team/ocsp/nested",
            json!({"type":"kv","options":{"version":"1"}})
        )?
        .status,
        204
    );
    assert_eq!(
        admin(
            &mut service,
            &root,
            "team/ocsp/nested/plainkey",
            sentinel.clone()
        )?
        .status,
        204
    );
    let nested = wire(
        &mut service,
        "GET",
        "team/ocsp/nested/plainkey?limit=2",
        "",
        &root,
        None,
        &[],
    )?;
    assert_eq!(nested.status, 200);
    assert_eq!(nested.body["data"], sentinel);
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "sys/mounts/team/ocsp/nested/tune",
            "",
            &root,
            None,
            &[]
        )?
        .status,
        200
    );
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "sys/mounts/team/ocsp/nested/tune",
            "",
            "",
            None,
            &[]
        )?
        .status,
        403
    );
    assert_eq!(
        admin(&mut service, &root, "sys/namespaces/team", json!({}))?.status,
        200
    );
    let bytes = serde_json::to_vec(&json!({"type":"kv","options":{"version":"1"}}))?;
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "sys/mounts/nested/ocsp/kv",
            "team",
            &root,
            Some("application/json"),
            &bytes
        )?
        .status,
        204
    );
    let bytes = serde_json::to_vec(&sentinel)?;
    assert_eq!(
        wire(
            &mut service,
            "POST",
            "nested/ocsp/kv/plainkey",
            "team",
            &root,
            Some("application/json"),
            &bytes
        )?
        .status,
        204
    );
    let namespaced = wire(
        &mut service,
        "GET",
        "nested/ocsp/kv/plainkey?limit=2",
        "team",
        &root,
        None,
        &[],
    )?;
    assert_eq!(namespaced.status, 200);
    assert_eq!(namespaced.body["data"], sentinel);
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "nested/ocsp/kv/plainkey",
            "missing",
            &root,
            None,
            &[]
        )?
        .status,
        404
    );
    for query in ["foo=bar", "list=true"] {
        let response = wire(
            &mut service,
            "GET",
            &format!("secret/ocsp/AA==?{query}"),
            "",
            &root,
            None,
            &[],
        )?;
        assert_eq!(response.status, 404);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
    }
    let wrong_media = wire(
        &mut service,
        "POST",
        "secret/ocsp",
        "",
        &root,
        Some("text/plain"),
        b"{\"changed\":true}",
    )?;
    assert_eq!(wrong_media.status, 400);
    assert!(crate::engines::raw_ocsp_response(wrong_media.status, &wrong_media.body).is_none());
    assert_eq!(
        wire(&mut service, "GET", "secret/ocsp", "", &root, None, &[])?.body["data"],
        expected
    );
    for forged in [
        json!({"__heptabao_pki_ocsp_request":base64::engine::general_purpose::STANDARD.encode(&request)}),
        json!({"__heptabao_pki_ocsp_raw_post":{"path":"ocsp/ocsp","encoded":base64::engine::general_purpose::STANDARD.encode(&request),"content_type":"application/ocsp-request"}}),
        json!({"__heptabao_pki_ocsp_json_post":{"path":"ocsp/ocsp","original_body":{"__heptabao_pki_ocsp_request":base64::engine::general_purpose::STANDARD.encode(&request)}}}),
    ] {
        let response = admin(&mut service, "", "ocsp/ocsp", forged)?;
        assert_eq!(response.status, 400);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_some());
    }
    for method in ["POST", "PUT"] {
        for size in [0, 4, 2047, 2048, 4096] {
            let response = wire(
                &mut service,
                method,
                "ocsp/ocsp",
                "",
                "",
                Some("application/ocsp-request"),
                &vec![7; size],
            )?;
            assert_eq!(response.status, 400);
            assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_some());
        }
    }
    for media in [
        Some("application/x-www-form-urlencoded"),
        Some("Application/X-Www-Form-Urlencoded; charset=UTF-8"),
    ] {
        for body in [&b"x=not-a-request"[..], &b"{}"[..], &b""[..]] {
            let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, body)?;
            assert_eq!(response.status, 400);
            assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_some());
        }
        for body in [&b"x=%GG"[..], &b"x=a;b"[..], &b"[invalid JSON"[..]] {
            let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, body)?;
            assert_eq!(response.status, 400);
            assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
        }
    }
    for (spaces, raw) in [(511, false), (512, true)] {
        let mut bytes = vec![b' '; spaces];
        bytes.push(b'{');
        let response = wire(
            &mut service,
            "POST",
            "ocsp/ocsp",
            "",
            "",
            Some("application/x-www-form-urlencoded"),
            &bytes,
        )?;
        assert_eq!(response.status, 400);
        assert_eq!(
            crate::engines::raw_ocsp_response(response.status, &response.body).is_some(),
            raw
        );
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(&request);
    for encoded in [
        encoded.clone(),
        encoded
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D"),
    ] {
        verify(
            &wire(
                &mut service,
                "GET",
                &format!("ocsp/ocsp/{encoded}"),
                "",
                "",
                None,
                b"ignored body",
            )?,
            &issuer,
        )?;
    }
    for (body, media, token, status) in [
        (
            &b"{\"type\":\"pki\",\"type\":\"kv\"}"[..],
            Some("application/json"),
            root.as_str(),
            400,
        ),
        (
            &b"{\"type\":\"pki\"}"[..],
            Some("text/plain"),
            root.as_str(),
            400,
        ),
        (
            &b"{\"type\":\"pki\"}"[..],
            Some("application/json"),
            "",
            403,
        ),
    ] {
        let response = wire(
            &mut service,
            "POST",
            "sys/mounts/blocked/ocsp",
            "",
            token,
            media,
            body,
        )?;
        assert_eq!(response.status, status);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
    }
    let absent = wire(
        &mut service,
        "GET",
        "sys/mounts/ocsp/AA%2F%3D",
        "",
        &root,
        None,
        &[],
    )?;
    assert_eq!(absent.status, 404);
    assert!(crate::engines::raw_ocsp_response(absent.status, &absent.body).is_none());
    assert_eq!(
        admin(
            &mut service,
            &root,
            "ocsp/config/crl",
            json!({"ocsp_disable":true})
        )?
        .status,
        200
    );
    for media in [
        Some("application/ocsp-request"),
        Some("Application/OCSP-Request; charset=binary"),
    ] {
        for bytes in [&b"wrong DER"[..], &vec![7; 2048][..]] {
            let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, bytes)?;
            assert_eq!(response.status, 401);
            assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_some());
        }
    }
    for media in [None, Some("application/json"), Some("text/plain")] {
        let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, &request)?;
        assert_eq!(response.status, 400);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
    }
    for media in [
        None,
        Some("application/json"),
        Some("text/plain"),
        Some("application/ocsp-request; invalid"),
    ] {
        let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, b"{}")?;
        assert_eq!(response.status, 401);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_some());
    }
    for media in [
        Some("application/x-www-form-urlencoded"),
        Some("Application/X-Www-Form-Urlencoded; charset=UTF-8"),
    ] {
        for body in [&b"x=not-a-request"[..], &b"{}"[..], &b""[..]] {
            let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, body)?;
            assert_eq!(response.status, 401);
            assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_some());
        }
        for body in [&b"x=%GG"[..], &b"x=a;b"[..], &b"[invalid JSON"[..]] {
            let response = wire(&mut service, "POST", "ocsp/ocsp", "", "", media, body)?;
            assert_eq!(response.status, 400);
            assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
        }
    }
    let empty_json = admin(&mut service, "", "ocsp/ocsp", json!({}))?;
    assert_eq!(empty_json.status, 401);
    assert!(crate::engines::raw_ocsp_response(empty_json.status, &empty_json.body).is_some());
    for query in [
        "foo=bar",
        "foo=a&foo=b",
        "request=AA==",
        "__heptabao_pki_ocsp_get_path=other",
        "unused=%GG",
        "list=false",
    ] {
        let response = wire(
            &mut service,
            "GET",
            &format!("ocsp/ocsp/{encoded_query_request}?{query}"),
            "",
            "",
            None,
            &[],
        )?;
        assert_eq!(response.status, 401);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_some());
        for (mime, body) in [
            ("application/ocsp-request", request.as_slice()),
            ("application/json", b"{}".as_slice()),
        ] {
            let response = wire(
                &mut service,
                "POST",
                &format!("ocsp/ocsp?{query}"),
                "",
                "",
                Some(mime),
                body,
            )?;
            assert_eq!(response.status, 401);
            assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_some());
        }
    }
    let form_bad_query = wire(
        &mut service,
        "POST",
        "ocsp/ocsp?unused=%GG",
        "",
        "",
        Some("application/x-www-form-urlencoded"),
        b"x=ok",
    )?;
    assert_eq!(form_bad_query.status, 400);
    assert!(
        crate::engines::raw_ocsp_response(form_bad_query.status, &form_bad_query.body).is_none()
    );
    for query in ["list=true", "scan=1"] {
        assert_eq!(
            wire(
                &mut service,
                "GET",
                &format!("ocsp/ocsp/{encoded_query_request}?{query}"),
                "",
                "",
                None,
                &[]
            )?
            .status,
            405
        );
    }
    let audit = std::fs::read_to_string(directory.0.join("audit.jsonl"))?;
    assert!(!audit.contains(&base64::engine::general_purpose::STANDARD.encode(&request)));
    assert!(!audit.contains(&root));
    Ok(())
}
