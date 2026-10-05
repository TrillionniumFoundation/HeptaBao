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
    for (query, ignored) in [
        ("", None),
        ("?limit=2", Some("limit")),
        ("?list=false", Some("list")),
    ] {
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
        assert_eq!(
            response
                .body
                .get("warnings")
                .cloned()
                .unwrap_or(Value::Null),
            ignored.map_or(Value::Null, |key| json!([format!(
                "Endpoint ignored these unrecognized parameters: [{key}]"
            )]))
        );
    }
    for (query, ignored) in [
        ("foo=bar", Some("foo")),
        ("limit=2&limit=3", Some("limit")),
        ("limit=%GG", None),
        ("foo=a&limit=2&foo=b", Some("foo limit")),
        ("path=unrelated&help=false", None),
    ] {
        let read = wire(
            &mut service,
            "GET",
            &format!("secret/ocsp/plainkey?{query}"),
            "",
            &root,
            None,
            &[],
        )?;
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"], sentinel);
        assert_eq!(
            read.body.get("warnings").cloned().unwrap_or(Value::Null),
            ignored.map_or(Value::Null, |keys| json!([format!(
                "Endpoint ignored these unrecognized parameters: [{keys}]"
            )]))
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

#[test]
fn ordinary_kv_query_uses_actual_owner_go_values_and_keeps_authentication() -> TestResult {
    let directory = Directory(std::env::temp_dir().join(format!(
        "heptabao-kv-query-{}-{}",
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
    for (mount, version) in [("kv-one", "1"), ("kv-two", "2")] {
        assert_eq!(
            admin(
                &mut service,
                &root,
                &format!("sys/mounts/{mount}"),
                json!({"type":"kv","options":{"version":version}})
            )?
            .status,
            204
        );
    }
    let sentinel = json!({"ordinary":"preserve","__heptabao_pki_ocsp_request":"AA==",
        "__heptabao_kv_read_query":{"path":"kv-one/ocsp/plainkey","query":"token=forged","wire_method":"GET"},"__heptabao_http_help_request":{"path":"kv-one/ocsp/plainkey","query":"help=true","wire_method":"POST"}});
    for path in ["ocsp/plainkey", "plainkey", "ocsp/branch/child"] {
        assert_eq!(
            admin(
                &mut service,
                &root,
                &format!("kv-one/{path}"),
                sentinel.clone()
            )?
            .status,
            204
        );
        for value in ["one", "two"] {
            assert_eq!(
                admin(
                    &mut service,
                    &root,
                    &format!("kv-two/data/{path}"),
                    json!({"data":{"value":value}})
                )?
                .status,
                200
            );
        }
    }
    for (query, expected_v2, selected) in [
        ("foo=bar", 200, 2),
        ("bare", 200, 2),
        ("=value", 200, 2),
        ("foo=%00", 200, 2),
        ("foo=%FF", 200, 2),
        ("foo=a;b", 200, 2),
        ("version=1&foo=%GG", 200, 1),
        ("f%GGoo=x", 200, 2),
        ("foo=%GG", 200, 2),
        ("foo=a&foo=b", 200, 2),
        ("limit=2&limit=3", 200, 2),
        ("version=1&version=2", 400, 0),
        ("version=1", 200, 1),
        ("version=2", 200, 2),
        ("version=0", 200, 2),
        ("version=", 200, 2),
        ("version=-1", 200, 2),
        ("version=0x1", 200, 1),
        ("version=%2B1", 200, 1),
        ("version=%201%20", 400, 0),
        ("depth=bad", 200, 2),
        ("list=false", 200, 2),
        ("list=false&list=true", 200, 2),
        ("__heptabao_pki_ocsp_get_path=other", 200, 2),
    ] {
        for stem in ["ocsp/plainkey", "plainkey"] {
            let one = wire(
                &mut service,
                "GET",
                &format!("kv-one/{stem}?{query}"),
                "",
                &root,
                Some("text/plain"),
                b"ignored GET body",
            )?;
            assert_eq!(one.status, 200, "v1 {query}");
            assert_eq!(one.body["data"], sentinel);
            let two = wire(
                &mut service,
                "GET",
                &format!("kv-two/data/{stem}?{query}"),
                "",
                &root,
                None,
                &[],
            )?;
            assert_eq!(two.status, expected_v2, "v2 {query}");
            if expected_v2 == 200 {
                assert_eq!(two.body["data"]["metadata"]["version"], selected);
            }
        }
    }
    for (query, two_status) in [
        ("list=true&foo=bar", 200),
        ("list=true&foo=%GG", 200),
        ("list=true&limit=1&limit=2", 400),
        ("list=true&list=false", 200),
        ("list=%GG&list=true", 200),
        ("scan=true&foo=bar", 200),
    ] {
        for (mount, status) in [("kv-one", 200), ("kv-two/metadata", two_status)] {
            let response = wire(
                &mut service,
                "GET",
                &format!("{mount}/ocsp/branch?{query}"),
                "",
                &root,
                None,
                &[],
            )?;
            assert_eq!(response.status, status, "{mount} {query}");
            if status == 200 {
                assert_eq!(response.body["data"]["keys"], json!(["child"]));
            }
        }
    }
    for method in ["LIST", "SCAN"] {
        for mount in ["kv-one", "kv-two/metadata"] {
            let response = wire(
                &mut service,
                method,
                &format!("{mount}/ocsp/branch?foo=bar"),
                "",
                &root,
                None,
                &[],
            )?;
            assert_eq!(response.status, 200);
            assert_eq!(response.body["data"]["keys"], json!(["child"]));
        }
    }
    for query in ["list=invalid", "list=true&scan=true"] {
        assert_eq!(
            wire(
                &mut service,
                "GET",
                &format!("kv-one/ocsp/plainkey?{query}"),
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
        admin(
            &mut service,
            &root,
            "sys/policies/acl/query-no-kv",
            json!({"policy":"path \"auth/token/lookup-self\" { capabilities = [\"read\"] }"})
        )?
        .status,
        204
    );
    let denied = admin(
        &mut service,
        &root,
        "auth/token/create",
        json!({"policies":["query-no-kv"],"no_default_policy":true}),
    )?;
    assert_eq!(denied.status, 200);
    let denied_token = text(&denied.body, "/auth/client_token")?;
    for (token, expected) in [(&root, 200), (&denied_token, 200), (&String::new(), 403)] {
        for path in ["kv-one/ocsp/plainkey", "kv-two/data/ocsp/plainkey"] {
            for (method, suffix) in [
                ("GET", "?help=anything"),
                ("HELP", ""),
                ("POST", "?help=true"),
            ] {
                let response = wire(
                    &mut service,
                    method,
                    &format!("{path}{suffix}"),
                    "",
                    token,
                    None,
                    b"not-json",
                )?;
                assert_eq!(response.status, expected);
                if expected == 200 {
                    assert!(response.body["help"].is_string());
                    assert!(response.body["openapi"].is_object());
                    assert!(response.body.get("data").is_none());
                }
            }
        }
    }
    for token in ["", denied_token.as_str()] {
        for path in ["kv-one/ocsp/plainkey", "kv-two/data/ocsp/plainkey"] {
            assert_eq!(
                wire(
                    &mut service,
                    "GET",
                    &format!("{path}?token=forged&foo=%GG"),
                    "",
                    token,
                    None,
                    &[]
                )?
                .status,
                403
            );
        }
    }

    // Authentication/ACL see original Go string/array values before backend
    // declared version/limit coercion, including malformed typed values.
    for token in ["", denied_token.as_str()] {
        for path in [
            "kv-two/data/ocsp/plainkey?version=bad",
            "kv-two/data/ocsp/plainkey?version=1&version=2",
            "kv-two/metadata/ocsp/branch?list=true&limit=1&limit=2",
        ] {
            assert_eq!(
                wire(&mut service, "GET", path, "", token, None, &[])?.status,
                403
            );
        }
    }
    for (label, rule, statuses) in [
        (
            "allowed-string",
            "allowed_parameters = { \"version\" = [\"1\"] }",
            [200, 403, 403, 403, 403],
        ),
        (
            "denied-string",
            "denied_parameters = { \"version\" = [\"1\"] }",
            [403, 200, 400, 400, 400],
        ),
        (
            "allowed-number",
            "allowed_parameters = { \"version\" = [1] }",
            [403, 403, 403, 403, 403],
        ),
    ] {
        let name = format!("query-{label}");
        let policy =
            format!("path \"kv-two/data/ocsp/plainkey\" {{ capabilities = [\"read\"] {rule} }}");
        assert_eq!(
            admin(
                &mut service,
                &root,
                &format!("sys/policies/acl/{name}"),
                json!({"policy":policy})
            )?
            .status,
            204
        );
        let created = admin(
            &mut service,
            &root,
            "auth/token/create",
            json!({"policies":[name],"no_default_policy":true}),
        )?;
        assert_eq!(created.status, 200);
        let token = text(&created.body, "/auth/client_token")?;
        for (query, status) in [
            "version=1",
            "version=2",
            "version=bad",
            "version=1&version=2",
            "version=1&version=1",
        ]
        .into_iter()
        .zip(statuses)
        {
            assert_eq!(
                wire(
                    &mut service,
                    "GET",
                    &format!("kv-two/data/ocsp/plainkey?{query}"),
                    "",
                    &token,
                    None,
                    &[]
                )?
                .status,
                status,
                "{label} {query}"
            );
        }
    }
    let before = std::fs::read_to_string(directory.0.join("audit.jsonl"))?;
    for query in ["version=1", "version=2"] {
        assert_eq!(
            wire(
                &mut service,
                "GET",
                &format!("kv-one/plainkey?{query}"),
                "",
                &root,
                None,
                &[]
            )?
            .status,
            200
        );
    }
    let after = std::fs::read_to_string(directory.0.join("audit.jsonl"))?;
    let records = after[before.len()..]
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let records: Vec<_> = records
        .into_iter()
        .filter(|record| {
            matches!(
                record["event"]["kind"].as_str(),
                Some("request" | "response")
            )
        })
        .collect();
    assert_eq!(records.len(), 4);
    assert_eq!(
        records[0]["event"]["path_digest"],
        records[1]["event"]["path_digest"]
    );
    assert_eq!(
        records[2]["event"]["path_digest"],
        records[3]["event"]["path_digest"]
    );
    assert_ne!(
        records[0]["event"]["path_digest"],
        records[2]["event"]["path_digest"]
    );
    assert!(
        !after.contains("version=1")
            && !after.contains("version=2")
            && !after.contains("__heptabao_kv_read_query")
    );
    for path in [
        "sys/mounts/kv-one/tune?foo=bar",
        "auth/token/lookup-self?foo=bar",
        "missing/path?foo=bar",
    ] {
        assert_eq!(
            wire(&mut service, "GET", path, "", &root, None, &[])?.status,
            400
        );
    }
    assert_eq!(
        admin(&mut service, &root, "sys/seal", json!({}))?.status,
        204
    );
    assert_eq!(
        wire(
            &mut service,
            "GET",
            "kv-one/ocsp/plainkey?foo=bar",
            "",
            &root,
            None,
            &[]
        )?
        .status,
        503
    );
    Ok(())
}
