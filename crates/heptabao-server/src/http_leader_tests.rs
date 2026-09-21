use super::*;

fn parse(method: &str, query: &str, extra: &str, body: &str) -> Result<Request, ParseError> {
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    let raw = format!(
        "{method} /v1/sys/leader{query} HTTP/1.1\r\nHost: local\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    read_request_mode(&mut raw.as_bytes(), Duration::from_secs(1), true)
}

#[test]
fn legal_extension_methods_reach_the_dedicated_leader_405() -> Result<(), Box<dyn std::error::Error>>
{
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = Directory(std::env::temp_dir().join(format!(
        "heptabao-leader-methods-{}-{}",
        std::process::id(),
        u64::from_le_bytes(crypto::random::<8>()?),
    )));
    std::fs::create_dir(&root.0)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut service = Service::new(root.0.join("data"), &root.0.join("audit.jsonl"))?;
    for method in [
        "OPTIONS",
        "TRACE",
        "CONNECT",
        "PROPFIND",
        "get",
        "GeT",
        "123",
        "!#$%&'*+-.^_`|~",
    ] {
        let mut request = parse(
            method,
            "list=invalid&scan=true",
            "Content-Type: text/plain\r\nX-Vault-Token: invalid\r\n",
            "not-json",
        )
        .map_err(|_| "valid extension method was rejected by the parser")?;
        assert_eq!(request.method, method);
        let response = service.handle_request(ServiceRequest {
            method: &request.method,
            path: &request.path,
            namespace: &request.namespace,
            token: &request.token,
            body: std::mem::take(&mut request.body.0),
            wrap_ttl_seconds: request.wrap_ttl_seconds,
            origin_peer: None,
            client_certificates: None,
        });
        assert_eq!(response.status, 405, "{method}");
        assert_eq!(response.body, json!({"errors": []}));
    }
    Ok(())
}

#[test]
fn leader_rejects_malformed_methods_and_keeps_other_api_method_boundaries() {
    for method in [
        "BAD/METHOD",
        "BAD:METHOD",
        "BAD(METHOD)",
        "G\tET",
        "BAD\x7f",
        "BADé",
        "",
        "BAD METHOD",
    ] {
        let error = parse(method, "", "", "").err().unwrap();
        assert_eq!(error.status, 400);
    }
    for path in [
        "secret/data/a",
        "sys/leader/",
        "sys/leader-other",
        "sys/lea%64er",
    ] {
        for method in ["OPTIONS", "TRACE", "CONNECT", "PROPFIND", "get", "123", "!"] {
            let wire = format!("{method} /v1/{path} HTTP/1.1\r\nHost: local\r\n\r\n");
            let error = read_request_mode(&mut wire.as_bytes(), Duration::from_secs(1), true)
                .err()
                .unwrap();
            assert_eq!(error.status, 400);
        }
    }
    for wire in [
        "OPTIONS /v1/sys/leader HTTP/1.1\r\nHost: local\r\nContent-Length: 262145\r\n\r\n",
        "TRACE /v1/sys/leader HTTP/1.1\r\nHost: local\r\nContent-Length: 3\r\n\r\nx",
        "PROPFIND /v1/sys/leader HTTP/1.0\r\nHost: local\r\n\r\n",
    ] {
        assert!(read_request_mode(&mut wire.as_bytes(), Duration::from_secs(1), true).is_err());
    }
}

#[test]
fn leader_http_uses_first_valid_selector_pair_without_rewriting_the_method()
-> Result<(), &'static str> {
    for (query, accepted) in [
        ("list=true", true),
        ("scan=true", true),
        ("list=true&scan=true", false),
        ("unknown", true),
        ("unknown=%GG", true),
        ("list=false&list=true&scan=true", true),
        ("list=true&list=false&scan=true", false),
        ("list=&list=true&scan=true", true),
        ("list=invalid&list=false", false),
        ("list=false&list=invalid", true),
        ("list=%GG&list=true&scan=true", false),
        ("list=%GG&scan=true", true),
        ("li%GGst=true&scan=true", true),
        ("unrelated=%GG&list=true&scan=true", false),
        ("list=true;x=1&scan=true", true),
        ("list=true&scan=true;x=1", true),
        ("list=true%3B", false),
        ("%6cist=true&scan=true", false),
        ("list&list=true&scan=true", true),
        ("list=%00", false),
        ("scan=%FF", false),
        ("%FF=true&scan=true", true),
        ("list=FALSE&scan=0", true),
    ] {
        match parse("GET", query, "", "") {
            Ok(request) => {
                assert!(accepted, "{query}");
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "sys/leader");
                assert_eq!(request.body.0, json!({}));
                assert!(request.native_snapshot.is_none());
            }
            Err(error) => {
                assert!(!accepted, "{query}");
                assert_eq!(error.status, 400);
                assert!(error.empty_errors);
            }
        }
    }
    for method in ["HEAD", "POST", "PUT", "DELETE", "LIST", "SCAN"] {
        let request = parse(
            method,
            "list=invalid&scan=true",
            "Content-Type: text/plain\r\n",
            "not-json",
        )
        .map_err(|_| "dedicated method must reach Service")?;
        assert_eq!(request.method, method);
        assert_eq!(request.body.0, json!({}));
    }
    Ok(())
}

#[test]
fn leader_http_ignores_only_semantic_headers_and_consumes_the_bounded_body()
-> Result<(), &'static str> {
    let headers = "X-Vault-Token: invalid\r\nX-Vault-Wrap-TTL: invalid\r\nX-Vault-Wrap-Format: unknown\r\nX-Vault-Namespace: a//b\r\nX-Vault-Synthetic: x\r\nContent-Type: text/plain\r\n";
    let request = parse("GET", "bare&unknown=%GG", headers, "synthetic-body")
        .map_err(|_| "leader semantic headers")?;
    assert_eq!(request.method, "GET");
    assert!(request.token.is_empty());
    assert!(request.namespace.is_empty());
    assert!(request.wrap_ttl_seconds.is_none());
    let request = parse("POST", "", "Content-Type: application/json\r\n", "{")
        .map_err(|_| "leader body must not be parsed as JSON")?;
    assert_eq!(request.method, "POST");
    struct Split<'a> {
        header: &'a [u8],
        body: &'a [u8],
        reads: usize,
    }
    impl Read for Split<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            let data = if self.header.is_empty() {
                &mut self.body
            } else {
                &mut self.header
            };
            let count = out.len().min(data.len());
            out[..count].copy_from_slice(&data[..count]);
            *data = &data[count..];
            Ok(count)
        }
    }
    let mut split = Split {
        header: b"POST /v1/sys/leader HTTP/1.1\r\nHost: local\r\nContent-Length: 3\r\n\r\n",
        body: b"{!?",
        reads: 0,
    };
    assert!(read_request_mode(&mut split, Duration::from_secs(1), true).is_ok());
    assert_eq!(split.reads, 2);
    assert!(split.body.is_empty());
    for wire in [
        "GET /v1/sys/leader HTTP/1.1\r\nHost: local\r\nContent-Length: 3\r\n\r\nx",
        "GET /v1/sys/leader HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\nx",
        "GET /v1/sys/leader HTTP/1.1\r\nHost: local\r\nContent-Length: 262145\r\n\r\n",
        "GET /v1/sys/leader HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "POST /v1/sys/leader HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "POST /v1/sys/leader HTTP/1.1\r\nHost: local\r\nExpect: 100-continue\r\n\r\n",
        "GET /v1/sys/leader?unknown=raw\tcontrol HTTP/1.1\r\nHost: local\r\n\r\n",
    ] {
        assert!(read_request_mode(&mut wire.as_bytes(), Duration::from_secs(1), true).is_err());
    }
    Ok(())
}

#[test]
fn dedicated_leader_parsing_does_not_relax_other_api_routes() {
    for wire in [
        "GET /v1/secret/data/a?unknown=value HTTP/1.1\r\nHost: local\r\n\r\n",
        "GET /v1/sys/leader/?unknown=value HTTP/1.1\r\nHost: local\r\n\r\n",
        "GET /v1/sys/leader-other?bare HTTP/1.1\r\nHost: local\r\n\r\n",
        "GET /v1/secret/data/a HTTP/1.1\r\nHost: local\r\nX-Vault-Synthetic: x\r\n\r\n",
        "GET /v1/secret/data/a HTTP/1.1\r\nHost: local\r\nX-Vault-Wrap-TTL: invalid\r\n\r\n",
        "GET /v1/secret/data/a HTTP/1.1\r\nHost: local\r\nX-Vault-Wrap-Format: unknown\r\n\r\n",
        "GET /v1/secret/data/a HTTP/1.1\r\nHost: local\r\nX-Vault-Namespace: a//b\r\n\r\n",
        "POST /v1/secret/data/a HTTP/1.1\r\nHost: local\r\nContent-Length: 1\r\nContent-Type: application/json\r\n\r\n{",
    ] {
        assert!(read_request_mode(&mut wire.as_bytes(), Duration::from_secs(1), true).is_err());
    }
}
