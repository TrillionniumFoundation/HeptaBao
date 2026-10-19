//! Actual loopback HTTPS through the production parser, Service admission,
//! snapshot transfer and HTTP writer. No Actor, archive, clock or reply is forged.
use super::*;
use rustls::{ClientConfig, ClientConnection, ServerConnection, pki_types::ServerName};
use sha2::{Digest, Sha256};
use std::fs;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const REQUEST_SECONDS: u64 = 15;
const MAX_TEST_RESPONSE: usize = 8 * 1024 * 1024;
const SNAPSHOT: &str = "sys/storage/raft/snapshot";
const WITNESS: &str = "sys/internal/storage/kv2-version-witness";
const EXACT_PAYLOAD: &str = r#"{"a":0.123456789012345678901234567890,"nested":[null,true,{"zero":"\\u0000"}],"unicode":"凭证迁移试验🧪","z":9007199254740993}"#;
const EXACT_HASH: &str = "8f55c32f8c1f2f2a8d0e5cc14f08b7007ae6ca496782cdc2ae84143879b40395";

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct WireResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Zeroizing<Vec<u8>>,
}
impl WireResponse {
    fn json(&self) -> TestResult<Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

// Consume the complete advertised body with bounded headers and payload. The
// binary archive has Content-Length; ordinary JSON may use the production
// writer's chunked framing above its 2048-byte buffer threshold.
fn read_response(reader: &mut impl Read, head: bool) -> TestResult<WireResponse> {
    let mut prefix = Vec::new();
    while !prefix.ends_with(b"\r\n\r\n") {
        if prefix.len() >= MAX_HEADERS {
            return Err("test HTTP response headers exceeded bound".into());
        }
        let mut byte = [0; 1];
        reader.read_exact(&mut byte)?;
        prefix.push(byte[0]);
    }
    let mut lines = std::str::from_utf8(&prefix[..prefix.len() - 4])?.split("\r\n");
    let mut status = lines.next().ok_or("missing HTTP status")?.splitn(3, ' ');
    assert_eq!(status.next(), Some("HTTP/1.1"));
    let code = status.next().ok_or("missing status code")?;
    assert!(code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()));
    let status: u16 = code.parse()?;
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid response header")?;
        assert!(
            headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_none()
        );
    }
    let length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()?;
    let chunked = headers.get("transfer-encoding");
    assert!(
        length.is_none() || chunked.is_none(),
        "ambiguous HTTP response framing"
    );
    assert!(length.is_none_or(|value| value <= MAX_TEST_RESPONSE));
    let mut body = Zeroizing::new(Vec::new());
    if !head && status != 204 {
        if let Some(length) = length {
            body.resize(length, 0);
            reader.read_exact(&mut body)?;
        } else if chunked.is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
            loop {
                let mut line = Vec::new();
                while !line.ends_with(b"\r\n") {
                    if line.len() >= 128 {
                        return Err("test HTTP chunk line exceeded bound".into());
                    }
                    let mut byte = [0; 1];
                    reader.read_exact(&mut byte)?;
                    line.push(byte[0]);
                }
                let number = &line[..line.len() - 2];
                assert!(!number.is_empty() && number.iter().all(u8::is_ascii_hexdigit));
                let count = usize::from_str_radix(std::str::from_utf8(number)?, 16)?;
                if count == 0 {
                    let mut end = [0; 2];
                    reader.read_exact(&mut end)?;
                    assert_eq!(&end, b"\r\n", "fixture has no response trailers");
                    break;
                }
                let end = body
                    .len()
                    .checked_add(count)
                    .ok_or("response chunk length overflow")?;
                assert!(end <= MAX_TEST_RESPONSE);
                let begin = body.len();
                body.resize(end, 0);
                reader.read_exact(&mut body[begin..])?;
                let mut suffix = [0; 2];
                reader.read_exact(&mut suffix)?;
                assert_eq!(&suffix, b"\r\n");
            }
        } else {
            return Err("missing or unsupported bounded response framing".into());
        }
    }
    Ok(WireResponse {
        status,
        headers,
        body,
    })
}

// A panic in a fixture assertion also joins the request worker before its
// Service or directory can be dropped. The original socket deadline bounds it.
struct OwnedHttpsWorker(Option<std::thread::JoinHandle<io::Result<()>>>);
impl OwnedHttpsWorker {
    fn join(mut self) -> TestResult {
        self.0
            .take()
            .ok_or("HTTPS worker already joined")?
            .join()
            .map_err(|_| "owned HTTPS request worker panicked")??;
        Ok(())
    }
}
impl Drop for OwnedHttpsWorker {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            let _ = worker.join();
        }
    }
}

struct HttpsFixture {
    // Drop the actual Service before deleting its uniquely owned directory.
    service: Option<Arc<Mutex<Service>>>,
    directory: Directory,
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    expected_leaf: Vec<u8>,
}
impl HttpsFixture {
    fn new() -> TestResult<Self> {
        let directory = Directory(std::env::temp_dir().join(format!(
            "heptabao-snapshot-https-{}-{}",
            std::process::id(),
            u64::from_le_bytes(crypto::random::<8>()?),
        )));
        fs::create_dir(&directory.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700))?;
        }
        let mut service = Service::new(directory.0.join("data"), &directory.0.join("audit.jsonl"))?;
        service.configure_native_v6_candidate()?;
        let (ca, certificates, key) = api_alpn_tests::tls_identity()?;
        let expected_leaf = certificates[0].as_ref().to_vec();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certificates, key)?;
        configure_api_alpn(&mut server_config);
        let mut roots = RootCertStore::empty();
        roots.add(ca)?;
        let mut client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            service: Some(Arc::new(Mutex::new(service))),
            directory,
            server_config: Arc::new(server_config),
            client_config: Arc::new(client_config),
            expected_leaf,
        })
    }

    fn exchange(
        &self,
        method: &str,
        path: &str,
        token: &str,
        namespace: &str,
        content_type: &str,
        body: &[u8],
    ) -> TestResult<WireResponse> {
        // One accepted request owns this unchanged fifteen-second endpoint.
        // Socket connect, TLS, parsing, admission, body I/O and reply share it.
        let deadline = Instant::now() + Duration::from_secs(REQUEST_SECONDS);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let client_socket = TcpStream::connect_timeout(
            &address,
            deadline.saturating_duration_since(Instant::now()),
        )?;
        let (server_socket, peer) = listener.accept()?;
        drop(listener);
        let service = Arc::clone(
            self.service
                .as_ref()
                .ok_or("cold Service is not reopened")?,
        );
        let server_connection = ServerConnection::new(Arc::clone(&self.server_config))?;
        let client_connection = ClientConnection::new(
            Arc::clone(&self.client_config),
            ServerName::try_from("localhost")?,
        )?;
        let attempt_id = crypto::random::<16>()?;
        let worker = OwnedHttpsWorker(Some(std::thread::spawn(move || -> io::Result<()> {
            let mut stream = StreamOwned::new(
                server_connection,
                DeadlineStream {
                    stream: server_socket,
                    deadline,
                },
            );
            stream.sock.deadline =
                execution_deadline_with_response_reserve(Instant::now(), deadline);
            let read_budget = stream
                .sock
                .deadline
                .saturating_duration_since(Instant::now());
            let parsed = read_request_with_ui(&mut stream, read_budget, true, false);
            stream.sock.deadline = deadline;
            let (reply, head, namespace) = process_parsed_request(
                &service,
                None,
                parsed,
                &mut stream,
                None,
                peer.ip(),
                &attempt_id,
                consistency::Settings::default(),
                deadline,
            );
            write_http1_reply(&mut stream, reply, head, &namespace, deadline);
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "test HTTPS terminal deadline",
                ));
            }
            Ok(())
        })));
        let mut client = StreamOwned::new(
            client_connection,
            DeadlineStream {
                stream: client_socket,
                deadline,
            },
        );
        let result = (|| -> TestResult<WireResponse> {
            write!(
                client,
                "{method} /v1/{path} HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {token}\r\nX-Vault-Namespace: {namespace}\r\nAccept: application/json\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len(),
            )?;
            client.write_all(body)?;
            client.flush()?;
            let reply = read_response(&mut client, method == "HEAD")?;
            assert!(!client.conn.is_handshaking());
            assert_eq!(client.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
            assert!(matches!(
                client.conn.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_2 | rustls::ProtocolVersion::TLSv1_3)
            ));
            let actual = client
                .conn
                .peer_certificates()
                .ok_or("verified TLS peer absent")?;
            assert_eq!(actual[0].as_ref(), self.expected_leaf.as_slice());
            assert!(
                Instant::now() < deadline,
                "full response inside the original request budget"
            );
            Ok(reply)
        })();
        // Join even after client failure; the server socket retains the same
        // original deadline. No detached server or extra listener is retained.
        drop(client);
        worker.join()?;
        result
    }

    fn call(&self, method: &str, path: &str, token: &str, body: Value) -> TestResult<WireResponse> {
        let bytes = if matches!(method, "GET" | "HEAD") {
            Vec::new()
        } else {
            serde_json::to_vec(&body)?
        };
        self.exchange(method, path, token, "", "application/json", &bytes)
    }

    fn audit_entries(&self) -> TestResult<usize> {
        Ok(fs::read_to_string(self.directory.0.join("audit.jsonl"))?
            .lines()
            .count())
    }

    fn snapshot(
        &self,
        method: &str,
        token: &str,
        namespace: &str,
        body: &[u8],
    ) -> TestResult<WireResponse> {
        let audit_before = self.audit_entries()?;
        let reply = self.exchange(
            method,
            SNAPSHOT,
            token,
            namespace,
            if method == "POST" {
                "application/octet-stream"
            } else {
                "application/json"
            },
            body,
        )?;
        assert_eq!(
            self.audit_entries()?,
            audit_before + 2,
            "actual request and terminal response audit precede the complete HTTPS reply"
        );
        Ok(reply)
    }

    fn cleanup(mut self) -> TestResult {
        let service = self
            .service
            .take()
            .ok_or("Service missing before fixture cleanup")?;
        let mutex =
            Arc::try_unwrap(service).map_err(|_| "HTTPS worker survived fixture cleanup")?;
        drop(
            mutex
                .into_inner()
                .map_err(|_| "Service mutex poisoned at fixture cleanup")?,
        );
        fs::remove_dir_all(&self.directory.0)?;
        assert!(
            !self.directory.0.exists(),
            "owned synthetic fixture directory removed"
        );
        Ok(())
    }

    fn cold_reopen(&mut self, key: &str) -> TestResult {
        let old = self
            .service
            .take()
            .ok_or("Service missing before cold close")?;
        let mutex = Arc::try_unwrap(old).map_err(|_| "owned HTTPS worker retained old Service")?;
        drop(
            mutex
                .into_inner()
                .map_err(|_| "old Service mutex poisoned")?,
        );
        let mut service = Service::new(
            self.directory.0.join("data"),
            &self.directory.0.join("audit.jsonl"),
        )?;
        service.configure_native_v6_candidate()?;
        self.service = Some(Arc::new(Mutex::new(service)));
        assert_eq!(
            self.call("POST", "sys/unseal", "", json!({"key":key}))?
                .status,
            200
        );
        Ok(())
    }
}

fn seed() -> TestResult<(
    HttpsFixture,
    Zeroizing<String>,
    Zeroizing<String>,
    Zeroizing<String>,
)> {
    let fixture = HttpsFixture::new()?;
    let init = fixture.call(
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    )?;
    assert_eq!(init.status, 200);
    let initialized = init.json()?;
    let root = Zeroizing::new(
        initialized["root_token"]
            .as_str()
            .ok_or("initialized root")?
            .to_owned(),
    );
    let key = Zeroizing::new(
        initialized["keys_base64"][0]
            .as_str()
            .ok_or("initialized key")?
            .to_owned(),
    );
    assert_eq!(
        fixture
            .call("POST", "sys/unseal", "", json!({"key":&*key}))?
            .status,
        200
    );
    assert_eq!(
        fixture
            .call(
                "POST",
                "sys/mounts/secret",
                &root,
                json!({"type":"kv","options":{"version":"2"}})
            )?
            .status,
        204
    );
    assert_eq!(fixture.call("PUT", "sys/policies/acl/snapshot-read-sudo", &root,
        json!({"policy":"path \"sys/storage/raft/snapshot\" { capabilities=[\"read\",\"update\",\"sudo\"] }"}))?.status, 204);
    let issued = fixture.call(
        "POST",
        "auth/token/create",
        &root,
        json!({"policies":["snapshot-read-sudo"],"no_default_policy":true,"ttl":"1h"}),
    )?;
    assert_eq!(issued.status, 200);
    let actor = Zeroizing::new(
        issued.json()?["auth"]["client_token"]
            .as_str()
            .ok_or("issued actor")?
            .to_owned(),
    );
    assert_eq!(
        fixture
            .call("POST", "sys/internal/native-v6/activate", &root, json!({}))?
            .status,
        204
    );
    let data: Value = serde_json::from_str(EXACT_PAYLOAD)?;
    assert_eq!(EXACT_PAYLOAD.len(), 134);
    assert_eq!(
        format!("{:x}", Sha256::digest(EXACT_PAYLOAD.as_bytes())),
        EXACT_HASH
    );
    let bundle = json!({
        "schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":3,"cas_required":true,"metadata_cas_required":true,"delete_version_after":"0s"},
        "entries":{"history":{
            "created_time":"1970-01-01T00:01:40.000000113Z","updated_time":"1970-01-01T00:01:43.000000113Z",
            "current_version":3,"oldest_version":0,"current_metadata_version":2,
            "max_versions":3,"cas_required":true,"metadata_cas_required":true,
            "delete_version_after":"0s","custom_metadata":{"purpose":"HTTPS snapshot"},
            "versions":{
                "1":{"created_time":"1970-01-01T00:01:41.000000113Z","deletion_time":"1970-01-01T00:03:20.000000113Z","destroyed":false,"data":data},
                "2":{"created_time":"1970-01-01T00:01:42.000000113Z","deletion_time":"","destroyed":true,"data":null},
                "3":{"created_time":"1970-01-01T00:01:43.000000113Z","deletion_time":"","destroyed":false,"data":data}
            }
        }}
    });
    assert_eq!(
        fixture
            .call(
                "POST",
                "sys/migration/openbao/kv2",
                &root,
                json!({"mount":"secret","bundle":bundle})
            )?
            .status,
        204
    );
    let signed_zero = fixture.exchange(
        "POST",
        "secret/data/negative-zero",
        &root,
        "",
        "application/json",
        br#"{"options":{"cas":0},"data":{"n":-0}}"#,
    )?;
    assert_eq!(signed_zero.status, 200);
    Ok((fixture, key, root, actor))
}

fn exact_history(fixture: &HttpsFixture, root: &str) -> TestResult {
    for version in 1..=3 {
        let observed = fixture.call(
            "POST",
            WITNESS,
            root,
            json!({"mount":"secret","path":"history","version":version}),
        )?;
        assert_eq!(observed.status, 200);
        let witness = observed.json()?;
        let data = &witness["data"];
        assert_eq!(data["schema"], "heptabao-native-kv2-storage-witness-v1");
        assert_eq!(data["canonical_profile"], "heptabao-lossless-json-v1");
        assert_eq!(data["mount"], "secret");
        assert_eq!(data["path"], "history");
        assert_eq!(data["version"], version);
        assert_eq!(
            data["created_time"],
            format!("1970-01-01T00:01:{:02}.000000113Z", 40 + version)
        );
        assert_eq!(data["destroyed"], version == 2);
        assert_eq!(data["payload_present"], version != 2);
        assert_eq!(
            data["deletion_time"],
            if version == 1 {
                "1970-01-01T00:03:20.000000113Z"
            } else {
                ""
            }
        );
        if version == 2 {
            assert!(data["payload_canonical_sha256"].is_null());
            assert_eq!(data["payload_canonical_bytes"], 0);
        } else {
            assert_eq!(data["payload_canonical_sha256"], EXACT_HASH);
            assert_eq!(data["payload_canonical_bytes"], 134);
        }
        let public = fixture.call(
            "GET",
            &format!("secret/data/history?version={version}"),
            root,
            Value::Null,
        )?;
        assert_eq!(public.status, if version == 3 { 200 } else { 404 });
        if version == 3 {
            let public = public.json()?;
            assert_eq!(public["data"]["data"]["z"].to_string(), "9007199254740992");
            assert_eq!(
                public["data"]["data"]["a"].to_string(),
                "0.12345678901234568"
            );
        }
    }
    let zero = fixture.call("GET", "secret/data/negative-zero", root, Value::Null)?;
    assert_eq!(zero.status, 200);
    assert!(
        zero.body
            .windows(b"\"n\":-0".len())
            .any(|value| value == b"\"n\":-0")
    );
    assert!(zero.json()?["data"]["data"]["n"].is_number());
    let witness = fixture.call(
        "POST",
        WITNESS,
        root,
        json!({"mount":"secret","path":"negative-zero","version":1}),
    )?;
    assert_eq!(witness.status, 200);
    assert_eq!(
        witness.json()?["data"]["payload_canonical_sha256"],
        format!("{:x}", Sha256::digest(br#"{"n":-0}"#))
    );
    let metadata = fixture.call("GET", "secret/metadata/history", root, Value::Null)?;
    assert_eq!(metadata.status, 200);
    assert_eq!(metadata.json()?["data"]["current_version"], 3);
    Ok(())
}

#[test]
fn native_snapshot_https_json_accept_download_restore_and_cold_keep_exact_history() -> TestResult {
    let (mut fixture, key, root, _actor) = seed()?;
    exact_history(&fixture, &root)?;
    let archive = fixture.snapshot("GET", &root, "", &[])?;
    assert_eq!(
        archive.status, 200,
        "snapshot download must reach typed admission"
    );
    assert_eq!(
        archive.headers.get("content-type").map(String::as_str),
        Some("application/gzip")
    );
    assert!(archive.body.starts_with(&[0x1f, 0x8b]));
    assert!(!archive.body.is_empty());
    let changed = fixture.call(
        "POST",
        "secret/data/history",
        &root,
        json!({"options":{"cas":3},"data":{"after_snapshot":true}}),
    )?;
    assert_eq!(changed.status, 200);
    assert_eq!(changed.json()?["data"]["version"], 4);
    let current = fixture.call("GET", "secret/data/history", &root, Value::Null)?;
    assert_eq!(
        current.json()?["data"]["data"],
        json!({"after_snapshot":true})
    );
    let restored = fixture.snapshot("POST", &root, "", &archive.body)?;
    assert_eq!(
        restored.status,
        200,
        "typed restore response: {}",
        restored.json()?
    );
    exact_history(&fixture, &root)?;
    fixture.cold_reopen(&key)?;
    exact_history(&fixture, &root)?;
    let head = fixture.snapshot("HEAD", &root, "", &[])?;
    assert_eq!(head.status, 200);
    assert_eq!(
        head.headers.get("content-type").map(String::as_str),
        Some("application/gzip")
    );
    assert!(head.body.is_empty());
    assert!(head.headers["content-length"].parse::<usize>()? > 0);
    assert!(
        fs::read_dir(fixture.directory.0.join("data/.snapshot-transfer"))?
            .next()
            .is_none()
    );
    fixture.cleanup()?;
    Ok(())
}

#[test]
fn native_snapshot_https_json_accept_keeps_actor_namespace_seal_and_archive_refusals() -> TestResult
{
    let (fixture, key, root, actor) = seed()?;
    for token in ["", actor.as_str()] {
        for (method, body) in [
            ("GET", b"".as_slice()),
            ("POST", b"not-an-archive".as_slice()),
        ] {
            let rejected = fixture.snapshot(method, token, "", body)?;
            assert_eq!(rejected.status, 403, "typed snapshot remains root-owned");
            assert!(rejected.json()?.get("data").is_none());
        }
    }
    let foreign = fixture.snapshot("GET", &root, "unlisted-snapshot-namespace", &[])?;
    assert_eq!(foreign.status, 404);
    assert!(foreign.json()?.get("data").is_none());
    assert!(
        !fixture.directory.0.join("data/.snapshot-transfer").exists(),
        "denied HTTP requests cannot allocate a snapshot spool"
    );
    let corrupted = fixture.snapshot("POST", &root, "", b"invalid gzip archive")?;
    assert_eq!(corrupted.status, 400);
    assert!(corrupted.json()?.get("data").is_none());
    exact_history(&fixture, &root)?;
    assert!(
        fs::read_dir(fixture.directory.0.join("data/.snapshot-transfer"))?
            .next()
            .is_none()
    );
    assert_eq!(
        fixture.call("POST", "sys/seal", &root, json!({}))?.status,
        204
    );
    assert_eq!(fixture.snapshot("GET", &root, "", &[])?.status, 503);
    assert_eq!(
        fixture
            .call("POST", "sys/unseal", "", json!({"key":&*key}))?
            .status,
        200
    );
    exact_history(&fixture, &root)?;
    fixture.cleanup()?;
    Ok(())
}
