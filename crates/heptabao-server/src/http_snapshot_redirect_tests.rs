//! Framing tests use real Service + Raft observations, not a fabricated origin.
use super::*;
use crate::ha::snapshot_test_support::Cluster;

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct UnreadBody(usize);
impl Read for UnreadBody {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        self.0 += 1;
        Err(io::Error::other("standby must not read the native upload"))
    }
}

fn dispatch(
    service: &Arc<Mutex<Service>>,
    raw: &str,
    reader: &mut impl Read,
    deadline: Instant,
) -> Result<(NativeReply, bool), Box<dyn std::error::Error>> {
    let mut parsed = read_request_mode(&mut raw.as_bytes(), Duration::from_secs(5), true)
        .map_err(|_| "parse request")?;
    let head = parsed.method == "HEAD";
    let native = parsed.native_snapshot.take().ok_or("native request")?;
    let request = ServiceRequest {
        method: &parsed.method,
        path: &parsed.path,
        namespace: &parsed.namespace,
        token: &parsed.token,
        body: std::mem::take(&mut parsed.body.0),
        wrap_ttl_seconds: parsed.wrap_ttl_seconds,
        origin_peer: None,
        client_certificates: None,
    };
    Ok((execute(service, request, native, reader, deadline), head))
}

#[test]
fn native_http_redirect_has_exact_safe_location_and_no_upload_read_or_response_body() -> TestResult
{
    let root = Directory(std::env::temp_dir().join(format!(
        "heptabao-native-redirect-{}-{}",
        std::process::id(),
        u64::from_le_bytes(crypto::random::<8>()?),
    )));
    std::fs::create_dir(&root.0)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))?;
    }
    let data = root.0.join("data");
    let audit = root.0.join("audit.jsonl");
    let mut local = Service::new(data.clone(), &audit)?;
    let initialized = local.handle(
        "POST",
        "sys/init",
        "",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(initialized.status, 200);
    let key = initialized.body["keys_base64"][0]
        .as_str()
        .ok_or("key")?
        .to_owned();
    assert_eq!(
        local
            .handle("POST", "sys/unseal", "", "", json!({"key":key}))
            .status,
        200
    );
    let health = local.handle("GET", "sys/health", "", "", json!({}));
    let cluster_id = health.body["cluster_id"]
        .as_str()
        .ok_or("cluster id")?
        .to_owned();
    drop(local);
    let cluster = Cluster::new(&root.0.join("raft"), &cluster_id)?;
    cluster.configure_api_address(1, "https://[::1]:18200/")?;
    let mut standby = Service::new_with_ha(data, &audit, Arc::clone(&cluster.processes[1]))?;
    assert_eq!(
        standby
            .handle("POST", "sys/unseal", "", "", json!({"key":key}))
            .status,
        200
    );
    let service = Arc::new(Mutex::new(standby));
    let deadline = || Instant::now() + Duration::from_secs(5);
    for (method, route, framing) in [
        ("GET", "snapshot?after=a%2Fb+z&limit=00", ""),
        ("HEAD", "snapshot", ""),
        ("POST", "snapshot", "Content-Length: 25000000\r\n"),
        (
            "PUT",
            "snapshot-force?after=x%26y",
            "Transfer-Encoding: chunked\r\n",
        ),
    ] {
        let raw = format!(
            "{method} /v1/sys/storage/raft/{route} HTTP/1.1\r\nHost: attacker.invalid\r\nX-Forwarded-Host: attacker.invalid\r\nX-Forwarded-Proto: http\r\nX-Vault-Token: invalid\r\n{framing}\r\n"
        );
        let mut source = UnreadBody(0);
        let (reply, head) = dispatch(&service, &raw, &mut source, deadline())?;
        let mut response = Vec::new();
        reply.write(&mut response, head)?;
        assert_eq!(source.0, 0);
        assert_eq!(
            std::str::from_utf8(&response)?,
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://[::1]:18200/v1/sys/storage/raft/{route}\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
            )
        );
    }
    let mut source = UnreadBody(0);
    let (reply, _) = dispatch(
        &service,
        "POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nContent-Length: 25000000\r\n\r\n",
        &mut source,
        Instant::now() - Duration::from_millis(1),
    )?;
    assert!(matches!(reply, NativeReply::Json(ref response) if response.status == 503));
    assert_eq!(source.0, 0);
    assert!(crate::request_deadline::current().is_none());
    Ok(())
}

#[test]
fn native_redirect_target_keeps_existing_query_validation_and_rejects_header_injection() {
    for target in [
        "/v1/sys/storage/raft/snapshot?after=%0d%0aLocation%3aevil",
        "/v1/sys/storage/raft/snapshot?after=%0a",
        "/v1/sys/storage/raft/snapshot?after=%zz",
        "/v1/sys/storage/raft/snapshot?after=fragment#ignored",
        "/v1/sys/storage/raft/snapshot?after=raw\tcontrol",
        "/v1/sys/storage/raft/snapshot?after=x&after=y",
        "/v1/sys/storage/raft/snapshot?unknown=x",
        "/v1/sys/storage/raft/snapshot%2fforce",
        "https://evil.invalid/v1/sys/storage/raft/snapshot",
    ] {
        let raw = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
        assert!(read_request_mode(&mut raw.as_bytes(), Duration::from_secs(5), true).is_err());
    }
}
