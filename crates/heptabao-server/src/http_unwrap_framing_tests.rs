//! Real Auth consumption is the sole local framing producer. Private synthetic
//! wrappers exercise the existing service audit/commit path before HTTP writes.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture(std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn service() -> Result<(Fixture, Service, String), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "hb-unwrap-framing-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let f = Fixture(dir);
    let mut s = Service::new(f.0.join("data"), &f.0.join("audit"))?;
    let init = s.handle_at(
        "POST",
        "sys/init",
        "",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
        100,
    );
    assert_eq!(init.status, 200);
    let token = init.body["root_token"].as_str().ok_or("root")?.to_owned();
    let key = init.body["keys_base64"][0]
        .as_str()
        .ok_or("key")?
        .to_owned();
    assert_eq!(
        s.handle_at("POST", "sys/unseal", "", "", json!({"key":key}), 100)
            .status,
        200
    );
    Ok((f, s, token))
}
fn unwrap(s: &mut Service, root: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let wrapped = s.handle_request_at(
        crate::service::ServiceRequest {
            method: "POST",
            path: "sys/wrapping/wrap",
            namespace: "",
            token: root,
            body: json!({"value":"synthetic-original-payload"}),
            wrap_ttl_seconds: Some(60),
            origin_peer: None,
            client_certificates: None,
        },
        100,
    );
    assert_eq!(wrapped.status, 200);
    assert!(wrapped.unwrapped_json.is_none());
    let token = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?
        .to_owned();
    let reply = s.handle_at("POST", "sys/wrapping/unwrap", "", &token, json!({}), 100);
    assert_eq!(reply.status, 200);
    assert!(reply.unwrapped_json.is_some());
    let replay = s.handle_at("POST", "sys/wrapping/unwrap", "", &token, json!({}), 100);
    assert_eq!(replay.status, 400);
    assert!(replay.unwrapped_json.is_none());
    Ok(reply)
}
fn body(wire: &[u8]) -> Result<(&str, &[u8]), Box<dyn std::error::Error>> {
    let cut = wire
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or("framing")?;
    Ok((std::str::from_utf8(&wire[..cut])?, &wire[cut + 4..]))
}
#[test]
fn unwrap_trusted_framing_only_actual_consumption_omits_lf() -> TestResult {
    let (_f, mut s, root) = service()?;
    let actual = unwrap(&mut s, &root)?;
    let mut reply = snapshot::NativeReply::Json(actual);
    // A URL cannot grant or revoke this response-only trusted producer origin.
    logical::project(&mut reply, &[0x91; 16], "arbitrary/ordinary/path");
    let mut wire = Vec::new();
    reply.write(&mut wire, false)?;
    let (headers, raw) = body(&wire)?;
    assert!(!raw.ends_with(b"\n"));
    assert_eq!(
        serde_json::from_slice::<Value>(raw)?["data"]["value"],
        "synthetic-original-payload"
    );
    assert!(headers.contains(&format!("Content-Length: {}\r\n", raw.len())));
    for payload in [
        json!({"data":{"unwrapped_json":"stored-json","__heptabao_unwrap":true}}),
        json!({"data":{"value":"synthetic-original-payload"}}),
    ] {
        let ordinary = Response {
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
            status: 200,
            body: payload,
        };
        let mut reply = snapshot::NativeReply::Json(ordinary);
        logical::project(&mut reply, &[0x91; 16], "sys/wrapping/unwrap");
        let mut wire = Vec::new();
        reply.write(&mut wire, false)?;
        assert!(body(&wire)?.1.ends_with(b"\n"));
    }
    Ok(())
}
#[test]
fn unwrap_trusted_framing_cannot_apply_to_failed_terminal_response() -> TestResult {
    let (_f, mut s, root) = service()?;
    let mut response = unwrap(&mut s, &root)?;
    crate::service::erase_json(&mut response.body);
    response.body = json!({"errors":["synthetic delivery veto"]});
    response.status = 503;
    let mut wire = Vec::new();
    write_response(&mut wire, response, false)?;
    let (_, raw) = body(&wire)?;
    assert!(raw.ends_with(b"\n"));
    assert!(!std::str::from_utf8(raw)?.contains("synthetic-original-payload"));
    Ok(())
}
