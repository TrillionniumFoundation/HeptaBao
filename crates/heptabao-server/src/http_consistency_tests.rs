//! OpenBao 2.7 consistency middleware regressions; all input is synthetic.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

fn status(headers: &str, path: &str) -> u16 {
    let wire = format!("GET /v1/{path} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n");
    match read_request(&mut wire.as_bytes(), Duration::from_secs(1)) {
        Ok(_) => 200,
        Err(error) => error.status,
    }
}

#[test]
fn consistency270_accepts_opaque_index_and_each_valid_behavior() {
    let index = STANDARD.encode(br#"{"cluster":"synthetic","value":"opaque"}"#);
    for policy in [
        "",
        "X-Vault-Inconsistent: fail\r\n",
        "X-Vault-Inconsistent: forward-active-node\r\n",
        "X-Vault-Inconsistent: await-state\r\n",
        "X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: fail\r\n",
        "X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: forward-active-node\r\n",
    ] {
        let headers = format!("X-Vault-Index: {index}\r\n{policy}");
        assert_eq!(status(&headers, "secret/data/fixture"), 200);
    }
}

#[test]
fn consistency270_accepts_policy_without_index_and_empty_index() {
    for headers in [
        "X-Vault-Index: \r\n",
        "X-Vault-Inconsistent: fail\r\n",
        "X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: forward-active-node\r\n",
    ] {
        assert_eq!(status(headers, "secret/data/fixture"), 200);
    }
}

#[test]
fn consistency270_rejects_malformed_index_before_logical_or_leader_dispatch() {
    for value in [
        "invalid",
        "e30",
        "W10=",
        "Im5vdC1hbi1vYmplY3Qi",
        "eyJjbHVzdGVyIjo3fQ==",
    ] {
        let headers = format!("X-Vault-Index: {value}\r\n");
        for path in ["secret/data/fixture", "sys/leader"] {
            assert_eq!(status(&headers, path), 400);
        }
    }
}

#[test]
fn consistency270_rejects_ambiguous_policy_pairs_and_duplicate_index() {
    for headers in [
        "X-Vault-Inconsistent: \r\n",
        "X-Vault-Inconsistent: await-state, fail\r\n",
        "X-Vault-Inconsistent: fail\r\nX-Vault-Inconsistent: fail\r\n",
        "X-Vault-Inconsistent: forward-active-node\r\nX-Vault-Inconsistent: fail\r\n",
        "X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: await-state\r\n",
        "X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: fail\r\nX-Vault-Inconsistent: fail\r\n",
        "X-Vault-Index: \r\nX-Vault-Index: \r\n",
    ] {
        for path in ["secret/data/fixture", "sys/leader"] {
            assert_eq!(status(headers, path), 400);
        }
    }
}

#[test]
fn consistency270_does_not_relax_duplicate_tokens_or_framing() {
    for headers in [
        "X-Vault-Token: a\r\nx-vault-token: b\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Host: other\r\n",
        "X-Vault-Inconsistent: fail\r\n folded: value\r\n",
    ] {
        assert_eq!(status(headers, "secret/data/fixture"), 400);
    }
    assert_eq!(
        status("X-Vault-MFA: synthetic\r\n", "secret/data/fixture"),
        501
    );
}

fn parsed(headers: &str) -> consistency::Headers {
    let wire = format!("GET /v1/secret/data/fixture HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n");
    read_request(&mut wire.as_bytes(), Duration::from_secs(1))
        .unwrap_or_else(|_| unreachable!("synthetic headers must parse"))
        .consistency
}

#[test]
fn consistency270_index_is_a_prerequisite_not_read_authority() {
    use consistency::{Decision, IndexValue, Observation, Settings};
    let index = IndexValue::for_raft("synthetic", 12)
        .wire()
        .unwrap_or_else(|| unreachable!("synthetic index"));
    let h = |policy: &str| parsed(&format!("X-Vault-Index: {}\r\n{policy}", index.as_str()));
    let mut seen = Observation {
        cluster: "synthetic".into(),
        standby: true,
        committed: Some(12),
        applied: Some(11),
    };
    let default = Settings::default();
    assert_eq!(h("").decide(Some(&seen), default, false), Decision::Reject);
    assert_eq!(
        h("X-Vault-Inconsistent: forward-active-node\r\n").decide(Some(&seen), default, false),
        Decision::Forward
    );
    let await_fail = h("X-Vault-Inconsistent: await-state\r\n");
    assert_eq!(
        await_fail.decide(Some(&seen), default, false),
        Decision::Await
    );
    assert_eq!(
        await_fail.decide(Some(&seen), default, true),
        Decision::Reject
    );
    let await_forward =
        h("X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: forward-active-node\r\n");
    assert_eq!(
        await_forward.decide(Some(&seen), default, true),
        Decision::Forward
    );
    seen.applied = Some(12);
    assert_eq!(
        h("").decide(Some(&seen), default, false),
        Decision::Continue
    );
    seen.committed = Some(11);
    assert_eq!(h("").decide(Some(&seen), default, false), Decision::Reject);
    seen.standby = false;
    assert_eq!(
        h("").decide(Some(&seen), default, false),
        Decision::Continue
    );
    seen.standby = true;
    seen.cluster = "different-cluster".into();
    assert_eq!(
        h("").decide(Some(&seen), default, false),
        Decision::Continue
    );
    assert_eq!(h("").decide(None, default, false), Decision::Continue);
}

#[test]
fn consistency270_missing_foreign_and_unknown_index_keep_distinct_semantics() {
    use consistency::{Decision, Observation, Settings};
    let seen = Observation {
        cluster: "synthetic".into(),
        standby: true,
        committed: Some(1),
        applied: Some(1),
    };
    let configured = Settings::checked(Some("25ms"), Some("forward-active-node"), true)
        .unwrap_or_else(|_| unreachable!("valid setting"));
    assert_eq!(
        parsed("").decide(Some(&seen), configured, false),
        Decision::Forward
    );
    assert_eq!(
        parsed("X-Vault-Inconsistent: fail\r\n").decide(Some(&seen), configured, false),
        Decision::Continue
    );
    let unknown = STANDARD.encode(br#"{"cluster":"synthetic","value":"opaque-backend-value"}"#);
    assert_eq!(
        parsed(&format!("X-Vault-Index: {unknown}\r\n")).decide(Some(&seen), configured, false),
        Decision::Continue
    );
    let wait = parsed(&format!(
        "X-Vault-Index: {unknown}\r\nX-Vault-Inconsistent: await-state\r\n"
    ));
    assert_eq!(wait.decide(Some(&seen), configured, false), Decision::Await);
    assert_eq!(
        wait.decide(Some(&seen), configured, true),
        Decision::Forward
    );
    for value in [
        "heptabao-raft-v1:01",
        "heptabao-raft-v1:+1",
        "heptabao-raft-v1:18446744073709551616",
    ] {
        let index = consistency::IndexValue {
            cluster: "synthetic".into(),
            value: value.into(),
        };
        assert!(index.raft_index().is_none());
    }
}

#[test]
fn consistency270_decoder_matches_null_unknown_and_case_insensitive_fields() {
    for json in [
        "null",
        "{}",
        r#"{"unknown":[1,2],"CLUSTER":"synthetic","value":null}"#,
        r#"{"cluster":"old","cluster":null,"value":"opaque"}"#,
    ] {
        assert_eq!(
            status(
                &format!("X-Vault-Index: {}\r\n", STANDARD.encode(json)),
                "sys/leader"
            ),
            200
        );
    }
    for json in ["7", "false", r#"{"value":7}"#, "{} {}"] {
        assert_eq!(
            status(
                &format!("X-Vault-Index: {}\r\n", STANDARD.encode(json)),
                "sys/leader"
            ),
            400
        );
    }
}

#[test]
fn consistency270_http_response_projects_only_server_encoded_index()
-> Result<(), Box<dyn std::error::Error>> {
    let index = consistency::IndexValue::for_raft("synthetic", 42)
        .wire()
        .ok_or("index")?;
    let wire_index = index.as_str().to_owned();
    let mut bytes = Vec::new();
    write_response(
        &mut bytes,
        Response {
            status: 200,
            body: json!({"data":{"synthetic":true}}),
            consistency_index: Some(index),
        },
        false,
    )?;
    let text = String::from_utf8(bytes)?;
    assert_eq!(text.matches("X-Vault-Index:").count(), 1);
    assert!(text.contains(&format!("X-Vault-Index: {wire_index}\r\n")));
    let mut bytes = Vec::new();
    write_response(
        &mut bytes,
        Response {
            status: 429,
            body: json!({"errors":[]}),
            consistency_index: None,
        },
        true,
    )?;
    let text = String::from_utf8(bytes)?;
    assert!(text.contains("Retry-After: 1\r\n"));
    assert!(!text.contains("X-Vault-Index:"));
    assert!(text.ends_with("\r\n\r\n"));
    Ok(())
}

#[test]
fn consistency270_configuration_rejects_unbounded_or_unknown_fallbacks() {
    assert!(consistency::Settings::checked(Some("60001ms"), None, false).is_err());
    assert!(consistency::Settings::checked(Some("-1s"), None, false).is_err());
    assert!(consistency::Settings::checked(Some("1s"), Some("await-state"), false).is_err());
    assert!(consistency::Settings::checked(Some("25ms"), Some("fail"), false).is_ok());
}

// Model headers and body arriving in separate TLS records. Rejecting an index
// must not leave a bounded ordinary body unread when the response socket closes.
struct SplitRejectedBody {
    header: std::io::Cursor<Vec<u8>>,
    body: std::io::Cursor<Vec<u8>>,
    body_reads: usize,
}
impl Read for SplitRejectedBody {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.header.position() < self.header.get_ref().len() as u64 {
            self.header.read(bytes)
        } else {
            self.body_reads += 1;
            self.body.read(bytes)
        }
    }
}
fn rejected_body(path: &str, framing: &str) -> SplitRejectedBody {
    SplitRejectedBody {
        header: std::io::Cursor::new(format!(
            "POST /v1/{path} HTTP/1.1\r\nHost: localhost\r\nX-Vault-Index: invalid\r\n{framing}\r\n"
        ).into_bytes()),
        body: std::io::Cursor::new(b"BAD!trailing-must-not-be-consumed".to_vec()),
        body_reads: 0,
    }
}

#[test]
fn rejected_consistency_body_is_discarded_without_json_or_next_request_parsing() {
    let mut input = rejected_body("secret/data/rejected", "Content-Length: 4\r\n");
    let result = read_request(&mut input, Duration::from_secs(1));
    assert_eq!(result.err().map(|error| error.status), Some(400));
    assert_eq!(input.body.position(), 4);
    assert_eq!(input.body_reads, 1);
}

#[test]
fn rejected_consistency_body_never_reads_unbounded_or_ambiguous_framing() {
    for framing in [
        "",
        "Content-Length: 0\r\n",
        "Content-Length: -1\r\n",
        "Content-Length: invalid\r\n",
        "Content-Length: 262145\r\n",
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
        "Content-Length: 4\r\nExpect: 100-continue\r\n",
    ] {
        let mut input = rejected_body("secret/data/rejected", framing);
        assert_eq!(
            read_request(&mut input, Duration::from_secs(1))
                .err()
                .map(|error| error.status),
            Some(400)
        );
        assert_eq!(input.body_reads, 0);
    }
}

#[test]
fn rejected_consistency_body_keeps_native_snapshot_upload_unread() {
    for path in [
        "sys/storage/raft/snapshot",
        "sys/storage/raft/snapshot-force",
    ] {
        let mut input = rejected_body(path, "Content-Length: 4\r\n");
        assert_eq!(
            read_request_mode(&mut input, Duration::from_secs(1), true)
                .err()
                .map(|error| error.status),
            Some(400)
        );
        assert_eq!(input.body_reads, 0);
    }
}

#[test]
fn rejected_consistency_body_discard_stops_on_expiry_and_io_error() {
    struct FailingReader(usize);
    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0 += 1;
            Err(io::Error::new(io::ErrorKind::TimedOut, "synthetic timeout"))
        }
    }
    let headers = BTreeMap::from([("content-length".to_owned(), Zeroizing::new("4".to_owned()))]);
    let mut reader = FailingReader(0);
    discard_rejected_consistency_body(&mut reader, &headers, 0, Instant::now(), Duration::ZERO);
    assert_eq!(reader.0, 0);
    discard_rejected_consistency_body(
        &mut reader,
        &headers,
        0,
        Instant::now(),
        Duration::from_secs(1),
    );
    assert_eq!(reader.0, 1);
    discard_rejected_consistency_body(
        &mut reader,
        &headers,
        4,
        Instant::now(),
        Duration::from_secs(1),
    );
    assert_eq!(reader.0, 1);
}
