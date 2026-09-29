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
    for policy in ["", "X-Vault-Inconsistent: fail\r\n",
        "X-Vault-Inconsistent: forward-active-node\r\n",
        "X-Vault-Inconsistent: await-state\r\n",
        "X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: fail\r\n",
        "X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: forward-active-node\r\n"] {
        let headers = format!("X-Vault-Index: {index}\r\n{policy}");
        assert_eq!(status(&headers, "secret/data/fixture"), 200);
    }
}

#[test]
fn consistency270_accepts_policy_without_index_and_empty_index() {
    for headers in ["X-Vault-Index: \r\n", "X-Vault-Inconsistent: fail\r\n",
        "X-Vault-Inconsistent: await-state\r\nX-Vault-Inconsistent: forward-active-node\r\n"] {
        assert_eq!(status(headers, "secret/data/fixture"), 200);
    }
}

#[test]
fn consistency270_rejects_malformed_index_before_logical_or_leader_dispatch() {
    for value in ["invalid", "e30", "W10=", "Im5vdC1hbi1vYmplY3Qi", "eyJjbHVzdGVyIjo3fQ=="] {
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
    for headers in ["X-Vault-Token: a\r\nx-vault-token: b\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Host: other\r\n", "X-Vault-Inconsistent: fail\r\n folded: value\r\n"] {
        assert_eq!(status(headers, "secret/data/fixture"), 400);
    }
    assert_eq!(status("X-Vault-MFA: synthetic\r\n", "secret/data/fixture"), 501);
}
