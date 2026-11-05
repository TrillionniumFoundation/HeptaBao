//! Real configured NativeV6Raft and original request/forward/ReadIndex budgets.
//! This process-local three-voter test is not a physical-host/wire qualification.
use super::*;
use ssh_key::{Certificate, HashAlg, PublicKey};

fn ssh_setup(pipeline: &PkiPipeline, node: usize) -> TestResult {
    for (path, body) in [
        (
            "sys/mounts/ssh",
            json!({"type":"ssh","config":{"default_lease_ttl":"1h","max_lease_ttl":"2h"}}),
        ),
        (
            "ssh/roles/otp",
            json!({"key_type":"otp","default_user":"deploy","allowed_users":"deploy","cidr_list":"127.0.0.0/8"}),
        ),
    ] {
        expect(
            pipeline.call(node, "POST", path, pipeline.admin(), body)?,
            204,
            "formal-HA-actual-SSH-setup",
        )?;
    }
    Ok(())
}
fn text(response: &Response, path: &str) -> TestResult<String> {
    response
        .body
        .pointer(path)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "HA SSH synthetic field absent".into())
}
fn issue(pipeline: &PkiPipeline, node: usize) -> TestResult<(Zeroizing<String>, String)> {
    let mut response = expect(
        pipeline.call(
            node,
            "POST",
            "ssh/creds/otp",
            pipeline.admin(),
            json!({"ip":"127.0.0.1"}),
        )?,
        200,
        "formal-HA-original-OTP-issuer",
    )?;
    let lease = text(&response, "/lease_id")?;
    let otp = secret_field(&mut response, "/data/key")?;
    erase_json(&mut response.body);
    Ok((otp, lease))
}
fn configured(pipeline: &PkiPipeline, node: usize) -> TestResult {
    pipeline.with_service(node, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    pipeline.assert_history(node, &[(1, "seed-v5")])
}
fn setup_ca(pipeline: &PkiPipeline, node: usize) -> TestResult<String> {
    let result = expect(
        pipeline.call(
            node,
            "POST",
            "ssh/config/ca",
            pipeline.admin(),
            json!({"key_type":"ed25519"}),
        )?,
        200,
        "formal-HA-real-SSH-CA",
    )?;
    let public = text(&result, "/data/public_key")?;
    expect(pipeline.call(node, "POST", "ssh/roles/operators", pipeline.admin(),
        json!({"key_type":"ca","allow_user_certificates":true,"allowed_users":"alice","default_user":"alice","ttl":"1h"}))?,
        204, "formal-HA-SSH-CA-role")?;
    Ok(public)
}
fn exact_public(pipeline: &PkiPipeline, node: usize, expected: &str) -> TestResult {
    exact_public_path(pipeline, node, "ssh/public_key", expected)
}
fn exact_public_path(
    pipeline: &PkiPipeline,
    node: usize,
    path: &str,
    expected: &str,
) -> TestResult {
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xd3; 16]);
    let response = expect(
        pipeline.call(node, "GET", path, "invalid-ignored-bearer", json!({}))?,
        200,
        "formal-HA-actual-raw-public-key",
    )?;
    let actual = response
        .unwrapped_json
        .as_ref()
        .ok_or("actual affine SSH raw reply")?;
    assert_eq!(
        actual.raw_http_transport(&response.body)?,
        Some((200, "text/plain"))
    );
    assert_eq!(
        actual
            .raw_bytes(&response.body)?
            .ok_or("actual raw bytes")?,
        expected.as_bytes()
    );
    configured(pipeline, node)
}

#[test]
fn formal_native_ssh_ha_custom_public_reply_transport_keeps_kv_json() -> TestResult {
    use base64::Engine as _;

    let pipeline = PkiPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let follower = (leader + 1) % 3;
    expect(
        pipeline.call(
            follower,
            "POST",
            "sys/mounts/custom/ssh",
            pipeline.admin(),
            json!({"type":"ssh"}),
        )?,
        204,
        "formal-HA-custom-SSH-mount",
    )?;
    let ca = expect(
        pipeline.call(
            follower,
            "POST",
            "custom/ssh/config/ca",
            pipeline.admin(),
            json!({"key_type":"ed25519"}),
        )?,
        200,
        "formal-HA-custom-real-CA",
    )?;
    let public = text(&ca, "/data/public_key")?;
    for path in [
        "custom/ssh/public_key",
        "custom/ssh/issuer/default/public_key",
    ] {
        exact_public_path(&pipeline, follower, path, &public)?;
    }

    expect(
        pipeline.call(
            follower,
            "POST",
            "sys/mounts/ordinary",
            pipeline.admin(),
            json!({"type":"kv","options":{"version":"2"}}),
        )?,
        204,
        "formal-HA-ordinary-KV2-mount",
    )?;
    // A suffix must not select the new profile or acquire a raw-response
    // capability. The large second reply also cannot fit in Q8/S6: the actual
    // forwarded native KV path must retain its original Q9/S7 capacity.
    for (path, payload_bytes) in [
        ("ordinary/data/public_key", 32),
        ("ordinary/data/issuer/default/public_key", 2 * 1024 * 1024),
    ] {
        let forged = json!({
            "http_content_type":"text/plain",
            "http_status_code":200,
            "http_raw_body":base64::engine::general_purpose::STANDARD.encode(b"synthetic-not-an-SSH-key"),
            "payload":"x".repeat(payload_bytes),
        });
        expect(
            pipeline.call(
                follower,
                "POST",
                path,
                pipeline.admin(),
                json!({"data":forged.clone(),"options":{"cas":0}}),
            )?,
            200,
            "formal-HA-ordinary-KV2-fake-raw-fields",
        )?;
        let _ingress = crate::auth::IngressReplyScope::listener(&[0xd4; 16]);
        let response = expect(
            pipeline.call(follower, "GET", path, pipeline.admin(), json!({}))?,
            200,
            "formal-HA-public-key-suffix-remains-KV2",
        )?;
        assert!(response.body["data"]["data"] == forged);
        assert_eq!(response.body["data"]["metadata"]["version"], 1);
        assert!(response.unwrapped_json.is_none());
        if payload_bytes > 1024 * 1024 {
            assert!(serde_json::to_vec(&response.body)?.len() > 1024 * 1024);
        }
    }
    // Send an intentionally mismatched selected profile over the real pinned
    // peer transport. The receiver must recheck its own actual mount and
    // refuse before an ordinary KV read, despite valid original ingress/nonce.
    let source_before = pipeline.with_service(leader, |service| {
        Ok(service
            .current_state_identity()
            .map_err(|_| "actual source identity")?)
    })?;
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xd5; 16]);
    let denied = pipeline.with_service(follower, |service| {
        let ha = service.ha.as_ref().ok_or("actual follower process")?;
        let body = json!({});
        let (response, _receipt) = ha
            .lock_for_request()
            .map_err(|_| "actual follower process lock")?
            .forward_request_completed_with_native_original_reply(
                crate::ha_forward::ForwardContext {
                    method: "GET",
                    path: "ordinary/data/public_key",
                    namespace: "",
                    token: pipeline.admin(),
                    body: &body,
                    wrap_ttl_seconds: None,
                    origin_peer: None,
                    client_certificates: None,
                    caller_deadline: crate::request_deadline::current(),
                },
                crate::ha_forward::NativeOriginalReplyProfile::RootSshPublicKey,
            )?;
        Ok(response)
    })?;
    assert_eq!(denied.status, 503);
    assert!(denied.body.get("data").is_none() && denied.body.get("auth").is_none());
    assert!(denied.unwrapped_json.is_none() && denied.consistency_index.is_none());
    pipeline.with_service(leader, |service| {
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "actual source identity")?
                == source_before
        );
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    configured(&pipeline, follower)
}

#[test]
fn formal_native_ssh_ha_forwarded_otp_election_cold_consume_and_replay() -> TestResult {
    let mut pipeline = PkiPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let follower = (leader + 1) % 3;
    ssh_setup(&pipeline, follower)?;
    let (otp, lease) = issue(&pipeline, follower)?;
    pipeline.stop_process(leader)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, leader);
    expect(
        pipeline.call(
            next,
            "POST",
            "sys/leases/lookup",
            pipeline.admin(),
            json!({"lease_id":lease}),
        )?,
        200,
        "formal-HA-elected-SSH-lease",
    )?;
    pipeline.start_formal_process(leader)?;
    pipeline.wait_cold_native_readindex_ready(leader)?;
    pipeline.unseal(leader)?;
    let verified = expect(
        pipeline.call(
            leader,
            "POST",
            "ssh/verify",
            "invalid-ignored-bearer",
            json!({"otp":otp.as_str()}),
        )?,
        200,
        "formal-HA-cold-anonymous-OTP-verification",
    )?;
    assert_eq!(
        verified.body["data"],
        json!({"ip":"127.0.0.1","username":"deploy","role_name":"otp"})
    );
    configured(&pipeline, leader)?;
    pipeline.stop_process(leader)?;
    pipeline.start_formal_process(leader)?;
    pipeline.wait_cold_native_readindex_ready(leader)?;
    pipeline.unseal(leader)?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "ssh/verify",
            "",
            json!({"otp":otp.as_str()}),
        )?,
        400,
        "formal-HA-durable-OTP-replay-refusal",
    )?;
    configured(&pipeline, leader)
}

#[test]
fn formal_native_ssh_ha_actual_ca_signature_and_raw_public_cold_readindex() -> TestResult {
    let mut pipeline = PkiPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let follower = (leader + 1) % 3;
    ssh_setup(&pipeline, follower)?;
    let ca = setup_ca(&pipeline, follower)?;
    let mut issued = expect(
        pipeline.call(
            follower,
            "POST",
            "ssh/issue/operators",
            pipeline.admin(),
            json!({"key_type":"ed25519"}),
        )?,
        200,
        "formal-HA-one-real-SSH-signature",
    )?;
    let signed = text(&issued, "/data/signed_key")?;
    let cert = Certificate::from_openssh(&signed)?;
    cert.validate_at(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        [&PublicKey::from_openssh(&ca)?.fingerprint(HashAlg::Sha256)],
    )?;
    assert_eq!(cert.valid_principals(), &["alice"]);
    erase_json(&mut issued.body);
    exact_public(&pipeline, follower, &ca)?;
    pipeline.stop_process(leader)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, leader);
    pipeline.start_formal_process(leader)?;
    pipeline.wait_cold_native_readindex_ready(leader)?;
    pipeline.unseal(leader)?;
    exact_public(&pipeline, leader, &ca)?;
    pipeline.with_service(leader, |service| {
        assert_eq!(
            service
                .state
                .as_ref()
                .ok_or("cold state")?
                .engines
                .native_ssh_signature_count("ssh/"),
            Some(1)
        );
        Ok(())
    })
}

#[test]
fn formal_native_ssh_ha_lost_quorum_cannot_issue_sign_or_disclose_public_key() -> TestResult {
    let mut pipeline = PkiPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    ssh_setup(&pipeline, leader)?;
    setup_ca(&pipeline, leader)?;
    let before = pipeline.with_service(leader, |service| {
        service
            .current_state_identity()
            .map_err(|_| "SSH HA source identity".into())
    })?;
    for peer in (0..3).filter(|peer| *peer != leader) {
        pipeline.stop_process(peer)?;
    }
    for (method, path, body) in [
        ("POST", "ssh/creds/otp", json!({"ip":"127.0.0.1"})),
        ("POST", "ssh/issue/operators", json!({"key_type":"ed25519"})),
        ("GET", "ssh/public_key", json!({})),
    ] {
        let response = expect(
            pipeline.call(
                leader,
                method,
                path,
                if method == "GET" {
                    ""
                } else {
                    pipeline.admin()
                },
                body,
            )?,
            503,
            "formal-HA-no-quorum-SSH-proof-veto",
        )?;
        assert!(response.body.get("data").is_none() && response.body.get("auth").is_none());
        assert!(response.consistency_index.is_none() && response.unwrapped_json.is_none());
    }
    pipeline.with_service(leader, |service| {
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "SSH HA final identity")?
                == before
        );
        assert!(service.pending_native_auth_delivery.is_none());
        assert_eq!(
            service
                .state
                .as_ref()
                .ok_or("state")?
                .engines
                .native_ssh_signature_count("ssh/"),
            Some(0)
        );
        Ok(())
    })
}
