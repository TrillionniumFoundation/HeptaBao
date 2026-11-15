//! Closed transport-profile tests; these do not mint an SSH response owner.
//! Actual mount selection, raw delivery and ordinary large KV run separately
//! through the unchanged real three-voter normal Service pipeline.
use super::*;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CLUSTER: &str = "native-ssh-original-reply-fixture";
const PROFILE: NativeOriginalReplyProfile = NativeOriginalReplyProfile::RootSshPublicKey;

fn context<'a>(body: &'a Value, path: &'a str) -> ForwardContext<'a> {
    ForwardContext {
        method: "GET",
        path,
        namespace: "",
        token: "synthetic-ignored-bearer",
        body,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        caller_deadline: None,
    }
}

#[test]
fn native_ssh_reply_profile_retains_original_ingress_nonce_and_custom_route() -> TestResult {
    let body = json!({});
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xa3; 16]);
    for path in [
        "ssh/public_key",
        "custom/ssh/public_key",
        "custom/ssh/issuer/default/public_key",
    ] {
        let request = context(&body, path);
        let frame = encode_completed_request_with_native_original_reply(
            CLUSTER,
            (1, 2),
            &request,
            Some([0xa4; 32]),
            PROFILE,
        )?;
        assert!(frame.starts_with(UNWRAP_REQUEST_MAGIC));
        let decoded = decode_request_for_cluster(&frame, CLUSTER)?;
        assert!(
            decoded.unwrap_response && decoded.index_response && !decoded.native_index_response
        );
        assert_eq!(decoded.native_original_reply_profile, Some(PROFILE));
        assert_eq!(decoded.wrapped_reply_ingress, Some([0xa3; 16]));
        assert_eq!(decoded.completion_nonce, Some([0xa4; 32]));
        assert_eq!((decoded.source, decoded.target), (1, 2));
        assert_eq!(decoded.path, path);
        assert_eq!(decoded.token, request.token);
        assert_eq!(decoded.body, body);
        assert!(decoded.wrapped_reply_lexical.is_none() && decoded.namespace.is_empty());
        assert!(decode_request_for_cluster(&frame, "another-cluster").is_err());
    }
    Ok(())
}

#[test]
fn native_ssh_reply_profile_refuses_missing_ingress_nonce_or_wrong_root_get() -> TestResult {
    let body = json!({});
    let mut request = context(&body, "ssh/public_key");
    {
        let _no_ingress = crate::auth::IngressReplyScope::authenticated_forward(None, None);
        assert!(
            encode_completed_request_with_native_original_reply(
                CLUSTER,
                (1, 2),
                &request,
                Some([0xa5; 32]),
                PROFILE,
            )
            .is_err()
        );
    }
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xa6; 16]);
    assert!(
        encode_completed_request_with_native_original_reply(
            CLUSTER,
            (1, 2),
            &request,
            None,
            PROFILE,
        )
        .is_err()
    );
    for (method, path, namespace, ttl) in [
        ("HEAD", "ssh/public_key", "", None),
        ("POST", "ssh/public_key", "", None),
        ("GET", "ssh/public_key", "child", None),
        ("GET", "ssh/public_key", "", Some(30)),
        ("GET", "public_key", "", None),
        ("GET", "/ssh/public_key", "", None),
        ("GET", "ssh//public_key", "", None),
        ("GET", "ssh/../public_key", "", None),
        ("GET", "ssh/public_key/extra", "", None),
    ] {
        request.method = method;
        request.path = path;
        request.namespace = namespace;
        request.wrap_ttl_seconds = ttl;
        assert!(
            encode_completed_request_with_native_original_reply(
                CLUSTER,
                (1, 2),
                &request,
                Some([0xa7; 32]),
                PROFILE,
            )
            .is_err(),
            "explicit profile must refuse a different request shape"
        );
    }
    Ok(())
}

#[test]
fn native_ssh_reply_profile_rejects_wire_downgrade_and_missing_or_unknown_metadata() -> TestResult {
    let body = json!({});
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xa8; 16]);
    let frame = encode_completed_request_with_native_original_reply(
        CLUSTER,
        (1, 2),
        &context(&body, "custom/ssh/public_key"),
        Some([0xa9; 32]),
        PROFILE,
    )?;
    for magic in [
        REQUEST_MAGIC,
        WRAPPED_REQUEST_MAGIC,
        PEER_REQUEST_MAGIC,
        INDEX_REQUEST_MAGIC,
        NATIVE_INDEX_REQUEST_MAGIC,
        NATIVE_KV2_WRITE_REQUEST_MAGIC,
        FORM_INDEX_REQUEST_MAGIC,
        FORM_UNWRAP_REQUEST_MAGIC,
    ] {
        let mut changed = frame.clone();
        changed[..5].copy_from_slice(magic);
        assert!(decode_request_for_cluster_compatible(&changed, CLUSTER, true).is_err());
    }
    let value: Value = serde_json::from_slice(&frame[9..])?;
    for field in [
        "completion_nonce",
        "wrapped_reply_ingress",
        "native_original_reply_profile",
    ] {
        let mut changed = value.clone();
        changed
            .as_object_mut()
            .ok_or("synthetic request object")?
            .remove(field);
        assert!(
            decode_request_for_cluster(&encode(UNWRAP_REQUEST_MAGIC, &changed)?, CLUSTER).is_err()
        );
    }
    for (field, replacement) in [
        ("native_original_reply_profile", json!("any-raw-response")),
        (
            "native_original_reply_profile",
            json!({"root-ssh-public-key":true}),
        ),
        ("namespace", json!("child")),
        ("method", json!("POST")),
        ("path", json!("custom/ssh/sign/operator")),
        ("wrap_ttl_seconds", json!(60)),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        assert!(
            decode_request_for_cluster(&encode(UNWRAP_REQUEST_MAGIC, &changed)?, CLUSTER).is_err()
        );
    }
    Ok(())
}

#[test]
fn native_ssh_reply_profile_does_not_upgrade_ordinary_suffix_or_shrink_large_json() -> TestResult {
    let body = json!({});
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xaa; 16]);
    for path in [
        "ordinary/data/public_key",
        "ordinary/data/issuer/default/public_key",
    ] {
        let request = context(&body, path);
        let frame = encode_completed_request_with_native_index_capacity(
            CLUSTER,
            (1, 2),
            &request,
            Some([0xab; 32]),
        )?;
        assert!(frame.starts_with(NATIVE_INDEX_REQUEST_MAGIC));
        let decoded = decode_request_for_cluster(&frame, CLUSTER)?;
        assert!(decoded.native_index_response && !decoded.unwrap_response);
        assert!(decoded.native_original_reply_profile.is_none());
        assert!(decoded.wrapped_reply_ingress.is_none());
        let wire: Value = serde_json::from_slice(&frame[9..])?;
        assert!(wire.get("native_original_reply_profile").is_none());
    }
    let response = crate::Response {
        status: 200,
        body: json!({"data":{"data":{"payload":"x".repeat(2 * 1024 * 1024),
            "http_content_type":"text/plain","http_status_code":200,
            "http_raw_body":"c3ludGhldGljLW9yZGluYXJ5LUpTT04="}}}),
        unwrapped_json: None,
        response_headers: Default::default(),
        consistency_index: None,
    };
    let frame = encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &response, None)?;
    assert!(
        frame.starts_with(NATIVE_INDEX_RESPONSE_MAGIC) && frame.len() > MAX_FORWARD_FRAME_BYTES
    );
    let decoded = decode_native_index_response_for_cluster(&frame, CLUSTER)?;
    assert!(decoded.body == response.body);
    assert!(decoded.unwrapped_json.is_none() && decoded.raw_wrapped_reply.is_none());
    assert!(encode_completed_unwrap_response_for_cluster(CLUSTER, 2, 1, &response, None).is_err());
    Ok(())
}
