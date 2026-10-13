use super::*;
use serde_json::json;

#[test]
fn approle_form_forwarding_refuses_old_receiver_and_codec_downgrades()
-> Result<(), Box<dyn std::error::Error>> {
    let body = json!({"role_id":"synthetic-role", "secret_id":"synthetic-secret"});
    let path = "auth/forms/login";
    let context = ForwardContext {
        method: "POST",
        path,
        namespace: "",
        token: "",
        body: &body,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        caller_deadline: None,
    };
    let mut data = crate::request_metadata::DataFrame::default();
    data.headers.insert(
        crate::request_metadata::AUTH_FORM_CODEC_HEADER.into(),
        vec!["approle-form-v1".into()],
    );
    let _data = crate::request_metadata::Scope::enter(Some(data), "POST", path, "", &body)?;
    let encoded =
        encode_completed_index_request_for_cluster("form-ha", (1, 2), &context, Some([7; 32]))?;
    assert!(encoded.starts_with(FORM_INDEX_REQUEST_MAGIC));
    assert!(is_forward_request(&encoded));
    let request = decode_request_for_cluster_compatible(&encoded, "form-ha", true)?;
    assert!(request.index_response && !request.unwrap_response);
    assert!(
        request
            .logical_data
            .as_ref()
            .is_some_and(crate::request_metadata::DataFrame::is_approle_form)
    );
    // These are every request magic recognized by the older receiver. Its
    // selection falls through to HBFQ1; even legacy fallback cannot match.
    for old in [
        REQUEST_MAGIC,
        WRAPPED_REQUEST_MAGIC,
        PEER_REQUEST_MAGIC,
        INDEX_REQUEST_MAGIC,
        UNWRAP_REQUEST_MAGIC,
    ] {
        assert!(decode::<ForwardRequest>(old, &encoded).is_err());
    }
    assert!(!encoded.starts_with(REQUEST_MAGIC));
    for old in [
        REQUEST_MAGIC,
        WRAPPED_REQUEST_MAGIC,
        PEER_REQUEST_MAGIC,
        INDEX_REQUEST_MAGIC,
        UNWRAP_REQUEST_MAGIC,
    ] {
        let mut downgraded = encoded.clone();
        downgraded[..5].copy_from_slice(old);
        assert!(decode_request_for_cluster_compatible(&downgraded, "form-ha", true).is_err());
    }
    let mut payload: serde_json::Value = serde_json::from_slice(&encoded[9..])?;
    payload["logical_data"] = serde_json::Value::Null;
    assert!(
        decode_request_for_cluster(&encode(FORM_INDEX_REQUEST_MAGIC, &payload)?, "form-ha")
            .is_err()
    );
    Ok(())
}

#[test]
fn approle_form_forwarding_preserves_full_reply_and_normal_json_versions()
-> Result<(), Box<dyn std::error::Error>> {
    let body = json!({"role_id":"synthetic-role", "secret_id":"synthetic-secret"});
    let path = "auth/forms/login";
    let mut context = ForwardContext {
        method: "POST",
        path,
        namespace: "",
        token: "",
        body: &body,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        caller_deadline: None,
    };
    let normal =
        encode_completed_index_request_for_cluster("form-ha", (1, 2), &context, Some([8; 32]))?;
    assert!(normal.starts_with(INDEX_REQUEST_MAGIC));
    assert!(decode_request_for_cluster(&normal, "form-ha").is_ok());
    let _ingress = crate::auth::IngressReplyScope::listener(&[0x95; 16]);
    context.wrap_ttl_seconds = Some(60);
    let normal_wrapped =
        encode_completed_index_request_for_cluster("form-ha", (1, 2), &context, Some([8; 32]))?;
    assert!(normal_wrapped.starts_with(UNWRAP_REQUEST_MAGIC));
    let mut data = crate::request_metadata::DataFrame::default();
    data.headers.insert(
        crate::request_metadata::AUTH_FORM_CODEC_HEADER.into(),
        vec!["approle-form-v1".into()],
    );
    let _data = crate::request_metadata::Scope::enter(Some(data), "POST", path, "", &body)?;
    assert!(encode_completed_index_request_for_cluster("form-ha", (1, 2), &context, None).is_err());
    let form_wrapped =
        encode_completed_index_request_for_cluster("form-ha", (1, 2), &context, Some([9; 32]))?;
    assert!(form_wrapped.starts_with(FORM_UNWRAP_REQUEST_MAGIC));
    assert!(is_forward_request(&form_wrapped));
    let request = decode_request_for_cluster(&form_wrapped, "form-ha")?;
    assert!(request.index_response && request.unwrap_response);
    assert_eq!(request.wrapped_reply_ingress, Some([0x95; 16]));
    assert!(decode::<ForwardRequest>(REQUEST_MAGIC, &form_wrapped).is_err());
    let mut downgraded = form_wrapped.clone();
    downgraded[..5].copy_from_slice(UNWRAP_REQUEST_MAGIC);
    assert!(decode_request_for_cluster(&downgraded, "form-ha").is_err());
    Ok(())
}
