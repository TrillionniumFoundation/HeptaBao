//! Actual formal File V6 producers, normal HTTP projection and durable wrappers.
//! All credentials and values in this module belong to newly initialized fixtures.
use super::*;

fn wire_response(
    response: Response,
    namespace: &str,
    path: &str,
    attempt: u8,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let bytes =
        crate::http::signed_kv1_wire_projection_fixture(response, namespace, path, &[attempt; 16])?;
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("actual HTTP header missing")?;
    let header = std::str::from_utf8(&bytes[..split])?;
    let status: u16 = header
        .lines()
        .next()
        .ok_or("HTTP status missing")?
        .split_whitespace()
        .nth(1)
        .ok_or("HTTP status malformed")?
        .parse()?;
    let body = if bytes.len() == split + 4 {
        Value::Null
    } else {
        serde_json::from_slice(&bytes[split + 4..])?
    };
    Ok((status, body))
}

fn wire_request(
    service: &mut Service,
    request: ServiceRequest<'_>,
    attempt: u8,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() + Duration::from_secs(15),
    );
    let _ingress = crate::auth::IngressReplyScope::listener_wrapping(&[attempt; 16], None);
    let path = request.path.to_owned();
    let namespace = request.namespace.to_owned();
    let response = service.handle_request(request);
    wire_response(response, &namespace, &path, attempt)
}

type SignedKv1Fixture = (
    crate::service::tests::Root,
    Service,
    Zeroizing<String>,
    Zeroizing<String>,
);

fn signed_fixture() -> Result<SignedKv1Fixture, Box<dyn std::error::Error>> {
    let root = crate::service::tests::Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    assert_eq!(
        request(&mut service, "POST", ACTIVATE_PATH, &token, json!({})).status,
        204
    );
    let mounted = request(
        &mut service,
        "POST",
        "sys/mounts/signed",
        &token,
        json!({"type":"kv","options":{"version":"1"},
            "config":{"default_lease_ttl":-1,"max_lease_ttl":60}}),
    );
    assert_eq!(mounted.status, 204, "{:?}", mounted.body.get("errors"));
    write_v1(
        &mut service,
        &token,
        "signed/value",
        json!({"value":"synthetic-signed-kv1","nested":{"lease_duration":-37}}),
    );
    Ok((root, service, key, token))
}

fn assert_signed(status: u16, body: &Value) {
    assert_eq!(status, 200, "{:?}", body.get("errors"));
    assert_eq!(body["lease_duration"], -1);
    assert_eq!(body["renewable"], false);
    assert_eq!(body["lease_id"], "");
    assert_eq!(body["data"]["value"], "synthetic-signed-kv1");
    assert_eq!(body["data"]["nested"]["lease_duration"], -37);
    assert!(body["auth"].is_null() && body["wrap_info"].is_null());
}

#[test]
fn formal_v6_signed_kv1_http_projection_cold_and_kv2_isolation() -> TestResult {
    let (root, mut service, key, token) = signed_fixture()?;
    let (status, body) = wire_request(
        &mut service,
        ServiceRequest::new("GET", "signed/value", "", &token, json!({})),
        0xb2,
    )?;
    assert_signed(status, &body);
    assert_eq!(
        body["request_id"],
        crate::crypto::uuid_from_bytes(&[0xb2; 16])
    );
    drop(service);
    let mut service = reopen(&root, &key)?;
    let (status, body) = wire_request(
        &mut service,
        ServiceRequest::new("GET", "signed/value", "", &token, json!({})),
        0xb3,
    )?;
    assert_signed(status, &body);

    mount_kv2(&mut service, &token);
    tune_configuration(
        &mut service,
        &token,
        "secret",
        json!({"default_lease_ttl":-1,"max_lease_ttl":60}),
        204,
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/value",
            &token,
            json!({"data":{"lease_duration":-99,"sentinel":"kv2"}})
        )
        .status,
        200
    );
    let (status, body) = wire_request(
        &mut service,
        ServiceRequest::new("GET", "secret/data/value", "", &token, json!({})),
        0xb4,
    )?;
    assert_eq!(status, 200, "{:?}", body.get("errors"));
    assert_eq!(body["lease_duration"], 0);
    assert_eq!(body["data"]["data"]["lease_duration"], -99);
    assert_eq!(body["data"]["data"]["sentinel"], "kv2");
    Ok(())
}

#[test]
fn formal_v6_signed_kv1_http_missing_marker_wrong_scope_and_mutation_refuse() -> TestResult {
    let (_root, mut service, _key, token) = signed_fixture()?;
    for case in 0..9 {
        let mut response = request(&mut service, "GET", "signed/value", &token, json!({}));
        assert_eq!(response.status, 200);
        assert!(
            response
                .unwrapped_json
                .as_ref()
                .and_then(|o| o.static_kv1_lease())
                .is_some()
        );
        let mut namespace = "";
        let mut path = "signed/value";
        match case {
            0 => response.unwrapped_json = None,
            1 => path = "signed/other",
            2 => namespace = "other/",
            3 => response.body["lease_duration"] = json!(-2),
            4 => response.body["renewable"] = json!(true),
            5 => response.body["lease_id"] = json!("synthetic-dynamic-lease"),
            6 => response.body["auth"] = json!({"lease_duration":1}),
            7 => response.body["wrap_info"] = json!({"ttl":1}),
            8 => response.body["data"]["value"] = json!("not-the-captured-value"),
            _ => unreachable!(),
        }
        let (status, body) = wire_response(response, namespace, path, 0xb5)?;
        assert_eq!(status, 503, "case {case}");
        assert!(body.get("data").is_none_or(Value::is_null), "case {case}");
    }
    let response = request(&mut service, "GET", "signed/value", &token, json!({}));
    assert!(
        crate::auth::logical_envelope(
            &response.body,
            &crate::crypto::uuid_from_bytes(&[0xb6; 16]),
            "signed/value"
        )
        .is_err()
    );
    let (status, body) = wire_response(response, "", "signed/value", 0xb6)?;
    assert_signed(status, &body);
    Ok(())
}

#[test]
fn formal_v6_signed_kv1_wrapper_snapshot_restore_cold_preserves_original_envelope() -> TestResult {
    let (root, mut service, key, token) = signed_fixture()?;
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    // A plain signed read must not publish a wrapping reader floor.
    let (status, body) = wire_request(
        &mut service,
        ServiceRequest::new("GET", "signed/value", "", &token, json!({})),
        0xc0,
    )?;
    assert_signed(status, &body);
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    // Establish the pre-existing public-origin and wrapped-reply floors first.
    // This archive must differ only by the later signed-static KV1 protection,
    // so an unrelated first-wrap owner floor cannot mask that rejection.
    tune_configuration(
        &mut service,
        &token,
        "signed",
        json!({"default_lease_ttl":30}),
        204,
    );
    let mut positive = ServiceRequest::new("GET", "signed/value", "", &token, json!({}));
    positive.wrap_ttl_seconds = Some(60);
    let (status, positive_wrapped) = wire_request(&mut service, positive, 0xbe)?;
    assert_eq!(status, 200, "{:?}", positive_wrapped.get("errors"));
    assert_eq!(positive_wrapped["wrap_info"]["ttl"], 60);
    assert!(positive_wrapped["data"].is_null());
    let positive_wrapper = Zeroizing::new(
        positive_wrapped["wrap_info"]["token"]
            .as_str()
            .ok_or("positive baseline wrapper missing")?
            .to_owned(),
    );
    let (status, positive_unwrapped) = wire_request(
        &mut service,
        ServiceRequest::new(
            "POST",
            "sys/wrapping/unwrap",
            "",
            &positive_wrapper,
            json!({}),
        ),
        0xbf,
    )?;
    assert_eq!(status, 200, "{:?}", positive_unwrapped.get("errors"));
    assert_eq!(positive_unwrapped["lease_duration"], 30);
    assert_eq!(positive_unwrapped["lease_id"], "");
    assert_eq!(positive_unwrapped["renewable"], false);
    assert_eq!(positive_unwrapped["data"]["value"], "synthetic-signed-kv1");
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    tune_configuration(
        &mut service,
        &token,
        "signed",
        json!({"default_lease_ttl":-1}),
        204,
    );
    let before_wrapping = download(&mut service, &token)?;
    let mut get = ServiceRequest::new("GET", "signed/value", "", &token, json!({}));
    get.wrap_ttl_seconds = Some(60);
    let (status, wrapped) = wire_request(&mut service, get, 0xc1)?;
    assert_eq!(status, 200, "{:?}", wrapped.get("errors"));
    assert_eq!(wrapped["wrap_info"]["ttl"], 60);
    assert_eq!(wrapped["wrap_info"]["creation_path"], "signed/value");
    assert!(wrapped["data"].is_null());
    let wrapper = Zeroizing::new(
        wrapped["wrap_info"]["token"]
            .as_str()
            .ok_or("actual wrapper token missing")?
            .to_owned(),
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    let floor = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?
        .get("raw_wrapped_reply_floor")
        .cloned()
        .ok_or("floor missing")?;
    assert_eq!(floor["static_kv1_reply"], "signed-static-kv1-v1");
    assert_prior_floor_reader_refuses(&floor)?;
    let (rejected, _) = snapshot_transfer(
        &mut service,
        "POST",
        &token,
        &mut before_wrapping.as_slice(),
    )?;
    assert_eq!(rejected.status, 400);
    assert!(
        rejected.body["errors"]
            .as_array()
            .ok_or("errors")?
            .iter()
            .any(|e| e.as_str().is_some_and(|s| s.contains("wrapped reply"))),
        "expected protected wrapped-reply floor rejection: {:?}",
        rejected.body.get("errors")
    );
    let snapshot = download(&mut service, &token)?;
    tune_configuration(
        &mut service,
        &token,
        "signed",
        json!({"default_lease_ttl":15}),
        204,
    );
    write_v1(
        &mut service,
        &token,
        "signed/value",
        json!({"value":"after-snapshot"}),
    );
    drop(service);
    let mut service = reopen(&root, &key)?;
    let (status, changed) = wire_request(
        &mut service,
        ServiceRequest::new("GET", "signed/value", "", &token, json!({})),
        0xc2,
    )?;
    assert_eq!(status, 200);
    assert_eq!(changed["lease_duration"], 15);
    assert_eq!(changed["data"]["value"], "after-snapshot");
    let (restored, _) = snapshot_transfer(&mut service, "POST", &token, &mut snapshot.as_slice())?;
    assert_eq!(restored.status, 200, "{:?}", restored.body.get("errors"));
    drop(service);
    let mut service = reopen(&root, &key)?;
    let (status, unwrapped) = wire_request(
        &mut service,
        ServiceRequest::new("POST", "sys/wrapping/unwrap", "", &wrapper, json!({})),
        0xc3,
    )?;
    assert_signed(status, &unwrapped);
    assert_eq!(
        unwrapped["request_id"],
        crate::crypto::uuid_from_bytes(&[0xc1; 16])
    );
    let (status, denied) = wire_request(
        &mut service,
        ServiceRequest::new("POST", "sys/wrapping/unwrap", "", &wrapper, json!({})),
        0xc4,
    )?;
    assert!(
        matches!(status, 400 | 403),
        "actual single-use status {status}"
    );
    assert!(denied.get("data").is_none_or(Value::is_null));
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    drop(service);
    let mut service = reopen(&root, &key)?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    let (rejected, _) = snapshot_transfer(
        &mut service,
        "POST",
        &token,
        &mut before_wrapping.as_slice(),
    )?;
    assert_eq!(rejected.status, 400);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/mounts/signed",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert!(service.state.as_ref().ok_or("state")?.schema >= 146);
    mount_kv2(&mut service, &token);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/retirement",
            &token,
            json!({"data":{"phase":"captured"}})
        )
        .status,
        200
    );
    let retired = download(&mut service, &token)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/retirement",
            &token,
            json!({"data":{"phase":"changed"}})
        )
        .status,
        200
    );
    let (restored, _) = snapshot_transfer(&mut service, "POST", &token, &mut retired.as_slice())?;
    assert_eq!(restored.status, 200, "{:?}", restored.body.get("errors"));
    drop(service);
    let mut service = reopen(&root, &key)?;
    assert!(service.state.as_ref().ok_or("state")?.schema >= 146);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    assert_eq!(
        request(&mut service, "GET", "signed/value", &token, json!({})).status,
        404
    );
    let restored_value = request(
        &mut service,
        "GET",
        "secret/data/retirement",
        &token,
        json!({}),
    );
    assert_eq!(restored_value.status, 200);
    assert_eq!(restored_value.body["data"]["data"]["phase"], "captured");
    assert_eq!(restored_value.body["data"]["metadata"]["version"], 1);
    let (status, denied) = wire_request(
        &mut service,
        ServiceRequest::new("POST", "sys/wrapping/unwrap", "", &wrapper, json!({})),
        0xc5,
    )?;
    assert!(matches!(status, 400 | 403));
    assert!(denied.get("data").is_none_or(Value::is_null));
    Ok(())
}

fn assert_prior_floor_reader_refuses(floor: &Value) -> TestResult {
    // Exact old bool/string alternatives from frozen e0's RawReplyReaderFloor.
    // This is a decoder unit check, not a claim of an old-binary service run.
    #[allow(dead_code)]
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum PriorReader {
        Legacy(bool),
        Pki(PriorPki),
        General(PriorGeneral),
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "kebab-case")]
    enum PriorPki {
        PkiRawHttpV1,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "kebab-case")]
    enum PriorGeneral {
        GeneralWrappedReplyV1,
        PkiAndGeneralWrappedReplyV1,
    }
    assert!(serde_json::from_value::<PriorReader>(floor.clone()).is_err());
    assert!(serde_json::from_value::<PriorReader>(json!(true)).is_ok());
    assert!(serde_json::from_value::<PriorReader>(json!("general-wrapped-reply-v1")).is_ok());
    Ok(())
}

#[test]
fn formal_v6_signed_kv1_wrapper_ttl_and_owner_checks_do_not_relax() -> TestResult {
    let (_root, mut service, _key, token) = signed_fixture()?;
    let response = request(&mut service, "GET", "signed/value", &token, json!({}));
    let projection = *response
        .unwrapped_json
        .as_ref()
        .ok_or("origin")?
        .static_kv1_lease()
        .ok_or("static KV1 origin")?;
    let _ingress = crate::auth::IngressReplyScope::listener_wrapping(&[0xd1; 16], None);
    let auth = &mut service.state.as_mut().ok_or("state")?.auth;
    let before = Zeroizing::new(serde_json::to_vec(auth)?);
    for ttl in [0, 32 * 24 * 3600 + 1] {
        let result =
            auth.wrap_static_kv1_response("", "signed/value", ttl, &response.body, 1, &projection);
        assert!(result.is_err());
        assert_eq!(result.err().ok_or("TTL should reject")?.status, 400);
        assert_eq!(serde_json::to_vec(auth)?, *before);
    }
    for (namespace, path) in [("other/", "signed/value"), ("", "signed/other")] {
        let result =
            auth.wrap_static_kv1_response(namespace, path, 60, &response.body, 1, &projection);
        assert!(result.is_err());
        assert_eq!(result.err().ok_or("owner should reject")?.status, 503);
        assert_eq!(serde_json::to_vec(auth)?, *before);
    }
    // Ordinary dynamic and caller-selected Values still use the closed unsigned route.
    let result = auth.wrap_logical_response("", "signed/value", 60, &response.body, 1);
    assert!(result.is_err());
    assert_eq!(serde_json::to_vec(auth)?, *before);
    Ok(())
}

#[test]
fn formal_v6_signed_kv1_normalized_namespace_header_keeps_exact_owner() -> TestResult {
    let (_root, mut service, _key, token) = signed_fixture()?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    // The real parser owns trimming the public header; no hand-coded alias map.
    let bytes = format!(
        "GET /v1/signed/value HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {}\r\nX-Vault-Namespace: team/\r\nContent-Length: 0\r\n\r\n",
        token.as_str()
    );
    let (method, path, namespace, parsed_token, mut parsed_body) =
        crate::http::parsed_api_request_for_test(bytes.as_bytes())?;
    assert_eq!(method, "GET");
    assert_eq!(path, "signed/value");
    assert_eq!(namespace, "team");
    // Use the same original 15-second ingress deadline as every native request.
    let (status, mounted) = wire_request(
        &mut service,
        ServiceRequest::new(
            "POST",
            "sys/mounts/signed",
            &namespace,
            &token,
            json!({"type":"kv","options":{"version":"1"},
                "config":{"default_lease_ttl":-1,"max_lease_ttl":60}}),
        ),
        0xdf,
    )?;
    assert_eq!(status, 204, "{:?}", mounted.get("errors"));
    let (status, written) = wire_request(
        &mut service,
        ServiceRequest::new(
            "POST",
            "signed/value",
            &namespace,
            &token,
            json!({"value":"synthetic-child","lease_duration":"user-data"}),
        ),
        0xe0,
    )?;
    assert_eq!(status, 204, "{:?}", written.get("errors"));
    let (status, body) = wire_request(
        &mut service,
        ServiceRequest::new(
            &method,
            &path,
            &namespace,
            &parsed_token,
            std::mem::take(&mut parsed_body.0),
        ),
        0xe1,
    )?;
    assert_eq!(status, 200, "{:?}", body.get("errors"));
    assert_eq!(body["lease_duration"], -1);
    assert_eq!(body["data"]["value"], "synthetic-child");
    assert_eq!(body["data"]["lease_duration"], "user-data");
    let child = {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            std::time::Instant::now() + Duration::from_secs(15),
        );
        service.handle("GET", "signed/value", &namespace, &token, json!({}))
    };
    assert_eq!(child.status, 200, "{:?}", child.body.get("errors"));
    assert!(
        child
            .unwrapped_json
            .as_ref()
            .and_then(|o| o.static_kv1_lease())
            .is_some()
    );
    let (status, body) = wire_response(child, "", "signed/value", 0xe2)?;
    assert_eq!(status, 503);
    assert!(body.get("data").is_none_or(Value::is_null));
    Ok(())
}

fn rewrite_frame(encoded: &[u8], logical: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let json = serde_json::to_vec(logical)?;
    let length = u32::try_from(json.len())?;
    let mut result = encoded[..5].to_vec();
    result.extend_from_slice(&length.to_be_bytes());
    result.extend_from_slice(&json);
    Ok(result)
}

#[test]
fn formal_v6_signed_kv1_q9_n1_capacity_completion_digest_and_missing_marker() -> TestResult {
    let (_root, mut service, _key, token) = signed_fixture()?;
    let empty = json!({});
    let context = crate::ha_forward::ForwardContext {
        method: "GET",
        path: "signed/value",
        namespace: "",
        token: &token,
        body: &empty,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        caller_deadline: None,
    };
    let encoded_request = crate::ha_forward::encode_completed_request_with_native_index_capacity(
        "signed-kv1-ha",
        (1, 2),
        &context,
        Some([0xe3; 32]),
    )?;
    let admitted =
        crate::ha_forward::decode_request_for_cluster(&encoded_request, "signed-kv1-ha")?;
    assert!(admitted.index_response && !admitted.unwrap_response);
    for length in [128, 2560 * 1024] {
        write_v1(
            &mut service,
            &token,
            "signed/value",
            json!({"synthetic":"x".repeat(length)}),
        );
        let response = request(&mut service, "GET", "signed/value", &token, json!({}));
        assert_eq!(response.status, 200);
        assert!(
            response
                .unwrapped_json
                .as_ref()
                .and_then(|o| o.static_kv1_lease())
                .is_some()
        );
        if length == 128 {
            let q9 = crate::ha_forward::encode_completed_index_response_for_cluster(
                "signed-kv1-ha",
                2,
                1,
                &response,
                None,
            )?;
            let q9 = crate::ha_forward::decode_index_response_for_cluster(&q9, "signed-kv1-ha")?;
            assert_eq!(q9.body, response.body);
            assert_eq!(
                crate::ha_forward_completion::response_digest(&response)?,
                crate::ha_forward_completion::wire_response_digest(&q9)?
            );
        }
        let n1 = crate::ha_forward::encode_completed_native_index_response_for_cluster(
            "signed-kv1-ha",
            2,
            1,
            &response,
            None,
        )?;
        let received =
            crate::ha_forward::decode_native_index_response_for_cluster(&n1, "signed-kv1-ha")?;
        assert_eq!(received.body, response.body);
        assert_eq!(
            crate::ha_forward_completion::response_digest(&response)?,
            crate::ha_forward_completion::wire_response_digest(&received)?
        );
        assert!(crate::ha_forward::decode_response_for_cluster(&n1, "signed-kv1-ha").is_err());
        let mut mismatched = serde_json::to_value(&received)?;
        mismatched["body"]["lease_duration"] = json!(-2);
        assert!(
            crate::ha_forward::decode_native_index_response_for_cluster(
                &rewrite_frame(&n1, &mismatched)?,
                "signed-kv1-ha"
            )
            .is_err()
        );
        let mut no_marker = serde_json::to_value(&received)?;
        no_marker
            .as_object_mut()
            .ok_or("frame")?
            .remove("unwrapped_json");
        let mut no_marker = crate::ha_forward::decode_native_index_response_for_cluster(
            &rewrite_frame(&n1, &no_marker)?,
            "signed-kv1-ha",
        )?;
        let body = std::mem::take(&mut no_marker.body);
        let (status, body) = wire_response(
            Response {
                status: 200,
                body,
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
            },
            "",
            "signed/value",
            0xe4,
        )?;
        assert_eq!(status, 503);
        assert!(body.get("data").is_none_or(Value::is_null));
    }
    Ok(())
}

#[test]
fn formal_v6_signed_kv1_wrapped_special_data_keeps_original_selector_after_cold() -> TestResult {
    let (root, mut service, key, token) = signed_fixture()?;
    let mut wrappers = Vec::new();
    for (index, (path, data)) in [
        (
            "signed/raw",
            json!({"http_status_code":200,
            "http_content_type":"application/octet-stream","http_raw_body":"MAMKAQE="}),
        ),
        (
            "signed/selected",
            json!({"http_content_type":"text/plain",
            "http_raw_body":"YQ==\n","extra":"must-not-be-selected"}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        write_v1(&mut service, &token, path, data);
        let mut get = ServiceRequest::new("GET", path, "", &token, json!({}));
        get.wrap_ttl_seconds = Some(60);
        let (status, body) = wire_request(&mut service, get, 0xf1 + index as u8)?;
        assert_eq!(status, 200, "{:?}", body.get("errors"));
        wrappers.push(Zeroizing::new(
            body["wrap_info"]["token"]
                .as_str()
                .ok_or("special wrapper token")?
                .to_owned(),
        ));
    }
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_general_wrapped_reply_state()
    );
    drop(service);
    let mut service = reopen(&root, &key)?;
    let bytes = {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            std::time::Instant::now() + Duration::from_secs(15),
        );
        let _ingress = crate::auth::IngressReplyScope::listener_wrapping(&[0xf3; 16], None);
        let response = service.handle_request(ServiceRequest::new(
            "POST",
            "sys/wrapping/unwrap",
            "",
            &wrappers[0],
            json!({}),
        ));
        crate::http::signed_kv1_wire_projection_fixture(
            response,
            "",
            "sys/wrapping/unwrap",
            &[0xf3; 16],
        )?
    };
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("raw header")?;
    let header = std::str::from_utf8(&bytes[..split])?;
    assert!(header.starts_with("HTTP/1.1 200 "));
    assert!(
        header
            .to_ascii_lowercase()
            .contains("content-type: application/octet-stream")
    );
    assert_eq!(&bytes[split + 4..], &[0x30, 3, 10, 1, 1]);
    let (status, body) = wire_request(
        &mut service,
        ServiceRequest::new("POST", "sys/wrapping/unwrap", "", &wrappers[1], json!({})),
        0xf4,
    )?;
    assert_eq!(status, 200, "{:?}", body.get("errors"));
    // Fixed official 2.7.1 selected-Data unwrap projects canonical zero metadata
    // for both configured 30 and -1 TTLs (actual special44 receipt f3f5e540...).
    assert_eq!(body["lease_duration"], 0);
    assert_eq!(body["renewable"], false);
    assert_eq!(
        body["data"],
        json!({"http_content_type":"text/plain","http_raw_body":"YQ=="})
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_static_kv1_wrapped_reply_state()
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_general_wrapped_reply_state()
    );
    Ok(())
}
