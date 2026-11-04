//! Codec boundaries only. Real Service/Actor/completion delivery still belongs
//! to the original native/HA tests and the actual multi-host acceptance run.
use super::*;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CLUSTER: &str = "native-index-capacity-fixture";

fn context<'a>(body: &'a Value, path: &'a str) -> ForwardContext<'a> {
    ForwardContext {
        method: "GET",
        path,
        namespace: "",
        token: "synthetic-native-index-token",
        body,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        caller_deadline: None,
    }
}

fn response(body: Value) -> crate::Response {
    crate::Response {
        status: 200,
        body,
        unwrapped_json: None,
        response_headers: Default::default(),
        consistency_index: None,
    }
}

fn json_frame(magic: &[u8; 5], value: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(value)?;
    let mut frame = magic.to_vec();
    frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

fn reset_length(frame: &mut [u8]) -> TestResult {
    let length = u32::try_from(
        frame
            .len()
            .checked_sub(9)
            .ok_or("short synthetic JSON frame")?,
    )?;
    frame[5..9].copy_from_slice(&length.to_be_bytes());
    Ok(())
}

#[test]
fn native_index_capacity_negotiation_requires_nonce_and_original_one_mib_request() -> TestResult {
    let body = json!({"value":""});
    let request = context(&body, "secret/data/history?version=3");
    let old = encode_completed_index_request_for_cluster(CLUSTER, (1, 2), &request, Some([6; 32]))?;
    let new = encode_completed_request_with_native_index_capacity(
        CLUSTER,
        (1, 2),
        &request,
        Some([6; 32]),
    )?;
    assert!(old.starts_with(INDEX_REQUEST_MAGIC));
    assert!(new.starts_with(NATIVE_INDEX_REQUEST_MAGIC));
    assert_eq!(&old[5..], &new[5..]);
    assert_ne!(
        crate::ha_forward_completion::digest(&old),
        crate::ha_forward_completion::digest(&new)
    );
    let admitted = decode_request_for_cluster(&new, CLUSTER)?;
    assert!(admitted.native_index_response && admitted.index_response);
    assert!(!admitted.unwrap_response && !admitted.legacy_v1);
    assert_eq!(admitted.completion_nonce, Some([6; 32]));
    assert!(decode_request_for_cluster(&new, "foreign-cluster").is_err());
    for old_magic in [
        REQUEST_MAGIC,
        WRAPPED_REQUEST_MAGIC,
        PEER_REQUEST_MAGIC,
        INDEX_REQUEST_MAGIC,
        UNWRAP_REQUEST_MAGIC,
        FORM_INDEX_REQUEST_MAGIC,
        FORM_UNWRAP_REQUEST_MAGIC,
    ] {
        assert!(decode::<ForwardRequest>(old_magic, &new).is_err());
    }
    assert!(
        encode_completed_request_with_native_index_capacity(CLUSTER, (1, 2), &request, None)
            .is_err()
    );
    let mut missing_nonce: Value = serde_json::from_slice(&new[9..])?;
    missing_nonce
        .as_object_mut()
        .ok_or("request object")?
        .remove("completion_nonce");
    assert!(
        decode_request_for_cluster(
            &json_frame(NATIVE_INDEX_REQUEST_MAGIC, &missing_nonce)?,
            CLUSTER
        )
        .is_err()
    );

    let at_limit = json!({"value":"x".repeat(MAX_FORWARD_FRAME_BYTES - new.len())});
    let exact = encode_completed_request_with_native_index_capacity(
        CLUSTER,
        (1, 2),
        &context(&at_limit, request.path),
        Some([6; 32]),
    )?;
    assert_eq!(exact.len(), MAX_FORWARD_FRAME_BYTES);
    assert!(decode_request_for_cluster(&exact, CLUSTER).is_ok());
    let over_limit = json!({"value":"x".repeat(MAX_FORWARD_FRAME_BYTES - new.len() + 1)});
    assert!(
        encode_completed_request_with_native_index_capacity(
            CLUSTER,
            (1, 2),
            &context(&over_limit, request.path),
            Some([6; 32])
        )
        .is_err()
    );
    assert!(
        encode_completed_index_request_for_cluster(
            CLUSTER,
            (1, 2),
            &context(&over_limit, request.path),
            Some([6; 32])
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn native_index_capacity_preserves_old_unwrap_workflow_and_form_versions() -> TestResult {
    let body = json!({});
    for path in ["sys/wrapping/unwrap", "sys/workflows/execute/fixture"] {
        let request = context(&body, path);
        let old =
            encode_completed_index_request_for_cluster(CLUSTER, (1, 2), &request, Some([7; 32]))?;
        let new = encode_completed_request_with_native_index_capacity(
            CLUSTER,
            (1, 2),
            &request,
            Some([7; 32]),
        )?;
        assert_eq!(old, new);
        assert!(new.starts_with(UNWRAP_REQUEST_MAGIC));
        assert!(!decode_request_for_cluster(&new, CLUSTER)?.native_index_response);
        let mut invalid_upgrade = new;
        invalid_upgrade[..5].copy_from_slice(NATIVE_INDEX_REQUEST_MAGIC);
        assert!(decode_request_for_cluster(&invalid_upgrade, CLUSTER).is_err());
    }
    let form_body = json!({"role_id":"synthetic-role", "secret_id":"synthetic-secret"});
    let mut request = context(&form_body, "auth/forms/login");
    request.method = "POST";
    let mut data = crate::request_metadata::DataFrame::default();
    data.headers.insert(
        crate::request_metadata::AUTH_FORM_CODEC_HEADER.into(),
        vec!["approle-form-v1".into()],
    );
    let _data =
        crate::request_metadata::Scope::enter(Some(data), "POST", request.path, "", &form_body)?;
    let ordinary = encode_completed_request_with_native_index_capacity(
        CLUSTER,
        (1, 2),
        &request,
        Some([8; 32]),
    )?;
    assert!(ordinary.starts_with(FORM_INDEX_REQUEST_MAGIC));
    assert!(!decode_request_for_cluster(&ordinary, CLUSTER)?.native_index_response);
    let mut invalid_upgrade = ordinary;
    invalid_upgrade[..5].copy_from_slice(NATIVE_INDEX_REQUEST_MAGIC);
    assert!(decode_request_for_cluster(&invalid_upgrade, CLUSTER).is_err());
    let _ingress = crate::auth::IngressReplyScope::listener(&[0x96; 16]);
    request.wrap_ttl_seconds = Some(60);
    let wrapped = encode_completed_request_with_native_index_capacity(
        CLUSTER,
        (1, 2),
        &request,
        Some([9; 32]),
    )?;
    assert!(wrapped.starts_with(FORM_UNWRAP_REQUEST_MAGIC));
    assert!(!decode_request_for_cluster(&wrapped, CLUSTER)?.native_index_response);
    Ok(())
}

#[test]
fn native_index_capacity_roundtrips_two_mib_base64_with_index_headers_and_digest() -> TestResult {
    let binary = vec![0xa5_u8; 2 * 1024 * 1024];
    let mut reply = response(
        json!({"data":{"data":{"payload":STANDARD.encode(&binary),"integer":9007199254740993_u64,"escaped":"\u{0}\n\\\""},"metadata":{"version":3,"destroyed":false}}}),
    );
    reply.consistency_index = crate::http::consistency::IndexValue::for_raft(CLUSTER, 42).wire();
    reply.response_headers = crate::service::ResponseHeaders::from_sdk(
        Some(&json!({"X-Approved-Fixture":["first","second"]})),
        &["X-Approved-Fixture".into()],
    )
    .map_err(|()| "response header fixture")?;
    assert!(encode_completed_index_response_for_cluster(CLUSTER, 2, 1, &reply, None).is_err());
    let frame = encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &reply, None)?;
    assert!(frame.len() > binary.len() * 4 / 3 && frame.starts_with(NATIVE_INDEX_RESPONSE_MAGIC));
    assert!(decode_index_response_for_cluster(&frame, CLUSTER).is_err());
    let decoded = decode_native_index_response_for_cluster(&frame, CLUSTER)?;
    assert_eq!(decoded.body, reply.body);
    assert_eq!(
        (
            decoded.source,
            decoded.target,
            decoded.status,
            decoded.consistency_index
        ),
        (2, 1, 200, Some(42))
    );
    assert_eq!(
        STANDARD.decode(
            decoded.body["data"]["data"]["payload"]
                .as_str()
                .ok_or("payload")?
        )?,
        binary
    );
    let mut headers = Vec::new();
    decoded.response_headers.write(&mut headers)?;
    assert_eq!(
        headers,
        b"X-Approved-Fixture: first\r\nX-Approved-Fixture: second\r\n"
    );
    assert_eq!(
        crate::ha_forward_completion::response_digest(&reply)?,
        crate::ha_forward_completion::wire_response_digest(&decoded)?
    );
    assert!(
        decoded.completion.is_none(),
        "codec alone never fabricates a completed authority"
    );
    Ok(())
}

#[test]
fn native_index_capacity_enforces_body_json_wire_boundary_and_escape_cost() -> TestResult {
    let overhead = serde_json::to_vec(&json!({"data":{"value":""}}))?.len();
    let mut reply = response(
        json!({"data":{"value":"x".repeat(MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES - overhead)}}),
    );
    assert_eq!(
        native_index_body_size(&reply.body)?,
        MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES
    );
    let frame = encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &reply, None)?;
    assert!(frame.len() <= MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES);
    let mut decoded = decode_native_index_response_for_cluster(&frame, CLUSTER)?;
    assert_eq!(
        decoded.body["data"]["value"]
            .as_str()
            .ok_or("exact body")?
            .len(),
        MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES - overhead
    );
    drop(frame);
    reply.body["data"]["value"] =
        json!("x".repeat(MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES - overhead + 1));
    assert!(
        encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &reply, None).is_err()
    );
    decoded.body = std::mem::take(&mut reply.body);
    let oversized = json_frame(NATIVE_INDEX_RESPONSE_MAGIC, &decoded)?;
    assert!(
        oversized.len() < MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES,
        "body cap is independent of the metadata reserve"
    );
    assert!(decode_native_index_response_for_cluster(&oversized, CLUSTER).is_err());
    drop(oversized);
    drop(decoded);
    let escaping =
        response(json!({"data":"\u{0}".repeat(MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES / 6 + 1)}));
    assert!(
        encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &escaping, None).is_err()
    );
    Ok(())
}

#[test]
fn native_index_capacity_bounds_metadata_independently_and_rejects_inner_drift() -> TestResult {
    let reply = response(json!({"data":"fixture"}));
    let body_size = native_index_body_size(&reply.body)?;
    let mut frame =
        encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &reply, None)?;
    let extra = MAX_NATIVE_INDEX_RESPONSE_METADATA_BYTES - (frame.len() - body_size);
    frame.resize(frame.len() + extra, b' ');
    reset_length(&mut frame)?;
    assert_eq!(
        frame.len() - body_size,
        MAX_NATIVE_INDEX_RESPONSE_METADATA_BYTES
    );
    assert!(decode_native_index_response_for_cluster(&frame, CLUSTER).is_ok());
    frame.push(b' ');
    reset_length(&mut frame)?;
    assert!(frame.len() < MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES);
    assert!(decode_native_index_response_for_cluster(&frame, CLUSTER).is_err());
    let valid = encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &reply, None)?;
    let mut drift = valid.clone();
    drift[8] ^= 1;
    assert!(decode_native_index_response_for_cluster(&drift, CLUSTER).is_err());
    let mut trailing = valid.clone();
    trailing.push(b' ');
    assert!(decode_native_index_response_for_cluster(&trailing, CLUSTER).is_err());
    assert!(
        decode_index_response_for_cluster(&valid, CLUSTER).is_err(),
        "unsolicited S7 cannot upgrade a Q4 decoder even for a small reply"
    );
    let old = encode_completed_index_response_for_cluster(CLUSTER, 2, 1, &reply, None)?;
    assert!(decode_native_index_response_for_cluster(&old, CLUSTER).is_err());
    Ok(())
}

#[test]
fn native_index_capacity_rejects_unwrap_claims_foreign_identity_and_status() -> TestResult {
    let reply = response(json!({"data":"fixture"}));
    let frame = encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &reply, None)?;
    assert!(decode_native_index_response_for_cluster(&frame, "foreign-cluster").is_err());
    let raw: Value = serde_json::from_slice(&frame[9..])?;
    for (field, value) in [
        ("target", json!(2)),
        ("status", json!(600)),
        ("unwrapped_json", json!("stored-json")),
        (
            "unrecognized_response_capacity",
            json!(MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES),
        ),
    ] {
        let mut changed = raw.clone();
        changed[field] = value;
        assert!(
            decode_native_index_response_for_cluster(
                &json_frame(NATIVE_INDEX_RESPONSE_MAGIC, &changed)?,
                CLUSTER
            )
            .is_err()
        );
    }
    Ok(())
}

fn frame_with_raw_body(raw_body: &str) -> Vec<u8> {
    let json = format!(
        r#"{{"cluster_id":"{CLUSTER}","source":2,"target":1,"status":200,"body":{raw_body}}}"#
    );
    let mut frame = NATIVE_INDEX_RESPONSE_MAGIC.to_vec();
    frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
    frame.extend_from_slice(json.as_bytes());
    frame
}

#[test]
fn native_index_capacity_raw_unicode_escape_cannot_borrow_metadata_reserve() -> TestResult {
    let overhead = serde_json::to_vec(&json!({"data":""}))?.len();
    let reply =
        response(json!({"data":"x".repeat(MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES - overhead)}));
    let mut frame =
        encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &reply, None)?;
    drop(reply);
    let marker = b"\"body\":{\"data\":\"";
    let position = frame
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("body marker")?
        + marker.len();
    assert_eq!(frame[position], b'x');
    frame.splice(position..position + 1, br#"\u0078"#.iter().copied());
    reset_length(&mut frame)?;
    let wire: NativeIndexResponseWire<'_> = serde_json::from_slice(&frame[9..])?;
    assert_eq!(
        wire.body.get().len(),
        MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES + 5
    );
    assert!(frame.len() < MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES);
    assert!(decode_native_index_response_for_cluster(&frame, CLUSTER).is_err());
    Ok(())
}

#[test]
fn native_index_capacity_raw_internal_whitespace_cannot_borrow_metadata_reserve() -> TestResult {
    let overhead = serde_json::to_vec(&json!({"data":""}))?.len();
    let reply =
        response(json!({"data":"x".repeat(MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES - overhead)}));
    let mut frame =
        encode_completed_native_index_response_for_cluster(CLUSTER, 2, 1, &reply, None)?;
    drop(reply);
    let marker = b"\"body\":{";
    let position = frame
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("body marker")?
        + marker.len();
    frame.insert(position, b' ');
    reset_length(&mut frame)?;
    let wire: NativeIndexResponseWire<'_> = serde_json::from_slice(&frame[9..])?;
    assert_eq!(
        wire.body.get().len(),
        MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES + 1
    );
    assert!(frame.len() < MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES);
    assert!(decode_native_index_response_for_cluster(&frame, CLUSTER).is_err());
    Ok(())
}

#[test]
fn native_index_capacity_negative_zero_growth_cannot_hide_metadata_overflow() -> TestResult {
    let raw_body = format!(r#"{{"x":[{}]}}"#, vec!["-0"; 1024].join(","));
    let raw: &serde_json::value::RawValue = serde_json::from_str(&raw_body)?;
    let canonical = heptabao_domain::json::decode_bounded_ha_response_raw(raw)?;
    let canonical_size = native_index_body_size(&canonical)?;
    assert_eq!(canonical_size, raw_body.len() + 2048);
    let mut frame = frame_with_raw_body(&raw_body);
    let true_metadata = frame.len() - raw_body.len();
    frame.resize(
        frame.len() + MAX_NATIVE_INDEX_RESPONSE_METADATA_BYTES + 1 - true_metadata,
        b' ',
    );
    reset_length(&mut frame)?;
    assert_eq!(
        frame.len() - raw_body.len(),
        MAX_NATIVE_INDEX_RESPONSE_METADATA_BYTES + 1
    );
    assert!(
        frame.len() - canonical_size <= MAX_NATIVE_INDEX_RESPONSE_METADATA_BYTES,
        "old canonical subtraction hid this overflow"
    );
    assert!(decode_native_index_response_for_cluster(&frame, CLUSTER).is_err());
    frame.pop();
    reset_length(&mut frame)?;
    let admitted = decode_native_index_response_for_cluster(&frame, CLUSTER)?;
    assert_eq!(admitted.body, canonical);
    Ok(())
}

#[test]
fn native_index_capacity_canonical_output_growth_retains_its_own_body_bound() -> TestResult {
    let zeroes = vec!["-0"; 1024].join(",");
    let overhead = format!(r#"{{"padding":"","z":[{zeroes}]}}"#).len();
    let padding = "x".repeat(MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES - 1024 - overhead);
    let raw_body = format!(r#"{{"padding":"{padding}","z":[{zeroes}]}}"#);
    drop(padding);
    assert_eq!(raw_body.len(), MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES - 1024);
    let frame = frame_with_raw_body(&raw_body);
    drop(raw_body);
    assert!(frame.len() < MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES);
    assert!(
        decode_native_index_response_for_cluster(&frame, CLUSTER).is_err(),
        "raw body fits but canonical signed zero output expands beyond32MiB"
    );
    Ok(())
}
