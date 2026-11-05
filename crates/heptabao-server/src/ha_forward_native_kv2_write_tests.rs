//! Exact wire/profile boundaries. Product authority is exercised separately
//! by the real three-node Service test; no codec test mints an Actor or receipt.
use super::*;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const CLUSTER: &str = "native-kv2-write-fixture";

fn context(body: &Value) -> ForwardContext<'_> {
    ForwardContext {
        method: "POST",
        path: "secret/data/native-large",
        namespace: "",
        token: "synthetic-native-write-token",
        body,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        caller_deadline: None,
    }
}

fn encode_native(request: &ForwardContext<'_>) -> TestResult<Vec<u8>> {
    Ok(encode_completed_request_with_native_index_capacity(
        CLUSTER,
        (1, 2),
        request,
        Some([42; 32]),
    )?)
}

fn json_frame(magic: &[u8; 5], value: &Value) -> TestResult<Vec<u8>> {
    let json = serde_json::to_vec(value)?;
    let mut frame = magic.to_vec();
    frame.extend_from_slice(&u32::try_from(json.len())?.to_be_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

fn raw_frame(body: &str) -> TestResult<Vec<u8>> {
    let nonce = serde_json::to_string(&[42_u8; 32])?;
    let json = format!(
        r#"{{"cluster_id":"{CLUSTER}","source":1,"target":2,"method":"POST","path":"secret/data/native-large","namespace":"","token":"synthetic-native-write-token","completion_nonce":{nonce},"body":{body}}}"#
    );
    let mut frame = NATIVE_KV2_WRITE_REQUEST_MAGIC.to_vec();
    frame.extend_from_slice(&u32::try_from(json.len())?.to_be_bytes());
    frame.extend_from_slice(json.as_bytes());
    Ok(frame)
}

fn reset_length(frame: &mut [u8]) -> TestResult {
    let length = u32::try_from(frame.len().checked_sub(9).ok_or("short synthetic frame")?)?;
    frame[5..9].copy_from_slice(&length.to_be_bytes());
    Ok(())
}

#[test]
fn native_kv2_write_codec_two_mib_binary_preserves_nonce_peer_data_and_old_small_bytes()
-> TestResult {
    let binary = vec![0xa5_u8; 2 * 1024 * 1024];
    let body = json!({"options":{"cas":0},"data":{"payload":STANDARD.encode(&binary),"integer":9007199254740993_u64}});
    let certificates = vec![vec![0x30_u8, 0x10, 0x22, 0x34]];
    let mut request = context(&body);
    request.client_certificates = Some(&certificates);
    request.origin_peer = Some("192.0.2.40".parse()?);
    let mut data = crate::request_metadata::DataFrame::default();
    data.headers.insert(
        "x-synthetic-forward-binding".into(),
        vec!["retained".into()],
    );
    let _data = crate::request_metadata::Scope::enter(
        Some(data),
        request.method,
        request.path,
        request.namespace,
        &body,
    )?;
    let frame = encode_native(&request)?;
    assert!(frame.starts_with(NATIVE_KV2_WRITE_REQUEST_MAGIC));
    assert!(frame.len() > 2 * 1024 * 1024 && frame.len() <= MAX_NATIVE_KV2_WRITE_FRAME_BYTES);
    let decoded = decode_request_for_cluster(&frame, CLUSTER)?;
    assert!(decoded.body == body);
    assert_eq!(decoded.completion_nonce, Some([42; 32]));
    assert_eq!(decoded.origin_peer, request.origin_peer);
    assert_eq!(decoded.client_certificates.as_ref(), Some(&certificates));
    assert_eq!(
        decoded
            .logical_data
            .as_ref()
            .ok_or("logical data")?
            .headers
            .get("x-synthetic-forward-binding"),
        Some(&vec!["retained".to_owned()])
    );
    assert!(decoded.native_index_response && decoded.index_response);
    assert!(!decoded.unwrap_response && !decoded.legacy_v1);
    assert!(
        encode_completed_index_request_for_cluster(CLUSTER, (1, 2), &request, Some([42; 32]))
            .is_err()
    );
    assert!(
        encode_completed_request_with_native_index_capacity(CLUSTER, (1, 2), &request, None)
            .is_err()
    );
    assert!(decode_request_for_cluster(&frame, "foreign-cluster").is_err());
    for magic in [
        REQUEST_MAGIC,
        WRAPPED_REQUEST_MAGIC,
        PEER_REQUEST_MAGIC,
        INDEX_REQUEST_MAGIC,
        NATIVE_INDEX_REQUEST_MAGIC,
        UNWRAP_REQUEST_MAGIC,
        FORM_INDEX_REQUEST_MAGIC,
        FORM_UNWRAP_REQUEST_MAGIC,
        b"HBFN2",
    ] {
        let mut old = frame.clone();
        old[..5].copy_from_slice(magic);
        assert!(decode_request_for_cluster_compatible(&old, CLUSTER, true).is_err());
    }
    drop(_data);
    let small_body = json!({"options":{"cas":0},"data":{"value":"small"}});
    let small = context(&small_body);
    let old = encode_completed_index_request_for_cluster(CLUSTER, (1, 2), &small, Some([42; 32]))?;
    let new = encode_native(&small)?;
    assert!(new.starts_with(NATIVE_INDEX_REQUEST_MAGIC));
    assert_eq!(&old[5..], &new[5..]);
    assert_ne!(
        crate::ha_forward_completion::digest(&old),
        crate::ha_forward_completion::digest(&new)
    );
    Ok(())
}

#[test]
fn native_kv2_write_codec_refuses_wrong_scope_nonce_identity_and_specialized_claims() -> TestResult
{
    let body = json!({"options":{"cas":0},"data":{"value":"x".repeat(2 * 1024 * 1024)}});
    let valid = encode_native(&context(&body))?;
    let raw: Value = serde_json::from_slice(&valid[9..])?;
    for (field, value) in [
        ("completion_nonce", Value::Null),
        ("source", json!(2)),
        ("method", json!("GET")),
        ("method", json!("DELETE")),
        ("path", json!("auth/custom/data/login")),
        ("path", json!("sys/workflows/execute/fixture")),
        ("path", json!("secret//data/key")),
        ("path", json!("secret/data/key?version=1")),
        ("wrap_ttl_seconds", json!(60)),
        ("wrapped_reply_ingress", json!(vec![0_u8; 16])),
        (
            "logical_data",
            json!({"headers":{"x-heptabao-internal-auth-form-codec":["approle-form-v1"]}}),
        ),
        ("unrecognized_capacity_grant", json!(true)),
    ] {
        let mut changed = raw.clone();
        changed[field] = value;
        assert!(
            decode_request_for_cluster(
                &json_frame(NATIVE_KV2_WRITE_REQUEST_MAGIC, &changed)?,
                CLUSTER
            )
            .is_err()
        );
    }
    for (method, path) in [
        ("GET", "secret/data/native-large"),
        ("POST", "auth/custom/login"),
        ("PUT", "sys/workflows/execute/fixture"),
        ("POST", "secret//data/key"),
    ] {
        let mut request = context(&body);
        request.method = method;
        request.path = path;
        assert!(encode_native(&request).is_err());
    }
    let mut drift = valid.clone();
    drift[8] ^= 1;
    assert!(decode_request_for_cluster(&drift, CLUSTER).is_err());
    drift = valid;
    drift.push(b' ');
    assert!(decode_request_for_cluster(&drift, CLUSTER).is_err());
    Ok(())
}

#[test]
fn native_kv2_write_codec_body_boundary_cannot_borrow_metadata_or_ignore_escape_cost() -> TestResult
{
    let overhead = serde_json::to_vec(&json!({"options":{"cas":0},"data":{"value":""}}))?.len();
    let body = json!({"options":{"cas":0},"data":{"value":"x".repeat(MAX_NATIVE_KV2_WRITE_BODY_BYTES - overhead)}});
    assert_eq!(body_size(&body)?, MAX_NATIVE_KV2_WRITE_BODY_BYTES);
    let exact = encode_native(&context(&body))?;
    assert!(decode_request_for_cluster(&exact, CLUSTER).is_ok());
    let over = json!({"options":{"cas":0},"data":{"value":"x".repeat(MAX_NATIVE_KV2_WRITE_BODY_BYTES - overhead + 1)}});
    assert!(encode_native(&context(&over)).is_err());
    let mut forged: Value = serde_json::from_slice(&exact[9..])?;
    forged["body"] = over;
    let forged = json_frame(NATIVE_KV2_WRITE_REQUEST_MAGIC, &forged)?;
    assert!(forged.len() < MAX_NATIVE_KV2_WRITE_FRAME_BYTES);
    assert!(decode_request_for_cluster(&forged, CLUSTER).is_err());
    let escaped = json!({"data":{"value":"\u{0}".repeat(MAX_NATIVE_KV2_WRITE_BODY_BYTES / 6 + 1)}});
    assert!(encode_native(&context(&escaped)).is_err());
    for whitespace in [false, true] {
        let mut drift = exact.clone();
        let marker = b"\"body\":{";
        let object = drift
            .windows(marker.len())
            .position(|bytes| bytes == marker)
            .ok_or("raw body object")?
            + marker.len();
        if whitespace {
            drift.insert(object, b' ');
        } else {
            let value_marker = b"\"value\":\"";
            let value = drift[object..]
                .windows(value_marker.len())
                .position(|bytes| bytes == value_marker)
                .ok_or("raw body value")?
                + object
                + value_marker.len();
            assert_eq!(drift[value], b'x');
            drift.splice(value..value + 1, br#"\u0078"#.iter().copied());
        }
        reset_length(&mut drift)?;
        assert!(drift.len() < MAX_NATIVE_KV2_WRITE_FRAME_BYTES);
        assert!(decode_request_for_cluster(&drift, CLUSTER).is_err());
    }
    Ok(())
}

#[test]
fn native_kv2_write_codec_metadata_boundary_includes_raw_whitespace_and_frame() -> TestResult {
    let body = json!({"data":{"value":"small"}});
    let mut frame = encode_native(&context(&body))?;
    frame[..5].copy_from_slice(NATIVE_KV2_WRITE_REQUEST_MAGIC);
    let body_bytes = body_size(&body)?;
    let padding = MAX_NATIVE_KV2_WRITE_METADATA_BYTES - (frame.len() - body_bytes);
    frame.resize(frame.len() + padding, b' ');
    reset_length(&mut frame)?;
    assert_eq!(
        frame.len() - body_bytes,
        MAX_NATIVE_KV2_WRITE_METADATA_BYTES
    );
    assert!(decode_request_for_cluster(&frame, CLUSTER).is_ok());
    frame.push(b' ');
    reset_length(&mut frame)?;
    assert!(frame.len() < MAX_NATIVE_KV2_WRITE_FRAME_BYTES);
    assert!(decode_request_for_cluster(&frame, CLUSTER).is_err());
    Ok(())
}

#[test]
fn native_kv2_write_codec_negative_zero_growth_does_not_hide_metadata_overflow() -> TestResult {
    let raw_body = format!(r#"{{"data":{{"zeros":[{}]}}}}"#, vec!["-0"; 1024].join(","));
    let mut frame = raw_frame(&raw_body)?;
    let decoded: ForwardRequest = serde_json::from_slice(&frame[9..])?;
    let canonical = body_size(&decoded.body)?;
    assert_eq!(canonical, raw_body.len() + 2048);
    let true_metadata = frame.len() - raw_body.len();
    frame.resize(
        frame.len() + MAX_NATIVE_KV2_WRITE_METADATA_BYTES + 1 - true_metadata,
        b' ',
    );
    reset_length(&mut frame)?;
    assert!(frame.len() - canonical <= MAX_NATIVE_KV2_WRITE_METADATA_BYTES);
    assert!(decode_request_for_cluster(&frame, CLUSTER).is_err());
    frame.pop();
    reset_length(&mut frame)?;
    assert!(decode_request_for_cluster(&frame, CLUSTER)?.body == decoded.body);
    Ok(())
}

#[test]
fn native_kv2_write_codec_canonical_output_keeps_its_independent_body_limit() -> TestResult {
    let zeros = vec!["-0"; 1024].join(",");
    let overhead = format!(r#"{{"data":{{"padding":"","zeros":[{zeros}]}}}}"#).len();
    let padding = "x".repeat(MAX_NATIVE_KV2_WRITE_BODY_BYTES - 1024 - overhead);
    let raw_body = format!(r#"{{"data":{{"padding":"{padding}","zeros":[{zeros}]}}}}"#);
    assert_eq!(raw_body.len(), MAX_NATIVE_KV2_WRITE_BODY_BYTES - 1024);
    let frame = raw_frame(&raw_body)?;
    assert!(frame.len() < MAX_NATIVE_KV2_WRITE_FRAME_BYTES);
    assert!(decode_request_for_cluster(&frame, CLUSTER).is_err());
    Ok(())
}
