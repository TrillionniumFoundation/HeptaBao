use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const REQUEST_MAGIC: &[u8; 5] = b"HBFQ1";
const WRAPPED_REQUEST_MAGIC: &[u8; 5] = b"HBFQ2";
const PEER_REQUEST_MAGIC: &[u8; 5] = b"HBFQ3";
const RESPONSE_MAGIC: &[u8; 5] = b"HBFS1";
const MAX_FORWARD_FRAME_BYTES: usize = 1024 * 1024;
const MAX_METHOD_BYTES: usize = 8;
const MAX_PATH_BYTES: usize = 8192;
const MAX_NAMESPACE_BYTES: usize = 512;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_CLIENT_CERT_CHAIN: usize = 8;
const MAX_CLIENT_CERT_BYTES: usize = 64 * 1024;
const MAX_CLUSTER_ID_BYTES: usize = 128;
#[cfg(test)]
const TEST_CLUSTER_ID: &str = "test-cluster";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForwardRequest {
    pub cluster_id: String,
    pub source: u64,
    pub target: u64,
    pub method: String,
    pub path: String,
    pub namespace: String,
    pub token: String,
    pub body: Value,
    #[serde(default)]
    pub wrap_ttl_seconds: Option<u64>,
    #[serde(default)]
    pub client_certificates: Option<Vec<Vec<u8>>>,
    #[serde(default)]
    pub origin_peer: Option<std::net::IpAddr>,
    /// True only when an explicitly enabled one-step rolling transition
    /// admitted the pre-cluster-bound HBFQ1 wire after mTLS peer identity.
    #[serde(skip)]
    pub legacy_v1: bool,
}

impl fmt::Debug for ForwardRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForwardRequest")
            .field("source", &self.source)
            .field("target", &self.target)
            .field("method", &self.method)
            .field("path", &"[REDACTED]")
            .field("namespace", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ForwardRequest {
    fn drop(&mut self) {
        self.token.zeroize();
        if let Some(certificates) = &mut self.client_certificates {
            certificates.iter_mut().for_each(Vec::zeroize);
        }
        erase_json(&mut self.body);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyForwardRequest {
    source: u64,
    target: u64,
    method: String,
    path: String,
    namespace: String,
    token: String,
    body: Value,
}

impl Drop for LegacyForwardRequest {
    fn drop(&mut self) {
        self.token.zeroize();
        erase_json(&mut self.body);
    }
}

#[derive(Serialize)]
struct LegacyForwardRequestRef<'a> {
    source: u64,
    target: u64,
    method: &'a str,
    path: &'a str,
    namespace: &'a str,
    token: &'a str,
    body: &'a Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyForwardResponse {
    source: u64,
    target: u64,
    status: u16,
    body: Value,
}

impl Drop for LegacyForwardResponse {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

#[derive(Serialize)]
struct ForwardRequestRef<'a> {
    cluster_id: &'a str,
    source: u64,
    target: u64,
    method: &'a str,
    path: &'a str,
    namespace: &'a str,
    token: &'a str,
    body: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    wrap_ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_certificates: Option<&'a [Vec<u8>]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_peer: Option<std::net::IpAddr>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForwardResponse {
    pub cluster_id: String,
    pub source: u64,
    pub target: u64,
    pub status: u16,
    pub body: Value,
}

impl fmt::Debug for ForwardResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForwardResponse")
            .field("source", &self.source)
            .field("target", &self.target)
            .field("status", &self.status)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ForwardResponse {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

pub(crate) fn is_forward_request(encoded: &[u8]) -> bool {
    encoded.starts_with(REQUEST_MAGIC)
        || encoded.starts_with(WRAPPED_REQUEST_MAGIC)
        || encoded.starts_with(PEER_REQUEST_MAGIC)
}

#[cfg(test)]
pub(crate) fn encode_request(
    source: u64,
    target: u64,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
) -> Result<Vec<u8>, String> {
    encode_request_with_client_certificates(
        source, target, method, path, namespace, token, body, None,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_request_with_client_certificates(
    source: u64,
    target: u64,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
    client_certificates: Option<&[Vec<u8>]>,
) -> Result<Vec<u8>, String> {
    encode_request_for_cluster(
        TEST_CLUSTER_ID,
        source,
        target,
        method,
        path,
        namespace,
        token,
        body,
        client_certificates,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_request_for_cluster(
    cluster_id: &str,
    source: u64,
    target: u64,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
    client_certificates: Option<&[Vec<u8>]>,
) -> Result<Vec<u8>, String> {
    validate_cluster_id(cluster_id)?;
    validate_direction(source, target)?;
    validate_request_fields(method, path, namespace, token)?;
    validate_client_certificates(client_certificates)?;
    encode(
        REQUEST_MAGIC,
        &ForwardRequestRef {
            cluster_id,
            source,
            target,
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: None,
            client_certificates,
            origin_peer: None,
        },
    )
}

#[cfg(test)]
pub(crate) fn encode_wrapped_request(
    direction: (u64, u64),
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
    ttl: u64,
) -> Result<Vec<u8>, String> {
    encode_wrapped_request_with_client_certificates(
        direction, method, path, namespace, token, body, ttl, None,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_wrapped_request_with_client_certificates(
    direction: (u64, u64),
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
    ttl: u64,
    client_certificates: Option<&[Vec<u8>]>,
) -> Result<Vec<u8>, String> {
    encode_wrapped_request_for_cluster(
        TEST_CLUSTER_ID,
        direction,
        method,
        path,
        namespace,
        token,
        body,
        ttl,
        client_certificates,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_wrapped_request_for_cluster(
    cluster_id: &str,
    direction: (u64, u64),
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
    ttl: u64,
    client_certificates: Option<&[Vec<u8>]>,
) -> Result<Vec<u8>, String> {
    let (source, target) = direction;
    validate_cluster_id(cluster_id)?;
    validate_direction(source, target)?;
    validate_request_fields(method, path, namespace, token)?;
    validate_client_certificates(client_certificates)?;
    if ttl == 0 || ttl > 32 * 24 * 3600 {
        return Err("invalid HA wrapping TTL".into());
    }
    encode(
        WRAPPED_REQUEST_MAGIC,
        &ForwardRequestRef {
            cluster_id,
            source,
            target,
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: Some(ttl),
            client_certificates,
            origin_peer: None,
        },
    )
}

/// HBFQ3 is accepted only through the peer-authenticated listener. The source
/// node attests this socket IP together with the complete request inside mTLS.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_peer_request_for_cluster(
    cluster_id: &str,
    direction: (u64, u64),
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
    wrap_ttl_seconds: Option<u64>,
    client_certificates: Option<&[Vec<u8>]>,
    origin_peer: std::net::IpAddr,
) -> Result<Vec<u8>, String> {
    validate_cluster_id(cluster_id)?;
    validate_direction(direction.0, direction.1)?;
    validate_request_fields(method, path, namespace, token)?;
    validate_client_certificates(client_certificates)?;
    if wrap_ttl_seconds.is_some_and(|ttl| ttl == 0 || ttl > 32 * 24 * 3600) {
        return Err("HA wrapping TTL is invalid".into());
    }
    encode(
        PEER_REQUEST_MAGIC,
        &ForwardRequestRef {
            cluster_id,
            source: direction.0,
            target: direction.1,
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds,
            client_certificates,
            origin_peer: Some(origin_peer),
        },
    )
}

pub(crate) fn decode_request(encoded: &[u8]) -> Result<ForwardRequest, String> {
    let with_peer = encoded.starts_with(PEER_REQUEST_MAGIC);
    let wrapped = encoded.starts_with(WRAPPED_REQUEST_MAGIC);
    let magic = if with_peer {
        PEER_REQUEST_MAGIC
    } else if wrapped {
        WRAPPED_REQUEST_MAGIC
    } else {
        REQUEST_MAGIC
    };
    let request: ForwardRequest = decode(magic, encoded)?;
    if with_peer != request.origin_peer.is_some()
        || !with_peer && wrapped != request.wrap_ttl_seconds.is_some()
        || request
            .wrap_ttl_seconds
            .is_some_and(|ttl| ttl == 0 || ttl > 32 * 24 * 3600)
    {
        return Err("HA wrapping version or TTL mismatch".into());
    }
    validate_direction(request.source, request.target)?;
    validate_cluster_id(&request.cluster_id)?;
    validate_request_fields(
        &request.method,
        &request.path,
        &request.namespace,
        &request.token,
    )?;
    validate_client_certificates(request.client_certificates.as_deref())?;
    Ok(request)
}

pub(crate) fn decode_request_for_cluster(
    encoded: &[u8],
    expected_cluster_id: &str,
) -> Result<ForwardRequest, String> {
    validate_cluster_id(expected_cluster_id)?;
    let request = decode_request(encoded)?;
    if request.cluster_id != expected_cluster_id {
        return Err("HA forward cluster identity is invalid".into());
    }
    Ok(request)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_legacy_request_for_transition(
    source: u64,
    target: u64,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
) -> Result<Vec<u8>, String> {
    validate_direction(source, target)?;
    validate_request_fields(method, path, namespace, token)?;
    encode(
        REQUEST_MAGIC,
        &LegacyForwardRequestRef {
            source,
            target,
            method,
            path,
            namespace,
            token,
            body,
        },
    )
}

/// Accept the pre-cluster-bound HBFQ1 shape only when the deployment has
/// explicitly enabled the one-step rolling transition. The caller must have
/// already authenticated the transport peer with the pinned mTLS identity.
pub(crate) fn decode_request_for_cluster_compatible(
    encoded: &[u8],
    expected_cluster_id: &str,
    allow_legacy_v1: bool,
) -> Result<ForwardRequest, String> {
    match decode_request_for_cluster(encoded, expected_cluster_id) {
        Ok(request) => Ok(request),
        Err(strict_error) if allow_legacy_v1 && encoded.starts_with(REQUEST_MAGIC) => {
            validate_cluster_id(expected_cluster_id)?;
            let mut legacy: LegacyForwardRequest =
                decode(REQUEST_MAGIC, encoded).map_err(|_| strict_error)?;
            validate_direction(legacy.source, legacy.target)?;
            validate_request_fields(
                &legacy.method,
                &legacy.path,
                &legacy.namespace,
                &legacy.token,
            )?;
            Ok(ForwardRequest {
                cluster_id: expected_cluster_id.to_owned(),
                source: legacy.source,
                target: legacy.target,
                method: std::mem::take(&mut legacy.method),
                path: std::mem::take(&mut legacy.path),
                namespace: std::mem::take(&mut legacy.namespace),
                token: std::mem::take(&mut legacy.token),
                body: std::mem::take(&mut legacy.body),
                wrap_ttl_seconds: None,
                client_certificates: None,
                origin_peer: None,
                legacy_v1: true,
            })
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
pub(crate) fn encode_response(
    source: u64,
    target: u64,
    status: u16,
    body: &Value,
) -> Result<Vec<u8>, String> {
    encode_response_for_cluster(TEST_CLUSTER_ID, source, target, status, body)
}

pub(crate) fn encode_response_for_cluster(
    cluster_id: &str,
    source: u64,
    target: u64,
    status: u16,
    body: &Value,
) -> Result<Vec<u8>, String> {
    validate_cluster_id(cluster_id)?;
    validate_direction(source, target)?;
    if !(100..=599).contains(&status) {
        return Err("HA forward response status is invalid".into());
    }
    encode(
        RESPONSE_MAGIC,
        &ForwardResponse {
            cluster_id: cluster_id.to_owned(),
            source,
            target,
            status,
            body: body.clone(),
        },
    )
}

pub(crate) fn decode_response(encoded: &[u8]) -> Result<ForwardResponse, String> {
    let response: ForwardResponse = decode(RESPONSE_MAGIC, encoded)?;
    validate_direction(response.source, response.target)?;
    validate_cluster_id(&response.cluster_id)?;
    if !(100..=599).contains(&response.status) {
        return Err("HA forward response status is invalid".into());
    }
    Ok(response)
}

pub(crate) fn decode_response_for_cluster(
    encoded: &[u8],
    expected_cluster_id: &str,
) -> Result<ForwardResponse, String> {
    validate_cluster_id(expected_cluster_id)?;
    let response = decode_response(encoded)?;
    if response.cluster_id != expected_cluster_id {
        return Err("HA forward response cluster identity is invalid".into());
    }
    Ok(response)
}

pub(crate) fn encode_legacy_response_for_transition(
    source: u64,
    target: u64,
    status: u16,
    body: &Value,
) -> Result<Vec<u8>, String> {
    validate_direction(source, target)?;
    if !(100..=599).contains(&status) {
        return Err("HA forward response status is invalid".into());
    }
    encode(
        RESPONSE_MAGIC,
        &LegacyForwardResponse {
            source,
            target,
            status,
            body: body.clone(),
        },
    )
}

pub(crate) fn decode_legacy_response_for_transition(
    encoded: &[u8],
    expected_cluster_id: &str,
) -> Result<ForwardResponse, String> {
    validate_cluster_id(expected_cluster_id)?;
    let mut response: LegacyForwardResponse = decode(RESPONSE_MAGIC, encoded)?;
    validate_direction(response.source, response.target)?;
    if !(100..=599).contains(&response.status) {
        return Err("HA forward response status is invalid".into());
    }
    Ok(ForwardResponse {
        cluster_id: expected_cluster_id.to_owned(),
        source: response.source,
        target: response.target,
        status: response.status,
        body: std::mem::take(&mut response.body),
    })
}

fn validate_direction(source: u64, target: u64) -> Result<(), String> {
    if source == 0 || target == 0 || source == target {
        return Err("HA forward direction is invalid".into());
    }
    Ok(())
}

fn validate_cluster_id(cluster_id: &str) -> Result<(), String> {
    if cluster_id.is_empty() || cluster_id.len() > MAX_CLUSTER_ID_BYTES {
        return Err("HA cluster identity is outside bounds".into());
    }
    if cluster_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Ok(());
    }
    let decoded = STANDARD
        .decode(cluster_id)
        .map_err(|_| "HA cluster identity is invalid")?;
    if decoded.len() == 16 && STANDARD.encode(decoded) == cluster_id {
        Ok(())
    } else {
        Err("HA cluster identity is invalid".into())
    }
}

fn validate_request_fields(
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
) -> Result<(), String> {
    if method.is_empty()
        || method.len() > MAX_METHOD_BYTES
        || !matches!(
            method,
            "GET" | "POST" | "PUT" | "DELETE" | "LIST" | "SCAN" | "PATCH" | "HEAD"
        )
        || path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || namespace.len() > MAX_NAMESPACE_BYTES
        || token.len() > MAX_TOKEN_BYTES
    {
        return Err("HA forward request is outside bounded API shape".into());
    }
    Ok(())
}

fn validate_client_certificates(certificates: Option<&[Vec<u8>]>) -> Result<(), String> {
    let Some(certificates) = certificates else {
        return Ok(());
    };
    if certificates.is_empty()
        || certificates.len() > MAX_CLIENT_CERT_CHAIN
        || certificates
            .iter()
            .any(|certificate| certificate.is_empty() || certificate.len() > MAX_CLIENT_CERT_BYTES)
    {
        return Err("HA client certificate chain is outside bounds".into());
    }
    Ok(())
}

fn encode<T: Serialize>(magic: &[u8; 5], value: &T) -> Result<Vec<u8>, String> {
    let json =
        Zeroizing::new(serde_json::to_vec(value).map_err(|_| "cannot encode HA forward frame")?);
    if json.len() > MAX_FORWARD_FRAME_BYTES - 9 {
        return Err("HA forward frame exceeds transport bound".into());
    }
    let length = u32::try_from(json.len()).map_err(|_| "HA forward frame is oversized")?;
    let mut encoded = Vec::with_capacity(9 + json.len());
    encoded.extend_from_slice(magic);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(&json);
    Ok(encoded)
}

fn decode<T: for<'de> Deserialize<'de>>(magic: &[u8; 5], encoded: &[u8]) -> Result<T, String> {
    if encoded.len() < 9 || encoded.len() > MAX_FORWARD_FRAME_BYTES || &encoded[..5] != magic {
        return Err("HA forward frame is invalid".into());
    }
    let length = u32::from_be_bytes(
        encoded[5..9]
            .try_into()
            .map_err(|_| "HA forward frame length is invalid")?,
    ) as usize;
    if encoded.len() != 9 + length {
        return Err("HA forward frame length does not match payload".into());
    }
    serde_json::from_slice(&encoded[9..]).map_err(|_| "HA forward frame JSON is invalid".into())
}

fn erase_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(erase_json),
        Value::Object(values) => values.values_mut().for_each(erase_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    *value = Value::Null;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_and_response_bind_direction_and_bounds() -> Result<(), String> {
        let request = encode_request(
            1,
            2,
            "POST",
            "secret/data/demo",
            "team-a",
            "synthetic-token",
            &json!({"data":{"value":"synthetic"}}),
        )?;
        let request = decode_request(&request)?;
        assert_eq!(request.source, 1);
        assert_eq!(request.target, 2);
        assert_eq!(request.method, "POST");
        assert_eq!(request.cluster_id, TEST_CLUSTER_ID);

        let response = encode_response(2, 1, 200, &json!({"data":{"version":1}}))?;
        let response = decode_response(&response)?;
        assert_eq!(response.source, 2);
        assert_eq!(response.target, 1);
        assert_eq!(response.status, 200);
        assert_eq!(response.cluster_id, TEST_CLUSTER_ID);
        Ok(())
    }

    #[test]
    fn cross_cluster_forward_frames_are_rejected() -> Result<(), String> {
        let request = encode_request_for_cluster(
            "cluster-a",
            1,
            2,
            "GET",
            "secret/data/demo",
            "",
            "token",
            &json!({}),
            None,
        )?;
        assert!(decode_request_for_cluster(&request, "cluster-a").is_ok());
        assert!(decode_request_for_cluster(&request, "cluster-b").is_err());

        let response = encode_response_for_cluster("cluster-a", 2, 1, 200, &json!({}))?;
        assert!(decode_response_for_cluster(&response, "cluster-a").is_ok());
        assert!(decode_response_for_cluster(&response, "cluster-b").is_err());
        Ok(())
    }

    #[test]
    fn legacy_v1_transition_is_explicit_and_cannot_bypass_cluster_binding() -> Result<(), String> {
        let legacy = encode_legacy_request_for_transition(
            1,
            2,
            "GET",
            "secret/data/demo",
            "",
            "synthetic-token",
            &json!({}),
        )?;
        assert!(decode_request_for_cluster(&legacy, "cluster-a").is_err());
        assert!(decode_request_for_cluster_compatible(&legacy, "cluster-a", false).is_err());
        let admitted = decode_request_for_cluster_compatible(&legacy, "cluster-a", true)?;
        assert!(admitted.legacy_v1);
        assert_eq!(admitted.cluster_id, "cluster-a");

        let foreign = encode_request_for_cluster(
            "cluster-b",
            1,
            2,
            "GET",
            "secret/data/demo",
            "",
            "synthetic-token",
            &json!({}),
            None,
        )?;
        assert!(decode_request_for_cluster_compatible(&foreign, "cluster-a", true).is_err());

        let legacy_response =
            encode_legacy_response_for_transition(2, 1, 200, &json!({"ok":true}))?;
        assert!(decode_response_for_cluster(&legacy_response, "cluster-a").is_err());
        let response = decode_legacy_response_for_transition(&legacy_response, "cluster-a")?;
        assert_eq!(response.cluster_id, "cluster-a");
        assert_eq!(response.status, 200);
        Ok(())
    }

    #[test]
    fn rejects_self_direction_unknown_method_and_length_drift() -> Result<(), String> {
        assert!(encode_request(1, 1, "GET", "sys/health", "", "", &json!({})).is_err());
        assert!(encode_request(1, 2, "TRACE", "sys/health", "", "", &json!({})).is_err());
        let mut encoded = encode_request(1, 2, "GET", "secret/data/a", "", "", &json!({}))?;
        encoded[8] ^= 1;
        assert!(decode_request(&encoded).is_err());
        Ok(())
    }

    #[test]
    fn debug_never_discloses_forward_credentials_or_payloads() -> Result<(), String> {
        let encoded = encode_request(
            1,
            2,
            "POST",
            "secret/data/private-path",
            "private-namespace",
            "private-bearer",
            &json!({"private-field":"private-value"}),
        )?;
        let request = decode_request(&encoded)?;
        let debug = format!("{request:?}");
        for value in [
            "private-path",
            "private-namespace",
            "private-bearer",
            "private-field",
            "private-value",
        ] {
            assert!(!debug.contains(value));
        }
        assert!(debug.contains("[REDACTED]"));
        let encoded = encode_response(2, 1, 200, &json!({"client_token":"private-new-token"}))?;
        let response = decode_response(&encoded)?;
        let debug = format!("{response:?}");
        assert!(!debug.contains("private-new-token"));
        assert!(!debug.contains("client_token"));
        assert!(debug.contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn oversized_and_trailing_payloads_are_rejected() -> Result<(), String> {
        assert!(
            encode_response(
                2,
                1,
                200,
                &json!({"value":"x".repeat(MAX_FORWARD_FRAME_BYTES)})
            )
            .is_err()
        );
        let mut encoded = encode_response(2, 1, 200, &json!({}))?;
        encoded.push(0);
        assert!(decode_response(&encoded).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod wrapping_frame_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn wrapped_forwarding_binds_options_and_rejects_version_downgrade() -> Result<(), String> {
        let frame = encode_wrapped_request(
            (1, 2),
            "GET",
            "secret/data/a",
            "",
            "synthetic",
            &json!({}),
            60,
        )?;
        let decoded = decode_request(&frame)?;
        assert_eq!(decoded.wrap_ttl_seconds, Some(60));
        assert!(is_forward_request(&frame));
        let mut changed = frame.clone();
        changed[..5].copy_from_slice(REQUEST_MAGIC);
        assert!(decode_request(&changed).is_err());
        let legacy = encode_request(1, 2, "GET", "secret/data/a", "", "synthetic", &json!({}))?;
        assert!(decode_request(&legacy)?.wrap_ttl_seconds.is_none());
        let mut changed = legacy;
        changed[..5].copy_from_slice(WRAPPED_REQUEST_MAGIC);
        assert!(decode_request(&changed).is_err());
        assert!(
            encode_wrapped_request(
                (1, 2),
                "GET",
                "secret/data/a",
                "",
                "synthetic",
                &json!({}),
                0
            )
            .is_err()
        );
        Ok(())
    }
}

#[cfg(test)]
mod peer_frame_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn original_peer_is_typed_versioned_and_bound_with_wrapping_and_cluster() -> Result<(), String>
    {
        for peer in ["127.0.0.2", "2001:db8::2"] {
            let peer: std::net::IpAddr = peer.parse().map_err(|_| "bad test peer")?;
            for ttl in [None, Some(60)] {
                let frame = encode_peer_request_for_cluster(
                    TEST_CLUSTER_ID,
                    (1, 2),
                    "POST",
                    "auth/token/renew-self",
                    "",
                    "synthetic-token",
                    &json!({}),
                    ttl,
                    None,
                    peer,
                )?;
                assert!(frame.starts_with(PEER_REQUEST_MAGIC));
                assert!(is_forward_request(&frame));
                let request = decode_request_for_cluster(&frame, TEST_CLUSTER_ID)?;
                assert_eq!(request.origin_peer, Some(peer));
                assert_eq!(request.wrap_ttl_seconds, ttl);
                assert_eq!((request.source, request.target), (1, 2));
                assert!(decode_request_for_cluster(&frame, "other-cluster").is_err());
                for magic in [REQUEST_MAGIC, WRAPPED_REQUEST_MAGIC] {
                    let mut downgraded = frame.clone();
                    downgraded[..5].copy_from_slice(magic);
                    assert!(decode_request(&downgraded).is_err());
                }
                let mut value: Value =
                    serde_json::from_slice(&frame[9..]).map_err(|_| "bad test frame")?;
                value
                    .as_object_mut()
                    .ok_or("not an object")?
                    .remove("origin_peer");
                assert!(decode_request(&encode(PEER_REQUEST_MAGIC, &value)?).is_err());
                value["origin_peer"] = json!("localhost");
                assert!(decode_request(&encode(PEER_REQUEST_MAGIC, &value)?).is_err());
            }
        }
        let old = encode_request(1, 2, "GET", "secret/data/a", "", "synthetic", &json!({}))?;
        assert!(decode_request(&old)?.origin_peer.is_none());
        let mut falsely_upgraded = old;
        falsely_upgraded[..5].copy_from_slice(PEER_REQUEST_MAGIC);
        assert!(decode_request(&falsely_upgraded).is_err());
        Ok(())
    }
}
