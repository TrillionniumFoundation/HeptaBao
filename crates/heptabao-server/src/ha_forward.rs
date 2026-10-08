use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const REQUEST_MAGIC: &[u8; 5] = b"HBFQ1";
const WRAPPED_REQUEST_MAGIC: &[u8; 5] = b"HBFQ2";
const PEER_REQUEST_MAGIC: &[u8; 5] = b"HBFQ3";
const RESPONSE_MAGIC: &[u8; 5] = b"HBFS1";
// Versioned negotiation: only HBFQ4 clients receive the HBFS2 index sidecar.
// Older frames and their strict decoding remain unchanged; no mutation replay.
const INDEX_REQUEST_MAGIC: &[u8; 5] = b"HBFQ4";
const INDEX_RESPONSE_MAGIC: &[u8; 5] = b"HBFS2";
// Q8/S6 negotiates complete original bytes, lexical ingress and two sticky reader facts. Q5/S3 only
// represented the older newline unit and cannot authorize full reply transfer.
const LEGACY_UNWRAP_REQUEST_MAGIC: &[u8; 5] = b"HBFQ5";
const UNWRAP_REQUEST_MAGIC: &[u8; 5] = b"HBFQ8";
const UNWRAP_RESPONSE_MAGIC: &[u8; 5] = b"HBFS6";
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

pub(crate) struct ForwardContext<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub namespace: &'a str,
    pub token: &'a str,
    pub body: &'a Value,
    pub wrap_ttl_seconds: Option<u64>,
    pub origin_peer: Option<std::net::IpAddr>,
    pub client_certificates: Option<&'a [Vec<u8>]>,
    pub caller_deadline: Option<std::time::Instant>,
}

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
    #[serde(default)]
    pub completion_nonce: Option<[u8; 32]>,
    #[serde(default)]
    pub wrapped_reply_ingress: Option<[u8; 16]>,
    #[serde(default)]
    pub wrapped_reply_lexical: Option<crate::auth::LexicalJson>,
    /// True only when an explicitly enabled one-step rolling transition
    /// admitted the pre-cluster-bound HBFQ1 wire after mTLS peer identity.
    #[serde(skip)]
    pub legacy_v1: bool,
    #[serde(skip)]
    pub index_response: bool,
    #[serde(skip)]
    pub unwrap_response: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_nonce: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wrapped_reply_ingress: Option<[u8; 16]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wrapped_reply_lexical: Option<&'a crate::auth::LexicalJson>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UnwrapFramingWire {
    StoredJson,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForwardResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unwrapped_json: Option<UnwrapFramingWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_wrapped_reply: Option<crate::auth::StoredWrappedReply>,
    pub cluster_id: String,
    pub source: u64,
    pub target: u64,
    pub status: u16,
    pub body: Value,
    #[serde(
        default,
        skip_serializing_if = "crate::service::ResponseHeaders::is_empty"
    )]
    pub response_headers: crate::service::ResponseHeaders,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<crate::ha_forward_completion::CompletionWire>,
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
        || encoded.starts_with(INDEX_REQUEST_MAGIC)
        || encoded.starts_with(UNWRAP_REQUEST_MAGIC)
        || encoded.starts_with(LEGACY_UNWRAP_REQUEST_MAGIC)
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
#[cfg(test)]
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
            completion_nonce: None,
            wrapped_reply_ingress: None,
            wrapped_reply_lexical: None,
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
#[cfg(test)]
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
    if ttl > 32 * 24 * 3600 {
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
            completion_nonce: None,
            wrapped_reply_ingress: None,
            wrapped_reply_lexical: None,
        },
    )
}

/// HBFQ3 is accepted only through the peer-authenticated listener. The source
/// node attests this socket IP together with the complete request inside mTLS.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
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
    if wrap_ttl_seconds.is_some_and(|ttl| ttl > 32 * 24 * 3600) {
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
            completion_nonce: None,
            wrapped_reply_ingress: None,
            wrapped_reply_lexical: None,
        },
    )
}

/// Index-capable forwarding keeps the complete authority tuple and explicitly
/// negotiates response metadata. Unknown versions fail before handler admission.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn encode_index_request_for_cluster(
    cluster_id: &str,
    direction: (u64, u64),
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
    wrap_ttl_seconds: Option<u64>,
    client_certificates: Option<&[Vec<u8>]>,
    origin_peer: Option<std::net::IpAddr>,
) -> Result<Vec<u8>, String> {
    encode_completed_index_request_for_cluster(
        cluster_id,
        direction,
        &ForwardContext {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds,
            origin_peer,
            client_certificates,
            caller_deadline: None,
        },
        None,
    )
}

pub(crate) fn encode_completed_index_request_for_cluster(
    cluster_id: &str,
    direction: (u64, u64),
    context: &ForwardContext<'_>,
    completion_nonce: Option<[u8; 32]>,
) -> Result<Vec<u8>, String> {
    let method = context.method;
    let path = context.path;
    let namespace = context.namespace;
    let token = context.token;
    let body = context.body;
    let wrap_ttl_seconds = context.wrap_ttl_seconds;
    let origin_peer = context.origin_peer;
    let client_certificates = context.client_certificates;
    validate_cluster_id(cluster_id)?;
    validate_direction(direction.0, direction.1)?;
    validate_request_fields(method, path, namespace, token)?;
    validate_client_certificates(client_certificates)?;
    let wrapped_reply_context = crate::auth::current_ingress();
    let wrapped_reply_ingress = wrapped_reply_context
        .as_ref()
        .map(|context| context.attempt_id());
    let wrapped_reply_lexical = wrapped_reply_context
        .as_ref()
        .and_then(|context| context.wrapping_body());
    if let Some(context) = &wrapped_reply_context {
        context
            .lexical_request_binding(method, path, body)
            .map_err(|_| "HA private lexical request binding differs")?;
    }
    let full_reply = path == "sys/wrapping/unwrap"
        || wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) && wrapped_reply_ingress.is_some()
        || wrapped_reply_lexical.is_some();
    if full_reply && completion_nonce.is_none() {
        return Err("HA unwrap requires original completed-request nonce".into());
    }
    if wrap_ttl_seconds.is_some_and(|ttl| ttl > 32 * 24 * 3600) {
        return Err("HA wrapping TTL is invalid".into());
    }
    encode(
        if full_reply {
            UNWRAP_REQUEST_MAGIC
        } else {
            INDEX_REQUEST_MAGIC
        },
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
            origin_peer,
            completion_nonce,
            wrapped_reply_ingress: if full_reply {
                wrapped_reply_ingress
            } else {
                None
            },
            wrapped_reply_lexical: if full_reply {
                wrapped_reply_lexical
            } else {
                None
            },
        },
    )
}

pub(crate) fn decode_request(encoded: &[u8]) -> Result<ForwardRequest, String> {
    if encoded.starts_with(b"HBFQ7") {
        return Err("HA general stored reply requires Q8 before consumption".into());
    }
    if encoded.starts_with(LEGACY_UNWRAP_REQUEST_MAGIC) {
        return Err("HA original stored reply requires Q7 before consumption".into());
    }
    let unwrap_response = encoded.starts_with(UNWRAP_REQUEST_MAGIC);
    let index_response = encoded.starts_with(INDEX_REQUEST_MAGIC) || unwrap_response;
    let with_peer = encoded.starts_with(PEER_REQUEST_MAGIC);
    let wrapped = encoded.starts_with(WRAPPED_REQUEST_MAGIC);
    let magic = if unwrap_response {
        UNWRAP_REQUEST_MAGIC
    } else if index_response {
        INDEX_REQUEST_MAGIC
    } else if with_peer {
        PEER_REQUEST_MAGIC
    } else if wrapped {
        WRAPPED_REQUEST_MAGIC
    } else {
        REQUEST_MAGIC
    };
    let mut request: ForwardRequest = decode(magic, encoded)?;
    if request.completion_nonce.is_some() && !index_response {
        return Err("HA completion nonce requires negotiated version".into());
    }
    request.index_response = index_response;
    request.unwrap_response = unwrap_response;
    if unwrap_response && request.completion_nonce.is_none() {
        return Err("HA unwrap framing requires original completion nonce".into());
    }
    let full_reply = request.path == "sys/wrapping/unwrap"
        || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
            && request.wrapped_reply_ingress.is_some()
        || request.wrapped_reply_lexical.is_some();
    if let Some(lexical) = &request.wrapped_reply_lexical {
        if !unwrap_response
            || request.wrapped_reply_ingress.is_none()
            || request.path != "sys/wrapping/wrap"
            || !matches!(request.method.as_str(), "POST" | "PUT")
        {
            return Err("HA lexical payload is outside negotiated wrapping ingress".into());
        }
        lexical
            .validate_wrapping_view(&request.body)
            .map_err(|_| "HA lexical payload and complete request body differ")?;
    }
    if unwrap_response != full_reply || !unwrap_response && request.wrapped_reply_ingress.is_some()
    {
        return Err("HA original reply requires explicit negotiated version".into());
    }
    if !index_response
        && (with_peer != request.origin_peer.is_some()
            || !with_peer && wrapped != request.wrap_ttl_seconds.is_some())
        || request
            .wrap_ttl_seconds
            .is_some_and(|ttl| ttl > 32 * 24 * 3600)
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
            if legacy.path == "sys/wrapping/unwrap" {
                return Err("legacy HA peer cannot negotiate unwrap framing".into());
            }
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
                index_response: false,
                unwrap_response: false,
                completion_nonce: None,
                wrapped_reply_ingress: None,
                wrapped_reply_lexical: None,
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
            unwrapped_json: None,
            raw_wrapped_reply: None,
            response_headers: Default::default(),
            consistency_index: None,
            completion: None,
        },
    )
}

#[cfg(test)]
pub(crate) fn encode_index_response_for_cluster(
    cluster_id: &str,
    source: u64,
    target: u64,
    response: &crate::Response,
) -> Result<Vec<u8>, String> {
    encode_completed_index_response_for_cluster(cluster_id, source, target, response, None)
}

pub(crate) fn encode_completed_index_response_for_cluster(
    cluster_id: &str,
    source: u64,
    target: u64,
    response: &crate::Response,
    completion: Option<crate::ha_forward_completion::CompletionWire>,
) -> Result<Vec<u8>, String> {
    encode_completed_framed_response_for_cluster(
        cluster_id, source, target, response, completion, false,
    )
}

pub(crate) fn encode_completed_unwrap_response_for_cluster(
    cluster_id: &str,
    source: u64,
    target: u64,
    response: &crate::Response,
    completion: Option<crate::ha_forward_completion::CompletionWire>,
) -> Result<Vec<u8>, String> {
    encode_completed_framed_response_for_cluster(
        cluster_id, source, target, response, completion, true,
    )
}

fn encode_completed_framed_response_for_cluster(
    cluster_id: &str,
    source: u64,
    target: u64,
    response: &crate::Response,
    completion: Option<crate::ha_forward_completion::CompletionWire>,
    unwrap_response: bool,
) -> Result<Vec<u8>, String> {
    if response.unwrapped_json.is_some()
        && (!unwrap_response || response.status != 200 || !response.body.is_object())
    {
        return Err("HA trusted unwrap origin requires successful negotiated framing".into());
    }
    if let Some(stored) = response
        .unwrapped_json
        .as_ref()
        .and_then(|origin| origin.stored_reply())
    {
        stored
            .validate(&response.body)
            .map_err(|_| "HA stored reply representation rejected")?;
    }
    validate_cluster_id(cluster_id)?;
    validate_direction(source, target)?;
    if !(100..=599).contains(&response.status) {
        return Err("HA forward response status is invalid".into());
    }
    let consistency_index = response
        .consistency_index
        .as_ref()
        .map(|index| {
            index
                .raft_index_for_cluster(cluster_id)
                .ok_or_else(|| "HA response index cluster or value is invalid".to_owned())
        })
        .transpose()?;
    encode(
        if unwrap_response {
            UNWRAP_RESPONSE_MAGIC
        } else {
            INDEX_RESPONSE_MAGIC
        },
        &ForwardResponse {
            cluster_id: cluster_id.to_owned(),
            source,
            target,
            status: response.status,
            body: response.body.clone(),
            unwrapped_json: response
                .unwrapped_json
                .as_ref()
                .map(|_| UnwrapFramingWire::StoredJson),
            raw_wrapped_reply: response
                .unwrapped_json
                .as_ref()
                .and_then(|origin| origin.stored_reply().cloned()),
            response_headers: response.response_headers.copy_for_forward(),
            consistency_index,
            completion,
        },
    )
}

pub(crate) fn decode_index_response_for_cluster(
    encoded: &[u8],
    expected_cluster_id: &str,
) -> Result<ForwardResponse, String> {
    decode_framed_response_for_cluster(encoded, expected_cluster_id, false)
}

pub(crate) fn decode_unwrap_response_for_cluster(
    encoded: &[u8],
    expected_cluster_id: &str,
) -> Result<ForwardResponse, String> {
    decode_framed_response_for_cluster(encoded, expected_cluster_id, true)
}

fn decode_framed_response_for_cluster(
    encoded: &[u8],
    expected_cluster_id: &str,
    unwrap_response: bool,
) -> Result<ForwardResponse, String> {
    let response: ForwardResponse = decode(
        if unwrap_response {
            UNWRAP_RESPONSE_MAGIC
        } else {
            INDEX_RESPONSE_MAGIC
        },
        encoded,
    )?;
    if response.unwrapped_json.is_some()
        && (!unwrap_response || response.status != 200 || !response.body.is_object())
    {
        return Err("HA unwrapped JSON origin is outside negotiated successful reply".into());
    }
    if let Some(stored) = &response.raw_wrapped_reply {
        if !unwrap_response || response.unwrapped_json.is_none() || response.status != 200 {
            return Err("HA original stored reply is outside negotiated consumption".into());
        }
        stored
            .validate(&response.body)
            .map_err(|_| "HA stored reply representation rejected")?;
    }
    validate_direction(response.source, response.target)?;
    validate_cluster_id(&response.cluster_id)?;
    if response.cluster_id != expected_cluster_id || !(100..=599).contains(&response.status) {
        return Err("HA index response identity or status is invalid".into());
    }
    Ok(response)
}

#[cfg(test)]
pub(crate) fn decode_response(encoded: &[u8]) -> Result<ForwardResponse, String> {
    let response: ForwardResponse = decode(RESPONSE_MAGIC, encoded)?;
    if response.unwrapped_json.is_some()
        || response.raw_wrapped_reply.is_some()
        || response.consistency_index.is_some()
        || response.completion.is_some()
        || !response.response_headers.is_empty()
    {
        return Err("HA response index requires negotiated version".into());
    }
    validate_direction(response.source, response.target)?;
    validate_cluster_id(&response.cluster_id)?;
    if !(100..=599).contains(&response.status) {
        return Err("HA forward response status is invalid".into());
    }
    Ok(response)
}

#[cfg(test)]
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
        unwrapped_json: None,
        raw_wrapped_reply: None,
        response_headers: Default::default(),
        consistency_index: None,
        completion: None,
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
            "GET" | "POST" | "PUT" | "DELETE" | "LIST" | "SCAN" | "PATCH" | "HEAD" | "HELP"
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

    #[test]
    fn raw113_actual_q8_lexical_shadow_binding_oldpeer_nonce_and_s6_immutable_reply()
    -> Result<(), Box<dyn std::error::Error>> {
        let lexical = crate::auth::LexicalJson::parse_listener(br#"{"number":1.0,"large":1e309}"#)?;
        let body = lexical.wrapping_view()?;
        let _ingress =
            crate::auth::IngressReplyScope::listener_wrapping(&[0x93; 16], Some(lexical));
        let context = ForwardContext {
            method: "POST",
            path: "sys/wrapping/wrap",
            namespace: "",
            token: "root-fixture",
            body: &body,
            wrap_ttl_seconds: Some(60),
            origin_peer: None,
            client_certificates: None,
            caller_deadline: None,
        };
        assert!(
            encode_completed_index_request_for_cluster("raw113-ha", (1, 2), &context, None)
                .is_err()
        );
        let encoded = encode_completed_index_request_for_cluster(
            "raw113-ha",
            (1, 2),
            &context,
            Some([7; 32]),
        )?;
        assert!(encoded.starts_with(b"HBFQ8"));
        let admitted = decode_request_for_cluster(&encoded, "raw113-ha")?;
        assert!(admitted.wrapped_reply_lexical.is_some() && admitted.unwrap_response);
        assert_eq!(admitted.wrapped_reply_ingress, Some([0x93; 16]));
        assert!(decode_request_for_cluster(&encoded, "wrong-cluster").is_err());
        for magic in [b"HBFQ4", b"HBFQ5", b"HBFQ6", b"HBFQ7"] {
            let mut old = encoded.clone();
            old[..5].copy_from_slice(magic);
            assert!(decode_request_for_cluster(&old, "raw113-ha").is_err());
        }
        let mut wire: Value = serde_json::from_slice(&encoded[9..])?;
        for mutation in 0..4 {
            let mut changed = wire.clone();
            match mutation {
                0 => changed["wrapped_reply_ingress"] = serde_json::Value::Null,
                1 => changed["completion_nonce"] = serde_json::Value::Null,
                2 => changed["body"]["number"] = json!("1.0"),
                _ => changed["path"] = json!("auth/token/create"),
            }
            assert!(
                decode_request_for_cluster(&encode(UNWRAP_REQUEST_MAGIC, &changed)?, "raw113-ha")
                    .is_err()
            );
            erase_json(&mut changed);
        }
        let (mut auth, root) = crate::auth::AuthState::bootstrap(100)?;
        let admin = auth.authenticate(&root, 100)?;
        let wrapped =
            auth.wrap_logical_response("", "sys/wrapping/wrap", 60, &json!({"data":body}), 100)?;
        let token = wrapped.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?;
        let _later = crate::auth::IngressReplyScope::listener(&[0x94; 16]);
        let unwrapped = auth.wrapping_route(
            Some(&admin),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({"token":token}),
            100,
        )?;
        let response = crate::Response {
            status: unwrapped.status,
            body: unwrapped.body,
            unwrapped_json: unwrapped.unwrapped_json,
            response_headers: Default::default(),
            consistency_index: None,
        };
        let encoded =
            encode_completed_unwrap_response_for_cluster("raw113-ha", 2, 1, &response, None)?;
        assert!(encoded.starts_with(b"HBFS6"));
        let received = decode_unwrap_response_for_cluster(&encoded, "raw113-ha")?;
        assert_eq!(
            crate::ha_forward_completion::response_digest(&response)?,
            crate::ha_forward_completion::wire_response_digest(&received)?
        );
        for magic in [b"HBFS3", b"HBFS4", b"HBFS5"] {
            let mut old = encoded.clone();
            old[..5].copy_from_slice(magic);
            assert!(decode_unwrap_response_for_cluster(&old, "raw113-ha").is_err());
        }
        let mut changed = serde_json::to_value(&received)?;
        changed["raw_wrapped_reply"]["kind"]["general-json-envelope-v1"]["lexical_data"] =
            json!({"type":"number","value":"NaN"});
        assert!(
            decode_unwrap_response_for_cluster(
                &encode(UNWRAP_RESPONSE_MAGIC, &changed)?,
                "raw113-ha"
            )
            .is_err()
        );
        erase_json(&mut changed);
        erase_json(&mut wire);
        Ok(())
    }
    #[test]
    fn raw113_q8_preconsume_and_s6_complete_payload_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut auth, root) = crate::auth::AuthState::bootstrap(100)?;
        let admin = auth.authenticate(&root, 100)?;
        let _ingress = crate::auth::IngressReplyScope::listener(&[0x91; 16]);
        let issued = auth.wrap_logical_response(
            "",
            "sys/wrapping/wrap",
            60,
            &json!({"data":{"stable":"<>&"}}),
            100,
        )?;
        let token = issued.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?
            .to_owned();
        let context = ForwardContext {
            method: "POST",
            path: "sys/wrapping/unwrap",
            namespace: "",
            token: &root,
            body: &Value::Null,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
            caller_deadline: None,
        };
        let request = encode_completed_index_request_for_cluster(
            "raw110-ha",
            (1, 2),
            &context,
            Some([5; 32]),
        )?;
        assert!(request.starts_with(b"HBFQ8"));
        for old_magic in [b"HBFQ5", b"HBFQ6"] {
            let mut downgraded = request.clone();
            downgraded[..5].copy_from_slice(old_magic);
            assert!(decode_request_for_cluster(&downgraded, "raw110-ha").is_err());
            assert!(auth.is_wrapping_token(&token));
        }
        // Refusal occurred before any Auth dispatch or token consume.
        assert!(auth.is_wrapping_token(&token));
        let consumed = auth.wrapping_route(
            Some(&admin),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({"token":token}),
            100,
        )?;
        let response = crate::Response {
            unwrapped_json: consumed.unwrapped_json,
            status: consumed.status,
            body: consumed.body,
            response_headers: Default::default(),
            consistency_index: None,
        };
        let bytes =
            encode_completed_unwrap_response_for_cluster("raw110-ha", 2, 1, &response, None)?;
        assert!(bytes.starts_with(b"HBFS6"));
        let received = decode_unwrap_response_for_cluster(&bytes, "raw110-ha")?;
        assert!(received.raw_wrapped_reply.is_some());
        assert!(
            crate::ha_forward_completion::response_digest(&response)?
                == crate::ha_forward_completion::wire_response_digest(&received)?
        );
        for old_magic in [b"HBFS3", b"HBFS4", b"HBFS5"] {
            let mut lower = bytes.clone();
            lower[..5].copy_from_slice(old_magic);
            assert!(decode_unwrap_response_for_cluster(&lower, "raw110-ha").is_err());
        }
        let mut tampered = serde_json::to_value(&received)?;
        tampered["raw_wrapped_reply"]["digest"] = json!(vec![9_u8; 32]);
        assert!(
            decode_unwrap_response_for_cluster(
                &encode(UNWRAP_RESPONSE_MAGIC, &tampered)?,
                "raw110-ha"
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn trusted_unwrap_framing_negotiation_rejects_downgrade_and_unknown_origin()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut auth, root) = crate::auth::AuthState::bootstrap(100)?;
        let admin = auth.authenticate(&root, 100)?;
        let wrapped = auth.wrap_response(
            "",
            "sys/wrapping/wrap",
            60,
            &json!({"data":{"synthetic":"HA-origin"}}),
            100,
        )?;
        let token = wrapped.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?
            .to_owned();
        let consumed = auth.wrapping_route(
            Some(&admin),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({"token":token}),
            100,
        )?;
        assert!(consumed.unwrapped_json.is_some());
        let response = crate::Response {
            unwrapped_json: consumed.unwrapped_json,
            response_headers: Default::default(),
            consistency_index: None,
            status: consumed.status,
            body: consumed.body,
        };
        let context = ForwardContext {
            method: "POST",
            path: "sys/wrapping/unwrap",
            namespace: "",
            token: &root,
            body: &Value::Null,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
            caller_deadline: None,
        };
        let mut request = encode_completed_index_request_for_cluster(
            "unwrap-ha",
            (1, 2),
            &context,
            Some([4; 32]),
        )?;
        assert!(request.starts_with(UNWRAP_REQUEST_MAGIC));
        let admitted = decode_request_for_cluster(&request, "unwrap-ha")?;
        assert!(admitted.unwrap_response && admitted.index_response);
        request[..5].copy_from_slice(INDEX_REQUEST_MAGIC);
        assert!(decode_request_for_cluster(&request, "unwrap-ha").is_err());
        let legacy = encode_legacy_request_for_transition(
            1,
            2,
            "POST",
            "sys/wrapping/unwrap",
            "",
            &root,
            &Value::Null,
        )?;
        assert!(decode_request_for_cluster_compatible(&legacy, "unwrap-ha", true).is_err());
        assert!(
            encode_completed_index_response_for_cluster("unwrap-ha", 2, 1, &response, None)
                .is_err()
        );
        let bytes =
            encode_completed_unwrap_response_for_cluster("unwrap-ha", 2, 1, &response, None)?;
        assert!(bytes.starts_with(UNWRAP_RESPONSE_MAGIC));
        assert!(decode_index_response_for_cluster(&bytes, "unwrap-ha").is_err());
        let received = decode_unwrap_response_for_cluster(&bytes, "unwrap-ha")?;
        assert!(received.unwrapped_json.is_some());
        assert_eq!(
            crate::ha_forward_completion::response_digest(&response)?,
            crate::ha_forward_completion::wire_response_digest(&received)?
        );
        let mut unknown = serde_json::to_value(&received)?;
        unknown["unwrapped_json"] = json!("arbitrary-sdk-value");
        assert!(
            decode_unwrap_response_for_cluster(
                &encode(UNWRAP_RESPONSE_MAGIC, &unknown)?,
                "unwrap-ha"
            )
            .is_err()
        );
        let mut forged = serde_json::to_value(&received)?;
        forged["status"] = json!(503);
        assert!(
            decode_unwrap_response_for_cluster(
                &encode(UNWRAP_RESPONSE_MAGIC, &forged)?,
                "unwrap-ha"
            )
            .is_err()
        );
        let mut old = serde_json::to_value(&received)?;
        old.as_object_mut()
            .ok_or("object")?
            .remove("unwrapped_json");
        let ordinary =
            decode_index_response_for_cluster(&encode(INDEX_RESPONSE_MAGIC, &old)?, "unwrap-ha")?;
        assert!(ordinary.unwrapped_json.is_none());
        assert_ne!(
            crate::ha_forward_completion::wire_response_digest(&ordinary)?,
            crate::ha_forward_completion::wire_response_digest(&received)?
        );
        Ok(())
    }

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
        let zero = encode_wrapped_request(
            (1, 2),
            "GET",
            "secret/data/a",
            "",
            "synthetic",
            &json!({}),
            0,
        )?;
        assert_eq!(decode_request(&zero)?.wrap_ttl_seconds, Some(0));
        assert_ne!(zero, legacy);
        let mut zero_downgrade = zero;
        zero_downgrade[..5].copy_from_slice(REQUEST_MAGIC);
        assert!(decode_request(&zero_downgrade).is_err());
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
                32 * 24 * 3600 + 1
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
            for ttl in [None, Some(0), Some(60)] {
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

#[cfg(test)]
mod consistency270_tests {
    use super::*;
    #[test]
    fn consistency270_forward_roundtrip_negotiates_index_and_retains_authority_tuple()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = encode_index_request_for_cluster(
            "synthetic",
            (1, 2),
            "POST",
            "secret/data/key",
            "team",
            "synthetic-token",
            &serde_json::json!({"data":{"fixture":true}}),
            Some(30),
            None,
            Some("127.0.0.1".parse()?),
        )?;
        assert!(is_forward_request(&bytes));
        let request = decode_request_for_cluster(&bytes, "synthetic")?;
        assert!(request.index_response && !request.legacy_v1);
        assert_eq!(request.origin_peer, Some("127.0.0.1".parse()?));
        assert_eq!(request.wrap_ttl_seconds, Some(30));
        assert_eq!(request.namespace, "team");
        assert_eq!(request.token, "synthetic-token");
        assert!(decode_request_for_cluster(&bytes, "another-cluster").is_err());
        let response = crate::Response {
            unwrapped_json: None,
            response_headers: Default::default(),
            status: 204,
            body: Value::Null,
            consistency_index: crate::http::consistency::IndexValue::for_raft("synthetic", 42)
                .wire(),
        };
        let bytes = encode_index_response_for_cluster("synthetic", 2, 1, &response)?;
        assert!(decode_response_for_cluster(&bytes, "synthetic").is_err());
        let received = decode_index_response_for_cluster(&bytes, "synthetic")?;
        assert_eq!(received.consistency_index, Some(42));
        assert_eq!(received.status, 204);
        assert!(decode_index_response_for_cluster(&bytes, "another-cluster").is_err());
        assert!(encode_index_response_for_cluster("another-cluster", 2, 1, &response).is_err());
        let old = encode_response_for_cluster("synthetic", 2, 1, 204, &Value::Null)?;
        assert!(
            decode_response_for_cluster(&old, "synthetic")?
                .consistency_index
                .is_none()
        );
        assert!(decode_index_response_for_cluster(&old, "synthetic").is_err());
        Ok(())
    }
}

#[cfg(test)]
mod sdk_response_header_tests {
    use super::*;
    #[test]
    fn sdk_headers95_negotiated_forward_multivalue_and_bounded_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut response = crate::Response {
            status: 200,
            body: serde_json::json!({"data":{"marker":"same-approved-response"}}),
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
        };
        response.response_headers = crate::service::ResponseHeaders::from_sdk(Some(&serde_json::json!({"X-SDK-One":["one"],"x-sdk-multi":["first","second"],"X-SDK-Blocked":["withheld"]})), &["X-SDK-One".into(),"X-SDK-Multi".into()]).map_err(|()| "response header fixture")?;
        let frame = encode_index_response_for_cluster("sdk-forward95", 1, 2, &response)?;
        let received = decode_index_response_for_cluster(&frame, "sdk-forward95")?;
        assert_eq!(
            (received.source, received.target, received.status),
            (1, 2, 200)
        );
        assert_eq!(received.body, response.body);
        let mut headers = Vec::new();
        received.response_headers.write(&mut headers)?;
        assert_eq!(
            std::str::from_utf8(&headers)?,
            "X-Sdk-Multi: first\r\nX-Sdk-Multi: second\r\nX-Sdk-One: one\r\n"
        );
        let mut merged = crate::Response {
            status: 200,
            body: serde_json::json!({"data":{"marker":"case-variant-merged"}}),
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
        };
        merged.response_headers = crate::service::ResponseHeaders::from_sdk(
            Some(&serde_json::json!({
                "X-SDK-Variant":vec!["first";32], "x-sdk-variant":vec!["second";32]
            })),
            &["X-SDK-Variant".into()],
        )
        .map_err(|()| "merged local headers")?;
        let frame_merged = encode_index_response_for_cluster("sdk-forward95", 1, 2, &merged)?;
        let received_merged = decode_index_response_for_cluster(&frame_merged, "sdk-forward95")?;
        let mut merged_wire = Vec::new();
        received_merged.response_headers.write(&mut merged_wire)?;
        assert_eq!(
            std::str::from_utf8(&merged_wire)?
                .matches("X-Sdk-Variant:")
                .count(),
            64
        );
        assert!(decode_index_response_for_cluster(&frame, "other-cluster").is_err());
        assert!(
            serde_json::from_value::<crate::service::ResponseHeaders>(
                serde_json::json!({"Content-Length":["123"]})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<crate::service::ResponseHeaders>(
                serde_json::json!({"X-SDK-One":["x".repeat(4097)]})
            )
            .is_err()
        );
        let legacy = encode_response_for_cluster(
            "sdk-forward95",
            1,
            2,
            403,
            &serde_json::json!({"errors":["denied"]}),
        )?;
        assert!(
            decode_response_for_cluster(&legacy, "sdk-forward95")?
                .response_headers
                .is_empty()
        );
        let mut response = received;
        response.target = 1;
        assert!(
            decode_index_response_for_cluster(
                &encode(INDEX_RESPONSE_MAGIC, &response)?,
                "sdk-forward95"
            )
            .is_err()
        );
        Ok(())
    }
}
