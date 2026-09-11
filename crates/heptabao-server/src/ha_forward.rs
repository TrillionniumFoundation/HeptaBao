use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

const REQUEST_MAGIC: &[u8; 5] = b"HBFQ1";
const RESPONSE_MAGIC: &[u8; 5] = b"HBFS1";
const MAX_FORWARD_FRAME_BYTES: usize = 1024 * 1024;
const MAX_METHOD_BYTES: usize = 8;
const MAX_PATH_BYTES: usize = 8192;
const MAX_NAMESPACE_BYTES: usize = 512;
const MAX_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForwardRequest {
    pub source: u64,
    pub target: u64,
    pub method: String,
    pub path: String,
    pub namespace: String,
    pub token: String,
    pub body: Value,
}

impl Drop for ForwardRequest {
    fn drop(&mut self) {
        self.token.zeroize();
        erase_json(&mut self.body);
    }
}

#[derive(Serialize)]
struct ForwardRequestRef<'a> {
    source: u64,
    target: u64,
    method: &'a str,
    path: &'a str,
    namespace: &'a str,
    token: &'a str,
    body: &'a Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForwardResponse {
    pub source: u64,
    pub target: u64,
    pub status: u16,
    pub body: Value,
}

impl Drop for ForwardResponse {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

pub(crate) fn is_forward_request(encoded: &[u8]) -> bool {
    encoded.starts_with(REQUEST_MAGIC)
}

pub(crate) fn encode_request(
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
        &ForwardRequestRef {
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

pub(crate) fn decode_request(encoded: &[u8]) -> Result<ForwardRequest, String> {
    let request: ForwardRequest = decode(REQUEST_MAGIC, encoded)?;
    validate_direction(request.source, request.target)?;
    validate_request_fields(
        &request.method,
        &request.path,
        &request.namespace,
        &request.token,
    )?;
    Ok(request)
}

pub(crate) fn encode_response(
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
        &ForwardResponse {
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
    if !(100..=599).contains(&response.status) {
        return Err("HA forward response status is invalid".into());
    }
    Ok(response)
}

fn validate_direction(source: u64, target: u64) -> Result<(), String> {
    if source == 0 || target == 0 || source == target {
        return Err("HA forward direction is invalid".into());
    }
    Ok(())
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

fn encode<T: Serialize>(magic: &[u8; 5], value: &T) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(value).map_err(|_| "cannot encode HA forward frame")?;
    let length = u32::try_from(json.len()).map_err(|_| "HA forward frame is oversized")?;
    let mut encoded = Vec::with_capacity(9 + json.len());
    encoded.extend_from_slice(magic);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(&json);
    if encoded.len() > MAX_FORWARD_FRAME_BYTES {
        return Err("HA forward frame exceeds transport bound".into());
    }
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

        let response = encode_response(2, 1, 200, &json!({"data":{"version":1}}))?;
        let response = decode_response(&response)?;
        assert_eq!(response.source, 2);
        assert_eq!(response.target, 1);
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
}
