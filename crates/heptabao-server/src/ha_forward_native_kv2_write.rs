//! N1 adds bounded request capacity to an ordinary completed KV2 write.
//! This is a transport allowance, not mount ownership, an Actor or a writer.
use super::*;

const _: () = assert!(MAX_NATIVE_KV2_WRITE_BODY_BYTES == crate::http::MAX_KV2_JSON_WRITE_BODY);
const _: () = assert!(MAX_NATIVE_KV2_WRITE_METADATA_BYTES == MAX_FORWARD_FRAME_BYTES);

fn route(method: &str, path: &str) -> bool {
    crate::http::json_ingress_body_limit(method, path, Some("application/json"))
        == crate::http::MAX_KV2_JSON_WRITE_BODY
}

fn body_size(value: &Value) -> Result<usize, String> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|size| *size <= MAX_NATIVE_KV2_WRITE_BODY_BYTES)
                .ok_or_else(|| std::io::Error::other("native KV2 request body exceeds bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value)
        .map_err(|_| "HA native KV2 request body exceeds bound")?;
    Ok(count.0)
}

pub(super) fn encode(request: &ForwardRequestRef<'_>) -> Result<Vec<u8>, String> {
    // Keep every non-write and specialized request on its old framing/bound.
    // The parent has already separated AppRole form and original-byte replies.
    if !route(request.method, request.path)
        || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
        || request.wrapped_reply_ingress.is_some()
        || request.wrapped_reply_lexical.is_some()
        || request
            .logical_data
            .is_some_and(crate::request_metadata::DataFrame::is_approle_form)
    {
        return super::encode(NATIVE_INDEX_REQUEST_MAGIC, request);
    }
    if request.completion_nonce.is_none() {
        return Err("HA native KV2 request requires original completion nonce".into());
    }
    let body_bytes = body_size(request.body)?;
    // This serializer wipes every allocation it replaces, including failure.
    let json = crate::secret_serde::to_vec(request, MAX_NATIVE_KV2_WRITE_FRAME_BYTES - 9)
        .map_err(|_| "HA native KV2 request frame exceeds bound")?;
    let wire_bytes = 9 + json.len();
    if wire_bytes
        .checked_sub(body_bytes)
        .is_none_or(|metadata| metadata > MAX_NATIVE_KV2_WRITE_METADATA_BYTES)
    {
        return Err("HA native KV2 request metadata exceeds bound".into());
    }
    // Capacity follows the exact request. Small requests keep their existing
    // Q9 bytes, and a peer refusal never causes a fallback or mutation replay.
    let magic = if wire_bytes <= MAX_FORWARD_FRAME_BYTES {
        NATIVE_INDEX_REQUEST_MAGIC
    } else {
        NATIVE_KV2_WRITE_REQUEST_MAGIC
    };
    let length = u32::try_from(json.len()).map_err(|_| "HA native KV2 request is oversized")?;
    let mut frame = Vec::with_capacity(wire_bytes);
    frame.extend_from_slice(magic);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

// This first pass borrows only the body and ignores other fields without
// retaining them. The complete ForwardRequest decoder below still rejects
// unknown/duplicate fields and uses the original bounded domain JSON parser.
#[derive(Deserialize)]
struct Body<'a> {
    #[serde(borrow)]
    body: &'a serde_json::value::RawValue,
}

pub(super) fn decode(frame: &[u8]) -> Result<ForwardRequest, String> {
    if !(10..=MAX_NATIVE_KV2_WRITE_FRAME_BYTES).contains(&frame.len())
        || !frame.starts_with(NATIVE_KV2_WRITE_REQUEST_MAGIC)
    {
        return Err("HA native KV2 request frame is invalid".into());
    }
    let length = u32::from_be_bytes(
        frame[5..9]
            .try_into()
            .map_err(|_| "HA native KV2 request length is invalid")?,
    ) as usize;
    if length != frame.len() - 9 {
        return Err("HA native KV2 request length differs from payload".into());
    }
    let borrowed: Body<'_> =
        serde_json::from_slice(&frame[9..]).map_err(|_| "HA native KV2 request JSON is invalid")?;
    let raw_body_bytes = borrowed.body.get().len();
    if raw_body_bytes > MAX_NATIVE_KV2_WRITE_BODY_BYTES
        || frame
            .len()
            .checked_sub(raw_body_bytes)
            .is_none_or(|metadata| metadata > MAX_NATIVE_KV2_WRITE_METADATA_BYTES)
    {
        return Err("HA native KV2 raw body or metadata exceeds request bound".into());
    }
    let request: ForwardRequest =
        serde_json::from_slice(&frame[9..]).map_err(|_| "HA native KV2 request JSON is invalid")?;
    // Own the zeroizing request before checking canonical growth and scope.
    body_size(&request.body)?;
    if !route(&request.method, &request.path)
        || request.completion_nonce.is_none()
        || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
        || request.wrapped_reply_ingress.is_some()
        || request.wrapped_reply_lexical.is_some()
        || request
            .logical_data
            .as_ref()
            .is_some_and(crate::request_metadata::DataFrame::is_approle_form)
    {
        return Err("HA native KV2 request is outside completed ordinary write profile".into());
    }
    Ok(request)
}

#[cfg(test)]
#[path = "ha_forward_native_kv2_write_tests.rs"]
mod tests;
