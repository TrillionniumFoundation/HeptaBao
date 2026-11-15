//! A separate completed-forward request version for the existing public KV2
//! JSON write budget. Only an authenticated strict-ALPN peer may allocate this
//! larger request. Q1-Q9, Raft, replica and legacy transport bounds stay fixed.
use super::*;

pub const NATIVE_KV2_WRITE_REQUEST_MAGIC: &[u8; 5] = b"HBFN1";
/// Matches the server's existing route-specific public JSON body allowance.
pub const MAX_NATIVE_KV2_WRITE_BODY_BYTES: usize = 3 * 1024 * 1024;
/// Includes the inner frame and all non-body fields. Preserve the original
/// complete request bound for certificate chains and logical metadata.
pub const MAX_NATIVE_KV2_WRITE_METADATA_BYTES: usize = 1024 * 1024;
pub const MAX_NATIVE_KV2_WRITE_FRAME_BYTES: usize =
    MAX_NATIVE_KV2_WRITE_BODY_BYTES + MAX_NATIVE_KV2_WRITE_METADATA_BYTES;
const HEADER_BYTES: usize = 9;

pub(crate) fn validate_inner_frame(frame: &[u8]) -> Result<(), HaError> {
    if !(HEADER_BYTES + 1..=MAX_NATIVE_KV2_WRITE_FRAME_BYTES).contains(&frame.len())
        || !frame.starts_with(NATIVE_KV2_WRITE_REQUEST_MAGIC)
        || u32::from_be_bytes(frame[5..9].try_into().map_err(|_| HaError::InvalidFrame)?) as usize
            != frame.len() - HEADER_BYTES
    {
        return Err(HaError::InvalidFrame);
    }
    Ok(())
}

pub(crate) fn validate_authenticated_request(frame: &[u8]) -> Result<(), HaError> {
    if frame.starts_with(NATIVE_KV2_WRITE_REQUEST_MAGIC) {
        return validate_inner_frame(frame);
    }
    if frame.is_empty() || frame.len() > MAX_PAYLOAD_BYTES + 4096 {
        return Err(HaError::InvalidFrame);
    }
    Ok(())
}

/// Called only after the actual mTLS identity has been authenticated. No
/// response, unrecognized magic or legacy rolling exception can raise a
/// request's allocation limit. Inspect only the fixed header before allocating.
pub(crate) fn read_authenticated_request(
    reader: &mut impl Read,
    alpn: Option<&[u8]>,
) -> Result<Vec<u8>, HaError> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| forward_transport_io_error("native_write_request_read_length", &error))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_NATIVE_KV2_WRITE_FRAME_BYTES {
        return Err(HaError::InvalidFrame);
    }
    let mut header = [0_u8; HEADER_BYTES];
    let prefix_bytes = length.min(HEADER_BYTES);
    reader
        .read_exact(&mut header[..prefix_bytes])
        .map_err(|error| forward_transport_io_error("native_write_request_read_header", &error))?;
    if header[..prefix_bytes].starts_with(NATIVE_KV2_WRITE_REQUEST_MAGIC) {
        if alpn != Some(RAFT_ALPN_PROTOCOL) {
            return Err(HaError::PeerAuthenticationFailed);
        }
        if length <= HEADER_BYTES
            || u32::from_be_bytes(header[5..9].try_into().map_err(|_| HaError::InvalidFrame)?)
                as usize
                != length - HEADER_BYTES
        {
            return Err(HaError::InvalidFrame);
        }
    } else if length > MAX_PAYLOAD_BYTES + 4096 {
        return Err(HaError::InvalidFrame);
    }
    let mut frame = zeroize::Zeroizing::new(vec![0_u8; length]);
    frame[..prefix_bytes].copy_from_slice(&header[..prefix_bytes]);
    reader
        .read_exact(&mut frame[prefix_bytes..])
        .map_err(|error| forward_transport_io_error("native_write_request_read_payload", &error))?;
    Ok(std::mem::take(&mut *frame))
}

/// The caller has completed the original-budget TLS handshake and checked its
/// strict ALPN before writing an N1 frame. Other frames use the old writer.
pub(crate) fn write_authenticated_request(
    writer: &mut impl Write,
    frame: &[u8],
) -> Result<(), HaError> {
    if !frame.starts_with(NATIVE_KV2_WRITE_REQUEST_MAGIC) {
        return write_bounded_frame(writer, frame);
    }
    validate_inner_frame(frame)?;
    let length = u32::try_from(frame.len()).map_err(|_| HaError::InvalidFrame)?;
    writer
        .write_all(&length.to_be_bytes())
        .map_err(|error| forward_transport_io_error("native_write_request_write_length", &error))?;
    writer.write_all(frame).map_err(|error| {
        forward_transport_io_error("native_write_request_write_payload", &error)
    })?;
    writer
        .flush()
        .map_err(|error| forward_transport_io_error("native_write_request_flush", &error))
}

#[cfg(test)]
#[path = "native_kv2_write_request_tests.rs"]
mod tests;
