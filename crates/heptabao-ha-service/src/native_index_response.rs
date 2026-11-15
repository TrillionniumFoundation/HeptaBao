//! Q9/S7 explicitly negotiates one bounded ordinary completed-forward reply.
//! Q9 request, Raft, replica and legacy response bounds do not grow. N1 has a
//! separate bounded KV2 request profile and also negotiates S7. The response
//! cannot select its own capacity: only the original request selects this profile.
use super::*;

/// Ordinary completed native forwarding; no wrapping, form or workflow upgrade.
pub const NATIVE_INDEX_REQUEST_MAGIC: &[u8; 5] = b"HBFQ9";
/// The only response accepted for an original Q9 request.
pub const NATIVE_INDEX_RESPONSE_MAGIC: &[u8; 5] = b"HBFS7";
/// The server's existing public HTTP JSON response bound, before peer metadata.
pub const MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Includes peer framing, identity, headers, consistency and completion metadata.
pub const MAX_NATIVE_INDEX_RESPONSE_METADATA_BYTES: usize = 64 * 1024;
/// Both layers apply this complete wire bound, including the nine-byte inner frame.
pub const MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES: usize =
    MAX_NATIVE_INDEX_RESPONSE_BODY_BYTES + MAX_NATIVE_INDEX_RESPONSE_METADATA_BYTES;
const MAX_NATIVE_INDEX_REQUEST_BYTES: usize = 1024 * 1024;
const INNER_HEADER_BYTES: usize = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseFrameProfile {
    Legacy,
    NativeIndexV1,
}

impl ResponseFrameProfile {
    pub(crate) fn for_request(request: &[u8]) -> Result<Self, HaError> {
        if request.starts_with(NATIVE_KV2_WRITE_REQUEST_MAGIC) {
            native_kv2_write_request::validate_inner_frame(request)?;
            return Ok(Self::NativeIndexV1);
        }
        if !request.starts_with(NATIVE_INDEX_REQUEST_MAGIC) {
            return Ok(Self::Legacy);
        }
        validate_inner_frame(
            request,
            NATIVE_INDEX_REQUEST_MAGIC,
            MAX_NATIVE_INDEX_REQUEST_BYTES,
        )?;
        Ok(Self::NativeIndexV1)
    }

    pub(crate) fn is_native_index(self) -> bool {
        self == Self::NativeIndexV1
    }

    pub(crate) fn require_alpn(self, alpn: Option<&[u8]>) -> Result<(), HaError> {
        if self.is_native_index() && alpn != Some(RAFT_ALPN_PROTOCOL) {
            return Err(HaError::PeerAuthenticationFailed);
        }
        Ok(())
    }

    pub(crate) fn read(self, reader: &mut impl Read) -> Result<Vec<u8>, HaError> {
        if self == Self::Legacy {
            return read_bounded_frame(reader);
        }
        let mut length = [0_u8; 4];
        reader
            .read_exact(&mut length)
            .map_err(|error| forward_transport_io_error("native_index_read_length", &error))?;
        let length = u32::from_be_bytes(length) as usize;
        if !(INNER_HEADER_BYTES + 1..=MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES).contains(&length) {
            return Err(HaError::InvalidFrame);
        }
        // Check the negotiated response version and both lengths before any
        // body-sized allocation. An S7 response never raises an old Q4 budget.
        let mut header = [0_u8; INNER_HEADER_BYTES];
        reader
            .read_exact(&mut header)
            .map_err(|error| forward_transport_io_error("native_index_read_header", &error))?;
        if &header[..5] != NATIVE_INDEX_RESPONSE_MAGIC
            || u32::from_be_bytes(header[5..9].try_into().map_err(|_| HaError::InvalidFrame)?)
                as usize
                != length - INNER_HEADER_BYTES
        {
            return Err(HaError::InvalidFrame);
        }
        let mut frame = zeroize::Zeroizing::new(vec![0_u8; length]);
        frame[..INNER_HEADER_BYTES].copy_from_slice(&header);
        reader
            .read_exact(&mut frame[INNER_HEADER_BYTES..])
            .map_err(|error| forward_transport_io_error("native_index_read_payload", &error))?;
        Ok(std::mem::take(&mut *frame))
    }

    pub(crate) fn write(self, writer: &mut impl Write, response: &[u8]) -> Result<(), HaError> {
        if self == Self::Legacy {
            return write_bounded_frame(writer, response);
        }
        validate_inner_frame(
            response,
            NATIVE_INDEX_RESPONSE_MAGIC,
            MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES,
        )?;
        let length = u32::try_from(response.len()).map_err(|_| HaError::InvalidFrame)?;
        writer
            .write_all(&length.to_be_bytes())
            .map_err(|error| forward_transport_io_error("native_index_write_length", &error))?;
        writer
            .write_all(response)
            .map_err(|error| forward_transport_io_error("native_index_write_payload", &error))?;
        writer
            .flush()
            .map_err(|error| forward_transport_io_error("native_index_flush", &error))
    }
}

fn validate_inner_frame(frame: &[u8], magic: &[u8; 5], maximum: usize) -> Result<(), HaError> {
    if !(INNER_HEADER_BYTES + 1..=maximum).contains(&frame.len()) || &frame[..5] != magic {
        return Err(HaError::InvalidFrame);
    }
    let json_length =
        u32::from_be_bytes(frame[5..9].try_into().map_err(|_| HaError::InvalidFrame)?) as usize;
    if json_length != frame.len() - INNER_HEADER_BYTES {
        return Err(HaError::InvalidFrame);
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_index_response_tests.rs"]
mod tests;
