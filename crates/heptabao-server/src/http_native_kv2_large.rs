//! Deferred Content-Length upload. All large allocation follows actual Service
//! authentication, root custody, ACL/sudo and original-deadline admission.
use super::*;
use crate::engines::kv2_native_large::MAX_BUNDLE_BYTES;

struct BodyReader<'a, R> {
    source: &'a mut R,
    prefix: Zeroizing<Vec<u8>>,
    offset: usize,
    remaining: u64,
    deadline: Instant,
}
impl<'a, R: Read> BodyReader<'a, R> {
    fn new(source: &'a mut R, body: snapshot::NativeBody, deadline: Instant) -> io::Result<Self> {
        let snapshot::Framing::Length(length) = body.framing else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "native-large KV2 requires length framing"));
        };
        if length == 0 || length > MAX_BUNDLE_BYTES as u64 || body.prefix.len() as u64 > length {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "native-large KV2 length bound"));
        }
        Ok(Self { source, prefix: body.prefix, offset: 0, remaining: length, deadline })
    }
}
impl<R: Read> Read for BodyReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "native-large KV2 original body deadline"));
        }
        if bytes.is_empty() || self.remaining == 0 { return Ok(0); }
        let wanted = bytes.len().min(self.remaining as usize);
        let count = if self.offset < self.prefix.len() {
            let count = wanted.min(self.prefix.len() - self.offset);
            bytes[..count].copy_from_slice(&self.prefix[self.offset..self.offset + count]);
            self.offset += count;
            count
        } else { self.source.read(&mut bytes[..wanted])? };
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete native-large KV2 body"));
        }
        self.remaining -= count as u64;
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "native-large KV2 original body deadline"));
        }
        Ok(count)
    }
}

pub(super) fn execute(
    service: &Arc<Mutex<Service>>,
    request: ServiceRequest<'_>,
    native: snapshot::NativeRequest,
    source: &mut impl Read,
    deadline: Instant,
) -> snapshot::NativeReply {
    let _scope = RequestDeadlineScope::enter(deadline);
    let execution = match lock_until(service, deadline) {
        Ok(mut writer) => writer.begin_native_kv2_large_before(request, deadline),
        Err(_) => return snapshot::NativeReply::Json(Response::error(503, "native-large KV2 admission unavailable")),
    };
    let mut pending = match execution {
        // No large drain or body allocation on a refusal. The connection is
        // closed; a rejected body never acquires an upload capability.
        RequestExecution::Complete(response) => return snapshot::NativeReply::Json(response),
        RequestExecution::External(pending) => pending,
    };
    let observation = match BodyReader::new(source, native.body, deadline) {
        Ok(mut reader) => pending.execute_native_kv2_large_transfer(&mut reader),
        Err(_) => crate::service::ExternalEffectResult::NativeKv2Large(Err(Response::error(
            400, "invalid native-large KV2 body framing",
        ))),
    };
    let response = match lock_until(service, deadline) {
        Ok(mut writer) => writer.finish_external_request(*pending, observation),
        Err(_) => return snapshot::NativeReply::Json(Response::error(503, "native-large KV2 finalize unavailable")),
    };
    snapshot::NativeReply::Json(response)
}

#[cfg(test)]
#[path = "http_native_kv2_large_tests.rs"]
mod tests;
