//! Deployment-opted, bounded HTTP ReadIndex transcript. The response header
//! contains observations made before writing, not a claim that writing or
//! delivery succeeded. A client must independently complete the original HTTP
//! request. Missing, incomplete or overflowing evidence cannot qualify a read.
use crate::Response;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use heptabao_raft_runtime::read_index_observation as raft;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use zeroize::Zeroizing;

/// Both added header lines, including CRLF, fit this allowance.
pub(super) const MAX_HEADER_BYTES: usize = 12 * 1024;
const MAX_TRANSCRIPT_JSON: usize = 9000;

// No payload bytes or hashes leave this private request-owned state. The digest
// exists only to connect the actual dispatched data to the final encoded data.
struct PayloadCandidate {
    identity: raft::ReadIdentity,
    digest: Zeroizing<[u8; 32]>,
}
#[derive(Default)]
struct PayloadState {
    candidate: Option<PayloadCandidate>,
    count: u64,
    state: u8,
    finalized: bool,
    ordinal: Option<u64>,
}
struct DigestWriter {
    digest: Sha256,
    bytes: usize,
}
impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|size| *size <= super::MAX_RESPONSE)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "diagnostic data bound"))?;
        self.digest.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn data_digest(value: &serde_json::Value) -> Option<Zeroizing<[u8; 32]>> {
    let mut writer = DigestWriter {
        digest: Sha256::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(Zeroizing::new(writer.digest.finalize().into()))
}
/// Called only beside the existing typed native data-read completion, after
/// the original authority check. This neither reauthorizes nor reads data.
pub(crate) fn record_native_payload(identity: Option<raft::ReadIdentity>, response: &Response) {
    let handle = current();
    let Some(inner) = handle.0.as_ref() else {
        return;
    };
    let Ok(mut payload) = inner.payload.try_lock() else {
        inner.payload_busy.store(true, Ordering::Relaxed);
        return;
    };
    payload.count = payload.count.saturating_add(1);
    if payload.count != 1 || payload.finalized {
        payload.state = 2;
        payload.candidate = None;
        return;
    }
    let Some(identity) = identity else {
        payload.state = 3;
        return;
    };
    if response.status != 200
        || response.unwrapped_json.is_some()
        || response
            .body
            .get("wrap_info")
            .is_some_and(|value| !value.is_null())
    {
        payload.state = 3;
        return;
    }
    let Some(digest) = response.body.get("data").and_then(data_digest) else {
        payload.state = 3;
        return;
    };
    // Check the SAME ReadIndex bound after diagnostic hashing, not before it.
    if identity.current_payload_ordinal().is_none() {
        payload.state = 3;
        return;
    }
    payload.candidate = Some(PayloadCandidate { identity, digest });
}
fn wire_payload_matches(bytes: &[u8], digest: &[u8; 32], attempt: &str) -> bool {
    if bytes.len() > super::MAX_RESPONSE || attempt.len() != 32 {
        return false;
    }
    #[derive(serde::Deserialize)]
    struct WirePayload {
        request_id: String,
        data: serde_json::Value,
        #[serde(default)]
        wrap_info: Option<serde_json::Value>,
    }
    // Derived struct decoding refuses duplicate known fields; the ordinary
    // encoder itself emits one field per existing Value map entry.
    let Ok(mut body) = serde_json::from_slice::<WirePayload>(bytes) else {
        return false;
    };
    let expected_id = format!(
        "{}-{}-{}-{}-{}",
        &attempt[..8],
        &attempt[8..12],
        &attempt[12..16],
        &attempt[16..20],
        &attempt[20..]
    );
    let matches = body.request_id == expected_id
        && body
            .wrap_info
            .as_ref()
            .is_none_or(serde_json::Value::is_null)
        && data_digest(&body.data).is_some_and(|actual| *actual == *digest);
    crate::service::erase_json(&mut body.data);
    if let Some(wrap) = body.wrap_info.as_mut() {
        crate::service::erase_json(wrap);
    }
    matches
}
/// Inspect the already encoded, bounded bytes used by both real transports.
/// Any raw/stored-origin/HEAD/error/ambiguous path remains unqualified.
pub(super) fn bind_final_wire_payload(
    response: &Response,
    status: u16,
    head: bool,
    raw: bool,
    bytes: &[u8],
) {
    let handle = current();
    let Some(inner) = handle.0.as_ref() else {
        return;
    };
    let Ok(mut payload) = inner.payload.try_lock() else {
        inner.payload_busy.store(true, Ordering::Relaxed);
        return;
    };
    if payload.finalized {
        payload.state = 2;
        payload.ordinal = None;
        return;
    }
    payload.finalized = true;
    if payload.count == 0 {
        return;
    }
    if payload.count != 1 || payload.state == 2 {
        payload.state = 2;
        return;
    }
    let Some(candidate) = payload.candidate.take() else {
        payload.state = 3;
        return;
    };
    if status != 200
        || response.status != 200
        || head
        || raw
        || response.unwrapped_json.is_some()
        || !wire_payload_matches(bytes, &candidate.digest, &inner.attempt)
    {
        payload.state = 4;
        return;
    }
    // Parsing/hash work cannot carry an earlier successful bound check past
    // expiry. This only rejects diagnostic qualification, never the response.
    let Some(ordinal) = candidate.identity.current_payload_ordinal() else {
        payload.state = 3;
        return;
    };
    payload.state = 1;
    payload.ordinal = Some(ordinal);
}

#[derive(Clone)]
struct Frozen {
    snapshot: raft::Snapshot,
    header: Vec<u8>,
    complete: bool,
    payload_state: u8,
    payload_ordinal: Option<u64>,
}
struct Inner {
    collector: raft::Collector,
    launch: &'static str,
    attempt: String,
    protocol: &'static str,
    began: Instant,
    deadline: Instant,
    frozen: Mutex<Option<Frozen>>,
    payload: Mutex<PayloadState>,
    payload_busy: AtomicBool,
    header_attempted: AtomicBool,
    header_completed: AtomicBool,
    finished: AtomicBool,
}
#[derive(Clone, Default)]
pub(super) struct Handle(Option<Arc<Inner>>);
pub(super) struct Owner {
    handle: Handle,
}
impl Owner {
    pub(super) fn new(attempt: &[u8; 16], protocol: &'static str, deadline: Instant) -> Self {
        let handle =
            if let (Some(launch), Some(collector)) = (raft::launch_id(), raft::Collector::new()) {
                let attempt = attempt
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                Handle(Some(Arc::new(Inner {
                    collector,
                    launch,
                    attempt,
                    protocol,
                    began: Instant::now(),
                    deadline,
                    frozen: Mutex::new(None),
                    payload: Mutex::new(PayloadState::default()),
                    payload_busy: AtomicBool::new(false),
                    header_attempted: AtomicBool::new(false),
                    header_completed: AtomicBool::new(false),
                    finished: AtomicBool::new(false),
                })))
            } else {
                Handle::default()
            };
        Self { handle }
    }
    pub(super) fn handle(&self) -> Handle {
        self.handle.clone()
    }
    pub(super) fn enter_thread(&self) -> Scope {
        self.handle.enter_thread()
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.handle.finish("abandoned", None, 0, false);
    }
}
fn encode_headers(
    launch: &str,
    attempt: &str,
    transcript: &serde_json::Value,
) -> Result<Vec<u8>, ()> {
    let raw = serde_json::to_vec(transcript).map_err(|_| ())?;
    if raw.len() > MAX_TRANSCRIPT_JSON {
        return Err(());
    }
    let encoded = URL_SAFE_NO_PAD.encode(raw);
    let header = format!(
        "X-HeptaBao-Read-Observation: 1,{launch},{attempt}\r\nX-HeptaBao-Read-Index-Trace: {encoded}\r\n"
    );
    if header.len() > MAX_HEADER_BYTES {
        return Err(());
    }
    Ok(header.into_bytes())
}
impl Handle {
    fn freeze(&self) -> Option<Frozen> {
        let inner = self.0.as_ref()?;
        let mut frozen = inner.frozen.try_lock().ok()?;
        if let Some(value) = frozen.as_ref() {
            return Some(value.clone());
        }
        let snapshot = inner.collector.snapshot();
        let trace = snapshot.compact();
        let (mut payload_state, mut payload_ordinal) = match inner.payload.try_lock() {
            Ok(payload) if !inner.payload_busy.load(Ordering::Relaxed) => {
                (payload.state, payload.ordinal)
            }
            _ => (3, None),
        };
        let payload_bindings = if payload_state == 1 {
            payload_ordinal
                .map(|ordinal| vec![serde_json::json!([1, ordinal, 200, true])])
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let (lost, failed) = raft::log_loss();
        let value = serde_json::json!({
            "v":1,"phase":"pre_write","process_id":std::process::id(),
            "attempt_id":inner.attempt,"launch_id":inner.launch,
            "read_index":trace,"log_lost_before":lost,"log_writer_failed":failed,
            "payload_bindings":payload_bindings,"payload_binding_state":payload_state,
            "writer_completed":false,"client_delivery_observed":false
        });
        let complete = value["read_index"]["complete"].as_bool() == Some(true);
        let (header, complete) = match encode_headers(inner.launch, &inner.attempt, &value) {
            Ok(header) => (header, complete),
            Err(()) => {
                payload_state = 3;
                payload_ordinal = None;
                let rejected = serde_json::json!({
                    "v":1,"phase":"pre_write","process_id":std::process::id(),
                    "attempt_id":inner.attempt,"launch_id":inner.launch,
                    "read_index":snapshot.incomplete_header(),
                    "payload_bindings":[],"payload_binding_state":3,
                    "writer_completed":false,"client_delivery_observed":false
                });
                (
                    encode_headers(inner.launch, &inner.attempt, &rejected).ok()?,
                    false,
                )
            }
        };
        let result = Frozen {
            snapshot,
            header,
            complete,
            payload_state,
            payload_ordinal,
        };
        *frozen = Some(result.clone());
        Some(result)
    }
    pub(super) fn enter_thread(&self) -> Scope {
        let installed = Arc::new(AtomicBool::new(true));
        let mut previous = None;
        let attached = ACTIVE.with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                previous = slot.replace(Entry {
                    handle: self.clone(),
                    active: Arc::clone(&installed),
                });
                true
            } else {
                false
            }
        });
        let runtime = raft::enter_thread(self.0.as_ref().map(|inner| inner.collector.clone()));
        Scope {
            previous,
            installed,
            attached,
            _runtime: runtime,
            _thread_bound: PhantomData,
        }
    }
    pub(super) fn finish(
        &self,
        outcome: &'static str,
        status: Option<u16>,
        accepted: u64,
        flush: bool,
    ) {
        let Some(inner) = self.0.as_ref() else { return };
        if inner.finished.swap(true, Ordering::Relaxed) {
            return;
        }
        let frozen = self.freeze();
        let snapshot = frozen
            .as_ref()
            .map(|f| f.snapshot.clone())
            .unwrap_or_else(|| inner.collector.snapshot());
        let header_complete = frozen.as_ref().is_some_and(|f| f.complete)
            && inner.header_completed.load(Ordering::Relaxed);
        inner.collector.close();
        raft::emit_http_terminal(
            &inner.attempt,
            inner.protocol,
            status,
            outcome,
            accepted,
            flush,
            u64::try_from(inner.began.elapsed().as_micros()).unwrap_or(u64::MAX),
            Instant::now() >= inner.deadline,
            &snapshot,
            header_complete,
            frozen.as_ref().map_or(3, |f| f.payload_state),
            frozen.as_ref().and_then(|f| f.payload_ordinal),
        );
    }
}

#[derive(Clone)]
struct Entry {
    handle: Handle,
    active: Arc<AtomicBool>,
}
thread_local! {
    static ACTIVE: RefCell<Option<Entry>>=const { RefCell::new(None) };
}
pub(super) struct Scope {
    previous: Option<Entry>,
    installed: Arc<AtomicBool>,
    attached: bool,
    _runtime: raft::ThreadScope,
    _thread_bound: PhantomData<Rc<()>>,
}
impl Drop for Scope {
    fn drop(&mut self) {
        self.installed.store(false, Ordering::Relaxed);
        if self.attached {
            ACTIVE.with(|slot| {
                if let Ok(mut slot) = slot.try_borrow_mut()
                    && slot
                        .as_ref()
                        .is_some_and(|entry| Arc::ptr_eq(&entry.active, &self.installed))
                {
                    *slot = self
                        .previous
                        .take()
                        .filter(|entry| entry.active.load(Ordering::Relaxed));
                }
            });
        }
    }
}
fn current() -> Handle {
    ACTIVE
        .with(|slot| {
            slot.try_borrow().ok().and_then(|slot| {
                slot.as_ref()
                    .filter(|entry| entry.active.load(Ordering::Relaxed))
                    .map(|entry| entry.handle.clone())
            })
        })
        .unwrap_or_default()
}
pub(super) fn active() -> bool {
    current().0.is_some()
}
pub(super) fn header_allowance() -> usize {
    if active() { MAX_HEADER_BYTES } else { 0 }
}
/// No added flush or retry. A partial diagnostic header write remains the
/// original writer error, so it cannot silently corrupt an otherwise valid reply.
pub(super) fn write_header(writer: &mut impl Write) -> io::Result<()> {
    let handle = current();
    let Some(inner) = handle.0.as_ref() else {
        return Ok(());
    };
    if inner.header_attempted.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    let Some(frozen) = handle.freeze() else {
        return Ok(());
    };
    writer.write_all(&frozen.header)?;
    inner.header_completed.store(true, Ordering::Relaxed);
    Ok(())
}
pub(super) fn finish_current(success: bool, status: Option<u16>, accepted: usize, flush: bool) {
    current().finish(
        if success { "complete" } else { "failed" },
        status,
        accepted as u64,
        flush,
    );
}
/// Only bytes actually accepted by the real writer enter this fixed status
/// prefix. Body, header values and errors are neither copied nor inspected.
pub(super) struct StatusLine {
    prefix: [u8; 12],
    used: usize,
}
impl StatusLine {
    pub(super) fn new() -> Self {
        Self {
            prefix: [0; 12],
            used: 0,
        }
    }
    pub(super) fn accepted(&mut self, bytes: &[u8]) {
        let count = (self.prefix.len() - self.used).min(bytes.len());
        self.prefix[self.used..self.used + count].copy_from_slice(&bytes[..count]);
        self.used += count;
    }
    pub(super) fn status(&self) -> Option<u16> {
        if self.used < 12 || &self.prefix[..9] != b"HTTP/1.1 " {
            return None;
        }
        let digits = &self.prefix[9..12];
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let value = u16::from(digits[0] - b'0') * 100
            + u16::from(digits[1] - b'0') * 10
            + u16::from(digits[2] - b'0');
        (100..=599).contains(&value).then_some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn read_observation_headers_are_bounded_prewrite_metadata() -> TestResult {
        let launch = "0123456789abcdef0123456789abcdef";
        let attempt = "fedcba9876543210fedcba9876543210";
        let value = serde_json::json!({"v":1,"phase":"pre_write","read_index":{"complete":false,"events":[]}});
        let header = encode_headers(launch, attempt, &value).map_err(|_| "header encoding")?;
        assert!(header.len() <= MAX_HEADER_BYTES);
        let text = std::str::from_utf8(&header)?;
        assert!(text.starts_with("X-HeptaBao-Read-Observation: 1,"));
        assert_eq!(text.matches("\r\n").count(), 2);
        assert!(!text.contains("token"));
        assert!(
            encode_headers(
                launch,
                attempt,
                &serde_json::json!({"value":"x".repeat(MAX_TRANSCRIPT_JSON)})
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn payload_match_requires_actual_wire_data_and_attempt() -> TestResult {
        let attempt = "00112233445566778899aabbccddeeff";
        let data = serde_json::json!({"data":{"counter":7},"metadata":{"version":3}});
        let digest = data_digest(&data).ok_or("digest")?;
        let wire = serde_json::to_vec(&serde_json::json!({
            "request_id":"00112233-4455-6677-8899-aabbccddeeff",
            "data":data,"wrap_info":null}))?;
        assert!(wire_payload_matches(&wire, &digest, attempt));
        assert!(!wire_payload_matches(
            &wire,
            &digest,
            "10112233445566778899aabbccddeeff"
        ));
        let wrong =
            data_digest(&serde_json::json!({"data":{"counter":8},"metadata":{"version":3}}))
                .ok_or("digest")?;
        assert!(!wire_payload_matches(&wire, &wrong, attempt));
        Ok(())
    }
    #[test]
    fn payload_match_refuses_duplicate_wrapped_or_missing_wire_fields() -> TestResult {
        let attempt = "00112233445566778899aabbccddeeff";
        let digest = data_digest(&serde_json::json!({"n":1})).ok_or("digest")?;
        for wire in [
            r#"{"request_id":"00112233-4455-6677-8899-aabbccddeeff","data":{"n":0},"data":{"n":1}}"#,
            r#"{"request_id":"00112233-4455-6677-8899-aabbccddeeff","data":{"n":1},"wrap_info":{"wrapped":true}}"#,
            r#"{"request_id":"00112233-4455-6677-8899-aabbccddeeff"}"#,
            r#"{"data":{"n":1}}"#,
        ] {
            assert!(!wire_payload_matches(wire.as_bytes(), &digest, attempt));
        }
        Ok(())
    }
    #[test]
    fn status_observer_uses_only_accepted_status_prefix() {
        let mut status = StatusLine::new();
        status.accepted(b"HTTP/1.");
        assert!(status.status().is_none());
        status.accepted(b"1 503 Service Unavailable\r\nsecret body not retained");
        assert_eq!(status.status(), Some(503));
        assert_eq!(status.used, 12);
        let mut wrong = StatusLine::new();
        wrong.accepted(b"not HTTP 200");
        assert!(wrong.status().is_none());
    }
    #[test]
    fn disabled_handle_has_no_header_or_terminal_effect() -> TestResult {
        let handle = Handle::default();
        let _scope = handle.enter_thread();
        assert!(!active());
        let mut out = Vec::new();
        write_header(&mut out)?;
        assert!(out.is_empty());
        assert_eq!(header_allowance(), 0);
        finish_current(true, Some(200), 0, false);
        Ok(())
    }
}
