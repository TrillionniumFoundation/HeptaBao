//! The bounded original HTTP request for one immutable KV clock observation.
//! This capsule is data custody, never an Actor, KV owner or ReadIndex proof.
use crate::{Response, ServiceRequest};
use serde_json::Value;
use std::{cell::RefCell, marker::PhantomData, rc::Rc, time::Instant};
use zeroize::Zeroizing;

pub(crate) const MAX_COMBINED_RAW_BYTES: usize = super::MAX_HEADERS + 4;

pub(crate) struct RequestView<'a> {
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) token: &'a str,
    pub(crate) body: &'a Value,
}

pub(super) struct Parsed {
    wire_method: &'static str,
    raw_target: Zeroizing<String>,
    namespace: Zeroizing<String>,
    token: Zeroizing<String>,
    digest: [u8; 32],
}

fn unavailable() -> Response {
    Response::error(503, "original immutable HTTP request is unavailable")
}

fn binding(request: RequestView<'_>) -> Result<[u8; 32], Response> {
    let raw = crate::secret_serde::to_vec(
        &(
            "immutable-http-kv-clock-v1",
            request.method,
            request.path,
            request.namespace,
            request.token,
            request.body,
        ),
        64 * 1024,
    )
    .map_err(|_| unavailable())?;
    Ok(crate::crypto::digest(&raw))
}

fn wire_method(method: &str) -> Option<&'static str> {
    match method {
        "GET" => Some("GET"),
        "HEAD" => Some("HEAD"),
        "LIST" => Some("LIST"),
        "SCAN" => Some("SCAN"),
        _ => None,
    }
}

impl Parsed {
    // Only the actual HTTP parser in the parent module can construct this.
    // The decoded field sum is bounded by its already-checked complete header.
    pub(super) fn capture(
        original_method: &str,
        raw_target: &str,
        request: RequestView<'_>,
    ) -> Result<Option<Self>, super::ParseError> {
        let Some(wire_method) = wire_method(original_method) else {
            return Ok(None);
        };
        if !matches!(request.method, "GET" | "HEAD" | "LIST" | "SCAN") {
            return Ok(None);
        }
        let combined = request.token.len()
            .checked_add(request.namespace.len())
            .and_then(|value| value.checked_add(raw_target.len()));
        if combined.is_none_or(|value| value > MAX_COMBINED_RAW_BYTES) {
            return Err(super::bad("immutable HTTP metadata exceeds original header bound"));
        }
        let digest = binding(RequestView {
            method: if request.method == "HEAD" { "GET" } else { request.method },
            path: request.path,
            namespace: request.namespace,
            token: request.token,
            body: request.body,
        }).map_err(|_| super::bad("immutable HTTP request binding unavailable"))?;
        Ok(Some(Self {
            wire_method,
            raw_target: Zeroizing::new(raw_target.to_owned()),
            namespace: Zeroizing::new(request.namespace.to_owned()),
            token: Zeroizing::new(request.token.to_owned()),
            digest,
        }))
    }
}

struct Bound {
    parsed: Parsed,
    ingress: [u8; 16],
}
thread_local! {
    static CURRENT: RefCell<Option<Bound>> = const { RefCell::new(None) };
}

pub(super) struct Scope {
    previous: Option<Bound>,
    _thread: PhantomData<Rc<()>>,
}

impl Scope {
    pub(super) fn enter(
        parsed: Option<Parsed>,
        request: &ServiceRequest<'_>,
        ingress: [u8; 16],
    ) -> Result<Self, Response> {
        let parsed = if matches!(request.method, "GET" | "LIST" | "SCAN") { parsed } else { None };
        if let Some(parsed) = &parsed
            && parsed.digest != binding(RequestView {
                method: request.method,
                path: request.path,
                namespace: request.namespace,
                token: request.token,
                body: &request.body,
            })?
        {
            return Err(unavailable());
        }
        let previous = CURRENT.with(|slot| slot.replace(parsed.map(|parsed| Bound { parsed, ingress })));
        Ok(Self { previous, _thread: PhantomData })
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|slot| { slot.replace(self.previous.take()); });
    }
}

/// One move from an actual parser scope. No public fields, Clone or serde can
/// reconstruct its original HTTP bound, ingress or absolute request deadline.
pub(crate) struct OriginalImmutableHttpRequest {
    parsed: Parsed,
    method: String,
    ingress: [u8; 16],
    deadline: Instant,
}

impl OriginalImmutableHttpRequest {
    pub(crate) fn capture(request: RequestView<'_>) -> Result<Option<Self>, Response> {
        if CURRENT.with(|slot| slot.borrow().is_none()) {
            return Ok(None);
        }
        let digest = binding(RequestView {
            method: request.method,
            path: request.path,
            namespace: request.namespace,
            token: request.token,
            body: request.body,
        })?;
        let ingress = crate::auth::current_ingress().ok_or_else(unavailable)?.attempt_id();
        let deadline = crate::request_deadline::current().ok_or_else(unavailable)?;
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        CURRENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(bound) = slot.as_ref() else {
                return Ok(None);
            };
            if bound.ingress != ingress || bound.parsed.digest != digest {
                return Err(unavailable());
            }
            let bound = slot.take().ok_or_else(unavailable)?;
            Ok(Some(Self {
                parsed: bound.parsed,
                method: request.method.to_owned(),
                ingress,
                deadline,
            }))
        })
    }

    pub(crate) fn check(&self) -> Result<(), Response> {
        if Instant::now() >= self.deadline
            || crate::request_deadline::current() != Some(self.deadline)
            || crate::auth::current_ingress().map(|context| context.attempt_id()) != Some(self.ingress)
        {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(crate) fn wire_method(&self) -> &'static str { self.parsed.wire_method }
    pub(crate) fn method(&self) -> &str { &self.method }
    pub(crate) fn raw_target(&self) -> &str { &self.parsed.raw_target }
    pub(crate) fn namespace(&self) -> &str { &self.parsed.namespace }
    pub(crate) fn token(&self) -> &str { &self.parsed.token }
    pub(crate) fn ingress(&self) -> [u8; 16] { self.ingress }
    pub(crate) fn deadline(&self) -> Instant { self.deadline }
}
