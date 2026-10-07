//! Request-local OCSP carriers. Ordinary HTTP framing remains in the parent;
//! only an opaque GET suffix is decoded, never a mount or namespace selector.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
const REQUEST_MARKER: &str = "__heptabao_pki_ocsp_request";
const REQUEST_LIMIT: usize = 2048;

pub(crate) struct CarrierBody(pub(crate) Value);
impl Drop for CarrierBody {
    fn drop(&mut self) {
        crate::service::erase_json(&mut self.0);
    }
}

pub(super) struct GetCarrier {
    original_path: String,
}
const GET_PATH_MARKER: &str = "__heptabao_pki_ocsp_get_path";
const QUERY_MARKER: &str = "__heptabao_kv_read_query";

fn ordinary_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.contains("//")
        && !path.starts_with('/')
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && !matches!(segment, "." | "..")
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        })
}

// This is only a bounded transport candidate, never a mount selection. A
// nested mount or the opaque base64 text can itself contain `/ocsp/`.
fn opaque_get_candidate(method: &str, route: &str) -> bool {
    method == "GET"
        && route.len() <= 4096
        && route
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'#' | b'?'))
        && route
            .split_once("/ocsp/")
            .is_some_and(|(prefix, _)| ordinary_path(prefix))
}

pub(super) fn get_carrier(method: &str, route: &str) -> Result<Option<GetCarrier>, ParseError> {
    Ok(opaque_get_candidate(method, route).then(|| GetCarrier {
        original_path: route.to_owned(),
    }))
}

pub(crate) fn opaque_get_request(method: &str, path: &str, body: &Value) -> bool {
    get_request(method, path, body).is_some()
}

pub(crate) struct GetRequest<'a> {
    path: &'a str,
    query: &'a str,
}

pub(crate) fn get_request<'a>(
    method: &str,
    path: &'a str,
    body: &'a Value,
) -> Option<GetRequest<'a>> {
    if !matches!(method, "GET" | "LIST" | "SCAN") || !opaque_get_candidate("GET", path) {
        return None;
    }
    let object = body.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let carrier = object.get(GET_PATH_MARKER)?.as_object()?;
    if carrier.len() != 2 || carrier.get("path")?.as_str()? != path {
        return None;
    }
    let query = carrier.get("query")?.as_str()?;
    if query.len() > MAX_HEADERS || get_query_method(query).ok()? != method {
        return None;
    }
    Some(GetRequest { path, query })
}

impl GetRequest<'_> {
    // No actual PKI responder owns this path. Rebuild exactly the ordinary
    // GET's query-only body and selectors; the private carrier is never data.
    pub(crate) fn ordinary(
        &self,
        actual_kv: bool,
    ) -> Result<(&'static str, CarrierBody), Response> {
        if actual_kv {
            return kv_query("GET", self.query);
        }
        let mut body = CarrierBody(json!({}));
        merge_query_fields("GET", self.path, self.query, &mut body.0)
            .map_err(|error| Response::error(error.status, error.message))?;
        let object = body
            .0
            .as_object_mut()
            .ok_or_else(|| Response::error(400, "JSON object required"))?;
        let list = object.get("list") == Some(&Value::Bool(true));
        let scan = object.get("scan") == Some(&Value::Bool(true));
        let method = match (list, scan) {
            (true, true) => {
                return Err(Response::error(400, "list and scan are mutually exclusive"));
            }
            (true, false) => {
                object.remove("list");
                "LIST"
            }
            (false, true) => {
                object.remove("scan");
                "SCAN"
            }
            (false, false) => "GET",
        };
        Ok((method, body))
    }
}

pub(super) fn head_candidate(method: &str, path: &str) -> bool {
    method == "HEAD"
        && !path.starts_with("sys/")
        && !path.starts_with("auth/")
        && !path.starts_with('/')
        && path.len() <= 4096
        && !path.is_empty()
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#'))
}

fn sdk_auth_query_candidate(method: &str, path: &str, query: &str) -> bool {
    matches!(method, "GET" | "LIST" | "SCAN")
        && !query.is_empty()
        && path.starts_with("auth/")
        && path.len() <= 4096
}

fn query_candidate(method: &str, path: &str, query: &str) -> bool {
    sdk_auth_query_candidate(method, path, query)
        || head_candidate(method, path)
        || (matches!(method, "GET" | "LIST" | "SCAN")
            && !query.is_empty()
            && !path.starts_with("sys/")
            && !path.starts_with("auth/")
            && !path.contains("//")
            && ordinary_path(path.trim_end_matches('/')))
}

pub(crate) fn opaque_header_request(method: &str, path: &str, body: &Value) -> bool {
    method == "HEAD" && query_request(method, path, body).is_some()
}
pub(super) fn query_carrier_body(method: &str, path: &str, query: &str) -> Option<Value> {
    query_candidate(method, path, query)
        .then(|| json!({QUERY_MARKER:{"path":path,"query":query,"wire_method":method}}))
}

pub(crate) struct QueryRequest<'a> {
    path: &'a str,
    query: &'a str,
    wire_method: &'a str,
}

pub(crate) fn query_request<'a>(
    method: &str,
    path: &'a str,
    body: &'a Value,
) -> Option<QueryRequest<'a>> {
    let object = body.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let carrier = object.get(QUERY_MARKER)?.as_object()?;
    if carrier.len() != 3 || carrier.get("path")?.as_str()? != path {
        return None;
    }
    let query = carrier.get("query")?.as_str()?;
    let wire_method = carrier.get("wire_method")?.as_str()?;
    if query.len() > MAX_HEADERS || !query_candidate(wire_method, path, query) {
        return None;
    }
    let selected = if wire_method == "GET" {
        get_query_method(query).ok()?
    } else {
        wire_method
    };
    (selected == method).then_some(QueryRequest {
        path,
        query,
        wire_method,
    })
}

impl QueryRequest<'_> {
    pub(crate) fn resolve(
        &self,
        actual_native_query: bool,
    ) -> Result<(&str, CarrierBody), Response> {
        if actual_native_query || self.wire_method == "HEAD" {
            return kv_query(self.wire_method, self.query);
        }
        let mut body = CarrierBody(json!({}));
        merge_query_fields(self.wire_method, self.path, self.query, &mut body.0)
            .map_err(|error| Response::error(error.status, error.message))?;
        if self.wire_method == "GET" {
            let method = get_query_method(self.query)
                .map_err(|error| Response::error(error.status, error.message))?;
            if method == "LIST" {
                body.0
                    .as_object_mut()
                    .ok_or_else(|| Response::error(400, "JSON object required"))?
                    .remove("list");
            }
            if method == "SCAN" {
                body.0
                    .as_object_mut()
                    .ok_or_else(|| Response::error(400, "JSON object required"))?
                    .remove("scan");
            }
            return Ok((method, body));
        }
        Ok((self.wire_method, body))
    }
}

// Go URL.Query discards a malformed field, accepts a bare key, and retains
// duplicate values in order. Query bytes never become a namespace or token.
fn decode_url_query(value: &str) -> Option<String> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let a = char::from(bytes.next()?).to_digit(16)?;
                let b = char::from(bytes.next()?).to_digit(16)?;
                u8::try_from(a * 16 + b).ok()?
            }
            _ => byte,
        });
    }
    Some(String::from_utf8_lossy(&decoded).into_owned())
}

pub(super) fn url_query(query: &str) -> BTreeMap<String, Vec<String>> {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for field in query
        .split('&')
        .filter(|field| !field.is_empty() && !field.contains(';'))
    {
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        if let Some((key, value)) = decode_url_query(key).zip(decode_url_query(value)) {
            values.entry(key).or_default().push(value);
        }
    }
    values
}

/// Called only for a successful read at the synchronized actual KV1 owner.
/// The pinned passthrough route declares only its captured `path` field.
/// Values and private carrier-shaped user data never become warning selectors.
pub(crate) fn kv1_read_ignored_parameter_warning(body: &Value) -> Option<Value> {
    let mut keys = body
        .as_object()?
        .keys()
        .filter(|key| key.as_str() != "path")
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    (!keys.is_empty()).then(|| {
        json!([format!(
            "Endpoint ignored these unrecognized parameters: [{}]",
            keys.join(" ")
        )])
    })
}

fn kv_query<'a>(wire_method: &'a str, query: &str) -> Result<(&'a str, CarrierBody), Response> {
    let mut values = url_query(query);
    let method = if wire_method == "GET" {
        get_query_method(query).map_err(|error| Response::error(error.status, error.message))?
    } else {
        wire_method
    };
    if wire_method == "GET" && method == "LIST" {
        values.remove("list");
    }
    if wire_method == "GET" && method == "SCAN" {
        values.remove("scan");
    }
    let object = values
        .into_iter()
        .filter(|(key, _)| key != "help")
        .map(|(key, mut values)| {
            let value = if values.len() == 1 {
                Value::String(values.remove(0))
            } else {
                json!(values)
            };
            (key, value)
        })
        .collect();
    Ok((method, CarrierBody(Value::Object(object))))
}

// The pinned outer GET operation reads the first valid URL.Query list/scan
// value. Other query fields never replace the path-captured OCSP request.
// Go URL.Query discards fields containing bad escapes or raw semicolons.
pub(super) fn get_query_method(query: &str) -> Result<&'static str, ParseError> {
    let mut list = None;
    let mut scan = None;
    for field in query.split('&').filter(|field| !field.contains(';')) {
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        let Some(key) = decode_url_query(key) else {
            continue;
        };
        let target = match key.as_str() {
            "list" => &mut list,
            "scan" => &mut scan,
            _ => continue,
        };
        if target.is_none()
            && let Some(value) = decode_url_query(value)
        {
            *target = Some(value);
        }
    }
    let boolean = |value: Option<String>| match value.as_deref().unwrap_or("") {
        "true" | "True" | "TRUE" | "t" | "T" | "1" => Ok(true),
        "" | "false" | "False" | "FALSE" | "f" | "F" | "0" => Ok(false),
        _ => Err(bad("invalid list or scan query")),
    };
    match (boolean(list)?, boolean(scan)?) {
        (true, true) => Err(bad("list and scan are mutually exclusive")),
        (true, false) => Ok("LIST"),
        (false, true) => Ok("SCAN"),
        (false, false) => Ok("GET"),
    }
}

// Called only after Service has selected the longest actual PKI mount in its
// synchronized namespace. Percent decoding cannot select a mount or route.
pub(crate) fn decoded_get_body(suffix: &str) -> Value {
    let mut encoded = Vec::with_capacity(suffix.len().min(REQUEST_LIMIT));
    let mut bytes = suffix.bytes();
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'%' {
            let Some((a, b)) = bytes.next().zip(bytes.next()) else {
                return json!({REQUEST_MARKER: "!"});
            };
            let Ok(text) = std::str::from_utf8(&[a, b]).map(str::to_owned) else {
                return json!({REQUEST_MARKER: "!"});
            };
            let Ok(byte) = u8::from_str_radix(&text, 16) else {
                return json!({REQUEST_MARKER: "!"});
            };
            byte
        } else {
            byte
        };
        if !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/' | b'=')
            || encoded.len() >= REQUEST_LIMIT
        {
            // A well-framed malformed request reaches only its actual PKI
            // responder, preserving disabled-before-malformed precedence.
            return json!({REQUEST_MARKER: "!"});
        }
        encoded.push(byte);
    }
    json!({REQUEST_MARKER: String::from_utf8(encoded).unwrap_or_default()})
}

const POST_MARKER: &str = "__heptabao_pki_ocsp_raw_post";

pub(crate) fn post_route(method: &str, route: &str) -> bool {
    matches!(method, "POST" | "PUT") && route.strip_suffix("/ocsp").is_some_and(ordinary_path)
}

// Mirrors the pinned outer HTTP isOcspRequest admission, including media case
// normalization and parameter parsing; other media enter ordinary JSON first.
pub(super) fn raw_post(method: &str, route: &str, media: Option<&str>) -> bool {
    post_route(method, route)
        && media
            .and_then(|media| media.parse::<mime::Mime>().ok())
            .is_some_and(|media| media.essence_str() == "application/ocsp-request")
}

pub(super) fn form_media(media: Option<&str>) -> bool {
    media
        .and_then(|media| media.parse::<mime::Mime>().ok())
        .is_some_and(|media| media.essence_str() == "application/x-www-form-urlencoded")
}

// Pinned isForm samples only 512 bytes and skips JSON's four whitespace bytes.
pub(super) fn form_request(media: Option<&str>, bytes: &[u8]) -> bool {
    form_media(media)
        && !bytes
            .iter()
            .take(512)
            .find(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            .is_some_and(|byte| matches!(byte, b'{' | b'['))
}

pub(super) fn validate_form(bytes: &[u8]) -> Result<(), ParseError> {
    let mut bytes = bytes.iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            b';' => return Err(bad("error parsing form data")),
            b'%' if !bytes
                .next()
                .zip(bytes.next())
                .is_some_and(|(a, b)| a.is_ascii_hexdigit() && b.is_ascii_hexdigit()) =>
            {
                return Err(bad("error parsing form data"));
            }
            _ => {}
        }
    }
    Ok(())
}

const JSON_POST_MARKER: &str = "__heptabao_pki_ocsp_json_post";
pub(super) fn normal_json_post(
    path: &str,
    body: Value,
    media: Option<&str>,
    body_nonempty: bool,
    query: &str,
) -> Value {
    json!({JSON_POST_MARKER:{"path":path,"original_body":body,"content_type":media,"body_nonempty":body_nonempty,"query":query}})
}

// External normal JSON is wrapped exactly once by HTTP. Original user data is
// restored on non-PKI routes; its inner markers are never reinterpreted.
pub(crate) struct JsonPost<'a> {
    original: &'a Value,
    media: Option<&'a str>,
    body_nonempty: bool,
    method: &'a str,
    path: &'a str,
    query: &'a str,
}

pub(crate) fn json_post_request<'a>(
    method: &'a str,
    path: &'a str,
    body: &'a Value,
) -> Option<JsonPost<'a>> {
    if !post_route(method, path) {
        return None;
    }
    let body = body.as_object()?;
    if body.len() != 1 {
        return None;
    }
    let carrier = body.get(JSON_POST_MARKER)?.as_object()?;
    if carrier.len() != 5 || carrier.get("path")?.as_str()? != path {
        return None;
    }
    let original = carrier
        .get("original_body")
        .filter(|body| body.is_object())?;
    let media = match carrier.get("content_type")? {
        Value::Null => None,
        Value::String(media) if media.len() <= MAX_HEADERS => Some(media.as_str()),
        _ => return None,
    };
    Some(JsonPost {
        original,
        media,
        body_nonempty: carrier.get("body_nonempty")?.as_bool()?,
        method,
        path,
        query: carrier
            .get("query")?
            .as_str()
            .filter(|query| query.len() <= MAX_HEADERS)?,
    })
}

impl JsonPost<'_> {
    pub(crate) fn resolve(&self, actual_pki_ocsp: bool) -> Result<CarrierBody, Response> {
        if actual_pki_ocsp {
            // The pinned JSON branch supplies logical Data without HTTPRequest,
            // irrespective of its MIME type; the disable gate still runs first.
            return Ok(CarrierBody(json!({})));
        }
        if self.body_nonempty
            && self.media.is_some_and(|media| {
                !matches!(
                    media.split(';').next(),
                    Some("application/json" | "application/merge-patch+json")
                )
            })
        {
            return Err(Response::error(400, "JSON content type required"));
        }
        let mut body = CarrierBody(self.original.clone());
        merge_query_fields(self.method, self.path, self.query, &mut body.0)
            .map_err(|error| Response::error(error.status, error.message))?;
        Ok(body)
    }
}

// The HTTP parser retains the ordinary 256 KiB body limit and complete framing
// before making this carrier. Interpretation happens only at the actual mount;
// e.g. sys/mounts/ocsp remains an ordinary authenticated JSON control request.
pub(super) fn carrier_body(
    get: Option<&GetCarrier>,
    post: bool,
    path: &str,
    media: Option<&str>,
    bytes: &[u8],
    query: &str,
) -> Option<Value> {
    if let Some(get) = get {
        return Some(json!({GET_PATH_MARKER: {"path":get.original_path,"query":query}}));
    }
    post.then(|| {
        json!({POST_MARKER: {
            "path":path, "encoded":STANDARD.encode(bytes), "content_type":media,"query":query,
        }})
    })
}

pub(crate) struct RawPost<'a> {
    encoded: &'a str,
    media: Option<&'a str>,
    method: &'a str,
    path: &'a str,
    query: &'a str,
}

pub(crate) fn raw_post_request<'a>(
    method: &'a str,
    path: &'a str,
    body: &'a Value,
) -> Option<RawPost<'a>> {
    if !post_route(method, path) {
        return None;
    }
    let body = body.as_object()?;
    if body.len() != 1 {
        return None;
    }
    let carrier = body.get(POST_MARKER)?.as_object()?;
    if carrier.len() != 4 || carrier.get("path")?.as_str()? != path {
        return None;
    }
    let encoded = carrier.get("encoded")?.as_str()?;
    if encoded.len() > MAX_BODY.div_ceil(3) * 4 {
        return None;
    }
    let media = match carrier.get("content_type")? {
        Value::Null => None,
        Value::String(media) if media.len() <= MAX_HEADERS => Some(media.as_str()),
        _ => return None,
    };
    if !raw_post(method, path, media) && !form_media(media) {
        return None;
    }
    Some(RawPost {
        encoded,
        media,
        method,
        path,
        query: carrier
            .get("query")?
            .as_str()
            .filter(|query| query.len() <= MAX_HEADERS)?,
    })
}

impl RawPost<'_> {
    pub(crate) fn resolve(&self, actual_pki_ocsp: bool) -> Result<CarrierBody, Response> {
        if actual_pki_ocsp {
            // The pinned form branch has ordinary Data but no HTTPRequest;
            // the responder observes a missing raw body after its disable gate.
            return Ok(CarrierBody(if form_media(self.media) {
                json!({})
            } else {
                // No DER/base64 parsing before the disabled check.
                json!({REQUEST_MARKER:self.encoded})
            }));
        }
        if !self.encoded.is_empty()
            && self.media.is_some_and(|media| {
                !matches!(
                    media.split(';').next(),
                    Some("application/json" | "application/merge-patch+json")
                )
            })
        {
            return Err(Response::error(400, "JSON content type required"));
        }
        let bytes = Zeroizing::new(
            STANDARD
                .decode(self.encoded)
                .map_err(|_| Response::error(400, "invalid request-local body carrier"))?,
        );
        let canonical = Zeroizing::new(STANDARD.encode(bytes.as_slice()));
        if bytes.len() > MAX_BODY || canonical.as_str() != self.encoded {
            return Err(Response::error(400, "invalid request-local body carrier"));
        }
        if bytes.is_empty() {
            let mut body = CarrierBody(json!({}));
            merge_query_fields(self.method, self.path, self.query, &mut body.0)
                .map_err(|error| Response::error(error.status, error.message))?;
            return Ok(body);
        }
        let mut body = CarrierBody(
            crate::auth::parse_strict_json(bytes.as_slice())
                .map_err(|_| Response::error(400, "invalid JSON object"))?,
        );
        if !body.0.is_object() {
            crate::service::erase_json(&mut body.0);
            return Err(Response::error(400, "JSON object required"));
        }
        merge_query_fields(self.method, self.path, self.query, &mut body.0)
            .map_err(|error| Response::error(error.status, error.message))?;
        Ok(body)
    }
}

// Both audit events retain the same admitted fingerprint. Bind original
// request-local query bytes before routing; never log or persist those bytes.
pub(crate) fn audit_query<'a>(
    method: &str,
    path: &'a str,
    body: &'a Value,
) -> Option<(&'a str, &'a str, &'a str)> {
    if let Some(request) = super::help::request(method, path, body) {
        return Some(request);
    }

    if let Some(carrier) = get_request(method, path, body) {
        return Some(("GET", carrier.path, carrier.query));
    }
    query_request(method, path, body)
        .map(|carrier| (carrier.wire_method, carrier.path, carrier.query))
}

pub(crate) fn audit_payload<'a>(
    method: &'a str,
    path: &'a str,
    body: &'a Value,
) -> Option<&'a str> {
    if opaque_get_request(method, path, body) {
        return body.get(GET_PATH_MARKER)?.get("path")?.as_str();
    }
    if let Some(carrier) = query_request(method, path, body) {
        return Some(carrier.path);
    }
    if let Some(carrier) = raw_post_request(method, path, body) {
        return Some(carrier.encoded);
    }
    if !matches!(method, "GET" | "POST" | "PUT")
        || !path.strip_suffix("/ocsp").is_some_and(ordinary_path)
    {
        return None;
    }
    let object = body.as_object()?;
    if object.len() != 1 {
        return None;
    }
    object
        .get(REQUEST_MARKER)?
        .as_str()
        .filter(|text| text.len() <= REQUEST_LIMIT.div_ceil(3) * 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_get_queries_preserve_the_pinned_first_valid_operation_selector() {
        for (query, method) in [
            ("foo=bar", "GET"),
            ("unused=%GG", "GET"),
            ("list=true&list=false", "LIST"),
            ("list=false&list=true", "GET"),
            ("%6cist=1", "LIST"),
            ("list=%GG&list=true", "LIST"),
            ("list=true;x=a", "GET"),
            ("scan=true&list=false", "SCAN"),
            ("list=true&scan=false", "LIST"),
        ] {
            assert_eq!(get_query_method(query).ok(), Some(method));
        }
        for query in ["list=invalid", "list=true&scan=true"] {
            assert!(get_query_method(query).is_err());
        }
    }
    #[test]
    fn opaque_get_retains_the_complete_path_until_actual_mount_resolution() {
        for path in [
            "pki/ocsp/AA+/=",
            "pki/ocsp/AA%2B%2F%3D",
            "nested/ocsp/pki/ocsp/AA==",
            "pki/ocsp/AA/ocsp/AA==",
        ] {
            let get = get_carrier("GET", path).ok().flatten();
            assert!(get.is_some());
            let body =
                carrier_body(get.as_ref(), false, path, None, &[], "").unwrap_or(Value::Null);
            assert!(opaque_get_request("GET", path, &body));
            assert_eq!(body[GET_PATH_MARKER]["path"], path);
            assert_eq!(body[GET_PATH_MARKER]["query"], "");
            assert!(!opaque_get_request("POST", path, &body));
            assert!(!opaque_get_request("GET", "other/ocsp/AA==", &body));
        }
        for path in [
            "p%6bi/ocsp/AA==",
            "pki//ocsp/AA==",
            "../ocsp/AA==",
            "pki/ocsp/AA#",
        ] {
            assert!(get_carrier("GET", path).ok().flatten().is_none());
        }
        for suffix in ["AA+/=", "AA%2B%2F%3D"] {
            assert_eq!(decoded_get_body(suffix)[REQUEST_MARKER], "AA+/=");
        }
        for suffix in ["%0a", "%", "%gg"] {
            assert_eq!(decoded_get_body(suffix)[REQUEST_MARKER], "!");
        }
    }
    #[test]
    fn raw_post_carrier_selects_der_or_strict_json_only_after_actual_mount() {
        for (path, bytes, media) in [
            ("pki/ocsp", &b"DER!"[..], Some("application/ocsp-request")),
            (
                "sys/mounts/ocsp",
                &b"{\"type\":\"pki\"}"[..],
                Some("application/ocsp-request"),
            ),
        ] {
            let body = carrier_body(None, true, path, media, bytes, "").unwrap_or(Value::Null);
            let request = raw_post_request("POST", path, &body);
            assert!(request.is_some());
            let Some(request) = request else { return };
            assert!(request.resolve(true).is_ok());
            assert!(raw_post_request("POST", "other/ocsp", &body).is_none());
            assert!(request.resolve(false).is_err());
        }
        for raw in [&b"{\"type\":1,\"type\":2}"[..], &b"[]"[..], &b"DER!"[..]] {
            let body = carrier_body(
                None,
                true,
                "sys/mounts/ocsp",
                Some("application/ocsp-request"),
                raw,
                "",
            )
            .unwrap_or(Value::Null);
            assert!(
                raw_post_request("POST", "sys/mounts/ocsp", &body)
                    .is_some_and(|r| r.resolve(false).is_err())
            );
        }
    }
}

#[cfg(test)]
mod sdk_auth_query_tests {
    use super::*;

    #[test]
    fn sdk_auth_query_original_strings_duplicates_and_selected_operation() {
        let body = query_carrier_body(
            "GET",
            "auth/sdk/record",
            "username=a%2Bb&delay_ms=2000&value=x&value=y&bare&bad=%zz&semicolon=x;y&help=1&list=false",
        )
        .unwrap_or_else(|| unreachable!());
        let carrier =
            query_request("GET", "auth/sdk/record", &body).unwrap_or_else(|| unreachable!());
        let (method, projected) = carrier.resolve(true).unwrap_or_else(|_| unreachable!());
        assert_eq!(method, "GET");
        assert_eq!(
            projected.0,
            json!({
                "username":"a+b", "delay_ms":"2000", "value":["x","y"], "bare":"", "list":"false"
            })
        );
        assert!(carrier.resolve(false).is_err());
        assert!(query_request("GET", "auth/other/record", &body).is_none());
        assert!(query_request("POST", "auth/sdk/record", &body).is_none());
    }

    #[test]
    fn sdk_auth_query_list_consumes_only_selector_and_preserves_repeated_data() {
        let body = query_carrier_body(
            "GET",
            "auth/sdk/record",
            "list=true&list=false&scan=false&n=1&n=2",
        )
        .unwrap_or_else(|| unreachable!());
        let carrier =
            query_request("LIST", "auth/sdk/record", &body).unwrap_or_else(|| unreachable!());
        let (method, projected) = carrier.resolve(true).unwrap_or_else(|_| unreachable!());
        assert_eq!(method, "LIST");
        assert_eq!(projected.0, json!({"scan":"false","n":["1","2"]}));
        assert!(query_request("GET", "auth/sdk/record", &body).is_none());
        assert!(query_carrier_body("POST", "auth/sdk/record", "x=1").is_none());
    }
}
