//! Bounded HTTP HelpOperation provenance; ordinary JSON can never select it.
use super::*;
const MARKER: &str = "__heptabao_http_help_request";
pub(super) fn requested(method: &str, query: &str) -> bool {
    method == "HELP"
        || ocsp::url_query(query)
            .get("help")
            .and_then(|v| v.first())
            .is_some_and(|v| !v.is_empty())
}
pub(super) fn carrier(method: &str, path: &str, query: &str) -> Result<Value, ParseError> {
    if method == "GET" {
        ocsp::get_query_method(query)?;
    }
    Ok(json!({MARKER:{"path":path,"query":query,"wire_method":method}}))
}
pub(crate) fn request<'a>(
    method: &str,
    path: &'a str,
    body: &'a Value,
) -> Option<(&'a str, &'a str, &'a str)> {
    if method != "HELP" {
        return None;
    }
    let object = body.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let carrier = object.get(MARKER)?.as_object()?;
    if carrier.len() != 3 || carrier.get("path")?.as_str()? != path {
        return None;
    }
    let query = carrier.get("query")?.as_str()?;
    let wire_method = carrier.get("wire_method")?.as_str()?;
    if query.len() > MAX_HEADERS
        || !matches!(
            wire_method,
            "GET" | "POST" | "PUT" | "DELETE" | "LIST" | "SCAN" | "PATCH" | "HEAD" | "HELP"
        )
        || !requested(wire_method, query)
        || wire_method == "GET" && ocsp::get_query_method(query).is_err()
    {
        return None;
    }
    Some((wire_method, path, query))
}
pub(crate) fn opaque_request(method: &str, path: &str, body: &Value) -> bool {
    request(method, path, body).is_some()
        && path.len() <= 4096
        && path
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'?' | b'#'))
        && path.contains("/ocsp/")
}
