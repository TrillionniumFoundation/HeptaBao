//! Private custody of the original admitted logical HTTP envelope (format110).
//! This carries response data only: no actor, provider authority or new clock.
use super::*;
use base64::engine::general_purpose::STANDARD as RAW_BASE64;
use std::cell::RefCell;
#[path = "auth_lexical_json113.rs"]
mod lexical113;
pub(crate) use lexical113::LexicalJson;

#[derive(Clone)]
pub(crate) struct IngressReplyContext {
    attempt_id: [u8; 16],
    lexical_body: Option<LexicalJson>,
}
thread_local! {
    static INGRESS: RefCell<Option<IngressReplyContext>> = const { RefCell::new(None) };
}
pub(crate) struct IngressReplyScope {
    previous: Option<IngressReplyContext>,
}
impl IngressReplyScope {
    /// Test controls supply a fixed admitted ID; production uses listener_wrapping.
    #[cfg(test)]
    pub(crate) fn listener(attempt_id: &[u8; 16]) -> Self {
        Self::restore(Some(IngressReplyContext {
            attempt_id: *attempt_id,
            lexical_body: None,
        }))
    }
    /// The actual listener has already parsed and bound the complete body.
    pub(crate) fn listener_wrapping(
        attempt_id: &[u8; 16],
        lexical_body: Option<LexicalJson>,
    ) -> Self {
        Self::restore(Some(IngressReplyContext {
            attempt_id: *attempt_id,
            lexical_body,
        }))
    }
    /// Called after the authenticated peer frame and direction are admitted.
    pub(crate) fn authenticated_forward(
        attempt_id: Option<[u8; 16]>,
        lexical_body: Option<LexicalJson>,
    ) -> Self {
        Self::restore(attempt_id.map(|attempt_id| IngressReplyContext {
            attempt_id,
            lexical_body,
        }))
    }
    pub(crate) fn restore(context: Option<IngressReplyContext>) -> Self {
        let previous = INGRESS.with(|slot| slot.replace(context));
        Self { previous }
    }
}
impl Drop for IngressReplyScope {
    fn drop(&mut self) {
        INGRESS.with(|slot| {
            slot.replace(self.previous.take());
        });
    }
}
pub(crate) fn current_ingress() -> Option<IngressReplyContext> {
    INGRESS.with(|slot| slot.borrow().clone())
}
impl IngressReplyContext {
    pub(crate) fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }
    pub(crate) fn wrapping_body(&self) -> Option<&LexicalJson> {
        self.lexical_body.as_ref()
    }
    pub(crate) fn lexical_request_binding(
        &self,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, AuthError> {
        let Some(lexical) = &self.lexical_body else {
            return Ok(None);
        };
        if !matches!(method, "POST" | "PUT") || path != "sys/wrapping/wrap" {
            return Err(bad("lexical ingress is outside opaque wrapping endpoint"));
        }
        lexical.validate_wrapping_view(body)?;
        lexical.encode(64 * 1024).map(Some)
    }
    fn request_id(&self) -> String {
        crate::crypto::uuid_from_bytes(&self.attempt_id)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
enum ReplyKind {
    JsonEnvelopeV1,
    PkiRawHttpV1 {
        status: u16,
        nil_body: bool,
    },
    GeneralJsonEnvelopeV1 {
        lexical_data: LexicalJson,
    },
    GeneralSelectedJsonV1 {
        lexical_data: Option<LexicalJson>,
    },
    GeneralRawHttpV1 {
        lexical_data: Option<LexicalJson>,
        presentation: GeneralRawPresentation,
    },
}

/// Only the admitted server route selects this closed internal Data projection.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum LogicalProjection {
    Ordinary,
    TokenLookup,
    MountTune,
    MountTable,
}
impl LogicalProjection {
    fn for_path(path: &str) -> Self {
        if matches!(
            path,
            "auth/token/lookup" | "auth/token/lookup-self" | "auth/token/lookup-accessor"
        ) {
            Self::TokenLookup
        } else if path.ends_with("/tune")
            && (path.starts_with("sys/mounts/") || path.starts_with("sys/auth/"))
        {
            Self::MountTune
        } else if path == "sys/mounts" {
            Self::MountTable
        } else {
            Self::Ordinary
        }
    }
    fn project_data(&self, projection: &mut Value) {
        let Some(data) = projection.get_mut("data").and_then(Value::as_object_mut) else {
            return;
        };
        let erase_field = |data: &mut serde_json::Map<String, Value>, name: &str| {
            if let Some(mut removed) = data.remove(name) {
                crate::service::erase_json(&mut removed);
            }
        };
        match self {
            Self::TokenLookup => {
                erase_field(data, "namespace");
                erase_field(data, "expire_time_unix");
                data.entry("meta").or_insert(Value::Null);
                if !data.contains_key("issue_time")
                    && let Some(created) = data.get("creation_time").and_then(Value::as_u64)
                {
                    data.insert(
                        "issue_time".into(),
                        json!(crate::engines::timestamp(created)),
                    );
                }
                if data.contains_key("identity_policies") {
                    data.entry("external_namespace_policies")
                        .or_insert_with(|| json!({}));
                }
            }
            Self::MountTune => {
                for name in ["revision", "incarnation", "accessor"] {
                    erase_field(data, name);
                }
            }
            Self::MountTable => {
                for mount in data.values_mut().filter_map(Value::as_object_mut) {
                    for name in ["revision", "incarnation"] {
                        erase_field(mount, name);
                    }
                }
            }
            Self::Ordinary => {}
        }
    }
}

/// Legacy bool JSON stays byte-identical. The dedicated PKI marker permanently
/// refuses old literal bool decoders, including after last-token retirement.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(in crate::auth) enum RawReplyReaderFloor {
    Legacy(bool),
    PkiHttp(PkiHttpReader),
    GeneralHttp(GeneralHttpReader),
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(in crate::auth) enum PkiHttpReader {
    PkiRawHttpV1,
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(in crate::auth) enum GeneralHttpReader {
    GeneralWrappedReplyV1,
    PkiAndGeneralWrappedReplyV1,
}
impl Default for RawReplyReaderFloor {
    fn default() -> Self {
        Self::Legacy(false)
    }
}
impl RawReplyReaderFloor {
    pub(in crate::auth) fn is_absent(&self) -> bool {
        matches!(self, Self::Legacy(false))
    }
    fn has_original(&self) -> bool {
        !self.is_absent()
    }
    fn has_pki_http(&self) -> bool {
        matches!(
            self,
            Self::PkiHttp(PkiHttpReader::PkiRawHttpV1)
                | Self::GeneralHttp(GeneralHttpReader::PkiAndGeneralWrappedReplyV1)
        )
    }
    fn has_general(&self) -> bool {
        matches!(self, Self::GeneralHttp(_))
    }
    pub(in crate::auth) fn observe(&mut self, pki_http: bool, general: bool) {
        let pki_http = self.has_pki_http() || pki_http;
        let general = self.has_general() || general;
        if general {
            *self = Self::GeneralHttp(if pki_http {
                GeneralHttpReader::PkiAndGeneralWrappedReplyV1
            } else {
                GeneralHttpReader::GeneralWrappedReplyV1
            });
        } else if pki_http {
            *self = Self::PkiHttp(PkiHttpReader::PkiRawHttpV1);
        } else if self.is_absent() {
            *self = Self::Legacy(true);
        }
    }
}

/// Only encrypted Auth custody and explicitly negotiated HA frames serialize it.
/// Neither Debug nor a public constructor exposes a secret-bearing representation.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredWrappedReply {
    kind: ReplyKind,
    logical_projection: LogicalProjection,
    media_type: String,
    byte_count: usize,
    digest: [u8; 32],
    request_id: String,
    bytes: Vec<u8>,
}
impl Drop for StoredWrappedReply {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.request_id.zeroize();
    }
}

const ENVELOPE_FIELDS: [&str; 8] = [
    "request_id",
    "lease_id",
    "renewable",
    "lease_duration",
    "data",
    "wrap_info",
    "warnings",
    "auth",
];
const AUTH_FIELDS: [&str; 13] = [
    "client_token",
    "accessor",
    "policies",
    "token_policies",
    "identity_policies",
    "metadata",
    "lease_duration",
    "renewable",
    "entity_id",
    "token_type",
    "orphan",
    "mfa_requirement",
    "num_uses",
];

fn field(value: &Value, name: &str, default: Value) -> Value {
    value.get(name).cloned().unwrap_or(default)
}

/// Closed projection of the backend's admitted logical reply, never user Data.
pub(crate) fn logical_envelope(
    response: &Value,
    request_id: &str,
    path: &str,
) -> Result<Value, AuthError> {
    logical_envelope_for_projection(response, request_id, &LogicalProjection::for_path(path))
}
fn logical_envelope_for_projection(
    response: &Value,
    request_id: &str,
    logical_projection: &LogicalProjection,
) -> Result<Value, AuthError> {
    if !response.is_object() || !valid_request_id(request_id) {
        return Err(bad("invalid stored logical reply projection"));
    }
    let mut auth = field(response, "auth", Value::Null);
    if let Some(object) = auth.as_object_mut() {
        object.entry("mfa_requirement").or_insert(Value::Null);
        object.entry("metadata").or_insert(Value::Null);
        for name in ["identity_policies", "token_policies"] {
            if object
                .get(name)
                .is_some_and(|v| v.is_null() || v.as_array().is_some_and(Vec::is_empty))
            {
                object.remove(name);
            }
        }
        // Exact HTTPAuth projection from the admitted backend Auth, with Go defaults.
        let mut original = auth;
        let mut projected = serde_json::Map::new();
        for (name, default) in [
            ("client_token", json!("")),
            ("accessor", json!("")),
            ("policies", Value::Null),
            ("metadata", Value::Null),
            ("lease_duration", json!(0)),
            ("renewable", json!(false)),
            ("entity_id", json!("")),
            ("token_type", json!("")),
            ("orphan", json!(false)),
            ("mfa_requirement", Value::Null),
            ("num_uses", json!(0)),
        ] {
            projected.insert(name.into(), field(&original, name, default));
        }
        for name in ["token_policies", "identity_policies"] {
            if let Some(value) = original.get(name) {
                projected.insert(name.into(), value.clone());
            }
        }
        crate::service::erase_json(&mut original);
        auth = Value::Object(projected);
    } else if !auth.is_null() {
        crate::service::erase_json(&mut auth);
        return Err(bad("invalid stored logical Auth projection"));
    }
    let mut projection = json!({
        "request_id":request_id, "lease_id":field(response,"lease_id",json!("")),
        "renewable":field(response,"renewable",json!(false)),
        "lease_duration":field(response,"lease_duration",json!(0)),
        "data":field(response,"data",Value::Null),
        "wrap_info":Value::Null,
        "warnings":field(response,"warnings",Value::Null), "auth":auth
    });
    if projection["lease_id"].as_str().is_none()
        || projection["renewable"].as_bool().is_none()
        || projection["lease_duration"].as_u64().is_none()
        || !(projection["data"].is_null() || projection["data"].is_object())
        || !(projection["warnings"].is_null()
            || projection["warnings"]
                .as_array()
                .is_some_and(|a| a.iter().all(Value::is_string)))
    {
        crate::service::erase_json(&mut projection);
        return Err(bad("invalid stored logical envelope types"));
    }
    logical_projection.project_data(&mut projection);
    Ok(projection)
}
fn valid_request_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(n, b)| {
            if [8, 13, 18, 23].contains(&n) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

/// Encode Go's HTTPResponse field order and HTML/line-separator escaping.
pub(crate) fn encode_envelope(projection: &Value) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    encode_http_envelope(projection, MAX_WRAPPED_RESPONSE_BYTES)
}
pub(crate) fn encode_http_envelope(
    projection: &Value,
    bound: usize,
) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.push(b'{');
    for (index, name) in ENVELOPE_FIELDS.iter().enumerate() {
        if index != 0 {
            bytes.push(b',');
        }
        append_json(&mut bytes, &json!(name), bound)?;
        bytes.push(b':');
        if *name == "auth" && projection[*name].is_object() {
            bytes.push(b'{');
            let mut first = true;
            for field in AUTH_FIELDS {
                if let Some(value) = projection[*name].get(field) {
                    if !first {
                        bytes.push(b',');
                    }
                    first = false;
                    append_json(&mut bytes, &json!(field), bound)?;
                    bytes.push(b':');
                    append_json(&mut bytes, value, bound)?;
                }
            }
            bytes.push(b'}');
        } else {
            append_json(&mut bytes, &projection[*name], bound)?;
        }
        if bytes.len() > bound {
            return Err(err(413, "stored wrapped reply exceeds supported bounds"));
        }
    }
    bytes.push(b'}');
    if bytes.len() > bound {
        return Err(err(413, "logical envelope exceeds supported bounds"));
    }
    Ok(bytes)
}

fn encode_lexical_envelope(
    projection: &Value,
    lexical_data: &LexicalJson,
    bound: usize,
) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.push(b'{');
    for (index, name) in ENVELOPE_FIELDS.iter().enumerate() {
        if index != 0 {
            bytes.push(b',');
        }
        append_json(&mut bytes, &json!(name), bound)?;
        bytes.push(b':');
        if *name == "data" {
            bytes.extend_from_slice(&lexical_data.encode(bound)?);
        } else if *name == "auth" && projection[*name].is_object() {
            bytes.push(b'{');
            let mut first = true;
            for field in AUTH_FIELDS {
                if let Some(value) = projection[*name].get(field) {
                    if !first {
                        bytes.push(b',');
                    }
                    first = false;
                    append_json(&mut bytes, &json!(field), bound)?;
                    bytes.push(b':');
                    append_json(&mut bytes, value, bound)?;
                }
            }
            bytes.push(b'}');
        } else {
            append_json(&mut bytes, &projection[*name], bound)?;
        }
        if bytes.len() > bound {
            return Err(err(413, "lexical envelope exceeds bound"));
        }
    }
    bytes.push(b'}');
    if bytes.len() > bound {
        return Err(err(413, "lexical envelope exceeds bound"));
    }
    Ok(bytes)
}

fn append_json(output: &mut Vec<u8>, value: &Value, bound: usize) -> Result<(), AuthError> {
    match value {
        Value::Array(values) => {
            output.push(b'[');
            for (n, value) in values.iter().enumerate() {
                if n != 0 {
                    output.push(b',');
                }
                append_json(output, value, bound)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (n, key) in keys.into_iter().enumerate() {
                if n != 0 {
                    output.push(b',');
                }
                append_json(output, &Value::String(key.clone()), bound)?;
                output.push(b':');
                append_json(output, &values[key], bound)?;
            }
            output.push(b'}');
        }
        Value::Number(number) => {
            let text = if number.is_i64() || number.is_u64() {
                number.to_string()
            } else {
                go_float(number)?
            };
            output.extend_from_slice(text.as_bytes());
        }
        _ => {
            let encoded = Zeroizing::new(
                serde_json::to_vec(value).map_err(|_| bad("stored JSON encoding failed"))?,
            );
            let mut n = 0;
            while n < encoded.len() {
                let (replacement, count): (Option<&[u8]>, usize) = match encoded[n] {
                    b'<' => (Some(b"\\u003c"), 1),
                    b'>' => (Some(b"\\u003e"), 1),
                    b'&' => (Some(b"\\u0026"), 1),
                    0xe2 if encoded.get(n..n + 3) == Some(&[0xe2, 0x80, 0xa8]) => {
                        (Some(b"\\u2028"), 3)
                    }
                    0xe2 if encoded.get(n..n + 3) == Some(&[0xe2, 0x80, 0xa9]) => {
                        (Some(b"\\u2029"), 3)
                    }
                    _ => (None, 1),
                };
                if let Some(replacement) = replacement {
                    output.extend_from_slice(replacement);
                } else {
                    output.push(encoded[n]);
                }
                n += count;
            }
        }
    }
    if output.len() > bound {
        Err(err(413, "stored wrapped reply exceeds supported bounds"))
    } else {
        Ok(())
    }
}
fn go_float(number: &serde_json::Number) -> Result<String, AuthError> {
    let value = number
        .as_f64()
        .ok_or_else(|| bad("invalid logical number"))?;
    if !value.is_finite() {
        return Err(bad("invalid logical number"));
    }
    let text = number.to_string();
    let (negative, text) = if let Some(rest) = text.strip_prefix('-') {
        (true, rest)
    } else {
        (false, text.as_str())
    };
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((m, e)) => (
            m,
            e.parse::<i32>()
                .map_err(|_| bad("invalid logical exponent"))?,
        ),
        None => (text, 0),
    };
    let mut digits = mantissa.replace('.', "");
    let decimal = i32::try_from(mantissa.find('.').unwrap_or(mantissa.len()))
        .map_err(|_| bad("logical number exceeds bound"))?
        + exponent;
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    let absolute = value.abs();
    let mut result = if absolute == 0.0 {
        "0".to_owned()
    } else if (1e-6..1e21).contains(&absolute) {
        if decimal <= 0 {
            format!("0.{}{}", "0".repeat((-decimal) as usize), digits)
        } else if decimal as usize >= digits.len() {
            format!("{}{}", digits, "0".repeat(decimal as usize - digits.len()))
        } else {
            let n = decimal as usize;
            format!("{}.{}", &digits[..n], &digits[n..])
        }
    } else {
        // Ryu's shortest decimal mantissa is shared; use Go's exponent boundary.
        let leading = digits.bytes().take_while(|b| *b == b'0').count();
        let significant = &digits[leading..];
        let scientific_exp =
            decimal - i32::try_from(leading).map_err(|_| bad("logical number exceeds bound"))? - 1;
        let fraction = if significant.len() > 1 {
            format!(".{}", &significant[1..])
        } else {
            String::new()
        };
        format!(
            "{}{}e{}{scientific_exp}",
            &significant[..1],
            fraction,
            if scientific_exp >= 0 { "+" } else { "" }
        )
    };
    if negative {
        result.insert(0, '-');
    }
    Ok(result)
}
/// A closed projection is validated again after encrypted loading and HA receipt.
/// This cannot mint an origin: only capture_pki accepts the sealed producer type.
type PkiHttpProjection = (u16, String, bool, Zeroizing<Vec<u8>>);
fn pki_http_projection(logical: &Value) -> Result<PkiHttpProjection, AuthError> {
    let invalid = || bad("invalid stored PKI raw HTTP projection");
    let root = logical.as_object().ok_or_else(invalid)?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    if root.len() != 1 || data.len() != 3 {
        return Err(invalid());
    }
    let status = data
        .get("http_status_code")
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(invalid)?;
    let media = data
        .get("http_content_type")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let valid_status = match media {
        "application/pkix-cert" | "application/pem-certificate-chain" => status == 200,
        "application/pkix-crl" | "application/x-pem-file" => matches!(status, 200 | 204),
        "application/ocsp-response" => matches!(status, 200 | 400 | 401 | 500),
        _ => false,
    };
    if !valid_status {
        return Err(invalid());
    }
    let body = data.get("http_raw_body").ok_or_else(invalid)?;
    let nil_body = status == 204;
    let bytes = if nil_body {
        if !body.is_null() {
            return Err(invalid());
        }
        Zeroizing::new(Vec::new())
    } else {
        let text = body.as_str().ok_or_else(invalid)?;
        if text.len() > MAX_WRAPPED_RESPONSE_BYTES.div_ceil(3) * 4 {
            return Err(invalid());
        }
        let bytes = Zeroizing::new(RAW_BASE64.decode(text).map_err(|_| invalid())?);
        if bytes.is_empty()
            || bytes.len() > MAX_WRAPPED_RESPONSE_BYTES
            || RAW_BASE64.encode(&*bytes) != text
        {
            return Err(invalid());
        }
        bytes
    };
    Ok((status, media.to_owned(), nil_body, bytes))
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
enum GeneralRawError {
    NoStatusCode,
    CannotDecodeStatusCode,
    NoContentType,
    CannotDecodeContentType,
}
impl GeneralRawError {
    fn header(self) -> &'static str {
        match self {
            Self::NoStatusCode => "no status code given",
            Self::CannotDecodeStatusCode => "cannot decode status code",
            Self::NoContentType => "no content type given",
            Self::CannotDecodeContentType => "cannot decode content type",
        }
    }
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GeneralRawPresentation {
    status: u16,
    error: Option<GeneralRawError>,
    connection_abort: bool,
}
type GeneralRawProjection = (GeneralRawPresentation, String, Zeroizing<Vec<u8>>);
fn has_special_presentation(response: &Value) -> bool {
    response
        .get("data")
        .and_then(Value::as_object)
        .is_some_and(|data| {
            ["http_status_code", "http_content_type", "http_raw_body"]
                .iter()
                .any(|name| data.get(*name).is_some_and(|value| !value.is_null()))
        })
}
/// Affine response-only selection prepared before the mandatory response audit.
/// The HTTP Data and the original []byte/string audit type share this owner;
/// neither a client marker nor an SDK Data key can construct this owner.
pub(super) struct SelectedResponseProjection {
    wire_data: LexicalJson,
    raw_body: Option<SelectedAuditRawBody>,
}
enum SelectedAuditRawBody {
    DecodedBytes(Zeroizing<Vec<u8>>),
    Text(Zeroizing<String>),
}
impl SelectedResponseProjection {
    pub(super) fn audit_binding(&self) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        // This is custody input for the existing mandatory audit chain, not
        // OpenBao's per-field HashResponse format or a device salt contract.
        let typed = Zeroizing::new(
            serde_json::to_vec(&self.wire_data)
                .map_err(|_| bad("selected response audit projection cannot encode"))?,
        );
        let mut payload = Zeroizing::new(Vec::new());
        payload.extend_from_slice(&(typed.len() as u64).to_le_bytes());
        payload.extend_from_slice(&typed);
        let (kind, raw): (u8, &[u8]) = match &self.raw_body {
            None => (0, &[]),
            Some(SelectedAuditRawBody::DecodedBytes(bytes)) => (1, bytes),
            Some(SelectedAuditRawBody::Text(text)) => (2, text.as_bytes()),
        };
        payload.push(kind);
        payload.extend_from_slice(&(raw.len() as u64).to_le_bytes());
        payload.extend_from_slice(raw);
        if payload.len() > 256 * 1024 {
            return Err(bad("selected response audit projection exceeds bound"));
        }
        Ok(payload)
    }
    fn same_selection(&self, other: &Self) -> bool {
        self.wire_data == other.wire_data
            && match (&self.raw_body, &other.raw_body) {
                (None, None) => true,
                (
                    Some(SelectedAuditRawBody::DecodedBytes(left)),
                    Some(SelectedAuditRawBody::DecodedBytes(right)),
                ) => left.as_slice() == right.as_slice(),
                (
                    Some(SelectedAuditRawBody::Text(left)),
                    Some(SelectedAuditRawBody::Text(right)),
                ) => left.as_str() == right.as_str(),
                _ => false,
            }
    }
    fn has_status(&self) -> bool {
        matches!(&self.wire_data, LexicalJson::Object(data) if data.contains_key("http_status_code"))
    }
}
fn selected_response_projection(
    logical: &Value,
    lexical_data: Option<&LexicalJson>,
) -> Result<Option<SelectedResponseProjection>, AuthError> {
    if !has_special_presentation(logical) {
        return Ok(None);
    }
    let generated;
    let data = if let Some(data) = lexical_data {
        data.validate_wrapping_view(&logical["data"])?;
        data
    } else {
        generated = LexicalJson::from_backend(&logical["data"])?;
        &generated
    };
    let LexicalJson::Object(fields) = data else {
        return Err(bad("selected presentation requires actual data object"));
    };
    let get = |name| fields.get(name).filter(|v| !matches!(v, LexicalJson::Null));
    let mut selected = std::collections::BTreeMap::new();
    for name in ["http_status_code", "http_content_type"] {
        if let Some(value) = get(name) {
            selected.insert(name.into(), value.clone());
        }
    }
    let mut raw_body = None;
    if let Some(body) = get("http_raw_body") {
        if let LexicalJson::String(text) = body {
            let input = Zeroizing::new(
                text.bytes()
                    .filter(|b| !matches!(b, b'\r' | b'\n'))
                    .collect::<Vec<_>>(),
            );
            let decoder = base64::engine::general_purpose::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::general_purpose::GeneralPurposeConfig::new()
                    .with_decode_allow_trailing_bits(true),
            );
            // OpenBao restores valid Base64 to []byte for HashResponse, while
            // the ordinary HTTP JSON encoder emits its standard Base64 text.
            let wire_body = match decoder.decode(&*input) {
                Ok(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    let wire = LexicalJson::String(RAW_BASE64.encode(&*bytes));
                    raw_body = Some(SelectedAuditRawBody::DecodedBytes(bytes));
                    wire
                }
                Err(_) => {
                    raw_body = Some(SelectedAuditRawBody::Text(Zeroizing::new(text.clone())));
                    LexicalJson::String(text.clone())
                }
            };
            selected.insert("http_raw_body".into(), wire_body);
            // request_handling removes the internal marker before both the
            // mandatory audit and terminal projection when the body survives.
        } else {
            // logical_system dropped a non-string body, so request_handling's
            // non-null body gate does not remove the server-created marker.
            selected.insert(
                "http_raw_body_already_json_decoded".into(),
                LexicalJson::Bool(true),
            );
        }
    }
    Ok(Some(SelectedResponseProjection {
        wire_data: LexicalJson::Object(selected),
        raw_body,
    }))
}
// A selected response without status is ordinary JSON of the current unwrap
// request. Its original stored response bytes and request ID stay immutable.
fn selected_ordinary_data(
    logical: &Value,
    lexical_data: Option<&LexicalJson>,
) -> Result<Option<LexicalJson>, AuthError> {
    Ok(selected_response_projection(logical, lexical_data)?
        .filter(|projection| !projection.has_status())
        .map(|projection| projection.wire_data.clone()))
}
fn general_raw_projection(
    logical: &Value,
    lexical_data: Option<&LexicalJson>,
) -> Result<GeneralRawProjection, AuthError> {
    let generated;
    let data = if let Some(data) = lexical_data {
        data.validate_wrapping_view(&logical["data"])?;
        data
    } else {
        generated = LexicalJson::from_backend(&logical["data"])?;
        &generated
    };
    let LexicalJson::Object(fields) = data else {
        return Err(bad(
            "special presentation requires admitted logical data object",
        ));
    };
    // The primary stored unwrap copies non-null special values only. It does
    // not inherit client Auth, Secret, arbitrary headers or a PKI producer label.
    let get = |name| fields.get(name).filter(|v| !matches!(v, LexicalJson::Null));
    let error = |value| {
        Ok((
            GeneralRawPresentation {
                status: 500,
                error: Some(value),
                connection_abort: false,
            },
            String::new(),
            Zeroizing::new(Vec::new()),
        ))
    };
    let Some(status) = get("http_status_code") else {
        return error(GeneralRawError::NoStatusCode);
    };
    let LexicalJson::Number(number) = status else {
        return error(GeneralRawError::CannotDecodeStatusCode);
    };
    let number = match number.parse::<f64>() {
        Ok(number) if number.is_finite() => number.trunc(),
        _ => return error(GeneralRawError::CannotDecodeStatusCode),
    };
    // net/http panics rather than emits a status outside its valid 100..999
    // range. The owned writer closes this connection after the genuine consume.
    if !(100.0..=999.0).contains(&number) {
        return Ok((
            GeneralRawPresentation {
                status: 500,
                error: None,
                connection_abort: true,
            },
            String::new(),
            Zeroizing::new(Vec::new()),
        ));
    }
    let status = number as u16;
    let media_type = match get("http_content_type") {
        Some(LexicalJson::String(media)) => {
            if media.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                return Err(bad("raw content type contains invalid header bytes"));
            }
            media.clone()
        }
        Some(_) => return error(GeneralRawError::CannotDecodeContentType),
        None if status != 204 => return error(GeneralRawError::NoContentType),
        None => String::new(),
    };
    let bytes = if status == 204 {
        Zeroizing::new(Vec::new())
    } else if let Some(LexicalJson::String(body)) = get("http_raw_body") {
        // Go StdEncoding ignores CR/LF and permits non-zero trailing pad bits.
        let input = Zeroizing::new(
            body.bytes()
                .filter(|b| !matches!(b, b'\r' | b'\n'))
                .collect::<Vec<_>>(),
        );
        let decoder = base64::engine::general_purpose::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::general_purpose::GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true),
        );
        Zeroizing::new(
            decoder
                .decode(&*input)
                .unwrap_or_else(|_| body.as_bytes().to_vec()),
        )
    } else {
        // Missing or non-string body is not copied by primary unwrap.
        Zeroizing::new(Vec::new())
    };
    if bytes.len() > MAX_WRAPPED_RESPONSE_BYTES {
        return Err(err(413, "raw presentation exceeds supported bounds"));
    }
    Ok((
        GeneralRawPresentation {
            status,
            error: None,
            connection_abort: false,
        },
        media_type,
        bytes,
    ))
}

impl StoredWrappedReply {
    pub(super) fn capture(
        response: &Value,
        context: &IngressReplyContext,
        path: &str,
    ) -> Result<Self, AuthError> {
        if has_special_presentation(response) {
            return Self::capture_general_raw(response, context, path);
        }
        if let Some(lexical_data) = context.wrapping_body() {
            return Self::capture_lexical(response, context, path, lexical_data);
        }
        let request_id = context.request_id();
        let logical_projection = LogicalProjection::for_path(path);
        let mut projection =
            logical_envelope_for_projection(response, &request_id, &logical_projection)?;
        let bytes = encode_envelope(&projection);
        crate::service::erase_json(&mut projection);
        let bytes = bytes?;
        let result = Self {
            kind: ReplyKind::JsonEnvelopeV1,
            logical_projection,
            media_type: "application/json".into(),
            byte_count: bytes.len(),
            digest: crate::ha_forward_completion::digest(&bytes),
            request_id,
            bytes: bytes.to_vec(),
        };
        result.validate(response)?;
        Ok(result)
    }

    fn capture_general_raw(
        response: &Value,
        context: &IngressReplyContext,
        path: &str,
    ) -> Result<Self, AuthError> {
        let lexical_data = context.wrapping_body();
        if lexical_data.is_some() && path != "sys/wrapping/wrap" {
            return Err(bad("lexical raw owner is outside wrapping endpoint"));
        }
        if selected_ordinary_data(response, lexical_data)?.is_some() {
            return Self::capture_selected_json(response, context, path);
        }
        let (presentation, media_type, bytes) = general_raw_projection(response, lexical_data)?;
        let result = Self {
            kind: ReplyKind::GeneralRawHttpV1 {
                lexical_data: lexical_data.cloned(),
                presentation,
            },
            logical_projection: LogicalProjection::for_path(path),
            media_type,
            byte_count: bytes.len(),
            digest: crate::ha_forward_completion::digest(&bytes),
            request_id: context.request_id(),
            bytes: bytes.to_vec(),
        };
        result.validate(response)?;
        Ok(result)
    }
    fn capture_selected_json(
        response: &Value,
        context: &IngressReplyContext,
        path: &str,
    ) -> Result<Self, AuthError> {
        let lexical_data = context.wrapping_body();
        if selected_ordinary_data(response, lexical_data)?.is_none() {
            return Err(bad(
                "selected JSON has a raw status or lacks special fields",
            ));
        }
        let request_id = context.request_id();
        let logical_projection = LogicalProjection::for_path(path);
        let generated;
        let data = if let Some(data) = lexical_data {
            data
        } else {
            generated = LexicalJson::from_backend(&response["data"])?;
            &generated
        };
        let mut projection =
            logical_envelope_for_projection(response, &request_id, &logical_projection)?;
        let bytes = encode_lexical_envelope(&projection, data, MAX_WRAPPED_RESPONSE_BYTES);
        crate::service::erase_json(&mut projection);
        let bytes = bytes?;
        let result = Self {
            kind: ReplyKind::GeneralSelectedJsonV1 {
                lexical_data: lexical_data.cloned(),
            },
            logical_projection,
            media_type: "application/json".into(),
            byte_count: bytes.len(),
            digest: crate::ha_forward_completion::digest(&bytes),
            request_id,
            bytes: bytes.to_vec(),
        };
        result.validate(response)?;
        Ok(result)
    }
    pub(crate) fn uses_selected_json_ingress(&self) -> bool {
        matches!(self.kind, ReplyKind::GeneralSelectedJsonV1 { .. })
    }
    pub(super) fn selected_response_for_audit(
        &self,
        logical: &Value,
    ) -> Result<Option<SelectedResponseProjection>, AuthError> {
        self.validate(logical)?;
        match &self.kind {
            ReplyKind::GeneralSelectedJsonV1 { lexical_data }
            | ReplyKind::GeneralRawHttpV1 { lexical_data, .. } => {
                selected_response_projection(logical, lexical_data.as_ref())
            }
            _ => Ok(None),
        }
    }
    pub(super) fn selected_json_for_ingress(
        &self,
        logical: &Value,
        actual_ingress: &[u8; 16],
        prepared: &SelectedResponseProjection,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, AuthError> {
        self.validate(logical)?;
        let ReplyKind::GeneralSelectedJsonV1 { lexical_data } = &self.kind else {
            return Ok(None);
        };
        let selected = selected_response_projection(logical, lexical_data.as_ref())?
            .ok_or_else(|| bad("selected JSON no longer has ordinary presentation"))?;
        if selected.has_status() || !selected.same_selection(prepared) {
            return Err(bad("selected JSON differs from mandatory audit projection"));
        }
        let selected = &prepared.wire_data;
        let mut public_logical = json!({"data":selected.wrapping_view()?});
        let request_id = crate::crypto::uuid_from_bytes(actual_ingress);
        let mut projection = logical_envelope_for_projection(
            &public_logical,
            &request_id,
            &LogicalProjection::Ordinary,
        )?;
        let encoded = encode_lexical_envelope(&projection, selected, MAX_WRAPPED_RESPONSE_BYTES);
        crate::service::erase_json(&mut public_logical);
        crate::service::erase_json(&mut projection);
        let mut encoded = encoded?;
        // The selected ordinary response follows the JSON encoder's newline.
        encoded.push(b'\n');
        Ok(Some(encoded))
    }
    pub(crate) fn raw_error_header(
        &self,
        logical: &Value,
    ) -> Result<Option<&'static str>, AuthError> {
        self.validate(logical)?;
        Ok(match &self.kind {
            ReplyKind::GeneralRawHttpV1 { presentation, .. } => {
                presentation.error.map(GeneralRawError::header)
            }
            _ => None,
        })
    }

    fn capture_lexical(
        response: &Value,
        context: &IngressReplyContext,
        path: &str,
        lexical_data: &LexicalJson,
    ) -> Result<Self, AuthError> {
        if path != "sys/wrapping/wrap" {
            return Err(bad("lexical response owner is outside wrapping endpoint"));
        }
        lexical_data.validate_wrapping_view(&response["data"])?;
        let request_id = context.request_id();
        let logical_projection = LogicalProjection::Ordinary;
        let mut projection =
            logical_envelope_for_projection(response, &request_id, &logical_projection)?;
        let bytes = encode_lexical_envelope(&projection, lexical_data, MAX_WRAPPED_RESPONSE_BYTES);
        crate::service::erase_json(&mut projection);
        let bytes = bytes?;
        let result = Self {
            kind: ReplyKind::GeneralJsonEnvelopeV1 {
                lexical_data: lexical_data.clone(),
            },
            logical_projection,
            media_type: "application/json".into(),
            byte_count: bytes.len(),
            digest: crate::ha_forward_completion::digest(&bytes),
            request_id,
            bytes: bytes.to_vec(),
        };
        result.validate(response)?;
        Ok(result)
    }
    pub(in crate::auth) fn is_general_reply(&self) -> bool {
        matches!(
            &self.kind,
            ReplyKind::GeneralJsonEnvelopeV1 { .. }
                | ReplyKind::GeneralSelectedJsonV1 { .. }
                | ReplyKind::GeneralRawHttpV1 { .. }
        )
    }

    /// Only the actual sealed PKI producer selects a dedicated raw HTTP reply.
    /// The ingress ID stays in encrypted custody; raw HTTP exposes no UUID.
    pub(super) fn capture_pki(
        transport: &crate::engines::PkiWrappedTransport,
        context: &IngressReplyContext,
        path: &str,
    ) -> Result<Self, AuthError> {
        let logical = transport.logical_response();
        let (status, media_type, nil_body, bytes) = pki_http_projection(logical)?;
        let result = Self {
            kind: ReplyKind::PkiRawHttpV1 { status, nil_body },
            logical_projection: LogicalProjection::for_path(path),
            media_type,
            byte_count: bytes.len(),
            digest: crate::ha_forward_completion::digest(&bytes),
            request_id: context.request_id(),
            bytes: bytes.to_vec(),
        };
        result.validate(logical)?;
        Ok(result)
    }
    /// This authenticated private discriminant, never a Data key, selects HTTP.
    pub(crate) fn raw_http_transport<'a>(
        &'a self,
        logical: &Value,
    ) -> Result<Option<(u16, &'a str)>, AuthError> {
        self.validate(logical)?;
        match self.kind {
            ReplyKind::JsonEnvelopeV1
            | ReplyKind::GeneralJsonEnvelopeV1 { .. }
            | ReplyKind::GeneralSelectedJsonV1 { .. } => Ok(None),
            ReplyKind::PkiRawHttpV1 { status, .. } => Ok(Some((status, &self.media_type))),
            ReplyKind::GeneralRawHttpV1 {
                ref presentation, ..
            } => {
                if presentation.connection_abort {
                    return Err(bad("raw status requires connection abort"));
                }
                Ok(Some((presentation.status, &self.media_type)))
            }
        }
    }
    pub(super) fn validate_owner(&self, logical: &Value, path: &str) -> Result<(), AuthError> {
        if self.logical_projection != LogicalProjection::for_path(path) {
            return Err(bad("stored logical projection owner differs"));
        }
        self.validate(logical)
    }
    pub(crate) fn validate(&self, logical: &Value) -> Result<(), AuthError> {
        if let ReplyKind::GeneralSelectedJsonV1 { lexical_data } = &self.kind {
            if selected_ordinary_data(logical, lexical_data.as_ref())?.is_none() {
                return Err(bad(
                    "stored selected JSON differs from original presentation",
                ));
            }
            if !valid_request_id(&self.request_id)
                || self.media_type != "application/json"
                || self.byte_count != self.bytes.len()
                || self.bytes.len() > MAX_WRAPPED_RESPONSE_BYTES
                || self.digest != crate::ha_forward_completion::digest(&self.bytes)
            {
                return Err(bad("stored selected JSON immutable metadata differs"));
            }
            let generated;
            let data = if let Some(data) = lexical_data {
                data.validate_wrapping_view(&logical["data"])?;
                data
            } else {
                generated = LexicalJson::from_backend(&logical["data"])?;
                &generated
            };
            let mut projection = logical_envelope_for_projection(
                logical,
                &self.request_id,
                &self.logical_projection,
            )?;
            let encoded = encode_lexical_envelope(&projection, data, MAX_WRAPPED_RESPONSE_BYTES);
            crate::service::erase_json(&mut projection);
            let encoded = encoded?;
            let decoded = LexicalJson::parse_listener(&self.bytes)?;
            let exact = matches!(&decoded, LexicalJson::Object(fields)
                if fields.len() == 8 && ENVELOPE_FIELDS.iter().all(|n| fields.contains_key(*n)));
            if !exact || encoded.as_slice() != self.bytes.as_slice() {
                return Err(bad("stored selected JSON original custody differs"));
            }
            return Ok(());
        }
        if let ReplyKind::GeneralRawHttpV1 {
            lexical_data,
            presentation,
        } = &self.kind
        {
            if !has_special_presentation(logical)
                || selected_ordinary_data(logical, lexical_data.as_ref())?.is_some()
            {
                return Err(bad(
                    "stored generic raw presentation has no actual special data",
                ));
            }
            let (actual, media_type, bytes) =
                general_raw_projection(logical, lexical_data.as_ref())?;
            if &actual != presentation
                || (lexical_data.is_some()
                    && self.logical_projection != LogicalProjection::Ordinary)
                || !valid_request_id(&self.request_id)
                || self.media_type != media_type
                || self.byte_count != self.bytes.len()
                || self.bytes.as_slice() != bytes.as_slice()
                || self.digest != crate::ha_forward_completion::digest(&self.bytes)
            {
                return Err(bad("stored generic raw projection differs"));
            }
            return Ok(());
        }

        if let ReplyKind::GeneralJsonEnvelopeV1 { lexical_data } = &self.kind {
            lexical_data.validate_wrapping_view(&logical["data"])?;
            if self.logical_projection != LogicalProjection::Ordinary
                || !valid_request_id(&self.request_id)
                || self.media_type != "application/json"
                || self.byte_count != self.bytes.len()
                || self.bytes.len() > MAX_WRAPPED_RESPONSE_BYTES
                || self.digest != crate::ha_forward_completion::digest(&self.bytes)
            {
                return Err(bad("stored general lexical metadata differs"));
            }
            let mut projection = logical_envelope_for_projection(
                logical,
                &self.request_id,
                &self.logical_projection,
            )?;
            let encoded =
                encode_lexical_envelope(&projection, lexical_data, MAX_WRAPPED_RESPONSE_BYTES);
            crate::service::erase_json(&mut projection);
            let encoded = encoded?;
            let decoded = LexicalJson::parse_listener(&self.bytes)?;
            let exact_fields = match &decoded {
                LexicalJson::Object(fields) => {
                    fields.len() == 8 && ENVELOPE_FIELDS.iter().all(|n| fields.contains_key(*n))
                }
                _ => false,
            };
            if !exact_fields || encoded.as_slice() != self.bytes.as_slice() {
                return Err(bad("stored general lexical projection differs"));
            }
            return Ok(());
        }

        if let ReplyKind::PkiRawHttpV1 { status, nil_body } = self.kind {
            let (actual_status, media_type, actual_nil, bytes) = pki_http_projection(logical)?;
            if self.logical_projection != LogicalProjection::Ordinary
                || !valid_request_id(&self.request_id)
                || status != actual_status
                || nil_body != actual_nil
                || self.media_type != media_type
                || self.byte_count != self.bytes.len()
                || self.bytes.as_slice() != bytes.as_slice()
                || self.digest != crate::ha_forward_completion::digest(&self.bytes)
            {
                return Err(bad("stored PKI raw HTTP projection differs"));
            }
            return Ok(());
        }
        if self.media_type != "application/json"
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_WRAPPED_RESPONSE_BYTES
            || self.byte_count != self.bytes.len()
            || self.digest != crate::ha_forward_completion::digest(&self.bytes)
            || !valid_request_id(&self.request_id)
        {
            return Err(bad("invalid stored wrapped reply representation"));
        }
        let mut decoded: Value = serde_json::from_slice(&self.bytes)
            .map_err(|_| bad("invalid stored wrapped reply JSON"))?;
        let mut projected = match logical_envelope_for_projection(
            logical,
            &self.request_id,
            &self.logical_projection,
        ) {
            Ok(projected) => projected,
            Err(error) => {
                crate::service::erase_json(&mut decoded);
                return Err(error);
            }
        };
        let exact_fields = decoded.as_object().is_some_and(|o| {
            o.len() == 8 && ENVELOPE_FIELDS.iter().all(|name| o.contains_key(*name))
        });
        // JSON numbers share a closed Go encoding; 1.0 marshals as 1. Compare
        // the complete canonical projection, never a permissive field subset.
        let canonical = encode_envelope(&projected);
        let decoded_canonical = encode_envelope(&decoded);
        let equal = exact_fields
            && canonical
                .as_ref()
                .is_ok_and(|b| b.as_slice() == self.bytes.as_slice())
            && decoded_canonical
                .as_ref()
                .is_ok_and(|b| b.as_slice() == self.bytes.as_slice());
        crate::service::erase_json(&mut decoded);
        crate::service::erase_json(&mut projected);
        if equal {
            Ok(())
        } else {
            Err(bad("stored wrapped reply projection differs"))
        }
    }
    pub(in crate::auth) fn is_pki_raw_http(&self) -> bool {
        matches!(self.kind, ReplyKind::PkiRawHttpV1 { .. })
    }
    pub(crate) fn bytes<'a>(&'a self, logical: &Value) -> Result<&'a [u8], AuthError> {
        self.validate(logical)?;
        Ok(&self.bytes)
    }
}

/// Same token owner remains after exact consumption. No SDK or user body mints it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "phase", rename_all = "kebab-case", deny_unknown_fields)]
pub(in crate::auth) enum RawReplyTokenCustody {
    Live { owner_digest: [u8; 32] },
    Consumed { owner_digest: [u8; 32] },
}
struct ImmutableTokenOwner<'a>(&'a Token);
impl Serialize for ImmutableTokenOwner<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let token = self.0;
        let mut owner = serializer.serialize_struct("OriginalWrappedReplyTokenOwnerV1", 24)?;
        owner.serialize_field("token_api_precision", &token.token_api_precision)?;
        owner.serialize_field("public_origin", &token.public_origin)?;
        owner.serialize_field("issue_stamp", &token.issue_stamp)?;
        owner.serialize_field("token_api_lease_ttl", &token.token_api_lease_ttl)?;
        owner.serialize_field("token_role", &token.token_role)?;
        owner.serialize_field("bound_cidrs", &token.bound_cidrs)?;
        owner.serialize_field("entity_id", &token.entity_id)?;
        owner.serialize_field("cubbyhole", &token.cubbyhole)?;
        owner.serialize_field("accessor", &token.accessor)?;
        owner.serialize_field("namespace", &token.namespace)?;
        owner.serialize_field("policies", &token.policies)?;
        owner.serialize_field("root", &token.root)?;
        owner.serialize_field("parent", &token.parent)?;
        owner.serialize_field("created_at", &token.created_at)?;
        owner.serialize_field("expires_at", &token.expires_at)?;
        owner.serialize_field("max_expires_at", &token.max_expires_at)?;
        owner.serialize_field("period", &token.period)?;
        owner.serialize_field("renewable", &token.renewable)?;
        owner.serialize_field("display_name", &token.display_name)?;
        owner.serialize_field("auth_mount", &token.auth_mount)?;
        owner.serialize_field("auth_origin_known", &token.auth_origin_known)?;
        owner.serialize_field("auth_cert_role", &token.auth_cert_role)?;
        owner.serialize_field("auth_cert_sha256", &token.auth_cert_sha256)?;
        owner.serialize_field("auth_provenance", &token.auth_provenance)?;
        owner.end()
    }
}
impl RawReplyTokenCustody {
    pub(super) fn live(token: &Token) -> Result<Self, AuthError> {
        Ok(Self::Live {
            owner_digest: Self::owner_digest(token)?,
        })
    }
    fn owner_digest(token: &Token) -> Result<[u8; 32], AuthError> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(&ImmutableTokenOwner(token))
                .map_err(|_| bad("stored reply token owner encoding rejected"))?,
        );
        Ok(crate::ha_forward_completion::digest(&bytes))
    }
    fn digest(&self) -> &[u8; 32] {
        match self {
            Self::Live { owner_digest } | Self::Consumed { owner_digest } => owner_digest,
        }
    }
    pub(in crate::auth) fn consume(&mut self) {
        *self = Self::Consumed {
            owner_digest: *self.digest(),
        };
    }
    fn validate(&self, token: &Token) -> Result<(), AuthError> {
        if *self.digest() != Self::owner_digest(token)? {
            return Err(bad("stored reply immutable token owner differs"));
        }
        match self {
            Self::Live { .. }
                if token.uses_remaining == Some(1)
                    && token
                        .wrapping
                        .as_ref()
                        .is_some_and(|w| w.stored_reply.is_some()) =>
            {
                Ok(())
            }
            Self::Consumed { .. }
                if token.uses_remaining == Some(0) && token.wrapping.is_none() =>
            {
                Ok(())
            }
            _ => Err(bad("stored reply token phase is not canonical")),
        }
    }
}

impl AuthState {
    pub(crate) fn has_raw_wrapped_reply_state(&self) -> bool {
        self.raw_wrapped_reply_floor.has_original()
            || self.tokens.values().any(|t| {
                t.raw_wrapped_reply_custody.is_some()
                    || t.wrapping
                        .as_ref()
                        .is_some_and(|w| w.stored_reply.is_some())
            })
    }
    pub(crate) fn has_pki_raw_http_reply_state(&self) -> bool {
        self.raw_wrapped_reply_floor.has_pki_http()
            || self.tokens.values().any(|token| {
                token
                    .wrapping
                    .as_ref()
                    .and_then(|wrapped| wrapped.stored_reply.as_ref())
                    .is_some_and(|stored| stored.is_pki_raw_http())
            })
    }
    pub(crate) fn has_general_wrapped_reply_state(&self) -> bool {
        self.raw_wrapped_reply_floor.has_general()
            || self.tokens.values().any(|token| {
                token
                    .wrapping
                    .as_ref()
                    .and_then(|owner| owner.stored_reply.as_ref())
                    .is_some_and(StoredWrappedReply::is_general_reply)
            })
    }
    pub(crate) fn validate_raw_wrapped_reply_state(&self) -> Result<(), AuthError> {
        for token in self.tokens.values() {
            // Token API admission forbids assigning this reserved policy. Both
            // historical and new wrapper producers end at None plus uses0.
            if token.wrapping.is_none()
                && token.policies.contains("response-wrapping")
                && (token.uses_remaining != Some(0)
                    || token.root
                    || token.parent.is_some()
                    || token.entity_id.is_some()
                    || token.renewable
                    || token.period != 0
                    || token.policies != BTreeSet::from(["response-wrapping".into()]))
            {
                return Err(bad("consumed wrapping token is not canonical"));
            }
            if let Some(custody) = &token.raw_wrapped_reply_custody {
                if !self.raw_wrapped_reply_floor.has_original() {
                    return Err(bad("stored reply token reader floor missing"));
                }
                custody.validate(token)?;
            }
            if let Some(stored) = token
                .wrapping
                .as_ref()
                .and_then(|w| w.stored_reply.as_ref())
            {
                if !self.raw_wrapped_reply_floor.has_original()
                    || token.raw_wrapped_reply_custody.is_none()
                {
                    return Err(bad("stored reply reader or token owner missing"));
                }
                let owner = token
                    .wrapping
                    .as_ref()
                    .ok_or_else(|| bad("stored reply owner missing"))?;
                if stored.is_pki_raw_http() && !self.raw_wrapped_reply_floor.has_pki_http() {
                    return Err(bad("PKI raw HTTP permanent reader floor missing"));
                }
                if stored.is_general_reply() && !self.raw_wrapped_reply_floor.has_general() {
                    return Err(bad("general reply permanent reader floor missing"));
                }
                stored.validate_owner(&owner.response, &owner.creation_path)?;
            }
        }
        Ok(())
    }
    pub(crate) fn validate_raw_wrapped_reply_successor(
        &self,
        previous: &Self,
    ) -> Result<(), AuthError> {
        self.validate_raw_wrapped_reply_state()?;
        if previous.raw_wrapped_reply_floor.has_general()
            && !self.raw_wrapped_reply_floor.has_general()
        {
            return Err(bad("general reply reader floor cannot retire"));
        }
        if previous.raw_wrapped_reply_floor.has_pki_http()
            && !self.raw_wrapped_reply_floor.has_pki_http()
        {
            return Err(bad("PKI raw HTTP reader floor cannot retire"));
        }
        if previous.raw_wrapped_reply_floor.has_original()
            && !self.raw_wrapped_reply_floor.has_original()
        {
            return Err(bad("stored reply reader floor cannot retire"));
        }
        for (id, old) in &previous.tokens {
            let Some(next) = self.tokens.get(id) else {
                continue;
            }; // Existing revoke can delete the token.
            if old.raw_wrapped_reply_custody.is_none() && next.raw_wrapped_reply_custody.is_some() {
                return Err(bad(
                    "retained historical token cannot promote original reply custody",
                ));
            }
            if let Some(origin) = &old.raw_wrapped_reply_custody {
                let next_origin = next
                    .raw_wrapped_reply_custody
                    .as_ref()
                    .ok_or_else(|| bad("retained original reply token owner is stripped"))?;
                if origin.digest() != next_origin.digest()
                    || matches!(origin, RawReplyTokenCustody::Consumed { .. })
                        && !matches!(next_origin, RawReplyTokenCustody::Consumed { .. })
                {
                    return Err(bad("retained original reply token owner cannot regress"));
                }
            }
            if let (Some(old), Some(next)) = (old.wrapping.as_ref(), next.wrapping.as_ref())
                && (old.stored_reply != next.stored_reply
                    || (old.stored_reply.is_some() && old.response != next.response))
            {
                return Err(bad("retained stored wrapped reply is immutable"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
impl AuthState {
    /// Deliberate attack built from a real historical producer/consume and a
    /// distinct newly issued private raw wrapper, never user Data flags.
    pub(crate) fn raw110_promote_historical_countercandidate(
        &self,
        historical_bearer: &str,
        raw_bearer: &str,
        consumed: bool,
    ) -> Result<Self, AuthError> {
        let mut next = self.clone();
        let source = self
            .tokens
            .get(&hash(raw_bearer))
            .ok_or_else(|| bad("private raw source"))?;
        let wrapping = source
            .wrapping
            .as_ref()
            .ok_or_else(|| bad("private raw wrapping"))?;
        if source.raw_wrapped_reply_custody.is_none() || wrapping.stored_reply.is_none() {
            return Err(bad("actual private raw source missing"));
        }
        let target = next
            .tokens
            .get_mut(&hash(historical_bearer))
            .ok_or_else(|| bad("historical target"))?;
        if target.raw_wrapped_reply_custody.is_some()
            || target.wrapping.is_some()
            || target.uses_remaining != Some(0)
        {
            return Err(bad("actual historical consume required"));
        }
        target.wrapping = Some(wrapping.clone());
        target.uses_remaining = Some(1);
        target.raw_wrapped_reply_custody = Some(RawReplyTokenCustody::live(target)?);
        if consumed {
            target.wrapping = None;
            target.uses_remaining = Some(0);
            target
                .raw_wrapped_reply_custody
                .as_mut()
                .ok_or_else(|| bad("custody"))?
                .consume();
        }
        Ok(next)
    }

    /// Hostile test-only candidate of an actual retained private token, no issuer.
    pub(crate) fn raw110_token_countercandidate(&self, case: usize) -> Result<Self, AuthError> {
        let mut next = self.clone();
        let token = next
            .tokens
            .values_mut()
            .find(|t| t.raw_wrapped_reply_custody.is_some())
            .ok_or_else(|| bad("actual raw token absent in countercontrol"))?;
        match case {
            0 => token.wrapping = None,
            1 => {
                token.wrapping = None;
                token.uses_remaining = Some(0);
            }
            2 => {
                token.wrapping = None;
                token
                    .raw_wrapped_reply_custody
                    .as_mut()
                    .ok_or_else(|| bad("custody"))?
                    .consume();
            }
            3 => token.raw_wrapped_reply_custody = None,
            4 => token.uses_remaining = Some(1),
            5 => token.raw_wrapped_reply_custody = None,
            6 => token.accessor.push('x'),
            7 => token.namespace = "other-owner".into(),
            8 => {
                token.policies.insert("root".into());
            }
            9 => token.expires_at = token.expires_at.and_then(|n| n.checked_add(1)),
            10 => token.root = true,
            11 => {
                token.accessor.push('x');
                let owner_digest = RawReplyTokenCustody::owner_digest(token)?;
                token.raw_wrapped_reply_custody =
                    Some(match token.raw_wrapped_reply_custody.as_ref() {
                        Some(RawReplyTokenCustody::Consumed { .. }) => {
                            RawReplyTokenCustody::Consumed { owner_digest }
                        }
                        _ => RawReplyTokenCustody::Live { owner_digest },
                    });
            }
            12 => {
                token.wrapping = None;
                token.raw_wrapped_reply_custody = None;
            }
            _ => return Err(bad("unknown raw token countercontrol")),
        }
        Ok(next)
    }
}

#[derive(Deserialize)]
struct RawAuthProbe {
    #[serde(default)]
    raw_wrapped_reply_floor: RawReplyReaderFloor,
    #[serde(default)]
    tokens: BTreeMap<String, RawTokenProbe>,
}
#[derive(Deserialize)]
struct RawTokenProbe {
    #[serde(default)]
    wrapping: Option<RawWrapperProbe>,
    #[serde(default)]
    raw_wrapped_reply_custody: Option<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
struct RawWrapperProbe {
    #[serde(default)]
    stored_reply: Option<serde::de::IgnoredAny>,
}
impl RawAuthProbe {
    fn requires_raw_floor(&self) -> bool {
        self.raw_wrapped_reply_floor.has_original()
            || self.tokens.values().any(|token| {
                token.raw_wrapped_reply_custody.is_some()
                    || token
                        .wrapping
                        .as_ref()
                        .is_some_and(|w| w.stored_reply.is_some())
            })
    }
    fn validate_schema(&self, schema: u32) -> Result<(), AuthError> {
        if schema < 113 && self.raw_wrapped_reply_floor.has_general() {
            return Err(bad("general reply incoming header is downgraded"));
        }
        if schema < 112 && self.raw_wrapped_reply_floor.has_pki_http() {
            return Err(bad("PKI raw HTTP incoming header is downgraded"));
        }
        if schema < 110 && self.requires_raw_floor() {
            Err(bad("original wrapped reply incoming header is downgraded"))
        } else {
            Ok(())
        }
    }
}
impl AuthState {
    pub(crate) fn predecode_raw_reply_owner(bytes: &[u8], schema: u32) -> Result<(), AuthError> {
        let probe: RawAuthProbe = serde_json::from_slice(bytes)
            .map_err(|_| bad("original wrapped reply incoming owner is malformed"))?;
        probe.validate_schema(schema)
    }
    pub(crate) fn predecode_raw_reply_state(bytes: &[u8]) -> Result<(), AuthError> {
        #[derive(Deserialize)]
        struct Probe {
            schema: u32,
            auth: RawAuthProbe,
        }
        let probe: Probe = serde_json::from_slice(bytes)
            .map_err(|_| bad("original wrapped reply incoming state is malformed"))?;
        probe.auth.validate_schema(probe.schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn wrapper_token(response: &AuthResponse) -> Result<String, Box<dyn std::error::Error>> {
        Ok(response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper bearer absent")?
            .to_owned())
    }
    fn issue(
        state: &mut AuthState,
        logical: &Value,
        attempt: [u8; 16],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let _ingress = IngressReplyScope::listener(&attempt);
        wrapper_token(&state.wrap_logical_response("", "sys/wrapping/wrap", 60, logical, 100)?)
    }
    #[test]
    fn raw110_original_ingress_order_five_escapes_and_one_consume() -> TestResult {
        let (mut state, root) = AuthState::bootstrap(100)?;
        let logical = json!({"data":{"value":"<>&\u{2028}\u{2029}"},"warnings":[]});
        let bearer = issue(&mut state, &logical, [0x12; 16])?;
        let owner = state.tokens[&hash(&bearer)]
            .wrapping
            .as_ref()
            .ok_or("wrapper")?;
        let stored = owner.stored_reply.as_ref().ok_or("stored reply")?;
        let expected_id = crate::crypto::uuid_from_bytes(&[0x12; 16]);
        assert!(stored.request_id == expected_id);
        assert!(stored.bytes.starts_with(format!("{{\"request_id\":\"{}\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,\"data\":", expected_id).as_bytes()));
        for escaped in [
            b"\\u003c".as_slice(),
            b"\\u003e",
            b"\\u0026",
            b"\\u2028",
            b"\\u2029",
        ] {
            assert!(stored.bytes.windows(escaped.len()).any(|w| w == escaped));
        }
        let original = stored.bytes.clone();
        let admin = state.authenticate(&root, 100)?;
        let _later = IngressReplyScope::listener(&[0x34; 16]);
        let response = state.wrapping_route(
            Some(&admin),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({"token":bearer}),
            100,
        )?;
        let actual = response
            .unwrapped_json
            .as_ref()
            .ok_or("unwrap origin")?
            .raw_bytes(&response.body)?
            .ok_or("raw bytes")?;
        assert!(actual == original);
        assert!(
            state
                .wrapping_route(
                    Some(&admin),
                    "",
                    "POST",
                    "sys/wrapping/unwrap",
                    &json!({"token":bearer}),
                    100
                )
                .is_err()
        );
        assert!(
            state.raw_wrapped_reply_floor.has_original()
                && state.validate_raw_wrapped_reply_state().is_ok()
        );
        Ok(())
    }
    #[test]
    fn raw110_rewrap_transfers_original_bytes_id_and_none_stays_none() -> TestResult {
        let (mut state, root) = AuthState::bootstrap(100)?;
        let logical = json!({"data":{"stable":"rewrap payload"}});
        let bearer = issue(&mut state, &logical, [0x11; 16])?;
        let original = state.tokens[&hash(&bearer)]
            .wrapping
            .as_ref()
            .ok_or("wrapper")?
            .stored_reply
            .clone();
        let historical =
            wrapper_token(&state.wrap_response("", "sys/wrapping/wrap", 60, &logical, 100)?)?;
        let admin = state.authenticate(&root, 100)?;
        let _later = IngressReplyScope::listener(&[0x22; 16]);
        for (old, expected) in [(bearer, original), (historical, None)] {
            let response = state.wrapping_route(
                Some(&admin),
                "",
                "POST",
                "sys/wrapping/rewrap",
                &json!({"token":old}),
                100,
            )?;
            let new = wrapper_token(&response)?;
            let actual = &state.tokens[&hash(&new)]
                .wrapping
                .as_ref()
                .ok_or("rewrapper")?
                .stored_reply;
            assert!(actual == &expected);
            assert!(state.tokens[&hash(&old)].wrapping.is_none());
        }
        Ok(())
    }
    #[test]
    fn raw110_retained_projection_and_original_bytes_are_immutable_even_with_new_digest()
    -> TestResult {
        let (mut state, _) = AuthState::bootstrap(100)?;
        let logical = json!({"data":{"stable":1},"warnings":[],"auth":{"client_token":"test-only","lease_duration":30}});
        let bearer = issue(&mut state, &logical, [0x33; 16])?;
        let id = hash(&bearer);
        for (field, value) in [
            ("data", json!({"stable":2})),
            ("warnings", json!(["changed"])),
            ("lease_id", json!("other")),
            ("lease_duration", json!(5)),
            ("renewable", json!(true)),
            ("auth", json!({"client_token":"other","lease_duration":30})),
        ] {
            let mut candidate = state.clone();
            let wrapped = candidate
                .tokens
                .get_mut(&id)
                .and_then(|t| t.wrapping.as_mut())
                .ok_or("wrapper")?;
            wrapped.response[field] = value;
            wrapped.stored_reply = Some(StoredWrappedReply::capture(
                &wrapped.response,
                &IngressReplyContext {
                    attempt_id: [0x33; 16],
                    lexical_body: None,
                },
                "sys/wrapping/wrap",
            )?);
            assert!(candidate.validate_raw_wrapped_reply_state().is_ok());
            assert!(
                candidate
                    .validate_raw_wrapped_reply_successor(&state)
                    .is_err()
            );
        }
        let mut stripped = state.clone();
        stripped
            .tokens
            .get_mut(&id)
            .and_then(|t| t.wrapping.as_mut())
            .ok_or("wrapper")?
            .stored_reply = None;
        assert!(
            stripped
                .validate_raw_wrapped_reply_successor(&state)
                .is_err()
        );
        let mut replaced = state.clone();
        let wrapped = replaced
            .tokens
            .get_mut(&id)
            .and_then(|t| t.wrapping.as_mut())
            .ok_or("wrapper")?;
        wrapped.stored_reply = Some(StoredWrappedReply::capture(
            &wrapped.response,
            &IngressReplyContext {
                attempt_id: [0x44; 16],
                lexical_body: None,
            },
            "sys/wrapping/wrap",
        )?);
        assert!(
            replaced
                .validate_raw_wrapped_reply_successor(&state)
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn raw110_incoming_owner_and_consumed_floor_reject_downgrade() -> TestResult {
        let (mut state, root) = AuthState::bootstrap(100)?;
        let bearer = issue(&mut state, &json!({"data":{"stable":true}}), [0x55; 16])?;
        let encoded = Zeroizing::new(serde_json::to_vec(&state)?);
        assert!(AuthState::predecode_raw_reply_owner(&encoded, 108).is_err());
        assert!(AuthState::predecode_raw_reply_owner(&encoded, 110).is_ok());
        let admin = state.authenticate(&root, 100)?;
        let _ = state.wrapping_route(
            Some(&admin),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({"token":bearer}),
            100,
        )?;
        assert!(state.has_raw_wrapped_reply_state() && !state.has_live_wrappers());
        let mut downgraded = state.clone();
        downgraded.raw_wrapped_reply_floor = RawReplyReaderFloor::Legacy(false);
        assert!(
            downgraded
                .validate_raw_wrapped_reply_successor(&state)
                .is_err()
        );
        let encoded = Zeroizing::new(serde_json::to_vec(&state)?);
        assert!(AuthState::predecode_raw_reply_owner(&encoded, 108).is_err());
        Ok(())
    }
    #[test]
    fn raw110_client_data_cannot_mint_request_id_auth_or_framing() -> TestResult {
        let logical = json!({"data":{"request_id":"forged","auth":{"client_token":"forged"},
            "stored_reply":{"kind":"future"},"__heptabao_pki_certificate":"forged"}});
        let stored = StoredWrappedReply::capture(
            &logical,
            &IngressReplyContext {
                attempt_id: [0x92; 16],
                lexical_body: None,
            },
            "sys/wrapping/wrap",
        )?;
        let mut decoded: Value = serde_json::from_slice(&stored.bytes)?;
        assert_eq!(
            decoded["request_id"],
            crate::crypto::uuid_from_bytes(&[0x92; 16])
        );
        assert!(decoded["auth"].is_null());
        assert!(decoded["wrap_info"].is_null());
        assert_eq!(decoded["data"], logical["data"]);
        crate::service::erase_json(&mut decoded);
        Ok(())
    }
    #[test]
    fn raw110_go_float_boundaries_preserve_complete_numeric_projection() -> TestResult {
        for (value, expected) in [
            (1.0, "1"),
            (-0.0, "-0"),
            (0.000001, "0.000001"),
            (0.0000001, "1e-7"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (-1e21, "-1e+21"),
        ] {
            let number = serde_json::Number::from_f64(value).ok_or("finite number")?;
            assert!(go_float(&number)? == expected);
            let logical = json!({"data":{"number":Value::Number(number)}});
            let stored = StoredWrappedReply::capture(
                &logical,
                &IngressReplyContext {
                    attempt_id: [0x88; 16],
                    lexical_body: None,
                },
                "sys/wrapping/wrap",
            )?;
            assert!(stored.validate(&logical).is_ok());
        }
        Ok(())
    }
    #[test]
    fn raw110_closed_route_projection_matches_native_http_and_rejects_wrong_owner() -> TestResult {
        for (path, logical, absent) in [
            (
                "auth/token/lookup-self",
                json!({"data":{"namespace":"internal","expire_time_unix":130,"creation_time":100,"identity_policies":[]}}),
                vec!["namespace", "expire_time_unix"],
            ),
            (
                "sys/mounts/secret/tune",
                json!({"data":{"revision":1,"incarnation":2,"accessor":"internal","default_lease_ttl":60}}),
                vec!["revision", "incarnation", "accessor"],
            ),
            (
                "sys/mounts",
                json!({"data":{"secret/":{"revision":1,"incarnation":2,"type":"kv"}}}),
                vec![],
            ),
        ] {
            let context = IngressReplyContext {
                attempt_id: [0x93; 16],
                lexical_body: None,
            };
            let stored = StoredWrappedReply::capture(&logical, &context, path)?;
            assert!(stored.validate_owner(&logical, path).is_ok());
            assert!(
                stored
                    .validate_owner(&logical, "sys/wrapping/wrap")
                    .is_err()
            );
            let mut decoded: Value = serde_json::from_slice(&stored.bytes)?;
            let mut native = logical_envelope(&logical, &context.request_id(), path)?;
            assert_eq!(decoded, native);
            for field in absent {
                assert!(decoded["data"].get(field).is_none());
            }
            if path == "sys/mounts" {
                assert!(decoded["data"]["secret/"].get("revision").is_none());
                assert!(decoded["data"]["secret/"].get("incarnation").is_none());
            }
            crate::service::erase_json(&mut decoded);
            crate::service::erase_json(&mut native);
        }
        // Equal user field names stay in an ordinary Data projection.
        let logical =
            json!({"data":{"namespace":"user","revision":1,"incarnation":2,"accessor":"user"}});
        let context = IngressReplyContext {
            attempt_id: [0x94; 16],
            lexical_body: None,
        };
        let stored = StoredWrappedReply::capture(&logical, &context, "sys/wrapping/wrap")?;
        let mut decoded: Value = serde_json::from_slice(&stored.bytes)?;
        assert_eq!(decoded["data"], logical["data"]);
        crate::service::erase_json(&mut decoded);
        Ok(())
    }

    #[test]
    fn raw110_same_token_requires_canonical_consume_and_preserves_terminal_owner() -> TestResult {
        let (mut live, root) = AuthState::bootstrap(100)?;
        let bearer = issue(
            &mut live,
            &json!({"data":{"stable":"terminal"}}),
            [0x95; 16],
        )?;
        for case in [0, 1, 2, 3, 6, 7, 8, 9, 10, 12] {
            let forged = live.raw110_token_countercandidate(case)?;
            assert!(forged.validate_raw_wrapped_reply_state().is_err());
            assert!(forged.validate_raw_wrapped_reply_successor(&live).is_err());
        }
        let forged = live.raw110_token_countercandidate(11)?;
        assert!(forged.validate_raw_wrapped_reply_state().is_ok());
        assert!(forged.validate_raw_wrapped_reply_successor(&live).is_err());
        let before = live.clone();
        let admin = live.authenticate(&root, 100)?;
        let _ = live.wrapping_route(
            Some(&admin),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({"token":bearer}),
            100,
        )?;
        let terminal = &live.tokens[&hash(&bearer)];
        assert!(terminal.wrapping.is_none() && terminal.uses_remaining == Some(0));
        assert!(matches!(
            terminal.raw_wrapped_reply_custody,
            Some(RawReplyTokenCustody::Consumed { .. })
        ));
        assert!(live.validate_raw_wrapped_reply_state().is_ok());
        assert!(live.validate_raw_wrapped_reply_successor(&before).is_ok());
        for case in [4, 6, 7, 8, 9, 10] {
            let forged = live.raw110_token_countercandidate(case)?;
            assert!(forged.validate_raw_wrapped_reply_state().is_err());
            assert!(forged.validate_raw_wrapped_reply_successor(&live).is_err());
        }
        // Historical None must stay readable, so full marker stripping needs the
        // actual protected predecessor; it cannot be inferred from a bare Value.
        for case in [5, 11] {
            let forged = live.raw110_token_countercandidate(case)?;
            assert!(forged.validate_raw_wrapped_reply_state().is_ok());
            assert!(forged.validate_raw_wrapped_reply_successor(&live).is_err());
        }
        assert!(before.validate_raw_wrapped_reply_state().is_ok());
        assert!(before.validate_raw_wrapped_reply_successor(&live).is_err());
        let mut expiry = before.clone();
        assert!(expiry.advance_wrapping_clock(160));
        assert!(expiry.validate_raw_wrapped_reply_state().is_ok());
        assert!(expiry.validate_raw_wrapped_reply_successor(&before).is_ok());
        let mut floor_stripped = live.clone();
        floor_stripped.raw_wrapped_reply_floor = RawReplyReaderFloor::Legacy(false);
        let bytes = Zeroizing::new(serde_json::to_vec(&floor_stripped)?);
        assert!(AuthState::predecode_raw_reply_owner(&bytes, 108).is_err());
        let mut deleted = live.clone();
        deleted.tokens.remove(&hash(&bearer));
        assert!(deleted.validate_raw_wrapped_reply_successor(&live).is_ok());
        assert!(deleted.raw_wrapped_reply_floor.has_original());
        Ok(())
    }

    #[test]
    fn raw110_actual_historical_consume_cannot_promote_retained_id_to_raw_live_or_consumed()
    -> TestResult {
        let (mut state, root) = AuthState::bootstrap(100)?;
        let historical = wrapper_token(&state.wrap_response(
            "",
            "sys/wrapping/wrap",
            60,
            &json!({"data":{"legacy":true}}),
            100,
        )?)?;
        let admin = state.authenticate(&root, 100)?;
        let _ = state.wrapping_route(
            Some(&admin),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({"token":historical}),
            100,
        )?;
        let old = state.clone();
        let target = &state.tokens[&hash(&historical)];
        assert!(
            target.wrapping.is_none()
                && target.uses_remaining == Some(0)
                && target.raw_wrapped_reply_custody.is_none()
        );
        let raw = issue(
            &mut state,
            &json!({"data":{"private_new":true}}),
            [0x96; 16],
        )?;
        assert!(state.validate_raw_wrapped_reply_state().is_ok());
        assert!(state.validate_raw_wrapped_reply_successor(&old).is_ok()); // Genuine new ID is admitted.
        for consumed in [false, true] {
            let candidate =
                state.raw110_promote_historical_countercandidate(&historical, &raw, consumed)?;
            assert!(candidate.validate_raw_wrapped_reply_state().is_ok());
            assert!(
                candidate
                    .validate_raw_wrapped_reply_successor(&state)
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn raw110_missing_extra_unknown_or_tampered_representation_rejects() -> TestResult {
        let logical = json!({"data":{"stable":true}});
        let stored = StoredWrappedReply::capture(
            &logical,
            &IngressReplyContext {
                attempt_id: [0x66; 16],
                lexical_body: None,
            },
            "sys/wrapping/wrap",
        )?;
        for mutate in 0..5 {
            let mut candidate = stored.clone();
            match mutate {
                0 => candidate.bytes.push(b' '),
                1 => candidate.digest = [9; 32],
                2 => candidate.media_type = "text/plain".into(),
                3 => candidate.byte_count += 1,
                _ => candidate.request_id = crate::crypto::uuid_from_bytes(&[0x77; 16]),
            }
            assert!(candidate.validate(&logical).is_err());
        }
        let mut unknown = serde_json::to_value(&stored)?;
        unknown["kind"] = json!("future-raw-body");
        assert!(serde_json::from_value::<StoredWrappedReply>(unknown).is_err());
        Ok(())
    }
    #[test]
    fn raw112_reader_marker_keeps_bool_bytes_and_rejects_unknown_or_numeric_claims() -> TestResult {
        assert_eq!(
            serde_json::to_vec(&RawReplyReaderFloor::Legacy(false))?,
            b"false"
        );
        assert_eq!(
            serde_json::to_vec(&RawReplyReaderFloor::Legacy(true))?,
            b"true"
        );
        let tagged = RawReplyReaderFloor::PkiHttp(PkiHttpReader::PkiRawHttpV1);
        assert_eq!(serde_json::to_vec(&tagged)?, b"\"pki-raw-http-v1\"");
        for value in [
            json!(null),
            json!(0),
            json!(112),
            json!({}),
            json!([]),
            json!("true"),
            json!("unknown"),
            json!({"pki-raw-http-v1":112}),
        ] {
            assert!(serde_json::from_value::<RawReplyReaderFloor>(value).is_err());
        }
        let mut floor = tagged;
        floor.observe(false, false);
        assert!(floor == tagged);
        Ok(())
    }

    #[test]
    fn raw113_private_listener_number_tree_rewrap_original_id_and_consumed_floor() -> TestResult {
        let (mut state, root) = AuthState::bootstrap(100)?;
        let admin = state.authenticate(&root, 100)?;
        let lexical = LexicalJson::parse_listener(
            br#"{"number":1.0,"large":1e309,"literal":"1.0","array":[-0.0],"named":{"$serde_json::private::Number":"1.0"}}"#
        )?;
        let mut logical = json!({"data":lexical.wrapping_view()?});
        let _ingress = IngressReplyScope::listener_wrapping(&[0x81; 16], Some(lexical));
        let first = wrapper_token(&state.wrap_logical_response(
            "",
            "sys/wrapping/wrap",
            60,
            &logical,
            100,
        )?)?;
        assert!(state.has_general_wrapped_reply_state() && !state.has_pki_raw_http_reply_state());
        let original = state.tokens[&hash(&first)]
            .wrapping
            .as_ref()
            .ok_or("wrapper")?
            .stored_reply
            .as_ref()
            .ok_or("private original")?
            .clone();
        assert_eq!(
            original.request_id,
            crate::crypto::uuid_from_bytes(&[0x81; 16])
        );
        for value in [
            b"\"number\":1.0".as_slice(),
            b"\"large\":1e309",
            b"\"literal\":\"1.0\"",
            b"\"array\":[-0.0]",
        ] {
            assert!(original.bytes.windows(value.len()).any(|w| w == value));
        }
        let before = state.clone();
        let encoded = Zeroizing::new(serde_json::to_vec(&state)?);
        assert!(AuthState::predecode_raw_reply_owner(&encoded, 112).is_err());
        assert!(AuthState::predecode_raw_reply_owner(&encoded, 113).is_ok());
        let _later = IngressReplyScope::listener(&[0x82; 16]);
        let second = wrapper_token(&state.wrapping_route(
            Some(&admin),
            "",
            "POST",
            "sys/wrapping/rewrap",
            &json!({"token":first}),
            100,
        )?)?;
        assert!(
            state
                .wrapping_route(
                    Some(&admin),
                    "",
                    "POST",
                    "sys/wrapping/unwrap",
                    &json!({"token":first}),
                    100
                )
                .is_err()
        );
        let transferred = state.tokens[&hash(&second)]
            .wrapping
            .as_ref()
            .ok_or("rewrap")?
            .stored_reply
            .as_ref()
            .ok_or("original")?;
        assert!(transferred == &original);
        let mut response = state.wrapping_route(
            Some(&admin),
            "",
            "POST",
            "sys/wrapping/unwrap",
            &json!({"token":second}),
            100,
        )?;
        assert_eq!(
            response
                .unwrapped_json
                .as_ref()
                .ok_or("origin")?
                .raw_bytes(&response.body)?
                .ok_or("original bytes")?,
            original.bytes.as_slice()
        );
        assert!(
            state
                .wrapping_route(
                    Some(&admin),
                    "",
                    "POST",
                    "sys/wrapping/unwrap",
                    &json!({"token":second}),
                    100
                )
                .is_err()
        );
        state.validate_raw_wrapped_reply_successor(&before)?;
        let retained = state.clone();
        state.tokens.remove(&hash(&second));
        state.validate_raw_wrapped_reply_successor(&retained)?;
        assert!(state.has_general_wrapped_reply_state() && !state.has_pki_raw_http_reply_state());
        let encoded = Zeroizing::new(serde_json::to_vec(&state)?);
        assert!(AuthState::predecode_raw_reply_owner(&encoded, 112).is_err());
        let reopened: AuthState = serde_json::from_slice(&encoded)?;
        reopened.validate_raw_wrapped_reply_state()?;
        assert!(reopened.has_general_wrapped_reply_state());
        for floor in [
            RawReplyReaderFloor::Legacy(false),
            RawReplyReaderFloor::Legacy(true),
            RawReplyReaderFloor::PkiHttp(PkiHttpReader::PkiRawHttpV1),
        ] {
            let mut lower = state.clone();
            lower.raw_wrapped_reply_floor = floor;
            assert!(lower.validate_raw_wrapped_reply_successor(&state).is_err());
        }
        for mutation in 0..4 {
            let mut altered = original.clone();
            match mutation {
                0 => altered.bytes.push(b' '),
                1 => altered.request_id = crate::crypto::uuid_from_bytes(&[0x83; 16]),
                2 => altered.media_type = "text/plain".into(),
                _ => {
                    if let ReplyKind::GeneralJsonEnvelopeV1 { lexical_data } = &mut altered.kind {
                        *lexical_data = LexicalJson::parse_listener(br#"{"number":"1.0"}"#)?;
                    }
                }
            }
            assert!(altered.validate(&logical).is_err());
        }
        crate::service::erase_json(&mut logical);
        crate::service::erase_json(&mut response.body);
        Ok(())
    }
    #[test]
    fn raw113_closed_general_tag_preserves_independent_pki_history_and_old_readers_refuse()
    -> TestResult {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Old112Floor {
            Bool(bool),
            Pki(PkiHttpReader),
        }
        let mut general = RawReplyReaderFloor::Legacy(false);
        general.observe(false, true);
        assert!(general.has_general() && !general.has_pki_http());
        let general_wire = serde_json::to_vec(&general)?;
        assert_eq!(general_wire, b"\"general-wrapped-reply-v1\"");
        assert!(serde_json::from_slice::<bool>(&general_wire).is_err());
        assert!(serde_json::from_slice::<Old112Floor>(&general_wire).is_err());
        let mut combined = RawReplyReaderFloor::PkiHttp(PkiHttpReader::PkiRawHttpV1);
        combined.observe(false, true);
        assert!(combined.has_general() && combined.has_pki_http());
        assert_eq!(
            serde_json::to_vec(&combined)?,
            b"\"pki-and-general-wrapped-reply-v1\""
        );
        combined.observe(false, false);
        assert!(combined.has_general() && combined.has_pki_http());
        general.observe(true, false);
        assert!(general == combined);
        assert!(serde_json::from_slice::<Old112Floor>(&serde_json::to_vec(&combined)?).is_err());
        // Read the old variants so the literal negative decoder has no dead fields.
        match serde_json::from_slice::<Old112Floor>(b"true")? {
            Old112Floor::Bool(true) => {}
            _ => return Err("old bool changed".into()),
        }
        match serde_json::from_slice::<Old112Floor>(b"\"pki-raw-http-v1\"")? {
            Old112Floor::Pki(PkiHttpReader::PkiRawHttpV1) => {}
            _ => return Err("old PKI changed".into()),
        }
        for value in [
            json!(113),
            json!({"general-wrapped-reply-v1":true}),
            json!("pki-or-general"),
            json!("general-v2"),
        ] {
            assert!(serde_json::from_value::<RawReplyReaderFloor>(value).is_err());
        }
        Ok(())
    }
    #[test]
    fn raw113_generic_special_data_protocol_is_separate_from_private_pki_and_legacy_json()
    -> TestResult {
        let _ingress = IngressReplyScope::listener(&[0x84; 16]);
        let context = current_ingress().ok_or("real private context")?;
        for (data, status, media, body, error) in [
            (
                json!({"http_status_code":200,"http_content_type":"application/octet-stream","http_raw_body":"MAMKAQE="}),
                200,
                "application/octet-stream",
                vec![0x30, 3, 10, 1, 1],
                None,
            ),
            (
                json!({"http_status_code":204,"http_raw_body":"not-used"}),
                204,
                "",
                vec![],
                None,
            ),
            (
                json!({"http_status_code":200,"http_content_type":"text/plain","http_raw_body":123}),
                200,
                "text/plain",
                vec![],
                None,
            ),
            (
                json!({"http_status_code":"200","http_content_type":"text/plain"}),
                500,
                "",
                vec![],
                Some("cannot decode status code"),
            ),
            (
                json!({"http_status_code":200,"http_raw_body":"hello!"}),
                500,
                "",
                vec![],
                Some("no content type given"),
            ),
            (
                json!({"http_status_code":200,"http_content_type":3}),
                500,
                "",
                vec![],
                Some("cannot decode content type"),
            ),
        ] {
            let mut logical = json!({"data":data});
            let stored = StoredWrappedReply::capture(&logical, &context, "sys/wrapping/wrap")?;
            assert!(stored.is_general_reply() && !stored.is_pki_raw_http());
            assert_eq!(stored.raw_http_transport(&logical)?, Some((status, media)));
            assert_eq!(stored.bytes(&logical)?, body.as_slice());
            assert_eq!(stored.raw_error_header(&logical)?, error);
            let (mut state, _root) = AuthState::bootstrap(100)?;
            state.wrap_logical_response("", "sys/wrapping/wrap", 60, &logical, 100)?;
            assert!(
                state.has_general_wrapped_reply_state() && !state.has_pki_raw_http_reply_state()
            );
            // An already stored JsonEnvelopeV1 never reclassifies by these keys.
            let request_id = context.request_id();
            let mut projected = logical_envelope(&logical, &request_id, "sys/wrapping/wrap")?;
            let bytes = encode_envelope(&projected)?;
            let legacy = StoredWrappedReply {
                kind: ReplyKind::JsonEnvelopeV1,
                logical_projection: LogicalProjection::Ordinary,
                media_type: "application/json".into(),
                byte_count: bytes.len(),
                digest: crate::ha_forward_completion::digest(&bytes),
                request_id,
                bytes: bytes.to_vec(),
            };
            assert!(legacy.raw_http_transport(&logical)?.is_none());
            legacy.validate(&logical)?;
            crate::service::erase_json(&mut projected);
            crate::service::erase_json(&mut logical);
        }
        Ok(())
    }
    #[test]
    fn raw113_selected_special_data_without_status_uses_actual_unwrap_ingress_and_preserves_original_custody()
    -> TestResult {
        let _ingress = IngressReplyScope::listener(&[0x85; 16]);
        let context = current_ingress().ok_or("actual private context")?;
        for (data, expected) in [
            (
                json!({"http_content_type":"text/plain","http_raw_body":"hello!","extra":"drop"}),
                json!({"http_content_type":"text/plain","http_raw_body":"hello!"}),
            ),
            (
                json!({"http_status_code":null,"http_content_type":"text/plain","http_raw_body":"YQ==","extra":1}),
                json!({"http_content_type":"text/plain","http_raw_body":"YQ=="}),
            ),
            (
                json!({"http_raw_body":"YQ==\n"}),
                json!({"http_raw_body":"YQ=="}),
            ),
            (
                json!({"http_raw_body":123}),
                json!({"http_raw_body_already_json_decoded":true}),
            ),
            (
                json!({"http_content_type":3}),
                json!({"http_content_type":3}),
            ),
        ] {
            let mut logical = json!({"data":data});
            let stored = StoredWrappedReply::capture(&logical, &context, "sys/wrapping/wrap")?;
            assert!(
                stored.uses_selected_json_ingress()
                    && stored.is_general_reply()
                    && !stored.is_pki_raw_http()
            );
            assert!(
                stored.raw_http_transport(&logical)?.is_none()
                    && stored.raw_error_header(&logical)?.is_none()
            );
            let original_id = stored.request_id.clone();
            let original = stored.bytes(&logical)?.to_vec();
            let prepared = stored
                .selected_response_for_audit(&logical)?
                .ok_or("actual mandatory audit projection")?;
            for current in [[0x86; 16], [0x87; 16]] {
                let wire = stored
                    .selected_json_for_ingress(&logical, &current, &prepared)?
                    .ok_or("selected ordinary HTTP")?;
                assert!(wire.ends_with(b"\n"));
                let public: Value = serde_json::from_slice(&wire)?;
                assert_eq!(
                    public["request_id"],
                    crate::crypto::uuid_from_bytes(&current)
                );
                assert_ne!(public["request_id"], original_id);
                assert_eq!(public["data"], expected);
                assert_eq!(public.as_object().ok_or("actual envelope")?.len(), 8);
                assert_eq!(stored.bytes(&logical)?, original.as_slice());
                assert_eq!(stored.request_id, original_id);
            }
            let mut changed = logical.clone();
            changed["data"]["http_status_code"] = json!(200);
            assert!(stored.validate(&changed).is_err());
            let mut altered = stored.clone();
            altered.request_id = crate::crypto::uuid_from_bytes(&[0x88; 16]);
            assert!(altered.validate(&logical).is_err());
            crate::service::erase_json(&mut changed);
            crate::service::erase_json(&mut logical);
        }
        Ok(())
    }
    #[test]
    fn raw113_selected_json_keeps_typed_numeric_lexical_data_separate_from_body_strings()
    -> TestResult {
        let lexical = LexicalJson::parse_listener(br#"{"http_content_type":1.0,"http_raw_body":"1.0","request_id":"client-cannot-mint","extra":1e309}"#)?;
        let context = IngressReplyContext {
            attempt_id: [0x89; 16],
            lexical_body: Some(lexical.clone()),
        };
        let mut logical = json!({"data":lexical.wrapping_view()?});
        let stored = StoredWrappedReply::capture(&logical, &context, "sys/wrapping/wrap")?;
        let prepared = stored
            .selected_response_for_audit(&logical)?
            .ok_or("typed mandatory audit projection")?;
        let wire = stored
            .selected_json_for_ingress(&logical, &[0x90; 16], &prepared)?
            .ok_or("typed selected public response")?;
        let text = std::str::from_utf8(&wire)?;
        assert!(
            text.contains("\"http_content_type\":1.0")
                && text.contains("\"http_raw_body\":\"1.0\"")
        );
        assert!(!text.contains("client-cannot-mint") && !text.contains("1e309"));
        assert!(stored.raw_http_transport(&logical)?.is_none());
        crate::service::erase_json(&mut logical);
        Ok(())
    }

    #[test]
    fn raw113_selected_audit_preserves_decoded_bytes_text_and_dropped_body_without_utf8_loss()
    -> TestResult {
        let cases = [
            (
                json!({"http_raw_body":"/wBh","extra":"drop","http_raw_body_already_json_decoded":true}),
                json!({"http_raw_body":"/wBh"}),
                1_u8,
                vec![0xff, 0, 0x61],
            ),
            (
                json!({"http_raw_body":"1.0","http_raw_body_already_json_decoded":true}),
                json!({"http_raw_body":"1.0"}),
                2,
                b"1.0".to_vec(),
            ),
            (
                json!({"http_raw_body":""}),
                json!({"http_raw_body":""}),
                1,
                vec![],
            ),
            (
                json!({"http_raw_body":{"body":"drop"}}),
                json!({"http_raw_body_already_json_decoded":true}),
                0,
                vec![],
            ),
            (
                json!({"http_raw_body":null,"http_content_type":"text/plain","http_raw_body_already_json_decoded":true}),
                json!({"http_content_type":"text/plain"}),
                0,
                vec![],
            ),
        ];
        for (data, expected_wire, kind, expected_raw) in cases {
            let mut logical = json!({"data":data});
            let selected =
                selected_response_projection(&logical, None)?.ok_or("actual selection")?;
            let mut view = selected.wire_data.wrapping_view()?;
            assert!(view == expected_wire, "closed selected wire projection");
            let (actual_kind, actual_raw): (u8, &[u8]) = match &selected.raw_body {
                None => (0, &[]),
                Some(SelectedAuditRawBody::DecodedBytes(bytes)) => (1, bytes),
                Some(SelectedAuditRawBody::Text(text)) => (2, text.as_bytes()),
            };
            assert!(actual_kind == kind && actual_raw == expected_raw.as_slice());
            let binding = selected.audit_binding()?;
            assert!(binding.ends_with(&expected_raw));
            crate::service::erase_json(&mut view);
            crate::service::erase_json(&mut logical);
        }
        Ok(())
    }

    #[test]
    fn raw113_selected_http_refuses_substituted_projection_after_mandatory_audit_selection()
    -> TestResult {
        let _ingress = IngressReplyScope::listener(&[0x94; 16]);
        let context = current_ingress().ok_or("actual private context")?;
        let mut logical = json!({"data":{"http_raw_body":"YQ==","extra":"drop"}});
        let stored = StoredWrappedReply::capture(&logical, &context, "sys/wrapping/wrap")?;
        let mut prepared = stored
            .selected_response_for_audit(&logical)?
            .ok_or("actual audit selection")?;
        assert!(
            stored
                .selected_json_for_ingress(&logical, &[0x95; 16], &prepared)?
                .is_some()
        );
        let original = Zeroizing::new(stored.bytes(&logical)?.to_vec());
        let LexicalJson::Object(fields) = &mut prepared.wire_data else {
            return Err("selected data".into());
        };
        fields.insert("http_raw_body".into(), LexicalJson::String("YmI=".into()));
        assert!(
            stored
                .selected_json_for_ingress(&logical, &[0x95; 16], &prepared)
                .is_err()
        );
        assert!(stored.bytes(&logical)? == original.as_slice());
        let mut prepared = stored
            .selected_response_for_audit(&logical)?
            .ok_or("fresh actual selection")?;
        prepared.raw_body = Some(SelectedAuditRawBody::Text(Zeroizing::new("a".into())));
        // The wire Data still matches, but replacing []byte with string must veto.
        assert!(
            stored
                .selected_json_for_ingress(&logical, &[0x95; 16], &prepared)
                .is_err()
        );
        assert!(stored.bytes(&logical)? == original.as_slice());
        crate::service::erase_json(&mut logical);
        Ok(())
    }
}
