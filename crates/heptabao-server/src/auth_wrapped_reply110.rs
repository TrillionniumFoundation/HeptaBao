//! Private custody of the original admitted logical HTTP envelope (format110).
//! This carries response data only: no actor, provider authority or new clock.
use super::*;
use std::cell::RefCell;

#[derive(Clone)]
pub(crate) struct IngressReplyContext {
    attempt_id: [u8; 16],
}
thread_local! {
    static INGRESS: RefCell<Option<IngressReplyContext>> = const { RefCell::new(None) };
}
pub(crate) struct IngressReplyScope {
    previous: Option<IngressReplyContext>,
}
impl IngressReplyScope {
    /// Only the actual HTTP listener's already generated attempt enters here.
    pub(crate) fn listener(attempt_id: &[u8; 16]) -> Self {
        Self::restore(Some(IngressReplyContext {
            attempt_id: *attempt_id,
        }))
    }
    /// Called after the authenticated peer frame and direction are admitted.
    pub(crate) fn authenticated_forward(attempt_id: Option<[u8; 16]>) -> Self {
        Self::restore(attempt_id.map(|attempt_id| IngressReplyContext { attempt_id }))
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
    fn request_id(&self) -> String {
        crate::crypto::uuid_from_bytes(&self.attempt_id)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ReplyKind {
    JsonEnvelopeV1,
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
impl StoredWrappedReply {
    pub(super) fn capture(
        response: &Value,
        context: &IngressReplyContext,
        path: &str,
    ) -> Result<Self, AuthError> {
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
    pub(super) fn validate_owner(&self, logical: &Value, path: &str) -> Result<(), AuthError> {
        if self.logical_projection != LogicalProjection::for_path(path) {
            return Err(bad("stored logical projection owner differs"));
        }
        self.validate(logical)
    }
    pub(crate) fn validate(&self, logical: &Value) -> Result<(), AuthError> {
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
        self.raw_wrapped_reply_floor
            || self.tokens.values().any(|t| {
                t.raw_wrapped_reply_custody.is_some()
                    || t.wrapping
                        .as_ref()
                        .is_some_and(|w| w.stored_reply.is_some())
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
                if !self.raw_wrapped_reply_floor {
                    return Err(bad("stored reply token reader floor missing"));
                }
                custody.validate(token)?;
            }
            if let Some(stored) = token
                .wrapping
                .as_ref()
                .and_then(|w| w.stored_reply.as_ref())
            {
                if !self.raw_wrapped_reply_floor || token.raw_wrapped_reply_custody.is_none() {
                    return Err(bad("stored reply reader or token owner missing"));
                }
                let owner = token
                    .wrapping
                    .as_ref()
                    .ok_or_else(|| bad("stored reply owner missing"))?;
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
        if previous.raw_wrapped_reply_floor && !self.raw_wrapped_reply_floor {
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
            if let (Some(old), Some(next)) = (old.wrapping.as_ref(), next.wrapping.as_ref()) {
                if old.stored_reply != next.stored_reply
                    || (old.stored_reply.is_some() && old.response != next.response)
                {
                    return Err(bad("retained stored wrapped reply is immutable"));
                }
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
    raw_wrapped_reply_floor: bool,
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
        self.raw_wrapped_reply_floor
            || self.tokens.values().any(|token| {
                token.raw_wrapped_reply_custody.is_some()
                    || token
                        .wrapping
                        .as_ref()
                        .is_some_and(|w| w.stored_reply.is_some())
            })
    }
    fn validate_schema(&self, schema: u32) -> Result<(), AuthError> {
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
        assert!(state.raw_wrapped_reply_floor && state.validate_raw_wrapped_reply_state().is_ok());
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
        downgraded.raw_wrapped_reply_floor = false;
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
        floor_stripped.raw_wrapped_reply_floor = false;
        let bytes = Zeroizing::new(serde_json::to_vec(&floor_stripped)?);
        assert!(AuthState::predecode_raw_reply_owner(&bytes, 108).is_err());
        let mut deleted = live.clone();
        deleted.tokens.remove(&hash(&bearer));
        assert!(deleted.validate_raw_wrapped_reply_successor(&live).is_ok());
        assert!(deleted.raw_wrapped_reply_floor);
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
}
