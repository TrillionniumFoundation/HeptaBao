//! Request-local original JSON number spelling for PKI role fields. HTTP
//! always creates an outer carrier. Client JSON resembling it remains inner
//! data; workflow step Values do not receive transport provenance. HA carries
//! the same authenticated envelope. SecretJson/CarrierBody erase both copies.
use serde_json::{Map, Value, json, value::RawValue};
use std::collections::BTreeMap;

const MARKER: &str = "__heptabao_pki_role_number_fields";
const INVALID: &str = "invalid request-local PKI role number carrier";
const FIELDS: &[&str] = &[
    "allow_localhost",
    "require_cn",
    "enforce_hostnames",
    "cn_validations",
    "allow_glob_domains",
    "allowed_ip_sans_cidr",
    "allowed_uri_sans",
    "no_store",
    "allowed_serial_numbers",
    "allowed_user_ids",
    "allowed_other_sans",
    "policy_identifiers",
    "server_flag",
    "client_flag",
    "code_signing_flag",
    "email_protection_flag",
    "basic_constraints_valid_for_non_ca",
    "key_usage",
    "ext_key_usage",
    "ext_key_usage_oids",
    "country",
    "province",
    "locality",
    "street_address",
    "postal_code",
    "organization",
    "ou",
];

pub(crate) fn eligible(method: &str, path: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH")
        && !["auth/", "sys/", "identity/", "cubbyhole/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
        && path.rsplit_once("/roles/").is_some_and(|(mount, name)| {
            !mount.is_empty() && !name.is_empty() && !name.contains('/')
        })
}

pub(crate) fn transport_body(
    method: &str,
    path: &str,
    body: &mut Value,
    bytes: &[u8],
) -> Result<(), &'static str> {
    if !eligible(method, path) {
        return Ok(());
    }
    let raw: BTreeMap<String, &RawValue> = if bytes.is_empty() {
        BTreeMap::new()
    } else {
        serde_json::from_slice(bytes).map_err(|_| INVALID)?
    };
    let mut numbers = Map::new();
    for &field in FIELDS {
        if let (Some(raw), Some(value)) = (raw.get(field), body.get(field))
            && let Some(spelling) = capture(raw, value)?
        {
            numbers.insert(field.into(), spelling);
        }
    }
    *body = json!({MARKER:{"wire_method":method,"path":path,"original_body":std::mem::take(body),"number_fields":numbers}});
    Ok(())
}

fn capture(raw: &RawValue, value: &Value) -> Result<Option<Value>, &'static str> {
    let result = match value {
        Value::Number(_) => Some(Value::String(raw.get().into())),
        Value::Array(values) => {
            let raw: Vec<&RawValue> = serde_json::from_str(raw.get()).map_err(|_| INVALID)?;
            if raw.len() != values.len() {
                return Err(INVALID);
            }
            let mut any = false;
            let mut spellings = Vec::new();
            for (raw, value) in raw.iter().zip(values) {
                let captured = capture(raw, value)?;
                any |= captured.is_some();
                spellings.push(captured.unwrap_or(Value::Null));
            }
            any.then_some(Value::Array(spellings))
        }
        Value::Object(values) => {
            let raw: BTreeMap<String, &RawValue> =
                serde_json::from_str(raw.get()).map_err(|_| INVALID)?;
            if raw.len() != values.len() {
                return Err(INVALID);
            }
            let mut any = false;
            let mut spellings = Map::new();
            for (key, value) in values {
                let captured = capture(raw.get(key).ok_or(INVALID)?, value)?;
                any |= captured.is_some();
                spellings.insert(key.clone(), captured.unwrap_or(Value::Null));
            }
            any.then_some(Value::Object(spellings))
        }
        _ => None,
    };
    Ok(result)
}

fn has_number(value: &Value) -> bool {
    match value {
        Value::Number(_) => true,
        Value::Array(v) => v.iter().any(has_number),
        Value::Object(v) => v.values().any(has_number),
        _ => false,
    }
}

fn valid_mapping(value: &Value, spelling: &Value) -> bool {
    match (value, spelling) {
        (Value::Number(_), Value::String(spelling)) => {
            crate::auth::parse_strict_json(spelling.as_bytes())
                .is_ok_and(|parsed| parsed.is_number() && &parsed == value)
        }
        (Value::Array(values), Value::Array(spellings)) => {
            has_number(value)
                && values.len() == spellings.len()
                && values
                    .iter()
                    .zip(spellings)
                    .all(|(v, s)| valid_mapping(v, s))
        }
        (Value::Object(values), Value::Object(spellings)) => {
            has_number(value)
                && values.len() == spellings.len()
                && values
                    .iter()
                    .all(|(k, v)| spellings.get(k).is_some_and(|s| valid_mapping(v, s)))
        }
        (_, Value::Null) => !has_number(value),
        _ => false,
    }
}

pub(crate) struct Carrier<'a> {
    pub(crate) original: &'a Value,
    numbers: &'a Map<String, Value>,
}

pub(crate) fn request<'a>(
    method: &str,
    path: &str,
    body: &'a Value,
) -> Result<Option<Carrier<'a>>, &'static str> {
    if !eligible(method, path) || body.get(MARKER).is_none() {
        return Ok(None);
    }
    let outer = body.as_object().ok_or(INVALID)?;
    let carrier = body[MARKER].as_object().ok_or(INVALID)?;
    if outer.len() != 1
        || carrier.len() != 4
        || carrier.get("wire_method").and_then(Value::as_str) != Some(method)
        || carrier.get("path").and_then(Value::as_str) != Some(path)
    {
        return Err(INVALID);
    }
    let original = carrier
        .get("original_body")
        .filter(|v| v.is_object())
        .ok_or(INVALID)?;
    let numbers = carrier
        .get("number_fields")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    if numbers
        .keys()
        .any(|field| !FIELDS.contains(&field.as_str()))
    {
        return Err(INVALID);
    }
    for &field in FIELDS {
        match (original.get(field), numbers.get(field)) {
            (Some(value), Some(spelling)) if valid_mapping(value, spelling) => {}
            (Some(value), None) if !has_number(value) => {}
            (None, None) => {}
            _ => return Err(INVALID),
        }
    }
    Ok(Some(Carrier { original, numbers }))
}

fn apply(value: &mut Value, spelling: &Value) {
    match (value, spelling) {
        (value @ Value::Number(_), Value::String(_)) => *value = spelling.clone(),
        (Value::Array(values), Value::Array(spellings)) => {
            for (v, s) in values.iter_mut().zip(spellings) {
                apply(v, s);
            }
        }
        (Value::Object(values), Value::Object(spellings)) => {
            for (k, v) in values {
                if let Some(s) = spellings.get(k) {
                    apply(v, s);
                }
            }
        }
        _ => {}
    }
}

impl Carrier<'_> {
    pub(crate) fn number_fields(&self) -> &Map<String, Value> {
        self.numbers
    }
    // Called only after original body authorization and actual PKI mount check.
    pub(crate) fn backend_body(&self) -> super::ocsp::CarrierBody {
        let mut body = self.original.clone();
        for (field, spelling) in self.numbers {
            if let Some(value) = body.get_mut(field) {
                apply(value, spelling);
            }
        }
        super::ocsp::CarrierBody(body)
    }
}
