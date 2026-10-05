//! Original JSON number spelling for the token backend's weak string fields.
//! The HTTP parser always wraps these routes, including requests without numbers;
//! client JSON resembling this marker consequently remains ordinary inner data.
use serde_json::{Map, Value, json, value::RawValue};
use std::collections::BTreeMap;
use zeroize::Zeroize;

const MARKER: &str = "__heptabao_token_number_fields";
const INVALID: &str = "invalid request-local token number carrier";
const CREATE_FIELDS: &[&str] = &[
    "policies",
    "no_default_policy",
    "no_parent",
    "renewable",
    "meta",
];
const ROLE_FIELDS: &[&str] = &[
    "orphan",
    "renewable",
    "token_no_default_policy",
    "token_num_uses",
    "token_period",
    "period",
    "token_explicit_max_ttl",
    "explicit_max_ttl",
    "allowed_policies",
    "disallowed_policies",
    "allowed_policies_glob",
    "disallowed_policies_glob",
    "allowed_entity_aliases",
    "token_bound_cidrs",
    "bound_cidrs",
    "path_suffix",
];

fn fields(path: &str) -> &'static [&'static str] {
    if path.starts_with("auth/token/roles/") {
        ROLE_FIELDS
    } else {
        CREATE_FIELDS
    }
}

fn array_field(field: &str) -> bool {
    matches!(
        field,
        "policies"
            | "allowed_policies"
            | "disallowed_policies"
            | "allowed_policies_glob"
            | "disallowed_policies_glob"
            | "allowed_entity_aliases"
            | "token_bound_cidrs"
            | "bound_cidrs"
    )
}

// Raw JSON object keys can themselves be private metadata. These temporary
// indexes retain only borrowed raw values and erase their owned key copies.
struct RawFields<'a>(BTreeMap<String, &'a RawValue>);
impl Drop for RawFields<'_> {
    fn drop(&mut self) {
        for (mut key, _) in std::mem::take(&mut self.0) {
            key.zeroize();
        }
    }
}

pub(crate) fn eligible(method: &str, path: &str) -> bool {
    matches!(method, "POST" | "PUT")
        && (matches!(path, "auth/token/create" | "auth/token/create-orphan")
            || path.starts_with("auth/token/create/")
            || path.starts_with("auth/token/roles/"))
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
    let raw = RawFields(if bytes.is_empty() {
        BTreeMap::new()
    } else {
        serde_json::from_slice(bytes).map_err(|_| INVALID)?
    });
    let mut numbers = super::ocsp::CarrierBody(Value::Object(Map::new()));
    for &field in fields(path) {
        if let Some(raw) = raw.0.get(field)
            && let Some(value) = body.get(field)
        {
            let spelling = if field == "meta" {
                capture_metadata(raw, value)?
            } else {
                capture(raw, value, array_field(field))?
            };
            if let Some(spelling) = spelling {
                numbers
                    .0
                    .as_object_mut()
                    .ok_or(INVALID)?
                    .insert(field.into(), spelling);
            }
        }
    }
    *body = json!({MARKER:{
        "wire_method":method,
        "path":path,
        "original_body":std::mem::take(body),
        "number_fields":std::mem::take(&mut numbers.0)
    }});
    Ok(())
}

// TypeKVPairs accepts recursively nested JSON slices/maps. Preserve a sparse
// numeric spelling tree, not a retyped copy of the original parameter ACL data.
// Intermediate carrier values use the same private erase-on-drop body owner.
fn capture_metadata(raw: &RawValue, value: &Value) -> Result<Option<Value>, &'static str> {
    match value {
        Value::Number(_) => Ok(Some(Value::String(raw.get().into()))),
        Value::Array(values) => {
            let raw: Vec<&RawValue> = serde_json::from_str(raw.get()).map_err(|_| INVALID)?;
            if raw.len() != values.len() {
                return Err(INVALID);
            }
            let mut sparse =
                super::ocsp::CarrierBody(Value::Array(Vec::with_capacity(values.len())));
            let mut present = false;
            for (raw, value) in raw.into_iter().zip(values) {
                let spelling = capture_metadata(raw, value)?;
                present |= spelling.is_some();
                sparse
                    .0
                    .as_array_mut()
                    .ok_or(INVALID)?
                    .push(spelling.unwrap_or(Value::Null));
            }
            Ok(present.then(|| std::mem::take(&mut sparse.0)))
        }
        Value::Object(values) => {
            let raw = RawFields(serde_json::from_str(raw.get()).map_err(|_| INVALID)?);
            if raw.0.len() != values.len() {
                return Err(INVALID);
            }
            let mut sparse = super::ocsp::CarrierBody(Value::Object(Map::new()));
            for (name, value) in values {
                if let Some(spelling) = capture_metadata(raw.0.get(name).ok_or(INVALID)?, value)? {
                    sparse
                        .0
                        .as_object_mut()
                        .ok_or(INVALID)?
                        .insert(name.clone(), spelling);
                }
            }
            Ok((!sparse.0.as_object().ok_or(INVALID)?.is_empty())
                .then(|| std::mem::take(&mut sparse.0)))
        }
        _ => Ok(None),
    }
}

fn capture(raw: &RawValue, value: &Value, array: bool) -> Result<Option<Value>, &'static str> {
    if value.is_number() {
        return Ok(Some(Value::String(raw.get().into())));
    }
    if array && let Some(values) = value.as_array() {
        let raw: Vec<&RawValue> = serde_json::from_str(raw.get()).map_err(|_| INVALID)?;
        if values.len() != raw.len() {
            return Err(INVALID);
        }
        if values.iter().any(Value::is_number) {
            return Ok(Some(Value::Array(
                raw.iter()
                    .zip(values)
                    .map(|(raw, value)| {
                        if value.is_number() {
                            Value::String(raw.get().into())
                        } else {
                            Value::Null
                        }
                    })
                    .collect(),
            )));
        }
    }
    Ok(None)
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
        .filter(|body| body.is_object())
        .ok_or(INVALID)?;
    let numbers = carrier
        .get("number_fields")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    if numbers
        .keys()
        .any(|field| !fields(path).contains(&field.as_str()))
    {
        return Err(INVALID);
    }
    for &field in fields(path) {
        let valid = if field == "meta" {
            match original.get(field) {
                Some(value) => valid_metadata_mapping(value, numbers.get(field)),
                None => !numbers.contains_key(field),
            }
        } else {
            valid_mapping(original.get(field), numbers.get(field), array_field(field))
        };
        if !valid {
            return Err(INVALID);
        }
    }
    Ok(Some(Carrier { original, numbers }))
}

fn valid_metadata_mapping(value: &Value, spelling: Option<&Value>) -> bool {
    match (value, spelling) {
        (Value::Number(_), Some(spelling)) => valid_number(value, spelling),
        (Value::Number(_), None) => false,
        (Value::Array(values), Some(Value::Array(spellings))) => {
            values.len() == spellings.len()
                && spellings.iter().any(|spelling| !spelling.is_null())
                && values.iter().zip(spellings).all(|(value, spelling)| {
                    valid_metadata_mapping(value, (!spelling.is_null()).then_some(spelling))
                })
        }
        (Value::Object(values), Some(Value::Object(spellings))) => {
            !spellings.is_empty()
                && spellings.keys().all(|name| values.contains_key(name))
                && values
                    .iter()
                    .all(|(name, value)| valid_metadata_mapping(value, spellings.get(name)))
        }
        (Value::Array(values), None) => values
            .iter()
            .all(|value| valid_metadata_mapping(value, None)),
        (Value::Object(values), None) => values
            .values()
            .all(|value| valid_metadata_mapping(value, None)),
        (_, None) => true,
        _ => false,
    }
}

fn restore_metadata_spelling(value: &mut Value, spelling: &Value) {
    match (value, spelling) {
        (value @ Value::Number(_), spelling) => *value = spelling.clone(),
        (Value::Array(values), Value::Array(spellings)) => {
            for (value, spelling) in values.iter_mut().zip(spellings) {
                if !spelling.is_null() {
                    restore_metadata_spelling(value, spelling);
                }
            }
        }
        (Value::Object(values), Value::Object(spellings)) => {
            for (name, spelling) in spellings {
                if let Some(value) = values.get_mut(name) {
                    restore_metadata_spelling(value, spelling);
                }
            }
        }
        _ => {}
    }
}

fn valid_number(value: &Value, spelling: &Value) -> bool {
    spelling.as_str().is_some_and(|spelling| {
        // Match the strict visitor used by ordinary HTTP parsing (including -0),
        // without enabling arbitrary-precision parsing at other owners or ACLs.
        crate::auth::parse_strict_json(spelling.as_bytes())
            .is_ok_and(|parsed| parsed.is_number() && &parsed == value)
    })
}

fn valid_mapping(value: Option<&Value>, spelling: Option<&Value>, array: bool) -> bool {
    match (value, spelling) {
        (Some(value), Some(spelling)) if value.is_number() => valid_number(value, spelling),
        (Some(Value::Array(values)), Some(Value::Array(spellings))) if array => {
            values.len() == spellings.len()
                && values.iter().any(Value::is_number)
                && values.iter().zip(spellings).all(|(value, spelling)| {
                    if value.is_number() {
                        valid_number(value, spelling)
                    } else {
                        spelling.is_null()
                    }
                })
        }
        (Some(value), None) if value.is_number() => false,
        (Some(Value::Array(values)), None) if array => !values.iter().any(Value::is_number),
        (_, None) => true,
        _ => false,
    }
}

impl Carrier<'_> {
    pub(crate) fn number_fields(&self) -> &Map<String, Value> {
        self.numbers
    }

    /// Called only after authorization of original numeric request parameters.
    pub(crate) fn backend_body(&self) -> super::ocsp::CarrierBody {
        let mut body = self.original.clone();
        for (field, spelling) in self.numbers {
            if field == "meta" {
                if let Some(value) = body.get_mut(field) {
                    restore_metadata_spelling(value, spelling);
                }
            } else if let Value::Array(spellings) = spelling {
                if let Some(Value::Array(values)) = body.get_mut(field) {
                    for (value, spelling) in values.iter_mut().zip(spellings) {
                        if value.is_number() {
                            *value = spelling.clone();
                        }
                    }
                }
            } else {
                body[field] = spelling.clone();
            }
        }
        super::ocsp::CarrierBody(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn token_metadata_weak_decode_recursive_numbers_require_original_numeric_binding() {
        let input = br#"{"meta":[[{"exp":1E+01,"negzero":-0}],null,{"wide":900719925474099312345,"decimal":1000000.0}]}"#;
        let mut body = crate::auth::parse_strict_json(input).unwrap_or(Value::Null);
        assert!(transport_body("POST", "auth/token/create", &mut body, input).is_ok());
        let carrier = request("POST", "auth/token/create", &body)
            .unwrap_or_else(|_| unreachable!())
            .unwrap_or_else(|| unreachable!());
        assert!(carrier.original["meta"][0][0]["exp"].is_number());
        assert_eq!(
            carrier.backend_body().0["meta"],
            json!([[{"exp":"1E+01","negzero":"-0"}],null,{"wide":"900719925474099312345","decimal":"1000000.0"}])
        );
        for (tree, value) in [
            ("number_fields", json!({})),
            (
                "number_fields",
                json!({"meta":[[{"exp":"10","negzero":"-0"}],null,{"wide":"1","decimal":"1000000.0"}]}),
            ),
            (
                "number_fields",
                json!({"meta":[[{"exp":"1E+01","negzero":"-0","extra":"1"}],null,{"wide":"900719925474099312345","decimal":"1000000.0"}]}),
            ),
            (
                "number_fields",
                json!({"meta":[[{"exp":"1E+01","negzero":"-0"}],"forged",{"wide":"900719925474099312345","decimal":"1000000.0"}]}),
            ),
            (
                "original_body",
                json!({"meta":[[{"exp":"1E+01","negzero":-0}],null,{"wide":900719925474099312345u128.to_string(),"decimal":1000000.0}]}),
            ),
        ] {
            let mut invalid = body.clone();
            invalid[MARKER][tree] = value;
            assert!(request("POST", "auth/token/create", &invalid).is_err());
        }
        assert!(request("PUT", "auth/token/create", &body).is_err());
        assert!(request("POST", "auth/token/create/other", &body).is_err());
        let mut ordinary = json!({"meta":{"anything":1},MARKER:{"client":"userdata"}});
        let original = ordinary.clone();
        assert!(transport_body("POST", "secret/ocsp", &mut ordinary, br#"{}"#).is_ok());
        assert_eq!(ordinary, original);
    }

    #[test]
    fn token_number_wire_spelling_survives_http_and_cannot_be_supplied_as_inner_marker() {
        for (raw, expected) in [
            ("1e0", "1e0"),
            ("1E+01", "1E+01"),
            ("1e+06", "1e+06"),
            ("-0", "-0"),
            ("1000000.0", "1000000.0"),
            ("9007199254740993", "9007199254740993"),
        ] {
            let input = format!("{{\"policies\":[{raw},true,null],\"no_default_policy\":{raw}}}");
            let wire = format!(
                "POST /v1/auth/token/create HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{input}",
                input.len()
            );
            let parsed = super::super::read_request(&mut wire.as_bytes(), Duration::from_secs(1));
            assert!(parsed.is_ok());
            let parsed = parsed.unwrap_or_else(|_| unreachable!());
            let carrier = request("POST", "auth/token/create", &parsed.body.0)
                .unwrap_or_else(|_| unreachable!())
                .unwrap_or_else(|| unreachable!());
            assert!(carrier.original["policies"][0].is_number());
            let backend = carrier.backend_body();
            assert_eq!(backend.0["policies"][0], expected);
            assert_eq!(backend.0["policies"][1], true);
            assert!(backend.0["policies"][2].is_null());
            assert_eq!(backend.0["no_default_policy"], expected);
        }
        let input = json!({MARKER:{"wire_method":"POST","path":"auth/token/create",
            "original_body":{"policies":"root"},"number_fields":{}}})
        .to_string();
        let wire = format!(
            "POST /v1/auth/token/create HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{input}",
            input.len()
        );
        let parsed = super::super::read_request(&mut wire.as_bytes(), Duration::from_secs(1))
            .unwrap_or_else(|_| unreachable!());
        let carrier = request("POST", "auth/token/create", &parsed.body.0)
            .unwrap_or_else(|_| unreachable!())
            .unwrap_or_else(|| unreachable!());
        assert_eq!(
            carrier.original,
            &serde_json::from_str::<Value>(&input).unwrap_or(Value::Null)
        );
        assert!(carrier.number_fields().is_empty());
    }

    #[test]
    fn token_number_carrier_requires_exact_path_method_and_numeric_body_binding() {
        let mut body =
            crate::auth::parse_strict_json(br#"{"policies":[1e0]}"#).unwrap_or(Value::Null);
        assert!(
            transport_body(
                "POST",
                "auth/token/create",
                &mut body,
                br#"{"policies":[1e0]}"#
            )
            .is_ok()
        );
        assert!(request("PUT", "auth/token/create", &body).is_err());
        assert!(request("POST", "auth/token/create/other", &body).is_err());
        for (field, value) in [
            ("number_fields", json!({})),
            ("number_fields", json!({"policies":["2"]})),
            ("number_fields", json!({"policies":["true"]})),
            ("original_body", json!({"policies":["1e0"]})),
        ] {
            let mut invalid = body.clone();
            invalid[MARKER][field] = value;
            assert!(request("POST", "auth/token/create", &invalid).is_err());
        }
        assert!(crate::auth::parse_strict_json(br#"{"other":1e9999}"#).is_err());
    }
}
