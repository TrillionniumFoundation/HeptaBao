//! Request-local values preserve Go float64 outside the JSON representation.
//! No public JSON marker creates a private output owner or changes its authority.
use serde::ser::{SerializeMap, SerializeStruct};
use serde_json::Value as Json;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
enum Data {
    Json(Json),
    Float(f64),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}
#[derive(Clone)]
pub(crate) struct Value(Data);
impl Drop for Value {
    fn drop(&mut self) {
        match &mut self.0 {
            Data::Json(value) => crate::service::erase_json(value),
            Data::Float(value) => value.zeroize(),
            Data::Array(values) => values.clear(),
            Data::Object(values) => {
                for (mut key, value) in std::mem::take(values) {
                    key.zeroize();
                    drop(value);
                }
            }
        }
    }
}
impl Value {
    pub(crate) fn from_json(value: &Json) -> Self {
        match value {
            Json::Array(values) => Self::array(values.iter().map(Self::from_json).collect()),
            Json::Object(values) => {
                let mut result = Self::object();
                for (key, value) in values {
                    result.insert(key.clone(), Self::from_json(value));
                }
                result
            }
            _ => Self(Data::Json(value.clone())),
        }
    }
    pub(crate) fn from_response_json(value: &Json) -> Self {
        match value {
            // Provider JSON is already a typed, lossless boundary. Rounding
            // it to float64 here corrupts large integers and exact decimals
            // when a workflow forwards or exposes a response. Floats created
            // by evaluated expressions still use the explicit Float variant.
            Json::Number(_) => Self::from_json(value),
            Json::Array(values) => {
                Self::array(values.iter().map(Self::from_response_json).collect())
            }
            Json::Object(values) => {
                let mut result = Self::object();
                for (key, value) in values {
                    result.insert(key.clone(), Self::from_response_json(value));
                }
                result
            }
            _ => Self::from_json(value),
        }
    }
    pub(crate) fn float(value: f64) -> Self {
        Self(Data::Float(value))
    }
    pub(crate) fn string(value: String) -> Self {
        Self(Data::Json(Json::String(value)))
    }
    pub(crate) fn array(values: Vec<Self>) -> Self {
        Self(Data::Array(values))
    }
    pub(crate) fn object() -> Self {
        Self(Data::Object(BTreeMap::new()))
    }
    pub(crate) fn insert(&mut self, mut key: String, value: Self) {
        if let Data::Object(values) = &mut self.0 {
            if let Some(previous) = values.get_mut(&key) {
                *previous = value;
                key.zeroize();
            } else {
                values.insert(key, value);
            }
        } else {
            key.zeroize();
        }
    }
    pub(crate) fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        if let Data::Object(values) = &self.0 {
            Some(values)
        } else {
            None
        }
    }
    pub(crate) fn as_array(&self) -> Option<&[Self]> {
        if let Data::Array(values) = &self.0 {
            Some(values)
        } else {
            None
        }
    }
    pub(crate) fn as_str(&self) -> Option<&str> {
        if let Data::Json(value) = &self.0 {
            value.as_str()
        } else {
            None
        }
    }
    pub(crate) fn as_bool(&self) -> Option<bool> {
        if let Data::Json(value) = &self.0 {
            value.as_bool()
        } else {
            None
        }
    }
    pub(crate) fn json_scalar(&self) -> Option<&Json> {
        if let Data::Json(value) = &self.0 {
            Some(value)
        } else {
            None
        }
    }
    pub(crate) fn actual_float(&self) -> Option<f64> {
        if let Data::Float(value) = &self.0 {
            Some(*value)
        } else {
            None
        }
    }
    pub(crate) fn is_object(&self) -> bool {
        self.as_object().is_some()
    }
    pub(crate) fn is_boolean(&self) -> bool {
        self.as_bool().is_some()
    }
    pub(crate) fn is_string(&self) -> bool {
        self.as_str().is_some()
    }
    pub(crate) fn has_nonfinite(&self) -> bool {
        match &self.0 {
            Data::Float(value) => !value.is_finite(),
            Data::Array(values) => values.iter().any(Self::has_nonfinite),
            Data::Object(values) => values.values().any(Self::has_nonfinite),
            Data::Json(_) => false,
        }
    }
    // A JSON boundary is explicit. This never substitutes null for a float.
    pub(crate) fn to_json(&self) -> Result<Json, ()> {
        match &self.0 {
            Data::Json(value) => Ok(value.clone()),
            Data::Float(value) => {
                let mut wire =
                    Zeroizing::new(serde_json::Number::from_f64(*value).ok_or(())?.to_string());
                if wire.ends_with(".0") && !(*value == 0.0 && value.is_sign_negative()) {
                    let end = wire.len() - 2;
                    wire.truncate(end);
                }
                wire.parse::<serde_json::Number>()
                    .map(Json::Number)
                    .map_err(|_| ())
            }
            Data::Array(values) => {
                let mut result = Sensitive(Json::Array(Vec::new()));
                for value in values {
                    let converted = value.to_json()?;
                    if let Json::Array(values) = &mut result.0 {
                        values.push(converted);
                    }
                }
                Ok(std::mem::take(&mut result.0))
            }
            Data::Object(values) => {
                let mut result = Sensitive(Json::Object(serde_json::Map::new()));
                for (key, value) in values {
                    let converted = value.to_json()?;
                    if let Json::Object(values) = &mut result.0 {
                        values.insert(key.clone(), converted);
                    }
                }
                Ok(std::mem::take(&mut result.0))
            }
        }
    }
    pub(crate) fn within_bounds(&self) -> bool {
        fn walk(value: &Value, depth: usize, nodes: &mut usize, bytes: &mut usize) -> bool {
            if depth > 8 || *nodes >= 4096 {
                return false;
            }
            *nodes += 1;
            let size = match &value.0 {
                Data::Json(Json::String(value)) => value.len(),
                Data::Json(Json::Number(value)) => value.to_string().len(),
                Data::Json(_) => 8,
                Data::Float(_) => 16,
                Data::Array(values) => {
                    if values.len() > 4096 {
                        return false;
                    }
                    if !values
                        .iter()
                        .all(|value| walk(value, depth + 1, nodes, bytes))
                    {
                        return false;
                    }
                    2
                }
                Data::Object(values) => {
                    if values.len() > 4096 {
                        return false;
                    }
                    for (key, value) in values {
                        if key.len() > 32 * 1024 {
                            return false;
                        }
                        let Some(sum) = bytes.checked_add(key.len()) else {
                            return false;
                        };
                        *bytes = sum;
                        if *bytes > 64 * 1024 || !walk(value, depth + 1, nodes, bytes) {
                            return false;
                        }
                    }
                    2
                }
            };
            let Some(sum) = bytes.checked_add(size) else {
                return false;
            };
            *bytes = sum;
            *bytes <= 64 * 1024
        }
        walk(self, 0, &mut 0, &mut 0)
    }
    pub(crate) fn float_text(value: f64) -> String {
        if value.is_nan() {
            "NaN".into()
        } else if value == f64::INFINITY {
            "+Inf".into()
        } else if value == f64::NEG_INFINITY {
            "-Inf".into()
        } else {
            gotmpl::Value::Float(value).to_string()
        }
    }
    pub(crate) fn go_int(value: f64) -> i64 {
        // Observed amd64 Go int conversion; Rust's saturating cast differs.
        if !value.is_finite()
            || !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&value)
        {
            i64::MIN
        } else {
            value.trunc() as i64
        }
    }
    fn encoded(&self) -> Result<Zeroizing<Vec<u8>>, ()> {
        struct Bounded(Zeroizing<Vec<u8>>);
        impl std::io::Write for Bounded {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self
                    .0
                    .len()
                    .checked_add(bytes.len())
                    .is_none_or(|size| size > 256 * 1024)
                {
                    return Err(std::io::Error::other(
                        "private workflow value exceeds bound",
                    ));
                }
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut encoded = Bounded(Zeroizing::new(Vec::new()));
        serde_json::to_writer(&mut encoded, self).map_err(|_| ())?;
        Ok(encoded.0)
    }
}
struct Sensitive(Json);
impl Drop for Sensitive {
    fn drop(&mut self) {
        crate::service::erase_json(&mut self.0);
    }
}
// Private audit/hash transcript: float bits, never JSON NaN/null. It is not a
// request/provider/FieldData carrier and has no public Deserialize implementation.
impl serde::Serialize for Value {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PrivateWorkflowValue", 2)?;
        match &self.0 {
            Data::Json(value) => {
                state.serialize_field("kind", "json-scalar")?;
                state.serialize_field("value", value)?;
            }
            Data::Float(value) => {
                state.serialize_field("kind", "float64-bits")?;
                state.serialize_field("value", &value.to_bits())?;
            }
            Data::Array(value) => {
                state.serialize_field("kind", "array")?;
                state.serialize_field("value", value)?;
            }
            Data::Object(value) => {
                struct Map<'a>(&'a BTreeMap<String, Value>);
                impl serde::Serialize for Map<'_> {
                    fn serialize<S: serde::Serializer>(
                        &self,
                        serializer: S,
                    ) -> Result<S::Ok, S::Error> {
                        let mut map = serializer.serialize_map(Some(self.0.len()))?;
                        for (key, value) in self.0 {
                            map.serialize_entry(key, value)?;
                        }
                        map.end()
                    }
                }
                state.serialize_field("kind", "object")?;
                state.serialize_field("value", &Map(value))?;
            }
        }
        state.end()
    }
}
// The local producer owns the exact evaluated value after all workflow steps.
// Forwarding carries only its completion-MAC-bound digest, never new authority.
pub(crate) struct FailedOutput {
    value: Value,
    digest: [u8; 32],
    logical_digest: [u8; 32],
}
impl FailedOutput {
    pub(crate) fn capture(value: Value) -> Result<Self, ()> {
        if !value.is_object() || !value.within_bounds() || !value.has_nonfinite() {
            return Err(());
        }
        let encoded = value.encoded()?;
        let logical = Self::logical();
        let digest = crate::crypto::digest(&encoded);
        let logical_digest = crate::crypto::digest(&serde_json::to_vec(&logical).map_err(|_| ())?);
        Ok(Self {
            value,
            digest,
            logical_digest,
        })
    }
    // An internal finite projection for existing Response layout/audit custody.
    // It does not encode a NaN value and is never emitted as the public output.
    pub(crate) fn logical() -> Json {
        serde_json::json!({"data":{}})
    }
    pub(crate) fn value(&self) -> &Value {
        &self.value
    }
    pub(crate) fn audit_binding(&self) -> Result<Zeroizing<Vec<u8>>, ()> {
        self.value.encoded()
    }
    pub(crate) fn digests(&self) -> ([u8; 32], [u8; 32]) {
        (self.digest, self.logical_digest)
    }
    pub(crate) fn matches(&self, logical: &Json) -> bool {
        logical == &Self::logical()
            && serde_json::to_vec(logical)
                .is_ok_and(|bytes| crate::crypto::digest(&bytes) == self.logical_digest)
            && self.value.has_nonfinite()
    }
}

#[cfg(test)]
mod lossless_response_tests {
    use super::*;

    #[test]
    fn workflow_response_keeps_exact_json_numbers_and_public_marker_objects() {
        let original = heptabao_domain::json::decode(
            br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"nested":[{"big":184467440737095516160001}],"fake":{"$serde_json::private::Number":"7"}}"#
        ).expect("lossless source JSON");
        let carried = Value::from_response_json(&original);
        assert_eq!(carried.to_json().expect("response JSON"), original);
        assert!(carried.to_json().expect("response JSON")["fake"].is_object());

        // Runtime computations, unlike pass-through JSON, retain a distinct
        // float variant and must not turn NaN/Infinity into public null.
        assert_eq!(
            Value::float(1.5).to_json().expect("finite float"),
            Json::from(1.5)
        );
        assert!(Value::float(f64::NAN).to_json().is_err());
        assert!(Value::float(f64::INFINITY).to_json().is_err());
    }
}
