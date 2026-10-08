//! Closed, lossless JSON number representation for real admitted listener bodies.
//! A Number stores JSON numeric grammar, never a user JSON string or authority.
//! Private request custody must bind this complete tree to the actual ingress.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(crate) enum LexicalJson {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<LexicalJson>),
    Object(BTreeMap<String, LexicalJson>),
}
impl Drop for LexicalJson {
    fn drop(&mut self) {
        match self {
            Self::Number(text) | Self::String(text) => text.zeroize(),
            Self::Object(entries) => {
                for (mut key, value) in std::mem::take(entries) {
                    key.zeroize();
                    drop(value);
                }
            }
            _ => {}
        }
    }
}
impl LexicalJson {
    pub(crate) fn parse_listener(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() > 64 * 1024 {
            return Err(err(413, "listener JSON exceeds lexical bound"));
        }
        let mut parser = Parser { bytes, position: 0 };
        let value = parser.value(0)?;
        parser.whitespace();
        if parser.position != bytes.len() {
            return Err(bad("invalid lexical JSON"));
        }
        Ok(value)
    }

    /// This view belongs only to opaque sys/wrapping/wrap Data. An overflowing
    /// number retains its decimal bytes as a shadow string; the private typed
    /// tree is always the actual data source and audit binding. No other backend
    /// receives this view, and a JSON string has a different typed tree.
    pub(crate) fn wrapping_view(&self) -> Result<Value, AuthError> {
        self.validate()?;
        self.view_inner()
    }
    fn view_inner(&self) -> Result<Value, AuthError> {
        Ok(match self {
            Self::Null => Value::Null,
            Self::Bool(value) => Value::Bool(*value),
            Self::String(text) => Value::String(text.clone()),
            Self::Number(text) => serde_json::from_str::<serde_json::Number>(text)
                .map(Value::Number)
                .unwrap_or_else(|_| Value::String(text.clone())),
            Self::Array(values) => Value::Array(
                values
                    .iter()
                    .map(Self::view_inner)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), value.view_inner()?)))
                    .collect::<Result<serde_json::Map<_, _>, AuthError>>()?,
            ),
        })
    }
    pub(crate) fn validate_wrapping_view(&self, view: &Value) -> Result<(), AuthError> {
        let mut expected = self.wrapping_view()?;
        let equal = &expected == view;
        crate::service::erase_json(&mut expected);
        if equal {
            Ok(())
        } else {
            Err(bad("private lexical request view differs"))
        }
    }
    /// Transport query fields are already decoded by the actual listener.
    /// Existing body entries must remain exact; added fields use their server
    /// decoded Value type and cannot reinterpret a client string as a Number.
    pub(crate) fn bind_transport_fields(&mut self, body: &Value) -> Result<(), AuthError> {
        let Self::Object(original) = self else {
            return Err(bad("lexical wrapping object required"));
        };
        let fields = body
            .as_object()
            .ok_or_else(|| bad("wrapping body object required"))?;
        for (key, value) in original.iter() {
            let mut view = value.view_inner()?;
            let equal = fields.get(key) == Some(&view);
            crate::service::erase_json(&mut view);
            if !equal {
                return Err(bad("lexical body changed during transport admission"));
            }
        }
        for (key, value) in fields {
            if !original.contains_key(key) {
                original.insert(key.clone(), Self::from_backend(value)?);
            }
        }
        self.validate_wrapping_view(body)
    }
    pub(crate) fn from_backend(value: &Value) -> Result<Self, AuthError> {
        let mut encoded = Zeroizing::new(Vec::new());
        super::append_json(&mut encoded, value, 64 * 1024)?;
        Self::parse_listener(&encoded)
    }

    pub(crate) fn validate(&self) -> Result<(), AuthError> {
        let encoded = self.encode(64 * 1024)?;
        let parsed = Self::parse_listener(&encoded)?;
        if &parsed != self {
            return Err(bad("lexical JSON canonical tree differs"));
        }
        Ok(())
    }
    pub(crate) fn encode(&self, bound: usize) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        let mut output = Zeroizing::new(Vec::new());
        self.append(&mut output, bound, 0)?;
        Ok(output)
    }
    fn append(&self, output: &mut Vec<u8>, bound: usize, depth: usize) -> Result<(), AuthError> {
        if depth >= 128 {
            return Err(bad("lexical JSON nesting exceeds bound"));
        }
        match self {
            Self::Null => output.extend_from_slice(b"null"),
            Self::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
            Self::Number(text) => {
                let mut parser = Parser {
                    bytes: text.as_bytes(),
                    position: 0,
                };
                let mut parsed = parser.number()?;
                if parser.position != text.len() {
                    return Err(bad("invalid lexical number"));
                }
                parsed.zeroize();
                output.extend_from_slice(text.as_bytes());
            }
            Self::String(value) => append_string(output, value, bound)?,
            Self::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    value.append(output, bound, depth + 1)?;
                }
                output.push(b']');
            }
            Self::Object(values) => {
                output.push(b'{');
                for (index, (key, value)) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    append_string(output, key, bound)?;
                    output.push(b':');
                    value.append(output, bound, depth + 1)?;
                }
                output.push(b'}');
            }
        }
        if output.len() > bound {
            return Err(err(413, "lexical JSON exceeds encoded bound"));
        }
        Ok(())
    }
}
fn append_string(output: &mut Vec<u8>, value: &str, bound: usize) -> Result<(), AuthError> {
    let mut scalar = Value::String(value.to_owned());
    let result = super::append_json(output, &scalar, bound);
    crate::service::erase_json(&mut scalar);
    result
}
struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Parser<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.position += 1;
        }
    }
    fn take(&mut self, expected: u8) -> Result<(), AuthError> {
        self.whitespace();
        if self.bytes.get(self.position) != Some(&expected) {
            return Err(bad("invalid lexical JSON"));
        }
        self.position += 1;
        Ok(())
    }
    fn literal(&mut self, expected: &[u8]) -> Result<(), AuthError> {
        if self
            .bytes
            .get(self.position..self.position + expected.len())
            != Some(expected)
        {
            return Err(bad("invalid lexical JSON"));
        }
        self.position += expected.len();
        Ok(())
    }
    fn string(&mut self) -> Result<String, AuthError> {
        self.whitespace();
        let start = self.position;
        self.take(b'"')?;
        let mut escaped = false;
        while let Some(&byte) = self.bytes.get(self.position) {
            self.position += 1;
            if !escaped && byte == b'"' {
                return serde_json::from_slice::<String>(&self.bytes[start..self.position])
                    .map_err(|_| bad("invalid lexical JSON string"));
            }
            if !escaped && byte == b'\\' {
                escaped = true;
            } else {
                escaped = false;
            }
        }
        Err(bad("unterminated lexical JSON string"))
    }
    fn number(&mut self) -> Result<String, AuthError> {
        let start = self.position;
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        match self.bytes.get(self.position) {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.position += 1;
                while self
                    .bytes
                    .get(self.position)
                    .is_some_and(u8::is_ascii_digit)
                {
                    self.position += 1;
                }
            }
            _ => return Err(bad("invalid lexical JSON number")),
        }
        if self.bytes.get(self.position) == Some(&b'.') {
            self.position += 1;
            let digits = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == digits {
                return Err(bad("invalid lexical JSON fraction"));
            }
        }
        if self
            .bytes
            .get(self.position)
            .is_some_and(|b| matches!(b, b'e' | b'E'))
        {
            self.position += 1;
            if self
                .bytes
                .get(self.position)
                .is_some_and(|b| matches!(b, b'+' | b'-'))
            {
                self.position += 1;
            }
            let digits = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == digits {
                return Err(bad("invalid lexical JSON exponent"));
            }
        }
        std::str::from_utf8(&self.bytes[start..self.position])
            .map(str::to_owned)
            .map_err(|_| bad("invalid lexical JSON number bytes"))
    }
    fn value(&mut self, depth: usize) -> Result<LexicalJson, AuthError> {
        if depth >= 128 {
            return Err(bad("lexical JSON nesting exceeds bound"));
        }
        self.whitespace();
        match self.bytes.get(self.position) {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(LexicalJson::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(LexicalJson::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(LexicalJson::Bool(false))
            }
            Some(b'"') => Ok(LexicalJson::String(self.string()?)),
            Some(b'-' | b'0'..=b'9') => Ok(LexicalJson::Number(self.number()?)),
            Some(b'[') => {
                self.position += 1;
                self.whitespace();
                let mut values = Vec::new();
                if self.bytes.get(self.position) == Some(&b']') {
                    self.position += 1;
                    return Ok(LexicalJson::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    self.whitespace();
                    if self.bytes.get(self.position) == Some(&b']') {
                        self.position += 1;
                        break;
                    }
                    self.take(b',')?;
                }
                Ok(LexicalJson::Array(values))
            }
            Some(b'{') => {
                self.position += 1;
                self.whitespace();
                let mut result = LexicalJson::Object(BTreeMap::new());
                let LexicalJson::Object(values) = &mut result else {
                    return Err(bad("invalid lexical object"));
                };
                if self.bytes.get(self.position) == Some(&b'}') {
                    self.position += 1;
                    return Ok(result);
                }
                loop {
                    let mut key = Zeroizing::new(self.string()?);
                    self.take(b':')?;
                    let value = self.value(depth + 1)?;
                    // encoding/json v1 Decode into map[string]any processes
                    // members in input order. A duplicate replaces the whole
                    // prior value, preserving the final Number/String type.
                    if let Some(previous) = values.get_mut(key.as_str()) {
                        *previous = value;
                    } else {
                        values.insert(std::mem::take(&mut *key), value);
                    }
                    self.whitespace();
                    if self.bytes.get(self.position) == Some(&b'}') {
                        self.position += 1;
                        break;
                    }
                    self.take(b',')?;
                }
                Ok(result)
            }
            _ => Err(bad("invalid lexical JSON value")),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw113_actual_numeric_grammar_retains_literal_and_keeps_sdk_float_encoding_distinct() {
        for literal in [
            "1.0",
            "1E+0",
            "-0",
            "-0.0",
            "1e-7",
            "1e+21",
            "1e309",
            "18446744073709551616",
        ] {
            let value = LexicalJson::parse_listener(literal.as_bytes()).unwrap();
            assert!(matches!(&value, LexicalJson::Number(number) if number == literal));
            assert_eq!(value.encode(65536).unwrap().as_slice(), literal.as_bytes());
            value.validate().unwrap();
        }
        let typed_float = serde_json::Number::from_f64(1.0).unwrap();
        assert_eq!(super::super::go_float(&typed_float).unwrap(), "1");
        assert_eq!(
            LexicalJson::parse_listener(b"1.0")
                .unwrap()
                .encode(65536)
                .unwrap()
                .as_slice(),
            b"1.0"
        );
        assert!(matches!(
            LexicalJson::parse_listener(br#""1.0""#).unwrap(),
            LexicalJson::String(_)
        ));
    }
    #[test]
    fn raw113_actual_nested_numbers_do_not_confuse_string_or_private_number_named_object() {
        let source = br#"{"array":[1.0,"1.0"],"nested":{"number":1e309},"$serde_json::private::Number":"not-a-number"}"#;
        let parsed = LexicalJson::parse_listener(source).unwrap();
        let LexicalJson::Object(values) = &parsed else {
            panic!("actual object required")
        };
        assert!(
            matches!(values.get("$serde_json::private::Number"), Some(LexicalJson::String(value)) if value == "not-a-number")
        );
        let LexicalJson::Array(array) = &values["array"] else {
            panic!("actual array required")
        };
        assert!(matches!(&array[0], LexicalJson::Number(n) if n == "1.0"));
        assert!(matches!(&array[1], LexicalJson::String(n) if n == "1.0"));
        parsed.validate().unwrap();
    }
    #[test]
    fn raw113_actual_malformed_deep_and_forged_number_claims_are_rejected() {
        for invalid in [
            b"01".as_slice(),
            b"1.",
            b"+1",
            b"-",
            b"1e",
            b"1e+",
            b"NaN",
            b"1]null",
        ] {
            assert!(LexicalJson::parse_listener(invalid).is_err());
        }
        let deep = format!("{}0{}", "[".repeat(129), "]".repeat(129));
        assert!(LexicalJson::parse_listener(deep.as_bytes()).is_err());
        for claim in ["NaN", "1]null", "01", "1e+", "\"secret\""] {
            let forged = LexicalJson::Number(claim.to_owned());
            assert!(forged.encode(65536).is_err());
        }
    }

    #[test]
    fn raw113_actual_primary_duplicate_map_members_keep_last_typed_value_in_input_order()
    -> Result<(), AuthError> {
        for (input, expected) in [
            (br#"{"a":1,"a":2.0}"#.as_slice(), br#"{"a":2.0}"#.as_slice()),
            (br#"{"a":"discard","a":1.0}"#, br#"{"a":1.0}"#),
            (br#"{"a":1.0,"a":"1.0"}"#, br#"{"a":"1.0"}"#),
            (br#"{"a":1,"\u0061":-0.0}"#, br#"{"a":-0.0}"#),
            (
                br#"{"nest":{"a":1},"nest":{"b":2.0}}"#,
                br#"{"nest":{"b":2.0}}"#,
            ),
            (br#"{"nest":{"a":1,"a":2.0}}"#, br#"{"nest":{"a":2.0}}"#),
        ] {
            let actual = LexicalJson::parse_listener(input)?;
            let expected = LexicalJson::parse_listener(expected)?;
            assert!(actual == expected, "actual last member typed tree");
            actual.validate()?;
            assert!(actual.encode(65536)?.as_slice() == expected.encode(65536)?.as_slice());
        }
        Ok(())
    }
}
