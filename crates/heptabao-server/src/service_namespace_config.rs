//! Namespace Shamir configuration at the logical backend boundary. The pinned
//! Go backend weak-decodes its outer string, parses HCL 1/JSON and then parses
//! signed integer counts. This bounded parser covers scalar HCL assignments and
//! JSON block maps/arrays; HCL expressions/heredocs and encrypted PGP delivery
//! remain separate, unqualified contracts.
use super::*;
use base64::engine::general_purpose::STANDARD;

pub(super) struct Config {
    pub(super) shares: u8,
    pub(super) threshold: u8,
}

pub(super) fn weak_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some(String::new()),
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn invalid() -> Response {
    Response::error(500, "unable to parse seal config")
}

pub(super) fn parse(body: &Value) -> Result<Option<Config>, Response> {
    let Some(raw) = body.get("seal") else {
        return Ok(None);
    };
    let text = weak_string(raw)
        .ok_or_else(|| Response::error(400, "seal must be a HCL or JSON string"))?;
    if text.len() > 64 * 1024 {
        return Err(invalid());
    }
    let blocks = if text.trim_start().starts_with('{') {
        json_blocks(&serde_json::from_str::<JsonConfig>(&text).map_err(|_| invalid())?)?
    } else {
        Parser::new(&text)?.blocks()?
    };
    if blocks.len() != 1 {
        return Err(Response::error(
            500,
            "seal config must contain exactly one seal stanza",
        ));
    }
    let (kind, fields) = &blocks[0];
    if !kind.eq_ignore_ascii_case("shamir") {
        return Err(Response::error(
            500,
            "namespaces currently only support shamir seals",
        ));
    }
    // ParseKMSes converts all non-special config values to strings, including
    // unused fields. A composite value is therefore an error before validation.
    for (field, value) in fields {
        if !matches!(field.as_str(), "purpose") && weak_string(value).is_none() {
            return Err(invalid());
        }
    }
    let count = |name: &str| -> Result<i64, Response> {
        fields.get(name).map_or(Ok(0), |value| {
            weak_string(value)
                .ok_or_else(invalid)?
                .parse::<i64>()
                .map_err(|_| Response::error(500, "seal count parameter must be integer"))
        })
    };
    let shares = count("shares")?;
    let threshold = count("threshold")?;
    if !(1..=255).contains(&shares) || !(1..=shares).contains(&threshold) {
        return Err(Response::error(
            400,
            "invalid seal config: share counts outside bounds",
        ));
    }
    if shares > 1 && threshold == 1 {
        return Err(Response::error(
            400,
            "invalid seal config: threshold must be greater than one for multiple shares",
        ));
    }
    if let Some(pgp) = body.get("pgp_keys") {
        let keys = match pgp {
            Value::Null => Vec::new(),
            Value::Array(keys) => keys
                .iter()
                .map(|key| weak_string(key).ok_or_else(invalid))
                .collect::<Result<Vec<_>, _>>()?,
            other => vec![weak_string(other).ok_or_else(invalid)?],
        };
        if !keys.is_empty() {
            if keys.len() != shares as usize {
                return Err(Response::error(
                    400,
                    "invalid seal config: PGP key count must match shares",
                ));
            }
            for key in keys {
                let bytes = STANDARD.decode(key).map_err(|_| {
                    Response::error(400, "invalid seal config: PGP key is not base64")
                })?;
                if bytes.is_empty() {
                    return Err(Response::error(
                        400,
                        "invalid seal config: PGP key is empty",
                    ));
                }
            }
            return Err(Response::error(
                501,
                "namespace PGP share encryption is not implemented",
            ));
        }
    }
    Ok(Some(Config {
        shares: u8::try_from(shares).map_err(|_| invalid())?,
        threshold: u8::try_from(threshold).map_err(|_| invalid())?,
    }))
}

type Fields = serde_json::Map<String, Value>;
type Blocks = Vec<(String, Fields)>;

// HCL 1 preserves repeated JSON block names as separate stanzas, while KMS
// config assignments within one stanza use the last value. A Value map alone
// would silently erase duplicate top-level seal blocks before this boundary.
enum JsonConfig {
    Object(Vec<(String, Self)>),
    Array(Vec<Self>),
    Scalar(Value),
}
impl JsonConfig {
    fn object(&self) -> Result<&[(String, Self)], Response> {
        match self {
            Self::Object(fields) => Ok(fields),
            _ => Err(invalid()),
        }
    }
    fn values(&self) -> Vec<&Self> {
        match self {
            Self::Array(values) => values.iter().collect(),
            other => vec![other],
        }
    }
    fn value(&self) -> Value {
        match self {
            Self::Scalar(value) => value.clone(),
            Self::Array(values) => Value::Array(values.iter().map(Self::value).collect()),
            Self::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), value.value()))
                    .collect(),
            ),
        }
    }
}
impl<'de> Deserialize<'de> for JsonConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JsonConfig;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("namespace JSON seal configuration")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut fields = Vec::new();
                while let Some(field) = map.next_entry()? {
                    if fields.len() >= 4096 {
                        return Err(serde::de::Error::custom("configuration exceeds bounds"));
                    }
                    fields.push(field);
                }
                Ok(JsonConfig::Object(fields))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    if values.len() >= 4096 {
                        return Err(serde::de::Error::custom("configuration exceeds bounds"));
                    }
                    values.push(value);
                }
                Ok(JsonConfig::Array(values))
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(JsonConfig::Scalar(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(JsonConfig::Scalar(Value::Number(value.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(JsonConfig::Scalar(Value::Number(value.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|value| JsonConfig::Scalar(Value::Number(value)))
                    .ok_or_else(|| serde::de::Error::custom("invalid configuration number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(JsonConfig::Scalar(Value::String(value.into())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(JsonConfig::Scalar(Value::String(value)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(JsonConfig::Scalar(Value::Null))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn json_blocks(root: &JsonConfig) -> Result<Blocks, Response> {
    let object = root.object()?;
    let mut blocks = Vec::new();
    for (name, value) in object {
        if matches!(name.as_str(), "seal" | "kms") {
            for value in value.values() {
                for (kind, fields) in value.object()? {
                    for fields in fields.values() {
                        if blocks.len() >= 4 {
                            return Err(invalid());
                        }
                        let fields = fields
                            .object()?
                            .iter()
                            .map(|(name, value)| (name.clone(), value.value()))
                            .collect();
                        blocks.push((kind.clone(), fields));
                    }
                }
            }
        }
    }
    Ok(blocks)
}

#[derive(Clone)]
enum Token {
    Text(String),
    Scalar(Value),
    Symbol(char),
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn new(text: &str) -> Result<Self, Response> {
        let bytes = text.as_bytes();
        let mut position = 0;
        let mut tokens = Vec::new();
        while position < bytes.len() {
            if tokens.len() >= 4096 {
                return Err(invalid());
            }
            let byte = bytes[position];
            if byte.is_ascii_whitespace() {
                position += 1;
                continue;
            }
            if byte == b'#' || bytes[position..].starts_with(b"//") {
                while position < bytes.len() && bytes[position] != b'\n' {
                    position += 1;
                }
                continue;
            }
            if bytes[position..].starts_with(b"/*") {
                let end = text[position + 2..].find("*/").ok_or_else(invalid)?;
                position += end + 4;
                continue;
            }
            if b"{}[]=,:".contains(&byte) {
                tokens.push(Token::Symbol(char::from(byte)));
                position += 1;
                continue;
            }
            if byte == b'"' {
                let start = position;
                position += 1;
                let mut closed = false;
                while position < bytes.len() {
                    match bytes[position] {
                        b'\\' => {
                            position = position.checked_add(2).ok_or_else(invalid)?;
                        }
                        b'"' => {
                            position += 1;
                            closed = true;
                            break;
                        }
                        _ => position += 1,
                    }
                }
                if !closed || position > bytes.len() {
                    return Err(invalid());
                }
                tokens.push(Token::Text(
                    serde_json::from_str(&text[start..position]).map_err(|_| invalid())?,
                ));
                continue;
            }
            let start = position;
            while position < bytes.len()
                && !bytes[position].is_ascii_whitespace()
                && !b"{}[]=,:\"#".contains(&bytes[position])
            {
                position += 1;
            }
            if position == start {
                return Err(invalid());
            }
            let word = &text[start..position];
            if let Ok(value @ (Value::Bool(_) | Value::Number(_) | Value::Null)) =
                serde_json::from_str::<Value>(word)
            {
                tokens.push(Token::Scalar(value));
            } else {
                tokens.push(Token::Text(word.to_owned()));
            }
        }
        Ok(Self {
            tokens,
            position: 0,
        })
    }
    fn take(&mut self) -> Result<Token, Response> {
        let token = self
            .tokens
            .get(self.position)
            .cloned()
            .ok_or_else(invalid)?;
        self.position += 1;
        Ok(token)
    }
    fn symbol(&mut self, expected: char) -> bool {
        if matches!(self.tokens.get(self.position), Some(Token::Symbol(actual)) if *actual == expected)
        {
            self.position += 1;
            true
        } else {
            false
        }
    }
    fn text(&mut self) -> Result<String, Response> {
        match self.take()? {
            Token::Text(value) => Ok(value),
            _ => Err(invalid()),
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, Response> {
        if depth > 16 {
            return Err(invalid());
        }
        if self.symbol('{') {
            return self.fields(depth + 1).map(Value::Object);
        }
        if self.symbol('[') {
            let mut values = Vec::new();
            while !self.symbol(']') {
                values.push(self.value(depth + 1)?);
                self.symbol(',');
            }
            return Ok(Value::Array(values));
        }
        match self.take()? {
            Token::Text(value) => Ok(Value::String(value)),
            Token::Scalar(value) => Ok(value),
            _ => Err(invalid()),
        }
    }
    fn fields(&mut self, depth: usize) -> Result<Fields, Response> {
        let mut fields = Fields::new();
        while !self.symbol('}') {
            let name = self.text()?;
            if !self.symbol('=') && !self.symbol(':') {
                return Err(invalid());
            }
            let value = self.value(depth)?;
            fields.insert(name, value);
            self.symbol(',');
        }
        Ok(fields)
    }
    fn blocks(&mut self) -> Result<Blocks, Response> {
        let mut blocks = Vec::new();
        while self.position < self.tokens.len() {
            let name = self.text()?;
            if self.symbol('=') {
                self.value(0)?;
                continue;
            }
            let kind = self.text()?;
            if !self.symbol('{') {
                return Err(invalid());
            }
            let fields = self.fields(0)?;
            if matches!(name.as_str(), "seal" | "kms") {
                if blocks.len() >= 4 {
                    return Err(invalid());
                }
                blocks.push((kind, fields));
            }
        }
        Ok(blocks)
    }
}
