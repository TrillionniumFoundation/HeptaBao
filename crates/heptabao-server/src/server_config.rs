//! Bounded static HCL adapted to the existing deployment configuration schema.
//!
//! JSON retains its original strict serde decoder. HCL supports literal
//! attributes, arrays, objects and unlabelled native blocks. A single TCP
//! listener has explicit aliases. Storage selectors bind existing native durable,
//! PostgreSQL and enrolled Raft consumers; unsupported options remain explicit.
//! Expressions, repeated listeners and unmapped official settings fail closed.
//! Runtime TLS, audit, filesystem and HA admission are unchanged.

use crate::{ha::HaProcessConfig, http::Config};
use serde::de::DeserializeOwned;
use serde_json::{Map, Number, Value};
use zeroize::{Zeroize, Zeroizing};

#[path = "server_storage.rs"]
mod storage;
pub use storage::StorageConfig;
pub use storage::{validate_storage, validate_storage_running, validate_storage_runtime};

const MAX_BYTES: usize = 65_536;
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 4_096;
const SERVER_SCHEMA: &str = "invalid server configuration schema";
const HA_SCHEMA: &str = "invalid HA configuration schema";

/// Decode one bounded JSON or static HCL configuration without I/O or evaluation.
pub fn parse_server(bytes: &[u8]) -> Result<Config, String> {
    decode(bytes, SERVER_SCHEMA, true)
}

/// Decode the existing explicitly enrolled HA schema, without peer discovery.
pub fn parse_ha(bytes: &[u8]) -> Result<HaProcessConfig, String> {
    decode(bytes, HA_SCHEMA, false)
}

fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    schema: &'static str,
    server: bool,
) -> Result<T, String> {
    if bytes.len() > MAX_BYTES {
        return Err("configuration exceeds limit".into());
    }
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'{')
    {
        return serde_json::from_slice(bytes).map_err(|_| schema.to_owned());
    }
    let source = std::str::from_utf8(bytes).map_err(|_| schema.to_owned())?;
    let mut parser = Parser {
        source,
        offset: 0,
        nodes: 0,
    };
    let mut tree = parser.body(false, 0).map_err(|_| schema.to_owned())?;
    parser.space().map_err(|_| schema.to_owned())?;
    if parser.offset != source.len() {
        return Err(schema.into());
    }
    if server {
        normalize_server(&mut tree.0).map_err(|_| schema.to_owned())?;
    }
    T::deserialize(&tree.0).map_err(|_| schema.to_owned())
}

// Intermediate HCL strings may contain deployment credentials. Clear them on
// success and every error path; the bounded input remains Zeroizing in main.rs.
struct Tree(Value);

fn clear(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(clear),
        Value::Object(values) => {
            for (mut key, mut child) in std::mem::take(values) {
                key.zeroize();
                clear(&mut child);
            }
        }
        _ => {}
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        clear(&mut self.0);
    }
}

impl Tree {
    fn take(&mut self) -> Value {
        std::mem::replace(&mut self.0, Value::Null)
    }
}

struct Parser<'a> {
    source: &'a str,
    offset: usize,
    nodes: usize,
}

type Invalid = ();

impl Parser<'_> {
    fn space(&mut self) -> Result<bool, Invalid> {
        let mut newline = false;
        let bytes = self.source.as_bytes();
        while self.offset < bytes.len() {
            if matches!(bytes[self.offset], b' ' | b'\t' | b'\n') {
                newline |= bytes[self.offset] == b'\n';
                self.offset += 1;
            } else if bytes[self.offset..].starts_with(b"\r\n") {
                newline = true;
                self.offset += 2;
            } else if bytes[self.offset] == b'#' || bytes[self.offset..].starts_with(b"//") {
                while self.offset < bytes.len() && bytes[self.offset] != b'\n' {
                    self.offset += 1;
                }
            } else if bytes[self.offset..].starts_with(b"/*") {
                self.offset += 2;
                let end = self.source[self.offset..].find("*/").ok_or(())?;
                self.offset += end + 2;
            } else {
                break;
            }
        }
        Ok(newline)
    }

    fn symbol(&mut self, byte: u8) -> Result<bool, Invalid> {
        self.space()?;
        if self.source.as_bytes().get(self.offset) == Some(&byte) {
            self.offset += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn require(&mut self, byte: u8) -> Result<(), Invalid> {
        if self.symbol(byte)? { Ok(()) } else { Err(()) }
    }

    fn count(&mut self, depth: usize) -> Result<(), Invalid> {
        if depth > MAX_DEPTH || self.nodes >= MAX_NODES {
            return Err(());
        }
        self.nodes += 1;
        Ok(())
    }

    fn identifier(&mut self) -> Result<Zeroizing<String>, Invalid> {
        self.space()?;
        let bytes = self.source.as_bytes();
        let start = self.offset;
        if !bytes
            .get(start)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            return Err(());
        }
        self.offset += 1;
        while bytes
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        {
            self.offset += 1;
        }
        Ok(Zeroizing::new(self.source[start..self.offset].to_owned()))
    }

    fn string(&mut self) -> Result<Zeroizing<String>, Invalid> {
        self.require(b'"')?;
        let mut result = Zeroizing::new(String::new());
        loop {
            let character = self.source[self.offset..].chars().next().ok_or(())?;
            self.offset += character.len_utf8();
            match character {
                '"' => return Ok(result),
                '\\' => {
                    let escaped = self.source[self.offset..].chars().next().ok_or(())?;
                    self.offset += escaped.len_utf8();
                    match escaped {
                        'n' => result.push('\n'),
                        'r' => result.push('\r'),
                        't' => result.push('\t'),
                        '"' => result.push('"'),
                        '\\' => result.push('\\'),
                        'u' | 'U' => {
                            let count = if escaped == 'u' { 4 } else { 8 };
                            let end = self.offset.checked_add(count).ok_or(())?;
                            let digits = self.source.get(self.offset..end).ok_or(())?;
                            if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                                return Err(());
                            }
                            let scalar = u32::from_str_radix(digits, 16).map_err(|_| ())?;
                            result.push(char::from_u32(scalar).ok_or(())?);
                            self.offset = end;
                        }
                        _ => return Err(()),
                    }
                }
                '$' | '%' => {
                    let marker = character as u8;
                    let tail = self.source.as_bytes().get(self.offset..).ok_or(())?;
                    if tail.starts_with(&[marker, b'{']) {
                        result.push(character);
                        result.push('{');
                        self.offset += 2;
                    } else if tail.starts_with(b"{") {
                        return Err(());
                    } else {
                        result.push(character);
                    }
                }
                value if value.is_control() => return Err(()),
                value => result.push(value),
            }
        }
    }

    fn body(&mut self, closed: bool, depth: usize) -> Result<Tree, Invalid> {
        self.count(depth)?;
        let mut result = Tree(Value::Object(Map::new()));
        loop {
            self.space()?;
            if self.offset == self.source.len() {
                return if closed { Err(()) } else { Ok(result) };
            }
            if self.symbol(b'}')? {
                return if closed { Ok(result) } else { Err(()) };
            }
            let key = self.identifier()?;
            if result.0.get(key.as_str()).is_some() {
                return Err(());
            }
            let mut value = if self.symbol(b'=')? {
                self.value(depth + 1)?
            } else {
                let mut label: Option<Zeroizing<String>> = None;
                self.space()?;
                if self.source.as_bytes().get(self.offset) == Some(&b'"') {
                    label = Some(self.string()?);
                }
                self.require(b'{')?;
                let mut nested = self.body(true, depth + 1)?;
                if let Some(label) = label {
                    if depth != 0 || !matches!(key.as_str(), "listener" | "storage") {
                        return Err(());
                    }
                    let mut labelled = Tree(Value::Object(Map::new()));
                    labelled
                        .0
                        .as_object_mut()
                        .ok_or(())?
                        .insert(label.as_str().to_owned(), nested.take());
                    labelled
                } else {
                    nested
                }
            };
            result
                .0
                .as_object_mut()
                .ok_or(())?
                .insert(key.as_str().to_owned(), value.take());
            let newline = self.space()?;
            if !newline
                && !(closed && self.source.as_bytes().get(self.offset) == Some(&b'}'))
                && !(!closed && self.offset == self.source.len())
            {
                return Err(());
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Tree, Invalid> {
        self.count(depth)?;
        self.space()?;
        match self.source.as_bytes().get(self.offset).copied() {
            Some(b'"') => {
                let value = self.string()?;
                Ok(Tree(Value::String(value.as_str().to_owned())))
            }
            Some(b'[') => {
                self.offset += 1;
                let mut result = Tree(Value::Array(Vec::new()));
                if self.symbol(b']')? {
                    return Ok(result);
                }
                loop {
                    let mut child = self.value(depth + 1)?;
                    result.0.as_array_mut().ok_or(())?.push(child.take());
                    let newline = self.space()?;
                    if self.symbol(b']')? {
                        return Ok(result);
                    }
                    if !self.symbol(b',')? && !newline {
                        return Err(());
                    }
                    if self.symbol(b']')? {
                        return Ok(result);
                    }
                }
            }
            Some(b'{') => {
                self.offset += 1;
                let mut result = Tree(Value::Object(Map::new()));
                loop {
                    if self.symbol(b'}')? {
                        return Ok(result);
                    }
                    self.space()?;
                    let key = if self.source.as_bytes().get(self.offset) == Some(&b'"') {
                        self.string()?
                    } else {
                        self.identifier()?
                    };
                    if result.0.get(key.as_str()).is_some() {
                        return Err(());
                    }
                    if !self.symbol(b'=')? {
                        self.require(b':')?;
                    }
                    let mut child = self.value(depth + 1)?;
                    result
                        .0
                        .as_object_mut()
                        .ok_or(())?
                        .insert(key.as_str().to_owned(), child.take());
                    let newline = self.space()?;
                    if self.symbol(b'}')? {
                        return Ok(result);
                    }
                    if !self.symbol(b',')? && !newline {
                        return Err(());
                    }
                }
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.offset;
                let bytes = self.source.as_bytes();
                while bytes.get(self.offset).is_some_and(|byte| {
                    byte.is_ascii_digit() || matches!(*byte, b'-' | b'+' | b'.' | b'e' | b'E')
                }) {
                    self.offset += 1;
                }
                let number: Number = self.source[start..self.offset].parse().map_err(|_| ())?;
                Ok(Tree(Value::Number(number)))
            }
            _ => {
                let word = self.identifier()?;
                match word.as_str() {
                    "true" => Ok(Tree(Value::Bool(true))),
                    "false" => Ok(Tree(Value::Bool(false))),
                    "null" => Ok(Tree(Value::Null)),
                    _ => Err(()),
                }
            }
        }
    }
}

fn unique(map: &mut Map<String, Value>, key: &str, value: Value) -> Result<(), Invalid> {
    let mut value = Tree(value);
    if map.contains_key(key) {
        return Err(());
    }
    map.insert(key.into(), value.take());
    Ok(())
}

// These three official listener fields document quoted boolean values. Accept
// only their exact "true"/"false" spellings; native typed fields stay strict.
fn optional_listener_bool(
    map: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, Invalid> {
    map.remove(key)
        .map(|value| {
            let value = Tree(value);
            match &value.0 {
                Value::Bool(value) => Ok(*value),
                Value::String(value) if value == "true" => Ok(true),
                Value::String(value) if value == "false" => Ok(false),
                _ => Err(()),
            }
        })
        .transpose()
}

fn normalize_server(value: &mut Value) -> Result<(), Invalid> {
    let root = value.as_object_mut().ok_or(())?;
    storage::normalize(root)?;
    if let Some(listener) = root.remove("listener") {
        let mut listener = Tree(listener);
        let labelled = listener.0.as_object_mut().ok_or(())?;
        if labelled.len() != 1 || !labelled.contains_key("tcp") {
            return Err(());
        }
        let mut tcp = Tree(labelled.remove("tcp").ok_or(())?);
        let fields = tcp.0.as_object_mut().ok_or(())?;
        if optional_listener_bool(fields, "tls_disable")? == Some(true) {
            return Err(());
        }
        let require_client = optional_listener_bool(fields, "tls_require_and_verify_client_cert")?;
        let disable_client = optional_listener_bool(fields, "tls_disable_client_certs")?;
        if require_client == Some(true) && disable_client == Some(true) {
            return Err(());
        }
        let address = fields
            .remove("address")
            .unwrap_or_else(|| Value::String("127.0.0.1:8200".into()));
        unique(root, "listen", address)?;
        let keys: Vec<_> = fields.keys().cloned().collect();
        for key in keys {
            let mut value = Tree(fields.remove(&key).ok_or(())?);
            if !matches!(
                key.as_str(),
                "tls_cert_file"
                    | "tls_key_file"
                    | "tls_min_version"
                    | "tls_max_version"
                    | "tls_key_exchange_preferences"
                    | "tls_client_ca_file"
                    | "tls_client_crl_file"
                    | "tls_client_auth_optional"
                    | "disable_unauthed_rekey_endpoints"
                    | "consistency_max_index_wait"
                    | "consistency_fallback_behavior"
                    | "consistency_missing_header_forward"
            ) {
                return Err(());
            }
            unique(root, &key, value.take())?;
        }
        let has_ca = root
            .get("tls_client_ca_file")
            .is_some_and(|value| value.is_string());
        if disable_client == Some(true) && has_ca {
            return Err(());
        }
        match require_client {
            Some(true) => {
                if !has_ca || root.get("tls_client_auth_optional") == Some(&Value::Bool(true)) {
                    return Err(());
                }
            }
            Some(false) if has_ca => unique(root, "tls_client_auth_optional", Value::Bool(true))?,
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "server_config_tests.rs"]
mod tests;
