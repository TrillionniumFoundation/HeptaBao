//! Context-derived AEAD uses maintained HKDF, HMAC and AEAD implementations.
//! The observed OpenBao 2.7 modern convergent wire contract derives a separate
//! nonce PRF key after the encryption key. Caller nonces are ignored by this
//! contract; no legacy caller-controlled convergent version is manufactured.
use super::*;
use ring::hkdf;

pub(super) fn is_false(value: &bool) -> bool {
    !*value
}

pub(super) fn is_kind(kind: &str) -> bool {
    matches!(
        kind,
        "aes128-gcm96" | "aes256-gcm96" | "chacha20-poly1305" | "xchacha20-poly1305"
    )
}

pub(super) fn key_len(kind: &str) -> usize {
    if kind == "aes128-gcm96" { 16 } else { 32 }
}

pub(super) fn context(key: &Key, body: &Value) -> Result<Zeroizing<Vec<u8>>> {
    flag(body, "convergent_encryption")?;
    let context = context_bytes(body)?;
    if key.derived && context.is_empty() {
        return Err(bad("derived keys require a nonempty context"));
    }
    Ok(context)
}

fn context_bytes(body: &Value) -> Result<Zeroizing<Vec<u8>>> {
    Ok(match body.get("context") {
        None | Some(Value::Null) => Zeroizing::new(Vec::new()),
        Some(Value::String(value)) => decode(value)?,
        Some(Value::Number(value)) => decode(&value.to_string())?,
        _ => return Err(bad("context must be base64")),
    })
}

pub(super) fn batch_context(key: &Key, operation: &str, items: &[Value]) -> Result<()> {
    if !is_kind(&key.kind) || !matches!(operation, "encrypt" | "decrypt" | "rewrap") {
        return Ok(());
    }
    for item in items {
        if !item.is_object() {
            continue;
        }
        let allowed = match item.get("context") {
            None | Some(Value::Null | Value::String(_)) => true,
            Some(Value::Number(_)) => operation == "rewrap",
            _ => false,
        };
        if !allowed {
            return Err(error(500, "batch context is invalid"));
        }
    }
    if key.derived
        && items.iter().any(|item| {
            item.is_object() && matches!(item.get("context"), None | Some(Value::Null))
                || item
                    .get("context")
                    .is_some_and(|value| value.as_str() == Some(""))
        })
    {
        return Err(bad(
            "derived keys require a nonempty context for every batch item",
        ));
    }
    Ok(())
}

pub(super) fn upsert_derived(body: &Value) -> Result<bool> {
    let Some(batch) = body.get("batch_input") else {
        return context_bytes(body).map(|context| !context.is_empty());
    };
    let items = batch
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= MAX_BATCH)
        .ok_or_else(|| bad("batch_input must contain between 1 and 256 items"))?;
    let mut mode = None;
    for item in items {
        if !item.is_object() {
            return Err(bad("batch items must be objects"));
        }
        let derived = !context_bytes(item)?.is_empty();
        if mode.is_some_and(|previous| previous != derived) {
            return Err(bad(
                "upsert batch must consistently provide derivation contexts",
            ));
        }
        mode = Some(derived);
    }
    Ok(mode.unwrap_or(false))
}

pub(super) fn flag(body: &Value, name: &str) -> Result<bool> {
    match body.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(Value::String(value)) => match value.as_str() {
            "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
            "" | "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
            _ => Err(bad("expected a boolean parameter")),
        },
        Some(Value::Number(value)) if value.as_i64() == Some(0) => Ok(false),
        Some(Value::Number(value)) if value.as_i64() == Some(1) => Ok(true),
        _ => Err(bad("expected a boolean parameter")),
    }
}

pub(super) fn version(body: &Value) -> Result<u64> {
    match body.get("key_version") {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Bool(value)) => Ok(u64::from(*value)),
        Some(Value::String(value)) => value.parse().map_err(|_| bad("invalid key version")),
        Some(Value::Number(value)) => value.as_u64().ok_or_else(|| bad("invalid key version")),
        _ => Err(bad("invalid key version")),
    }
}

pub(super) fn associated_data(body: &Value) -> Result<Vec<u8>> {
    match body.get("associated_data") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(value)) => decode(value)
            .map(|bytes| bytes.to_vec())
            .map_err(|_| error(500, "associated data is invalid")),
        Some(Value::Number(value)) => decode(&value.to_string())
            .map(|bytes| bytes.to_vec())
            .map_err(|_| error(500, "associated data is invalid")),
        Some(Value::Bool(_)) => Err(error(500, "associated data is invalid")),
        _ => Err(bad("associated_data must be base64")),
    }
}

struct Length(usize);
impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

pub(super) fn material(
    kind: &str,
    derived: bool,
    convergent: bool,
    master: &[u8],
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if master.len() != key_len(kind) {
        return Err(error(500, "stored encryption key is invalid"));
    }
    if !derived {
        return Ok(Zeroizing::new(master.to_vec()));
    }
    let length = key_len(kind) + if convergent { 32 } else { 0 };
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(master);
    let info = [context];
    let output = prk
        .expand(&info, Length(length))
        .map_err(|_| error(500, "key derivation failed"))?;
    let mut material = Zeroizing::new(vec![0; length]);
    output
        .fill(&mut material)
        .map_err(|_| error(500, "key derivation failed"))?;
    Ok(material)
}

pub(super) fn nonce(
    convergent: bool,
    material: &[u8],
    key_len: usize,
    plaintext: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    if !convergent {
        return Ok(random_bytes(length)?.to_vec());
    }
    let nonce_key = material
        .get(key_len..)
        .filter(|key| key.len() == 32)
        .ok_or_else(|| error(500, "stored convergent key is invalid"))?;
    let tag = Zeroizing::new(hmac_tag("sha2-256", nonce_key, plaintext)?);
    tag.get(..length)
        .map(|nonce| nonce.to_vec())
        .ok_or_else(|| error(500, "nonce derivation failed"))
}
