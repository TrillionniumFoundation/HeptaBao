use super::*;
use ::hmac::{Hmac, Mac};
use base64::{
    Engine as _,
    engine::general_purpose::{GeneralPurpose, STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL},
};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom, generate},
    signature::{self, KeyPair},
};
use sha2::{Digest as RustDigest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
use zeroize::Zeroizing;
#[path = "transit_external.rs"]
mod external;
#[path = "transit_mldsa.rs"]
mod mldsa;
const MAX_BATCH: usize = 256;
const MAX_ENCRYPTIONS_PER_VERSION: u64 = 1 << 32;

#[derive(Clone, Serialize, Deserialize, Default)]
pub(super) struct Transit {
    keys: BTreeMap<String, Key>,
    disable_upsert: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct Key {
    kind: String,
    latest_version: u64,
    min_decryption_version: u64,
    min_encryption_version: u64,
    deletion_allowed: bool,
    exportable: bool,
    #[serde(default)]
    auto_rotate_period: u64,
    deleted: bool,
    versions: BTreeMap<u64, KeyVersion>,
}

#[derive(Clone, Serialize, Deserialize)]
struct KeyVersion {
    material: String,
    hmac_material: String,
    created_at: u64,
    encryptions: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_key_ref: Option<String>,
}

impl Drop for KeyVersion {
    fn drop(&mut self) {
        self.material.zeroize();
        self.hmac_material.zeroize();
    }
}

fn random_bytes(length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(vec![0; length]);
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| error(503, "system entropy is unavailable"))?;
    Ok(bytes)
}

fn decode(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    decode_with(value, &BASE64)
}

fn decode_with(value: &str, encoding: &GeneralPurpose) -> Result<Zeroizing<Vec<u8>>> {
    if value.len() > MAX_INPUT_BYTES * 4 / 3 + 4 {
        return Err(error(413, "cryptographic input exceeds the supported size"));
    }
    encoding
        .decode(value)
        .map(Zeroizing::new)
        .map_err(|_| bad("invalid base64 input"))
}

fn decode_field(body: &Value, field: &str) -> Result<Zeroizing<Vec<u8>>> {
    decode(string(body, field)?)
}
fn stored_material(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    BASE64
        .decode(value)
        .map(Zeroizing::new)
        .map_err(|_| error(500, "stored key material is invalid"))
}

impl KeyVersion {
    fn generate(kind: &str, now: u64) -> Result<Self> {
        let material = match kind {
            "aes128-gcm96" => random_bytes(16)?,
            "mldsa-44" | "mldsa-65" | "mldsa-87" => random_bytes(32)?,
            "aes256-gcm96" | "chacha20-poly1305" | "xchacha20-poly1305" | "hmac" => {
                random_bytes(32)?
            }
            "ed25519" => Zeroizing::new(
                signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map_err(|_| error(503, "key generation failed"))?
                    .as_ref()
                    .to_vec(),
            ),
            _ => return Err(error(501, "key type is not implemented")),
        };
        Ok(Self {
            material: BASE64.encode(material),
            hmac_material: BASE64.encode(random_bytes(32)?),
            created_at: now,
            encryptions: 0,
            external_key_ref: None,
        })
    }
}

impl Key {
    fn new(body: &Value, now: u64) -> Result<Self> {
        let kind = body
            .get("type")
            .map(|v| v.as_str().ok_or_else(|| bad("key type must be a string")))
            .transpose()?
            .unwrap_or("aes256-gcm96");
        for flag in ["derived", "convergent_encryption", "allow_plaintext_backup"] {
            if optional_bool(body, flag)?.unwrap_or(false) {
                return Err(error(
                    501,
                    "derived keys, convergent encryption and plaintext backups are not implemented",
                ));
            }
        }
        let auto_rotate_period = auto_rotate_period(body.get("auto_rotate_period"))?;
        let exportable = optional_bool(body, "exportable")?.unwrap_or(false);
        let version = if kind == "external-key" {
            external::new_version(body, now)?
        } else {
            if body.get("external_key_ref").is_some() {
                return Err(bad("external_key_ref requires type external-key"));
            }
            KeyVersion::generate(kind, now)?
        };
        if kind == "external-key" && (exportable || auto_rotate_period != 0) {
            return Err(bad(
                "external keys cannot be exported or automatically rotated",
            ));
        }
        Ok(Self {
            kind: kind.into(),
            latest_version: 1,
            min_decryption_version: 1,
            min_encryption_version: 0,
            deletion_allowed: false,
            exportable,
            auto_rotate_period,
            deleted: false,
            versions: BTreeMap::from([(1, version)]),
        })
    }

    fn descriptor(&self, name: &str) -> Result<Value> {
        if self.kind == "external-key" {
            return external::descriptor(self, name);
        }
        let mut versions = serde_json::Map::new();
        for (number, version) in &self.versions {
            let value = if self.kind == "ed25519" {
                let material = stored_material(&version.material)?;
                let pair = signature::Ed25519KeyPair::from_pkcs8(&material)
                    .map_err(|_| error(500, "stored signing key is invalid"))?;
                json!({"creation_time":timestamp(version.created_at),"public_key":BASE64.encode(pair.public_key().as_ref())})
            } else if mldsa::is_kind(&self.kind) {
                let material = stored_material(&version.material)?;
                json!({"creation_time":timestamp(version.created_at),
                    "public_key":BASE64.encode(mldsa::public(&self.kind, &material)?),
                    "name":"", "certificate_chain":Value::Null})
            } else {
                json!(version.created_at)
            };
            versions.insert(number.to_string(), value);
        }
        let encryption = matches!(
            self.kind.as_str(),
            "aes128-gcm96" | "aes256-gcm96" | "chacha20-poly1305" | "xchacha20-poly1305"
        );
        Ok(
            json!({"name":name,"type":self.kind,"keys":versions,"latest_version":self.latest_version,
            "min_decryption_version":self.min_decryption_version,"min_encryption_version":self.min_encryption_version,
            "deletion_allowed":self.deletion_allowed,"exportable":self.exportable,"allow_plaintext_backup":false,
            "derived":false,"convergent_encryption":false,"supports_derivation":false,
            "supports_encryption":encryption,"supports_decryption":encryption,"supports_signing":self.kind=="ed25519" || mldsa::is_kind(&self.kind),
            "supports_hmac":true,"imported_key":false,"auto_rotate_period":self.auto_rotate_period,"soft_deleted":self.deleted,"min_available_version":0}),
        )
    }

    fn alive(&self) -> Result<()> {
        if self.deleted {
            return Err(bad("key is soft deleted"));
        }
        Ok(())
    }

    fn selected_version(&self, body: &Value) -> Result<u64> {
        self.alive()?;
        let version = optional_u64(body, "key_version")?
            .filter(|v| *v != 0)
            .unwrap_or(self.latest_version);
        let minimum = self.min_encryption_version.max(1);
        if version < minimum || !self.versions.contains_key(&version) {
            return Err(bad(
                "key version is unavailable or disallowed by encryption policy",
            ));
        }
        Ok(version)
    }

    fn decrypt_version(&self, version: u64) -> Result<&KeyVersion> {
        self.alive()?;
        if version < self.min_decryption_version {
            return Err(bad("key version is disallowed by decryption policy"));
        }
        self.versions
            .get(&version)
            .ok_or_else(|| bad("key version is unavailable"))
    }

    fn configure(&mut self, body: &Value) -> Result<()> {
        reject_unknown(
            body,
            &[
                "min_decryption_version",
                "min_encryption_version",
                "deletion_allowed",
                "exportable",
                "allow_plaintext_backup",
                "auto_rotate_period",
            ],
        )?;
        if self.kind == "external-key"
            && (optional_bool(body, "exportable")?.unwrap_or(false)
                || body
                    .get("auto_rotate_period")
                    .map(|value| auto_rotate_period(Some(value)))
                    .transpose()?
                    .is_some_and(|period| period != 0))
        {
            return Err(bad(
                "external keys cannot be exported or automatically rotated",
            ));
        }
        let requested_auto_rotate_period = body
            .get("auto_rotate_period")
            .map(|value| auto_rotate_period(Some(value)))
            .transpose()?;
        if let Some(value) = optional_u64(body, "min_decryption_version")? {
            self.min_decryption_version = value.max(1);
        }
        if let Some(value) = optional_u64(body, "min_encryption_version")? {
            self.min_encryption_version = value;
        }
        if self.min_decryption_version > self.latest_version
            || self.min_encryption_version > self.latest_version
            || (self.min_encryption_version != 0
                && self.min_encryption_version < self.min_decryption_version)
        {
            return Err(bad(
                "minimum key versions are inconsistent or exceed the latest version",
            ));
        }
        if let Some(value) = optional_bool(body, "deletion_allowed")? {
            self.deletion_allowed = value;
        }
        if let Some(value) = optional_bool(body, "exportable")? {
            if self.exportable && !value {
                return Err(bad("exportability cannot be revoked once enabled"));
            }
            self.exportable = value;
        }
        if optional_bool(body, "allow_plaintext_backup")?.unwrap_or(false) {
            return Err(error(501, "plaintext backup is not implemented"));
        }
        if let Some(period) = requested_auto_rotate_period {
            self.auto_rotate_period = period;
        }
        Ok(())
    }

    fn auto_rotate(&mut self, now: u64) -> Result<bool> {
        if self.deleted || self.auto_rotate_period == 0 || self.versions.len() >= 10_000 {
            return Ok(false);
        }
        let created = self
            .versions
            .get(&self.latest_version)
            .ok_or_else(|| error(500, "latest transit key version is missing"))?
            .created_at;
        let due = created
            .checked_add(self.auto_rotate_period)
            .ok_or_else(|| error(500, "transit rotation deadline overflow"))?;
        if now < due {
            return Ok(false);
        }
        let next = self
            .latest_version
            .checked_add(1)
            .ok_or_else(|| bad("key version limit reached"))?;
        self.versions
            .insert(next, KeyVersion::generate(&self.kind, now)?);
        self.latest_version = next;
        Ok(true)
    }
}

fn auto_rotate_period(value: Option<&Value>) -> Result<u64> {
    let period = value.map(duration_seconds).transpose()?.unwrap_or(0);
    if period != 0 && period < 3600 {
        return Err(bad("auto_rotate_period must be at least 1h or 0"));
    }
    Ok(period)
}

impl Transit {
    pub(super) fn contains(&self, name: &str) -> bool {
        self.keys.contains_key(name)
    }

    pub(super) fn has_auto_rotate_keys(&self) -> bool {
        self.keys
            .values()
            .any(|key| key.auto_rotate_period != 0 && !key.deleted)
    }

    pub(super) fn maintain_auto_rotation(&mut self, now: u64) -> Result<bool> {
        let mut changed = false;
        for key in self.keys.values_mut() {
            changed |= key.auto_rotate(now)?;
        }
        Ok(changed)
    }

    pub(super) fn handle(
        &mut self,
        namespace: &str,
        mount: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if path == "config/keys" {
            if method == "GET" {
                return Ok(ok(json!({"disable_upsert":self.disable_upsert}), false));
            }
            if !write_method(method) {
                return Err(unsupported());
            }
            reject_unknown(body, &["disable_upsert"])?;
            self.disable_upsert = optional_bool(body, "disable_upsert")?
                .ok_or_else(|| bad("disable_upsert is required"))?;
            return Ok(empty(true));
        }
        if path == "keys" || path == "keys/" {
            if method != "LIST" {
                return Err(unsupported());
            }
            let keys = list_keys(self.keys.keys(), "", false, body)?;
            if keys.is_empty() {
                return Err(not_found());
            }
            return Ok(ok(json!({"keys":keys}), false));
        }
        if let Some(rest) = path.strip_prefix("keys/") {
            return self.handle_key(method, rest, body, now);
        }
        if let Some(rest) = path.strip_prefix("export/") {
            return self.export(method, rest);
        }
        let (operation, rest) = path.split_once('/').unwrap_or((path, ""));
        if !write_method(method) {
            return Err(unsupported());
        }
        match operation {
            "random" => return random(rest, body),
            "hash" => return hash(rest, body),
            "encrypt" | "decrypt" | "rewrap" | "hmac" | "sign" | "verify" => {}
            "datakey" => return self.datakey(namespace, mount, rest, body),
            _ => return Err(error(404, "unknown or unsupported transit operation")),
        }
        let (name, algorithm) = rest.split_once('/').unwrap_or((rest, ""));
        valid_path(name)?;
        if !algorithm.is_empty() && !matches!(operation, "hmac" | "sign" | "verify") {
            return Err(bad("unexpected transit path suffix"));
        }
        if operation == "encrypt" && !self.keys.contains_key(name) {
            if self.disable_upsert {
                return Err(bad("key does not exist and upsert is disabled"));
            }
            reject_context(body)?;
            self.keys.insert(name.into(), Key::new(body, now)?);
        }
        let key = self.keys.get_mut(name).ok_or_else(not_found)?;
        key.alive()?;
        handle_crypto(key, namespace, mount, name, operation, algorithm, body)
    }

    fn handle_key(
        &mut self,
        method: &str,
        rest: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        let (name, operation) = rest.split_once('/').unwrap_or((rest, ""));
        valid_path(name)?;
        if operation.is_empty() {
            if method == "GET" {
                return Ok(ok(
                    self.keys
                        .get(name)
                        .ok_or_else(not_found)?
                        .descriptor(name)?,
                    false,
                ));
            }
            if method == "DELETE" {
                let Some(key) = self.keys.get(name) else {
                    return Ok(empty(false));
                };
                if !key.deletion_allowed {
                    return Err(bad(
                        "key deletion is disabled; explicitly enable deletion_allowed first",
                    ));
                }
                self.keys.remove(name);
                return Ok(empty(true));
            }
            if !write_method(method) {
                return Err(unsupported());
            }
            reject_unknown(
                body,
                &[
                    "type",
                    "derived",
                    "convergent_encryption",
                    "exportable",
                    "allow_plaintext_backup",
                    "auto_rotate_period",
                    "external_key_ref",
                ],
            )?;
            if let Some(key) = self.keys.get(name) {
                if body.get("type").is_some_and(|v| v != &key.kind) {
                    return Err(bad("key already exists with a different immutable type"));
                }
                for flag in ["derived", "convergent_encryption", "allow_plaintext_backup"] {
                    if optional_bool(body, flag)?.unwrap_or(false) {
                        return Err(error(501, "requested key feature is not implemented"));
                    }
                }
                if optional_bool(body, "exportable")?
                    .is_some_and(|exportable| exportable != key.exportable)
                {
                    return Err(bad("use the key config endpoint to change exportability"));
                }
                if let Some(value) = body.get("auto_rotate_period")
                    && auto_rotate_period(Some(value))? != key.auto_rotate_period
                {
                    return Err(bad(
                        "use the key config endpoint to change auto_rotate_period",
                    ));
                }
                if let Some(reference) = body.get("external_key_ref") {
                    let current = key
                        .versions
                        .get(&key.latest_version)
                        .and_then(|version| version.external_key_ref.as_deref());
                    if reference.as_str() != current {
                        return Err(bad("use rotation to change an external key reference"));
                    }
                }
                return Ok(ok(key.descriptor(name)?, false));
            }
            self.keys.insert(name.into(), Key::new(body, now)?);
            return Ok(ok(
                self.keys
                    .get(name)
                    .ok_or_else(not_found)?
                    .descriptor(name)?,
                true,
            ));
        }
        if !write_method(method) && !(operation == "soft-delete" && method == "DELETE") {
            return Err(unsupported());
        }
        let key = self.keys.get_mut(name).ok_or_else(not_found)?;
        match operation {
            "config" => {
                key.configure(body)?;
                return Ok(ok(key.descriptor(name)?, true));
            }
            "rotate" => {
                reject_unknown(
                    body,
                    if key.kind == "external-key" {
                        &["external_key_ref"]
                    } else {
                        &[]
                    },
                )?;
                key.alive()?;
                if key.versions.len() >= 10_000 {
                    return Err(bad("key version retention limit reached"));
                }
                let next = key
                    .latest_version
                    .checked_add(1)
                    .ok_or_else(|| bad("key version limit reached"))?;
                let version = if key.kind == "external-key" {
                    if body.get("external_key_ref").is_some() {
                        external::new_version(body, now)?
                    } else {
                        let reference = key
                            .versions
                            .get(&key.latest_version)
                            .and_then(|version| version.external_key_ref.as_deref())
                            .ok_or_else(|| error(503, "external key reference is unavailable"))?;
                        external::new_version(&json!({"external_key_ref":reference}), now)?
                    }
                } else {
                    KeyVersion::generate(&key.kind, now)?
                };
                key.versions.insert(next, version);
                key.latest_version = next;
            }
            "soft-delete" => {
                reject_unknown(body, &[])?;
                key.deleted = true;
            }
            "soft-delete-restore" => {
                reject_unknown(body, &[])?;
                key.deleted = false;
            }
            _ => return Err(error(404, "unknown or unsupported transit key operation")),
        }
        if operation == "rotate" {
            Ok(ok(key.descriptor(name)?, true))
        } else {
            Ok(empty(true))
        }
    }

    fn export(&self, method: &str, rest: &str) -> Result<EngineResponse> {
        if method != "GET" {
            return Err(unsupported());
        }
        let parts: Vec<_> = rest.split('/').collect();
        if !(2..=3).contains(&parts.len()) {
            return Err(bad("invalid key export path"));
        }
        let kind = parts[0];
        let name = parts[1];
        let key = self.keys.get(name).ok_or_else(not_found)?;
        key.alive()?;
        let mldsa_key = mldsa::is_kind(&key.kind);
        let public_export = mldsa_key && kind == "public-key";
        if !key.exportable && !public_export {
            return Err(error(403, "key is not exportable"));
        }
        if kind != "hmac-key"
            && !(mldsa_key && matches!(kind, "public-key" | "signing-key"))
            && !(kind == "encryption-key"
                && matches!(
                    key.kind.as_str(),
                    "aes128-gcm96" | "aes256-gcm96" | "chacha20-poly1305" | "xchacha20-poly1305"
                ))
        {
            return Err(error(501, "requested key export format is not implemented"));
        }
        let selected = parts
            .get(2)
            .map(|version| {
                if *version == "latest" {
                    Ok(key.latest_version)
                } else {
                    version
                        .parse::<u64>()
                        .map_err(|_| bad("invalid key version"))
                }
            })
            .transpose()?;
        if let Some(version) = selected {
            key.decrypt_version(version)?;
        }
        let keys = key
            .versions
            .iter()
            .filter(|(version, _)| {
                **version >= key.min_decryption_version
                    && selected.is_none_or(|number| **version == number)
            })
            .map(|(version, value)| {
                let encoded = if public_export {
                    BASE64.encode(mldsa::public(
                        &key.kind,
                        &stored_material(&value.material)?,
                    )?)
                } else if kind == "hmac-key" {
                    value.hmac_material.clone()
                } else {
                    value.material.clone()
                };
                Ok((version.to_string(), json!(&*Zeroizing::new(encoded))))
            })
            .collect::<Result<serde_json::Map<String, Value>>>()?;
        Ok(ok(
            json!({"name":name,"type":key.kind,"keys":Value::Object(keys)}),
            false,
        ))
    }

    fn datakey(
        &mut self,
        namespace: &str,
        mount: &str,
        rest: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        reject_unknown(
            body,
            &["bits", "key_version", "associated_data", "context", "nonce"],
        )?;
        let (mode, name) = rest
            .split_once('/')
            .ok_or_else(|| bad("data key path requires mode and key name"))?;
        if !matches!(mode, "plaintext" | "wrapped") {
            return Err(bad("data key mode must be plaintext or wrapped"));
        }
        valid_path(name)?;
        if name.contains('/') {
            return Err(bad("transit key names cannot contain path separators"));
        }
        reject_context(body)?;
        let bits = optional_u64(body, "bits")?.unwrap_or(256);
        if !matches!(bits, 128 | 256 | 512) {
            return Err(bad("data key bits must be 128, 256 or 512"));
        }
        let key = self.keys.get_mut(name).ok_or_else(not_found)?;
        if key.kind == "external-key" {
            return Err(error(
                501,
                "external key data-key generation is not implemented",
            ));
        }
        let plaintext = random_bytes((bits / 8) as usize)?;
        let mut data = encrypt(key, namespace, mount, name, body, &plaintext)?;
        if mode == "plaintext" {
            let encoded = Zeroizing::new(BASE64.encode(plaintext));
            data["plaintext"] = json!(&*encoded);
        }
        Ok(ok(data, true))
    }
}

fn reject_context(body: &Value) -> Result<()> {
    for field in ["context", "nonce"] {
        if let Some(value) = body.get(field)
            && value.as_str() != Some("")
        {
            return Err(error(
                501,
                "derived contexts and caller-supplied nonces are not implemented",
            ));
        }
    }
    if optional_bool(body, "convergent_encryption")?.unwrap_or(false) {
        return Err(error(501, "convergent encryption is not implemented"));
    }
    Ok(())
}

fn handle_crypto(
    key: &mut Key,
    namespace: &str,
    mount: &str,
    name: &str,
    operation: &str,
    algorithm: &str,
    body: &Value,
) -> Result<EngineResponse> {
    if key.kind == "external-key" {
        return Err(error(
            501,
            "external key operations require the audited external-effect dispatcher",
        ));
    }
    let allowed: &[&str] = match operation {
        "encrypt" => &[
            "plaintext",
            "key_version",
            "associated_data",
            "context",
            "nonce",
            "type",
            "convergent_encryption",
            "reference",
            "batch_input",
            "partial_failure_response_code",
        ],
        "decrypt" => &[
            "ciphertext",
            "associated_data",
            "context",
            "nonce",
            "reference",
            "batch_input",
            "partial_failure_response_code",
        ],
        "rewrap" => &[
            "ciphertext",
            "key_version",
            "associated_data",
            "context",
            "nonce",
            "reference",
            "batch_input",
            "partial_failure_response_code",
        ],
        "hmac" => &[
            "input",
            "key_version",
            "algorithm",
            "reference",
            "batch_input",
            "partial_failure_response_code",
        ],
        "sign" => &[
            "input",
            "key_version",
            "hash_algorithm",
            "context",
            "prehashed",
            "signature_algorithm",
            "marshaling_algorithm",
            "reference",
            "batch_input",
            "partial_failure_response_code",
        ],
        "verify" => &[
            "input",
            "signature",
            "hmac",
            "algorithm",
            "hash_algorithm",
            "context",
            "prehashed",
            "signature_algorithm",
            "marshaling_algorithm",
            "reference",
            "batch_input",
            "partial_failure_response_code",
        ],
        _ => return Err(unsupported()),
    };
    reject_unknown(body, allowed)?;
    if let Some(items) = body.get("batch_input") {
        let items = items
            .as_array()
            .filter(|items| !items.is_empty() && items.len() <= MAX_BATCH)
            .ok_or_else(|| bad("batch_input must contain between 1 and 256 items"))?;
        let partial_code = optional_u64(body, "partial_failure_response_code")?.unwrap_or(400);
        if !(200..=599).contains(&partial_code) {
            return Err(bad(
                "partial failure response code must be between 200 and 599",
            ));
        }
        let mut responses = Vec::with_capacity(items.len());
        let mut failed = 0;
        let mut mutated = false;
        for item in items {
            let mut combined = SecretJson(body.clone());
            if let Some(combined) = combined.as_object_mut() {
                combined.remove("batch_input");
                combined.remove("partial_failure_response_code");
                // Per-item payloads never inherit a sibling or top-level payload.
                for field in [
                    "input",
                    "plaintext",
                    "ciphertext",
                    "context",
                    "associated_data",
                    "signature",
                    "hmac",
                    "reference",
                ] {
                    if let Some(mut value) = combined.remove(field) {
                        wipe_json(&mut value);
                    }
                }
                if let Some(item_map) = item.as_object() {
                    for (field, value) in item_map {
                        combined.insert(field.clone(), value.clone());
                    }
                }
            }
            // A failed item cannot leave counters or key state behind.
            let mut key_candidate = key.clone();
            let result = if item.is_object()
                && item.get("batch_input").is_none()
                && item.get("partial_failure_response_code").is_none()
            {
                handle_crypto(
                    &mut key_candidate,
                    namespace,
                    mount,
                    name,
                    operation,
                    algorithm,
                    &combined,
                )
            } else {
                Err(bad("batch items must be objects without nested batches"))
            };
            let mut value = match result {
                Ok(response) => {
                    if response.mutated {
                        *key = key_candidate;
                        mutated = true;
                    }
                    response.body["data"].clone()
                }
                Err(failure) => {
                    failed += 1;
                    json!({"error":failure.message})
                }
            };
            if let Some(reference) = item.get("reference") {
                value["reference"] = reference.clone();
            }
            responses.push(value);
        }
        let status = if failed == 0 {
            200
        } else if failed == items.len() {
            400
        } else {
            partial_code as u16
        };
        return Ok(EngineResponse {
            status,
            body: json!({"data":{"batch_results":responses}}),
            mutated,
        });
    }
    if mldsa::is_kind(&key.kind) && matches!(operation, "sign" | "verify") {
        // Context is a key-derivation parameter, not a FIPS 204 signature
        // context. Native ML-DSA keys are not derived, but the generic API
        // still validates the Base64 encoding before ignoring decoded bytes.
        if body.get("context").is_some() {
            let _context = decode_field(body, "context")?;
        }
    } else {
        reject_context(body)?;
    }
    let data = match operation {
        "encrypt" => {
            if body.get("type").is_some_and(|kind| kind != &key.kind) {
                return Err(bad("requested encryption type does not match the key"));
            }
            encrypt(
                key,
                namespace,
                mount,
                name,
                body,
                &decode_field(body, "plaintext")?,
            )?
        }
        "decrypt" => {
            let encoded =
                Zeroizing::new(BASE64.encode(decrypt(key, namespace, mount, name, body)?));
            json!({"plaintext":&*encoded})
        }
        "rewrap" => {
            let plaintext = decrypt(key, namespace, mount, name, body)?;
            encrypt(key, namespace, mount, name, body, &plaintext)?
        }
        "hmac" => {
            let version = key.selected_version(body)?;
            let algorithm = select_algorithm(algorithm, body, "algorithm", "sha2-256")?;
            let material = stored_material(
                &key.versions
                    .get(&version)
                    .ok_or_else(not_found)?
                    .hmac_material,
            )?;
            let input = decode_field(body, "input")?;
            let tag = hmac_tag(algorithm, &material, &input)?;
            json!({"hmac":format!("vault:v{version}:{}", BASE64.encode(tag))})
        }
        "sign" => {
            let external_mu = signing_options(key, body, algorithm)?;
            let version = key.selected_version(body)?;
            let material =
                stored_material(&key.versions.get(&version).ok_or_else(not_found)?.material)?;
            let input = decode_field(body, "input")?;
            let signature = if mldsa::is_kind(&key.kind) {
                if external_mu {
                    mldsa::sign_mu(&key.kind, &material, &input)?
                } else {
                    mldsa::sign(&key.kind, &material, &input)?
                }
            } else {
                let pair = signature::Ed25519KeyPair::from_pkcs8(&material)
                    .map_err(|_| error(500, "stored signing key is invalid"))?;
                pair.sign(&input).as_ref().to_vec()
            };
            json!({"signature":format!("vault:v{version}:{}", signature_encoding(body)?.encode(signature)),"key_version":version})
        }
        "verify" => {
            let input = decode_field(body, "input")?;
            let valid = if let Some(mac) = body.get("hmac") {
                if body.get("signature").is_some() {
                    return Err(bad("provide exactly one of hmac or signature"));
                }
                let (version, tag) =
                    parse_wrapped(mac.as_str().ok_or_else(|| bad("hmac must be a string"))?)?;
                let version = key.decrypt_version(version)?;
                let material = stored_material(&version.hmac_material)?;
                let algorithm = select_algorithm(algorithm, body, "algorithm", "sha2-256")?;
                hmac_verify(algorithm, &material, &input, &tag)?
            } else {
                let external_mu = signing_options(key, body, algorithm)?;
                if external_mu {
                    return Err(bad("ML-DSA external mu is not supported for verification"));
                }
                let (version, bytes) =
                    parse_wrapped_with(string(body, "signature")?, signature_encoding(body)?)?;
                let version = key.decrypt_version(version)?;
                let material = stored_material(&version.material)?;
                if mldsa::is_kind(&key.kind) {
                    mldsa::verify(&key.kind, &material, &input, &bytes)?
                } else {
                    let pair = signature::Ed25519KeyPair::from_pkcs8(&material)
                        .map_err(|_| error(500, "stored signing key is invalid"))?;
                    signature::UnparsedPublicKey::new(
                        &signature::ED25519,
                        pair.public_key().as_ref(),
                    )
                    .verify(&input, &bytes)
                    .is_ok()
                }
            };
            json!({"valid":valid})
        }
        _ => return Err(unsupported()),
    };
    Ok(ok(data, matches!(operation, "encrypt" | "rewrap")))
}

// True selects the provider's external-mu API; false preserves pure signing.
fn signing_options(key: &Key, body: &Value, path_algorithm: &str) -> Result<bool> {
    signature_encoding(body)?;
    if key.kind != "ed25519" && !mldsa::is_kind(&key.kind) {
        return Err(bad("key does not support Ed25519 signing"));
    }
    let algorithm = signing_hash_algorithm(path_algorithm, body)?;
    let prehashed = signing_prehashed(body)?;
    if mldsa::is_kind(&key.kind) && algorithm == "mldsa-mu" {
        if !prehashed {
            return Err(bad("ML-DSA external mu requires prehashed=true"));
        }
        return Ok(true);
    }
    if !matches!(
        algorithm,
        "none"
            | "sha1"
            | "sha2-224"
            | "sha2-256"
            | "sha2-384"
            | "sha2-512"
            | "sha3-224"
            | "sha3-256"
            | "sha3-384"
            | "sha3-512"
    ) {
        return Err(bad("unsupported hash algorithm"));
    }
    // These key types own their pure-message hash. Generic hash/prehashed
    // arguments do not select Ed25519ph or HashML-DSA. signature_algorithm
    // selects RSA padding only and is ignored for these non-RSA keys, including
    // the pkcs1v15 argument sent by the official external PKI consumer.
    Ok(false)
}

fn signature_encoding(body: &Value) -> Result<&'static GeneralPurpose> {
    match body.get("marshaling_algorithm") {
        None => Ok(&BASE64),
        Some(Value::String(value)) if value == "asn1" => Ok(&BASE64),
        Some(Value::String(value)) if value == "jws" => Ok(&BASE64_URL),
        _ => Err(bad("unsupported signature marshaling algorithm")),
    }
}

// Signing routes capture the path algorithm ahead of the body field. Keep
// this compatibility rule separate from encryption and HMAC parsing.
fn signing_hash_algorithm<'a>(path: &'a str, body: &'a Value) -> Result<&'a str> {
    if !path.is_empty() {
        return Ok(path);
    }
    match body.get("hash_algorithm") {
        None | Some(Value::Null) => Ok("none"),
        Some(Value::String(value)) if value.is_empty() => Ok("none"),
        Some(Value::String(value)) => Ok(value),
        _ => Err(bad("algorithm must be a string")),
    }
}

fn signing_prehashed(body: &Value) -> Result<bool> {
    match body.get("prehashed") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(Value::String(value)) => match value.as_str() {
            "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
            "" | "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
            _ => Err(bad("expected a boolean parameter")),
        },
        Some(Value::Number(value)) if value.as_f64() == Some(0.0) => Ok(false),
        Some(Value::Number(value)) if value.as_f64() == Some(1.0) => Ok(true),
        _ => Err(bad("expected a boolean parameter")),
    }
}

fn select_algorithm<'a>(
    path: &'a str,
    body: &'a Value,
    field: &str,
    default: &'a str,
) -> Result<&'a str> {
    let value = body
        .get(field)
        .map(|v| v.as_str().ok_or_else(|| bad("algorithm must be a string")))
        .transpose()?;
    if !path.is_empty() {
        if value.is_some_and(|value| value != path) {
            return Err(bad("conflicting path and body algorithms"));
        }
        Ok(path)
    } else {
        Ok(value.unwrap_or(default))
    }
}

fn aead_algorithm(kind: &str) -> Result<&'static aead::Algorithm> {
    match kind {
        "aes128-gcm96" => Ok(&aead::AES_128_GCM),
        "aes256-gcm96" => Ok(&aead::AES_256_GCM),
        "chacha20-poly1305" => Ok(&aead::CHACHA20_POLY1305),
        _ => Err(bad("key type does not support encryption")),
    }
}

fn associated_data(body: &Value) -> Result<Vec<u8>> {
    let associated = body
        .get("associated_data")
        .map(|v| {
            decode(
                v.as_str()
                    .ok_or_else(|| bad("associated_data must be base64"))?,
            )
        })
        .transpose()?
        .unwrap_or_default();
    Ok(associated.to_vec())
}

fn legacy_aad(namespace: &str, mount: &str, name: &str, body: &Value) -> Result<Vec<u8>> {
    let associated = associated_data(body)?;
    // A JSON tuple is unambiguous even when namespace/path contain delimiters.
    // This remains a read-only migration path for pre-OpenBao-compatibility
    // HeptaBao ciphertexts. New ciphertexts use the raw caller AAD below.
    serde_json::to_vec(&(
        "heptabao-transit-aead-v1",
        namespace,
        mount,
        name,
        &*associated,
    ))
    .map_err(|_| error(500, "associated data encoding failed"))
}

fn xchacha20_encrypt(
    material: &[u8],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(material)
        .map_err(|_| error(500, "stored encryption key is invalid"))?;
    let mut ciphertext = Zeroizing::new(plaintext.to_vec());
    cipher
        .encrypt_in_place(XNonce::from_slice(nonce), aad, &mut *ciphertext)
        .map_err(|_| error(500, "encryption failed"))?;
    Ok(ciphertext.to_vec())
}

fn xchacha20_decrypt(
    material: &[u8],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &mut [u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(material)
        .map_err(|_| error(500, "stored encryption key is invalid"))?;
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_in_place(XNonce::from_slice(nonce), aad, &mut plaintext)
        .map_err(|_| bad("ciphertext authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

fn encrypt(
    key: &mut Key,
    _namespace: &str,
    _mount: &str,
    _name: &str,
    body: &Value,
    plaintext: &[u8],
) -> Result<Value> {
    let xchacha = key.kind == "xchacha20-poly1305";
    let algorithm = (!xchacha).then(|| aead_algorithm(&key.kind)).transpose()?;
    let version_number = key.selected_version(body)?;
    let version = key
        .versions
        .get_mut(&version_number)
        .ok_or_else(not_found)?;
    if version.encryptions >= MAX_ENCRYPTIONS_PER_VERSION {
        return Err(bad(
            "key version reached its encryption limit; rotate the key",
        ));
    }
    let material = stored_material(&version.material)?;
    let (nonce, ciphertext) = if xchacha {
        let nonce = generate::<[u8; 24]>(&SystemRandom::new())
            .map_err(|_| error(503, "system entropy is unavailable"))?
            .expose();
        let associated = associated_data(body)?;
        let ciphertext = xchacha20_encrypt(&material, &nonce, &associated, plaintext)?;
        (nonce.to_vec(), ciphertext)
    } else {
        let algorithm = algorithm.ok_or_else(|| error(500, "AEAD algorithm is unavailable"))?;
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(algorithm, &material)
                .map_err(|_| error(500, "stored encryption key is invalid"))?,
        );
        let nonce = generate::<[u8; 12]>(&SystemRandom::new())
            .map_err(|_| error(503, "system entropy is unavailable"))?
            .expose();
        let mut ciphertext = Zeroizing::new(plaintext.to_vec());
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(associated_data(body)?),
            &mut *ciphertext,
        )
        .map_err(|_| error(500, "encryption failed"))?;
        (nonce.to_vec(), ciphertext.to_vec())
    };
    let mut wrapped = nonce;
    wrapped.extend_from_slice(&ciphertext);
    version.encryptions += 1;
    Ok(
        json!({"ciphertext":format!("vault:v{version_number}:{}", BASE64.encode(wrapped)),"key_version":version_number}),
    )
}

fn decrypt(
    key: &Key,
    namespace: &str,
    mount: &str,
    name: &str,
    body: &Value,
) -> Result<Zeroizing<Vec<u8>>> {
    let xchacha = key.kind == "xchacha20-poly1305";
    let algorithm = (!xchacha).then(|| aead_algorithm(&key.kind)).transpose()?;
    let (version_number, mut ciphertext) = parse_wrapped(string(body, "ciphertext")?)?;
    let version = key.decrypt_version(version_number)?;
    let nonce_len = if xchacha { 24 } else { 12 };
    if ciphertext.len() < nonce_len + 16 {
        return Err(bad("invalid ciphertext"));
    }
    let material = stored_material(&version.material)?;
    if xchacha {
        let nonce: [u8; 24] = ciphertext[..24]
            .try_into()
            .map_err(|_| bad("invalid ciphertext"))?;
        return xchacha20_decrypt(
            &material,
            &nonce,
            &associated_data(body)?,
            &mut ciphertext[24..],
        );
    }
    let algorithm = algorithm.ok_or_else(|| error(500, "AEAD algorithm is unavailable"))?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(algorithm, &material)
            .map_err(|_| error(500, "stored encryption key is invalid"))?,
    );
    let nonce = &ciphertext[..12];
    let associated = associated_data(body)?;
    let mut raw_payload = ciphertext[12..].to_vec();
    if let Ok(plaintext) = key.open_in_place(
        aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| bad("invalid ciphertext"))?,
        aead::Aad::from(associated),
        &mut raw_payload,
    ) {
        return Ok(Zeroizing::new(plaintext.to_vec()));
    }

    // Keep already-persisted HeptaBao ciphertexts readable while all new
    // ciphertexts follow OpenBao's portable raw-AAD contract.
    let mut legacy_payload = ciphertext[12..].to_vec();
    let plaintext = key
        .open_in_place(
            aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| bad("invalid ciphertext"))?,
            aead::Aad::from(legacy_aad(namespace, mount, name, body)?),
            &mut legacy_payload,
        )
        .map_err(|_| bad("ciphertext authentication failed"))?;
    Ok(Zeroizing::new(plaintext.to_vec()))
}

fn parse_wrapped(input: &str) -> Result<(u64, Zeroizing<Vec<u8>>)> {
    parse_wrapped_with(input, &BASE64)
}

fn parse_wrapped_with(input: &str, encoding: &GeneralPurpose) -> Result<(u64, Zeroizing<Vec<u8>>)> {
    let rest = input
        .strip_prefix("vault:v")
        .ok_or_else(|| bad("invalid versioned cryptographic value"))?;
    let (version, data) = rest
        .split_once(':')
        .ok_or_else(|| bad("invalid versioned cryptographic value"))?;
    if version.starts_with('0') || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("invalid cryptographic key version"));
    }
    let version = version
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| bad("invalid cryptographic key version"))?;
    Ok((version, decode_with(data, encoding)?))
}

fn hmac_tag(name: &str, material: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    macro_rules! compute {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(material)
                .map_err(|_| error(500, "stored HMAC key material is invalid"))?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }
    match name {
        "sha2-224" => compute!(Sha224),
        "sha2-256" => compute!(Sha256),
        "sha2-384" => compute!(Sha384),
        "sha2-512" => compute!(Sha512),
        "sha3-224" => compute!(Sha3_224),
        "sha3-256" => compute!(Sha3_256),
        "sha3-384" => compute!(Sha3_384),
        "sha3-512" => compute!(Sha3_512),
        _ => Err(error(501, "HMAC algorithm is not implemented")),
    }
}

fn hmac_verify(name: &str, material: &[u8], input: &[u8], tag: &[u8]) -> Result<bool> {
    macro_rules! verify {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(material)
                .map_err(|_| error(500, "stored HMAC key material is invalid"))?;
            mac.update(input);
            Ok(mac.verify_slice(tag).is_ok())
        }};
    }
    match name {
        "sha2-224" => verify!(Sha224),
        "sha2-256" => verify!(Sha256),
        "sha2-384" => verify!(Sha384),
        "sha2-512" => verify!(Sha512),
        "sha3-224" => verify!(Sha3_224),
        "sha3-256" => verify!(Sha3_256),
        "sha3-384" => verify!(Sha3_384),
        "sha3-512" => verify!(Sha3_512),
        _ => Err(error(501, "HMAC algorithm is not implemented")),
    }
}

fn encoded(bytes: &[u8], format: &str) -> Result<String> {
    match format {
        "base64" => Ok(BASE64.encode(bytes)),
        "hex" => Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect()),
        _ => Err(bad("output format must be hex or base64")),
    }
}

fn random(path: &str, body: &Value) -> Result<EngineResponse> {
    reject_unknown(body, &["bytes", "source", "format"])?;
    let mut count = optional_u64(body, "bytes")?.unwrap_or(32);
    let mut source = body
        .get("source")
        .map(|v| {
            v.as_str()
                .ok_or_else(|| bad("random source must be a string"))
        })
        .transpose()?
        .unwrap_or("platform");
    if !path.is_empty() {
        let parts: Vec<_> = path.split('/').collect();
        match parts.as_slice() {
            [part] if part.bytes().all(|b| b.is_ascii_digit()) => {
                count = part.parse().map_err(|_| bad("invalid byte count"))?;
            }
            [part] => source = part,
            [selected, bytes] => {
                source = selected;
                count = bytes.parse().map_err(|_| bad("invalid byte count"))?;
            }
            _ => return Err(bad("invalid random endpoint path")),
        }
    }
    if !matches!(source, "platform" | "all") {
        return Err(error(501, "external entropy source is not implemented"));
    }
    if !(1..=MAX_INPUT_BYTES as u64).contains(&count) {
        return Err(bad("random byte count is outside supported bounds"));
    }
    let format = body
        .get("format")
        .map(|v| v.as_str().ok_or_else(|| bad("format must be a string")))
        .transpose()?
        .unwrap_or("base64");
    Ok(ok(
        json!({"random_bytes":encoded(&random_bytes(count as usize)?,format)?}),
        false,
    ))
}

fn hash(path: &str, body: &Value) -> Result<EngineResponse> {
    reject_unknown(body, &["input", "algorithm", "format"])?;
    let algorithm = select_algorithm(path, body, "algorithm", "sha2-256")?;
    let input = decode_field(body, "input")?;
    let hashed = hash_digest(algorithm, &input)?;
    let format = body
        .get("format")
        .map(|v| v.as_str().ok_or_else(|| bad("format must be a string")))
        .transpose()?
        .unwrap_or("hex");
    Ok(ok(json!({"sum":encoded(&hashed,format)?}), false))
}

fn hash_digest(name: &str, input: &[u8]) -> Result<Vec<u8>> {
    macro_rules! compute {
        ($digest:ty) => {{
            let mut digest = <$digest>::new();
            digest.update(input);
            Ok(digest.finalize().to_vec())
        }};
    }
    match name {
        "sha2-224" => compute!(Sha224),
        "sha2-256" => compute!(Sha256),
        "sha2-384" => compute!(Sha384),
        "sha2-512" => compute!(Sha512),
        "sha3-224" => compute!(Sha3_224),
        "sha3-256" => compute!(Sha3_256),
        "sha3-384" => compute!(Sha3_384),
        "sha3-512" => compute!(Sha3_512),
        _ => Err(error(501, "hash algorithm is not implemented")),
    }
}

#[cfg(test)]
mod auto_rotation_tests {
    use super::*;

    #[test]
    fn auto_rotation_uses_one_hour_minimum_and_persists_across_restart()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut key = Key::new(
            &json!({"type":"aes256-gcm96", "auto_rotate_period":"1h"}),
            100,
        )?;
        assert_eq!(key.auto_rotate_period, 3600);
        assert!(!key.auto_rotate(3_699)?);
        assert!(key.auto_rotate(3_700)?);
        assert_eq!(key.latest_version, 2);
        assert_eq!(key.versions[&2].created_at, 3_700);
        assert!(!key.auto_rotate(7_299)?);
        assert!(key.auto_rotate(7_300)?);

        let restored: Key = serde_json::from_value(serde_json::to_value(&key)?)?;
        assert_eq!(restored.auto_rotate_period, 3600);
        assert_eq!(restored.latest_version, 3);
        Ok(())
    }

    #[test]
    fn zero_disables_rotation_and_soft_deleted_or_retained_keys_do_not_rotate()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut disabled = Key::new(&json!({"auto_rotate_period":"0"}), 100)?;
        assert!(!disabled.auto_rotate(10_000)?);

        let mut deleted = Key::new(&json!({"auto_rotate_period":"1h"}), 100)?;
        deleted.deleted = true;
        assert!(!deleted.auto_rotate(10_000)?);

        let mut retained = Key::new(&json!({"auto_rotate_period":"1h"}), 100)?;
        for version in 2..=10_000 {
            retained
                .versions
                .insert(version, KeyVersion::generate(&retained.kind, version)?);
        }
        retained.latest_version = 10_000;
        assert!(!retained.auto_rotate(20_000)?);
        Ok(())
    }

    #[test]
    fn auto_rotation_rejects_sub_hour_periods()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert!(auto_rotate_period(Some(&json!("3599s"))).is_err());
        assert_eq!(auto_rotate_period(Some(&json!("0")))?, 0);
        Ok(())
    }
}

#[cfg(test)]
#[path = "transit_mldsa_tests.rs"]
mod mldsa_tests;
