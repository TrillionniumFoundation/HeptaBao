//! OpenBao 2.7 External Keys registry.
//!
//! Registry state is namespace-scoped and is published only through the existing
//! `EngineState` copy-on-write transaction. Provider verification and key use are
//! deliberately separate external-effect operations. `verify=true` is staged
//! here but can be published only by the Service-owned KMS dispatcher after
//! provider success and a fresh authority/state fence check.

use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use heptabao_domain::SecretValue;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use zeroize::Zeroizing;

fn prehash_transit_input(body: &mut SecretJson, disable_prehashing: bool) -> Result<()> {
    let prehashed = optional_bool(body, "prehashed")?.unwrap_or(false);
    let algorithm = body
        .get("hash_algorithm")
        .and_then(Value::as_str)
        .unwrap_or("none");
    if disable_prehashing && prehashed && algorithm != "none" {
        return Err(error(
            500,
            "external signing cannot hash prehashed input when prehashing is disabled",
        ));
    }
    if disable_prehashing || prehashed || matches!(algorithm, "none" | "mldsa-mu") {
        return Ok(());
    }
    let input = Zeroizing::new(
        BASE64
            .decode(string(body, "input")?)
            .map_err(|_| bad("invalid external signing input"))?,
    );
    let digest = Zeroizing::new(match algorithm {
        "sha1" => ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input)
            .as_ref()
            .to_vec(),
        "sha2-224" => Sha224::digest(&input).to_vec(),
        "sha2-256" => Sha256::digest(&input).to_vec(),
        "sha2-384" => Sha384::digest(&input).to_vec(),
        "sha2-512" => Sha512::digest(&input).to_vec(),
        "sha3-224" => Sha3_224::digest(&input).to_vec(),
        "sha3-256" => Sha3_256::digest(&input).to_vec(),
        "sha3-384" => Sha3_384::digest(&input).to_vec(),
        "sha3-512" => Sha3_512::digest(&input).to_vec(),
        _ => return Err(bad("unsupported external signing hash algorithm")),
    });
    wipe_json(&mut body["input"]);
    body["input"] = json!(BASE64.encode(&*digest));
    body["prehashed"] = json!(true);
    Ok(())
}

const PREFIX: &str = "sys/external-keys";
const MAX_CONFIGS: usize = 256;
const MAX_KEYS_PER_CONFIG: usize = 1_024;
const MAX_GRANTS_PER_KEY: usize = 1_024;
const MAX_NAME_BYTES: usize = 128;
const MAX_VALUE_FIELDS: usize = 128;
const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_GRANT_BYTES: usize = 1_024;

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct Registry {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    configs: BTreeMap<String, ConfigEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigEntry {
    plugin: String,
    values: SecretJson,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    keys: BTreeMap<String, KeyEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    values: SecretJson,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    grants: BTreeSet<String>,
}

pub(super) fn owns(path: &str) -> bool {
    path == PREFIX || path.starts_with("sys/external-keys/")
}

// Only config and key mutations request verification. Grant writes are
// local registry changes and must never be decorated with a verify field.
pub(super) fn verification_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("sys/external-keys/configs/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let config = segments.next().unwrap_or_default();
    if !valid_name(config) {
        return false;
    }
    match segments.next() {
        None => true,
        Some("keys") => segments.next().is_some_and(valid_name) && segments.next().is_none(),
        Some(_) => false,
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
}

fn valid_plugin(value: &str) -> bool {
    matches!(value, "transit" | "pkcs11")
}

fn canonical_grant(value: &str) -> Result<String> {
    let value = value.trim_end_matches('/');
    if value.is_empty()
        || value.len() > MAX_GRANT_BYTES
        || value.starts_with('/')
        || value.contains("//")
        || value.split('/').any(|segment| !valid_name(segment))
    {
        return Err(bad("external key grant must be a canonical mount path"));
    }
    Ok(format!("{value}/"))
}

// Validate the exact JSON wire-size without making a disposable plaintext
// serialization of provider credentials or private-key parameters.
#[derive(Default)]
struct EncodedSize(usize);

impl std::io::Write for EncodedSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let size = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_VALUE_BYTES)
            .ok_or_else(|| std::io::Error::other("external key parameter bound"))?;
        self.0 = size;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_values(value: &Value) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Err(bad("external key parameters must be an object"));
    };
    if object.len() > MAX_VALUE_FIELDS
        || object.keys().any(|key| {
            key.is_empty() || key.len() > MAX_NAME_BYTES || key.chars().any(char::is_control)
        })
        || serde_json::to_writer(EncodedSize::default(), value).is_err()
    {
        return Err(bad("external key parameters exceed bounded storage limits"));
    }
    Ok(())
}

pub(super) fn verify_requested(body: &Value) -> Result<bool> {
    match body.get("verify") {
        None => Ok(true),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(bad("verify must be boolean")),
    }
}

fn reject_provider_verification(body: &Value) -> Result<()> {
    if verify_requested(body)? {
        return Err(error(
            501,
            "external key verification requires an admitted KMS provider",
        ));
    }
    Ok(())
}

fn filtered_values(body: &Value, excluded: &[&str]) -> Result<SecretJson> {
    let object = body
        .as_object()
        .ok_or_else(|| bad("external key request body must be an object"))?;
    let values = object
        .iter()
        .filter(|(key, _)| !excluded.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let value = SecretJson(Value::Object(values));
    validate_values(&value)?;
    Ok(value)
}

fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(patch) = patch else {
        let discarded = SecretJson(std::mem::replace(target, patch.clone()));
        drop(discarded);
        return;
    };
    if !target.is_object() {
        let discarded = SecretJson(std::mem::replace(target, json!({})));
        drop(discarded);
    }
    let Value::Object(target) = target else {
        return;
    };
    for (key, value) in patch {
        if value.is_null() {
            if let Some(discarded) = target.remove(key) {
                drop(SecretJson(discarded));
            }
        } else {
            merge_patch(target.entry(key.clone()).or_insert(Value::Null), value);
        }
    }
}

fn redacted(_plugin: &str, values: &SecretJson) -> Result<Value> {
    let object = values
        .as_object()
        .ok_or_else(|| error(503, "invalid external key parameter state"))?;
    let sensitive = [
        "token",
        "tls_client_key",
        // OpenBao 2.7 Transit External Keys uses this exact parameter name.
        "tls_client_key_bytes",
        "pin",
        "password",
        "secret",
        "private_key",
        "client_secret",
    ];
    // Project before cloning: never allocate a plaintext copy of a sensitive
    // parameter merely to overwrite and drop it in a response object.
    Ok(Value::Object(
        object
            .iter()
            .map(|(name, value)| {
                let public_value = if sensitive.contains(&name.as_str()) {
                    json!("(redacted)")
                } else {
                    value.clone()
                };
                (name.clone(), public_value)
            })
            .collect(),
    ))
}

fn list_page<'a>(keys: impl Iterator<Item = &'a String>, body: &Value) -> Result<Vec<String>> {
    reject_unknown(body, &["after", "limit", "list"])?;
    let after = body.get("after").and_then(Value::as_str).unwrap_or("");
    let limit = optional_u64(body, "limit")?.unwrap_or(0);
    if limit > 10_000 {
        return Err(bad("external key list limit exceeds bound"));
    }
    Ok(keys
        .filter(|key| key.as_str() > after)
        .take(if limit == 0 {
            usize::MAX
        } else {
            usize::try_from(limit).unwrap_or(usize::MAX)
        })
        .cloned()
        .collect())
}

fn list_response(keys: Vec<String>) -> EngineResponse {
    if keys.is_empty() {
        EngineResponse {
            status: 404,
            body: json!({"errors": []}),
            mutated: false,
        }
    } else {
        ok(json!({"keys":keys}), false)
    }
}

fn method_error() -> EngineError {
    error(405, "unsupported external key method")
}

pub(super) struct ProviderVerification {
    pub(super) plugin_id: String,
    pub(super) action: &'static str,
    pub(super) config_name: String,
    pub(super) key_name: Option<String>,
    pub(super) request: SecretValue,
}

#[derive(Serialize)]
struct ConfigVerificationRequest<'a> {
    action: &'static str,
    namespace: &'a str,
    plugin: &'a str,
    config: &'a str,
    values: &'a SecretJson,
}

#[derive(Serialize)]
struct KeyVerificationRequest<'a> {
    action: &'static str,
    namespace: &'a str,
    plugin: &'a str,
    config: &'a str,
    key: &'a str,
    config_values: &'a SecretJson,
    key_values: &'a SecretJson,
}

// Serialization failures and size rejections retain a zeroizing owner too.
fn encode_provider_request(value: &impl Serialize) -> Result<SecretValue> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *bytes, value)
        .map_err(|_| error(500, "external key provider request encoding failed"))?;
    if bytes.is_empty() || bytes.len() > heptabao_domain::MAX_SECRET_BYTES {
        return Err(error(
            413,
            "external key provider request exceeds runtime bound",
        ));
    }
    SecretValue::new(std::mem::take(&mut *bytes))
        .map_err(|_| error(413, "external key provider request exceeds runtime bound"))
}

impl Registry {
    // Resolve authority before cloning any provider credential. Grant paths are
    // namespace-relative; callers must provide the actual owning mount path.
    pub(super) fn require_consumer(
        &self,
        reference: &str,
        mount: &str,
    ) -> Result<(&SecretJson, &SecretJson)> {
        let (config_name, key_name) = reference
            .split_once(':')
            .filter(|(config, key)| valid_name(config) && valid_name(key))
            .ok_or_else(|| bad("external_key_ref must be config:key"))?;
        let config = self
            .configs
            .get(config_name)
            .ok_or_else(|| bad("external key reference is unavailable"))?;
        let key = config
            .keys
            .get(key_name)
            .ok_or_else(|| bad("external key reference is unavailable"))?;
        if !key.grants.contains(&canonical_grant(mount)?) {
            return Err(bad("external key has no grant for this mount"));
        }
        if config.plugin != "transit" {
            return Err(error(
                501,
                "external key provider consumption is not implemented",
            ));
        }
        Ok((&config.values, &key.values))
    }

    pub(super) fn transit_consumer_request(
        &self,
        reference: &str,
        mount: &str,
        operation: &str,
        mut body: SecretJson,
    ) -> Result<SecretValue> {
        let (config, key) = self.require_consumer(reference, mount).map_err(|cause| {
            if matches!(operation, "sign" | "verify") && cause.status == 400 {
                // Official external signing wraps an unavailable mapping/grant
                // as an operation error; authorization still fails before entry.
                error(500, "external signing reference or grant is unavailable")
            } else {
                cause
            }
        })?;
        reject_unknown(
            config,
            &[
                "address",
                "token",
                "namespace",
                "mount_path",
                "tls_server_name",
                "tls_skip_verify",
                "tls_ca_cert_bytes",
                "tls_client_cert_bytes",
                "tls_client_key_bytes",
            ],
        )?;
        reject_unknown(key, &["name", "version", "disable_prehashing"])?;
        // Native egress trust is host-enrolled, never selected or weakened by
        // encrypted API parameters. Other TLS options await a qualified lane.
        if optional_bool(config, "tls_skip_verify")?.unwrap_or(false) {
            return Err(bad("external Transit requires verified TLS"));
        }
        for field in [
            "tls_server_name",
            "tls_ca_cert_bytes",
            "tls_client_cert_bytes",
            "tls_client_key_bytes",
        ] {
            if config
                .get(field)
                .is_some_and(|value| value.as_str() != Some(""))
            {
                return Err(error(
                    501,
                    "external Transit TLS options require deployment enrollment",
                ));
            }
        }
        let address = config
            .get("address")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("external Transit address must be a string"))
            })
            .transpose()?
            .unwrap_or("https://127.0.0.1:8200")
            .trim_end_matches('/');
        let target = crate::outbound::Target::parse(address, "https")
            .map_err(|_| bad("invalid external Transit address"))?;
        if target.path != "/" {
            return Err(bad("external Transit address must be an HTTPS origin"));
        }
        let remote_mount = config
            .get("mount_path")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("external Transit mount must be a string"))
            })
            .transpose()?
            .unwrap_or("transit");
        let remote_mount = canonical_grant(remote_mount)?;
        let name = string(key, "name")?;
        if !valid_name(name) {
            return Err(bad("invalid remote Transit key name"));
        }
        let version = optional_u64(key, "version")?
            .filter(|version| *version > 0)
            .ok_or_else(|| bad("remote Transit key requires a positive fixed version"))?;
        let namespace = config
            .get("namespace")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("remote namespace must be a string"))
            })
            .transpose()?
            .unwrap_or("");
        if !namespace.is_empty() {
            let _ = canonical_grant(namespace)?;
        }
        let token = string(config, "token")?;
        if token.is_empty()
            || token.len() > 32 * 1024
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(bad("invalid remote Transit token"));
        }
        if matches!(operation, "sign" | "verify") {
            prehash_transit_input(
                &mut body,
                optional_bool(key, "disable_prehashing")?.unwrap_or(false),
            )?;
        }
        if matches!(operation, "encrypt" | "sign") {
            body["key_version"] = json!(version);
        } else if operation == "decrypt" {
            // The public local version selects the registry reference. Its
            // opaque Base64 payload is the remote ciphertext, not a nested
            // remote version string; the fixed mapping supplies that prefix.
            let payload = string(&body, "ciphertext")?;
            body["ciphertext"] = json!(format!("vault:v{version}:{payload}"));
        } else if operation == "verify" {
            let payload = string(&body, "signature")?;
            body["signature"] = json!(format!("vault:v{version}:{payload}"));
        } else {
            return Err(bad("invalid external Transit operation"));
        }
        let envelope = SecretJson(
            json!({"url":format!("{address}/v1/{remote_mount}{operation}/{name}"),
            "token":token,"namespace":namespace,"remote_version":version,"body":&*body}),
        );
        encode_provider_request(&*envelope)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    pub(super) fn provider_verification(
        &self,
        namespace: &str,
        path: &str,
    ) -> Result<ProviderVerification> {
        let suffix = path
            .strip_prefix("sys/external-keys/configs/")
            .ok_or_else(|| bad("external key verification path is invalid"))?;
        let segments = suffix.split('/').collect::<Vec<_>>();
        let config_name = segments.first().copied().unwrap_or_default();
        if !valid_name(config_name) {
            return Err(bad("invalid external key config name"));
        }
        let config = self
            .configs
            .get(config_name)
            .ok_or_else(|| error(503, "external key verification candidate is missing"))?;
        let (action, key_name, encoded) = match segments.as_slice() {
            [_] => (
                "verify_config",
                None,
                encode_provider_request(&ConfigVerificationRequest {
                    action: "verify_config",
                    namespace,
                    plugin: &config.plugin,
                    config: config_name,
                    values: &config.values,
                })?,
            ),
            [_, "keys", key_name] if valid_name(key_name) => {
                let key = config.keys.get(*key_name).ok_or_else(|| {
                    error(
                        503,
                        "external key verification candidate mapping is missing",
                    )
                })?;
                (
                    "verify_key",
                    Some((*key_name).to_owned()),
                    encode_provider_request(&KeyVerificationRequest {
                        action: "verify_key",
                        namespace,
                        plugin: &config.plugin,
                        config: config_name,
                        key: key_name,
                        config_values: &config.values,
                        key_values: &key.values,
                    })?,
                )
            }
            _ => return Err(bad("external key verification path is not a config or key")),
        };
        let request = encoded;
        Ok(ProviderVerification {
            plugin_id: config.plugin.clone(),
            action,
            config_name: config_name.to_owned(),
            key_name,
            request,
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.configs.len() > MAX_CONFIGS {
            return Err(error(503, "external key config capacity exceeded"));
        }
        for (config_name, config) in &self.configs {
            if !valid_name(config_name) || !valid_plugin(&config.plugin) {
                return Err(error(503, "invalid external key config identity"));
            }
            validate_values(&config.values)
                .map_err(|_| error(503, "invalid external key config parameters"))?;
            if config.keys.len() > MAX_KEYS_PER_CONFIG {
                return Err(error(503, "external key mapping capacity exceeded"));
            }
            for (key_name, key) in &config.keys {
                if !valid_name(key_name) {
                    return Err(error(503, "invalid external key mapping identity"));
                }
                validate_values(&key.values)
                    .map_err(|_| error(503, "invalid external key mapping parameters"))?;
                if key.grants.len() > MAX_GRANTS_PER_KEY
                    || key.grants.iter().any(|grant| {
                        !grant.ends_with('/')
                            || !canonical_grant(grant).is_ok_and(|normalized| normalized == *grant)
                    })
                {
                    return Err(error(503, "invalid external key grants"));
                }
            }
        }
        Ok(())
    }

    pub(super) fn handle(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        let suffix = path
            .strip_prefix("sys/external-keys/")
            .ok_or_else(not_found)?;
        // Match complete segments. Prefix aliases would authorize a different
        // path from the config that is actually read or changed.
        let rest = if suffix == "configs" {
            ""
        } else {
            suffix.strip_prefix("configs/").ok_or_else(not_found)?
        };
        if rest.is_empty() {
            return match method {
                "LIST" => list_page(self.configs.keys(), body).map(list_response),
                _ => Err(method_error()),
            };
        }

        let mut segments = rest.split('/');
        let config_name = segments.next().unwrap_or_default();
        if !valid_name(config_name) {
            return Err(bad("invalid external key config name"));
        }
        let Some(next) = segments.next() else {
            return self.handle_config(method, config_name, body);
        };
        if next != "keys" {
            return Err(not_found());
        }
        let Some(key_name) = segments.next() else {
            return self.handle_key_list(method, config_name, body);
        };
        if !valid_name(key_name) {
            return Err(bad("invalid external key mapping name"));
        }
        let Some(next) = segments.next() else {
            return self.handle_key(method, config_name, key_name, body);
        };
        if next != "grants" {
            return Err(not_found());
        }
        let grant = segments.collect::<Vec<_>>().join("/");
        if grant.is_empty() {
            return self.handle_grant_list(method, config_name, key_name, body);
        }
        self.handle_grant(method, config_name, key_name, &grant, body)
    }

    fn handle_config(&mut self, method: &str, name: &str, body: &Value) -> Result<EngineResponse> {
        match method {
            "GET" | "HEAD" => {
                reject_unknown(body, &[])?;
                let entry = self
                    .configs
                    .get(name)
                    .ok_or_else(|| error(400, &format!("config \"{name}\" not found")))?;
                let mut data = redacted(&entry.plugin, &entry.values)?;
                data.as_object_mut()
                    .ok_or_else(|| error(503, "invalid external key config state"))?
                    .insert("plugin".into(), json!(entry.plugin));
                Ok(ok(data, false))
            }
            "POST" | "PUT" => {
                reject_provider_verification(body)?;
                let plugin = body
                    .get("plugin")
                    .and_then(Value::as_str)
                    .filter(|plugin| valid_plugin(plugin))
                    .ok_or_else(|| bad("plugin must be transit or pkcs11"))?;
                if !self.configs.contains_key(name) && self.configs.len() >= MAX_CONFIGS {
                    return Err(error(507, "external key config capacity exhausted"));
                }
                let values = filtered_values(body, &["plugin", "verify"])?;
                let keys = self
                    .configs
                    .get(name)
                    .map(|entry| entry.keys.clone())
                    .unwrap_or_default();
                self.configs.insert(
                    name.to_owned(),
                    ConfigEntry {
                        plugin: plugin.to_owned(),
                        values,
                        keys,
                    },
                );
                Ok(empty(true))
            }
            "PATCH" => {
                reject_provider_verification(body)?;
                let entry = self
                    .configs
                    .get(name)
                    .cloned()
                    .ok_or_else(|| error(400, &format!("config \"{name}\" not found")))?;
                let plugin = match body.get("plugin") {
                    None | Some(Value::Null) => entry.plugin,
                    Some(Value::String(value)) if valid_plugin(value) => value.clone(),
                    Some(_) => return Err(bad("plugin must be transit or pkcs11")),
                };
                let patch = filtered_values(body, &["plugin", "verify"])?;
                let mut values = entry.values.clone();
                merge_patch(&mut values, &patch);
                validate_values(&values)?;
                self.configs.insert(
                    name.to_owned(),
                    ConfigEntry {
                        plugin,
                        values,
                        keys: entry.keys,
                    },
                );
                Ok(empty(true))
            }
            "DELETE" => {
                reject_unknown(body, &[])?;
                Ok(empty(self.configs.remove(name).is_some()))
            }
            _ => Err(method_error()),
        }
    }

    fn handle_key_list(
        &self,
        method: &str,
        config_name: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        if method != "LIST" {
            return Err(method_error());
        }
        let Some(config) = self.configs.get(config_name) else {
            return Ok(list_response(Vec::new()));
        };
        list_page(config.keys.keys(), body).map(list_response)
    }

    fn handle_key(
        &mut self,
        method: &str,
        config_name: &str,
        key_name: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        match method {
            "GET" | "HEAD" => {
                reject_unknown(body, &[])?;
                let key = self
                    .configs
                    .get(config_name)
                    .and_then(|config| config.keys.get(key_name))
                    .ok_or_else(|| error(400, &format!("key \"{key_name}\" not found")))?;
                let plugin = &self
                    .configs
                    .get(config_name)
                    .ok_or_else(|| error(400, &format!("key \"{key_name}\" not found")))?
                    .plugin;
                Ok(ok(redacted(plugin, &key.values)?, false))
            }
            "POST" | "PUT" => {
                reject_provider_verification(body)?;
                let config = self.configs.get_mut(config_name).ok_or_else(|| {
                    error(400, &format!("config \"{config_name}\" does not exist"))
                })?;
                if !config.keys.contains_key(key_name) && config.keys.len() >= MAX_KEYS_PER_CONFIG {
                    return Err(error(507, "external key mapping capacity exhausted"));
                }
                let values = filtered_values(body, &["verify"])?;
                let grants = config
                    .keys
                    .get(key_name)
                    .map(|entry| entry.grants.clone())
                    .unwrap_or_default();
                config
                    .keys
                    .insert(key_name.to_owned(), KeyEntry { values, grants });
                Ok(empty(true))
            }
            "PATCH" => {
                reject_provider_verification(body)?;
                let config = self.configs.get_mut(config_name).ok_or_else(|| {
                    error(400, &format!("config \"{config_name}\" does not exist"))
                })?;
                let key = config
                    .keys
                    .get_mut(key_name)
                    .ok_or_else(|| error(400, &format!("key \"{key_name}\" not found")))?;
                let patch = filtered_values(body, &["verify"])?;
                let mut values = key.values.clone();
                merge_patch(&mut values, &patch);
                validate_values(&values)?;
                key.values = values;
                Ok(empty(true))
            }
            "DELETE" => {
                reject_unknown(body, &[])?;
                let Some(config) = self.configs.get_mut(config_name) else {
                    return Ok(empty(false));
                };
                Ok(empty(config.keys.remove(key_name).is_some()))
            }
            _ => Err(method_error()),
        }
    }

    fn handle_grant_list(
        &self,
        method: &str,
        config_name: &str,
        key_name: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        if method != "LIST" {
            return Err(method_error());
        }
        let key = self
            .configs
            .get(config_name)
            .and_then(|config| config.keys.get(key_name))
            .ok_or_else(|| error(400, &format!("key \"{key_name}\" not found")))?;
        list_page(key.grants.iter(), body).map(list_response)
    }

    fn handle_grant(
        &mut self,
        method: &str,
        config_name: &str,
        key_name: &str,
        grant: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &[])?;
        if grant.ends_with('/') {
            return Err(bad("external key grant request must not end with a slash"));
        }
        let grant = canonical_grant(grant)?;
        let key = self
            .configs
            .get_mut(config_name)
            .and_then(|config| config.keys.get_mut(key_name))
            .ok_or_else(|| error(400, &format!("key \"{key_name}\" not found")))?;
        match method {
            "POST" | "PUT" => {
                if key.grants.len() >= MAX_GRANTS_PER_KEY && !key.grants.contains(&grant) {
                    return Err(error(507, "external key grant capacity exhausted"));
                }
                Ok(empty(key.grants.insert(grant)))
            }
            "DELETE" => Ok(empty(key.grants.remove(&grant))),
            _ => Err(method_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn call(
        registry: &mut Registry,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<EngineResponse> {
        registry.handle(method, path, &body)
    }

    #[test]
    fn verify_false_registry_matches_openbao270_crud_and_grant_shapes() -> TestResult {
        let mut registry = Registry::default();
        let empty = call(
            &mut registry,
            "LIST",
            "sys/external-keys/configs",
            json!({}),
        )?;
        assert_eq!(empty.status, 404);
        assert_eq!(empty.body, json!({"errors":[]}));

        let missing = call(
            &mut registry,
            "GET",
            "sys/external-keys/configs/demo",
            json!({}),
        )
        .err()
        .ok_or("missing config must fail")?;
        assert_eq!(missing.status, 400);

        let missing_plugin = call(
            &mut registry,
            "POST",
            "sys/external-keys/configs/demo",
            json!({"verify":false}),
        )
        .err()
        .ok_or("missing plugin must fail")?;
        assert_eq!(missing_plugin.status, 400);

        assert_eq!(
            call(
                &mut registry,
                "POST",
                "sys/external-keys/configs/demo",
                json!({"plugin":"transit","verify":false,"token":"synthetic",
                    "mount_path":"transit","namespace":""}),
            )?
            .status,
            204
        );
        let config = call(
            &mut registry,
            "GET",
            "sys/external-keys/configs/demo",
            json!({}),
        )?;
        assert_eq!(config.body["data"]["plugin"], "transit");
        assert_eq!(config.body["data"]["token"], "(redacted)");

        assert_eq!(
            call(
                &mut registry,
                "PATCH",
                "sys/external-keys/configs/demo",
                json!({"verify":false,"token":null,"mount_path":"remote"}),
            )?
            .status,
            204
        );
        let config = call(
            &mut registry,
            "GET",
            "sys/external-keys/configs/demo",
            json!({}),
        )?;
        assert!(config.body["data"].get("token").is_none());
        assert_eq!(config.body["data"]["mount_path"], "remote");

        let empty_keys = call(
            &mut registry,
            "LIST",
            "sys/external-keys/configs/demo/keys",
            json!({}),
        )?;
        assert_eq!(empty_keys.status, 404);
        assert_eq!(empty_keys.body, json!({"errors":[]}));
        assert_eq!(
            call(
                &mut registry,
                "POST",
                "sys/external-keys/configs/demo/keys/key1",
                json!({"verify":false}),
            )?
            .status,
            204
        );
        assert_eq!(
            call(
                &mut registry,
                "GET",
                "sys/external-keys/configs/demo/keys/key1",
                json!({}),
            )?
            .body,
            json!({"data":{}})
        );
        assert_eq!(
            call(
                &mut registry,
                "PUT",
                "sys/external-keys/configs/demo/keys/key1/grants/pki",
                json!({}),
            )?
            .status,
            204
        );
        assert!(
            !call(
                &mut registry,
                "PUT",
                "sys/external-keys/configs/demo/keys/key1/grants/pki",
                json!({}),
            )?
            .mutated
        );
        let trailing = call(
            &mut registry,
            "POST",
            "sys/external-keys/configs/demo/keys/key1/grants/pki/",
            json!({}),
        )
        .err()
        .ok_or("trailing grant path must fail")?;
        assert_eq!(trailing.status, 400);
        let grants = call(
            &mut registry,
            "LIST",
            "sys/external-keys/configs/demo/keys/key1/grants",
            json!({}),
        )?;
        assert_eq!(grants.body["data"]["keys"], json!(["pki/"]));
        registry.validate()?;
        Ok(())
    }

    #[test]
    fn provider_verification_refusal_is_atomic() -> TestResult {
        let mut registry = Registry::default();
        let before = serde_json::to_vec(&registry)?;
        let error = call(
            &mut registry,
            "POST",
            "sys/external-keys/configs/demo",
            json!({"plugin":"transit","token":"synthetic"}),
        )
        .err()
        .ok_or("verification must be refused")?;
        assert_eq!(error.status, 501);
        assert!(
            serde_json::to_vec(&registry)? == before,
            "rejected provider verification changed registry state"
        );

        call(
            &mut registry,
            "POST",
            "sys/external-keys/configs/demo",
            json!({"plugin":"transit","verify":false,"token":"synthetic"}),
        )?;
        let before = serde_json::to_vec(&registry)?;
        let error = call(
            &mut registry,
            "POST",
            "sys/external-keys/configs/demo/keys/key1",
            json!({"name":"remote","version":1}),
        )
        .err()
        .ok_or("key verification must be refused")?;
        assert_eq!(error.status, 501);
        assert!(
            serde_json::to_vec(&registry)? == before,
            "rejected provider verification changed registry state"
        );
        Ok(())
    }

    #[test]
    fn external_keys270_noncanonical_config_prefix_never_aliases_an_owned_route() -> TestResult {
        for path in [
            "sys/external-keys/configsdemo",
            "sys/external-keys/configs-demo",
            "sys/external-keys/configs_demo",
            "sys/external-keys/configsdemo/keys/key1",
            "sys/external-keys//configs/demo",
        ] {
            let mut registry = Registry::default();
            let result = call(
                &mut registry,
                "POST",
                path,
                json!({"plugin":"transit","verify":false}),
            );
            assert!(
                result.is_err(),
                "noncanonical external key route was admitted"
            );
            assert!(registry.is_empty(), "rejected alias changed registry state");
        }
        Ok(())
    }

    #[test]
    fn external_keys270_tls_client_key_bytes_are_redacted_without_changing_stored_values()
    -> TestResult {
        let mut registry = Registry::default();
        let config = "sys/external-keys/configs/client-auth";
        let key = "sys/external-keys/configs/client-auth/keys/mapped";
        let secret = "synthetic-external-client-private-key-canary";
        call(
            &mut registry,
            "POST",
            config,
            json!({
                "plugin":"transit", "verify":false, "tls_client_key_bytes":secret,
                "tls_client_cert_bytes":"synthetic-public-certificate",
                "tls_ca_cert_bytes":"synthetic-public-ca"
            }),
        )?;
        call(
            &mut registry,
            "POST",
            key,
            json!({"verify":false,"tls_client_key_bytes":secret}),
        )?;
        let stored = Zeroizing::new(serde_json::to_vec(&registry)?);
        for path in [config, key] {
            for method in ["GET", "HEAD"] {
                let response = call(&mut registry, method, path, json!({}))?;
                assert!(
                    response.body["data"]["tls_client_key_bytes"] == "(redacted)",
                    "private client key field was not redacted"
                );
                assert!(
                    !serde_json::to_string(&response.body)?.contains(secret),
                    "response contains synthetic private key"
                );
            }
        }
        let response = call(&mut registry, "GET", config, json!({}))?;
        assert_eq!(
            response.body["data"]["tls_client_cert_bytes"],
            "synthetic-public-certificate"
        );
        assert_eq!(
            response.body["data"]["tls_ca_cert_bytes"],
            "synthetic-public-ca"
        );
        assert!(
            stored.as_slice() == serde_json::to_vec(&registry)?,
            "read changed registry state"
        );
        let mut reopened: Registry = serde_json::from_slice(&stored)?;
        assert!(
            call(&mut reopened, "GET", config, json!({}))?.body["data"]["tls_client_key_bytes"]
                == "(redacted)"
        );
        call(
            &mut reopened,
            "PATCH",
            config,
            json!({"verify":false,"tls_client_key_bytes":null}),
        )?;
        assert!(
            call(&mut reopened, "GET", config, json!({}))?.body["data"]
                .get("tls_client_key_bytes")
                .is_none()
        );
        Ok(())
    }
}

#[cfg(test)]
mod parameter_lifetime_tests {
    use super::*;

    #[test]
    fn encoded_bound_counts_utf8_and_json_escaping_without_a_payload_buffer()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        for value in [
            json!({"token":"synthetic"}),
            json!({"control":String::from_utf8(vec![0, 10, 34, 92])?}),
            json!({"nested":{"text":"é中\n\u{0000}\"\\"},"array":[true,null,1]}),
        ] {
            let mut size = EncodedSize::default();
            assert!(serde_json::to_writer(&mut size, &value).is_ok());
            assert_eq!(size.0, serde_json::to_vec(&value)?.len());
            assert!(validate_values(&value).is_ok());
        }
        Ok(())
    }

    #[test]
    fn encoded_bound_accepts_exact_limit_and_rejects_one_extra_byte() {
        // Twelve JSON bytes surround this synthetic token value.
        let exact = SecretJson(json!({"token":"x".repeat(MAX_VALUE_BYTES - 12)}));
        let too_large = SecretJson(json!({"token":"x".repeat(MAX_VALUE_BYTES - 11)}));
        assert!(validate_values(&exact).is_ok());
        assert!(validate_values(&too_large).is_err());
    }

    #[test]
    fn merge_patch_removal_and_type_replacement_preserve_json_semantics() {
        let mut value = SecretJson(
            json!({"token":"old synthetic","nested":{"drop":"old synthetic","keep":1},"scalar":"old synthetic"}),
        );
        let patch = SecretJson(
            json!({"token":"new synthetic","nested":{"drop":null},"scalar":{"child":"new synthetic"}}),
        );
        merge_patch(&mut value, &patch);
        assert_eq!(
            *value,
            json!({"token":"new synthetic","nested":{"keep":1},"scalar":{"child":"new synthetic"}})
        );
        merge_patch(&mut value, &json!({"nested":null,"scalar":false}));
        assert_eq!(*value, json!({"token":"new synthetic","scalar":false}));
    }

    #[test]
    fn rejected_config_and_key_patches_preserve_the_installed_parameters()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut registry = Registry::default();
        let config = "sys/external-keys/configs/lifetime";
        let key = "sys/external-keys/configs/lifetime/keys/key1";
        assert!(
            registry
                .handle(
                    "POST",
                    config,
                    &json!({"plugin":"transit","verify":false,"token":"original synthetic"})
                )
                .is_ok()
        );
        assert!(
            registry
                .handle(
                    "POST",
                    key,
                    &json!({"verify":false,"name":"original","version":1})
                )
                .is_ok()
        );
        let oversized = SecretJson(json!({"verify":false,"token":"x".repeat(MAX_VALUE_BYTES)}));
        for method in ["POST", "PATCH"] {
            let mut config_body = oversized.clone();
            config_body
                .as_object_mut()
                .ok_or("synthetic object")?
                .insert("plugin".into(), json!("transit"));
            assert!(registry.handle(method, config, &config_body).is_err());
            assert!(registry.handle(method, key, &oversized).is_err());
            let installed = &registry.configs["lifetime"];
            assert_eq!(installed.values["token"], "original synthetic");
            assert_eq!(installed.keys["key1"].values["name"], "original");
            assert_eq!(installed.keys["key1"].values["version"], 1);
        }
        Ok(())
    }

    #[test]
    fn filtered_parameters_are_guarded_and_do_not_persist_control_fields()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let body =
            json!({"plugin":"transit","verify":false,"token":"synthetic","namespace":"team/"});
        let filtered = filtered_values(&body, &["plugin", "verify"])?;
        assert_eq!(*filtered, json!({"token":"synthetic","namespace":"team/"}));
        Ok(())
    }
}

#[cfg(test)]
mod verification_candidate_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn external_keys_verification_selects_only_complete_config_and_key_paths() {
        for path in [
            "sys/external-keys/configs/demo",
            "sys/external-keys/configs/demo/keys/key1",
        ] {
            assert!(verification_path(path));
        }
        for path in [
            "sys/external-keys/configsdemo",
            "sys/external-keys/configs/",
            "sys/external-keys/configs/demo/keys",
            "sys/external-keys/configs/demo/keys/",
            "sys/external-keys/configs/demo/keys/key1/grants/pki",
            "sys/external-keys/configs/demo/keys/key1/grants",
            "sys/external-keys/configs/demo/",
        ] {
            assert!(!verification_path(path), "{path}");
        }
    }

    #[test]
    fn external_keys_candidate_verifies_merged_values_without_publishing_or_changing_grants()
    -> TestResult {
        let mut state = EngineState::default();
        let config = "sys/external-keys/configs/demo";
        let key = "sys/external-keys/configs/demo/keys/key1";
        for namespace in ["", "team"] {
            for (path, body) in [
                (
                    config,
                    json!({"plugin":"transit","verify":false,
                    "address":"https://kms.example:443","token":"synthetic","nested":{"keep":1,"drop":2}}),
                ),
                (key, json!({"verify":false,"name":"remote","version":1})),
                (
                    "sys/external-keys/configs/demo/keys/key1/grants/pki",
                    json!({}),
                ),
            ] {
                let result = state
                    .handle(namespace, "POST", path, &body, 100)?
                    .ok_or("response")?;
                assert_eq!(result.status, 204);
            }
        }
        let before = zeroize::Zeroizing::new(serde_json::to_vec(&state)?);
        let verified = state
            .prepare_external_key_verification(
                "",
                "PATCH",
                config,
                &json!({"nested":{"drop":null},"mount_path":"remote"}),
            )?
            .ok_or("candidate")?;
        assert_eq!(serde_json::to_vec(&state)?, *before);
        let request = SecretJson(crate::auth::parse_strict_json(verified.request.expose())?);
        assert_eq!(request["action"], "verify_config");
        assert_eq!(request["namespace"], "");
        assert_eq!(request["values"]["nested"], json!({"keep":1}));
        assert_eq!(request["values"]["token"], "synthetic");
        assert!(request["values"].get("verify").is_none());
        let registry = &verified.candidate.namespaces[""].external_keys;
        assert_eq!(
            registry.configs["demo"].keys["key1"].grants,
            BTreeSet::from(["pki/".to_owned()])
        );
        assert_eq!(
            serde_json::to_vec(&verified.candidate.namespaces["team"])?,
            serde_json::to_vec(&state.namespaces["team"])?
        );
        let key_candidate = state
            .prepare_external_key_verification(
                "team",
                "PATCH",
                key,
                &json!({"verify":true,"version":2}),
            )?
            .ok_or("key candidate")?;
        let request = SecretJson(crate::auth::parse_strict_json(
            key_candidate.request.expose(),
        )?);
        assert_eq!(request["action"], "verify_key");
        assert_eq!(request["namespace"], "team");
        assert_eq!(request["key_values"]["name"], "remote");
        assert_eq!(request["key_values"]["version"], 2);
        assert_eq!(request["config_values"]["token"], "synthetic");
        assert_eq!(serde_json::to_vec(&state)?, *before);
        Ok(())
    }

    #[test]
    fn external_keys_grants_and_explicit_unverified_requests_never_stage_provider_io() -> TestResult
    {
        let state = EngineState::default();
        for (method, path, body) in [
            (
                "POST",
                "sys/external-keys/configs/demo/keys/key1/grants/pki",
                json!({}),
            ),
            ("DELETE", "sys/external-keys/configs/demo", json!({})),
            (
                "POST",
                "sys/external-keys/configs/demo",
                json!({"plugin":"transit","verify":false}),
            ),
            ("GET", "sys/external-keys/configs/demo", json!({})),
        ] {
            assert!(
                state
                    .prepare_external_key_verification("", method, path, &body)?
                    .is_none()
            );
        }
        assert!(
            state
                .prepare_external_key_verification(
                    "",
                    "POST",
                    "sys/external-keys/configs/demo",
                    &json!({"plugin":"transit","verify":"false"})
                )
                .is_err()
        );
        assert!(
            state
                .prepare_external_key_verification(
                    "",
                    "POST",
                    "sys/external-keys/configs/demo",
                    &json!({"plugin":"transit","token":"x".repeat(70_000)})
                )
                .is_err()
        );
        assert!(state.namespaces.is_empty());
        Ok(())
    }
}
