//! OpenBao 2.7 External Keys registry.
//!
//! Registry state is namespace-scoped and is published only through the existing
//! `EngineState` copy-on-write transaction. Provider verification and key use are
//! deliberately separate external-effect operations; a caller must set
//! `verify=false` until a deployment-owned KMS provider is admitted.

use super::*;

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

fn validate_values(value: &Value) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Err(bad("external key parameters must be an object"));
    };
    if object.len() > MAX_VALUE_FIELDS
        || object.keys().any(|key| {
            key.is_empty() || key.len() > MAX_NAME_BYTES || key.chars().any(char::is_control)
        })
        || serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_VALUE_BYTES)
    {
        return Err(bad("external key parameters exceed bounded storage limits"));
    }
    Ok(())
}

fn verify_requested(body: &Value) -> Result<bool> {
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

fn filtered_values(body: &Value, excluded: &[&str]) -> Result<Value> {
    let object = body
        .as_object()
        .ok_or_else(|| bad("external key request body must be an object"))?;
    let values = object
        .iter()
        .filter(|(key, _)| !excluded.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let value = Value::Object(values);
    validate_values(&value)?;
    Ok(value)
}

fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(patch) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = json!({});
    }
    let Value::Object(target) = target else {
        return;
    };
    for (key, value) in patch {
        if value.is_null() {
            target.remove(key);
        } else {
            merge_patch(target.entry(key.clone()).or_insert(Value::Null), value);
        }
    }
}

fn redacted(_plugin: &str, values: &SecretJson) -> Value {
    let mut value = values.0.clone();
    let sensitive = [
        "token",
        "tls_client_key",
        "pin",
        "password",
        "secret",
        "private_key",
        "client_secret",
    ];
    if let Some(object) = value.as_object_mut() {
        for name in sensitive {
            if object.contains_key(name) {
                object.insert(name.to_owned(), json!("(redacted)"));
            }
        }
    }
    value
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

impl Registry {
    pub(super) fn is_empty(&self) -> bool {
        self.configs.is_empty()
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
                let mut data = redacted(&entry.plugin, &entry.values);
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
                        values: SecretJson(values),
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
                let mut values = entry.values.0.clone();
                merge_patch(&mut values, &patch);
                validate_values(&values)?;
                self.configs.insert(
                    name.to_owned(),
                    ConfigEntry {
                        plugin,
                        values: SecretJson(values),
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
                Ok(ok(redacted(plugin, &key.values), false))
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
                config.keys.insert(
                    key_name.to_owned(),
                    KeyEntry {
                        values: SecretJson(values),
                        grants,
                    },
                );
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
                let mut values = key.values.0.clone();
                merge_patch(&mut values, &patch);
                validate_values(&values)?;
                key.values = SecretJson(values);
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
        assert_eq!(
            call(
                &mut registry,
                "PUT",
                "sys/external-keys/configs/demo/keys/key1/grants/pki",
                json!({}),
            )?
            .mutated,
            false
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
}
