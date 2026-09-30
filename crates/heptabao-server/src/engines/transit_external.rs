//! Original bounded external-key Transit metadata. No private key is generated
//! or imported here; only references and creation times are durable.
use super::*;

pub(super) const MAX_EXTERNAL_PLAINTEXT: usize = 64 * 1024;

pub(super) fn valid_reference(reference: &str) -> bool {
    let Some((config, key)) = reference.split_once(':') else {
        return false;
    };
    [config, key].iter().all(|value| {
        !value.is_empty()
            && value.len() <= 128
            && *value != "."
            && *value != ".."
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
    })
}

pub(super) fn new_version(body: &Value, now: u64) -> Result<KeyVersion> {
    let reference = string(body, "external_key_ref")?;
    if !valid_reference(reference) {
        return Err(bad("external_key_ref must be config:key"));
    }
    Ok(KeyVersion {
        material: String::new(),
        hmac_material: String::new(),
        created_at: now,
        encryptions: 0,
        external_key_ref: Some(reference.into()),
    })
}

pub(super) fn descriptor(key: &Key, name: &str) -> Result<Value> {
    let _reference = key
        .versions
        .get(&key.latest_version)
        .and_then(|version| version.external_key_ref.as_deref())
        .ok_or_else(|| error(503, "external key reference is unavailable"))?;
    let versions = key
        .versions
        .iter()
        .map(|(number, version)| (number.to_string(), json!(version.external_key_ref)))
        .collect::<serde_json::Map<_, _>>();
    Ok(json!({"name":name,"type":"external-key","keys":versions,
        "latest_version":key.latest_version,"min_decryption_version":key.min_decryption_version,
        "min_encryption_version":key.min_encryption_version,"deletion_allowed":key.deletion_allowed,
        "exportable":false,"allow_plaintext_backup":false,"derived":false,
        "supports_derivation":false,"supports_encryption":true,"supports_decryption":true,
        "supports_signing":false,"imported_key":false,"auto_rotate_period":0,
        "soft_deleted":key.deleted,"min_available_version":0}))
}

pub(in crate::engines) struct Request {
    pub(in crate::engines) reference: String,
    pub(in crate::engines) operation: &'static str,
    pub(in crate::engines) local_version: u64,
    pub(in crate::engines) body: SecretJson,
}

fn split_ciphertext(ciphertext: &str) -> Result<(u64, Zeroizing<Vec<u8>>)> {
    let mut fields = ciphertext.splitn(3, ':');
    if fields.next() != Some("vault") {
        return Err(bad("invalid external ciphertext"));
    }
    let version = fields
        .next()
        .and_then(|field| field.strip_prefix('v'))
        .and_then(|field| field.parse::<u64>().ok())
        .filter(|version| *version > 0)
        .ok_or_else(|| bad("invalid external ciphertext version"))?;
    let encoded = fields
        .next()
        .ok_or_else(|| bad("invalid external ciphertext"))?;
    if encoded.len() > (MAX_EXTERNAL_PLAINTEXT + 64) * 4 / 3 + 4 {
        return Err(error(413, "external ciphertext exceeds bound"));
    }
    let payload = decode(encoded)?;
    if payload.len() < 28 {
        return Err(bad("invalid external ciphertext"));
    }
    if payload.len() > MAX_EXTERNAL_PLAINTEXT + 64 {
        return Err(error(413, "external ciphertext exceeds bound"));
    }
    Ok((version, payload))
}

impl Transit {
    pub(in crate::engines) fn has_external_state(&self) -> bool {
        self.keys.values().any(|key| {
            key.kind == "external-key"
                || key
                    .versions
                    .values()
                    .any(|version| version.external_key_ref.is_some())
        })
    }

    pub(in crate::engines) fn validate_external_state(&self) -> Result<()> {
        for key in self.keys.values() {
            if key.kind != "external-key" {
                if key
                    .versions
                    .values()
                    .any(|version| version.external_key_ref.is_some())
                {
                    return Err(error(503, "external reference on a local key"));
                }
                continue;
            }
            if key.exportable
                || key.auto_rotate_period != 0
                || key.versions.is_empty()
                || key.versions.len() > 10_000
                || key.versions.keys().next_back() != Some(&key.latest_version)
                || key.min_decryption_version == 0
                || key.min_decryption_version > key.latest_version
                || key.min_encryption_version > key.latest_version
                || key
                    .versions
                    .iter()
                    .enumerate()
                    .any(|(index, (number, version))| {
                        *number != index as u64 + 1
                            || !version.material.is_empty()
                            || !version.hmac_material.is_empty()
                            || version.encryptions != 0
                            || !version
                                .external_key_ref
                                .as_deref()
                                .is_some_and(valid_reference)
                    })
            {
                return Err(error(503, "invalid external key metadata"));
            }
        }
        Ok(())
    }

    pub(in crate::engines) fn external_handles(&self, path: &str) -> bool {
        let Some((operation, rest)) = path.split_once('/') else {
            return false;
        };
        let name = if operation == "datakey" {
            rest.split_once('/').map_or("", |(_, name)| name)
        } else {
            rest.split('/').next().unwrap_or("")
        };
        matches!(
            operation,
            "encrypt" | "decrypt" | "rewrap" | "hmac" | "sign" | "verify" | "datakey"
        ) && self
            .keys
            .get(name)
            .is_some_and(|key| key.kind == "external-key")
    }

    pub(in crate::engines) fn requested_external_reference<'a>(
        &'a self,
        method: &str,
        path: &str,
        body: &'a Value,
    ) -> Result<Option<&'a str>> {
        if !write_method(method) {
            return Ok(None);
        }
        let Some(rest) = path.strip_prefix("keys/") else {
            return Ok(None);
        };
        let (name, operation) = rest.split_once('/').unwrap_or((rest, ""));
        let external = body.get("type").and_then(Value::as_str) == Some("external-key")
            || self
                .keys
                .get(name)
                .is_some_and(|key| key.kind == "external-key");
        if external && (operation.is_empty() || operation == "rotate") {
            let reference = match body.get("external_key_ref") {
                Some(value) => value
                    .as_str()
                    .ok_or_else(|| bad("external_key_ref must be a string"))?,
                None => self
                    .keys
                    .get(name)
                    .and_then(|key| key.versions.get(&key.latest_version))
                    .and_then(|version| version.external_key_ref.as_deref())
                    .ok_or_else(|| bad("external_key_ref is required"))?,
            };
            if !valid_reference(reference) {
                return Err(bad("external_key_ref must be config:key"));
            }
            Ok(Some(reference))
        } else {
            Ok(None)
        }
    }

    pub(in crate::engines) fn prepare_external(
        &self,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<Request>> {
        if !self.external_handles(path) {
            return Ok(None);
        }
        if !matches!(method, "POST" | "PUT") {
            return Err(unsupported());
        }
        let (operation, name) = path.split_once('/').ok_or_else(not_found)?;
        let key = self.keys.get(name).ok_or_else(not_found)?;
        key.alive()?;
        let (operation, local_version, mut remote_body) = match operation {
            "encrypt" => {
                reject_unknown(
                    body,
                    &[
                        "plaintext",
                        "key_version",
                        "associated_data",
                        "context",
                        "nonce",
                    ],
                )?;
                reject_context(body)?;
                if string(body, "plaintext")?.len() > MAX_EXTERNAL_PLAINTEXT * 4 / 3 + 4 {
                    return Err(error(413, "external plaintext exceeds 64 KiB bound"));
                }
                let plaintext = decode_field(body, "plaintext")?;
                if plaintext.len() > MAX_EXTERNAL_PLAINTEXT {
                    return Err(error(413, "external plaintext exceeds 64 KiB bound"));
                }
                let version = key.selected_version(body)?;
                (
                    "encrypt",
                    version,
                    SecretJson(json!({"plaintext":string(body,"plaintext")?})),
                )
            }
            "decrypt" => {
                reject_unknown(body, &["ciphertext", "associated_data", "context", "nonce"])?;
                reject_context(body)?;
                let (version, payload) = split_ciphertext(string(body, "ciphertext")?)?;
                key.decrypt_version(version)?;
                (
                    "decrypt",
                    version,
                    SecretJson(json!({"ciphertext":BASE64.encode(&*payload)})),
                )
            }
            _ => return Err(error(501, "external key operation is not implemented")),
        };
        if let Some(associated) = body.get("associated_data") {
            let decoded = decode(
                associated
                    .as_str()
                    .ok_or_else(|| bad("associated_data must be base64"))?,
            )?;
            if decoded.len() > 4096 {
                return Err(error(413, "external associated data exceeds bound"));
            }
            remote_body["associated_data"] = associated.clone();
        }
        let reference = key
            .versions
            .get(&local_version)
            .and_then(|version| version.external_key_ref.as_deref())
            .ok_or_else(|| error(503, "external key reference is unavailable"))?;
        Ok(Some(Request {
            reference: reference.into(),
            operation,
            local_version,
            body: remote_body,
        }))
    }
}
