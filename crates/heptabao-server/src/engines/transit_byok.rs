//! Authenticated AES/ML-DSA wrapped imports and canonical ML-DSA public imports.
use super::*;

#[path = "transit_byok_crypto.rs"]
mod envelope;

const MAX_ENVELOPE_BASE64: usize = 736;
const MAX_PRIVATE_BASE64: usize = 10928;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WrappingKey {
    material: String,
}

impl Drop for WrappingKey {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

impl WrappingKey {
    fn new() -> Result<Self> {
        let material = envelope::generate_wrapping_private_key()
            .map_err(|_| error(503, "wrapping key generation is unavailable"))?;
        Ok(Self {
            material: BASE64.encode(material),
        })
    }

    fn private(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.material.is_empty() || self.material.len() > MAX_PRIVATE_BASE64 {
            return Err(error(500, "stored wrapping key is invalid"));
        }
        stored_material(&self.material)
    }

    fn public_pem(&self) -> Result<String> {
        let public = envelope::wrapping_public_pem(&self.private()?)
            .map_err(|_| error(500, "stored wrapping key is invalid"))?;
        String::from_utf8(public).map_err(|_| error(500, "wrapping public key encoding failed"))
    }

    fn validate(&self) -> Result<()> {
        envelope::validate_wrapping_private_key(&self.private()?)
            .map_err(|_| bad("invalid stored wrapping key"))
    }
}

/// The marker remains after native rotation; omitted for every ordinary key.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImportPolicy {
    allow_rotation: bool,
    imported_key: bool,
}

pub(super) fn rotation_allowed(key: &Key) -> Result<()> {
    if key
        .byok
        .as_ref()
        .is_some_and(|policy| !policy.allow_rotation)
    {
        return Err(error(500, "rotation is disabled for this imported key"));
    }
    Ok(())
}

pub(super) fn native_rotation_completed(key: &mut Key) {
    if let Some(policy) = key.byok.as_mut() {
        policy.imported_key = false;
    }
}

pub(super) fn imported_key(key: &Key) -> bool {
    key.byok.as_ref().is_some_and(|policy| policy.imported_key)
}

pub(super) fn imported_key_allow_rotation(key: &Key) -> Option<bool> {
    key.byok
        .as_ref()
        .filter(|policy| policy.imported_key)
        .map(|policy| policy.allow_rotation)
}

fn digest(body: &Value) -> Result<envelope::OaepDigest> {
    let name = body
        .get("hash_function")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| bad("hash_function must be a string"))
        })
        .transpose()?
        .unwrap_or("SHA256");
    match name {
        "SHA1" => Ok(envelope::OaepDigest::Sha1),
        "SHA224" => Ok(envelope::OaepDigest::Sha224),
        "SHA256" => Ok(envelope::OaepDigest::Sha256),
        "SHA384" => Ok(envelope::OaepDigest::Sha384),
        "SHA512" => Ok(envelope::OaepDigest::Sha512),
        _ => Err(bad("unsupported wrapping hash function")),
    }
}

fn target_length(kind: &str) -> Result<usize> {
    match kind {
        "aes128-gcm96" => Ok(16),
        "aes256-gcm96" => Ok(32),
        "external-key" => Err(bad("external keys cannot be imported")),
        _ => Err(error(
            501,
            "wrapped import is unsupported for this key type",
        )),
    }
}

fn imported_version(material: Zeroizing<Vec<u8>>, now: u64) -> Result<KeyVersion> {
    let hmac_material = Zeroizing::new(random_bytes(32)?);
    Ok(KeyVersion {
        material: BASE64.encode(material),
        hmac_material: BASE64.encode(hmac_material),
        public_key_only: None,
        created_at: now,
        encryptions: 0,
        external_key_ref: None,
        heptabao_convergent_version: None,
    })
}

impl Transit {
    pub(in crate::engines) fn has_byok_state(&self) -> bool {
        self.wrapping_key.is_some() || self.keys.values().any(|key| key.byok.is_some())
    }

    pub(in crate::engines) fn validate_byok_state(&self) -> Result<()> {
        if let Some(wrapping) = self.wrapping_key.as_ref() {
            wrapping.validate()?;
        }
        for key in self.keys.values() {
            if key
                .versions
                .values()
                .any(|version| version.public_key_only.is_some())
                && (key.byok.is_none() || !mldsa::is_kind(&key.kind))
            {
                return Err(bad("public-only versions require an imported ML-DSA owner"));
            }
            if let Some(policy) = key.byok.as_ref() {
                let mldsa_key = mldsa::is_kind(&key.kind);
                let length = if mldsa_key {
                    32
                } else {
                    target_length(&key.kind)?
                };
                if (!mldsa_key && self.wrapping_key.is_none())
                    || key.derived
                    || key.convergent_encryption
                    || key.convergent_write_min_version != 0
                    || (!policy.imported_key && !policy.allow_rotation)
                    || (!policy.allow_rotation && key.auto_rotate_period != 0)
                    || key.versions.keys().next_back() != Some(&key.latest_version)
                    || key.versions.is_empty()
                {
                    return Err(bad("invalid imported key policy"));
                }
                for version in key.versions.values() {
                    if let Some(public) = version.public_key_only.as_ref() {
                        if !mldsa_key
                            || !version.material.is_empty()
                            || stored_material(&version.hmac_material)?.len() != 32
                            || version.encryptions != 0
                        {
                            return Err(bad("invalid public-only imported key version"));
                        }
                        mldsa::validate_public(&key.kind, &stored_material(public)?)?;
                    } else if stored_material(&version.material)?.len() != length
                        || stored_material(&version.hmac_material)?.len() != 32
                        || (mldsa_key && version.encryptions != 0)
                    {
                        return Err(bad("invalid imported key version"));
                    }
                    if version.external_key_ref.is_some()
                        || version.heptabao_convergent_version.is_some()
                    {
                        return Err(bad("invalid imported key version"));
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn wrapping(&mut self, method: &str, body: &Value) -> Result<EngineResponse> {
        if method != "GET" {
            return Err(unsupported());
        }
        reject_unknown(body, &[])?;
        let changed = self.wrapping_key.is_none();
        if changed {
            self.wrapping_key = Some(WrappingKey::new()?);
        }
        let public = self
            .wrapping_key
            .as_ref()
            .ok_or_else(|| error(500, "wrapping key is unavailable"))?
            .public_pem()?;
        Ok(ok(json!({"public_key": public}), changed))
    }

    fn unwrap(&self, body: &Value, kind: &str) -> Result<Zeroizing<Vec<u8>>> {
        let length = target_length(kind)?;
        let digest = digest(body)?;
        // A ciphertext takes precedence over public_key. No private plaintext path exists.
        let value = body
            .get("ciphertext")
            .and_then(Value::as_str)
            .ok_or_else(|| error(500, "wrapped key material is required"))?;
        if value.len() > MAX_ENVELOPE_BASE64 {
            return Err(error(500, "wrapped key material is invalid"));
        }
        let ciphertext = BASE64
            .decode(value)
            .map(Zeroizing::new)
            .map_err(|_| error(500, "wrapped key material is invalid"))?;
        let private = self
            .wrapping_key
            .as_ref()
            .ok_or_else(|| error(500, "wrapping key is unavailable"))?
            .private()?;
        envelope::unwrap_aes_envelope(&private, &ciphertext, length, digest)
            .map_err(|_| error(500, "wrapped key material is invalid"))
    }

    pub(super) fn import(&mut self, name: &str, body: &Value, now: u64) -> Result<EngineResponse> {
        reject_unknown(
            body,
            &[
                "type",
                "ciphertext",
                "public_key",
                "hash_function",
                "allow_rotation",
                "derived",
                "context",
                "exportable",
                "allow_plaintext_backup",
                "auto_rotate_period",
            ],
        )?;
        if self.keys.contains_key(name) {
            return Err(error(500, "key already exists"));
        }
        let kind = body
            .get("type")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("key type must be a string"))
            })
            .transpose()?
            .unwrap_or("aes256-gcm96");
        if mldsa::is_kind(kind) {
            return self.import_mldsa(name, kind, body, now);
        }
        target_length(kind)?;
        if optional_bool(body, "derived")?.unwrap_or(false) {
            return Err(error(501, "derived key imports are not implemented"));
        }
        if optional_bool(body, "allow_plaintext_backup")?.unwrap_or(false) {
            return Err(error(501, "plaintext key backups are not implemented"));
        }
        let allow_rotation = optional_bool(body, "allow_rotation")?.unwrap_or(false);
        let period = auto_rotate_period(body.get("auto_rotate_period"))?;
        if period != 0 && !allow_rotation {
            return Err(error(500, "rotation is disabled for this imported key"));
        }
        let exportable = optional_bool(body, "exportable")?.unwrap_or(false);
        let version = imported_version(self.unwrap(body, kind)?, now)?;
        self.keys.insert(
            name.into(),
            Key {
                kind: kind.into(),
                derived: false,
                convergent_encryption: false,
                convergent_write_min_version: 0,
                latest_version: 1,
                min_decryption_version: 1,
                min_encryption_version: 0,
                deletion_allowed: false,
                exportable,
                auto_rotate_period: period,
                deleted: false,
                versions: BTreeMap::from([(1, version)]),
                byok: Some(ImportPolicy {
                    allow_rotation,
                    imported_key: true,
                }),
            },
        );
        Ok(empty(true))
    }

    pub(super) fn import_version(
        &mut self,
        name: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        reject_unknown(
            body,
            &["ciphertext", "public_key", "hash_function", "version"],
        )?;
        let key = self.keys.get(name).ok_or_else(not_found)?;
        key.alive()?;
        if !imported_key(key) {
            return Err(if mldsa::is_kind(&key.kind) {
                openbao_compatibility_error(
                    "the import_version endpoint can only be used with an imported key",
                )
            } else {
                error(500, "key does not permit imported versions")
            });
        }
        if mldsa::is_kind(&key.kind) {
            return self.import_mldsa_version(name, body, now);
        }
        if body.get("version").is_some() {
            return Err(error(501, "explicit import versions are not implemented"));
        }
        if key.versions.len() >= 10_000 {
            return Err(bad("key version retention limit reached"));
        }
        let next = key
            .latest_version
            .checked_add(1)
            .ok_or_else(|| bad("key version limit reached"))?;
        let version = imported_version(self.unwrap(body, &key.kind)?, now)?;
        let key = self.keys.get_mut(name).ok_or_else(not_found)?;
        key.versions.insert(next, version);
        key.latest_version = next;
        Ok(empty(true))
    }
}

impl Transit {
    pub(in crate::engines) fn has_mldsa_import_state(&self) -> bool {
        self.keys.values().any(|key| {
            (mldsa::is_kind(&key.kind) && key.byok.is_some())
                || key
                    .versions
                    .values()
                    .any(|version| version.public_key_only.is_some())
        })
    }

    fn mldsa_imported_version(&self, body: &Value, kind: &str, now: u64) -> Result<KeyVersion> {
        if let Some(value) = body.get("ciphertext") {
            let value = value
                .as_str()
                .ok_or_else(|| bad("ciphertext must be a string"))?;
            if value.len() > 768 {
                return Err(error(500, "wrapped key material is invalid"));
            }
            let ciphertext = BASE64
                .decode(value)
                .map(Zeroizing::new)
                .map_err(|_| error(500, "wrapped key material is invalid"))?;
            let private = self
                .wrapping_key
                .as_ref()
                .ok_or_else(|| error(500, "wrapping key is unavailable"))?
                .private()?;
            let pkcs8 = envelope::unwrap_mldsa_envelope(&private, &ciphertext, digest(body)?)
                .map_err(|_| error(500, "wrapped key material is invalid"))?;
            return imported_version(mldsa::import_private(kind, &pkcs8)?, now);
        }
        let public = string(body, "public_key")?;
        let der = mldsa::import_public_pem(kind, public)?;
        let hmac_material = Zeroizing::new(random_bytes(32)?);
        Ok(KeyVersion {
            material: String::new(),
            hmac_material: BASE64.encode(hmac_material),
            public_key_only: Some(BASE64.encode(der)),
            created_at: now,
            encryptions: 0,
            external_key_ref: None,
            heptabao_convergent_version: None,
        })
    }

    fn import_mldsa(
        &mut self,
        name: &str,
        kind: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if optional_bool(body, "derived")?.unwrap_or(false) {
            return Err(error(501, "derived key imports are not implemented"));
        }
        if optional_bool(body, "allow_plaintext_backup")?.unwrap_or(false) {
            return Err(error(501, "plaintext key backups are not implemented"));
        }
        let allow_rotation = optional_bool(body, "allow_rotation")?.unwrap_or(false);
        let period = auto_rotate_period(body.get("auto_rotate_period"))?;
        if period != 0 && !allow_rotation {
            return Err(error(500, "rotation is disabled for this imported key"));
        }
        let exportable = optional_bool(body, "exportable")?.unwrap_or(false);
        let version = self.mldsa_imported_version(body, kind, now)?;
        self.keys.insert(
            name.into(),
            Key {
                kind: kind.into(),
                derived: false,
                convergent_encryption: false,
                convergent_write_min_version: 0,
                latest_version: 1,
                min_decryption_version: 1,
                min_encryption_version: 0,
                deletion_allowed: false,
                exportable,
                auto_rotate_period: period,
                deleted: false,
                versions: BTreeMap::from([(1, version)]),
                byok: Some(ImportPolicy {
                    allow_rotation,
                    imported_key: true,
                }),
            },
        );
        Ok(empty(true))
    }

    fn import_mldsa_version(
        &mut self,
        name: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        let key = self.keys.get(name).ok_or_else(not_found)?;
        let explicit = body
            .get("version")
            .map(|value| -> Result<u64> {
                let number = match value {
                    Value::Number(number) => number.as_u64(),
                    Value::String(number) => number.parse::<u64>().ok(),
                    _ => None,
                }
                .filter(|number| *number != 0)
                .ok_or_else(|| bad("version must be a positive integer"))?;
                Ok(number)
            })
            .transpose()?;
        let mut imported = self.mldsa_imported_version(body, &key.kind, now)?;
        let private = imported.public_key_only.is_none();
        let destination = explicit.or_else(|| {
            (private
                && key
                    .versions
                    .get(&key.latest_version)
                    .is_some_and(|version| version.public_key_only.is_some()))
            .then_some(key.latest_version)
        });
        let (number, append) = if let Some(number) = destination {
            let existing = key
                .versions
                .get(&number)
                .ok_or_else(|| bad("requested public-only version does not exist"))?;
            let public = existing
                .public_key_only
                .as_ref()
                .ok_or_else(|| bad("only public-only versions can be completed"))?;
            if !private {
                return Err(bad(
                    "a public-only version requires matching private material",
                ));
            }
            let expected = stored_material(public)?;
            let actual = mldsa::export_standard(
                &key.kind,
                &stored_material(&imported.material)?,
                true,
                "der",
            )?;
            if BASE64
                .decode(actual.as_bytes())
                .map_err(|_| bad("invalid derived ML-DSA public key"))?
                .as_slice()
                != expected.as_slice()
            {
                return Err(openbao_compatibility_error(
                    "cannot import key, key pair does not match",
                ));
            }
            // Completion retains the version, creation time, and independent HMAC owner.
            imported.created_at = existing.created_at;
            imported.hmac_material.clone_from(&existing.hmac_material);
            (number, false)
        } else {
            if key.versions.len() >= 10_000 {
                return Err(bad("key version retention limit reached"));
            }
            (
                key.latest_version
                    .checked_add(1)
                    .ok_or_else(|| bad("key version limit reached"))?,
                true,
            )
        };
        let key = self.keys.get_mut(name).ok_or_else(not_found)?;
        key.versions.insert(number, imported);
        if append {
            key.latest_version = number;
        }
        Ok(empty(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrapPadded};
    use openssl::{encrypt::Encrypter, hash::MessageDigest, pkey::PKey, rsa::Padding};

    type TestResult = std::result::Result<(), &'static str>;

    fn fixture() -> std::result::Result<Transit, &'static str> {
        let mut transit = Transit::default();
        let response = transit
            .wrapping("GET", &json!({}))
            .map_err(|_| "wrapping_fixture_failed")?;
        assert!(
            response.status == 200 && response.mutated,
            "first public read publishes custody"
        );
        Ok(transit)
    }

    fn wrapped(transit: &Transit, material: &[u8]) -> std::result::Result<String, &'static str> {
        let public = transit
            .wrapping_key
            .as_ref()
            .ok_or("wrapping_fixture_missing")?
            .public_pem()
            .map_err(|_| "wrapping_public_failed")?;
        let public = PKey::public_key_from_pem(public.as_bytes())
            .map_err(|_| "wrapping_public_parse_failed")?;
        let mut encrypter = Encrypter::new(&public).map_err(|_| "test_encrypter_failed")?;
        encrypter
            .set_rsa_padding(Padding::PKCS1_OAEP)
            .map_err(|_| "test_padding_failed")?;
        encrypter
            .set_rsa_oaep_md(MessageDigest::sha256())
            .map_err(|_| "test_digest_failed")?;
        encrypter
            .set_rsa_mgf1_md(MessageDigest::sha256())
            .map_err(|_| "test_mgf_failed")?;
        let mut result = vec![0; 512];
        assert!(
            encrypter
                .encrypt(&[0x41; 32], &mut result)
                .map_err(|_| "test_oaep_failed")?
                == 512
        );
        let kek = AesKek::new(&AES_256, &[0x41; 32]).map_err(|_| "test_kek_failed")?;
        let mut output = vec![0; material.len() + 15];
        result.extend_from_slice(
            kek.wrap_with_padding(material, &mut output)
                .map_err(|_| "test_kwp_failed")?,
        );
        Ok(BASE64.encode(result))
    }

    fn bytes(transit: &Transit) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
        serde_json::to_vec(transit)
            .map(Zeroizing::new)
            .map_err(|_| "test_state_encoding_failed")
    }

    #[test]
    fn ordinary_state_has_exact_legacy_fields_and_no_byok_marker() -> TestResult {
        let transit = Transit::default();
        assert!(
            bytes(&transit)?.as_slice() == b"{\"keys\":{},\"disable_upsert\":false}",
            "ordinary canonical bytes remain unchanged"
        );
        let key =
            Key::new(&json!({"type":"aes256-gcm96"}), 100).map_err(|_| "ordinary_key_failed")?;
        let encoded =
            SecretJson(serde_json::to_value(&key).map_err(|_| "test_key_encoding_failed")?);
        assert!(
            encoded.get("byok").is_none(),
            "ordinary key omits the imported policy marker"
        );
        assert!(!imported_key(&key));
        Ok(())
    }

    #[test]
    fn imported_versions_preserve_original_material_and_disable_default_rotation() -> TestResult {
        let mut transit = fixture()?;
        for (kind, length) in [("aes128-gcm96", 16), ("aes256-gcm96", 32)] {
            let first = wrapped(&transit, &vec![0x50; length])?;
            let response = transit
                .import(kind, &json!({"type":kind,"ciphertext":first}), 100)
                .map_err(|_| "test_import_failed")?;
            assert!(response.status == 204 && response.mutated);
            assert!(imported_key(&transit.keys[kind]));
            let before = bytes(&transit)?;
            let failed = transit.handle_key("POST", &format!("{kind}/rotate"), &json!({}), 101);
            assert!(
                matches!(failed, Err(EngineError { status: 500, .. })),
                "default imported rotation is rejected"
            );
            assert!(
                bytes(&transit)?.as_slice() == before.as_slice(),
                "rejected rotation preserves all state"
            );
            let next = wrapped(&transit, &vec![0x51; length])?;
            let imported = transit
                .import_version(kind, &json!({"ciphertext":next}), 102)
                .map_err(|_| "test_version_import_failed")?;
            assert!(imported.status == 204 && imported.mutated);
            let key = &transit.keys[kind];
            assert!(key.latest_version == 2 && imported_key(key));
            assert!(
                stored_material(&key.versions[&1].material)
                    .map_err(|_| "test_material_failed")?
                    .as_slice()
                    == vec![0x50; length]
            );
            assert!(
                stored_material(&key.versions[&2].material)
                    .map_err(|_| "test_material_failed")?
                    .as_slice()
                    == vec![0x51; length]
            );
        }
        transit
            .validate_byok_state()
            .map_err(|_| "test_imported_state_validation_failed")?;
        let reloaded: Transit =
            serde_json::from_slice(&bytes(&transit)?).map_err(|_| "test_reload_failed")?;
        reloaded
            .validate_byok_state()
            .map_err(|_| "test_reload_validation_failed")?;
        assert!(
            bytes(&transit)?.as_slice() == bytes(&reloaded)?.as_slice(),
            "serializer preserves imported policy and material"
        );
        Ok(())
    }

    #[test]
    fn native_manual_and_automatic_rotation_close_future_imports() -> TestResult {
        let mut transit = fixture()?;
        let ciphertext = wrapped(&transit, &[0x50; 32])?;
        for name in ["manual", "automatic"] {
            transit
                .import(
                    name,
                    &json!({"ciphertext":ciphertext,"allow_rotation":true}),
                    100,
                )
                .map_err(|_| "test_import_failed")?;
        }
        transit
            .handle_key("POST", "manual/rotate", &json!({}), 101)
            .map_err(|_| "test_rotation_failed")?;
        let key = transit
            .keys
            .get_mut("automatic")
            .ok_or("automatic_key_missing")?;
        key.configure(&json!({"auto_rotate_period":"1h"}))
            .map_err(|_| "test_rotation_configuration_failed")?;
        assert!(
            key.auto_rotate(3700)
                .map_err(|_| "test_auto_rotation_failed")?
        );
        for name in ["manual", "automatic"] {
            let key = &transit.keys[name];
            assert!(key.latest_version == 2 && !imported_key(key));
            assert!(
                key.byok.is_some(),
                "retired import policy retains the reader requirement"
            );
            let before = bytes(&transit)?;
            assert!(
                matches!(
                    transit.import_version(name, &json!({"ciphertext":ciphertext}), 3701),
                    Err(EngineError { status: 500, .. })
                ),
                "native rotation permanently closes this live key's import path"
            );
            assert!(
                bytes(&transit)?.as_slice() == before.as_slice(),
                "rejected imports preserve all state"
            );
        }
        transit
            .validate_byok_state()
            .map_err(|_| "test_rotated_state_validation_failed")?;
        Ok(())
    }

    #[test]
    fn invalid_envelopes_and_unsupported_lanes_never_publish_partial_keys() -> TestResult {
        let mut transit = fixture()?;
        let good = wrapped(&transit, &[0x50; 32])?;
        let before = bytes(&transit)?;
        for (name, body, status) in [
            ("invalid", json!({"ciphertext":"***"}), 500),
            ("short", json!({"ciphertext":BASE64.encode([0; 32])}), 500),
            (
                "digest",
                json!({"ciphertext":good,"hash_function":"unknown"}),
                400,
            ),
            (
                "wrong-digest",
                json!({"ciphertext":good,"hash_function":"SHA512"}),
                500,
            ),
            (
                "wrong-length",
                json!({"type":"aes128-gcm96","ciphertext":good}),
                500,
            ),
            (
                "external",
                json!({"type":"external-key","ciphertext":good}),
                400,
            ),
            ("derived", json!({"derived":true,"ciphertext":good}), 501),
            ("public", json!({"public_key":"PUBLIC_DUMMY"}), 500),
        ] {
            let result = transit.import(name, &body, 100);
            assert!(
                result
                    .as_ref()
                    .err()
                    .is_some_and(|failure| failure.status == status),
                "failed import has its fixed status"
            );
            assert!(
                bytes(&transit)?.as_slice() == before.as_slice(),
                "failed import has no partial publication"
            );
        }
        transit
            .import(
                "precedence",
                &json!({"ciphertext":good,"public_key":"PUBLIC_DUMMY"}),
                100,
            )
            .map_err(|_| "ciphertext_precedence_failed")?;
        assert!(imported_key(&transit.keys["precedence"]));
        Ok(())
    }
}

#[cfg(test)]
mod mldsa_import_tests {
    use super::*;
    use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrapPadded};
    use openssl::{encrypt::Encrypter, hash::MessageDigest, pkey::PKey, rsa::Padding};

    type TestResult<T = ()> = std::result::Result<T, &'static str>;

    fn encoded(transit: &Transit) -> TestResult<Zeroizing<Vec<u8>>> {
        serde_json::to_vec(transit)
            .map(Zeroizing::new)
            .map_err(|_| "state_encoding_failed")
    }

    fn wrap(transit: &Transit, material: &[u8]) -> TestResult<String> {
        let pem = transit
            .wrapping_key
            .as_ref()
            .ok_or("wrapping_missing")?
            .public_pem()
            .map_err(|_| "wrapping_public_failed")?;
        let key = PKey::public_key_from_pem(pem.as_bytes()).map_err(|_| "public_parse_failed")?;
        let mut encrypt = Encrypter::new(&key).map_err(|_| "encrypter_failed")?;
        encrypt
            .set_rsa_padding(Padding::PKCS1_OAEP)
            .map_err(|_| "padding_failed")?;
        encrypt
            .set_rsa_oaep_md(MessageDigest::sha256())
            .map_err(|_| "digest_failed")?;
        encrypt
            .set_rsa_mgf1_md(MessageDigest::sha256())
            .map_err(|_| "mgf_failed")?;
        let mut envelope = vec![0; 512];
        assert!(
            encrypt
                .encrypt(&[0x41; 32], &mut envelope)
                .map_err(|_| "rsa_failed")?
                == 512
        );
        let kek = AesKek::new(&AES_256, &[0x41; 32]).map_err(|_| "kek_failed")?;
        let mut tail = vec![0; material.len() + 15];
        envelope.extend_from_slice(
            kek.wrap_with_padding(material, &mut tail)
                .map_err(|_| "kwp_failed")?,
        );
        Ok(BASE64.encode(envelope))
    }

    fn private_der(kind: &str, seed: &[u8]) -> TestResult<Zeroizing<Vec<u8>>> {
        let encoded = mldsa::export_standard(kind, seed, false, "der")
            .map_err(|_| "private_encoding_failed")?;
        BASE64
            .decode(encoded.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| "private_decoding_failed")
    }

    fn public_pem(kind: &str, seed: &[u8]) -> TestResult<Zeroizing<String>> {
        mldsa::export_standard(kind, seed, true, "pem").map_err(|_| "public_encoding_failed")
    }

    fn call(
        transit: &mut Transit,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<EngineResponse> {
        transit.handle("", "transit", method, path, &body, 100)
    }

    #[test]
    fn mldsa270_public_only_import_preserves_independent_hmac_without_private_seed() -> TestResult {
        for kind in ["mldsa-44", "mldsa-65", "mldsa-87"] {
            let seed = [0x50; 32];
            let mut transit = Transit::default();
            let public = public_pem(kind, &seed)?;
            let imported = call(
                &mut transit,
                "POST",
                "keys/key/import",
                json!({"type":kind,"public_key":public.as_str(),"exportable":true}),
            )
            .map_err(|_| "public_import_failed")?;
            assert!(imported.status == 204 && imported.mutated);
            assert!(transit.wrapping_key.is_none());
            let version = &transit.keys["key"].versions[&1];
            assert!(
                version.material.is_empty()
                    && stored_material(&version.hmac_material)
                        .map_err(|_| "public_hmac_invalid")?.len() == 32
                    && version.public_key_only.is_some()
            );
            let before = encoded(&transit)?;
            let signature = mldsa::sign(kind, &seed, b"public fixture")
                .map_err(|_| "independent_signature_failed")?;
            let signature = format!("vault:v1:{}", BASE64.encode(signature));
            for (input, valid) in [
                (b"public fixture".as_slice(), true),
                (b"changed".as_slice(), false),
            ] {
                let response = call(
                    &mut transit,
                    "POST",
                    "verify/key",
                    json!({"input":BASE64.encode(input),"signature":signature}),
                )
                .map_err(|_| "public_verify_failed")?;
                assert!(response.body["data"]["valid"] == valid);
            }
            let input = BASE64.encode(b"public fixture");
            assert!(matches!(call(&mut transit,"POST","sign/key",json!({"input":input})),
                Err(EngineError {status:500,..})));
            let mac = call(&mut transit,"POST","hmac/key",json!({"input":input}))
                .map_err(|_| "public_hmac_failed")?.body["data"]["hmac"].clone();
            for (message,valid) in [(b"public fixture".as_slice(),true),(b"changed".as_slice(),false)] {
                let verified = call(&mut transit,"POST","verify/key",
                    json!({"input":BASE64.encode(message),"hmac":mac}))
                    .map_err(|_| "public_hmac_verify_failed")?;
                assert!(verified.status == 200 && verified.body["data"]["valid"] == valid);
            }
            for format in ["","raw","der","pem"] {
                let private = call(&mut transit,"GET","export/signing-key/key",json!({"format":format}))
                    .map_err(|_| "public_private_export_failed")?;
                assert!(private.status == 200 && private.body["data"]["keys"]["1"] == "");
                let exported = call(&mut transit,"GET","export/hmac-key/key",json!({"format":format}));
                if matches!(format,""|"raw") {
                    let exported = exported.map_err(|_| "public_hmac_export_failed")?;
                    let material = BASE64.decode(exported.body["data"]["keys"]["1"].as_str()
                        .ok_or("missing_hmac_key")?).map_err(|_| "invalid_hmac_base64")?;
                    assert!(material.len() == 32);
                    let mut independent = <Hmac<Sha256> as Mac>::new_from_slice(&material)
                        .map_err(|_| "independent_hmac_failed")?;
                    Mac::update(&mut independent,b"public fixture");
                    let tag = Mac::finalize(independent).into_bytes();
                    assert!(mac == format!("vault:v1:{}",BASE64.encode(tag)));
                } else {
                    assert!(matches!(exported,Err(EngineError {status:500,..})));
                }
            }
            let mut locked = Transit::default();
            call(&mut locked,"POST","keys/locked/import",json!({"type":kind,"public_key":public.as_str()}))
                .map_err(|_| "locked_public_import_failed")?;
            assert!(call(&mut locked,"POST","hmac/locked",json!({"input":input}))
                .map_err(|_| "locked_public_hmac_failed")?.status == 200);
            for path in ["export/signing-key/locked","export/hmac-key/locked"] {
                for format in ["","raw","der","pem"] {
                    assert!(matches!(call(&mut locked,"GET",path,json!({"format":format})),
                        Err(EngineError {status:400,..})));
                }
            }
            assert!(call(&mut locked,"GET","export/public-key/locked",json!({}))
                .map_err(|_| "locked_public_export_failed")?.status == 200);
            let raw = call(&mut transit, "GET", "export/public-key/key", json!({}))
                .map_err(|_| "public_raw_export_failed")?;
            assert!(
                raw.body["data"]["keys"]["1"]
                    == BASE64
                        .encode(mldsa::public(kind, &seed).map_err(|_| "expected_public_failed")?)
            );
            let pem = call(
                &mut transit,
                "GET",
                "export/public-key/key",
                json!({"format":"pem"}),
            )
            .map_err(|_| "public_pem_export_failed")?;
            assert!(pem.body["data"]["keys"]["1"] == public.as_str());
            assert!(encoded(&transit)?.as_slice() == before.as_slice());
            transit
                .validate_byok_state()
                .map_err(|_| "public_policy_invalid")?;
            transit
                .validate_mldsa_state()
                .map_err(|_| "public_state_invalid")?;
            let reloaded: Transit =
                serde_json::from_slice(&before).map_err(|_| "public_reload_failed")?;
            reloaded
                .validate_byok_state()
                .map_err(|_| "public_reload_invalid")?;
        }
        Ok(())
    }

    #[test]
    fn mldsa270_wrapped_private_import_is_canonical_oid_bound_and_atomic() -> TestResult {
        let mut transit = Transit::default();
        transit
            .wrapping("GET", &json!({}))
            .map_err(|_| "wrapping_failed")?;
        for kind in ["mldsa-44", "mldsa-65", "mldsa-87"] {
            let seed = [0x51; 32];
            let der = private_der(kind, &seed)?;
            let ciphertext = wrap(&transit, &der)?;
            let response = call(&mut transit, "POST", &format!("keys/{kind}/import"),
                json!({"type":kind,"ciphertext":ciphertext,"public_key":"PUBLIC_DUMMY","exportable":true}))
                .map_err(|_| "private_import_failed")?;
            assert!(response.status == 204);
            assert!(
                stored_material(&transit.keys[kind].versions[&1].material)
                    .map_err(|_| "seed_decoding_failed")?
                    .as_slice()
                    == seed
            );
            let signed = call(
                &mut transit,
                "POST",
                &format!("sign/{kind}"),
                json!({"input":BASE64.encode(b"public fixture")}),
            )
            .map_err(|_| "imported_sign_failed")?;
            let signature = signed.body["data"]["signature"]
                .as_str()
                .and_then(|value| value.strip_prefix("vault:v1:"))
                .ok_or("signature_missing")?;
            let signature = BASE64
                .decode(signature)
                .map_err(|_| "signature_decoding_failed")?;
            assert!(
                mldsa::verify(kind, &seed, b"public fixture", &signature)
                    .map_err(|_| "independent_verify_failed")?
            );
            let exported = call(
                &mut transit,
                "GET",
                &format!("export/signing-key/{kind}"),
                json!({"format":"der"}),
            )
            .map_err(|_| "private_export_failed")?;
            assert!(exported.body["data"]["keys"]["1"] == BASE64.encode(der.as_slice()));
        }
        let before = encoded(&transit)?;
        let good = private_der("mldsa-44", &[0x50; 32])?;
        let mut malformed = good.to_vec();
        malformed[20] = 0;
        let mut truncated = good.to_vec();
        truncated.pop();
        for (name, kind, bytes) in [
            ("wrong_oid", "mldsa-65", good.as_slice()),
            ("malformed", "mldsa-44", malformed.as_slice()),
            ("truncated", "mldsa-44", truncated.as_slice()),
            ("raw_seed", "mldsa-44", &[0x50; 32]),
        ] {
            let ciphertext = wrap(&transit, bytes)?;
            assert!(
                call(
                    &mut transit,
                    "POST",
                    &format!("keys/{name}/import"),
                    json!({"type":kind,"ciphertext":ciphertext})
                )
                .is_err()
            );
            assert!(encoded(&transit)?.as_slice() == before.as_slice());
        }
        transit
            .validate_byok_state()
            .map_err(|_| "private_policy_invalid")?;
        transit
            .validate_mldsa_state()
            .map_err(|_| "private_state_invalid")?;
        Ok(())
    }

    #[test]
    fn mldsa270_matching_private_completion_preserves_explicit_and_latest_versions() -> TestResult {
        let kind = "mldsa-44";
        let mut transit = Transit::default();
        transit
            .wrapping("GET", &json!({}))
            .map_err(|_| "wrapping_failed")?;
        let first = public_pem(kind, &[0x50; 32])?;
        let second = public_pem(kind, &[0x51; 32])?;
        call(
            &mut transit,
            "POST",
            "keys/key/import",
            json!({"type":kind,"public_key":first.as_str(),"allow_rotation":true}),
        )
        .map_err(|_| "initial_public_failed")?;
        call(
            &mut transit,
            "POST",
            "keys/key/import_version",
            json!({"public_key":second.as_str()}),
        )
        .map_err(|_| "next_public_failed")?;
        let input = BASE64.encode(b"public completion HMAC owner");
        let original_hmacs: Vec<Value> = [1,2].into_iter().map(|version| {
            call(&mut transit,"POST","hmac/key",json!({"input":input,"key_version":version}))
                .map(|response| response.body["data"]["hmac"].clone())
                .map_err(|_| "initial_public_hmac_failed")
        }).collect::<TestResult<Vec<Value>>>()?;
        let wrong = wrap(&transit, &private_der(kind, &[0x51; 32])?)?;
        let before = encoded(&transit)?;
        for body in [
            json!({"ciphertext":wrong,"version":1}),
            json!({"ciphertext":wrong,"version":0}),
            json!({"ciphertext":wrong,"version":3}),
            json!({"public_key":first.as_str(),"version":1}),
        ] {
            assert!(call(&mut transit, "POST", "keys/key/import_version", body).is_err());
            assert!(encoded(&transit)?.as_slice() == before.as_slice());
        }
        let private = wrap(&transit, &private_der(kind, &[0x50; 32])?)?;
        assert!(
            call(
                &mut transit,
                "POST",
                "keys/key/import_version",
                json!({"ciphertext":private,"version":1})
            )
            .map_err(|_| "explicit_fill_failed")?
            .status
                == 204
        );
        assert!(transit.keys["key"].latest_version == 2 && transit.keys["key"].versions.len() == 2);
        assert!(transit.keys["key"].versions[&1].public_key_only.is_none());
        assert!(
            call(
                &mut transit,
                "POST",
                "keys/key/import_version",
                json!({"ciphertext":wrong})
            )
            .map_err(|_| "latest_fill_failed")?
            .status
                == 204
        );
        assert!(transit.keys["key"].latest_version == 2 && transit.keys["key"].versions.len() == 2);
        for mac in original_hmacs {
            let verified = call(&mut transit,"POST","verify/key",json!({"input":input,"hmac":mac}))
                .map_err(|_| "completed_original_hmac_verify_failed")?;
            assert!(verified.status == 200 && verified.body["data"]["valid"] == true);
        }
        let before = encoded(&transit)?;
        assert!(
            call(
                &mut transit,
                "POST",
                "keys/key/import_version",
                json!({"ciphertext":private,"version":1})
            )
            .is_err()
        );
        assert!(encoded(&transit)?.as_slice() == before.as_slice());
        call(
            &mut transit,
            "POST",
            "keys/key/import_version",
            json!({"ciphertext":private}),
        )
        .map_err(|_| "next_private_failed")?;
        assert!(transit.keys["key"].latest_version == 3);
        call(&mut transit, "POST", "keys/key/rotate", json!({}))
            .map_err(|_| "native_rotate_failed")?;
        let before = encoded(&transit)?;
        assert!(
            call(
                &mut transit,
                "POST",
                "keys/key/import_version",
                json!({"ciphertext":private})
            )
            .is_err()
        );
        assert!(encoded(&transit)?.as_slice() == before.as_slice());
        call(&mut transit, "POST", "keys/generated", json!({"type":kind}))
            .map_err(|_| "generation_failed")?;
        let before = encoded(&transit)?;
        assert!(
            call(
                &mut transit,
                "POST",
                "keys/generated/import_version",
                json!({"ciphertext":private})
            )
            .is_err()
        );
        assert!(encoded(&transit)?.as_slice() == before.as_slice());
        transit
            .validate_byok_state()
            .map_err(|_| "completed_state_invalid")?;
        Ok(())
    }

    #[test]
    fn mldsa270_public_spki_rejects_cross_oid_parameters_truncation_and_forged_storage()
    -> TestResult {
        let kind = "mldsa-44";
        let mut transit = Transit::default();
        let pem = public_pem(kind, &[0x50; 32])?;
        let der = mldsa::import_public_pem(kind, &pem).map_err(|_| "fixture_public_failed")?;
        let before = encoded(&transit)?;
        let other = public_pem("mldsa-65", &[0x50; 32])?;
        for public in [
            other.as_str(),
            "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
            "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----",
        ] {
            assert!(
                call(
                    &mut transit,
                    "POST",
                    "keys/key/import",
                    json!({"type":kind,"public_key":public})
                )
                .is_err()
            );
            assert!(encoded(&transit)?.as_slice() == before.as_slice());
        }
        // Adding NULL algorithm parameters is rejected even if its OID is correct.
        let mut null_parameters = der.clone();
        null_parameters[3] += 2;
        null_parameters[5] += 2;
        drop(null_parameters.splice(17..17, [5, 0]));
        assert!(mldsa::validate_public(kind, &null_parameters).is_err());
        assert!(mldsa::validate_public(kind, &der[..der.len() - 1]).is_err());
        call(
            &mut transit,
            "POST",
            "keys/key/import",
            json!({"type":kind,"public_key":pem.as_str()}),
        )
        .map_err(|_| "valid_import_failed")?;
        let version = transit
            .keys
            .get_mut("key")
            .ok_or("owner_missing")?
            .versions
            .get_mut(&1)
            .ok_or("version_missing")?;
        version.material = BASE64.encode([0x50; 32]);
        assert!(transit.validate_byok_state().is_err() && transit.validate_mldsa_state().is_err());
        Ok(())
    }
}

#[cfg(test)]
mod hmac_export270_tests {
    use super::*;
    #[test]
    fn asymmetric270_hmac_raw_exports_real_material_and_private_permission_precedes_format() -> Result<()> {
        for kind in ["rsa-2048","ecdsa-p256"] {
            let mut transit = Transit::default();
            transit.handle("","transit","POST","keys/key",&json!({"type":kind,"exportable":true}),100)?;
            let input = BASE64.encode(b"asymmetric HMAC fixture");
            let mac = transit.handle("","transit","POST","hmac/key",&json!({"input":input}),100)?
                .body["data"]["hmac"].clone();
            for format in ["","raw","der","pem"] {
                let exported = transit.handle("","transit","GET","export/hmac-key/key/1",&json!({"format":format}),100);
                if matches!(format,""|"raw") {
                    let exported = exported?;
                    let material = BASE64.decode(exported.body["data"]["keys"]["1"].as_str().expect("HMAC key"))
                        .expect("base64 HMAC key");
                    assert_eq!(material.len(),32);
                    let mut independent = <Hmac<Sha256> as Mac>::new_from_slice(&material).expect("HMAC material");
                    Mac::update(&mut independent,b"asymmetric HMAC fixture");
                    let tag = Mac::finalize(independent).into_bytes();
                    assert_eq!(mac,format!("vault:v1:{}",BASE64.encode(tag)));
                } else {
                    assert!(matches!(exported,Err(EngineError {status:500,..})));
                }
            }
            transit.handle("","transit","POST","keys/locked",&json!({"type":kind}),100)?;
            for family in ["signing-key","hmac-key"] {
                for format in ["","raw","der","pem"] {
                    assert!(matches!(transit.handle("","transit","GET",&format!("export/{family}/locked"),
                        &json!({"format":format}),100),Err(EngineError {status:400,..})));
                }
            }
        }
        Ok(())
    }
}
