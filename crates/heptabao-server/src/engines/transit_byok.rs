//! AES-only wrapped key import. Public-key-only and other types remain unsupported.
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
    Ok(KeyVersion {
        material: BASE64.encode(material),
        hmac_material: BASE64.encode(random_bytes(32)?),
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
            if let Some(policy) = key.byok.as_ref() {
                let length = target_length(&key.kind)?;
                if self.wrapping_key.is_none()
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
                    if stored_material(&version.material)?.len() != length
                        || stored_material(&version.hmac_material)?.len() != 32
                        || version.external_key_ref.is_some()
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
            return Err(error(500, "key does not permit imported versions"));
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
