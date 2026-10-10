//! Read-only BYOK export with maintained RSA-OAEP and RFC5649 AES-256-KWP.
//! Public query ownership is admitted by the actual Transit mount before this route.
use super::*;
use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrapPadded};
use openssl::{
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    rsa::Padding,
};

fn export_digest(body: &Value) -> Result<MessageDigest> {
    let hash = body.get("hash")
        .map(|value| value.as_str().ok_or_else(|| bad("hash must be a string")))
        .transpose()?.unwrap_or("SHA256");
    match hash {
        "SHA1" => Ok(MessageDigest::sha1()),
        "SHA224" => Ok(MessageDigest::sha224()),
        "SHA256" => Ok(MessageDigest::sha256()),
        "SHA384" => Ok(MessageDigest::sha384()),
        "SHA512" => Ok(MessageDigest::sha512()),
        _ => Err(openbao_compatibility_error(&format!("unknown hash function: {hash}"))),
    }
}

fn destination_public(key: &Key) -> Result<PKey<Public>> {
    if !asymmetric::is_rsa(&key.kind) {
        return Err(openbao_compatibility_error(&format!(
            "key wrapping (requring message signing) is not supported for key type {}", key.kind
        )));
    }
    key.alive()?;
    let version = key.versions.get(&key.latest_version)
        .ok_or_else(|| error(500, "destination key version is unavailable"))?;
    let public = if let Some(encoded) = version.public_key_only.as_ref() {
        stored_material(encoded)?
    } else {
        let private = stored_material(&version.material)?;
        Zeroizing::new(PKey::private_key_from_der(&private)
            .and_then(|key| key.public_key_to_der())
            .map_err(|_| error(500, "stored destination key is invalid"))?)
    };
    let public = PKey::public_key_from_der(&public)
        .map_err(|_| error(500, "stored destination public key is invalid"))?;
    if public.id() != Id::RSA || !matches!(public.bits(), 2048 | 3072 | 4096) {
        return Err(error(500, "stored destination RSA key is invalid"));
    }
    Ok(public)
}

fn source_material(key: &Key, version: &KeyVersion) -> Result<Zeroizing<Vec<u8>>> {
    if version.external_key_ref.is_some() {
        return Err(error(501, "external key material cannot be wrapped for export"));
    }
    if version.public_key_only.is_some() || version.material.is_empty() {
        return Err(bad("source key version does not contain a private part"));
    }
    if derivation::is_ed(key) {
        // The imported-derived Ed25519 policy is still a distinct unsupported lane;
        // wrapping only its private PKCS8 would silently erase its derivation owner.
        return Err(error(501, "derived Ed25519 BYOK export is not implemented"));
    }
    if matches!(key.kind.as_str(),
        "aes128-gcm96" | "aes256-gcm96" | "chacha20-poly1305" | "xchacha20-poly1305")
    {
        let material = stored_material(&version.material)?;
        if material.len() != symmetric::key_len(&key.kind) {
            return Err(error(500, "stored source key material is invalid"));
        }
        return Ok(material);
    }
    if key.kind == "hmac" {
        return stored_material(backup::hmac_material(key, version));
    }
    let private = stored_material(&version.material)?;
    let encoded = if mldsa::is_kind(&key.kind) {
        mldsa::export_standard(&key.kind, &private, false, "der")?
    } else if asymmetric::is_kind(&key.kind) || key.kind == "ed25519" {
        asymmetric::export_standard(&key.kind, &private, false, "der")?
    } else {
        return Err(error(501, "source key type cannot be wrapped for export"));
    };
    let result = decode(&encoded)?;
    if !(16..=8192).contains(&result.len()) {
        return Err(error(500, "stored source private key is invalid"));
    }
    Ok(result)
}

fn wrap(public: &PKey<Public>, material: &[u8], digest: MessageDigest) -> Result<Zeroizing<Vec<u8>>> {
    let kek = random_bytes(32)?;
    let mut rsa = Encrypter::new(public).map_err(|_| error(500, "key wrapping failed"))?;
    rsa.set_rsa_padding(Padding::PKCS1_OAEP).map_err(|_| error(500, "key wrapping failed"))?;
    rsa.set_rsa_oaep_md(digest).map_err(|_| error(500, "key wrapping failed"))?;
    rsa.set_rsa_mgf1_md(digest).map_err(|_| error(500, "key wrapping failed"))?;
    let rsa_length = rsa.encrypt_len(&kek).map_err(|_| error(500, "key wrapping failed"))?;
    let mut encrypted_kek = Zeroizing::new(vec![0; rsa_length]);
    let length = rsa.encrypt(&kek, &mut encrypted_kek).map_err(|_| error(500, "key wrapping failed"))?;
    if length != rsa_length { return Err(error(500, "key wrapping failed")); }
    let kwp = AesKek::new(&AES_256, &kek).map_err(|_| error(500, "key wrapping failed"))?;
    let mut wrapped = Zeroizing::new(vec![0; material.len().checked_add(15)
        .ok_or_else(|| error(500, "key wrapping failed"))?]);
    let length = kwp.wrap_with_padding(material, &mut wrapped)
        .map_err(|_| error(500, "key wrapping failed"))?.len();
    wrapped.truncate(length);
    encrypted_kek.extend_from_slice(&wrapped);
    Ok(encrypted_kek)
}

impl Transit {
    pub(super) fn byok_export(&self, method: &str, rest: &str, body: &Value) -> Result<EngineResponse> {
        if method != "GET" { return Err(unsupported()); }
        reject_unknown(body, &["hash"])?;
        let parts: Vec<_> = rest.split('/').collect();
        if !matches!(parts.len(), 2 | 3) || parts.iter().any(|part| part.is_empty()) {
            return Err(bad("invalid BYOK export path"));
        }
        valid_path(parts[0])?;
        valid_path(parts[1])?;
        let source = self.keys.get(parts[1])
            .ok_or_else(|| openbao_compatibility_error("no such source key for export"))?;
        source.alive()?;
        if !source.exportable { return Err(bad("key is not exportable")); }
        if source.convergent_write_min_version != 0 {
            return Err(error(403, "AAD-bound convergent keys cannot export unversioned material"));
        }
        let selected = parts.get(2).map(|number| {
            if *number == "latest" { Ok(source.latest_version) }
            else { number.parse::<u64>().map_err(|_| bad("invalid key version")) }
        }).transpose()?;
        if let Some(version) = selected
            && (version < source.min_decryption_version || !source.versions.contains_key(&version))
        {
            return Err(bad("version does not exist or cannot be found"));
        }
        let destination = self.keys.get(parts[0])
            .ok_or_else(|| openbao_compatibility_error("no such destination key for export"))?;
        let public = destination_public(destination)?;
        let digest = export_digest(body)?;
        let mut keys = serde_json::Map::new();
        for (number, version) in &source.versions {
            if *number < source.min_decryption_version || selected.is_some_and(|wanted| wanted != *number) {
                continue;
            }
            let material = source_material(source, version)?;
            let ciphertext = wrap(&public, &material, digest)?;
            keys.insert(number.to_string(), json!(BASE64.encode(&ciphertext)));
        }
        Ok(ok(json!({"name":parts[1],"keys":Value::Object(keys)}), false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{encrypt::Decrypter, pkey::Private, rsa::Rsa};
    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn call(t: &mut Transit, method: &str, path: &str, body: Value) -> TestResult<EngineResponse> {
        t.handle("team", "transit/", method, path, &body, 100)
            .map_err(|_| "actual BYOK export route failed".into())
    }
    fn state(t: &Transit) -> TestResult<Zeroizing<Vec<u8>>> {
        crate::secret_serde::to_vec(t, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| "BYOK state snapshot".into())
    }
    fn independent_unwrap(private: &PKey<Private>, encoded: &Value, digest: MessageDigest)
        -> TestResult<Zeroizing<Vec<u8>>>
    {
        let bytes = Zeroizing::new(BASE64.decode(encoded.as_str().ok_or("wrapped value")?)?);
        assert!(bytes.len() >= private.size() + 16);
        let mut rsa = Decrypter::new(private)?;
        rsa.set_rsa_padding(Padding::PKCS1_OAEP)?;
        rsa.set_rsa_oaep_md(digest)?;
        rsa.set_rsa_mgf1_md(digest)?;
        let mut kek = Zeroizing::new(vec![0; private.size()]);
        let n = rsa.decrypt(&bytes[..private.size()], &mut kek)?;
        assert_eq!(n, 32);
        kek.truncate(n);
        let kwp = AesKek::new(&AES_256, &kek).map_err(|_| "independent AES KWP key")?;
        let mut material = Zeroizing::new(vec![0; bytes.len() - private.size()]);
        let n = kwp.unwrap_with_padding(&bytes[private.size()..], &mut material)
            .map_err(|_| "independent RFC5649 authentication")?.len();
        material.truncate(n);
        Ok(material)
    }

    #[test]
    fn byok270_export_versions_and_five_oaep_hashes_match_independent_kwp_without_state_effects() -> TestResult {
        let private = PKey::from_rsa(Rsa::generate(4096)?)?;
        let public = String::from_utf8(private.public_key_to_pem()?)?;
        let mut t = Transit::default();
        assert_eq!(call(&mut t, "POST", "keys/destination/import", json!({"type":"rsa-4096","public_key":public}))?.status, 204);
        assert_eq!(call(&mut t, "POST", "keys/locked", json!({"type":"aes256-gcm96"}))?.status, 200);
        let locked = state(&t)?;
        let error = t.byok_export("GET", "destination/locked/1", &json!({})).err().ok_or("locked exported")?;
        assert!(error.status == 400 && error.message == "key is not exportable");
        assert!(state(&t)?.as_slice() == locked.as_slice());
        for kind in ["aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "xchacha20-poly1305"] {
            assert_eq!(call(&mut t, "POST", &format!("keys/{kind}"), json!({"type":kind,"exportable":true}))?.status, 200);
            assert_eq!(call(&mut t, "POST", &format!("keys/{kind}/rotate"), json!({}))?.status, 200);
            let before = state(&t)?;
            for (hash, digest) in [
                ("SHA1", MessageDigest::sha1()), ("SHA224", MessageDigest::sha224()),
                ("SHA256", MessageDigest::sha256()), ("SHA384", MessageDigest::sha384()),
                ("SHA512", MessageDigest::sha512())
            ] {
                for (suffix, expected) in [("", vec!["1","2"]), ("/1", vec!["1"]), ("/latest", vec!["2"])] {
                    let result = call(&mut t, "GET", &format!("byok-export/destination/{kind}{suffix}"), json!({"hash":hash}))?;
                    assert_eq!(result.status, 200);
                    assert!(result.body["data"]["name"] == kind);
                    let keys = result.body["data"]["keys"].as_object().ok_or("version response")?;
                    assert_eq!(keys.keys().map(String::as_str).collect::<Vec<_>>(), expected);
                    for (number, encoded) in keys {
                        let material = independent_unwrap(&private, encoded, digest)?;
                        let original = stored_material(&t.keys[kind].versions[&number.parse::<u64>()?].material)
                            .map_err(|_| "actual raw source")?;
                        assert!(material.as_slice() == original.as_slice());
                    }
                    assert!(state(&t)?.as_slice() == before.as_slice());
                }
            }
            for (path, body, status, message) in [
                (format!("destination/{kind}/1"), json!({"hash":"bad"}), 500, "unknown hash function: bad"),
                (format!("destination/{kind}/999"), json!({}), 400, "version does not exist or cannot be found"),
                ("destination/missing/1".to_owned(), json!({}), 500, "no such source key for export"),
                (format!("locked/{kind}/1"), json!({}), 500, "key wrapping (requring message signing) is not supported"),
            ] {
                let error = t.byok_export("GET", &path, &body).err().ok_or("rejected export succeeded")?;
                assert!(error.status == status && error.message.contains(message));
                assert!(state(&t)?.as_slice() == before.as_slice());
            }
        }
        // Exercise the real BYOK import consumer with a distinct RSA wrapping owner.
        let mut receiver = Transit::default();
        let wrapping = call(&mut receiver, "GET", "wrapping_key", json!({}))?;
        let public = wrapping.body["data"]["public_key"].as_str().ok_or("receiver wrapping public")?;
        assert_eq!(call(&mut t, "POST", "keys/receiver/import", json!({"type":"rsa-4096","public_key":public}))?.status, 204);
        for kind in ["aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "xchacha20-poly1305"] {
            let before = state(&t)?;
            let exported = call(&mut t, "GET", &format!("byok-export/receiver/{kind}/1"), json!({}))?;
            assert!(state(&t)?.as_slice() == before.as_slice());
            let cipher = exported.body["data"]["keys"]["1"].as_str().ok_or("receiver envelope")?;
            assert_eq!(call(&mut receiver, "POST", &format!("keys/{kind}/import"), json!({"type":kind,"ciphertext":cipher}))?.status, 204);
            assert!(t.keys[kind].versions[&1].material == receiver.keys[kind].versions[&1].material);
            let encrypted = call(&mut t, "POST", &format!("encrypt/{kind}"), json!({"plaintext":"aW5kZXBlbmRlbnQgY29uc3VtZXI=","key_version":1}))?;
            let decoded = call(&mut receiver, "POST", &format!("decrypt/{kind}"), json!({"ciphertext":encrypted.body["data"]["ciphertext"]}))?;
            assert!(decoded.body["data"]["plaintext"] == "aW5kZXBlbmRlbnQgY29uc3VtZXI=");
        }
        // Reads themselves have no side effect; the subsequent encryptions are explicit mutations.
        assert!(t.keys["receiver"].versions[&1].public_key_only.is_some());
        Ok(())
    }
}
