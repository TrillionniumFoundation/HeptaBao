use super::*;
use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrapPadded};
use openssl::{
    encrypt::{Decrypter, Encrypter}, hash::MessageDigest, rsa::Padding,
    sign::{Signer, Verifier},
};

type TestResult<T = ()> = std::result::Result<T, &'static str>;
const FAMILIES: [&str; 7] = [
    "rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "ed25519",
];

fn request(t: &mut Transit, method: &str, path: &str, body: Value, now: u64) -> TestResult<EngineResponse> {
    t.handle("", "transit", method, path, &body, now).map_err(|_| "real_transit_request_failed")
}

fn fixture() -> TestResult<(Transit, PKey<Public>)> {
    let mut t = Transit::default();
    let response = request(&mut t, "GET", "wrapping_key", json!({}), 1)?;
    let public = response.body["data"]["public_key"].as_str().ok_or("wrapping_public_missing")?;
    let pair = PKey::public_key_from_pem(public.as_bytes()).map_err(|_| "wrapping_public_parse_failed")?;
    Ok((t, pair))
}

fn pair(kind: &str) -> TestResult<(Zeroizing<Vec<u8>>, PKey<Private>)> {
    let der = if kind == "ed25519" {
        Zeroizing::new(PKey::generate_ed25519().map_err(|_| "Ed_generation_failed")?
            .private_key_to_pkcs8().map_err(|_| "Ed_PKCS8_failed")?)
    } else {
        asymmetric::generate(kind).map_err(|_| "key_generation_failed")?
    };
    let key = PKey::private_key_from_pkcs8(&der).map_err(|_| "private_parse_failed")?;
    Ok((der, key))
}

fn wrapped(public: &PKey<Public>, der: &[u8], digest: MessageDigest) -> TestResult<String> {
    let mut encrypter = Encrypter::new(public).map_err(|_| "encrypter_failed")?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP).map_err(|_| "padding_failed")?;
    encrypter.set_rsa_oaep_md(digest).map_err(|_| "oaep_failed")?;
    encrypter.set_rsa_mgf1_md(digest).map_err(|_| "mgf_failed")?;
    let mut envelope = Zeroizing::new(vec![0; 512]);
    assert!(encrypter.encrypt(&[0x41; 32], &mut envelope).map_err(|_| "RSA_wrap_failed")? == 512);
    let kek = AesKek::new(&AES_256, &[0x41; 32]).map_err(|_| "KEK_failed")?;
    let mut tail = Zeroizing::new(vec![0; der.len() + 15]);
    envelope.extend_from_slice(kek.wrap_with_padding(der, &mut tail).map_err(|_| "KWP_failed")?);
    Ok(BASE64.encode(envelope.as_slice()))
}

fn sign_options(kind: &str, message: &[u8], version: u64) -> Value {
    let mut value = json!({"input":BASE64.encode(message),"key_version":version,"prehashed":false});
    if asymmetric::is_rsa(kind) { value["signature_algorithm"] = json!("pkcs1v15"); }
    if asymmetric::is_kind(kind) && !asymmetric::is_rsa(kind) { value["marshaling_algorithm"] = json!("asn1"); }
    value
}

fn signature_from_provider(kind: &str, key: &PKey<Private>, message: &[u8]) -> TestResult<Vec<u8>> {
    if kind == "ed25519" {
        return Signer::new_without_digest(key).map_err(|_| "Ed_signer_failed")?
            .sign_oneshot_to_vec(message).map_err(|_| "Ed_sign_failed");
    }
    let mut signer = Signer::new(MessageDigest::sha256(), key).map_err(|_| "signer_failed")?;
    if asymmetric::is_rsa(kind) { signer.set_rsa_padding(Padding::PKCS1).map_err(|_| "RSA_sign_padding_failed")?; }
    signer.update(message).map_err(|_| "sign_input_failed")?;
    signer.sign_to_vec().map_err(|_| "provider_sign_failed")
}

fn check_private_signature(t: &mut Transit, name: &str, kind: &str, version: u64, key: &PKey<Private>) -> TestResult {
    let message = b"independent seven-family BYOK verification";
    let algorithm = if kind == "ed25519" { "none" } else { "sha2-256" };
    let response = request(t, "POST", &format!("sign/{name}/{algorithm}"), sign_options(kind, message, version), 15)?;
    let encoded = response.body["data"]["signature"].as_str().ok_or("signature_missing")?;
    let prefix = format!("vault:v{version}:");
    let bytes = BASE64.decode(encoded.strip_prefix(&prefix).ok_or("wrong_signature_version")?)
        .map_err(|_| "signature_base64_failed")?;
    let mut verifier = if kind == "ed25519" { Verifier::new_without_digest(key) } else { Verifier::new(MessageDigest::sha256(), key) }
        .map_err(|_| "provider_verifier_failed")?;
    if asymmetric::is_rsa(kind) { verifier.set_rsa_padding(Padding::PKCS1).map_err(|_| "RSA_verify_padding_failed")?; }
    assert!(verifier.verify_oneshot(&bytes, message).map_err(|_| "provider_verify_failed")?);
    let mut verifier = if kind == "ed25519" { Verifier::new_without_digest(key) } else { Verifier::new(MessageDigest::sha256(), key) }
        .map_err(|_| "negative_verifier_failed")?;
    if asymmetric::is_rsa(kind) { verifier.set_rsa_padding(Padding::PKCS1).map_err(|_| "negative_padding_failed")?; }
    assert!(!verifier.verify_oneshot(&bytes, b"changed message").map_err(|_| "negative_verify_failed")?);
    Ok(())
}

#[test]
fn asymmetric270_all_seven_public_private_imports_match_real_signatures_versions_and_hmac() -> TestResult {
    let (mut t, wrapping) = fixture()?;
    for kind in FAMILIES {
        let (der1, first) = pair(kind)?;
        let (der2, second) = pair(kind)?;
        let pem1 = String::from_utf8(first.public_key_to_pem().map_err(|_| "public_PEM_failed")?).map_err(|_| "PEM_UTF8_failed")?;
        let pem2 = String::from_utf8(second.public_key_to_pem().map_err(|_| "second_public_PEM_failed")?).map_err(|_| "second_PEM_UTF8_failed")?;
        let cipher1 = wrapped(&wrapping, &der1, MessageDigest::sha256())?;
        let cipher2 = wrapped(&wrapping, &der2, MessageDigest::sha256())?;
        let name = kind;
        assert!(request(&mut t, "POST", &format!("keys/{name}/import"),
            json!({"type":kind,"public_key":pem1,"exportable":true}), 2)?.status == 204);
        let public_version = &t.keys[name].versions[&1];
        assert!(public_version.material.is_empty() && public_version.public_key_only.is_some());
        assert!(stored_material(&public_version.hmac_material).map_err(|_| "stored_HMAC_failed")?.len() == 32);
        let hmac_owner = Zeroizing::new(public_version.hmac_material.clone());
        let created = public_version.created_at;
        let message = b"external signature";
        let algorithm = if kind == "ed25519" { "none" } else { "sha2-256" };
        let external = signature_from_provider(kind, &first, message)?;
        for changed in [false, true] {
            let mut body = sign_options(kind, if changed { b"changed" } else { message }, 1);
            body["signature"] = json!(format!("vault:v1:{}", BASE64.encode(&external)));
            body.as_object_mut().ok_or("verification_body_not_object")?.remove("key_version");
            assert!(request(&mut t, "POST", &format!("verify/{name}/{algorithm}"), body, 3)?
                .body["data"]["valid"] == json!(!changed));
        }
        let denied = t.handle("", "transit", "POST", &format!("sign/{name}/{algorithm}"),
            &sign_options(kind, message, 1), 3).err().ok_or("public_signed_without_private")?;
        assert!(denied.status == 500 && denied.message == "1 error occurred:\n\t* requested version for signing does not contain a private part\n\n");
        let exported = request(&mut t, "GET", &format!("export/signing-key/{name}/1"), json!({"format":"der"}), 4)?;
        assert!(exported.body["data"]["keys"] == json!({"1":""}));
        let before = Zeroizing::new(serde_json::to_vec(&t).map_err(|_| "state_encoding_failed")?);
        let denied = t.handle("", "transit", "POST", &format!("keys/{name}/import_version"),
            &json!({"ciphertext":cipher2,"version":1}), 4).err().ok_or("wrong_private_completed")?;
        assert!(denied.status == 500 && denied.message.contains("key pair does not match"));
        assert!(serde_json::to_vec(&t).map(Zeroizing::new).map_err(|_| "after_state_failed")?.as_slice() == before.as_slice());
        let denied = t.handle("", "transit", "POST", &format!("keys/{name}/import_version"),
            &json!({"ciphertext":cipher1,"version":"not-an-integer"}), 4).err().ok_or("invalid_version_accepted")?;
        assert!(denied.status == 400 && denied.message == "Field validation failed: error converting input for field \"version\": '' cannot parse value as 'int': strconv.ParseInt: invalid syntax");
        assert!(serde_json::to_vec(&t).map(Zeroizing::new).map_err(|_| "invalid_version_after_failed")?.as_slice() == before.as_slice());
        let isolated = format!("{name}-different");
        request(&mut t, "POST", &format!("keys/{isolated}/import"), json!({"type":kind,"public_key":pem1,"exportable":true}), 4)?;
        request(&mut t, "POST", &format!("keys/{isolated}/import_version"), json!({"ciphertext":cipher2}), 5)?;
        assert!(t.keys[&isolated].latest_version == 2);
        assert!(stored_material(t.keys[&isolated].versions[&1].public_key_only.as_ref().ok_or("original_public_lost")?)
            .map_err(|_| "original_public_decode_failed")?.as_slice() == first.public_key_to_der().map_err(|_| "original_public_DER_failed")?);
        check_private_signature(&mut t, &isolated, kind, 2, &second)?;
        if asymmetric::is_rsa(kind) {
            let encrypted = request(&mut t, "POST", &format!("encrypt/{name}"), json!({"plaintext":BASE64.encode(b"public encryption")}), 5)?;
            let ciphertext = encrypted.body["data"]["ciphertext"].as_str().and_then(|v| v.strip_prefix("vault:v1:")).ok_or("RSA_ciphertext_missing")?;
            let ciphertext = BASE64.decode(ciphertext).map_err(|_| "RSA_ciphertext_decode_failed")?;
            let mut decrypt = Decrypter::new(&first).map_err(|_| "independent_RSA_decrypter_failed")?;
            decrypt.set_rsa_padding(Padding::PKCS1_OAEP).map_err(|_| "independent_RSA_padding_failed")?;
            decrypt.set_rsa_oaep_md(MessageDigest::sha256()).map_err(|_| "independent_RSA_hash_failed")?;
            decrypt.set_rsa_mgf1_md(MessageDigest::sha256()).map_err(|_| "independent_RSA_mgf_failed")?;
            let mut plain = Zeroizing::new(vec![0; ciphertext.len()]);
            let size = decrypt.decrypt(&ciphertext, &mut plain).map_err(|_| "independent_RSA_decrypt_failed")?;
            assert!(&plain[..size] == b"public encryption");
        }
        request(&mut t, "POST", &format!("keys/{name}/import_version"), json!({"public_key":pem2}), 6)?;
        request(&mut t, "POST", &format!("keys/{name}/import_version"), json!({"ciphertext":cipher1,"version":1}), 7)?;
        assert!(t.keys[name].latest_version == 2 && t.keys[name].versions[&1].created_at == created
            && t.keys[name].versions[&1].hmac_material == *hmac_owner);
        check_private_signature(&mut t, name, kind, 1, &first)?;
        request(&mut t, "POST", &format!("keys/{name}/import_version"), json!({"ciphertext":cipher2}), 8)?;
        assert!(t.keys[name].latest_version == 2);
        check_private_signature(&mut t, name, kind, 2, &second)?;
        request(&mut t, "POST", &format!("keys/{name}/import_version"), json!({"ciphertext":cipher1}), 9)?;
        assert!(t.keys[name].latest_version == 3);
        check_private_signature(&mut t, name, kind, 3, &first)?;
        let descriptor = request(&mut t, "GET", &format!("keys/{name}"), json!({}), 9)?;
        assert!(descriptor.body["data"]["imported_key"] == json!(true));
        assert!(descriptor.body["data"]["imported_key_allow_rotation"] == json!(false));
        let before = Zeroizing::new(serde_json::to_vec(&t).map_err(|_| "rotation_before_failed")?);
        let denied = t.handle("", "transit", "POST", &format!("keys/{name}/rotate"), &json!({}), 10)
            .err().ok_or("forbidden_native_rotation_accepted")?;
        assert!(denied.status == 500 && denied.message == format!("1 error occurred:\n\t* imported key {name} does not allow rotation within Vault\n\n"));
        assert!(serde_json::to_vec(&t).map(Zeroizing::new).map_err(|_| "rotation_after_failed")?.as_slice() == before.as_slice());
        let rot = format!("{kind}-rotation");
        request(&mut t, "POST", &format!("keys/{rot}/import"),
            json!({"type":kind,"ciphertext":cipher1,"allow_rotation":true}), 10)?;
        request(&mut t, "POST", &format!("keys/{rot}/rotate"), json!({}), 11)?;
        assert!(!byok::imported_key(&t.keys[&rot]));
        let before = Zeroizing::new(serde_json::to_vec(&t).map_err(|_| "rotated_state_failed")?);
        assert!(t.handle("", "transit", "POST", &format!("keys/{rot}/import_version"),
            &json!({"ciphertext":cipher1}), 12).err().is_some_and(|e| e.status == 500));
        assert!(serde_json::to_vec(&t).map(Zeroizing::new).map_err(|_| "rotated_after_failed")?.as_slice() == before.as_slice());
        assert!(t.validate_byok_state().is_ok());
    }
    Ok(())
}

#[test]
fn asymmetric270_standard_imports_reject_cross_family_oid_bad_envelopes_and_forged_state_atomically() -> TestResult {
    let (mut t, wrapping) = fixture()?;
    let (der, private) = pair("ecdsa-p384")?;
    let public = private.public_key_to_der().map_err(|_| "public_DER_failed")?;
    assert!(import_private("ecdsa-p256", &der).is_err());
    assert!(validate_public("ecdsa-p256", &public).is_err());
    let mut trailing = der.to_vec(); trailing.push(0);
    assert!(import_private("ecdsa-p384", &trailing).is_err());
    let mut trailing = public.clone(); trailing.push(0);
    assert!(validate_public("ecdsa-p384", &trailing).is_err());
    let mut bad_oid = public.clone();
    let at = bad_oid.windows(7).position(|v| v == [6, 5, 43, 129, 4, 0, 34]).ok_or("curve_OID_missing")?;
    bad_oid[at+6] = 35;
    assert!(validate_public("ecdsa-p384", &bad_oid).is_err());
    let cipher = wrapped(&wrapping, &der, MessageDigest::sha256())?;
    let mut corrupt = Zeroizing::new(BASE64.decode(&cipher).map_err(|_| "envelope_decode_failed")?);
    let end = corrupt.len()-1; corrupt[end] ^= 1;
    let before = Zeroizing::new(serde_json::to_vec(&t).map_err(|_| "before_failed")?);
    for ciphertext in [BASE64.encode(corrupt.as_slice()), BASE64.encode(&corrupt[..corrupt.len()-1])] {
        assert!(t.handle("", "transit", "POST", "keys/invalid/import",
            &json!({"type":"ecdsa-p384","ciphertext":ciphertext}), 2).is_err());
        assert!(serde_json::to_vec(&t).map(Zeroizing::new).map_err(|_| "after_failed")?.as_slice() == before.as_slice());
    }
    let pem = String::from_utf8(private.public_key_to_pem().map_err(|_| "PEM_failed")?).map_err(|_| "UTF8_failed")?;
    request(&mut t, "POST", "keys/public/import", json!({"type":"ecdsa-p384","public_key":pem}), 3)?;
    let pristine = t.clone();
    t.keys.get_mut("public").ok_or("key_missing")?.versions.get_mut(&1).ok_or("version_missing")?.material = BASE64.encode(&public);
    assert!(t.validate_byok_state().is_err());
    t = pristine.clone();
    t.keys.get_mut("public").ok_or("key_missing")?.versions.get_mut(&1).ok_or("version_missing")?.hmac_material = BASE64.encode(&public);
    assert!(t.validate_byok_state().is_err());
    t = pristine;
    t.keys.get_mut("public").ok_or("key_missing")?.byok = None;
    assert!(t.validate_byok_state().is_err());
    Ok(())
}

#[test]
fn asymmetric270_generic_pkcs8_envelopes_authenticate_all_five_hashes_without_relaxing_old_profiles() -> TestResult {
    let (mut t, wrapping) = fixture()?;
    let (der, _) = pair("ed25519")?;
    assert!(der.len() == 48);
    for (name, digest) in [
        ("SHA1", MessageDigest::sha1()), ("SHA224", MessageDigest::sha224()),
        ("SHA256", MessageDigest::sha256()), ("SHA384", MessageDigest::sha384()),
        ("SHA512", MessageDigest::sha512()),
    ] {
        let cipher = wrapped(&wrapping, &der, digest)?;
        request(&mut t, "POST", &format!("keys/{name}/import"),
            json!({"type":"ed25519","ciphertext":cipher,"hash_function":name}), 2)?;
        assert!(t.validate_byok_state().is_ok());
    }
    let cipher = wrapped(&wrapping, &der, MessageDigest::sha256())?;
    assert!(t.handle("", "transit", "POST", "keys/not-AES/import",
        &json!({"type":"aes256-gcm96","ciphertext":cipher}), 3).is_err());
    assert!(t.handle("", "transit", "POST", "keys/not-MLDSA/import",
        &json!({"type":"mldsa-44","ciphertext":cipher}), 3).is_err());
    Ok(())
}
