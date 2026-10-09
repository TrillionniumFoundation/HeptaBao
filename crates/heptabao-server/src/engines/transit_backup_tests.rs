//! Real Transit routes plus independently generated, deliberately public SDK fixtures.
use super::*;
use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrapPadded};
use openssl::{encrypt::Encrypter, hash::MessageDigest, pkey::PKey, rsa::Padding};

type TestResult<T = ()> = std::result::Result<T, &'static str>;

fn call(
    transit: &mut Transit,
    method: &str,
    path: &str,
    body: &Value,
) -> TestResult<EngineResponse> {
    transit
        .handle("team", "transit", method, path, body, 100)
        .map_err(|_| "real_transit_route_failed")
}

fn encoded(transit: &Transit) -> TestResult<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(transit)
        .map(Zeroizing::new)
        .map_err(|_| "state_encoding_failed")
}

fn envelope(transit: &Transit, material: &[u8]) -> TestResult<String> {
    let pem = transit
        .wrapping_key
        .as_ref()
        .ok_or("wrapping_missing")?
        .public_pem()
        .map_err(|_| "wrapping_public_failed")?;
    let public = PKey::public_key_from_pem(pem.as_bytes()).map_err(|_| "public_parse_failed")?;
    let mut rsa = Encrypter::new(&public).map_err(|_| "encrypter_failed")?;
    rsa.set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|_| "padding_failed")?;
    rsa.set_rsa_oaep_md(MessageDigest::sha256())
        .map_err(|_| "digest_failed")?;
    rsa.set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(|_| "mgf_failed")?;
    let mut out = vec![0; 512];
    assert!(
        rsa.encrypt(&[0x41; 32], &mut out)
            .map_err(|_| "oaep_failed")?
            == 512
    );
    let kek = AesKek::new(&AES_256, &[0x41; 32]).map_err(|_| "kek_failed")?;
    let mut tail = vec![0; material.len() + 15];
    out.extend_from_slice(
        kek.wrap_with_padding(material, &mut tail)
            .map_err(|_| "kwp_failed")?,
    );
    Ok(BASE64.encode(out))
}

fn fixture() -> TestResult<Transit> {
    let mut t = Transit::default();
    assert!(call(&mut t, "GET", "wrapping_key", &json!({}))?.status == 200);
    Ok(t)
}

fn wire_fixture(kind: &str, kdf: u8, derived: bool) -> TestResult<Value> {
    let code = kind_code(kind).map_err(|_| "kind_failed")?;
    let version = |byte, time: &str| {
        let mut e = Entry::empty();
        e.key = Some(BASE64.encode(vec![byte; symmetric::key_len(kind)]));
        e.hmac_key = Some(BASE64.encode([0x71; 32]));
        e.time = time.into();
        e.creation_time = 100;
        e
    };
    let a = version(0x51, "1970-01-01T00:01:40.123456789Z");
    let b = version(0x61, "1969-12-31T19:01:40.987654321-05:00");
    let wire = Backup {
        policy: Policy {
            name: "original".into(),
            keys: BTreeMap::from([("1".into(), a.clone()), ("2".into(), b.clone())]),
            derived,
            kdf,
            convergent_encryption: false,
            exportable: true,
            min_decryption_version: 1,
            min_encryption_version: 0,
            latest_version: 2,
            archive_version: 2,
            archive_min_version: 0,
            min_available_version: 0,
            deletion_allowed: false,
            convergent_version: 0,
            kind: code,
            backup_info: None,
            restore_info: None,
            allow_plaintext_backup: true,
            version_template: String::new(),
            storage_prefix: String::new(),
            auto_rotate_period: 0,
            imported: kdf == 0,
            allow_imported_rotation: true,
            soft_deleted: false,
            key_size: None,
        },
        archived_keys: Archived {
            keys: vec![Entry::empty(), a, b],
        },
    };
    serde_json::to_value(&wire).map_err(|_| "wire_encoding_failed")
}

fn restore_wire(t: &mut Transit, name: &str, wire: &Value) -> TestResult {
    let bytes = Zeroizing::new(serde_json::to_vec(wire).map_err(|_| "wire_encoding_failed")?);
    assert!(
        call(
            t,
            "POST",
            &format!("restore/{name}"),
            &json!({"backup":BASE64.encode(bytes.as_slice())})
        )?
        .status
            == 204
    );
    Ok(())
}

fn sdk_open(kind: &str, key: &[u8], ciphertext: &str) -> TestResult<Zeroizing<Vec<u8>>> {
    let bytes = BASE64
        .decode(
            ciphertext
                .strip_prefix("vault:v1:")
                .ok_or("wrong_version")?,
        )
        .map(Zeroizing::new)
        .map_err(|_| "ciphertext_decode_failed")?;
    let nonce_len = if kind == "xchacha20-poly1305" { 24 } else { 12 };
    if bytes.len() < nonce_len + 16 {
        return Err("ciphertext_short");
    }
    if nonce_len == 24 {
        let cipher =
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| "independent_key_failed")?;
        let mut payload = Zeroizing::new(bytes[24..].to_vec());
        cipher
            .decrypt_in_place(XNonce::from_slice(&bytes[..24]), &[], &mut *payload)
            .map_err(|_| "independent_authentication_failed")?;
        return Ok(payload);
    }
    let cipher = match kind {
        "aes128-gcm96" => openssl::symm::Cipher::aes_128_gcm(),
        "aes256-gcm96" => openssl::symm::Cipher::aes_256_gcm(),
        "chacha20-poly1305" => openssl::symm::Cipher::chacha20_poly1305(),
        _ => return Err("independent_kind_failed"),
    };
    openssl::symm::decrypt_aead(
        cipher,
        key,
        Some(&bytes[..12]),
        &[],
        &bytes[12..bytes.len() - 16],
        &bytes[bytes.len() - 16..],
    )
    .map(Zeroizing::new)
    .map_err(|_| "independent_authentication_failed")
}

#[test]
fn symmetric270_kdf0_and_kdf1_are_distinct_and_match_independent_sdk_vectors() -> TestResult {
    let vectors: Value = serde_json::from_str(include_str!("transit_backup_sdk_vectors.json"))
        .map_err(|_| "vectors_parse_failed")?;
    let rows = vectors["vectors"].as_array().ok_or("vectors_missing")?;
    assert!(rows.len() == 16);
    let mut t = fixture()?;
    for (index, row) in rows.iter().enumerate() {
        let kind = row["kind"].as_str().ok_or("kind_missing")?;
        let kdf =
            u8::try_from(row["kdf"].as_u64().ok_or("kdf_missing")?).map_err(|_| "kdf_range")?;
        let name = format!("matrix{index}");
        restore_wire(&mut t, &name, &wire_fixture(kind, kdf, true)?)?;
        let context = row["context"].as_str().ok_or("context_missing")?;
        let message = row["message"].as_str().ok_or("message_missing")?;
        let ciphertext = row["ciphertext"].as_str().ok_or("ciphertext_missing")?;
        let known_key = BASE64
            .decode(
                row["synthetic_public_known_derived_key"]
                    .as_str()
                    .ok_or("key_missing")?,
            )
            .map(Zeroizing::new)
            .map_err(|_| "key_decode_failed")?;
        let plaintext = BASE64
            .decode(message)
            .map(Zeroizing::new)
            .map_err(|_| "message_decode_failed")?;
        assert!(sdk_open(kind, &known_key, ciphertext)?.as_slice() == plaintext.as_slice());
        let encrypted = call(
            &mut t,
            "POST",
            &format!("encrypt/{name}"),
            &json!({"context":context,"plaintext":message,"key_version":1}),
        )?;
        let produced = encrypted.body["data"]["ciphertext"]
            .as_str()
            .ok_or("encryption_missing")?;
        assert!(
            sdk_open(kind, &known_key, produced)?.as_slice() == plaintext.as_slice(),
            "production encryption must authenticate using the independent derived key"
        );
        let before = encoded(&t)?;
        let decoded = t.handle(
            "team",
            "transit",
            "POST",
            &format!("decrypt/{name}"),
            &json!({"context":context,"ciphertext":ciphertext}),
            100,
        );
        if kind == "aes128-gcm96" && kdf == 0 {
            let failed = decoded.err().ok_or("vendor_limitation_missing")?;
            assert!(
                failed.status == 500
                    && failed.message
                        == "1 error occurred:\n\t* could not derive enc key, length not correct\n\n"
            );
        } else {
            let decoded = decoded.map_err(|_| "vector_decrypt_failed")?;
            assert!(decoded.status == 200 && decoded.body["data"]["plaintext"] == message);
            let changed = t.handle(
                "team",
                "transit",
                "POST",
                &format!("decrypt/{name}"),
                &json!({"context":BASE64.encode(b"changed-context"),"ciphertext":ciphertext}),
                100,
            );
            assert!(
                changed.is_err(),
                "another context cannot authenticate this ciphertext"
            );
        }
        let mut corrupt = BASE64
            .decode(
                ciphertext
                    .strip_prefix("vault:v1:")
                    .ok_or("version_missing")?,
            )
            .map_err(|_| "decode_failed")?;
        let last = corrupt.last_mut().ok_or("empty_ciphertext")?;
        *last ^= 1;
        let corrupt = format!("vault:v1:{}", BASE64.encode(corrupt));
        assert!(sdk_open(kind, &known_key, &corrupt).is_err());
        assert!(
            t.handle(
                "team",
                "transit",
                "POST",
                &format!("decrypt/{name}"),
                &json!({"context":context,"ciphertext":corrupt}),
                100
            )
            .is_err()
        );
        assert!(
            t.handle(
                "team",
                "transit",
                "POST",
                &format!("decrypt/{name}"),
                &json!({"ciphertext":ciphertext}),
                100
            )
            .is_err()
        );
        assert!(
            encoded(&t)?.as_slice() == before.as_slice(),
            "all decrypt attempts preserve complete state"
        );
        assert!(t.keys[&name].legacy_counter_kdf == (kdf == 0));
        t.validate_byok_state()
            .map_err(|_| "matrix_state_invalid")?;
    }
    Ok(())
}

#[test]
fn symmetric270_wrapped_four_family_import_append_backup_restore_and_hmac_continuity() -> TestResult
{
    let mut t = fixture()?;
    for (kind, length) in [
        ("aes128-gcm96", 16),
        ("aes256-gcm96", 32),
        ("chacha20-poly1305", 32),
        ("xchacha20-poly1305", 32),
    ] {
        for derived in [false, true] {
            let name = format!("{kind}-{}", u8::from(derived));
            let first = envelope(&t, &vec![0x51; length])?;
            assert!(
                call(
                    &mut t,
                    "POST",
                    &format!("keys/{name}/import"),
                    &json!({"type":kind,"ciphertext":first,"derived":derived,
                    "context":BASE64.encode(b"import-context"),"exportable":true,
                    "allow_rotation":true,"allow_plaintext_backup":true})
                )?
                .status
                    == 204
            );
            let hmac_first = t.keys[&name].versions[&1].hmac_material.clone();
            let second = envelope(&t, &vec![0x61; length])?;
            assert!(
                call(
                    &mut t,
                    "POST",
                    &format!("keys/{name}/import_version"),
                    &json!({"ciphertext":second})
                )?
                .status
                    == 204
            );
            let exported = call(
                &mut t,
                "GET",
                &format!("export/encryption-key/{name}"),
                &json!({}),
            )?;
            assert!(
                exported.body["data"]["keys"]["1"] == BASE64.encode(vec![0x51; length])
                    && exported.body["data"]["keys"]["2"] == BASE64.encode(vec![0x61; length])
            );
            let hmac = call(
                &mut t,
                "POST",
                &format!("hmac/{name}/sha2-256"),
                &json!({"input":BASE64.encode(b"independent HMAC message"),"key_version":1}),
            )?;
            let secret = BASE64
                .decode(&hmac_first)
                .map(Zeroizing::new)
                .map_err(|_| "hmac_decode_failed")?;
            let independent = openssl::pkey::PKey::hmac(&secret).map_err(|_| "hmac_key_failed")?;
            let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &independent)
                .map_err(|_| "hmac_signer_failed")?;
            signer
                .update(b"independent HMAC message")
                .map_err(|_| "hmac_update_failed")?;
            let expected = format!(
                "vault:v1:{}",
                BASE64.encode(signer.sign_to_vec().map_err(|_| "hmac_sign_failed")?)
            );
            assert!(hmac.body["data"]["hmac"] == expected);
            let backup = call(&mut t, "GET", &format!("backup/{name}"), &json!({}))?;
            let blob = backup.body["data"]["backup"]
                .as_str()
                .ok_or("backup_missing")?;
            let raw = BASE64
                .decode(blob)
                .map(Zeroizing::new)
                .map_err(|_| "backup_decode_failed")?;
            let wire: Value = serde_json::from_slice(&raw).map_err(|_| "backup_parse_failed")?;
            assert!(
                wire["policy"]["kdf"] == 0
                    && wire["policy"]["type"] == kind_code(kind).map_err(|_| "kind_code_failed")?
            );
            assert!(wire["policy"]["keys"]["1"]["hmac_key"] == hmac_first);
            let restored = format!("{name}-copy");
            assert!(
                call(
                    &mut t,
                    "POST",
                    &format!("restore/{restored}"),
                    &json!({"backup":blob})
                )?
                .status
                    == 204
            );
            assert!(t.keys[&restored].latest_version == 2 && t.keys[&restored].derived == derived);
            let after_hmac = call(
                &mut t,
                "POST",
                &format!("hmac/{restored}/sha2-256"),
                &json!({"input":BASE64.encode(b"independent HMAC message"),"key_version":1}),
            )?;
            assert!(
                after_hmac.body["data"]["hmac"] == expected,
                "restored HMAC retains the independent original material"
            );
            for version in [1, 2] {
                assert!(
                    t.keys[&restored].versions[&version].material
                        == t.keys[&name].versions[&version].material
                        && t.keys[&restored].versions[&version].hmac_material
                            == t.keys[&name].versions[&version].hmac_material
                );
            }
            let before = encoded(&t)?;
            let duplicate = t.handle(
                "team",
                "transit",
                "POST",
                &format!("restore/{restored}"),
                &json!({"backup":blob}),
                100,
            );
            assert!(matches!(duplicate, Err(EngineError { status: 500, .. })));
            assert!(encoded(&t)?.as_slice() == before.as_slice());
            assert!(
                call(
                    &mut t,
                    "POST",
                    &format!("restore/{restored}"),
                    &json!({"backup":blob,"force":true})
                )?
                .status
                    == 204
            );
            assert!(
                call(
                    &mut t,
                    "POST",
                    &format!("keys/{restored}/config"),
                    &json!({"allow_plaintext_backup":false})
                )?
                .status
                    == 200
            );
            assert!(
                t.keys[&restored].allow_plaintext_backup,
                "backup permission is irreversible"
            );
            assert!(
                call(
                    &mut t,
                    "POST",
                    &format!("keys/{restored}/rotate"),
                    &json!({})
                )?
                .status
                    == 200
            );
            assert!(
                t.keys[&restored].latest_version == 3 && !byok::imported_key(&t.keys[&restored])
            );
            let closed = encoded(&t)?;
            let next_envelope = envelope(&t, &vec![0x51; length])?;
            let import = t.handle(
                "team",
                "transit",
                "POST",
                &format!("keys/{restored}/import_version"),
                &json!({"ciphertext":next_envelope}),
                100,
            );
            assert!(matches!(import, Err(EngineError { status: 500, .. })));
            assert!(encoded(&t)?.as_slice() == closed.as_slice());
        }
    }
    let reloaded: Transit =
        serde_json::from_slice(&encoded(&t)?).map_err(|_| "restart_decode_failed")?;
    reloaded
        .validate_byok_state()
        .map_err(|_| "restart_state_failed")?;
    assert!(encoded(&t)?.as_slice() == encoded(&reloaded)?.as_slice());
    Ok(())
}

#[test]
fn symmetric270_backup_restore_preserves_wire_nanoseconds_and_rejects_ambiguous_or_corrupt_state()
-> TestResult {
    let mut t = fixture()?;
    let valid = wire_fixture("aes256-gcm96", 0, true)?;
    restore_wire(&mut t, "restored", &valid)?;
    let output = call(&mut t, "GET", "backup/restored", &json!({}))?;
    let raw = BASE64
        .decode(
            output.body["data"]["backup"]
                .as_str()
                .ok_or("backup_missing")?,
        )
        .map(Zeroizing::new)
        .map_err(|_| "decode_failed")?;
    let back: Value = serde_json::from_slice(&raw).map_err(|_| "parse_failed")?;
    for n in ["1", "2"] {
        for field in ["key", "hmac_key", "time", "creation_time"] {
            assert!(
                back["policy"]["keys"][n][field] == valid["policy"]["keys"][n][field],
                "backup restores original secret versions and precise timestamp spelling"
            );
        }
    }
    let before = encoded(&t)?;
    let mut invalids = Vec::new();
    for (path, value) in [
        (vec!["policy", "kdf"], json!(2)),
        (vec!["policy", "latest_version"], json!(10001)),
        (vec!["policy", "convergent_encryption"], json!(true)),
        (vec!["policy", "version_template"], json!("unsupported")),
        (vec!["policy", "keys", "1", "creation_time"], json!(101)),
        (vec!["policy", "keys", "1", "time"], json!("not-time")),
        (
            vec!["policy", "keys", "1", "key"],
            json!(BASE64.encode([0; 16])),
        ),
        (
            vec!["policy", "keys", "1", "hmac_key"],
            json!(BASE64.encode([0; 16])),
        ),
        (
            vec!["policy", "keys", "1", "rsa_key"],
            json!({"unexpected":true}),
        ),
        (vec!["policy", "keys", "1", "extra"], json!(true)),
    ] {
        let mut changed = valid.clone();
        let mut target = &mut changed;
        for component in &path[..path.len() - 1] {
            target = &mut target[*component];
        }
        target[path[path.len() - 1]] = value;
        invalids.push(serde_json::to_vec(&changed).map_err(|_| "invalid_encoding_failed")?);
    }
    let mut unknown = valid.clone();
    unknown["unknown"] = json!(true);
    invalids.push(serde_json::to_vec(&unknown).map_err(|_| "invalid_encoding_failed")?);
    let serialized = serde_json::to_string(&valid).map_err(|_| "invalid_encoding_failed")?;
    let marker = "\"keys\":{";
    let first = serde_json::to_string(&valid["policy"]["keys"]["1"])
        .map_err(|_| "entry_encoding_failed")?;
    let duplicate = serialized.replacen(marker, &format!("{marker}\"1\":{first},"), 1);
    invalids.push(duplicate.into_bytes());
    for raw in invalids {
        assert!(
            t.handle(
                "team",
                "transit",
                "POST",
                "restore/restored",
                &json!({"backup":BASE64.encode(raw),"force":true}),
                100
            )
            .is_err()
        );
        assert!(
            encoded(&t)?.as_slice() == before.as_slice(),
            "invalid force restore cannot publish partial material"
        );
    }
    assert!(
        t.handle(
            "team",
            "transit",
            "POST",
            "restore/new",
            &json!({"backup":"A".repeat(MAX_BACKUP_BYTES*4/3+5)}),
            100
        )
        .is_err()
    );
    assert!(encoded(&t)?.as_slice() == before.as_slice());
    let mut malformed = t.clone();
    let key = malformed.keys.get_mut("restored").ok_or("key_missing")?;
    key.backup_metadata
        .as_mut()
        .ok_or("metadata_missing")?
        .version_times
        .insert(1, "bad-time".into());
    assert!(
        malformed.validate_byok_state().is_err(),
        "persisted invalid timestamps fail closed"
    );
    let mut malformed = t.clone();
    malformed
        .keys
        .get_mut("restored")
        .ok_or("key_missing")?
        .versions
        .get_mut(&1)
        .ok_or("version_missing")?
        .hmac_material = BASE64.encode([0; 16]);
    assert!(
        malformed.validate_byok_state().is_err(),
        "persisted wrong HMAC length fails closed"
    );
    Ok(())
}

#[test]
fn symmetric270_legacy_default_serialization_and_protected_convergent_backup_fences() -> TestResult
{
    let legacy =
        Key::new(&json!({"type":"aes256-gcm96"}), 100).map_err(|_| "key_creation_failed")?;
    let raw = SecretJson(serde_json::to_value(&legacy).map_err(|_| "key_encoding_failed")?);
    for field in [
        "legacy_counter_kdf",
        "allow_plaintext_backup",
        "backup_metadata",
    ] {
        assert!(
            raw.get(field).is_none(),
            "default AES omits all schema119 additions"
        );
    }
    let native = Key::new(&json!({"type":"aes256-gcm96","derived":true}), 100)
        .map_err(|_| "key_creation_failed")?;
    let known: Value = serde_json::from_str(include_str!("transit_backup_sdk_vectors.json"))
        .map_err(|_| "vectors_failed")?;
    let row = known["vectors"]
        .as_array()
        .ok_or("vectors_missing")?
        .iter()
        .find(|r| r["kind"] == "aes256-gcm96" && r["kdf"] == 1)
        .ok_or("vector_missing")?;
    let context = BASE64
        .decode(row["context"].as_str().ok_or("context_missing")?)
        .map_err(|_| "context_decode_failed")?;
    let expected = BASE64
        .decode(
            row["synthetic_public_known_derived_key"]
                .as_str()
                .ok_or("key_missing")?,
        )
        .map_err(|_| "key_decode_failed")?;
    let derived = symmetric::material_with_kdf(
        &native.kind,
        true,
        false,
        None,
        &[0x51; 32],
        &context,
        false,
    )
    .map_err(|_| "native_hkdf_failed")?;
    assert!(
        derived.as_slice() == expected.as_slice() && !native.legacy_counter_kdf,
        "the preexisting native HKDF remains distinct from imported counter KDF"
    );
    let mut t = Transit::default();
    for mode in [
        json!({"type":"aes256-gcm96","derived":true,"convergent_encryption":true}),
        json!({"type":"aes256-gcm96","derived":true,"convergent_encryption":true,"heptabao_convergent_version":1}),
    ] {
        assert!(call(&mut t, "POST", "keys/protected", &mode)?.status == 200);
        let before = encoded(&t)?;
        assert!(
            t.handle(
                "team",
                "transit",
                "POST",
                "keys/protected/config",
                &json!({"allow_plaintext_backup":true}),
                100
            )
            .is_err()
        );
        assert!(encoded(&t)?.as_slice() == before.as_slice());
        assert!(
            t.handle(
                "team",
                "transit",
                "GET",
                "backup/protected",
                &json!({}),
                100
            )
            .is_err()
        );
        let wire = wire_fixture("aes256-gcm96", 0, true)?;
        let raw = serde_json::to_vec(&wire).map_err(|_| "wire_encode_failed")?;
        assert!(
            t.handle(
                "team",
                "transit",
                "POST",
                "restore/protected",
                &json!({"backup":BASE64.encode(raw),"force":true}),
                100
            )
            .is_err()
        );
        assert!(encoded(&t)?.as_slice() == before.as_slice());
        t.keys.remove("protected");
    }
    Ok(())
}

#[test]
fn symmetric270_native_kdf1_hot_archive_trim_and_restore_preserve_retained_secrets() -> TestResult {
    let vectors: Value = serde_json::from_str(include_str!("transit_backup_sdk_vectors.json"))
        .map_err(|_| "vectors_parse_failed")?;
    let rows = vectors["vectors"].as_array().ok_or("vectors_missing")?;
    let mut t = fixture()?;
    for kind in [
        "aes128-gcm96",
        "aes256-gcm96",
        "chacha20-poly1305",
        "xchacha20-poly1305",
    ] {
        let name = format!("trim-{kind}");
        let copy = format!("{name}-copy");
        let mut wire = wire_fixture(kind, 1, true)?;
        // Deliberately public v2 material permits authentication with the independent SDK fixture.
        let material = BASE64.encode(vec![0x51; symmetric::key_len(kind)]);
        wire["policy"]["keys"]["2"]["key"] = json!(material);
        wire["archived_keys"]["keys"][2]["key"] = json!(material);
        restore_wire(&mut t, &name, &wire)?;
        let descriptor = call(&mut t, "GET", &format!("keys/{name}"), &json!({}))?;
        assert!(descriptor.body["data"]["kdf"] == "hkdf_sha256");
        assert!(descriptor.body["data"].get("kdf_mode").is_none());
        assert!(
            descriptor.body["data"]["restore_info"] == json!({"time":timestamp(100),"version":2})
        );
        assert!(descriptor.body["data"].get("backup_info").is_none());
        let state = encoded(&t)?;
        let failure = t
            .handle(
                "team",
                "transit",
                "POST",
                &format!("keys/{name}/trim"),
                &json!({"min_available_version":1}),
                100,
            )
            .err()
            .ok_or("zero_floor_accepted")?;
        assert!(
            failure.status == 400
                && failure.message
                    == "minimum available version cannot be set when minimum encryption version is not set"
        );
        assert!(encoded(&t)?.as_slice() == state.as_slice());
        assert!(call(&mut t, "POST", &format!("keys/{name}/rotate"), &json!({}))?.status == 200);
        assert!(
            call(
                &mut t,
                "POST",
                &format!("keys/{name}/config"),
                &json!({"min_decryption_version":2,"min_encryption_version":2})
            )?
            .status
                == 200
        );
        let before_trim = call(&mut t, "GET", &format!("backup/{name}"), &json!({}))?;
        let before_raw = Zeroizing::new(
            BASE64
                .decode(
                    before_trim.body["data"]["backup"]
                        .as_str()
                        .ok_or("backup_missing")?,
                )
                .map_err(|_| "backup_decode_failed")?,
        );
        let before_wire: Value =
            serde_json::from_slice(&before_raw).map_err(|_| "backup_parse_failed")?;
        let hot: Vec<_> = before_wire["policy"]["keys"]
            .as_object()
            .ok_or("hot_missing")?
            .keys()
            .cloned()
            .collect();
        assert!(hot == ["2", "3"]);
        assert!(
            before_wire["policy"]["archive_min_version"] == 0
                && before_wire["archived_keys"]["keys"]
                    .as_array()
                    .ok_or("archive_missing")?
                    .len()
                    == 4
        );
        assert!(
            before_wire["archived_keys"]["keys"][1]["key"] == wire["policy"]["keys"]["1"]["key"]
        );
        let info = call(&mut t, "GET", &format!("keys/{name}"), &json!({}))?;
        assert!(info.body["data"]["backup_info"] == json!({"time":timestamp(100),"version":3}));
        let hmac_input = b"retained symmetric key HMAC";
        let hmac_body = json!({"input":BASE64.encode(hmac_input),"key_version":2});
        let hmac = call(&mut t, "POST", &format!("hmac/{name}/sha2-256"), &hmac_body)?;
        let independent = PKey::hmac(&[0x71; 32]).map_err(|_| "hmac_key_failed")?;
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &independent)
            .map_err(|_| "hmac_signer_failed")?;
        signer
            .update(hmac_input)
            .map_err(|_| "hmac_update_failed")?;
        let expected = format!(
            "vault:v2:{}",
            BASE64.encode(signer.sign_to_vec().map_err(|_| "hmac_sign_failed")?)
        );
        assert!(hmac.body["data"]["hmac"] == expected);
        let retained = t.keys[&name].versions[&2].clone();
        let third = t.keys[&name].versions[&3].clone();
        let trimmed = call(
            &mut t,
            "POST",
            &format!("keys/{name}/trim"),
            &json!({"min_available_version":2}),
        )?;
        assert!(trimmed.status == 200 && trimmed.body["data"]["min_available_version"] == 2);
        assert!(!t.keys[&name].versions.contains_key(&1));
        assert!(t.keys[&name].versions.keys().copied().collect::<Vec<_>>() == [2, 3]);
        assert!(
            t.keys[&name].versions[&2].material == retained.material
                && t.keys[&name].versions[&2].hmac_material == retained.hmac_material
                && t.keys[&name].versions[&3].material == third.material
                && t.keys[&name].versions[&3].hmac_material == third.hmac_material
        );
        let after = call(&mut t, "GET", &format!("backup/{name}"), &json!({}))?;
        let blob = after.body["data"]["backup"]
            .as_str()
            .ok_or("backup_missing")?;
        let raw = Zeroizing::new(BASE64.decode(blob).map_err(|_| "backup_decode_failed")?);
        let trimmed_wire: Value =
            serde_json::from_slice(&raw).map_err(|_| "backup_parse_failed")?;
        assert!(
            trimmed_wire["policy"]["kdf"] == 1
                && trimmed_wire["policy"]["archive_min_version"] == 2
                && trimmed_wire["policy"]["min_available_version"] == 2
        );
        assert!(
            trimmed_wire["archived_keys"]["keys"]
                .as_array()
                .ok_or("archive_missing")?
                .len()
                == 2
        );
        assert!(
            trimmed_wire["archived_keys"]["keys"][0]["time"]
                == wire["archived_keys"]["keys"][2]["time"]
        );
        assert!(
            trimmed_wire["archived_keys"]["keys"][0]["key"] == material
                && trimmed_wire["archived_keys"]["keys"][0]["hmac_key"]
                    == BASE64.encode([0x71; 32])
        );
        assert!(
            call(
                &mut t,
                "POST",
                &format!("restore/{copy}"),
                &json!({"backup":blob})
            )?
            .status
                == 204
        );
        let restored = call(&mut t, "GET", &format!("keys/{copy}"), &json!({}))?;
        assert!(
            restored.body["data"]["min_available_version"] == 2
                && restored.body["data"]["restore_info"]
                    == json!({"time":timestamp(100),"version":3})
        );
        assert!(t.keys[&copy].versions.keys().copied().collect::<Vec<_>>() == [2, 3]);
        for version in [2, 3] {
            assert!(
                t.keys[&name].versions[&version].material
                    == t.keys[&copy].versions[&version].material
                    && t.keys[&name].versions[&version].hmac_material
                        == t.keys[&copy].versions[&version].hmac_material
            );
        }
        let restored_hmac = call(&mut t, "POST", &format!("hmac/{copy}/sha2-256"), &hmac_body)?;
        assert!(restored_hmac.body["data"]["hmac"] == expected);
        let row = rows
            .iter()
            .find(|row| row["kind"] == kind && row["kdf"] == 1)
            .ok_or("native_sdk_vector_missing")?;
        let known = Zeroizing::new(
            BASE64
                .decode(
                    row["synthetic_public_known_derived_key"]
                        .as_str()
                        .ok_or("known_key_missing")?,
                )
                .map_err(|_| "known_key_decode_failed")?,
        );
        let encrypted = call(
            &mut t,
            "POST",
            &format!("encrypt/{name}"),
            &json!({"key_version":2,"context":row["context"],"plaintext":row["message"]}),
        )?;
        let ciphertext = encrypted.body["data"]["ciphertext"]
            .as_str()
            .ok_or("ciphertext_missing")?;
        let fixture_ciphertext = ciphertext.replacen("vault:v2:", "vault:v1:", 1);
        let plaintext = Zeroizing::new(
            BASE64
                .decode(row["message"].as_str().ok_or("message_missing")?)
                .map_err(|_| "message_decode_failed")?,
        );
        assert!(sdk_open(kind, &known, &fixture_ciphertext)?.as_slice() == plaintext.as_slice());
        let decrypted = call(
            &mut t,
            "POST",
            &format!("decrypt/{copy}"),
            &json!({"context":row["context"],"ciphertext":ciphertext}),
        )?;
        assert!(decrypted.body["data"]["plaintext"] == row["message"]);
        for (body, expected_message) in [
            (
                json!({"min_available_version":1}),
                "minimum available version cannot be decremented",
            ),
            (
                json!({"min_available_version":4}),
                "minimum available version cannot be greater than minmum encryption version",
            ),
            (
                json!({"min_available_version":2,"unknown":true}),
                "unknown field",
            ),
        ] {
            let state = encoded(&t)?;
            let failure = t
                .handle(
                    "team",
                    "transit",
                    "POST",
                    &format!("keys/{name}/trim"),
                    &body,
                    100,
                )
                .err()
                .ok_or("bad_trim_accepted")?;
            assert!(failure.status == 400);
            if expected_message != "unknown field" {
                assert!(failure.message == expected_message);
            }
            assert!(encoded(&t)?.as_slice() == state.as_slice());
        }
        let state = encoded(&t)?;
        let lower = t
            .handle(
                "team",
                "transit",
                "POST",
                &format!("keys/{name}/config"),
                &json!({"min_decryption_version":1}),
                100,
            )
            .err()
            .ok_or("trim_floor_lowered")?;
        assert!(lower.status == 400 && encoded(&t)?.as_slice() == state.as_slice());
        let reloaded: Transit =
            serde_json::from_slice(&state).map_err(|_| "state_reload_failed")?;
        reloaded
            .validate_byok_state()
            .map_err(|_| "state_custody_failed")?;
        assert!(
            min_available_version(&reloaded.keys[&name]) == 2
                && !reloaded.keys[&name].versions.contains_key(&1)
        );
    }
    Ok(())
}
#[test]
fn symmetric270_backup_rotation_nanoseconds_restore_and_atomic_boundaries() -> TestResult {
    let mut t = fixture()?;
    assert!(
        call(
            &mut t,
            "POST",
            "keys/rotation-source",
            &json!({
                "type":"aes256-gcm96","exportable":true,"allow_plaintext_backup":true
            })
        )?
        .status
            == 200
    );
    assert!(
        call(
            &mut t,
            "POST",
            "keys/rotation-source/config",
            &json!({"auto_rotate_period":"168h"})
        )?
        .status
            == 200
    );
    let exported = call(&mut t, "GET", "backup/rotation-source", &json!({}))?;
    let blob = exported.body["data"]["backup"]
        .as_str()
        .ok_or("backup_missing")?;
    let raw = Zeroizing::new(BASE64.decode(blob).map_err(|_| "backup_decode_failed")?);
    let wire: Value = serde_json::from_slice(&raw).map_err(|_| "backup_parse_failed")?;
    assert!(wire["policy"]["auto_rotate_period"] == 604_800_000_000_000u64);
    assert!(
        call(
            &mut t,
            "POST",
            "restore/rotation-copy",
            &json!({"backup":blob})
        )?
        .status
            == 204
    );
    assert!(t.keys["rotation-copy"].auto_rotate_period == 604_800);
    let source_private = call(
        &mut t,
        "GET",
        "export/encryption-key/rotation-source",
        &json!({}),
    )?;
    let restored_private = call(
        &mut t,
        "GET",
        "export/encryption-key/rotation-copy",
        &json!({}),
    )?;
    assert!(source_private.body["data"]["keys"] == restored_private.body["data"]["keys"]);
    let encrypted = call(
        &mut t,
        "POST",
        "encrypt/rotation-source",
        &json!({"plaintext":BASE64.encode(b"nonzero backup period keeps real AES material")}),
    )?;
    let plaintext = call(
        &mut t,
        "POST",
        "decrypt/rotation-copy",
        &json!({"ciphertext":encrypted.body["data"]["ciphertext"]}),
    )?;
    assert!(
        plaintext.body["data"]["plaintext"]
            == BASE64.encode(b"nonzero backup period keeps real AES material")
    );

    for (index, seconds) in [0u64, 3_600, 604_800, 315_360_000].into_iter().enumerate() {
        let mut input = wire_fixture("aes256-gcm96", 0, false)?;
        input["policy"]["auto_rotate_period"] = json!(seconds * 1_000_000_000);
        restore_wire(&mut t, &format!("period-{index}"), &input)?;
        assert!(t.keys[&format!("period-{index}")].auto_rotate_period == seconds);
        let output = call(&mut t, "GET", &format!("backup/period-{index}"), &json!({}))?;
        let raw = Zeroizing::new(
            BASE64
                .decode(
                    output.body["data"]["backup"]
                        .as_str()
                        .ok_or("backup_missing")?,
                )
                .map_err(|_| "backup_decode_failed")?,
        );
        let output: Value = serde_json::from_slice(&raw).map_err(|_| "backup_parse_failed")?;
        assert!(output["policy"]["auto_rotate_period"] == seconds * 1_000_000_000);
    }
    let before = encoded(&t)?;
    for nanoseconds in [
        3_599_000_000_000,
        315_360_001_000_000_000,
        u64::MAX,
    ] {
        let mut input = wire_fixture("aes256-gcm96", 0, false)?;
        input["policy"]["auto_rotate_period"] = json!(nanoseconds);
        let raw = Zeroizing::new(serde_json::to_vec(&input).map_err(|_| "wire_encoding_failed")?);
        let failure = t
            .handle(
                "team",
                "transit",
                "POST",
                "restore/rotation-copy",
                &json!({"backup":BASE64.encode(raw.as_slice()),"force":true}),
                100,
            )
            .err()
            .ok_or("invalid_period_accepted")?;
        assert!(failure.status == 400);
        assert!(
            encoded(&t)?.as_slice() == before.as_slice(),
            "precision, duration bounds and overflow failures cannot replace any live key"
        );
    }
    assert!(
        t.handle(
            "team",
            "transit",
            "POST",
            "keys/rotation-source/config",
            &json!({"auto_rotate_period":604_800}),
            100
        )
        .is_err(),
        "backup integer units do not relax the existing public duration API"
    );
    assert!(encoded(&t)?.as_slice() == before.as_slice());
    Ok(())
}
