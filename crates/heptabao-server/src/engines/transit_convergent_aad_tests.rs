use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
const KINDS: [&str; 4] = [
    "aes128-gcm96",
    "aes256-gcm96",
    "chacha20-poly1305",
    "xchacha20-poly1305",
];

fn call(transit: &mut Transit, method: &str, path: &str, body: Value) -> Result<EngineResponse> {
    transit.handle("", "transit", method, path, &body, 100)
}

fn create(transit: &mut Transit, kind: &str) -> Result<EngineResponse> {
    call(
        transit,
        "POST",
        "keys/key",
        json!({"type":kind,"derived":true,"convergent_encryption":true,"heptabao_convergent_version":1}),
    )
}

fn options(aad: &[u8]) -> Value {
    json!({"plaintext":BASE64.encode(b"synthetic message"),"context":BASE64.encode(b"synthetic context"),"associated_data":BASE64.encode(aad)})
}

fn payload(response: &EngineResponse) -> Result<Zeroizing<Vec<u8>>> {
    Ok(parse_wrapped(string(&response.body["data"], "ciphertext")?)?.1)
}

#[test]
fn aad_bound_versions_bind_nonce_to_aad_and_preserve_determinism() -> TestResult {
    for kind in KINDS {
        let mut transit = Transit::default();
        let descriptor = create(&mut transit, kind)?;
        assert!(descriptor.body["data"]["heptabao_convergent_version"] == 1);
        let first = call(&mut transit, "POST", "encrypt/key", options(b"first AAD"))?;
        let repeat = call(&mut transit, "POST", "encrypt/key", options(b"first AAD"))?;
        let changed = call(&mut transit, "POST", "encrypt/key", options(b"second AAD"))?;
        assert!(first.body["data"]["ciphertext"] == repeat.body["data"]["ciphertext"]);
        let first_bytes = payload(&first)?;
        let changed_bytes = payload(&changed)?;
        let nonce_len = if kind == "xchacha20-poly1305" { 24 } else { 12 };
        assert!(first_bytes[..nonce_len] != changed_bytes[..nonce_len]);
        assert!(
            first_bytes[nonce_len..first_bytes.len() - 16]
                != changed_bytes[nonce_len..changed_bytes.len() - 16]
        );
        for (cipher, aad) in [
            (&first, b"first AAD".as_slice()),
            (&changed, b"second AAD".as_slice()),
        ] {
            let response = call(
                &mut transit,
                "POST",
                "decrypt/key",
                json!({"ciphertext":cipher.body["data"]["ciphertext"],"context":BASE64.encode(b"synthetic context"),"associated_data":BASE64.encode(aad)}),
            )?;
            assert!(response.body["data"]["plaintext"] == options(aad)["plaintext"]);
        }
        assert!(call(&mut transit,"POST","decrypt/key",json!({"ciphertext":first.body["data"]["ciphertext"],"context":BASE64.encode(b"synthetic context"),"associated_data":BASE64.encode(b"second AAD")})).err().is_some_and(|error| error.status == 400));
    }
    Ok(())
}

#[test]
fn upgrade_rotates_fresh_material_preserves_legacy_reads_and_fences_all_writes() -> TestResult {
    for kind in KINDS {
        let mut transit = Transit::default();
        let legacy = call(
            &mut transit,
            "POST",
            "keys/key",
            json!({"type":kind,"derived":true,"convergent_encryption":true}),
        )?;
        assert!(
            legacy.body["data"]
                .get("heptabao_convergent_version")
                .is_none()
        );
        let old = call(&mut transit, "POST", "encrypt/key", options(b"first AAD"))?;
        let master = Zeroizing::new(transit.keys["key"].versions[&1].material.clone());
        assert!(
            call(
                &mut transit,
                "POST",
                "keys/key",
                json!({"heptabao_convergent_version":1})
            )
            .err()
            .is_some_and(|error| error.status == 400)
        );
        call(
            &mut transit,
            "POST",
            "keys/key/rotate",
            json!({"heptabao_convergent_version":1}),
        )?;
        assert!(transit.keys["key"].versions[&2].material != *master);
        assert!(
            transit.keys["key"].versions[&1]
                .heptabao_convergent_version
                .is_none()
        );
        assert!(
            transit.keys["key"].versions[&2]
                .heptabao_convergent_version
                .is_some()
        );
        let legacy_decrypt = call(
            &mut transit,
            "POST",
            "decrypt/key",
            json!({"ciphertext":old.body["data"]["ciphertext"],"context":BASE64.encode(b"synthetic context"),"associated_data":BASE64.encode(b"first AAD")}),
        )?;
        assert!(legacy_decrypt.body["data"]["plaintext"] == options(b"first AAD")["plaintext"]);
        for path in [
            "encrypt/key",
            "rewrap/key",
            "datakey/plaintext/key",
            "datakey/wrapped/key",
        ] {
            let mut body = options(b"first AAD");
            body["ciphertext"] = old.body["data"]["ciphertext"].clone();
            body["key_version"] = json!(1);
            // Each endpoint receives only its documented fields.
            if path.starts_with("rewrap") {
                body.as_object_mut().ok_or("object")?.remove("plaintext");
            } else {
                body.as_object_mut().ok_or("object")?.remove("ciphertext");
            }
            if path.starts_with("datakey") {
                body.as_object_mut().ok_or("object")?.remove("plaintext");
            }
            assert!(
                call(&mut transit, "POST", path, body)
                    .err()
                    .is_some_and(|error| error.status == 400)
            );
        }
        for minimum in [0, 1] {
            assert!(
                call(
                    &mut transit,
                    "POST",
                    "keys/key/config",
                    json!({"min_encryption_version":minimum})
                )
                .err()
                .is_some_and(|error| error.status == 400)
            );
            assert!(
                transit.keys["key"].convergent_write_min_version == 2
                    && transit.keys["key"].min_encryption_version == 2
            );
        }
        let migrated = call(
            &mut transit,
            "POST",
            "rewrap/key",
            json!({"ciphertext":old.body["data"]["ciphertext"],"context":BASE64.encode(b"synthetic context"),"associated_data":BASE64.encode(b"first AAD")}),
        )?;
        assert!(migrated.body["data"]["key_version"] == 2);
        let encoded = Zeroizing::new(serde_json::to_vec(&transit)?);
        let mut reopened: Transit = serde_json::from_slice(&encoded)?;
        assert!(reopened.validate_aad_bound_convergent_state().is_ok());
        let plain = call(
            &mut reopened,
            "POST",
            "decrypt/key",
            json!({"ciphertext":migrated.body["data"]["ciphertext"],"context":BASE64.encode(b"synthetic context"),"associated_data":BASE64.encode(b"first AAD")}),
        )?;
        assert!(plain.body["data"]["plaintext"] == options(b"first AAD")["plaintext"]);
        call(&mut reopened, "POST", "keys/key/rotate", json!({}))?;
        assert!(
            reopened.keys["key"].versions[&3]
                .heptabao_convergent_version
                .is_some()
        );
        reopened
            .keys
            .get_mut("key")
            .ok_or("key")?
            .auto_rotate_period = 3600;
        assert!(reopened.maintain_auto_rotation(4000)?);
        assert!(
            reopened.keys["key"].versions[&4]
                .heptabao_convergent_version
                .is_some()
        );
        assert!(reopened.keys["key"].convergent_write_min_version == 2);
    }
    Ok(())
}

#[test]
fn safe_mode_cannot_be_downgraded_exported_backed_up_or_injected_by_crypto_body() -> TestResult {
    let mut transit = Transit::default();
    create(&mut transit, "aes256-gcm96")?;
    for value in [
        Value::Null,
        json!(0),
        json!(2),
        json!(true),
        json!("1"),
        json!([]),
        json!({}),
    ] {
        assert!(
            call(
                &mut transit,
                "POST",
                "keys/key/rotate",
                json!({"heptabao_convergent_version":value})
            )
            .err()
            .is_some_and(|error| error.status == 400)
        );
        assert!(transit.keys["key"].latest_version == 1);
    }
    for body in [
        json!({"exportable":true}),
        json!({"allow_plaintext_backup":true}),
        json!({"heptabao_convergent_version":0}),
    ] {
        assert!(call(&mut transit, "POST", "keys/key/config", body).is_err());
        assert!(!transit.keys["key"].exportable);
    }
    for path in [
        "export/encryption-key/key",
        "export/encryption-key/key/1",
        "export/hmac-key/key",
        "backup/key",
    ] {
        assert!(call(&mut transit, "GET", path, json!({})).is_err());
    }
    let mut bad_options = options(b"AAD");
    bad_options["heptabao_convergent_version"] = json!(0);
    assert!(
        call(&mut transit, "POST", "encrypt/key", bad_options.clone())
            .err()
            .is_some_and(|error| error.status == 400)
    );
    assert!(transit.keys["key"].versions[&1].encryptions == 0);
    assert!(
        call(&mut transit, "POST", "encrypt/upsert", bad_options)
            .err()
            .is_some_and(|error| error.status == 400)
    );
    assert!(!transit.keys.contains_key("upsert"));
    call(
        &mut transit,
        "POST",
        "keys/exported",
        json!({"derived":true,"convergent_encryption":true,"exportable":true}),
    )?;
    assert!(
        call(
            &mut transit,
            "POST",
            "keys/exported/rotate",
            json!({"heptabao_convergent_version":1})
        )
        .err()
        .is_some_and(|error| error.status == 400)
    );
    assert!(transit.keys["exported"].latest_version == 1);
    Ok(())
}

#[test]
fn malformed_safe_version_floor_and_mode_cannot_be_materialized() -> TestResult {
    let mut transit = Transit::default();
    create(&mut transit, "aes128-gcm96")?;
    let canonical = SecretJson(serde_json::to_value(&transit)?);
    for (pointer, value) in [
        ("/keys/key/convergent_write_min_version", json!(0)),
        ("/keys/key/convergent_write_min_version", json!(2)),
        ("/keys/key/min_encryption_version", json!(0)),
        ("/keys/key/derived", json!(false)),
        ("/keys/key/convergent_encryption", json!(false)),
        ("/keys/key/exportable", json!(true)),
        (
            "/keys/key/versions/1/heptabao_convergent_version",
            Value::Null,
        ),
    ] {
        let mut altered = SecretJson(canonical.0.clone());
        *altered.pointer_mut(pointer).ok_or("pointer")? = value;
        let decoded: Transit = serde_json::from_value(altered.0.clone())?;
        assert!(decoded.validate_aad_bound_convergent_state().is_err());
    }
    let mut unknown = SecretJson(canonical.0.clone());
    unknown["keys"]["key"]["versions"]["1"]["heptabao_convergent_version"] = json!("unknown");
    assert!(serde_json::from_value::<Transit>(unknown.0.clone()).is_err());
    Ok(())
}

#[test]
fn aad_nonce_frames_have_unambiguous_boundaries_and_kdf_separates_legacy() -> TestResult {
    for kind in KINDS {
        let master = Zeroizing::new(vec![7; symmetric::key_len(kind)]);
        let safe = symmetric::material(
            kind,
            true,
            true,
            Some(symmetric::ConvergentMode::AadBoundV1),
            &master,
            b"context",
        )?;
        let legacy = symmetric::material(kind, true, true, None, &master, b"context")?;
        assert!(safe.len() == symmetric::key_len(kind) + 32);
        assert!(safe[..symmetric::key_len(kind)] != legacy[..symmetric::key_len(kind)]);
        let nonce_len = if kind == "xchacha20-poly1305" { 24 } else { 12 };
        let mut seen = std::collections::BTreeSet::new();
        for (aad, plain) in [
            (b"a".as_slice(), b"bc".as_slice()),
            (b"ab", b"c"),
            (b"", b"abc"),
            (b"abc", b""),
        ] {
            let nonce = symmetric::nonce(
                true,
                Some(symmetric::ConvergentMode::AadBoundV1),
                &safe,
                symmetric::key_len(kind),
                plain,
                aad,
                nonce_len,
            )?;
            assert!(seen.insert(nonce));
        }
    }
    Ok(())
}

#[test]
fn batch_and_datakey_use_the_same_version_guard_and_authenticated_mode() -> TestResult {
    for kind in KINDS {
        let mut transit = Transit::default();
        call(
            &mut transit,
            "POST",
            "keys/key",
            json!({"type":kind,"derived":true,"convergent_encryption":true}),
        )?;
        call(
            &mut transit,
            "POST",
            "keys/key/rotate",
            json!({"heptabao_convergent_version":1}),
        )?;
        let mut first = options(b"first AAD");
        first["key_version"] = json!(1);
        let second = options(b"second AAD");
        let batch = call(
            &mut transit,
            "POST",
            "encrypt/key",
            json!({"partial_failure_response_code":207,"batch_input":[first,second]}),
        )?;
        assert!(batch.status == 207);
        assert!(
            batch.body["data"]["batch_results"][0]
                .get("error")
                .is_some()
        );
        assert!(batch.body["data"]["batch_results"][1]["key_version"] == 2);
        assert!(transit.keys["key"].versions[&1].encryptions == 0);
        assert!(transit.keys["key"].versions[&2].encryptions == 1);
        for bits in [128, 256, 512] {
            let generated = call(
                &mut transit,
                "POST",
                "datakey/plaintext/key",
                json!({"bits":bits,"context":BASE64.encode(b"synthetic context"),"associated_data":BASE64.encode(b"AAD")}),
            )?;
            assert!(decode(string(&generated.body["data"], "plaintext")?)?.len() == bits / 8);
            let decrypted = call(
                &mut transit,
                "POST",
                "decrypt/key",
                json!({"ciphertext":generated.body["data"]["ciphertext"],"context":BASE64.encode(b"synthetic context"),"associated_data":BASE64.encode(b"AAD")}),
            )?;
            assert!(decrypted.body["data"]["plaintext"] == generated.body["data"]["plaintext"]);
        }
        let wrapped = call(
            &mut transit,
            "POST",
            "datakey/wrapped/key",
            json!({"context":BASE64.encode(b"synthetic context"),"associated_data":BASE64.encode(b"AAD")}),
        )?;
        assert!(wrapped.body["data"].get("plaintext").is_none());
        assert!(wrapped.body["data"]["key_version"] == 2);
    }
    Ok(())
}

#[test]
fn safe_derivation_matches_independent_cryptography_synthetic_vectors() -> TestResult {
    // Generated with pinned cryptography 46.0.4 HKDF/HMAC, not this helper.
    for (kind, material_digest, nonce_digest) in [
        (
            "aes128-gcm96",
            [
                73, 136, 114, 233, 115, 146, 180, 79, 96, 109, 244, 140, 91, 174, 191, 186, 115,
                211, 201, 209, 28, 109, 216, 54, 155, 91, 124, 193, 64, 204, 38, 31,
            ],
            [
                40, 253, 235, 249, 59, 228, 5, 221, 151, 243, 136, 3, 161, 65, 77, 123, 45, 57,
                221, 167, 47, 67, 128, 55, 51, 136, 240, 69, 227, 163, 38, 206,
            ],
        ),
        (
            "aes256-gcm96",
            [
                45, 238, 159, 76, 208, 135, 34, 32, 217, 121, 213, 26, 124, 109, 188, 0, 132, 199,
                65, 216, 107, 151, 207, 254, 205, 189, 199, 156, 69, 88, 15, 70,
            ],
            [
                235, 224, 10, 128, 125, 211, 112, 189, 43, 128, 103, 64, 251, 191, 11, 98, 133, 98,
                48, 8, 104, 227, 65, 167, 227, 14, 112, 145, 66, 181, 192, 139,
            ],
        ),
        (
            "chacha20-poly1305",
            [
                251, 8, 40, 31, 0, 62, 253, 5, 83, 250, 96, 54, 192, 57, 91, 65, 113, 27, 198, 226,
                147, 178, 248, 154, 222, 148, 54, 179, 32, 109, 207, 61,
            ],
            [
                18, 114, 94, 248, 156, 250, 93, 86, 187, 37, 217, 79, 78, 53, 40, 31, 210, 92, 14,
                72, 253, 145, 246, 247, 116, 53, 254, 43, 108, 8, 253, 19,
            ],
        ),
        (
            "xchacha20-poly1305",
            [
                178, 232, 9, 84, 97, 212, 122, 87, 254, 66, 200, 100, 102, 51, 75, 4, 5, 146, 178,
                27, 168, 100, 39, 139, 154, 52, 6, 211, 14, 194, 195, 142,
            ],
            [
                231, 104, 152, 27, 241, 207, 230, 226, 146, 59, 171, 226, 64, 54, 205, 143, 6, 203,
                104, 29, 233, 207, 76, 91, 16, 198, 133, 69, 159, 178, 47, 167,
            ],
        ),
    ] {
        let master = Zeroizing::new(vec![7; symmetric::key_len(kind)]);
        let material = symmetric::material(
            kind,
            true,
            true,
            Some(symmetric::ConvergentMode::AadBoundV1),
            &master,
            b"context",
        )?;
        assert!(Sha256::digest(&*material).as_slice() == material_digest);
        let nonce = symmetric::nonce(
            true,
            Some(symmetric::ConvergentMode::AadBoundV1),
            &material,
            symmetric::key_len(kind),
            b"bc",
            b"a",
            if kind.starts_with("xchacha") { 24 } else { 12 },
        )?;
        assert!(Sha256::digest(&nonce).as_slice() == nonce_digest);
    }
    Ok(())
}

#[test]
fn caller_nonce_cannot_override_safe_derivation_and_successful_invocations_are_bounded()
-> TestResult {
    let mut transit = Transit::default();
    create(&mut transit, "aes128-gcm96")?;
    let first = call(&mut transit, "POST", "encrypt/key", options(b"AAD"))?;
    for caller_nonce in [
        Value::Null,
        json!(false),
        json!("invalid-base64"),
        json!(BASE64.encode([0u8; 12])),
    ] {
        let mut body = options(b"AAD");
        body["nonce"] = caller_nonce;
        let repeated = call(&mut transit, "POST", "encrypt/key", body)?;
        assert!(first.body["data"]["ciphertext"] == repeated.body["data"]["ciphertext"]);
    }
    transit
        .keys
        .get_mut("key")
        .ok_or("key")?
        .versions
        .get_mut(&1)
        .ok_or("version")?
        .encryptions = MAX_ENCRYPTIONS_PER_VERSION - 1;
    call(
        &mut transit,
        "POST",
        "encrypt/key",
        options(b"different AAD"),
    )?;
    assert!(transit.keys["key"].versions[&1].encryptions == MAX_ENCRYPTIONS_PER_VERSION);
    assert!(
        call(&mut transit, "POST", "encrypt/key", options(b"AAD"))
            .err()
            .is_some_and(|error| error.status == 400)
    );
    assert!(transit.keys["key"].versions[&1].encryptions == MAX_ENCRYPTIONS_PER_VERSION);
    Ok(())
}

#[test]
fn malformed_safe_latest_version_cannot_rewind_while_retaining_future_material() -> TestResult {
    let mut transit = Transit::default();
    create(&mut transit, "aes128-gcm96")?;
    call(&mut transit, "POST", "keys/key/rotate", json!({}))?;
    assert!(transit.validate_aad_bound_convergent_state().is_ok());
    transit.keys.get_mut("key").ok_or("key")?.latest_version = 1;
    assert!(transit.validate_aad_bound_convergent_state().is_err());
    Ok(())
}
