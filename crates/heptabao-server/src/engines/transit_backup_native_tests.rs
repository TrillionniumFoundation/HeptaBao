//! Genuine native routes, independent standard crypto verification, and strict private-wire rejection.
use super::*;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Padding,
    sign::{Signer, Verifier},
};
type TestResult<T = ()> = std::result::Result<T, &'static str>;
fn call(t: &mut Transit, method: &str, path: &str, body: &Value) -> TestResult<EngineResponse> {
    t.handle("team", "transit", method, path, body, 100)
        .map_err(|_| "native_transit_route_failed")
}
fn data(r: EngineResponse) -> TestResult<Value> {
    r.body.get("data").cloned().ok_or("missing_data")
}
fn export(t: &mut Transit, name: &str, category: &str, format: &str) -> TestResult<Value> {
    data(call(
        t,
        "GET",
        &format!("export/{category}/{name}"),
        &json!({"format":format}),
    )?)
}
fn bytes(value: &Value) -> TestResult<Zeroizing<Vec<u8>>> {
    BASE64
        .decode(value.as_str().ok_or("expected_base64")?)
        .map(Zeroizing::new)
        .map_err(|_| "invalid_base64")
}
fn capture(t: &Transit) -> TestResult<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(t)
        .map(Zeroizing::new)
        .map_err(|_| "state_encode_failed")
}
fn backup_wire(t: &mut Transit, name: &str) -> TestResult<(String, Backup)> {
    let r = data(call(t, "GET", &format!("backup/{name}"), &json!({}))?)?;
    let encoded = r["backup"].as_str().ok_or("backup_missing")?.to_string();
    let raw = Zeroizing::new(
        BASE64
            .decode(&encoded)
            .map_err(|_| "backup_base64_failed")?,
    );
    let wire = serde_json::from_slice(&raw).map_err(|_| "typed_backup_parse_failed")?;
    Ok((encoded, wire))
}
fn independent_mac(material: &[u8], message: &[u8]) -> TestResult<Vec<u8>> {
    let key = PKey::hmac(material).map_err(|_| "SDK_HMAC_key_failed")?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).map_err(|_| "SDK_HMAC_failed")?;
    signer
        .update(message)
        .map_err(|_| "SDK_HMAC_input_failed")?;
    signer.sign_to_vec().map_err(|_| "SDK_HMAC_sign_failed")
}
fn independent_signature(
    kind: &str,
    private: &[u8],
    message: &[u8],
    signature: &[u8],
) -> TestResult<bool> {
    let key = PKey::private_key_from_der(private).map_err(|_| "SDK_PKCS8_failed")?;
    if kind == "ed25519" {
        let mut v = Verifier::new_without_digest(&key).map_err(|_| "SDK_Ed_verifier_failed")?;
        return v
            .verify_oneshot(signature, message)
            .map_err(|_| "SDK_Ed_verify_failed");
    }
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &key).map_err(|_| "SDK_verifier_failed")?;
    if asymmetric::is_rsa(kind) {
        verifier
            .set_rsa_padding(Padding::PKCS1)
            .map_err(|_| "SDK_RSA_padding_failed")?;
    }
    verifier.update(message).map_err(|_| "SDK_input_failed")?;
    verifier.verify(signature).map_err(|_| "SDK_verify_failed")
}
#[test]
fn backup270_native_seven_standard_and_hmac_restore_exact_private_versions_and_independent_crypto()
-> TestResult {
    let mut t = Transit::default();
    let message = b"native backup independent signatures and HMAC";
    for kind in [
        "rsa-2048",
        "rsa-3072",
        "rsa-4096",
        "ecdsa-p256",
        "ecdsa-p384",
        "ecdsa-p521",
        "ed25519",
        "hmac",
    ] {
        let mut creation = json!({"type":kind,"exportable":true,"allow_plaintext_backup":true});
        if kind == "hmac" {
            creation["key_size"] = json!(32);
        }
        assert!(call(&mut t, "POST", &format!("keys/{kind}"), &creation)?.status == 200);
        assert!(call(&mut t, "POST", &format!("keys/{kind}/rotate"), &json!({}))?.status == 200);
        let category = if kind == "hmac" {
            "hmac-key"
        } else {
            "signing-key"
        };
        let format = if kind == "hmac" { "raw" } else { "der" };
        let original = export(&mut t, kind, category, format)?;
        let (blob, wire) = backup_wire(&mut t, kind)?;
        assert!(wire.policy.kind == kind_code(kind).map_err(|_| "kind_failed")?);
        assert!(wire.policy.kdf == 0 && !wire.policy.imported && wire.policy.keys.len() == 2);
        assert!(wire.archived_keys.keys.len() == 3 && wire.archived_keys.keys[0].empty_exact());
        assert!(wire.policy.key_size == if kind == "hmac" { Some(32) } else { None });
        for n in 1..=2 {
            assert!(wire.policy.keys[&n.to_string()] == wire.archived_keys.keys[n as usize]);
        }
        let copy = format!("{kind}-restored");
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
        let restored = export(&mut t, &copy, category, format)?;
        assert!(restored["keys"] == original["keys"]);
        for n in 1..=2 {
            let private = bytes(&original["keys"][n.to_string()])?;
            let source = &wire.archived_keys.keys[n as usize];
            let hmac = if kind == "hmac" {
                private.clone()
            } else {
                Zeroizing::new(
                    BASE64
                        .decode(source.hmac_key.as_deref().ok_or("HMAC_missing")?)
                        .map_err(|_| "HMAC_invalid")?,
                )
            };
            let expected = format!(
                "vault:v{n}:{}",
                BASE64.encode(independent_mac(&hmac, message)?)
            );
            let tag = data(call(
                &mut t,
                "POST",
                &format!("hmac/{copy}"),
                &json!({"input":BASE64.encode(message),"key_version":n}),
            )?)?;
            assert!(tag["hmac"] == expected);
            let positive = data(call(
                &mut t,
                "POST",
                &format!("verify/{copy}"),
                &json!({"input":BASE64.encode(message),"hmac":expected}),
            )?)?;
            let negative = data(call(
                &mut t,
                "POST",
                &format!("verify/{copy}"),
                &json!({"input":BASE64.encode(b"changed"),"hmac":expected}),
            )?)?;
            assert!(positive["valid"] == true && negative["valid"] == false);
            if kind != "hmac" {
                let body = if kind == "ed25519" {
                    json!({"input":BASE64.encode(message),"key_version":n})
                } else {
                    json!({"input":BASE64.encode(message),"key_version":n,"hash_algorithm":"sha2-256","marshaling_algorithm":"asn1"})
                };
                let mut body = body;
                if asymmetric::is_rsa(kind) {
                    body["signature_algorithm"] = json!("pkcs1v15");
                }
                let signed = data(call(&mut t, "POST", &format!("sign/{copy}"), &body)?)?;
                let signature = signed["signature"].as_str().ok_or("signature_missing")?;
                let (version, raw) =
                    parse_wrapped(signature).map_err(|_| "signature_parse_failed")?;
                assert!(version == n);
                assert!(independent_signature(kind, &private, message, &raw)?);
                assert!(!independent_signature(kind, &private, b"changed", &raw)?);
            }
        }
        let descriptor = data(call(&mut t, "GET", &format!("keys/{copy}"), &json!({}))?)?;
        if kind == "hmac" {
            assert!(descriptor.get("keys").is_none() && descriptor["key_size"] == 32);
        }
        assert!(
            descriptor["backup_info"]["version"] == 2 && descriptor["restore_info"]["version"] == 2
        );
        let restarted: Transit =
            serde_json::from_slice(&capture(&t)?).map_err(|_| "restart_parse_failed")?;
        restarted
            .validate_byok_state()
            .map_err(|_| "restart_validation_failed")?;
        assert!(capture(&restarted)?.as_slice() == capture(&t)?.as_slice());
    }
    Ok(())
}
#[test]
fn backup270_native_mldsa_seeds_reconstruct_complete_private_signers_and_exact_public_versions()
-> TestResult {
    let mut t = Transit::default();
    let message = b"ML-DSA real private reconstruction from native backup";
    for kind in ["mldsa-44", "mldsa-65", "mldsa-87"] {
        assert!(
            call(
                &mut t,
                "POST",
                &format!("keys/{kind}"),
                &json!({"type":kind,"exportable":true,"allow_plaintext_backup":true})
            )?
            .status
                == 200
        );
        assert!(call(&mut t, "POST", &format!("keys/{kind}/rotate"), &json!({}))?.status == 200);
        let before = export(&mut t, kind, "signing-key", "der")?;
        let (blob, wire) = backup_wire(&mut t, kind)?;
        assert!(
            wire.policy.kdf == 0
                && wire.policy.kind == kind_code(kind).map_err(|_| "kind_failed")?
        );
        for n in 1..=2 {
            let entry = &wire.archived_keys.keys[n as usize];
            let seed = Zeroizing::new(
                BASE64
                    .decode(entry.key.as_deref().ok_or("seed_missing")?)
                    .map_err(|_| "seed_invalid")?,
            );
            assert!(seed.len() == 32);
            assert!(
                entry.public_key
                    == BASE64.encode(mldsa::public(kind, &seed).map_err(|_| "public_failed")?)
            );
            let der =
                mldsa::export_standard(kind, &seed, false, "der").map_err(|_| "DER_failed")?;
            assert!(
                der.as_str()
                    == before["keys"][n.to_string()]
                        .as_str()
                        .ok_or("DER_missing")?
            );
        }
        let copy = format!("{kind}-restored");
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
        let restored = export(&mut t, &copy, "signing-key", "der")?;
        assert!(restored["keys"] == before["keys"]);
        for n in 1..=2 {
            let signed = data(call(
                &mut t,
                "POST",
                &format!("sign/{copy}"),
                &json!({"input":BASE64.encode(message),"key_version":n}),
            )?)?;
            let positive = data(call(
                &mut t,
                "POST",
                &format!("verify/{kind}"),
                &json!({"input":BASE64.encode(message),"signature":signed["signature"]}),
            )?)?;
            let negative = data(call(
                &mut t,
                "POST",
                &format!("verify/{kind}"),
                &json!({"input":BASE64.encode(b"changed"),"signature":signed["signature"]}),
            )?)?;
            assert!(positive["valid"] == true && negative["valid"] == false);
            let key = t.keys.get(&copy).ok_or("key_missing")?;
            let version = key.versions.get(&n).ok_or("version_missing")?;
            assert!(
                version.public_key_only.is_none()
                    && stored_material(&version.material)
                        .map_err(|_| "seed_failed")?
                        .len()
                        == 32
            );
        }
    }
    Ok(())
}
#[test]
fn backup270_typed_integer_arithmetic_and_public_mismatch_rejection_leave_state_exact() -> TestResult
{
    use crypto::Decimal;
    for invalid in [
        r#""123""#,
        "-1",
        "1.0",
        "1e3",
        "00",
        r#"{"$serde_json::private::Number":"123"}"#,
    ] {
        assert!(serde_json::from_str::<Decimal>(invalid).is_err());
    }
    let large = "123456789012345678901234567890123456789012345678901234567890";
    let n: Decimal = serde_json::from_str(large).map_err(|_| "exact_integer_parse_failed")?;
    assert!(serde_json::to_string(&n).map_err(|_| "integer_encode_failed")? == large);
    assert!(serde_json::from_str::<Decimal>(&"9".repeat(1235)).is_err());
    let mut t = Transit::default();
    for kind in ["rsa-2048", "ecdsa-p256", "ed25519", "mldsa-44"] {
        call(
            &mut t,
            "POST",
            &format!("keys/{kind}"),
            &json!({"type":kind,"exportable":true,"allow_plaintext_backup":true}),
        )?;
        let (_, mut wire) = backup_wire(&mut t, kind)?;
        let entry = wire.policy.keys.get_mut("1").ok_or("entry_missing")?;
        if kind == "rsa-2048" {
            let old = entry.rsa_key.as_mut().ok_or("RSA_missing")?;
            // Replace a real component with a valid decimal token having invalid private arithmetic.
            let raw = serde_json::to_vec(old).map_err(|_| "RSA_encode_failed")?;
            let text = std::str::from_utf8(&raw).map_err(|_| "RSA_UTF8_failed")?;
            let d_start = text.find("\"D\":").ok_or("RSA_D_missing")? + 4;
            let d_end = d_start + text[d_start..].find(',').ok_or("RSA_D_end_missing")?;
            let corrupted = format!("{}1{}", &text[..d_start], &text[d_end..]);
            *old = serde_json::from_str(&corrupted).map_err(|_| "typed_corruption_parse_failed")?;
        } else {
            entry.public_key.push('A');
        }
        wire.archived_keys.keys[1] = entry.clone();
        let raw =
            Zeroizing::new(serde_json::to_vec(&wire).map_err(|_| "corrupt_wire_encode_failed")?);
        let before = capture(&t)?;
        let result = t.handle(
            "team",
            "transit",
            "POST",
            "restore/rejected",
            &json!({"backup":BASE64.encode(raw.as_slice())}),
            100,
        );
        assert!(result.is_err() && capture(&t)?.as_slice() == before.as_slice());
        assert!(!t.keys.contains_key("rejected"));
    }
    Ok(())
}
#[test]
fn backup270_native_hmac_marker_preserves_legacy_bytes_and_new_key_size_across_rotation_restart()
-> TestResult {
    let mut t = Transit::default();
    let legacy = Key {
        kind: "hmac".into(),
        byok: None,
        derived: false,
        legacy_counter_kdf: false,
        allow_plaintext_backup: false,
        backup_metadata: None,
        convergent_encryption: false,
        convergent_write_min_version: 0,
        latest_version: 1,
        min_decryption_version: 1,
        min_encryption_version: 0,
        deletion_allowed: false,
        exportable: true,
        auto_rotate_period: 0,
        deleted: false,
        versions: BTreeMap::from([(
            1,
            KeyVersion {
                material: BASE64.encode([0x51; 32]),
                hmac_material: BASE64.encode([0x71; 32]),
                public_key_only: None,
                created_at: 100,
                encryptions: 0,
                external_key_ref: None,
                heptabao_convergent_version: None,
            },
        )]),
    };
    t.keys.insert("legacy".into(), legacy);
    let before = capture(&t)?;
    let expected = format!(
        "vault:v1:{}",
        BASE64.encode(independent_mac(&[0x71; 32], b"legacy")?)
    );
    let result = data(call(
        &mut t,
        "POST",
        "hmac/legacy",
        &json!({"input":BASE64.encode(b"legacy")}),
    )?)?;
    assert!(result["hmac"] == expected && capture(&t)?.as_slice() == before.as_slice());
    assert!(!t.has_symmetric_backup_state());
    for bad_size in [0, 31, 513] {
        let result = t.handle(
            "team",
            "transit",
            "POST",
            "keys/bad",
            &json!({"type":"hmac","key_size":bad_size}),
            100,
        );
        assert!(result.is_err_and(|e| e.status == if bad_size == 0 { 500 } else { 400 }));
        assert!(capture(&t)?.as_slice() == before.as_slice());
    }
    call(
        &mut t,
        "POST",
        "keys/new",
        &json!({"type":"hmac","key_size":64,"exportable":true}),
    )?;
    assert!(t.has_symmetric_backup_state());
    call(&mut t, "POST", "keys/new/rotate", &json!({}))?;
    let exported = export(&mut t, "new", "hmac-key", "raw")?;
    for n in 1..=2 {
        let material = bytes(&exported["keys"][n.to_string()])?;
        assert!(material.len() == 64);
        let result = data(call(
            &mut t,
            "POST",
            "hmac/new",
            &json!({"input":BASE64.encode(b"new"),"key_version":n}),
        )?)?;
        assert!(
            result["hmac"]
                == format!(
                    "vault:v{n}:{}",
                    BASE64.encode(independent_mac(&material, b"new")?)
                )
        );
    }
    let restarted: Transit = serde_json::from_slice(&capture(&t)?).map_err(|_| "restart_failed")?;
    restarted
        .validate_byok_state()
        .map_err(|_| "marker_validation_failed")?;
    assert!(capture(&restarted)?.as_slice() == capture(&t)?.as_slice());
    let mut forged = restarted.clone();
    let m = forged
        .keys
        .get_mut("new")
        .ok_or("key_missing")?
        .backup_metadata
        .as_mut()
        .ok_or("metadata_missing")?;
    m.hmac_key_size = Some(32);
    assert!(forged.validate_byok_state().is_err());
    Ok(())
}
