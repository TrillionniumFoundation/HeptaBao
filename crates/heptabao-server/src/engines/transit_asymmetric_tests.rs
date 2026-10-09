//! Real synthetic EC/RSA operations, persistence and policy boundaries.
use super::*;
use openssl::{ec::EcKey, pkey::PKey, rsa::Rsa};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
const KINDS: [&str; 6] = [
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdsa-p521",
    "rsa-2048",
    "rsa-3072",
    "rsa-4096",
];
fn request(transit: &mut Transit, path: &str, body: &Value) -> Result<EngineResponse> {
    transit.handle("", "transit", "POST", path, body, 100)
}

#[test]
fn asymmetric270_uses_the_locked_aws_lc_provider() {
    assert!(openssl::version::version().contains("AWS-LC 1.73.0"));
}

#[test]
fn asymmetric270_six_types_export_true_keys_and_persist_rotation_policy() -> TestResult {
    for kind in KINDS {
        let mut transit = Transit::default();
        assert!(!transit.has_asymmetric_state());
        let created = request(
            &mut transit,
            "keys/test",
            &json!({"type":kind,"exportable":true}),
        )?;
        assert!(transit.has_asymmetric_state());
        assert_eq!(created.body["data"]["supports_signing"], true);
        assert_eq!(
            created.body["data"]["supports_encryption"],
            asymmetric::is_rsa(kind)
        );
        assert!(created.body["data"].get("supports_hmac").is_none());
        let public = created.body["data"]["keys"]["1"]["public_key"]
            .as_str()
            .ok_or("missing public key")?;
        let public = PKey::public_key_from_pem(public.as_bytes())?;
        let exported = transit.export("GET", "signing-key/test/1")?;
        let private_pem = exported.body["data"]["keys"]["1"]
            .as_str()
            .ok_or("missing private key")?;
        let private = if asymmetric::is_rsa(kind) {
            PKey::from_rsa(Rsa::private_key_from_pem(private_pem.as_bytes())?)?
        } else {
            PKey::from_ec_key(EcKey::private_key_from_pem(private_pem.as_bytes())?)?
        };
        assert!(public.public_key_to_der()? == private.public_key_to_der()?);
        let message = BASE64.encode(b"synthetic retained asymmetric message");
        let signed = request(&mut transit, "sign/test", &json!({"input":message}))?;
        request(&mut transit, "keys/test/rotate", &json!({}))?;
        let encoded = Zeroizing::new(serde_json::to_vec(&transit)?);
        let mut reopened: Transit = serde_json::from_slice(&encoded)?;
        let old = request(
            &mut reopened,
            "verify/test",
            &json!({"input":message,"signature":signed.body["data"]["signature"]}),
        )?;
        assert_eq!(old.body["data"]["valid"], true);
        request(
            &mut reopened,
            "keys/test/config",
            &json!({"min_decryption_version":2,"min_encryption_version":2}),
        )?;
        assert_eq!(
            request(
                &mut reopened,
                "sign/test",
                &json!({"input":message,"key_version":1})
            )
            .err()
            .ok_or("expected retired signing failure")?
            .status,
            500
        );
        assert_eq!(
            request(
                &mut reopened,
                "verify/test",
                &json!({"input":message,"signature":signed.body["data"]["signature"]})
            )
            .err()
            .ok_or("expected retired verification failure")?
            .status,
            400
        );
        let latest = reopened.export("GET", "public-key/test/latest")?;
        assert_eq!(
            latest.body["data"]["keys"]
                .as_object()
                .ok_or("missing versions")?
                .len(),
            1
        );
        assert!(latest.body["data"]["keys"].get("2").is_some());
    }
    Ok(())
}

#[test]
fn asymmetric270_signatures_cover_hashes_prehashes_jws_and_pss_salt() -> TestResult {
    for kind in KINDS {
        let mut transit = Transit::default();
        request(&mut transit, "keys/test", &json!({"type":kind}))?;
        for name in [
            "sha1", "sha2-224", "sha2-256", "sha2-384", "sha2-512", "sha3-224", "sha3-256",
            "sha3-384", "sha3-512",
        ] {
            for prehashed in [false, true] {
                for marshaling in ["asn1", "jws"] {
                    for scheme in if asymmetric::is_rsa(kind) {
                        &['p', 'k'][..]
                    } else {
                        &['k'][..]
                    } {
                        let raw = b"synthetic asymmetric test input";
                        let hash =
                            openssl::hash::MessageDigest::from_name(&name.replace("sha2-", "sha"))
                                .ok_or("missing hash")?;
                        let input = if prehashed {
                            BASE64.encode(openssl::hash::hash(hash, raw)?)
                        } else {
                            BASE64.encode(raw)
                        };
                        let options = json!({"input":input,"hash_algorithm":name,"prehashed":prehashed,"marshaling_algorithm":marshaling,"signature_algorithm":if *scheme=='p' {"pss"}else{"pkcs1v15"},"salt_length":"hash"});
                        let signed = request(&mut transit, "sign/test", &options)?;
                        let mut verify = options.clone();
                        verify["signature"] = signed.body["data"]["signature"].clone();
                        assert_eq!(
                            request(&mut transit, "verify/test", &verify)?.body["data"]["valid"],
                            true,
                            "{kind}/{name}/{prehashed}/{marshaling}"
                        );
                        verify["input"] =
                            json!(
                                BASE64.encode(vec![0xA5; if prehashed { hash.size() } else { 32 }])
                            );
                        assert_eq!(
                            request(&mut transit, "verify/test", &verify)?.body["data"]["valid"],
                            false
                        );
                    }
                }
            }
        }
        if asymmetric::is_rsa(kind) {
            for salt in [
                json!("auto"),
                json!("hash"),
                json!(0),
                json!(-1),
                json!(17),
                json!(true),
                json!(false),
            ] {
                let input = BASE64.encode(b"synthetic PSS salt");
                let signed = request(
                    &mut transit,
                    "sign/test",
                    &json!({"input":input,"salt_length":salt}),
                )?;
                assert_eq!(request(&mut transit,"verify/test",&json!({"input":input,"salt_length":salt,"signature":signed.body["data"]["signature"]}))?.body["data"]["valid"],true);
            }
        }
    }
    Ok(())
}

#[test]
fn asymmetric270_rsa_oaep_roundtrips_rejects_tamper_and_keeps_failed_counters() -> TestResult {
    for kind in ["rsa-2048", "rsa-3072", "rsa-4096"] {
        let mut transit = Transit::default();
        request(&mut transit, "keys/test", &json!({"type":kind}))?;
        let size = match kind {
            "rsa-2048" => 256,
            "rsa-3072" => 384,
            _ => 512,
        };
        for len in [0, 1, size - 66] {
            let input = BASE64.encode(vec![0x52; len]);
            let encrypted = request(&mut transit, "encrypt/test", &json!({"plaintext":input}))?;
            let decrypted = request(
                &mut transit,
                "decrypt/test",
                &json!({"ciphertext":encrypted.body["data"]["ciphertext"]}),
            )?;
            assert!(decrypted.body["data"]["plaintext"] == input);
        }
        let before = Zeroizing::new(serde_json::to_vec(&transit)?);
        assert_eq!(
            request(
                &mut transit,
                "encrypt/test",
                &json!({"plaintext":BASE64.encode(vec![0x52;size-65])})
            )
            .err()
            .ok_or("expected oversized failure")?
            .status,
            500
        );
        assert!(*before == serde_json::to_vec(&transit)?);
        assert!(
            request(
                &mut transit,
                "decrypt/test",
                &json!({"ciphertext":format!("vault:v1:{}",BASE64.encode(vec![0;size]))})
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn asymmetric270_prehash_and_padding_failures_match_observed_statuses() -> TestResult {
    for kind in ["ecdsa-p256", "rsa-2048"] {
        let mut transit = Transit::default();
        request(&mut transit, "keys/test", &json!({"type":kind}))?;
        let input = BASE64.encode(b"synthetic raw prehash");
        let signed = request(
            &mut transit,
            "sign/test",
            &json!({"input":input,"hash_algorithm":"none","prehashed":true,"signature_algorithm":"pkcs1v15"}),
        )?;
        assert_eq!(request(&mut transit,"verify/test",&json!({"input":input,"hash_algorithm":"none","prehashed":true,"signature_algorithm":"pkcs1v15","signature":signed.body["data"]["signature"]}))?.body["data"]["valid"],true);
        assert_eq!(
            request(
                &mut transit,
                "sign/test",
                &json!({"input":input,"hash_algorithm":"none","prehashed":true})
            )
            .err()
            .ok_or("expected none error")?
            .status,
            400
        );
        assert_eq!(
            request(
                &mut transit,
                "sign/test",
                &json!({"input":"","hash_algorithm":"sha2-256","prehashed":true})
            )
            .err()
            .ok_or("expected empty prehash error")?
            .status,
            500
        );
        let signed = request(
            &mut transit,
            "sign/test",
            &json!({"input":input,"context":"YQ=="}),
        )?;
        assert_eq!(request(&mut transit,"verify/test",&json!({"input":input,"signature":signed.body["data"]["signature"],"context":"Yg=="}))?.body["data"]["valid"],true);
        assert_eq!(
            request(
                &mut transit,
                "sign/test",
                &json!({"input":input,"context":"!invalid!"})
            )
            .err()
            .ok_or("expected invalid context")?
            .status,
            400
        );
    }
    Ok(())
}

#[test]
fn asymmetric270_explicit_standard_formats_use_real_private_key_info_and_spki() -> TestResult {
    use openssl::{hash::MessageDigest, sign::Verifier};
    for kind in KINDS.into_iter().chain(["ed25519"]) {
        let mut transit = Transit::default();
        let created = request(
            &mut transit,
            "keys/standard",
            &json!({"type":kind,"exportable":true}),
        )?;
        assert_eq!(created.status, 200);
        let input = b"synthetic standard exported key verification";
        let signed = request(
            &mut transit,
            "sign/standard",
            &json!({"input":BASE64.encode(input),"signature_algorithm":"pkcs1v15"}),
        )?;
        let signature = signed.body["data"]["signature"]
            .as_str()
            .ok_or("signature")?
            .strip_prefix("vault:v1:")
            .ok_or("version")?;
        let signature = BASE64.decode(signature)?;
        let before = serde_json::to_vec(&transit)?;
        for format in ["der", "pem"] {
            let public = transit.handle(
                "",
                "transit",
                "GET",
                "export/public-key/standard/latest",
                &json!({"format":format}),
                100,
            )?;
            let private = transit.handle(
                "",
                "transit",
                "GET",
                "export/signing-key/standard/1",
                &json!({"format":format}),
                100,
            )?;
            assert!(!public.mutated && !private.mutated);
            let public = public.body["data"]["keys"]["1"].as_str().ok_or("public")?;
            let private = private.body["data"]["keys"]["1"]
                .as_str()
                .ok_or("private")?;
            let (public, private) = if format == "der" {
                let public_der = BASE64.decode(public)?;
                let private_der = Zeroizing::new(BASE64.decode(private)?);
                let public = PKey::public_key_from_der(&public_der)?;
                let private = PKey::private_key_from_pkcs8(&private_der)?;
                assert_eq!(public.public_key_to_der()?, public_der);
                assert_eq!(
                    private.private_key_to_pkcs8()?.as_slice(),
                    private_der.as_slice()
                );
                (public, private)
            } else {
                assert!(public.starts_with("-----BEGIN PUBLIC KEY-----\n"));
                assert!(public.ends_with("-----END PUBLIC KEY-----\n"));
                assert!(private.starts_with("-----BEGIN PRIVATE KEY-----\n"));
                assert!(private.ends_with("-----END PRIVATE KEY-----\n"));
                (
                    PKey::public_key_from_pem(public.as_bytes())?,
                    PKey::private_key_from_pem(private.as_bytes())?,
                )
            };
            assert_eq!(public.public_key_to_der()?, private.public_key_to_der()?);
            for (message, valid) in [
                (input.as_slice(), true),
                (b"changed input".as_slice(), false),
            ] {
                let mut verifier = if kind == "ed25519" {
                    Verifier::new_without_digest(&public)?
                } else {
                    Verifier::new(MessageDigest::sha256(), &public)?
                };
                if asymmetric::is_rsa(kind) {
                    verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
                }
                assert_eq!(verifier.verify_oneshot(&signature, message)?, valid);
            }
        }
        assert_eq!(serde_json::to_vec(&transit)?, before);
    }
    Ok(())
}

#[test]
fn asymmetric270_standard_export_and_ed25519_raw_enforce_permission_and_versions() -> TestResult {
    for kind in ["ed25519", "ecdsa-p256", "rsa-2048"] {
        let mut transit = Transit::default();
        request(&mut transit, "keys/permissions", &json!({"type":kind}))?;
        let before = serde_json::to_vec(&transit)?;
        for format in ["der", "pem"] {
            let public = transit.handle(
                "",
                "transit",
                "GET",
                "export/public-key/permissions",
                &json!({"format":format}),
                100,
            )?;
            assert!(!public.mutated);
            assert!(public.body["data"]["keys"]["1"].as_str().is_some());
            assert!(matches!(
                transit.handle(
                    "",
                    "transit",
                    "GET",
                    "export/signing-key/permissions",
                    &json!({"format":format}),
                    100,
                ),
                Err(EngineError { status: 403, .. })
            ));
        }
        assert_eq!(serde_json::to_vec(&transit)?, before);
        request(
            &mut transit,
            "keys/permissions/config",
            &json!({"exportable":true}),
        )?;
        request(&mut transit, "keys/permissions/rotate", &json!({}))?;
        request(
            &mut transit,
            "keys/permissions/config",
            &json!({"min_decryption_version":2}),
        )?;
        let before = serde_json::to_vec(&transit)?;
        for format in ["der", "pem"] {
            assert!(
                transit
                    .handle(
                        "",
                        "transit",
                        "GET",
                        "export/signing-key/permissions/1",
                        &json!({"format":format}),
                        100,
                    )
                    .is_err()
            );
            let latest = transit.handle(
                "",
                "transit",
                "GET",
                "export/signing-key/permissions/latest",
                &json!({"format":format}),
                100,
            )?;
            assert!(latest.body["data"]["keys"]["1"].is_null());
            assert!(latest.body["data"]["keys"]["2"].as_str().is_some());
        }
        if kind == "ed25519" {
            let mut raw = Vec::new();
            for target in ["signing-key", "public-key"] {
                let legacy = transit.handle(
                    "",
                    "transit",
                    "GET",
                    &format!("export/{target}/permissions/latest"),
                    &json!({}),
                    100,
                )?;
                let explicit = transit.handle(
                    "",
                    "transit",
                    "GET",
                    &format!("export/{target}/permissions/latest"),
                    &json!({"format":"raw"}),
                    100,
                )?;
                assert_eq!(legacy.body, explicit.body);
                raw.push(BASE64.decode(legacy.body["data"]["keys"]["2"].as_str().ok_or("raw")?)?);
            }
            assert_eq!(raw[0].len(), 64);
            assert_eq!(raw[1].len(), 32);
            assert_eq!(&raw[0][32..], raw[1].as_slice());
            let pair = signature::Ed25519KeyPair::from_seed_and_public_key(&raw[0][..32], &raw[1])
                .map_err(|_| "exported raw Ed25519 private/public")?;
            let input = b"synthetic exported raw Ed25519";
            signature::UnparsedPublicKey::new(&signature::ED25519, &raw[1])
                .verify(input, pair.sign(input).as_ref())
                .map_err(|_| "real exported Ed25519 verification")?;
        } else {
            for target in ["signing-key", "public-key"] {
                assert!(matches!(
                    transit.handle(
                        "",
                        "transit",
                        "GET",
                        &format!("export/{target}/permissions/latest"),
                        &json!({"format":"raw"}),
                        100,
                    ),
                    Err(EngineError { status: 400, .. })
                ));
            }
        }
        assert_eq!(serde_json::to_vec(&transit)?, before);
    }
    Ok(())
}
