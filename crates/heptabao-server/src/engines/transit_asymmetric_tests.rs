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
