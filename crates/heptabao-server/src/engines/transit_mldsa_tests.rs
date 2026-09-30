//! Native OpenBao 2.7 ML-DSA regressions; test input is synthetic.
use super::*;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn mldsa270_generated_keys_sign_verify_and_reject_changed_messages() -> TestResult {
    for kind in ["mldsa-44", "mldsa-65", "mldsa-87"] {
        let mut transit = Transit::default();
        let created = transit.handle(
            "",
            "transit",
            "POST",
            "keys/test",
            &json!({"type":kind}),
            100,
        )?;
        assert_eq!(created.status, 200);
        assert_eq!(created.body["data"]["type"], kind);
        assert_eq!(created.body["data"]["supports_signing"], true);
        assert!(
            created.body["data"]["keys"]["1"]["public_key"]
                .as_str()
                .is_some()
        );
        let input = BASE64.encode(b"synthetic ML-DSA message");
        let signed = transit.handle(
            "",
            "transit",
            "POST",
            "sign/test",
            &json!({"input":input}),
            101,
        )?;
        let sig = &signed.body["data"]["signature"];
        assert_eq!(signed.body["data"]["key_version"], 1);
        let valid = transit.handle(
            "",
            "transit",
            "POST",
            "verify/test",
            &json!({"input":input,"signature":sig}),
            102,
        )?;
        assert_eq!(valid.body["data"]["valid"], true);
        let wrong = transit.handle(
            "",
            "transit",
            "POST",
            "verify/test",
            &json!({"input":BASE64.encode(b"changed"),"signature":sig}),
            102,
        )?;
        assert_eq!(wrong.body["data"]["valid"], false);
    }
    Ok(())
}

#[test]
fn mldsa270_rotation_retains_old_signatures_and_enforces_minimum_versions() -> TestResult {
    let mut transit = Transit::default();
    transit.handle(
        "",
        "transit",
        "POST",
        "keys/test",
        &json!({"type":"mldsa-44"}),
        100,
    )?;
    let input = BASE64.encode(b"synthetic retained message");
    let signed = transit.handle(
        "",
        "transit",
        "POST",
        "sign/test",
        &json!({"input":input}),
        101,
    )?;
    transit.handle("", "transit", "POST", "keys/test/rotate", &json!({}), 102)?;
    let mut reopened: Transit = serde_json::from_value(serde_json::to_value(&transit)?)?;
    let valid = reopened.handle(
        "",
        "transit",
        "POST",
        "verify/test",
        &json!({"input":input,"signature":signed.body["data"]["signature"]}),
        103,
    )?;
    assert_eq!(valid.body["data"]["valid"], true);
    let configured = reopened.handle(
        "",
        "transit",
        "POST",
        "keys/test/config",
        &json!({"min_decryption_version":2}),
        104,
    )?;
    assert_eq!(configured.status, 200);
    assert!(configured.mutated);
    assert_eq!(configured.body["data"]["type"], "mldsa-44");
    assert_eq!(configured.body["data"]["latest_version"], 2);
    assert_eq!(configured.body["data"]["min_decryption_version"], 2);
    assert!(
        reopened
            .handle(
                "",
                "transit",
                "POST",
                "verify/test",
                &json!({"input":input,"signature":signed.body["data"]["signature"]}),
                105
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn mldsa270_public_encoding_seed_export_and_randomized_signatures() -> TestResult {
    for (kind, public_len, signature_len) in [
        ("mldsa-44", 1312, 2420),
        ("mldsa-65", 1952, 3309),
        ("mldsa-87", 2592, 4627),
    ] {
        let mut transit = Transit::default();
        transit.handle(
            "",
            "transit",
            "POST",
            "keys/test",
            &json!({"type":kind,"exportable":true}),
            100,
        )?;
        let descriptor = transit.handle("", "transit", "GET", "keys/test", &json!({}), 101)?;
        let public = descriptor.body["data"]["keys"]["1"]["public_key"]
            .as_str()
            .ok_or("public")?;
        assert_eq!(BASE64.decode(public)?.len(), public_len);
        let exported = transit.handle(
            "",
            "transit",
            "GET",
            "export/signing-key/test",
            &json!({}),
            101,
        )?;
        let seed = Zeroizing::new(
            BASE64.decode(exported.body["data"]["keys"]["1"].as_str().ok_or("seed")?)?,
        );
        assert_eq!(seed.len(), 32);
        assert!(mldsa::public(kind, &seed)? == BASE64.decode(public)?);
        let input = BASE64.encode(b"synthetic randomized signing");
        let first = transit.handle(
            "",
            "transit",
            "POST",
            "sign/test",
            &json!({"input":input}),
            102,
        )?;
        let second = transit.handle(
            "",
            "transit",
            "POST",
            "sign/test",
            &json!({"input":input}),
            102,
        )?;
        assert!(first.body["data"]["signature"] != second.body["data"]["signature"]);
        let (_, bytes) = parse_wrapped(
            first.body["data"]["signature"]
                .as_str()
                .ok_or("signature")?,
        )?;
        assert_eq!(bytes.len(), signature_len);
        assert!(mldsa::verify(
            kind,
            &seed,
            b"synthetic randomized signing",
            &bytes
        )?);
        assert!(!mldsa::verify(kind, &seed, b"changed", &bytes)?);
        assert!(!mldsa::verify(
            kind,
            &seed,
            b"synthetic randomized signing",
            &bytes[..bytes.len() - 1]
        )?);
        transit.validate_mldsa_state()?;
    }
    Ok(())
}

#[test]
fn mldsa270_public_export_never_releases_a_nonexportable_seed() -> TestResult {
    let mut transit = Transit::default();
    transit.handle(
        "",
        "transit",
        "POST",
        "keys/test",
        &json!({"type":"mldsa-44"}),
        100,
    )?;
    assert!(
        transit
            .handle(
                "",
                "transit",
                "GET",
                "export/signing-key/test",
                &json!({}),
                101
            )
            .is_err()
    );
    let public = transit.handle(
        "",
        "transit",
        "GET",
        "export/public-key/test",
        &json!({}),
        101,
    )?;
    assert_eq!(
        BASE64
            .decode(public.body["data"]["keys"]["1"].as_str().ok_or("public")?)?
            .len(),
        1312
    );
    Ok(())
}

#[test]
fn mldsa270_batch_failures_and_corrupt_seed_never_mutate_retained_keys() -> TestResult {
    let mut transit = Transit::default();
    transit.handle(
        "",
        "transit",
        "POST",
        "keys/test",
        &json!({"type":"mldsa-65"}),
        100,
    )?;
    let before = Zeroizing::new(serde_json::to_vec(&transit)?);
    let response=transit.handle("", "transit", "POST", "sign/test", &json!({"batch_input":[{"input":"eA==","reference":"good"},{"input":"!","reference":"bad"}]}),101)?;
    assert_eq!(response.status, 400);
    assert!(response.body["data"]["batch_results"][0]["signature"].is_string());
    assert!(response.body["data"]["batch_results"][1]["error"].is_string());
    assert!(!response.mutated);
    assert!(*before == *Zeroizing::new(serde_json::to_vec(&transit)?));
    let key = transit.keys.get_mut("test").ok_or("key")?;
    key.deleted = true;
    assert!(transit.has_mldsa_state());
    transit
        .keys
        .get_mut("test")
        .ok_or("key")?
        .versions
        .get_mut(&1)
        .ok_or("version")?
        .material = BASE64.encode(b"invalid");
    assert!(transit.validate_mldsa_state().is_err());
    Ok(())
}

// Independent FIPS 204 preprocessing proves that external-mu does not sign
// the 64-byte input as an ordinary message. Public test material stays local.
fn fips204_mu(public: &[u8], message: &[u8]) -> [u8; 64] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut tr_hash = sha3::Shake256::default();
    tr_hash.update(public);
    let mut tr = [0u8; 64];
    tr_hash.finalize_xof().read(&mut tr);
    let mut mu_hash = sha3::Shake256::default();
    mu_hash.update(&tr);
    mu_hash.update(&[0, 0]);
    mu_hash.update(message);
    let mut mu = [0u8; 64];
    mu_hash.finalize_xof().read(&mut mu);
    mu
}

#[test]
fn mldsa270_external_mu_interoperates_with_pure_signatures_for_every_parameter_set() -> TestResult {
    for kind in ["mldsa-44", "mldsa-65", "mldsa-87"] {
        let mut transit = Transit::default();
        transit.handle(
            "",
            "transit",
            "POST",
            "keys/test",
            &json!({"type":kind}),
            100,
        )?;
        let descriptor = transit.handle("", "transit", "GET", "keys/test", &json!({}), 101)?;
        let public = BASE64.decode(
            descriptor.body["data"]["keys"]["1"]["public_key"]
                .as_str()
                .ok_or("public")?,
        )?;
        let message = b"synthetic FIPS 204 preprocessing";
        let mu = fips204_mu(&public, message);
        let pure = transit.handle(
            "",
            "transit",
            "POST",
            "sign/test",
            &json!({"input":BASE64.encode(message),"hash_algorithm":"none"}),
            102,
        )?;
        let key = transit.keys.get("test").ok_or("key")?;
        let seed = stored_material(&key.versions.get(&1).ok_or("version")?.material)?;
        let (_, pure_bytes) =
            parse_wrapped(pure.body["data"]["signature"].as_str().ok_or("signature")?)?;
        assert!(mldsa::verify_mu(kind, &seed, &mu, &pure_bytes)?);
        let first = transit.handle(
            "",
            "transit",
            "POST",
            "sign/test",
            &json!({"input":BASE64.encode(mu),"prehashed":true,"hash_algorithm":"mldsa-mu"}),
            104,
        )?;
        let second = transit.handle(
            "",
            "transit",
            "POST",
            "sign/test/mldsa-mu",
            &json!({"input":BASE64.encode(mu),"prehashed":true}),
            104,
        )?;
        assert_eq!(first.body["data"]["key_version"], 1);
        assert_ne!(
            first.body["data"]["signature"],
            second.body["data"]["signature"]
        );
        let verified = transit.handle("", "transit", "POST", "verify/test", &json!({"input":BASE64.encode(message),"hash_algorithm":"none","signature":first.body["data"]["signature"]}), 105)?;
        assert_eq!(verified.body["data"]["valid"], true);
        let mut changed = mu;
        changed[0] ^= 1;
        let (_, first_bytes) = parse_wrapped(
            first.body["data"]["signature"]
                .as_str()
                .ok_or("signature")?,
        )?;
        assert!(!mldsa::verify_mu(kind, &seed, &changed, &first_bytes)?);
        assert_eq!(transit.handle("", "transit", "POST", "verify/test/mldsa-mu", &json!({"input":BASE64.encode(mu),"prehashed":true,"signature":first.body["data"]["signature"]}), 105).err().ok_or("mu verification accepted")?.status, 400);
        transit.handle("", "transit", "POST", "keys/test/rotate", &json!({}), 106)?;
        let mut reopened: Transit = serde_json::from_value(serde_json::to_value(&transit)?)?;
        assert_eq!(reopened.handle("", "transit", "POST", "verify/test", &json!({"input":BASE64.encode(message),"signature":first.body["data"]["signature"]}), 107)?.body["data"]["valid"], true);
        reopened.handle(
            "",
            "transit",
            "POST",
            "keys/test/config",
            &json!({"min_decryption_version":2}),
            108,
        )?;
        assert_eq!(reopened.handle("", "transit", "POST", "verify/test", &json!({"input":BASE64.encode(message),"signature":first.body["data"]["signature"]}), 109).err().ok_or("retired")?.status, 400);
    }
    Ok(())
}

#[test]
fn mldsa270_external_mu_rejects_malformed_length_options_and_conflicts_without_mutation()
-> TestResult {
    let mut transit = Transit::default();
    transit.handle(
        "",
        "transit",
        "POST",
        "keys/test",
        &json!({"type":"mldsa-44"}),
        100,
    )?;
    let before = Zeroizing::new(serde_json::to_vec(&transit)?);
    for length in [0, 63, 65] {
        let body = json!({"input":BASE64.encode(vec![0u8;length]),"prehashed":true,"hash_algorithm":"mldsa-mu"});
        assert_eq!(
            transit
                .handle("", "transit", "POST", "sign/test", &body, 101)
                .err()
                .ok_or("length accepted")?
                .status,
            500
        );
        let mut verify = body;
        verify["signature"] = json!("vault:v1:AA==");
        assert_eq!(
            transit
                .handle("", "transit", "POST", "verify/test", &verify, 101)
                .err()
                .ok_or("verify length accepted")?
                .status,
            400
        );
    }
    for body in [
        json!({"input":BASE64.encode([0u8;64]),"hash_algorithm":"mldsa-mu"}),
        json!({"input":BASE64.encode([0u8;64]),"hash_algorithm":"mldsa-mu","prehashed":false}),
        json!({"input":BASE64.encode([0u8;64]),"hash_algorithm":"mldsa-mu","prehashed":"true"}),
    ] {
        assert_eq!(
            transit
                .handle("", "transit", "POST", "sign/test", &body, 101)
                .err()
                .ok_or("prehashed accepted")?
                .status,
            400
        );
    }
    assert_eq!(
        transit
            .handle(
                "",
                "transit",
                "POST",
                "sign/test/mldsa-mu",
                &json!({"input":BASE64.encode([0u8;64]),"hash_algorithm":"none","prehashed":true}),
                101
            )
            .err()
            .ok_or("conflict accepted")?
            .status,
        400
    );
    let batch = transit.handle("", "transit", "POST", "sign/test/mldsa-mu", &json!({"prehashed":true,"batch_input":[{"input":BASE64.encode([0u8;64]),"reference":"valid"},{"input":BASE64.encode([0u8;63]),"reference":"invalid"}]}), 102)?;
    assert_eq!(batch.status, 400);
    assert!(batch.body["data"]["batch_results"][0]["signature"].is_string());
    assert!(batch.body["data"]["batch_results"][1]["error"].is_string());
    assert!(!batch.mutated);
    assert_eq!(*before, *Zeroizing::new(serde_json::to_vec(&transit)?));
    Ok(())
}

#[test]
fn mldsa270_pure_signing_ignores_generic_hash_prehashed_and_derivation_context() -> TestResult {
    let mut transit = Transit::default();
    transit.handle(
        "",
        "transit",
        "POST",
        "keys/test",
        &json!({"type":"mldsa-44"}),
        100,
    )?;
    let input = BASE64.encode(b"synthetic pure message, not a caller hash");
    for algorithm in ["none", "sha2-256", "sha2-512"] {
        for prehashed in [false, true] {
            let signed = transit.handle("", "transit", "POST", "sign/test", &json!({"input":input,"hash_algorithm":algorithm,"prehashed":prehashed,"context":BASE64.encode(b"ignored-context")}), 101)?;
            let verified = transit.handle("", "transit", "POST", "verify/test", &json!({"input":input,"signature":signed.body["data"]["signature"],"context":BASE64.encode(b"different-context")}), 102)?;
            assert_eq!(verified.body["data"]["valid"], true);
        }
    }
    let before = serde_json::to_value(&transit)?;
    for operation in ["sign/test", "verify/test"] {
        for context in [json!("!"), json!("non-derived-context"), json!(17)] {
            assert_eq!(
                transit
                    .handle(
                        "",
                        "transit",
                        "POST",
                        operation,
                        &json!({"input":input,"context":context}),
                        103
                    )
                    .err()
                    .ok_or("malformed context accepted")?
                    .status,
                400
            );
            assert_eq!(serde_json::to_value(&transit)?, before);
        }
    }
    assert_eq!(
        transit
            .handle(
                "",
                "transit",
                "POST",
                "sign/test",
                &json!({"input":input,"hash_algorithm":"not-an-algorithm"}),
                103
            )
            .err()
            .ok_or("algorithm accepted")?
            .status,
        400
    );
    Ok(())
}
