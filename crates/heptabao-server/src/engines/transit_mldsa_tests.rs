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
    reopened.handle(
        "",
        "transit",
        "POST",
        "keys/test/config",
        &json!({"min_decryption_version":2}),
        104,
    )?;
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
