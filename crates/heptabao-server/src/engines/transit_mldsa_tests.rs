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
