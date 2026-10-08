//! Real CA signatures are verified by ssh-key's independent public crypto.
//! These source controls are not an OpenBao paired runtime qualification.
use super::*;
use ssh_key::{Certificate, HashAlg, certificate::CertType};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn context() -> SigningContext<'static> {
    SigningContext {
        role_name: "operators",
        display_name: "alice-token",
        now: 1_700_000_000,
        default_ttl: 3600,
        max_ttl: 86400,
    }
}
fn configured(kind: &str, bits: u32, algorithm: &str) -> Result<CaState> {
    let mut ca = CaState::default();
    let response = ca
        .handle_admin(
            "POST",
            "config/ca",
            &json!({"key_type":kind,"key_bits":bits}),
        )?
        .ok_or_else(not_found)?;
    assert_eq!(response.status, 200);
    ca.put_role(
        "operators",
        &json!({"key_type":"ca","allow_user_certificates":true,
        "allowed_users":"alice,bob","default_user":"alice","ttl":"90s",
        "algorithm_signer":algorithm,"allowed_extensions":"permit-pty",
        "allowed_critical_options":"source-address"}),
    )?;
    ca.validate()?;
    Ok(ca)
}
#[test]
fn ssh115_real_six_ca_algorithms_independent_trust_time_and_tamper_checks() -> TestResult {
    let subject = crypto_key::generate("ed25519", 0)?;
    let public = subject.public()?;
    let wrong = crypto_key::generate("ed25519", 0)?
        .public()?
        .fingerprint(HashAlg::Sha256);
    for (kind, bits, algorithm) in [
        ("rsa", 2048, "rsa-sha2-256"),
        ("rsa", 2048, "rsa-sha2-512"),
        ("ec", 256, "default"),
        ("ec", 384, "default"),
        ("ec", 521, "default"),
        ("ed25519", 0, "default"),
    ] {
        let mut ca = configured(kind, bits, algorithm)?;
        let response = ca.sign(
            &json!({"public_key":public.to_openssh()?,
            "critical_options":{"source-address":"192.0.2.0/24"},
            "extensions":{"permit-pty":""}}),
            &context(),
            false,
        )?;
        assert!(response.mutated);
        assert_eq!(ca.signatures, 1);
        let cert = Certificate::from_openssh(
            response.body["data"]["signed_key"]
                .as_str()
                .ok_or("certificate")?,
        )?;
        let trusted =
            PublicKey::from_openssh(ca.public_key("default")?)?.fingerprint(HashAlg::Sha256);
        cert.validate_at(context().now, [&trusted])?;
        assert!(cert.validate_at(context().now, [&wrong]).is_err());
        assert!(cert.validate_at(context().now + 90, [&trusted]).is_err());
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(cert.public_key(), public.key_data());
        assert_eq!(cert.valid_principals(), ["alice"]);
        assert_eq!(cert.valid_after(), context().now - 30);
        assert_eq!(cert.valid_before(), context().now + 90);
        assert_eq!(
            cert.critical_options()
                .get("source-address")
                .map(String::as_str),
            Some("192.0.2.0/24")
        );
        assert_eq!(
            cert.extensions().get("permit-pty").map(String::as_str),
            Some("")
        );
        assert_eq!(
            u64::from_str_radix(
                response.body["data"]["serial_number"]
                    .as_str()
                    .ok_or("serial")?,
                16
            )?,
            cert.serial()
        );
        let mut encoded = cert.to_bytes()?;
        *encoded.last_mut().ok_or("signature")? ^= 1;
        let tampered = Certificate::from_bytes(&encoded)?;
        assert!(tampered.validate_at(context().now, [&trusted]).is_err());
    }
    Ok(())
}
#[test]
fn ssh115_issue_returns_matching_actual_private_subject_and_public_certificate() -> TestResult {
    let mut ca = configured("ed25519", 0, "default")?;
    for (kind, bits) in [("rsa", 2048), ("ec", 384), ("ed25519", 0)] {
        let response = ca.sign(
            &json!({"key_type":kind,"key_bits":bits,
            "valid_principals":"bob"}),
            &context(),
            true,
        )?;
        let private = crypto_key::import(
            response.body["data"]["private_key"]
                .as_str()
                .ok_or("private key")?,
        )?;
        let cert = Certificate::from_openssh(
            response.body["data"]["signed_key"]
                .as_str()
                .ok_or("certificate")?,
        )?;
        assert_eq!(cert.public_key(), private.public()?.key_data());
        assert_eq!(cert.valid_principals(), ["bob"]);
        cert.validate_at(
            context().now,
            [&PublicKey::from_openssh(ca.public_key("default")?)?.fingerprint(HashAlg::Sha256)],
        )?;
        assert_eq!(response.body["data"]["private_key_type"], kind);
    }
    assert_eq!(ca.signatures, 3);
    Ok(())
}
#[test]
fn ssh115_import_pair_binding_duplicate_identity_and_strict_encrypted_state() -> TestResult {
    let material = crypto_key::generate("ed25519", 0)?;
    let public = material.public()?.to_openssh()?;
    let mut ca = CaState::default();
    let input = json!({"generate_signing_key":false,"private_key":material.pem(),
        "public_key":public,"issuer_name":"primary"});
    let created = ca
        .handle_admin("POST", "issuers/import", &input)?
        .ok_or("created issuer")?;
    let duplicate = ca
        .handle_admin("POST", "issuers/import", &input)?
        .ok_or("duplicate issuer")?;
    assert_eq!(
        created.body["data"]["issuer_id"],
        duplicate.body["data"]["issuer_id"]
    );
    assert_eq!(
        duplicate.body["warnings"]
            .as_array()
            .ok_or("warning")?
            .len(),
        1
    );
    assert_eq!(ca.issuers.len(), 1);
    let decoded: CaState =
        serde_json::from_slice(&zeroize::Zeroizing::new(serde_json::to_vec(&ca)?))?;
    decoded.validate()?;
    let mut mismatched = input.clone();
    mismatched["public_key"] = json!(crypto_key::generate("ed25519", 0)?.public()?.to_openssh()?);
    assert_eq!(
        ca.handle_admin("POST", "issuers/import", &mismatched)
            .err()
            .ok_or("pair rejection")?
            .status,
        400
    );
    assert_eq!(ca.issuers.len(), 1);
    let mut corrupt: Value = serde_json::to_value(&ca)?;
    corrupt["unknown_custody"] = json!(true);
    assert!(serde_json::from_value::<CaState>(corrupt).is_err());
    Ok(())
}
#[test]
fn ssh115_expired_original_deadline_never_creates_or_signs_a_candidate() -> TestResult {
    let mut ca = configured("ed25519", 0, "default")?;
    let public = crypto_key::generate("ed25519", 0)?.public()?.to_openssh()?;
    let before = ca.signatures;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() - std::time::Duration::from_millis(1),
    );
    assert_eq!(
        ca.sign(&json!({"public_key":public}), &context(), false)
            .err()
            .ok_or("deadline")?
            .status,
        503
    );
    assert_eq!(ca.signatures, before);
    assert_eq!(
        ca.handle_admin("POST", "config/ca", &json!({"key_type":"ed25519"}))
            .err()
            .ok_or("generation deadline")?
            .status,
        503
    );
    assert_eq!(ca.issuers.len(), 1);
    Ok(())
}

#[test]
fn ssh115_role_limit_combines_ca_and_otp_and_same_name_replacement_remains_legal() -> TestResult {
    let mut engine = super::super::ssh::SshOtp::default();
    for i in 0..128 {
        engine.handle_role(
            "POST",
            &format!("roles/r{i}"),
            &json!({"key_type":"ca","allowed_users":"alice","allow_user_certificates":true}),
            100,
            "",
        )?;
    }
    assert_eq!(
        engine
            .handle_role(
                "POST",
                "roles/overflow",
                &json!({"key_type":"otp","default_user":"alice","cidr_list":"192.0.2.0/24"}),
                100,
                ""
            )
            .err()
            .ok_or("combined capacity")?
            .status,
        507
    );
    engine.handle_role(
        "POST",
        "roles/r0",
        &json!({"key_type":"otp","default_user":"alice","cidr_list":"192.0.2.0/24"}),
        100,
        "",
    )?;
    engine.validate("", "ssh/", 100)?;
    assert_eq!(
        engine
            .handle_role("GET", "roles/r0", &json!({}), 100, "")?
            .body["data"]["key_type"],
        "otp"
    );
    engine.handle_role(
        "POST",
        "roles/r0",
        &json!({"key_type":"ca","allowed_users":"alice","allow_user_certificates":true}),
        100,
        "",
    )?;
    engine.validate("", "ssh/", 100)?;
    assert_eq!(
        engine
            .handle_role("GET", "roles/r0", &json!({}), 100, "")?
            .body["data"]["key_type"],
        "ca"
    );
    Ok(())
}
#[test]
fn ssh115_issuer_delete_retains_role_reference_warns_and_missing_delete_is_idempotent() -> TestResult
{
    let mut ca = configured("ed25519", 0, "default")?;
    let deleted = ca
        .handle_admin("DELETE", "issuer/default", &json!({}))?
        .ok_or("delete")?;
    assert_eq!(deleted.status, 200);
    assert_eq!(
        deleted.body["warnings"].as_array().ok_or("warnings")?.len(),
        2
    );
    assert!(ca.default_issuer.is_none());
    assert!(ca.contains_role("operators"));
    assert!(ca.public_key("default").is_err());
    let absent = ca
        .handle_admin("DELETE", "issuer/removed", &json!({}))?
        .ok_or("missing delete")?;
    assert_eq!(absent.status, 204);
    assert!(!absent.mutated);
    ca.validate()?;
    Ok(())
}
