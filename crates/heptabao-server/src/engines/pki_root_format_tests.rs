//! Public internal-root output contracts; stored DER and private ownership stay fixed.
use super::*;
use openssl::{pkey::Id, x509::X509};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn certificate_der(
    response: &EngineResponse,
    format: &str,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let certificate = response.body["data"]["certificate"]
        .as_str()
        .ok_or("certificate field")?;
    let issuing_ca = response.body["data"]["issuing_ca"]
        .as_str()
        .ok_or("issuing CA field")?;
    assert!(certificate == issuing_ca, "self-signed response CA differs");
    assert!(
        response.body["data"].get("private_key").is_none(),
        "internal root exposes a private field"
    );
    if format == "der" {
        let der = BASE64.decode(certificate)?;
        assert!(
            BASE64.encode(&der) == certificate,
            "DER response is not canonical base64"
        );
        Ok(der)
    } else {
        assert!(!certificate.ends_with('\n'), "PEM response has a final LF");
        assert!(
            certificate.matches("-----BEGIN CERTIFICATE-----").count() == 1,
            "internal bundle has multiple certificates"
        );
        assert!(
            !certificate.contains("PRIVATE KEY"),
            "internal bundle exposes key material"
        );
        Ok(X509::from_pem(certificate.as_bytes())?.to_der()?)
    }
}

#[test]
fn local_root_formats_use_real_selected_crypto_and_survive_serde() -> TestResult {
    for (kind, bits, id) in [
        ("ed25519", 0, Id::ED25519),
        ("ec", 256, Id::EC),
        ("rsa", 2048, Id::RSA),
    ] {
        for format in ["pem", "der", "pem_bundle"] {
            let mut pki = Pki::default();
            let generated = pki.handle_admin("POST", "root/generate/internal", &json!({
                "common_name":"formats.example.test", "ttl":"1h", "key_type":kind, "key_bits":bits, "format":format
            }), 1_700_000_000)?;
            assert!(generated.status == 200, "root format generation rejected");
            let der = certificate_der(&generated, format)?;
            let cert = X509::from_der(&der)?;
            let public = cert.public_key()?;
            assert!(public.id() == id, "root certificate algorithm differs");
            assert!(cert.verify(&public)?, "root self-signature is invalid");
            let root = pki.root.as_ref().ok_or("root owner")?;
            assert!(
                der == root.certificate_der,
                "wire format changed stored DER"
            );
            root.local_key()?.public()?.validate_certificate(&der)?;
            let mut changed = der.clone();
            let last = changed.last_mut().ok_or("certificate bytes")?;
            *last ^= 1;
            assert!(
                !X509::from_der(&changed)?.verify(&public)?,
                "tampered signature was accepted"
            );
            let encoded = Zeroizing::new(serde_json::to_vec(&pki)?);
            let restored: Pki = serde_json::from_slice(encoded.as_slice())?;
            let restored_root = restored.root.as_ref().ok_or("restored root owner")?;
            assert!(
                restored_root.certificate_der == der,
                "serde altered root DER"
            );
            restored_root
                .local_key()?
                .public()?
                .validate_certificate(&der)?;
            if kind == "ed25519" {
                assert!(
                    restored_root.local_material.is_none() && !restored_root.pkcs8.is_empty(),
                    "legacy Ed owner changed"
                );
            } else {
                assert!(
                    restored_root.local_material.is_some() && restored_root.pkcs8.is_empty(),
                    "typed owner changed"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn internal_private_key_format_observed_scalars_are_ignored_without_private_output() -> TestResult {
    for value in [
        json!(""),
        json!("der"),
        json!("pem"),
        json!("pkcs8"),
        json!("unknown-root-private-format"),
        Value::Null,
        json!(true),
        json!(1),
    ] {
        let mut pki = Pki::default();
        let generated = pki.handle_admin("PUT", "root/generate/internal", &json!({
            "common_name":"ignored.example.test", "ttl":"1h", "key_type":"ed25519", "private_key_format":value
        }), 1_700_000_000)?;
        assert!(generated.status == 200, "internal private format rejected");
        let der = certificate_der(&generated, "pem")?;
        let cert = X509::from_der(&der)?;
        let public = cert.public_key()?;
        assert!(
            cert.verify(&public)?,
            "ignored option broke actual root signature"
        );
    }
    Ok(())
}

#[test]
fn invalid_root_formats_and_unrelated_fields_leave_engine_state_unchanged() -> TestResult {
    let mut pki = Pki::default();
    let before = Zeroizing::new(serde_json::to_vec(&pki)?);
    for value in [
        json!(""),
        json!("unknown-root-format"),
        Value::Null,
        json!(true),
        json!(1),
        json!([]),
        json!({}),
    ] {
        let result = pki.handle_admin(
            "POST",
            "root/generate/internal",
            &json!({
                "common_name":"rejected.example.test", "key_type":"ed25519", "format":value
            }),
            1_700_000_000,
        );
        assert!(
            matches!(result, Err(ref error) if error.status == 400),
            "invalid format was not rejected"
        );
        let after = Zeroizing::new(serde_json::to_vec(&pki)?);
        assert!(
            before.as_slice() == after.as_slice(),
            "invalid format mutated root state"
        );
    }
    let result = pki.handle_admin("POST", "root/generate/internal", &json!({
        "common_name":"rejected.example.test", "key_type":"ed25519", "format":"pem", "unrelated":true
    }), 1_700_000_000);
    assert!(
        matches!(result, Err(ref error) if error.status == 400),
        "unrelated option was accepted"
    );
    let after = Zeroizing::new(serde_json::to_vec(&pki)?);
    assert!(
        before.as_slice() == after.as_slice(),
        "unknown option mutated root state"
    );
    Ok(())
}
