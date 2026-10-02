use super::*;

type TestResult = std::result::Result<(), &'static str>;

fn kinds() -> [LocalKeyKind; 11] {
    [
        LocalKeyKind::Rsa2048,
        LocalKeyKind::Rsa3072,
        LocalKeyKind::Rsa4096,
        LocalKeyKind::Ec224,
        LocalKeyKind::Ec256,
        LocalKeyKind::Ec384,
        LocalKeyKind::Ec521,
        LocalKeyKind::Ed25519,
        LocalKeyKind::Mldsa44,
        LocalKeyKind::Mldsa65,
        LocalKeyKind::Mldsa87,
    ]
}

#[test]
fn all_local_key_algorithms_sign_verify_and_export_standard_pkcs8() -> TestResult {
    for kind in kinds() {
        let material = LocalPrivateMaterial::generate(kind).map_err(|_| "key generation")?;
        let public = material.public().map_err(|_| "public key")?;
        public.validate().map_err(|_| "public validation")?;
        assert!(public.kind() == kind, "generated key selection");
        let message = b"public local PKI cryptographic fixture";
        let signature = material.sign(message).map_err(|_| "real signature")?;
        assert!(
            public
                .verify(message, &signature)
                .map_err(|_| "real verify")?,
            "actual signature"
        );
        assert!(
            !public
                .verify(b"different public message", &signature)
                .map_err(|_| "tampered verify")?,
            "tampered TBS rejection"
        );
        let mut wrong = signature.clone();
        wrong[0] ^= 1;
        assert!(
            !public.verify(message, &wrong).unwrap_or(false),
            "tampered signature rejection"
        );
        let private = material.private_der().map_err(|_| "private encoding")?;
        let pem =
            LocalPrivateMaterial::private_pem(kind, &private).map_err(|_| "private export")?;
        assert!(
            pem.starts_with("-----BEGIN PRIVATE KEY-----\n"),
            "standard PKCS8 label"
        );
        let encoded = Zeroizing::new(
            pem.lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        );
        let encoded = Zeroizing::new(
            BASE64
                .decode(encoded.as_bytes())
                .map_err(|_| "private PEM decode")?,
        );
        if kind.is_mldsa() {
            let imported = mldsa_dispatch!(kind, mldsa_import_pkcs8, encoded.as_slice())
                .map_err(|_| "maintained MLDSA PKCS8 decode")?;
            assert!(
                imported.public().map_err(|_| "imported public")? == public,
                "standard PKCS8 public binding"
            );
            let signature = imported.sign(message).map_err(|_| "imported sign")?;
            assert!(
                public
                    .verify(message, &signature)
                    .map_err(|_| "imported verify")?,
                "imported key actual signing"
            );
        } else {
            let imported = PKey::private_key_from_der(&encoded)
                .map_err(|_| "maintained classic PKCS8 decode")?;
            assert!(
                imported.public_key_to_der().map_err(|_| "imported SPKI")?
                    == public.spki().map_err(|_| "original SPKI")?,
                "standard PKCS8 public binding"
            );
        }
    }
    Ok(())
}

#[test]
fn root_internal_twelve_requests_have_actual_self_signatures_and_no_private_export() -> TestResult {
    let mut requests = vec![json!({"common_name":"local-root.example.test","ttl":"1h"})];
    requests.extend(kinds().map(|kind| json!({"common_name":"local-root.example.test","ttl":"1h","key_type":kind.key_type(),"key_bits":kind.bits()})));
    assert!(requests.len() == 12, "fixed root request count");
    for (ordinal, request) in requests.iter().enumerate() {
        let mut pki = Pki::default();
        let response = pki
            .handle_admin("POST", "root/generate/internal", request, 100)
            .map_err(|_| "internal root generation")?;
        assert!(
            response.status == 200 && response.body["data"].get("private_key").is_none(),
            "internal root has no private export"
        );
        let root = pki.root.as_ref().ok_or("stored root")?;
        let key = root.local_key().map_err(|_| "stored key")?;
        if ordinal == 0 {
            assert!(
                key.kind() == LocalKeyKind::Rsa2048,
                "omitted root selects RSA2048"
            );
        }
        key.public()
            .map_err(|_| "stored public")?
            .validate_certificate(&root.certificate_der)
            .map_err(|_| "actual root certificate signature")?;
        pki.validate("", "pki/", 100)
            .map_err(|_| "persistent root validation")?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(&pki).map_err(|_| "encrypted-boundary serialization")?,
        );
        let reopened: Pki = serde_json::from_slice(&bytes).map_err(|_| "persistent root decode")?;
        reopened
            .validate("", "pki/", 100)
            .map_err(|_| "reopened root validation")?;
        let reopened_key = reopened
            .root
            .as_ref()
            .ok_or("reopened root")?
            .local_key()
            .map_err(|_| "reopened key")?;
        let signature = reopened_key
            .sign(b"public restart signing fixture")
            .map_err(|_| "reopened signing")?;
        assert!(
            key.public()
                .map_err(|_| "original public")?
                .verify(b"public restart signing fixture", &signature)
                .map_err(|_| "reopened verification")?,
            "reopened private key actual signature"
        );
        if key.kind() == LocalKeyKind::Ed25519 {
            assert!(
                !pki.has_local_typed_key_state(),
                "legacy Ed root needs no new state field"
            );
            assert!(
                !String::from_utf8_lossy(&bytes).contains("local_material"),
                "legacy Ed field absence"
            );
        }
    }
    Ok(())
}

#[test]
fn typed_key_markers_and_material_bindings_fail_closed() -> TestResult {
    for value in [
        json!({"encoding":"unknown","kind":"mldsa44","seed":vec![0;32]}),
        json!({"encoding":"mldsa_seed32","kind":"mldsa44","seed":vec![0;32],"extra":true}),
        json!({"encoding":"pkcs8","kind":"unknown","der":[]}),
    ] {
        assert!(
            serde_json::from_value::<LocalPrivateMaterial>(value).is_err(),
            "closed material marker and fields"
        );
    }
    let malformed = LocalPrivateMaterial::MldsaSeed32 {
        kind: LocalKeyKind::Rsa2048,
        seed: [0; 32],
    };
    assert!(
        malformed.public().is_err(),
        "seed never falls back to classic DER"
    );
    let malformed = LocalPrivateMaterial::Pkcs8 {
        kind: LocalKeyKind::Mldsa44,
        der: vec![0; 32],
    };
    assert!(malformed.public().is_err(), "seed is not silently PKCS8");
    let key = LocalPrivateMaterial::generate(LocalKeyKind::Ec224).map_err(|_| "binding fixture")?;
    let malformed = LocalPrivateMaterial::Pkcs8 {
        kind: LocalKeyKind::Ec256,
        der: key.private_der().map_err(|_| "binding encoding")?.to_vec(),
    };
    assert!(malformed.public().is_err(), "wrong named curve refusal");
    let public = key.public().map_err(|_| "binding public")?;
    let unrelated =
        LocalPrivateMaterial::generate(LocalKeyKind::Ec224).map_err(|_| "wrong-key fixture")?;
    let signature = unrelated
        .sign(b"public binding fixture")
        .map_err(|_| "wrong-key signature")?;
    assert!(
        !public
            .verify(b"public binding fixture", &signature)
            .map_err(|_| "wrong-key verify")?,
        "wrong public key rejection"
    );
    // Preserve the valid public n/e while replacing the private exponent.
    // The maintained provider must reject the private/public inconsistency.
    let rsa = Rsa::generate(2048).map_err(|_| "invalid RSA fixture generation")?;
    let private = Rsa::from_private_components(
        rsa.n().to_owned().map_err(|_| "fixture n")?,
        rsa.e().to_owned().map_err(|_| "fixture e")?,
        BigNum::from_u32(1).map_err(|_| "fixture invalid exponent")?,
        rsa.p()
            .ok_or("fixture p")?
            .to_owned()
            .map_err(|_| "fixture p copy")?,
        rsa.q()
            .ok_or("fixture q")?
            .to_owned()
            .map_err(|_| "fixture q copy")?,
        rsa.dmp1()
            .ok_or("fixture dmp1")?
            .to_owned()
            .map_err(|_| "fixture dmp1 copy")?,
        rsa.dmq1()
            .ok_or("fixture dmq1")?
            .to_owned()
            .map_err(|_| "fixture dmq1 copy")?,
        rsa.iqmp()
            .ok_or("fixture iqmp")?
            .to_owned()
            .map_err(|_| "fixture iqmp copy")?,
    )
    .map_err(|_| "invalid RSA fixture construction")?;
    let encoded = Zeroizing::new(
        PKey::from_rsa(private)
            .map_err(|_| "invalid RSA fixture owner")?
            .private_key_to_pkcs8()
            .map_err(|_| "invalid RSA fixture encoding")?,
    );
    let malformed = LocalPrivateMaterial::Pkcs8 {
        kind: LocalKeyKind::Rsa2048,
        der: encoded.to_vec(),
    };
    assert!(
        malformed.public().is_err(),
        "private RSA validity check is mandatory"
    );
    // A nonempty typed local marker never selects the external empty-key lane.
    let mut pki = Pki::default();
    pki.handle_admin(
        "POST",
        "root/generate/internal",
        &json!({
            "common_name":"local-material-binding.example.test", "key_type":"ec", "key_bits":224
        }),
        100,
    )
    .map_err(|_| "root binding fixture")?;
    let root = pki.root.as_mut().ok_or("binding root")?;
    root.local_material = Some(unrelated);
    assert!(
        !root.is_external(),
        "typed material never selects external signer"
    );
    assert!(
        pki.validate("", "pki/", 100).is_err(),
        "wrong typed root certificate public binding"
    );
    let root = pki.root.as_mut().ok_or("malformed root")?;
    root.local_material = Some(malformed);
    assert!(!root.is_external(), "bad typed material remains local");
    assert!(
        pki.validate("", "pki/", 100).is_err(),
        "bad typed local material fails closed"
    );
    Ok(())
}

#[test]
fn legacy_roles_preserve_bytes_and_new_roles_default_rsa() -> TestResult {
    let bytes = br#"{"allowed_domains":["example.test"],"allow_subdomains":true,"allow_ip_sans":false,"max_ttl":3600,"generate_lease":false}"#;
    let role: Role = serde_json::from_slice(bytes).map_err(|_| "legacy role decode")?;
    role.validate().map_err(|_| "legacy role validation")?;
    assert!(
        role.local_key_kind.is_none() && role.descriptor()["key_type"] == "ed25519",
        "legacy implicit Ed role selection"
    );
    assert!(
        serde_json::to_vec(&role).map_err(|_| "legacy role encode")? == bytes,
        "exact legacy role bytes"
    );
    let role =
        Role::from_body(&json!({"allowed_domains":["example.test"]})).map_err(|_| "new role")?;
    assert!(
        role.local_key_kind == Some(LocalKeyKind::Rsa2048),
        "new role defaults RSA2048"
    );
    let role = Role::from_body(&json!({"allowed_domains":["example.test"],"key_type":"ed25519"}))
        .map_err(|_| "explicit Ed role")?;
    assert!(
        role.local_key_kind.is_none(),
        "explicit Ed preserves legacy format"
    );
    Ok(())
}
