//! Genuine any-role subject keys, cryptographic ownership, and protected reader104.
use super::*;

fn csr_for_key(key: &PKey<openssl::pkey::Private>) -> TestResult<(String, Vec<u8>)> {
    let mut name = openssl::x509::X509Name::builder()?;
    name.append_entry_by_text("CN", "any.example.test")?;
    let mut request = openssl::x509::X509Req::builder()?;
    request.set_subject_name(&name.build())?;
    request.set_pubkey(key)?;
    let digest = if key.id() == openssl::pkey::Id::ED25519 {
        openssl::hash::MessageDigest::null()
    } else {
        openssl::hash::MessageDigest::sha256()
    };
    request.sign(key, digest)?;
    let request = request.build();
    assert!(request.verify(key)?, "real CSR self signature");
    Ok((
        String::from_utf8(request.to_pem()?)?,
        key.public_key_to_der()?,
    ))
}

// The linked AWS-LC X509Req signing API does not support Ed25519. Construct
// this fresh standard CSR with the maintained Ed25519 signer and independently
// verify its self signature before handing the public request to the service.
fn ed25519_csr() -> TestResult<(String, Vec<u8>)> {
    use ring::signature::KeyPair as _;
    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        if value.len() < 128 {
            result.push(value.len() as u8);
        } else if value.len() < 256 {
            result.extend([0x81, value.len() as u8]);
        } else {
            result.extend([0x82, (value.len() >> 8) as u8, value.len() as u8]);
        }
        result.extend(value);
        result
    }
    let material =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| "fresh Ed25519 fixture")?;
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(material.as_ref())
        .map_err(|_| "Ed25519 fixture key")?;
    let algorithm = der(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x70]);
    let mut public_bits = vec![0];
    public_bits.extend(key.public_key().as_ref());
    let public = der(
        0x30,
        &[algorithm.as_slice(), &der(0x03, &public_bits)].concat(),
    );
    let cn = der(
        0x30,
        &[
            &[0x06, 0x03, 0x55, 0x04, 0x03][..],
            der(0x0c, b"any.example.test").as_slice(),
        ]
        .concat(),
    );
    let subject = der(0x30, &der(0x31, &cn));
    let info = der(
        0x30,
        &[
            &[0x02, 0x01, 0x00][..],
            subject.as_slice(),
            public.as_slice(),
            &[0xa0, 0x00],
        ]
        .concat(),
    );
    let signature = key.sign(&info);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key.public_key().as_ref())
        .verify(&info, signature.as_ref())
        .map_err(|_| "CSR fixture self signature")?;
    let mut signature_bits = vec![0];
    signature_bits.extend(signature.as_ref());
    let request = der(
        0x30,
        &[
            info.as_slice(),
            algorithm.as_slice(),
            &der(0x03, &signature_bits),
        ]
        .concat(),
    );
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &request);
    let mut pem = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line)?);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE REQUEST-----\n");
    Ok((pem, public))
}

fn any_role(service: &mut Service, admin: &str, bits: i64) -> TestResult {
    named_role(service, admin, json!({"key_type":"any", "key_bits":bits}))?;
    let read = call(service, "GET", "ca/roles/time", admin, json!({}));
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["key_type"], "any");
    assert_eq!(read.body["data"]["key_bits"], bits);
    Ok(())
}

#[test]
fn pki_key_policy104_any_csr_actual_signature_spki_and_safe_minimum() -> TestResult {
    let (_root, mut service, _unseal, admin, issuer) = local_fixture()?;
    let mut keys = Vec::new();
    for curve in [
        openssl::nid::Nid::SECP224R1,
        openssl::nid::Nid::X9_62_PRIME256V1,
        openssl::nid::Nid::SECP384R1,
        openssl::nid::Nid::SECP521R1,
    ] {
        let group = openssl::ec::EcGroup::from_curve_name(curve)?;
        keys.push(PKey::from_ec_key(openssl::ec::EcKey::generate(&group)?)?);
    }
    keys.push(PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?);
    keys.push(PKey::from_rsa(openssl::rsa::Rsa::generate(3072)?)?);
    let ed_request = ed25519_csr()?;
    for bits in [4096, -1] {
        any_role(&mut service, &admin, bits)?;
        for key in &keys {
            let (csr, public) = csr_for_key(key)?;
            let signed = call(
                &mut service,
                "POST",
                "ca/sign/time",
                &admin,
                json!({"csr":csr}),
            );
            let certificate = signed_leaf(&signed, &issuer)?;
            assert_eq!(
                certificate.public_key()?.public_key_to_der()?,
                public,
                "role bits do not replace the actual signed CSR key"
            );
            assert!(signed.body["data"].get("private_key").is_none());
        }
        let signed = call(
            &mut service,
            "POST",
            "ca/sign/time",
            &admin,
            json!({"csr":ed_request.0}),
        );
        assert_eq!(
            signed_leaf(&signed, &issuer)?
                .public_key()?
                .public_key_to_der()?,
            ed_request.1,
            "fresh Ed25519 CSR retains its actual subject key"
        );
    }
    let weak = PKey::from_rsa(openssl::rsa::Rsa::generate(1024)?)?;
    let (csr, _) = csr_for_key(&weak)?;
    let rejected = call(
        &mut service,
        "POST",
        "ca/sign/time",
        &admin,
        json!({"csr":csr}),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["errors"],
        json!(["RSA keys < 2048 bits are unsafe and not supported"])
    );
    let (csr, _) = csr_for_key(&keys[0])?;
    let mut damaged = openssl::x509::X509Req::from_pem(csr.as_bytes())?.to_der()?;
    *damaged.last_mut().ok_or("CSR signature")? ^= 1;
    let damaged = String::from_utf8(openssl::x509::X509Req::from_der(&damaged)?.to_pem()?)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ca/sign/time",
            &admin,
            json!({"csr":damaged})
        )
        .status,
        400,
        "any policy never admits an invalid CSR proof"
    );
    Ok(())
}

#[test]
fn pki_key_policy104_issue_explicit_kind_override_and_pinned_warning() -> TestResult {
    let (_root, mut service, _unseal, admin, issuer) = local_fixture()?;
    any_role(&mut service, &admin, 4096)?;
    for body in [
        json!({"common_name":"any.example.test"}),
        json!({"common_name":"any.example.test","key_bits":256}),
    ] {
        let response = call(&mut service, "POST", "ca/issue/time", &admin, body);
        assert_eq!(response.status, 400);
        assert_eq!(
            response.body["errors"],
            json!([
                r#"role key type "any" not allowed for issuing certificates without providing key_type and/or key_bits request parameters"#
            ])
        );
    }
    let invalid = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"any.example.test","key_type":"ec"}),
    );
    assert_eq!(invalid.status, 500);
    assert_eq!(
        invalid.body["errors"],
        json!([
            "1 error occurred:\n\t* failed to validate role: unsupported bit length for EC key: 4096\n\n"
        ])
    );
    for bits in [json!(0), Value::Null, json!("256"), json!("")] {
        let response = call(
            &mut service,
            "POST",
            "ca/issue/time",
            &admin,
            json!({"common_name":"any.example.test","key_type":"ec","key_bits":bits}),
        );
        let key = signed_leaf(&response, &issuer)?.public_key()?;
        assert_eq!(
            key.ec_key()?.group().curve_name(),
            Some(openssl::nid::Nid::X9_62_PRIME256V1),
            "explicit zero/null/weak string is present and overrides stored4096"
        );
    }
    for (bits, status, message) in [
        (
            json!(true),
            500,
            "1 error occurred:\n\t* failed to validate role: unsupported bit length for EC key: 1\n\n",
        ),
        (
            json!(256.75),
            400,
            "Field validation failed: error converting input for field \"key_bits\": '' cannot parse value as 'int': strconv.ParseInt: invalid syntax",
        ),
    ] {
        let response = call(
            &mut service,
            "POST",
            "ca/issue/time",
            &admin,
            json!({"common_name":"any.example.test","key_type":"ec","key_bits":bits}),
        );
        assert_eq!(response.status, status);
        assert_eq!(response.body["errors"], json!([message]));
    }
    for (kind, message) in [
        (Value::Null, ""),
        (json!(""), ""),
        (json!(true), "1"),
        (json!(256), "256"),
    ] {
        let response = call(
            &mut service,
            "POST",
            "ca/issue/time",
            &admin,
            json!({"common_name":"any.example.test","key_type":kind,"key_bits":256}),
        );
        assert_eq!(response.status, 500);
        assert_eq!(
            response.body["errors"],
            json!([format!(
                "1 error occurred:\n\t* failed to validate role: unknown key type {message}\n\n"
            )])
        );
    }
    for (kind, bits) in [
        ("rsa", 3072),
        ("ec", 224),
        ("ec", 256),
        ("ec", 384),
        ("ec", 521),
        ("ed25519", 0),
    ] {
        let response = call(
            &mut service,
            "POST",
            "ca/issue/time",
            &admin,
            json!({"common_name":"any.example.test","key_type":kind,"key_bits":bits}),
        );
        let certificate = signed_leaf(&response, &issuer)?;
        let private = PKey::private_key_from_pem(
            response.body["data"]["private_key"]
                .as_str()
                .ok_or("private key")?
                .as_bytes(),
        )?;
        assert_eq!(
            private.public_key_to_der()?,
            certificate.public_key()?.public_key_to_der()?,
            "actual delivered private key owns the leaf SPKI"
        );
        assert_eq!(response.body["data"]["private_key_type"], kind);
    }
    let role = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
    assert_eq!(role.body["data"]["key_type"], "any");
    assert_eq!(role.body["data"]["key_bits"], 4096);
    named_role(
        &mut service,
        &admin,
        json!({"key_type":"ec","key_bits":256}),
    )?;
    let response = call(
        &mut service,
        "POST",
        "ca/issue/time",
        &admin,
        json!({"common_name":"any.example.test","key_type":"rsa","key_bits":2048}),
    );
    assert_eq!(
        signed_leaf(&response, &issuer)?.public_key()?.id(),
        openssl::pkey::Id::EC
    );
    assert_eq!(
        response.body["warnings"],
        json!(["parameters key_type and key_bits ignored as role had specific values"])
    );
    assert_eq!(
        call(&mut service, "GET", "ca/roles/time", &admin, json!({})).body["data"]["key_type"],
        "ec"
    );
    Ok(())
}

#[test]
fn pki_key_policy104_actual_predecessor_encrypted_reopen_and_retirement_floor() -> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    named_role(
        &mut service,
        &admin,
        json!({"key_type":"ec","key_bits":256}),
    )?;
    let predecessor = service.state.as_ref().ok_or("actual predecessor")?.clone();
    assert_eq!(predecessor.schema, 93);
    assert!(!predecessor.engines.has_pki_key_policy_state());
    let role_before = pki_value(&service, "", "ca/")?.0["roles"]["time"].clone();
    assert!(
        role_before.get("role_key_policy").is_none(),
        "real historical role has no new field"
    );
    let backup = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("durable predecessor")?
            .export_backup()?,
    );
    any_role(&mut service, &admin, -1)?;
    let current = service.state.as_ref().ok_or("actual any role")?;
    assert!(
        current.schema == 104
            && current.writer_schema() == 104
            && current.engines.has_pki_key_policy_state()
    );
    current
        .validate_format()
        .map_err(|_| "actual104 graph rejected")?;
    for schema in [93, 99, 101, 103] {
        let mut lower = current.clone();
        lower.schema = schema;
        assert!(
            lower.validate_format().is_err()
                && lower
                    .validate_publication_schema(Some(&predecessor))
                    .is_err()
        );
        assert_eq!(lower.writer_schema(), 104);
        assert!(
            service.prepare_record_plan(&mut lower).is_err(),
            "new owner rejects predecode downgrade"
        );
    }
    assert!(
        supported_reader_schema(SDK_BATCH_CREDENTIAL_SECRET_STATE_SCHEMA),
        "joint SDK102 reader requires its implemented typed model"
    );
    assert!(service.prepare_snapshot_restore(&backup).is_err());
    let (csr, public) = actual_csr_fixture()?;
    let response = call(
        &mut service,
        "POST",
        "ca/sign/time",
        &admin,
        json!({"csr":csr}),
    );
    let certificate = signed_leaf(&response, &issuer)?;
    assert_eq!(certificate.public_key()?.public_key_to_der()?, public);
    let serial = response.body["data"]["serial_number"]
        .as_str()
        .ok_or("actual serial")?
        .to_owned();
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(reopened.state.as_ref().ok_or("reopened104")?.schema, 104);
    assert_eq!(
        call(&mut reopened, "GET", "ca/roles/time", &admin, json!({})).body["data"]["key_bits"],
        -1
    );
    let read = call(
        &mut reopened,
        "GET",
        &format!("ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(
        X509::from_pem(
            read.body["data"]["certificate"]
                .as_str()
                .ok_or("persisted leaf")?
                .as_bytes()
        )?
        .to_der()?,
        certificate.to_der()?
    );
    assert_eq!(
        call(&mut reopened, "DELETE", "ca/roles/time", &admin, json!({})).status,
        204
    );
    let retired = reopened.state.as_ref().ok_or("retired owner")?;
    assert!(
        retired.schema == 104
            && retired.writer_schema() == 104
            && !retired.engines.has_pki_key_policy_state()
    );
    assert!(
        reopened.prepare_snapshot_restore(&backup).is_err(),
        "last role removal never restores old capability"
    );
    predecessor
        .validate_format()
        .map_err(|_| "original predecessor changed")?;
    Ok(())
}

#[test]
fn pki_key_policy104_any_base_zero_native_scalar_bounds_and_no_failed_role_write() -> TestResult {
    let (_root, mut service, _unseal, admin, issuer) = local_fixture()?;
    // These stored values and error classes were observed on genuine 2.7.0
    // role writes and public descriptor reads, including both signed limits.
    for (raw, expected) in [
        ("0x800", 2048),
        ("04000", 2048),
        ("0o4000", 2048),
        ("0b100000000000", 2048),
        ("+0x800", 2048),
        ("-0x800", -2048),
        ("2_048", 2048),
        ("0x8_00", 2048),
        ("0x_800", 2048),
        ("0_4000", 2048),
        ("-0x8000000000000000", i64::MIN),
        ("0x7fffffffffffffff", i64::MAX),
    ] {
        named_role(
            &mut service,
            &admin,
            json!({"key_type":"any","key_bits":raw}),
        )?;
        let read = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["key_type"], "any");
        assert_eq!(read.body["data"]["key_bits"], expected);
    }
    let before = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
    assert_eq!(before.status, 200);
    for (raw, reason) in [
        (json!("08"), "invalid syntax"),
        (json!(" 2048"), "invalid syntax"),
        (json!("2048 "), "invalid syntax"),
        (json!("9223372036854775808"), "value out of range"),
        (json!("-0x8000000000000001"), "value out of range"),
        (json!(2048.0), "invalid syntax"),
        (json!(2048.5), "invalid syntax"),
    ] {
        let failed = call(
            &mut service,
            "POST",
            "ca/roles/time",
            &admin,
            json!({"allow_any_name":true,"key_type":"any","key_bits":raw}),
        );
        assert_eq!(failed.status, 400);
        assert_eq!(
            failed.body["errors"],
            json!([format!(
                "Field validation failed: error converting input for field \"key_bits\": '' cannot parse value as 'int': strconv.ParseInt: {reason}"
            )])
        );
        let retained = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
        assert_eq!(retained.status, 200);
        assert_eq!(
            retained.body["data"], before.body["data"],
            "a rejected conversion cannot alter the existing typed role"
        );
    }
    any_role(&mut service, &admin, 4096)?;
    for raw in ["0x100", "0_400", "0b100000000"] {
        let issued = call(
            &mut service,
            "POST",
            "ca/issue/time",
            &admin,
            json!({"common_name":"any.example.test","key_type":"ec","key_bits":raw}),
        );
        let certificate = signed_leaf(&issued, &issuer)?;
        let key = certificate.public_key()?;
        assert_eq!(
            key.ec_key()?.group().curve_name(),
            Some(openssl::nid::Nid::X9_62_PRIME256V1)
        );
        let private = PKey::private_key_from_pem(
            issued.body["data"]["private_key"]
                .as_str()
                .ok_or("issued private key")?
                .as_bytes(),
        )?;
        assert_eq!(
            private.public_key_to_der()?,
            key.public_key_to_der()?,
            "actual weak request override remains bound to the signed leaf key"
        );
    }
    let retained = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
    assert_eq!(retained.body["data"]["key_bits"], 4096);
    Ok(())
}

#[path = "service_pki_rsa8192_tests.rs"]
mod rsa8192;
