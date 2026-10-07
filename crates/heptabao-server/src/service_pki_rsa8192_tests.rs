//! Actual RSA8192 public CSR and private-key import with a distinct reader108.
use super::*;

#[test]
fn pki_rsa8192_108_role_actual_predecessor_retirement_and_snapshot_floor() -> TestResult {
    let (root, mut service, unseal, admin, _issuer) = local_fixture()?;
    named_role(
        &mut service,
        &admin,
        json!({"key_type":"ec","key_bits":256}),
    )?;
    let predecessor = service.state.as_ref().ok_or("actual earlier role")?.clone();
    assert_eq!(predecessor.schema, PKI_ROLE_NAMES_STATE_SCHEMA);
    assert!(!predecessor.engines.has_pki_rsa8192_state());
    let backup = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("durable predecessor")?
            .export_backup()?,
    );
    named_role(
        &mut service,
        &admin,
        json!({"key_type":"rsa","key_bits":8192}),
    )?;
    let current = service.state.as_ref().ok_or("actual RSA8192 role")?.clone();
    assert!(current.engines.has_pki_rsa8192_state());
    assert_eq!(current.schema, PKI_RSA8192_STATE_SCHEMA);
    current
        .validate_format()
        .map_err(|_| "actual RSA8192 graph rejected")?;
    let descriptor = call(&mut service, "GET", "ca/roles/time", &admin, json!({}));
    assert_eq!(descriptor.body["data"]["key_type"], "rsa");
    assert_eq!(descriptor.body["data"]["key_bits"], 8192);
    for schema in [
        PKI_ROLE_NAMES_STATE_SCHEMA,
        PKI_KEY_POLICY_STATE_SCHEMA,
        PKI_ORDINARY_REVOCATION_STATE_SCHEMA,
    ] {
        let mut lower = current.clone();
        lower.schema = schema;
        assert!(lower.validate_format().is_err());
        assert_eq!(lower.writer_schema(), PKI_RSA8192_STATE_SCHEMA);
        assert!(
            lower
                .validate_publication_schema(Some(&predecessor))
                .is_err()
        );
        assert!(service.prepare_record_plan(&mut lower).is_err());
    }
    assert!(supported_reader_schema(NAMESPACE_DELETION_STATE_SCHEMA));
    for schema in [107, MAX_SUPPORTED_STATE_SCHEMA + 1] {
        assert!(
            !supported_reader_schema(schema),
            "absent models are not numerically admitted"
        );
    }
    assert!(service.prepare_snapshot_restore(&backup).is_err());
    assert_eq!(
        call(&mut service, "DELETE", "ca/roles/time", &admin, json!({})).status,
        204
    );
    let retired = service.state.as_ref().ok_or("retired RSA8192 role")?;
    assert!(!retired.engines.has_pki_rsa8192_state());
    assert_eq!(retired.schema, PKI_RSA8192_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), PKI_RSA8192_STATE_SCHEMA);
    assert!(Service::validate_snapshot_protected_floor(retired, &predecessor).is_err());
    assert!(service.prepare_snapshot_restore(&backup).is_err());
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
    assert_eq!(
        reopened
            .state
            .as_ref()
            .ok_or("reopened RSA8192 floor")?
            .schema,
        PKI_RSA8192_STATE_SCHEMA
    );
    assert!(
        !reopened
            .state
            .as_ref()
            .ok_or("reopened RSA8192 floor")?
            .engines
            .has_pki_rsa8192_state()
    );
    predecessor
        .validate_format()
        .map_err(|_| "original predecessor changed")?;
    Ok(())
}

#[test]
fn pki_rsa8192_108_actual_native_csr_any_subject_der_reopen_and_retained_floor() -> TestResult {
    let (root, mut service, unseal, admin, issuer) = local_fixture()?;
    named_role(
        &mut service,
        &admin,
        json!({"key_type":"any","key_bits":8192,"allow_any_name":true}),
    )?;
    let predecessor = service
        .state
        .as_ref()
        .ok_or("actual any-role predecessor")?
        .clone();
    assert_eq!(predecessor.schema, PKI_KEY_POLICY_STATE_SCHEMA);
    assert!(
        !predecessor.engines.has_pki_rsa8192_state(),
        "an any-role scalar is not a durable RSA key"
    );
    let backup = Zeroizing::new(
        service
            .durable
            .as_ref()
            .ok_or("actual104 backup")?
            .export_backup()?,
    );
    let csr = include_str!("testdata/pki108-rsa8192-native.csr.pem");
    let request = openssl::x509::X509Req::from_pem(csr.as_bytes())?;
    let public = request.public_key()?;
    assert_eq!(public.id(), openssl::pkey::Id::RSA);
    assert_eq!(public.bits(), 8192);
    assert!(
        request.verify(&public)?,
        "actual maintained CSR self signature"
    );
    let response = call(
        &mut service,
        "POST",
        "ca/sign/time",
        &admin,
        json!({"csr":csr}),
    );
    let certificate = signed_leaf(&response, &issuer)?;
    assert_eq!(
        certificate.public_key()?.public_key_to_der()?,
        public.public_key_to_der()?
    );
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let wrong = PKey::from_ec_key(openssl::ec::EcKey::generate(&group)?)?;
    assert!(
        !certificate.verify(&wrong)?,
        "fresh wrong issuer is rejected"
    );
    assert!(response.body["data"].get("private_key").is_none());
    let serial = response.body["data"]["serial_number"]
        .as_str()
        .ok_or("actual signed serial")?
        .to_owned();
    let current = service
        .state
        .as_ref()
        .ok_or("actual signed8192 subject")?
        .clone();
    assert!(
        current.engines.has_pki_rsa8192_state(),
        "signed DER alone raises actual108 without a specific-key role"
    );
    assert_eq!(current.schema, PKI_RSA8192_STATE_SCHEMA);
    let mut lower = current.clone();
    lower.schema = PKI_ORDINARY_REVOCATION_STATE_SCHEMA;
    assert!(lower.validate_format().is_err());
    assert_eq!(lower.writer_schema(), PKI_RSA8192_STATE_SCHEMA);
    assert!(service.prepare_snapshot_restore(&backup).is_err());
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
    let read = call(
        &mut reopened,
        "GET",
        &format!("ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(
        read.body["data"]["certificate"],
        response.body["data"]["certificate"]
    );
    assert_eq!(
        call(&mut reopened, "DELETE", "ca/roles/time", &admin, json!({})).status,
        204
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("retained8192 DER")?
            .engines
            .has_pki_rsa8192_state()
    );
    assert_eq!(
        call(&mut reopened, "DELETE", "sys/mounts/ca", &admin, json!({})).status,
        204
    );
    let retired = reopened.state.as_ref().ok_or("last8192 owner retired")?;
    assert!(!retired.engines.has_pki_rsa8192_state());
    assert_eq!(retired.schema, PKI_RSA8192_STATE_SCHEMA);
    assert!(Service::validate_snapshot_protected_floor(retired, &predecessor).is_err());
    assert!(reopened.prepare_snapshot_restore(&backup).is_err());
    Ok(())
}

#[test]
fn pki_rsa8192_108_actual_private_import_pending_csr_and_encrypted_reopen() -> TestResult {
    let (root, mut service, unseal, admin, _issuer) = local_fixture()?;
    let key = PKey::from_rsa(openssl::rsa::Rsa::generate(8192)?)?;
    let private = Zeroizing::new(key.private_key_to_pkcs8()?);
    assert!(
        private.len() > 4096 && private.len() <= 8192,
        "actual8192 private DER requires its distinct bounded owner"
    );
    let pem = Zeroizing::new(String::from_utf8(key.private_key_to_pem_pkcs8()?)?);
    let public = key.public_key_to_der()?;
    let imported = call(
        &mut service,
        "POST",
        "ca/keys/import",
        &admin,
        json!({"pem_bundle":pem.as_str(),"key_name":"large"}),
    );
    assert_eq!(imported.status, 200, "actual8192 private-key import");
    let id = imported.body["data"]["key_id"]
        .as_str()
        .ok_or("actual imported key ID")?
        .to_owned();
    assert!(
        service
            .state
            .as_ref()
            .ok_or("actual imported8192")?
            .engines
            .has_pki_rsa8192_state()
    );
    assert_eq!(
        service.state.as_ref().ok_or("actual imported8192")?.schema,
        PKI_RSA8192_STATE_SCHEMA
    );
    let generated = call(
        &mut service,
        "POST",
        "ca/intermediate/generate/existing",
        &admin,
        json!({"key_ref":id,"common_name":"large.example"}),
    );
    assert_eq!(
        generated.status, 200,
        "original imported key signs its bounded CSR"
    );
    let csr = generated.body["data"]["csr"]
        .as_str()
        .ok_or("actual imported8192 CSR")?;
    let request = openssl::x509::X509Req::from_pem(csr.as_bytes())?;
    assert_eq!(request.public_key()?.public_key_to_der()?, public);
    assert!(request.verify(&key)?);
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
    let descriptor = call(
        &mut reopened,
        "GET",
        &format!("ca/key/{id}"),
        &admin,
        json!({}),
    );
    assert_eq!(descriptor.status, 200);
    assert_eq!(descriptor.body["data"]["key_type"], "rsa");
    assert!(descriptor.body["data"].get("key_bits").is_none());
    let retained = call(
        &mut reopened,
        "POST",
        "ca/intermediate/generate/existing",
        &admin,
        json!({"key_ref":id,"common_name":"retained-large.example"}),
    );
    assert_eq!(
        retained.status, 200,
        "actual retained private key signs again"
    );
    let retained_csr = retained.body["data"]["csr"]
        .as_str()
        .ok_or("actual retained8192 CSR")?;
    let retained_request = openssl::x509::X509Req::from_pem(retained_csr.as_bytes())?;
    let retained_public = retained_request.public_key()?;
    assert_eq!(retained_public.bits(), 8192);
    assert_eq!(retained_public.public_key_to_der()?, public);
    assert!(retained_request.verify(&retained_public)?);
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("actual retained8192 key")?
            .engines
            .has_pki_rsa8192_state()
    );
    assert_eq!(
        reopened
            .state
            .as_ref()
            .ok_or("actual retained8192 key")?
            .schema,
        PKI_RSA8192_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn pki_serial_api_actual_local_root_signed_integer_canonical_public_and_reopen() -> TestResult {
    let (root, mut service, unseal, admin, _) = local_fixture()?;
    let generated = call(
        &mut service,
        "POST",
        "ca/root/generate/internal",
        &admin,
        json!({"common_name":"serial.example.test","key_type":"ec","key_bits":256,"ttl":"4h"}),
    );
    assert_eq!(generated.status, 200);
    let pem = generated.body["data"]["certificate"]
        .as_str()
        .ok_or("actual root public certificate")?
        .to_owned();
    let certificate = X509::from_pem(pem.as_bytes())?;
    let issuer_public = certificate.public_key()?;
    assert!(certificate.verify(&issuer_public)?);
    let integer = certificate.serial_number().to_bn()?;
    assert!(integer.num_bits() <= 159);
    let octets = integer.to_vec();
    assert!(!octets.is_empty() && octets.len() <= 20);
    let canonical = octets
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    assert_eq!(generated.body["data"]["serial_number"], canonical);
    let read = call(
        &mut service,
        "GET",
        &format!("ca/cert/{canonical}"),
        "",
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["certificate"], pem);
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
    let read = call(
        &mut reopened,
        "GET",
        &format!("ca/cert/{canonical}"),
        "",
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["certificate"], pem);
    Ok(())
}
