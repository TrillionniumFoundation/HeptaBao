//! Actual local issuer/subject signatures, durable restart and reader-floor
//! gates. Assertions contain fixed messages and never format private responses.
use super::*;
use crate::service::tests::bootstrap_unmounted;
use ml_dsa::{
    MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, VerifyingKey,
    pkcs8::{
        DecodePrivateKey, DecodePublicKey, EncodePublicKey, der::AnyRef,
        spki::AssociatedAlgorithmIdentifier,
    },
};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey},
    rsa::Padding,
    sign::Verifier,
};

fn key_choices() -> [(&'static str, u32); 11] {
    [
        ("rsa", 2048),
        ("rsa", 3072),
        ("rsa", 4096),
        ("ec", 224),
        ("ec", 256),
        ("ec", 384),
        ("ec", 521),
        ("ed25519", 0),
        ("mldsa", 44),
        ("mldsa", 65),
        ("mldsa", 87),
    ]
}

fn ml_verify<P>(spki: &[u8], tbs: &[u8], signature: &[u8]) -> TestResult
where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    let public = VerifyingKey::<P>::from_public_key_der(spki).map_err(|_| "MLDSA public decode")?;
    let signature = Signature::<P>::try_from(signature).map_err(|_| "MLDSA signature decode")?;
    assert!(
        public.verify_with_context(tbs, b"", &signature),
        "actual maintained MLDSA issuer signature"
    );
    Ok(())
}

fn verify_signature(spki: &[u8], tbs: &[u8], signature: &[u8]) -> TestResult {
    let (rest, public) = SubjectPublicKeyInfo::from_der(spki).map_err(|_| "issuer SPKI")?;
    assert!(rest.is_empty(), "canonical issuer SPKI");
    match public.algorithm.algorithm.to_id_string().as_str() {
        "1.3.101.112" => ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            public.subject_public_key.data.as_ref(),
        )
        .verify(tbs, signature)
        .map_err(|_| "actual Ed issuer signature".into()),
        "2.16.840.1.101.3.4.3.17" => ml_verify::<MlDsa44>(spki, tbs, signature),
        "2.16.840.1.101.3.4.3.18" => ml_verify::<MlDsa65>(spki, tbs, signature),
        "2.16.840.1.101.3.4.3.19" => ml_verify::<MlDsa87>(spki, tbs, signature),
        _ => {
            let public = PKey::public_key_from_der(spki).map_err(|_| "classic issuer SPKI")?;
            let digest = if public.id() == Id::EC {
                match public
                    .ec_key()
                    .map_err(|_| "issuer curve")?
                    .group()
                    .curve_name()
                {
                    Some(Nid::SECP384R1) => MessageDigest::sha384(),
                    Some(Nid::SECP521R1) => MessageDigest::sha512(),
                    _ => MessageDigest::sha256(),
                }
            } else {
                MessageDigest::sha256()
            };
            let mut verifier = Verifier::new(digest, &public).map_err(|_| "classic verifier")?;
            if public.id() == Id::RSA {
                verifier
                    .set_rsa_padding(Padding::PKCS1)
                    .map_err(|_| "RSA padding")?;
            }
            verifier.update(tbs).map_err(|_| "classic verifier input")?;
            assert!(
                verifier
                    .verify(signature)
                    .map_err(|_| "classic verifier finish")?,
                "actual maintained classic issuer signature"
            );
            Ok(())
        }
    }
}

fn private_public<P>(private: &[u8]) -> TestResult<Vec<u8>>
where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    use ml_dsa::Keypair as _;
    let key = ml_dsa::SigningKey::<P>::from_pkcs8_der(private)
        .map_err(|_| "standard MLDSA leaf PKCS8")?;
    Ok(key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| "leaf public encode")?
        .as_bytes()
        .to_vec())
}

fn leaf_binding(response: &Response) -> TestResult<Vec<u8>> {
    assert!(response.status == 200, "leaf response success");
    let certificate = decode_pem(
        response.body["data"]["certificate"]
            .as_str()
            .ok_or("leaf certificate")?,
    )?;
    let (tail, parsed) = X509Certificate::from_der(&certificate).map_err(|_| "leaf DER")?;
    assert!(tail.is_empty(), "canonical leaf DER");
    let text = response.body["data"]["private_key"]
        .as_str()
        .ok_or("leaf private response")?;
    assert!(
        text.starts_with("-----BEGIN PRIVATE KEY-----\n"),
        "standard maintained leaf PKCS8"
    );
    let encoded = Zeroizing::new(
        text.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>(),
    );
    let private = Zeroizing::new(
        BASE64
            .decode(encoded.as_bytes())
            .map_err(|_| "leaf private decode")?,
    );
    let public = match parsed
        .public_key()
        .algorithm
        .algorithm
        .to_id_string()
        .as_str()
    {
        "2.16.840.1.101.3.4.3.17" => private_public::<MlDsa44>(&private)?,
        "2.16.840.1.101.3.4.3.18" => private_public::<MlDsa65>(&private)?,
        "2.16.840.1.101.3.4.3.19" => private_public::<MlDsa87>(&private)?,
        _ => PKey::private_key_from_der(&private)
            .map_err(|_| "standard classic leaf PKCS8")?
            .public_key_to_der()
            .map_err(|_| "classic leaf public")?,
    };
    assert!(
        parsed.public_key().raw == public,
        "actual private leaf key matches certificate SPKI"
    );
    Ok(certificate)
}

fn current_crl(service: &mut Service, token: &str) -> TestResult<Vec<u8>> {
    let response = call(service, "GET", "local-ca/cert/crl", token, json!({}));
    assert!(response.status == 200, "local CRL read");
    decode_pem(
        response.body["data"]["certificate"]
            .as_str()
            .ok_or("local CRL response")?,
    )
}

fn verify_local_crl(root_spki: &[u8], bytes: &[u8], revoked: usize) -> TestResult {
    let (tail, crl) = CertificateRevocationList::from_der(bytes).map_err(|_| "CRL parse")?;
    assert!(
        tail.is_empty() && crl.iter_revoked_certificates().count() == revoked,
        "actual revoked projection"
    );
    verify_signature(
        root_spki,
        crl.tbs_cert_list.as_ref(),
        crl.signature_value.data.as_ref(),
    )
}

#[test]
fn exported_ed_root_requires_sticky_identifier_floor_and_keeps_private_delivery_out_of_audit()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/mounts/exported-ca",
            &admin,
            json!({"type":"pki"})
        )
        .status
            == 204,
        "exported root mount"
    );
    let ordinary = service.state.clone().ok_or("ordinary state")?;
    let backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let response = call(
        &mut service,
        "POST",
        "exported-ca/root/generate/exported",
        &admin,
        json!({"common_name":"exported-ca.example.test", "key_type":"ed25519", "format":"pem_bundle", "private_key_format":"pkcs8"}),
    );
    assert!(response.status == 200, "actual exported Ed root success");
    let private = Zeroizing::new(
        response.body["data"]["private_key"]
            .as_str()
            .ok_or("exported private field")?
            .to_owned(),
    );
    let active = service
        .state
        .clone()
        .ok_or("committed exported root state")?;
    assert!(
        active.schema == LOCAL_PKI_IDENTIFIER_STATE_SCHEMA
            && active.engines.has_local_pki_identifier_state()
            && !active.engines.has_local_typed_pki_state(),
        "Ed identifiers activate independent reader floor"
    );
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    assert!(
        !audit
            .windows(private.len())
            .any(|part| part == private.as_bytes())
            && !audit
                .windows(b"PRIVATE KEY".len())
                .any(|part| part == b"PRIVATE KEY"),
        "private exported key and bundle are absent from real audit records"
    );
    let before = service
        .current_state_identity()
        .map_err(|_| "committed identity")?;
    let mut lower = active.clone();
    lower.schema = INDEXED_RECOVERY_WIRE_STATE_SCHEMA;
    assert!(
        lower.writer_schema() == LOCAL_PKI_IDENTIFIER_STATE_SCHEMA
            && lower.validate_format().is_err()
            && service.commit_state(&lower).is_err(),
        "actual older writer label cannot publish exported identifiers"
    );
    assert!(
        service.prepare_snapshot_restore(&backup).is_err(),
        "actual old snapshot cannot remove identifier reader floor"
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "identity after refused downgrade")?
            == before,
        "failed downgrade and restore leave committed state unchanged"
    );
    drop(service);
    let mut reopened = root.service()?;
    assert!(
        call(
            &mut reopened,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "actual exported key encrypted restart"
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("reopened state")?
            .engines
            .has_local_pki_identifier_state(),
        "identifiers survived encrypted reopen"
    );
    assert!(
        call(
            &mut reopened,
            "DELETE",
            "sys/mounts/exported-ca",
            &admin,
            json!({})
        )
        .status
            == 204,
        "exported root retirement"
    );
    let retired = reopened.state.as_ref().ok_or("retired state")?;
    assert!(
        !retired.engines.has_local_pki_identifier_state()
            && retired.schema == LOCAL_PKI_IDENTIFIER_STATE_SCHEMA
            && retired.writer_schema() == LOCAL_PKI_IDENTIFIER_STATE_SCHEMA,
        "identifier floor survives root retirement"
    );
    let mut retired_lower = retired.clone();
    retired_lower.schema = INDEXED_RECOVERY_WIRE_STATE_SCHEMA;
    assert!(
        retired_lower
            .validate_publication_schema(Some(retired))
            .is_err()
            && Service::validate_snapshot_protected_floor(retired, &ordinary).is_err(),
        "retired identifiers cannot authorize earlier writer or restore"
    );
    Ok(())
}

#[test]
fn local_issuers_all_algorithms_issue_revoke_sign_crl_and_encrypted_restart() -> TestResult {
    for (key_type, key_bits) in key_choices() {
        let root = Root::new();
        let mut service = root.service()?;
        let (unseal, admin) = bootstrap_unmounted(&mut service)?;
        assert!(
            call(
                &mut service,
                "POST",
                "sys/mounts/local-ca",
                &admin,
                json!({"type":"pki"})
            )
            .status
                == 204,
            "local mount"
        );
        let generated = call(
            &mut service,
            "POST",
            "local-ca/root/generate/internal",
            &admin,
            json!({"common_name":"local-ca.example.test","ttl":"1h","key_type":key_type,"key_bits":key_bits}),
        );
        assert!(
            generated.status == 200 && generated.body["data"].get("private_key").is_none(),
            "root internal does not export key"
        );
        let root_bytes = decode_pem(
            generated.body["data"]["certificate"]
                .as_str()
                .ok_or("root certificate")?,
        )?;
        let (tail, root_certificate) =
            X509Certificate::from_der(&root_bytes).map_err(|_| "root parse")?;
        assert!(tail.is_empty(), "canonical root");
        let root_spki = root_certificate.public_key().raw.to_vec();
        verify_signature(
            &root_spki,
            root_certificate.tbs_certificate.as_ref(),
            root_certificate.signature_value.data.as_ref(),
        )?;
        assert!(call(&mut service,"POST","local-ca/roles/leaf",&admin,json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"30m","generate_lease":true,"key_type":key_type,"key_bits":key_bits})).status==200,"typed leaf role");
        let issued = call(
            &mut service,
            "POST",
            "local-ca/issue/leaf",
            &admin,
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
        );
        assert!(
            issued.body["data"]["private_key_type"] == key_type,
            "private response type matches actual subject"
        );
        let leaf = leaf_binding(&issued)?;
        let (_, leaf_certificate) = X509Certificate::from_der(&leaf).map_err(|_| "leaf parse")?;
        verify_signature(
            &root_spki,
            leaf_certificate.tbs_certificate.as_ref(),
            leaf_certificate.signature_value.data.as_ref(),
        )?;
        let serial = issued.body["data"]["serial_number"]
            .as_str()
            .ok_or("leaf serial")?
            .to_owned();
        verify_local_crl(&root_spki, &current_crl(&mut service, &admin)?, 0)?;
        assert!(
            call(
                &mut service,
                "POST",
                "local-ca/revoke",
                &admin,
                json!({"serial_number":serial})
            )
            .status
                == 200,
            "durable certificate revoke"
        );
        let crl = current_crl(&mut service, &admin)?;
        verify_local_crl(&root_spki, &crl, 1)?;
        assert!(
            service.state.as_ref().ok_or("state")?.schema == LOCAL_PKI_IDENTIFIER_STATE_SCHEMA,
            "local root identifiers require the protected reader floor for every key kind"
        );
        drop(service);
        let mut reopened = root.service()?;
        assert!(
            call(
                &mut reopened,
                "PUT",
                "sys/unseal",
                "",
                json!({"key":unseal})
            )
            .status
                == 200,
            "actual encrypted restart unseal"
        );
        assert!(
            reopened.state.as_ref().ok_or("reopened state")?.schema == expected,
            "reopened reader floor"
        );
        verify_local_crl(&root_spki, &current_crl(&mut reopened, &admin)?, 1)?;
        let next = call(
            &mut reopened,
            "POST",
            "local-ca/issue/leaf",
            &admin,
            json!({"common_name":"next.example.test","ttl":"10m"}),
        );
        let next = leaf_binding(&next)?;
        let (_, next) = X509Certificate::from_der(&next).map_err(|_| "reopened leaf parse")?;
        verify_signature(
            &root_spki,
            next.tbs_certificate.as_ref(),
            next.signature_value.data.as_ref(),
        )?;
    }
    Ok(())
}

#[test]
fn local_typed_material_has_all_namespace_sticky_floor_and_active_retired_restore_gates()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap_unmounted(&mut service)?;
    assert!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status
            == 200,
        "namespace creation"
    );
    assert!(
        service
            .handle_at(
                "POST",
                "sys/mounts/local-ca",
                "team",
                &admin,
                json!({"type":"pki"}),
                100
            )
            .status
            == 204,
        "isolated PKI mount"
    );
    let ordinary = service.state.clone().ok_or("ordinary state")?;
    assert!(
        ordinary.schema == CURRENT_STATE_SCHEMA,
        "ordinary writer remains65"
    );
    let backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut prepared = service
        .prepare_snapshot_restore(&backup)
        .map_err(|_| "ordinary prepared restore")?;
    assert!(service.handle_at("POST","local-ca/root/generate/internal","team",&admin,json!({"common_name":"local-ca.example.test","ttl":"1h","key_type":"ec","key_bits":224}),100).status==200,"typed root in nonroot namespace");
    let active = service.state.clone().ok_or("active state")?;
    assert!(
        active.schema == LOCAL_PKI_IDENTIFIER_STATE_SCHEMA
            && active.engines.has_local_typed_pki_state()
            && active.engines.has_local_pki_identifier_state(),
        "all-namespace typed material and identifier floor"
    );
    let before = service
        .current_state_identity()
        .map_err(|_| "current identity")?;
    let mut downgraded = active.clone();
    downgraded.schema = 71;
    assert!(
        downgraded.validate_format().is_err(),
        "active typed material admission under71 denied"
    );
    assert!(
        service.commit_state(&downgraded).is_err(),
        "active publication downgrade denied"
    );
    assert!(
        service.prepare_snapshot_restore(&backup).is_err(),
        "actual prepared restore75-to65 denied"
    );
    prepared.fixture_rebind_base_for_protected_floor(
        service
            .current_state_identity()
            .map_err(|_| "final test base")?,
    );
    let principal = service
        .state
        .as_mut()
        .ok_or("actor state")?
        .auth
        .authenticate_from(&admin, 100, None)
        .map_err(|_| "root actor")?;
    let body = json!({});
    let request = RequestView {
        method: "POST",
        path: "sys/storage/raft/snapshot-force",
        namespace: "",
        token: &admin,
        body: &body,
        now: 100,
        admission_started: std::time::Instant::now(),
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    assert!(
        service
            .commit_snapshot_restore(prepared, &principal, &request)
            .status
            == 400,
        "independent final restore floor denies prior snapshot"
    );
    assert!(
        service
            .current_state_identity()
            .map_err(|_| "after rejection identity")?
            == before,
        "rejected floor operations do not publish"
    );
    assert!(
        service
            .handle_at(
                "DELETE",
                "sys/mounts/local-ca",
                "team",
                &admin,
                json!({}),
                100
            )
            .status
            == 204,
        "typed mount retirement"
    );
    let retired = service.state.clone().ok_or("retired state")?;
    assert!(
        !retired.engines.has_local_typed_pki_state()
            && retired.schema == LOCAL_PKI_IDENTIFIER_STATE_SCHEMA
            && retired.writer_schema() == LOCAL_PKI_IDENTIFIER_STATE_SCHEMA,
        "retired identifier floor remains75"
    );
    let mut lower = retired.clone();
    lower.schema = 71;
    assert!(
        lower.validate_publication_schema(Some(&retired)).is_err(),
        "retired publication downgrade denied"
    );
    assert!(
        Service::validate_snapshot_protected_floor(&retired, &ordinary).is_err(),
        "retired restore downgrade denied"
    );
    let mut future = retired.clone();
    future.schema = MAX_SUPPORTED_STATE_SCHEMA + 1;
    assert!(
        future.writer_schema() == MAX_SUPPORTED_STATE_SCHEMA + 1
            && future.validate_format().is_err(),
        "unknown future schema is not normalized"
    );
    drop(service);
    let mut reopened = root.service()?;
    assert!(
        call(
            &mut reopened,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "retired encrypted restart"
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("retired reopened state")?
            .schema
            == LOCAL_PKI_IDENTIFIER_STATE_SCHEMA,
        "sticky identifier floor survives restart"
    );
    Ok(())
}

#[test]
fn external_issuer_default_rsa_and_mldsa_subjects_are_real_and_bound() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            body()
        )
        .status
            == 200,
        "remote issuer"
    );
    let descriptor = call(
        &mut *remote.service.lock().map_err(|_| "remote lock")?,
        "GET",
        "transit/keys/remote",
        &remote.admin,
        json!({}),
    );
    let issuer = BASE64.decode(
        descriptor.body["data"]["keys"]["2"]["public_key"]
            .as_str()
            .ok_or("remote public key")?,
    )?;
    for (ordinal, kind, bits) in [
        (0, "rsa", 2048),
        (1, "ec", 224),
        (2, "mldsa", 44),
        (3, "mldsa", 65),
        (4, "mldsa", 87),
    ] {
        let mut request = json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"30m","generate_lease":true});
        if ordinal != 0 {
            request["key_type"] = json!(kind);
            request["key_bits"] = json!(bits);
        }
        assert!(
            call(
                &mut service,
                "POST",
                "external-ca/roles/leaf",
                &admin,
                request
            )
            .status
                == 200,
            "external typed subject role"
        );
        let response = call(
            &mut service,
            "POST",
            "external-ca/issue/leaf",
            &admin,
            json!({"common_name":"subject.example.test","ttl":"10m"}),
        );
        assert!(
            response.body["data"]["private_key_type"] == kind,
            "external leaf has selected subject type"
        );
        let bytes = leaf_binding(&response)?;
        let (_, leaf) = X509Certificate::from_der(&bytes).map_err(|_| "external leaf DER")?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &issuer)
            .verify(
                leaf.tbs_certificate.as_ref(),
                leaf.signature_value.data.as_ref(),
            )
            .map_err(|_| "real remote signature over independently selected subject")?;
    }
    assert!(
        service.state.as_ref().ok_or("external typed state")?.schema
            == LOCAL_TYPED_PKI_STATE_SCHEMA,
        "external typed subject requires72"
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        call(
            &mut reopened,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "typed external subjects encrypted restart"
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("external reopened state")?
            .schema
            == LOCAL_TYPED_PKI_STATE_SCHEMA,
        "external typed subjects retain floor"
    );
    Ok(())
}
