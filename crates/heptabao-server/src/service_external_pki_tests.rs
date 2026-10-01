//! Independent remote native Transit signs DER. Assertions never format public
//! certificates, signatures, input, credentials or serialized secret state.
use super::*;
use x509_parser::prelude::*;
#[path = "service_external_pki_asymmetric_tests.rs"]
mod asymmetric_tests;
#[path = "service_external_pki_issuer_alias_tests.rs"]
mod issuer_alias_tests;
#[path = "service_external_pki_issuer_issue_tests.rs"]
mod issuer_issue_tests;
#[path = "service_external_pki_leaf_tests.rs"]
mod leaf_tests;
#[path = "service_external_pki_public_tests.rs"]
mod public_tests;

fn pki_fixture(remote: &RemoteTransit) -> TestResult<(Root, Service, String, String)> {
    let (root, mut service, unseal, admin) = remote.fixture()?;
    for (path, body, status) in [
        ("sys/mounts/external-ca", json!({"type":"pki"}), 204),
        (
            "sys/external-keys/configs/remote/keys/v2",
            json!({"verify":false,"name":"remote","version":2}),
            204,
        ),
        (
            "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
            json!({}),
            204,
        ),
    ] {
        assert!(
            call(&mut service, "POST", path, &admin, body).status == status,
            "PKI fixture admission"
        );
    }
    Ok((root, service, unseal, admin))
}

fn body() -> Value {
    json!({"external_key_ref":"remote:v2","common_name":"external-ca.example.test","ttl":"1h"})
}

fn pki_staged(
    service: &mut Service,
    admin: &str,
    route: &str,
) -> TestResult<PendingExternalRequest> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: route,
        namespace: "",
        token: admin,
        body: body(),
        now: 100,
        allow_forward: true,
        enforce_namespace: false,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(pending) => Ok(*pending),
        RequestExecution::Complete(_) => Err("PKI effect did not stage".into()),
    }
}

fn decode_pem(text: &str) -> TestResult<Vec<u8>> {
    Ok(BASE64.decode(
        text.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>(),
    )?)
}

fn leaf_fixture(remote: &RemoteTransit) -> TestResult<(Root, Service, String, String)> {
    let (root, mut service, unseal, admin) = pki_fixture(remote)?;
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
        "external root and CRL publication"
    );
    assert!(call(&mut service,"POST","external-ca/roles/leaf",&admin,json!({
        "allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"30m","generate_lease":true,"key_type":"ed25519"
    })).status==200,"bounded Ed25519 leaf role");
    Ok((root, service, unseal, admin))
}

fn crl_bytes(service: &mut Service, admin: &str, delta: bool) -> TestResult<Vec<u8>> {
    let response = call(
        service,
        "GET",
        if delta {
            "external-ca/crl/delta"
        } else {
            "external-ca/crl"
        },
        admin,
        json!({}),
    );
    assert!(response.status == 200, "cached external CRL read");
    Ok(BASE64.decode(
        response.body["__heptabao_pki_crl"]
            .as_str()
            .ok_or("CRL transport envelope")?,
    )?)
}

fn verify_crl(public: &[u8], der: &[u8], number: u64, revoked: usize, delta: bool) -> TestResult {
    let (tail, crl) = CertificateRevocationList::from_der(der).map_err(|_| "CRL DER parse")?;
    assert!(tail.is_empty(), "canonical CRL DER");
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
        .verify(
            crl.tbs_cert_list.as_ref(),
            crl.signature_value.data.as_ref(),
        )
        .map_err(|_| "actual remote CRL signature")?;
    assert!(
        crl.crl_number()
            .is_some_and(|n| n.to_string() == number.to_string()),
        "exact monotonic CRL number"
    );
    assert!(
        crl.iter_revoked_certificates().count() == revoked,
        "exact CRL revocation projection"
    );
    assert!(
        crl.extensions().len() == if delta { 3 } else { 2 },
        "exact full and delta extensions"
    );
    assert!(
        crl.next_update().ok_or("CRL next update")?.timestamp() - crl.last_update().timestamp()
            == 72 * 3600,
        "CRL expiry 72 hours"
    );
    Ok(())
}

#[test]
fn external_pki270_actual_leaf_private_output_root_full_delta_crls_and_revoke_restart() -> TestResult
{
    exercise_external_pki270_leaf_crls_with_schema(false)
}

#[test]
fn external_pki270_aad_bound_schema_keeps_real_root_leaf_crls_private_binding_and_restart()
-> TestResult {
    exercise_external_pki270_leaf_crls_with_schema(true)
}

fn exercise_external_pki270_leaf_crls_with_schema(safe_schema: bool) -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let expected_schema = if safe_schema { 66 } else { 65 };
    let safe_ciphertext = if safe_schema {
        assert!(
            call(
                &mut service,
                "POST",
                "sys/mounts/safe",
                &admin,
                json!({"type":"transit"})
            )
            .status
                == 204,
            "mixed safe Transit mount admission"
        );
        assert!(
            call(
                &mut service,
                "POST",
                "safe/keys/key",
                &admin,
                json!({"type":"aes128-gcm96","derived":true,"convergent_encryption":true,
                       "heptabao_convergent_version":1})
            )
            .status
                == 200,
            "actual opt-in key precedes remote PKI publication"
        );
        let encrypted = call(
            &mut service,
            "POST",
            "safe/encrypt/key",
            &admin,
            json!({"plaintext":BASE64.encode(b"synthetic mixed safe PKI plaintext"),
                   "context":BASE64.encode(b"synthetic mixed safe PKI context"),
                   "associated_data":BASE64.encode(b"synthetic mixed safe PKI AAD")}),
        );
        assert!(encrypted.status == 200, "real AES128 opt-in encryption");
        Some(
            encrypted.body["data"]["ciphertext"]
                .as_str()
                .ok_or("mixed safe ciphertext")?
                .to_owned(),
        )
    } else {
        None
    };
    let before_root = remote.calls()?;
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
        "mixed schema actual external root generation"
    );
    assert!(
        remote.calls()? == before_root + 4,
        "root metadata plus certificate, full CRL and delta CRL signatures"
    );
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/roles/leaf",
            &admin,
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,
                   "max_ttl":"30m","generate_lease":true,"key_type":"ed25519"})
        )
        .status
            == 200,
        "mixed schema bounded leaf role"
    );
    assert!(
        service.state.as_ref().ok_or("mixed root state")?.schema == expected_schema,
        "ordinary PKI stays65 and mixed opt-in PKI retains66"
    );
    let descriptor = call(
        &mut *remote.service.lock().map_err(|_| "remote lock")?,
        "GET",
        "transit/keys/remote",
        &remote.admin,
        json!({}),
    );
    let public = BASE64.decode(
        descriptor.body["data"]["keys"]["2"]["public_key"]
            .as_str()
            .ok_or("remote public key")?,
    )?;
    let retained_root = call(
        &mut service,
        "GET",
        "external-ca/cert/ca",
        &admin,
        json!({}),
    );
    assert!(retained_root.status == 200, "mixed schema root readback");
    let root_der = decode_pem(
        retained_root.body["data"]["certificate"]
            .as_str()
            .ok_or("mixed root certificate")?,
    )?;
    let (tail, root_certificate) =
        parse_x509_certificate(&root_der).map_err(|_| "mixed root DER")?;
    assert!(
        tail.is_empty()
            && root_certificate.is_ca()
            && root_certificate
                .public_key()
                .subject_public_key
                .data
                .as_ref()
                == public,
        "mixed schema root DER and SPKI remain provider-bound"
    );
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
        .verify(
            root_certificate.tbs_certificate.as_ref(),
            root_certificate.signature_value.data.as_ref(),
        )
        .map_err(|_| "mixed schema actual root signature")?;
    let before = remote.calls()?;
    verify_crl(
        &public,
        &crl_bytes(&mut service, &admin, false)?,
        1,
        0,
        false,
    )?;
    verify_crl(&public, &crl_bytes(&mut service, &admin, true)?, 2, 0, true)?;
    assert!(remote.calls()? == before, "CRL read uses the signed cache");
    let issued = call(
        &mut service,
        "POST",
        "external-ca/issue/leaf",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    assert!(issued.status == 200, "genuine external leaf issue");
    assert!(
        remote.calls()? == before + 2,
        "one metadata read and one leaf sign"
    );
    let data = &issued.body["data"];
    assert!(
        data.as_object().is_some_and(|data| data.len() == 8),
        "exact official leaf fields"
    );
    assert!(
        issued.body["lease_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "original lease owner retained"
    );
    let der = decode_pem(data["certificate"].as_str().ok_or("leaf certificate")?)?;
    let (_, leaf) = parse_x509_certificate(&der).map_err(|_| "leaf DER")?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
        .verify(
            leaf.tbs_certificate.as_ref(),
            leaf.signature_value.data.as_ref(),
        )
        .map_err(|_| "actual external CA leaf signature")?;
    assert!(
        leaf.extensions().len() == 5 && !leaf.is_ca(),
        "exact default Ed leaf extensions"
    );
    let usage = leaf
        .key_usage()
        .map_err(|_| "leaf key usage")?
        .ok_or("leaf key usage")?;
    assert!(
        usage.value.digital_signature()
            && usage.value.key_encipherment()
            && usage.value.key_agreement(),
        "official default leaf usage"
    );
    let private = zeroize::Zeroizing::new(decode_pem(
        data["private_key"]
            .as_str()
            .ok_or("single leaf private output")?,
    )?);
    let pair = openssl::pkey::PKey::private_key_from_der(&private)
        .map_err(|_| "standard leaf private output")?;
    assert!(
        pair.raw_public_key()?.as_slice() == leaf.public_key().subject_public_key.data.as_ref(),
        "private output belongs to this leaf"
    );
    let message = b"synthetic issued leaf private consumer proof";
    let mut signer = openssl::sign::Signer::new_without_digest(&pair)?;
    let signature = zeroize::Zeroizing::new(signer.sign_oneshot_to_vec(message)?);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        leaf.public_key().subject_public_key.data.as_ref(),
    )
    .verify(message, &signature)
    .map_err(|_| "issued standard private key performs leaf-bound signing")?;
    let serial = data["serial_number"].as_str().ok_or("leaf serial")?;
    let read = call(
        &mut service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        &admin,
        json!({}),
    );
    assert!(
        read.status == 200
            && read.body["data"]["certificate"].as_str()
                == Some(
                    data["certificate"]
                        .as_str()
                        .ok_or("issued certificate PEM")?
                )
            && read.body["data"].get("private_key").is_none(),
        "durable certificate readback omits private material"
    );
    let before = remote.calls()?;
    let revoked = call(
        &mut service,
        "POST",
        "external-ca/revoke",
        &admin,
        json!({"serial_number":serial}),
    );
    assert!(
        revoked.status == 200 && revoked.body["data"]["state"] == "revoked",
        "external leaf revoke contract"
    );
    assert!(
        remote.calls()? == before + 3,
        "metadata plus full and delta CRL effects"
    );
    let full = crl_bytes(&mut service, &admin, false)?;
    let delta = crl_bytes(&mut service, &admin, true)?;
    verify_crl(&public, &full, 3, 1, false)?;
    verify_crl(&public, &delta, 4, 0, true)?;
    let retained_state = service.state.as_ref().ok_or("state")?;
    assert!(
        retained_state.schema == expected_schema && retained_state.validate_format().is_ok(),
        "mixed schema real leaf and CRL publication retain authenticated format"
    );
    if safe_schema {
        let mut downgraded = retained_state.clone();
        downgraded.schema = 65;
        assert!(
            downgraded.validate_format().is_err(),
            "safe material plus external PKI cannot enter legacy65 format"
        );
    }
    let state = serde_json::to_value(retained_state)?;
    let state_text = serde_json::to_string(&state)?;
    assert!(
        !state_text.contains(data["private_key"].as_str().ok_or("leaf private key")?)
            && !state_text.contains(&BASE64.encode(&*private)),
        "no durable leaf or CA private material"
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "encrypted external PKI restart"
    );
    assert!(
        crl_bytes(&mut reopened, &admin, false)? == full
            && crl_bytes(&mut reopened, &admin, true)? == delta,
        "CRL signed bytes retain exact restart identity"
    );
    assert!(
        reopened
            .state
            .as_ref()
            .ok_or("mixed reopened state")?
            .schema
            == expected_schema,
        "mixed schema encrypted restart preserves the exact writer contract"
    );
    if let Some(ciphertext) = safe_ciphertext {
        let descriptor = call(&mut reopened, "GET", "safe/keys/key", &admin, json!({}));
        assert!(
            descriptor.status == 200
                && descriptor.body["data"]["heptabao_convergent_version"] == 1
                && descriptor.body["data"]["heptabao_convergent_min_encryption_version"] == 1
                && descriptor.body["data"]["heptabao_convergent_versions"] == json!({"1":1}),
            "mixed PKI restart retains the safe mode and per-version floor"
        );
        let decrypted = call(
            &mut reopened,
            "POST",
            "safe/decrypt/key",
            &admin,
            json!({"ciphertext":ciphertext,
                   "context":BASE64.encode(b"synthetic mixed safe PKI context"),
                   "associated_data":BASE64.encode(b"synthetic mixed safe PKI AAD")}),
        );
        assert!(
            decrypted.status == 200
                && decrypted.body["data"]["plaintext"]
                    == BASE64.encode(b"synthetic mixed safe PKI plaintext"),
            "safe AES128 ciphertext decrypts after the complete real PKI workflow"
        );
    }
    let before_rotate = remote.calls()?;
    let rotated = call(
        &mut reopened,
        "GET",
        "external-ca/crl/rotate",
        &admin,
        json!({}),
    );
    assert!(
        rotated.status == 200 && rotated.body["data"]["success"] == true,
        "GET explicit CRL rotation"
    );
    assert!(
        remote.calls()? == before_rotate + 3,
        "mixed restart rotate has metadata and exactly two CRL signing effects"
    );
    verify_crl(
        &public,
        &crl_bytes(&mut reopened, &admin, false)?,
        5,
        1,
        false,
    )?;
    verify_crl(
        &public,
        &crl_bytes(&mut reopened, &admin, true)?,
        6,
        0,
        true,
    )?;
    assert!(
        reopened.state.as_ref().ok_or("mixed rotated state")?.schema == expected_schema,
        "explicit CRL rotation cannot downgrade the mixed writer schema"
    );
    Ok(())
}

#[test]
fn external_pki270_leaf_sign_result_grant_aba_and_owner_authority_fence_private_release()
-> TestResult {
    for mutation in ["grant-aba", "role-delete", "owner-revoke"] {
        let remote = RemoteTransit::new_kind("ed25519")?;
        let (_root, mut service, _unseal, admin) = leaf_fixture(&remote)?;
        let _last_use = limited_token(
            &mut service,
            &admin,
            "path \"external-ca/issue/leaf\" { capabilities = [\"update\"] }",
        )?;
        let created = call(
            &mut service,
            "POST",
            "auth/token/create",
            &admin,
            json!({"policies":["scoped"],"no_default_policy":true}),
        );
        assert!(created.status == 200, "live durable leaf owner fixture");
        let token = created.body["auth"]["client_token"]
            .as_str()
            .ok_or("owner token")?
            .to_owned();
        let pending = match service.begin_at_mode(RequestDispatch {
            method: "POST",
            path: "external-ca/issue/leaf",
            namespace: "",
            token: &token,
            body: json!({"common_name":"leaf.example.test","ttl":"10m"}),
            now: 100,
            allow_forward: true,
            enforce_namespace: false,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        }) {
            RequestExecution::External(pending) => *pending,
            RequestExecution::Complete(_) => return Err("leaf effect did not stage".into()),
        };
        let observation = pending.execute();
        assert!(
            matches!(&observation, ExternalEffectResult::ExternalPki(Ok(_))),
            "actual remote leaf signature before authority change"
        );
        let before = remote.calls()?;
        if mutation == "grant-aba" {
            for method in ["DELETE", "POST"] {
                assert!(
                    call(
                        &mut service,
                        method,
                        "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
                        &admin,
                        json!({})
                    )
                    .status
                        == 204,
                    "grant ABA mutation"
                );
            }
        } else if mutation == "role-delete" {
            assert!(
                call(
                    &mut service,
                    "DELETE",
                    "external-ca/roles/leaf",
                    &admin,
                    json!({})
                )
                .status
                    == 204,
                "role revocation"
            );
        } else {
            assert!(
                call(
                    &mut service,
                    "POST",
                    "auth/token/revoke",
                    &admin,
                    json!({"token":token})
                )
                .status
                    == 204,
                "original leaf owner revocation"
            );
        }
        let response = service.finish_external_request(pending, observation);
        assert!(
            response.status >= 400 && response.body.get("data").is_none(),
            "stale leaf result never releases private output"
        );
        assert!(
            remote.calls()? == before,
            "authority failure never retries provider"
        );
        let value = serde_json::to_value(&service.state.as_ref().ok_or("state")?.engines)?;
        assert!(
            value["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"]["issued"]
                .as_object()
                .is_some_and(|issued| issued.is_empty()),
            "failed leaf has no durable certificate or lease"
        );
    }
    Ok(())
}

#[test]
fn external_pki270_dns_common_name_has_exact_san_and_text_common_name_has_none() -> TestResult {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    for (common_name, dns) in [
        ("synthetic-preflight-ca.example.test", true),
        ("Synthetic Direct External Root", false),
    ] {
        for route in ["root/generate/kms", "intermediate/generate/kms"] {
            let remote = RemoteTransit::new_kind("ed25519")?;
            let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
            let response = call(
                &mut service,
                "POST",
                &format!("external-ca/{route}"),
                &admin,
                json!({"external_key_ref":"remote:v2","common_name":common_name,"ttl":"1h"}),
            );
            assert!(response.status == 200, "PKI subject generation");
            let root_route = route.starts_with("root");
            let field = if root_route { "certificate" } else { "csr" };
            let der = decode_pem(
                response.body["data"][field]
                    .as_str()
                    .ok_or("PKI document")?,
            )?;
            if root_route {
                let (_, cert) = parse_x509_certificate(&der).map_err(|_| "root DER")?;
                let san = cert.subject_alternative_name().map_err(|_| "root SAN")?;
                assert!(
                    san.as_ref().is_some_and(
                        |san| san.value.general_names == [GeneralName::DNSName(common_name)]
                    ) == dns,
                    "root exact DNS SAN contract"
                );
                assert!(
                    cert.extensions().len() == if dns { 5 } else { 4 },
                    "root exact extension count"
                );
                if !dns {
                    assert!(san.is_none(), "text root excludes DNS SAN");
                }
            } else {
                let (_, csr) = X509CertificationRequest::from_der(&der).map_err(|_| "CSR DER")?;
                let extensions = csr
                    .requested_extensions()
                    .map(|extensions| extensions.collect::<Vec<_>>());
                if dns {
                    assert!(
                        matches!(extensions.as_deref(), Some([ParsedExtension::SubjectAlternativeName(san)]) if san.general_names == [GeneralName::DNSName(common_name)]),
                        "CSR exact DNS SAN contract"
                    );
                } else {
                    assert!(extensions.is_none(), "text CSR excludes extensionRequest");
                }
            }
            assert!(
                remote.calls()? == if route.starts_with("root") { 4 } else { 2 },
                "one metadata read and complete real signing effects"
            );
            drop(service);
            let mut reopened = root.service()?;
            assert!(
                call(
                    &mut reopened,
                    "POST",
                    "sys/unseal",
                    "",
                    json!({"key":unseal})
                )
                .status
                    == 200,
                "SAN metadata encrypted restart"
            );
            assert!(
                reopened
                    .state
                    .as_ref()
                    .ok_or("SAN state")?
                    .validate_format()
                    .is_ok(),
                "SAN metadata retains exact DER authority"
            );
        }
    }
    Ok(())
}

#[test]
fn external_pki270_real_remote_root_and_csr_have_bound_public_keys_and_restart() -> TestResult {
    for route in ["root/generate/kms", "intermediate/generate/kms"] {
        let remote = RemoteTransit::new_kind("ed25519")?;
        let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
        let response = call(
            &mut service,
            "POST",
            &format!("external-ca/{route}"),
            &admin,
            body(),
        );
        assert!(response.status == 200, "actual external PKI generation");
        let data = response.body["data"]
            .as_object()
            .ok_or("PKI data missing")?;
        assert!(
            !data.contains_key("private_key"),
            "external PKI local private key forbidden"
        );
        assert!(
            remote.calls()? == if route.starts_with("root") { 4 } else { 2 },
            "one metadata read and complete actual signatures, without retry"
        );
        let public = call(
            &mut *remote.service.lock().map_err(|_| "remote lock")?,
            "GET",
            "transit/keys/remote",
            &remote.admin,
            json!({}),
        );
        assert!(public.status == 200, "remote public descriptor");
        let public = BASE64.decode(
            public.body["data"]["keys"]["2"]["public_key"]
                .as_str()
                .ok_or("remote public key missing")?,
        )?;
        if route.starts_with("root") {
            assert!(data.len() == 8, "exact official root response fields");
            let der = decode_pem(
                data["certificate"]
                    .as_str()
                    .ok_or("root certificate missing")?,
            )?;
            let (tail, certificate) = parse_x509_certificate(&der).map_err(|_| "root DER parse")?;
            assert!(tail.is_empty(), "root canonical DER consumed");
            assert!(
                certificate.public_key().subject_public_key.data.as_ref() == public,
                "root SPKI bound to fixed remote key"
            );
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
                .verify(
                    certificate.tbs_certificate.as_ref(),
                    certificate.signature_value.data.as_ref(),
                )
                .map_err(|_| "root actual cryptographic signature invalid")?;
            assert!(certificate.is_ca(), "external root CA constraint");
        } else {
            assert!(data.len() == 2, "exact official CSR response fields");
            let der = decode_pem(data["csr"].as_str().ok_or("CSR missing")?)?;
            let (tail, csr) =
                X509CertificationRequest::from_der(&der).map_err(|_| "CSR DER parse")?;
            assert!(tail.is_empty(), "CSR canonical DER consumed");
            assert!(
                csr.certification_request_info
                    .subject_pki
                    .subject_public_key
                    .data
                    .as_ref()
                    == public,
                "CSR SPKI bound to fixed remote key"
            );
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
                .verify(
                    csr.certification_request_info.raw,
                    csr.signature_value.data.as_ref(),
                )
                .map_err(|_| "CSR actual cryptographic signature invalid")?;
        }
        let state = service.state.as_ref().ok_or("state missing")?;
        assert!(
            state.schema == CURRENT_STATE_SCHEMA,
            "external PKI writer schema fence"
        );
        let mut downgraded = state.clone();
        downgraded.schema = 64;
        assert!(
            downgraded.validate_format().is_err(),
            "external PKI reader schema fence"
        );
        let encoded = serde_json::to_value(&state.engines)?;
        let pki = &encoded["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"];
        if route.starts_with("root") {
            assert!(
                pki["root"]["pkcs8"].as_array().is_some_and(Vec::is_empty),
                "root retains no local private key"
            );
        }
        let audit = fs::read_to_string(root.path.join("audit.jsonl"))?;
        assert!(
            !audit.contains(&remote.admin),
            "PKI provider credential audit redaction"
        );
        drop(service);
        let mut reopened = root.service()?;
        reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
        assert!(
            call(
                &mut reopened,
                "POST",
                "sys/unseal",
                "",
                json!({"key":unseal})
            )
            .status
                == 200,
            "external PKI encrypted restart"
        );
        assert!(
            reopened
                .state
                .as_ref()
                .ok_or("reopened state")?
                .validate_format()
                .is_ok(),
            "retained cryptographic PKI metadata"
        );
        if route.starts_with("root") {
            let retained = call(
                &mut reopened,
                "GET",
                "external-ca/cert/ca",
                &admin,
                json!({}),
            );
            assert!(
                retained.status == 200
                    && retained.body["data"]["certificate"].as_str()
                        == Some(data["certificate"].as_str().ok_or("generated root PEM")?),
                "external root certificate readback exact"
            );
        }
    }
    Ok(())
}

#[test]
fn external_pki270_original_grant_acl_tls_and_synthetic_ack_cannot_generate_certificate()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let before = remote.calls()?;
    let token = limited_token(
        &mut service,
        &admin,
        "path \"secret/*\" { capabilities = [\"read\"] }",
    )?;
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &token,
            body()
        )
        .status
            == 403,
        "consumer ACL before provider entry"
    );
    assert!(
        remote.calls()? == before,
        "ACL denial has no provider entry"
    );
    assert!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
            &admin,
            json!({})
        )
        .status
            == 204,
        "grant remove"
    );
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            body()
        )
        .status
            == 400,
        "missing PKI grant official rejection"
    );
    assert!(
        remote.calls()? == before,
        "grant denial has no provider entry"
    );
    assert!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
            &admin,
            json!({})
        )
        .status
            == 204,
        "grant restore"
    );
    assert!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote/keys/v1/grants/external-ca",
            &admin,
            json!({})
        )
        .status
            == 204,
        "old version grant"
    );
    let before = remote.calls()?;
    let mut old = body();
    old["external_key_ref"] = json!("remote:v1");
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            old
        )
        .status
            == 400,
        "official direct generation rejects old fixed provider version"
    );
    assert!(
        remote.calls()? == before + 1,
        "old mapping metadata read never enters sign"
    );
    remote.ack_only.store(true, Ordering::SeqCst);
    let failed = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    assert!(
        failed.status >= 400 && failed.body.get("data").is_none(),
        "verification ack is not a PKI signature"
    );
    assert!(
        call(
            &mut service,
            "GET",
            "external-ca/cert/ca",
            &admin,
            json!({})
        )
        .status
            == 404,
        "failed generation publishes no root"
    );
    remote.ack_only.store(false, Ordering::SeqCst);
    let other = RemoteTransit::new_kind("ed25519")?;
    let mut endpoint = remote.endpoint();
    endpoint.ca_pem = other.ca.clone();
    service.outbound = crate::outbound::Outbound::new(vec![endpoint])?;
    let before = remote.calls()?;
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &admin,
            body()
        )
        .status
            == 503,
        "deployment TLS admission fence"
    );
    assert!(
        remote.calls()? == before,
        "wrong CA has no metadata or sign entry"
    );
    Ok(())
}

#[test]
fn external_pki270_completed_real_signature_is_fenced_by_grant_aba_mount_and_state_changes()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    for mutation in [
        "grant-aba",
        "mapping-delete",
        "unrelated",
        "mount-aba",
        "seal",
    ] {
        let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
        let pending = pki_staged(&mut service, &admin, "external-ca/root/generate/kms")?;
        let result = pending.execute();
        assert!(
            matches!(&result, ExternalEffectResult::ExternalPki(Ok(_))),
            "actual remote PKI signature before fencing"
        );
        let before = remote.calls()?;
        match mutation {
            "grant-aba" => {
                assert!(
                    call(
                        &mut service,
                        "DELETE",
                        "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
                        &admin,
                        json!({})
                    )
                    .status
                        == 204,
                    "grant ABA delete"
                );
                assert!(
                    call(
                        &mut service,
                        "POST",
                        "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
                        &admin,
                        json!({})
                    )
                    .status
                        == 204,
                    "grant ABA restore"
                );
            }
            "mapping-delete" => {
                assert!(
                    call(
                        &mut service,
                        "DELETE",
                        "sys/external-keys/configs/remote/keys/v2",
                        &admin,
                        json!({})
                    )
                    .status
                        == 204,
                    "mapping delete"
                );
            }
            "unrelated" => {
                assert!(
                    call(
                        &mut service,
                        "POST",
                        "secret/data/unrelated",
                        &admin,
                        json!({"data":{"value":"write"}})
                    )
                    .status
                        == 200,
                    "unrelated conservative fence"
                );
            }
            "mount-aba" => {
                assert!(
                    call(
                        &mut service,
                        "DELETE",
                        "sys/mounts/external-ca",
                        &admin,
                        json!({})
                    )
                    .status
                        == 204,
                    "mount ABA delete"
                );
                assert!(
                    call(
                        &mut service,
                        "POST",
                        "sys/mounts/external-ca",
                        &admin,
                        json!({"type":"pki"})
                    )
                    .status
                        == 204,
                    "mount ABA restore"
                );
            }
            "seal" => {
                assert!(
                    call(&mut service, "POST", "sys/seal", &admin, json!({})).status == 204,
                    "seal fence"
                );
            }
            _ => return Err("unknown mutation".into()),
        }
        let response = service.finish_external_request(pending, result);
        assert!(
            response.status == 503 && response.body.get("data").is_none(),
            "stale PKI signature withheld"
        );
        assert!(
            remote.calls()? == before,
            "publication failure never replays remote signing"
        );
    }
    Ok(())
}

#[test]
fn external_pki270_namespace_registry_and_remote_namespace_cannot_cross_authority() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    for (method, path, namespace, body, status) in [
        ("POST", "sys/namespaces/team", "", json!({}), 200),
        (
            "POST",
            "sys/mounts/external-ca",
            "team",
            json!({"type":"pki"}),
            204,
        ),
        ("POST", "external-ca/root/generate/kms", "team", body(), 400),
    ] {
        assert!(
            service
                .handle_at(method, path, namespace, &admin, body, 100)
                .status
                == status,
            "consumer namespace authority"
        );
    }
    assert!(
        remote.calls()? == 0,
        "root namespace registry never authorizes team consumer"
    );
    {
        let mut provider = remote.service.lock().map_err(|_| "remote lock")?;
        assert!(
            provider
                .handle_at(
                    "POST",
                    "sys/namespaces/provider-team",
                    "",
                    &remote.admin,
                    json!({}),
                    100
                )
                .status
                == 200,
            "remote namespace create"
        );
        // This native test fixture creates each namespace with a Transit mount.
        assert!(
            provider
                .handle_at(
                    "POST",
                    "transit/keys/team",
                    "provider-team",
                    &remote.admin,
                    json!({"type":"ed25519"}),
                    100
                )
                .status
                == 200,
            "remote namespace private key owner"
        );
    }
    for (path, body, status) in [
        (
            "sys/external-keys/configs/remote",
            json!({"plugin":"transit","verify":false,"address":remote.origin(),"token":remote.admin,"mount_path":"transit","namespace":"provider-team"}),
            204,
        ),
        (
            "sys/external-keys/configs/remote/keys/v2",
            json!({"verify":false,"name":"team","version":1}),
            204,
        ),
        (
            "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
            json!({}),
            204,
        ),
    ] {
        assert!(
            service
                .handle_at("POST", path, "team", &admin, body, 100)
                .status
                == status,
            "team-owned registry admission"
        );
    }
    let response = service.handle_at(
        "POST",
        "external-ca/root/generate/kms",
        "team",
        &admin,
        body(),
        100,
    );
    assert!(
        response.status == 200,
        "team consumer actual namespaced provider signature"
    );
    assert!(
        call(
            &mut service,
            "GET",
            "external-ca/cert/ca",
            &admin,
            json!({})
        )
        .status
            == 404,
        "namespaced root never publishes to root namespace"
    );
    let paths = remote.trace.lock().map_err(|_| "trace lock")?;
    assert!(
        paths.iter().any(|path| path == "/v1/transit/sign/team"),
        "only selected remote namespace key route"
    );
    Ok(())
}

#[test]
fn external_pki270_metadata_rejects_private_key_injection_certificate_and_spki_tampering()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
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
        "actual issuer fixture"
    );
    let state = service.state.as_ref().ok_or("state")?;
    let original = serde_json::to_value(&state.engines)?;
    for field in ["private-key", "spki", "certificate"] {
        let mut encoded = original.clone();
        let pki = &mut encoded["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"];
        match field {
            "private-key" => pki["root"]["pkcs8"] = json!([1, 2, 3]),
            "spki" => {
                let bytes = pki["external"]["root"]["public_key"]
                    .as_array_mut()
                    .ok_or("public metadata")?;
                bytes[0] = json!(bytes[0].as_u64().ok_or("public byte")? ^ 1);
            }
            "certificate" => {
                let bytes = pki["root"]["certificate_der"]
                    .as_array_mut()
                    .ok_or("certificate metadata")?;
                let index = bytes.len() - 1;
                bytes[index] = json!(bytes[index].as_u64().ok_or("certificate byte")? ^ 1);
            }
            _ => return Err("mutation".into()),
        }
        let engines: EngineState = serde_json::from_value(encoded)?;
        let mut tampered = state.clone();
        tampered.engines = engines.into();
        assert!(
            tampered.validate_format().is_err(),
            "external issuer ownership and crypto metadata fence"
        );
    }
    let mut unknown = original;
    unknown["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"]["external"]["root"]["private_key"] =
        json!("forbidden private payload");
    assert!(
        serde_json::from_value::<EngineState>(unknown).is_err(),
        "unknown external key fields cannot be silently discarded"
    );
    Ok(())
}

#[test]
fn external_pki270_original_last_use_principal_deadline_and_audit_veto_remain_authoritative()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let token = limited_token(
        &mut service,
        &admin,
        "path \"external-ca/root/generate/kms\" { capabilities = [\"update\"] }",
    )?;
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &token,
            body()
        )
        .status
            == 200,
        "original admitted last-use principal succeeds"
    );
    let before = remote.calls()?;
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/root/generate/kms",
            &token,
            body()
        )
        .status
            == 403,
        "finite token cannot be replayed"
    );
    assert!(
        remote.calls()? == before,
        "retired token never reads metadata or signs"
    );
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let scope = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() + std::time::Duration::from_millis(2000),
    );
    let pending = pki_staged(&mut service, &admin, "external-ca/root/generate/kms")?;
    let result = pending.execute();
    assert!(
        matches!(&result, ExternalEffectResult::ExternalPki(Ok(_))),
        "actual cryptographic result within admission deadline"
    );
    drop(scope);
    thread::sleep(std::time::Duration::from_millis(2050));
    let response = service.finish_external_request(pending, result);
    assert!(
        response.status == 503 && response.body.get("data").is_none(),
        "expired original deadline cannot publish certificate"
    );
    assert!(
        call(
            &mut service,
            "GET",
            "external-ca/cert/ca",
            &admin,
            json!({})
        )
        .status
            == 404,
        "expired result publishes no root"
    );
    let pending = pki_staged(&mut service, &admin, "external-ca/root/generate/kms")?;
    let result = pending.execute();
    assert!(
        matches!(&result, ExternalEffectResult::ExternalPki(Ok(_))),
        "actual signature before audit veto"
    );
    service.audit_failed = true;
    let response = service.finish_external_request(pending, result);
    assert!(
        response.status == 503 && response.body.get("data").is_none(),
        "audit veto never returns certificate"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn external_pki270_optional_provider_host_sign_capability_disable_and_revoke_fence_publication()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    for (capabilities, enabled, scenario) in [
        (vec!["wrap".into(), "unwrap".into()], true, "no-sign"),
        (vec!["sign".into()], false, "disabled"),
        (vec!["sign".into()], true, "revoke-before"),
        (vec!["sign".into()], true, "revoke-after"),
        (vec!["sign".into()], true, "disable-after"),
    ] {
        let can_sign = enabled && capabilities.iter().any(|capability| capability == "sign");
        let (_root, mut service, _unseal, admin) =
            remote.fixture_kms_capabilities(Some(enabled), Some(capabilities))?;
        for (path, body) in [
            ("sys/mounts/external-ca", json!({"type":"pki"})),
            (
                "sys/external-keys/configs/remote/keys/v2",
                json!({"verify":false,"name":"remote","version":2}),
            ),
            (
                "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
                json!({}),
            ),
        ] {
            assert!(
                call(&mut service, "POST", path, &admin, body).status == 204,
                "host-bound fixture"
            );
        }
        if !can_sign {
            let before = remote.calls()?;
            assert!(
                call(
                    &mut service,
                    "POST",
                    "external-ca/root/generate/kms",
                    &admin,
                    body()
                )
                .status
                    == 403,
                "wrap is not sign authority"
            );
            assert!(
                remote.calls()? == before,
                "host capability denial never enters provider"
            );
        } else {
            let pending = pki_staged(&mut service, &admin, "external-ca/root/generate/kms")?;
            let before = remote.calls()?;
            if scenario == "revoke-before" {
                service
                    .kms_plugins
                    .get("transit")
                    .ok_or("host")?
                    .lock()
                    .map_err(|_| "host lock")?
                    .revoke();
            }
            let result = pending.execute();
            if scenario == "revoke-before" {
                assert!(
                    matches!(&result, ExternalEffectResult::ExternalPki(Err(_))),
                    "revoked staged host rejects before entry"
                );
                assert!(
                    remote.calls()? == before,
                    "revoked staged host never reads metadata or signs"
                );
            } else {
                assert!(
                    matches!(&result, ExternalEffectResult::ExternalPki(Ok(_))),
                    "sign-capable host actual crypto"
                );
                if scenario == "disable-after" {
                    service
                        .kms_keys
                        .get_mut("transit")
                        .ok_or("binding")?
                        .enabled = false;
                } else {
                    service
                        .kms_plugins
                        .get("transit")
                        .ok_or("host")?
                        .lock()
                        .map_err(|_| "host lock")?
                        .revoke();
                }
            }
            let response = service.finish_external_request(pending, result);
            assert!(
                response.status == 503 && response.body.get("data").is_none(),
                "same-Arc host revocation fences publication"
            );
        }
    }
    Ok(())
}
