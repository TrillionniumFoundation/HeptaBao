//! Independent remote native Transit signs DER. Assertions never format public
//! certificates, signatures, input, credentials or serialized secret state.
use super::*;
use x509_parser::prelude::*;

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
            remote.calls()? == 2,
            "one metadata read and one actual sign, without retry"
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
        assert!(state.schema == 65, "external PKI writer schema fence");
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
                    && retained.body["data"]["certificate"] == data["certificate"],
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
