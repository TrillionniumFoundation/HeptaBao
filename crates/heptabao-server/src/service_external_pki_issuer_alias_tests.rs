//! Real provider signatures, no material or private state in assertion output.
use super::*;
use openssl::x509::{X509, X509Crl};

const ALIASES: [&str; 9] = [
    "json",
    "der",
    "pem",
    "crl",
    "crl/der",
    "crl/pem",
    "crl/delta",
    "crl/delta/der",
    "crl/delta/pem",
];

fn named_root(remote: &RemoteTransit) -> TestResult<(Root, Service, String, String, String)> {
    let (root, mut service, unseal, admin) = pki_fixture(remote)?;
    let mut named = body();
    named["issuer_name"] = json!("primary");
    let generated = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        named,
    );
    assert!(generated.status == 200, "real named issuer publication");
    let id = generated.body["data"]["issuer_id"]
        .as_str()
        .ok_or("issuer identifier")?
        .to_owned();
    Ok((root, service, unseal, admin, id))
}

fn material(response: &Response, suffix: &str) -> TestResult<Vec<u8>> {
    let crl = suffix.starts_with("crl");
    let json = suffix == "json" || matches!(suffix, "crl" | "crl/delta");
    if json {
        let field = if crl { "crl" } else { "certificate" };
        Ok(response.body["data"][field]
            .as_str()
            .ok_or("public PEM")?
            .as_bytes()
            .to_vec())
    } else {
        let marker = if crl {
            "__heptabao_pki_crl"
        } else {
            "__heptabao_pki_certificate"
        };
        Ok(BASE64.decode(
            response.body[marker]
                .as_str()
                .ok_or("closed public transport")?,
        )?)
    }
}

#[test]
fn external_pki270_issuer_aliases_bind_seven_real_kinds_and_exact_selected_pem() -> TestResult {
    for kind in [
        "ed25519",
        "ecdsa-p256",
        "ecdsa-p384",
        "ecdsa-p521",
        "rsa-2048",
        "rsa-3072",
        "rsa-4096",
    ] {
        let remote = RemoteTransit::new_kind(kind)?;
        let (root, mut service, unseal, _admin, id) = named_root(&remote)?;
        let generated = call(
            &mut service,
            "GET",
            "external-ca/issuer/default/json",
            "",
            json!({}),
        );
        let certificate = X509::from_pem(
            generated.body["data"]["certificate"]
                .as_str()
                .ok_or("certificate")?
                .as_bytes(),
        )?;
        let public = certificate.public_key()?;
        assert!(
            certificate.verify(&public)?,
            "real root self-signature remains valid"
        );
        let certificate_der = certificate.to_der()?;
        let certificate_pem = certificate.to_pem()?;
        let full = crl_bytes(&mut service, "", false)?;
        let delta = crl_bytes(&mut service, "", true)?;
        let calls = remote.calls()?;
        let identity = service.current_state_identity().map_err(|_| "identity")?;
        let generation = service
            .external_effect_generation()
            .map_err(|_| "generation")?;
        let audit_before = fs::read_to_string(root.path.join("audit.jsonl"))?
            .lines()
            .count();
        for token in ["", "synthetic.invalid.bearer"] {
            for reference in ["default", id.as_str(), "primary"] {
                for suffix in ALIASES {
                    let response = call(
                        &mut service,
                        "GET",
                        &format!("external-ca/issuer/{reference}/{suffix}"),
                        token,
                        json!({}),
                    );
                    assert!(
                        response.status == 200,
                        "closed issuer alias discloses only bound public material"
                    );
                    let bytes = material(&response, suffix)?;
                    let is_crl = suffix.starts_with("crl");
                    let is_der = suffix == "der" || suffix.ends_with("/der");
                    if is_crl {
                        let decoded = if is_der {
                            X509Crl::from_der(&bytes)?
                        } else {
                            X509Crl::from_pem(&bytes)?
                        };
                        let expected = if suffix.contains("delta") {
                            &delta
                        } else {
                            &full
                        };
                        assert!(
                            decoded.verify(&public)? && decoded.to_der()? == *expected,
                            "alias cache retains its actual provider signature and exact original DER"
                        );
                        let canonical = decoded.to_pem()?;
                        assert!(
                            if is_der {
                                bytes == *expected
                            } else {
                                bytes == canonical
                            },
                            "CRL endpoint chooses its exact DER or one-LF canonical PEM"
                        );
                        if matches!(suffix, "crl" | "crl/delta") {
                            assert!(response.body["data"].as_object().is_some_and(|data| data.len() == 1 && data.contains_key("crl")), "issuer CRL JSON exposes exactly one crl field");
                        }
                    } else {
                        assert!(
                            if is_der {
                                bytes == certificate_der
                            } else {
                                bytes == certificate_pem
                            },
                            "issuer certificate endpoints preserve exact selected encoding"
                        );
                        if suffix == "json" {
                            assert!(
                                response.body["data"] == generated.body["data"],
                                "ID and name bind the same complete public issuer metadata"
                            );
                        }
                    }
                    assert!(
                        response
                            .body
                            .get("data")
                            .is_none_or(|d| d.get("private_key").is_none()
                                && d.get("external_key_ref").is_none()),
                        "public aliases disclose no private fields"
                    );
                }
            }
        }
        let audit_after = fs::read_to_string(root.path.join("audit.jsonl"))?
            .lines()
            .count();
        assert!(
            audit_after - audit_before == 2 * 2 * 3 * ALIASES.len(),
            "each alias read retains one request and response audit"
        );
        assert!(
            remote.calls()? == calls
                && service.current_state_identity().map_err(|_| "identity")? == identity
                && service
                    .external_effect_generation()
                    .map_err(|_| "generation")?
                    == generation,
            "aliases do not sign or publish business state"
        );
        // Legacy CA/CRL projections remain exactly no-LF despite issuer-specific LF1.
        for path in [
            "external-ca/ca/pem",
            "external-ca/crl/pem",
            "external-ca/crl/delta/pem",
        ] {
            let response = call(&mut service, "GET", path, "", json!({}));
            let marker = if path.contains("crl") {
                "__heptabao_pki_crl"
            } else {
                "__heptabao_pki_certificate"
            };
            let bytes = BASE64.decode(
                response.body[marker]
                    .as_str()
                    .ok_or("legacy public envelope")?,
            )?;
            assert!(
                !bytes.ends_with(b"\n"),
                "legacy public endpoints retain their exact original no-LF encoding"
            );
        }
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
            "encrypted restart retains the original issuer"
        );
        for reference in ["default", id.as_str(), "primary"] {
            for suffix in ALIASES {
                let response = call(
                    &mut reopened,
                    "GET",
                    &format!("external-ca/issuer/{reference}/{suffix}"),
                    "",
                    json!({}),
                );
                assert!(
                    response.status == 200,
                    "restart resolves the same closed issuer reference"
                );
                let bytes = material(&response, suffix)?;
                if suffix.starts_with("crl") {
                    let crl = if suffix.ends_with("/der") {
                        X509Crl::from_der(&bytes)?
                    } else {
                        X509Crl::from_pem(&bytes)?
                    };
                    assert!(
                        crl.verify(&public)?
                            && crl.to_der()?
                                == if suffix.contains("delta") {
                                    delta.clone()
                                } else {
                                    full.clone()
                                },
                        "restart cache remains actually verified and byte-bound"
                    );
                } else {
                    assert!(
                        bytes
                            == if suffix == "der" {
                                certificate_der.clone()
                            } else {
                                certificate_pem.clone()
                            },
                        "restart binds the original public certificate bytes"
                    );
                }
            }
        }
        assert!(
            remote.calls()? == calls,
            "encrypted reopen and all alias reads enter no provider request"
        );
    }
    Ok(())
}

#[test]
fn external_pki270_unknown_issuer_aliases_fail_exact500_without_default_fallback() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, _admin, id) = named_root(&remote)?;
    let calls = remote.calls()?;
    for reference in [
        "unknown-issuer",
        "00000000-0000-4000-8000-000000000000",
        "Primary",
        "Default",
    ] {
        for suffix in ALIASES {
            let response = call(
                &mut service,
                "GET",
                &format!("external-ca/issuer/{reference}/{suffix}"),
                "",
                json!({}),
            );
            assert!(
                response.status == 500 && response.body.get("data").is_none(),
                "unknown name or ID never falls back to the default issuer"
            );
        }
    }
    for suffix in ALIASES {
        let path = format!("external-ca/issuer/{id}/{suffix}");
        assert!(
            call(&mut service, "POST", &path, "", json!({})).status == 403,
            "public GET aliases do not authorize anonymous mutation"
        );
        assert!(
            call(
                &mut service,
                "GET",
                &path,
                "",
                json!({"synthetic_extra":true})
            )
            .status
                == 400,
            "closed public input cannot smuggle engine effects"
        );
        assert!(
            service
                .handle_at("GET", &path, "missing-namespace", "", json!({}), 100)
                .status
                != 200,
            "issuer identifiers do not cross namespace ownership"
        );
    }
    assert!(
        remote.calls()? == calls,
        "unknown, denied, and wrong namespace requests enter no provider operation"
    );
    Ok(())
}

#[test]
fn external_pki270_issuer_alias_cache_expiry_cannot_rollback() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, _admin, id) = named_root(&remote)?;
    let calls = remote.calls()?;
    let future = 100 + 72 * 3600 + 1;
    assert!(
        service
            .handle_at(
                "GET",
                "external-ca/issuer/primary/crl",
                "",
                "",
                json!({}),
                future
            )
            .status
            == 503,
        "independent cache expiry is observed before rollback"
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        reopened
            .handle_at("POST", "sys/unseal", "", "", json!({"key":unseal}), 101)
            .status
            == 200,
        "clock floor survives encrypted reopen"
    );
    for reference in ["default", id.as_str(), "primary"] {
        for suffix in ALIASES.into_iter().filter(|s| s.starts_with("crl")) {
            let response = reopened.handle_at(
                "GET",
                &format!("external-ca/issuer/{reference}/{suffix}"),
                "",
                "",
                json!({}),
                101,
            );
            assert!(
                response.status == 503 && response.body.get("data").is_none(),
                "issuer aliases cannot resurrect an observed-expired cache"
            );
        }
    }
    assert!(
        remote.calls()? == calls,
        "expiry and rollback reads never re-sign"
    );
    Ok(())
}

#[test]
fn external_pki270_issuer_alias_owner_revocation_is_durable_and_never_rebuilds() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (root, mut service, unseal, admin, id) = named_root(&remote)?;
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/roles/leaf",
            &admin,
            json!({
                "allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"30m",
                "generate_lease":true,"key_type":"ed25519"
            })
        )
        .status
            == 200,
        "lease-backed leaf role uses ordinary admission"
    );
    let _unused_last_use = limited_token(
        &mut service,
        &admin,
        "path \"external-ca/issue/leaf\" { capabilities = [\"update\"] }",
    )?;
    let owner = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["scoped"],"no_default_policy":true}),
    );
    assert!(owner.status == 200, "original leaf owner admission");
    let token = owner.body["auth"]["client_token"]
        .as_str()
        .ok_or("leaf owner")?;
    assert!(
        call(
            &mut service,
            "POST",
            "external-ca/issue/leaf",
            token,
            json!({"common_name":"owned-public.example.test","ttl":"10m"})
        )
        .status
            == 200,
        "real leased leaf publication"
    );
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
        "ordinary owner revocation"
    );
    let generation_before = service
        .external_effect_generation()
        .map_err(|_| "generation")?;
    let calls = remote.calls()?;
    let observed = call(
        &mut service,
        "GET",
        "external-ca/issuer/primary/crl",
        "",
        json!({}),
    );
    assert!(
        observed.status == 503 && observed.body.get("data").is_none(),
        "issuer alias reconciles owner revocation before public disclosure"
    );
    let generation = service
        .external_effect_generation()
        .map_err(|_| "generation")?;
    assert!(
        generation != generation_before,
        "necessary owner maintenance is durably published"
    );
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    for reference in ["default", id.as_str(), "primary"] {
        for suffix in ALIASES.into_iter().filter(|s| s.starts_with("crl")) {
            let response = call(
                &mut service,
                "GET",
                &format!("external-ca/issuer/{reference}/{suffix}"),
                "",
                json!({}),
            );
            assert!(
                response.status == 503 && response.body.get("data").is_none(),
                "no alias can serve a cache missing the durable owner revocation"
            );
        }
    }
    assert!(
        service.current_state_identity().map_err(|_| "identity")? == identity
            && service
                .external_effect_generation()
                .map_err(|_| "generation")?
                == generation,
        "already reconciled alias reads publish no further maintenance"
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
        "owner revocation survives authenticated encrypted restart"
    );
    for reference in ["default", id.as_str(), "primary"] {
        for suffix in ALIASES.into_iter().filter(|s| s.starts_with("crl")) {
            let response = call(
                &mut reopened,
                "GET",
                &format!("external-ca/issuer/{reference}/{suffix}"),
                "",
                json!({}),
            );
            assert!(
                response.status == 503 && response.body.get("data").is_none(),
                "restart cannot resurrect the stale signed CRL cache"
            );
        }
    }
    assert!(
        remote.calls()? == calls,
        "owner maintenance and all public aliases never re-enter provider"
    );
    Ok(())
}

#[test]
fn external_pki270_issuer_retirement_keeps_typed_snapshot_floor_and_removes_all_aliases()
-> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
    let (_root, mut service, _unseal, admin) = pki_fixture(&remote)?;
    let mut ordinary66 = service.state.clone().ok_or("ordinary state")?;
    ordinary66.schema = AAD_BOUND_STATE_SCHEMA;
    service
        .commit_state(&mut ordinary66)
        .map_err(|_| "ordinary66 publication")?;
    service.state = Some(ordinary66);
    let old66 =
        zeroize::Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut named = body();
    named["issuer_name"] = json!("primary");
    let generated = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        named,
    );
    assert!(generated.status == 200, "actual typed issuer");
    let id = generated.body["data"]["issuer_id"]
        .as_str()
        .ok_or("issuer identifier")?
        .to_owned();
    let calls = remote.calls()?;
    for retired in [false, true] {
        if retired {
            assert!(
                call(
                    &mut service,
                    "POST",
                    "external-ca/root/delete",
                    &admin,
                    json!({})
                )
                .status
                    == 200,
                "explicit issuer retirement"
            );
        }
        assert!(
            service.state.as_ref().ok_or("state")?.schema == TYPED_PKI_STATE_SCHEMA,
            "typed67 remains sticky across alias reads and retirement"
        );
        let before = service.current_state_identity().map_err(|_| "identity")?;
        assert!(
            service
                .prepare_snapshot_restore(&old66)
                .err()
                .is_some_and(|r| r.status == 400),
            "actual authenticated old66 snapshot remains refused for active and retired typed issuer"
        );
        assert!(
            service.current_state_identity().map_err(|_| "identity")? == before,
            "old-format rejection publishes no state"
        );
        for reference in ["default", id.as_str(), "primary"] {
            for suffix in ALIASES {
                let response = call(
                    &mut service,
                    "GET",
                    &format!("external-ca/issuer/{reference}/{suffix}"),
                    "",
                    json!({}),
                );
                assert!(
                    response.status == if retired { 500 } else { 200 },
                    "issuer alias lifecycle follows original issuer retirement"
                );
                if retired {
                    assert!(
                        response.body.get("data").is_none(),
                        "retired issuer aliases disclose no former material"
                    );
                }
            }
        }
    }
    assert!(
        remote.calls()? == calls,
        "alias and retirement checks never enter provider operations"
    );
    Ok(())
}
