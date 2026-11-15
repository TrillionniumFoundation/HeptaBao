//! Parameter verification and actual encrypted HTTPS consumer operations.
//! No verification acknowledgement is accepted as a cryptographic result.
use super::*;

fn config(remote: &RemoteTransit) -> Value {
    json!({"plugin":"transit","verify":true,"address":remote.origin(),"token":remote.admin,
        "mount_path":"transit","tls_server_name":"external.test","tls_ca_cert_bytes":remote.ca})
}

fn verify_mapping(service: &mut Service, admin: &str, name: &str, version: u64) -> Response {
    call(
        service,
        "POST",
        "sys/external-keys/configs/remote/keys/v1",
        admin,
        json!({"verify":true,"name":name,"version":version}),
    )
}

fn pending_mapping(service: &mut Service, admin: &str) -> TestResult<PendingExternalRequest> {
    let pending = staged_path(
        service,
        admin,
        "sys/external-keys/configs/remote/keys/v1",
        json!({"verify":true,"name":"remote","version":1}),
    )?;
    if !matches!(pending.effect, ExternalEffectPlan::ExternalKey(_)) {
        return Err("native verification staged wrong effect".into());
    }
    Ok(pending)
}

#[test]
fn external_keys270_native_verified_tls_config_mapping_and_real_crypto_reopen() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (root, mut service, unseal, admin) = remote.fixture()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote",
            &admin,
            config(&remote)
        )
        .status,
        204
    );
    assert_eq!(
        verify_mapping(&mut service, &admin, "remote", 1).status,
        204
    );
    assert_eq!(
        remote.calls()?,
        0,
        "parameter verification must not enter remote crypto"
    );
    // The official parameter verification accepts well-formed absent/future
    // references; the actual consumer must independently obtain real crypto.
    assert_eq!(
        verify_mapping(&mut service, &admin, "absent", 999).status,
        204
    );
    assert_eq!(remote.calls()?, 0);
    assert_eq!(
        verify_mapping(&mut service, &admin, "remote", 1).status,
        204
    );
    let plaintext = BASE64.encode(b"verified TLS remote consumer");
    let encrypted = call(
        &mut service,
        "POST",
        "consumer/encrypt/local",
        &admin,
        json!({"plaintext":plaintext}),
    );
    assert_eq!(encrypted.status, 200);
    let ciphertext = encrypted.body["data"]["ciphertext"].clone();
    let decrypted = call(
        &mut service,
        "POST",
        "consumer/decrypt/local",
        &admin,
        json!({"ciphertext":ciphertext}),
    );
    assert_eq!(decrypted.status, 200);
    assert!(
        decrypted.body["data"]["plaintext"] == plaintext,
        "real remote plaintext readback mismatch"
    );
    assert_eq!(remote.calls()?, 2);
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
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
    let readback = call(
        &mut reopened,
        "POST",
        "consumer/decrypt/local",
        &admin,
        json!({"ciphertext":ciphertext}),
    );
    assert_eq!(readback.status, 200);
    assert!(
        readback.body["data"]["plaintext"] == plaintext,
        "encrypted restart remote plaintext mismatch"
    );
    assert_eq!(remote.calls()?, 3);
    let audit = fs::read_to_string(root.path.join("audit.jsonl"))?;
    assert!(
        !audit.contains(&remote.admin),
        "remote credential leaked to audit"
    );
    assert!(
        !audit.contains(&plaintext),
        "consumer plaintext leaked to audit"
    );
    Ok(())
}

#[test]
fn external_keys270_native_tls_assertions_cannot_widen_enrolled_trust_or_sni() -> TestResult {
    let remote = RemoteTransit::new()?;
    let other = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let before = service
        .current_state_identity()
        .map_err(|r| format!("identity status {}", r.status))?;
    for (field, value, expected) in [
        ("tls_server_name", json!("other.test"), 503),
        ("tls_ca_cert_bytes", json!(other.ca), 503),
        (
            "tls_ca_cert_bytes",
            json!(format!("{}\n{}", remote.ca, other.ca)),
            503,
        ),
        ("tls_ca_cert_bytes", json!("malformed"), 503),
        ("tls_ca_cert_bytes", json!(true), 400),
        ("tls_skip_verify", json!(true), 400),
        ("tls_client_key_bytes", json!("unsupported"), 501),
        ("tls_client_cert_bytes", json!("unsupported"), 501),
    ] {
        let mut body = config(&remote);
        body[field] = value;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/external-keys/configs/remote",
                &admin,
                body
            )
            .status,
            expected,
            "TLS assertion rejection status"
        );
        assert!(
            service
                .current_state_identity()
                .is_ok_and(|identity| identity == before),
            "TLS rejection changed state"
        );
        assert_eq!(remote.calls()?, 0);
    }
    // A disabled verification flag does not bypass the same TLS checks during
    // actual consumption. Registry storage and egress authority remain separate.
    let mut body = config(&remote);
    body["verify"] = json!(false);
    body["tls_ca_cert_bytes"] = json!(other.ca);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote",
            &admin,
            body
        )
        .status,
        204
    );
    let rejected = call(
        &mut service,
        "POST",
        "consumer/encrypt/local",
        &admin,
        json!({"plaintext":""}),
    );
    assert_eq!(rejected.status, 503);
    assert!(
        rejected.body.get("data").is_none(),
        "TLS rejection returned secret result"
    );
    assert_eq!(remote.calls()?, 0);
    Ok(())
}

#[test]
fn external_keys270_native_tls_ca_comparison_is_complete_canonical_der_set() -> TestResult {
    let remote = RemoteTransit::new()?;
    let other = RemoteTransit::new()?;
    let mut endpoint = remote.endpoint();
    endpoint.ca_pem = format!("{}\n{}", remote.ca, other.ca);
    let outbound = crate::outbound::Outbound::new(vec![endpoint])?;
    let url = format!("{}/v1/transit/", remote.origin());
    assert!(
        outbound
            .validate_external_transit_tls(
                &url,
                "external.test",
                &format!("{}\n{}\n{}", other.ca, remote.ca, other.ca)
            )
            .is_ok(),
        "reordered identical anchor set rejected"
    );
    assert!(
        outbound
            .validate_external_transit_tls(&url, "external.test", &remote.ca)
            .is_err(),
        "anchor subset accepted"
    );
    assert!(
        outbound
            .validate_external_transit_tls(
                &url,
                "external.test",
                &format!(
                    "{}\n-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----",
                    remote.ca
                )
            )
            .is_err(),
        "private PEM accepted as CA"
    );
    let cert = openssl::x509::X509::from_pem(remote.ca.as_bytes())?;
    let mut der = cert.to_der()?;
    der.push(0);
    let malformed = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        BASE64.encode(&der)
    );
    assert!(
        outbound
            .validate_external_transit_tls(&url, "external.test", &malformed)
            .is_err(),
        "noncanonical DER accepted"
    );
    Ok(())
}

#[test]
fn external_keys270_native_verification_publication_keeps_generation_and_enrollment_fences()
-> TestResult {
    let remote = RemoteTransit::new()?;
    for scenario in ["registry_aba", "enrollment_replaced", "enrollment_removed"] {
        let (root, mut service, unseal, admin) = remote.fixture()?;
        let identity = service
            .current_state_identity()
            .map_err(|r| format!("identity {}", r.status))?;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let pending = pending_mapping(&mut service, &admin)?;
        let result = pending.execute();
        match scenario {
            "registry_aba" => {
                let grant = "sys/external-keys/configs/remote/keys/v1/grants/consumer";
                assert_eq!(
                    call(&mut service, "DELETE", grant, &admin, json!({})).status,
                    204
                );
                assert_eq!(
                    call(&mut service, "POST", grant, &admin, json!({})).status,
                    204
                );
                assert!(
                    service
                        .current_state_identity()
                        .is_ok_and(|current| current == identity),
                    "ABA fixture did not restore content identity"
                );
                assert!(
                    service.durable.as_ref().ok_or("durable")?.generation() > generation,
                    "ABA fixture did not advance publication generation"
                );
            }
            // Explicit test-only lifecycle injection: the normal deployment
            // API correctly refuses endpoint replacement while unsealed.
            "enrollment_replaced" => {
                service.outbound = crate::outbound::Outbound::new(vec![remote.endpoint()])?
            }
            "enrollment_removed" => service.outbound = crate::outbound::Outbound::default(),
            _ => return Err("invalid scenario".into()),
        }
        let withheld = service.finish_external_request(pending, result);
        assert_eq!(
            withheld.status, 503,
            "stale native verification result published"
        );
        assert_eq!(
            remote.calls()?,
            0,
            "verification entered or replayed provider operation"
        );
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
            call(
                &mut reopened,
                "GET",
                "sys/external-keys/configs/remote/keys/v1",
                &admin,
                json!({})
            )
            .body["data"]["version"],
            1
        );
    }
    Ok(())
}

#[test]
fn external_keys270_native_verified_config_does_not_replace_pki_crypto_validation() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote",
            &admin,
            config(&remote)
        )
        .status,
        204
    );
    assert_eq!(
        verify_mapping(&mut service, &admin, "remote", 2).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/externalpki",
            &admin,
            json!({"type":"pki"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote/keys/v1/grants/externalpki",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(remote.calls()?, 0);
    remote.ack_only.store(true, Ordering::SeqCst);
    let rejected = call(
        &mut service,
        "POST",
        "externalpki/root/generate/kms",
        &admin,
        json!({"external_key_ref":"remote:v1","common_name":"Synthetic External Root","ttl":"1h"}),
    );
    assert_eq!(rejected.status, 503);
    assert!(
        rejected.body.get("data").is_none(),
        "synthetic provider result escaped crypto validation"
    );
    remote.ack_only.store(false, Ordering::SeqCst);
    let root = call(
        &mut service,
        "POST",
        "externalpki/root/generate/kms",
        &admin,
        json!({"external_key_ref":"remote:v1","common_name":"Synthetic External Root","ttl":"1h"}),
    );
    assert_eq!(root.status, 200);
    let certificate = openssl::x509::X509::from_pem(
        root.body["data"]["certificate"]
            .as_str()
            .ok_or("certificate")?
            .as_bytes(),
    )?;
    let public = certificate.public_key()?;
    assert!(
        certificate.verify(&public)?,
        "actual external root self signature invalid"
    );
    assert!(
        root.body["data"].get("private_key").is_none(),
        "external CA private key returned"
    );
    assert!(
        remote.calls()? >= 5,
        "actual remote metadata and three signatures were not entered"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn external_keys270_native_fallback_cannot_bypass_disabled_or_revoked_kms_owner() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture_kms(Some(false))?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote",
            &admin,
            config(&remote)
        )
        .status,
        403
    );
    assert_eq!(remote.calls()?, 0);
    let host = service.kms_plugins.get("transit").ok_or("host")?.clone();
    service
        .kms_keys
        .get_mut("transit")
        .ok_or("binding")?
        .enabled = true;
    host.lock().map_err(|_| "host")?.revoke();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote",
            &admin,
            config(&remote)
        )
        .status,
        503
    );
    assert_eq!(remote.calls()?, 0);
    service.kms_plugins.remove("transit");
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote",
            &admin,
            config(&remote)
        )
        .status,
        403
    );
    assert_eq!(remote.calls()?, 0);
    Ok(())
}

#[test]
fn external_keys270_native_verification_original_actor_and_acl_remain_authoritative() -> TestResult
{
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let token = limited_token(
        &mut service,
        &admin,
        "path \"sys/external-keys/configs/remote/keys/v1\" { capabilities = [\"create\",\"update\"] }",
    )?;
    let pending = pending_mapping(&mut service, &token)?;
    let result = pending.execute();
    assert!(call(&mut service, "PUT", "sys/policies/acl/scoped", &admin,
        json!({"policy":"path \"sys/external-keys/configs/remote/keys/v1\" { capabilities = [\"deny\"] }"})).status < 300, "policy revoke fixture");
    let withheld = service.finish_external_request(pending, result);
    assert_eq!(
        withheld.status, 403,
        "original actor survived live ACL revocation"
    );
    assert!(
        withheld.body.get("data").is_none(),
        "revoked actor received provider result"
    );
    assert_eq!(remote.calls()?, 0);
    let denied = call(
        &mut service,
        "POST",
        "sys/external-keys/configs/remote/keys/v1",
        &token,
        json!({"verify":true,"name":"remote","version":2}),
    );
    assert_eq!(denied.status, 403);
    assert_eq!(remote.calls()?, 0);
    Ok(())
}

#[test]
fn external_keys270_native_verification_deadline_is_retained_before_entry_and_publication()
-> TestResult {
    let remote = RemoteTransit::new()?;
    for before_entry in [true, false] {
        let (_root, mut service, _unseal, admin) = remote.fixture()?;
        let identity = service
            .current_state_identity()
            .map_err(|r| format!("identity {}", r.status))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let pending = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
            pending_mapping(&mut service, &admin)?
        };
        let result = if before_entry {
            std::thread::sleep(
                deadline.saturating_duration_since(std::time::Instant::now())
                    + std::time::Duration::from_millis(10),
            );
            pending.execute()
        } else {
            let result = pending.execute();
            std::thread::sleep(
                deadline.saturating_duration_since(std::time::Instant::now())
                    + std::time::Duration::from_millis(10),
            );
            result
        };
        let withheld = service.finish_external_request(pending, result);
        assert_eq!(
            withheld.status, 503,
            "expired original deadline published verification"
        );
        assert!(
            service
                .current_state_identity()
                .is_ok_and(|current| current == identity),
            "deadline rejection changed authoritative state"
        );
        assert_eq!(remote.calls()?, 0);
    }
    Ok(())
}
