//! Normal NativeV6Raft, actual three-node OpenRaft and pinned peer TLS.
//! No public HTTPS or physical-machine qualification is implied by this suite.
use super::formal_fixture::FormalPipeline as PkiPipeline;
use super::*;
use crate::configuration::NativeStorageProfile;
use openssl::x509::{X509, X509Crl};

// SSH reuses this exact configured normal three-voter/pinned-TLS pipeline.
// Only the selected engine operations and their assertions differ.
#[path = "service_native_ssh_ha_tests.rs"]
mod ssh_tests;

#[path = "service_no_forwarding_ha_tests.rs"]
mod no_forwarding_tests;

fn pki_setup(pipeline: &PkiPipeline, node: usize) -> TestResult {
    for (path, body, status) in [
        ("sys/mounts/pki", json!({"type":"pki"}), 204),
        (
            "pki/root/generate/internal",
            json!({"common_name":"ca.example.test",
            "key_type":"ec","key_bits":256,"ttl":"48h"}),
            200,
        ),
        (
            "pki/roles/web",
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,
            "key_type":"ec","key_bits":256,"max_ttl":"2h","generate_lease":true}),
            200,
        ),
    ] {
        expect(
            pipeline.call(node, "POST", path, pipeline.admin(), body)?,
            status,
            "formal-HA-local-PKI-setup",
        )?;
    }
    Ok(())
}
fn pki_text(response: &Response, pointer: &str) -> TestResult<String> {
    response
        .body
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "HA PKI synthetic response field absent".into())
}
fn pki_issued(
    pipeline: &PkiPipeline,
    node: usize,
    actor: &str,
) -> TestResult<(String, String, String, X509, X509)> {
    let mut response = expect(
        pipeline.call(
            node,
            "POST",
            "pki/issue/web",
            actor,
            json!({"common_name":"ha.example.test","ttl":"1h"}),
        )?,
        200,
        "formal-HA-actual-PKI-issuance",
    )?;
    let certificate = pki_text(&response, "/data/certificate")?;
    let leaf = X509::from_pem(certificate.as_bytes())?;
    let issuer = X509::from_pem(pki_text(&response, "/data/issuing_ca")?.as_bytes())?;
    let issuer_key = issuer.public_key()?;
    assert!(leaf.verify(&issuer_key)?);
    let lease = pki_text(&response, "/lease_id")?;
    let serial = pki_text(&response, "/data/serial_number")?;
    assert_eq!(response.body["renewable"], false);
    assert!(response.body["data"]["private_key"].is_string());
    erase_json(&mut response.body);
    Ok((lease, serial, certificate, leaf, issuer))
}
fn pki_cold_public(
    pipeline: &PkiPipeline,
    node: usize,
    serial: &str,
    certificate: &str,
    revoked: bool,
) -> TestResult {
    let response = expect(
        pipeline.call(node, "GET", &format!("pki/cert/{serial}"), "", json!({}))?,
        200,
        "formal-HA-public-certificate-through-real-ReadIndex",
    )?;
    assert_eq!(response.body["data"]["certificate"], certificate);
    let at = response.body["data"]["revocation_time"]
        .as_u64()
        .ok_or("HA PKI revocation time")?;
    assert_eq!(at > 0, revoked);
    pipeline.with_service(node, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    pipeline.assert_history(node, &[(1, "seed-v5")])
}
fn pki_revoked_crl(pipeline: &PkiPipeline, node: usize, leaf: &X509, issuer: &X509) -> TestResult {
    let response = expect(
        pipeline.call(node, "GET", "pki/cert/crl", "", json!({}))?,
        200,
        "formal-HA-actual-durable-CRL",
    )?;
    let crl = X509Crl::from_pem(pki_text(&response, "/data/certificate")?.as_bytes())?;
    let key = issuer.public_key()?;
    assert!(crl.verify(&key)?);
    let target = leaf.serial_number().to_bn()?.to_vec();
    let mut found = false;
    if let Some(revoked) = crl.get_revoked() {
        for entry in revoked {
            found |= entry.serial_number().to_bn()?.to_vec() == target;
        }
    }
    assert!(found, "real HA CRL must contain the actual issued serial");
    Ok(())
}

#[test]
fn formal_native_pki_ha_forwarded_signing_election_cold_and_actual_crl() -> TestResult {
    let mut pipeline = PkiPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    pki_setup(&pipeline, follower)?;
    let (lease, serial, certificate, leaf, issuer) =
        pki_issued(&pipeline, follower, pipeline.admin())?;
    pki_cold_public(&pipeline, follower, &serial, &certificate, false)?;
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    expect(
        pipeline.call(
            next,
            "POST",
            "sys/leases/lookup",
            pipeline.admin(),
            json!({"lease_id":lease}),
        )?,
        200,
        "formal-HA-new-leader-PKI-lease",
    )?;
    pki_cold_public(&pipeline, next, &serial, &certificate, false)?;
    expect(
        pipeline.call(
            next,
            "POST",
            "sys/leases/revoke",
            pipeline.admin(),
            json!({"lease_id":lease}),
        )?,
        204,
        "formal-HA-original-lease-revocation",
    )?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    pki_cold_public(&pipeline, first, &serial, &certificate, true)?;
    pki_revoked_crl(&pipeline, first, &leaf, &issuer)?;
    Ok(())
}

#[test]
fn formal_native_pki_ha_batch_lease_keeps_typed_owner_across_actual_cold_election() -> TestResult {
    let mut pipeline = PkiPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    pki_setup(&pipeline, follower)?;
    for (path, body) in [
        ("sys/auth/up", json!({"type":"userpass"})),
        (
            "sys/policies/acl/pki-ha",
            json!({"policy":"path \"pki/issue/web\" { capabilities=[\"update\"] }"}),
        ),
        (
            "auth/up/users/batch",
            json!({"password":"synthetic-pki-ha-batch","policies":["pki-ha"],
            "token_type":"batch","token_ttl":120,"token_max_ttl":600,"token_num_uses":0}),
        ),
    ] {
        expect(
            pipeline.call(follower, "POST", path, pipeline.admin(), body)?,
            204,
            "formal-HA-real-batch-issuer-setup",
        )?;
    }
    let mut login = expect(
        pipeline.call(
            follower,
            "POST",
            "auth/up/login/batch",
            "",
            json!({"password":"synthetic-pki-ha-batch"}),
        )?,
        200,
        "formal-HA-real-batch-login",
    )?;
    assert_eq!(login.body["auth"]["token_type"], "batch");
    let actor = secret_field(&mut login, "/auth/client_token")?;
    erase_json(&mut login.body);
    let (lease, serial, certificate, leaf, issuer) = pki_issued(&pipeline, follower, &actor)?;
    let owner = pipeline.with_service(first, |service| {
        let state = service.state.as_ref().ok_or("HA PKI state")?;
        assert_eq!(state.schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
        let root = service.native_root.as_ref().ok_or("actual HA PKI root")?;
        assert_eq!(root.state_schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
        assert_eq!(
            root.reader_floor.minimum_state_schema,
            AUTH_SECURITY_CONTRACT_STATE_SCHEMA
        );
        state
            .validate_namespace_batch_state()
            .map_err(|_| "actual paired lifecycle")?;
        state
            .engines
            .lease_owners()
            .into_iter()
            .find(|(_, owner)| owner.batch_claims().is_some())
            .map(|(_, owner)| owner)
            .ok_or_else(|| "actual typed PKI batch owner".into())
    })?;
    let claims = owner.batch_claims().ok_or("actual batch claims")?;
    let deadline = claims.precision().map_or_else(
        || crate::engines::timestamp(claims.expires_at()),
        |value| value.expires_at.rfc3339(),
    );
    let actor_end = openssl::asn1::Asn1Time::from_unix(i64::try_from(claims.expires_at())?)?;
    assert_eq!(
        leaf.not_after().compare(&actor_end)?,
        std::cmp::Ordering::Greater
    );
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    let lookup = expect(
        pipeline.call(
            next,
            "POST",
            "sys/leases/lookup",
            pipeline.admin(),
            json!({"lease_id":lease}),
        )?,
        200,
        "formal-HA-batch-lease-survives-leader",
    )?;
    assert_eq!(lookup.body["data"]["expire_time"], deadline);
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    pki_cold_public(&pipeline, first, &serial, &certificate, false)?;
    pipeline.with_service(first, |service| {
        let state = service.state.as_ref().ok_or("cold HA PKI state")?;
        assert_eq!(state.schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
        let root = service.native_root.as_ref().ok_or("cold HA PKI root")?;
        assert_eq!(root.state_schema, AUTH_SECURITY_CONTRACT_STATE_SCHEMA);
        assert_eq!(
            root.reader_floor.minimum_state_schema,
            AUTH_SECURITY_CONTRACT_STATE_SCHEMA
        );
        state
            .validate_namespace_batch_state()
            .map_err(|_| "cold paired lifecycle")?;
        assert!(
            state
                .engines
                .lease_owners()
                .iter()
                .any(|(_, current)| current == &owner)
        );
        Ok(())
    })?;
    expect(
        pipeline.call(
            first,
            "POST",
            "sys/leases/revoke",
            pipeline.admin(),
            json!({"lease_id":lease}),
        )?,
        204,
        "formal-HA-real-batch-owned-lease-revocation",
    )?;
    pipeline.stop_process(first)?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    pki_cold_public(&pipeline, first, &serial, &certificate, true)?;
    pki_revoked_crl(&pipeline, first, &leaf, &issuer)?;
    Ok(())
}

#[test]
fn formal_native_pki_ha_lost_actual_quorum_cannot_sign_or_disclose_public_material() -> TestResult {
    let mut pipeline = PkiPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    pki_setup(&pipeline, leader)?;
    let before = pipeline.with_service(leader, |service| {
        service
            .current_state_identity()
            .map_err(|_| "PKI HA source identity".into())
    })?;
    for index in (0..3).filter(|index| *index != leader) {
        pipeline.stop_process(index)?;
    }
    for (method, path, body) in [
        (
            "POST",
            "pki/issue/web",
            json!({"common_name":"must-not-sign.example.test","ttl":"1h"}),
        ),
        ("GET", "pki/cert/ca", json!({})),
    ] {
        let response = expect(
            pipeline.call(
                leader,
                method,
                path,
                if method == "GET" {
                    ""
                } else {
                    pipeline.admin()
                },
                body,
            )?,
            503,
            "formal-HA-no-quorum-PKI-proof-veto",
        )?;
        assert!(response.body.get("data").is_none() && response.body.get("auth").is_none());
        assert!(response.consistency_index.is_none());
    }
    pipeline.with_service(leader, |service| {
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "PKI HA identity")?
                == before
        );
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    Ok(())
}
