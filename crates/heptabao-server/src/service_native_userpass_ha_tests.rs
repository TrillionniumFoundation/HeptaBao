//! Normal NativeV6Raft Userpass, actual three-node OpenRaft and pinned peer TLS.
//! Service::handle is the public dispatcher; no public HTTPS listener or
//! physical-host failure qualification is claimed by these process-local tests.
use super::formal_fixture::FormalPipeline as UserpassPipeline;
use super::*;
use crate::configuration::NativeStorageProfile;

fn userpass_account(pipeline: &UserpassPipeline, node: usize) -> TestResult {
    expect(
        pipeline.call(
            node,
            "POST",
            "sys/auth/up",
            pipeline.admin(),
            json!({"type":"userpass"}),
        )?,
        204,
        "formal-HA-Userpass-mount",
    )?;
    expect(
        pipeline.call(
            node,
            "POST",
            "sys/policies/acl/ha-up",
            pipeline.admin(),
            json!({"policy":"path \"secret/data/pipeline/history\" { capabilities = [\"read\"] }"}),
        )?,
        204,
        "formal-HA-Userpass-policy",
    )?;
    expect(
        pipeline.call(
            node,
            "POST",
            "auth/up/users/alice",
            pipeline.admin(),
            json!({
                "password":"ha-native-userpass-synthetic-password", "policies":["ha-up"],
                "token_ttl":120,"token_max_ttl":600,
            }),
        )?,
        204,
        "formal-HA-Userpass-account",
    )?;
    Ok(())
}

fn userpass_login(pipeline: &UserpassPipeline, node: usize) -> TestResult<Zeroizing<String>> {
    let mut response = expect(
        pipeline.call(
            node,
            "POST",
            "auth/up/login/alice",
            "",
            json!({
                "password":"ha-native-userpass-synthetic-password",
            }),
        )?,
        200,
        "formal-HA-actual-Userpass-login",
    )?;
    assert_eq!(response.body["auth"]["metadata"]["username"], "alice");
    let token = secret_field(&mut response, "/auth/client_token")?;
    erase_json(&mut response.body);
    Ok(token)
}

fn userpass_read(pipeline: &UserpassPipeline, node: usize, token: &str) -> TestResult {
    let response = expect(
        pipeline.call(
            node,
            "GET",
            "secret/data/pipeline/history",
            token,
            json!({"version":1}),
        )?,
        200,
        "formal-HA-Userpass-authorized-read",
    )?;
    assert_eq!(response.body["data"]["metadata"]["version"], 1);
    assert!(response.body["data"]["data"]["value"].as_str() == Some("seed-v5"));
    let denied = expect(
        pipeline.call(
            node,
            "POST",
            "secret/data/pipeline/history",
            token,
            json!({"options":{"cas":1},"data":{"value":"must-not-write"}}),
        )?,
        403,
        "formal-HA-Userpass-ACL-stays-read-only",
    )?;
    assert!(denied.body.get("data").is_none());
    Ok(())
}

#[test]
fn formal_native_userpass_ha_forwarded_issuance_election_cold_provenance_and_revoke() -> TestResult
{
    let mut pipeline = UserpassPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    userpass_account(&pipeline, follower)?;
    let token = userpass_login(&pipeline, follower)?;
    let first_lookup = expect(
        pipeline.call(follower, "GET", "auth/token/lookup-self", &token, json!({}))?,
        200,
        "formal-HA-Userpass-first-provenance",
    )?;
    assert_eq!(first_lookup.body["data"]["meta"]["username"], "alice");
    assert_eq!(first_lookup.body["data"]["creation_ttl"], 120);
    let creation_time = first_lookup.body["data"]["creation_time"]
        .as_u64()
        .ok_or("HA Userpass creation time")?;
    userpass_read(&pipeline, follower, &token)?;

    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    let renewed = expect(
        pipeline.call(
            next,
            "POST",
            "auth/token/renew-self",
            &token,
            json!({"increment":"180s"}),
        )?,
        200,
        "formal-HA-Userpass-renew-on-new-leader",
    )?;
    assert!(renewed.body["auth"]["client_token"].as_str() == Some(token.as_str()));
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    userpass_read(&pipeline, first, &token)?;
    let cold = expect(
        pipeline.call(first, "GET", "auth/token/lookup-self", &token, json!({}))?,
        200,
        "formal-HA-Userpass-cold-provenance",
    )?;
    assert_eq!(cold.body["data"]["meta"]["username"], "alice");
    assert_eq!(cold.body["data"]["creation_ttl"], 120);
    assert_eq!(cold.body["data"]["creation_time"], creation_time);
    pipeline.with_service(first, |service| {
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(service.native_candidate_profile.is_none());
        let auth = &service.state.as_ref().ok_or("HA Userpass state")?.auth;
        assert!(auth.has_userpass_issuance_state());
        assert!(auth.validate_userpass_native_tokens().is_ok());
        Ok(())
    })?;
    expect(
        pipeline.call(first, "POST", "auth/token/revoke-self", &token, json!({}))?,
        204,
        "formal-HA-Userpass-actual-forwarded-revocation",
    )?;
    pipeline.stop_process(first)?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    let denied = expect(
        pipeline.call(
            first,
            "GET",
            "secret/data/pipeline/history",
            &token,
            json!({}),
        )?,
        403,
        "formal-HA-cold-Userpass-token-stays-revoked",
    )?;
    assert!(denied.body.get("data").is_none());
    pipeline.assert_history(first, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn formal_native_userpass_ha_lost_actual_quorum_cannot_issue_a_credential() -> TestResult {
    let mut pipeline = UserpassPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    userpass_account(&pipeline, leader)?;
    let token = userpass_login(&pipeline, leader)?;
    userpass_read(&pipeline, leader, &token)?;
    let before = pipeline.with_service(leader, |service| {
        service
            .current_state_identity()
            .map_err(|_| "HA Userpass identity".into())
    })?;
    for index in (0..3).filter(|index| *index != leader) {
        pipeline.stop_process(index)?;
    }
    let denied = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/up/login/alice",
            "",
            json!({
                "password":"ha-native-userpass-synthetic-password",
            }),
        )?,
        503,
        "formal-HA-no-quorum-Userpass-issuance-veto",
    )?;
    assert!(denied.body.get("auth").is_none());
    assert!(denied.body.get("data").is_none());
    assert!(denied.consistency_index.is_none());
    pipeline.with_service(leader, |service| {
        assert!(service.current_state_identity().map_err(|_| "identity")? == before);
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    Ok(())
}

#[path = "service_native_userpass_batch_ha_tests.rs"]
mod batch_tests;

#[path = "service_native_batch_issuer_ha_tests.rs"]
mod batch_issuer_tests;
