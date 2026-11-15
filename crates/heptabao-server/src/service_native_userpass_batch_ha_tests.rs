//! Normal Raft storage, real peer TLS, actual elections and cold batch grants.
//! This module reuses the normal startup wrapper, not a fixture candidate.
use super::*;

#[derive(Eq, PartialEq)]
struct BatchObservation {
    services: usize,
    authority: [u8; 32],
    namespace: [u8; 32],
}

fn observation(pipeline: &UserpassPipeline, index: usize) -> TestResult<BatchObservation> {
    pipeline.with_service(index, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        assert!(service.native_root.is_some() && service.record_root.is_none());
        let state = service.state.as_ref().ok_or("HA batch state")?;
        state
            .validate_namespace_batch_state()
            .map_err(|_| "paired HA lifecycle")?;
        let registry = state
            .auth
            .namespace_batch_registry()
            .ok_or("actual HA batch registry")?;
        assert!(registry.native_v6_flat_catalog_profile());
        assert_eq!(registry.current_incarnation(""), Some(0));
        let encoded = owner_store::serialize_owner(&state.auth).map_err(|_| "HA Auth owner")?;
        let mut auth: Value = serde_json::from_slice(&encoded)?;
        let result = (|| -> TestResult<BatchObservation> {
            let services = auth
                .get("tokens")
                .and_then(Value::as_object)
                .ok_or("HA service token records")?
                .len();
            let authority = auth
                .get("batch_authority")
                .filter(|v| !v.is_null())
                .ok_or("actual HA batch authority")?;
            let authority = Zeroizing::new(serde_json::to_vec(authority)?);
            let namespace = owner_store::serialize_owner(&state.namespaces)
                .map_err(|_| "HA Namespace owner")?;
            Ok(BatchObservation {
                services,
                authority: crypto::digest(&authority),
                namespace: crypto::digest(&namespace),
            })
        })();
        erase_json(&mut auth);
        result
    })
}

fn batch_account(pipeline: &UserpassPipeline, index: usize) -> TestResult {
    userpass_account(pipeline, index)?;
    expect(
        pipeline.call(
            index,
            "POST",
            "auth/up/users/alice",
            pipeline.admin(),
            json!({
                "password":"ha-native-userpass-synthetic-password","policies":["ha-up"],
                "token_type":"batch","token_ttl":120,"token_max_ttl":600,"token_num_uses":0,
            }),
        )?,
        204,
        "formal-HA-batch-account",
    )?;
    Ok(())
}

fn batch_login(pipeline: &UserpassPipeline, index: usize) -> TestResult<Zeroizing<String>> {
    let mut response = expect(
        pipeline.call(
            index,
            "POST",
            "auth/up/login/alice",
            "",
            json!({
                "password":"ha-native-userpass-synthetic-password",
            }),
        )?,
        200,
        "formal-HA-actual-batch-login",
    )?;
    assert_eq!(response.body["auth"]["token_type"], "batch");
    assert_eq!(response.body["auth"]["metadata"]["username"], "alice");
    assert_eq!(response.body["auth"]["accessor"], "");
    assert_eq!(response.body["auth"]["renewable"], false);
    let token = secret_field(&mut response, "/auth/client_token")?;
    erase_json(&mut response.body);
    Ok(token)
}

fn lifetime(pipeline: &UserpassPipeline, index: usize, token: &str) -> TestResult<(u64, u64)> {
    let response = expect(
        pipeline.call(index, "GET", "auth/token/lookup-self", token, json!({}))?,
        200,
        "formal-HA-actual-batch-lifetime",
    )?;
    assert_eq!(response.body["data"]["type"], "batch");
    assert_eq!(response.body["data"]["meta"]["username"], "alice");
    assert_eq!(response.body["data"]["renewable"], false);
    let created = response.body["data"]["creation_time"]
        .as_u64()
        .ok_or("HA batch issue time")?;
    let expires = response.body["data"]["expire_time_unix"]
        .as_u64()
        .ok_or("HA batch expiry")?;
    assert_eq!(expires.checked_sub(created), Some(120));
    Ok((created, expires))
}

#[test]
fn formal_native_userpass_batch_ha_first_issuance_election_cold_and_current_policy() -> TestResult {
    let mut pipeline = UserpassPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    batch_account(&pipeline, follower)?;
    let service_records = pipeline.with_service(first, |service| {
        let state = service.state.as_ref().ok_or("source HA state")?;
        assert!(!state.has_namespace_batch_state());
        let bytes = owner_store::serialize_owner(&state.auth).map_err(|_| "source Auth")?;
        let mut value: Value = serde_json::from_slice(&bytes)?;
        let count = value
            .get("tokens")
            .and_then(Value::as_object)
            .map(|v| v.len());
        erase_json(&mut value);
        count.ok_or_else(|| "actual source services".into())
    })?;
    let token = batch_login(&pipeline, follower)?;
    let grant = lifetime(&pipeline, follower, &token)?;
    userpass_read(&pipeline, follower, &token)?;
    let admitted = observation(&pipeline, first)?;
    assert_eq!(admitted.services, service_records);
    expect(
        pipeline.call(
            follower,
            "POST",
            "auth/token/renew-self",
            &token,
            json!({"increment":"180s"}),
        )?,
        400,
        "formal-HA-batch-is-not-renewable",
    )?;
    expect(
        pipeline.call(
            follower,
            "POST",
            "auth/token/revoke-self",
            &token,
            json!({}),
        )?,
        400,
        "formal-HA-batch-has-no-service-revocation",
    )?;

    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, first);
    assert_eq!(lifetime(&pipeline, next, &token)?, grant);
    userpass_read(&pipeline, next, &token)?;
    assert!(observation(&pipeline, next)? == admitted);
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    assert_eq!(lifetime(&pipeline, first, &token)?, grant);
    userpass_read(&pipeline, first, &token)?;
    assert!(observation(&pipeline, first)? == admitted);
    expect(
        pipeline.call(
            first,
            "POST",
            "sys/policies/acl/ha-up",
            pipeline.admin(),
            json!({
                "policy":"path \"secret/data/pipeline/history\" { capabilities = [\"deny\"] }"
            }),
        )?,
        204,
        "formal-HA-withdraw-current-batch-policy",
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
            json!({"version":1}),
        )?,
        403,
        "formal-HA-cold-batch-honors-current-policy",
    )?;
    assert!(denied.body.get("data").is_none());
    assert!(observation(&pipeline, first)? == admitted);
    pipeline.assert_history(first, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn formal_native_userpass_batch_ha_lost_quorum_cannot_install_first_lifecycle_or_reply()
-> TestResult {
    let mut pipeline = UserpassPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    batch_account(&pipeline, leader)?;
    let original = pipeline.with_service(leader, |service| {
        assert!(
            !service
                .state
                .as_ref()
                .ok_or("source state")?
                .has_namespace_batch_state()
        );
        service
            .current_state_identity()
            .map_err(|_| "source native identity".into())
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
        "formal-HA-no-quorum-first-batch-issuance",
    )?;
    assert!(denied.body.get("auth").is_none() && denied.body.get("data").is_none());
    assert!(denied.consistency_index.is_none());
    pipeline.with_service(leader, |service| {
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "native identity")?
                == original
        );
        assert!(
            !service
                .state
                .as_ref()
                .ok_or("retained source")?
                .has_namespace_batch_state()
        );
        assert!(service.pending_native_auth_delivery.is_none());
        Ok(())
    })?;
    Ok(())
}
