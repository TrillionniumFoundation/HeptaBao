//! Real normal three-node native storage and the original peer TLS/forwarding
//! path. No direct Raft intent, copied native root or fabricated proof is used.
use super::*;

fn no_output(response: &Response) {
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("auth").is_none());
    assert!(response.body.get("wrap_info").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
}

fn wrapper(response: &mut Response, path: &str) -> TestResult<Zeroizing<String>> {
    assert_eq!(response.status, 200);
    assert_eq!(response.body["wrap_info"]["creation_path"], path);
    assert!(response.body["data"].is_null());
    assert!(response.body["auth"].is_null());
    secret_field(response, "/wrap_info/token")
}

#[test]
fn formal_native_wrapping_response_ha_forwarded_cas_election_cold_exact_once() -> TestResult {
    let mut pipeline = WrappingPipeline::start()?;
    let first = pipeline.ready_leader()?;
    let follower = (first + 1) % 3;
    let path = "secret/data/composition/once";
    let mut response = expect(
        pipeline.wrapped_call(
            follower,
            "POST",
            path,
            pipeline.admin(),
            json!({"options":{"cas":0},"data":{"value":"HA-wrapped-CAS-private-value"}}),
            Some(120),
        )?,
        200,
        "formal-HA-original-CAS-with-wrapped-result",
    )?;
    let token = wrapper(&mut response, path)?;
    assert!(
        !response
            .body
            .to_string()
            .contains("HA-wrapped-CAS-private-value")
    );
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(first, next);
    let value = expect(
        pipeline.call(next, "GET", path, pipeline.admin(), json!({}))?,
        200,
        "formal-HA-committed-CAS-after-election",
    )?;
    assert_eq!(value.body["data"]["metadata"]["version"], 1);
    assert_eq!(
        value.body["data"]["data"]["value"],
        "HA-wrapped-CAS-private-value"
    );
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    let result = expect(
        pipeline.call(first, "POST", "sys/wrapping/unwrap", &token, json!({}))?,
        200,
        "formal-HA-cold-wrapped-CAS-result",
    )?;
    assert_eq!(result.body["data"]["version"], 1);
    assert!(result.unwrapped_json.is_some());
    pipeline.stop_process(first)?;
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    let denied = expect(
        pipeline.call(first, "POST", "sys/wrapping/unwrap", &token, json!({}))?,
        400,
        "formal-HA-cold-consumed-wrapper-does-not-reexecute-CAS",
    )?;
    no_output(&denied);
    let value = expect(
        pipeline.call(first, "GET", path, pipeline.admin(), json!({}))?,
        200,
        "formal-HA-exact-single-CAS-version",
    )?;
    assert_eq!(value.body["data"]["metadata"]["version"], 1);
    pipeline.assert_history(first, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn formal_native_wrapping_response_ha_approle_failed_wrapper_consumption_and_cold_success()
-> TestResult {
    let mut pipeline = WrappingPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let follower = (leader + 1) % 3;
    expect(
        pipeline.call(
            follower,
            "POST",
            "sys/auth/compose",
            pipeline.admin(),
            json!({"type":"approle"}),
        )?,
        204,
        "formal-HA-AppRole-mount",
    )?;
    expect(
        pipeline.call(
            follower,
            "POST",
            "auth/compose/role/once",
            pipeline.admin(),
            json!({
                "token_policies":["default"],"token_ttl":"300s","token_max_ttl":"600s",
                "secret_id_ttl":"600s","secret_id_num_uses":1,
            }),
        )?,
        204,
        "formal-HA-finite-SID-role",
    )?;
    let mut response = expect(
        pipeline.call(
            follower,
            "GET",
            "auth/compose/role/once/role-id",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-HA-actual-role-ID",
    )?;
    let role = secret_field(&mut response, "/data/role_id")?;
    let mut response = expect(
        pipeline.wrapped_call(
            follower,
            "POST",
            "auth/compose/role/once/secret-id",
            pipeline.admin(),
            json!({}),
            Some(120),
        )?,
        200,
        "formal-HA-wrapped-actual-SID-issuance",
    )?;
    let secret_wrapper = wrapper(&mut response, "auth/compose/role/once/secret-id")?;
    let mut response = expect(
        pipeline.call(
            follower,
            "POST",
            "sys/wrapping/unwrap",
            &secret_wrapper,
            json!({}),
        )?,
        200,
        "formal-HA-actual-SID-unwrapped-once",
    )?;
    let secret = secret_field(&mut response, "/data/secret_id")?;
    let body = json!({"role_id":role.as_str(),"secret_id":secret.as_str()});
    let mut response = expect(
        pipeline.wrapped_call(
            follower,
            "POST",
            "auth/compose/login",
            "",
            body.clone(),
            Some(120),
        )?,
        200,
        "formal-HA-actual-SID-consumption-and-token-wrapper",
    )?;
    let login_wrapper = wrapper(&mut response, "auth/compose/login")?;
    expect(
        pipeline.call(follower, "POST", "auth/compose/login", "", body.clone())?,
        400,
        "formal-HA-original-SID-is-spent-before-wrapper-delivery",
    )?;
    pipeline.stop_process(leader)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(next, leader);
    pipeline.start_formal_process(leader)?;
    pipeline.wait_cold_native_readindex_ready(leader)?;
    pipeline.unseal(leader)?;
    expect(
        pipeline.call(leader, "POST", "auth/compose/login", "", body)?,
        400,
        "formal-HA-cold-SID-consumption-persists",
    )?;
    let mut response = expect(
        pipeline.call(
            leader,
            "POST",
            "sys/wrapping/unwrap",
            &login_wrapper,
            json!({}),
        )?,
        200,
        "formal-HA-cold-actual-issued-token",
    )?;
    let token = secret_field(&mut response, "/auth/client_token")?;
    expect(
        pipeline.call(leader, "GET", "auth/token/lookup-self", &token, json!({}))?,
        200,
        "formal-HA-unwrapped-issued-token-accepted",
    )?;
    let denied = expect(
        pipeline.call(
            leader,
            "POST",
            "sys/wrapping/unwrap",
            &login_wrapper,
            json!({}),
        )?,
        400,
        "formal-HA-issued-token-wrapper-single-use",
    )?;
    no_output(&denied);
    expect(
        pipeline.call(
            leader,
            "POST",
            "auth/compose/role/once",
            pipeline.admin(),
            json!({
                "token_policies":["default"],"token_ttl":"300s","token_max_ttl":"600s",
                "secret_id_ttl":"600s","secret_id_num_uses":2,
            }),
        )?,
        204,
        "formal-HA-two-use-SID-role",
    )?;
    let metadata = json!({"large":"x".repeat(70*1024)}).to_string();
    assert!(metadata.len() > 64 * 1024 && metadata.len() < crate::login_metadata::MAX_BYTES);
    let mut response = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/compose/role/once/secret-id",
            pipeline.admin(),
            json!({"metadata":metadata}),
        )?,
        200,
        "formal-HA-valid-large-SID-metadata",
    )?;
    let secret = secret_field(&mut response, "/data/secret_id")?;
    let body = json!({"role_id":role.as_str(),"secret_id":secret.as_str()});
    let before = expect(
        pipeline.call(
            leader,
            "LIST",
            "auth/token/accessors",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-HA-original-issued-token-set",
    )?
    .body["data"]["keys"]
        .clone();
    let rejected = expect(
        pipeline.wrapped_call(
            leader,
            "POST",
            "auth/compose/login",
            "",
            body.clone(),
            Some(120),
        )?,
        413,
        "formal-HA-actual-login-then-wrapper-size-rejection",
    )?;
    no_output(&rejected);
    assert_eq!(
        rejected.body["errors"][0],
        "wrapped response exceeds supported bounds"
    );
    let after = expect(
        pipeline.call(
            leader,
            "LIST",
            "auth/token/accessors",
            pipeline.admin(),
            json!({}),
        )?,
        200,
        "formal-HA-rejected-issued-token-is-not-published",
    )?
    .body["data"]["keys"]
        .clone();
    assert!(before == after);
    pipeline.stop_process(leader)?;
    pipeline.start_formal_process(leader)?;
    pipeline.wait_cold_native_readindex_ready(leader)?;
    pipeline.unseal(leader)?;
    let mut response = expect(
        pipeline.call(leader, "POST", "auth/compose/login", "", body.clone())?,
        200,
        "formal-HA-cold-one-SID-use-remains-after-wrapper-failure",
    )?;
    assert_eq!(
        response.body["auth"]["metadata"]["large"]
            .as_str()
            .map(str::len),
        Some(70 * 1024)
    );
    let token = secret_field(&mut response, "/auth/client_token")?;
    expect(
        pipeline.call(leader, "GET", "auth/token/lookup-self", &token, json!({}))?,
        200,
        "formal-HA-original-remaining-use-issues-valid-token",
    )?;
    expect(
        pipeline.call(leader, "POST", "auth/compose/login", "", body)?,
        400,
        "formal-HA-no-double-SID-consumption-or-rollback",
    )?;
    pipeline.assert_history(leader, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn formal_native_wrapping_response_ha_real_quorum_loss_publishes_no_half_operation() -> TestResult {
    let mut pipeline = WrappingPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let before = pipeline.with_service(leader, |service| {
        service
            .current_state_identity()
            .map_err(|_| "formal-HA-source-root".into())
    })?;
    for node in (0..3).filter(|node| *node != leader) {
        pipeline.stop_process(node)?;
    }
    let denied = expect(
        pipeline.wrapped_call(
            leader,
            "POST",
            "secret/data/composition/no-quorum",
            pipeline.admin(),
            json!({"options":{"cas":0},"data":{"value":"must-not-publish"}}),
            Some(120),
        )?,
        503,
        "formal-HA-no-quorum-no-domain-or-wrapper-publication",
    )?;
    no_output(&denied);
    pipeline.with_service(leader, |service| {
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "root identity")?
                == before
        );
        assert!(service.pending_native_auth_delivery.is_none());
        assert!(service.pending_ordinary_kv_authority.is_none());
        Ok(())
    })?;
    for node in (0..3).filter(|node| *node != leader) {
        pipeline.start_formal_process(node)?;
        pipeline.wait_cold_native_readindex_ready(node)?;
        pipeline.unseal(node)?;
    }
    let available = pipeline.ready_leader()?;
    expect(
        pipeline.call(
            available,
            "GET",
            "secret/data/composition/no-quorum",
            pipeline.admin(),
            json!({}),
        )?,
        404,
        "formal-HA-no-half-KV-after-cold-quorum-return",
    )?;
    pipeline.with_service(available, |service| {
        assert!(
            !service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .has_live_wrappers()
        );
        Ok(())
    })?;
    pipeline.assert_history(available, &[(1, "seed-v5")])?;
    Ok(())
}

#[test]
fn formal_native_wrapping_response_ha_actual_post_audit_root_change_cannot_rebind_proof()
-> TestResult {
    let pipeline = WrappingPipeline::start()?;
    let leader = pipeline.ready_leader()?;
    let follower = (leader + 1) % 3;
    let started = Instant::now();
    let until = started + REQUEST_BUDGET;
    let observed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let clock = RequestClock::anchored(observed, started)?;
    let _scope = RequestDeadlineScope::enter(until);
    let _publication = external_pki::PublicationClockScope::enter(observed, started);
    let ingress = crypto::random::<16>().map_err(std::io::Error::other)?;
    let _ingress = crate::auth::IngressReplyScope::listener(&ingress);
    let service = pipeline.services[leader]
        .as_ref()
        .ok_or("original leader Service")?;
    let mut writer = lock_until(service, until).map_err(|_| "original leader lock")?;
    let body = json!({});
    let response = expect(
        writer.handle_inner(RequestView {
            method: "GET",
            path: "secret/data/pipeline/history",
            namespace: "",
            token: pipeline.admin(),
            body: &body,
            now: observed.as_secs(),
            admission_started: started,
            token_clock: Some(clock),
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: Some(120),
            origin_peer: None,
            client_certificates: None,
        }),
        200,
        "formal-HA-actual-domain-output",
    )?;
    assert!(writer.pending_native_auth_delivery.is_none());
    let response = expect(
        writer.audit_completed_response_with_receipt(
            "formal-HA-original-composed-response-audit",
            observed.as_secs(),
            Some(clock),
            response,
            || {},
        ),
        200,
        "formal-HA-actual-response-audit-and-terminal-proof",
    )?;
    let wrapper_token = Zeroizing::new(
        response
            .body
            .pointer("/wrap_info/token")
            .and_then(Value::as_str)
            .ok_or("actual wrapper")?
            .to_owned(),
    );
    let checkpoint = writer
        .current_state_identity()
        .map_err(|_| "actual checkpoint")?;
    let original = writer
        .pending_ordinary_kv_authority
        .take()
        .ok_or("original affine KV owner")?;
    assert!(original.native_response_wrapping.is_some());
    drop(writer);
    expect(
        pipeline.call(
            follower,
            "POST",
            "secret/data/composition/after-audit",
            pipeline.admin(),
            json!({"options":{"cas":0},"data":{"value":"new-authoritative-root"}}),
        )?,
        200,
        "formal-HA-real-independent-forwarded-root-change",
    )?;
    let mut writer =
        lock_until(service, until).map_err(|_| "same original deadline leader lock")?;
    assert!(
        writer
            .current_state_identity()
            .map_err(|_| "new checkpoint")?
            != checkpoint
    );
    assert!(writer.pending_ordinary_kv_authority.is_none());
    let denied = expect(
        writer.complete_ordinary_kv_delivery(
            original,
            response,
            "formal-HA-original-composed-response-audit",
        ),
        503,
        "formal-HA-no-post-audit-proof-refresh",
    )?;
    no_output(&denied);
    assert!(started.elapsed() < REQUEST_BUDGET);
    drop(writer);
    // The original delivery authority has been consumed and its unchanged
    // deadline assertion above has completed. The two following unwraps are
    // separate public requests; retire only this finished request's scopes.
    drop(_ingress);
    drop(_publication);
    drop(_scope);
    expect(
        pipeline.call(
            follower,
            "POST",
            "sys/wrapping/unwrap",
            &wrapper_token,
            json!({}),
        )?,
        200,
        "formal-HA-veto-does-not-fabricate-rollback-of-committed-wrapper",
    )?;
    expect(
        pipeline.call(
            follower,
            "POST",
            "sys/wrapping/unwrap",
            &wrapper_token,
            json!({}),
        )?,
        400,
        "formal-HA-actual-committed-wrapper-remains-once-use",
    )?;
    Ok(())
}
