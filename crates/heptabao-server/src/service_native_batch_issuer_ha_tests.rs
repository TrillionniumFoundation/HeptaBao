//! Real three-node OpenRaft, peer TLS, original request/lock budgets, actual
//! forwarded issuer calls, process election and cold metadata/read-index reopen.
use super::*;
use crate::service::native_auth::batch_issuer_test_observer::after_audit;
use std::sync::atomic::{AtomicBool, Ordering};

fn call_ok(
    p: &UserpassPipeline,
    index: usize,
    method: &str,
    path: &str,
    actor: &str,
    body: Value,
    code: u16,
) -> TestResult<Response> {
    expect(
        p.call(index, method, path, actor, body)?,
        code,
        "native-typed-batch-HA",
    )
}

fn grant(mut response: Response) -> TestResult<Zeroizing<String>> {
    assert_eq!(response.body["auth"]["token_type"], "batch");
    assert_eq!(response.body["auth"]["accessor"], "");
    assert_eq!(response.body["auth"]["renewable"], false);
    let token = secret_field(&mut response, "/auth/client_token")?;
    erase_json(&mut response.body);
    Ok(token)
}

fn no_private(response: &Response) {
    assert!(response.body.get("auth").is_none());
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("wrap_info").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
}

fn count(p: &UserpassPipeline, index: usize, require_paired: bool) -> TestResult<usize> {
    p.with_service(index, |service| {
        assert!(matches!(
            service.native_storage_profile,
            Some(NativeStorageProfile::Raft)
        ));
        assert!(service.native_candidate_profile.is_none());
        assert!(service.native_root.is_some() && service.record_root.is_none());
        let state = service.state.as_ref().ok_or("actual native state")?;
        if require_paired {
            state
                .validate_namespace_batch_state()
                .map_err(|_| "actual paired lifecycle")?;
            let registry = state
                .auth
                .namespace_batch_registry()
                .ok_or("actual registry")?;
            assert!(registry.native_v6_flat_catalog_profile());
            assert_eq!(registry.current_incarnation(""), Some(0));
        }
        let raw = owner_store::serialize_owner(&state.auth).map_err(|_| "Auth owner")?;
        let mut body: Value = serde_json::from_slice(&raw)?;
        let result = body["tokens"].as_object().map(|tokens| tokens.len());
        erase_json(&mut body);
        result.ok_or_else(|| "actual service count".into())
    })
}

fn approle(
    p: &UserpassPipeline,
    index: usize,
) -> TestResult<(Zeroizing<String>, Zeroizing<String>)> {
    userpass_account(p, index)?;
    call_ok(
        p,
        index,
        "POST",
        "sys/auth/nb",
        p.admin(),
        json!({"type":"approle"}),
        204,
    )?;
    call_ok(
        p,
        index,
        "POST",
        "auth/nb/role/issuer",
        p.admin(),
        json!({
            "bind_secret_id":true,"token_type":"batch","token_policies":["ha-up"],
            "token_ttl":"120s","token_max_ttl":"600s","secret_id_ttl":"300s","secret_id_num_uses":2,
        }),
        204,
    )?;
    let mut role = call_ok(
        p,
        index,
        "GET",
        "auth/nb/role/issuer/role-id",
        p.admin(),
        json!({}),
        200,
    )?;
    let role_id = secret_field(&mut role, "/data/role_id")?;
    erase_json(&mut role.body);
    let mut sid = call_ok(
        p,
        index,
        "POST",
        "auth/nb/role/issuer/secret-id",
        p.admin(),
        json!({}),
        200,
    )?;
    let secret_id = secret_field(&mut sid, "/data/secret_id")?;
    erase_json(&mut sid.body);
    Ok((role_id, secret_id))
}

fn login(
    p: &UserpassPipeline,
    index: usize,
    role: &str,
    sid: &str,
    code: u16,
) -> TestResult<Response> {
    call_ok(
        p,
        index,
        "POST",
        "auth/nb/login",
        "",
        json!({"role_id":role,"secret_id":sid}),
        code,
    )
}

fn lifetime(p: &UserpassPipeline, index: usize, token: &str) -> TestResult<(u64, u64)> {
    let mut response = call_ok(
        p,
        index,
        "GET",
        "auth/token/lookup-self",
        token,
        json!({}),
        200,
    )?;
    assert_eq!(response.body["data"]["type"], "batch");
    assert_eq!(response.body["data"]["num_uses"], 0);
    let created = response.body["data"]["creation_time"]
        .as_u64()
        .ok_or("creation")?;
    let expires = response.body["data"]["expire_time_unix"]
        .as_u64()
        .ok_or("expiry")?;
    erase_json(&mut response.body);
    Ok((created, expires))
}

fn issuer(p: &UserpassPipeline, index: usize) -> TestResult<Zeroizing<String>> {
    userpass_account(p, index)?;
    call_ok(
        p,
        index,
        "POST",
        "sys/policies/acl/ha-batch-issuer",
        p.admin(),
        json!({
            "policy":"path \"auth/token/create*\" { capabilities = [\"update\"] }",
        }),
        204,
    )?;
    let mut response = call_ok(
        p,
        index,
        "POST",
        "auth/token/create",
        p.admin(),
        json!({
            "policies":["ha-up","ha-batch-issuer"],"no_default_policy":true,"ttl":"600s",
        }),
        200,
    )?;
    let token = secret_field(&mut response, "/auth/client_token")?;
    erase_json(&mut response.body);
    Ok(token)
}

fn token_batch(
    p: &UserpassPipeline,
    index: usize,
    parent: &str,
    code: u16,
) -> TestResult<Response> {
    call_ok(
        p,
        index,
        "POST",
        "auth/token/create",
        parent,
        json!({
            "type":"batch","policies":["ha-up"],"no_default_policy":true,"ttl":"120s",
        }),
        code,
    )
}

#[test]
fn formal_native_batch_approle_ha_forwarded_sid_once_election_cold() -> TestResult {
    let mut p = UserpassPipeline::start()?;
    let first = p.ready_leader()?;
    let follower = (first + 1) % 3;
    let (role, sid) = approle(&p, follower)?;
    let services = count(&p, first, false)?;
    let token = grant(login(&p, follower, &role, &sid, 200)?)?;
    let original = lifetime(&p, follower, &token)?;
    assert_eq!(original.1 - original.0, 120);
    userpass_read(&p, follower, &token)?;
    assert_eq!(count(&p, first, true)?, services);
    let mut lookup = call_ok(
        &p,
        follower,
        "POST",
        "auth/nb/role/issuer/secret-id/lookup",
        p.admin(),
        json!({"secret_id":sid.as_str()}),
        200,
    )?;
    assert_eq!(lookup.body["data"]["secret_id_num_uses"], 1);
    erase_json(&mut lookup.body);
    p.stop_process(first)?;
    let next = p.ready_leader()?;
    assert_ne!(next, first);
    assert_eq!(lifetime(&p, next, &token)?, original);
    let second = grant(login(&p, next, &role, &sid, 200)?)?;
    assert!(second.as_str() != token.as_str());
    no_private(&login(&p, next, &role, &sid, 400)?);
    assert_eq!(count(&p, next, true)?, services);
    p.start_formal_process(first)?;
    p.wait_cold_native_readindex_ready(first)?;
    p.unseal(first)?;
    assert_eq!(lifetime(&p, first, &token)?, original);
    userpass_read(&p, first, &token)?;
    userpass_read(&p, first, &second)?;
    no_private(&login(&p, first, &role, &sid, 400)?);
    assert_eq!(count(&p, first, true)?, services);
    Ok(())
}

#[test]
fn formal_native_batch_token_api_ha_forwarded_election_parent_revoke_cold() -> TestResult {
    let mut p = UserpassPipeline::start()?;
    let first = p.ready_leader()?;
    let follower = (first + 1) % 3;
    userpass_account(&p, follower)?;
    call_ok(
        &p,
        follower,
        "POST",
        "sys/policies/acl/ha-batch-issuer",
        p.admin(),
        json!({"policy":"path \"auth/token/create*\" { capabilities = [\"update\"] }"}),
        204,
    )?;
    call_ok(
        &p,
        follower,
        "POST",
        "sys/policies/acl/ha-batch-self-lookup",
        p.admin(),
        json!({"policy":"path \"auth/token/lookup-self\" { capabilities = [\"read\"] }"}),
        204,
    )?;
    let mut response = call_ok(
        &p,
        follower,
        "POST",
        "auth/token/create",
        p.admin(),
        json!({
            "policies":["ha-up","ha-batch-issuer","ha-batch-self-lookup"],
            "no_default_policy":true,"ttl":"600s",
        }),
        200,
    )?;
    let parent = secret_field(&mut response, "/auth/client_token")?;
    erase_json(&mut response.body);
    let services = count(&p, first, false)?;
    let token = grant(call_ok(
        &p,
        follower,
        "POST",
        "auth/token/create",
        &parent,
        json!({
            "type":"batch","policies":["ha-up","ha-batch-self-lookup"],
            "no_default_policy":true,"ttl":"120s",
        }),
        200,
    )?)?;
    let original = lifetime(&p, follower, &token)?;
    assert_eq!(original.1 - original.0, 120);
    userpass_read(&p, follower, &token)?;
    assert_eq!(count(&p, first, true)?, services);
    p.stop_process(first)?;
    let next = p.ready_leader()?;
    assert_ne!(next, first);
    assert_eq!(lifetime(&p, next, &token)?, original);
    userpass_read(&p, next, &token)?;
    call_ok(
        &p,
        next,
        "POST",
        "auth/token/revoke",
        p.admin(),
        json!({"token":parent.as_str()}),
        204,
    )?;
    no_private(&call_ok(
        &p,
        next,
        "GET",
        "secret/data/pipeline/history",
        &token,
        json!({"version":1}),
        403,
    )?);
    p.start_formal_process(first)?;
    p.wait_cold_native_readindex_ready(first)?;
    p.unseal(first)?;
    no_private(&call_ok(
        &p,
        first,
        "GET",
        "secret/data/pipeline/history",
        &token,
        json!({"version":1}),
        403,
    )?);
    no_private(&token_batch(&p, first, &parent, 403)?);
    count(&p, first, true)?;
    Ok(())
}

#[test]
fn formal_native_batch_ha_actual_audit_parent_revoke_vetoes_original_response() -> TestResult {
    let p = UserpassPipeline::start()?;
    let leader = p.ready_leader()?;
    let parent = issuer(&p, leader)?;
    let admin = Zeroizing::new(p.admin().to_owned());
    let revoke = Zeroizing::new(parent.as_str().to_owned());
    let observed = Arc::new(AtomicBool::new(false));
    let observed_hook = Arc::clone(&observed);
    let captured = Arc::new(Mutex::new(None::<Zeroizing<String>>));
    let captured_hook = Arc::clone(&captured);
    let _hook = after_audit(move |service, response| {
        assert!(response.status == 200 && response.body["auth"]["token_type"] == "batch");
        observed_hook.store(true, Ordering::SeqCst);
        let capture_result = (|| -> TestResult {
            let token = response.body["auth"]["client_token"]
                .as_str()
                .ok_or("actual grant")?;
            *captured_hook.lock().map_err(|_| "captured test bearer")? =
                Some(Zeroizing::new(token.to_owned()));
            Ok(())
        })();
        assert!(capture_result.is_ok(), "capture actual audited batch");
        let changed = service.handle(
            "POST",
            "auth/token/revoke",
            "",
            &admin,
            json!({"token":revoke.as_str()}),
        );
        assert_eq!(changed.status, 204);
    })?;
    let response = token_batch(&p, leader, &parent, 503)?;
    assert!(observed.load(Ordering::SeqCst));
    no_private(&response);
    let token = captured
        .lock()
        .map_err(|_| "capture")?
        .take()
        .ok_or("actual audited grant")?;
    assert!(!response.body.to_string().contains(token.as_str()));
    for index in 0..3 {
        no_private(&call_ok(
            &p,
            index,
            "GET",
            "secret/data/pipeline/history",
            &token,
            json!({"version":1}),
            403,
        )?);
    }
    Ok(())
}

#[test]
fn formal_native_batch_ha_missing_quorum_cannot_consume_sid_or_publish_either_issuer() -> TestResult
{
    for approle_issuer in [false, true] {
        let mut p = UserpassPipeline::start()?;
        let leader = p.ready_leader()?;
        let credentials = if approle_issuer {
            Some(approle(&p, leader)?)
        } else {
            None
        };
        let parent = if approle_issuer {
            None
        } else {
            Some(issuer(&p, leader)?)
        };
        let original = p.with_service(leader, |service| {
            assert!(
                !service
                    .state
                    .as_ref()
                    .ok_or("source")?
                    .has_namespace_batch_state()
            );
            service
                .current_state_identity()
                .map_err(|_| "source native identity".into())
        })?;
        for index in (0..3).filter(|index| *index != leader) {
            p.stop_process(index)?;
        }
        let rejected = if let Some((role, sid)) = credentials.as_ref() {
            login(&p, leader, role, sid, 503)?
        } else {
            token_batch(&p, leader, parent.as_ref().ok_or("actual issuer")?, 503)?
        };
        no_private(&rejected);
        p.with_service(leader, |service| {
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
    }
    Ok(())
}
