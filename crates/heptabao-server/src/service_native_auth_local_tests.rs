//! Real native batch issuer custody agrees with the admitted AppRole login.
//! The trusted embedder peer below is not a public body/header override.
use super::*;

fn peer_call(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    peer: std::net::IpAddr,
) -> Response {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let response = service
        .handle_request(ServiceRequest::new(method, path, "", token, body).with_origin_peer(peer));
    assert!(service.pending_native_auth_delivery.is_none());
    response
}

fn strict_batch_partition(local: bool) -> TestResult {
    let (files, mut service, key, admin) = activated()?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/native-authbus",
            &admin,
            json!({"policy":POLICY})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("sys/auth/{MOUNT}"),
            &admin,
            json!({"type":"approle"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            ROLE,
            &admin,
            json!({
                "token_policies":["native-authbus"],
                "token_no_default_policy":true,
                "token_ttl":"10m",
                "token_max_ttl":"20m",
                "secret_id_ttl":"10m",
                "secret_id_num_uses":1,
                "token_type":"batch",
                "local_secret_ids":local,
                "token_strictly_bind_ip":true,
            })
        )
        .status,
        204
    );
    assert_partition(&mut service, &admin, local)?;
    let mut role = call(
        &mut service,
        "GET",
        &format!("{ROLE}/role-id"),
        &admin,
        json!({}),
    );
    assert_eq!(role.status, 200);
    let role_id = secret_field(&mut role, "/data/role_id")?;
    let secret_id = issue_secret_id(&mut service, &admin)?;
    let peer = std::net::IpAddr::from([127, 0, 0, 1]);
    let foreign = std::net::IpAddr::from([127, 0, 0, 2]);
    let mut issued = peer_call(
        &mut service,
        "POST",
        LOGIN,
        "",
        json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()}),
        peer,
    );
    // Without the issuer's strict-IP projection this actual native operation
    // fails after domain login, when its sealed claims are checked for delivery.
    assert_eq!(issued.status, 200);
    assert_eq!(issued.body["auth"]["token_type"], "batch");
    assert_eq!(issued.body["auth"]["renewable"], false);
    assert!(
        issued.body["auth"]["entity_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    let token = secret_field(&mut issued, "/auth/client_token")?;
    assert!(token.starts_with("hvb."));
    assert_consumed(&mut service, &role_id, &secret_id);

    let mut lookup = peer_call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
        peer,
    );
    assert_eq!(lookup.status, 200);
    // A single-address sockaddr is canonically rendered without /32. The
    // different and absent peer refusals below still prove the strict binding.
    assert_eq!(lookup.body["data"]["bound_cidrs"], json!(["127.0.0.1"]));
    erase_json(&mut lookup.body);
    assert_eq!(
        peer_call(
            &mut service,
            "POST",
            SECRET,
            &token,
            json!({"options":{"cas":0},"data":{"synthetic":"strict-native"}}),
            peer
        )
        .status,
        200
    );
    let denied = peer_call(&mut service, "GET", SECRET, &token, json!({}), foreign);
    assert_eq!(denied.status, 403);
    assert!(denied.body.get("data").is_none());
    assert_eq!(
        call(&mut service, "GET", SECRET, &token, json!({})).status,
        403
    );
    drop(service);

    let mut service = reopened(&files, &key)?;
    assert_partition(&mut service, &admin, local)?;
    assert_consumed(&mut service, &role_id, &secret_id);
    let persisted = peer_call(&mut service, "GET", SECRET, &token, json!({}), peer);
    assert_eq!(persisted.status, 200);
    assert_eq!(persisted.body["data"]["data"]["synthetic"], "strict-native");
    assert_eq!(
        peer_call(&mut service, "GET", SECRET, &token, json!({}), foreign).status,
        403
    );
    assert_eq!(
        peer_call(
            &mut service,
            "POST",
            SECRET,
            &token,
            json!({"options":{"cas":1},"data":{"synthetic":"strict-after-reopen"}}),
            peer
        )
        .status,
        200
    );
    assert!(!service.recovery_required);
    assert!(!service.audit_failed);
    Ok(())
}

#[test]
fn native_approle141_global_strict_ip_batch_issuer_matches_real_login_and_cold_reopen() -> TestResult
{
    strict_batch_partition(false)
}

#[test]
fn native_approle142_local_strict_ip_batch_issuer_matches_real_login_and_cold_reopen() -> TestResult
{
    strict_batch_partition(true)
}
