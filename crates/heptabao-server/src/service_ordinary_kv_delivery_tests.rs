//! Actual KV admission/publication and retained original delivery capability.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use std::time::{Duration, Instant};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn policy(service: &mut Service, root: &str, source: &str) {
    assert_eq!(
        call(
            service,
            "PUT",
            "sys/policies/acl/kv-delivery",
            root,
            json!({"policy": source})
        )
        .status,
        204
    );
}

fn issue(service: &mut Service, root: &str, uses: u64, ttl: &str) -> TestResult<String> {
    let response = call(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"policies":["kv-delivery"], "no_default_policy":true,
               "num_uses":uses, "ttl":ttl}),
    );
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token missing")?
        .into())
}

fn fixture(service: &mut Service, root: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/kv-late",
            root,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            service,
            "POST",
            "kv-late/item",
            root,
            json!({"synthetic":"private-kv-value"})
        )
        .status,
        204
    );
    policy(
        service,
        root,
        r#"path "kv-late/*" { capabilities=["read","create"] }"#,
    );
}

fn read_admitted(
    service: &mut Service,
    token: &str,
    body: &Value,
) -> TestResult<(OrdinaryKvAuthority, Response)> {
    let state = service.state.as_mut().ok_or("state missing")?;
    let mut principal = state.auth.authenticate(token, 100)?;
    Service::bind_identity_principal(state, &mut principal, "")
        .map_err(|response| format!("identity admission {}", response.status))?;
    let request = RequestView {
        method: "GET",
        path: "kv-late/item",
        namespace: "",
        token,
        body,
        now: 100,
        admission_started: Instant::now(),
        token_clock: None,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let authority = OrdinaryKvAuthority::new(principal, state, &request, &service.unseal_nonce)
        .map_err(|response| format!("KV admission {}: {}", response.status, response.body))?;
    let mut domain =
        state
            .engines
            .handle_immutable_kv_read("", "GET", "kv-late/item", body, 100)?;
    assert_eq!(domain.status, 200);
    let response = Response {
        consistency_index: None,
        status: domain.status,
        body: std::mem::take(&mut domain.body),
    };
    Ok((authority, response))
}

#[test]
fn ordinary_kv_delivery_preserves_one_final_use_and_original_create_capability() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    fixture(&mut service, &root);
    let final_use = issue(&mut service, &root, 1, "10m")?;
    let read = call(&mut service, "GET", "kv-late/item", &final_use, json!({}));
    assert_eq!(read.status, 200, "{}", read.body);
    assert_eq!(read.body["data"]["synthetic"], "private-kv-value");
    assert_eq!(
        call(&mut service, "GET", "kv-late/item", &final_use, json!({})).status,
        403
    );
    let create_only = issue(&mut service, &root, 0, "10m")?;
    let created = call(
        &mut service,
        "POST",
        "kv-late/new-item",
        &create_only,
        json!({"synthetic":"created"}),
    );
    assert_eq!(created.status, 204, "{}", created.body);
    // The publication gate must retain create, even though the key now exists.
    assert_eq!(
        call(
            &mut service,
            "POST",
            "kv-late/new-item",
            &create_only,
            json!({"synthetic":"replacement"})
        )
        .status,
        403
    );
    let value = call(&mut service, "GET", "kv-late/new-item", &root, json!({}));
    assert_eq!(value.body["data"]["synthetic"], "created");
    assert!(service.pending_ordinary_kv_authority.is_none());
    Ok(())
}

#[test]
fn ordinary_kv_delivery_withholds_actual_read_after_late_revocation_policy_or_parameters()
-> TestResult {
    for scenario in ["revoke", "policy", "parameters"] {
        let files = Root::new();
        let mut service = files.service()?;
        let (_, root) = bootstrap(&mut service)?;
        fixture(&mut service, &root);
        let token = issue(&mut service, &root, 0, "10m")?;
        let (authority, response) =
            read_admitted(&mut service, &token, &json!({"selector":"open"}))?;
        match scenario {
            "revoke" => assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "auth/token/revoke",
                    &root,
                    json!({"token":token})
                )
                .status,
                204
            ),
            "policy" => policy(
                &mut service,
                &root,
                r#"path "kv-late/*" { capabilities=["deny"] }"#,
            ),
            _ => policy(
                &mut service,
                &root,
                r#"path "kv-late/*" { capabilities=["read"] allowed_parameters={ "selector"=["closed"] } }"#,
            ),
        }
        let audited =
            service.audit_completed_response("synthetic-kv-delivery", 100, None, response);
        let denied = service.complete_ordinary_kv_delivery(authority, audited);
        assert_eq!(denied.status, 403, "{scenario}: {}", denied.body);
        assert!(denied.body.get("data").is_none());
        assert!(denied.consistency_index.is_none());
    }
    Ok(())
}

#[test]
fn ordinary_kv_delivery_keeps_original_elapsed_expiry_deadline_and_mount_incarnation() -> TestResult
{
    for scenario in [
        "expiry",
        "deadline",
        "mount-recreated",
        "mount-upgraded",
        "seal",
        "recovery",
    ] {
        let files = Root::new();
        let mut service = files.service()?;
        let (_, root) = bootstrap(&mut service)?;
        fixture(&mut service, &root);
        let token = issue(&mut service, &root, 0, "1s")?;
        let (mut authority, response) = read_admitted(&mut service, &token, &json!({}))?;
        let expected = match scenario {
            "expiry" => {
                authority.started = Instant::now()
                    .checked_sub(Duration::from_millis(1200))
                    .ok_or("clock")?;
                403
            }
            "deadline" => {
                authority.deadline = Some(
                    Instant::now()
                        .checked_sub(Duration::from_nanos(1))
                        .ok_or("deadline")?,
                );
                503
            }
            "mount-recreated" => {
                assert_eq!(
                    call(
                        &mut service,
                        "DELETE",
                        "sys/mounts/kv-late",
                        &root,
                        json!({})
                    )
                    .status,
                    204
                );
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        "sys/mounts/kv-late",
                        &root,
                        json!({"type":"kv","options":{"version":"1"}})
                    )
                    .status,
                    204
                );
                503
            }
            "mount-upgraded" => {
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        "sys/mounts/kv-late/tune",
                        &root,
                        json!({"options":{"version":"2"}})
                    )
                    .status,
                    200
                );
                503
            }
            "seal" => {
                assert_eq!(
                    call(&mut service, "POST", "sys/seal", &root, json!({})).status,
                    204
                );
                503
            }
            _ => {
                service.recovery_required = true;
                503
            }
        };
        let audited =
            service.audit_completed_response("synthetic-kv-delivery", 100, None, response);
        let denied = service.complete_ordinary_kv_delivery(authority, audited);
        assert_eq!(denied.status, expected, "{scenario}: {}", denied.body);
        assert!(denied.body.get("data").is_none());
        assert!(denied.consistency_index.is_none());
    }
    Ok(())
}

#[test]
fn ordinary_kv_delivery_preserves_trusted_native_scope_without_bypassing_http_or_rebinding()
-> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    let (_, root) = bootstrap(&mut service)?;
    fixture(&mut service, &root);
    let namespace = "legacy-team";
    for (method, path, body, expected) in [
        (
            "POST",
            "sys/mounts/kv-late",
            json!({"type":"kv","options":{"version":"1"}}),
            204,
        ),
        (
            "POST",
            "kv-late/item",
            json!({"synthetic":"private-legacy-KV"}),
            204,
        ),
        (
            "PUT",
            "sys/policies/acl/legacy-reader",
            json!({"policy":r#"path "kv-late/*" { capabilities=["read"] }"#}),
            204,
        ),
    ] {
        let response = service.handle_at(method, path, namespace, &root, body, 100);
        assert_eq!(response.status, expected, "{path}: {}", response.body);
    }
    let issued = service.handle_at(
        "POST",
        "auth/token/create",
        namespace,
        &root,
        json!({"policies":["legacy-reader"],"no_default_policy":true,"ttl":"10m"}),
        100,
    );
    assert_eq!(issued.status, 200, "{}", issued.body);
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("legacy scoped token")?
        .to_owned();
    let native = service.handle_at("GET", "kv-late/item", namespace, &token, json!({}), 100);
    assert_eq!(native.status, 200, "{}", native.body);
    assert_eq!(native.body["data"]["synthetic"], "private-legacy-KV");
    assert_eq!(
        service
            .handle_at("GET", "kv-late/item", "", &token, json!({}), 100)
            .status,
        403,
        "the actual namespace-scoped actor cannot read the root KV owner"
    );
    let http = service.begin_at_mode(RequestDispatch {
        method: "GET",
        path: "kv-late/item",
        namespace,
        token: &token,
        body: json!({"enforce_namespace":false}),
        now: 100,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    let http = service.finish_synchronous_request(http);
    assert_eq!(http.status, 404, "{}", http.body);
    assert!(http.body.get("data").is_none());

    let body = json!({});
    let state = service.state.as_mut().ok_or("legacy state")?;
    assert!(state.namespaces.incarnation(namespace).is_none());
    let mut principal = state.auth.authenticate(&token, 100)?;
    Service::bind_identity_principal(state, &mut principal, namespace)
        .map_err(|response| format!("legacy identity admission {}", response.status))?;
    let request = RequestView {
        method: "GET",
        path: "kv-late/item",
        namespace,
        token: &token,
        body: &body,
        now: 100,
        admission_started: Instant::now(),
        token_clock: None,
        allow_forward: true,
        enforce_namespace: false,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let authority = OrdinaryKvAuthority::new(principal, state, &request, &service.unseal_nonce)
        .map_err(|response| format!("legacy capsule admission {}", response.status))?;
    let mut domain =
        state
            .engines
            .handle_immutable_kv_read(namespace, "GET", "kv-late/item", &body, 100)?;
    assert_eq!(domain.status, 200);
    let response = Response {
        consistency_index: None,
        status: domain.status,
        body: std::mem::take(&mut domain.body),
    };
    // A new real catalog incarnation must not adopt an earlier native delivery.
    state.namespaces.create(
        &state.cluster_id,
        namespace,
        std::collections::BTreeMap::new(),
        false,
    )?;
    assert!(state.namespaces.incarnation(namespace).is_some());
    let audited =
        service.audit_completed_response("synthetic-legacy-delivery", 100, None, response);
    let withheld = service.complete_ordinary_kv_delivery(authority, audited);
    assert_eq!(withheld.status, 503);
    assert!(withheld.body.get("data").is_none() && withheld.consistency_index.is_none());
    Ok(())
}
