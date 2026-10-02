//! Real Service admission and durable recovery with simulated provider outcomes.
//! These tests do not execute Kubernetes or LDAP network operations.
use super::tests::{Root, bootstrap, call};
use super::*;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn begin(
    service: &mut Service,
    token: &str,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
) -> RequestExecution {
    service.begin_at_mode_started(
        RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now: 100,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now(),
    )
}

fn complete(execution: RequestExecution, expected: u16) -> TestResult<Response> {
    match execution {
        RequestExecution::Complete(response) => {
            assert_eq!(response.status, expected);
            Ok(response)
        }
        RequestExecution::External(_) => Err("unexpected external operation; not executed".into()),
    }
}

fn setup(
    service: &mut Service,
    root: &str,
    kind: &str,
    namespace: &str,
    batch: bool,
) -> TestResult<String> {
    if !namespace.is_empty() {
        complete(
            begin(service, root, "", "POST", "sys/namespaces/team", json!({})),
            200,
        )?;
    }
    complete(
        begin(
            service,
            root,
            namespace,
            "POST",
            &format!("sys/mounts/{kind}"),
            json!({"type":kind}),
        ),
        204,
    )?;
    let mut state = service.state.clone().ok_or("state unavailable")?;
    if kind == "kubernetes" {
        for (path, body) in [
            (
                "kubernetes/config",
                json!({"kubernetes_host":"https://localhost:8443", "service_account_token":"synthetic-manager"}),
            ),
            (
                "kubernetes/roles/reader",
                json!({"allowed_kubernetes_namespaces":["default"], "service_account_name":"reader", "token_default_ttl":600, "token_max_ttl":3600}),
            ),
        ] {
            state
                .engines
                .kubernetes_dispatch(namespace, path, "POST", &body, 100, None)
                .map_err(|_| "Kubernetes fixture configuration")?
                .ok_or("configuration route")?;
        }
    } else {
        let creation = "dn: uid={{.Username}},ou=people,dc=example,dc=test\nchangetype: add\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\nobjectClass: inetOrgPerson\ncn: {{.Username}}\nsn: Synthetic\nuid: {{.Username}}\nuserPassword: {{.Password}}\n";
        let deletion = "dn: uid={{.Username}},ou=people,dc=example,dc=test\nchangetype: delete\n";
        for (path, body) in [
            (
                "ldap/config",
                json!({"url":"ldaps://localhost:636", "binddn":"cn=manager,dc=example,dc=test", "bindpass":"synthetic-manager", "userdn":"ou=people,dc=example,dc=test"}),
            ),
            (
                "ldap/role/reader",
                json!({"creation_ldif":creation, "deletion_ldif":deletion, "default_ttl":120, "max_ttl":600}),
            ),
        ] {
            state
                .engines
                .openldap_dispatch(namespace, path, "POST", &body, 100, None)
                .map_err(|_| "LDAP fixture configuration")?
                .ok_or("configuration route")?;
        }
    }
    state.schema = CURRENT_STATE_SCHEMA;
    state.validate_format().map_err(|_| "fixture format")?;
    service
        .commit_state(&state)
        .map_err(|_| "fixture publication")?;
    service.state = Some(state);
    let policy =
        format!("path \"{kind}/creds/reader\" {{ capabilities = [\"read\", \"update\"] }}");
    complete(
        begin(
            service,
            root,
            namespace,
            "POST",
            "sys/policies/acl/delivery-reader",
            json!({"policy":policy}),
        ),
        204,
    )?;
    let mut options = json!({"policies":["delivery-reader"], "ttl":"10m"});
    if batch {
        options["type"] = json!("batch");
    } else {
        options["num_uses"] = json!(2);
    }
    let response = complete(
        begin(
            service,
            root,
            namespace,
            "POST",
            "auth/token/create",
            options,
        ),
        200,
    )?;
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned())
}

fn issue(
    service: &mut Service,
    token: &str,
    kind: &str,
    namespace: &str,
) -> TestResult<PendingExternalRequest> {
    let (method, body) = if kind == "kubernetes" {
        ("POST", json!({"kubernetes_namespace":"default"}))
    } else {
        ("GET", json!({}))
    };
    match begin(
        service,
        token,
        namespace,
        method,
        &format!("{kind}/creds/reader"),
        body,
    ) {
        RequestExecution::External(pending) => Ok(*pending),
        RequestExecution::Complete(response) => {
            Err(format!("expected external dispatch, got {}", response.status).into())
        }
    }
}

fn observed(pending: &PendingExternalRequest) -> TestResult<(String, ExternalEffectResult)> {
    match &pending.effect {
        ExternalEffectPlan::KubernetesToken(plan) => Ok((
            plan.inner.lease_id.clone(),
            ExternalEffectResult::KubernetesToken(Ok(crate::engines::kubernetes::TokenMetadata {
                token: Zeroizing::new("synthetic-provider-token-no-network".into()),
                expires_at: 700,
                audiences: Vec::new(),
            })),
        )),
        ExternalEffectPlan::OpenLdap(plan) => Ok((
            plan.inner.lease_id.clone(),
            ExternalEffectResult::OpenLdap(Ok(())),
        )),
        _ => Err("unexpected effect kind".into()),
    }
}

fn revoked_delivery(kind: &str, change: &str, batch: bool) -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;
    let namespace = if change == "namespace" { "team" } else { "" };
    let token = setup(&mut service, &root_token, kind, namespace, batch)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let pending = if change == "deadline" {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        issue(&mut service, &token, kind, namespace)?
    } else {
        issue(&mut service, &token, kind, namespace)?
    };
    let (id, observation) = observed(&pending)?;
    match change {
        "policy" => {
            complete(
                begin(
                    &mut service,
                    &root_token,
                    namespace,
                    "POST",
                    "sys/policies/acl/delivery-reader",
                    json!({"policy":"path \"*\" { capabilities = [\"deny\"] }"}),
                ),
                204,
            )?;
        }
        "namespace" => {
            complete(
                begin(
                    &mut service,
                    &root_token,
                    "",
                    "POST",
                    "sys/namespaces/team/seal",
                    json!({}),
                ),
                204,
            )?;
        }
        "revoke" => {
            complete(
                begin(
                    &mut service,
                    &root_token,
                    "",
                    "POST",
                    "auth/token/revoke",
                    json!({"token":token}),
                ),
                204,
            )?;
        }
        "seal" => {
            complete(
                begin(&mut service, &root_token, "", "POST", "sys/seal", json!({})),
                204,
            )?;
        }
        "seal_cycle" => {
            complete(
                begin(&mut service, &root_token, "", "POST", "sys/seal", json!({})),
                204,
            )?;
            complete(
                begin(
                    &mut service,
                    "",
                    "",
                    "POST",
                    "sys/unseal",
                    json!({"key": &key}),
                ),
                200,
            )?;
        }
        "deadline" => std::thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        ),
        _ => return Err("unknown change".into()),
    }
    let response = service.finish_external_request(pending, observation);
    assert_eq!(response.status, 503, "{kind} must withhold after {change}");
    assert!(response.body.get("data").is_none());
    assert_eq!(response.body["retry_allowed"], false);
    if kind == "kubernetes" && matches!(change, "policy" | "deadline") {
        assert_eq!(response.body["provider_token_revoked"], false);
        assert_eq!(response.body["local_lease_retired"], true);
    }
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    if kind == "ldap" {
        let cleanup = reopened
            .prepare_openldap_maintenance(102)?
            .ok_or("durable cleanup missing")?;
        assert_eq!(cleanup.plan.inner.lease_id, id);
        if change == "seal" {
            // Global unseal restores the still-live owner, not the lost HTTP
            // admission. Reconciliation may observe the original durable issue;
            // it returns only a maintenance outcome and cannot deliver a secret.
            assert!(cleanup.plan.inner.action == crate::engines::openldap::EffectAction::Issue);
            let original_expiry = cleanup.plan.inner.expires_at;
            assert!(reopened.finish_openldap_maintenance(cleanup, Ok(()))?);
            assert!(reopened.prepare_openldap_maintenance(102)?.is_none());
            let retirement = reopened
                .prepare_openldap_maintenance(original_expiry)?
                .ok_or("original expiry must still retire the recovered lease")?;
            assert_eq!(retirement.plan.inner.lease_id, id);
            assert_eq!(retirement.plan.inner.expires_at, original_expiry);
            assert!(retirement.plan.inner.action == crate::engines::openldap::EffectAction::Revoke);
        } else {
            assert!(cleanup.plan.inner.action == crate::engines::openldap::EffectAction::Revoke);
        }
    }
    Ok(())
}

#[test]
fn secret_delivery_kubernetes_policy_change_retires_service_and_batch() -> TestResult {
    for batch in [false, true] {
        revoked_delivery("kubernetes", "policy", batch)?;
    }
    Ok(())
}
#[test]
fn secret_delivery_openldap_policy_change_retains_cleanup_for_service_and_batch() -> TestResult {
    for batch in [false, true] {
        revoked_delivery("ldap", "policy", batch)?;
    }
    Ok(())
}
#[test]
fn secret_delivery_kubernetes_deadline_is_not_an_owner_lifetime() -> TestResult {
    revoked_delivery("kubernetes", "deadline", false)
}
#[test]
fn secret_delivery_openldap_deadline_is_not_an_owner_lifetime() -> TestResult {
    revoked_delivery("ldap", "deadline", false)
}
#[test]
fn secret_delivery_openldap_namespace_seal_does_not_release_a_password() -> TestResult {
    revoked_delivery("ldap", "namespace", false)
}
#[test]
fn secret_delivery_kubernetes_namespace_seal_keeps_pending_observation() -> TestResult {
    revoked_delivery("kubernetes", "namespace", false)
}

#[test]
fn secret_delivery_current_authority_keeps_unrelated_work_and_single_consumption() -> TestResult {
    for kind in ["kubernetes", "ldap"] {
        for batch in [false, true] {
            let root = Root::new();
            let mut service = root.service()?;
            let (_, root_token) = bootstrap(&mut service)?;
            let token = setup(&mut service, &root_token, kind, "", batch)?;
            let pending = issue(&mut service, &token, kind, "")?;
            let (_, observation) = observed(&pending)?;
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "secret/data/unrelated",
                    &root_token,
                    json!({"data":{"progress":true}})
                )
                .status,
                200
            );
            let response = service.finish_external_request(pending, observation);
            assert_eq!(response.status, 200);
            assert!(response.body["data"].is_object());
            if !batch {
                let lookup = call(
                    &mut service,
                    "POST",
                    "auth/token/lookup",
                    &root_token,
                    json!({"token":token}),
                );
                assert_eq!(lookup.status, 200);
                assert_eq!(lookup.body["data"]["num_uses"], 1);
            }
        }
    }
    Ok(())
}

#[test]
fn secret_delivery_explicit_revocation_never_returns_provider_credentials() -> TestResult {
    for kind in ["kubernetes", "ldap"] {
        revoked_delivery(kind, "revoke", false)?;
    }
    Ok(())
}

#[test]
fn secret_delivery_global_seal_retains_recoverable_original_intent() -> TestResult {
    for kind in ["kubernetes", "ldap"] {
        revoked_delivery(kind, "seal", false)?;
    }
    Ok(())
}

#[test]
fn secret_delivery_namespace_seal_before_crash_never_readmits_pending_add() -> TestResult {
    for batch in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, root_token) = bootstrap(&mut service)?;
        let token = setup(&mut service, &root_token, "ldap", "team", batch)?;
        let pending = issue(&mut service, &token, "ldap", "team")?;
        let (id, _) = observed(&pending)?;
        complete(
            begin(
                &mut service,
                &root_token,
                "",
                "POST",
                "sys/namespaces/team/seal",
                json!({}),
            ),
            204,
        )?;
        // Lose the process-local finalizer before it could persist rejection.
        drop(pending);
        drop(service);
        let mut reopened = root.service()?;
        assert_eq!(
            call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let cleanup = reopened
            .prepare_openldap_maintenance(102)?
            .ok_or("sealed pending intent must be recoverable")?;
        assert_eq!(cleanup.plan.inner.lease_id, id);
        assert!(
            cleanup.plan.inner.action == crate::engines::openldap::EffectAction::Revoke,
            "sealed namespace cannot authorize another directory Add after restart"
        );
        assert!(reopened.finish_openldap_maintenance(cleanup, Ok(()))?);
        assert!(reopened.prepare_openldap_maintenance(103)?.is_none());
    }
    Ok(())
}

#[test]
fn secret_delivery_seal_unseal_cannot_revive_old_http_admission() -> TestResult {
    for kind in ["kubernetes", "ldap"] {
        revoked_delivery(kind, "seal_cycle", false)?;
    }
    Ok(())
}

#[test]
fn secret_delivery_namespace_seal_preserves_already_delivered_lease_until_expiry() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;
    let token = setup(&mut service, &root_token, "ldap", "team", false)?;
    let pending = issue(&mut service, &token, "ldap", "team")?;
    let (id, observation) = observed(&pending)?;
    let expiry = match &pending.effect {
        ExternalEffectPlan::OpenLdap(plan) => plan.inner.expires_at,
        _ => return Err("unexpected provider".into()),
    };
    assert_eq!(
        service.finish_external_request(pending, observation).status,
        200
    );
    complete(
        begin(
            &mut service,
            &root_token,
            "",
            "POST",
            "sys/namespaces/team/seal",
            json!({}),
        ),
        204,
    )?;
    drop(service);
    let mut reopened = root.service()?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(reopened.prepare_openldap_maintenance(102)?.is_none());
    let cleanup = reopened
        .prepare_openldap_maintenance(expiry)?
        .ok_or("original expiry must still clean up")?;
    assert_eq!(cleanup.plan.inner.lease_id, id);
    assert!(cleanup.plan.inner.action == crate::engines::openldap::EffectAction::Revoke);
    assert!(reopened.finish_openldap_maintenance(cleanup, Ok(()))?);
    Ok(())
}
