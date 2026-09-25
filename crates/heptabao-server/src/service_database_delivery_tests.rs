//! Request delivery regressions with simulated provider results only.
//! These tests never execute a provider, plugin, or external network request.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn request(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
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
        RequestExecution::External(_) => Err("unexpected external dispatch; not executed".into()),
    }
}

fn pending(execution: RequestExecution) -> TestResult<PendingExternalRequest> {
    match execution {
        RequestExecution::External(pending) => Ok(*pending),
        RequestExecution::Complete(response) => {
            Err(format!("expected staged provider work, status {}", response.status).into())
        }
    }
}

fn setup(service: &mut Service, root: &str, namespace: &str, batch: bool) -> TestResult<String> {
    if !namespace.is_empty() {
        complete(
            request(service, "POST", "sys/namespaces/team", "", root, json!({})),
            200,
        )?;
    }
    complete(
        request(
            service,
            "POST",
            "sys/mounts/database",
            namespace,
            root,
            json!({"type":"database"}),
        ),
        204,
    )?;
    let configuration = pending(request(
        service,
        "POST",
        "database/config/local",
        namespace,
        root,
        json!({"plugin_name":"postgresql-database-plugin",
            "connection_url":"postgresql://localhost:5432/app", "username":"manager",
            "password":"synthetic-unit-test", "allowed_roles":["reader"],
            "verify_connection":true}),
    ))?;
    assert!(matches!(
        configuration.effect,
        ExternalEffectPlan::DatabaseConfig(_)
    ));
    // Deliberately simulate verification instead of calling configuration.execute().
    assert_eq!(
        service
            .finish_external_request(configuration, ExternalEffectResult::DatabaseConfig(Ok(())))
            .status,
        204
    );
    complete(
        request(
            service,
            "POST",
            "database/roles/reader",
            namespace,
            root,
            json!({"db_name":"local", "provider_role":"reader", "default_ttl":60,
            "max_ttl":600}),
        ),
        204,
    )?;
    complete(
        request(
            service,
            "POST",
            "sys/policies/acl/db-caller",
            namespace,
            root,
            json!({"policy":concat!(
                "path \"database/creds/reader\" { capabilities = [\"read\"] } ",
                "path \"sys/leases/renew\" { capabilities = [\"update\", \"sudo\"] }"
            )}),
        ),
        204,
    )?;
    let mut options = json!({"policies":["db-caller"], "ttl":"10m"});
    if batch {
        options["type"] = json!("batch");
    }
    let response = complete(
        request(
            service,
            "POST",
            "auth/token/create",
            namespace,
            root,
            options,
        ),
        200,
    )?;
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned())
}

fn lease_id(pending: &PendingExternalRequest) -> TestResult<String> {
    match &pending.effect {
        ExternalEffectPlan::Database(plan) => Ok(plan.lease.id.clone()),
        _ => Err("expected database effect".into()),
    }
}

fn cleanup_is_retained(service: &Service, namespace: &str, id: &str) -> TestResult {
    let lease = service
        .state
        .as_ref()
        .ok_or("missing state")?
        .database
        .mount(namespace, "database/")
        .ok_or("missing mount")?
        .leases
        .get(id)
        .ok_or("cleanup obligation lost")?;
    assert!(lease.phase == Phase::PendingRevoke);
    assert!(lease.password.is_none());
    assert_eq!(lease.expires, 0);
    Ok(())
}

#[test]
fn database_delivery_policy_change_stages_cleanup_for_service_and_batch() -> TestResult {
    for batch in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, root_token) = bootstrap(&mut service)?;
        let token = setup(&mut service, &root_token, "", batch)?;
        let effect = pending(request(
            &mut service,
            "GET",
            "database/creds/reader",
            "",
            &token,
            json!({}),
        ))?;
        let id = lease_id(&effect)?;
        complete(
            request(
                &mut service,
                "POST",
                "sys/policies/acl/db-caller",
                "",
                &root_token,
                json!({"policy":"path \"*\" { capabilities = [\"deny\"] }"}),
            ),
            204,
        )?;
        let response =
            service.finish_external_request(effect, ExternalEffectResult::Database(Ok(())));
        assert_eq!(response.status, 503);
        assert!(response.body.get("data").is_none());
        assert_eq!(response.body["retry_allowed"], false);
        cleanup_is_retained(&service, "", &id)?;
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        cleanup_is_retained(&service, "", &id)?;
    }
    Ok(())
}

#[test]
fn database_delivery_namespace_seal_withholds_secret_and_preserves_cleanup() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;
    let token = setup(&mut service, &root_token, "team", false)?;
    let effect = pending(request(
        &mut service,
        "GET",
        "database/creds/reader",
        "team",
        &token,
        json!({}),
    ))?;
    let id = lease_id(&effect)?;
    complete(
        request(
            &mut service,
            "POST",
            "sys/namespaces/team/seal",
            "",
            &root_token,
            json!({}),
        ),
        204,
    )?;
    let response = service.finish_external_request(effect, ExternalEffectResult::Database(Ok(())));
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    cleanup_is_retained(&service, "team", &id)?;
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    cleanup_is_retained(&service, "team", &id)?;
    Ok(())
}

#[test]
fn database_delivery_deadline_keeps_durable_compensation_without_a_secret() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    let token = setup(&mut service, &root_token, "", false)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let effect = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        pending(request(
            &mut service,
            "GET",
            "database/creds/reader",
            "",
            &token,
            json!({}),
        ))?
    };
    let id = lease_id(&effect)?;
    std::thread::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
    );
    let response = service.finish_external_request(effect, ExternalEffectResult::Database(Ok(())));
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    cleanup_is_retained(&service, "", &id)?;
    Ok(())
}

#[test]
fn database_delivery_retains_valid_service_batch_and_unrelated_commits() -> TestResult {
    for batch in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, root_token) = bootstrap(&mut service)?;
        let token = setup(&mut service, &root_token, "", batch)?;
        let effect = pending(request(
            &mut service,
            "GET",
            "database/creds/reader",
            "",
            &token,
            json!({}),
        ))?;
        let id = lease_id(&effect)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/unrelated",
                &root_token,
                json!({"data":{"retained":true}})
            )
            .status,
            200
        );
        let response =
            service.finish_external_request(effect, ExternalEffectResult::Database(Ok(())));
        assert_eq!(response.status, 200);
        assert!(response.body["data"]["password"].is_string());
        assert_eq!(response.body["lease_id"], id);
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "secret/data/unrelated",
                &root_token,
                json!({})
            )
            .body["data"]["data"]["retained"],
            true
        );
        let lease = service
            .state
            .as_ref()
            .ok_or("state")?
            .database
            .mount("", "database/")
            .ok_or("mount")?
            .leases
            .get(&id)
            .ok_or("lease")?;
        assert!(lease.phase == Phase::Active);
        assert!(lease.password.is_none());
    }
    Ok(())
}

#[test]
fn database_delivery_admin_renewal_does_not_inherit_the_lease_owners_authority() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    let requester = setup(&mut service, &root_token, "", false)?;
    // A root-owned lease remains live while the independently authorized renewer
    // loses permission. Owner liveness alone must not authorize that response.
    let issue = pending(request(
        &mut service,
        "GET",
        "database/creds/reader",
        "",
        &root_token,
        json!({}),
    ))?;
    let id = lease_id(&issue)?;
    assert_eq!(
        service
            .finish_external_request(issue, ExternalEffectResult::Database(Ok(())))
            .status,
        200
    );
    let renewal = pending(request(
        &mut service,
        "POST",
        "sys/leases/renew",
        "",
        &requester,
        json!({"lease_id":id, "increment":120}),
    ))?;
    complete(
        request(
            &mut service,
            "POST",
            "sys/policies/acl/db-caller",
            "",
            &root_token,
            json!({"policy":"path \"*\" { capabilities = [\"deny\"] }"}),
        ),
        204,
    )?;
    let response = service.finish_external_request(renewal, ExternalEffectResult::Database(Ok(())));
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    cleanup_is_retained(&service, "", &id)?;
    Ok(())
}

#[test]
fn database_delivery_subtractive_cleanup_survives_requester_revocation() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    let _requester = setup(&mut service, &root_token, "", false)?;
    let issue = pending(request(
        &mut service,
        "GET",
        "database/creds/reader",
        "",
        &root_token,
        json!({}),
    ))?;
    let id = lease_id(&issue)?;
    assert_eq!(
        service
            .finish_external_request(issue, ExternalEffectResult::Database(Ok(())))
            .status,
        200
    );
    let revoke = pending(request(
        &mut service,
        "POST",
        "sys/leases/revoke",
        "",
        &root_token,
        json!({"lease_id":id}),
    ))?;
    complete(
        request(
            &mut service,
            "POST",
            "auth/token/revoke-self",
            "",
            &root_token,
            json!({}),
        ),
        204,
    )?;
    let response = service.finish_external_request(revoke, ExternalEffectResult::Database(Ok(())));
    assert_eq!(response.status, 204);
    assert!(response.body.get("data").is_none());
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .database
            .mount("", "database/")
            .ok_or("mount")?
            .leases
            .contains_key(&id)
    );
    Ok(())
}
