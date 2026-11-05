//! Real request admission and durable publication; provider success is simulated
//! here. The live TLS database_config_completion profile supplies actual I/O.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use crate::test_support::runtime_secret;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn config(password: &str) -> Value {
    json!({"plugin_name":"postgresql-database-plugin",
        "connection_url":"postgresql://localhost:5432/app",
        "username":"manager", "password":password,
        "allowed_roles":["reader"], "verify_connection":true})
}

fn stage_body(
    service: &mut Service,
    token: &str,
    started: Instant,
    body: Value,
) -> TestResult<PendingExternalRequest> {
    let execution = service.begin_at_mode_started(
        RequestDispatch {
            method: "POST",
            path: "database/config/local",
            namespace: "",
            token,
            body,
            now: 100,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        started,
    );
    match execution {
        RequestExecution::External(pending) => {
            assert!(matches!(
                pending.effect,
                ExternalEffectPlan::DatabaseConfig(_)
            ));
            Ok(*pending)
        }
        RequestExecution::Complete(response) => {
            Err(format!("configuration did not stage: {}", response.status).into())
        }
    }
}

fn stage(
    service: &mut Service,
    token: &str,
    started: Instant,
) -> TestResult<PendingExternalRequest> {
    let password = runtime_secret("database-config-stage");
    stage_body(service, token, started, config(password.as_str()))
}

fn setup(service: &mut Service, root: &str, extra: Value) -> TestResult<String> {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/database",
            root,
            json!({"type":"database"})
        )
        .status,
        204
    );
    assert_eq!(call(service, "POST", "sys/policies/acl/db-admin", root, json!({
        "policy":"path \"database/config/local\" { capabilities = [\"read\", \"update\", \"sudo\"] }"
    })).status, 204);
    let mut body = json!({"policies":["db-admin"], "ttl":"10m"});
    for (key, value) in extra.as_object().ok_or("invalid test options")? {
        body[key] = value.clone();
    }
    let result = call(service, "POST", "auth/token/create", root, body);
    assert_eq!(result.status, 200);
    Ok(result.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing test token")?
        .to_owned())
}

#[test]
fn database_config_completion_revocation_and_policy_preserve_original_after_reopen() -> TestResult {
    for scenario in ["revoke", "policy", "expiry"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, root_token) = bootstrap(&mut service)?;
        let extra = if scenario == "expiry" {
            json!({"ttl":"1s"})
        } else {
            json!({})
        };
        let token = setup(&mut service, &root_token, extra)?;
        let initial = stage(&mut service, &root_token, Instant::now())?;
        assert_eq!(
            service
                .finish_external_request(initial, ExternalEffectResult::DatabaseConfig(Ok(())))
                .status,
            204
        );
        let original = serde_json::to_vec(&service.state.as_ref().ok_or("state")?.database)?;
        let started = if scenario == "expiry" {
            Instant::now() - Duration::from_secs(2)
        } else {
            Instant::now()
        };
        let mut pending = stage(&mut service, &token, started)?;
        if let ExternalEffectPlan::DatabaseConfig(plan) = &mut pending.effect {
            plan.connection.password = PrivateString("must-not-be-published".into());
        }
        match scenario {
            "revoke" => assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "auth/token/revoke",
                    &root_token,
                    json!({"token":token})
                )
                .status,
                204
            ),
            "policy" => assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/policies/acl/db-admin",
                    &root_token,
                    json!({
                        "policy":"path \"*\" { capabilities = [\"deny\"] }"
                    })
                )
                .status,
                204
            ),
            _ => {}
        }
        let response =
            service.finish_external_request(pending, ExternalEffectResult::DatabaseConfig(Ok(())));
        assert_eq!(response.status, 403, "{scenario}");
        assert_eq!(
            serde_json::to_vec(&service.state.as_ref().ok_or("state")?.database)?,
            original,
            "{scenario}"
        );
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            serde_json::to_vec(&service.state.as_ref().ok_or("restored state")?.database)?,
            original,
            "{scenario}"
        );
    }
    Ok(())
}

#[test]
fn database_config_completion_preserves_single_use_batch_and_unrelated_commits() -> TestResult {
    for extra in [json!({"num_uses":1}), json!({"type":"batch"}), json!({})] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, root_token) = bootstrap(&mut service)?;
        let token = setup(&mut service, &root_token, extra.clone())?;
        let pending = stage(&mut service, &token, Instant::now())?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/concurrent",
                &root_token,
                json!({"data":{"retained":true}})
            )
            .status,
            200
        );
        assert_eq!(
            service
                .finish_external_request(pending, ExternalEffectResult::DatabaseConfig(Ok(())))
                .status,
            204
        );
        if extra.get("num_uses").is_some() {
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "database/config/local",
                    &token,
                    config(runtime_secret("database-config-rejected").as_str())
                )
                .status,
                403
            );
        }
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
                "database/config/local",
                &root_token,
                json!({})
            )
            .status,
            200
        );
        let value = call(
            &mut service,
            "GET",
            "secret/data/concurrent",
            &root_token,
            json!({}),
        );
        assert_eq!(value.body["data"]["data"]["retained"], true);
    }
    Ok(())
}

#[test]
fn database_config_completion_rejects_mount_recreation_without_publishing_credentials() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    let token = setup(&mut service, &root_token, json!({}))?;
    let pending = stage(&mut service, &token, Instant::now())?;
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/database",
            &root_token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/database",
            &root_token,
            json!({"type":"database"})
        )
        .status,
        204
    );
    let before = serde_json::to_vec(&service.state.as_ref().ok_or("state")?.database)?;
    assert_eq!(
        service
            .finish_external_request(pending, ExternalEffectResult::DatabaseConfig(Ok(())))
            .status,
        409
    );
    assert_eq!(
        serde_json::to_vec(&service.state.as_ref().ok_or("state")?.database)?,
        before
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "database/config/local",
            &root_token,
            json!({})
        )
        .status,
        404
    );
    Ok(())
}

#[test]
fn database_config_partial_metadata_update_preserves_frozen_provider_identity() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    setup(&mut service, &root_token, json!({}))?;

    let initial = stage(&mut service, &root_token, Instant::now())?;
    assert_eq!(
        service
            .finish_external_request(initial, ExternalEffectResult::DatabaseConfig(Ok(())))
            .status,
        204
    );

    let rotation = service.begin_at_mode_started(
        RequestDispatch {
            method: "POST",
            path: "database/rotate-root/local",
            namespace: "",
            token: &root_token,
            body: json!({}),
            now: 101,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now(),
    );
    let RequestExecution::External(rotation) = rotation else {
        return Err("root rotation did not persist an external intent".into());
    };
    drop(rotation);
    let before = service
        .state
        .as_ref()
        .and_then(|state| state.database.mount("", "database/"))
        .and_then(|mount| mount.connections.get("local"))
        .ok_or("connection")?;
    let identity = (
        before.plugin_name().to_owned(),
        before.connection_url.clone(),
        before.username.clone(),
        before.password.0.clone(),
        before.password_authentication,
    );
    let rotation_digest = before
        .root_rotation
        .as_ref()
        .ok_or("root rotation")?
        .request_digest
        .clone();

    let partial = stage_body(
        &mut service,
        &root_token,
        Instant::now(),
        json!({
            "allowed_roles":["reader", "writer"],
            "password_policy":"future-policy",
            "username_template":"{{ printf \"future-%s\" (.RoleName | truncate 16) }}",
            "verify_connection":true
        }),
    )?;
    assert_eq!(
        service
            .finish_external_request(partial, ExternalEffectResult::DatabaseConfig(Ok(())))
            .status,
        204
    );
    let after = service
        .state
        .as_ref()
        .and_then(|state| state.database.mount("", "database/"))
        .and_then(|mount| mount.connections.get("local"))
        .ok_or("updated connection")?;
    assert_eq!(
        (
            after.plugin_name().to_owned(),
            after.connection_url.clone(),
            after.username.clone(),
            after.password.0.clone(),
            after.password_authentication,
        ),
        identity
    );
    assert_eq!(
        after.allowed_roles,
        BTreeSet::from(["reader".to_owned(), "writer".to_owned()])
    );
    assert_eq!(after.password_policy.as_deref(), Some("future-policy"));
    assert_eq!(
        after.username_template,
        r#"{{ printf "future-%s" (.RoleName | truncate 16) }}"#
    );
    assert_eq!(
        after
            .root_rotation
            .as_ref()
            .ok_or("preserved root rotation")?
            .request_digest,
        rotation_digest
    );

    let denied = service.begin_at_mode_started(
        RequestDispatch {
            method: "POST",
            path: "database/config/local",
            namespace: "",
            token: &root_token,
            body: json!({"password":"different-manager-password", "verify_connection":true}),
            now: 102,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now(),
    );
    let RequestExecution::Complete(denied) = denied else {
        return Err("provider identity update entered external validation".into());
    };
    assert_eq!(denied.status, 409);
    Ok(())
}

#[test]
fn database_config_completion_deadline_and_recovery_refuse_publication() -> TestResult {
    for scenario in ["deadline", "recovery", "seal"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, root_token) = bootstrap(&mut service)?;
        let token = setup(&mut service, &root_token, json!({}))?;
        let deadline = Instant::now() + Duration::from_millis(50);
        let pending = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
            stage(&mut service, &token, Instant::now())?
        };
        match scenario {
            "deadline" => std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            ),
            "recovery" => service.recovery_required = true,
            "seal" => assert_eq!(
                call(&mut service, "POST", "sys/seal", &root_token, json!({})).status,
                204
            ),
            _ => unreachable!(),
        }
        let response =
            service.finish_external_request(pending, ExternalEffectResult::DatabaseConfig(Ok(())));
        assert_eq!(response.status, 503, "{scenario}");
        assert!(
            service
                .state
                .as_ref()
                .is_none_or(|state| state.database.mount("", "database/").is_none())
        );
    }
    Ok(())
}
