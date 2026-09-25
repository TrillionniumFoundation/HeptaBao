//! Completion checks retain the single consumed admission capability.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn admitted(
    service: &mut Service,
    token: &str,
    namespace: &str,
    sudo: bool,
) -> TestResult<PluginResponseAuthority> {
    let state = service.state.as_mut().ok_or("missing test state")?;
    let mut principal = state
        .auth
        .authenticate(token, 100)
        .map_err(|_| "test authentication failed")?;
    Service::bind_identity_principal(state, &mut principal, namespace)
        .map_err(|_| "test identity binding failed")?;
    let path = if sudo {
        "sys/plugins/kms/fixture/wrap"
    } else {
        "external/item"
    };
    let capability = if sudo { "update" } else { "read" };
    let body = json!({});
    let request = RequestView {
        method: if sudo { "POST" } else { "GET" },
        path,
        namespace,
        token,
        body: &body,
        now: 100,
        admission_started: Instant::now(),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    Ok(PluginResponseAuthority::new(
        principal, state, &request, capability, sudo,
    ))
}

fn issue(service: &mut Service, root: &str, extra: Value) -> TestResult<String> {
    // The real policy and token endpoints, rather than fabricated Principals.
    assert_eq!(call(service, "POST", "sys/policies/acl/plugin-reader", root, json!({
        "policy": "path \"external/*\" { capabilities = [\"read\"] } path \"sys/plugins/kms/*\" { capabilities = [\"update\", \"sudo\"] }"
    })).status, 204);
    let mut body = json!({"policies":["plugin-reader"], "ttl":"10m"});
    for (key, value) in extra.as_object().ok_or("invalid test extras")? {
        body[key] = value.clone();
    }
    let response = call(service, "POST", "auth/token/create", root, body);
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing test token")?
        .to_owned())
}

#[test]
fn plugin_completion_rechecks_revocation_acl_expiry_deadline_seal_and_owner() -> TestResult {
    for sudo in [false, true] {
        for scenario in [
            "revoke",
            "acl",
            "expiry",
            "deadline",
            "seal",
            "recovery",
            "cluster",
            "namespace",
        ] {
            let root = Root::new();
            let mut service = root.service()?;
            let (_, root_token) = bootstrap(&mut service)?;
            let token = issue(&mut service, &root_token, json!({}))?;
            let mut authority = admitted(&mut service, &token, "", sudo)?;
            assert!(service.validate_plugin_response(&mut authority).is_ok());
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
                "acl" => assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        "sys/policies/acl/plugin-reader",
                        &root_token,
                        json!({"policy":"path \"*\" { capabilities = [\"deny\"] }"})
                    )
                    .status,
                    204
                ),
                "expiry" => authority.started = Instant::now() - Duration::from_secs(601),
                "deadline" => authority.deadline = Some(Instant::now() - Duration::from_secs(1)),
                "seal" => assert_eq!(
                    call(&mut service, "POST", "sys/seal", &root_token, json!({})).status,
                    204
                ),
                "recovery" => service.recovery_required = true,
                "cluster" => authority.cluster_id.push_str("-different"),
                "namespace" => authority.namespace_incarnation = Some(u64::MAX),
                _ => unreachable!(),
            }
            let result = service.validate_plugin_response(&mut authority);
            assert!(result.is_err(), "sudo={sudo}, scenario={scenario}");
        }
    }
    Ok(())
}

#[test]
fn plugin_completion_preserves_finite_use_and_batch_admission() -> TestResult {
    for extra in [json!({"num_uses":1}), json!({"type":"batch"})] {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, root_token) = bootstrap(&mut service)?;
        let token = issue(&mut service, &root_token, extra.clone())?;
        let mut authority = admitted(&mut service, &token, "", false)?;
        assert!(service.validate_plugin_response(&mut authority).is_ok());
        if extra.get("num_uses").is_some() {
            assert!(
                service
                    .state
                    .as_mut()
                    .ok_or("missing state")?
                    .auth
                    .authenticate(&token, 100)
                    .is_err()
            );
        } else {
            assert!(token.starts_with("hvb."));
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "auth/token/revoke",
                    &root_token,
                    json!({"token":root_token})
                )
                .status,
                204
            );
            assert!(service.validate_plugin_response(&mut authority).is_err());
        }
    }
    Ok(())
}

#[test]
fn plugin_completion_rechecks_current_namespace_seal() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    let mut authority = admitted(&mut service, &token, "team", false)?;
    assert!(service.validate_plugin_response(&mut authority).is_ok());
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team/seal",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert!(service.validate_plugin_response(&mut authority).is_err());
    Ok(())
}

#[test]
fn plugin_mount_binding_distinguishes_recreated_identical_plugin() -> TestResult {
    let mut engines = EngineState::default();
    let config = json!({"type":"plugin","config":{"plugin_id":"fixture"}});
    engines.handle("", "POST", "sys/mounts/external", &config, 100)?;
    let old = engines
        .plugin_secret_mount_binding("", "external/item")
        .ok_or("missing binding")?;
    engines.handle("", "DELETE", "sys/mounts/external", &json!({}), 100)?;
    engines.handle("", "POST", "sys/mounts/external", &config, 100)?;
    let current = engines
        .plugin_secret_mount_binding("", "external/item")
        .ok_or("missing new binding")?;
    assert_eq!((&old.0, &old.1), (&current.0, &current.1));
    assert_ne!(old.2, current.2);
    let reopened: EngineState = serde_json::from_slice(&serde_json::to_vec(&engines)?)?;
    assert_eq!(
        reopened.plugin_secret_mount_binding("", "external/item"),
        Some(current)
    );
    Ok(())
}

#[test]
fn plugin_completion_rejects_recreated_namespace_identity() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    let mut authority = admitted(&mut service, &token, "team", false)?;
    assert!(service.validate_plugin_response(&mut authority).is_ok());
    // A namespace with no materialized engine can actually be removed. The
    // independent mount-incarnation test covers disable/recreate under I/O.
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert!(service.validate_plugin_response(&mut authority).is_err());
    Ok(())
}
