//! Format admission units. Actual old-program upgrades have separate live evidence.
use super::tests::{Root, bootstrap, call};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn batch_schema_requires41_for_precreated_authority_and_explicit_issuance_configuration()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    assert!(state.auth.has_batch_authority());
    state.schema = 40;
    assert!(state.validate_format().is_err());
    state
        .auth
        .remove_unused_batch_authority_for_legacy_format_test();
    assert!(state.validate_format().is_ok());
    service.commit_state(&state).map_err(|_| "fixture commit")?;
    service.state = Some(state);
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let digest = service.current_state_digest().map_err(|_| "digest")?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        digest
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_batch_authority()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/batch",
            &admin,
            json!({"password":"schema fixture password", "token_type":"batch", "token_ttl":60})
        )
        .status,
        204
    );
    let mut configured = service.state.clone().ok_or("state")?;
    assert!(!configured.auth.has_batch_authority());
    assert!(configured.auth.has_batch_issuance_state());
    assert!(configured.validate_format().is_ok());
    configured.schema = 40;
    assert!(configured.validate_format().is_err());
    let issued = call(
        &mut service,
        "POST",
        "auth/userpass/login/batch",
        "",
        json!({"password":"schema fixture password"}),
    );
    assert_eq!(issued.status, 200);
    assert_eq!(issued.body["auth"]["token_type"], "batch");
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_batch_authority()
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .validate_format()
            .is_ok()
    );
    Ok(())
}

#[test]
fn batch_schema_checks_persisted_lease_key_authority_without_a_backing_token() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    for (path, body) in [
        (
            "sys/policies/acl/batch-ssh",
            json!({"policy":"path \"ssh/*\" { capabilities = [\"create\", \"update\", \"read\"] }"}),
        ),
        ("sys/mounts/ssh", json!({"type":"ssh"})),
        (
            "ssh/roles/worker",
            json!({"key_type":"otp", "default_user":"alice", "cidr_list":"127.0.0.0/8"}),
        ),
    ] {
        assert!([200, 204].contains(&call(&mut service, "POST", path, &admin, body).status));
    }
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"type":"batch", "policies":["batch-ssh"], "ttl":60}),
    );
    assert_eq!(issued.status, 200);
    let token = zeroize::Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("token")?
            .to_owned(),
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "ssh/creds/worker",
            &token,
            json!({"ip":"127.0.0.1"})
        )
        .status,
        200
    );
    let state = service.state.clone().ok_or("state")?;
    assert!(
        state
            .engines
            .all_lease_owners()
            .iter()
            .any(|(_, owner)| owner.batch_claims().is_some())
    );
    assert!(state.validate_format().is_ok());
    let mut missing = state.clone();
    let mut wire = serde_json::to_value(&missing.auth)?;
    wire.as_object_mut()
        .ok_or("auth")?
        .remove("batch_authority");
    missing.auth = serde_json::from_value::<AuthState>(wire)?.into();
    assert!(missing.validate_format().is_err());
    missing.schema = 40;
    assert!(missing.validate_format().is_err());
    let (foreign, _) = AuthState::bootstrap(100)?;
    let mut foreign_state = state;
    let foreign_authority = serde_json::to_value(foreign)?["batch_authority"].take();
    let mut wire = serde_json::to_value(&foreign_state.auth)?;
    wire["batch_authority"] = foreign_authority;
    foreign_state.auth = serde_json::from_value::<AuthState>(wire)?.into();
    assert!(foreign_state.validate_format().is_err());
    Ok(())
}
