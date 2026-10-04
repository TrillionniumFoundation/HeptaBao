use super::tests::{Root, bootstrap_unmounted, call};
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn token_role_schema80_namespace_reopen_retirement_and_snapshot_floor() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status,
        200
    );
    let previous = service.state.clone().ok_or("previous")?;
    let backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/token/roles/shared",
                "team",
                &admin,
                json!({"allowed_policies":["p-one"],"orphan":true}),
                100
            )
            .status,
        204
    );
    let active = service.state.clone().ok_or("active")?;
    assert_eq!(active.schema, TOKEN_ROLE_STATE_SCHEMA);
    assert_eq!(active.writer_schema(), TOKEN_ROLE_STATE_SCHEMA);
    assert!(active.auth.has_token_role_state());
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let mut lower = active.clone();
    lower.schema = LOCAL_PKI_INTERMEDIATE_STATE_SCHEMA;
    assert!(lower.validate_format().is_err());
    assert!(service.commit_state(&lower).is_err());
    assert!(Service::validate_snapshot_protected_floor(&active, &lower).is_err());
    assert!(service.prepare_snapshot_restore(&backup).is_err());
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "GET",
                "auth/token/roles/shared",
                "team",
                &admin,
                json!({}),
                100
            )
            .body["data"]["allowed_policies"],
        json!(["p-one"])
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/roles/shared",
            &admin,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        service
            .handle_at(
                "DELETE",
                "auth/token/roles/shared",
                "team",
                &admin,
                json!({}),
                100
            )
            .status,
        204
    );
    let retired = service.state.clone().ok_or("retired")?;
    assert!(!retired.auth.has_token_role_state());
    assert_eq!(retired.schema, TOKEN_ROLE_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), TOKEN_ROLE_STATE_SCHEMA);
    let mut lower = retired.clone();
    lower.schema = LOCAL_PKI_INTERMEDIATE_STATE_SCHEMA;
    assert!(lower.validate_format().is_ok());
    assert!(lower.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &lower).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &previous).is_err());
    Ok(())
}
#[test]
fn token_role_alias_uses_owned_identity_and_disabled_entity_prevents_publication() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/roles/alias",
            &admin,
            json!({"allowed_policies":["default"],"allowed_entity_aliases":["Ada"]})
        )
        .status,
        204
    );
    let first = call(
        &mut service,
        "POST",
        "auth/token/create/alias",
        &admin,
        json!({"entity_alias":"Ada"}),
    );
    assert_eq!(first.status, 200);
    let entity = first.body["auth"]["entity_id"]
        .as_str()
        .ok_or("owned alias entity")?
        .to_owned();
    assert!(!entity.is_empty());
    let second = call(
        &mut service,
        "POST",
        "auth/token/create/alias",
        &admin,
        json!({"entity_alias":"Ada"}),
    );
    assert_eq!(second.status, 200);
    assert_eq!(second.body["auth"]["entity_id"], entity);
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("identity/entity/id/{entity}"),
            &admin,
            json!({"disabled":true})
        )
        .status,
        204
    );
    let identity = service.current_state_identity().map_err(|_| "identity")?;
    let denied = call(
        &mut service,
        "POST",
        "auth/token/create/alias",
        &admin,
        json!({"entity_alias":"Ada"}),
    );
    assert_eq!(denied.status, 403);
    assert!(denied.body.get("auth").is_none());
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    Ok(())
}
