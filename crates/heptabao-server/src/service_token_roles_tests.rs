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
    let created = service.handle_at(
        "POST",
        "auth/token/roles/shared",
        "team",
        &admin,
        json!({"allowed_policies":["p-one"],"orphan":true}),
        100,
    );
    assert_eq!(created.status, 204, "{:?}", created.body.get("errors"));
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
    let created = call(
        &mut service,
        "POST",
        "auth/token/roles/alias",
        &admin,
        json!({"allowed_policies":["default"],"allowed_entity_aliases":["Ada"]}),
    );
    assert_eq!(created.status, 204, "{:?}", created.body.get("errors"));
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

#[test]
fn token_role_batch_provenance_cidrs_and_lookup_survive_retirement_and_encrypted_reopen()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap_unmounted(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/reader",
            &admin,
            json!({"policy":r#"path "auth/token/lookup-self" { capabilities = ["read"] }"#})
        )
        .status,
        204
    );
    assert_eq!(call(&mut service, "POST", "auth/token/roles/batch", &admin, json!({"allowed_policies":["reader"],"token_type":"batch","orphan":true,"renewable":false,"token_num_uses":2,"path_suffix":"v123","token_bound_cidrs":["127.0.0.1/32"]})).status, 204);
    let records = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?["tokens"]
        .as_object()
        .ok_or("token records")?
        .len();
    let grant = call(
        &mut service,
        "POST",
        "auth/token/create/batch",
        &admin,
        json!({"policies":["reader"],"no_default_policy":true,"ttl":300}),
    );
    assert_eq!(grant.status, 200);
    assert_eq!(grant.body["auth"]["num_uses"], 2);
    let token = grant.body["auth"]["client_token"]
        .as_str()
        .ok_or("authenticated batch")?
        .to_owned();
    assert_eq!(
        serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?["tokens"]
            .as_object()
            .ok_or("token records")?
            .len(),
        records
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        TOKEN_ROLE_STATE_SCHEMA
    );
    let peer = "127.0.0.1".parse()?;
    for _ in 0..4 {
        let lookup = service.handle_request_at(
            ServiceRequest::new("GET", "auth/token/lookup-self", "", &token, json!({}))
                .with_origin_peer(peer),
            100,
        );
        assert_eq!(lookup.status, 200);
        assert_eq!(lookup.body["data"]["role"], "batch");
        assert_eq!(lookup.body["data"]["path"], "auth/token/create/batch/v123");
        assert_eq!(lookup.body["data"]["num_uses"], 0);
        assert_eq!(lookup.body["data"]["bound_cidrs"], json!(["127.0.0.1"]));
        assert_eq!(lookup.body["data"]["creation_ttl"], 300);
    }
    assert_eq!(
        service
            .handle_request_at(
                ServiceRequest::new("GET", "auth/token/lookup-self", "", &token, json!({}))
                    .with_origin_peer("192.0.2.1".parse()?),
                100
            )
            .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "auth/token/roles/batch",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_token_role_state()
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        TOKEN_ROLE_STATE_SCHEMA
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let lookup = service.handle_request_at(
        ServiceRequest::new("GET", "auth/token/lookup-self", "", &token, json!({}))
            .with_origin_peer(peer),
        100,
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["role"], "batch");
    assert_eq!(lookup.body["data"]["path"], "auth/token/create/batch/v123");
    assert_eq!(lookup.body["data"]["bound_cidrs"], json!(["127.0.0.1"]));
    Ok(())
}

#[test]
fn ordinary_unicode_batch_schema80_floor_and_authenticated_lookup_survive_encrypted_reopen()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap_unmounted(&mut service)?;
    let backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let grant = service.handle_at(
        "POST",
        "auth/token/create",
        "",
        &admin,
        json!({"type":"batch","policies":["Σ","x,y"],"no_default_policy":true,"ttl":"60s"}),
        100,
    );
    assert_eq!(grant.status, 200, "public errors: {}", grant.body["errors"]);
    let raw = Zeroizing::new(
        grant.body["auth"]["client_token"]
            .as_str()
            .ok_or("actual ordinary batch grant")?
            .to_owned(),
    );
    let active = service.state.clone().ok_or("active")?;
    assert_eq!(active.schema, TOKEN_ROLE_STATE_SCHEMA);
    assert!(active.auth.has_token_api_schema80_state());
    assert!(!active.auth.has_token_role_state());
    let mut lower = active.clone();
    lower.schema = LOCAL_PKI_INTERMEDIATE_STATE_SCHEMA;
    assert!(lower.validate_format().is_err());
    assert!(service.prepare_snapshot_restore(&backup).is_err());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let lookup = service.handle_at(
        "POST",
        "auth/token/lookup",
        "",
        &admin,
        json!({"token":raw.as_str()}),
        101,
    );
    assert_eq!(
        lookup.status, 200,
        "public errors: {}",
        lookup.body["errors"]
    );
    assert_eq!(lookup.body["data"]["policies"], json!(["x,y", "σ"]));
    assert_eq!(lookup.body["data"]["path"], "auth/token/create");
    assert!(lookup.body["data"].get("role").is_none());
    let reopened = service.state.as_ref().ok_or("reopened")?;
    assert_eq!(reopened.schema, TOKEN_ROLE_STATE_SCHEMA);
    assert!(Service::validate_snapshot_protected_floor(reopened, &lower).is_err());
    Ok(())
}
