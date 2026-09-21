use super::tests::{Root, bootstrap, call};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn fresh_userpass_case_variants_share_identity_and_survive_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/Alice",
            &admin,
            json!({"password":"original password"})
        )
        .status,
        204
    );
    let mut entity = None;
    for name in ["alice", "ALICE", "AlIcE"] {
        let response = call(
            &mut service,
            "POST",
            &format!("auth/userpass/login/{name}"),
            "",
            json!({"password":"original password"}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["metadata"]["username"], "alice");
        let id = response.body["auth"]["entity_id"]
            .as_str()
            .ok_or("entity")?
            .to_owned();
        if let Some(expected) = &entity {
            assert_eq!(expected, &id);
        } else {
            entity = Some(id);
        }
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/ALICE/password",
            &admin,
            json!({"password":"replacement password"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/alice",
            "",
            json!({"password":"original password"})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "auth/userpass/users",
            &admin,
            json!({})
        )
        .body["data"]["keys"],
        json!(["alice"])
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let response = call(
        &mut service,
        "POST",
        "auth/userpass/login/ALICE",
        "",
        json!({"password":"replacement password"}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["auth"]["entity_id"].as_str(),
        entity.as_deref()
    );
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 40);
    Ok(())
}

#[test]
fn new_namespace_has_native_default_but_untouched_defaults_do_not_prevent_deletion() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    for _ in 0..2 {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/namespaces/team",
                &admin,
                json!({})
            )
            .status,
            204
        );
        let encoded = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?;
        assert_eq!(
            encoded["auth_mounts"]["team"]["userpass"]["userpass_name_mode"],
            "ascii_lower_v1"
        );
        assert_eq!(
            call(
                &mut service,
                "DELETE",
                "sys/namespaces/team",
                &admin,
                json!({})
            )
            .status,
            204
        );
        let encoded = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?;
        assert!(encoded["auth_mounts"].get("team").is_none());
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/userpass/users/Mixed",
                "team",
                &admin,
                json!({"password":"password"}),
                100
            )
            .status,
        204
    );
    let response = service.handle_at(
        "POST",
        "auth/userpass/login/MIXED",
        "team",
        "",
        json!({"password":"password"}),
        100,
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["metadata"]["username"], "mixed");
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status,
        409
    );
    Ok(())
}

#[test]
fn schema38_and39_accept_absent_name_modes_without_adopting_legacy_accounts() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let mut old = service.state.clone().ok_or("state")?;
    old.schema = 39;
    assert!(old.validate_format().is_err());
    // Historical shape unit, not an actual migration: true previous-program
    // writes and downgrade rejection belong to the separate upgrade runner.
    let mut auth = serde_json::to_value(&old.auth)?;
    for namespace in auth["auth_mounts"]
        .as_object_mut()
        .ok_or("mounts")?
        .values_mut()
    {
        for mount in namespace
            .as_object_mut()
            .ok_or("namespace mounts")?
            .values_mut()
        {
            mount
                .as_object_mut()
                .ok_or("mount")?
                .remove("userpass_name_mode");
        }
    }
    old.auth = serde_json::from_value::<AuthState>(auth)?.into();
    for schema in [38, 39] {
        old.schema = schema;
        assert!(old.validate_format().is_ok());
    }
    service
        .commit_state(&old)
        .map_err(|_| "publish format fixture")?;
    service.state = Some(old);
    let before = service.current_state_digest().map_err(|_| "digest")?;
    assert_eq!(
        call(&mut service, "GET", "sys/auth", &admin, json!({})).status,
        200
    );
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        before
    );
    for (name, password) in [("Alice", "upper password"), ("alice", "lower password")] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("auth/userpass/users/{name}"),
                &admin,
                json!({"password":password})
            )
            .status,
            204
        );
    }
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "auth/userpass/users",
            &admin,
            json!({})
        )
        .body["data"]["keys"],
        json!(["Alice", "alice"])
    );
    let response = call(
        &mut service,
        "POST",
        "auth/userpass/login/Alice",
        "",
        json!({"password":"upper password"}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["metadata"]["username"], "Alice");
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_userpass_name_modes()
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn canonical_account_resolution_does_not_rewrite_the_acl_request_path() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/mixed",
            &admin,
            json!({"password":"original","token_policies":["login-policy"]})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/case-admin",
            &admin,
            json!({"policy":"path \"auth/userpass/users/MiXeD\" { capabilities = [\"update\"] }"})
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["case-admin"],"ttl":300}),
    );
    assert_eq!(issued.status, 200);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/mixed",
            actor,
            json!({"password":"denied"})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/MiXeD",
            actor,
            json!({"password":"allowed"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/MIXED",
            "",
            json!({"password":"allowed"})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "LIST",
            "auth/userpass/users",
            &admin,
            json!({})
        )
        .body["data"]["keys"],
        json!(["mixed"])
    );
    Ok(())
}

#[test]
fn userpass_path_acl_delegates_policies_but_cannot_issue_root_tokens() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(call(&mut service, "PUT", "sys/policies/acl/account-admin", &admin,
        json!({"policy":"path \"auth/userpass/users/delegated\" { capabilities=[\"update\"] } path \"auth/directory/users/delegated\" { capabilities=[\"update\"] }"})).status, 204);
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["account-admin"],"ttl":300}),
    );
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/delegated",
            actor,
            json!({"password":"delegated-password","token_policies":["not-held"]})
        )
        .status,
        204
    );
    let login = call(
        &mut service,
        "POST",
        "auth/userpass/login/delegated",
        "",
        json!({"password":"delegated-password"}),
    );
    assert_eq!(login.status, 200);
    assert_eq!(
        login.body["auth"]["policies"],
        json!(["default", "not-held"])
    );
    let held = login.body["auth"]["client_token"].as_str().ok_or("held")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/delegated",
            actor,
            json!({"token_ttl":121})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/delegated",
            actor,
            json!({"token_policies":["root"]})
        )
        .status,
        204
    );
    let before = service.current_state_digest().map_err(|_| "digest")?;
    let wrong = call(
        &mut service,
        "POST",
        "auth/userpass/login/delegated",
        "",
        json!({"password":"wrong"}),
    );
    assert_eq!(wrong.status, 400);
    assert_eq!(
        wrong.body["errors"],
        json!(["invalid username or password"])
    );
    let root_login = call(
        &mut service,
        "POST",
        "auth/userpass/login/delegated",
        "",
        json!({"password":"delegated-password"}),
    );
    assert_eq!(root_login.status, 400);
    assert_eq!(
        root_login.body["errors"],
        json!(["auth methods cannot create root tokens"])
    );
    assert!(root_login.body.get("auth").is_none());
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        before
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/lookup",
            &admin,
            json!({"token":held})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/directory",
            &admin,
            json!({"type":"ldap"})
        )
        .status,
        204
    );
    let before = service.current_state_digest().map_err(|_| "digest")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/directory/users/delegated",
            actor,
            json!({"password":"bounded-password","token_policies":["not-held"]})
        )
        .status,
        403
    );
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        before
    );
    Ok(())
}
