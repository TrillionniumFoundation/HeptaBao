use super::tests::{Root, bootstrap, call};
use serde_json::json;

#[test]
fn system_defaults_and_token_grants_each_require_schema_thirty_three()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let mut state = service.state.clone().ok_or("state")?;
    state.schema = 32;
    assert_eq!(
        state
            .validate_format()
            .err()
            .ok_or("system metadata admitted")?
            .status,
        503
    );
    state.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(state.validate_format().is_ok());

    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/create",
            &admin,
            json!({"policies":["default"], "ttl":75})
        )
        .status,
        200
    );
    let mut value = serde_json::to_value(service.state.as_ref().ok_or("state")?)?;
    value["schema"] = json!(32);
    value["auth"]
        .as_object_mut()
        .ok_or("auth")?
        .remove("system_lease_defaults");
    let mut grant_only: super::State = serde_json::from_value(value)?;
    assert_eq!(
        grant_only
            .validate_format()
            .err()
            .ok_or("grant metadata admitted")?
            .status,
        503
    );
    grant_only.schema = super::CURRENT_STATE_SCHEMA;
    assert!(grant_only.validate_format().is_ok());
    grant_only.auth.omit_lease_metadata_for_legacy_fixture();
    grant_only.schema = 32;
    assert!(grant_only.validate_format().is_ok());
    Ok(())
}

#[test]
fn auth_mount_ttl_limits_drive_issue_and_survive_restart() -> Result<(), Box<dyn std::error::Error>>
{
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, root_token) = bootstrap(&mut service)?;

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/scoped",
            &root_token,
            json!({"type":"userpass","description":"scoped login","cas_revision":0})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/scoped/tune",
            &root_token,
            json!({
                "default_lease_ttl":120,
                "max_lease_ttl":300,
                "description":"scoped login tuned",
                "cas_revision":1
            })
        )
        .status,
        204
    );
    let tuned = call(
        &mut service,
        "GET",
        "sys/auth/scoped/tune",
        &root_token,
        json!({}),
    );
    assert_eq!(tuned.status, 200);
    assert_eq!(tuned.body["data"]["default_lease_ttl"], 120);
    assert_eq!(tuned.body["data"]["max_lease_ttl"], 300);
    assert_eq!(tuned.body["data"]["revision"], 2);

    assert_eq!(
        call(
            &mut service,
            "PUT",
            "auth/scoped/users/alice",
            &root_token,
            json!({"password":"correct horse battery staple"})
        )
        .status,
        204
    );
    let user = call(
        &mut service,
        "GET",
        "auth/scoped/users/alice",
        &root_token,
        json!({}),
    );
    assert_eq!(user.status, 200);
    assert_eq!(user.body["data"]["token_ttl"], 120);
    assert_eq!(user.body["data"]["token_max_ttl"], 300);

    let first = call(
        &mut service,
        "POST",
        "auth/scoped/login/alice",
        "",
        json!({"password":"correct horse battery staple"}),
    );
    assert_eq!(first.status, 200);
    assert_eq!(first.body["auth"]["lease_duration"], 120);
    let first_token = first.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing first login token")?
        .to_owned();
    let first_info = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &first_token,
        json!({}),
    );
    assert_eq!(first_info.status, 200);
    assert_eq!(first_info.body["data"]["ttl"], 120);
    assert_eq!(first_info.body["data"]["explicit_max_ttl"], 300);

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/scoped/tune",
            &root_token,
            json!({
                "default_lease_ttl":60,
                "max_lease_ttl":90,
                "cas_revision":2
            })
        )
        .status,
        204
    );
    let bounded = call(
        &mut service,
        "POST",
        "auth/scoped/login/alice",
        "",
        json!({"password":"correct horse battery staple"}),
    );
    assert_eq!(bounded.status, 200);
    assert_eq!(bounded.body["auth"]["lease_duration"], 90);
    let bounded_token = bounded.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing bounded login token")?
        .to_owned();
    let bounded_info = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &bounded_token,
        json!({}),
    );
    assert_eq!(bounded_info.status, 200);
    assert_eq!(bounded_info.body["data"]["ttl"], 90);
    assert_eq!(bounded_info.body["data"]["explicit_max_ttl"], 90);

    let invalid = call(
        &mut service,
        "POST",
        "sys/auth/scoped/tune",
        &root_token,
        json!({
            "default_lease_ttl":91,
            "max_lease_ttl":90,
            "cas_revision":3
        }),
    );
    assert_eq!(invalid.status, 400);
    let unchanged = call(
        &mut service,
        "GET",
        "sys/auth/scoped/tune",
        &root_token,
        json!({}),
    );
    assert_eq!(unchanged.body["data"]["revision"], 3);
    assert_eq!(unchanged.body["data"]["default_lease_ttl"], 60);
    assert_eq!(unchanged.body["data"]["max_lease_ttl"], 90);

    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let reopened = call(
        &mut service,
        "GET",
        "sys/auth/scoped/tune",
        &root_token,
        json!({}),
    );
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body["data"]["default_lease_ttl"], 60);
    assert_eq!(reopened.body["data"]["max_lease_ttl"], 90);
    assert_eq!(reopened.body["data"]["revision"], 3);
    let post_restart = call(
        &mut service,
        "POST",
        "auth/scoped/login/alice",
        "",
        json!({"password":"correct horse battery staple"}),
    );
    assert_eq!(post_restart.status, 200);
    assert_eq!(post_restart.body["auth"]["lease_duration"], 90);
    Ok(())
}
