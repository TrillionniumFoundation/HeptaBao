use super::tests::{Root, bootstrap, call};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[test]
fn userpass_no_default_presence_requires39_and_legacy_unknown_survives_read_and_login() -> TestResult
{
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/nd",
            &admin,
            json!({"password":"source password"})
        )
        .status,
        204
    );
    let mut old = service.state.clone().ok_or("state")?;
    old.schema = 38;
    assert!(old.validate_format().is_err());
    let mut wire = serde_json::to_value(&old.auth)?;
    wire["users"][""]["nd"]
        .as_object_mut()
        .ok_or("user")?
        .remove("token_policies_configured");
    old.auth = serde_json::from_value::<AuthState>(wire)?.into();
    assert!(old.validate_format().is_ok());
    service
        .commit_state(&old)
        .map_err(|_| "publish format fixture")?;
    service.state = Some(old);
    let before = service.current_state_digest().map_err(|_| "digest")?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/userpass/users/nd",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        before
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/nd",
            "",
            json!({"password":"source password"})
        )
        .status,
        200
    );
    let auth = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?;
    assert!(
        auth["users"][""]["nd"]
            .get("token_policies_configured")
            .is_none()
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    Ok(())
}
#[test]
fn userpass_empty_policy_shape_and_same_token_nil_to_explicit_empty_survive_restart() -> TestResult
{
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/nd",
            &admin,
            json!({"password":"source password","token_no_default_policy":true})
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/userpass/login/nd",
        "",
        json!({"password":"source password"}),
    );
    assert_eq!(issued.status, 200);
    assert_eq!(issued.body["auth"]["policies"], json!([]));
    assert!(issued.body["auth"].get("token_policies").is_none());
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let accessor = issued.body["auth"]["accessor"]
        .as_str()
        .ok_or("accessor")?
        .to_owned();
    let before = service.current_state_digest().map_err(|_| "digest")?;
    for (path, body) in [
        ("renew", json!({"token":token})),
        ("renew-accessor", json!({"accessor":accessor})),
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("auth/token/{path}"),
                &admin,
                body
            )
            .status,
            500
        );
        assert_eq!(
            service.current_state_digest().map_err(|_| "digest")?,
            before
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/nd",
            &admin,
            json!({"token_policies":null,"token_no_default_policy":false})
        )
        .status,
        204
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    for (path, body) in [
        ("renew", json!({"token":token})),
        ("renew-accessor", json!({"accessor":accessor})),
    ] {
        let renewed = call(
            &mut service,
            "POST",
            &format!("auth/token/{path}"),
            &admin,
            body,
        );
        assert_eq!(renewed.status, 200);
        assert_eq!(renewed.body["auth"]["policies"], json!([]));
        assert!(renewed.body["auth"].get("token_policies").is_none());
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/renew-self",
            &token,
            json!({})
        )
        .status,
        403
    );
    let mut disguised = service.state.clone().ok_or("state")?;
    let mut auth = serde_json::to_value(&disguised.auth)?;
    auth["users"][""]["nd"]
        .as_object_mut()
        .ok_or("user")?
        .remove("token_policies_configured");
    disguised.auth = serde_json::from_value::<AuthState>(auth)?.into();
    disguised.schema = 38;
    assert!(
        disguised.auth.has_userpass_no_default_policy(),
        "issued no-default token still fences even after account metadata is removed"
    );
    assert!(disguised.validate_format().is_err());
    Ok(())
}
