use super::tests::{Root, bootstrap, call};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[allow(clippy::too_many_arguments)]
fn from_peer(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    peer: Option<&str>,
    wrap: Option<u64>,
) -> TestResult<Response> {
    match service.begin_at_mode(RequestDispatch {
        method,
        path,
        namespace: "",
        token,
        body,
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: wrap,
        origin_peer: peer.map(str::parse).transpose()?,
        client_certificates: None,
    }) {
        RequestExecution::Complete(response) => Ok(response),
        RequestExecution::External(_) => Err("local userpass unexpectedly staged provider".into()),
    }
}
fn secret(response: &Response, key: &str) -> TestResult<String> {
    Ok(response.body["auth"][key]
        .as_str()
        .ok_or("missing auth field")?
        .to_owned())
}
#[test]
fn userpass_cidr_service_denial_preserves_state_and_finite_uses_after_reopen() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    assert_eq!(call(&mut service,"POST","auth/userpass/users/cidr",&admin,json!({"password":"source credential","token_bound_cidrs":["127.0.0.1"],"token_num_uses":2})).status,204);
    let path = "auth/userpass/login/cidr";
    for peer in [None, Some("127.0.0.2")] {
        let before = service.current_state_digest().map_err(|_| "digest")?;
        let response = from_peer(
            &mut service,
            "POST",
            path,
            "",
            json!({"password":"source credential"}),
            peer,
            Some(60),
        )?;
        assert_eq!(response.status, 403);
        assert!(response.body.get("auth").is_none_or(Value::is_null));
        assert!(response.body.get("wrap_info").is_none_or(Value::is_null));
        assert_eq!(
            service.current_state_digest().map_err(|_| "digest")?,
            before
        );
    }
    let issued = from_peer(
        &mut service,
        "POST",
        path,
        "",
        json!({"password":"source credential"}),
        Some("127.0.0.1"),
        None,
    )?;
    assert_eq!(issued.status, 200);
    let token = secret(&issued, "client_token")?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/cidr",
            &admin,
            json!({"token_bound_cidrs":null})
        )
        .status,
        204
    );
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let before = service.current_state_digest().map_err(|_| "digest")?;
    assert_eq!(
        from_peer(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({}),
            Some("127.0.0.2"),
            None
        )?
        .status,
        403
    );
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        before
    );
    for _ in 0..2 {
        assert_eq!(
            from_peer(
                &mut service,
                "GET",
                "auth/token/lookup-self",
                &token,
                json!({}),
                Some("127.0.0.1"),
                None
            )?
            .status,
            200
        );
    }
    assert_eq!(
        from_peer(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({}),
            Some("127.0.0.1"),
            None
        )?
        .status,
        403
    );
    Ok(())
}

#[test]
fn userpass_cidr_schema39_covers_config_and_token_after_clear_without_rejecting_old_empty_shape()
-> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/cidr",
            &admin,
            json!({"password":"source credential"})
        )
        .status,
        204
    );
    let mut old = service.state.clone().ok_or("state")?;
    // Format fixture for a genuine pre39 account: absence is not inferred nil.
    let mut auth = serde_json::to_value(&old.auth)?;
    auth["users"][""]["cidr"]
        .as_object_mut()
        .ok_or("user")?
        .remove("token_policies_configured");
    old.auth = serde_json::from_value::<AuthState>(auth)?.into();
    old.auth.remove_name_modes_for_legacy_format_test();
    old.schema = 38;
    assert!(old.validate_format().is_ok());
    let before = service.current_state_digest().map_err(|_| "digest")?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/userpass/users/cidr",
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
            "auth/userpass/users/cidr",
            &admin,
            json!({"token_bound_cidrs":["127.0.0.1"]})
        )
        .status,
        204
    );
    let mut config = service.state.clone().ok_or("state")?;
    config.auth.remove_name_modes_for_legacy_format_test();
    config.schema = 38;
    assert!(config.validate_format().is_err());
    let login = from_peer(
        &mut service,
        "POST",
        "auth/userpass/login/cidr",
        "",
        json!({"password":"source credential"}),
        Some("127.0.0.1"),
        Some(60),
    )?;
    assert_eq!(login.status, 200);
    let wrapper = login.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?
        .to_owned();
    let inner = from_peer(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        &wrapper,
        json!({}),
        Some("127.0.0.2"),
        None,
    )?;
    assert_eq!(inner.status, 200);
    let token = secret(&inner, "client_token")?;
    assert_eq!(
        from_peer(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({}),
            Some("127.0.0.2"),
            None
        )?
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/users/cidr",
            &admin,
            json!({"token_bound_cidrs":[]})
        )
        .status,
        204
    );
    let mut issued = service.state.clone().ok_or("state")?;
    issued.auth.remove_name_modes_for_legacy_format_test();
    issued.schema = 38;
    assert!(issued.auth.has_userpass_token_bound_cidrs());
    assert!(issued.validate_format().is_err());
    assert_eq!(
        from_peer(
            &mut service,
            "POST",
            "auth/token/renew",
            &admin,
            json!({"token":token,"increment":120}),
            Some("127.0.0.2"),
            None
        )?
        .status,
        200
    );
    Ok(())
}
