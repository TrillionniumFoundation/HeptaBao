use super::tests::{Root, bootstrap, call};
use super::*;
use crate::http::logical_data_wire_fixture;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn form_wire(path: &str, payload: &str) -> Vec<u8> {
    format!("POST /v1/{path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{payload}", payload.len()).into_bytes()
}

#[test]
fn actual_default_and_custom_form_logins_share_single_use_auth_dispatch() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    for mount in ["approle", "forms", "team/forms"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/auth/{mount}"),
                &admin,
                json!({"type":"approle"})
            )
            .status,
            204
        );
        let role = format!("auth/{mount}/role/fixture");
        assert_eq!(
            call(
                &mut service,
                "POST",
                &role,
                &admin,
                json!({"secret_id_num_uses":1,"token_ttl":60})
            )
            .status,
            204
        );
        let id = call(
            &mut service,
            "GET",
            &format!("{role}/role-id"),
            &admin,
            json!({}),
        );
        let issued = call(
            &mut service,
            "POST",
            &format!("{role}/secret-id"),
            &admin,
            json!({}),
        );
        let payload = format!(
            "role_id={}&secret_id={}",
            id.body["data"]["role_id"].as_str().ok_or("role id")?,
            issued.body["data"]["secret_id"]
                .as_str()
                .ok_or("secret id")?
        );
        let wire = form_wire(&format!("auth/{mount}/login"), &payload);
        let response = logical_data_wire_fixture(&mut service, &wire, 100)?;
        assert_eq!(response.status, 200);
        assert!(
            response.body["auth"]["client_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
        );
        assert_eq!(
            logical_data_wire_fixture(&mut service, &wire, 100)?.status,
            400
        );
    }
    Ok(())
}

#[test]
fn actual_form_dispatch_rejects_unknown_or_replaced_auth_kind_before_login() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/forms",
            &admin,
            json!({"type":"approle"})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "DELETE", "sys/auth/forms", &admin, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/forms",
            &admin,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    for path in [
        "auth/forms/login",
        "auth/unknown/login",
        "auth/userpass/login",
    ] {
        let response = logical_data_wire_fixture(
            &mut service,
            &form_wire(path, "role_id=synthetic&secret_id=synthetic"),
            100,
        )?;
        assert_eq!(response.status, 400);
        assert!(response.body.get("auth").is_none());
        assert!(response.body["errors"][0].as_str().is_some_and(
            |message| message == "AppRole form requires an actual AppRole login mount"
        ));
    }
    Ok(())
}

#[test]
fn logical_content_type_header_does_not_turn_json_kv_or_userpass_into_form() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/users",
            &admin,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/users/users/fixture",
            &admin,
            json!({"password":"synthetic-password-for-header-regression"})
        )
        .status,
        204
    );
    for (path, token, body, expected) in [
        (
            "secret/data/json-header",
            admin.as_str(),
            json!({"data":{"v":1}}),
            200,
        ),
        (
            "auth/users/login/fixture",
            "",
            json!({"password":"synthetic-password-for-header-regression"}),
            200,
        ),
    ] {
        let mut frame = crate::request_metadata::DataFrame::default();
        frame.headers.insert(
            "content-type".to_owned(),
            vec!["application/x-www-form-urlencoded".to_owned()],
        );
        let _scope = crate::request_metadata::Scope::enter(Some(frame), "POST", path, "", &body)?;
        let response = service.handle_http_fixture_at(
            ServiceRequest {
                method: "POST",
                path,
                namespace: "",
                token,
                body,
                wrap_ttl_seconds: None,
                origin_peer: Some(std::net::IpAddr::from([127, 0, 0, 1])),
                client_certificates: None,
            },
            100,
        );
        assert_eq!(response.status, expected);
    }
    Ok(())
}
