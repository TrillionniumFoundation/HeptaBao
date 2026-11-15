//! Lookup IDs are request-only response fields, never persisted bearers.
use super::tests::{Root, bootstrap, call};
use super::*;

#[test]
fn token_lookup_echoes_only_authorized_presented_credentials_and_preserves_storage()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["default"],"ttl":300}),
    );
    assert_eq!(issued.status, 200);
    let child = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("child")?;
    let accessor = issued.body["auth"]["accessor"].as_str().ok_or("accessor")?;
    let digest = service.current_state_digest().map_err(|_| "digest")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for method in ["GET", "POST"] {
        let response = call(
            &mut service,
            method,
            "auth/token/lookup-self",
            child,
            json!({}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["id"], child);
        assert_eq!(response.body["data"]["accessor"], accessor);
        for body in [
            json!({}),
            json!({"token":null}),
            json!({"token":""}),
            json!({"token":token}),
        ] {
            let response = call(&mut service, method, "auth/token/lookup", &token, body);
            assert_eq!(response.status, 200);
            assert_eq!(response.body["data"]["id"], token);
        }
        let response = call(
            &mut service,
            method,
            "auth/token/lookup",
            &token,
            json!({"token":child}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["id"], child);
        assert_eq!(response.body["data"]["accessor"], accessor);
    }
    // Accessor lookup uses Update (POST/PUT), while the bearer lookup and
    // self lookup above retain their GET/POST contract.
    for method in ["POST", "PUT"] {
        let response = call(
            &mut service,
            method,
            "auth/token/lookup-accessor",
            &token,
            json!({"accessor":accessor}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["id"], "");
        assert_eq!(response.body["data"]["accessor"], accessor);
    }
    for (actor, target, expected) in [
        (token.as_str(), accessor, 405),
        (token.as_str(), "invalid-target", 405),
        ("", accessor, 403),
        (child, accessor, 403),
    ] {
        let response = call(
            &mut service,
            "GET",
            "auth/token/lookup-accessor",
            actor,
            json!({"accessor":target}),
        );
        assert_eq!(response.status, expected);
        assert!(response.body.get("data").is_none());
        assert!(response.body.get("auth").is_none());
        assert!(response.unwrapped_json.is_none());
        assert!(response.response_headers.is_empty());
        if expected == 405 {
            assert_eq!(response.body["errors"], json!(["unsupported operation"]));
        }
    }
    for (actor, body) in [
        (child, json!({"token":token})),
        ("missing", json!({"token":child})),
        (&token, json!({"token":"invalid-target"})),
    ] {
        let response = call(&mut service, "POST", "auth/token/lookup", actor, body);
        assert!(response.status >= 400);
        assert!(response.body.get("data").is_none());
    }
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        digest
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let serialized = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    assert!(
        !serialized
            .windows(token.len())
            .any(|bytes| bytes == token.as_bytes())
    );
    assert!(
        !serialized
            .windows(child.len())
            .any(|bytes| bytes == child.as_bytes())
    );
    Ok(())
}

#[test]
fn wrapped_token_lookup_keeps_the_echo_inside_the_one_use_response()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let response = service.handle_at_mode(RequestDispatch {
        method: "GET",
        path: "auth/token/lookup-self",
        namespace: "",
        token: &token,
        body: json!({}),
        now: 100,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: Some(60),
        origin_peer: None,
        client_certificates: None,
    });
    assert_eq!(response.status, 200);
    assert!(response.body.get("data").is_none_or(Value::is_null));
    let wrapper = response.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?;
    assert!(!serde_json::to_string(&response.body)?.contains(&token));
    let unwrapped = call(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        wrapper,
        json!({}),
    );
    assert_eq!(unwrapped.status, 200);
    assert_eq!(unwrapped.body["data"]["id"], token);
    assert!(
        call(
            &mut service,
            "POST",
            "sys/wrapping/unwrap",
            wrapper,
            json!({})
        )
        .status
            >= 400
    );
    Ok(())
}

#[test]
fn retained_expired_token_api_renewal_reaches_offline_classification_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let issued = service.handle_at(
        "POST",
        "auth/token/create",
        "",
        &token,
        json!({"policies":["default"], "ttl":"1s"}),
        100,
    );
    assert_eq!(issued.status, 200);
    let child = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("child")?;
    let accessor = issued.body["auth"]["accessor"].as_str().ok_or("accessor")?;
    let before = service.current_state_digest().map_err(|_| "digest")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    for (path, body) in [
        ("auth/token/renew", json!({"token":child})),
        ("auth/token/renew-accessor", json!({"accessor":accessor})),
    ] {
        let reply = service.handle_at("POST", path, "", &token, body, 101);
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["errors"], json!(["token not found"]));
        assert!(reply.body.get("auth").is_none());
    }
    assert_eq!(
        service.current_state_digest().map_err(|_| "digest")?,
        before
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}
