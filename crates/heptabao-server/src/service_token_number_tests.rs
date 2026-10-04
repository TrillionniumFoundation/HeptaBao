use super::tests::{Root, bootstrap, call};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn wire_body(input: &str) -> Result<Value, Box<dyn std::error::Error>> {
    wire_body_at("auth/token/create", input)
}

fn wire_body_at(path: &str, input: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut body = crate::auth::parse_strict_json(input.as_bytes())?;
    crate::http::token_fields::transport_body("POST", path, &mut body, input.as_bytes())?;
    Ok(body)
}

#[test]
fn token_number_lexemes_have_actual_policies_errors_and_audit_binding() -> TestResult {
    let fixture = Root::new();
    let mut service = fixture.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let audit_before = service.audit_sequence;
    for (raw, expected) in [
        ("1e0", "1e0"),
        ("1E+01", "1e+01"),
        ("-0", "-0"),
        ("1000000.0", "1000000.0"),
    ] {
        let response = call(
            &mut service,
            "POST",
            "auth/token/create",
            &root,
            wire_body(&format!(
                "{{\"policies\":[{raw}],\"no_default_policy\":true}}"
            ))?,
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["policies"], json!([expected]));
        assert_eq!(
            response.body["warnings"],
            json!([format!("Policy \"{expected}\" does not exist")])
        );
        let rejected = call(
            &mut service,
            "POST",
            "auth/token/create",
            &root,
            wire_body(&format!("{{\"no_default_policy\":{raw}}}"))?,
        );
        assert_eq!(rejected.status, 400);
        assert!(rejected.body.get("auth").is_none());
        assert_eq!(
            rejected.body["errors"],
            json!([
                "Field validation failed: error converting input for field \"no_default_policy\": '' cannot parse value as 'bool': strconv.ParseBool: invalid syntax"
            ])
        );
    }
    // Equal parsed numeric Values with distinct original spellings bind distinct
    // audit HMACs. The request/response pair keeps the same original fingerprint.
    for raw in ["1e0", "1.0"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/token/create",
                &root,
                wire_body(&format!(
                    "{{\"policies\":{raw},\"no_default_policy\":true}}"
                ))?
            )
            .status,
            200
        );
    }
    let audit = fs::read(fixture.path.join("audit.jsonl"))?;
    let events = audit
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice::<AuditRecord>)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|record| record.event.sequence > audit_before)
        .map(|record| record.event)
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 20);
    for pair in events.as_chunks::<2>().0 {
        assert_eq!(pair[0].path_digest, pair[1].path_digest);
    }
    assert_ne!(events[16].path_digest, events[18].path_digest);
    let audit = String::from_utf8(audit)?;
    assert!(!audit.contains(&root));
    assert!(!audit.contains("__heptabao_token_number_fields"));
    assert!(!audit.contains("number_fields"));
    Ok(())
}

#[test]
fn token_number_role_fields_preserve_wire_lexemes_and_original_parameter_acl() -> TestResult {
    let fixture = Root::new();
    let mut service = fixture.service()?;
    let (_, root) = bootstrap(&mut service)?;
    let path = "auth/token/roles/raw-numbers";
    let response = call(
        &mut service,
        "POST",
        path,
        &root,
        wire_body_at(path, r#"{"allowed_policies":[1e0,1.0],"path_suffix":1e0}"#)?,
    );
    assert_eq!(response.status, 204, "{}", response.body["errors"]);
    let read = call(&mut service, "GET", path, &root, json!({}));
    assert_eq!(read.body["data"]["allowed_policies"], json!(["1.0", "1e0"]));
    assert_eq!(read.body["data"]["path_suffix"], "1e0");
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let failure = call(
        &mut service,
        "POST",
        path,
        &root,
        wire_body_at(path, r#"{"token_period":1e0,"renewable":false}"#)?,
    );
    assert_eq!(failure.status, 400);
    assert_eq!(
        failure.body["errors"],
        json!([
            "error converting input for field \"token_period\": time: missing unit in duration \"1e0\""
        ])
    );
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        before
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/role-writer",
            &root,
            json!({"policy":r#"path "auth/token/roles/acl-numbers" {
            capabilities = ["update"]
            allowed_parameters = { "allowed_policies" = ["1"] }
        }"#})
        )
        .status,
        204
    );
    let parent = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root,
        json!({"policies":["role-writer"],"no_default_policy":true}),
    );
    let parent = parent.body["auth"]["client_token"]
        .as_str()
        .ok_or("role writer")?;
    let path = "auth/token/roles/acl-numbers";
    assert_eq!(
        call(
            &mut service,
            "POST",
            path,
            parent,
            wire_body_at(path, r#"{"allowed_policies":"1"}"#)?
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            path,
            parent,
            wire_body_at(path, r#"{"allowed_policies":1}"#)?
        )
        .status,
        403
    );
    Ok(())
}

#[test]
fn token_number_conversion_does_not_retype_original_parameter_acl() -> TestResult {
    let fixture = Root::new();
    let mut service = fixture.service()?;
    let (_, root) = bootstrap(&mut service)?;
    for (name, policy) in [
        ("1", "path \"number-probe\" { capabilities = [\"read\"] }"),
        (
            "numeric-create",
            r#"path "auth/token/create" {
            capabilities = ["update"]
            allowed_parameters = { "policies" = ["1"] "no_default_policy" = [true] }
        }"#,
        ),
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/policies/acl/{name}"),
                &root,
                json!({"policy":policy})
            )
            .status,
            204
        );
    }
    let parent = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root,
        json!({"policies":["1","numeric-create"],"no_default_policy":true}),
    );
    let parent = parent.body["auth"]["client_token"]
        .as_str()
        .ok_or("parent token")?;
    let response = call(
        &mut service,
        "POST",
        "auth/token/create",
        parent,
        wire_body(r#"{"policies":"1","no_default_policy":true}"#)?,
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["policies"], json!(["1"]));
    let rejected = call(
        &mut service,
        "POST",
        "auth/token/create",
        parent,
        wire_body(r#"{"policies":1,"no_default_policy":true}"#)?,
    );
    assert_eq!(rejected.status, 403);
    assert!(rejected.body.get("auth").is_none());
    Ok(())
}

#[test]
fn token_number_boolean_fields_preserve_noncanonical_spelling_after_authorization() -> TestResult {
    let fixture = Root::new();
    let mut service = fixture.service()?;
    let (_, root) = bootstrap(&mut service)?;
    for field in ["no_parent", "renewable"] {
        for raw in ["-0", "1e0", "1.0"] {
            let rejected = call(
                &mut service,
                "POST",
                "auth/token/create",
                &root,
                wire_body(&format!("{{\"{field}\":{raw}}}"))?,
            );
            assert_eq!(rejected.status, 400);
            assert_eq!(
                rejected.body["errors"],
                json!([format!(
                    "Field validation failed: error converting input for field \"{field}\": '' cannot parse value as 'bool': strconv.ParseBool: invalid syntax"
                )])
            );
            assert!(rejected.body.get("auth").is_none());
        }
    }
    Ok(())
}
