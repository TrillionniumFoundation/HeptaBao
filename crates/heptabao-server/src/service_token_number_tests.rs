use super::tests::{Root, bootstrap, call};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn wire_body(input: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut body = crate::auth::parse_strict_json(input.as_bytes())?;
    crate::http::token_fields::transport_body(
        "POST",
        "auth/token/create",
        &mut body,
        input.as_bytes(),
    )?;
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
fn token_number_conversion_follows_actual_numeric_parameter_acl() -> TestResult {
    let fixture = Root::new();
    let mut service = fixture.service()?;
    let (_, root) = bootstrap(&mut service)?;
    for (name, policy) in [
        ("1", "path \"number-probe\" { capabilities = [\"read\"] }"),
        (
            "numeric-create",
            r#"path "auth/token/create" {
            capabilities = ["update"]
            allowed_parameters = { "policies" = [1] "no_default_policy" = [true] }
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
        wire_body(r#"{"policies":[1],"no_default_policy":true}"#)?,
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["policies"], json!(["1"]));
    let rejected = call(
        &mut service,
        "POST",
        "auth/token/create",
        parent,
        wire_body(r#"{"policies":["1"],"no_default_policy":true}"#)?,
    );
    assert_eq!(rejected.status, 403);
    assert!(rejected.body.get("auth").is_none());
    Ok(())
}
