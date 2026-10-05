use super::tests::{Root, bootstrap, call};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn metadata_actor(
    service: &mut Service,
    root: &str,
    body: Value,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let response = call(
        service,
        "POST",
        "auth/token/create",
        root,
        wire_body(&body.to_string())?,
    );
    assert_eq!(response.status, 200);
    Ok(Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .ok_or("genuine metadata actor")?
            .into(),
    ))
}

#[test]
fn token_metadata_weak_decode_follows_auth_acl_then_precedes_creation_rules_and_consumes_real_use()
-> TestResult {
    let fixture = Root::new();
    let mut service = fixture.service()?;
    let (_, root) = bootstrap(&mut service)?;
    for (name, policy) in [
        (
            "reader-meta",
            r#"path "auth/token/create" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }"#,
        ),
        (
            "no-meta-create",
            r#"path "somewhere-else" { capabilities = ["read"] }"#,
        ),
        (
            "meta-number-acl",
            r#"path "auth/token/create" {
 capabilities = ["update", "sudo"]
 allowed_parameters = { "policies" = ["reader-meta"] "no_default_policy" = [true] "meta" = [{ "n" = 1 }] }
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
    let reader = metadata_actor(
        &mut service,
        &root,
        json!({"policies":["reader-meta"],"no_default_policy":true}),
    )?;
    let denied = metadata_actor(
        &mut service,
        &root,
        json!({"policies":["no-meta-create"],"no_default_policy":true}),
    )?;
    let batch = metadata_actor(
        &mut service,
        &root,
        json!({"policies":["reader-meta"],"no_default_policy":true,"type":"batch","ttl":"1h"}),
    )?;
    let malformed = json!({"policies":["default"],"no_default_policy":true,"meta":{"bad":{}}});
    let field_error = "Field validation failed: error converting input for field \"meta\": decoding failed due to the following error(s):\n\n'[0]' expected type 'string', got unconvertible type 'map[string]interface {}'";
    for token in ["", "synthetic-invalid-token", denied.as_str()] {
        let response = call(
            &mut service,
            "POST",
            "auth/token/create",
            token,
            wire_body(&malformed.to_string())?,
        );
        assert_eq!(response.status, 403);
        assert!(response.body.get("auth").is_none());
    }
    for token in [reader.as_str(), batch.as_str()] {
        let response = call(
            &mut service,
            "POST",
            "auth/token/create",
            token,
            wire_body(&malformed.to_string())?,
        );
        assert_eq!(response.status, 400);
        assert_eq!(response.body["errors"], json!([field_error]));
    }
    for (token, expected) in [
        (reader.as_str(), "child policies must be subset of parent"),
        (batch.as_str(), "batch tokens cannot create more tokens"),
    ] {
        let response = call(
            &mut service,
            "POST",
            "auth/token/create",
            token,
            wire_body(r#"{"policies":["default"],"no_default_policy":true,"meta":{"flag":true}}"#)?,
        );
        assert_eq!(response.status, 400);
        assert_eq!(response.body["errors"], json!([expected]));
    }
    for invalid in [
        json!({"type":"invalid"}),
        json!({"num_uses":-1}),
        json!({"entity_alias":"unscoped"}),
        json!({"type":"batch","explicit_max_ttl":"1h"}),
    ] {
        let mut body = invalid;
        body["meta"] = json!({"bad":{}});
        let response = call(
            &mut service,
            "POST",
            "auth/token/create",
            &root,
            wire_body(&body.to_string())?,
        );
        assert_eq!(response.status, 400);
        assert_eq!(response.body["errors"], json!([field_error]));
    }
    let finite = metadata_actor(
        &mut service,
        &root,
        json!({"policies":["reader-meta"],"no_default_policy":true,"num_uses":1}),
    )?;
    let response = call(
        &mut service,
        "POST",
        "auth/token/create",
        &finite,
        wire_body(&malformed.to_string())?,
    );
    assert_eq!(response.status, 400);
    assert_eq!(response.body["errors"], json!([field_error]));
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &finite,
            json!({})
        )
        .status,
        403
    );

    // The ACL sees the actual original numeric map. Restoring string spelling
    // before admission would turn this authorized numeric request into 403.
    let numeric = metadata_actor(
        &mut service,
        &root,
        json!({"policies":["meta-number-acl"],"no_default_policy":true}),
    )?;
    let response = call(
        &mut service,
        "POST",
        "auth/token/create",
        &numeric,
        wire_body(r#"{"policies":["reader-meta"],"no_default_policy":true,"meta":{"n":1}}"#)?,
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["metadata"], json!({"n":"1"}));
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/create",
            &numeric,
            wire_body(r#"{"policies":["reader-meta"],"no_default_policy":true,"meta":{"n":"1"}}"#)?
        )
        .status,
        403
    );

    let audit_before = service.audit_sequence;
    for raw in ["1e0", "1.0"] {
        let response = call(
            &mut service,
            "POST",
            "auth/token/create",
            &root,
            wire_body(&format!(
                "{{\"policies\":[\"default\"],\"no_default_policy\":true,\"meta\":{{\"n\":{raw}}}}}"
            ))?,
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["metadata"], json!({"n":raw}));
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
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].path_digest, events[1].path_digest);
    assert_eq!(events[2].path_digest, events[3].path_digest);
    assert_ne!(events[0].path_digest, events[2].path_digest);
    let audit = String::from_utf8(audit)?;
    assert!(!audit.contains(root.as_str()) && !audit.contains(reader.as_str()));
    assert!(!audit.contains("number_fields") && !audit.contains("meta-number-acl"));
    Ok(())
}

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
